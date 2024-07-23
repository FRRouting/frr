// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM RP database for BSR operation
 * Copyright (C) 2021 David Lamparter for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <lib/network.h>
#include <lib/iana_afi.h>
#include <lib/sockunion.h>

#include "if.h"
#include "pimd.h"
#include "pim_iface.h"
#include "pim_instance.h"
#include "pim_rpf.h"
#include "pim_hello.h"
#include "pim_pim.h"
#include "pim_nht.h"
#include "pim_bsm.h"
#include "pim_time.h"

/* safety limits to prevent DoS/memory exhaustion attacks against the BSR
 *
 * The BSR is more susceptible than other PIM protocol operation because
 * Candidate-RP messages are unicast to the BSR without any 2-way interaction
 * and can thus be spoofed blindly(!) from anywhere in the internet.
 *
 * Everything else is on-link, multicast, or requires an adjacency - much
 * harder to mess with.
 */

/* total number of RPs we keep information for */
static size_t bsr_max_rps = 1024;

DEFINE_MTYPE_STATIC(PIMD, PIM_BSR_CRP, "PIM BSR C-RP");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSR_GROUP, "PIM BSR range");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSR_ITEM, "PIM BSR C-RP range item");

static int rp_cmp(const struct bsr_crp_rp *a, const struct bsr_crp_rp *b)
{
	return pim_addr_cmp(a->addr, b->addr);
}

DECLARE_RBTREE_UNIQ(bsr_crp_rps, struct bsr_crp_rp, item, rp_cmp);

static int group_cmp(const struct bsr_crp_group *a,
		     const struct bsr_crp_group *b)
{
	return prefix_cmp(&a->range, &b->range);
}

DECLARE_RBTREE_UNIQ(bsr_crp_groups, struct bsr_crp_group, item, group_cmp);

static int r_g_cmp(const struct bsr_crp_item *a, const struct bsr_crp_item *b)
{
	return prefix_cmp(&a->group->range, &b->group->range);
}

DECLARE_RBTREE_UNIQ(bsr_crp_rp_groups, struct bsr_crp_item, r_g_item, r_g_cmp);

static int g_r_cmp(const struct bsr_crp_item *a, const struct bsr_crp_item *b)
{
	const struct bsr_crp_rp *rp_a = a->rp, *rp_b = b->rp;

	/* NHT-failed RPs last */
	if (rp_a->nht_ok > rp_b->nht_ok)
		return -1;
	if (rp_a->nht_ok < rp_b->nht_ok)
		return 1;

	/* This function determines BSR policy in what subset of the received
	 * RP candidates to advertise.  The BSR is free to make its choices
	 * any way it deems useful
	 */

	/* lower numeric values are better */
	if (rp_a->prio < rp_b->prio)
		return -1;
	if (rp_a->prio > rp_b->prio)
		return 1;

	/* prefer older RP for less churn */
	if (rp_a->seen_first < rp_b->seen_first)
		return -1;
	if (rp_a->seen_first > rp_b->seen_first)
		return 1;

	return pim_addr_cmp(rp_a->addr, rp_b->addr);
}

DECLARE_RBTREE_UNIQ(bsr_crp_group_rps, struct bsr_crp_item, g_r_item, g_r_cmp);

void pim_bsm_generate(struct bsm_scope *scope)
{
	struct bsm_frag *frag;
	struct bsm_hdr *hdr;
	bool have_dead = false;

	assertf(scope->state == BSR_ELECTED, "state=%d", scope->state);

	pim_bsm_frags_free(scope);

	struct bsr_crp_group *group;
	struct bsr_crp_item *item;
	struct bsr_crp_rp *rp;
	size_t n_groups = 0, n_rps = 0;

	frr_each (bsr_crp_groups, scope->ebsr_groups, group) {
		if (group->n_selected == 0) {
			if (group->dead_count >= PIM_BSR_DEAD_COUNT)
				continue;

			have_dead = true;
		} else
			group->dead_count = 0;

		n_groups++;
		n_rps += group->n_selected;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Generating BSM (%zu ranges, %zu RPs)", n_groups, n_rps);

	size_t datalen = PIM_MSG_HEADER_LEN + sizeof(*hdr) +
			 n_groups * sizeof(struct bsmmsg_grpinfo) +
			 n_rps * sizeof(struct bsmmsg_rpinfo);

	frag = XCALLOC(MTYPE_PIM_BSM_FRAG, sizeof(*frag) + datalen);

	uint8_t *pos = frag->data + PIM_MSG_HEADER_LEN;
	uint8_t *end = frag->data + datalen;

	hdr = (struct bsm_hdr *)pos;
	pos += sizeof(*hdr);
	assert(pos <= end);

	/* TODO: make BSR hashmasklen configurable */
#if PIM_IPV == 6
	hdr->hm_len = 126;
#else
	hdr->hm_len = 30;
#endif
	hdr->bsr_prio = scope->current_bsr_prio;
	hdr->bsr_addr.family = PIM_IANA_AFI;
	hdr->bsr_addr.reserved = 0;
	hdr->bsr_addr.addr = scope->bsr_addrsel.run_addr;

	frr_each (bsr_crp_groups, scope->ebsr_groups, group) {
		if (group->n_selected == 0 &&
		    group->dead_count >= PIM_BSR_DEAD_COUNT)
			continue;

		struct bsmmsg_grpinfo *gi = (struct bsmmsg_grpinfo *)pos;

		pos += sizeof(*gi);
		assert(pos <= end);

		gi->group.family = PIM_MSG_ADDRESS_FAMILY;
		gi->group.mask = group->range.prefixlen;
		gi->group.addr = group->range.prefix;

		size_t n_added = 0;

		frr_each (bsr_crp_group_rps, group->rps, item) {
			if (!item->selected)
				break;

			struct bsmmsg_rpinfo *ri = (struct bsmmsg_rpinfo *)pos;

			pos += sizeof(*ri);
			assert(pos <= end);

			rp = item->rp;
			ri->rpaddr.family = PIM_MSG_ADDRESS_FAMILY;
			ri->rpaddr.addr = rp->addr;
			ri->rp_holdtime = htons(rp->holdtime);
			ri->rp_pri = rp->prio;

			n_added++;
		}

		gi->rp_count = group->n_selected;
		gi->frag_rp_count = n_added;
		assert(n_added == group->n_selected);
	}

	assertf(pos == end, "end-pos=%td", end - pos);
	frag->size = datalen;

	bsm_frags_add_head(scope->bsm_frags, frag);

	scope->ebsr_have_dead_pending = have_dead;

	/*
	 * The BSR itself doesn't receive (no loopback) the BSM msgs advertising
	 * the rps. Install the rps directly for the local BSR node.
	 */
	pim_bsm_parse_install_g2rp(scope, ((uint8_t *) hdr) + PIM_BSM_HDR_LEN,
		datalen - PIM_BSM_HDR_LEN - PIM_MSG_HEADER_LEN, scope->bsm_frag_tag);

	pim_bsm_changed(scope);
}

static void pim_bsm_generate_timer(struct event *t)
{
	struct bsm_scope *scope = EVENT_ARG(t);

	pim_bsm_generate(scope);
}

static void pim_bsm_generate_sched(struct bsm_scope *scope)
{
	assertf(scope->state == BSR_ELECTED, "state=%d", scope->state);

	if (scope->t_ebsr_regen_bsm)
		return;

	event_add_timer(router->master, pim_bsm_generate_timer, scope, 1,
			&scope->t_ebsr_regen_bsm);
}

void pim_bsm_sent(struct bsm_scope *scope)
{
	struct bsr_crp_group *group;
	bool have_dead = false, changed = false;

	if (!scope->ebsr_have_dead_pending)
		return;

	frr_each_safe (bsr_crp_groups, scope->ebsr_groups, group) {
		if (group->n_selected != 0)
			continue;

		if (group->dead_count < PIM_BSR_DEAD_COUNT) {
			group->dead_count++;
			have_dead = true;
			continue;
		}

		changed = true;

		if (bsr_crp_group_rps_count(group->rps))
			/* have RPs, but none selected */
			continue;

		/* no reason to keep this range anymore */
		bsr_crp_groups_del(scope->ebsr_groups, group);
		bsr_crp_group_rps_fini(group->rps);
		XFREE(MTYPE_PIM_BSR_GROUP, group);
		continue;
	}

	scope->ebsr_have_dead_pending = have_dead;
	if (changed)
		pim_bsm_generate_sched(scope);
}

static void bsr_crp_reselect(struct bsm_scope *scope,
			     struct bsr_crp_group *group)
{
	bool changed = false;
	struct bsr_crp_item *item;
	size_t n_selected = 0;

	frr_each (bsr_crp_group_rps, group->rps, item) {
		bool select = false;

		/* hardcode best 2 RPs for now */
		if (item->rp->nht_ok && n_selected < 2) {
			select = true;
			n_selected++;
		}

		if (item->selected != select) {
			changed = true;
			item->selected = select;
		}
	}

	changed |= group->deleted_selected;
	group->deleted_selected = false;
	group->n_selected = n_selected;

	if (changed)
		pim_bsm_generate_sched(scope);

	scope->elec_rp_data_changed |= changed;
}

/* changing rp->nht_ok or rp->prio affects the sort order in group->rp
 * lists, so need a delete & re-add if either changes
 */
static void pim_crp_nht_prio_change(struct bsr_crp_rp *rp, bool nht_ok,
				    uint8_t prio)
{
	struct bsr_crp_item *item;

	frr_each (bsr_crp_rp_groups, rp->groups, item)
		bsr_crp_group_rps_del(item->group->rps, item);

	rp->prio = prio;
	rp->nht_ok = nht_ok;

	frr_each (bsr_crp_rp_groups, rp->groups, item) {
		bsr_crp_group_rps_add(item->group->rps, item);
		bsr_crp_reselect(rp->scope, item->group);
	}
}

static struct bsr_crp_group *group_get(struct bsm_scope *scope,
				       prefix_pim *range)
{
	struct bsr_crp_group *group, ref;

	ref.range = *range;
	group = bsr_crp_groups_find(scope->ebsr_groups, &ref);
	if (!group) {
		group = XCALLOC(MTYPE_PIM_BSR_GROUP, sizeof(*group));
		group->range = *range;
		bsr_crp_group_rps_init(group->rps);
		bsr_crp_groups_add(scope->ebsr_groups, group);
	}
	return group;
}

static void pim_crp_update(struct bsr_crp_rp *rp, struct cand_rp_msg *msg,
			   size_t ngroups)
{
	struct bsr_crp_rp_groups_head oldgroups[1];
	struct bsr_crp_item *item, itemref;
	struct bsr_crp_group *group, groupref;

	//struct bsm_scope *scope = rp->scope;

	bsr_crp_rp_groups_init(oldgroups);
	bsr_crp_rp_groups_swap_all(rp->groups, oldgroups);

	itemref.rp = rp;
	itemref.group = &groupref;

	assert(msg || ngroups == 0);

	for (size_t i = 0; i < ngroups; i++) {
		if (msg->groups[i].family != PIM_MSG_ADDRESS_FAMILY)
			continue;
		if (msg->groups[i].bidir)
			continue;

		prefix_pim pfx;

		pfx.family = PIM_AF;
		pfx.prefixlen = msg->groups[i].mask;
		pfx.prefix = msg->groups[i].addr;

#if PIM_IPV == 4
		if (pfx.prefixlen < 4)
			continue;
		if (!IPV4_CLASS_DE(ntohl(pfx.prefix.s_addr)))
			continue;
#endif

		apply_mask(&pfx);

		groupref.range = pfx;
		item = bsr_crp_rp_groups_find(oldgroups, &itemref);

		if (item) {
			bsr_crp_rp_groups_del(oldgroups, item);
			bsr_crp_rp_groups_add(rp->groups, item);
			continue;
		}

		group = group_get(rp->scope, &pfx);

		item = XCALLOC(MTYPE_PIM_BSR_ITEM, sizeof(*item));
		item->rp = rp;
		item->group = group;

		bsr_crp_group_rps_add(group->rps, item);
		bsr_crp_rp_groups_add(rp->groups, item);

		bsr_crp_reselect(rp->scope, group);
	}

	while ((item = bsr_crp_rp_groups_pop(oldgroups))) {
		group = item->group;
		if (item->selected)
			group->deleted_selected = true;

		bsr_crp_group_rps_del(group->rps, item);
		XFREE(MTYPE_PIM_BSR_ITEM, item);

		bsr_crp_reselect(rp->scope, group);
	}
	bsr_crp_rp_groups_fini(oldgroups);

	if (msg && msg->rp_prio != rp->prio)
		pim_crp_nht_prio_change(rp, rp->nht_ok, msg->rp_prio);
}

void pim_crp_nht_update(struct pim_instance *pim, struct pim_nexthop_cache *pnc)
{
	struct bsm_scope *scope = &pim->global_scope;
	struct bsr_crp_rp *rp, ref;
	bool ok;

	ref.addr = pnc->rpf.rpf_addr;
	rp = bsr_crp_rps_find(scope->ebsr_rps, &ref);
	assertf(rp, "addr=%pPA", &ref.addr);

	ok = CHECK_FLAG(pnc->flags, PIM_NEXTHOP_VALID);
	if (ok == rp->nht_ok)
		return;

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate-RP %pPA NHT %s", &rp->addr, ok ? "UP" : "DOWN");
	pim_crp_nht_prio_change(rp, ok, rp->prio);
}

static void pim_crp_free(struct pim_instance *pim, struct bsr_crp_rp *rp)
{
	EVENT_OFF(rp->t_hold);
	pim_nht_candrp_del(pim, rp->addr);
	bsr_crp_rp_groups_fini(rp->groups);

	XFREE(MTYPE_PIM_BSR_CRP, rp);
}

static void pim_crp_expire(struct event *t)
{
	struct bsr_crp_rp *rp = EVENT_ARG(t);
	struct pim_instance *pim = rp->scope->pim;

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate-RP %pPA holdtime expired", &rp->addr);

	pim_crp_update(rp, NULL, 0);

	bsr_crp_rps_del(rp->scope->ebsr_rps, rp);
	pim_crp_free(pim, rp);
}

int pim_crp_process(struct interface *ifp, pim_sgaddr *src_dst, uint8_t *buf,
		    uint32_t buf_size)
{
	struct pim_interface *pim_ifp = NULL;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: multicast not enabled on interface %s",
				   __func__, ifp->name);
		return -1;
	}

	//pim_ifp->pim_ifstat_bsm_rx++;
	pim = pim_ifp->pim;
	//pim->bsm_rcvd++;

	if (!pim_ifp->bsm_enable) {
		zlog_warn("%s: BSM not enabled on interface %s", __func__,
			  ifp->name);
		//pim_ifp->pim_ifstat_bsm_cfg_miss++;
		//pim->bsm_dropped++;
		return -1;
	}

	if (buf_size < (PIM_MSG_HEADER_LEN + sizeof(struct cand_rp_msg))) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: received buffer length of %d which is too small to properly decode",
				   __func__, buf_size);
		return -1;
	}

	scope = &pim->global_scope;

	if (scope->state < BSR_PENDING) {
		if (PIM_DEBUG_BSM)
			zlog_debug("received Candidate-RP message from %pPA while not BSR",
				   &src_dst->src);
		return -1;
	}

	size_t remain = buf_size;
	struct cand_rp_msg *crp_hdr;

	buf += PIM_MSG_HEADER_LEN;
	remain -= PIM_MSG_HEADER_LEN;

	crp_hdr = (struct cand_rp_msg *)buf;
	buf += sizeof(*crp_hdr);
	remain -= sizeof(*crp_hdr);

	size_t ngroups = crp_hdr->prefix_cnt;

	if (remain < ngroups * sizeof(struct pim_encoded_group_ipv4)) {
		if (PIM_DEBUG_BSM)
			zlog_debug("truncated Candidate-RP advertisement for RP %pPA from %pPA (too short for %zu groups)",
				   (pim_addr *)&crp_hdr->rp_addr.addr,
				   &src_dst->src, ngroups);
		return -1;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate-RP: %pPA, prio=%u (from %pPA, %zu groups)",
			   (pim_addr *)&crp_hdr->rp_addr.addr, crp_hdr->rp_prio,
			   &src_dst->src, ngroups);


	struct bsr_crp_rp *rp, ref;

	ref.addr = crp_hdr->rp_addr.addr;
	rp = bsr_crp_rps_find(scope->ebsr_rps, &ref);

	if (!rp) {
		if (bsr_crp_rps_count(scope->ebsr_rps) >= bsr_max_rps) {
			zlog_err("BSR: number of tracked Candidate RPs (%zu) exceeds DoS-protection limit (%zu), dropping advertisement for RP %pPA (packet source %pPA)",
				 bsr_crp_rps_count(scope->ebsr_rps),
				 bsr_max_rps, (pim_addr *)&crp_hdr->rp_addr.addr,
				 &src_dst->src);
			return -1;
		}

		if (PIM_DEBUG_BSM)
			zlog_debug("new Candidate-RP: %pPA (from %pPA)",
				   (pim_addr *)&crp_hdr->rp_addr.addr,
				   &src_dst->src);

		rp = XCALLOC(MTYPE_PIM_BSR_CRP, sizeof(*rp));
		rp->scope = scope;
		rp->addr = crp_hdr->rp_addr.addr;
		rp->prio = 255;
		bsr_crp_rp_groups_init(rp->groups);
		rp->seen_first = monotime(NULL);

		bsr_crp_rps_add(scope->ebsr_rps, rp);
		rp->nht_ok = pim_nht_candrp_add(pim, rp->addr);
	}

	rp->seen_last = monotime(NULL);
	rp->holdtime = ntohs(crp_hdr->rp_holdtime);

	EVENT_OFF(rp->t_hold);
	event_add_timer(router->master, pim_crp_expire, rp,
			ntohs(crp_hdr->rp_holdtime), &rp->t_hold);

	pim_crp_update(rp, crp_hdr, ngroups);
	return 0;
}

void pim_crp_db_clear(struct bsm_scope *scope)
{
	struct bsr_crp_rp *rp;
	struct bsr_crp_group *group;
	struct bsr_crp_item *item;

	while ((rp = bsr_crp_rps_pop(scope->ebsr_rps))) {
		while ((item = bsr_crp_rp_groups_pop(rp->groups))) {
			group = item->group;

			if (item->selected)
				group->deleted_selected = true;

			bsr_crp_group_rps_del(group->rps, item);
			XFREE(MTYPE_PIM_BSR_ITEM, item);
		}
		pim_crp_free(scope->pim, rp);
	}

	while ((group = bsr_crp_groups_pop(scope->ebsr_groups))) {
		assertf(!bsr_crp_group_rps_count(group->rps),
			"range=%pFX rp_count=%zu", &group->range,
			bsr_crp_group_rps_count(group->rps));

		bsr_crp_group_rps_fini(group->rps);
		XFREE(MTYPE_PIM_BSR_GROUP, group);
	}
}

int pim_crp_db_show(struct vty *vty, struct bsm_scope *scope, bool json)
{
	struct bsr_crp_rp *rp;
	struct bsr_crp_item *item;

	vty_out(vty, "RP/Group             NHT  Prio  Uptime    Hold\n");

	frr_each (bsr_crp_rps, scope->ebsr_rps, rp) {
		vty_out(vty, "%-15pPA     %4s  %4u  %8ld  %4lu\n", &rp->addr,
			rp->nht_ok ? "UP" : "DOWN", rp->prio,
			(long)(monotime(NULL) - rp->seen_first),
			event_timer_remain_second(rp->t_hold));

		frr_each (bsr_crp_rp_groups, rp->groups, item)
			vty_out(vty, "%c %-18pFX\n", item->selected ? '>' : ' ',
				&item->group->range);
	}

	return CMD_SUCCESS;
}

int pim_crp_groups_show(struct vty *vty, struct bsm_scope *scope, bool json)
{
	struct bsr_crp_group *group;
	struct bsr_crp_item *item;

	if (scope->ebsr_have_dead_pending)
		vty_out(vty, "have_dead_pending\n");

	frr_each (bsr_crp_groups, scope->ebsr_groups, group) {
		vty_out(vty, "%c %pFX", group->n_selected ? '^' : '!',
			&group->range);
		if (group->n_selected == 0)
			vty_out(vty, " (dead %u)", group->dead_count);

		vty_out(vty, "\n");

		frr_each (bsr_crp_group_rps, group->rps, item)
			vty_out(vty, "%c   %pPA\n", item->selected ? '>' : ' ',
				&item->rp->addr);
	}

	return CMD_SUCCESS;
}
