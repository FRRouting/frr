// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
 */
#include <zebra.h>
#include "network.h"
#include "zclient.h"
#include "stream.h"
#include "nexthop.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "lib/printfrr.h"

#include "pimd.h"
#include "pimd/pim_nht.h"
#include "pim_instance.h"
#include "log.h"
#include "pim_time.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_mroute.h"
#include "pim_zebra.h"
#include "pim_upstream.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_zebra.h"
#include "pim_zlookup.h"
#include "pim_rp.h"
#include "pim_addr.h"
#include "pim_register.h"
#include "pim_vxlan.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_LOOKUP_MODE, "PIM RPF lookup mode");
DEFINE_MTYPE_STATIC(PIMD, PIM_LOOKUP_MODE_STR, "PIM RPF lookup mode prefix list string");

static void pim_update_rp_nh(struct pim_instance *pim, struct pim_nexthop_cache *pnc);
static int pim_update_upstream_nh(struct pim_instance *pim, struct pim_nexthop_cache *pnc);

static int pim_lookup_mode_cmp(const struct pim_lookup_mode *l, const struct pim_lookup_mode *r)
{
	/* Let's just sort anything with both lists set above those with only one list set,
	 * which is above the global where neither are set
	 */

	/* Both are set on right, either lower or equal */
	if (l->grp_plist != NULL && l->src_plist != NULL)
		return (r->grp_plist == NULL || r->src_plist == NULL) ? -1 : 0;

	/* Only one set on the left */
	if (!(l->grp_plist == NULL && l->src_plist == NULL)) {
		/* Lower only if both are not set on right */
		if (r->grp_plist == NULL && r->src_plist == NULL)
			return -1;
		/* Higher only if both are set on right */
		if (r->grp_plist != NULL && r->src_plist != NULL)
			return 1;
		/* Otherwise both sides have at least one set, so equal */
		return 0;
	}

	/* Neither set on left, so equal if neither set on right also */
	if (r->grp_plist == NULL && r->src_plist == NULL)
		return 0;

	/* Otherwise higher */
	return 1;
}

DECLARE_SORTLIST_NONUNIQ(pim_lookup_mode, struct pim_lookup_mode, list, pim_lookup_mode_cmp);

static void pim_lookup_mode_free(struct pim_lookup_mode *m)
{
	if (m->grp_plist)
		XFREE(MTYPE_PIM_LOOKUP_MODE_STR, m->grp_plist);
	if (m->src_plist)
		XFREE(MTYPE_PIM_LOOKUP_MODE_STR, m->src_plist);
	XFREE(MTYPE_PIM_LOOKUP_MODE, m);
}

static void pim_lookup_mode_list_free(struct pim_lookup_mode_head *head)
{
	struct pim_lookup_mode *m;

	while ((m = pim_lookup_mode_pop(head)))
		pim_lookup_mode_free(m);
}

enum pim_rpf_lookup_mode pim_get_lookup_mode(struct pim_instance *pim, pim_addr group,
					     pim_addr source)
{
	struct pim_lookup_mode *m;
	struct prefix_list *plist;
	struct prefix p;

	frr_each_safe (pim_lookup_mode, &(pim->rpf_mode), m) {
		if (!pim_addr_is_any(group) && m->grp_plist) {
			/* Match group against plist, continue if no match */
			plist = prefix_list_lookup(PIM_AFI, m->grp_plist);
			if (plist == NULL)
				continue;
			pim_addr_to_prefix(&p, group);
			if (prefix_list_apply(plist, &p) == PREFIX_DENY)
				continue;
		}

		if (!pim_addr_is_any(source) && m->src_plist) {
			/* Match source against plist, continue if no match */
			plist = prefix_list_lookup(PIM_AFI, m->src_plist);
			if (plist == NULL)
				continue;
			pim_addr_to_prefix(&p, source);
			if (prefix_list_apply(plist, &p) == PREFIX_DENY)
				continue;
		}

		/* If lookup mode has a group list, but no group is provided, don't match it */
		if (pim_addr_is_any(group) && m->grp_plist)
			continue;

		/* If lookup mode has a source list, but no source is provided, don't match it */
		if (pim_addr_is_any(source) && m->src_plist)
			continue;

		/* Match found */
		return m->mode;
	}

	/* This shouldn't happen since we have the global mode, but if it's gone,
	 * just return the default of no config
	 */
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: No RPF lookup matched for given group %pPA and source %pPA",
			   __func__, &group, &source);

	return MCAST_NO_CONFIG;
}

static bool pim_rpf_mode_changed(enum pim_rpf_lookup_mode old, enum pim_rpf_lookup_mode new)
{
	if (old != new) {
		/* These two are equivalent, so don't update in that case */
		if (old == MCAST_NO_CONFIG && new == MCAST_MIX_MRIB_FIRST)
			return false;
		if (old == MCAST_MIX_MRIB_FIRST && new == MCAST_NO_CONFIG)
			return false;
		return true;
	}
	return false;
}

struct pnc_mode_update_hash_walk_data {
	struct pim_instance *pim;
	struct prefix_list *grp_plist;
	struct prefix_list *src_plist;
};

static int pim_nht_hash_mode_update_helper(struct hash_bucket *bucket, void *arg)
{
	struct pim_nexthop_cache *pnc = bucket->data;
	struct pnc_mode_update_hash_walk_data *pwd = arg;
	struct pim_instance *pim = pwd->pim;
	struct prefix p;

	pim_addr_to_prefix(&p, pnc->addr);

	/* Make sure this pnc entry matches the prefix lists */
	/* TODO: For now, pnc only has the source address, so we can only check that */
	if (pwd->src_plist &&
	    (pim_addr_is_any(pnc->addr) || prefix_list_apply(pwd->src_plist, &p) == PREFIX_DENY))
		return HASHWALK_CONTINUE;

	/* Otherwise the address is any, or matches the prefix list, or no prefix list to match, so do the updates */
	/* TODO for RP, there are groups....but I don't think we'd want to use those */
	if (listcount(pnc->rp_list))
		pim_update_rp_nh(pim, pnc);

	/* TODO for upstream, there is an S,G key...can/should we use that group?? */
	if (pnc->upstream_hash->count)
		pim_update_upstream_nh(pim, pnc);

	if (pnc->candrp_count)
		pim_crp_nht_update(pim, pnc);

	return HASHWALK_CONTINUE;
}

static void pim_rpf_mode_changed_update(struct pim_instance *pim, const char *group_plist,
					const char *source_plist)
{
	struct pnc_mode_update_hash_walk_data pwd;

	/* Update the refresh time to force new lookups if needed */
	pim_rpf_set_refresh_time(pim);

	/* Force update the registered RP and upstreams for all cache entries */
	pwd.pim = pim;
	pwd.grp_plist = prefix_list_lookup(PIM_AFI, group_plist);
	pwd.src_plist = prefix_list_lookup(PIM_AFI, source_plist);

	hash_walk(pim->nht_hash, pim_nht_hash_mode_update_helper, &pwd);
}

/**
 * pim_sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 */
static void pim_sendmsg_zebra_rnh(struct pim_instance *pim, struct zclient *zclient, pim_addr addr,
				  int command)
{
	struct prefix p;
	int ret;

	pim_addr_to_prefix(&p, addr);

	/* Register to track nexthops from the MRIB */
	ret = zclient_send_rnh(zclient, command, &p, SAFI_MULTICAST, false, false, pim->vrf->vrf_id);
	if (ret == ZCLIENT_SEND_FAILURE)
		zlog_warn(
			"sendmsg_nexthop: zclient_send_message() failed registering MRIB tracking");

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: MRIB NHT %sregistered addr %pFX(%s) with Zebra ret:%d ", __func__,
			   (command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", &p, pim->vrf->name,
			   ret);

	/* Also register to track nexthops from the URIB */
	ret = zclient_send_rnh(zclient, command, &p, SAFI_UNICAST, false, false, pim->vrf->vrf_id);
	if (ret == ZCLIENT_SEND_FAILURE)
		zlog_warn(
			"sendmsg_nexthop: zclient_send_message() failed registering URIB tracking");

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: URIB NHT %sregistered addr %pFX(%s) with Zebra ret:%d ", __func__,
			   (command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", &p, pim->vrf->name,
			   ret);

	return;
}

static struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.addr = addr;
	pnc = hash_lookup(pim->nht_hash, &lookup);

	return pnc;
}

static struct pim_nexthop_cache *pim_nexthop_cache_add(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc;
	char hash_name[64];

	/* This function is only ever called if we are unable to find an entry, so
	 * the hash_get should always add a new entry
	 */
	pnc = XCALLOC(MTYPE_PIM_NEXTHOP_CACHE, sizeof(struct pim_nexthop_cache));
	pnc->addr = addr;

	pnc = hash_get(pim->nht_hash, pnc, hash_alloc_intern);

	pnc->rp_list = list_new();
	pnc->rp_list->cmp = pim_rp_list_cmp;

	snprintfrr(hash_name, sizeof(hash_name), "PNC %pPA(%s) Upstream Hash", &pnc->addr,
		   pim->vrf->name);
	pnc->upstream_hash = hash_create_size(32, pim_upstream_hash_key, pim_upstream_equal,
					      hash_name);

	return pnc;
}

static bool pim_nht_pnc_has_answer(struct pim_instance *pim, struct pim_nexthop_cache *pnc,
				   pim_addr group)
{
	switch (pim_get_lookup_mode(pim, group, pnc->addr)) {
	case MCAST_MRIB_ONLY:
		return CHECK_FLAG(pnc->mrib.flags, PIM_NEXTHOP_ANSWER_RECEIVED);

	case MCAST_URIB_ONLY:
		return CHECK_FLAG(pnc->urib.flags, PIM_NEXTHOP_ANSWER_RECEIVED);

	case MCAST_MIX_MRIB_FIRST:
	case MCAST_NO_CONFIG:
	case MCAST_MIX_DISTANCE:
	case MCAST_MIX_PFXLEN:
		/* This check is to determine if we've received an answer necessary to make a NH decision.
		 * For the mixed modes, where we may lookup from MRIB or URIB, let's require an answer
		 * for both tables.
		 */
		return CHECK_FLAG(pnc->mrib.flags, PIM_NEXTHOP_ANSWER_RECEIVED) &&
		       CHECK_FLAG(pnc->urib.flags, PIM_NEXTHOP_ANSWER_RECEIVED);

	default:
		break;
	}
	return false;
}

static struct pim_nexthop_cache_rib *pim_pnc_get_rib(struct pim_instance *pim,
						     struct pim_nexthop_cache *pnc, pim_addr group)
{
	struct pim_nexthop_cache_rib *pnc_rib = NULL;
	enum pim_rpf_lookup_mode mode;

	mode = pim_get_lookup_mode(pim, group, pnc->addr);

	if (mode == MCAST_MRIB_ONLY)
		pnc_rib = &pnc->mrib;
	else if (mode == MCAST_URIB_ONLY)
		pnc_rib = &pnc->urib;
	else if (mode == MCAST_MIX_MRIB_FIRST || mode == MCAST_NO_CONFIG) {
		if (pnc->mrib.nexthop_num > 0)
			pnc_rib = &pnc->mrib;
		else
			pnc_rib = &pnc->urib;
	} else if (mode == MCAST_MIX_DISTANCE) {
		if (pnc->mrib.distance <= pnc->urib.distance)
			pnc_rib = &pnc->mrib;
		else
			pnc_rib = &pnc->urib;
	} else if (mode == MCAST_MIX_PFXLEN) {
		if (pnc->mrib.prefix_len >= pnc->urib.prefix_len)
			pnc_rib = &pnc->mrib;
		else
			pnc_rib = &pnc->urib;
	}

	return pnc_rib;
}

void pim_nht_change_rpf_mode(struct pim_instance *pim, const char *group_plist,
			     const char *source_plist, enum pim_rpf_lookup_mode mode)
{
	struct pim_lookup_mode *m;
	bool found = false;
	bool update = false;
	const char *glist = NULL;
	const char *slist = NULL;

	/* Prefix lists may be passed in as empty string, leave them NULL instead */
	if (group_plist && strlen(group_plist))
		glist = group_plist;
	if (source_plist && strlen(source_plist))
		slist = source_plist;

	frr_each_safe (pim_lookup_mode, &(pim->rpf_mode), m) {
		if ((m->grp_plist && glist && strmatch(m->grp_plist, glist)) &&
		    (m->src_plist && slist && strmatch(m->src_plist, slist))) {
			/* Group and source plists are both set and matched */
			found = true;
			if (mode == MCAST_NO_CONFIG) {
				/* MCAST_NO_CONFIG means we should remove this lookup mode
				 * We don't know what other modes might match, or if only the global, so we need to
				 * update all lookups
				 */
				pim_lookup_mode_del(&pim->rpf_mode, m);
				pim_lookup_mode_free(m);
				glist = NULL;
				slist = NULL;
				update = true;
			} else {
				/* Just changing mode */
				update = pim_rpf_mode_changed(m->mode, mode);
				m->mode = mode; /* Always make sure the mode is set, even if not updating */
			}

			if (update)
				pim_rpf_mode_changed_update(pim, glist, slist);
			break;
		}

		if ((m->grp_plist && glist && strmatch(m->grp_plist, glist)) &&
		    (!m->src_plist && !slist)) {
			/* Only group list set and matched */
			found = true;
			if (mode == MCAST_NO_CONFIG) {
				/* MCAST_NO_CONFIG means we should remove this lookup mode
				 * We don't know what other modes might match, or if only the global, so we need to
				 * update all lookups
				 */
				pim_lookup_mode_del(&pim->rpf_mode, m);
				pim_lookup_mode_free(m);
				glist = NULL;
				slist = NULL;
				update = true;
			} else {
				/* Just changing mode */
				update = pim_rpf_mode_changed(m->mode, mode);
				m->mode = mode; /* Always make sure the mode is set, even if not updating */
			}

			if (update)
				pim_rpf_mode_changed_update(pim, glist, slist);
			break;
		}

		if ((!m->grp_plist && !glist) &&
		    (m->src_plist && slist && strmatch(m->src_plist, slist))) {
			/* Only source list set and matched */
			found = true;
			if (mode == MCAST_NO_CONFIG) {
				/* MCAST_NO_CONFIG means we should remove this lookup mode
				 * We don't know what other modes might match, or if only the global, so we need to
				 * update all lookups
				 */
				pim_lookup_mode_del(&pim->rpf_mode, m);
				pim_lookup_mode_free(m);
				glist = NULL;
				slist = NULL;
				update = true;
			} else {
				/* Just changing mode */
				update = pim_rpf_mode_changed(m->mode, mode);
				m->mode = mode; /* Always make sure the mode is set, even if not updating */
			}

			if (update)
				pim_rpf_mode_changed_update(pim, glist, slist);
			break;
		}

		if (!m->grp_plist && !glist && !m->src_plist && !slist) {
			/* No prefix lists set, so this is the global mode */
			/* We never delete this mode, even when set back to MCAST_NO_CONFIG */
			update = pim_rpf_mode_changed(m->mode, mode);
			m->mode = mode; /* Always make sure the mode is set, even if not updating */
			if (update)
				pim_rpf_mode_changed_update(pim, glist, slist);
			found = true;
			break;
		}
	}

	if (!found) {
		/* Adding a new lookup mode with unique prefix lists, add it */
		m = XCALLOC(MTYPE_PIM_LOOKUP_MODE, sizeof(struct pim_lookup_mode));
		m->grp_plist = XSTRDUP(MTYPE_PIM_LOOKUP_MODE_STR, glist);
		m->src_plist = XSTRDUP(MTYPE_PIM_LOOKUP_MODE_STR, slist);
		m->mode = mode;
		pim_lookup_mode_add(&(pim->rpf_mode), m);
		pim_rpf_mode_changed_update(pim, glist, slist);
	}
}

int pim_lookup_mode_write(struct pim_instance *pim, struct vty *vty)
{
	int writes = 0;
	struct pim_lookup_mode *m;

	frr_each_safe (pim_lookup_mode, &(pim->rpf_mode), m) {
		if (m->mode == MCAST_NO_CONFIG)
			continue;

		++writes;
		vty_out(vty, " rpf-lookup-mode %s",
			m->mode == MCAST_URIB_ONLY	  ? "urib-only"
			: m->mode == MCAST_MRIB_ONLY	  ? "mrib-only"
			: m->mode == MCAST_MIX_MRIB_FIRST ? "mrib-then-urib"
			: m->mode == MCAST_MIX_DISTANCE	  ? "lower-distance"
							  : "longer-prefix");

		if (m->grp_plist)
			vty_out(vty, " group-list %s", m->grp_plist);

		if (m->src_plist)
			vty_out(vty, " source-list %s", m->src_plist);

		vty_out(vty, "\n");
	}
	return writes;
}

bool pim_nht_pnc_is_valid(struct pim_instance *pim, struct pim_nexthop_cache *pnc, pim_addr group)
{
	switch (pim_get_lookup_mode(pim, group, pnc->addr)) {
	case MCAST_MRIB_ONLY:
		return CHECK_FLAG(pnc->mrib.flags, PIM_NEXTHOP_VALID);

	case MCAST_URIB_ONLY:
		return CHECK_FLAG(pnc->urib.flags, PIM_NEXTHOP_VALID);

	case MCAST_MIX_MRIB_FIRST:
	case MCAST_NO_CONFIG:
	case MCAST_MIX_DISTANCE:
	case MCAST_MIX_PFXLEN:
		/* The valid flag is set if there are nexthops...so when doing mixed, mrib might not have
		 * any nexthops, so consider valid if at least one RIB is valid
		 */
		return CHECK_FLAG(pnc->mrib.flags, PIM_NEXTHOP_VALID) ||
		       CHECK_FLAG(pnc->urib.flags, PIM_NEXTHOP_VALID);

	default:
		break;
	}
	return false;
}

struct pim_nexthop_cache *pim_nht_get(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct zclient *zclient = NULL;

	zclient = pim_zebra_zclient_get();
	pnc = pim_nexthop_cache_find(pim, addr);

	if (pnc)
		return pnc;

	pnc = pim_nexthop_cache_add(pim, addr);
	pim_sendmsg_zebra_rnh(pim, zclient, pnc->addr, ZEBRA_NEXTHOP_REGISTER);

	if (PIM_DEBUG_PIM_NHT_DETAIL)
		zlog_debug("%s: NHT cache and zebra notification added for %pPA(%s)", __func__,
			   &addr, pim->vrf->name);

	return pnc;
}

void pim_nht_set_gateway(struct pim_instance *pim, struct pim_nexthop_cache *pnc, pim_addr addr,
			 struct interface *ifp)
{
	struct nexthop *nh_node = NULL;
	struct interface *ifp1 = NULL;

	for (nh_node = pnc->mrib.nexthop; nh_node; nh_node = nh_node->next) {
		/* If the gateway is already set, then keep it */
#if PIM_IPV == 4
		if (!pim_addr_is_any(nh_node->gate.ipv4))
			continue;
#else
		if (!pim_addr_is_any(nh_node->gate.ipv6))
			continue;
#endif

		/* Only set gateway on the correct interface */
		ifp1 = if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);
		if (ifp != ifp1)
			continue;

			/* Update the gateway address with the given address */
#if PIM_IPV == 4
		nh_node->gate.ipv4 = addr;
#else
		nh_node->gate.ipv6 = addr;
#endif
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: addr %pPA new MRIB nexthop addr %pPAs interface %s",
				   __func__, &pnc->addr, &addr, ifp1->name);
	}

	/* Now do the same with URIB nexthop entries */
	for (nh_node = pnc->urib.nexthop; nh_node; nh_node = nh_node->next) {
#if PIM_IPV == 4
		if (!pim_addr_is_any(nh_node->gate.ipv4))
			continue;
#else
		if (!pim_addr_is_any(nh_node->gate.ipv6))
			continue;
#endif

		ifp1 = if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);

		if (ifp != ifp1)
			continue;

#if PIM_IPV == 4
		nh_node->gate.ipv4 = addr;
#else
		nh_node->gate.ipv6 = addr;
#endif
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: addr %pPA new URIB nexthop addr %pPAs interface %s",
				   __func__, &pnc->addr, &addr, ifp1->name);
	}
}

/* Finds the nexthop cache entry for the given address. If no cache, add it for tracking.
 * Up and/or rp may be given to add to the nexthop cache entry so that they get updates when the nexthop changes
 * If out_pnc is not null, then copy the nexthop cache entry to it.
 * Return true if an entry was found and is valid.
 */
bool pim_nht_find_or_track(struct pim_instance *pim, pim_addr addr, struct pim_upstream *up,
			   struct rp_info *rp, struct pim_nexthop_cache *out_pnc)
{
	struct pim_nexthop_cache *pnc;
	struct listnode *ch_node = NULL;
	pim_addr group = PIMADDR_ANY;

	/* This will find the entry and add it to tracking if not found */
	pnc = pim_nht_get(pim, addr);

	assertf(up || rp, "addr=%pPA", &addr);

	/* Store the RP if provided and not currently in the list */
	if (rp != NULL) {
		ch_node = listnode_lookup(pnc->rp_list, rp);
		if (ch_node == NULL)
			listnode_add_sort(pnc->rp_list, rp);
	}

	/* Store the upstream if provided and not currently in the list */
	if (up != NULL) {
		(void)hash_get(pnc->upstream_hash, up, hash_alloc_intern);
		group = up->sg.grp;
	}

	if (pim_nht_pnc_is_valid(pim, pnc, group)) {
		if (out_pnc)
			memcpy(out_pnc, pnc, sizeof(struct pim_nexthop_cache));
		return true;
	}

	return false;
}

void pim_nht_bsr_add(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc;

	pnc = pim_nht_get(pim, addr);
	pnc->bsr_count++;
}

bool pim_nht_candrp_add(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc;

	pnc = pim_nht_get(pim, addr);
	pnc->candrp_count++;
	return pim_nht_pnc_is_valid(pim, pnc, PIMADDR_ANY);
}

static void pim_nht_drop_maybe(struct pim_instance *pim, struct pim_nexthop_cache *pnc)
{
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: NHT %pPA(%s) rp_list count:%d upstream count:%ld BSR count:%u Cand-RP count:%u",
			   __func__, &pnc->addr, pim->vrf->name, pnc->rp_list->count,
			   pnc->upstream_hash->count, pnc->bsr_count, pnc->candrp_count);

	if (pnc->rp_list->count == 0 && pnc->upstream_hash->count == 0 && pnc->bsr_count == 0 &&
	    pnc->candrp_count == 0) {
		struct zclient *zclient = pim_zebra_zclient_get();

		pim_sendmsg_zebra_rnh(pim, zclient, pnc->addr, ZEBRA_NEXTHOP_UNREGISTER);

		list_delete(&pnc->rp_list);

		hash_free(pnc->upstream_hash);
		hash_release(pim->nht_hash, pnc);

		if (pnc->urib.nexthop)
			nexthops_free(pnc->urib.nexthop);
		if (pnc->mrib.nexthop)
			nexthops_free(pnc->mrib.nexthop);

		XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
	}
}

void pim_nht_delete_tracked(struct pim_instance *pim, pim_addr addr, struct pim_upstream *up,
			    struct rp_info *rp)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_upstream *upstream = NULL;

	/* Remove from RPF hash if it is the last entry */
	lookup.addr = addr;
	pnc = hash_lookup(pim->nht_hash, &lookup);
	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT entry %pPA",
			  &addr);
		return;
	}

	if (rp) {
		/* Release the (*, G)upstream from pnc->upstream_hash,
		 * whose Group belongs to the RP getting deleted
		 */
		frr_each (rb_pim_upstream, &pim->upstream_head, upstream) {
			struct prefix grp;
			struct rp_info *trp_info;

			if (!pim_addr_is_any(upstream->sg.src))
				continue;

			pim_addr_to_prefix(&grp, upstream->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);
			if (trp_info == rp)
				hash_release(pnc->upstream_hash, upstream);
		}
		listnode_delete(pnc->rp_list, rp);
	}

	if (up)
		hash_release(pnc->upstream_hash, up);

	pim_nht_drop_maybe(pim, pnc);
}

void pim_nht_bsr_del(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	/*
	 * Nothing to do here if the address to unregister
	 * is 0.0.0.0 as that the BSR has not been registered
	 * for tracking yet.
	 */
	if (pim_addr_is_any(addr))
		return;

	lookup.addr = addr;

	pnc = hash_lookup(pim->nht_hash, &lookup);

	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT BSR entry %pPA",
			  &addr);
		return;
	}

	assertf(pnc->bsr_count > 0, "addr=%pPA", &addr);
	pnc->bsr_count--;

	pim_nht_drop_maybe(pim, pnc);
}

void pim_nht_candrp_del(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.addr = addr;

	pnc = hash_lookup(pim->nht_hash, &lookup);

	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT C-RP entry %pPA",
			  &addr);
		return;
	}

	assertf(pnc->candrp_count > 0, "addr=%pPA", &addr);
	pnc->candrp_count--;

	pim_nht_drop_maybe(pim, pnc);
}

bool pim_nht_bsr_rpf_check(struct pim_instance *pim, pim_addr bsr_addr,
			   struct interface *src_ifp, pim_addr src_ip)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_neighbor *nbr = NULL;
	struct nexthop *nh;
	struct interface *ifp;

	lookup.addr = bsr_addr;

	pnc = hash_lookup(pim->nht_hash, &lookup);
	if (!pnc || !pim_nht_pnc_has_answer(pim, pnc, PIMADDR_ANY)) {
		/* BSM from a new freshly registered BSR - do a synchronous
		 * zebra query since otherwise we'd drop the first packet,
		 * leading to additional delay in picking up BSM data
		 */

		/* FIXME: this should really be moved into a generic NHT
		 * function that does "add and get immediate result" or maybe
		 * "check cache or get immediate result." But until that can
		 * be worked in, here's a copy of the code below :(
		 */
		ifindex_t i;
		int num_ifindex;
		struct zclient_next_hop_args args = {
			.address = bsr_addr,
			.pim = pim,
		};

		num_ifindex = zclient_lookup_nexthop(&args, PIM_NEXTHOP_LOOKUP_MAX);

		if (num_ifindex <= 0)
			return false;

		for (i = 0; i < num_ifindex; i++) {
			struct pim_zlookup_nexthop *znh = &args.next_hops[i];

			/* pim_zlookup_nexthop has no ->type */

			/* 1:1 match code below with znh instead of nh */
			ifp = if_lookup_by_index(znh->ifindex,
						 pim->vrf->vrf_id);

			if (!ifp || !ifp->info)
				continue;

			if (if_is_loopback(ifp) && if_is_loopback(src_ifp))
				return true;

			nbr = pim_neighbor_find(ifp, znh->nexthop_addr, true);
			if (!nbr)
				continue;
			/* Are we on the correct interface? */
			if (znh->ifindex == src_ifp->ifindex) {
				/* Do we have the correct NH ? */
				if (!pim_addr_cmp(znh->nexthop_addr, src_ip))
					return true;
				/*
				 * check If the packet came from the neighbor,
				 * and the dst is a secondary address on the connected interface
				 */
				return (!pim_addr_cmp(nbr->source_addr, src_ip) &&
					pim_if_connected_to_source(ifp, znh->nexthop_addr));
			}
			return false;
		}
		return false;
	}

	if (pim_nht_pnc_is_valid(pim, pnc, PIMADDR_ANY)) {
		/* if we accept BSMs from more than one ECMP nexthop, this will cause
		 * BSM message "multiplication" for each ECMP hop.  i.e. if you have
		 * 4-way ECMP and 4 hops you end up with 256 copies of each BSM
		 * message.
		 *
		 * so...  only accept the first (IPv4) valid nexthop as source.
		 */
		struct pim_nexthop_cache_rib *rib = pim_pnc_get_rib(pim, pnc, PIMADDR_ANY);

		for (nh = rib->nexthop; nh; nh = nh->next) {
			pim_addr nhaddr;

			switch (nh->type) {
#if PIM_IPV == 4
			case NEXTHOP_TYPE_IPV4:
				if (nh->ifindex == IFINDEX_INTERNAL)
					continue;

				fallthrough;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				nhaddr = nh->gate.ipv4;
				break;

			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				continue;
#else
			case NEXTHOP_TYPE_IPV6:
				if (nh->ifindex == IFINDEX_INTERNAL)
					continue;

				fallthrough;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				nhaddr = nh->gate.ipv6;
				break;

			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				continue;
#endif
			case NEXTHOP_TYPE_IFINDEX:
				nhaddr = bsr_addr;
				break;

			case NEXTHOP_TYPE_BLACKHOLE:
				continue;
			}

			ifp = if_lookup_by_index(nh->ifindex, pim->vrf->vrf_id);
			if (!ifp || !ifp->info)
				continue;

			if (if_is_loopback(ifp) && if_is_loopback(src_ifp))
				return true;

			/* MRIB (IGP) may be pointing at a router where PIM is down */
			nbr = pim_neighbor_find(ifp, nhaddr, true);
			if (!nbr)
				continue;

			/* Are we on the correct interface? */
			if (nh->ifindex == src_ifp->ifindex) {
				/* Do we have the correct NH ? */
				if (!pim_addr_cmp(nhaddr, src_ip))
					return true;
				/*
				 * check If the packet came from the neighbor,
				 * and the dst is a secondary address on the connected interface
				 */
				return (!pim_addr_cmp(nbr->source_addr, src_ip) &&
					pim_if_connected_to_source(ifp, nhaddr));
			}
			return false;
		}
	}
	return false;
}

void pim_nht_rp_del(struct rp_info *rp_info)
{
	rp_info->rp.source_nexthop.interface = NULL;
	rp_info->rp.source_nexthop.mrib_nexthop_addr = PIMADDR_ANY;
	rp_info->rp.source_nexthop.mrib_metric_preference =
		router->infinite_assert_metric.metric_preference;
	rp_info->rp.source_nexthop.mrib_route_metric = router->infinite_assert_metric.route_metric;
}

/* Update RP nexthop info based on Nexthop update received from Zebra.*/
static void pim_update_rp_nh(struct pim_instance *pim,
			     struct pim_nexthop_cache *pnc)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;
	struct interface *ifp;

	/*Traverse RP list and update each RP Nexthop info */
	for (ALL_LIST_ELEMENTS_RO(pnc->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		ifp = rp_info->rp.source_nexthop.interface;
		// Compute PIM RPF using cached nexthop
		if (!pim_nht_lookup_ecmp(pim, &rp_info->rp.source_nexthop, rp_info->rp.rpf_addr,
					 &rp_info->group, true))
			pim_nht_rp_del(rp_info);

		/*
		 * If we transition from no path to a path
		 * we need to search through all the vxlan's
		 * that use this rp and send NULL registers
		 * for all the vxlan S,G streams
		 */
		if (!ifp && rp_info->rp.source_nexthop.interface)
			pim_vxlan_rp_info_is_alive(pim, &rp_info->rp);
	}
}

/* Update Upstream nexthop info based on Nexthop update received from Zebra.*/
static int pim_update_upstream_nh_helper(struct hash_bucket *bucket, void *arg)
{
	struct pim_instance *pim = (struct pim_instance *)arg;
	struct pim_upstream *up = (struct pim_upstream *)bucket->data;

	enum pim_rpf_result rpf_result;
	struct pim_rpf old;

	old.source_nexthop.interface = up->rpf.source_nexthop.interface;
	rpf_result = pim_rpf_update(pim, up, &old, __func__);

	/* update kernel multicast forwarding cache (MFC); if the
	 * RPF nbr is now unreachable the MFC has already been updated
	 * by pim_rpf_clear
	 */
	if (rpf_result == PIM_RPF_CHANGED)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	if (rpf_result == PIM_RPF_CHANGED ||
		(rpf_result == PIM_RPF_FAILURE && old.source_nexthop.interface))
		pim_zebra_upstream_rpf_changed(pim, up, &old);

	/*
	 * If we are a VXLAN source and we are transitioning from not
	 * having an outgoing interface to having an outgoing interface
	 * let's immediately send the null pim register
	 */
	if (!old.source_nexthop.interface && up->rpf.source_nexthop.interface &&
	    PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(up->flags) &&
	    (up->reg_state == PIM_REG_NOINFO || up->reg_state == PIM_REG_JOIN)) {
		pim_null_register_send(up);
	}

	if (PIM_DEBUG_PIM_NHT) {
		zlog_debug("%s: NHT upstream %s(%s) old ifp %s new ifp %s rpf_result: %d",
			   __func__, up->sg_str, pim->vrf->name,
			   old.source_nexthop.interface ? old.source_nexthop
								  .interface->name
							: "Unknown",
			   up->rpf.source_nexthop.interface ? up->rpf.source_nexthop
								      .interface->name
							    : "Unknown",
			   rpf_result);
	}

	return HASHWALK_CONTINUE;
}

static int pim_update_upstream_nh(struct pim_instance *pim,
				  struct pim_nexthop_cache *pnc)
{
	hash_walk(pnc->upstream_hash, pim_update_upstream_nh_helper, pim);

	pim_zebra_update_all_interfaces(pim);

	return 0;
}

static int pim_upstream_nh_if_update_helper(struct hash_bucket *bucket,
					    void *arg)
{
	struct pim_nexthop_cache *pnc = bucket->data;
	struct pnc_hash_walk_data *pwd = arg;
	struct pim_instance *pim = pwd->pim;
	struct interface *ifp = pwd->ifp;
	struct nexthop *nh_node = NULL;

	/* This update happens when an interface is added to/removed from pim.
	 * So go through both MRIB and URIB and update any upstreams for any
	 * matching nexthop
	 */
	for (nh_node = pnc->mrib.nexthop; nh_node; nh_node = nh_node->next) {
		if (ifp->ifindex == nh_node->ifindex) {
			if (pnc->upstream_hash->count) {
				pim_update_upstream_nh(pim, pnc);
				break;
			}
		}
	}

	for (nh_node = pnc->urib.nexthop; nh_node; nh_node = nh_node->next) {
		if (ifp->ifindex == nh_node->ifindex) {
			if (pnc->upstream_hash->count) {
				pim_update_upstream_nh(pim, pnc);
				break;
			}
		}
	}

	return HASHWALK_CONTINUE;
}

void pim_nht_upstream_if_update(struct pim_instance *pim, struct interface *ifp)
{
	struct pnc_hash_walk_data pwd;

	pwd.pim = pim;
	pwd.ifp = ifp;

	hash_walk(pim->nht_hash, pim_upstream_nh_if_update_helper, &pwd);
}

static uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp)
{
	uint32_t hash_val;

	if (!src)
		return 0;

	hash_val = prefix_hash_key(src);
	if (grp)
		hash_val ^= prefix_hash_key(grp);
	return hash_val;
}

static bool pim_ecmp_nexthop_search(struct pim_instance *pim, struct pim_nexthop_cache *pnc,
				    struct pim_nexthop *nexthop, pim_addr src, struct prefix *grp,
				    bool neighbor_needed)
{
	struct nexthop *nh_node = NULL;
	uint32_t hash_val = 0;
	uint32_t mod_val = 0;
	uint16_t nh_iter = 0;
	bool found = false;
	uint32_t num_nbrs = 0;
	pim_addr nh_addr;
	pim_addr grp_addr;
	struct pim_nexthop_cache_rib *rib;
	pim_addr group;

	group = pim_addr_from_prefix(grp);

	/* Early return if required parameters aren't provided */
	if (!pim || !pnc || !pim_nht_pnc_is_valid(pim, pnc, group) || !nexthop || !grp)
		return false;

	nh_addr = nexthop->mrib_nexthop_addr;
	grp_addr = pim_addr_from_prefix(grp);
	rib = pim_pnc_get_rib(pim, pnc, group);

	/* Current Nexthop is VALID, check to stay on the current path. */
	if (nexthop->interface && nexthop->interface->info &&
	    (!pim_addr_is_any(nh_addr))) {
		/* User configured knob to explicitly switch to new path is disabled or
		 * current path metric is less than nexthop update.
		 */
		if (!pim->ecmp_rebalance_enable) {
			bool curr_route_valid = false;

			/* Check if current nexthop is present in new updated Nexthop list.
			 * If the current nexthop is not valid, candidate to choose new
			 * Nexthop.
			 */
			for (nh_node = rib->nexthop; nh_node; nh_node = nh_node->next) {
				curr_route_valid = (nexthop->interface->ifindex
						    == nh_node->ifindex);
				if (curr_route_valid)
					break;
			}

			if (curr_route_valid &&
			    !pim_if_connected_to_source(nexthop->interface,
							src)) {
				struct pim_neighbor *nbr =
					pim_neighbor_find(nexthop->interface,
							  nexthop->mrib_nexthop_addr, true);
				if (!nbr
				    && !if_is_loopback(nexthop->interface)) {
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: current nexthop does not have nbr ",
							__func__);
				} else {
					/* update metric even if the upstream
					 * neighbor stays unchanged
					 */
					nexthop->mrib_metric_preference = rib->distance;
					nexthop->mrib_route_metric = rib->metric;
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: (%pPA,%pPA)(%s) current nexthop %s is valid, skipping new path selection",
							__func__, &src,
							&grp_addr,
							pim->vrf->name,
							nexthop->interface->name);
					return true;
				}
			}
		}
	}

	/* Count the number of neighbors for ECMP */
	for (nh_node = rib->nexthop; nh_node; nh_node = nh_node->next) {
		struct pim_neighbor *nbr;
		struct interface *ifp = if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);

		if (!ifp)
			continue;

#if PIM_IPV == 4
		pim_addr nhaddr = nh_node->gate.ipv4;
#else
		pim_addr nhaddr = nh_node->gate.ipv6;
#endif
		nbr = pim_neighbor_find(ifp, nhaddr, true);
		if (nbr || pim_if_connected_to_source(ifp, src))
			num_nbrs++;
	}

	if (pim->ecmp_enable) {
		struct prefix src_pfx;
		uint32_t consider = rib->nexthop_num;

		if (neighbor_needed && num_nbrs < consider)
			consider = num_nbrs;

		if (consider == 0)
			return false;

		// PIM ECMP flag is enable then choose ECMP path.
		pim_addr_to_prefix(&src_pfx, src);
		hash_val = pim_compute_ecmp_hash(&src_pfx, grp);
		mod_val = hash_val % consider;
	}

	for (nh_node = rib->nexthop; nh_node && !found; nh_node = nh_node->next) {
		struct pim_neighbor *nbr = NULL;
		struct pim_interface *pim_ifp;
		struct interface *ifp = if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);

		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug("%s %s: could not find interface for ifindex %d (address %pPA(%s))",
					   __FILE__, __func__, nh_node->ifindex, &src,
					   pim->vrf->name);
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		pim_ifp = ifp->info;

		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug("%s: pim not enabled on input interface %s(%s) (ifindex=%d, RPF for source %pPA)",
					   __func__, ifp->name, pim->vrf->name, nh_node->ifindex,
					   &src);
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		if (neighbor_needed && !pim_if_connected_to_source(ifp, src)) {
#if PIM_IPV == 4
			nbr = pim_neighbor_find(ifp, nh_node->gate.ipv4, true);
#else
			nbr = pim_neighbor_find(ifp, nh_node->gate.ipv6, true);
#endif

			if (!nbr && !if_is_loopback(ifp)) {
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: pim nbr not found on input interface %s(%s)",
						__func__, ifp->name,
						pim->vrf->name);
				if (nh_iter == mod_val)
					mod_val++; // Select nexthpath
				nh_iter++;
				continue;
			}
		}

		if (nh_iter == mod_val) {
			nexthop->interface = ifp;
#if PIM_IPV == 4
			nexthop->mrib_nexthop_addr = nh_node->gate.ipv4;
#else
			nexthop->mrib_nexthop_addr = nh_node->gate.ipv6;
#endif
			nexthop->mrib_metric_preference = rib->distance;
			nexthop->mrib_route_metric = rib->metric;
			nexthop->last_lookup = src;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = true;
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: (%pPA,%pPA)(%s) selected nhop interface %s addr %pPAs mod_val %u iter %d ecmp %d",
					__func__, &src, &grp_addr,
					pim->vrf->name, ifp->name, &nh_addr,
					mod_val, nh_iter, pim->ecmp_enable);
		}
		nh_iter++;
	}

	return found;
}

bool pim_nht_lookup_ecmp(struct pim_instance *pim, struct pim_nexthop *nexthop, pim_addr src,
			 struct prefix *grp, bool neighbor_needed)
{
	struct pim_nexthop_cache *pnc;
	int num_ifindex;
	bool found = false;
	uint16_t i = 0;
	uint32_t hash_val = 0;
	uint32_t mod_val = 0;
	uint32_t num_nbrs = 0;
	pim_addr group;
	struct zclient_next_hop_args args = {
		.pim = pim,
		.address = src,
#if PIM_IPV == 4
		.group = grp->u.prefix4,
#else
		.group = grp->u.prefix6,
#endif
	};

	group = pim_addr_from_prefix(grp);

	if (PIM_DEBUG_PIM_NHT_DETAIL)
		zlog_debug("%s: Looking up: %pPA(%s), last lookup time: %lld", __func__, &src,
			   pim->vrf->name, nexthop->last_lookup_time);

	pnc = pim_nexthop_cache_find(pim, src);
	if (pnc) {
		if (pim_nht_pnc_has_answer(pim, pnc, group))
			return pim_ecmp_nexthop_search(pim, pnc, nexthop, src, grp, neighbor_needed);
	}

	num_ifindex = zclient_lookup_nexthop(&args, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_warn("%s: could not find nexthop ifindex for address %pPA(%s)",
				  __func__, &src, pim->vrf->name);
		return false;
	}

	/* Count the number of neighbors for ECMP computation */
	for (i = 0; i < num_ifindex; i++) {
		struct pim_neighbor *nbr;
		struct interface *ifp = if_lookup_by_index(args.next_hops[i].ifindex,
							   pim->vrf->vrf_id);

		if (!ifp)
			continue;

		nbr = pim_neighbor_find(ifp, args.next_hops[i].nexthop_addr, true);
		if (nbr || pim_if_connected_to_source(ifp, src))
			num_nbrs++;
	}

	/* If PIM ECMP enable then choose ECMP path. */
	if (pim->ecmp_enable) {
		struct prefix src_pfx;
		uint32_t consider = num_ifindex;

		if (neighbor_needed && num_nbrs < consider)
			consider = num_nbrs;

		if (consider == 0)
			return false;

		pim_addr_to_prefix(&src_pfx, src);
		hash_val = pim_compute_ecmp_hash(&src_pfx, grp);
		mod_val = hash_val % consider;
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: hash_val %u mod_val %u", __func__, hash_val, mod_val);
	}

	for (i = 0; i < num_ifindex && !found; i++) {
		struct pim_neighbor *nbr = NULL;
		struct pim_interface *pim_ifp;
		struct interface *ifp = if_lookup_by_index(args.next_hops[i].ifindex,
							   pim->vrf->vrf_id);

		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug("%s %s: could not find interface for ifindex %d (address %pPA(%s))",
					   __FILE__, __func__, args.next_hops[i].ifindex, &src,
					   pim->vrf->name);
			if (i == mod_val)
				mod_val++;
			continue;
		}

		pim_ifp = ifp->info;

		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug("%s: pim not enabled on input interface %s(%s) (ifindex=%d, RPF for source %pPA)",
					   __func__, ifp->name, pim->vrf->name,
					   args.next_hops[i].ifindex, &src);
			if (i == mod_val)
				mod_val++;
			continue;
		}

		if (neighbor_needed && !pim_if_connected_to_source(ifp, src)) {
			nbr = pim_neighbor_find(ifp, args.next_hops[i].nexthop_addr, true);
			if (PIM_DEBUG_PIM_NHT_DETAIL)
				zlog_debug("ifp name: %s(%s), pim nbr: %p", ifp->name,
					   pim->vrf->name, nbr);
			if (!nbr && !if_is_loopback(ifp)) {
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug("%s: NBR (%pPA) not found on input interface %s(%s) (RPF for source %pPA)",
						   __func__, &args.next_hops[i].nexthop_addr,
						   ifp->name, pim->vrf->name, &src);
				if (i == mod_val)
					mod_val++;
				continue;
			}
		}

		if (i == mod_val) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug("%s: found nhop %pPA for addr %pPA interface %s(%s) metric %d dist %d",
					   __func__, &args.next_hops[i].nexthop_addr, &src,
					   ifp->name, pim->vrf->name, args.next_hops[i].route_metric,
					   args.next_hops[i].protocol_distance);
			/* update nexthop data */
			nexthop->interface = ifp;
			nexthop->mrib_nexthop_addr = args.next_hops[i].nexthop_addr;
			nexthop->mrib_metric_preference = args.next_hops[i].protocol_distance;
			nexthop->mrib_route_metric = args.next_hops[i].route_metric;
			nexthop->last_lookup = src;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = true;
		}
	}

	return found;
}

bool pim_nht_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop, pim_addr addr,
		    pim_addr group, bool neighbor_needed)
{
	struct pim_neighbor *nbr = NULL;
	int num_ifindex;
	struct interface *ifp = NULL;
	ifindex_t first_ifindex = 0;
	bool found = false;
	int i = 0;
	struct pim_interface *pim_ifp;
	struct zclient_next_hop_args args = {
		.pim = pim,
		.address = addr,
		.group = group,
	};

#if PIM_IPV == 4
	/*
	 * We should not attempt to lookup a
	 * 255.255.255.255 address, since
	 * it will never work
	 */
	if (pim_addr_is_any(addr))
		return false;
#endif

	if ((!pim_addr_cmp(nexthop->last_lookup, addr)) &&
	    (nexthop->last_lookup_time > pim->last_route_change_time)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug("%s: Using last lookup for %pPAs at %lld, %" PRId64 " addr %pPAs",
				   __func__, &addr, nexthop->last_lookup_time,
				   pim->last_route_change_time, &nexthop->mrib_nexthop_addr);
		pim->nexthop_lookups_avoided++;
		return true;
	}

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: Looking up: %pPAs, last lookup time: %lld, %" PRId64, __func__,
			   &addr, nexthop->last_lookup_time, pim->last_route_change_time);

	num_ifindex = zclient_lookup_nexthop(&args, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug("%s: could not find nexthop ifindex for address %pPAs", __func__,
				   &addr);
		return false;
	}

	while (!found && (i < num_ifindex)) {
		first_ifindex = args.next_hops[i].ifindex;

		ifp = if_lookup_by_index(first_ifindex, pim->vrf->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: could not find interface for ifindex %d (address %pPAs)",
					   __func__, first_ifindex, &addr);
			i++;
			continue;
		}

		pim_ifp = ifp->info;
		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: pim not enabled on input interface %s (ifindex=%d, RPF for source %pPAs)",
					   __func__, ifp->name, first_ifindex, &addr);
			i++;
		} else if (neighbor_needed && !pim_if_connected_to_source(ifp, addr)) {
			nbr = pim_neighbor_find(ifp, args.next_hops[i].nexthop_addr, true);
			if (PIM_DEBUG_PIM_TRACE_DETAIL)
				zlog_debug("ifp name: %s, pim nbr: %p", ifp->name, nbr);
			if (!nbr && !if_is_loopback(ifp))
				i++;
			else
				found = true;
		} else
			found = true;
	}

	if (found) {
		if (PIM_DEBUG_ZEBRA)
			zlog_debug("%s: found nexthop %pPAs for address %pPAs: interface %s ifindex=%d metric=%d pref=%d",
				   __func__, &args.next_hops[i].nexthop_addr, &addr, ifp->name,
				   first_ifindex, args.next_hops[i].route_metric,
				   args.next_hops[i].protocol_distance);

		/* update nexthop data */
		nexthop->interface = ifp;
		nexthop->mrib_nexthop_addr = args.next_hops[i].nexthop_addr;
		nexthop->mrib_metric_preference = args.next_hops[i].protocol_distance;
		nexthop->mrib_route_metric = args.next_hops[i].route_metric;
		nexthop->last_lookup = addr;
		nexthop->last_lookup_time = pim_time_monotonic_usec();
		nexthop->nbr = nbr;
		return true;
	} else
		return false;
}

int pim_nht_lookup_ecmp_if_vif_index(struct pim_instance *pim, pim_addr src, struct prefix *grp)
{
	struct pim_nexthop nhop;
	int vif_index;
	ifindex_t ifindex;

	memset(&nhop, 0, sizeof(nhop));
	if (!pim_nht_lookup_ecmp(pim, &nhop, src, grp, true)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug("%s: could not find nexthop ifindex for address %pPA(%s)",
				   __func__, &src, pim->vrf->name);
		return -1;
	}

	ifindex = nhop.interface->ifindex;
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: found nexthop ifindex=%d (interface %s(%s)) for address %pPA",
			   __func__, ifindex, ifindex2ifname(ifindex, pim->vrf->vrf_id),
			   pim->vrf->name, &src);

	vif_index = pim_if_find_vifindex_by_ifindex(pim, ifindex);

	if (vif_index < 0) {
		if (PIM_DEBUG_PIM_NHT) {
			zlog_debug("%s: low vif_index=%d(%s) < 1 nexthop for address %pPA",
				   __func__, vif_index, pim->vrf->name, &src);
		}
		return -2;
	}

	return vif_index;
}

/* This API is used to parse Registered address nexthop update coming from Zebra
 */
void pim_nexthop_update(struct vrf *vrf, struct prefix *match, struct zapi_route *nhr)
{
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache_rib *pnc_rib = NULL;
	struct interface *ifp = NULL;
	struct pim_instance *pim;
	pim_addr addr;

	pim = vrf->info;
	addr = pim_addr_from_prefix(match);
	pnc = pim_nexthop_cache_find(pim, addr);
	if (!pnc) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug("%s: Skipping NHT update, addr %pPA is not in local cached DB.",
				   __func__, &addr);
		return;
	}

	if (nhr->safi == SAFI_UNICAST)
		pnc_rib = &pnc->urib;
	else if (nhr->safi == SAFI_MULTICAST)
		pnc_rib = &pnc->mrib;
	else
		return;

	pnc_rib->last_update = pim_time_monotonic_usec();
	SET_FLAG(pnc_rib->flags, PIM_NEXTHOP_ANSWER_RECEIVED);
	UNSET_FLAG(pnc_rib->flags, PIM_NEXTHOP_VALID);
	pnc_rib->nexthop_num = 0;
	/* Free the existing nexthop list, resets with any valid nexthops from the update */
	nexthops_free(pnc_rib->nexthop);
	pnc_rib->nexthop = NULL;

	for (int i = 0; i < nhr->nexthop_num; i++) {
		struct nexthop *nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);

		switch (nexthop->type) {
		case NEXTHOP_TYPE_IFINDEX:
			/*
			 * Connected route (i.e. no nexthop), use
			 * RPF address from nexthop cache (i.e.
			 * destination) as PIM nexthop.
			 */
#if PIM_IPV == 4
			nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			nexthop->gate.ipv4 = pnc->addr;
#else
			nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			nexthop->gate.ipv6 = pnc->addr;
#endif
			break;

#if PIM_IPV == 4
		/* RFC5549 IPv4-over-IPv6 nexthop handling:
		 * if we get an IPv6 nexthop in IPv4 PIM, hunt down a
		 * PIM neighbor and use that instead.
		 */
		case NEXTHOP_TYPE_IPV6_IFINDEX: {
			struct pim_neighbor *nbr = NULL;
			struct interface *ifp1 = if_lookup_by_index(nexthop->ifindex,
								    pim->vrf->vrf_id);

			if (ifp1)
				/* FIXME: should really use nbr's
				 * secondary address list here
				 */
				nbr = pim_neighbor_find_if(ifp1);

			/* Overwrite with Nbr address as NH addr */
			if (nbr)
				nexthop->gate.ipv4 = nbr->source_addr;
			else
				/* Mark nexthop address to 0 until PIM Nbr is resolved. */
				nexthop->gate.ipv4 = PIMADDR_ANY;

			break;
		}
#else
		case NEXTHOP_TYPE_IPV6_IFINDEX:
#endif
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_BLACKHOLE:
			/* nothing to do for the other nexthop types */
			break;
		}

		ifp = if_lookup_by_index(nexthop->ifindex, pim->vrf->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT) {
				char buf[NEXTHOP_STRLEN];
				zlog_debug("%s: could not find interface for ifindex %d(%s) (addr %s)",
					   __func__, nexthop->ifindex, pim->vrf->name,
					   nexthop2str(nexthop, buf, sizeof(buf)));
			}
			nexthop_free(nexthop);
			continue;
		}

		if (PIM_DEBUG_PIM_NHT) {
#if PIM_IPV == 4
			pim_addr nhaddr = nexthop->gate.ipv4;
#else
			pim_addr nhaddr = nexthop->gate.ipv6;
#endif
			zlog_debug("%s: NHT addr %pFX(%s) %d-nhop via %pPA(%s) type %d distance:%u metric:%u ",
				   __func__, match, pim->vrf->name, i + 1, &nhaddr, ifp->name,
				   nexthop->type, nhr->distance, nhr->metric);
		}

		if (!ifp->info) {
			/*
			 * Though Multicast is not enabled on this
			 * Interface store it in database otheriwse we
			 * may miss this update and this will not cause
			 * any issue, because while choosing the path we
			 * are ommitting the Interfaces which are not
			 * multicast enabled
			 */
			if (PIM_DEBUG_PIM_NHT) {
				char buf[NEXTHOP_STRLEN];

				zlog_debug("%s: multicast not enabled on input interface %s(%s) (ifindex=%d, addr %s)",
					   __func__, ifp->name, pim->vrf->name, nexthop->ifindex,
					   nexthop2str(nexthop, buf, sizeof(buf)));
			}
		}

		if (nhlist_tail) {
			nhlist_tail->next = nexthop;
			nhlist_tail = nexthop;
		} else {
			nhlist_tail = nexthop;
			nhlist_head = nexthop;
		}

		/* Keep track of all nexthops, even PIM-disabled ones. */
		pnc_rib->nexthop_num++;
	} /* End for nexthops */

	/* Assign the list if there are nexthops */
	if (pnc_rib->nexthop_num) {
		SET_FLAG(pnc_rib->flags, PIM_NEXTHOP_VALID);
		pnc_rib->nexthop = nhlist_head;
		pnc_rib->distance = nhr->distance;
		pnc_rib->metric = nhr->metric;
		pnc_rib->prefix_len = nhr->prefix.prefixlen;
	}

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: NHT Update for %pFX(%s) num_nh %d num_pim_nh %d vrf:%u up %ld rp %d",
			   __func__, match, pim->vrf->name, nhr->nexthop_num, pnc_rib->nexthop_num,
			   vrf->vrf_id, pnc->upstream_hash->count, listcount(pnc->rp_list));

	pim_rpf_set_refresh_time(pim);

	if (listcount(pnc->rp_list))
		pim_update_rp_nh(pim, pnc);
	if (pnc->upstream_hash->count)
		pim_update_upstream_nh(pim, pnc);

	if (pnc->candrp_count)
		pim_crp_nht_update(pim, pnc);
}

/* Cleanup pim->nht_hash each node data */
static void pim_nht_hash_clean(void *data)
{
	struct pim_nexthop_cache *pnc = (struct pim_nexthop_cache *)data;

	list_delete(&pnc->rp_list);
	hash_clean_and_free(&pnc->upstream_hash, NULL);

	if (pnc->mrib.nexthop)
		nexthops_free(pnc->mrib.nexthop);

	if (pnc->urib.nexthop)
		nexthops_free(pnc->urib.nexthop);

	XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
}

static unsigned int pim_nht_hash_key(const void *arg)
{
	const struct pim_nexthop_cache *r = arg;

#if PIM_IPV == 4
	return jhash_1word(r->addr.s_addr, 0);
#else
	return jhash2(r->addr.s6_addr32, array_size(r->addr.s6_addr32), 0);
#endif
}

static bool pim_nht_equal(const void *arg1, const void *arg2)
{
	const struct pim_nexthop_cache *r1 = arg1;
	const struct pim_nexthop_cache *r2 = arg2;

	return (!pim_addr_cmp(r1->addr, r2->addr));
}

void pim_nht_init(struct pim_instance *pim)
{
	char hash_name[64];
	struct pim_lookup_mode *global_mode;

	snprintf(hash_name, sizeof(hash_name), "PIM %s NHT Hash", pim->vrf->name);
	pim->nht_hash = hash_create_size(256, pim_nht_hash_key, pim_nht_equal, hash_name);

	pim_lookup_mode_init(&(pim->rpf_mode));

	/* Add the default global mode */
	global_mode = XCALLOC(MTYPE_PIM_LOOKUP_MODE, sizeof(*global_mode));
	global_mode->grp_plist = NULL;
	global_mode->src_plist = NULL;
	global_mode->mode = MCAST_NO_CONFIG;
	pim_lookup_mode_add(&(pim->rpf_mode), global_mode);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: NHT hash init: %s ", __func__, hash_name);
}

void pim_nht_terminate(struct pim_instance *pim)
{
	/* Traverse and cleanup nht_hash */
	hash_clean_and_free(&pim->nht_hash, (void *)pim_nht_hash_clean);

	pim_lookup_mode_list_free(&(pim->rpf_mode));
	pim_lookup_mode_fini(&(pim->rpf_mode));
}
