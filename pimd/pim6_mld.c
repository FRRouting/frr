// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIMv6 MLD querier
 * Copyright (C) 2021-2022  David Lamparter for NetDEF, Inc.
 */

/*
 * keep pim6_mld.h open when working on this code.  Most data structures are
 * commented in the header.
 *
 * IPv4 support is pre-planned but hasn't been tackled yet.  It is intended
 * that this code will replace the old IGMP querier at some point.
 */

#include <zebra.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "lib/memory.h"
#include "lib/jhash.h"
#include "lib/prefix.h"
#include "lib/checksum.h"
#include "lib/frrevent.h"
#include "termtable.h"

#include "pimd/pim6_mld.h"
#include "pimd/pim6_mld_protocol.h"
#include "pimd/pim_memory.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_iface.h"
#include "pimd/pim6_cmd.h"
#include "pimd/pim_cmd_common.h"
#include "pimd/pim_util.h"
#include "pimd/pim_tib.h"
#include "pimd/pimd.h"

#ifndef IPV6_MULTICAST_ALL
#define IPV6_MULTICAST_ALL 29
#endif

DEFINE_MTYPE_STATIC(PIMD, GM_IFACE, "MLD interface");
DEFINE_MTYPE_STATIC(PIMD, GM_PACKET, "MLD packet");
DEFINE_MTYPE_STATIC(PIMD, GM_SUBSCRIBER, "MLD subscriber");
DEFINE_MTYPE_STATIC(PIMD, GM_STATE, "MLD subscription state");
DEFINE_MTYPE_STATIC(PIMD, GM_SG, "MLD (S,G)");
DEFINE_MTYPE_STATIC(PIMD, GM_GRP_PENDING, "MLD group query state");
DEFINE_MTYPE_STATIC(PIMD, GM_GSQ_PENDING, "MLD group/source query aggregate");

static void gm_t_query(struct event *t);
static void gm_trigger_specific(struct gm_sg *sg);
static void gm_sg_timer_start(struct gm_if *gm_ifp, struct gm_sg *sg,
			      struct timeval expire_wait);

/* shorthand for log messages */
#define log_ifp(msg)                                                           \
	"[MLD %s:%s] " msg, gm_ifp->ifp->vrf->name, gm_ifp->ifp->name
#define log_pkt_src(msg)                                                       \
	"[MLD %s:%s %pI6] " msg, gm_ifp->ifp->vrf->name, gm_ifp->ifp->name,    \
		&pkt_src->sin6_addr
#define log_sg(sg, msg)                                                        \
	"[MLD %s:%s %pSG] " msg, sg->iface->ifp->vrf->name,                    \
		sg->iface->ifp->name, &sg->sgaddr

/* clang-format off */
static const pim_addr gm_all_hosts = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	},
};
static const pim_addr gm_all_routers = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	},
};
/* MLDv1 does not allow subscriber tracking due to report suppression
 * hence, the source address is replaced with ffff:...:ffff
 */
static const pim_addr gm_dummy_untracked = {
	.s6_addr = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	},
};
/* clang-format on */

#define IPV6_MULTICAST_SCOPE_LINK 2

static inline uint8_t in6_multicast_scope(const pim_addr *addr)
{
	return addr->s6_addr[1] & 0xf;
}

bool in6_multicast_nofwd(const pim_addr *addr)
{
	return in6_multicast_scope(addr) <= IPV6_MULTICAST_SCOPE_LINK;
}

/*
 * (S,G) -> subscriber,(S,G)
 */

static int gm_packet_sg_cmp(const struct gm_packet_sg *a,
			    const struct gm_packet_sg *b)
{
	const struct gm_packet_state *s_a, *s_b;

	s_a = gm_packet_sg2state(a);
	s_b = gm_packet_sg2state(b);
	return IPV6_ADDR_CMP(&s_a->subscriber->addr, &s_b->subscriber->addr);
}

DECLARE_RBTREE_UNIQ(gm_packet_sg_subs, struct gm_packet_sg, subs_itm,
		    gm_packet_sg_cmp);

static struct gm_packet_sg *gm_packet_sg_find(struct gm_sg *sg,
					      enum gm_sub_sense sense,
					      struct gm_subscriber *sub)
{
	struct {
		struct gm_packet_state hdr;
		struct gm_packet_sg item;
	} ref = {
		/* clang-format off */
		.hdr = {
			.subscriber = sub,
		},
		.item = {
			.offset = 0,
		},
		/* clang-format on */
	};

	return gm_packet_sg_subs_find(&sg->subs[sense], &ref.item);
}

/*
 * interface -> (*,G),pending
 */

static int gm_grp_pending_cmp(const struct gm_grp_pending *a,
			      const struct gm_grp_pending *b)
{
	return IPV6_ADDR_CMP(&a->grp, &b->grp);
}

DECLARE_RBTREE_UNIQ(gm_grp_pends, struct gm_grp_pending, itm,
		    gm_grp_pending_cmp);

/*
 * interface -> ([S1,S2,...],G),pending
 */

static int gm_gsq_pending_cmp(const struct gm_gsq_pending *a,
			      const struct gm_gsq_pending *b)
{
	if (a->s_bit != b->s_bit)
		return numcmp(a->s_bit, b->s_bit);

	return IPV6_ADDR_CMP(&a->grp, &b->grp);
}

static uint32_t gm_gsq_pending_hash(const struct gm_gsq_pending *a)
{
	uint32_t seed = a->s_bit ? 0x68f0eb5e : 0x156b7f19;

	return jhash(&a->grp, sizeof(a->grp), seed);
}

DECLARE_HASH(gm_gsq_pends, struct gm_gsq_pending, itm, gm_gsq_pending_cmp,
	     gm_gsq_pending_hash);

/*
 * interface -> (S,G)
 */

int gm_sg_cmp(const struct gm_sg *a, const struct gm_sg *b)
{
	return pim_sgaddr_cmp(a->sgaddr, b->sgaddr);
}

static struct gm_sg *gm_sg_find(struct gm_if *gm_ifp, pim_addr grp,
				pim_addr src)
{
	struct gm_sg ref = {};

	ref.sgaddr.grp = grp;
	ref.sgaddr.src = src;
	return gm_sgs_find(gm_ifp->sgs, &ref);
}

static struct gm_sg *gm_sg_make(struct gm_if *gm_ifp, pim_addr grp,
				pim_addr src)
{
	struct gm_sg *ret, *prev;

	ret = XCALLOC(MTYPE_GM_SG, sizeof(*ret));
	ret->sgaddr.grp = grp;
	ret->sgaddr.src = src;
	ret->iface = gm_ifp;
	prev = gm_sgs_add(gm_ifp->sgs, ret);

	if (prev) {
		XFREE(MTYPE_GM_SG, ret);
		ret = prev;
	} else {
		monotime(&ret->created);
		gm_packet_sg_subs_init(ret->subs_positive);
		gm_packet_sg_subs_init(ret->subs_negative);
	}
	return ret;
}

/*
 * interface -> packets, sorted by expiry (because add_tail insert order)
 */

DECLARE_DLIST(gm_packet_expires, struct gm_packet_state, exp_itm);

/*
 * subscriber -> packets
 */

DECLARE_DLIST(gm_packets, struct gm_packet_state, pkt_itm);

/*
 * interface -> subscriber
 */

static int gm_subscriber_cmp(const struct gm_subscriber *a,
			     const struct gm_subscriber *b)
{
	return IPV6_ADDR_CMP(&a->addr, &b->addr);
}

static uint32_t gm_subscriber_hash(const struct gm_subscriber *a)
{
	return jhash(&a->addr, sizeof(a->addr), 0xd0e94ad4);
}

DECLARE_HASH(gm_subscribers, struct gm_subscriber, itm, gm_subscriber_cmp,
	     gm_subscriber_hash);

static struct gm_subscriber *gm_subscriber_findref(struct gm_if *gm_ifp,
						   pim_addr addr)
{
	struct gm_subscriber ref = {}, *ret;

	ref.addr = addr;
	ret = gm_subscribers_find(gm_ifp->subscribers, &ref);
	if (ret)
		ret->refcount++;
	return ret;
}

static struct gm_subscriber *gm_subscriber_get(struct gm_if *gm_ifp,
					       pim_addr addr)
{
	struct gm_subscriber ref = {}, *ret;

	ref.addr = addr;
	ret = gm_subscribers_find(gm_ifp->subscribers, &ref);

	if (!ret) {
		ret = XCALLOC(MTYPE_GM_SUBSCRIBER, sizeof(*ret));
		ret->iface = gm_ifp;
		ret->addr = addr;
		ret->refcount = 1;
		monotime(&ret->created);
		gm_packets_init(ret->packets);

		gm_subscribers_add(gm_ifp->subscribers, ret);
	}
	return ret;
}

static void gm_subscriber_drop(struct gm_subscriber **subp)
{
	struct gm_subscriber *sub = *subp;
	struct gm_if *gm_ifp;

	if (!sub)
		return;
	gm_ifp = sub->iface;

	*subp = NULL;
	sub->refcount--;

	if (sub->refcount)
		return;

	gm_subscribers_del(gm_ifp->subscribers, sub);
	XFREE(MTYPE_GM_SUBSCRIBER, sub);
}

/****************************************************************************/

/* bundle query timer values for combined v1/v2 handling */
struct gm_query_timers {
	unsigned int qrv;
	unsigned int max_resp_ms;
	unsigned int qqic_ms;

	struct timeval fuzz;
	struct timeval expire_wait;
};

static void gm_expiry_calc(struct gm_query_timers *timers)
{
	unsigned int expire =
		(timers->qrv - 1) * timers->qqic_ms + timers->max_resp_ms;
	ldiv_t exp_div = ldiv(expire, 1000);

	timers->expire_wait.tv_sec = exp_div.quot;
	timers->expire_wait.tv_usec = exp_div.rem * 1000;
	timeradd(&timers->expire_wait, &timers->fuzz, &timers->expire_wait);
}

static void gm_sg_free(struct gm_sg *sg)
{
	/* t_sg_expiry is handled before this is reached */
	EVENT_OFF(sg->t_sg_query);
	gm_packet_sg_subs_fini(sg->subs_negative);
	gm_packet_sg_subs_fini(sg->subs_positive);
	XFREE(MTYPE_GM_SG, sg);
}

/* clang-format off */
static const char *const gm_states[] = {
	[GM_SG_NOINFO]			= "NOINFO",
	[GM_SG_JOIN]			= "JOIN",
	[GM_SG_JOIN_EXPIRING]		= "JOIN_EXPIRING",
	[GM_SG_PRUNE]			= "PRUNE",
	[GM_SG_NOPRUNE]			= "NOPRUNE",
	[GM_SG_NOPRUNE_EXPIRING]	= "NOPRUNE_EXPIRING",
};
/* clang-format on */

/* TODO: S,G entries in EXCLUDE (i.e. prune) unsupported" */

/* tib_sg_gm_prune() below is an "un-join", it doesn't prune S,G when *,G is
 * joined.  Whether we actually want/need to support this is a separate
 * question - it is almost never used.  In fact this is exactly what RFC5790
 * ("lightweight" MLDv2) does:  it removes S,G EXCLUDE support.
 */

static void gm_sg_update(struct gm_sg *sg, bool has_expired)
{
	struct gm_if *gm_ifp = sg->iface;
	struct pim_interface *pim_ifp = gm_ifp->ifp->info;
	enum gm_sg_state prev, desired;
	bool new_join;
	struct gm_sg *grp = NULL;

	if (!pim_addr_is_any(sg->sgaddr.src))
		grp = gm_sg_find(gm_ifp, sg->sgaddr.grp, PIMADDR_ANY);
	else
		assert(sg->state != GM_SG_PRUNE);

	if (gm_packet_sg_subs_count(sg->subs_positive)) {
		desired = GM_SG_JOIN;
		assert(!sg->t_sg_expire);
	} else if ((sg->state == GM_SG_JOIN ||
		    sg->state == GM_SG_JOIN_EXPIRING) &&
		   !has_expired)
		desired = GM_SG_JOIN_EXPIRING;
	else if (!grp || !gm_packet_sg_subs_count(grp->subs_positive))
		desired = GM_SG_NOINFO;
	else if (gm_packet_sg_subs_count(grp->subs_positive) ==
		 gm_packet_sg_subs_count(sg->subs_negative)) {
		if ((sg->state == GM_SG_NOPRUNE ||
		     sg->state == GM_SG_NOPRUNE_EXPIRING) &&
		    !has_expired)
			desired = GM_SG_NOPRUNE_EXPIRING;
		else
			desired = GM_SG_PRUNE;
	} else if (gm_packet_sg_subs_count(sg->subs_negative))
		desired = GM_SG_NOPRUNE;
	else
		desired = GM_SG_NOINFO;

	if (desired != sg->state && !gm_ifp->stopping) {
		if (PIM_DEBUG_GM_EVENTS)
			zlog_debug(log_sg(sg, "%s => %s"), gm_states[sg->state],
				   gm_states[desired]);

		if (desired == GM_SG_JOIN_EXPIRING ||
		    desired == GM_SG_NOPRUNE_EXPIRING) {
			struct gm_query_timers timers;

			timers.qrv = gm_ifp->cur_qrv;
			timers.max_resp_ms = gm_ifp->cur_max_resp;
			timers.qqic_ms = gm_ifp->cur_query_intv_trig;
			timers.fuzz = gm_ifp->cfg_timing_fuzz;

			gm_expiry_calc(&timers);
			gm_sg_timer_start(gm_ifp, sg, timers.expire_wait);

			EVENT_OFF(sg->t_sg_query);
			sg->query_sbit = false;
			/* Trigger the specific queries only for querier. */
			if (IPV6_ADDR_SAME(&gm_ifp->querier, &pim_ifp->ll_lowest)) {
				sg->n_query = gm_ifp->cur_lmqc;
				gm_trigger_specific(sg);
			}
		}
	}
	prev = sg->state;
	sg->state = desired;

	if (in6_multicast_nofwd(&sg->sgaddr.grp) || gm_ifp->stopping)
		new_join = false;
	else
		new_join = gm_sg_state_want_join(desired);

	if (new_join && !sg->tib_joined) {
		/* this will retry if join previously failed */
		sg->tib_joined = tib_sg_gm_join(gm_ifp->pim, sg->sgaddr,
						gm_ifp->ifp, &sg->oil);
		if (!sg->tib_joined)
			zlog_warn(
				"MLD join for %pSG%%%s not propagated into TIB",
				&sg->sgaddr, gm_ifp->ifp->name);
		else
			zlog_info(log_ifp("%pSG%%%s TIB joined"), &sg->sgaddr,
				  gm_ifp->ifp->name);

	} else if (sg->tib_joined && !new_join) {
		tib_sg_gm_prune(gm_ifp->pim, sg->sgaddr, gm_ifp->ifp, &sg->oil);

		sg->oil = NULL;
		sg->tib_joined = false;
	}

	if (desired == GM_SG_NOINFO) {
		/* multiple paths can lead to the last state going away;
		 * t_sg_expire can still be running if we're arriving from
		 * another path.
		 */
		if (has_expired)
			EVENT_OFF(sg->t_sg_expire);

		assertf((!sg->t_sg_expire &&
			 !gm_packet_sg_subs_count(sg->subs_positive) &&
			 !gm_packet_sg_subs_count(sg->subs_negative)),
			"%pSG%%%s hx=%u exp=%pTHD state=%s->%s pos=%zu neg=%zu grp=%p",
			&sg->sgaddr, gm_ifp->ifp->name, has_expired,
			sg->t_sg_expire, gm_states[prev], gm_states[desired],
			gm_packet_sg_subs_count(sg->subs_positive),
			gm_packet_sg_subs_count(sg->subs_negative), grp);

		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(log_sg(sg, "dropping"));

		gm_sgs_del(gm_ifp->sgs, sg);
		gm_sg_free(sg);
	}
}

/****************************************************************************/

/* the following bunch of functions deals with transferring state from
 * received packets into gm_packet_state.  As a reminder, the querier is
 * structured to keep all items received in one packet together, since they
 * will share expiry timers and thus allows efficient handling.
 */

static void gm_packet_free(struct gm_packet_state *pkt)
{
	gm_packet_expires_del(pkt->iface->expires, pkt);
	gm_packets_del(pkt->subscriber->packets, pkt);
	gm_subscriber_drop(&pkt->subscriber);
	XFREE(MTYPE_GM_STATE, pkt);
}

static struct gm_packet_sg *gm_packet_sg_setup(struct gm_packet_state *pkt,
					       struct gm_sg *sg, bool is_excl,
					       bool is_src)
{
	struct gm_packet_sg *item;

	assert(pkt->n_active < pkt->n_sg);

	item = &pkt->items[pkt->n_active];
	item->sg = sg;
	item->is_excl = is_excl;
	item->is_src = is_src;
	item->offset = pkt->n_active;

	pkt->n_active++;
	return item;
}

static bool gm_packet_sg_drop(struct gm_packet_sg *item)
{
	struct gm_packet_state *pkt;
	size_t i;

	assert(item->sg);

	pkt = gm_packet_sg2state(item);
	if (item->sg->most_recent == item)
		item->sg->most_recent = NULL;

	for (i = 0; i < item->n_exclude; i++) {
		struct gm_packet_sg *excl_item;

		excl_item = item + 1 + i;
		if (!excl_item->sg)
			continue;

		gm_packet_sg_subs_del(excl_item->sg->subs_negative, excl_item);
		excl_item->sg = NULL;
		pkt->n_active--;

		assert(pkt->n_active > 0);
	}

	if (item->is_excl && item->is_src)
		gm_packet_sg_subs_del(item->sg->subs_negative, item);
	else
		gm_packet_sg_subs_del(item->sg->subs_positive, item);
	item->sg = NULL;
	pkt->n_active--;

	if (!pkt->n_active) {
		gm_packet_free(pkt);
		return true;
	}
	return false;
}

static void gm_packet_drop(struct gm_packet_state *pkt, bool trace)
{
	for (size_t i = 0; i < pkt->n_sg; i++) {
		struct gm_sg *sg = pkt->items[i].sg;
		bool deleted;

		if (!sg)
			continue;

		if (trace && PIM_DEBUG_GM_TRACE)
			zlog_debug(log_sg(sg, "general-dropping from %pPA"),
				   &pkt->subscriber->addr);
		deleted = gm_packet_sg_drop(&pkt->items[i]);

		gm_sg_update(sg, true);
		if (deleted)
			break;
	}
}

static void gm_packet_sg_remove_sources(struct gm_if *gm_ifp,
					struct gm_subscriber *subscriber,
					pim_addr grp, pim_addr *srcs,
					size_t n_src, enum gm_sub_sense sense)
{
	struct gm_sg *sg;
	struct gm_packet_sg *old_src;
	size_t i;

	for (i = 0; i < n_src; i++) {
		sg = gm_sg_find(gm_ifp, grp, srcs[i]);
		if (!sg)
			continue;

		old_src = gm_packet_sg_find(sg, sense, subscriber);
		if (!old_src)
			continue;

		gm_packet_sg_drop(old_src);
		gm_sg_update(sg, false);
	}
}

static void gm_sg_expiry_cancel(struct gm_sg *sg)
{
	if (sg->t_sg_expire && PIM_DEBUG_GM_TRACE)
		zlog_debug(log_sg(sg, "alive, cancelling expiry timer"));
	EVENT_OFF(sg->t_sg_expire);
	sg->query_sbit = true;
}

/* first pass: process all changes resulting in removal of state:
 *  - {TO,IS}_INCLUDE removes *,G EXCLUDE state (and S,G)
 *  - ALLOW_NEW_SOURCES, if *,G in EXCLUDE removes S,G state
 *  - BLOCK_OLD_SOURCES, if *,G in INCLUDE removes S,G state
 *  - {TO,IS}_EXCLUDE,   if *,G in INCLUDE removes S,G state
 * note *replacing* state is NOT considered *removing* state here
 *
 * everything else is thrown into pkt for creation of state in pass 2
 */
static void gm_handle_v2_pass1(struct gm_packet_state *pkt,
			       struct mld_v2_rec_hdr *rechdr, size_t n_src)
{
	/* NB: pkt->subscriber can be NULL here if the subscriber was not
	 * previously seen!
	 */
	struct gm_subscriber *subscriber = pkt->subscriber;
	struct gm_sg *grp;
	struct gm_packet_sg *old_grp = NULL;
	struct gm_packet_sg *item;
	size_t j;
	bool is_excl = false;

	grp = gm_sg_find(pkt->iface, rechdr->grp, PIMADDR_ANY);
	if (grp && subscriber)
		old_grp = gm_packet_sg_find(grp, GM_SUB_POS, subscriber);

	assert(old_grp == NULL || old_grp->is_excl);

	switch (rechdr->type) {
	case MLD_RECTYPE_IS_EXCLUDE:
	case MLD_RECTYPE_CHANGE_TO_EXCLUDE:
		/* this always replaces or creates state */
		is_excl = true;
		if (!grp)
			grp = gm_sg_make(pkt->iface, rechdr->grp, PIMADDR_ANY);

		item = gm_packet_sg_setup(pkt, grp, is_excl, false);
		item->n_exclude = n_src;

		/* [EXCL_INCL_SG_NOTE] referenced below
		 *
		 * in theory, we should drop any S,G that the host may have
		 * previously added in INCLUDE mode.  In practice, this is both
		 * incredibly rare and entirely irrelevant.  It only makes any
		 * difference if an S,G that the host previously had on the
		 * INCLUDE list is now on the blocked list for EXCLUDE, which
		 * we can cover in processing the S,G list in pass2_excl().
		 *
		 * Other S,G from the host are simply left to expire
		 * "naturally" through general expiry.
		 */
		break;

	case MLD_RECTYPE_IS_INCLUDE:
	case MLD_RECTYPE_CHANGE_TO_INCLUDE:
		if (old_grp) {
			/* INCLUDE has no *,G state, so old_grp here refers to
			 * previous EXCLUDE => delete it
			 */
			gm_packet_sg_drop(old_grp);
			gm_sg_update(grp, false);
/* TODO "need S,G PRUNE => NO_INFO transition here" */
		}
		break;

	case MLD_RECTYPE_ALLOW_NEW_SOURCES:
		if (old_grp) {
			/* remove S,Gs from EXCLUDE, and then we're done */
			gm_packet_sg_remove_sources(pkt->iface, subscriber,
						    rechdr->grp, rechdr->srcs,
						    n_src, GM_SUB_NEG);
			return;
		}
		/* in INCLUDE mode => ALLOW_NEW_SOURCES is functionally
		 * idential to IS_INCLUDE (because the list of sources in
		 * IS_INCLUDE is not exhaustive)
		 */
		break;

	case MLD_RECTYPE_BLOCK_OLD_SOURCES:
		if (old_grp) {
			/* this is intentionally not implemented because it
			 * would be complicated as hell.  we only take the list
			 * of blocked sources from full group state records
			 */
			return;
		}

		if (subscriber)
			gm_packet_sg_remove_sources(pkt->iface, subscriber,
						    rechdr->grp, rechdr->srcs,
						    n_src, GM_SUB_POS);
		return;
	}

	for (j = 0; j < n_src; j++) {
		struct gm_sg *sg;

		sg = gm_sg_find(pkt->iface, rechdr->grp, rechdr->srcs[j]);
		if (!sg)
			sg = gm_sg_make(pkt->iface, rechdr->grp,
					rechdr->srcs[j]);

		gm_packet_sg_setup(pkt, sg, is_excl, true);
	}
}

/* second pass: creating/updating/refreshing state.  All the items from the
 * received packet have already been thrown into gm_packet_state.
 */

static void gm_handle_v2_pass2_incl(struct gm_packet_state *pkt, size_t i)
{
	struct gm_packet_sg *item = &pkt->items[i];
	struct gm_packet_sg *old = NULL;
	struct gm_sg *sg = item->sg;

	/* EXCLUDE state was already dropped in pass1 */
	assert(!gm_packet_sg_find(sg, GM_SUB_NEG, pkt->subscriber));

	old = gm_packet_sg_find(sg, GM_SUB_POS, pkt->subscriber);
	if (old)
		gm_packet_sg_drop(old);

	pkt->n_active++;
	gm_packet_sg_subs_add(sg->subs_positive, item);

	sg->most_recent = item;
	gm_sg_expiry_cancel(sg);
	gm_sg_update(sg, false);
}

static void gm_handle_v2_pass2_excl(struct gm_packet_state *pkt, size_t offs)
{
	struct gm_packet_sg *item = &pkt->items[offs];
	struct gm_packet_sg *old_grp, *item_dup;
	struct gm_sg *sg_grp = item->sg;
	size_t i;

	old_grp = gm_packet_sg_find(sg_grp, GM_SUB_POS, pkt->subscriber);
	if (old_grp) {
		for (i = 0; i < item->n_exclude; i++) {
			struct gm_packet_sg *item_src, *old_src;

			item_src = &pkt->items[offs + 1 + i];
			old_src = gm_packet_sg_find(item_src->sg, GM_SUB_NEG,
						    pkt->subscriber);
			if (old_src)
				gm_packet_sg_drop(old_src);

			/* See [EXCL_INCL_SG_NOTE] above - we can have old S,G
			 * items left over if the host previously had INCLUDE
			 * mode going.  Remove them here if we find any.
			 */
			old_src = gm_packet_sg_find(item_src->sg, GM_SUB_POS,
						    pkt->subscriber);
			if (old_src)
				gm_packet_sg_drop(old_src);
		}

		/* the previous loop has removed the S,G entries which are
		 * still excluded after this update.  So anything left on the
		 * old item was previously excluded but is now included
		 * => need to trigger update on S,G
		 */
		for (i = 0; i < old_grp->n_exclude; i++) {
			struct gm_packet_sg *old_src;
			struct gm_sg *old_sg_src;

			old_src = old_grp + 1 + i;
			old_sg_src = old_src->sg;
			if (!old_sg_src)
				continue;

			gm_packet_sg_drop(old_src);
			gm_sg_update(old_sg_src, false);
		}

		gm_packet_sg_drop(old_grp);
	}

	item_dup = gm_packet_sg_subs_add(sg_grp->subs_positive, item);
	assert(!item_dup);
	pkt->n_active++;

	sg_grp->most_recent = item;
	gm_sg_expiry_cancel(sg_grp);

	for (i = 0; i < item->n_exclude; i++) {
		struct gm_packet_sg *item_src;

		item_src = &pkt->items[offs + 1 + i];
		item_dup = gm_packet_sg_subs_add(item_src->sg->subs_negative,
						 item_src);

		if (item_dup)
			item_src->sg = NULL;
		else {
			pkt->n_active++;
			gm_sg_update(item_src->sg, false);
		}
	}

	/* TODO: determine best ordering between gm_sg_update(S,G) and (*,G)
	 * to get lower PIM churn/flapping
	 */
	gm_sg_update(sg_grp, false);
}

/* TODO: QRV/QQIC are not copied from queries to local state" */

/* on receiving a query, we need to update our robustness/query interval to
 * match, so we correctly process group/source specific queries after last
 * member leaves
 */

static void gm_handle_v2_report(struct gm_if *gm_ifp,
				const struct sockaddr_in6 *pkt_src, char *data,
				size_t len)
{
	struct mld_v2_report_hdr *hdr;
	size_t i, n_records, max_entries;
	struct gm_packet_state *pkt;

	if (len < sizeof(*hdr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(log_pkt_src(
				"malformed MLDv2 report (truncated header)"));
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	hdr = (struct mld_v2_report_hdr *)data;
	data += sizeof(*hdr);
	len -= sizeof(*hdr);

	n_records = ntohs(hdr->n_records);
	if (n_records > len / sizeof(struct mld_v2_rec_hdr)) {
		/* note this is only an upper bound, records with source lists
		 * are larger.  This is mostly here to make coverity happy.
		 */
		zlog_warn(log_pkt_src(
			"malformed MLDv2 report (infeasible record count)"));
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	/* errors after this may at least partially process the packet */
	gm_ifp->stats.rx_new_report++;

	/* can't have more *,G and S,G items than there is space for ipv6
	 * addresses, so just use this to allocate temporary buffer
	 */
	max_entries = len / sizeof(pim_addr);
	pkt = XCALLOC(MTYPE_GM_STATE,
		      offsetof(struct gm_packet_state, items[max_entries]));
	pkt->n_sg = max_entries;
	pkt->iface = gm_ifp;
	pkt->subscriber = gm_subscriber_findref(gm_ifp, pkt_src->sin6_addr);

	/* validate & remove state in v2_pass1() */
	for (i = 0; i < n_records; i++) {
		struct mld_v2_rec_hdr *rechdr;
		size_t n_src, record_size;

		if (len < sizeof(*rechdr)) {
			zlog_warn(log_pkt_src(
				"malformed MLDv2 report (truncated record header)"));
			gm_ifp->stats.rx_trunc_report++;
			break;
		}

		rechdr = (struct mld_v2_rec_hdr *)data;
		data += sizeof(*rechdr);
		len -= sizeof(*rechdr);

		n_src = ntohs(rechdr->n_src);
		record_size = n_src * sizeof(pim_addr) + rechdr->aux_len * 4;

		if (len < record_size) {
			zlog_warn(log_pkt_src(
				"malformed MLDv2 report (truncated source list)"));
			gm_ifp->stats.rx_trunc_report++;
			break;
		}
		if (!IN6_IS_ADDR_MULTICAST(&rechdr->grp)) {
			zlog_warn(
				log_pkt_src(
					"malformed MLDv2 report (invalid group %pI6)"),
				&rechdr->grp);
			gm_ifp->stats.rx_trunc_report++;
			break;
		}

		data += record_size;
		len -= record_size;

		gm_handle_v2_pass1(pkt, rechdr, n_src);
	}

	if (!pkt->n_active) {
		gm_subscriber_drop(&pkt->subscriber);
		XFREE(MTYPE_GM_STATE, pkt);
		return;
	}

	pkt = XREALLOC(MTYPE_GM_STATE, pkt,
		       offsetof(struct gm_packet_state, items[pkt->n_active]));
	pkt->n_sg = pkt->n_active;
	pkt->n_active = 0;

	monotime(&pkt->received);
	if (!pkt->subscriber)
		pkt->subscriber = gm_subscriber_get(gm_ifp, pkt_src->sin6_addr);
	gm_packets_add_tail(pkt->subscriber->packets, pkt);
	gm_packet_expires_add_tail(gm_ifp->expires, pkt);

	for (i = 0; i < pkt->n_sg; i++)
		if (!pkt->items[i].is_excl)
			gm_handle_v2_pass2_incl(pkt, i);
		else {
			gm_handle_v2_pass2_excl(pkt, i);
			i += pkt->items[i].n_exclude;
		}

	if (pkt->n_active == 0)
		gm_packet_free(pkt);
}

static void gm_handle_v1_report(struct gm_if *gm_ifp,
				const struct sockaddr_in6 *pkt_src, char *data,
				size_t len)
{
	struct mld_v1_pkt *hdr;
	struct gm_packet_state *pkt;
	struct gm_sg *grp;
	struct gm_packet_sg *item;
	size_t max_entries;

	if (len < sizeof(*hdr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(log_pkt_src(
				"malformed MLDv1 report (truncated)"));
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	gm_ifp->stats.rx_old_report++;

	hdr = (struct mld_v1_pkt *)data;

	max_entries = 1;
	pkt = XCALLOC(MTYPE_GM_STATE,
		      offsetof(struct gm_packet_state, items[max_entries]));
	pkt->n_sg = max_entries;
	pkt->iface = gm_ifp;
	pkt->subscriber = gm_subscriber_findref(gm_ifp, gm_dummy_untracked);

	/* { equivalent of gm_handle_v2_pass1() with IS_EXCLUDE */

	grp = gm_sg_find(pkt->iface, hdr->grp, PIMADDR_ANY);
	if (!grp)
		grp = gm_sg_make(pkt->iface, hdr->grp, PIMADDR_ANY);

	item = gm_packet_sg_setup(pkt, grp, true, false);
	item->n_exclude = 0;

/* TODO "set v1-seen timer on grp here" */

	/* } */

	/* pass2 will count n_active back up to 1.  Also since a v1 report
	 * has exactly 1 group, we can skip the realloc() that v2 needs here.
	 */
	assert(pkt->n_active == 1);
	pkt->n_sg = pkt->n_active;
	pkt->n_active = 0;

	monotime(&pkt->received);
	if (!pkt->subscriber)
		pkt->subscriber = gm_subscriber_get(gm_ifp, gm_dummy_untracked);
	gm_packets_add_tail(pkt->subscriber->packets, pkt);
	gm_packet_expires_add_tail(gm_ifp->expires, pkt);

	/* pass2 covers installing state & removing old state;  all the v1
	 * compat is handled at this point.
	 *
	 * Note that "old state" may be v2;  subscribers will switch from v2
	 * reports to v1 reports when the querier changes from v2 to v1.  So,
	 * limiting this to v1 would be wrong.
	 */
	gm_handle_v2_pass2_excl(pkt, 0);

	if (pkt->n_active == 0)
		gm_packet_free(pkt);
}

static void gm_handle_v1_leave(struct gm_if *gm_ifp,
			       const struct sockaddr_in6 *pkt_src, char *data,
			       size_t len)
{
	struct mld_v1_pkt *hdr;
	struct gm_subscriber *subscriber;
	struct gm_sg *grp;
	struct gm_packet_sg *old_grp;

	if (len < sizeof(*hdr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(log_pkt_src(
				"malformed MLDv1 leave (truncated)"));
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	gm_ifp->stats.rx_old_leave++;

	hdr = (struct mld_v1_pkt *)data;

	subscriber = gm_subscriber_findref(gm_ifp, gm_dummy_untracked);
	if (!subscriber)
		return;

	/* { equivalent of gm_handle_v2_pass1() with IS_INCLUDE */

	grp = gm_sg_find(gm_ifp, hdr->grp, PIMADDR_ANY);
	if (grp) {
		old_grp = gm_packet_sg_find(grp, GM_SUB_POS, subscriber);
		if (old_grp) {
			gm_packet_sg_drop(old_grp);
			gm_sg_update(grp, false);

/* TODO "need S,G PRUNE => NO_INFO transition here" */

		}
	}

	/* } */

	/* nothing more to do here, pass2 is no-op for leaves */
	gm_subscriber_drop(&subscriber);
}

/* for each general query received (or sent), a timer is started to expire
 * _everything_ at the appropriate time (including robustness multiplier).
 *
 * So when this timer hits, all packets - with all of their items - that were
 * received *before* the query are aged out, and state updated accordingly.
 * Note that when we receive a refresh/update, the previous/old packet is
 * already dropped and replaced with a new one, so in normal steady-state
 * operation, this timer won't be doing anything.
 *
 * Additionally, if a subscriber actively leaves a group, that goes through
 * its own path too and won't hit this.  This is really only triggered when a
 * host straight up disappears.
 */
static void gm_t_expire(struct event *t)
{
	struct gm_if *gm_ifp = EVENT_ARG(t);
	struct gm_packet_state *pkt;

	zlog_info(log_ifp("general expiry timer"));

	while (gm_ifp->n_pending) {
		struct gm_general_pending *pend = gm_ifp->pending;
		struct timeval remain;
		int64_t remain_ms;

		remain_ms = monotime_until(&pend->expiry, &remain);
		if (remain_ms > 0) {
			if (PIM_DEBUG_GM_EVENTS)
				zlog_debug(
					log_ifp("next general expiry in %" PRId64 "ms"),
					remain_ms / 1000);

			event_add_timer_tv(router->master, gm_t_expire, gm_ifp,
					   &remain, &gm_ifp->t_expire);
			return;
		}

		while ((pkt = gm_packet_expires_first(gm_ifp->expires))) {
			if (timercmp(&pkt->received, &pend->query, >=))
				break;

			if (PIM_DEBUG_GM_PACKETS)
				zlog_debug(log_ifp("expire packet %p"), pkt);
			gm_packet_drop(pkt, true);
		}

		gm_ifp->n_pending--;
		memmove(gm_ifp->pending, gm_ifp->pending + 1,
			gm_ifp->n_pending * sizeof(gm_ifp->pending[0]));
	}

	if (PIM_DEBUG_GM_EVENTS)
		zlog_debug(log_ifp("next general expiry waiting for query"));
}

/* NB: the receive handlers will also run when sending packets, since we
 * receive our own packets back in.
 */
static void gm_handle_q_general(struct gm_if *gm_ifp,
				struct gm_query_timers *timers)
{
	struct timeval now, expiry;
	struct gm_general_pending *pend;

	monotime(&now);
	timeradd(&now, &timers->expire_wait, &expiry);

	while (gm_ifp->n_pending) {
		pend = &gm_ifp->pending[gm_ifp->n_pending - 1];

		if (timercmp(&pend->expiry, &expiry, <))
			break;

		/* if we end up here, the last item in pending[] has an expiry
		 * later than the expiry for this query.  But our query time
		 * (now) is later than that of the item (because, well, that's
		 * how time works.)  This makes this query meaningless since
		 * it's "supersetted" within the preexisting query
		 */

		if (PIM_DEBUG_GM_TRACE_DETAIL)
			zlog_debug(
				log_ifp("zapping supersetted general timer %pTVMu"),
				&pend->expiry);

		gm_ifp->n_pending--;
		if (!gm_ifp->n_pending)
			EVENT_OFF(gm_ifp->t_expire);
	}

	/* people might be messing with their configs or something */
	if (gm_ifp->n_pending == array_size(gm_ifp->pending))
		return;

	pend = &gm_ifp->pending[gm_ifp->n_pending];
	pend->query = now;
	pend->expiry = expiry;

	if (!gm_ifp->n_pending++) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				log_ifp("starting general timer @ 0: %pTVMu"),
				&pend->expiry);
		event_add_timer_tv(router->master, gm_t_expire, gm_ifp,
				   &timers->expire_wait, &gm_ifp->t_expire);
	} else if (PIM_DEBUG_GM_TRACE)
		zlog_debug(log_ifp("appending general timer @ %u: %pTVMu"),
			   gm_ifp->n_pending, &pend->expiry);
}

static void gm_t_sg_expire(struct event *t)
{
	struct gm_sg *sg = EVENT_ARG(t);
	struct gm_if *gm_ifp = sg->iface;
	struct gm_packet_sg *item;

	assertf(sg->state == GM_SG_JOIN_EXPIRING ||
			sg->state == GM_SG_NOPRUNE_EXPIRING,
		"%pSG%%%s %pTHD", &sg->sgaddr, gm_ifp->ifp->name, t);

	frr_each_safe (gm_packet_sg_subs, sg->subs_positive, item)
		/* this will also drop EXCLUDE mode S,G lists together with
		 * the *,G entry
		 */
		gm_packet_sg_drop(item);

	/* subs_negative items are only timed out together with the *,G entry
	 * since we won't get any reports for a group-and-source query
	 */
	gm_sg_update(sg, true);
}

static bool gm_sg_check_recent(struct gm_if *gm_ifp, struct gm_sg *sg,
			       struct timeval ref)
{
	struct gm_packet_state *pkt;

	if (!sg->most_recent) {
		struct gm_packet_state *best_pkt = NULL;
		struct gm_packet_sg *item;

		frr_each (gm_packet_sg_subs, sg->subs_positive, item) {
			pkt = gm_packet_sg2state(item);

			if (!best_pkt ||
			    timercmp(&pkt->received, &best_pkt->received, >)) {
				best_pkt = pkt;
				sg->most_recent = item;
			}
		}
	}
	if (sg->most_recent) {
		struct timeval fuzz;

		pkt = gm_packet_sg2state(sg->most_recent);

		/* this shouldn't happen on plain old real ethernet segment,
		 * but on something like a VXLAN or VPLS it is very possible
		 * that we get a report before the query that triggered it.
		 * (imagine a triangle scenario with 3 datacenters, it's very
		 * possible A->B + B->C is faster than A->C due to odd routing)
		 *
		 * This makes a little tolerance allowance to handle that case.
		 */
		timeradd(&pkt->received, &gm_ifp->cfg_timing_fuzz, &fuzz);

		if (timercmp(&fuzz, &ref, >))
			return true;
	}
	return false;
}

static void gm_sg_timer_start(struct gm_if *gm_ifp, struct gm_sg *sg,
			      struct timeval expire_wait)
{
	struct timeval now;

	if (!sg)
		return;
	if (sg->state == GM_SG_PRUNE)
		return;

	monotime(&now);
	if (gm_sg_check_recent(gm_ifp, sg, now))
		return;

	if (PIM_DEBUG_GM_TRACE)
		zlog_debug(log_sg(sg, "expiring in %pTVI"), &expire_wait);

	if (sg->t_sg_expire) {
		struct timeval remain;

		remain = event_timer_remain(sg->t_sg_expire);
		if (timercmp(&remain, &expire_wait, <=))
			return;

		EVENT_OFF(sg->t_sg_expire);
	}

	event_add_timer_tv(router->master, gm_t_sg_expire, sg, &expire_wait,
			   &sg->t_sg_expire);
}

static void gm_handle_q_groupsrc(struct gm_if *gm_ifp,
				 struct gm_query_timers *timers, pim_addr grp,
				 const pim_addr *srcs, size_t n_src)
{
	struct gm_sg *sg;
	size_t i;

	for (i = 0; i < n_src; i++) {
		sg = gm_sg_find(gm_ifp, grp, srcs[i]);
		GM_UPDATE_SG_STATE(sg);
		gm_sg_timer_start(gm_ifp, sg, timers->expire_wait);
	}
}

static void gm_t_grp_expire(struct event *t)
{
	/* if we're here, that means when we received the group-specific query
	 * there was one or more active S,G for this group.  For *,G the timer
	 * in sg->t_sg_expire is running separately and gets cancelled when we
	 * receive a report, so that work is left to gm_t_sg_expire and we
	 * shouldn't worry about it here.
	 */
	struct gm_grp_pending *pend = EVENT_ARG(t);
	struct gm_if *gm_ifp = pend->iface;
	struct gm_sg *sg, *sg_start, sg_ref = {};

	if (PIM_DEBUG_GM_EVENTS)
		zlog_debug(log_ifp("*,%pPAs S,G timer expired"), &pend->grp);

	/* gteq lookup - try to find *,G or S,G  (S,G is > *,G)
	 * could technically be gt to skip a possible *,G
	 */
	sg_ref.sgaddr.grp = pend->grp;
	sg_ref.sgaddr.src = PIMADDR_ANY;
	sg_start = gm_sgs_find_gteq(gm_ifp->sgs, &sg_ref);

	frr_each_from (gm_sgs, gm_ifp->sgs, sg, sg_start) {
		struct gm_packet_sg *item;

		if (pim_addr_cmp(sg->sgaddr.grp, pend->grp))
			break;
		if (pim_addr_is_any(sg->sgaddr.src))
			/* handled by gm_t_sg_expire / sg->t_sg_expire */
			continue;
		if (gm_sg_check_recent(gm_ifp, sg, pend->query))
			continue;

		/* we may also have a group-source-specific query going on in
		 * parallel.  But if we received nothing for the *,G query,
		 * the S,G query is kinda irrelevant.
		 */
		EVENT_OFF(sg->t_sg_expire);

		frr_each_safe (gm_packet_sg_subs, sg->subs_positive, item)
			/* this will also drop the EXCLUDE S,G lists */
			gm_packet_sg_drop(item);

		gm_sg_update(sg, true);
	}

	gm_grp_pends_del(gm_ifp->grp_pends, pend);
	XFREE(MTYPE_GM_GRP_PENDING, pend);
}

static void gm_handle_q_group(struct gm_if *gm_ifp,
			      struct gm_query_timers *timers, pim_addr grp)
{
	struct gm_sg *sg, sg_ref = {};
	struct gm_grp_pending *pend, pend_ref = {};

	sg_ref.sgaddr.grp = grp;
	sg_ref.sgaddr.src = PIMADDR_ANY;
	/* gteq lookup - try to find *,G or S,G  (S,G is > *,G) */
	sg = gm_sgs_find_gteq(gm_ifp->sgs, &sg_ref);

	if (!sg || pim_addr_cmp(sg->sgaddr.grp, grp))
		/* we have nothing at all for this group - don't waste RAM */
		return;

	if (pim_addr_is_any(sg->sgaddr.src)) {
		/* actually found *,G entry here */
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(log_ifp("*,%pPAs expiry timer starting"),
				   &grp);
		GM_UPDATE_SG_STATE(sg);
		gm_sg_timer_start(gm_ifp, sg, timers->expire_wait);

		sg = gm_sgs_next(gm_ifp->sgs, sg);
		if (!sg || pim_addr_cmp(sg->sgaddr.grp, grp))
			/* no S,G for this group */
			return;
	}

	pend_ref.grp = grp;
	pend = gm_grp_pends_find(gm_ifp->grp_pends, &pend_ref);

	if (pend) {
		struct timeval remain;

		remain = event_timer_remain(pend->t_expire);
		if (timercmp(&remain, &timers->expire_wait, <=))
			return;

		EVENT_OFF(pend->t_expire);
	} else {
		pend = XCALLOC(MTYPE_GM_GRP_PENDING, sizeof(*pend));
		pend->grp = grp;
		pend->iface = gm_ifp;
		gm_grp_pends_add(gm_ifp->grp_pends, pend);
	}

	monotime(&pend->query);
	event_add_timer_tv(router->master, gm_t_grp_expire, pend,
			   &timers->expire_wait, &pend->t_expire);

	if (PIM_DEBUG_GM_TRACE)
		zlog_debug(log_ifp("*,%pPAs S,G timer started: %pTHD"), &grp,
			   pend->t_expire);
}

static void gm_bump_querier(struct gm_if *gm_ifp)
{
	struct pim_interface *pim_ifp = gm_ifp->ifp->info;

	EVENT_OFF(gm_ifp->t_query);

	if (pim_addr_is_any(pim_ifp->ll_lowest))
		return;
	if (!IPV6_ADDR_SAME(&gm_ifp->querier, &pim_ifp->ll_lowest))
		return;

	gm_ifp->n_startup = gm_ifp->cur_qrv;

	event_execute(router->master, gm_t_query, gm_ifp, 0, NULL);
}

static void gm_t_other_querier(struct event *t)
{
	struct gm_if *gm_ifp = EVENT_ARG(t);
	struct pim_interface *pim_ifp = gm_ifp->ifp->info;

	zlog_info(log_ifp("other querier timer expired"));

	gm_ifp->querier = pim_ifp->ll_lowest;
	gm_ifp->n_startup = gm_ifp->cur_qrv;

	event_execute(router->master, gm_t_query, gm_ifp, 0, NULL);
}

static void gm_handle_query(struct gm_if *gm_ifp,
			    const struct sockaddr_in6 *pkt_src,
			    pim_addr *pkt_dst, char *data, size_t len)
{
	struct mld_v2_query_hdr *hdr;
	struct pim_interface *pim_ifp = gm_ifp->ifp->info;
	struct gm_query_timers timers;
	bool general_query;

	if (len < sizeof(struct mld_v2_query_hdr) &&
	    len != sizeof(struct mld_v1_pkt)) {
		zlog_warn(log_pkt_src("invalid query size"));
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	hdr = (struct mld_v2_query_hdr *)data;
	general_query = pim_addr_is_any(hdr->grp);

	if (!general_query && !IN6_IS_ADDR_MULTICAST(&hdr->grp)) {
		zlog_warn(log_pkt_src(
				  "malformed MLDv2 query (invalid group %pI6)"),
			  &hdr->grp);
		gm_ifp->stats.rx_drop_malformed++;
		return;
	}

	if (len >= sizeof(struct mld_v2_query_hdr)) {
		size_t src_space = ntohs(hdr->n_src) * sizeof(pim_addr);

		if (len < sizeof(struct mld_v2_query_hdr) + src_space) {
			zlog_warn(log_pkt_src(
				"malformed MLDv2 query (truncated source list)"));
			gm_ifp->stats.rx_drop_malformed++;
			return;
		}

		if (general_query && src_space) {
			zlog_warn(log_pkt_src(
				"malformed MLDv2 query (general query with non-empty source list)"));
			gm_ifp->stats.rx_drop_malformed++;
			return;
		}
	}

	/* accepting queries unicast to us (or addressed to a wrong group)
	 * can mess up querier election as well as cause us to terminate
	 * traffic (since after a unicast query no reports will be coming in)
	 */
	if (!IPV6_ADDR_SAME(pkt_dst, &gm_all_hosts)) {
		if (pim_addr_is_any(hdr->grp)) {
			zlog_warn(
				log_pkt_src(
					"wrong destination %pPA for general query"),
				pkt_dst);
			gm_ifp->stats.rx_drop_dstaddr++;
			return;
		}

		if (!IPV6_ADDR_SAME(&hdr->grp, pkt_dst)) {
			gm_ifp->stats.rx_drop_dstaddr++;
			zlog_warn(
				log_pkt_src(
					"wrong destination %pPA for group specific query"),
				pkt_dst);
			return;
		}
	}

	if (IPV6_ADDR_CMP(&pkt_src->sin6_addr, &gm_ifp->querier) < 0) {
		if (PIM_DEBUG_GM_EVENTS)
			zlog_debug(
				log_pkt_src("replacing elected querier %pPA"),
				&gm_ifp->querier);

		gm_ifp->querier = pkt_src->sin6_addr;
	}

	if (len == sizeof(struct mld_v1_pkt)) {
		timers.qrv = gm_ifp->cur_qrv;
		timers.max_resp_ms = hdr->max_resp_code;
		timers.qqic_ms = gm_ifp->cur_query_intv;
	} else {
		timers.qrv = (hdr->flags & 0x7) ?: 8;
		timers.max_resp_ms = mld_max_resp_decode(hdr->max_resp_code);
		timers.qqic_ms = igmp_msg_decode8to16(hdr->qqic) * 1000;
	}
	timers.fuzz = gm_ifp->cfg_timing_fuzz;

	gm_expiry_calc(&timers);

	if (PIM_DEBUG_GM_TRACE_DETAIL)
		zlog_debug(
			log_ifp("query timers: QRV=%u max_resp=%ums qqic=%ums expire_wait=%pTVI"),
			timers.qrv, timers.max_resp_ms, timers.qqic_ms,
			&timers.expire_wait);

	if (IPV6_ADDR_CMP(&pkt_src->sin6_addr, &pim_ifp->ll_lowest) < 0) {
		unsigned int other_ms;

		EVENT_OFF(gm_ifp->t_query);
		EVENT_OFF(gm_ifp->t_other_querier);

		other_ms = timers.qrv * timers.qqic_ms + timers.max_resp_ms / 2;
		event_add_timer_msec(router->master, gm_t_other_querier, gm_ifp,
				     other_ms, &gm_ifp->t_other_querier);
	}

	if (len == sizeof(struct mld_v1_pkt)) {
		if (general_query) {
			gm_handle_q_general(gm_ifp, &timers);
			gm_ifp->stats.rx_query_old_general++;
		} else {
			gm_handle_q_group(gm_ifp, &timers, hdr->grp);
			gm_ifp->stats.rx_query_old_group++;
		}
		return;
	}

	/* v2 query - [S]uppress bit */
	if (hdr->flags & 0x8) {
		gm_ifp->stats.rx_query_new_sbit++;
		return;
	}

	if (general_query) {
		gm_handle_q_general(gm_ifp, &timers);
		gm_ifp->stats.rx_query_new_general++;
	} else if (!ntohs(hdr->n_src)) {
		gm_handle_q_group(gm_ifp, &timers, hdr->grp);
		gm_ifp->stats.rx_query_new_group++;
	} else {
		/* this is checked above:
		 * if (len >= sizeof(struct mld_v2_query_hdr)) {
		 *   size_t src_space = ntohs(hdr->n_src) * sizeof(pim_addr);
		 *   if (len < sizeof(struct mld_v2_query_hdr) + src_space) {
		 */
		assume(ntohs(hdr->n_src) <=
		       (len - sizeof(struct mld_v2_query_hdr)) /
			       sizeof(pim_addr));

		gm_handle_q_groupsrc(gm_ifp, &timers, hdr->grp, hdr->srcs,
				     ntohs(hdr->n_src));
		gm_ifp->stats.rx_query_new_groupsrc++;
	}
}

static void gm_rx_process(struct gm_if *gm_ifp,
			  const struct sockaddr_in6 *pkt_src, pim_addr *pkt_dst,
			  void *data, size_t pktlen)
{
	struct icmp6_plain_hdr *icmp6 = data;
	uint16_t pkt_csum, ref_csum;
	struct ipv6_ph ph6 = {
		.src = pkt_src->sin6_addr,
		.dst = *pkt_dst,
		.ulpl = htons(pktlen),
		.next_hdr = IPPROTO_ICMPV6,
	};

	pkt_csum = icmp6->icmp6_cksum;
	icmp6->icmp6_cksum = 0;
	ref_csum = in_cksum_with_ph6(&ph6, data, pktlen);

	if (pkt_csum != ref_csum) {
		zlog_warn(
			log_pkt_src(
				"(dst %pPA) packet RX checksum failure, expected %04hx, got %04hx"),
			pkt_dst, pkt_csum, ref_csum);
		gm_ifp->stats.rx_drop_csum++;
		return;
	}

	data = (icmp6 + 1);
	pktlen -= sizeof(*icmp6);

	switch (icmp6->icmp6_type) {
	case ICMP6_MLD_QUERY:
		gm_handle_query(gm_ifp, pkt_src, pkt_dst, data, pktlen);
		break;
	case ICMP6_MLD_V1_REPORT:
		gm_handle_v1_report(gm_ifp, pkt_src, data, pktlen);
		break;
	case ICMP6_MLD_V1_DONE:
		gm_handle_v1_leave(gm_ifp, pkt_src, data, pktlen);
		break;
	case ICMP6_MLD_V2_REPORT:
		gm_handle_v2_report(gm_ifp, pkt_src, data, pktlen);
		break;
	}
}

static bool ip6_check_hopopts_ra(uint8_t *hopopts, size_t hopopt_len,
				 uint16_t alert_type)
{
	uint8_t *hopopt_end;

	if (hopopt_len < 8)
		return false;
	if (hopopt_len < (hopopts[1] + 1U) * 8U)
		return false;

	hopopt_end = hopopts + (hopopts[1] + 1) * 8;
	hopopts += 2;

	while (hopopts < hopopt_end) {
		if (hopopts[0] == IP6OPT_PAD1) {
			hopopts++;
			continue;
		}

		if (hopopts > hopopt_end - 2)
			break;
		if (hopopts > hopopt_end - 2 - hopopts[1])
			break;

		if (hopopts[0] == IP6OPT_ROUTER_ALERT && hopopts[1] == 2) {
			uint16_t have_type = (hopopts[2] << 8) | hopopts[3];

			if (have_type == alert_type)
				return true;
		}

		hopopts += 2 + hopopts[1];
	}
	return false;
}

static void gm_t_recv(struct event *t)
{
	struct pim_instance *pim = EVENT_ARG(t);
	union {
		char buf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
			 CMSG_SPACE(256) /* hop options */ +
			 CMSG_SPACE(sizeof(int)) /* hopcount */];
		struct cmsghdr align;
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo = NULL;
	uint8_t *hopopts = NULL;
	size_t hopopt_len = 0;
	int *hoplimit = NULL;
	char rxbuf[2048];
	struct msghdr mh[1] = {};
	struct iovec iov[1];
	struct sockaddr_in6 pkt_src[1] = {};
	ssize_t nread;
	size_t pktlen;

	event_add_read(router->master, gm_t_recv, pim, pim->gm_socket,
		       &pim->t_gm_recv);

	iov->iov_base = rxbuf;
	iov->iov_len = sizeof(rxbuf);

	mh->msg_name = pkt_src;
	mh->msg_namelen = sizeof(pkt_src);
	mh->msg_control = cmsgbuf.buf;
	mh->msg_controllen = sizeof(cmsgbuf.buf);
	mh->msg_iov = iov;
	mh->msg_iovlen = array_size(iov);
	mh->msg_flags = 0;

	nread = recvmsg(pim->gm_socket, mh, MSG_PEEK | MSG_TRUNC);
	if (nread <= 0) {
		zlog_err("(VRF %s) RX error: %m", pim->vrf->name);
		pim->gm_rx_drop_sys++;
		return;
	}

	if ((size_t)nread > sizeof(rxbuf)) {
		iov->iov_base = XMALLOC(MTYPE_GM_PACKET, nread);
		iov->iov_len = nread;
	}
	nread = recvmsg(pim->gm_socket, mh, 0);
	if (nread <= 0) {
		zlog_err("(VRF %s) RX error: %m", pim->vrf->name);
		pim->gm_rx_drop_sys++;
		goto out_free;
	}

	struct interface *ifp;

	ifp = if_lookup_by_index(pkt_src->sin6_scope_id, pim->vrf->vrf_id);
	if (!ifp || !ifp->info)
		goto out_free;

	struct pim_interface *pim_ifp = ifp->info;
	struct gm_if *gm_ifp = pim_ifp->mld;

	if (!gm_ifp)
		goto out_free;

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg; cmsg = CMSG_NXTHDR(mh, cmsg)) {
		if (cmsg->cmsg_level != SOL_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			break;
		case IPV6_HOPOPTS:
			hopopts = CMSG_DATA(cmsg);
			hopopt_len = cmsg->cmsg_len - sizeof(*cmsg);
			break;
		case IPV6_HOPLIMIT:
			hoplimit = (int *)CMSG_DATA(cmsg);
			break;
		}
	}

	if (!pktinfo || !hoplimit) {
		zlog_err(log_ifp(
			"BUG: packet without IPV6_PKTINFO or IPV6_HOPLIMIT"));
		pim->gm_rx_drop_sys++;
		goto out_free;
	}

	if (*hoplimit != 1) {
		zlog_err(log_pkt_src("packet with hop limit != 1"));
		/* spoofing attempt => count on srcaddr counter */
		gm_ifp->stats.rx_drop_srcaddr++;
		goto out_free;
	}

	if (!ip6_check_hopopts_ra(hopopts, hopopt_len, IP6_ALERT_MLD)) {
		zlog_err(log_pkt_src(
			"packet without IPv6 Router Alert MLD option"));
		gm_ifp->stats.rx_drop_ra++;
		goto out_free;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&pkt_src->sin6_addr))
		/* reports from :: happen in normal operation for DAD, so
		 * don't spam log messages about this
		 */
		goto out_free;

	if (!IN6_IS_ADDR_LINKLOCAL(&pkt_src->sin6_addr)) {
		zlog_warn(log_pkt_src("packet from invalid source address"));
		gm_ifp->stats.rx_drop_srcaddr++;
		goto out_free;
	}

	pktlen = nread;
	if (pktlen < sizeof(struct icmp6_plain_hdr)) {
		zlog_warn(log_pkt_src("truncated packet"));
		gm_ifp->stats.rx_drop_malformed++;
		goto out_free;
	}

	gm_rx_process(gm_ifp, pkt_src, &pktinfo->ipi6_addr, iov->iov_base,
		      pktlen);

out_free:
	if (iov->iov_base != rxbuf)
		XFREE(MTYPE_GM_PACKET, iov->iov_base);
}

static void gm_send_query(struct gm_if *gm_ifp, pim_addr grp,
			  const pim_addr *srcs, size_t n_srcs, bool s_bit)
{
	struct pim_interface *pim_ifp = gm_ifp->ifp->info;
	struct sockaddr_in6 dstaddr = {
		.sin6_family = AF_INET6,
		.sin6_scope_id = gm_ifp->ifp->ifindex,
	};
	struct {
		struct icmp6_plain_hdr hdr;
		struct mld_v2_query_hdr v2_query;
	} query = {
		/* clang-format off */
		.hdr = {
			.icmp6_type = ICMP6_MLD_QUERY,
			.icmp6_code = 0,
		},
		.v2_query = {
			.grp = grp,
		},
		/* clang-format on */
	};
	struct ipv6_ph ph6 = {
		.src = pim_ifp->ll_lowest,
		.ulpl = htons(sizeof(query)),
		.next_hdr = IPPROTO_ICMPV6,
	};
	union {
		char buf[CMSG_SPACE(8) /* hop options */ +
			 CMSG_SPACE(sizeof(struct in6_pktinfo))];
		struct cmsghdr align;
	} cmsg = {};
	struct cmsghdr *cmh;
	struct msghdr mh[1] = {};
	struct iovec iov[3];
	size_t iov_len;
	ssize_t ret, expect_ret;
	uint8_t *dp;
	struct in6_pktinfo *pktinfo;

	if (if_is_loopback(gm_ifp->ifp)) {
		/* Linux is a bit odd with multicast on loopback */
		ph6.src = in6addr_loopback;
		dstaddr.sin6_addr = in6addr_loopback;
	} else if (pim_addr_is_any(grp))
		dstaddr.sin6_addr = gm_all_hosts;
	else
		dstaddr.sin6_addr = grp;

	query.v2_query.max_resp_code =
		mld_max_resp_encode(gm_ifp->cur_max_resp);
	query.v2_query.flags = (gm_ifp->cur_qrv < 8) ? gm_ifp->cur_qrv : 0;
	if (s_bit)
		query.v2_query.flags |= 0x08;
	query.v2_query.qqic =
		igmp_msg_encode16to8(gm_ifp->cur_query_intv / 1000);
	query.v2_query.n_src = htons(n_srcs);

	ph6.dst = dstaddr.sin6_addr;

	/* ph6 not included in sendmsg */
	iov[0].iov_base = &ph6;
	iov[0].iov_len = sizeof(ph6);
	iov[1].iov_base = &query;
	if (gm_ifp->cur_version == GM_MLDV1) {
		iov_len = 2;
		iov[1].iov_len = sizeof(query.hdr) + sizeof(struct mld_v1_pkt);
	} else if (!n_srcs) {
		iov_len = 2;
		iov[1].iov_len = sizeof(query);
	} else {
		iov[1].iov_len = sizeof(query);
		iov[2].iov_base = (void *)srcs;
		iov[2].iov_len = n_srcs * sizeof(srcs[0]);
		iov_len = 3;
	}

	query.hdr.icmp6_cksum = in_cksumv(iov, iov_len);

	if (PIM_DEBUG_GM_PACKETS)
		zlog_debug(
			log_ifp("MLD query %pPA -> %pI6 (grp=%pPA, %zu srcs)"),
			&pim_ifp->ll_lowest, &dstaddr.sin6_addr, &grp, n_srcs);

	mh->msg_name = &dstaddr;
	mh->msg_namelen = sizeof(dstaddr);
	mh->msg_iov = iov + 1;
	mh->msg_iovlen = iov_len - 1;
	mh->msg_control = &cmsg;
	mh->msg_controllen = sizeof(cmsg.buf);

	cmh = CMSG_FIRSTHDR(mh);
	cmh->cmsg_level = IPPROTO_IPV6;
	cmh->cmsg_type = IPV6_HOPOPTS;
	cmh->cmsg_len = CMSG_LEN(8);
	dp = CMSG_DATA(cmh);
	*dp++ = 0;		     /* next header */
	*dp++ = 0;		     /* length (8-byte blocks, minus 1) */
	*dp++ = IP6OPT_ROUTER_ALERT; /* router alert */
	*dp++ = 2;		     /* length */
	*dp++ = 0;		     /* value (2 bytes) */
	*dp++ = 0;		     /* value (2 bytes) (0 = MLD) */
	*dp++ = 0;		     /* pad0 */
	*dp++ = 0;		     /* pad0 */

	cmh = CMSG_NXTHDR(mh, cmh);
	cmh->cmsg_level = IPPROTO_IPV6;
	cmh->cmsg_type = IPV6_PKTINFO;
	cmh->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmh);
	pktinfo->ipi6_ifindex = gm_ifp->ifp->ifindex;
	pktinfo->ipi6_addr = gm_ifp->cur_ll_lowest;

	expect_ret = iov[1].iov_len;
	if (iov_len == 3)
		expect_ret += iov[2].iov_len;

	frr_with_privs (&pimd_privs) {
		ret = sendmsg(gm_ifp->pim->gm_socket, mh, 0);
	}

	if (ret != expect_ret) {
		zlog_warn(log_ifp("failed to send query: %m"));
		gm_ifp->stats.tx_query_fail++;
	} else {
		if (gm_ifp->cur_version == GM_MLDV1) {
			if (pim_addr_is_any(grp))
				gm_ifp->stats.tx_query_old_general++;
			else
				gm_ifp->stats.tx_query_old_group++;
		} else {
			if (pim_addr_is_any(grp))
				gm_ifp->stats.tx_query_new_general++;
			else if (!n_srcs)
				gm_ifp->stats.tx_query_new_group++;
			else
				gm_ifp->stats.tx_query_new_groupsrc++;
		}
	}
}

static void gm_t_query(struct event *t)
{
	struct gm_if *gm_ifp = EVENT_ARG(t);
	unsigned int timer_ms = gm_ifp->cur_query_intv;

	if (gm_ifp->n_startup) {
		timer_ms /= 4;
		gm_ifp->n_startup--;
	}

	event_add_timer_msec(router->master, gm_t_query, gm_ifp, timer_ms,
			     &gm_ifp->t_query);

	gm_send_query(gm_ifp, PIMADDR_ANY, NULL, 0, false);
}

static void gm_t_sg_query(struct event *t)
{
	struct gm_sg *sg = EVENT_ARG(t);

	gm_trigger_specific(sg);
}

/* S,G specific queries (triggered by a member leaving) get a little slack
 * time so we can bundle queries for [S1,S2,S3,...],G into the same query
 */
static void gm_send_specific(struct gm_gsq_pending *pend_gsq)
{
	struct gm_if *gm_ifp = pend_gsq->iface;

	gm_send_query(gm_ifp, pend_gsq->grp, pend_gsq->srcs, pend_gsq->n_src,
		      pend_gsq->s_bit);

	gm_gsq_pends_del(gm_ifp->gsq_pends, pend_gsq);
	XFREE(MTYPE_GM_GSQ_PENDING, pend_gsq);
}

static void gm_t_gsq_pend(struct event *t)
{
	struct gm_gsq_pending *pend_gsq = EVENT_ARG(t);

	gm_send_specific(pend_gsq);
}

static void gm_trigger_specific(struct gm_sg *sg)
{
	struct gm_if *gm_ifp = sg->iface;
	struct gm_gsq_pending *pend_gsq, ref = {};

	sg->n_query--;
	if (sg->n_query)
		event_add_timer_msec(router->master, gm_t_sg_query, sg,
				     gm_ifp->cur_query_intv_trig,
				     &sg->t_sg_query);

	/* As per RFC 2271, s6 p14:
	 * E.g. a router that starts as a Querier, receives a
	 * Done message for a group and then receives a Query from a router with
	 * a lower address (causing a transition to the Non-Querier state)
	 * continues to send multicast-address-specific queries for the group in
	 * question until it either receives a Report or its timer expires, at
	 * which time it starts performing the actions of a Non-Querier for this
	 * group.
	 */
	 /* Therefore here we do not need to check if this router is querier or
	  * not. This is called only for querier, hence it will work even if the
	  * router transitions from querier to non-querier.
	  */

	if (gm_ifp->pim->gm_socket == -1)
		return;

	if (PIM_DEBUG_GM_TRACE)
		zlog_debug(log_sg(sg, "triggered query"));

	if (pim_addr_is_any(sg->sgaddr.src)) {
		gm_send_query(gm_ifp, sg->sgaddr.grp, NULL, 0, sg->query_sbit);
		return;
	}

	ref.grp = sg->sgaddr.grp;
	ref.s_bit = sg->query_sbit;

	pend_gsq = gm_gsq_pends_find(gm_ifp->gsq_pends, &ref);
	if (!pend_gsq) {
		pend_gsq = XCALLOC(MTYPE_GM_GSQ_PENDING, sizeof(*pend_gsq));
		pend_gsq->grp = sg->sgaddr.grp;
		pend_gsq->s_bit = sg->query_sbit;
		pend_gsq->iface = gm_ifp;
		gm_gsq_pends_add(gm_ifp->gsq_pends, pend_gsq);

		event_add_timer_tv(router->master, gm_t_gsq_pend, pend_gsq,
				   &gm_ifp->cfg_timing_fuzz, &pend_gsq->t_send);
	}

	assert(pend_gsq->n_src < array_size(pend_gsq->srcs));

	pend_gsq->srcs[pend_gsq->n_src] = sg->sgaddr.src;
	pend_gsq->n_src++;

	if (pend_gsq->n_src == array_size(pend_gsq->srcs)) {
		EVENT_OFF(pend_gsq->t_send);
		gm_send_specific(pend_gsq);
		pend_gsq = NULL;
	}
}

static void gm_vrf_socket_incref(struct pim_instance *pim)
{
	struct vrf *vrf = pim->vrf;
	int ret, intval;
	struct icmp6_filter filter[1];

	if (pim->gm_socket_if_count++ && pim->gm_socket != -1)
		return;

	ICMP6_FILTER_SETBLOCKALL(filter);
	ICMP6_FILTER_SETPASS(ICMP6_MLD_QUERY, filter);
	ICMP6_FILTER_SETPASS(ICMP6_MLD_V1_REPORT, filter);
	ICMP6_FILTER_SETPASS(ICMP6_MLD_V1_DONE, filter);
	ICMP6_FILTER_SETPASS(ICMP6_MLD_V2_REPORT, filter);

	frr_with_privs (&pimd_privs) {
		pim->gm_socket = vrf_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6,
					    vrf->vrf_id, vrf->name);
		if (pim->gm_socket < 0) {
			zlog_err("(VRF %s) could not create MLD socket: %m",
				 vrf->name);
			return;
		}

		ret = setsockopt(pim->gm_socket, SOL_ICMPV6, ICMP6_FILTER,
				 filter, sizeof(filter));
		if (ret)
			zlog_err("(VRF %s) failed to set ICMP6_FILTER: %m",
				 vrf->name);

		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_RECVPKTINFO,
				 &intval, sizeof(intval));
		if (ret)
			zlog_err("(VRF %s) failed to set IPV6_RECVPKTINFO: %m",
				 vrf->name);

		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_RECVHOPOPTS,
				 &intval, sizeof(intval));
		if (ret)
			zlog_err("(VRF %s) failed to set IPV6_HOPOPTS: %m",
				 vrf->name);

		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_RECVHOPLIMIT,
				 &intval, sizeof(intval));
		if (ret)
			zlog_err("(VRF %s) failed to set IPV6_HOPLIMIT: %m",
				 vrf->name);

		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_MULTICAST_LOOP,
				 &intval, sizeof(intval));
		if (ret)
			zlog_err(
				"(VRF %s) failed to disable IPV6_MULTICAST_LOOP: %m",
				vrf->name);

		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_MULTICAST_HOPS,
				 &intval, sizeof(intval));
		if (ret)
			zlog_err(
				"(VRF %s) failed to set IPV6_MULTICAST_HOPS: %m",
				vrf->name);

		/* NB: IPV6_MULTICAST_ALL does not completely bypass multicast
		 * RX filtering in Linux.  It only means "receive all groups
		 * that something on the system has joined".  To actually
		 * receive *all* MLD packets - which is what we need -
		 * multicast routing must be enabled on the interface.  And
		 * this only works for MLD packets specifically.
		 *
		 * For reference, check ip6_mc_input() in net/ipv6/ip6_input.c
		 * and in particular the #ifdef CONFIG_IPV6_MROUTE block there.
		 *
		 * Also note that the code there explicitly checks for the IPv6
		 * router alert MLD option (which is required by the RFC to be
		 * on MLD packets.)  That implies trying to support hosts which
		 * erroneously don't add that option is just not possible.
		 */
		intval = 1;
		ret = setsockopt(pim->gm_socket, SOL_IPV6, IPV6_MULTICAST_ALL,
				 &intval, sizeof(intval));
		if (ret)
			zlog_info(
				"(VRF %s) failed to set IPV6_MULTICAST_ALL: %m (OK on old kernels)",
				vrf->name);
	}

	event_add_read(router->master, gm_t_recv, pim, pim->gm_socket,
		       &pim->t_gm_recv);
}

static void gm_vrf_socket_decref(struct pim_instance *pim)
{
	if (--pim->gm_socket_if_count)
		return;

	EVENT_OFF(pim->t_gm_recv);
	close(pim->gm_socket);
	pim->gm_socket = -1;
}

static void gm_start(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct gm_if *gm_ifp;

	assert(pim_ifp);
	assert(pim_ifp->pim);
	assert(pim_ifp->mroute_vif_index >= 0);
	assert(!pim_ifp->mld);

	gm_vrf_socket_incref(pim_ifp->pim);

	gm_ifp = XCALLOC(MTYPE_GM_IFACE, sizeof(*gm_ifp));
	gm_ifp->ifp = ifp;
	pim_ifp->mld = gm_ifp;
	gm_ifp->pim = pim_ifp->pim;
	monotime(&gm_ifp->started);

	zlog_info(log_ifp("starting MLD"));

	if (pim_ifp->mld_version == 1)
		gm_ifp->cur_version = GM_MLDV1;
	else
		gm_ifp->cur_version = GM_MLDV2;

	gm_ifp->cur_qrv = pim_ifp->gm_default_robustness_variable;
	gm_ifp->cur_query_intv = pim_ifp->gm_default_query_interval * 1000;
	gm_ifp->cur_query_intv_trig =
		pim_ifp->gm_specific_query_max_response_time_dsec * 100;
	gm_ifp->cur_max_resp = pim_ifp->gm_query_max_response_time_dsec * 100;
	gm_ifp->cur_lmqc = pim_ifp->gm_last_member_query_count;

	gm_ifp->cfg_timing_fuzz.tv_sec = 0;
	gm_ifp->cfg_timing_fuzz.tv_usec = 10 * 1000;

	gm_sgs_init(gm_ifp->sgs);
	gm_subscribers_init(gm_ifp->subscribers);
	gm_packet_expires_init(gm_ifp->expires);
	gm_grp_pends_init(gm_ifp->grp_pends);
	gm_gsq_pends_init(gm_ifp->gsq_pends);

	frr_with_privs (&pimd_privs) {
		struct ipv6_mreq mreq;
		int ret;

		/* all-MLDv2 group */
		mreq.ipv6mr_multiaddr = gm_all_routers;
		mreq.ipv6mr_interface = ifp->ifindex;
		ret = setsockopt(gm_ifp->pim->gm_socket, SOL_IPV6,
				 IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
		if (ret)
			zlog_err("(%s) failed to join ff02::16 (all-MLDv2): %m",
				 ifp->name);
	}
}

void gm_group_delete(struct gm_if *gm_ifp)
{
	struct gm_sg *sg;
	struct gm_packet_state *pkt;
	struct gm_grp_pending *pend_grp;
	struct gm_gsq_pending *pend_gsq;
	struct gm_subscriber *subscriber;

	while ((pkt = gm_packet_expires_first(gm_ifp->expires)))
		gm_packet_drop(pkt, false);

	while ((pend_grp = gm_grp_pends_pop(gm_ifp->grp_pends))) {
		EVENT_OFF(pend_grp->t_expire);
		XFREE(MTYPE_GM_GRP_PENDING, pend_grp);
	}

	while ((pend_gsq = gm_gsq_pends_pop(gm_ifp->gsq_pends))) {
		EVENT_OFF(pend_gsq->t_send);
		XFREE(MTYPE_GM_GSQ_PENDING, pend_gsq);
	}

	while ((sg = gm_sgs_pop(gm_ifp->sgs))) {
		EVENT_OFF(sg->t_sg_expire);
		assertf(!gm_packet_sg_subs_count(sg->subs_negative), "%pSG",
			&sg->sgaddr);
		assertf(!gm_packet_sg_subs_count(sg->subs_positive), "%pSG",
			&sg->sgaddr);

		gm_sg_free(sg);
	}
	while ((subscriber = gm_subscribers_pop(gm_ifp->subscribers))) {
		assertf(!gm_packets_count(subscriber->packets), "%pPA",
			&subscriber->addr);
		XFREE(MTYPE_GM_SUBSCRIBER, subscriber);
	}
}

void gm_ifp_teardown(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct gm_if *gm_ifp;

	if (!pim_ifp || !pim_ifp->mld)
		return;

	gm_ifp = pim_ifp->mld;
	gm_ifp->stopping = true;
	if (PIM_DEBUG_GM_EVENTS)
		zlog_debug(log_ifp("MLD stop"));

	EVENT_OFF(gm_ifp->t_query);
	EVENT_OFF(gm_ifp->t_other_querier);
	EVENT_OFF(gm_ifp->t_expire);

	frr_with_privs (&pimd_privs) {
		struct ipv6_mreq mreq;
		int ret;

		/* all-MLDv2 group */
		mreq.ipv6mr_multiaddr = gm_all_routers;
		mreq.ipv6mr_interface = ifp->ifindex;
		ret = setsockopt(gm_ifp->pim->gm_socket, SOL_IPV6,
				 IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
		if (ret)
			zlog_err(
				"(%s) failed to leave ff02::16 (all-MLDv2): %m",
				ifp->name);
	}

	gm_vrf_socket_decref(gm_ifp->pim);

	gm_group_delete(gm_ifp);

	gm_grp_pends_fini(gm_ifp->grp_pends);
	gm_packet_expires_fini(gm_ifp->expires);
	gm_subscribers_fini(gm_ifp->subscribers);
	gm_sgs_fini(gm_ifp->sgs);

	XFREE(MTYPE_GM_IFACE, gm_ifp);
	pim_ifp->mld = NULL;
}

static void gm_update_ll(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct gm_if *gm_ifp = pim_ifp->mld;
	bool was_querier;

	was_querier =
		!IPV6_ADDR_CMP(&gm_ifp->cur_ll_lowest, &gm_ifp->querier) &&
		!pim_addr_is_any(gm_ifp->querier);

	gm_ifp->cur_ll_lowest = pim_ifp->ll_lowest;
	if (was_querier)
		gm_ifp->querier = pim_ifp->ll_lowest;
	EVENT_OFF(gm_ifp->t_query);

	if (pim_addr_is_any(gm_ifp->cur_ll_lowest)) {
		if (was_querier)
			zlog_info(log_ifp(
				"lost link-local address, stopping querier"));
		return;
	}

	if (was_querier)
		zlog_info(log_ifp("new link-local %pPA while querier"),
			  &gm_ifp->cur_ll_lowest);
	else if (IPV6_ADDR_CMP(&gm_ifp->cur_ll_lowest, &gm_ifp->querier) < 0 ||
		 pim_addr_is_any(gm_ifp->querier)) {
		zlog_info(log_ifp("new link-local %pPA, becoming querier"),
			  &gm_ifp->cur_ll_lowest);
		gm_ifp->querier = gm_ifp->cur_ll_lowest;
	} else
		return;

	gm_ifp->n_startup = gm_ifp->cur_qrv;
	event_execute(router->master, gm_t_query, gm_ifp, 0, NULL);
}

void gm_ifp_update(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct gm_if *gm_ifp;
	bool changed = false;

	if (!pim_ifp)
		return;
	if (!if_is_operative(ifp) || !pim_ifp->pim ||
	    pim_ifp->mroute_vif_index < 0) {
		gm_ifp_teardown(ifp);
		return;
	}

	/*
	 * If ipv6 mld is not enabled on interface, do not start mld activites.
	 */
	if (!pim_ifp->gm_enable)
		return;

	if (!pim_ifp->mld) {
		changed = true;
		gm_start(ifp);
		assume(pim_ifp->mld != NULL);
	}

	gm_ifp = pim_ifp->mld;
	if (IPV6_ADDR_CMP(&pim_ifp->ll_lowest, &gm_ifp->cur_ll_lowest))
		gm_update_ll(ifp);

	unsigned int cfg_query_intv = pim_ifp->gm_default_query_interval * 1000;

	if (gm_ifp->cur_query_intv != cfg_query_intv) {
		gm_ifp->cur_query_intv = cfg_query_intv;
		changed = true;
	}

	unsigned int cfg_query_intv_trig =
		pim_ifp->gm_specific_query_max_response_time_dsec * 100;

	if (gm_ifp->cur_query_intv_trig != cfg_query_intv_trig) {
		gm_ifp->cur_query_intv_trig = cfg_query_intv_trig;
		changed = true;
	}

	unsigned int cfg_max_response =
		pim_ifp->gm_query_max_response_time_dsec * 100;

	if (gm_ifp->cur_max_resp != cfg_max_response)
		gm_ifp->cur_max_resp = cfg_max_response;

	if (gm_ifp->cur_lmqc != pim_ifp->gm_last_member_query_count)
		gm_ifp->cur_lmqc = pim_ifp->gm_last_member_query_count;

	enum gm_version cfg_version;

	if (pim_ifp->mld_version == 1)
		cfg_version = GM_MLDV1;
	else
		cfg_version = GM_MLDV2;
	if (gm_ifp->cur_version != cfg_version) {
		gm_ifp->cur_version = cfg_version;
		changed = true;
	}

	if (changed) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(log_ifp(
				"MLD querier config changed, querying"));
		gm_bump_querier(gm_ifp);
	}
}

/*
 * CLI (show commands only)
 */

#include "lib/command.h"

#include "pimd/pim6_mld_clippy.c"

static struct vrf *gm_cmd_vrf_lookup(struct vty *vty, const char *vrf_str,
				     int *err)
{
	struct vrf *ret;

	if (!vrf_str)
		return vrf_lookup_by_id(VRF_DEFAULT);
	if (!strcmp(vrf_str, "all"))
		return NULL;
	ret = vrf_lookup_by_name(vrf_str);
	if (ret)
		return ret;

	vty_out(vty, "%% VRF %pSQq does not exist\n", vrf_str);
	*err = CMD_WARNING;
	return NULL;
}

static void gm_show_if_one_detail(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = (struct pim_interface *)ifp->info;
	struct gm_if *gm_ifp;
	bool querier;
	size_t i;

	if (!pim_ifp) {
		vty_out(vty, "Interface %s: no PIM/MLD config\n\n", ifp->name);
		return;
	}

	gm_ifp = pim_ifp->mld;
	if (!gm_ifp) {
		vty_out(vty, "Interface %s: MLD not running\n\n", ifp->name);
		return;
	}

	querier = IPV6_ADDR_SAME(&gm_ifp->querier, &pim_ifp->ll_lowest);

	vty_out(vty, "Interface %s: MLD running\n", ifp->name);
	vty_out(vty, "  Uptime:                  %pTVMs\n", &gm_ifp->started);
	vty_out(vty, "  MLD version:             %d\n", gm_ifp->cur_version);
	vty_out(vty, "  Querier:                 %pPA%s\n", &gm_ifp->querier,
		querier ? " (this system)" : "");
	vty_out(vty, "  Query timer:             %pTH\n", gm_ifp->t_query);
	vty_out(vty, "  Other querier timer:     %pTH\n",
		gm_ifp->t_other_querier);
	vty_out(vty, "  Robustness value:        %u\n", gm_ifp->cur_qrv);
	vty_out(vty, "  Query interval:          %ums\n",
		gm_ifp->cur_query_intv);
	vty_out(vty, "  Query response timer:    %ums\n", gm_ifp->cur_max_resp);
	vty_out(vty, "  Last member query intv.: %ums\n",
		gm_ifp->cur_query_intv_trig);
	vty_out(vty, "  %u expiry timers from general queries:\n",
		gm_ifp->n_pending);
	for (i = 0; i < gm_ifp->n_pending; i++) {
		struct gm_general_pending *p = &gm_ifp->pending[i];

		vty_out(vty, "    %9pTVMs ago (query) -> %9pTVMu (expiry)\n",
			&p->query, &p->expiry);
	}
	vty_out(vty, "  %zu expiry timers from *,G queries\n",
		gm_grp_pends_count(gm_ifp->grp_pends));
	vty_out(vty, "  %zu expiry timers from S,G queries\n",
		gm_gsq_pends_count(gm_ifp->gsq_pends));
	vty_out(vty, "  %zu total *,G/S,G from %zu hosts in %zu bundles\n",
		gm_sgs_count(gm_ifp->sgs),
		gm_subscribers_count(gm_ifp->subscribers),
		gm_packet_expires_count(gm_ifp->expires));
	vty_out(vty, "\n");
}

static void gm_show_if_one(struct vty *vty, struct interface *ifp,
			   json_object *js_if, struct ttable *tt)
{
	struct pim_interface *pim_ifp = (struct pim_interface *)ifp->info;
	struct gm_if *gm_ifp = pim_ifp->mld;
	bool querier;

	assume(js_if || tt);

	querier = IPV6_ADDR_SAME(&gm_ifp->querier, &pim_ifp->ll_lowest);

	if (js_if) {
		json_object_string_add(js_if, "name", ifp->name);
		json_object_string_addf(js_if, "address", "%pPA",
					&pim_ifp->primary_address);
		json_object_string_add(js_if, "state", "up");
		json_object_string_addf(js_if, "version", "%d",
					gm_ifp->cur_version);
		json_object_string_addf(js_if, "upTime", "%pTVMs",
					&gm_ifp->started);
		json_object_boolean_add(js_if, "querier", querier);
		json_object_string_addf(js_if, "querierIp", "%pPA",
					&gm_ifp->querier);
		if (querier)
			json_object_string_addf(js_if, "queryTimer", "%pTH",
						gm_ifp->t_query);
		else
			json_object_string_addf(js_if, "otherQuerierTimer",
						"%pTH",
						gm_ifp->t_other_querier);
		json_object_int_add(js_if, "timerRobustnessValue",
				    gm_ifp->cur_qrv);
		json_object_int_add(js_if, "lastMemberQueryCount",
				    gm_ifp->cur_lmqc);
		json_object_int_add(js_if, "timerQueryIntervalMsec",
				    gm_ifp->cur_query_intv);
		json_object_int_add(js_if, "timerQueryResponseTimerMsec",
				    gm_ifp->cur_max_resp);
		json_object_int_add(js_if, "timerLastMemberQueryIntervalMsec",
				    gm_ifp->cur_query_intv_trig);
	} else {
		ttable_add_row(tt, "%s|%s|%pPAs|%d|%s|%pPAs|%pTH|%pTVMs",
			       ifp->name, "up", &pim_ifp->primary_address,
			       gm_ifp->cur_version, querier ? "local" : "other",
			       &gm_ifp->querier, gm_ifp->t_query,
			       &gm_ifp->started);
	}
}

static void gm_show_if_vrf(struct vty *vty, struct vrf *vrf, const char *ifname,
			   bool detail, json_object *js)
{
	struct interface *ifp;
	json_object *js_vrf = NULL;
	struct pim_interface *pim_ifp;
	struct ttable *tt = NULL;
	char *table = NULL;

	if (js) {
		js_vrf = json_object_new_object();
		json_object_object_add(js, vrf->name, js_vrf);
	}

	if (!js && !detail) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Interface|State|Address|V|Querier|QuerierIp|Query Timer|Uptime");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	FOR_ALL_INTERFACES (vrf, ifp) {
		json_object *js_if = NULL;

		if (ifname && strcmp(ifp->name, ifname))
			continue;
		if (detail && !js) {
			gm_show_if_one_detail(vty, ifp);
			continue;
		}

		pim_ifp = ifp->info;

		if (!pim_ifp || !pim_ifp->mld)
			continue;

		if (js) {
			js_if = json_object_new_object();
			/*
			 * If we have js as true and detail as false
			 * and if Coverity thinks that js_if is NULL
			 * because of a failed call to new then
			 * when we call gm_show_if_one below
			 * the tt can be deref'ed and as such
			 * FRR will crash.  But since we know
			 * that json_object_new_object never fails
			 * then let's tell Coverity that this assumption
			 * is true.  I'm not worried about fast path
			 * here at all.
			 */
			assert(js_if);
			json_object_object_add(js_vrf, ifp->name, js_if);
		}

		gm_show_if_one(vty, ifp, js_if, tt);
	}

	/* Dump the generated table. */
	if (!js && !detail) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
		ttable_del(tt);
	}
}

static void gm_show_if(struct vty *vty, struct vrf *vrf, const char *ifname,
		       bool detail, json_object *js)
{
	if (vrf)
		gm_show_if_vrf(vty, vrf, ifname, detail, js);
	else
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
			gm_show_if_vrf(vty, vrf, ifname, detail, js);
}

DEFPY(gm_show_interface,
      gm_show_interface_cmd,
      "show ipv6 mld [vrf <VRF|all>$vrf_str] interface [IFNAME | detail$detail] [json$json]",
      SHOW_STR
      IPV6_STR
      MLD_STR
      VRF_FULL_CMD_HELP_STR
      "MLD interface information\n"
      "Interface name\n"
      "Detailed output\n"
      JSON_STR)
{
	int ret = CMD_SUCCESS;
	struct vrf *vrf;
	json_object *js = NULL;

	vrf = gm_cmd_vrf_lookup(vty, vrf_str, &ret);
	if (ret != CMD_SUCCESS)
		return ret;

	if (json)
		js = json_object_new_object();
	gm_show_if(vty, vrf, ifname, !!detail, js);
	return vty_json(vty, js);
}

static void gm_show_stats_one(struct vty *vty, struct gm_if *gm_ifp,
			      json_object *js_if)
{
	struct gm_if_stats *stats = &gm_ifp->stats;
	/* clang-format off */
	struct {
		const char *text;
		const char *js_key;
		uint64_t *val;
	} *item, items[] = {
		{ "v2 reports received", "rxV2Reports", &stats->rx_new_report },
		{ "v1 reports received", "rxV1Reports", &stats->rx_old_report },
		{ "v1 done received",    "rxV1Done",    &stats->rx_old_leave },

		{ "v2 *,* queries received",   "rxV2QueryGeneral",     &stats->rx_query_new_general },
		{ "v2 *,G queries received",   "rxV2QueryGroup",       &stats->rx_query_new_group },
		{ "v2 S,G queries received",   "rxV2QueryGroupSource", &stats->rx_query_new_groupsrc },
		{ "v2 S-bit queries received", "rxV2QuerySBit",        &stats->rx_query_new_sbit },
		{ "v1 *,* queries received",   "rxV1QueryGeneral",     &stats->rx_query_old_general },
		{ "v1 *,G queries received",   "rxV1QueryGroup",       &stats->rx_query_old_group },

		{ "v2 *,* queries sent", "txV2QueryGeneral",     &stats->tx_query_new_general },
		{ "v2 *,G queries sent", "txV2QueryGroup",       &stats->tx_query_new_group },
		{ "v2 S,G queries sent", "txV2QueryGroupSource", &stats->tx_query_new_groupsrc },
		{ "v1 *,* queries sent", "txV1QueryGeneral",     &stats->tx_query_old_general },
		{ "v1 *,G queries sent", "txV1QueryGroup",       &stats->tx_query_old_group },
		{ "TX errors",           "txErrors",             &stats->tx_query_fail },

		{ "RX dropped (checksum error)", "rxDropChecksum",  &stats->rx_drop_csum },
		{ "RX dropped (invalid source)", "rxDropSrcAddr",   &stats->rx_drop_srcaddr },
		{ "RX dropped (invalid dest.)",  "rxDropDstAddr",   &stats->rx_drop_dstaddr },
		{ "RX dropped (missing alert)",  "rxDropRtrAlert",  &stats->rx_drop_ra },
		{ "RX dropped (malformed pkt.)", "rxDropMalformed", &stats->rx_drop_malformed },
		{ "RX truncated reports",        "rxTruncatedRep",  &stats->rx_trunc_report },
	};
	/* clang-format on */

	for (item = items; item < items + array_size(items); item++) {
		if (js_if)
			json_object_int_add(js_if, item->js_key, *item->val);
		else
			vty_out(vty, "  %-30s  %" PRIu64 "\n", item->text,
				*item->val);
	}
}

static void gm_show_stats_vrf(struct vty *vty, struct vrf *vrf,
			      const char *ifname, json_object *js)
{
	struct interface *ifp;
	json_object *js_vrf;

	if (js) {
		js_vrf = json_object_new_object();
		json_object_object_add(js, vrf->name, js_vrf);
	}

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct pim_interface *pim_ifp;
		struct gm_if *gm_ifp;
		json_object *js_if = NULL;

		if (ifname && strcmp(ifp->name, ifname))
			continue;

		if (!ifp->info)
			continue;
		pim_ifp = ifp->info;
		if (!pim_ifp->mld)
			continue;
		gm_ifp = pim_ifp->mld;

		if (js) {
			js_if = json_object_new_object();
			json_object_object_add(js_vrf, ifp->name, js_if);
		} else {
			vty_out(vty, "Interface: %s\n", ifp->name);
		}
		gm_show_stats_one(vty, gm_ifp, js_if);
		if (!js)
			vty_out(vty, "\n");
	}
}

DEFPY(gm_show_interface_stats,
      gm_show_interface_stats_cmd,
      "show ipv6 mld [vrf <VRF|all>$vrf_str] statistics [interface IFNAME] [json$json]",
      SHOW_STR
      IPV6_STR
      MLD_STR
      VRF_FULL_CMD_HELP_STR
      "MLD statistics\n"
      INTERFACE_STR
      "Interface name\n"
      JSON_STR)
{
	int ret = CMD_SUCCESS;
	struct vrf *vrf;
	json_object *js = NULL;

	vrf = gm_cmd_vrf_lookup(vty, vrf_str, &ret);
	if (ret != CMD_SUCCESS)
		return ret;

	if (json)
		js = json_object_new_object();

	if (vrf)
		gm_show_stats_vrf(vty, vrf, ifname, js);
	else
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
			gm_show_stats_vrf(vty, vrf, ifname, js);
	return vty_json(vty, js);
}

static void gm_show_joins_one(struct vty *vty, struct gm_if *gm_ifp,
			      const struct prefix_ipv6 *groups,
			      const struct prefix_ipv6 *sources, bool detail,
			      json_object *js_if)
{
	struct gm_sg *sg, *sg_start;
	json_object *js_group = NULL;
	pim_addr js_grpaddr = PIMADDR_ANY;
	struct gm_subscriber sub_ref = {}, *sub_untracked;

	if (groups) {
		struct gm_sg sg_ref = {};

		sg_ref.sgaddr.grp = pim_addr_from_prefix(groups);
		sg_start = gm_sgs_find_gteq(gm_ifp->sgs, &sg_ref);
	} else
		sg_start = gm_sgs_first(gm_ifp->sgs);

	sub_ref.addr = gm_dummy_untracked;
	sub_untracked = gm_subscribers_find(gm_ifp->subscribers, &sub_ref);
	/* NB: sub_untracked may be NULL if no untracked joins exist */

	frr_each_from (gm_sgs, gm_ifp->sgs, sg, sg_start) {
		struct timeval *recent = NULL, *untracked = NULL;
		json_object *js_src;

		if (groups) {
			struct prefix grp_p;

			pim_addr_to_prefix(&grp_p, sg->sgaddr.grp);
			if (!prefix_match(groups, &grp_p))
				break;
		}

		if (sources) {
			struct prefix src_p;

			pim_addr_to_prefix(&src_p, sg->sgaddr.src);
			if (!prefix_match(sources, &src_p))
				continue;
		}

		if (sg->most_recent) {
			struct gm_packet_state *packet;

			packet = gm_packet_sg2state(sg->most_recent);
			recent = &packet->received;
		}

		if (sub_untracked) {
			struct gm_packet_state *packet;
			struct gm_packet_sg *item;

			item = gm_packet_sg_find(sg, GM_SUB_POS, sub_untracked);
			if (item) {
				packet = gm_packet_sg2state(item);
				untracked = &packet->received;
			}
		}

		if (!js_if) {
			FMT_NSTD_BEGIN; /* %.0p */
			vty_out(vty,
				"%-30pPA  %-30pPAs  %-16s  %10.0pTVMs  %10.0pTVMs  %10.0pTVMs\n",
				&sg->sgaddr.grp, &sg->sgaddr.src,
				gm_states[sg->state], recent, untracked,
				&sg->created);

			if (!detail)
				continue;

			struct gm_packet_sg *item;
			struct gm_packet_state *packet;

			frr_each (gm_packet_sg_subs, sg->subs_positive, item) {
				packet = gm_packet_sg2state(item);

				if (packet->subscriber == sub_untracked)
					continue;
				vty_out(vty, "    %-58pPA  %-16s  %10.0pTVMs\n",
					&packet->subscriber->addr, "(JOIN)",
					&packet->received);
			}
			frr_each (gm_packet_sg_subs, sg->subs_negative, item) {
				packet = gm_packet_sg2state(item);

				if (packet->subscriber == sub_untracked)
					continue;
				vty_out(vty, "    %-58pPA  %-16s  %10.0pTVMs\n",
					&packet->subscriber->addr, "(PRUNE)",
					&packet->received);
			}
			FMT_NSTD_END; /* %.0p */
			continue;
		}
		/* if (js_if) */

		if (!js_group || pim_addr_cmp(js_grpaddr, sg->sgaddr.grp)) {
			js_group = json_object_new_object();
			json_object_object_addf(js_if, js_group, "%pPA",
						&sg->sgaddr.grp);
			js_grpaddr = sg->sgaddr.grp;
		}

		js_src = json_object_new_object();
		json_object_object_addf(js_group, js_src, "%pPAs",
					&sg->sgaddr.src);

		json_object_string_add(js_src, "state", gm_states[sg->state]);
		json_object_string_addf(js_src, "created", "%pTVMs",
					&sg->created);
		json_object_string_addf(js_src, "lastSeen", "%pTVMs", recent);

		if (untracked)
			json_object_string_addf(js_src, "untrackedLastSeen",
						"%pTVMs", untracked);
		if (!detail)
			continue;

		json_object *js_subs;
		struct gm_packet_sg *item;
		struct gm_packet_state *packet;

		js_subs = json_object_new_object();
		json_object_object_add(js_src, "joinedBy", js_subs);
		frr_each (gm_packet_sg_subs, sg->subs_positive, item) {
			packet = gm_packet_sg2state(item);
			if (packet->subscriber == sub_untracked)
				continue;

			json_object *js_sub;

			js_sub = json_object_new_object();
			json_object_object_addf(js_subs, js_sub, "%pPA",
						&packet->subscriber->addr);
			json_object_string_addf(js_sub, "lastSeen", "%pTVMs",
						&packet->received);
		}

		js_subs = json_object_new_object();
		json_object_object_add(js_src, "prunedBy", js_subs);
		frr_each (gm_packet_sg_subs, sg->subs_negative, item) {
			packet = gm_packet_sg2state(item);
			if (packet->subscriber == sub_untracked)
				continue;

			json_object *js_sub;

			js_sub = json_object_new_object();
			json_object_object_addf(js_subs, js_sub, "%pPA",
						&packet->subscriber->addr);
			json_object_string_addf(js_sub, "lastSeen", "%pTVMs",
						&packet->received);
		}
	}
}

static void gm_show_joins_vrf(struct vty *vty, struct vrf *vrf,
			      const char *ifname,
			      const struct prefix_ipv6 *groups,
			      const struct prefix_ipv6 *sources, bool detail,
			      json_object *js)
{
	struct interface *ifp;
	json_object *js_vrf;

	if (js) {
		js_vrf = json_object_new_object();
		json_object_string_add(js_vrf, "vrf", vrf->name);
		json_object_object_add(js, vrf->name, js_vrf);
	}

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct pim_interface *pim_ifp;
		struct gm_if *gm_ifp;
		json_object *js_if = NULL;

		if (ifname && strcmp(ifp->name, ifname))
			continue;

		if (!ifp->info)
			continue;
		pim_ifp = ifp->info;
		if (!pim_ifp->mld)
			continue;
		gm_ifp = pim_ifp->mld;

		if (js) {
			js_if = json_object_new_object();
			json_object_object_add(js_vrf, ifp->name, js_if);
		}

		if (!js && !ifname)
			vty_out(vty, "\nOn interface %s:\n", ifp->name);

		gm_show_joins_one(vty, gm_ifp, groups, sources, detail, js_if);
	}
}

DEFPY(gm_show_interface_joins,
      gm_show_interface_joins_cmd,
      "show ipv6 mld [vrf <VRF|all>$vrf_str] joins [{interface IFNAME|groups X:X::X:X/M|sources X:X::X:X/M|detail$detail}] [json$json]",
      SHOW_STR
      IPV6_STR
      MLD_STR
      VRF_FULL_CMD_HELP_STR
      "MLD joined groups & sources\n"
      INTERFACE_STR
      "Interface name\n"
      "Limit output to group range\n"
      "Show groups covered by this prefix\n"
      "Limit output to source range\n"
      "Show sources covered by this prefix\n"
      "Show details, including tracked receivers\n"
      JSON_STR)
{
	int ret = CMD_SUCCESS;
	struct vrf *vrf;
	json_object *js = NULL;

	vrf = gm_cmd_vrf_lookup(vty, vrf_str, &ret);
	if (ret != CMD_SUCCESS)
		return ret;

	if (json)
		js = json_object_new_object();
	else
		vty_out(vty, "%-30s  %-30s  %-16s  %10s  %10s  %10s\n", "Group",
			"Source", "State", "LastSeen", "NonTrkSeen", "Created");

	if (vrf)
		gm_show_joins_vrf(vty, vrf, ifname, groups, sources, !!detail,
				  js);
	else
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
			gm_show_joins_vrf(vty, vrf, ifname, groups, sources,
					  !!detail, js);
	return vty_json(vty, js);
}

static void gm_show_groups(struct vty *vty, struct vrf *vrf, bool uj)
{
	struct interface *ifp;
	struct ttable *tt = NULL;
	char *table;
	json_object *json = NULL;
	json_object *json_iface = NULL;
	json_object *json_group = NULL;
	json_object *json_groups = NULL;
	struct pim_instance *pim = vrf->info;

	if (uj) {
		json = json_object_new_object();
		json_object_int_add(json, "totalGroups", pim->gm_group_count);
		json_object_int_add(json, "watermarkLimit",
				    pim->gm_watermark_limit);
	} else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Interface|Group|Version|Uptime");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);

		vty_out(vty, "Total MLD groups: %u\n", pim->gm_group_count);
		vty_out(vty, "Watermark warn limit(%s): %u\n",
			pim->gm_watermark_limit ? "Set" : "Not Set",
			pim->gm_watermark_limit);
	}

	/* scan interfaces */
	FOR_ALL_INTERFACES (vrf, ifp) {

		struct pim_interface *pim_ifp = ifp->info;
		struct gm_if *gm_ifp;
		struct gm_sg *sg;

		if (!pim_ifp)
			continue;

		gm_ifp = pim_ifp->mld;
		if (!gm_ifp)
			continue;

		/* scan mld groups */
		frr_each (gm_sgs, gm_ifp->sgs, sg) {

			if (uj) {
				json_object_object_get_ex(json, ifp->name,
							  &json_iface);

				if (!json_iface) {
					json_iface = json_object_new_object();
					json_object_pim_ifp_add(json_iface,
								ifp);
					json_object_object_add(json, ifp->name,
							       json_iface);
					json_groups = json_object_new_array();
					json_object_object_add(json_iface,
							       "groups",
							       json_groups);
				}

				json_group = json_object_new_object();
				json_object_string_addf(json_group, "group",
							"%pPAs",
							&sg->sgaddr.grp);

				json_object_int_add(json_group, "version",
						    pim_ifp->mld_version);
				json_object_string_addf(json_group, "uptime",
							"%pTVMs", &sg->created);
				json_object_array_add(json_groups, json_group);
			} else {
				ttable_add_row(tt, "%s|%pPAs|%d|%pTVMs",
					       ifp->name, &sg->sgaddr.grp,
					       pim_ifp->mld_version,
					       &sg->created);
			}
		} /* scan gm groups */
	}	 /* scan interfaces */

	if (uj)
		vty_json(vty, json);
	else {
		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
		ttable_del(tt);
	}
}

DEFPY(gm_show_mld_groups,
      gm_show_mld_groups_cmd,
      "show ipv6 mld [vrf <VRF|all>$vrf_str] groups [json$json]",
      SHOW_STR
      IPV6_STR
      MLD_STR
      VRF_FULL_CMD_HELP_STR
      MLD_GROUP_STR
      JSON_STR)
{
	int ret = CMD_SUCCESS;
	struct vrf *vrf;

	vrf = gm_cmd_vrf_lookup(vty, vrf_str, &ret);
	if (ret != CMD_SUCCESS)
		return ret;

	if (vrf)
		gm_show_groups(vty, vrf, !!json);
	else
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
			gm_show_groups(vty, vrf, !!json);

	return CMD_SUCCESS;
}

DEFPY(gm_debug_show,
      gm_debug_show_cmd,
      "debug show mld interface IFNAME",
      DEBUG_STR
      SHOW_STR
      MLD_STR
      INTERFACE_STR
      "interface name\n")
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct gm_if *gm_ifp;

	ifp = if_lookup_by_name(ifname, VRF_DEFAULT);
	if (!ifp) {
		vty_out(vty, "%% no such interface: %pSQq\n", ifname);
		return CMD_WARNING;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		vty_out(vty, "%% no PIM state for interface %pSQq\n", ifname);
		return CMD_WARNING;
	}

	gm_ifp = pim_ifp->mld;
	if (!gm_ifp) {
		vty_out(vty, "%% no MLD state for interface %pSQq\n", ifname);
		return CMD_WARNING;
	}

	vty_out(vty, "querier:         %pPA\n", &gm_ifp->querier);
	vty_out(vty, "ll_lowest:       %pPA\n\n", &pim_ifp->ll_lowest);
	vty_out(vty, "t_query:         %pTHD\n", gm_ifp->t_query);
	vty_out(vty, "t_other_querier: %pTHD\n", gm_ifp->t_other_querier);
	vty_out(vty, "t_expire:        %pTHD\n", gm_ifp->t_expire);

	vty_out(vty, "\nn_pending: %u\n", gm_ifp->n_pending);
	for (size_t i = 0; i < gm_ifp->n_pending; i++) {
		int64_t query, expiry;

		query = monotime_since(&gm_ifp->pending[i].query, NULL);
		expiry = monotime_until(&gm_ifp->pending[i].expiry, NULL);

		vty_out(vty, "[%zu]: query %"PRId64"ms ago, expiry in %"PRId64"ms\n",
			i, query / 1000, expiry / 1000);
	}

	struct gm_sg *sg;
	struct gm_packet_state *pkt;
	struct gm_packet_sg *item;
	struct gm_subscriber *subscriber;

	vty_out(vty, "\n%zu S,G entries:\n", gm_sgs_count(gm_ifp->sgs));
	frr_each (gm_sgs, gm_ifp->sgs, sg) {
		vty_out(vty, "\t%pSG    t_expire=%pTHD\n", &sg->sgaddr,
			sg->t_sg_expire);

		vty_out(vty, "\t     @pos:%zu\n",
			gm_packet_sg_subs_count(sg->subs_positive));
		frr_each (gm_packet_sg_subs, sg->subs_positive, item) {
			pkt = gm_packet_sg2state(item);

			vty_out(vty, "\t\t+%s%s [%pPAs %p] %p+%u\n",
				item->is_src ? "S" : "",
				item->is_excl ? "E" : "",
				&pkt->subscriber->addr, pkt->subscriber, pkt,
				item->offset);

			assert(item->sg == sg);
		}
		vty_out(vty, "\t     @neg:%zu\n",
			gm_packet_sg_subs_count(sg->subs_negative));
		frr_each (gm_packet_sg_subs, sg->subs_negative, item) {
			pkt = gm_packet_sg2state(item);

			vty_out(vty, "\t\t-%s%s [%pPAs %p] %p+%u\n",
				item->is_src ? "S" : "",
				item->is_excl ? "E" : "",
				&pkt->subscriber->addr, pkt->subscriber, pkt,
				item->offset);

			assert(item->sg == sg);
		}
	}

	vty_out(vty, "\n%zu subscribers:\n",
		gm_subscribers_count(gm_ifp->subscribers));
	frr_each (gm_subscribers, gm_ifp->subscribers, subscriber) {
		vty_out(vty, "\t%pPA %p %zu packets\n", &subscriber->addr,
			subscriber, gm_packets_count(subscriber->packets));

		frr_each (gm_packets, subscriber->packets, pkt) {
			vty_out(vty, "\t\t%p %.3fs ago %u of %u items active\n",
				pkt,
				monotime_since(&pkt->received, NULL) *
					0.000001f,
				pkt->n_active, pkt->n_sg);

			for (size_t i = 0; i < pkt->n_sg; i++) {
				item = pkt->items + i;

				vty_out(vty, "\t\t[%zu]", i);

				if (!item->sg) {
					vty_out(vty, " inactive\n");
					continue;
				}

				vty_out(vty, " %s%s %pSG nE=%u\n",
					item->is_src ? "S" : "",
					item->is_excl ? "E" : "",
					&item->sg->sgaddr, item->n_exclude);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFPY(gm_debug_iface_cfg,
      gm_debug_iface_cfg_cmd,
      "debug ipv6 mld {"
        "robustness (0-7)|"
	"query-max-response-time (1-8387584)"
      "}",
      DEBUG_STR
      IPV6_STR
      "Multicast Listener Discovery\n"
      "QRV\nQRV\n"
      "maxresp\nmaxresp\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct pim_interface *pim_ifp;
	struct gm_if *gm_ifp;
	bool changed = false;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		vty_out(vty, "%% no PIM state for interface %pSQq\n",
			ifp->name);
		return CMD_WARNING;
	}
	gm_ifp = pim_ifp->mld;
	if (!gm_ifp) {
		vty_out(vty, "%% no MLD state for interface %pSQq\n",
			ifp->name);
		return CMD_WARNING;
	}

	if (robustness_str && gm_ifp->cur_qrv != robustness) {
		gm_ifp->cur_qrv = robustness;
		changed = true;
	}
	if (query_max_response_time_str &&
	    gm_ifp->cur_max_resp != (unsigned int)query_max_response_time) {
		gm_ifp->cur_max_resp = query_max_response_time;
		changed = true;
	}

	if (changed) {
		vty_out(vty, "%% MLD querier config changed, bumping\n");
		gm_bump_querier(gm_ifp);
	}
	return CMD_SUCCESS;
}

void gm_cli_init(void);

void gm_cli_init(void)
{
	install_element(VIEW_NODE, &gm_show_interface_cmd);
	install_element(VIEW_NODE, &gm_show_interface_stats_cmd);
	install_element(VIEW_NODE, &gm_show_interface_joins_cmd);
	install_element(VIEW_NODE, &gm_show_mld_groups_cmd);

	install_element(VIEW_NODE, &gm_debug_show_cmd);
	install_element(INTERFACE_NODE, &gm_debug_iface_cfg_cmd);
}
