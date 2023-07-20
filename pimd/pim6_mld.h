// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIMv6 MLD querier
 * Copyright (C) 2021-2022  David Lamparter for NetDEF, Inc.
 */

#ifndef PIM6_MLD_H
#define PIM6_MLD_H

#include "typesafe.h"
#include "pim_addr.h"

struct event;
struct pim_instance;
struct gm_packet_sg;
struct gm_if;
struct channel_oil;

#define MLD_DEFAULT_VERSION 2

/* see comment below on subs_negative/subs_positive */
enum gm_sub_sense {
	/* negative/pruning: S,G in EXCLUDE */
	GM_SUB_NEG = 0,
	/* positive/joining: *,G in EXCLUDE and S,G in INCLUDE */
	GM_SUB_POS = 1,
};

enum gm_sg_state {
	GM_SG_NOINFO = 0,
	GM_SG_JOIN,
	GM_SG_JOIN_EXPIRING,
	/* remaining 3 only valid for S,G when *,G in EXCLUDE */
	GM_SG_PRUNE,
	GM_SG_NOPRUNE,
	GM_SG_NOPRUNE_EXPIRING,
};

/* If the timer gm_t_sg_expire is started without a leave message being received,
 * the sg->state should be moved to expiring states.
 * When the timer expires, we do not expect the state to be in join state.
 * If a JOIN message is received while the timer is running,
 * the state will be moved to JOIN and this timer will be switched off.
 * Hence the below state transition is done.
 */
#define GM_UPDATE_SG_STATE(sg)                                                 \
	do {                                                                   \
		if (sg->state == GM_SG_JOIN)                                   \
			sg->state = GM_SG_JOIN_EXPIRING;                       \
		else if (sg->state == GM_SG_NOPRUNE)                           \
			sg->state = GM_SG_NOPRUNE_EXPIRING;                    \
	} while (0)

static inline bool gm_sg_state_want_join(enum gm_sg_state state)
{
	return state != GM_SG_NOINFO && state != GM_SG_PRUNE;
}

/* MLD (S,G) state (on an interface)
 *
 * group is always != ::, src is :: for (*,G) joins.  sort order in RB tree is
 * such that sources for a particular group can be iterated by starting at the
 * group.  For INCLUDE, no (*,G) entry exists, only (S,G).
 */

PREDECL_RBTREE_UNIQ(gm_packet_sg_subs);
PREDECL_RBTREE_UNIQ(gm_sgs);
struct gm_sg {
	pim_sgaddr sgaddr;
	struct gm_if *iface;
	struct gm_sgs_item itm;

	enum gm_sg_state state;
	struct channel_oil *oil;
	bool tib_joined;

	struct timeval created;

	/* if a group- or group-and-source specific query is running
	 * (implies we haven't received any report yet, since it's cancelled
	 * by that)
	 */
	struct event *t_sg_expire;

	/* last-member-left triggered queries (group/group-source specific)
	 *
	 * this timer will be running even if we aren't the elected querier,
	 * in case the election result changes midway through.
	 */
	struct event *t_sg_query;

	/* we must keep sending (QRV) queries even if we get a positive
	 * response, to make sure other routers are updated.  query_sbit
	 * will be set in that case, since other routers need the *response*,
	 * not the *query*
	 */
	uint8_t n_query;
	bool query_sbit;

	/* subs_positive tracks gm_packet_sg resulting in a JOIN, i.e. for
	 * (*,G) it has *EXCLUDE* items, for (S,G) it has *INCLUDE* items.
	 *
	 * subs_negative is always empty for (*,G) and tracks EXCLUDE items
	 * for (S,G).  This means that an (S,G) entry is active as a PRUNE if
	 *   len(src->subs_negative) == len(grp->subs_positive)
	 *   && len(src->subs_positive) == 0
	 * (i.e. all receivers for the group opted to exclude this S,G and
	 * noone did an SSM join for the S,G)
	 */
	union {
		struct {
			struct gm_packet_sg_subs_head subs_negative[1];
			struct gm_packet_sg_subs_head subs_positive[1];
		};
		struct gm_packet_sg_subs_head subs[2];
	};

	/* If the elected querier is not ourselves, queries and reports might
	 * get reordered in rare circumstances, i.e. the report could arrive
	 * just a microsecond before the query kicks off the timer.  This can
	 * then result in us thinking there are no more receivers since no
	 * report might be received during the query period.
	 *
	 * To avoid this, keep track of the most recent report for this (S,G)
	 * so we can do a quick check to add just a little bit of slack.
	 *
	 * EXCLUDE S,Gs are never in most_recent.
	 */
	struct gm_packet_sg *most_recent;
};
int gm_sg_cmp(const struct gm_sg *a, const struct gm_sg *b);
DECLARE_RBTREE_UNIQ(gm_sgs, struct gm_sg, itm, gm_sg_cmp);

/* host tracking entry.  addr will be one of:
 *
 * ::		- used by hosts during address acquisition
 * ::1		- may show up on some OS for joins by the router itself
 * link-local	- regular operation by MLDv2 hosts
 * ffff:..:ffff	- MLDv1 entry (cannot be tracked due to report suppression)
 *
 * global scope IPv6 addresses can never show up here
 */
PREDECL_HASH(gm_subscribers);
PREDECL_DLIST(gm_packets);
struct gm_subscriber {
	pim_addr addr;
	struct gm_subscribers_item itm;

	struct gm_if *iface;
	size_t refcount;

	struct gm_packets_head packets[1];

	struct timeval created;
};

/*
 * MLD join state is kept batched by packet.  Since the timers for all items
 * in a packet are the same, this reduces the number of timers we're keeping
 * track of.  It also eases tracking for EXCLUDE state groups because the
 * excluded sources are in the same packet.  (MLD does not support splitting
 * that if it exceeds MTU, it's always a full replace for exclude.)
 *
 * Since packets may be partially superseded by newer packets, the "active"
 * field is used to track this.
 */

/* gm_packet_sg is allocated as part of gm_packet_state, note the items[0]
 * array at the end of that.  gm_packet_sg is NEVER directly allocated with
 * XMALLOC/XFREE.
 */
struct gm_packet_sg {
	/* non-NULL as long as this gm_packet_sg is the most recent entry
	 * for (subscriber,S,G).  Cleared to NULL when a newer packet by the
	 * subscriber replaces this item.
	 *
	 * (Old items are kept around so we don't need to realloc/resize
	 * gm_packet_state, which would mess up a whole lot of pointers)
	 */
	struct gm_sg *sg;

	/* gm_sg -> (subscriber, gm_packet_sg)
	 * only on RB-tree while sg != NULL, i.e. not superseded by newer.
	 */
	struct gm_packet_sg_subs_item subs_itm;

	bool is_src : 1; /* := (src != ::) */
	bool is_excl : 1;

	/* for getting back to struct gm_packet_state, cf.
	 * gm_packet_sg2state() below
	 */
	uint16_t offset;

	/* if this is a group entry in EXCLUDE state, n_exclude counts how
	 * many sources are on the exclude list here.  They follow immediately
	 * after.
	 */
	uint16_t n_exclude;
};

#define gm_packet_sg2state(sg)                                                 \
	container_of(sg, struct gm_packet_state, items[sg->offset])

PREDECL_DLIST(gm_packet_expires);
struct gm_packet_state {
	struct gm_if *iface;
	struct gm_subscriber *subscriber;
	struct gm_packets_item pkt_itm;

	struct timeval received;
	struct gm_packet_expires_item exp_itm;

	/* n_active starts equal to n_sg;  whenever active is set to false on
	 * an item it is decremented.  When n_active == 0, the packet can be
	 * freed.
	 */
	uint16_t n_sg, n_active;
	struct gm_packet_sg items[0];
};

/* general queries are rather different from group/S,G specific queries;  it's
 * not particularly efficient or useful to try to shoehorn them into the S,G
 * timers.  Instead, we keep a history of recent queries and their implied
 * expiries.
 */
struct gm_general_pending {
	struct timeval query, expiry;
};

/* similarly, group queries also age out S,G entries for the group, but in
 * this case we only keep one query for each group
 *
 * why is this not in the *,G gm_sg?  There may not be one (for INCLUDE mode
 * groups, or groups we don't know about.)  Also, malicious clients could spam
 * random group-specific queries to trigger resource exhaustion, so it makes
 * sense to limit these.
 */
PREDECL_RBTREE_UNIQ(gm_grp_pends);
struct gm_grp_pending {
	struct gm_grp_pends_item itm;
	struct gm_if *iface;
	pim_addr grp;

	struct timeval query;
	struct event *t_expire;
};

/* guaranteed MTU for IPv6 is 1280 bytes.  IPv6 header is 40 bytes, MLDv2
 * query header is 24 bytes, RA option is 8 bytes - leaves 1208 bytes for the
 * source list, which is 151 IPv6 addresses.  But we may have some more IPv6
 * extension headers (e.g. IPsec AH), so just cap to 128
 */
#define MLD_V2Q_MTU_MAX_SOURCES 128

/* group-and-source-specific queries are bundled together, if some host joins
 * multiple sources it's likely to drop all at the same time.
 *
 * Unlike gm_grp_pending, this is only used for aggregation since the S,G
 * state is kept directly in the gm_sg structure.
 */
PREDECL_HASH(gm_gsq_pends);
struct gm_gsq_pending {
	struct gm_gsq_pends_item itm;

	struct gm_if *iface;
	struct event *t_send;

	pim_addr grp;
	bool s_bit;

	size_t n_src;
	pim_addr srcs[MLD_V2Q_MTU_MAX_SOURCES];
};


/* The size of this history is limited by QRV, i.e. there can't be more than
 * 8 items here.
 */
#define GM_MAX_PENDING 8

enum gm_version {
	GM_NONE,
	GM_MLDV1,
	GM_MLDV2,
};

struct gm_if_stats {
	uint64_t rx_drop_csum;
	uint64_t rx_drop_srcaddr;
	uint64_t rx_drop_dstaddr;
	uint64_t rx_drop_ra;
	uint64_t rx_drop_malformed;
	uint64_t rx_trunc_report;

	/* since the types are different, this is rx_old_* not of rx_*_old */
	uint64_t rx_old_report;
	uint64_t rx_old_leave;
	uint64_t rx_new_report;

	uint64_t rx_query_new_general;
	uint64_t rx_query_new_group;
	uint64_t rx_query_new_groupsrc;
	uint64_t rx_query_new_sbit;
	uint64_t rx_query_old_general;
	uint64_t rx_query_old_group;

	uint64_t tx_query_new_general;
	uint64_t tx_query_new_group;
	uint64_t tx_query_new_groupsrc;
	uint64_t tx_query_old_general;
	uint64_t tx_query_old_group;

	uint64_t tx_query_fail;
};

struct gm_if {
	struct interface *ifp;
	struct pim_instance *pim;
	struct event *t_query, *t_other_querier, *t_expire;

	bool stopping;

	uint8_t n_startup;

	uint8_t cur_qrv;
	unsigned int cur_query_intv;	  /* ms */
	unsigned int cur_query_intv_trig; /* ms */
	unsigned int cur_max_resp;	  /* ms */
	enum gm_version cur_version;
	int cur_lmqc; /* last member query count in ds */

	/* this value (positive, default 10ms) defines our "timing tolerance":
	 * - added to deadlines for expiring joins
	 * - used to look backwards in time for queries, in case a report was
	 *   reordered before the query
	 */
	struct timeval cfg_timing_fuzz;

	/* items in pending[] are sorted by expiry, pending[0] is earliest */
	struct gm_general_pending pending[GM_MAX_PENDING];
	uint8_t n_pending;
	struct gm_grp_pends_head grp_pends[1];
	struct gm_gsq_pends_head gsq_pends[1];

	pim_addr querier;
	pim_addr cur_ll_lowest;

	struct gm_sgs_head sgs[1];
	struct gm_subscribers_head subscribers[1];
	struct gm_packet_expires_head expires[1];

	struct timeval started;
	struct gm_if_stats stats;
};

#if PIM_IPV == 6
extern void gm_ifp_update(struct interface *ifp);
extern void gm_ifp_teardown(struct interface *ifp);
extern void gm_group_delete(struct gm_if *gm_ifp);
#else
static inline void gm_ifp_update(struct interface *ifp)
{
}

static inline void gm_ifp_teardown(struct interface *ifp)
{
}
#endif

extern void gm_cli_init(void);
bool in6_multicast_nofwd(const pim_addr *addr);

#endif /* PIM6_MLD_H */
