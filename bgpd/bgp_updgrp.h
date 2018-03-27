/**
 * bgp_updgrp.c: BGP update group structures
 *
 * @copyright Copyright (C) 2014 Cumulus Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.net>
 * @author Rajesh Varadarajan <rajesh@sproute.net>
 * @author Pradosh Mohapatra <pradosh@sproute.net>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_UPDGRP_H
#define _QUAGGA_BGP_UPDGRP_H

#include "bgp_advertise.h"

/*
 * The following three heuristic constants determine how long advertisement to
 * a subgroup will be delayed after it is created. The intent is to allow
 * transient changes in peer state (primarily session establishment) to settle,
 * so that more peers can be grouped together and benefit from sharing
 * advertisement computations with the subgroup.
 *
 * These values have a very large impact on initial convergence time; any
 * changes should be accompanied by careful performance testing at all scales.
 *
 * The coalesce time 'C' for a new subgroup within a particular BGP instance
 * 'B' with total number of known peers 'P', established or not, is computed as
 * follows:
 *
 * C = MIN(BGP_MAX_SUBGROUP_COALESCE_TIME,
 *         BGP_DEFAULT_SUBGROUP_COALESCE_TIME +
 *         (P*BGP_PEER_ADJUST_SUBGROUP_COALESCE_TIME))
 */
#define BGP_DEFAULT_SUBGROUP_COALESCE_TIME 1000
#define BGP_MAX_SUBGROUP_COALESCE_TIME 10000
#define BGP_PEER_ADJUST_SUBGROUP_COALESCE_TIME 50

#define PEER_UPDGRP_FLAGS                                                      \
	(PEER_FLAG_LOCAL_AS_NO_PREPEND | PEER_FLAG_LOCAL_AS_REPLACE_AS)

#define PEER_UPDGRP_AF_FLAGS                                                   \
	(PEER_FLAG_SEND_COMMUNITY | PEER_FLAG_SEND_EXT_COMMUNITY               \
	 | PEER_FLAG_DEFAULT_ORIGINATE | PEER_FLAG_REFLECTOR_CLIENT            \
	 | PEER_FLAG_RSERVER_CLIENT | PEER_FLAG_NEXTHOP_SELF                   \
	 | PEER_FLAG_NEXTHOP_UNCHANGED | PEER_FLAG_FORCE_NEXTHOP_SELF          \
	 | PEER_FLAG_AS_PATH_UNCHANGED | PEER_FLAG_MED_UNCHANGED               \
	 | PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED | PEER_FLAG_REMOVE_PRIVATE_AS     \
	 | PEER_FLAG_REMOVE_PRIVATE_AS_ALL                                     \
	 | PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE                                 \
	 | PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE                             \
	 | PEER_FLAG_ADDPATH_TX_ALL_PATHS                                      \
	 | PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS | PEER_FLAG_AS_OVERRIDE)

#define PEER_UPDGRP_CAP_FLAGS (PEER_CAP_AS4_RCV)

#define PEER_UPDGRP_AF_CAP_FLAGS                                               \
	(PEER_CAP_ORF_PREFIX_SM_RCV | PEER_CAP_ORF_PREFIX_SM_OLD_RCV           \
	 | PEER_CAP_ADDPATH_AF_TX_ADV | PEER_CAP_ADDPATH_AF_RX_RCV             \
	 | PEER_CAP_ENHE_AF_NEGO)

typedef enum { BGP_ATTR_VEC_NH = 0, BGP_ATTR_VEC_MAX } bpacket_attr_vec_type;

typedef struct {
	uint32_t flags;
	unsigned long offset;
} bpacket_attr_vec;

#define BPKT_ATTRVEC_FLAGS_UPDATED        (1 << 0)
#define BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS   (1 << 1)
#define BPKT_ATTRVEC_FLAGS_REFLECTED (1 << 2)
#define BPKT_ATTRVEC_FLAGS_RMAP_NH_UNCHANGED   (1 << 3)
#define BPKT_ATTRVEC_FLAGS_RMAP_IPV4_NH_CHANGED   (1 << 4)
#define BPKT_ATTRVEC_FLAGS_RMAP_IPV6_GNH_CHANGED  (1 << 5)
#define BPKT_ATTRVEC_FLAGS_RMAP_IPV6_LNH_CHANGED  (1 << 6)

typedef struct bpacket_attr_vec_arr {
	bpacket_attr_vec entries[BGP_ATTR_VEC_MAX];
} bpacket_attr_vec_arr;

struct bpacket {
	/* for being part of an update subgroup's message list */
	TAILQ_ENTRY(bpacket) pkt_train;

	/* list of peers (well, peer_afs) that the packet needs to be sent to */
	LIST_HEAD(pkt_peer_list, peer_af) peers;

	struct stream *buffer;
	bpacket_attr_vec_arr arr;

	unsigned int ver;
};

struct bpacket_queue {
	TAILQ_HEAD(pkt_queue, bpacket) pkts;

#if 0
  /* A dummy packet that is used to thread all peers that have
     completed their work */
  struct bpacket sentinel;
#endif

	unsigned int conf_max_count;
	unsigned int curr_count;
	unsigned int hwm_count;
	unsigned int max_count_reached_count;
};

struct update_group {
	/* back pointer to the BGP instance */
	struct bgp *bgp;

	/* list of subgroups that belong to the update group */
	LIST_HEAD(subgrp_list, update_subgroup) subgrps;

	/* lazy way to store configuration common to all peers
	   hash function will compute from this data */
	struct peer *conf;

	afi_t afi;
	safi_t safi;
	int afid;

	uint64_t id;
	time_t uptime;

	uint32_t join_events;
	uint32_t prune_events;
	uint32_t merge_events;
	uint32_t updgrp_switch_events;
	uint32_t peer_refreshes_combined;
	uint32_t adj_count;
	uint32_t split_events;
	uint32_t merge_checks_triggered;

	uint32_t subgrps_created;
	uint32_t subgrps_deleted;

	uint32_t num_dbg_en_peers;
};

/*
 * Shorthand for a global statistics counter.
 */
#define UPDGRP_GLOBAL_STAT(updgrp, stat)                                       \
	((updgrp)->bgp->update_group_stats.stat)

/*
 * Add the given value to a counter on an update group and the bgp
 * instance.
 */
#define UPDGRP_INCR_STAT_BY(updgrp, stat, value)                               \
	do {                                                                   \
		(updgrp)->stat += (value);                                     \
		UPDGRP_GLOBAL_STAT(updgrp, stat) += (value);                   \
	} while (0)

/*
 * Increment a counter on a update group and its parent structures.
 */
#define UPDGRP_INCR_STAT(subgrp, stat) UPDGRP_INCR_STAT_BY(subgrp, stat, 1)

struct update_subgroup {
	/* back pointer to the parent update group */
	struct update_group *update_group;

	/* list of peers that belong to the subgroup */
	LIST_HEAD(peer_list, peer_af) peers;
	int peer_count;

	/* for being part of an update group's subgroup list */
	LIST_ENTRY(update_subgroup) updgrp_train;

	struct bpacket_queue pkt_queue;

	/*
	 * List of adj-out structures for this subgroup.
	 * It essentially represents the snapshot of every prefix that
	 * has been advertised to the members of the subgroup
	 */
	TAILQ_HEAD(adjout_queue, bgp_adj_out) adjq;

	/* packet buffer for update generation */
	struct stream *work;

	/* We use a separate stream to encode MP_REACH_NLRI for efficient
	 * NLRI packing. peer->obuf_work stores all the other attributes. The
	 * actual packet is then constructed by concatenating the two.
	 */
	struct stream *scratch;

	/* synchronization list and time */
	struct bgp_synchronize *sync;

	/* send prefix count */
	unsigned long scount;

	/* announcement attribute hash */
	struct hash *hash;

	struct thread *t_coalesce;
	uint32_t v_coalesce;

	struct thread *t_merge_check;

	/* table version that the subgroup has caught up to. */
	uint64_t version;

	/* version maintained to record adj changes */
	uint64_t adj_version;

	time_t uptime;

	/*
	 * Identifying information about the subgroup that this subgroup was
	 * split
	 * from, if any.
	 */
	struct {
		uint64_t update_group_id;
		uint64_t subgroup_id;
	} split_from;

	uint32_t join_events;
	uint32_t prune_events;

	/*
	 * This is bumped up when another subgroup merges into this one.
	 */
	uint32_t merge_events;
	uint32_t updgrp_switch_events;
	uint32_t peer_refreshes_combined;
	uint32_t adj_count;
	uint32_t split_events;
	uint32_t merge_checks_triggered;

	uint64_t id;

	uint16_t sflags;

	/* Subgroup flags, see below  */
	uint16_t flags;
};

/*
 * We need to do an outbound refresh to get this subgroup into a
 * consistent state.
 */
#define SUBGRP_FLAG_NEEDS_REFRESH         (1 << 0)

#define SUBGRP_STATUS_DEFAULT_ORIGINATE   (1 << 0)

/*
 * Add the given value to the specified counter on a subgroup and its
 * parent structures.
 */
#define SUBGRP_INCR_STAT_BY(subgrp, stat, value)                               \
	do {                                                                   \
		(subgrp)->stat += (value);                                     \
		if ((subgrp)->update_group)                                    \
			UPDGRP_INCR_STAT_BY((subgrp)->update_group, stat,      \
					    value);                            \
	} while (0)

/*
 * Increment a counter on a subgroup and its parent structures.
 */
#define SUBGRP_INCR_STAT(subgrp, stat) SUBGRP_INCR_STAT_BY(subgrp, stat, 1)

/*
 * Decrement a counter on a subgroup and its parent structures.
 */
#define SUBGRP_DECR_STAT(subgrp, stat) SUBGRP_INCR_STAT_BY(subgrp, stat, -1)

typedef int (*updgrp_walkcb)(struct update_group *updgrp, void *ctx);

/* really a private structure */
struct updwalk_context {
	struct vty *vty;
	struct bgp_node *rn;
	struct bgp_info *ri;
	uint64_t updgrp_id;
	uint64_t subgrp_id;
	bgp_policy_type_e policy_type;
	const char *policy_name;
	int policy_event_start_flag;
	int policy_route_update;
	updgrp_walkcb cb;
	void *context;
	uint8_t flags;

#define UPDWALK_FLAGS_ADVQUEUE   (1 << 0)
#define UPDWALK_FLAGS_ADVERTISED (1 << 1)
};

#define UPDWALK_CONTINUE HASHWALK_CONTINUE
#define UPDWALK_ABORT HASHWALK_ABORT

#define PAF_PEER(p)        ((p)->peer)
#define PAF_SUBGRP(p)      ((p)->subgroup)
#define PAF_UPDGRP(p)      ((p)->subgroup->update_group)
#define PAF_PKTQ(f)        SUBGRP_PKTQ((f)->subgroup)

#define UPDGRP_PEER(u)     ((u)->conf)
#define UPDGRP_AFI(u)      ((u)->afi)
#define UPDGRP_SAFI(u)     ((u)->safi)
#define UPDGRP_INST(u)     ((u)->bgp)
#define UPDGRP_AFFLAGS(u) ((u)->conf->af_flags[UPDGRP_AFI(u)][UPDGRP_SAFI(u)])
#define UPDGRP_DBG_ON(u)   ((u)->num_dbg_en_peers)
#define UPDGRP_PEER_DBG_EN(u)  (((u)->num_dbg_en_peers)++)
#define UPDGRP_PEER_DBG_DIS(u) (((u)->num_dbg_en_peers)--)
#define UPDGRP_PEER_DBG_OFF(u) (u)->num_dbg_en_peers = 0

#define SUBGRP_AFI(s)      UPDGRP_AFI((s)->update_group)
#define SUBGRP_SAFI(s)     UPDGRP_SAFI((s)->update_group)
#define SUBGRP_PEER(s)     UPDGRP_PEER((s)->update_group)
#define SUBGRP_PCOUNT(s)   ((s)->peer_count)
#define SUBGRP_PFIRST(s)   LIST_FIRST(&((s)->peers))
#define SUBGRP_PKTQ(s)     &((s)->pkt_queue)
#define SUBGRP_INST(s)     UPDGRP_INST((s)->update_group)
#define SUBGRP_AFFLAGS(s)  UPDGRP_AFFLAGS((s)->update_group)
#define SUBGRP_UPDGRP(s)   ((s)->update_group)

/*
 * Walk all subgroups in an update group.
 */
#define UPDGRP_FOREACH_SUBGRP(updgrp, subgrp)                                  \
	LIST_FOREACH (subgrp, &((updgrp)->subgrps), updgrp_train)

#define UPDGRP_FOREACH_SUBGRP_SAFE(updgrp, subgrp, tmp_subgrp)                 \
	LIST_FOREACH_SAFE (subgrp, &((updgrp)->subgrps), updgrp_train,         \
			   tmp_subgrp)

#define SUBGRP_FOREACH_PEER(subgrp, paf)                                       \
	LIST_FOREACH (paf, &(subgrp->peers), subgrp_train)

#define SUBGRP_FOREACH_PEER_SAFE(subgrp, paf, temp_paf)                        \
	LIST_FOREACH_SAFE (paf, &(subgrp->peers), subgrp_train, temp_paf)

#define SUBGRP_FOREACH_ADJ(subgrp, adj)                                        \
	TAILQ_FOREACH (adj, &(subgrp->adjq), subgrp_adj_train)

#define SUBGRP_FOREACH_ADJ_SAFE(subgrp, adj, adj_temp)                         \
	TAILQ_FOREACH_SAFE (adj, &(subgrp->adjq), subgrp_adj_train, adj_temp)

/* Prototypes.  */
/* bgp_updgrp.c */
extern void update_bgp_group_init(struct bgp *);
extern void udpate_bgp_group_free(struct bgp *);

extern void update_group_show(struct bgp *bgp, afi_t afi, safi_t safi,
			      struct vty *vty, uint64_t subgrp_id);
extern void update_group_show_stats(struct bgp *bgp, struct vty *vty);
extern void update_group_adjust_peer(struct peer_af *paf);
extern int update_group_adjust_soloness(struct peer *peer, int set);

extern void update_subgroup_remove_peer(struct update_subgroup *,
					struct peer_af *);
extern struct bgp_table *update_subgroup_rib(struct update_subgroup *);
extern void update_subgroup_split_peer(struct peer_af *, struct update_group *);
extern int update_subgroup_check_merge(struct update_subgroup *, const char *);
extern int update_subgroup_trigger_merge_check(struct update_subgroup *,
					       int force);
extern void update_group_policy_update(struct bgp *bgp, bgp_policy_type_e ptype,
				       const char *pname, int route_update,
				       int start_event);
extern void update_group_af_walk(struct bgp *bgp, afi_t afi, safi_t safi,
				 updgrp_walkcb cb, void *ctx);
extern void update_group_walk(struct bgp *bgp, updgrp_walkcb cb, void *ctx);
extern void update_group_periodic_merge(struct bgp *bgp);
extern int
update_group_refresh_default_originate_route_map(struct thread *thread);
extern void update_group_start_advtimer(struct bgp *bgp);

extern void update_subgroup_inherit_info(struct update_subgroup *to,
					 struct update_subgroup *from);

/* bgp_updgrp_packet.c */
extern struct bpacket *bpacket_alloc(void);
extern void bpacket_free(struct bpacket *pkt);
extern void bpacket_queue_init(struct bpacket_queue *q);
extern void bpacket_queue_cleanup(struct bpacket_queue *q);
extern void bpacket_queue_sanity_check(struct bpacket_queue *q);
extern struct bpacket *bpacket_queue_add(struct bpacket_queue *q,
					 struct stream *s,
					 struct bpacket_attr_vec_arr *vecarr);
struct bpacket *bpacket_queue_remove(struct bpacket_queue *q);
extern struct bpacket *bpacket_queue_first(struct bpacket_queue *q);
struct bpacket *bpacket_queue_last(struct bpacket_queue *q);
unsigned int bpacket_queue_length(struct bpacket_queue *q);
unsigned int bpacket_queue_hwm_length(struct bpacket_queue *q);
int bpacket_queue_is_full(struct bgp *bgp, struct bpacket_queue *q);
extern void bpacket_queue_advance_peer(struct peer_af *paf);
extern void bpacket_queue_remove_peer(struct peer_af *paf);
extern void bpacket_add_peer(struct bpacket *pkt, struct peer_af *paf);
unsigned int bpacket_queue_virtual_length(struct peer_af *paf);
extern void bpacket_queue_show_vty(struct bpacket_queue *q, struct vty *vty);
int subgroup_packets_to_build(struct update_subgroup *subgrp);
extern struct bpacket *subgroup_update_packet(struct update_subgroup *s);
extern struct bpacket *subgroup_withdraw_packet(struct update_subgroup *s);
extern struct stream *bpacket_reformat_for_peer(struct bpacket *pkt,
						struct peer_af *paf);
extern void bpacket_attr_vec_arr_reset(struct bpacket_attr_vec_arr *vecarr);
extern void bpacket_attr_vec_arr_set_vec(struct bpacket_attr_vec_arr *vecarr,
					 bpacket_attr_vec_type type,
					 struct stream *s, struct attr *attr);
extern void subgroup_default_update_packet(struct update_subgroup *subgrp,
					   struct attr *attr,
					   struct peer *from);
extern void subgroup_default_withdraw_packet(struct update_subgroup *subgrp);

/* bgp_updgrp_adv.c */
extern struct bgp_advertise *
bgp_advertise_clean_subgroup(struct update_subgroup *subgrp,
			     struct bgp_adj_out *adj);
extern void update_group_show_adj_queue(struct bgp *bgp, afi_t afi, safi_t safi,
					struct vty *vty, uint64_t id);
extern void update_group_show_advertised(struct bgp *bgp, afi_t afi,
					 safi_t safi, struct vty *vty,
					 uint64_t id);
extern void update_group_show_packet_queue(struct bgp *bgp, afi_t afi,
					   safi_t safi, struct vty *vty,
					   uint64_t id);
extern void subgroup_announce_route(struct update_subgroup *subgrp);
extern void subgroup_announce_all(struct update_subgroup *subgrp);

extern void subgroup_default_originate(struct update_subgroup *subgrp,
				       int withdraw);
extern void group_announce_route(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct bgp_node *rn, struct bgp_info *ri);
extern void subgroup_clear_table(struct update_subgroup *subgrp);
extern void update_group_announce(struct bgp *bgp);
extern void update_group_announce_rrclients(struct bgp *bgp);
extern void peer_af_announce_route(struct peer_af *paf, int combine);
extern struct bgp_adj_out *bgp_adj_out_alloc(struct update_subgroup *subgrp,
					     struct bgp_node *rn,
					     uint32_t addpath_tx_id);
extern void bgp_adj_out_remove_subgroup(struct bgp_node *rn,
					struct bgp_adj_out *adj,
					struct update_subgroup *subgrp);
extern void bgp_adj_out_set_subgroup(struct bgp_node *rn,
				     struct update_subgroup *subgrp,
				     struct attr *attr, struct bgp_info *binfo);
extern void bgp_adj_out_unset_subgroup(struct bgp_node *rn,
				       struct update_subgroup *subgrp,
				       char withdraw, uint32_t addpath_tx_id);
void subgroup_announce_table(struct update_subgroup *subgrp,
			     struct bgp_table *table);
extern void subgroup_trigger_write(struct update_subgroup *subgrp);

extern int update_group_clear_update_dbg(struct update_group *updgrp,
					 void *arg);

extern void update_bgp_group_free(struct bgp *bgp);
extern int bgp_addpath_encode_tx(struct peer *peer, afi_t afi, safi_t safi);
extern int bgp_addpath_tx_path(struct peer *peer, afi_t afi, safi_t safi,
			       struct bgp_info *ri);

/*
 * Inline functions
 */

/*
 * bpacket_queue_is_empty
 */
static inline int bpacket_queue_is_empty(struct bpacket_queue *queue)
{

	/*
	 * The packet queue is empty if it only contains a sentinel.
	 */
	if (queue->curr_count != 1)
		return 0;

	assert(bpacket_queue_first(queue)->buffer == NULL);
	return 1;
}

/*
 * bpacket_next
 *
 * Returns the packet after the given packet in a bpacket queue.
 */
static inline struct bpacket *bpacket_next(struct bpacket *pkt)
{
	return TAILQ_NEXT(pkt, pkt_train);
}

/*
 * update_group_adjust_peer_afs
 *
 * Adjust all peer_af structures for the given peer.
 */
static inline void update_group_adjust_peer_afs(struct peer *peer)
{
	struct peer_af *paf;
	int afidx;

	for (afidx = BGP_AF_START; afidx < BGP_AF_MAX; afidx++) {
		paf = peer->peer_af_array[afidx];
		if (paf != NULL)
			update_group_adjust_peer(paf);
	}
}

/*
 * update_group_remove_peer_afs
 *
 * Remove all peer_af structures for the given peer from their subgroups.
 */
static inline void update_group_remove_peer_afs(struct peer *peer)
{
	struct peer_af *paf;
	int afidx;

	for (afidx = BGP_AF_START; afidx < BGP_AF_MAX; afidx++) {
		paf = peer->peer_af_array[afidx];
		if (paf != NULL)
			update_subgroup_remove_peer(PAF_SUBGRP(paf), paf);
	}
}

/*
 * update_subgroup_needs_refresh
 */
static inline int
update_subgroup_needs_refresh(const struct update_subgroup *subgrp)
{
	if (CHECK_FLAG(subgrp->flags, SUBGRP_FLAG_NEEDS_REFRESH))
		return 1;
	else
		return 0;
}

/*
 * update_subgroup_set_needs_refresh
 */
static inline void
update_subgroup_set_needs_refresh(struct update_subgroup *subgrp, int value)
{
	if (value)
		SET_FLAG(subgrp->flags, SUBGRP_FLAG_NEEDS_REFRESH);
	else
		UNSET_FLAG(subgrp->flags, SUBGRP_FLAG_NEEDS_REFRESH);
}

static inline struct update_subgroup *peer_subgroup(struct peer *peer,
						    afi_t afi, safi_t safi)
{
	struct peer_af *paf;

	paf = peer_af_find(peer, afi, safi);
	if (paf)
		return PAF_SUBGRP(paf);
	return NULL;
}

/*
 * update_group_adjust_peer_afs
 *
 * Adjust all peer_af structures for the given peer.
 */
static inline void bgp_announce_peer(struct peer *peer)
{
	struct peer_af *paf;
	int afidx;

	for (afidx = BGP_AF_START; afidx < BGP_AF_MAX; afidx++) {
		paf = peer->peer_af_array[afidx];
		if (paf != NULL)
			subgroup_announce_all(PAF_SUBGRP(paf));
	}
}

/**
 * advertise_list_is_empty
 */
static inline int advertise_list_is_empty(struct update_subgroup *subgrp)
{
	if (!BGP_ADV_FIFO_EMPTY(&subgrp->sync->update)
	    || !BGP_ADV_FIFO_EMPTY(&subgrp->sync->withdraw)
	    || !BGP_ADV_FIFO_EMPTY(&subgrp->sync->withdraw_low)) {
		return 0;
	}

	return 1;
}

#endif /* _QUAGGA_BGP_UPDGRP_H */
