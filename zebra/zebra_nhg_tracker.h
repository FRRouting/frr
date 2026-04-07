// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra NHG Event Tracker for defer and reuse of NHGs after interface events.
 *
 * Copyright (C) 2024 NVIDIA Corporation
 *		      Krishnasamy R
 *		      Donald Sharp
 *		      Eyal Nissim
 */

#ifndef __ZEBRA_NHG_TRACKER_H__
#define __ZEBRA_NHG_TRACKER_H__

#include "typesafe.h"
#include "prefix.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(NHG_TRACKER_PREFIX_MAP);

struct nhg_hash_entry;
struct event;
struct route_table;
struct route_entry;
struct route_node;

#define NHG_TRACKER_DEFAULT_TIMEOUT_SEC 20

enum nhg_tracker_event_intf {
	NHG_TRACKER_EVENT_INTF_DOWN = 0,
	NHG_TRACKER_EVENT_INTF_UP,
};

PREDECL_DLIST(nhg_event_tracker_list);
PREDECL_HASH(nhg_event_tracker_hash);
PREDECL_HASH(tracker_prefix_map);

struct tracker_prefix_map_entry {
	struct prefix p;
	int type;
	uint16_t instance;
	vrf_id_t vrf_id;
	struct nhg_event_tracker *tracker;
	struct tracker_prefix_map_item item;
};

/* Per-VRF route table entry for tracker matched/unmatched storage */
struct tracker_vrf_table {
	vrf_id_t vrf_id;
	struct route_table *table;
	struct tracker_vrf_table *next;
};

/* Matched/unmatched route table wrappers — one route_table per VRF */
struct nhg_tracker_table {
	struct tracker_vrf_table *vrf_tables;
	uint32_t re_count;
};

/*
 * Flush batch state: tracks the two-phase flush of a tracker.
 * Phase 1 processes losers (non-winner NHG groups).
 * Phase 2 updates the parent NHG and processes winners.
 */
enum tracker_flush_batch_state {
	TRACKER_FLUSH_IDLE = 0,
	TRACKER_FLUSH_PHASE1,
	TRACKER_FLUSH_PHASE2,
};

/*
 * Per-NHG group entry used during flush to count REs per incoming NHG
 * and to map incoming NHG IDs back to the parent NHG for dplane ack tracking.
 */
struct tracker_flush_nhg_group {
	uint32_t incoming_nhg_id;
	struct nhg_hash_entry *incoming_nhe;
	uint32_t re_count;
	bool is_winner;
};

struct nhg_event_tracker {
	uint32_t nhg_tracker_id;

	struct nhg_event_tracker_list_item list_entry;
	struct nhg_event_tracker_hash_item tracker_hash_link;

	/* Prefixes whose nexthops match nhg_tracker_snapshot */
	struct nhg_tracker_table matched_table;

	/* Prefixes whose nexthops do NOT match nhg_tracker_snapshot */
	struct nhg_tracker_table unmatched_table;

	/* Started on tracker creation; repurposed as safety timer during flush */
	struct event *timer;

	/* Back-pointer to the original NHG that this tracker is managing. */
	struct nhg_hash_entry *parent_nhe;

	/* Snapshot of the original NHG at the time of tracker creation. */
	struct nhg_hash_entry *nhg_tracker_snapshot;

	/* Index of the interface whose state change created this tracker. */
	ifindex_t ifindex;
	enum nhg_tracker_event_intf event;

	/* Number of REs using the original NHG at tracker creation time */
	uint32_t orig_re_count;

	/*
	 * Flush batch state.  When flushing == true, the tracker is in
	 * two-phase flush and must not be collapsed, parked into, or
	 * reused.  Its prefix_map entries are removed so new routes park
	 * in fresh trackers.  The tracker stays in tracker_list/hash
	 * until the batch completes.
	 */
	bool flushing;
	enum tracker_flush_batch_state flush_state;
	uint32_t routes_pending;

	/* Winner NHG metadata (set during flush, used by phase 2) */
	uint32_t winner_nhg_id;
	struct nhg_hash_entry *winner_nhe;
	bool winner_is_matched;

	/* NHG group list built during flush for winner selection and ack tracking.
	 * Each listnode->data is a struct tracker_flush_nhg_group *.
	 */
	struct list *flush_nhg_groups;
};

DECLARE_DLIST(nhg_event_tracker_list, struct nhg_event_tracker, list_entry);

/*
 * Typesafe hash for nhg_event_tracker
 */
extern int nhg_event_tracker_hash_cmp(const struct nhg_event_tracker *a,
				      const struct nhg_event_tracker *b);
extern uint32_t nhg_event_tracker_hash_key(const struct nhg_event_tracker *t);

DECLARE_HASH(nhg_event_tracker_hash, struct nhg_event_tracker, tracker_hash_link,
	     nhg_event_tracker_hash_cmp, nhg_event_tracker_hash_key);

/*
 * Typesafe hash for tracker_prefix_map: (prefix, type, instance, vrf_id) -> tracker
 */
extern uint32_t
tracker_prefix_map_hash_key(const struct tracker_prefix_map_entry *e);
extern int
tracker_prefix_map_hash_cmp(const struct tracker_prefix_map_entry *a,
			    const struct tracker_prefix_map_entry *b);

DECLARE_HASH(tracker_prefix_map, struct tracker_prefix_map_entry, item,
	     tracker_prefix_map_hash_cmp, tracker_prefix_map_hash_key);

/*
 * Tracker two-phase batch install.
 *
 * Phase 1: send all non-reuse groups at once (parallel).
 * Phase 2: send the reuse group (biggest group, preserves NHG ID).
 *
 * All batch state lives on the flushing tracker itself.
 * tracker->flushing == true indicates a batch is active.
 * tracker->timer is repurposed as the batch safety timer.
 */

/*
 * Global batch NHG map: maps child NHG IDs involved in active batches
 * to their parent NHG ID.  Used by rib_process_result to find the
 * batch counter without storing a per-RE field.  Typically 1-5 entries.
 */
extern void tracker_batch_nhg_map_add(uint32_t child_nhg_id, uint32_t parent_nhg_id);
extern void tracker_batch_nhg_map_clear(uint32_t parent_nhg_id);
extern uint32_t tracker_batch_nhg_map_lookup(uint32_t child_nhg_id);

/* Called from rib_process_result and rib_unlink when a batch route completes */
extern void tracker_batch_route_done(uint32_t parent_nhg_id);

/* Called from process_subq_route for batch routes not sent to dplane */
extern void tracker_batch_check_unsent(struct route_node *rn);

/* Init/fini tracker list and hash inside nhg_hash_entry */
extern void zebra_nhg_tracker_init(struct nhg_hash_entry *nhe);
extern void zebra_nhg_tracker_fini(struct nhg_hash_entry *nhe);

/* Lookup tracker by snapshot NHG state */
extern struct nhg_event_tracker *zebra_nhg_tracker_lookup(struct nhg_hash_entry *nhe,
							  struct nhg_hash_entry *snapshot);

/* Add a RIB route_node to a tracker table and update prefix_map */
extern void zebra_nhg_tracker_rn_add(struct nhg_tracker_table *tt, uint32_t *re_count,
				     struct tracker_prefix_map_head *prefix_map,
				     struct nhg_event_tracker *tracker, struct route_node *rn,
				     struct route_entry *re);

/* Park an RE in the appropriate tracker (called from rib_link).
 * orig_nhe is the originating NHE that carries the trackers.
 */
extern struct nhg_event_tracker *zebra_nhg_tracker_park_re(struct route_node *rn,
							   struct route_entry *re,
							   struct nhg_hash_entry *orig_nhe);

/* Flush tracker if all expected REs have been parked */
extern void zebra_nhg_tracker_flush_if_full(struct nhg_event_tracker *tracker,
					    struct nhg_hash_entry *nhe);

/* Create and cleanup tracker */
extern struct nhg_event_tracker *zebra_nhg_tracker_create(struct nhg_hash_entry *nhe,
							  ifindex_t ifindex,
							  enum nhg_tracker_event_intf event);

/* Create or update tracker for multi-singleton event batches */
extern struct nhg_event_tracker *
zebra_nhg_tracker_create_or_update(struct nhg_hash_entry *nhe, ifindex_t ifindex,
				   enum nhg_tracker_event_intf event);

extern void zebra_nhg_tracker_free(struct nhg_hash_entry *nhe, struct nhg_event_tracker *tracker);

/* Release all tracker-held RIB route_node locks before table teardown. */
extern void zebra_nhg_tracker_sweep_all(void);

/*
 * Two-phase flush batch API.
 * Called from rib_process_result (dplane ack), process_subq_route
 * (routes not sent to dplane), and rib_unlink (removed without dplane).
 */
extern void tracker_flush_batch_route_dplane_ack(struct route_entry *re);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NHG_TRACKER_H__ */
