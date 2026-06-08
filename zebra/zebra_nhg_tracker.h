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
#include "table.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(NHG_TRACKER_PREFIX_MAP);

struct nhg_hash_entry;
struct event;
struct route_table;
struct route_entry;
struct route_node;

#define NHG_TRACKER_DEFAULT_TIMEOUT_SEC 10
//#define NHG_TRK_VERBOSE_LOG

enum nhg_tracker_event {
	NHG_TRACKER_EVENT_INTF_DOWN = 0,
	NHG_TRACKER_EVENT_INTF_UP,
	NHG_TRACKER_EVENT_ECMP_CHANGE,
};

PREDECL_DLIST(nhg_event_tracker_list);
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
 * Pausable table iterator over ONE nhg_tracker_table: libfrr inner
 * route_table_iter per VRF + outer cursor over vrf_tables list.
 */
struct nhg_tracker_table_iter {
	struct nhg_tracker_table *table;      /* which of matched/unmatched/deleted */
	struct tracker_vrf_table *current_vt; /* current entry in vrf_tables list */
	route_table_iter_t inner;	      /* libfrr layer-1, pausable */
};

extern void nhg_tracker_table_iter_rn_init(struct nhg_tracker_table_iter *iter,
					   struct nhg_tracker_table *table);
extern struct route_node *nhg_tracker_table_iter_rn_next(struct nhg_tracker_table_iter *iter);
extern void nhg_tracker_table_iter_rn_pause(struct nhg_tracker_table_iter *iter);
extern void nhg_tracker_table_iter_rn_cleanup(struct nhg_tracker_table_iter *iter);

/*
 * Per-RN options for tracker_flush_process_rn.
 */
struct tracker_flush_rn_opts {
	/* which table to process */
	struct nhg_tracker_table *table;
	uint32_t filter_nhg_id;
	uint32_t exclude_nhg_id;
	/* Used to track pending REs for dplane ack tracking */
	bool track_pending;
	/* Used to determine if this is the last walk of the table */
	bool is_last_walk;
};

/*
 * Flush batch state: tracks the two-phase flush of a tracker.
 * Phase 1 processes loser REs (non-winner NHG groups).
 * Phase 2 updates the parent NHG and processes winner REs.
 */
enum tracker_flush_batch_state {
	TRACKER_ACTIVE,	       /* parking REs, hasn't reached flush trigger */
	TRACKER_FLUSH_WAITING, /* ready to flush, blocked by another flushing tracker on same NHE */
	TRACKER_FLUSH_PHASE1,  /* draining loser/silent/deleted REs; waiting for dplane acks */
	TRACKER_FLUSH_PHASE2,  /* releasing winners and reworking parent NHG */
};

/*
 * Bitmask for winner flags:
 *   0                                      no winner (deletions-only flush)
 *   TRACKER_WIN_SILENT                     silent REs alone win
 *   TRACKER_WIN_MATCHED                    matched REs alone win
 *   TRACKER_WIN_SILENT|TRACKER_WIN_MATCHED matched & silent together win
 *   TRACKER_WIN_UNMATCHED                  unmatched group wins
 */
#define TRACKER_WIN_SILENT    (1u << 0)
#define TRACKER_WIN_MATCHED   (1u << 1)
#define TRACKER_WIN_UNMATCHED (1u << 2)

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

	/* Prefixes whose nexthops match nhg_tracker_snapshot */
	struct nhg_tracker_table matched_table;

	/* Prefixes whose nexthops do NOT match nhg_tracker_snapshot */
	struct nhg_tracker_table unmatched_table;

	/* Route deletions parked while tracker is active */
	struct nhg_tracker_table deleted_table;

	/* Started on tracker creation */
	struct event *timer;

	/* Back-pointer to the original NHG that this tracker is managing. */
	struct nhg_hash_entry *parent_nhe;

	/* Snapshot of the original NHG at the time of tracker creation. */
	struct nhg_hash_entry *nhg_tracker_snapshot;

	/* Index of the interface whose state change created this tracker. */
	ifindex_t ifindex;
	enum nhg_tracker_event event;

	/* Number of REs using the original NHG at tracker creation time */
	uint32_t orig_re_count;

	/*
	 * Flush batch state.  When flushing == true, the tracker is in
	 * two-phase flush and must not be collapsed, parked into, or reused.
	 * The tracker stays in tracker_list until the batch completes.
	 */
	bool flushing;
	enum tracker_flush_batch_state flush_state;
	uint32_t routes_pending;

	/*
	 * Winner metadata - computed by tracker_flush_build_groups and used by
	 * phases 1/2 flushing operations.  winner_nhg_id is the incoming NHG
	 * id of the unmatched winner group (used to filter unmatched_table
	 * processing), or the snapshot id when matched is the winner.
	 */
	uint8_t winner_flags;
	uint32_t winner_nhg_id;

	/* NHG group list built during flush for winner selection and ack tracking.
	 * Each listnode->data is a struct tracker_flush_nhg_group *.
	 */
	struct list *flush_nhg_groups;

	/* Pausable table iterator for the flush */
	struct nhg_tracker_table_iter iter;
	struct event *flush_iter_event;

	/*
	 * Phase-2 consumer count accumulator.  Bumped by every winner-
	 * release in phase 2 across all iter slices and tables.  At the
	 * end of phase 2 (when all iter tables are exhausted) the
	 * accumulator drives the tracker flush complete decision.
	 */
	uint32_t flush_phase2_consumers;

	/*
	 * Cached silent-RE count from tracker_flush_build_groups.
	 * Used by start_phase1 to silent RE flush decision.
	 */
	uint32_t flush_silent_count;
};

static inline bool tracker_win_includes_silent(const struct nhg_event_tracker *t)
{
	return (t->winner_flags & TRACKER_WIN_SILENT) != 0;
}

static inline bool tracker_win_includes_matched(const struct nhg_event_tracker *t)
{
	return (t->winner_flags & TRACKER_WIN_MATCHED) != 0;
}

static inline bool tracker_win_is_unmatched(const struct nhg_event_tracker *t)
{
	return (t->winner_flags & TRACKER_WIN_UNMATCHED) != 0;
}

static inline bool tracker_win_has_winner(const struct nhg_event_tracker *t)
{
	return t->winner_flags != 0;
}

DECLARE_DLIST(nhg_event_tracker_list, struct nhg_event_tracker, list_entry);

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

/* Init/fini tracker list inside nhg_hash_entry */
extern void zebra_nhg_tracker_init(struct nhg_hash_entry *nhe);
extern void zebra_nhg_tracker_fini(struct nhg_hash_entry *nhe);

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

/*
 * Returns true if there is at least one non-flushing (active) tracker
 */
extern bool zebra_nhg_tracker_has_active(struct nhg_hash_entry *nhe);

/* Returns true if a flushing tracker is attached to nhe */
extern bool zebra_nhg_tracker_has_flushing(struct nhg_hash_entry *nhe);

/*
 * Returns true if the prefix has an entry in nhe's tracker_prefix_map
 */
extern bool zebra_nhg_tracker_prefix_in_pm(struct nhg_hash_entry *nhe,
					   const struct route_node *rn,
					   const struct route_entry *re);

/* Flush tracker if all expected REs have been parked */
extern void zebra_nhg_tracker_flush_if_full(struct nhg_event_tracker *tracker,
					    struct nhg_hash_entry *nhe);

/* Create a new tracker on parent_nhe */
extern struct nhg_event_tracker *zebra_nhg_tracker_create(struct nhg_hash_entry *parent_nhe,
							  struct nhg_hash_entry *snapshot_src_nhe,
							  ifindex_t ifindex,
							  enum nhg_tracker_event event);

/* Create or update tracker for multi-singleton event batches */
extern struct nhg_event_tracker *zebra_nhg_tracker_create_or_update(struct nhg_hash_entry *nhe,
								    ifindex_t ifindex,
								    enum nhg_tracker_event event);

/* Walk the dependents of root_nhe and create/refresh a tracker on each. */
extern void zebra_nhg_tracker_create_for_event(struct nhg_hash_entry *root_nhe, ifindex_t ifindex,
					       enum nhg_tracker_event event);

/* Compare two NHGs for tracker semantics (resolution-tolerant). */
extern bool zebra_nhg_tracker_nhgs_equal(const struct nhg_hash_entry *a,
					 const struct nhg_hash_entry *b, bool skip_inactive_old);

extern void zebra_nhg_tracker_free(struct nhg_hash_entry *nhe, struct nhg_event_tracker *tracker);

/* Release all tracker-held RIB route_node locks before table teardown. */
extern void zebra_nhg_tracker_sweep_all(void);

/*
 * Two-phase flush batch API.
 * Called from rib_process_result (dplane ack), process_subq_route
 * (routes not sent to dplane), and rib_unlink (removed without dplane).
 */
extern void tracker_flush_batch_route_dplane_ack(struct route_entry *re);

/*
 * Drain a WINNER RE's slot from parent's pending counter before
 * rib_delnode sets REMOVED.  Call from rib_delnode prior to SET REMOVED.
 */
extern void tracker_winner_pre_remove(struct route_node *rn, struct route_entry *re);

/* Helper macros to check winner flags. */
static inline bool tracker_win_includes_silent(const struct nhg_event_tracker *t);
static inline bool tracker_win_includes_matched(const struct nhg_event_tracker *t);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NHG_TRACKER_H__ */
