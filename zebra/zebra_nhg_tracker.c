// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra NHG Event Tracker implementation.
 *
 * Copyright (C) 2024 NVIDIA Corporation
 *                    Krishnasamy R
 *                    Donald Sharp
 *                    Eyal Nissim
 */

#include <zebra.h>

#include "jhash.h"
#include "memory.h"
#include "table.h"

#include "zebra/rib.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_nhg_tracker.h"
#include "zebra/zebra_router.h"

DEFINE_MTYPE_STATIC(ZEBRA, NHG_TRACKER, "NHG Event Tracker");
DEFINE_MTYPE(ZEBRA, NHG_TRACKER_PREFIX_MAP, "NHG Tracker Prefix Map Entry");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_TRACKER_FLUSH_GROUP, "NHG Tracker Flush Group");

bool zebra_nhg_tracker_nhgs_equal(const struct nhg_hash_entry *a, const struct nhg_hash_entry *b,
				  bool skip_inactive_old)
{
	const struct nexthop *a_backup, *b_backup;

	if (a == b)
		return true;
	if (!a || !b)
		return false;

	/* NHG IDs are unique. equal non-zero IDs imply equal content. */
	if (a->id && b->id && a->id == b->id)
		return true;

	/* Resolution-tolerant comparision of primary nexthops. */
	if (!zebra_nhg_nexthop_compare(a->nhg.nexthop, b->nhg.nexthop, NULL, skip_inactive_old))
		return false;

	/*
	 * Compare the backup nexthops too so NHGs that share a primary but
	 * differ in backup gateway/label. They are not treated as equal.
	 * otherwise they would collapse onto one NHG.
	 */
	a_backup = a->backup_info ? a->backup_info->nhe->nhg.nexthop : NULL;
	b_backup = b->backup_info ? b->backup_info->nhe->nhg.nexthop : NULL;

	if ((a_backup == NULL) != (b_backup == NULL))
		return false;

	if (a_backup &&
	    !zebra_nhg_nexthop_compare(a_backup, b_backup, NULL, skip_inactive_old))
		return false;

	return true;
}

/*
 * Walk transitive dependents of nhe and create/refresh a tracker on each.
 * 'visited' is used to deduplicate the walk.
 */
static void tracker_create_walk_dependents(struct nhg_hash_entry *nhe, ifindex_t ifindex,
					   enum nhg_tracker_event event,
					   struct nhg_connected_tree_head *visited)
{
	struct nhg_connected *rb_node_dep;

	if (!nhe)
		return;

	/* already visited in this walk - skip subtree */
	if (nhg_connected_tree_add_nhe(visited, nhe) != NULL)
		return;

	zebra_nhg_tracker_create_or_update(nhe, ifindex, event);

	frr_each (nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep) {
		tracker_create_walk_dependents(rb_node_dep->nhe, ifindex, event, visited);
	}
}

void zebra_nhg_tracker_create_for_event(struct nhg_hash_entry *root_nhe, ifindex_t ifindex,
					enum nhg_tracker_event event)
{
	struct nhg_connected_tree_head visited = {};

	if (!root_nhe)
		return;

	nhg_connected_tree_init(&visited);
	tracker_create_walk_dependents(root_nhe, ifindex, event, &visited);
	nhg_connected_tree_free(&visited);
}

/* Get or create the route_table for a given VRF within a tracker table. */
static struct route_table *tracker_vrf_table_get(struct nhg_tracker_table *tt, vrf_id_t vrf_id)
{
	struct tracker_vrf_table *vt;

	for (vt = tt->vrf_tables; vt; vt = vt->next) {
		if (vt->vrf_id == vrf_id)
			return vt->table;
	}

	vt = XCALLOC(MTYPE_NHG_TRACKER, sizeof(*vt));
	vt->vrf_id = vrf_id;
	vt->table = route_table_init();
	vt->next = tt->vrf_tables;
	tt->vrf_tables = vt;
	return vt->table;
}

/* Free all per-VRF tables in a tracker table, unlocking any stored RIB RNs. */
static void tracker_vrf_tables_free(struct nhg_tracker_table *tt)
{
	struct tracker_vrf_table *vt, *next;

	for (vt = tt->vrf_tables; vt; vt = next) {
		next = vt->next;
		if (vt->table) {
			struct route_node *trn;

			for (trn = route_top(vt->table); trn; trn = route_next(trn)) {
				if (trn->info) {
					route_unlock_node(trn->info);
					trn->info = NULL;
					route_unlock_node(trn);
				}
			}
			route_table_finish(vt->table);
		}
		XFREE(MTYPE_NHG_TRACKER, vt);
	}
	tt->vrf_tables = NULL;
}

/*
 * tracker_prefix_map hash.
 * Key:   (prefix, protocol type, protocol instance, vrf_id).
 * Value: pointer to the tracker that owns this (prefix, type, instance, vrf).
 */
uint32_t tracker_prefix_map_hash_key(const struct tracker_prefix_map_entry *e)
{
	uint32_t key;

	key = prefix_hash_key(&e->p);
	key = jhash_2words((uint32_t)e->type, (uint32_t)e->instance, key);
	key = jhash_1word((uint32_t)e->vrf_id, key);
	return key;
}

int tracker_prefix_map_hash_cmp(const struct tracker_prefix_map_entry *a,
				const struct tracker_prefix_map_entry *b)
{
	if (a->type != b->type)
		return 1;
	if (a->instance != b->instance)
		return 1;
	if (a->vrf_id != b->vrf_id)
		return 1;
	return prefix_cmp(&a->p, &b->p) != 0;
}

/*
 * Move all per-VRF table entries from src into dst.
 * For each VRF table in src, get-or-create the matching VRF table in dst.
 * For each prefix: if dst doesn't have it, move the RN pointer.
 * If dst already has it, release the src reference.
 */
static void tracker_vrf_tables_move(struct nhg_tracker_table *src, struct nhg_tracker_table *dst)
{
	struct tracker_vrf_table *vt, *next;

	for (vt = src->vrf_tables; vt; vt = next) {
		next = vt->next;
		if (!vt->table) {
			XFREE(MTYPE_NHG_TRACKER, vt);
			continue;
		}

		struct route_table *dst_vrf_table = tracker_vrf_table_get(dst, vt->vrf_id);
		struct route_node *old_trn;

		for (old_trn = route_top(vt->table); old_trn; old_trn = route_next(old_trn)) {
			if (!old_trn->info)
				continue;

			struct route_node *trn = route_node_get(dst_vrf_table, &old_trn->p);

			if (!trn->info) {
				trn->info = old_trn->info;
			} else {
				route_unlock_node(trn);
				route_unlock_node(old_trn->info);
			}

			old_trn->info = NULL;
			route_unlock_node(old_trn);
		}

		route_table_finish(vt->table);
		XFREE(MTYPE_NHG_TRACKER, vt);
	}
	src->vrf_tables = NULL;
}

/*
 * Collapse a stale tracker into a target tracker.
 * Moves per-VRF table entries and re-points prefix_map entries from
 * old_tracker to new_tracker. Matched and unmatched rows become unmatched on
 * the keeper; deleted-table rows stay in deleted-table on the keeper. Transfers
 * counts, then destroys old tracker.
 */
static void zebra_nhg_tracker_collapse(struct tracker_prefix_map_head *prefix_map,
				       struct nhg_event_tracker *old_tracker,
				       struct nhg_event_tracker *new_tracker)
{
	struct tracker_prefix_map_entry *entry;

	tracker_vrf_tables_move(&old_tracker->matched_table, &new_tracker->unmatched_table);
	tracker_vrf_tables_move(&old_tracker->unmatched_table, &new_tracker->unmatched_table);
	tracker_vrf_tables_move(&old_tracker->deleted_table, &new_tracker->deleted_table);

	frr_each_safe (tracker_prefix_map, prefix_map, entry) {
		if (entry->tracker == old_tracker)
			entry->tracker = new_tracker;
	}

	new_tracker->unmatched_table.re_count += old_tracker->matched_table.re_count +
						 old_tracker->unmatched_table.re_count;
	old_tracker->matched_table.re_count = 0;
	old_tracker->unmatched_table.re_count = 0;

	new_tracker->deleted_table.re_count += old_tracker->deleted_table.re_count;
	old_tracker->deleted_table.re_count = 0;

	zlog_info("%s: collapsed tracker %u into tracker %u for NHG %u (new unmatched=%u deleted=%u)",
		  __func__, old_tracker->nhg_tracker_id, new_tracker->nhg_tracker_id,
		  new_tracker->parent_nhe ? new_tracker->parent_nhe->id : 0,
		  new_tracker->unmatched_table.re_count, new_tracker->deleted_table.re_count);

	zebra_nhg_tracker_free(old_tracker->parent_nhe, old_tracker);
}

/*
 * Add a RIB route_node to a tracker table (matched or unmatched)
 * and update the prefix_map.
 * If the prefix is new, sets trn->info = rn and increments re_count.
 * If the prefix already exists, releases the get-lock (no re_count change).
 * Uses prefix_map to ensure each prefix is owned by exactly one tracker.
 */
void zebra_nhg_tracker_rn_add(struct nhg_tracker_table *tt, uint32_t *re_count,
			      struct tracker_prefix_map_head *prefix_map,
			      struct nhg_event_tracker *tracker, struct route_node *rn,
			      struct route_entry *re)
{
	struct route_table *vrf_table;
	struct route_node *trn;

	vrf_table = tracker_vrf_table_get(tt, re->vrf_id);
	trn = route_node_get(vrf_table, &rn->p);
	if (!trn->info) {
		trn->info = rn;
		route_lock_node(rn);
	} else {
		route_unlock_node(trn);
	}

	if (prefix_map) {
		struct tracker_prefix_map_entry lookup_key;
		struct tracker_prefix_map_entry *entry;

		memset(&lookup_key, 0, sizeof(lookup_key));
		prefix_copy(&lookup_key.p, &rn->p);
		lookup_key.type = re->type;
		lookup_key.instance = re->instance;
		lookup_key.vrf_id = re->vrf_id;

		entry = tracker_prefix_map_find(prefix_map, &lookup_key);
		if (!entry) {
			entry = XCALLOC(MTYPE_NHG_TRACKER_PREFIX_MAP, sizeof(*entry));
			prefix_copy(&entry->p, &rn->p);
			entry->type = re->type;
			entry->instance = re->instance;
			entry->vrf_id = re->vrf_id;
			entry->tracker = tracker;
			tracker_prefix_map_add(prefix_map, entry);
			(*re_count)++;
#ifdef NHG_TRK_VERBOSE_LOG
			zlog_info("%s: added %pRN (type %s vrf %s(%u)) to tracker %u, re_count=%u",
				  __func__, rn, zebra_route_string(re->type),
				  vrf_id_to_name(re->vrf_id), re->vrf_id, tracker->nhg_tracker_id,
				  *re_count);
#endif
		}
	}
}

/*
 * Check if the RN is already tracked by a different tracker via the
 * prefix_map.  If so, evict the stale entry and collapse the old tracker.
 * Then add the RN to the given tracker's table.
 */
static void zebra_nhg_tracker_add_route(struct tracker_prefix_map_head *prefix_map,
					struct nhg_event_tracker *tracker,
					struct nhg_tracker_table *tt, struct route_node *rn,
					struct route_entry *re)
{
	zebra_nhg_tracker_rn_add(tt, &tt->re_count, prefix_map, tracker, rn, re);
}

/*
 * Evict a parked RE (same protocol/instance as the incoming RE) from a
 * tracker table (matched, unmatched, or deleted; see evict_from_* wrappers).
 * We must not unlock/deref the RN while another RE on the same RN is still
 * parked for this originating NHG (orig_nhe) on this tracker—each protocol
 * RE is one prefix_map row.  Example: RN1 has RE1 (proto1, NHG1) and RE2
 * (proto2, NHG1); evicting RE1 still leaves RE2 referencing the same RN.
 */
static void zebra_nhg_tracker_evict_re(struct nhg_event_tracker *tracker,
				       struct nhg_hash_entry *orig_nhe,
				       struct tracker_prefix_map_head *prefix_map,
				       struct nhg_tracker_table *tt, struct route_node *rn,
				       struct route_entry *re)
{
	struct tracker_prefix_map_entry lk;
	struct tracker_prefix_map_entry *pm_entry;
	struct route_table *vrf_table;
	struct route_node *trn;

	memset(&lk, 0, sizeof(lk));
	prefix_copy(&lk.p, &rn->p);
	lk.type = re->type;
	lk.instance = re->instance;
	lk.vrf_id = re->vrf_id;

	pm_entry = tracker_prefix_map_find(prefix_map, &lk);
	if (!pm_entry)
		return;

	if (pm_entry->tracker != tracker)
		return;

	vrf_table = tracker_vrf_table_get(tt, re->vrf_id);
	trn = route_node_lookup(vrf_table, &rn->p);
	/* Parking for this prefix is in only one of matched vs unmatched for this
	 * tracker VRF; skip so the sibling evict_from_* removes the map row and
	 * decrements the correct re_count.  route_node_lookup yields NULL unless
	 * this node has info (locked reference).
	 */
	if (!trn)
		return;

	UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);

	tracker_prefix_map_del(prefix_map, pm_entry);
	XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, pm_entry);
	if (tt->re_count > 0)
		tt->re_count--;

	{
		bool others_remain = false;
		struct route_node *parked_rn = trn->info;
		struct route_entry *check_re;

		RNODE_FOREACH_RE (parked_rn, check_re) {
			struct tracker_prefix_map_entry chk;

			memset(&chk, 0, sizeof(chk));
			prefix_copy(&chk.p, &rn->p);
			chk.type = check_re->type;
			chk.instance = check_re->instance;
			chk.vrf_id = check_re->vrf_id;

			if (tracker_prefix_map_find(prefix_map, &chk)) {
				others_remain = true;
				break;
			}
		}

		if (!others_remain) {
			route_unlock_node(trn->info);
			trn->info = NULL;
		}
		route_unlock_node(trn);
	}
}

static void zebra_nhg_tracker_evict_from_unmatched(struct nhg_event_tracker *tracker,
						   struct nhg_hash_entry *orig_nhe,
						   struct tracker_prefix_map_head *prefix_map,
						   struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_evict_re(tracker, orig_nhe, prefix_map, &tracker->unmatched_table, rn,
				   re);
}

static void zebra_nhg_tracker_evict_from_matched(struct nhg_event_tracker *tracker,
						 struct nhg_hash_entry *orig_nhe,
						 struct tracker_prefix_map_head *prefix_map,
						 struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_evict_re(tracker, orig_nhe, prefix_map, &tracker->matched_table, rn, re);
}

static void zebra_nhg_tracker_evict_from_deleted(struct nhg_event_tracker *tracker,
						 struct nhg_hash_entry *orig_nhe,
						 struct tracker_prefix_map_head *prefix_map,
						 struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_evict_re(tracker, orig_nhe, prefix_map, &tracker->deleted_table, rn, re);
}

/*
 * No tracker matched the incoming RE's NHG.  Park the RE in the newest
 * tracker's unmatched table.  Returns the tracker used, or NULL.
 */
static struct nhg_event_tracker *
zebra_nhg_tracker_park_unmatched(struct nhg_hash_entry *orig_nhe,
				 struct tracker_prefix_map_head *prefix_map, struct route_node *rn,
				 struct route_entry *re)
{
	struct nhg_event_tracker *tracker;

	tracker = nhg_event_tracker_list_first(&orig_nhe->tracker_list);
	while (tracker && tracker->flushing)
		tracker = nhg_event_tracker_list_next(&orig_nhe->tracker_list, tracker);
	if (!tracker)
		return NULL;

	zebra_nhg_tracker_add_route(prefix_map, tracker, &tracker->unmatched_table, rn, re);

#ifdef NHG_TRK_VERBOSE_LOG
	zlog_info("%s: %pRN (type %s) unmatched, parking in tracker %u for originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
		  __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
		  orig_nhe->id, tracker->matched_table.re_count, tracker->unmatched_table.re_count,
		  tracker->orig_re_count);
#endif

	return tracker;
}

static struct nhg_event_tracker *zebra_nhg_tracker_park_deleted(
	struct nhg_hash_entry *orig_nhe, struct tracker_prefix_map_head *prefix_map,
	struct nhg_event_tracker *tracker, struct route_node *rn, struct route_entry *re)
{
	if (!tracker) {
		tracker = nhg_event_tracker_list_first(&orig_nhe->tracker_list);
		while (tracker && tracker->flushing)
			tracker = nhg_event_tracker_list_next(&orig_nhe->tracker_list, tracker);
		if (!tracker)
			return NULL;
	} else if (tracker->flushing) {
		return NULL;
	}

	zebra_nhg_tracker_add_route(prefix_map, tracker, &tracker->deleted_table, rn, re);

#ifdef NHG_TRK_VERBOSE_LOG
	zlog_info("%s: %pRN (type %s) deleted parked in tracker %u for originating NHG %u (deleted=%u matched=%u unmatched=%u orig_re=%u)",
		  __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
		  orig_nhe->id, tracker->deleted_table.re_count, tracker->matched_table.re_count,
		  tracker->unmatched_table.re_count, tracker->orig_re_count);
#endif

	return tracker;
}

static void zebra_nhg_tracker_park_matched(struct nhg_hash_entry *orig_nhe,
					   struct tracker_prefix_map_head *prefix_map,
					   struct nhg_event_tracker *tracker,
					   struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_add_route(prefix_map, tracker, &tracker->matched_table, rn, re);

#ifdef NHG_TRK_VERBOSE_LOG
	zlog_info("%s: %pRN (type %s) matched tracker %u from originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
		  __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
		  orig_nhe->id, tracker->matched_table.re_count, tracker->unmatched_table.re_count,
		  tracker->orig_re_count);
#endif
}


/*
 * Return true if at least one non-flushing (active) tracker is attached
 * to nhe.  A flushing tracker no longer accepts new REs for parking.
 */
bool zebra_nhg_tracker_has_active(struct nhg_hash_entry *nhe)
{
	struct nhg_event_tracker *head;

	if (!nhe)
		return false;

	head = nhg_event_tracker_list_first(&nhe->tracker_list);
	return (head && !head->flushing);
}

/*
 * Return true if a flushing tracker is attached to nhe.
 */
bool zebra_nhg_tracker_has_flushing(struct nhg_hash_entry *nhe)
{
	struct nhg_event_tracker *t;

	if (!nhe)
		return false;

	frr_each (nhg_event_tracker_list, &nhe->tracker_list, t)
		if (t->flushing)
			return true;
	return false;
}

/*
 * Return true if the prefix is parked in a tracker using tracker_prefix_map
 * (rn->p, re->type, re->instance, re->vrf_id)
 */
bool zebra_nhg_tracker_prefix_in_pm(struct nhg_hash_entry *nhe,
				    const struct route_node *rn,
				    const struct route_entry *re)
{
	struct tracker_prefix_map_entry pm_key;
	struct tracker_prefix_map_entry *pm_entry;

	if (!nhe || !rn || !re)
		return false;

	memset(&pm_key, 0, sizeof(pm_key));
	prefix_copy(&pm_key.p, &rn->p);
	pm_key.type = re->type;
	pm_key.instance = re->instance;
	pm_key.vrf_id = re->vrf_id;

	pm_entry = tracker_prefix_map_find(&nhe->tracker_prefix_map, &pm_key);
	return (pm_entry != NULL);
}

/*
 * Park an RE in the appropriate tracker instead of queuing it
 * for best-path selection.
 * orig_nhe	: the originating NHE, carries the trackers and prefix_map
 * re		: the incoming RE

 * RE movement within the single active tracker (the only one accepting new
 * REs at this time):
 * +-----------------------+----------------------------------------------+
 * | Transition            | Action                                       |
 * +-----------------------+----------------------------------------------+
 * | matched -> matched    | already there: evict + re-add (idempotent)   |
 * | matched -> unmatched  | evict from matched, store in unmatched       |
 * | unmatched -> matched  | evict from unmatched, store in matched       |
 * | unmatched -> unmatched| already there: evict + re-add (idempotent)   |
 * +-----------------------+----------------------------------------------+
 *
 * If the prefix was previously parked in the older flushing tracker, the
 * caller (zebra_nhg_tracker_park_re) evicts from the flushing tracker's
 * tables before adding to the active tracker's table.  prefix_map ownership
 * follows the new tracker after the add.
 */
struct nhg_event_tracker *zebra_nhg_tracker_park_re(struct route_node *rn, struct route_entry *re,
						    struct nhg_hash_entry *orig_nhe)
{
	struct nhg_event_tracker *active;
	struct tracker_prefix_map_head *prefix_map = &orig_nhe->tracker_prefix_map;
	struct tracker_prefix_map_entry pm_key;
	struct tracker_prefix_map_entry *pm_re;
	struct nhg_event_tracker *tracker = NULL;

	/* Active tracker is at the head (skip the flushing one if it's the head). */
	active = nhg_event_tracker_list_first(&orig_nhe->tracker_list);
	while (active && active->flushing)
		active = nhg_event_tracker_list_next(&orig_nhe->tracker_list, active);
	if (!active)
		return NULL;

	memset(&pm_key, 0, sizeof(pm_key));
	prefix_copy(&pm_key.p, &rn->p);
	pm_key.type = re->type;
	pm_key.instance = re->instance;
	pm_key.vrf_id = re->vrf_id;
	pm_re = tracker_prefix_map_find(prefix_map, &pm_key);

	/*
	 * If this prefix is already parked somewhere (active OR flushing),
	 * evict it before parking in the active tracker's target table.
	 * The prefix_map row tells us exactly which tracker owns it; we
	 * try all three tables to find where it sits.
	 */
	if (pm_re) {
		struct nhg_event_tracker *evict_from = pm_re->tracker;

		zebra_nhg_tracker_evict_from_unmatched(evict_from, orig_nhe, prefix_map, rn, re);
		zebra_nhg_tracker_evict_from_matched(evict_from, orig_nhe, prefix_map, rn, re);
		zebra_nhg_tracker_evict_from_deleted(evict_from, orig_nhe, prefix_map, rn, re);
	}

	/*
	 * Park in the active tracker's table based on RE state and snapshot match:
	 *   REMOVED          -> deleted table
	 *   matches snapshot -> matched table
	 *   otherwise        -> unmatched table
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
		tracker = zebra_nhg_tracker_park_deleted(orig_nhe, prefix_map, active, rn, re);
	else if (zebra_nhg_tracker_nhgs_equal(re->nhe, active->nhg_tracker_snapshot,
					      active->event != NHG_TRACKER_EVENT_ECMP_CHANGE)) {
		zebra_nhg_tracker_park_matched(orig_nhe, prefix_map, active, rn, re);
		tracker = active;
	} else
		tracker = zebra_nhg_tracker_park_unmatched(orig_nhe, prefix_map, rn, re);

	/* Only mark the RE with TRACKER when it actually got parked. */
	if (tracker)
		SET_FLAG(re->status, ROUTE_ENTRY_TRACKER);

	return tracker;
}

static void tracker_flush_batch_start_phase2(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *tracker);
static void tracker_track_loser_nhe(struct nhg_event_tracker *tracker,
				    struct nhg_hash_entry *loser_nhe);
static void tracker_clear_loser_parent_ids(struct nhg_event_tracker *tracker);
static void zebra_nhg_tracker_flush(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe);
static uint32_t tracker_flush_fire_silent_routes_phase2(struct nhg_hash_entry *parent_nhe,
							struct nhg_event_tracker *tracker);

/* Update global tracker statistics and log the flush event. */
static void tracker_flush_update_counters(struct nhg_event_tracker *tracker,
					  struct nhg_hash_entry *nhe)
{
	struct tracker_flush_event *evt;

	zrouter.tracker_counters.tracker_full++;
	if (tracker->matched_table.re_count == tracker->orig_re_count)
		zrouter.tracker_counters.tracker_full_matched++;
	else if (tracker->unmatched_table.re_count == tracker->orig_re_count)
		zrouter.tracker_counters.tracker_full_unmatched++;
	else {
		zrouter.tracker_counters.tracker_full_combined++;
		if (tracker->matched_table.re_count > tracker->unmatched_table.re_count)
			zrouter.tracker_counters.tracker_full_combined_matched_gt++;
		else if (tracker->unmatched_table.re_count > tracker->matched_table.re_count)
			zrouter.tracker_counters.tracker_full_combined_unmatched_gt++;
	}

	evt = &zrouter.tracker_counters
		       .log[zrouter.tracker_counters.log_idx % TRACKER_FLUSH_LOG_SIZE];
	evt->nhg_id = nhe->id;
	evt->tracker_id = tracker->nhg_tracker_id;
	evt->matched = tracker->matched_table.re_count;
	evt->unmatched = tracker->unmatched_table.re_count;
	evt->deleted = tracker->deleted_table.re_count;
	evt->orig_re_count = tracker->orig_re_count;
	zrouter.tracker_counters.log_idx++;
}

/*
 * Count the number of REs that are currently attached to parent_nhe but
 * were NOT parked in any tracker table during this convergence window.
 * These are the "silent" REs: the protocol did not re-advertise them, so
 * they still point at parent_nhe by their re->nhe.
 */
static uint32_t tracker_count_silent_res(struct nhg_hash_entry *parent_nhe)
{
	struct route_entry *re;
	uint32_t silent = 0;

	frr_each (nhe_re_tree, &parent_nhe->re_head, re) {
		if (re->nhe != parent_nhe)
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
			continue;
		/*
		 * Skip REs that are either parked in a tracker table
		 * (TRACKER) or already on their way out (REMOVED).  They
		 * do not represent active users of parent_nhe's content
		 * and must not bias winner selection toward "old content".
		 */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER))
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;
		silent++;
	}
	return silent;
}

/*
 * Select the winner group and populate tracker->winner_flags /
 * winner_nhg_id.  Winner is chosen by count among silent, matched, and
 * unmatched-per-incoming-NHG candidates.
 *
 * The tracker's snapshot was taken from parent_nhe during link event.
 * So snapshot.content == parent_nhe.content, matched REs and
 * silent REs share the same resolved content, so their counts are
 * combined for winner selection.  In the ECMP-change case the snapshot
 * is from an incoming RE and the two stay separate.
 *
 * Tie-break order (highest first):
 *   1. SILENT (+ MATCHED in link-event)  — old content wins, no rework.
 *   2. MATCHED                            — matched alone wins.
 *   3. UNMATCHED (smallest incoming id)   — lowest id on count ties.
 */
static void tracker_flush_build_groups(struct nhg_event_tracker *tracker,
				       struct nhg_hash_entry *parent_nhe)
{
	struct list *groups = tracker->flush_nhg_groups;
	struct tracker_flush_nhg_group *g, *unmatched_winner = NULL;
	struct listnode *node;
	uint32_t matched_count = tracker->matched_table.re_count;
	uint32_t silent_count;
	uint32_t unmatched_max = 0;
	struct tracker_vrf_table *vt;
	bool is_snapshot_eq_parent_nhe;
	uint32_t silent_plus_matched_count;

	/* Count unmatched groups by incoming NHG ID. */
	for (vt = tracker->unmatched_table.vrf_tables; vt; vt = vt->next) {
		struct route_node *trn;

		for (trn = route_top(vt->table); trn; trn = route_next(trn)) {
			struct route_node *rn;
			struct route_entry *re;

			if (!trn->info)
				continue;
			rn = trn->info;

			RNODE_FOREACH_RE (rn, re) {
				if (!CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER))
					continue;
				if (!CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
					continue;
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;
				if (!re->nhe)
					continue;

				g = NULL;
				for (ALL_LIST_ELEMENTS_RO(groups, node, g)) {
					if (g->incoming_nhg_id == re->nhe->id)
						break;
					g = NULL;
				}
				if (!g) {
					g = XCALLOC(MTYPE_NHG_TRACKER_FLUSH_GROUP, sizeof(*g));
					g->incoming_nhg_id = re->nhe->id;
					g->incoming_nhe = re->nhe;
					listnode_add(groups, g);
				}
				g->re_count++;
			}
		}
	}

	/* Count silent REs that are still on parent_nhe. */
	silent_count = tracker_count_silent_res(parent_nhe);

	/*
	 * Check if the tracker's snapshot was taken from parent_nhe itself.
	 * When true, matched REs would resolve to the same content as silent
	 * REs and can be counted together as winners that "keep" parent_nhe;
	 * when false, matched and silent stay separate buckets.
	 */
	is_snapshot_eq_parent_nhe = (tracker->event == NHG_TRACKER_EVENT_INTF_DOWN ||
				     tracker->event == NHG_TRACKER_EVENT_INTF_UP);

	silent_plus_matched_count = silent_count + (is_snapshot_eq_parent_nhe ? matched_count : 0);

	/* Find the largest unmatched group (pick lowest id on ties). */
	for (ALL_LIST_ELEMENTS_RO(groups, node, g)) {
		if (g->re_count > unmatched_max ||
		    (g->re_count == unmatched_max && unmatched_winner &&
		     g->incoming_nhg_id < unmatched_winner->incoming_nhg_id)) {
			unmatched_max = g->re_count;
			unmatched_winner = g;
		}
	}

	tracker->winner_flags = 0;
	tracker->winner_nhg_id = 0;

	/* Silent (always) + matched (when snapshot==parent) wins. */
	if (silent_plus_matched_count > 0 && silent_plus_matched_count >= matched_count &&
	    silent_plus_matched_count >= unmatched_max) {
		if (silent_count > 0)
			tracker->winner_flags |= TRACKER_WIN_SILENT;
		if (is_snapshot_eq_parent_nhe && matched_count > 0)
			tracker->winner_flags |= TRACKER_WIN_MATCHED;
		/* Matched wins alone */
	} else if (matched_count > 0 && matched_count >= unmatched_max) {
		tracker->winner_flags = TRACKER_WIN_MATCHED;
		tracker->winner_nhg_id = tracker->nhg_tracker_snapshot
						 ? tracker->nhg_tracker_snapshot->id
						 : 0;
		/* Unmatched wins: pick the largest incoming-NHG group (lowest id on ties). */
	} else if (unmatched_winner) {
		tracker->winner_flags = TRACKER_WIN_UNMATCHED;
		tracker->winner_nhg_id = unmatched_winner->incoming_nhg_id;
		unmatched_winner->is_winner = true;
	}
	/* else: winner_flags stays 0 (no winner — deletions-only flush). */

	zlog_info("%s: NHG %u tracker %u winner flags=0x%x nhg=%u (matched=%u silent=%u unmatched_max=%u silent_plus_matched=%u snapshot_eq_parent=%d)",
		  __func__, parent_nhe->id, tracker->nhg_tracker_id, tracker->winner_flags,
		  tracker->winner_nhg_id, matched_count, silent_count, unmatched_max,
		  silent_plus_matched_count, is_snapshot_eq_parent_nhe ? 1 : 0);
}

static void tracker_flush_nhg_group_free(void *data)
{
	XFREE(MTYPE_NHG_TRACKER_FLUSH_GROUP, data);
}

static void tracker_flush_free_groups(struct nhg_event_tracker *tracker)
{
	if (tracker->flush_nhg_groups)
		list_delete_all_node(tracker->flush_nhg_groups);
}


/*
 * Find the flushing tracker on an NHE, or NULL if none.
 */
static struct nhg_event_tracker *tracker_find_flushing(struct nhg_hash_entry *nhe)
{
	struct nhg_event_tracker *t;

	frr_each (nhg_event_tracker_list, &nhe->tracker_list, t) {
		if (t->flushing)
			return t;
	}
	return NULL;
}

/*
 * Walk a tracker table, clear TRACKER on matching REs, optionally repoint
 * them to the parent NHG, and queue route_nodes for rib_process.
 *
 * filter_nhg_id:  non-zero -> only process REs whose incoming NHG matches.
 * exclude_nhg_id: non-zero -> skip REs whose incoming NHG matches.
 * update_nhe:     true -> repoint RE to parent NHG (winners reuse old ID).
 * track_pending:  true -> mark RE with NHG_TRACKER_FLUSH_BATCH and increment
 *                 routes_pending for phase 1 dplane ack tracking.
 *                 false -> just queue (phase 2 finishes synchronously).
 */
static size_t tracker_flush_batch_process_table(struct nhg_hash_entry *parent_nhe,
						struct nhg_event_tracker *tracker,
						struct nhg_tracker_table *table,
						uint32_t filter_nhg_id, uint32_t exclude_nhg_id,
						bool update_nhe, bool track_pending)
{
	struct tracker_vrf_table *vt;
	const bool is_deleted_table = table ? (table == &tracker->deleted_table) : false;
	size_t released = 0;

	if (!table)
		return 0;

	for (vt = table->vrf_tables; vt; vt = vt->next) {
		struct route_node *trn;

		for (trn = route_top(vt->table); trn; trn = route_next(trn)) {
			struct route_node *rn;
			struct route_entry *re;
			bool flush_rn = false;

			if (!trn->info)
				continue;
			rn = trn->info;

			/*
			 * First pass: release incoming (CHANGED) REs that
			 * pass the filter/exclude criteria.  Old installed
			 * REs (!CHANGED) are skipped here — they are handled
			 * in the second pass below.
			 */
			RNODE_FOREACH_RE (rn, re) {
				if (!CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER))
					continue;
				if (!CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
					/*
					 * REs parked in deleted_table (from rib_delnode) have
					 * REMOVED + TRACKER but never CHANGED.
					 * Let them fall through, so that the TRACKER flag is
					 * cleared and rib_process can unlink them.
					 */
					if (!(is_deleted_table &&
					      CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)))
						continue;
				}

				if (filter_nhg_id && re->nhe && re->nhe->id != filter_nhg_id)
					continue;
				if (exclude_nhg_id && re->nhe && re->nhe->id == exclude_nhg_id)
					continue;

				UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);

				if (update_nhe && !CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					route_entry_update_nhe(re, parent_nhe);

				if (track_pending) {
					/*
					 * Record the parent NHG ID on the RE's
					 * NHE so the dplane ack can find the
					 * flushing tracker even if re->nhe
					 * changes during rib_process resolution.
					 *
					 * Also remember this loser NHE on the
					 * tracker so we can clear its
					 * parent_nhg_id once when phase 1
					 * finishes.  The previous "clear on
					 * first ack" approach lost subsequent
					 * acks when multiple REs shared an
					 * incoming NHG.
					 */
					SET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH);
					if (re->nhe) {
						re->nhe->tracker_flush_batch_parent_nhg_id =
							parent_nhe->id;
						tracker_track_loser_nhe(tracker, re->nhe);
					}
					tracker->routes_pending++;
				} else if (!CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
					/*
					 * Phase-2 winner release: tag the RE so nexthop_active_update
					 * can lookup parent_nhe and schedule NHG dup consolidation.
					 */
					SET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
				}
				flush_rn = true;
				released++;
			}

			/*
			 * Second pass: clear TRACKER on old installed REs
			 * only when at least one new RE was released above.
			 *
			 * Old REs (REMOVED + TRACKER + !CHANGED) are kept
			 * alive by rib_process while TRACKER is set.
			 * Clearing it lets rib_process remove the old RE
			 * alongside installing the new one.
			 *
			 * When no new RE passed the filters (all excluded),
			 * old REs must keep TRACKER — otherwise rib_process
			 * finds no installable candidate, uninstalls the
			 * prefix from FIB, and frees the parent NHG's
			 * refcount prematurely.
			 */
			if (flush_rn) {
				RNODE_FOREACH_RE (rn, re) {
					if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER) &&
					    !CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
						UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);
				}

				/*
				 * Diagnostic: dump every RE on this rn just
				 * before it goes to the work queue, so we can
				 * correlate which REs flushed where and what
				 * their NHG state looked like at queue-add
				 * time.  Includes both the drained RE(s) of
				 * this tracker and any siblings still on rn
				 * (different protocol, REMOVED, etc.).
				 */
#ifdef NHG_TRK_VERBOSE_LOG
				RNODE_FOREACH_RE (rn, re) {
					zlog_info("%s: queueing re %p prefix %pRN type %s status 0x%x re->nhe NHG %u (flags 0x%x refcnt %d nhe_parent_id=%u) parent NHG %u tracker %u table %s%s",
						  __func__, re, rn, zebra_route_string(re->type),
						  re->status, re->nhe ? re->nhe->id : 0,
						  re->nhe ? re->nhe->flags : 0,
						  re->nhe ? re->nhe->refcnt : 0,
						  re->nhe ? re->nhe->tracker_flush_batch_parent_nhg_id
							  : 0,
						  parent_nhe->id, tracker->nhg_tracker_id,
						  is_deleted_table
							  ? "deleted"
							  : (table == &tracker->matched_table
								     ? "matched"
								     : "unmatched"),
						  track_pending ? " (phase1 drain)"
								: " (phase2 release)");
				}
#endif
				rib_queue_add(rn);
			}
		}
	}

	return released;
}

/*
 * Walk the per-tracker list of loser NHEs whose
 * tracker_flush_batch_parent_nhg_id was set to this tracker's parent
 * during phase-1 drain.  Clear the field on each (defensively only
 * when it still points at this tracker's parent so we don't stomp on
 * a sibling tracker that may have rewritten it).  Drop the refcount
 * we held on each loser NHE, then empty the list.
 */
static void tracker_clear_loser_parent_ids(struct nhg_event_tracker *tracker)
{
	struct listnode *ln, *nnode;
	struct nhg_hash_entry *loser;

	if (!tracker->flush_loser_nhes || !tracker->parent_nhe)
		return;

	for (ALL_LIST_ELEMENTS(tracker->flush_loser_nhes, ln, nnode, loser)) {
		if (loser->tracker_flush_batch_parent_nhg_id == tracker->parent_nhe->id)
			loser->tracker_flush_batch_parent_nhg_id = 0;
		zebra_nhg_decrement_ref(loser);
	}

	list_delete_all_node(tracker->flush_loser_nhes);
}

/*
 * Add a loser NHE to the tracker's loser-NHE list (if not already
 * present) and bump its refcount so it stays alive until the
 * tracker's bulk clear.  Caller must hold parent_nhe alive separately.
 */
static void tracker_track_loser_nhe(struct nhg_event_tracker *tracker,
				    struct nhg_hash_entry *loser_nhe)
{
	struct listnode *ln;
	struct nhg_hash_entry *seen;

	if (!tracker->flush_loser_nhes || !loser_nhe)
		return;

	for (ALL_LIST_ELEMENTS_RO(tracker->flush_loser_nhes, ln, seen)) {
		if (seen == loser_nhe)
			return;
	}

	zebra_nhg_increment_ref(loser_nhe);
	listnode_add(tracker->flush_loser_nhes, loser_nhe);
}

/*
 * Complete the flush batch: free groups, free the flushing tracker,
 * and hand off to any tracker on the same NHE that was waiting for
 * the flushing slot to free up.
 */
static void tracker_flush_batch_finish(struct nhg_hash_entry *nhe,
				       struct nhg_event_tracker *tracker)
{
	struct nhg_event_tracker *t, *waiting = NULL;
	struct nhg_hash_entry *waiting_parent = NULL;

	event_cancel(&tracker->timer);
	tracker_clear_loser_parent_ids(tracker);
	tracker_flush_free_groups(tracker);

	/*
	 * Capture the handoff candidate BEFORE freeing this tracker.
	 * Walk this NHE's tracker list and pick a tracker in WAITING
	 * state; if multiple exist (shouldn't in practice), the last
	 * one we see in head-first iteration is the oldest in
	 * insertion order, which we hand off first (FIFO).
	 *
	 * Capture parent_nhe through the waiting tracker rather than
	 * via `nhe`, because zebra_nhg_tracker_free below may free
	 * `nhe` if its refcount drops to zero with this tracker's
	 * removal — but the waiting tracker still holds its own ref
	 * on the parent NHE, keeping it alive.
	 */
	frr_each (nhg_event_tracker_list, &nhe->tracker_list, t) {
		if (t == tracker)
			continue;
		if (t->flush_state == TRACKER_FLUSH_WAITING) {
			waiting = t;
			waiting_parent = t->parent_nhe;
		}
	}

	zebra_nhg_tracker_free(nhe, tracker);

	/*
	 * If nhe carries DUPLICATE, the consolidate handler may have been
	 * unable to make progress while this tracker was active.  Fire a
	 * fresh consolidate attempt now that the tracker has finished.
	 * This handles the "no winners released" / "tracker freed without
	 * consuming pending_winners" cases.
	 * The pending_winners path in nexthop_active_update covers the
	 * common case (winners attach -> counter -> 0 -> schedule).
	 */
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE))
		zebra_nhg_schedule_consolidate(nhe);

	if (waiting && waiting_parent) {
		zlog_info("%s: handoff to waiting tracker %u on NHG %u", __func__,
			  waiting->nhg_tracker_id, waiting_parent->id);
		zebra_nhg_tracker_flush(waiting, waiting_parent);
	}
}

/*
 * Phase 2: release winner REs and arm REUSE+REINSTALL on parent_nhe.
 *
 * parent_nhe stays OUT of zrouter.nhgs throughout phase 2.  It gets
 * re-inserted during nexthop_active_update's reuse path when a
 * winner RE arrives and triggers zebra_nhg_rework_in_place().
 *
 * The first winner RE to enter the reuse path consumes them, subsequent REs
 * fall through the normal NHG resolution path and just get the reworked NHG.
 * If no winner RE is released, silent REs are fired through rib_process
 * so that the REUSE+REINSTALL flags are consumed and the NHG is re-inserted.
 */
static void tracker_flush_batch_start_phase2(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *tracker)
{
	size_t consumers = 0;

	tracker->flush_state = TRACKER_FLUSH_PHASE2;

	zlog_info("%s: NHG %u tracker %u phase 2: flags=0x%x winner_nhg=%u", __func__, nhe->id,
		  tracker->nhg_tracker_id, tracker->winner_flags, tracker->winner_nhg_id);

	/*
	 * Release the winner REs.
	 */
	if (tracker_win_includes_matched(tracker)) {
		consumers += tracker_flush_batch_process_table(nhe, tracker,
							       &tracker->matched_table, 0, 0,
							       false, false);
	}

	if (tracker_win_is_unmatched(tracker)) {
		consumers +=
			tracker_flush_batch_process_table(nhe, tracker, &tracker->unmatched_table,
							  tracker->winner_nhg_id, 0, false, false);
	}

	/*
	 * No winner RE to consume REUSE/REINSTALL - fire silent REs so that
	 * the REUSE+REINSTALL flags are consumed and the NHG is re-inserted.
	 */
	if (consumers == 0) {
		zlog_info("%s: NHG %u tracker %u no winners released, firing silent REs to consume REUSE/REINSTALL",
			  __func__, nhe->id, tracker->nhg_tracker_id);
		consumers += tracker_flush_fire_silent_routes_phase2(nhe, tracker);
	}

	/*
	 * Arm REUSE+REINSTALL only when there is a consumer to actually
	 * consume them (winner RE released or silent RE fired).  Without a
	 * consumer the flags would leak to the next tracker's phase 1, where
	 * loser REs may inappropriately enter the reuse path.
	 *
	 * nexthop_active_update's reuse path decides per-RE whether to rework,
	 * fast-path skip, mark_duplicate, or shape-skip based on the fully
	 * resolved incoming content.
	 */
	if (consumers > 0) {
		if (nhe->tracker_pending_winners > 0)
			zlog_info("%s: NHG %u stale tracker_pending_winners=%u, resetting before this flush",
				  __func__, nhe->id, nhe->tracker_pending_winners);
		/* Assign winner counter for tracking */
		nhe->tracker_pending_winners = consumers;

		zebra_nhg_mark_reuse(nhe);
		SET_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL);
		zlog_info("%s: NHG %u tracker %u armed REUSE/REINSTALL (consumers=%zu, pending_winners=%u)",
			  __func__, nhe->id, tracker->nhg_tracker_id, consumers,
			  nhe->tracker_pending_winners);
	} else {
		zlog_info("%s: NHG %u tracker %u no consumer, NOT arming REUSE/REINSTALL",
			  __func__, nhe->id, tracker->nhg_tracker_id);
		/*
		 * No winner RE to re-insert parent_nhe. Rehash it
		 * explicitly so future content lookups can dedup.
		 */
		zebra_nhg_rework_content_rehash(nhe);
	}

	zlog_info("%s: phase 2 done for NHG %u tracker %u (consumers=%zu), finishing tracker",
		  __func__, nhe->id, tracker->nhg_tracker_id, consumers);
	tracker_flush_batch_finish(nhe, tracker);
}

/*
 * Called when a phase 1 (loser) RE completes — via dplane ack,
 * rib_unlink, or rib_process without dplane send.
 *
 * Decrements routes_pending regardless of which incoming NHG the RE
 * belongs to — the counter tracks total outstanding loser REs across
 * all non-winner groups.  When pending reaches 0, phase 1 is complete
 * and phase 2 (winner processing) begins.
 */
void tracker_flush_batch_route_dplane_ack(struct route_entry *re)
{
	struct nhg_hash_entry *nhe;
	struct nhg_event_tracker *tracker = NULL;

	if (!CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH))
		return;

	UNSET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH);

	if (!re->nhe)
		return;

	/*
	 * tracker_flush_batch_parent_nhg_id is the authoritative bridge from
	 * a drained loser RE back to its flushing tracker -- stamped on
	 * re->nhe at phase-1 drain time, bulk-cleared in
	 * tracker_clear_loser_parent_ids() when the tracker finishes.
	 *
	 * Direct lookup via tracker_find_flushing(re->nhe) is intentionally
	 * not used as a fallback: re->nhe could be the parent of an UNRELATED
	 * flushing tracker, and decrementing that tracker's routes_pending
	 * would corrupt its phase-1 accounting.
	 */
	nhe = re->nhe;
	if (nhe->tracker_flush_batch_parent_nhg_id) {
		struct nhg_hash_entry *parent;

		parent = zebra_nhg_lookup_id(nhe->tracker_flush_batch_parent_nhg_id);
		if (parent)
			tracker = tracker_find_flushing(parent);
	}

	if (!tracker) {
		zlog_warn("%s: re %p prefix %pRN type %s status 0x%x re->nhe NHG %u parent_nhg_id=%u -- no flushing tracker found, ack dropped",
			  __func__, re, re->rn, zebra_route_string(re->type), re->status, nhe->id,
			  nhe->tracker_flush_batch_parent_nhg_id);
		return;
	}

	if (tracker->routes_pending == 0)
		return;

	tracker->routes_pending--;

	if (tracker->routes_pending > 0)
		return;

	/* All phase 1 loser REs processed — start phase 2 */
	nhe = tracker->parent_nhe;
	if (!nhe) {
		tracker_flush_free_groups(tracker);
		return;
	}

	zlog_info("%s: phase 1 complete for NHG %u tracker %u, starting phase 2", __func__,
		  nhe->id, tracker->nhg_tracker_id);
	tracker_flush_batch_start_phase2(nhe, tracker);
}

/*
 * Drain a phase-2 winner RE that's being withdrawn before its
 * nexthop_active_update runs, so parent_nhe->tracker_pending_winners
 * stays accurate.  Called from rib_delnode BEFORE SET REMOVED while
 * the previously-installed peer RE is still on the RN; the peer's
 * nhe is parent_nhe.  May also schedule consolidation if needed.
 */
void tracker_winner_pre_remove(struct route_node *rn, struct route_entry *re)
{
	struct route_entry *old_re;
	struct nhg_hash_entry *parent_nhe = NULL;

	if (!re || !CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER))
		return;

	/* Find the installed RE on the RN for the same protocol/instance. */
	RNODE_FOREACH_RE (rn, old_re) {
		if (old_re == re)
			continue;
		if (old_re->type != re->type)
			continue;
		if (old_re->instance != re->instance)
			continue;
		if (CHECK_FLAG(old_re->status, ROUTE_ENTRY_INSTALLED) && old_re->nhe) {
			parent_nhe = old_re->nhe;
			break;
		}
	}

	UNSET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);

	if (!parent_nhe) {
#ifdef NHG_TRK_VERBOSE_LOG
		zlog_info("%s: re %p prefix %pRN type %s vrf %u status 0x%x re->nhe NHG %u: WINNER set but no installed peer on rn",
			  __func__, re, rn, re->type ? zebra_route_string(re->type) : "?",
			  re->vrf_id, re->status, re->nhe ? re->nhe->id : 0);
#endif
		return;
	}

	if (parent_nhe->tracker_pending_winners > 0)
		parent_nhe->tracker_pending_winners--;

	if (parent_nhe->tracker_pending_winners == 0 &&
	    CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_DUPLICATE)) {
		zlog_info("%s: NHG %u: all winners drained (last via pre-remove of re %p prefix %pRN), scheduling consolidation",
			  __func__, parent_nhe->id, re, rn);
		zebra_nhg_schedule_consolidate(parent_nhe);
	}
}

/*
 * Enqueue silent REs for phase 1 processing.
 *
 * Silent REs are route entries that point at parent_nhe but are NOT
 * parked in any tracker table (!CHANGED): the protocol never
 * re-advertised them during this convergence window.
 *
 * parent_nhe is already out of the content hash (released at phase 1 start)
 * so rib_process -> nexthop_active_update -> zebra_nhg_rib_find_nhe will
 * allocate a fresh NHG (or find another content-matching one) for them
 * naturally — and the first silent RE's allocation gets picked up via
 * content-hash lookup by the subsequent silent REs, so they all end up
 * on the same NHG.
 */
static void tracker_flush_enqueue_silent_res(struct nhg_hash_entry *parent_nhe,
					     struct nhg_event_tracker *tracker)
{
	struct route_entry *re;
	uint32_t queued = 0;

	frr_each (nhe_re_tree, &parent_nhe->re_head, re) {
		if (re->nhe != parent_nhe)
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
			continue; /* tracked-latched, drained via tracker tables */
		/*
		 * Skip REs already parked in a tracker table (TRACKER) or
		 * REMOVED — they are handled by the loser-drain path or
		 * are on their way out, and must not be re-queued here.
		 */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER))
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
		SET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH);
		/* Record parent id so the dplane-ack callback can find the
		 * flushing tracker even after re->nhe migrates to a fresh
		 * NHG during nexthop_active_update.  Also track the loser
		 * NHE so we can bulk-clear parent_nhg_id at flush finish.
		 */
		re->nhe->tracker_flush_batch_parent_nhg_id = parent_nhe->id;
		tracker_track_loser_nhe(tracker, re->nhe);
		tracker->routes_pending++;
		queued++;
		rib_queue_add(re->rn);
	}

	zlog_info("%s: NHG %u tracker %u queued %u silent RE(s) for phase 1", __func__,
		  parent_nhe->id, tracker->nhg_tracker_id, queued);
}

/*
 * Phase 2: fire silent REs through rib_process so rib_install_kernel(parent_nhe)
 * consumes any externally-set NEXTHOP_GROUP_REINSTALL.
 */
static uint32_t tracker_flush_fire_silent_routes_phase2(struct nhg_hash_entry *parent_nhe,
							struct nhg_event_tracker *tracker)
{
	struct route_entry *re;
	uint32_t fired = 0;

	frr_each (nhe_re_tree, &parent_nhe->re_head, re) {
		if (re->nhe != parent_nhe)
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER))
			continue;
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;
		/*
		 * Only selected silent REs need rib_process + kernel install;
		 * non-selected silent REs are handled when their CHANGED peer
		 * RE on the same rn goes through rib_process.
		 */
		if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			continue;

		SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
		/* Silent fire is also a consumer; mark as winner. */
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER)) {
			SET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
			parent_nhe->tracker_pending_winners++;
		}
		rib_queue_add(re->rn);
		fired++;
	}

	zlog_info("%s: NHG %u tracker %u fired %u silent RE(s) in phase 2", __func__,
		  parent_nhe->id, tracker->nhg_tracker_id, fired);
	return fired;
}

/*
 * Start the two-phase flush batch.
 *
 * Phase 1 responsibilities:
 *   - Remove parent_nhe from the content hash (zrouter.nhgs) for the
 *     entire phase 1 duration.  This is what isolates loser REs from
 *     ever content-hash-finding parent_nhe during their rib_process runs,
 *     regardless of what their post-resolution content ends up being.
 *   - If silent REs are losers (winner content != parent_nhe content),
 *     enqueue them so they go through the normal rib_process path.
 *   - Drain tracked losers from matched / unmatched / deleted tables
 *     according to winner_flags.
 */
static void tracker_flush_batch_start_phase1(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *tracker)
{
	/*
	 * Release parent_nhe from the content hash.
	 */
	zebra_nhg_rework_content_release(nhe);

	/* Cancel creation timer */
	event_cancel(&tracker->timer);

	tracker->routes_pending = 0;
	tracker->flush_state = TRACKER_FLUSH_PHASE1;

	zlog_info("%s: NHG %u tracker %u winner flags=0x%x nhg=%u", __func__, nhe->id,
		  tracker->nhg_tracker_id, tracker->winner_flags, tracker->winner_nhg_id);

	/*
	 * Silent REs are losers when they are NOT in the winner set.
	 */
	if (!tracker_win_includes_silent(tracker))
		tracker_flush_enqueue_silent_res(nhe, tracker);

	/*
	 * Drain tracked losers:
	 * - unmatched_table drained excluding the winning group's id
	 * - deleted_table always drained regardless of winner.
	 */
	if (!tracker_win_includes_matched(tracker)) {
		tracker_flush_batch_process_table(nhe, tracker, &tracker->matched_table, 0, 0,
						  false, true);
	}

	tracker_flush_batch_process_table(nhe, tracker, &tracker->unmatched_table, 0,
					  tracker->winner_nhg_id, false, true);

	tracker_flush_batch_process_table(nhe, tracker, &tracker->deleted_table, 0, 0, false, true);

	/*
	 * If nothing was queued (no losers, no silent REs to migrate),
	 * go straight to phase 2 — no dplane acks to wait for.
	 */
	if (tracker->routes_pending == 0)
		tracker_flush_batch_start_phase2(nhe, tracker);
}

static void zebra_nhg_tracker_flush(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe)
{
	/*
	 * Single-flushing-tracker invariant: at most one tracker per NHE
	 * may be in PHASE1 or PHASE2 at any time.  If another tracker is
	 * already flushing on this NHE, defer this one to WAITING state
	 * and return.  The handoff in tracker_flush_batch_finish will
	 * re-invoke this function when the slot frees up.
	 *
	 * Defer BEFORE running tracker_flush_update_counters /
	 * tracker_flush_build_groups: the tracker may keep accumulating
	 * REs while waiting, so winner selection should always run
	 * against the latest table state at the moment phase 1 is
	 * actually entered.
	 */
	if (tracker_find_flushing(nhe)) {
		zlog_info("%s: NHG %u tracker %u deferred (state=WAITING) -- another tracker is already flushing",
			  __func__, nhe->id, tracker->nhg_tracker_id);
		tracker->flush_state = TRACKER_FLUSH_WAITING;
		/* No timer is needed in WAITING state — the tracker is
		 * woken up purely by the event-driven handoff in
		 * tracker_flush_batch_finish.  Cancel any creation timer
		 * to avoid duplicate wake-ups.
		 */
		event_cancel(&tracker->timer);
		return;
	}

	tracker_flush_update_counters(tracker, nhe);
	tracker_flush_build_groups(tracker, nhe);

	if (!tracker_win_has_winner(tracker) && listcount(tracker->flush_nhg_groups) == 0) {
		/*
		 * No matched/unmatched/silent winner, but deleted_table may
		 * still have REs parked (REMOVED+TRACKER) that need TRACKER
		 * cleared and queued for rib_process.
		 */
		tracker_flush_batch_process_table(nhe, tracker, &tracker->deleted_table, 0, 0,
						  false, false);
		zebra_nhg_tracker_free(nhe, tracker);
		return;
	}

	/*
	 * Mark as flushing.  The tracker stays in tracker_list so new
	 * trackers can see it (and skip it), but:
	 * - It must not be collapsed into another tracker.
	 * - No additional routes may be parked in it.
	 *
	 * Note: prefix_map entries owned by this flushing tracker are
	 * INTENTIONALLY left in place.  When a new rib_link arrives for
	 * a prefix that is still latched in the flushing tracker's
	 * tables, zebra_nhg_tracker_park_re relies on the prefix_map
	 * lookup to redirect eviction to this flushing tracker so the
	 * prefix's ownership transfers cleanly to the new active tracker.
	 * Without these entries, the prefix would end up parked in two
	 * trackers simultaneously and their phase-1/2 walks would race
	 * on the shared RIB route_node.
	 *
	 * The remaining prefix_map entries are released by
	 * zebra_nhg_tracker_free when the flush completes (or by
	 * evict_re calls during the flush window).
	 */
	tracker->flushing = true;

	tracker_flush_batch_start_phase1(nhe, tracker);
}

/*
 * Check if all expected REs have been parked; if so, flush.
 */
void zebra_nhg_tracker_flush_if_full(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe)
{
	if (!tracker)
		return;

	if ((tracker->matched_table.re_count + tracker->unmatched_table.re_count +
	     tracker->deleted_table.re_count) != tracker->orig_re_count)
		return;

	zlog_info("flush_if_full tracker %u NHG %u (matched=%u unmatched=%u deleted=%u orig_re=%u)",
		  tracker->nhg_tracker_id, nhe->id, tracker->matched_table.re_count,
		  tracker->unmatched_table.re_count, tracker->deleted_table.re_count,
		  tracker->orig_re_count);

	zebra_nhg_tracker_flush(tracker, nhe);
}

/* Timer callback - handle REs from matched/unmatched tables */
static void nhg_tracker_timer_expiry(struct event *event)
{
	struct nhg_event_tracker *tracker = EVENT_ARG(event);

	zrouter.tracker_counters.tracker_timer_expired++;

	struct nhg_hash_entry *nhe = tracker->parent_nhe;

	if (!nhe) {
		zlog_err("%s: tracker %u has NULL parent_nhe, freeing without flush", __func__,
			 tracker->nhg_tracker_id);
		return;
	}

	zlog_info("timer_expiry tracker %u NHG %u ifindex %u event %d (matched=%u unmatched=%u orig_re=%u)",
		  tracker->nhg_tracker_id, nhe->id, tracker->ifindex, tracker->event,
		  tracker->matched_table.re_count, tracker->unmatched_table.re_count,
		  tracker->orig_re_count);

	zebra_nhg_tracker_flush(tracker, nhe);
}

/*
 * Initialise the tracker list and hash embedded in an nhg_hash_entry.
 */
void zebra_nhg_tracker_init(struct nhg_hash_entry *nhe)
{
	nhg_event_tracker_list_init(&nhe->tracker_list);
	tracker_prefix_map_init(&nhe->tracker_prefix_map);
}

/*
 * Tear down all trackers for an NHE.
 */
void zebra_nhg_tracker_fini(struct nhg_hash_entry *nhe)
{
	struct nhg_event_tracker *t;

	while ((t = nhg_event_tracker_list_first(&nhe->tracker_list)) != NULL)
		zebra_nhg_tracker_free(nhe, t);

	{
		struct tracker_prefix_map_entry *entry;

		while ((entry = tracker_prefix_map_pop(&nhe->tracker_prefix_map)) != NULL)
			XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, entry);
	}
	tracker_prefix_map_fini(&nhe->tracker_prefix_map);
}

/*
 * Count unique (prefix, type, instance, vrf_id) tuples in the NHE's
 * re-tree.  Only installed unicast REs are counted, so that orig_re_count
 * matches what the tracker will actually receive during parking.
 */
static uint32_t tracker_count_unique_res(struct nhe_re_tree_head *head)
{
	struct route_entry *re;
	struct tracker_prefix_map_head tmp = {};
	struct tracker_prefix_map_entry *e;
	uint32_t count = 0;

	tracker_prefix_map_init(&tmp);

	frr_each (nhe_re_tree, head, re) {
		struct tracker_prefix_map_entry key;

		/*
		 * Multicast REs are excluded because only unicast routes are
		 * parked (the tracker's prefix-based dedup cannot handle
		 * cross-SAFI route_nodes; e.g. connected routes on eth1 exist
		 * in both unicast and multicast tables with different RNs but
		 * the same prefix).
		 */
		if (!re->rn || rib_table_info(re->rn->table)->safi != SAFI_UNICAST)
			continue;

		/*
		 * Non-installed REs are excluded because rib_link only parks
		 * an incoming RE when old_re is INSTALLED, and non-installed
		 * REs (e.g. an ospf route losing to a connected route for
		 * the same prefix) will never arrive through the tracker
		 * path.  Counting them would inflate orig_re_count,
		 * preventing flush_if_full.
		 */
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
			continue;

		memset(&key, 0, sizeof(key));
		prefix_copy(&key.p, &re->rn->p);
		key.type = re->type;
		key.instance = re->instance;
		key.vrf_id = re->vrf_id;

		if (!tracker_prefix_map_find(&tmp, &key)) {
			struct tracker_prefix_map_entry *entry;

			entry = XCALLOC(MTYPE_NHG_TRACKER_PREFIX_MAP, sizeof(*entry));
			*entry = key;
			tracker_prefix_map_add(&tmp, entry);
			count++;
		}
	}

	frr_each_safe (tracker_prefix_map, &tmp, e) {
		tracker_prefix_map_del(&tmp, e);
		XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, e);
	}
	tracker_prefix_map_fini(&tmp);

	return count;
}

/*
 * Create a new tracker attached to parent_nhe.
 *
 * The snapshot is a deep copy of snapshot_src_nhe's nexthop group.  It
 * represents the "expected" nexthop set for the convergence batch and is
 * used by zebra_nhg_tracker_park_re to classify incoming REs into the
 * matched or unmatched tables.
 *
 * The snapshot source depends on which event triggered tracker creation:
 * - Link UP/DOWN event: Caller passes the same NHE as both parent and snapshot source.
 * - ECMP change detected in rib_link: Caller passes the installed NHG as parent and the
 *   incoming RE's NHG as snapshot source.  The parent still holds the pre-change
 *   (installed) nexthops, while the protocol's new target ECMP set lives on re->nhe.
 */
struct nhg_event_tracker *zebra_nhg_tracker_create(struct nhg_hash_entry *parent_nhe,
						   struct nhg_hash_entry *snapshot_src_nhe,
						   ifindex_t ifindex, enum nhg_tracker_event event)
{
	struct nhg_event_tracker *tracker;
	struct nhg_event_tracker *active;
	struct nhg_event_tracker *head;
	struct nhg_hash_entry *snapshot;
	unsigned long inherit_secs;
	uint32_t unique_re_count;

	if (PROTO_OWNED(parent_nhe))
		return NULL;

	/*
	 * Only count installed unicast REs — these are the ones that will
	 * actually arrive through the tracker path.  Skip tracker creation
	 * when the count is zero.
	 */
	unique_re_count = tracker_count_unique_res(&parent_nhe->re_head);
	if (unique_re_count == 0)
		return NULL;

	snapshot = zebra_nhe_copy(snapshot_src_nhe, snapshot_src_nhe->id);

	tracker = XCALLOC(MTYPE_NHG_TRACKER, sizeof(*tracker));

	head = nhg_event_tracker_list_first(&parent_nhe->tracker_list);
	tracker->nhg_tracker_id = head ? head->nhg_tracker_id + 1 : 1;

	tracker->parent_nhe = parent_nhe;
	tracker->nhg_tracker_snapshot = snapshot;
	tracker->ifindex = ifindex;
	tracker->event = event;
	tracker->orig_re_count = unique_re_count;

	tracker->matched_table.vrf_tables = NULL;
	tracker->matched_table.re_count = 0;

	tracker->unmatched_table.vrf_tables = NULL;
	tracker->unmatched_table.re_count = 0;

	tracker->deleted_table.vrf_tables = NULL;
	tracker->deleted_table.re_count = 0;

	tracker->flush_nhg_groups = list_new();
	tracker->flush_nhg_groups->del = tracker_flush_nhg_group_free;

	/*
	 * List of loser NHEs whose tracker_flush_batch_parent_nhg_id we
	 * set during phase-1 drain.  Cleared in bulk by
	 * tracker_clear_loser_parent_ids() when the tracker finishes.
	 */
	tracker->flush_loser_nhes = list_new();
	tracker->flush_loser_nhes->del = NULL; /* refs are released manually */

	/* New tracker starts out actively parking REs.  Transitions to
	 * WAITING / PHASE1 / PHASE2 happen via zebra_nhg_tracker_flush
	 * and the phase-1/2 entry points.
	 */
	tracker->flush_state = TRACKER_ACTIVE;

	/*
	 * Inherit the oldest existing tracker's remaining timer so that
	 * back-to-back ECMP change events don't keep pushing the expiry out
	 * indefinitely. Capture it before adding the new tracker.
	 */
	inherit_secs = zrouter.nhg_tracker_timeout;
	if (head && event_is_scheduled(head->timer)) {
		unsigned long remain = event_timer_remain_second(head->timer);

		if (remain > 0)
			inherit_secs = remain;
	}

	/*
	 * At any point of time, the NHE has at most one ACTIVE tracker
	 * and at most one FLUSHING tracker can be present.
	 * Find any existing active tracker so that we can collapse
	 * it into the new tracker we're about to add. A flushing
	 * tracker, if present, is left untouched.
	 */
	active = head && !head->flushing ? head : NULL;

	nhg_event_tracker_list_add_head(&parent_nhe->tracker_list, tracker);

	if (active)
		zebra_nhg_tracker_collapse(&parent_nhe->tracker_prefix_map, active, tracker);

	event_add_timer(zrouter.master, nhg_tracker_timer_expiry, tracker, inherit_secs,
			&tracker->timer);

	zrouter.tracker_counters.trackers_allocated++;

	zlog_info("%s: NHG %u created tracker %u (event=%d ifindex=%u snapshot_src_nhg=%u expected_re=%u timer=%lus) total trackers=%zu",
		  __func__, parent_nhe->id, tracker->nhg_tracker_id, event, ifindex,
		  snapshot_src_nhe->id, tracker->orig_re_count, inherit_secs,
		  nhg_event_tracker_list_count(&parent_nhe->tracker_list));

	return tracker;
}

/*
 * Create or update a tracker when multiple singletons on the same
 * interface affect the same NHG.  If a tracker already exists
 * for this ifindex+event with 0 routes, update its snapshot in-place.
 */
struct nhg_event_tracker *zebra_nhg_tracker_create_or_update(struct nhg_hash_entry *nhe,
							     ifindex_t ifindex,
							     enum nhg_tracker_event event)
{
	struct nhg_event_tracker *existing;
	struct nhg_hash_entry *snapshot;

	if (PROTO_OWNED(nhe))
		return NULL;

	frr_each (nhg_event_tracker_list, &nhe->tracker_list, existing) {
		if (existing->ifindex == ifindex && existing->event == event &&
		    existing->matched_table.re_count == 0 &&
		    existing->unmatched_table.re_count == 0) {
			snapshot = zebra_nhe_copy(nhe, nhe->id);

			zebra_nhg_free(existing->nhg_tracker_snapshot);
			existing->nhg_tracker_snapshot = snapshot;

			zlog_info("%s: NHG %u updated tracker %u snapshot (event=%d ifindex=%u)",
				  __func__, nhe->id, existing->nhg_tracker_id, event, ifindex);
			return existing;
		}
	}

	return zebra_nhg_tracker_create(nhe, nhe, ifindex, event);
}

/*
 * Cleanup a tracker
 */
void zebra_nhg_tracker_free(struct nhg_hash_entry *nhe, struct nhg_event_tracker *tracker)
{
	struct tracker_prefix_map_entry *entry;

	zrouter.tracker_counters.trackers_freed++;

	nhg_event_tracker_list_del(&nhe->tracker_list, tracker);

	if (nhg_event_tracker_list_count(&nhe->tracker_list) == 0)
		zlog_info("%s: NHG %u last tracker %u freed, no active trackers remain", __func__,
			  nhe->id, tracker->nhg_tracker_id);

	event_cancel(&tracker->timer);

	/* Clean up prefix_map entries pointing to this tracker */
	frr_each_safe (tracker_prefix_map, &nhe->tracker_prefix_map, entry) {
		if (entry->tracker == tracker) {
			tracker_prefix_map_del(&nhe->tracker_prefix_map, entry);
			XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, entry);
		}
	}

	/* Free flush NHG group list */
	if (tracker->flush_nhg_groups) {
		list_delete(&tracker->flush_nhg_groups);
		tracker->flush_nhg_groups = NULL;
	}

	/* Clear and free the loser-NHE list. */
	if (tracker->flush_loser_nhes) {
		tracker_clear_loser_parent_ids(tracker);
		list_delete(&tracker->flush_loser_nhes);
		tracker->flush_loser_nhes = NULL;
	}

	/* Free per-VRF tables (unlocks RIB RNs stored in trn->info) */
	tracker_vrf_tables_free(&tracker->matched_table);
	tracker_vrf_tables_free(&tracker->unmatched_table);
	tracker_vrf_tables_free(&tracker->deleted_table);

	if (tracker->nhg_tracker_snapshot) {
		zebra_nhg_free(tracker->nhg_tracker_snapshot);
		tracker->nhg_tracker_snapshot = NULL;
	}

	tracker->parent_nhe = NULL;

	XFREE(MTYPE_NHG_TRACKER, tracker);
}

static void zebra_nhg_tracker_sweep_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;

	if (nhg_event_tracker_list_count(&nhe->tracker_list) > 0)
		zebra_nhg_tracker_fini(nhe);
}

/*
 * Release all tracker-held locks on RIB route_nodes before table teardown.
 * Called during shutdown, before any route_table_free runs, so that trackers
 * do not hold dangling references to RIB nodes whose lock has been zeroed
 * by route_table_free.
 */
void zebra_nhg_tracker_sweep_all(void)
{
	hash_iterate(zrouter.nhgs_id, zebra_nhg_tracker_sweep_entry, NULL);
}
