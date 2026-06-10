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

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_nhg_tracker.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_trace.h"

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
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: added %pRN (type %s vrf %s(%u)) to tracker %u, re_count=%u",
					   __func__, rn, zebra_route_string(re->type),
					   vrf_id_to_name(re->vrf_id), re->vrf_id,
					   tracker->nhg_tracker_id, *re_count);
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

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: %pRN (type %s) unmatched, parking in tracker %u for originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
			   __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
			   orig_nhe->id, tracker->matched_table.re_count,
			   tracker->unmatched_table.re_count, tracker->orig_re_count);

	frrtrace(9, frr_zebra, nhg_tracker_park_re, "unmatched", &rn->p, re->type,
		 tracker->nhg_tracker_id, orig_nhe->id, tracker->matched_table.re_count,
		 tracker->unmatched_table.re_count, 0, tracker->orig_re_count);

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

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: %pRN (type %s) deleted parked in tracker %u for originating NHG %u (deleted=%u matched=%u unmatched=%u orig_re=%u)",
			   __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
			   orig_nhe->id, tracker->deleted_table.re_count,
			   tracker->matched_table.re_count, tracker->unmatched_table.re_count,
			   tracker->orig_re_count);

	frrtrace(9, frr_zebra, nhg_tracker_park_re, "deleted", &rn->p, re->type,
		 tracker->nhg_tracker_id, orig_nhe->id, tracker->matched_table.re_count,
		 tracker->unmatched_table.re_count, tracker->deleted_table.re_count,
		 tracker->orig_re_count);

	return tracker;
}

static void zebra_nhg_tracker_park_matched(struct nhg_hash_entry *orig_nhe,
					   struct tracker_prefix_map_head *prefix_map,
					   struct nhg_event_tracker *tracker,
					   struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_add_route(prefix_map, tracker, &tracker->matched_table, rn, re);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: %pRN (type %s) matched tracker %u from originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
			   __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
			   orig_nhe->id, tracker->matched_table.re_count,
			   tracker->unmatched_table.re_count, tracker->orig_re_count);

	frrtrace(9, frr_zebra, nhg_tracker_park_re, "matched", &rn->p, re->type,
		 tracker->nhg_tracker_id, orig_nhe->id, tracker->matched_table.re_count,
		 tracker->unmatched_table.re_count, 0, tracker->orig_re_count);
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

/*
 * Initialise the tracker list and hash embedded in an nhg_hash_entry.
 */
void zebra_nhg_tracker_init(struct nhg_hash_entry *nhe)
{
	nhg_event_tracker_list_init(&nhe->tracker_list);
	tracker_prefix_map_init(&nhe->tracker_prefix_map);
}
