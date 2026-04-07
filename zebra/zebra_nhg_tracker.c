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
#include "zebra/zebra_nhg_tracker.h"
#include "zebra/zebra_router.h"

DEFINE_MTYPE_STATIC(ZEBRA, NHG_TRACKER, "NHG Event Tracker");
DEFINE_MTYPE(ZEBRA, NHG_TRACKER_PREFIX_MAP, "NHG Tracker Prefix Map Entry");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_TRACKER_FLUSH_GROUP, "NHG Tracker Flush Group");

/*
 * Global batch NHG map: child_nhg_id → parent_nhg_id.
 * Simple linked list — typically 1-5 entries.
 */
struct batch_nhg_map_entry {
	uint32_t child_nhg_id;
	uint32_t parent_nhg_id;
	struct batch_nhg_map_entry *next;
};

static struct batch_nhg_map_entry *batch_nhg_map_head;

void tracker_batch_nhg_map_add(uint32_t child_nhg_id, uint32_t parent_nhg_id)
{
	struct batch_nhg_map_entry *e;

	for (e = batch_nhg_map_head; e; e = e->next) {
		if (e->child_nhg_id == child_nhg_id) {
			e->parent_nhg_id = parent_nhg_id;
			return;
		}
	}

	e = XCALLOC(MTYPE_NHG_TRACKER, sizeof(*e));
	e->child_nhg_id = child_nhg_id;
	e->parent_nhg_id = parent_nhg_id;
	e->next = batch_nhg_map_head;
	batch_nhg_map_head = e;
}

void tracker_batch_nhg_map_clear(uint32_t parent_nhg_id)
{
	struct batch_nhg_map_entry *e, *prev = NULL, *next;

	for (e = batch_nhg_map_head; e; e = next) {
		next = e->next;
		if (e->parent_nhg_id == parent_nhg_id) {
			if (prev)
				prev->next = next;
			else
				batch_nhg_map_head = next;
			XFREE(MTYPE_NHG_TRACKER, e);
		} else {
			prev = e;
		}
	}
}

uint32_t tracker_batch_nhg_map_lookup(uint32_t child_nhg_id)
{
	struct batch_nhg_map_entry *e;

	for (e = batch_nhg_map_head; e; e = e->next) {
		if (e->child_nhg_id == child_nhg_id)
			return e->parent_nhg_id;
	}

	return 0;
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
 * Hash key: parent NHG ID + nexthop hashes.
 */
uint32_t nhg_event_tracker_hash_key(const struct nhg_event_tracker *t)
{
	const struct nhg_hash_entry *snap = t->nhg_tracker_snapshot;
	uint32_t key = 0x5a351234;
	uint32_t primary;
	uint32_t backup = 0;

	primary = nexthop_group_hash(&snap->nhg);
	if (snap->backup_info)
		backup = nexthop_group_hash(&snap->backup_info->nhe->nhg);

	key = jhash_3words(snap->id, primary, backup, key);

	return key;
}

/*
 * Returns 0 on match, non-zero otherwise.
 */
int nhg_event_tracker_hash_cmp(const struct nhg_event_tracker *a, const struct nhg_event_tracker *b)
{
	const struct nhg_hash_entry *sa = a->nhg_tracker_snapshot;
	const struct nhg_hash_entry *sb = b->nhg_tracker_snapshot;
	struct nexthop *nh1, *nh2;

	if (sa->id != sb->id)
		return 1;

	/* Compare primary nexthops */
	for (nh1 = sa->nhg.nexthop, nh2 = sb->nhg.nexthop; nh1 && nh2;
	     nh1 = nexthop_next(nh1), nh2 = nexthop_next(nh2)) {
		if (!nhg_compare_nexthops(nh1, nh2))
			return 1;
	}
	if (nh1 || nh2)
		return 1;

	/* Compare backup nexthops */
	if (!sa->backup_info && !sb->backup_info)
		return 0;
	if (sa->backup_info && !sb->backup_info)
		return 1;
	if (!sa->backup_info && sb->backup_info)
		return 1;

	for (nh1 = sa->backup_info->nhe->nhg.nexthop, nh2 = sb->backup_info->nhe->nhg.nexthop;
	     nh1 && nh2; nh1 = nexthop_next(nh1), nh2 = nexthop_next(nh2)) {
		if (!nhg_compare_nexthops(nh1, nh2))
			return 1;
	}
	if (nh1 || nh2)
		return 1;

	return 0;
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
 * old_tracker to new_tracker (all become unmatched), transfers counts,
 * then destroys old tracker.
 */
static void zebra_nhg_tracker_collapse(struct tracker_prefix_map_head *prefix_map,
				       struct nhg_event_tracker *old_tracker,
				       struct nhg_event_tracker *new_tracker)
{
	struct tracker_prefix_map_entry *entry;

	tracker_vrf_tables_move(&old_tracker->matched_table, &new_tracker->unmatched_table);
	tracker_vrf_tables_move(&old_tracker->unmatched_table, &new_tracker->unmatched_table);

	frr_each_safe (tracker_prefix_map, prefix_map, entry) {
		if (entry->tracker == old_tracker)
			entry->tracker = new_tracker;
	}

	new_tracker->unmatched_table.re_count += old_tracker->matched_table.re_count +
						 old_tracker->unmatched_table.re_count;
	old_tracker->matched_table.re_count = 0;
	old_tracker->unmatched_table.re_count = 0;

	zlog_info("%s: collapsed tracker %u into tracker %u for NHG %u (new unmatched=%u)",
		  __func__, old_tracker->nhg_tracker_id, new_tracker->nhg_tracker_id,
		  new_tracker->parent_nhe ? new_tracker->parent_nhe->id : 0,
		  new_tracker->unmatched_table.re_count);

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
			zlog_info("%s: added %pRN (type %s vrf %s(%u)) to tracker %u, re_count=%u",
				  __func__, rn, zebra_route_string(re->type),
				  vrf_id_to_name(re->vrf_id), re->vrf_id, tracker->nhg_tracker_id,
				  *re_count);
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
 * tracker table (matched or unmatched).
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

	zlog_info("%s: %pRN (type %s) unmatched, parking in tracker %u for originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
		  __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
		  orig_nhe->id, tracker->matched_table.re_count, tracker->unmatched_table.re_count,
		  tracker->orig_re_count);

	return tracker;
}

/*
 * Collapse all trackers strictly older than keeper into keeper.
 * Their routes land in keeper's unmatched table.
 */
static void zebra_nhg_tracker_absorb_older(struct nhg_hash_entry *orig_nhe,
					   struct tracker_prefix_map_head *prefix_map,
					   struct nhg_event_tracker *keeper)
{
	struct nhg_event_tracker *t, *next_t;

	for (t = nhg_event_tracker_list_next(&orig_nhe->tracker_list, keeper); t; t = next_t) {
		next_t = nhg_event_tracker_list_next(&orig_nhe->tracker_list, t);
		if (t->flushing)
			continue;
		zebra_nhg_tracker_collapse(prefix_map, t, keeper);
	}
}

/*
 * Insert the route into the tracker's matched table and log the event.
 * Tracker Truth Table for RE movement:
 * +---------------------+--------------------+--------------------+--------------------+----------------------+
 * | Transition          | matched->matched   | matched->unmatched | unmatched->matched | unmatched->unmatched |
 * +---------------------+--------------------+--------------------+--------------------+----------------------+
 * | within same tracker |        NA          | evict from same    | evict from same    |          NA          |
 * |                     |                    | tracker's matched, | tracker's          |                      |
 * |                     |                    | store in same      | unmatched, store   |                      |
 * |                     |                    | tracker's unmatched| in same tracker's  |                      |
 * |                     |                    |                    | matched            |                      |
 * +---------------------+--------------------+--------------------+--------------------+----------------------+
 * | old to new tracker  | collapse old       | evict from old     | collapse old       | evict from old       |
 * |                     | trackers into new, | matched, store in  | trackers into new, | unmatched, store in  |
 * |                     | evict from old     | new unmatched      | evict from old     | new unmatched        |
 * |                     | matched, store in  |                    | unmatched, store   |                      |
 * |                     | new matched        |                    | in new matched     |                      |
 * +---------------------+--------------------+--------------------+--------------------+----------------------+
 * | new to old tracker  | evict from new     |        NA          | evict from new     |          NA          |
 * |                     | matched, store in  |                    | unmatched, store   |                      |
 * |                     | old matched (new   |                    | in old matched     |                      |
 * |                     | tracker still      |                    | (new tracker still |                      |
 * |                     | alive)             |                    | alive)             |                      |
 * +---------------------+--------------------+--------------------+--------------------+----------------------+
 */
static void zebra_nhg_tracker_park_matched(struct nhg_hash_entry *orig_nhe,
					   struct tracker_prefix_map_head *prefix_map,
					   struct nhg_event_tracker *tracker,
					   struct route_node *rn, struct route_entry *re)
{
	zebra_nhg_tracker_add_route(prefix_map, tracker, &tracker->matched_table, rn, re);

	zlog_info("%s: %pRN (type %s) matched tracker %u from originating NHG %u (matched=%u unmatched=%u orig_re=%u)",
		  __func__, rn, zebra_route_string(re->type), tracker->nhg_tracker_id,
		  orig_nhe->id, tracker->matched_table.re_count, tracker->unmatched_table.re_count,
		  tracker->orig_re_count);
}

/*
 * Park an RE in the appropriate tracker instead of queuing it
 * for best-path selection.
 * orig_nhe	: the originating NHE, carries the trackers and prefix_map
 * re		: the incoming RE
 */
struct nhg_event_tracker *zebra_nhg_tracker_park_re(struct route_node *rn, struct route_entry *re,
						    struct nhg_hash_entry *orig_nhe)
{
	struct nhg_event_tracker *tracker, *keeper;
	struct nhg_event_tracker *evict_from;
	struct tracker_prefix_map_head *prefix_map = &orig_nhe->tracker_prefix_map;
	struct tracker_prefix_map_entry pm_key;
	struct tracker_prefix_map_entry *pm_re;
	struct nhg_event_tracker *newest_tracker;
	bool matched = false;

	memset(&pm_key, 0, sizeof(pm_key));
	prefix_copy(&pm_key.p, &rn->p);
	pm_key.type = re->type;
	pm_key.instance = re->instance;
	pm_key.vrf_id = re->vrf_id;
	pm_re = tracker_prefix_map_find(prefix_map, &pm_key);

	/*
	 * In general, a prefix is parked in at most one trackers matched table at any
	 * point in time.  Walk trackers (older to newest) to find one whose
	 * snapshot matches the incoming RE's NHG.
	 * Match: collapse all strictly older trackers into that keeper; their
	 * routes land in keeper's unmatched.
	 * No match for this RE's NHG: if the prefix_map still shows it parked
	 * in an older tracker (stale), zebra_nhg_tracker_add_route (below)
	 * evicts that tracker and moves the route to the newest tracker's
	 * unmatched, collapsing the stale tracker.
	 */
	frr_rev_each (nhg_event_tracker_list, &orig_nhe->tracker_list, tracker) {
		if (tracker->flushing)
			continue;
		if (zebra_nhg_nexthop_compare(re->nhe->nhg.nexthop,
					      tracker->nhg_tracker_snapshot->nhg.nexthop, rn,
					      true)) {
			keeper = tracker;

			zebra_nhg_tracker_absorb_older(orig_nhe, prefix_map, keeper);

			/*
			 * Collapse has already repointed prefix_map entries from absorbed
			 * trackers to the keeper.  Get the latest owner from prefix_map
			 * and evict the RE from that tracker's unmatched/matched
			 * table (default to the keeper when no map row exists yet).
			 * This covers:
			 * - RE moved into this tracker's unmatched via collapse.
			 * - RE in a newer tracker's unmatched/matched while this older
			 *   tracker's NHG matches—evict there before parking here.
			 * - RE already in the same tracker's matched from a prior
			 *   iteration—evict so park_matched creates a fresh entry.
			 */
			evict_from = tracker;
			/* prefix_map may have changed during collapse; re-resolve owner. */
			pm_re = tracker_prefix_map_find(prefix_map, &pm_key);
			if (pm_re)
				evict_from = pm_re->tracker;

			zebra_nhg_tracker_evict_from_unmatched(evict_from, orig_nhe, prefix_map,
							       rn, re);
			zebra_nhg_tracker_evict_from_matched(evict_from, orig_nhe, prefix_map, rn,
							     re);

			zebra_nhg_tracker_park_matched(orig_nhe, prefix_map, tracker, rn, re);
			matched = true;
			break;
		}
	}

	if (!matched) {
		/*
		 * Unmatched REs are always parked in the newest tracker.  Evict the RE
		 * from the tracker that currently owns it (as per prefix_map) when that
		 * tracker's ID <= newest(covers matched->unmatched transitions from old->new
		 * and within-same-tracker).  The RE may sit in its unmatched or
		 * matched table.
		 */
		newest_tracker = nhg_event_tracker_list_first(&orig_nhe->tracker_list);
		while (newest_tracker && newest_tracker->flushing)
			newest_tracker = nhg_event_tracker_list_next(&orig_nhe->tracker_list,
								     newest_tracker);
		if (pm_re && newest_tracker &&
		    pm_re->tracker->nhg_tracker_id <= newest_tracker->nhg_tracker_id) {
			zebra_nhg_tracker_evict_from_unmatched(pm_re->tracker, orig_nhe,
							       prefix_map, rn, re);
			zebra_nhg_tracker_evict_from_matched(pm_re->tracker, orig_nhe, prefix_map,
							     rn, re);
		}

		tracker = zebra_nhg_tracker_park_unmatched(orig_nhe, prefix_map, rn, re);
	}

	SET_FLAG(re->status, ROUTE_ENTRY_TRACKER);

	return tracker;
}

/* Forward declarations for mutually-recursive flush batch functions */
static void tracker_flush_batch_expiry_timer(struct event *event);
static void tracker_flush_batch_start_phase2(struct nhg_hash_entry *nhe,
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
	evt->orig_re_count = tracker->orig_re_count;
	zrouter.tracker_counters.log_idx++;
}

/*
 * Build the NHG group list: walk matched + unmatched tables, count REs
 * per incoming NHG, and pick the winner (highest count; matched wins tie).
 * Result stored in tracker->flush_nhg_groups and tracker->winner_*.
 */
static void tracker_flush_build_groups(struct nhg_event_tracker *tracker,
				       struct nhg_hash_entry *parent_nhe)
{
	struct list *groups = tracker->flush_nhg_groups;
	struct tracker_flush_nhg_group *g, *winner = NULL;
	struct listnode *node;
	uint32_t matched_count = tracker->matched_table.re_count;
	uint32_t max_count = matched_count;
	struct tracker_vrf_table *vt;

	/* Count unmatched groups by incoming NHG ID (new converged REs only) */
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

	/* Find max across unmatched groups */
	for (ALL_LIST_ELEMENTS_RO(groups, node, g)) {
		if (g->re_count > max_count) {
			max_count = g->re_count;
			winner = g;
		}
	}

	/* Pick winner: matched wins on tie */
	if (matched_count >= max_count && matched_count > 0) {
		tracker->winner_nhg_id = parent_nhe->id;
		tracker->winner_nhe = parent_nhe;
		tracker->winner_is_matched = true;
	} else if (winner) {
		tracker->winner_nhg_id = winner->incoming_nhg_id;
		tracker->winner_nhe = winner->incoming_nhe;
		tracker->winner_is_matched = false;
		winner->is_winner = true;
	}

	zlog_info("%s: NHG %u winner: NHG %u (%s, %u routes), matched=%u unmatched=%u", __func__,
		  parent_nhe->id, tracker->winner_nhg_id,
		  tracker->winner_is_matched ? "matched" : "unmatched", max_count,
		  tracker->matched_table.re_count, tracker->unmatched_table.re_count);
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
 * filter_nhg_id:  non-zero → only process REs whose incoming NHG matches.
 * exclude_nhg_id: non-zero → skip REs whose incoming NHG matches.
 * update_nhe:     true → repoint RE to parent NHG (winners reuse old ID).
 * track_pending:  true → mark RE with NHG_TRACKER_FLUSH_BATCH and increment
 *                 routes_pending for phase 1 dplane ack tracking.
 *                 false → just queue (phase 2 finishes synchronously).
 */
static void tracker_flush_batch_process_table(struct nhg_hash_entry *parent_nhe,
					      struct nhg_event_tracker *tracker,
					      struct nhg_tracker_table *table,
					      uint32_t filter_nhg_id, uint32_t exclude_nhg_id,
					      bool update_nhe, bool track_pending)
{
	struct tracker_vrf_table *vt;

	if (!table)
		return;

	for (vt = table->vrf_tables; vt; vt = vt->next) {
		struct route_node *trn;

		for (trn = route_top(vt->table); trn; trn = route_next(trn)) {
			struct route_node *rn;
			struct route_entry *re;
			bool processed_new_re = false;

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
				if (!CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
					continue;

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
					 */
					SET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH);
					if (re->nhe)
						re->nhe->tracker_flush_batch_parent_nhg_id =
							parent_nhe->id;
					tracker->routes_pending++;
				}
				processed_new_re = true;
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
			if (processed_new_re) {
				RNODE_FOREACH_RE (rn, re) {
					if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER) &&
					    !CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED))
						UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);
				}
				rib_queue_add(rn);
			}
		}
	}
}

/*
 * Complete the flush batch: free groups, free the flushing tracker.
 */
static void tracker_flush_batch_finish(struct nhg_hash_entry *nhe,
				       struct nhg_event_tracker *tracker)
{
	event_cancel(&tracker->timer);
	tracker_flush_free_groups(tracker);
	zebra_nhg_tracker_free(nhe, tracker);
}

/*
 * Rework the parent NHG in-place with the winner NHG's nexthop list.
 *
 * 1. Remove parent NHG from the content hash (zrouter.nhgs).
 * 2. Release old nhg_depends edges and free old nexthop list.
 * 3. Copy the winner NHG's full nexthop list (all NHs the protocol sent).
 * 4. Rebuild nhg_depends from the new nexthop list.
 * 5. Re-insert into the content hash (collision deferred).
 *
 * The NHG stays at the same memory address and keeps the same ID,
 * so all re->nhe pointers and the ID hash remain valid.
 */
static void tracker_flush_rework_nhg(struct nhg_hash_entry *nhe, struct nhg_hash_entry *winner_nhe)
{
	zebra_nhg_rework_in_place(nhe, winner_nhe);
}

/*
 * Phase 2: rework the parent NHG and process winner REs.
 *
 * 1. Structurally rework the parent NHG with the winner's nexthop list.
 * 2. Set REINSTALL and install the updated NHG to kernel.
 * 3. Send winner REs through rib_process.
 */
static void tracker_flush_batch_start_phase2(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *tracker)
{
	if (!tracker->winner_nhg_id) {
		zlog_info("%s: no winner, finishing for NHG %u", __func__, nhe->id);
		tracker_flush_batch_finish(nhe, tracker);
		return;
	}

	tracker->flush_state = TRACKER_FLUSH_PHASE2;

	/* No safety timer for phase 2 — it finishes synchronously */
	event_cancel(&tracker->timer);

	zlog_info("%s: NHG %u phase 2: winner NHG %u (%s)", __func__, nhe->id,
		  tracker->winner_nhg_id, tracker->winner_is_matched ? "matched" : "unmatched");

	/*
	 * Set TRACKER_REWORKED now — right before sending winner REs.
	 * This flag is NOT set during phase 1, so phase 1 loser REs
	 * go through normal nexthop_active_update without triggering
	 * the second rework.  The first winner RE consumes and clears it.
	 *
	 * The first rework was already done before phase 1.  REINSTALL
	 * is already set.  The first winner RE triggers the second rework
	 * in nexthop_active_update (copies resolved state back to NHG-10).
	 * Subsequent winner REs find NHG-10 via content lookup.
	 */
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_TRACKER_REWORKED);

	if (tracker->winner_is_matched) {
		tracker_flush_batch_process_table(nhe, tracker, &tracker->matched_table, 0, 0,
						  true, false);
	} else {
		tracker_flush_batch_process_table(nhe, tracker, &tracker->unmatched_table,
						  tracker->winner_nhg_id, 0, true, false);
	}

	/* Phase 2 is done — no need to wait for dplane acks since the
	 * winner routes reuse the same NHG ID and the kernel NHG was
	 * already updated above.
	 */
	zlog_info("%s: phase 2 done for NHG %u, finishing tracker", __func__, nhe->id);
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
	struct nhg_event_tracker *tracker;

	if (!CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH))
		return;

	UNSET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH);

	if (!re->nhe)
		return;

	/*
	 * The RE may have been switched to a new NHG by rib_process
	 * (e.g. loser NHG-31 resolved to NHG-37).  Try the current
	 * NHG first; if no flushing tracker there, use the parent NHG
	 * ID that was carried forward from the original NHG.
	 */
	nhe = re->nhe;
	tracker = tracker_find_flushing(nhe);
	if (!tracker && nhe->tracker_flush_batch_parent_nhg_id) {
		struct nhg_hash_entry *parent;

		parent = zebra_nhg_lookup_id(nhe->tracker_flush_batch_parent_nhg_id);
		if (parent)
			tracker = tracker_find_flushing(parent);

		/* Clear the transient parent ID now that we've used it */
		nhe->tracker_flush_batch_parent_nhg_id = 0;
	}

	if (!tracker)
		return;

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

	zlog_info("%s: phase 1 complete for NHG %u, starting phase 2", __func__, nhe->id);
	tracker_flush_batch_start_phase2(nhe, tracker);
}

static void tracker_flush_batch_expiry_timer(struct event *event)
{
	struct nhg_event_tracker *tracker = EVENT_ARG(event);
	struct nhg_hash_entry *nhe = tracker->parent_nhe;

	zlog_warn("%s: safety timer expired for NHG %u phase %u (pending=%u)", __func__,
		  nhe ? nhe->id : 0, tracker->flush_state, tracker->routes_pending);

	/* Safety timer only runs during phase 1 — force transition to phase 2 */
	tracker->routes_pending = 0;
	tracker_flush_batch_start_phase2(nhe, tracker);
}

/*
 * Start the two-phase flush batch.
 * Phase 1: send all losers (non-winner NHG groups) through rib_process.
 * Phase 2: after phase 1 acks, update parent NHG and send winners.
 */
static void tracker_flush_batch_start_phase1(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *tracker)
{
	bool has_phase1 = false;
	struct tracker_flush_nhg_group *g;
	struct listnode *node;

	/*
	 * Rework NHG-10 BEFORE sending any routes.  This prevents phase 1
	 * loser REs from claiming the old NHG-10 content via
	 * zebra_nhg_rib_compare_old_nhe during their rib_process.  After
	 * rework, NHG-10 has the winner's NH content so losers (different
	 * NH set) won't match it.
	 *
	 * TRACKER_REWORKED signals nexthop_active_update to keep the
	 * NHG ID on the copy and do the second rework (resolved state
	 * copy-back) for the first winner RE.
	 */
	if (!tracker->winner_is_matched && tracker->winner_nhe && tracker->winner_nhe != nhe) {
		zlog_info("%s: first rework NHG %u (id stays %u) with winner NHG %u content before phase 1",
			  __func__, nhe->id, nhe->id, tracker->winner_nhe->id);
		tracker_flush_rework_nhg(nhe, tracker->winner_nhe);
	}

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL);

	/* Check if there are any phase 1 groups */
	if (!tracker->winner_is_matched && tracker->matched_table.re_count > 0)
		has_phase1 = true;
	for (ALL_LIST_ELEMENTS_RO(tracker->flush_nhg_groups, node, g)) {
		if (g->incoming_nhg_id != tracker->winner_nhg_id) {
			has_phase1 = true;
			break;
		}
	}

	tracker->routes_pending = 0;

	/* Repurpose timer as safety timer */
	event_cancel(&tracker->timer);
	event_add_timer(zrouter.master, tracker_flush_batch_expiry_timer, tracker,
			NHG_TRACKER_DEFAULT_TIMEOUT_SEC, &tracker->timer);

	zlog_info("%s: NHG %u winner NHG %u, has_phase1=%d", __func__, nhe->id,
		  tracker->winner_nhg_id, has_phase1);

	if (has_phase1) {
		tracker->flush_state = TRACKER_FLUSH_PHASE1;

		/* Send unmatched losers (exclude winner NHG ID, track acks) */
		tracker_flush_batch_process_table(nhe, tracker, &tracker->unmatched_table, 0,
						  tracker->winner_nhg_id, false, true);

		/* Send matched losers (if matched is not the winner, track acks) */
		if (!tracker->winner_is_matched)
			tracker_flush_batch_process_table(nhe, tracker, &tracker->matched_table, 0,
							  0, false, true);

		if (tracker->routes_pending == 0)
			tracker_flush_batch_start_phase2(nhe, tracker);
	} else {
		tracker_flush_batch_start_phase2(nhe, tracker);
	}
}

static void zebra_nhg_tracker_flush(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe)
{
	tracker_flush_update_counters(tracker, nhe);
	tracker_flush_build_groups(tracker, nhe);

	if (!tracker->winner_nhg_id && listcount(tracker->flush_nhg_groups) == 0) {
		/* Nothing to flush */
		zebra_nhg_tracker_free(nhe, tracker);
		return;
	}

	/*
	 * Mark as flushing.  The tracker stays in tracker_list so new
	 * trackers can see it (and skip it), but:
	 * - It must not be collapsed into another tracker.
	 * - No additional routes may be parked in it.
	 * Remove its prefix_map entries so new routes for the same
	 * prefixes can park in fresh trackers.
	 */
	tracker->flushing = true;

	struct tracker_prefix_map_entry *entry;

	frr_each_safe (tracker_prefix_map, &nhe->tracker_prefix_map, entry) {
		if (entry->tracker == tracker) {
			tracker_prefix_map_del(&nhe->tracker_prefix_map, entry);
			XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, entry);
		}
	}

	tracker_flush_batch_start_phase1(nhe, tracker);
}

/*
 * Check if all expected REs have been parked; if so, flush.
 */
void zebra_nhg_tracker_flush_if_full(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe)
{
	if (!tracker)
		return;

	if ((tracker->matched_table.re_count + tracker->unmatched_table.re_count) !=
	    tracker->orig_re_count)
		return;

	zlog_info("flush_if_full tracker %u NHG %u (matched=%u unmatched=%u orig_re=%u)",
		  tracker->nhg_tracker_id, nhe->id, tracker->matched_table.re_count,
		  tracker->unmatched_table.re_count, tracker->orig_re_count);

	zebra_nhg_tracker_flush(tracker, nhe);
}

/* Timer callback - flush via the batch mechanism */
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

	zlog_info("timer_expiry tracker %u NHG %u ifindex %u event %s (matched=%u unmatched=%u orig_re=%u)",
		  tracker->nhg_tracker_id, nhe->id, tracker->ifindex,
		  tracker->event == NHG_TRACKER_EVENT_INTF_UP ? "UP" : "DOWN",
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
	nhg_event_tracker_hash_init(&nhe->tracker_hash);
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

	nhg_event_tracker_hash_fini(&nhe->tracker_hash);

	{
		struct tracker_prefix_map_entry *entry;

		while ((entry = tracker_prefix_map_pop(&nhe->tracker_prefix_map)) != NULL)
			XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, entry);
	}
	tracker_prefix_map_fini(&nhe->tracker_prefix_map);
}

/*
 * Lookup an existing tracker whose snapshot matches the given NHG state.
 */
struct nhg_event_tracker *zebra_nhg_tracker_lookup(struct nhg_hash_entry *nhe,
						   struct nhg_hash_entry *snapshot)
{
	struct nhg_event_tracker key;
	struct nhg_event_tracker *found;

	memset(&key, 0, sizeof(key));
	key.nhg_tracker_snapshot = snapshot;

	found = nhg_event_tracker_hash_find(&nhe->tracker_hash, &key);

	/* Skip flushing trackers — they must not be reused */
	if (found && found->flushing)
		return NULL;

	return found;
}

/*
 * The new event produces an NHG state that matches an existing
 * tracker.  Reuse the matching tracker and collapse all other
 * trackers into it - other tracker's routes become unmatched in keeper
 */
static void zebra_nhg_tracker_loop_detection(struct nhg_hash_entry *nhe,
					     struct nhg_event_tracker *keeper)
{
	struct nhg_event_tracker *t, *next;
	struct tracker_prefix_map_head *prefix_map = &nhe->tracker_prefix_map;

	zrouter.tracker_counters.tracker_loop_detected++;

	for (t = nhg_event_tracker_list_first(&nhe->tracker_list); t; t = next) {
		next = nhg_event_tracker_list_next(&nhe->tracker_list, t);

		if (t == keeper || t->flushing)
			continue;

		zlog_info("%s: NHG %u loop: collapsing old tracker %u (matched=%u unmatched=%u) into keeper %u (matched=%u unmatched=%u)",
			  __func__, nhe->id, t->nhg_tracker_id, t->matched_table.re_count,
			  t->unmatched_table.re_count, keeper->nhg_tracker_id,
			  keeper->matched_table.re_count, keeper->unmatched_table.re_count);

		zebra_nhg_tracker_collapse(prefix_map, t, keeper);
	}
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

	while (tracker_prefix_map_count(&tmp)) {
		struct tracker_prefix_map_entry *e = tracker_prefix_map_pop(&tmp);

		XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, e);
	}
	tracker_prefix_map_fini(&tmp);

	return count;
}

/*
 * Create a new tracker upon interface event.
 */
struct nhg_event_tracker *zebra_nhg_tracker_create(struct nhg_hash_entry *nhe, ifindex_t ifindex,
						   enum nhg_tracker_event_intf event)
{
	struct nhg_event_tracker *existing;
	struct nhg_event_tracker *tracker;
	struct nhg_event_tracker *head;
	struct nhg_event_tracker *oldest;
	struct nhg_hash_entry *snapshot;
	unsigned long inherit_secs;
	uint32_t unique_re_count;

	/*
	 * Only count installed unicast REs — these are the ones that will
	 * actually arrive through the tracker path.  Skip tracker creation
	 * when the count is zero.
	 */
	unique_re_count = tracker_count_unique_res(&nhe->re_head);
	if (unique_re_count == 0)
		return NULL;

	snapshot = zebra_nhe_copy(nhe, nhe->id);

	existing = zebra_nhg_tracker_lookup(nhe, snapshot);
	if (existing) {
		zebra_nhg_free(snapshot);
		zlog_info("%s: already existing tracker found for NHG %u, reusing tracker %u",
			  __func__, nhe->id, existing->nhg_tracker_id);
		zebra_nhg_tracker_loop_detection(nhe, existing);
		return existing;
	}

	tracker = XCALLOC(MTYPE_NHG_TRACKER, sizeof(*tracker));

	head = nhg_event_tracker_list_first(&nhe->tracker_list);
	tracker->nhg_tracker_id = head ? head->nhg_tracker_id + 1 : 1;

	tracker->parent_nhe = nhe;
	tracker->nhg_tracker_snapshot = snapshot;
	tracker->ifindex = ifindex;
	tracker->event = event;
	tracker->orig_re_count = unique_re_count;

	tracker->matched_table.vrf_tables = NULL;
	tracker->matched_table.re_count = 0;

	tracker->unmatched_table.vrf_tables = NULL;
	tracker->unmatched_table.re_count = 0;

	tracker->flush_nhg_groups = list_new();
	tracker->flush_nhg_groups->del = tracker_flush_nhg_group_free;

	/*
	 * Inherit the oldest existing tracker's remaining timer so that
	 * back-to-back interface events don't keep pushing the expiry out
	 * indefinitely.  Capture it before collapsing older trackers.
	 */
	inherit_secs = zrouter.nhg_tracker_timeout;
	oldest = nhg_event_tracker_list_last(&nhe->tracker_list);
	if (oldest && event_is_scheduled(oldest->timer)) {
		unsigned long remain = event_timer_remain_second(oldest->timer);

		if (remain > 0)
			inherit_secs = remain;
	}

	nhg_event_tracker_list_add_head(&nhe->tracker_list, tracker);
	nhg_event_tracker_hash_add(&nhe->tracker_hash, tracker);

	/*
	 * Collapse all older trackers into this one: their matched and
	 * unmatched routes move into new tracker's unmatched table, and
	 * prefix_map entries are repointed.
	 */
	if (nhg_event_tracker_list_count(&nhe->tracker_list) > 1) {
		zebra_nhg_tracker_absorb_older(nhe, &nhe->tracker_prefix_map, tracker);
	}

	event_add_timer(zrouter.master, nhg_tracker_timer_expiry, tracker, inherit_secs,
			&tracker->timer);

	zrouter.tracker_counters.trackers_allocated++;

	zlog_info("%s: NHG %u created tracker %u (event=%s ifindex=%u timer=%lus) total trackers=%zu",
		  __func__, nhe->id, tracker->nhg_tracker_id,
		  event == NHG_TRACKER_EVENT_INTF_UP ? "UP" : "DOWN", ifindex, inherit_secs,
		  nhg_event_tracker_list_count(&nhe->tracker_list));

	return tracker;
}

/*
 * Create or update a tracker when multiple singletons on the same
 * interface affect the same NHG.  If a tracker already exists
 * for this ifindex+event with 0 routes, update its snapshot in-place.
 */
struct nhg_event_tracker *zebra_nhg_tracker_create_or_update(struct nhg_hash_entry *nhe,
							     ifindex_t ifindex,
							     enum nhg_tracker_event_intf event)
{
	struct nhg_event_tracker *existing;
	struct nhg_hash_entry *snapshot;

	frr_each (nhg_event_tracker_list, &nhe->tracker_list, existing) {
		if (existing->ifindex == ifindex && existing->event == event &&
		    existing->matched_table.re_count == 0 &&
		    existing->unmatched_table.re_count == 0) {
			snapshot = zebra_nhe_copy(nhe, nhe->id);

			nhg_event_tracker_hash_del(&nhe->tracker_hash, existing);

			zebra_nhg_free(existing->nhg_tracker_snapshot);
			existing->nhg_tracker_snapshot = snapshot;

			nhg_event_tracker_hash_add(&nhe->tracker_hash, existing);

			zlog_info("%s: NHG %u updated tracker %u snapshot (event=%s ifindex=%u)",
				  __func__, nhe->id, existing->nhg_tracker_id,
				  event == NHG_TRACKER_EVENT_INTF_UP ? "UP" : "DOWN", ifindex);
			return existing;
		}
	}

	return zebra_nhg_tracker_create(nhe, ifindex, event);
}

/*
 * Cleanup a tracker
 */
void zebra_nhg_tracker_free(struct nhg_hash_entry *nhe, struct nhg_event_tracker *tracker)
{
	struct tracker_prefix_map_entry *entry;

	zrouter.tracker_counters.trackers_freed++;

	nhg_event_tracker_hash_del(&nhe->tracker_hash, tracker);
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

	/* Free per-VRF tables (unlocks RIB RNs stored in trn->info) */
	tracker_vrf_tables_free(&tracker->matched_table);
	tracker_vrf_tables_free(&tracker->unmatched_table);

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
