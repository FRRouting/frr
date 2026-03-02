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

/*
 * tracker_prefix_map hash.
 * Key:   (prefix, protocol type, protocol instance).
 * Value: pointer to the tracker that owns this (prefix, type, instance).
 */
uint32_t tracker_prefix_map_hash_key(const struct tracker_prefix_map_entry *e)
{
	uint32_t key;

	key = prefix_hash_key(&e->p);
	key = jhash_2words((uint32_t)e->type, (uint32_t)e->instance, key);
	return key;
}

int tracker_prefix_map_hash_cmp(const struct tracker_prefix_map_entry *a,
				const struct tracker_prefix_map_entry *b)
{
	if (a->type != b->type)
		return 1;
	if (a->instance != b->instance)
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
 * Move all RN entries from src_table to dst_table.
 * For each prefix in src: if dst doesn't have it, set dst trn->info = src trn->info.
 * If dst already has it, skip (both point to the same RIB RN).
 * Clears src entries and updates both counters.
 */
void zebra_nhg_tracker_move_routes(struct route_table *src_table, uint32_t *src_count,
				   struct route_table *dst_table, uint32_t *dst_count)
{
	struct route_node *old_trn;
	struct route_node *trn;

	for (old_trn = route_top(src_table); old_trn; old_trn = route_next(old_trn)) {
		if (!old_trn->info)
			continue;

		trn = route_node_get(dst_table, &old_trn->p);
		if (!trn->info) {
			trn->info = old_trn->info;
			(*dst_count)++;
		} else {
			/* release the lock held during node find */
			route_unlock_node(trn);
			/*
			 * we end up here if there is a duplicate RN in 2 trackers
			 * So there are now two tracker-side locks on the same RIB rn
			 * and we need to unlock the old tracker's reference
			 */
			zlog_info("%s warning: duplicate RIB RN %pRN already in dst table, releasing src reference",
				  __func__, (struct route_node *)old_trn->info);
			route_unlock_node((struct route_node *)old_trn->info);
		}

		old_trn->info = NULL;
		(*src_count)--;
		route_unlock_node(old_trn);
	}
}

/*
 * Collapse a stale tracker into a target tracker.
 * Moves all prefixes from old_tracker's matched and unmatched tables
 * into new_tracker's unmatched table, updates the prefix_map, then
 * destroys the old tracker.
 */
static void zebra_nhg_tracker_collapse(struct tracker_prefix_map_head *prefix_map,
				       struct nhg_event_tracker *old_tracker,
				       struct nhg_event_tracker *new_tracker)
{
	zebra_nhg_tracker_move_routes(old_tracker->matched_table.matched_table,
				      &old_tracker->matched_table.re_count,
				      new_tracker->unmatched_table.unmatched_table,
				      &new_tracker->unmatched_table.re_count);

	zebra_nhg_tracker_move_routes(old_tracker->unmatched_table.unmatched_table,
				      &old_tracker->unmatched_table.re_count,
				      new_tracker->unmatched_table.unmatched_table,
				      &new_tracker->unmatched_table.re_count);

	struct tracker_prefix_map_entry *entry;

	frr_each_safe (tracker_prefix_map, prefix_map, entry) {
		if (entry->tracker == old_tracker)
			entry->tracker = new_tracker;
	}

	zlog_info("%s: collapsed tracker %u into tracker %u for NHG %u (new unmatched=%u)",
		  __func__, old_tracker->nhg_tracker_id, new_tracker->nhg_tracker_id,
		  new_tracker->parent_nhe ? new_tracker->parent_nhe->id : 0,
		  new_tracker->unmatched_table.re_count);

	zebra_nhg_tracker_free(old_tracker->parent_nhe, old_tracker);
}

/*
 * Evict a stale RE from an older tracker and collapse that tracker.
 */
static void zebra_nhg_tracker_decount_stale_re(struct tracker_prefix_map_head *prefix_map,
					       struct nhg_event_tracker *tracker,
					       struct tracker_prefix_map_entry *old_entry,
					       struct route_node *rn)
{
	struct nhg_event_tracker *old_tracker = old_entry->tracker;
	struct route_node *old_rn;

	old_rn = route_node_lookup(old_tracker->matched_table.matched_table, &rn->p);
	if (old_rn) {
		if (old_tracker->matched_table.re_count > 0)
			old_tracker->matched_table.re_count--;
		route_unlock_node(old_rn);
	} else {
		old_rn = route_node_lookup(old_tracker->unmatched_table.unmatched_table, &rn->p);
		if (old_rn) {
			if (old_tracker->unmatched_table.re_count > 0)
				old_tracker->unmatched_table.re_count--;
			route_unlock_node(old_rn);
		}
	}

	zlog_info("%s: stale RE for %pRN in tracker %u (matched=%u unmatched=%u), collapsing into tracker %u",
		  __func__, rn, old_tracker->nhg_tracker_id, old_tracker->matched_table.re_count,
		  old_tracker->unmatched_table.re_count, tracker->nhg_tracker_id);

	old_entry->tracker = tracker;

	zebra_nhg_tracker_collapse(prefix_map, old_tracker, tracker);
}

/*
 * Add a RIB route_node to a tracker table (matched or unmatched)
 * and update the prefix_map.
 * If the prefix is new, sets trn->info = rn and increments re_count.
 * If the prefix already exists, releases the get-lock (no re_count change).
 * Uses prefix_map to ensure each prefix is owned by exactly one tracker.
 */
void zebra_nhg_tracker_rn_add(struct route_table *tracker_table, uint32_t *re_count,
			      struct tracker_prefix_map_head *prefix_map,
			      struct nhg_event_tracker *tracker, struct route_node *rn,
			      struct route_entry *re)
{
	struct route_node *trn;

	trn = route_node_get(tracker_table, &rn->p);
	if (!trn->info) {
		trn->info = rn;
		route_lock_node(rn);
		(*re_count)++;
		zlog_info("%s: added %pRN (type %s) to tracker %u, re_count=%u", __func__, rn,
			  zebra_route_string(re->type), tracker->nhg_tracker_id, *re_count);
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

		entry = tracker_prefix_map_find(prefix_map, &lookup_key);
		if (!entry) {
			entry = XCALLOC(MTYPE_NHG_TRACKER_PREFIX_MAP, sizeof(*entry));
			prefix_copy(&entry->p, &rn->p);
			entry->type = re->type;
			entry->instance = re->instance;
			entry->tracker = tracker;
			tracker_prefix_map_add(prefix_map, entry);
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
					struct route_table *tracker_table, uint32_t *re_count,
					struct route_node *rn, struct route_entry *re)
{
	struct tracker_prefix_map_entry lookup_key;
	struct tracker_prefix_map_entry *old_entry;

	memset(&lookup_key, 0, sizeof(lookup_key));
	prefix_copy(&lookup_key.p, &rn->p);
	lookup_key.type = re->type;
	lookup_key.instance = re->instance;

	old_entry = tracker_prefix_map_find(prefix_map, &lookup_key);
	if (old_entry && old_entry->tracker != tracker)
		zebra_nhg_tracker_decount_stale_re(prefix_map, tracker, old_entry, rn);

	zebra_nhg_tracker_rn_add(tracker_table, re_count, prefix_map, tracker, rn, re);
}

/*
 * Park an RE in the appropriate tracker instead of queuing it
 * for best-path selection.  Called from rib_link when the RE's
 * NHG has active trackers.
 */
struct nhg_event_tracker *zebra_nhg_tracker_park_re(struct route_node *rn, struct route_entry *re)
{
	struct nhg_event_tracker *tracker;
	struct tracker_prefix_map_head *prefix_map = &re->nhe->tracker_prefix_map;
	bool matched = false;

	frr_rev_each (nhg_event_tracker_list, &re->nhe->tracker_list, tracker) {
		if (zebra_nhg_nexthop_compare(re->nhe->nhg.nexthop,
					      tracker->nhg_tracker_snapshot->nhg.nexthop, rn)) {
			zlog_info("%s: %pRN (type %s) matched tracker %u for NHG %u (matched=%u unmatched=%u)",
				  __func__, rn, zebra_route_string(re->type),
				  tracker->nhg_tracker_id, re->nhe->id,
				  tracker->matched_table.re_count,
				  tracker->unmatched_table.re_count);
			zebra_nhg_tracker_add_route(prefix_map, tracker,
						    tracker->matched_table.matched_table,
						    &tracker->matched_table.re_count, rn, re);
			matched = true;
			break;
		}
	}

	if (!matched) {
		tracker = nhg_event_tracker_list_first(&re->nhe->tracker_list);
		if (tracker) {
			zlog_info("%s: %pRN (type %s) unmatched, parking in tracker %u for NHG %u (matched=%u unmatched=%u)",
				  __func__, rn, zebra_route_string(re->type),
				  tracker->nhg_tracker_id, re->nhe->id,
				  tracker->matched_table.re_count,
				  tracker->unmatched_table.re_count);
			zebra_nhg_tracker_add_route(prefix_map, tracker,
						    tracker->unmatched_table.unmatched_table,
						    &tracker->unmatched_table.re_count, rn, re);
		}
	}

	SET_FLAG(re->status, ROUTE_ENTRY_TRACKER);

	return tracker;
}

/*
 * If all REs that reference this NHG have been parked in the tracker,
 * queue every parked RN for best-path selection and free the tracker.
 */
void zebra_nhg_tracker_flush_if_full(struct nhg_event_tracker *tracker, struct nhg_hash_entry *nhe)
{
	struct route_node *trn;

	if (!tracker)
		return;

	if ((tracker->matched_table.re_count + tracker->unmatched_table.re_count) !=
	    nhe_re_tree_count(&nhe->re_head))
		return;

	zlog_info("%s: tracker %u for NHG %u is full (matched=%u unmatched=%u total_re=%zu), flushing",
		  __func__, tracker->nhg_tracker_id, nhe->id, tracker->matched_table.re_count,
		  tracker->unmatched_table.re_count, nhe_re_tree_count(&nhe->re_head));

	for (trn = route_top(tracker->matched_table.matched_table); trn; trn = route_next(trn)) {
		if (trn->info) {
			struct route_node *rn = trn->info;
			struct route_entry *re;

			RNODE_FOREACH_RE (rn, re)
				UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);
			rib_queue_add(rn);
		}
	}

	/*
	 * unmatched routes should probably belong to different NHGs -
	 * not sure how to implement that
	 * decide which NHGs to create and create them
	 * rewire re->nhe to point at them
	 */
	for (trn = route_top(tracker->unmatched_table.unmatched_table); trn;
	     trn = route_next(trn)) {
		if (trn->info) {
			struct route_node *rn = trn->info;
			struct route_entry *re;

			RNODE_FOREACH_RE (rn, re)
				UNSET_FLAG(re->status, ROUTE_ENTRY_TRACKER);
			rib_queue_add(rn);
		}
	}

	zebra_nhg_tracker_free(nhe, tracker);
}

/* Timer callback - handle REs from matched/unmatched tables */
static void nhg_tracker_timer_expiry(struct event *event)
{
	struct nhg_event_tracker *tracker = EVENT_ARG(event);

	zlog_info("%s: tracker %u (parent NHG %u ifindex %u event %s): timer expired", __func__,
		  tracker->nhg_tracker_id, tracker->parent_nhe ? tracker->parent_nhe->id : 0,
		  tracker->ifindex, tracker->event == NHG_TRACKER_EVENT_INTF_UP ? "UP" : "DOWN");

	/* TODO: add completion logic before freeing */

	zebra_nhg_tracker_free(tracker->parent_nhe, tracker);
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

		while ((entry = tracker_prefix_map_pop(
				&nhe->tracker_prefix_map)) != NULL)
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

	memset(&key, 0, sizeof(key));
	key.nhg_tracker_snapshot = snapshot;

	return nhg_event_tracker_hash_find(&nhe->tracker_hash, &key);
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

	for (t = nhg_event_tracker_list_first(&nhe->tracker_list); t; t = next) {
		next = nhg_event_tracker_list_next(&nhe->tracker_list, t);

		if (t == keeper)
			continue;

		zlog_info("%s: NHG %u loop: collapsing old tracker %u (matched=%u unmatched=%u) into keeper %u (matched=%u unmatched=%u)",
			  __func__, nhe->id, t->nhg_tracker_id, t->matched_table.re_count,
			  t->unmatched_table.re_count, keeper->nhg_tracker_id,
			  keeper->matched_table.re_count, keeper->unmatched_table.re_count);

		zebra_nhg_tracker_collapse(prefix_map, t, keeper);
	}
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
	struct nhg_hash_entry *snapshot;

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

	tracker->matched_table.matched_table = route_table_init();
	tracker->matched_table.re_count = 0;

	tracker->unmatched_table.unmatched_table = route_table_init();
	tracker->unmatched_table.re_count = 0;

	nhg_event_tracker_list_add_head(&nhe->tracker_list, tracker);
	nhg_event_tracker_hash_add(&nhe->tracker_hash, tracker);

	event_add_timer(zrouter.master, nhg_tracker_timer_expiry, tracker,
			NHG_TRACKER_DEFAULT_TIMEOUT_SEC, &tracker->timer);

	zlog_info("%s: NHG %u created tracker %u (event=%s ifindex=%u) total trackers=%zu",
		  __func__, nhe->id, tracker->nhg_tracker_id,
		  event == NHG_TRACKER_EVENT_INTF_UP ? "UP" : "DOWN", ifindex,
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
	nhg_event_tracker_hash_del(&nhe->tracker_hash, tracker);
	nhg_event_tracker_list_del(&nhe->tracker_list, tracker);

	if (nhg_event_tracker_list_count(&nhe->tracker_list) == 0)
		zlog_info("%s: NHG %u last tracker %u freed, no active trackers remain", __func__,
			  nhe->id, tracker->nhg_tracker_id);

	event_cancel(&tracker->timer);

	/* Clean up any prefix_map entries that still point to this
	 * tracker.  Iterates over all entries in the per-NHG
	 * tracker_prefix_map hash.  For each entry whose tracker
	 * pointer matches the tracker being freed, removes it
	 * from the hash and frees its memory.
	 */
	{
		struct tracker_prefix_map_entry *entry;

		frr_each_safe (tracker_prefix_map, &nhe->tracker_prefix_map,
			       entry) {
			if (entry->tracker == tracker) {
				tracker_prefix_map_del(
					&nhe->tracker_prefix_map, entry);
				XFREE(MTYPE_NHG_TRACKER_PREFIX_MAP, entry);
			}
		}
	}

	if (tracker->matched_table.matched_table) {
		struct route_node *trn;

		for (trn = route_top(tracker->matched_table.matched_table); trn;
		     trn = route_next(trn)) {
			if (trn->info) {
				route_unlock_node(trn->info);
				trn->info = NULL;
				route_unlock_node(trn);
			}
		}
		route_table_finish(tracker->matched_table.matched_table);
		tracker->matched_table.matched_table = NULL;
	}

	if (tracker->unmatched_table.unmatched_table) {
		struct route_node *trn;

		for (trn = route_top(tracker->unmatched_table.unmatched_table); trn;
		     trn = route_next(trn)) {
			if (trn->info) {
				route_unlock_node(trn->info);
				trn->info = NULL;
				route_unlock_node(trn);
			}
		}
		route_table_finish(tracker->unmatched_table.unmatched_table);
		tracker->unmatched_table.unmatched_table = NULL;
	}

	if (tracker->nhg_tracker_snapshot) {
		zebra_nhg_free(tracker->nhg_tracker_snapshot);
		tracker->nhg_tracker_snapshot = NULL;
	}

	tracker->parent_nhe = NULL;

	XFREE(MTYPE_NHG_TRACKER, tracker);
}
