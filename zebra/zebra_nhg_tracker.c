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

/* Timer callback - handle REs from matched/unmatched tables */
static void nhg_tracker_timer_expiry(struct event *event)
{
	struct nhg_event_tracker *tracker = EVENT_ARG(event);

	zlog_info("NHG tracker %u (parent NHG %u ifindex %u event %s): timer expired",
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
		zlog_info("NHG tracker: duplicate state for NHG %u, reusing tracker %u", nhe->id,
			  existing->nhg_tracker_id);
		// todo: consolidate the things here?
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

	return tracker;
}

/*
 * Cleanup a tracker
 */
void zebra_nhg_tracker_free(struct nhg_hash_entry *nhe, struct nhg_event_tracker *tracker)
{
	nhg_event_tracker_hash_del(&nhe->tracker_hash, tracker);
	nhg_event_tracker_list_del(&nhe->tracker_list, tracker);

	if (nhg_event_tracker_list_count(&nhe->tracker_list) == 0)
		zlog_info("NHG %u: last tracker %u freed, no active trackers remain", nhe->id,
			  tracker->nhg_tracker_id);

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
		route_table_finish(tracker->matched_table.matched_table);
		tracker->matched_table.matched_table = NULL;
	}

	if (tracker->unmatched_table.unmatched_table) {
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
