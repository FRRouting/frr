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

#include "lib/event.h"
#include "lib/table.h"
#include "lib/typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nhg_hash_entry;

#define NHG_TRACKER_DEFAULT_TIMEOUT_SEC 300

enum nhg_tracker_event_intf {
	NHG_TRACKER_EVENT_INTF_DOWN = 0,
	NHG_TRACKER_EVENT_INTF_UP,
};

PREDECL_DLIST(nhg_event_tracker_list);
PREDECL_HASH(nhg_event_tracker_hash);

/* Matched/unmatched route table wrappers */
struct nhg_tracker_matched_table {
	struct route_table *matched_table;
	uint32_t re_count;
};

struct nhg_tracker_unmatched_table {
	struct route_table *unmatched_table;
	uint32_t re_count;
};

struct nhg_event_tracker {
	uint32_t nhg_tracker_id;

	struct nhg_event_tracker_list_item list_entry;
	struct nhg_event_tracker_hash_item tracker_hash_link;

	/* Prefixes whose nexthops match nhg_tracker_snapshot */
	struct nhg_tracker_matched_table matched_table;

	/* Prefixes whose nexthops do NOT match nhg_tracker_snapshot */
	struct nhg_tracker_unmatched_table unmatched_table;

	/* Started on tracker creation and fires after NHG_TRACKER_DEFAULT_TIMEOUT_SEC */
	struct event *timer;

	/* Back-pointer to the original NHG that this tracker is managing. */
	struct nhg_hash_entry *parent_nhe;

	/* Snapshot of the original NHG at the time of tracker creation. */
	struct nhg_hash_entry *nhg_tracker_snapshot;

	/* Index of the interface whose state change created this tracker. */
	ifindex_t ifindex;
	enum nhg_tracker_event_intf event;
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

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NHG_TRACKER_H__ */
