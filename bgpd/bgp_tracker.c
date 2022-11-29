/* BGP Tracker
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "memory.h"
#include "network.h"
#include "hook.h"
#include "linklist.h"
#include "tracker.h"

#include "bgpd.h"
#include "bgp_tracker.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_TRACKER, "BGP Tracker");


struct tracker *bgp_tracker_get(char *name)
{
	struct tracker *tracker;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bm->trackers, node, tracker)) {
		if (strncmp(name, tracker->name, sizeof(tracker->name)) == 0)
			return tracker;
	}

	return NULL;
}

struct tracker *bgp_tracker_new(char *name)
{
	struct tracker *tracker;

	tracker = bgp_tracker_get(name);
	if (tracker)
		return tracker;

	tracker = XCALLOC(MTYPE_BGP_TRACKER, sizeof(struct tracker));

	snprintf(tracker->name, sizeof(tracker->name), "%s", name);

	zlog_info("Tracker name %s inited", tracker->name);

	listnode_add(bm->trackers, tracker);

	return tracker;
}

static void _bgp_tracker_free(struct tracker *tracker)
{
	XFREE(MTYPE_BGP_TRACKER, tracker);
}

void bgp_tracker_free(char *name)
{
	struct tracker *tracker;

	tracker = bgp_tracker_get(name);

	if (!tracker)
		return;

	listnode_delete(bm->trackers, tracker);

	zlog_info("Tracker name %s deleted", tracker->name);

	bgp_route_map_tracker_event(tracker->name);

	_bgp_tracker_free(tracker);
}

void bgp_tracker_set(char *name, bool status)
{
	struct tracker *tracker;

	tracker = bgp_tracker_get(name);

	zlog_info("Tracker name %s set status to %s", tracker->name,
		  status ? "Up" : "Down");

	tracker->status = status;

	bgp_route_map_tracker_event(tracker->name);
}

void bgp_tracker_terminate()
{
	struct tracker *tracker;
	struct listnode *node, *nnode;

	if (!bm->trackers)
		return;

	for (ALL_LIST_ELEMENTS(bm->trackers, node, nnode, tracker)) {
		listnode_delete(bm->trackers, tracker);
		_bgp_tracker_free(tracker);
	}

	list_delete(&bm->trackers);
}

void bgp_tracker_init()
{
	bm->trackers = list_new();
}
