/*
 * PBR-event Header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __PBR_EVENT_H__
#define __PBR_EVENT_H__

enum pbr_events {
	/*
	 * A NHG has been added to the system, handle it
	 */
	PBR_NHG_NEW,

	/*
	 * A NHG has been modified( added a new nexthop )
	 */
	PBR_NHG_ADD_NEXTHOP,

	/*
	 * A NHG has been modified( deleted a nexthop )
	 */
	PBR_NHG_DEL_NEXTHOP,

	/*
	 * A NHG has been deleted from the system
	 */
	PBR_NHG_DELETE,

	/*
	 * A individual nexthop has been added
	 */
	PBR_MAP_NEXTHOP_ADD,

	/*
	 * A individual nexthop has been deleted
	 */
	PBR_MAP_NEXTHOP_DELETE,

	/*
	 * A nexthop group has been added to a pbr-map
	 */
	PBR_MAP_NHG_ADD,

	/*
	 * A nexthop group has been deleted from a pbr-map
	 */
	PBR_MAP_NHG_DELETE,

	/*
	 * A new pbr-map has been created
	 */
	PBR_MAP_ADD,

	/*
	 * The pbr-map has been modified in some fashion
	 */
	PBR_MAP_MODIFY,

	/*
	 * The pbr-map has been deleted from the system
	 */
	PBR_MAP_DELETE,

	/*
	 * Start the sequence of events to install/remove the policy
	 * from being installed
	 */
	PBR_MAP_INSTALL,

	/*
	 * We believe we have gotten enough information to actually
	 * install the rule portion, since the nexthops are installed
	 */
	PBR_MAP_POLICY_INSTALL,

	/*
	 * Callbacks for a Nexthop in a nexthop group has been
	 * changed in some fashion
	 */
	PBR_NH_CHANGED,

	/*
	 * Callback for when a policy has been applied to an interface
	 */
	PBR_POLICY_CHANGED,

	/*
	 * Callback for when a interface has been issued a no
	 * policy command
	 */
	PBR_POLICY_DELETED,
};

struct pbr_event {
	enum pbr_events event;

	char name[100];
	union g_addr addr;
	uint32_t seqno;
};

/*
 * Return a event structure that can be filled in and enqueued.
 * Assume this memory is owned by the event subsystem.
 */
extern struct pbr_event *pbr_event_new(enum pbr_events ev, const char *name);

/*
 * Free the associated pbr_event item
 */
extern void pbr_event_free(struct pbr_event **pbre);

/*
 * Enqueue an event for later processing
 */
void pbr_event_enqueue(struct pbr_event *pbre);

extern void pbr_event_init(void);
extern void pbr_event_stop(void);
#endif
