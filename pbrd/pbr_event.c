/*
 * PBR-event Code
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
#include <zebra.h>

#include <thread.h>
#include <workqueue.h>
#include <nexthop.h>
#include <log.h>
#include <vty.h>

#include "pbrd/pbr_event.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_memory.h"
#include "pbrd/pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_EVENT, "Event WorkQueue")

struct work_queue *pbr_event_wq;

static const char *pbr_event_wqentry2str(struct pbr_event *pbre,
					 char *buffer, size_t buflen)
{
	switch(pbre->event) {
	case PBR_NHG_NEW:
		snprintf(buffer, buflen, "Nexthop Group Added %s",
			 pbre->name);
		break;
	case PBR_NHG_ADD_NEXTHOP:
		snprintf(buffer, buflen, "Nexthop Group Nexthop Added %s",
			 pbre->name);
		break;
	case PBR_NHG_DEL_NEXTHOP:
		snprintf(buffer, buflen, "Nexthop Group Nexthop Deleted %s",
			 pbre->name);
		break;
	case PBR_NHG_DELETE:
		snprintf(buffer, buflen, "Nexthop Group Deleted %s",
			 pbre->name);
		break;
	case PBR_MAP_NEXTHOP_ADD:
		snprintf(buffer, buflen, "Nexthop Added to %s(%d)", pbre->name,
			 pbre->seqno);
		break;
	case PBR_MAP_NEXTHOP_DELETE:
		snprintf(buffer, buflen, "Nexthop Deleted from %s(%d)",
			 pbre->name, pbre->seqno);
		break;
	case PBR_MAP_NHG_ADD:
		snprintf(buffer, buflen, "Nexthop Group Added to %s(%d)",
			 pbre->name, pbre->seqno);
		break;
	case PBR_MAP_NHG_DELETE:
		snprintf(buffer, buflen, "Nexthop Group Deleted from %s(%d)",
			 pbre->name, pbre->seqno);
		break;
	case PBR_MAP_ADD:
		snprintf(buffer, buflen, "PBR-MAP %s Added",
			 pbre->name);
		break;
	case PBR_MAP_MODIFY:
		snprintf(buffer, buflen, "PBR_MAP %s Modified",
			 pbre->name);
		break;
	case PBR_MAP_DELETE:
		snprintf(buffer, buflen, "PBR_MAP %s Deleted",
			 pbre->name);
		break;
	case PBR_NH_CHANGED:
		snprintf(buffer, buflen, "Nexthop Call back from Zebra");
		break;
	case PBR_MAP_INSTALL:
		snprintf(buffer, buflen, "PBR_MAP %s Installing into zapi",
			 pbre->name);
		break;
	case PBR_POLICY_CHANGED:
		snprintf(buffer, buflen,
			 "PBR-Policy %s applied to an interface", pbre->name);
		break;
	case PBR_MAP_POLICY_INSTALL:
		snprintf(buffer, buflen, "PBR-POLICY installation time for %s",
			 pbre->name);
		break;
	case PBR_POLICY_DELETED:
		snprintf(buffer, buflen, "PBR-POLICY deleted from %s",
			 pbre->name);
		break;
	}

	return buffer;
}

void pbr_event_free(struct pbr_event **pbre)
{
	XFREE(MTYPE_PBR_EVENT, *pbre);
}

static void pbr_event_delete_wq(struct work_queue *wq, void *data)
{
	struct pbr_event *pbre = (struct pbr_event *)data;

	XFREE(MTYPE_PBR_EVENT, pbre);
}

static wq_item_status pbr_event_process_wq(struct work_queue *wq, void *data)
{
	struct pbr_event *pbre = (struct pbr_event *)data;
	char buffer[256];

	DEBUGD(&pbr_dbg_event, "%s: Handling event %s", __PRETTY_FUNCTION__,
	       pbr_event_wqentry2str(pbre, buffer, sizeof(buffer)));

	switch (pbre->event) {
	case PBR_NHG_NEW:
		pbr_nht_add_group(pbre->name);
		pbr_map_check_nh_group_change(pbre->name);
		break;
	case PBR_NHG_ADD_NEXTHOP:
		pbr_nht_change_group(pbre->name);
		pbr_map_check_nh_group_change(pbre->name);
		break;
	case PBR_NHG_DEL_NEXTHOP:
		pbr_nht_change_group(pbre->name);
		pbr_map_check_nh_group_change(pbre->name);
		break;
	case PBR_NHG_DELETE:
		pbr_nht_delete_group(pbre->name);
		pbr_map_check_nh_group_change(pbre->name);
		break;
	case PBR_MAP_NEXTHOP_ADD:
		pbr_nht_add_individual_nexthop(pbre->name, pbre->seqno);
		pbr_map_check(pbre->name, pbre->seqno);
		break;
	case PBR_MAP_NEXTHOP_DELETE:
		pbr_nht_delete_individual_nexthop(pbre->name, pbre->seqno);
		pbr_map_check(pbre->name, pbre->seqno);
		break;
	case PBR_MAP_NHG_ADD:
		pbr_map_check(pbre->name, pbre->seqno);
		break;
	case PBR_MAP_NHG_DELETE:
		pbr_map_check(pbre->name, pbre->seqno);
		break;
	case PBR_MAP_ADD:
		pbr_map_add_interfaces(pbre->name);
		break;
	case PBR_MAP_MODIFY:
		pbr_map_check(pbre->name, pbre->seqno);
		break;
	case PBR_MAP_DELETE:
		pbr_map_delete(pbre->name, pbre->seqno);
		break;
	case PBR_NH_CHANGED:
		pbr_map_check_nh_group_change(pbre->name);
		break;
	case PBR_MAP_INSTALL:
		pbr_map_install(pbre->name);
		break;
	case PBR_POLICY_CHANGED:
		pbr_map_check_policy_change(pbre->name);
		break;
	case PBR_MAP_POLICY_INSTALL:
		pbr_map_policy_install(pbre->name);
		break;
	case PBR_POLICY_DELETED:
		pbr_map_policy_delete(pbre->name);
		break;
	}

	return WQ_SUCCESS;
}

void pbr_event_enqueue(struct pbr_event *pbre)
{
	work_queue_add(pbr_event_wq, pbre);
}

struct pbr_event *pbr_event_new(enum pbr_events ev, const char *name)
{
	struct pbr_event *event;
	event = XCALLOC(MTYPE_PBR_EVENT, sizeof(struct pbr_event));
	event->event = ev;
	if (name)
		strlcpy(event->name, name, sizeof(event->name));
	return event;
}

extern struct thread_master *master;

void pbr_event_init(void)
{
	pbr_event_wq = work_queue_new(master, "PBR Main Work Queue");
	pbr_event_wq->spec.workfunc = &pbr_event_process_wq;
	pbr_event_wq->spec.del_item_data = &pbr_event_delete_wq;
}

void pbr_event_stop(void)
{
	work_queue_free_and_null(&pbr_event_wq);
}
