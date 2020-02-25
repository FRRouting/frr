/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "routemap.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/*
 * XPath: /frr-ripd:clear-rip-route
 */
static void clear_rip_route(struct rip *rip)
{
	struct route_node *rp;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("Clearing all RIP routes (VRF %s)", rip->vrf_name);

	/* Clear received RIP routes */
	for (rp = route_top(rip->table); rp; rp = route_next(rp)) {
		struct list *list;
		struct listnode *listnode;
		struct rip_info *rinfo;

		list = rp->info;
		if (!list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			if (!rip_route_rte(rinfo))
				continue;

			if (CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
				rip_zebra_ipv4_delete(rip, rp);
			break;
		}

		if (rinfo) {
			RIP_TIMER_OFF(rinfo->t_timeout);
			RIP_TIMER_OFF(rinfo->t_garbage_collect);
			listnode_delete(list, rinfo);
			rip_info_free(rinfo);
		}

		if (list_isempty(list)) {
			list_delete(&list);
			rp->info = NULL;
			route_unlock_node(rp);
		}
	}
}

int clear_rip_route_rpc(const char *xpath, const struct list *input,
			struct list *output)
{
	struct rip *rip;
	struct yang_data *yang_vrf;

	yang_vrf = yang_data_list_find(input, "%s/%s", xpath, "input/vrf");
	if (yang_vrf) {
		rip = rip_lookup_by_vrf_name(yang_vrf->value);
		if (rip)
			clear_rip_route(rip);
	} else {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			rip = vrf->info;
			if (!rip)
				continue;

			clear_rip_route(rip);
		}
	}

	return NB_OK;
}
