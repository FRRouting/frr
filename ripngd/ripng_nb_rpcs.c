/*
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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
#include "agg_table.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"
#include "ripngd/ripng_debug.h"
#include "ripngd/ripng_route.h"

/*
 * XPath: /frr-ripngd:clear-ripng-route
 */
static void clear_ripng_route(struct ripng *ripng)
{
	struct agg_node *rp;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("Clearing all RIPng routes (VRF %s)",
			   ripng->vrf_name);

	/* Clear received RIPng routes */
	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		struct list *list;
		struct listnode *listnode;
		struct ripng_info *rinfo;

		list = rp->info;
		if (list == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			if (!ripng_route_rte(rinfo))
				continue;

			if (CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
				ripng_zebra_ipv6_delete(ripng, rp);
			break;
		}

		if (rinfo) {
			RIPNG_TIMER_OFF(rinfo->t_timeout);
			RIPNG_TIMER_OFF(rinfo->t_garbage_collect);
			listnode_delete(list, rinfo);
			ripng_info_free(rinfo);
		}

		if (list_isempty(list)) {
			list_delete(&list);
			rp->info = NULL;
			agg_unlock_node(rp);
		}
	}
}

int clear_ripng_route_rpc(const char *xpath, const struct list *input,
			  struct list *output)
{
	struct ripng *ripng;
	struct yang_data *yang_vrf;

	yang_vrf = yang_data_list_find(input, "%s/%s", xpath, "input/vrf");
	if (yang_vrf) {
		ripng = ripng_lookup_by_vrf_name(yang_vrf->value);
		if (ripng)
			clear_ripng_route(ripng);
	} else {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			ripng = vrf->info;
			if (!ripng)
				continue;

			clear_ripng_route(ripng);
		}
	}

	return NB_OK;
}
