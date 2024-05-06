// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
			EVENT_OFF(rinfo->t_timeout);
			EVENT_OFF(rinfo->t_garbage_collect);
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

int clear_rip_route_rpc(struct nb_cb_rpc_args *args)
{
	struct rip *rip;

	if (args->input && yang_dnode_exists(args->input, "vrf")) {
		const char *name = yang_dnode_get_string(args->input, "vrf");

		rip = rip_lookup_by_vrf_name(name);
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
