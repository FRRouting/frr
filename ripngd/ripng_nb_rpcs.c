// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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
			EVENT_OFF(rinfo->t_timeout);
			EVENT_OFF(rinfo->t_garbage_collect);
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

int clear_ripng_route_rpc(struct nb_cb_rpc_args *args)
{
	struct ripng *ripng;

	if (args->input && yang_dnode_exists(args->input, "vrf")) {
		const char *name = yang_dnode_get_string(args->input, "vrf");

		ripng = ripng_lookup_by_vrf_name(name);
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
