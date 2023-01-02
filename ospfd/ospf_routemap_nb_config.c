/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
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

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "ospf_routemap_nb.h"

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-ospf-route-map:metric-type
 */
int lib_route_map_entry_set_action_rmap_set_action_metric_type_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "metric-type";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(rhc->rhc_rmi, "metric-type", type,
			     args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_metric_type_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}
