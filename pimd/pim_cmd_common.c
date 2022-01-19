/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "plist.h"
#include "hash.h"
#include "nexthop.h"
#include "vrf.h"
#include "ferr.h"

#include "pimd.h"
#include "pim_vty.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"
#include "pim_cmd_common.h"

/**
 * Get current node VRF name.
 *
 * NOTE:
 * In case of failure it will print error message to user.
 *
 * \returns name or NULL if failed to get VRF.
 */
const char *pim_cli_get_vrf_name(struct vty *vty)
{
	const struct lyd_node *vrf_node;

	/* Not inside any VRF context. */
	if (vty->xpath_index == 0)
		return VRF_DEFAULT_NAME;

	vrf_node = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (vrf_node == NULL) {
		vty_out(vty, "%% Failed to get vrf dnode in configuration\n");
		return NULL;
	}

	return yang_dnode_get_string(vrf_node, "./name");
}

int pim_process_join_prune_cmd(struct vty *vty, const char *jpi_str)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/join-prune-interval", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, jpi_str);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_join_prune_cmd(struct vty *vty)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/join-prune-interval", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}
