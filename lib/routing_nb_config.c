/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
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

#include "northbound.h"
#include "libfrr.h"
#include "vrf.h"
#include "lib_errors.h"
#include "routing_nb.h"


DEFINE_HOOK(routing_conf_event, (struct nb_cb_create_args *args), (args))

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol
 */

int routing_control_plane_protocols_control_plane_protocol_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	const char *vrfname;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (hook_call(routing_conf_event, args))
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrfname = yang_dnode_get_string(args->dnode, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		vrf = vrf ? vrf : vrf_get(VRF_UNKNOWN, vrfname);
		if (!vrf) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "vrf creation %s failed", vrfname);
			return NB_ERR;
		}
		nb_running_set_entry(args->dnode, vrf);
		break;
	};

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf __attribute__((unused));

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_unset_entry(args->dnode);

	return NB_OK;
}
