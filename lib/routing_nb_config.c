// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "vrf.h"
#include "lib_errors.h"
#include "routing_nb.h"


DEFINE_HOOK(routing_conf_event, (struct nb_cb_create_args *args), (args));
DEFINE_HOOK(routing_create, (struct nb_cb_create_args *args), (args));
DEFINE_KOOH(routing_destroy, (struct nb_cb_destroy_args *args), (args));

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
		/*
		 * If the daemon relies on the VRF pointer stored in this
		 * dnode, then it should register the dependency between this
		 * module and the VRF module using
		 * routing_control_plane_protocols_register_vrf_dependency.
		 * If such dependency is not registered, then nothing is
		 * stored in the dnode. If the dependency is registered,
		 * find the vrf and store the pointer.
		 */
		if (nb_node_has_dependency(args->dnode->schema->priv)) {
			vrfname = yang_dnode_get_string(args->dnode, "vrf");
			vrf = vrf_lookup_by_name(vrfname);
			assert(vrf);
			nb_running_set_entry(args->dnode, vrf);
		}
		hook_call(routing_create, args);
		break;
	};

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(routing_destroy, args);

	/*
	 * If dependency on VRF module is registered, then VRF
	 * pointer was stored and must be cleared.
	 */
	if (nb_node_has_dependency(args->dnode->schema->priv))
		nb_running_unset_entry(args->dnode);

	return NB_OK;
}

static void vrf_to_control_plane_protocol(const struct lyd_node *dnode,
					  char *xpath)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "name");

	snprintf(xpath, XPATH_MAXLEN, FRR_ROUTING_KEY_XPATH_VRF, vrf);
}

static void control_plane_protocol_to_vrf(const struct lyd_node *dnode,
					  char *xpath)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "vrf");

	snprintf(xpath, XPATH_MAXLEN, FRR_VRF_KEY_XPATH, vrf);
}

void routing_control_plane_protocols_register_vrf_dependency(void)
{
	struct nb_dependency_callbacks cbs;

	cbs.get_dependant_xpath = vrf_to_control_plane_protocol;
	cbs.get_dependency_xpath = control_plane_protocol_to_vrf;

	nb_node_set_dependency_cbs(FRR_VRF_XPATH, FRR_ROUTING_XPATH, &cbs);
}
