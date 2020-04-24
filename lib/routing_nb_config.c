#include "northbound.h"
#include "libfrr.h"
#include "vrf.h"
#include "routing_nb.h"


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol
 */
int routing_control_plane_protocols_control_plane_protocol_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct vrf *vrf;
	const char *vrfname;

	switch (event) {
	case NB_EV_VALIDATE:
		vrfname = yang_dnode_get_string(dnode, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf) {
			zlog_warn("vrf is not configured\n");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrfname = yang_dnode_get_string(dnode, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		nb_running_set_entry(dnode, vrf);
		break;
	};

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct vrf *vrf;

	if (event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_unset_entry(dnode);
	(void)vrf;
	return NB_OK;
}
