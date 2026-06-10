// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound RPC handlers (RFC 9129 ietf-ospf).
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "northbound.h"
#include "vrf.h"
#include "yang.h"

#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6_nb.h"

/*
 * XPath: /ietf-ospf:clear-neighbor
 *
 * Reset OSPFv3 neighbors on the named instance.  Optional `interface` narrows
 * the reset to one OSPFv3-running interface; without it, every interface
 * bound to the instance is cleared.  ospfd registers the same RPC xpath;
 * mgmtd fans out to both backends, so if the named instance doesn't belong
 * to this daemon we return NB_OK silently.
 */
int ospf6d_ietf_ospf_clear_neighbor_rpc(struct nb_cb_rpc_args *args)
{
	const char *name;
	const char *ifname = NULL;
	struct ospf6 *ospf6;
	struct vrf *vrf;
	struct interface *ifp;

	if (!args->input || !yang_dnode_exists(args->input, "routing-protocol-name"))
		return NB_OK;

	name = yang_dnode_get_string(args->input, "routing-protocol-name");
	ospf6 = ospf6d_ietf_ospf_lookup_instance(name);
	if (!ospf6)
		return NB_OK;

	vrf = vrf_lookup_by_id(ospf6->vrf_id);
	if (!vrf)
		return NB_OK;

	if (yang_dnode_exists(args->input, "interface"))
		ifname = yang_dnode_get_string(args->input, "interface");

	if (ifname) {
		ifp = if_lookup_by_name_vrf(ifname, vrf);
		if (!ifp || !ifp->info) {
			/* See ospfd's matching handler for the NB_ERR_NOT_
			 * FOUND vs NB_ERR_RESOURCE choice; same rationale.
			 */
			snprintf(args->errmsg, args->errmsg_len, "ospf-interface-not-found: %s",
				 ifname);
			return NB_ERR_NOT_FOUND;
		}
		ospf6_interface_clear(ifp);
		return NB_OK;
	}

	FOR_ALL_INTERFACES (vrf, ifp)
		if (ifp->info)
			ospf6_interface_clear(ifp);
	return NB_OK;
}

/*
 * XPath: /ietf-ospf:clear-database
 *
 * Force every OSPFv3 neighbor adjacency on the named instance down and
 * reoriginate self-originated LSAs.  `ospf6_process_reset` is the helper the
 * legacy `clear ipv6 ospf6 process` command uses.
 */
int ospf6d_ietf_ospf_clear_database_rpc(struct nb_cb_rpc_args *args)
{
	const char *name;
	struct ospf6 *ospf6;

	if (!args->input || !yang_dnode_exists(args->input, "routing-protocol-name"))
		return NB_OK;

	name = yang_dnode_get_string(args->input, "routing-protocol-name");
	ospf6 = ospf6d_ietf_ospf_lookup_instance(name);
	if (!ospf6)
		return NB_OK;

	ospf6_router_id_update(ospf6, true);
	ospf6_process_reset(ospf6);
	return NB_OK;
}
