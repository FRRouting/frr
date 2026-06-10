// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv2 northbound RPC handlers (RFC 9129 ietf-ospf).
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "northbound.h"
#include "vrf.h"
#include "yang.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospf_nb.h"

/*
 * Locate the ospf_interface for `ifname` inside `ospf`.  Returns NULL if the
 * interface is not currently bound to this OSPFv2 instance (which is also the
 * indicator the RPC must propagate as an `ospf-interface-not-found` failure
 * per RFC 9129).
 */
static struct ospf_interface *ospfd_ietf_lookup_oi(struct ospf *ospf, const char *ifname)
{
	struct listnode *node;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		if (oi->ifp && strcmp(oi->ifp->name, ifname) == 0)
			return oi;
	return NULL;
}

/*
 * XPath: /ietf-ospf:clear-neighbor
 *
 * Reset OSPFv2 neighbors on the named instance.  Optional `interface` input
 * narrows the reset to one OSPF interface.  This daemon handles only OSPFv2;
 * if the named instance isn't local (it may belong to ospf6d) return NB_OK
 * silently -- mgmtd fans the RPC out to every backend that registered the
 * xpath, so non-owners must not surface an error.
 */
int ospfd_ietf_ospf_clear_neighbor_rpc(struct nb_cb_rpc_args *args)
{
	const char *name;
	const char *ifname = NULL;
	struct ospf *ospf;
	struct ospf_interface *oi;

	if (!args->input || !yang_dnode_exists(args->input, "routing-protocol-name"))
		return NB_OK;

	name = yang_dnode_get_string(args->input, "routing-protocol-name");
	ospf = ospfd_ietf_ospf_lookup_instance(name);
	if (!ospf)
		return NB_OK;

	if (yang_dnode_exists(args->input, "interface"))
		ifname = yang_dnode_get_string(args->input, "interface");

	if (ifname) {
		oi = ospfd_ietf_lookup_oi(ospf, ifname);
		if (!oi) {
			/*
			 * RFC 9129 specifies error-tag `data-missing` plus
			 * error-app-tag `ospf-interface-not-found`.  FRR's
			 * nb_cb_rpc_args carries only an unstructured errmsg,
			 * so the app-tag string goes in the message and we
			 * pick NB_ERR_NOT_FOUND (mgmtd maps to
			 * MGMTD_INVALID_PARAM, the closest "client supplied
			 * a bad reference" signal); NB_ERR_RESOURCE would
			 * map to MGMTD_INTERNAL_ERROR which incorrectly
			 * implies a daemon-side failure.
			 */
			snprintf(args->errmsg, args->errmsg_len, "ospf-interface-not-found: %s",
				 ifname);
			return NB_ERR_NOT_FOUND;
		}
		ospf_interface_neighbor_reset(oi);
		return NB_OK;
	}

	if (ospf->oi_running) {
		struct in_addr any = { .s_addr = 0 };

		ospf_neighbor_reset(ospf, any, NULL);
	}
	return NB_OK;
}

/*
 * XPath: /ietf-ospf:clear-database
 *
 * Flush every neighbor adjacency on the named OSPFv2 instance and reoriginate
 * self-originated LSAs.  `ospf_process_reset` is exactly the helper the
 * legacy `clear ip ospf process` command uses.
 */
int ospfd_ietf_ospf_clear_database_rpc(struct nb_cb_rpc_args *args)
{
	const char *name;
	struct ospf *ospf;

	if (!args->input || !yang_dnode_exists(args->input, "routing-protocol-name"))
		return NB_OK;

	name = yang_dnode_get_string(args->input, "routing-protocol-name");
	ospf = ospfd_ietf_ospf_lookup_instance(name);
	if (!ospf)
		return NB_OK;

	if (ospf->oi_running)
		ospf_process_reset(ospf);
	return NB_OK;
}
