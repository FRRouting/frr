// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound configuration callbacks.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_nb.h"

/*
 * Look up the OSPF instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
 *
 * mgmtd's predicate-aware dispatch (mgmt_be_xpath_prefix) routes only
 * control-plane-protocol[type='ietf-ospf:ospfv2'] entries to ospfd, so
 * the type check is handled at the dispatch layer and not repeated here.
 *
 * Returns NULL when no FRR-side OSPF instance exists for the named
 * control-plane-protocol; the caller should treat the configuration as a
 * no-op until the instance is created (today: via `router ospf`).
 */
static struct ospf *ospfd_ietf_ospf_instance_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *cpp;
	const char *name;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (!cpp)
		return NULL;

	name = yang_dnode_get_string(cpp, "name");
	return ospfd_ietf_ospf_lookup_instance(name);
}

/*
 * Resolve the OSPF instance for create / modify callbacks. Per-leaf callbacks
 * route through this so mgmtd cannot accept a commit whose APPLY phase would
 * be a silent no-op.
 *
 * Returns:
 *   NB_OK + *ospf_out set      -- proceed.
 *   NB_OK + *ospf_out == NULL  -- APPLY-phase race tolerated (the instance
 *                                 vanished between VALIDATE and APPLY).
 *                                 Caller should bail out cleanly.
 *   NB_ERR_INCONSISTENCY       -- VALIDATE rejected the commit.
 */
static int ospfd_ietf_ospf_resolve_instance(const struct lyd_node *dnode, enum nb_event event,
					    char *errmsg, size_t errmsg_len, struct ospf **ospf_out)
{
	struct ospf *ospf;

	ospf = ospfd_ietf_ospf_instance_from_dnode(dnode);
	*ospf_out = ospf;
	if (ospf)
		return NB_OK;

	if (event == NB_EV_VALIDATE) {
		const struct lyd_node *cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");

		snprintf(errmsg, errmsg_len,
			 "OSPF instance '%s' is not configured (use 'router ospf' first)",
			 cpp ? yang_dnode_get_string(cpp, "name") : "?");
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
}


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/explicit-router-id
 */
int ospfd_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr router_id;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	ospf->router_id_static = router_id;
	ospf_router_id_update(ospf);

	return NB_OK;
}

int ospfd_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;

	ospf->router_id_static.s_addr = INADDR_ANY;
	ospf_router_id_update(ospf);

	return NB_OK;
}
