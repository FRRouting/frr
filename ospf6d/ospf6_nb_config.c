// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound configuration callbacks.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospf6_top.h"
#include "ospf6_nb.h"

/*
 * Look up the OSPFv3 instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
 *
 * mgmtd's predicate-aware dispatch (mgmt_be_xpath_prefix) routes only
 * control-plane-protocol[type='ietf-ospf:ospfv3'] entries to ospf6d, so
 * the type check is handled at the dispatch layer and not repeated here.
 *
 * Returns NULL when no FRR-side OSPFv3 instance exists for the named
 * control-plane-protocol; the caller should treat the configuration as a
 * no-op until the instance is created (today: via `router ospf6`).
 */
static struct ospf6 *ospf6d_ietf_ospf_instance_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *cpp;
	const char *name;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (!cpp)
		return NULL;

	name = yang_dnode_get_string(cpp, "name");
	return ospf6d_ietf_ospf_lookup_instance(name);
}

/*
 * Resolve the OSPFv3 instance for create / modify callbacks. See the OSPFv2
 * equivalent in ospfd/ospf_nb_config.c for the rationale; APPLY-phase
 * tolerance preserves commit progress if the instance is torn down
 * mid-transaction. Returns NB_OK + *ospf6_out set on success, NB_OK + NULL
 * for the APPLY-race case, NB_ERR_INCONSISTENCY when VALIDATE rejects.
 */
static int ospf6d_ietf_ospf_resolve_instance(const struct lyd_node *dnode, enum nb_event event,
					     char *errmsg, size_t errmsg_len,
					     struct ospf6 **ospf6_out)
{
	struct ospf6 *ospf6;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(dnode);
	*ospf6_out = ospf6;
	if (ospf6)
		return NB_OK;

	if (event == NB_EV_VALIDATE) {
		const struct lyd_node *cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");

		snprintf(errmsg, errmsg_len,
			 "OSPFv3 instance '%s' is not configured (use 'router ospf6' first)",
			 cpp ? yang_dnode_get_string(cpp, "name") : "?");
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
}


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/explicit-router-id
 */
int ospf6d_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct in_addr router_id;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	/* ospf6d stores router IDs as network-byte-order uint32_t values. */
	ospf6->router_id_static = router_id.s_addr;

	if (ospf6_router_id_update(ospf6, false))
		ospf6_process_reset(ospf6);

	return NB_OK;
}

int ospf6d_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;

	ospf6->router_id_static = 0;

	if (ospf6_router_id_update(ospf6, false))
		ospf6_process_reset(ospf6);

	return NB_OK;
}
