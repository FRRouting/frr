// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Route map northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"

/*
 * Auxiliary functions to avoid code duplication:
 *
 * lib_route_map_entry_set_destroy: unset `set` commands.
 * lib_route_map_entry_match_destroy: unset `match` commands.
 */
int lib_route_map_entry_match_destroy(struct nb_cb_destroy_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rhc = nb_running_get_entry(args->dnode, NULL, true);
	if (rhc->rhc_mhook == NULL)
		return NB_OK;

	rv = rhc->rhc_mhook(rhc->rhc_rmi, rhc->rhc_rule, NULL,
			    rhc->rhc_event,
			    args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

int lib_route_map_entry_set_destroy(struct nb_cb_destroy_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rhc = nb_running_get_entry(args->dnode, NULL, true);
	if (rhc->rhc_shook == NULL)
		return NB_OK;

	rv = rhc->rhc_shook(rhc->rhc_rmi, rhc->rhc_rule, NULL,
			    args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * Auxiliary hook context list manipulation functions.
 */
struct routemap_hook_context *
routemap_hook_context_insert(struct route_map_index *rmi)
{
	struct routemap_hook_context *rhc;

	rhc = XCALLOC(MTYPE_TMP, sizeof(*rhc));
	rhc->rhc_rmi = rmi;
	TAILQ_INSERT_TAIL(&rmi->rhclist, rhc, rhc_entry);

	return rhc;
}

void routemap_hook_context_free(struct routemap_hook_context *rhc)
{
	struct route_map_index *rmi = rhc->rhc_rmi;

	TAILQ_REMOVE(&rmi->rhclist, rhc, rhc_entry);
	XFREE(MTYPE_TMP, rhc);
}

/*
 * XPath: /frr-route-map:lib/route-map
 */
static int lib_route_map_create(struct nb_cb_create_args *args)
{
	struct route_map *rm;
	const char *rm_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rm_name = yang_dnode_get_string(args->dnode, "name");
		rm = route_map_get(rm_name);
		nb_running_set_entry(args->dnode, rm);
		break;
	}

	return NB_OK;
}

static int lib_route_map_destroy(struct nb_cb_destroy_args *args)
{
	struct route_map *rm;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rm = nb_running_unset_entry(args->dnode);
		route_map_delete(rm);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/optimization-disabled
 */
static int
lib_route_map_optimization_disabled_modify(struct nb_cb_modify_args *args)
{
	struct route_map *rm;
	bool disabled = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rm = nb_running_get_entry(args->dnode, NULL, true);
		rm->optimization_disabled = disabled;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry
 */
static int lib_route_map_entry_create(struct nb_cb_create_args *args)
{
	struct route_map_index *rmi;
	struct route_map *rm;
	uint16_t sequence;
	int action;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		sequence = yang_dnode_get_uint16(args->dnode, "sequence");
		action = yang_dnode_get_enum(args->dnode, "action") == 0
				 ? RMAP_PERMIT
				 : RMAP_DENY;
		rm = nb_running_get_entry(args->dnode, NULL, true);
		rmi = route_map_index_get(rm, action, sequence);
		nb_running_set_entry(args->dnode, rmi);
		break;
	}

	return NB_OK;
}

static int lib_route_map_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct route_map_index *rmi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_unset_entry(args->dnode);
		route_map_index_delete(rmi, 1);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/description
 */
static int
lib_route_map_entry_description_modify(struct nb_cb_modify_args *args)
{
	struct route_map_index *rmi;
	const char *description;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* NOTHING */
		break;
	case NB_EV_PREPARE:
		description = yang_dnode_get_string(args->dnode, NULL);
		args->resource->ptr = XSTRDUP(MTYPE_TMP, description);
		if (args->resource->ptr == NULL)
			return NB_ERR_RESOURCE;
		break;
	case NB_EV_ABORT:
		XFREE(MTYPE_TMP, args->resource->ptr);
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_TMP, rmi->description);
		rmi->description = args->resource->ptr;
		break;
	}

	return NB_OK;
}

static int
lib_route_map_entry_description_destroy(struct nb_cb_destroy_args *args)
{
	struct route_map_index *rmi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_TMP, rmi->description);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/action
 */
static int lib_route_map_entry_action_modify(struct nb_cb_modify_args *args)
{
	struct route_map_index *rmi;
	struct route_map *map;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		rmi->type = yang_dnode_get_enum(args->dnode, NULL);
		map = rmi->map;

		/* Execute event hook. */
		if (route_map_master.event_hook) {
			(*route_map_master.event_hook)(map->name);
			route_map_notify_dependencies(map->name,
						      RMAP_EVENT_CALL_ADDED);
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/call
 */
static int lib_route_map_entry_call_modify(struct nb_cb_modify_args *args)
{
	struct route_map_index *rmi;
	const char *rm_name, *rmn_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rm_name = yang_dnode_get_string(args->dnode, "../../name");
		rmn_name = yang_dnode_get_string(args->dnode, NULL);
		/* Don't allow to jump to the same route map instance. */
		if (strcmp(rm_name, rmn_name) == 0)
			return NB_ERR_VALIDATION;

		/* TODO: detect circular route map sequences. */
		break;
	case NB_EV_PREPARE:
		rmn_name = yang_dnode_get_string(args->dnode, NULL);
		args->resource->ptr = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmn_name);
		break;
	case NB_EV_ABORT:
		XFREE(MTYPE_ROUTE_MAP_NAME, args->resource->ptr);
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		if (rmi->nextrm) {
			route_map_upd8_dependency(RMAP_EVENT_CALL_DELETED,
						  rmi->nextrm, rmi->map->name);
			XFREE(MTYPE_ROUTE_MAP_NAME, rmi->nextrm);
		}
		rmi->nextrm = args->resource->ptr;
		route_map_upd8_dependency(RMAP_EVENT_CALL_ADDED, rmi->nextrm,
					  rmi->map->name);
		break;
	}

	return NB_OK;
}

static int lib_route_map_entry_call_destroy(struct nb_cb_destroy_args *args)
{
	struct route_map_index *rmi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		route_map_upd8_dependency(RMAP_EVENT_CALL_DELETED, rmi->nextrm,
					  rmi->map->name);
		XFREE(MTYPE_ROUTE_MAP_NAME, rmi->nextrm);
		rmi->nextrm = NULL;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/exit-policy
 */
static int
lib_route_map_entry_exit_policy_modify(struct nb_cb_modify_args *args)
{
	struct route_map_index *rmi;
	struct route_map *map;
	int rm_action;
	int policy;

	switch (args->event) {
	case NB_EV_VALIDATE:
		policy = yang_dnode_get_enum(args->dnode, NULL);
		switch (policy) {
		case 0: /* permit-or-deny */
			break;
		case 1: /* next */
		case 2: /* goto */
			rm_action =
				yang_dnode_get_enum(args->dnode, "../action");
			if (rm_action == 1 /* deny */) {
				/*
				 * On deny it is not possible to 'goto'
				 * anywhere.
				 */
				return NB_ERR_VALIDATION;
			}
			break;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		map = rmi->map;
		policy = yang_dnode_get_enum(args->dnode, NULL);

		switch (policy) {
		case 0: /* permit-or-deny */
			rmi->exitpolicy = RMAP_EXIT;
			break;
		case 1: /* next */
			rmi->exitpolicy = RMAP_NEXT;
			break;
		case 2: /* goto */
			rmi->exitpolicy = RMAP_GOTO;
			break;
		}

		/* Execute event hook. */
		if (route_map_master.event_hook) {
			(*route_map_master.event_hook)(map->name);
			route_map_notify_dependencies(map->name,
						      RMAP_EVENT_CALL_ADDED);
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/goto-value
 */
static int lib_route_map_entry_goto_value_modify(struct nb_cb_modify_args *args)
{
	struct route_map_index *rmi;
	uint16_t rmi_index;
	uint16_t rmi_next;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rmi_index = yang_dnode_get_uint16(args->dnode, "../sequence");
		rmi_next = yang_dnode_get_uint16(args->dnode, NULL);
		if (rmi_next <= rmi_index) {
			/* Can't jump backwards on a route map. */
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		rmi->nextpref = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
lib_route_map_entry_goto_value_destroy(struct nb_cb_destroy_args *args)
{
	struct route_map_index *rmi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		rmi->nextpref = 0;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition
 */
static int
lib_route_map_entry_match_condition_create(struct nb_cb_create_args *args)
{
	struct routemap_hook_context *rhc;
	struct route_map_index *rmi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		rmi = nb_running_get_entry(args->dnode, NULL, true);
		rhc = routemap_hook_context_insert(rmi);
		nb_running_set_entry(args->dnode, rhc);
		break;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_destroy(struct nb_cb_destroy_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rv = lib_route_map_entry_match_destroy(args);
	rhc = nb_running_unset_entry(args->dnode);
	routemap_hook_context_free(rhc);

	return rv;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/interface
 */
static int lib_route_map_entry_match_condition_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *ifname;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.match_interface == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = rmap_match_set_hook.no_match_interface;
	rhc->rhc_rule = "interface";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = rmap_match_set_hook.match_interface(rhc->rhc_rmi,
						 "interface", ifname,
						 RMAP_EVENT_MATCH_ADDED,
						 args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_match_condition_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/list-name
 */
static int lib_route_map_entry_match_condition_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *acl;
	const char *condition;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook installation, otherwise we can just stop. */
	acl = yang_dnode_get_string(args->dnode, NULL);
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	condition = yang_dnode_get_string(args->dnode, "../../condition");

	if (IS_MATCH_IPv4_ADDRESS_LIST(condition)) {
		if (rmap_match_set_hook.match_ip_address == NULL)
			return NB_OK;
		rhc->rhc_mhook = rmap_match_set_hook.no_match_ip_address;
		rhc->rhc_rule = "ip address";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;
		rv = rmap_match_set_hook.match_ip_address(
			rhc->rhc_rmi, "ip address", acl,
			RMAP_EVENT_FILTER_ADDED,
			args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv4_PREFIX_LIST(condition)) {
		if (rmap_match_set_hook.match_ip_address_prefix_list == NULL)
			return NB_OK;
		rhc->rhc_mhook =
			rmap_match_set_hook.no_match_ip_address_prefix_list;
		rhc->rhc_rule = "ip address prefix-list";
		rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;
		rv = rmap_match_set_hook.match_ip_address_prefix_list(
			rhc->rhc_rmi, "ip address prefix-list", acl,
			RMAP_EVENT_PLIST_ADDED,
			args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv4_NEXTHOP_LIST(condition)) {
		if (rmap_match_set_hook.match_ip_next_hop == NULL)
			return NB_OK;
		rhc->rhc_mhook = rmap_match_set_hook.no_match_ip_next_hop;
		rhc->rhc_rule = "ip next-hop";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;
		rv = rmap_match_set_hook.match_ip_next_hop(
			rhc->rhc_rmi, "ip next-hop", acl,
			RMAP_EVENT_FILTER_ADDED,
			args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv6_NEXTHOP_LIST(condition)) {
		if (rmap_match_set_hook.match_ipv6_next_hop == NULL)
			return NB_OK;
		rhc->rhc_mhook = rmap_match_set_hook.no_match_ipv6_next_hop;
		rhc->rhc_rule = "ipv6 next-hop";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;
		rv = rmap_match_set_hook.match_ipv6_next_hop(
			rhc->rhc_rmi, "ipv6 next-hop", acl,
			RMAP_EVENT_FILTER_ADDED, args->errmsg,
			args->errmsg_len);
	} else if (IS_MATCH_IPv4_NEXTHOP_PREFIX_LIST(condition)) {
		if (rmap_match_set_hook.match_ip_next_hop_prefix_list == NULL)
			return NB_OK;
		rhc->rhc_mhook =
			rmap_match_set_hook.no_match_ip_next_hop_prefix_list;
		rhc->rhc_rule = "ip next-hop prefix-list";
		rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;
		rv = rmap_match_set_hook.match_ip_next_hop_prefix_list(
			rhc->rhc_rmi, "ip next-hop prefix-list", acl,
			RMAP_EVENT_PLIST_ADDED,
			args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv6_NEXTHOP_PREFIX_LIST(condition)) {
		if (rmap_match_set_hook.match_ipv6_next_hop_prefix_list == NULL)
			return NB_OK;
		rhc->rhc_mhook =
			rmap_match_set_hook.no_match_ipv6_next_hop_prefix_list;
		rhc->rhc_rule = "ipv6 next-hop prefix-list";
		rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;
		rv = rmap_match_set_hook.match_ipv6_next_hop_prefix_list(
			rhc->rhc_rmi, "ipv6 next-hop prefix-list", acl,
			RMAP_EVENT_PLIST_ADDED, args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv6_ADDRESS_LIST(condition)) {
		if (rmap_match_set_hook.match_ipv6_address == NULL)
			return NB_OK;
		rhc->rhc_mhook = rmap_match_set_hook.no_match_ipv6_address;
		rhc->rhc_rule = "ipv6 address";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;
		rv = rmap_match_set_hook.match_ipv6_address(
			rhc->rhc_rmi, "ipv6 address", acl,
			RMAP_EVENT_FILTER_ADDED,
			args->errmsg, args->errmsg_len);
	} else if (IS_MATCH_IPv6_PREFIX_LIST(condition)) {
		if (rmap_match_set_hook.match_ipv6_address_prefix_list == NULL)
			return NB_OK;
		rhc->rhc_mhook =
			rmap_match_set_hook.no_match_ipv6_address_prefix_list;
		rhc->rhc_rule = "ipv6 address prefix-list";
		rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;
		rv = rmap_match_set_hook.match_ipv6_address_prefix_list(
			rhc->rhc_rmi, "ipv6 address prefix-list", acl,
			RMAP_EVENT_PLIST_ADDED,
			args->errmsg, args->errmsg_len);
	} else
		rv = CMD_ERR_NO_MATCH;

	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_match_condition_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/ipv4-next-hop-type
 */
static int lib_route_map_entry_match_condition_ipv4_next_hop_type_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.match_ip_next_hop_type == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = rmap_match_set_hook.no_match_ip_next_hop_type;
	rhc->rhc_rule = "ip next-hop type";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = rmap_match_set_hook.match_ip_next_hop_type(
		rhc->rhc_rmi, "ip next-hop type", type,
		RMAP_EVENT_MATCH_ADDED,
		args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_match_condition_ipv4_next_hop_type_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/ipv6-next-hop-type
 */
static int lib_route_map_entry_match_condition_ipv6_next_hop_type_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.match_ipv6_next_hop_type == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = rmap_match_set_hook.no_match_ipv6_next_hop_type;
	rhc->rhc_rule = "ipv6 next-hop type";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = rmap_match_set_hook.match_ipv6_next_hop_type(
		rhc->rhc_rmi, "ipv6 next-hop type", type,
		RMAP_EVENT_MATCH_ADDED,
		args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_match_condition_ipv6_next_hop_type_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/metric
 */
static int lib_route_map_entry_match_condition_metric_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.match_metric == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = rmap_match_set_hook.no_match_metric;
	rhc->rhc_rule = "metric";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = rmap_match_set_hook.match_metric(rhc->rhc_rmi, "metric",
					      type, RMAP_EVENT_MATCH_ADDED,
					      args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_match_condition_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/tag
 */
static int
lib_route_map_entry_match_condition_tag_modify(struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *tag;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.match_tag == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	tag = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = rmap_match_set_hook.no_match_tag;
	rhc->rhc_rule = "tag";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = rmap_match_set_hook.match_tag(rhc->rhc_rmi, "tag", tag,
					   RMAP_EVENT_MATCH_ADDED,
					   args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_tag_destroy(struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action
 */
static int lib_route_map_entry_set_action_create(struct nb_cb_create_args *args)
{
	return lib_route_map_entry_match_condition_create(args);
}

static int
lib_route_map_entry_set_action_destroy(struct nb_cb_destroy_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rv = lib_route_map_entry_set_destroy(args);
	rhc = nb_running_unset_entry(args->dnode);
	routemap_hook_context_free(rhc);

	return rv;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/ipv4-address
 */
static int lib_route_map_entry_set_action_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *address;
	struct in_addr ia;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * NOTE: validate if 'action' is 'ipv4-next-hop',
		 * currently it is not necessary because this is the
		 * only implemented action.
		 */
		yang_dnode_get_ipv4(&ia, args->dnode, NULL);
		if (ia.s_addr == INADDR_ANY || !ipv4_unicast_valid(&ia))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Check for hook function. */
	if (rmap_match_set_hook.set_ip_nexthop == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	address = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_ip_nexthop;
	rhc->rhc_rule = "ip next-hop";

	rv = rmap_match_set_hook.set_ip_nexthop(rhc->rhc_rmi, "ip next-hop",
						address,
						args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_ipv4_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/ipv6-address
 */
static int lib_route_map_entry_set_action_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *address;
	struct in6_addr i6a;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * NOTE: validate if 'action' is 'ipv6-next-hop',
		 * currently it is not necessary because this is the
		 * only implemented action. Other actions might have
		 * different validations.
		 */
		yang_dnode_get_ipv6(&i6a, args->dnode, NULL);
		if (!IN6_IS_ADDR_LINKLOCAL(&i6a))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Check for hook function. */
	if (rmap_match_set_hook.set_ipv6_nexthop_local == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	address = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_ipv6_nexthop_local;
	rhc->rhc_rule = "ipv6 next-hop local";

	rv = rmap_match_set_hook.set_ipv6_nexthop_local(
		rhc->rhc_rmi, "ipv6 next-hop local", address,
		args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_ipv6_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/value
 */
static int set_action_modify(enum nb_event event, const struct lyd_node *dnode,
			     union nb_resource *resource, const char *value,
			     char *errmsg, size_t errmsg_len)
{
	struct routemap_hook_context *rhc;
	int rv;

	/*
	 * NOTE: validate if 'action' is 'metric', currently it is not
	 * necessary because this is the only implemented action. Other
	 * actions might have different validations.
	 */
	if (event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.set_metric == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(dnode, NULL, true);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_metric;
	rhc->rhc_rule = "metric";

	rv = rmap_match_set_hook.set_metric(rhc->rhc_rmi, "metric",
					    value,
					    errmsg, errmsg_len
					    );
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_value_modify(struct nb_cb_modify_args *args)
{
	const char *metric = yang_dnode_get_string(args->dnode, NULL);

	return set_action_modify(args->event, args->dnode, args->resource,
				 metric, args->errmsg, args->errmsg_len);
}

static int
lib_route_map_entry_set_action_value_destroy(struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/min-metric
 */
static int set_action_min_metric_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource,
					const char *value, char *errmsg,
					size_t errmsg_len)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.set_min_metric == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(dnode, NULL, true);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_min_metric;
	rhc->rhc_rule = "min-metric";

	rv = rmap_match_set_hook.set_min_metric(rhc->rhc_rmi, "min-metric",
						value, errmsg, errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_min_metric_modify(struct nb_cb_modify_args *args)
{
	const char *min_metric = yang_dnode_get_string(args->dnode, NULL);

	return set_action_min_metric_modify(args->event, args->dnode,
					    args->resource, min_metric,
					    args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_min_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/max-metric
 */
static int set_action_max_metric_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource,
					const char *value, char *errmsg,
					size_t errmsg_len)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.set_max_metric == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(dnode, NULL, true);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_max_metric;
	rhc->rhc_rule = "max-metric";

	rv = rmap_match_set_hook.set_max_metric(rhc->rhc_rmi, "max-metric",
						value, errmsg, errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_max_metric_modify(struct nb_cb_modify_args *args)
{
	const char *max_metric = yang_dnode_get_string(args->dnode, NULL);

	return set_action_max_metric_modify(args->event, args->dnode,
					    args->resource, max_metric,
					    args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_max_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/add-metric
 */
static int
lib_route_map_entry_set_action_add_metric_modify(struct nb_cb_modify_args *args)
{
	char metric_str[16];

	if (args->event == NB_EV_VALIDATE
	    && yang_dnode_get_uint32(args->dnode, NULL) == 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Can't add zero to metric");
		return NB_ERR_VALIDATION;
	}

	snprintf(metric_str, sizeof(metric_str), "+%s",
		 yang_dnode_get_string(args->dnode, NULL));
	return set_action_modify(args->event, args->dnode, args->resource,
				 metric_str,
				 args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_add_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_action_value_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/subtract-metric
 */
static int lib_route_map_entry_set_action_subtract_metric_modify(
	struct nb_cb_modify_args *args)
{
	char metric_str[16];

	if (args->event == NB_EV_VALIDATE
	    && yang_dnode_get_uint32(args->dnode, NULL) == 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Can't subtract zero from metric");
		return NB_ERR_VALIDATION;
	}

	snprintf(metric_str, sizeof(metric_str), "-%s",
		 yang_dnode_get_string(args->dnode, NULL));
	return set_action_modify(args->event, args->dnode, args->resource,
				 metric_str,
				 args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_subtract_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_action_value_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/use-round-trip-time
 */
static int lib_route_map_entry_set_action_use_round_trip_time_modify(
	struct nb_cb_modify_args *args)
{
	return set_action_modify(args->event, args->dnode, args->resource,
				 "rtt",
				 args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_use_round_trip_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_action_value_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/add-round-trip-time
 */
static int lib_route_map_entry_set_action_add_round_trip_time_modify(
	struct nb_cb_modify_args *args)
{
	return set_action_modify(args->event, args->dnode, args->resource,
				 "+rtt",
				 args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_add_round_trip_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_action_value_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/subtract-round-trip-time
 */
static int lib_route_map_entry_set_action_subtract_round_trip_time_modify(
	struct nb_cb_modify_args *args)
{
	return set_action_modify(args->event, args->dnode, args->resource,
				 "-rtt", args->errmsg, args->errmsg_len);
}

static int lib_route_map_entry_set_action_subtract_round_trip_time_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_action_value_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/tag
 */
static int
lib_route_map_entry_set_action_tag_modify(struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *tag;
	int rv;

	/*
	 * NOTE: validate if 'action' is 'tag', currently it is not
	 * necessary because this is the only implemented action. Other
	 * actions might have different validations.
	 */
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.set_tag == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	tag = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_tag;
	rhc->rhc_rule = "tag";

	rv = rmap_match_set_hook.set_tag(rhc->rhc_rmi, "tag", tag,
					 args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_tag_destroy(struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/policy
 */
static int
lib_route_map_entry_set_action_policy_modify(struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *policy;
	int rv;

	/*
	 * NOTE: validate if 'action' is 'tag', currently it is not
	 * necessary because this is the only implemented action. Other
	 * actions might have different validations.
	 */
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Check for hook function. */
	if (rmap_match_set_hook.set_srte_color == NULL)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	policy = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = rmap_match_set_hook.no_set_tag;
	rhc->rhc_rule = "sr-te color";

	rv = rmap_match_set_hook.set_tag(rhc->rhc_rmi, "sr-te color", policy,
			args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_policy_destroy(struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/* clang-format off */
const struct frr_yang_module_info frr_route_map_info = {
	.name = "frr-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map",
			.cbs = {
				.create = lib_route_map_create,
				.destroy = lib_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/optimization-disabled",
			.cbs = {
				.modify = lib_route_map_optimization_disabled_modify,
				.cli_show = route_map_optimization_disabled_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry",
			.cbs = {
				.create = lib_route_map_entry_create,
				.destroy = lib_route_map_entry_destroy,
				.cli_cmp = route_map_instance_cmp,
				.cli_show = route_map_instance_show,
				.cli_show_end = route_map_instance_show_end,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/description",
			.cbs = {
				.modify = lib_route_map_entry_description_modify,
				.destroy = lib_route_map_entry_description_destroy,
				.cli_show = route_map_description_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/action",
			.cbs = {
				.modify = lib_route_map_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/call",
			.cbs = {
				.modify = lib_route_map_entry_call_modify,
				.destroy = lib_route_map_entry_call_destroy,
				.cli_show = route_map_call_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/exit-policy",
			.cbs = {
				.modify = lib_route_map_entry_exit_policy_modify,
				.cli_show = route_map_exit_policy_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/goto-value",
			.cbs = {
				.modify = lib_route_map_entry_goto_value_modify,
				.destroy = lib_route_map_entry_goto_value_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition",
			.cbs = {
				.create = lib_route_map_entry_match_condition_create,
				.destroy = lib_route_map_entry_match_condition_destroy,
				.cli_show = route_map_condition_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/interface",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_interface_modify,
				.destroy = lib_route_map_entry_match_condition_interface_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/list-name",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_list_name_modify,
				.destroy = lib_route_map_entry_match_condition_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/ipv4-next-hop-type",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_ipv4_next_hop_type_modify,
				.destroy = lib_route_map_entry_match_condition_ipv4_next_hop_type_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/ipv6-next-hop-type",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_ipv6_next_hop_type_modify,
				.destroy = lib_route_map_entry_match_condition_ipv6_next_hop_type_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/metric",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_metric_modify,
				.destroy = lib_route_map_entry_match_condition_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/tag",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_tag_modify,
				.destroy = lib_route_map_entry_match_condition_tag_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action",
			.cbs = {
				.create = lib_route_map_entry_set_action_create,
				.destroy = lib_route_map_entry_set_action_destroy,
				.cli_show = route_map_action_show,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_ipv4_address_modify,
				.destroy = lib_route_map_entry_set_action_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_ipv6_address_modify,
				.destroy = lib_route_map_entry_set_action_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/value",
			.cbs = {
				.modify = lib_route_map_entry_set_action_value_modify,
				.destroy = lib_route_map_entry_set_action_value_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/min-metric",
			.cbs = {
				.modify = lib_route_map_entry_set_action_min_metric_modify,
				.destroy = lib_route_map_entry_set_action_min_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/max-metric",
			.cbs = {
				.modify = lib_route_map_entry_set_action_max_metric_modify,
				.destroy = lib_route_map_entry_set_action_max_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/add-metric",
			.cbs = {
				.modify = lib_route_map_entry_set_action_add_metric_modify,
				.destroy = lib_route_map_entry_set_action_add_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/subtract-metric",
			.cbs = {
				.modify = lib_route_map_entry_set_action_subtract_metric_modify,
				.destroy = lib_route_map_entry_set_action_subtract_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/use-round-trip-time",
			.cbs = {
				.modify = lib_route_map_entry_set_action_use_round_trip_time_modify,
				.destroy = lib_route_map_entry_set_action_use_round_trip_time_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/add-round-trip-time",
			.cbs = {
				.modify = lib_route_map_entry_set_action_add_round_trip_time_modify,
				.destroy = lib_route_map_entry_set_action_add_round_trip_time_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/subtract-round-trip-time",
			.cbs = {
				.modify = lib_route_map_entry_set_action_subtract_round_trip_time_modify,
				.destroy = lib_route_map_entry_set_action_subtract_round_trip_time_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/tag",
			.cbs = {
				.modify = lib_route_map_entry_set_action_tag_modify,
				.destroy = lib_route_map_entry_set_action_tag_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/policy",
			.cbs = {
				.modify = lib_route_map_entry_set_action_policy_modify,
				.destroy = lib_route_map_entry_set_action_policy_destroy,
			}
		},

		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info frr_route_map_cli_info = {
	.name = "frr-route-map",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/optimization-disabled",
			.cbs.cli_show = route_map_optimization_disabled_show,
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry",
			.cbs = {
				.cli_cmp = route_map_instance_cmp,
				.cli_show = route_map_instance_show,
				.cli_show_end = route_map_instance_show_end,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/description",
			.cbs.cli_show = route_map_description_show,
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/call",
			.cbs.cli_show = route_map_call_show,
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/exit-policy",
			.cbs.cli_show = route_map_exit_policy_show,
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition",
			.cbs.cli_show = route_map_condition_show,
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action",
			.cbs.cli_show = route_map_action_show,
		},
		{
			.xpath = NULL,
		},
	}
};
