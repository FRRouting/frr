// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "zebra/rib.h"
#include "zebra/zebra_routemap_nb.h"

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int rv;
	const char *condition;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		length = yang_dnode_get_string(args->dnode, NULL);
		condition = yang_dnode_get_string(args->dnode,
				"../../frr-route-map:condition");

		if (IS_MATCH_IPv4_PREFIX_LEN(condition))
			rhc->rhc_rule = "ip address prefix-len";
		else if (IS_MATCH_IPv4_NH_PREFIX_LEN(condition))
			rhc->rhc_rule = "ip next-hop prefix-len";

		rhc->rhc_mhook = generic_match_delete;
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		rv = generic_match_add(rhc->rhc_rmi, rhc->rhc_rule,
				       length, RMAP_EVENT_MATCH_ADDED,
				       args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_match_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		length = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = generic_match_delete;
		rhc->rhc_rule = "ipv6 address prefix-len";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		rv = generic_match_add(rhc->rhc_rmi, "ipv6 address prefix-len",
				length, RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_match_destroy(args);
	}

	return NB_OK;

}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-instance
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_source_instance_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		type = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = generic_match_delete;
		rhc->rhc_rule = "source-instance";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		rv = generic_match_add(rhc->rhc_rmi, "source-instance",
				       type, RMAP_EVENT_MATCH_ADDED,
				       args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_source_instance_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_match_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-protocol
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		type = yang_dnode_get_string(args->dnode, NULL);
		if (proto_name2num(type) == -1) {
			zlog_warn("%s: invalid protocol: %s", __func__, type);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "source-protocol";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(rhc->rhc_rmi, "source-protocol", type,
			       RMAP_EVENT_MATCH_ADDED,
			       args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_match_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv4-src-address
 */
int
lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *source;
	struct prefix p;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		memset(&p, 0, sizeof(p));
		yang_dnode_get_ipv4p(&p, args->dnode, NULL);
		if (zebra_check_addr(&p) == 0) {
			zlog_warn("%s: invalid IPv4 address: %s", __func__,
				  yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	source = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "src";

	rv = generic_set_add(rhc->rhc_rmi, "src", source,
			     args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_set_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv6-src-address
 */
int
lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *source;
	struct prefix p;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		memset(&p, 0, sizeof(p));
		yang_dnode_get_ipv6p(&p, args->dnode, NULL);
		if (zebra_check_addr(&p) == 0) {
			zlog_warn("%s: invalid IPv6 address: %s", __func__,
				  yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	source = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "src";

	rv = generic_set_add(rhc->rhc_rmi, "src", source,
			     args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return lib_route_map_entry_set_destroy(args);
	}

	return NB_OK;
}
