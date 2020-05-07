#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "zebra/rib.h"

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int rv;
	const char *condition;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

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

	rv = generic_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, length,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	length = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "ipv6 address prefix-len";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, "ipv6 address prefix-len",
			       length, RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-instance
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_source_instance_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "source-instance";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, "source-instance", type,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_source_instance_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-protocol
 */
static int
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

	rv = generic_match_add(NULL, rhc->rhc_rmi, "source-protocol", type,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv4-src-address
 */
static int
lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	struct interface *pif = NULL;
	const char *source;
	struct vrf *vrf;
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

		RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id) {
			pif = if_lookup_exact_address(&p.u.prefix4, AF_INET,
						      vrf->vrf_id);
			if (pif != NULL)
				break;
		}
		if (pif == NULL) {
			zlog_warn("%s: is not a local adddress: %s", __func__,
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

	rv = generic_set_add(NULL, rhc->rhc_rmi, "src", source);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv6-src-address
 */
static int
lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	struct interface *pif = NULL;
	const char *source;
	struct vrf *vrf;
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

		RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id) {
			pif = if_lookup_exact_address(&p.u.prefix6, AF_INET6,
						      vrf->vrf_id);
			if (pif != NULL)
				break;
		}
		if (pif == NULL) {
			zlog_warn("%s: is not a local adddress: %s", __func__,
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

	rv = generic_set_add(NULL, rhc->rhc_rmi, "src", source);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/* clang-format off */
const struct frr_yang_module_info frr_zebra_route_map_info = {
	.name = "frr-zebra-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-instance",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_instance_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_instance_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-protocol",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv4-src-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv6-src-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
