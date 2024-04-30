// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_routemap_nb.h"

/* Add bgp route map rule. */
static int bgp_route_match_add(struct route_map_index *index,
		const char *command, const char *arg,
		route_map_event_t type,
		char *errmsg, size_t errmsg_len)
{
	int retval = CMD_SUCCESS;
	enum rmap_compile_rets ret;

	ret = route_map_add_match(index, command, arg, type);
	switch (ret) {
	case RMAP_RULE_MISSING:
		snprintf(errmsg, errmsg_len, "%% BGP Can't find rule.");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		snprintf(errmsg, errmsg_len, "%% BGP Argument is malformed.");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		/*
		 * Intentionally doing nothing here.
		 */
		break;
	}

	return retval;
}

/* Delete bgp route map rule. */
static int bgp_route_match_delete(struct route_map_index *index,
		const char *command, const char *arg,
		route_map_event_t type,
		char *errmsg, size_t errmsg_len)
{
	enum rmap_compile_rets ret;
	int retval = CMD_SUCCESS;
	char *dep_name = NULL;
	const char *tmpstr;
	char *rmap_name = NULL;

	if (type != RMAP_EVENT_MATCH_DELETED) {
		/* ignore the mundane, the types without any dependency */
		if (arg == NULL) {
			tmpstr = route_map_get_match_arg(index, command);
			if (tmpstr != NULL)
				dep_name =
					XSTRDUP(MTYPE_ROUTE_MAP_RULE, tmpstr);
		} else {
			dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, arg);
		}
		rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
	}

	ret = route_map_delete_match(index, command, dep_name, type);
	switch (ret) {
		case RMAP_RULE_MISSING:
			snprintf(errmsg, errmsg_len, "%% BGP Can't find rule.");
			retval = CMD_WARNING_CONFIG_FAILED;
			break;
		case RMAP_COMPILE_ERROR:
			snprintf(errmsg, errmsg_len,
				 "%% BGP Argument is malformed.");
			retval = CMD_WARNING_CONFIG_FAILED;
			break;
		case RMAP_COMPILE_SUCCESS:
			/*
			 * Nothing to do here
			 */
			break;
	}

	XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
	XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

	return retval;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:local-preference
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_local_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *local_pref;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		local_pref = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "local-preference";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "local-preference",
				local_pref, RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

		return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_local_preference_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:alias
 */
int lib_route_map_entry_match_condition_rmap_match_condition_alias_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *alias;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		alias = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "alias";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "alias", alias,
					  RMAP_EVENT_MATCH_ADDED, args->errmsg,
					  args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_VALIDATION;
		}

		break;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_rmap_match_condition_alias_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:script
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_script_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *script;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		script = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "script";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "script",
				script, RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_script_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:origin
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_origin_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *origin;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		origin = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "origin";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "origin", origin,
					  RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_origin_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_rpki_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *rpki;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		rpki = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "rpki";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "rpki", rpki,
				RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_rpki_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-protocol
 */
int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	enum rmap_compile_rets ret;
	const char *proto;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		proto = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "source-protocol";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "source-protocol",
					  proto, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki-extcommunity
 */
int lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *rpki;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		rpki = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "rpki-extcommunity";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "rpki-extcommunity",
					  rpki, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:probability
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_probability_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *probability;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		probability = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "probability";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "probability",
					  probability, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_probability_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-vrf
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *vrf;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		vrf = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "source-vrf";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "source-vrf", vrf,
					  RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		peer = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "peer";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "peer", peer,
					  RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-interface
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		peer = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "peer";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "peer", peer,
				RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		peer = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "peer";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "peer", peer,
				RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-local
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_peer_local_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool value;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		value = yang_dnode_get_bool(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "peer";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		if (value) {
			ret = bgp_route_match_add(rhc->rhc_rmi, "peer",
						"local",
						RMAP_EVENT_MATCH_ADDED,
						args->errmsg, args->errmsg_len);

			if (ret != RMAP_COMPILE_SUCCESS) {
				rhc->rhc_mhook = NULL;
				return NB_ERR_INCONSISTENCY;
			}
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_peer_local_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:list-name
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *list_name;
	enum rmap_compile_rets ret = RMAP_COMPILE_SUCCESS;
	const char *condition;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		list_name = yang_dnode_get_string(args->dnode, NULL);
		condition = yang_dnode_get_string(args->dnode,
				"../../frr-route-map:condition");

		if (IS_MATCH_AS_LIST(condition)) {
			/* Set destroy information. */
			rhc->rhc_mhook = bgp_route_match_delete;
			rhc->rhc_rule = "as-path";
			rhc->rhc_event = RMAP_EVENT_ASLIST_DELETED;

			ret = bgp_route_match_add(rhc->rhc_rmi, "as-path",
					list_name, RMAP_EVENT_ASLIST_ADDED,
					args->errmsg, args->errmsg_len);
		} else if (IS_MATCH_MAC_LIST(condition)) {
			/* Set destroy information. */
			rhc->rhc_mhook = bgp_route_match_delete;
			rhc->rhc_rule = "mac address";
			rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

			ret = bgp_route_match_add(rhc->rhc_rmi,
						  "mac address",
						  list_name,
						  RMAP_EVENT_FILTER_ADDED,
						  args->errmsg, args->errmsg_len);
		} else if (IS_MATCH_ROUTE_SRC(condition)) {
			/* Set destroy information. */
			rhc->rhc_mhook = bgp_route_match_delete;
			rhc->rhc_rule = "ip route-source";
			rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

			ret = bgp_route_match_add(rhc->rhc_rmi,
					"ip route-source",
					list_name, RMAP_EVENT_FILTER_ADDED,
					args->errmsg, args->errmsg_len);
		} else if (IS_MATCH_ROUTE_SRC_PL(condition)) {
			/* Set destroy information. */
			rhc->rhc_mhook = bgp_route_match_delete;
			rhc->rhc_rule = "ip route-source prefix-list";
			rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;

			ret = bgp_route_match_add(rhc->rhc_rmi,
					"ip route-source prefix-list",
					list_name, RMAP_EVENT_PLIST_ADDED,
					args->errmsg, args->errmsg_len);
		}

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_list_name_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-default-route
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_create(
	struct nb_cb_create_args *args)
{
	struct routemap_hook_context *rhc;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "evpn default-route";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "evpn default-route",
					  NULL, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-vni
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *vni;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		vni = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "evpn vni";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "evpn vni", vni,
				RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-route-type
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	enum rmap_compile_rets ret;

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
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "evpn route-type";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "evpn route-type",
					  type,
					  RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:route-distinguisher
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *rd;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		rd = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "evpn rd";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, "evpn rd", rd,
				RMAP_EVENT_MATCH_ADDED,
				args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_destroy(
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
 * XPath = /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list
 */
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_destroy(
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

void
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	bool exact_match = false;
	bool any = false;
	char *argstr;
	const char *condition;
	route_map_event_t event;
	int ret;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, "comm-list-name");

	if (yang_dnode_exists(args->dnode, "comm-list-name-exact-match"))
		exact_match = yang_dnode_get_bool(
			args->dnode, "./comm-list-name-exact-match");

	if (yang_dnode_exists(args->dnode, "comm-list-name-any"))
		any = yang_dnode_get_bool(args->dnode, "comm-list-name-any");

	if (exact_match) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(value) + strlen("exact-match") + 2);

		snprintf(argstr, (strlen(value) + strlen("exact-match") + 2),
			 "%s exact-match", value);
	} else if (any) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(value) + strlen("any") + 2);

		snprintf(argstr, (strlen(value) + strlen("any") + 2), "%s any",
			 value);
	} else
		argstr = (char *)value;

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;

	condition = yang_dnode_get_string(args->dnode,
					  "../../frr-route-map:condition");
	if (IS_MATCH_COMMUNITY(condition)) {
		rhc->rhc_rule = "community";
		event = RMAP_EVENT_CLIST_ADDED;
		rhc->rhc_event = RMAP_EVENT_CLIST_DELETED;
	} else if (IS_MATCH_LCOMMUNITY(condition)) {
		rhc->rhc_rule = "large-community";
		event = RMAP_EVENT_LLIST_ADDED;
		rhc->rhc_event = RMAP_EVENT_LLIST_DELETED;
	} else {
		rhc->rhc_rule = "extcommunity";
		event = RMAP_EVENT_ECLIST_ADDED;
		rhc->rhc_event = RMAP_EVENT_ECLIST_DELETED;
	}

	ret = bgp_route_match_add(rhc->rhc_rmi, rhc->rhc_rule, argstr, event,
				  args->errmsg, args->errmsg_len);
	/*
	 * At this point if this is not a successful operation
	 * bgpd is about to crash.  Let's just cut to the
	 * chase and do it.
	 */
	assert(ret == RMAP_COMPILE_SUCCESS);

	if (argstr != value)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any
 */
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv4-address
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		peer = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "ip next-hop address";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, rhc->rhc_rule,
					  peer, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_destroy(
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
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv6-address
 */
int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		peer = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "ipv6 next-hop address";
		rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

		ret = bgp_route_match_add(rhc->rhc_rmi, rhc->rhc_rule,
					  peer, RMAP_EVENT_MATCH_ADDED,
					  args->errmsg, args->errmsg_len);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:distance
 */
int lib_route_map_entry_set_action_rmap_set_action_distance_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "distance";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "distance", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_distance_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-rt
 */
int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "extcommunity rt";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "extcommunity rt", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-nt
 */
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *str;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		str = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "extcommunity nt";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "extcommunity nt", str,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-soo
 */
int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "extcommunity soo";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "extcommunity soo",
				     type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-address
 */
int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *addr;
	int rv = CMD_SUCCESS;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		addr = yang_dnode_get_string(args->dnode, NULL);

		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;
		rhc->rhc_rule = "ipv4 vpn next-hop";

		rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, addr,
				     args->errmsg, args->errmsg_len);

		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-nexthop
 */
int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "ip next-hop";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, type,
				    args->errmsg, args->errmsg_len);

		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv6-address
 */
int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *addr;
	int rv = CMD_SUCCESS;
	const char *action = NULL;
	struct in6_addr i6a;

	action = yang_dnode_get_string(args->dnode,
				       "../../frr-route-map:action");
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (action && IS_SET_IPV6_NH_GLOBAL(action)) {
			yang_dnode_get_ipv6(&i6a, args->dnode, NULL);
			if (IN6_IS_ADDR_UNSPECIFIED(&i6a)
			    || IN6_IS_ADDR_LOOPBACK(&i6a)
			    || IN6_IS_ADDR_MULTICAST(&i6a)
			    || IN6_IS_ADDR_LINKLOCAL(&i6a))
				return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	addr = yang_dnode_get_string(args->dnode, NULL);

	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	if (IS_SET_IPV6_NH_GLOBAL(action))
		/* Set destroy information. */
		rhc->rhc_rule = "ipv6 next-hop global";
	else
		rhc->rhc_rule = "ipv6 vpn next-hop";

	rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, addr,
			     args->errmsg, args->errmsg_len);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:preference
 */
int lib_route_map_entry_set_action_rmap_set_action_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	int rv = CMD_SUCCESS;
	const char *action = NULL;
	bool value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		value = yang_dnode_get_bool(args->dnode, NULL);

		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		action = yang_dnode_get_string(args->dnode,
				"../../frr-route-map:action");

		if (value) {
			if (IS_SET_IPV6_PEER_ADDR(action))
				/* Set destroy information. */
				rhc->rhc_rule = "ipv6 next-hop peer-address";
			else
				rhc->rhc_rule = "ipv6 next-hop prefer-global";

			rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule,
					     NULL,
					     args->errmsg, args->errmsg_len);
		}

		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_preference_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:label-index
 */
int lib_route_map_entry_set_action_rmap_set_action_label_index_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "label-index";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "label-index", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_label_index_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:local-pref
 */
int lib_route_map_entry_set_action_rmap_set_action_local_pref_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "local-preference";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "local-preference",
				     type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_local_pref_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:weight
 */
int lib_route_map_entry_set_action_rmap_set_action_weight_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "weight";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "weight", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_weight_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:origin
 */
int lib_route_map_entry_set_action_rmap_set_action_origin_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "origin";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "origin", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_origin_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:originator-id
 */
int lib_route_map_entry_set_action_rmap_set_action_originator_id_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "originator-id";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "originator-id", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_originator_id_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:table
 */
int lib_route_map_entry_set_action_rmap_set_action_table_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "table";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "table", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_table_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:atomic-aggregate
 */
int
lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_create(
	struct nb_cb_create_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "atomic-aggregate";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, NULL,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aigp-metric
 */
int lib_route_map_entry_set_action_rmap_set_action_aigp_metric_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *aigp;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		aigp = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "aigp-metric";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, aigp,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_aigp_metric_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:prepend-as-path
 */
int
lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "as-path prepend";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "as-path prepend",
				     type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:last-as
 */
int lib_route_map_entry_set_action_rmap_set_action_last_as_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	char *argstr;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		value = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "as-path prepend";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				strlen(value) + strlen("last-as") + 2);

		snprintf(argstr, (strlen(value) + strlen("last-as") + 2),
			 "last-as %s", value);

		rv = generic_set_add(rhc->rhc_rmi, "as-path prepend",
				     argstr,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
			return NB_ERR_INCONSISTENCY;
		}

		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_last_as_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:exclude-as-path
 */
int
lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "as-path exclude";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "as-path exclude",
				     type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:replace-as-path
 */
int lib_route_map_entry_set_action_rmap_set_action_replace_as_path_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "as-path replace";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "as-path replace", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_replace_as_path_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-none
 */
int lib_route_map_entry_set_action_rmap_set_action_community_none_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool none = false;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		none = yang_dnode_get_bool(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "community";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		if (none) {
			rv = generic_set_add(rhc->rhc_rmi, "community",
					     "none",
					     args->errmsg, args->errmsg_len);
			if (rv != CMD_SUCCESS) {
				rhc->rhc_shook = NULL;
				return NB_ERR_INCONSISTENCY;
			}
			return NB_OK;
		}

		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_community_none_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-string
 */
int
lib_route_map_entry_set_action_rmap_set_action_community_string_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "community";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "community", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_community_string_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-none
 */
int
lib_route_map_entry_set_action_rmap_set_action_large_community_none_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool none = false;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		none = yang_dnode_get_bool(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "large-community";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		if (none) {
			rv = generic_set_add(rhc->rhc_rmi,
					     "large-community",
					     "none",
					      args->errmsg, args->errmsg_len);
			if (rv != CMD_SUCCESS) {
				rhc->rhc_shook = NULL;
				return NB_ERR_INCONSISTENCY;
			}
		return NB_OK;
		}

		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_large_community_none_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-string
 */
int
lib_route_map_entry_set_action_rmap_set_action_large_community_string_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "large-community";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "large-community",
				     type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_large_community_string_destroy(
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
 * xpath =
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator
 */
int lib_route_map_entry_set_action_rmap_set_action_aggregator_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_aggregator_destroy(
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

void lib_route_map_entry_set_action_rmap_set_action_aggregator_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *asn;
	const char *addr;
	char *argstr;
	int ret;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	asn = yang_dnode_get_string(args->dnode, "aggregator-asn");
	addr = yang_dnode_get_string(args->dnode, "aggregator-address");

	argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
			 strlen(asn) + strlen(addr) + 2);

	snprintf(argstr, (strlen(asn) + strlen(addr) + 2), "%s %s", asn, addr);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "aggregator as";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	ret = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, argstr, args->errmsg,
			      args->errmsg_len);
	/*
	 * At this point if this is not a successful operation
	 * bgpd is about to crash.  Let's just cut to the
	 * chase and do it.
	 */
	assert(ret == CMD_SUCCESS);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}
/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn
 */
int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify(
	struct nb_cb_modify_args *args)
{
	const char *asn;
	enum match_type match;

	switch (args->event) {
	case NB_EV_VALIDATE:
		asn = yang_dnode_get_string(args->dnode, NULL);
		if (!asn)
			return NB_ERR_VALIDATION;
		match = asn_str2asn_match(asn);
		if (match == exact_match)
			return NB_OK;
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address
 */
int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-name
 */
int lib_route_map_entry_set_action_rmap_set_action_comm_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	const char *action;
	int rv = CMD_SUCCESS;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		value = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;

		action = yang_dnode_get_string(args->dnode,
				"../../frr-route-map:action");
		if (IS_SET_COMM_LIST_DEL(action))
			rhc->rhc_rule = "comm-list";
		else if (IS_SET_EXTCOMM_LIST_DEL(action))
			rhc->rhc_rule = "extended-comm-list";
		else
			rhc->rhc_rule = "large-comm-list";

		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, rhc->rhc_rule, value,
				     args->errmsg, args->errmsg_len);

		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_comm_list_name_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb
 */
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_destroy(
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

void
lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	enum ecommunity_lb_type lb_type;
	char str[VTY_BUFSIZ];
	uint16_t bandwidth;
	int ret;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	lb_type = yang_dnode_get_enum(args->dnode, "lb-type");

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "extcommunity bandwidth";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	switch (lb_type) {
	case EXPLICIT_BANDWIDTH:
		bandwidth = yang_dnode_get_uint16(args->dnode, "bandwidth");
		snprintf(str, sizeof(str), "%d", bandwidth);
		break;
	case CUMULATIVE_BANDWIDTH:
		snprintf(str, sizeof(str), "%s", "cumulative");
		break;
	case COMPUTED_BANDWIDTH:
		snprintf(str, sizeof(str), "%s", "num-multipaths");
	}

	if (yang_dnode_get_bool(args->dnode, "two-octet-as-specific"))
		strlcat(str, " non-transitive", sizeof(str));

	ret = generic_set_add(rhc->rhc_rmi, "extcommunity bandwidth", str,
			      args->errmsg, args->errmsg_len);
	/*
	 * At this point if this is not a successful operation
	 * bgpd is about to crash.  Let's just cut to the
	 * chase and do it.
	 */
	assert(ret == CMD_SUCCESS);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/lb-type
 */
int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_lb_type_modify(
		struct nb_cb_modify_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/bandwidth
 */
int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_modify(
		struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_destroy(
		struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-color
 */
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *str;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		str = yang_dnode_get_string(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "extcommunity color";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "extcommunity color", str,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/two-octet-as-specific
 */
int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_two_octet_as_specific_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-none
 */
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool none = false;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Add configuration. */
		rhc = nb_running_get_entry(args->dnode, NULL, true);
		none = yang_dnode_get_bool(args->dnode, NULL);

		/* Set destroy information. */
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "extcommunity";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		if (none) {
			rv = generic_set_add(rhc->rhc_rmi, "extcommunity",
					     "none", args->errmsg,
					     args->errmsg_len);
			if (rv != CMD_SUCCESS) {
				rhc->rhc_shook = NULL;
				return NB_ERR_INCONSISTENCY;
			}
			return NB_OK;
		}

		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv4
 */
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "evpn gateway-ip ipv4";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "evpn gateway-ip ipv4", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv6
 */
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "evpn gateway-ip ipv6";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi, "evpn gateway-ip ipv6", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_destroy(
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/l3vpn-nexthop-encapsulation
 */
int lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_modify(
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
		rhc->rhc_shook = generic_set_delete;
		rhc->rhc_rule = "l3vpn next-hop encapsulation";
		rhc->rhc_event = RMAP_EVENT_SET_DELETED;

		rv = generic_set_add(rhc->rhc_rmi,
				     "l3vpn next-hop encapsulation", type,
				     args->errmsg, args->errmsg_len);
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_destroy(
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
