#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "bgpd/bgpd.h"

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:local-preference
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_local_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *local_pref;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	local_pref = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "local-preference";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "local-preference",
				  local_pref, RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_local_preference_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:origin
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_origin_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *origin;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	origin = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "origin";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "origin", origin,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_rpki_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *rpki;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	rpki = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "rpki";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "rpki", rpki,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_rpki_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:probability
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_probability_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *probability;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	probability = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "probability";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "probability",
				  probability, RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_probability_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-vrf
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *vrf;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	vrf = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "source-vrf";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "source-vrf", vrf,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	peer = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "peer";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "peer", peer,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-interface
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	peer = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "peer";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "peer", peer,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	peer = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "peer";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "peer", peer,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-local
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_local_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool value;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_bool(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "peer";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	if (value) {
		ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "peer", "local",
					  RMAP_EVENT_MATCH_ADDED);

		if (ret != RMAP_COMPILE_SUCCESS) {
			rhc->rhc_mhook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_peer_local_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:list-name
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *list_name;
	enum rmap_compile_rets ret = RMAP_COMPILE_SUCCESS;
	const char *condition;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

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

		ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "as-path",
					  list_name, RMAP_EVENT_ASLIST_ADDED);
	} else if (IS_MATCH_MAC_LIST(condition)) {
		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "mac address";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

		ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "mac address",
					  list_name, RMAP_EVENT_FILTER_ADDED);
	} else if (IS_MATCH_ROUTE_SRC(condition)) {
		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "ip route-source";
		rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

		ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "ip route-source",
					  list_name, RMAP_EVENT_FILTER_ADDED);
	} else if (IS_MATCH_ROUTE_SRC_PL(condition)) {
		/* Set destroy information. */
		rhc->rhc_mhook = bgp_route_match_delete;
		rhc->rhc_rule = "ip route-source prefix-list";
		rhc->rhc_event = RMAP_EVENT_PLIST_DELETED;

		ret = bgp_route_match_add(NULL, rhc->rhc_rmi,
					  "ip route-source prefix-list",
					  list_name, RMAP_EVENT_PLIST_ADDED);
	}

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:access-list-num
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *list_num;
	enum rmap_compile_rets ret = RMAP_COMPILE_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	list_num = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "ip route-source";
	rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "ip route-source",
				  list_num, RMAP_EVENT_FILTER_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:access-list-num-extended
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *list_num;
	enum rmap_compile_rets ret = RMAP_COMPILE_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	list_num = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "ip route-source";
	rhc->rhc_event = RMAP_EVENT_FILTER_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "ip route-source",
				  list_num, RMAP_EVENT_FILTER_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-default-route
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_create(
	struct nb_cb_create_args *args)
{
	struct routemap_hook_context *rhc;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "evpn default-route";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "evpn default-route",
				  NULL, RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-vni
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *vni;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	vni = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "evpn vni";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "evpn vni", vni,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-route-type
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "evpn route-type";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "evpn route-type", type,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:route-distinguisher
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *rd;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	rd = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "evpn rd";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, "evpn rd", rd,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath = /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard
 */
static void
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	bool exact_match = false;
	char *argstr;
	const char *condition;
	route_map_event_t event;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, "./comm-list-num");

	if (yang_dnode_exists(args->dnode, "./comm-list-num-exact-match"))
		exact_match = yang_dnode_get_bool(
			args->dnode, "./comm-list-num-exact-match");

	if (exact_match) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(value) + strlen("exact-match") + 2);

		snprintf(argstr, (strlen(value) + strlen("exact-match") + 2),
			 "%s exact-match", value);
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

	bgp_route_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, argstr, event);

	if (argstr != value)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard/comm-list-num
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard/comm-list-num-exact-match
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_exact_match_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_exact_match_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath = /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended
 */
static void
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	bool exact_match = false;
	char *argstr;
	const char *condition;
	route_map_event_t event;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, "./comm-list-num-extended");

	if (yang_dnode_exists(args->dnode,
			      "./comm-list-num-extended-exact-match"))
		exact_match = yang_dnode_get_bool(args->dnode,
				"./comm-list-num-extended-exact-match");

	if (exact_match) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(value) + strlen("exact-match") + 2);

		snprintf(argstr, (strlen(value) + strlen("exact-match") + 2),
			 "%s exact-match", value);
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

	bgp_route_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, argstr, event);

	if (argstr != value)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended/comm-list-num-extended
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended/comm-list-num-extended-exact-match
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_exact_match_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_exact_match_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath = /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list
 */
static void
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	bool exact_match = false;
	char *argstr;
	const char *condition;
	route_map_event_t event;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, "./comm-list-name");

	if (yang_dnode_exists(args->dnode, "./comm-list-name-exact-match"))
		exact_match = yang_dnode_get_bool(
			args->dnode, "./comm-list-name-exact-match");

	if (exact_match) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(value) + strlen("exact-match") + 2);

		snprintf(argstr, (strlen(value) + strlen("exact-match") + 2),
			 "%s exact-match", value);
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

	bgp_route_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, argstr, event);

	if (argstr != value)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv4-address
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	peer = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "ip next-hop address";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, peer,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv6-address
 */
static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *peer;
	enum rmap_compile_rets ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	peer = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = bgp_route_match_delete;
	rhc->rhc_rule = "ipv6 next-hop";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	ret = bgp_route_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, peer,
				  RMAP_EVENT_MATCH_ADDED);

	if (ret != RMAP_COMPILE_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:distance
 */
static int lib_route_map_entry_set_action_rmap_set_action_distance_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "distance";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "distance", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_distance_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-rt
 */
static int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "extcommunity rt";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "extcommunity rt", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-soo
 */
static int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "extcommunity soo";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "extcommunity soo", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-address
 */
static int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *addr;
	int rv = CMD_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	addr = yang_dnode_get_string(args->dnode, NULL);

	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;
	rhc->rhc_rule = "ipv4 vpn next-hop";

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, addr);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-nexthop
 */
static int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "ip next-hop";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, type);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv6-address
 */
static int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify(
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
	/* FALLTHROUGH */
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

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, addr);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:preference
 */
static int lib_route_map_entry_set_action_rmap_set_action_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	int rv = CMD_SUCCESS;
	const char *action = NULL;
	bool value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

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

		rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, NULL);
	}

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_preference_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:label-index
 */
static int lib_route_map_entry_set_action_rmap_set_action_label_index_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "label-index";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "label-index", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:local-pref
 */
static int lib_route_map_entry_set_action_rmap_set_action_local_pref_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "local-preference";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "local-preference", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_local_pref_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:weight
 */
static int lib_route_map_entry_set_action_rmap_set_action_weight_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "weight";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "weight", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_weight_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:origin
 */
static int lib_route_map_entry_set_action_rmap_set_action_origin_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "origin";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "origin", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:originator-id
 */
static int lib_route_map_entry_set_action_rmap_set_action_originator_id_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "originator-id";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "originator-id", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_originator_id_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:table
 */
static int lib_route_map_entry_set_action_rmap_set_action_table_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "table";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "table", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_table_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:atomic-aggregate
 */
static int
lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_create(
	struct nb_cb_create_args *args)
{
	struct routemap_hook_context *rhc;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "atomic-aggregate";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, NULL);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:prepend-as-path
 */
static int
lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "as-path prepend";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "as-path prepend", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:last-as
 */
static int lib_route_map_entry_set_action_rmap_set_action_last_as_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	char *argstr;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "as-path prepend";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
			 strlen(value) + strlen("last-as") + 2);

	snprintf(argstr, (strlen(value) + strlen("last-as") + 2), "last-as %s",
		 value);

	rv = generic_set_add(NULL, rhc->rhc_rmi, "as-path prepend", argstr);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
		return NB_ERR_INCONSISTENCY;
	}

	XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_last_as_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:exclude-as-path
 */
static int
lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "as-path exclude";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "as-path exclude", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-none
 */
static int lib_route_map_entry_set_action_rmap_set_action_community_none_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool none = false;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	none = yang_dnode_get_bool(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "community";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	if (none) {
		rv = generic_set_add(NULL, rhc->rhc_rmi, "community", "none");
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
		return NB_OK;
	}

	return NB_ERR_INCONSISTENCY;
}

static int
lib_route_map_entry_set_action_rmap_set_action_community_none_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-string
 */
static int
lib_route_map_entry_set_action_rmap_set_action_community_string_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "community";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "community", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_community_string_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-none
 */
static int
lib_route_map_entry_set_action_rmap_set_action_large_community_none_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	bool none = false;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	none = yang_dnode_get_bool(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "large-community";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	if (none) {
		rv = generic_set_add(NULL, rhc->rhc_rmi, "large-community",
				     "none");
		if (rv != CMD_SUCCESS) {
			rhc->rhc_shook = NULL;
			return NB_ERR_INCONSISTENCY;
		}
		return NB_OK;
	}

	return NB_ERR_INCONSISTENCY;
}

static int
lib_route_map_entry_set_action_rmap_set_action_large_community_none_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-string
 */
static int
lib_route_map_entry_set_action_rmap_set_action_large_community_string_modify(
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
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "large-community";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, "large-community", type);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_large_community_string_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * xpath =
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator
 */
static void lib_route_map_entry_set_action_rmap_set_action_aggregator_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct routemap_hook_context *rhc;
	const char *asn;
	const char *addr;
	char *argstr;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	asn = yang_dnode_get_string(args->dnode, "./aggregator-asn");
	addr = yang_dnode_get_string(args->dnode, "./aggregator-address");

	argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
			 strlen(asn) + strlen(addr) + 2);

	snprintf(argstr, (strlen(asn) + strlen(addr) + 2), "%s %s", asn, addr);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "aggregator as";
	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, argstr);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);
}
/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn
 */
static int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address
 */
static int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-num
 */
static int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	const char *action;
	int rv = CMD_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;

	action = yang_dnode_get_string(args->dnode,
				       "../../frr-route-map:action");
	if (IS_SET_COMM_LIST_DEL(action))
		rhc->rhc_rule = "comm-list";
	else
		rhc->rhc_rule = "large-comm-list";

	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, value);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-num-extended
 */
static int
lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	const char *action;
	int rv = CMD_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;

	action = yang_dnode_get_string(args->dnode,
				       "../../frr-route-map:action");
	if (IS_SET_COMM_LIST_DEL(action))
		rhc->rhc_rule = "comm-list";
	else
		rhc->rhc_rule = "large-comm-list";

	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, value);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-name
 */
static int lib_route_map_entry_set_action_rmap_set_action_comm_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *value;
	const char *action;
	int rv = CMD_SUCCESS;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;

	action = yang_dnode_get_string(args->dnode,
				       "../../frr-route-map:action");
	if (IS_SET_COMM_LIST_DEL(action))
		rhc->rhc_rule = "comm-list";
	else
		rhc->rhc_rule = "large-comm-list";

	rhc->rhc_event = RMAP_EVENT_SET_DELETED;

	rv = generic_set_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, value);

	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int
lib_route_map_entry_set_action_rmap_set_action_comm_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_route_map_info = {
	.name = "frr-bgp-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:local-preference",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_local_preference_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_local_preference_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:origin",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_origin_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_origin_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_rpki_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_rpki_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:probability",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_probability_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_probability_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-vrf",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-interface",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-local",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_local_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_local_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:list-name",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_list_name_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:access-list-num",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:access-list-num-extended",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-default-route",
			.cbs = {
				.create = lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_create,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-vni",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-route-type",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:route-distinguisher",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard",
			.cbs = {
				.apply_finish = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard/comm-list-num",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-standard/comm-list-num-exact-match",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_exact_match_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_standard_comm_list_num_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended",
			.cbs = {
				.apply_finish = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended/comm-list-num-extended",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list-extended/comm-list-num-extended-exact-match",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_exact_match_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_extended_comm_list_num_extended_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list",
			.cbs = {
				.apply_finish = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:distance",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_distance_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_distance_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-rt",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-soo",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_destroy,
			}
		},
		{
			.xpath ="/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:preference",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_preference_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_preference_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:label-index",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_label_index_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:local-pref",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_local_pref_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_local_pref_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:weight",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_weight_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_weight_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:origin",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_origin_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_origin_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:originator-id",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_originator_id_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_originator_id_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:table",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_table_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_table_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:atomic-aggregate",
			.cbs = {
				.create = lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_create,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:prepend-as-path",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:last-as",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_last_as_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_last_as_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:exclude-as-path",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-none",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_community_none_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_community_none_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-string",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_community_string_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-none",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_large_community_none_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_large_community_none_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-string",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_large_community_string_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_large_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator",
			.cbs = {
				.apply_finish = lib_route_map_entry_set_action_rmap_set_action_aggregator_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-num",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_comm_list_num_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_comm_list_num_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-num-extended",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-name",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_comm_list_name_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_comm_list_name_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
