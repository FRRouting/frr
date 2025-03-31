// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_top.h"
#include "ospf6_network.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_spf.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_bfd.h"
#include "ospf6_tlv.h"
#include "ospf6_gr.h"
#include "lib/json.h"
#include "ospf6_nssa.h"
#include "ospf6_auth_trailer.h"
#include "ospf6d/ospf6d_clippy.c"

DEFINE_MGROUP(OSPF6D, "ospf6d");

/* OSPF6 config processing timer thread */
struct event *t_ospf6_cfg;

/* OSPF6 debug event state */
unsigned char conf_debug_ospf6_event;

struct route_node *route_prev(struct route_node *node)
{
	struct route_node *end;
	struct route_node *prev = NULL;

	end = node;
	node = node->parent;
	if (node)
		route_lock_node(node);
	while (node) {
		prev = node;
		node = route_next(node);
		if (node == end) {
			route_unlock_node(node);
			node = NULL;
		}
	}
	route_unlock_node(end);
	if (prev)
		route_lock_node(prev);

	return prev;
}

static int config_write_ospf6_debug(struct vty *vty);
static int config_write_ospf6_debug_event(struct vty *vty);
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_ospf6_debug,
};

static int config_write_ospf6_debug(struct vty *vty)
{
	config_write_ospf6_debug_message(vty);
	config_write_ospf6_debug_lsa(vty);
	config_write_ospf6_debug_zebra(vty);
	config_write_ospf6_debug_interface(vty);
	config_write_ospf6_debug_neighbor(vty);
	config_write_ospf6_debug_spf(vty);
	config_write_ospf6_debug_route(vty);
	config_write_ospf6_debug_brouter(vty);
	config_write_ospf6_debug_asbr(vty);
	config_write_ospf6_debug_abr(vty);
	config_write_ospf6_debug_flood(vty);
	config_write_ospf6_debug_nssa(vty);
	config_write_ospf6_debug_gr_helper(vty);
	config_write_ospf6_debug_auth(vty);
	config_write_ospf6_debug_event(vty);

	return 0;
}

DEFUN_NOSH (show_debugging_ospf6,
	    show_debugging_ospf6_cmd,
	    "show debugging [ospf6]",
	    SHOW_STR
	    DEBUG_STR
	    OSPF6_STR)
{
	vty_out(vty, "OSPF6 debugging status:\n");

	config_write_ospf6_debug(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

#define AREA_LSDB_TITLE_FORMAT                                                 \
	"\n        Area Scoped Link State Database (Area %s)\n\n"
#define IF_LSDB_TITLE_FORMAT                                                   \
	"\n        I/F Scoped Link State Database (I/F %s in Area %s)\n\n"
#define AS_LSDB_TITLE_FORMAT "\n        AS Scoped Link State Database\n\n"

static int parse_show_level(int idx_level, int argc, struct cmd_token **argv)
{
	int level = OSPF6_LSDB_SHOW_LEVEL_NORMAL;

	if (argc > idx_level) {
		if (strmatch(argv[idx_level]->text, "detail"))
			level = OSPF6_LSDB_SHOW_LEVEL_DETAIL;
		else if (strmatch(argv[idx_level]->text, "dump"))
			level = OSPF6_LSDB_SHOW_LEVEL_DUMP;
		else if (strmatch(argv[idx_level]->text, "internal"))
			level = OSPF6_LSDB_SHOW_LEVEL_INTERNAL;
	}

	return level;
}

static uint16_t parse_type_spec(int idx_lsa, int argc, struct cmd_token **argv)
{
	uint16_t type = 0;

	if (argc > idx_lsa) {
		if (strmatch(argv[idx_lsa]->text, "router"))
			type = htons(OSPF6_LSTYPE_ROUTER);
		else if (strmatch(argv[idx_lsa]->text, "network"))
			type = htons(OSPF6_LSTYPE_NETWORK);
		else if (strmatch(argv[idx_lsa]->text, "as-external"))
			type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
		else if (strmatch(argv[idx_lsa]->text, "intra-prefix"))
			type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
		else if (strmatch(argv[idx_lsa]->text, "inter-router"))
			type = htons(OSPF6_LSTYPE_INTER_ROUTER);
		else if (strmatch(argv[idx_lsa]->text, "inter-prefix"))
			type = htons(OSPF6_LSTYPE_INTER_PREFIX);
		else if (strmatch(argv[idx_lsa]->text, "link"))
			type = htons(OSPF6_LSTYPE_LINK);
		else if (strmatch(argv[idx_lsa]->text, "type-7"))
			type = htons(OSPF6_LSTYPE_TYPE_7);
	}

	return type;
}

void ospf6_lsdb_show(struct vty *vty, enum ospf_lsdb_show_level level,
		     uint16_t *type, uint32_t *id, uint32_t *adv_router,
		     struct ospf6_lsdb *lsdb, json_object *json_obj,
		     bool use_json)
{
	struct ospf6_lsa *lsa;
	const struct route_node *end = NULL;
	void (*showfunc)(struct vty *, struct ospf6_lsa *, json_object *,
			 bool) = NULL;
	json_object *json_array = NULL;

	switch (level) {
	case OSPF6_LSDB_SHOW_LEVEL_DETAIL:
		showfunc = ospf6_lsa_show;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_INTERNAL:
		showfunc = ospf6_lsa_show_internal;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_DUMP:
		showfunc = ospf6_lsa_show_dump;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_NORMAL:
	default:
		showfunc = ospf6_lsa_show_summary;
	}

	if (use_json)
		json_array = json_object_new_array();

	if (type && id && adv_router) {
		lsa = ospf6_lsdb_lookup(*type, *id, *adv_router, lsdb);
		if (lsa) {
			if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
				ospf6_lsa_show(vty, lsa, json_array, use_json);
			else
				(*showfunc)(vty, lsa, json_array, use_json);
		}

		if (use_json)
			json_object_object_add(json_obj, "lsa", json_array);
		return;
	}

	if ((level == OSPF6_LSDB_SHOW_LEVEL_NORMAL) && !use_json)
		ospf6_lsa_show_summary_header(vty);

	end = ospf6_lsdb_head(lsdb, !!type + !!(type && adv_router),
			      type ? *type : 0, adv_router ? *adv_router : 0,
			      &lsa);
	while (lsa) {
		if ((!adv_router || lsa->header->adv_router == *adv_router)
		    && (!id || lsa->header->id == *id))
			(*showfunc)(vty, lsa, json_array, use_json);
		lsa = ospf6_lsdb_next(end, lsa);
	}

	if (use_json)
		json_object_object_add(json_obj, "lsa", json_array);
}

static void ospf6_lsdb_show_wrapper(struct vty *vty,
				    enum ospf_lsdb_show_level level,
				    uint16_t *type, uint32_t *id,
				    uint32_t *adv_router, bool uj,
				    struct ospf6 *ospf6)
{
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	json_object *json = NULL;
	json_object *json_array = NULL;
	json_object *json_obj = NULL;

	if (uj) {
		json = json_object_new_object();
		json_array = json_object_new_array();
	}
	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		if (uj) {
			json_obj = json_object_new_object();
			json_object_string_add(json_obj, "areaId", oa->name);
		} else
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, type, id, adv_router, oa->lsdb,
				json_obj, uj);
		if (uj)
			json_object_array_add(json_array, json_obj);
	}
	if (uj)
		json_object_object_add(json, "areaScopedLinkStateDb",
				       json_array);

	if (uj)
		json_array = json_object_new_array();
	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			if (uj) {
				json_obj = json_object_new_object();
				json_object_string_add(json_obj, "areaId",
						       oa->name);
				json_object_string_add(json_obj, "interface",
						       oi->interface->name);
			} else
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
			ospf6_lsdb_show(vty, level, type, id, adv_router,
					oi->lsdb, json_obj, uj);
			if (uj)
				json_object_array_add(json_array, json_obj);
		}
	}
	if (uj)
		json_object_object_add(json, "interfaceScopedLinkStateDb",
				       json_array);
	if (uj) {
		json_array = json_object_new_array();
		json_obj = json_object_new_object();
	} else
		vty_out(vty, AS_LSDB_TITLE_FORMAT);

	ospf6_lsdb_show(vty, level, type, id, adv_router, o->lsdb, json_obj,
			uj);

	if (uj) {
		json_object_array_add(json_array, json_obj);
		json_object_object_add(json, "asScopedLinkStateDb", json_array);

		vty_json(vty, json);
	} else
		vty_out(vty, "\n");
}

static void ospf6_lsdb_type_show_wrapper(struct vty *vty,
					 enum ospf_lsdb_show_level level,
					 uint16_t *type, uint32_t *id,
					 uint32_t *adv_router, bool uj,
					 struct ospf6 *ospf6)
{
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	json_object *json = NULL;
	json_object *json_array = NULL;
	json_object *json_obj = NULL;

	if (uj) {
		json = json_object_new_object();
		json_array = json_object_new_array();
	}

	switch (OSPF6_LSA_SCOPE(*type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			if (uj) {
				json_obj = json_object_new_object();
				json_object_string_add(json_obj, "areaId",
						       oa->name);
			} else
				vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);

			ospf6_lsdb_show(vty, level, type, id, adv_router,
					oa->lsdb, json_obj, uj);
			if (uj)
				json_object_array_add(json_array, json_obj);
		}
		if (uj)
			json_object_object_add(json, "areaScopedLinkStateDb",
					       json_array);
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				if (uj) {
					json_obj = json_object_new_object();
					json_object_string_add(
						json_obj, "areaId", oa->name);
					json_object_string_add(
						json_obj, "interface",
						oi->interface->name);
				} else
					vty_out(vty, IF_LSDB_TITLE_FORMAT,
						oi->interface->name, oa->name);

				ospf6_lsdb_show(vty, level, type, id,
						adv_router, oi->lsdb, json_obj,
						uj);

				if (uj)
					json_object_array_add(json_array,
							      json_obj);
			}
		}
		if (uj)
			json_object_object_add(
				json, "interfaceScopedLinkStateDb", json_array);
		break;

	case OSPF6_SCOPE_AS:
		if (uj)
			json_obj = json_object_new_object();
		else
			vty_out(vty, AS_LSDB_TITLE_FORMAT);

		ospf6_lsdb_show(vty, level, type, id, adv_router, o->lsdb,
				json_obj, uj);
		if (uj) {
			json_object_array_add(json_array, json_obj);
			json_object_object_add(json, "asScopedLinkStateDb",
					       json_array);
		}
		break;

	default:
		assert(0);
		break;
	}
	if (uj)
		vty_json(vty, json);
	else
		vty_out(vty, "\n");
}

DEFUN(show_ipv6_ospf6_database, show_ipv6_ospf6_database_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int level;
	int idx_level = 4;
	struct listnode *node;
	struct ospf6 *ospf6;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_level += 2;

	level = parse_show_level(idx_level, argc, argv);
	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, NULL, NULL,
						uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type, show_ipv6_ospf6_database_type_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_level = 5;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_type_show_wrapper(vty, level, &type, NULL,
						     NULL, uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_id, show_ipv6_ospf6_database_id_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <*|linkstate-id> A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Any Link state Type\n"
      "Search by Link state ID\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_ipv4 = 5;
	int idx_level = 6;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint32_t id = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (argv[idx_ipv4]->type == IPV4_TKN)
		inet_pton(AF_INET, argv[idx_ipv4]->arg, &id);

	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, &id, NULL, uj,
						ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_router, show_ipv6_ospf6_database_router_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <*|adv-router> * A.B.C.D <detail|dump|internal> [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Any Link state Type\n"
      "Search by Advertising Router\n"
      "Any Link state ID\n"
      "Specify Advertising Router as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	struct listnode *node;
	struct ospf6 *ospf6;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_ipv4 += 2;
		idx_level += 2;
	}

	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, NULL,
						&adv_router, uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int ipv6_ospf6_database_aggr_router_common(struct vty *vty,
						  uint32_t adv_router,
						  struct ospf6 *ospf6)
{
	int level = OSPF6_LSDB_SHOW_LEVEL_DETAIL;
	uint16_t type = htons(OSPF6_LSTYPE_ROUTER);
	struct listnode *i;
	struct ospf6_area *oa;
	struct ospf6_lsdb *lsdb;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa)) {
		if (adv_router == ospf6->router_id)
			lsdb = oa->lsdb_self;
		else
			lsdb = oa->lsdb;
		if (ospf6_create_single_router_lsa(oa, lsdb, adv_router)
		    == NULL) {
			vty_out(vty, "Adv router is not found in LSDB.");
			return CMD_SUCCESS;
		}
		ospf6_lsdb_show(vty, level, &type, NULL, NULL,
				oa->temp_router_lsa_lsdb, NULL, false);
		/* Remove the temp cache */
		ospf6_remove_temp_router_lsa(oa);
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(
	show_ipv6_ospf6_database_aggr_router,
	show_ipv6_ospf6_database_aggr_router_cmd,
	"show ipv6 ospf6 [vrf <NAME|all>] database aggr adv-router A.B.C.D",
	SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
	"All VRFs\n"
	"Display Link state database\n"
	"Aggregated Router LSA\n"
	"Search by Advertising Router\n"
	"Specify Advertising Router as IPv4 address notation\n")
{
	int idx_ipv4 = 6;
	struct listnode *node;
	struct ospf6 *ospf6;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_ipv4 += 2;

	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ipv6_ospf6_database_aggr_router_common(vty, adv_router,
							       ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type_id, show_ipv6_ospf6_database_type_id_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> linkstate-id A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Search by Link state ID\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t id = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_ipv4 += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_type_show_wrapper(vty, level, &type, &id,
						     NULL, uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type_router,
      show_ipv6_ospf6_database_type_router_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> <*|adv-router> A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Any Link state ID\n"
      "Search by Advertising Router\n"
      "Specify Advertising Router as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_ipv4 += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_type_show_wrapper(vty, level, &type, NULL,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_id_router,
      show_ipv6_ospf6_database_id_router_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database * A.B.C.D A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Any Link state Type\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Specify Advertising Router as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_ls_id = 5;
	int idx_adv_rtr = 6;
	int idx_level = 7;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint32_t id = 0;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_ls_id += 2;
		idx_adv_rtr += 2;
		idx_level += 2;
	}

	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, &id,
						&adv_router, uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_adv_router_linkstate_id,
      show_ipv6_ospf6_database_adv_router_linkstate_id_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database adv-router A.B.C.D linkstate-id A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Search by Advertising Router\n"
      "Specify Advertising Router as IPv4 address notation\n"
      "Search by Link state ID\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_adv_rtr = 5;
	int idx_ls_id = 7;
	int idx_level = 8;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint32_t id = 0;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_adv_rtr += 2;
		idx_ls_id += 2;
		idx_level += 2;
	}
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, &id,
						&adv_router, uj, ospf6);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type_id_router,
      show_ipv6_ospf6_database_type_id_router_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> A.B.C.D A.B.C.D [<dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Specify Advertising Router as IPv4 address notation\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_ls_id = 5;
	int idx_adv_rtr = 6;
	int idx_level = 7;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t id = 0;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_ls_id += 2;
		idx_adv_rtr += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_type_show_wrapper(vty, level, &type, &id,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_database_type_adv_router_linkstate_id,
       show_ipv6_ospf6_database_type_adv_router_linkstate_id_cmd,
       "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> adv-router A.B.C.D linkstate-id A.B.C.D [<dump|internal>] [json]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Search by Advertising Router\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Search by Link state ID\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
       JSON_STR)
{
	int idx_lsa = 4;
	int idx_adv_rtr = 6;
	int idx_ls_id = 8;
	int idx_level = 9;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t id = 0;
	uint32_t adv_router = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_adv_rtr += 2;
		idx_ls_id += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_type_show_wrapper(vty, level, &type, &id,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_self_originated,
      show_ipv6_ospf6_database_self_originated_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database self-originated [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Self-originated LSAs\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_level = 5;
	int level;
	struct listnode *node;
	struct ospf6 *ospf6;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	uint32_t adv_router = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_level += 2;

	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		adv_router = ospf6->router_id;
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_lsdb_show_wrapper(vty, level, NULL, NULL,
						&adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}


DEFUN(show_ipv6_ospf6_database_type_self_originated,
      show_ipv6_ospf6_database_type_self_originated_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> self-originated [<detail|dump|internal>]  [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Display Self-originated LSAs\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_level = 6;
	int level;
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	bool uj = use_json(argc, argv);

	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			adv_router = ospf6->router_id;
			ospf6_lsdb_type_show_wrapper(vty, level, &type, NULL,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type_self_originated_linkstate_id,
      show_ipv6_ospf6_database_type_self_originated_linkstate_id_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> self-originated linkstate-id A.B.C.D [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Display Self-originated LSAs\n"
      "Search by Link state ID\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_ls_id = 7;
	int idx_level = 8;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	uint32_t id = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_ls_id += 2;
		idx_level += 2;
	}


	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			adv_router = ospf6->router_id;
			ospf6_lsdb_type_show_wrapper(vty, level, &type, &id,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_database_type_id_self_originated,
      show_ipv6_ospf6_database_type_id_self_originated_cmd,
      "show ipv6 ospf6  [vrf <NAME|all>] database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> A.B.C.D self-originated [<detail|dump|internal>] [json]",
      SHOW_STR IPV6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display Link state database\n"
      "Display Router LSAs\n"
      "Display Network LSAs\n"
      "Display Inter-Area-Prefix LSAs\n"
      "Display Inter-Area-Router LSAs\n"
      "Display As-External LSAs\n"
      "Display Group-Membership LSAs\n"
      "Display Type-7 LSAs\n"
      "Display Link LSAs\n"
      "Display Intra-Area-Prefix LSAs\n"
      "Specify Link state ID as IPv4 address notation\n"
      "Display Self-originated LSAs\n"
      "Display details of LSAs\n"
      "Dump LSAs\n"
      "Display LSA's internal information\n" JSON_STR)
{
	int idx_lsa = 4;
	int idx_ls_id = 5;
	int idx_level = 7;
	int level;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	uint32_t id = 0;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_lsa += 2;
		idx_ls_id += 2;
		idx_level += 2;
	}

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			adv_router = ospf6->router_id;
			ospf6_lsdb_type_show_wrapper(vty, level, &type, &id,
						     &adv_router, uj, ospf6);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int show_ospf6_border_routers_common(struct vty *vty, int argc,
					    struct cmd_token **argv,
					    struct ospf6 *ospf6, int idx_ipv4,
					    int idx_argc)
{
	uint32_t adv_router;
	struct ospf6_route *ro;
	struct prefix prefix;


	if (argc == idx_argc) {
		if (strmatch(argv[idx_ipv4]->text, "detail")) {
			for (ro = ospf6_route_head(ospf6->brouter_table); ro;
			     ro = ospf6_route_next(ro))
				ospf6_route_show_detail(vty, ro, NULL, false);
		} else {
			inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);

			ospf6_linkstate_prefix(adv_router, 0, &prefix);
			ro = ospf6_route_lookup(&prefix, ospf6->brouter_table);
			if (!ro) {
				vty_out(vty,
					"No Route found for Router ID: %s\n",
					argv[idx_ipv4]->arg);
				return CMD_SUCCESS;
			}

			ospf6_route_show_detail(vty, ro, NULL, false);
			return CMD_SUCCESS;
		}
	} else {
		ospf6_brouter_show_header(vty);

		for (ro = ospf6_route_head(ospf6->brouter_table); ro;
		     ro = ospf6_route_next(ro))
			ospf6_brouter_show(vty, ro);
	}

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_border_routers, show_ipv6_ospf6_border_routers_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] border-routers [<A.B.C.D|detail>]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display routing table for ABR and ASBR\n"
      "Router ID\n"
      "Show detailed output\n")
{
	int idx_ipv4 = 4;
	struct ospf6 *ospf6 = NULL;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_argc = 5;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_argc += 2;
		idx_ipv4 += 2;
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			show_ospf6_border_routers_common(vty, argc, argv, ospf6,
							 idx_ipv4, idx_argc);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}


DEFUN(show_ipv6_ospf6_linkstate, show_ipv6_ospf6_linkstate_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] linkstate <router A.B.C.D|network A.B.C.D A.B.C.D>",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display linkstate routing table\n"
      "Display Router Entry\n"
      "Specify Router ID as IPv4 address notation\n"
      "Display Network Entry\n"
      "Specify Router ID as IPv4 address notation\n"
      "Specify Link state ID as IPv4 address notation\n")
{
	int idx_ipv4 = 5;
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6 *ospf6 = NULL;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_ipv4 += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, nnode, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
				vty_out(vty,
					"\n        SPF Result in Area %s\n\n",
					oa->name);
				ospf6_linkstate_table_show(vty, idx_ipv4, argc,
							   argv, oa->spf_table);
			}
			vty_out(vty, "\n");

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}


DEFUN(show_ipv6_ospf6_linkstate_detail, show_ipv6_ospf6_linkstate_detail_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] linkstate detail",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Display linkstate routing table\n"
      "Display detailed information\n")
{
	int idx_detail = 4;
	struct listnode *node;
	struct ospf6_area *oa;
	struct ospf6 *ospf6 = NULL;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_detail += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
				vty_out(vty,
					"\n        SPF Result in Area %s\n\n",
					oa->name);
				ospf6_linkstate_table_show(vty, idx_detail,
							   argc, argv,
							   oa->spf_table);
			}
			vty_out(vty, "\n");

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFPY(debug_ospf6_event, debug_ospf6_event_cmd, "[no] debug ospf6 event",
      NO_STR DEBUG_STR OSPF6_STR "Debug OSPFv3 event function\n")
{
	if (!no)
		OSPF6_DEBUG_EVENT_ON();
	else
		OSPF6_DEBUG_EVENT_OFF();
	return CMD_SUCCESS;
}

static int config_write_ospf6_debug_event(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_EVENT)
		vty_out(vty, "debug ospf6 event\n");
	return 0;
}

static void install_element_ospf6_debug_event(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_event_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_event_cmd);
}

/* Install ospf related commands. */
void ospf6_init(struct event_loop *master)
{
	ospf6_top_init();
	ospf6_area_init();
	ospf6_interface_init();
	ospf6_neighbor_init();
	ospf6_zebra_init(master);

	ospf6_lsa_init();
	ospf6_spf_init();
	ospf6_intra_init();
	ospf6_asbr_init();
	ospf6_abr_init();
	ospf6_gr_init();
	ospf6_gr_helper_config_init();

	/* initialize hooks for modifying filter rules */
	prefix_list_add_hook(ospf6_plist_update);
	prefix_list_delete_hook(ospf6_plist_update);
	access_list_add_hook(ospf6_filter_update);
	access_list_delete_hook(ospf6_filter_update);

	ospf6_bfd_init();
	install_node(&debug_node);

	install_element_ospf6_debug_message();
	install_element_ospf6_debug_lsa();
	install_element_ospf6_debug_interface();
	install_element_ospf6_debug_neighbor();
	install_element_ospf6_debug_zebra();
	install_element_ospf6_debug_spf();
	install_element_ospf6_debug_route();
	install_element_ospf6_debug_brouter();
	install_element_ospf6_debug_asbr();
	install_element_ospf6_debug_abr();
	install_element_ospf6_debug_flood();
	install_element_ospf6_debug_nssa();

	install_element_ospf6_clear_process();
	install_element_ospf6_clear_interface();

	install_element(ENABLE_NODE, &show_debugging_ospf6_cmd);

	install_element(VIEW_NODE, &show_ipv6_ospf6_border_routers_cmd);

	install_element(VIEW_NODE, &show_ipv6_ospf6_linkstate_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_linkstate_detail_cmd);

	install_element(VIEW_NODE, &show_ipv6_ospf6_database_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_type_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_id_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_router_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_type_id_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_type_router_cmd);
	install_element(VIEW_NODE,
			&show_ipv6_ospf6_database_adv_router_linkstate_id_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_id_router_cmd);
	install_element(VIEW_NODE,
			&show_ipv6_ospf6_database_type_id_router_cmd);
	install_element(
		VIEW_NODE,
		&show_ipv6_ospf6_database_type_adv_router_linkstate_id_cmd);
	install_element(VIEW_NODE,
			&show_ipv6_ospf6_database_self_originated_cmd);
	install_element(VIEW_NODE,
			&show_ipv6_ospf6_database_type_self_originated_cmd);
	install_element(VIEW_NODE,
			&show_ipv6_ospf6_database_type_id_self_originated_cmd);
	install_element(
		VIEW_NODE,
		&show_ipv6_ospf6_database_type_self_originated_linkstate_id_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_database_aggr_router_cmd);
	install_element_ospf6_debug_event();
	install_element_ospf6_debug_auth();
	ospf6_interface_auth_trailer_cmd_init();
	install_element_ospf6_clear_intf_auth();
}
