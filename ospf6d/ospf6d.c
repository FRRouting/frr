/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "plist.h"

#include "ospf6_proto.h"
#include "ospf6_network.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_bfd.h"

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

static struct cmd_node debug_node = {
	DEBUG_NODE, "", 1 /* VTYSH */
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
	}

	return type;
}

DEFUN (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_level = 4;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;

	OSPF6_CMD_CHECK_RUNNING();

	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, NULL, NULL, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, NULL, NULL, oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, NULL, NULL, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type,
       show_ipv6_ospf6_database_type_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n"
      )
{
	int idx_lsa = 4;
	int idx_level = 5;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	level = parse_show_level(idx_level, argc, argv);

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, NULL, NULL,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, NULL, NULL,
						oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, NULL, NULL, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_id,
       show_ipv6_ospf6_database_id_cmd,
       "show ipv6 ospf6 database <*|linkstate-id> A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Search by Link state ID\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_ipv4 = 5;
	int idx_level = 6;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint32_t id = 0;

	OSPF6_CMD_CHECK_RUNNING();

	if (argv[idx_ipv4]->type == IPV4_TKN)
		inet_pton(AF_INET, argv[idx_ipv4]->arg, &id);

	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, &id, NULL, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, &id, NULL, oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, &id, NULL, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_router,
       show_ipv6_ospf6_database_router_cmd,
       "show ipv6 ospf6 database <*|adv-router> * A.B.C.D <detail|dump|internal>",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Search by Advertising Router\n"
       "Any Link state ID\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router,
					oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (show_ipv6_ospf6_database_aggr_router,
       show_ipv6_ospf6_database_aggr_router_cmd,
       "show ipv6 ospf6 database aggr adv-router A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Aggregated Router LSA\n"
       "Search by Advertising Router\n"
       "Specify Advertising Router as IPv4 address notation\n")
{
	int level = OSPF6_LSDB_SHOW_LEVEL_DETAIL;
	uint16_t type = htons(OSPF6_LSTYPE_ROUTER);
	int idx_ipv4 = 6;
	struct listnode *i;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_lsdb *lsdb;
	uint32_t adv_router = 0;

	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		if (adv_router == o->router_id)
			lsdb = oa->lsdb_self;
		else
			lsdb = oa->lsdb;
		if (ospf6_create_single_router_lsa(oa, lsdb, adv_router)
		    == NULL) {
			vty_out(vty, "Adv router is not found in LSDB.");
			return CMD_SUCCESS;
		}
		ospf6_lsdb_show(vty, level, &type, NULL, NULL,
				oa->temp_router_lsa_lsdb);
		/* Remove the temp cache */
		ospf6_remove_temp_router_lsa(oa);
	}

	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_id,
       show_ipv6_ospf6_database_type_id_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> linkstate-id A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n"
      )
{
	int idx_lsa = 4;
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t id = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, &id, NULL, oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, &id, NULL,
						oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, &id, NULL, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_router,
       show_ipv6_ospf6_database_type_router_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> <*|adv-router> A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n"
      )
{
	int idx_lsa = 4;
	int idx_ipv4 = 6;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, NULL, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, NULL,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, NULL, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_database_id_router,
       show_ipv6_ospf6_database_id_router_cmd,
       "show ipv6 ospf6 database * A.B.C.D A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      )
{
	int idx_ls_id = 5;
	int idx_adv_rtr = 6;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint32_t id = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, &id, &adv_router, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, &id, &adv_router,
					oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, &id, &adv_router, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_database_adv_router_linkstate_id,
       show_ipv6_ospf6_database_adv_router_linkstate_id_cmd,
       "show ipv6 ospf6 database adv-router A.B.C.D linkstate-id A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Search by Advertising Router\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Search by Link state ID\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_adv_rtr = 5;
	int idx_ls_id = 7;
	int idx_level = 8;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint32_t id = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, &id, &adv_router, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, &id, &adv_router,
					oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, &id, &adv_router, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_id_router,
       show_ipv6_ospf6_database_type_id_router_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> A.B.C.D A.B.C.D [<dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_ls_id = 5;
	int idx_adv_rtr = 6;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t id = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	level = parse_show_level(idx_level, argc, argv);

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, &id, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, &id,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, &id, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_database_type_adv_router_linkstate_id,
       show_ipv6_ospf6_database_type_adv_router_linkstate_id_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> adv-router A.B.C.D linkstate-id A.B.C.D [<dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_adv_rtr = 6;
	int idx_ls_id = 8;
	int idx_level = 9;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t id = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_adv_rtr]->arg, &adv_router);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, &id, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, &id,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, &id, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_self_originated,
       show_ipv6_ospf6_database_self_originated_cmd,
       "show ipv6 ospf6 database self-originated [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Self-originated LSAs\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_level = 5;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();
	level = parse_show_level(idx_level, argc, argv);
	adv_router = o->router_id;

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
		ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router, oa->lsdb);
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			vty_out(vty, IF_LSDB_TITLE_FORMAT, oi->interface->name,
				oa->name);
			ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router,
					oi->lsdb);
		}
	}

	vty_out(vty, AS_LSDB_TITLE_FORMAT);
	ospf6_lsdb_show(vty, level, NULL, NULL, &adv_router, o->lsdb);

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_database_type_self_originated,
       show_ipv6_ospf6_database_type_self_originated_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> self-originated [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_level = 6;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t adv_router = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	level = parse_show_level(idx_level, argc, argv);

	adv_router = o->router_id;

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, NULL, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, NULL,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, NULL, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_self_originated_linkstate_id,
       show_ipv6_ospf6_database_type_self_originated_linkstate_id_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> self-originated linkstate-id A.B.C.D [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_ls_id = 7;
	int idx_level = 8;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	uint32_t id = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);
	adv_router = o->router_id;

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, &id, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, &id,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, &id, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_id_self_originated,
       show_ipv6_ospf6_database_type_id_self_originated_cmd,
       "show ipv6 ospf6 database <router|network|inter-prefix|inter-router|as-external|group-membership|type-7|link|intra-prefix> A.B.C.D self-originated [<detail|dump|internal>]",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
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
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_ls_id = 5;
	int idx_level = 7;
	int level;
	struct listnode *i, *j;
	struct ospf6 *o = ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	uint16_t type = 0;
	uint32_t adv_router = 0;
	uint32_t id = 0;

	OSPF6_CMD_CHECK_RUNNING();

	type = parse_type_spec(idx_lsa, argc, argv);
	inet_pton(AF_INET, argv[idx_ls_id]->arg, &id);
	level = parse_show_level(idx_level, argc, argv);
	adv_router = o->router_id;

	switch (OSPF6_LSA_SCOPE(type)) {
	case OSPF6_SCOPE_AREA:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			vty_out(vty, AREA_LSDB_TITLE_FORMAT, oa->name);
			ospf6_lsdb_show(vty, level, &type, &id, &adv_router,
					oa->lsdb);
		}
		break;

	case OSPF6_SCOPE_LINKLOCAL:
		for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				vty_out(vty, IF_LSDB_TITLE_FORMAT,
					oi->interface->name, oa->name);
				ospf6_lsdb_show(vty, level, &type, &id,
						&adv_router, oi->lsdb);
			}
		}
		break;

	case OSPF6_SCOPE_AS:
		vty_out(vty, AS_LSDB_TITLE_FORMAT);
		ospf6_lsdb_show(vty, level, &type, &id, &adv_router, o->lsdb);
		break;

	default:
		assert(0);
		break;
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_border_routers,
       show_ipv6_ospf6_border_routers_cmd,
       "show ipv6 ospf6 border-routers [<A.B.C.D|detail>]",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Display routing table for ABR and ASBR\n"
       "Router ID\n"
       "Show detailed output\n")
{
	int idx_ipv4 = 4;
	uint32_t adv_router;
	struct ospf6_route *ro;
	struct prefix prefix;

	OSPF6_CMD_CHECK_RUNNING();

	if (argc == 5) {
		if (strmatch(argv[idx_ipv4]->text, "detail")) {
			for (ro = ospf6_route_head(ospf6->brouter_table); ro;
			     ro = ospf6_route_next(ro))
				ospf6_route_show_detail(vty, ro);
		} else {
			inet_pton(AF_INET, argv[idx_ipv4]->arg, &adv_router);

			ospf6_linkstate_prefix(adv_router, 0, &prefix);
			ro = ospf6_route_lookup(&prefix, ospf6->brouter_table);
			if (!ro) {
				vty_out(vty,
					"No Route found for Router ID: %s\n",
					argv[4]->arg);
				return CMD_SUCCESS;
			}

			ospf6_route_show_detail(vty, ro);
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


DEFUN (show_ipv6_ospf6_linkstate,
       show_ipv6_ospf6_linkstate_cmd,
       "show ipv6 ospf6 linkstate <router A.B.C.D|network A.B.C.D A.B.C.D>",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Display linkstate routing table\n"
       "Display Router Entry\n"
       "Specify Router ID as IPv4 address notation\n"
       "Display Network Entry\n"
       "Specify Router ID as IPv4 address notation\n"
       "Specify Link state ID as IPv4 address notation\n")
{
	int idx_ipv4 = 5;
	struct listnode *node;
	struct ospf6_area *oa;

	OSPF6_CMD_CHECK_RUNNING();

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		vty_out(vty, "\n        SPF Result in Area %s\n\n", oa->name);
		ospf6_linkstate_table_show(vty, idx_ipv4, argc, argv,
					   oa->spf_table);
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_linkstate_detail,
       show_ipv6_ospf6_linkstate_detail_cmd,
       "show ipv6 ospf6 linkstate detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Display linkstate routing table\n"
       "Display detailed information\n")
{
	int idx_detail = 4;
	struct listnode *node;
	struct ospf6_area *oa;

	OSPF6_CMD_CHECK_RUNNING();

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		vty_out(vty, "\n        SPF Result in Area %s\n\n", oa->name);
		ospf6_linkstate_table_show(vty, idx_detail, argc, argv,
					   oa->spf_table);
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

static void ospf6_plist_add(struct prefix_list *plist)
{
	if (prefix_list_afi(plist) != AFI_IP6)
		return;
	ospf6_area_plist_update(plist, 1);
}

static void ospf6_plist_del(struct prefix_list *plist)
{
	if (prefix_list_afi(plist) != AFI_IP6)
		return;
	ospf6_area_plist_update(plist, 0);
}

/* Install ospf related commands. */
void ospf6_init(void)
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

	prefix_list_add_hook(ospf6_plist_add);
	prefix_list_delete_hook(ospf6_plist_del);

	ospf6_bfd_init();
	install_node(&debug_node, config_write_ospf6_debug);

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

	install_element_ospf6_clear_interface();

	install_element(VIEW_NODE, &show_debugging_ospf6_cmd);

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

	/* Make ospf protocol socket. */
	ospf6_serv_sock();
	thread_add_read(master, ospf6_receive, NULL, ospf6_sock, NULL);
}

void ospf6_clean(void)
{
	if (!ospf6)
		return;
	if (ospf6->route_table)
		ospf6_route_remove_all(ospf6->route_table);
	if (ospf6->brouter_table)
		ospf6_route_remove_all(ospf6->brouter_table);
}
