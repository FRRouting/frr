/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "srv6.h"
#include "lib/json.h"

#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_srv6_vty.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"

#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_srv6_vty_clippy.c"
#endif

static int zebra_sr_config(struct vty *vty);

static struct cmd_node sr_node = {
	.name = "sr",
	.node = SEGMENT_ROUTING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-sr)# ",
	.config_write = zebra_sr_config,
};

static struct cmd_node srv6_node = {
	.name = "srv6",
	.node = SRV6_NODE,
	.parent_node = SEGMENT_ROUTING_NODE,
	.prompt = "%s(config-srv6)# ",

};

static struct cmd_node srv6_locs_node = {
	.name = "srv6-locators",
	.node = SRV6_LOCS_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-locators)# ",
};

static struct cmd_node srv6_loc_node = {
	.name = "srv6-locator",
	.node = SRV6_LOC_NODE,
	.parent_node = SRV6_LOCS_NODE,
	.prompt = "%s(config-srv6-locator)# "
};

DEFUN (show_srv6_locator,
       show_srv6_locator_cmd,
       "show segment-routing srv6 locator [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Locator Information\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;
	char str[256];
	int id;
	json_object *json = NULL;
	json_object *json_locators = NULL;
	json_object *json_locator = NULL;

	if (uj) {
		json = json_object_new_object();
		json_locators = json_object_new_array();
		json_object_object_add(json, "locators", json_locators);

		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			json_locator = srv6_locator_json(locator);
			if (!json_locator)
				continue;
			json_object_array_add(json_locators, json_locator);

		}

		vty_out(vty, "%s\n", json_object_to_json_string_ext(json,
					JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		vty_out(vty, "Locator:\n");
		vty_out(vty, "Name                 ID      Prefix                   Status\n");
		vty_out(vty, "-------------------- ------- ------------------------ -------\n");

		id = 1;
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			prefix2str(&locator->prefix, str, sizeof(str));
			vty_out(vty, "%-20s %7d %-24s %s\n",
				locator->name, id, str,
				locator->status_up ? "Up" : "Down");
			++id;
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_srv6_locator_detail,
       show_srv6_locator_detail_cmd,
       "show segment-routing srv6 locator NAME detail [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Locator Information\n"
       "Locator Name\n"
       "Detailed information\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;
	char str[256];
	const char *locator_name = argv[4]->arg;

	if (uj) {
		vty_out(vty, "JSON format isn't supported\n");
		return CMD_WARNING;
	}

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
		struct listnode *node;
		struct srv6_locator_chunk *chunk;

		if (strcmp(locator->name, locator_name) != 0)
			continue;

		prefix2str(&locator->prefix, str, sizeof(str));
		vty_out(vty, "Name: %s\n", locator->name);
		vty_out(vty, "Prefix: %s\n", str);
		vty_out(vty, "Function-Bit-Len: %u\n",
			locator->function_bits_length);

		vty_out(vty, "Chunks:\n");
		for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, node,
					  chunk)) {
			prefix2str(&chunk->prefix, str, sizeof(str));
			vty_out(vty, "- prefix: %s, owner: %s\n", str,
				zebra_route_string(chunk->proto));
		}
	}


	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing,
            segment_routing_cmd,
            "segment-routing",
            "Segment Routing\n")
{
	vty->node = SEGMENT_ROUTING_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6,
            srv6_cmd,
            "srv6",
            "Segment Routing SRv6\n")
{
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN (no_srv6,
       no_srv6_cmd,
       "no srv6",
       NO_STR
       "Segment Routing SRv6\n")
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(srv6->locators, node, nnode, locator))
		zebra_srv6_locator_delete(locator);
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locators,
            srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locator,
            srv6_locator_cmd,
            "locator WORD",
            "Segment Routing SRv6 locator\n"
            "Specify locator-name\n")
{
	struct srv6_locator *locator = NULL;

	locator = zebra_srv6_locator_lookup(argv[1]->arg);
	if (locator) {
		VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
		locator->status_up = true;
		return CMD_SUCCESS;
	}

	locator = srv6_locator_alloc(argv[1]->arg);
	if (!locator) {
		vty_out(vty, "%% Alloc failed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	locator->status_up = true;

	VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator);
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

DEFUN (no_srv6_locator,
       no_srv6_locator_cmd,
       "no locator WORD",
       NO_STR
       "Segment Routing SRv6 locator\n"
       "Specify locator-name\n")
{
	struct srv6_locator *locator = zebra_srv6_locator_lookup(argv[2]->arg);
	if (!locator) {
		vty_out(vty, "%% Can't find SRv6 locator\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	zebra_srv6_locator_delete(locator);
	return CMD_SUCCESS;
}

DEFPY (locator_prefix,
       locator_prefix_cmd,
       "prefix X:X::X:X/M$prefix [func-bits (16-64)$func_bit_len]",
       "Configure SRv6 locator prefix\n"
       "Specify SRv6 locator prefix\n"
       "Configure SRv6 locator function length in bits\n"
       "Specify SRv6 locator function length in bits\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct srv6_locator_chunk *chunk = NULL;
	struct listnode *node = NULL;

	locator->prefix = *prefix;

	/*
	 * TODO(slankdev): please support variable node-bit-length.
	 * In draft-ietf-bess-srv6-services-05#section-3.2.1.
	 * Locator block length and Locator node length are defined.
	 * Which are defined as "locator-len == block-len + node-len".
	 * In current implementation, node bits length is hardcoded as 24.
	 * It should be supported various val.
	 *
	 * Cisco IOS-XR support only following pattern.
	 *  (1) Teh locator length should be 64-bits long.
	 *  (2) The SID block portion (MSBs) cannot exceed 40 bits.
	 *      If this value is less than 40 bits,
	 *      user should use a pattern of zeros as a filler.
	 *  (3) The Node Id portion (LSBs) cannot exceed 24 bits.
	 */
	locator->block_bits_length = prefix->prefixlen - 24;
	locator->node_bits_length = 24;
	locator->function_bits_length = func_bit_len;
	locator->argument_bits_length = 0;

	if (list_isempty(locator->chunks)) {
		chunk = srv6_locator_chunk_alloc();
		chunk->prefix = *prefix;
		chunk->proto = 0;
		listnode_add(locator->chunks, chunk);
	} else {
		for (ALL_LIST_ELEMENTS_RO(locator->chunks, node, chunk)) {
			uint8_t zero[16] = {0};

			if (memcmp(&chunk->prefix.prefix, zero, 16) == 0) {
				struct zserv *client;
				struct listnode *client_node;

				chunk->prefix = *prefix;
				for (ALL_LIST_ELEMENTS_RO(zrouter.client_list,
							  client_node,
							  client)) {
					struct srv6_locator *tmp;

					if (client->proto != chunk->proto)
						continue;

					srv6_manager_get_locator_chunk_call(
							&tmp, client,
							locator->name,
							VRF_DEFAULT);
				}
			}
		}
	}

	zebra_srv6_locator_add(locator);
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	struct srv6_locator *locator;
	char str[256];

	vty_out(vty, "!\n");
	if (zebra_srv6_is_enable()) {
		vty_out(vty, "segment-routing\n");
		vty_out(vty, " srv6\n");
		vty_out(vty, "  locators\n");
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			inet_ntop(AF_INET6, &locator->prefix.prefix,
				  str, sizeof(str));
			vty_out(vty, "   locator %s\n", locator->name);
			vty_out(vty, "    prefix %s/%u\n", str,
				locator->prefix.prefixlen);
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");
		vty_out(vty, " exit\n");
		vty_out(vty, " !\n");
		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

void zebra_srv6_vty_init(void)
{
	/* Install nodes and its default commands */
	install_node(&sr_node);
	install_node(&srv6_node);
	install_node(&srv6_locs_node);
	install_node(&srv6_loc_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &srv6_cmd);
	install_element(SEGMENT_ROUTING_NODE, &no_srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
	install_element(SRV6_LOCS_NODE, &no_srv6_locator_cmd);

	/* Command for configuration */
	install_element(SRV6_LOC_NODE, &locator_prefix_cmd);

	/* Command for operation */
	install_element(VIEW_NODE, &show_srv6_locator_cmd);
	install_element(VIEW_NODE, &show_srv6_locator_detail_cmd);
}
