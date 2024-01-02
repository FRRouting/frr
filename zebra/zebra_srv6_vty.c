// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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

#include "zebra/zebra_srv6_vty_clippy.c"

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

static struct cmd_node srv6_encap_node = {
	.name = "srv6-encap",
	.node = SRV6_ENCAP_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-encap)# "
};

DEFPY (show_srv6_manager,
       show_srv6_manager_cmd,
       "show segment-routing srv6 manager [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Verify SRv6 Manager\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	json_object *json = NULL;
	json_object *json_parameters = NULL;
	json_object *json_encapsulation = NULL;
	json_object *json_source_address = NULL;

	if (uj) {
		json = json_object_new_object();
		json_parameters = json_object_new_object();
		json_object_object_add(json, "parameters", json_parameters);
		json_encapsulation = json_object_new_object();
		json_object_object_add(json_parameters, "encapsulation",
				       json_encapsulation);
		json_source_address = json_object_new_object();
		json_object_object_add(json_encapsulation, "sourceAddress",
				       json_source_address);
		json_object_string_addf(json_source_address, "configured",
					"%pI6", &srv6->encap_src_addr);
		vty_json(vty, json);
	} else {
		vty_out(vty, "Parameters:\n");
		vty_out(vty, "  Encapsulation:\n");
		vty_out(vty, "    Source Address:\n");
		vty_out(vty, "      Configured: %pI6\n", &srv6->encap_src_addr);
	}

	return CMD_SUCCESS;
}

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

		vty_json(vty, json);
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
	json_object *json_locator = NULL;

	if (uj) {
		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator)
			return CMD_WARNING;

		json_locator = srv6_locator_detailed_json(locator);
		vty_json(vty, json_locator);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
		struct listnode *node;
		struct srv6_locator_chunk *chunk;

		if (strcmp(locator->name, locator_name) != 0)
			continue;

		prefix2str(&locator->prefix, str, sizeof(str));
		vty_out(vty, "Name: %s\n", locator->name);
		vty_out(vty, "Prefix: %s\n", str);
		vty_out(vty, "Block-Bit-Len: %u\n", locator->block_bits_length);
		vty_out(vty, "Node-Bit-Len: %u\n", locator->node_bits_length);
		vty_out(vty, "Function-Bit-Len: %u\n",
			locator->function_bits_length);
		vty_out(vty, "Argument-Bit-Len: %u\n",
			locator->argument_bits_length);

		if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
			vty_out(vty, "Behavior: uSID\n");

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
       "prefix X:X::X:X/M$prefix [block-len (16-64)$block_bit_len]  \
	        [node-len (16-64)$node_bit_len] [func-bits (0-64)$func_bit_len]",
       "Configure SRv6 locator prefix\n"
       "Specify SRv6 locator prefix\n"
       "Configure SRv6 locator block length in bits\n"
       "Specify SRv6 locator block length in bits\n"
       "Configure SRv6 locator node length in bits\n"
       "Specify SRv6 locator node length in bits\n"
       "Configure SRv6 locator function length in bits\n"
       "Specify SRv6 locator function length in bits\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct srv6_locator_chunk *chunk = NULL;
	struct listnode *node = NULL;

	locator->prefix = *prefix;
	func_bit_len = func_bit_len ?: ZEBRA_SRV6_FUNCTION_LENGTH;

	/* Resolve optional arguments */
	if (block_bit_len == 0 && node_bit_len == 0) {
		block_bit_len =
			prefix->prefixlen - ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
		node_bit_len = ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
	} else if (block_bit_len == 0) {
		block_bit_len = prefix->prefixlen - node_bit_len;
	} else if (node_bit_len == 0) {
		node_bit_len = prefix->prefixlen - block_bit_len;
	} else {
		if (block_bit_len + node_bit_len != prefix->prefixlen) {
			vty_out(vty,
				"%% block-len + node-len must be equal to the selected prefix length %d\n",
				prefix->prefixlen);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (prefix->prefixlen + func_bit_len + 0 > 128) {
		vty_out(vty,
			"%% prefix-len + function-len + arg-len (%ld) cannot be greater than 128\n",
			prefix->prefixlen + func_bit_len + 0);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Currently, the SID transposition algorithm implemented in bgpd
	 * handles incorrectly the SRv6 locators with function length greater
	 * than 20 bits. To prevent issues, we currently limit the function
	 * length to 20 bits.
	 * This limit will be removed when the bgpd SID transposition is fixed.
	 */
	if (func_bit_len > 20) {
		vty_out(vty,
			"%% currently func_bit_len > 20 is not supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	locator->block_bits_length = block_bit_len;
	locator->node_bits_length = node_bit_len;
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

DEFPY (locator_behavior,
       locator_behavior_cmd,
       "[no] behavior usid",
       NO_STR
       "Configure SRv6 behavior\n"
       "Specify SRv6 behavior uSID\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);

	if (no && !CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
		/* SRv6 locator uSID flag already unset, nothing to do */
		return CMD_SUCCESS;

	if (!no && CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
		/* SRv6 locator uSID flag already set, nothing to do */
		return CMD_SUCCESS;

	/* Remove old locator from zclients */
	zebra_notify_srv6_locator_delete(locator);

	/* Set/Unset the SRV6_LOCATOR_USID */
	if (no)
		UNSET_FLAG(locator->flags, SRV6_LOCATOR_USID);
	else
		SET_FLAG(locator->flags, SRV6_LOCATOR_USID);

	/* Notify the new locator to zclients */
	zebra_notify_srv6_locator_add(locator);

	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_encap,
            srv6_encap_cmd,
            "encapsulation",
            "Segment Routing SRv6 encapsulation\n")
{
	vty->node = SRV6_ENCAP_NODE;
	return CMD_SUCCESS;
}

DEFPY (srv6_src_addr,
       srv6_src_addr_cmd,
       "source-address X:X::X:X$encap_src_addr",
       "Segment Routing SRv6 source address\n"
       "Specify source address for SRv6 encapsulation\n")
{
	zebra_srv6_encap_src_addr_set(&encap_src_addr);
	dplane_srv6_encap_srcaddr_set(&encap_src_addr, NS_DEFAULT);
	return CMD_SUCCESS;
}

DEFPY (no_srv6_src_addr,
       no_srv6_src_addr_cmd,
       "no source-address [X:X::X:X$encap_src_addr]",
       NO_STR
       "Segment Routing SRv6 source address\n"
       "Specify source address for SRv6 encapsulation\n")
{
	zebra_srv6_encap_src_addr_unset();
	dplane_srv6_encap_srcaddr_set(&in6addr_any, NS_DEFAULT);
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
		if (!IPV6_ADDR_SAME(&srv6->encap_src_addr, &in6addr_any)) {
			vty_out(vty, "  encapsulation\n");
			vty_out(vty, "   source-address %pI6\n",
				&srv6->encap_src_addr);
		}
		vty_out(vty, "  locators\n");
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			inet_ntop(AF_INET6, &locator->prefix.prefix,
				  str, sizeof(str));
			vty_out(vty, "   locator %s\n", locator->name);
			vty_out(vty, "    prefix %s/%u", str,
				locator->prefix.prefixlen);
			if (locator->block_bits_length)
				vty_out(vty, " block-len %u",
					locator->block_bits_length);
			if (locator->node_bits_length)
				vty_out(vty, " node-len %u",
					locator->node_bits_length);
			if (locator->function_bits_length)
				vty_out(vty, " func-bits %u",
					locator->function_bits_length);
			if (locator->argument_bits_length)
				vty_out(vty, " arg-len %u",
					locator->argument_bits_length);
			vty_out(vty, "\n");
			if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
				vty_out(vty, "    behavior usid\n");
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
	install_node(&srv6_encap_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
	install_default(SRV6_ENCAP_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &srv6_cmd);
	install_element(SEGMENT_ROUTING_NODE, &no_srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_NODE, &srv6_encap_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
	install_element(SRV6_LOCS_NODE, &no_srv6_locator_cmd);

	/* Command for configuration */
	install_element(SRV6_LOC_NODE, &locator_prefix_cmd);
	install_element(SRV6_LOC_NODE, &locator_behavior_cmd);
	install_element(SRV6_ENCAP_NODE, &srv6_src_addr_cmd);
	install_element(SRV6_ENCAP_NODE, &no_srv6_src_addr_cmd);

	/* Command for operation */
	install_element(VIEW_NODE, &show_srv6_locator_cmd);
	install_element(VIEW_NODE, &show_srv6_locator_detail_cmd);
	install_element(VIEW_NODE, &show_srv6_manager_cmd);
}
