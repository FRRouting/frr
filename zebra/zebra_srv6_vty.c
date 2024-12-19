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
#include "zebra/zapi_msg.h"

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

static struct cmd_node srv6_prefix_node = { .name = "srv6-locator-prefix",
					    .node = SRV6_PREFIX_NODE,
					    .parent_node = SRV6_LOC_NODE,
					    .prompt = "%s(config-srv6-locator-prefix)# " };

static struct seg6_sid *sid_lookup_by_vrf_action(struct srv6_locator *loc, const char *vrfname,
						 enum seg6local_action_t sidaction)

{
	struct seg6_sid *sid = NULL;
	struct listnode *node, *nnode;

	if (!vrfname)
		return NULL;

	for (ALL_LIST_ELEMENTS(loc->sids, node, nnode, sid)) {
		if (strcmp(sid->vrfName, vrfname) == 0 && (sid->sidaction == sidaction))
			return sid;
	}
	return NULL;
}

static struct cmd_node srv6_encap_node = {
	.name = "srv6-encap",
	.node = SRV6_ENCAP_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-encap)# "
};

static struct cmd_node srv6_sid_formats_node = {
	.name = "srv6-formats",
	.node = SRV6_SID_FORMATS_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-formats)# ",
};

static struct cmd_node srv6_sid_format_usid_f3216_node = {
	.name = "srv6-format-usid-f3216",
	.node = SRV6_SID_FORMAT_USID_F3216_NODE,
	.parent_node = SRV6_SID_FORMATS_NODE,
	.prompt = "%s(config-srv6-format)# "
};

static struct cmd_node srv6_sid_format_uncompressed_f4024_node = {
	.name = "srv6-format-uncompressed-f4024",
	.node = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE,
	.parent_node = SRV6_SID_FORMATS_NODE,
	.prompt = "%s(config-srv6-format)# "
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
	struct listnode *sidnode;
	struct seg6_sid *sid = NULL;
	char str[256];
	char buf[256];
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
		if (locator->sid_format) {
			vty_out(vty, "Block-Bit-Len: %u\n",
				locator->sid_format->block_len);
			vty_out(vty, "Node-Bit-Len: %u\n",
				locator->sid_format->node_len);
			vty_out(vty, "Function-Bit-Len: %u\n",
				locator->sid_format->function_len);
			vty_out(vty, "Argument-Bit-Len: %u\n",
				locator->sid_format->argument_len);

			if (locator->sid_format->type ==
			    SRV6_SID_FORMAT_TYPE_USID)
				vty_out(vty, "Behavior: uSID\n");
		} else {
			vty_out(vty, "Block-Bit-Len: %u\n",
				locator->block_bits_length);
			vty_out(vty, "Node-Bit-Len: %u\n",
				locator->node_bits_length);
			vty_out(vty, "Function-Bit-Len: %u\n",
				locator->function_bits_length);
			vty_out(vty, "Argument-Bit-Len: %u\n",
				locator->argument_bits_length);

			if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
				vty_out(vty, "Behavior: uSID\n");
		}

		vty_out(vty, "Chunks:\n");
		for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, node,
					  chunk)) {
			prefix2str(&chunk->prefix, str, sizeof(str));
			vty_out(vty, "- prefix: %s, owner: %s\n", str,
				zebra_route_string(chunk->proto));
		}
		vty_out(vty, "  sids:\n");
		for (ALL_LIST_ELEMENTS_RO(locator->sids, sidnode, sid)) {
			prefix2str(&sid->ipv6Addr, buf, sizeof(buf));
			vty_out(vty, "   -opcode %s\n", buf);
			vty_out(vty, "    sidaction %s\n", seg6local_action2str(sid->sidaction));
			vty_out(vty, "    vrf %s\n", sid->vrfName);
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
	struct zebra_srv6_sid_block *block;
	struct zebra_srv6_sid_ctx *ctx;

	for (ALL_LIST_ELEMENTS(srv6->sids, node, nnode, ctx)) {
		if (ctx->sid)
			zebra_srv6_sid_free(ctx->sid);

		listnode_delete(srv6->sids, ctx);
		zebra_srv6_sid_ctx_free(ctx);
	}

	for (ALL_LIST_ELEMENTS(srv6->locators, node, nnode, locator)) {
		block = locator->sid_block;
		if (block) {
			block->refcnt--;
			if (block->refcnt == 0) {
				listnode_delete(srv6->sid_blocks, block);
				zebra_srv6_sid_block_free(block);
			}
			locator->sid_block = NULL;
		}

		zebra_srv6_locator_delete(locator);
	}
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
		vty->node = SRV6_LOC_NODE;
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
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block;
	struct listnode *node, *nnode;
	struct zebra_srv6_sid_ctx *ctx;
	struct srv6_locator *locator = zebra_srv6_locator_lookup(argv[2]->arg);
	if (!locator) {
		vty_out(vty, "%% Can't find SRv6 locator\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS(srv6->sids, node, nnode, ctx)) {
		if (!ctx->sid || ctx->sid->locator != locator)
			continue;

		if (ctx->sid)
			zebra_srv6_sid_free(ctx->sid);

		listnode_delete(srv6->sids, ctx);
		zebra_srv6_sid_ctx_free(ctx);
	}

	block = locator->sid_block;
	if (block) {
		block->refcnt--;
		if (block->refcnt == 0) {
			listnode_delete(srv6->sid_blocks, block);
			zebra_srv6_sid_block_free(block);
		}
		locator->sid_block = NULL;
	}

	zebra_srv6_locator_delete(locator);
	return CMD_SUCCESS;
}

DEFUN_NOSH (locator_prefix,
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
	uint8_t expected_prefixlen;
	struct srv6_sid_format *format;
	char *prefixstr = NULL;
	struct prefix_ipv6 prefix;
	int ret = 0;
	int idx = 0;
	int block_bit_len = 0;
	int node_bit_len = 0;
	int func_bit_len = 0;

	prefixstr = argv[1]->arg;
	ret = str2prefix_ipv6(prefixstr, &prefix);
	apply_mask_ipv6(&prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "block-len", &idx))
		block_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	if (argv_find(argv, argc, "node-len", &idx))
		node_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	if (argv_find(argv, argc, "func-bits", &idx))
		func_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);

	locator->prefix = prefix;
	func_bit_len = func_bit_len ?: ZEBRA_SRV6_FUNCTION_LENGTH;

	expected_prefixlen = prefix.prefixlen;
	format = locator->sid_format;
	if (format) {
		if (strmatch(format->name, SRV6_SID_FORMAT_USID_F3216_NAME))
			expected_prefixlen =
				SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN +
				SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
		else if (strmatch(format->name,
				  SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME))
			expected_prefixlen =
				SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN +
				SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN;
	}

	if (prefix.prefixlen != expected_prefixlen) {
		vty_out(vty,
			"%% Locator prefix length '%u' inconsistent with configured format '%s'. Please either use a prefix length that is consistent with the format or change the format.\n",
			prefix.prefixlen, format->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Resolve optional arguments */
	if (block_bit_len == 0 && node_bit_len == 0) {
		block_bit_len = prefix.prefixlen - ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
		node_bit_len = ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
	} else if (block_bit_len == 0) {
		block_bit_len = prefix.prefixlen - node_bit_len;
	} else if (node_bit_len == 0) {
		node_bit_len = prefix.prefixlen - block_bit_len;
	} else {
		if (block_bit_len + node_bit_len != prefix.prefixlen) {
			vty_out(vty,
				"%% block-len + node-len must be equal to the selected prefix length %d\n",
				prefix.prefixlen);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (prefix.prefixlen + func_bit_len + 0 > 128) {
		vty_out(vty,
			"%% prefix-len + function-len + arg-len (%d) cannot be greater than 128\n",
			prefix.prefixlen + func_bit_len + 0);
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
		chunk->prefix = prefix;
		chunk->proto = 0;
		listnode_add(locator->chunks, chunk);
	} else {
		for (ALL_LIST_ELEMENTS_RO(locator->chunks, node, chunk)) {
			uint8_t zero[16] = {0};

			if (memcmp(&chunk->prefix.prefix, zero, 16) == 0) {
				struct zserv *client;
				struct listnode *client_node;

				chunk->prefix = prefix;
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

	zebra_srv6_locator_format_set(locator, locator->sid_format);

	vty->node = SRV6_PREFIX_NODE;

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

	if (!locator->sid_format)
		/* Remove old locator from zclients */
		zebra_notify_srv6_locator_delete(locator);

	/* Set/Unset the SRV6_LOCATOR_USID */
	if (no)
		UNSET_FLAG(locator->flags, SRV6_LOCATOR_USID);
	else
		SET_FLAG(locator->flags, SRV6_LOCATOR_USID);

	if (!locator->sid_format)
		/* Notify the new locator to zclients */
		zebra_srv6_locator_add(locator);

	return CMD_SUCCESS;
}

DEFPY(locator_sid_format,
      locator_sid_format_cmd,
      "format <usid-f3216|uncompressed-f4024>$format",
      "Configure SRv6 SID format\n"
      "Specify usid-f3216 format\n"
      "Specify uncompressed-f4024 format\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct srv6_sid_format *sid_format = NULL;
	uint8_t expected_prefixlen;

	expected_prefixlen = locator->prefix.prefixlen;
	if (strmatch(format, SRV6_SID_FORMAT_USID_F3216_NAME))
		expected_prefixlen = SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN +
				     SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	else if (strmatch(format, SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME))
		expected_prefixlen =
			SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN +
			SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN;

	if (IPV6_ADDR_SAME(&locator->prefix, &in6addr_any)) {
		vty_out(vty,
			"%% Unexpected configuration sequence: the prefix of the locator is required before configuring the format. Please configure the prefix first and then configure the format.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (locator->prefix.prefixlen != expected_prefixlen) {
		vty_out(vty,
			"%% Locator prefix length '%u' inconsistent with configured format '%s'. Please either use a prefix length that is consistent with the format or change the format.\n",
			locator->prefix.prefixlen, format);
		return CMD_WARNING_CONFIG_FAILED;
	}

	sid_format = srv6_sid_format_lookup(format);
	if (!sid_format) {
		vty_out(vty, "%% Cannot find SRv6 SID format '%s'\n", format);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (sid_format == locator->sid_format)
		/* Format has not changed, nothing to do */
		return CMD_SUCCESS;

	zebra_srv6_locator_format_set(locator, sid_format);

	return CMD_SUCCESS;
}

DEFPY (no_locator_sid_format,
       no_locator_sid_format_cmd,
       "no format [WORD]",
       NO_STR
       "Configure SRv6 SID format\n"
       "Specify SRv6 SID format\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);

	if (!locator->sid_format)
		/* SID format already unset, nothing to do */
		return CMD_SUCCESS;

	zebra_srv6_locator_format_set(locator, NULL);

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

DEFUN_NOSH(srv6_sid_formats,
           srv6_sid_formats_cmd,
           "formats",
           "Segment Routing SRv6 SID formats\n")
{
	vty->node = SRV6_SID_FORMATS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_sid_format_f3216_usid,
            srv6_sid_format_f3216_usid_cmd,
            "format usid-f3216",
            "Configure SRv6 SID format\n"
            "Configure the uSID f3216 format\n")
{
	struct srv6_sid_format *format;

	format = srv6_sid_format_lookup(SRV6_SID_FORMAT_USID_F3216_NAME);
	assert(format);

	VTY_PUSH_CONTEXT(SRV6_SID_FORMAT_USID_F3216_NODE, format);
	return CMD_SUCCESS;
}

DEFUN(no_srv6_sid_format_f3216_usid,
      no_srv6_sid_format_f3216_usid_cmd,
      "no format usid-f3216",
      NO_STR
      "Configure SRv6 SID format\n"
      "Configure the uSID f3216 format\n")
{
	struct srv6_sid_format *format;

	format = srv6_sid_format_lookup(SRV6_SID_FORMAT_USID_F3216_NAME);
	assert(format);

	format->config.usid.lib_start = SRV6_SID_FORMAT_USID_F3216_LIB_START;
	format->config.usid.elib_start = SRV6_SID_FORMAT_USID_F3216_ELIB_START;
	format->config.usid.elib_end = SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	format->config.usid.wlib_start = SRV6_SID_FORMAT_USID_F3216_WLIB_START;
	format->config.usid.wlib_end = SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	format->config.usid.ewlib_start = SRV6_SID_FORMAT_USID_F3216_EWLIB_START;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_sid_format_f4024_uncompressed,
            srv6_sid_format_uncompressed_cmd,
            "format uncompressed-f4024",
            "Configure SRv6 SID format\n"
            "Configure the uncompressed f4024 format\n")
{
	struct srv6_sid_format *format;

	format = srv6_sid_format_lookup(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME);
	assert(format);

	VTY_PUSH_CONTEXT(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE, format);
	return CMD_SUCCESS;
}

DEFUN(no_srv6_sid_format_f4024_uncompressed,
      no_srv6_sid_format_f4024_uncompressed_cmd,
      "no format uncompressed-f4024",
      NO_STR
      "Configure SRv6 SID format\n"
      "Configure the uncompressed f4024 format\n")
{
	struct srv6_sid_format *format;

	format = srv6_sid_format_lookup(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME);
	assert(format);

	format->config.uncompressed.explicit_start =
		SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(srv6_sid_format_usid_lib,
      srv6_sid_format_usid_lib_cmd,
      "local-id-block start (0-4294967295)$start",
      "Configure LIB\n"
      "Configure the start value for the LIB\n"
      "Specify the start value for the LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	format->config.usid.lib_start = start;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(no_srv6_sid_format_usid_lib,
      no_srv6_sid_format_usid_lib_cmd,
      "no local-id-block [start (0-4294967295)]",
      NO_STR
      "Configure LIB\n"
      "Configure the start value for the LIB\n"
      "Specify the start value for the LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	if (strmatch(format->name, SRV6_SID_FORMAT_USID_F3216_NAME))
		format->config.usid.lib_start =
			SRV6_SID_FORMAT_USID_F3216_LIB_START;
	else
		assert(0);

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(srv6_sid_format_usid_lib_explicit,
      srv6_sid_format_usid_lib_explicit_cmd,
      "local-id-block explicit start (0-4294967295)$start end (0-4294967295)$end",
      "Configure LIB\n"
      "Configure the Explicit LIB\n"
      "Configure the start value for the Explicit LIB\n"
      "Specify the start value for the Explicit LIB\n"
      "Configure the end value for the Explicit LIB\n"
      "Specify the end value for the Explicit LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	format->config.usid.elib_start = start;
	format->config.usid.elib_end = end;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(no_srv6_sid_format_usid_lib_explicit,
      no_srv6_sid_format_usid_lib_explicit_cmd,
      "no local-id-block explicit [start (0-4294967295) end (0-4294967295)]",
      NO_STR
      "Configure LIB\n"
      "Configure the Explicit LIB\n"
      "Configure the start value for the Explicit LIB\n"
      "Specify the start value for the Explicit LIB\n"
      "Configure the end value for the Explicit LIB\n"
      "Specify the end value for the Explicit LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	if (strmatch(format->name, SRV6_SID_FORMAT_USID_F3216_NAME)) {
		format->config.usid.elib_start =
			SRV6_SID_FORMAT_USID_F3216_ELIB_START;
		format->config.usid.elib_end =
			SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	} else {
		assert(0);
	}

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(srv6_sid_format_usid_wlib,
      srv6_sid_format_usid_wlib_cmd,
      "wide-local-id-block start (0-4294967295)$start end (0-4294967295)$end",
      "Configure Wide LIB\n"
      "Configure the start value for the Wide LIB\n"
      "Specify the start value for the Wide LIB\n"
      "Configure the end value for the Wide LIB\n"
      "Specify the end value for the Wide LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	format->config.usid.wlib_start = start;
	format->config.usid.wlib_end = end;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(no_srv6_sid_format_usid_wlib,
      no_srv6_sid_format_usid_wlib_cmd,
      "no wide-local-id-block [start (0-4294967295) end (0-4294967295)]",
      NO_STR
      "Configure Wide LIB\n"
      "Configure the start value for the Wide LIB\n"
      "Specify the start value for the Wide LIB\n"
      "Configure the end value for the Wide LIB\n"
      "Specify the end value for the Wide LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	if (strmatch(format->name, SRV6_SID_FORMAT_USID_F3216_NAME)) {
		format->config.usid.wlib_start =
			SRV6_SID_FORMAT_USID_F3216_WLIB_START;
		format->config.usid.wlib_end =
			SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	} else {
		assert(0);
	}

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(srv6_sid_format_usid_wide_lib_explicit,
      srv6_sid_format_usid_wide_lib_explicit_cmd,
      "wide-local-id-block explicit start (0-4294967295)$start",
      "Configure Wide LIB\n"
      "Configure Explicit Wide LIB\n"
      "Configure the start value for the Explicit Wide LIB\n"
      "Specify the start value for the Explicit Wide LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	format->config.usid.ewlib_start = start;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(no_srv6_sid_format_usid_wide_lib_explicit,
      no_srv6_sid_format_usid_wide_lib_explicit_cmd,
      "no wide-local-id-block explicit [start (0-4294967295)]",
	  NO_STR
      "Configure Wide LIB\n"
      "Configure Explicit Wide LIB\n"
      "Configure the start value for the Explicit Wide LIB\n"
      "Specify the start value for the Explicit Wide LIB\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	if (strmatch(format->name, SRV6_SID_FORMAT_USID_F3216_NAME))
		format->config.usid.ewlib_start =
			SRV6_SID_FORMAT_USID_F3216_EWLIB_START;
	else
		assert(0);

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(srv6_sid_format_explicit,
      srv6_sid_format_explicit_cmd,
      "explicit start (0-4294967295)$start",
      "Configure Explicit range\n"
      "Configure the start value for the Explicit range\n"
      "Specify the start value for the Explicit range\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	format->config.uncompressed.explicit_start = start;

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}

DEFPY(no_srv6_sid_format_explicit,
      no_srv6_sid_format_explicit_cmd,
      "no explicit [start (0-4294967295)$start]",
	  NO_STR
      "Configure Explicit range\n"
      "Configure the start value for the Explicit range\n"
      "Specify the start value for the Explicit range\n")
{
	VTY_DECLVAR_CONTEXT(srv6_sid_format, format);

	if (strmatch(format->name, SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME))
		format->config.usid.ewlib_start =
			SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START;
	else
		assert(0);

	/* Notify zclients that the format has changed */
	zebra_srv6_sid_format_changed_cb(format);

	return CMD_SUCCESS;
}


DEFPY(locator_opcode, locator_opcode_cmd,
      "opcode WORD <end | end-dt46 vrf VIEWVRFNAME | end-dt4 vrf VIEWVRFNAME | end-dt6 vrf VIEWVRFNAME>",
      "Configure SRv6 locator prefix\n"
      "Specify SRv6 locator hex opcode\n"
      "Apply the code to an End SID\n"
      "Apply the code to an End.DT46 SID\n"
      "vrf\n"
      "vrf\n"
      "Apply the code to an End.DT4 SID\n"
      "vrf\n"
      "vrf\n"
      "Apply the code to an End.DT6 SID\n"
      "vrf\n"
      "vrf\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct seg6_sid *sid = NULL;
	struct listnode *node = NULL;
	enum seg6local_action_t sidaction = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	int idx = 0;
	char *vrfName = NULL;
	char *prefix = NULL;
	int ret = 0;
	struct prefix_ipv6 ipv6prefix = { 0 };
	struct zserv *client;
	struct listnode *client_node;

	if (!locator->status_up) {
		vty_out(vty, "Missing valid prefix.\n");
		return CMD_WARNING;
	}
	if (argv_find(argv, argc, "end", &idx))
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END;
	else if (argv_find(argv, argc, "end-dt46", &idx)) {
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrfName = argv[idx + 2]->arg;
	} else if (argv_find(argv, argc, "end-dt4", &idx)) {
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrfName = argv[idx + 2]->arg;
	} else if (argv_find(argv, argc, "end-dt6", &idx)) {
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrfName = argv[idx + 2]->arg;
	}
	prefix = argv[1]->arg;
	ret = str2prefix_ipv6(prefix, &ipv6prefix);
	apply_mask_ipv6(&ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	for (ALL_LIST_ELEMENTS_RO(locator->sids, node, sid)) {
		if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix)) {
			vty_out(vty, "Prefix %s is already exist,please delete it first.\n",
				argv[1]->arg);
			return CMD_WARNING;
		}
	}
	sid = sid_lookup_by_vrf_action(locator, vrfName, sidaction);
	if (sid) {
		vty_out(vty, "VRF %s is already exist,please delete it first.\n", vrfName);
		return CMD_WARNING;
	}
	sid = srv6_locator_sid_alloc();
	sid->sidaction = sidaction;
	if (vrfName != NULL)
		strlcpy(sid->vrfName, vrfName, VRF_NAMSIZ);
	else
		strlcpy(sid->vrfName, VRF_DEFAULT_NAME, VRF_NAMSIZ);

	sid->ipv6Addr = ipv6prefix;
	strlcpy(sid->sidstr, prefix, PREFIX_STRLEN);

	listnode_add(locator->sids, sid);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, client_node, client))
		zsend_srv6_manager_get_locator_sid_response(client, VRF_DEFAULT, locator);
	return CMD_SUCCESS;
}

DEFPY(no_locator_opcode,
	  no_locator_opcode_cmd,
	  "no opcode WORD",
      NO_STR
      "Configure SRv6 locator prefix\n"
      "Specify SRv6 locator hex opcode\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct seg6_sid *sid = NULL;
	struct listnode *node, *next;
	char *prefix = NULL;
	int ret = 0;
	struct prefix_ipv6 ipv6prefix = { 0 };
	struct zserv *client;
	struct listnode *client_node;

	prefix = argv[2]->arg;
	ret = str2prefix_ipv6(prefix, &ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS(locator->sids, node, next, sid)) {
		if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix)) {
			for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, client_node, client))
				zsend_srv6_manager_del_sid(client, VRF_DEFAULT, locator, sid);
			listnode_delete(locator->sids, sid);
			srv6_locator_sid_free(sid);
			return CMD_SUCCESS;
		}
	}
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node, *opcodenode;
	struct srv6_locator *locator;
	struct seg6_sid *sid;
	struct srv6_sid_format *format;
	char str[256];
	bool display_source_srv6 = false;

	if (srv6 && !IPV6_ADDR_SAME(&srv6->encap_src_addr, &in6addr_any))
		display_source_srv6 = true;

	vty_out(vty, "!\n");
	if (display_source_srv6 || zebra_srv6_is_enable()) {
		vty_out(vty, "segment-routing\n");
		vty_out(vty, " srv6\n");
	}
	if (display_source_srv6) {
		if (!IPV6_ADDR_SAME(&srv6->encap_src_addr, &in6addr_any)) {
			vty_out(vty, "  encapsulation\n");
			vty_out(vty, "   source-address %pI6\n",
				&srv6->encap_src_addr);
		}
	}
	if (srv6 && zebra_srv6_is_enable()) {
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
			for (ALL_LIST_ELEMENTS_RO(locator->sids, opcodenode, sid)) {
				vty_out(vty, "     opcode %s", sid->sidstr);
				if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END)
					vty_out(vty, " end");
				else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT4) {
					vty_out(vty, " end-dt4");
					vty_out(vty, " vrf %s", sid->vrfName);
				} else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT6) {
					vty_out(vty, " end-dt6");
					vty_out(vty, " vrf %s", sid->vrfName);
				} else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT46) {
					vty_out(vty, " end-dt46");
					vty_out(vty, " vrf %s", sid->vrfName);
				}
				vty_out(vty, "\n");
			}
			vty_out(vty, "\n");
			vty_out(vty, "    exit\n");
			vty_out(vty, "    !\n");
			if (locator->sid_format) {
				format = locator->sid_format;
				vty_out(vty, "    format %s\n", format->name);
			}
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");
		vty_out(vty, "  formats\n");
		for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format)) {
			if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
				vty_out(vty, "   format %s\n", format->name);
				if (format->config.uncompressed.explicit_start !=
				    SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START)
					vty_out(vty, "    explicit start %u\n",
						format->config.uncompressed
							.explicit_start);
			}
			if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
				vty_out(vty, "   format %s\n", format->name);
				if (format->config.usid.lib_start !=
				    SRV6_SID_FORMAT_USID_F3216_LIB_START)
					vty_out(vty,
						"    local-id-block start %u\n",
						format->config.usid.lib_start);
				if (format->config.usid.elib_start !=
					    SRV6_SID_FORMAT_USID_F3216_ELIB_START ||
				    format->config.usid.elib_end !=
					    SRV6_SID_FORMAT_USID_F3216_ELIB_END)
					vty_out(vty,
						"    local-id-block explicit start %u end %u\n",
						format->config.usid.elib_start,
						format->config.usid.elib_end);
				if (format->config.usid.wlib_start !=
					    SRV6_SID_FORMAT_USID_F3216_WLIB_START ||
				    format->config.usid.wlib_end !=
					    SRV6_SID_FORMAT_USID_F3216_WLIB_END)
					vty_out(vty,
						"    wide-local-id-block start %u end %u\n",
						format->config.usid.wlib_start,
						format->config.usid.wlib_end);
				if (format->config.usid.ewlib_start !=
				    SRV6_SID_FORMAT_USID_F3216_EWLIB_START)
					vty_out(vty,
						"    wide-local-id-block explicit start %u\n",
						format->config.usid.ewlib_start);
			}
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");
		vty_out(vty, " exit\n");
		vty_out(vty, " !\n");
	}
	if (display_source_srv6 || zebra_srv6_is_enable()) {
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
	install_node(&srv6_prefix_node);
	install_node(&srv6_encap_node);
	install_node(&srv6_sid_formats_node);
	install_node(&srv6_sid_format_usid_f3216_node);
	install_node(&srv6_sid_format_uncompressed_f4024_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
	install_default(SRV6_PREFIX_NODE);
	install_default(SRV6_ENCAP_NODE);
	install_default(SRV6_SID_FORMATS_NODE);
	install_default(SRV6_SID_FORMAT_USID_F3216_NODE);
	install_default(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &srv6_cmd);
	install_element(SEGMENT_ROUTING_NODE, &no_srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_NODE, &srv6_encap_cmd);
	install_element(SRV6_NODE, &srv6_sid_formats_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
	install_element(SRV6_LOCS_NODE, &no_srv6_locator_cmd);
	install_element(SRV6_SID_FORMATS_NODE, &srv6_sid_format_f3216_usid_cmd);
	install_element(SRV6_SID_FORMATS_NODE,
			&srv6_sid_format_uncompressed_cmd);
	install_element(SRV6_SID_FORMATS_NODE,
			&no_srv6_sid_format_f3216_usid_cmd);
	install_element(SRV6_SID_FORMATS_NODE,
			&no_srv6_sid_format_f4024_uncompressed_cmd);

	/* Command for configuration */
	install_element(SRV6_LOC_NODE, &locator_prefix_cmd);
	//install_element(SRV6_LOC_NODE, &no_srv6_prefix_cmd);
	install_element(SRV6_PREFIX_NODE, &locator_opcode_cmd);
	install_element(SRV6_PREFIX_NODE, &no_locator_opcode_cmd);
	install_element(SRV6_LOC_NODE, &locator_behavior_cmd);
	install_element(SRV6_LOC_NODE, &locator_sid_format_cmd);
	install_element(SRV6_LOC_NODE, &no_locator_sid_format_cmd);
	install_element(SRV6_ENCAP_NODE, &srv6_src_addr_cmd);
	install_element(SRV6_ENCAP_NODE, &no_srv6_src_addr_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&srv6_sid_format_usid_lib_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&no_srv6_sid_format_usid_lib_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&srv6_sid_format_usid_lib_explicit_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&no_srv6_sid_format_usid_lib_explicit_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&srv6_sid_format_usid_wlib_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&no_srv6_sid_format_usid_wlib_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&srv6_sid_format_usid_wide_lib_explicit_cmd);
	install_element(SRV6_SID_FORMAT_USID_F3216_NODE,
			&no_srv6_sid_format_usid_wide_lib_explicit_cmd);
	install_element(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE,
			&srv6_sid_format_explicit_cmd);
	install_element(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE,
			&no_srv6_sid_format_explicit_cmd);

	/* Command for operation */
	install_element(VIEW_NODE, &show_srv6_locator_cmd);
	install_element(VIEW_NODE, &show_srv6_locator_detail_cmd);
	install_element(VIEW_NODE, &show_srv6_manager_cmd);
}
