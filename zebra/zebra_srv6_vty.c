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
#include "termtable.h"

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
		struct listnode *nnode;
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
		if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_PSP))
			vty_out(vty, "Flavor: PSP\n");

		vty_out(vty, "Chunks:\n");
		for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, nnode, chunk)) {
			prefix2str(&chunk->prefix, str, sizeof(str));
			vty_out(vty, "- prefix: %s, owner: %s\n", str,
				zebra_route_string(chunk->proto));
		}
	}


	return CMD_SUCCESS;
}

static const char *show_srv6_sid_seg6_action(enum seg6local_action_t behavior)
{
	switch (behavior) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		return "uN";
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
		return "uA";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		return "uDX6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		return "uDX4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		return "uDT6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		return "uDT4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		return "uDT46";
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		return "unspec";
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BPF:
		break;
	}

	return "unknown";
}

static const char *show_srv6_sid_seg6_context(char *str, size_t size, const struct srv6_sid_ctx *ctx,
					      enum seg6local_action_t behavior)
{
	struct vrf *vrf;
	struct interface *ifp;

	switch (behavior) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			ifp = if_lookup_by_index(ctx->ifindex, vrf->vrf_id);
			if (ifp)
				snprintf(str, size, "Interface '%s'", ifp->name);
		}
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		vrf = vrf_lookup_by_id(ctx->vrf_id);
		snprintf(str, size, "VRF '%s'", vrf ? vrf->name : "<unknown>");
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BPF:
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		break;
	}

	return str;
}

static void do_show_srv6_sid_line(struct ttable *tt, struct zebra_srv6_sid *sid)
{
	struct listnode *node;
	struct zserv *client;
	char clients[256];
	char ctx[256] = {};
	char behavior[256] = {};
	char alloc_mode_str[10] = {};
	char locator_name[SRV6_LOCNAME_SIZE];
	int ret;

	/* Zclients */
	if (listcount(sid->client_list)) {
		bool first = true;
		int i = 0;
		for (ALL_LIST_ELEMENTS_RO(sid->client_list, node, client)) {
			if (first) {
				ret = snprintf(clients + i, sizeof(clients) - i, "%s(%d)",
					       zebra_route_string(client->proto), client->instance);
				first = false;
			} else {
				ret = snprintf(clients + i, sizeof(clients) - i, ", %s(%d)",
					       zebra_route_string(client->proto), client->instance);
			}

			if (ret > 0)
				i += ret;
		}
	}

	/* Behavior */
	if (sid->locator) {
		if ((sid->locator->sid_format &&
		     sid->locator->sid_format->type == SRV6_SID_FORMAT_TYPE_USID) ||
		    (!sid->locator->sid_format &&
		     CHECK_FLAG(sid->locator->flags, SRV6_LOCATOR_USID))) {
			snprintf(behavior, sizeof(behavior), "%s",
				 show_srv6_sid_seg6_action(sid->ctx->ctx.behavior));
		} else {
			snprintf(behavior, sizeof(behavior), "%s",
				 seg6local_action2str(sid->ctx->ctx.behavior));
		}
	}

	/* SID context */
	show_srv6_sid_seg6_context(ctx, sizeof(ctx), &sid->ctx->ctx, sid->ctx->ctx.behavior);

	if (strlen(ctx) == 0)
		snprintf(ctx, sizeof(ctx), "-");

	if (sid->locator)
		snprintf(locator_name, sizeof(locator_name), "%s", sid->locator->name);
	else
		snprintf(locator_name, sizeof(locator_name), "-");

	snprintf(alloc_mode_str, sizeof(alloc_mode_str), "%s",
		 srv6_sid_alloc_mode2str(sid->alloc_mode));

	ttable_add_row(tt, "%pI6|%s|%s|%s|%s|%s", &sid->value, behavior, ctx, clients, locator_name,
		       alloc_mode_str);
}

static void do_show_srv6_sid_json(struct vty *vty, json_object **json, struct srv6_locator *locator,
				  struct zebra_srv6_sid_ctx *sid_ctx)
{
	json_object *json_sid_ctx = NULL;
	json_object *json_sid = NULL;
	json_object *json_sid_clients = NULL;
	json_object *json_sid_client = NULL;
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct interface *ifp;
	struct listnode *node;
	struct zserv *client;
	char buf[256];

	if (!sid_ctx || !sid_ctx->sid)
		return;

	if (locator && sid_ctx->sid->locator != locator)
		return;

	json_sid = json_object_new_object();
	json_sid_ctx = json_object_new_object();

	json_object_string_addf(json_sid, "sid", "%pI6", &sid_ctx->sid->value);
	if ((sid_ctx->sid->locator->sid_format &&
	     sid_ctx->sid->locator->sid_format->type == SRV6_SID_FORMAT_TYPE_USID) ||
	    (!sid_ctx->sid->locator->sid_format &&
	     CHECK_FLAG(sid_ctx->sid->locator->flags, SRV6_LOCATOR_USID))) {
		json_object_string_add(json_sid, "behavior",
				       show_srv6_sid_seg6_action(sid_ctx->ctx.behavior));
	} else {
		json_object_string_add(json_sid, "behavior",
				       seg6local_action2str(sid_ctx->ctx.behavior));
	}

	if (sid_ctx->ctx.vrf_id) {
		json_object_int_add(json_sid_ctx, "vrfId", sid_ctx->ctx.vrf_id);

		vrf = vrf_lookup_by_id(sid_ctx->ctx.vrf_id);
		if (vrf)
			json_object_string_add(json_sid_ctx, "vrfName", vrf->name);

		zvrf = vrf_info_lookup(sid_ctx->ctx.vrf_id);
		if (vrf)
			json_object_int_add(json_sid_ctx, "table", zvrf->table_id);
	}
	if (sid_ctx->ctx.ifindex) {
		json_object_int_add(json_sid_ctx, "interfaceIndex", sid_ctx->ctx.ifindex);
		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			ifp = if_lookup_by_index(sid_ctx->ctx.ifindex, vrf->vrf_id);
			if (ifp)
				json_object_string_add(json_sid_ctx, "interfaceName", ifp->name);
		}
	}
	if (memcmp(&sid_ctx->ctx.nh6, &in6addr_any, sizeof(struct in6_addr)) != 0) {
		json_object_string_addf(json_sid_ctx, "nexthopIpv6Address", "%pI6",
					&sid_ctx->ctx.nh6);
	}
	json_object_object_add(json_sid, "context", json_sid_ctx);

	json_object_string_add(json_sid, "locator", sid_ctx->sid->locator->name);
	json_object_string_add(json_sid, "allocationMode",
			       srv6_sid_alloc_mode2str(sid_ctx->sid->alloc_mode));

	/* Zclients */
	json_sid_clients = json_object_new_array();
	if (listcount(sid_ctx->sid->client_list)) {
		for (ALL_LIST_ELEMENTS_RO(sid_ctx->sid->client_list, node, client)) {
			json_sid_client = json_object_new_object();
			json_object_string_add(json_sid_client, "protocol",
					       zebra_route_string(client->proto));
			json_object_int_add(json_sid_client, "instance", client->instance);
			json_object_array_add(json_sid_clients, json_sid_client);
		}
	}
	json_object_object_add(json_sid, "clients", json_sid_clients);

	json_object_object_add(*json, inet_ntop(AF_INET6, &sid_ctx->sid->value, buf, sizeof(buf)),
			       json_sid);
}

static void do_show_srv6_sid_specific(struct vty *vty, json_object **json,
				      struct srv6_locator *locator,
				      struct zebra_srv6_sid_ctx *sid_ctx)
{
	struct ttable *tt;

	if (json) {
		do_show_srv6_sid_json(vty, json, locator, sid_ctx);
	} else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);

		ttable_add_row(tt, "SID|Behavior|Context|Daemon/Instance|Locator|AllocationType");
		tt->style.cell.rpad = 2;
		tt->style.corner = ' ';
		ttable_restyle(tt);
		ttable_rowseps(tt, 0, BOTTOM, true, '-');

		if (!sid_ctx || !sid_ctx->sid) {
			ttable_del(tt);
			return;
		}

		if (locator && sid_ctx->sid->locator != locator) {
			ttable_del(tt);
			return;
		}

		do_show_srv6_sid_line(tt, sid_ctx->sid);

		ttable_colseps(tt, 1, RIGHT, true, ' ');
		ttable_colseps(tt, 2, LEFT, true, ' ');
		ttable_colseps(tt, 2, RIGHT, true, ' ');
		ttable_colseps(tt, 3, LEFT, true, ' ');
		ttable_colseps(tt, 3, RIGHT, true, ' ');
		ttable_colseps(tt, 4, LEFT, true, ' ');
		ttable_colseps(tt, 4, RIGHT, true, ' ');
		ttable_colseps(tt, 5, LEFT, true, ' ');

		/* Dump the generated table. */
		if (tt->nrows > 1) {
			char *table;

			table = ttable_dump(tt, "\n");
			vty_out(vty, "%s\n", table);
			XFREE(MTYPE_TMP_TTABLE, table);
		}
		ttable_del(tt);
	}
}

static void do_show_srv6_sid_all(struct vty *vty, json_object **json, struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_ctx *ctx;
	struct listnode *node;
	struct ttable *tt;

	if (json) {
		for (ALL_LIST_ELEMENTS_RO(srv6->sids, node, ctx)) {
			/* Skip contexts not associated with any SID */
			if (!ctx->sid)
				continue;

			/* Skip SIDs from locators we are not interested in */
			if (locator && ctx->sid->locator != locator)
				continue;

			do_show_srv6_sid_json(vty, json, locator, ctx);
		}
	} else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "SID|Behavior|Context|Daemon/Instance|Locator|AllocationType");
		tt->style.cell.rpad = 2;
		tt->style.corner = ' ';
		ttable_restyle(tt);
		ttable_rowseps(tt, 0, BOTTOM, true, '-');

		for (ALL_LIST_ELEMENTS_RO(srv6->sids, node, ctx)) {
			/* Skip contexts not associated with any SID */
			if (!ctx->sid)
				continue;

			/* Skip SIDs from locators we are not interested in */
			if (locator && ctx->sid->locator != locator)
				continue;

			do_show_srv6_sid_line(tt, ctx->sid);
		}

		ttable_colseps(tt, 1, RIGHT, true, ' ');
		ttable_colseps(tt, 2, LEFT, true, ' ');
		ttable_colseps(tt, 2, RIGHT, true, ' ');
		ttable_colseps(tt, 3, LEFT, true, ' ');
		ttable_colseps(tt, 3, RIGHT, true, ' ');
		ttable_colseps(tt, 4, LEFT, true, ' ');
		ttable_colseps(tt, 4, RIGHT, true, ' ');
		ttable_colseps(tt, 5, LEFT, true, ' ');

		/* Dump the generated table. */
		if (tt->nrows > 1) {
			char *table;

			table = ttable_dump(tt, "\n");
			vty_out(vty, "%s\n", table);
			XFREE(MTYPE_TMP_TTABLE, table);
		}
		ttable_del(tt);
	}
}

DEFPY (show_srv6_sid,
       show_srv6_sid_cmd,
       "show segment-routing srv6 [locator NAME$locator_name] sid [X:X::X:X$sid_value] [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Locator Information\n"
       "Locator Name\n"
       "SID\n"
       "SID value\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator = NULL;
	struct zebra_srv6_sid_ctx *sid_ctx = NULL, *c;
	struct listnode *node;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	if (locator_name) {
		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator) {
			if (uj)
				vty_json(vty, json); /* Return empty json */
			else
				vty_out(vty, "%% Can't find the SRv6 locator\n");
			return CMD_WARNING;
		}
	}

	if (!IPV6_ADDR_SAME(&sid_value, &in6addr_any)) {
		for (ALL_LIST_ELEMENTS_RO(srv6->sids, node, c)) {
			if (c->sid && IPV6_ADDR_SAME(&c->sid->value, &sid_value)) {
				sid_ctx = c;
				break;
			}
		}

		if (!sid_ctx) {
			if (uj)
				vty_json(vty, json); /* Return empty json */
			else
				vty_out(vty, "%% Can't find the SRv6 SID\n");
			return CMD_WARNING;
		}
	}

	if (locator && sid_ctx)
		if (!sid_ctx->sid || sid_ctx->sid->locator != locator) {
			if (uj)
				vty_json(vty, json); /* Return empty json */
			else
				vty_out(vty, "%% Can't find the SRv6 SID in the provided locator\n");
			return CMD_WARNING;
		}

	if (sid_ctx)
		do_show_srv6_sid_specific(vty, uj ? &json : NULL, locator, sid_ctx);
	else
		do_show_srv6_sid_all(vty, uj ? &json : NULL, locator);

	if (uj)
		vty_json(vty, json);

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
		return CMD_SUCCESS;
	}

	locator = srv6_locator_alloc(argv[1]->arg);
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

DEFPY (locator_prefix,
       locator_prefix_cmd,
       "prefix X:X::X:X/M$prefix [block-len (16-64)$block_bit_len]  \
	        [node-len (0-64)$node_bit_len] [func-bits (0-64)$func_bit_len]",
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
	int idx = 0;
	bool node_bit_not_conf = false;

	locator->prefix = *prefix;
	/* Only set default if func_bit_len was not provided in command */
	if (func_bit_len == 0 && !argv_find(argv, argc, "func-bits", &idx))
		func_bit_len = ZEBRA_SRV6_FUNCTION_LENGTH;

	if (node_bit_len == 0 && !argv_find(argv, argc, "node-len", &idx))
		node_bit_not_conf = true;

	expected_prefixlen = prefix->prefixlen;
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

	if (prefix->prefixlen != expected_prefixlen) {
		vty_out(vty,
			"%% Locator prefix length '%u' inconsistent with configured format '%s'. Please either use a prefix length that is consistent with the format or change the format.\n",
			prefix->prefixlen, format->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Resolve optional arguments */
	if (block_bit_len == 0 && node_bit_not_conf) {
		block_bit_len = prefix->prefixlen -
				ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
		node_bit_len = ZEBRA_SRV6_LOCATOR_NODE_LENGTH;
	} else if (block_bit_len == 0) {
		block_bit_len = prefix->prefixlen - node_bit_len;
	} else if (node_bit_not_conf) {
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

				chunk->prefix = *prefix;
				frr_each (zserv_client_list, &zrouter.client_list, client) {
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

DEFPY (locator_flavor_psp,
       locator_flavor_psp_cmd,
       "[no] flavor psp",
       NO_STR
       "Configure SRv6 flavors\n"
       "Specify Penultimate Segment Popping flavor\n")
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);

	if (no && !CHECK_FLAG(locator->flags, SRV6_LOCATOR_PSP))
		/* SRv6 locator PSP flag already unset, nothing to do */
		return CMD_SUCCESS;

	if (!no && CHECK_FLAG(locator->flags, SRV6_LOCATOR_PSP))
		/* SRv6 locator PSP flag already set, nothing to do */
		return CMD_SUCCESS;

	/* Remove old locator from zclients */
	zebra_notify_srv6_locator_delete(locator);

	/* Set/Unset the SRV6_LOCATOR_USID */
	if (no)
		UNSET_FLAG(locator->flags, SRV6_LOCATOR_PSP);
	else
		SET_FLAG(locator->flags, SRV6_LOCATOR_PSP);

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

/* Helper function to check if a SID format is using the default config */
static bool has_default_sid_format_config(struct srv6_sid_format *format)
{
	bool has_default_config = true;

	switch (format->type) {
	case SRV6_SID_FORMAT_TYPE_USID:
		if (format->config.usid.lib_start != SRV6_SID_FORMAT_USID_F3216_LIB_START)
			has_default_config = false;

		if (format->config.usid.elib_start != SRV6_SID_FORMAT_USID_F3216_ELIB_START)
			has_default_config = false;

		if (format->config.usid.elib_end != SRV6_SID_FORMAT_USID_F3216_ELIB_END)
			has_default_config = false;

		if (format->config.usid.wlib_start != SRV6_SID_FORMAT_USID_F3216_WLIB_START)
			has_default_config = false;

		if (format->config.usid.wlib_end != SRV6_SID_FORMAT_USID_F3216_WLIB_END)
			has_default_config = false;

		if (format->config.usid.ewlib_start != SRV6_SID_FORMAT_USID_F3216_EWLIB_START)
			has_default_config = false;

		break;

	case SRV6_SID_FORMAT_TYPE_UNCOMPRESSED:
		if (format->config.uncompressed.explicit_start !=
		    SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START)
			has_default_config = false;

		break;

	case SRV6_SID_FORMAT_TYPE_UNSPEC:
		break;
	}

	return has_default_config;
}

/* Helper function to check if all SID formats are using the default config */
static bool has_default_sid_format_config_all(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	struct srv6_sid_format *format;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format))
		if (!has_default_sid_format_config(format))
			return false;

	return true;
}
static int zebra_sr_config(struct vty *vty)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	struct srv6_locator *locator;
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
			if (locator->block_bits_length !=
			    locator->prefix.prefixlen - ZEBRA_SRV6_LOCATOR_NODE_LENGTH)
				vty_out(vty, " block-len %u",
					locator->block_bits_length);
			if (locator->node_bits_length != ZEBRA_SRV6_LOCATOR_NODE_LENGTH)
				vty_out(vty, " node-len %u",
					locator->node_bits_length);

			if (locator->function_bits_length != ZEBRA_SRV6_FUNCTION_LENGTH)
				vty_out(vty, " func-bits %u", locator->function_bits_length);

			if (locator->argument_bits_length)
				vty_out(vty, " arg-len %u",
					locator->argument_bits_length);
			vty_out(vty, "\n");
			if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))
				vty_out(vty, "    behavior usid\n");
			if (CHECK_FLAG(locator->flags, SRV6_LOCATOR_PSP))
				vty_out(vty, "    flavor psp\n");
			if (locator->sid_format) {
				format = locator->sid_format;
				vty_out(vty, "    format %s\n", format->name);
			}
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
		vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");

		if (!has_default_sid_format_config_all()) {
			vty_out(vty, "  formats\n");
			for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format)) {
				if (has_default_sid_format_config(format))
					/* This SID format is using the default config, skipping */
					continue;

				if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
					vty_out(vty, "   format %s\n", format->name);
					if (format->config.uncompressed.explicit_start !=
					    SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START)
						vty_out(vty, "    explicit start %u\n",
							format->config.uncompressed.explicit_start);
				}
				if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
					vty_out(vty, "   format %s\n", format->name);
					if (format->config.usid.lib_start !=
					    SRV6_SID_FORMAT_USID_F3216_LIB_START)
						vty_out(vty, "    local-id-block start %u\n",
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
		}
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
	install_node(&srv6_encap_node);
	install_node(&srv6_sid_formats_node);
	install_node(&srv6_sid_format_usid_f3216_node);
	install_node(&srv6_sid_format_uncompressed_f4024_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
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
	install_element(SRV6_LOC_NODE, &locator_behavior_cmd);
	install_element(SRV6_LOC_NODE, &locator_flavor_psp_cmd);
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
	install_element(VIEW_NODE, &show_srv6_sid_cmd);
}
