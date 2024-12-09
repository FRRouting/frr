// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 */

#include "zebra.h"

#include "srv6.h"
#include "log.h"

DEFINE_QOBJ_TYPE(srv6_locator);
DEFINE_QOBJ_TYPE(srv6_sid_format);
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR, "SRV6 locator");
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR_CHUNK, "SRV6 locator chunk");
DEFINE_MTYPE_STATIC(LIB, SRV6_SID_FORMAT, "SRv6 SID format");
DEFINE_MTYPE_STATIC(LIB, SRV6_SID_CTX, "SRv6 SID context");

const char *seg6local_action2str(uint32_t action)
{
	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		return "End";
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
		return "End.X";
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
		return "End.T";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
		return "End.DX2";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		return "End.DX6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		return "End.DX4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		return "End.DT6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		return "End.DT4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
		return "End.B6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
		return "End.B6.Encap";
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
		return "End.BM";
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
		return "End.S";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
		return "End.AS";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
		return "End.AM";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		return "End.DT46";
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs)
{
	str[0] = '\0';
	for (size_t i = 0; i < segs->num_segs; i++) {
		char addr[INET6_ADDRSTRLEN];
		bool not_last = (i + 1) < segs->num_segs;

		inet_ntop(AF_INET6, &segs->segs[i], addr, sizeof(addr));
		strlcat(str, addr, size);
		strlcat(str, not_last ? "," : "", size);
	}
	return strlen(str);
}

void seg6local_context2json(const struct seg6local_context *ctx,
			    uint32_t action, json_object *json)
{
	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		json_object_boolean_add(json, "USP", true);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		json_object_string_addf(json, "nh6", "%pI6", &ctx->nh6);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		json_object_string_addf(json, "nh4", "%pI4", &ctx->nh4);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		json_object_int_add(json, "table", ctx->table);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
		json_object_boolean_add(json, "none", true);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
		json_object_string_addf(json, "nh6", "%pI6", &ctx->nh6);
		return;
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
	default:
		json_object_boolean_add(json, "unknown", true);
		return;
	}
}

const char *seg6local_context2str(char *str, size_t size,
				  const struct seg6local_context *ctx,
				  uint32_t action)
{
	switch (action) {

	case ZEBRA_SEG6_LOCAL_ACTION_END:
		snprintf(str, size, "USP");
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		snprintfrr(str, size, "nh6 %pI6", &ctx->nh6);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		snprintfrr(str, size, "nh4 %pI4", &ctx->nh4);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		snprintf(str, size, "table %u", ctx->table);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
		snprintfrr(str, size, "nh6 %pI6", &ctx->nh6);
		return str;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
	default:
		snprintf(str, size, "unknown(%s)", __func__);
		return str;
	}
}

void srv6_locator_chunk_list_free(void *data)
{
	struct srv6_locator_chunk *chunk = data;

	srv6_locator_chunk_free(&chunk);
}

struct srv6_locator *srv6_locator_alloc(const char *name)
{
	struct srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_SRV6_LOCATOR, sizeof(struct srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));
	locator->chunks = list_new();
	locator->chunks->del = srv6_locator_chunk_list_free;

	locator->sids = list_new();

	QOBJ_REG(locator, srv6_locator);
	return locator;
}
void srv6_locator_del(struct srv6_locator *locator)
{
	if (locator->chunks)
		list_delete(&locator->chunks);
	if (locator->sids)
		list_delete(&locator->sids);
	XFREE(MTYPE_SRV6_LOCATOR, locator);
}

struct srv6_locator_chunk *srv6_locator_chunk_alloc(void)
{
	struct srv6_locator_chunk *chunk = NULL;

	chunk = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK,
			sizeof(struct srv6_locator_chunk));
	return chunk;
}

void srv6_locator_copy(struct srv6_locator *copy,
		       const struct srv6_locator *locator)
{
	strlcpy(copy->name, locator->name, sizeof(locator->name));
	copy->prefix = locator->prefix;
	copy->block_bits_length = locator->block_bits_length;
	copy->node_bits_length = locator->node_bits_length;
	copy->function_bits_length = locator->function_bits_length;
	copy->argument_bits_length = locator->argument_bits_length;
	copy->algonum = locator->algonum;
	copy->current = locator->current;
	copy->status_up = locator->status_up;
	copy->flags = locator->flags;
}

void srv6_locator_free(struct srv6_locator *locator)
{
	if (locator) {
		QOBJ_UNREG(locator);
		list_delete(&locator->chunks);

		XFREE(MTYPE_SRV6_LOCATOR, locator);
	}
}

struct seg6_sid *srv6_locator_sid_alloc(void)
{
	struct seg6_sid *sid = NULL;

	sid = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK, sizeof(struct seg6_sid));
	strlcpy(sid->vrfName, "Default", sizeof(sid->vrfName));
	return sid;
}
void srv6_locator_sid_free(struct seg6_sid *sid)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, sid);
}

void combine_sid(struct srv6_locator *locator, struct in6_addr *sid_addr,
		 struct in6_addr *result_addr)
{
	uint8_t idx = 0;
	uint8_t funcid = 0;
	uint8_t locatorbit = 0;
	/* uint8_t sidbit = 0;*/
	uint8_t totalbit = 0;
	uint8_t funbit = 0;

	locatorbit = (locator->block_bits_length + locator->node_bits_length) / 8;
	/* sidbit = 16 - locatorbit; */
	totalbit = (locator->block_bits_length + locator->node_bits_length +
		    locator->function_bits_length + locator->argument_bits_length) /
		   8;
	funbit = (locator->function_bits_length + locator->argument_bits_length) / 8;
	for (idx = 0; idx < locatorbit; idx++)
		result_addr->s6_addr[idx] = locator->prefix.prefix.s6_addr[idx];
	for (; idx < totalbit; idx++) {
		result_addr->s6_addr[idx] = sid_addr->s6_addr[16 - funbit + funcid];
		funcid++;
	}
}

void srv6_locator_chunk_free(struct srv6_locator_chunk **chunk)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, *chunk);
}

struct srv6_sid_format *srv6_sid_format_alloc(const char *name)
{
	struct srv6_sid_format *format = NULL;

	format = XCALLOC(MTYPE_SRV6_SID_FORMAT, sizeof(struct srv6_sid_format));
	strlcpy(format->name, name, sizeof(format->name));

	QOBJ_REG(format, srv6_sid_format);
	return format;
}

void srv6_sid_format_free(struct srv6_sid_format *format)
{
	if (!format)
		return;

	QOBJ_UNREG(format);
	XFREE(MTYPE_SRV6_SID_FORMAT, format);
}

/**
 * Free an SRv6 SID format.
 *
 * @param val SRv6 SID format to be freed
 */
void delete_srv6_sid_format(void *val)
{
	srv6_sid_format_free((struct srv6_sid_format *)val);
}

struct srv6_sid_ctx *srv6_sid_ctx_alloc(enum seg6local_action_t behavior,
					struct in_addr *nh4,
					struct in6_addr *nh6, vrf_id_t vrf_id)
{
	struct srv6_sid_ctx *ctx = NULL;

	ctx = XCALLOC(MTYPE_SRV6_SID_CTX, sizeof(struct srv6_sid_ctx));
	ctx->behavior = behavior;
	if (nh4)
		ctx->nh4 = *nh4;
	if (nh6)
		ctx->nh6 = *nh6;
	if (vrf_id)
		ctx->vrf_id = vrf_id;

	return ctx;
}

void srv6_sid_ctx_free(struct srv6_sid_ctx *ctx)
{
	XFREE(MTYPE_SRV6_SID_CTX, ctx);
}

json_object *srv6_locator_chunk_json(const struct srv6_locator_chunk *chunk)
{
	json_object *jo_root = NULL;

	jo_root = json_object_new_object();
	json_object_string_addf(jo_root, "prefix", "%pFX", &chunk->prefix);
	json_object_string_add(jo_root, "proto",
			       zebra_route_string(chunk->proto));

	return jo_root;
}

json_object *
srv6_locator_chunk_detailed_json(const struct srv6_locator_chunk *chunk)
{
	json_object *jo_root = NULL;

	jo_root = json_object_new_object();

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &chunk->prefix);

	/* set block_bits_length */
	json_object_int_add(jo_root, "blockBitsLength",
			    chunk->block_bits_length);

	/* set node_bits_length */
	json_object_int_add(jo_root, "nodeBitsLength", chunk->node_bits_length);

	/* set function_bits_length */
	json_object_int_add(jo_root, "functionBitsLength",
			    chunk->function_bits_length);

	/* set argument_bits_length */
	json_object_int_add(jo_root, "argumentBitsLength",
			    chunk->argument_bits_length);

	/* set keep */
	json_object_int_add(jo_root, "keep", chunk->keep);

	/* set proto */
	json_object_string_add(jo_root, "proto",
			       zebra_route_string(chunk->proto));

	/* set instance */
	json_object_int_add(jo_root, "instance", chunk->instance);

	/* set session_id */
	json_object_int_add(jo_root, "sessionId", chunk->session_id);

	return jo_root;
}

json_object *srv6_locator_sid_detailed_json(const struct srv6_locator *locator,
					    const struct seg6_sid *sid)
{
	json_object *jo_root = NULL;
	char buf[256];

	jo_root = json_object_new_object();

	/* set opcode */
	prefix2str(&sid->ipv6Addr, buf, sizeof(buf));
	json_object_string_add(jo_root, "opcode", buf);

	/* set sidaction */
	json_object_string_add(jo_root, "sidaction", seg6local_action2str(sid->sidaction));

	/* set vrf */
	json_object_string_add(jo_root, "vrf", sid->vrfName);

	return jo_root;
}

json_object *srv6_locator_json(const struct srv6_locator *loc)
{
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	json_object *jo_root = NULL;
	json_object *jo_chunk = NULL;
	json_object *jo_chunks = NULL;

	jo_root = json_object_new_object();

	/* set name */
	json_object_string_add(jo_root, "name", loc->name);

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &loc->prefix);

	if (loc->sid_format) {
		/* set block_bits_length */
		json_object_int_add(jo_root, "blockBitsLength",
				    loc->sid_format->block_len);

		/* set node_bits_length */
		json_object_int_add(jo_root, "nodeBitsLength",
				    loc->sid_format->node_len);

		/* set function_bits_length */
		json_object_int_add(jo_root, "functionBitsLength",
				    loc->sid_format->function_len);

		/* set argument_bits_length */
		json_object_int_add(jo_root, "argumentBitsLength",
				    loc->sid_format->argument_len);

		/* set true if the locator is a Micro-segment (uSID) locator */
		if (loc->sid_format->type == SRV6_SID_FORMAT_TYPE_USID)
			json_object_string_add(jo_root, "behavior", "usid");
	} else {
		/* set block_bits_length */
		json_object_int_add(jo_root, "blockBitsLength",
				    loc->block_bits_length);

		/* set node_bits_length */
		json_object_int_add(jo_root, "nodeBitsLength",
				    loc->node_bits_length);

		/* set function_bits_length */
		json_object_int_add(jo_root, "functionBitsLength",
				    loc->function_bits_length);

		/* set argument_bits_length */
		json_object_int_add(jo_root, "argumentBitsLength",
				    loc->argument_bits_length);

		/* set true if the locator is a Micro-segment (uSID) locator */
		if (CHECK_FLAG(loc->flags, SRV6_LOCATOR_USID))
			json_object_string_add(jo_root, "behavior", "usid");
	}

	/* set status_up */
	json_object_boolean_add(jo_root, "statusUp",
				loc->status_up);

	/* set chunks */
	jo_chunks = json_object_new_array();
	json_object_object_add(jo_root, "chunks", jo_chunks);
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		jo_chunk = srv6_locator_chunk_json(chunk);
		json_object_array_add(jo_chunks, jo_chunk);
	}

	return jo_root;
}

json_object *srv6_locator_detailed_json(const struct srv6_locator *loc)
{
	struct listnode *node;
	struct listnode *sidnode;
	struct srv6_locator_chunk *chunk;
	struct seg6_sid *sid = NULL;
	json_object *jo_root = NULL;
	json_object *jo_chunk = NULL;
	json_object *jo_chunks = NULL;
	json_object *jo_sid = NULL;
	json_object *jo_sids = NULL;

	jo_root = json_object_new_object();

	/* set name */
	json_object_string_add(jo_root, "name", loc->name);

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &loc->prefix);

	if (loc->sid_format) {
		/* set block_bits_length */
		json_object_int_add(jo_root, "blockBitsLength",
				    loc->sid_format->block_len);

		/* set node_bits_length */
		json_object_int_add(jo_root, "nodeBitsLength",
				    loc->sid_format->node_len);

		/* set function_bits_length */
		json_object_int_add(jo_root, "functionBitsLength",
				    loc->sid_format->function_len);

		/* set argument_bits_length */
		json_object_int_add(jo_root, "argumentBitsLength",
				    loc->sid_format->argument_len);

		/* set true if the locator is a Micro-segment (uSID) locator */
		if (loc->sid_format->type == SRV6_SID_FORMAT_TYPE_USID)
			json_object_string_add(jo_root, "behavior", "usid");
	} else {
		/* set block_bits_length */
		json_object_int_add(jo_root, "blockBitsLength",
				    loc->block_bits_length);

		/* set node_bits_length */
		json_object_int_add(jo_root, "nodeBitsLength",
				    loc->node_bits_length);

		/* set function_bits_length */
		json_object_int_add(jo_root, "functionBitsLength",
				    loc->function_bits_length);

		/* set argument_bits_length */
		json_object_int_add(jo_root, "argumentBitsLength",
				    loc->argument_bits_length);

		/* set true if the locator is a Micro-segment (uSID) locator */
		if (CHECK_FLAG(loc->flags, SRV6_LOCATOR_USID))
			json_object_string_add(jo_root, "behavior", "usid");
	}

	/* set algonum */
	json_object_int_add(jo_root, "algoNum", loc->algonum);

	/* set status_up */
	json_object_boolean_add(jo_root, "statusUp", loc->status_up);

	/* set chunks */
	jo_chunks = json_object_new_array();
	json_object_object_add(jo_root, "chunks", jo_chunks);
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		jo_chunk = srv6_locator_chunk_detailed_json(chunk);
		json_object_array_add(jo_chunks, jo_chunk);
	}
	/* set sids */
	jo_sids = json_object_new_array();
	json_object_object_add(jo_root, "sids", jo_sids);
	for (ALL_LIST_ELEMENTS_RO(loc->sids, sidnode, sid)) {
		jo_sid = srv6_locator_sid_detailed_json(loc, sid);
		json_object_array_add(jo_sids, jo_sid);
	}

	return jo_root;
}
