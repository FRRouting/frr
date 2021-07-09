/*
 * SRv6 definitions
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

#include "zebra.h"

#include "srv6.h"
#include "log.h"

DEFINE_QOBJ_TYPE(srv6_locator);
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR, "SRV6 locator");
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR_CHUNK, "SRV6 locator chunk");

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

const char *seg6local_context2str(char *str, size_t size,
				  const struct seg6local_context *ctx,
				  uint32_t action)
{
	char b0[128];

	switch (action) {

	case ZEBRA_SEG6_LOCAL_ACTION_END:
		snprintf(str, size, "USP");
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		inet_ntop(AF_INET6, &ctx->nh6, b0, 128);
		snprintf(str, size, "nh6 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		inet_ntop(AF_INET, &ctx->nh4, b0, 128);
		snprintf(str, size, "nh4 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		snprintf(str, size, "table %u", ctx->table);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
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

struct srv6_locator *srv6_locator_alloc(const char *name)
{
	struct srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_SRV6_LOCATOR, sizeof(struct srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));
	locator->chunks = list_new();
	QOBJ_REG(locator, srv6_locator);
	return locator;
}

struct srv6_locator_chunk *srv6_locator_chunk_alloc(void)
{
	struct srv6_locator_chunk *chunk = NULL;

	chunk = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK,
			sizeof(struct srv6_locator_chunk));
	return chunk;
}

void srv6_locator_free(struct srv6_locator *locator)
{
	XFREE(MTYPE_SRV6_LOCATOR, locator);
}

void srv6_locator_chunk_free(struct srv6_locator_chunk *chunk)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, chunk);
}

json_object *srv6_locator_chunk_json(const struct srv6_locator_chunk *chunk)
{
	char str[256];
	json_object *jo_root = NULL;

	jo_root = json_object_new_object();
	prefix2str(&chunk->prefix, str, sizeof(str));
	json_object_string_add(jo_root, "prefix", str);
	json_object_string_add(jo_root, "proto",
			       zebra_route_string(chunk->proto));

	return jo_root;
}

json_object *srv6_locator_json(const struct srv6_locator *loc)
{
	char str[256];
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	json_object *jo_root = NULL;
	json_object *jo_chunk = NULL;
	json_object *jo_chunks = NULL;

	jo_root = json_object_new_object();

	/* set name */
	json_object_string_add(jo_root, "name", loc->name);

	/* set prefix */
	prefix2str(&loc->prefix, str, sizeof(str));
	json_object_string_add(jo_root, "prefix", str);

	/* set function_bits_length */
	json_object_int_add(jo_root, "functionBitsLength",
			    loc->function_bits_length);

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
