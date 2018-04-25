/* zebra table Manager for routing table identifier management
 * Copyright (C) 2018 6WIND
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "lib/log.h"
#include "lib/memory.h"
#include "lib/table.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/libfrr.h"
#include "lib/vrf.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/label_manager.h" /* for NO_PROTO */
#include "zebra/table_manager.h"

/* routing table identifiers
 *
 */
#ifdef SUNOS_5
/* SunOS
 */
#else
#if !defined(GNU_LINUX) && !defined(SUNOS_5)
/* BSD systems
 */
#else
/* Linux Systems
 */
#define RT_TABLE_ID_LOCAL                  255
#define RT_TABLE_ID_MAIN                   254
#define RT_TABLE_ID_DEFAULT                253
#define RT_TABLE_ID_COMPAT                 252
#define RT_TABLE_ID_UNSPEC                 0
#endif /* !def(GNU_LINUX) && !defined(SUNOS_5) */
#endif /* SUNOS_5 */
#define RT_TABLE_ID_UNRESERVED_MIN         1
#define RT_TABLE_ID_UNRESERVED_MAX         0xffffffff

struct table_manager tbl_mgr;

DEFINE_MGROUP(TABLE_MGR, "Table Manager");
DEFINE_MTYPE_STATIC(TABLE_MGR, TM_CHUNK, "Table Manager Chunk");

static void delete_table_chunk(void *val)
{
	XFREE(MTYPE_TM_CHUNK, val);
}

/**
 * Init table manager
 */
void table_manager_enable(ns_id_t ns_id)
{
	if (ns_id != NS_DEFAULT)
		return;
	tbl_mgr.lc_list = list_new();
	tbl_mgr.lc_list->del = delete_table_chunk;
	hook_register(zserv_client_close, release_daemon_table_chunks);
}

/**
 * Core function, assigns table chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @para size Size of the table chunk
 * @return Pointer to the assigned table chunk
 */
struct table_manager_chunk *assign_table_chunk(uint8_t proto, uint16_t instance,
					       uint32_t size)
{
	struct table_manager_chunk *tmc;
	struct listnode *node;
	uint32_t start;

	/* first check if there's one available */
	for (ALL_LIST_ELEMENTS_RO(tbl_mgr.lc_list, node, tmc)) {
		if (tmc->proto == NO_PROTO
		    && tmc->end - tmc->start + 1 == size) {
			tmc->proto = proto;
			tmc->instance = instance;
			return tmc;
		}
	}
	/* otherwise create a new one */
	tmc = XCALLOC(MTYPE_TM_CHUNK, sizeof(struct table_manager_chunk));
	if (!tmc)
		return NULL;

	/* table RT IDs range are [1;252] and [256;0xffffffff]
	 * - check if the requested range can be within the first range,
	 * otherwise elect second one
	 * - TODO : vrf-lites have their own table identifier.
	 * In that case, table_id should be removed from the table range.
	 */
	if (list_isempty(tbl_mgr.lc_list))
		start = RT_TABLE_ID_UNRESERVED_MIN;
	else
		start = ((struct table_manager_chunk *)listgetdata(
			   listtail(tbl_mgr.lc_list)))->end + 1;

#ifdef SUNOS_5
/* SunOS
 */
#else
#if !defined(GNU_LINUX) && !defined(SUNOS_5)
/* BSD systems
 */
#else
/* Linux Systems
 */
	/* if not enough room space between MIN and COMPAT,
	 * then begin after LOCAL
	 */
	if (start < RT_TABLE_ID_COMPAT && (size >
				RT_TABLE_ID_COMPAT
				- RT_TABLE_ID_UNRESERVED_MIN))
		start = RT_TABLE_ID_LOCAL + 1;
#endif /* !def(GNU_LINUX) && !defined(SUNOS_5) */
#endif /* SUNOS_5 */
	tmc->start = start;
	if (RT_TABLE_ID_UNRESERVED_MAX - size  + 1 < start) {
		zlog_err("Reached max table id. Start/Size %u/%u",
			 start, size);
		XFREE(MTYPE_TM_CHUNK, tmc);
		return NULL;
	}
	tmc->end = tmc->start + size - 1;
	tmc->proto = proto;
	tmc->instance = instance;
	listnode_add(tbl_mgr.lc_list, tmc);

	return tmc;
}

/**
 * Core function, release no longer used table chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param start First table RT ID of the chunk
 * @param end Last table RT ID of the chunk
 * @return 0 on success, -1 otherwise
 */
int release_table_chunk(uint8_t proto, uint16_t instance, uint32_t start,
			uint32_t end)
{
	struct listnode *node;
	struct table_manager_chunk *tmc;
	int ret = -1;

	/* check that size matches */
	zlog_debug("Releasing table chunk: %u - %u", start, end);
	/* find chunk and disown */
	for (ALL_LIST_ELEMENTS_RO(tbl_mgr.lc_list, node, tmc)) {
		if (tmc->start != start)
			continue;
		if (tmc->end != end)
			continue;
		if (tmc->proto != proto || tmc->instance != instance) {
			zlog_err("%s: Daemon mismatch!!", __func__);
			continue;
		}
		tmc->proto = NO_PROTO;
		tmc->instance = 0;
		ret = 0;
		break;
	}
	if (ret != 0)
		zlog_err("%s: Table chunk not released!!", __func__);

	return ret;
}

/**
 * Release table chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param client the client to release chunks from
 * @return Number of chunks released
 */
int release_daemon_table_chunks(struct zserv *client)
{
	uint8_t proto = client->proto;
	uint16_t instance = client->instance;
	struct listnode *node;
	struct table_manager_chunk *tmc;
	int count = 0;
	int ret;

	for (ALL_LIST_ELEMENTS_RO(tbl_mgr.lc_list, node, tmc)) {
		if (tmc->proto == proto && tmc->instance == instance) {
			ret = release_table_chunk(tmc->proto, tmc->instance,
						  tmc->start, tmc->end);
			if (ret == 0)
				count++;
		}
	}

	zlog_debug("%s: Released %d table chunks", __func__, count);

	return count;
}

void table_manager_disable(ns_id_t ns_id)
{
	if (ns_id != NS_DEFAULT)
		return;
	list_delete_and_null(&tbl_mgr.lc_list);
}
