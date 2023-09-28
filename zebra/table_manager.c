// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra table Manager for routing table identifier management
 * Copyright (C) 2018 6WIND
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
#include "zebra/zebra_errors.h"

/* routing table identifiers
 *
 */
#if !defined(GNU_LINUX)
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
#endif /* !def(GNU_LINUX) */
#define RT_TABLE_ID_UNRESERVED_MIN         1
#define RT_TABLE_ID_UNRESERVED_MAX         0xffffffff

DEFINE_MGROUP(TABLE_MGR, "Table Manager");
DEFINE_MTYPE_STATIC(TABLE_MGR, TM_CHUNK, "Table Manager Chunk");
DEFINE_MTYPE_STATIC(TABLE_MGR, TM_TABLE, "Table Manager Context");

static void delete_table_chunk(void *val)
{
	XFREE(MTYPE_TM_CHUNK, val);
}

/**
 * Init table manager
 */
void table_manager_enable(struct zebra_vrf *zvrf)
{

	if (zvrf->tbl_mgr)
		return;
	if (!vrf_is_backend_netns()
	    && strcmp(zvrf_name(zvrf), VRF_DEFAULT_NAME)) {
		struct zebra_vrf *def = zebra_vrf_lookup_by_id(VRF_DEFAULT);

		zvrf->tbl_mgr = def->tbl_mgr;
		return;
	}
	zvrf->tbl_mgr = XCALLOC(MTYPE_TM_TABLE, sizeof(struct table_manager));
	zvrf->tbl_mgr->lc_list = list_new();
	zvrf->tbl_mgr->lc_list->del = delete_table_chunk;
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
					       uint32_t size,
					       struct zebra_vrf *zvrf)
{
	struct table_manager_chunk *tmc;
	struct listnode *node;
	uint32_t start;
	bool manual_conf = false;

	if (!zvrf)
		return NULL;

	/* first check if there's one available */
	for (ALL_LIST_ELEMENTS_RO(zvrf->tbl_mgr->lc_list, node, tmc)) {
		if (tmc->proto == NO_PROTO
		    && tmc->end - tmc->start + 1 == size) {
			tmc->proto = proto;
			tmc->instance = instance;
			return tmc;
		}
	}
	/* otherwise create a new one */
	tmc = XCALLOC(MTYPE_TM_CHUNK, sizeof(struct table_manager_chunk));

	if (zvrf->tbl_mgr->start || zvrf->tbl_mgr->end)
		manual_conf = true;
	/* table RT IDs range are [1;252] and [256;0xffffffff]
	 * - check if the requested range can be within the first range,
	 * otherwise elect second one
	 * - TODO : vrf-lites have their own table identifier.
	 * In that case, table_id should be removed from the table range.
	 */
	if (list_isempty(zvrf->tbl_mgr->lc_list)) {
		if (!manual_conf)
			start = RT_TABLE_ID_UNRESERVED_MIN;
		else
			start = zvrf->tbl_mgr->start;
	} else
		start = ((struct table_manager_chunk *)listgetdata(
				 listtail(zvrf->tbl_mgr->lc_list)))
				->end
			+ 1;

	if (!manual_conf) {

#if !defined(GNU_LINUX)
/* BSD systems
 */
#else
/* Linux Systems
 */
		/* if not enough room space between MIN and COMPAT,
		 * then begin after LOCAL
		 */
		if (start < RT_TABLE_ID_COMPAT
		    && (size > RT_TABLE_ID_COMPAT - RT_TABLE_ID_UNRESERVED_MIN))
			start = RT_TABLE_ID_LOCAL + 1;
#endif /* !def(GNU_LINUX) */
		tmc->start = start;
		if (RT_TABLE_ID_UNRESERVED_MAX - size + 1 < start) {
			flog_err(EC_ZEBRA_TM_EXHAUSTED_IDS,
				 "Reached max table id. Start/Size %u/%u",
				 start, size);
			XFREE(MTYPE_TM_CHUNK, tmc);
			return NULL;
		}
	} else {
		tmc->start = start;
		if (zvrf->tbl_mgr->end - size + 1 < start) {
			flog_err(EC_ZEBRA_TM_EXHAUSTED_IDS,
				 "Reached max table id. Start/Size %u/%u",
				 start, size);
			XFREE(MTYPE_TM_CHUNK, tmc);
			return NULL;
		}
	}
	tmc->end = tmc->start + size - 1;
	tmc->proto = proto;
	tmc->instance = instance;
	listnode_add(zvrf->tbl_mgr->lc_list, tmc);

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
			uint32_t end, struct zebra_vrf *zvrf)
{
	struct listnode *node;
	struct table_manager_chunk *tmc;
	int ret = -1;
	struct table_manager *tbl_mgr;

	if (!zvrf)
		return -1;

	tbl_mgr = zvrf->tbl_mgr;
	if (!tbl_mgr)
		return ret;
	/* check that size matches */
	zlog_debug("Releasing table chunk: %u - %u", start, end);
	/* find chunk and disown */
	for (ALL_LIST_ELEMENTS_RO(tbl_mgr->lc_list, node, tmc)) {
		if (tmc->start != start)
			continue;
		if (tmc->end != end)
			continue;
		if (tmc->proto != proto || tmc->instance != instance) {
			flog_err(EC_ZEBRA_TM_DAEMON_MISMATCH,
				 "%s: Daemon mismatch!!", __func__);
			continue;
		}
		tmc->proto = NO_PROTO;
		tmc->instance = 0;
		ret = 0;
		break;
	}
	if (ret != 0)
		flog_err(EC_ZEBRA_TM_UNRELEASED_CHUNK,
			 "%s: Table chunk not released!!", __func__);

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
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;

		if (!zvrf)
			continue;
		if (!vrf_is_backend_netns() && vrf->vrf_id != VRF_DEFAULT)
			continue;
		for (ALL_LIST_ELEMENTS_RO(zvrf->tbl_mgr->lc_list, node, tmc)) {
			if (tmc->proto == proto && tmc->instance == instance) {
				ret = release_table_chunk(
					tmc->proto, tmc->instance, tmc->start,
					tmc->end, zvrf);
				if (ret == 0)
					count++;
			}
		}
	}
	zlog_debug("%s: Released %d table chunks", __func__, count);

	return count;
}

static void table_range_add(struct zebra_vrf *zvrf, uint32_t start,
			    uint32_t end)
{
	if (!zvrf->tbl_mgr)
		return;
	zvrf->tbl_mgr->start = start;
	zvrf->tbl_mgr->end = end;
}

void table_manager_disable(struct zebra_vrf *zvrf)
{
	if (!zvrf->tbl_mgr)
		return;
	if (!vrf_is_backend_netns()
	    && strcmp(zvrf_name(zvrf), VRF_DEFAULT_NAME)) {
		zvrf->tbl_mgr = NULL;
		return;
	}
	list_delete(&zvrf->tbl_mgr->lc_list);
	XFREE(MTYPE_TM_TABLE, zvrf->tbl_mgr);
	zvrf->tbl_mgr = NULL;
}

int table_manager_range(struct vty *vty, bool add, struct zebra_vrf *zvrf,
			const char *start_table_str, const char *end_table_str)
{
	uint32_t start;
	uint32_t end;

	if (add) {
		if (!start_table_str || !end_table_str) {
			vty_out(vty, "%% Labels not specified\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		start = atoi(start_table_str);
		end = atoi(end_table_str);
		if (end < start) {
			vty_out(vty, "%% End table is less than Start table\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

#if !defined(GNU_LINUX)
/* BSD systems
 */
#else
		/* Linux Systems
		 */
		if ((start >= RT_TABLE_ID_COMPAT && start <= RT_TABLE_ID_LOCAL)
		    || (end >= RT_TABLE_ID_COMPAT
			&& end <= RT_TABLE_ID_LOCAL)) {
			vty_out(vty, "%% Values forbidden in range [%u;%u]\n",
				RT_TABLE_ID_COMPAT, RT_TABLE_ID_LOCAL);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (start < RT_TABLE_ID_COMPAT && end > RT_TABLE_ID_LOCAL) {
			vty_out(vty,
				"%% Range overlaps range [%u;%u] forbidden\n",
				RT_TABLE_ID_COMPAT, RT_TABLE_ID_LOCAL);
			return CMD_WARNING_CONFIG_FAILED;
		}
#endif
		if (zvrf->tbl_mgr
		    && ((zvrf->tbl_mgr->start && zvrf->tbl_mgr->start != start)
			|| (zvrf->tbl_mgr->end && zvrf->tbl_mgr->end != end))) {
			vty_out(vty,
				"%% New range will be taken into account at restart\n");
		}
		table_range_add(zvrf, start, end);
	} else
		table_range_add(zvrf, 0, 0);
	return CMD_SUCCESS;
}
