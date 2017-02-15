/*
 * Label Manager for FRR
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "zebra.h"
#include "zserv.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/mpls.h"
#include "lib/stream.h"
#include "lib/zclient.h"

#include "label_manager.h"

struct label_manager lbl_mgr;

DEFINE_MGROUP (LBL_MGR, "Label Manager");
DEFINE_MTYPE_STATIC (LBL_MGR, LM_CHUNK, "Label Manager Chunk");

/* In case this zebra daemon is not acting as label manager,
 * it will be a proxy to relay messages to external label manager
 * This zclient thus is to connect to it
 */
static struct zclient	*zclient;
bool lm_is_external;

static void
delete_label_chunk (void *val)
{
		XFREE (MTYPE_LM_CHUNK, val);
}

/**
 * Receive a request to get or release a label chunk and forward it to external
 * label manager
 */
int
zread_relay_label_chunk_request (struct stream *src)
{
		struct stream		*s;

		s = zclient->obuf;

		stream_copy (s, src);

		return (zclient_send_message(zclient));
}
/**
 * Receive response from an external label manager and forward it
 * to client who requested it
 */
static int
zsend_relay_assign_label_chunk (struct zclient *client, zebra_size_t length,
								vrf_id_t vrf_id)
{
		struct listnode *node, *nnode;
		struct zserv *zserv;

		for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, zserv)) {
				stream_copy (zserv->obuf, client->ibuf);
				zebra_server_send_message(zserv);
		}

		return 0;
}
static void
lm_zclient_init (struct thread_master *master, char *lm_zserv_path)
{
		if (lm_zserv_path)
				zclient_serv_path_set(lm_zserv_path);

		/* Set default values. */
		zclient = zclient_new(master);
		zclient_init(zclient, ZEBRA_LABEL_MANAGER, 0);

		/* set callbacks */
		zclient->assign_label_chunk = zsend_relay_assign_label_chunk;
}
void
label_manager_init (u_short chunk_size, char *lm_zserv_path,
					struct thread_master *master)
{
		/* this is an actual label manager */
		if (!lm_zserv_path) {
				lm_is_external = false;
				lbl_mgr.chunk_size = chunk_size;
				lbl_mgr.lc_list = list_new();
				lbl_mgr.lc_list->del = delete_label_chunk;
		} else { /* it's acting just as a proxy */
				lm_is_external = true;
				lm_zclient_init (master, lm_zserv_path);
		}
}

struct label_manager_chunk *
assign_label_chunk (label_owner_t owner)
{
		struct label_manager_chunk *lmc;
		struct listnode *node;

		node = lbl_mgr.lc_list->head;
		/* first check if there's one available */
		for (ALL_LIST_ELEMENTS_RO (lbl_mgr.lc_list, node, lmc)) {
				if (lmc->owner == NO_OWNER) {
						lmc->owner = owner;
						return lmc;
				}
		}
		/* otherwise create a new one */
		lmc = XCALLOC (MTYPE_LM_CHUNK, sizeof(struct label_manager_chunk));

		if (list_isempty(lbl_mgr.lc_list))
				lmc->start = MPLS_MIN_UNRESERVED_LABEL;
		else
				lmc->start = ((struct label_manager_chunk *)
							  listgetdata(listtail(lbl_mgr.lc_list)))->end + 1;
		lmc->end = lmc->start + lbl_mgr.chunk_size - 1;
		lmc->owner = owner;
		listnode_add (lbl_mgr.lc_list, lmc);

		return lmc;
}

int
release_label_chunk (label_owner_t owner, uint32_t start, uint32_t end)
{
		struct listnode *node;
		struct label_manager_chunk *lmc;
		int ret = -1;

		/* check that size matches */
		zlog_debug ("Relasing %u - %u, chunk size %u", start, end, lbl_mgr.chunk_size);
		if (end - start + 1 != lbl_mgr.chunk_size) {
				zlog_err ("%s: Label chunk not released!!", __func__);
				return -1;
		}
		/* find chunk and disown */
		for (ALL_LIST_ELEMENTS_RO (lbl_mgr.lc_list, node, lmc)) {
				if (lmc->start != start)
						continue;
				if (lmc->end != end)
						continue;
				if (lmc->owner != owner) {
						zlog_err ("%s: Owner mismatch!!", __func__);
						continue;
				}
				lmc->owner = NO_OWNER;
				ret = 0;
				break;
		}
		if (ret != 0)
				zlog_err ("%s: Label chunk not released!!", __func__);

		return ret;
}

void
label_manager_close ()
{
		list_delete (lbl_mgr.lc_list);
}
