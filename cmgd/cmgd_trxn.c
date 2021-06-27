/*
 * CMGD Transactions
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"
#include "cmgd/cmgd_trxn.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_TRXN_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_TRXN_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_TRXN_DBG(fmt, ...)				\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_TRXN_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */


// static struct thread_master *cmgd_trxn_tm = NULL;
static struct cmgd_master *cmgd_trxn_cm = NULL;

// static void cmgd_trxn_register_event(
// 	cmgd_trxn_ctxt_t *trxn, cmgd_frntnd_event_t event);

static cmgd_trxn_ctxt_t *cmgd_frntnd_find_trxn_by_session_id(
	struct cmgd_master *cm, cmgd_session_id_t session_id)
{
	cmgd_trxn_ctxt_t *trxn;

	FOREACH_TRXN_IN_LIST(cm, trxn) {
		if (trxn->session_id == session_id) 
			return trxn;
	}

	return NULL;
}

// static void cmgd_frntnd_trxn_cleanup_old_conn(
// 	cmgd_trxn_ctxt_t *trxn)
// {
// 	cmgd_trxn_ctxt_t *old;

// 	FOREACH_ADPTR_IN_LIST(old) {
// 		if (old != trxn &&
// 			!strncmp(trxn->name, old->name, sizeof(trxn->name))) {
// 			/*
// 			 * We have a Zombie lingering around
// 			 */
// 			CMGD_TRXN_DBG(
// 				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
// 				trxn->name, trxn->conn_fd, old->conn_fd);
// 			cmgd_frntnd_trxn_disconnect(old);
// 		}
// 	}
// }


// static void cmgd_trxn_register_event(
// 	cmgd_trxn_ctxt_t *trxn, cmgd_frntnd_event_t event)
// {
// 	switch (event) {
// 	case CMGD_FRNTND_CONN_READ:
// 		trxn->conn_read_ev = 
// 			thread_add_read(cmgd_trxn_tm,
// 				cmgd_frntnd_trxn_read, trxn,
// 				trxn->conn_fd, NULL);
// 		break;
// 	case CMGD_FRNTND_CONN_WRITE:
// 		trxn->conn_read_ev = 
// 			thread_add_write(cmgd_trxn_tm,
// 				cmgd_frntnd_trxn_write, trxn,
// 				trxn->conn_fd, NULL);
// 		break;
// 	case CMGD_FRNTND_PROC_MSG:
// 		trxn->proc_msg_ev = 
// 			thread_add_timer_msec(cmgd_trxn_tm,
// 				cmgd_frntnd_trxn_proc_msgbufs, trxn,
// 				CMGD_FRNTND_MSG_PROC_DELAY_MSEC, NULL);
// 		break;
// 	default:
// 		assert(!"cmgd_trxn_post_event() called incorrectly");
// 	}
// }

void cmgd_trxn_lock(cmgd_trxn_ctxt_t *trxn)
{
	trxn->refcount++;
}

extern void cmgd_trxn_unlock(cmgd_trxn_ctxt_t **trxn)
{
	assert(*trxn && (*trxn)->refcount);

	(*trxn)->refcount--;
	if (!(*trxn)->refcount) {
		cmgd_trxn_list_del(&(*trxn)->cm->cmgd_trxns, *trxn);

		// stream_fifo_free((*trxn)->ibuf_fifo);
		// stream_free((*trxn)->ibuf_work);
		// stream_fifo_free((*trxn)->obuf_fifo);
		// stream_free((*trxn)->obuf_work);

		XFREE(MTYPE_CMGD_TRXN, *trxn);
	}

	*trxn = NULL;
}

int cmgd_trxn_init(struct cmgd_master *cm)
{
	if (!cmgd_trxn_cm) {
		cmgd_trxn_cm = cm;
		cmgd_trxn_list_init(&cm->cmgd_trxns);
		assert(!cm->cfg_trxn);
		cm->cfg_trxn = NULL;
	}

	return 0;
}

cmgd_trxn_id_t cmgd_create_trxn(
        cmgd_session_id_t session_id, cmgd_trxn_type_t type)
{
	cmgd_trxn_ctxt_t *trxn = NULL;

	trxn = cmgd_frntnd_find_trxn_by_session_id(cmgd_trxn_cm, session_id);
	if (!trxn) {
		trxn = XMALLOC(MTYPE_CMGD_TRXN, 
				sizeof(cmgd_trxn_ctxt_t));
		assert(trxn);

		trxn->session_id = session_id;
		trxn->type = type;
		cmgd_trxn_badptr_list_init(&trxn->bcknd_adptrs);
		cmgd_trxn_lock(trxn);
		cmgd_trxn_list_add_tail(&cmgd_trxn_cm->cmgd_trxns, trxn);

		CMGD_TRXN_DBG("Added new CMGD Transaction '%p'", trxn);
	}

	return (cmgd_trxn_id_t) trxn;
}

void cmgd_destroy_trxn(cmgd_trxn_id_t trxn_id)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	// if (trxn) {
		
	// }

	cmgd_trxn_unlock(&trxn);
}

int cmgd_trxn_send_set_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_cfgdata_req_t *cfg_req[], int num_req)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	return 0;
}

int cmgd_trxn_send_commit_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t src_db_id,
        cmgd_database_id_t dst_db_id)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	return 0;
}

int cmgd_trxn_send_get_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	return 0;
}

int cmgd_trxn_send_get_data_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	return 0;
}

void cmgd_trxn_status_write(struct vty *vty)
{
	cmgd_trxn_ctxt_t *trxn;

	vty_out(vty, "CMGD Transactions\n");

	FOREACH_TRXN_IN_LIST(cmgd_trxn_cm, trxn) {
		vty_out(vty, "  Trxn-Id: \t\t\t%p\n", trxn);
		vty_out(vty, "    Session-Id: \t\t\t%lx\n", trxn->session_id);
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_trxn_list_count(&cmgd_trxn_cm->cmgd_trxns));
}
