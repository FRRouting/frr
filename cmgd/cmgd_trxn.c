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

typedef enum cmgd_trxn_event_ {
	CMGD_TRXN_PROC_SETCFG = 1,
	CMGD_TRXN_PROC_COMMITCFG,
	CMGD_TRXN_PROC_GETCFG,
	CMGD_TRXN_PROC_GETDATA
} cmgd_trxn_event_t;

#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	for ((trxn) = cmgd_trxn_list_first(&(cm)->cmgd_trxns); (trxn);	\
		(trxn) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (trxn)))

struct cmgd_trxn_ctxt_ {
        cmgd_session_id_t session_id; /* One transaction per client session */
        cmgd_trxn_type_t type;

	struct cmgd_master *cm;

	struct thread *proc_set_cfg;
	struct thread *proc_comm_cfg;

        /* List of backend adapters involved in this transaction */
        struct cmgd_trxn_badptr_list_head bcknd_adptrs;

        /* IO streams for read and write */
	// pthread_mutex_t ibuf_mtx;
	// struct stream_fifo *ibuf_fifo;
	// pthread_mutex_t obuf_mtx;
	// struct stream_fifo *obuf_fifo;

	// /* Private I/O buffers */
	// struct stream *ibuf_work;
	// struct stream *obuf_work;

	/* Buffer of data waiting to be written to client. */
	// struct buffer *wb;

        int refcount;

        struct cmgd_trxn_list_item list_linkage;
};

DECLARE_LIST(cmgd_trxn_list, cmgd_trxn_ctxt_t, list_linkage);


static struct thread_master *cmgd_trxn_tm = NULL;
static struct cmgd_master *cmgd_trxn_cm = NULL;

static void cmgd_trxn_register_event(
	cmgd_trxn_ctxt_t *trxn, cmgd_trxn_event_t event);

static int cmgd_trxn_process_set_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing SET_CONFIG for Trxn:%p Session:0x%lx",
		trxn, trxn->session_id);

	// nb_candidate_edit();

	/*
	 * For now send a positive reply.
	 */
	(void) cmgd_frntnd_send_set_cfg_reply(
		trxn->session_id, (cmgd_trxn_id_t) trxn, CMGD_DB_CANDIDATE,
		0, CMGD_SUCCESS, NULL);
	
	return 0;
}

static int cmgd_trxn_process_commit_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing COMMIT_CONFIG for Trxn:%p Session:0x%lx",
		trxn, trxn->session_id);

	/*
	 * For now send a positive reply.
	 */
	// (void) cmgd_frntnd_send_comm_cfg_reply(
	// 	trxn->session_id, (cmgd_trxn_id_t) trxn, CMGD_DB_CANDIDATE,
	// 	0, CMGD_SUCCESS, NULL);
	
	return 0;
}

static void cmgd_trxn_register_event(
	cmgd_trxn_ctxt_t *trxn, cmgd_trxn_event_t event)
{
	assert(cmgd_trxn_cm && cmgd_trxn_cm->master);

	switch (event) {
	case CMGD_TRXN_PROC_SETCFG:
		trxn->proc_set_cfg = 
			thread_add_timer_msec(cmgd_trxn_cm->master,
				cmgd_trxn_process_set_cfg, trxn,
				CMGD_TRXN_PROC_DELAY_MSEC, NULL);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		trxn->proc_comm_cfg = 
			thread_add_timer_msec(cmgd_trxn_cm->master,
				cmgd_trxn_process_commit_cfg, trxn,
				CMGD_TRXN_PROC_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_trxn_register_event() called incorrectly");
	}
}

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
		cmgd_trxn_tm = cm->master;
		cmgd_trxn_list_init(&cm->cmgd_trxns);
		assert(!cm->cfg_trxn);
		cm->cfg_trxn = NULL;
	}

	return 0;
}

cmgd_session_id_t cmgd_config_trxn_in_progress(void)
{
	if (cmgd_trxn_cm && cmgd_trxn_cm->cfg_trxn) {
		return cmgd_trxn_cm->cfg_trxn->session_id;
	}

	return CMGD_SESSION_ID_NONE;
}

cmgd_trxn_id_t cmgd_create_trxn(
        cmgd_session_id_t session_id, cmgd_trxn_type_t type)
{
	cmgd_trxn_ctxt_t *trxn = NULL;

	/*
	 * For 'CONFIG' transaction check if one is already created 
	 * or not.
	 */
	if (type == CMGD_TRXN_TYPE_CONFIG && cmgd_trxn_cm->cfg_trxn) {
		if (cmgd_config_trxn_in_progress() == session_id)
			trxn = cmgd_trxn_cm->cfg_trxn;
		goto cmgd_create_trxn_done;
	}

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

		CMGD_TRXN_DBG("Added new '%s' CMGD Transaction '%p'",
			cmgd_trxn_type2str(type), trxn);
	}

cmgd_create_trxn_done:
	return (cmgd_trxn_id_t) trxn;
}

void cmgd_destroy_trxn(cmgd_trxn_id_t trxn_id)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	// if (!trxn) {
		
	// }

	cmgd_trxn_unlock(&trxn);
}

cmgd_trxn_type_t cmgd_get_trxn_type(cmgd_trxn_id_t trxn_id)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn) {
		return CMGD_TRXN_TYPE_NONE;
	}

	return trxn->type;
}

int cmgd_trxn_send_set_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t db_id,
        cmgd_yang_cfgdata_req_t *cfg_req[], int num_req)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	/*
	 * For now send a positive reply back.
	 */
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_SETCFG);

	return 0;
}

int cmgd_trxn_send_commit_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t src_db_id, cmgd_database_id_t dst_db_id,
	bool validate_only)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	/*
	 * For now send a positive reply back.
	 */
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_COMMITCFG);
	return 0;
}

int cmgd_trxn_send_get_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	return 0;
}

int cmgd_trxn_send_get_data_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t db_id,
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
