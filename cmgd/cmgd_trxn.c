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

PREDECL_LIST(cmgd_trxn_req_list);

struct cmgd_trxn_ctxt_ {
        cmgd_session_id_t session_id; /* One transaction per client session */
        cmgd_trxn_type_t type;

	// struct cmgd_master *cm;

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

	struct cmgd_trxn_req_list_head set_cfg_reqs;
	struct cmgd_trxn_req_list_head commit_cfg_reqs;
	struct cmgd_trxn_req_list_head get_data_reqs;
};

DECLARE_LIST(cmgd_trxn_list, cmgd_trxn_ctxt_t, list_linkage);

#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	for ((trxn) = cmgd_trxn_list_first(&(cm)->cmgd_trxns); (trxn);	\
		(trxn) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (trxn)))

typedef struct cmgd_set_cfg_req_ {
	cmgd_database_id_t db_id;
	struct nb_cfg_change cfg_changes[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
} cmgd_set_cfg_req_t;

typedef struct cmgd_commit_cfg_req_ {
	cmgd_database_id_t src_db_id;
	cmgd_database_id_t dst_db_id;
	bool validate_only;
} cmgd_commit_cfg_req_t;

typedef struct cmgd_trxn_req_ {
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_event_t req_event;
	cmgd_client_req_id_t req_id;
	union {
		cmgd_set_cfg_req_t *set_cfg;
		cmgd_commit_cfg_req_t *commit_cfg;
	} req;
	struct cmgd_trxn_req_list_item list_linkage;
} cmgd_trxn_req_t;

DECLARE_LIST(cmgd_trxn_req_list, cmgd_trxn_req_t, list_linkage);

#define FOREACH_TRXN_REQ_IN_LIST(list, curr, next)			\
	for ((curr) = cmgd_trxn_req_list_first(list),			\
	     (next) = cmgd_trxn_req_list_next((list), (curr)); (curr);	\
	     (curr) = (next))


static struct thread_master *cmgd_trxn_tm = NULL;
static struct cmgd_master *cmgd_trxn_cm = NULL;

static void cmgd_trxn_register_event(
	cmgd_trxn_ctxt_t *trxn, cmgd_trxn_event_t event);

static cmgd_trxn_req_t *cmgd_trxn_req_alloc(
	cmgd_trxn_ctxt_t *trxn, cmgd_client_req_id_t req_id,
	cmgd_trxn_event_t req_event)
{
	cmgd_trxn_req_t *trxn_req;

	trxn_req = XMALLOC(MTYPE_CMGD_TRXN_REQ, sizeof(cmgd_trxn_req_t));
	assert(trxn_req);
	trxn_req->trxn = trxn;
	cmgd_trxn_lock(trxn);
	trxn_req->req_id = req_id;
	trxn_req->req_event = req_event;
	
	switch (trxn_req->req_event) {
	case CMGD_TRXN_PROC_SETCFG:
		trxn_req->req.set_cfg = XMALLOC(MTYPE_CMGD_TRXN_SETCFG_REQ,
						sizeof(cmgd_set_cfg_req_t));
		assert(trxn_req->req.set_cfg);
		trxn_req->req.set_cfg->num_cfg_changes = 0;
		cmgd_trxn_req_list_add_tail(&trxn->set_cfg_reqs, trxn_req);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		trxn_req->req.commit_cfg = XMALLOC(MTYPE_CMGD_TRXN_COMMCFG_REQ,
						sizeof(cmgd_commit_cfg_req_t));
		assert(trxn_req->req.commit_cfg);
		cmgd_trxn_req_list_add_tail(&trxn->commit_cfg_reqs, trxn_req);
		break;
	case CMGD_TRXN_PROC_GETCFG:
	default:
		break;
	}


	return (trxn_req);
}

static void cmgd_trxn_req_free(cmgd_trxn_req_t **trxn_req)
{
	size_t indx;

	switch ((*trxn_req)->req_event) {
	case CMGD_TRXN_PROC_SETCFG:
		for (indx = 0;
			indx < (*trxn_req)->req.set_cfg->num_cfg_changes;
			indx++) {
			if ((*trxn_req)->req.set_cfg->cfg_changes[indx].value)
				free((void *)(*trxn_req)->req.set_cfg->cfg_changes[indx].value);
		}
		cmgd_trxn_req_list_del(&(*trxn_req)->trxn->set_cfg_reqs, *trxn_req);
		cmgd_trxn_unlock(&(*trxn_req)->trxn);
		XFREE(MTYPE_CMGD_TRXN_SETCFG_REQ, (*trxn_req)->req.set_cfg);
		break;
	default:
		break;
	}
	XFREE(MTYPE_CMGD_TRXN_REQ, (*trxn_req));
	*trxn_req = NULL;
}

static int cmgd_trxn_process_set_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req, *next;
	cmgd_db_hndl_t db_hndl;
	struct nb_config *nb_config;
	char err_buf[1024];
	bool error;
	int num_setcfg_proc = 0;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d SET_CONFIG requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST(&trxn->set_cfg_reqs, trxn_req, next) {
		assert(trxn_req->req_event == CMGD_TRXN_PROC_SETCFG);
		db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_trxn_cm, trxn_req->req.set_cfg->db_id);
		if (!db_hndl) {
			cmgd_frntnd_send_set_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				"No such database!");
			goto cmgd_trxn_process_set_cfg_done;
		}

		nb_config = cmgd_db_get_nb_config(db_hndl);
		if (!db_hndl) {
			cmgd_frntnd_send_set_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				"Unable to retrieve DB Config Tree!");
			goto cmgd_trxn_process_set_cfg_done;
		}

		error = false;
		nb_apply_config_changes(nb_config,
			trxn_req->req.set_cfg->cfg_changes,
			(size_t) trxn_req->req.set_cfg->num_cfg_changes,
			NULL, NULL, 0, err_buf, sizeof(err_buf), &error);
		if (error) {
			cmgd_frntnd_send_set_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				err_buf);
			goto cmgd_trxn_process_set_cfg_done;
		}

		if (cmgd_frntnd_send_set_cfg_reply(
			trxn->session_id, (cmgd_trxn_id_t) trxn,
			trxn_req->req.set_cfg->db_id,
			trxn_req->req_id, CMGD_SUCCESS, NULL) != 0) {
			CMGD_TRXN_ERR("Failed to send SET_CONFIG_REPLY for trxn %p sessn 0x%lx",
				trxn, trxn->session_id);
		}

cmgd_trxn_process_set_cfg_done:

		/*
		 * Note: The following will remove it from the list as well.
		 */
		cmgd_trxn_req_free(&trxn_req);

		num_setcfg_proc++;
		if (num_setcfg_proc == CMGD_TRXN_MAX_NUM_SETCFG_PROC) {
			break;
		}
	}

	if (cmgd_trxn_req_list_count(&trxn->set_cfg_reqs)) {
		CMGD_TRXN_DBG("Processed maximum number of Set-Config requests (%d/%d). Rescheduling for rest.", 
			num_setcfg_proc, CMGD_TRXN_MAX_NUM_SETCFG_PROC);
		cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_SETCFG);
	}
	
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
	(void) cmgd_frntnd_send_commit_cfg_reply(
		trxn->session_id, (cmgd_trxn_id_t) trxn, CMGD_DB_CANDIDATE,
		CMGD_DB_RUNNING, 0, false, CMGD_SUCCESS, NULL);
	
	return 0;
}

static void cmgd_trxn_register_event(
	cmgd_trxn_ctxt_t *trxn, cmgd_trxn_event_t event)
{
	assert(cmgd_trxn_cm && cmgd_trxn_tm);

	switch (event) {
	case CMGD_TRXN_PROC_SETCFG:
		trxn->proc_set_cfg = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_process_set_cfg, trxn,
				CMGD_TRXN_PROC_DELAY_MSEC, NULL);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		trxn->proc_comm_cfg = 
			thread_add_timer_msec(cmgd_trxn_tm,
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

void cmgd_trxn_lock(cmgd_trxn_ctxt_t *trxn)
{
	trxn->refcount++;
}

extern void cmgd_trxn_unlock(cmgd_trxn_ctxt_t **trxn)
{
	assert(*trxn && (*trxn)->refcount);

	(*trxn)->refcount--;
	if (!(*trxn)->refcount) {
		cmgd_trxn_list_del(&cmgd_trxn_cm->cmgd_trxns, *trxn);

		// stream_fifo_free((*trxn)->ibuf_fifo);
		// stream_free((*trxn)->ibuf_work);
		// stream_fifo_free((*trxn)->obuf_fifo);
		// stream_free((*trxn)->obuf_work);

		XFREE(MTYPE_CMGD_TRXN, *trxn);
	}

	*trxn = NULL;
}

int cmgd_trxn_init(struct cmgd_master *cm, struct thread_master *tm)
{
	if (cmgd_trxn_cm || cmgd_trxn_tm)
		assert(!"Call cmgd_trxn_init() only once");

	cmgd_trxn_cm = cm;
	cmgd_trxn_tm = tm;
	cmgd_trxn_list_init(&cm->cmgd_trxns);
	assert(!cm->cfg_trxn);
	cm->cfg_trxn = NULL;

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
		cmgd_trxn_req_list_init(&trxn->set_cfg_reqs);
		cmgd_trxn_req_list_init(&trxn->commit_cfg_reqs);
		cmgd_trxn_req_list_init(&trxn->get_data_reqs);

		CMGD_TRXN_DBG("Added new '%s' CMGD Transaction '%p'",
			cmgd_trxn_type2str(type), trxn);

		if (type == CMGD_TRXN_TYPE_CONFIG)
			cmgd_trxn_cm->cfg_trxn = trxn;
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
	cmgd_trxn_req_t *trxn_req;
	int indx;
	uint16_t *num_chgs;
	struct nb_cfg_change *cfg_chg;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	trxn_req = cmgd_trxn_req_alloc(trxn, req_id, CMGD_TRXN_PROC_SETCFG);
	trxn_req->req.set_cfg->db_id = db_id;
	num_chgs = &trxn_req->req.set_cfg->num_cfg_changes;
	for (indx = 0; indx < num_req; indx++) {
		cfg_chg = &trxn_req->req.set_cfg->cfg_changes[*num_chgs];
		CMGD_TRXN_DBG("XPath: '%s', Value: '%s'",
			cfg_req[indx]->data->xpath,
			(cfg_req[indx]->data->value &&
			 cfg_req[indx]->data->value->encoded_str_val ? 
			 cfg_req[indx]->data->value->encoded_str_val :
			 "NULL"));
		strlcpy(cfg_chg->xpath, cfg_req[indx]->data->xpath, 
			sizeof(cfg_chg->xpath));
		cfg_chg->value = 
			(cfg_req[indx]->data->value &&
			 cfg_req[indx]->data->value->encoded_str_val ? 
			 strdup(cfg_req[indx]->data->value->encoded_str_val) :
			 NULL);
		(*num_chgs)++;
	}
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
