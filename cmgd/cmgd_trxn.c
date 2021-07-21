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

typedef struct cmgd_set_cfg_req_ {
	cmgd_database_id_t db_id;
	struct nb_cfg_change cfg_changes[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
} cmgd_set_cfg_req_t;

typedef struct cmgd_commit_cfg_req_ {
	cmgd_database_id_t src_db_id;
	cmgd_database_id_t dst_db_id;
	bool validate_only;
	uint32_t nb_trxn_id;
} cmgd_commit_cfg_req_t;

typedef struct cmgd_get_data_req_ {
	cmgd_database_id_t db_id;
	char *xpaths[CMGD_MAX_NUM_DATA_IN_BATCH];
	uint16_t num_xpaths;
} cmgd_get_data_req_t;

typedef struct cmgd_trxn_req_ {
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_event_t req_event;
	cmgd_client_req_id_t req_id;
	union {
		cmgd_set_cfg_req_t *set_cfg;
		cmgd_get_data_req_t *get_data;
		cmgd_commit_cfg_req_t commit_cfg;
	} req;

	bool pending_bknd_proc;
	struct cmgd_trxn_req_list_item list_linkage;
} cmgd_trxn_req_t;

DECLARE_LIST(cmgd_trxn_req_list, cmgd_trxn_req_t, list_linkage);

#define FOREACH_TRXN_REQ_IN_LIST(list, req)				\
	for ((req) = cmgd_trxn_req_list_first(list); (req);		\
	     (req) = cmgd_trxn_req_list_next((list), (req)))

#define FOREACH_TRXN_REQ_IN_LIST_SAFE(list, curr, next)			\
	for ((curr) = cmgd_trxn_req_list_first(list),			\
	     (next) = cmgd_trxn_req_list_next((list), (curr)); (curr);	\
	     (curr) = (next))

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

 	/* 
	 * List of pending set-config requests for a given
	 * transaction/session
	 */
	struct cmgd_trxn_req_list_head set_cfg_reqs;
	struct cmgd_trxn_req_list_head pending_set_cfgs;
 	/* 
	 * List of pending get-config requests for a given
	 * transaction/session
	 */
	struct cmgd_trxn_req_list_head get_cfg_reqs;
	struct cmgd_trxn_req_list_head pending_get_cfgs;
 	/* 
	 * List of pending get-data requests for a given
	 * transaction/session
	 */
	struct cmgd_trxn_req_list_head get_data_reqs;
	struct cmgd_trxn_req_list_head pending_get_datas;
 	/* 
	 * There will always be one commit-config allowed for a given
	 * transaction/session
	 */
	cmgd_trxn_req_t *commit_cfg_req;
};

DECLARE_LIST(cmgd_trxn_list, cmgd_trxn_ctxt_t, list_linkage);

#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	for ((trxn) = cmgd_trxn_list_first(&(cm)->cmgd_trxns); (trxn);	\
		(trxn) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (trxn)))

#define FOREACH_TRXN_IN_LIST_SAFE(cm, curr, next)			\
	for ((curr) = cmgd_trxn_list_first(&(cm)->cmgd_trxns),		\
		(next) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (curr));\
		(curr);	(curr) = (next))


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
		cmgd_trxn_req_list_add_tail(&trxn->set_cfg_reqs, trxn_req);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		trxn->commit_cfg_req = trxn_req;
		break;
	case CMGD_TRXN_PROC_GETCFG:
		trxn_req->req.get_data = XMALLOC(MTYPE_CMGD_TRXN_GETDATA_REQ,
						sizeof(cmgd_get_data_req_t));
		assert(trxn_req->req.get_data);
		cmgd_trxn_req_list_add_tail(&trxn->get_cfg_reqs, trxn_req);
		break;
	case CMGD_TRXN_PROC_GETDATA:
		trxn_req->req.get_data = XMALLOC(MTYPE_CMGD_TRXN_GETDATA_REQ,
						sizeof(cmgd_get_data_req_t));
		assert(trxn_req->req.get_data);
		cmgd_trxn_req_list_add_tail(&trxn->get_data_reqs, trxn_req);
		break;
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
				free((void *)(*trxn_req)->req.set_cfg->
					cfg_changes[indx].value);
		}
		cmgd_trxn_req_list_del(
			(*trxn_req)->pending_bknd_proc ?
				&(*trxn_req)->trxn->pending_set_cfgs :
				&(*trxn_req)->trxn->set_cfg_reqs, *trxn_req);
		XFREE(MTYPE_CMGD_TRXN_SETCFG_REQ, (*trxn_req)->req.set_cfg);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		break;
	case CMGD_TRXN_PROC_GETCFG:
		for (indx = 0;
			indx < (*trxn_req)->req.get_data->num_xpaths;
			indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)->req.get_data->
					xpaths[indx]);
		}
		cmgd_trxn_req_list_del(
			(*trxn_req)->pending_bknd_proc ?
				&(*trxn_req)->trxn->pending_get_cfgs :
				&(*trxn_req)->trxn->get_cfg_reqs, *trxn_req);
		XFREE(MTYPE_CMGD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	case CMGD_TRXN_PROC_GETDATA:
		for (indx = 0;
			indx < (*trxn_req)->req.get_data->num_xpaths;
			indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)->req.get_data->xpaths[indx]);
		}
		cmgd_trxn_req_list_del(
			(*trxn_req)->pending_bknd_proc ?
				&(*trxn_req)->trxn->pending_get_datas :
				&(*trxn_req)->trxn->get_data_reqs, *trxn_req);
		XFREE(MTYPE_CMGD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	default:
		break;
	}

	(*trxn_req)->pending_bknd_proc = false;
	cmgd_trxn_unlock(&(*trxn_req)->trxn);
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
	int num_processed = 0;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d SET_CONFIG requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST_SAFE(&trxn->set_cfg_reqs, trxn_req, next) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_SETCFG);
		db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_trxn_cm, trxn_req->req.set_cfg->db_id);
		if (!db_hndl) {
			cmgd_frntnd_send_set_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				"No such database!");
			error = true;
			goto cmgd_trxn_process_set_cfg_done;
		}

		nb_config = cmgd_db_get_nb_config(db_hndl);
		if (!nb_config) {
			cmgd_frntnd_send_set_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				"Unable to retrieve DB Config Tree!");
			error = true;
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
			error = true;
		}

cmgd_trxn_process_set_cfg_done:

		/*
		 * Note: The following will remove it from the list as well.
		 */
		cmgd_trxn_req_free(&trxn_req);

		num_processed++;
		if (num_processed == CMGD_TRXN_MAX_NUM_SETCFG_PROC) {
			break;
		}
	}

	if (cmgd_trxn_req_list_count(&trxn->set_cfg_reqs)) {
		CMGD_TRXN_DBG("Processed maximum number of Set-Config requests (%d/%d). Rescheduling for rest.", 
			num_processed, CMGD_TRXN_MAX_NUM_SETCFG_PROC);
		cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_SETCFG);
	}
	
	return 0;
}

static int cmgd_trxn_send_commit_cfg_reply(cmgd_trxn_ctxt_t *trxn,
	bool success, const char *error_if_any)
{
	if (!trxn->commit_cfg_req)
		return -1;

	if (cmgd_frntnd_send_commit_cfg_reply(
		trxn->session_id, (cmgd_trxn_id_t) trxn,
		trxn->commit_cfg_req->req.commit_cfg.src_db_id,
		trxn->commit_cfg_req->req.commit_cfg.dst_db_id,
		trxn->commit_cfg_req->req_id,
		trxn->commit_cfg_req->req.commit_cfg.validate_only,
		success ? CMGD_SUCCESS : CMGD_INTERNAL_ERROR, error_if_any)
		!= 0) {
		CMGD_TRXN_ERR("Failed to send COMMIT-CONFIG-REPLY for Trxn %p Sessn 0x%lx",
			trxn, trxn->session_id);
		return -1;
	}
	
	/*
	 * TODO: Need to take care of some post-commit cleanup for both
	 * successful commit and abort.
	 */
	
	cmgd_trxn_req_free(&trxn->commit_cfg_req);

	return 0;
}

static int cmgd_trxn_process_commit_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	struct nb_context nb_ctxt = { 0 };
	cmgd_db_hndl_t db_hndl;
	struct nb_config *nb_config;
	char err_buf[1024];

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing COMMIT_CONFIG for Trxn:%p Session:0x%lx",
		trxn, trxn->session_id);

	assert(trxn->commit_cfg_req);

	if (trxn->commit_cfg_req->req.commit_cfg.src_db_id !=
		CMGD_DB_CANDIDATE) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Source DB cannot be any other than CANDIDATE!");
		goto cmgd_trxn_process_commit_cfg_done;	
	}

	if (trxn->commit_cfg_req->req.commit_cfg.dst_db_id !=
		CMGD_DB_RUNNING) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Destination DB cannot be any other than RUNNING!");
		goto cmgd_trxn_process_commit_cfg_done;	
	}

	db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_trxn_cm,
			trxn->commit_cfg_req->req.commit_cfg.src_db_id);
	if (!db_hndl) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"No such database!");
		goto cmgd_trxn_process_commit_cfg_done;
	}

	nb_config = cmgd_db_get_nb_config(db_hndl);
	if (!nb_config) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Unable to retrieve Commit DB Config Tree!");
		goto cmgd_trxn_process_commit_cfg_done;
	}

	nb_ctxt.client = NB_CLIENT_CLI;
	nb_ctxt.user = (void *)trxn;
	if (nb_candidate_validate(
		&nb_ctxt, nb_config, err_buf, sizeof(err_buf)-1) != NB_OK) {
		err_buf[sizeof(err_buf)-1] = 0;
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false, err_buf);
		goto cmgd_trxn_process_commit_cfg_done;
	}

	/*
	 * For now reply right after validation. 
	 * TODO: Call this once Apply has been completed.
	 */
	(void) cmgd_trxn_send_commit_cfg_reply(trxn, true, NULL);

cmgd_trxn_process_commit_cfg_done:

	return 0;
}

static int cmgd_trxn_get_config(cmgd_trxn_ctxt_t *trxn,
	cmgd_trxn_req_t *trxn_req, cmgd_db_hndl_t db_hndl)
{
	struct nb_config *nb_config;
	struct cmgd_trxn_req_list_head *req_list;
	struct cmgd_trxn_req_list_head *pending_list;

	switch (trxn_req->req_event) {
	case CMGD_TRXN_PROC_GETCFG:
		req_list = &trxn->get_cfg_reqs;
		pending_list = NULL;
		break;
	case CMGD_TRXN_PROC_GETDATA:
		req_list = &trxn->get_data_reqs;
		pending_list = &trxn->pending_get_datas;
		break;
	default:
		assert(!"Wrong trxn request type!");
		break;
	}

	nb_config = cmgd_db_get_nb_config(db_hndl);
	if (!nb_config) {
		cmgd_frntnd_send_get_cfg_reply(
			trxn->session_id, (cmgd_trxn_id_t) trxn,
			trxn_req->req.get_data->db_id,
			trxn_req->req_id, CMGD_INTERNAL_ERROR,
			NULL, 0, "Unable to retrieve DB Config Tree!");
		return -1;
	}

	/*
	 * TODO: Read data contents from the DB and respond back directly. 
	 * No need to go to backend for getting data.
	 */
	/* For now send a blank DATA/CONFIG REPLY */
	if (CMGD_TRXN_PROC_GETCFG == trxn_req->req_event && 
	    cmgd_frntnd_send_get_cfg_reply(
		trxn->session_id, (cmgd_trxn_id_t) trxn,
		trxn_req->req.get_data->db_id,
		trxn_req->req_id, CMGD_SUCCESS, NULL, 0, NULL) != 0) {
		CMGD_TRXN_ERR("Failed to send GET-CONNFIG-REPLY for Trxn %p, Sessn: 0x%lx, Req: %ld",
			trxn, trxn->session_id, trxn_req->req_id);
	} else if (cmgd_frntnd_send_get_data_reply(
		trxn->session_id, (cmgd_trxn_id_t) trxn,
		trxn_req->req.get_data->db_id,
		trxn_req->req_id, CMGD_SUCCESS, NULL, 0, NULL) != 0) {
		CMGD_TRXN_ERR("Failed to send GET-DATA-REPLY for Trxn %p, Sessn: 0x%lx, Req: %ld",
			trxn, trxn->session_id, trxn_req->req_id);

	}

	if (pending_list) {
		/*
		 * Move the transaction to corresponding pending list.
		 */
		cmgd_trxn_req_list_del(req_list, trxn_req);
		trxn_req->pending_bknd_proc = true;
		cmgd_trxn_req_list_add_tail(pending_list, trxn_req);
	} else {
		/*
		 * Delete the trxn request. It will also remove it from request list.
		 */
		cmgd_trxn_req_free(&trxn_req);
	}

	return 0;
}

static int cmgd_trxn_process_get_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req, *next;
	cmgd_db_hndl_t db_hndl;
	int num_processed = 0;
	bool error;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d GET_CONFIG requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST_SAFE(&trxn->get_cfg_reqs, trxn_req, next) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_GETCFG);
		db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_trxn_cm, trxn_req->req.set_cfg->db_id);
		if (!db_hndl) {
			cmgd_frntnd_send_get_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.get_data->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				NULL, 0, "No such database!");
			error = true;
			goto cmgd_trxn_process_get_cfg_done;
		}

		if (cmgd_trxn_get_config(trxn, trxn_req, db_hndl) != 0) {
			CMGD_TRXN_ERR("Unable to retrieve Config from DB %d for Trxn %p, Sessn: 0x%lx, Req: %ld!", 
				trxn_req->req.get_data->db_id, trxn,
				trxn->session_id, trxn_req->req_id);
			error = true;
		}

cmgd_trxn_process_get_cfg_done:

		if (error) {
			/*
			 * Delete the trxn request.
			 * Note: The following will remove it from the list
			 * as well.
			 */
			cmgd_trxn_req_free(&trxn_req);
		} 

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */

		num_processed++;
		if (num_processed == CMGD_TRXN_MAX_NUM_GETCFG_PROC) {
			break;
		}
	}

	if (cmgd_trxn_req_list_count(&trxn->get_cfg_reqs)) {
		CMGD_TRXN_DBG("Processed maximum number of Get-Config requests (%d/%d). Rescheduling for rest.", 
			num_processed, CMGD_TRXN_MAX_NUM_GETCFG_PROC);
		cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_GETCFG);
	}
	
	return 0;
}

static int cmgd_trxn_process_get_data(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req, *next;
	cmgd_db_hndl_t db_hndl;
	int num_processed = 0;
	bool error;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d GET_DATA requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST_SAFE(&trxn->get_data_reqs, trxn_req, next) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_GETCFG);
		db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_trxn_cm, trxn_req->req.set_cfg->db_id);
		if (!db_hndl) {
			cmgd_frntnd_send_get_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.get_data->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				NULL, 0, "No such database!");
			error = true;
			goto cmgd_trxn_process_get_cfg_done;
		}

		if (cmgd_db_is_config(db_hndl) &&
			cmgd_trxn_get_config(trxn, trxn_req, db_hndl) != 0) {
			CMGD_TRXN_ERR("Unable to retrieve Config from DB %d for Trxn %p, Sessn: 0x%lx, Req: %ld!", 
				trxn_req->req.get_data->db_id, trxn,
				trxn->session_id, trxn_req->req_id);
			error = true;
			goto cmgd_trxn_process_get_cfg_done;
		} else {
			/* TODO: Trigger GET procedures for Backend */
		}

cmgd_trxn_process_get_cfg_done:

		if (error) {
			/*
			 * Delete the trxn request.
			 * Note: The following will remove it from the list
			 * as well.
			 */
			cmgd_trxn_req_free(&trxn_req);
		}

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */

		num_processed++;
		if (num_processed == CMGD_TRXN_MAX_NUM_GETCFG_PROC) {
			break;
		}
	}

	if (cmgd_trxn_req_list_count(&trxn->get_data_reqs)) {
		CMGD_TRXN_DBG("Processed maximum number of Get-Data requests (%d/%d). Rescheduling for rest.", 
			num_processed, CMGD_TRXN_MAX_NUM_GETDATA_PROC);
		cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_GETDATA);
	}
	
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
	case CMGD_TRXN_PROC_GETCFG:
		trxn->proc_comm_cfg = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_process_get_cfg, trxn,
				CMGD_TRXN_PROC_DELAY_MSEC, NULL);
		break;
	case CMGD_TRXN_PROC_GETDATA:
		trxn->proc_comm_cfg = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_process_get_data, trxn,
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
		cmgd_trxn_req_list_init(&trxn->pending_set_cfgs);
		cmgd_trxn_req_list_init(&trxn->get_cfg_reqs);
		cmgd_trxn_req_list_init(&trxn->pending_get_cfgs);
		cmgd_trxn_req_list_init(&trxn->get_data_reqs);
		cmgd_trxn_req_list_init(&trxn->pending_get_datas);
		trxn->commit_cfg_req = NULL;

		CMGD_TRXN_DBG("Added new '%s' CMGD Transaction '%p'",
			cmgd_trxn_type2str(type), trxn);

		if (type == CMGD_TRXN_TYPE_CONFIG)
			cmgd_trxn_cm->cfg_trxn = trxn;
	}

cmgd_create_trxn_done:
	return (cmgd_trxn_id_t) trxn;
}

void cmgd_destroy_trxn(cmgd_trxn_id_t *trxn_id)
{
	cmgd_trxn_ctxt_t **trxn;

	trxn = (cmgd_trxn_ctxt_t **)trxn_id;
	if (!trxn || !*trxn) {
		return;
	}

	cmgd_trxn_unlock(trxn);
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
	cmgd_trxn_req_t *trxn_req;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	if (trxn->commit_cfg_req) {
		CMGD_TRXN_ERR("A commit is already in-progress for Trxn %p, session 0x%lx. Cannot start another!",
			trxn, trxn->session_id);
		return -1;
	}

	trxn_req = cmgd_trxn_req_alloc(trxn, req_id, CMGD_TRXN_PROC_COMMITCFG);
	trxn_req->req.commit_cfg.src_db_id = src_db_id;
	trxn_req->req.commit_cfg.dst_db_id = dst_db_id;
	trxn_req->req.commit_cfg.validate_only = validate_only;

	/*
	 * For now send a positive reply back.
	 */
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_COMMITCFG);
	return 0;
}

int cmgd_trxn_send_commit_config_reply(
        cmgd_trxn_id_t trxn_id, bool success, const char *error_if_any)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	if (!trxn->commit_cfg_req) {
		CMGD_TRXN_ERR("NO commit in-progress for Trxn %p, session 0x%lx!",
			trxn, trxn->session_id);
		return -1;
	}

	return cmgd_trxn_send_commit_cfg_reply(trxn, success, error_if_any);
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
