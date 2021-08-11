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
#define CMGD_TRXN_DBG(fmt, ...)					\
	if (cmgd_debug_trxn)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_TRXN_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define CMGD_TRXN_LOCK(trxn)	cmgd_trxn_lock(trxn, __FILE__, __LINE__)
#define CMGD_TRXN_UNLOCK(trxn)	cmgd_trxn_unlock(trxn, __FILE__, __LINE__)

typedef enum cmgd_trxn_event_ {
	CMGD_TRXN_PROC_SETCFG = 1,
	CMGD_TRXN_PROC_COMMITCFG,
	CMGD_TRXN_PROC_GETCFG,
	CMGD_TRXN_PROC_GETDATA,
#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
	CMGD_TRXN_SEND_BCKND_CFG_VALIDATE,
#else /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
	CMGD_TRXN_SEND_BCKND_CFG_APPLY,
#endif /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
	CMGD_TRXN_COMMITCFG_TIMEOUT,
	CMGD_TRXN_CLEANUP
} cmgd_trxn_event_t;

PREDECL_LIST(cmgd_trxn_req_list);

typedef struct cmgd_set_cfg_req_ {
	cmgd_database_id_t db_id;
	cmgd_db_hndl_t db_hndl;
	struct nb_cfg_change cfg_changes[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
} cmgd_set_cfg_req_t;

typedef enum cmgd_commit_phase_ {
	CMGD_COMMIT_PHASE_PREPARE_CFG = 0,
	CMGD_COMMIT_PHASE_TRXN_CREATE,
	CMGD_COMMIT_PHASE_SEND_CFG,
	CMGD_COMMIT_PHASE_VALIDATE_CFG,
	CMGD_COMMIT_PHASE_APPLY_CFG,
	CMGD_COMMIT_PHASE_TRXN_DELETE,
	CMGD_COMMIT_PHASE_MAX
} cmgd_commit_phase_t;

static inline const char* cmgd_commit_phase2str(
	cmgd_commit_phase_t cmt_phase)
{
	switch (cmt_phase) {
	case CMGD_COMMIT_PHASE_PREPARE_CFG:
		return "PREP-CFG";
		break;
	case CMGD_COMMIT_PHASE_TRXN_CREATE:
		return "CREATE-TRXN";
		break;
	case CMGD_COMMIT_PHASE_SEND_CFG:
		return "SEND-CFG";
		break;
	case CMGD_COMMIT_PHASE_VALIDATE_CFG:
		return "VALIDATE-CFG";
		break;
	case CMGD_COMMIT_PHASE_APPLY_CFG:
		return "APPLY-CFG";
		break;
	case CMGD_COMMIT_PHASE_TRXN_DELETE:
		return "DELETE-TRXN";
		break;
	default:
		break;
	}

	return "Invalid/Unknown";
}

PREDECL_LIST(cmgd_trxn_batch_list);

typedef struct cmgd_trxn_bcknd_cfg_batch_ {
	cmgd_trxn_ctxt_t *trxn;
	cmgd_bcknd_client_id_t bcknd_id;
	cmgd_bcknd_client_adapter_t *bcknd_adptr;
	cmgd_bcknd_xpath_subscr_info_t xp_subscr[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	cmgd_yang_cfgdata_req_t cfg_data[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	cmgd_yang_cfgdata_req_t *cfg_datap[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	cmgd_yang_data_t data[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	cmgd_yang_data_value_t value[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	size_t num_cfg_data;
	cmgd_commit_phase_t comm_phase;
	struct cmgd_trxn_batch_list_item list_linkage;
} cmgd_trxn_bcknd_cfg_batch_t;

DECLARE_LIST(cmgd_trxn_batch_list, cmgd_trxn_bcknd_cfg_batch_t, list_linkage);

#define FOREACH_TRXN_CFG_BATCH_IN_LIST(list,  batch)		\
	frr_each_safe(cmgd_trxn_batch_list, list, batch)

typedef struct cmgd_commit_cfg_req_ {
	cmgd_database_id_t src_db_id;
	cmgd_db_hndl_t src_db_hndl;
	cmgd_database_id_t dst_db_id;
	cmgd_db_hndl_t dst_db_hndl;
	bool validate_only;
	bool abort;
	uint32_t nb_trxn_id;

	/* Track commit phases */
	cmgd_commit_phase_t curr_phase;
	cmgd_commit_phase_t next_phase;

	/*
	 * Details on all the Backend Clients associated with
	 * this commit.
	 */
	cmgd_bcknd_client_subscr_info_t subscr_info;

	/*
	 * List of backend batches for this commit to be validated
	 * and applied at the backend.
	 *
	 * FIXME: Need to re-think this design for the case set of
	 * validators for a given YANG data item is different from
	 * the set of notifiers for the same. We may need to have
	 * separate list of batches for VALIDATE and APPLY.
	 */
	struct cmgd_trxn_batch_list_head curr_batches[CMGD_BCKND_CLIENT_ID_MAX];
	struct cmgd_trxn_batch_list_head next_batches[CMGD_BCKND_CLIENT_ID_MAX];
	/*
	 * The last batch added for any backend client. This is always on
	 * 'curr_batches'
	 */
	cmgd_trxn_bcknd_cfg_batch_t *last_bcknd_cfg_batch[CMGD_BCKND_CLIENT_ID_MAX];
} cmgd_commit_cfg_req_t;

typedef struct cmgd_get_data_reply_ {
	/* Buffer space for preparing data reply */
	int num_reply;
	int last_batch;
	cmgd_yang_data_reply_t data_reply;
	cmgd_yang_data_t reply_data[CMGD_MAX_NUM_DATA_REPLY_IN_BATCH];
	cmgd_yang_data_t *reply_datap[CMGD_MAX_NUM_DATA_REPLY_IN_BATCH];
	cmgd_yang_data_value_t reply_value[CMGD_MAX_NUM_DATA_REPLY_IN_BATCH];

	// struct lyd_node *dnodes[CMGD_MAX_NUM_DBNODES_PER_BATCH];
	// char reply_xpath[CMGD_MAX_NUM_DATA_REPLY_IN_BATCH][CMGD_MAX_XPATH_LEN];
	char *reply_xpathp[CMGD_MAX_NUM_DATA_REPLY_IN_BATCH];
} cmgd_get_data_reply_t;

typedef struct cmgd_get_data_req_ {
	cmgd_database_id_t db_id;
	cmgd_db_hndl_t db_hndl;
	char *xpaths[CMGD_MAX_NUM_DATA_REQ_IN_BATCH];
	int num_xpaths;

	/*
	 * Buffer space for preparing reply.
	 * NOTE: Should only be malloc-ed on demand to reduce 
	 * memory footprint. Freed up via cmgd_trx_req_free()
	 */
	cmgd_get_data_reply_t *reply;

	int total_reply;
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

#if 0
#define FOREACH_TRXN_REQ_IN_LIST(list, req)				\
	for ((req) = cmgd_trxn_req_list_first(list); (req);		\
	     (req) = cmgd_trxn_req_list_next((list), (req)))

#define FOREACH_TRXN_REQ_IN_LIST_SAFE(list, curr, next)			\
	for ((curr) = cmgd_trxn_req_list_first(list),			\
	     (next) = cmgd_trxn_req_list_next((list), (curr)); (curr);	\
	     (curr) = (next))
#else
#define FOREACH_TRXN_REQ_IN_LIST(list, req)				\
	frr_each_safe(cmgd_trxn_req_list, list, req)
#endif

struct cmgd_trxn_ctxt_ {
        cmgd_session_id_t session_id; /* One transaction per client session */
        cmgd_trxn_type_t type;

	// struct cmgd_master *cm;

	struct thread *proc_set_cfg;
	struct thread *proc_comm_cfg;
#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
	struct thread *send_cfg_validate;
#else /* CMGD_LOCAL_VALIDATIONS_ENABLED */
	struct thread *send_cfg_apply;
#endif /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
	struct thread *comm_cfg_timeout;

        /* List of backend adapters involved in this transaction */
        struct cmgd_trxn_badptr_list_head bcknd_adptrs;

        int refcount;

        struct cmgd_trxn_list_item list_linkage;

 	/* 
	 * List of pending set-config requests for a given
	 * transaction/session. Just one list for requests 
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct cmgd_trxn_req_list_head set_cfg_reqs;
 	/* 
	 * List of pending get-config requests for a given
	 * transaction/session. Just one list for requests 
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct cmgd_trxn_req_list_head get_cfg_reqs;
 	/* 
	 * List of pending get-data requests for a given
	 * transaction/session Two lists, one for requests 
	 * not processed at all, and one for requests that 
	 * has been sent to backend for processing.
	 */
	struct cmgd_trxn_req_list_head get_data_reqs;
	struct cmgd_trxn_req_list_head pending_get_datas;
 	/* 
	 * There will always be one commit-config allowed for a given
	 * transaction/session. No need to maintain lists for it.
	 */
	cmgd_trxn_req_t *commit_cfg_req;
};

DECLARE_LIST(cmgd_trxn_list, cmgd_trxn_ctxt_t, list_linkage);

#if 0
#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	for ((trxn) = cmgd_trxn_list_first(&(cm)->cmgd_trxns); (trxn);	\
		(trxn) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (trxn)))

#define FOREACH_TRXN_IN_LIST_SAFE(cm, curr, next)			\
	for ((curr) = cmgd_trxn_list_first(&(cm)->cmgd_trxns),		\
		(next) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (curr));\
		(curr);	(curr) = (next))
#else
#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	frr_each_safe(cmgd_trxn_list, &(cm)->cmgd_trxns, (trxn))
#endif

static inline const char* cmgd_trxn_commit_phase_str(
	cmgd_trxn_ctxt_t *trxn, bool curr)
{
	if (!trxn->commit_cfg_req)
		return "None";

	return (cmgd_commit_phase2str(curr ?
		trxn->commit_cfg_req->req.commit_cfg.curr_phase :
		trxn->commit_cfg_req->req.commit_cfg.next_phase));
}

static void cmgd_trxn_lock(cmgd_trxn_ctxt_t *trxn, const char* file, int line);
static void cmgd_trxn_unlock(cmgd_trxn_ctxt_t **trxn, const char* file, int line);
static int cmgd_trxn_send_bcknd_trxn_delete(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_adapter_t *adptr);

static struct thread_master *cmgd_trxn_tm = NULL;
static struct cmgd_master *cmgd_trxn_cm = NULL;

static void cmgd_trxn_register_event(
	cmgd_trxn_ctxt_t *trxn, cmgd_trxn_event_t event);

static int cmgd_move_bcknd_commit_to_next_phase(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_adapter_t *adptr);

static cmgd_trxn_bcknd_cfg_batch_t *cmgd_trxn_cfg_batch_alloc(
	cmgd_trxn_ctxt_t *trxn, cmgd_bcknd_client_id_t id, 
	cmgd_bcknd_client_adapter_t *bcknd_adptr)
{
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	cfg_btch = XCALLOC(MTYPE_CMGD_TRXN_CFG_BATCH,
		sizeof(cmgd_trxn_bcknd_cfg_batch_t));
	assert(cfg_btch);
	cfg_btch->bcknd_id = id;

	cfg_btch->trxn = trxn;
	CMGD_TRXN_LOCK(trxn);
	assert(trxn->commit_cfg_req);
	cmgd_trxn_batch_list_add_tail(
		&trxn->commit_cfg_req->req.commit_cfg.curr_batches[id], cfg_btch);
	cfg_btch->bcknd_adptr = bcknd_adptr;
	if (bcknd_adptr)
		cmgd_bcknd_adapter_lock(bcknd_adptr);

	trxn->commit_cfg_req->req.commit_cfg.last_bcknd_cfg_batch[id] =
		cfg_btch;

	return (cfg_btch);
}

static void cmgd_trxn_adjust_last_cfg_batch(cmgd_commit_cfg_req_t *cmtcfg_req,
	cmgd_bcknd_client_id_t id)
{
	// FOREACH_TRXN_CFG_BATCH_IN_LIST(&cmtcfg_req->curr_batches[id],
	// 	cmtcfg_req->last_bcknd_cfg_batch[id]) {
	// 	/* Do nothing */
	// }
}

static void cmgd_trxn_cfg_batch_free(
		cmgd_trxn_bcknd_cfg_batch_t **cfg_btch)
{
	size_t indx;
	cmgd_commit_cfg_req_t *cmtcfg_req;

	CMGD_TRXN_DBG(" Batch: %p, Trxn: %p", *cfg_btch, (*cfg_btch)->trxn);

	assert((*cfg_btch)->trxn &&
		(*cfg_btch)->trxn->type == CMGD_TRXN_TYPE_CONFIG);

	cmtcfg_req = 
		&(*cfg_btch)->trxn->commit_cfg_req->req.commit_cfg;
	cmgd_trxn_batch_list_del(&cmtcfg_req->
		curr_batches[(*cfg_btch)->bcknd_id], *cfg_btch);
	cmgd_trxn_batch_list_del(&cmtcfg_req->
		next_batches[(*cfg_btch)->bcknd_id], *cfg_btch);

	/* Update the 'last_bcknd_cfg_batch' appropriately */
	if (*cfg_btch == cmtcfg_req->last_bcknd_cfg_batch
		[(*cfg_btch)->bcknd_id]) {
		cmgd_trxn_adjust_last_cfg_batch(
			cmtcfg_req, (*cfg_btch)->bcknd_id);
	}

	if ((*cfg_btch)->bcknd_adptr)
		cmgd_bcknd_adapter_unlock(&(*cfg_btch)->bcknd_adptr);

	for (indx = 0; indx < (*cfg_btch)->num_cfg_data; indx++) {
		if ((*cfg_btch)->data->xpath) {
			free((*cfg_btch)->data->xpath);
			(*cfg_btch)->data->xpath = NULL;
		}
	}

	CMGD_TRXN_UNLOCK(&(*cfg_btch)->trxn);

	XFREE(MTYPE_CMGD_TRXN_CFG_BATCH, *cfg_btch);
	*cfg_btch = NULL;
}

static void cmgd_trxn_cleanup_bcknd_cfg_batches(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_id_t id)
{
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;
	struct cmgd_trxn_batch_list_head *list;

	list = &trxn->commit_cfg_req->req.commit_cfg.curr_batches[id];
	FOREACH_TRXN_CFG_BATCH_IN_LIST(list, cfg_btch) {
		cmgd_trxn_cfg_batch_free(&cfg_btch);
	}
	cmgd_trxn_batch_list_fini(list);

	list = &trxn->commit_cfg_req->req.commit_cfg.next_batches[id];
	FOREACH_TRXN_CFG_BATCH_IN_LIST(list, cfg_btch) {
		cmgd_trxn_cfg_batch_free(&cfg_btch);
	}
	cmgd_trxn_batch_list_fini(list);

	trxn->commit_cfg_req->req.commit_cfg.last_bcknd_cfg_batch[id] = NULL;
}

static cmgd_trxn_req_t *cmgd_trxn_req_alloc(
	cmgd_trxn_ctxt_t *trxn, cmgd_client_req_id_t req_id,
	cmgd_trxn_event_t req_event)
{
	cmgd_trxn_req_t *trxn_req;
	cmgd_bcknd_client_id_t id;

	trxn_req = XCALLOC(MTYPE_CMGD_TRXN_REQ, sizeof(cmgd_trxn_req_t));
	assert(trxn_req);
	trxn_req->trxn = trxn;
	trxn_req->req_id = req_id;
	trxn_req->req_event = req_event;
	trxn_req->pending_bknd_proc = false;

	switch (trxn_req->req_event) {
	case CMGD_TRXN_PROC_SETCFG:
		trxn_req->req.set_cfg = XCALLOC(MTYPE_CMGD_TRXN_SETCFG_REQ,
						sizeof(cmgd_set_cfg_req_t));
		assert(trxn_req->req.set_cfg);
		cmgd_trxn_req_list_add_tail(&trxn->set_cfg_reqs, trxn_req);
		CMGD_TRXN_DBG("Added a new SETCFG Req: %p for Trxn: %p, Sessn: 0x%lx",
			trxn_req, trxn, trxn->session_id);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		trxn->commit_cfg_req = trxn_req;
		CMGD_TRXN_DBG("Added a new COMMITCFG Req: %p for Trxn: %p, Sessn: 0x%lx",
			trxn_req, trxn, trxn->session_id);

		FOREACH_CMGD_BCKND_CLIENT_ID(id) {
			cmgd_trxn_batch_list_init(
				&trxn_req->req.commit_cfg.curr_batches[id]);
			cmgd_trxn_batch_list_init(
				&trxn_req->req.commit_cfg.next_batches[id]);
		}
		break;
	case CMGD_TRXN_PROC_GETCFG:
		trxn_req->req.get_data = XCALLOC(MTYPE_CMGD_TRXN_GETDATA_REQ,
						sizeof(cmgd_get_data_req_t));
		assert(trxn_req->req.get_data);
		cmgd_trxn_req_list_add_tail(&trxn->get_cfg_reqs, trxn_req);
		CMGD_TRXN_DBG("Added a new GETCFG Req: %p for Trxn: %p, Sessn: 0x%lx",
			trxn_req, trxn, trxn->session_id);
		break;
	case CMGD_TRXN_PROC_GETDATA:
		trxn_req->req.get_data = XCALLOC(MTYPE_CMGD_TRXN_GETDATA_REQ,
						sizeof(cmgd_get_data_req_t));
		assert(trxn_req->req.get_data);
		cmgd_trxn_req_list_add_tail(&trxn->get_data_reqs, trxn_req);
		CMGD_TRXN_DBG("Added a new GETDATA Req: %p for Trxn: %p, Sessn: 0x%lx",
			trxn_req, trxn, trxn->session_id);
		break;
	default:
		break;
	}

	CMGD_TRXN_LOCK(trxn);

	return (trxn_req);
}

static void cmgd_trxn_req_free(cmgd_trxn_req_t **trxn_req)
{
	int indx;
	struct cmgd_trxn_req_list_head *req_list = NULL;
	struct cmgd_trxn_req_list_head *pending_list = NULL;
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;

	switch ((*trxn_req)->req_event) {
	case CMGD_TRXN_PROC_SETCFG:
		for (indx = 0;
			indx < (*trxn_req)->req.set_cfg->num_cfg_changes;
			indx++) {
			if ((*trxn_req)->req.set_cfg->cfg_changes[indx].value) {
				CMGD_TRXN_DBG("Freeing value for %s at %p ==> '%s'",
					(*trxn_req)->req.set_cfg->
						cfg_changes[indx].xpath,
					(*trxn_req)->req.set_cfg->
						cfg_changes[indx].value,
					(*trxn_req)->req.set_cfg->
						cfg_changes[indx].value);
				free((void *)(*trxn_req)->req.set_cfg->
					cfg_changes[indx].value);
			}
		}
		req_list = &(*trxn_req)->trxn->set_cfg_reqs;
		CMGD_TRXN_DBG("Deleting SETCFG Req: %p for Trxn: %p",
			*trxn_req, (*trxn_req)->trxn);
		XFREE(MTYPE_CMGD_TRXN_SETCFG_REQ, (*trxn_req)->req.set_cfg);
		break;
	case CMGD_TRXN_PROC_COMMITCFG:
		CMGD_TRXN_DBG("Deleting COMMITCFG Req: %p for Trxn: %p",
			*trxn_req, (*trxn_req)->trxn);
		FOREACH_CMGD_BCKND_CLIENT_ID(id) {
			/* 
			 * Send TRXN_DELETE to cleanup state for this
			 * transaction on backend
			 */
			if ((*trxn_req)->req.commit_cfg.curr_phase >=
				CMGD_COMMIT_PHASE_TRXN_CREATE && 
				(*trxn_req)->req.commit_cfg.subscr_info.
				xpath_subscr[id].subscribed) {
				adptr = cmgd_bcknd_get_adapter_by_id(id);
				if (adptr)
					cmgd_trxn_send_bcknd_trxn_delete(
						(*trxn_req)->trxn, adptr);
			}

			cmgd_trxn_cleanup_bcknd_cfg_batches(
				(*trxn_req)->trxn, id);
		}
		break;
	case CMGD_TRXN_PROC_GETCFG:
		for (indx = 0;
			indx < (*trxn_req)->req.get_data->num_xpaths;
			indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)->req.get_data->
					xpaths[indx]);
		}
		req_list = &(*trxn_req)->trxn->get_cfg_reqs;
		CMGD_TRXN_DBG("Deleting GETCFG Req: %p for Trxn: %p",
			*trxn_req, (*trxn_req)->trxn);
		if ((*trxn_req)->req.get_data->reply)
			XFREE(MTYPE_CMGD_TRXN_GETDATA_REPLY,
				(*trxn_req)->req.get_data->reply);
		XFREE(MTYPE_CMGD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	case CMGD_TRXN_PROC_GETDATA:
		for (indx = 0;
			indx < (*trxn_req)->req.get_data->num_xpaths;
			indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)->req.get_data->xpaths[indx]);
		}
		pending_list = &(*trxn_req)->trxn->pending_get_datas;
		req_list = &(*trxn_req)->trxn->get_data_reqs;
		CMGD_TRXN_DBG("Deleting GETDATA Req: %p for Trxn: %p",
			*trxn_req, (*trxn_req)->trxn);
		if ((*trxn_req)->req.get_data->reply)
			XFREE(MTYPE_CMGD_TRXN_GETDATA_REPLY,
				(*trxn_req)->req.get_data->reply);
		XFREE(MTYPE_CMGD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	default:
		break;
	}

	if ((*trxn_req)->pending_bknd_proc && pending_list) {
		cmgd_trxn_req_list_del(pending_list, *trxn_req);
		CMGD_TRXN_DBG("Removed Req: %p from pending-list (left:%d)", 
			*trxn_req, (int) cmgd_trxn_req_list_count(pending_list));
	} else if (req_list) {
		cmgd_trxn_req_list_del(req_list, *trxn_req);
		CMGD_TRXN_DBG("Removed Req: %p from request-list (left:%d)", 
			*trxn_req, (int) cmgd_trxn_req_list_count(req_list));
	}

	(*trxn_req)->pending_bknd_proc = false;
	CMGD_TRXN_UNLOCK(&(*trxn_req)->trxn);
	XFREE(MTYPE_CMGD_TRXN_REQ, (*trxn_req));
	*trxn_req = NULL;
}

static int cmgd_trxn_process_set_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req;
	cmgd_db_hndl_t db_hndl;
	struct nb_config *nb_config;
	char err_buf[1024];
	bool error;
	int num_processed = 0;
	size_t left;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d SET_CONFIG requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST(&trxn->set_cfg_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_SETCFG);
		db_hndl = trxn_req->req.set_cfg->db_hndl;
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
		nb_candidate_edit_config_changes(nb_config,
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

	left = cmgd_trxn_req_list_count(&trxn->set_cfg_reqs);
	if (left) {
		CMGD_TRXN_DBG("Processed maximum number of Set-Config requests (%d/%d/%d). Rescheduling for rest.", 
			num_processed, CMGD_TRXN_MAX_NUM_SETCFG_PROC, (int)left);
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

	if (success) {
		/* Stop the commit-timeout timer */
		THREAD_OFF(trxn->comm_cfg_timeout);

		/*
		 * Successful commit: Merge Src DB into Dst DB if and only if
		 * this was not a validate-only or abort request.
		 */
		if (!trxn->commit_cfg_req->req.commit_cfg.validate_only && 
			 !trxn->commit_cfg_req->req.commit_cfg.abort)
			cmgd_db_merge_dbs(
				trxn->commit_cfg_req->req.commit_cfg.src_db_hndl,
				trxn->commit_cfg_req->req.commit_cfg.dst_db_hndl);

		/*
		 * Restore Src DB back to Dest DB only through a commit abort
		 * request.
		 */
		if (trxn->commit_cfg_req->req.commit_cfg.abort)
			cmgd_db_copy_dbs(
				trxn->commit_cfg_req->req.commit_cfg.dst_db_hndl,
				trxn->commit_cfg_req->req.commit_cfg.src_db_hndl);
	} else {
#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
		THREAD_OFF(trxn->send_cfg_validate);
#else /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
		THREAD_OFF(trxn->send_cfg_apply);
#endif /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
	}
	
	cmgd_trxn_req_free(&trxn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 */

	return 0;
}

static void cmgd_move_trxn_cfg_batch_to_next(cmgd_commit_cfg_req_t *cmtcfg_req,
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch, 
	struct cmgd_trxn_batch_list_head *src_list,
	struct cmgd_trxn_batch_list_head *dst_list, bool update_commit_phase,
	cmgd_commit_phase_t to_phase)
{
	cmgd_trxn_batch_list_del(src_list, cfg_btch);

	if (update_commit_phase) {
		CMGD_TRXN_DBG("Move Trxn-Id %p Batch-Id %p from '%s' --> '%s'",
			cfg_btch->trxn, cfg_btch,
			cmgd_commit_phase2str(cfg_btch->comm_phase),
			cmgd_trxn_commit_phase_str(cfg_btch->trxn, false));
		// assert(cfg_btch->comm_phase == cmtcfg_req->curr_phase);
		cfg_btch->comm_phase = to_phase;
	}

	cmgd_trxn_batch_list_add_tail(dst_list, cfg_btch);
}

static void cmgd_move_trxn_cfg_batches(cmgd_trxn_ctxt_t *trxn,
	cmgd_commit_cfg_req_t *cmtcfg_req, 
	struct cmgd_trxn_batch_list_head *src_list,
	struct cmgd_trxn_batch_list_head *dst_list, bool update_commit_phase,
	cmgd_commit_phase_t to_phase)
{
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	FOREACH_TRXN_CFG_BATCH_IN_LIST(src_list, cfg_btch) {
		cmgd_move_trxn_cfg_batch_to_next(cmtcfg_req, cfg_btch,
			src_list, dst_list, update_commit_phase, to_phase);
	}
}

static int cmgd_try_move_commit_to_next_phase(cmgd_trxn_ctxt_t *trxn,
	cmgd_commit_cfg_req_t *cmtcfg_req)
{
	struct cmgd_trxn_batch_list_head *curr_list, *next_list;
	cmgd_bcknd_client_id_t id;

	CMGD_TRXN_DBG("Trxn-Id %p, Phase(current:'%s' next:'%s')", trxn,
			cmgd_trxn_commit_phase_str(trxn, true),
			cmgd_trxn_commit_phase_str(trxn, false));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].subscribed &&
		    	cmgd_trxn_batch_list_count(
				&cmtcfg_req->curr_batches[id])) {
			/*
			 * There's atleast once client who hasn't moved to
			 * next phase.
			 *
			 * TODO: Need to re-think this design for the case
			 * set of validators for a given YANG data item is
			 * different from the set of notifiers for the same.
			 */
			return -1;
		}
	}

	CMGD_TRXN_DBG("Move entire Trxn-Id %p from '%s' to '%s'",
		trxn, cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));

	/*
	 * If we are here, it means all the clients has moved to next phase.
	 * So we can move the whole commit to next phase.
	 */
	cmtcfg_req->curr_phase = cmtcfg_req->next_phase;
	cmtcfg_req->next_phase++;
	CMGD_TRXN_DBG("Move back all config batches for Trxn %p from next to current branch",
		trxn);
	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		curr_list = &cmtcfg_req->curr_batches[id];
		next_list = &cmtcfg_req->next_batches[id];
		cmgd_move_trxn_cfg_batches(trxn, cmtcfg_req, next_list, curr_list,
			false, 0);
	}

	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_COMMITCFG);

	return 0;
}

static int cmgd_move_bcknd_commit_to_next_phase(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_commit_cfg_req_t *cmtcfg_req;
	struct cmgd_trxn_batch_list_head *curr_list, *next_list;

	if (trxn->type != CMGD_TRXN_TYPE_CONFIG || !trxn->commit_cfg_req)
		return -1;

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;

	CMGD_TRXN_DBG("Move Trxn-Id %p for '%s' Phase(current: '%s' next:'%s')",
		trxn, adptr->name,
		cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));

	CMGD_TRXN_DBG("Move all config batches for '%s' from current to next list",
		adptr->name);
	curr_list = &cmtcfg_req->curr_batches[adptr->id];
	next_list = &cmtcfg_req->next_batches[adptr->id];
	cmgd_move_trxn_cfg_batches(trxn, cmtcfg_req, curr_list, next_list,
		true, cmtcfg_req->next_phase);

	CMGD_TRXN_DBG("Trxn-Id %p, Phase(current:'%s' next:'%s')", trxn,
		cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	cmgd_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

static int cmgd_trxn_create_config_batches(cmgd_trxn_req_t *trxn_req,
		struct nb_config_cbs *changes)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;
	cmgd_bcknd_client_subscr_info_t subscr_info;
	char *xpath = NULL, *value = NULL;
	char err_buf[1024];
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;
	cmgd_commit_cfg_req_t *cmtcfg_req;
	bool found_validator;
	int num_chgs = 0;

	cmtcfg_req = &trxn_req->req.commit_cfg;

	RB_FOREACH_SAFE(cb, nb_config_cbs, changes, nxt) {
		chg = (struct nb_config_change *)cb;

		// Could have directly pointed to xpath in nb_node. 
		// But dont want to mess with it now.
		// xpath = chg->cb.nb_node->xpath;
		xpath = lyd_path(chg->cb.dnode, LYD_PATH_STD, NULL, 0);
		if (!xpath) {
			(void) cmgd_trxn_send_commit_cfg_reply(trxn_req->trxn, false,
					"Internal error! Could not get Xpath from Db node!");
			goto cmgd_trxn_create_config_batches_failed;
		}

		value = (char *) lyd_get_value(chg->cb.dnode);
		if (!value) {
			// free(xpath);
			// continue;
			value = (char *)CMGD_BCKND_CONTAINER_NODE_VAL;
		}

		CMGD_TRXN_DBG("XPATH: %s, Value: '%s'", xpath, value ? value : "NIL");

		if (cmgd_bcknd_get_subscr_info_for_xpath(
				xpath, &subscr_info) != 0) {
			snprintf(err_buf, sizeof(err_buf),
				"No backend module found for XPATH: '%s", xpath);
			(void) cmgd_trxn_send_commit_cfg_reply(
					trxn_req->trxn, false, err_buf);
			goto cmgd_trxn_create_config_batches_failed;
		}

		found_validator = false;
		FOREACH_CMGD_BCKND_CLIENT_ID(id) {
			if (!subscr_info.xpath_subscr[id].validate_config &&
				!subscr_info.xpath_subscr[id].notify_config)
				continue;

			adptr = cmgd_bcknd_get_adapter_by_id(id);
			if (!adptr)
				continue;

			cfg_btch = cmtcfg_req->last_bcknd_cfg_batch[id];
			if (!cfg_btch ||
				cfg_btch->num_cfg_data ==
					CMGD_MAX_CFG_CHANGES_IN_BATCH) {
				/* Allocate a new config batch */
				cfg_btch = cmgd_trxn_cfg_batch_alloc(
						trxn_req->trxn, id, adptr);
			}

			memcpy(&cfg_btch->xp_subscr[cfg_btch->num_cfg_data],
				&subscr_info.xpath_subscr[id],
				sizeof(cfg_btch->xp_subscr[0]));

			cmgd_yang_cfg_data_req_init(
				&cfg_btch->cfg_data[cfg_btch->num_cfg_data]);
			cfg_btch->cfg_datap[cfg_btch->num_cfg_data] = 
				&cfg_btch->cfg_data[cfg_btch->num_cfg_data];

			switch(chg->cb.operation) {
			case NB_OP_DESTROY:
				cfg_btch->cfg_data[cfg_btch->num_cfg_data].req_type =
					CMGD__CFG_DATA_REQ_TYPE__DELETE_DATA;
				break;
			default:
				cfg_btch->cfg_data[cfg_btch->num_cfg_data].req_type =
					CMGD__CFG_DATA_REQ_TYPE__SET_DATA;
				break;
			}

			cmgd_yang_data_init(
				&cfg_btch->data[cfg_btch->num_cfg_data]);
			cfg_btch->cfg_data[cfg_btch->num_cfg_data].data = 
				&cfg_btch->data[cfg_btch->num_cfg_data];
			cfg_btch->data[cfg_btch->num_cfg_data].xpath = xpath;
			xpath = NULL;

			cmgd__yang_data_value__init(
				&cfg_btch->value[cfg_btch->num_cfg_data]);
			cfg_btch->data[cfg_btch->num_cfg_data].value = 
				&cfg_btch->value[cfg_btch->num_cfg_data];
			cfg_btch->value[cfg_btch->num_cfg_data].value_case =
					CMGD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
			cfg_btch->value[cfg_btch->num_cfg_data].
				encoded_str_val = value;
			value = NULL;

			if (subscr_info.xpath_subscr[id].validate_config)
				found_validator = true;

			cmtcfg_req->subscr_info.xpath_subscr[id].subscribed |= 
				subscr_info.xpath_subscr[id].subscribed;
			CMGD_TRXN_DBG(" -- %s, {V:%d, N:%d}, Batch: %p, Item:%d",
				adptr->name,
				subscr_info.xpath_subscr[id].validate_config,
				subscr_info.xpath_subscr[id].notify_config,
				cfg_btch, (int) cfg_btch->num_cfg_data);

			cfg_btch->num_cfg_data++;
			num_chgs++;
		}

		if (!found_validator) {
			snprintf(err_buf, sizeof(err_buf),
				"No validator module found for XPATH: '%s", xpath);
			(void) cmgd_trxn_send_commit_cfg_reply(
					trxn_req->trxn, false, err_buf);
			goto cmgd_trxn_create_config_batches_failed;
		}
	}

	if (!num_chgs) {
		(void) cmgd_trxn_send_commit_cfg_reply(
				trxn_req->trxn, false, "No changes found to commit!");
		goto cmgd_trxn_create_config_batches_failed;
	}

	cmtcfg_req->next_phase = CMGD_COMMIT_PHASE_TRXN_CREATE;
	return 0;

cmgd_trxn_create_config_batches_failed:

	if (xpath)
		free (xpath);
	// if (value)
	// 	free (value);

	return -1;
}

static int cmgd_trxn_prepare_config(cmgd_trxn_ctxt_t *trxn)
{
	struct nb_context nb_ctxt = { 0 };
	struct nb_config *nb_config;
	char err_buf[1024] = { 0 };
	struct nb_config_cbs changes = { 0 };
	int ret;

	ret = 0;
	if (trxn->commit_cfg_req->req.commit_cfg.src_db_id !=
		CMGD_DB_CANDIDATE) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Source DB cannot be any other than CANDIDATE!");
		ret = -1;
		goto cmgd_trxn_prepare_config_done;	
	}

	if (trxn->commit_cfg_req->req.commit_cfg.dst_db_id !=
		CMGD_DB_RUNNING) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Destination DB cannot be any other than RUNNING!");
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	if (!trxn->commit_cfg_req->req.commit_cfg.src_db_hndl) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"No such source database!");
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	if (!trxn->commit_cfg_req->req.commit_cfg.dst_db_hndl) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"No such destination database!");
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.abort) {
		/*
		 * This is a commit abort request. Return back success. 
		 * That should trigger a restore of Candidate database to 
		 * Running.
		 */
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, true, NULL);
		goto cmgd_trxn_prepare_config_done;
	}

	nb_config = cmgd_db_get_nb_config(
			trxn->commit_cfg_req->req.commit_cfg.src_db_hndl);
	if (!nb_config) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Unable to retrieve Commit DB Config Tree!");
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	/*
	 * Validate YANG contents of the srource DB and get the diff 
	 * between source and destination DB contents.
	 */
	nb_ctxt.client = NB_CLIENT_CMGD_SERVER;
	nb_ctxt.user = (void *)trxn;
	ret = nb_candidate_diff_and_validate_yang(&nb_ctxt, nb_config,
		&changes, err_buf, sizeof(err_buf)-1);
	if (ret != NB_OK) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false, err_buf);
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

#ifdef CMGD_LOCAL_VALIDATIONS_ENABLED
	/*
	 * Perform application level validations locally on the CMGD 
	 * process by calling application specific validation routines
	 * loaded onto CMGD process using libraries.
	 */
	ret = nb_candidate_validate_code(&nb_ctxt, nb_config,
		&changes, err_buf, sizeof(err_buf)-1);
	if (ret != NB_OK) {
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, false, err_buf);
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.validate_only) {
		/*
		 * This was a validate-only COMMIT request return success.
		 */
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, true, NULL);
		goto cmgd_trxn_prepare_config_done;
	}
#endif /* ifdef CMGD_LOCAL_VALIDATIONS_ENABLED */

	/*
	 * Iterate over the diffs and create ordered batches of config 
	 * commands to be validated.
	 */
	ret = cmgd_trxn_create_config_batches(trxn->commit_cfg_req, &changes);
	if (ret != 0) {
		ret = -1;
		goto cmgd_trxn_prepare_config_done;
	}

	/* Move to the Transaction Create Phase */
	trxn->commit_cfg_req->req.commit_cfg.curr_phase = 
		CMGD_COMMIT_PHASE_TRXN_CREATE;
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_COMMITCFG);

	/*
	 * Start the COMMIT Timeout Timer to abort Trxn if things get stuck at 
	 * backend.
	 */
	cmgd_trxn_register_event(trxn, CMGD_TRXN_COMMITCFG_TIMEOUT);

cmgd_trxn_prepare_config_done:

	nb_config_diff_del_changes(&changes);

	return ret;
}

static int cmgd_trxn_send_bcknd_trxn_create(cmgd_trxn_ctxt_t *trxn)
{
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;
	cmgd_commit_cfg_req_t *cmtcfg_req;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].subscribed) {
			adptr = cmgd_bcknd_get_adapter_by_id(id);
			if (cmgd_bcknd_create_trxn(adptr,
				(cmgd_trxn_id_t) trxn) != 0) {
				(void) cmgd_trxn_send_commit_cfg_reply(
					trxn, false,
					"Could not send TRXN_CREATE to backend adapter");
				return -1;
			}

			FOREACH_TRXN_CFG_BATCH_IN_LIST(
				&trxn->commit_cfg_req->req.commit_cfg.
				curr_batches[id], cfg_btch) {
				cfg_btch->comm_phase = CMGD_COMMIT_PHASE_TRXN_CREATE;
			}
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		CMGD_COMMIT_PHASE_SEND_CFG;

	/*
	 * Dont move the commit to next phase yet. Wait for the TRXN_REPLY to
	 * come back.
	 */

	CMGD_TRXN_DBG("Trxn:%p Session:0x%lx, Phase(Current:'%s', Next: '%s')",
		trxn, trxn->session_id, cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));

	return 0;
}

static int cmgd_trxn_send_bcknd_cfg_data(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_commit_cfg_req_t *cmtcfg_req;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;
	cmgd_bcknd_cfgreq_t cfg_req = { 0 };

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	assert(cmtcfg_req->subscr_info.xpath_subscr[adptr->id].subscribed);

	FOREACH_TRXN_CFG_BATCH_IN_LIST(&cmtcfg_req->curr_batches[adptr->id],
		cfg_btch) {
		assert(cmtcfg_req->next_phase == CMGD_COMMIT_PHASE_SEND_CFG);

		cfg_req.cfgdata_reqs = cfg_btch->cfg_datap;
		cfg_req.num_reqs = cfg_btch->num_cfg_data;
		if (cmgd_bcknd_send_cfg_data_create_req(adptr,
			(cmgd_trxn_id_t) trxn, (cmgd_trxn_batch_id_t) cfg_btch,
			&cfg_req) != 0) {
			(void) cmgd_trxn_send_commit_cfg_reply(
				trxn, false,
				"Internal Error! Could not send config data to backend!");
			CMGD_TRXN_ERR("Could not send CFGDATA_CREATE for Trxn %p Batch %p to client '%s",
				trxn, cfg_btch, adptr->name);
			return -1;
		}

		cmgd_move_trxn_cfg_batch_to_next(cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			CMGD_COMMIT_PHASE_SEND_CFG);
	}

	/*
	 * This could ne the last Backend Client to send CFGDATA_CREATE_REQ to.
	 * Try moving the commit to next phase.
	 */
	cmgd_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

static int cmgd_trxn_send_bcknd_trxn_delete(cmgd_trxn_ctxt_t *trxn,
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_commit_cfg_req_t *cmtcfg_req;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	if (cmtcfg_req->subscr_info.xpath_subscr[adptr->id].subscribed) {
		adptr = cmgd_bcknd_get_adapter_by_id(adptr->id);
		(void) cmgd_bcknd_destroy_trxn(adptr,
				(cmgd_trxn_id_t) trxn);

		FOREACH_TRXN_CFG_BATCH_IN_LIST(
			&trxn->commit_cfg_req->req.commit_cfg.
			curr_batches[adptr->id], cfg_btch) {
			cfg_btch->comm_phase = CMGD_COMMIT_PHASE_TRXN_DELETE;
		}
	}

	return 0;
}

static int cmgd_trxn_cfg_commit_timedout(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	CMGD_TRXN_ERR("Backend operations for Config Trxn %p has timedout! Aborting commit!!",
		trxn);

	/*
	 * Send a COMMIT_CONFIG_REPLY with failure. 
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */
	cmgd_trxn_send_commit_cfg_reply(trxn, false,
		"Operation on the backend timed-out. Aborting commit!");
	
	return 0;
}

/*
 * Send CFG_APPLY_REQs to all the backend client.
 *
 * NOTE: This is always dispatched when all CFGDATA_CREATE_REQs
 * for all backend clients has been generated. Please see
 * cmgd_trxn_register_event() and cmgd_trxn_process_commit_cfg()
 * for details.
 */
static int cmgd_trxn_send_bcknd_cfg_apply(cmgd_trxn_ctxt_t *trxn)
{
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;
	cmgd_commit_cfg_req_t *cmtcfg_req;
	cmgd_trxn_batch_id_t *batch_ids;
	size_t indx, num_batches;
	struct cmgd_trxn_batch_list_head *btch_list;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	if (cmtcfg_req->validate_only) {
		/*
		 * If this was a validate-only COMMIT request return success.
		 */
		(void) cmgd_trxn_send_commit_cfg_reply(trxn, true, NULL);
		return 0;
	}

	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].notify_config) {
			adptr = cmgd_bcknd_get_adapter_by_id(id);
			if (!adptr) 
				return -1;

			btch_list = &cmtcfg_req->curr_batches[id];
			num_batches = cmgd_trxn_batch_list_count(btch_list);
			batch_ids = (cmgd_trxn_batch_id_t *)
					calloc(num_batches,
						sizeof(cmgd_trxn_batch_id_t));

			indx = 0;
			FOREACH_TRXN_CFG_BATCH_IN_LIST(btch_list, cfg_btch) {
				batch_ids[indx] = (cmgd_trxn_batch_id_t) cfg_btch;
				indx++;
				assert(indx <= num_batches);
			}
		
			if (cmgd_bcknd_send_cfg_apply_req(adptr,
				(cmgd_trxn_id_t) trxn, batch_ids, indx) != 0) {
				(void) cmgd_trxn_send_commit_cfg_reply(
					trxn, false,
					"Could not send TRXN_CREATE to backend adapter");
				return -1;
			}

			FOREACH_TRXN_CFG_BATCH_IN_LIST(btch_list, cfg_btch) {
				cfg_btch->comm_phase = CMGD_COMMIT_PHASE_APPLY_CFG;
			}

			free(batch_ids);
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		CMGD_COMMIT_PHASE_TRXN_DELETE;

	/*
	 * Dont move the commit to next phase yet. Wait for all VALIDATE_REPLIES to
	 * come back.
	 */

	return 0;
}

#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
/*
 * Send CFG_VALIDATE_REQs to all the backend client.
 *
 * NOTE:This is always dispatched through a timer expiry which is
 * started when all CFGDATA_CREATE_REQs for all backend clients
 * has been generated. Please see cmgd_trxn_register_event() and
 * cmgd_trxn_process_commit_cfg() for details.
 */
static int cmgd_trxn_send_bcknd_cfg_validate(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;
	cmgd_commit_cfg_req_t *cmtcfg_req;
	cmgd_trxn_batch_id_t *batch_ids;
	size_t indx, num_batches;
	struct cmgd_trxn_batch_list_head *btch_list;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	assert(trxn->type == CMGD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].validate_config) {
			adptr = cmgd_bcknd_get_adapter_by_id(id);
			if (!adptr) 
				return -1;

			btch_list = &cmtcfg_req->curr_batches[id];
			num_batches = cmgd_trxn_batch_list_count(btch_list);
			batch_ids = (cmgd_trxn_batch_id_t *)
					calloc(num_batches,
						sizeof(cmgd_trxn_batch_id_t));

			indx = 0;
			FOREACH_TRXN_CFG_BATCH_IN_LIST(btch_list, cfg_btch) {
				batch_ids[indx] = (cmgd_trxn_batch_id_t) cfg_btch;
				indx++;
				assert(indx <= num_batches);
			}
		
			if (cmgd_bcknd_send_cfg_validate_req(adptr,
				(cmgd_trxn_id_t) trxn, batch_ids, indx) != 0) {
				(void) cmgd_trxn_send_commit_cfg_reply(
					trxn, false,
					"Could not send TRXN_CREATE to backend adapter");
				return -1;
			}

			FOREACH_TRXN_CFG_BATCH_IN_LIST(btch_list, cfg_btch) {
				cfg_btch->comm_phase = CMGD_COMMIT_PHASE_VALIDATE_CFG;
			}

			free(batch_ids);
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		CMGD_COMMIT_PHASE_APPLY_CFG;

	/*
	 * Dont move the commit to next phase yet. Wait for all VALIDATE_REPLIES to
	 * come back.
	 */

	return 0;
}
#else /* ifdef CMGD_LOCAL_VALIDATIONS_ENABLED */
/*
 * Send CFG_APPLY_REQs to all the backend client.
 *
 * NOTE:This is always dispatched through a timer expiry which is
 * started when all CFGDATA_CREATE_REQs for all backend clients
 * has been generated. Please see cmgd_trxn_register_event() and
 * cmgd_trxn_process_commit_cfg() for details.
 */
static int cmgd_trxn_send_bcknd_config_apply(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	if (cmgd_trxn_send_bcknd_cfg_apply(trxn) != 0)
		return -1;

	return 0;
}
#endif /* iddef CMGD_LOCAL_VALIDATIONS_ENABLED */

static int cmgd_trxn_process_commit_cfg(struct thread *thread)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_commit_cfg_req_t *cmtcfg_req;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing COMMIT_CONFIG for Trxn:%p Session:0x%lx, Phase(Current:'%s', Next: '%s')",
		trxn, trxn->session_id, cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));

	assert(trxn->commit_cfg_req);
	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	switch (cmtcfg_req->curr_phase) {
	case CMGD_COMMIT_PHASE_PREPARE_CFG:
		cmgd_trxn_prepare_config(trxn);
		break;
	case CMGD_COMMIT_PHASE_TRXN_CREATE:
		/*
		 * Send TRXN_CREATE_REQ to all Backend now.
		 */
		cmgd_trxn_send_bcknd_trxn_create(trxn);
		break;
	case CMGD_COMMIT_PHASE_SEND_CFG:
		/*
		 * All CFGDATA_CREATE_REQ should have been sent to Backend by now.
		 * Start the wait timer for receiving any CFGDATA_CREATE_FAIL.
		 * On expiry of the wait timer we will start sending CFG_VALIDATE_REQ
		 * to all backend clients.
		 */
		assert(cmtcfg_req->next_phase == CMGD_COMMIT_PHASE_VALIDATE_CFG);
		CMGD_TRXN_DBG("Trxn:%p Session:0x%lx, trigger sending CFG_VALIDATE_REQ to all backend clients",
			trxn, trxn->session_id);
#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
		cmgd_trxn_register_event(trxn, CMGD_TRXN_SEND_BCKND_CFG_VALIDATE);
#else  /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
		cmgd_trxn_register_event(trxn, CMGD_TRXN_SEND_BCKND_CFG_APPLY);
#endif /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
		break;
	case CMGD_COMMIT_PHASE_VALIDATE_CFG:
		/*
		 * Nothing to do. Currently we must be waiting for successful
		 * CFG_VALIDATE_REPLY from all backend clients.
		 */
		break;
	case CMGD_COMMIT_PHASE_APPLY_CFG:
		/*
		 * We should have received successful CFG_VALIDATE_REPLY from all
		 * concerned Backend Clients by now. Send out the CFG_APPLY_REQs
		 * now.
		 */
		cmgd_trxn_send_bcknd_cfg_apply(trxn);
		break;
	case CMGD_COMMIT_PHASE_TRXN_DELETE:
		/*
		 * We would have sent TRXN_DELETE_REQ to all backend by now.
		 * Send a successful CONFIG_COMMIT_REPLY back to front-end.
		 * NOTE: This should also trigger DB merge/unlock and Trxn cleanup. 
		 * Please see cmgd_frntnd_send_commit_cfg_reply() for more 
		 * details.
		 */
		cmgd_trxn_send_commit_cfg_reply(trxn, true, NULL);
		break;
	default:
		break;
	}

	CMGD_TRXN_DBG("Trxn:%p Session:0x%lx, Phase updated to (Current:'%s', Next: '%s')",
		trxn, trxn->session_id, cmgd_trxn_commit_phase_str(trxn, true),
		cmgd_trxn_commit_phase_str(trxn, false));
	return 0;
}

static void cmgd_init_get_data_reply(
	cmgd_get_data_reply_t *get_reply)
{
	size_t indx;

	for (indx = 0; indx < array_size(get_reply->reply_data); indx++) {
		get_reply->reply_datap[indx] = &get_reply->reply_data[indx];
	}
	// for (indx = 0; indx < array_size(get_reply->reply_xpath); indx++) {
	// 	get_reply->reply_xpathp[indx] = &get_reply->reply_xpath[indx][0];
	// }
}

static void cmgd_reset_get_data_reply(
	cmgd_get_data_reply_t *get_reply)
{
	size_t indx;

	get_reply->num_reply = 0;
	memset(&get_reply->data_reply, 0,
		sizeof(get_reply->data_reply));
	memset(&get_reply->reply_data, 0,
		sizeof(get_reply->reply_data));
	memset(&get_reply->reply_datap, 0,
		sizeof(get_reply->reply_datap));
	// memset(get_reply->reply_xpath, 0,
	// 	sizeof(get_reply->reply_xpath));
	// memset(get_reply->reply_xpathp, 0,
	// 	sizeof(get_reply->reply_xpathp));
	for (indx = 0; indx < array_size(get_reply->reply_xpathp); indx++) {
		if (get_reply->reply_xpathp[indx]) {
			free(get_reply->reply_xpathp[indx]);
			get_reply->reply_xpathp[indx] = 0;
		}
	}
	memset(&get_reply->reply_value, 0,
		sizeof(get_reply->reply_value));
	
	cmgd_init_get_data_reply(get_reply);
}

static void cmgd_reset_get_data_reply_buf(
	cmgd_get_data_req_t *get_data)
{
	if (get_data->reply)
		cmgd_reset_get_data_reply(get_data->reply);
}

static void cmgd_trxn_send_getcfg_reply_data(cmgd_trxn_req_t *trxn_req,
	cmgd_get_data_req_t *get_req)
{
	cmgd_get_data_reply_t *get_reply;
	cmgd_yang_data_reply_t *data_reply;

	get_reply = get_req->reply;
	if (!get_reply)
		return;

	data_reply = &get_reply->data_reply;
	cmgd_yang_data_reply_init(data_reply);
	data_reply->n_data = get_reply->num_reply;
	data_reply->data = get_reply->reply_datap;
	data_reply->next_indx = (!get_reply->last_batch ?
		get_req->total_reply : -1);

	CMGD_TRXN_DBG("Sending %d Get-Config/Data replies (next-idx:%lld)",
		(int) data_reply->n_data, data_reply->next_indx);

	if (CMGD_TRXN_PROC_GETCFG ==
		trxn_req->req_event &&
		cmgd_frntnd_send_get_cfg_reply(
			trxn_req->trxn->session_id,
			(cmgd_trxn_id_t) trxn_req->trxn,
			get_req->db_id, trxn_req->req_id,
			CMGD_SUCCESS, data_reply, NULL) != 0) {
		CMGD_TRXN_ERR("Failed to send GET-CONFIG-REPLY for Trxn %p, Sessn: 0x%lx, Req: %ld",
			trxn_req->trxn, trxn_req->trxn->session_id,
			trxn_req->req_id);
	} else if (cmgd_frntnd_send_get_data_reply(
			trxn_req->trxn->session_id,
			(cmgd_trxn_id_t) trxn_req->trxn,
			get_req->db_id, trxn_req->req_id,
			CMGD_SUCCESS, data_reply, NULL) != 0) {
		CMGD_TRXN_ERR("Failed to send GET-DATA-REPLY for Trxn %p, Sessn: 0x%lx, Req: %ld",
			trxn_req->trxn, trxn_req->trxn->session_id,
			trxn_req->req_id);
	}

	/*
	 * Reset reply buffer for next reply.
	 */
	cmgd_reset_get_data_reply_buf(get_req);
}

static void cmgd_trxn_iter_and_send_get_cfg_reply(cmgd_db_hndl_t db_hndl, 
        char *xpath, struct lyd_node *node, struct nb_node *nb_node,
	void *ctxt)
{
	cmgd_trxn_req_t *trxn_req;
	cmgd_get_data_req_t *get_req;
	cmgd_get_data_reply_t *get_reply;
	cmgd_yang_data_t *data;
	cmgd_yang_data_value_t *data_value;

	trxn_req = (cmgd_trxn_req_t *)ctxt;
	if (!trxn_req)
		return;

	if (!(node->schema->nodetype & LYD_NODE_TERM))
		return;

	assert(trxn_req->req_event == CMGD_TRXN_PROC_GETCFG ||
		trxn_req->req_event == CMGD_TRXN_PROC_GETDATA);

	get_req = trxn_req->req.get_data;
	assert(get_req);
	get_reply = get_req->reply;
	data = &get_reply->reply_data[get_reply->num_reply];
	data_value = &get_reply->reply_value[get_reply->num_reply];

	cmgd_yang_data_init(data);
	data->xpath = xpath;
	cmgd_yang_data_value_init(data_value);
	data_value->value_case = 
		CMGD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
	data_value->encoded_str_val = (char *)lyd_get_value(node);
	data->value = data_value;

	get_reply->num_reply++;
	get_req->total_reply++;
	CMGD_TRXN_DBG(" [%d] XPATH: '%s', Value: '%s'",
		get_req->total_reply, data->xpath, data_value->encoded_str_val);

	if (get_reply->num_reply == CMGD_MAX_NUM_DATA_REPLY_IN_BATCH) {
		cmgd_trxn_send_getcfg_reply_data(trxn_req, get_req);
	}
}

static int cmgd_trxn_get_config(cmgd_trxn_ctxt_t *trxn,
	cmgd_trxn_req_t *trxn_req, cmgd_db_hndl_t db_hndl)
{
	struct cmgd_trxn_req_list_head *req_list = NULL;
	struct cmgd_trxn_req_list_head *pending_list = NULL;
	int indx; 
	cmgd_get_data_req_t *get_data;
	cmgd_get_data_reply_t *get_reply;

	switch (trxn_req->req_event) {
	case CMGD_TRXN_PROC_GETCFG:
		req_list = &trxn->get_cfg_reqs;
		break;
	case CMGD_TRXN_PROC_GETDATA:
		req_list = &trxn->get_data_reqs;
		// pending_list = &trxn->pending_get_datas;
		break;
	default:
		assert(!"Wrong trxn request type!");
		break;
	}

	get_data = trxn_req->req.get_data;

	if (!get_data->reply) {
		get_data->reply = 
			XCALLOC(MTYPE_CMGD_TRXN_GETDATA_REPLY,
				sizeof(cmgd_get_data_reply_t));
		if (!get_data->reply) {
			cmgd_frntnd_send_get_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				get_data->db_id, trxn_req->req_id,
				CMGD_INTERNAL_ERROR, NULL,
				"Internal error: Unable to allocate reply buffers!");
			goto cmgd_trxn_get_config_failed;
		}
	}

	/*
	 * Read data contents from the DB and respond back directly. 
	 * No need to go to backend for getting data.
	 */
	get_reply = get_data->reply;
	for (indx = 0; indx < get_data->num_xpaths; indx++) {
		CMGD_TRXN_DBG("Trying to get all data under '%s'",
			get_data->xpaths[indx]);
		cmgd_init_get_data_reply(get_reply);
		cmgd_db_iter_data(get_data->db_hndl, get_data->xpaths[indx],
			cmgd_trxn_iter_and_send_get_cfg_reply,
			(void *)trxn_req, true);

		CMGD_TRXN_DBG("Got %d remaining data-replies for xpath '%s'",
			get_reply->num_reply, get_data->xpaths[indx]);
		get_reply->last_batch = true;
		cmgd_trxn_send_getcfg_reply_data(trxn_req, get_data);
	}

cmgd_trxn_get_config_failed:

	if (pending_list) {
		/*
		 * Move the transaction to corresponding pending list.
		 */
		cmgd_trxn_req_list_del(req_list, trxn_req);
		trxn_req->pending_bknd_proc = true;
		cmgd_trxn_req_list_add_tail(pending_list, trxn_req);
		CMGD_TRXN_DBG("Moved Req: %p for Trxn: %p from Req-List to Pending-List",
			trxn_req, trxn_req->trxn);
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
	cmgd_trxn_req_t *trxn_req;
	cmgd_db_hndl_t db_hndl;
	int num_processed = 0;
	bool error;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d GET_CONFIG requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->get_cfg_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST(&trxn->get_cfg_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_GETCFG);
		db_hndl = trxn_req->req.get_data->db_hndl;
		if (!db_hndl) {
			cmgd_frntnd_send_get_cfg_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.get_data->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				NULL, "No such database!");
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
	cmgd_trxn_req_t *trxn_req;
	cmgd_db_hndl_t db_hndl;
	int num_processed = 0;
	bool error;

	trxn = (cmgd_trxn_ctxt_t *)THREAD_ARG(thread);
	assert(trxn);

	CMGD_TRXN_DBG("Processing %d GET_DATA requests for Trxn:%p Session:0x%lx",
		(int) cmgd_trxn_req_list_count(&trxn->get_data_reqs), trxn,
		trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST(&trxn->get_data_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == CMGD_TRXN_PROC_GETDATA);
		db_hndl = trxn_req->req.get_data->db_hndl;
		if (!db_hndl) {
			cmgd_frntnd_send_get_data_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.get_data->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				NULL, "No such database!");
			error = true;
			goto cmgd_trxn_process_get_data_done;
		}

		if (cmgd_db_is_config(db_hndl) &&
			cmgd_trxn_get_config(trxn, trxn_req, db_hndl) != 0) {
			CMGD_TRXN_ERR("Unable to retrieve Config from DB %d for Trxn %p, Sessn: 0x%lx, Req: %ld!", 
				trxn_req->req.get_data->db_id, trxn,
				trxn->session_id, trxn_req->req_id);
			error = true;
			goto cmgd_trxn_process_get_data_done;
		} else {
			/* 
			 * TODO: Trigger GET procedures for Backend 
			 * For now return back error.
			 */
			cmgd_frntnd_send_get_data_reply(
				trxn->session_id, (cmgd_trxn_id_t) trxn,
				trxn_req->req.get_data->db_id,
				trxn_req->req_id, CMGD_INTERNAL_ERROR,
				NULL, "GET-DATA on Oper DB is not supported yet!");
			error = true;
			goto cmgd_trxn_process_get_data_done;
		}

cmgd_trxn_process_get_data_done:

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
#ifndef CMGD_LOCAL_VALIDATIONS_ENABLED
	case CMGD_TRXN_SEND_BCKND_CFG_VALIDATE:
		trxn->send_cfg_validate = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_send_bcknd_cfg_validate, trxn,
				CMGD_TRXN_SEND_CFGVALIDATE_DELAY_MSEC, NULL);
		break;
#else /* CMGD_LOCAL_VALIDATIONS_ENABLED */
	case CMGD_TRXN_SEND_BCKND_CFG_APPLY:
		trxn->send_cfg_apply = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_send_bcknd_config_apply, trxn,
				CMGD_TRXN_SEND_CFGAPPLY_DELAY_MSEC, NULL);
		break;
#endif /* ifndef CMGD_LOCAL_VALIDATIONS_ENABLED */
	case CMGD_TRXN_COMMITCFG_TIMEOUT:
		trxn->comm_cfg_timeout = 
			thread_add_timer_msec(cmgd_trxn_tm,
				cmgd_trxn_cfg_commit_timedout, trxn,
				CMGD_TRXN_CFG_COMMIT_MAX_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_trxn_register_event() called incorrectly");
	}
}

static cmgd_trxn_ctxt_t *cmgd_frntnd_find_trxn_by_session_id(
	struct cmgd_master *cm, cmgd_session_id_t session_id,
	cmgd_trxn_type_t type)
{
	cmgd_trxn_ctxt_t *trxn;

	FOREACH_TRXN_IN_LIST(cm, trxn) {
		if (trxn->session_id == session_id && trxn->type == type)
			return trxn;
	}

	return NULL;
}

static void cmgd_trxn_lock(cmgd_trxn_ctxt_t *trxn, const char* file, int line)
{
	trxn->refcount++;
	CMGD_TRXN_DBG("%s:%d --> Lock %s Trxn %p, Count: %d",
			file, line, cmgd_trxn_type2str(trxn->type), trxn,
			trxn->refcount);
}

static void cmgd_trxn_unlock(cmgd_trxn_ctxt_t **trxn, const char* file, int line)
{
	assert(*trxn && (*trxn)->refcount);

	(*trxn)->refcount--;
	CMGD_TRXN_DBG("%s:%d --> Unlock %s Trxn %p, Count: %d",
			file, line, cmgd_trxn_type2str((*trxn)->type), *trxn,
			(*trxn)->refcount);
	if (!(*trxn)->refcount) {
		switch ((*trxn)->type) {
		case CMGD_TRXN_TYPE_CONFIG:
			if (cmgd_trxn_cm->cfg_trxn == *trxn)
				cmgd_trxn_cm->cfg_trxn = NULL;
			break;
		default:
			break;
		}

		cmgd_trxn_list_del(&cmgd_trxn_cm->cmgd_trxns, *trxn);

		CMGD_TRXN_DBG("Deleted %s Trxn %p for Sessn: 0x%lx",
			cmgd_trxn_type2str((*trxn)->type), *trxn,
			(*trxn)->session_id);

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

	trxn = cmgd_frntnd_find_trxn_by_session_id(cmgd_trxn_cm, session_id, type);
	if (!trxn) {
		trxn = XCALLOC(MTYPE_CMGD_TRXN, 
				sizeof(cmgd_trxn_ctxt_t));
		assert(trxn);

		trxn->session_id = session_id;
		trxn->type = type;
		cmgd_trxn_badptr_list_init(&trxn->bcknd_adptrs);
		cmgd_trxn_list_add_tail(&cmgd_trxn_cm->cmgd_trxns, trxn);
		cmgd_trxn_req_list_init(&trxn->set_cfg_reqs);
		cmgd_trxn_req_list_init(&trxn->get_cfg_reqs);
		cmgd_trxn_req_list_init(&trxn->get_data_reqs);
		cmgd_trxn_req_list_init(&trxn->pending_get_datas);
		trxn->commit_cfg_req = NULL;
		trxn->refcount = 0;

		CMGD_TRXN_DBG("Added new '%s' CMGD Transaction '%p'",
			cmgd_trxn_type2str(type), trxn);

		if (type == CMGD_TRXN_TYPE_CONFIG)
			cmgd_trxn_cm->cfg_trxn = trxn;

		CMGD_TRXN_LOCK(trxn);
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

	CMGD_TRXN_UNLOCK(trxn);

	*trxn_id = CMGD_TRXN_ID_NONE;
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
        cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
        cmgd_yang_cfgdata_req_t *cfg_req[], size_t num_req)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req;
	size_t indx;
	uint16_t *num_chgs;
	struct nb_cfg_change *cfg_chg;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	trxn_req = cmgd_trxn_req_alloc(trxn, req_id, CMGD_TRXN_PROC_SETCFG);
	trxn_req->req.set_cfg->db_id = db_id;
	trxn_req->req.set_cfg->db_hndl = db_hndl;
	num_chgs = &trxn_req->req.set_cfg->num_cfg_changes;
	for (indx = 0; indx < num_req; indx++) {
		cfg_chg = &trxn_req->req.set_cfg->cfg_changes[*num_chgs];

		switch(cfg_req[indx]->req_type) {
		case CMGD__CFG_DATA_REQ_TYPE__DELETE_DATA:
			cfg_chg->operation = NB_OP_DESTROY;
			break;
		case CMGD__CFG_DATA_REQ_TYPE__SET_DATA:
			cfg_chg->operation = 
				cmgd_db_find_data_node_by_xpath(
					db_hndl, cfg_req[indx]->data->xpath) ?
				NB_OP_MODIFY : NB_OP_CREATE;
			break;
		default:
			continue;
		}

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
		if (cfg_chg->value)
			CMGD_TRXN_DBG("Allocated value at %p ==> '%s'",
				cfg_chg->value, cfg_chg->value);

		(*num_chgs)++;
	}
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_SETCFG);

	return 0;
}

int cmgd_trxn_send_commit_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t src_db_id, cmgd_db_hndl_t src_db_hndl,
	cmgd_database_id_t dst_db_id, cmgd_db_hndl_t dst_db_hndl,
	bool validate_only, bool abort)
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
	trxn_req->req.commit_cfg.src_db_hndl = src_db_hndl;
	trxn_req->req.commit_cfg.dst_db_id = dst_db_id;
	trxn_req->req.commit_cfg.dst_db_hndl = dst_db_hndl;
	trxn_req->req.commit_cfg.validate_only = validate_only;
	trxn_req->req.commit_cfg.abort = abort;

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_COMMITCFG);
	return 0;
}

int cmgd_trxn_notify_bcknd_trxn_reply(
	cmgd_trxn_id_t trxn_id, bool create, bool success,
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_commit_cfg_req_t *cmtcfg_req = NULL;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn || trxn->type != CMGD_TRXN_TYPE_CONFIG) 
		return -1;

	if (!create && !trxn->commit_cfg_req)
		return 0;

	assert(trxn->commit_cfg_req);
	cmtcfg_req = 
		&trxn->commit_cfg_req->req.commit_cfg;
	if (create) {
		if (success) {
			/*
			 * Done with TRXN_CREATE. Move the backend client to next phase.
			 */
			assert(cmtcfg_req->curr_phase == 
				CMGD_COMMIT_PHASE_TRXN_CREATE);
			// cmgd_move_bcknd_commit_to_next_phase(trxn, adptr);

			/*
			 * Send CFGDATA_CREATE-REQs to the backend immediately.
			 */
			cmgd_trxn_send_bcknd_cfg_data(trxn, adptr);
		} else {
			cmgd_trxn_send_commit_cfg_reply(trxn, false,
				"Internal error! Failed to initiate transaction at backend!");
		}
	} else {
		/*
		 * Done with TRXN_DELETE. Move the backend client to next phase.
		 */
		cmgd_move_bcknd_commit_to_next_phase(trxn, adptr);
	}

	return 0;
}

int cmgd_trxn_notify_bcknd_cfgdata_fail(
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_id,
	char *error_if_any, cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn || trxn->type != CMGD_TRXN_TYPE_CONFIG) 
		return -1;

	assert(trxn->commit_cfg_req);

	cfg_btch = (cmgd_trxn_bcknd_cfg_batch_t *)batch_id;
	if (cfg_btch->trxn != trxn)
		return -1;

	CMGD_TRXN_ERR("CFGDATA_CREATE_REQ sent to '%s' failed for Trxn %p, Batch %p, Err: %s",
		adptr->name, trxn, cfg_btch,
		error_if_any ? error_if_any : "None");
	cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Internal error! Failed to download config data to backend!");

	return 0;
}

int cmgd_trxn_notify_bcknd_cfg_validate_reply(
	cmgd_trxn_id_t trxn_id, bool success, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
        cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;
	cmgd_commit_cfg_req_t *cmtcfg_req = NULL;
	size_t indx;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn || trxn->type != CMGD_TRXN_TYPE_CONFIG) 
		return -1;

	assert(trxn->commit_cfg_req);
	cmtcfg_req = 
		&trxn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		CMGD_TRXN_ERR("CFGDATA_VALIDATE_REQ sent to '%s' failed for Trxn %p, Batches [0x%lx - 0x%lx], Err: %s",
		adptr->name, trxn, batch_ids[0], batch_ids[num_batch_ids-1],
		error_if_any ? error_if_any : "None");
		cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Internal error! Failed to validate config data on backend!");
		return 0;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		cfg_btch = (cmgd_trxn_bcknd_cfg_batch_t *)batch_ids[indx];
		if (cfg_btch->trxn != trxn)
			return -1;
		// cfg_btch->comm_phase = CMGD_COMMIT_PHASE_APPLY_CFG;
		cmgd_move_trxn_cfg_batch_to_next(cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			CMGD_COMMIT_PHASE_APPLY_CFG);
	}

	cmgd_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

extern int cmgd_trxn_notify_bcknd_cfg_apply_reply(
	cmgd_trxn_id_t trxn_id, bool success, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
        cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_bcknd_cfg_batch_t *cfg_btch;
	cmgd_commit_cfg_req_t *cmtcfg_req = NULL;
	size_t indx;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn || trxn->type != CMGD_TRXN_TYPE_CONFIG) 
		return -1;

	assert(trxn->commit_cfg_req);
	cmtcfg_req = 
		&trxn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		CMGD_TRXN_ERR("CFGDATA_APPLY_REQ sent to '%s' failed for Trxn %p, Batches [0x%lx - 0x%lx], Err: %s",
		adptr->name, trxn, batch_ids[0], batch_ids[num_batch_ids-1],
		error_if_any ? error_if_any : "None");
		cmgd_trxn_send_commit_cfg_reply(trxn, false,
			"Internal error! Failed to apply config data on backend!");
		return 0;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		cfg_btch = (cmgd_trxn_bcknd_cfg_batch_t *)batch_ids[indx];
		if (cfg_btch->trxn != trxn)
			return -1;
		cmgd_move_trxn_cfg_batch_to_next(cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			CMGD_COMMIT_PHASE_TRXN_DELETE);
	}

	if (!cmgd_trxn_batch_list_count(&cmtcfg_req->curr_batches[adptr->id]))
		cmgd_trxn_send_bcknd_trxn_delete(trxn, adptr);

	cmgd_try_move_commit_to_next_phase(trxn, cmtcfg_req);

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
        cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
        cmgd_yang_getdata_req_t **data_req, size_t num_reqs)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req;
	size_t indx;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	trxn_req = cmgd_trxn_req_alloc(trxn, req_id, CMGD_TRXN_PROC_GETCFG);
	trxn_req->req.get_data->db_id = db_id;
	trxn_req->req.get_data->db_hndl = db_hndl;
	for (indx = 0; indx < num_reqs &&
		indx < CMGD_MAX_NUM_DATA_REPLY_IN_BATCH; indx++) {
		CMGD_TRXN_DBG("XPath: '%s'", data_req[indx]->data->xpath);
		trxn_req->req.get_data->xpaths[indx] =
			strdup(data_req[indx]->data->xpath);
		trxn_req->req.get_data->num_xpaths++;
	}

	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_GETCFG);

	return 0;
}

int cmgd_trxn_send_get_data_req(
        cmgd_trxn_id_t trxn_id, cmgd_client_req_id_t req_id,
        cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
        cmgd_yang_getdata_req_t **data_req, size_t num_reqs)
{
	cmgd_trxn_ctxt_t *trxn;
	cmgd_trxn_req_t *trxn_req;
	size_t indx;

	trxn = (cmgd_trxn_ctxt_t *)trxn_id;
	if (!trxn)
		return -1;

	trxn_req = cmgd_trxn_req_alloc(trxn, req_id, CMGD_TRXN_PROC_GETDATA);
	trxn_req->req.get_data->db_id = db_id;
	trxn_req->req.get_data->db_hndl = db_hndl;
	for (indx = 0; indx < num_reqs &&
		indx < CMGD_MAX_NUM_DATA_REPLY_IN_BATCH; indx++) {
		CMGD_TRXN_DBG("XPath: '%s'", data_req[indx]->data->xpath);
		trxn_req->req.get_data->xpaths[indx] =
			strdup(data_req[indx]->data->xpath);
		trxn_req->req.get_data->num_xpaths++;
	}

	cmgd_trxn_register_event(trxn, CMGD_TRXN_PROC_GETDATA);

	return 0;
}

void cmgd_trxn_status_write(struct vty *vty)
{
	cmgd_trxn_ctxt_t *trxn;

	vty_out(vty, "CMGD Transactions\n");

	FOREACH_TRXN_IN_LIST(cmgd_trxn_cm, trxn) {
		vty_out(vty, "  Trxn-Id: \t\t\t%p\n", trxn);
		vty_out(vty, "    Session-Id: \t\t0x%lx\n", trxn->session_id);
		vty_out(vty, "    Type: \t\t\t%s\n", cmgd_trxn_type2str(trxn->type));
		vty_out(vty, "    Ref-Count: \t\t\t%d\n", trxn->refcount);
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_trxn_list_count(&cmgd_trxn_cm->cmgd_trxns));
}
