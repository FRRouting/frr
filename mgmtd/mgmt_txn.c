// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Transactions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "darr.h"
#include "hash.h"
#include "jhash.h"
#include "libfrr.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_txn.h"

#define MGMTD_TXN_DBG(fmt, ...)                                                \
	DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define MGMTD_TXN_ERR(fmt, ...)                                                \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define MGMTD_TXN_LOCK(txn)   mgmt_txn_lock(txn, __FILE__, __LINE__)
#define MGMTD_TXN_UNLOCK(txn) mgmt_txn_unlock(txn, __FILE__, __LINE__)

enum mgmt_txn_event {
	MGMTD_TXN_PROC_SETCFG = 1,
	MGMTD_TXN_PROC_COMMITCFG,
	MGMTD_TXN_PROC_GETCFG,
	MGMTD_TXN_PROC_GETDATA,
	MGMTD_TXN_PROC_GETTREE,
	MGMTD_TXN_COMMITCFG_TIMEOUT,
	MGMTD_TXN_GETTREE_TIMEOUT,
	MGMTD_TXN_CLEANUP
};

PREDECL_LIST(mgmt_txn_reqs);

struct mgmt_set_cfg_req {
	Mgmtd__DatastoreId ds_id;
	struct mgmt_ds_ctx *ds_ctx;
	struct nb_cfg_change cfg_changes[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
	bool implicit_commit;
	Mgmtd__DatastoreId dst_ds_id;
	struct mgmt_ds_ctx *dst_ds_ctx;
	struct mgmt_setcfg_stats *setcfg_stats;
};

enum mgmt_commit_phase {
	MGMTD_COMMIT_PHASE_PREPARE_CFG = 0,
	MGMTD_COMMIT_PHASE_TXN_CREATE,
	MGMTD_COMMIT_PHASE_SEND_CFG,
	MGMTD_COMMIT_PHASE_APPLY_CFG,
	MGMTD_COMMIT_PHASE_TXN_DELETE,
	MGMTD_COMMIT_PHASE_MAX
};

static inline const char *mgmt_commit_phase2str(enum mgmt_commit_phase cmt_phase)
{
	switch (cmt_phase) {
	case MGMTD_COMMIT_PHASE_PREPARE_CFG:
		return "PREP-CFG";
	case MGMTD_COMMIT_PHASE_TXN_CREATE:
		return "CREATE-TXN";
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		return "SEND-CFG";
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		return "APPLY-CFG";
	case MGMTD_COMMIT_PHASE_TXN_DELETE:
		return "DELETE-TXN";
	case MGMTD_COMMIT_PHASE_MAX:
		return "Invalid/Unknown";
	}

	return "Invalid/Unknown";
}

PREDECL_LIST(mgmt_txn_batches);

struct mgmt_txn_be_cfg_batch {
	struct mgmt_txn_ctx *txn;
	enum mgmt_be_client_id be_id;
	struct mgmt_be_client_adapter *be_adapter;
	Mgmtd__YangCfgDataReq cfg_data[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangCfgDataReq *cfg_datap[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangData data[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangDataValue value[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	size_t num_cfg_data;
	int buf_space_left;
	struct mgmt_txn_batches_item list_linkage;
};

DECLARE_LIST(mgmt_txn_batches, struct mgmt_txn_be_cfg_batch, list_linkage);

#define FOREACH_TXN_CFG_BATCH_IN_LIST(list, batch)                             \
	frr_each_safe (mgmt_txn_batches, list, batch)

struct mgmt_commit_cfg_req {
	Mgmtd__DatastoreId src_ds_id;
	struct mgmt_ds_ctx *src_ds_ctx;
	Mgmtd__DatastoreId dst_ds_id;
	struct mgmt_ds_ctx *dst_ds_ctx;
	uint32_t nb_txn_id;
	uint8_t validate_only : 1;
	uint8_t abort : 1;
	uint8_t implicit : 1;
	uint8_t rollback : 1;

	/* Track commit phases */
	enum mgmt_commit_phase curr_phase;
	enum mgmt_commit_phase next_phase;

	enum mgmt_commit_phase be_phase[MGMTD_BE_CLIENT_ID_MAX];

	/*
	 * Set of config changes to commit. This is used only
	 * when changes are NOT to be determined by comparing
	 * candidate and running DSs. This is typically used
	 * for downloading all relevant configs for a new backend
	 * client that has recently come up and connected with
	 * MGMTD.
	 */
	struct nb_config_cbs *cfg_chgs;

	/*
	 * Details on all the Backend Clients associated with
	 * this commit.
	 */
	uint64_t clients;

	/*
	 * List of backend batches for this commit to be validated
	 * and applied at the backend.
	 */
	struct mgmt_txn_batches_head batches[MGMTD_BE_CLIENT_ID_MAX];
	/*
	 * The last batch added for any backend client.
	 */
	struct mgmt_txn_be_cfg_batch *last_be_cfg_batch[MGMTD_BE_CLIENT_ID_MAX];

	struct mgmt_commit_stats *cmt_stats;
};

struct mgmt_get_data_reply {
	/* Buffer space for preparing data reply */
	int num_reply;
	int last_batch;
	Mgmtd__YangDataReply data_reply;
	Mgmtd__YangData reply_data[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	Mgmtd__YangData *reply_datap[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	Mgmtd__YangDataValue reply_value[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	char *reply_xpathp[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
};

struct mgmt_get_data_req {
	Mgmtd__DatastoreId ds_id;
	struct nb_config *cfg_root;
	char *xpaths[MGMTD_MAX_NUM_DATA_REQ_IN_BATCH];
	int num_xpaths;

	/*
	 * Buffer space for preparing reply.
	 * NOTE: Should only be malloc-ed on demand to reduce
	 * memory footprint. Freed up via mgmt_trx_req_free()
	 */
	struct mgmt_get_data_reply *reply;

	int total_reply;
};


struct txn_req_get_tree {
	char *xpath;	       /* xpath of tree to get */
	uint8_t result_type;   /* LYD_FORMAT for results */
	uint64_t sent_clients; /* Bitmask of clients sent req to */
	uint64_t recv_clients; /* Bitmask of clients recv reply from */
	int32_t partial_error; /* an error while gather results */
	struct lyd_node *client_results; /* result tree from clients */
};

struct mgmt_txn_req {
	struct mgmt_txn_ctx *txn;
	enum mgmt_txn_event req_event;
	uint64_t req_id;
	union {
		struct mgmt_set_cfg_req *set_cfg;
		struct mgmt_get_data_req *get_data;
		struct txn_req_get_tree *get_tree;
		struct mgmt_commit_cfg_req commit_cfg;
	} req;

	bool pending_be_proc;
	struct mgmt_txn_reqs_item list_linkage;
};

DECLARE_LIST(mgmt_txn_reqs, struct mgmt_txn_req, list_linkage);

#define FOREACH_TXN_REQ_IN_LIST(list, req)                                     \
	frr_each_safe (mgmt_txn_reqs, list, req)

struct mgmt_txn_ctx {
	uint64_t session_id; /* One transaction per client session */
	uint64_t txn_id;
	enum mgmt_txn_type type;

	/* struct mgmt_master *mm; */

	struct event *proc_set_cfg;
	struct event *proc_comm_cfg;
	struct event *proc_get_cfg;
	struct event *proc_get_data;
	struct event *proc_get_tree;
	struct event *comm_cfg_timeout;
	struct event *get_tree_timeout;
	struct event *clnup;

	/* List of backend adapters involved in this transaction */
	struct mgmt_txn_badapters_head be_adapters;

	int refcount;

	struct mgmt_txns_item list_linkage;

	/* TODO: why do we need unique lists for each type of transaction since
	 * a transaction is of only 1 type?
	 */

	/*
	 * List of pending set-config requests for a given
	 * transaction/session. Just one list for requests
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct mgmt_txn_reqs_head set_cfg_reqs;
	/*
	 * List of pending get-config requests for a given
	 * transaction/session. Just one list for requests
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct mgmt_txn_reqs_head get_cfg_reqs;
	/*
	 * List of pending get-data requests for a given
	 * transaction/session Two lists, one for requests
	 * not processed at all, and one for requests that
	 * has been sent to backend for processing.
	 */
	struct mgmt_txn_reqs_head get_data_reqs;
	struct mgmt_txn_reqs_head pending_get_datas;
	/*
	 * List of pending get-tree requests.
	 */
	struct mgmt_txn_reqs_head get_tree_reqs;
	/*
	 * There will always be one commit-config allowed for a given
	 * transaction/session. No need to maintain lists for it.
	 */
	struct mgmt_txn_req *commit_cfg_req;
};

DECLARE_LIST(mgmt_txns, struct mgmt_txn_ctx, list_linkage);

#define FOREACH_TXN_IN_LIST(mm, txn)                                           \
	frr_each_safe (mgmt_txns, &(mm)->txn_list, (txn))

static int mgmt_txn_send_commit_cfg_reply(struct mgmt_txn_ctx *txn,
					  enum mgmt_result result,
					  const char *error_if_any);

static inline const char *mgmt_txn_commit_phase_str(struct mgmt_txn_ctx *txn,
						    bool curr)
{
	if (!txn->commit_cfg_req)
		return "None";

	return (mgmt_commit_phase2str(
		curr ? txn->commit_cfg_req->req.commit_cfg.curr_phase
		     : txn->commit_cfg_req->req.commit_cfg.next_phase));
}

static void mgmt_txn_lock(struct mgmt_txn_ctx *txn, const char *file, int line);
static void mgmt_txn_unlock(struct mgmt_txn_ctx **txn, const char *file,
			    int line);
static int mgmt_txn_send_be_txn_delete(struct mgmt_txn_ctx *txn,
				       struct mgmt_be_client_adapter *adapter);

static struct event_loop *mgmt_txn_tm;
static struct mgmt_master *mgmt_txn_mm;

static void mgmt_txn_register_event(struct mgmt_txn_ctx *txn,
				    enum mgmt_txn_event event);

static struct mgmt_txn_be_cfg_batch *
mgmt_txn_cfg_batch_alloc(struct mgmt_txn_ctx *txn, enum mgmt_be_client_id id,
			 struct mgmt_be_client_adapter *be_adapter)
{
	struct mgmt_txn_be_cfg_batch *batch;

	batch = XCALLOC(MTYPE_MGMTD_TXN_CFG_BATCH,
			sizeof(struct mgmt_txn_be_cfg_batch));
	assert(batch);
	batch->be_id = id;

	batch->txn = txn;
	MGMTD_TXN_LOCK(txn);
	assert(txn->commit_cfg_req);
	mgmt_txn_batches_add_tail(&txn->commit_cfg_req->req.commit_cfg
					   .batches[id],
				  batch);
	batch->be_adapter = be_adapter;
	batch->buf_space_left = MGMTD_BE_CFGDATA_MAX_MSG_LEN;
	if (be_adapter)
		mgmt_be_adapter_lock(be_adapter);

	txn->commit_cfg_req->req.commit_cfg.last_be_cfg_batch[id] = batch;

	return batch;
}

static void mgmt_txn_cfg_batch_free(struct mgmt_txn_be_cfg_batch **batch)
{
	size_t indx;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	MGMTD_TXN_DBG(" freeing batch txn-id %" PRIu64, (*batch)->txn->txn_id);

	assert((*batch)->txn && (*batch)->txn->type == MGMTD_TXN_TYPE_CONFIG);

	cmtcfg_req = &(*batch)->txn->commit_cfg_req->req.commit_cfg;
	mgmt_txn_batches_del(&cmtcfg_req->batches[(*batch)->be_id], *batch);

	if ((*batch)->be_adapter)
		mgmt_be_adapter_unlock(&(*batch)->be_adapter);

	for (indx = 0; indx < (*batch)->num_cfg_data; indx++) {
		if ((*batch)->data[indx].xpath) {
			free((*batch)->data[indx].xpath);
			(*batch)->data[indx].xpath = NULL;
		}
	}

	MGMTD_TXN_UNLOCK(&(*batch)->txn);

	XFREE(MTYPE_MGMTD_TXN_CFG_BATCH, *batch);
	*batch = NULL;
}

static void mgmt_txn_cleanup_be_cfg_batches(struct mgmt_txn_ctx *txn,
					    enum mgmt_be_client_id id)
{
	struct mgmt_txn_be_cfg_batch *batch;
	struct mgmt_txn_batches_head *list;

	list = &txn->commit_cfg_req->req.commit_cfg.batches[id];
	FOREACH_TXN_CFG_BATCH_IN_LIST (list, batch)
		mgmt_txn_cfg_batch_free(&batch);

	mgmt_txn_batches_fini(list);

	txn->commit_cfg_req->req.commit_cfg.last_be_cfg_batch[id] = NULL;
}

static struct mgmt_txn_req *mgmt_txn_req_alloc(struct mgmt_txn_ctx *txn,
					       uint64_t req_id,
					       enum mgmt_txn_event req_event)
{
	struct mgmt_txn_req *txn_req;
	enum mgmt_be_client_id id;

	txn_req = XCALLOC(MTYPE_MGMTD_TXN_REQ, sizeof(struct mgmt_txn_req));
	assert(txn_req);
	txn_req->txn = txn;
	txn_req->req_id = req_id;
	txn_req->req_event = req_event;
	txn_req->pending_be_proc = false;

	switch (txn_req->req_event) {
	case MGMTD_TXN_PROC_SETCFG:
		txn_req->req.set_cfg = XCALLOC(MTYPE_MGMTD_TXN_SETCFG_REQ,
					       sizeof(struct mgmt_set_cfg_req));
		assert(txn_req->req.set_cfg);
		mgmt_txn_reqs_add_tail(&txn->set_cfg_reqs, txn_req);
		MGMTD_TXN_DBG("Added a new SETCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64 ", session-id: %" PRIu64,
			      txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_COMMITCFG:
		txn->commit_cfg_req = txn_req;
		MGMTD_TXN_DBG("Added a new COMMITCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64 " session-id: %" PRIu64,
			      txn_req->req_id, txn->txn_id, txn->session_id);

		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			txn_req->req.commit_cfg.be_phase[id] =
				MGMTD_COMMIT_PHASE_PREPARE_CFG;
			mgmt_txn_batches_init(
				&txn_req->req.commit_cfg.batches[id]);
		}

		txn_req->req.commit_cfg.curr_phase = MGMTD_COMMIT_PHASE_PREPARE_CFG;
		break;
	case MGMTD_TXN_PROC_GETCFG:
		txn_req->req.get_data =
			XCALLOC(MTYPE_MGMTD_TXN_GETDATA_REQ,
				sizeof(struct mgmt_get_data_req));
		assert(txn_req->req.get_data);
		mgmt_txn_reqs_add_tail(&txn->get_cfg_reqs, txn_req);
		MGMTD_TXN_DBG("Added a new GETCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64 " session-id: %" PRIu64,
			      txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_GETDATA:
		txn_req->req.get_data =
			XCALLOC(MTYPE_MGMTD_TXN_GETDATA_REQ,
				sizeof(struct mgmt_get_data_req));
		assert(txn_req->req.get_data);
		mgmt_txn_reqs_add_tail(&txn->get_data_reqs, txn_req);
		MGMTD_TXN_DBG("Added a new GETDATA req-id: %" PRIu64
			      " txn-id: %" PRIu64 " session-id: %" PRIu64,
			      txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_GETTREE:
		txn_req->req.get_tree = XCALLOC(MTYPE_MGMTD_TXN_GETTREE_REQ,
						sizeof(struct txn_req_get_tree));
		mgmt_txn_reqs_add_tail(&txn->get_tree_reqs, txn_req);
		MGMTD_TXN_DBG("Added a new GETTREE req-id: %" PRIu64
			      " txn-id: %" PRIu64 " session-id: %" PRIu64,
			      txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_COMMITCFG_TIMEOUT:
	case MGMTD_TXN_GETTREE_TIMEOUT:
	case MGMTD_TXN_CLEANUP:
		break;
	}

	MGMTD_TXN_LOCK(txn);

	return txn_req;
}

static void mgmt_txn_req_free(struct mgmt_txn_req **txn_req)
{
	int indx;
	struct mgmt_txn_reqs_head *req_list = NULL;
	struct mgmt_txn_reqs_head *pending_list = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *ccreq;
	bool cleanup;

	switch ((*txn_req)->req_event) {
	case MGMTD_TXN_PROC_SETCFG:
		for (indx = 0; indx < (*txn_req)->req.set_cfg->num_cfg_changes;
		     indx++) {
			if ((*txn_req)->req.set_cfg->cfg_changes[indx].value) {
				MGMTD_TXN_DBG("Freeing value for %s at %p ==> '%s'",
					      (*txn_req)
						      ->req.set_cfg
						      ->cfg_changes[indx]
						      .xpath,
					      (*txn_req)
						      ->req.set_cfg
						      ->cfg_changes[indx]
						      .value,
					      (*txn_req)
						      ->req.set_cfg
						      ->cfg_changes[indx]
						      .value);
				free((void *)(*txn_req)
					     ->req.set_cfg->cfg_changes[indx]
					     .value);
			}
		}
		req_list = &(*txn_req)->txn->set_cfg_reqs;
		MGMTD_TXN_DBG("Deleting SETCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64,
			      (*txn_req)->req_id, (*txn_req)->txn->txn_id);
		XFREE(MTYPE_MGMTD_TXN_SETCFG_REQ, (*txn_req)->req.set_cfg);
		break;
	case MGMTD_TXN_PROC_COMMITCFG:
		MGMTD_TXN_DBG("Deleting COMMITCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64,
			      (*txn_req)->req_id, (*txn_req)->txn->txn_id);

		ccreq = &(*txn_req)->req.commit_cfg;
		cleanup = (ccreq->curr_phase >= MGMTD_COMMIT_PHASE_TXN_CREATE &&
			   ccreq->curr_phase < MGMTD_COMMIT_PHASE_TXN_DELETE);

		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			/*
			 * Send TXN_DELETE to cleanup state for this
			 * transaction on backend
			 */

			/*
			 * Get rid of the batches first so we don't end up doing
			 * anything more with them
			 */
			mgmt_txn_cleanup_be_cfg_batches((*txn_req)->txn, id);

			/*
			 * If we were in the middle of the state machine then
			 * send a txn delete message
			 */
			adapter = mgmt_be_get_adapter_by_id(id);
			if (adapter && cleanup && IS_IDBIT_SET(ccreq->clients, id))
				mgmt_txn_send_be_txn_delete((*txn_req)->txn,
							    adapter);
		}
		break;
	case MGMTD_TXN_PROC_GETCFG:
		for (indx = 0; indx < (*txn_req)->req.get_data->num_xpaths;
		     indx++) {
			if ((*txn_req)->req.get_data->xpaths[indx])
				free((void *)(*txn_req)
					     ->req.get_data->xpaths[indx]);
		}
		req_list = &(*txn_req)->txn->get_cfg_reqs;
		MGMTD_TXN_DBG("Deleting GETCFG req-id: %" PRIu64
			      " txn-id: %" PRIu64,
			      (*txn_req)->req_id, (*txn_req)->txn->txn_id);
		if ((*txn_req)->req.get_data->reply)
			XFREE(MTYPE_MGMTD_TXN_GETDATA_REPLY,
			      (*txn_req)->req.get_data->reply);

		if ((*txn_req)->req.get_data->cfg_root)
			nb_config_free((*txn_req)->req.get_data->cfg_root);

		XFREE(MTYPE_MGMTD_TXN_GETDATA_REQ, (*txn_req)->req.get_data);
		break;
	case MGMTD_TXN_PROC_GETDATA:
		for (indx = 0; indx < (*txn_req)->req.get_data->num_xpaths;
		     indx++) {
			if ((*txn_req)->req.get_data->xpaths[indx])
				free((void *)(*txn_req)
					     ->req.get_data->xpaths[indx]);
		}
		pending_list = &(*txn_req)->txn->pending_get_datas;
		req_list = &(*txn_req)->txn->get_data_reqs;
		MGMTD_TXN_DBG("Deleting GETDATA req-id: %" PRIu64
			      " txn-id: %" PRIu64,
			      (*txn_req)->req_id, (*txn_req)->txn->txn_id);
		if ((*txn_req)->req.get_data->reply)
			XFREE(MTYPE_MGMTD_TXN_GETDATA_REPLY,
			      (*txn_req)->req.get_data->reply);
		XFREE(MTYPE_MGMTD_TXN_GETDATA_REQ, (*txn_req)->req.get_data);
		break;
	case MGMTD_TXN_PROC_GETTREE:
		MGMTD_TXN_DBG("Deleting GETTREE req-id: %" PRIu64
			      " of txn-id: %" PRIu64,
			      (*txn_req)->req_id, (*txn_req)->txn->txn_id);
		req_list = &(*txn_req)->txn->get_tree_reqs;
		lyd_free_all((*txn_req)->req.get_tree->client_results);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.get_tree->xpath);
		XFREE(MTYPE_MGMTD_TXN_GETTREE_REQ, (*txn_req)->req.get_tree);
		break;
	case MGMTD_TXN_COMMITCFG_TIMEOUT:
	case MGMTD_TXN_GETTREE_TIMEOUT:
	case MGMTD_TXN_CLEANUP:
		break;
	}

	if ((*txn_req)->pending_be_proc && pending_list) {
		mgmt_txn_reqs_del(pending_list, *txn_req);
		MGMTD_TXN_DBG("Removed req-id: %" PRIu64
			      " from pending-list (left:%zu)",
			      (*txn_req)->req_id,
			      mgmt_txn_reqs_count(pending_list));
	} else if (req_list) {
		mgmt_txn_reqs_del(req_list, *txn_req);
		MGMTD_TXN_DBG("Removed req-id: %" PRIu64
			      " from request-list (left:%zu)",
			      (*txn_req)->req_id, mgmt_txn_reqs_count(req_list));
	}

	(*txn_req)->pending_be_proc = false;
	MGMTD_TXN_UNLOCK(&(*txn_req)->txn);
	XFREE(MTYPE_MGMTD_TXN_REQ, (*txn_req));
	*txn_req = NULL;
}

static void mgmt_txn_process_set_cfg(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_ds_ctx *ds_ctx;
	struct nb_config *nb_config;
	char err_buf[1024];
	bool error;
	int num_processed = 0;
	size_t left;
	struct mgmt_commit_stats *cmt_stats;
	int ret = 0;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);
	cmt_stats = mgmt_fe_get_session_commit_stats(txn->session_id);

	MGMTD_TXN_DBG("Processing %zu SET_CONFIG requests txn-id:%" PRIu64
		      " session-id: %" PRIu64,
		      mgmt_txn_reqs_count(&txn->set_cfg_reqs), txn->txn_id,
		      txn->session_id);

	FOREACH_TXN_REQ_IN_LIST (&txn->set_cfg_reqs, txn_req) {
		assert(txn_req->req_event == MGMTD_TXN_PROC_SETCFG);
		ds_ctx = txn_req->req.set_cfg->ds_ctx;
		if (!ds_ctx) {
			mgmt_fe_send_set_cfg_reply(txn->session_id, txn->txn_id,
						   txn_req->req.set_cfg->ds_id,
						   txn_req->req_id,
						   MGMTD_INTERNAL_ERROR,
						   "No such datastore!",
						   txn_req->req.set_cfg
							   ->implicit_commit);
			goto mgmt_txn_process_set_cfg_done;
		}

		nb_config = mgmt_ds_get_nb_config(ds_ctx);
		if (!nb_config) {
			mgmt_fe_send_set_cfg_reply(txn->session_id, txn->txn_id,
						   txn_req->req.set_cfg->ds_id,
						   txn_req->req_id,
						   MGMTD_INTERNAL_ERROR,
						   "Unable to retrieve DS Config Tree!",
						   txn_req->req.set_cfg
							   ->implicit_commit);
			goto mgmt_txn_process_set_cfg_done;
		}

		error = false;
		nb_candidate_edit_config_changes(nb_config,
						 txn_req->req.set_cfg->cfg_changes,
						 (size_t)txn_req->req.set_cfg
							 ->num_cfg_changes,
						 NULL, err_buf, sizeof(err_buf),
						 &error);
		if (error) {
			mgmt_fe_send_set_cfg_reply(txn->session_id, txn->txn_id,
						   txn_req->req.set_cfg->ds_id,
						   txn_req->req_id,
						   MGMTD_INTERNAL_ERROR, err_buf,
						   txn_req->req.set_cfg
							   ->implicit_commit);
			goto mgmt_txn_process_set_cfg_done;
		}

		if (txn_req->req.set_cfg->implicit_commit) {
			assert(mgmt_txn_reqs_count(&txn->set_cfg_reqs) == 1);
			assert(txn_req->req.set_cfg->dst_ds_ctx);

			/* We expect the user to have locked the DST DS */
			if (!mgmt_ds_is_locked(txn_req->req.set_cfg->dst_ds_ctx,
					       txn->session_id)) {
				MGMTD_TXN_ERR("DS %u not locked for implicit commit txn-id: %" PRIu64
					      " session-id: %" PRIu64 " err: %s",
					      txn_req->req.set_cfg->dst_ds_id,
					      txn->txn_id, txn->session_id,
					      strerror(ret));
				mgmt_fe_send_set_cfg_reply(
					txn->session_id, txn->txn_id,
					txn_req->req.set_cfg->ds_id,
					txn_req->req_id, MGMTD_DS_LOCK_FAILED,
					"running DS not locked for implicit commit",
					txn_req->req.set_cfg->implicit_commit);
				goto mgmt_txn_process_set_cfg_done;
			}

			mgmt_txn_send_commit_config_req(txn->txn_id,
							txn_req->req_id,
							txn_req->req.set_cfg
								->ds_id,
							txn_req->req.set_cfg
								->ds_ctx,
							txn_req->req.set_cfg
								->dst_ds_id,
							txn_req->req.set_cfg
								->dst_ds_ctx,
							false, false, true);

			if (mm->perf_stats_en)
				gettimeofday(&cmt_stats->last_start, NULL);
			cmt_stats->commit_cnt++;
		} else if (mgmt_fe_send_set_cfg_reply(txn->session_id,
						      txn->txn_id,
						      txn_req->req.set_cfg->ds_id,
						      txn_req->req_id,
						      MGMTD_SUCCESS, NULL,
						      false) != 0) {
			MGMTD_TXN_ERR("Failed to send SET_CONFIG_REPLY txn-id %" PRIu64
				      " session-id: %" PRIu64,
				      txn->txn_id, txn->session_id);
		}

mgmt_txn_process_set_cfg_done:

		/*
		 * Note: The following will remove it from the list as well.
		 */
		mgmt_txn_req_free(&txn_req);

		num_processed++;
		if (num_processed == MGMTD_TXN_MAX_NUM_SETCFG_PROC)
			break;
	}

	left = mgmt_txn_reqs_count(&txn->set_cfg_reqs);
	if (left) {
		MGMTD_TXN_DBG("Processed maximum number of Set-Config requests (%d/%d/%d). Rescheduling for rest.",
			      num_processed, MGMTD_TXN_MAX_NUM_SETCFG_PROC,
			      (int)left);
		mgmt_txn_register_event(txn, MGMTD_TXN_PROC_SETCFG);
	}
}

static int mgmt_txn_send_commit_cfg_reply(struct mgmt_txn_ctx *txn,
					  enum mgmt_result result,
					  const char *error_if_any)
{
	bool success, create_cmt_info_rec;

	if (!txn->commit_cfg_req)
		return -1;

	success = (result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES);

	/* TODO: these replies should not be send if it's a rollback
	 * b/c right now that is special cased.. that special casing should be
	 * removed; however...
	 */
	if (!txn->commit_cfg_req->req.commit_cfg.implicit && txn->session_id &&
	    !txn->commit_cfg_req->req.commit_cfg.rollback &&
	    mgmt_fe_send_commit_cfg_reply(txn->session_id, txn->txn_id,
					  txn->commit_cfg_req->req.commit_cfg
						  .src_ds_id,
					  txn->commit_cfg_req->req.commit_cfg
						  .dst_ds_id,
					  txn->commit_cfg_req->req_id,
					  txn->commit_cfg_req->req.commit_cfg
						  .validate_only,
					  result, error_if_any) != 0) {
		MGMTD_TXN_ERR("Failed to send COMMIT-CONFIG-REPLY txn-id: %" PRIu64
			      " session-id: %" PRIu64,
			      txn->txn_id, txn->session_id);
	}

	if (txn->commit_cfg_req->req.commit_cfg.implicit && txn->session_id &&
	    !txn->commit_cfg_req->req.commit_cfg.rollback &&
	    mgmt_fe_send_set_cfg_reply(txn->session_id, txn->txn_id,
				       txn->commit_cfg_req->req.commit_cfg
					       .src_ds_id,
				       txn->commit_cfg_req->req_id,
				       success ? MGMTD_SUCCESS
					       : MGMTD_INTERNAL_ERROR,
				       error_if_any, true) != 0) {
		MGMTD_TXN_ERR("Failed to send SET-CONFIG-REPLY txn-id: %" PRIu64
			      " session-id: %" PRIu64,
			      txn->txn_id, txn->session_id);
	}

	if (success) {
		/* Stop the commit-timeout timer */
		/* XXX why only on success? */
		EVENT_OFF(txn->comm_cfg_timeout);

		create_cmt_info_rec =
			(result != MGMTD_NO_CFG_CHANGES &&
			 !txn->commit_cfg_req->req.commit_cfg.rollback);

		/*
		 * Successful commit: Merge Src DS into Dst DS if and only if
		 * this was not a validate-only or abort request.
		 */
		if ((txn->session_id &&
		     !txn->commit_cfg_req->req.commit_cfg.validate_only &&
		     !txn->commit_cfg_req->req.commit_cfg.abort) ||
		    txn->commit_cfg_req->req.commit_cfg.rollback) {
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg
						 .src_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg
						 .dst_ds_ctx,
					 create_cmt_info_rec);
		}

		/*
		 * Restore Src DS back to Dest DS only through a commit abort
		 * request.
		 */
		if (txn->session_id && txn->commit_cfg_req->req.commit_cfg.abort)
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg
						 .dst_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg
						 .src_ds_ctx,
					 false);
	} else {
		/*
		 * The commit has failied. For implicit commit requests restore
		 * back the contents of the candidate DS.
		 */
		if (txn->commit_cfg_req->req.commit_cfg.implicit)
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg
						 .dst_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg
						 .src_ds_ctx,
					 false);
	}

	if (txn->commit_cfg_req->req.commit_cfg.rollback) {
		mgmt_ds_unlock(txn->commit_cfg_req->req.commit_cfg.src_ds_ctx);
		mgmt_ds_unlock(txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx);
		/*
		 * Resume processing the rollback command.
		 *
		 * TODO: there's no good reason to special case rollback, the
		 * rollback boolean should be passed back to the FE client and it
		 * can do the right thing.
		 */
		mgmt_history_rollback_complete(success);
	}

	txn->commit_cfg_req->req.commit_cfg.cmt_stats = NULL;
	mgmt_txn_req_free(&txn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!txn->session_id)
		mgmt_txn_register_event(txn, MGMTD_TXN_CLEANUP);

	return 0;
}

static int
mgmt_try_move_commit_to_next_phase(struct mgmt_txn_ctx *txn,
				   struct mgmt_commit_cfg_req *cmtcfg_req)
{
	enum mgmt_be_client_id id;

	MGMTD_TXN_DBG("txn-id: %" PRIu64 ", Phase(current:'%s' next:'%s')",
		      txn->txn_id, mgmt_txn_commit_phase_str(txn, true),
		      mgmt_txn_commit_phase_str(txn, false));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id) &&
		    cmtcfg_req->be_phase[id] == cmtcfg_req->curr_phase) {
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

	MGMTD_TXN_DBG("Move entire txn-id: %" PRIu64 " from '%s' to '%s'",
		      txn->txn_id, mgmt_txn_commit_phase_str(txn, true),
		      mgmt_txn_commit_phase_str(txn, false));

	/*
	 * If we are here, it means all the clients has moved to next phase.
	 * So we can move the whole commit to next phase.
	 */
	cmtcfg_req->curr_phase = cmtcfg_req->next_phase;
	cmtcfg_req->next_phase++;

	mgmt_txn_register_event(txn, MGMTD_TXN_PROC_COMMITCFG);

	return 0;
}

/*
 * This is the real workhorse
 */
static int mgmt_txn_create_config_batches(struct mgmt_txn_req *txn_req,
					  struct nb_config_cbs *changes)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	struct mgmt_txn_be_cfg_batch *batch;
	char *xpath = NULL, *value = NULL;
	char err_buf[1024];
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	bool found_validator;
	int num_chgs = 0;
	int xpath_len, value_len;
	uint64_t clients;

	cmtcfg_req = &txn_req->req.commit_cfg;

	RB_FOREACH_SAFE (cb, nb_config_cbs, changes, nxt) {
		chg = (struct nb_config_change *)cb;

		/*
		 * Could have directly pointed to xpath in nb_node.
		 * But dont want to mess with it now.
		 * xpath = chg->cb.nb_node->xpath;
		 */
		xpath = lyd_path(chg->cb.dnode, LYD_PATH_STD, NULL, 0);
		if (!xpath) {
			(void)mgmt_txn_send_commit_cfg_reply(
				txn_req->txn, MGMTD_INTERNAL_ERROR,
				"Internal error! Could not get Xpath from Ds node!");
			return -1;
		}

		value = (char *)lyd_get_value(chg->cb.dnode);
		if (!value)
			value = (char *)MGMTD_BE_CONTAINER_NODE_VAL;

		MGMTD_TXN_DBG("XPATH: %s, Value: '%s'", xpath,
			      value ? value : "NIL");

		clients = mgmt_be_interested_clients(xpath, true);
		cmtcfg_req->clients |= clients;
		if (clients)
			found_validator = true;
		else
			found_validator = false;

		xpath_len = strlen(xpath) + 1;
		value_len = strlen(value) + 1;
		FOREACH_BE_CLIENT_BITS (id, clients) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (!adapter)
				continue;

			batch = cmtcfg_req->last_be_cfg_batch[id];
			if (!batch ||
			    (batch->num_cfg_data ==
			     MGMTD_MAX_CFG_CHANGES_IN_BATCH) ||
			    (batch->buf_space_left < (xpath_len + value_len))) {
				/* Allocate a new config batch */
				batch = mgmt_txn_cfg_batch_alloc(txn_req->txn,
								 id, adapter);
			}

			batch->buf_space_left -= (xpath_len + value_len);

			mgmt_yang_cfg_data_req_init(
				&batch->cfg_data[batch->num_cfg_data]);
			batch->cfg_datap[batch->num_cfg_data] =
				&batch->cfg_data[batch->num_cfg_data];

			if (chg->cb.operation == NB_OP_DESTROY)
				batch->cfg_data[batch->num_cfg_data].req_type =
					MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA;
			else
				batch->cfg_data[batch->num_cfg_data].req_type =
					MGMTD__CFG_DATA_REQ_TYPE__SET_DATA;

			mgmt_yang_data_init(&batch->data[batch->num_cfg_data]);
			batch->cfg_data[batch->num_cfg_data].data =
				&batch->data[batch->num_cfg_data];
			batch->data[batch->num_cfg_data].xpath = strdup(xpath);

			mgmt_yang_data_value_init(
				&batch->value[batch->num_cfg_data]);
			batch->data[batch->num_cfg_data].value =
				&batch->value[batch->num_cfg_data];
			batch->value[batch->num_cfg_data].value_case =
				MGMTD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
			batch->value[batch->num_cfg_data].encoded_str_val =
				value;
			value = NULL;

			MGMTD_TXN_DBG(" -- %s, batch item:%d", adapter->name,
				      (int)batch->num_cfg_data);

			batch->num_cfg_data++;
			num_chgs++;
		}

		if (!found_validator) {
			snprintf(err_buf, sizeof(err_buf),
				 "No validator module found for XPATH: '%s",
				 xpath);
			MGMTD_TXN_ERR("***** %s", err_buf);
		}

		free(xpath);
	}

	cmtcfg_req->cmt_stats->last_batch_cnt = num_chgs;
	if (!num_chgs) {
		(void)mgmt_txn_send_commit_cfg_reply(txn_req->txn,
						     MGMTD_NO_CFG_CHANGES,
						     "No changes found to commit!");
		return -1;
	}

	/* Move all BE clients to create phase */
	FOREACH_MGMTD_BE_CLIENT_ID(id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id))
			cmtcfg_req->be_phase[id] =
				MGMTD_COMMIT_PHASE_TXN_CREATE;
	}

	cmtcfg_req->next_phase = MGMTD_COMMIT_PHASE_TXN_CREATE;
	return 0;
}

static int mgmt_txn_prepare_config(struct mgmt_txn_ctx *txn)
{
	struct nb_context nb_ctx;
	struct nb_config *nb_config;
	struct nb_config_cbs changes;
	struct nb_config_cbs *cfg_chgs = NULL;
	int ret;
	bool del_cfg_chgs = false;

	ret = 0;
	memset(&nb_ctx, 0, sizeof(nb_ctx));
	memset(&changes, 0, sizeof(changes));
	if (txn->commit_cfg_req->req.commit_cfg.cfg_chgs) {
		cfg_chgs = txn->commit_cfg_req->req.commit_cfg.cfg_chgs;
		del_cfg_chgs = true;
		goto mgmt_txn_prep_config_validation_done;
	}

	if (txn->commit_cfg_req->req.commit_cfg.src_ds_id != MGMTD_DS_CANDIDATE) {
		(void)mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INVALID_PARAM,
			"Source DS cannot be any other than CANDIDATE!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	if (txn->commit_cfg_req->req.commit_cfg.dst_ds_id != MGMTD_DS_RUNNING) {
		(void)mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INVALID_PARAM,
			"Destination DS cannot be any other than RUNNING!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	if (!txn->commit_cfg_req->req.commit_cfg.src_ds_ctx) {
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_INVALID_PARAM,
						     "No such source datastore!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	if (!txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx) {
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_INVALID_PARAM,
						     "No such destination datastore!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	if (txn->commit_cfg_req->req.commit_cfg.abort) {
		/*
		 * This is a commit abort request. Return back success.
		 * That should trigger a restore of Candidate datastore to
		 * Running.
		 */
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_SUCCESS, NULL);
		goto mgmt_txn_prepare_config_done;
	}

	nb_config = mgmt_ds_get_nb_config(
		txn->commit_cfg_req->req.commit_cfg.src_ds_ctx);
	if (!nb_config) {
		(void)mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INTERNAL_ERROR,
			"Unable to retrieve Commit DS Config Tree!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	/*
	 * Validate YANG contents of the source DS and get the diff
	 * between source and destination DS contents.
	 */
	char err_buf[BUFSIZ] = { 0 };

	ret = nb_candidate_validate_yang(nb_config, true, err_buf,
					 sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_INVALID_PARAM,
						     err_buf);
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	nb_config_diff(mgmt_ds_get_nb_config(txn->commit_cfg_req->req.commit_cfg
					     .dst_ds_ctx),
		       nb_config, &changes);
	cfg_chgs = &changes;
	del_cfg_chgs = true;

	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		/*
		 * This means there's no changes to commit whatsoever
		 * is the source of the changes in config.
		 */
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_NO_CFG_CHANGES,
						     "No changes found to be committed!");
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
	if (mm->perf_stats_en)
		gettimeofday(&txn->commit_cfg_req->req.commit_cfg.cmt_stats
				      ->validate_start,
			     NULL);
	/*
	 * Perform application level validations locally on the MGMTD
	 * process by calling application specific validation routines
	 * loaded onto MGMTD process using libraries.
	 */
	nb_ctx.client = NB_CLIENT_MGMTD_SERVER;
	nb_ctx.user = (void *)txn;
	ret = nb_candidate_validate_code(&nb_ctx, nb_config, &changes, err_buf,
					 sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_INVALID_PARAM,
						     err_buf);
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	if (txn->commit_cfg_req->req.commit_cfg.validate_only) {
		/*
		 * This was a validate-only COMMIT request return success.
		 */
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_SUCCESS, NULL);
		goto mgmt_txn_prepare_config_done;
	}
#endif /* ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED */

mgmt_txn_prep_config_validation_done:

	if (mm->perf_stats_en)
		gettimeofday(&txn->commit_cfg_req->req.commit_cfg.cmt_stats
				      ->prep_cfg_start,
			     NULL);

	/*
	 * Iterate over the diffs and create ordered batches of config
	 * commands to be validated.
	 */
	ret = mgmt_txn_create_config_batches(txn->commit_cfg_req, cfg_chgs);
	if (ret != 0) {
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	/* Move to the Transaction Create Phase */
	txn->commit_cfg_req->req.commit_cfg.curr_phase =
		MGMTD_COMMIT_PHASE_TXN_CREATE;
	mgmt_txn_register_event(txn, MGMTD_TXN_PROC_COMMITCFG);

	/*
	 * Start the COMMIT Timeout Timer to abort Txn if things get stuck at
	 * backend.
	 */
	mgmt_txn_register_event(txn, MGMTD_TXN_COMMITCFG_TIMEOUT);
mgmt_txn_prepare_config_done:

	if (cfg_chgs && del_cfg_chgs)
		nb_config_diff_del_changes(cfg_chgs);

	return ret;
}

static int mgmt_txn_send_be_txn_create(struct mgmt_txn_ctx *txn)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req);

	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id)) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (mgmt_be_send_txn_req(adapter, txn->txn_id, true)) {
				(void)mgmt_txn_send_commit_cfg_reply(
					txn, MGMTD_INTERNAL_ERROR,
					"Could not send TXN_CREATE to backend adapter");
				return -1;
			}
		}
	}

	txn->commit_cfg_req->req.commit_cfg.next_phase =
		MGMTD_COMMIT_PHASE_SEND_CFG;

	/*
	 * Dont move the commit to next phase yet. Wait for the TXN_REPLY to
	 * come back.
	 */

	MGMTD_TXN_DBG("txn-id: %" PRIu64 " session-id: %" PRIu64
		      " Phase(Current:'%s', Next: '%s')",
		      txn->txn_id, txn->session_id,
		      mgmt_txn_commit_phase_str(txn, true),
		      mgmt_txn_commit_phase_str(txn, false));

	return 0;
}

static int mgmt_txn_send_be_cfg_data(struct mgmt_txn_ctx *txn,
				     struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_txn_be_cfg_batch *batch;
	struct mgmt_be_cfgreq cfg_req = { 0 };
	size_t num_batches, indx;

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req);

	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	assert(IS_IDBIT_SET(cmtcfg_req->clients, adapter->id));

	indx = 0;
	num_batches = mgmt_txn_batches_count(&cmtcfg_req->batches[adapter->id]);
	FOREACH_TXN_CFG_BATCH_IN_LIST (&cmtcfg_req->batches[adapter->id],
				       batch) {
		assert(cmtcfg_req->next_phase == MGMTD_COMMIT_PHASE_SEND_CFG);

		cfg_req.cfgdata_reqs = batch->cfg_datap;
		cfg_req.num_reqs = batch->num_cfg_data;
		indx++;
		if (mgmt_be_send_cfgdata_req(adapter, txn->txn_id,
					     cfg_req.cfgdata_reqs,
					     cfg_req.num_reqs,
					     indx == num_batches)) {
			(void)mgmt_txn_send_commit_cfg_reply(
				txn, MGMTD_INTERNAL_ERROR,
				"Internal Error! Could not send config data to backend!");
			MGMTD_TXN_ERR("Could not send CFGDATA_CREATE txn-id: %" PRIu64
				      " to client '%s", txn->txn_id, adapter->name);
			return -1;
		}

		cmtcfg_req->cmt_stats->last_num_cfgdata_reqs++;
	}

	cmtcfg_req->be_phase[adapter->id] = MGMTD_COMMIT_PHASE_SEND_CFG;

	/*
	 * This could be the last Backend Client to send CFGDATA_CREATE_REQ to.
	 * Try moving the commit to next phase.
	 */
	mgmt_try_move_commit_to_next_phase(txn, cmtcfg_req);

	return 0;
}

static int mgmt_txn_send_be_txn_delete(struct mgmt_txn_ctx *txn,
				       struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *cmtcfg_req =
		&txn->commit_cfg_req->req.commit_cfg;

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG);

	if (IS_IDBIT_UNSET(cmtcfg_req->clients, adapter->id))
		return 0;

	return mgmt_be_send_txn_req(adapter, txn->txn_id, false);
}

static void mgmt_txn_cfg_commit_timedout(struct event *thread)
{
	struct mgmt_txn_ctx *txn;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG);

	if (!txn->commit_cfg_req)
		return;

	MGMTD_TXN_ERR("Backend timeout txn-id: %" PRIu64 " aborting commit",
		      txn->txn_id);

	/*
	 * Send a COMMIT_CONFIG_REPLY with failure.
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */
	mgmt_txn_send_commit_cfg_reply(
		txn, MGMTD_INTERNAL_ERROR,
		"Operation on the backend timed-out. Aborting commit!");
}


static int txn_get_tree_data_done(struct mgmt_txn_ctx *txn,
				  struct mgmt_txn_req *txn_req)
{
	struct txn_req_get_tree *get_tree = txn_req->req.get_tree;
	int ret = 0;

	/* cancel timer and send reply onward */
	EVENT_OFF(txn->get_tree_timeout);

	ret = mgmt_fe_adapter_send_tree_data(txn->session_id, txn->txn_id,
					     txn_req->req_id,
					     get_tree->result_type,
					     get_tree->client_results,
					     get_tree->partial_error, false);

	/* we're done with the request */
	mgmt_txn_req_free(&txn_req);

	if (ret) {
		MGMTD_TXN_ERR("Error saving the results of GETTREE for txn-id %" PRIu64
			      " req_id %" PRIu64 " to requested type %u",
			      txn->txn_id, txn_req->req_id,
			      get_tree->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, txn_req->req_id,
						false, ret,
						"Error converting results of GETTREE");
	}

	return ret;
}


static void txn_get_tree_timeout(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(thread);
	txn = txn_req->txn;

	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_SHOW);


	MGMTD_TXN_ERR("Backend timeout txn-id: %" PRIu64 " ending get-tree",
		      txn->txn_id);

	/*
	 * Send a get-tree data reply.
	 *
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */

	txn_req->req.get_tree->partial_error = -ETIMEDOUT;
	txn_get_tree_data_done(txn, txn_req);
}

/*
 * Send CFG_APPLY_REQs to all the backend client.
 *
 * NOTE: This is always dispatched when all CFGDATA_CREATE_REQs
 * for all backend clients has been generated. Please see
 * mgmt_txn_register_event() and mgmt_txn_process_commit_cfg()
 * for details.
 */
static int mgmt_txn_send_be_cfg_apply(struct mgmt_txn_ctx *txn)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req);

	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	if (cmtcfg_req->validate_only) {
		/*
		 * If this was a validate-only COMMIT request return success.
		 */
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_SUCCESS, NULL);
		return 0;
	}

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id)) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (!adapter)
				return -1;

			if (mgmt_be_send_cfgapply_req(adapter, txn->txn_id)) {
				(void)mgmt_txn_send_commit_cfg_reply(
					txn, MGMTD_INTERNAL_ERROR,
					"Could not send CFG_APPLY_REQ to backend adapter");
				return -1;
			}
			cmtcfg_req->cmt_stats->last_num_apply_reqs++;

			UNSET_FLAG(adapter->flags,
				   MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED);
		}
	}

	txn->commit_cfg_req->req.commit_cfg.next_phase =
		MGMTD_COMMIT_PHASE_TXN_DELETE;

	/*
	 * Dont move the commit to next phase yet. Wait for all VALIDATE_REPLIES
	 * to come back.
	 */

	return 0;
}

static void mgmt_txn_process_commit_cfg(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);

	MGMTD_TXN_DBG("Processing COMMIT_CONFIG for txn-id: %" PRIu64
		      " session-id: %" PRIu64 " Phase(Current:'%s', Next: '%s')",
		      txn->txn_id, txn->session_id,
		      mgmt_txn_commit_phase_str(txn, true),
		      mgmt_txn_commit_phase_str(txn, false));

	assert(txn->commit_cfg_req);
	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	switch (cmtcfg_req->curr_phase) {
	case MGMTD_COMMIT_PHASE_PREPARE_CFG:
		mgmt_txn_prepare_config(txn);
		break;
	case MGMTD_COMMIT_PHASE_TXN_CREATE:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->txn_create_start,
				     NULL);
		/*
		 * Send TXN_CREATE_REQ to all Backend now.
		 */
		mgmt_txn_send_be_txn_create(txn);
		break;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->send_cfg_start,
				     NULL);
			/*
			 * All CFGDATA_CREATE_REQ should have been sent to
			 * Backend by now.
			 */
#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
		assert(cmtcfg_req->next_phase == MGMTD_COMMIT_PHASE_APPLY_CFG);
		MGMTD_TXN_DBG("txn-id: %" PRIu64 " session-id: %" PRIu64
			      " trigger sending CFG_VALIDATE_REQ to all backend clients",
			      txn->txn_id, txn->session_id);
#else  /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
		assert(cmtcfg_req->next_phase == MGMTD_COMMIT_PHASE_APPLY_CFG);
		MGMTD_TXN_DBG("txn-id: %" PRIu64 " session-id: %" PRIu64
			      " trigger sending CFG_APPLY_REQ to all backend clients",
			      txn->txn_id, txn->session_id);
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
		break;
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_start,
				     NULL);
		/*
		 * We should have received successful CFG_VALIDATE_REPLY from
		 * all concerned Backend Clients by now. Send out the
		 * CFG_APPLY_REQs now.
		 */
		mgmt_txn_send_be_cfg_apply(txn);
		break;
	case MGMTD_COMMIT_PHASE_TXN_DELETE:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->txn_del_start,
				     NULL);
		/*
		 * We would have sent TXN_DELETE_REQ to all backend by now.
		 * Send a successful CONFIG_COMMIT_REPLY back to front-end.
		 * NOTE: This should also trigger DS merge/unlock and Txn
		 * cleanup. Please see mgmt_fe_send_commit_cfg_reply() for
		 * more details.
		 */
		EVENT_OFF(txn->comm_cfg_timeout);
		mgmt_txn_send_commit_cfg_reply(txn, MGMTD_SUCCESS, NULL);
		break;
	case MGMTD_COMMIT_PHASE_MAX:
		break;
	}

	MGMTD_TXN_DBG("txn-id:%" PRIu64 " session-id: %" PRIu64
		      " phase updated to (current:'%s', next: '%s')",
		      txn->txn_id, txn->session_id,
		      mgmt_txn_commit_phase_str(txn, true),
		      mgmt_txn_commit_phase_str(txn, false));
}

static void mgmt_init_get_data_reply(struct mgmt_get_data_reply *get_reply)
{
	size_t indx;

	for (indx = 0; indx < array_size(get_reply->reply_data); indx++)
		get_reply->reply_datap[indx] = &get_reply->reply_data[indx];
}

static void mgmt_reset_get_data_reply(struct mgmt_get_data_reply *get_reply)
{
	int indx;

	for (indx = 0; indx < get_reply->num_reply; indx++) {
		if (get_reply->reply_xpathp[indx]) {
			free(get_reply->reply_xpathp[indx]);
			get_reply->reply_xpathp[indx] = 0;
		}
		if (get_reply->reply_data[indx].xpath) {
			zlog_debug("%s free xpath %p", __func__,
				   get_reply->reply_data[indx].xpath);
			free(get_reply->reply_data[indx].xpath);
			get_reply->reply_data[indx].xpath = 0;
		}
	}

	get_reply->num_reply = 0;
	memset(&get_reply->data_reply, 0, sizeof(get_reply->data_reply));
	memset(&get_reply->reply_data, 0, sizeof(get_reply->reply_data));
	memset(&get_reply->reply_datap, 0, sizeof(get_reply->reply_datap));

	memset(&get_reply->reply_value, 0, sizeof(get_reply->reply_value));

	mgmt_init_get_data_reply(get_reply);
}

static void mgmt_reset_get_data_reply_buf(struct mgmt_get_data_req *get_data)
{
	if (get_data->reply)
		mgmt_reset_get_data_reply(get_data->reply);
}

static void mgmt_txn_send_getcfg_reply_data(struct mgmt_txn_req *txn_req,
					    struct mgmt_get_data_req *get_req)
{
	struct mgmt_get_data_reply *get_reply;
	Mgmtd__YangDataReply *data_reply;

	get_reply = get_req->reply;
	if (!get_reply)
		return;

	data_reply = &get_reply->data_reply;
	mgmt_yang_data_reply_init(data_reply);
	data_reply->n_data = get_reply->num_reply;
	data_reply->data = get_reply->reply_datap;
	data_reply->next_indx = (!get_reply->last_batch ? get_req->total_reply
							: -1);

	MGMTD_TXN_DBG("Sending %zu Get-Config/Data replies next-index:%" PRId64,
		      data_reply->n_data, data_reply->next_indx);

	switch (txn_req->req_event) {
	case MGMTD_TXN_PROC_GETCFG:
		if (mgmt_fe_send_get_reply(txn_req->txn->session_id,
					   txn_req->txn->txn_id, get_req->ds_id,
					   txn_req->req_id, MGMTD_SUCCESS,
					   data_reply, NULL) != 0) {
			MGMTD_TXN_ERR("Failed to send GET-CONFIG-REPLY txn-id: %" PRIu64
				      " session-id: %" PRIu64
				      " req-id: %" PRIu64,
				      txn_req->txn->txn_id,
				      txn_req->txn->session_id, txn_req->req_id);
		}
		break;
	case MGMTD_TXN_PROC_GETDATA:
		if (mgmt_fe_send_get_reply(txn_req->txn->session_id,
					   txn_req->txn->txn_id, get_req->ds_id,
					   txn_req->req_id, MGMTD_SUCCESS,
					   data_reply, NULL) != 0) {
			MGMTD_TXN_ERR("Failed to send GET-DATA-REPLY txn-id: %" PRIu64
				      " session-id: %" PRIu64
				      " req-id: %" PRIu64,
				      txn_req->txn->txn_id,
				      txn_req->txn->session_id, txn_req->req_id);
		}
		break;
	case MGMTD_TXN_PROC_SETCFG:
	case MGMTD_TXN_PROC_COMMITCFG:
	case MGMTD_TXN_PROC_GETTREE:
	case MGMTD_TXN_GETTREE_TIMEOUT:
	case MGMTD_TXN_COMMITCFG_TIMEOUT:
	case MGMTD_TXN_CLEANUP:
		MGMTD_TXN_ERR("Invalid Txn-Req-Event %u", txn_req->req_event);
		break;
	}

	/*
	 * Reset reply buffer for next reply.
	 */
	mgmt_reset_get_data_reply_buf(get_req);
}

static void txn_iter_get_config_data_cb(const char *xpath, struct lyd_node *node,
					struct nb_node *nb_node, void *ctx)
{
	struct mgmt_txn_req *txn_req;
	struct mgmt_get_data_req *get_req;
	struct mgmt_get_data_reply *get_reply;
	Mgmtd__YangData *data;
	Mgmtd__YangDataValue *data_value;

	txn_req = (struct mgmt_txn_req *)ctx;
	if (!txn_req)
		return;

	if (!(node->schema->nodetype & LYD_NODE_TERM))
		return;

	assert(txn_req->req_event == MGMTD_TXN_PROC_GETCFG ||
	       txn_req->req_event == MGMTD_TXN_PROC_GETDATA);

	get_req = txn_req->req.get_data;
	assert(get_req);
	get_reply = get_req->reply;
	data = &get_reply->reply_data[get_reply->num_reply];
	data_value = &get_reply->reply_value[get_reply->num_reply];

	mgmt_yang_data_init(data);
	data->xpath = strdup(xpath);
	mgmt_yang_data_value_init(data_value);
	data_value->value_case = MGMTD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
	data_value->encoded_str_val = (char *)lyd_get_value(node);
	data->value = data_value;

	get_reply->num_reply++;
	get_req->total_reply++;
	MGMTD_TXN_DBG(" [%d] XPATH: '%s', Value: '%s'", get_req->total_reply,
		      data->xpath, data_value->encoded_str_val);

	if (get_reply->num_reply == MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH)
		mgmt_txn_send_getcfg_reply_data(txn_req, get_req);
}

static int mgmt_txn_get_config(struct mgmt_txn_ctx *txn,
			       struct mgmt_txn_req *txn_req,
			       struct nb_config *root)
{
	int indx;
	struct mgmt_get_data_req *get_data;
	struct mgmt_get_data_reply *get_reply;

	get_data = txn_req->req.get_data;

	if (!get_data->reply) {
		get_data->reply = XCALLOC(MTYPE_MGMTD_TXN_GETDATA_REPLY,
					  sizeof(struct mgmt_get_data_reply));
		if (!get_data->reply) {
			mgmt_fe_send_get_reply(
				txn->session_id, txn->txn_id, get_data->ds_id,
				txn_req->req_id, MGMTD_INTERNAL_ERROR, NULL,
				"Internal error: Unable to allocate reply buffers!");
			goto mgmt_txn_get_config_failed;
		}
	}

	/*
	 * Read data contents from the DS and respond back directly.
	 * No need to go to backend for getting data.
	 */
	get_reply = get_data->reply;
	for (indx = 0; indx < get_data->num_xpaths; indx++) {
		MGMTD_TXN_DBG("Trying to get all data under '%s'",
			      get_data->xpaths[indx]);
		mgmt_init_get_data_reply(get_reply);
		/*
		 * mgmt_ds_iter_data works on path prefixes, but the user may
		 * want to also use an xpath regexp we need to add this
		 * functionality.
		 */
		if (mgmt_ds_iter_data(get_data->ds_id, root,
				      get_data->xpaths[indx],
				      txn_iter_get_config_data_cb,
				      (void *)txn_req) == -1) {
			MGMTD_TXN_DBG("Invalid Xpath '%s",
				      get_data->xpaths[indx]);
			mgmt_fe_send_get_reply(txn->session_id, txn->txn_id,
					       get_data->ds_id, txn_req->req_id,
					       MGMTD_INTERNAL_ERROR, NULL,
					       "Invalid xpath");
			goto mgmt_txn_get_config_failed;
		}
		MGMTD_TXN_DBG("Got %d remaining data-replies for xpath '%s'",
			      get_reply->num_reply, get_data->xpaths[indx]);
		get_reply->last_batch = true;
		mgmt_txn_send_getcfg_reply_data(txn_req, get_data);
	}

mgmt_txn_get_config_failed:

	/*
	 * Delete the txn request. It will also remove it from request
	 * list.
	 */
	mgmt_txn_req_free(&txn_req);

	return 0;
}

static void mgmt_txn_process_get_cfg(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct nb_config *cfg_root;
	int num_processed = 0;
	bool error;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);

	MGMTD_TXN_DBG("Processing %zu GET_CONFIG requests txn-id: %" PRIu64
		      " session-id: %" PRIu64,
		      mgmt_txn_reqs_count(&txn->get_cfg_reqs), txn->txn_id,
		      txn->session_id);

	FOREACH_TXN_REQ_IN_LIST (&txn->get_cfg_reqs, txn_req) {
		error = false;
		assert(txn_req->req_event == MGMTD_TXN_PROC_GETCFG);
		cfg_root = txn_req->req.get_data->cfg_root;
		assert(cfg_root);

		if (mgmt_txn_get_config(txn, txn_req, cfg_root) != 0) {
			MGMTD_TXN_ERR("Unable to retrieve config from DS %d txn-id: %" PRIu64
				      " session-id: %" PRIu64
				      " req-id: %" PRIu64,
				      txn_req->req.get_data->ds_id, txn->txn_id,
				      txn->session_id, txn_req->req_id);
			error = true;
		}

		if (error) {
			/*
			 * Delete the txn request.
			 * Note: The following will remove it from the list
			 * as well.
			 */
			mgmt_txn_req_free(&txn_req);
		}

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */
		num_processed++;
		if (num_processed == MGMTD_TXN_MAX_NUM_GETCFG_PROC)
			break;
	}

	if (mgmt_txn_reqs_count(&txn->get_cfg_reqs)) {
		MGMTD_TXN_DBG("Processed maximum number of Get-Config requests (%d/%d). Rescheduling for rest.",
			      num_processed, MGMTD_TXN_MAX_NUM_GETCFG_PROC);
		mgmt_txn_register_event(txn, MGMTD_TXN_PROC_GETCFG);
	}
}

static void mgmt_txn_process_get_data(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	int num_processed = 0;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);

	MGMTD_TXN_DBG("Processing %zu GET_DATA requests txn-id: %" PRIu64
		      " session-id: %" PRIu64,
		      mgmt_txn_reqs_count(&txn->get_data_reqs), txn->txn_id,
		      txn->session_id);

	FOREACH_TXN_REQ_IN_LIST (&txn->get_data_reqs, txn_req) {
		assert(txn_req->req_event == MGMTD_TXN_PROC_GETDATA);

		/*
		 * TODO: Trigger GET procedures for Backend
		 * For now return back error.
		 */
		mgmt_fe_send_get_reply(txn->session_id, txn->txn_id,
				       txn_req->req.get_data->ds_id,
				       txn_req->req_id, MGMTD_INTERNAL_ERROR,
				       NULL, "GET-DATA is not supported yet!");
		/*
		 * Delete the txn request.
		 * Note: The following will remove it from the list
		 * as well.
		 */
		mgmt_txn_req_free(&txn_req);

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */
		num_processed++;
		if (num_processed == MGMTD_TXN_MAX_NUM_GETDATA_PROC)
			break;
	}

	if (mgmt_txn_reqs_count(&txn->get_data_reqs)) {
		MGMTD_TXN_DBG("Processed maximum number of Get-Data requests (%d/%d). Rescheduling for rest.",
			      num_processed, MGMTD_TXN_MAX_NUM_GETDATA_PROC);
		mgmt_txn_register_event(txn, MGMTD_TXN_PROC_GETDATA);
	}
}

static struct mgmt_txn_ctx *
mgmt_fe_find_txn_by_session_id(struct mgmt_master *cm, uint64_t session_id,
			       enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn;

	FOREACH_TXN_IN_LIST (cm, txn) {
		if (txn->session_id == session_id && txn->type == type)
			return txn;
	}

	return NULL;
}

static struct mgmt_txn_ctx *mgmt_txn_create_new(uint64_t session_id,
						enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn = NULL;

	/*
	 * For 'CONFIG' transaction check if one is already created
	 * or not. TODO: figure out what code counts on this and fix it.
	 */
	if (type == MGMTD_TXN_TYPE_CONFIG && mgmt_txn_mm->cfg_txn) {
		if (mgmt_config_txn_in_progress() == session_id)
			txn = mgmt_txn_mm->cfg_txn;
		goto mgmt_create_txn_done;
	}

	txn = mgmt_fe_find_txn_by_session_id(mgmt_txn_mm, session_id, type);
	if (!txn) {
		txn = XCALLOC(MTYPE_MGMTD_TXN, sizeof(struct mgmt_txn_ctx));
		assert(txn);

		txn->session_id = session_id;
		txn->type = type;
		mgmt_txns_add_tail(&mgmt_txn_mm->txn_list, txn);
		/* TODO: why do we need N lists for one transaction */
		mgmt_txn_reqs_init(&txn->set_cfg_reqs);
		mgmt_txn_reqs_init(&txn->get_cfg_reqs);
		mgmt_txn_reqs_init(&txn->get_data_reqs);
		mgmt_txn_reqs_init(&txn->pending_get_datas);
		mgmt_txn_reqs_init(&txn->get_tree_reqs);
		txn->commit_cfg_req = NULL;
		txn->refcount = 0;
		if (!mgmt_txn_mm->next_txn_id)
			mgmt_txn_mm->next_txn_id++;
		txn->txn_id = mgmt_txn_mm->next_txn_id++;
		hash_get(mgmt_txn_mm->txn_hash, txn, hash_alloc_intern);

		MGMTD_TXN_DBG("Added new '%s' txn-id: %" PRIu64,
			      mgmt_txn_type2str(type), txn->txn_id);

		if (type == MGMTD_TXN_TYPE_CONFIG)
			mgmt_txn_mm->cfg_txn = txn;

		MGMTD_TXN_LOCK(txn);
	}

mgmt_create_txn_done:
	return txn;
}

static void mgmt_txn_delete(struct mgmt_txn_ctx **txn)
{
	MGMTD_TXN_UNLOCK(txn);
}

static unsigned int mgmt_txn_hash_key(const void *data)
{
	const struct mgmt_txn_ctx *txn = data;

	return jhash2((uint32_t *)&txn->txn_id,
		      sizeof(txn->txn_id) / sizeof(uint32_t), 0);
}

static bool mgmt_txn_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_txn_ctx *txn1 = d1;
	const struct mgmt_txn_ctx *txn2 = d2;

	return (txn1->txn_id == txn2->txn_id);
}

static void mgmt_txn_hash_free(void *data)
{
	struct mgmt_txn_ctx *txn = data;

	mgmt_txn_delete(&txn);
}

static void mgmt_txn_hash_init(void)
{
	if (!mgmt_txn_mm || mgmt_txn_mm->txn_hash)
		return;

	mgmt_txn_mm->txn_hash = hash_create(mgmt_txn_hash_key, mgmt_txn_hash_cmp,
					    "MGMT Transactions");
}

static void mgmt_txn_hash_destroy(void)
{
	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	hash_clean(mgmt_txn_mm->txn_hash, mgmt_txn_hash_free);
	hash_free(mgmt_txn_mm->txn_hash);
	mgmt_txn_mm->txn_hash = NULL;
}

static inline struct mgmt_txn_ctx *mgmt_txn_id2ctx(uint64_t txn_id)
{
	struct mgmt_txn_ctx key = { 0 };
	struct mgmt_txn_ctx *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return NULL;

	key.txn_id = txn_id;
	txn = hash_lookup(mgmt_txn_mm->txn_hash, &key);

	return txn;
}

uint64_t mgmt_txn_get_session_id(uint64_t txn_id)
{
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);

	return txn ? txn->session_id : MGMTD_SESSION_ID_NONE;
}

static void mgmt_txn_lock(struct mgmt_txn_ctx *txn, const char *file, int line)
{
	txn->refcount++;
	MGMTD_TXN_DBG("%s:%d --> Lock %s txn-id: %" PRIu64 " refcnt: %d", file,
		      line, mgmt_txn_type2str(txn->type), txn->txn_id,
		      txn->refcount);
}

static void mgmt_txn_unlock(struct mgmt_txn_ctx **txn, const char *file,
			    int line)
{
	assert(*txn && (*txn)->refcount);

	(*txn)->refcount--;
	MGMTD_TXN_DBG("%s:%d --> Unlock %s txn-id: %" PRIu64 " refcnt: %d",
		      file, line, mgmt_txn_type2str((*txn)->type),
		      (*txn)->txn_id, (*txn)->refcount);
	if (!(*txn)->refcount) {
		if ((*txn)->type == MGMTD_TXN_TYPE_CONFIG)
			if (mgmt_txn_mm->cfg_txn == *txn)
				mgmt_txn_mm->cfg_txn = NULL;
		EVENT_OFF((*txn)->proc_get_cfg);
		EVENT_OFF((*txn)->proc_get_data);
		EVENT_OFF((*txn)->proc_comm_cfg);
		EVENT_OFF((*txn)->comm_cfg_timeout);
		EVENT_OFF((*txn)->get_tree_timeout);
		hash_release(mgmt_txn_mm->txn_hash, *txn);
		mgmt_txns_del(&mgmt_txn_mm->txn_list, *txn);

		MGMTD_TXN_DBG("Deleted %s txn-id: %" PRIu64
			      " session-id: %" PRIu64,
			      mgmt_txn_type2str((*txn)->type), (*txn)->txn_id,
			      (*txn)->session_id);

		XFREE(MTYPE_MGMTD_TXN, *txn);
	}

	*txn = NULL;
}

static void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn)
{
	/* TODO: Any other cleanup applicable */

	mgmt_txn_delete(txn);
}

static void mgmt_txn_cleanup_all_txns(void)
{
	struct mgmt_txn_ctx *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn)
		mgmt_txn_cleanup_txn(&txn);
}

static void mgmt_txn_cleanup(struct event *thread)
{
	struct mgmt_txn_ctx *txn;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(thread);
	assert(txn);

	mgmt_txn_cleanup_txn(&txn);
}

static void mgmt_txn_register_event(struct mgmt_txn_ctx *txn,
				    enum mgmt_txn_event event)
{
	struct timeval tv = { .tv_sec = 0,
			      .tv_usec = MGMTD_TXN_PROC_DELAY_USEC };

	assert(mgmt_txn_mm && mgmt_txn_tm);

	switch (event) {
	case MGMTD_TXN_PROC_SETCFG:
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_process_set_cfg, txn,
				   &tv, &txn->proc_set_cfg);
		break;
	case MGMTD_TXN_PROC_COMMITCFG:
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_process_commit_cfg,
				   txn, &tv, &txn->proc_comm_cfg);
		break;
	case MGMTD_TXN_PROC_GETCFG:
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_process_get_cfg, txn,
				   &tv, &txn->proc_get_cfg);
		break;
	case MGMTD_TXN_PROC_GETDATA:
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_process_get_data, txn,
				   &tv, &txn->proc_get_data);
		break;
	case MGMTD_TXN_COMMITCFG_TIMEOUT:
		event_add_timer(mgmt_txn_tm, mgmt_txn_cfg_commit_timedout, txn,
				MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC,
				&txn->comm_cfg_timeout);
		break;
	case MGMTD_TXN_GETTREE_TIMEOUT:
		event_add_timer(mgmt_txn_tm, txn_get_tree_timeout, txn,
				MGMTD_TXN_GET_TREE_MAX_DELAY_SEC,
				&txn->get_tree_timeout);
		break;
	case MGMTD_TXN_CLEANUP:
		tv.tv_usec = MGMTD_TXN_CLEANUP_DELAY_USEC;
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_cleanup, txn, &tv,
				   &txn->clnup);
		break;
	case MGMTD_TXN_PROC_GETTREE:
		assert(!"code bug do not register this event");
		break;
	}
}

int mgmt_txn_init(struct mgmt_master *mm, struct event_loop *tm)
{
	if (mgmt_txn_mm || mgmt_txn_tm)
		assert(!"MGMTD TXN: Call txn_init() only once");

	mgmt_txn_mm = mm;
	mgmt_txn_tm = tm;
	mgmt_txns_init(&mm->txn_list);
	mgmt_txn_hash_init();
	assert(!mm->cfg_txn);
	mm->cfg_txn = NULL;

	return 0;
}

void mgmt_txn_destroy(void)
{
	mgmt_txn_cleanup_all_txns();
	mgmt_txn_hash_destroy();
}

uint64_t mgmt_config_txn_in_progress(void)
{
	if (mgmt_txn_mm && mgmt_txn_mm->cfg_txn)
		return mgmt_txn_mm->cfg_txn->session_id;

	return MGMTD_SESSION_ID_NONE;
}

uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn_ctx *txn;

	txn = mgmt_txn_create_new(session_id, type);
	return txn ? txn->txn_id : MGMTD_TXN_ID_NONE;
}

void mgmt_destroy_txn(uint64_t *txn_id)
{
	struct mgmt_txn_ctx *txn;

	txn = mgmt_txn_id2ctx(*txn_id);
	if (!txn)
		return;

	mgmt_txn_delete(&txn);
	*txn_id = MGMTD_TXN_ID_NONE;
}

int mgmt_txn_send_set_config_req(uint64_t txn_id, uint64_t req_id,
				 Mgmtd__DatastoreId ds_id,
				 struct mgmt_ds_ctx *ds_ctx,
				 Mgmtd__YangCfgDataReq **cfg_req,
				 size_t num_req, bool implicit_commit,
				 Mgmtd__DatastoreId dst_ds_id,
				 struct mgmt_ds_ctx *dst_ds_ctx)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	size_t indx;
	uint16_t *num_chgs;
	struct nb_cfg_change *cfg_chg;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	if (implicit_commit && mgmt_txn_reqs_count(&txn->set_cfg_reqs)) {
		MGMTD_TXN_ERR(
			"For implicit commit config only one SETCFG-REQ can be allowed!");
		return -1;
	}

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_SETCFG);
	txn_req->req.set_cfg->ds_id = ds_id;
	txn_req->req.set_cfg->ds_ctx = ds_ctx;
	num_chgs = &txn_req->req.set_cfg->num_cfg_changes;
	for (indx = 0; indx < num_req; indx++) {
		cfg_chg = &txn_req->req.set_cfg->cfg_changes[*num_chgs];

		if (cfg_req[indx]->req_type ==
		    MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA)
			cfg_chg->operation = NB_OP_DESTROY;
		else if (cfg_req[indx]->req_type ==
			 MGMTD__CFG_DATA_REQ_TYPE__SET_DATA)
			cfg_chg->operation =
				mgmt_ds_find_data_node_by_xpath(ds_ctx,
								cfg_req[indx]
									->data
									->xpath)
					? NB_OP_MODIFY
					: NB_OP_CREATE;
		else
			continue;

		MGMTD_TXN_DBG("XPath: '%s', Value: '%s'",
			      cfg_req[indx]->data->xpath,
			      (cfg_req[indx]->data->value &&
					       cfg_req[indx]->data->value->encoded_str_val
				       ? cfg_req[indx]->data->value->encoded_str_val
				       : "NULL"));
		strlcpy(cfg_chg->xpath, cfg_req[indx]->data->xpath,
			sizeof(cfg_chg->xpath));
		cfg_chg->value =
			(cfg_req[indx]->data->value &&
					 cfg_req[indx]->data->value->encoded_str_val
				 ? strdup(cfg_req[indx]
						  ->data->value->encoded_str_val)
				 : NULL);
		if (cfg_chg->value)
			MGMTD_TXN_DBG("Allocated value at %p ==> '%s'",
				      cfg_chg->value, cfg_chg->value);

		(*num_chgs)++;
	}
	txn_req->req.set_cfg->implicit_commit = implicit_commit;
	txn_req->req.set_cfg->dst_ds_id = dst_ds_id;
	txn_req->req.set_cfg->dst_ds_ctx = dst_ds_ctx;
	txn_req->req.set_cfg->setcfg_stats =
		mgmt_fe_get_session_setcfg_stats(txn->session_id);
	mgmt_txn_register_event(txn, MGMTD_TXN_PROC_SETCFG);

	return 0;
}

int mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id,
				    Mgmtd__DatastoreId src_ds_id,
				    struct mgmt_ds_ctx *src_ds_ctx,
				    Mgmtd__DatastoreId dst_ds_id,
				    struct mgmt_ds_ctx *dst_ds_ctx,
				    bool validate_only, bool abort,
				    bool implicit)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	if (txn->commit_cfg_req) {
		MGMTD_TXN_ERR("Commit already in-progress txn-id: %" PRIu64
			      " session-id: %" PRIu64 ". Cannot start another",
			      txn->txn_id, txn->session_id);
		return -1;
	}

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = src_ds_id;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = dst_ds_id;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = validate_only;
	txn_req->req.commit_cfg.abort = abort;
	txn_req->req.commit_cfg.implicit = implicit;
	txn_req->req.commit_cfg.cmt_stats =
		mgmt_fe_get_session_commit_stats(txn->session_id);

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	mgmt_txn_register_event(txn, MGMTD_TXN_PROC_COMMITCFG);
	return 0;
}

int mgmt_txn_notify_be_adapter_conn(struct mgmt_be_client_adapter *adapter,
				    bool connect)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	static struct mgmt_commit_stats dummy_stats;
	struct nb_config_cbs *adapter_cfgs = NULL;

	memset(&dummy_stats, 0, sizeof(dummy_stats));
	if (connect) {
		/* Get config for this single backend client */

		mgmt_be_get_adapter_config(adapter, &adapter_cfgs);
		if (!adapter_cfgs || RB_EMPTY(nb_config_cbs, adapter_cfgs)) {
			SET_FLAG(adapter->flags,
				 MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED);
			return 0;
		}

		/*
		 * Create a CONFIG transaction to push the config changes
		 * provided to the backend client.
		 */
		txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
		if (!txn) {
			MGMTD_TXN_ERR("Failed to create CONFIG Transaction for downloading CONFIGs for client '%s'",
				      adapter->name);
			return -1;
		}

		MGMTD_TXN_DBG("Created initial txn-id: %" PRIu64
			      " for BE client '%s'",
			      txn->txn_id, adapter->name);
		/*
		 * Set the changeset for transaction to commit and trigger the
		 * commit request.
		 */
		txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
		txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_NONE;
		txn_req->req.commit_cfg.src_ds_ctx = 0;
		txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_NONE;
		txn_req->req.commit_cfg.dst_ds_ctx = 0;
		txn_req->req.commit_cfg.validate_only = false;
		txn_req->req.commit_cfg.abort = false;
		txn_req->req.commit_cfg.cmt_stats = &dummy_stats;
		txn_req->req.commit_cfg.cfg_chgs = adapter_cfgs;

		/*
		 * Trigger a COMMIT-CONFIG process.
		 */
		mgmt_txn_register_event(txn, MGMTD_TXN_PROC_COMMITCFG);

	} else {
		/*
		 * Check if any transaction is currently on-going that
		 * involves this backend client. If so, report the transaction
		 * has failed.
		 */
		FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn) {
			/* TODO: update with operational state when that is
			 * completed */
			if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
				cmtcfg_req = txn->commit_cfg_req
						     ? &txn->commit_cfg_req->req
								.commit_cfg
						     : NULL;
				if (cmtcfg_req && IS_IDBIT_SET(cmtcfg_req->clients,
							       adapter->id)) {
					mgmt_txn_send_commit_cfg_reply(
						txn, MGMTD_INTERNAL_ERROR,
						"Backend daemon disconnected while processing commit!");
				}
			}
		}
	}

	return 0;
}

int mgmt_txn_notify_be_txn_reply(uint64_t txn_id, bool create, bool success,
				 struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn || txn->type != MGMTD_TXN_TYPE_CONFIG)
		return -1;

	if (!create && !txn->commit_cfg_req)
		return 0;

	assert(txn->commit_cfg_req);
	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	if (create) {
		if (success) {
			/*
			 * Done with TXN_CREATE. Move the backend client to
			 * next phase.
			 */
			assert(cmtcfg_req->curr_phase ==
			       MGMTD_COMMIT_PHASE_TXN_CREATE);

			/*
			 * Send CFGDATA_CREATE-REQs to the backend immediately.
			 */
			mgmt_txn_send_be_cfg_data(txn, adapter);
		} else {
			mgmt_txn_send_commit_cfg_reply(
				txn, MGMTD_INTERNAL_ERROR,
				"Internal error! Failed to initiate transaction at backend!");
		}
	}

	return 0;
}

int mgmt_txn_notify_be_cfgdata_reply(uint64_t txn_id, bool success,
				     char *error_if_any,
				     struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn || txn->type != MGMTD_TXN_TYPE_CONFIG)
		return -1;

	if (!txn->commit_cfg_req)
		return -1;
	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		MGMTD_TXN_ERR("CFGDATA_CREATE_REQ sent to '%s' failed txn-id: %" PRIu64
			      " err: %s", adapter->name, txn->txn_id,
			      error_if_any ? error_if_any : "None");
		mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INTERNAL_ERROR,
			error_if_any
				? error_if_any
				: "Internal error! Failed to download config data to backend!");
		return 0;
	}

	MGMTD_TXN_DBG("CFGDATA_CREATE_REQ sent to '%s' was successful txn-id: %" PRIu64
		      " err: %s", adapter->name, txn->txn_id,
		      error_if_any ? error_if_any : "None");

	cmtcfg_req->be_phase[adapter->id] = MGMTD_COMMIT_PHASE_APPLY_CFG;

	mgmt_try_move_commit_to_next_phase(txn, cmtcfg_req);

	return 0;
}

int mgmt_txn_notify_be_cfg_apply_reply(uint64_t txn_id, bool success,
				       char *error_if_any,
				       struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn || txn->type != MGMTD_TXN_TYPE_CONFIG || !txn->commit_cfg_req)
		return -1;

	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		MGMTD_TXN_ERR("CFGDATA_APPLY_REQ sent to '%s' failed txn-id: %" PRIu64
			      " err: %s",
			      adapter->name, txn->txn_id,
			      error_if_any ? error_if_any : "None");
		mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INTERNAL_ERROR,
			error_if_any
				? error_if_any
				: "Internal error! Failed to apply config data on backend!");
		return 0;
	}

	cmtcfg_req->be_phase[adapter->id] = MGMTD_COMMIT_PHASE_TXN_DELETE;

	/*
	 * All configuration for the specific backend has been applied.
	 * Send TXN-DELETE to wrap up the transaction for this backend.
	 */
	SET_FLAG(adapter->flags, MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED);
	mgmt_txn_send_be_txn_delete(txn, adapter);

	mgmt_try_move_commit_to_next_phase(txn, cmtcfg_req);
	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_end, NULL);

	return 0;
}

int mgmt_txn_send_get_req(uint64_t txn_id, uint64_t req_id,
			  Mgmtd__DatastoreId ds_id, struct nb_config *cfg_root,
			  Mgmtd__YangGetDataReq **data_req, size_t num_reqs)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	enum mgmt_txn_event req_event;
	size_t indx;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	req_event = cfg_root ? MGMTD_TXN_PROC_GETCFG : MGMTD_TXN_PROC_GETDATA;

	txn_req = mgmt_txn_req_alloc(txn, req_id, req_event);
	txn_req->req.get_data->ds_id = ds_id;
	txn_req->req.get_data->cfg_root = cfg_root;
	for (indx = 0;
	     indx < num_reqs && indx < MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH;
	     indx++) {
		MGMTD_TXN_DBG("XPath: '%s'", data_req[indx]->data->xpath);
		txn_req->req.get_data->xpaths[indx] =
			strdup(data_req[indx]->data->xpath);
		txn_req->req.get_data->num_xpaths++;
	}

	mgmt_txn_register_event(txn, req_event);

	return 0;
}


/**
 * Send get-tree requests to each client indicated in `clients` bitmask, which
 * has registered operational state that matches the given `xpath`
 */
int mgmt_txn_send_get_tree_oper(uint64_t txn_id, uint64_t req_id,
				uint64_t clients, LYD_FORMAT result_type,
				const char *xpath)
{
	struct mgmt_msg_get_tree *msg;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	enum mgmt_be_client_id id;
	size_t mlen = sizeof(*msg) + strlen(xpath) + 1;
	int ret;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	/* If error in this function below here, be sure to free the req */
	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_GETTREE);
	get_tree = txn_req->req.get_tree;
	get_tree->result_type = result_type;
	get_tree->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);

	msg = XCALLOC(MTYPE_MSG_NATIVE_MSG, mlen);
	msg->txn_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_TREE;
	/* Always operate with the binary format in the backend */
	msg->result_type = LYD_LYB;
	strlcpy(msg->xpath, xpath, mlen - sizeof(*msg));

	assert(clients);
	FOREACH_BE_CLIENT_BITS (id, clients) {
		ret = mgmt_be_send_native(id, msg, mlen);
		if (ret) {
			MGMTD_TXN_ERR("Could not send get-tree message to backend client %s",
				      mgmt_be_client_id2name(id));
			continue;
		}

		MGMTD_TXN_DBG("Sent get-tree req to backend client %s",
			      mgmt_be_client_id2name(id));

		/* record that we sent the request to the client */
		get_tree->sent_clients |= (1u << id);
	}

	XFREE(MTYPE_MSG_NATIVE_MSG, msg);

	/* Start timeout timer - pulled out of register event code so we can
	 * pass a different arg
	 */
	event_add_timer(mgmt_txn_tm, txn_get_tree_timeout, txn_req,
			MGMTD_TXN_GET_TREE_MAX_DELAY_SEC,
			&txn->get_tree_timeout);
	return 0;
}

/*
 * Error reply from the backend client.
 */
int mgmt_txn_notify_error(struct mgmt_be_client_adapter *adapter,
			  uint64_t txn_id, uint64_t req_id, int error,
			  const char *errstr)
{
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req_get_tree *get_tree;
	struct mgmt_txn_req *txn_req;

	if (!txn) {
		MGMTD_TXN_ERR("Error reply from %s cannot find txn-id %" PRIu64,
			      adapter->name, txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->get_tree_reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		MGMTD_TXN_ERR("Error reply from %s for txn-id %" PRIu64
			      " cannot find req_id %" PRIu64,
			      adapter->name, txn_id, req_id);
		return -1;
	}

	MGMTD_TXN_ERR("Error reply from %s for txn-id %" PRIu64
		      " req_id %" PRIu64,
		      adapter->name, txn_id, req_id);

	switch (txn_req->req_event) {
	case MGMTD_TXN_PROC_GETTREE:
		get_tree = txn_req->req.get_tree;
		get_tree->recv_clients |= (1u << id);
		get_tree->partial_error = error;

		/* check if done yet */
		if (get_tree->recv_clients != get_tree->sent_clients)
			return 0;
		return txn_get_tree_data_done(txn, txn_req);

	/* non-native message events */
	case MGMTD_TXN_PROC_SETCFG:
	case MGMTD_TXN_PROC_COMMITCFG:
	case MGMTD_TXN_PROC_GETCFG:
	case MGMTD_TXN_PROC_GETDATA:
	case MGMTD_TXN_COMMITCFG_TIMEOUT:
	case MGMTD_TXN_GETTREE_TIMEOUT:
	case MGMTD_TXN_CLEANUP:
	default:
		assert(!"non-native req event in native erorr path");
		return -1;
	}
}

/*
 * Get-tree data from the backend client.
 */
int mgmt_txn_notify_tree_data_reply(struct mgmt_be_client_adapter *adapter,
				    struct mgmt_msg_tree_data *data_msg,
				    size_t msg_len)
{
	uint64_t txn_id = data_msg->txn_id;
	uint64_t req_id = data_msg->req_id;

	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	if (!txn) {
		MGMTD_TXN_ERR("GETTREE reply from %s for a missing txn-id %" PRIu64,
			      adapter->name, txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->get_tree_reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		MGMTD_TXN_ERR("GETTREE reply from %s for txn-id %" PRIu64
			      " missing req_id %" PRIu64,
			      adapter->name, txn_id, req_id);
		return -1;
	}

	get_tree = txn_req->req.get_tree;

	/* store the result */
	err = lyd_parse_data_mem(ly_native_ctx, (const char *)data_msg->result,
				 data_msg->result_type,
				 LYD_PARSE_STRICT | LYD_PARSE_ONLY,
				 0 /*LYD_VALIDATE_OPERATIONAL*/, &tree);
	if (err) {
		MGMTD_TXN_ERR("GETTREE reply from %s for txn-id %" PRIu64
			      " req_id %" PRIu64
			      " error parsing result of type %u",
			      adapter->name, txn_id, req_id,
			      data_msg->result_type);
	}
	if (!err) {
		/* TODO: we could merge ly_errs here if it's not binary */

		if (!get_tree->client_results)
			get_tree->client_results = tree;
		else
			err = lyd_merge_siblings(&get_tree->client_results,
						 tree, LYD_MERGE_DESTRUCT);
		if (err) {
			MGMTD_TXN_ERR("GETTREE reply from %s for txn-id %" PRIu64
				      " req_id %" PRIu64 " error merging result",
				      adapter->name, txn_id, req_id);
		}
	}
	if (!get_tree->partial_error)
		get_tree->partial_error = (data_msg->partial_error
						   ? data_msg->partial_error
						   : (int)err);

	get_tree->recv_clients |= (1u << id);

	/* check if done yet */
	if (get_tree->recv_clients != get_tree->sent_clients)
		return 0;

	return txn_get_tree_data_done(txn, txn_req);
}

void mgmt_txn_status_write(struct vty *vty)
{
	struct mgmt_txn_ctx *txn;

	vty_out(vty, "MGMTD Transactions\n");

	FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn) {
		vty_out(vty, "  Txn: \t\t\t0x%p\n", txn);
		vty_out(vty, "    Txn-Id: \t\t\t%" PRIu64 "\n", txn->txn_id);
		vty_out(vty, "    Session-Id: \t\t%" PRIu64 "\n",
			txn->session_id);
		vty_out(vty, "    Type: \t\t\t%s\n",
			mgmt_txn_type2str(txn->type));
		vty_out(vty, "    Ref-Count: \t\t\t%d\n", txn->refcount);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_txns_count(&mgmt_txn_mm->txn_list));
}

int mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_ds_ctx *src_ds_ctx,
					struct mgmt_ds_ctx *dst_ds_ctx)
{
	static struct nb_config_cbs changes;
	static struct mgmt_commit_stats dummy_stats;

	struct nb_config_cbs *cfg_chgs = NULL;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	memset(&changes, 0, sizeof(changes));
	memset(&dummy_stats, 0, sizeof(dummy_stats));
	/*
	 * This could be the case when the config is directly
	 * loaded onto the candidate DS from a file. Get the
	 * diff from a full comparison of the candidate and
	 * running DSs.
	 */
	nb_config_diff(mgmt_ds_get_nb_config(dst_ds_ctx),
		       mgmt_ds_get_nb_config(src_ds_ctx), &changes);
	cfg_chgs = &changes;

	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		/*
		 * This means there's no changes to commit whatsoever
		 * is the source of the changes in config.
		 */
		return -1;
	}

	/*
	 * Create a CONFIG transaction to push the config changes
	 * provided to the backend client.
	 */
	txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
	if (!txn) {
		MGMTD_TXN_ERR(
			"Failed to create CONFIG Transaction for downloading CONFIGs");
		return -1;
	}

	MGMTD_TXN_DBG("Created rollback txn-id: %" PRIu64, txn->txn_id);

	/*
	 * Set the changeset for transaction to commit and trigger the commit
	 * request.
	 */
	txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_CANDIDATE;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = false;
	txn_req->req.commit_cfg.abort = false;
	txn_req->req.commit_cfg.rollback = true;
	txn_req->req.commit_cfg.cmt_stats = &dummy_stats;
	txn_req->req.commit_cfg.cfg_chgs = cfg_chgs;

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	mgmt_txn_register_event(txn, MGMTD_TXN_PROC_COMMITCFG);
	return 0;
}
