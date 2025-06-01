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

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define MGMTD_TXN_LOCK(txn)   mgmt_txn_lock(txn, __FILE__, __LINE__)
#define MGMTD_TXN_UNLOCK(txn, in_hash_free) mgmt_txn_unlock(txn, in_hash_free, __FILE__, __LINE__)

enum mgmt_txn_req_type {
	MGMTD_TXN_PROC_COMMITCFG = 1,
	MGMTD_TXN_PROC_GETTREE,
	MGMTD_TXN_PROC_RPC,
};

enum mgmt_txn_frr_event {
	MGMTD_TXN_EVENT_COMMITCFG = 1,
	MGMTD_TXN_EVENT_COMMITCFG_TIMEOUT,
};

PREDECL_LIST(mgmt_txn_reqs);

enum mgmt_commit_phase {
	MGMTD_COMMIT_PHASE_PREPARE_CFG = 0,
	MGMTD_COMMIT_PHASE_TXN_CREATE,
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
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		return "APPLY-CFG";
	case MGMTD_COMMIT_PHASE_TXN_DELETE:
		return "DELETE-TXN";
	case MGMTD_COMMIT_PHASE_MAX:
		return "Invalid/Unknown";
	}

	return "Invalid/Unknown";
}

struct mgmt_edit_req {
	char xpath_created[XPATH_MAXLEN];
	bool created;
	bool unlock;
};

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
	uint8_t init : 1;
	uint8_t unlock : 1;

	/* Track commit phases */
	enum mgmt_commit_phase phase;

	enum mgmt_commit_phase be_phase[MGMTD_BE_CLIENT_ID_MAX];

	/*
	 * Additional information when the commit is triggered by native edit
	 * request.
	 */
	struct mgmt_edit_req *edit;

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
	 * Config messages to send to the backends, and their action strings to
	 * add to the message just prior to sending.
	 */
	struct mgmt_msg_cfg_req *cfg_msgs[MGMTD_BE_CLIENT_ID_MAX];
	char *cfg_actions[MGMTD_BE_CLIENT_ID_MAX];
	uint64_t num_cfg_data[MGMTD_BE_CLIENT_ID_MAX];

	struct mgmt_commit_stats *cmt_stats;
};

struct txn_req_get_tree {
	char *xpath;	       /* xpath of tree to get */
	uint64_t sent_clients; /* Bitmask of clients sent req to */
	uint64_t recv_clients; /* Bitmask of clients recv reply from */
	int32_t partial_error; /* an error while gather results */
	uint8_t result_type;   /* LYD_FORMAT for results */
	uint8_t wd_options;    /* LYD_PRINT_WD_* flags for results */
	uint8_t exact;	       /* if exact node is requested */
	uint8_t simple_xpath;  /* if xpath is simple */
	struct lyd_node *client_results; /* result tree from clients */
};

struct txn_req_rpc {
	char *xpath;	       /* xpath of rpc/action to invoke */
	uint64_t sent_clients; /* Bitmask of clients sent req to */
	uint64_t recv_clients; /* Bitmask of clients recv reply from */
	uint8_t result_type;   /* LYD_FORMAT for results */
	char *errstr;	       /* error string */
	struct lyd_node *client_results; /* result tree from clients */
};

struct mgmt_txn_req {
	struct mgmt_txn_ctx *txn;
	enum mgmt_txn_req_type req_type;
	uint64_t req_id;
	union {
		struct txn_req_get_tree *get_tree;
		struct txn_req_rpc *rpc;
		struct mgmt_commit_cfg_req commit_cfg;
	} req;

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

	struct event *proc_comm_cfg;
	struct event *proc_get_tree;
	struct event *comm_cfg_timeout;
	struct event *get_tree_timeout;
	struct event *rpc_timeout;
	struct event *clnup;

	/* List of backend adapters involved in this transaction */
	/* XXX reap this */
	struct mgmt_txn_badapters_head be_adapters;

	int refcount;

	struct mgmt_txns_item list_linkage;

	/* TODO: why do we need unique lists for each type of transaction since
	 * a transaction is of only 1 type?
	 */

	/*
	 * List of pending get-tree requests.
	 */
	struct mgmt_txn_reqs_head get_tree_reqs;
	/*
	 * List of pending rpc requests.
	 */
	struct mgmt_txn_reqs_head rpc_reqs;
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

static inline const char *mgmt_txn_commit_phase_str(struct mgmt_txn_ctx *txn)
{
	if (!txn->commit_cfg_req)
		return "None";

	return mgmt_commit_phase2str(txn->commit_cfg_req->req.commit_cfg.phase);
}

static void mgmt_txn_lock(struct mgmt_txn_ctx *txn, const char *file, int line);
static void mgmt_txn_unlock(struct mgmt_txn_ctx **txn, bool in_hash_free, const char *file,
			    int line);
static int mgmt_txn_send_be_txn_delete(struct mgmt_txn_ctx *txn,
				       struct mgmt_be_client_adapter *adapter);

static struct event_loop *mgmt_txn_tm;
static struct mgmt_master *mgmt_txn_mm;

static void mgmt_txn_register_event(struct mgmt_txn_ctx *txn, enum mgmt_txn_frr_event event);

static void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn);

static struct mgmt_txn_req *mgmt_txn_req_alloc(struct mgmt_txn_ctx *txn, uint64_t req_id,
					       enum mgmt_txn_req_type req_type)
{
	struct mgmt_txn_req *txn_req;

	txn_req = XCALLOC(MTYPE_MGMTD_TXN_REQ, sizeof(struct mgmt_txn_req));
	assert(txn_req);
	txn_req->txn = txn;
	txn_req->req_id = req_id;
	txn_req->req_type = req_type;

	switch (txn_req->req_type) {
	case MGMTD_TXN_PROC_COMMITCFG:
		txn->commit_cfg_req = txn_req;
		_dbg("Added a new COMMITCFG req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);

		txn_req->req.commit_cfg.phase = MGMTD_COMMIT_PHASE_PREPARE_CFG;
		break;
	case MGMTD_TXN_PROC_GETTREE:
		txn_req->req.get_tree = XCALLOC(MTYPE_MGMTD_TXN_GETTREE_REQ,
						sizeof(struct txn_req_get_tree));
		mgmt_txn_reqs_add_tail(&txn->get_tree_reqs, txn_req);
		_dbg("Added a new GETTREE req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_RPC:
		txn_req->req.rpc = XCALLOC(MTYPE_MGMTD_TXN_RPC_REQ,
					   sizeof(struct txn_req_rpc));
		assert(txn_req->req.rpc);
		mgmt_txn_reqs_add_tail(&txn->rpc_reqs, txn_req);
		_dbg("Added a new RPC req-id: %" PRIu64 " txn-id: %" PRIu64 " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	}

	MGMTD_TXN_LOCK(txn);

	return txn_req;
}

static void mgmt_txn_req_free(struct mgmt_txn_req **txn_req)
{
	struct mgmt_txn_reqs_head *req_list = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *ccreq;
	bool cleanup;

	switch ((*txn_req)->req_type) {
	case MGMTD_TXN_PROC_COMMITCFG:
		_dbg("Deleting COMMITCFG req-id: %" PRIu64 " txn-id: %" PRIu64, (*txn_req)->req_id,
		     (*txn_req)->txn->txn_id);

		ccreq = &(*txn_req)->req.commit_cfg;
		cleanup = (ccreq->phase >= MGMTD_COMMIT_PHASE_TXN_CREATE &&
			   ccreq->phase < MGMTD_COMMIT_PHASE_TXN_DELETE);

		XFREE(MTYPE_MGMTD_TXN_REQ, ccreq->edit);

		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			/*
			 * Send TXN_DELETE to cleanup state for this
			 * transaction on backend
			 */

			/*
			 * Delete any config messages and action data
			 */
			mgmt_msg_native_free_msg(ccreq->cfg_msgs[id]);
			darr_free(ccreq->cfg_actions[id]);

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
	case MGMTD_TXN_PROC_GETTREE:
		_dbg("Deleting GETTREE req-id: %" PRIu64 " of txn-id: %" PRIu64, (*txn_req)->req_id,
		     (*txn_req)->txn->txn_id);
		req_list = &(*txn_req)->txn->get_tree_reqs;
		lyd_free_all((*txn_req)->req.get_tree->client_results);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.get_tree->xpath);
		XFREE(MTYPE_MGMTD_TXN_GETTREE_REQ, (*txn_req)->req.get_tree);
		break;
	case MGMTD_TXN_PROC_RPC:
		_dbg("Deleting RPC req-id: %" PRIu64 " txn-id: %" PRIu64, (*txn_req)->req_id,
		     (*txn_req)->txn->txn_id);
		req_list = &(*txn_req)->txn->rpc_reqs;
		lyd_free_all((*txn_req)->req.rpc->client_results);
		XFREE(MTYPE_MGMTD_ERR, (*txn_req)->req.rpc->errstr);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.rpc->xpath);
		XFREE(MTYPE_MGMTD_TXN_RPC_REQ, (*txn_req)->req.rpc);
		break;
	}

	if (req_list) {
		mgmt_txn_reqs_del(req_list, *txn_req);
		_dbg("Removed req-id: %" PRIu64 " from request-list (left:%zu)", (*txn_req)->req_id,
		     mgmt_txn_reqs_count(req_list));
	}

	MGMTD_TXN_UNLOCK(&(*txn_req)->txn, false);
	XFREE(MTYPE_MGMTD_TXN_REQ, (*txn_req));
	*txn_req = NULL;
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
	if (!txn->commit_cfg_req->req.commit_cfg.edit &&
	    !txn->commit_cfg_req->req.commit_cfg.implicit && txn->session_id &&
	    !txn->commit_cfg_req->req.commit_cfg.rollback &&
	    mgmt_fe_send_commit_cfg_reply(txn->session_id, txn->txn_id,
					  txn->commit_cfg_req->req.commit_cfg.src_ds_id,
					  txn->commit_cfg_req->req.commit_cfg.dst_ds_id,
					  txn->commit_cfg_req->req_id,
					  txn->commit_cfg_req->req.commit_cfg.validate_only,
					  txn->commit_cfg_req->req.commit_cfg.unlock, result,
					  error_if_any) != 0) {
		_log_err("Failed to send COMMIT-CONFIG-REPLY txn-id: %" PRIu64
			 " session-id: %" PRIu64,
			 txn->txn_id, txn->session_id);
	}

	if (txn->commit_cfg_req->req.commit_cfg.edit &&
	    mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id,
					    txn->commit_cfg_req->req_id,
					    txn->commit_cfg_req->req.commit_cfg
						    .edit->unlock,
					    true,
					    txn->commit_cfg_req->req.commit_cfg
						    .edit->created,
					    txn->commit_cfg_req->req.commit_cfg
						    .edit->xpath_created,
					    success ? 0 : -1,
					    error_if_any) != 0) {
		_log_err("Failed to send EDIT-REPLY txn-id: %" PRIu64 " session-id: %" PRIu64,
			 txn->txn_id, txn->session_id);
	}

	if (success) {
		/* Stop the commit-timeout timer */
		/* XXX why only on success? */
		event_cancel(&txn->comm_cfg_timeout);

		create_cmt_info_rec =
			(result != MGMTD_NO_CFG_CHANGES &&
			 !txn->commit_cfg_req->req.commit_cfg.rollback);

		/*
		 * Successful commit: Copy Src DS to Dst DS if and only if
		 * this was not a validate-only or abort request.
		 */
		if ((txn->session_id &&
		     !txn->commit_cfg_req->req.commit_cfg.validate_only &&
		     !txn->commit_cfg_req->req.commit_cfg.abort) ||
		    txn->commit_cfg_req->req.commit_cfg.rollback) {
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg.src_ds_ctx,
					 create_cmt_info_rec);
		}

		/*
		 * Restore Src DS back to Dest DS only through a commit abort
		 * request.
		 */
		if (txn->session_id && txn->commit_cfg_req->req.commit_cfg.abort)
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg.src_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx, false);
	} else {
		/*
		 * The commit has failied. For implicit commit requests restore
		 * back the contents of the candidate DS. For non-implicit
		 * commit we want to allow the user to re-commit on the changes
		 * (whether further modified or not).
		 */
		if (txn->commit_cfg_req->req.commit_cfg.implicit ||
		    txn->commit_cfg_req->req.commit_cfg.unlock)
			mgmt_ds_copy_dss(txn->commit_cfg_req->req.commit_cfg.src_ds_ctx,
					 txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx, false);
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

	if (txn->commit_cfg_req->req.commit_cfg.init) {
		/*
		 * This is the backend init request.
		 * We need to unlock the running datastore.
		 */
		mgmt_ds_unlock(txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx);
	}

	txn->commit_cfg_req->req.commit_cfg.cmt_stats = NULL;
	mgmt_txn_req_free(&txn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!txn->session_id)
		mgmt_txn_cleanup_txn(&txn);

	return 0;
}

static int
mgmt_try_move_commit_to_next_phase(struct mgmt_txn_ctx *txn,
				   struct mgmt_commit_cfg_req *cmtcfg_req)
{
	enum mgmt_be_client_id id;

	_dbg("txn-id: %" PRIu64 ", Phase '%s'", txn->txn_id, mgmt_txn_commit_phase_str(txn));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id) &&
		    cmtcfg_req->be_phase[id] == cmtcfg_req->phase) {
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

	/*
	 * If we are here, it means all the clients has moved to next phase.
	 * So we can move the whole commit to next phase.
	 */
	cmtcfg_req->phase++;

	_dbg("Move entire txn-id: %" PRIu64 " to phase '%s'", txn->txn_id,
	     mgmt_txn_commit_phase_str(txn));

	mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG);

	return 0;
}

/*
 * This is the real workhorse
 */
static int mgmt_txn_create_config_msgs(struct mgmt_txn_req *txn_req, struct nb_config_cbs *changes)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	char *xpath = NULL, *value = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	int num_chgs = 0;
	uint64_t clients, chg_clients;
	char op;

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

		_dbg("XPATH: %s, Value: '%s'", xpath, value ? value : "NIL");

		clients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		if (!clients) {
			_dbg("No backends interested in xpath: %s", xpath);
			continue;
		}

		chg_clients = 0;
		FOREACH_BE_CLIENT_BITS (id, clients) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (!adapter)
				continue;

			chg_clients |= (1ull << id);

			if (!cmtcfg_req->cfg_msgs[id]) {
				/* Allocate a new config message */
				struct mgmt_msg_cfg_req *msg;

				msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_req, 0,
								MTYPE_MSG_NATIVE_CFG_REQ);
				msg->code = MGMT_MSG_CODE_CFG_REQ;
				msg->refer_id = txn_req->txn->txn_id;
				msg->req_id = txn_req->req_id;
				cmtcfg_req->cfg_msgs[id] = msg;
			}

			/*
			 * On the backend, we don't really care if it's CREATE
			 * or MODIFY, because the existence was already checked
			 * on the frontend. Therefore we use SET for both.
			 */
			op = chg->cb.operation == NB_CB_DESTROY ? 'd' : 'm';
			darr_push(cmtcfg_req->cfg_actions[id], op);

			mgmt_msg_native_add_str(cmtcfg_req->cfg_msgs[id], xpath);
			if (op == 'm')
				mgmt_msg_native_add_str(cmtcfg_req->cfg_msgs[id], value);
			cmtcfg_req->num_cfg_data[id]++;

			_dbg(" -- %s, batch item: %Lu", adapter->name, cmtcfg_req->num_cfg_data[id]);

			num_chgs++;
		}

		if (!chg_clients)
			_dbg("Daemons interested in XPATH are not currently connected: %s", xpath);

		cmtcfg_req->clients |= chg_clients;

		free(xpath);
	}

	cmtcfg_req->cmt_stats->last_batch_cnt = num_chgs;
	if (!num_chgs) {
		(void)mgmt_txn_send_commit_cfg_reply(txn_req->txn,
						     MGMTD_NO_CFG_CHANGES,
						     "No connected daemons interested in changes");
		return -1;
	}

	/* Move all BE clients to create phase -- XXX go straight to cfg_req */
	FOREACH_MGMTD_BE_CLIENT_ID(id) {
		if (IS_IDBIT_SET(cmtcfg_req->clients, id))
			cmtcfg_req->be_phase[id] =
				MGMTD_COMMIT_PHASE_TXN_CREATE;
	}

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
	 * Iterate over the diffs and create config messages to send to backends.
	 */
	ret = mgmt_txn_create_config_msgs(txn->commit_cfg_req, cfg_chgs);
	if (ret != 0) {
		ret = -1;
		goto mgmt_txn_prepare_config_done;
	}

	/* Move to the Transaction Create Phase */
	txn->commit_cfg_req->req.commit_cfg.phase =
		MGMTD_COMMIT_PHASE_TXN_CREATE;
	mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG);

	/*
	 * Start the COMMIT Timeout Timer to abort Txn if things get stuck at
	 * backend.
	 */
	mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG_TIMEOUT);
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

	/*
	 * Dont move the commit to next phase yet. Wait for the TXN_REPLY to
	 * come back.
	 */

	_dbg("txn-id: %" PRIu64 " session-id: %" PRIu64 " Phase '%s'", txn->txn_id, txn->session_id,
	     mgmt_txn_commit_phase_str(txn));

	return 0;
}

static int mgmt_txn_send_be_cfg_data(struct mgmt_txn_ctx *txn,
				     struct mgmt_be_client_adapter *adapter)
{
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_commit_cfg_req *ccreq;
	int ret;

	assert(txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req);

	ccreq = &txn->commit_cfg_req->req.commit_cfg;
	assert(IS_IDBIT_SET(ccreq->clients, id));

	/* NUL terminate the actions string */
	darr_push(ccreq->cfg_actions[id], 0);

	_dbg("Finished CFG_REQ for '%s' txn-id: %Lu with actions: %s", adapter->name, txn->txn_id,
	     ccreq->cfg_actions[id]);

	/* Add the final action string to the message */
	mgmt_msg_native_add_str(ccreq->cfg_msgs[id], ccreq->cfg_actions[id]);
	darr_free(ccreq->cfg_actions[id]);

	ret = mgmt_be_send_cfgdata_req(adapter, ccreq->cfg_msgs[id]);
	mgmt_msg_native_free_msg(ccreq->cfg_msgs[id]);
	if (ret) {
		(void)mgmt_txn_send_commit_cfg_reply(txn, MGMTD_INTERNAL_ERROR,
						     "Internal Error! Could not send config data to backend!");
		return -1;
	}
	ccreq->cmt_stats->last_num_cfgdata_reqs++;

	/*
	 * We don't advance the phase here, instead that is driven by the
	 * cfg_reply.
	 */

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

	_log_err("Backend timeout txn-id: %" PRIu64 " aborting commit", txn->txn_id);

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
	uint64_t req_id = txn_req->req_id;
	struct lyd_node *result;
	int ret = NB_OK;

	/* cancel timer and send reply onward */
	event_cancel(&txn->get_tree_timeout);

	if (!get_tree->simple_xpath && get_tree->client_results) {
		/*
		 * We have a complex query so Filter results by the xpath query.
		 */
		if (yang_lyd_trim_xpath(&get_tree->client_results,
					txn_req->req.get_tree->xpath))
			ret = NB_ERR;
	}

	result = get_tree->client_results;

	if (ret == NB_OK && result && get_tree->exact)
		result = yang_dnode_get(result, get_tree->xpath);

	if (ret == NB_OK)
		ret = mgmt_fe_adapter_send_tree_data(txn->session_id,
						     txn->txn_id,
						     txn_req->req_id,
						     get_tree->result_type,
						     get_tree->wd_options,
						     result,
						     get_tree->partial_error,
						     false);

	/* we're done with the request */
	mgmt_txn_req_free(&txn_req);

	if (ret) {
		_log_err("Error sending the results of GETTREE for txn-id %" PRIu64
			 " req_id %" PRIu64 " to requested type %u",
			 txn->txn_id, req_id, get_tree->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false,
						errno_from_nb_error(ret),
						"Error converting results of GETTREE");
	}

	return ret;
}

static int txn_rpc_done(struct mgmt_txn_ctx *txn, struct mgmt_txn_req *txn_req)
{
	struct txn_req_rpc *rpc = txn_req->req.rpc;
	uint64_t req_id = txn_req->req_id;

	/* cancel timer and send reply onward */
	event_cancel(&txn->rpc_timeout);

	if (rpc->errstr)
		mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false, -EINVAL,
					  rpc->errstr);
	else if (mgmt_fe_adapter_send_rpc_reply(txn->session_id, txn->txn_id,
						req_id, rpc->result_type,
						rpc->client_results)) {
		_log_err("Error sending the results of RPC for txn-id %" PRIu64 " req_id %" PRIu64
			 " to requested type %u",
			 txn->txn_id, req_id, rpc->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false,
						-EINVAL,
						"Error converting results of RPC");
	}

	/* we're done with the request */
	mgmt_txn_req_free(&txn_req);

	return 0;
}

static void txn_get_tree_timeout(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(thread);
	txn = txn_req->txn;

	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_SHOW);


	_log_err("Backend timeout txn-id: %" PRIu64 " ending get-tree", txn->txn_id);

	/*
	 * Send a get-tree data reply.
	 *
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */

	txn_req->req.get_tree->partial_error = -ETIMEDOUT;
	txn_get_tree_data_done(txn, txn_req);
}

static void txn_rpc_timeout(struct event *thread)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(thread);
	txn = txn_req->txn;

	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_RPC);

	_log_err("Backend timeout txn-id: %" PRIu64 " ending rpc", txn->txn_id);

	/*
	 * Send a get-tree data reply.
	 *
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */

	txn_req->req.rpc->errstr =
		XSTRDUP(MTYPE_MGMTD_ERR, "Operation on the backend timed-out");
	txn_rpc_done(txn, txn_req);
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

	_dbg("Processing COMMIT_CONFIG for txn-id: %" PRIu64 " session-id: %" PRIu64 " Phase '%s'",
	     txn->txn_id, txn->session_id, mgmt_txn_commit_phase_str(txn));

	assert(txn->commit_cfg_req);
	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;
	switch (cmtcfg_req->phase) {
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
		event_cancel(&txn->comm_cfg_timeout);
		mgmt_txn_send_commit_cfg_reply(txn, MGMTD_SUCCESS, NULL);
		break;
	case MGMTD_COMMIT_PHASE_MAX:
		break;
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

	/* Do not allow multiple config transactions */
	if (type == MGMTD_TXN_TYPE_CONFIG && mgmt_config_txn_in_progress())
		return NULL;

	txn = mgmt_fe_find_txn_by_session_id(mgmt_txn_mm, session_id, type);
	if (!txn) {
		txn = XCALLOC(MTYPE_MGMTD_TXN, sizeof(struct mgmt_txn_ctx));
		assert(txn);

		txn->session_id = session_id;
		txn->type = type;
		mgmt_txns_add_tail(&mgmt_txn_mm->txn_list, txn);
		/* TODO: why do we need N lists for one transaction */
		mgmt_txn_reqs_init(&txn->get_tree_reqs);
		mgmt_txn_reqs_init(&txn->rpc_reqs);
		txn->commit_cfg_req = NULL;
		txn->refcount = 0;
		if (!mgmt_txn_mm->next_txn_id)
			mgmt_txn_mm->next_txn_id++;
		txn->txn_id = mgmt_txn_mm->next_txn_id++;
		hash_get(mgmt_txn_mm->txn_hash, txn, hash_alloc_intern);

		_dbg("Added new '%s' txn-id: %" PRIu64, mgmt_txn_type2str(type), txn->txn_id);

		if (type == MGMTD_TXN_TYPE_CONFIG)
			mgmt_txn_mm->cfg_txn = txn;

		MGMTD_TXN_LOCK(txn);
	}

	return txn;
}

static void mgmt_txn_delete(struct mgmt_txn_ctx **txn, bool in_hash_free)
{
	MGMTD_TXN_UNLOCK(txn, in_hash_free);
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

	mgmt_txn_delete(&txn, true);
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
	_dbg("%s:%d --> Lock %s txn-id: %" PRIu64 " refcnt: %d", file, line,
	     mgmt_txn_type2str(txn->type), txn->txn_id, txn->refcount);
}

static void mgmt_txn_unlock(struct mgmt_txn_ctx **txn, bool in_hash_free, const char *file, int line)
{
	assert(*txn && (*txn)->refcount);

	(*txn)->refcount--;
	_dbg("%s:%d --> Unlock %s txn-id: %" PRIu64 " refcnt: %d", file, line,
	     mgmt_txn_type2str((*txn)->type), (*txn)->txn_id, (*txn)->refcount);
	if (!(*txn)->refcount) {
		if ((*txn)->type == MGMTD_TXN_TYPE_CONFIG)
			if (mgmt_txn_mm->cfg_txn == *txn)
				mgmt_txn_mm->cfg_txn = NULL;
		event_cancel(&(*txn)->proc_comm_cfg);
		event_cancel(&(*txn)->comm_cfg_timeout);
		event_cancel(&(*txn)->get_tree_timeout);
		if (!in_hash_free)
			hash_release(mgmt_txn_mm->txn_hash, *txn);

		mgmt_txns_del(&mgmt_txn_mm->txn_list, *txn);

		_dbg("Deleted %s txn-id: %" PRIu64 " session-id: %" PRIu64,
		     mgmt_txn_type2str((*txn)->type), (*txn)->txn_id, (*txn)->session_id);

		XFREE(MTYPE_MGMTD_TXN, *txn);
	}

	*txn = NULL;
}

static void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn)
{
	/* TODO: Any other cleanup applicable */

	mgmt_txn_delete(txn, false);
}

static void mgmt_txn_cleanup_all_txns(void)
{
	struct mgmt_txn_ctx *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn)
		mgmt_txn_cleanup_txn(&txn);
}

static void mgmt_txn_register_event(struct mgmt_txn_ctx *txn, enum mgmt_txn_frr_event event)
{
	struct timeval tv = { .tv_sec = 0,
			      .tv_usec = MGMTD_TXN_PROC_DELAY_USEC };

	assert(mgmt_txn_mm && mgmt_txn_tm);

	switch (event) {
	case MGMTD_TXN_EVENT_COMMITCFG:
		event_add_timer_tv(mgmt_txn_tm, mgmt_txn_process_commit_cfg,
				   txn, &tv, &txn->proc_comm_cfg);
		break;
	case MGMTD_TXN_EVENT_COMMITCFG_TIMEOUT:
		event_add_timer(mgmt_txn_tm, mgmt_txn_cfg_commit_timedout, txn,
				MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC,
				&txn->comm_cfg_timeout);
		break;
	}
}

int mgmt_txn_init(struct mgmt_master *m, struct event_loop *loop)
{
	if (mgmt_txn_mm || mgmt_txn_tm)
		assert(!"MGMTD TXN: Call txn_init() only once");

	mgmt_txn_mm = m;
	mgmt_txn_tm = loop;
	mgmt_txns_init(&m->txn_list);
	mgmt_txn_hash_init();
	assert(!m->cfg_txn);
	m->cfg_txn = NULL;

	return 0;
}

void mgmt_txn_destroy(void)
{
	mgmt_txn_cleanup_all_txns();
	mgmt_txn_hash_destroy();
}

bool mgmt_config_txn_in_progress(void)
{
	if (mgmt_txn_mm && mgmt_txn_mm->cfg_txn)
		return true;

	return false;
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

	mgmt_txn_delete(&txn, false);
	*txn_id = MGMTD_TXN_ID_NONE;
}

int mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id, Mgmtd__DatastoreId src_ds_id,
				    struct mgmt_ds_ctx *src_ds_ctx, Mgmtd__DatastoreId dst_ds_id,
				    struct mgmt_ds_ctx *dst_ds_ctx, bool validate_only, bool abort,
				    bool implicit, bool unlock, struct mgmt_edit_req *edit)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	if (txn->commit_cfg_req) {
		_log_err("Commit already in-progress txn-id: %" PRIu64 " session-id: %" PRIu64
			 ". Cannot start another",
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
	txn_req->req.commit_cfg.unlock = unlock;
	txn_req->req.commit_cfg.edit = edit;
	txn_req->req.commit_cfg.cmt_stats =
		mgmt_fe_get_session_commit_stats(txn->session_id);

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG);
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
	struct mgmt_ds_ctx *ds_ctx;

	memset(&dummy_stats, 0, sizeof(dummy_stats));
	if (connect) {
		ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
		assert(ds_ctx);

		/*
		 * Lock the running datastore to prevent any changes while we
		 * are initializing the backend.
		 */
		if (mgmt_ds_lock(ds_ctx, 0) != 0)
			return -1;

		/* Get config for this single backend client */
		mgmt_be_get_adapter_config(adapter, &adapter_cfgs);
		if (!adapter_cfgs || RB_EMPTY(nb_config_cbs, adapter_cfgs)) {
			SET_FLAG(adapter->flags,
				 MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED);
			mgmt_ds_unlock(ds_ctx);
			return 0;
		}

		/*
		 * Create a CONFIG transaction to push the config changes
		 * provided to the backend client.
		 */
		txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
		if (!txn) {
			_log_err("Failed to create CONFIG Transaction for downloading CONFIGs for client '%s'",
				 adapter->name);
			mgmt_ds_unlock(ds_ctx);
			nb_config_diff_del_changes(adapter_cfgs);
			return -1;
		}

		_dbg("Created initial txn-id: %" PRIu64 " for BE client '%s'", txn->txn_id,
		     adapter->name);
		/*
		 * Set the changeset for transaction to commit and trigger the
		 * commit request.
		 */
		txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
		txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_NONE;
		txn_req->req.commit_cfg.src_ds_ctx = 0;
		txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
		txn_req->req.commit_cfg.dst_ds_ctx = ds_ctx;
		txn_req->req.commit_cfg.validate_only = false;
		txn_req->req.commit_cfg.abort = false;
		txn_req->req.commit_cfg.init = true;
		txn_req->req.commit_cfg.cmt_stats = &dummy_stats;
		txn_req->req.commit_cfg.cfg_chgs = adapter_cfgs;

		/*
		 * Trigger a COMMIT-CONFIG process.
		 */
		mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG);

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
			assert(cmtcfg_req->phase ==
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

int mgmt_txn_notify_be_cfg_reply(uint64_t txn_id, bool success, const char *error_if_any,
				 struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn) {
		_log_err("CFG_REPLY from '%s' failed no TXN for txn-id: %Lu", adapter->name, txn_id);
		return -1;
	}
	if (txn->type != MGMTD_TXN_TYPE_CONFIG) {
		_log_err("CFG_REPLY from '%s' failed wrong txn TYPE %u for txn-id: %Lu",
			 adapter->name, txn->type, txn_id);
		return -1;
	}

	if (!txn->commit_cfg_req) {
		_log_err("CFG_REPLY from '%s' failed no COMMITCFG_REQ for txn-id: %Lu",
			 adapter->name, txn_id);
		return -1;
	}
	cmtcfg_req = &txn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		_log_err("CFG_REQ sent to '%s' failed txn-id: %" PRIu64 " err: %s", adapter->name,
			 txn->txn_id, error_if_any ? error_if_any : "None");
		mgmt_txn_send_commit_cfg_reply(
			txn, MGMTD_INTERNAL_ERROR,
			error_if_any ? error_if_any
				     : "Internal error! Failed to download config data to backend!");
		return 0;
	}

	_dbg("CFG_REQ sent to '%s' was successful txn-id: %" PRIu64 " err: %s", adapter->name,
	     txn->txn_id, error_if_any ? error_if_any : "None");

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
		_log_err("CFGDATA_APPLY_REQ sent to '%s' failed txn-id: %" PRIu64 " err: %s",
			 adapter->name, txn->txn_id, error_if_any ? error_if_any : "None");
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

/**
 * Send get-tree requests to each client indicated in `clients` bitmask, which
 * has registered operational state that matches the given `xpath`
 */
int mgmt_txn_send_get_tree(uint64_t txn_id, uint64_t req_id, uint64_t clients,
			   Mgmtd__DatastoreId ds_id, LYD_FORMAT result_type, uint8_t flags,
			   uint32_t wd_options, bool simple_xpath, struct lyd_node **ylib,
			   const char *xpath)
{
	struct mgmt_msg_get_tree *msg;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	enum mgmt_be_client_id id;
	ssize_t slen = strlen(xpath);
	int ret;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	/* If error in this function below here, be sure to free the req */
	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_GETTREE);
	get_tree = txn_req->req.get_tree;
	get_tree->result_type = result_type;
	get_tree->wd_options = wd_options;
	get_tree->exact = CHECK_FLAG(flags, GET_DATA_FLAG_EXACT);
	get_tree->simple_xpath = simple_xpath;
	get_tree->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);

	if (CHECK_FLAG(flags, GET_DATA_FLAG_CONFIG)) {
		/*
		 * If the requested datastore is operational, get the config
		 * from running.
		 */
		struct mgmt_ds_ctx *ds =
			mgmt_ds_get_ctx_by_id(mm, ds_id == MGMTD_DS_OPERATIONAL
							  ? MGMTD_DS_RUNNING
							  : ds_id);
		struct nb_config *config = mgmt_ds_get_nb_config(ds);

		if (config) {
			struct ly_set *set = NULL;
			LY_ERR err;

			err = lyd_find_xpath(config->dnode, xpath, &set);
			if (err) {
				get_tree->partial_error = err;
				goto state;
			}

			/*
			 * If there's a single result, duplicate the returned
			 * node. If there are multiple results, duplicate the
			 * whole config and mark simple_xpath as false so the
			 * result is trimmed later in txn_get_tree_data_done.
			 */
			if (set->count == 1) {
				err = lyd_dup_single(set->dnodes[0], NULL,
						     LYD_DUP_WITH_PARENTS |
							     LYD_DUP_WITH_FLAGS |
							     LYD_DUP_RECURSIVE,
						     &get_tree->client_results);
				if (!err)
					while (get_tree->client_results->parent)
						get_tree->client_results = lyd_parent(
							get_tree->client_results);
			} else if (set->count > 1) {
				err = lyd_dup_siblings(config->dnode, NULL,
						       LYD_DUP_RECURSIVE |
							       LYD_DUP_WITH_FLAGS,
						       &get_tree->client_results);
				if (!err)
					get_tree->simple_xpath = false;
			}

			if (err)
				get_tree->partial_error = err;

			ly_set_free(set, NULL);
		}
	}
state:
	if (*ylib) {
		LY_ERR err;

		err = lyd_merge_siblings(&get_tree->client_results, *ylib, LYD_MERGE_DESTRUCT);
		*ylib = NULL;
		if (err) {
			_log_err("Error merging yang-library result for txn-id: %Lu", txn_id);
			return NB_ERR;
		}
	}

	/* If we are only getting config, we are done */
	if (!CHECK_FLAG(flags, GET_DATA_FLAG_STATE) ||
	    ds_id != MGMTD_DS_OPERATIONAL || !clients)
		return txn_get_tree_data_done(txn, txn_req);

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_get_tree, slen + 1,
					MTYPE_MSG_NATIVE_GET_TREE);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_TREE;
	/* Always operate with the binary format in the backend */
	msg->result_type = LYD_LYB;
	strlcpy(msg->xpath, xpath, slen + 1);

	assert(clients);
	FOREACH_BE_CLIENT_BITS (id, clients) {
		ret = mgmt_be_send_native(id, msg);
		if (ret) {
			_log_err("Could not send get-tree message to backend client %s",
				 mgmt_be_client_id2name(id));
			continue;
		}

		_dbg("Sent get-tree req to backend client %s", mgmt_be_client_id2name(id));

		/* record that we sent the request to the client */
		get_tree->sent_clients |= (1u << id);
	}

	mgmt_msg_native_free_msg(msg);

	/* Return if we didn't send any messages to backends */
	if (!get_tree->sent_clients)
		return txn_get_tree_data_done(txn, txn_req);

	/* Start timeout timer - pulled out of register event code so we can
	 * pass a different arg
	 */
	event_add_timer(mgmt_txn_tm, txn_get_tree_timeout, txn_req,
			MGMTD_TXN_GET_TREE_MAX_DELAY_SEC,
			&txn->get_tree_timeout);
	return 0;
}

int mgmt_txn_send_edit(uint64_t txn_id, uint64_t req_id,
		       Mgmtd__DatastoreId ds_id, struct mgmt_ds_ctx *ds_ctx,
		       Mgmtd__DatastoreId commit_ds_id,
		       struct mgmt_ds_ctx *commit_ds_ctx, bool unlock,
		       bool commit, LYD_FORMAT request_type, uint8_t flags,
		       uint8_t operation, const char *xpath, const char *data)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_edit_req *edit;
	struct nb_config *nb_config;
	char errstr[BUFSIZ];
	int ret;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	edit = XCALLOC(MTYPE_MGMTD_TXN_REQ, sizeof(struct mgmt_edit_req));

	nb_config = mgmt_ds_get_nb_config(ds_ctx);
	assert(nb_config);

	/* XXX Should we do locking here? */

	ret = nb_candidate_edit_tree(nb_config, operation, request_type, xpath,
				     data, &edit->created, edit->xpath_created,
				     errstr, sizeof(errstr));
	if (ret)
		goto reply;

	if (commit) {
		edit->unlock = unlock;

		mgmt_txn_send_commit_config_req(txn_id, req_id, ds_id, ds_ctx, commit_ds_id,
						commit_ds_ctx, false, false, true, false, edit);
		return 0;
	}
reply:
	mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id, req_id,
					unlock, commit, edit->created,
					edit->xpath_created,
					errno_from_nb_error(ret), errstr);

	XFREE(MTYPE_MGMTD_TXN_REQ, edit);

	return 0;
}

int mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients,
		      LYD_FORMAT result_type, const char *xpath,
		      const char *data, size_t data_len)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_msg_rpc *msg;
	struct txn_req_rpc *rpc;
	uint64_t id;
	int ret;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_RPC);
	rpc = txn_req->req.rpc;
	rpc->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);
	rpc->result_type = result_type;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc, 0,
					MTYPE_MSG_NATIVE_RPC);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_RPC;
	msg->request_type = result_type;

	mgmt_msg_native_xpath_encode(msg, xpath);
	if (data)
		mgmt_msg_native_append(msg, data, data_len);

	assert(clients);
	FOREACH_BE_CLIENT_BITS (id, clients) {
		ret = mgmt_be_send_native(id, msg);
		if (ret) {
			_log_err("Could not send rpc message to backend client %s",
				 mgmt_be_client_id2name(id));
			continue;
		}

		_dbg("Sent rpc req to backend client %s", mgmt_be_client_id2name(id));

		/* record that we sent the request to the client */
		rpc->sent_clients |= (1u << id);
	}

	mgmt_msg_native_free_msg(msg);

	if (!rpc->sent_clients)
		return txn_rpc_done(txn, txn_req);

	event_add_timer(mgmt_txn_tm, txn_rpc_timeout, txn_req,
			MGMTD_TXN_RPC_MAX_DELAY_SEC, &txn->rpc_timeout);

	return 0;
}

int mgmt_txn_send_notify_selectors(uint64_t req_id, uint64_t session_id, uint64_t clients,
				   const char **selectors)
{
	struct mgmt_msg_notify_select *msg;
	char **all_selectors = NULL;
	uint64_t id;
	int ret;
	uint i;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_notify_select, 0,
					MTYPE_MSG_NATIVE_NOTIFY_SELECT);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_NOTIFY_SELECT;
	msg->replace = selectors == NULL;
	msg->get_only = session_id != MGMTD_SESSION_ID_NONE;

	if (selectors == NULL) {
		/* Get selectors for all sessions */
		all_selectors = mgmt_fe_get_all_selectors();
		selectors = (const char **)all_selectors;
	}

	darr_foreach_i (selectors, i)
		mgmt_msg_native_add_str(msg, selectors[i]);

	assert(clients);
	FOREACH_BE_CLIENT_BITS (id, clients) {
		/* make sure the backend is running/connected */
		if (!mgmt_be_get_adapter_by_id(id))
			continue;
		ret = mgmt_be_send_native(id, msg);
		if (ret) {
			_log_err("Could not send notify-select message to backend client %s",
				 mgmt_be_client_id2name(id));
			continue;
		}

		_dbg("Sent notify-select req to backend client %s", mgmt_be_client_id2name(id));
	}
	mgmt_msg_native_free_msg(msg);

	if (all_selectors)
		darr_free_free(all_selectors);

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
	struct txn_req_rpc *rpc;
	struct mgmt_txn_req *txn_req;

	if (!txn) {
		_log_err("Error reply from %s cannot find txn-id %" PRIu64, adapter->name, txn_id);
		return -1;
	}

	if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
		/*
		 * XXX want to make sure this isn't an error from sending
		 * cfg_apply_req, I think in that case we want to disconnect
		 * earlier anyway
		 */
		txn_req = txn->commit_cfg_req;
		if (txn_req)
			return mgmt_txn_notify_be_cfg_reply(txn_id, false, errstr, adapter);
	} else {
		/* Find the request. */
		FOREACH_TXN_REQ_IN_LIST (&txn->get_tree_reqs, txn_req)
			if (txn_req->req_id == req_id)
				break;
		if (!txn_req)
			FOREACH_TXN_REQ_IN_LIST (&txn->rpc_reqs, txn_req)
				if (txn_req->req_id == req_id)
					break;
	}

	if (!txn_req) {
		_log_err("Error reply from %s for txn-id %" PRIu64 " cannot find req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}

	_log_err("Error reply from %s for txn-id %" PRIu64 " req_id %" PRIu64, adapter->name,
		 txn_id, req_id);

	switch (txn_req->req_type) {
	case MGMTD_TXN_PROC_GETTREE:
		get_tree = txn_req->req.get_tree;
		get_tree->recv_clients |= (1u << id);
		get_tree->partial_error = error;

		/* check if done yet */
		if (get_tree->recv_clients != get_tree->sent_clients)
			return 0;
		return txn_get_tree_data_done(txn, txn_req);
	case MGMTD_TXN_PROC_RPC:
		rpc = txn_req->req.rpc;
		rpc->recv_clients |= (1u << id);
		if (errstr) {
			XFREE(MTYPE_MGMTD_ERR, rpc->errstr);
			rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR, errstr);
		}
		/* check if done yet */
		if (rpc->recv_clients != rpc->sent_clients)
			return 0;
		return txn_rpc_done(txn, txn_req);

	/* non-native message events */
	case MGMTD_TXN_PROC_COMMITCFG:
	default:
		assert(!"non-native req type in native error path");
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
	uint64_t txn_id = data_msg->refer_id;
	uint64_t req_id = data_msg->req_id;

	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	if (!txn) {
		_log_err("GETTREE reply from %s for a missing txn-id %" PRIu64, adapter->name,
			 txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->get_tree_reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
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
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
			 " error parsing result of type %u",
			 adapter->name, txn_id, req_id, data_msg->result_type);
	}
	if (!err) {
		/* TODO: we could merge ly_errs here if it's not binary */

		if (!get_tree->client_results)
			get_tree->client_results = tree;
		else
			err = lyd_merge_siblings(&get_tree->client_results,
						 tree, LYD_MERGE_DESTRUCT);
		if (err) {
			_log_err("GETTREE reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
				 " error merging result",
				 adapter->name, txn_id, req_id);
		}
	}
	if (!get_tree->partial_error)
		get_tree->partial_error = (data_msg->partial_error
						   ? data_msg->partial_error
						   : (int)err);

	if (!data_msg->more)
		get_tree->recv_clients |= (1u << id);

	/* check if done yet */
	if (get_tree->recv_clients != get_tree->sent_clients)
		return 0;

	return txn_get_tree_data_done(txn, txn_req);
}

int mgmt_txn_notify_rpc_reply(struct mgmt_be_client_adapter *adapter,
			      struct mgmt_msg_rpc_reply *reply_msg,
			      size_t msg_len)
{
	uint64_t txn_id = reply_msg->refer_id;
	uint64_t req_id = reply_msg->req_id;
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct mgmt_txn_req *txn_req;
	struct txn_req_rpc *rpc;
	struct lyd_node *tree;
	size_t data_len = msg_len - sizeof(*reply_msg);
	LY_ERR err = LY_SUCCESS;

	if (!txn) {
		_log_err("RPC reply from %s for a missing txn-id %" PRIu64, adapter->name, txn_id);
		return -1;
	}

	/* Find the request. */
	FOREACH_TXN_REQ_IN_LIST (&txn->rpc_reqs, txn_req)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}

	rpc = txn_req->req.rpc;

	tree = NULL;
	if (data_len)
		err = yang_parse_rpc(rpc->xpath, reply_msg->result_type,
				     reply_msg->data, true, &tree);
	if (err) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
			 " error parsing result of type %u: %s",
			 adapter->name, txn_id, req_id, reply_msg->result_type, ly_strerrcode(err));
	}
	if (!err && tree) {
		if (!rpc->client_results)
			rpc->client_results = tree;
		else
			err = lyd_merge_siblings(&rpc->client_results, tree,
						 LYD_MERGE_DESTRUCT);
		if (err) {
			_log_err("RPC reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
				 " error merging result: %s",
				 adapter->name, txn_id, req_id, ly_strerrcode(err));
		}
	}
	if (err) {
		XFREE(MTYPE_MGMTD_ERR, rpc->errstr);
		rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR,
				      "Cannot parse result from the backend");
	}

	rpc->recv_clients |= (1u << id);

	/* check if done yet */
	if (rpc->recv_clients != rpc->sent_clients)
		return 0;

	return txn_rpc_done(txn, txn_req);
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
		_log_err("Failed to create CONFIG Transaction for downloading CONFIGs");
		return -1;
	}

	_dbg("Created rollback txn-id: %" PRIu64, txn->txn_id);

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
	mgmt_txn_register_event(txn, MGMTD_TXN_EVENT_COMMITCFG);
	return 0;
}
