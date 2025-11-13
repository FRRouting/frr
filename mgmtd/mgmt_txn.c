// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Transactions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2025, LabN Consulting, L.L.C.
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
#include "mgmtd/mgmt_be_adapter.h"
#include "queue.h"

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_warn(fmt, ...) zlog_warn("%s: WARNING: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define TXN_INCREF(txn)   txn_incref(txn, __FILE__, __LINE__)
#define TXN_DECREF(txn, in_hash_free) txn_decref(txn, in_hash_free, __FILE__, __LINE__)


enum txn_req_type {
	TXN_REQ_TYPE_COMMIT = 1,
	TXN_REQ_TYPE_GETTREE,
	TXN_REQ_TYPE_RPC,
};

enum mgmt_commit_phase {
	MGMTD_COMMIT_PHASE_SEND_CFG = 0,
	MGMTD_COMMIT_PHASE_APPLY_CFG,
	MGMTD_COMMIT_PHASE_FINISH,
};

static const char *mgmt_commit_phase_name[] = {
	[MGMTD_COMMIT_PHASE_SEND_CFG] = "SEND-CFG",
	[MGMTD_COMMIT_PHASE_APPLY_CFG] = "APPLY-CFG",
	[MGMTD_COMMIT_PHASE_FINISH] = "FINISH",
};

struct txn_req {
	uint64_t req_id;
	struct mgmt_txn *txn;
	TAILQ_ENTRY(txn_req) link;
	enum txn_req_type req_type;
	int16_t error;		/* cfg: MGMTD return code, else errno */
	char *err_info;		/* darr str */
	struct event *timeout;	/* for timing out the request */
};
/* Macro to coerce back into txn_req */
#define into_txn_req(xreq) (&(xreq)->req)

struct txn_req_commit {
	struct txn_req req;
	enum mgmt_ds_id src_ds_id;
	struct mgmt_ds_ctx *src_ds_ctx;
	enum mgmt_ds_id dst_ds_id;
	struct mgmt_ds_ctx *dst_ds_ctx;

	uint32_t nb_txn_id;

	uint8_t validate_only : 1;
	uint8_t abort : 1;
	uint8_t implicit : 1;
	uint8_t rollback : 1;
	uint8_t init : 1;
	uint8_t unlock_info : 1;
	uint8_t txn_lock : 1;

	/* Track commit phases */
	enum mgmt_commit_phase phase;

	/*
	 * Additional information when the commit is triggered by native edit
	 * request.
	 */
	struct mgmt_edit_req *edit;


	/* Used for holding changes mgmtd itself is interested in */
	struct nb_transaction *mgmtd_nb_txn;

	/*
	 * Details on all the Backend Clients associated with
	 * this commit.
	 */
	uint64_t clients;      /* interested clients */
	uint64_t clients_wait; /* set when cfg_req sent */

	struct mgmt_commit_stats *cmt_stats;
};
#define into_commit_req(txn_req)                                                                  \
	({                                                                                        \
		assert((txn_req)->req_type == TXN_REQ_TYPE_COMMIT);                               \
		(struct txn_req_commit *)(txn_req);                                               \
	})

struct txn_req_get_tree {
	struct txn_req req;
	char *xpath;	       /* xpath of tree to get */
	uint64_t clients;      /* Bitmask of clients sent req to */
	uint64_t clients_wait; /* Bitmask of clients waiting for reply from */
	int32_t partial_error; /* an error while gather results */
	uint8_t result_type;   /* LYD_FORMAT for results */
	uint8_t wd_options;    /* LYD_PRINT_WD_* flags for results */
	uint8_t exact;	       /* if exact node is requested */
	uint8_t simple_xpath;  /* if xpath is simple */
	struct lyd_node *client_results; /* result tree from clients */
};
#define into_get_tree_req(txn_req)                                                                \
	({                                                                                        \
		assert((txn_req)->req_type == TXN_REQ_TYPE_GETTREE);                              \
		(struct txn_req_get_tree *)(txn_req);                                             \
	})

struct txn_req_rpc {
	struct txn_req req;
	char *xpath;	       /* xpath of rpc/action to invoke */
	uint64_t clients;      /* Bitmask of clients sent req to */
	uint64_t clients_wait; /* Bitmask of clients waiting for reply from */
	uint8_t result_type;   /* LYD_FORMAT for results */
	struct lyd_node *client_results; /* result tree from clients */
};
#define into_rpc_req(txn_req)                                                                     \
	({                                                                                        \
		assert((txn_req)->req_type == TXN_REQ_TYPE_RPC);                                  \
		(struct txn_req_rpc *)(txn_req);                                                  \
	})

const char *txn_req_names[] = {
	[TXN_REQ_TYPE_COMMIT] = "COMMIT",
	[TXN_REQ_TYPE_GETTREE] = "GET-TREE",
	[TXN_REQ_TYPE_RPC] = "RPC",
};

struct mgmt_txn {
	uint64_t session_id; /* One transaction per client session */
	uint64_t txn_id;
	enum mgmt_txn_type type;
	int refcount;

	TAILQ_ENTRY(mgmt_txn) link;

	/*
	 * List of pending requests.
	 */
	TAILQ_HEAD(txn_req_head, txn_req) reqs;
};

/* Global list of all transactions */
TAILQ_HEAD(mgmt_txn_head, mgmt_txn) txn_txns = TAILQ_HEAD_INITIALIZER(txn_txns);

/* The single instance of config transaction allowed at any time */
struct mgmt_txn *txn_config_txn;

/* The number of init txn's in progress, we lock on 0->1 and unlock on 1->0 */
uint txn_init_readers;

static inline struct txn_req_commit *txn_txn_req_commit(struct mgmt_txn *txn)
{
	struct txn_req *first_req = TAILQ_FIRST(&txn->reqs);

	if (first_req && first_req->req_type == TXN_REQ_TYPE_COMMIT)
		return into_commit_req(first_req);
	return NULL;
}

static inline struct txn_req *txn_txn_req(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req;

	TAILQ_FOREACH (txn_req, &txn->reqs, link)
		if (txn_req->req_id == req_id)
			return txn_req;
	return NULL;
}

static void txn_incref(struct mgmt_txn *txn, const char *file, int line);
static void txn_decref(struct mgmt_txn **txn, bool in_hash_free, const char *file, int line);

static struct event_loop *mgmt_txn_tm;
static struct mgmt_master *mgmt_txn_mm;

static void mgmt_txn_cleanup_txn(struct mgmt_txn **txn);

static void mgmt_txn_cfg_commit_timedout(struct event *thread);
static void txn_cfg_send_cfg_apply(struct txn_req_commit *ccreq);

static struct txn_req *txn_req_alloc(struct mgmt_txn *txn, uint64_t req_id,
				     enum txn_req_type req_type, size_t size)
{
	struct txn_req *txn_req = XCALLOC(MTYPE_MGMTD_TXN_REQ, size);

	txn_req->req_type = req_type;
	txn_req->req_id = req_id;

	txn_req->txn = txn;
	TAILQ_INSERT_TAIL(&txn->reqs, txn_req, link);
	TXN_INCREF(txn);

	_dbg("Added %s txn-req req-id: %Lu txn-id: %Lu session-id: %Lu", txn_req_names[req_type],
	     req_id, txn->txn_id, txn->session_id);

	return txn_req;
}

static struct txn_req_commit *txn_req_commit_alloc(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req = txn_req_alloc(txn, req_id, TXN_REQ_TYPE_COMMIT,
						sizeof(struct txn_req_commit));
	return into_commit_req(txn_req);
}

static struct txn_req_get_tree *txn_req_get_tree_alloc(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req = txn_req_alloc(txn, req_id, TXN_REQ_TYPE_GETTREE,
						sizeof(struct txn_req_get_tree));
	return into_get_tree_req(txn_req);
}

static struct txn_req_rpc *txn_req_rpc_alloc(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req = txn_req_alloc(txn, req_id, TXN_REQ_TYPE_RPC,
						sizeof(struct txn_req_rpc));
	return into_rpc_req(txn_req);
}

static int txn_send_txn_delete(struct mgmt_be_client_adapter *adapter, uint64_t txn_id)
{
	struct mgmt_msg_txn_req *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_txn_req, 0, MTYPE_MSG_NATIVE_TXN_REQ);
	msg->code = MGMT_MSG_CODE_TXN_REQ;
	msg->refer_id = txn_id;
	msg->create = false;

	ret = mgmt_be_send_native(adapter, msg);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

static void txn_cfg_cleanup(struct txn_req_commit *ccreq)
{
	struct txn_req *txn_req = &ccreq->req;
	struct mgmt_be_client_adapter *adapter;
	enum mgmt_commit_phase phase;
	enum mgmt_be_client_id id;
	uint64_t txn_id = txn_req->txn->txn_id;
	uint64_t clients;

	_dbg("Deleting COMMITCFG req-id: %Lu txn-id: %Lu", txn_req->req_id, txn_id);

	XFREE(MTYPE_MGMTD_TXN_REQ, ccreq->edit);

	/* If we (still) had an internal nb transaction, abort it */
	if (ccreq->mgmtd_nb_txn) {
		nb_candidate_commit_abort(ccreq->mgmtd_nb_txn, NULL, 0);
		ccreq->mgmtd_nb_txn = NULL;
	}

	/*
	 * What state are we in:
	 *
	 * FINISH: Everythign went OK. If this was NOT validate-only then all
	 * clients have replied to the CFG_APPLY and deleted their txn state. We
	 * have nothing to do. Otherwise, this is validate-only and all the
	 * clients still have config txn state with the changes. We need to
	 * clean that txn state up. Treat the phase as SEND-CFG so we send
	 * config abort (TXN-delete) to have the clients delete their txn state.
	 *
	 * APPLY: Any clients that have not CFG_APPLY_REPLY'd yet (clients_wait)
	 * need to be disconnected so they will resync config state on reconnect.
	 *
	 * SEND-CFG: Some clients may have cfg txn state. We send all clients
	 * config abort (TXN-delete) to cleanup any transaction state. Even if
	 * clients have rejected the config and deleted txn state already they
	 * are expected to handle receving TXN-delete gracefully (e.g., their
	 * reply may still be in flight when we got here).
	 */
	phase = ccreq->phase;
	if (phase == MGMTD_COMMIT_PHASE_FINISH && ccreq->validate_only)
		phase = MGMTD_COMMIT_PHASE_SEND_CFG;

	switch (phase) {
	case MGMTD_COMMIT_PHASE_FINISH:
		break;
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		/* cache and clear the bits as they are checked on client disconnect */
		clients = ccreq->clients_wait;
		ccreq->clients_wait = 0;
		ccreq->clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			_dbg("Disconnect client: %s for txn-id: %Lu resync required",
			     adapter->name, txn_id);
			msg_conn_disconnect(adapter->conn, false);
		}
		break;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		/* cache and clear the bits as they are checked on client disconnect */
		clients = ccreq->clients;
		ccreq->clients_wait = 0;
		ccreq->clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			if (!txn_send_txn_delete(adapter, txn_id))
				continue;
			_dbg("Disconnect client: %s for txn-id: %Lu failed to send CFG_ABORT",
			     adapter->name, txn_id);
			msg_conn_disconnect(adapter->conn, false);
		}
		break;
	}

	/*
	 * Now release the TXN locks if held.
	 */
	if (ccreq->txn_lock) {
		mgmt_ds_txn_unlock(ccreq->src_ds_ctx, txn_id);
		mgmt_ds_txn_unlock(ccreq->dst_ds_ctx, txn_id);
	}
}

static void mgmt_txn_req_free(struct txn_req *txn_req)
{
	struct mgmt_txn *txn = txn_req->txn;
	struct txn_req_rpc *rreq;
	struct txn_req_get_tree *gtreq;
	uint64_t txn_id = txn->txn_id;

	/* prevent recursion */
	_dbg("Deleting %s txn-req req-id: %Lu txn-id: %Lu", txn_req_names[txn_req->req_type],
	     txn_req->req_id, txn_id);

	switch (txn_req->req_type) {
	case TXN_REQ_TYPE_COMMIT:
		txn_cfg_cleanup(into_commit_req(txn_req));
		break;
	case TXN_REQ_TYPE_GETTREE:
		gtreq = into_get_tree_req(txn_req);
		lyd_free_all(gtreq->client_results);
		XFREE(MTYPE_MGMTD_XPATH, gtreq->xpath);
		break;
	case TXN_REQ_TYPE_RPC:
		rreq = into_rpc_req(txn_req);
		lyd_free_all(rreq->client_results);
		XFREE(MTYPE_MGMTD_XPATH, rreq->xpath);
		break;
	}

	TAILQ_REMOVE(&txn->reqs, txn_req, link);
	_dbg("Removed req-id: %Lu from request-list", txn_req->req_id);

	darr_free(txn_req->err_info);
	TXN_DECREF(&txn_req->txn, false);
	XFREE(MTYPE_MGMTD_TXN_REQ, txn_req);
}

static int txn_set_config_error(struct txn_req *txn_req, enum mgmt_result error,
				const char *error_info)
{
	txn_req->error = error;
	darr_in_strdup(txn_req->err_info, error_info);
	return -1;
}

/*
 * Finish processing a commit-config request.
 *
 * NOTE: can disconnect (and delete) backends.
 */
static void txn_finish_commit(struct txn_req_commit *ccreq, enum mgmt_result result,
			      const char *error_if_any)
{
	bool success, apply_op, accept_changes, discard_changes;
	struct txn_req *txn_req = into_txn_req(ccreq);
	struct mgmt_txn *txn = txn_req->txn;
	int ret;

	success = (result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES);

	/*
	 * Stop the commit-timeout timer.
	 */
	event_cancel(&txn_req->timeout);

	/*
	 * Decide what our datastores should now look like
	 *
	 * Accept changes into running (candidate->running):
	 *
	 *    If this is a commit (apply or rollback) and we've at least started
	 *    telling backend clients to apply, we need to accept the changes
	 *    into running. Any clients who have not acked the apply yet will be
	 *    disconnected in the txn cleanup so they sync to running on
	 *    reconnect.
	 *
	 * Discard candidate changes (running->candidate):
	 *
	 *    If this is a successful abort
	 */
	apply_op = !ccreq->validate_only && !ccreq->abort && !ccreq->init;
	accept_changes = ccreq->phase >= MGMTD_COMMIT_PHASE_APPLY_CFG && apply_op;
	discard_changes = (result == MGMTD_SUCCESS && ccreq->abort);
	if (accept_changes) {
		bool create_cmt_info_rec = (result != MGMTD_NO_CFG_CHANGES && !ccreq->rollback);

		mgmt_ds_copy_dss(ccreq->dst_ds_ctx, ccreq->src_ds_ctx, create_cmt_info_rec);
	}
	if (discard_changes)
		mgmt_ds_copy_dss(ccreq->src_ds_ctx, ccreq->dst_ds_ctx, false);

	/*
	 * For internal txns do lock cleanup, for front-end session send replies.
	 */
	if (ccreq->init) {
		/*
		 * This is the backend init request. Unlock the running
		 * datastore if we are the last reader.
		 */
		if (!--txn_init_readers)
			mgmt_ds_unlock(ccreq->dst_ds_ctx, 0);
		ret = 0;
	} else if (ccreq->rollback) {
		/*
		 * Resume processing the rollback command.
		 *
		 * TODO: there's no good reason to special case rollback, the
		 * rollback boolean should be passed back to the FE client and it
		 * can do the right thing.
		 */
		mgmt_history_rollback_complete(success);
		ret = 0;
	} else if (!ccreq->edit)
		/* This means we are in the mgmtd CLI vty code */
		ret = mgmt_fe_send_commit_cfg_reply(txn->session_id, txn->txn_id, ccreq->src_ds_id,
						    ccreq->dst_ds_id, txn_req->req_id,
						    ccreq->validate_only, ccreq->unlock_info,
						    result, error_if_any);
	else {
		ret = mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id,
						      txn_req->req_id, ccreq->unlock_info,
						      true /* commit */, &ccreq->edit,
						      success ? 0 : MGMTD_INTERNAL_ERROR,
						      error_if_any);
	}
	if (ret)
		_log_err("Failed sending config reply for txn-id: %Lu session-id: %Lu",
			 txn->txn_id, txn->session_id);

	ccreq->cmt_stats = NULL;
	mgmt_txn_req_free(txn_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!txn->session_id)
		mgmt_txn_cleanup_txn(&txn);
}

static void txn_cfg_next_phase(struct txn_req_commit *ccreq)
{
	struct txn_req *txn_req = &ccreq->req;

	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		if (ccreq->validate_only)
			ccreq->phase = MGMTD_COMMIT_PHASE_FINISH;
		else
			ccreq->phase = MGMTD_COMMIT_PHASE_APPLY_CFG;
		break;
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&ccreq->cmt_stats->apply_cfg_end, NULL);
		ccreq->phase = MGMTD_COMMIT_PHASE_FINISH;
		break;
	case MGMTD_COMMIT_PHASE_FINISH:
	default:
		assert(!"Invalid commit phase transition from FINISH");
		break;
	}

	_dbg("CONFIG-STATE-MACHINE txn-id: %Lu transition to state: %s", txn_req->txn->txn_id,
	     mgmt_commit_phase_name[ccreq->phase]);

	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		txn_cfg_send_cfg_apply(ccreq);
		break;
	case MGMTD_COMMIT_PHASE_FINISH:
		if (mm->perf_stats_en)
			gettimeofday(&ccreq->cmt_stats->txn_del_start, NULL);
		txn_finish_commit(ccreq, MGMTD_SUCCESS, NULL);
		return;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
	default:
		assert(!"Invalid commit phase transition to SEND_CFG");
	}
}

static void txn_cfg_adapter_acked(struct txn_req_commit *ccreq, struct mgmt_be_client_adapter *adapter)
{
	struct txn_req *txn_req = &ccreq->req;

	_dbg("CONFIG-STATE-MACHINE txn-id: %Lu in state: %s", txn_req->txn->txn_id,
	     mgmt_commit_phase_name[ccreq->phase]);

	if (adapter) {
		enum mgmt_be_client_id id = adapter->id;

		if (IS_IDBIT_SET(ccreq->clients_wait, id))
			UNSET_IDBIT(ccreq->clients_wait, id);
		else
			_dbg("Wasn't waiting on client: %s", adapter->name);
	}

	if (ccreq->clients_wait) {
		_dbg("CONFIG-STATE-MACHINE txn-id: %Lu still waiting on clients: 0x%Lx",
		     txn_req->txn->txn_id, ccreq->clients_wait);
		return;
	}

	txn_cfg_next_phase(ccreq);
}

/*
 * This is the real workhorse. Take the list of changes and check each change
 * against our backend clients to see who is interested. For each interested
 * client we create a config message -- we also track which changes mgmtd itself
 * is interested in. If a client is interested we add the change to it's config
 * message and track the type of chagne in another string array.
 *
 * When done with the changes we first handle mgmtd's own changes, validating,
 * and preparing them into the mgmtd candidate (using normal lib/northbound
 * routines). Then for each backend client we complete it's config message by
 * append the action string and then we send it to the client.
 *
 * Return: 0 on success, the caller should arrange to receive REPLYS from the
 * clients before proceeding further, if no clients were interested the caller
 * should proceed to apply the mgmtd local changes (if any) to complete the txn.
 *
 * On failure, if we were called from a front-end client (the TXN has a
 * session_id) we have it reply with the error and cleanup the txn. Otherwise
 * this is an internal txn and we just cleanup the txn in that case. In either
 * case we return -1 and the caller should not proceed further.
 *
 * Can disconnect backends, but this is not called from backends, so it's safe.
 */

static int txn_make_and_send_cfg_msgs(struct txn_req_commit *ccreq, const struct nb_config_cbs *changes,
				      uint64_t init_client_mask)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	struct nb_config_cbs mgmtd_changes = { 0 };
	char *xpath = NULL, *value = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct txn_req *txn_req = &ccreq->req;
	struct mgmt_msg_cfg_req **cfg_msgs = NULL;
	char **cfg_actions = NULL;
	uint64_t *num_cfg_data = NULL;
	bool mgmtd_interest;
	uint batch_items = 0;
	uint num_chgs = 0;
	uint64_t clients, chg_clients;
	char op;
	int ret = -1;

	RB_FOREACH_SAFE (cb, nb_config_cbs, changes, nxt) {
		chg = (struct nb_config_change *)cb;

		xpath = lyd_path(chg->cb.dnode, LYD_PATH_STD, NULL, 0);
		assert(xpath);

		value = (char *)lyd_get_value(chg->cb.dnode);
		if (!value)
			value = (char *)MGMTD_BE_CONTAINER_NODE_VAL;

		_dbg("XPATH: %s, Value: '%s'", xpath, value ? value : "NIL");

		/* Collect changes for mgmtd itself */
		mgmtd_interest = false;
		if (!init_client_mask && mgmt_is_mgmtd_interested(xpath) &&
		    /* We send tree changes to BEs that we don't need callbacks for */
		    nb_cb_operation_is_valid(cb->operation, cb->dnode->schema)) {
			uint32_t seq = cb->seq;

			nb_config_diff_add_change(&mgmtd_changes, cb->operation, &seq, cb->dnode);
			mgmtd_interest = true;
		}
		if (init_client_mask)
			clients = init_client_mask;
		else
			clients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		if (!clients)
			_dbg("No backends interested in xpath: %s", xpath);

		if (mgmtd_interest || clients)
			num_chgs++;

		chg_clients = 0;
		FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
			SET_IDBIT(chg_clients, id);

			darr_ensure_i(cfg_msgs, id);
			darr_ensure_i(cfg_actions, id);
			if (DEBUG_MODE_CHECK(&mgmt_debug_txn, DEBUG_MODE_ALL))
				darr_ensure_i(num_cfg_data, id);
			if (!cfg_msgs[id]) {
				/* Allocate a new config message */
				struct mgmt_msg_cfg_req *msg;

				msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_req, 0,
								MTYPE_MSG_NATIVE_CFG_REQ);
				msg->code = MGMT_MSG_CODE_CFG_REQ;
				msg->refer_id = txn_req->txn->txn_id;
				msg->req_id = txn_req->req_id;
				cfg_msgs[id] = msg;
			}

			/*
			 * On the backend, we don't really care if it's CREATE
			 * or MODIFY, because the existence was already checked
			 * on the frontend. Therefore we use SET for both.
			 */
			op = chg->cb.operation == NB_CB_DESTROY ? 'd' : 'm';
			darr_push(cfg_actions[id], op);

			mgmt_msg_native_add_str(cfg_msgs[id], xpath);
			if (op == 'm')
				mgmt_msg_native_add_str(cfg_msgs[id], value);
			if (DEBUG_MODE_CHECK(&mgmt_debug_txn, DEBUG_MODE_ALL)) {
				num_cfg_data[id]++;
				_dbg(" -- %s, batch item: %Lu", adapter->name, num_cfg_data[id]);
			}

			batch_items++;
		}

		if (clients && clients != chg_clients)
			_dbg("Some deamons interested in XPATH are not currently connected");

		ccreq->clients |= chg_clients;

		free(xpath);
	}
	ccreq->cmt_stats->last_batch_cnt = batch_items;

	if (!RB_EMPTY(nb_config_cbs, &mgmtd_changes)) {
		/* Create a northbound transaction for local mgmtd config changes */
		char errmsg[BUFSIZ] = { 0 };
		size_t errmsg_len = sizeof(errmsg);
		struct nb_context nb_ctx = { 0 };

		_dbg("Processing mgmtd bound changes");

		assert(!ccreq->mgmtd_nb_txn);
		nb_ctx.client = NB_CLIENT_MGMTD_SERVER;

		/* Prepare the mgmtd local config changes */
		/*
		 * This isn't calling the VALIDATE callback, it's just
		 * running PREPARE. See #19948
		 */
		if (nb_changes_commit_prepare(nb_ctx, mgmtd_changes, "mgmtd-changes", NULL,
					      &ccreq->mgmtd_nb_txn, errmsg, errmsg_len)) {
			_log_err("Failed to prepare local config for mgmtd: %s", errmsg);
			if (ccreq->mgmtd_nb_txn) {
				nb_candidate_commit_abort(ccreq->mgmtd_nb_txn, NULL, 0);
				ccreq->mgmtd_nb_txn = NULL;
			}
			(void)txn_set_config_error(txn_req, MGMTD_INTERNAL_ERROR,
						   "Failed to prepare local config for mgmtd");
			goto done;
		}
		assert(ccreq->mgmtd_nb_txn);
	}

	/* Record txn create start time */
	if (mm->perf_stats_en)
		gettimeofday(&ccreq->cmt_stats->txn_create_start, NULL);

	/* Send the messages to the backends */
	FOREACH_BE_ADAPTER_BITS (id, adapter, ccreq->clients) {
		/* NUL terminate actions string and add to tail of message */
		darr_push(cfg_actions[id], 0);
		mgmt_msg_native_add_str(cfg_msgs[id], cfg_actions[id]);
		_dbg("Finished CFG_REQ for '%s' txn-id: %Lu with actions: %s", adapter->name,
		     txn_req->txn->txn_id, cfg_actions[id]);

		if (mgmt_be_send_native(adapter, cfg_msgs[id])) {
			/* remove this client and reset the connection */
			UNSET_IDBIT(ccreq->clients, id);
			msg_conn_disconnect(adapter->conn, false);
		}
		ccreq->cmt_stats->last_num_cfgdata_reqs++;
	}
	/* Record who we are waiting for */
	ccreq->clients_wait = ccreq->clients;

	if (ccreq->clients) {
		/* set a timeout for hearing back from the backend clients */
		event_add_timer(mgmt_txn_tm, mgmt_txn_cfg_commit_timedout, txn_req,
				MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC, &txn_req->timeout);
	} else {
		/* We have no connected interested clients */
		if (ccreq->mgmtd_nb_txn)
			_dbg("No connected and interested backend clients, proceed with mgmtd local changes");
		else
			_dbg("No connected and interested backend clients, proceed to apply changes");
		txn_cfg_adapter_acked(ccreq, NULL);
	}

	ret = 0;
done:
	darr_free(num_cfg_data);
	darr_free_func(cfg_msgs, mgmt_msg_native_free_msg);
	darr_free_free(cfg_actions);
	return ret;
}

static int txn_send_config_changes(struct txn_req_commit *ccreq, struct nb_config_cbs *cfg_chgs,
				   uint64_t init_client_mask);

/*
 * Prepare and send config changes by comparing the source and destination
 * datastores.
 */
static int txn_get_config_changes(struct txn_req_commit *ccreq, struct nb_config_cbs *cfg_chgs)
{
	struct nb_config *nb_config;
	struct txn_req *txn_req = &ccreq->req;
	int ret = 0;

	if (ccreq->src_ds_id != MGMTD_DS_CANDIDATE) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "Source DS cannot be any other than CANDIDATE!");
	}

	if (ccreq->dst_ds_id != MGMTD_DS_RUNNING) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "Destination DS cannot be any other than RUNNING!");
	}

	if (!ccreq->src_ds_ctx) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "No such source datastore!");
	}

	if (!ccreq->dst_ds_ctx) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "No such destination datastore!");
	}

	if (ccreq->abort) {
		/*
		 * This is a commit abort request. Return back success.
		 * The reply routing special cases abort, this isn't pretty,
		 * fix in later cleanup.
		 */
		return txn_set_config_error(txn_req, MGMTD_SUCCESS, "commit abort");
	}

	nb_config = mgmt_ds_get_nb_config(ccreq->src_ds_ctx);
	if (!nb_config) {
		return txn_set_config_error(txn_req, MGMTD_INTERNAL_ERROR,
					    "Unable to retrieve Commit DS Config Tree!");
	}

	/*
	 * Validate YANG contents of the source DS and get the diff
	 * between source and destination DS contents.
	 */
	char err_buf[BUFSIZ] = { 0 };

	ret = nb_candidate_validate_yang(nb_config, true, err_buf, sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM, err_buf);
	}

	nb_config_diff(mgmt_ds_get_nb_config(ccreq->dst_ds_ctx),
		       nb_config, cfg_chgs);
	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		return txn_set_config_error(txn_req, MGMTD_NO_CFG_CHANGES,
					    "No changes found to be committed!");
	}
	return 0;
}

/*
 * Given a list of config changes, make backend client messages and send them. Aslo
 * apply any mgmtd specific config as well.
 */
static int txn_send_config_changes(struct txn_req_commit *ccreq, struct nb_config_cbs *cfg_chgs,
				   uint64_t init_client_mask)
{
	int ret;

	if (mm->perf_stats_en)
		gettimeofday(&ccreq->cmt_stats->prep_cfg_start, NULL);

	ret = txn_make_and_send_cfg_msgs(ccreq, cfg_chgs, init_client_mask);
	nb_config_diff_del_changes(cfg_chgs);
	return ret;
}


static void mgmt_txn_cfg_commit_timedout(struct event *event)
{
	struct txn_req *txn_req;
	struct txn_req_commit *ccreq;

	txn_req = EVENT_ARG(event);
	ccreq = into_commit_req(txn_req);

	/*
	 * If we are applying changes we need to return SUCCESS as there is no
	 * way to abort those. Slow backends that haven't replied yet will be
	 * disconnected. If we are still sending config for validate/prepare
	 * phase we return an error and abort the commit.
	 */
	if (ccreq->phase < MGMTD_COMMIT_PHASE_APPLY_CFG) {
		_log_err("Backend timeout validating txn-id: %Lu waiting: 0x%Lx aborting commit",
			 txn_req->txn->txn_id, ccreq->clients_wait);
		txn_finish_commit(ccreq, MGMTD_INTERNAL_ERROR,
				  "Some backend clients taking too long to validate the changes.");
	} else {
		_log_warn("Backend timeout applying txn-id: %Lu waiting: 0x%Lx, applying commit",
			  txn_req->txn->txn_id, ccreq->clients_wait);
		txn_finish_commit(ccreq, MGMTD_SUCCESS,
				  "Some backend clients taking too long to apply the changes.");
	}
}


static int txn_get_tree_data_done(struct txn_req_get_tree *get_tree)
{
	struct txn_req *txn_req = into_txn_req(get_tree);
	struct mgmt_txn *txn = txn_req->txn;
	uint64_t req_id = txn_req->req_id;
	struct lyd_node *result;
	int ret = NB_OK;

	/* cancel timer and send reply onward */
	event_cancel(&txn_req->timeout);

	if (!get_tree->simple_xpath && get_tree->client_results) {
		/*
		 * We have a complex query so Filter results by the xpath query.
		 */
		if (yang_lyd_trim_xpath(&get_tree->client_results, get_tree->xpath))
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
	mgmt_txn_req_free(txn_req);

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

static int txn_rpc_done(struct txn_req_rpc *rpc)
{
	struct txn_req *txn_req = into_txn_req(rpc);
	struct mgmt_txn *txn = txn_req->txn;
	uint64_t req_id = rpc->req.req_id;

	/* cancel timer and send reply onward */
	event_cancel(&rpc->req.timeout);

	if (txn_req->err_info)
		mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false, txn_req->error ?: -EINVAL,
					  txn_req->err_info);
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
	mgmt_txn_req_free(txn_req);

	return 0;
}

static void txn_get_tree_timeout(struct event *event)
{
	struct txn_req_get_tree *get_tree = EVENT_ARG(event);
	struct mgmt_txn *txn = get_tree->req.txn;

	_log_err("Backend timeout txn-id: %" PRIu64 " ending get-tree", txn->txn_id);

	get_tree->partial_error = -ETIMEDOUT;
	get_tree->req.err_info = darr_strdup("Get data on the backend timed-out");
	txn_get_tree_data_done(get_tree);
}

static void txn_rpc_timeout(struct event *event)
{
	struct txn_req_rpc *rpc = EVENT_ARG(event);
	struct mgmt_txn *txn = rpc->req.txn;

	_log_err("Backend timeout txn-id: %" PRIu64 " ending rpc", txn->txn_id);

	rpc->req.error = -ETIMEDOUT;
	rpc->req.err_info = darr_strdup("RPC on the backend timed-out");
	txn_rpc_done(rpc);
}

/*
 * Send CFG_APPLY_REQs to all the backend client.
 */
static void txn_cfg_send_cfg_apply(struct txn_req_commit *ccreq)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_cfg_apply_req *msg;
	uint64_t txn_id = ccreq->req.txn->txn_id;

	assert(ccreq->req.txn->type == MGMTD_TXN_TYPE_CONFIG);

	assert(!ccreq->validate_only);

	if (mm->perf_stats_en)
		gettimeofday(&ccreq->cmt_stats->apply_cfg_start, NULL);
	/*
	 * Handle mgmtd internal special case
	 */
	if (ccreq->mgmtd_nb_txn) {
		char errmsg[BUFSIZ] = { 0 };

		_dbg("Applying mgmtd local bound changes");

		(void)nb_candidate_commit_apply(ccreq->mgmtd_nb_txn, false, NULL, errmsg,
						sizeof(errmsg));
		ccreq->mgmtd_nb_txn = NULL;
	}

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_apply_req, 0,
					MTYPE_MSG_NATIVE_CFG_APPLY_REQ);
	msg->code = MGMT_MSG_CODE_CFG_APPLY_REQ;
	msg->refer_id = txn_id;
	FOREACH_BE_ADAPTER_BITS (id, adapter, ccreq->clients) {
		if (mgmt_be_send_native(adapter, msg)) {
			msg_conn_disconnect(adapter->conn, false);
			continue;
		}
		SET_IDBIT(ccreq->clients_wait, id);
		ccreq->cmt_stats->last_num_apply_reqs++;
	}
	mgmt_msg_native_free_msg(msg);

	if (!ccreq->clients_wait) {
		_dbg("No backends to wait for on CFG_APPLY for txn-id: %Lu", txn_id);
		txn_cfg_adapter_acked(ccreq, NULL);
	}
}

static struct mgmt_txn *mgmt_fe_find_txn_by_session_id(struct mgmt_master *cm, uint64_t session_id,
						       enum mgmt_txn_type type)
{
	struct mgmt_txn *txn, *next;

	TAILQ_FOREACH_SAFE (txn, &txn_txns, link, next) {
		if (txn->session_id == session_id && txn->type == type)
			return txn;
	}

	return NULL;
}

static struct mgmt_txn *mgmt_txn_create_new(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn *txn = NULL;

	/* Do not allow multiple config transactions */
	if (type == MGMTD_TXN_TYPE_CONFIG && txn_config_txn)
		return NULL;

	txn = mgmt_fe_find_txn_by_session_id(mgmt_txn_mm, session_id, type);
	if (!txn) {
		txn = XCALLOC(MTYPE_MGMTD_TXN, sizeof(struct mgmt_txn));
		txn->session_id = session_id;
		txn->type = type;
		TAILQ_INSERT_TAIL(&txn_txns, txn, link);
		TAILQ_INIT(&txn->reqs);
		if (!mgmt_txn_mm->next_txn_id)
			mgmt_txn_mm->next_txn_id++;
		txn->txn_id = mgmt_txn_mm->next_txn_id++;
		hash_get(mgmt_txn_mm->txn_hash, txn, hash_alloc_intern);

		_dbg("Added new '%s' txn-id: %" PRIu64, mgmt_txn_type2str(type), txn->txn_id);

		if (type == MGMTD_TXN_TYPE_CONFIG)
			txn_config_txn = txn;

		TXN_INCREF(txn);
	}

	return txn;
}

static unsigned int mgmt_txn_hash_key(const void *data)
{
	const struct mgmt_txn *txn = data;

	return jhash2((uint32_t *)&txn->txn_id,
		      sizeof(txn->txn_id) / sizeof(uint32_t), 0);
}

static bool mgmt_txn_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_txn *txn1 = d1;
	const struct mgmt_txn *txn2 = d2;

	return (txn1->txn_id == txn2->txn_id);
}

static void mgmt_txn_hash_free(void *data)
{
	struct mgmt_txn *txn = data;

	TXN_DECREF(&txn, true);
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

static inline struct mgmt_txn *mgmt_txn_id2ctx(uint64_t txn_id)
{
	struct mgmt_txn key = { 0 };
	struct mgmt_txn *txn;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return NULL;

	key.txn_id = txn_id;
	txn = hash_lookup(mgmt_txn_mm->txn_hash, &key);

	return txn;
}

uint64_t mgmt_txn_get_session_id(uint64_t txn_id)
{
	struct mgmt_txn *txn = mgmt_txn_id2ctx(txn_id);

	return txn ? txn->session_id : MGMTD_SESSION_ID_NONE;
}

static void txn_incref(struct mgmt_txn *txn, const char *file, int line)
{
	txn->refcount++;
	_dbg("TXN-INCREF %s txn-id: %Lu refcnt: %d file: %s line: %d)",
	     mgmt_txn_type2str(txn->type), txn->txn_id, txn->refcount, file, line);
}

static void txn_decref(struct mgmt_txn **txn, bool in_hash_free, const char *file, int line)
{
	assert(*txn && (*txn)->refcount);

	(*txn)->refcount--;
	_dbg("TXN-DECREF %s txn-id: %Lu refcnt: %d file: %s line: %d",
	     mgmt_txn_type2str((*txn)->type), (*txn)->txn_id, (*txn)->refcount, file, line);
	if (!(*txn)->refcount) {
		if ((*txn)->type == MGMTD_TXN_TYPE_CONFIG)
			if (txn_config_txn == *txn)
				txn_config_txn = NULL;
		if (!in_hash_free)
			hash_release(mgmt_txn_mm->txn_hash, *txn);

		TAILQ_REMOVE(&txn_txns, *txn, link);

		_dbg("Deleted %s txn-id: %Lu session-id: %Lu", mgmt_txn_type2str((*txn)->type),
		     (*txn)->txn_id, (*txn)->session_id);

		XFREE(MTYPE_MGMTD_TXN, *txn);
	}

	*txn = NULL;
}

static void mgmt_txn_cleanup_txn(struct mgmt_txn **txn)
{
	/* TODO: Any other cleanup applicable */

	TXN_DECREF(txn, false);
}

static void mgmt_txn_cleanup_all_txns(void)
{
	struct mgmt_txn *txn, *next;

	if (!mgmt_txn_mm || !mgmt_txn_mm->txn_hash)
		return;

	TAILQ_FOREACH_SAFE (txn, &txn_txns, link, next)
		mgmt_txn_cleanup_txn(&txn);
}

int mgmt_txn_init(struct mgmt_master *m, struct event_loop *loop)
{
	if (mgmt_txn_mm || mgmt_txn_tm)
		assert(!"MGMTD TXN: Call txn_init() only once");

	mgmt_txn_mm = m;
	mgmt_txn_tm = loop;
	mgmt_txn_hash_init();

	return 0;
}

void mgmt_txn_destroy(void)
{
	mgmt_txn_cleanup_all_txns();
	mgmt_txn_hash_destroy();
}

bool mgmt_config_txn_in_progress(void)
{
	return txn_config_txn != NULL;
}

uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn *txn;

	txn = mgmt_txn_create_new(session_id, type);
	return txn ? txn->txn_id : MGMTD_TXN_ID_NONE;
}

void mgmt_destroy_txn(uint64_t *txn_id)
{
	struct mgmt_txn *txn;

	txn = mgmt_txn_id2ctx(*txn_id);
	if (!txn)
		return;

	TXN_DECREF(&txn, false);
	*txn_id = MGMTD_TXN_ID_NONE;
}

/**
 * mgmt_txn_send_commit_config_req() - Send a commit config request
 * @txn_id - A config TXN which must exist.
 *
 * Return: -1 on setup failure -- should immediately handle error, Otherwise 0
 * and will reply to session with any downstream error.
 */
void mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id src_ds_id,
				     struct mgmt_ds_ctx *src_ds_ctx, enum mgmt_ds_id dst_ds_id,
				     struct mgmt_ds_ctx *dst_ds_ctx, bool validate_only, bool abort,
				     bool implicit, bool unlock, struct mgmt_edit_req *edit)
{
	struct mgmt_txn *txn;
	struct txn_req_commit *ccreq;
	struct nb_config_cbs changes = { 0 };

	txn = mgmt_txn_id2ctx(txn_id);
	assert(txn && txn->type == MGMTD_TXN_TYPE_CONFIG);

	/* Only one outstanding commit request per txn */
	assert(txn_txn_req_commit(txn) == NULL);

	ccreq = txn_req_commit_alloc(txn, req_id);

	/* Lock the datastores for this transaction */
	assert(!mgmt_ds_txn_lock(src_ds_ctx, txn->txn_id));
	assert(!mgmt_ds_txn_lock(dst_ds_ctx, txn->txn_id));
	ccreq->txn_lock = true;

	ccreq->src_ds_id = src_ds_id;
	ccreq->src_ds_ctx = src_ds_ctx;
	ccreq->dst_ds_id = dst_ds_id;
	ccreq->dst_ds_ctx = dst_ds_ctx;
	ccreq->validate_only = validate_only;
	ccreq->abort = abort;
	ccreq->implicit = implicit; /* this is only true iff edit */
	ccreq->unlock_info = unlock; /* this is true for implicit commit in front-end */
	ccreq->edit = edit;
	ccreq->cmt_stats = mgmt_fe_get_session_commit_stats(txn->session_id);

	int ret = txn_get_config_changes(ccreq, &changes);
	if (ret == 0)
		ret = txn_send_config_changes(ccreq, &changes, 0);
	if (ret)
		txn_finish_commit(ccreq, ccreq->req.error, ccreq->req.err_info);
}

int mgmt_txn_notify_be_adapter_conn(struct mgmt_be_client_adapter *adapter,
				    bool connect)
{
	struct mgmt_txn *txn, *next;
	struct txn_req_commit *ccreq;
	struct nb_config_cbs *adapter_cfgs = NULL;
	struct mgmt_ds_ctx *ds_ctx;

	if (connect) {
		ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
		assert(ds_ctx);

		/* We don't send configs to ourselves we already have them */
		if (adapter->id == MGMTD_BE_CLIENT_ID_MGMTD) {
			_dbg("Not sending initial config to myself");
			return 0;
		}

		/*
		 * If this is the first set of changes we are sending to a
		 * backend, obtain a lock on running. We will release the lock
		 * when the last init cfg request completes. This allows for
		 * initializing the backends in parallel.
		 */

		if (!txn_init_readers++ && mgmt_ds_lock(ds_ctx, 0) != 0) {
			_dbg("Failed to lock DS:%s for init of BE adapter '%s'",
			     mgmt_ds_id2name(MGMTD_DS_RUNNING), adapter->name);
			--txn_init_readers;
			return -1;
		}

		/* Get config for this single backend client */
		mgmt_be_get_adapter_config(adapter, &adapter_cfgs);
		if (!adapter_cfgs || RB_EMPTY(nb_config_cbs, adapter_cfgs)) {
			if (!--txn_init_readers)
				mgmt_ds_unlock(ds_ctx, 0);
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
			if (!--txn_init_readers)
				mgmt_ds_unlock(ds_ctx, 0);
			nb_config_diff_del_changes(adapter_cfgs);
			return -1;
		}

		_dbg("Created initial txn-id: %" PRIu64 " for BE client '%s'", txn->txn_id,
		     adapter->name);

		/*
		 * Set the changeset for transaction to commit and trigger the
		 * commit request.
		 */
		memset(&adapter->cfg_stats, 0, sizeof(adapter->cfg_stats));
		ccreq = txn_req_commit_alloc(txn, 0);
		ccreq->src_ds_id = MGMTD_DS_NONE;
		ccreq->src_ds_ctx = 0;
		ccreq->dst_ds_id = MGMTD_DS_RUNNING;
		ccreq->dst_ds_ctx = ds_ctx;
		ccreq->validate_only = false;
		ccreq->abort = false;
		ccreq->init = true;
		ccreq->cmt_stats = &adapter->cfg_stats;

		/*
		 * Apply the initial changes.
		 */
		return txn_send_config_changes(ccreq, adapter_cfgs, 1ull << adapter->id);
	} else {
		/*
		 * Check if any transaction is currently on-going that
		 * involves this backend client. If so check if we can now
		 * advance that configuration.
		 */
		TAILQ_FOREACH_SAFE (txn, &txn_txns, link, next) {
			/* XXX update to handle get-tree and RPC too! */
			if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
				ccreq = txn_txn_req_commit(txn);
				if (!ccreq)
					continue;

				UNSET_IDBIT(ccreq->clients, adapter->id);
				if (IS_IDBIT_SET(ccreq->clients_wait, adapter->id))
					txn_cfg_adapter_acked(ccreq, adapter);
			}
		}
	}

	return 0;
}

/*
 * Handle CFG_REQ reply from backend client adapter. This is the only point of
 * failure that is expected in the config commit process; it is where the
 * backend client can report validation or prepare errors.
 *
 * NOTE: can disconnect (and delete) the backend.
 */
static void txn_handle_cfg_reply(struct txn_req_commit *ccreq, bool success, const char *error_if_any,
				 struct mgmt_be_client_adapter *adapter)
{
	struct txn_req *txn_req = into_txn_req(ccreq);

	if (!IS_IDBIT_SET(ccreq->clients_wait, adapter->id)) {
		_log_warn("CFG_REPLY from '%s' but not waiting for it for txn-id: %Lu, resetting connection",
			  adapter->name, txn_req->txn->txn_id);
		msg_conn_disconnect(adapter->conn, false);
		return;
	}

	if (success)
		_dbg("CFG_REPLY from '%s'", adapter->name);
	else {
		_log_err("CFG_REQ to '%s' failed err: %s", adapter->name, error_if_any ?: "None");
		txn_finish_commit(ccreq, MGMTD_VALIDATION_ERROR,
				  error_if_any ?: "config validation failed by backend daemon");
		return;
	}

	txn_cfg_adapter_acked(ccreq, adapter);
}

static struct txn_req_commit *
txn_ensure_be_cfg_msg(uint64_t txn_id, struct mgmt_be_client_adapter *adapter, const char *tag)
{
	struct mgmt_txn *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req_commit *ccreq;

	if (!txn) {
		_log_err("%s reply from '%s' for txn-id: %Lu no TXN, resetting connection", tag,
			 adapter->name, txn_id);
		return NULL;
	}
	if (txn->type != MGMTD_TXN_TYPE_CONFIG) {
		_log_err("%s reply from '%s' for txn-id: %Lu failed wrong txn TYPE %u, resetting connection",
			 tag, adapter->name, txn_id, txn->type);
		return NULL;
	}
	ccreq = txn_txn_req_commit(txn);
	if (!ccreq) {
		_log_err("%s reply from '%s' for txn-id: %Lu failed no COMMITCFG_REQ, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	/* make sure we are part of this config commit */
	if (!IS_IDBIT_SET(ccreq->clients, adapter->id)) {
		_log_err("%s reply from '%s' for txn-id %Lu not participating, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	return ccreq;
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_notify_be_cfg_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct txn_req_commit *ccreq = txn_ensure_be_cfg_msg(txn_id, adapter, "CFG_REPLY");

	if (!ccreq)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_handle_cfg_reply(ccreq, true, NULL, adapter);
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_notify_be_cfg_apply_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct txn_req_commit *ccreq = txn_ensure_be_cfg_msg(txn_id, adapter, "CFG_APPLY");

	if (!ccreq)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_cfg_adapter_acked(ccreq, adapter);
}

/**
 * Send get-tree requests to each client indicated in `clients` bitmask, which
 * has registered operational state that matches the given `xpath`
 */
int mgmt_txn_send_get_tree(uint64_t txn_id, uint64_t req_id, uint64_t clients,
			   enum mgmt_ds_id ds_id, LYD_FORMAT result_type, uint8_t flags,
			   uint32_t wd_options, bool simple_xpath, struct lyd_node **ylib,
			   const char *xpath)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_get_tree *msg;
	struct txn_req_get_tree *get_tree;
	struct mgmt_txn *txn;
	enum mgmt_be_client_id id;
	ssize_t slen = strlen(xpath);

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	/* If error in this function below here, be sure to free the req */
	get_tree = txn_req_get_tree_alloc(txn, req_id);
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
		struct mgmt_ds_ctx *ds = mgmt_ds_get_ctx_by_id(mm, ds_id == MGMTD_DS_OPERATIONAL
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
						     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS |
							     LYD_DUP_RECURSIVE,
						     &get_tree->client_results);
				if (!err)
					while (get_tree->client_results->parent)
						get_tree->client_results =
							lyd_parent(get_tree->client_results);
			} else if (set->count > 1) {
				err = lyd_dup_siblings(config->dnode, NULL,
						       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
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
		return txn_get_tree_data_done(get_tree);

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_get_tree, slen + 1,
					MTYPE_MSG_NATIVE_GET_TREE);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_TREE;
	/* Always operate with the binary format in the backend */
	msg->result_type = LYD_LYB;
	strlcpy(msg->xpath, xpath, slen + 1);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(get_tree->clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	get_tree->clients_wait = get_tree->clients;
	if (!get_tree->clients_wait)
		return txn_get_tree_data_done(get_tree);

	/* Start timeout timer - pulled out of register event code so we can
	 * pass a different arg
	 */
	event_add_timer(mgmt_txn_tm, txn_get_tree_timeout, get_tree,
			MGMTD_TXN_GET_TREE_MAX_DELAY_SEC, &get_tree->req.timeout);
	return 0;
}

int mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients,
		      LYD_FORMAT result_type, const char *xpath,
		      const char *data, size_t data_len)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_txn *txn;
	struct mgmt_msg_rpc *msg;
	struct txn_req_rpc *rpc;
	enum mgmt_be_client_id id;

	txn = mgmt_txn_id2ctx(txn_id);
	if (!txn)
		return -1;

	rpc = txn_req_rpc_alloc(txn, req_id);
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
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(rpc->clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	rpc->clients_wait = rpc->clients;
	if (!rpc->clients_wait)
		return txn_rpc_done(rpc);

	event_add_timer(mgmt_txn_tm, txn_rpc_timeout, rpc,
			MGMTD_TXN_RPC_MAX_DELAY_SEC, &rpc->req.timeout);

	return 0;
}

int mgmt_txn_send_notify_selectors(uint64_t req_id, uint64_t session_id, uint64_t clients,
				   const char **selectors)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_notify_select *msg;
	enum mgmt_be_client_id id;
	char **all_selectors = NULL;
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
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
	}
	mgmt_msg_native_free_msg(msg);

	if (all_selectors)
		darr_free_free(all_selectors);

	return 0;
}

/*
 * Error reply from the backend client.
 *
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_notify_error(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
			   uint64_t req_id, int error, const char *errstr)
{
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req_get_tree *get_tree;
	struct txn_req_commit *ccreq;
	struct txn_req_rpc *rpc;
	struct txn_req *txn_req;

	if (!txn) {
		_log_err("Error reply from %s cannot find txn-id %" PRIu64, adapter->name, txn_id);
		return;
	}

	if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
		/*
		 * Handle an error during a configuration transaction.
		 */
		ccreq = txn_ensure_be_cfg_msg(txn_id, adapter, "ERROR");
		if (!ccreq) {
			msg_conn_disconnect(adapter->conn, false);
			return;
		}
		/*
		 * We only handle errors in reply to our CFG_REQ messages (due
		 * to validation/preparation). Otherwise, this is an error
		 * during some other phase of the commit process and we
		 * disconnect the client and start over.
		 */
		if (ccreq->phase == MGMTD_COMMIT_PHASE_SEND_CFG)
			txn_handle_cfg_reply(ccreq, false, errstr, adapter);
		else
			/* Drop the connection these errors should never happen */
			msg_conn_disconnect(adapter->conn, false);
		return;
	}

	/*
	 * Find the non-config request.
	 */

	TAILQ_FOREACH (txn_req, &txn->reqs, link)
		if (txn_req->req_id == req_id)
			break;
	if (!txn_req) {
		_log_err("Error reply from %s for txn-id %" PRIu64 " cannot find req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return;
	}

	_log_err("Error reply from %s for txn-id %" PRIu64 " req_id %" PRIu64, adapter->name,
		 txn_id, req_id);

	switch (txn_req->req_type) {
	case TXN_REQ_TYPE_GETTREE:
		get_tree = into_get_tree_req(txn_req);
		UNSET_IDBIT(get_tree->clients_wait, id);
		get_tree->partial_error = error;

		/* check if done yet */
		if (!get_tree->clients_wait)
			txn_get_tree_data_done(get_tree);
		return;
	case TXN_REQ_TYPE_RPC:
		rpc = into_rpc_req(txn_req);
		UNSET_IDBIT(rpc->clients_wait, id);
		if (errstr)
			darr_in_strdup(rpc->req.err_info, errstr);
		/* check if done yet */
		if (!rpc->clients_wait)
			txn_rpc_done(rpc);
		return;

	/* non-native message events */
	case TXN_REQ_TYPE_COMMIT:
	default:
		assert(!"non-native req type in native error path");
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
	struct mgmt_txn *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	if (!txn) {
		_log_err("GETTREE reply from %s for a missing txn-id %" PRIu64, adapter->name,
			 txn_id);
		return -1;
	}

	/* Find the request. */
	txn_req = txn_txn_req(txn, req_id);
	if (!txn_req || txn_req->req_type != TXN_REQ_TYPE_GETTREE) {
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}
	get_tree = into_get_tree_req(txn_req);

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
		UNSET_IDBIT(get_tree->clients_wait, id);

	/* check if done yet */
	if (get_tree->clients_wait)
		return 0;

	return txn_get_tree_data_done(get_tree);
}

int mgmt_txn_notify_rpc_reply(struct mgmt_be_client_adapter *adapter,
			      struct mgmt_msg_rpc_reply *reply_msg,
			      size_t msg_len)
{
	uint64_t txn_id = reply_msg->refer_id;
	uint64_t req_id = reply_msg->req_id;
	enum mgmt_be_client_id id = adapter->id;
	struct mgmt_txn *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req *txn_req;
	struct txn_req_rpc *rpc;
	struct lyd_node *tree;
	size_t data_len = msg_len - sizeof(*reply_msg);
	LY_ERR err = LY_SUCCESS;

	if (!txn) {
		_log_err("RPC reply from %s for a missing txn-id %" PRIu64, adapter->name, txn_id);
		return -1;
	}

	/* Find the request. */
	txn_req = txn_txn_req(txn, req_id);
	if (!txn_req || txn_req->req_type != TXN_REQ_TYPE_RPC) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return -1;
	}
	rpc = into_rpc_req(txn_req);

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
	if (err)
		darr_in_strdup(rpc->req.err_info, "Cannot parse result from the backend");

	UNSET_IDBIT(rpc->clients_wait, id);

	/* check if done yet */
	if (rpc->clients_wait)
		return 0;

	return txn_rpc_done(rpc);
}

void mgmt_txn_status_write(struct vty *vty)
{
	struct mgmt_txn *txn;
	uint count = 0;

	vty_out(vty, "MGMTD Transactions\n");

	TAILQ_FOREACH (txn, &txn_txns, link) {
		vty_out(vty, "  Txn: \t\t\t0x%p\n", txn);
		vty_out(vty, "    Txn-Id: \t\t\t%" PRIu64 "\n", txn->txn_id);
		vty_out(vty, "    Session-Id: \t\t%" PRIu64 "\n", txn->session_id);
		vty_out(vty, "    Type: \t\t\t%s\n", mgmt_txn_type2str(txn->type));
		vty_out(vty, "    Ref-Count: \t\t\t%d\n", txn->refcount);
		count++;
	}
	vty_out(vty, "  Total: %u\n", count);
}

int mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_ds_ctx *src_ds_ctx,
					struct mgmt_ds_ctx *dst_ds_ctx)
{
	static struct mgmt_commit_stats dummy_stats = { 0 };

	struct nb_config_cbs changes = { 0 };
	struct mgmt_txn *txn;
	struct txn_req *txn_req;
	struct txn_req_commit *ccreq;
	int ret;

	/*
	 * This could be the case when the config is directly
	 * loaded onto the candidate DS from a file. Get the
	 * diff from a full comparison of the candidate and
	 * running DSs.
	 */
	nb_config_diff(mgmt_ds_get_nb_config(dst_ds_ctx),
		       mgmt_ds_get_nb_config(src_ds_ctx), &changes);

	if (RB_EMPTY(nb_config_cbs, &changes))
		return -1;

	/*
	 * Create a CONFIG transaction to push the config changes
	 * provided to the backend client.
	 */
	txn = mgmt_txn_create_new(0, MGMTD_TXN_TYPE_CONFIG);
	if (!txn) {
		_log_err("Failed to create CONFIG Transaction for downloading CONFIGs");
		nb_config_diff_del_changes(&changes);
		return -1;
	}

	_dbg("Created rollback txn-id: %" PRIu64, txn->txn_id);

	/*
	 * Set the changeset for transaction to commit and trigger the commit
	 * request.
	 */
	ccreq = txn_req_commit_alloc(txn, 0);
	txn_req = into_txn_req(ccreq);
	ccreq->src_ds_id = MGMTD_DS_CANDIDATE;
	ccreq->src_ds_ctx = src_ds_ctx;
	ccreq->dst_ds_id = MGMTD_DS_RUNNING;
	ccreq->dst_ds_ctx = dst_ds_ctx;
	ccreq->validate_only = false;
	ccreq->abort = false;
	ccreq->rollback = true;
	ccreq->cmt_stats = &dummy_stats;

	/*
	 * Send the changes.
	 */
	ret = txn_send_config_changes(ccreq, &changes, 0);
	if (ret)
		txn_finish_commit(ccreq, txn_req->error, txn_req->err_info);
	return ret;
}
