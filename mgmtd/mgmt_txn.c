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

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_warn(fmt, ...) zlog_warn("%s: WARNING: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define MGMTD_TXN_LOCK(txn)   mgmt_txn_lock(txn, __FILE__, __LINE__)
#define MGMTD_TXN_UNLOCK(txn, in_hash_free) mgmt_txn_unlock(txn, in_hash_free, __FILE__, __LINE__)

enum mgmt_txn_req_type {
	MGMTD_TXN_PROC_COMMITCFG = 1,
	MGMTD_TXN_PROC_GETTREE,
	MGMTD_TXN_PROC_RPC,
};

PREDECL_LIST(mgmt_txn_reqs);

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

struct mgmt_edit_req {
	char xpath_created[XPATH_MAXLEN];
	bool created;
	bool unlock;
};

struct mgmt_commit_cfg_req {
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
	uint8_t unlock : 1;

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
		/*
		 * XXX Make the sub-structure variants either allocated or
		 * embedded -- not both; embedding only the commit_cfg variant
		 * makes little sense since it is the largest of the variants
		 * though!
		 */
		struct txn_req_get_tree *get_tree;
		struct txn_req_rpc *rpc;
		struct mgmt_commit_cfg_req commit_cfg;
	} req;

	/* So far used by commit_cfg to expand to others */
	enum mgmt_result error; /* MGMTD return code */
	char *err_info;		/* darr str */

	struct mgmt_txn_reqs_item list_linkage;
};

DECLARE_LIST(mgmt_txn_reqs, struct mgmt_txn_req, list_linkage);

#define FOREACH_TXN_REQ_IN_LIST(list, req)                                     \
	frr_each_safe (mgmt_txn_reqs, list, req)

struct mgmt_txn_ctx {
	uint64_t session_id; /* One transaction per client session */
	uint64_t txn_id;
	enum mgmt_txn_type type;

	struct event *proc_comm_cfg;
	struct event *proc_get_tree;
	struct event *comm_cfg_timeout;
	struct event *get_tree_timeout;
	struct event *rpc_timeout;
	struct event *clnup;

	int refcount;

	struct mgmt_txns_item list_linkage;

	/*
	 * List of pending requests.
	 */
	struct mgmt_txn_reqs_head reqs;

	/*
	 * There will always be one commit-config allowed for a given
	 * transaction/session. Keep a pointer to it for quick access.
	 */
	struct mgmt_txn_req *commit_cfg_req;
};

DECLARE_LIST(mgmt_txns, struct mgmt_txn_ctx, list_linkage);

#define FOREACH_TXN_IN_LIST(mm, txn)                                           \
	frr_each_safe (mgmt_txns, &(mm)->txn_list, (txn))

static inline const char *mgmt_txn_commit_phase_str(struct mgmt_txn_req *txn_req)
{
	return mgmt_commit_phase_name[txn_req->req.commit_cfg.phase];
}

static void mgmt_txn_lock(struct mgmt_txn_ctx *txn, const char *file, int line);
static void mgmt_txn_unlock(struct mgmt_txn_ctx **txn, bool in_hash_free, const char *file,
			    int line);

static struct event_loop *mgmt_txn_tm;
static struct mgmt_master *mgmt_txn_mm;

static void mgmt_txn_cleanup_txn(struct mgmt_txn_ctx **txn);

static void mgmt_txn_cfg_commit_timedout(struct event *thread);
static void txn_cfg_send_cfg_apply(struct mgmt_txn_req *txn_req);

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
		/*
		 * XXX Not allocated, makes no sense to have some allocated and
		 * some not, and this embedded one is the largest of the lot
		 */

		txn->commit_cfg_req = txn_req;
		_dbg("Added a new COMMITCFG req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);

		break;
	case MGMTD_TXN_PROC_GETTREE:
		txn_req->req.get_tree = XCALLOC(MTYPE_MGMTD_TXN_GETTREE_REQ,
						sizeof(struct txn_req_get_tree));

		_dbg("Added a new GETTREE req-id: %" PRIu64 " txn-id: %" PRIu64
		     " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	case MGMTD_TXN_PROC_RPC:
		txn_req->req.rpc = XCALLOC(MTYPE_MGMTD_TXN_RPC_REQ, sizeof(struct txn_req_rpc));

		_dbg("Added a new RPC req-id: %" PRIu64 " txn-id: %" PRIu64 " session-id: %" PRIu64,
		     txn_req->req_id, txn->txn_id, txn->session_id);
		break;
	}

	mgmt_txn_reqs_add_tail(&txn->reqs, txn_req);

	MGMTD_TXN_LOCK(txn);

	return txn_req;
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

static void txn_cfg_cleanup(struct mgmt_txn_req *txn_req)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;
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
}

static void mgmt_txn_req_free(struct mgmt_txn_req **txn_req)
{
	struct mgmt_txn_ctx *txn = (*txn_req)->txn;
	struct mgmt_txn_req *safe_req = NULL;
	uint64_t txn_id = txn->txn_id;

	switch ((*txn_req)->req_type) {
	case MGMTD_TXN_PROC_COMMITCFG:
		/* prevent recursion */
		safe_req = *txn_req;
		*txn_req = NULL;
		txn_req = &safe_req;
		txn_cfg_cleanup(*txn_req);
		/* NOTE: config request state is not allocated separately */
		break;
	case MGMTD_TXN_PROC_GETTREE:
		_dbg("Deleting GETTREE req-id: %" PRIu64 " of txn-id: %" PRIu64,
		     (*txn_req)->req_id, txn_id);
		lyd_free_all((*txn_req)->req.get_tree->client_results);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.get_tree->xpath);
		XFREE(MTYPE_MGMTD_TXN_GETTREE_REQ, (*txn_req)->req.get_tree);
		break;
	case MGMTD_TXN_PROC_RPC:
		_dbg("Deleting RPC req-id: %" PRIu64 " txn-id: %" PRIu64, (*txn_req)->req_id,
		     txn_id);
		lyd_free_all((*txn_req)->req.rpc->client_results);
		XFREE(MTYPE_MGMTD_ERR, (*txn_req)->req.rpc->errstr);
		XFREE(MTYPE_MGMTD_XPATH, (*txn_req)->req.rpc->xpath);
		XFREE(MTYPE_MGMTD_TXN_RPC_REQ, (*txn_req)->req.rpc);
		break;
	}

	mgmt_txn_reqs_del(&txn->reqs, *txn_req);
	_dbg("Removed req-id: %Lu from request-list (left:%zu)", (*txn_req)->req_id,
	     mgmt_txn_reqs_count(&txn->reqs));

	darr_free((*txn_req)->err_info);
	MGMTD_TXN_UNLOCK(&(*txn_req)->txn, false);
	XFREE(MTYPE_MGMTD_TXN_REQ, (*txn_req));
	*txn_req = NULL;
}

static int txn_set_config_error(struct mgmt_txn_req *txn_req, enum mgmt_result error,
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
static void txn_finish_commit(struct mgmt_txn_req *txn_req, enum mgmt_result result,
			      const char *error_if_any)
{
	bool success, apply_op, accept_changes, discard_changes;
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;
	struct mgmt_txn_ctx *txn = txn_req->txn;
	int ret;

	success = (result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES);

	/*
	 * Send reply to front-end session (if any).
	 */
	if (!txn->session_id)
		ret = 0; /* No front-end session to reply to (rollback or init) */
	else if (!ccreq->edit)
		/* This means we are in the mgmtd CLI vty code */
		ret = mgmt_fe_send_commit_cfg_reply(txn->session_id, txn->txn_id, ccreq->src_ds_id,
						    ccreq->dst_ds_id, txn_req->req_id,
						    ccreq->validate_only, ccreq->unlock, result,
						    error_if_any);
	else
		ret = mgmt_fe_adapter_send_edit_reply(txn->session_id, txn->txn_id,
						      txn_req->req_id, ccreq->edit->unlock, true,
						      ccreq->edit->created,
						      ccreq->edit->xpath_created, success ? 0 : -1,
						      error_if_any);
	if (ret)
		_log_err("Failed sending config reply for txn-id: %Lu session-id: %Lu",
			 txn->txn_id, txn->session_id);
	/*
	 * Stop the commit-timeout timer.
	 */
	event_cancel(&txn->comm_cfg_timeout);

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
	 *    If this is a successful abort, or a failed immediate-effect config
	 *    operation. Failed means no backend clients have been told to apply
	 *    the config yet, and immediate-effect config ops are from classic
	 *    CLI interface (unlock set) or edit messages with implicit commit
	 *    indicated (implicit set, e.g., as used by clients like RESTCONF).
	 *
	 *    In particular when doing validate-only operation (`commit check`)
	 *    the candidate shouldn't revert, the user will expect to keep
	 *    modifying it to make it valid.
	 *
	 *    NOTE: the mgmtd front-end adapter code should ideally be doing
	 *    this candidate restore itself as it is the one modifying the
	 *    candidate datastore. So this is sloppy. This code is handling a
	 *    commit request so it is either accepting the changes into running
	 *    or it is not.
	 *
	 * It would be nice to reduce options to better represent some of the
	 * mutual exclusivity, not all variations are valid (e.g., validate_only
	 * will never be set with abort or init or rollback or when doing
	 * immediate-effect operations).
	 */
	apply_op = !ccreq->validate_only && !ccreq->abort && !ccreq->init;
	accept_changes = ccreq->phase >= MGMTD_COMMIT_PHASE_APPLY_CFG && apply_op;
	discard_changes = (result == MGMTD_SUCCESS && ccreq->abort) ||
			  (apply_op && ccreq->phase < MGMTD_COMMIT_PHASE_APPLY_CFG &&
			   (ccreq->implicit || ccreq->unlock));

	if (accept_changes) {
		bool create_cmt_info_rec = (result != MGMTD_NO_CFG_CHANGES && !ccreq->rollback);

		mgmt_ds_copy_dss(ccreq->dst_ds_ctx, ccreq->src_ds_ctx, create_cmt_info_rec);
	}
	if (discard_changes)
		mgmt_ds_copy_dss(ccreq->src_ds_ctx, ccreq->dst_ds_ctx, false);

	if (ccreq->rollback) {
		mgmt_ds_unlock(ccreq->src_ds_ctx);
		mgmt_ds_unlock(ccreq->dst_ds_ctx);
		/*
		 * Resume processing the rollback command.
		 *
		 * TODO: there's no good reason to special case rollback, the
		 * rollback boolean should be passed back to the FE client and it
		 * can do the right thing.
		 */
		mgmt_history_rollback_complete(success);
	}

	if (ccreq->init) {
		/*
		 * This is the backend init request.
		 * We need to unlock the running datastore.
		 */
		mgmt_ds_unlock(ccreq->dst_ds_ctx);
	}

	ccreq->cmt_stats = NULL;
	mgmt_txn_req_free(&txn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!txn->session_id)
		mgmt_txn_cleanup_txn(&txn);
}

static void txn_cfg_next_phase(struct mgmt_txn_req *txn_req)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;

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
	     mgmt_txn_commit_phase_str(txn_req));

	switch (ccreq->phase) {
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		txn_cfg_send_cfg_apply(txn_req);
		break;
	case MGMTD_COMMIT_PHASE_FINISH:
		if (mm->perf_stats_en)
			gettimeofday(&ccreq->cmt_stats->txn_del_start, NULL);
		txn_finish_commit(txn_req, MGMTD_SUCCESS, NULL);
		return;
	case MGMTD_COMMIT_PHASE_SEND_CFG:
	default:
		assert(!"Invalid commit phase transition to SEND_CFG");
	}
}

static void txn_cfg_adapter_acked(struct mgmt_txn_req *txn_req,
				  struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *ccreq = &txn_req->req.commit_cfg;

	_dbg("CONFIG-STATE-MACHINE txn-id: %Lu in state: %s", txn_req->txn->txn_id,
	     mgmt_txn_commit_phase_str(txn_req));

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

	txn_cfg_next_phase(txn_req);
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

static int txn_make_and_send_cfg_msgs(struct mgmt_txn_req *txn_req,
				      const struct nb_config_cbs *changes,
				      uint64_t init_client_mask)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	struct nb_config_cbs mgmtd_changes = { 0 };
	char *xpath = NULL, *value = NULL;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_msg_cfg_req **cfg_msgs = NULL;
	char **cfg_actions = NULL;
	uint64_t *num_cfg_data = NULL;
	bool mgmtd_interest;
	uint batch_items = 0;
	uint num_chgs = 0;
	uint64_t clients, chg_clients;
	char op;
	int ret = -1;

	cmtcfg_req = &txn_req->req.commit_cfg;

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

		cmtcfg_req->clients |= chg_clients;

		free(xpath);
	}
	cmtcfg_req->cmt_stats->last_batch_cnt = batch_items;

	if (!RB_EMPTY(nb_config_cbs, &mgmtd_changes)) {
		/* Create a northbound transaction for local mgmtd config changes */
		char errmsg[BUFSIZ] = { 0 };
		size_t errmsg_len = sizeof(errmsg);
		struct nb_context nb_ctx = { 0 };

		_dbg("Processing mgmtd bound changes");

		assert(!cmtcfg_req->mgmtd_nb_txn);
		nb_ctx.client = NB_CLIENT_MGMTD_SERVER;

		/* Prepare the mgmtd local config changes */
		/*
		 * This isn't calling the VALIDATE callback, it's just
		 * running PREPARE. See #19948
		 */
		if (nb_changes_commit_prepare(nb_ctx, mgmtd_changes, "mgmtd-changes", NULL,
					      &cmtcfg_req->mgmtd_nb_txn, errmsg, errmsg_len)) {
			_log_err("Failed to prepare local config for mgmtd: %s", errmsg);
			if (cmtcfg_req->mgmtd_nb_txn) {
				nb_candidate_commit_abort(cmtcfg_req->mgmtd_nb_txn, NULL, 0);
				cmtcfg_req->mgmtd_nb_txn = NULL;
			}
			(void)txn_set_config_error(txn_req, MGMTD_INTERNAL_ERROR,
						   "Failed to prepare local config for mgmtd");
			goto done;
		}
		assert(cmtcfg_req->mgmtd_nb_txn);
	}

	/* Record txn create start time */
	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->txn_create_start, NULL);

	/* Send the messages to the backends */
	FOREACH_BE_ADAPTER_BITS (id, adapter, cmtcfg_req->clients) {
		/* NUL terminate actions string and add to tail of message */
		darr_push(cfg_actions[id], 0);
		mgmt_msg_native_add_str(cfg_msgs[id], cfg_actions[id]);
		_dbg("Finished CFG_REQ for '%s' txn-id: %Lu with actions: %s", adapter->name,
		     txn_req->txn->txn_id, cfg_actions[id]);

		if (mgmt_be_send_native(adapter, cfg_msgs[id])) {
			/* remove this client and reset the connection */
			UNSET_IDBIT(cmtcfg_req->clients, id);
			msg_conn_disconnect(adapter->conn, false);
		}
		cmtcfg_req->cmt_stats->last_num_cfgdata_reqs++;
	}
	/* Record who we are waiting for */
	cmtcfg_req->clients_wait = cmtcfg_req->clients;

	if (cmtcfg_req->clients) {
		/* set a timeout for hearing back from the backend clients */
		event_add_timer(mgmt_txn_tm, mgmt_txn_cfg_commit_timedout, txn_req->txn,
				MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC,
				&txn_req->txn->comm_cfg_timeout);
	} else {
		/* We have no connected interested clients */
		if (cmtcfg_req->mgmtd_nb_txn)
			_dbg("No connected and interested backend clients, proceed with mgmtd local changes");
		else
			_dbg("No connected and interested backend clients, proceed to apply changes");
		txn_cfg_adapter_acked(txn_req, NULL);
	}

	ret = 0;
done:
	darr_free(num_cfg_data);
	darr_free_func(cfg_msgs, mgmt_msg_native_free_msg);
	darr_free_free(cfg_actions);
	return ret;
}

static int txn_send_config_changes(struct mgmt_txn_ctx *txn, struct nb_config_cbs *cfg_chgs,
				   uint64_t init_client_mask);

/*
 * Prepare and send config changes by comparing the source and destination
 * datastores.
 */
static int txn_get_config_changes(struct mgmt_txn_ctx *txn, struct nb_config_cbs *cfg_chgs)
{
	struct nb_config *nb_config;
	struct mgmt_txn_req *txn_req = txn->commit_cfg_req;
	int ret = 0;

	if (txn->commit_cfg_req->req.commit_cfg.src_ds_id != MGMTD_DS_CANDIDATE) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "Source DS cannot be any other than CANDIDATE!");
	}

	if (txn->commit_cfg_req->req.commit_cfg.dst_ds_id != MGMTD_DS_RUNNING) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "Destination DS cannot be any other than RUNNING!");
	}

	if (!txn->commit_cfg_req->req.commit_cfg.src_ds_ctx) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "No such source datastore!");
	}

	if (!txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx) {
		return txn_set_config_error(txn_req, MGMTD_INVALID_PARAM,
					    "No such destination datastore!");
	}

	if (txn->commit_cfg_req->req.commit_cfg.abort) {
		/*
		 * This is a commit abort request. Return back success.
		 * The reply routing special cases abort, this isn't pretty,
		 * fix in later cleanup.
		 */
		return txn_set_config_error(txn->commit_cfg_req, MGMTD_SUCCESS, "commit abort");
	}

	nb_config = mgmt_ds_get_nb_config(txn->commit_cfg_req->req.commit_cfg.src_ds_ctx);
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

	nb_config_diff(mgmt_ds_get_nb_config(txn->commit_cfg_req->req.commit_cfg.dst_ds_ctx),
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
static int txn_send_config_changes(struct mgmt_txn_ctx *txn, struct nb_config_cbs *cfg_chgs,
				   uint64_t init_client_mask)
{
	int ret;

	if (mm->perf_stats_en)
		gettimeofday(&txn->commit_cfg_req->req.commit_cfg.cmt_stats->prep_cfg_start, NULL);

	ret = txn_make_and_send_cfg_msgs(txn->commit_cfg_req, cfg_chgs, init_client_mask);
	nb_config_diff_del_changes(cfg_chgs);
	return ret;
}


static void mgmt_txn_cfg_commit_timedout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_commit_cfg_req *ccreq;

	txn = (struct mgmt_txn_ctx *)EVENT_ARG(event);
	assert(txn);
	assert(txn->type == MGMTD_TXN_TYPE_CONFIG);
	txn_req = txn->commit_cfg_req;
	if (!txn_req)
		return;
	ccreq = &txn_req->req.commit_cfg;

	/*
	 * If we are applying changes we need to return SUCCESS as there is no
	 * way to abort those. Slow backends that haven't replied yet will be
	 * disconnected. If we are still sending config for validate/prepare
	 * phase we return an error and abort the commit.
	 */
	if (ccreq->phase < MGMTD_COMMIT_PHASE_APPLY_CFG) {
		_log_err("Backend timeout validating txn-id: %Lu waiting: 0x%Lx aborting commit",
			 txn->txn_id, ccreq->clients_wait);
		txn_finish_commit(txn_req, MGMTD_INTERNAL_ERROR,
				  "Some backend clients taking too long to validate the changes.");
	} else {
		_log_warn("Backend timeout applying txn-id: %Lu waiting: 0x%Lx, applying commit",
			  txn->txn_id, ccreq->clients_wait);
		txn_finish_commit(txn_req, MGMTD_SUCCESS,
				  "Some backend clients taking too long to apply the changes.");
	}
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

static void txn_get_tree_timeout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(event);
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

static void txn_rpc_timeout(struct event *event)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;

	txn_req = (struct mgmt_txn_req *)EVENT_ARG(event);
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
 */
static void txn_cfg_send_cfg_apply(struct mgmt_txn_req *txn_req)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_msg_cfg_apply_req *msg;
	uint64_t txn_id = txn_req->txn->txn_id;

	assert(txn_req->txn->type == MGMTD_TXN_TYPE_CONFIG);

	cmtcfg_req = &txn_req->req.commit_cfg;
	assert(!cmtcfg_req->validate_only);

	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_start, NULL);
	/*
	 * Handle mgmtd internal special case
	 */
	if (cmtcfg_req->mgmtd_nb_txn) {
		char errmsg[BUFSIZ] = { 0 };

		_dbg("Applying mgmtd local bound changes");

		(void)nb_candidate_commit_apply(cmtcfg_req->mgmtd_nb_txn, false, NULL, errmsg,
						sizeof(errmsg));
		cmtcfg_req->mgmtd_nb_txn = NULL;
	}

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_apply_req, 0,
					MTYPE_MSG_NATIVE_CFG_APPLY_REQ);
	msg->code = MGMT_MSG_CODE_CFG_APPLY_REQ;
	msg->refer_id = txn_id;
	FOREACH_BE_ADAPTER_BITS (id, adapter, cmtcfg_req->clients) {
		if (mgmt_be_send_native(adapter, msg)) {
			msg_conn_disconnect(adapter->conn, false);
			continue;
		}
		SET_IDBIT(cmtcfg_req->clients_wait, id);
		cmtcfg_req->cmt_stats->last_num_apply_reqs++;
	}
	mgmt_msg_native_free_msg(msg);

	if (!cmtcfg_req->clients_wait) {
		_dbg("No backends to wait for on CFG_APPLY for txn-id: %Lu", txn_id);
		txn_cfg_adapter_acked(txn_req, NULL);
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
		mgmt_txn_reqs_init(&txn->reqs);
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

/**
 * mgmt_txn_send_commit_config_req() - Send a commit config request
 * @txn_id - A config TXN which must exist.
 *
 * Return: -1 on setup failure -- should immediately handle error, Otherwise 0
 * and will reply to session with any downstream error.
 */
int mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id src_ds_id,
				    struct mgmt_ds_ctx *src_ds_ctx, enum mgmt_ds_id dst_ds_id,
				    struct mgmt_ds_ctx *dst_ds_ctx, bool validate_only, bool abort,
				    bool implicit, bool unlock, struct mgmt_edit_req *edit)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct nb_config_cbs changes = { 0 };

	txn = mgmt_txn_id2ctx(txn_id);
	assert(txn && txn->type == MGMTD_TXN_TYPE_CONFIG && txn->commit_cfg_req == NULL);

	txn_req = mgmt_txn_req_alloc(txn, req_id, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = src_ds_id;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = dst_ds_id;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = validate_only;
	txn_req->req.commit_cfg.abort = abort;
	txn_req->req.commit_cfg.implicit = implicit; /* this is only true iff edit */
	txn_req->req.commit_cfg.unlock = unlock; /* this is true for implicit commit in front-end */
	txn_req->req.commit_cfg.edit = edit;
	txn_req->req.commit_cfg.cmt_stats =
		mgmt_fe_get_session_commit_stats(txn->session_id);

	int ret = txn_get_config_changes(txn, &changes);
	if (ret == 0)
		ret = txn_send_config_changes(txn, &changes, 0);
	if (ret)
		txn_finish_commit(txn_req, txn_req->error, txn_req->err_info);
	return 0;
}

int mgmt_txn_notify_be_adapter_conn(struct mgmt_be_client_adapter *adapter,
				    bool connect)
{
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_commit_cfg_req *cmtcfg_req;
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
		 * Lock the running datastore to prevent any changes while we
		 * are initializing the backend.
		 */
		if (mgmt_ds_lock(ds_ctx, 0) != 0) {
			_dbg("Failed to lock DS:%s for init of BE adapter '%s'",
			     mgmt_ds_id2name(MGMTD_DS_RUNNING), adapter->name);
			return -1;
		}

		/* Get config for this single backend client */
		mgmt_be_get_adapter_config(adapter, &adapter_cfgs);
		if (!adapter_cfgs || RB_EMPTY(nb_config_cbs, adapter_cfgs)) {
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
		memset(&adapter->cfg_stats, 0, sizeof(adapter->cfg_stats));
		txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
		txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_NONE;
		txn_req->req.commit_cfg.src_ds_ctx = 0;
		txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
		txn_req->req.commit_cfg.dst_ds_ctx = ds_ctx;
		txn_req->req.commit_cfg.validate_only = false;
		txn_req->req.commit_cfg.abort = false;
		txn_req->req.commit_cfg.init = true;
		txn_req->req.commit_cfg.cmt_stats = &adapter->cfg_stats;

		/*
		 * Apply the initial changes.
		 */
		return txn_send_config_changes(txn, adapter_cfgs, 1ull << adapter->id);
	} else {
		/*
		 * Check if any transaction is currently on-going that
		 * involves this backend client. If so check if we can now
		 * advance that configuration.
		 */
		FOREACH_TXN_IN_LIST (mgmt_txn_mm, txn) {
			/* XXX update to handle get-tree and RPC too! */
			if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
				cmtcfg_req = txn->commit_cfg_req
						     ? &txn->commit_cfg_req->req.commit_cfg
						     : NULL;
				if (!cmtcfg_req)
					continue;

				UNSET_IDBIT(cmtcfg_req->clients, adapter->id);
				if (IS_IDBIT_SET(cmtcfg_req->clients_wait, adapter->id))
					txn_cfg_adapter_acked(txn->commit_cfg_req, adapter);
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
static void txn_handle_cfg_reply(struct mgmt_txn_req *txn_req, bool success,
				 const char *error_if_any, struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_commit_cfg_req *cmtcfg_req = &txn_req->req.commit_cfg;

	assert(cmtcfg_req);

	if (!IS_IDBIT_SET(cmtcfg_req->clients_wait, adapter->id)) {
		_log_warn("CFG_REPLY from '%s' but not waiting for it for txn-id: %Lu, resetting connection",
			  adapter->name, txn_req->txn->txn_id);
		msg_conn_disconnect(adapter->conn, false);
		return;
	}

	if (success)
		_dbg("CFG_REPLY from '%s'", adapter->name);
	else {
		_log_err("CFG_REQ to '%s' failed err: %s", adapter->name, error_if_any ?: "None");
		txn_finish_commit(txn_req, MGMTD_VALIDATION_ERROR,
				  error_if_any ?: "config validation failed by backend daemon");
		return;
	}

	txn_cfg_adapter_acked(txn_req, adapter);
}

static struct mgmt_txn_req *
txn_ensure_be_cfg_msg(uint64_t txn_id, struct mgmt_be_client_adapter *adapter, const char *tag)
{
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct mgmt_txn_req *txn_req;

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
	txn_req = txn->commit_cfg_req;
	if (!txn_req) {
		_log_err("%s reply from '%s' for txn-id: %Lu failed no COMMITCFG_REQ, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	/* make sure we are part of this config commit */
	if (!IS_IDBIT_SET(txn_req->req.commit_cfg.clients, adapter->id)) {
		_log_err("%s reply from '%s' for txn-id %Lu not participating, resetting connection",
			 tag, adapter->name, txn_id);
		return NULL;
	}
	return txn_req;
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_notify_be_cfg_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_req *txn_req = txn_ensure_be_cfg_msg(txn_id, adapter, "CFG_REPLY");

	if (!txn_req)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_handle_cfg_reply(txn_req, true, NULL, adapter);
}

/*
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_notify_be_cfg_apply_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_txn_req *txn_req = txn_ensure_be_cfg_msg(txn_id, adapter, "CFG_APPLY");

	if (!txn_req)
		msg_conn_disconnect(adapter->conn, false);
	else
		txn_cfg_adapter_acked(txn_req, adapter);
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
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	enum mgmt_be_client_id id;
	ssize_t slen = strlen(xpath);

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
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(get_tree->sent_clients, id);
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

int mgmt_txn_send_edit(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id ds_id,
		       struct mgmt_ds_ctx *ds_ctx, enum mgmt_ds_id commit_ds_id,
		       struct mgmt_ds_ctx *commit_ds_ctx, bool unlock, bool commit,
		       LYD_FORMAT request_type, uint8_t flags, uint8_t operation,
		       const char *xpath, const char *data)
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
		if (mgmt_txn_send_commit_config_req(txn_id, req_id, ds_id, ds_ctx, commit_ds_id,
						    commit_ds_ctx, false, false, true /*implicit*/,
						    false /*unlock*/, edit)) {
			ret = NB_ERR;
			goto reply;
		}
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
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
	struct mgmt_msg_rpc *msg;
	struct txn_req_rpc *rpc;
	enum mgmt_be_client_id id;

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
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		if (mgmt_be_send_native(adapter, msg))
			continue;
		SET_IDBIT(rpc->sent_clients, id);
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
	struct mgmt_txn_ctx *txn = mgmt_txn_id2ctx(txn_id);
	struct txn_req_get_tree *get_tree;
	struct txn_req_rpc *rpc;
	struct mgmt_txn_req *txn_req;

	if (!txn) {
		_log_err("Error reply from %s cannot find txn-id %" PRIu64, adapter->name, txn_id);
		return;
	}

	if (txn->type == MGMTD_TXN_TYPE_CONFIG) {
		/*
		 * Handle an error during a configuration transaction.
		 */
		txn_req = txn_ensure_be_cfg_msg(txn_id, adapter, "ERROR");
		if (!txn_req) {
			msg_conn_disconnect(adapter->conn, false);
			return;
		}
		/*
		 * We only handle errors in reply to our CFG_REQ messages (due
		 * to validation/preparation). Otherwise, this is an error
		 * during some other phase of the commit process and we
		 * disconnect the client and start over.
		 */
		if (txn_req->req.commit_cfg.phase == MGMTD_COMMIT_PHASE_SEND_CFG)
			txn_handle_cfg_reply(txn_req, false, errstr, adapter);
		else
			/* Drop the connection these errors should never happen */
			msg_conn_disconnect(adapter->conn, false);
		return;
	}

	/*
	 * Find the non-config request.
	 */

	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
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
	case MGMTD_TXN_PROC_GETTREE:
		get_tree = txn_req->req.get_tree;
		get_tree->recv_clients |= (1u << id);
		get_tree->partial_error = error;

		/* check if done yet */
		if (get_tree->recv_clients == get_tree->sent_clients)
			txn_get_tree_data_done(txn, txn_req);
		return;
	case MGMTD_TXN_PROC_RPC:
		rpc = txn_req->req.rpc;
		rpc->recv_clients |= (1u << id);
		if (errstr) {
			XFREE(MTYPE_MGMTD_ERR, rpc->errstr);
			rpc->errstr = XSTRDUP(MTYPE_MGMTD_ERR, errstr);
		}
		/* check if done yet */
		if (rpc->recv_clients == rpc->sent_clients)
			txn_rpc_done(txn, txn_req);
		return;

	/* non-native message events */
	case MGMTD_TXN_PROC_COMMITCFG:
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
	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
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
	FOREACH_TXN_REQ_IN_LIST (&txn->reqs, txn_req)
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
	static struct mgmt_commit_stats dummy_stats = { 0 };

	struct nb_config_cbs changes = { 0 };
	struct mgmt_txn_ctx *txn;
	struct mgmt_txn_req *txn_req;
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
	txn_req = mgmt_txn_req_alloc(txn, 0, MGMTD_TXN_PROC_COMMITCFG);
	txn_req->req.commit_cfg.src_ds_id = MGMTD_DS_CANDIDATE;
	txn_req->req.commit_cfg.src_ds_ctx = src_ds_ctx;
	txn_req->req.commit_cfg.dst_ds_id = MGMTD_DS_RUNNING;
	txn_req->req.commit_cfg.dst_ds_ctx = dst_ds_ctx;
	txn_req->req.commit_cfg.validate_only = false;
	txn_req->req.commit_cfg.abort = false;
	txn_req->req.commit_cfg.rollback = true;
	txn_req->req.commit_cfg.cmt_stats = &dummy_stats;

	/*
	 * Send the changes.
	 */
	ret = txn_send_config_changes(txn, &changes, 0);
	if (ret)
		txn_finish_commit(txn_req, txn_req->error, txn_req->err_info);
	return ret;
}
