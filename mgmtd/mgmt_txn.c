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
#include "mgmtd/mgmt_txn_priv.h"

/* ================= */
/* TXN Request Types */
/* ================= */

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
#define as_get_tree(txn_req)                                                                      \
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
	uint8_t restconf;      /* if restconf formatted data */
	struct lyd_node *client_results; /* result tree from clients */
};
#define as_rpc(txn_req)                                                                           \
	({                                                                                        \
		assert((txn_req)->req_type == TXN_REQ_TYPE_RPC);                                  \
		(struct txn_req_rpc *)(txn_req);                                                  \
	})

const char *txn_req_names[] = {
	[TXN_REQ_TYPE_COMMIT] = "COMMIT",
	[TXN_REQ_TYPE_GETTREE] = "GET-TREE",
	[TXN_REQ_TYPE_RPC] = "RPC",
};

/* Global list of all transactions */
TAILQ_HEAD(mgmt_txn_head, mgmt_txn) txn_txns = TAILQ_HEAD_INITIALIZER(txn_txns);

/* The single instance of config transaction allowed at any time */
struct mgmt_txn *txn_config_txn;

/* Map of Transactions and its ID */
struct hash *txn_id_tab;
uint64_t txn_next_id;

static void txn_incref(struct mgmt_txn *txn, const char *file, int line);

/* ====================== */
/* Txn Request Management */
/* ====================== */

static inline struct txn_req *txn_txn_req(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req;

	TAILQ_FOREACH (txn_req, &txn->reqs, link)
		if (txn_req->req_id == req_id)
			return txn_req;
	return NULL;
}

struct txn_req *txn_req_alloc(struct mgmt_txn *txn, uint64_t req_id, enum txn_req_type req_type,
			      size_t size)
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

static struct txn_req_get_tree *txn_req_get_tree_alloc(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req = txn_req_alloc(txn, req_id, TXN_REQ_TYPE_GETTREE,
						sizeof(struct txn_req_get_tree));
	assert(txn->type == MGMTD_TXN_TYPE_SHOW);
	return as_get_tree(txn_req);
}

static struct txn_req_rpc *txn_req_rpc_alloc(struct mgmt_txn *txn, uint64_t req_id)
{
	struct txn_req *txn_req = txn_req_alloc(txn, req_id, TXN_REQ_TYPE_RPC,
						sizeof(struct txn_req_rpc));
	assert(txn->type == MGMTD_TXN_TYPE_RPC);
	return as_rpc(txn_req);
}

void txn_req_free(struct txn_req *txn_req)
{
	struct mgmt_txn *txn = txn_req->txn;
	struct txn_req_rpc *rpc;
	struct txn_req_get_tree *get_tree;
	uint64_t txn_id = txn->txn_id;

	/* prevent recursion */
	_dbg("Deleting %s txn-req req-id: %Lu txn-id: %Lu", txn_req_names[txn_req->req_type],
	     txn_req->req_id, txn_id);

	switch (txn_req->req_type) {
	case TXN_REQ_TYPE_COMMIT:
		txn_cfg_cleanup(txn_req);
		break;
	case TXN_REQ_TYPE_GETTREE:
		get_tree = as_get_tree(txn_req);
		lyd_free_all(get_tree->client_results);
		XFREE(MTYPE_MGMTD_XPATH, get_tree->xpath);
		break;
	case TXN_REQ_TYPE_RPC:
		rpc = as_rpc(txn_req);
		lyd_free_all(rpc->client_results);
		XFREE(MTYPE_MGMTD_XPATH, rpc->xpath);
		break;
	}

	TAILQ_REMOVE(&txn->reqs, txn_req, link);
	_dbg("Removed req-id: %Lu from request-list", txn_req->req_id);

	darr_free(txn_req->err_info);
	TXN_DECREF(txn_req->txn);
	XFREE(MTYPE_MGMTD_TXN_REQ, txn_req);
}

/* =========================== */
/* GET TREE (data) BACKEND TXN */
/* =========================== */

static void txn_get_tree_data_done(struct txn_req_get_tree *get_tree)
{
	struct txn_req *txn_req = as_txn_req(get_tree);
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
		mgmt_fe_adapter_send_tree_data(txn->session_id, txn->txn_id, txn_req->req_id,
					       get_tree->result_type, get_tree->wd_options, result,
					       get_tree->partial_error, false);
	else {
		_log_err("Error sending the results of GET-TREE for txn-id %Lu req_id %Lu to requested type %u",
			 txn->txn_id, req_id, get_tree->result_type);

		(void)mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false,
						errno_from_nb_error(ret),
						"Error converting results of GET-TREE");
	}

	/* we're done with the request */
	txn_req_free(txn_req);
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

static void txn_get_tree_handle_error_reply(struct txn_req_get_tree *get_tree,
					    struct mgmt_be_client_adapter *adapter, int error,
					    const char *errstr)
{
	UNSET_IDBIT(get_tree->clients_wait, adapter->id);
	get_tree->partial_error = error;

	/* check if done yet */
	if (!get_tree->clients_wait)
		txn_get_tree_data_done(get_tree);
}

/*
 * Get-tree data from the backend client.
 */
void mgmt_txn_handle_tree_data_reply(struct mgmt_be_client_adapter *adapter,
				     struct mgmt_msg_tree_data *data_msg, size_t msg_len)
{
	uint64_t txn_id = data_msg->refer_id;
	uint64_t req_id = data_msg->req_id;

	mgmt_be_client_id_t id = adapter->id;
	uint32_t parse_options = LYD_PARSE_STRICT | LYD_PARSE_ONLY;
	struct mgmt_txn *txn = txn_lookup(txn_id);
	struct txn_req *txn_req;
	struct txn_req_get_tree *get_tree;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	if (!txn) {
		_log_err("GETTREE reply from %s for a missing txn-id %" PRIu64, adapter->name,
			 txn_id);
		return;
	}

	/* Find the request. */
	txn_req = txn_txn_req(txn, req_id);
	if (!txn_req || txn_req->req_type != TXN_REQ_TYPE_GETTREE) {
		_log_err("GETTREE reply from %s for txn-id %" PRIu64 " missing req_id %" PRIu64,
			 adapter->name, txn_id, req_id);
		return;
	}
	get_tree = as_get_tree(txn_req);

	/* store the result */
#ifdef LYD_PARSE_LYB_SKIP_CTX_CHECK
	if (data_msg->result_type == LYD_LYB)
		parse_options |= LYD_PARSE_LYB_SKIP_CTX_CHECK;
#endif
	err = lyd_parse_data_mem(ly_native_ctx, (const char *)data_msg->result,
				 data_msg->result_type, parse_options,
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
			err = lyd_merge_siblings(&get_tree->client_results, tree,
						 LYD_MERGE_DESTRUCT);
		if (err) {
			_log_err("GETTREE reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
				 " error merging result",
				 adapter->name, txn_id, req_id);
		}
	}
	if (!get_tree->partial_error)
		get_tree->partial_error = (data_msg->partial_error ? data_msg->partial_error
								   : (int)err);

	if (!data_msg->more)
		UNSET_IDBIT(get_tree->clients_wait, id);

	/* check if done */
	if (!get_tree->clients_wait)
		txn_get_tree_data_done(get_tree);
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
	mgmt_be_client_id_t id;
	ssize_t slen = strlen(xpath);
	int ret;

	txn = txn_lookup(txn_id);
	assert(txn && txn->type == MGMTD_TXN_TYPE_SHOW);

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
	if (!CHECK_FLAG(flags, GET_DATA_FLAG_STATE) || ds_id != MGMTD_DS_OPERATIONAL || !clients) {
		txn_get_tree_data_done(get_tree);
		return 0;
	}

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_get_tree, slen + 1,
					MTYPE_MSG_NATIVE_GET_TREE);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_TREE;
#if (LY_VERSION_MAJOR < 4)
	/* Always operate with the binary format in the backend */
	msg->result_type = LYD_LYB;
#else
	/* Libyang4 has severe restrictions on LYB so we can't use it anymore */
	msg->result_type = result_type;
#endif
	strlcpy(msg->xpath, xpath, slen + 1);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		ret = mgmt_be_adapter_send(adapter, msg);
		if (ret) {
			darr_in_sprintf(get_tree->req.err_info, "Failed to send GET-DATA to %s",
					adapter->name);
			continue;
		}
		SET_IDBIT(get_tree->clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	get_tree->clients_wait = get_tree->clients;
	if (!get_tree->clients_wait)
		txn_get_tree_data_done(get_tree);
	else
		event_add_timer(mm->master, txn_get_tree_timeout, get_tree,
				MGMTD_TXN_GET_TREE_MAX_DELAY_SEC, &get_tree->req.timeout);
	return 0;
}

/* =============== */
/* RPC BACKEND TXN */
/* =============== */

static void txn_rpc_done(struct txn_req_rpc *rpc)
{
	struct txn_req *txn_req = as_txn_req(rpc);
	struct mgmt_txn *txn = txn_req->txn;
	uint64_t req_id = rpc->req.req_id;

	/* cancel timer and send reply onward */
	event_cancel(&rpc->req.timeout);

	if (txn_req->err_info)
		mgmt_fe_adapter_txn_error(txn->txn_id, req_id, false, txn_req->error ?: -EINVAL,
					  txn_req->err_info);
	else
		mgmt_fe_adapter_send_rpc_reply(txn->session_id, txn->txn_id, req_id,
					       rpc->result_type, rpc->restconf,
					       rpc->client_results);

	/* we're done with the request */
	txn_req_free(txn_req);
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

static void txn_rpc_handle_error_reply(struct txn_req_rpc *rpc,
				       struct mgmt_be_client_adapter *adapter, int error,
				       const char *errstr)
{
	UNSET_IDBIT(rpc->clients_wait, adapter->id);
	if (errstr)
		darr_in_strdup(rpc->req.err_info, errstr);
	/* check if done */
	if (!rpc->clients_wait)
		txn_rpc_done(rpc);
}

void mgmt_txn_handle_rpc_reply(struct mgmt_be_client_adapter *adapter,
			       struct mgmt_msg_rpc_reply *reply_msg, size_t msg_len)
{
	uint64_t txn_id = reply_msg->refer_id;
	uint64_t req_id = reply_msg->req_id;
	mgmt_be_client_id_t id = adapter->id;
	struct mgmt_txn *txn = txn_lookup(txn_id);
	struct txn_req *txn_req;
	struct txn_req_rpc *rpc;
	struct lyd_node *tree;
	size_t data_len = msg_len - sizeof(*reply_msg);
	LY_ERR err = LY_SUCCESS;

	if (!txn) {
		_log_err("RPC reply from %s for a missing txn-id %Lu", adapter->name, txn_id);
		return;
	}

	/* Find the request. */
	txn_req = txn_txn_req(txn, req_id);
	if (!txn_req || txn_req->req_type != TXN_REQ_TYPE_RPC) {
		_log_err("RPC reply from %s for txn-id %Lu missing req_id %Lu", adapter->name,
			 txn_id, req_id);
		return;
	}
	rpc = as_rpc(txn_req);

	tree = NULL;
	if (data_len)
		err = yang_parse_rpc(rpc->xpath, reply_msg->result_type, reply_msg->data, true,
				     &tree);
	if (err) {
		_log_err("RPC reply from %s for txn-id %" PRIu64 " req_id %" PRIu64
			 " error parsing result of type %u: %s",
			 adapter->name, txn_id, req_id, reply_msg->result_type, ly_strerrcode(err));
	}
	if (!err && tree) {
		if (!rpc->client_results)
			rpc->client_results = tree;
		else
			err = lyd_merge_siblings(&rpc->client_results, tree, LYD_MERGE_DESTRUCT);
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
	if (!rpc->clients_wait)
		txn_rpc_done(rpc);
}

void mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients, LYD_FORMAT result_type,
		       bool restconf, const char *xpath, const char *data, size_t data_len)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_txn *txn;
	struct mgmt_msg_rpc *msg;
	struct txn_req_rpc *rpc;
	mgmt_be_client_id_t id;
	int ret;

	txn = txn_lookup(txn_id);
	assert(txn && txn->type == MGMTD_TXN_TYPE_RPC);

	rpc = txn_req_rpc_alloc(txn, req_id);
	rpc->xpath = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);
	rpc->result_type = result_type;
	rpc->restconf = restconf;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc, 0,
					MTYPE_MSG_NATIVE_RPC);
	msg->refer_id = txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_RPC;
	msg->request_type = result_type;
	msg->restconf = restconf;

	mgmt_msg_native_xpath_encode(msg, xpath);
	if (data)
		mgmt_msg_native_append(msg, data, data_len);

	assert(clients);
	FOREACH_BE_ADAPTER_BITS (id, adapter, clients) {
		ret = mgmt_be_adapter_send(adapter, msg);
		if (ret) {
			darr_in_sprintf(rpc->req.err_info, "Failed to send RPC to %s",
					adapter->name);
			continue;
		}
		SET_IDBIT(rpc->clients, id);
	}

	mgmt_msg_native_free_msg(msg);

	rpc->clients_wait = rpc->clients;
	if (!rpc->clients_wait)
		txn_rpc_done(rpc);
	else
		event_add_timer(mm->master, txn_rpc_timeout, rpc, MGMTD_TXN_RPC_MAX_DELAY_SEC,
				&rpc->req.timeout);
}

/* =========================== */
/* NOTIFY SELECTOR BACKEND TXN */
/* =========================== */

void mgmt_txn_send_notify_selectors(uint64_t req_id, uint64_t session_id, uint64_t clients,
				    const char **selectors)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_msg_notify_select *msg;
	mgmt_be_client_id_t id;
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
		if (mgmt_be_adapter_send(adapter, msg)) {
			/*
			 * Failed to send to this backend since we require
			 * reliable notifications from the backends we need to
			 * disconnect here.
			 */
			msg_conn_disconnect(adapter->conn, false);
			continue;
		}
	}
	mgmt_msg_native_free_msg(msg);

	if (all_selectors)
		darr_free_free(all_selectors);
}

/* =============== */
/* TXN ERROR REPLY */
/* =============== */

/*
 * Error reply from the backend client.
 *
 * NOTE: can disconnect (and delete) the backend.
 */
void mgmt_txn_handle_error_reply(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
				 uint64_t req_id, int error, const char *errstr)
{
	struct txn_req *txn_req;
	struct mgmt_txn *txn;

	txn = txn_lookup(txn_id);
	if (!txn) {
		_log_err("Error reply from %s cannot find txn-id %Lu", adapter->name, txn_id);
		return;
	}

	TAILQ_FOREACH (txn_req, &txn->reqs, link) {
		/* Clients do not set req_id for commit errors yet there's only
		 * one so this works for now. */
		if (req_id == 0 && txn_req->req_type == TXN_REQ_TYPE_COMMIT)
			break;
		else if (txn_req->req_id == req_id)
			break;
	}
	if (!txn_req) {
		_log_err("Error reply from %s for txn-id %Lu cannot find req_id %Lu",
			 adapter->name, txn_id, req_id);
		return;
	}

	_log_err("Error reply from %s for txn-id %Lu req_id %Lu", adapter->name, txn_id, req_id);

	switch (txn_req->req_type) {
	case TXN_REQ_TYPE_COMMIT:
		txn_cfg_handle_error(txn_req, adapter, error, errstr);
		return;
	case TXN_REQ_TYPE_GETTREE:
		txn_get_tree_handle_error_reply(as_get_tree(txn_req), adapter, error, errstr);
		return;
	case TXN_REQ_TYPE_RPC:
		txn_rpc_handle_error_reply(as_rpc(txn_req), adapter, error, errstr);
		return;
	/* non-native message events */
	default:
		assert(!"non-native req type in native error path");
	}
}

/* ============== */
/* Txn Management */
/* ============== */

static unsigned int txn_txn_id_hash(const struct mgmt_txn *txn)
{
	uint64_t key = txn->txn_id;

	return (uint32_t)key ^ (uint32_t)(key >> 32);
}

static bool txn_txn_id_cmp(const struct mgmt_txn *a, const struct mgmt_txn *b)
{
	return (a->txn_id == b->txn_id);
}

struct mgmt_txn *txn_lookup(uint64_t txn_id)
{
	struct mgmt_txn key = { 0 };

	if (!txn_id_tab)
		return NULL;
	key.txn_id = txn_id;
	return hash_lookup(txn_id_tab, &key);
}

uint64_t mgmt_txn_get_session_id(uint64_t txn_id)
{
	struct mgmt_txn *txn = txn_lookup(txn_id);

	return txn ? txn->session_id : MGMTD_SESSION_ID_NONE;
}

static void txn_incref(struct mgmt_txn *txn, const char *file, int line)
{
	txn->refcount++;
	_dbg("TXN-INCREF %s txn-id: %Lu refcnt: %d file: %s line: %d)",
	     mgmt_txn_type2str(txn->type), txn->txn_id, txn->refcount, file, line);
}

void txn_decref(struct mgmt_txn *txn, const char *file, int line)
{
	assert(txn && txn->refcount);

	txn->refcount--;
	_dbg("TXN-DECREF %s txn-id: %Lu refcnt: %d file: %s line: %d",
	     mgmt_txn_type2str(txn->type), txn->txn_id, txn->refcount, file, line);
	if (!txn->refcount) {
		if (txn->type == MGMTD_TXN_TYPE_CONFIG)
			if (txn_config_txn == txn)
				txn_config_txn = NULL;
		hash_release(txn_id_tab, txn);
		TAILQ_REMOVE(&txn_txns, txn, link);

		_dbg("Deleted %s txn-id: %Lu session-id: %Lu", mgmt_txn_type2str(txn->type),
		     txn->txn_id, txn->session_id);

		XFREE(MTYPE_MGMTD_TXN, txn);
	}
}

struct mgmt_txn *txn_create(enum mgmt_txn_type type)
{
	struct mgmt_txn *txn;

	txn = XCALLOC(MTYPE_MGMTD_TXN, sizeof(struct mgmt_txn));
	txn->type = type;
	TAILQ_INSERT_TAIL(&txn_txns, txn, link);
	TAILQ_INIT(&txn->reqs);
	txn->txn_id = txn_next_id++;
	hash_get(txn_id_tab, txn, hash_alloc_intern);

	_dbg("Added new '%s' txn-id: %" PRIu64, mgmt_txn_type2str(type), txn->txn_id);

	TXN_INCREF(txn);
	return txn;
}

uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type)
{
	struct mgmt_txn *txn;

	/* Do not allow multiple (external) config transactions */
	if (type == MGMTD_TXN_TYPE_CONFIG && txn_config_txn)
		return MGMTD_TXN_ID_NONE;

	/* Find existing txn for this session and type */
	TAILQ_FOREACH (txn, &txn_txns, link)
		if (txn->session_id == session_id && txn->type == type)
			return txn->txn_id;

	txn = txn_create(type);
	txn->session_id = session_id;
	if (type == MGMTD_TXN_TYPE_CONFIG)
		txn_config_txn = txn;
	return txn->txn_id;
}

void mgmt_destroy_txn(uint64_t *txn_id)
{
	struct mgmt_txn *txn;

	if (*txn_id == MGMTD_TXN_ID_NONE)
		return;

	txn = txn_lookup(*txn_id);
	if (!txn)
		return;

	TXN_DECREF(txn);
	*txn_id = MGMTD_TXN_ID_NONE;
}

bool mgmt_txn_config_in_progress(void)
{
	return txn_config_txn != NULL;
}

int mgmt_txn_handle_be_adapter_connect(struct mgmt_be_client_adapter *adapter, bool connect)
{
	struct mgmt_txn *txn, *next;

	if (connect)
		return txn_cfg_be_client_connect(adapter);

	/*
	 * Disconnecting: check if any transaction is currently on-going that
	 * involves this backend client. If so check if we can now advance that
	 * transaction.
	 */
	TAILQ_FOREACH_SAFE (txn, &txn_txns, link, next) {
		/* XXX update to handle get-tree and RPC too! */
		if (txn->type == MGMTD_TXN_TYPE_CONFIG)
			txn_cfg_txn_be_client_disconnect(txn, adapter);
	}

	return 0;
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

void mgmt_txn_init(void)
{
	assert(txn_next_id == 0);
	txn_next_id = 1;
	txn_id_tab = hash_create((unsigned int (*)(const void *))txn_txn_id_hash,
				 (bool (*)(const void *, const void *))txn_txn_id_cmp,
				 "Mgmt Txns by txn-id");
}

void mgmt_txn_destroy(void)
{
	struct mgmt_txn *txn, *next;
	struct txn_req *txn_req, *next_req;

	TAILQ_FOREACH_SAFE (txn, &txn_txns, link, next) {
		/* Free all txn_reqs associated with this txn -- pop-first-free trips up coverity */
		TAILQ_FOREACH_SAFE (txn_req, &txn->reqs, link, next_req)
			txn_req_free(txn_req);
		assert(txn->refcount == 1);
		TXN_DECREF(txn);
	}

	if (txn_id_tab)
		hash_free(txn_id_tab);
}
