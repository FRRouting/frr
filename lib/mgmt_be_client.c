// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "debug.h"
#include "compiler.h"
#include "darr.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "mgmt_be_client.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "network.h"
#include "northbound.h"
#include "stream.h"
#include "sockopt.h"
#include "northbound_cli.h"

#include "lib/mgmt_be_client_clippy.c"

DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_CLIENT, "backend client");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_CLIENT_NAME, "backend client name");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_BATCH, "backend transaction batch data");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_TXN, "backend transaction data");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_GT_CB_ARGS, "backend get-tree cb args");

struct be_oper_iter_arg {
	struct lyd_node *root; /* the tree we are building */
	struct lyd_node *hint; /* last node added */
};

PREDECL_LIST(mgmt_be_txns);
struct mgmt_be_txn_ctx {
	/* Txn-Id as assigned by MGMTD */
	uint64_t txn_id;
	uint32_t flags;

	struct mgmt_be_client_txn_ctx client_data;
	struct mgmt_be_client *client;

	struct mgmt_be_txns_item list_linkage;

	struct nb_transaction *nb_txn;
	uint32_t nb_txn_id;
};
#define MGMTD_BE_TXN_FLAGS_CFGPREP_FAILED (1U << 1)

DECLARE_LIST(mgmt_be_txns, struct mgmt_be_txn_ctx, list_linkage);

struct mgmt_be_client {
	struct msg_client client;

	char *name;

	struct nb_config *candidate_config;
	struct nb_config *running_config;

	uint64_t num_edit_nb_cfg;
	uint64_t avg_edit_nb_cfg_tm;
	uint64_t num_prep_nb_cfg;
	uint64_t avg_prep_nb_cfg_tm;
	uint64_t num_apply_nb_cfg;
	uint64_t avg_apply_nb_cfg_tm;

	struct mgmt_be_txns_head txn_head;

	struct mgmt_be_client_cbs cbs;
	uintptr_t user_data;
};

#define FOREACH_BE_TXN_IN_LIST(client_ctx, txn)                                \
	frr_each_safe (mgmt_be_txns, &(client_ctx)->txn_head, (txn))

struct debug mgmt_dbg_be_client = {
	.conf = "debug mgmt client backend",
	.desc = "Management backend client operations",
};

/* NOTE: only one client per proc for now. */
static struct mgmt_be_client *__be_client;

static int be_client_send_native_msg(struct mgmt_be_client *client_ctx,
				     void *msg, size_t len,
				     bool short_circuit_ok)
{
	return msg_conn_send_msg(&client_ctx->client.conn,
				 MGMT_MSG_VERSION_NATIVE, msg, len, NULL,
				 short_circuit_ok);
}

static struct mgmt_be_txn_ctx *
mgmt_be_find_txn_by_id(struct mgmt_be_client *client_ctx, uint64_t txn_id,
		       bool warn)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	FOREACH_BE_TXN_IN_LIST (client_ctx, txn)
		if (txn->txn_id == txn_id)
			return txn;
	if (warn)
		log_err_be_client("client %s unkonwn txn-id: %" PRIu64,
				  client_ctx->name, txn_id);

	return NULL;
}

static struct mgmt_be_txn_ctx *
mgmt_be_txn_create(struct mgmt_be_client *client_ctx, uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id, false);
	if (txn) {
		log_err_be_client("Can't create existing txn-id: %" PRIu64,
				  txn_id);
		return NULL;
	}

	txn = XCALLOC(MTYPE_MGMTD_BE_TXN, sizeof(struct mgmt_be_txn_ctx));
	txn->txn_id = txn_id;
	txn->client = client_ctx;
	mgmt_be_txns_add_tail(&client_ctx->txn_head, txn);

	debug_be_client("Created new txn-id: %" PRIu64, txn_id);

	return txn;
}

static void mgmt_be_txn_delete(struct mgmt_be_client *client_ctx,
			       struct mgmt_be_txn_ctx **txn)
{
	char err_msg[] = "MGMT Transaction Delete";

	if (!txn)
		return;

	/*
	 * Remove the transaction from the list of transactions
	 * so that future lookups with the same transaction id
	 * does not return this one.
	 */
	mgmt_be_txns_del(&client_ctx->txn_head, *txn);

	/*
	 * Time to delete the transaction which should also take care of
	 * cleaning up all batches created via CFG_REQs. But first notify the
	 * client about the transaction delete.
	 */
	if (client_ctx->cbs.txn_notify)
		(void)(*client_ctx->cbs.txn_notify)(client_ctx,
						    client_ctx->user_data,
						    &(*txn)->client_data, true);

	if ((*txn)->nb_txn)
		nb_candidate_commit_abort((*txn)->nb_txn, err_msg,
					sizeof(err_msg));
	XFREE(MTYPE_MGMTD_BE_TXN, *txn);

	*txn = NULL;
}

static void mgmt_be_cleanup_all_txns(struct mgmt_be_client *client_ctx)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	FOREACH_BE_TXN_IN_LIST (client_ctx, txn) {
		mgmt_be_txn_delete(client_ctx, &txn);
	}
}


/**
 * Send an error back to MGMTD using native messaging.
 *
 * Args:
 *	client: the BE client.
 *	txn_id: the txn_id this error pertains to.
 *	short_circuit_ok: True if OK to short-circuit the call.
 *	error: An integer error value.
 *	errfmt: An error format string (i.e., printfrr)
 *      ...: args for use by the `errfmt` format string.
 *
 * Return:
 *	the return value from the underlying send message function.
 */
static int be_client_send_error(struct mgmt_be_client *client, uint64_t txn_id,
				uint64_t req_id, bool short_circuit_ok,
				int16_t error, const char *errfmt, ...)
	PRINTFRR(6, 7);

static int be_client_send_error(struct mgmt_be_client *client, uint64_t txn_id,
				uint64_t req_id, bool short_circuit_ok,
				int16_t error, const char *errfmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, errfmt);
	ret = vmgmt_msg_native_send_error(&client->client.conn, txn_id, req_id,
					  short_circuit_ok, error, errfmt, ap);
	va_end(ap);

	return ret;
}

static int __send_notification(struct mgmt_be_client *client, const char *xpath,
			       const struct lyd_node *tree, uint8_t op, uint64_t refer_id)
{
	struct mgmt_msg_notify_data *msg = NULL;
	// LYD_FORMAT format = LYD_LYB;
	LYD_FORMAT format = LYD_JSON;
	uint8_t **darrp;
	LY_ERR err;
	int ret = 0;

	assert(op != NOTIFY_OP_NOTIFICATION || xpath || tree);
	debug_be_client("%s: sending %sYANG %snotification: %s", __func__,
			op == NOTIFY_OP_DS_DELETE    ? "delete "
			: op == NOTIFY_OP_DS_REPLACE ? "replace "
			: op == NOTIFY_OP_DS_PATCH   ? "patch "
						     : "",
			op == NOTIFY_OP_NOTIFICATION ? "" : "DS ", xpath ?: tree->schema->name);
	/*
	 * Allocate a message and append the data to it using `format`
	 */
	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_notify_data, 0, MTYPE_MSG_NATIVE_NOTIFY);
	msg->code = MGMT_MSG_CODE_NOTIFY;
	msg->result_type = format;
	msg->refer_id = refer_id;
	msg->op = op;

	mgmt_msg_native_xpath_encode(msg, xpath);

	if (tree) {
		darrp = mgmt_msg_native_get_darrp(msg);
		err = yang_print_tree_append(darrp, tree, format,
					     (LYD_PRINT_SHRINK | LYD_PRINT_WD_EXPLICIT |
					      LYD_PRINT_WITHSIBLINGS));
		if (err) {
			flog_err(EC_LIB_LIBYANG, "%s: error creating notification data: %s",
				 __func__, ly_strerrcode(err));
			ret = 1;
			goto done;
		}
	}

	ret = be_client_send_native_msg(client, msg, mgmt_msg_native_get_msg_len(msg), false);
done:
	mgmt_msg_native_free_msg(msg);
	return ret;
}

/**
 * mgmt_be_send_ds_delete_notification() - Send DS notification to mgmtd
 */
int mgmt_be_send_ds_delete_notification(const char *path)
{
	if (!__be_client) {
		debug_be_client("%s: No mgmtd connection for DS delete notification: %s", __func__,
				path);
		return 1;
	}
	return __send_notification(__be_client, path, NULL, NOTIFY_OP_DS_DELETE, 0);
}

/**
 * mgmt_be_send_ds_patch_notification() - Send a YANG patch DS notification to mgmtd
 */
int mgmt_be_send_ds_patch_notification(const char *path, const struct lyd_node *patch)
{
	if (!__be_client) {
		debug_be_client("%s: No mgmtd connection for DS delete notification: %s", __func__,
				path);
		return 1;
	}
	return __send_notification(__be_client, path, patch, NOTIFY_OP_DS_PATCH, 0);
}

/**
 * mgmt_be_send_ds_replace_notification() - Send a replace DS notification to mgmtd
 */
int mgmt_be_send_ds_replace_notification(const char *path, const struct lyd_node *tree,
					 uint64_t refer_id)
{
	uint8_t op = refer_id ? NOTIFY_OP_DS_GET_SYNC : NOTIFY_OP_DS_REPLACE;

	if (!__be_client) {
		debug_be_client("%s: No mgmtd connection for DS delete notification: %s", __func__,
				path);
		return 1;
	}

	return __send_notification(__be_client, path, tree, op, refer_id);
}

/**
 * mgmt_be_send_notification() - Send notification to mgmtd
 *
 * This function is attached to the northbound notification hook.
 */
static int mgmt_be_send_notification(void *__client, const char *path, const struct lyd_node *tree)
{
	__send_notification(__client, path, tree, NOTIFY_OP_NOTIFICATION, 0);
	return 0;
}

static int mgmt_be_send_txn_reply(struct mgmt_be_client *client, uint64_t txn_id, bool create)
{
	struct mgmt_msg_txn_reply *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_txn_reply, 0, MTYPE_MSG_NATIVE_TXN_REPLY);
	msg->code = MGMT_MSG_CODE_TXN_REPLY;
	msg->refer_id = txn_id;
	msg->created = create;

	debug_be_client("Sending TXN_REPLY txn-id %Lu", txn_id);

	ret = be_client_send_native_msg(client, msg, mgmt_msg_native_get_msg_len(msg), false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

/* ===================== */
/* CONFIGURATION PROCESS */
/* ===================== */

/* ------------------ */
/* Create Transaction */
/* ------------------ */

/*
 * Process transaction create message
 */
static void be_client_handle_txn_req(struct mgmt_be_client *client, uint64_t txn_id, void *msgbuf,
				     size_t msg_len)
{
	struct mgmt_msg_txn_req *msg = msgbuf;
	struct mgmt_be_txn_ctx *txn;

	debug_be_client("Got TXN_REQ for client %s txn-id %Lu req-id %Lu", client->name, txn_id,
			msg->req_id);

	if (msg->create) {
		debug_be_client("Creating new txn-id %" PRIu64, txn_id);

		txn = mgmt_be_txn_create(client, txn_id);
		if (!txn) {
			msg_conn_disconnect(&client->client.conn, true);
			return;
		}

		if (client->cbs.txn_notify)
			(*client->cbs.txn_notify)(client, client->user_data, &txn->client_data,
						  false);
	} else {
		debug_be_client("Deleting txn-id: %" PRIu64, txn_id);
		txn = mgmt_be_find_txn_by_id(client, txn_id, false);
		if (txn)
			mgmt_be_txn_delete(client, &txn);
	}

	mgmt_be_send_txn_reply(client, txn_id, msg->create);
}

/* ------------------------- */
/* Receive Config from MgmtD */
/* ------------------------- */

static int mgmt_be_send_cfg_reply(struct mgmt_be_client *client_ctx, uint64_t txn_id, bool success,
				  const char *error_if_any)
{
	struct mgmt_msg_cfg_reply *msg;
	int ret;

	if (!success) {
		if (!error_if_any)
			error_if_any = "Unknown error";
		return be_client_send_error(client_ctx, txn_id, 0, false, EINVAL,
					    "Failed to create cfgdata: %s", error_if_any);
	}
	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_reply, 0, MTYPE_MSG_NATIVE_CFG_REPLY);
	msg->code = MGMT_MSG_CODE_CFG_REPLY;
	msg->refer_id = txn_id;

	debug_be_client("Sending CFG_REPLY txn-id: %Lu", txn_id);

	ret = be_client_send_native_msg(client_ctx, msg, mgmt_msg_native_get_msg_len(msg), false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

static void mgmt_be_txn_cfg_abort(struct mgmt_be_txn_ctx *txn)
{
	char errmsg[BUFSIZ] = {0};

	assert(txn && txn->client);
	if (txn->nb_txn) {
		log_err_be_client("Aborting configs after prep for txn-id: %" PRIu64,
				  txn->txn_id);
		nb_candidate_commit_abort(txn->nb_txn, errmsg, sizeof(errmsg));
		txn->nb_txn = 0;
	}

	/*
	 * revert candidate back to running
	 *
	 * This is one txn ctx but the candidate_config is per client ctx, how
	 * does that work?
	 */
	debug_be_client("Reset candidate configurations after abort of txn-id: %" PRIu64,
			txn->txn_id);
	nb_config_replace(txn->client->candidate_config,
			  txn->client->running_config, true);
}

/* ------------------------------------------------ */
/* Received All Configuration, Prepare and Validate */
/* ------------------------------------------------ */

static bool be_client_change_edit_config(struct nb_config *candidate_config, const char **changes,
					 char *err_buf, int err_bufsize)
{
	enum nb_change_result result;
	enum nb_operation operation;
	const char *actions;
	const char *xpath;
	const char *value;
	uint end = darr_len(changes);
	bool error = false;
	uint i = 0;

	assert(end > 0);
	end -= 1;
	actions = changes[end]; /* action string in last element */
	while (i < end) {
		char action = *actions++;

		xpath = changes[i++];

		if (action == 'm') {
			operation = NB_OP_MODIFY;
			assert(i < end);
			value = changes[i++];
		} else if (action == 'd') {
			operation = NB_OP_DESTROY;
			value = NULL;
		} else {
			assert(!"config change action is invalid");
			value = NULL;
		}
		result = nb_candidate_edit_config_change(candidate_config, operation, xpath, value,
							 true);
		if (result != NB_CHANGE_OK)
			error = true;
		if (result == NB_CHANGE_ERR)
			break;
	}
	if (error) {
		char buf[BUFSIZ];

		snprintf(err_buf, err_bufsize, "%% Failed to edit configuration.\n\n%s",
			 yang_print_errors(ly_native_ctx, buf, sizeof(buf)));
		err_buf[err_bufsize - 1] = 0;
	}
	return error;
}

static int mgmt_be_txn_cfg_prepare(struct mgmt_be_txn_ctx *txn, const char **config)
{
	struct mgmt_be_client *client_ctx;
	struct nb_context nb_ctx = {0};
	struct timeval edit_nb_cfg_start;
	struct timeval edit_nb_cfg_end;
	unsigned long edit_nb_cfg_tm;
	struct timeval prep_nb_cfg_start;
	struct timeval prep_nb_cfg_end;
	unsigned long prep_nb_cfg_tm;
	bool error;
	char err_buf[BUFSIZ];
	size_t num_processed;
	int err;

	assert(txn && txn->client);
	client_ctx = txn->client;

	num_processed = 0;
	error = false;
	nb_ctx.client = NB_CLIENT_CLI;
	nb_ctx.user = (void *)client_ctx->user_data;

	/*
	 * this is always true, right?!
	 */
	assert(!txn->nb_txn);

	if (!txn->nb_txn) {
		/*
		 * XXX, is this just an old crusty comment?
		 *
		 * This happens when the current backend client is only
		 * interested in consuming the config items but is not
		 * interested in validating it.
		 */
		gettimeofday(&edit_nb_cfg_start, NULL);

		error = be_client_change_edit_config(client_ctx->candidate_config, config, err_buf,
						     sizeof(err_buf));
		if (error) {
			log_err_be_client("Failed to update configs for txn-id: %" PRIu64
					  " to candidate, err: '%s'",
					  txn->txn_id, err_buf);
			return -1;
		}

		gettimeofday(&edit_nb_cfg_end, NULL);
		edit_nb_cfg_tm = timeval_elapsed(edit_nb_cfg_end, edit_nb_cfg_start);
		client_ctx->avg_edit_nb_cfg_tm =
			((client_ctx->avg_edit_nb_cfg_tm * client_ctx->num_edit_nb_cfg) +
			 edit_nb_cfg_tm) /
			(client_ctx->num_edit_nb_cfg + 1);
		client_ctx->num_edit_nb_cfg++;
	}

	gettimeofday(&prep_nb_cfg_start, NULL);
	err = nb_candidate_commit_prepare(nb_ctx, client_ctx->candidate_config,
					  "MGMTD Backend Txn", &txn->nb_txn,
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
					  true, true,
#else
					  false, true,
#endif
					  err_buf, sizeof(err_buf) - 1);
	if (err != NB_OK) {
		err_buf[sizeof(err_buf) - 1] = 0;
		if (err == NB_ERR_VALIDATION)
			log_err_be_client("Failed to validate configs txn-id: %" PRIu64
					  " %zu batches, err: '%s'",
					  txn->txn_id, num_processed, err_buf);
		else
			log_err_be_client("Failed to prepare configs for txn-id: %" PRIu64
					  " %zu batches, err: '%s'",
					  txn->txn_id, num_processed, err_buf);
		error = true;
		SET_FLAG(txn->flags, MGMTD_BE_TXN_FLAGS_CFGPREP_FAILED);
	} else
		debug_be_client("Prepared configs for txn-id: %" PRIu64
				" %zu batches",
				txn->txn_id, num_processed);

	gettimeofday(&prep_nb_cfg_end, NULL);
	prep_nb_cfg_tm = timeval_elapsed(prep_nb_cfg_end, prep_nb_cfg_start);
	client_ctx->avg_prep_nb_cfg_tm = ((client_ctx->avg_prep_nb_cfg_tm *
					   client_ctx->num_prep_nb_cfg) +
					  prep_nb_cfg_tm) /
					 (client_ctx->num_prep_nb_cfg + 1);
	client_ctx->num_prep_nb_cfg++;

	mgmt_be_send_cfg_reply(client_ctx, txn->txn_id, !error, error ? err_buf : NULL);

	debug_be_client("Avg-nb-edit-duration %Lu uSec, nb-prep-duration %lu (avg: %Lu) uSec, batch size %u",
			client_ctx->avg_edit_nb_cfg_tm, prep_nb_cfg_tm,
			client_ctx->avg_prep_nb_cfg_tm, (uint32_t)num_processed);

	if (error)
		mgmt_be_txn_cfg_abort(txn);

	return 0;
}

static void be_client_handle_cfg(struct mgmt_be_client *client, uint64_t txn_id, void *msgbuf,
				 size_t msg_len)
{
	struct mgmt_msg_cfg_req *msg = msgbuf;
	struct mgmt_be_txn_ctx *txn;
	const char **config = NULL;

	debug_be_client("Got CFG_DATA_REQ txn-id: %Lu", txn_id);

	txn = mgmt_be_find_txn_by_id(client, txn_id, true);
	if (!txn) {
		log_err_be_client("Can't find TXN for txn_id: %Lu", txn_id);
		goto failed;
	}

	config = mgmt_msg_native_strings_decode(msg, msg_len, msg->config);
	if (darr_len(config) == 0) {
		log_err_be_client("No config data in CFG_REQ");
		goto failed;
	}

	debug_be_client("End of data; CFG_PREPARE_REQ processing");

	if (mgmt_be_txn_cfg_prepare(txn, config))
		goto failed;

	darr_free_free(config);
	return;

failed:
	darr_free_free(config);
	msg_conn_disconnect(&client->client.conn, true);
}

/* ----------------------------- */
/* Apply Config Message Handling */
/* ----------------------------- */

static int mgmt_be_send_apply_reply(struct mgmt_be_client *client_ctx,
				    uint64_t txn_id, bool success,
				    const char *error_if_any)
{
	struct mgmt_msg_cfg_apply_reply *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_apply_reply, 0,
					MTYPE_MSG_NATIVE_CFG_APPLY_REPLY);
	msg->code = MGMT_MSG_CODE_CFG_APPLY_REPLY;
	msg->refer_id = txn_id;

	debug_be_client("Sending CFG_APPLY_REPLY txn-id %" PRIu64, txn_id);

	ret = be_client_send_native_msg(client_ctx, msg, mgmt_msg_native_get_msg_len(msg), false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

static int mgmt_be_txn_proc_cfgapply(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_client *client_ctx;
	struct timeval apply_nb_cfg_start;
	struct timeval apply_nb_cfg_end;
	unsigned long apply_nb_cfg_tm;
	char err_buf[BUFSIZ];

	assert(txn && txn->client);
	client_ctx = txn->client;

	assert(txn->nb_txn);

	/*
	 * Now apply all the batches we have applied in one go.
	 */
	gettimeofday(&apply_nb_cfg_start, NULL);
	(void)nb_candidate_commit_apply(txn->nb_txn, true, &txn->nb_txn_id,
					err_buf, sizeof(err_buf) - 1);
	gettimeofday(&apply_nb_cfg_end, NULL);

	apply_nb_cfg_tm = timeval_elapsed(apply_nb_cfg_end, apply_nb_cfg_start);
	client_ctx->avg_apply_nb_cfg_tm =
		((client_ctx->avg_apply_nb_cfg_tm * client_ctx->num_apply_nb_cfg) + apply_nb_cfg_tm) /
		(client_ctx->num_apply_nb_cfg + 1);
	client_ctx->num_apply_nb_cfg++;
	txn->nb_txn = NULL;

	mgmt_be_send_apply_reply(client_ctx, txn->txn_id, true, NULL);

	debug_be_client("Nb-apply-duration %lu (avg: %Lu) uSec", apply_nb_cfg_tm,
			client_ctx->avg_apply_nb_cfg_tm);

	return 0;
}

static void be_client_handle_cfg_apply(struct mgmt_be_client *client, uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn;

	debug_be_client("Got CFG_APPLY_REQ for client %s txn-id %Lu", client->name, txn_id);

	txn = mgmt_be_find_txn_by_id(client, txn_id, true);
	if (!txn || mgmt_be_txn_proc_cfgapply(txn))
		msg_conn_disconnect(&client->client.conn, true);
}


struct be_client_tree_data_batch_args {
	struct mgmt_be_client *client;
	uint64_t txn_id;
	uint64_t req_id;
	LYD_FORMAT result_type;
};

/*
 * Process the get-tree request on our local oper state
 */
static enum nb_error be_client_send_tree_data_batch(const struct lyd_node *tree,
						    void *arg, enum nb_error ret)
{
	struct be_client_tree_data_batch_args *args = arg;
	struct mgmt_be_client *client = args->client;
	struct mgmt_msg_tree_data *tree_msg = NULL;
	bool more = false;
	uint8_t **darrp;
	LY_ERR err;

	if (ret == NB_YIELD) {
		more = true;
		ret = NB_OK;
	}
	if (ret != NB_OK) {
		if (be_client_send_error(client, args->txn_id, args->req_id, false, -EINVAL,
					 "BE client %s txn-id %Lu error fetching oper state %d",
					 client->name, args->txn_id, ret))
			ret = NB_ERR;
		else
			ret = NB_OK;
		goto done;
	}

	tree_msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_tree_data, 0,
					     MTYPE_MSG_NATIVE_TREE_DATA);
	tree_msg->refer_id = args->txn_id;
	tree_msg->req_id = args->req_id;
	tree_msg->code = MGMT_MSG_CODE_TREE_DATA;
	tree_msg->result_type = args->result_type;
	tree_msg->more = more;

	darrp = mgmt_msg_native_get_darrp(tree_msg);
	err = yang_print_tree_append(darrp, tree, args->result_type,
				     (LYD_PRINT_SHRINK | LYD_PRINT_WD_EXPLICIT |
				      LYD_PRINT_WITHSIBLINGS));
	if (err) {
		mgmt_msg_native_free_msg(tree_msg);
		/* We will be called again to send the error */
		return NB_ERR;
	}
	(void)be_client_send_native_msg(client, tree_msg,
					mgmt_msg_native_get_msg_len(tree_msg),
					false);
	mgmt_msg_native_free_msg(tree_msg);
done:
	if (ret != NB_OK || !more)
		XFREE(MTYPE_MGMTD_BE_GT_CB_ARGS, args);
	return ret;
}

/*
 * Process the get-tree request on our local oper state
 */
static void be_client_handle_get_tree(struct mgmt_be_client *client,
				      uint64_t txn_id, void *msgbuf,
				      size_t msg_len)
{
	struct mgmt_msg_get_tree *get_tree_msg = msgbuf;
	struct be_client_tree_data_batch_args *args;

	debug_be_client("Received get-tree request for client %s txn-id %" PRIu64
			" req-id %" PRIu64,
			client->name, txn_id, get_tree_msg->req_id);

	/* NOTE: removed the translator, if put back merge with northbound_cli
	 * code
	 */

	args = XMALLOC(MTYPE_MGMTD_BE_GT_CB_ARGS, sizeof(*args));
	args->client = client;
	args->txn_id = get_tree_msg->refer_id;
	args->req_id = get_tree_msg->req_id;
	args->result_type = get_tree_msg->result_type;
	nb_oper_walk(get_tree_msg->xpath, NULL, 0, true, NULL, NULL,
		   be_client_send_tree_data_batch, args);
}

static void be_client_send_rpc_reply(struct mgmt_be_client *client,
				     uint64_t txn_id, uint64_t req_id,
				     uint8_t result_type,
				     struct lyd_node *output)
{
	struct mgmt_msg_rpc_reply *rpc_reply_msg;
	uint8_t **darrp;
	LY_ERR err;
	int ret = NB_OK;

	rpc_reply_msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc_reply, 0,
						  MTYPE_MSG_NATIVE_RPC_REPLY);
	rpc_reply_msg->refer_id = txn_id;
	rpc_reply_msg->req_id = req_id;
	rpc_reply_msg->code = MGMT_MSG_CODE_RPC_REPLY;
	rpc_reply_msg->result_type = result_type;

	if (output) {
		darrp = mgmt_msg_native_get_darrp(rpc_reply_msg);
		err = yang_print_tree_append(darrp, output, result_type,
					     LYD_PRINT_SHRINK);
		lyd_free_all(output);
		if (err) {
			ret = NB_ERR;
			goto done;
		}
	}

	(void)be_client_send_native_msg(client, rpc_reply_msg,
					mgmt_msg_native_get_msg_len(
						rpc_reply_msg),
					false);
done:
	mgmt_msg_native_free_msg(rpc_reply_msg);
	if (ret != NB_OK)
		be_client_send_error(client, txn_id, req_id, false, -EINVAL,
				     "Can't format RPC reply");
}

/*
 * Process the RPC request.
 */
static void be_client_handle_rpc(struct mgmt_be_client *client, uint64_t txn_id,
				 void *msgbuf, size_t msg_len)
{
	struct mgmt_msg_rpc *rpc_msg = msgbuf;
	struct nb_node *nb_node;
	struct lyd_node *input, *output;
	const char *xpath;
	const char *data;
	char errmsg[BUFSIZ] = { 0 };
	LY_ERR err;
	int ret;

	debug_be_client("Received RPC request for client %s txn-id %" PRIu64
			" req-id %" PRIu64,
			client->name, txn_id, rpc_msg->req_id);

	xpath = mgmt_msg_native_xpath_data_decode(rpc_msg, msg_len, data);
	if (!xpath) {
		be_client_send_error(client, txn_id, rpc_msg->req_id, false,
				     -EINVAL, "Corrupt RPC message");
		return;
	}

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		be_client_send_error(client, txn_id, rpc_msg->req_id, false,
				     -EINVAL, "No schema found for RPC: %s",
				     xpath);
		return;
	}

	if (!nb_node->cbs.rpc) {
		be_client_send_error(client, txn_id, rpc_msg->req_id, false,
				     -EINVAL, "No RPC callback for: %s", xpath);
		return;
	}

	if (data) {
		err = yang_parse_rpc(xpath, rpc_msg->request_type, data, false,
				     &input);
		if (err) {
			be_client_send_error(client, txn_id, rpc_msg->req_id,
					     false, -EINVAL,
					     "Can't parse RPC data for: %s",
					     xpath);
			return;
		}
	} else {
		/*
		 * If there's no input data, create an empty input container.
		 * It is especially needed for actions, because their parents
		 * may hold necessary information.
		 */
		err = lyd_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, 0, 0,
				    NULL, &input);
		if (err) {
			be_client_send_error(client, txn_id, rpc_msg->req_id,
					     false, -EINVAL,
					     "Can't create input node for RPC: %s",
					     xpath);
			return;
		}
	}

	err = lyd_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, 0, 0, NULL,
			    &output);
	if (err) {
		lyd_free_all(input);
		be_client_send_error(client, txn_id, rpc_msg->req_id, false,
				     -EINVAL,
				     "Can't create output node for RPC: %s",
				     xpath);
		return;
	}

	ret = nb_callback_rpc(nb_node, xpath, input, output, errmsg,
			      sizeof(errmsg));
	if (ret != NB_OK) {
		lyd_free_all(input);
		lyd_free_all(output);
		be_client_send_error(client, txn_id, rpc_msg->req_id, false,
				     -EINVAL, "%s", errmsg);
		return;
	}

	lyd_free_all(input);
	if (!lyd_child(output)) {
		lyd_free_all(output);
		output = NULL;
	}

	be_client_send_rpc_reply(client, txn_id, rpc_msg->req_id,
				 rpc_msg->request_type, output);
}

/*
 * Process the notification.
 */
static void be_client_handle_notify(struct mgmt_be_client *client, void *msgbuf,
				    size_t msg_len)
{
	struct mgmt_msg_notify_data *notif_msg = msgbuf;
	struct nb_node *nb_node, *nb_parent;
	struct lyd_node *dnode = NULL;
	const char *data = NULL;
	const char *notif;
	bool is_yang_notify;
	LY_ERR err = LY_SUCCESS;

	debug_be_client("Received notification for client %s", client->name);

	notif = mgmt_msg_native_xpath_data_decode(notif_msg, msg_len, data);
	if (!notif) {
		log_err_be_client("Corrupt notify msg");
		return;
	}
	if (!data && (notif_msg->op == NOTIFY_OP_DS_REPLACE || notif_msg->op == NOTIFY_OP_DS_PATCH)) {
		log_err_be_client("Corrupt replace/patch notify msg: missing data");
		return;
	}

	nb_node = nb_node_find(notif);
	if (!nb_node) {
		log_err_be_client("No schema found for notification: %s", notif);
		return;
	}

	is_yang_notify = !!CHECK_FLAG(nb_node->snode->nodetype, LYS_NOTIF);

	if (is_yang_notify && !nb_node->cbs.notify) {
		debug_be_client("No notification callback for: %s", notif);
		return;
	}

	if (!nb_node->cbs.notify) {
		/*
		 * See if a parent has a callback, this is so backend's can
		 * listen for changes on an entire datastore sub-tree.
		 */
		for (nb_parent = nb_node->parent; nb_parent; nb_parent = nb_node->parent)
			if (nb_parent->cbs.notify)
				break;
		if (!nb_parent) {
			debug_be_client("Including parents, no DS notification callback for: %s",
					notif);
			return;
		}
		nb_node = nb_parent;
	}

	if (data && is_yang_notify) {
		err = yang_parse_notification(notif, notif_msg->result_type, data, &dnode);
	} else if (data) {
		err = yang_parse_data(notif, notif_msg->result_type, false, true, false, data,
				      &dnode);
	}
	if (err) {
		log_err_be_client("Can't parse notification data for: %s", notif);
		return;
	}

	nb_callback_notify(nb_node, notif_msg->op, notif, dnode);

	lyd_free_all(dnode);
}

/*
 * Process a notify select msg
 */
static void be_client_handle_notify_select(struct mgmt_be_client *client, void *msgbuf,
					   size_t msg_len)
{
	struct mgmt_msg_notify_select *msg = msgbuf;
	const char **selectors = NULL;

	debug_be_client("Received notify-select for client %s", client->name);

	if (msg_len >= sizeof(*msg))
		selectors = mgmt_msg_native_strings_decode(msg, msg_len, msg->selectors);
	if (!msg->get_only)
		nb_notif_set_filters(selectors, msg->replace);
	else
		nb_notif_get_state(selectors, msg->refer_id);
}

/*
 * Handle a native encoded message
 *
 * We don't create transactions with native messaging.
 */
static void be_client_handle_native_msg(struct mgmt_be_client *client,
					struct mgmt_msg_header *msg,
					size_t msg_len)
{
	uint64_t txn_id = msg->refer_id;

	switch (msg->code) {
	case MGMT_MSG_CODE_TXN_REQ:
		be_client_handle_txn_req(client, txn_id, msg, msg_len);
		break;
	case MGMT_MSG_CODE_CFG_REQ:
		be_client_handle_cfg(client, txn_id, msg, msg_len);
		break;
	case MGMT_MSG_CODE_CFG_APPLY_REQ:
		be_client_handle_cfg_apply(client, txn_id);
		break;
	case MGMT_MSG_CODE_GET_TREE:
		be_client_handle_get_tree(client, txn_id, msg, msg_len);
		break;
	case MGMT_MSG_CODE_RPC:
		be_client_handle_rpc(client, txn_id, msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY:
		be_client_handle_notify(client, msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY_SELECT:
		be_client_handle_notify_select(client, msg, msg_len);
		break;
	default:
		log_err_be_client("unknown native message txn-id %" PRIu64
				  " req-id %" PRIu64 " code %u to client %s",
				  txn_id, msg->req_id, msg->code, client->name);
		be_client_send_error(client, msg->refer_id, msg->req_id, false,
				     -1,
				     "BE client %s recv msg unknown txn-id %" PRIu64,
				     client->name, txn_id);
		break;
	}
}

static void mgmt_be_client_process_msg(uint8_t version, uint8_t *data,
				       size_t len, struct msg_conn *conn)
{
	struct mgmt_be_client *client_ctx;
	struct msg_client *client;

	client = container_of(conn, struct msg_client, conn);
	client_ctx = container_of(client, struct mgmt_be_client, client);

	if (version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *msg = (typeof(msg))data;

		if (len >= sizeof(*msg))
			be_client_handle_native_msg(client_ctx, msg, len);
		else
			log_err_be_client("native message to client %s too short %zu",
					  client_ctx->name, len);
		return;
	}

	log_err_be_client("Protobuf no longer used in backend API");
	msg_conn_disconnect(&client_ctx->client.conn, true);
}

/**
 * mgmt_be_send_subscribe() - Send subscription request to mgmtd.
 * @client: the client.
 *
 * Return: 0 on success, negative value on error.
 */
static int mgmt_be_send_subscribe(struct mgmt_be_client *client)
{
	const struct mgmt_be_client_cbs *cbs = &client->cbs;
	struct mgmt_msg_subscribe *msg;
	int ret;
	uint i;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_subscribe, 0, MTYPE_MSG_NATIVE_SUBSCRIBE);
	msg->code = MGMT_MSG_CODE_SUBSCRIBE;

	mgmt_msg_native_add_str(msg, client->name);

	for (i = 0; i < cbs->nconfig_xpaths; i++)
		mgmt_msg_native_add_str(msg, cbs->config_xpaths[i]);
	msg->nconfig = cbs->nconfig_xpaths;

	for (i = 0; i < cbs->noper_xpaths; i++)
		mgmt_msg_native_add_str(msg, cbs->oper_xpaths[i]);
	msg->noper = cbs->noper_xpaths;

	for (i = 0; i < cbs->nnotify_xpaths; i++)
		mgmt_msg_native_add_str(msg, cbs->notify_xpaths[i]);
	msg->nnotify = cbs->nnotify_xpaths;

	for (i = 0; i < cbs->nrpc_xpaths; i++)
		mgmt_msg_native_add_str(msg, cbs->rpc_xpaths[i]);
	msg->nrpc = cbs->nrpc_xpaths;

	debug_be_client("Sending SUBSCRIBE name: %s xpaths: config %d oper: %d notify: %d rpc: %d",
			client->name, cbs->nconfig_xpaths, cbs->noper_xpaths, cbs->nnotify_xpaths,
			cbs->nrpc_xpaths);

	ret = be_client_send_native_msg(client, msg, mgmt_msg_native_get_msg_len(msg), false);
	mgmt_msg_native_free_msg(msg);

	return ret;
}

static int _notify_conenct_disconnect(struct msg_client *msg_client,
				      bool connected)
{
	struct mgmt_be_client *client =
		container_of(msg_client, struct mgmt_be_client, client);
	int ret;

	if (connected) {
		assert(msg_client->conn.fd != -1);
		ret = mgmt_be_send_subscribe(client);
		if (ret)
			return ret;
	}

	/* Notify BE client through registered callback (if any) */
	if (client->cbs.client_connect_notify)
		(void)(*client->cbs.client_connect_notify)(client,
							   client->user_data,
							   connected);

	/* Cleanup any in-progress TXN on disconnect */
	if (!connected)
		mgmt_be_cleanup_all_txns(client);

	return 0;
}

static int mgmt_be_client_notify_conenct(struct msg_client *client)
{
	return _notify_conenct_disconnect(client, true);
}

static int mgmt_be_client_notify_disconenct(struct msg_conn *conn)
{
	struct msg_client *client = container_of(conn, struct msg_client, conn);

	return _notify_conenct_disconnect(client, false);
}

/*
 * Debug Flags
 */

static void mgmt_debug_client_be_set(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&mgmt_dbg_be_client, flags, set);

	if (!__be_client)
		return;

	__be_client->client.conn.debug = DEBUG_MODE_CHECK(&mgmt_dbg_be_client,
							  DEBUG_MODE_ALL);
}

DEFPY(debug_mgmt_client_be, debug_mgmt_client_be_cmd,
      "[no] debug mgmt client backend",
      NO_STR DEBUG_STR MGMTD_STR "client\n"
				 "backend\n")
{
	mgmt_debug_client_be_set(DEBUG_NODE2MODE(vty->node), !no);

	return CMD_SUCCESS;
}

/*
 * XPath: /frr-backend:clients/client
 *
 * We only implement a list of one entry (for the this backend client) the
 * results will be merged inside mgmtd.
 */
static const void *clients_client_get_next(struct nb_cb_get_next_args *args)
{
	if (args->list_entry == NULL)
		return __be_client;
	return NULL;
}

static int clients_client_get_keys(struct nb_cb_get_keys_args *args)
{
	args->keys->num = 1;
	strlcpy(args->keys->key[0], __be_client->name, sizeof(args->keys->key[0]));

	return NB_OK;
}

static const void *clients_client_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];

	if (!strcmp(name, __be_client->name))
		return __be_client;

	return NULL;
}

/*
 * XPath: /frr-backend:clients/client/name
 */
static enum nb_error clients_client_name_get(const struct nb_node *nb_node,
					     const void *parent_list_entry, struct lyd_node *parent)
{
	const struct lysc_node *snode = nb_node->snode;
	LY_ERR err;

	err = lyd_new_term(parent, snode->module, snode->name, __be_client->name, false, NULL);
	if (err != LY_SUCCESS)
		return NB_ERR_RESOURCE;

	return NB_OK;
}

/*
 * XPath: /frr-backend:clients/client/state/candidate-config-version
 */
static enum nb_error clients_client_state_candidate_config_version_get(
	const struct nb_node *nb_node, const void *parent_list_entry, struct lyd_node *parent)
{
	const struct lysc_node *snode = nb_node->snode;
	uint64_t value = __be_client->candidate_config->version;

	if (lyd_new_term_bin(parent, snode->module, snode->name, &value, sizeof(value),
			     LYD_NEW_PATH_UPDATE, NULL))
		return NB_ERR_RESOURCE;

	return NB_OK;
}

/*
 * XPath: /frr-backend:clients/client/state/running-config-version
 */
static enum nb_error clients_client_state_running_config_version_get(const struct nb_node *nb_node,
								     const void *parent_list_entry,
								     struct lyd_node *parent)
{
	const struct lysc_node *snode = nb_node->snode;
	uint64_t value = __be_client->running_config->version;

	if (lyd_new_term_bin(parent, snode->module, snode->name, &value, sizeof(value),
			     LYD_NEW_PATH_UPDATE, NULL))
		return NB_ERR_RESOURCE;

	return NB_OK;
}

/*
 * XPath: /frr-backend:clients/client/state/notify-selectors
 *
 * Is this better in northbound_notif.c? Let's decide when we add more to this module.
 */

static enum nb_error clients_client_state_notify_selectors_get(const struct nb_node *nb_node,
							       const void *parent_list_entry,
							       struct lyd_node *parent)
{
	const struct lysc_node *snode = nb_node->snode;
	const char **p;
	LY_ERR err;

	darr_foreach_p (nb_notif_filters, p) {
		err = lyd_new_term(parent, snode->module, snode->name, *p, false, NULL);
		if (err != LY_SUCCESS)
			return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_backend_info = {
	.name = "frr-backend",
	.nodes = {
		{
			.xpath = "/frr-backend:clients/client",
			.cbs = {
				.get_next = clients_client_get_next,
				.get_keys = clients_client_get_keys,
				.lookup_entry = clients_client_lookup_entry,
			}
		},
		{
			.xpath = "/frr-backend:clients/client/name",
			.cbs.get = clients_client_name_get,
		},
		{
			.xpath = "/frr-backend:clients/client/state/candidate-config-version",
			.cbs = {
				.get = clients_client_state_candidate_config_version_get,
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/running-config-version",
			.cbs = {
				.get = clients_client_state_running_config_version_get,
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/edit-count",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, num_edit_nb_cfg),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/avg-edit-time",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, avg_edit_nb_cfg_tm),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/prep-count",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, num_prep_nb_cfg),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/avg-prep-time",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, avg_prep_nb_cfg_tm),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/apply-count",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, num_apply_nb_cfg),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/avg-apply-time",
			.cbs = {
				.get = nb_oper_uint64_get,
				.get_elem = (void *)(intptr_t)offsetof(struct mgmt_be_client, avg_apply_nb_cfg_tm),
			}
		},
		{
			.xpath = "/frr-backend:clients/client/state/notify-selectors",
			.cbs.get = clients_client_state_notify_selectors_get,
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

struct mgmt_be_client *mgmt_be_client_create(const char *client_name,
					     struct mgmt_be_client_cbs *cbs,
					     uintptr_t user_data,
					     struct event_loop *event_loop)
{
	struct mgmt_be_client *client;
	char server_path[MAXPATHLEN];

	if (__be_client)
		return NULL;

	client = XCALLOC(MTYPE_MGMTD_BE_CLIENT, sizeof(*client));
	__be_client = client;

	/* Only call after frr_init() */
	assert(running_config);

	client->name = XSTRDUP(MTYPE_MGMTD_BE_CLIENT_NAME, client_name);
	client->running_config = running_config;
	client->candidate_config = vty_shared_candidate_config;
	if (cbs)
		client->cbs = *cbs;
	mgmt_be_txns_init(&client->txn_head);

	snprintf(server_path, sizeof(server_path), MGMTD_BE_SOCK_NAME);

	msg_client_init(&client->client, event_loop, server_path,
			mgmt_be_client_notify_conenct,
			mgmt_be_client_notify_disconenct,
			mgmt_be_client_process_msg, MGMTD_BE_MAX_NUM_MSG_PROC,
			MGMTD_BE_MAX_NUM_MSG_WRITE, MGMTD_BE_MAX_MSG_LEN, false,
			"BE-client", debug_check_be_client());

	/* Hook to receive notifications */
	hook_register_arg(nb_notification_tree_send, mgmt_be_send_notification,
			  client);

	debug_be_client("Initialized client '%s'", client_name);

	return client;
}


void mgmt_be_client_lib_vty_init(void)
{
	debug_install(&mgmt_dbg_be_client);

	install_element(ENABLE_NODE, &debug_mgmt_client_be_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_client_be_cmd);
}

void mgmt_be_client_destroy(struct mgmt_be_client *client)
{
	assert(client == __be_client);

	debug_be_client("Destroying MGMTD Backend Client '%s'", client->name);

	nb_oper_cancel_all_walks();
	msg_client_cleanup(&client->client);
	mgmt_be_cleanup_all_txns(client);
	mgmt_be_txns_fini(&client->txn_head);

	XFREE(MTYPE_MGMTD_BE_CLIENT_NAME, client->name);
	XFREE(MTYPE_MGMTD_BE_CLIENT, client);

	__be_client = NULL;
}
