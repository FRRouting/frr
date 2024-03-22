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
#include "mgmt_pb.h"
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

enum mgmt_be_txn_event {
	MGMTD_BE_TXN_PROC_SETCFG = 1,
	MGMTD_BE_TXN_PROC_GETCFG,
};

struct mgmt_be_set_cfg_req {
	struct nb_cfg_change cfg_changes[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
};

struct mgmt_be_txn_req {
	enum mgmt_be_txn_event event;
	union {
		struct mgmt_be_set_cfg_req set_cfg;
	} req;
};

struct be_oper_iter_arg {
	struct lyd_node *root; /* the tree we are building */
	struct lyd_node *hint; /* last node added */
};

PREDECL_LIST(mgmt_be_batches);
struct mgmt_be_batch_ctx {
	struct mgmt_be_txn_req txn_req;

	uint32_t flags;

	struct mgmt_be_batches_item list_linkage;
};
#define MGMTD_BE_BATCH_FLAGS_CFG_PREPARED (1U << 0)
#define MGMTD_BE_TXN_FLAGS_CFG_APPLIED (1U << 1)
DECLARE_LIST(mgmt_be_batches, struct mgmt_be_batch_ctx, list_linkage);

PREDECL_LIST(mgmt_be_txns);
struct mgmt_be_txn_ctx {
	/* Txn-Id as assigned by MGMTD */
	uint64_t txn_id;
	uint32_t flags;

	struct mgmt_be_client_txn_ctx client_data;
	struct mgmt_be_client *client;

	/* List of batches belonging to this transaction */
	struct mgmt_be_batches_head cfg_batches;
	struct mgmt_be_batches_head apply_cfgs;

	struct mgmt_be_txns_item list_linkage;

	struct nb_transaction *nb_txn;
	uint32_t nb_txn_id;
};
#define MGMTD_BE_TXN_FLAGS_CFGPREP_FAILED (1U << 1)

DECLARE_LIST(mgmt_be_txns, struct mgmt_be_txn_ctx, list_linkage);

#define FOREACH_BE_TXN_BATCH_IN_LIST(txn, batch)                               \
	frr_each_safe (mgmt_be_batches, &(txn)->cfg_batches, (batch))

#define FOREACH_BE_APPLY_BATCH_IN_LIST(txn, batch)                             \
	frr_each_safe (mgmt_be_batches, &(txn)->apply_cfgs, (batch))

struct mgmt_be_client {
	struct msg_client client;

	char *name;

	struct nb_config *candidate_config;
	struct nb_config *running_config;

	unsigned long num_edit_nb_cfg;
	unsigned long avg_edit_nb_cfg_tm;
	unsigned long num_prep_nb_cfg;
	unsigned long avg_prep_nb_cfg_tm;
	unsigned long num_apply_nb_cfg;
	unsigned long avg_apply_nb_cfg_tm;

	struct mgmt_be_txns_head txn_head;

	struct mgmt_be_client_cbs cbs;
	uintptr_t user_data;
};

#define FOREACH_BE_TXN_IN_LIST(client_ctx, txn)                                \
	frr_each_safe (mgmt_be_txns, &(client_ctx)->txn_head, (txn))

struct debug mgmt_dbg_be_client = {
	.desc = "Management backend client operations"
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

static int mgmt_be_client_send_msg(struct mgmt_be_client *client_ctx,
				   Mgmtd__BeMessage *be_msg)
{
	return msg_conn_send_msg(
		&client_ctx->client.conn, MGMT_MSG_VERSION_PROTOBUF, be_msg,
		mgmtd__be_message__get_packed_size(be_msg),
		(size_t(*)(void *, void *))mgmtd__be_message__pack, false);
}

static struct mgmt_be_batch_ctx *
mgmt_be_batch_create(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_batch_ctx *batch = NULL;

	batch = XCALLOC(MTYPE_MGMTD_BE_BATCH, sizeof(struct mgmt_be_batch_ctx));

	mgmt_be_batches_add_tail(&txn->cfg_batches, batch);

	debug_be_client("Added new batch to transaction");

	return batch;
}

static void mgmt_be_batch_delete(struct mgmt_be_txn_ctx *txn,
				    struct mgmt_be_batch_ctx **batch)
{
	uint16_t indx;

	if (!batch)
		return;

	mgmt_be_batches_del(&txn->cfg_batches, *batch);
	if ((*batch)->txn_req.event == MGMTD_BE_TXN_PROC_SETCFG) {
		for (indx = 0; indx < MGMTD_MAX_CFG_CHANGES_IN_BATCH; indx++) {
			if ((*batch)->txn_req.req.set_cfg.cfg_changes[indx]
				    .value) {
				free((char *)(*batch)
					     ->txn_req.req.set_cfg
					     .cfg_changes[indx]
					     .value);
			}
		}
	}

	XFREE(MTYPE_MGMTD_BE_BATCH, *batch);
	*batch = NULL;
}

static void mgmt_be_cleanup_all_batches(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_batch_ctx *batch = NULL;

	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		mgmt_be_batch_delete(txn, &batch);
	}

	FOREACH_BE_APPLY_BATCH_IN_LIST (txn, batch) {
		mgmt_be_batch_delete(txn, &batch);
	}
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
	mgmt_be_batches_init(&txn->cfg_batches);
	mgmt_be_batches_init(&txn->apply_cfgs);
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
	 * Time to delete the transaction which should also
	 * take care of cleaning up all batches created via
	 * CFGDATA_CREATE_REQs. But first notify the client
	 * about the transaction delete.
	 */
	if (client_ctx->cbs.txn_notify)
		(void)(*client_ctx->cbs.txn_notify)(client_ctx,
						    client_ctx->user_data,
						    &(*txn)->client_data, true);

	mgmt_be_cleanup_all_batches(*txn);
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

static int mgmt_be_send_notification(void *__be_client, const char *xpath,
				     const struct lyd_node *tree)
{
	struct mgmt_be_client *client = __be_client;
	struct mgmt_msg_notify_data *msg = NULL;
	LYD_FORMAT format = LYD_JSON;
	uint8_t **darrp;
	LY_ERR err;
	int ret = 0;

	assert(tree);

	debug_be_client("%s: sending YANG notification: %s", __func__,
			tree->schema->name);
	/*
	 * Allocate a message and append the data to it using `format`
	 */
	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_notify_data, 0,
					MTYPE_MSG_NATIVE_NOTIFY);
	msg->code = MGMT_MSG_CODE_NOTIFY;
	msg->result_type = format;

	mgmt_msg_native_xpath_encode(msg, xpath);

	darrp = mgmt_msg_native_get_darrp(msg);
	err = yang_print_tree_append(darrp, tree, format,
				     (LYD_PRINT_SHRINK | LYD_PRINT_WD_EXPLICIT |
				      LYD_PRINT_WITHSIBLINGS));
	if (err) {
		flog_err(EC_LIB_LIBYANG,
			 "%s: error creating notification data: %s", __func__,
			 ly_strerrcode(err));
		ret = 1;
		goto done;
	}

	(void)be_client_send_native_msg(client, msg,
					mgmt_msg_native_get_msg_len(msg), false);
done:
	mgmt_msg_native_free_msg(msg);
	return ret;
}

static int mgmt_be_send_txn_reply(struct mgmt_be_client *client_ctx,
				  uint64_t txn_id, bool create)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeTxnReply txn_reply;

	mgmtd__be_txn_reply__init(&txn_reply);
	txn_reply.create = create;
	txn_reply.txn_id = txn_id;
	txn_reply.success = true;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY;
	be_msg.txn_reply = &txn_reply;

	debug_be_client("Sending TXN_REPLY txn-id %" PRIu64, txn_id);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static int mgmt_be_process_txn_req(struct mgmt_be_client *client_ctx,
				   uint64_t txn_id, bool create)
{
	struct mgmt_be_txn_ctx *txn;

	if (create) {
		debug_be_client("Creating new txn-id %" PRIu64, txn_id);

		txn = mgmt_be_txn_create(client_ctx, txn_id);
		if (!txn)
			goto failed;

		if (client_ctx->cbs.txn_notify)
			(*client_ctx->cbs.txn_notify)(client_ctx,
						      client_ctx->user_data,
						      &txn->client_data, false);
	} else {
		debug_be_client("Deleting txn-id: %" PRIu64, txn_id);
		txn = mgmt_be_find_txn_by_id(client_ctx, txn_id, false);
		if (txn)
			mgmt_be_txn_delete(client_ctx, &txn);
	}

	return mgmt_be_send_txn_reply(client_ctx, txn_id, create);

failed:
	msg_conn_disconnect(&client_ctx->client.conn, true);
	return -1;
}

static int mgmt_be_send_cfgdata_create_reply(struct mgmt_be_client *client_ctx,
					     uint64_t txn_id, bool success,
					     const char *error_if_any)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataCreateReply cfgdata_reply;

	mgmtd__be_cfg_data_create_reply__init(&cfgdata_reply);
	cfgdata_reply.txn_id = (uint64_t)txn_id;
	cfgdata_reply.success = success;
	if (error_if_any)
		cfgdata_reply.error_if_any = (char *)error_if_any;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY;
	be_msg.cfg_data_reply = &cfgdata_reply;

	debug_be_client("Sending CFGDATA_CREATE_REPLY txn-id: %" PRIu64, txn_id);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
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

static int mgmt_be_txn_cfg_prepare(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_client *client_ctx;
	struct mgmt_be_txn_req *txn_req = NULL;
	struct nb_context nb_ctx = {0};
	struct timeval edit_nb_cfg_start;
	struct timeval edit_nb_cfg_end;
	unsigned long edit_nb_cfg_tm;
	struct timeval prep_nb_cfg_start;
	struct timeval prep_nb_cfg_end;
	unsigned long prep_nb_cfg_tm;
	struct mgmt_be_batch_ctx *batch;
	bool error;
	char err_buf[BUFSIZ];
	size_t num_processed;
	int err;

	assert(txn && txn->client);
	client_ctx = txn->client;

	num_processed = 0;
	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		txn_req = &batch->txn_req;
		error = false;
		nb_ctx.client = NB_CLIENT_CLI;
		nb_ctx.user = (void *)client_ctx->user_data;

		if (!txn->nb_txn) {
			/*
			 * This happens when the current backend client is only
			 * interested in consuming the config items but is not
			 * interested in validating it.
			 */
			error = false;

			gettimeofday(&edit_nb_cfg_start, NULL);
			nb_candidate_edit_config_changes(
				client_ctx->candidate_config,
				txn_req->req.set_cfg.cfg_changes,
				(size_t)txn_req->req.set_cfg.num_cfg_changes,
				NULL, true, err_buf, sizeof(err_buf), &error);
			if (error) {
				err_buf[sizeof(err_buf) - 1] = 0;
				log_err_be_client("Failed to update configs for txn-id: %" PRIu64
						  " to candidate, err: '%s'",
						  txn->txn_id, err_buf);
				return -1;
			}
			gettimeofday(&edit_nb_cfg_end, NULL);
			edit_nb_cfg_tm = timeval_elapsed(edit_nb_cfg_end,
							 edit_nb_cfg_start);
			client_ctx->avg_edit_nb_cfg_tm =
				((client_ctx->avg_edit_nb_cfg_tm *
				  client_ctx->num_edit_nb_cfg) +
				 edit_nb_cfg_tm) /
				(client_ctx->num_edit_nb_cfg + 1);
			client_ctx->num_edit_nb_cfg++;
		}

		num_processed++;
	}

	if (!num_processed)
		return 0;

	/*
	 * Now prepare all the batches we have applied in one go.
	 */
	nb_ctx.client = NB_CLIENT_CLI;
	nb_ctx.user = (void *)client_ctx->user_data;

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

	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		if (!error) {
			SET_FLAG(batch->flags,
				 MGMTD_BE_BATCH_FLAGS_CFG_PREPARED);
			mgmt_be_batches_del(&txn->cfg_batches, batch);
			mgmt_be_batches_add_tail(&txn->apply_cfgs, batch);
		}
	}

	mgmt_be_send_cfgdata_create_reply(client_ctx, txn->txn_id,
		error ? false : true, error ? err_buf : NULL);

	debug_be_client("Avg-nb-edit-duration %lu uSec, nb-prep-duration %lu (avg: %lu) uSec, batch size %u",
			client_ctx->avg_edit_nb_cfg_tm, prep_nb_cfg_tm,
			client_ctx->avg_prep_nb_cfg_tm, (uint32_t)num_processed);

	if (error)
		mgmt_be_txn_cfg_abort(txn);

	return 0;
}

/*
 * Process all CFG_DATA_REQs received so far and prepare them all in one go.
 */
static int mgmt_be_update_setcfg_in_batch(struct mgmt_be_client *client_ctx,
					  struct mgmt_be_txn_ctx *txn,
					  Mgmtd__YangCfgDataReq *cfg_req[],
					  int num_req)
{
	struct mgmt_be_batch_ctx *batch = NULL;
	struct mgmt_be_txn_req *txn_req = NULL;
	int index;
	struct nb_cfg_change *cfg_chg;

	batch = mgmt_be_batch_create(txn);
	assert(batch);

	txn_req = &batch->txn_req;
	txn_req->event = MGMTD_BE_TXN_PROC_SETCFG;
	debug_be_client("Created SETCFG request for txn-id: %" PRIu64
			" cfg-items:%d",
			txn->txn_id, num_req);

	txn_req->req.set_cfg.num_cfg_changes = num_req;
	for (index = 0; index < num_req; index++) {
		cfg_chg = &txn_req->req.set_cfg.cfg_changes[index];

		/*
		 * Treat all operations as destroy or modify, because we don't
		 * need additional existence checks on the backend. Everything
		 * is already checked by mgmtd.
		 */
		switch (cfg_req[index]->req_type) {
		case MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA:
		case MGMTD__CFG_DATA_REQ_TYPE__REMOVE_DATA:
			cfg_chg->operation = NB_OP_DESTROY;
			break;
		case MGMTD__CFG_DATA_REQ_TYPE__SET_DATA:
		case MGMTD__CFG_DATA_REQ_TYPE__CREATE_DATA:
		case MGMTD__CFG_DATA_REQ_TYPE__REPLACE_DATA:
			cfg_chg->operation = NB_OP_MODIFY;
			break;
		case MGMTD__CFG_DATA_REQ_TYPE__REQ_TYPE_NONE:
		case _MGMTD__CFG_DATA_REQ_TYPE_IS_INT_SIZE:
		default:
			continue;
		}

		strlcpy(cfg_chg->xpath, cfg_req[index]->data->xpath,
			sizeof(cfg_chg->xpath));
		cfg_chg->value = (cfg_req[index]->data->value
						  && cfg_req[index]
							     ->data->value
							     ->encoded_str_val
					  ? strdup(cfg_req[index]
							   ->data->value
							   ->encoded_str_val)
					  : NULL);
		if (cfg_chg->value
		    && !strncmp(cfg_chg->value, MGMTD_BE_CONTAINER_NODE_VAL,
				strlen(MGMTD_BE_CONTAINER_NODE_VAL))) {
			free((char *)cfg_chg->value);
			cfg_chg->value = NULL;
		}
	}

	return 0;
}

static int mgmt_be_process_cfgdata_req(struct mgmt_be_client *client_ctx,
				       uint64_t txn_id,
				       Mgmtd__YangCfgDataReq *cfg_req[],
				       int num_req, bool end_of_data)
{
	struct mgmt_be_txn_ctx *txn;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id, true);
	if (!txn)
		goto failed;

	mgmt_be_update_setcfg_in_batch(client_ctx, txn, cfg_req, num_req);

	if (txn && end_of_data) {
		debug_be_client("End of data; CFG_PREPARE_REQ processing");
		if (mgmt_be_txn_cfg_prepare(txn))
			goto failed;
	}

	return 0;
failed:
	msg_conn_disconnect(&client_ctx->client.conn, true);
	return -1;
}

static int mgmt_be_send_apply_reply(struct mgmt_be_client *client_ctx,
				    uint64_t txn_id, bool success,
				    const char *error_if_any)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataApplyReply apply_reply;

	mgmtd__be_cfg_data_apply_reply__init(&apply_reply);
	apply_reply.success = success;
	apply_reply.txn_id = txn_id;

	if (error_if_any)
		apply_reply.error_if_any = (char *)error_if_any;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY;
	be_msg.cfg_apply_reply = &apply_reply;

	debug_be_client("Sending CFG_APPLY_REPLY txn-id %" PRIu64, txn_id);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static int mgmt_be_txn_proc_cfgapply(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_client *client_ctx;
	struct timeval apply_nb_cfg_start;
	struct timeval apply_nb_cfg_end;
	unsigned long apply_nb_cfg_tm;
	struct mgmt_be_batch_ctx *batch;
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
	client_ctx->avg_apply_nb_cfg_tm = ((client_ctx->avg_apply_nb_cfg_tm *
					    client_ctx->num_apply_nb_cfg) +
					   apply_nb_cfg_tm) /
					  (client_ctx->num_apply_nb_cfg + 1);
	client_ctx->num_apply_nb_cfg++;
	txn->nb_txn = NULL;

	FOREACH_BE_APPLY_BATCH_IN_LIST (txn, batch) {
		/*
		 * No need to delete the batch yet. Will be deleted during
		 * transaction cleanup on receiving TXN_DELETE_REQ.
		 */
		SET_FLAG(batch->flags, MGMTD_BE_TXN_FLAGS_CFG_APPLIED);
		mgmt_be_batches_del(&txn->apply_cfgs, batch);
		mgmt_be_batches_add_tail(&txn->cfg_batches, batch);
	}

	mgmt_be_send_apply_reply(client_ctx, txn->txn_id, true, NULL);

	debug_be_client("Nb-apply-duration %lu (avg: %lu) uSec",
			apply_nb_cfg_tm, client_ctx->avg_apply_nb_cfg_tm);

	return 0;
}

static int mgmt_be_process_cfg_apply(struct mgmt_be_client *client_ctx,
				     uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id, true);
	if (!txn)
		goto failed;

	debug_be_client("Trigger CFG_APPLY_REQ processing");
	if (mgmt_be_txn_proc_cfgapply(txn))
		goto failed;

	return 0;
failed:
	msg_conn_disconnect(&client_ctx->client.conn, true);
	return -1;
}


static int mgmt_be_client_handle_msg(struct mgmt_be_client *client_ctx,
				     Mgmtd__BeMessage *be_msg)
{
	/*
	 * On error we may have closed the connection so don't do anything with
	 * the client_ctx on return.
	 *
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)be_msg->message_case) {
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REPLY:
		debug_be_client("Got SUBSCR_REPLY success %u",
				be_msg->subscr_reply->success);

		if (client_ctx->cbs.subscr_done)
			(*client_ctx->cbs.subscr_done)(client_ctx,
						       client_ctx->user_data,
						       be_msg->subscr_reply
							       ->success);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REQ:
		debug_be_client("Got TXN_REQ %s txn-id: %" PRIu64,
				be_msg->txn_req->create ? "Create" : "Delete",
				be_msg->txn_req->txn_id);
		mgmt_be_process_txn_req(client_ctx,
					    be_msg->txn_req->txn_id,
					    be_msg->txn_req->create);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REQ:
		debug_be_client("Got CFG_DATA_REQ txn-id: %" PRIu64
				" end-of-data %u",
				be_msg->cfg_data_req->txn_id,
				be_msg->cfg_data_req->end_of_data);
		mgmt_be_process_cfgdata_req(
			client_ctx, be_msg->cfg_data_req->txn_id,
			be_msg->cfg_data_req->data_req,
			be_msg->cfg_data_req->n_data_req,
			be_msg->cfg_data_req->end_of_data);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REQ:
		debug_be_client("Got CFG_APPLY_REQ txn-id: %" PRIu64,
				be_msg->cfg_data_req->txn_id);
		mgmt_be_process_cfg_apply(
			client_ctx, (uint64_t)be_msg->cfg_apply_req->txn_id);
		break;
	/*
	 * NOTE: The following messages are always sent from Backend
	 * clients to MGMTd only and/or need not be handled here.
	 */
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE__NOT_SET:
	default:
		/*
		 * A 'default' case is being added contrary to the
		 * FRR code guidelines to take care of build
		 * failures on certain build systems (courtesy of
		 * the proto-c package).
		 */
		break;
	}

	return 0;
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
	if (ret != NB_OK)
		goto done;

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
		ret = NB_ERR;
		goto done;
	}
	(void)be_client_send_native_msg(client, tree_msg,
					mgmt_msg_native_get_msg_len(tree_msg),
					false);
done:
	mgmt_msg_native_free_msg(tree_msg);
	if (ret)
		be_client_send_error(client, args->txn_id, args->req_id, false,
				     -EINVAL,
				     "BE client %s txn-id %" PRIu64
				     " error fetching oper state %d",
				     client->name, args->txn_id, ret);
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

/*
 * Process the notification.
 */
static void be_client_handle_notify(struct mgmt_be_client *client, void *msgbuf,
				    size_t msg_len)
{
	struct mgmt_msg_notify_data *notif_msg = msgbuf;
	struct nb_node *nb_node;
	struct lyd_node *dnode;
	const char *data;
	const char *notif;
	LY_ERR err;

	debug_be_client("Received notification for client %s", client->name);

	notif = mgmt_msg_native_xpath_data_decode(notif_msg, msg_len, data);
	if (!notif || !data) {
		log_err_be_client("Corrupt notify msg");
		return;
	}

	nb_node = nb_node_find(notif);
	if (!nb_node) {
		log_err_be_client("No schema found for notification: %s", notif);
		return;
	}

	if (!nb_node->cbs.notify) {
		debug_be_client("No notification callback for: %s", notif);
		return;
	}

	err = yang_parse_notification(notif, notif_msg->result_type, data,
				      &dnode);
	if (err) {
		log_err_be_client("Can't parse notification data for: %s",
				  notif);
		return;
	}

	nb_callback_notify(nb_node, notif, dnode);

	lyd_free_all(dnode);
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
	case MGMT_MSG_CODE_GET_TREE:
		be_client_handle_get_tree(client, txn_id, msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY:
		be_client_handle_notify(client, msg, msg_len);
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
	Mgmtd__BeMessage *be_msg;

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

	be_msg = mgmtd__be_message__unpack(NULL, len, data);
	if (!be_msg) {
		debug_be_client("Failed to decode %zu bytes from server", len);
		return;
	}
	debug_be_client("Decoded %zu bytes of message(msg: %u/%u) from server",
			len, be_msg->message_case, be_msg->message_case);
	(void)mgmt_be_client_handle_msg(client_ctx, be_msg);
	mgmtd__be_message__free_unpacked(be_msg, NULL);
}

int mgmt_be_send_subscr_req(struct mgmt_be_client *client_ctx,
			    int n_config_xpaths, char **config_xpaths,
			    int n_oper_xpaths, char **oper_xpaths)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeSubscribeReq subscr_req;

	mgmtd__be_subscribe_req__init(&subscr_req);
	subscr_req.client_name = client_ctx->name;
	subscr_req.n_config_xpaths = n_config_xpaths;
	subscr_req.config_xpaths = config_xpaths;
	subscr_req.n_oper_xpaths = n_oper_xpaths;
	subscr_req.oper_xpaths = oper_xpaths;

	/* See if we should register for notifications */
	subscr_req.n_notif_xpaths = client_ctx->cbs.nnotif_xpaths;
	subscr_req.notif_xpaths = (char **)client_ctx->cbs.notif_xpaths;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ;
	be_msg.subscr_req = &subscr_req;

	debug_be_client("Sending SUBSCR_REQ name: %s xpaths: config %zu oper: %zu notif: %zu",
			subscr_req.client_name, subscr_req.n_config_xpaths,
			subscr_req.n_oper_xpaths, subscr_req.n_notif_xpaths);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static int _notify_conenct_disconnect(struct msg_client *msg_client,
				      bool connected)
{
	struct mgmt_be_client *client =
		container_of(msg_client, struct mgmt_be_client, client);
	int ret;

	if (connected) {
		assert(msg_client->conn.fd != -1);
		ret = mgmt_be_send_subscr_req(client, 0, NULL, 0, NULL);
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

static int mgmt_debug_be_client_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&mgmt_dbg_be_client, DEBUG_MODE_CONF))
		vty_out(vty, "debug mgmt client backend\n");

	return 1;
}

void mgmt_debug_be_client_show_debug(struct vty *vty)
{
	if (debug_check_be_client())
		vty_out(vty, "debug mgmt client backend\n");
}

static struct debug_callbacks mgmt_dbg_be_client_cbs = {
	.debug_set_all = mgmt_debug_client_be_set
};

static struct cmd_node mgmt_dbg_node = {
	.name = "debug mgmt client backend",
	.node = MGMT_BE_DEBUG_NODE,
	.prompt = "",
	.config_write = mgmt_debug_be_client_config_write,
};

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
	debug_init(&mgmt_dbg_be_client_cbs);
	install_node(&mgmt_dbg_node);
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
