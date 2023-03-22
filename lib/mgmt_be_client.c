// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "libfrr.h"
#include "mgmtd/mgmt.h"
#include "mgmt_be_client.h"
#include "mgmt_msg.h"
#include "mgmt_pb.h"
#include "network.h"
#include "stream.h"
#include "sockopt.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_BE_CLIENT_DBG(fmt, ...)                                         \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_BE_CLIENT_ERR(fmt, ...)                                         \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_BE_CLIENT_DBG(fmt, ...)                                         \
	do {                                                                   \
		if (mgmt_debug_be_client)                                     \
			zlog_debug("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_BE_CLIENT_ERR(fmt, ...)                                         \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_BATCH,
		    "MGMTD backend transaction batch data");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BE_TXN, "MGMTD backend transaction data");

enum mgmt_be_txn_event {
	MGMTD_BE_TXN_PROC_SETCFG = 1,
	MGMTD_BE_TXN_PROC_GETCFG,
	MGMTD_BE_TXN_PROC_GETDATA
};

struct mgmt_be_set_cfg_req {
	struct nb_cfg_change cfg_changes[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
};

struct mgmt_be_get_data_req {
	char *xpaths[MGMTD_MAX_NUM_DATA_REQ_IN_BATCH];
	uint16_t num_xpaths;
};

struct mgmt_be_txn_req {
	enum mgmt_be_txn_event event;
	union {
		struct mgmt_be_set_cfg_req set_cfg;
		struct mgmt_be_get_data_req get_data;
	} req;
};

PREDECL_LIST(mgmt_be_batches);
struct mgmt_be_batch_ctx {
	/* Batch-Id as assigned by MGMTD */
	uint64_t batch_id;

	struct mgmt_be_txn_req txn_req;

	uint32_t flags;

	struct mgmt_be_batches_item list_linkage;
};
#define MGMTD_BE_BATCH_FLAGS_CFG_PREPARED (1U << 0)
#define MGMTD_BE_TXN_FLAGS_CFG_APPLIED (1U << 1)
DECLARE_LIST(mgmt_be_batches, struct mgmt_be_batch_ctx, list_linkage);

struct mgmt_be_client_ctx;

PREDECL_LIST(mgmt_be_txns);
struct mgmt_be_txn_ctx {
	/* Txn-Id as assigned by MGMTD */
	uint64_t txn_id;
	uint32_t flags;

	struct mgmt_be_client_txn_ctx client_data;
	struct mgmt_be_client_ctx *client_ctx;

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

struct mgmt_be_client_ctx {
	int conn_fd;
	struct thread_master *tm;
	struct thread *conn_retry_tmr;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	struct thread *conn_writes_on;
	struct thread *msg_proc_ev;
	uint32_t flags;

	struct mgmt_msg_state mstate;

	struct nb_config *candidate_config;
	struct nb_config *running_config;

	unsigned long num_batch_find;
	unsigned long avg_batch_find_tm;
	unsigned long num_edit_nb_cfg;
	unsigned long avg_edit_nb_cfg_tm;
	unsigned long num_prep_nb_cfg;
	unsigned long avg_prep_nb_cfg_tm;
	unsigned long num_apply_nb_cfg;
	unsigned long avg_apply_nb_cfg_tm;

	struct mgmt_be_txns_head txn_head;
	struct mgmt_be_client_params client_params;
};

#define MGMTD_BE_CLIENT_FLAGS_WRITES_OFF (1U << 0)

#define FOREACH_BE_TXN_IN_LIST(client_ctx, txn)                                \
	frr_each_safe (mgmt_be_txns, &(client_ctx)->txn_head, (txn))

static bool mgmt_debug_be_client;

static struct mgmt_be_client_ctx mgmt_be_client_ctx = {
	.conn_fd = -1,
};

const char *mgmt_be_client_names[MGMTD_BE_CLIENT_ID_MAX + 1] = {
#ifdef HAVE_STATICD
	[MGMTD_BE_CLIENT_ID_STATICD] = "staticd",
#endif
	[MGMTD_BE_CLIENT_ID_MAX] = "Unknown/Invalid",
};

/* Forward declarations */
static void
mgmt_be_client_register_event(struct mgmt_be_client_ctx *client_ctx,
				 enum mgmt_be_event event);
static void
mgmt_be_client_schedule_conn_retry(struct mgmt_be_client_ctx *client_ctx,
				      unsigned long intvl_secs);
static int mgmt_be_client_send_msg(struct mgmt_be_client_ctx *client_ctx,
				      Mgmtd__BeMessage *be_msg);

static void
mgmt_be_server_disconnect(struct mgmt_be_client_ctx *client_ctx,
			     bool reconnect)
{
	/* Notify client through registered callback (if any) */
	if (client_ctx->client_params.client_connect_notify)
		(void)(*client_ctx->client_params.client_connect_notify)(
			(uintptr_t)client_ctx,
			client_ctx->client_params.user_data, false);

	if (client_ctx->conn_fd != -1) {
		close(client_ctx->conn_fd);
		client_ctx->conn_fd = -1;
	}

	if (reconnect)
		mgmt_be_client_schedule_conn_retry(
			client_ctx,
			client_ctx->client_params.conn_retry_intvl_sec);
}

static struct mgmt_be_batch_ctx *
mgmt_be_find_batch_by_id(struct mgmt_be_txn_ctx *txn,
			    uint64_t batch_id)
{
	struct mgmt_be_batch_ctx *batch = NULL;

	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		if (batch->batch_id == batch_id)
			return batch;
	}

	return NULL;
}

static struct mgmt_be_batch_ctx *
mgmt_be_batch_create(struct mgmt_be_txn_ctx *txn, uint64_t batch_id)
{
	struct mgmt_be_batch_ctx *batch = NULL;

	batch = mgmt_be_find_batch_by_id(txn, batch_id);
	if (!batch) {
		batch = XCALLOC(MTYPE_MGMTD_BE_BATCH,
				sizeof(struct mgmt_be_batch_ctx));
		assert(batch);

		batch->batch_id = batch_id;
		mgmt_be_batches_add_tail(&txn->cfg_batches, batch);

		MGMTD_BE_CLIENT_DBG("Added new batch 0x%llx to transaction",
				    (unsigned long long)batch_id);
	}

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
mgmt_be_find_txn_by_id(struct mgmt_be_client_ctx *client_ctx,
			   uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	FOREACH_BE_TXN_IN_LIST (client_ctx, txn) {
		if (txn->txn_id == txn_id)
			return txn;
	}

	return NULL;
}

static struct mgmt_be_txn_ctx *
mgmt_be_txn_create(struct mgmt_be_client_ctx *client_ctx,
		       uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id);
	if (!txn) {
		txn = XCALLOC(MTYPE_MGMTD_BE_TXN,
			       sizeof(struct mgmt_be_txn_ctx));
		assert(txn);

		txn->txn_id = txn_id;
		txn->client_ctx = client_ctx;
		mgmt_be_batches_init(&txn->cfg_batches);
		mgmt_be_batches_init(&txn->apply_cfgs);
		mgmt_be_txns_add_tail(&client_ctx->txn_head, txn);

		MGMTD_BE_CLIENT_DBG("Added new transaction 0x%llx",
				    (unsigned long long)txn_id);
	}

	return txn;
}

static void mgmt_be_txn_delete(struct mgmt_be_client_ctx *client_ctx,
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
	if (client_ctx->client_params.txn_notify)
		(void)(*client_ctx->client_params
				.txn_notify)(
			(uintptr_t)client_ctx,
			client_ctx->client_params.user_data,
			&(*txn)->client_data, true);

	mgmt_be_cleanup_all_batches(*txn);
	if ((*txn)->nb_txn)
		nb_candidate_commit_abort((*txn)->nb_txn, err_msg,
					sizeof(err_msg));
	XFREE(MTYPE_MGMTD_BE_TXN, *txn);

	*txn = NULL;
}

static void
mgmt_be_cleanup_all_txns(struct mgmt_be_client_ctx *client_ctx)
{
	struct mgmt_be_txn_ctx *txn = NULL;

	FOREACH_BE_TXN_IN_LIST (client_ctx, txn) {
		mgmt_be_txn_delete(client_ctx, &txn);
	}
}

static int mgmt_be_send_txn_reply(struct mgmt_be_client_ctx *client_ctx,
				      uint64_t txn_id, bool create,
				      bool success)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeTxnReply txn_reply;

	mgmtd__be_txn_reply__init(&txn_reply);
	txn_reply.create = create;
	txn_reply.txn_id = txn_id;
	txn_reply.success = success;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY;
	be_msg.txn_reply = &txn_reply;

	MGMTD_BE_CLIENT_DBG(
		"Sending TXN_REPLY message to MGMTD for txn 0x%llx",
		(unsigned long long)txn_id);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static int mgmt_be_process_txn_req(struct mgmt_be_client_ctx *client_ctx,
				       uint64_t txn_id, bool create)
{
	struct mgmt_be_txn_ctx *txn;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id);
	if (create) {
		if (txn) {
			/*
			 * Transaction with same txn-id already exists.
			 * Should not happen under any circumstances.
			 */
			MGMTD_BE_CLIENT_ERR(
				"Transaction 0x%llx already exists!!!",
				(unsigned long long)txn_id);
			mgmt_be_send_txn_reply(client_ctx, txn_id, create,
						   false);
		}

		MGMTD_BE_CLIENT_DBG("Created new transaction 0x%llx",
				     (unsigned long long)txn_id);
		txn = mgmt_be_txn_create(client_ctx, txn_id);

		if (client_ctx->client_params.txn_notify)
			(void)(*client_ctx->client_params
					.txn_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				&txn->client_data, false);
	} else {
		if (!txn) {
			/*
			 * Transaction with same txn-id does not exists.
			 * Return sucess anyways.
			 */
			MGMTD_BE_CLIENT_DBG(
				"Transaction to delete 0x%llx does NOT exists!!!",
				(unsigned long long)txn_id);
		} else {
			MGMTD_BE_CLIENT_DBG("Delete transaction 0x%llx",
					     (unsigned long long)txn_id);
			mgmt_be_txn_delete(client_ctx, &txn);
		}
	}

	mgmt_be_send_txn_reply(client_ctx, txn_id, create, true);

	return 0;
}

static int
mgmt_be_send_cfgdata_create_reply(struct mgmt_be_client_ctx *client_ctx,
				     uint64_t txn_id, uint64_t batch_id,
				     bool success, const char *error_if_any)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataCreateReply cfgdata_reply;

	mgmtd__be_cfg_data_create_reply__init(&cfgdata_reply);
	cfgdata_reply.txn_id = (uint64_t)txn_id;
	cfgdata_reply.batch_id = (uint64_t)batch_id;
	cfgdata_reply.success = success;
	if (error_if_any)
		cfgdata_reply.error_if_any = (char *)error_if_any;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY;
	be_msg.cfg_data_reply = &cfgdata_reply;

	MGMTD_BE_CLIENT_DBG(
		"Sending CFGDATA_CREATE_REPLY message to MGMTD for txn 0x%llx batch 0x%llx",
		(unsigned long long)txn_id, (unsigned long long)batch_id);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static void mgmt_be_txn_cfg_abort(struct mgmt_be_txn_ctx *txn)
{
	char errmsg[BUFSIZ] = {0};

	assert(txn && txn->client_ctx);
	if (txn->nb_txn) {
		MGMTD_BE_CLIENT_ERR(
			"Aborting configurations after prep for Txn 0x%llx",
			(unsigned long long)txn->txn_id);
		nb_candidate_commit_abort(txn->nb_txn, errmsg, sizeof(errmsg));
		txn->nb_txn = 0;
	}

	/*
	 * revert candidate back to running
	 *
	 * This is one txn ctx but the candidate_config is per client ctx, how
	 * does that work?
	 */
	MGMTD_BE_CLIENT_DBG(
		"Reset candidate configurations after abort of Txn 0x%llx",
		(unsigned long long)txn->txn_id);
	nb_config_replace(txn->client_ctx->candidate_config,
			  txn->client_ctx->running_config, true);
}

static int mgmt_be_txn_cfg_prepare(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_client_ctx *client_ctx;
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
	bool debug_be = mgmt_debug_be_client;
	int err;

	assert(txn && txn->client_ctx);
	client_ctx = txn->client_ctx;

	num_processed = 0;
	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		txn_req = &batch->txn_req;
		error = false;
		nb_ctx.client = NB_CLIENT_CLI;
		nb_ctx.user = (void *)client_ctx->client_params.user_data;

		if (!txn->nb_txn) {
			/*
			 * This happens when the current backend client is only
			 * interested in consuming the config items but is not
			 * interested in validating it.
			 */
			error = false;
			if (debug_be)
				gettimeofday(&edit_nb_cfg_start, NULL);
			nb_candidate_edit_config_changes(
				client_ctx->candidate_config,
				txn_req->req.set_cfg.cfg_changes,
				(size_t)txn_req->req.set_cfg.num_cfg_changes,
				NULL, NULL, 0, err_buf, sizeof(err_buf),
				&error);
			if (error) {
				err_buf[sizeof(err_buf) - 1] = 0;
				MGMTD_BE_CLIENT_ERR(
					"Failed to update configs for Txn %llx Batch %llx to Candidate! Err: '%s'",
					(unsigned long long)txn->txn_id,
					(unsigned long long)batch->batch_id,
					err_buf);
				return -1;
			}
			if (debug_be) {
				gettimeofday(&edit_nb_cfg_end, NULL);
				edit_nb_cfg_tm = timeval_elapsed(
					edit_nb_cfg_end, edit_nb_cfg_start);
				client_ctx->avg_edit_nb_cfg_tm =
					((client_ctx->avg_edit_nb_cfg_tm
					  * client_ctx->num_edit_nb_cfg)
					 + edit_nb_cfg_tm)
					/ (client_ctx->num_edit_nb_cfg + 1);
			}
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
	nb_ctx.user = (void *)client_ctx->client_params.user_data;
	if (debug_be)
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
			MGMTD_BE_CLIENT_ERR(
				"Failed to validate configs for Txn %llx %u Batches! Err: '%s'",
				(unsigned long long)txn->txn_id,
				(uint32_t)num_processed, err_buf);
		else
			MGMTD_BE_CLIENT_ERR(
				"Failed to prepare configs for Txn %llx, %u Batches! Err: '%s'",
				(unsigned long long)txn->txn_id,
				(uint32_t)num_processed, err_buf);
		error = true;
		SET_FLAG(txn->flags, MGMTD_BE_TXN_FLAGS_CFGPREP_FAILED);
	} else
		MGMTD_BE_CLIENT_DBG(
			"Prepared configs for Txn %llx, %u Batches! successfully!",
			(unsigned long long)txn->txn_id,
			(uint32_t)num_processed);
	if (debug_be) {
		gettimeofday(&prep_nb_cfg_end, NULL);
		prep_nb_cfg_tm =
			timeval_elapsed(prep_nb_cfg_end, prep_nb_cfg_start);
		client_ctx->avg_prep_nb_cfg_tm =
			((client_ctx->avg_prep_nb_cfg_tm
			  * client_ctx->num_prep_nb_cfg)
			 + prep_nb_cfg_tm)
			/ (client_ctx->num_prep_nb_cfg + 1);
	}
	client_ctx->num_prep_nb_cfg++;

	FOREACH_BE_TXN_BATCH_IN_LIST (txn, batch) {
		mgmt_be_send_cfgdata_create_reply(
			client_ctx, txn->txn_id, batch->batch_id,
			error ? false : true, error ? err_buf : NULL);
		if (!error) {
			SET_FLAG(batch->flags,
				 MGMTD_BE_BATCH_FLAGS_CFG_PREPARED);
			mgmt_be_batches_del(&txn->cfg_batches, batch);
			mgmt_be_batches_add_tail(&txn->apply_cfgs, batch);
		}
	}

	if (debug_be)
		MGMTD_BE_CLIENT_DBG(
			"Avg-nb-edit-duration %lu uSec, nb-prep-duration %lu (avg: %lu) uSec, batch size %u",
			client_ctx->avg_edit_nb_cfg_tm, prep_nb_cfg_tm,
			client_ctx->avg_prep_nb_cfg_tm, (uint32_t)num_processed);

	if (error)
		mgmt_be_txn_cfg_abort(txn);

	return 0;
}

/*
 * Process all CFG_DATA_REQs received so far and prepare them all in one go.
 */
static int
mgmt_be_update_setcfg_in_batch(struct mgmt_be_client_ctx *client_ctx,
				  struct mgmt_be_txn_ctx *txn,
				  uint64_t batch_id,
				  Mgmtd__YangCfgDataReq * cfg_req[],
				  int num_req)
{
	struct mgmt_be_batch_ctx *batch = NULL;
	struct mgmt_be_txn_req *txn_req = NULL;
	int index;
	struct nb_cfg_change *cfg_chg;

	batch = mgmt_be_batch_create(txn, batch_id);
	if (!batch) {
		MGMTD_BE_CLIENT_ERR("Batch create failed!");
		return -1;
	}

	txn_req = &batch->txn_req;
	txn_req->event = MGMTD_BE_TXN_PROC_SETCFG;
	MGMTD_BE_CLIENT_DBG(
		"Created Set-Config request for batch 0x%llx, txn id 0x%llx, cfg-items:%d",
		(unsigned long long)batch_id, (unsigned long long)txn->txn_id,
		num_req);

	txn_req->req.set_cfg.num_cfg_changes = num_req;
	for (index = 0; index < num_req; index++) {
		cfg_chg = &txn_req->req.set_cfg.cfg_changes[index];

		if (cfg_req[index]->req_type
		    == MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA)
			cfg_chg->operation = NB_OP_DESTROY;
		else
			cfg_chg->operation = NB_OP_CREATE;

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

static int
mgmt_be_process_cfgdata_req(struct mgmt_be_client_ctx *client_ctx,
			       uint64_t txn_id, uint64_t batch_id,
			       Mgmtd__YangCfgDataReq * cfg_req[], int num_req,
			       bool end_of_data)
{
	struct mgmt_be_txn_ctx *txn;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id);
	if (!txn) {
		MGMTD_BE_CLIENT_ERR(
			"Invalid txn-id 0x%llx provided from MGMTD server",
			(unsigned long long)txn_id);
		mgmt_be_send_cfgdata_create_reply(
			client_ctx, txn_id, batch_id, false,
			"Transaction context not created yet");
	} else {
		mgmt_be_update_setcfg_in_batch(client_ctx, txn, batch_id,
						  cfg_req, num_req);
	}

	if (txn && end_of_data) {
		MGMTD_BE_CLIENT_DBG("Triggering CFG_PREPARE_REQ processing");
		mgmt_be_txn_cfg_prepare(txn);
	}

	return 0;
}

static int mgmt_be_send_apply_reply(struct mgmt_be_client_ctx *client_ctx,
				       uint64_t txn_id, uint64_t batch_ids[],
				       size_t num_batch_ids, bool success,
				       const char *error_if_any)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataApplyReply apply_reply;

	mgmtd__be_cfg_data_apply_reply__init(&apply_reply);
	apply_reply.success = success;
	apply_reply.txn_id = txn_id;
	apply_reply.batch_ids = (uint64_t *)batch_ids;
	apply_reply.n_batch_ids = num_batch_ids;

	if (error_if_any)
		apply_reply.error_if_any = (char *)error_if_any;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY;
	be_msg.cfg_apply_reply = &apply_reply;

	MGMTD_BE_CLIENT_DBG(
		"Sending CFG_APPLY_REPLY message to MGMTD for txn 0x%llx, %d batches [0x%llx - 0x%llx]",
		(unsigned long long)txn_id, (int)num_batch_ids,
		success && num_batch_ids ?
			(unsigned long long)batch_ids[0] : 0,
		success && num_batch_ids ?
		(unsigned long long)batch_ids[num_batch_ids - 1] : 0);

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static int mgmt_be_txn_proc_cfgapply(struct mgmt_be_txn_ctx *txn)
{
	struct mgmt_be_client_ctx *client_ctx;
	struct timeval apply_nb_cfg_start;
	struct timeval apply_nb_cfg_end;
	unsigned long apply_nb_cfg_tm;
	struct mgmt_be_batch_ctx *batch;
	char err_buf[BUFSIZ];
	size_t num_processed;
	static uint64_t batch_ids[MGMTD_BE_MAX_BATCH_IDS_IN_REQ];
	bool debug_be = mgmt_debug_be_client;

	assert(txn && txn->client_ctx);
	client_ctx = txn->client_ctx;

	assert(txn->nb_txn);
	num_processed = 0;

	/*
	 * Now apply all the batches we have applied in one go.
	 */
	if (debug_be)
		gettimeofday(&apply_nb_cfg_start, NULL);
	(void)nb_candidate_commit_apply(txn->nb_txn, true, &txn->nb_txn_id,
					err_buf, sizeof(err_buf) - 1);
	if (debug_be) {
		gettimeofday(&apply_nb_cfg_end, NULL);
		apply_nb_cfg_tm =
			timeval_elapsed(apply_nb_cfg_end, apply_nb_cfg_start);
		client_ctx->avg_apply_nb_cfg_tm =
			((client_ctx->avg_apply_nb_cfg_tm
			  * client_ctx->num_apply_nb_cfg)
			 + apply_nb_cfg_tm)
			/ (client_ctx->num_apply_nb_cfg + 1);
	}
	client_ctx->num_apply_nb_cfg++;
	txn->nb_txn = NULL;

	/*
	 * Send back CFG_APPLY_REPLY for all batches applied.
	 */
	FOREACH_BE_APPLY_BATCH_IN_LIST (txn, batch) {
		/*
		 * No need to delete the batch yet. Will be deleted during
		 * transaction cleanup on receiving TXN_DELETE_REQ.
		 */
		SET_FLAG(batch->flags, MGMTD_BE_TXN_FLAGS_CFG_APPLIED);
		mgmt_be_batches_del(&txn->apply_cfgs, batch);
		mgmt_be_batches_add_tail(&txn->cfg_batches, batch);

		batch_ids[num_processed] = batch->batch_id;
		num_processed++;
		if (num_processed == MGMTD_BE_MAX_BATCH_IDS_IN_REQ) {
			mgmt_be_send_apply_reply(client_ctx, txn->txn_id,
						    batch_ids, num_processed,
						    true, NULL);
			num_processed = 0;
		}
	}

	mgmt_be_send_apply_reply(client_ctx, txn->txn_id, batch_ids,
				    num_processed, true, NULL);

	if (debug_be)
		MGMTD_BE_CLIENT_DBG("Nb-apply-duration %lu (avg: %lu) uSec",
				     apply_nb_cfg_tm,
				     client_ctx->avg_apply_nb_cfg_tm);

	return 0;
}

static int
mgmt_be_process_cfg_apply(struct mgmt_be_client_ctx *client_ctx,
			     uint64_t txn_id)
{
	struct mgmt_be_txn_ctx *txn;

	txn = mgmt_be_find_txn_by_id(client_ctx, txn_id);
	if (!txn) {
		mgmt_be_send_apply_reply(client_ctx, txn_id, NULL, 0, false,
					    "Transaction not created yet!");
		return -1;
	}

	MGMTD_BE_CLIENT_DBG("Trigger CFG_APPLY_REQ processing");
	mgmt_be_txn_proc_cfgapply(txn);

	return 0;
}

static int
mgmt_be_client_handle_msg(struct mgmt_be_client_ctx *client_ctx,
			     Mgmtd__BeMessage *be_msg)
{
	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)be_msg->message_case) {
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REPLY:
		MGMTD_BE_CLIENT_DBG("Subscribe Reply Msg from mgmt, status %u",
				     be_msg->subscr_reply->success);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REQ:
		mgmt_be_process_txn_req(client_ctx,
					    be_msg->txn_req->txn_id,
					    be_msg->txn_req->create);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REQ:
		mgmt_be_process_cfgdata_req(
			client_ctx, be_msg->cfg_data_req->txn_id,
			be_msg->cfg_data_req->batch_id,
			be_msg->cfg_data_req->data_req,
			be_msg->cfg_data_req->n_data_req,
			be_msg->cfg_data_req->end_of_data);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REQ:
		mgmt_be_process_cfg_apply(
			client_ctx, (uint64_t)be_msg->cfg_apply_req->txn_id);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_GET_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_CMD_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_SHOW_CMD_REQ:
		/*
		 * TODO: Add handling code in future.
		 */
		break;
	/*
	 * NOTE: The following messages are always sent from Backend
	 * clients to MGMTd only and/or need not be handled here.
	 */
	case MGMTD__BE_MESSAGE__MESSAGE_GET_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_CMD_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_SHOW_CMD_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_NOTIFY_DATA:
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

static void mgmt_be_client_process_msg(void *user_ctx, uint8_t *data,
				       size_t len)
{
	struct mgmt_be_client_ctx *client_ctx = user_ctx;
	Mgmtd__BeMessage *be_msg;

	be_msg = mgmtd__be_message__unpack(NULL, len, data);
	if (!be_msg) {
		MGMTD_BE_CLIENT_DBG("Failed to decode %zu bytes from server",
				    len);
		return;
	}
	MGMTD_BE_CLIENT_DBG(
		"Decoded %zu bytes of message(msg: %u/%u) from server", len,
		be_msg->message_case, be_msg->message_case);
	(void)mgmt_be_client_handle_msg(client_ctx, be_msg);
	mgmtd__be_message__free_unpacked(be_msg, NULL);
}

static void mgmt_be_client_proc_msgbufs(struct thread *thread)
{
	struct mgmt_be_client_ctx *client_ctx = THREAD_ARG(thread);

	if (mgmt_msg_procbufs(&client_ctx->mstate, mgmt_be_client_process_msg,
			      client_ctx, mgmt_debug_be_client))
		mgmt_be_client_register_event(client_ctx, MGMTD_BE_PROC_MSG);
}

static void mgmt_be_client_read(struct thread *thread)
{
	struct mgmt_be_client_ctx *client_ctx = THREAD_ARG(thread);
	enum mgmt_msg_rsched rv;

	rv = mgmt_msg_read(&client_ctx->mstate, client_ctx->conn_fd,
			   mgmt_debug_be_client);
	if (rv == MSR_DISCONNECT) {
		mgmt_be_server_disconnect(client_ctx, true);
		return;
	}
	if (rv == MSR_SCHED_BOTH)
		mgmt_be_client_register_event(client_ctx, MGMTD_BE_PROC_MSG);
	mgmt_be_client_register_event(client_ctx, MGMTD_BE_CONN_READ);
}

static inline void
mgmt_be_client_sched_msg_write(struct mgmt_be_client_ctx *client_ctx)
{
	if (!CHECK_FLAG(client_ctx->flags, MGMTD_BE_CLIENT_FLAGS_WRITES_OFF))
		mgmt_be_client_register_event(client_ctx,
						 MGMTD_BE_CONN_WRITE);
}

static inline void
mgmt_be_client_writes_on(struct mgmt_be_client_ctx *client_ctx)
{
	MGMTD_BE_CLIENT_DBG("Resume writing msgs");
	UNSET_FLAG(client_ctx->flags, MGMTD_BE_CLIENT_FLAGS_WRITES_OFF);
	mgmt_be_client_sched_msg_write(client_ctx);
}

static inline void
mgmt_be_client_writes_off(struct mgmt_be_client_ctx *client_ctx)
{
	SET_FLAG(client_ctx->flags, MGMTD_BE_CLIENT_FLAGS_WRITES_OFF);
	MGMTD_BE_CLIENT_DBG("Paused writing msgs");
}

static int mgmt_be_client_send_msg(struct mgmt_be_client_ctx *client_ctx,
				   Mgmtd__BeMessage *be_msg)
{
	if (client_ctx->conn_fd == -1) {
		MGMTD_BE_CLIENT_DBG("can't send message on closed connection");
		return -1;
	}

	int rv = mgmt_msg_send_msg(
		&client_ctx->mstate, be_msg,
		mgmtd__be_message__get_packed_size(be_msg),
		(size_t(*)(void *, void *))mgmtd__be_message__pack,
		mgmt_debug_be_client);
	mgmt_be_client_sched_msg_write(client_ctx);
	return rv;
}

static void mgmt_be_client_write(struct thread *thread)
{
	struct mgmt_be_client_ctx *client_ctx = THREAD_ARG(thread);
	enum mgmt_msg_wsched rv;

	rv = mgmt_msg_write(&client_ctx->mstate, client_ctx->conn_fd,
			    mgmt_debug_be_client);
	if (rv == MSW_SCHED_STREAM)
		mgmt_be_client_register_event(client_ctx, MGMTD_BE_CONN_WRITE);
	else if (rv == MSW_DISCONNECT)
		mgmt_be_server_disconnect(client_ctx, true);
	else if (rv == MSW_SCHED_WRITES_OFF) {
		mgmt_be_client_writes_off(client_ctx);
		mgmt_be_client_register_event(client_ctx,
					      MGMTD_BE_CONN_WRITES_ON);
	} else
		assert(rv == MSW_SCHED_NONE);
}

static void mgmt_be_client_resume_writes(struct thread *thread)
{
	struct mgmt_be_client_ctx *client_ctx;

	client_ctx = (struct mgmt_be_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx && client_ctx->conn_fd != -1);

	mgmt_be_client_writes_on(client_ctx);
}

static int mgmt_be_send_subscr_req(struct mgmt_be_client_ctx *client_ctx,
				   bool subscr_xpaths, uint16_t num_reg_xpaths,
				   char **reg_xpaths)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeSubscribeReq subscr_req;

	mgmtd__be_subscribe_req__init(&subscr_req);
	subscr_req.client_name = client_ctx->client_params.name;
	subscr_req.n_xpath_reg = num_reg_xpaths;
	if (num_reg_xpaths)
		subscr_req.xpath_reg = reg_xpaths;
	else
		subscr_req.xpath_reg = NULL;
	subscr_req.subscribe_xpaths = subscr_xpaths;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ;
	be_msg.subscr_req = &subscr_req;

	return mgmt_be_client_send_msg(client_ctx, &be_msg);
}

static void mgmt_be_server_connect(struct mgmt_be_client_ctx *client_ctx)
{
	const char *dbgtag = mgmt_debug_be_client ? "BE-client" : NULL;

	assert(client_ctx->conn_fd == -1);
	client_ctx->conn_fd = mgmt_msg_connect(
		MGMTD_BE_SERVER_PATH, MGMTD_SOCKET_BE_SEND_BUF_SIZE,
		MGMTD_SOCKET_BE_RECV_BUF_SIZE, dbgtag);

	/* Send SUBSCRIBE_REQ message */
	if (client_ctx->conn_fd == -1 ||
	    mgmt_be_send_subscr_req(client_ctx, false, 0, NULL) != 0) {
		mgmt_be_server_disconnect(client_ctx, true);
		return;
	}

	/* Start reading from the socket */
	mgmt_be_client_register_event(client_ctx, MGMTD_BE_CONN_READ);

	/* Notify client through registered callback (if any) */
	if (client_ctx->client_params.client_connect_notify)
		(void)(*client_ctx->client_params.client_connect_notify)(
			(uintptr_t)client_ctx,
			client_ctx->client_params.user_data, true);
}

static void mgmt_be_client_conn_timeout(struct thread *thread)
{
	mgmt_be_server_connect(THREAD_ARG(thread));
}

static void
mgmt_be_client_register_event(struct mgmt_be_client_ctx *client_ctx,
				 enum mgmt_be_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_BE_CONN_READ:
		thread_add_read(client_ctx->tm, mgmt_be_client_read,
				client_ctx, client_ctx->conn_fd,
				&client_ctx->conn_read_ev);
		assert(client_ctx->conn_read_ev);
		break;
	case MGMTD_BE_CONN_WRITE:
		thread_add_write(client_ctx->tm, mgmt_be_client_write,
				 client_ctx, client_ctx->conn_fd,
				 &client_ctx->conn_write_ev);
		assert(client_ctx->conn_write_ev);
		break;
	case MGMTD_BE_PROC_MSG:
		tv.tv_usec = MGMTD_BE_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(client_ctx->tm, mgmt_be_client_proc_msgbufs,
				    client_ctx, &tv, &client_ctx->msg_proc_ev);
		assert(client_ctx->msg_proc_ev);
		break;
	case MGMTD_BE_CONN_WRITES_ON:
		thread_add_timer_msec(client_ctx->tm,
				      mgmt_be_client_resume_writes, client_ctx,
				      MGMTD_BE_MSG_WRITE_DELAY_MSEC,
				      &client_ctx->conn_writes_on);
		assert(client_ctx->conn_writes_on);
		break;
	case MGMTD_BE_SERVER:
	case MGMTD_BE_CONN_INIT:
	case MGMTD_BE_SCHED_CFG_PREPARE:
	case MGMTD_BE_RESCHED_CFG_PREPARE:
	case MGMTD_BE_SCHED_CFG_APPLY:
	case MGMTD_BE_RESCHED_CFG_APPLY:
		assert(!"mgmt_be_client_post_event() called incorrectly");
		break;
	}
}

static void
mgmt_be_client_schedule_conn_retry(struct mgmt_be_client_ctx *client_ctx,
				      unsigned long intvl_secs)
{
	MGMTD_BE_CLIENT_DBG(
		"Scheduling MGMTD Backend server connection retry after %lu seconds",
		intvl_secs);
	thread_add_timer(client_ctx->tm, mgmt_be_client_conn_timeout,
			 (void *)client_ctx, intvl_secs,
			 &client_ctx->conn_retry_tmr);
}

extern struct nb_config *running_config;

/*
 * Initialize library and try connecting with MGMTD.
 */
uintptr_t mgmt_be_client_lib_init(struct mgmt_be_client_params *params,
				    struct thread_master *master_thread)
{
	assert(master_thread && params && strlen(params->name)
	       && !mgmt_be_client_ctx.tm);

	mgmt_be_client_ctx.tm = master_thread;

	if (!running_config)
		assert(!"MGMTD Be Client lib_init() after frr_init() only!");
	mgmt_be_client_ctx.running_config = running_config;
	mgmt_be_client_ctx.candidate_config = nb_config_new(NULL);

	memcpy(&mgmt_be_client_ctx.client_params, params,
	       sizeof(mgmt_be_client_ctx.client_params));
	if (!mgmt_be_client_ctx.client_params.conn_retry_intvl_sec)
		mgmt_be_client_ctx.client_params.conn_retry_intvl_sec =
			MGMTD_BE_DEFAULT_CONN_RETRY_INTVL_SEC;

	mgmt_be_txns_init(&mgmt_be_client_ctx.txn_head);
	mgmt_msg_init(&mgmt_be_client_ctx.mstate, MGMTD_BE_MAX_NUM_MSG_PROC,
		      MGMTD_BE_MAX_NUM_MSG_WRITE, MGMTD_BE_MSG_MAX_LEN,
		      "BE-client");

	/* Start trying to connect to MGMTD backend server immediately */
	mgmt_be_client_schedule_conn_retry(&mgmt_be_client_ctx, 1);

	MGMTD_BE_CLIENT_DBG("Initialized client '%s'", params->name);

	return (uintptr_t)&mgmt_be_client_ctx;
}

/*
 * Subscribe with MGMTD for one or more YANG subtree(s).
 */
enum mgmt_result mgmt_be_subscribe_yang_data(uintptr_t lib_hndl,
						char *reg_yang_xpaths[],
						int num_reg_xpaths)
{
	struct mgmt_be_client_ctx *client_ctx;

	client_ctx = (struct mgmt_be_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_be_send_subscr_req(client_ctx, true, num_reg_xpaths,
				       reg_yang_xpaths)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Unsubscribe with MGMTD for one or more YANG subtree(s).
 */
enum mgmt_result mgmt_be_unsubscribe_yang_data(uintptr_t lib_hndl,
						  char *reg_yang_xpaths[],
						  int num_reg_xpaths)
{
	struct mgmt_be_client_ctx *client_ctx;

	client_ctx = (struct mgmt_be_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;


	if (mgmt_be_send_subscr_req(client_ctx, false, num_reg_xpaths,
				       reg_yang_xpaths)
	    < 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send one or more YANG notifications to MGMTD daemon.
 */
enum mgmt_result mgmt_be_send_yang_notify(uintptr_t lib_hndl,
					     Mgmtd__YangData * data_elems[],
					     int num_elems)
{
	struct mgmt_be_client_ctx *client_ctx;

	client_ctx = (struct mgmt_be_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	return MGMTD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void mgmt_be_client_lib_destroy(uintptr_t lib_hndl)
{
	struct mgmt_be_client_ctx *client_ctx;

	client_ctx = (struct mgmt_be_client_ctx *)lib_hndl;
	assert(client_ctx);

	MGMTD_BE_CLIENT_DBG("Destroying MGMTD Backend Client '%s'",
			    client_ctx->client_params.name);

	mgmt_be_server_disconnect(client_ctx, false);

	mgmt_msg_destroy(&client_ctx->mstate);

	THREAD_OFF(client_ctx->conn_retry_tmr);
	THREAD_OFF(client_ctx->conn_read_ev);
	THREAD_OFF(client_ctx->conn_write_ev);
	THREAD_OFF(client_ctx->conn_writes_on);
	THREAD_OFF(client_ctx->msg_proc_ev);
	mgmt_be_cleanup_all_txns(client_ctx);
	mgmt_be_txns_fini(&client_ctx->txn_head);
}
