/*
 * MGMTD Backend Client Library api interfaces
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

#include "northbound.h"
#include "libfrr.h"
#include "lib/typesafe.h"
#include "mgmtd/mgmt.h"
#include "lib/mgmt_bcknd_client.h"
#include "lib/mgmt_pb.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "lib/memory.h"
#include "sockopt.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_BCKND_CLNT_DBG(fmt, ...)                                         \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_BCKND_CLNT_ERR(fmt, ...)                                         \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_BCKND_CLNT_DBG(fmt, ...)                                         \
	do {                                                                   \
		if (mgmt_debug_bcknd_clnt)                                     \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_BCKND_CLNT_ERR(fmt, ...)                                         \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

DEFINE_MTYPE_STATIC(LIB, MGMTD_BCKND_BATCH,
		    "MGMTD backend transaction batch data");
DEFINE_MTYPE_STATIC(LIB, MGMTD_BCKND_TRXN, "MGMTD backend transaction data");

enum mgmt_bcknd_trxn_event {
	MGMTD_BCKND_TRXN_PROC_SETCFG = 1,
	MGMTD_BCKND_TRXN_PROC_GETCFG,
	MGMTD_BCKND_TRXN_PROC_GETDATA
};

struct mgmt_bcknd_set_cfg_req {
	struct nb_cfg_change cfg_changes[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
};

struct mgmt_bcknd_get_data_req {
	char *xpaths[MGMTD_MAX_NUM_DATA_REQ_IN_BATCH];
	uint16_t num_xpaths;
};

struct mgmt_bcknd_trxn_req {
	enum mgmt_bcknd_trxn_event event;
	union {
		struct mgmt_bcknd_set_cfg_req set_cfg;
		struct mgmt_bcknd_get_data_req get_data;
	} req;
};

PREDECL_LIST(mgmt_bcknd_batch_list);
struct mgmt_bcknd_batch_ctxt {
	/* Batch-Id as assigned by MGMTD */
	uint64_t batch_id;

	struct mgmt_bcknd_trxn_req trxn_req;

	uint32_t flags;

	struct mgmt_bcknd_batch_list_item list_linkage;
};
#define MGMTD_BCKND_BATCH_FLAGS_CFG_PREPARED (1U << 0)
#define MGMTD_BCKND_TRXN_FLAGS_CFG_APPLIED (1U << 1)
DECLARE_LIST(mgmt_bcknd_batch_list, struct mgmt_bcknd_batch_ctxt, list_linkage);

struct mgmt_bcknd_client_ctxt;

PREDECL_LIST(mgmt_bcknd_trxn_list);
struct mgmt_bcknd_trxn_ctxt {
	/* Trxn-Id as assigned by MGMTD */
	uint64_t trxn_id;
	uint32_t flags;

	struct mgmt_bcknd_client_trxn_ctxt client_data;
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	/* List of batches belonging to this transaction */
	struct mgmt_bcknd_batch_list_head cfg_batches;
	struct mgmt_bcknd_batch_list_head apply_cfgs;

	struct mgmt_bcknd_trxn_list_item list_linkage;

	struct nb_transaction *nb_trxn;
	uint32_t nb_trxn_id;
};
#define MGMTD_BCKND_TRXN_FLAGS_CFGPREP_OFF (1U << 0)
#define MGMTD_BCKND_TRXN_FLAGS_CFGPREP_FAILED (1U << 1)
#define MGMTD_BCKND_TRXN_FLAGS_CFGAPPLY_OFF (1U << 2)
#define MGMTD_BCKND_TRXN_FLAGS_CLEANUP_PENDING (1U << 3)

DECLARE_LIST(mgmt_bcknd_trxn_list, struct mgmt_bcknd_trxn_ctxt, list_linkage);

#define FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)                          \
	frr_each_safe(mgmt_bcknd_batch_list, &(trxn)->cfg_batches, (batch))

#define FOREACH_BCKND_APPLY_BATCH_IN_LIST(trxn, batch)                         \
	frr_each_safe(mgmt_bcknd_batch_list, &(trxn)->apply_cfgs, (batch))

struct mgmt_bcknd_client_ctxt {
	int conn_fd;
	struct thread_master *tm;
	struct thread *conn_retry_tmr;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	struct thread *conn_writes_on;
	struct thread *msg_proc_ev;
	uint32_t flags;
	uint32_t num_msg_tx;
	uint32_t num_msg_rx;

	struct stream_fifo *ibuf_fifo;
	struct stream *ibuf_work;
	struct stream_fifo *obuf_fifo;
	struct stream *obuf_work;
	uint8_t msg_buf[MGMTD_BCKND_MSG_MAX_LEN];

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

	struct mgmt_bcknd_trxn_list_head trxn_head;
	struct mgmt_bcknd_client_params client_params;
};

#define MGMTD_BCKND_CLNT_FLAGS_WRITES_OFF (1U << 0)

#define FOREACH_BCKND_TRXN_IN_LIST(clntctxt, trxn)                             \
	frr_each_safe(mgmt_bcknd_trxn_list, &(clntctxt)->trxn_head, (trxn))

static bool mgmt_debug_bcknd_clnt;

static struct mgmt_bcknd_client_ctxt mgmt_bcknd_clntctxt = {0};

const char *mgmt_bcknd_client_names[MGMTD_CLIENT_NAME_MAX_LEN] = {
	MGMTD_BCKND_CLIENT_STATICD, /* MGMTD_BCKND_CLIENT_ID_STATICD */
	MGMTD_BCKND_CLIENT_BGPD,    /* MGMTD_BCKND_CLIENT_ID_BGPDD */
	"Unknown/Invalid",	  /* MGMTD_BCKND_CLIENT_ID_MAX */
};

/* Forward declarations */
static void
mgmt_bcknd_client_register_event(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				 enum mgmt_event event);
static void
mgmt_bcknd_client_schedule_conn_retry(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      unsigned long intvl_secs);
static int mgmt_bcknd_client_send_msg(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      Mgmtd__BckndMessage *bcknd_msg);

static void
mgmt_bcknd_server_disconnect(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			     bool reconnect)
{
	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void)(*clnt_ctxt->client_params.conn_notify_cb)(
			(uint64_t)clnt_ctxt, clnt_ctxt->client_params.user_data,
			false);

	if (clnt_ctxt->conn_fd) {
		close(clnt_ctxt->conn_fd);
		clnt_ctxt->conn_fd = 0;
	}

	if (reconnect)
		mgmt_bcknd_client_schedule_conn_retry(
			clnt_ctxt,
			clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static struct mgmt_bcknd_batch_ctxt *
mgmt_bcknd_find_batch_by_id(struct mgmt_bcknd_trxn_ctxt *trxn,
			    uint64_t batch_id)
{
	struct mgmt_bcknd_batch_ctxt *batch = NULL;

	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)
	{
		if (batch->batch_id == batch_id)
			return batch;
	}

	return NULL;
}

static struct mgmt_bcknd_batch_ctxt *
mgmt_bcknd_batch_create(struct mgmt_bcknd_trxn_ctxt *trxn, uint64_t batch_id)
{
	struct mgmt_bcknd_batch_ctxt *batch = NULL;

	batch = mgmt_bcknd_find_batch_by_id(trxn, batch_id);
	if (!batch) {
		batch = XCALLOC(MTYPE_MGMTD_BCKND_BATCH,
				sizeof(struct mgmt_bcknd_batch_ctxt));
		assert(batch);

		batch->batch_id = batch_id;
		mgmt_bcknd_batch_list_add_tail(&trxn->cfg_batches, batch);

		MGMTD_BCKND_CLNT_DBG("Added new batch 0x%llx to transaction",
				     batch_id);
	}

	return batch;
}

static void mgmt_bcknd_batch_delete(struct mgmt_bcknd_trxn_ctxt *trxn,
				    struct mgmt_bcknd_batch_ctxt **batch)
{
	uint16_t indx;

	if (!batch)
		return;

	mgmt_bcknd_batch_list_del(&trxn->cfg_batches, *batch);
	switch ((*batch)->trxn_req.event) {
	case MGMTD_BCKND_TRXN_PROC_SETCFG:
		for (indx = 0; indx < MGMTD_MAX_CFG_CHANGES_IN_BATCH; indx++) {
			if ((*batch)->trxn_req.req.set_cfg.cfg_changes[indx]
				    .value) {
				free((char *)(*batch)
					     ->trxn_req.req.set_cfg
					     .cfg_changes[indx]
					     .value);
			}
		}
		break;
	case MGMTD_BCKND_TRXN_PROC_GETCFG:
	case MGMTD_BCKND_TRXN_PROC_GETDATA:
		/*
		 * TODO: Add cleanup code here.
		 */
		break;
	default:
		break;
	}

	XFREE(MTYPE_MGMTD_BCKND_BATCH, *batch);
	*batch = NULL;
}

static void mgmt_bcknd_cleanup_all_batches(struct mgmt_bcknd_trxn_ctxt *trxn)
{
	struct mgmt_bcknd_batch_ctxt *batch = NULL;

	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)
	{
		mgmt_bcknd_batch_delete(trxn, &batch);
	}
}

static struct mgmt_bcknd_trxn_ctxt *
mgmt_bcknd_find_trxn_by_id(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			   uint64_t trxn_id)
{
	struct mgmt_bcknd_trxn_ctxt *trxn = NULL;

	FOREACH_BCKND_TRXN_IN_LIST(clnt_ctxt, trxn)
	{
		if (trxn->trxn_id == trxn_id)
			return trxn;
	}

	return NULL;
}

static struct mgmt_bcknd_trxn_ctxt *
mgmt_bcknd_trxn_create(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
		       uint64_t trxn_id)
{
	struct mgmt_bcknd_trxn_ctxt *trxn = NULL;

	trxn = mgmt_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		trxn = XCALLOC(MTYPE_MGMTD_BCKND_TRXN,
			       sizeof(struct mgmt_bcknd_trxn_ctxt));
		assert(trxn);

		trxn->trxn_id = trxn_id;
		trxn->clnt_ctxt = clnt_ctxt;
		mgmt_bcknd_batch_list_init(&trxn->cfg_batches);
		mgmt_bcknd_batch_list_init(&trxn->apply_cfgs);
		mgmt_bcknd_trxn_list_add_tail(&clnt_ctxt->trxn_head, trxn);

		MGMTD_BCKND_CLNT_DBG("Added new transaction 0x%llx", trxn_id);
	}

	return trxn;
}

static void mgmt_bcknd_trxn_delete(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				   struct mgmt_bcknd_trxn_ctxt **trxn)
{
	if (!trxn)
		return;

	/*
	 * Remove the transaction from the list of transactions
	 * so that future lookups with the same transaction id
	 * does not return this one.
	 */
	mgmt_bcknd_trxn_list_del(&clnt_ctxt->trxn_head, *trxn);

	if (mgmt_bcknd_batch_list_count(&(*trxn)->apply_cfgs)) {
		/*
		 * CFG_APPLY_REQs still pending for processing. Set
		 * appropraite flag so that the transaction will be
		 * cleaned up after all CFG_APPLY_REQ has been
		 * processed.
		 */
		SET_FLAG((*trxn)->flags,
			 MGMTD_BCKND_TRXN_FLAGS_CLEANUP_PENDING);
	} else {
		/*
		 * Time to delete the transaction which should also
		 * take care of cleaning up all batches created via
		 * CFGDATA_CREATE_REQs. But first notify the client
		 * about the transaction delete.
		 */
		if (clnt_ctxt->client_params.trxn_notify_cb)
			(void)(*clnt_ctxt->client_params.trxn_notify_cb)(
				(uint64_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				&(*trxn)->client_data, false);

		mgmt_bcknd_cleanup_all_batches(*trxn);
		XFREE(MTYPE_MGMTD_BCKND_TRXN, *trxn);
	}

	*trxn = NULL;
}

static void
mgmt_bcknd_cleanup_all_trxns(struct mgmt_bcknd_client_ctxt *clnt_ctxt)
{
	struct mgmt_bcknd_trxn_ctxt *trxn = NULL;

	FOREACH_BCKND_TRXN_IN_LIST(clnt_ctxt, trxn)
	{
		mgmt_bcknd_trxn_delete(clnt_ctxt, &trxn);
	}
}

static int mgmt_bcknd_send_trxn_reply(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      uint64_t trxn_id, bool create,
				      bool success)
{
	Mgmtd__BckndMessage bcknd_msg;
	Mgmtd__BckndTrxnReply trxn_reply;

	mgmtd__bcknd_trxn_reply__init(&trxn_reply);
	trxn_reply.create = create;
	trxn_reply.trxn_id = trxn_id;
	trxn_reply.success = success;

	mgmtd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = MGMTD__BCKND_MESSAGE__TYPE__TRXN_REPLY;
	bcknd_msg.message_case = MGMTD__BCKND_MESSAGE__MESSAGE_TRXN_REPLY;
	bcknd_msg.trxn_reply = &trxn_reply;

	MGMTD_BCKND_CLNT_DBG(
		"Sending TRXN_REPLY message to MGMTD for trxn 0x%llx", trxn_id);

	return mgmt_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int mgmt_bcknd_process_trxn_req(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				       uint64_t trxn_id, bool create)
{
	struct mgmt_bcknd_trxn_ctxt *trxn;

	trxn = mgmt_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (create) {
		if (trxn) {
			/*
			 * Transaction with same trxn-id already exists.
			 * Should not happen under any circumstances.
			 */
			MGMTD_BCKND_CLNT_ERR(
				"Transaction 0x%llx already exists!!!",
				trxn_id);
			mgmt_bcknd_send_trxn_reply(clnt_ctxt, trxn_id, create,
						   false);
		}

		MGMTD_BCKND_CLNT_DBG("Created new transaction 0x%llx", trxn_id);
		trxn = mgmt_bcknd_trxn_create(clnt_ctxt, trxn_id);

		if (clnt_ctxt->client_params.trxn_notify_cb)
			(void)(*clnt_ctxt->client_params.trxn_notify_cb)(
				(uint64_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				&trxn->client_data, true);
	} else {
		if (!trxn) {
			/*
			 * Transaction with same trxn-id does not exists.
			 * Return sucess anyways.
			 */
			MGMTD_BCKND_CLNT_DBG(
				"Transaction to delete 0x%llx does NOT exists!!!",
				trxn_id);
		} else {
			MGMTD_BCKND_CLNT_DBG("Delete transaction 0x%llx",
					     trxn_id);
			mgmt_bcknd_trxn_delete(clnt_ctxt, &trxn);
		}
	}

	mgmt_bcknd_send_trxn_reply(clnt_ctxt, trxn_id, create, true);

	return 0;
}

static int
mgmt_bcknd_send_cfgdata_create_reply(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				     uint64_t trxn_id, uint64_t batch_id,
				     bool success, const char *error_if_any)
{
	Mgmtd__BckndMessage bcknd_msg;
	Mgmtd__BckndCfgDataCreateReply cfgdata_reply;

	mgmtd__bcknd_cfg_data_create_reply__init(&cfgdata_reply);
	cfgdata_reply.trxn_id = (uint64_t)trxn_id;
	cfgdata_reply.batch_id = (uint64_t)batch_id;
	cfgdata_reply.success = success;
	if (error_if_any)
		cfgdata_reply.error_if_any = (char *)error_if_any;

	mgmtd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_REPLY;
	bcknd_msg.message_case = MGMTD__BCKND_MESSAGE__MESSAGE_CFG_DATA_REPLY;
	bcknd_msg.cfg_data_reply = &cfgdata_reply;

	MGMTD_BCKND_CLNT_DBG(
		"Sending CFGDATA_CREATE_REPLY message to MGMTD for trxn 0x%llx batch 0x%llx",
		trxn_id, batch_id);

	return mgmt_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int mgmt_bcknd_trxn_cfg_abort(struct mgmt_bcknd_trxn_ctxt *trxn)
{
	char errmsg[BUFSIZ] = {0};

	assert(trxn && trxn->clnt_ctxt);
	if (!trxn->nb_trxn
	    || !CHECK_FLAG(trxn->flags, MGMTD_BCKND_TRXN_FLAGS_CFGPREP_FAILED))
		return -1;

	MGMTD_BCKND_CLNT_ERR("Aborting configurations for Trxn 0x%llx",
			     trxn->trxn_id);
	nb_candidate_commit_abort(trxn->nb_trxn, errmsg, sizeof(errmsg));
	trxn->nb_trxn = 0;

	return 0;
}

static int mgmt_bcknd_trxn_cfg_prepare(struct mgmt_bcknd_trxn_ctxt *trxn)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;
	struct mgmt_bcknd_trxn_req *trxn_req = NULL;
	struct nb_context nb_ctxt = {0};
	struct timeval edit_nb_cfg_start;
	struct timeval edit_nb_cfg_end;
	unsigned long edit_nb_cfg_tm;
	struct timeval prep_nb_cfg_start;
	struct timeval prep_nb_cfg_end;
	unsigned long prep_nb_cfg_tm;
	struct mgmt_bcknd_batch_ctxt *batch;
	bool error;
	char err_buf[BUFSIZ];
	size_t num_processed;

	assert(trxn && trxn->clnt_ctxt);
	clnt_ctxt = trxn->clnt_ctxt;

	UNSET_FLAG(trxn->flags, MGMTD_BCKND_TRXN_FLAGS_CFGPREP_OFF);

	num_processed = 0;
	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)
	{
		trxn_req = &batch->trxn_req;
		error = false;
		nb_ctxt.client = NB_CLIENT_CLI;
		nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;

		if (!trxn->nb_trxn) {
			/*
			 * This happens when the current backend client is only
			 * interested in consuming the config items but is not
			 * interested in validating it.
			 */
			error = false;
			if (mgmt_debug_bcknd_clnt)
				mgmt_get_realtime(&edit_nb_cfg_start);
			nb_candidate_edit_config_changes(
				clnt_ctxt->candidate_config,
				trxn_req->req.set_cfg.cfg_changes,
				(size_t)trxn_req->req.set_cfg.num_cfg_changes,
				NULL, NULL, 0, err_buf, sizeof(err_buf),
				&error);
			if (error) {
				err_buf[sizeof(err_buf) - 1] = 0;
				MGMTD_BCKND_CLNT_ERR(
					"Failed to update configs for Trxn %llx Batch %llx to Candidate! Err: '%s'",
					trxn->trxn_id, batch->batch_id,
					err_buf);
				return -1;
			}
			if (mgmt_debug_bcknd_clnt) {
				mgmt_get_realtime(&edit_nb_cfg_end);
				edit_nb_cfg_tm = timeval_elapsed(
					edit_nb_cfg_end, edit_nb_cfg_start);
				clnt_ctxt->avg_edit_nb_cfg_tm =
					((clnt_ctxt->avg_edit_nb_cfg_tm
					  * clnt_ctxt->num_edit_nb_cfg)
					 + edit_nb_cfg_tm)
					/ (clnt_ctxt->num_edit_nb_cfg + 1);
			}
			clnt_ctxt->num_edit_nb_cfg++;
		}

		num_processed++;
	}

	if (!num_processed)
		return 0;

	/*
	 * Now prepare all the batches we have applied in one go.
	 */
	nb_ctxt.client = NB_CLIENT_CLI;
	nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;
	if (mgmt_debug_bcknd_clnt)
		mgmt_get_realtime(&prep_nb_cfg_start);
	if (nb_candidate_commit_prepare(
		    &nb_ctxt, clnt_ctxt->candidate_config, "MGMTD Backend Trxn",
		    &trxn->nb_trxn, true, true, err_buf, sizeof(err_buf) - 1)
	    != NB_OK) {
		err_buf[sizeof(err_buf) - 1] = 0;
		MGMTD_BCKND_CLNT_ERR(
			"Failed to prepare configs for Trxn %llx, %u Batches! Err: '%s'",
			trxn->trxn_id, (uint32_t)num_processed, err_buf);
		error = true;
		SET_FLAG(trxn->flags, MGMTD_BCKND_TRXN_FLAGS_CFGPREP_FAILED);
	}

	MGMTD_BCKND_CLNT_DBG(
		"Prepared configs for Trxn %llx, %u Batches! successfully!",
		trxn->trxn_id, (uint32_t)num_processed);
	if (mgmt_debug_bcknd_clnt) {
		mgmt_get_realtime(&prep_nb_cfg_end);
		prep_nb_cfg_tm =
			timeval_elapsed(prep_nb_cfg_end, prep_nb_cfg_start);
		clnt_ctxt->avg_prep_nb_cfg_tm =
			((clnt_ctxt->avg_prep_nb_cfg_tm
			  * clnt_ctxt->num_prep_nb_cfg)
			 + prep_nb_cfg_tm)
			/ (clnt_ctxt->num_prep_nb_cfg + 1);
	}
	clnt_ctxt->num_prep_nb_cfg++;

	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)
	{
		mgmt_bcknd_send_cfgdata_create_reply(
			clnt_ctxt, trxn->trxn_id, batch->batch_id,
			error ? false : true, error ? err_buf : NULL);
		if (!error) {
			SET_FLAG(batch->flags,
				 MGMTD_BCKND_BATCH_FLAGS_CFG_PREPARED);
			mgmt_bcknd_batch_list_del(&trxn->cfg_batches, batch);
			mgmt_bcknd_batch_list_add_tail(&trxn->apply_cfgs,
						       batch);
		}
	}

	if (mgmt_debug_bcknd_clnt)
		MGMTD_BCKND_CLNT_DBG(
			"Avg-nb-edit-duration %zu uSec, nb-prep-duration %zu (avg: %zu) uSec, batch size %u",
			clnt_ctxt->avg_edit_nb_cfg_tm, prep_nb_cfg_tm,
			clnt_ctxt->avg_prep_nb_cfg_tm, (uint32_t)num_processed);

	if (error)
		mgmt_bcknd_trxn_cfg_abort(trxn);

	return 0;
}

/*
 * Process all CFG_DATA_REQs received so far and prepare them all in one go.
 */
static int
mgmt_bcknd_update_setcfg_in_batch(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				  struct mgmt_bcknd_trxn_ctxt *trxn,
				  uint64_t batch_id,
				  Mgmtd__YangCfgDataReq * cfg_req[],
				  int num_req)
{
	struct mgmt_bcknd_batch_ctxt *batch = NULL;
	struct mgmt_bcknd_trxn_req *trxn_req = NULL;
	int index;
	struct nb_cfg_change *cfg_chg;

	batch = mgmt_bcknd_batch_create(trxn, batch_id);
	if (!batch) {
		MGMTD_BCKND_CLNT_ERR("Batch create failed!");
		return -1;
	}

	trxn_req = &batch->trxn_req;
	trxn_req->event = MGMTD_BCKND_TRXN_PROC_SETCFG;
	MGMTD_BCKND_CLNT_DBG(
		"Created Set-Config request for batch 0x%llx, trxn id 0x%llx, cfg-items:%d",
		batch_id, trxn->trxn_id, num_req);

	trxn_req->req.set_cfg.num_cfg_changes = num_req;
	for (index = 0; index < num_req; index++) {
		cfg_chg = &trxn_req->req.set_cfg.cfg_changes[index];

		switch (cfg_req[index]->req_type) {
		case MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA:
			cfg_chg->operation = NB_OP_DESTROY;
			break;
		case MGMTD__CFG_DATA_REQ_TYPE__SET_DATA:
		default:
			cfg_chg->operation = NB_OP_CREATE;
			break;
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
		    && !strncmp(cfg_chg->value, MGMTD_BCKND_CONTAINER_NODE_VAL,
				strlen(MGMTD_BCKND_CONTAINER_NODE_VAL))) {
			free((char *)cfg_chg->value);
			cfg_chg->value = NULL;
		}
	}

	return 0;
}

static int
mgmt_bcknd_process_cfgdata_req(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			       uint64_t trxn_id, uint64_t batch_id,
			       Mgmtd__YangCfgDataReq * cfg_req[], int num_req,
			       bool end_of_data)
{
	struct mgmt_bcknd_trxn_ctxt *trxn;

	trxn = mgmt_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		MGMTD_BCKND_CLNT_ERR(
			"Invalid trxn-id 0x%llx provided from MGMTD server",
			trxn_id);
		mgmt_bcknd_send_cfgdata_create_reply(
			clnt_ctxt, trxn_id, batch_id, false,
			"Transaction context not created yet");
	} else {
		mgmt_bcknd_update_setcfg_in_batch(clnt_ctxt, trxn, batch_id,
						  cfg_req, num_req);
	}

	if (trxn && end_of_data) {
		MGMTD_BCKND_CLNT_DBG("Triggering CFG_PREPARE_REQ processing");
		mgmt_bcknd_trxn_cfg_prepare(trxn);
	}

	return 0;
}

static int
mgmt_bcknd_send_validate_reply(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			       uint64_t trxn_id, uint64_t batch_ids[],
			       size_t num_batch_ids, bool success,
			       const char *error_if_any)
{
	Mgmtd__BckndMessage bcknd_msg;
	Mgmtd__BckndCfgDataValidateReply validate_reply;

	mgmtd__bcknd_cfg_data_validate_reply__init(&validate_reply);
	validate_reply.success = success;
	validate_reply.trxn_id = trxn_id;
	validate_reply.batch_ids = (uint64_t *)batch_ids;
	validate_reply.n_batch_ids = num_batch_ids;

	if (error_if_any)
		validate_reply.error_if_any = (char *)error_if_any;

	mgmtd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REPLY;
	bcknd_msg.message_case =
		MGMTD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REPLY;
	bcknd_msg.cfg_validate_reply = &validate_reply;

	MGMTD_BCKND_CLNT_DBG(
		"Sending CFG_VALIDATE_REPLY message to MGMTD for trxn 0x%llx %d  batches [0x%llx - 0x%llx]",
		trxn_id, (int)num_batch_ids, batch_ids[0],
		batch_ids[num_batch_ids - 1]);

	return mgmt_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int
mgmt_bcknd_process_cfg_validate(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				uint64_t trxn_id, uint64_t batch_ids[],
				size_t num_batch_ids)
{
	int ret = 0;
	size_t indx;
	struct mgmt_bcknd_trxn_ctxt *trxn;
	struct mgmt_bcknd_trxn_req *trxn_req = NULL;
	struct mgmt_bcknd_batch_ctxt *batch;
	bool error;
	char err_buf[1024];
	struct nb_context nb_ctxt = {0};

	trxn = mgmt_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		mgmt_bcknd_send_validate_reply(clnt_ctxt, trxn_id, batch_ids,
					       num_batch_ids, false,
					       "Transaction not created yet!");
		return -1;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		batch = mgmt_bcknd_find_batch_by_id(trxn, batch_ids[indx]);
		if (!batch) {
			mgmt_bcknd_send_validate_reply(
				clnt_ctxt, trxn_id, batch_ids, num_batch_ids,
				false, "Batch context not created!");
			return -1;
		}

		if (batch->trxn_req.event != MGMTD_BCKND_TRXN_PROC_SETCFG) {
			snprintf(err_buf, sizeof(err_buf),
				 "Batch-id 0x%llx not a Config Data Batch!",
				 batch_ids[indx]);
			mgmt_bcknd_send_validate_reply(clnt_ctxt, trxn_id,
						       batch_ids, num_batch_ids,
						       false, err_buf);
			return -1;
		}

		trxn_req = &batch->trxn_req;
		error = false;
		nb_candidate_edit_config_changes(
			clnt_ctxt->candidate_config,
			trxn_req->req.set_cfg.cfg_changes,
			(size_t)trxn_req->req.set_cfg.num_cfg_changes, NULL,
			NULL, 0, err_buf, sizeof(err_buf), &error);
		if (error) {
			err_buf[sizeof(err_buf) - 1] = 0;
			MGMTD_BCKND_CLNT_ERR(
				"Failed to apply configs for Trxn %llx Batch %llx to Candidate! Err: '%s'",
				trxn_id, batch_ids[indx], err_buf);
			mgmt_bcknd_send_validate_reply(
				clnt_ctxt, trxn_id, batch_ids, num_batch_ids,
				false,
				"Failed to update Candidate Db on backend!");
			return -1;
		}
	}

	nb_ctxt.client = NB_CLIENT_CLI;
	nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;
	if (nb_candidate_commit_prepare(&nb_ctxt, clnt_ctxt->candidate_config,
					"MGMTD Trxn", &trxn->nb_trxn, false,
					false, err_buf, sizeof(err_buf) - 1)
	    != NB_OK) {
		err_buf[sizeof(err_buf) - 1] = 0;
		MGMTD_BCKND_CLNT_ERR(
			"Failed to validate configs for Trxn %llx Batch %llx! Err: '%s'",
			trxn_id, batch_ids[indx], err_buf);
		mgmt_bcknd_send_validate_reply(
			clnt_ctxt, trxn_id, batch_ids, num_batch_ids, false,
			"Failed to validate Config on backend!");
		return -1;
	}

	if (ret == 0) {
		mgmt_bcknd_send_validate_reply(clnt_ctxt, trxn_id, batch_ids,
					       num_batch_ids, true, NULL);
	}

	return ret;
}

static int mgmt_bcknd_send_apply_reply(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				       uint64_t trxn_id, uint64_t batch_ids[],
				       size_t num_batch_ids, bool success,
				       const char *error_if_any)
{
	Mgmtd__BckndMessage bcknd_msg;
	Mgmtd__BckndCfgDataApplyReply apply_reply;

	mgmtd__bcknd_cfg_data_apply_reply__init(&apply_reply);
	apply_reply.success = success;
	apply_reply.trxn_id = trxn_id;
	apply_reply.batch_ids = (uint64_t *)batch_ids;
	apply_reply.n_batch_ids = num_batch_ids;

	if (error_if_any)
		apply_reply.error_if_any = (char *)error_if_any;

	mgmtd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REPLY;
	bcknd_msg.message_case = MGMTD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REPLY;
	bcknd_msg.cfg_apply_reply = &apply_reply;

	MGMTD_BCKND_CLNT_DBG(
		"Sending CFG_APPLY_REPLY message to MGMTD for trxn 0x%llx %d  batches [0x%llx - 0x%llx]",
		trxn_id, (int)num_batch_ids, batch_ids[0],
		batch_ids[num_batch_ids - 1]);

	return mgmt_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int mgmt_bcknd_trxn_proc_cfgapply(struct mgmt_bcknd_trxn_ctxt *trxn)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;
	struct timeval apply_nb_cfg_start;
	struct timeval apply_nb_cfg_end;
	unsigned long apply_nb_cfg_tm;
	struct mgmt_bcknd_batch_ctxt *batch;
	char err_buf[BUFSIZ];
	size_t num_processed;
	static uint64_t batch_ids[MGMTD_BCKND_MAX_BATCH_IDS_IN_REQ];

	assert(trxn && trxn->clnt_ctxt);
	clnt_ctxt = trxn->clnt_ctxt;

	UNSET_FLAG(trxn->flags, MGMTD_BCKND_TRXN_FLAGS_CFGAPPLY_OFF);

	assert(trxn->nb_trxn);
	num_processed = 0;

	/*
	 * Now apply all the batches we have applied in one go.
	 */
	(void)nb_candidate_commit_apply(trxn->nb_trxn, true, &trxn->nb_trxn_id,
					err_buf, sizeof(err_buf) - 1);
	if (mgmt_debug_bcknd_clnt) {
		mgmt_get_realtime(&apply_nb_cfg_end);
		apply_nb_cfg_tm =
			timeval_elapsed(apply_nb_cfg_end, apply_nb_cfg_start);
		clnt_ctxt->avg_apply_nb_cfg_tm =
			((clnt_ctxt->avg_apply_nb_cfg_tm
			  * clnt_ctxt->num_apply_nb_cfg)
			 + apply_nb_cfg_tm)
			/ (clnt_ctxt->num_apply_nb_cfg + 1);
	}
	clnt_ctxt->num_apply_nb_cfg++;
	trxn->nb_trxn = NULL;

	/*
	 * Send back CFG_APPLY_REPLY for all batches applied.
	 */
	FOREACH_BCKND_APPLY_BATCH_IN_LIST(trxn, batch)
	{
		/*
		 * No need to delete the batch yet. Will be deleted during
		 * transaction cleanup on receiving TRXN_DELETE_REQ.
		 */
		SET_FLAG(batch->flags, MGMTD_BCKND_TRXN_FLAGS_CFG_APPLIED);
		mgmt_bcknd_batch_list_del(&trxn->apply_cfgs, batch);
		mgmt_bcknd_batch_list_add_tail(&trxn->cfg_batches, batch);

		batch_ids[num_processed] = batch->batch_id;
		num_processed++;
		if (num_processed == MGMTD_BCKND_MAX_BATCH_IDS_IN_REQ) {
			mgmt_bcknd_send_apply_reply(clnt_ctxt, trxn->trxn_id,
						    batch_ids, num_processed,
						    true, NULL);
			num_processed = 0;
		}
	}

	mgmt_bcknd_send_apply_reply(clnt_ctxt, trxn->trxn_id, batch_ids,
				    num_processed, true, NULL);

	if (mgmt_debug_bcknd_clnt)
		MGMTD_BCKND_CLNT_DBG("Nb-apply-duration %zu (avg: %zu) uSec",
				     apply_nb_cfg_tm,
				     clnt_ctxt->avg_apply_nb_cfg_tm);

	return 0;
}

static int
mgmt_bcknd_process_cfg_apply(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			     uint64_t trxn_id)
{
	struct mgmt_bcknd_trxn_ctxt *trxn;

	trxn = mgmt_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		mgmt_bcknd_send_apply_reply(clnt_ctxt, trxn_id, NULL, 0, false,
					    "Transaction not created yet!");
		return -1;
	}

	MGMTD_BCKND_CLNT_DBG("Trigger CFG_APPLY_REQ processing");
	mgmt_bcknd_trxn_proc_cfgapply(trxn);

	return 0;
}

static int
mgmt_bcknd_client_handle_msg(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			     Mgmtd__BckndMessage *bcknd_msg)
{
	switch (bcknd_msg->type) {
	case MGMTD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REPLY:
		assert(bcknd_msg->message_case
		       == MGMTD__BCKND_MESSAGE__MESSAGE_SUBSCR_REPLY);
		MGMTD_BCKND_CLNT_DBG("Subscribe Reply Msg from mgmt, status %u",
				     bcknd_msg->subscr_reply->success);
		break;
	case MGMTD__BCKND_MESSAGE__TYPE__TRXN_REQ:
		assert(bcknd_msg->message_case
		       == MGMTD__BCKND_MESSAGE__MESSAGE_TRXN_REQ);
		mgmt_bcknd_process_trxn_req(clnt_ctxt,
					    bcknd_msg->trxn_req->trxn_id,
					    bcknd_msg->trxn_req->create);
		break;
	case MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_REQ:
		assert(bcknd_msg->message_case
		       == MGMTD__BCKND_MESSAGE__MESSAGE_CFG_DATA_REQ);
		mgmt_bcknd_process_cfgdata_req(
			clnt_ctxt, bcknd_msg->cfg_data_req->trxn_id,
			bcknd_msg->cfg_data_req->batch_id,
			bcknd_msg->cfg_data_req->data_req,
			bcknd_msg->cfg_data_req->n_data_req,
			bcknd_msg->cfg_data_req->end_of_data);
		break;
	case MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REQ:
		assert(bcknd_msg->message_case
		       == MGMTD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REQ);
		mgmt_bcknd_process_cfg_validate(
			clnt_ctxt,
			(uint64_t)bcknd_msg->cfg_validate_req->trxn_id,
			(uint64_t *)bcknd_msg->cfg_validate_req->batch_ids,
			bcknd_msg->cfg_validate_req->n_batch_ids);
		break;
	case MGMTD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REQ:
		assert(bcknd_msg->message_case
		       == MGMTD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REQ);
		mgmt_bcknd_process_cfg_apply(
			clnt_ctxt, (uint64_t)bcknd_msg->cfg_apply_req->trxn_id);
		break;
	default:
		break;
	}

	return 0;
}

static int
mgmt_bcknd_client_process_msg(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
			      uint8_t *msg_buf, int bytes_read)
{
	Mgmtd__BckndMessage *bcknd_msg;
	struct mgmt_bcknd_msg *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	MGMTD_BCKND_CLNT_DBG(
		"Got message of %d bytes from MGMTD Backend Server",
		bytes_read);

	bytes_left = bytes_read;
	for (; bytes_left > MGMTD_BCKND_MSG_HDR_LEN;
	     bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (struct mgmt_bcknd_msg *)msg_buf;
		if (msg->hdr.marker != MGMTD_BCKND_MSG_MARKER) {
			MGMTD_BCKND_CLNT_DBG(
				"Marker not found in message from MGMTD '%s'",
				clnt_ctxt->client_params.name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_BCKND_CLNT_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD '%s'",
				bytes_left, msg->hdr.len,
				clnt_ctxt->client_params.name);
			break;
		}

		bcknd_msg = mgmtd__bcknd_message__unpack(
			NULL, (size_t)(msg->hdr.len - MGMTD_BCKND_MSG_HDR_LEN),
			msg->payload);
		if (!bcknd_msg) {
			MGMTD_BCKND_CLNT_DBG(
				"Failed to decode %d bytes from MGMTD '%s'",
				msg->hdr.len, clnt_ctxt->client_params.name);
			continue;
		}

		(void)mgmt_bcknd_client_handle_msg(clnt_ctxt, bcknd_msg);
		mgmtd__bcknd_message__free_unpacked(bcknd_msg, NULL);
		processed++;
		clnt_ctxt->num_msg_rx++;
	}

	return processed;
}

static int mgmt_bcknd_client_proc_msgbufs(struct thread *thread)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;
	struct stream *work;
	int processed = 0;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	if (clnt_ctxt->conn_fd == 0)
		return 0;

	for (; processed < MGMTD_BCKND_MAX_NUM_MSG_PROC;) {
		work = stream_fifo_pop_safe(clnt_ctxt->ibuf_fifo);
		if (!work)
			break;

		processed += mgmt_bcknd_client_process_msg(
			clnt_ctxt, STREAM_DATA(work), stream_get_endp(work));

		if (work != clnt_ctxt->ibuf_work) {
			/* Free it up */
			stream_free(work);
		} else {
			/* Reset stream buffer for next read */
			stream_reset(work);
		}
	}

	/*
	 * If we have more to process, reschedule for processing it.
	 */
	if (stream_fifo_head(clnt_ctxt->ibuf_fifo))
		mgmt_bcknd_client_register_event(clnt_ctxt,
						 MGMTD_BCKND_PROC_MSG);

	return 0;
}

static int mgmt_bcknd_client_read(struct thread *thread)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	struct mgmt_bcknd_msg_hdr *msg_hdr;
	bool incomplete = false;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(clnt_ctxt->ibuf_work)
		     - stream_get_endp(clnt_ctxt->ibuf_work);
	for (; bytes_left > MGMTD_BCKND_MSG_HDR_LEN;) {
		bytes_read = stream_read_try(clnt_ctxt->ibuf_work,
					     clnt_ctxt->conn_fd, bytes_left);
		MGMTD_BCKND_CLNT_DBG(
			"Got %d bytes of message from MGMTD Backend server",
			bytes_read);
		if (bytes_read <= 0) {
			if (bytes_read == -1
			    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				mgmt_bcknd_client_register_event(
					clnt_ctxt, MGMTD_BCKND_CONN_READ);
				return 0;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				MGMTD_BCKND_CLNT_ERR(
					"Got error (%d) while reading from MGMTD Backend server. Err: '%s'",
					bytes_read, safe_strerror(errno));
				mgmt_bcknd_server_disconnect(clnt_ctxt, true);
				return -1;
			}
			break;
		}

		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we would have read incomplete messages or not.
	 */
	stream_set_getp(clnt_ctxt->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(clnt_ctxt->ibuf_work);
	for (; bytes_left > MGMTD_BCKND_MSG_HDR_LEN;) {
		msg_hdr = (struct mgmt_bcknd_msg_hdr
				   *)(STREAM_DATA(clnt_ctxt->ibuf_work)
				      + total_bytes);
		if (msg_hdr->marker != MGMTD_BCKND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_BCKND_CLNT_ERR(
				"Received corrupted buffer from MGMTD backend server.");
			mgmt_bcknd_server_disconnect(clnt_ctxt, true);
			return -1;
		}
		if (msg_hdr->len > bytes_left)
			break;

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	if (bytes_left > 0)
		incomplete = true;

	/*
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	msg_hdr =
		(struct mgmt_bcknd_msg_hdr *)(STREAM_DATA(clnt_ctxt->ibuf_work)
					      + total_bytes);
	stream_set_endp(clnt_ctxt->ibuf_work, total_bytes);
	stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);
	clnt_ctxt->ibuf_work = stream_new(MGMTD_BCKND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(clnt_ctxt->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(clnt_ctxt->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		mgmt_bcknd_client_register_event(clnt_ctxt,
						 MGMTD_BCKND_PROC_MSG);

	mgmt_bcknd_client_register_event(clnt_ctxt, MGMTD_BCKND_CONN_READ);

	return 0;
}

static inline void
mgmt_bcknd_client_sched_msg_write(struct mgmt_bcknd_client_ctxt *clnt_ctxt)
{
	if (!CHECK_FLAG(clnt_ctxt->flags, MGMTD_BCKND_CLNT_FLAGS_WRITES_OFF))
		mgmt_bcknd_client_register_event(clnt_ctxt,
						 MGMTD_BCKND_CONN_WRITE);
}

static inline void
mgmt_bcknd_client_writes_on(struct mgmt_bcknd_client_ctxt *clnt_ctxt)
{
	MGMTD_BCKND_CLNT_DBG("Resume writing msgs");
	UNSET_FLAG(clnt_ctxt->flags, MGMTD_BCKND_CLNT_FLAGS_WRITES_OFF);
	if (clnt_ctxt->obuf_work
	    || stream_fifo_count_safe(clnt_ctxt->obuf_fifo))
		mgmt_bcknd_client_sched_msg_write(clnt_ctxt);
}

static inline void
mgmt_bcknd_client_writes_off(struct mgmt_bcknd_client_ctxt *clnt_ctxt)
{
	SET_FLAG(clnt_ctxt->flags, MGMTD_BCKND_CLNT_FLAGS_WRITES_OFF);
	MGMTD_BCKND_CLNT_DBG("Paused writing msgs");
}

static int mgmt_bcknd_client_send_msg(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      Mgmtd__BckndMessage *bcknd_msg)
{
	size_t msg_size;
	uint8_t *msg_buf = clnt_ctxt->msg_buf;
	struct mgmt_bcknd_msg *msg;

	if (clnt_ctxt->conn_fd == 0)
		return -1;

	msg_size = mgmtd__bcknd_message__get_packed_size(bcknd_msg);
	msg_size += MGMTD_BCKND_MSG_HDR_LEN;
	if (msg_size > MGMTD_BCKND_MSG_MAX_LEN) {
		MGMTD_BCKND_CLNT_ERR(
			"Message size %d more than max size'%d. Not sending!'",
			(int)msg_size, (int)MGMTD_BCKND_MSG_MAX_LEN);
		return -1;
	}

	msg = (struct mgmt_bcknd_msg *)msg_buf;
	msg->hdr.marker = MGMTD_BCKND_MSG_MARKER;
	msg->hdr.len = (uint16_t)msg_size;
	mgmtd__bcknd_message__pack(bcknd_msg, msg->payload);

#ifndef MGMTD_PACK_TX_MSGS
	clnt_ctxt->obuf_work = stream_new(msg_size);
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
	stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
	clnt_ctxt->obuf_work = NULL;
#else
	if (!clnt_ctxt->obuf_work)
		clnt_ctxt->obuf_work = stream_new(MGMTD_BCKND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(clnt_ctxt->obuf_work) < msg_size) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = stream_new(MGMTD_BCKND_MSG_MAX_LEN);
	}
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
#endif
	mgmt_bcknd_client_sched_msg_write(clnt_ctxt);
	clnt_ctxt->num_msg_tx++;
	return 0;
}

static int mgmt_bcknd_client_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (clnt_ctxt->obuf_work) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = NULL;
	}

	for (s = stream_fifo_head(clnt_ctxt->obuf_fifo);
	     s && processed < MGMTD_BCKND_MAX_NUM_MSG_WRITE;
	     s = stream_fifo_head(clnt_ctxt->obuf_fifo)) {
		/* msg_size = (int)stream_get_size(s); */
		msg_size = (int)STREAM_READABLE(s);
		bytes_written = stream_flush(s, clnt_ctxt->conn_fd);
		if (bytes_written == -1
		    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_bcknd_client_register_event(
				clnt_ctxt, MGMTD_BCKND_CONN_WRITE);
			return 0;
		} else if (bytes_written != msg_size) {
			MGMTD_BCKND_CLNT_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_bcknd_client_register_event(
					clnt_ctxt, MGMTD_BCKND_CONN_WRITE);
				return 0;
			}
			mgmt_bcknd_server_disconnect(clnt_ctxt, true);
			return -1;
		}

		free = stream_fifo_pop(clnt_ctxt->obuf_fifo);
		stream_free(free);
		MGMTD_BCKND_CLNT_DBG(
			"Wrote %d bytes of message to MGMTD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_bcknd_client_writes_off(clnt_ctxt);
		mgmt_bcknd_client_register_event(clnt_ctxt,
						 MGMTD_BCKND_CONN_WRITES_ON);
	}

	return 0;
}

static int mgmt_bcknd_client_resume_writes(struct thread *thread)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	mgmt_bcknd_client_writes_on(clnt_ctxt);

	return 0;
}

static int mgmt_bcknd_send_subscr_req(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      bool subscr_xpaths,
				      uint16_t num_reg_xpaths,
				      char **reg_xpaths)
{
	Mgmtd__BckndMessage bcknd_msg;
	Mgmtd__BckndSubscribeReq subscr_req;

	mgmtd__bcknd_subscribe_req__init(&subscr_req);
	subscr_req.client_name = clnt_ctxt->client_params.name;
	subscr_req.n_xpath_reg = num_reg_xpaths;
	if (num_reg_xpaths)
		subscr_req.xpath_reg = reg_xpaths;
	else
		subscr_req.xpath_reg = NULL;
	subscr_req.subscribe_xpaths = subscr_xpaths;

	mgmtd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = MGMTD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REQ;
	bcknd_msg.message_case = MGMTD__BCKND_MESSAGE__MESSAGE_SUBSCR_REQ;
	bcknd_msg.subscr_req = &subscr_req;

	return mgmt_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int mgmt_bcknd_server_connect(struct mgmt_bcknd_client_ctxt *clnt_ctxt)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	MGMTD_BCKND_CLNT_DBG("Trying to connect to MGMTD Backend server at %s",
			     MGMTD_BCKND_SERVER_PATH);

	assert(!clnt_ctxt->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		MGMTD_BCKND_CLNT_ERR("Failed to create socket");
		goto mgmt_bcknd_server_connect_failed;
	}

	MGMTD_BCKND_CLNT_DBG(
		"Created MGMTD Backend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, MGMTD_BCKND_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		MGMTD_BCKND_CLNT_ERR(
			"Failed to connect to MGMTD Backend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto mgmt_bcknd_server_connect_failed;
	}

	MGMTD_BCKND_CLNT_DBG(
		"Connected to MGMTD Backend Server at %s successfully!",
		addr.sun_path);
	clnt_ctxt->conn_fd = sock;

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);
	setsockopt_so_sendbuf(clnt_ctxt->conn_fd,
			      MGMTD_SOCKET_BCKND_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(clnt_ctxt->conn_fd,
			      MGMTD_SOCKET_BCKND_RECV_BUF_SIZE);

	mgmt_bcknd_client_register_event(clnt_ctxt, MGMTD_BCKND_CONN_READ);

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void)(*clnt_ctxt->client_params.conn_notify_cb)(
			(uint64_t)clnt_ctxt, clnt_ctxt->client_params.user_data,
			true);

	/* Send SUBSCRIBE_REQ message */
	if (mgmt_bcknd_send_subscr_req(clnt_ctxt, false, 0, NULL) != 0)
		goto mgmt_bcknd_server_connect_failed;

	return 0;

mgmt_bcknd_server_connect_failed:
	if (sock && sock != clnt_ctxt->conn_fd)
		close(sock);

	mgmt_bcknd_server_disconnect(clnt_ctxt, true);
	return -1;
}

static int mgmt_bcknd_client_conn_timeout(struct thread *thread)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	return mgmt_bcknd_server_connect(clnt_ctxt);
}

static void
mgmt_bcknd_client_register_event(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				 enum mgmt_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_BCKND_CONN_READ:
		thread_add_read(clnt_ctxt->tm, mgmt_bcknd_client_read,
				clnt_ctxt, clnt_ctxt->conn_fd,
				&clnt_ctxt->conn_read_ev);
		assert(clnt_ctxt->conn_read_ev);
		break;
	case MGMTD_BCKND_CONN_WRITE:
		thread_add_write(clnt_ctxt->tm, mgmt_bcknd_client_write,
				 clnt_ctxt, clnt_ctxt->conn_fd,
				 &clnt_ctxt->conn_write_ev);
		assert(clnt_ctxt->conn_write_ev);
		break;
	case MGMTD_BCKND_PROC_MSG:
		tv.tv_usec = MGMTD_BCKND_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(clnt_ctxt->tm,
				    mgmt_bcknd_client_proc_msgbufs, clnt_ctxt,
				    &tv, &clnt_ctxt->msg_proc_ev);
		assert(clnt_ctxt->msg_proc_ev);
		break;
	/* case MGMTD_BCKND_SCHED_CFG_APPLY:
	 *	tv.tv_usec = MGMTD_BCKND_CFGAPPLY_SCHED_DELAY_USEC;
	 *	clnt_ctxt->msg_proc_ev =
	 *		thread_add_timer_tv(clnt_ctxt->tm,
	 *			mgmt_bcknd_client_proc_msgbufs, clnt_ctxt,
	 *			&tv, NULL);
	 *	break;
	 */
	case MGMTD_BCKND_CONN_WRITES_ON:
		thread_add_timer_msec(
			clnt_ctxt->tm, mgmt_bcknd_client_resume_writes,
			clnt_ctxt, MGMTD_BCKND_MSG_WRITE_DELAY_MSEC,
			&clnt_ctxt->conn_writes_on);
		assert(clnt_ctxt->conn_writes_on);
		break;
	default:
		assert(!"mgmt_bcknd_client_post_event() called incorrectly");
	}
}

static void
mgmt_bcknd_client_schedule_conn_retry(struct mgmt_bcknd_client_ctxt *clnt_ctxt,
				      unsigned long intvl_secs)
{
	MGMTD_BCKND_CLNT_DBG(
		"Scheduling MGMTD Backend server connection retry after %lu seconds",
		intvl_secs);
	thread_add_timer(clnt_ctxt->tm, mgmt_bcknd_client_conn_timeout,
			 (void *)clnt_ctxt, intvl_secs,
			 &clnt_ctxt->conn_retry_tmr);
}

extern struct nb_config *running_config;

/*
 * Initialize library and try connecting with MGMTD.
 */
uint64_t mgmt_bcknd_client_lib_init(struct mgmt_bcknd_client_params *params,
				    struct thread_master *master_thread)
{
	assert(master_thread && params && strlen(params->name)
	       && !mgmt_bcknd_clntctxt.tm);

	mgmt_bcknd_clntctxt.tm = master_thread;

	if (!running_config)
		assert(!"MGMTD Bcknd Client lib_init() after frr_init() only!");
	mgmt_bcknd_clntctxt.running_config = running_config;
	mgmt_bcknd_clntctxt.candidate_config = nb_config_new(NULL);

	memcpy(&mgmt_bcknd_clntctxt.client_params, params,
	       sizeof(mgmt_bcknd_clntctxt.client_params));
	if (!mgmt_bcknd_clntctxt.client_params.conn_retry_intvl_sec)
		mgmt_bcknd_clntctxt.client_params.conn_retry_intvl_sec =
			MGMTD_BCKND_DEFAULT_CONN_RETRY_INTVL_SEC;

	assert(!mgmt_bcknd_clntctxt.ibuf_fifo && !mgmt_bcknd_clntctxt.ibuf_work
	       && !mgmt_bcknd_clntctxt.obuf_fifo
	       && !mgmt_bcknd_clntctxt.obuf_work);

	mgmt_bcknd_trxn_list_init(&mgmt_bcknd_clntctxt.trxn_head);
	mgmt_bcknd_clntctxt.ibuf_fifo = stream_fifo_new();
	mgmt_bcknd_clntctxt.ibuf_work = stream_new(MGMTD_BCKND_MSG_MAX_LEN);
	mgmt_bcknd_clntctxt.obuf_fifo = stream_fifo_new();
	/* mgmt_bcknd_clntctxt.obuf_work = stream_new(MGMTD_BCKND_MSG_MAX_LEN);
	 */
	mgmt_bcknd_clntctxt.obuf_work = NULL;

	/* Start trying to connect to MGMTD backend server immediately */
	mgmt_bcknd_client_schedule_conn_retry(&mgmt_bcknd_clntctxt, 1);

	MGMTD_BCKND_CLNT_DBG("Initialized client '%s'", params->name);

	return (uint64_t)&mgmt_bcknd_clntctxt;
}

/*
 * Subscribe with MGMTD for one or more YANG subtree(s).
 */
enum mgmt_result mgmt_bcknd_subscribe_yang_data(uint64_t lib_hndl,
						char *reg_yang_xpaths[],
						int num_reg_xpaths)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_bcknd_send_subscr_req(clnt_ctxt, true, num_reg_xpaths,
				       reg_yang_xpaths)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Unsubscribe with MGMTD for one or more YANG subtree(s).
 */
enum mgmt_result mgmt_bcknd_unsubscribe_yang_data(uint64_t lib_hndl,
						  char *reg_yang_xpaths[],
						  int num_reg_xpaths)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;


	if (mgmt_bcknd_send_subscr_req(clnt_ctxt, false, num_reg_xpaths,
				       reg_yang_xpaths)
	    < 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send one or more YANG notifications to MGMTD daemon.
 */
enum mgmt_result mgmt_bcknd_send_yang_notify(uint64_t lib_hndl,
					     Mgmtd__YangData * data_elems[],
					     int num_elems)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	return MGMTD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void mgmt_bcknd_client_lib_destroy(uint64_t lib_hndl)
{
	struct mgmt_bcknd_client_ctxt *clnt_ctxt;

	clnt_ctxt = (struct mgmt_bcknd_client_ctxt *)lib_hndl;
	assert(clnt_ctxt);

	MGMTD_BCKND_CLNT_DBG("Destroying MGMTD Backend Client '%s'",
			     clnt_ctxt->client_params.name);

	mgmt_bcknd_server_disconnect(clnt_ctxt, false);

	assert(mgmt_bcknd_clntctxt.ibuf_fifo && mgmt_bcknd_clntctxt.obuf_fifo);

	stream_fifo_free(mgmt_bcknd_clntctxt.ibuf_fifo);
	if (mgmt_bcknd_clntctxt.ibuf_work)
		stream_free(mgmt_bcknd_clntctxt.ibuf_work);
	stream_fifo_free(mgmt_bcknd_clntctxt.obuf_fifo);
	if (mgmt_bcknd_clntctxt.obuf_work)
		stream_free(mgmt_bcknd_clntctxt.obuf_work);

	THREAD_OFF(clnt_ctxt->conn_retry_tmr);
	THREAD_OFF(clnt_ctxt->conn_read_ev);
	THREAD_OFF(clnt_ctxt->conn_write_ev);
	THREAD_OFF(clnt_ctxt->conn_writes_on);
	THREAD_OFF(clnt_ctxt->msg_proc_ev);
	mgmt_bcknd_cleanup_all_trxns(clnt_ctxt);
	mgmt_bcknd_trxn_list_fini(&clnt_ctxt->trxn_head);
}
