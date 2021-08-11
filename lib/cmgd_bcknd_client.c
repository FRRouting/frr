/*
 * CMGD Backend Client Library api interfaces
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
#include "lib/cmgd_bcknd_client.h"
#include "lib/cmgd_pb.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "lib/memory.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_BCKND_CLNT_DBG(fmt, ...)					\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_BCKND_CLNT_ERR(fmt, ...)					\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_BCKND_CLNT_DBG(fmt, ...)					\
	if (cmgd_debug_bcknd_clnt)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_BCKND_CLNT_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

DEFINE_MTYPE_STATIC(LIB, CMGD_BCKND_BATCH, "CMGD backend transaction batch data");
DEFINE_MTYPE_STATIC(LIB, CMGD_BCKND_TRXN, "CMGD backend transaction data");

typedef enum cmgd_bcknd_trxn_event_ {
	CMGD_BCKND_TRXN_PROC_SETCFG = 1,
	CMGD_BCKND_TRXN_PROC_GETCFG,
	CMGD_BCKND_TRXN_PROC_GETDATA
} cmgd_bcknd_trxn_event_t;

typedef struct cmgd_bcknd_set_cfg_req_ {
	struct nb_cfg_change cfg_changes[CMGD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
} cmgd_bcknd_set_cfg_req_t;

typedef struct cmgd_bcknd_get_data_req_ {
	char *xpaths[CMGD_MAX_NUM_DATA_REQ_IN_BATCH];
	uint16_t num_xpaths;
} cmgd_bcknd_get_data_req_t;

typedef struct cmgd_bcknd_trxn_req_ {
	cmgd_bcknd_trxn_event_t event;
	union {
		// cmgd_bcknd_set_cfg_req_t *set_cfg;
		// cmgd_bcknd_get_data_req_t *get_data;
		cmgd_bcknd_set_cfg_req_t set_cfg;
		cmgd_bcknd_get_data_req_t get_data;
	} req;
} cmgd_bcknd_trxn_req_t;

PREDECL_LIST(cmgd_bcknd_batch_list);
typedef struct cmgd_bcknd_batch_ctxt_ {
	/* Batch-Id as assigned by CMGD */
	cmgd_trxn_batch_id_t batch_id;

	cmgd_bcknd_trxn_req_t trxn_req;

	struct cmgd_bcknd_batch_list_item batch_list_linkage;
} cmgd_bcknd_batch_ctxt_t;
DECLARE_LIST(cmgd_bcknd_batch_list, cmgd_bcknd_batch_ctxt_t, batch_list_linkage);

PREDECL_LIST(cmgd_bcknd_trxn_list);
typedef struct cmgd_bcknd_trxn_ctxt_ {
	/* Trxn-Id as assigned by CMGD */
	cmgd_trxn_id_t trxn_id;

	cmgd_bcknd_client_trxn_ctxt_t client_data;

	/* List of batches belonging to this transaction */
	struct cmgd_bcknd_batch_list_head batch_head;
	struct cmgd_bcknd_trxn_list_item trxn_list_linkage;

	struct nb_transaction *nb_trxn;
	uint32_t nb_trxn_id;
} cmgd_bcknd_trxn_ctxt_t;
DECLARE_LIST(cmgd_bcknd_trxn_list, cmgd_bcknd_trxn_ctxt_t, trxn_list_linkage);

#define FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch)		\
	frr_each_safe(cmgd_bcknd_batch_list, &(trxn)->batch_head, (batch))

typedef struct cmgd_bcknd_client_ctxt_ {
	int conn_fd;
	struct thread_master *tm;
	struct thread *conn_retry_tmr;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	struct thread *msg_proc_ev;

	struct stream_fifo *ibuf_fifo;
	struct stream *ibuf_work;
	// struct stream_fifo *obuf_fifo;
	// struct stream *obuf_work;

	struct nb_config *candidate_config;
	struct nb_config *running_config;

	struct cmgd_bcknd_trxn_list_head trxn_head;
	cmgd_bcknd_client_params_t client_params;
} cmgd_bcknd_client_ctxt_t;

#define FOREACH_BCKND_TRXN_IN_LIST(clntctxt, trxn)			\
	frr_each_safe(cmgd_bcknd_trxn_list, &(clntctxt)->trxn_head, (trxn))

// static bool cmgd_debug_bcknd_clnt = false;
static bool cmgd_debug_bcknd_clnt = true;

static cmgd_bcknd_client_ctxt_t cmgd_bcknd_clntctxt = { 0 };

const char *cmgd_bcknd_client_names[CMGD_CLIENT_NAME_MAX_LEN] = {
	CMGD_BCKND_CLIENT_STATICD, 	/* CMGD_BCKND_CLIENT_ID_STATICD */
	CMGD_BCKND_CLIENT_BGPD, 	/* CMGD_BCKND_CLIENT_ID_BGPDD */
	"Unknown/Invalid",		/* CMGD_BCKND_CLIENT_ID_MAX */
};

/* Forward declarations */
static void cmgd_bcknd_client_register_event(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_event_t event);
static void cmgd_bcknd_client_schedule_conn_retry(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs);
static int cmgd_bcknd_client_send_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	Cmgd__BckndMessage *bcknd_msg);

static void cmgd_bcknd_server_disconnect(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, bool reconnect)
{
	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(cmgd_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, false);

	if (clnt_ctxt->conn_fd) {
		close(clnt_ctxt->conn_fd);
		clnt_ctxt->conn_fd = 0;
	}

	// THREAD_OFF(clnt_ctxt->conn_read_ev);
	// THREAD_OFF(clnt_ctxt->conn_retry_tmr);
	// THREAD_OFF(clnt_ctxt->msg_proc_ev);

	if (reconnect)
		cmgd_bcknd_client_schedule_conn_retry(clnt_ctxt,
			clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static cmgd_bcknd_batch_ctxt_t *cmgd_bcknd_find_batch_by_id(
	cmgd_bcknd_trxn_ctxt_t *trxn, cmgd_trxn_batch_id_t batch_id)
{
	cmgd_bcknd_batch_ctxt_t *batch = NULL;

	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch) {
		if (batch->batch_id == batch_id)
			return batch;
	}

	return NULL;
}

static cmgd_bcknd_batch_ctxt_t *cmgd_bcknd_batch_create(
	cmgd_bcknd_trxn_ctxt_t *trxn, cmgd_trxn_batch_id_t batch_id)
{
	cmgd_bcknd_batch_ctxt_t *batch = NULL;

	batch = cmgd_bcknd_find_batch_by_id(trxn, batch_id);
	if (!batch) {
		batch = XCALLOC(MTYPE_CMGD_BCKND_BATCH,
				sizeof(cmgd_bcknd_batch_ctxt_t));
		assert(batch);

		batch->batch_id = batch_id;
		cmgd_bcknd_batch_list_add_tail(&trxn->batch_head, batch);

		CMGD_BCKND_CLNT_DBG("Added new batch 0x%lx to transaction",
				    batch_id);
	}

	return batch;
}

static void cmgd_bcknd_batch_delete(
	cmgd_bcknd_trxn_ctxt_t *trxn, cmgd_bcknd_batch_ctxt_t **batch)
{
	if (!batch)
		return;

	cmgd_bcknd_batch_list_del(&trxn->batch_head, *batch);
	XFREE(MTYPE_CMGD_BCKND_BATCH, *batch);
	*batch = NULL;
}

static void cmgd_bcknd_cleanup_all_batches(cmgd_bcknd_trxn_ctxt_t *trxn)
{
	cmgd_bcknd_batch_ctxt_t *batch = NULL;

	FOREACH_BCKND_TRXN_BATCH_IN_LIST(trxn, batch) {
		cmgd_bcknd_batch_delete(trxn, &batch);
	}
}

static cmgd_bcknd_trxn_ctxt_t *cmgd_bcknd_find_trxn_by_id(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_trxn_id_t trxn_id)
{
	cmgd_bcknd_trxn_ctxt_t *trxn = NULL;

	FOREACH_BCKND_TRXN_IN_LIST(clnt_ctxt, trxn) {
		if (trxn->trxn_id == trxn_id)
			return trxn;
	}

	return NULL;
}

static cmgd_bcknd_trxn_ctxt_t *cmgd_bcknd_trxn_create(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_trxn_id_t trxn_id)
{
	cmgd_bcknd_trxn_ctxt_t *trxn = NULL;

	trxn = cmgd_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		trxn = XCALLOC(MTYPE_CMGD_BCKND_TRXN,
				sizeof(cmgd_bcknd_trxn_ctxt_t));
		assert(trxn);

		trxn->trxn_id = trxn_id;
		cmgd_bcknd_batch_list_init(&trxn->batch_head);
		cmgd_bcknd_trxn_list_add_tail(&clnt_ctxt->trxn_head, trxn);

		CMGD_BCKND_CLNT_DBG("Added new transaction 0x%lx",
				trxn_id);
	}

	return trxn;
}

static void cmgd_bcknd_trxn_delete(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_bcknd_trxn_ctxt_t **trxn)
{
	if (!trxn)
		return;

	cmgd_bcknd_cleanup_all_batches(*trxn);
	cmgd_bcknd_trxn_list_del(&clnt_ctxt->trxn_head, *trxn);
	XFREE(MTYPE_CMGD_BCKND_TRXN, *trxn);
	*trxn = NULL;
}

static void cmgd_bcknd_cleanup_all_trxns(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt)
{
        cmgd_bcknd_trxn_ctxt_t *trxn = NULL;

        FOREACH_BCKND_TRXN_IN_LIST(clnt_ctxt, trxn) {
		cmgd_bcknd_trxn_delete(clnt_ctxt, &trxn);
	}
}

static int cmgd_bcknd_send_trxn_reply(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_trxn_id_t trxn_id, bool create, bool success)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndTrxnReply trxn_reply;

	cmgd__bcknd_trxn_reply__init(&trxn_reply);
	trxn_reply.create = create;
	trxn_reply.trxn_id = trxn_id;
	trxn_reply.success = success;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__TRXN_REPLY;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_TRXN_REPLY;
	bcknd_msg.trxn_reply = &trxn_reply;

	CMGD_BCKND_CLNT_DBG("Sending TRXN_REPLY message to CMGD for trxn 0x%lx",
			    trxn_id);

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int cmgd_bcknd_send_cfgdata_create_failed(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_trxn_id_t trxn_id,
	cmgd_trxn_batch_id_t batch_id, const char *error_if_any)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataCreateFail cfgdata_fail;

	cmgd__bcknd_cfg_data_create_fail__init(&cfgdata_fail);
	cfgdata_fail.trxn_id = (uint64_t) trxn_id;
	cfgdata_fail.batch_id = (uint64_t) batch_id;
	if (error_if_any)
		cfgdata_fail.error_if_any = (char *)error_if_any;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_FAIL;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_DATA_FAIL;
	bcknd_msg.cfg_data_fail = &cfgdata_fail;

	CMGD_BCKND_CLNT_DBG("Sending CFGDATA_CREATE_FAIL message to CMGD for trxn 0x%lx batch 0x%lx",
			    trxn_id, batch_id);

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int cmgd_bcknd_send_validate_reply(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[], 
	size_t num_batch_ids, bool success, const char *error_if_any)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataValidateReply validate_reply;

	cmgd__bcknd_cfg_data_validate_reply__init(&validate_reply);
	validate_reply.success = success;
	validate_reply.trxn_id = trxn_id;
	validate_reply.batch_ids = (uint64_t *) batch_ids;
	validate_reply.n_batch_ids = num_batch_ids;

	if (error_if_any)
		validate_reply.error_if_any = (char *)error_if_any;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REPLY;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REPLY;
	bcknd_msg.cfg_validate_reply = &validate_reply;

	CMGD_BCKND_CLNT_DBG("Sending CFG_VALIDATE_REPLY message to CMGD for trxn 0x%lx %d  batches [0x%lx - 0x%lx]",
			    trxn_id, (int) num_batch_ids, batch_ids[0],
			    batch_ids[num_batch_ids-1]);

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int cmgd_bcknd_update_setcfg_in_batch(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_bcknd_trxn_ctxt_t *trxn, cmgd_trxn_batch_id_t batch_id,
	cmgd_yang_cfgdata_req_t *cfg_req[], int num_req)
{
	cmgd_bcknd_batch_ctxt_t *batch = NULL;
	cmgd_bcknd_trxn_req_t *trxn_req = NULL;
	int index;
	struct nb_cfg_change *cfg_chg;

	batch = cmgd_bcknd_batch_create(trxn, batch_id);
	if (!batch) {
		CMGD_BCKND_CLNT_ERR("Batch create failed!");
		return -1;
	}

	// trxn_req = cmgd_bcknd_trxn_req_alloc(event);
	trxn_req = &batch->trxn_req;
	trxn_req->event = CMGD_BCKND_TRXN_PROC_SETCFG;
	CMGD_BCKND_CLNT_DBG("Created Set-Config request for batch 0x%lx, trxn id 0x%lx",
		batch_id, trxn->trxn_id);

	trxn_req->req.set_cfg.num_cfg_changes = num_req;
	for (index = 0; index < num_req; index++) {
		cfg_chg = &trxn_req->req.set_cfg.cfg_changes[index];

		switch(cfg_req[index]->req_type) {
		case CMGD__CFG_DATA_REQ_TYPE__DELETE_DATA:
			cfg_chg->operation = NB_OP_DESTROY;
			break;
		case CMGD__CFG_DATA_REQ_TYPE__SET_DATA:
		default:
			cfg_chg->operation = NB_OP_CREATE;
			break;
		}

		CMGD_BCKND_CLNT_DBG("XPath: '%s', Value: '%s'",
			cfg_req[index]->data->xpath,
			(cfg_req[index]->data->value &&
			 cfg_req[index]->data->value->encoded_str_val ?
			 cfg_req[index]->data->value->encoded_str_val :
			 "NULL"));
		strlcpy(cfg_chg->xpath, cfg_req[index]->data->xpath,
			sizeof(cfg_chg->xpath));
		cfg_chg->value =
			(cfg_req[index]->data->value &&
			 cfg_req[index]->data->value->encoded_str_val ?
			 strdup(cfg_req[index]->data->value->encoded_str_val) :
			 NULL);
		if (cfg_chg->value && 
			!strncmp(cfg_chg->value, CMGD_BCKND_CONTAINER_NODE_VAL, 
				strlen(CMGD_BCKND_CONTAINER_NODE_VAL))) {
			cfg_chg->value = NULL;
		}
	}

	// cmgd_bcknd_trxn_req_list_add_tail(&batch->trxn_data, trxn_req);
	return 0;
}

static int cmgd_bcknd_process_cfg_validate(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids)
{
	int ret = 0;
	size_t indx;
	cmgd_bcknd_trxn_ctxt_t *trxn;
	cmgd_bcknd_trxn_req_t *trxn_req = NULL;
	cmgd_bcknd_batch_ctxt_t *batch;
	bool error;
	char err_buf[1024];
	struct nb_context nb_ctxt = { 0 };

	trxn = cmgd_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id, batch_ids,
			num_batch_ids, false, "Transaction not created yet!");
		return -1;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		batch = cmgd_bcknd_find_batch_by_id(trxn, batch_ids[indx]);
		if (!batch) {
			cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id, batch_ids,
				num_batch_ids, false, "Batch context not created!");
			return -1;
		}

		if (batch->trxn_req.event != CMGD_BCKND_TRXN_PROC_SETCFG) {
			snprintf(err_buf, sizeof(err_buf),
				"Batch-id 0x%lx not a Config Data Batch!",
				batch_ids[indx]);
			cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id,
				batch_ids, num_batch_ids, false, err_buf);
			return -1;
		}

		trxn_req = &batch->trxn_req;
		error = false;
		nb_candidate_edit_config_changes(clnt_ctxt->candidate_config,
			trxn_req->req.set_cfg.cfg_changes,
			(size_t) trxn_req->req.set_cfg.num_cfg_changes,
			NULL, NULL, 0, err_buf, sizeof(err_buf), &error);
		if (error) {
			err_buf[sizeof(err_buf)-1] = 0;
			CMGD_BCKND_CLNT_ERR("Failed to apply configs for Trxn %lx Batch %lx to Candidate! Err: '%s'",
				trxn_id, batch_ids[indx], err_buf);
			cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id,
				batch_ids, num_batch_ids, false,
				"Failed to update Candidate Db on backend!");
			return -1;
		}
	}

	nb_ctxt.client = NB_CLIENT_CLI;
	nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;
	if (nb_candidate_commit_prepare(&nb_ctxt,
		clnt_ctxt->candidate_config, "CMGD Trxn",
		&trxn->nb_trxn, err_buf,
		sizeof(err_buf)-1) != NB_OK) {
		err_buf[sizeof(err_buf)-1] = 0;
		CMGD_BCKND_CLNT_ERR("Failed to validate configs for Trxn %lx Batch %lx! Err: '%s'",
			trxn_id, batch_ids[indx], err_buf);
		cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id,
			batch_ids, num_batch_ids, false,
			"Failed to validate Config on backend!");
		return -1;
	}

	if (ret == 0) {
		cmgd_bcknd_send_validate_reply(clnt_ctxt, trxn_id, batch_ids,
			num_batch_ids, true, NULL);
	}

	return ret;
}

static int cmgd_bcknd_send_apply_reply(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[], 
	size_t num_batch_ids, bool success, const char *error_if_any)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataApplyReply apply_reply;

	cmgd__bcknd_cfg_data_apply_reply__init(&apply_reply);
	apply_reply.success = success;
	apply_reply.trxn_id = trxn_id;
	apply_reply.batch_ids = (uint64_t *) batch_ids;
	apply_reply.n_batch_ids = num_batch_ids;

	if (error_if_any)
		apply_reply.error_if_any = (char *)error_if_any;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REPLY;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REPLY;
	bcknd_msg.cfg_apply_reply = &apply_reply;

	CMGD_BCKND_CLNT_DBG("Sending CFG_APPLY_REPLY message to CMGD for trxn 0x%lx %d  batches [0x%lx - 0x%lx]",
			    trxn_id, (int) num_batch_ids, batch_ids[0],
			    batch_ids[num_batch_ids-1]);

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int cmgd_bcknd_process_cfg_apply(cmgd_bcknd_client_ctxt_t *clnt_ctxt,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids)
{
	size_t indx;
	cmgd_bcknd_trxn_ctxt_t *trxn;
	cmgd_bcknd_trxn_req_t *trxn_req = NULL;
	cmgd_bcknd_batch_ctxt_t *batch;
	bool error;
	char err_buf[1024];
	struct nb_context nb_ctxt = { 0 };

	trxn = cmgd_bcknd_find_trxn_by_id(clnt_ctxt, trxn_id);
	if (!trxn) {
		cmgd_bcknd_send_apply_reply(clnt_ctxt, trxn_id, batch_ids,
			num_batch_ids, false, "Transaction not created yet!");
		return -1;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		batch = cmgd_bcknd_find_batch_by_id(trxn, batch_ids[indx]);
		if (!batch) {
			cmgd_bcknd_send_apply_reply(clnt_ctxt, trxn_id, batch_ids,
				num_batch_ids, false, "Batch context not created!");
			return -1;
		}

		trxn_req = &batch->trxn_req;
		error = false;
		nb_ctxt.client = NB_CLIENT_CLI;
		nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;

		if (!trxn->nb_trxn) {
			/*
			 * This happens when the current backend client is only interested
			 * in consuming the config items but is not interested in validating 
			 * it.
			 */
			error = false;
			nb_candidate_edit_config_changes(
				clnt_ctxt->candidate_config,
				trxn_req->req.set_cfg.cfg_changes,
				(size_t) trxn_req->req.set_cfg.num_cfg_changes,
				NULL, NULL, 0, err_buf, sizeof(err_buf),
				&error);
			if (error) {
				err_buf[sizeof(err_buf)-1] = 0;
				CMGD_BCKND_CLNT_ERR("Failed to update configs for Trxn %lx Batch %lx to Candidate! Err: '%s'",
					trxn_id, batch_ids[indx], err_buf);
				cmgd_bcknd_send_apply_reply(clnt_ctxt, trxn_id,
					batch_ids, num_batch_ids, false,
					"Failed to update Candidate Db on backend!");
				return -1;
			}
		}

		/*
		 * No need to delete the batch yet. Will be deleted during transaction
		 * cleanup on receiving TRXN_DELETE_REQ.
		 */
	}

#if 0
	if (!trxn->nb_trxn) {
		/*
		 * This happens when the current backend client is only interested
		 * in consuming the config items but is not interested in validating 
		 * it.
		 */
		nb_ctxt.client = NB_CLIENT_CLI;
		nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;
		if (nb_candidate_commit_prepare(&nb_ctxt,
			clnt_ctxt->candidate_config, "CMGD Trxn",
			&trxn->nb_trxn, err_buf, sizeof(err_buf)-1) != NB_OK) {
			err_buf[sizeof(err_buf)-1] = 0;
			CMGD_BCKND_CLNT_ERR("Failed to prepare configs for Trxn %lx Batch %lx! Err: '%s'",
				trxn_id, batch_ids[indx], err_buf);
			cmgd_bcknd_send_apply_reply(clnt_ctxt, trxn_id,
				batch_ids, num_batch_ids, false,
				"Failed to validate Config on backend!");
			return -1;
		}
	}

	nb_candidate_commit_apply(trxn->nb_trxn, true,
		&trxn->nb_trxn_id, err_buf, sizeof(err_buf)-1);
#else
	nb_ctxt.client = NB_CLIENT_CLI;
	nb_ctxt.user = (void *)clnt_ctxt->client_params.user_data;
	(void) nb_candidate_apply(&nb_ctxt, clnt_ctxt->candidate_config,
			trxn->nb_trxn, "CMGD Backend Trxn",
			true, &trxn->nb_trxn_id, err_buf, sizeof(err_buf)-1);
#endif
	trxn->nb_trxn = NULL;

	cmgd_bcknd_send_apply_reply(clnt_ctxt, trxn_id, batch_ids,
		num_batch_ids, true, NULL);

        return 0;
}

static int cmgd_bcknd_client_handle_msg(
        cmgd_bcknd_client_ctxt_t *clnt_ctxt, Cmgd__BckndMessage *bcknd_msg)
{
	cmgd_bcknd_trxn_ctxt_t *trxn = NULL;

        switch(bcknd_msg->type) {
        case CMGD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REPLY:
                assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_SUBSCR_REPLY);
                CMGD_BCKND_CLNT_DBG(
                        "Subscribe Reply Msg from cmgd, status %u",
                        bcknd_msg->subscr_reply->success);
		//Need to add handle code
                break;
	case CMGD__BCKND_MESSAGE__TYPE__TRXN_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_TRXN_REQ);
		if (bcknd_msg->trxn_req->create) {
			CMGD_BCKND_CLNT_DBG("Created new transaction 0x%llx",
					bcknd_msg->trxn_req->trxn_id);
			trxn = cmgd_bcknd_trxn_create(clnt_ctxt,
					bcknd_msg->trxn_req->trxn_id);
		} else {
			CMGD_BCKND_CLNT_DBG("Delete transaction 0x%llx",
					bcknd_msg->trxn_req->trxn_id);
			trxn = cmgd_bcknd_find_trxn_by_id(clnt_ctxt,
					bcknd_msg->trxn_req->trxn_id);
		}

		// Delete client_data as part of this callback
		if (trxn && clnt_ctxt->client_params.trxn_notify_cb)
			(void) (*clnt_ctxt->client_params.trxn_notify_cb)(
					(cmgd_lib_hndl_t)clnt_ctxt,
					clnt_ctxt->client_params.user_data,
					&trxn->client_data,
					!bcknd_msg->trxn_req->create);

		if (trxn && !bcknd_msg->trxn_req->create) {
			/*
			 * Time to delete the transaction which should also
			 * take care of cleaning up all batches created via
			 * CFGDATA_CREATE_REQs.
			 */
			cmgd_bcknd_trxn_delete(clnt_ctxt, &trxn);
		}

		cmgd_bcknd_send_trxn_reply(clnt_ctxt, bcknd_msg->trxn_req->trxn_id,
					   bcknd_msg->trxn_req->create,
					   true);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_DATA_REQ);
		trxn = cmgd_bcknd_find_trxn_by_id(clnt_ctxt,
				bcknd_msg->cfg_data_req->trxn_id);
		if (!trxn)
			cmgd_bcknd_send_cfgdata_create_failed(clnt_ctxt,
					bcknd_msg->cfg_data_req->trxn_id,
					bcknd_msg->cfg_data_req->batch_id,
					"Transaction context not created yet");

		cmgd_bcknd_update_setcfg_in_batch(clnt_ctxt, trxn,
				bcknd_msg->cfg_data_req->batch_id,
				bcknd_msg->cfg_data_req->data_req,
				bcknd_msg->cfg_data_req->n_data_req);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REQ);
		cmgd_bcknd_process_cfg_validate(clnt_ctxt,
			(cmgd_trxn_id_t) bcknd_msg->cfg_validate_req->trxn_id,
			(cmgd_trxn_batch_id_t *)
				bcknd_msg->cfg_validate_req->batch_ids,
			bcknd_msg->cfg_validate_req->n_batch_ids);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REQ);
		cmgd_bcknd_process_cfg_apply(clnt_ctxt,
			(cmgd_trxn_id_t) bcknd_msg->cfg_apply_req->trxn_id,
			(cmgd_trxn_batch_id_t *)
				bcknd_msg->cfg_apply_req->batch_ids,
			bcknd_msg->cfg_apply_req->n_batch_ids);
		break;
        default:
                break;
        }

        return 0;
}

static int cmgd_bcknd_client_process_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	uint8_t *msg_buf, int bytes_read)
{
	Cmgd__BckndMessage *bcknd_msg;
	cmgd_bcknd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	CMGD_BCKND_CLNT_DBG(
		"Got message of %d bytes from CMGD Backend Server", bytes_read);

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_bcknd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_BCKND_MSG_MARKER) {
			CMGD_BCKND_CLNT_DBG(
				"Marker not found in message from CMGD '%s'",
				clnt_ctxt->client_params.name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_BCKND_CLNT_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD '%s'",
				bytes_left, msg->hdr.len, clnt_ctxt->client_params.name);
			break;
		}

		bcknd_msg = cmgd__bcknd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_BCKND_MSG_HDR_LEN),
			msg->payload);
		if (!bcknd_msg) {
			CMGD_BCKND_CLNT_DBG(
				"Failed to decode %d bytes from CMGD '%s'",
				msg->hdr.len, clnt_ctxt->client_params.name);
			continue;
		}

		(void) cmgd_bcknd_client_handle_msg(clnt_ctxt, bcknd_msg);
		cmgd__bcknd_message__free_unpacked(bcknd_msg, NULL);
		processed++;
	}

	return processed;
}

static int cmgd_bcknd_client_proc_msgbufs(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;
	struct stream *work;
	int processed = 0;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	for ( ; processed < CMGD_BCKND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(clnt_ctxt->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_bcknd_client_process_msg(
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
		cmgd_bcknd_client_register_event(
			clnt_ctxt, CMGD_BCKND_PROC_MSG);
	
	return 0;
}

static int cmgd_bcknd_client_read(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_bcknd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(clnt_ctxt->ibuf_work) - 
		stream_get_endp(clnt_ctxt->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				clnt_ctxt->ibuf_work, clnt_ctxt->conn_fd, bytes_left);
		CMGD_BCKND_CLNT_DBG(
			"Got %d bytes of message from CMGD Backend server", 
			bytes_read);
		if (bytes_read <= 0) {
			if (!total_bytes) {
				/* Looks like connection closed */
				CMGD_BCKND_CLNT_ERR(
					"Got error (%d) while reading from CMGD Backend server. Err: '%s'", 
					bytes_read, safe_strerror(errno));
				cmgd_bcknd_server_disconnect(clnt_ctxt, true);
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
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_bcknd_msg_hdr_t *)
			(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_BCKND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			cmgd_bcknd_server_disconnect(clnt_ctxt, true);
			return -1;
		}
		if (msg_hdr->len > bytes_left) {
			/* 
			 * Incomplete message. Terminate the current buffer
			 * and add it to process fifo. And then copy the rest
			 * to a new Ibuf 
			 */
			incomplete = true;
			stream_set_endp(clnt_ctxt->ibuf_work, total_bytes);
			stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);

			clnt_ctxt->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
			stream_put(clnt_ctxt->ibuf_work, msg_hdr, bytes_left);
			stream_set_endp(clnt_ctxt->ibuf_work, bytes_left);
			break;
		}

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	/* 
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	if (!incomplete)
		stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);
	if (msg_cnt)
		cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_PROC_MSG);

	cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_CONN_READ);

	return 0;
}

static int cmgd_bcknd_client_write(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	return 0;
}

static int cmgd_bcknd_client_send_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	Cmgd__BckndMessage *bcknd_msg)
{
	int bytes_written;
	size_t msg_size;
	uint8_t msg_buf[CMGD_BCKND_MSG_MAX_LEN];
	cmgd_bcknd_msg_t *msg;

	if (clnt_ctxt->conn_fd == 0)
		return -1;

	msg_size = cmgd__bcknd_message__get_packed_size(bcknd_msg);
	msg_size += CMGD_BCKND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_BCKND_CLNT_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_bcknd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_BCKND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__bcknd_message__pack(bcknd_msg, msg->payload);

	bytes_written = write(clnt_ctxt->conn_fd, (void *)msg_buf, msg_size);
	if (bytes_written != (int) msg_size) {
		CMGD_BCKND_CLNT_ERR(
			"Could not write all %d bytes (wrote: %d) to CMGD Backend server socket. Err: '%s'", 
			(int) msg_size, bytes_written, safe_strerror(errno));
		cmgd_bcknd_server_disconnect(clnt_ctxt, true);
		return -1;
	}

	CMGD_BCKND_CLNT_DBG(
		"Wrote %d bytes of message to CMGD Backend server socket.'", 
		bytes_written);
	return 0;
}

static int cmgd_bcknd_send_subscr_req(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	bool subscr_xpaths, uint16_t num_reg_xpaths, char **reg_xpaths)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndSubscribeReq subscr_req;

	cmgd__bcknd_subscribe_req__init(&subscr_req);
	subscr_req.client_name = clnt_ctxt->client_params.name;
	subscr_req.n_xpath_reg = num_reg_xpaths;
	if (num_reg_xpaths)
		subscr_req.xpath_reg = reg_xpaths;
	else
		subscr_req.xpath_reg = NULL;
	subscr_req.subscribe_xpaths = subscr_xpaths;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_SUBSCR_REQ;
	bcknd_msg.subscr_req = &subscr_req;

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
}

static int cmgd_bcknd_server_connect(cmgd_bcknd_client_ctxt_t *clnt_ctxt)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	CMGD_BCKND_CLNT_DBG("Trying to connect to CMGD Backend server at %s",
		CMGD_BCKND_SERVER_PATH);

	assert(!clnt_ctxt->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		CMGD_BCKND_CLNT_ERR("Failed to create socket");
		goto cmgd_bcknd_server_connect_failed;
	}

	CMGD_BCKND_CLNT_DBG("Created CMGD Backend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, CMGD_BCKND_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		CMGD_BCKND_CLNT_ERR(
			"Failed to connect to CMGD Backend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto cmgd_bcknd_server_connect_failed;
	}

	CMGD_BCKND_CLNT_DBG("Connected to CMGD Backend Server at %s successfully!",
		addr.sun_path);
	clnt_ctxt->conn_fd = sock;

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);

	cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_CONN_READ);

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(cmgd_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, true);

	/* Send SUBSCRIBE_REQ message */
	if (cmgd_bcknd_send_subscr_req(clnt_ctxt, false, 0, NULL) != 0)
		goto cmgd_bcknd_server_connect_failed;

	return 0;

cmgd_bcknd_server_connect_failed:
	if (sock && sock != clnt_ctxt->conn_fd) {
		close(sock);
	}
	cmgd_bcknd_server_disconnect(clnt_ctxt, true);
	return -1;
}

static int cmgd_bcknd_client_conn_timeout(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	clnt_ctxt->conn_retry_tmr = NULL;
	return cmgd_bcknd_server_connect(clnt_ctxt);
}

static void cmgd_bcknd_client_register_event(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_event_t event)
{
	switch (event) {
	case CMGD_BCKND_CONN_READ:
		clnt_ctxt->conn_read_ev = 
			thread_add_read(clnt_ctxt->tm,
				cmgd_bcknd_client_read, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_BCKND_CONN_WRITE:
		clnt_ctxt->conn_write_ev = 
			thread_add_write(clnt_ctxt->tm,
				cmgd_bcknd_client_write, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_BCKND_PROC_MSG:
		clnt_ctxt->msg_proc_ev = 
			thread_add_timer_msec(clnt_ctxt->tm,
				cmgd_bcknd_client_proc_msgbufs, clnt_ctxt,
				CMGD_BCKND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_bcknd_clnt_ctxt_post_event() called incorrectly");
	}
}

static void cmgd_bcknd_client_schedule_conn_retry(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs)
{
	CMGD_BCKND_CLNT_DBG("Scheduling CMGD Backend server connection retry after %lu seconds",
		intvl_secs);
	clnt_ctxt->conn_retry_tmr = thread_add_timer(
		clnt_ctxt->tm, cmgd_bcknd_client_conn_timeout,
		(void *)clnt_ctxt, intvl_secs, NULL);
}

extern struct nb_config *running_config;

/*
 * Initialize library and try connecting with CMGD.
 */
cmgd_lib_hndl_t cmgd_bcknd_client_lib_init(
	cmgd_bcknd_client_params_t *params, 
	struct thread_master *master_thread)
{
	assert(master_thread && params && 
		strlen(params->name) && !cmgd_bcknd_clntctxt.tm);

	cmgd_bcknd_clntctxt.tm = master_thread;

	if (!running_config)
		assert(!"Call cmgd_bcknd_client_lib_init() after frr_init() only!");
	cmgd_bcknd_clntctxt.running_config = running_config;
	cmgd_bcknd_clntctxt.candidate_config = nb_config_new(NULL);

	memcpy(&cmgd_bcknd_clntctxt.client_params, params, 
		sizeof(cmgd_bcknd_clntctxt.client_params));
	if (!cmgd_bcknd_clntctxt.client_params.conn_retry_intvl_sec) 
		cmgd_bcknd_clntctxt.client_params.conn_retry_intvl_sec = 
			CMGD_BCKND_DEFAULT_CONN_RETRY_INTVL_SEC;

	assert(!cmgd_bcknd_clntctxt.ibuf_fifo &&
		!cmgd_bcknd_clntctxt.ibuf_work/* &&
		!cmgd_bcknd_clntctxt.obuf_fifo &&
		!cmgd_bcknd_clntctxt.obuf_work*/);

	cmgd_bcknd_trxn_list_init(&cmgd_bcknd_clntctxt.trxn_head);
	cmgd_bcknd_clntctxt.ibuf_fifo = stream_fifo_new();
	cmgd_bcknd_clntctxt.ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
	// cmgd_bcknd_clntctxt.obuf_fifo = stream_fifo_new();
	// cmgd_bcknd_clntctxt.obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);

	/* Start trying to connect to CMGD backend server immediately */
	cmgd_bcknd_client_schedule_conn_retry(&cmgd_bcknd_clntctxt, 1);

	CMGD_BCKND_CLNT_DBG("Initialized client '%s'", params->name);

	return (cmgd_lib_hndl_t)&cmgd_bcknd_clntctxt;
}

/*
 * Subscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_subscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt) {
		return CMGD_INVALID_PARAM;
	}

	if (cmgd_bcknd_send_subscr_req(
		clnt_ctxt, true, num_reg_xpaths, reg_yang_xpaths) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Unsubscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_unsubscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;


	if (cmgd_bcknd_send_subscr_req(
		clnt_ctxt, false, num_reg_xpaths, reg_yang_xpaths) < 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send one or more YANG notifications to CMGD daemon.
 */
cmgd_result_t cmgd_bcknd_send_yang_notify(
	cmgd_lib_hndl_t lib_hndl, cmgd_yang_data_t *data_elems[],
	int num_elems)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	return CMGD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void cmgd_bcknd_client_lib_destroy(cmgd_lib_hndl_t lib_hndl)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	assert(clnt_ctxt);

	CMGD_BCKND_CLNT_DBG("Destroying CMGD Backend Client '%s'", 
		clnt_ctxt->client_params.name);

	cmgd_bcknd_server_disconnect(clnt_ctxt, false);

	assert(cmgd_bcknd_clntctxt.ibuf_fifo &&
		cmgd_bcknd_clntctxt.ibuf_work/* &&
		cmgd_bcknd_clntctxt.obuf_fifo &&
		cmgd_bcknd_clntctxt.obuf_work*/);
	
	stream_fifo_free(cmgd_bcknd_clntctxt.ibuf_fifo);
	stream_free(cmgd_bcknd_clntctxt.ibuf_work);
	// stream_fifo_free(cmgd_bcknd_clntctxt.obuf_fifo);
	// stream_free(cmgd_bcknd_clntctxt.obuf_work);

	cmgd_bcknd_cleanup_all_trxns(clnt_ctxt);
	cmgd_bcknd_trxn_list_fini(&clnt_ctxt->trxn_head);
}
