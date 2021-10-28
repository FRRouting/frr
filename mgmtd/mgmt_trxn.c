/*
 * MGMTD Transactions
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

#include <zebra.h>
#include "hash.h"
#include "jhash.h"
#include "libfrr.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_trxn.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_TRXN_DBG(fmt, ...)                                               \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_TRXN_ERR(fmt, ...)                                               \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_TRXN_DBG(fmt, ...)                                               \
	do {                                                                   \
		if (mgmt_debug_trxn)                                           \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_TRXN_ERR(fmt, ...)                                               \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define MGMTD_TRXN_LOCK(trxn) mgmt_trxn_lock(trxn, __FILE__, __LINE__)
#define MGMTD_TRXN_UNLOCK(trxn) mgmt_trxn_unlock(trxn, __FILE__, __LINE__)

enum mgmt_trxn_event {
	MGMTD_TRXN_PROC_SETCFG = 1,
	MGMTD_TRXN_PROC_COMMITCFG,
	MGMTD_TRXN_PROC_GETCFG,
	MGMTD_TRXN_PROC_GETDATA,
	MGMTD_TRXN_COMMITCFG_TIMEOUT,
	MGMTD_TRXN_CLEANUP
};

PREDECL_LIST(mgmt_trxn_req_list);

struct mgmt_set_cfg_req {
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctxt *db_ctxt;
	struct nb_cfg_change cfg_changes[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	uint16_t num_cfg_changes;
	bool implicit_commit;
	Mgmtd__DatabaseId dst_db_id;
	struct mgmt_db_ctxt *dst_db_ctxt;
	struct mgmt_setcfg_stats *setcfg_stats;
};

enum mgmt_commit_phase {
	MGMTD_COMMIT_PHASE_PREPARE_CFG = 0,
	MGMTD_COMMIT_PHASE_TRXN_CREATE,
	MGMTD_COMMIT_PHASE_SEND_CFG,
#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
	MGMTD_COMMIT_PHASE_VALIDATE_CFG,
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
	MGMTD_COMMIT_PHASE_APPLY_CFG,
	MGMTD_COMMIT_PHASE_TRXN_DELETE,
	MGMTD_COMMIT_PHASE_MAX
};

static inline const char *
mgmt_commit_phase2str(enum mgmt_commit_phase cmt_phase)
{
	switch (cmt_phase) {
	case MGMTD_COMMIT_PHASE_PREPARE_CFG:
		return "PREP-CFG";
	case MGMTD_COMMIT_PHASE_TRXN_CREATE:
		return "CREATE-TRXN";
	case MGMTD_COMMIT_PHASE_SEND_CFG:
		return "SEND-CFG";
#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
	case MGMTD_COMMIT_PHASE_VALIDATE_CFG:
		return "VALIDATE-CFG";
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		return "APPLY-CFG";
	case MGMTD_COMMIT_PHASE_TRXN_DELETE:
		return "DELETE-TRXN";
	case MGMTD_COMMIT_PHASE_MAX:
		return "Invalid/Unknown";
	}

	return "Invalid/Unknown";
}

PREDECL_LIST(mgmt_trxn_batch_list);

struct mgmt_trxn_bcknd_cfg_batch {
	struct mgmt_trxn_ctxt *trxn;
	uint64_t batch_id;
	enum mgmt_bcknd_client_id bcknd_id;
	struct mgmt_bcknd_client_adapter *bcknd_adptr;
	union mgmt_bcknd_xpath_subscr_info
		xp_subscr[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangCfgDataReq cfg_data[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangCfgDataReq * cfg_datap[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangData data[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	Mgmtd__YangDataValue value[MGMTD_MAX_CFG_CHANGES_IN_BATCH];
	size_t num_cfg_data;
	int buf_space_left;
	enum mgmt_commit_phase comm_phase;
	struct mgmt_trxn_batch_list_item list_linkage;
};

DECLARE_LIST(mgmt_trxn_batch_list, struct mgmt_trxn_bcknd_cfg_batch,
	     list_linkage);

#define FOREACH_TRXN_CFG_BATCH_IN_LIST(list, batch)                            \
	frr_each_safe(mgmt_trxn_batch_list, list, batch)

struct mgmt_commit_cfg_req {
	Mgmtd__DatabaseId src_db_id;
	struct mgmt_db_ctxt *src_db_ctxt;
	Mgmtd__DatabaseId dst_db_id;
	struct mgmt_db_ctxt *dst_db_ctxt;
	uint32_t nb_trxn_id;
	uint8_t validate_only : 1;
	uint8_t abort : 1;
	uint8_t implicit : 1;
	uint8_t rollback : 1;

	/* Track commit phases */
	enum mgmt_commit_phase curr_phase;
	enum mgmt_commit_phase next_phase;

	/*
	 * Set of config changes to commit. This is used only
	 * when changes are NOT to be determined by comparing
	 * candidate and running DBs. This is typically used
	 * for downloading all relevant configs for a new backend
	 * client that has recently come up and connected with
	 * MGMTD.
	 */
	struct nb_config_cbs *cfg_chgs;

	/*
	 * Details on all the Backend Clients associated with
	 * this commit.
	 */
	struct mgmt_bcknd_client_subscr_info subscr_info;

	/*
	 * List of backend batches for this commit to be validated
	 * and applied at the backend.
	 *
	 * FIXME: Need to re-think this design for the case set of
	 * validators for a given YANG data item is different from
	 * the set of notifiers for the same. We may need to have
	 * separate list of batches for VALIDATE and APPLY.
	 */
	struct mgmt_trxn_batch_list_head
		curr_batches[MGMTD_BCKND_CLIENT_ID_MAX];
	struct mgmt_trxn_batch_list_head
		next_batches[MGMTD_BCKND_CLIENT_ID_MAX];
	/*
	 * The last batch added for any backend client. This is always on
	 * 'curr_batches'
	 */
	struct mgmt_trxn_bcknd_cfg_batch
		*last_bcknd_cfg_batch[MGMTD_BCKND_CLIENT_ID_MAX];
	struct hash *batches;
	uint64_t next_batch_id;

	struct mgmt_commit_stats *cmt_stats;
};

struct mgmt_get_data_reply {
	/* Buffer space for preparing data reply */
	int num_reply;
	int last_batch;
	Mgmtd__YangDataReply data_reply;
	Mgmtd__YangData reply_data[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	Mgmtd__YangData * reply_datap[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	Mgmtd__YangDataValue reply_value[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
	char *reply_xpathp[MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH];
};

struct mgmt_get_data_req {
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctxt *db_ctxt;
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

struct mgmt_trxn_req {
	struct mgmt_trxn_ctxt *trxn;
	enum mgmt_trxn_event req_event;
	uint64_t req_id;
	union {
		struct mgmt_set_cfg_req *set_cfg;
		struct mgmt_get_data_req *get_data;
		struct mgmt_commit_cfg_req commit_cfg;
	} req;

	bool pending_bknd_proc;
	struct mgmt_trxn_req_list_item list_linkage;
};

DECLARE_LIST(mgmt_trxn_req_list, struct mgmt_trxn_req, list_linkage);

#define FOREACH_TRXN_REQ_IN_LIST(list, req)                                    \
	frr_each_safe(mgmt_trxn_req_list, list, req)

struct mgmt_trxn_ctxt {
	uint64_t session_id; /* One transaction per client session */
	uint64_t trxn_id;
	enum mgmt_trxn_type type;

	/* struct mgmt_master *mm; */

	struct thread *proc_set_cfg;
	struct thread *proc_comm_cfg;
	struct thread *proc_get_cfg;
	struct thread *proc_get_data;
	struct thread *comm_cfg_timeout;
	struct thread *clnup;

	/* List of backend adapters involved in this transaction */
	struct mgmt_trxn_badptr_list_head bcknd_adptrs;

	int refcount;

	struct mgmt_trxn_list_item list_linkage;

	/*
	 * List of pending set-config requests for a given
	 * transaction/session. Just one list for requests
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct mgmt_trxn_req_list_head set_cfg_reqs;
	/*
	 * List of pending get-config requests for a given
	 * transaction/session. Just one list for requests
	 * not processed at all. There's no backend interaction
	 * involved.
	 */
	struct mgmt_trxn_req_list_head get_cfg_reqs;
	/*
	 * List of pending get-data requests for a given
	 * transaction/session Two lists, one for requests
	 * not processed at all, and one for requests that
	 * has been sent to backend for processing.
	 */
	struct mgmt_trxn_req_list_head get_data_reqs;
	struct mgmt_trxn_req_list_head pending_get_datas;
	/*
	 * There will always be one commit-config allowed for a given
	 * transaction/session. No need to maintain lists for it.
	 */
	struct mgmt_trxn_req *commit_cfg_req;
};

DECLARE_LIST(mgmt_trxn_list, struct mgmt_trxn_ctxt, list_linkage);

#define FOREACH_TRXN_IN_LIST(mm, trxn)                                         \
	frr_each_safe(mgmt_trxn_list, &(mm)->trxn_list, (trxn))

static int mgmt_trxn_send_commit_cfg_reply(struct mgmt_trxn_ctxt *trxn,
					   enum mgmt_result result,
					   const char *error_if_any);

static inline const char *
mgmt_trxn_commit_phase_str(struct mgmt_trxn_ctxt *trxn, bool curr)
{
	if (!trxn->commit_cfg_req)
		return "None";

	return (mgmt_commit_phase2str(
		curr ? trxn->commit_cfg_req->req.commit_cfg.curr_phase
		     : trxn->commit_cfg_req->req.commit_cfg.next_phase));
}

static void mgmt_trxn_lock(struct mgmt_trxn_ctxt *trxn, const char *file,
			   int line);
static void mgmt_trxn_unlock(struct mgmt_trxn_ctxt **trxn, const char *file,
			     int line);
static int
mgmt_trxn_send_bcknd_trxn_delete(struct mgmt_trxn_ctxt *trxn,
				 struct mgmt_bcknd_client_adapter *adptr);

static struct thread_master *mgmt_trxn_tm;
static struct mgmt_master *mgmt_trxn_mm;

static void mgmt_trxn_register_event(struct mgmt_trxn_ctxt *trxn,
				     enum mgmt_trxn_event event);

static int
mgmt_move_bcknd_commit_to_next_phase(struct mgmt_trxn_ctxt *trxn,
				     struct mgmt_bcknd_client_adapter *adptr);

static struct mgmt_trxn_bcknd_cfg_batch *
mgmt_trxn_cfg_batch_alloc(struct mgmt_trxn_ctxt *trxn,
			  enum mgmt_bcknd_client_id id,
			  struct mgmt_bcknd_client_adapter *bcknd_adptr)
{
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	cfg_btch = XCALLOC(MTYPE_MGMTD_TRXN_CFG_BATCH,
			   sizeof(struct mgmt_trxn_bcknd_cfg_batch));
	assert(cfg_btch);
	cfg_btch->bcknd_id = id;

	cfg_btch->trxn = trxn;
	MGMTD_TRXN_LOCK(trxn);
	assert(trxn->commit_cfg_req);
	mgmt_trxn_batch_list_add_tail(
		&trxn->commit_cfg_req->req.commit_cfg.curr_batches[id],
		cfg_btch);
	cfg_btch->bcknd_adptr = bcknd_adptr;
	cfg_btch->buf_space_left = MGMTD_BCKND_CFGDATA_MAX_MSG_LEN;
	if (bcknd_adptr)
		mgmt_bcknd_adapter_lock(bcknd_adptr);

	trxn->commit_cfg_req->req.commit_cfg.last_bcknd_cfg_batch[id] =
		cfg_btch;
	if (!trxn->commit_cfg_req->req.commit_cfg.next_batch_id)
		trxn->commit_cfg_req->req.commit_cfg.next_batch_id++;
	cfg_btch->batch_id =
		trxn->commit_cfg_req->req.commit_cfg.next_batch_id++;
	hash_get(trxn->commit_cfg_req->req.commit_cfg.batches, cfg_btch,
		 hash_alloc_intern);

	return cfg_btch;
}

static void
mgmt_trxn_cfg_batch_free(struct mgmt_trxn_bcknd_cfg_batch **cfg_btch)
{
	size_t indx;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	MGMTD_TRXN_DBG(" Batch: %p, Trxn: %p", *cfg_btch, (*cfg_btch)->trxn);

	assert((*cfg_btch)->trxn
	       && (*cfg_btch)->trxn->type == MGMTD_TRXN_TYPE_CONFIG);

	cmtcfg_req = &(*cfg_btch)->trxn->commit_cfg_req->req.commit_cfg;
	hash_release(cmtcfg_req->batches, *cfg_btch);
	mgmt_trxn_batch_list_del(
		&cmtcfg_req->curr_batches[(*cfg_btch)->bcknd_id], *cfg_btch);
	mgmt_trxn_batch_list_del(
		&cmtcfg_req->next_batches[(*cfg_btch)->bcknd_id], *cfg_btch);

	if ((*cfg_btch)->bcknd_adptr)
		mgmt_bcknd_adapter_unlock(&(*cfg_btch)->bcknd_adptr);

	for (indx = 0; indx < (*cfg_btch)->num_cfg_data; indx++) {
		if ((*cfg_btch)->data[indx].xpath) {
			free((*cfg_btch)->data[indx].xpath);
			(*cfg_btch)->data[indx].xpath = NULL;
		}
	}

	MGMTD_TRXN_UNLOCK(&(*cfg_btch)->trxn);

	XFREE(MTYPE_MGMTD_TRXN_CFG_BATCH, *cfg_btch);
	*cfg_btch = NULL;
}

static unsigned int mgmt_trxn_cfgbatch_hash_key(const void *data)
{
	const struct mgmt_trxn_bcknd_cfg_batch *batch = data;

	return jhash2((uint32_t *) &batch->batch_id,
		      sizeof(batch->batch_id) / sizeof(uint32_t), 0);
}

static bool mgmt_trxn_cfgbatch_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_trxn_bcknd_cfg_batch *batch1 = d1;
	const struct mgmt_trxn_bcknd_cfg_batch *batch2 = d2;

	return (batch1->batch_id == batch2->batch_id);
}

static void mgmt_trxn_cfgbatch_hash_free(void *data)
{
	struct mgmt_trxn_bcknd_cfg_batch *batch = data;

	mgmt_trxn_cfg_batch_free(&batch);
}

static inline struct mgmt_trxn_bcknd_cfg_batch *
mgmt_trxn_cfgbatch_id2ctxt(struct mgmt_trxn_ctxt *trxn, uint64_t batch_id)
{
	struct mgmt_trxn_bcknd_cfg_batch key = {0};
	struct mgmt_trxn_bcknd_cfg_batch *batch;

	if (!trxn->commit_cfg_req)
		return NULL;

	key.batch_id = batch_id;
	batch = hash_lookup(trxn->commit_cfg_req->req.commit_cfg.batches,
			    &key);

	return batch;
}

static void mgmt_trxn_cleanup_bcknd_cfg_batches(struct mgmt_trxn_ctxt *trxn,
						enum mgmt_bcknd_client_id id)
{
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_trxn_batch_list_head *list;

	list = &trxn->commit_cfg_req->req.commit_cfg.curr_batches[id];
	FOREACH_TRXN_CFG_BATCH_IN_LIST (list, cfg_btch)
		mgmt_trxn_cfg_batch_free(&cfg_btch);

	mgmt_trxn_batch_list_fini(list);

	list = &trxn->commit_cfg_req->req.commit_cfg.next_batches[id];
	FOREACH_TRXN_CFG_BATCH_IN_LIST (list, cfg_btch)
		mgmt_trxn_cfg_batch_free(&cfg_btch);

	mgmt_trxn_batch_list_fini(list);

	trxn->commit_cfg_req->req.commit_cfg.last_bcknd_cfg_batch[id] = NULL;
}

static struct mgmt_trxn_req *mgmt_trxn_req_alloc(struct mgmt_trxn_ctxt *trxn,
						 uint64_t req_id,
						 enum mgmt_trxn_event req_event)
{
	struct mgmt_trxn_req *trxn_req;
	enum mgmt_bcknd_client_id id;

	trxn_req = XCALLOC(MTYPE_MGMTD_TRXN_REQ, sizeof(struct mgmt_trxn_req));
	assert(trxn_req);
	trxn_req->trxn = trxn;
	trxn_req->req_id = req_id;
	trxn_req->req_event = req_event;
	trxn_req->pending_bknd_proc = false;

	switch (trxn_req->req_event) {
	case MGMTD_TRXN_PROC_SETCFG:
		trxn_req->req.set_cfg =
			XCALLOC(MTYPE_MGMTD_TRXN_SETCFG_REQ,
				sizeof(struct mgmt_set_cfg_req));
		assert(trxn_req->req.set_cfg);
		mgmt_trxn_req_list_add_tail(&trxn->set_cfg_reqs, trxn_req);
		MGMTD_TRXN_DBG(
			"Added a new SETCFG Req: %p for Trxn: %p, Sessn: 0x%llx",
			trxn_req, trxn, (unsigned long long)trxn->session_id);
		break;
	case MGMTD_TRXN_PROC_COMMITCFG:
		trxn->commit_cfg_req = trxn_req;
		MGMTD_TRXN_DBG(
			"Added a new COMMITCFG Req: %p for Trxn: %p, Sessn: 0x%llx",
			trxn_req, trxn, (unsigned long long)trxn->session_id);

		FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
			mgmt_trxn_batch_list_init(
				&trxn_req->req.commit_cfg.curr_batches[id]);
			mgmt_trxn_batch_list_init(
				&trxn_req->req.commit_cfg.next_batches[id]);
		}

		trxn_req->req.commit_cfg.batches =
			hash_create(mgmt_trxn_cfgbatch_hash_key,
				    mgmt_trxn_cfgbatch_hash_cmp,
				    "MGMT Config Batches");
		break;
	case MGMTD_TRXN_PROC_GETCFG:
		trxn_req->req.get_data =
			XCALLOC(MTYPE_MGMTD_TRXN_GETDATA_REQ,
				sizeof(struct mgmt_get_data_req));
		assert(trxn_req->req.get_data);
		mgmt_trxn_req_list_add_tail(&trxn->get_cfg_reqs, trxn_req);
		MGMTD_TRXN_DBG(
			"Added a new GETCFG Req: %p for Trxn: %p, Sessn: 0x%llx",
			trxn_req, trxn, (unsigned long long)trxn->session_id);
		break;
	case MGMTD_TRXN_PROC_GETDATA:
		trxn_req->req.get_data =
			XCALLOC(MTYPE_MGMTD_TRXN_GETDATA_REQ,
				sizeof(struct mgmt_get_data_req));
		assert(trxn_req->req.get_data);
		mgmt_trxn_req_list_add_tail(&trxn->get_data_reqs, trxn_req);
		MGMTD_TRXN_DBG(
			"Added a new GETDATA Req: %p for Trxn: %p, Sessn: 0x%llx",
			trxn_req, trxn, (unsigned long long)trxn->session_id);
		break;
	case MGMTD_TRXN_COMMITCFG_TIMEOUT:
	case MGMTD_TRXN_CLEANUP:
		break;
	}

	MGMTD_TRXN_LOCK(trxn);

	return trxn_req;
}

static void mgmt_trxn_req_free(struct mgmt_trxn_req **trxn_req)
{
	int indx;
	struct mgmt_trxn_req_list_head *req_list = NULL;
	struct mgmt_trxn_req_list_head *pending_list = NULL;
	enum mgmt_bcknd_client_id id;
	struct mgmt_bcknd_client_adapter *adptr;

	switch ((*trxn_req)->req_event) {
	case MGMTD_TRXN_PROC_SETCFG:
		for (indx = 0; indx < (*trxn_req)->req.set_cfg->num_cfg_changes;
		     indx++) {
			if ((*trxn_req)->req.set_cfg->cfg_changes[indx].value) {
				MGMTD_TRXN_DBG(
					"Freeing value for %s at %p ==> '%s'",
					(*trxn_req)
						->req.set_cfg->cfg_changes[indx]
						.xpath,
					(*trxn_req)
						->req.set_cfg->cfg_changes[indx]
						.value,
					(*trxn_req)
						->req.set_cfg->cfg_changes[indx]
						.value);
				free((void *)(*trxn_req)
					     ->req.set_cfg->cfg_changes[indx]
					     .value);
			}
		}
		req_list = &(*trxn_req)->trxn->set_cfg_reqs;
		MGMTD_TRXN_DBG("Deleting SETCFG Req: %p for Trxn: %p",
			       *trxn_req, (*trxn_req)->trxn);
		XFREE(MTYPE_MGMTD_TRXN_SETCFG_REQ, (*trxn_req)->req.set_cfg);
		break;
	case MGMTD_TRXN_PROC_COMMITCFG:
		MGMTD_TRXN_DBG("Deleting COMMITCFG Req: %p for Trxn: %p",
			       *trxn_req, (*trxn_req)->trxn);
		FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
			/*
			 * Send TRXN_DELETE to cleanup state for this
			 * transaction on backend
			 */
			if ((*trxn_req)->req.commit_cfg.curr_phase
				    >= MGMTD_COMMIT_PHASE_TRXN_CREATE
			    && (*trxn_req)->req.commit_cfg.curr_phase
				       < MGMTD_COMMIT_PHASE_TRXN_DELETE
			    && (*trxn_req)
				       ->req.commit_cfg.subscr_info
				       .xpath_subscr[id]
				       .subscribed) {
				adptr = mgmt_bcknd_get_adapter_by_id(id);
				if (adptr)
					mgmt_trxn_send_bcknd_trxn_delete(
						(*trxn_req)->trxn, adptr);
			}

			mgmt_trxn_cleanup_bcknd_cfg_batches((*trxn_req)->trxn,
							    id);
			if ((*trxn_req)->req.commit_cfg.batches) {
				hash_clean((*trxn_req)->req.commit_cfg.batches,
					   mgmt_trxn_cfgbatch_hash_free);
				hash_free((*trxn_req)->req.commit_cfg.batches);
				(*trxn_req)->req.commit_cfg.batches = NULL;
			}
		}
		break;
	case MGMTD_TRXN_PROC_GETCFG:
		for (indx = 0; indx < (*trxn_req)->req.get_data->num_xpaths;
		     indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)
					     ->req.get_data->xpaths[indx]);
		}
		req_list = &(*trxn_req)->trxn->get_cfg_reqs;
		MGMTD_TRXN_DBG("Deleting GETCFG Req: %p for Trxn: %p",
			       *trxn_req, (*trxn_req)->trxn);
		if ((*trxn_req)->req.get_data->reply)
			XFREE(MTYPE_MGMTD_TRXN_GETDATA_REPLY,
			      (*trxn_req)->req.get_data->reply);
		XFREE(MTYPE_MGMTD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	case MGMTD_TRXN_PROC_GETDATA:
		for (indx = 0; indx < (*trxn_req)->req.get_data->num_xpaths;
		     indx++) {
			if ((*trxn_req)->req.get_data->xpaths[indx])
				free((void *)(*trxn_req)
					     ->req.get_data->xpaths[indx]);
		}
		pending_list = &(*trxn_req)->trxn->pending_get_datas;
		req_list = &(*trxn_req)->trxn->get_data_reqs;
		MGMTD_TRXN_DBG("Deleting GETDATA Req: %p for Trxn: %p",
			       *trxn_req, (*trxn_req)->trxn);
		if ((*trxn_req)->req.get_data->reply)
			XFREE(MTYPE_MGMTD_TRXN_GETDATA_REPLY,
			      (*trxn_req)->req.get_data->reply);
		XFREE(MTYPE_MGMTD_TRXN_GETDATA_REQ, (*trxn_req)->req.get_data);
		break;
	case MGMTD_TRXN_COMMITCFG_TIMEOUT:
	case MGMTD_TRXN_CLEANUP:
		break;
	}

	if ((*trxn_req)->pending_bknd_proc && pending_list) {
		mgmt_trxn_req_list_del(pending_list, *trxn_req);
		MGMTD_TRXN_DBG("Removed Req: %p from pending-list (left:%d)",
			       *trxn_req,
			       (int)mgmt_trxn_req_list_count(pending_list));
	} else if (req_list) {
		mgmt_trxn_req_list_del(req_list, *trxn_req);
		MGMTD_TRXN_DBG("Removed Req: %p from request-list (left:%d)",
			       *trxn_req,
			       (int)mgmt_trxn_req_list_count(req_list));
	}

	(*trxn_req)->pending_bknd_proc = false;
	MGMTD_TRXN_UNLOCK(&(*trxn_req)->trxn);
	XFREE(MTYPE_MGMTD_TRXN_REQ, (*trxn_req));
	*trxn_req = NULL;
}

static void mgmt_trxn_process_set_cfg(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	struct mgmt_db_ctxt *db_ctxt;
	struct nb_config *nb_config;
	char err_buf[1024];
	bool error;
	int num_processed = 0;
	size_t left;
	struct mgmt_commit_stats *cmt_stats;
	int ret = 0;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);
	cmt_stats = mgmt_frntnd_get_sessn_commit_stats(trxn->session_id);

	MGMTD_TRXN_DBG(
		"Processing %d SET_CONFIG requests for Trxn:%p Session:0x%llx",
		(int)mgmt_trxn_req_list_count(&trxn->set_cfg_reqs), trxn,
		(unsigned long long)trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST (&trxn->set_cfg_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == MGMTD_TRXN_PROC_SETCFG);
		db_ctxt = trxn_req->req.set_cfg->db_ctxt;
		if (!db_ctxt) {
			mgmt_frntnd_send_set_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.set_cfg->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, "No such database!",
				trxn_req->req.set_cfg->implicit_commit);
			error = true;
			goto mgmt_trxn_process_set_cfg_done;
		}

		nb_config = mgmt_db_get_nb_config(db_ctxt);
		if (!nb_config) {
			mgmt_frntnd_send_set_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.set_cfg->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR,
				"Unable to retrieve DB Config Tree!",
				trxn_req->req.set_cfg->implicit_commit);
			error = true;
			goto mgmt_trxn_process_set_cfg_done;
		}

		error = false;
		nb_candidate_edit_config_changes(
			nb_config, trxn_req->req.set_cfg->cfg_changes,
			(size_t)trxn_req->req.set_cfg->num_cfg_changes, NULL,
			NULL, 0, err_buf, sizeof(err_buf), &error);
		if (error) {
			mgmt_frntnd_send_set_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.set_cfg->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, err_buf,
				trxn_req->req.set_cfg->implicit_commit);
			goto mgmt_trxn_process_set_cfg_done;
		}

		if (trxn_req->req.set_cfg->implicit_commit) {
			assert(mgmt_trxn_req_list_count(&trxn->set_cfg_reqs)
			       == 1);
			assert(trxn_req->req.set_cfg->dst_db_ctxt);

			ret = mgmt_db_write_lock(
				trxn_req->req.set_cfg->dst_db_ctxt);
			if (ret != 0) {
				MGMTD_TRXN_ERR(
					"Failed to lock the DB %u for trxn: %p sessn 0x%llx, errstr %s!",
					trxn_req->req.set_cfg->dst_db_id, trxn,
					(unsigned long long)trxn->session_id,
					strerror(ret));
				mgmt_trxn_send_commit_cfg_reply(
					trxn, MGMTD_DB_LOCK_FAILED,
					"Lock running DB before implicit commit failed!");
				goto mgmt_trxn_process_set_cfg_done;
			}

			mgmt_trxn_send_commit_config_req(
				trxn->trxn_id, trxn_req->req_id,
				trxn_req->req.set_cfg->db_id,
				trxn_req->req.set_cfg->db_ctxt,
				trxn_req->req.set_cfg->dst_db_id,
				trxn_req->req.set_cfg->dst_db_ctxt, false,
				false, true);

			if (mm->perf_stats_en)
				gettimeofday(&cmt_stats->last_start, NULL);
			cmt_stats->commit_cnt++;
		} else if (mgmt_frntnd_send_set_cfg_reply(
				   trxn->session_id, trxn->trxn_id,
				   trxn_req->req.set_cfg->db_id,
				   trxn_req->req_id, MGMTD_SUCCESS, NULL, false)
			   != 0) {
			MGMTD_TRXN_ERR(
				"Failed to send SET_CONFIG_REPLY for trxn %p sessn 0x%llx",
				trxn, (unsigned long long)trxn->session_id);
			error = true;
		}

	mgmt_trxn_process_set_cfg_done:

		/*
		 * Note: The following will remove it from the list as well.
		 */
		mgmt_trxn_req_free(&trxn_req);

		num_processed++;
		if (num_processed == MGMTD_TRXN_MAX_NUM_SETCFG_PROC)
			break;
	}

	left = mgmt_trxn_req_list_count(&trxn->set_cfg_reqs);
	if (left) {
		MGMTD_TRXN_DBG(
			"Processed maximum number of Set-Config requests (%d/%d/%d). Rescheduling for rest.",
			num_processed, MGMTD_TRXN_MAX_NUM_SETCFG_PROC,
			(int)left);
		mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_SETCFG);
	}
}

static int mgmt_trxn_send_commit_cfg_reply(struct mgmt_trxn_ctxt *trxn,
					   enum mgmt_result result,
					   const char *error_if_any)
{
	int ret = 0;
	bool success, create_cmt_info_rec;

	if (!trxn->commit_cfg_req)
		return -1;

	success = result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES
			  ? true
			  : false;
	if (!trxn->commit_cfg_req->req.commit_cfg.implicit && trxn->session_id
	    && mgmt_frntnd_send_commit_cfg_reply(
		       trxn->session_id, trxn->trxn_id,
		       trxn->commit_cfg_req->req.commit_cfg.src_db_id,
		       trxn->commit_cfg_req->req.commit_cfg.dst_db_id,
		       trxn->commit_cfg_req->req_id,
		       trxn->commit_cfg_req->req.commit_cfg.validate_only,
		       result, error_if_any)
		       != 0) {
		MGMTD_TRXN_ERR(
			"Failed to send COMMIT-CONFIG-REPLY for Trxn %p Sessn 0x%llx",
			trxn, (unsigned long long)trxn->session_id);
	}

	if (trxn->commit_cfg_req->req.commit_cfg.implicit && trxn->session_id
	    && mgmt_frntnd_send_set_cfg_reply(
		       trxn->session_id, trxn->trxn_id,
		       trxn->commit_cfg_req->req.commit_cfg.src_db_id,
		       trxn->commit_cfg_req->req_id,
		       success ? MGMTD_SUCCESS : MGMTD_INTERNAL_ERROR,
		       error_if_any, true)
		       != 0) {
		MGMTD_TRXN_ERR(
			"Failed to send SET-CONFIG-REPLY for Trxn %p Sessn 0x%llx",
			trxn, (unsigned long long)trxn->session_id);
	}

	if (success) {
		/* Stop the commit-timeout timer */
		THREAD_OFF(trxn->comm_cfg_timeout);

		create_cmt_info_rec =
			result != MGMTD_NO_CFG_CHANGES
					&& !trxn->commit_cfg_req->req.commit_cfg
						    .rollback
				? true
				: false;

		/*
		 * Successful commit: Merge Src DB into Dst DB if and only if
		 * this was not a validate-only or abort request.
		 */
		if ((trxn->session_id
		     && !trxn->commit_cfg_req->req.commit_cfg.validate_only
		     && !trxn->commit_cfg_req->req.commit_cfg.abort)
		    || trxn->commit_cfg_req->req.commit_cfg.rollback) {
			mgmt_db_copy_dbs(trxn->commit_cfg_req->req.commit_cfg
						 .src_db_ctxt,
					 trxn->commit_cfg_req->req.commit_cfg
						 .dst_db_ctxt,
					 create_cmt_info_rec);
		}

		/*
		 * Restore Src DB back to Dest DB only through a commit abort
		 * request.
		 */
		if (trxn->session_id
		    && trxn->commit_cfg_req->req.commit_cfg.abort)
			mgmt_db_copy_dbs(trxn->commit_cfg_req->req.commit_cfg
						 .dst_db_ctxt,
					 trxn->commit_cfg_req->req.commit_cfg
						 .src_db_ctxt,
					 false);
	} else {
		/*
		 * The commit has failied. For implicit commit requests restore
		 * back the contents of the candidate DB.
		 */
		if (trxn->commit_cfg_req->req.commit_cfg.implicit)
			mgmt_db_copy_dbs(trxn->commit_cfg_req->req.commit_cfg
						 .dst_db_ctxt,
					 trxn->commit_cfg_req->req.commit_cfg
						 .src_db_ctxt,
					 false);
	}

	if (trxn->commit_cfg_req->req.commit_cfg.rollback) {
		ret = mgmt_db_unlock(
			trxn->commit_cfg_req->req.commit_cfg.dst_db_ctxt);
		if (ret != 0)
			MGMTD_TRXN_ERR(
				"Failed to unlock the dst DB during rollback : %s",
				strerror(ret));
	}

	if (trxn->commit_cfg_req->req.commit_cfg.implicit)
		if (mgmt_db_unlock(
			    trxn->commit_cfg_req->req.commit_cfg.dst_db_ctxt)
		    != 0)
			MGMTD_TRXN_ERR(
				"Failed to unlock the dst DB during implicit : %s",
				strerror(ret));

	trxn->commit_cfg_req->req.commit_cfg.cmt_stats = NULL;
	mgmt_trxn_req_free(&trxn->commit_cfg_req);

	/*
	 * The CONFIG Transaction should be destroyed from Frontend-adapter.
	 * But in case the transaction is not triggered from a front-end session
	 * we need to cleanup by itself.
	 */
	if (!trxn->session_id)
		mgmt_trxn_register_event(trxn, MGMTD_TRXN_CLEANUP);

	return 0;
}

static void
mgmt_move_trxn_cfg_batch_to_next(struct mgmt_commit_cfg_req *cmtcfg_req,
				 struct mgmt_trxn_bcknd_cfg_batch *cfg_btch,
				 struct mgmt_trxn_batch_list_head *src_list,
				 struct mgmt_trxn_batch_list_head *dst_list,
				 bool update_commit_phase,
				 enum mgmt_commit_phase to_phase)
{
	mgmt_trxn_batch_list_del(src_list, cfg_btch);

	if (update_commit_phase) {
		MGMTD_TRXN_DBG(
			"Move Trxn-Id %p Batch-Id %p from '%s' --> '%s'",
			cfg_btch->trxn, cfg_btch,
			mgmt_commit_phase2str(cfg_btch->comm_phase),
			mgmt_trxn_commit_phase_str(cfg_btch->trxn, false));
		cfg_btch->comm_phase = to_phase;
	}

	mgmt_trxn_batch_list_add_tail(dst_list, cfg_btch);
}

static void mgmt_move_trxn_cfg_batches(
	struct mgmt_trxn_ctxt *trxn, struct mgmt_commit_cfg_req *cmtcfg_req,
	struct mgmt_trxn_batch_list_head *src_list,
	struct mgmt_trxn_batch_list_head *dst_list, bool update_commit_phase,
	enum mgmt_commit_phase to_phase)
{
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	FOREACH_TRXN_CFG_BATCH_IN_LIST (src_list, cfg_btch) {
		mgmt_move_trxn_cfg_batch_to_next(cmtcfg_req, cfg_btch, src_list,
						 dst_list, update_commit_phase,
						 to_phase);
	}
}

static int
mgmt_try_move_commit_to_next_phase(struct mgmt_trxn_ctxt *trxn,
				   struct mgmt_commit_cfg_req *cmtcfg_req)
{
	struct mgmt_trxn_batch_list_head *curr_list, *next_list;
	enum mgmt_bcknd_client_id id;

	MGMTD_TRXN_DBG("Trxn-Id %p, Phase(current:'%s' next:'%s')", trxn,
		       mgmt_trxn_commit_phase_str(trxn, true),
		       mgmt_trxn_commit_phase_str(trxn, false));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].subscribed
		    && mgmt_trxn_batch_list_count(
			       &cmtcfg_req->curr_batches[id])) {
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

	MGMTD_TRXN_DBG("Move entire Trxn-Id %p from '%s' to '%s'", trxn,
		       mgmt_trxn_commit_phase_str(trxn, true),
		       mgmt_trxn_commit_phase_str(trxn, false));

	/*
	 * If we are here, it means all the clients has moved to next phase.
	 * So we can move the whole commit to next phase.
	 */
	cmtcfg_req->curr_phase = cmtcfg_req->next_phase;
	cmtcfg_req->next_phase++;
	MGMTD_TRXN_DBG(
		"Move back all config batches for Trxn %p from next to current branch",
		trxn);
	FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
		curr_list = &cmtcfg_req->curr_batches[id];
		next_list = &cmtcfg_req->next_batches[id];
		mgmt_move_trxn_cfg_batches(trxn, cmtcfg_req, next_list,
					   curr_list, false, 0);
	}

	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_COMMITCFG);

	return 0;
}

static int
mgmt_move_bcknd_commit_to_next_phase(struct mgmt_trxn_ctxt *trxn,
				     struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_trxn_batch_list_head *curr_list, *next_list;

	if (trxn->type != MGMTD_TRXN_TYPE_CONFIG || !trxn->commit_cfg_req)
		return -1;

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;

	MGMTD_TRXN_DBG(
		"Move Trxn-Id %p for '%s' Phase(current: '%s' next:'%s')", trxn,
		adptr->name, mgmt_trxn_commit_phase_str(trxn, true),
		mgmt_trxn_commit_phase_str(trxn, false));

	MGMTD_TRXN_DBG(
		"Move all config batches for '%s' from current to next list",
		adptr->name);
	curr_list = &cmtcfg_req->curr_batches[adptr->id];
	next_list = &cmtcfg_req->next_batches[adptr->id];
	mgmt_move_trxn_cfg_batches(trxn, cmtcfg_req, curr_list, next_list, true,
				   cmtcfg_req->next_phase);

	MGMTD_TRXN_DBG("Trxn-Id %p, Phase(current:'%s' next:'%s')", trxn,
		       mgmt_trxn_commit_phase_str(trxn, true),
		       mgmt_trxn_commit_phase_str(trxn, false));

	/*
	 * Check if all clients has moved to next phase or not.
	 */
	mgmt_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

static int mgmt_trxn_create_config_batches(struct mgmt_trxn_req *trxn_req,
					   struct nb_config_cbs *changes)
{
	struct nb_config_cb *cb, *nxt;
	struct nb_config_change *chg;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_bcknd_client_subscr_info subscr_info;
	char *xpath = NULL, *value = NULL;
	char err_buf[1024];
	enum mgmt_bcknd_client_id id;
	struct mgmt_bcknd_client_adapter *adptr;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	bool found_validator;
	int num_chgs = 0;
	int xpath_len, value_len;

	cmtcfg_req = &trxn_req->req.commit_cfg;

	RB_FOREACH_SAFE (cb, nb_config_cbs, changes, nxt) {
		chg = (struct nb_config_change *)cb;

		/*
		 * Could have directly pointed to xpath in nb_node.
		 * But dont want to mess with it now.
		 * xpath = chg->cb.nb_node->xpath;
		 */
		xpath = lyd_path(chg->cb.dnode, LYD_PATH_STD, NULL, 0);
		if (!xpath) {
			(void)mgmt_trxn_send_commit_cfg_reply(
				trxn_req->trxn, MGMTD_INTERNAL_ERROR,
				"Internal error! Could not get Xpath from Db node!");
			goto mgmt_trxn_create_config_batches_failed;
		}

		value = (char *)lyd_get_value(chg->cb.dnode);
		if (!value)
			value = (char *)MGMTD_BCKND_CONTAINER_NODE_VAL;

		MGMTD_TRXN_DBG("XPATH: %s, Value: '%s'", xpath,
			       value ? value : "NIL");

		if (mgmt_bcknd_get_subscr_info_for_xpath(xpath, &subscr_info)
		    != 0) {
			snprintf(err_buf, sizeof(err_buf),
				 "No backend module found for XPATH: '%s",
				 xpath);
			(void)mgmt_trxn_send_commit_cfg_reply(
				trxn_req->trxn, MGMTD_INTERNAL_ERROR, err_buf);
			goto mgmt_trxn_create_config_batches_failed;
		}

		xpath_len = strlen(xpath) + 1;
		value_len = strlen(value) + 1;
		found_validator = false;
		FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
			if (!subscr_info.xpath_subscr[id].validate_config
			    && !subscr_info.xpath_subscr[id].notify_config)
				continue;

			adptr = mgmt_bcknd_get_adapter_by_id(id);
			if (!adptr)
				continue;

			cfg_btch = cmtcfg_req->last_bcknd_cfg_batch[id];
			if (!cfg_btch
			    || (cfg_btch->num_cfg_data
				== MGMTD_MAX_CFG_CHANGES_IN_BATCH)
			    || (cfg_btch->buf_space_left
				< (xpath_len + value_len))) {
				/* Allocate a new config batch */
				cfg_btch = mgmt_trxn_cfg_batch_alloc(
					trxn_req->trxn, id, adptr);
			}

			cfg_btch->buf_space_left -= (xpath_len + value_len);
			memcpy(&cfg_btch->xp_subscr[cfg_btch->num_cfg_data],
			       &subscr_info.xpath_subscr[id],
			       sizeof(cfg_btch->xp_subscr[0]));

			mgmt_yang_cfg_data_req_init(
				&cfg_btch->cfg_data[cfg_btch->num_cfg_data]);
			cfg_btch->cfg_datap[cfg_btch->num_cfg_data] =
				&cfg_btch->cfg_data[cfg_btch->num_cfg_data];

			if (chg->cb.operation == NB_OP_DESTROY)
				cfg_btch->cfg_data[cfg_btch->num_cfg_data]
					.req_type =
					MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA;
			else
				cfg_btch->cfg_data[cfg_btch->num_cfg_data]
					.req_type =
					MGMTD__CFG_DATA_REQ_TYPE__SET_DATA;

			mgmt_yang_data_init(
				&cfg_btch->data[cfg_btch->num_cfg_data]);
			cfg_btch->cfg_data[cfg_btch->num_cfg_data].data =
				&cfg_btch->data[cfg_btch->num_cfg_data];
			cfg_btch->data[cfg_btch->num_cfg_data].xpath = xpath;
			xpath = NULL;

			mgmt_yang_data_value_init(
				&cfg_btch->value[cfg_btch->num_cfg_data]);
			cfg_btch->data[cfg_btch->num_cfg_data].value =
				&cfg_btch->value[cfg_btch->num_cfg_data];
			cfg_btch->value[cfg_btch->num_cfg_data].value_case =
				MGMTD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
			cfg_btch->value[cfg_btch->num_cfg_data]
				.encoded_str_val = value;
			value = NULL;

			if (subscr_info.xpath_subscr[id].validate_config)
				found_validator = true;

			cmtcfg_req->subscr_info.xpath_subscr[id].subscribed |=
				subscr_info.xpath_subscr[id].subscribed;
			MGMTD_TRXN_DBG(
				" -- %s, {V:%d, N:%d}, Batch: %p, Item:%d",
				adptr->name,
				subscr_info.xpath_subscr[id].validate_config,
				subscr_info.xpath_subscr[id].notify_config,
				cfg_btch, (int)cfg_btch->num_cfg_data);

			cfg_btch->num_cfg_data++;
			num_chgs++;
		}

		if (!found_validator) {
			snprintf(err_buf, sizeof(err_buf),
				 "No validator module found for XPATH: '%s",
				 xpath);
			MGMTD_TRXN_ERR("***** %s", err_buf);
		}
	}

	cmtcfg_req->cmt_stats->last_batch_cnt = num_chgs;
	if (!num_chgs) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn_req->trxn, MGMTD_NO_CFG_CHANGES,
			"No changes found to commit!");
		goto mgmt_trxn_create_config_batches_failed;
	}

	cmtcfg_req->next_phase = MGMTD_COMMIT_PHASE_TRXN_CREATE;
	return 0;

mgmt_trxn_create_config_batches_failed:

	if (xpath)
		free(xpath);

	return -1;
}

static int mgmt_trxn_prepare_config(struct mgmt_trxn_ctxt *trxn)
{
	struct nb_context nb_ctxt;
	struct nb_config *nb_config;
	char err_buf[1024] = {0};
	struct nb_config_cbs changes;
	struct nb_config_cbs *cfg_chgs = NULL;
	int ret;
	bool del_cfg_chgs = false;

	ret = 0;
	memset(&nb_ctxt, 0, sizeof(nb_ctxt));
	memset(&changes, 0, sizeof(changes));
	if (trxn->commit_cfg_req->req.commit_cfg.cfg_chgs) {
		cfg_chgs = trxn->commit_cfg_req->req.commit_cfg.cfg_chgs;
		del_cfg_chgs = true;
		goto mgmt_trxn_prep_config_validation_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.src_db_id
	    != MGMTD_DB_CANDIDATE) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INVALID_PARAM,
			"Source DB cannot be any other than CANDIDATE!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.dst_db_id
	    != MGMTD_DB_RUNNING) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INVALID_PARAM,
			"Destination DB cannot be any other than RUNNING!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	if (!trxn->commit_cfg_req->req.commit_cfg.src_db_ctxt) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INVALID_PARAM, "No such source database!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	if (!trxn->commit_cfg_req->req.commit_cfg.dst_db_ctxt) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INVALID_PARAM,
			"No such destination database!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.abort) {
		/*
		 * This is a commit abort request. Return back success.
		 * That should trigger a restore of Candidate database to
		 * Running.
		 */
		(void)mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_SUCCESS,
						      NULL);
		goto mgmt_trxn_prepare_config_done;
	}

	nb_config = mgmt_db_get_nb_config(
		trxn->commit_cfg_req->req.commit_cfg.src_db_ctxt);
	if (!nb_config) {
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INTERNAL_ERROR,
			"Unable to retrieve Commit DB Config Tree!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	/*
	 * Check for diffs from scratch buffer. If found empty
	 * get the diff from Candidate DB itself.
	 */
	cfg_chgs = &nb_config->cfg_chgs;
	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		/*
		 * This could be the case when the config is directly
		 * loaded onto the candidate DB from a file. Get the
		 * diff from a full comparison of the candidate and
		 * running DBs.
		 */
		nb_config_diff(
			mgmt_db_get_nb_config(trxn->commit_cfg_req->req
						      .commit_cfg.dst_db_ctxt),
			nb_config, &changes);
		cfg_chgs = &changes;
		del_cfg_chgs = true;
	}

	if (RB_EMPTY(nb_config_cbs, cfg_chgs)) {
		/*
		 * This means there's no changes to commit whatsoever
		 * is the source of the changes in config.
		 */
		(void)mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_NO_CFG_CHANGES,
			"No changes found to be committed!");
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	/*
	 * Validate YANG contents of the source DB and get the diff
	 * between source and destination DB contents.
	 */
	nb_ctxt.client = NB_CLIENT_MGMTD_SERVER;
	nb_ctxt.user = (void *)trxn;
	ret = nb_candidate_validate_yang(nb_config, false, err_buf,
					 sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		(void)mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_INVALID_PARAM,
						      err_buf);
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
	if (mm->perf_stats_en)
		gettimeofday(&trxn->commit_cfg_req->req.commit_cfg.cmt_stats
				      ->validate_start,
			     NULL);

	/*
	 * Perform application level validations locally on the MGMTD
	 * process by calling application specific validation routines
	 * loaded onto MGMTD process using libraries.
	 */
	ret = nb_candidate_validate_code(&nb_ctxt, nb_config, &changes, err_buf,
					 sizeof(err_buf) - 1);
	if (ret != NB_OK) {
		if (strncmp(err_buf, " ", strlen(err_buf)) == 0)
			strlcpy(err_buf, "Validation failed", sizeof(err_buf));
		(void)mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_INVALID_PARAM,
						      err_buf);
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	if (trxn->commit_cfg_req->req.commit_cfg.validate_only) {
		/*
		 * This was a validate-only COMMIT request return success.
		 */
		(void)mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_SUCCESS,
						      NULL);
		goto mgmt_trxn_prepare_config_done;
	}
#endif /* ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED */

mgmt_trxn_prep_config_validation_done:

	if (mm->perf_stats_en)
		gettimeofday(&trxn->commit_cfg_req->req.commit_cfg.cmt_stats
				      ->prep_cfg_start,
			     NULL);

	/*
	 * Iterate over the diffs and create ordered batches of config
	 * commands to be validated.
	 */
	ret = mgmt_trxn_create_config_batches(trxn->commit_cfg_req, cfg_chgs);
	if (ret != 0) {
		ret = -1;
		goto mgmt_trxn_prepare_config_done;
	}

	/* Move to the Transaction Create Phase */
	trxn->commit_cfg_req->req.commit_cfg.curr_phase =
		MGMTD_COMMIT_PHASE_TRXN_CREATE;
	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_COMMITCFG);

	/*
	 * Start the COMMIT Timeout Timer to abort Trxn if things get stuck at
	 * backend.
	 */
	mgmt_trxn_register_event(trxn, MGMTD_TRXN_COMMITCFG_TIMEOUT);
mgmt_trxn_prepare_config_done:

	if (cfg_chgs && del_cfg_chgs)
		nb_config_diff_del_changes(cfg_chgs);

	return ret;
}

static int mgmt_trxn_send_bcknd_trxn_create(struct mgmt_trxn_ctxt *trxn)
{
	enum mgmt_bcknd_client_id id;
	struct mgmt_bcknd_client_adapter *adptr;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].subscribed) {
			adptr = mgmt_bcknd_get_adapter_by_id(id);
			if (mgmt_bcknd_create_trxn(adptr, trxn->trxn_id)
			    != 0) {
				(void)mgmt_trxn_send_commit_cfg_reply(
					trxn, MGMTD_INTERNAL_ERROR,
					"Could not send TRXN_CREATE to backend adapter");
				return -1;
			}

			FOREACH_TRXN_CFG_BATCH_IN_LIST (
				&trxn->commit_cfg_req->req.commit_cfg
					 .curr_batches[id],
				cfg_btch)
				cfg_btch->comm_phase =
					MGMTD_COMMIT_PHASE_TRXN_CREATE;
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		MGMTD_COMMIT_PHASE_SEND_CFG;

	/*
	 * Dont move the commit to next phase yet. Wait for the TRXN_REPLY to
	 * come back.
	 */

	MGMTD_TRXN_DBG(
		"Trxn:%p Session:0x%llx, Phase(Current:'%s', Next: '%s')", trxn,
		(unsigned long long)trxn->session_id,
		mgmt_trxn_commit_phase_str(trxn, true),
		mgmt_trxn_commit_phase_str(trxn, false));

	return 0;
}

static int
mgmt_trxn_send_bcknd_cfg_data(struct mgmt_trxn_ctxt *trxn,
			      struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_bcknd_cfgreq cfg_req = {0};
	size_t num_batches, indx;

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	assert(cmtcfg_req->subscr_info.xpath_subscr[adptr->id].subscribed);

	indx = 0;
	num_batches = mgmt_trxn_batch_list_count(
		&cmtcfg_req->curr_batches[adptr->id]);
	FOREACH_TRXN_CFG_BATCH_IN_LIST (&cmtcfg_req->curr_batches[adptr->id],
					cfg_btch) {
		assert(cmtcfg_req->next_phase == MGMTD_COMMIT_PHASE_SEND_CFG);

		cfg_req.cfgdata_reqs = cfg_btch->cfg_datap;
		cfg_req.num_reqs = cfg_btch->num_cfg_data;
		indx++;
		if (mgmt_bcknd_send_cfg_data_create_req(
			    adptr, trxn->trxn_id, cfg_btch->batch_id, &cfg_req,
			    indx == num_batches ? true : false)
		    != 0) {
			(void)mgmt_trxn_send_commit_cfg_reply(
				trxn, MGMTD_INTERNAL_ERROR,
				"Internal Error! Could not send config data to backend!");
			MGMTD_TRXN_ERR(
				"Could not send CFGDATA_CREATE for Trxn %p Batch %p to client '%s",
				trxn, cfg_btch, adptr->name);
			return -1;
		}

		cmtcfg_req->cmt_stats->last_num_cfgdata_reqs++;
		mgmt_move_trxn_cfg_batch_to_next(
			cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			MGMTD_COMMIT_PHASE_SEND_CFG);
	}

	/*
	 * This could ne the last Backend Client to send CFGDATA_CREATE_REQ to.
	 * Try moving the commit to next phase.
	 */
	mgmt_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

static int
mgmt_trxn_send_bcknd_trxn_delete(struct mgmt_trxn_ctxt *trxn,
				 struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	if (cmtcfg_req->subscr_info.xpath_subscr[adptr->id].subscribed) {
		adptr = mgmt_bcknd_get_adapter_by_id(adptr->id);
		(void)mgmt_bcknd_destroy_trxn(adptr, trxn->trxn_id);

		FOREACH_TRXN_CFG_BATCH_IN_LIST (
			&trxn->commit_cfg_req->req.commit_cfg
				 .curr_batches[adptr->id],
			cfg_btch)
			cfg_btch->comm_phase = MGMTD_COMMIT_PHASE_TRXN_DELETE;
	}

	return 0;
}

static void mgmt_trxn_cfg_commit_timedout(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG);

	if (!trxn->commit_cfg_req)
		return;

	MGMTD_TRXN_ERR(
		"Backend operations for Config Trxn %p has timedout! Aborting commit!!",
		trxn);

	/*
	 * Send a COMMIT_CONFIG_REPLY with failure.
	 * NOTE: The transaction cleanup will be triggered from Front-end
	 * adapter.
	 */
	mgmt_trxn_send_commit_cfg_reply(
		trxn, MGMTD_INTERNAL_ERROR,
		"Operation on the backend timed-out. Aborting commit!");
}

/*
 * Send CFG_APPLY_REQs to all the backend client.
 *
 * NOTE: This is always dispatched when all CFGDATA_CREATE_REQs
 * for all backend clients has been generated. Please see
 * mgmt_trxn_register_event() and mgmt_trxn_process_commit_cfg()
 * for details.
 */
static int mgmt_trxn_send_bcknd_cfg_apply(struct mgmt_trxn_ctxt *trxn)
{
	enum mgmt_bcknd_client_id id;
	struct mgmt_bcknd_client_adapter *adptr;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	struct mgmt_trxn_batch_list_head *btch_list;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	if (cmtcfg_req->validate_only) {
		/*
		 * If this was a validate-only COMMIT request return success.
		 */
		(void)mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_SUCCESS,
						      NULL);
		return 0;
	}

	FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].notify_config) {
			adptr = mgmt_bcknd_get_adapter_by_id(id);
			if (!adptr)
				return -1;

			btch_list = &cmtcfg_req->curr_batches[id];
			if (mgmt_bcknd_send_cfg_apply_req(adptr, trxn->trxn_id)
			    != 0) {
				(void)mgmt_trxn_send_commit_cfg_reply(
					trxn, MGMTD_INTERNAL_ERROR,
					"Could not send CFG_APPLY_REQ to backend adapter");
				return -1;
			}
			cmtcfg_req->cmt_stats->last_num_apply_reqs++;

			UNSET_FLAG(adptr->flags,
				   MGMTD_BCKND_ADPTR_FLAGS_CFG_SYNCED);

			FOREACH_TRXN_CFG_BATCH_IN_LIST (btch_list, cfg_btch)
				cfg_btch->comm_phase =
					MGMTD_COMMIT_PHASE_APPLY_CFG;
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		MGMTD_COMMIT_PHASE_TRXN_DELETE;

	/*
	 * Dont move the commit to next phase yet. Wait for all VALIDATE_REPLIES
	 * to come back.
	 */

	return 0;
}

#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
/*
 * Send CFG_VALIDATE_REQs to all the backend client.
 */
static int mgmt_trxn_send_bcknd_cfg_validate(struct mgmt_trxn_ctxt *trxn)
{
	enum mgmt_bcknd_client_id id;
	struct mgmt_bcknd_client_adapter *adptr;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	uint64_t *batch_ids;
	size_t indx, num_batches;
	struct mgmt_trxn_batch_list_head *btch_list;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;

	assert(trxn->type == MGMTD_TRXN_TYPE_CONFIG && trxn->commit_cfg_req);

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	FOREACH_MGMTD_BCKND_CLIENT_ID (id) {
		if (cmtcfg_req->subscr_info.xpath_subscr[id].validate_config) {
			adptr = mgmt_bcknd_get_adapter_by_id(id);
			if (!adptr)
				return -1;

			btch_list = &cmtcfg_req->curr_batches[id];
			num_batches = mgmt_trxn_batch_list_count(btch_list);
			batch_ids = (uint64_t *)calloc(num_batches,
						       sizeof(uint64_t));

			indx = 0;
			FOREACH_TRXN_CFG_BATCH_IN_LIST (btch_list, cfg_btch) {
				batch_ids[indx] = cfg_btch->batch_id;
				indx++;
				assert(indx <= num_batches);
			}

			if (mgmt_bcknd_send_cfg_validate_req(
				    adptr, trxn->trxn_id, batch_ids, indx)
			    != 0) {
				(void)mgmt_trxn_send_commit_cfg_reply(
					trxn, MGMTD_INTERNAL_ERROR,
					"Could not send CFG_VALIDATE_REQ to backend adapter");
				return -1;
			}

			FOREACH_TRXN_CFG_BATCH_IN_LIST (btch_list, cfg_btch) {
				cfg_btch->comm_phase =
					MGMTD_COMMIT_PHASE_VALIDATE_CFG;
			}

			free(batch_ids);
		}
	}

	trxn->commit_cfg_req->req.commit_cfg.next_phase =
		MGMTD_COMMIT_PHASE_APPLY_CFG;

	/*
	 * Dont move the commit to next phase yet. Wait for all VALIDATE_REPLIES
	 * to come back.
	 */

	return 0;
}
#endif /* iddef MGMTD_LOCAL_VALIDATIONS_ENABLED */

static void mgmt_trxn_process_commit_cfg(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_commit_cfg_req *cmtcfg_req;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);

	MGMTD_TRXN_DBG(
		"Processing COMMIT_CONFIG for Trxn:%p Session:0x%llx, Phase(Current:'%s', Next: '%s')",
		trxn, (unsigned long long)trxn->session_id,
		mgmt_trxn_commit_phase_str(trxn, true),
		mgmt_trxn_commit_phase_str(trxn, false));

	assert(trxn->commit_cfg_req);
	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	switch (cmtcfg_req->curr_phase) {
	case MGMTD_COMMIT_PHASE_PREPARE_CFG:
		mgmt_trxn_prepare_config(trxn);
		break;
	case MGMTD_COMMIT_PHASE_TRXN_CREATE:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->trxn_create_start,
				     NULL);
		/*
		 * Send TRXN_CREATE_REQ to all Backend now.
		 */
		mgmt_trxn_send_bcknd_trxn_create(trxn);
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
		assert(cmtcfg_req->next_phase
		       == MGMTD_COMMIT_PHASE_VALIDATE_CFG);
		MGMTD_TRXN_DBG(
			"Trxn:%p Session:0x%llx, trigger sending CFG_VALIDATE_REQ to all backend clients",
			trxn, (unsigned long long)trxn->session_id);
#else  /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
		assert(cmtcfg_req->next_phase == MGMTD_COMMIT_PHASE_APPLY_CFG);
		MGMTD_TRXN_DBG(
			"Trxn:%p Session:0x%llx, trigger sending CFG_APPLY_REQ to all backend clients",
			trxn, (unsigned long long)trxn->session_id);
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
		break;
#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
	case MGMTD_COMMIT_PHASE_VALIDATE_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->validate_start,
				     NULL);
		/*
		 * We should have received successful CFFDATA_CREATE_REPLY from
		 * all concerned Backend Clients by now. Send out the
		 * CFG_VALIDATE_REQs now.
		 */
		mgmt_trxn_send_bcknd_cfg_validate(trxn);
		break;
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
	case MGMTD_COMMIT_PHASE_APPLY_CFG:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_start,
				     NULL);
		/*
		 * We should have received successful CFG_VALIDATE_REPLY from
		 * all concerned Backend Clients by now. Send out the
		 * CFG_APPLY_REQs now.
		 */
		mgmt_trxn_send_bcknd_cfg_apply(trxn);
		break;
	case MGMTD_COMMIT_PHASE_TRXN_DELETE:
		if (mm->perf_stats_en)
			gettimeofday(&cmtcfg_req->cmt_stats->trxn_del_start,
				     NULL);
		/*
		 * We would have sent TRXN_DELETE_REQ to all backend by now.
		 * Send a successful CONFIG_COMMIT_REPLY back to front-end.
		 * NOTE: This should also trigger DB merge/unlock and Trxn
		 * cleanup. Please see mgmt_frntnd_send_commit_cfg_reply() for
		 * more details.
		 */
		THREAD_OFF(trxn->comm_cfg_timeout);
		mgmt_trxn_send_commit_cfg_reply(trxn, MGMTD_SUCCESS, NULL);
		break;
	case MGMTD_COMMIT_PHASE_MAX:
		break;
	}

	MGMTD_TRXN_DBG(
		"Trxn:%p Session:0x%llx, Phase updated to (Current:'%s', Next: '%s')",
		trxn, (unsigned long long)trxn->session_id,
		mgmt_trxn_commit_phase_str(trxn, true),
		mgmt_trxn_commit_phase_str(trxn, false));
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

static void mgmt_trxn_send_getcfg_reply_data(struct mgmt_trxn_req *trxn_req,
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
	data_reply->next_indx =
		(!get_reply->last_batch ? get_req->total_reply : -1);

	MGMTD_TRXN_DBG("Sending %d Get-Config/Data replies (next-idx:%lld)",
		(int) data_reply->n_data,
		(long long)data_reply->next_indx);

	switch (trxn_req->req_event) {
	case MGMTD_TRXN_PROC_GETCFG:
		if (mgmt_frntnd_send_get_cfg_reply(
			    trxn_req->trxn->session_id, trxn_req->trxn->trxn_id,
			    get_req->db_id, trxn_req->req_id, MGMTD_SUCCESS,
			    data_reply, NULL)
		    != 0) {
			MGMTD_TRXN_ERR(
				"Failed to send GET-CONFIG-REPLY for Trxn %p, Sessn: 0x%llx, Req: %llu",
				trxn_req->trxn,
				(unsigned long long)trxn_req->trxn->session_id,
				(unsigned long long)trxn_req->req_id);
		}
		break;
	case MGMTD_TRXN_PROC_GETDATA:
		if (mgmt_frntnd_send_get_data_reply(
			    trxn_req->trxn->session_id, trxn_req->trxn->trxn_id,
			    get_req->db_id, trxn_req->req_id, MGMTD_SUCCESS,
			    data_reply, NULL)
		    != 0) {
			MGMTD_TRXN_ERR(
				"Failed to send GET-DATA-REPLY for Trxn %p, Sessn: 0x%llx, Req: %llu",
				trxn_req->trxn,
				(unsigned long long)trxn_req->trxn->session_id,
				(unsigned long long)trxn_req->req_id);
		}
		break;
	case MGMTD_TRXN_PROC_SETCFG:
	case MGMTD_TRXN_PROC_COMMITCFG:
	case MGMTD_TRXN_COMMITCFG_TIMEOUT:
	case MGMTD_TRXN_CLEANUP:
		MGMTD_TRXN_ERR("Invalid Trxn-Req-Event %u",
			       trxn_req->req_event);
		break;
	}

	/*
	 * Reset reply buffer for next reply.
	 */
	mgmt_reset_get_data_reply_buf(get_req);
}

static void mgmt_trxn_iter_and_send_get_cfg_reply(struct mgmt_db_ctxt *db_ctxt,
						  char *xpath,
						  struct lyd_node *node,
						  struct nb_node *nb_node,
						  void *ctxt)
{
	struct mgmt_trxn_req *trxn_req;
	struct mgmt_get_data_req *get_req;
	struct mgmt_get_data_reply *get_reply;
	Mgmtd__YangData *data;
	Mgmtd__YangDataValue *data_value;

	trxn_req = (struct mgmt_trxn_req *)ctxt;
	if (!trxn_req)
		goto mgmtd_ignore_get_cfg_reply_data;

	if (!(node->schema->nodetype & LYD_NODE_TERM))
		goto mgmtd_ignore_get_cfg_reply_data;

	assert(trxn_req->req_event == MGMTD_TRXN_PROC_GETCFG
	       || trxn_req->req_event == MGMTD_TRXN_PROC_GETDATA);

	get_req = trxn_req->req.get_data;
	assert(get_req);
	get_reply = get_req->reply;
	data = &get_reply->reply_data[get_reply->num_reply];
	data_value = &get_reply->reply_value[get_reply->num_reply];

	mgmt_yang_data_init(data);
	data->xpath = xpath;
	mgmt_yang_data_value_init(data_value);
	data_value->value_case = MGMTD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
	data_value->encoded_str_val = (char *)lyd_get_value(node);
	data->value = data_value;

	get_reply->num_reply++;
	get_req->total_reply++;
	MGMTD_TRXN_DBG(" [%d] XPATH: '%s', Value: '%s'", get_req->total_reply,
		       data->xpath, data_value->encoded_str_val);

	if (get_reply->num_reply == MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH)
		mgmt_trxn_send_getcfg_reply_data(trxn_req, get_req);

	return;

mgmtd_ignore_get_cfg_reply_data:
	if (xpath)
		free(xpath);
}

static int mgmt_trxn_get_config(struct mgmt_trxn_ctxt *trxn,
				struct mgmt_trxn_req *trxn_req,
				struct mgmt_db_ctxt *db_ctxt)
{
	struct mgmt_trxn_req_list_head *req_list = NULL;
	struct mgmt_trxn_req_list_head *pending_list = NULL;
	int indx;
	struct mgmt_get_data_req *get_data;
	struct mgmt_get_data_reply *get_reply;

	switch (trxn_req->req_event) {
	case MGMTD_TRXN_PROC_GETCFG:
		req_list = &trxn->get_cfg_reqs;
		break;
	case MGMTD_TRXN_PROC_GETDATA:
		req_list = &trxn->get_data_reqs;
		break;
	case MGMTD_TRXN_PROC_SETCFG:
	case MGMTD_TRXN_PROC_COMMITCFG:
	case MGMTD_TRXN_COMMITCFG_TIMEOUT:
	case MGMTD_TRXN_CLEANUP:
		assert(!"Wrong trxn request type!");
		break;
	}

	get_data = trxn_req->req.get_data;

	if (!get_data->reply) {
		get_data->reply = XCALLOC(MTYPE_MGMTD_TRXN_GETDATA_REPLY,
					  sizeof(struct mgmt_get_data_reply));
		if (!get_data->reply) {
			mgmt_frntnd_send_get_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				get_data->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, NULL,
				"Internal error: Unable to allocate reply buffers!");
			goto mgmt_trxn_get_config_failed;
		}
	}

	/*
	 * Read data contents from the DB and respond back directly.
	 * No need to go to backend for getting data.
	 */
	get_reply = get_data->reply;
	for (indx = 0; indx < get_data->num_xpaths; indx++) {
		MGMTD_TRXN_DBG("Trying to get all data under '%s'",
			       get_data->xpaths[indx]);
		mgmt_init_get_data_reply(get_reply);
		if (mgmt_db_iter_data(get_data->db_ctxt, get_data->xpaths[indx],
				      mgmt_trxn_iter_and_send_get_cfg_reply,
				      (void *)trxn_req, true)
		    == -1) {
			MGMTD_TRXN_DBG("Invalid Xpath '%s",
				       get_data->xpaths[indx]);
			mgmt_frntnd_send_get_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				get_data->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, NULL, "Invalid xpath");
			goto mgmt_trxn_get_config_failed;
		}
		MGMTD_TRXN_DBG("Got %d remaining data-replies for xpath '%s'",
			       get_reply->num_reply, get_data->xpaths[indx]);
		get_reply->last_batch = true;
		mgmt_trxn_send_getcfg_reply_data(trxn_req, get_data);
	}

mgmt_trxn_get_config_failed:

	if (pending_list) {
		/*
		 * Move the transaction to corresponding pending list.
		 */
		if (req_list)
			mgmt_trxn_req_list_del(req_list, trxn_req);
		trxn_req->pending_bknd_proc = true;
		mgmt_trxn_req_list_add_tail(pending_list, trxn_req);
		MGMTD_TRXN_DBG(
			"Moved Req: %p for Trxn: %p from Req-List to Pending-List",
			trxn_req, trxn_req->trxn);
	} else {
		/*
		 * Delete the trxn request. It will also remove it from request
		 * list.
		 */
		mgmt_trxn_req_free(&trxn_req);
	}

	return 0;
}

static void mgmt_trxn_process_get_cfg(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	struct mgmt_db_ctxt *db_ctxt;
	int num_processed = 0;
	bool error;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);

	MGMTD_TRXN_DBG(
		"Processing %d GET_CONFIG requests for Trxn:%p Session:0x%llx",
		(int)mgmt_trxn_req_list_count(&trxn->get_cfg_reqs), trxn,
		(unsigned long long)trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST (&trxn->get_cfg_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == MGMTD_TRXN_PROC_GETCFG);
		db_ctxt = trxn_req->req.get_data->db_ctxt;
		if (!db_ctxt) {
			mgmt_frntnd_send_get_cfg_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.get_data->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, NULL,
				"No such database!");
			error = true;
			goto mgmt_trxn_process_get_cfg_done;
		}

		if (mgmt_trxn_get_config(trxn, trxn_req, db_ctxt) != 0) {
			MGMTD_TRXN_ERR(
				"Unable to retrieve Config from DB %d for Trxn %p, Sessn: 0x%llx, Req: %llu!",
				trxn_req->req.get_data->db_id, trxn,
				(unsigned long long)trxn->session_id,
				(unsigned long long)trxn_req->req_id);
			error = true;
		}

	mgmt_trxn_process_get_cfg_done:

		if (error) {
			/*
			 * Delete the trxn request.
			 * Note: The following will remove it from the list
			 * as well.
			 */
			mgmt_trxn_req_free(&trxn_req);
		}

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */
		num_processed++;
		if (num_processed == MGMTD_TRXN_MAX_NUM_GETCFG_PROC)
			break;
	}

	if (mgmt_trxn_req_list_count(&trxn->get_cfg_reqs)) {
		MGMTD_TRXN_DBG(
			"Processed maximum number of Get-Config requests (%d/%d). Rescheduling for rest.",
			num_processed, MGMTD_TRXN_MAX_NUM_GETCFG_PROC);
		mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_GETCFG);
	}
}

static void mgmt_trxn_process_get_data(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	struct mgmt_db_ctxt *db_ctxt;
	int num_processed = 0;
	bool error;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);

	MGMTD_TRXN_DBG(
		"Processing %d GET_DATA requests for Trxn:%p Session:0x%llx",
		(int)mgmt_trxn_req_list_count(&trxn->get_data_reqs), trxn,
		(unsigned long long)trxn->session_id);

	FOREACH_TRXN_REQ_IN_LIST (&trxn->get_data_reqs, trxn_req) {
		error = false;
		assert(trxn_req->req_event == MGMTD_TRXN_PROC_GETDATA);
		db_ctxt = trxn_req->req.get_data->db_ctxt;
		if (!db_ctxt) {
			mgmt_frntnd_send_get_data_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.get_data->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, NULL,
				"No such database!");
			error = true;
			goto mgmt_trxn_process_get_data_done;
		}

		if (mgmt_db_is_config(db_ctxt)) {
			if (mgmt_trxn_get_config(trxn, trxn_req, db_ctxt)
			    != 0) {
				MGMTD_TRXN_ERR(
					"Unable to retrieve Config from DB %d for Trxn %p, Sessn: 0x%llx, Req: %llu!",
					trxn_req->req.get_data->db_id, trxn,
					(unsigned long long)trxn->session_id,
					(unsigned long long)trxn_req->req_id);
				error = true;
			}
		} else {
			/*
			 * TODO: Trigger GET procedures for Backend
			 * For now return back error.
			 */
			mgmt_frntnd_send_get_data_reply(
				trxn->session_id, trxn->trxn_id,
				trxn_req->req.get_data->db_id, trxn_req->req_id,
				MGMTD_INTERNAL_ERROR, NULL,
				"GET-DATA on Oper DB is not supported yet!");
			error = true;
		}

	mgmt_trxn_process_get_data_done:

		if (error) {
			/*
			 * Delete the trxn request.
			 * Note: The following will remove it from the list
			 * as well.
			 */
			mgmt_trxn_req_free(&trxn_req);
		}

		/*
		 * Else the transaction would have been already deleted or
		 * moved to corresponding pending list. No need to delete it.
		 */
		num_processed++;
		if (num_processed == MGMTD_TRXN_MAX_NUM_GETDATA_PROC)
			break;
	}

	if (mgmt_trxn_req_list_count(&trxn->get_data_reqs)) {
		MGMTD_TRXN_DBG(
			"Processed maximum number of Get-Data requests (%d/%d). Rescheduling for rest.",
			num_processed, MGMTD_TRXN_MAX_NUM_GETDATA_PROC);
		mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_GETDATA);
	}
}

static struct mgmt_trxn_ctxt *
mgmt_frntnd_find_trxn_by_session_id(struct mgmt_master *cm, uint64_t session_id,
				    enum mgmt_trxn_type type)
{
	struct mgmt_trxn_ctxt *trxn;

	FOREACH_TRXN_IN_LIST (cm, trxn) {
		if (trxn->session_id == session_id && trxn->type == type)
			return trxn;
	}

	return NULL;
}

static struct mgmt_trxn_ctxt *mgmt_trxn_create_new(uint64_t session_id,
						   enum mgmt_trxn_type type)
{
	struct mgmt_trxn_ctxt *trxn = NULL;

	/*
	 * For 'CONFIG' transaction check if one is already created
	 * or not.
	 */
	if (type == MGMTD_TRXN_TYPE_CONFIG && mgmt_trxn_mm->cfg_trxn) {
		if (mgmt_config_trxn_in_progress() == session_id)
			trxn = mgmt_trxn_mm->cfg_trxn;
		goto mgmt_create_trxn_done;
	}

	trxn = mgmt_frntnd_find_trxn_by_session_id(mgmt_trxn_mm, session_id,
						   type);
	if (!trxn) {
		trxn = XCALLOC(MTYPE_MGMTD_TRXN, sizeof(struct mgmt_trxn_ctxt));
		assert(trxn);

		trxn->session_id = session_id;
		trxn->type = type;
		mgmt_trxn_badptr_list_init(&trxn->bcknd_adptrs);
		mgmt_trxn_list_add_tail(&mgmt_trxn_mm->trxn_list, trxn);
		mgmt_trxn_req_list_init(&trxn->set_cfg_reqs);
		mgmt_trxn_req_list_init(&trxn->get_cfg_reqs);
		mgmt_trxn_req_list_init(&trxn->get_data_reqs);
		mgmt_trxn_req_list_init(&trxn->pending_get_datas);
		trxn->commit_cfg_req = NULL;
		trxn->refcount = 0;
		if (!mgmt_trxn_mm->next_trxn_id)
			mgmt_trxn_mm->next_trxn_id++;
		trxn->trxn_id = mgmt_trxn_mm->next_trxn_id++;
		hash_get(mgmt_trxn_mm->trxn_hash, trxn, hash_alloc_intern);

		MGMTD_TRXN_DBG("Added new '%s' MGMTD Transaction '%p'",
			       mgmt_trxn_type2str(type), trxn);

		if (type == MGMTD_TRXN_TYPE_CONFIG)
			mgmt_trxn_mm->cfg_trxn = trxn;

		MGMTD_TRXN_LOCK(trxn);
	}

mgmt_create_trxn_done:
	return trxn;
}

static void mgmt_trxn_delete(struct mgmt_trxn_ctxt **trxn)
{
	MGMTD_TRXN_UNLOCK(trxn);
}

static unsigned int mgmt_trxn_hash_key(const void *data)
{
	const struct mgmt_trxn_ctxt *trxn = data;

	return jhash2((uint32_t *) &trxn->trxn_id,
		      sizeof(trxn->trxn_id) / sizeof(uint32_t), 0);
}

static bool mgmt_trxn_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_trxn_ctxt *trxn1 = d1;
	const struct mgmt_trxn_ctxt *trxn2 = d2;

	return (trxn1->trxn_id == trxn2->trxn_id);
}

static void mgmt_trxn_hash_free(void *data)
{
	struct mgmt_trxn_ctxt *trxn = data;

	mgmt_trxn_delete(&trxn);
}

static void mgmt_trxn_hash_init(void)
{
	if (!mgmt_trxn_mm || mgmt_trxn_mm->trxn_hash)
		return;

	mgmt_trxn_mm->trxn_hash = hash_create(mgmt_trxn_hash_key,
					      mgmt_trxn_hash_cmp,
					      "MGMT Transactions");
}

static void mgmt_trxn_hash_destroy(void)
{
	if (!mgmt_trxn_mm || !mgmt_trxn_mm->trxn_hash)
		return;

	hash_clean(mgmt_trxn_mm->trxn_hash,
		   mgmt_trxn_hash_free);
	hash_free(mgmt_trxn_mm->trxn_hash);
	mgmt_trxn_mm->trxn_hash = NULL;
}

static inline struct mgmt_trxn_ctxt *
mgmt_trxn_id2ctxt(uint64_t trxn_id)
{
	struct mgmt_trxn_ctxt key = {0};
	struct mgmt_trxn_ctxt *trxn;

	if (!mgmt_trxn_mm || !mgmt_trxn_mm->trxn_hash)
		return NULL;

	key.trxn_id = trxn_id;
	trxn = hash_lookup(mgmt_trxn_mm->trxn_hash, &key);

	return trxn;
}

static void mgmt_trxn_lock(struct mgmt_trxn_ctxt *trxn, const char *file,
			   int line)
{
	trxn->refcount++;
	MGMTD_TRXN_DBG("%s:%d --> Lock %s Trxn %p, Count: %d", file, line,
		       mgmt_trxn_type2str(trxn->type), trxn, trxn->refcount);
}

static void mgmt_trxn_unlock(struct mgmt_trxn_ctxt **trxn, const char *file,
			     int line)
{
	assert(*trxn && (*trxn)->refcount);

	(*trxn)->refcount--;
	MGMTD_TRXN_DBG("%s:%d --> Unlock %s Trxn %p, Count: %d", file, line,
		       mgmt_trxn_type2str((*trxn)->type), *trxn,
		       (*trxn)->refcount);
	if (!(*trxn)->refcount) {
		if ((*trxn)->type == MGMTD_TRXN_TYPE_CONFIG)
			if (mgmt_trxn_mm->cfg_trxn == *trxn)
				mgmt_trxn_mm->cfg_trxn = NULL;
		THREAD_OFF((*trxn)->proc_get_cfg);
		THREAD_OFF((*trxn)->proc_get_data);
		THREAD_OFF((*trxn)->proc_comm_cfg);
		THREAD_OFF((*trxn)->comm_cfg_timeout);
		hash_release(mgmt_trxn_mm->trxn_hash, *trxn);
		mgmt_trxn_list_del(&mgmt_trxn_mm->trxn_list, *trxn);

		MGMTD_TRXN_DBG("Deleted %s Trxn %p for Sessn: 0x%llx",
			       mgmt_trxn_type2str((*trxn)->type), *trxn,
			       (unsigned long long)(*trxn)->session_id);

		XFREE(MTYPE_MGMTD_TRXN, *trxn);
	}

	*trxn = NULL;
}

static void mgmt_trxn_cleanup_trxn(struct mgmt_trxn_ctxt **trxn)
{
	/* TODO: Any other cleanup applicable */

	mgmt_trxn_delete(trxn);
}

static void
mgmt_trxn_cleanup_all_trxns(void)
{
	struct mgmt_trxn_ctxt *trxn;

	if (!mgmt_trxn_mm || !mgmt_trxn_mm->trxn_hash)
		return;

	FOREACH_TRXN_IN_LIST (mgmt_trxn_mm, trxn)
		mgmt_trxn_cleanup_trxn(&trxn);
}

static void mgmt_trxn_cleanup(struct thread *thread)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = (struct mgmt_trxn_ctxt *)THREAD_ARG(thread);
	assert(trxn);

	mgmt_trxn_cleanup_trxn(&trxn);
}

static void mgmt_trxn_register_event(struct mgmt_trxn_ctxt *trxn,
				     enum mgmt_trxn_event event)
{
	struct timeval tv = {.tv_sec = 0,
			     .tv_usec = MGMTD_TRXN_PROC_DELAY_USEC};

	assert(mgmt_trxn_mm && mgmt_trxn_tm);

	switch (event) {
	case MGMTD_TRXN_PROC_SETCFG:
		thread_add_timer_tv(mgmt_trxn_tm, mgmt_trxn_process_set_cfg,
				    trxn, &tv, &trxn->proc_set_cfg);
		assert(trxn->proc_set_cfg);
		break;
	case MGMTD_TRXN_PROC_COMMITCFG:
		thread_add_timer_tv(mgmt_trxn_tm, mgmt_trxn_process_commit_cfg,
				    trxn, &tv, &trxn->proc_comm_cfg);
		assert(trxn->proc_comm_cfg);
		break;
	case MGMTD_TRXN_PROC_GETCFG:
		thread_add_timer_tv(mgmt_trxn_tm, mgmt_trxn_process_get_cfg,
				    trxn, &tv, &trxn->proc_get_cfg);
		assert(trxn->proc_get_cfg);
		break;
	case MGMTD_TRXN_PROC_GETDATA:
		thread_add_timer_tv(mgmt_trxn_tm, mgmt_trxn_process_get_data,
				    trxn, &tv, &trxn->proc_get_data);
		assert(trxn->proc_get_data);
		break;
	case MGMTD_TRXN_COMMITCFG_TIMEOUT:
		thread_add_timer_msec(mgmt_trxn_tm,
				      mgmt_trxn_cfg_commit_timedout, trxn,
				      MGMTD_TRXN_CFG_COMMIT_MAX_DELAY_MSEC,
				      &trxn->comm_cfg_timeout);
		assert(trxn->comm_cfg_timeout);
		break;
	case MGMTD_TRXN_CLEANUP:
		tv.tv_usec = MGMTD_TRXN_CLEANUP_DELAY_USEC;
		thread_add_timer_tv(mgmt_trxn_tm, mgmt_trxn_cleanup, trxn, &tv,
				    &trxn->clnup);
		assert(trxn->clnup);
	}
}

int mgmt_trxn_init(struct mgmt_master *mm, struct thread_master *tm)
{
	if (mgmt_trxn_mm || mgmt_trxn_tm)
		assert(!"MGMTD TRXN: Call trxn_init() only once");

	mgmt_trxn_mm = mm;
	mgmt_trxn_tm = tm;
	mgmt_trxn_list_init(&mm->trxn_list);
	mgmt_trxn_hash_init();
	assert(!mm->cfg_trxn);
	mm->cfg_trxn = NULL;

	return 0;
}

void mgmt_trxn_destroy(void)
{
	mgmt_trxn_cleanup_all_trxns();
	mgmt_trxn_hash_destroy();
}

uint64_t mgmt_config_trxn_in_progress(void)
{
	if (mgmt_trxn_mm && mgmt_trxn_mm->cfg_trxn)
		return mgmt_trxn_mm->cfg_trxn->session_id;

	return MGMTD_SESSION_ID_NONE;
}

uint64_t mgmt_create_trxn(uint64_t session_id, enum mgmt_trxn_type type)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = mgmt_trxn_create_new(session_id, type);
	return trxn ? trxn->trxn_id : MGMTD_TRXN_ID_NONE;
}

bool mgmt_trxn_id_is_valid(uint64_t trxn_id)
{
	return mgmt_trxn_id2ctxt(trxn_id) ? true : false;
}

void mgmt_destroy_trxn(uint64_t *trxn_id)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = mgmt_trxn_id2ctxt(*trxn_id);
	if (!trxn)
		return;

	mgmt_trxn_delete(&trxn);
	*trxn_id = MGMTD_TRXN_ID_NONE;
}

enum mgmt_trxn_type mgmt_get_trxn_type(uint64_t trxn_id)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return MGMTD_TRXN_TYPE_NONE;

	return trxn->type;
}

int mgmt_trxn_send_set_config_req(uint64_t trxn_id, uint64_t req_id,
				  Mgmtd__DatabaseId db_id,
				  struct mgmt_db_ctxt *db_ctxt,
				  Mgmtd__YangCfgDataReq **cfg_req,
				  size_t num_req, bool implicit_commit,
				  Mgmtd__DatabaseId dst_db_id,
				  struct mgmt_db_ctxt *dst_db_ctxt)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	size_t indx;
	uint16_t *num_chgs;
	struct nb_cfg_change *cfg_chg;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return -1;

	if (implicit_commit && mgmt_trxn_req_list_count(&trxn->set_cfg_reqs)) {
		MGMTD_TRXN_ERR(
			"For implicit commit config only one SETCFG-REQ can be allowed!");
		return -1;
	}

	trxn_req = mgmt_trxn_req_alloc(trxn, req_id, MGMTD_TRXN_PROC_SETCFG);
	trxn_req->req.set_cfg->db_id = db_id;
	trxn_req->req.set_cfg->db_ctxt = db_ctxt;
	num_chgs = &trxn_req->req.set_cfg->num_cfg_changes;
	for (indx = 0; indx < num_req; indx++) {
		cfg_chg = &trxn_req->req.set_cfg->cfg_changes[*num_chgs];

		if (cfg_req[indx]->req_type
		    == MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA)
			cfg_chg->operation = NB_OP_DESTROY;
		else if (cfg_req[indx]->req_type
			 == MGMTD__CFG_DATA_REQ_TYPE__SET_DATA)
			cfg_chg->operation =
				mgmt_db_find_data_node_by_xpath(
					db_ctxt, cfg_req[indx]->data->xpath)
					? NB_OP_MODIFY
					: NB_OP_CREATE;
		else
			continue;

		MGMTD_TRXN_DBG(
			"XPath: '%s', Value: '%s'", cfg_req[indx]->data->xpath,
			(cfg_req[indx]->data->value
					 && cfg_req[indx]
						    ->data->value
						    ->encoded_str_val
				 ? cfg_req[indx]->data->value->encoded_str_val
				 : "NULL"));
		strlcpy(cfg_chg->xpath, cfg_req[indx]->data->xpath,
			sizeof(cfg_chg->xpath));
		cfg_chg->value = (cfg_req[indx]->data->value
						  && cfg_req[indx]
							     ->data->value
							     ->encoded_str_val
					  ? strdup(cfg_req[indx]
							   ->data->value
							   ->encoded_str_val)
					  : NULL);
		if (cfg_chg->value)
			MGMTD_TRXN_DBG("Allocated value at %p ==> '%s'",
				       cfg_chg->value, cfg_chg->value);

		(*num_chgs)++;
	}
	trxn_req->req.set_cfg->implicit_commit = implicit_commit;
	trxn_req->req.set_cfg->dst_db_id = dst_db_id;
	trxn_req->req.set_cfg->dst_db_ctxt = dst_db_ctxt;
	trxn_req->req.set_cfg->setcfg_stats =
		mgmt_frntnd_get_sessn_setcfg_stats(trxn->session_id);
	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_SETCFG);

	return 0;
}

int mgmt_trxn_send_commit_config_req(uint64_t trxn_id, uint64_t req_id,
				     Mgmtd__DatabaseId src_db_id,
				     struct mgmt_db_ctxt *src_db_ctxt,
				     Mgmtd__DatabaseId dst_db_id,
				     struct mgmt_db_ctxt *dst_db_ctxt,
				     bool validate_only, bool abort,
				     bool implicit)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return -1;

	if (trxn->commit_cfg_req) {
		MGMTD_TRXN_ERR(
			"A commit is already in-progress for Trxn %p, session 0x%llx. Cannot start another!",
			trxn, (unsigned long long)trxn->session_id);
		return -1;
	}

	trxn_req = mgmt_trxn_req_alloc(trxn, req_id, MGMTD_TRXN_PROC_COMMITCFG);
	trxn_req->req.commit_cfg.src_db_id = src_db_id;
	trxn_req->req.commit_cfg.src_db_ctxt = src_db_ctxt;
	trxn_req->req.commit_cfg.dst_db_id = dst_db_id;
	trxn_req->req.commit_cfg.dst_db_ctxt = dst_db_ctxt;
	trxn_req->req.commit_cfg.validate_only = validate_only;
	trxn_req->req.commit_cfg.abort = abort;
	trxn_req->req.commit_cfg.implicit = implicit;
	trxn_req->req.commit_cfg.cmt_stats =
		mgmt_frntnd_get_sessn_commit_stats(trxn->session_id);

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_COMMITCFG);
	return 0;
}

int mgmt_trxn_notify_bcknd_adapter_conn(struct mgmt_bcknd_client_adapter *adptr,
					bool connect)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	struct mgmt_commit_cfg_req *cmtcfg_req;
	static struct mgmt_commit_stats dummy_stats;
	struct nb_config_cbs *adptr_cfgs = NULL;

	memset(&dummy_stats, 0, sizeof(dummy_stats));
	if (connect) {
		/* Get config for this single backend client */
		mgmt_bcknd_get_adapter_config(adptr, mm->running_db,
					      &adptr_cfgs);

		if (!adptr_cfgs || RB_EMPTY(nb_config_cbs, adptr_cfgs)) {
			SET_FLAG(adptr->flags,
				 MGMTD_BCKND_ADPTR_FLAGS_CFG_SYNCED);
			return 0;
		}

		/*
		 * Create a CONFIG transaction to push the config changes
		 * provided to the backend client.
		 */
		trxn = mgmt_trxn_create_new(0, MGMTD_TRXN_TYPE_CONFIG);
		if (!trxn) {
			MGMTD_TRXN_ERR(
				"Failed to create CONFIG Transaction for downloading CONFIGs for client '%s'",
				adptr->name);
			return -1;
		}

		/*
		 * Set the changeset for transaction to commit and trigger the
		 * commit request.
		 */
		trxn_req =
			mgmt_trxn_req_alloc(trxn, 0, MGMTD_TRXN_PROC_COMMITCFG);
		trxn_req->req.commit_cfg.src_db_id = MGMTD_DB_NONE;
		trxn_req->req.commit_cfg.src_db_ctxt = 0;
		trxn_req->req.commit_cfg.dst_db_id = MGMTD_DB_NONE;
		trxn_req->req.commit_cfg.dst_db_ctxt = 0;
		trxn_req->req.commit_cfg.validate_only = false;
		trxn_req->req.commit_cfg.abort = false;
		trxn_req->req.commit_cfg.cmt_stats = &dummy_stats;
		trxn_req->req.commit_cfg.cfg_chgs = adptr_cfgs;

		/*
		 * Trigger a COMMIT-CONFIG process.
		 */
		mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_COMMITCFG);

	} else {
		/*
		 * Check if any transaction is currently on-going that
		 * involves this backend client. If so, report the transaction
		 * has failed.
		 */
		FOREACH_TRXN_IN_LIST (mgmt_trxn_mm, trxn) {
			if (trxn->type == MGMTD_TRXN_TYPE_CONFIG) {
				cmtcfg_req = trxn->commit_cfg_req
						     ? &trxn->commit_cfg_req
								->req.commit_cfg
						     : NULL;
				if (cmtcfg_req
				    && cmtcfg_req->subscr_info
					       .xpath_subscr[adptr->id]
					       .subscribed) {
					mgmt_trxn_send_commit_cfg_reply(
						trxn, MGMTD_INTERNAL_ERROR,
						"Backend daemon disconnected while processing commit!");
				}
			}
		}
	}

	return 0;
}

int mgmt_trxn_notify_bcknd_trxn_reply(uint64_t trxn_id, bool create,
				      bool success,
				      struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn || trxn->type != MGMTD_TRXN_TYPE_CONFIG)
		return -1;

	if (!create && !trxn->commit_cfg_req)
		return 0;

	assert(trxn->commit_cfg_req);
	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;
	if (create) {
		if (success) {
			/*
			 * Done with TRXN_CREATE. Move the backend client to
			 * next phase.
			 */
			assert(cmtcfg_req->curr_phase
			       == MGMTD_COMMIT_PHASE_TRXN_CREATE);

			/*
			 * Send CFGDATA_CREATE-REQs to the backend immediately.
			 */
			mgmt_trxn_send_bcknd_cfg_data(trxn, adptr);
		} else {
			mgmt_trxn_send_commit_cfg_reply(
				trxn, MGMTD_INTERNAL_ERROR,
				"Internal error! Failed to initiate transaction at backend!");
		}
	} else {
		/*
		 * Done with TRXN_DELETE. Move the backend client to next phase.
		 */
		if (false)
			mgmt_move_bcknd_commit_to_next_phase(trxn, adptr);
	}

	return 0;
}

int mgmt_trxn_notify_bcknd_cfgdata_reply(
	uint64_t trxn_id, uint64_t batch_id, bool success, char *error_if_any,
	struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn || trxn->type != MGMTD_TRXN_TYPE_CONFIG)
		return -1;

	if (!trxn->commit_cfg_req)
		return -1;
	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;

	cfg_btch = mgmt_trxn_cfgbatch_id2ctxt(trxn, batch_id);
	if (!cfg_btch || cfg_btch->trxn != trxn)
		return -1;

	if (!success) {
		MGMTD_TRXN_ERR(
			"CFGDATA_CREATE_REQ sent to '%s' failed for Trxn %p, Batch %p, Err: %s",
			adptr->name, trxn, cfg_btch,
			error_if_any ? error_if_any : "None");
		mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INTERNAL_ERROR,
			"Internal error! Failed to download config data to backend!");
		return 0;
	}

	MGMTD_TRXN_DBG(
		"CFGDATA_CREATE_REQ sent to '%s' was successful for Trxn %p, Batch %p, Err: %s",
		adptr->name, trxn, cfg_btch,
		error_if_any ? error_if_any : "None");
	mgmt_move_trxn_cfg_batch_to_next(
		cmtcfg_req, cfg_btch, &cmtcfg_req->curr_batches[adptr->id],
		&cmtcfg_req->next_batches[adptr->id], true,
#ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED
		MGMTD_COMMIT_PHASE_VALIDATE_CFG);
#else  /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */
		MGMTD_COMMIT_PHASE_APPLY_CFG);
#endif /* ifndef MGMTD_LOCAL_VALIDATIONS_ENABLED */

	mgmt_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

int mgmt_trxn_notify_bcknd_cfg_validate_reply(
	uint64_t trxn_id, bool success, uint64_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
	struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;
	size_t indx;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn || trxn->type != MGMTD_TRXN_TYPE_CONFIG)
		return -1;

	assert(trxn->commit_cfg_req);
	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		MGMTD_TRXN_ERR(
			"CFGDATA_VALIDATE_REQ sent to '%s' failed for Trxn %p, Batches [0x%llx - 0x%llx], Err: %s",
			adptr->name, trxn, (unsigned long long)batch_ids[0],
			(unsigned long long)batch_ids[num_batch_ids - 1],
			error_if_any ? error_if_any : "None");
		mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INTERNAL_ERROR,
			"Internal error! Failed to validate config data on backend!");
		return 0;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		cfg_btch = mgmt_trxn_cfgbatch_id2ctxt(trxn, batch_ids[indx]);
		if (cfg_btch->trxn != trxn)
			return -1;
		mgmt_move_trxn_cfg_batch_to_next(
			cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			MGMTD_COMMIT_PHASE_APPLY_CFG);
	}

	mgmt_try_move_commit_to_next_phase(trxn, cmtcfg_req);

	return 0;
}

extern int
mgmt_trxn_notify_bcknd_cfg_apply_reply(uint64_t trxn_id, bool success,
				       uint64_t batch_ids[],
				       size_t num_batch_ids, char *error_if_any,
				       struct mgmt_bcknd_client_adapter *adptr)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_bcknd_cfg_batch *cfg_btch;
	struct mgmt_commit_cfg_req *cmtcfg_req = NULL;
	size_t indx;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn || trxn->type != MGMTD_TRXN_TYPE_CONFIG
	    || !trxn->commit_cfg_req)
		return -1;

	cmtcfg_req = &trxn->commit_cfg_req->req.commit_cfg;

	if (!success) {
		MGMTD_TRXN_ERR(
			"CFGDATA_APPLY_REQ sent to '%s' failed for Trxn %p, Batches [0x%llx - 0x%llx], Err: %s",
			adptr->name, trxn, (unsigned long long)batch_ids[0],
			(unsigned long long)batch_ids[num_batch_ids - 1],
			error_if_any ? error_if_any : "None");
		mgmt_trxn_send_commit_cfg_reply(
			trxn, MGMTD_INTERNAL_ERROR,
			"Internal error! Failed to apply config data on backend!");
		return 0;
	}

	for (indx = 0; indx < num_batch_ids; indx++) {
		cfg_btch = mgmt_trxn_cfgbatch_id2ctxt(trxn, batch_ids[indx]);
		if (cfg_btch->trxn != trxn)
			return -1;
		mgmt_move_trxn_cfg_batch_to_next(
			cmtcfg_req, cfg_btch,
			&cmtcfg_req->curr_batches[adptr->id],
			&cmtcfg_req->next_batches[adptr->id], true,
			MGMTD_COMMIT_PHASE_TRXN_DELETE);
	}

	if (!mgmt_trxn_batch_list_count(&cmtcfg_req->curr_batches[adptr->id])) {
		/*
		 * All configuration for the specific backend has been applied.
		 * Send TRXN-DELETE to wrap up the transaction for this backend.
		 */
		SET_FLAG(adptr->flags, MGMTD_BCKND_ADPTR_FLAGS_CFG_SYNCED);
		mgmt_trxn_send_bcknd_trxn_delete(trxn, adptr);
	}

	mgmt_try_move_commit_to_next_phase(trxn, cmtcfg_req);
	if (mm->perf_stats_en)
		gettimeofday(&cmtcfg_req->cmt_stats->apply_cfg_end, NULL);

	return 0;
}

int mgmt_trxn_send_commit_config_reply(uint64_t trxn_id,
				       enum mgmt_result result,
				       const char *error_if_any)
{
	struct mgmt_trxn_ctxt *trxn;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return -1;

	if (!trxn->commit_cfg_req) {
		MGMTD_TRXN_ERR(
			"NO commit in-progress for Trxn %p, session 0x%llx!",
			trxn, (unsigned long long)trxn->session_id);
		return -1;
	}

	return mgmt_trxn_send_commit_cfg_reply(trxn, result, error_if_any);
}

int mgmt_trxn_send_get_config_req(uint64_t trxn_id, uint64_t req_id,
				  Mgmtd__DatabaseId db_id,
				  struct mgmt_db_ctxt *db_ctxt,
				  Mgmtd__YangGetDataReq **data_req,
				  size_t num_reqs)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	size_t indx;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return -1;

	trxn_req = mgmt_trxn_req_alloc(trxn, req_id, MGMTD_TRXN_PROC_GETCFG);
	trxn_req->req.get_data->db_id = db_id;
	trxn_req->req.get_data->db_ctxt = db_ctxt;
	for (indx = 0;
	     indx < num_reqs && indx < MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH;
	     indx++) {
		MGMTD_TRXN_DBG("XPath: '%s'", data_req[indx]->data->xpath);
		trxn_req->req.get_data->xpaths[indx] =
			strdup(data_req[indx]->data->xpath);
		trxn_req->req.get_data->num_xpaths++;
	}

	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_GETCFG);

	return 0;
}

int mgmt_trxn_send_get_data_req(uint64_t trxn_id, uint64_t req_id,
				Mgmtd__DatabaseId db_id,
				struct mgmt_db_ctxt *db_ctxt,
				Mgmtd__YangGetDataReq **data_req,
				size_t num_reqs)
{
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	size_t indx;

	trxn = mgmt_trxn_id2ctxt(trxn_id);
	if (!trxn)
		return -1;

	trxn_req = mgmt_trxn_req_alloc(trxn, req_id, MGMTD_TRXN_PROC_GETDATA);
	trxn_req->req.get_data->db_id = db_id;
	trxn_req->req.get_data->db_ctxt = db_ctxt;
	for (indx = 0;
	     indx < num_reqs && indx < MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH;
	     indx++) {
		MGMTD_TRXN_DBG("XPath: '%s'", data_req[indx]->data->xpath);
		trxn_req->req.get_data->xpaths[indx] =
			strdup(data_req[indx]->data->xpath);
		trxn_req->req.get_data->num_xpaths++;
	}

	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_GETDATA);

	return 0;
}

void mgmt_trxn_status_write(struct vty *vty)
{
	struct mgmt_trxn_ctxt *trxn;

	vty_out(vty, "MGMTD Transactions\n");

	FOREACH_TRXN_IN_LIST (mgmt_trxn_mm, trxn) {
		vty_out(vty, "  Trxn: \t\t\t%p\n", trxn);
		vty_out(vty, "    Trxn-Id: \t\t\t%llu\n",
			(unsigned long long)trxn->trxn_id);
		vty_out(vty, "    Session-Id: \t\t%llu\n",
			(unsigned long long)trxn->session_id);
		vty_out(vty, "    Type: \t\t\t%s\n",
			mgmt_trxn_type2str(trxn->type));
		vty_out(vty, "    Ref-Count: \t\t\t%d\n", trxn->refcount);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_trxn_list_count(&mgmt_trxn_mm->trxn_list));
}

int mgmt_trxn_rollback_trigger_cfg_apply(struct mgmt_db_ctxt *src_db_ctxt,
					 struct mgmt_db_ctxt *dst_db_ctxt)
{
	static struct nb_config_cbs changes;
	struct nb_config_cbs *cfg_chgs = NULL;
	struct mgmt_trxn_ctxt *trxn;
	struct mgmt_trxn_req *trxn_req;
	static struct mgmt_commit_stats dummy_stats;

	memset(&changes, 0, sizeof(changes));
	memset(&dummy_stats, 0, sizeof(dummy_stats));
	/*
	 * This could be the case when the config is directly
	 * loaded onto the candidate DB from a file. Get the
	 * diff from a full comparison of the candidate and
	 * running DBs.
	 */
	nb_config_diff(mgmt_db_get_nb_config(dst_db_ctxt),
		       mgmt_db_get_nb_config(src_db_ctxt), &changes);
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
	trxn = mgmt_trxn_create_new(0, MGMTD_TRXN_TYPE_CONFIG);
	if (!trxn) {
		MGMTD_TRXN_ERR(
			"Failed to create CONFIG Transaction for downloading CONFIGs");
		return -1;
	}

	/*
	 * Set the changeset for transaction to commit and trigger the commit
	 * request.
	 */
	trxn_req = mgmt_trxn_req_alloc(trxn, 0, MGMTD_TRXN_PROC_COMMITCFG);
	trxn_req->req.commit_cfg.src_db_id = MGMTD_DB_CANDIDATE;
	trxn_req->req.commit_cfg.src_db_ctxt = src_db_ctxt;
	trxn_req->req.commit_cfg.dst_db_id = MGMTD_DB_RUNNING;
	trxn_req->req.commit_cfg.dst_db_ctxt = dst_db_ctxt;
	trxn_req->req.commit_cfg.validate_only = false;
	trxn_req->req.commit_cfg.abort = false;
	trxn_req->req.commit_cfg.rollback = true;
	trxn_req->req.commit_cfg.cmt_stats = &dummy_stats;
	trxn_req->req.commit_cfg.cfg_chgs = cfg_chgs;

	/*
	 * Trigger a COMMIT-CONFIG process.
	 */
	mgmt_trxn_register_event(trxn, MGMTD_TRXN_PROC_COMMITCFG);
	return 0;
}
