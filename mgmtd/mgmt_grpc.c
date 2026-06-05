// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmtd gRPC northbound integration.
 * Copyright (C) 2026  Eric Parsonage
 *
 * Bridges gRPC northbound operations from lib/northbound_grpc.cpp into
 * mgmtd's central datastore and backend transaction machinery.
 */

#include <zebra.h>

#include "darr.h"
#include "libfrr.h"
#include "northbound.h"
#include "yang.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_fe_adapter.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_txn.h"

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_fe, "GRPC: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

struct mgmt_grpc_rpc_req {
	/*
	 * mgmtd normally completes these requests on mm->master.  The mutex
	 * keeps the completion path defensive against shutdown and future
	 * dispatchers that may complete from outside that event loop.
	 */
	pthread_mutex_t mtx;
	unsigned int refcnt;
	bool done;
	bool dispatched;
	uint64_t txn_id;
	uint64_t req_id;

	char *xpath;
	struct lyd_node *input;
	struct lyd_node *output;
	struct event *event;
	int error;
	char *errstr;
	nb_rpc_dispatch_done_cb done_cb;
	void *done_arg;

	LIST_ENTRY(mgmt_grpc_rpc_req) link;
};

struct mgmt_grpc_config_req {
	pthread_mutex_t mtx;
	unsigned int refcnt;
	bool done;
	bool dispatched;
	uint64_t txn_id;
	uint64_t req_id;
	enum nb_config_commit_phase phase;

	struct nb_config *candidate;
	struct nb_config *candidate_backup;
	struct event *event;
	int error;
	char *errstr;
	nb_config_commit_done_cb done_cb;
	void *done_arg;

	LIST_ENTRY(mgmt_grpc_config_req) link;
};

static uint64_t mgmt_grpc_session_id = MGMT_GRPC_SESSION_ID_BASE;
static uint64_t mgmt_grpc_req_id;
static LIST_HEAD(mgmt_grpc_rpc_reqs, mgmt_grpc_rpc_req) mgmt_grpc_rpc_reqs;
static LIST_HEAD(mgmt_grpc_config_reqs, mgmt_grpc_config_req) mgmt_grpc_config_reqs;

static void mgmt_grpc_rpc_req_put(struct mgmt_grpc_rpc_req *req)
{
	bool destroy;

	pthread_mutex_lock(&req->mtx);
	assert(req->refcnt);
	destroy = --req->refcnt == 0;
	pthread_mutex_unlock(&req->mtx);

	if (!destroy)
		return;

	event_cancel(&req->event);
	LIST_REMOVE(req, link);
	lyd_free_all(req->input);
	lyd_free_all(req->output);
	darr_free(req->errstr);
	XFREE(MTYPE_MGMTD_GRPC_RPC, req->xpath);
	pthread_mutex_destroy(&req->mtx);
	XFREE(MTYPE_MGMTD_GRPC_RPC, req);
}

static void mgmt_grpc_rpc_complete(struct mgmt_grpc_rpc_req *req, int error, const char *errstr,
				   const struct lyd_node *result)
{
	nb_rpc_dispatch_done_cb done_cb = NULL;
	void *done_arg = NULL;
	struct lyd_node *output = NULL;
	LY_ERR err = LY_SUCCESS;
	int cb_error;
	const char *cb_errstr;

	pthread_mutex_lock(&req->mtx);

	if (req->done)
		goto done;

	req->error = error;
	if (errstr)
		darr_in_strdup(req->errstr, errstr);
	if (!error && result)
		err = lyd_dup_siblings(result, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
				       &req->output);
	if (err) {
		req->error = -EINVAL;
		darr_in_strdup(req->errstr, "Cannot copy RPC result");
	}
	req->done = true;
	done_cb = req->done_cb;
	done_arg = req->done_arg;
	if (done_cb) {
		output = req->output;
		req->output = NULL;
		cb_error = req->error;
		cb_errstr = req->errstr;
	}

done:
	pthread_mutex_unlock(&req->mtx);

	/*
	 * The request keeps cb_errstr alive until the callback returns.  The
	 * output tree is handed to the callback, which becomes responsible for
	 * freeing it.
	 */
	if (done_cb)
		done_cb(cb_error, cb_errstr, output, done_arg);
}

static bool mgmt_grpc_rpc_is_done(struct mgmt_grpc_rpc_req *req)
{
	bool done;

	pthread_mutex_lock(&req->mtx);
	done = req->done;
	pthread_mutex_unlock(&req->mtx);

	return done;
}

static void mgmt_grpc_rpc_done(uint64_t txn_id, uint64_t req_id, int error, const char *errstr,
			       LYD_FORMAT result_type, bool restconf,
			       const struct lyd_node *result, void *arg)
{
	struct mgmt_grpc_rpc_req *req = arg;

	(void)txn_id;
	(void)req_id;
	(void)result_type;
	(void)restconf;

	mgmt_grpc_rpc_complete(req, error, errstr, result);
	mgmt_grpc_rpc_req_put(req);
}

static uint64_t mgmt_grpc_next_session_id(void)
{
	/* Wrap is not expected in practice for synthetic gRPC sessions. */
	return mgmt_grpc_session_id++;
}

static uint64_t mgmt_grpc_next_req_id(void)
{
	return ++mgmt_grpc_req_id;
}

static void mgmt_grpc_rpc_event(struct event *event)
{
	struct mgmt_grpc_rpc_req *req = EVENT_ARG(event);
	const struct lysc_node *snode;
	uint64_t session_id;
	uint64_t txn_id;
	uint64_t req_id;
	uint64_t clients;
	char *data = NULL;
	LY_ERR err;

	req->event = NULL;

	if (mgmt_grpc_rpc_is_done(req)) {
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	snode = lys_find_path(ly_native_ctx, NULL, req->xpath, 0);
	if (!snode) {
		mgmt_grpc_rpc_complete(req, -ENOENT, "No such RPC path", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	if (snode->nodetype != LYS_RPC && snode->nodetype != LYS_ACTION) {
		mgmt_grpc_rpc_complete(req, -EINVAL, "Path is not an RPC or action", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	clients = mgmt_be_interested_clients(req->xpath, MGMT_BE_XPATH_SUBSCR_TYPE_RPC, "RPC");
	if (!clients) {
		mgmt_grpc_rpc_complete(req, -ENOENT, "No backend implements RPC path", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	err = lyd_print_mem(&data, req->input, LYD_JSON, LYD_PRINT_SHRINK);
	if (err) {
		mgmt_grpc_rpc_complete(req, -EINVAL, "Cannot serialize RPC input", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	session_id = mgmt_grpc_next_session_id();
	txn_id = mgmt_create_txn(session_id, MGMTD_TXN_TYPE_RPC);
	if (txn_id == MGMTD_TXN_ID_NONE) {
		free(data);
		_log_err("failed to create RPC txn for xpath=%s", req->xpath);
		mgmt_grpc_rpc_complete(req, -EINPROGRESS, "Failed to create RPC transaction", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	req_id = mgmt_grpc_next_req_id();
	_dbg("created RPC txn-id=%" PRIu64 " req-id=%" PRIu64 " for xpath=%s", txn_id, req_id,
	     req->xpath);
	req->dispatched = true;
	req->txn_id = txn_id;
	req->req_id = req_id;
	/* Native mgmtd RPC messages carry a NUL-terminated encoded payload. */
	mgmt_txn_send_rpc_notify(txn_id, req_id, clients, LYD_JSON, false, req->xpath, data,
				 strlen(data) + 1, mgmt_grpc_rpc_done, req);
	free(data);
}

static int mgmt_grpc_rpc_dispatch_async(const char *xpath, const struct lyd_node *input,
					nb_rpc_dispatch_done_cb done, void *arg, char *errmsg,
					size_t errmsg_len)
{
	struct mgmt_grpc_rpc_req *req;
	LY_ERR err;

	_dbg("dispatching async gRPC RPC xpath=%s", xpath);

	req = XCALLOC(MTYPE_MGMTD_GRPC_RPC, sizeof(*req));
	pthread_mutex_init(&req->mtx, NULL);
	req->refcnt = 1;
	req->done_cb = done;
	req->done_arg = arg;
	req->xpath = XSTRDUP(MTYPE_MGMTD_GRPC_RPC, xpath);
	LIST_INSERT_HEAD(&mgmt_grpc_rpc_reqs, req, link);
	err = lyd_dup_siblings(input, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &req->input);
	if (err) {
		snprintf(errmsg, errmsg_len, "Cannot copy RPC input");
		mgmt_grpc_rpc_req_put(req);
		return -EINVAL;
	}

	/*
	 * No per-req timeout here: the RPC transaction created in
	 * mgmt_grpc_rpc_event carries its own MGMTD_TXN_RPC_MAX_DELAY_SEC
	 * deadline and calls mgmt_grpc_rpc_done (which calls put) on expiry,
	 * bounding the req lifetime without an extra timer.
	 */
	event_add_event(mm->master, mgmt_grpc_rpc_event, req, 0, &req->event);
	return 0;
}

static void mgmt_grpc_config_restore_candidate(struct mgmt_grpc_config_req *req)
{
	struct mgmt_ds_ctx *can_ds;

	if (!req->candidate_backup)
		return;

	can_ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_CANDIDATE);
	mgmt_ds_restore_nb_config(can_ds, req->candidate_backup);
	req->candidate_backup = NULL;
}

static bool mgmt_grpc_config_phase_supported(enum nb_config_commit_phase phase)
{
	return phase == NB_CONFIG_COMMIT_VALIDATE || phase == NB_CONFIG_COMMIT_ALL;
}

static void mgmt_grpc_config_install_candidate(struct mgmt_grpc_config_req *req,
					       struct mgmt_ds_ctx *can_ds)
{
	/*
	 * mgmtd's commit engine diffs its candidate datastore against running.
	 * gRPC candidates live in lib/northbound_grpc.cpp, so install a copy in
	 * mgmtd for the duration of this commit request.  Completion uses
	 * running_updated to decide whether the previous candidate is restored.
	 */
	req->candidate_backup = nb_config_dup(mgmt_ds_get_nb_config(can_ds));
	mgmt_ds_restore_nb_config(can_ds, nb_config_dup(req->candidate));
}

static void mgmt_grpc_config_req_put(struct mgmt_grpc_config_req *req)
{
	bool destroy;

	pthread_mutex_lock(&req->mtx);
	assert(req->refcnt);
	destroy = --req->refcnt == 0;
	pthread_mutex_unlock(&req->mtx);

	if (!destroy)
		return;

	event_cancel(&req->event);
	LIST_REMOVE(req, link);
	nb_config_free(req->candidate);
	if (req->candidate_backup)
		nb_config_free(req->candidate_backup);
	darr_free(req->errstr);
	pthread_mutex_destroy(&req->mtx);
	XFREE(MTYPE_MGMTD_GRPC_CONFIG, req);
}

static void mgmt_grpc_config_complete(struct mgmt_grpc_config_req *req, int error,
				      const char *errstr, uint32_t transaction_id)
{
	nb_config_commit_done_cb done_cb = NULL;
	void *done_arg = NULL;
	int cb_error;
	const char *cb_errstr;
	uint32_t cb_transaction_id = 0;

	pthread_mutex_lock(&req->mtx);

	if (req->done)
		goto done;

	req->error = error;
	if (errstr)
		darr_in_strdup(req->errstr, errstr);
	req->done = true;
	done_cb = req->done_cb;
	done_arg = req->done_arg;
	if (done_cb) {
		cb_error = req->error;
		cb_errstr = req->errstr;
		cb_transaction_id = transaction_id;
	}

done:
	pthread_mutex_unlock(&req->mtx);

	if (done_cb)
		done_cb(cb_error, cb_errstr, cb_transaction_id, done_arg);
}

static bool mgmt_grpc_config_is_done(struct mgmt_grpc_config_req *req)
{
	bool done;

	pthread_mutex_lock(&req->mtx);
	done = req->done;
	pthread_mutex_unlock(&req->mtx);

	return done;
}

static void mgmt_grpc_config_done(uint64_t txn_id, uint64_t req_id, int error,
				  const char *errstr, bool running_updated, void *arg)
{
	struct mgmt_grpc_config_req *req = arg;

	(void)txn_id;
	(void)req_id;

	if (!running_updated)
		mgmt_grpc_config_restore_candidate(req);
	mgmt_grpc_config_complete(req, error, errstr, 0);
	mgmt_grpc_config_req_put(req);
}

static int mgmt_grpc_config_start_commit(struct mgmt_grpc_config_req *req, char *errmsg,
					 size_t errmsg_len)
{
	struct mgmt_ds_ctx *can_ds, *run_ds;
	uint64_t lock_session;
	uint64_t locked_by;
	uint64_t session_id;
	uint64_t txn_id;
	uint64_t req_id;
	bool validate_only;

	if (!mgmt_grpc_config_phase_supported(req->phase)) {
		snprintf(errmsg, errmsg_len, "mgmtd gRPC Commit supports VALIDATE and ALL");
		return -EOPNOTSUPP;
	}

	can_ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_CANDIDATE);
	run_ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	if (mgmt_ds_is_locked(can_ds, &lock_session, &locked_by) ||
	    mgmt_ds_is_locked(run_ds, &lock_session, &locked_by)) {
		snprintf(errmsg, errmsg_len, "Datastore is locked");
		return -EBUSY;
	}

	session_id = mgmt_grpc_next_session_id();
	txn_id = mgmt_create_txn(session_id, MGMTD_TXN_TYPE_CONFIG);
	if (txn_id == MGMTD_TXN_ID_NONE) {
		snprintf(errmsg, errmsg_len, "A configuration transaction is active");
		return -EBUSY;
	}

	mgmt_grpc_config_install_candidate(req, can_ds);

	req_id = mgmt_grpc_next_req_id();
	req->dispatched = true;
	req->txn_id = txn_id;
	req->req_id = req_id;
	validate_only = req->phase == NB_CONFIG_COMMIT_VALIDATE;

	_dbg("created config txn-id=%" PRIu64 " req-id=%" PRIu64 " validate-only=%u", txn_id,
	     req_id, validate_only);
	mgmt_txn_send_commit_config_notify(txn_id, req_id, MGMTD_DS_CANDIDATE, can_ds,
					   MGMTD_DS_RUNNING, run_ds, validate_only,
					   false /*abort*/, false /*implicit*/, false /*unlock*/,
					   NULL, mgmt_grpc_config_done, req);
	return 0;
}

static void mgmt_grpc_config_event(struct event *event)
{
	struct mgmt_grpc_config_req *req = EVENT_ARG(event);
	char errmsg[BUFSIZ] = { 0 };
	int ret;

	req->event = NULL;

	if (mgmt_grpc_config_is_done(req)) {
		mgmt_grpc_config_req_put(req);
		return;
	}

	ret = mgmt_grpc_config_start_commit(req, errmsg, sizeof(errmsg));
	if (ret) {
		mgmt_grpc_config_complete(req, ret, errmsg, 0);
		mgmt_grpc_config_req_put(req);
	}
}

static int mgmt_grpc_config_commit_dispatch_async(const struct nb_config *candidate,
						  enum nb_config_commit_phase phase,
						  const char *comment,
						  nb_config_commit_done_cb done, void *arg,
						  char *errmsg, size_t errmsg_len)
{
	struct mgmt_grpc_config_req *req;

	(void)comment;

	if (!mgmt_grpc_config_phase_supported(phase)) {
		snprintf(errmsg, errmsg_len, "mgmtd gRPC Commit supports VALIDATE and ALL");
		return -EOPNOTSUPP;
	}

	req = XCALLOC(MTYPE_MGMTD_GRPC_CONFIG, sizeof(*req));
	pthread_mutex_init(&req->mtx, NULL);
	req->refcnt = 1;
	req->phase = phase;
	req->candidate = nb_config_dup(candidate);
	req->done_cb = done;
	req->done_arg = arg;
	LIST_INSERT_HEAD(&mgmt_grpc_config_reqs, req, link);

	event_add_event(mm->master, mgmt_grpc_config_event, req, 0, &req->event);
	return 0;
}

static int mgmt_grpc_config_get_dispatch(const char *xpath, struct lyd_node **result, char *errmsg,
					 size_t errmsg_len)
{
	struct mgmt_ds_ctx *ds;
	struct nb_config *config;
	const char *query = xpath;
	LY_ERR err;

	*result = NULL;

	ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	config = mgmt_ds_get_nb_config(ds);
	if (!config || !config->dnode) {
		snprintf(errmsg, errmsg_len, "No running configuration");
		return -ENOENT;
	}

	if (!query || !query[0] || strmatch(query, "/"))
		query = NULL;

	if (!query) {
		err = lyd_dup_siblings(config->dnode, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
				       result);
	} else if (yang_dnode_exists(config->dnode, query)) {
		struct lyd_node *dnode = yang_dnode_get(config->dnode, query);

		if (!dnode) {
			snprintf(errmsg, errmsg_len, "Data path not found");
			return -ENOENT;
		}

		err = lyd_dup_single(dnode, NULL,
				     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS | LYD_DUP_RECURSIVE,
				     result);
	} else {
		snprintf(errmsg, errmsg_len, "Data path not found");
		return -ENOENT;
	}

	if (err) {
		snprintf(errmsg, errmsg_len, "Cannot copy configuration");
		return -EINVAL;
	}
	if (!*result) {
		snprintf(errmsg, errmsg_len, "Data path not found");
		return -ENOENT;
	}

	while ((*result)->parent)
		*result = lyd_parent(*result);

	return 0;
}

static int mgmt_grpc_config_root_borrow_dispatch(const struct lyd_node **result, char *errmsg,
						 size_t errmsg_len)
{
	struct mgmt_ds_ctx *ds;
	struct nb_config *config;

	*result = NULL;

	ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	config = mgmt_ds_get_nb_config(ds);
	if (!config || !config->dnode) {
		snprintf(errmsg, errmsg_len, "No running configuration");
		return -ENOENT;
	}

	/* Borrowed by the caller for read-only validation. */
	*result = config->dnode;
	return 0;
}

void mgmt_grpc_init(void)
{
	LIST_INIT(&mgmt_grpc_rpc_reqs);
	LIST_INIT(&mgmt_grpc_config_reqs);
	nb_config_get_dispatch_set(mgmt_grpc_config_get_dispatch);
	nb_config_root_borrow_dispatch_set(mgmt_grpc_config_root_borrow_dispatch);
	nb_config_commit_dispatch_async_set(mgmt_grpc_config_commit_dispatch_async);
	nb_rpc_dispatch_async_set(mgmt_grpc_rpc_dispatch_async);
	nb_notification_data_subscribe_set(mgmt_fe_adapter_notify_subscribe);
	nb_notification_data_unsubscribe_set(mgmt_fe_adapter_notify_unsubscribe);
}

void mgmt_grpc_terminate(void)
{
	struct mgmt_grpc_rpc_req *req, *next;
	struct mgmt_grpc_config_req *cfg_req, *cfg_next;

	LIST_FOREACH_SAFE (req, &mgmt_grpc_rpc_reqs, link, next) {
		if (req->dispatched) {
			if (mgmt_txn_cancel_rpc_notify(req->txn_id, req->req_id, -ECANCELED,
						       "gRPC RPC dispatch cancelled"))
				continue;
		}

		/*
		 * mgmtd runs this list and RPC completion on the main thread.
		 * A request whose transaction already completed was removed
		 * and put by mgmt_grpc_rpc_done, so reaching this fallback
		 * means there is still exactly one list-held reference to
		 * complete locally.
		 */
		mgmt_grpc_rpc_complete(req, -ECANCELED, "gRPC RPC dispatch cancelled", NULL);
		mgmt_grpc_rpc_req_put(req);
	}

	LIST_FOREACH_SAFE (cfg_req, &mgmt_grpc_config_reqs, link, cfg_next) {
		if (cfg_req->dispatched) {
			if (mgmt_txn_cancel_commit_config_notify(
				    cfg_req->txn_id, cfg_req->req_id, -ECANCELED,
				    "gRPC config commit cancelled"))
				continue;
		}

		/*
		 * mgmtd runs this list and config commit completion on the
		 * main thread.  A request whose transaction already completed
		 * was removed and put by mgmt_grpc_config_done, so reaching
		 * this fallback means there is still exactly one list-held
		 * reference to complete locally.
		 */
		mgmt_grpc_config_restore_candidate(cfg_req);
		mgmt_grpc_config_complete(cfg_req, -ECANCELED, "gRPC config commit cancelled",
					  0);
		mgmt_grpc_config_req_put(cfg_req);
	}

	nb_grpc_terminate_call();
	nb_notification_data_subscribe_set(NULL);
	nb_notification_data_unsubscribe_set(NULL);
	nb_rpc_dispatch_async_set(NULL);
	nb_config_commit_dispatch_async_set(NULL);
	nb_config_root_borrow_dispatch_set(NULL);
	nb_config_get_dispatch_set(NULL);
}
