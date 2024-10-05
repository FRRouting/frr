// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "darr.h"
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_fe_client.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "mgmt_pb.h"
#include "hash.h"
#include "jhash.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_fe_adapter.h"

#define __dbg(fmt, ...)                                                        \
	DEBUGD(&mgmt_debug_fe, "FE-ADAPTER: %s: " fmt, __func__, ##__VA_ARGS__)
#define __log_err(fmt, ...)                                                    \
	zlog_err("FE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define FOREACH_ADAPTER_IN_LIST(adapter)                                       \
	frr_each_safe (mgmt_fe_adapters, &mgmt_fe_adapters, (adapter))

enum mgmt_session_event {
	MGMTD_FE_SESSION_CFG_TXN_CLNUP = 1,
	MGMTD_FE_SESSION_SHOW_TXN_CLNUP,
};

struct mgmt_fe_session_ctx {
	struct mgmt_fe_client_adapter *adapter;
	uint64_t session_id;
	uint64_t client_id;
	uint64_t txn_id;
	uint64_t cfg_txn_id;
	uint8_t ds_locked[MGMTD_DS_MAX_ID];
	const char **notify_xpaths;
	struct event *proc_cfg_txn_clnp;
	struct event *proc_show_txn_clnp;

	struct mgmt_fe_sessions_item list_linkage;
};

DECLARE_LIST(mgmt_fe_sessions, struct mgmt_fe_session_ctx, list_linkage);

#define FOREACH_SESSION_IN_LIST(adapter, session)                              \
	frr_each_safe (mgmt_fe_sessions, &(adapter)->fe_sessions, (session))

static struct event_loop *mgmt_loop;
static struct msg_server mgmt_fe_server = {.fd = -1};

static struct mgmt_fe_adapters_head mgmt_fe_adapters;

static struct hash *mgmt_fe_sessions;
static uint64_t mgmt_fe_next_session_id;

/* Forward declarations */
static void
mgmt_fe_session_register_event(struct mgmt_fe_session_ctx *session,
				   enum mgmt_session_event event);

static int
mgmt_fe_session_write_lock_ds(Mgmtd__DatastoreId ds_id,
				  struct mgmt_ds_ctx *ds_ctx,
				  struct mgmt_fe_session_ctx *session)
{
	if (session->ds_locked[ds_id])
		zlog_warn("multiple lock taken by session-id: %" PRIu64
			  " on DS:%s",
			  session->session_id, mgmt_ds_id2name(ds_id));
	else {
		if (mgmt_ds_lock(ds_ctx, session->session_id)) {
			__dbg("Failed to lock the DS:%s for session-id: %" PRIu64
			      " from %s!",
			      mgmt_ds_id2name(ds_id), session->session_id,
			      session->adapter->name);
			return -1;
		}

		session->ds_locked[ds_id] = true;
		__dbg("Write-Locked the DS:%s for session-id: %" PRIu64
		      " from %s",
		      mgmt_ds_id2name(ds_id), session->session_id,
		      session->adapter->name);
	}

	return 0;
}

static void mgmt_fe_session_unlock_ds(Mgmtd__DatastoreId ds_id,
				      struct mgmt_ds_ctx *ds_ctx,
				      struct mgmt_fe_session_ctx *session)
{
	if (!session->ds_locked[ds_id])
		zlog_warn("unlock unlocked by session-id: %" PRIu64 " on DS:%s",
			  session->session_id, mgmt_ds_id2name(ds_id));

	session->ds_locked[ds_id] = false;
	mgmt_ds_unlock(ds_ctx);
	__dbg("Unlocked DS:%s write-locked earlier by session-id: %" PRIu64
	      " from %s",
	      mgmt_ds_id2name(ds_id), session->session_id,
	      session->adapter->name);
}

static void
mgmt_fe_session_cfg_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	/*
	 * Ensure any uncommitted changes in Candidate DS
	 * is discarded.
	 */
	mgmt_ds_copy_dss(mm->running_ds, mm->candidate_ds, false);

	/*
	 * Destroy the actual transaction created earlier.
	 */
	if (session->cfg_txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->cfg_txn_id);
}

static void
mgmt_fe_session_show_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	/*
	 * Destroy the transaction created recently.
	 */
	if (session->txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->txn_id);
}

static void
mgmt_fe_adapter_compute_set_cfg_timers(struct mgmt_setcfg_stats *setcfg_stats)
{
	setcfg_stats->last_exec_tm = timeval_elapsed(setcfg_stats->last_end,
						     setcfg_stats->last_start);
	if (setcfg_stats->last_exec_tm > setcfg_stats->max_tm)
		setcfg_stats->max_tm = setcfg_stats->last_exec_tm;

	if (setcfg_stats->last_exec_tm < setcfg_stats->min_tm)
		setcfg_stats->min_tm = setcfg_stats->last_exec_tm;

	setcfg_stats->avg_tm =
		(((setcfg_stats->avg_tm * (setcfg_stats->set_cfg_count - 1))
		  + setcfg_stats->last_exec_tm)
		 / setcfg_stats->set_cfg_count);
}

static void
mgmt_fe_session_compute_commit_timers(struct mgmt_commit_stats *cmt_stats)
{
	cmt_stats->last_exec_tm =
		timeval_elapsed(cmt_stats->last_end, cmt_stats->last_start);
	if (cmt_stats->last_exec_tm > cmt_stats->max_tm) {
		cmt_stats->max_tm = cmt_stats->last_exec_tm;
		cmt_stats->max_batch_cnt = cmt_stats->last_batch_cnt;
	}

	if (cmt_stats->last_exec_tm < cmt_stats->min_tm) {
		cmt_stats->min_tm = cmt_stats->last_exec_tm;
		cmt_stats->min_batch_cnt = cmt_stats->last_batch_cnt;
	}
}

static void mgmt_fe_cleanup_session(struct mgmt_fe_session_ctx **sessionp)
{
	Mgmtd__DatastoreId ds_id;
	struct mgmt_ds_ctx *ds_ctx;
	struct mgmt_fe_session_ctx *session = *sessionp;

	if (session->adapter) {
		mgmt_fe_session_cfg_txn_cleanup(session);
		mgmt_fe_session_show_txn_cleanup(session);
		for (ds_id = 0; ds_id < MGMTD_DS_MAX_ID; ds_id++) {
			ds_ctx = mgmt_ds_get_ctx_by_id(mm, ds_id);
			if (ds_ctx && session->ds_locked[ds_id])
				mgmt_fe_session_unlock_ds(ds_id, ds_ctx,
							  session);
		}
		mgmt_fe_sessions_del(&session->adapter->fe_sessions, session);
		assert(session->adapter->refcount > 1);
		mgmt_fe_adapter_unlock(&session->adapter);
	}

	hash_release(mgmt_fe_sessions, session);
	XFREE(MTYPE_MGMTD_FE_SESSION, session);
	*sessionp = NULL;
}

static struct mgmt_fe_session_ctx *
mgmt_fe_find_session_by_client_id(struct mgmt_fe_client_adapter *adapter,
				      uint64_t client_id)
{
	struct mgmt_fe_session_ctx *session;

	FOREACH_SESSION_IN_LIST (adapter, session) {
		if (session->client_id == client_id) {
			__dbg("Found session-id %" PRIu64
			      " using client-id %" PRIu64,
			      session->session_id, client_id);
			return session;
		}
	}
	__dbg("Session not found using client-id %" PRIu64, client_id);
	return NULL;
}

static unsigned int mgmt_fe_session_hash_key(const void *data)
{
	const struct mgmt_fe_session_ctx *session = data;

	return jhash2((uint32_t *) &session->session_id,
		      sizeof(session->session_id) / sizeof(uint32_t), 0);
}

static bool mgmt_fe_session_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_fe_session_ctx *session1 = d1;
	const struct mgmt_fe_session_ctx *session2 = d2;

	return (session1->session_id == session2->session_id);
}

static inline struct mgmt_fe_session_ctx *
mgmt_session_id2ctx(uint64_t session_id)
{
	struct mgmt_fe_session_ctx key = {0};
	struct mgmt_fe_session_ctx *session;

	if (!mgmt_fe_sessions)
		return NULL;

	key.session_id = session_id;
	session = hash_lookup(mgmt_fe_sessions, &key);

	return session;
}

void mgmt_fe_adapter_toggle_client_debug(bool set)
{
	struct mgmt_fe_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter)
		adapter->conn->debug = set;
}

static struct mgmt_fe_session_ctx *fe_adapter_session_by_txn_id(uint64_t txn_id)
{
	uint64_t session_id = mgmt_txn_get_session_id(txn_id);

	if (session_id == MGMTD_SESSION_ID_NONE)
		return NULL;
	return mgmt_session_id2ctx(session_id);
}

static struct mgmt_fe_session_ctx *
mgmt_fe_create_session(struct mgmt_fe_client_adapter *adapter,
			   uint64_t client_id)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_fe_find_session_by_client_id(adapter, client_id);
	if (session)
		mgmt_fe_cleanup_session(&session);

	session = XCALLOC(MTYPE_MGMTD_FE_SESSION,
			sizeof(struct mgmt_fe_session_ctx));
	assert(session);
	session->client_id = client_id;
	session->adapter = adapter;
	session->txn_id = MGMTD_TXN_ID_NONE;
	session->cfg_txn_id = MGMTD_TXN_ID_NONE;
	mgmt_fe_adapter_lock(adapter);
	mgmt_fe_sessions_add_tail(&adapter->fe_sessions, session);
	if (!mgmt_fe_next_session_id)
		mgmt_fe_next_session_id++;
	session->session_id = mgmt_fe_next_session_id++;
	hash_get(mgmt_fe_sessions, session, hash_alloc_intern);

	return session;
}

static int fe_adapter_send_native_msg(struct mgmt_fe_client_adapter *adapter,
				      void *msg, size_t len,
				      bool short_circuit_ok)
{
	return msg_conn_send_msg(adapter->conn, MGMT_MSG_VERSION_NATIVE, msg,
				 len, NULL, short_circuit_ok);
}

static int fe_adapter_send_msg(struct mgmt_fe_client_adapter *adapter,
			       Mgmtd__FeMessage *fe_msg, bool short_circuit_ok)
{
	return msg_conn_send_msg(
		adapter->conn, MGMT_MSG_VERSION_PROTOBUF, fe_msg,
		mgmtd__fe_message__get_packed_size(fe_msg),
		(size_t(*)(void *, void *))mgmtd__fe_message__pack,
		short_circuit_ok);
}

static int fe_adapter_send_session_reply(struct mgmt_fe_client_adapter *adapter,
					 struct mgmt_fe_session_ctx *session,
					 bool create, bool success)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeSessionReply session_reply;

	mgmtd__fe_session_reply__init(&session_reply);
	session_reply.create = create;
	if (create) {
		session_reply.has_client_conn_id = 1;
		session_reply.client_conn_id = session->client_id;
	}
	session_reply.session_id = session->session_id;
	session_reply.success = success;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SESSION_REPLY;
	fe_msg.session_reply = &session_reply;

	__dbg("Sending SESSION_REPLY message to MGMTD Frontend client '%s'",
	      adapter->name);

	return fe_adapter_send_msg(adapter, &fe_msg, true);
}

static int fe_adapter_send_lockds_reply(struct mgmt_fe_session_ctx *session,
					Mgmtd__DatastoreId ds_id,
					uint64_t req_id, bool lock_ds,
					bool success, const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeLockDsReply lockds_reply;
	bool scok = session->adapter->conn->is_short_circuit;

	assert(session->adapter);

	mgmtd__fe_lock_ds_reply__init(&lockds_reply);
	lockds_reply.session_id = session->session_id;
	lockds_reply.ds_id = ds_id;
	lockds_reply.req_id = req_id;
	lockds_reply.lock = lock_ds;
	lockds_reply.success = success;
	if (error_if_any)
		lockds_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REPLY;
	fe_msg.lockds_reply = &lockds_reply;

	__dbg("Sending LOCK_DS_REPLY message to MGMTD Frontend client '%s' scok: %d",
	      session->adapter->name, scok);

	return fe_adapter_send_msg(session->adapter, &fe_msg, scok);
}

static int fe_adapter_send_set_cfg_reply(struct mgmt_fe_session_ctx *session,
					 Mgmtd__DatastoreId ds_id,
					 uint64_t req_id, bool success,
					 const char *error_if_any,
					 bool implicit_commit)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeSetConfigReply setcfg_reply;

	assert(session->adapter);

	if (implicit_commit && session->cfg_txn_id)
		mgmt_fe_session_register_event(
			session, MGMTD_FE_SESSION_CFG_TXN_CLNUP);

	mgmtd__fe_set_config_reply__init(&setcfg_reply);
	setcfg_reply.session_id = session->session_id;
	setcfg_reply.ds_id = ds_id;
	setcfg_reply.req_id = req_id;
	setcfg_reply.success = success;
	setcfg_reply.implicit_commit = implicit_commit;
	if (error_if_any)
		setcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY;
	fe_msg.setcfg_reply = &setcfg_reply;

	__dbg("Sending SETCFG_REPLY message to MGMTD Frontend client '%s'",
	      session->adapter->name);

	if (implicit_commit) {
		if (mm->perf_stats_en)
			gettimeofday(&session->adapter->cmt_stats.last_end,
				     NULL);
		mgmt_fe_session_compute_commit_timers(
			&session->adapter->cmt_stats);
	}

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->setcfg_stats.last_end, NULL);
	mgmt_fe_adapter_compute_set_cfg_timers(&session->adapter->setcfg_stats);

	return fe_adapter_send_msg(session->adapter, &fe_msg, false);
}

static int fe_adapter_send_commit_cfg_reply(
	struct mgmt_fe_session_ctx *session, Mgmtd__DatastoreId src_ds_id,
	Mgmtd__DatastoreId dst_ds_id, uint64_t req_id, enum mgmt_result result,
	bool validate_only, const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeCommitConfigReply commcfg_reply;

	assert(session->adapter);

	mgmtd__fe_commit_config_reply__init(&commcfg_reply);
	commcfg_reply.session_id = session->session_id;
	commcfg_reply.src_ds_id = src_ds_id;
	commcfg_reply.dst_ds_id = dst_ds_id;
	commcfg_reply.req_id = req_id;
	commcfg_reply.success =
		(result == MGMTD_SUCCESS || result == MGMTD_NO_CFG_CHANGES)
			? true
			: false;
	commcfg_reply.validate_only = validate_only;
	if (error_if_any)
		commcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REPLY;
	fe_msg.commcfg_reply = &commcfg_reply;

	__dbg("Sending COMMIT_CONFIG_REPLY message to MGMTD Frontend client '%s'",
	      session->adapter->name);

	/*
	 * Cleanup the CONFIG transaction associated with this session.
	 */
	if (session->cfg_txn_id
	    && ((result == MGMTD_SUCCESS && !validate_only)
		|| (result == MGMTD_NO_CFG_CHANGES)))
		mgmt_fe_session_register_event(
			session, MGMTD_FE_SESSION_CFG_TXN_CLNUP);

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->cmt_stats.last_end, NULL);
	mgmt_fe_session_compute_commit_timers(&session->adapter->cmt_stats);
	return fe_adapter_send_msg(session->adapter, &fe_msg, false);
}

static int fe_adapter_send_get_reply(struct mgmt_fe_session_ctx *session,
				     Mgmtd__DatastoreId ds_id, uint64_t req_id,
				     bool success, Mgmtd__YangDataReply *data,
				     const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetReply get_reply;

	assert(session->adapter);

	mgmtd__fe_get_reply__init(&get_reply);
	get_reply.session_id = session->session_id;
	get_reply.ds_id = ds_id;
	get_reply.req_id = req_id;
	get_reply.success = success;
	get_reply.data = data;
	if (error_if_any)
		get_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GET_REPLY;
	fe_msg.get_reply = &get_reply;

	__dbg("Sending GET_REPLY message to MGMTD Frontend client '%s'",
	      session->adapter->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (session->txn_id && (!success || (data && data->next_indx < 0)))
		mgmt_fe_session_register_event(session,
					       MGMTD_FE_SESSION_SHOW_TXN_CLNUP);

	return fe_adapter_send_msg(session->adapter, &fe_msg, false);
}

static int fe_adapter_conn_send_error(struct msg_conn *conn,
				      uint64_t session_id, uint64_t req_id,
				      bool short_circuit_ok, int16_t error,
				      const char *errfmt, ...) PRINTFRR(6, 7);
static int fe_adapter_conn_send_error(struct msg_conn *conn, uint64_t session_id,
				      uint64_t req_id, bool short_circuit_ok,
				      int16_t error, const char *errfmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, errfmt);

	ret = vmgmt_msg_native_send_error(conn, session_id, req_id,
					  short_circuit_ok, error, errfmt, ap);
	va_end(ap);

	return ret;
}

static int fe_adapter_send_error(struct mgmt_fe_session_ctx *session,
				 uint64_t req_id, bool short_circuit_ok,
				 int16_t error, const char *errfmt, ...)
	PRINTFRR(5, 6);

static int fe_adapter_send_error(struct mgmt_fe_session_ctx *session,
				 uint64_t req_id, bool short_circuit_ok,
				 int16_t error, const char *errfmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, errfmt);
	ret = vmgmt_msg_native_send_error(session->adapter->conn,
					  session->session_id, req_id,
					  short_circuit_ok, error, errfmt, ap);
	va_end(ap);

	return ret;
}


static void mgmt_fe_session_cfg_txn_clnup(struct event *thread)
{
	struct mgmt_fe_session_ctx *session;

	session = (struct mgmt_fe_session_ctx *)EVENT_ARG(thread);

	mgmt_fe_session_cfg_txn_cleanup(session);
}

static void mgmt_fe_session_show_txn_clnup(struct event *thread)
{
	struct mgmt_fe_session_ctx *session;

	session = (struct mgmt_fe_session_ctx *)EVENT_ARG(thread);

	mgmt_fe_session_show_txn_cleanup(session);
}

static void
mgmt_fe_session_register_event(struct mgmt_fe_session_ctx *session,
				   enum mgmt_session_event event)
{
	struct timeval tv = {.tv_sec = 0,
			     .tv_usec = MGMTD_FE_MSG_PROC_DELAY_USEC};

	switch (event) {
	case MGMTD_FE_SESSION_CFG_TXN_CLNUP:
		event_add_timer_tv(mgmt_loop, mgmt_fe_session_cfg_txn_clnup,
				   session, &tv, &session->proc_cfg_txn_clnp);
		break;
	case MGMTD_FE_SESSION_SHOW_TXN_CLNUP:
		event_add_timer_tv(mgmt_loop, mgmt_fe_session_show_txn_clnup,
				   session, &tv, &session->proc_show_txn_clnp);
		break;
	}
}

static struct mgmt_fe_client_adapter *
mgmt_fe_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_fe_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (adapter->conn->fd == conn_fd)
			return adapter;
	}

	return NULL;
}

static void mgmt_fe_adapter_delete(struct mgmt_fe_client_adapter *adapter)
{
	struct mgmt_fe_session_ctx *session;
	__dbg("deleting client adapter '%s'", adapter->name);

	/* TODO: notify about client disconnect for appropriate cleanup */
	FOREACH_SESSION_IN_LIST (adapter, session)
		mgmt_fe_cleanup_session(&session);
	mgmt_fe_sessions_fini(&adapter->fe_sessions);

	assert(adapter->refcount == 1);
	mgmt_fe_adapter_unlock(&adapter);
}

static int mgmt_fe_adapter_notify_disconnect(struct msg_conn *conn)
{
	struct mgmt_fe_client_adapter *adapter = conn->user;

	__dbg("notify disconnect for client adapter '%s'", adapter->name);

	mgmt_fe_adapter_delete(adapter);

	return 0;
}

/*
 * Purge any old connections that share the same client name with `adapter`
 */
static void
mgmt_fe_adapter_cleanup_old_conn(struct mgmt_fe_client_adapter *adapter)
{
	struct mgmt_fe_client_adapter *old;

	FOREACH_ADAPTER_IN_LIST (old) {
		if (old == adapter)
			continue;
		if (strncmp(adapter->name, old->name, sizeof(adapter->name)))
			continue;

		__dbg("Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)",
		      adapter->name, adapter->conn->fd, old->conn->fd);
		msg_conn_disconnect(old->conn, false);
	}
}

static int
mgmt_fe_session_handle_lockds_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeLockDsReq *lockds_req)
{
	struct mgmt_ds_ctx *ds_ctx;

	if (lockds_req->ds_id != MGMTD_DS_CANDIDATE &&
	    lockds_req->ds_id != MGMTD_DS_RUNNING) {
		fe_adapter_send_lockds_reply(
			session, lockds_req->ds_id, lockds_req->req_id,
			lockds_req->lock, false,
			"Lock/Unlock on DS other than candidate or running DS not supported");
		return -1;
	}

	ds_ctx = mgmt_ds_get_ctx_by_id(mm, lockds_req->ds_id);
	if (!ds_ctx) {
		fe_adapter_send_lockds_reply(session, lockds_req->ds_id,
					     lockds_req->req_id,
					     lockds_req->lock, false,
					     "Failed to retrieve handle for DS!");
		return -1;
	}

	if (lockds_req->lock) {
		if (mgmt_fe_session_write_lock_ds(lockds_req->ds_id, ds_ctx,
						  session)) {
			fe_adapter_send_lockds_reply(
				session, lockds_req->ds_id, lockds_req->req_id,
				lockds_req->lock, false,
				"Lock already taken on DS by another session!");
			return -1;
		}
	} else {
		if (!session->ds_locked[lockds_req->ds_id]) {
			fe_adapter_send_lockds_reply(
				session, lockds_req->ds_id, lockds_req->req_id,
				lockds_req->lock, false,
				"Lock on DS was not taken by this session!");
			return 0;
		}

		mgmt_fe_session_unlock_ds(lockds_req->ds_id, ds_ctx, session);
	}

	if (fe_adapter_send_lockds_reply(session, lockds_req->ds_id,
					 lockds_req->req_id, lockds_req->lock,
					 true, NULL) != 0) {
		__dbg("Failed to send LOCK_DS_REPLY for DS %u session-id: %" PRIu64
		      " from %s",
		      lockds_req->ds_id, session->session_id,
		      session->adapter->name);
	}

	return 0;
}

/*
 * TODO: this function has too many conditionals relating to complex error
 * conditions. It needs to be simplified and these complex error conditions
 * probably need to just disconnect the client with a suitably loud log message.
 */
static int
mgmt_fe_session_handle_setcfg_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeSetConfigReq *setcfg_req)
{
	struct mgmt_ds_ctx *ds_ctx, *dst_ds_ctx = NULL;
	bool txn_created = false;

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->setcfg_stats.last_start, NULL);

	/* MGMTD currently only supports editing the candidate DS. */
	if (setcfg_req->ds_id != MGMTD_DS_CANDIDATE) {
		fe_adapter_send_set_cfg_reply(
			session, setcfg_req->ds_id, setcfg_req->req_id, false,
			"Set-Config on datastores other than Candidate DS not supported",
			setcfg_req->implicit_commit);
		return 0;
	}
	ds_ctx = mgmt_ds_get_ctx_by_id(mm, setcfg_req->ds_id);
	assert(ds_ctx);

	/* MGMTD currently only supports targetting the running DS. */
	if (setcfg_req->implicit_commit &&
	    setcfg_req->commit_ds_id != MGMTD_DS_RUNNING) {
		fe_adapter_send_set_cfg_reply(
			session, setcfg_req->ds_id, setcfg_req->req_id, false,
			"Implicit commit on datastores other than running DS not supported",
			setcfg_req->implicit_commit);
		return 0;
	}
	dst_ds_ctx = mgmt_ds_get_ctx_by_id(mm, setcfg_req->commit_ds_id);
	assert(dst_ds_ctx);

	/* User should have write lock to change the DS */
	if (!session->ds_locked[setcfg_req->ds_id]) {
		fe_adapter_send_set_cfg_reply(session, setcfg_req->ds_id,
					      setcfg_req->req_id, false,
					      "Candidate DS is not locked",
					      setcfg_req->implicit_commit);
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/* Start a CONFIG Transaction (if not started already) */
		session->cfg_txn_id = mgmt_create_txn(session->session_id,
						      MGMTD_TXN_TYPE_CONFIG);
		if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
			fe_adapter_send_set_cfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false,
				"Failed to create a Configuration session!",
				setcfg_req->implicit_commit);
			return 0;
		}
		txn_created = true;

		__dbg("Created new Config txn-id: %" PRIu64
		      " for session-id %" PRIu64,
		      session->cfg_txn_id, session->session_id);
	} else {
		__dbg("Config txn-id: %" PRIu64 " for session-id: %" PRIu64
		      " already created",
		      session->cfg_txn_id, session->session_id);

		if (setcfg_req->implicit_commit) {
			/*
			 * In this scenario need to skip cleanup of the txn,
			 * so setting implicit commit to false.
			 */
			fe_adapter_send_set_cfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false,
				"A Configuration transaction is already in progress!",
				false);
			return 0;
		}
	}

	/* Create the SETConfig request under the transaction. */
	if (mgmt_txn_send_set_config_req(session->cfg_txn_id, setcfg_req->req_id,
					 setcfg_req->ds_id, ds_ctx,
					 setcfg_req->data, setcfg_req->n_data,
					 setcfg_req->implicit_commit,
					 setcfg_req->commit_ds_id,
					 dst_ds_ctx) != 0) {
		fe_adapter_send_set_cfg_reply(session, setcfg_req->ds_id,
					      setcfg_req->req_id, false,
					      "Request processing for SET-CONFIG failed!",
					      setcfg_req->implicit_commit);

		/* delete transaction if we just created it */
		if (txn_created)
			mgmt_destroy_txn(&session->cfg_txn_id);
	}

	return 0;
}

static int mgmt_fe_session_handle_get_req_msg(struct mgmt_fe_session_ctx *session,
					      Mgmtd__FeGetReq *get_req)
{
	struct mgmt_ds_ctx *ds_ctx;
	struct nb_config *cfg_root = NULL;
	Mgmtd__DatastoreId ds_id = get_req->ds_id;
	uint64_t req_id = get_req->req_id;

	if (ds_id != MGMTD_DS_CANDIDATE && ds_id != MGMTD_DS_RUNNING) {
		fe_adapter_send_get_reply(session, ds_id, req_id, false, NULL,
					  "get-req on unsupported datastore");
		return 0;
	}
	ds_ctx = mgmt_ds_get_ctx_by_id(mm, ds_id);
	assert(ds_ctx);

	if (session->txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Start a SHOW Transaction (if not started already)
		 */
		session->txn_id = mgmt_create_txn(session->session_id,
						  MGMTD_TXN_TYPE_SHOW);
		if (session->txn_id == MGMTD_SESSION_ID_NONE) {
			fe_adapter_send_get_reply(session, ds_id, req_id, false,
						  NULL,
						  "Failed to create a Show transaction!");
			return -1;
		}

		__dbg("Created new show txn-id: %" PRIu64
		      " for session-id: %" PRIu64,
		      session->txn_id, session->session_id);
	} else {
		fe_adapter_send_get_reply(session, ds_id, req_id, false, NULL,
					  "Request processing for GET failed!");
		__dbg("Transaction in progress txn-id: %" PRIu64
		      " for session-id: %" PRIu64,
		      session->txn_id, session->session_id);
		return -1;
	}

	/*
	 * Get a copy of the datastore config root, avoids locking.
	 */
	cfg_root = nb_config_dup(mgmt_ds_get_nb_config(ds_ctx));

	/*
	 * Create a GET request under the transaction.
	 */
	if (mgmt_txn_send_get_req(session->txn_id, req_id, ds_id, cfg_root,
				  get_req->data, get_req->n_data)) {
		fe_adapter_send_get_reply(session, ds_id, req_id, false, NULL,
					  "Request processing for GET failed!");

		goto failed;
	}

	return 0;
failed:
	if (cfg_root)
		nb_config_free(cfg_root);
	/*
	 * Destroy the transaction created recently.
	 */
	if (session->txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->txn_id);

	return -1;
}


static int mgmt_fe_session_handle_commit_config_req_msg(
	struct mgmt_fe_session_ctx *session,
	Mgmtd__FeCommitConfigReq *commcfg_req)
{
	struct mgmt_ds_ctx *src_ds_ctx, *dst_ds_ctx;

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->cmt_stats.last_start, NULL);
	session->adapter->cmt_stats.commit_cnt++;

	/* Validate source and dest DS */
	if (commcfg_req->src_ds_id != MGMTD_DS_CANDIDATE ||
	    commcfg_req->dst_ds_id != MGMTD_DS_RUNNING) {
		fe_adapter_send_commit_cfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Source/Dest for commit must be candidate/running DS");
		return 0;
	}
	src_ds_ctx = mgmt_ds_get_ctx_by_id(mm, commcfg_req->src_ds_id);
	assert(src_ds_ctx);
	dst_ds_ctx = mgmt_ds_get_ctx_by_id(mm, commcfg_req->dst_ds_id);
	assert(dst_ds_ctx);

	/* User should have lock on both source and dest DS */
	if (!session->ds_locked[commcfg_req->dst_ds_id] ||
	    !session->ds_locked[commcfg_req->src_ds_id]) {
		fe_adapter_send_commit_cfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_DS_LOCK_FAILED,
			commcfg_req->validate_only,
			"Commit requires lock on candidate and/or running DS");
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/* as we have the lock no-one else should have a config txn */
		assert(!mgmt_config_txn_in_progress());

		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		session->cfg_txn_id = mgmt_create_txn(session->session_id,
						MGMTD_TXN_TYPE_CONFIG);
		if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
			fe_adapter_send_commit_cfg_reply(
				session, commcfg_req->src_ds_id,
				commcfg_req->dst_ds_id, commcfg_req->req_id,
				MGMTD_INTERNAL_ERROR, commcfg_req->validate_only,
				"Failed to create a Configuration session!");
			return 0;
		}
		__dbg("Created txn-id: %" PRIu64 " for session-id %" PRIu64
		      " for COMMIT-CFG-REQ",
		      session->cfg_txn_id, session->session_id);
	}

	/*
	 * Create COMMITConfig request under the transaction
	 */
	if (mgmt_txn_send_commit_config_req(session->cfg_txn_id,
					    commcfg_req->req_id,
					    commcfg_req->src_ds_id, src_ds_ctx,
					    commcfg_req->dst_ds_id, dst_ds_ctx,
					    commcfg_req->validate_only,
					    commcfg_req->abort, false,
					    NULL) != 0) {
		fe_adapter_send_commit_cfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Request processing for COMMIT-CONFIG failed!");
		return 0;
	}

	return 0;
}

static int
mgmt_fe_adapter_handle_msg(struct mgmt_fe_client_adapter *adapter,
			       Mgmtd__FeMessage *fe_msg)
{
	struct mgmt_fe_session_ctx *session;

	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)fe_msg->message_case) {
	case MGMTD__FE_MESSAGE__MESSAGE_REGISTER_REQ:
		__dbg("Got REGISTER_REQ from '%s'",
		      fe_msg->register_req->client_name);

		if (strlen(fe_msg->register_req->client_name)) {
			strlcpy(adapter->name,
				fe_msg->register_req->client_name,
				sizeof(adapter->name));
			mgmt_fe_adapter_cleanup_old_conn(adapter);
		}
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SESSION_REQ:
		if (fe_msg->session_req->create
		    && fe_msg->session_req->id_case
			== MGMTD__FE_SESSION_REQ__ID_CLIENT_CONN_ID) {
			__dbg("Got SESSION_REQ (create) for client-id %" PRIu64
			      " from '%s'",
			      fe_msg->session_req->client_conn_id,
			      adapter->name);

			session = mgmt_fe_create_session(
				adapter, fe_msg->session_req->client_conn_id);
			fe_adapter_send_session_reply(adapter, session, true,
						      session ? true : false);
		} else if (
			!fe_msg->session_req->create
			&& fe_msg->session_req->id_case
				== MGMTD__FE_SESSION_REQ__ID_SESSION_ID) {
			__dbg("Got SESSION_REQ (destroy) for session-id %" PRIu64
			      "from '%s'",
			      fe_msg->session_req->session_id, adapter->name);

			session = mgmt_session_id2ctx(
				fe_msg->session_req->session_id);
			fe_adapter_send_session_reply(adapter, session, false,
						      true);
			mgmt_fe_cleanup_session(&session);
		}
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->lockds_req->session_id);
		__dbg("Got LOCKDS_REQ (%sLOCK) for DS:%s for session-id %" PRIu64
		      " from '%s'",
		      fe_msg->lockds_req->lock ? "" : "UN",
		      mgmt_ds_id2name(fe_msg->lockds_req->ds_id),
		      fe_msg->lockds_req->session_id, adapter->name);
		mgmt_fe_session_handle_lockds_req_msg(
			session, fe_msg->lockds_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->setcfg_req->session_id);
		session->adapter->setcfg_stats.set_cfg_count++;
		__dbg("Got SETCFG_REQ (%d Xpaths, Implicit:%c) on DS:%s for session-id %" PRIu64
		      " from '%s'",
		      (int)fe_msg->setcfg_req->n_data,
		      fe_msg->setcfg_req->implicit_commit ? 'T' : 'F',
		      mgmt_ds_id2name(fe_msg->setcfg_req->ds_id),
		      fe_msg->setcfg_req->session_id, adapter->name);

		mgmt_fe_session_handle_setcfg_req_msg(
			session, fe_msg->setcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->commcfg_req->session_id);
		__dbg("Got COMMCFG_REQ for src-DS:%s dst-DS:%s (Abort:%c) on session-id %" PRIu64
		      " from '%s'",
		      mgmt_ds_id2name(fe_msg->commcfg_req->src_ds_id),
		      mgmt_ds_id2name(fe_msg->commcfg_req->dst_ds_id),
		      fe_msg->commcfg_req->abort ? 'T' : 'F',
		      fe_msg->commcfg_req->session_id, adapter->name);
		mgmt_fe_session_handle_commit_config_req_msg(
			session, fe_msg->commcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GET_REQ:
		session = mgmt_session_id2ctx(fe_msg->get_req->session_id);
		__dbg("Got GET_REQ for DS:%s (xpaths: %d) on session-id %" PRIu64
		      " from '%s'",
		      mgmt_ds_id2name(fe_msg->get_req->ds_id),
		      (int)fe_msg->get_req->n_data, fe_msg->get_req->session_id,
		      adapter->name);
		mgmt_fe_session_handle_get_req_msg(session, fe_msg->get_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_NOTIFY_DATA_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_REGNOTIFY_REQ:
		__log_err("Got unhandled message of type %u from '%s'",
			  fe_msg->message_case, adapter->name);
		/*
		 * TODO: Add handling code in future.
		 */
		break;
	/*
	 * NOTE: The following messages are always sent from MGMTD to
	 * Frontend clients only and/or need not be handled on MGMTd.
	 */
	case MGMTD__FE_MESSAGE__MESSAGE_SESSION_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_GET_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE__NOT_SET:
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

/**
 * Send result of get-tree request back to the FE client.
 *
 * Args:
 *	session: the session.
 *	req_id: the request ID.
 *	short_circuit_ok: if allowed to short circuit the message.
 *	result_format: LYD_FORMAT for the sent output.
 *	tree: the tree to send, can be NULL which will send an empty tree.
 *	partial_error: if an error occurred during gathering results.
 *
 * Return:
 *	Any error that occurs -- the message is likely not sent if non-zero.
 */
static int fe_adapter_send_tree_data(struct mgmt_fe_session_ctx *session,
				     uint64_t req_id, bool short_circuit_ok,
				     uint8_t result_type, uint32_t wd_options,
				     const struct lyd_node *tree,
				     int partial_error)

{
	struct mgmt_msg_tree_data *msg;
	uint8_t **darrp = NULL;
	int ret = 0;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_tree_data, 0,
					MTYPE_MSG_NATIVE_TREE_DATA);
	msg->refer_id = session->session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_TREE_DATA;
	msg->partial_error = partial_error;
	msg->result_type = result_type;

	darrp = mgmt_msg_native_get_darrp(msg);
	ret = yang_print_tree_append(darrp, tree, result_type,
				     (wd_options | LYD_PRINT_WITHSIBLINGS));
	if (ret != LY_SUCCESS) {
		__log_err("Error building get-tree result for client %s session-id %" PRIu64
			  " req-id %" PRIu64 " scok %d result type %u",
			  session->adapter->name, session->session_id, req_id,
			  short_circuit_ok, result_type);
		goto done;
	}

	__dbg("Sending get-tree result from adapter %s to session-id %" PRIu64
	      " req-id %" PRIu64 " scok %d result type %u len %u",
	      session->adapter->name, session->session_id, req_id,
	      short_circuit_ok, result_type, mgmt_msg_native_get_msg_len(msg));

	ret = fe_adapter_send_native_msg(session->adapter, msg,
					 mgmt_msg_native_get_msg_len(msg),
					 short_circuit_ok);
done:
	mgmt_msg_native_free_msg(msg);

	return ret;
}

static int fe_adapter_send_rpc_reply(struct mgmt_fe_session_ctx *session,
				     uint64_t req_id, uint8_t result_type,
				     const struct lyd_node *result)
{
	struct mgmt_msg_rpc_reply *msg;
	uint8_t **darrp = NULL;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc_reply, 0,
					MTYPE_MSG_NATIVE_RPC_REPLY);
	msg->refer_id = session->session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_RPC_REPLY;
	msg->result_type = result_type;

	if (result) {
		darrp = mgmt_msg_native_get_darrp(msg);
		ret = yang_print_tree_append(darrp, result, result_type, 0);
		if (ret != LY_SUCCESS) {
			__log_err("Error building rpc-reply result for client %s session-id %" PRIu64
				  " req-id %" PRIu64 " result type %u",
				  session->adapter->name, session->session_id,
				  req_id, result_type);
			goto done;
		}
	}

	__dbg("Sending rpc-reply from adapter %s to session-id %" PRIu64
	      " req-id %" PRIu64 " len %u",
	      session->adapter->name, session->session_id, req_id,
	      mgmt_msg_native_get_msg_len(msg));

	ret = fe_adapter_send_native_msg(session->adapter, msg,
					 mgmt_msg_native_get_msg_len(msg),
					 false);
done:
	mgmt_msg_native_free_msg(msg);

	return ret;
}

static int fe_adapter_send_edit_reply(struct mgmt_fe_session_ctx *session,
				      uint64_t req_id, bool changed,
				      bool created, const char *xpath,
				      const char *data)
{
	struct mgmt_msg_edit_reply *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_edit_reply, 0,
					MTYPE_MSG_NATIVE_EDIT_REPLY);
	msg->refer_id = session->session_id;
	msg->req_id = req_id;
	msg->changed = changed;
	msg->created = created;
	msg->code = MGMT_MSG_CODE_EDIT_REPLY;

	mgmt_msg_native_xpath_encode(msg, xpath);

	if (data)
		mgmt_msg_native_append(msg, data, strlen(data) + 1);

	__dbg("Sending edit-reply from adapter %s to session-id %" PRIu64
	      " req-id %" PRIu64 " changed %u created %u len %u",
	      session->adapter->name, session->session_id, req_id, changed,
	      created, mgmt_msg_native_get_msg_len(msg));

	ret = fe_adapter_send_native_msg(session->adapter, msg,
					 mgmt_msg_native_get_msg_len(msg),
					 false);
	mgmt_msg_native_free_msg(msg);

	return ret;
}

static int
fe_adapter_native_send_session_reply(struct mgmt_fe_client_adapter *adapter,
				     uint64_t req_id, uint64_t session_id,
				     bool created)
{
	struct mgmt_msg_session_reply *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_session_reply, 0,
					MTYPE_MSG_NATIVE_SESSION_REPLY);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_SESSION_REPLY;
	msg->created = created;

	__dbg("Sending session-reply from adapter %s to session-id %" PRIu64
	      " req-id %" PRIu64 " len %u",
	      adapter->name, session_id, req_id,
	      mgmt_msg_native_get_msg_len(msg));

	ret = fe_adapter_send_native_msg(adapter, msg,
					 mgmt_msg_native_get_msg_len(msg),
					 false);
	mgmt_msg_native_free_msg(msg);

	return ret;
}

/**
 * fe_adapter_handle_session_req() - Handle a session-req message from a FE client.
 * @msg_raw: the message data.
 * @msg_len: the length of the message data.
 */
static void fe_adapter_handle_session_req(struct mgmt_fe_client_adapter *adapter,
					  void *__msg, size_t msg_len)
{
	struct mgmt_msg_session_req *msg = __msg;
	struct mgmt_fe_session_ctx *session;
	uint64_t client_id;

	__dbg("Got session-req creating: %u for refer-id %" PRIu64 " from '%s'",
	      msg->refer_id == 0, msg->refer_id, adapter->name);

	if (msg->refer_id) {
		uint64_t session_id = msg->refer_id;

		session = mgmt_session_id2ctx(session_id);
		if (!session) {
			fe_adapter_conn_send_error(
				adapter->conn, session_id, msg->req_id, false,
				-EINVAL,
				"No session to delete for session-id: %" PRIu64,
				session_id);
			return;
		}
		fe_adapter_native_send_session_reply(adapter, msg->req_id,
						     session_id, false);
		mgmt_fe_cleanup_session(&session);
		return;
	}

	client_id = msg->req_id;

	/* See if we have a client name to register */
	if (msg_len > sizeof(*msg)) {
		if (!MGMT_MSG_VALIDATE_NUL_TERM(msg, msg_len)) {
			fe_adapter_conn_send_error(
				adapter->conn, client_id, msg->req_id, false,
				-EINVAL,
				"Corrupt session-req message rcvd from client-id: %" PRIu64,
				client_id);
			return;
		}
		__dbg("Set client-name to '%s'", msg->client_name);
		strlcpy(adapter->name, msg->client_name, sizeof(adapter->name));
	}

	session = mgmt_fe_create_session(adapter, client_id);
	fe_adapter_native_send_session_reply(adapter, client_id,
					     session->session_id, true);
}

/**
 * fe_adapter_handle_get_data() - Handle a get-tree message from a FE client.
 * @session: the client session.
 * @msg_raw: the message data.
 * @msg_len: the length of the message data.
 */
static void fe_adapter_handle_get_data(struct mgmt_fe_session_ctx *session,
				       void *__msg, size_t msg_len)
{
	struct mgmt_msg_get_data *msg = __msg;
	const struct lysc_node **snodes = NULL;
	uint64_t req_id = msg->req_id;
	Mgmtd__DatastoreId ds_id;
	uint64_t clients;
	uint32_t wd_options;
	bool simple_xpath;
	LY_ERR err;
	int ret;

	__dbg("Received get-data request from client %s for session-id %" PRIu64
	      " req-id %" PRIu64,
	      session->adapter->name, session->session_id, msg->req_id);

	if (!MGMT_MSG_VALIDATE_NUL_TERM(msg, msg_len)) {
		fe_adapter_send_error(session, req_id, false, -EINVAL,
				      "Invalid message rcvd from session-id: %" PRIu64,
				      session->session_id);
		goto done;
	}

	if (session->txn_id != MGMTD_TXN_ID_NONE) {
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "Transaction in progress txn-id: %" PRIu64
				      " for session-id: %" PRIu64,
				      session->txn_id, session->session_id);
		goto done;
	}

	switch (msg->defaults) {
	case GET_DATA_DEFAULTS_EXPLICIT:
		wd_options = LYD_PRINT_WD_EXPLICIT;
		break;
	case GET_DATA_DEFAULTS_TRIM:
		wd_options = LYD_PRINT_WD_TRIM;
		break;
	case GET_DATA_DEFAULTS_ALL:
		wd_options = LYD_PRINT_WD_ALL;
		break;
	case GET_DATA_DEFAULTS_ALL_ADD_TAG:
		wd_options = LYD_PRINT_WD_IMPL_TAG;
		break;
	default:
		fe_adapter_send_error(session, req_id, false, -EINVAL,
				      "Invalid defaults value %u for session-id: %" PRIu64,
				      msg->defaults, session->session_id);
		goto done;
	}

	/* Check for yang-library shortcut */
	if (nb_oper_is_yang_lib_query(msg->xpath)) {
		struct lyd_node *ylib = NULL;
		LY_ERR err;

		err = ly_ctx_get_yanglib_data(ly_native_ctx, &ylib, "%u",
					      ly_ctx_get_change_count(
						      ly_native_ctx));
		if (err) {
			fe_adapter_send_error(session, req_id, false, err,
					      "Error getting yang-library data, session-id: %" PRIu64
					      " error: %s",
					      session->session_id,
					      ly_last_errmsg());
		} else {
			yang_lyd_trim_xpath(&ylib, msg->xpath);
			(void)fe_adapter_send_tree_data(session, req_id, false,
							msg->result_type,
							wd_options, ylib, 0);
		}
		if (ylib)
			lyd_free_all(ylib);
		goto done;
	}

	switch (msg->datastore) {
	case MGMT_MSG_DATASTORE_CANDIDATE:
		ds_id = MGMTD_DS_CANDIDATE;
		break;
	case MGMT_MSG_DATASTORE_RUNNING:
		ds_id = MGMTD_DS_RUNNING;
		break;
	case MGMT_MSG_DATASTORE_OPERATIONAL:
		ds_id = MGMTD_DS_OPERATIONAL;
		break;
	default:
		fe_adapter_send_error(session, req_id, false, -EINVAL,
				      "Unsupported datastore %" PRIu8
				      " requested from session-id: %" PRIu64,
				      msg->datastore, session->session_id);
		goto done;
	}

	err = yang_resolve_snode_xpath(ly_native_ctx, msg->xpath, &snodes,
				       &simple_xpath);
	if (err) {
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "XPath doesn't resolve for session-id: %" PRIu64,
				      session->session_id);
		goto done;
	}
	darr_free(snodes);

	clients = mgmt_be_interested_clients(msg->xpath,
					     MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
	if (!clients && !CHECK_FLAG(msg->flags, GET_DATA_FLAG_CONFIG)) {
		__dbg("No backends provide xpath: %s for txn-id: %" PRIu64
		      " session-id: %" PRIu64,
		      msg->xpath, session->txn_id, session->session_id);

		fe_adapter_send_tree_data(session, req_id, false,
					  msg->result_type, wd_options, NULL, 0);
		goto done;
	}

	/* Start a SHOW Transaction */
	session->txn_id = mgmt_create_txn(session->session_id,
					  MGMTD_TXN_TYPE_SHOW);
	if (session->txn_id == MGMTD_SESSION_ID_NONE) {
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "failed to create a 'show' txn");
		goto done;
	}

	__dbg("Created new show txn-id: %" PRIu64 " for session-id: %" PRIu64,
	      session->txn_id, session->session_id);

	/* Create a GET-TREE request under the transaction */
	ret = mgmt_txn_send_get_tree_oper(session->txn_id, req_id, clients,
					  ds_id, msg->result_type, msg->flags,
					  wd_options, simple_xpath, msg->xpath);
	if (ret) {
		/* destroy the just created txn */
		mgmt_destroy_txn(&session->txn_id);
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "failed to create a 'show' txn");
	}
done:
	darr_free(snodes);
}

static void fe_adapter_handle_edit(struct mgmt_fe_session_ctx *session,
				   void *__msg, size_t msg_len)
{
	struct mgmt_msg_edit *msg = __msg;
	Mgmtd__DatastoreId ds_id, rds_id;
	struct mgmt_ds_ctx *ds_ctx, *rds_ctx;
	const char *xpath, *data;
	bool lock, commit;
	int ret;

	lock = CHECK_FLAG(msg->flags, EDIT_FLAG_IMPLICIT_LOCK);
	commit = CHECK_FLAG(msg->flags, EDIT_FLAG_IMPLICIT_COMMIT);

	if (lock && commit && msg->datastore == MGMT_MSG_DATASTORE_RUNNING)
		;
	else if (msg->datastore != MGMT_MSG_DATASTORE_CANDIDATE) {
		fe_adapter_send_error(session, msg->req_id, false, -EINVAL,
				      "Unsupported datastore");
		return;
	}

	xpath = mgmt_msg_native_xpath_data_decode(msg, msg_len, data);
	if (!xpath) {
		fe_adapter_send_error(session, msg->req_id, false, -EINVAL,
				      "Invalid message");
		return;
	}

	ds_id = MGMTD_DS_CANDIDATE;
	ds_ctx = mgmt_ds_get_ctx_by_id(mm, ds_id);
	assert(ds_ctx);

	rds_id = MGMTD_DS_RUNNING;
	rds_ctx = mgmt_ds_get_ctx_by_id(mm, rds_id);
	assert(rds_ctx);

	if (lock) {
		if (mgmt_fe_session_write_lock_ds(ds_id, ds_ctx, session)) {
			fe_adapter_send_error(session, msg->req_id, false,
					      -EBUSY,
					      "Candidate DS is locked by another session");
			return;
		}

		if (commit) {
			if (mgmt_fe_session_write_lock_ds(rds_id, rds_ctx,
							  session)) {
				mgmt_fe_session_unlock_ds(ds_id, ds_ctx,
							  session);
				fe_adapter_send_error(
					session, msg->req_id, false, -EBUSY,
					"Running DS is locked by another session");
				return;
			}
		}
	} else {
		if (!session->ds_locked[ds_id]) {
			fe_adapter_send_error(session, msg->req_id, false,
					      -EBUSY,
					      "Candidate DS is not locked");
			return;
		}

		if (commit) {
			if (!session->ds_locked[rds_id]) {
				fe_adapter_send_error(session, msg->req_id,
						      false, -EBUSY,
						      "Running DS is not locked");
				return;
			}
		}
	}

	session->cfg_txn_id = mgmt_create_txn(session->session_id,
					      MGMTD_TXN_TYPE_CONFIG);
	if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
		if (lock) {
			mgmt_fe_session_unlock_ds(ds_id, ds_ctx, session);
			if (commit)
				mgmt_fe_session_unlock_ds(rds_id, rds_ctx,
							  session);
		}
		fe_adapter_send_error(session, msg->req_id, false, -EBUSY,
				      "Failed to create a configuration transaction");
		return;
	}

	__dbg("Created new config txn-id: %" PRIu64 " for session-id: %" PRIu64,
	      session->cfg_txn_id, session->session_id);

	ret = mgmt_txn_send_edit(session->cfg_txn_id, msg->req_id, ds_id,
				 ds_ctx, rds_id, rds_ctx, lock, commit,
				 msg->request_type, msg->flags, msg->operation,
				 xpath, data);
	if (ret) {
		/* destroy the just created txn */
		mgmt_destroy_txn(&session->cfg_txn_id);
		if (lock) {
			mgmt_fe_session_unlock_ds(ds_id, ds_ctx, session);
			if (commit)
				mgmt_fe_session_unlock_ds(rds_id, rds_ctx,
							  session);
		}
		fe_adapter_send_error(session, msg->req_id, false, -EBUSY,
				      "Failed to create a configuration transaction");
	}
}

/**
 * fe_adapter_handle_notify_select() - Handle an Notify Select message.
 * @session: the client session.
 * @__msg: the message data.
 * @msg_len: the length of the message data.
 */
static void fe_adapter_handle_notify_select(struct mgmt_fe_session_ctx *session,
					    void *__msg, size_t msg_len)
{
	struct mgmt_msg_notify_select *msg = __msg;
	uint64_t req_id = msg->req_id;
	const char **selectors = NULL;
	const char **new;

	if (msg_len >= sizeof(*msg)) {
		selectors = mgmt_msg_native_strings_decode(msg, msg_len,
							   msg->selectors);
		if (!selectors) {
			fe_adapter_send_error(session, req_id, false, -EINVAL,
					      "Invalid message");
			return;
		}
	}
	if (msg->replace) {
		darr_free_free(session->notify_xpaths);
		session->notify_xpaths = selectors;
	} else if (selectors) {
		new = darr_append_nz(session->notify_xpaths,
				     darr_len(selectors));
		memcpy(new, selectors, darr_len(selectors) * sizeof(*selectors));
		darr_free(selectors);
	}
}

/**
 * fe_adapter_handle_rpc() - Handle an RPC message from an FE client.
 * @session: the client session.
 * @__msg: the message data.
 * @msg_len: the length of the message data.
 */
static void fe_adapter_handle_rpc(struct mgmt_fe_session_ctx *session,
				  void *__msg, size_t msg_len)
{
	struct mgmt_msg_rpc *msg = __msg;
	const struct lysc_node *snode;
	const char *xpath, *data;
	uint64_t req_id = msg->req_id;
	uint64_t clients;
	int ret;

	__dbg("Received RPC request from client %s for session-id %" PRIu64
	      " req-id %" PRIu64,
	      session->adapter->name, session->session_id, msg->req_id);

	xpath = mgmt_msg_native_xpath_data_decode(msg, msg_len, data);
	if (!xpath) {
		fe_adapter_send_error(session, req_id, false, -EINVAL,
				      "Invalid message");
		return;
	}

	if (session->txn_id != MGMTD_TXN_ID_NONE) {
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "Transaction in progress txn-id: %" PRIu64
				      " for session-id: %" PRIu64,
				      session->txn_id, session->session_id);
		return;
	}

	snode = lys_find_path(ly_native_ctx, NULL, xpath, 0);
	if (!snode) {
		fe_adapter_send_error(session, req_id, false, -ENOENT,
				      "No such path: %s", xpath);
		return;
	}

	if (snode->nodetype != LYS_RPC && snode->nodetype != LYS_ACTION) {
		fe_adapter_send_error(session, req_id, false, -EINVAL,
				      "Not an RPC or action path: %s", xpath);
		return;
	}

	clients = mgmt_be_interested_clients(xpath,
					     MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
	if (!clients) {
		__dbg("No backends implement xpath: %s for txn-id: %" PRIu64
		      " session-id: %" PRIu64,
		      xpath, session->txn_id, session->session_id);

		fe_adapter_send_error(session, req_id, false, -ENOENT,
				      "No backends implement xpath: %s", xpath);
		return;
	}

	/* Start a RPC Transaction */
	session->txn_id = mgmt_create_txn(session->session_id,
					  MGMTD_TXN_TYPE_RPC);
	if (session->txn_id == MGMTD_SESSION_ID_NONE) {
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "Failed to create an RPC transaction");
		return;
	}

	__dbg("Created new rpc txn-id: %" PRIu64 " for session-id: %" PRIu64,
	      session->txn_id, session->session_id);

	/* Create an RPC request under the transaction */
	ret = mgmt_txn_send_rpc(session->txn_id, req_id, clients,
				msg->request_type, xpath, data,
				mgmt_msg_native_data_len_decode(msg, msg_len));
	if (ret) {
		/* destroy the just created txn */
		mgmt_destroy_txn(&session->txn_id);
		fe_adapter_send_error(session, req_id, false, -EINPROGRESS,
				      "Failed to create an RPC transaction");
	}
}

/**
 * Handle a native encoded message from the FE client.
 */
static void fe_adapter_handle_native_msg(struct mgmt_fe_client_adapter *adapter,
					 struct mgmt_msg_header *msg,
					 size_t msg_len)
{
	struct mgmt_fe_session_ctx *session;
	size_t min_size = mgmt_msg_get_min_size(msg->code);

	if (msg_len < min_size) {
		if (!min_size)
			__log_err("adapter %s: recv msg refer-id %" PRIu64
				  " unknown message type %u",
				  adapter->name, msg->refer_id, msg->code);
		else
			__log_err("adapter %s: recv msg refer-id %" PRIu64
				  " short (%zu<%zu) msg for type %u",
				  adapter->name, msg->refer_id, msg_len,
				  min_size, msg->code);
		return;
	}

	if (msg->code == MGMT_MSG_CODE_SESSION_REQ) {
		__dbg("adapter %s: session-id %" PRIu64
		      " received SESSION_REQ message",
		      adapter->name, msg->refer_id);
		fe_adapter_handle_session_req(adapter, msg, msg_len);
		return;
	}

	session = mgmt_session_id2ctx(msg->refer_id);
	if (!session) {
		__log_err("adapter %s: recv msg unknown session-id %" PRIu64,
			  adapter->name, msg->refer_id);
		return;
	}
	assert(session->adapter == adapter);

	switch (msg->code) {
	case MGMT_MSG_CODE_EDIT:
		__dbg("adapter %s: session-id %" PRIu64 " received EDIT message",
		      adapter->name, msg->refer_id);
		fe_adapter_handle_edit(session, msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY_SELECT:
		__dbg("adapter %s: session-id %" PRIu64
		      " received NOTIFY_SELECT message",
		      adapter->name, msg->refer_id);
		fe_adapter_handle_notify_select(session, msg, msg_len);
		break;
	case MGMT_MSG_CODE_GET_DATA:
		__dbg("adapter %s: session-id %" PRIu64
		      " received GET_DATA message",
		      adapter->name, msg->refer_id);
		fe_adapter_handle_get_data(session, msg, msg_len);
		break;
	case MGMT_MSG_CODE_RPC:
		__dbg("adapter %s: session-id %" PRIu64 " received RPC message",
		      adapter->name, msg->refer_id);
		fe_adapter_handle_rpc(session, msg, msg_len);
		break;
	default:
		__log_err("unknown native message session-id %" PRIu64
			  " req-id %" PRIu64 " code %u to FE adapter %s",
			  msg->refer_id, msg->req_id, msg->code, adapter->name);
		break;
	}
}


static void mgmt_fe_adapter_process_msg(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *conn)
{
	struct mgmt_fe_client_adapter *adapter = conn->user;
	Mgmtd__FeMessage *fe_msg;

	if (version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *msg = (typeof(msg))data;

		if (len >= sizeof(*msg))
			fe_adapter_handle_native_msg(adapter, msg, len);
		else
			__log_err("native message to adapter %s too short %zu",
				  adapter->name, len);
		return;
	}

	fe_msg = mgmtd__fe_message__unpack(NULL, len, data);
	if (!fe_msg) {
		__dbg("Failed to decode %zu bytes for adapter: %s", len,
		      adapter->name);
		return;
	}
	__dbg("Decoded %zu bytes of message: %u from adapter: %s", len,
	      fe_msg->message_case, adapter->name);
	(void)mgmt_fe_adapter_handle_msg(adapter, fe_msg);
	mgmtd__fe_message__free_unpacked(fe_msg, NULL);
}

void mgmt_fe_adapter_send_notify(struct mgmt_msg_notify_data *msg, size_t msglen)
{
	struct mgmt_fe_client_adapter *adapter;
	struct mgmt_fe_session_ctx *session;
	struct nb_node *nb_node;
	const char **xpath_prefix;
	const char *notif;
	bool sendit;
	uint len;

	assert(msg->refer_id == 0);

	notif = mgmt_msg_native_xpath_decode(msg, msglen);
	if (!notif) {
		__log_err("Corrupt notify msg");
		return;
	}

	/*
	 * We need the nb_node to obtain a path which does not include any
	 * specific list entry selectors
	 */
	nb_node = nb_node_find(notif);
	if (!nb_node) {
		__log_err("No schema found for notification: %s", notif);
		return;
	}

	FOREACH_ADAPTER_IN_LIST (adapter) {
		FOREACH_SESSION_IN_LIST (adapter, session) {
			/* If no selectors then always send */
			sendit = !session->notify_xpaths;
			darr_foreach_p (session->notify_xpaths, xpath_prefix) {
				len = strlen(*xpath_prefix);
				if (!strncmp(*xpath_prefix, notif, len) ||
				    !strncmp(*xpath_prefix, nb_node->xpath,
					     len)) {
					sendit = true;
					break;
				}
			}
			if (sendit) {
				msg->refer_id = session->session_id;
				(void)fe_adapter_send_native_msg(adapter, msg,
								 msglen, false);
			}
		}
	}
	msg->refer_id = 0;
}

void mgmt_fe_adapter_lock(struct mgmt_fe_client_adapter *adapter)
{
	adapter->refcount++;
}

extern void mgmt_fe_adapter_unlock(struct mgmt_fe_client_adapter **adapter)
{
	struct mgmt_fe_client_adapter *a = *adapter;
	assert(a && a->refcount);

	if (!--a->refcount) {
		mgmt_fe_adapters_del(&mgmt_fe_adapters, a);
		msg_server_conn_delete(a->conn);
		XFREE(MTYPE_MGMTD_FE_ADPATER, a);
	}
	*adapter = NULL;
}

/*
 * Initialize the FE adapter module
 */
void mgmt_fe_adapter_init(struct event_loop *tm)
{
	char server_path[MAXPATHLEN];

	assert(!mgmt_loop);
	mgmt_loop = tm;

	mgmt_fe_adapters_init(&mgmt_fe_adapters);

	assert(!mgmt_fe_sessions);
	mgmt_fe_sessions =
		hash_create(mgmt_fe_session_hash_key, mgmt_fe_session_hash_cmp,
			    "MGMT Frontend Sessions");

	snprintf(server_path, sizeof(server_path), MGMTD_FE_SOCK_NAME);

	if (msg_server_init(&mgmt_fe_server, server_path, tm,
			    mgmt_fe_create_adapter, "frontend", &mgmt_debug_fe)) {
		zlog_err("cannot initialize frontend server");
		exit(1);
	}
}

static void mgmt_fe_abort_if_session(void *data)
{
	struct mgmt_fe_session_ctx *session = data;

	__log_err("found orphaned session id %" PRIu64 " client id %" PRIu64
		  " adapter %s",
		  session->session_id, session->client_id,
		  session->adapter ? session->adapter->name : "NULL");
	abort();
}

/*
 * Destroy the FE adapter module
 */
void mgmt_fe_adapter_destroy(void)
{
	struct mgmt_fe_client_adapter *adapter;

	msg_server_cleanup(&mgmt_fe_server);

	/* Deleting the adapters will delete all the sessions */
	FOREACH_ADAPTER_IN_LIST (adapter)
		mgmt_fe_adapter_delete(adapter);

	hash_clean_and_free(&mgmt_fe_sessions, mgmt_fe_abort_if_session);
}

/*
 * The server accepted a new connection
 */
struct msg_conn *mgmt_fe_create_adapter(int conn_fd, union sockunion *from)
{
	struct mgmt_fe_client_adapter *adapter = NULL;

	adapter = mgmt_fe_find_adapter_by_fd(conn_fd);
	if (!adapter) {
		adapter = XCALLOC(MTYPE_MGMTD_FE_ADPATER,
				sizeof(struct mgmt_fe_client_adapter));
		snprintf(adapter->name, sizeof(adapter->name), "Unknown-FD-%d",
			 conn_fd);

		mgmt_fe_sessions_init(&adapter->fe_sessions);
		mgmt_fe_adapter_lock(adapter);
		mgmt_fe_adapters_add_tail(&mgmt_fe_adapters, adapter);

		adapter->conn = msg_server_conn_create(
			mgmt_loop, conn_fd, mgmt_fe_adapter_notify_disconnect,
			mgmt_fe_adapter_process_msg, MGMTD_FE_MAX_NUM_MSG_PROC,
			MGMTD_FE_MAX_NUM_MSG_WRITE, MGMTD_FE_MAX_MSG_LEN,
			adapter, "FE-adapter");

		adapter->conn->debug = DEBUG_MODE_CHECK(&mgmt_debug_fe,
							DEBUG_MODE_ALL);

		adapter->setcfg_stats.min_tm = ULONG_MAX;
		adapter->cmt_stats.min_tm = ULONG_MAX;
		__dbg("Added new MGMTD Frontend adapter '%s'", adapter->name);
	}
	return adapter->conn;
}

int mgmt_fe_send_set_cfg_reply(uint64_t session_id, uint64_t txn_id,
				   Mgmtd__DatastoreId ds_id, uint64_t req_id,
				   enum mgmt_result result,
				   const char *error_if_any,
				   bool implicit_commit)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->cfg_txn_id != txn_id) {
		if (session)
			__log_err("txn-id doesn't match, session txn-id is %" PRIu64
				  " current txnid: %" PRIu64,
				  session->cfg_txn_id, txn_id);
		return -1;
	}

	return fe_adapter_send_set_cfg_reply(session, ds_id, req_id,
					     result == MGMTD_SUCCESS,
					     error_if_any, implicit_commit);
}

int mgmt_fe_send_commit_cfg_reply(uint64_t session_id, uint64_t txn_id,
				      Mgmtd__DatastoreId src_ds_id,
				      Mgmtd__DatastoreId dst_ds_id,
				      uint64_t req_id, bool validate_only,
				      enum mgmt_result result,
				      const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->cfg_txn_id != txn_id)
		return -1;

	return fe_adapter_send_commit_cfg_reply(session, src_ds_id, dst_ds_id,
						req_id, result, validate_only,
						error_if_any);
}

int mgmt_fe_send_get_reply(uint64_t session_id, uint64_t txn_id,
			   Mgmtd__DatastoreId ds_id, uint64_t req_id,
			   enum mgmt_result result,
			   Mgmtd__YangDataReply *data_resp,
			   const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	return fe_adapter_send_get_reply(session, ds_id, req_id,
					 result == MGMTD_SUCCESS, data_resp,
					 error_if_any);
}

int mgmt_fe_adapter_send_tree_data(uint64_t session_id, uint64_t txn_id,
				   uint64_t req_id, LYD_FORMAT result_type,
				   uint32_t wd_options,
				   const struct lyd_node *tree,
				   int partial_error, bool short_circuit_ok)
{
	struct mgmt_fe_session_ctx *session;
	int ret;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	ret = fe_adapter_send_tree_data(session, req_id, short_circuit_ok,
					result_type, wd_options, tree,
					partial_error);

	mgmt_destroy_txn(&session->txn_id);

	return ret;
}

int mgmt_fe_adapter_send_rpc_reply(uint64_t session_id, uint64_t txn_id,
				   uint64_t req_id, LYD_FORMAT result_type,
				   const struct lyd_node *result)
{
	struct mgmt_fe_session_ctx *session;
	int ret;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	ret = fe_adapter_send_rpc_reply(session, req_id, result_type, result);

	mgmt_destroy_txn(&session->txn_id);

	return ret;
}

int mgmt_fe_adapter_send_edit_reply(uint64_t session_id, uint64_t txn_id,
				    uint64_t req_id, bool unlock, bool commit,
				    bool created, const char *xpath,
				    int16_t error, const char *errstr)
{
	struct mgmt_fe_session_ctx *session;
	Mgmtd__DatastoreId ds_id, rds_id;
	struct mgmt_ds_ctx *ds_ctx, *rds_ctx;
	int ret;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->cfg_txn_id != txn_id)
		return -1;

	if (session->cfg_txn_id != MGMTD_TXN_ID_NONE && commit)
		mgmt_fe_session_register_event(session,
					       MGMTD_FE_SESSION_CFG_TXN_CLNUP);

	if (unlock) {
		ds_id = MGMTD_DS_CANDIDATE;
		ds_ctx = mgmt_ds_get_ctx_by_id(mm, ds_id);
		assert(ds_ctx);

		mgmt_fe_session_unlock_ds(ds_id, ds_ctx, session);

		if (commit) {
			rds_id = MGMTD_DS_RUNNING;
			rds_ctx = mgmt_ds_get_ctx_by_id(mm, rds_id);
			assert(rds_ctx);

			mgmt_fe_session_unlock_ds(rds_id, rds_ctx, session);
		}
	}

	if (error != 0 && error != -EALREADY)
		ret = fe_adapter_send_error(session, req_id, false, error, "%s",
					    errstr);
	else
		ret = fe_adapter_send_edit_reply(session, req_id, created,
						 !error, xpath, errstr);

	if (session->cfg_txn_id != MGMTD_TXN_ID_NONE && !commit)
		mgmt_destroy_txn(&session->cfg_txn_id);

	return ret;
}

/**
 * Send an error back to the FE client and cleanup any in-progress txn.
 */
int mgmt_fe_adapter_txn_error(uint64_t txn_id, uint64_t req_id,
			      bool short_circuit_ok, int16_t error,
			      const char *errstr)
{
	struct mgmt_fe_session_ctx *session;
	int ret;

	session = fe_adapter_session_by_txn_id(txn_id);
	if (!session) {
		__log_err("failed sending error for txn-id %" PRIu64
			  " session not found",
			  txn_id);
		return -ENOENT;
	}


	ret = fe_adapter_send_error(session, req_id, false, error, "%s", errstr);

	mgmt_destroy_txn(&session->txn_id);

	return ret;
}


struct mgmt_setcfg_stats *mgmt_fe_get_session_setcfg_stats(uint64_t session_id)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || !session->adapter)
		return NULL;

	return &session->adapter->setcfg_stats;
}

struct mgmt_commit_stats *
mgmt_fe_get_session_commit_stats(uint64_t session_id)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || !session->adapter)
		return NULL;

	return &session->adapter->cmt_stats;
}

static void
mgmt_fe_adapter_cmt_stats_write(struct vty *vty,
				    struct mgmt_fe_client_adapter *adapter)
{
	char buf[MGMT_LONG_TIME_MAX_LEN];

	if (!mm->perf_stats_en)
		return;

	vty_out(vty, "    Num-Commits: \t\t\t%lu\n",
		adapter->cmt_stats.commit_cnt);
	if (adapter->cmt_stats.commit_cnt > 0) {
		if (mm->perf_stats_en)
			vty_out(vty, "    Max-Commit-Duration: \t\t%lu uSecs\n",
				adapter->cmt_stats.max_tm);
		vty_out(vty, "    Max-Commit-Batch-Size: \t\t%lu\n",
			adapter->cmt_stats.max_batch_cnt);
		if (mm->perf_stats_en)
			vty_out(vty, "    Min-Commit-Duration: \t\t%lu uSecs\n",
				adapter->cmt_stats.min_tm);
		vty_out(vty, "    Min-Commit-Batch-Size: \t\t%lu\n",
			adapter->cmt_stats.min_batch_cnt);
		if (mm->perf_stats_en)
			vty_out(vty,
				"    Last-Commit-Duration: \t\t%lu uSecs\n",
				adapter->cmt_stats.last_exec_tm);
		vty_out(vty, "    Last-Commit-Batch-Size: \t\t%lu\n",
			adapter->cmt_stats.last_batch_cnt);
		vty_out(vty, "    Last-Commit-CfgData-Reqs: \t\t%lu\n",
			adapter->cmt_stats.last_num_cfgdata_reqs);
		vty_out(vty, "    Last-Commit-CfgApply-Reqs: \t\t%lu\n",
			adapter->cmt_stats.last_num_apply_reqs);
		if (mm->perf_stats_en) {
			vty_out(vty, "    Last-Commit-Details:\n");
			vty_out(vty, "      Commit Start: \t\t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.last_start, buf,
					sizeof(buf)));
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
			vty_out(vty, "        Config-Validate Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.validate_start, buf,
					sizeof(buf)));
#endif
			vty_out(vty, "        Prep-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.prep_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Txn-Create Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.txn_create_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Apply-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.apply_cfg_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Apply-Config End: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.apply_cfg_end, buf,
					sizeof(buf)));
			vty_out(vty, "        Txn-Delete Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.txn_del_start, buf,
					sizeof(buf)));
			vty_out(vty, "      Commit End: \t\t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.last_end, buf,
					sizeof(buf)));
		}
	}
}

static void
mgmt_fe_adapter_setcfg_stats_write(struct vty *vty,
				       struct mgmt_fe_client_adapter *adapter)
{
	char buf[MGMT_LONG_TIME_MAX_LEN];

	if (!mm->perf_stats_en)
		return;

	vty_out(vty, "    Num-Set-Cfg: \t\t\t%lu\n",
		adapter->setcfg_stats.set_cfg_count);
	if (mm->perf_stats_en && adapter->setcfg_stats.set_cfg_count > 0) {
		vty_out(vty, "    Max-Set-Cfg-Duration: \t\t%lu uSec\n",
			adapter->setcfg_stats.max_tm);
		vty_out(vty, "    Min-Set-Cfg-Duration: \t\t%lu uSec\n",
			adapter->setcfg_stats.min_tm);
		vty_out(vty, "    Avg-Set-Cfg-Duration: \t\t%lu uSec\n",
			adapter->setcfg_stats.avg_tm);
		vty_out(vty, "    Last-Set-Cfg-Details:\n");
		vty_out(vty, "      Set-Cfg Start: \t\t\t%s\n",
			mgmt_realtime_to_string(
				&adapter->setcfg_stats.last_start, buf,
				sizeof(buf)));
		vty_out(vty, "      Set-Cfg End: \t\t\t%s\n",
			mgmt_realtime_to_string(&adapter->setcfg_stats.last_end,
						buf, sizeof(buf)));
	}
}

void mgmt_fe_adapter_status_write(struct vty *vty, bool detail)
{
	struct mgmt_fe_client_adapter *adapter;
	struct mgmt_fe_session_ctx *session;
	Mgmtd__DatastoreId ds_id;
	bool locked = false;

	vty_out(vty, "MGMTD Frontend Adpaters\n");

	FOREACH_ADAPTER_IN_LIST (adapter) {
		vty_out(vty, "  Client: \t\t\t\t%s\n", adapter->name);
		vty_out(vty, "    Conn-FD: \t\t\t\t%d\n", adapter->conn->fd);
		if (detail) {
			mgmt_fe_adapter_setcfg_stats_write(vty, adapter);
			mgmt_fe_adapter_cmt_stats_write(vty, adapter);
		}
		vty_out(vty, "    Sessions\n");
		FOREACH_SESSION_IN_LIST (adapter, session) {
			vty_out(vty, "      Session: \t\t\t\t%p\n", session);
			vty_out(vty, "        Client-Id: \t\t\t%" PRIu64 "\n",
				session->client_id);
			vty_out(vty, "        Session-Id: \t\t\t%" PRIu64 "\n",
				session->session_id);
			vty_out(vty, "        DS-Locks:\n");
			FOREACH_MGMTD_DS_ID (ds_id) {
				if (session->ds_locked[ds_id]) {
					locked = true;
					vty_out(vty, "          %s\n",
						mgmt_ds_id2name(ds_id));
				}
			}
			if (!locked)
				vty_out(vty, "          None\n");
		}
		vty_out(vty, "    Total-Sessions: \t\t\t%d\n",
			(int)mgmt_fe_sessions_count(&adapter->fe_sessions));
		vty_out(vty, "    Msg-Recvd: \t\t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.nrxm);
		vty_out(vty, "    Bytes-Recvd: \t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.nrxb);
		vty_out(vty, "    Msg-Sent: \t\t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.ntxm);
		vty_out(vty, "    Bytes-Sent: \t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.ntxb);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_fe_adapters_count(&mgmt_fe_adapters));
}

void mgmt_fe_adapter_perf_measurement(struct vty *vty, bool config)
{
	mm->perf_stats_en = config;
}

void mgmt_fe_adapter_reset_perf_stats(struct vty *vty)
{
	struct mgmt_fe_client_adapter *adapter;
	struct mgmt_fe_session_ctx *session;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		memset(&adapter->setcfg_stats, 0,
		       sizeof(adapter->setcfg_stats));
		FOREACH_SESSION_IN_LIST (adapter, session) {
			memset(&adapter->cmt_stats, 0,
			       sizeof(adapter->cmt_stats));
		}
	}
}
