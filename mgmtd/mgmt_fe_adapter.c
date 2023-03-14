// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_fe_client.h"
#include "mgmt_msg.h"
#include "mgmt_pb.h"
#include "hash.h"
#include "jhash.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_fe_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_FE_ADAPTER_DBG(fmt, ...)                                       \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_FE_ADAPTER_ERR(fmt, ...)                                       \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_FE_ADAPTER_DBG(fmt, ...)                                       \
	do {                                                                 \
		if (mgmt_debug_fe)                                           \
			zlog_debug("%s: " fmt, __func__, ##__VA_ARGS__);     \
	} while (0)
#define MGMTD_FE_ADAPTER_ERR(fmt, ...)                                       \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

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
	uint8_t ds_write_locked[MGMTD_DS_MAX_ID];
	uint8_t ds_read_locked[MGMTD_DS_MAX_ID];
	uint8_t ds_locked_implict[MGMTD_DS_MAX_ID];
	struct thread *proc_cfg_txn_clnp;
	struct thread *proc_show_txn_clnp;

	struct mgmt_fe_sessions_item list_linkage;
};

DECLARE_LIST(mgmt_fe_sessions, struct mgmt_fe_session_ctx, list_linkage);

#define FOREACH_SESSION_IN_LIST(adapter, session)                              \
	frr_each_safe (mgmt_fe_sessions, &(adapter)->fe_sessions, (session))

static struct thread_master *mgmt_fe_adapter_tm;
static struct mgmt_master *mgmt_fe_adapter_mm;

static struct mgmt_fe_adapters_head mgmt_fe_adapters;

static struct hash *mgmt_fe_sessions;
static uint64_t mgmt_fe_next_session_id;

/* Forward declarations */
static void
mgmt_fe_adapter_register_event(struct mgmt_fe_client_adapter *adapter,
				 enum mgmt_fe_event event);
static void
mgmt_fe_adapter_disconnect(struct mgmt_fe_client_adapter *adapter);
static void
mgmt_fe_session_register_event(struct mgmt_fe_session_ctx *session,
				   enum mgmt_session_event event);

static int
mgmt_fe_session_write_lock_ds(Mgmtd__DatastoreId ds_id,
				  struct mgmt_ds_ctx *ds_ctx,
				  struct mgmt_fe_session_ctx *session)
{
	if (!session->ds_write_locked[ds_id]) {
		if (mgmt_ds_write_lock(ds_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to lock the DS %u for Sessn: %p from %s!",
				ds_id, session, session->adapter->name);
			return -1;
		}

		session->ds_write_locked[ds_id] = true;
		MGMTD_FE_ADAPTER_DBG(
			"Write-Locked the DS %u for Sessn: %p from %s!", ds_id,
			session, session->adapter->name);
	}

	return 0;
}

static int
mgmt_fe_session_read_lock_ds(Mgmtd__DatastoreId ds_id,
				 struct mgmt_ds_ctx *ds_ctx,
				 struct mgmt_fe_session_ctx *session)
{
	if (!session->ds_read_locked[ds_id]) {
		if (mgmt_ds_read_lock(ds_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to lock the DS %u for Sessn: %p from %s!",
				ds_id, session, session->adapter->name);
			return -1;
		}

		session->ds_read_locked[ds_id] = true;
		MGMTD_FE_ADAPTER_DBG(
			"Read-Locked the DS %u for Sessn: %p from %s!", ds_id,
			session, session->adapter->name);
	}

	return 0;
}

static int mgmt_fe_session_unlock_ds(Mgmtd__DatastoreId ds_id,
					 struct mgmt_ds_ctx *ds_ctx,
					 struct mgmt_fe_session_ctx *session,
					 bool unlock_write, bool unlock_read)
{
	if (unlock_write && session->ds_write_locked[ds_id]) {
		session->ds_write_locked[ds_id] = false;
		session->ds_locked_implict[ds_id] = false;
		if (mgmt_ds_unlock(ds_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to unlock the DS %u taken earlier by Sessn: %p from %s!",
				ds_id, session, session->adapter->name);
			return -1;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Unlocked DS %u write-locked earlier by Sessn: %p from %s",
			ds_id, session, session->adapter->name);
	} else if (unlock_read && session->ds_read_locked[ds_id]) {
		session->ds_read_locked[ds_id] = false;
		session->ds_locked_implict[ds_id] = false;
		if (mgmt_ds_unlock(ds_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to unlock the DS %u taken earlier by Sessn: %p from %s!",
				ds_id, session, session->adapter->name);
			return -1;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Unlocked DS %u read-locked earlier by Sessn: %p from %s",
			ds_id, session, session->adapter->name);
	}

	return 0;
}

static void
mgmt_fe_session_cfg_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	Mgmtd__DatastoreId ds_id;
	struct mgmt_ds_ctx *ds_ctx;

	/*
	 * Ensure any uncommitted changes in Candidate DS
	 * is discarded.
	 */
	mgmt_ds_copy_dss(mm->running_ds, mm->candidate_ds, false);

	for (ds_id = 0; ds_id < MGMTD_DS_MAX_ID; ds_id++) {
		ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm, ds_id);
		if (ds_ctx) {
			if (session->ds_locked_implict[ds_id])
				mgmt_fe_session_unlock_ds(
					ds_id, ds_ctx, session, true, false);
		}
	}

	/*
	 * Destroy the actual transaction created earlier.
	 */
	if (session->cfg_txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->cfg_txn_id);
}

static void
mgmt_fe_session_show_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	Mgmtd__DatastoreId ds_id;
	struct mgmt_ds_ctx *ds_ctx;

	for (ds_id = 0; ds_id < MGMTD_DS_MAX_ID; ds_id++) {
		ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm, ds_id);
		if (ds_ctx) {
			mgmt_fe_session_unlock_ds(ds_id, ds_ctx, session,
						      false, true);
		}
	}

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

static void mgmt_fe_cleanup_session(struct mgmt_fe_session_ctx **session)
{
	if ((*session)->adapter) {
		mgmt_fe_session_cfg_txn_cleanup((*session));
		mgmt_fe_session_show_txn_cleanup((*session));
		mgmt_fe_session_unlock_ds(MGMTD_DS_CANDIDATE,
					  mgmt_fe_adapter_mm->candidate_ds,
					  *session, true, true);
		mgmt_fe_session_unlock_ds(MGMTD_DS_RUNNING,
					  mgmt_fe_adapter_mm->running_ds,
					  *session, true, true);

		mgmt_fe_sessions_del(&(*session)->adapter->fe_sessions,
				     *session);
		mgmt_fe_adapter_unlock(&(*session)->adapter);
	}

	hash_release(mgmt_fe_sessions, *session);
	XFREE(MTYPE_MGMTD_FE_SESSION, *session);
	*session = NULL;
}

static struct mgmt_fe_session_ctx *
mgmt_fe_find_session_by_client_id(struct mgmt_fe_client_adapter *adapter,
				      uint64_t client_id)
{
	struct mgmt_fe_session_ctx *session;

	FOREACH_SESSION_IN_LIST (adapter, session) {
		if (session->client_id == client_id)
			return session;
	}

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

static void mgmt_fe_session_hash_free(void *data)
{
	struct mgmt_fe_session_ctx *session = data;

	mgmt_fe_cleanup_session(&session);
}

static void mgmt_fe_session_hash_destroy(void)
{
	if (mgmt_fe_sessions == NULL)
		return;

	hash_clean(mgmt_fe_sessions,
		   mgmt_fe_session_hash_free);
	hash_free(mgmt_fe_sessions);
	mgmt_fe_sessions = NULL;
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

static void
mgmt_fe_cleanup_sessions(struct mgmt_fe_client_adapter *adapter)
{
	struct mgmt_fe_session_ctx *session;

	FOREACH_SESSION_IN_LIST (adapter, session)
		mgmt_fe_cleanup_session(&session);
}

static inline void
mgmt_fe_adapter_sched_msg_write(struct mgmt_fe_client_adapter *adapter)
{
	if (!CHECK_FLAG(adapter->flags, MGMTD_FE_ADAPTER_FLAGS_WRITES_OFF))
		mgmt_fe_adapter_register_event(adapter,
						 MGMTD_FE_CONN_WRITE);
}

static inline void
mgmt_fe_adapter_writes_on(struct mgmt_fe_client_adapter *adapter)
{
	MGMTD_FE_ADAPTER_DBG("Resume writing msgs for '%s'", adapter->name);
	UNSET_FLAG(adapter->flags, MGMTD_FE_ADAPTER_FLAGS_WRITES_OFF);
	mgmt_fe_adapter_sched_msg_write(adapter);
}

static inline void
mgmt_fe_adapter_writes_off(struct mgmt_fe_client_adapter *adapter)
{
	SET_FLAG(adapter->flags, MGMTD_FE_ADAPTER_FLAGS_WRITES_OFF);
	MGMTD_FE_ADAPTER_DBG("Paused writing msgs for '%s'", adapter->name);
}

static int
mgmt_fe_adapter_send_msg(struct mgmt_fe_client_adapter *adapter,
			     Mgmtd__FeMessage *fe_msg)
{
	if (adapter->conn_fd == -1) {
		MGMTD_FE_ADAPTER_DBG("can't send message on closed connection");
		return -1;
	}

	int rv = mgmt_msg_send_msg(
		&adapter->mstate, fe_msg,
		mgmtd__fe_message__get_packed_size(fe_msg),
		(size_t(*)(void *, void *))mgmtd__fe_message__pack,
		mgmt_debug_fe);
	mgmt_fe_adapter_sched_msg_write(adapter);
	return rv;
}

static int
mgmt_fe_send_session_reply(struct mgmt_fe_client_adapter *adapter,
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

	MGMTD_FE_ADAPTER_DBG(
		"Sending SESSION_REPLY message to MGMTD Frontend client '%s'",
		adapter->name);

	return mgmt_fe_adapter_send_msg(adapter, &fe_msg);
}

static int mgmt_fe_send_lockds_reply(struct mgmt_fe_session_ctx *session,
					 Mgmtd__DatastoreId ds_id,
					 uint64_t req_id, bool lock_ds,
					 bool success, const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeLockDsReply lockds_reply;

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

	MGMTD_FE_ADAPTER_DBG(
		"Sending LOCK_DS_REPLY message to MGMTD Frontend client '%s'",
		session->adapter->name);

	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static int mgmt_fe_send_setcfg_reply(struct mgmt_fe_session_ctx *session,
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
	if (error_if_any)
		setcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY;
	fe_msg.setcfg_reply = &setcfg_reply;

	MGMTD_FE_ADAPTER_DBG(
		"Sending SET_CONFIG_REPLY message to MGMTD Frontend client '%s'",
		session->adapter->name);

	if (implicit_commit) {
		if (mm->perf_stats_en)
			gettimeofday(&session->adapter->cmt_stats.last_end, NULL);
		mgmt_fe_session_compute_commit_timers(
			&session->adapter->cmt_stats);
	}

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->setcfg_stats.last_end, NULL);
	mgmt_fe_adapter_compute_set_cfg_timers(&session->adapter->setcfg_stats);

	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static int mgmt_fe_send_commitcfg_reply(
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

	MGMTD_FE_ADAPTER_DBG(
		"Sending COMMIT_CONFIG_REPLY message to MGMTD Frontend client '%s'",
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
	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static int mgmt_fe_send_getcfg_reply(struct mgmt_fe_session_ctx *session,
					 Mgmtd__DatastoreId ds_id,
					 uint64_t req_id, bool success,
					 Mgmtd__YangDataReply *data,
					 const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetConfigReply getcfg_reply;

	assert(session->adapter);

	mgmtd__fe_get_config_reply__init(&getcfg_reply);
	getcfg_reply.session_id = session->session_id;
	getcfg_reply.ds_id = ds_id;
	getcfg_reply.req_id = req_id;
	getcfg_reply.success = success;
	getcfg_reply.data = data;
	if (error_if_any)
		getcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REPLY;
	fe_msg.getcfg_reply = &getcfg_reply;

	MGMTD_FE_ADAPTER_DBG(
		"Sending GET_CONFIG_REPLY message to MGMTD Frontend client '%s'",
		session->adapter->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (session->txn_id && (!success || (data && data->next_indx < 0)))
		mgmt_fe_session_register_event(
			session, MGMTD_FE_SESSION_SHOW_TXN_CLNUP);

	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static int mgmt_fe_send_getdata_reply(struct mgmt_fe_session_ctx *session,
					  Mgmtd__DatastoreId ds_id,
					  uint64_t req_id, bool success,
					  Mgmtd__YangDataReply *data,
					  const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetDataReply getdata_reply;

	assert(session->adapter);

	mgmtd__fe_get_data_reply__init(&getdata_reply);
	getdata_reply.session_id = session->session_id;
	getdata_reply.ds_id = ds_id;
	getdata_reply.req_id = req_id;
	getdata_reply.success = success;
	getdata_reply.data = data;
	if (error_if_any)
		getdata_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REPLY;
	fe_msg.getdata_reply = &getdata_reply;

	MGMTD_FE_ADAPTER_DBG(
		"Sending GET_DATA_REPLY message to MGMTD Frontend client '%s'",
		session->adapter->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (session->txn_id && (!success || (data && data->next_indx < 0)))
		mgmt_fe_session_register_event(
			session, MGMTD_FE_SESSION_SHOW_TXN_CLNUP);

	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static void mgmt_fe_session_cfg_txn_clnup(struct thread *thread)
{
	struct mgmt_fe_session_ctx *session;

	session = (struct mgmt_fe_session_ctx *)THREAD_ARG(thread);

	mgmt_fe_session_cfg_txn_cleanup(session);
}

static void mgmt_fe_session_show_txn_clnup(struct thread *thread)
{
	struct mgmt_fe_session_ctx *session;

	session = (struct mgmt_fe_session_ctx *)THREAD_ARG(thread);

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
		thread_add_timer_tv(mgmt_fe_adapter_tm,
				    mgmt_fe_session_cfg_txn_clnup, session,
				    &tv, &session->proc_cfg_txn_clnp);
		assert(session->proc_cfg_txn_clnp);
		break;
	case MGMTD_FE_SESSION_SHOW_TXN_CLNUP:
		thread_add_timer_tv(mgmt_fe_adapter_tm,
				    mgmt_fe_session_show_txn_clnup, session,
				    &tv, &session->proc_show_txn_clnp);
		assert(session->proc_show_txn_clnp);
		break;
	}
}

static struct mgmt_fe_client_adapter *
mgmt_fe_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_fe_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (adapter->conn_fd == conn_fd)
			return adapter;
	}

	return NULL;
}

static struct mgmt_fe_client_adapter *
mgmt_fe_find_adapter_by_name(const char *name)
{
	struct mgmt_fe_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (!strncmp(adapter->name, name, sizeof(adapter->name)))
			return adapter;
	}

	return NULL;
}

static void mgmt_fe_adapter_disconnect(struct mgmt_fe_client_adapter *adapter)
{
	if (adapter->conn_fd >= 0) {
		close(adapter->conn_fd);
		adapter->conn_fd = -1;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	mgmt_fe_cleanup_sessions(adapter);
	mgmt_fe_sessions_fini(&adapter->fe_sessions);
	mgmt_fe_adapters_del(&mgmt_fe_adapters, adapter);

	mgmt_fe_adapter_unlock(&adapter);
}

static void
mgmt_fe_adapter_cleanup_old_conn(struct mgmt_fe_client_adapter *adapter)
{
	struct mgmt_fe_client_adapter *old;

	FOREACH_ADAPTER_IN_LIST (old) {
		if (old != adapter
		    && !strncmp(adapter->name, old->name, sizeof(adapter->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			MGMTD_FE_ADAPTER_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adapter->name, adapter->conn_fd, old->conn_fd);
			mgmt_fe_adapter_disconnect(old);
		}
	}
}

static void
mgmt_fe_cleanup_adapters(void)
{
	struct mgmt_fe_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		mgmt_fe_cleanup_sessions(adapter);
		mgmt_fe_adapter_unlock(&adapter);
	}
}

static int
mgmt_fe_session_handle_lockds_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeLockDsReq *lockds_req)
{
	struct mgmt_ds_ctx *ds_ctx;

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DS
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DS.
	 */
	if (lockds_req->ds_id != MGMTD_DS_CANDIDATE) {
		mgmt_fe_send_lockds_reply(
			session, lockds_req->ds_id, lockds_req->req_id,
			lockds_req->lock, false,
			"Lock/Unlock on datastores other than Candidate DS not permitted!");
		return -1;
	}

	ds_ctx =
		mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm, lockds_req->ds_id);
	if (!ds_ctx) {
		mgmt_fe_send_lockds_reply(
			session, lockds_req->ds_id, lockds_req->req_id,
			lockds_req->lock, false,
			"Failed to retrieve handle for DS!");
		return -1;
	}

	if (lockds_req->lock) {
		if (mgmt_fe_session_write_lock_ds(lockds_req->ds_id,
						      ds_ctx, session)
		    != 0) {
			mgmt_fe_send_lockds_reply(
				session, lockds_req->ds_id, lockds_req->req_id,
				lockds_req->lock, false,
				"Lock already taken on DS by another session!");
			return -1;
		}

		session->ds_locked_implict[lockds_req->ds_id] = false;
	} else {
		if (!session->ds_write_locked[lockds_req->ds_id]) {
			mgmt_fe_send_lockds_reply(
				session, lockds_req->ds_id, lockds_req->req_id,
				lockds_req->lock, false,
				"Lock on DS was not taken by this session!");
			return 0;
		}

		(void)mgmt_fe_session_unlock_ds(lockds_req->ds_id, ds_ctx,
						    session, true, false);
	}

	if (mgmt_fe_send_lockds_reply(session, lockds_req->ds_id,
					   lockds_req->req_id, lockds_req->lock,
					   true, NULL)
	    != 0) {
		MGMTD_FE_ADAPTER_DBG(
			"Failed to send LOCK_DS_REPLY for DS %u Sessn: %p from %s",
			lockds_req->ds_id, session, session->adapter->name);
	}

	return 0;
}

static int
mgmt_fe_session_handle_setcfg_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeSetConfigReq *setcfg_req)
{
	uint64_t cfg_session_id;
	struct mgmt_ds_ctx *ds_ctx, *dst_ds_ctx;

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->setcfg_stats.last_start, NULL);

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DS
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DS.
	 */
	if (setcfg_req->ds_id != MGMTD_DS_CANDIDATE) {
		mgmt_fe_send_setcfg_reply(
			session, setcfg_req->ds_id, setcfg_req->req_id, false,
			"Set-Config on datastores other than Candidate DS not permitted!",
			setcfg_req->implicit_commit);
		return 0;
	}

	/*
	 * Get the DS handle.
	 */
	ds_ctx =
		mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm, setcfg_req->ds_id);
	if (!ds_ctx) {
		mgmt_fe_send_setcfg_reply(
			session, setcfg_req->ds_id, setcfg_req->req_id, false,
			"No such DS exists!", setcfg_req->implicit_commit);
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Check first if the current session can run a CONFIG
		 * transaction or not. Report failure if a CONFIG transaction
		 * from another session is already in progress.
		 */
		cfg_session_id = mgmt_config_txn_in_progress();
		if (cfg_session_id != MGMTD_SESSION_ID_NONE
		   && cfg_session_id != session->session_id) {
			mgmt_fe_send_setcfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false,
				"Configuration already in-progress through a different user session!",
				setcfg_req->implicit_commit);
			goto mgmt_fe_sess_handle_setcfg_req_failed;
		}


		/*
		 * Try taking write-lock on the requested DS (if not already).
		 */
		if (!session->ds_write_locked[setcfg_req->ds_id]) {
			if (mgmt_fe_session_write_lock_ds(setcfg_req->ds_id,
							      ds_ctx, session)
			    != 0) {
				mgmt_fe_send_setcfg_reply(
					session, setcfg_req->ds_id,
					setcfg_req->req_id, false,
					"Failed to lock the DS!",
					setcfg_req->implicit_commit);
				goto mgmt_fe_sess_handle_setcfg_req_failed;
			}

			session->ds_locked_implict[setcfg_req->ds_id] = true;
		}

		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		session->cfg_txn_id = mgmt_create_txn(session->session_id,
						      MGMTD_TXN_TYPE_CONFIG);
		if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
			mgmt_fe_send_setcfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false,
				"Failed to create a Configuration session!",
				setcfg_req->implicit_commit);
			goto mgmt_fe_sess_handle_setcfg_req_failed;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Created new Config Txn 0x%llx for session %p",
			(unsigned long long)session->cfg_txn_id, session);
	} else {
		MGMTD_FE_ADAPTER_DBG(
			"Config Txn 0x%llx for session %p already created",
			(unsigned long long)session->cfg_txn_id, session);

		if (setcfg_req->implicit_commit) {
			/*
			 * In this scenario need to skip cleanup of the txn,
			 * so setting implicit commit to false.
			 */
			mgmt_fe_send_setcfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false,
				"A Configuration transaction is already in progress!",
				false);
			return 0;
		}
	}

	dst_ds_ctx = 0;
	if (setcfg_req->implicit_commit) {
		dst_ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm,
						     setcfg_req->commit_ds_id);
		if (!dst_ds_ctx) {
			mgmt_fe_send_setcfg_reply(
				session, setcfg_req->ds_id, setcfg_req->req_id,
				false, "No such commit DS exists!",
				setcfg_req->implicit_commit);
			return 0;
		}
	}

	/*
	 * Create the SETConfig request under the transaction.
	 */
	if (mgmt_txn_send_set_config_req(
		    session->cfg_txn_id, setcfg_req->req_id, setcfg_req->ds_id,
		    ds_ctx, setcfg_req->data, setcfg_req->n_data,
		    setcfg_req->implicit_commit, setcfg_req->commit_ds_id,
		    dst_ds_ctx)
	    != 0) {
		mgmt_fe_send_setcfg_reply(
			session, setcfg_req->ds_id, setcfg_req->req_id, false,
			"Request processing for SET-CONFIG failed!",
			setcfg_req->implicit_commit);
		goto mgmt_fe_sess_handle_setcfg_req_failed;
	}

	return 0;

mgmt_fe_sess_handle_setcfg_req_failed:

	/*
	 * Delete transaction created recently.
	 */
	if (session->cfg_txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->cfg_txn_id);
	if (ds_ctx && session->ds_write_locked[setcfg_req->ds_id])
		mgmt_fe_session_unlock_ds(setcfg_req->ds_id, ds_ctx, session,
					      true, false);

	return 0;
}

static int
mgmt_fe_session_handle_getcfg_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeGetConfigReq *getcfg_req)
{
	struct mgmt_ds_ctx *ds_ctx;

	/*
	 * Get the DS handle.
	 */
	ds_ctx =
		mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm, getcfg_req->ds_id);
	if (!ds_ctx) {
		mgmt_fe_send_getcfg_reply(session, getcfg_req->ds_id,
					      getcfg_req->req_id, false, NULL,
					      "No such DS exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DS
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DS.
	 */
	if (getcfg_req->ds_id != MGMTD_DS_CANDIDATE
	    && getcfg_req->ds_id != MGMTD_DS_RUNNING) {
		mgmt_fe_send_getcfg_reply(
			session, getcfg_req->ds_id, getcfg_req->req_id, false,
			NULL,
			"Get-Config on datastores other than Candidate or Running DS not permitted!");
		return 0;
	}

	if (session->txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DS (if not already
		 * locked). If the DS has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DS.
		 */
		if (!session->ds_read_locked[getcfg_req->ds_id]
		    && !session->ds_write_locked[getcfg_req->ds_id]) {
			if (mgmt_fe_session_read_lock_ds(getcfg_req->ds_id,
							     ds_ctx, session)
			    != 0) {
				mgmt_fe_send_getcfg_reply(
					session, getcfg_req->ds_id,
					getcfg_req->req_id, false, NULL,
					"Failed to lock the DS! Another session might have locked it!");
				goto mgmt_fe_sess_handle_getcfg_req_failed;
			}

			session->ds_locked_implict[getcfg_req->ds_id] = true;
		}

		/*
		 * Start a SHOW Transaction (if not started already)
		 */
		session->txn_id = mgmt_create_txn(session->session_id,
						  MGMTD_TXN_TYPE_SHOW);
		if (session->txn_id == MGMTD_SESSION_ID_NONE) {
			mgmt_fe_send_getcfg_reply(
				session, getcfg_req->ds_id, getcfg_req->req_id,
				false, NULL,
				"Failed to create a Show transaction!");
			goto mgmt_fe_sess_handle_getcfg_req_failed;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Created new Show Txn 0x%llx for session %p",
			(unsigned long long)session->txn_id, session);
	} else {
		MGMTD_FE_ADAPTER_DBG(
			"Show Txn 0x%llx for session %p already created",
			(unsigned long long)session->txn_id, session);
	}

	/*
	 * Create a GETConfig request under the transaction.
	 */
	if (mgmt_txn_send_get_config_req(session->txn_id, getcfg_req->req_id,
					  getcfg_req->ds_id, ds_ctx,
					  getcfg_req->data, getcfg_req->n_data)
	    != 0) {
		mgmt_fe_send_getcfg_reply(
			session, getcfg_req->ds_id, getcfg_req->req_id, false,
			NULL, "Request processing for GET-CONFIG failed!");
		goto mgmt_fe_sess_handle_getcfg_req_failed;
	}

	return 0;

mgmt_fe_sess_handle_getcfg_req_failed:

	/*
	 * Destroy the transaction created recently.
	 */
	if (session->txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->txn_id);
	if (ds_ctx && session->ds_read_locked[getcfg_req->ds_id])
		mgmt_fe_session_unlock_ds(getcfg_req->ds_id, ds_ctx, session,
					      false, true);

	return -1;
}

static int
mgmt_fe_session_handle_getdata_req_msg(struct mgmt_fe_session_ctx *session,
					   Mgmtd__FeGetDataReq *getdata_req)
{
	struct mgmt_ds_ctx *ds_ctx;

	/*
	 * Get the DS handle.
	 */
	ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm,
					 getdata_req->ds_id);
	if (!ds_ctx) {
		mgmt_fe_send_getdata_reply(session, getdata_req->ds_id,
					       getdata_req->req_id, false, NULL,
					       "No such DS exists!");
		return 0;
	}

	if (session->txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DS (if not already
		 * locked). If the DS has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DS.
		 */
		if (!session->ds_read_locked[getdata_req->ds_id]
		    && !session->ds_write_locked[getdata_req->ds_id]) {
			if (mgmt_fe_session_read_lock_ds(getdata_req->ds_id,
							     ds_ctx, session)
			    != 0) {
				mgmt_fe_send_getdata_reply(
					session, getdata_req->ds_id,
					getdata_req->req_id, false, NULL,
					"Failed to lock the DS! Another session might have locked it!");
				goto mgmt_fe_sess_handle_getdata_req_failed;
			}

			session->ds_locked_implict[getdata_req->ds_id] = true;
		}

		/*
		 * Start a SHOW Transaction (if not started already)
		 */
		session->txn_id = mgmt_create_txn(session->session_id,
						  MGMTD_TXN_TYPE_SHOW);
		if (session->txn_id == MGMTD_SESSION_ID_NONE) {
			mgmt_fe_send_getdata_reply(
				session, getdata_req->ds_id, getdata_req->req_id,
				false, NULL,
				"Failed to create a Show transaction!");
			goto mgmt_fe_sess_handle_getdata_req_failed;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Created new Show Txn 0x%llx for session %p",
			(unsigned long long)session->txn_id, session);
	} else {
		MGMTD_FE_ADAPTER_DBG(
			"Show Txn 0x%llx for session %p already created",
			(unsigned long long)session->txn_id, session);
	}

	/*
	 * Create a GETData request under the transaction.
	 */
	if (mgmt_txn_send_get_data_req(session->txn_id, getdata_req->req_id,
					getdata_req->ds_id, ds_ctx,
					getdata_req->data, getdata_req->n_data)
	    != 0) {
		mgmt_fe_send_getdata_reply(
			session, getdata_req->ds_id, getdata_req->req_id, false,
			NULL, "Request processing for GET-CONFIG failed!");
		goto mgmt_fe_sess_handle_getdata_req_failed;
	}

	return 0;

mgmt_fe_sess_handle_getdata_req_failed:

	/*
	 * Destroy the transaction created recently.
	 */
	if (session->txn_id != MGMTD_TXN_ID_NONE)
		mgmt_destroy_txn(&session->txn_id);

	if (ds_ctx && session->ds_read_locked[getdata_req->ds_id])
		mgmt_fe_session_unlock_ds(getdata_req->ds_id, ds_ctx,
					      session, false, true);

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
	/*
	 * Get the source DS handle.
	 */
	src_ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm,
					     commcfg_req->src_ds_id);
	if (!src_ds_ctx) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"No such source DS exists!");
		return 0;
	}

	/*
	 * Get the destination DS handle.
	 */
	dst_ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_fe_adapter_mm,
					     commcfg_req->dst_ds_id);
	if (!dst_ds_ctx) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"No such destination DS exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DS
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DS.
	 */
	if (commcfg_req->dst_ds_id != MGMTD_DS_RUNNING) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_ds_id, commcfg_req->dst_ds_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Set-Config on datastores other than Running DS not permitted!");
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		session->cfg_txn_id = mgmt_create_txn(session->session_id,
						MGMTD_TXN_TYPE_CONFIG);
		if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
			mgmt_fe_send_commitcfg_reply(
				session, commcfg_req->src_ds_id,
				commcfg_req->dst_ds_id, commcfg_req->req_id,
				MGMTD_INTERNAL_ERROR,
				commcfg_req->validate_only,
				"Failed to create a Configuration session!");
			return 0;
		}
		MGMTD_FE_ADAPTER_DBG(
			"Created txn %llu for session %llu for COMMIT-CFG-REQ",
			session->cfg_txn_id, session->session_id);
	}


	/*
	 * Try taking write-lock on the destination DS (if not already).
	 */
	if (!session->ds_write_locked[commcfg_req->dst_ds_id]) {
		if (mgmt_fe_session_write_lock_ds(commcfg_req->dst_ds_id,
						      dst_ds_ctx, session)
		    != 0) {
			mgmt_fe_send_commitcfg_reply(
				session, commcfg_req->src_ds_id,
				commcfg_req->dst_ds_id, commcfg_req->req_id,
				MGMTD_DS_LOCK_FAILED,
				commcfg_req->validate_only,
				"Failed to lock the destination DS!");
			return 0;
		}

		session->ds_locked_implict[commcfg_req->dst_ds_id] = true;
	}

	/*
	 * Create COMMITConfig request under the transaction
	 */
	if (mgmt_txn_send_commit_config_req(
		    session->cfg_txn_id, commcfg_req->req_id,
		    commcfg_req->src_ds_id, src_ds_ctx, commcfg_req->dst_ds_id,
		    dst_ds_ctx, commcfg_req->validate_only, commcfg_req->abort,
		    false)
	    != 0) {
		mgmt_fe_send_commitcfg_reply(
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

	switch (fe_msg->message_case) {
	case MGMTD__FE_MESSAGE__MESSAGE_REGISTER_REQ:
		MGMTD_FE_ADAPTER_DBG("Got Register Req Msg from '%s'",
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
			MGMTD_FE_ADAPTER_DBG(
				"Got Session Create Req Msg for client-id %llu from '%s'",
				(unsigned long long)
					fe_msg->session_req->client_conn_id,
				adapter->name);

			session = mgmt_fe_create_session(
				adapter, fe_msg->session_req->client_conn_id);
			mgmt_fe_send_session_reply(adapter, session, true,
						       session ? true : false);
		} else if (
			!fe_msg->session_req->create
			&& fe_msg->session_req->id_case
				== MGMTD__FE_SESSION_REQ__ID_SESSION_ID) {
			MGMTD_FE_ADAPTER_DBG(
				"Got Session Destroy Req Msg for session-id %llu from '%s'",
				(unsigned long long)
					fe_msg->session_req->session_id,
				adapter->name);

			session = mgmt_session_id2ctx(
				fe_msg->session_req->session_id);
			mgmt_fe_send_session_reply(adapter, session, false,
						       true);
			mgmt_fe_cleanup_session(&session);
		}
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->lockds_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got %sockDS Req Msg for DS:%d for session-id %llx from '%s'",
			fe_msg->lockds_req->lock ? "L" : "Unl",
			fe_msg->lockds_req->ds_id,
			(unsigned long long)fe_msg->lockds_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_lockds_req_msg(
			session, fe_msg->lockds_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->setcfg_req->session_id);
		session->adapter->setcfg_stats.set_cfg_count++;
		MGMTD_FE_ADAPTER_DBG(
			"Got Set Config Req Msg (%d Xpaths, Implicit:%c) on DS:%d for session-id %llu from '%s'",
			(int)fe_msg->setcfg_req->n_data,
			fe_msg->setcfg_req->implicit_commit ? 'T':'F',
			fe_msg->setcfg_req->ds_id,
			(unsigned long long)fe_msg->setcfg_req->session_id,
			adapter->name);

		mgmt_fe_session_handle_setcfg_req_msg(
			session, fe_msg->setcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->commcfg_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got Commit Config Req Msg for src-DS:%d dst-DS:%d (Abort:%c) on session-id %llu from '%s'",
			fe_msg->commcfg_req->src_ds_id,
			fe_msg->commcfg_req->dst_ds_id,
			fe_msg->commcfg_req->abort ? 'T':'F',
			(unsigned long long)fe_msg->commcfg_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_commit_config_req_msg(
			session, fe_msg->commcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->getcfg_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got Get-Config Req Msg for DS:%d (xpaths: %d) on session-id %llu from '%s'",
			fe_msg->getcfg_req->ds_id,
			(int)fe_msg->getcfg_req->n_data,
			(unsigned long long)fe_msg->getcfg_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_getcfg_req_msg(
			session, fe_msg->getcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->getdata_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got Get-Data Req Msg for DS:%d (xpaths: %d) on session-id %llu from '%s'",
			fe_msg->getdata_req->ds_id,
			(int)fe_msg->getdata_req->n_data,
			(unsigned long long)fe_msg->getdata_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_getdata_req_msg(
			session, fe_msg->getdata_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_NOTIFY_DATA_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_REGNOTIFY_REQ:
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
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE__NOT_SET:
#if PROTOBUF_C_VERSION_NUMBER >= 1003000
	case _MGMTD__FE_MESSAGE__MESSAGE_IS_INT_SIZE:
#endif
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

static void mgmt_fe_adapter_process_msg(void *user_ctx, uint8_t *data,
					size_t len)
{
	struct mgmt_fe_client_adapter *adapter = user_ctx;
	Mgmtd__FeMessage *fe_msg;

	fe_msg = mgmtd__fe_message__unpack(NULL, len, data);
	if (!fe_msg) {
		MGMTD_FE_ADAPTER_DBG(
			"Failed to decode %zu bytes for adapter: %s", len,
			adapter->name);
		return;
	}
	MGMTD_FE_ADAPTER_DBG(
		"Decoded %zu bytes of message: %u from adapter: %s", len,
		fe_msg->message_case, adapter->name);
	(void)mgmt_fe_adapter_handle_msg(adapter, fe_msg);
	mgmtd__fe_message__free_unpacked(fe_msg, NULL);
}

static void mgmt_fe_adapter_proc_msgbufs(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter = THREAD_ARG(thread);

	if (mgmt_msg_procbufs(&adapter->mstate, mgmt_fe_adapter_process_msg,
			      adapter, mgmt_debug_fe))
		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_PROC_MSG);
}

static void mgmt_fe_adapter_read(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter = THREAD_ARG(thread);
	enum mgmt_msg_rsched rv;

	rv = mgmt_msg_read(&adapter->mstate, adapter->conn_fd, mgmt_debug_fe);
	if (rv == MSR_DISCONNECT) {
		mgmt_fe_adapter_disconnect(adapter);
		return;
	}
	if (rv == MSR_SCHED_BOTH)
		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_PROC_MSG);
	mgmt_fe_adapter_register_event(adapter, MGMTD_FE_CONN_READ);
}

static void mgmt_fe_adapter_write(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter = THREAD_ARG(thread);
	enum mgmt_msg_wsched rv;

	rv = mgmt_msg_write(&adapter->mstate, adapter->conn_fd, mgmt_debug_fe);
	if (rv == MSW_SCHED_STREAM)
		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_CONN_WRITE);
	else if (rv == MSW_DISCONNECT)
		mgmt_fe_adapter_disconnect(adapter);
	else if (rv == MSW_SCHED_WRITES_OFF) {
		mgmt_fe_adapter_writes_off(adapter);
		mgmt_fe_adapter_register_event(adapter,
					       MGMTD_FE_CONN_WRITES_ON);
	} else
		assert(rv == MSW_SCHED_NONE);
}

static void mgmt_fe_adapter_resume_writes(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter;

	adapter = (struct mgmt_fe_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd != -1);

	mgmt_fe_adapter_writes_on(adapter);
}

static void
mgmt_fe_adapter_register_event(struct mgmt_fe_client_adapter *adapter,
				 enum mgmt_fe_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_FE_CONN_READ:
		thread_add_read(mgmt_fe_adapter_tm, mgmt_fe_adapter_read,
				adapter, adapter->conn_fd, &adapter->conn_read_ev);
		assert(adapter->conn_read_ev);
		break;
	case MGMTD_FE_CONN_WRITE:
		thread_add_write(mgmt_fe_adapter_tm,
				 mgmt_fe_adapter_write, adapter,
				 adapter->conn_fd, &adapter->conn_write_ev);
		assert(adapter->conn_write_ev);
		break;
	case MGMTD_FE_PROC_MSG:
		tv.tv_usec = MGMTD_FE_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(mgmt_fe_adapter_tm,
				    mgmt_fe_adapter_proc_msgbufs, adapter,
				    &tv, &adapter->proc_msg_ev);
		assert(adapter->proc_msg_ev);
		break;
	case MGMTD_FE_CONN_WRITES_ON:
		thread_add_timer_msec(mgmt_fe_adapter_tm,
				      mgmt_fe_adapter_resume_writes, adapter,
				      MGMTD_FE_MSG_WRITE_DELAY_MSEC,
				      &adapter->conn_writes_on);
		assert(adapter->conn_writes_on);
		break;
	case MGMTD_FE_SERVER:
		assert(!"mgmt_fe_adapter_post_event() called incorrectly");
		break;
	}
}

void mgmt_fe_adapter_lock(struct mgmt_fe_client_adapter *adapter)
{
	adapter->refcount++;
}

extern void
mgmt_fe_adapter_unlock(struct mgmt_fe_client_adapter **adapter)
{
	assert(*adapter && (*adapter)->refcount);

	(*adapter)->refcount--;
	if (!(*adapter)->refcount) {
		mgmt_fe_adapters_del(&mgmt_fe_adapters, *adapter);
		THREAD_OFF((*adapter)->conn_read_ev);
		THREAD_OFF((*adapter)->conn_write_ev);
		THREAD_OFF((*adapter)->proc_msg_ev);
		THREAD_OFF((*adapter)->conn_writes_on);
		mgmt_msg_destroy(&(*adapter)->mstate);
		XFREE(MTYPE_MGMTD_FE_ADPATER, *adapter);
	}

	*adapter = NULL;
}

int mgmt_fe_adapter_init(struct thread_master *tm, struct mgmt_master *mm)
{
	if (!mgmt_fe_adapter_tm) {
		mgmt_fe_adapter_tm = tm;
		mgmt_fe_adapter_mm = mm;
		mgmt_fe_adapters_init(&mgmt_fe_adapters);

		assert(!mgmt_fe_sessions);
		mgmt_fe_sessions = hash_create(mgmt_fe_session_hash_key,
					       mgmt_fe_session_hash_cmp,
					       "MGMT Frontend Sessions");
	}

	return 0;
}

void mgmt_fe_adapter_destroy(void)
{
	mgmt_fe_cleanup_adapters();
	mgmt_fe_session_hash_destroy();
}

struct mgmt_fe_client_adapter *
mgmt_fe_create_adapter(int conn_fd, union sockunion *from)
{
	struct mgmt_fe_client_adapter *adapter = NULL;

	adapter = mgmt_fe_find_adapter_by_fd(conn_fd);
	if (!adapter) {
		adapter = XCALLOC(MTYPE_MGMTD_FE_ADPATER,
				sizeof(struct mgmt_fe_client_adapter));
		assert(adapter);

		adapter->conn_fd = conn_fd;
		memcpy(&adapter->conn_su, from, sizeof(adapter->conn_su));
		snprintf(adapter->name, sizeof(adapter->name), "Unknown-FD-%d",
			 adapter->conn_fd);
		mgmt_fe_sessions_init(&adapter->fe_sessions);

		mgmt_msg_init(&adapter->mstate, MGMTD_FE_MAX_NUM_MSG_PROC,
			      MGMTD_FE_MAX_NUM_MSG_WRITE, MGMTD_FE_MSG_MAX_LEN,
			      "FE-adapter");
		mgmt_fe_adapter_lock(adapter);

		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_CONN_READ);
		mgmt_fe_adapters_add_tail(&mgmt_fe_adapters, adapter);

		adapter->setcfg_stats.min_tm = ULONG_MAX;
		adapter->cmt_stats.min_tm = ULONG_MAX;
		MGMTD_FE_ADAPTER_DBG("Added new MGMTD Frontend adapter '%s'",
				       adapter->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adapter->conn_fd);
	setsockopt_so_sendbuf(adapter->conn_fd,
			      MGMTD_SOCKET_FE_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(adapter->conn_fd,
			      MGMTD_SOCKET_FE_RECV_BUF_SIZE);
	return adapter;
}

struct mgmt_fe_client_adapter *mgmt_fe_get_adapter(const char *name)
{
	return mgmt_fe_find_adapter_by_name(name);
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
			MGMTD_FE_ADAPTER_ERR(
				"Txn_id doesnot match, session txn is 0x%llx, current txn 0x%llx",
				(unsigned long long)session->cfg_txn_id,
				(unsigned long long)txn_id);
		return -1;
	}

	return mgmt_fe_send_setcfg_reply(
		session, ds_id, req_id, result == MGMTD_SUCCESS ? true : false,
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

	return mgmt_fe_send_commitcfg_reply(session, src_ds_id, dst_ds_id,
						req_id, result, validate_only,
						error_if_any);
}

int mgmt_fe_send_get_cfg_reply(uint64_t session_id, uint64_t txn_id,
				   Mgmtd__DatastoreId ds_id, uint64_t req_id,
				   enum mgmt_result result,
				   Mgmtd__YangDataReply *data_resp,
				   const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	return mgmt_fe_send_getcfg_reply(session, ds_id, req_id,
					     result == MGMTD_SUCCESS, data_resp,
					     error_if_any);
}

int mgmt_fe_send_get_data_reply(uint64_t session_id, uint64_t txn_id,
				    Mgmtd__DatastoreId ds_id, uint64_t req_id,
				    enum mgmt_result result,
				    Mgmtd__YangDataReply *data_resp,
				    const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	return mgmt_fe_send_getdata_reply(session, ds_id, req_id,
					      result == MGMTD_SUCCESS,
					      data_resp, error_if_any);
}

int mgmt_fe_send_data_notify(Mgmtd__DatastoreId ds_id,
				 Mgmtd__YangData * data_resp[], int num_data)
{
	/* struct mgmt_fe_session_ctx *session; */

	return 0;
}

struct mgmt_setcfg_stats *
mgmt_fe_get_session_setcfg_stats(uint64_t session_id)
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
	char buf[100] = {0};

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
			vty_out(vty,
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
				"        Send-Config Start: \t\t%s\n",
#else
				"        Send-Config-Validate Start: \t%s\n",
#endif
				mgmt_realtime_to_string(
					&adapter->cmt_stats.send_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Apply-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.apply_cfg_start, buf,
					sizeof(buf)));
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
	char buf[100] = {0};

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
			mgmt_realtime_to_string(&adapter->setcfg_stats.last_start,
						buf, sizeof(buf)));
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
		vty_out(vty, "    Conn-FD: \t\t\t\t%d\n", adapter->conn_fd);
		if (detail) {
			mgmt_fe_adapter_setcfg_stats_write(vty, adapter);
			mgmt_fe_adapter_cmt_stats_write(vty, adapter);
		}
		vty_out(vty, "    Sessions\n");
		FOREACH_SESSION_IN_LIST (adapter, session) {
			vty_out(vty, "      Session: \t\t\t\t%p\n", session);
			vty_out(vty, "        Client-Id: \t\t\t%llu\n",
				(unsigned long long)session->client_id);
			vty_out(vty, "        Session-Id: \t\t\t%llx\n",
				(unsigned long long)session->session_id);
			vty_out(vty, "        DS-Locks:\n");
			FOREACH_MGMTD_DS_ID (ds_id) {
				if (session->ds_write_locked[ds_id]
				    || session->ds_read_locked[ds_id]) {
					locked = true;
					vty_out(vty,
						"          %s\t\t\t%s, %s\n",
						mgmt_ds_id2name(ds_id),
						session->ds_write_locked[ds_id]
							? "Write"
							: "Read",
						session->ds_locked_implict[ds_id]
							? "Implicit"
							: "Explicit");
				}
			}
			if (!locked)
				vty_out(vty, "          None\n");
		}
		vty_out(vty, "    Total-Sessions: \t\t\t%d\n",
			(int)mgmt_fe_sessions_count(&adapter->fe_sessions));
		vty_out(vty, "    Msg-Recvd: \t\t\t\t%" PRIu64 "\n",
			adapter->mstate.nrxm);
		vty_out(vty, "    Bytes-Recvd: \t\t\t%" PRIu64 "\n",
			adapter->mstate.nrxb);
		vty_out(vty, "    Msg-Sent: \t\t\t\t%" PRIu64 "\n",
			adapter->mstate.ntxm);
		vty_out(vty, "    Bytes-Sent: \t\t\t%" PRIu64 "\n",
			adapter->mstate.ntxb);
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
		memset(&adapter->setcfg_stats, 0, sizeof(adapter->setcfg_stats));
		FOREACH_SESSION_IN_LIST (adapter, session) {
			memset(&adapter->cmt_stats, 0, sizeof(adapter->cmt_stats));
		}
	}
}
