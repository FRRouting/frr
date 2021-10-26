/*
 * MGMTD Frontend Client Connection Adapter
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
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_fe_client.h"
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
	do {                                                                   \
		if (mgmt_debug_fe)                                         \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_FE_ADAPTER_ERR(fmt, ...)                                       \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADAPTER_IN_LIST(adapter)                                           \
	frr_each_safe(mgmt_fe_adapter_list, &mgmt_fe_adapters, (adapter))

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
	uint8_t db_write_locked[MGMTD_DB_MAX_ID];
	uint8_t db_read_locked[MGMTD_DB_MAX_ID];
	uint8_t db_locked_implict[MGMTD_DB_MAX_ID];
	struct thread *proc_cfg_txn_clnp;
	struct thread *proc_show_txn_clnp;

	struct mgmt_fe_session_list_item list_linkage;
};

DECLARE_LIST(mgmt_fe_session_list, struct mgmt_fe_session_ctx,
	     list_linkage);

#define FOREACH_SESSION_IN_LIST(adapter, session)                               \
	frr_each_safe(mgmt_fe_session_list, &(adapter)->fe_sessions, (session))

static struct thread_master *mgmt_fe_adapter_tm;
static struct mgmt_master *mgmt_fe_adapter_mm;

static struct mgmt_fe_adapter_list_head mgmt_fe_adapters;

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
mgmt_fe_session_write_lock_db(Mgmtd__DatabaseId db_id,
				  struct mgmt_db_ctx *db_ctx,
				  struct mgmt_fe_session_ctx *session)
{
	if (!session->db_write_locked[db_id]) {
		if (mgmt_db_write_lock(db_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, session, session->adapter->name);
			return -1;
		}

		session->db_write_locked[db_id] = true;
		MGMTD_FE_ADAPTER_DBG(
			"Write-Locked the DB %u for Sessn: %p from %s!", db_id,
			session, session->adapter->name);
	}

	return 0;
}

static int
mgmt_fe_session_read_lock_db(Mgmtd__DatabaseId db_id,
				 struct mgmt_db_ctx *db_ctx,
				 struct mgmt_fe_session_ctx *session)
{
	if (!session->db_read_locked[db_id]) {
		if (mgmt_db_read_lock(db_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, session, session->adapter->name);
			return -1;
		}

		session->db_read_locked[db_id] = true;
		MGMTD_FE_ADAPTER_DBG(
			"Read-Locked the DB %u for Sessn: %p from %s!", db_id,
			session, session->adapter->name);
	}

	return 0;
}

static int mgmt_fe_session_unlock_db(Mgmtd__DatabaseId db_id,
					 struct mgmt_db_ctx *db_ctx,
					 struct mgmt_fe_session_ctx *session,
					 bool unlock_write, bool unlock_read)
{
	if (unlock_write && session->db_write_locked[db_id]) {
		session->db_write_locked[db_id] = false;
		session->db_locked_implict[db_id] = false;
		if (mgmt_db_unlock(db_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, session, session->adapter->name);
			return -1;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Unlocked DB %u write-locked earlier by Sessn: %p from %s",
			db_id, session, session->adapter->name);
	} else if (unlock_read && session->db_read_locked[db_id]) {
		session->db_read_locked[db_id] = false;
		session->db_locked_implict[db_id] = false;
		if (mgmt_db_unlock(db_ctx) != 0) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, session, session->adapter->name);
			return -1;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Unlocked DB %u read-locked earlier by Sessn: %p from %s",
			db_id, session, session->adapter->name);
	}

	return 0;
}

static void
mgmt_fe_session_cfg_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctx *db_ctx;

	/*
	 * Ensure any uncommitted changes in Candidate DB
	 * is discarded.
	 */
	mgmt_db_copy_dbs(mm->running_db, mm->candidate_db, false);

	for (db_id = 0; db_id < MGMTD_DB_MAX_ID; db_id++) {
		db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm, db_id);
		if (db_ctx) {
			if (session->db_locked_implict[db_id])
				mgmt_fe_session_unlock_db(
					db_id, db_ctx, session, true, false);
		}
	}

	/* TODO: Destroy the actual transaction created earlier.
	 * if (session->cfg_txn_id != MGMTD_TXN_ID_NONE)
	 *	mgmt_destroy_txn(&session->cfg_txn_id);
	 */
}

static void
mgmt_fe_session_show_txn_cleanup(struct mgmt_fe_session_ctx *session)
{
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctx *db_ctx;

	for (db_id = 0; db_id < MGMTD_DB_MAX_ID; db_id++) {
		db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm, db_id);
		if (db_ctx) {
			mgmt_fe_session_unlock_db(db_id, db_ctx, session,
						      false, true);
		}
	}

	/* TODO: Destroy the transaction created recently.
	 * if (session->txn_id != MGMTD_TXN_ID_NONE)
	 *	mgmt_destroy_txn(&session->txn_id);
	 */
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
		mgmt_fe_session_unlock_db(
			MGMTD_DB_CANDIDATE, mgmt_fe_adapter_mm->candidate_db,
			*session, true, true);
		mgmt_fe_session_unlock_db(MGMTD_DB_RUNNING,
					      mgmt_fe_adapter_mm->running_db,
					      *session, true, true);

		mgmt_fe_session_list_del(&(*session)->adapter->fe_sessions,
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
	mgmt_fe_session_list_add_tail(&adapter->fe_sessions, session);
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
	if (adapter->obuf_work || stream_fifo_count_safe(adapter->obuf_fifo))
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
	size_t msg_size;
	uint8_t msg_buf[MGMTD_FE_MSG_MAX_LEN];
	struct mgmt_fe_msg *msg;

	if (adapter->conn_fd == 0) {
		MGMTD_FE_ADAPTER_ERR("Connection already reset");
		return -1;
	}

	msg_size = mgmtd__fe_message__get_packed_size(fe_msg);
	msg_size += MGMTD_FE_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		MGMTD_FE_ADAPTER_ERR(
			"Message size %d more than max size'%d. Not sending!'",
			(int)msg_size, (int)sizeof(msg_buf));
		return -1;
	}

	msg = (struct mgmt_fe_msg *)msg_buf;
	msg->hdr.marker = MGMTD_FE_MSG_MARKER;
	msg->hdr.len = (uint16_t)msg_size;
	mgmtd__fe_message__pack(fe_msg, msg->payload);

	if (!adapter->obuf_work)
		adapter->obuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(adapter->obuf_work) < msg_size) {
		stream_fifo_push(adapter->obuf_fifo, adapter->obuf_work);
		adapter->obuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	}
	stream_write(adapter->obuf_work, (void *)msg_buf, msg_size);

	mgmt_fe_adapter_sched_msg_write(adapter);
	adapter->num_msg_tx++;
	return 0;
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

static int mgmt_fe_send_lockdb_reply(struct mgmt_fe_session_ctx *session,
					 Mgmtd__DatabaseId db_id,
					 uint64_t req_id, bool lock_db,
					 bool success, const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeLockDbReply lockdb_reply;

	assert(session->adapter);

	mgmtd__fe_lock_db_reply__init(&lockdb_reply);
	lockdb_reply.session_id = session->session_id;
	lockdb_reply.db_id = db_id;
	lockdb_reply.req_id = req_id;
	lockdb_reply.lock = lock_db;
	lockdb_reply.success = success;
	if (error_if_any)
		lockdb_reply.error_if_any = (char *)error_if_any;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_LOCKDB_REPLY;
	fe_msg.lockdb_reply = &lockdb_reply;

	MGMTD_FE_ADAPTER_DBG(
		"Sending LOCK_DB_REPLY message to MGMTD Frontend client '%s'",
		session->adapter->name);

	return mgmt_fe_adapter_send_msg(session->adapter, &fe_msg);
}

static int mgmt_fe_send_setcfg_reply(struct mgmt_fe_session_ctx *session,
					 Mgmtd__DatabaseId db_id,
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
	setcfg_reply.db_id = db_id;
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
	struct mgmt_fe_session_ctx *session, Mgmtd__DatabaseId src_db_id,
	Mgmtd__DatabaseId dst_db_id, uint64_t req_id, enum mgmt_result result,
	bool validate_only, const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeCommitConfigReply commcfg_reply;

	assert(session->adapter);

	mgmtd__fe_commit_config_reply__init(&commcfg_reply);
	commcfg_reply.session_id = session->session_id;
	commcfg_reply.src_db_id = src_db_id;
	commcfg_reply.dst_db_id = dst_db_id;
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
					 Mgmtd__DatabaseId db_id,
					 uint64_t req_id, bool success,
					 Mgmtd__YangDataReply *data,
					 const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetConfigReply getcfg_reply;

	assert(session->adapter);

	mgmtd__fe_get_config_reply__init(&getcfg_reply);
	getcfg_reply.session_id = session->session_id;
	getcfg_reply.db_id = db_id;
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
					  Mgmtd__DatabaseId db_id,
					  uint64_t req_id, bool success,
					  Mgmtd__YangDataReply *data,
					  const char *error_if_any)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetDataReply getdata_reply;

	assert(session->adapter);

	mgmtd__fe_get_data_reply__init(&getdata_reply);
	getdata_reply.session_id = session->session_id;
	getdata_reply.db_id = db_id;
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
	default:
		assert(!"mgmt_fe_adapter_post_event() called incorrectly");
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

static void
mgmt_fe_adapter_disconnect(struct mgmt_fe_client_adapter *adapter)
{
	if (adapter->conn_fd) {
		close(adapter->conn_fd);
		adapter->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	mgmt_fe_cleanup_sessions(adapter);
	mgmt_fe_session_list_fini(&adapter->fe_sessions);
	mgmt_fe_adapter_list_del(&mgmt_fe_adapters, adapter);

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
mgmt_fe_session_handle_lockdb_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeLockDbReq *lockdb_req)
{
	struct mgmt_db_ctx *db_ctx;

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (lockdb_req->db_id != MGMTD_DB_CANDIDATE) {
		mgmt_fe_send_lockdb_reply(
			session, lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Lock/Unlock on databases other than Candidate DB not permitted!");
		return -1;
	}

	db_ctx =
		mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm, lockdb_req->db_id);
	if (!db_ctx) {
		mgmt_fe_send_lockdb_reply(
			session, lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Failed to retrieve handle for DB!");
		return -1;
	}

	if (lockdb_req->lock) {
		if (mgmt_fe_session_write_lock_db(lockdb_req->db_id,
						      db_ctx, session)
		    != 0) {
			mgmt_fe_send_lockdb_reply(
				session, lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock already taken on DB by another session!");
			return -1;
		}

		session->db_locked_implict[lockdb_req->db_id] = false;
	} else {
		if (!session->db_write_locked[lockdb_req->db_id]) {
			mgmt_fe_send_lockdb_reply(
				session, lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock on DB was not taken by this session!");
			return 0;
		}

		(void)mgmt_fe_session_unlock_db(lockdb_req->db_id, db_ctx,
						    session, true, false);
	}

	if (mgmt_fe_send_lockdb_reply(session, lockdb_req->db_id,
					   lockdb_req->req_id, lockdb_req->lock,
					   true, NULL)
	    != 0) {
		MGMTD_FE_ADAPTER_DBG(
			"Failed to send LOCK_DB_REPLY for DB %u Sessn: %p from %s",
			lockdb_req->db_id, session, session->adapter->name);
	}

	return 0;
}

static int
mgmt_fe_session_handle_setcfg_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeSetConfigReq *setcfg_req)
{
	/* uint64_t cfg_session_id; */
	struct mgmt_db_ctx *db_ctx, *dst_db_ctx;

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->setcfg_stats.last_start, NULL);

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (setcfg_req->db_id != MGMTD_DB_CANDIDATE) {
		mgmt_fe_send_setcfg_reply(
			session, setcfg_req->db_id, setcfg_req->req_id, false,
			"Set-Config on databases other than Candidate DB not permitted!",
			setcfg_req->implicit_commit);
		return 0;
	}

	/*
	 * Get the DB handle.
	 */
	db_ctx =
		mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm, setcfg_req->db_id);
	if (!db_ctx) {
		mgmt_fe_send_setcfg_reply(
			session, setcfg_req->db_id, setcfg_req->req_id, false,
			"No such DB exists!", setcfg_req->implicit_commit);
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * TODO: Check first if the current session can run a CONFIG
		 * transaction or not. Report failure if a CONFIG transaction
		 * from another session is already in progress.
		 * cfg_session_id = mgmt_config_txn_in_progress();
		 * if (cfg_session_id != MGMTD_SESSION_ID_NONE
		 *   && cfg_session_id != session->session_id) {
		 *	mgmt_fe_send_setcfg_reply(
		 *		session, setcfg_req->db_id, setcfg_req->req_id,
		 *		false,
		 *		"Configuration already in-progress through a
		 *different user session!", setcfg_req->implicit_commit); goto
		 *mgmt_fe_sess_handle_setcfg_req_failed;
		 *}
		 */


		/*
		 * Try taking write-lock on the requested DB (if not already).
		 */
		if (!session->db_write_locked[setcfg_req->db_id]) {
			if (mgmt_fe_session_write_lock_db(setcfg_req->db_id,
							      db_ctx, session)
			    != 0) {
				mgmt_fe_send_setcfg_reply(
					session, setcfg_req->db_id,
					setcfg_req->req_id, false,
					"Failed to lock the DB!",
					setcfg_req->implicit_commit);
				goto mgmt_fe_sess_handle_setcfg_req_failed;
			}

			session->db_locked_implict[setcfg_req->db_id] = true;
		}

		/*
		 * TODO: Start a CONFIG Transaction (if not started already)
		 * session->cfg_txn_id = mgmt_create_txn(session->session_id,
		 *				      MGMTD_TXN_TYPE_CONFIG);
		 * if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_fe_send_setcfg_reply(
		 *		session, setcfg_req->db_id, setcfg_req->req_id,
		 *		false,
		 *		"Failed to create a Configuration session!",
		 *		setcfg_req->implicit_commit);
		 *	goto mgmt_fe_sess_handle_setcfg_req_failed;
		 * }
		 */

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
				session, setcfg_req->db_id, setcfg_req->req_id,
				false,
				"A Configuration transaction is already in progress!",
				false);
			return 0;
		}
	}

	dst_db_ctx = 0;
	if (setcfg_req->implicit_commit) {
		dst_db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm,
						     setcfg_req->commit_db_id);
		if (!dst_db_ctx) {
			mgmt_fe_send_setcfg_reply(
				session, setcfg_req->db_id, setcfg_req->req_id,
				false, "No such commit DB exists!",
				setcfg_req->implicit_commit);
			return 0;
		}
	}

	/* TODO: Create the SETConfig request under the transaction.
	 * if (mgmt_txn_send_set_config_req(
	 *	session->cfg_txn_id, setcfg_req->req_id, setcfg_req->db_id,
	 *	db_ctx, setcfg_req->data, setcfg_req->n_data,
	 *	setcfg_req->implicit_commit, setcfg_req->commit_db_id,
	 *	dst_db_ctx)
	 *	!= 0) {
	 *	mgmt_fe_send_setcfg_reply(
	 *		session, setcfg_req->db_id, setcfg_req->req_id, false,
	 *		"Request processing for SET-CONFIG failed!",
	 *		setcfg_req->implicit_commit);
	 *	goto mgmt_fe_sess_handle_setcfg_req_failed;
	 * }
	 *
	 * For now send a failure reply.
	 */
	mgmt_fe_send_setcfg_reply(
		session, setcfg_req->db_id, setcfg_req->req_id, false,
		"Request processing for SET-CONFIG failed!",
		setcfg_req->implicit_commit);
	goto mgmt_fe_sess_handle_setcfg_req_failed;

	return 0;

mgmt_fe_sess_handle_setcfg_req_failed:

	/* TODO: Delete transaction created recently.
	 * if (session->cfg_txn_id != MGMTD_TXN_ID_NONE)
	 *	mgmt_destroy_txn(&session->cfg_txn_id);
	 */
	if (db_ctx && session->db_write_locked[setcfg_req->db_id])
		mgmt_fe_session_unlock_db(setcfg_req->db_id, db_ctx, session,
					      true, false);

	return 0;
}

static int
mgmt_fe_session_handle_getcfg_req_msg(struct mgmt_fe_session_ctx *session,
					  Mgmtd__FeGetConfigReq *getcfg_req)
{
	struct mgmt_db_ctx *db_ctx;

	/*
	 * Get the DB handle.
	 */
	db_ctx =
		mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm, getcfg_req->db_id);
	if (!db_ctx) {
		mgmt_fe_send_getcfg_reply(session, getcfg_req->db_id,
					      getcfg_req->req_id, false, NULL,
					      "No such DB exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (getcfg_req->db_id != MGMTD_DB_CANDIDATE
	    && getcfg_req->db_id != MGMTD_DB_RUNNING) {
		mgmt_fe_send_getcfg_reply(
			session, getcfg_req->db_id, getcfg_req->req_id, false,
			NULL,
			"Get-Config on databases other than Candidate or Running DB not permitted!");
		return 0;
	}

	if (session->txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DB (if not already
		 * locked). If the DB has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DB.
		 */
		if (!session->db_read_locked[getcfg_req->db_id]
		    && !session->db_write_locked[getcfg_req->db_id]) {
			if (mgmt_fe_session_read_lock_db(getcfg_req->db_id,
							     db_ctx, session)
			    != 0) {
				mgmt_fe_send_getcfg_reply(
					session, getcfg_req->db_id,
					getcfg_req->req_id, false, NULL,
					"Failed to lock the DB! Another session might have locked it!");
				goto mgmt_fe_sess_handle_getcfg_req_failed;
			}

			session->db_locked_implict[getcfg_req->db_id] = true;
		}

		/*
		 * TODO: Start a SHOW Transaction (if not started already)
		 * session->txn_id = mgmt_create_txn(session->session_id,
		 *				MGMTD_TXN_TYPE_SHOW);
		 * if (session->txn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_fe_send_getcfg_reply(
		 *		session, getcfg_req->db_id, getcfg_req->req_id,
		 *		false, NULL,
		 *		"Failed to create a Show transaction!");
		 *	goto mgmt_fe_sess_handle_getcfg_req_failed;
		 * }
		 */
		mgmt_fe_send_getcfg_reply(
			session, getcfg_req->db_id, getcfg_req->req_id, false,
			NULL, "Failed to create a Show transaction!");
		goto mgmt_fe_sess_handle_getcfg_req_failed;


		MGMTD_FE_ADAPTER_DBG(
			"Created new Show Txn 0x%llx for session %p",
			(unsigned long long)session->txn_id, session);
	} else {
		MGMTD_FE_ADAPTER_DBG(
			"Show Txn 0x%llx for session %p already created",
			(unsigned long long)session->txn_id, session);
	}

	/* TODO: Create a GETConfig request under the transaction.
	 * if (mgmt_txn_send_get_config_req(session->txn_id, getcfg_req->req_id,
	 *				getcfg_req->db_id, db_ctx,
	 *				getcfg_req->data, getcfg_req->n_data)
	 *	!= 0) {
	 *	mgmt_fe_send_getcfg_reply(
	 *		session, getcfg_req->db_id, getcfg_req->req_id, false,
	 *		NULL, "Request processing for GET-CONFIG failed!");
	 *	goto mgmt_fe_sess_handle_getcfg_req_failed;
	 * }
	 *
	 * For now send back a failure reply.
	 */
	mgmt_fe_send_getcfg_reply(
		session, getcfg_req->db_id, getcfg_req->req_id, false, NULL,
		"Request processing for GET-CONFIG failed!");
	goto mgmt_fe_sess_handle_getcfg_req_failed;

	return 0;

mgmt_fe_sess_handle_getcfg_req_failed:

	/* TODO: Destroy the transaction created recently.
	 * if (session->txn_id != MGMTD_TXN_ID_NONE)
	 *	mgmt_destroy_txn(&session->txn_id);
	 */
	if (db_ctx && session->db_read_locked[getcfg_req->db_id])
		mgmt_fe_session_unlock_db(getcfg_req->db_id, db_ctx, session,
					      false, true);

	return -1;
}

static int
mgmt_fe_session_handle_getdata_req_msg(struct mgmt_fe_session_ctx *session,
					   Mgmtd__FeGetDataReq *getdata_req)
{
	struct mgmt_db_ctx *db_ctx;

	/*
	 * Get the DB handle.
	 */
	db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm,
					 getdata_req->db_id);
	if (!db_ctx) {
		mgmt_fe_send_getdata_reply(session, getdata_req->db_id,
					       getdata_req->req_id, false, NULL,
					       "No such DB exists!");
		return 0;
	}

	if (session->txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DB (if not already
		 * locked). If the DB has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DB.
		 */
		if (!session->db_read_locked[getdata_req->db_id]
		    && !session->db_write_locked[getdata_req->db_id]) {
			if (mgmt_fe_session_read_lock_db(getdata_req->db_id,
							     db_ctx, session)
			    != 0) {
				mgmt_fe_send_getdata_reply(
					session, getdata_req->db_id,
					getdata_req->req_id, false, NULL,
					"Failed to lock the DB! Another session might have locked it!");
				goto mgmt_fe_sess_handle_getdata_req_failed;
			}

			session->db_locked_implict[getdata_req->db_id] = true;
		}

		/*
		 * TODO: Start a SHOW Transaction (if not started already)
		 * session->txn_id =
		 *	mgmt_create_txn(session->session_id,
		 *			MGMTD_TXN_TYPE_SHOW);
		 * if (session->txn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_fe_send_getdata_reply(
		 *		session, getdata_req->db_id, getdata_req->req_id,
		 *		false, NULL,
		 *		"Failed to create a Show transaction!");
		 *	goto mgmt_fe_sess_handle_getdata_req_failed;
		 * }
		 */
		mgmt_fe_send_getdata_reply(
			session, getdata_req->db_id, getdata_req->req_id, false,
			NULL, "Failed to create a Show transaction!");
		goto mgmt_fe_sess_handle_getdata_req_failed;


		MGMTD_FE_ADAPTER_DBG(
			"Created new Show Txn 0x%llx for session %p",
			(unsigned long long)session->txn_id, session);
	} else {
		MGMTD_FE_ADAPTER_DBG(
			"Show Txn 0x%llx for session %p already created",
			(unsigned long long)session->txn_id, session);
	}

	/* TODO: Create a GETData request under the transaction.
	 * if (mgmt_txn_send_get_data_req(session->txn_id, getdata_req->req_id,
	 *				getdata_req->db_id, db_ctx,
	 *				getdata_req->data, getdata_req->n_data)
	 *	!= 0) {
	 *	mgmt_fe_send_getdata_reply(
	 *		session, getdata_req->db_id, getdata_req->req_id, false,
	 *		NULL, "Request processing for GET-CONFIG failed!");
	 *	goto mgmt_fe_sess_handle_getdata_req_failed;
	 * }
	 *
	 * For now send back a failure reply.
	 */
	mgmt_fe_send_getdata_reply(
		session, getdata_req->db_id, getdata_req->req_id, false, NULL,
		"Request processing for GET-CONFIG failed!");
	goto mgmt_fe_sess_handle_getdata_req_failed;

	return 0;

mgmt_fe_sess_handle_getdata_req_failed:

	/* TODO: Destroy the transaction created recently.
	 * if (session->txn_id != MGMTD_TXN_ID_NONE)
	 *	mgmt_destroy_txn(&session->txn_id);
	 */

	if (db_ctx && session->db_read_locked[getdata_req->db_id])
		mgmt_fe_session_unlock_db(getdata_req->db_id, db_ctx,
					      session, false, true);

	return -1;
}

static int mgmt_fe_session_handle_commit_config_req_msg(
	struct mgmt_fe_session_ctx *session,
	Mgmtd__FeCommitConfigReq *commcfg_req)
{
	struct mgmt_db_ctx *src_db_ctx, *dst_db_ctx;

	if (mm->perf_stats_en)
		gettimeofday(&session->adapter->cmt_stats.last_start, NULL);
	session->adapter->cmt_stats.commit_cnt++;
	/*
	 * Get the source DB handle.
	 */
	src_db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm,
					     commcfg_req->src_db_id);
	if (!src_db_ctx) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"No such source DB exists!");
		return 0;
	}

	/*
	 * Get the destination DB handle.
	 */
	dst_db_ctx = mgmt_db_get_ctx_by_id(mgmt_fe_adapter_mm,
					     commcfg_req->dst_db_id);
	if (!dst_db_ctx) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"No such destination DB exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (commcfg_req->dst_db_id != MGMTD_DB_RUNNING) {
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Set-Config on databases other than Running DB not permitted!");
		return 0;
	}

	if (session->cfg_txn_id == MGMTD_TXN_ID_NONE) {
		/*
		 * TODO: Start a CONFIG Transaction (if not started already)
		 * session->cfg_txn_id = mgmt_create_txn(session->session_id,
		 *				MGMTD_TXN_TYPE_CONFIG);
		 * if (session->cfg_txn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_fe_send_commitcfg_reply(
		 *		session, commcfg_req->src_db_id,
		 *		commcfg_req->dst_db_id, commcfg_req->req_id,
		 *		MGMTD_INTERNAL_ERROR,
		 *		commcfg_req->validate_only,
		 *		"Failed to create a Configuration session!");
		 *	return 0;
		 * }
		 */
		mgmt_fe_send_commitcfg_reply(
			session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Failed to create a Configuration session!");
		return 0;
	}


	/*
	 * Try taking write-lock on the destination DB (if not already).
	 */
	if (!session->db_write_locked[commcfg_req->dst_db_id]) {
		if (mgmt_fe_session_write_lock_db(commcfg_req->dst_db_id,
						      dst_db_ctx, session)
		    != 0) {
			mgmt_fe_send_commitcfg_reply(
				session, commcfg_req->src_db_id,
				commcfg_req->dst_db_id, commcfg_req->req_id,
				MGMTD_DB_LOCK_FAILED,
				commcfg_req->validate_only,
				"Failed to lock the destination DB!");
			return 0;
		}

		session->db_locked_implict[commcfg_req->dst_db_id] = true;
	}

	/* TODO: Create COMMITConfig request under the transaction
	 * if (mgmt_txn_send_commit_config_req(
	 *	session->cfg_txn_id, commcfg_req->req_id,
	 *	commcfg_req->src_db_id, src_db_ctx, commcfg_req->dst_db_id,
	 *	dst_db_ctx, commcfg_req->validate_only, commcfg_req->abort,
	 *	false)
	 *	!= 0) {
	 *	mgmt_fe_send_commitcfg_reply(
	 *		session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
	 *		commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
	 *		commcfg_req->validate_only,
	 *		"Request processing for COMMIT-CONFIG failed!");
	 *	return 0;
	 * }
	 *
	 * For now due to lack of txn modules send a unsuccessfull reply.
	 */
	mgmt_fe_send_commitcfg_reply(
		session, commcfg_req->src_db_id, commcfg_req->dst_db_id,
		commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
		commcfg_req->validate_only,
		"Request processing for COMMIT-CONFIG failed!");

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
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDB_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->lockdb_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got %sockDB Req Msg for DB:%d for session-id %llx from '%s'",
			fe_msg->lockdb_req->lock ? "L" : "Unl",
			fe_msg->lockdb_req->db_id,
			(unsigned long long)fe_msg->lockdb_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_lockdb_req_msg(
			session, fe_msg->lockdb_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->setcfg_req->session_id);
		session->adapter->setcfg_stats.set_cfg_count++;
		MGMTD_FE_ADAPTER_DBG(
			"Got Set Config Req Msg (%d Xpaths) on DB:%d for session-id %llu from '%s'",
			(int)fe_msg->setcfg_req->n_data,
			fe_msg->setcfg_req->db_id,
			(unsigned long long)fe_msg->setcfg_req->session_id,
			adapter->name);

		mgmt_fe_session_handle_setcfg_req_msg(
			session, fe_msg->setcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->commcfg_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got Commit Config Req Msg for src-DB:%d dst-DB:%d on session-id %llu from '%s'",
			fe_msg->commcfg_req->src_db_id,
			fe_msg->commcfg_req->dst_db_id,
			(unsigned long long)fe_msg->commcfg_req->session_id,
			adapter->name);
		mgmt_fe_session_handle_commit_config_req_msg(
			session, fe_msg->commcfg_req);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REQ:
		session = mgmt_session_id2ctx(
				fe_msg->getcfg_req->session_id);
		MGMTD_FE_ADAPTER_DBG(
			"Got Get-Config Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'",
			fe_msg->getcfg_req->db_id,
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
			"Got Get-Data Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'",
			fe_msg->getdata_req->db_id,
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
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDB_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REPLY:
	case MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REPLY:
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

static uint16_t
mgmt_fe_adapter_process_msg(struct mgmt_fe_client_adapter *adapter,
				uint8_t *msg_buf, uint16_t bytes_read)
{
	Mgmtd__FeMessage *fe_msg;
	struct mgmt_fe_msg *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	MGMTD_FE_ADAPTER_DBG(
		"Have %u bytes of messages from client '%s' to process",
		bytes_read, adapter->name);

	bytes_left = bytes_read;
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;
	     bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (struct mgmt_fe_msg *)msg_buf;
		if (msg->hdr.marker != MGMTD_FE_MSG_MARKER) {
			MGMTD_FE_ADAPTER_DBG(
				"Marker not found in message from MGMTD Frontend adapter '%s'",
				adapter->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_FE_ADAPTER_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD Frontend adapter '%s'",
				bytes_left, msg->hdr.len, adapter->name);
			break;
		}

		fe_msg = mgmtd__fe_message__unpack(
			NULL, (size_t)(msg->hdr.len - MGMTD_FE_MSG_HDR_LEN),
			msg->payload);
		if (!fe_msg) {
			MGMTD_FE_ADAPTER_DBG(
				"Failed to decode %d bytes from MGMTD Frontend adapter '%s'",
				msg->hdr.len, adapter->name);
			continue;
		}

		MGMTD_FE_ADAPTER_DBG(
			"Decoded %d bytes of message(msg: %u/%u) from MGMTD Frontend adapter '%s'",
			msg->hdr.len, fe_msg->message_case,
			fe_msg->message_case, adapter->name);

		(void)mgmt_fe_adapter_handle_msg(adapter, fe_msg);

		mgmtd__fe_message__free_unpacked(fe_msg, NULL);
		processed++;
		adapter->num_msg_rx++;
	}

	return processed;
}

static void mgmt_fe_adapter_proc_msgbufs(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter;
	struct stream *work;
	int processed = 0;

	adapter = (struct mgmt_fe_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd);

	MGMTD_FE_ADAPTER_DBG("Have %d ibufs for client '%s' to process",
			       (int)stream_fifo_count_safe(adapter->ibuf_fifo),
			       adapter->name);

	for (; processed < MGMTD_FE_MAX_NUM_MSG_PROC;) {
		work = stream_fifo_pop_safe(adapter->ibuf_fifo);
		if (!work)
			break;

		processed += mgmt_fe_adapter_process_msg(
			adapter, STREAM_DATA(work), stream_get_endp(work));

		if (work != adapter->ibuf_work) {
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
	if (stream_fifo_head(adapter->ibuf_fifo))
		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_PROC_MSG);
}

static void mgmt_fe_adapter_read(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	struct mgmt_fe_msg_hdr *msg_hdr;
	bool incomplete = false;

	adapter = (struct mgmt_fe_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adapter->ibuf_work)
		     - stream_get_endp(adapter->ibuf_work);
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;) {
		bytes_read = stream_read_try(adapter->ibuf_work, adapter->conn_fd,
					     bytes_left);
		MGMTD_FE_ADAPTER_DBG(
			"Got %d bytes of message from MGMTD Frontend adapter '%s'",
			bytes_read, adapter->name);
		if (bytes_read <= 0) {
			if (bytes_read == -1
			    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				mgmt_fe_adapter_register_event(
					adapter, MGMTD_FE_CONN_READ);
				return;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				MGMTD_FE_ADAPTER_ERR(
					"Got error (%d) while reading from MGMTD Frontend adapter '%s'. Err: '%s'",
					bytes_read, adapter->name,
					safe_strerror(errno));
				mgmt_fe_adapter_disconnect(adapter);
				return;
			}
			break;
		}

		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we would have read incomplete messages or not.
	 */
	stream_set_getp(adapter->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(adapter->ibuf_work);
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;) {
		msg_hdr =
			(struct mgmt_fe_msg_hdr *)(STREAM_DATA(
							       adapter->ibuf_work)
						       + total_bytes);
		if (msg_hdr->marker != MGMTD_FE_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_FE_ADAPTER_ERR(
				"Received corrupted buffer from MGMTD frontend client.");
			mgmt_fe_adapter_disconnect(adapter);
			return;
		}
		if (msg_hdr->len > bytes_left)
			break;

		MGMTD_FE_ADAPTER_DBG("Got message (len: %u) from client '%s'",
				       msg_hdr->len, adapter->name);

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
	msg_hdr = (struct mgmt_fe_msg_hdr *)(STREAM_DATA(adapter->ibuf_work)
						 + total_bytes);
	stream_set_endp(adapter->ibuf_work, total_bytes);
	stream_fifo_push(adapter->ibuf_fifo, adapter->ibuf_work);
	adapter->ibuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(adapter->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(adapter->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_PROC_MSG);

	mgmt_fe_adapter_register_event(adapter, MGMTD_FE_CONN_READ);
}

static void mgmt_fe_adapter_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	struct mgmt_fe_client_adapter *adapter;

	adapter = (struct mgmt_fe_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (adapter->obuf_work) {
		stream_fifo_push(adapter->obuf_fifo, adapter->obuf_work);
		adapter->obuf_work = NULL;
	}

	for (s = stream_fifo_head(adapter->obuf_fifo);
	     s && processed < MGMTD_FE_MAX_NUM_MSG_WRITE;
	     s = stream_fifo_head(adapter->obuf_fifo)) {
		/* msg_size = (int)stream_get_size(s); */
		msg_size = (int)STREAM_READABLE(s);
		bytes_written = stream_flush(s, adapter->conn_fd);
		if (bytes_written == -1
		    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_fe_adapter_register_event(
				adapter, MGMTD_FE_CONN_WRITE);
			return;
		} else if (bytes_written != msg_size) {
			MGMTD_FE_ADAPTER_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Frontend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_fe_adapter_register_event(
					adapter, MGMTD_FE_CONN_WRITE);
				return;
			}
			mgmt_fe_adapter_disconnect(adapter);
			return;
		}

		free = stream_fifo_pop(adapter->obuf_fifo);
		stream_free(free);
		MGMTD_FE_ADAPTER_DBG(
			"Wrote %d bytes of message to MGMTD Frontend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_fe_adapter_writes_off(adapter);
		mgmt_fe_adapter_register_event(adapter,
						 MGMTD_FE_CONN_WRITES_ON);
	}
}

static void mgmt_fe_adapter_resume_writes(struct thread *thread)
{
	struct mgmt_fe_client_adapter *adapter;

	adapter = (struct mgmt_fe_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd);

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
		mgmt_fe_adapter_list_del(&mgmt_fe_adapters, *adapter);

		stream_fifo_free((*adapter)->ibuf_fifo);
		stream_free((*adapter)->ibuf_work);
		stream_fifo_free((*adapter)->obuf_fifo);
		stream_free((*adapter)->obuf_work);

		THREAD_OFF((*adapter)->conn_read_ev);
		THREAD_OFF((*adapter)->conn_write_ev);
		THREAD_OFF((*adapter)->proc_msg_ev);
		THREAD_OFF((*adapter)->conn_writes_on);
		XFREE(MTYPE_MGMTD_FE_ADPATER, *adapter);
	}

	*adapter = NULL;
}

int mgmt_fe_adapter_init(struct thread_master *tm, struct mgmt_master *mm)
{
	if (!mgmt_fe_adapter_tm) {
		mgmt_fe_adapter_tm = tm;
		mgmt_fe_adapter_mm = mm;
		mgmt_fe_adapter_list_init(&mgmt_fe_adapters);

		assert(!mgmt_fe_sessions);
		mgmt_fe_sessions =
			hash_create(mgmt_fe_session_hash_key,
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
		mgmt_fe_session_list_init(&adapter->fe_sessions);
		adapter->ibuf_fifo = stream_fifo_new();
		adapter->ibuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
		adapter->obuf_fifo = stream_fifo_new();
		/* adapter->obuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN); */
		adapter->obuf_work = NULL;
		mgmt_fe_adapter_lock(adapter);

		mgmt_fe_adapter_register_event(adapter, MGMTD_FE_CONN_READ);
		mgmt_fe_adapter_list_add_tail(&mgmt_fe_adapters, adapter);

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
				   Mgmtd__DatabaseId db_id, uint64_t req_id,
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
		session, db_id, req_id, result == MGMTD_SUCCESS ? true : false,
		error_if_any, implicit_commit);
}

int mgmt_fe_send_commit_cfg_reply(uint64_t session_id, uint64_t txn_id,
				      Mgmtd__DatabaseId src_db_id,
				      Mgmtd__DatabaseId dst_db_id,
				      uint64_t req_id, bool validate_only,
				      enum mgmt_result result,
				      const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->cfg_txn_id != txn_id)
		return -1;

	return mgmt_fe_send_commitcfg_reply(session, src_db_id, dst_db_id,
						req_id, result, validate_only,
						error_if_any);
}

int mgmt_fe_send_get_cfg_reply(uint64_t session_id, uint64_t txn_id,
				   Mgmtd__DatabaseId db_id, uint64_t req_id,
				   enum mgmt_result result,
				   Mgmtd__YangDataReply *data_resp,
				   const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	return mgmt_fe_send_getcfg_reply(session, db_id, req_id,
					     result == MGMTD_SUCCESS, data_resp,
					     error_if_any);
}

int mgmt_fe_send_get_data_reply(uint64_t session_id, uint64_t txn_id,
				    Mgmtd__DatabaseId db_id, uint64_t req_id,
				    enum mgmt_result result,
				    Mgmtd__YangDataReply *data_resp,
				    const char *error_if_any)
{
	struct mgmt_fe_session_ctx *session;

	session = mgmt_session_id2ctx(session_id);
	if (!session || session->txn_id != txn_id)
		return -1;

	return mgmt_fe_send_getdata_reply(session, db_id, req_id,
					      result == MGMTD_SUCCESS,
					      data_resp, error_if_any);
}

int mgmt_fe_send_data_notify(Mgmtd__DatabaseId db_id,
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
			vty_out(vty, "        Config-Validate Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.validate_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Prep-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.prep_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Txn-Create Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adapter->cmt_stats.txn_create_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Send-Config Start: \t\t%s\n",
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
	Mgmtd__DatabaseId db_id;
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
			vty_out(vty, "        DB-Locks:\n");
			FOREACH_MGMTD_DB_ID (db_id) {
				if (session->db_write_locked[db_id]
				    || session->db_read_locked[db_id]) {
					locked = true;
					vty_out(vty,
						"          %s\t\t\t%s, %s\n",
						mgmt_db_id2name(db_id),
						session->db_write_locked[db_id]
							? "Write"
							: "Read",
						session->db_locked_implict[db_id]
							? "Implicit"
							: "Explicit");
				}
			}
			if (!locked)
				vty_out(vty, "          None\n");
		}
		vty_out(vty, "    Total-Sessions: \t\t\t%d\n",
			(int)mgmt_fe_session_list_count(
				&adapter->fe_sessions));
		vty_out(vty, "    Msg-Sent: \t\t\t\t%u\n", adapter->num_msg_tx);
		vty_out(vty, "    Msg-Recvd: \t\t\t\t%u\n", adapter->num_msg_rx);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_fe_adapter_list_count(&mgmt_fe_adapters));
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
