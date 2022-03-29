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
#include "mgmt_frntnd_client.h"
#include "mgmt_pb.h"
#include "hash.h"
#include "jhash.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_frntnd_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_FRNTND_ADPTR_DBG(fmt, ...)                                       \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_FRNTND_ADPTR_ERR(fmt, ...)                                       \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_FRNTND_ADPTR_DBG(fmt, ...)                                       \
	do {                                                                   \
		if (mgmt_debug_frntnd)                                         \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_FRNTND_ADPTR_ERR(fmt, ...)                                       \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)                                           \
	frr_each_safe(mgmt_frntnd_adptr_list, &mgmt_frntnd_adptrs, (adptr))

enum mgmt_sessn_event {
	MGMTD_FRNTND_SESSN_CFG_TRXN_CLNUP = 1,
	MGMTD_FRNTND_SESSN_SHOW_TRXN_CLNUP,
};

struct mgmt_frntnd_sessn_ctxt {
	struct mgmt_frntnd_client_adapter *adptr;
	uint64_t session_id;
	uint64_t client_id;
	uint64_t trxn_id;
	uint64_t cfg_trxn_id;
	uint8_t db_write_locked[MGMTD_DB_MAX_ID];
	uint8_t db_read_locked[MGMTD_DB_MAX_ID];
	uint8_t db_locked_implict[MGMTD_DB_MAX_ID];
	struct thread *proc_cfg_trxn_clnp;
	struct thread *proc_show_trxn_clnp;

	struct mgmt_frntnd_sessn_list_item list_linkage;
};

DECLARE_LIST(mgmt_frntnd_sessn_list, struct mgmt_frntnd_sessn_ctxt,
	     list_linkage);

#define FOREACH_SESSN_IN_LIST(adptr, sessn)                               \
	frr_each_safe(mgmt_frntnd_sessn_list, &(adptr)->frntnd_sessns, (sessn))

static struct thread_master *mgmt_frntnd_adptr_tm;
static struct mgmt_master *mgmt_frntnd_adptr_mm;

static struct mgmt_frntnd_adptr_list_head mgmt_frntnd_adptrs;

static struct hash *mgmt_frntnd_sessns;
static uint64_t mgmt_frntnd_next_sessn_id;

/* Forward declarations */
static void
mgmt_frntnd_adptr_register_event(struct mgmt_frntnd_client_adapter *adptr,
				 enum mgmt_frntnd_event event);
static void
mgmt_frntnd_adapter_disconnect(struct mgmt_frntnd_client_adapter *adptr);
static void
mgmt_frntnd_session_register_event(struct mgmt_frntnd_sessn_ctxt *sessn,
				   enum mgmt_sessn_event event);

static int
mgmt_frntnd_session_write_lock_db(Mgmtd__DatabaseId db_id,
				  struct mgmt_db_ctxt *db_ctxt,
				  struct mgmt_frntnd_sessn_ctxt *sessn)
{
	if (!sessn->db_write_locked[db_id]) {
		if (mgmt_db_write_lock(db_ctxt) != 0) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		sessn->db_write_locked[db_id] = true;
		MGMTD_FRNTND_ADPTR_DBG(
			"Write-Locked the DB %u for Sessn: %p from %s!", db_id,
			sessn, sessn->adptr->name);
	}

	return 0;
}

static int
mgmt_frntnd_session_read_lock_db(Mgmtd__DatabaseId db_id,
				 struct mgmt_db_ctxt *db_ctxt,
				 struct mgmt_frntnd_sessn_ctxt *sessn)
{
	if (!sessn->db_read_locked[db_id]) {
		if (mgmt_db_read_lock(db_ctxt) != 0) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		sessn->db_read_locked[db_id] = true;
		MGMTD_FRNTND_ADPTR_DBG(
			"Read-Locked the DB %u for Sessn: %p from %s!", db_id,
			sessn, sessn->adptr->name);
	}

	return 0;
}

static int mgmt_frntnd_session_unlock_db(Mgmtd__DatabaseId db_id,
					 struct mgmt_db_ctxt *db_ctxt,
					 struct mgmt_frntnd_sessn_ctxt *sessn,
					 bool unlock_write, bool unlock_read)
{
	if (unlock_write && sessn->db_write_locked[db_id]) {
		sessn->db_write_locked[db_id] = false;
		sessn->db_locked_implict[db_id] = false;
		if (mgmt_db_unlock(db_ctxt) != 0) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		MGMTD_FRNTND_ADPTR_DBG(
			"Unlocked DB %u write-locked earlier by Sessn: %p from %s",
			db_id, sessn, sessn->adptr->name);
	} else if (unlock_read && sessn->db_read_locked[db_id]) {
		sessn->db_read_locked[db_id] = false;
		sessn->db_locked_implict[db_id] = false;
		if (mgmt_db_unlock(db_ctxt) != 0) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		MGMTD_FRNTND_ADPTR_DBG(
			"Unlocked DB %u read-locked earlier by Sessn: %p from %s",
			db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static void
mgmt_frntnd_sessn_cfg_trxn_cleanup(struct mgmt_frntnd_sessn_ctxt *sessn)
{
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctxt *db_ctxt;

	/*
	 * Ensure any uncommitted changes in Candidate DB
	 * is discarded.
	 */
	mgmt_db_copy_dbs(mm->running_db, mm->candidate_db, false);

	for (db_id = 0; db_id < MGMTD_DB_MAX_ID; db_id++) {
		db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm, db_id);
		if (db_ctxt) {
			if (sessn->db_locked_implict[db_id])
				mgmt_frntnd_session_unlock_db(
					db_id, db_ctxt, sessn, true, false);
		}
	}

	/* TODO: Destroy the actual transaction created earlier.
	 * if (sessn->cfg_trxn_id != MGMTD_TRXN_ID_NONE)
	 *	mgmt_destroy_trxn(&sessn->cfg_trxn_id);
	 */
}

static void
mgmt_frntnd_sessn_show_trxn_cleanup(struct mgmt_frntnd_sessn_ctxt *sessn)
{
	Mgmtd__DatabaseId db_id;
	struct mgmt_db_ctxt *db_ctxt;

	for (db_id = 0; db_id < MGMTD_DB_MAX_ID; db_id++) {
		db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm, db_id);
		if (db_ctxt) {
			mgmt_frntnd_session_unlock_db(db_id, db_ctxt, sessn,
						      false, true);
		}
	}

	/* TODO: Destroy the transaction created recently.
	 * if (sessn->trxn_id != MGMTD_TRXN_ID_NONE)
	 *	mgmt_destroy_trxn(&sessn->trxn_id);
	 */
}

static void
mgmt_frntnd_adptr_compute_set_cfg_timers(struct mgmt_setcfg_stats *setcfg_stats)
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
mgmt_frntnd_sessn_compute_commit_timers(struct mgmt_commit_stats *cmt_stats)
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

static void mgmt_frntnd_cleanup_session(struct mgmt_frntnd_sessn_ctxt **sessn)
{
	if ((*sessn)->adptr) {
		mgmt_frntnd_sessn_cfg_trxn_cleanup((*sessn));
		mgmt_frntnd_sessn_show_trxn_cleanup((*sessn));
		mgmt_frntnd_session_unlock_db(
			MGMTD_DB_CANDIDATE, mgmt_frntnd_adptr_mm->candidate_db,
			*sessn, true, true);
		mgmt_frntnd_session_unlock_db(MGMTD_DB_RUNNING,
					      mgmt_frntnd_adptr_mm->running_db,
					      *sessn, true, true);

		mgmt_frntnd_sessn_list_del(&(*sessn)->adptr->frntnd_sessns,
					   *sessn);
		mgmt_frntnd_adapter_unlock(&(*sessn)->adptr);
	}

	hash_release(mgmt_frntnd_sessns, *sessn);
	XFREE(MTYPE_MGMTD_FRNTND_SESSN, *sessn);
	*sessn = NULL;
}

static struct mgmt_frntnd_sessn_ctxt *
mgmt_frntnd_find_session_by_client_id(struct mgmt_frntnd_client_adapter *adptr,
				      uint64_t client_id)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	FOREACH_SESSN_IN_LIST (adptr, sessn) {
		if (sessn->client_id == client_id)
			return sessn;
	}

	return NULL;
}

static unsigned int mgmt_frntnd_sessn_hash_key(const void *data)
{
	const struct mgmt_frntnd_sessn_ctxt *sessn = data;

	return jhash2((uint32_t *) &sessn->session_id,
		      sizeof(sessn->session_id) / sizeof(uint32_t), 0);
}

static bool mgmt_frntnd_sessn_hash_cmp(const void *d1, const void *d2)
{
	const struct mgmt_frntnd_sessn_ctxt *sessn1 = d1;
	const struct mgmt_frntnd_sessn_ctxt *sessn2 = d2;

	return (sessn1->session_id == sessn2->session_id);
}

static void mgmt_frntnd_sessn_hash_free(void *data)
{
	struct mgmt_frntnd_sessn_ctxt *sessn = data;

	mgmt_frntnd_cleanup_session(&sessn);
}

static void mgmt_frntnd_sessn_hash_destroy(void)
{
	if (mgmt_frntnd_sessns == NULL)
		return;

	hash_clean(mgmt_frntnd_sessns,
		   mgmt_frntnd_sessn_hash_free);
	hash_free(mgmt_frntnd_sessns);
	mgmt_frntnd_sessns = NULL;
}

static inline struct mgmt_frntnd_sessn_ctxt *
mgmt_session_id2ctxt(uint64_t session_id)
{
	struct mgmt_frntnd_sessn_ctxt key = {0};
	struct mgmt_frntnd_sessn_ctxt *sessn;

	if (!mgmt_frntnd_sessns)
		return NULL;

	key.session_id = session_id;
	sessn = hash_lookup(mgmt_frntnd_sessns, &key);

	return sessn;
}

static struct mgmt_frntnd_sessn_ctxt *
mgmt_frntnd_create_session(struct mgmt_frntnd_client_adapter *adptr,
			   uint64_t client_id)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_frntnd_find_session_by_client_id(adptr, client_id);
	if (sessn)
		mgmt_frntnd_cleanup_session(&sessn);

	sessn = XCALLOC(MTYPE_MGMTD_FRNTND_SESSN,
			sizeof(struct mgmt_frntnd_sessn_ctxt));
	assert(sessn);
	sessn->client_id = client_id;
	sessn->adptr = adptr;
	sessn->trxn_id = MGMTD_TRXN_ID_NONE;
	sessn->cfg_trxn_id = MGMTD_TRXN_ID_NONE;
	mgmt_frntnd_adapter_lock(adptr);
	mgmt_frntnd_sessn_list_add_tail(&adptr->frntnd_sessns, sessn);
	if (!mgmt_frntnd_next_sessn_id)
		mgmt_frntnd_next_sessn_id++;
	sessn->session_id = mgmt_frntnd_next_sessn_id++;
	hash_get(mgmt_frntnd_sessns, sessn, hash_alloc_intern);

	return sessn;
}

static void
mgmt_frntnd_cleanup_sessions(struct mgmt_frntnd_client_adapter *adptr)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	FOREACH_SESSN_IN_LIST (adptr, sessn)
		mgmt_frntnd_cleanup_session(&sessn);
}

static inline void
mgmt_frntnd_adapter_sched_msg_write(struct mgmt_frntnd_client_adapter *adptr)
{
	if (!CHECK_FLAG(adptr->flags, MGMTD_FRNTND_ADPTR_FLAGS_WRITES_OFF))
		mgmt_frntnd_adptr_register_event(adptr,
						 MGMTD_FRNTND_CONN_WRITE);
}

static inline void
mgmt_frntnd_adapter_writes_on(struct mgmt_frntnd_client_adapter *adptr)
{
	MGMTD_FRNTND_ADPTR_DBG("Resume writing msgs for '%s'", adptr->name);
	UNSET_FLAG(adptr->flags, MGMTD_FRNTND_ADPTR_FLAGS_WRITES_OFF);
	if (adptr->obuf_work || stream_fifo_count_safe(adptr->obuf_fifo))
		mgmt_frntnd_adapter_sched_msg_write(adptr);
}

static inline void
mgmt_frntnd_adapter_writes_off(struct mgmt_frntnd_client_adapter *adptr)
{
	SET_FLAG(adptr->flags, MGMTD_FRNTND_ADPTR_FLAGS_WRITES_OFF);
	MGMTD_FRNTND_ADPTR_DBG("Paused writing msgs for '%s'", adptr->name);
}

static int
mgmt_frntnd_adapter_send_msg(struct mgmt_frntnd_client_adapter *adptr,
			     Mgmtd__FrntndMessage *frntnd_msg)
{
	size_t msg_size;
	uint8_t msg_buf[MGMTD_FRNTND_MSG_MAX_LEN];
	struct mgmt_frntnd_msg *msg;

	if (adptr->conn_fd == 0) {
		MGMTD_FRNTND_ADPTR_ERR("Connection already reset");
		return -1;
	}

	msg_size = mgmtd__frntnd_message__get_packed_size(frntnd_msg);
	msg_size += MGMTD_FRNTND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		MGMTD_FRNTND_ADPTR_ERR(
			"Message size %d more than max size'%d. Not sending!'",
			(int)msg_size, (int)sizeof(msg_buf));
		return -1;
	}

	msg = (struct mgmt_frntnd_msg *)msg_buf;
	msg->hdr.marker = MGMTD_FRNTND_MSG_MARKER;
	msg->hdr.len = (uint16_t)msg_size;
	mgmtd__frntnd_message__pack(frntnd_msg, msg->payload);

	if (!adptr->obuf_work)
		adptr->obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(adptr->obuf_work) < msg_size) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	}
	stream_write(adptr->obuf_work, (void *)msg_buf, msg_size);

	mgmt_frntnd_adapter_sched_msg_write(adptr);
	adptr->num_msg_tx++;
	return 0;
}

static int
mgmt_frntnd_send_session_reply(struct mgmt_frntnd_client_adapter *adptr,
			       struct mgmt_frntnd_sessn_ctxt *sessn,
			       bool create, bool success)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndSessionReply sessn_reply;

	mgmtd__frntnd_session_reply__init(&sessn_reply);
	sessn_reply.create = create;
	if (create) {
		sessn_reply.has_client_conn_id = 1;
		sessn_reply.client_conn_id = sessn->client_id;
	}
	sessn_reply.session_id = sessn->session_id;
	sessn_reply.success = success;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY;
	frntnd_msg.sessn_reply = &sessn_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending SESSION_REPLY message to MGMTD Frontend client '%s'",
		adptr->name);

	return mgmt_frntnd_adapter_send_msg(adptr, &frntnd_msg);
}

static int mgmt_frntnd_send_lockdb_reply(struct mgmt_frntnd_sessn_ctxt *sessn,
					 Mgmtd__DatabaseId db_id,
					 uint64_t req_id, bool lock_db,
					 bool success, const char *error_if_any)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndLockDbReply lockdb_reply;

	assert(sessn->adptr);

	mgmtd__frntnd_lock_db_reply__init(&lockdb_reply);
	lockdb_reply.session_id = sessn->session_id;
	lockdb_reply.db_id = db_id;
	lockdb_reply.req_id = req_id;
	lockdb_reply.lock = lock_db;
	lockdb_reply.success = success;
	if (error_if_any)
		lockdb_reply.error_if_any = (char *)error_if_any;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REPLY;
	frntnd_msg.lockdb_reply = &lockdb_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending LOCK_DB_REPLY message to MGMTD Frontend client '%s'",
		sessn->adptr->name);

	return mgmt_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int mgmt_frntnd_send_setcfg_reply(struct mgmt_frntnd_sessn_ctxt *sessn,
					 Mgmtd__DatabaseId db_id,
					 uint64_t req_id, bool success,
					 const char *error_if_any,
					 bool implicit_commit)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndSetConfigReply setcfg_reply;

	assert(sessn->adptr);

	if (implicit_commit && sessn->cfg_trxn_id)
		mgmt_frntnd_session_register_event(
			sessn, MGMTD_FRNTND_SESSN_CFG_TRXN_CLNUP);

	mgmtd__frntnd_set_config_reply__init(&setcfg_reply);
	setcfg_reply.session_id = sessn->session_id;
	setcfg_reply.db_id = db_id;
	setcfg_reply.req_id = req_id;
	setcfg_reply.success = success;
	if (error_if_any)
		setcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY;
	frntnd_msg.setcfg_reply = &setcfg_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending SET_CONFIG_REPLY message to MGMTD Frontend client '%s'",
		sessn->adptr->name);

	if (implicit_commit) {
		if (mm->perf_stats_en)
			gettimeofday(&sessn->adptr->cmt_stats.last_end, NULL);
		mgmt_frntnd_sessn_compute_commit_timers(
			&sessn->adptr->cmt_stats);
	}

	if (mm->perf_stats_en)
		gettimeofday(&sessn->adptr->setcfg_stats.last_end, NULL);
	mgmt_frntnd_adptr_compute_set_cfg_timers(&sessn->adptr->setcfg_stats);

	return mgmt_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int mgmt_frntnd_send_commitcfg_reply(
	struct mgmt_frntnd_sessn_ctxt *sessn, Mgmtd__DatabaseId src_db_id,
	Mgmtd__DatabaseId dst_db_id, uint64_t req_id, enum mgmt_result result,
	bool validate_only, const char *error_if_any)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndCommitConfigReply commcfg_reply;

	assert(sessn->adptr);

	mgmtd__frntnd_commit_config_reply__init(&commcfg_reply);
	commcfg_reply.session_id = sessn->session_id;
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

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY;
	frntnd_msg.commcfg_reply = &commcfg_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending COMMIT_CONFIG_REPLY message to MGMTD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the CONFIG transaction associated with this session.
	 */
	if (sessn->cfg_trxn_id
	    && ((result == MGMTD_SUCCESS && !validate_only)
		|| (result == MGMTD_NO_CFG_CHANGES)))
		mgmt_frntnd_session_register_event(
			sessn, MGMTD_FRNTND_SESSN_CFG_TRXN_CLNUP);

	if (mm->perf_stats_en)
		gettimeofday(&sessn->adptr->cmt_stats.last_end, NULL);
	mgmt_frntnd_sessn_compute_commit_timers(&sessn->adptr->cmt_stats);
	return mgmt_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int mgmt_frntnd_send_getcfg_reply(struct mgmt_frntnd_sessn_ctxt *sessn,
					 Mgmtd__DatabaseId db_id,
					 uint64_t req_id, bool success,
					 Mgmtd__YangDataReply *data,
					 const char *error_if_any)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndGetConfigReply getcfg_reply;

	assert(sessn->adptr);

	mgmtd__frntnd_get_config_reply__init(&getcfg_reply);
	getcfg_reply.session_id = sessn->session_id;
	getcfg_reply.db_id = db_id;
	getcfg_reply.req_id = req_id;
	getcfg_reply.success = success;
	getcfg_reply.data = data;
	if (error_if_any)
		getcfg_reply.error_if_any = (char *)error_if_any;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY;
	frntnd_msg.getcfg_reply = &getcfg_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending GET_CONFIG_REPLY message to MGMTD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (sessn->trxn_id && (!success || (data && data->next_indx < 0)))
		mgmt_frntnd_session_register_event(
			sessn, MGMTD_FRNTND_SESSN_SHOW_TRXN_CLNUP);

	return mgmt_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int mgmt_frntnd_send_getdata_reply(struct mgmt_frntnd_sessn_ctxt *sessn,
					  Mgmtd__DatabaseId db_id,
					  uint64_t req_id, bool success,
					  Mgmtd__YangDataReply *data,
					  const char *error_if_any)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndGetDataReply getdata_reply;

	assert(sessn->adptr);

	mgmtd__frntnd_get_data_reply__init(&getdata_reply);
	getdata_reply.session_id = sessn->session_id;
	getdata_reply.db_id = db_id;
	getdata_reply.req_id = req_id;
	getdata_reply.success = success;
	getdata_reply.data = data;
	if (error_if_any)
		getdata_reply.error_if_any = (char *)error_if_any;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_GETDATA_REPLY;
	frntnd_msg.getdata_reply = &getdata_reply;

	MGMTD_FRNTND_ADPTR_DBG(
		"Sending GET_DATA_REPLY message to MGMTD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (sessn->trxn_id && (!success || (data && data->next_indx < 0)))
		mgmt_frntnd_session_register_event(
			sessn, MGMTD_FRNTND_SESSN_SHOW_TRXN_CLNUP);

	return mgmt_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static void mgmt_frntnd_session_cfg_trxn_clnup(struct thread *thread)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = (struct mgmt_frntnd_sessn_ctxt *)THREAD_ARG(thread);

	mgmt_frntnd_sessn_cfg_trxn_cleanup(sessn);
}

static void mgmt_frntnd_session_show_trxn_clnup(struct thread *thread)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = (struct mgmt_frntnd_sessn_ctxt *)THREAD_ARG(thread);

	mgmt_frntnd_sessn_show_trxn_cleanup(sessn);
}

static void
mgmt_frntnd_session_register_event(struct mgmt_frntnd_sessn_ctxt *sessn,
				   enum mgmt_sessn_event event)
{
	struct timeval tv = {.tv_sec = 0,
			     .tv_usec = MGMTD_FRNTND_MSG_PROC_DELAY_USEC};

	switch (event) {
	case MGMTD_FRNTND_SESSN_CFG_TRXN_CLNUP:
		thread_add_timer_tv(mgmt_frntnd_adptr_tm,
				    mgmt_frntnd_session_cfg_trxn_clnup, sessn,
				    &tv, &sessn->proc_cfg_trxn_clnp);
		assert(sessn->proc_cfg_trxn_clnp);
		break;
	case MGMTD_FRNTND_SESSN_SHOW_TRXN_CLNUP:
		thread_add_timer_tv(mgmt_frntnd_adptr_tm,
				    mgmt_frntnd_session_show_trxn_clnup, sessn,
				    &tv, &sessn->proc_show_trxn_clnp);
		assert(sessn->proc_show_trxn_clnp);
		break;
	default:
		assert(!"mgmt_frntnd_adptr_post_event() called incorrectly");
		break;
	}
}

static struct mgmt_frntnd_client_adapter *
mgmt_frntnd_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_frntnd_client_adapter *adptr;

	FOREACH_ADPTR_IN_LIST (adptr) {
		if (adptr->conn_fd == conn_fd)
			return adptr;
	}

	return NULL;
}

static struct mgmt_frntnd_client_adapter *
mgmt_frntnd_find_adapter_by_name(const char *name)
{
	struct mgmt_frntnd_client_adapter *adptr;

	FOREACH_ADPTR_IN_LIST (adptr) {
		if (!strncmp(adptr->name, name, sizeof(adptr->name)))
			return adptr;
	}

	return NULL;
}

static void
mgmt_frntnd_adapter_disconnect(struct mgmt_frntnd_client_adapter *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	mgmt_frntnd_cleanup_sessions(adptr);
	mgmt_frntnd_sessn_list_fini(&adptr->frntnd_sessns);
	mgmt_frntnd_adptr_list_del(&mgmt_frntnd_adptrs, adptr);

	mgmt_frntnd_adapter_unlock(&adptr);
}

static void
mgmt_frntnd_adapter_cleanup_old_conn(struct mgmt_frntnd_client_adapter *adptr)
{
	struct mgmt_frntnd_client_adapter *old;

	FOREACH_ADPTR_IN_LIST (old) {
		if (old != adptr
		    && !strncmp(adptr->name, old->name, sizeof(adptr->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			MGMTD_FRNTND_ADPTR_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adptr->name, adptr->conn_fd, old->conn_fd);
			mgmt_frntnd_adapter_disconnect(old);
		}
	}
}

static void
mgmt_frntnd_cleanup_adapters(void)
{
	struct mgmt_frntnd_client_adapter *adptr;

	FOREACH_ADPTR_IN_LIST (adptr) {
		mgmt_frntnd_cleanup_sessions(adptr);
		mgmt_frntnd_adapter_unlock(&adptr);
	}
}

static int
mgmt_frntnd_session_handle_lockdb_req_msg(struct mgmt_frntnd_sessn_ctxt *sessn,
					  Mgmtd__FrntndLockDbReq *lockdb_req)
{
	struct mgmt_db_ctxt *db_ctxt;

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (lockdb_req->db_id != MGMTD_DB_CANDIDATE) {
		mgmt_frntnd_send_lockdb_reply(
			sessn, lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Lock/Unlock on databases other than Candidate DB not permitted!");
		return -1;
	}

	db_ctxt =
		mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm, lockdb_req->db_id);
	if (!db_ctxt) {
		mgmt_frntnd_send_lockdb_reply(
			sessn, lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Failed to retrieve handle for DB!");
		return -1;
	}

	if (lockdb_req->lock) {
		if (mgmt_frntnd_session_write_lock_db(lockdb_req->db_id,
						      db_ctxt, sessn)
		    != 0) {
			mgmt_frntnd_send_lockdb_reply(
				sessn, lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock already taken on DB by another session!");
			return -1;
		}

		sessn->db_locked_implict[lockdb_req->db_id] = false;
	} else {
		if (!sessn->db_write_locked[lockdb_req->db_id]) {
			mgmt_frntnd_send_lockdb_reply(
				sessn, lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock on DB was not taken by this session!");
			return 0;
		}

		(void)mgmt_frntnd_session_unlock_db(lockdb_req->db_id, db_ctxt,
						    sessn, true, false);
	}

	if (mgmt_frntnd_send_lockdb_reply(sessn, lockdb_req->db_id,
					   lockdb_req->req_id, lockdb_req->lock,
					   true, NULL)
	    != 0) {
		MGMTD_FRNTND_ADPTR_DBG(
			"Failed to send LOCK_DB_REPLY for DB %u Sessn: %p from %s",
			lockdb_req->db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static int
mgmt_frntnd_session_handle_setcfg_req_msg(struct mgmt_frntnd_sessn_ctxt *sessn,
					  Mgmtd__FrntndSetConfigReq *setcfg_req)
{
	/* uint64_t cfg_sessn_id; */
	struct mgmt_db_ctxt *db_ctxt, *dst_db_ctxt;

	if (mm->perf_stats_en)
		gettimeofday(&sessn->adptr->setcfg_stats.last_start, NULL);

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB
	 * or not. Report failure if its not. MGMTD currently only
	 * supports editing the Candidate DB.
	 */
	if (setcfg_req->db_id != MGMTD_DB_CANDIDATE) {
		mgmt_frntnd_send_setcfg_reply(
			sessn, setcfg_req->db_id, setcfg_req->req_id, false,
			"Set-Config on databases other than Candidate DB not permitted!",
			setcfg_req->implicit_commit);
		return 0;
	}

	/*
	 * Get the DB handle.
	 */
	db_ctxt =
		mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm, setcfg_req->db_id);
	if (!db_ctxt) {
		mgmt_frntnd_send_setcfg_reply(
			sessn, setcfg_req->db_id, setcfg_req->req_id, false,
			"No such DB exists!", setcfg_req->implicit_commit);
		return 0;
	}

	if (sessn->cfg_trxn_id == MGMTD_TRXN_ID_NONE) {
		/*
		 * TODO: Check first if the current session can run a CONFIG
		 * transaction or not. Report failure if a CONFIG transaction
		 * from another session is already in progress.
		 * cfg_sessn_id = mgmt_config_trxn_in_progress();
		 * if (cfg_sessn_id != MGMTD_SESSION_ID_NONE
		 *   && cfg_sessn_id != sessn->session_id) {
		 *	mgmt_frntnd_send_setcfg_reply(
		 *		sessn, setcfg_req->db_id, setcfg_req->req_id,
		 *		false,
		 *		"Configuration already in-progress through a
		 *different user session!", setcfg_req->implicit_commit); goto
		 *mgmt_frntnd_sess_handle_setcfg_req_failed;
		 *}
		 */


		/*
		 * Try taking write-lock on the requested DB (if not already).
		 */
		if (!sessn->db_write_locked[setcfg_req->db_id]) {
			if (mgmt_frntnd_session_write_lock_db(setcfg_req->db_id,
							      db_ctxt, sessn)
			    != 0) {
				mgmt_frntnd_send_setcfg_reply(
					sessn, setcfg_req->db_id,
					setcfg_req->req_id, false,
					"Failed to lock the DB!",
					setcfg_req->implicit_commit);
				goto mgmt_frntnd_sess_handle_setcfg_req_failed;
			}

			sessn->db_locked_implict[setcfg_req->db_id] = true;
		}

		/*
		 * TODO: Start a CONFIG Transaction (if not started already)
		 * sessn->cfg_trxn_id = mgmt_create_trxn(sessn->session_id,
		 *				      MGMTD_TRXN_TYPE_CONFIG);
		 * if (sessn->cfg_trxn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_frntnd_send_setcfg_reply(
		 *		sessn, setcfg_req->db_id, setcfg_req->req_id,
		 *		false,
		 *		"Failed to create a Configuration session!",
		 *		setcfg_req->implicit_commit);
		 *	goto mgmt_frntnd_sess_handle_setcfg_req_failed;
		 * }
		 */

		MGMTD_FRNTND_ADPTR_DBG(
			"Created new Config Trxn 0x%llx for session %p",
			(unsigned long long)sessn->cfg_trxn_id, sessn);
	} else {
		MGMTD_FRNTND_ADPTR_DBG(
			"Config Trxn 0x%llx for session %p already created",
			(unsigned long long)sessn->cfg_trxn_id, sessn);

		if (setcfg_req->implicit_commit) {
			/*
			 * In this scenario need to skip cleanup of the trxn,
			 * so setting implicit commit to false.
			 */
			mgmt_frntnd_send_setcfg_reply(
				sessn, setcfg_req->db_id, setcfg_req->req_id,
				false,
				"A Configuration transaction is already in progress!",
				false);
			return 0;
		}
	}

	dst_db_ctxt = 0;
	if (setcfg_req->implicit_commit) {
		dst_db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm,
						     setcfg_req->commit_db_id);
		if (!dst_db_ctxt) {
			mgmt_frntnd_send_setcfg_reply(
				sessn, setcfg_req->db_id, setcfg_req->req_id,
				false, "No such commit DB exists!",
				setcfg_req->implicit_commit);
			return 0;
		}
	}

	/* TODO: Create the SETConfig request under the transaction.
	 * if (mgmt_trxn_send_set_config_req(
	 *	sessn->cfg_trxn_id, setcfg_req->req_id, setcfg_req->db_id,
	 *	db_ctxt, setcfg_req->data, setcfg_req->n_data,
	 *	setcfg_req->implicit_commit, setcfg_req->commit_db_id,
	 *	dst_db_ctxt)
	 *	!= 0) {
	 *	mgmt_frntnd_send_setcfg_reply(
	 *		sessn, setcfg_req->db_id, setcfg_req->req_id, false,
	 *		"Request processing for SET-CONFIG failed!",
	 *		setcfg_req->implicit_commit);
	 *	goto mgmt_frntnd_sess_handle_setcfg_req_failed;
	 * }
	 *
	 * For now send a failure reply.
	 */
	mgmt_frntnd_send_setcfg_reply(
		sessn, setcfg_req->db_id, setcfg_req->req_id, false,
		"Request processing for SET-CONFIG failed!",
		setcfg_req->implicit_commit);
	goto mgmt_frntnd_sess_handle_setcfg_req_failed;

	return 0;

mgmt_frntnd_sess_handle_setcfg_req_failed:

	/* TODO: Delete transaction created recently.
	 * if (sessn->cfg_trxn_id != MGMTD_TRXN_ID_NONE)
	 *	mgmt_destroy_trxn(&sessn->cfg_trxn_id);
	 */
	if (db_ctxt && sessn->db_write_locked[setcfg_req->db_id])
		mgmt_frntnd_session_unlock_db(setcfg_req->db_id, db_ctxt, sessn,
					      true, false);

	return 0;
}

static int
mgmt_frntnd_session_handle_getcfg_req_msg(struct mgmt_frntnd_sessn_ctxt *sessn,
					  Mgmtd__FrntndGetConfigReq *getcfg_req)
{
	struct mgmt_db_ctxt *db_ctxt;

	/*
	 * Get the DB handle.
	 */
	db_ctxt =
		mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm, getcfg_req->db_id);
	if (!db_ctxt) {
		mgmt_frntnd_send_getcfg_reply(sessn, getcfg_req->db_id,
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
		mgmt_frntnd_send_getcfg_reply(
			sessn, getcfg_req->db_id, getcfg_req->req_id, false,
			NULL,
			"Get-Config on databases other than Candidate or Running DB not permitted!");
		return 0;
	}

	if (sessn->trxn_id == MGMTD_TRXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DB (if not already
		 * locked). If the DB has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DB.
		 */
		if (!sessn->db_read_locked[getcfg_req->db_id]
		    && !sessn->db_write_locked[getcfg_req->db_id]) {
			if (mgmt_frntnd_session_read_lock_db(getcfg_req->db_id,
							     db_ctxt, sessn)
			    != 0) {
				mgmt_frntnd_send_getcfg_reply(
					sessn, getcfg_req->db_id,
					getcfg_req->req_id, false, NULL,
					"Failed to lock the DB! Another session might have locked it!");
				goto mgmt_frntnd_sess_handle_getcfg_req_failed;
			}

			sessn->db_locked_implict[getcfg_req->db_id] = true;
		}

		/*
		 * TODO: Start a SHOW Transaction (if not started already)
		 * sessn->trxn_id = mgmt_create_trxn(sessn->session_id,
		 *				MGMTD_TRXN_TYPE_SHOW);
		 * if (sessn->trxn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_frntnd_send_getcfg_reply(
		 *		sessn, getcfg_req->db_id, getcfg_req->req_id,
		 *		false, NULL,
		 *		"Failed to create a Show transaction!");
		 *	goto mgmt_frntnd_sess_handle_getcfg_req_failed;
		 * }
		 */
		mgmt_frntnd_send_getcfg_reply(
			sessn, getcfg_req->db_id, getcfg_req->req_id, false,
			NULL, "Failed to create a Show transaction!");
		goto mgmt_frntnd_sess_handle_getcfg_req_failed;


		MGMTD_FRNTND_ADPTR_DBG(
			"Created new Show Trxn 0x%llx for session %p",
			(unsigned long long)sessn->trxn_id, sessn);
	} else {
		MGMTD_FRNTND_ADPTR_DBG(
			"Show Trxn 0x%llx for session %p already created",
			(unsigned long long)sessn->trxn_id, sessn);
	}

	/* TODO: Create a GETConfig request under the transaction.
	 * if (mgmt_trxn_send_get_config_req(sessn->trxn_id, getcfg_req->req_id,
	 *				getcfg_req->db_id, db_ctxt,
	 *				getcfg_req->data, getcfg_req->n_data)
	 *	!= 0) {
	 *	mgmt_frntnd_send_getcfg_reply(
	 *		sessn, getcfg_req->db_id, getcfg_req->req_id, false,
	 *		NULL, "Request processing for GET-CONFIG failed!");
	 *	goto mgmt_frntnd_sess_handle_getcfg_req_failed;
	 * }
	 *
	 * For now send back a failure reply.
	 */
	mgmt_frntnd_send_getcfg_reply(
		sessn, getcfg_req->db_id, getcfg_req->req_id, false, NULL,
		"Request processing for GET-CONFIG failed!");
	goto mgmt_frntnd_sess_handle_getcfg_req_failed;

	return 0;

mgmt_frntnd_sess_handle_getcfg_req_failed:

	/* TODO: Destroy the transaction created recently.
	 * if (sessn->trxn_id != MGMTD_TRXN_ID_NONE)
	 *	mgmt_destroy_trxn(&sessn->trxn_id);
	 */
	if (db_ctxt && sessn->db_read_locked[getcfg_req->db_id])
		mgmt_frntnd_session_unlock_db(getcfg_req->db_id, db_ctxt, sessn,
					      false, true);

	return -1;
}

static int
mgmt_frntnd_session_handle_getdata_req_msg(struct mgmt_frntnd_sessn_ctxt *sessn,
					   Mgmtd__FrntndGetDataReq *getdata_req)
{
	struct mgmt_db_ctxt *db_ctxt;

	/*
	 * Get the DB handle.
	 */
	db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm,
					 getdata_req->db_id);
	if (!db_ctxt) {
		mgmt_frntnd_send_getdata_reply(sessn, getdata_req->db_id,
					       getdata_req->req_id, false, NULL,
					       "No such DB exists!");
		return 0;
	}

	if (sessn->trxn_id == MGMTD_TRXN_ID_NONE) {
		/*
		 * Try taking read-lock on the requested DB (if not already
		 * locked). If the DB has already been write-locked by a ongoing
		 * CONFIG transaction we may allow reading the contents of the
		 * same DB.
		 */
		if (!sessn->db_read_locked[getdata_req->db_id]
		    && !sessn->db_write_locked[getdata_req->db_id]) {
			if (mgmt_frntnd_session_read_lock_db(getdata_req->db_id,
							     db_ctxt, sessn)
			    != 0) {
				mgmt_frntnd_send_getdata_reply(
					sessn, getdata_req->db_id,
					getdata_req->req_id, false, NULL,
					"Failed to lock the DB! Another session might have locked it!");
				goto mgmt_frntnd_sess_handle_getdata_req_failed;
			}

			sessn->db_locked_implict[getdata_req->db_id] = true;
		}

		/*
		 * TODO: Start a SHOW Transaction (if not started already)
		 * sessn->trxn_id =
		 *	mgmt_create_trxn(sessn->session_id,
		 *			MGMTD_TRXN_TYPE_SHOW);
		 * if (sessn->trxn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_frntnd_send_getdata_reply(
		 *		sessn, getdata_req->db_id, getdata_req->req_id,
		 *		false, NULL,
		 *		"Failed to create a Show transaction!");
		 *	goto mgmt_frntnd_sess_handle_getdata_req_failed;
		 * }
		 */
		mgmt_frntnd_send_getdata_reply(
			sessn, getdata_req->db_id, getdata_req->req_id, false,
			NULL, "Failed to create a Show transaction!");
		goto mgmt_frntnd_sess_handle_getdata_req_failed;


		MGMTD_FRNTND_ADPTR_DBG(
			"Created new Show Trxn 0x%llx for session %p",
			(unsigned long long)sessn->trxn_id, sessn);
	} else {
		MGMTD_FRNTND_ADPTR_DBG(
			"Show Trxn 0x%llx for session %p already created",
			(unsigned long long)sessn->trxn_id, sessn);
	}

	/* TODO: Create a GETData request under the transaction.
	 * if (mgmt_trxn_send_get_data_req(sessn->trxn_id, getdata_req->req_id,
	 *				getdata_req->db_id, db_ctxt,
	 *				getdata_req->data, getdata_req->n_data)
	 *	!= 0) {
	 *	mgmt_frntnd_send_getdata_reply(
	 *		sessn, getdata_req->db_id, getdata_req->req_id, false,
	 *		NULL, "Request processing for GET-CONFIG failed!");
	 *	goto mgmt_frntnd_sess_handle_getdata_req_failed;
	 * }
	 *
	 * For now send back a failure reply.
	 */
	mgmt_frntnd_send_getdata_reply(
		sessn, getdata_req->db_id, getdata_req->req_id, false, NULL,
		"Request processing for GET-CONFIG failed!");
	goto mgmt_frntnd_sess_handle_getdata_req_failed;

	return 0;

mgmt_frntnd_sess_handle_getdata_req_failed:

	/* TODO: Destroy the transaction created recently.
	 * if (sessn->trxn_id != MGMTD_TRXN_ID_NONE)
	 *	mgmt_destroy_trxn(&sessn->trxn_id);
	 */

	if (db_ctxt && sessn->db_read_locked[getdata_req->db_id])
		mgmt_frntnd_session_unlock_db(getdata_req->db_id, db_ctxt,
					      sessn, false, true);

	return -1;
}

static int mgmt_frntnd_session_handle_commit_config_req_msg(
	struct mgmt_frntnd_sessn_ctxt *sessn,
	Mgmtd__FrntndCommitConfigReq *commcfg_req)
{
	struct mgmt_db_ctxt *src_db_ctxt, *dst_db_ctxt;

	if (mm->perf_stats_en)
		gettimeofday(&sessn->adptr->cmt_stats.last_start, NULL);
	sessn->adptr->cmt_stats.commit_cnt++;
	/*
	 * Get the source DB handle.
	 */
	src_db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm,
					     commcfg_req->src_db_id);
	if (!src_db_ctxt) {
		mgmt_frntnd_send_commitcfg_reply(
			sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"No such source DB exists!");
		return 0;
	}

	/*
	 * Get the destination DB handle.
	 */
	dst_db_ctxt = mgmt_db_get_hndl_by_id(mgmt_frntnd_adptr_mm,
					     commcfg_req->dst_db_id);
	if (!dst_db_ctxt) {
		mgmt_frntnd_send_commitcfg_reply(
			sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
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
		mgmt_frntnd_send_commitcfg_reply(
			sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Set-Config on databases other than Running DB not permitted!");
		return 0;
	}

	if (sessn->cfg_trxn_id == MGMTD_TRXN_ID_NONE) {
		/*
		 * TODO: Start a CONFIG Transaction (if not started already)
		 * sessn->cfg_trxn_id = mgmt_create_trxn(sessn->session_id,
		 *				MGMTD_TRXN_TYPE_CONFIG);
		 * if (sessn->cfg_trxn_id == MGMTD_SESSION_ID_NONE) {
		 *	mgmt_frntnd_send_commitcfg_reply(
		 *		sessn, commcfg_req->src_db_id,
		 *		commcfg_req->dst_db_id, commcfg_req->req_id,
		 *		MGMTD_INTERNAL_ERROR,
		 *		commcfg_req->validate_only,
		 *		"Failed to create a Configuration session!");
		 *	return 0;
		 * }
		 */
		mgmt_frntnd_send_commitcfg_reply(
			sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
			commcfg_req->validate_only,
			"Failed to create a Configuration session!");
		return 0;
	}


	/*
	 * Try taking write-lock on the destination DB (if not already).
	 */
	if (!sessn->db_write_locked[commcfg_req->dst_db_id]) {
		if (mgmt_frntnd_session_write_lock_db(commcfg_req->dst_db_id,
						      dst_db_ctxt, sessn)
		    != 0) {
			mgmt_frntnd_send_commitcfg_reply(
				sessn, commcfg_req->src_db_id,
				commcfg_req->dst_db_id, commcfg_req->req_id,
				MGMTD_DB_LOCK_FAILED,
				commcfg_req->validate_only,
				"Failed to lock the destination DB!");
			return 0;
		}

		sessn->db_locked_implict[commcfg_req->dst_db_id] = true;
	}

	/* TODO: Create COMMITConfig request under the transaction
	 * if (mgmt_trxn_send_commit_config_req(
	 *	sessn->cfg_trxn_id, commcfg_req->req_id,
	 *	commcfg_req->src_db_id, src_db_ctxt, commcfg_req->dst_db_id,
	 *	dst_db_ctxt, commcfg_req->validate_only, commcfg_req->abort,
	 *	false)
	 *	!= 0) {
	 *	mgmt_frntnd_send_commitcfg_reply(
	 *		sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
	 *		commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
	 *		commcfg_req->validate_only,
	 *		"Request processing for COMMIT-CONFIG failed!");
	 *	return 0;
	 * }
	 *
	 * For now due to lack of trxn modules send a unsuccessfull reply.
	 */
	mgmt_frntnd_send_commitcfg_reply(
		sessn, commcfg_req->src_db_id, commcfg_req->dst_db_id,
		commcfg_req->req_id, MGMTD_INTERNAL_ERROR,
		commcfg_req->validate_only,
		"Request processing for COMMIT-CONFIG failed!");

	return 0;
}

static int
mgmt_frntnd_adapter_handle_msg(struct mgmt_frntnd_client_adapter *adptr,
			       Mgmtd__FrntndMessage *frntnd_msg)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	switch (frntnd_msg->message_case) {
	case MGMTD__FRNTND_MESSAGE__MESSAGE_REGISTER_REQ:
		MGMTD_FRNTND_ADPTR_DBG("Got Register Req Msg from '%s'",
				       frntnd_msg->register_req->client_name);

		if (strlen(frntnd_msg->register_req->client_name)) {
			strlcpy(adptr->name,
				frntnd_msg->register_req->client_name,
				sizeof(adptr->name));
			mgmt_frntnd_adapter_cleanup_old_conn(adptr);
		}
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_SESSN_REQ:
		if (frntnd_msg->sessn_req->create
		    && frntnd_msg->sessn_req->id_case
			== MGMTD__FRNTND_SESSION_REQ__ID_CLIENT_CONN_ID) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Got Session Create Req Msg for client-id %llu from '%s'",
				(unsigned long long)
					frntnd_msg->sessn_req->client_conn_id,
				adptr->name);

			sessn = mgmt_frntnd_create_session(
				adptr, frntnd_msg->sessn_req->client_conn_id);
			mgmt_frntnd_send_session_reply(adptr, sessn, true,
						       sessn ? true : false);
		} else if (
			!frntnd_msg->sessn_req->create
			&& frntnd_msg->sessn_req->id_case
				== MGMTD__FRNTND_SESSION_REQ__ID_SESSION_ID) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Got Session Destroy Req Msg for session-id %llu from '%s'",
				(unsigned long long)
					frntnd_msg->sessn_req->session_id,
				adptr->name);

			sessn = mgmt_session_id2ctxt(
				frntnd_msg->sessn_req->session_id);
			mgmt_frntnd_send_session_reply(adptr, sessn, false,
						       true);
			mgmt_frntnd_cleanup_session(&sessn);
		}
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REQ:
		sessn = mgmt_session_id2ctxt(
				frntnd_msg->lockdb_req->session_id);
		MGMTD_FRNTND_ADPTR_DBG(
			"Got %sockDB Req Msg for DB:%d for session-id %llx from '%s'",
			frntnd_msg->lockdb_req->lock ? "L" : "Unl",
			frntnd_msg->lockdb_req->db_id,
			(unsigned long long)frntnd_msg->lockdb_req->session_id,
			adptr->name);
		mgmt_frntnd_session_handle_lockdb_req_msg(
			sessn, frntnd_msg->lockdb_req);
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_SETCFG_REQ:
		sessn = mgmt_session_id2ctxt(
				frntnd_msg->setcfg_req->session_id);
		sessn->adptr->setcfg_stats.set_cfg_count++;
		MGMTD_FRNTND_ADPTR_DBG(
			"Got Set Config Req Msg (%d Xpaths) on DB:%d for session-id %llu from '%s'",
			(int)frntnd_msg->setcfg_req->n_data,
			frntnd_msg->setcfg_req->db_id,
			(unsigned long long)frntnd_msg->setcfg_req->session_id,
			adptr->name);

		mgmt_frntnd_session_handle_setcfg_req_msg(
			sessn, frntnd_msg->setcfg_req);
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REQ:
		sessn = mgmt_session_id2ctxt(
				frntnd_msg->commcfg_req->session_id);
		MGMTD_FRNTND_ADPTR_DBG(
			"Got Commit Config Req Msg for src-DB:%d dst-DB:%d on session-id %llu from '%s'",
			frntnd_msg->commcfg_req->src_db_id,
			frntnd_msg->commcfg_req->dst_db_id,
			(unsigned long long)frntnd_msg->commcfg_req->session_id,
			adptr->name);
		mgmt_frntnd_session_handle_commit_config_req_msg(
			sessn, frntnd_msg->commcfg_req);
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_GETCFG_REQ:
		sessn = mgmt_session_id2ctxt(
				frntnd_msg->getcfg_req->session_id);
		MGMTD_FRNTND_ADPTR_DBG(
			"Got Get-Config Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'",
			frntnd_msg->getcfg_req->db_id,
			(int)frntnd_msg->getcfg_req->n_data,
			(unsigned long long)frntnd_msg->getcfg_req->session_id,
			adptr->name);
		mgmt_frntnd_session_handle_getcfg_req_msg(
			sessn, frntnd_msg->getcfg_req);
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_GETDATA_REQ:
		sessn = mgmt_session_id2ctxt(
				frntnd_msg->getdata_req->session_id);
		MGMTD_FRNTND_ADPTR_DBG(
			"Got Get-Data Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'",
			frntnd_msg->getdata_req->db_id,
			(int)frntnd_msg->getdata_req->n_data,
			(unsigned long long)frntnd_msg->getdata_req->session_id,
			adptr->name);
		mgmt_frntnd_session_handle_getdata_req_msg(
			sessn, frntnd_msg->getdata_req);
		break;
	case MGMTD__FRNTND_MESSAGE__MESSAGE_NOTIFY_DATA_REQ:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_REGNOTIFY_REQ:
		/*
		 * TODO: Add handling code in future.
		 */
		break;
	/*
	 * NOTE: The following messages are always sent from MGMTD to
	 * Frontend clients only and/or need not be handled on MGMTd.
	 */
	case MGMTD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE_GETDATA_REPLY:
	case MGMTD__FRNTND_MESSAGE__MESSAGE__NOT_SET:
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
mgmt_frntnd_adapter_process_msg(struct mgmt_frntnd_client_adapter *adptr,
				uint8_t *msg_buf, uint16_t bytes_read)
{
	Mgmtd__FrntndMessage *frntnd_msg;
	struct mgmt_frntnd_msg *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	MGMTD_FRNTND_ADPTR_DBG(
		"Have %u bytes of messages from client '%s' to process",
		bytes_read, adptr->name);

	bytes_left = bytes_read;
	for (; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN;
	     bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (struct mgmt_frntnd_msg *)msg_buf;
		if (msg->hdr.marker != MGMTD_FRNTND_MSG_MARKER) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Marker not found in message from MGMTD Frontend adapter '%s'",
				adptr->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD Frontend adapter '%s'",
				bytes_left, msg->hdr.len, adptr->name);
			break;
		}

		frntnd_msg = mgmtd__frntnd_message__unpack(
			NULL, (size_t)(msg->hdr.len - MGMTD_FRNTND_MSG_HDR_LEN),
			msg->payload);
		if (!frntnd_msg) {
			MGMTD_FRNTND_ADPTR_DBG(
				"Failed to decode %d bytes from MGMTD Frontend adapter '%s'",
				msg->hdr.len, adptr->name);
			continue;
		}

		MGMTD_FRNTND_ADPTR_DBG(
			"Decoded %d bytes of message(msg: %u/%u) from MGMTD Frontend adapter '%s'",
			msg->hdr.len, frntnd_msg->message_case,
			frntnd_msg->message_case, adptr->name);

		(void)mgmt_frntnd_adapter_handle_msg(adptr, frntnd_msg);

		mgmtd__frntnd_message__free_unpacked(frntnd_msg, NULL);
		processed++;
		adptr->num_msg_rx++;
	}

	return processed;
}

static void mgmt_frntnd_adapter_proc_msgbufs(struct thread *thread)
{
	struct mgmt_frntnd_client_adapter *adptr;
	struct stream *work;
	int processed = 0;

	adptr = (struct mgmt_frntnd_client_adapter *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	MGMTD_FRNTND_ADPTR_DBG("Have %d ibufs for client '%s' to process",
			       (int)stream_fifo_count_safe(adptr->ibuf_fifo),
			       adptr->name);

	for (; processed < MGMTD_FRNTND_MAX_NUM_MSG_PROC;) {
		work = stream_fifo_pop_safe(adptr->ibuf_fifo);
		if (!work)
			break;

		processed += mgmt_frntnd_adapter_process_msg(
			adptr, STREAM_DATA(work), stream_get_endp(work));

		if (work != adptr->ibuf_work) {
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
	if (stream_fifo_head(adptr->ibuf_fifo))
		mgmt_frntnd_adptr_register_event(adptr, MGMTD_FRNTND_PROC_MSG);
}

static void mgmt_frntnd_adapter_read(struct thread *thread)
{
	struct mgmt_frntnd_client_adapter *adptr;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	struct mgmt_frntnd_msg_hdr *msg_hdr;
	bool incomplete = false;

	adptr = (struct mgmt_frntnd_client_adapter *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adptr->ibuf_work)
		     - stream_get_endp(adptr->ibuf_work);
	for (; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN;) {
		bytes_read = stream_read_try(adptr->ibuf_work, adptr->conn_fd,
					     bytes_left);
		MGMTD_FRNTND_ADPTR_DBG(
			"Got %d bytes of message from MGMTD Frontend adapter '%s'",
			bytes_read, adptr->name);
		if (bytes_read <= 0) {
			if (bytes_read == -1
			    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				mgmt_frntnd_adptr_register_event(
					adptr, MGMTD_FRNTND_CONN_READ);
				return;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				MGMTD_FRNTND_ADPTR_ERR(
					"Got error (%d) while reading from MGMTD Frontend adapter '%s'. Err: '%s'",
					bytes_read, adptr->name,
					safe_strerror(errno));
				mgmt_frntnd_adapter_disconnect(adptr);
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
	stream_set_getp(adptr->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(adptr->ibuf_work);
	for (; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN;) {
		msg_hdr =
			(struct mgmt_frntnd_msg_hdr *)(STREAM_DATA(
							       adptr->ibuf_work)
						       + total_bytes);
		if (msg_hdr->marker != MGMTD_FRNTND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_FRNTND_ADPTR_ERR(
				"Received corrupted buffer from MGMTD frontend client.");
			mgmt_frntnd_adapter_disconnect(adptr);
			return;
		}
		if (msg_hdr->len > bytes_left)
			break;

		MGMTD_FRNTND_ADPTR_DBG("Got message (len: %u) from client '%s'",
				       msg_hdr->len, adptr->name);

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
	msg_hdr = (struct mgmt_frntnd_msg_hdr *)(STREAM_DATA(adptr->ibuf_work)
						 + total_bytes);
	stream_set_endp(adptr->ibuf_work, total_bytes);
	stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
	adptr->ibuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(adptr->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(adptr->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		mgmt_frntnd_adptr_register_event(adptr, MGMTD_FRNTND_PROC_MSG);

	mgmt_frntnd_adptr_register_event(adptr, MGMTD_FRNTND_CONN_READ);
}

static void mgmt_frntnd_adapter_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	struct mgmt_frntnd_client_adapter *adptr;

	adptr = (struct mgmt_frntnd_client_adapter *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (adptr->obuf_work) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = NULL;
	}

	for (s = stream_fifo_head(adptr->obuf_fifo);
	     s && processed < MGMTD_FRNTND_MAX_NUM_MSG_WRITE;
	     s = stream_fifo_head(adptr->obuf_fifo)) {
		/* msg_size = (int)stream_get_size(s); */
		msg_size = (int)STREAM_READABLE(s);
		bytes_written = stream_flush(s, adptr->conn_fd);
		if (bytes_written == -1
		    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_frntnd_adptr_register_event(
				adptr, MGMTD_FRNTND_CONN_WRITE);
			return;
		} else if (bytes_written != msg_size) {
			MGMTD_FRNTND_ADPTR_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Frontend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_frntnd_adptr_register_event(
					adptr, MGMTD_FRNTND_CONN_WRITE);
				return;
			}
			mgmt_frntnd_adapter_disconnect(adptr);
			return;
		}

		free = stream_fifo_pop(adptr->obuf_fifo);
		stream_free(free);
		MGMTD_FRNTND_ADPTR_DBG(
			"Wrote %d bytes of message to MGMTD Frontend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_frntnd_adapter_writes_off(adptr);
		mgmt_frntnd_adptr_register_event(adptr,
						 MGMTD_FRNTND_CONN_WRITES_ON);
	}
}

static void mgmt_frntnd_adapter_resume_writes(struct thread *thread)
{
	struct mgmt_frntnd_client_adapter *adptr;

	adptr = (struct mgmt_frntnd_client_adapter *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	mgmt_frntnd_adapter_writes_on(adptr);
}

static void
mgmt_frntnd_adptr_register_event(struct mgmt_frntnd_client_adapter *adptr,
				 enum mgmt_frntnd_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_FRNTND_CONN_READ:
		thread_add_read(mgmt_frntnd_adptr_tm, mgmt_frntnd_adapter_read,
				adptr, adptr->conn_fd, &adptr->conn_read_ev);
		assert(adptr->conn_read_ev);
		break;
	case MGMTD_FRNTND_CONN_WRITE:
		thread_add_write(mgmt_frntnd_adptr_tm,
				 mgmt_frntnd_adapter_write, adptr,
				 adptr->conn_fd, &adptr->conn_write_ev);
		assert(adptr->conn_write_ev);
		break;
	case MGMTD_FRNTND_PROC_MSG:
		tv.tv_usec = MGMTD_FRNTND_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(mgmt_frntnd_adptr_tm,
				    mgmt_frntnd_adapter_proc_msgbufs, adptr,
				    &tv, &adptr->proc_msg_ev);
		assert(adptr->proc_msg_ev);
		break;
	case MGMTD_FRNTND_CONN_WRITES_ON:
		thread_add_timer_msec(mgmt_frntnd_adptr_tm,
				      mgmt_frntnd_adapter_resume_writes, adptr,
				      MGMTD_FRNTND_MSG_WRITE_DELAY_MSEC,
				      &adptr->conn_writes_on);
		assert(adptr->conn_writes_on);
		break;
	case MGMTD_FRNTND_SERVER:
		assert(!"mgmt_frntnd_adptr_post_event() called incorrectly");
		break;
	}
}

void mgmt_frntnd_adapter_lock(struct mgmt_frntnd_client_adapter *adptr)
{
	adptr->refcount++;
}

extern void
mgmt_frntnd_adapter_unlock(struct mgmt_frntnd_client_adapter **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		mgmt_frntnd_adptr_list_del(&mgmt_frntnd_adptrs, *adptr);

		stream_fifo_free((*adptr)->ibuf_fifo);
		stream_free((*adptr)->ibuf_work);
		stream_fifo_free((*adptr)->obuf_fifo);
		stream_free((*adptr)->obuf_work);

		THREAD_OFF((*adptr)->conn_read_ev);
		THREAD_OFF((*adptr)->conn_write_ev);
		THREAD_OFF((*adptr)->proc_msg_ev);
		THREAD_OFF((*adptr)->conn_writes_on);
		XFREE(MTYPE_MGMTD_FRNTND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int mgmt_frntnd_adapter_init(struct thread_master *tm, struct mgmt_master *mm)
{
	if (!mgmt_frntnd_adptr_tm) {
		mgmt_frntnd_adptr_tm = tm;
		mgmt_frntnd_adptr_mm = mm;
		mgmt_frntnd_adptr_list_init(&mgmt_frntnd_adptrs);

		assert(!mgmt_frntnd_sessns);
		mgmt_frntnd_sessns =
			hash_create(mgmt_frntnd_sessn_hash_key,
				    mgmt_frntnd_sessn_hash_cmp,
				    "MGMT Frontend Sessions");
	}

	return 0;
}

void mgmt_frntnd_adapter_destroy(void)
{
	mgmt_frntnd_cleanup_adapters();
	mgmt_frntnd_sessn_hash_destroy();
}

struct mgmt_frntnd_client_adapter *
mgmt_frntnd_create_adapter(int conn_fd, union sockunion *from)
{
	struct mgmt_frntnd_client_adapter *adptr = NULL;

	adptr = mgmt_frntnd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XCALLOC(MTYPE_MGMTD_FRNTND_ADPATER,
				sizeof(struct mgmt_frntnd_client_adapter));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d",
			 adptr->conn_fd);
		mgmt_frntnd_sessn_list_init(&adptr->frntnd_sessns);
		adptr->ibuf_fifo = stream_fifo_new();
		adptr->ibuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
		adptr->obuf_fifo = stream_fifo_new();
		/* adptr->obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN); */
		adptr->obuf_work = NULL;
		mgmt_frntnd_adapter_lock(adptr);

		mgmt_frntnd_adptr_register_event(adptr, MGMTD_FRNTND_CONN_READ);
		mgmt_frntnd_adptr_list_add_tail(&mgmt_frntnd_adptrs, adptr);

		adptr->setcfg_stats.min_tm = ULONG_MAX;
		adptr->cmt_stats.min_tm = ULONG_MAX;
		MGMTD_FRNTND_ADPTR_DBG("Added new MGMTD Frontend adapter '%s'",
				       adptr->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adptr->conn_fd);
	setsockopt_so_sendbuf(adptr->conn_fd,
			      MGMTD_SOCKET_FRNTND_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(adptr->conn_fd,
			      MGMTD_SOCKET_FRNTND_RECV_BUF_SIZE);
	return adptr;
}

struct mgmt_frntnd_client_adapter *mgmt_frntnd_get_adapter(const char *name)
{
	return mgmt_frntnd_find_adapter_by_name(name);
}

int mgmt_frntnd_send_set_cfg_reply(uint64_t session_id, uint64_t trxn_id,
				   Mgmtd__DatabaseId db_id, uint64_t req_id,
				   enum mgmt_result result,
				   const char *error_if_any,
				   bool implicit_commit)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || sessn->cfg_trxn_id != trxn_id) {
		if (sessn)
			MGMTD_FRNTND_ADPTR_ERR(
				"Trxn_id doesnot match, session trxn is 0x%llx, current trxn 0x%llx",
				(unsigned long long)sessn->cfg_trxn_id,
				(unsigned long long)trxn_id);
		return -1;
	}

	return mgmt_frntnd_send_setcfg_reply(
		sessn, db_id, req_id, result == MGMTD_SUCCESS ? true : false,
		error_if_any, implicit_commit);
}

int mgmt_frntnd_send_commit_cfg_reply(uint64_t session_id, uint64_t trxn_id,
				      Mgmtd__DatabaseId src_db_id,
				      Mgmtd__DatabaseId dst_db_id,
				      uint64_t req_id, bool validate_only,
				      enum mgmt_result result,
				      const char *error_if_any)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || sessn->cfg_trxn_id != trxn_id)
		return -1;

	return mgmt_frntnd_send_commitcfg_reply(sessn, src_db_id, dst_db_id,
						req_id, result, validate_only,
						error_if_any);
}

int mgmt_frntnd_send_get_cfg_reply(uint64_t session_id, uint64_t trxn_id,
				   Mgmtd__DatabaseId db_id, uint64_t req_id,
				   enum mgmt_result result,
				   Mgmtd__YangDataReply *data_resp,
				   const char *error_if_any)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || sessn->trxn_id != trxn_id)
		return -1;

	return mgmt_frntnd_send_getcfg_reply(sessn, db_id, req_id,
					     result == MGMTD_SUCCESS, data_resp,
					     error_if_any);
}

int mgmt_frntnd_send_get_data_reply(uint64_t session_id, uint64_t trxn_id,
				    Mgmtd__DatabaseId db_id, uint64_t req_id,
				    enum mgmt_result result,
				    Mgmtd__YangDataReply *data_resp,
				    const char *error_if_any)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || sessn->trxn_id != trxn_id)
		return -1;

	return mgmt_frntnd_send_getdata_reply(sessn, db_id, req_id,
					      result == MGMTD_SUCCESS,
					      data_resp, error_if_any);
}

int mgmt_frntnd_send_data_notify(Mgmtd__DatabaseId db_id,
				 Mgmtd__YangData * data_resp[], int num_data)
{
	/* struct mgmt_frntnd_sessn_ctxt *sessn; */

	return 0;
}

struct mgmt_setcfg_stats *
mgmt_frntnd_get_sessn_setcfg_stats(uint64_t session_id)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || !sessn->adptr)
		return NULL;

	return &sessn->adptr->setcfg_stats;
}

struct mgmt_commit_stats *
mgmt_frntnd_get_sessn_commit_stats(uint64_t session_id)
{
	struct mgmt_frntnd_sessn_ctxt *sessn;

	sessn = mgmt_session_id2ctxt(session_id);
	if (!sessn || !sessn->adptr)
		return NULL;

	return &sessn->adptr->cmt_stats;
}

static void
mgmt_frntnd_adapter_cmt_stats_write(struct vty *vty,
				    struct mgmt_frntnd_client_adapter *adptr)
{
	char buf[100] = {0};

	if (!mm->perf_stats_en)
		return;

	vty_out(vty, "    Num-Commits: \t\t\t%lu\n",
		adptr->cmt_stats.commit_cnt);
	if (adptr->cmt_stats.commit_cnt > 0) {
		if (mm->perf_stats_en)
			vty_out(vty, "    Max-Commit-Duration: \t\t%lu uSecs\n",
				adptr->cmt_stats.max_tm);
		vty_out(vty, "    Max-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.max_batch_cnt);
		if (mm->perf_stats_en)
			vty_out(vty, "    Min-Commit-Duration: \t\t%lu uSecs\n",
				adptr->cmt_stats.min_tm);
		vty_out(vty, "    Min-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.min_batch_cnt);
		if (mm->perf_stats_en)
			vty_out(vty,
				"    Last-Commit-Duration: \t\t%lu uSecs\n",
				adptr->cmt_stats.last_exec_tm);
		vty_out(vty, "    Last-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.last_batch_cnt);
		vty_out(vty, "    Last-Commit-CfgData-Reqs: \t\t%lu\n",
			adptr->cmt_stats.last_num_cfgdata_reqs);
		vty_out(vty, "    Last-Commit-CfgApply-Reqs: \t\t%lu\n",
			adptr->cmt_stats.last_num_apply_reqs);
		if (mm->perf_stats_en) {
			vty_out(vty, "    Last-Commit-Details:\n");
			vty_out(vty, "      Commit Start: \t\t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.last_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Config-Validate Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.validate_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Prep-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.prep_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Trxn-Create Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.trxn_create_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Send-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.send_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Apply-Config Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.apply_cfg_start, buf,
					sizeof(buf)));
			vty_out(vty, "        Apply-Config End: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.apply_cfg_end, buf,
					sizeof(buf)));
			vty_out(vty, "        Trxn-Delete Start: \t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.trxn_del_start, buf,
					sizeof(buf)));
			vty_out(vty, "      Commit End: \t\t\t%s\n",
				mgmt_realtime_to_string(
					&adptr->cmt_stats.last_end, buf,
					sizeof(buf)));
		}
	}
}

static void
mgmt_frntnd_adapter_setcfg_stats_write(struct vty *vty,
				       struct mgmt_frntnd_client_adapter *adptr)
{
	char buf[100] = {0};

	if (!mm->perf_stats_en)
		return;

	vty_out(vty, "    Num-Set-Cfg: \t\t\t%lu\n",
		adptr->setcfg_stats.set_cfg_count);
	if (mm->perf_stats_en && adptr->setcfg_stats.set_cfg_count > 0) {
		vty_out(vty, "    Max-Set-Cfg-Duration: \t\t%lu uSec\n",
			adptr->setcfg_stats.max_tm);
		vty_out(vty, "    Min-Set-Cfg-Duration: \t\t%lu uSec\n",
			adptr->setcfg_stats.min_tm);
		vty_out(vty, "    Avg-Set-Cfg-Duration: \t\t%lu uSec\n",
			adptr->setcfg_stats.avg_tm);
		vty_out(vty, "    Last-Set-Cfg-Details:\n");
		vty_out(vty, "      Set-Cfg Start: \t\t\t%s\n",
			mgmt_realtime_to_string(&adptr->setcfg_stats.last_start,
						buf, sizeof(buf)));
		vty_out(vty, "      Set-Cfg End: \t\t\t%s\n",
			mgmt_realtime_to_string(&adptr->setcfg_stats.last_end,
						buf, sizeof(buf)));
	}
}

void mgmt_frntnd_adapter_status_write(struct vty *vty, bool detail)
{
	struct mgmt_frntnd_client_adapter *adptr;
	struct mgmt_frntnd_sessn_ctxt *sessn;
	Mgmtd__DatabaseId db_id;
	bool locked = false;

	vty_out(vty, "MGMTD Frontend Adpaters\n");

	FOREACH_ADPTR_IN_LIST (adptr) {
		vty_out(vty, "  Client: \t\t\t\t%s\n", adptr->name);
		vty_out(vty, "    Conn-FD: \t\t\t\t%d\n", adptr->conn_fd);
		if (detail) {
			mgmt_frntnd_adapter_setcfg_stats_write(vty, adptr);
			mgmt_frntnd_adapter_cmt_stats_write(vty, adptr);
		}
		vty_out(vty, "    Sessions\n");
		FOREACH_SESSN_IN_LIST (adptr, sessn) {
			vty_out(vty, "      Session: \t\t\t\t%p\n", sessn);
			vty_out(vty, "        Client-Id: \t\t\t%llu\n",
				(unsigned long long)sessn->client_id);
			vty_out(vty, "        Session-Id: \t\t\t%llx\n",
				(unsigned long long)sessn->session_id);
			vty_out(vty, "        DB-Locks:\n");
			FOREACH_MGMTD_DB_ID (db_id) {
				if (sessn->db_write_locked[db_id]
				    || sessn->db_read_locked[db_id]) {
					locked = true;
					vty_out(vty,
						"          %s\t\t\t%s, %s\n",
						mgmt_db_id2name(db_id),
						sessn->db_write_locked[db_id]
							? "Write"
							: "Read",
						sessn->db_locked_implict[db_id]
							? "Implicit"
							: "Explicit");
				}
			}
			if (!locked)
				vty_out(vty, "          None\n");
		}
		vty_out(vty, "    Total-Sessions: \t\t\t%d\n",
			(int)mgmt_frntnd_sessn_list_count(
				&adptr->frntnd_sessns));
		vty_out(vty, "    Msg-Sent: \t\t\t\t%u\n", adptr->num_msg_tx);
		vty_out(vty, "    Msg-Recvd: \t\t\t\t%u\n", adptr->num_msg_rx);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_frntnd_adptr_list_count(&mgmt_frntnd_adptrs));
}

void mgmt_frntnd_adapter_perf_measurement(struct vty *vty, bool config)
{
	mm->perf_stats_en = config;
}

void mgmt_frntnd_adapter_reset_perf_stats(struct vty *vty)
{
	struct mgmt_frntnd_client_adapter *adptr;
	struct mgmt_frntnd_sessn_ctxt *sessn;

	FOREACH_ADPTR_IN_LIST (adptr) {
		memset(&adptr->setcfg_stats, 0, sizeof(adptr->setcfg_stats));
		FOREACH_SESSN_IN_LIST (adptr, sessn) {
			memset(&adptr->cmt_stats, 0, sizeof(adptr->cmt_stats));
		}
	}
}
