/*
 * CMGD Frontend Client Connection Adapter
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

#include "thread.h"
#include "sockopt.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_frntnd_client.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_FRNTND_ADPTR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_ADPTR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_FRNTND_ADPTR_DBG(fmt, ...)				\
	if (cmgd_debug_frntnd)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_ADPTR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)							\
	for ((adptr) = cmgd_frntnd_adptr_list_first(&cmgd_frntnd_adptrs); (adptr);	\
		(adptr) = cmgd_frntnd_adptr_list_next(&cmgd_frntnd_adptrs, (adptr)))

typedef enum cmgd_sessn_event_ {
	CMGD_FRNTND_SESSN_CFG_TRXN_CLNUP = 1,
	CMGD_FRNTND_SESSN_SHOW_TRXN_CLNUP,
} cmgd_sessn_event_t;

typedef struct cmgd_frntnd_sessn_ctxt_ {
	struct cmgd_frntnd_client_adapter_ *adptr;
        cmgd_client_id_t client_id;
	cmgd_trxn_id_t	trxn_id;
	cmgd_trxn_id_t	cfg_trxn_id;
	uint8_t db_write_locked[CMGD_DB_MAX_ID];
	uint8_t db_read_locked[CMGD_DB_MAX_ID];
	uint8_t db_locked_implict[CMGD_DB_MAX_ID];
        struct thread *proc_cfg_trxn_clnp;
        struct thread *proc_show_trxn_clnp;

	struct cmgd_frntnd_sessn_list_item list_linkage;
} cmgd_frntnd_sessn_ctxt_t;

DECLARE_LIST(cmgd_frntnd_sessn_list, cmgd_frntnd_sessn_ctxt_t, list_linkage);

#define FOREACH_SESSN_IN_LIST(adptr, sessn)						\
	for ((sessn) = cmgd_frntnd_sessn_list_first(&(adptr)->frntnd_sessns); (sessn);	\
		(sessn) = cmgd_frntnd_sessn_list_next(&(adptr)->frntnd_sessns, (sessn)))

#define FOREACH_SESSN_IN_LIST_SAFE(adptr, sessn)					\
	frr_each_safe(cmgd_frntnd_sessn_list, &(adptr)->frntnd_sessns, (sessn))

static struct thread_master *cmgd_frntnd_adptr_tm = NULL;
static struct cmgd_master *cmgd_frntnd_adptr_cm = NULL;

static struct cmgd_frntnd_adptr_list_head cmgd_frntnd_adptrs = {0};

/* Forward declarations */
static void cmgd_frntnd_adptr_register_event(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_event_t event);
static void cmgd_frntnd_adapter_disconnect(
	cmgd_frntnd_client_adapter_t *adptr);
static void cmgd_frntnd_session_register_event(
	cmgd_frntnd_sessn_ctxt_t *sessn, cmgd_sessn_event_t event);

static int cmgd_frntnd_session_write_lock_db(
	cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
	cmgd_frntnd_sessn_ctxt_t *sessn)
{
	if (!sessn->db_write_locked[db_id]) { 
		if (cmgd_db_write_lock(db_hndl) != 0) {
			CMGD_FRNTND_ADPTR_DBG("Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		sessn->db_write_locked[db_id] = true;
		CMGD_FRNTND_ADPTR_DBG("Write-Locked the DB %u for Sessn: %p from %s!",
			db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static int cmgd_frntnd_session_read_lock_db(
	cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
	cmgd_frntnd_sessn_ctxt_t *sessn)
{
	if (!sessn->db_read_locked[db_id]) { 
		if (cmgd_db_read_lock(db_hndl) != 0) {
			CMGD_FRNTND_ADPTR_DBG("Failed to lock the DB %u for Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		sessn->db_read_locked[db_id] = true;
		CMGD_FRNTND_ADPTR_DBG("Read-Locked the DB %u for Sessn: %p from %s!",
			db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static int cmgd_frntnd_session_unlock_db(
	cmgd_database_id_t db_id, cmgd_db_hndl_t db_hndl,
	cmgd_frntnd_sessn_ctxt_t *sessn, bool unlock_write, bool unlock_read)
{
	if (unlock_write && sessn->db_write_locked[db_id]) {
		sessn->db_write_locked[db_id] = false;
		sessn->db_locked_implict[db_id] = false;
		if (cmgd_db_unlock(db_hndl) != 0) {
			CMGD_FRNTND_ADPTR_DBG("Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		CMGD_FRNTND_ADPTR_DBG("Unlocked DB %u write-locked earlier by Sessn: %p from %s",
			db_id, sessn, sessn->adptr->name);
	} else if (unlock_read && sessn->db_read_locked[db_id]) { 
		sessn->db_read_locked[db_id] = false;
		sessn->db_locked_implict[db_id] = false;
		if (cmgd_db_unlock(db_hndl) != 0) {
			CMGD_FRNTND_ADPTR_DBG("Failed to unlock the DB %u taken earlier by Sessn: %p from %s!",
				db_id, sessn, sessn->adptr->name);
			return -1;
		}

		CMGD_FRNTND_ADPTR_DBG("Unlocked DB %u read-locked earlier by Sessn: %p from %s",
			db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static void cmgd_frntnd_sessn_cfg_trxn_cleanup(cmgd_frntnd_sessn_ctxt_t *sessn)
{
	cmgd_database_id_t db_id;
	cmgd_db_hndl_t db_hndl;

	for (db_id = 0; db_id < CMGD_DB_MAX_ID; db_id++) {
		db_hndl = cmgd_db_get_hndl_by_id(cmgd_frntnd_adptr_cm, db_id);
		if (db_hndl) {
			if (sessn->db_locked_implict[db_id])
				cmgd_frntnd_session_unlock_db(db_id, db_hndl, sessn,
					true, false);
		}
	}

	if (sessn->cfg_trxn_id != CMGD_TRXN_ID_NONE)
		cmgd_destroy_trxn(&sessn->cfg_trxn_id);
}

static void cmgd_frntnd_sessn_show_trxn_cleanup(cmgd_frntnd_sessn_ctxt_t *sessn)
{
	cmgd_database_id_t db_id;
	cmgd_db_hndl_t db_hndl;

	for (db_id = 0; db_id < CMGD_DB_MAX_ID; db_id++) {
		db_hndl = cmgd_db_get_hndl_by_id(cmgd_frntnd_adptr_cm, db_id);
		if (db_hndl) {
			cmgd_frntnd_session_unlock_db(db_id, db_hndl, sessn,
				false, true);
		}
	}

	if (sessn->trxn_id != CMGD_TRXN_ID_NONE)
		cmgd_destroy_trxn(&sessn->trxn_id);
}

static void cmgd_frntnd_adptr_compute_set_cfg_timers(
		cmgd_setcfg_stats_t *setcfg_stats)
{
	setcfg_stats->last_exec_tm = timeval_elapsed(setcfg_stats->last_end,
						setcfg_stats->last_start);
	if (setcfg_stats->last_exec_tm > setcfg_stats->max_tm)
		setcfg_stats->max_tm = setcfg_stats->last_exec_tm;

	if (setcfg_stats->last_exec_tm < setcfg_stats->min_tm)
		setcfg_stats->min_tm = setcfg_stats->last_exec_tm;

	setcfg_stats->avg_tm = (((setcfg_stats->avg_tm * 
			       		(setcfg_stats->set_cfg_count - 1)) +
					setcfg_stats->last_exec_tm) /
					setcfg_stats->set_cfg_count);
}

static void cmgd_frntnd_sessn_compute_commit_timers(
		cmgd_commit_stats_t *cmt_stats)
{
	cmt_stats->last_exec_tm = timeval_elapsed(cmt_stats->last_end,
					cmt_stats->last_start);
	if (cmt_stats->last_exec_tm > cmt_stats->max_tm) {
		cmt_stats->max_tm = cmt_stats->last_exec_tm;
		cmt_stats->max_batch_cnt = cmt_stats->last_batch_cnt;
	}

	if (cmt_stats->last_exec_tm < cmt_stats->min_tm) {
		cmt_stats->min_tm = cmt_stats->last_exec_tm;
		cmt_stats->min_batch_cnt = cmt_stats->last_batch_cnt;
	}
}

static void cmgd_frntnd_cleanup_session(cmgd_frntnd_sessn_ctxt_t **sessn)
{
	if ((*sessn)->adptr) {
		cmgd_frntnd_sessn_cfg_trxn_cleanup((*sessn));
		cmgd_frntnd_sessn_show_trxn_cleanup((*sessn));

		cmgd_frntnd_sessn_list_del(&(*sessn)->adptr->frntnd_sessns, *sessn);
		cmgd_frntnd_adapter_unlock(&(*sessn)->adptr);
	}

	XFREE(MTYPE_CMGD_FRNTND_SESSN, *sessn);
	*sessn = NULL;
}

static cmgd_frntnd_sessn_ctxt_t *cmgd_frntnd_find_session_by_id(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_client_id_t client_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	FOREACH_SESSN_IN_LIST(adptr, sessn) {
		if (sessn->client_id == client_id)
			return sessn;
	}

	return NULL;
}

static cmgd_frntnd_sessn_ctxt_t *cmgd_frntnd_create_session(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_client_id_t client_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = cmgd_frntnd_find_session_by_id(adptr, client_id);
	if (sessn) {
		cmgd_frntnd_cleanup_session(&sessn);
	}

	sessn = XCALLOC(MTYPE_CMGD_FRNTND_SESSN, sizeof(cmgd_frntnd_sessn_ctxt_t));
	assert(sessn);
	sessn->client_id = client_id;
	sessn->adptr = adptr;
	sessn->trxn_id = CMGD_TRXN_ID_NONE;
	sessn->cfg_trxn_id = CMGD_TRXN_ID_NONE;
	cmgd_frntnd_adapter_lock(adptr);
	adptr->cmt_stats.min_tm = ULONG_MAX;
	cmgd_frntnd_sessn_list_add_tail(&adptr->frntnd_sessns, sessn);

	return sessn;
}

static void cmgd_frntnd_cleanup_sessions(cmgd_frntnd_client_adapter_t *adptr)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	FOREACH_SESSN_IN_LIST_SAFE(adptr, sessn) {
		cmgd_frntnd_cleanup_session(&sessn);
	}
}

static inline void cmgd_frntnd_adapter_sched_msg_write(cmgd_frntnd_client_adapter_t *adptr)
{
	if (!CHECK_FLAG(adptr->flags, CMGD_FRNTND_ADPTR_FLAGS_WRITES_OFF))
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_WRITE);
}

static inline void cmgd_frntnd_adapter_writes_on(cmgd_frntnd_client_adapter_t *adptr)
{
	CMGD_FRNTND_ADPTR_DBG("Resume writing msgs for '%s'", adptr->name);
	UNSET_FLAG(adptr->flags, CMGD_FRNTND_ADPTR_FLAGS_WRITES_OFF);
	if (adptr->obuf_work || stream_fifo_count_safe(adptr->obuf_fifo))
		cmgd_frntnd_adapter_sched_msg_write(adptr);
}

static inline void cmgd_frntnd_adapter_writes_off(cmgd_frntnd_client_adapter_t *adptr)
{
	SET_FLAG(adptr->flags, CMGD_FRNTND_ADPTR_FLAGS_WRITES_OFF);
	CMGD_FRNTND_ADPTR_DBG("Paused writing msgs for '%s'", adptr->name);
}

static int cmgd_frntnd_adapter_send_msg(cmgd_frntnd_client_adapter_t *adptr, 
	Cmgd__FrntndMessage *frntnd_msg)
{
	size_t msg_size;
	uint8_t msg_buf[CMGD_FRNTND_MSG_MAX_LEN];
	cmgd_frntnd_msg_t *msg;

	if (adptr->conn_fd == 0) {
		CMGD_FRNTND_ADPTR_ERR("Connection already reset");
		return -1;
	}

	msg_size = cmgd__frntnd_message__get_packed_size(frntnd_msg);
	msg_size += CMGD_FRNTND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_FRNTND_ADPTR_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_frntnd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_FRNTND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__frntnd_message__pack(frntnd_msg, msg->payload);

#ifndef CMGD_PACK_TX_MSGS
	adptr->obuf_work = stream_new(msg_size);
	stream_write(adptr->obuf_work, (void *)msg_buf, msg_size);
	stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
	adptr->obuf_work = NULL;
#else
	if (!adptr->obuf_work)
		adptr->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(adptr->obuf_work) < msg_size) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	}
	stream_write(adptr->obuf_work, (void *)msg_buf, msg_size);
#endif
	cmgd_frntnd_adapter_sched_msg_write(adptr);
	adptr->num_msg_tx++;
	return 0;
}

static int cmgd_frntnd_send_session_reply(cmgd_frntnd_client_adapter_t *adptr,
	cmgd_frntnd_sessn_ctxt_t *sessn, bool create, bool success)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSessionReply sessn_reply;

	cmgd__frntnd_session_reply__init(&sessn_reply);
	sessn_reply.create = create;
	if (create) {
		sessn_reply.has_client_conn_id = 1;
		sessn_reply.client_conn_id = sessn->client_id;
	}
	sessn_reply.session_id = (uint64_t) sessn;
	sessn_reply.success = success;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SESSION_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY;
	frntnd_msg.sessn_reply = &sessn_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending SESSION_REPLY message to CMGD Frontend client '%s'",
		adptr->name);

	return cmgd_frntnd_adapter_send_msg(adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_lockdb_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t db_id, cmgd_client_req_id_t req_id, bool lock_db,
	bool success, const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndLockDbReply lockdb_reply;

	assert(sessn->adptr);

	cmgd__frntnd_lock_db_reply__init(&lockdb_reply);
	lockdb_reply.session_id = (uint64_t) sessn;
	lockdb_reply.db_id = db_id;
	lockdb_reply.req_id = req_id;
	lockdb_reply.lock = lock_db;
	lockdb_reply.success = success;
	if (error_if_any) {
		lockdb_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__LOCK_DB_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REPLY;
	frntnd_msg.lockdb_reply = &lockdb_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending LOCK_DB_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_setcfg_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t db_id, cmgd_client_req_id_t req_id,
	bool success, const char *error_if_any, bool implicit_commit)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSetConfigReply setcfg_reply;

	assert(sessn->adptr);

	if (implicit_commit && sessn->cfg_trxn_id)
		cmgd_frntnd_session_register_event(
			sessn, CMGD_FRNTND_SESSN_CFG_TRXN_CLNUP);

	cmgd__frntnd_set_config_reply__init(&setcfg_reply);
	setcfg_reply.session_id = (uint64_t) sessn;
	setcfg_reply.db_id = db_id;
	setcfg_reply.req_id = req_id;
	setcfg_reply.success = success;
	if (error_if_any) {
		setcfg_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY;
	frntnd_msg.setcfg_reply = &setcfg_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending SET_CONFIG_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	if (implicit_commit) {
		if (cm->perf_stats_en)
			cmgd_get_realtime(&sessn->adptr->cmt_stats.last_end);
		cmgd_frntnd_sessn_compute_commit_timers(&sessn->adptr->cmt_stats);
	}

	if (cm->perf_stats_en)
		cmgd_get_realtime(&sessn->adptr->setcfg_stats.last_end);
	cmgd_frntnd_adptr_compute_set_cfg_timers(&sessn->adptr->setcfg_stats);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_commitcfg_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t src_db_id, cmgd_database_id_t dst_db_id,
	cmgd_client_req_id_t req_id, bool success, bool validate_only,
	const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndCommitConfigReply commcfg_reply;

	assert(sessn->adptr);

	cmgd__frntnd_commit_config_reply__init(&commcfg_reply);
	commcfg_reply.session_id = (uint64_t) sessn;
	commcfg_reply.src_db_id = src_db_id;
	commcfg_reply.dst_db_id = dst_db_id;
	commcfg_reply.req_id = req_id;
	commcfg_reply.success = success;
	commcfg_reply.validate_only = validate_only;
	if (error_if_any) {
		commcfg_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY;
	frntnd_msg.commcfg_reply = &commcfg_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending COMMIT_CONFIG_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the CONFIG transaction associated with this session.
	 */
	if (success && !validate_only &&sessn->cfg_trxn_id)
		cmgd_frntnd_session_register_event(
			sessn, CMGD_FRNTND_SESSN_CFG_TRXN_CLNUP);

	if (cm->perf_stats_en)
		cmgd_get_realtime(&sessn->adptr->cmt_stats.last_end);
	cmgd_frntnd_sessn_compute_commit_timers(&sessn->adptr->cmt_stats);
	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_getcfg_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t db_id, cmgd_client_req_id_t req_id,
	bool success, cmgd_yang_data_reply_t *data, const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndGetConfigReply getcfg_reply;

	assert(sessn->adptr);

	cmgd__frntnd_get_config_reply__init(&getcfg_reply);
	getcfg_reply.session_id = (uint64_t) sessn;
	getcfg_reply.db_id = db_id;
	getcfg_reply.req_id = req_id;
	getcfg_reply.success = success;
	getcfg_reply.data = data;
	if (error_if_any) {
		getcfg_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY;
	frntnd_msg.getcfg_reply = &getcfg_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending GET_CONFIG_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (data->next_indx < 0 && sessn->trxn_id)
		cmgd_frntnd_session_register_event(
			sessn, CMGD_FRNTND_SESSN_SHOW_TRXN_CLNUP);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_getdata_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t db_id, cmgd_client_req_id_t req_id,
	bool success, cmgd_yang_data_reply_t *data, const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndGetDataReply getdata_reply;

	assert(sessn->adptr);

	cmgd__frntnd_get_data_reply__init(&getdata_reply);
	getdata_reply.session_id = (uint64_t) sessn;
	getdata_reply.db_id = db_id;
	getdata_reply.req_id = req_id;
	getdata_reply.success = success;
	getdata_reply.data = data;
	if (error_if_any) {
		getdata_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__GET_DATA_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY;
	frntnd_msg.getdata_reply = &getdata_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending GET_DATA_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	/*
	 * Cleanup the SHOW transaction associated with this session.
	 */
	if (data->next_indx < 0 && sessn->trxn_id)
		cmgd_frntnd_session_register_event(
			sessn, CMGD_FRNTND_SESSN_SHOW_TRXN_CLNUP);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_session_cfg_trxn_clnup(struct thread *thread)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)THREAD_ARG(thread);

	cmgd_frntnd_sessn_cfg_trxn_cleanup(sessn);

	return 0;
}

static int cmgd_frntnd_session_show_trxn_clnup(struct thread *thread)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)THREAD_ARG(thread);

	cmgd_frntnd_sessn_show_trxn_cleanup(sessn);

	return 0;
}

static void cmgd_frntnd_session_register_event(
	cmgd_frntnd_sessn_ctxt_t *sessn, cmgd_sessn_event_t event)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = CMGD_FRNTND_MSG_PROC_DELAY_USEC};

	switch (event) {
	case CMGD_FRNTND_SESSN_CFG_TRXN_CLNUP:
		sessn->proc_cfg_trxn_clnp = 
			thread_add_timer_tv(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_session_cfg_trxn_clnup, sessn,
				&tv, NULL);
		break;
	case CMGD_FRNTND_SESSN_SHOW_TRXN_CLNUP:
		sessn->proc_show_trxn_clnp = 
			thread_add_timer_tv(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_session_show_trxn_clnup, sessn,
				&tv, NULL);
		break;
	default:
		assert(!"cmgd_frntnd_adptr_post_event() called incorrectly");
		break;
	}
}

static cmgd_frntnd_client_adapter_t *cmgd_frntnd_find_adapter_by_fd(int conn_fd)
{
	cmgd_frntnd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (adptr->conn_fd == conn_fd) 
			return adptr;
	}

	return NULL;
}

static cmgd_frntnd_client_adapter_t *cmgd_frntnd_find_adapter_by_name(const char *name)
{
	cmgd_frntnd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (!strncmp(adptr->name, name, sizeof(adptr->name)))
			return adptr;
	}

	return NULL;
}

static void cmgd_frntnd_adapter_disconnect(cmgd_frntnd_client_adapter_t *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	cmgd_frntnd_cleanup_sessions(adptr);
	cmgd_frntnd_sessn_list_fini(&adptr->frntnd_sessns);
	cmgd_frntnd_adptr_list_del(&cmgd_frntnd_adptrs, adptr);

	cmgd_frntnd_adapter_unlock(&adptr);
}

static void cmgd_frntnd_adapter_cleanup_old_conn(
	cmgd_frntnd_client_adapter_t *adptr)
{
	cmgd_frntnd_client_adapter_t *old;

	FOREACH_ADPTR_IN_LIST(old) {
		if (old != adptr &&
			!strncmp(adptr->name, old->name, sizeof(adptr->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			CMGD_FRNTND_ADPTR_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adptr->name, adptr->conn_fd, old->conn_fd);
			cmgd_frntnd_adapter_disconnect(old);
		}
	}
}

static int cmgd_frntnd_session_handle_lockdb_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndLockDbReq *lockdb_req)
{
	cmgd_db_hndl_t db_hndl;

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (lockdb_req->db_id != CMGD_DB_CANDIDATE) {
		cmgd_frntnd_send_lockdb_reply(sessn,
			lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Lock/Unlock on databases other than Candidate DB not permitted!");
		return -1;
	}

	db_hndl = cmgd_db_get_hndl_by_id(
		cmgd_frntnd_adptr_cm, lockdb_req->db_id);
	if (!db_hndl) {
		cmgd_frntnd_send_lockdb_reply(sessn,
			lockdb_req->db_id, lockdb_req->req_id,
			lockdb_req->lock, false,
			"Failed to retrieve handle for DB!");
		return -1;
	}

	if (lockdb_req->lock) {
		if (cmgd_frntnd_session_write_lock_db(
			lockdb_req->db_id, db_hndl, sessn) != 0) {
			cmgd_frntnd_send_lockdb_reply(sessn,
				lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock already taken on DB by another session!");
			return -1;
		}

		sessn->db_locked_implict[lockdb_req->db_id] = false;
	} else {
		if (!sessn->db_write_locked[lockdb_req->db_id]) {
			cmgd_frntnd_send_lockdb_reply(sessn,
				lockdb_req->db_id, lockdb_req->req_id,
				lockdb_req->lock, false,
				"Lock on DB was not taken by this session!");
			return 0;
		}

		(void) cmgd_frntnd_session_unlock_db(lockdb_req->db_id,
					db_hndl, sessn, true, false);
	}

	if (!cmgd_frntnd_send_lockdb_reply(sessn,
		lockdb_req->db_id, lockdb_req->req_id,
		lockdb_req->lock, true, NULL) != 0) {
		CMGD_FRNTND_ADPTR_DBG("Failed to send LOCK_DB_REPLY for DB %u Sessn: %p from %s",
				lockdb_req->db_id, sessn, sessn->adptr->name);
	}

	return 0;
}

static int cmgd_frntnd_session_handle_setcfg_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndSetConfigReq *setcfg_req)
{
	cmgd_session_id_t cfg_sessn_id;
	cmgd_db_hndl_t db_hndl, dst_db_hndl;

	if (cm->perf_stats_en)
		cmgd_get_realtime(&sessn->adptr->setcfg_stats.last_start);

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (setcfg_req->db_id != CMGD_DB_CANDIDATE) {
		cmgd_frntnd_send_setcfg_reply(sessn,
			setcfg_req->db_id, setcfg_req->req_id, false,
			"Set-Config on databases other than Candidate DB not permitted!",
			setcfg_req->implicit_commit);
		return 0;
	}

	/*
	 * Get the DB handle.
	 */
	db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_frntnd_adptr_cm, setcfg_req->db_id);
	if (!db_hndl) {
		cmgd_frntnd_send_setcfg_reply(sessn,
			setcfg_req->db_id, setcfg_req->req_id, false,
			"No such DB exists!",
			setcfg_req->implicit_commit);
		return 0;
	}

	if (sessn->cfg_trxn_id == CMGD_TRXN_ID_NONE) {
		/*
		 * Check first if the current session can run a CONFIG
		 * transaction or not. Report failure if a CONFIG transaction
		 * from another session is already in progress.
		 */
		cfg_sessn_id = cmgd_config_trxn_in_progress();
		if (cfg_sessn_id != CMGD_SESSION_ID_NONE &&
			cfg_sessn_id != (cmgd_session_id_t) sessn) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Configuration already in-progress through a different user session!",
				setcfg_req->implicit_commit);
			goto cmgd_frntnd_session_handle_setcfg_req_failed;
		}

		/*
		 * Try taking write-lock on the requested DB (if not already).
		 */
		if (!sessn->db_write_locked[setcfg_req->db_id]) {
			if (cmgd_frntnd_session_write_lock_db(
				setcfg_req->db_id, db_hndl, sessn) != 0) {
				cmgd_frntnd_send_setcfg_reply(sessn,
					setcfg_req->db_id, setcfg_req->req_id, false,
					"Failed to lock the DB!",
					setcfg_req->implicit_commit);
				goto cmgd_frntnd_session_handle_setcfg_req_failed;
			}

			sessn->db_locked_implict[setcfg_req->db_id] = true;
		}

		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		sessn->cfg_trxn_id = cmgd_create_trxn(
			(cmgd_session_id_t) sessn, CMGD_TRXN_TYPE_CONFIG);
		if (sessn->cfg_trxn_id == CMGD_SESSION_ID_NONE) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Failed to create a Configuration session!",
				setcfg_req->implicit_commit);
			goto cmgd_frntnd_session_handle_setcfg_req_failed;
		}

		CMGD_FRNTND_ADPTR_DBG("Created new Config Trxn 0x%lx for session %p",
			sessn->cfg_trxn_id, sessn);
	} else {
		CMGD_FRNTND_ADPTR_DBG("Config Trxn 0x%lx for session %p already created",
			sessn->cfg_trxn_id, sessn);

		if (setcfg_req->implicit_commit) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"A Configuration transaction is already in progress!",
				setcfg_req->implicit_commit);
			return 0;
		}
	}

	dst_db_hndl = 0;
	if (setcfg_req->implicit_commit) {
		dst_db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_frntnd_adptr_cm,
				setcfg_req->commit_db_id);
		if (!dst_db_hndl) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"No such commit DB exists!",
				setcfg_req->implicit_commit);
			return 0;
		}
	}

	if (cmgd_trxn_send_set_config_req(
		sessn->cfg_trxn_id, setcfg_req->req_id, setcfg_req->db_id,
		db_hndl, setcfg_req->data, setcfg_req->n_data,
		setcfg_req->implicit_commit, setcfg_req->commit_db_id,
		dst_db_hndl) != 0)
	{
		cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Request processing for SET-CONFIG failed!",
				setcfg_req->implicit_commit);
		goto cmgd_frntnd_session_handle_setcfg_req_failed;
	}

	return 0;

cmgd_frntnd_session_handle_setcfg_req_failed:

	if (sessn->cfg_trxn_id != CMGD_TRXN_ID_NONE)
		cmgd_destroy_trxn(&sessn->cfg_trxn_id);
	if (db_hndl && sessn->db_write_locked[setcfg_req->db_id])
		cmgd_frntnd_session_unlock_db(setcfg_req->db_id, db_hndl, sessn,
			true, false);

	return 0;
}

static int cmgd_frntnd_session_handle_getcfg_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndGetConfigReq *getcfg_req)
{
	cmgd_db_hndl_t db_hndl;

	/*
	 * Get the DB handle.
	 */
	db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_frntnd_adptr_cm, getcfg_req->db_id);
	if (!db_hndl) {
		cmgd_frntnd_send_getcfg_reply(sessn,
			getcfg_req->db_id, getcfg_req->req_id, false,
			NULL, "No such DB exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (getcfg_req->db_id != CMGD_DB_CANDIDATE &&
		getcfg_req->db_id != CMGD_DB_RUNNING) {
		cmgd_frntnd_send_getcfg_reply(sessn,
			getcfg_req->db_id, getcfg_req->req_id, false, NULL, 
			"Get-Config on databases other than Candidate or Running DB not permitted!");
		return 0;
	}

	if (sessn->trxn_id == CMGD_TRXN_ID_NONE) {
#if 0
		/*
		 * Check first if a CONFIG transaction is in progress or not. 
		 * Report failure if a CONFIG transaction from a different session 
		 * is already in progress.
		 */
		cfg_sessn_id = cmgd_config_trxn_in_progress();
		if (cfg_sessn_id != CMGD_SESSION_ID_NONE &&
			cfg_sessn_id != (cmgd_session_id_t) sessn) {
			cmgd_frntnd_send_getcfg_reply(sessn,
				getcfg_req->db_id, getcfg_req->req_id, false, NULL,
				"Configuration session currently in-progress through a different user session. Please try after sometime!");
			goto cmgd_frntnd_session_handle_getcfg_req_failed;
		}
#endif

		/*
		 * Try taking read-lock on the requested DB (if not already locked).
		 * If the DB has already been write-locked by a ongoing CONFIG transaction
		 * we may allow reading the contents of the same DB.
		 */
		if (!sessn->db_read_locked[getcfg_req->db_id] &&
			!sessn->db_write_locked[getcfg_req->db_id]) {
			if (cmgd_frntnd_session_read_lock_db(
				getcfg_req->db_id, db_hndl, sessn) != 0) {
				cmgd_frntnd_send_getcfg_reply(sessn,
					getcfg_req->db_id, getcfg_req->req_id, false,
					NULL, "Failed to lock the DB! Another session might have locked it!");
				goto cmgd_frntnd_session_handle_getcfg_req_failed;
			}

			sessn->db_locked_implict[getcfg_req->db_id] = true;
		}

		/*
		 * Start a SHOW Transaction (if not started already)
		 */
		sessn->trxn_id = cmgd_create_trxn(
			(cmgd_session_id_t) sessn, CMGD_TRXN_TYPE_SHOW);
		if (sessn->trxn_id == CMGD_SESSION_ID_NONE) {
			cmgd_frntnd_send_getcfg_reply(sessn,
				getcfg_req->db_id, getcfg_req->req_id, false,
				NULL, "Failed to create a Show transaction!");
			goto cmgd_frntnd_session_handle_getcfg_req_failed;
		}

		CMGD_FRNTND_ADPTR_DBG("Created new Show Trxn 0x%lx for session %p",
			sessn->trxn_id, sessn);
	} else {
		CMGD_FRNTND_ADPTR_DBG("Show Trxn 0x%lx for session %p already created",
			sessn->trxn_id, sessn);
	}

	if (cmgd_trxn_send_get_config_req(
		sessn->trxn_id, getcfg_req->req_id, getcfg_req->db_id,
		db_hndl, getcfg_req->data, getcfg_req->n_data) != 0)
	{
		cmgd_frntnd_send_getcfg_reply(sessn,
				getcfg_req->db_id, getcfg_req->req_id, false,
				NULL, "Request processing for GET-CONFIG failed!");
		goto cmgd_frntnd_session_handle_getcfg_req_failed;
	}

	return 0;

cmgd_frntnd_session_handle_getcfg_req_failed:

	if (sessn->trxn_id != CMGD_TRXN_ID_NONE)
		cmgd_destroy_trxn(&sessn->trxn_id);
	if (db_hndl && sessn->db_read_locked[getcfg_req->db_id])
		cmgd_frntnd_session_unlock_db(getcfg_req->db_id, db_hndl, sessn,
			false, true);

	return -1;
}

static int cmgd_frntnd_session_handle_getdata_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndGetDataReq *getdata_req)
{
	cmgd_db_hndl_t db_hndl;

	/*
	 * Get the DB handle.
	 */
	db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_frntnd_adptr_cm, getdata_req->db_id);
	if (!db_hndl) {
		cmgd_frntnd_send_getdata_reply(sessn,
			getdata_req->db_id, getdata_req->req_id, false,
			NULL, "No such DB exists!");
		return 0;
	}

#if 0
	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (getdata_req->db_id != CMGD_DB_CANDIDATE &&
		getdata_req->db_id != CMGD_DB_RUNNING) {
		cmgd_frntnd_send_getdata_reply(sessn,
			getdata_req->db_id, getdata_req->req_id, false, NULL, 
			"Get-Config on databases other than Candidate or Running DB not permitted!");
		return 0;
	}
#endif
	if (sessn->trxn_id == CMGD_TRXN_ID_NONE) {
#if 0
		/*
		 * Check first if a CONFIG transaction is in progress or not. 
		 * Report failure if a CONFIG transaction from a different session 
		 * is already in progress.
		 */
		cfg_sessn_id = cmgd_config_trxn_in_progress();
		if (cfg_sessn_id != CMGD_SESSION_ID_NONE &&
			cfg_sessn_id != (cmgd_session_id_t) sessn) {
			cmgd_frntnd_send_getdata_reply(sessn,
				getdata_req->db_id, getdata_req->req_id, false, NULL,
				"Configuration session currently in-progress through a different user session. Please try after sometime!");
			goto cmgd_frntnd_session_handle_getdata_req_failed;
		}
#endif

		/*
		 * Try taking read-lock on the requested DB (if not already locked).
		 * If the DB has already been write-locked by a ongoing CONFIG transaction
		 * we may allow reading the contents of the same DB.
		 */
		if (!sessn->db_read_locked[getdata_req->db_id] &&
			!sessn->db_write_locked[getdata_req->db_id]) {
			if (cmgd_frntnd_session_read_lock_db(
				getdata_req->db_id, db_hndl, sessn) != 0) {
				cmgd_frntnd_send_getdata_reply(sessn,
					getdata_req->db_id, getdata_req->req_id, false,
					NULL, "Failed to lock the DB! Another session might have locked it!");
				goto cmgd_frntnd_session_handle_getdata_req_failed;
			}

			sessn->db_locked_implict[getdata_req->db_id] = true;
		}

		/*
		 * Start a SHOW Transaction (if not started already)
		 */
		sessn->trxn_id = cmgd_create_trxn(
			(cmgd_session_id_t) sessn, CMGD_TRXN_TYPE_SHOW);
		if (sessn->trxn_id == CMGD_SESSION_ID_NONE) {
			cmgd_frntnd_send_getdata_reply(sessn,
				getdata_req->db_id, getdata_req->req_id, false,
				NULL, "Failed to create a Show transaction!");
			goto cmgd_frntnd_session_handle_getdata_req_failed;
		}

		CMGD_FRNTND_ADPTR_DBG("Created new Show Trxn 0x%lx for session %p",
			sessn->trxn_id, sessn);
	} else {
		CMGD_FRNTND_ADPTR_DBG("Show Trxn 0x%lx for session %p already created",
			sessn->trxn_id, sessn);
	}

	if (cmgd_trxn_send_get_data_req(
		sessn->trxn_id, getdata_req->req_id, getdata_req->db_id,
		db_hndl, getdata_req->data, getdata_req->n_data) != 0)
	{
		cmgd_frntnd_send_getdata_reply(sessn,
				getdata_req->db_id, getdata_req->req_id, false,
				NULL, "Request processing for GET-CONFIG failed!");
		goto cmgd_frntnd_session_handle_getdata_req_failed;
	}

	return 0;

cmgd_frntnd_session_handle_getdata_req_failed:

	if (sessn->trxn_id != CMGD_TRXN_ID_NONE)
		cmgd_destroy_trxn(&sessn->trxn_id);
	if (db_hndl && sessn->db_read_locked[getdata_req->db_id])
		cmgd_frntnd_session_unlock_db(getdata_req->db_id, db_hndl, sessn,
			false, true);

	return -1;
}

static int cmgd_frntnd_session_handle_commit_config_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndCommitConfigReq *commcfg_req)
{
	cmgd_db_hndl_t src_db_hndl, dst_db_hndl;

	if (cm->perf_stats_en)
		cmgd_get_realtime(&sessn->adptr->cmt_stats.last_start);
	sessn->adptr->cmt_stats.commit_cnt++;
	/*
	 * Get the source DB handle.
	 */
	src_db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_frntnd_adptr_cm, commcfg_req->src_db_id);
	if (!src_db_hndl) {
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"No such source DB exists!");
		return 0;
	}

	/*
	 * Get the destination DB handle.
	 */
	dst_db_hndl = cmgd_db_get_hndl_by_id(
			cmgd_frntnd_adptr_cm, commcfg_req->dst_db_id);
	if (!dst_db_hndl) {
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"No such destination DB exists!");
		return 0;
	}

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (commcfg_req->dst_db_id != CMGD_DB_RUNNING) {
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"Set-Config on databases other than Running DB not permitted!");
		return 0;
	}

	if (sessn->cfg_trxn_id == CMGD_TRXN_ID_NONE) {
		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		sessn->cfg_trxn_id = cmgd_create_trxn(
			(cmgd_session_id_t) sessn, CMGD_TRXN_TYPE_CONFIG);
		if (sessn->cfg_trxn_id == CMGD_SESSION_ID_NONE) {
			cmgd_frntnd_send_commitcfg_reply(sessn,
				commcfg_req->src_db_id, commcfg_req->dst_db_id,
				commcfg_req->req_id, false, commcfg_req->validate_only,
				"Failed to create a Configuration session!");
			return 0;
		}
	}

	/*
	 * Try taking write-lock on the destination DB (if not already).
	 */
	if (!sessn->db_write_locked[commcfg_req->dst_db_id]) {
		if (cmgd_frntnd_session_write_lock_db(
			commcfg_req->dst_db_id, dst_db_hndl, sessn) != 0) {
			cmgd_frntnd_send_commitcfg_reply(sessn,
				commcfg_req->src_db_id, commcfg_req->dst_db_id,
				commcfg_req->req_id, false, commcfg_req->validate_only,
				"Failed to lock the destination DB!");
			return 0;
		}

		sessn->db_locked_implict[commcfg_req->dst_db_id] = true;
	}

	if (cmgd_trxn_send_commit_config_req(
		sessn->cfg_trxn_id, commcfg_req->req_id, 
		commcfg_req->src_db_id, src_db_hndl,
		commcfg_req->dst_db_id, dst_db_hndl,
		commcfg_req->validate_only, commcfg_req->abort,
		false) != 0)
	{
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"Request processing for COMMIT-CONFIG failed!");
		return 0;
	}

	return 0;
}

static int cmgd_frntnd_adapter_handle_msg(
	cmgd_frntnd_client_adapter_t *adptr, Cmgd__FrntndMessage *frntnd_msg)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	switch(frntnd_msg->type) {
	case CMGD__FRNTND_MESSAGE__TYPE__REGISTER_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_REGISTER_REQ);
		CMGD_FRNTND_ADPTR_DBG(
			"Got Register Req Msg from '%s'", 
			frntnd_msg->register_req->client_name);

		if (strlen(frntnd_msg->register_req->client_name)) {
			strlcpy(adptr->name, frntnd_msg->register_req->client_name, 
				sizeof(adptr->name));
			cmgd_frntnd_adapter_cleanup_old_conn(adptr);
		}
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__SESSION_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REQ);
		if (frntnd_msg->sessn_req->create && 
			frntnd_msg->sessn_req->id_case == 
			CMGD__FRNTND_SESSION_REQ__ID_CLIENT_CONN_ID) {
			CMGD_FRNTND_ADPTR_DBG(
				"Got Session Create Req Msg for client-id %llu from '%s'", 
				frntnd_msg->sessn_req->client_conn_id, adptr->name);

			sessn = cmgd_frntnd_create_session(adptr,
				frntnd_msg->sessn_req->client_conn_id);
			cmgd_frntnd_send_session_reply(
				adptr, sessn, true, sessn ? true : false);
		} else if (!frntnd_msg->sessn_req->create && 
			frntnd_msg->sessn_req->id_case == 
			CMGD__FRNTND_SESSION_REQ__ID_SESSION_ID) {
			CMGD_FRNTND_ADPTR_DBG(
				"Got Session Destroy Req Msg for session-id %llu from '%s'", 
				frntnd_msg->sessn_req->session_id, adptr->name);

			sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->sessn_req->session_id;
			cmgd_frntnd_send_session_reply(
				adptr, sessn, false, true);
			cmgd_frntnd_cleanup_session(&sessn);
		}
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__LOCK_DB_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->lockdb_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got %sockDB Req Msg for DB:%d for session-id %llx from '%s'", 
				frntnd_msg->lockdb_req->lock ? "L" : "Unl",
				frntnd_msg->lockdb_req->db_id,
				frntnd_msg->lockdb_req->session_id, adptr->name);
		cmgd_frntnd_session_handle_lockdb_req_msg(sessn, frntnd_msg->lockdb_req);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->setcfg_req->session_id;
		sessn->adptr->setcfg_stats.set_cfg_count++;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Set Config Req Msg (%d Xpaths) on DB:%d for session-id %llu from '%s'", 
				(int) frntnd_msg->setcfg_req->n_data,
				frntnd_msg->setcfg_req->db_id,
				frntnd_msg->setcfg_req->session_id, adptr->name);

		cmgd_frntnd_session_handle_setcfg_req_msg(
				sessn, frntnd_msg->setcfg_req);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->commcfg_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Commit Config Req Msg for src-DB:%d dst-DB:%d on session-id %llu from '%s'", 
				frntnd_msg->commcfg_req->src_db_id,
				frntnd_msg->commcfg_req->dst_db_id,
				frntnd_msg->commcfg_req->session_id, adptr->name);
		cmgd_frntnd_session_handle_commit_config_req_msg(
			sessn, frntnd_msg->commcfg_req);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_GETCFG_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->getcfg_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Get-Config Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'", 
				frntnd_msg->getcfg_req->db_id,
				(int) frntnd_msg->getcfg_req->n_data,
				frntnd_msg->getcfg_req->session_id, adptr->name);
		cmgd_frntnd_session_handle_getcfg_req_msg(
			sessn, frntnd_msg->getcfg_req);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__GET_DATA_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_GETDATA_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->getdata_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Get-Data Req Msg for DB:%d (xpaths: %d) on session-id %llu from '%s'", 
				frntnd_msg->getdata_req->db_id,
				(int) frntnd_msg->getdata_req->n_data,
				frntnd_msg->getdata_req->session_id, adptr->name);
		cmgd_frntnd_session_handle_getdata_req_msg(
			sessn, frntnd_msg->getdata_req);
		break;
	default:
		break;
	}

	return 0;
}

static uint16_t cmgd_frntnd_adapter_process_msg(
	cmgd_frntnd_client_adapter_t *adptr, uint8_t *msg_buf, uint16_t bytes_read)
{
	Cmgd__FrntndMessage *frntnd_msg;
	cmgd_frntnd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	CMGD_FRNTND_ADPTR_DBG("Have %u bytes of messages from client '%s' to process",
		bytes_read, adptr->name);

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_frntnd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_FRNTND_MSG_MARKER) {
			CMGD_FRNTND_ADPTR_DBG(
				"Marker not found in message from CMGD Frontend adapter '%s'", 
				adptr->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_FRNTND_ADPTR_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD Frontend adapter '%s'", 
				bytes_left, msg->hdr.len, adptr->name);
			break;
		}

		frntnd_msg = cmgd__frntnd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_FRNTND_MSG_HDR_LEN), 
			msg->payload);
		if (!frntnd_msg) {
			CMGD_FRNTND_ADPTR_DBG(
				"Failed to decode %d bytes from CMGD Frontend adapter '%s'", 
				msg->hdr.len, adptr->name);
			continue;
		}

		CMGD_FRNTND_ADPTR_DBG(
			"Decoded %d bytes of message(type: %u/%u) from CMGD Frontend adapter '%s'", 
			msg->hdr.len, frntnd_msg->type,
			frntnd_msg->message_case, adptr->name);

		(void) cmgd_frntnd_adapter_handle_msg(adptr, frntnd_msg);

		cmgd__frntnd_message__free_unpacked(frntnd_msg, NULL);
		processed++;
		adptr->num_msg_rx++;
	}

	return processed;
}

static int cmgd_frntnd_adapter_proc_msgbufs(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;
	struct stream *work;
	int processed = 0;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	CMGD_FRNTND_ADPTR_DBG("Have %d ibufs for client '%s' to process",
		(int) stream_fifo_count_safe(adptr->ibuf_fifo), adptr->name);

	for ( ; processed < CMGD_FRNTND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(adptr->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_frntnd_adapter_process_msg(
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
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_PROC_MSG);
	
	return 0;
}

static int cmgd_frntnd_adapter_read(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_frntnd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adptr->ibuf_work) - 
		stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				adptr->ibuf_work, adptr->conn_fd, bytes_left);
		CMGD_FRNTND_ADPTR_DBG(
			"Got %d bytes of message from CMGD Frontend adapter '%s'", 
			bytes_read, adptr->name);
		if (bytes_read <= 0) {
			if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_READ);
				return 0;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				CMGD_FRNTND_ADPTR_ERR(
					"Got error (%d) while reading from CMGD Frontend adapter '%s'. Err: '%s'", 
					bytes_read, adptr->name, safe_strerror(errno));
				cmgd_frntnd_adapter_disconnect(adptr);
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
	stream_set_getp(adptr->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_frntnd_msg_hdr_t *)
			(STREAM_DATA(adptr->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_FRNTND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			CMGD_FRNTND_ADPTR_ERR(
				"Received corrupted buffer from CMGD frontend client.");
			cmgd_frntnd_adapter_disconnect(adptr);
			return -1;
		}
		if (msg_hdr->len > bytes_left)
			break;

		CMGD_FRNTND_ADPTR_DBG("Got message (len: %u) from client '%s'",
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
	msg_hdr = (cmgd_frntnd_msg_hdr_t *)
		(STREAM_DATA(adptr->ibuf_work) + total_bytes);
	stream_set_endp(adptr->ibuf_work, total_bytes);
	stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
	adptr->ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(adptr->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(adptr->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_PROC_MSG);

	cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_READ);

	return 0;
}

static int cmgd_frntnd_adapter_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	cmgd_frntnd_client_adapter_t *adptr;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (adptr->obuf_work) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = NULL;
	}

	for (s = stream_fifo_head(adptr->obuf_fifo);
		s && processed < CMGD_FRNTND_MAX_NUM_MSG_WRITE;
		s = stream_fifo_head(adptr->obuf_fifo)) {
		// msg_size = (int)stream_get_size(s);
		msg_size = (int) STREAM_READABLE(s);
		bytes_written = stream_flush(s, adptr->conn_fd);
		if (bytes_written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_WRITE);
			return 0;
		} else if (bytes_written != msg_size) {
			CMGD_FRNTND_ADPTR_ERR(
				"Could not write all %d bytes (wrote: %d) to CMGD Frontend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_WRITE);
				return 0;
			}
			cmgd_frntnd_adapter_disconnect(adptr);
			return -1;
		}

		free = stream_fifo_pop(adptr->obuf_fifo);
		stream_free(free);
		CMGD_FRNTND_ADPTR_DBG(
			"Wrote %d bytes of message to CMGD Frontend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		cmgd_frntnd_adapter_writes_off(adptr);
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_WRITES_ON);
	}

	return 0;
}

static int cmgd_frntnd_adapter_resume_writes(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	cmgd_frntnd_adapter_writes_on(adptr);

	return 0;
}

static void cmgd_frntnd_adptr_register_event(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_event_t event)
{
	struct timeval tv = { 0 };

	switch (event) {
	case CMGD_FRNTND_CONN_READ:
		adptr->conn_read_ev = 
			thread_add_read(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_read, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_FRNTND_CONN_WRITE:
		adptr->conn_write_ev = 
			thread_add_write(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_write, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_FRNTND_PROC_MSG:
		tv.tv_usec = CMGD_FRNTND_MSG_PROC_DELAY_USEC;
		adptr->proc_msg_ev = 
			thread_add_timer_tv(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_proc_msgbufs, adptr,
				&tv, NULL);
		break;
	case CMGD_FRNTND_CONN_WRITES_ON:
		adptr->conn_writes_on =
			thread_add_timer_msec(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_resume_writes, adptr,
				CMGD_FRNTND_MSG_WRITE_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_frntnd_adptr_post_event() called incorrectly");
		break;
	}
}

void cmgd_frntnd_adapter_lock(cmgd_frntnd_client_adapter_t *adptr)
{
	adptr->refcount++;
}

extern void cmgd_frntnd_adapter_unlock(cmgd_frntnd_client_adapter_t **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		cmgd_frntnd_adptr_list_del(&cmgd_frntnd_adptrs, *adptr);

		stream_fifo_free((*adptr)->ibuf_fifo);
		stream_free((*adptr)->ibuf_work);
		stream_fifo_free((*adptr)->obuf_fifo);
		stream_free((*adptr)->obuf_work);

		XFREE(MTYPE_CMGD_FRNTND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int cmgd_frntnd_adapter_init(struct thread_master *tm, struct cmgd_master *cm)
{
	if (!cmgd_frntnd_adptr_tm) {
		cmgd_frntnd_adptr_tm = tm;
		cmgd_frntnd_adptr_cm = cm;
		cmgd_frntnd_adptr_list_init(&cmgd_frntnd_adptrs);
	}

	return 0;
}

cmgd_frntnd_client_adapter_t *cmgd_frntnd_create_adapter(
	int conn_fd, union sockunion *from)
{
	cmgd_frntnd_client_adapter_t *adptr = NULL;

	adptr = cmgd_frntnd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XCALLOC(MTYPE_CMGD_FRNTND_ADPATER, 
				sizeof(cmgd_frntnd_client_adapter_t));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d", adptr->conn_fd);
		cmgd_frntnd_sessn_list_init(&adptr->frntnd_sessns);
		adptr->ibuf_fifo = stream_fifo_new();
		adptr->ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
		adptr->obuf_fifo = stream_fifo_new();
		// adptr->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
		adptr->obuf_work = NULL;
		cmgd_frntnd_adapter_lock(adptr);

		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_READ);
		cmgd_frntnd_adptr_list_add_tail(&cmgd_frntnd_adptrs, adptr);

		adptr->setcfg_stats.min_tm = ULONG_MAX;
		adptr->cmt_stats.min_tm = ULONG_MAX;
		CMGD_FRNTND_ADPTR_DBG(
			"Added new CMGD Frontend adapter '%s'", adptr->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adptr->conn_fd);
	setsockopt_so_sendbuf(adptr->conn_fd, CMGD_SOCKET_BUF_SIZE);
	setsockopt_so_recvbuf(adptr->conn_fd, CMGD_SOCKET_BUF_SIZE);
	return adptr;
}

cmgd_frntnd_client_adapter_t *cmgd_frntnd_get_adapter(const char *name)
{
	return cmgd_frntnd_find_adapter_by_name(name);
}

int cmgd_frntnd_send_set_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
	const char *error_if_any, bool implicit_commit)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->cfg_trxn_id != trxn_id) {
		if (sessn)
			CMGD_FRNTND_ADPTR_ERR(
				"Trxn_id doesnot match, session trxn is 0x%lx, current trxn 0x%lx",
				sessn->cfg_trxn_id, trxn_id);
		return -1;
	}

	return cmgd_frntnd_send_setcfg_reply(sessn, db_id, req_id,
		result == CMGD_SUCCESS ? true : false, error_if_any,
		implicit_commit);
}

int cmgd_frntnd_send_commit_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t src_db_id,
        cmgd_database_id_t dst_db_id, cmgd_client_req_id_t req_id,
	bool validate_only, cmgd_result_t result,
	const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->cfg_trxn_id != trxn_id)
		return -1;

	return cmgd_frntnd_send_commitcfg_reply(sessn,
			src_db_id, dst_db_id, req_id, result == CMGD_SUCCESS,
			validate_only, error_if_any);
}

int cmgd_frntnd_send_get_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        cmgd_yang_data_reply_t *data_resp, const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->trxn_id != trxn_id)
		return -1;

	return cmgd_frntnd_send_getcfg_reply(sessn, db_id, req_id,
			result == CMGD_SUCCESS, data_resp, error_if_any);
}

int cmgd_frntnd_send_get_data_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        cmgd_yang_data_reply_t *data_resp, const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->trxn_id != trxn_id)
		return -1;

	return 0;

	return cmgd_frntnd_send_getcfg_reply(sessn, db_id, req_id,
			result == CMGD_SUCCESS, data_resp, error_if_any);
}

int cmgd_frntnd_send_data_notify(
        cmgd_database_id_t db_id, cmgd_yang_data_t *data_resp[], int num_data)
{
	// cmgd_frntnd_sessn_ctxt_t *sessn;

	return 0;
}

cmgd_setcfg_stats_t *cmgd_frntnd_get_sessn_setcfg_stats(
        cmgd_session_id_t session_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || !sessn->adptr)
		return NULL;

	return &sessn->adptr->setcfg_stats;
}

cmgd_commit_stats_t *cmgd_frntnd_get_sessn_commit_stats(
        cmgd_session_id_t session_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || !sessn->adptr)
		return NULL;

	return &sessn->adptr->cmt_stats;
}

static void cmgd_frntnd_adapter_cmt_stats_write(struct vty *vty,
	cmgd_frntnd_client_adapter_t *adptr)
{
	char buf[100] = {0};

	if (!cm->perf_stats_en) {
		return;
	}

	vty_out(vty, "    Num-Commits: \t\t\t%lu\n",
		adptr->cmt_stats.commit_cnt);
	if (adptr->cmt_stats.commit_cnt > 0) {
		if (cm->perf_stats_en)
			vty_out(vty, "    Max-Commit-Duration: \t\t%zu uSecs\n",
				adptr->cmt_stats.max_tm);
		vty_out(vty, "    Max-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.max_batch_cnt);
		if (cm->perf_stats_en)
			vty_out(vty, "    Min-Commit-Duration: \t\t%zu uSecs\n",
				adptr->cmt_stats.min_tm);
		vty_out(vty, "    Min-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.min_batch_cnt);
		if (cm->perf_stats_en)
			vty_out(vty, "    Last-Commit-Duration: \t\t%zu uSecs\n",
				adptr->cmt_stats.last_exec_tm);
		vty_out(vty, "    Last-Commit-Batch-Size: \t\t%lu\n",
			adptr->cmt_stats.last_batch_cnt);
		vty_out(vty, "    Last-Commit-CfgData-Reqs: \t\t%lu\n",
			adptr->cmt_stats.last_num_cfgdata_reqs);
		vty_out(vty, "    Last-Commit-CfgApply-Reqs: \t\t%lu\n",
			adptr->cmt_stats.last_num_apply_reqs);
		if (cm->perf_stats_en) {
			vty_out(vty, "    Last-Commit-Details:\n");
			vty_out(vty, "      Commit Start: \t\t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.last_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Config-Validate Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.validate_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Prep-Config Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.prep_cfg_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Trxn-Create Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.trxn_create_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Send-Config Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.send_cfg_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Apply-Config Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.apply_cfg_start,
					buf, sizeof(buf)));
			vty_out(vty, "        Apply-Config End: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.apply_cfg_end,
					buf, sizeof(buf)));
			vty_out(vty, "        Trxn-Delete Start: \t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.trxn_del_start,
					buf, sizeof(buf)));
			vty_out(vty, "      Commit End: \t\t\t%s\n",
				cmgd_realtime_to_string(
					&adptr->cmt_stats.last_end,
					buf, sizeof(buf)));
		}
	}
}

static void cmgd_frntnd_adapter_setcfg_stats_write(struct vty *vty,
	cmgd_frntnd_client_adapter_t *adptr)
{
	char buf[100] = {0};

	if (!cm->perf_stats_en) {
		return;
	}

	vty_out(vty, "    Num-Set-Cfg: \t\t\t%lu\n",
		adptr->setcfg_stats.set_cfg_count);
	if (cm->perf_stats_en && adptr->setcfg_stats.set_cfg_count > 0) {
		vty_out(vty, "    Max-Set-Cfg-Duration: \t\t%zu uSec\n",
			adptr->setcfg_stats.max_tm);
		vty_out(vty, "    Min-Set-Cfg-Duration: \t\t%zu uSec\n",
			adptr->setcfg_stats.min_tm);
		vty_out(vty, "    Avg-Set-Cfg-Duration: \t\t%zu uSec\n",
			adptr->setcfg_stats.avg_tm);
		vty_out(vty, "    Last-Set-Cfg-Details:\n");
		vty_out(vty, "      Set-Cfg Start: \t\t\t%s\n",
			cmgd_realtime_to_string(
				&adptr->setcfg_stats.last_start,
				buf, sizeof(buf)));
		vty_out(vty, "      Set-Cfg End: \t\t\t%s\n",
			cmgd_realtime_to_string(
				&adptr->setcfg_stats.last_end,
				buf, sizeof(buf)));
	}
}

void cmgd_frntnd_adapter_status_write(struct vty *vty, bool detail)
{
	cmgd_frntnd_client_adapter_t *adptr;
	cmgd_frntnd_sessn_ctxt_t *sessn;
	cmgd_database_id_t db_id;

	vty_out(vty, "CMGD Frontend Adpaters\n");

	FOREACH_ADPTR_IN_LIST(adptr) {
		vty_out(vty, "  Client: \t\t\t\t%s\n", adptr->name);
		vty_out(vty, "    Conn-FD: \t\t\t\t%d\n", adptr->conn_fd);
		if (detail) {
			cmgd_frntnd_adapter_setcfg_stats_write(vty, adptr);
			cmgd_frntnd_adapter_cmt_stats_write(vty, adptr);
		}
		vty_out(vty, "    Sessions\n");
		FOREACH_SESSN_IN_LIST(adptr, sessn) {
			vty_out(vty, "      Client-Id: \t\t\t0x%lx\n",
				sessn->client_id);
			vty_out(vty, "        Session-Id: \t\t\t%p\n", sessn);
			vty_out(vty, "        DB-Locks: \n");
			FOREACH_CMGD_DB_ID(db_id) {
				if (sessn->db_write_locked[db_id] ||
					sessn->db_read_locked[db_id]) {
					vty_out(vty, "        %s\t\t\t\t%s, %s\n",
						cmgd_db_id2name(db_id),
						sessn->db_write_locked ?
							"Write" : "Read",
						sessn->db_locked_implict ?
							"Implicit" : "Explicit");
				}
			}
		}
		vty_out(vty, "    Total-Sessions: \t\t\t%d\n",
			(int) cmgd_frntnd_sessn_list_count(&adptr->frntnd_sessns));
		vty_out(vty, "    Msg-Sent: \t\t\t\t%u\n", adptr->num_msg_tx);
		vty_out(vty, "    Msg-Recvd: \t\t\t\t%u\n", adptr->num_msg_rx);
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_frntnd_adptr_list_count(&cmgd_frntnd_adptrs));
}

void cmgd_frntnd_adapter_perf_measurement(struct vty *vty, bool config)
{
	cm->perf_stats_en = config;
}

void cmgd_frntnd_adapter_reset_perf_stats(struct vty *vty)
{
	cmgd_frntnd_client_adapter_t *adptr;
	cmgd_frntnd_sessn_ctxt_t *sessn;

	FOREACH_ADPTR_IN_LIST(adptr) {
		memset(&adptr->setcfg_stats, 0, sizeof(adptr->setcfg_stats));
		FOREACH_SESSN_IN_LIST(adptr, sessn) {
			memset(&adptr->cmt_stats, 0, sizeof(adptr->cmt_stats));
		}
	}
}
