/*
 * MGMTD Frontend Client Library api interfaces
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

#include "memory.h"
#include "northbound.h"
#include "libfrr.h"
#include "lib/mgmt_frntnd_client.h"
#include "lib/mgmt_pb.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "sockopt.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_FRNTND_CLNT_DBG(fmt, ...)					\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_FRNTND_CLNT_ERR(fmt, ...)					\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_FRNTND_CLNT_DBG(fmt, ...)					\
	if (mgmt_debug_frntnd_clnt)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define MGMTD_FRNTND_CLNT_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct mgmt_frntnd_client_ctxt_;

PREDECL_LIST(mgmt_session_list);

typedef struct mgmt_frntnd_client_session_ {
	mgmt_client_id_t client_id;
	mgmt_session_id_t session_id;
	struct mgmt_frntnd_client_ctxt_ *clnt_ctxt;
	uintptr_t user_ctxt;

	struct mgmt_session_list_item list_linkage;
} mgmt_frntnd_client_session_t;

DECLARE_LIST(mgmt_session_list, mgmt_frntnd_client_session_t, list_linkage);

DEFINE_MTYPE_STATIC(LIB, MGMTD_FRNTND_SESSION, "MGMTD Frontend session");

typedef struct mgmt_frntnd_client_ctxt_ {
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

	mgmt_frntnd_client_params_t client_params;

	struct mgmt_session_list_head client_sessions;
} mgmt_frntnd_client_ctxt_t;

#define MGMTD_FRNTND_CLNT_FLAGS_WRITES_OFF         (1U << 0)

#define FOREACH_SESSN_IN_LIST(clntctxt, sessn)						\
	for ((sessn) = mgmt_session_list_first(&(clntctxt)->client_sessions); (sessn);	\
		(sessn) = mgmt_session_list_next(&(clntctxt)->client_sessions, (sessn)))

static bool mgmt_debug_frntnd_clnt = false;

static mgmt_frntnd_client_ctxt_t mgmt_frntnd_clntctxt = { 0 };

/* Forward declarations */
static void mgmt_frntnd_client_register_event(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, mgmt_event_t event);
static void mgmt_frntnd_client_schedule_conn_retry(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs);

static mgmt_frntnd_client_session_t *mgmt_frntnd_find_session_by_client_id(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, mgmt_client_id_t client_id)
{
	mgmt_frntnd_client_session_t *sessn;

	FOREACH_SESSN_IN_LIST(clnt_ctxt, sessn) {
		if (sessn->client_id == client_id) {
			MGMTD_FRNTND_CLNT_DBG(
				"Found session %p for client-id %lu.", 
				sessn, client_id);
			return sessn;
		}
	}

	return NULL;
}

static mgmt_frntnd_client_session_t *mgmt_frntnd_find_session_by_sessn_id(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, mgmt_session_id_t sessn_id)
{
	mgmt_frntnd_client_session_t *sessn;

	FOREACH_SESSN_IN_LIST(clnt_ctxt, sessn) {
		if (sessn->session_id == sessn_id) {
			MGMTD_FRNTND_CLNT_DBG(
				"Found session %p for session-id %lu.", 
				sessn, sessn_id);
			return sessn;
		}
	}

	return NULL;
}

static void mgmt_frntnd_server_disconnect(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, bool reconnect)
{
	if (clnt_ctxt->conn_fd) {
		close(clnt_ctxt->conn_fd);
		clnt_ctxt->conn_fd = 0;
	}

	// THREAD_OFF(clnt_ctxt->conn_read_ev);
	// THREAD_OFF(clnt_ctxt->conn_retry_tmr);
	// THREAD_OFF(clnt_ctxt->msg_proc_ev);

	if (reconnect)
		mgmt_frntnd_client_schedule_conn_retry(
			clnt_ctxt, clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static inline void mgmt_frntnd_client_sched_msg_write(mgmt_frntnd_client_ctxt_t *clnt_ctxt)
{
	if (!CHECK_FLAG(clnt_ctxt->flags, MGMTD_FRNTND_CLNT_FLAGS_WRITES_OFF))
		mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_WRITE);
}

static inline void mgmt_frntnd_client_writes_on(mgmt_frntnd_client_ctxt_t *clnt_ctxt)
{
	MGMTD_FRNTND_CLNT_DBG("Resume writing msgs");
	UNSET_FLAG(clnt_ctxt->flags, MGMTD_FRNTND_CLNT_FLAGS_WRITES_OFF);
	if (clnt_ctxt->obuf_work || stream_fifo_count_safe(clnt_ctxt->obuf_fifo))
		mgmt_frntnd_client_sched_msg_write(clnt_ctxt);
}

static inline void mgmt_frntnd_client_writes_off(mgmt_frntnd_client_ctxt_t *clnt_ctxt)
{
	SET_FLAG(clnt_ctxt->flags, MGMTD_FRNTND_CLNT_FLAGS_WRITES_OFF);
	MGMTD_FRNTND_CLNT_DBG("Paused writing msgs");
}

static int mgmt_frntnd_client_send_msg(mgmt_frntnd_client_ctxt_t *clnt_ctxt, 
	Mgmtd__FrntndMessage *frntnd_msg)
{
	size_t msg_size;
	uint8_t msg_buf[MGMTD_FRNTND_MSG_MAX_LEN];
	mgmt_frntnd_msg_t *msg;

	if (clnt_ctxt->conn_fd == 0)
		return -1;

	msg_size = mgmtd__frntnd_message__get_packed_size(frntnd_msg);
	msg_size += MGMTD_FRNTND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		MGMTD_FRNTND_CLNT_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (mgmt_frntnd_msg_t *)msg_buf;
	msg->hdr.marker = MGMTD_FRNTND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	mgmtd__frntnd_message__pack(frntnd_msg, msg->payload);

#ifndef MGMTD_PACK_TX_MSGS
	clnt_ctxt->obuf_work = stream_new(msg_size);
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
	stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
	clnt_ctxt->obuf_work = NULL;
#else
	if (!clnt_ctxt->obuf_work)
		clnt_ctxt->obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(clnt_ctxt->obuf_work) < msg_size) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	}
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
#endif
	mgmt_frntnd_client_sched_msg_write(clnt_ctxt);
	clnt_ctxt->num_msg_tx++;
	return 0;
}

static int mgmt_frntnd_client_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);
	clnt_ctxt->conn_write_ev = NULL;

	/* Ensure pushing any pending write buffer to FIFO */
	if (clnt_ctxt->obuf_work) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = NULL;
	}

	for (s = stream_fifo_head(clnt_ctxt->obuf_fifo);
		s && processed < MGMTD_FRNTND_MAX_NUM_MSG_WRITE;
		s = stream_fifo_head(clnt_ctxt->obuf_fifo)) {
		// msg_size = (int)stream_get_size(s);
		msg_size = (int) STREAM_READABLE(s);
		bytes_written = stream_flush(s, clnt_ctxt->conn_fd);
		if (bytes_written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_WRITE);
			return 0;
		} else if (bytes_written != msg_size) {
			MGMTD_FRNTND_CLNT_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_WRITE);
				return 0;
			}
			mgmt_frntnd_server_disconnect(clnt_ctxt, true);
			return -1;
		}

		free = stream_fifo_pop(clnt_ctxt->obuf_fifo);
		stream_free(free);
		MGMTD_FRNTND_CLNT_DBG(
			"Wrote %d bytes of message to MGMTD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_frntnd_client_writes_off(clnt_ctxt);
		mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_WRITES_ON);
	}

	return 0;
}

static int mgmt_frntnd_client_resume_writes(struct thread *thread)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);
	clnt_ctxt->conn_writes_on = NULL;

	mgmt_frntnd_client_writes_on(clnt_ctxt);

	return 0;
}

static int mgmt_frntnd_send_register_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndRegisterReq rgstr_req;

	mgmtd__frntnd_register_req__init(&rgstr_req);
	rgstr_req.client_name = clnt_ctxt->client_params.name;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__REGISTER_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_REGISTER_REQ;
	frntnd_msg.register_req = &rgstr_req;

	MGMTD_FRNTND_CLNT_DBG("Sending REGISTER_REQ message to MGMTD Frontend server");

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_session_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn, bool create)
{
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndSessionReq sess_req;

	mgmtd__frntnd_session_req__init(&sess_req);
	sess_req.create = create;
	if (create) {
		sess_req.id_case = MGMTD__FRNTND_SESSION_REQ__ID_CLIENT_CONN_ID;
		sess_req.client_conn_id = (uint64_t) sessn->client_id;
	} else {
		sess_req.id_case = MGMTD__FRNTND_SESSION_REQ__ID_SESSION_ID;
		sess_req.session_id = (uint64_t) sessn->session_id;
	}

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__SESSION_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_SESSN_REQ;
	frntnd_msg.sessn_req = &sess_req;

	MGMTD_FRNTND_CLNT_DBG("Sending SESSION_REQ message for %s session %lu to MGMTD Frontend server",
		create? "creating" : "destroying", sessn->client_id);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_lockdb_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn, bool lock,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndLockDbReq lockdb_req;

	mgmtd__frntnd_lock_db_req__init(&lockdb_req);
	lockdb_req.session_id = (uint64_t) sessn->session_id;
	lockdb_req.req_id = req_id;
	lockdb_req.db_id = db_id;
	lockdb_req.lock = lock;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__LOCK_DB_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REQ;
	frntnd_msg.lockdb_req = &lockdb_req;

	MGMTD_FRNTND_CLNT_DBG("Sending %sLOCK_REQ message for Db:%d session %lu to MGMTD Frontend server",
		lock? "" : "UN", db_id, sessn->client_id);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_setcfg_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id, 
	mgmt_yang_cfgdata_req_t **data_req, int num_data_reqs, 
	bool implicit_commit, mgmt_database_id_t dst_db_id)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndSetConfigReq setcfg_req;

	mgmtd__frntnd_set_config_req__init(&setcfg_req);
	setcfg_req.session_id = (uint64_t) sessn->session_id;
	setcfg_req.db_id = db_id;
	setcfg_req.req_id = req_id;
	setcfg_req.data = data_req;
	setcfg_req.n_data = (size_t) num_data_reqs;
	setcfg_req.implicit_commit = implicit_commit;
	setcfg_req.commit_db_id = dst_db_id;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_SETCFG_REQ;
	frntnd_msg.setcfg_req = &setcfg_req;

	MGMTD_FRNTND_CLNT_DBG("Sending SET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to MGMTD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_commitcfg_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn, mgmt_client_req_id_t req_id,
	mgmt_database_id_t src_db_id, mgmt_database_id_t dest_db_id, 
	bool validate_only, bool abort)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndCommitConfigReq commitcfg_req;

	mgmtd__frntnd_commit_config_req__init(&commitcfg_req);
	commitcfg_req.session_id = (uint64_t) sessn->session_id;
	commitcfg_req.src_db_id = src_db_id;
	commitcfg_req.dst_db_id = dest_db_id;
	commitcfg_req.req_id = req_id;
	commitcfg_req.validate_only = validate_only;
	commitcfg_req.abort = abort;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REQ;
	frntnd_msg.commcfg_req = &commitcfg_req;

	MGMTD_FRNTND_CLNT_DBG("Sending COMMIT_CONFIG_REQ message for Src-Db:%d, Dst-Db:%d session %lu to MGMTD Frontend server",
		src_db_id, dest_db_id, sessn->client_id);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_getcfg_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id, 
	mgmt_yang_getdata_req_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndGetConfigReq getcfg_req;

	mgmtd__frntnd_get_config_req__init(&getcfg_req);
	getcfg_req.session_id = (uint64_t) sessn->session_id;
	getcfg_req.db_id = db_id;
	getcfg_req.req_id = req_id;
	getcfg_req.data = data_req;
	getcfg_req.n_data = (size_t) num_data_reqs;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_GETCFG_REQ;
	frntnd_msg.getcfg_req = &getcfg_req;

	MGMTD_FRNTND_CLNT_DBG("Sending GET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to MGMTD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_getdata_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id, 
	mgmt_yang_getdata_req_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndGetDataReq getdata_req;

	mgmtd__frntnd_get_data_req__init(&getdata_req);
	getdata_req.session_id = (uint64_t) sessn->session_id;
	getdata_req.db_id = db_id;
	getdata_req.req_id = req_id;
	getdata_req.data = data_req;
	getdata_req.n_data = (size_t) num_data_reqs;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__GET_DATA_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_GETDATA_REQ;
	frntnd_msg.getdata_req = &getdata_req;

	MGMTD_FRNTND_CLNT_DBG("Sending GET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to MGMTD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_send_regnotify_req(mgmt_frntnd_client_ctxt_t *clnt_ctxt,
	mgmt_frntnd_client_session_t *sessn,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	bool register_req, mgmt_yang_xpath_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Mgmtd__FrntndMessage frntnd_msg;
	Mgmtd__FrntndRegisterNotifyReq regntfy_req;

	mgmtd__frntnd_register_notify_req__init(&regntfy_req);
	regntfy_req.session_id = (uint64_t) sessn->session_id;
	regntfy_req.db_id = db_id;
	regntfy_req.register_req = register_req;
	regntfy_req.data_xpath = data_req;
	regntfy_req.n_data_xpath = (size_t) num_data_reqs;

	mgmtd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = MGMTD__FRNTND_MESSAGE__TYPE__REGISTER_NOTIFY_REQ;
	frntnd_msg.message_case = MGMTD__FRNTND_MESSAGE__MESSAGE_REGNOTIFY_REQ;
	frntnd_msg.regnotify_req = &regntfy_req;

	return mgmt_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int mgmt_frntnd_client_handle_msg(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, Mgmtd__FrntndMessage *frntnd_msg)
{
	mgmt_frntnd_client_session_t *sessn = NULL;

	switch(frntnd_msg->type) {
	case MGMTD__FRNTND_MESSAGE__TYPE__SESSION_REPLY:
		assert(frntnd_msg->message_case == 
			MGMTD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY);
		if (frntnd_msg->sessn_reply->create &&
			frntnd_msg->sessn_reply->has_client_conn_id) {
			MGMTD_FRNTND_CLNT_DBG(
				"Got Session Create Reply Msg for client-id %llu with session-id: %llu.", 
				frntnd_msg->sessn_reply->client_conn_id,
				frntnd_msg->sessn_reply->session_id);

			sessn = mgmt_frntnd_find_session_by_client_id(clnt_ctxt,
				frntnd_msg->sessn_reply->client_conn_id);

			if (frntnd_msg->sessn_reply->success) {
				MGMTD_FRNTND_CLNT_DBG(
					"Session Create for client-id %llu successful.", 
					frntnd_msg->sessn_reply->client_conn_id);
				sessn->session_id = frntnd_msg->sessn_reply->session_id;
			} else {
				MGMTD_FRNTND_CLNT_ERR(
					"Session Create for client-id %llu failed.", 
					frntnd_msg->sessn_reply->client_conn_id);
			}
		} else if (!frntnd_msg->sessn_reply->create) {
			MGMTD_FRNTND_CLNT_DBG(
				"Got Session Destroy Reply Msg for session-id %llu", 
				frntnd_msg->sessn_reply->session_id);

			sessn = mgmt_frntnd_find_session_by_sessn_id(clnt_ctxt,
				frntnd_msg->sessn_req->session_id);
		}

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.sess_req_result_cb)
			(*sessn->clnt_ctxt->client_params.sess_req_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id,
				frntnd_msg->sessn_reply->create,
				frntnd_msg->sessn_reply->success,
				(mgmt_session_id_t) sessn, sessn->user_ctxt);
		break;
	case MGMTD__FRNTND_MESSAGE__TYPE__LOCK_DB_REPLY:
		assert(frntnd_msg->message_case == 
			MGMTD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REPLY);
		MGMTD_FRNTND_CLNT_DBG(
			"Got LockDb Reply Msg for session-id %llu", 
			frntnd_msg->lockdb_reply->session_id);
		sessn = mgmt_frntnd_find_session_by_sessn_id(clnt_ctxt,
				frntnd_msg->lockdb_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.lock_db_result_cb)
			(*sessn->clnt_ctxt->client_params.lock_db_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (mgmt_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->lockdb_reply->req_id,
				frntnd_msg->lockdb_reply->lock,
				frntnd_msg->lockdb_reply->success,
				frntnd_msg->lockdb_reply->db_id, 
				frntnd_msg->lockdb_reply->error_if_any);
		break;
	case MGMTD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REPLY:
		assert(frntnd_msg->message_case == 
			MGMTD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY);

		MGMTD_FRNTND_CLNT_DBG(
			"Got Set Config Reply Msg for session-id %llu", 
				frntnd_msg->setcfg_reply->session_id);

		sessn = mgmt_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->setcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.set_config_result_cb)
			(*sessn->clnt_ctxt->client_params.set_config_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (mgmt_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->setcfg_reply->req_id, 
				frntnd_msg->setcfg_reply->success,
				frntnd_msg->setcfg_reply->db_id, 
				frntnd_msg->setcfg_reply->error_if_any);
		break;
	case MGMTD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REPLY:
		assert(frntnd_msg->message_case == 
			MGMTD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY);

		MGMTD_FRNTND_CLNT_DBG(
			"Got Commit Config Reply Msg for session-id %llu", 
				frntnd_msg->commcfg_reply->session_id);

		sessn = mgmt_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->commcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.commit_cfg_result_cb)
			(*sessn->clnt_ctxt->client_params.commit_cfg_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (mgmt_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->commcfg_reply->req_id, 
				frntnd_msg->commcfg_reply->success,
				frntnd_msg->commcfg_reply->src_db_id, 
				frntnd_msg->commcfg_reply->dst_db_id, 
				frntnd_msg->commcfg_reply->validate_only,
				frntnd_msg->commcfg_reply->error_if_any);
		break;
	case MGMTD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REPLY:
		assert(frntnd_msg->message_case ==
			MGMTD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY);

		MGMTD_FRNTND_CLNT_DBG(
			"Got Get Config Reply Msg for session-id %llu",
				frntnd_msg->getcfg_reply->session_id);

		sessn = mgmt_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->getcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.get_data_result_cb)
			(*sessn->clnt_ctxt->client_params.get_data_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (mgmt_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->getcfg_reply->req_id,
				frntnd_msg->getcfg_reply->success,
				frntnd_msg->getcfg_reply->db_id,
				frntnd_msg->getcfg_reply->data ?
				frntnd_msg->getcfg_reply->data->data : NULL,
				frntnd_msg->getcfg_reply->data ?
				frntnd_msg->getcfg_reply->data->n_data : 0,
				frntnd_msg->getcfg_reply->data ?
				frntnd_msg->getcfg_reply->data->next_indx : 0,
				frntnd_msg->getcfg_reply->error_if_any);
		break;
	case MGMTD__FRNTND_MESSAGE__TYPE__GET_DATA_REPLY:
		assert(frntnd_msg->message_case ==
			MGMTD__FRNTND_MESSAGE__MESSAGE_GETDATA_REPLY);

		MGMTD_FRNTND_CLNT_DBG(
			"Got Get Data Reply Msg for session-id %llu",
				frntnd_msg->getdata_reply->session_id);

		sessn = mgmt_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->getdata_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.get_data_result_cb)
			(*sessn->clnt_ctxt->client_params.get_data_result_cb)(
				(mgmt_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (mgmt_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->getdata_reply->req_id,
				frntnd_msg->getdata_reply->success,
				frntnd_msg->getdata_reply->db_id,
				frntnd_msg->getdata_reply->data ?
				frntnd_msg->getdata_reply->data->data : NULL,
				frntnd_msg->getdata_reply->data ?
				frntnd_msg->getdata_reply->data->n_data : 0,
				frntnd_msg->getdata_reply->data ?
				frntnd_msg->getdata_reply->data->next_indx : 0,
				frntnd_msg->getdata_reply->error_if_any);
		break;
	default:
		break;
	}

	return 0;
}

static int mgmt_frntnd_client_process_msg(mgmt_frntnd_client_ctxt_t *clnt_ctxt, 
	uint8_t *msg_buf, int bytes_read)
{
	Mgmtd__FrntndMessage *frntnd_msg;
	mgmt_frntnd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	MGMTD_FRNTND_CLNT_DBG("Have %u bytes of messages from MGMTD Frontend server to .",
		bytes_read);

	bytes_left = bytes_read;
	for ( ; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (mgmt_frntnd_msg_t *)msg_buf;
		if (msg->hdr.marker != MGMTD_FRNTND_MSG_MARKER) {
			MGMTD_FRNTND_CLNT_DBG(
				"Marker not found in message from MGMTD Frontend server.");
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_FRNTND_CLNT_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD Frontend server.", 
				bytes_left, msg->hdr.len);
			break;
		}

		frntnd_msg = mgmtd__frntnd_message__unpack(
			NULL, (size_t) (msg->hdr.len - MGMTD_FRNTND_MSG_HDR_LEN), 
			msg->payload);
		if (!frntnd_msg) {
			MGMTD_FRNTND_CLNT_DBG(
				"Failed to decode %d bytes from MGMTD Frontend server.", 
				msg->hdr.len);
			continue;
		}

		MGMTD_FRNTND_CLNT_DBG(
			"Decoded %d bytes of message(type: %u/%u) from MGMTD Frontend server", 
			msg->hdr.len, frntnd_msg->type,
			frntnd_msg->message_case);

		(void) mgmt_frntnd_client_handle_msg(clnt_ctxt, frntnd_msg);

		mgmtd__frntnd_message__free_unpacked(frntnd_msg, NULL);
		processed++;
		clnt_ctxt->num_msg_rx++;
	}

	return processed;
}

static int mgmt_frntnd_client_proc_msgbufs(struct thread *thread)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	struct stream *work;
	int processed = 0;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);
	clnt_ctxt->msg_proc_ev = NULL;

	for ( ; processed < MGMTD_FRNTND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(clnt_ctxt->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += mgmt_frntnd_client_process_msg(
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
		mgmt_frntnd_client_register_event(
			clnt_ctxt, MGMTD_FRNTND_PROC_MSG);
	
	return 0;
}

static int mgmt_frntnd_client_read(struct thread *thread)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	mgmt_frntnd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);
	clnt_ctxt->conn_read_ev = NULL;

	total_bytes = 0;
	bytes_left = STREAM_SIZE(clnt_ctxt->ibuf_work) - 
		stream_get_endp(clnt_ctxt->ibuf_work);
	for ( ; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				clnt_ctxt->ibuf_work, clnt_ctxt->conn_fd, bytes_left);
		MGMTD_FRNTND_CLNT_DBG(
			"Got %d bytes of message from MGMTD Frontend server", 
			bytes_read);
		if (bytes_read <= 0) {
			if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_READ);
				return 0;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				MGMTD_FRNTND_CLNT_ERR(
					"Got error (%d) while reading from MGMTD Frontend server. Err: '%s'", 
					bytes_read, safe_strerror(errno));
				mgmt_frntnd_server_disconnect(clnt_ctxt, true);
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
	for ( ; bytes_left > MGMTD_FRNTND_MSG_HDR_LEN; ) {
		msg_hdr = (mgmt_frntnd_msg_hdr_t *)
			(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
		if (msg_hdr->marker != MGMTD_FRNTND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_FRNTND_CLNT_ERR(
				"Received corrupted buffer from MGMTD frontend server.");
			mgmt_frntnd_server_disconnect(clnt_ctxt, true);
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
	msg_hdr = (mgmt_frntnd_msg_hdr_t *)
		(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
	stream_set_endp(clnt_ctxt->ibuf_work, total_bytes);
	stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);
	clnt_ctxt->ibuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(clnt_ctxt->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(clnt_ctxt->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_PROC_MSG);

	mgmt_frntnd_client_register_event(clnt_ctxt, MGMTD_FRNTND_CONN_READ);

	return 0;
}

static int mgmt_frntnd_server_connect(mgmt_frntnd_client_ctxt_t *clnt_ctxt)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	MGMTD_FRNTND_CLNT_DBG("Trying to connect to MGMTD Frontend server at %s",
		MGMTD_FRNTND_SERVER_PATH);

	assert(!clnt_ctxt->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		MGMTD_FRNTND_CLNT_ERR("Failed to create socket");
		goto mgmt_frntnd_server_connect_failed;
	}

	MGMTD_FRNTND_CLNT_DBG("Created MGMTD Frontend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, MGMTD_FRNTND_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		MGMTD_FRNTND_CLNT_ERR(
			"Failed to connect to MGMTD Frontend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto mgmt_frntnd_server_connect_failed;
	}

	MGMTD_FRNTND_CLNT_DBG("Connected to MGMTD Frontend Server at %s successfully!",
		addr.sun_path);
	clnt_ctxt->conn_fd = sock;

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);
        setsockopt_so_sendbuf(clnt_ctxt->conn_fd, MGMTD_SOCKET_FRNTND_SEND_BUF_SIZE);
        setsockopt_so_recvbuf(clnt_ctxt->conn_fd, MGMTD_SOCKET_FRNTND_RECV_BUF_SIZE);

	thread_add_read(clnt_ctxt->tm, mgmt_frntnd_client_read,
		(void *)&mgmt_frntnd_clntctxt, clnt_ctxt->conn_fd,
		&clnt_ctxt->conn_read_ev);

	/* Send REGISTER_REQ message */
	if (mgmt_frntnd_send_register_req(clnt_ctxt) != 0)
		goto mgmt_frntnd_server_connect_failed;

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(mgmt_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, true);

	return 0;

mgmt_frntnd_server_connect_failed:
	if (sock && sock != clnt_ctxt->conn_fd) {
		close(sock);
	}
	mgmt_frntnd_server_disconnect(clnt_ctxt, true);
	return -1;
}

static int mgmt_frntnd_client_conn_timeout(struct thread *thread)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	clnt_ctxt->conn_retry_tmr = NULL;
	return mgmt_frntnd_server_connect(clnt_ctxt);
}

static void mgmt_frntnd_client_register_event(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, mgmt_event_t event)
{
	struct timeval tv = { 0 };

	switch (event) {
	case MGMTD_FRNTND_CONN_READ:
		clnt_ctxt->conn_read_ev = 
			thread_add_read(clnt_ctxt->tm,
				mgmt_frntnd_client_read, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case MGMTD_FRNTND_CONN_WRITE:
		clnt_ctxt->conn_write_ev = 
			thread_add_write(clnt_ctxt->tm,
				mgmt_frntnd_client_write, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case MGMTD_FRNTND_PROC_MSG:
		tv.tv_usec = MGMTD_FRNTND_MSG_PROC_DELAY_USEC;
		clnt_ctxt->msg_proc_ev = 
			thread_add_timer_tv(clnt_ctxt->tm,
				mgmt_frntnd_client_proc_msgbufs, clnt_ctxt,
				&tv, NULL);
		break;
	case MGMTD_FRNTND_CONN_WRITES_ON:
		clnt_ctxt->conn_writes_on =
			thread_add_timer_msec(clnt_ctxt->tm,
				mgmt_frntnd_client_resume_writes, clnt_ctxt,
				MGMTD_FRNTND_MSG_WRITE_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"mgmt_frntnd_clnt_ctxt_post_event() called incorrectly");
	}
}

static void mgmt_frntnd_client_schedule_conn_retry(
	mgmt_frntnd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs)
{
	MGMTD_FRNTND_CLNT_DBG("Scheduling MGMTD Frontend server connection retry after %lu seconds",
		intvl_secs);
	clnt_ctxt->conn_retry_tmr = thread_add_timer(
		clnt_ctxt->tm, mgmt_frntnd_client_conn_timeout,
		(void *)clnt_ctxt, intvl_secs, NULL);
}

/*
 * Initialize library and try connecting with MGMTD.
 */
mgmt_lib_hndl_t mgmt_frntnd_client_lib_init(
	mgmt_frntnd_client_params_t *params, 
	struct thread_master *master_thread)
{
	assert(master_thread && params && 
		strlen(params->name) && !mgmt_frntnd_clntctxt.tm);

	mgmt_frntnd_clntctxt.tm = master_thread;
	memcpy(&mgmt_frntnd_clntctxt.client_params, params, 
		sizeof(mgmt_frntnd_clntctxt.client_params));
	if (!mgmt_frntnd_clntctxt.client_params.conn_retry_intvl_sec) 
		mgmt_frntnd_clntctxt.client_params.conn_retry_intvl_sec = 
			MGMTD_FRNTND_DEFAULT_CONN_RETRY_INTVL_SEC;

	assert(!mgmt_frntnd_clntctxt.ibuf_fifo &&
		!mgmt_frntnd_clntctxt.ibuf_work &&
		!mgmt_frntnd_clntctxt.obuf_fifo &&
		!mgmt_frntnd_clntctxt.obuf_work);
	
	mgmt_frntnd_clntctxt.ibuf_fifo = stream_fifo_new();
	mgmt_frntnd_clntctxt.ibuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	mgmt_frntnd_clntctxt.obuf_fifo = stream_fifo_new();
	// mgmt_frntnd_clntctxt.obuf_work = stream_new(MGMTD_FRNTND_MSG_MAX_LEN);
	mgmt_frntnd_clntctxt.obuf_work = NULL;

	mgmt_session_list_init(&mgmt_frntnd_clntctxt.client_sessions);

	/* Start trying to connect to MGMTD frontend server immediately */
	mgmt_frntnd_client_schedule_conn_retry(&mgmt_frntnd_clntctxt, 1);

	MGMTD_FRNTND_CLNT_DBG("Initialized client '%s'", params->name);

	return (mgmt_lib_hndl_t)&mgmt_frntnd_clntctxt;
}

/*
 * Create a new Session for a Frontend Client connection.
 */
mgmt_result_t mgmt_frntnd_create_client_session(
	mgmt_lib_hndl_t lib_hndl, mgmt_client_id_t client_id,
	uintptr_t user_ctxt)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = XCALLOC(MTYPE_MGMTD_FRNTND_SESSION, 
			sizeof(mgmt_frntnd_client_session_t));
	assert(sessn);
	sessn->user_ctxt = user_ctxt;
	sessn->client_id = client_id;
	sessn->clnt_ctxt = clnt_ctxt;
	sessn->session_id = 0;
	mgmt_session_list_add_tail(&clnt_ctxt->client_sessions, sessn);

	if (mgmt_frntnd_send_session_req(clnt_ctxt, sessn, true) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Delete an existing Session for a Frontend Client connection.
 */
mgmt_result_t mgmt_frntnd_destroy_client_session(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_session_req(clnt_ctxt, sessn, false) != 0)
		return MGMTD_INTERNAL_ERROR;

	mgmt_session_list_del(&clnt_ctxt->client_sessions, sessn);
	XFREE(MTYPE_MGMTD_FRNTND_SESSION, sessn);

	return MGMTD_SUCCESS;
}

/*
 * Send UN/LOCK_DB_REQ to MGMTD for a specific Datastore DB.
 */
mgmt_result_t mgmt_frntnd_lock_db(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	bool lock_db)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_lockdb_req(
		clnt_ctxt, sessn, lock_db, req_id, db_id) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
mgmt_result_t mgmt_frntnd_set_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_cfgdata_req_t **config_req, int num_reqs, 
	bool implicit_commit, mgmt_database_id_t dst_db_id)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_setcfg_req(
		clnt_ctxt, sessn, req_id, db_id, config_req, num_reqs,
		implicit_commit, dst_db_id) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
mgmt_result_t mgmt_frntnd_commit_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t src_db_id, 
	mgmt_database_id_t dst_db_id, bool validate_only, bool abort)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_commitcfg_req(
		clnt_ctxt, sessn, req_id, src_db_id, dst_db_id,
		validate_only, abort) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send GET_CONFIG_REQ to MGMTD for one or more config data item(s).
 */
mgmt_result_t mgmt_frntnd_get_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_getdata_req_t *data_req[], int num_reqs)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_getcfg_req(
		clnt_ctxt, sessn, req_id, db_id, data_req, num_reqs) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send GET_DATA_REQ to MGMTD for one or more config data item(s).
 */
mgmt_result_t mgmt_frntnd_get_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_getdata_req_t *data_req[], int num_reqs)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_getdata_req(
		clnt_ctxt, sessn, req_id, db_id, data_req, num_reqs) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send NOTIFY_REGISTER_REQ to MGMTD daemon.
 */
mgmt_result_t mgmt_frntnd_register_yang_notify(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	bool register_req, mgmt_yang_xpath_t *data_req[], int num_reqs)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;
	mgmt_frntnd_client_session_t *sessn;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	sessn = (mgmt_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return MGMTD_INVALID_PARAM;

	if (mgmt_frntnd_send_regnotify_req(
		clnt_ctxt, sessn, req_id, db_id, register_req,
		data_req, num_reqs) != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void mgmt_frntnd_client_lib_destroy(mgmt_lib_hndl_t lib_hndl)
{
	mgmt_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (mgmt_frntnd_client_ctxt_t *)lib_hndl;
	assert(clnt_ctxt);

	MGMTD_FRNTND_CLNT_DBG("Destroying MGMTD Frontend Client '%s'", 
		clnt_ctxt->client_params.name);

	mgmt_frntnd_server_disconnect(clnt_ctxt, false);

	assert(mgmt_frntnd_clntctxt.ibuf_fifo &&
		mgmt_frntnd_clntctxt.obuf_fifo);

	THREAD_OFF(clnt_ctxt->conn_retry_tmr);
	THREAD_OFF(clnt_ctxt->conn_read_ev);
	THREAD_OFF(clnt_ctxt->conn_write_ev);
	THREAD_OFF(clnt_ctxt->conn_writes_on);
	THREAD_OFF(clnt_ctxt->msg_proc_ev);	
	stream_fifo_free(mgmt_frntnd_clntctxt.ibuf_fifo);
	if (mgmt_frntnd_clntctxt.ibuf_work)
		stream_free(mgmt_frntnd_clntctxt.ibuf_work);
	stream_fifo_free(mgmt_frntnd_clntctxt.obuf_fifo);
	if (mgmt_frntnd_clntctxt.obuf_work)
		stream_free(mgmt_frntnd_clntctxt.obuf_work);
}
