/*
 * CMGD Frontend Client Library api interfaces
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
#include "lib/cmgd_frntnd_client.h"
#include "lib/cmgd_pb.h"
#include "lib/network.h"
#include "lib/stream.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_FRNTND_CLNT_DBG(fmt, ...)					\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_CLNT_ERR(fmt, ...)					\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_FRNTND_CLNT_DBG(fmt, ...)					\
	if (cmgd_debug_frntnd_clnt)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_CLNT_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct cmgd_frntnd_client_ctxt_;

PREDECL_LIST(cmgd_session_list);

typedef struct cmgd_frntnd_client_session_ {
	cmgd_client_id_t client_id;
	cmgd_session_id_t session_id;
	struct cmgd_frntnd_client_ctxt_ *clnt_ctxt;
	uintptr_t user_ctxt;

	struct cmgd_session_list_item list_linkage;
} cmgd_frntnd_client_session_t;

DECLARE_LIST(cmgd_session_list, cmgd_frntnd_client_session_t, list_linkage);

DEFINE_MTYPE_STATIC(LIB, CMGD_FRNTND_SESSION, "CMGD Frontend session");

typedef struct cmgd_frntnd_client_ctxt_ {
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

	cmgd_frntnd_client_params_t client_params;

	struct cmgd_session_list_head client_sessions;
} cmgd_frntnd_client_ctxt_t;

#define CMGD_FRNTND_CLNT_FLAGS_WRITES_OFF         (1U << 0)

#define FOREACH_SESSN_IN_LIST(clntctxt, sessn)						\
	for ((sessn) = cmgd_session_list_first(&(clntctxt)->client_sessions); (sessn);	\
		(sessn) = cmgd_session_list_next(&(clntctxt)->client_sessions, (sessn)))

static bool cmgd_debug_frntnd_clnt = false;

static cmgd_frntnd_client_ctxt_t cmgd_frntnd_clntctxt = { 0 };

/* Forward declarations */
static void cmgd_frntnd_client_register_event(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, cmgd_event_t event);
static void cmgd_frntnd_client_schedule_conn_retry(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs);

static cmgd_frntnd_client_session_t *cmgd_frntnd_find_session_by_client_id(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, cmgd_client_id_t client_id)
{
	cmgd_frntnd_client_session_t *sessn;

	FOREACH_SESSN_IN_LIST(clnt_ctxt, sessn) {
		if (sessn->client_id == client_id) {
			CMGD_FRNTND_CLNT_DBG(
				"Found session %p for client-id %lu.", 
				sessn, client_id);
			return sessn;
		}
	}

	return NULL;
}

static cmgd_frntnd_client_session_t *cmgd_frntnd_find_session_by_sessn_id(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, cmgd_session_id_t sessn_id)
{
	cmgd_frntnd_client_session_t *sessn;

	FOREACH_SESSN_IN_LIST(clnt_ctxt, sessn) {
		if (sessn->session_id == sessn_id) {
			CMGD_FRNTND_CLNT_DBG(
				"Found session %p for session-id %lu.", 
				sessn, sessn_id);
			return sessn;
		}
	}

	return NULL;
}

static void cmgd_frntnd_server_disconnect(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, bool reconnect)
{
	if (clnt_ctxt->conn_fd) {
		close(clnt_ctxt->conn_fd);
		clnt_ctxt->conn_fd = 0;
	}

	// THREAD_OFF(clnt_ctxt->conn_read_ev);
	// THREAD_OFF(clnt_ctxt->conn_retry_tmr);
	// THREAD_OFF(clnt_ctxt->msg_proc_ev);

	if (reconnect)
		cmgd_frntnd_client_schedule_conn_retry(
			clnt_ctxt, clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static inline void cmgd_frntnd_client_sched_msg_write(cmgd_frntnd_client_ctxt_t *clnt_ctxt)
{
	if (!CHECK_FLAG(clnt_ctxt->flags, CMGD_FRNTND_CLNT_FLAGS_WRITES_OFF))
		cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_WRITE);
}

static inline void cmgd_frntnd_client_writes_on(cmgd_frntnd_client_ctxt_t *clnt_ctxt)
{
	CMGD_FRNTND_CLNT_DBG("Resume writing msgs");
	UNSET_FLAG(clnt_ctxt->flags, CMGD_FRNTND_CLNT_FLAGS_WRITES_OFF);
	if (clnt_ctxt->obuf_work || stream_fifo_count_safe(clnt_ctxt->obuf_fifo))
		cmgd_frntnd_client_sched_msg_write(clnt_ctxt);
}

static inline void cmgd_frntnd_client_writes_off(cmgd_frntnd_client_ctxt_t *clnt_ctxt)
{
	SET_FLAG(clnt_ctxt->flags, CMGD_FRNTND_CLNT_FLAGS_WRITES_OFF);
	CMGD_FRNTND_CLNT_DBG("Paused writing msgs");
}

static int cmgd_frntnd_client_send_msg(cmgd_frntnd_client_ctxt_t *clnt_ctxt, 
	Cmgd__FrntndMessage *frntnd_msg)
{
	size_t msg_size;
	uint8_t msg_buf[CMGD_FRNTND_MSG_MAX_LEN];
	cmgd_frntnd_msg_t *msg;

	if (clnt_ctxt->conn_fd == 0)
		return -1;

	msg_size = cmgd__frntnd_message__get_packed_size(frntnd_msg);
	msg_size += CMGD_FRNTND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_FRNTND_CLNT_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_frntnd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_FRNTND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__frntnd_message__pack(frntnd_msg, msg->payload);

#ifndef CMGD_PACK_TX_MSGS
	clnt_ctxt->obuf_work = stream_new(msg_size);
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
	stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
	clnt_ctxt->obuf_work = NULL;
#else
	if (!clnt_ctxt->obuf_work)
		clnt_ctxt->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(clnt_ctxt->obuf_work) < msg_size) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	}
	stream_write(clnt_ctxt->obuf_work, (void *)msg_buf, msg_size);
#endif
	cmgd_frntnd_client_sched_msg_write(clnt_ctxt);
	clnt_ctxt->num_msg_tx++;
	return 0;
}

static int cmgd_frntnd_client_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (clnt_ctxt->obuf_work) {
		stream_fifo_push(clnt_ctxt->obuf_fifo, clnt_ctxt->obuf_work);
		clnt_ctxt->obuf_work = NULL;
	}

	for (s = stream_fifo_head(clnt_ctxt->obuf_fifo);
		s && processed < CMGD_FRNTND_MAX_NUM_MSG_WRITE;
		s = stream_fifo_head(clnt_ctxt->obuf_fifo)) {
		// msg_size = (int)stream_get_size(s);
		msg_size = (int) STREAM_READABLE(s);
		bytes_written = stream_flush(s, clnt_ctxt->conn_fd);
		if (bytes_written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_WRITE);
			return 0;
		} else if (bytes_written != msg_size) {
			CMGD_FRNTND_CLNT_ERR(
				"Could not write all %d bytes (wrote: %d) to CMGD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_WRITE);
				return 0;
			}
			cmgd_frntnd_server_disconnect(clnt_ctxt, true);
			return -1;
		}

		free = stream_fifo_pop(clnt_ctxt->obuf_fifo);
		stream_free(free);
		CMGD_FRNTND_CLNT_DBG(
			"Wrote %d bytes of message to CMGD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		cmgd_frntnd_client_writes_off(clnt_ctxt);
		cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_WRITES_ON);
	}

	return 0;
}

static int cmgd_frntnd_client_resume_writes(struct thread *thread)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	cmgd_frntnd_client_writes_on(clnt_ctxt);

	return 0;
}

static int cmgd_frntnd_send_register_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndRegisterReq rgstr_req;

	cmgd__frntnd_register_req__init(&rgstr_req);
	rgstr_req.client_name = clnt_ctxt->client_params.name;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__REGISTER_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_REGISTER_REQ;
	frntnd_msg.register_req = &rgstr_req;

	CMGD_FRNTND_CLNT_DBG("Sending REGISTER_REQ message to CMGD Frontend server");

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_session_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn, bool create)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSessionReq sess_req;

	cmgd__frntnd_session_req__init(&sess_req);
	sess_req.create = create;
	if (create) {
		sess_req.id_case = CMGD__FRNTND_SESSION_REQ__ID_CLIENT_CONN_ID;
		sess_req.client_conn_id = (uint64_t) sessn->client_id;
	} else {
		sess_req.id_case = CMGD__FRNTND_SESSION_REQ__ID_SESSION_ID;
		sess_req.session_id = (uint64_t) sessn->session_id;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SESSION_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REQ;
	frntnd_msg.sessn_req = &sess_req;

	CMGD_FRNTND_CLNT_DBG("Sending SESSION_REQ message for %s session %lu to CMGD Frontend server",
		create? "creating" : "destroying", sessn->client_id);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_lockdb_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn, bool lock,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndLockDbReq lockdb_req;

	cmgd__frntnd_lock_db_req__init(&lockdb_req);
	lockdb_req.session_id = (uint64_t) sessn->session_id;
	lockdb_req.req_id = req_id;
	lockdb_req.db_id = db_id;
	lockdb_req.lock = lock;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__LOCK_DB_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REQ;
	frntnd_msg.lockdb_req = &lockdb_req;

	CMGD_FRNTND_CLNT_DBG("Sending %sLOCK_REQ message for Db:%d session %lu to CMGD Frontend server",
		lock? "" : "UN", db_id, sessn->client_id);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_setcfg_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id, 
	cmgd_yang_cfgdata_req_t **data_req, int num_data_reqs)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSetConfigReq setcfg_req;

	cmgd__frntnd_set_config_req__init(&setcfg_req);
	setcfg_req.session_id = (uint64_t) sessn->session_id;
	setcfg_req.db_id = db_id;
	setcfg_req.req_id = req_id;
	setcfg_req.data = data_req;
	setcfg_req.n_data = (size_t) num_data_reqs;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REQ;
	frntnd_msg.setcfg_req = &setcfg_req;

	CMGD_FRNTND_CLNT_DBG("Sending SET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to CMGD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_commitcfg_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn, cmgd_client_req_id_t req_id,
	cmgd_database_id_t src_db_id, cmgd_database_id_t dest_db_id, 
	bool validate_only, bool abort)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndCommitConfigReq commitcfg_req;

	cmgd__frntnd_commit_config_req__init(&commitcfg_req);
	commitcfg_req.session_id = (uint64_t) sessn->session_id;
	commitcfg_req.src_db_id = src_db_id;
	commitcfg_req.dst_db_id = dest_db_id;
	commitcfg_req.req_id = req_id;
	commitcfg_req.validate_only = validate_only;
	commitcfg_req.abort = abort;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REQ;
	frntnd_msg.commcfg_req = &commitcfg_req;

	CMGD_FRNTND_CLNT_DBG("Sending COMMIT_CONFIG_REQ message for Src-Db:%d, Dst-Db:%d session %lu to CMGD Frontend server",
		src_db_id, dest_db_id, sessn->client_id);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_getcfg_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id, 
	cmgd_yang_getdata_req_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndGetConfigReq getcfg_req;

	cmgd__frntnd_get_config_req__init(&getcfg_req);
	getcfg_req.session_id = (uint64_t) sessn->session_id;
	getcfg_req.db_id = db_id;
	getcfg_req.req_id = req_id;
	getcfg_req.data = data_req;
	getcfg_req.n_data = (size_t) num_data_reqs;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_GETCFG_REQ;
	frntnd_msg.getcfg_req = &getcfg_req;

	CMGD_FRNTND_CLNT_DBG("Sending GET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to CMGD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_getdata_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id, 
	cmgd_yang_getdata_req_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndGetDataReq getdata_req;

	cmgd__frntnd_get_data_req__init(&getdata_req);
	getdata_req.session_id = (uint64_t) sessn->session_id;
	getdata_req.db_id = db_id;
	getdata_req.req_id = req_id;
	getdata_req.data = data_req;
	getdata_req.n_data = (size_t) num_data_reqs;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__GET_DATA_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_GETDATA_REQ;
	frntnd_msg.getdata_req = &getdata_req;

	CMGD_FRNTND_CLNT_DBG("Sending GET_CONFIG_REQ message for Db:%d session %lu (#xpaths:%d) to CMGD Frontend server",
		db_id, sessn->client_id, num_data_reqs);

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_send_regnotify_req(cmgd_frntnd_client_ctxt_t *clnt_ctxt,
	cmgd_frntnd_client_session_t *sessn,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	bool register_req, cmgd_yang_xpath_t *data_req[], int num_data_reqs)
{
	(void) req_id;
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndRegisterNotifyReq regntfy_req;

	cmgd__frntnd_register_notify_req__init(&regntfy_req);
	regntfy_req.session_id = (uint64_t) sessn->session_id;
	regntfy_req.db_id = db_id;
	regntfy_req.register_req = register_req;
	regntfy_req.data_xpath = data_req;
	regntfy_req.n_data_xpath = (size_t) num_data_reqs;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__REGISTER_NOTIFY_REQ;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_REGNOTIFY_REQ;
	frntnd_msg.regnotify_req = &regntfy_req;

	return cmgd_frntnd_client_send_msg(clnt_ctxt, &frntnd_msg);
}

static int cmgd_frntnd_client_handle_msg(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, Cmgd__FrntndMessage *frntnd_msg)
{
	cmgd_frntnd_client_session_t *sessn = NULL;

	switch(frntnd_msg->type) {
	case CMGD__FRNTND_MESSAGE__TYPE__SESSION_REPLY:
		assert(frntnd_msg->message_case == 
			CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY);
		if (frntnd_msg->sessn_reply->create &&
			frntnd_msg->sessn_reply->has_client_conn_id) {
			CMGD_FRNTND_CLNT_DBG(
				"Got Session Create Reply Msg for client-id %llu with session-id: %llu.", 
				frntnd_msg->sessn_reply->client_conn_id,
				frntnd_msg->sessn_reply->session_id);

			sessn = cmgd_frntnd_find_session_by_client_id(clnt_ctxt,
				frntnd_msg->sessn_reply->client_conn_id);

			if (frntnd_msg->sessn_reply->success) {
				CMGD_FRNTND_CLNT_DBG(
					"Session Create for client-id %llu successful.", 
					frntnd_msg->sessn_reply->client_conn_id);
				sessn->session_id = frntnd_msg->sessn_reply->session_id;
			} else {
				CMGD_FRNTND_CLNT_ERR(
					"Session Create for client-id %llu failed.", 
					frntnd_msg->sessn_reply->client_conn_id);
			}
		} else if (!frntnd_msg->sessn_reply->create) {
			CMGD_FRNTND_CLNT_DBG(
				"Got Session Destroy Reply Msg for session-id %llu", 
				frntnd_msg->sessn_reply->session_id);

			sessn = cmgd_frntnd_find_session_by_sessn_id(clnt_ctxt,
				frntnd_msg->sessn_req->session_id);
		}

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.sess_req_result_cb)
			(*sessn->clnt_ctxt->client_params.sess_req_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id,
				frntnd_msg->sessn_reply->create,
				frntnd_msg->sessn_reply->success,
				(cmgd_session_id_t) sessn, sessn->user_ctxt);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__LOCK_DB_REPLY:
		assert(frntnd_msg->message_case == 
			CMGD__FRNTND_MESSAGE__MESSAGE_LOCKDB_REPLY);
		CMGD_FRNTND_CLNT_DBG(
			"Got LockDb Reply Msg for session-id %llu", 
			frntnd_msg->lockdb_reply->session_id);
		sessn = cmgd_frntnd_find_session_by_sessn_id(clnt_ctxt,
				frntnd_msg->lockdb_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.lock_db_result_cb)
			(*sessn->clnt_ctxt->client_params.lock_db_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (cmgd_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->lockdb_reply->req_id,
				frntnd_msg->lockdb_reply->lock,
				frntnd_msg->lockdb_reply->success,
				frntnd_msg->lockdb_reply->db_id, 
				frntnd_msg->lockdb_reply->error_if_any);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REPLY:
		assert(frntnd_msg->message_case == 
			CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY);

		CMGD_FRNTND_CLNT_DBG(
			"Got Set Config Reply Msg for session-id %llu", 
				frntnd_msg->setcfg_reply->session_id);

		sessn = cmgd_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->setcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.set_config_result_cb)
			(*sessn->clnt_ctxt->client_params.set_config_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (cmgd_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->setcfg_reply->req_id, 
				frntnd_msg->setcfg_reply->success,
				frntnd_msg->setcfg_reply->db_id, 
				frntnd_msg->setcfg_reply->error_if_any);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REPLY:
		assert(frntnd_msg->message_case == 
			CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY);

		CMGD_FRNTND_CLNT_DBG(
			"Got Commit Config Reply Msg for session-id %llu", 
				frntnd_msg->commcfg_reply->session_id);

		sessn = cmgd_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->commcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.commit_cfg_result_cb)
			(*sessn->clnt_ctxt->client_params.commit_cfg_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (cmgd_session_id_t) sessn,
				sessn->user_ctxt,
				frntnd_msg->commcfg_reply->req_id, 
				frntnd_msg->commcfg_reply->success,
				frntnd_msg->commcfg_reply->src_db_id, 
				frntnd_msg->commcfg_reply->dst_db_id, 
				frntnd_msg->commcfg_reply->validate_only,
				frntnd_msg->commcfg_reply->error_if_any);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__GET_CONFIG_REPLY:
		assert(frntnd_msg->message_case ==
			CMGD__FRNTND_MESSAGE__MESSAGE_GETCFG_REPLY);

		CMGD_FRNTND_CLNT_DBG(
			"Got Get Config Reply Msg for session-id %llu",
				frntnd_msg->getcfg_reply->session_id);

		sessn = cmgd_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->getcfg_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.get_data_result_cb)
			(*sessn->clnt_ctxt->client_params.get_data_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (cmgd_session_id_t) sessn,
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
	case CMGD__FRNTND_MESSAGE__TYPE__GET_DATA_REPLY:
		assert(frntnd_msg->message_case ==
			CMGD__FRNTND_MESSAGE__MESSAGE_GETDATA_REPLY);

		CMGD_FRNTND_CLNT_DBG(
			"Got Get Data Reply Msg for session-id %llu",
				frntnd_msg->getdata_reply->session_id);

		sessn = cmgd_frntnd_find_session_by_sessn_id(
				clnt_ctxt, frntnd_msg->getdata_reply->session_id);

		if (sessn && sessn->clnt_ctxt &&
		    sessn->clnt_ctxt->client_params.get_data_result_cb)
			(*sessn->clnt_ctxt->client_params.get_data_result_cb)(
				(cmgd_lib_hndl_t)clnt_ctxt,
				clnt_ctxt->client_params.user_data,
				sessn->client_id, (cmgd_session_id_t) sessn,
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

static int cmgd_frntnd_client_process_msg(cmgd_frntnd_client_ctxt_t *clnt_ctxt, 
	uint8_t *msg_buf, int bytes_read)
{
	Cmgd__FrntndMessage *frntnd_msg;
	cmgd_frntnd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	CMGD_FRNTND_CLNT_DBG("Have %u bytes of messages from CMGD Frontend server to .",
		bytes_read);

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_frntnd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_FRNTND_MSG_MARKER) {
			CMGD_FRNTND_CLNT_DBG(
				"Marker not found in message from CMGD Frontend server.");
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_FRNTND_CLNT_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD Frontend server.", 
				bytes_left, msg->hdr.len);
			break;
		}

		frntnd_msg = cmgd__frntnd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_FRNTND_MSG_HDR_LEN), 
			msg->payload);
		if (!frntnd_msg) {
			CMGD_FRNTND_CLNT_DBG(
				"Failed to decode %d bytes from CMGD Frontend server.", 
				msg->hdr.len);
			continue;
		}

		CMGD_FRNTND_CLNT_DBG(
			"Decoded %d bytes of message(type: %u/%u) from CMGD Frontend server", 
			msg->hdr.len, frntnd_msg->type,
			frntnd_msg->message_case);

		(void) cmgd_frntnd_client_handle_msg(clnt_ctxt, frntnd_msg);

		cmgd__frntnd_message__free_unpacked(frntnd_msg, NULL);
		processed++;
		clnt_ctxt->num_msg_rx++;
	}

	return processed;
}

static int cmgd_frntnd_client_proc_msgbufs(struct thread *thread)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	struct stream *work;
	int processed = 0;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	for ( ; processed < CMGD_FRNTND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(clnt_ctxt->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_frntnd_client_process_msg(
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
		cmgd_frntnd_client_register_event(
			clnt_ctxt, CMGD_FRNTND_PROC_MSG);
	
	return 0;
}

static int cmgd_frntnd_client_read(struct thread *thread)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_frntnd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(clnt_ctxt->ibuf_work) - 
		stream_get_endp(clnt_ctxt->ibuf_work);
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				clnt_ctxt->ibuf_work, clnt_ctxt->conn_fd, bytes_left);
		CMGD_FRNTND_CLNT_DBG(
			"Got %d bytes of message from CMGD Frontend server", 
			bytes_read);
		if (bytes_read <= 0) {
			if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_READ);
				return 0;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				CMGD_FRNTND_CLNT_ERR(
					"Got error (%d) while reading from CMGD Frontend server. Err: '%s'", 
					bytes_read, safe_strerror(errno));
				cmgd_frntnd_server_disconnect(clnt_ctxt, true);
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
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_frntnd_msg_hdr_t *)
			(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_FRNTND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			CMGD_FRNTND_CLNT_ERR(
				"Received corrupted buffer from CMGD frontend server.");
			cmgd_frntnd_server_disconnect(clnt_ctxt, true);
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
	msg_hdr = (cmgd_frntnd_msg_hdr_t *)
		(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
	stream_set_endp(clnt_ctxt->ibuf_work, total_bytes);
	stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);
	clnt_ctxt->ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(clnt_ctxt->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(clnt_ctxt->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_PROC_MSG);

	cmgd_frntnd_client_register_event(clnt_ctxt, CMGD_FRNTND_CONN_READ);

	return 0;
}

static int cmgd_frntnd_server_connect(cmgd_frntnd_client_ctxt_t *clnt_ctxt)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	CMGD_FRNTND_CLNT_DBG("Trying to connect to CMGD Frontend server at %s",
		CMGD_FRNTND_SERVER_PATH);

	assert(!clnt_ctxt->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		CMGD_FRNTND_CLNT_ERR("Failed to create socket");
		goto cmgd_frntnd_server_connect_failed;
	}

	CMGD_FRNTND_CLNT_DBG("Created CMGD Frontend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, CMGD_FRNTND_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		CMGD_FRNTND_CLNT_ERR(
			"Failed to connect to CMGD Frontend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto cmgd_frntnd_server_connect_failed;
	}

	CMGD_FRNTND_CLNT_DBG("Connected to CMGD Frontend Server at %s successfully!",
		addr.sun_path);
	clnt_ctxt->conn_fd = sock;

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);

	thread_add_read(clnt_ctxt->tm, cmgd_frntnd_client_read,
		(void *)&cmgd_frntnd_clntctxt, clnt_ctxt->conn_fd,
		&clnt_ctxt->conn_read_ev);

	/* Send REGISTER_REQ message */
	if (cmgd_frntnd_send_register_req(clnt_ctxt) != 0)
		goto cmgd_frntnd_server_connect_failed;

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(cmgd_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, true);

	return 0;

cmgd_frntnd_server_connect_failed:
	if (sock && sock != clnt_ctxt->conn_fd) {
		close(sock);
	}
	cmgd_frntnd_server_disconnect(clnt_ctxt, true);
	return -1;
}

static int cmgd_frntnd_client_conn_timeout(struct thread *thread)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	clnt_ctxt->conn_retry_tmr = NULL;
	return cmgd_frntnd_server_connect(clnt_ctxt);
}

static void cmgd_frntnd_client_register_event(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, cmgd_event_t event)
{
	switch (event) {
	case CMGD_FRNTND_CONN_READ:
		clnt_ctxt->conn_read_ev = 
			thread_add_read(clnt_ctxt->tm,
				cmgd_frntnd_client_read, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_FRNTND_CONN_WRITE:
		clnt_ctxt->conn_write_ev = 
			thread_add_write(clnt_ctxt->tm,
				cmgd_frntnd_client_write, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_FRNTND_PROC_MSG:
		clnt_ctxt->msg_proc_ev = 
			thread_add_timer_msec(clnt_ctxt->tm,
				cmgd_frntnd_client_proc_msgbufs, clnt_ctxt,
				CMGD_FRNTND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	case CMGD_FRNTND_CONN_WRITES_ON:
		clnt_ctxt->conn_writes_on =
			thread_add_timer_msec(clnt_ctxt->tm,
				cmgd_frntnd_client_resume_writes, clnt_ctxt,
				CMGD_FRNTND_MSG_WRITE_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_frntnd_clnt_ctxt_post_event() called incorrectly");
	}
}

static void cmgd_frntnd_client_schedule_conn_retry(
	cmgd_frntnd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs)
{
	CMGD_FRNTND_CLNT_DBG("Scheduling CMGD Frontend server connection retry after %lu seconds",
		intvl_secs);
	clnt_ctxt->conn_retry_tmr = thread_add_timer(
		clnt_ctxt->tm, cmgd_frntnd_client_conn_timeout,
		(void *)clnt_ctxt, intvl_secs, NULL);
}

/*
 * Initialize library and try connecting with CMGD.
 */
cmgd_lib_hndl_t cmgd_frntnd_client_lib_init(
	cmgd_frntnd_client_params_t *params, 
	struct thread_master *master_thread)
{
	assert(master_thread && params && 
		strlen(params->name) && !cmgd_frntnd_clntctxt.tm);

	cmgd_frntnd_clntctxt.tm = master_thread;
	memcpy(&cmgd_frntnd_clntctxt.client_params, params, 
		sizeof(cmgd_frntnd_clntctxt.client_params));
	if (!cmgd_frntnd_clntctxt.client_params.conn_retry_intvl_sec) 
		cmgd_frntnd_clntctxt.client_params.conn_retry_intvl_sec = 
			CMGD_FRNTND_DEFAULT_CONN_RETRY_INTVL_SEC;

	assert(!cmgd_frntnd_clntctxt.ibuf_fifo &&
		!cmgd_frntnd_clntctxt.ibuf_work &&
		!cmgd_frntnd_clntctxt.obuf_fifo &&
		!cmgd_frntnd_clntctxt.obuf_work);
	
	cmgd_frntnd_clntctxt.ibuf_fifo = stream_fifo_new();
	cmgd_frntnd_clntctxt.ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	cmgd_frntnd_clntctxt.obuf_fifo = stream_fifo_new();
	// cmgd_frntnd_clntctxt.obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
	cmgd_frntnd_clntctxt.obuf_work = NULL;

	cmgd_session_list_init(&cmgd_frntnd_clntctxt.client_sessions);

	/* Start trying to connect to CMGD frontend server immediately */
	cmgd_frntnd_client_schedule_conn_retry(&cmgd_frntnd_clntctxt, 1);

	CMGD_FRNTND_CLNT_DBG("Initialized client '%s'", params->name);

	return (cmgd_lib_hndl_t)&cmgd_frntnd_clntctxt;
}

/*
 * Create a new Session for a Frontend Client connection.
 */
cmgd_result_t cmgd_frntnd_create_client_session(
	cmgd_lib_hndl_t lib_hndl, cmgd_client_id_t client_id,
	uintptr_t user_ctxt)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = XCALLOC(MTYPE_CMGD_FRNTND_SESSION, 
			sizeof(cmgd_frntnd_client_session_t));
	assert(sessn);
	sessn->user_ctxt = user_ctxt;
	sessn->client_id = client_id;
	sessn->clnt_ctxt = clnt_ctxt;
	sessn->session_id = 0;
	cmgd_session_list_add_tail(&clnt_ctxt->client_sessions, sessn);

	if (cmgd_frntnd_send_session_req(clnt_ctxt, sessn, true) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Delete an existing Session for a Frontend Client connection.
 */
cmgd_result_t cmgd_frntnd_destroy_client_session(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_session_req(clnt_ctxt, sessn, false) != 0)
		return CMGD_INTERNAL_ERROR;

	cmgd_session_list_del(&clnt_ctxt->client_sessions, sessn);
	XFREE(MTYPE_CMGD_FRNTND_SESSION, sessn);

	return CMGD_SUCCESS;
}

/*
 * Send UN/LOCK_DB_REQ to CMGD for a specific Datastore DB.
 */
cmgd_result_t cmgd_frntnd_lock_db(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	bool lock_db)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_lockdb_req(
		clnt_ctxt, sessn, lock_db, req_id, db_id) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to CMGD for one or more config data(s).
 */
cmgd_result_t cmgd_frntnd_set_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_cfgdata_req_t **config_req, int num_reqs)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_setcfg_req(
		clnt_ctxt, sessn, req_id, db_id, config_req, num_reqs) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to CMGD for one or more config data(s).
 */
cmgd_result_t cmgd_frntnd_commit_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t src_db_id, 
	cmgd_database_id_t dst_db_id, bool validate_only, bool abort)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_commitcfg_req(
		clnt_ctxt, sessn, req_id, src_db_id, dst_db_id,
		validate_only, abort) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send GET_CONFIG_REQ to CMGD for one or more config data item(s).
 */
cmgd_result_t cmgd_frntnd_get_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_getdata_req_t *data_req[], int num_reqs)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_getcfg_req(
		clnt_ctxt, sessn, req_id, db_id, data_req, num_reqs) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send GET_DATA_REQ to CMGD for one or more config data item(s).
 */
cmgd_result_t cmgd_frntnd_get_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_getdata_req_t *data_req[], int num_reqs)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_getdata_req(
		clnt_ctxt, sessn, req_id, db_id, data_req, num_reqs) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send NOTIFY_REGISTER_REQ to CMGD daemon.
 */
cmgd_result_t cmgd_frntnd_register_yang_notify(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	bool register_req, cmgd_yang_xpath_t *data_req[], int num_reqs)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;
	cmgd_frntnd_client_session_t *sessn;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

	sessn = (cmgd_frntnd_client_session_t *)session_id;
	if (!sessn || sessn->clnt_ctxt != clnt_ctxt)
		return CMGD_INVALID_PARAM;

	if (cmgd_frntnd_send_regnotify_req(
		clnt_ctxt, sessn, req_id, db_id, register_req,
		data_req, num_reqs) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void cmgd_frntnd_client_lib_destroy(cmgd_lib_hndl_t lib_hndl)
{
	cmgd_frntnd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_frntnd_client_ctxt_t *)lib_hndl;
	assert(clnt_ctxt);

	CMGD_FRNTND_CLNT_DBG("Destroying CMGD Frontend Client '%s'", 
		clnt_ctxt->client_params.name);

	cmgd_frntnd_server_disconnect(clnt_ctxt, false);

	assert(cmgd_frntnd_clntctxt.ibuf_fifo &&
		cmgd_frntnd_clntctxt.obuf_fifo);
	
	stream_fifo_free(cmgd_frntnd_clntctxt.ibuf_fifo);
	if (cmgd_frntnd_clntctxt.ibuf_work)
		stream_free(cmgd_frntnd_clntctxt.ibuf_work);
	stream_fifo_free(cmgd_frntnd_clntctxt.obuf_fifo);
	if (cmgd_frntnd_clntctxt.obuf_work)
		stream_free(cmgd_frntnd_clntctxt.obuf_work);
}
