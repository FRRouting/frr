// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "memory.h"
#include "libfrr.h"
#include "mgmt_fe_client.h"
#include "mgmt_pb.h"
#include "network.h"
#include "stream.h"
#include "sockopt.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_FE_CLIENT_DBG(fmt, ...)                                        \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_FE_CLIENT_ERR(fmt, ...)                                        \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_FE_CLIENT_DBG(fmt, ...)                                        \
	do {                                                                 \
		if (mgmt_debug_fe_client)                                    \
			zlog_debug("%s: " fmt, __func__, ##__VA_ARGS__);     \
	} while (0)
#define MGMTD_FE_CLIENT_ERR(fmt, ...)                                        \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct mgmt_fe_client_ctx;

PREDECL_LIST(mgmt_sessions);

struct mgmt_fe_client_session {
	uint64_t client_id;
	uint64_t session_id;
	struct mgmt_fe_client_ctx *client_ctx;
	uintptr_t user_ctx;

	struct mgmt_sessions_item list_linkage;
};

DECLARE_LIST(mgmt_sessions, struct mgmt_fe_client_session, list_linkage);

DEFINE_MTYPE_STATIC(LIB, MGMTD_FE_SESSION, "MGMTD Frontend session");

struct mgmt_fe_client_ctx {
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

	struct mgmt_fe_client_params client_params;

	struct mgmt_sessions_head client_sessions;
};

#define MGMTD_FE_CLIENT_FLAGS_WRITES_OFF (1U << 0)

#define FOREACH_SESSION_IN_LIST(client_ctx, session)                           \
	frr_each_safe (mgmt_sessions, &(client_ctx)->client_sessions, (session))

static bool mgmt_debug_fe_client;

static struct mgmt_fe_client_ctx mgmt_fe_client_ctx = {0};

/* Forward declarations */
static void
mgmt_fe_client_register_event(struct mgmt_fe_client_ctx *client_ctx,
				  enum mgmt_fe_event event);
static void mgmt_fe_client_schedule_conn_retry(
	struct mgmt_fe_client_ctx *client_ctx, unsigned long intvl_secs);

static struct mgmt_fe_client_session *
mgmt_fe_find_session_by_client_id(struct mgmt_fe_client_ctx *client_ctx,
				      uint64_t client_id)
{
	struct mgmt_fe_client_session *session;

	FOREACH_SESSION_IN_LIST (client_ctx, session) {
		if (session->client_id == client_id) {
			MGMTD_FE_CLIENT_DBG(
				"Found session %p for client-id %llu.", session,
				(unsigned long long)client_id);
			return session;
		}
	}

	return NULL;
}

static struct mgmt_fe_client_session *
mgmt_fe_find_session_by_session_id(struct mgmt_fe_client_ctx *client_ctx,
				     uint64_t session_id)
{
	struct mgmt_fe_client_session *session;

	FOREACH_SESSION_IN_LIST (client_ctx, session) {
		if (session->session_id == session_id) {
			MGMTD_FE_CLIENT_DBG(
				"Found session %p for session-id %llu.", session,
				(unsigned long long)session_id);
			return session;
		}
	}

	return NULL;
}

static void
mgmt_fe_server_disconnect(struct mgmt_fe_client_ctx *client_ctx,
			      bool reconnect)
{
	if (client_ctx->conn_fd) {
		close(client_ctx->conn_fd);
		client_ctx->conn_fd = 0;
	}

	if (reconnect)
		mgmt_fe_client_schedule_conn_retry(
			client_ctx,
			client_ctx->client_params.conn_retry_intvl_sec);
}

static inline void
mgmt_fe_client_sched_msg_write(struct mgmt_fe_client_ctx *client_ctx)
{
	if (!CHECK_FLAG(client_ctx->flags, MGMTD_FE_CLIENT_FLAGS_WRITES_OFF))
		mgmt_fe_client_register_event(client_ctx,
						  MGMTD_FE_CONN_WRITE);
}

static inline void
mgmt_fe_client_writes_on(struct mgmt_fe_client_ctx *client_ctx)
{
	MGMTD_FE_CLIENT_DBG("Resume writing msgs");
	UNSET_FLAG(client_ctx->flags, MGMTD_FE_CLIENT_FLAGS_WRITES_OFF);
	if (client_ctx->obuf_work
	    || stream_fifo_count_safe(client_ctx->obuf_fifo))
		mgmt_fe_client_sched_msg_write(client_ctx);
}

static inline void
mgmt_fe_client_writes_off(struct mgmt_fe_client_ctx *client_ctx)
{
	SET_FLAG(client_ctx->flags, MGMTD_FE_CLIENT_FLAGS_WRITES_OFF);
	MGMTD_FE_CLIENT_DBG("Paused writing msgs");
}

static int
mgmt_fe_client_send_msg(struct mgmt_fe_client_ctx *client_ctx,
			    Mgmtd__FeMessage *fe_msg)
{
	size_t msg_size;
	uint8_t msg_buf[MGMTD_FE_MSG_MAX_LEN];
	struct mgmt_fe_msg *msg;

	if (client_ctx->conn_fd == 0)
		return -1;

	msg_size = mgmtd__fe_message__get_packed_size(fe_msg);
	msg_size += MGMTD_FE_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		MGMTD_FE_CLIENT_ERR(
			"Message size %d more than max size'%d. Not sending!'",
			(int)msg_size, (int)sizeof(msg_buf));
		return -1;
	}

	msg = (struct mgmt_fe_msg *)msg_buf;
	msg->hdr.marker = MGMTD_FE_MSG_MARKER;
	msg->hdr.len = (uint16_t)msg_size;
	mgmtd__fe_message__pack(fe_msg, msg->payload);

	if (!client_ctx->obuf_work)
		client_ctx->obuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(client_ctx->obuf_work) < msg_size) {
		stream_fifo_push(client_ctx->obuf_fifo, client_ctx->obuf_work);
		client_ctx->obuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	}
	stream_write(client_ctx->obuf_work, (void *)msg_buf, msg_size);

	mgmt_fe_client_sched_msg_write(client_ctx);
	client_ctx->num_msg_tx++;
	return 0;
}

static void mgmt_fe_client_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	struct mgmt_fe_client_ctx *client_ctx;

	client_ctx = (struct mgmt_fe_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx && client_ctx->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (client_ctx->obuf_work) {
		stream_fifo_push(client_ctx->obuf_fifo, client_ctx->obuf_work);
		client_ctx->obuf_work = NULL;
	}

	for (s = stream_fifo_head(client_ctx->obuf_fifo);
	     s && processed < MGMTD_FE_MAX_NUM_MSG_WRITE;
	     s = stream_fifo_head(client_ctx->obuf_fifo)) {
		/* msg_size = (int)stream_get_size(s); */
		msg_size = (int)STREAM_READABLE(s);
		bytes_written = stream_flush(s, client_ctx->conn_fd);
		if (bytes_written == -1
		    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_fe_client_register_event(
				client_ctx, MGMTD_FE_CONN_WRITE);
			return;
		} else if (bytes_written != msg_size) {
			MGMTD_FE_CLIENT_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_fe_client_register_event(
					client_ctx, MGMTD_FE_CONN_WRITE);
				return;
			}
			mgmt_fe_server_disconnect(client_ctx, true);
			return;
		}

		free = stream_fifo_pop(client_ctx->obuf_fifo);
		stream_free(free);
		MGMTD_FE_CLIENT_DBG(
			"Wrote %d bytes of message to MGMTD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_fe_client_writes_off(client_ctx);
		mgmt_fe_client_register_event(client_ctx,
						  MGMTD_FE_CONN_WRITES_ON);
	}
}

static void mgmt_fe_client_resume_writes(struct thread *thread)
{
	struct mgmt_fe_client_ctx *client_ctx;

	client_ctx = (struct mgmt_fe_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx && client_ctx->conn_fd);

	mgmt_fe_client_writes_on(client_ctx);
}

static int
mgmt_fe_send_register_req(struct mgmt_fe_client_ctx *client_ctx)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeRegisterReq rgstr_req;

	mgmtd__fe_register_req__init(&rgstr_req);
	rgstr_req.client_name = client_ctx->client_params.name;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_REGISTER_REQ;
	fe_msg.register_req = &rgstr_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending REGISTER_REQ message to MGMTD Frontend server");

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_session_req(struct mgmt_fe_client_ctx *client_ctx,
			     struct mgmt_fe_client_session *session,
			     bool create)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeSessionReq sess_req;

	mgmtd__fe_session_req__init(&sess_req);
	sess_req.create = create;
	if (create) {
		sess_req.id_case = MGMTD__FE_SESSION_REQ__ID_CLIENT_CONN_ID;
		sess_req.client_conn_id = session->client_id;
	} else {
		sess_req.id_case = MGMTD__FE_SESSION_REQ__ID_SESSION_ID;
		sess_req.session_id = session->session_id;
	}

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SESSION_REQ;
	fe_msg.session_req = &sess_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending SESSION_REQ message for %s session %llu to MGMTD Frontend server",
		create ? "creating" : "destroying",
		(unsigned long long)session->client_id);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_lockds_req(struct mgmt_fe_client_ctx *client_ctx,
			    struct mgmt_fe_client_session *session, bool lock,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeLockDsReq lockds_req;

	mgmtd__fe_lock_ds_req__init(&lockds_req);
	lockds_req.session_id = session->session_id;
	lockds_req.req_id = req_id;
	lockds_req.ds_id = ds_id;
	lockds_req.lock = lock;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REQ;
	fe_msg.lockds_req = &lockds_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending %sLOCK_REQ message for Ds:%d session %llu to MGMTD Frontend server",
		lock ? "" : "UN", ds_id, (unsigned long long)session->client_id);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_setcfg_req(struct mgmt_fe_client_ctx *client_ctx,
			    struct mgmt_fe_client_session *session,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangCfgDataReq **data_req, int num_data_reqs,
			    bool implicit_commit, Mgmtd__DatastoreId dst_ds_id)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeSetConfigReq setcfg_req;

	mgmtd__fe_set_config_req__init(&setcfg_req);
	setcfg_req.session_id = session->session_id;
	setcfg_req.ds_id = ds_id;
	setcfg_req.req_id = req_id;
	setcfg_req.data = data_req;
	setcfg_req.n_data = (size_t)num_data_reqs;
	setcfg_req.implicit_commit = implicit_commit;
	setcfg_req.commit_ds_id = dst_ds_id;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ;
	fe_msg.setcfg_req = &setcfg_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending SET_CONFIG_REQ message for Ds:%d session %llu (#xpaths:%d) to MGMTD Frontend server",
		ds_id, (unsigned long long)session->client_id, num_data_reqs);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_commitcfg_req(struct mgmt_fe_client_ctx *client_ctx,
			       struct mgmt_fe_client_session *session,
			       uint64_t req_id, Mgmtd__DatastoreId src_ds_id,
			       Mgmtd__DatastoreId dest_ds_id, bool validate_only,
			       bool abort)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeCommitConfigReq commitcfg_req;

	mgmtd__fe_commit_config_req__init(&commitcfg_req);
	commitcfg_req.session_id = session->session_id;
	commitcfg_req.src_ds_id = src_ds_id;
	commitcfg_req.dst_ds_id = dest_ds_id;
	commitcfg_req.req_id = req_id;
	commitcfg_req.validate_only = validate_only;
	commitcfg_req.abort = abort;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ;
	fe_msg.commcfg_req = &commitcfg_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending COMMIT_CONFIG_REQ message for Src-Ds:%d, Dst-Ds:%d session %llu to MGMTD Frontend server",
		src_ds_id, dest_ds_id, (unsigned long long)session->client_id);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_getcfg_req(struct mgmt_fe_client_ctx *client_ctx,
			    struct mgmt_fe_client_session *session,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangGetDataReq * data_req[],
			    int num_data_reqs)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetConfigReq getcfg_req;

	mgmtd__fe_get_config_req__init(&getcfg_req);
	getcfg_req.session_id = session->session_id;
	getcfg_req.ds_id = ds_id;
	getcfg_req.req_id = req_id;
	getcfg_req.data = data_req;
	getcfg_req.n_data = (size_t)num_data_reqs;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REQ;
	fe_msg.getcfg_req = &getcfg_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending GET_CONFIG_REQ message for Ds:%d session %llu (#xpaths:%d) to MGMTD Frontend server",
		ds_id, (unsigned long long)session->client_id, num_data_reqs);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_send_getdata_req(struct mgmt_fe_client_ctx *client_ctx,
			     struct mgmt_fe_client_session *session,
			     uint64_t req_id, Mgmtd__DatastoreId ds_id,
			     Mgmtd__YangGetDataReq * data_req[],
			     int num_data_reqs)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetDataReq getdata_req;

	mgmtd__fe_get_data_req__init(&getdata_req);
	getdata_req.session_id = session->session_id;
	getdata_req.ds_id = ds_id;
	getdata_req.req_id = req_id;
	getdata_req.data = data_req;
	getdata_req.n_data = (size_t)num_data_reqs;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REQ;
	fe_msg.getdata_req = &getdata_req;

	MGMTD_FE_CLIENT_DBG(
		"Sending GET_CONFIG_REQ message for Ds:%d session %llu (#xpaths:%d) to MGMTD Frontend server",
		ds_id, (unsigned long long)session->client_id, num_data_reqs);

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int mgmt_fe_send_regnotify_req(
	struct mgmt_fe_client_ctx *client_ctx,
	struct mgmt_fe_client_session *session, uint64_t req_id,
	Mgmtd__DatastoreId ds_id, bool register_req,
	Mgmtd__YangDataXPath * data_req[], int num_data_reqs)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeRegisterNotifyReq regntfy_req;

	mgmtd__fe_register_notify_req__init(&regntfy_req);
	regntfy_req.session_id = session->session_id;
	regntfy_req.ds_id = ds_id;
	regntfy_req.register_req = register_req;
	regntfy_req.data_xpath = data_req;
	regntfy_req.n_data_xpath = (size_t)num_data_reqs;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_REGNOTIFY_REQ;
	fe_msg.regnotify_req = &regntfy_req;

	return mgmt_fe_client_send_msg(client_ctx, &fe_msg);
}

static int
mgmt_fe_client_handle_msg(struct mgmt_fe_client_ctx *client_ctx,
			      Mgmtd__FeMessage *fe_msg)
{
	struct mgmt_fe_client_session *session = NULL;

	switch (fe_msg->message_case) {
	case MGMTD__FE_MESSAGE__MESSAGE_SESSION_REPLY:
		if (fe_msg->session_reply->create
		    && fe_msg->session_reply->has_client_conn_id) {
			MGMTD_FE_CLIENT_DBG(
				"Got Session Create Reply Msg for client-id %llu with session-id: %llu.",
				(unsigned long long)
					fe_msg->session_reply->client_conn_id,
				(unsigned long long)
					fe_msg->session_reply->session_id);

			session = mgmt_fe_find_session_by_client_id(
				client_ctx,
				fe_msg->session_reply->client_conn_id);

			if (session && fe_msg->session_reply->success) {
				MGMTD_FE_CLIENT_DBG(
					"Session Create for client-id %llu successful.",
					(unsigned long long)fe_msg
						->session_reply->client_conn_id);
				session->session_id =
					fe_msg->session_reply->session_id;
			} else {
				MGMTD_FE_CLIENT_ERR(
					"Session Create for client-id %llu failed.",
					(unsigned long long)fe_msg
						->session_reply->client_conn_id);
			}
		} else if (!fe_msg->session_reply->create) {
			MGMTD_FE_CLIENT_DBG(
				"Got Session Destroy Reply Msg for session-id %llu",
				(unsigned long long)
					fe_msg->session_reply->session_id);

			session = mgmt_fe_find_session_by_session_id(
				client_ctx, fe_msg->session_req->session_id);
		}

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .client_session_notify)
			(*session->client_ctx->client_params
				  .client_session_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id,
				fe_msg->session_reply->create,
				fe_msg->session_reply->success,
				(uintptr_t)session, session->user_ctx);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REPLY:
		MGMTD_FE_CLIENT_DBG(
			"Got LockDs Reply Msg for session-id %llu",
			(unsigned long long)
				fe_msg->lockds_reply->session_id);
		session = mgmt_fe_find_session_by_session_id(
			client_ctx, fe_msg->lockds_reply->session_id);

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .lock_ds_notify)
			(*session->client_ctx->client_params
				  .lock_ds_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id, (uintptr_t)session,
				session->user_ctx,
				fe_msg->lockds_reply->req_id,
				fe_msg->lockds_reply->lock,
				fe_msg->lockds_reply->success,
				fe_msg->lockds_reply->ds_id,
				fe_msg->lockds_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY:
		MGMTD_FE_CLIENT_DBG(
			"Got Set Config Reply Msg for session-id %llu",
			(unsigned long long)
				fe_msg->setcfg_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client_ctx, fe_msg->setcfg_reply->session_id);

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .set_config_notify)
			(*session->client_ctx->client_params
				  .set_config_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id, (uintptr_t)session,
				session->user_ctx,
				fe_msg->setcfg_reply->req_id,
				fe_msg->setcfg_reply->success,
				fe_msg->setcfg_reply->ds_id,
				fe_msg->setcfg_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REPLY:
		MGMTD_FE_CLIENT_DBG(
			"Got Commit Config Reply Msg for session-id %llu",
			(unsigned long long)
				fe_msg->commcfg_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client_ctx, fe_msg->commcfg_reply->session_id);

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .commit_config_notify)
			(*session->client_ctx->client_params
				  .commit_config_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id, (uintptr_t)session,
				session->user_ctx,
				fe_msg->commcfg_reply->req_id,
				fe_msg->commcfg_reply->success,
				fe_msg->commcfg_reply->src_ds_id,
				fe_msg->commcfg_reply->dst_ds_id,
				fe_msg->commcfg_reply->validate_only,
				fe_msg->commcfg_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REPLY:
		MGMTD_FE_CLIENT_DBG(
			"Got Get Config Reply Msg for session-id %llu",
			(unsigned long long)
				fe_msg->getcfg_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client_ctx, fe_msg->getcfg_reply->session_id);

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .get_data_notify)
			(*session->client_ctx->client_params
				  .get_data_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id, (uintptr_t)session,
				session->user_ctx,
				fe_msg->getcfg_reply->req_id,
				fe_msg->getcfg_reply->success,
				fe_msg->getcfg_reply->ds_id,
				fe_msg->getcfg_reply->data
					? fe_msg->getcfg_reply->data->data
					: NULL,
				fe_msg->getcfg_reply->data
					? fe_msg->getcfg_reply->data->n_data
					: 0,
				fe_msg->getcfg_reply->data
					? fe_msg->getcfg_reply->data
						  ->next_indx
					: 0,
				fe_msg->getcfg_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REPLY:
		MGMTD_FE_CLIENT_DBG(
			"Got Get Data Reply Msg for session-id %llu",
			(unsigned long long)
				fe_msg->getdata_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client_ctx, fe_msg->getdata_reply->session_id);

		if (session && session->client_ctx
		    && session->client_ctx->client_params
			       .get_data_notify)
			(*session->client_ctx->client_params
				  .get_data_notify)(
				(uintptr_t)client_ctx,
				client_ctx->client_params.user_data,
				session->client_id, (uintptr_t)session,
				session->user_ctx,
				fe_msg->getdata_reply->req_id,
				fe_msg->getdata_reply->success,
				fe_msg->getdata_reply->ds_id,
				fe_msg->getdata_reply->data
					? fe_msg->getdata_reply->data->data
					: NULL,
				fe_msg->getdata_reply->data
					? fe_msg->getdata_reply->data
						  ->n_data
					: 0,
				fe_msg->getdata_reply->data
					? fe_msg->getdata_reply->data
						  ->next_indx
					: 0,
				fe_msg->getdata_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_NOTIFY_DATA_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_REGNOTIFY_REQ:
		/*
		 * TODO: Add handling code in future.
		 */
		break;
	/*
	 * NOTE: The following messages are always sent from Frontend
	 * clients to MGMTd only and/or need not be handled here.
	 */
	case MGMTD__FE_MESSAGE__MESSAGE_REGISTER_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_SESSION_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_GETCFG_REQ:
	case MGMTD__FE_MESSAGE__MESSAGE_GETDATA_REQ:
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

static int
mgmt_fe_client_process_msg(struct mgmt_fe_client_ctx *client_ctx,
			       uint8_t *msg_buf, int bytes_read)
{
	Mgmtd__FeMessage *fe_msg;
	struct mgmt_fe_msg *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	MGMTD_FE_CLIENT_DBG(
		"Have %u bytes of messages from MGMTD Frontend server to .",
		bytes_read);

	bytes_left = bytes_read;
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;
	     bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (struct mgmt_fe_msg *)msg_buf;
		if (msg->hdr.marker != MGMTD_FE_MSG_MARKER) {
			MGMTD_FE_CLIENT_DBG(
				"Marker not found in message from MGMTD Frontend server.");
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_FE_CLIENT_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD Frontend server.",
				bytes_left, msg->hdr.len);
			break;
		}

		fe_msg = mgmtd__fe_message__unpack(
			NULL, (size_t)(msg->hdr.len - MGMTD_FE_MSG_HDR_LEN),
			msg->payload);
		if (!fe_msg) {
			MGMTD_FE_CLIENT_DBG(
				"Failed to decode %d bytes from MGMTD Frontend server.",
				msg->hdr.len);
			continue;
		}

		MGMTD_FE_CLIENT_DBG(
			"Decoded %d bytes of message(msg: %u/%u) from MGMTD Frontend server",
			msg->hdr.len, fe_msg->message_case,
			fe_msg->message_case);

		(void)mgmt_fe_client_handle_msg(client_ctx, fe_msg);

		mgmtd__fe_message__free_unpacked(fe_msg, NULL);
		processed++;
		client_ctx->num_msg_rx++;
	}

	return processed;
}

static void mgmt_fe_client_proc_msgbufs(struct thread *thread)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct stream *work;
	int processed = 0;

	client_ctx = (struct mgmt_fe_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx && client_ctx->conn_fd);

	for (; processed < MGMTD_FE_MAX_NUM_MSG_PROC;) {
		work = stream_fifo_pop_safe(client_ctx->ibuf_fifo);
		if (!work)
			break;

		processed += mgmt_fe_client_process_msg(
			client_ctx, STREAM_DATA(work), stream_get_endp(work));

		if (work != client_ctx->ibuf_work) {
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
	if (stream_fifo_head(client_ctx->ibuf_fifo))
		mgmt_fe_client_register_event(client_ctx,
						  MGMTD_FE_PROC_MSG);
}

static void mgmt_fe_client_read(struct thread *thread)
{
	struct mgmt_fe_client_ctx *client_ctx;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	struct mgmt_fe_msg_hdr *msg_hdr;
	bool incomplete = false;

	client_ctx = (struct mgmt_fe_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx && client_ctx->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(client_ctx->ibuf_work)
		     - stream_get_endp(client_ctx->ibuf_work);
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;) {
		bytes_read = stream_read_try(client_ctx->ibuf_work,
					     client_ctx->conn_fd, bytes_left);
		MGMTD_FE_CLIENT_DBG(
			"Got %d bytes of message from MGMTD Frontend server",
			bytes_read);
		/* -2 is normal nothing read, and to retry */
		if (bytes_read == -2)
			break;
		if (bytes_read <= 0) {
			if (bytes_read == 0) {
				MGMTD_FE_CLIENT_ERR(
					"Got EOF/disconnect while reading from MGMTD Frontend server.");
			} else {
				/* Fatal error */
				MGMTD_FE_CLIENT_ERR(
					"Got error (%d) while reading from MGMTD Frontend server. Err: '%s'",
					bytes_read, safe_strerror(errno));
			}
			mgmt_fe_server_disconnect(client_ctx, true);
			return;
		}
		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we have read complete messages or not.
	 */
	stream_set_getp(client_ctx->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(client_ctx->ibuf_work);
	for (; bytes_left > MGMTD_FE_MSG_HDR_LEN;) {
		msg_hdr = (struct mgmt_fe_msg_hdr
				   *)(STREAM_DATA(client_ctx->ibuf_work)
				      + total_bytes);
		if (msg_hdr->marker != MGMTD_FE_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_FE_CLIENT_ERR(
				"Received corrupted buffer from MGMTD frontend server.");
			mgmt_fe_server_disconnect(client_ctx, true);
			return;
		}
		if (msg_hdr->len > bytes_left)
			break;

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	if (!msg_cnt)
		goto resched;

	if (bytes_left > 0)
		incomplete = true;

	/*
	 * We have read one or several messages.
	 * Schedule processing them now.
	 */
	msg_hdr =
		(struct mgmt_fe_msg_hdr *)(STREAM_DATA(client_ctx->ibuf_work)
					       + total_bytes);
	stream_set_endp(client_ctx->ibuf_work, total_bytes);
	stream_fifo_push(client_ctx->ibuf_fifo, client_ctx->ibuf_work);
	client_ctx->ibuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(client_ctx->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(client_ctx->ibuf_work, bytes_left);
	}

	mgmt_fe_client_register_event(client_ctx, MGMTD_FE_PROC_MSG);

resched:
	mgmt_fe_client_register_event(client_ctx, MGMTD_FE_CONN_READ);
}

static int mgmt_fe_server_connect(struct mgmt_fe_client_ctx *client_ctx)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	MGMTD_FE_CLIENT_DBG(
		"Trying to connect to MGMTD Frontend server at %s",
		MGMTD_FE_SERVER_PATH);

	assert(!client_ctx->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		MGMTD_FE_CLIENT_ERR("Failed to create socket");
		goto mgmt_fe_server_connect_failed;
	}

	MGMTD_FE_CLIENT_DBG(
		"Created MGMTD Frontend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, MGMTD_FE_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		MGMTD_FE_CLIENT_ERR(
			"Failed to connect to MGMTD Frontend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto mgmt_fe_server_connect_failed;
	}

	MGMTD_FE_CLIENT_DBG(
		"Connected to MGMTD Frontend Server at %s successfully!",
		addr.sun_path);
	client_ctx->conn_fd = sock;

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);
	setsockopt_so_sendbuf(client_ctx->conn_fd,
			      MGMTD_SOCKET_FE_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(client_ctx->conn_fd,
			      MGMTD_SOCKET_FE_RECV_BUF_SIZE);

	thread_add_read(client_ctx->tm, mgmt_fe_client_read,
			(void *)&mgmt_fe_client_ctx, client_ctx->conn_fd,
			&client_ctx->conn_read_ev);
	assert(client_ctx->conn_read_ev);

	/* Send REGISTER_REQ message */
	if (mgmt_fe_send_register_req(client_ctx) != 0)
		goto mgmt_fe_server_connect_failed;

	/* Notify client through registered callback (if any) */
	if (client_ctx->client_params.client_connect_notify)
		(void)(*client_ctx->client_params.client_connect_notify)(
			(uintptr_t)client_ctx,
			client_ctx->client_params.user_data, true);

	return 0;

mgmt_fe_server_connect_failed:
	if (sock && sock != client_ctx->conn_fd)
		close(sock);

	mgmt_fe_server_disconnect(client_ctx, true);
	return -1;
}

static void mgmt_fe_client_conn_timeout(struct thread *thread)
{
	struct mgmt_fe_client_ctx *client_ctx;

	client_ctx = (struct mgmt_fe_client_ctx *)THREAD_ARG(thread);
	assert(client_ctx);

	mgmt_fe_server_connect(client_ctx);
}

static void
mgmt_fe_client_register_event(struct mgmt_fe_client_ctx *client_ctx,
				  enum mgmt_fe_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_FE_CONN_READ:
		thread_add_read(client_ctx->tm, mgmt_fe_client_read,
				client_ctx, client_ctx->conn_fd,
				&client_ctx->conn_read_ev);
		assert(client_ctx->conn_read_ev);
		break;
	case MGMTD_FE_CONN_WRITE:
		thread_add_write(client_ctx->tm, mgmt_fe_client_write,
				 client_ctx, client_ctx->conn_fd,
				 &client_ctx->conn_write_ev);
		assert(client_ctx->conn_write_ev);
		break;
	case MGMTD_FE_PROC_MSG:
		tv.tv_usec = MGMTD_FE_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(client_ctx->tm,
				    mgmt_fe_client_proc_msgbufs, client_ctx,
				    &tv, &client_ctx->msg_proc_ev);
		assert(client_ctx->msg_proc_ev);
		break;
	case MGMTD_FE_CONN_WRITES_ON:
		thread_add_timer_msec(
			client_ctx->tm, mgmt_fe_client_resume_writes,
			client_ctx, MGMTD_FE_MSG_WRITE_DELAY_MSEC,
			&client_ctx->conn_writes_on);
		assert(client_ctx->conn_writes_on);
		break;
	case MGMTD_FE_SERVER:
		assert(!"mgmt_fe_client_ctx_post_event called incorrectly");
		break;
	}
}

static void mgmt_fe_client_schedule_conn_retry(
	struct mgmt_fe_client_ctx *client_ctx, unsigned long intvl_secs)
{
	MGMTD_FE_CLIENT_DBG(
		"Scheduling MGMTD Frontend server connection retry after %lu seconds",
		intvl_secs);
	thread_add_timer(client_ctx->tm, mgmt_fe_client_conn_timeout,
			 (void *)client_ctx, intvl_secs,
			 &client_ctx->conn_retry_tmr);
}

/*
 * Initialize library and try connecting with MGMTD.
 */
uintptr_t mgmt_fe_client_lib_init(struct mgmt_fe_client_params *params,
				     struct thread_master *master_thread)
{
	assert(master_thread && params && strlen(params->name)
	       && !mgmt_fe_client_ctx.tm);

	mgmt_fe_client_ctx.tm = master_thread;
	memcpy(&mgmt_fe_client_ctx.client_params, params,
	       sizeof(mgmt_fe_client_ctx.client_params));
	if (!mgmt_fe_client_ctx.client_params.conn_retry_intvl_sec)
		mgmt_fe_client_ctx.client_params.conn_retry_intvl_sec =
			MGMTD_FE_DEFAULT_CONN_RETRY_INTVL_SEC;

	assert(!mgmt_fe_client_ctx.ibuf_fifo
	       && !mgmt_fe_client_ctx.ibuf_work
	       && !mgmt_fe_client_ctx.obuf_fifo
	       && !mgmt_fe_client_ctx.obuf_work);

	mgmt_fe_client_ctx.ibuf_fifo = stream_fifo_new();
	mgmt_fe_client_ctx.ibuf_work = stream_new(MGMTD_FE_MSG_MAX_LEN);
	mgmt_fe_client_ctx.obuf_fifo = stream_fifo_new();

	mgmt_fe_client_ctx.obuf_work = NULL;

	mgmt_sessions_init(&mgmt_fe_client_ctx.client_sessions);

	/* Start trying to connect to MGMTD frontend server immediately */
	mgmt_fe_client_schedule_conn_retry(&mgmt_fe_client_ctx, 1);

	MGMTD_FE_CLIENT_DBG("Initialized client '%s'", params->name);

	return (uintptr_t)&mgmt_fe_client_ctx;
}

/*
 * Create a new Session for a Frontend Client connection.
 */
enum mgmt_result mgmt_fe_create_client_session(uintptr_t lib_hndl,
						   uint64_t client_id,
						   uintptr_t user_ctx)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = XCALLOC(MTYPE_MGMTD_FE_SESSION,
			sizeof(struct mgmt_fe_client_session));
	assert(session);
	session->user_ctx = user_ctx;
	session->client_id = client_id;
	session->client_ctx = client_ctx;
	session->session_id = 0;

	if (mgmt_fe_send_session_req(client_ctx, session, true) != 0) {
		XFREE(MTYPE_MGMTD_FE_SESSION, session);
		return MGMTD_INTERNAL_ERROR;
	}
	mgmt_sessions_add_tail(&client_ctx->client_sessions, session);

	return MGMTD_SUCCESS;
}

/*
 * Delete an existing Session for a Frontend Client connection.
 */
enum mgmt_result mgmt_fe_destroy_client_session(uintptr_t lib_hndl,
						uint64_t client_id)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = mgmt_fe_find_session_by_client_id(client_ctx, client_id);
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (session->session_id &&
	    mgmt_fe_send_session_req(client_ctx, session, false) != 0)
		MGMTD_FE_CLIENT_ERR(
			"Failed to send session destroy request for the session-id %lu",
			(unsigned long)session->session_id);

	mgmt_sessions_del(&client_ctx->client_sessions, session);
	XFREE(MTYPE_MGMTD_FE_SESSION, session);

	return MGMTD_SUCCESS;
}

static void mgmt_fe_destroy_client_sessions(uintptr_t lib_hndl)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return;

	FOREACH_SESSION_IN_LIST (client_ctx, session)
		mgmt_fe_destroy_client_session(lib_hndl, session->client_id);
}

/*
 * Send UN/LOCK_DS_REQ to MGMTD for a specific Datastore DS.
 */
enum mgmt_result mgmt_fe_lock_ds(uintptr_t lib_hndl, uintptr_t session_id,
				     uint64_t req_id, Mgmtd__DatastoreId ds_id,
				     bool lock_ds)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_lockds_req(client_ctx, session, lock_ds, req_id,
					ds_id)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
enum mgmt_result
mgmt_fe_set_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangCfgDataReq **config_req, int num_reqs,
			    bool implicit_commit, Mgmtd__DatastoreId dst_ds_id)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_setcfg_req(client_ctx, session, req_id, ds_id,
					config_req, num_reqs, implicit_commit,
					dst_ds_id)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
enum mgmt_result mgmt_fe_commit_config_data(uintptr_t lib_hndl,
						uintptr_t session_id,
						uint64_t req_id,
						Mgmtd__DatastoreId src_ds_id,
						Mgmtd__DatastoreId dst_ds_id,
						bool validate_only, bool abort)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_commitcfg_req(client_ctx, session, req_id, src_ds_id,
					   dst_ds_id, validate_only, abort)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send GET_CONFIG_REQ to MGMTD for one or more config data item(s).
 */
enum mgmt_result
mgmt_fe_get_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangGetDataReq * data_req[], int num_reqs)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_getcfg_req(client_ctx, session, req_id, ds_id,
					data_req, num_reqs)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send GET_DATA_REQ to MGMTD for one or more config data item(s).
 */
enum mgmt_result mgmt_fe_get_data(uintptr_t lib_hndl, uintptr_t session_id,
				      uint64_t req_id, Mgmtd__DatastoreId ds_id,
				      Mgmtd__YangGetDataReq * data_req[],
				      int num_reqs)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_getdata_req(client_ctx, session, req_id, ds_id,
					 data_req, num_reqs)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Send NOTIFY_REGISTER_REQ to MGMTD daemon.
 */
enum mgmt_result
mgmt_fe_register_yang_notify(uintptr_t lib_hndl, uintptr_t session_id,
				 uint64_t req_id, Mgmtd__DatastoreId ds_id,
				 bool register_req,
				 Mgmtd__YangDataXPath * data_req[],
				 int num_reqs)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct mgmt_fe_client_session *session;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	if (!client_ctx)
		return MGMTD_INVALID_PARAM;

	session = (struct mgmt_fe_client_session *)session_id;
	if (!session || session->client_ctx != client_ctx)
		return MGMTD_INVALID_PARAM;

	if (mgmt_fe_send_regnotify_req(client_ctx, session, req_id, ds_id,
					   register_req, data_req, num_reqs)
	    != 0)
		return MGMTD_INTERNAL_ERROR;

	return MGMTD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void mgmt_fe_client_lib_destroy(uintptr_t lib_hndl)
{
	struct mgmt_fe_client_ctx *client_ctx;

	client_ctx = (struct mgmt_fe_client_ctx *)lib_hndl;
	assert(client_ctx);

	MGMTD_FE_CLIENT_DBG("Destroying MGMTD Frontend Client '%s'",
			      client_ctx->client_params.name);

	mgmt_fe_server_disconnect(client_ctx, false);

	assert(mgmt_fe_client_ctx.ibuf_fifo && mgmt_fe_client_ctx.obuf_fifo);

	mgmt_fe_destroy_client_sessions(lib_hndl);

	THREAD_OFF(client_ctx->conn_retry_tmr);
	THREAD_OFF(client_ctx->conn_read_ev);
	THREAD_OFF(client_ctx->conn_write_ev);
	THREAD_OFF(client_ctx->conn_writes_on);
	THREAD_OFF(client_ctx->msg_proc_ev);
	stream_fifo_free(mgmt_fe_client_ctx.ibuf_fifo);
	if (mgmt_fe_client_ctx.ibuf_work)
		stream_free(mgmt_fe_client_ctx.ibuf_work);
	stream_fifo_free(mgmt_fe_client_ctx.obuf_fifo);
	if (mgmt_fe_client_ctx.obuf_work)
		stream_free(mgmt_fe_client_ctx.obuf_work);
}
