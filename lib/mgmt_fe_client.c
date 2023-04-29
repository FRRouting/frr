// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "compiler.h"
#include "debug.h"
#include "memory.h"
#include "libfrr.h"
#include "mgmt_fe_client.h"
#include "mgmt_msg.h"
#include "mgmt_pb.h"
#include "network.h"
#include "stream.h"
#include "sockopt.h"

#include "lib/mgmt_fe_client_clippy.c"

#define MGMTD_FE_CLIENT_DBG(fmt, ...)                                          \
	DEBUGD(&mgmt_dbg_fe_client, "%s:" fmt, __func__, ##__VA_ARGS__)
#define MGMTD_FE_CLIENT_ERR(fmt, ...)                                          \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#define MGMTD_DBG_FE_CLIENT_CHECK()                                            \
	DEBUG_MODE_CHECK(&mgmt_dbg_fe_client, DEBUG_MODE_ALL)

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
	struct msg_client client;
	struct mgmt_fe_client_params client_params;
	struct mgmt_sessions_head client_sessions;
};

#define FOREACH_SESSION_IN_LIST(client_ctx, session)                           \
	frr_each_safe (mgmt_sessions, &(client_ctx)->client_sessions, (session))

struct debug mgmt_dbg_fe_client = {0, "Management frontend client operations"};

static struct mgmt_fe_client_ctx mgmt_fe_client_ctx = {
	.client = {.conn = {.fd = -1}}};

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
				"Found session %p for session-id %llu.",
				session, (unsigned long long)session_id);
			return session;
		}
	}

	return NULL;
}

static int mgmt_fe_client_send_msg(struct mgmt_fe_client_ctx *client_ctx,
				   Mgmtd__FeMessage *fe_msg)
{
	return msg_conn_send_msg(
		&client_ctx->client.conn, MGMT_MSG_VERSION_PROTOBUF, fe_msg,
		mgmtd__fe_message__get_packed_size(fe_msg),
		(size_t(*)(void *, void *))mgmtd__fe_message__pack);
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
		lock ? "" : "UN", ds_id,
		(unsigned long long)session->client_id);

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

static int mgmt_fe_send_commitcfg_req(struct mgmt_fe_client_ctx *client_ctx,
				      struct mgmt_fe_client_session *session,
				      uint64_t req_id,
				      Mgmtd__DatastoreId src_ds_id,
				      Mgmtd__DatastoreId dest_ds_id,
				      bool validate_only, bool abort)
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

	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)fe_msg->message_case) {
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
					(unsigned long long)
						fe_msg->session_reply
							->client_conn_id);
				session->session_id =
					fe_msg->session_reply->session_id;
			} else {
				MGMTD_FE_CLIENT_ERR(
					"Session Create for client-id %llu failed.",
					(unsigned long long)
						fe_msg->session_reply
							->client_conn_id);
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

static void mgmt_fe_client_process_msg(uint8_t version, uint8_t *data,
				       size_t len, struct msg_conn *conn)
{
	struct mgmt_fe_client_ctx *client_ctx;
	struct msg_client *client;
	Mgmtd__FeMessage *fe_msg;

	client = container_of(conn, struct msg_client, conn);
	client_ctx = container_of(client, struct mgmt_fe_client_ctx, client);

	fe_msg = mgmtd__fe_message__unpack(NULL, len, data);
	if (!fe_msg) {
		MGMTD_FE_CLIENT_DBG("Failed to decode %zu bytes from server.",
				    len);
		return;
	}
	MGMTD_FE_CLIENT_DBG(
		"Decoded %zu bytes of message(msg: %u/%u) from server", len,
		fe_msg->message_case, fe_msg->message_case);
	(void)mgmt_fe_client_handle_msg(client_ctx, fe_msg);
	mgmtd__fe_message__free_unpacked(fe_msg, NULL);
}

static int _notify_connect_disconnect(struct msg_client *client, bool connected)
{
	struct mgmt_fe_client_ctx *client_ctx =
		container_of(client, struct mgmt_fe_client_ctx, client);
	int ret;

	/* Send REGISTER_REQ message */
	if (connected) {
		if ((ret = mgmt_fe_send_register_req(client_ctx)) != 0)
			return ret;
	}

	/* Notify FE client through registered callback (if any). */
	if (client_ctx->client_params.client_connect_notify)
		(void)(*client_ctx->client_params.client_connect_notify)(
			(uintptr_t)client_ctx,
			client_ctx->client_params.user_data, connected);
	return 0;
}

static int mgmt_fe_client_notify_connect(struct msg_client *client)
{
	return _notify_connect_disconnect(client, true);
}

static int mgmt_fe_client_notify_disconnect(struct msg_conn *conn)
{
	struct msg_client *client = container_of(conn, struct msg_client, conn);

	return _notify_connect_disconnect(client, false);
}


DEFPY(debug_mgmt_client_fe, debug_mgmt_client_fe_cmd,
      "[no] debug mgmt client frontend",
      NO_STR DEBUG_STR MGMTD_STR
      "client\n"
      "frontend\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	DEBUG_MODE_SET(&mgmt_dbg_fe_client, mode, !no);

	return CMD_SUCCESS;
}

static void mgmt_debug_client_fe_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&mgmt_dbg_fe_client, flags, set);
}

static int mgmt_debug_fe_client_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&mgmt_dbg_fe_client, DEBUG_MODE_CONF))
		vty_out(vty, "debug mgmt client frontend\n");

	return CMD_SUCCESS;
}

void mgmt_debug_fe_client_show_debug(struct vty *vty)
{
	if (MGMTD_DBG_FE_CLIENT_CHECK())
		vty_out(vty, "debug mgmt client frontend\n");
}

static struct debug_callbacks mgmt_dbg_fe_client_cbs = {
	.debug_set_all = mgmt_debug_client_fe_set_all};

static struct cmd_node mgmt_dbg_node = {
	.name = "mgmt client frontend",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = mgmt_debug_fe_client_config_write,
};

/*
 * Initialize library and try connecting with MGMTD.
 */
uintptr_t mgmt_fe_client_lib_init(struct mgmt_fe_client_params *params,
				  struct event_loop *master_thread)
{
	/* Don't call twice */
	assert(!mgmt_fe_client_ctx.client.conn.loop);

	mgmt_fe_client_ctx.client_params = *params;

	mgmt_sessions_init(&mgmt_fe_client_ctx.client_sessions);

	msg_client_init(&mgmt_fe_client_ctx.client, master_thread,
			MGMTD_FE_SERVER_PATH, mgmt_fe_client_notify_connect,
			mgmt_fe_client_notify_disconnect,
			mgmt_fe_client_process_msg, MGMTD_FE_MAX_NUM_MSG_PROC,
			MGMTD_FE_MAX_NUM_MSG_WRITE, MGMTD_FE_MSG_MAX_LEN,
			"FE-client", MGMTD_DBG_FE_CLIENT_CHECK());

	MGMTD_FE_CLIENT_DBG("Initialized client '%s'", params->name);

	return (uintptr_t)&mgmt_fe_client_ctx;
}

void mgmt_fe_client_lib_vty_init(void)
{
	debug_init(&mgmt_dbg_fe_client_cbs);
	install_node(&mgmt_dbg_node);
	install_element(ENABLE_NODE, &debug_mgmt_client_fe_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_client_fe_cmd);
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
void mgmt_fe_client_lib_destroy(void)
{
	struct mgmt_fe_client_ctx *client_ctx = &mgmt_fe_client_ctx;

	MGMTD_FE_CLIENT_DBG("Destroying MGMTD Frontend Client '%s'",
			      client_ctx->client_params.name);

	mgmt_fe_destroy_client_sessions((uintptr_t)client_ctx);
	msg_client_cleanup(&client_ctx->client);
	memset(client_ctx, 0, sizeof(*client_ctx));
}
