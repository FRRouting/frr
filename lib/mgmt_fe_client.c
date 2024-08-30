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
#include "mgmt_msg_native.h"
#include "mgmt_pb.h"
#include "network.h"
#include "stream.h"
#include "sockopt.h"

#include "lib/mgmt_fe_client_clippy.c"

PREDECL_LIST(mgmt_sessions);

struct mgmt_fe_client_session {
	uint64_t client_id;  /* FE client identifies itself with this ID */
	uint64_t session_id; /* FE adapter identified session with this ID */
	struct mgmt_fe_client *client;
	uintptr_t user_ctx;

	struct mgmt_sessions_item list_linkage;
};

DECLARE_LIST(mgmt_sessions, struct mgmt_fe_client_session, list_linkage);

DEFINE_MTYPE_STATIC(LIB, MGMTD_FE_CLIENT, "frontend client");
DEFINE_MTYPE_STATIC(LIB, MGMTD_FE_CLIENT_NAME, "frontend client name");
DEFINE_MTYPE_STATIC(LIB, MGMTD_FE_SESSION, "frontend session");

struct mgmt_fe_client {
	struct msg_client client;
	char *name;
	struct mgmt_fe_client_cbs cbs;
	uintptr_t user_data;
	struct mgmt_sessions_head sessions;
};

#define FOREACH_SESSION_IN_LIST(client, session)                               \
	frr_each_safe (mgmt_sessions, &(client)->sessions, (session))

struct debug mgmt_dbg_fe_client = {
	.conf = "debug mgmt client frontend",
	.desc = "Management frontend client operations"
};

/* NOTE: only one client per proc for now. */
static struct mgmt_fe_client *__fe_client;

static inline const char *dsid2name(Mgmtd__DatastoreId id)
{
	switch ((int)id) {
	case MGMTD_DS_NONE:
		return "none";
	case MGMTD_DS_RUNNING:
		return "running";
	case MGMTD_DS_CANDIDATE:
		return "candidate";
	case MGMTD_DS_OPERATIONAL:
		return "operational";
	default:
		return "unknown-datastore-id";
	}
}

static struct mgmt_fe_client_session *
mgmt_fe_find_session_by_client_id(struct mgmt_fe_client *client,
				  uint64_t client_id)
{
	struct mgmt_fe_client_session *session;

	FOREACH_SESSION_IN_LIST (client, session) {
		if (session->client_id == client_id) {
			debug_fe_client("Found session-id %" PRIu64
					" using client-id %" PRIu64,
					session->session_id, client_id);
			return session;
		}
	}
	debug_fe_client("Session not found using client-id %" PRIu64, client_id);
	return NULL;
}

static struct mgmt_fe_client_session *
mgmt_fe_find_session_by_session_id(struct mgmt_fe_client *client,
				   uint64_t session_id)
{
	struct mgmt_fe_client_session *session;

	FOREACH_SESSION_IN_LIST (client, session) {
		if (session->session_id == session_id) {
			debug_fe_client("Found session of client-id %" PRIu64
					" using session-id %" PRIu64,
					session->client_id, session_id);
			return session;
		}
	}
	debug_fe_client("Session not found using session-id %" PRIu64,
			session_id);
	return NULL;
}

static int mgmt_fe_client_send_msg(struct mgmt_fe_client *client,
				   Mgmtd__FeMessage *fe_msg,
				   bool short_circuit_ok)
{
	return msg_conn_send_msg(
		&client->client.conn, MGMT_MSG_VERSION_PROTOBUF, fe_msg,
		mgmtd__fe_message__get_packed_size(fe_msg),
		(size_t(*)(void *, void *))mgmtd__fe_message__pack,
		short_circuit_ok);
}

static int mgmt_fe_send_register_req(struct mgmt_fe_client *client)
{
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeRegisterReq rgstr_req;

	mgmtd__fe_register_req__init(&rgstr_req);
	rgstr_req.client_name = client->name;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_REGISTER_REQ;
	fe_msg.register_req = &rgstr_req;

	debug_fe_client("Sending REGISTER_REQ message to MGMTD Frontend server");

	return mgmt_fe_client_send_msg(client, &fe_msg, true);
}

static int mgmt_fe_send_session_req(struct mgmt_fe_client *client,
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

	debug_fe_client("Sending SESSION_REQ %s message for client-id %" PRIu64,
			create ? "create" : "destroy", session->client_id);

	return mgmt_fe_client_send_msg(client, &fe_msg, true);
}

int mgmt_fe_send_lockds_req(struct mgmt_fe_client *client, uint64_t session_id,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    bool lock, bool scok)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeLockDsReq lockds_req;

	mgmtd__fe_lock_ds_req__init(&lockds_req);
	lockds_req.session_id = session_id;
	lockds_req.req_id = req_id;
	lockds_req.ds_id = ds_id;
	lockds_req.lock = lock;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REQ;
	fe_msg.lockds_req = &lockds_req;

	debug_fe_client("Sending LOCKDS_REQ (%sLOCK) message for DS:%s session-id %" PRIu64,
			lock ? "" : "UN", dsid2name(ds_id), session_id);


	return mgmt_fe_client_send_msg(client, &fe_msg, scok);
}

int mgmt_fe_send_setcfg_req(struct mgmt_fe_client *client, uint64_t session_id,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangCfgDataReq **data_req, int num_data_reqs,
			    bool implicit_commit, Mgmtd__DatastoreId dst_ds_id)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeSetConfigReq setcfg_req;

	mgmtd__fe_set_config_req__init(&setcfg_req);
	setcfg_req.session_id = session_id;
	setcfg_req.ds_id = ds_id;
	setcfg_req.req_id = req_id;
	setcfg_req.data = data_req;
	setcfg_req.n_data = (size_t)num_data_reqs;
	setcfg_req.implicit_commit = implicit_commit;
	setcfg_req.commit_ds_id = dst_ds_id;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REQ;
	fe_msg.setcfg_req = &setcfg_req;

	debug_fe_client("Sending SET_CONFIG_REQ message for DS:%s session-id %" PRIu64
			" (#xpaths:%d)",
			dsid2name(ds_id), session_id, num_data_reqs);

	return mgmt_fe_client_send_msg(client, &fe_msg, false);
}

int mgmt_fe_send_commitcfg_req(struct mgmt_fe_client *client,
			       uint64_t session_id, uint64_t req_id,
			       Mgmtd__DatastoreId src_ds_id,
			       Mgmtd__DatastoreId dest_ds_id,
			       bool validate_only, bool abort)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeCommitConfigReq commitcfg_req;

	mgmtd__fe_commit_config_req__init(&commitcfg_req);
	commitcfg_req.session_id = session_id;
	commitcfg_req.src_ds_id = src_ds_id;
	commitcfg_req.dst_ds_id = dest_ds_id;
	commitcfg_req.req_id = req_id;
	commitcfg_req.validate_only = validate_only;
	commitcfg_req.abort = abort;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REQ;
	fe_msg.commcfg_req = &commitcfg_req;

	debug_fe_client("Sending COMMIT_CONFIG_REQ message for Src-DS:%s, Dst-DS:%s session-id %" PRIu64,
			dsid2name(src_ds_id), dsid2name(dest_ds_id), session_id);

	return mgmt_fe_client_send_msg(client, &fe_msg, false);
}

int mgmt_fe_send_get_req(struct mgmt_fe_client *client, uint64_t session_id,
			 uint64_t req_id, bool is_config,
			 Mgmtd__DatastoreId ds_id,
			 Mgmtd__YangGetDataReq *data_req[], int num_data_reqs)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeGetReq getcfg_req;

	mgmtd__fe_get_req__init(&getcfg_req);
	getcfg_req.session_id = session_id;
	getcfg_req.config = is_config;
	getcfg_req.ds_id = ds_id;
	getcfg_req.req_id = req_id;
	getcfg_req.data = data_req;
	getcfg_req.n_data = (size_t)num_data_reqs;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_GET_REQ;
	fe_msg.get_req = &getcfg_req;

	debug_fe_client("Sending GET_REQ (iscfg %d) message for DS:%s session-id %" PRIu64
			" (#xpaths:%d)",
			is_config, dsid2name(ds_id), session_id, num_data_reqs);

	return mgmt_fe_client_send_msg(client, &fe_msg, false);
}

int mgmt_fe_send_regnotify_req(struct mgmt_fe_client *client,
			       uint64_t session_id, uint64_t req_id,
			       Mgmtd__DatastoreId ds_id, bool register_req,
			       Mgmtd__YangDataXPath *data_req[],
			       int num_data_reqs)
{
	(void)req_id;
	Mgmtd__FeMessage fe_msg;
	Mgmtd__FeRegisterNotifyReq regntfy_req;

	mgmtd__fe_register_notify_req__init(&regntfy_req);
	regntfy_req.session_id = session_id;
	regntfy_req.ds_id = ds_id;
	regntfy_req.register_req = register_req;
	regntfy_req.data_xpath = data_req;
	regntfy_req.n_data_xpath = (size_t)num_data_reqs;

	mgmtd__fe_message__init(&fe_msg);
	fe_msg.message_case = MGMTD__FE_MESSAGE__MESSAGE_REGNOTIFY_REQ;
	fe_msg.regnotify_req = &regntfy_req;

	return mgmt_fe_client_send_msg(client, &fe_msg, false);
}

/*
 * Send get-data request.
 */
int mgmt_fe_send_get_data_req(struct mgmt_fe_client *client,
			      uint64_t session_id, uint64_t req_id,
			      uint8_t datastore, LYD_FORMAT result_type,
			      uint8_t flags, uint8_t defaults, const char *xpath)
{
	struct mgmt_msg_get_data *msg;
	size_t xplen = strlen(xpath);
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_get_data, xplen + 1,
					MTYPE_MSG_NATIVE_GET_DATA);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_GET_DATA;
	msg->result_type = result_type;
	msg->flags = flags;
	msg->defaults = defaults;
	msg->datastore = datastore;
	strlcpy(msg->xpath, xpath, xplen + 1);

	debug_fe_client("Sending GET_DATA_REQ session-id %" PRIu64
			" req-id %" PRIu64 " xpath: %s",
			session_id, req_id, xpath);

	ret = mgmt_msg_native_send_msg(&client->client.conn, msg, false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

int mgmt_fe_send_edit_req(struct mgmt_fe_client *client, uint64_t session_id,
			  uint64_t req_id, uint8_t datastore,
			  LYD_FORMAT request_type, uint8_t flags,
			  uint8_t operation, const char *xpath, const char *data)
{
	struct mgmt_msg_edit *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_edit, 0,
					MTYPE_MSG_NATIVE_EDIT);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_EDIT;
	msg->request_type = request_type;
	msg->flags = flags;
	msg->datastore = datastore;
	msg->operation = operation;

	mgmt_msg_native_xpath_encode(msg, xpath);
	if (data)
		mgmt_msg_native_append(msg, data, strlen(data) + 1);

	debug_fe_client("Sending EDIT_REQ session-id %" PRIu64
			" req-id %" PRIu64 " xpath: %s",
			session_id, req_id, xpath);

	ret = mgmt_msg_native_send_msg(&client->client.conn, msg, false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

int mgmt_fe_send_rpc_req(struct mgmt_fe_client *client, uint64_t session_id,
			 uint64_t req_id, LYD_FORMAT request_type,
			 const char *xpath, const char *data)
{
	struct mgmt_msg_rpc *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_rpc, 0,
					MTYPE_MSG_NATIVE_RPC);
	msg->refer_id = session_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_RPC;
	msg->request_type = request_type;

	mgmt_msg_native_xpath_encode(msg, xpath);
	if (data)
		mgmt_msg_native_append(msg, data, strlen(data) + 1);

	debug_fe_client("Sending RPC_REQ session-id %" PRIu64 " req-id %" PRIu64
			" xpath: %s",
			session_id, req_id, xpath);

	ret = mgmt_msg_native_send_msg(&client->client.conn, msg, false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

static int mgmt_fe_client_handle_msg(struct mgmt_fe_client *client,
				     Mgmtd__FeMessage *fe_msg)
{
	struct mgmt_fe_client_session *session = NULL;

	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)fe_msg->message_case) {
	case MGMTD__FE_MESSAGE__MESSAGE_SESSION_REPLY:
		if (fe_msg->session_reply->create &&
		    fe_msg->session_reply->has_client_conn_id) {
			debug_fe_client("Got SESSION_REPLY (create) for client-id %" PRIu64
					" with session-id: %" PRIu64,
					fe_msg->session_reply->client_conn_id,
					fe_msg->session_reply->session_id);

			session = mgmt_fe_find_session_by_client_id(
				client, fe_msg->session_reply->client_conn_id);

			if (session && fe_msg->session_reply->success) {
				debug_fe_client("Session Created for client-id %" PRIu64,
						fe_msg->session_reply
							->client_conn_id);
				session->session_id =
					fe_msg->session_reply->session_id;
			} else {
				log_err_fe_client(
					"Session Create failed for client-id %" PRIu64,
					fe_msg->session_reply->client_conn_id);
			}
		} else if (!fe_msg->session_reply->create) {
			debug_fe_client("Got SESSION_REPLY (destroy) for session-id %" PRIu64,
					fe_msg->session_reply->session_id);

			session = mgmt_fe_find_session_by_session_id(
				client, fe_msg->session_req->session_id);
		}

		/* The session state may be deleted by the callback */
		if (session && session->client &&
		    session->client->cbs.client_session_notify)
			(*session->client->cbs.client_session_notify)(
				client, client->user_data, session->client_id,
				fe_msg->session_reply->create,
				fe_msg->session_reply->success,
				fe_msg->session_reply->session_id,
				session->user_ctx);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_LOCKDS_REPLY:
		debug_fe_client("Got LOCKDS_REPLY for session-id %" PRIu64,
				fe_msg->lockds_reply->session_id);
		session = mgmt_fe_find_session_by_session_id(
			client, fe_msg->lockds_reply->session_id);

		if (session && session->client &&
		    session->client->cbs.lock_ds_notify)
			(*session->client->cbs.lock_ds_notify)(
				client, client->user_data, session->client_id,
				fe_msg->lockds_reply->session_id,
				session->user_ctx, fe_msg->lockds_reply->req_id,
				fe_msg->lockds_reply->lock,
				fe_msg->lockds_reply->success,
				fe_msg->lockds_reply->ds_id,
				fe_msg->lockds_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_SETCFG_REPLY:
		debug_fe_client("Got SETCFG_REPLY for session-id %" PRIu64,
				fe_msg->setcfg_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client, fe_msg->setcfg_reply->session_id);

		if (session && session->client &&
		    session->client->cbs.set_config_notify)
			(*session->client->cbs.set_config_notify)(
				client, client->user_data, session->client_id,
				fe_msg->setcfg_reply->session_id,
				session->user_ctx, fe_msg->setcfg_reply->req_id,
				fe_msg->setcfg_reply->success,
				fe_msg->setcfg_reply->ds_id,
				fe_msg->setcfg_reply->implicit_commit,
				fe_msg->setcfg_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_COMMCFG_REPLY:
		debug_fe_client("Got COMMCFG_REPLY for session-id %" PRIu64,
				fe_msg->commcfg_reply->session_id);

		session = mgmt_fe_find_session_by_session_id(
			client, fe_msg->commcfg_reply->session_id);

		if (session && session->client &&
		    session->client->cbs.commit_config_notify)
			(*session->client->cbs.commit_config_notify)(
				client, client->user_data, session->client_id,
				fe_msg->commcfg_reply->session_id,
				session->user_ctx,
				fe_msg->commcfg_reply->req_id,
				fe_msg->commcfg_reply->success,
				fe_msg->commcfg_reply->src_ds_id,
				fe_msg->commcfg_reply->dst_ds_id,
				fe_msg->commcfg_reply->validate_only,
				fe_msg->commcfg_reply->error_if_any);
		break;
	case MGMTD__FE_MESSAGE__MESSAGE_GET_REPLY:
		debug_fe_client("Got GET_REPLY for session-id %" PRIu64,
				fe_msg->get_reply->session_id);

		session =
			mgmt_fe_find_session_by_session_id(client,
							   fe_msg->get_reply
								   ->session_id);

		if (session && session->client &&
		    session->client->cbs.get_data_notify)
			(*session->client->cbs.get_data_notify)(
				client, client->user_data, session->client_id,
				fe_msg->get_reply->session_id,
				session->user_ctx, fe_msg->get_reply->req_id,
				fe_msg->get_reply->success,
				fe_msg->get_reply->ds_id,
				fe_msg->get_reply->data
					? fe_msg->get_reply->data->data
					: NULL,
				fe_msg->get_reply->data
					? fe_msg->get_reply->data->n_data
					: 0,
				fe_msg->get_reply->data
					? fe_msg->get_reply->data->next_indx
					: 0,
				fe_msg->get_reply->error_if_any);
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
	case MGMTD__FE_MESSAGE__MESSAGE_GET_REQ:
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

/*
 * Handle a native encoded message
 */
static void fe_client_handle_native_msg(struct mgmt_fe_client *client,
					struct mgmt_msg_header *msg,
					size_t msg_len)
{
	struct mgmt_fe_client_session *session = NULL;
	struct mgmt_msg_notify_data *notify_msg;
	struct mgmt_msg_tree_data *tree_msg;
	struct mgmt_msg_edit_reply *edit_msg;
	struct mgmt_msg_rpc_reply *rpc_msg;
	struct mgmt_msg_error *err_msg;
	const char *xpath = NULL;
	const char *data = NULL;
	size_t dlen;

	debug_fe_client("Got native message for session-id %" PRIu64,
			msg->refer_id);

	session = mgmt_fe_find_session_by_session_id(client, msg->refer_id);
	if (!session || !session->client) {
		log_err_fe_client("No session for received native msg session-id %" PRIu64,
				  msg->refer_id);
		return;
	}

	switch (msg->code) {
	case MGMT_MSG_CODE_ERROR:
		if (!session->client->cbs.error_notify)
			return;

		err_msg = (typeof(err_msg))msg;
		if (!MGMT_MSG_VALIDATE_NUL_TERM(err_msg, msg_len)) {
			log_err_fe_client("Corrupt error msg recv");
			return;
		}
		session->client->cbs.error_notify(client, client->user_data,
						  session->client_id,
						  msg->refer_id,
						  session->user_ctx,
						  msg->req_id, err_msg->error,
						  err_msg->errstr);
		break;
	case MGMT_MSG_CODE_TREE_DATA:
		if (!session->client->cbs.get_tree_notify)
			return;

		tree_msg = (typeof(tree_msg))msg;
		if (msg_len < sizeof(*tree_msg)) {
			log_err_fe_client("Corrupt tree-data msg recv");
			return;
		}
		session->client->cbs.get_tree_notify(client, client->user_data,
						     session->client_id,
						     msg->refer_id,
						     session->user_ctx,
						     msg->req_id,
						     MGMTD_DS_OPERATIONAL,
						     tree_msg->result_type,
						     tree_msg->result,
						     msg_len - sizeof(*tree_msg),
						     tree_msg->partial_error);
		break;
	case MGMT_MSG_CODE_EDIT_REPLY:
		if (!session->client->cbs.edit_notify)
			return;

		edit_msg = (typeof(edit_msg))msg;
		if (msg_len < sizeof(*edit_msg)) {
			log_err_fe_client("Corrupt edit-reply msg recv");
			return;
		}

		xpath = mgmt_msg_native_xpath_decode(edit_msg, msg_len);
		if (!xpath) {
			log_err_fe_client("Corrupt edit-reply msg recv");
			return;
		}

		session->client->cbs.edit_notify(client, client->user_data,
						 session->client_id,
						 msg->refer_id,
						 session->user_ctx, msg->req_id,
						 xpath);
		break;
	case MGMT_MSG_CODE_RPC_REPLY:
		if (!session->client->cbs.rpc_notify)
			return;

		rpc_msg = (typeof(rpc_msg))msg;
		if (msg_len < sizeof(*rpc_msg)) {
			log_err_fe_client("Corrupt rpc-reply msg recv");
			return;
		}
		dlen = msg_len - sizeof(*rpc_msg);

		session->client->cbs.rpc_notify(client, client->user_data,
						session->client_id,
						msg->refer_id,
						session->user_ctx, msg->req_id,
						dlen ? rpc_msg->data : NULL);
		break;
	case MGMT_MSG_CODE_NOTIFY:
		if (!session->client->cbs.async_notification)
			return;

		notify_msg = (typeof(notify_msg))msg;
		if (msg_len < sizeof(*notify_msg)) {
			log_err_fe_client("Corrupt notify-data msg recv");
			return;
		}

		data = mgmt_msg_native_data_decode(notify_msg, msg_len);
		if (!data) {
			log_err_fe_client("Corrupt error msg recv");
			return;
		}
		dlen = mgmt_msg_native_data_len_decode(notify_msg, msg_len);
		if (notify_msg->result_type != LYD_JSON)
			data = yang_convert_lyd_format(data, dlen,
						       notify_msg->result_type,
						       LYD_JSON, true);
		if (!data) {
			log_err_fe_client("Can't convert format %d to JSON",
					  notify_msg->result_type);
			return;
		}

		session->client->cbs.async_notification(client,
							client->user_data,
							session->client_id,
							msg->refer_id,
							session->user_ctx, data);

		if (notify_msg->result_type != LYD_JSON)
			darr_free(data);
		break;
	default:
		log_err_fe_client("unknown native message session-id %" PRIu64
				  " req-id %" PRIu64 " code %u",
				  msg->refer_id, msg->req_id, msg->code);
		break;
	}
}

static void mgmt_fe_client_process_msg(uint8_t version, uint8_t *data,
				       size_t len, struct msg_conn *conn)
{
	struct mgmt_fe_client *client;
	struct msg_client *msg_client;
	Mgmtd__FeMessage *fe_msg;

	msg_client = container_of(conn, struct msg_client, conn);
	client = container_of(msg_client, struct mgmt_fe_client, client);

	if (version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *msg = (typeof(msg))data;

		if (len >= sizeof(*msg))
			fe_client_handle_native_msg(client, msg, len);
		else
			log_err_fe_client("native message to FE client %s too short %zu",
					  client->name, len);
		return;
	}

	fe_msg = mgmtd__fe_message__unpack(NULL, len, data);
	if (!fe_msg) {
		debug_fe_client("Failed to decode %zu bytes from server.", len);
		return;
	}
	debug_fe_client("Decoded %zu bytes of message(msg: %u/%u) from server",
			len, fe_msg->message_case, fe_msg->message_case);
	(void)mgmt_fe_client_handle_msg(client, fe_msg);
	mgmtd__fe_message__free_unpacked(fe_msg, NULL);
}

static int _notify_connect_disconnect(struct msg_client *msg_client,
				      bool connected)
{
	struct mgmt_fe_client *client =
		container_of(msg_client, struct mgmt_fe_client, client);
	struct mgmt_fe_client_session *session;
	int ret;

	/* Send REGISTER_REQ message */
	if (connected) {
		if ((ret = mgmt_fe_send_register_req(client)) != 0)
			return ret;
	}

	/* Walk list of sessions for this FE client deleting them */
	if (!connected && mgmt_sessions_count(&client->sessions)) {
		debug_fe_client("Cleaning up existing sessions");

		FOREACH_SESSION_IN_LIST (client, session) {
			assert(session->client);

			/* unlink from list first this avoids double free */
			mgmt_sessions_del(&client->sessions, session);

			/* notify FE client the session is being deleted */
			if (session->client->cbs.client_session_notify) {
				(*session->client->cbs.client_session_notify)(
					client, client->user_data,
					session->client_id, false, true,
					session->session_id, session->user_ctx);
			}

			XFREE(MTYPE_MGMTD_FE_SESSION, session);
		}
	}

	/* Notify FE client through registered callback (if any). */
	if (client->cbs.client_connect_notify)
		(void)(*client->cbs.client_connect_notify)(
			client, client->user_data, connected);
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

static void mgmt_debug_client_fe_set(uint32_t mode, bool set)
{
	DEBUG_FLAGS_SET(&mgmt_dbg_fe_client, mode, set);

	if (!__fe_client)
		return;

	__fe_client->client.conn.debug = DEBUG_MODE_CHECK(&mgmt_dbg_fe_client,
							  DEBUG_MODE_ALL);
}

DEFPY(debug_mgmt_client_fe, debug_mgmt_client_fe_cmd,
      "[no] debug mgmt client frontend",
      NO_STR DEBUG_STR MGMTD_STR
      "client\n"
      "frontend\n")
{
	mgmt_debug_client_fe_set(DEBUG_NODE2MODE(vty->node), !no);

	return CMD_SUCCESS;
}

/*
 * Initialize library and try connecting with MGMTD.
 */
struct mgmt_fe_client *mgmt_fe_client_create(const char *client_name,
					     struct mgmt_fe_client_cbs *cbs,
					     uintptr_t user_data,
					     struct event_loop *event_loop)
{
	struct mgmt_fe_client *client;
	char server_path[MAXPATHLEN];

	if (__fe_client)
		return NULL;

	client = XCALLOC(MTYPE_MGMTD_FE_CLIENT, sizeof(*client));
	__fe_client = client;

	client->name = XSTRDUP(MTYPE_MGMTD_FE_CLIENT_NAME, client_name);
	client->user_data = user_data;
	if (cbs)
		client->cbs = *cbs;

	mgmt_sessions_init(&client->sessions);

	snprintf(server_path, sizeof(server_path), MGMTD_FE_SOCK_NAME);

	msg_client_init(&client->client, event_loop, server_path,
			mgmt_fe_client_notify_connect,
			mgmt_fe_client_notify_disconnect,
			mgmt_fe_client_process_msg, MGMTD_FE_MAX_NUM_MSG_PROC,
			MGMTD_FE_MAX_NUM_MSG_WRITE, MGMTD_FE_MAX_MSG_LEN, true,
			"FE-client", debug_check_fe_client());

	debug_fe_client("Initialized client '%s'", client_name);

	return client;
}

void mgmt_fe_client_lib_vty_init(void)
{
	debug_install(&mgmt_dbg_fe_client);

	install_element(ENABLE_NODE, &debug_mgmt_client_fe_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_client_fe_cmd);
}

uint mgmt_fe_client_session_count(struct mgmt_fe_client *client)
{
	return mgmt_sessions_count(&client->sessions);
}

bool mgmt_fe_client_current_msg_short_circuit(struct mgmt_fe_client *client)
{
	return client->client.conn.is_short_circuit;
}

const char *mgmt_fe_client_name(struct mgmt_fe_client *client)
{
	return client->name;
}

/*
 * Create a new Session for a Frontend Client connection.
 */
enum mgmt_result mgmt_fe_create_client_session(struct mgmt_fe_client *client,
					       uint64_t client_id,
					       uintptr_t user_ctx)
{
	struct mgmt_fe_client_session *session;

	session = XCALLOC(MTYPE_MGMTD_FE_SESSION,
			  sizeof(struct mgmt_fe_client_session));
	assert(session);
	session->user_ctx = user_ctx;
	session->client_id = client_id;
	session->client = client;
	session->session_id = 0;

	mgmt_sessions_add_tail(&client->sessions, session);

	if (mgmt_fe_send_session_req(client, session, true) != 0) {
		XFREE(MTYPE_MGMTD_FE_SESSION, session);
		return MGMTD_INTERNAL_ERROR;
	}

	return MGMTD_SUCCESS;
}

/*
 * Delete an existing Session for a Frontend Client connection.
 */
enum mgmt_result mgmt_fe_destroy_client_session(struct mgmt_fe_client *client,
						uint64_t client_id)
{
	struct mgmt_fe_client_session *session;

	session = mgmt_fe_find_session_by_client_id(client, client_id);
	if (!session || session->client != client)
		return MGMTD_INVALID_PARAM;

	if (session->session_id &&
	    mgmt_fe_send_session_req(client, session, false) != 0)
		log_err_fe_client("Failed to send session destroy request for the session-id %" PRIu64,
				  session->session_id);

	mgmt_sessions_del(&client->sessions, session);
	XFREE(MTYPE_MGMTD_FE_SESSION, session);

	return MGMTD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void mgmt_fe_client_destroy(struct mgmt_fe_client *client)
{
	struct mgmt_fe_client_session *session;

	assert(client == __fe_client);

	debug_fe_client("Destroying MGMTD Frontend Client '%s'", client->name);

	FOREACH_SESSION_IN_LIST (client, session)
		mgmt_fe_destroy_client_session(client, session->client_id);

	msg_client_cleanup(&client->client);

	XFREE(MTYPE_MGMTD_FE_CLIENT_NAME, client->name);
	XFREE(MTYPE_MGMTD_FE_CLIENT, client);

	__fe_client = NULL;
}
