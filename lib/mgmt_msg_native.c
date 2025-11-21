// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 29 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "darr.h"
#include "mgmt_msg_native.h"

DEFINE_MGROUP(MSG_NATIVE, "Native message allocations");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_ERROR, "native error msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_GET_TREE, "native get tree msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_TREE_DATA, "native tree data msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_GET_DATA, "native get data msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_NOTIFY, "native notify msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_NOTIFY_SELECT, "native notify select msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_EDIT, "native edit msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_EDIT_REPLY, "native edit reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_RPC, "native RPC msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_RPC_REPLY, "native RPC reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_SUBSCRIBE, "native subscribe msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_SESSION_REQ, "native session-req msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_SESSION_REPLY, "native session-reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_TXN_REQ, "native txn-req msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_TXN_REPLY, "native txn-reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_CFG_REQ, "native cfg-req msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_CFG_REPLY, "native cfg-reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_CFG_APPLY_REQ, "native cfg-act-req msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_CFG_APPLY_REPLY, "native cfg-act-reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_LOCK, "native lock msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_LOCK_REPLY, "native lock-reply msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_COMMIT, "native commit msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_COMMIT_REPLY, "native commit-reply msg");

size_t mgmt_msg_min_sizes[] = {
	[MGMT_MSG_CODE_ERROR] = sizeof(struct mgmt_msg_error),
	[MGMT_MSG_CODE_GET_TREE] = sizeof(struct mgmt_msg_get_tree),
	[MGMT_MSG_CODE_TREE_DATA] = sizeof(struct mgmt_msg_tree_data),
	[MGMT_MSG_CODE_GET_DATA] = sizeof(struct mgmt_msg_get_data),
	[MGMT_MSG_CODE_NOTIFY] = sizeof(struct mgmt_msg_notify_data),
	[MGMT_MSG_CODE_EDIT] = sizeof(struct mgmt_msg_edit),
	[MGMT_MSG_CODE_EDIT_REPLY] = sizeof(struct mgmt_msg_edit_reply),
	[MGMT_MSG_CODE_RPC] = sizeof(struct mgmt_msg_rpc),
	[MGMT_MSG_CODE_RPC_REPLY] = sizeof(struct mgmt_msg_rpc_reply),
	[MGMT_MSG_CODE_NOTIFY_SELECT] = sizeof(struct mgmt_msg_notify_select),
	[MGMT_MSG_CODE_SESSION_REQ] = sizeof(struct mgmt_msg_session_req),
	[MGMT_MSG_CODE_SESSION_REPLY] = sizeof(struct mgmt_msg_session_reply),
	[MGMT_MSG_CODE_SUBSCRIBE] = sizeof(struct mgmt_msg_subscribe),
	[MGMT_MSG_CODE_TXN_REQ] = sizeof(struct mgmt_msg_txn_req),
	[MGMT_MSG_CODE_TXN_REPLY] = sizeof(struct mgmt_msg_txn_reply),
	[MGMT_MSG_CODE_CFG_REQ] = sizeof(struct mgmt_msg_cfg_req),
	[MGMT_MSG_CODE_CFG_REPLY] = sizeof(struct mgmt_msg_cfg_reply),
	[MGMT_MSG_CODE_CFG_APPLY_REQ] = sizeof(struct mgmt_msg_cfg_apply_req),
	[MGMT_MSG_CODE_CFG_APPLY_REPLY] = sizeof(struct mgmt_msg_cfg_apply_reply),
	[MGMT_MSG_CODE_LOCK] = sizeof(struct mgmt_msg_lock),
	[MGMT_MSG_CODE_LOCK_REPLY] = sizeof(struct mgmt_msg_lock_reply),
	[MGMT_MSG_CODE_COMMIT] = sizeof(struct mgmt_msg_commit),
	[MGMT_MSG_CODE_COMMIT_REPLY] = sizeof(struct mgmt_msg_commit_reply),
};
size_t nmgmt_msg_min_sizes = sizeof(mgmt_msg_min_sizes) /
			     sizeof(*mgmt_msg_min_sizes);

size_t mgmt_msg_get_min_size(uint code)
{
	if (code >= nmgmt_msg_min_sizes)
		return 0;
	return mgmt_msg_min_sizes[code];
}

const char *mgmt_msg_code_name(uint code)
{
	static char buf[48];

	switch (code) {
	case MGMT_MSG_CODE_ERROR:
		return "ERROR";
	case MGMT_MSG_CODE_GET_TREE:
		return "GET_TREE";
	case MGMT_MSG_CODE_TREE_DATA:
		return "TREE_DATA";
	case MGMT_MSG_CODE_GET_DATA:
		return "GET_DATA";
	case MGMT_MSG_CODE_NOTIFY:
		return "NOTIFY";
	case MGMT_MSG_CODE_EDIT:
		return "EDIT";
	case MGMT_MSG_CODE_EDIT_REPLY:
		return "EDIT_REPLY";
	case MGMT_MSG_CODE_RPC:
		return "RPC";
	case MGMT_MSG_CODE_RPC_REPLY:
		return "RPC_REPLY";
	case MGMT_MSG_CODE_NOTIFY_SELECT:
		return "NOTIFY_SELECT";
	case MGMT_MSG_CODE_SESSION_REQ:
		return "SESSION_REQ";
	case MGMT_MSG_CODE_SESSION_REPLY:
		return "SESSION_REPLY";
	case MGMT_MSG_CODE_LOCK:
		return "LOCK";
	case MGMT_MSG_CODE_LOCK_REPLY:
		return "LOCK_REPLY";
	case MGMT_MSG_CODE_COMMIT:
		return "COMMIT";
	case MGMT_MSG_CODE_COMMIT_REPLY:
		return "COMMIT_REPLY";
	case MGMT_MSG_CODE_SUBSCRIBE:
		return "SUBSCRIBE";
	case MGMT_MSG_CODE_TXN_REQ:
		return "TXN_REQ";
	case MGMT_MSG_CODE_TXN_REPLY:
		return "TXN_REPLY";
	case MGMT_MSG_CODE_CFG_REQ:
		return "CFG_REQ";
	case MGMT_MSG_CODE_CFG_REPLY:
		return "CFG_REPLY";
	case MGMT_MSG_CODE_CFG_APPLY_REQ:
		return "CFG_APPLY_REQ";
	case MGMT_MSG_CODE_CFG_APPLY_REPLY:
		return "CFG_APPLY_REPLY";
	default:
		snprintf(buf, sizeof(buf), "UNKNOWN(%u)", code);
		return buf;
	}
}


int vmgmt_msg_native_send_error(struct msg_conn *conn, uint64_t sess_or_txn_id, uint64_t req_id,
				bool short_circuit_ok, int16_t error, const char *errfmt,
				va_list ap)
{
	struct mgmt_msg_error *msg;
	char *errstr;
	ssize_t slen;
	int ret;

	errstr = darr_vsprintf(errfmt, ap);
	slen = strlen(errstr);

	msg = mgmt_msg_native_alloc_msg(typeof(*msg), slen + 1,
					MTYPE_MSG_NATIVE_ERROR);
	msg->refer_id = sess_or_txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_ERROR;
	msg->error = error;
	strlcpy(msg->errstr, errstr, slen + 1);
	darr_free(errstr);

	if (conn->debug)
		zlog_debug("Sending error %d session-id %" PRIu64
			   " req-id %" PRIu64 " scok %d errstr: %s",
			   error, sess_or_txn_id, req_id, short_circuit_ok,
			   msg->errstr);

	ret = mgmt_msg_native_send_msg(conn, msg, short_circuit_ok);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

const char **_mgmt_msg_native_strings_decode(const void *_sdata, int sdlen)
{
	const char *sdata = _sdata;
	const char **strings = NULL;
	int len;

	if (sdata[sdlen - 1] != 0)
		return NULL;

	for (; sdlen; sdata += len, sdlen -= len) {
		*darr_append(strings) = darr_strdup(sdata);
		len = 1 + darr_strlen(strings[darr_lasti(strings)]);
	}

	return strings;
}
