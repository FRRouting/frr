// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 29 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "mgmt_msg_native.h"

DEFINE_MGROUP(MSG_NATIVE, "Native message allocations");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_MSG, "native mgmt msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_ERROR, "native error msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_GET_TREE, "native get tree msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_TREE_DATA, "native tree data msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_GET_DATA, "native get data msg");
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_NOTIFY, "native get data msg");

int vmgmt_msg_native_send_error(struct msg_conn *conn, uint64_t sess_or_txn_id,
				uint64_t req_id, bool short_circuit_ok,
				int16_t error, const char *errfmt, va_list ap)
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
