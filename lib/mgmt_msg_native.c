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
DEFINE_MTYPE(MSG_NATIVE, MSG_NATIVE_ERROR, "native mgmt error msg");

int vmgmt_msg_native_send_error(struct msg_conn *conn, uint64_t sess_or_txn_id,
				uint64_t req_id, bool short_circuit_ok,
				int16_t error, const char *errfmt, va_list ap)
{
	struct mgmt_msg_error *msg;
	ssize_t slen;
	size_t mlen;
	int ret;

	msg = XCALLOC(MTYPE_MSG_NATIVE_ERROR, 1024);
	msg->session_id = sess_or_txn_id;
	msg->req_id = req_id;
	msg->code = MGMT_MSG_CODE_ERROR;
	msg->error = error;

	slen = vsnprintfrr(msg->errstr, 1024 - sizeof(*msg), errfmt, ap);
	mlen = MIN(slen + sizeof(*msg) + 1, 1024);

	if (conn->debug)
		zlog_debug("Sending error %d session-id %" PRIu64
			   " req-id %" PRIu64 " scok %d errstr: %s",
			   error, sess_or_txn_id, req_id, short_circuit_ok,
			   msg->errstr);

	ret = msg_conn_send_msg(conn, MGMT_MSG_VERSION_NATIVE, msg, mlen, NULL,
				short_circuit_ok);

	XFREE(MTYPE_MSG_NATIVE_ERROR, msg);

	return ret;
}
