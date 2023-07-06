// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 29 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */

#ifndef _FRR_MGMT_MSG_NATIVE_H_
#define _FRR_MGMT_MSG_NATIVE_H_

#ifdef __cplusplus
extern "C" {
#elif 0
}
#endif

#include <zebra.h>
#include "compiler.h"
#include "memory.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"

#include <stdalign.h>

DECLARE_MTYPE(MSG_NATIVE_MSG);
DECLARE_MTYPE(MSG_NATIVE_ERROR);

/*
 * Native message codes
 */
#define MGMT_MSG_CODE_ERROR	0
#define MGMT_MSG_CODE_GET_TREE	1
#define MGMT_MSG_CODE_TREE_DATA 2

/*
 * A note on alignments: The zero length arrays fields are aligned such that
 * this is so:
 *
 *    sizeof(struct mgmt_msg_foo) == offsetof(struct mgmt_msg_foo, field)
 *
 * This allows things like `ptr = darr_append_n(A, sizeof(*ptr))`
 * to work
 */


struct mgmt_msg_header {
	union {
		uint64_t session_id;
		uint64_t txn_id;
	};
	uint64_t req_id;
	uint16_t code;
};

struct mgmt_msg_error {
	struct mgmt_msg_header;
	int16_t error;

	alignas(8) char errstr[];
};
_Static_assert(sizeof(struct mgmt_msg_error) ==
		       offsetof(struct mgmt_msg_error, errstr),
	       "Size mismatch");

struct mgmt_msg_get_tree {
	struct mgmt_msg_header;
	uint8_t result_type;

	alignas(8) char xpath[];
};
_Static_assert(sizeof(struct mgmt_msg_get_tree) ==
		       offsetof(struct mgmt_msg_get_tree, xpath),
	       "Size mismatch");

struct mgmt_msg_tree_data {
	struct mgmt_msg_header;
	int8_t partial_error;
	uint8_t result_type;

	alignas(8) uint8_t result[];
};
_Static_assert(sizeof(struct mgmt_msg_tree_data) ==
		       offsetof(struct mgmt_msg_tree_data, result),
	       "Size mismatch");

#define MGMT_MSG_VALIDATE_NUL_TERM(msgp, len)                                  \
	((len) >= sizeof(*msg) + 1 && ((char *)msgp)[(len)-1] == 0)


/**
 * Send a native message error to the other end of the connection.
 *
 * This function is normally used by the server-side to indicate a failure to
 * process a client request. For this server side handling of client messages
 * which expect a reply, either that reply or this error should be returned, as
 * closing the connection is not allowed during message handling.
 *
 * Args:
 *	conn: the connection.
 *	sess_or_txn_id: Session ID (to FE client) or Txn ID (from BE client)
 *	req_id: which req_id this error is associated with.
 *	short_circuit_ok: if short circuit sending is OK.
 *	error: the error value
 *	errfmt: vprintfrr style format string
 *	ap: the variable args for errfmt.
 *
 * Return:
 *	The return value of ``msg_conn_send_msg``.
 */
extern int vmgmt_msg_native_send_error(struct msg_conn *conn,
				       uint64_t sess_or_txn_id, uint64_t req_id,
				       bool short_circuit_ok, int16_t error,
				       const char *errfmt, va_list ap)
	PRINTFRR(6, 0);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMT_MSG_NATIVE_H_ */
