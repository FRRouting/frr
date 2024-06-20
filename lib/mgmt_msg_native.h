// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 29 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 * Public APIs:
 *
 * The message type codes and corresponding message data definitions for
 * front-end client messages represent a public API, as such any changes should
 * only be made according to backward compatible principles (basically never,
 * just use a new message type). Back-end clients being always compiled with FRR
 * can be updated (although one should take care in modifying BE messages as it
 * could impact private back-end client implementations which will then need to
 * be updated by their owners).
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
#include "darr.h"
#include "memory.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"
#include "northbound.h"

#include <stdalign.h>

/*
 * ==================
 * Native Message API
 * ==================
 *
 * -----------------------
 * Defining A New Message:
 * -----------------------
 *
 *  1) Start with `struct mgmt_msg_header` as the first (unnamed) field.
 *
 *  2) Add fixed-width fields. Add on natural aligned boundaries (*)
 *
 *  3) [Optional] Add a zero-length variable field. Add aligned on a 64-bit
 *     boundary, this is done so that: `value = (HDR + 1)` works.
 *
 *  4) Define a new MTYPE for the new message type (see DECLARE_MTYPE below
 *     as well as the paired DEFINE_MTYPE in mgmt_msg_native.c)
 *
 * These rules are so the messages may be read from and written directly to
 * "the wire", easily, using common programming languages (e.g., C, rust, go,
 * python, ...)
 *
 * (*) Natrual aligned boundaries, i.e., uint16_t on 2-byte boundary, uint64_t
 * on 8-byte boundaries, ...)
 *
 * ------------------------------
 * Allocating New Native Messages
 * ------------------------------
 *
 * For fixed-length and variable length messages one should allocate new
 * messages with the mgmt_msg_native_alloc_msg() passing in the newly defined
 * MTYPE. Likewise, to free the message one should use
 * mgmt_msg_native_free_msg().
 *
 * Unknown Variable Length Messages:
 * ---------------------------------
 *
 * If using a zero-length variable length field and the length is not known at
 * message creation time, you can use the `native` API function
 * mgmt_msg_native_append() to add data to the end of the message, or if a more
 * full set of operations are required, the darr_xxxx() API is also available as
 * in the Advanced section below.
 *
 * Notable API Functions:
 * ---------------------------------
 *
 * mgmt_msg_native_alloc_msg() - Allocate a native msg.
 * mgmt_msg_native_free_msg() - Free a native msg.
 * mgmt_msg_native_append() - Append data to the end of the msg.
 * mgmt_msg_native_get_msg_len() - Get the total length of the msg.
 * mgmt_msg_native_send_msg() - Send the message.
 *
 * mgmt_msg_native_xpath_encode() - Encode xpath in xpath, data format message.
 * mgmt_msg_native_xpath_data_decode() - Decode xpath, data format message.
 * mgmt_msg_native_xpath_decode() - Get the xpath, from xpath, data format message.
 * mgmt_msg_native_data_decode() - Get the secondary data from xpath, data message.
 * mgmt_msg_native_data_len_decode() - Get length of secondary data.
 *
 * -------------------------------------
 * [Advanced Use] Dynamic Array Messages
 * -------------------------------------
 *
 * NOTE: Most users can simply use mgmt_msg_native_append() and skip this
 * section.
 *
 * This section is only important to understand if you wish to utilize the fact
 * that native messages allocated with mgmt_msg_native_alloc_msg are
 * actually allocated as uint8_t dynamic arrays (`darr`).
 *
 * You can utilize all the darr_xxxx() API to manipulate the variable length
 * message data in a native message. To do so you simply need to understand that
 * the native message is actually a `uint8_t *` darr. So, for example, to append
 * data to the end of a message one could do the following:
 *
 *     void append_metric_path(struct mgmt_msg_my_msg *msg)
 *     {
 *          msg = (struct mggm_msg_my_msg *)
 *              darr_strcat((uint8_t *)msg, "/metric");
 *
 *	    // ...
 *     }
 *
 * NOTE: If reallocs happen the original passed in pointer will be updated;
 * however, any other pointers into the message will become invalid, and so they
 * should always be discarded or reinitialized after using any reallocating
 * darr_xxx() API functions.
 *
 *     void append_metric_path(struct mgmt_msg_my_msg *msg)
 *     {
 *          char *xpath = msg->xpath;	// pointer into message
 *
 *          darr_in_strcat((uint8_t *)msg, "/metric");
 *          // msg may have been updated to point at new memory
 *
 *          xpath = NULL;		// now invalid
 *          xpath = msg->xpath;         // reinitialize
 *	    // ...
 *     }
 *
 * Rather than worry about this, it's typical when using dynamic arrays to always
 * work from the main pointer to the dynamic array, rather than caching multiple
 * pointers into the data. Modern compilers will optimize the code so that it
 * adds no extra execution cost.
 *
 *     void append_metric_path(struct mgmt_msg_my_msg *msg)
 *     {
 *          darr_in_strcat((uint8_t *)msg, "/metric");
 *
 *          // Use `msg->xpath` directly rather creating and using an
 *          // `xpath = msg->xpath` local variable.
 *
 *          if (strcmp(msg->xpath, "foobar/metric")) {
 *	        // ...
 *          }
 *     }
 *
 */

DECLARE_MTYPE(MSG_NATIVE_MSG);
DECLARE_MTYPE(MSG_NATIVE_ERROR);
DECLARE_MTYPE(MSG_NATIVE_GET_TREE);
DECLARE_MTYPE(MSG_NATIVE_TREE_DATA);
DECLARE_MTYPE(MSG_NATIVE_GET_DATA);
DECLARE_MTYPE(MSG_NATIVE_NOTIFY);
DECLARE_MTYPE(MSG_NATIVE_EDIT);
DECLARE_MTYPE(MSG_NATIVE_EDIT_REPLY);
DECLARE_MTYPE(MSG_NATIVE_RPC);
DECLARE_MTYPE(MSG_NATIVE_RPC_REPLY);
DECLARE_MTYPE(MSG_NATIVE_SESSION_REQ);
DECLARE_MTYPE(MSG_NATIVE_SESSION_REPLY);

/*
 * Native message codes
 */
#define MGMT_MSG_CODE_ERROR	 0 /* Public API */
#define MGMT_MSG_CODE_GET_TREE	 1 /* BE only, non-public API */
#define MGMT_MSG_CODE_TREE_DATA	 2 /* Public API */
#define MGMT_MSG_CODE_GET_DATA	 3 /* Public API */
#define MGMT_MSG_CODE_NOTIFY	 4 /* Public API */
#define MGMT_MSG_CODE_EDIT	 5 /* Public API */
#define MGMT_MSG_CODE_EDIT_REPLY 6 /* Public API */
#define MGMT_MSG_CODE_RPC	 7 /* Public API */
#define MGMT_MSG_CODE_RPC_REPLY	 8 /* Public API */
#define MGMT_MSG_CODE_NOTIFY_SELECT 9 /* Public API */
#define MGMT_MSG_CODE_SESSION_REQ   10 /* Public API */
#define MGMT_MSG_CODE_SESSION_REPLY 11 /* Public API */

/*
 * Datastores
 */
#define MGMT_MSG_DATASTORE_STARTUP     0
#define MGMT_MSG_DATASTORE_CANDIDATE   1
#define MGMT_MSG_DATASTORE_RUNNING     2
#define MGMT_MSG_DATASTORE_OPERATIONAL 3

/*
 * Formats
 */
#define MGMT_MSG_FORMAT_XML    1
#define MGMT_MSG_FORMAT_JSON   2
#define MGMT_MSG_FORMAT_BINARY 3 /* non-standard libyang internal format */

/*
 * Now we're using LYD_FORMAT directly to avoid mapping code, but having our
 * own definitions allows us to create such a mapping in the future if libyang
 * makes a backwards incompatible change.
 */
_Static_assert(MGMT_MSG_FORMAT_XML == LYD_XML, "Format mismatch");
_Static_assert(MGMT_MSG_FORMAT_JSON == LYD_JSON, "Format mismatch");
_Static_assert(MGMT_MSG_FORMAT_BINARY == LYD_LYB, "Format mismatch");

/**
 * struct mgmt_msg_header - Header common to all native messages.
 *
 * @code: the actual type of the message.
 * @resv: Set to zero, ignore on receive.
 * @vsplit: If a variable section is split in 2, the length of first part.
 * @refer_id: the session, txn, conn, etc, this message is associated with.
 * @req_id: the request this message is for.
 */
struct mgmt_msg_header {
	uint16_t code;
	uint16_t resv;
	uint32_t vsplit;
	uint64_t refer_id;
	uint64_t req_id;
};
_Static_assert(sizeof(struct mgmt_msg_header) == 3 * 8, "Bad padding");
_Static_assert(sizeof(struct mgmt_msg_header) ==
		       offsetof(struct mgmt_msg_header, req_id) +
			       sizeof(((struct mgmt_msg_header *)0)->req_id),
	       "Size mismatch");

/**
 * struct mgmt_msg_error - Common error message.
 *
 * @error: An error value.
 * @errst: Description of error can be 0 length.
 *
 * This common error message can be used for replies for many msg requests
 * (req_id).
 */
struct mgmt_msg_error {
	struct mgmt_msg_header;
	int16_t error;
	uint8_t resv2[6];

	alignas(8) char errstr[];
};
_Static_assert(sizeof(struct mgmt_msg_error) ==
		       offsetof(struct mgmt_msg_error, errstr),
	       "Size mismatch");

/**
 * struct mgmt_msg_get_tree - backend oper data request.
 *
 * @result_type: ``LYD_FORMAT`` for the returned result.
 * @xpath: the query for the data to return.
 */
struct mgmt_msg_get_tree {
	struct mgmt_msg_header;
	uint8_t result_type;
	uint8_t resv2[7];

	alignas(8) char xpath[];
};
_Static_assert(sizeof(struct mgmt_msg_get_tree) ==
		       offsetof(struct mgmt_msg_get_tree, xpath),
	       "Size mismatch");

/**
 * struct mgmt_msg_tree_data - Message carrying tree data.
 *
 * @partial_error: If the full result could not be returned do to this error.
 * @result_type: ``LYD_FORMAT`` for format of the @result value.
 * @more: if this is a partial return and there will be more coming.
 * @result: The tree data in @result_type format.
 *
 */
struct mgmt_msg_tree_data {
	struct mgmt_msg_header;
	int8_t partial_error;
	uint8_t result_type;
	uint8_t more;
	uint8_t resv2[5];

	alignas(8) uint8_t result[];
};
_Static_assert(sizeof(struct mgmt_msg_tree_data) ==
		       offsetof(struct mgmt_msg_tree_data, result),
	       "Size mismatch");

/* Flags for get-data request */
#define GET_DATA_FLAG_STATE	0x01	/* include "config false" data */
#define GET_DATA_FLAG_CONFIG	0x02	/* include "config true" data */
#define GET_DATA_FLAG_EXACT	0x04	/* get exact data node instead of the full tree */

/*
 * Modes of reporting default values. Non-default values are always reported.
 * These options reflect "with-defaults" modes as defined in RFC 6243.
 */
#define GET_DATA_DEFAULTS_EXPLICIT    0 /* "explicit" */
#define GET_DATA_DEFAULTS_TRIM	      1 /* "trim"  */
#define GET_DATA_DEFAULTS_ALL	      2 /* "report-all" */
#define GET_DATA_DEFAULTS_ALL_ADD_TAG 3 /* "report-all-tagged" */

/**
 * struct mgmt_msg_get_data - frontend get-data request.
 *
 * @result_type: ``LYD_FORMAT`` for the returned result.
 * @flags: combination of ``GET_DATA_FLAG_*`` flags.
 * @defaults: one of ``GET_DATA_DEFAULTS_*`` values.
 * @xpath: the query for the data to return.
 */
struct mgmt_msg_get_data {
	struct mgmt_msg_header;
	uint8_t result_type;
	uint8_t flags;
	uint8_t defaults;
	uint8_t datastore;
	uint8_t resv2[4];

	alignas(8) char xpath[];
};
_Static_assert(sizeof(struct mgmt_msg_get_data) ==
		       offsetof(struct mgmt_msg_get_data, xpath),
	       "Size mismatch");

/**
 * struct mgmt_msg_notify_data - Message carrying notification data.
 *
 * @result_type: ``LYD_FORMAT`` for format of the @result value.
 * @data: The xpath string of the notification followed by the tree data in
 *        @result_type format.
 */
struct mgmt_msg_notify_data {
	struct mgmt_msg_header;
	uint8_t result_type;
	uint8_t resv2[7];

	alignas(8) char data[];
};
_Static_assert(sizeof(struct mgmt_msg_notify_data) ==
		       offsetof(struct mgmt_msg_notify_data, data),
	       "Size mismatch");

#define EDIT_FLAG_IMPLICIT_LOCK	  0x01
#define EDIT_FLAG_IMPLICIT_COMMIT 0x02

#define EDIT_OP_CREATE	0
#define EDIT_OP_DELETE	4
#define EDIT_OP_MERGE	2
#define EDIT_OP_REPLACE 5
#define EDIT_OP_REMOVE	3

_Static_assert(EDIT_OP_CREATE == NB_OP_CREATE_EXCL, "Operation mismatch");
_Static_assert(EDIT_OP_DELETE == NB_OP_DELETE, "Operation mismatch");
_Static_assert(EDIT_OP_MERGE == NB_OP_MODIFY, "Operation mismatch");
_Static_assert(EDIT_OP_REPLACE == NB_OP_REPLACE, "Operation mismatch");
_Static_assert(EDIT_OP_REMOVE == NB_OP_DESTROY, "Operation mismatch");

/**
 * struct mgmt_msg_edit - frontend edit request.
 *
 * @request_type: ``LYD_FORMAT`` for the @data.
 * @flags: combination of ``EDIT_FLAG_*`` flags.
 * @datastore: the datastore to edit.
 * @operation: one of ``EDIT_OP_*`` operations.
 * @data: the xpath followed by the tree data for the operation.
 *        for CREATE, xpath points to the parent node.
 */
struct mgmt_msg_edit {
	struct mgmt_msg_header;
	uint8_t request_type;
	uint8_t flags;
	uint8_t datastore;
	uint8_t operation;
	uint8_t resv2[4];

	alignas(8) char data[];
};
_Static_assert(sizeof(struct mgmt_msg_edit) ==
		       offsetof(struct mgmt_msg_edit, data),
	       "Size mismatch");

/**
 * struct mgmt_msg_edit_reply - frontend edit reply.
 *
 * @changed: If true then changes in datastore resulted.
 * @created: If true then object was newly created (non-existing before)
 * @data: @vsplit values, second value may be zero len.
 * @data: [0] the xpath of the data node that was created.
 * @data: [1] Possible structured data to pass back to client (e.g., non-"error"
 *        yang modeled error data).
 */
struct mgmt_msg_edit_reply {
	struct mgmt_msg_header;
	uint8_t changed;
	uint8_t created;
	uint8_t resv2[6];

	alignas(8) char data[];
};
_Static_assert(sizeof(struct mgmt_msg_edit_reply) ==
		       offsetof(struct mgmt_msg_edit_reply, data),
	       "Size mismatch");

/**
 * struct mgmt_msg_rpc - RPC/action request.
 *
 * @request_type: ``LYD_FORMAT`` for the @data.
 * @data: the xpath followed by the tree data for the operation.
 */
struct mgmt_msg_rpc {
	struct mgmt_msg_header;
	uint8_t request_type;
	uint8_t resv2[7];

	alignas(8) char data[];
};

_Static_assert(sizeof(struct mgmt_msg_rpc) ==
		       offsetof(struct mgmt_msg_rpc, data),
	       "Size mismatch");

/**
 * struct mgmt_msg_rpc_reply - RPC/action reply.
 *
 * @result_type: ``LYD_FORMAT`` for the @data.
 * @data: the tree data for the reply.
 */
struct mgmt_msg_rpc_reply {
	struct mgmt_msg_header;
	uint8_t result_type;
	uint8_t resv2[7];

	alignas(8) char data[];
};

_Static_assert(sizeof(struct mgmt_msg_rpc_reply) ==
		       offsetof(struct mgmt_msg_rpc_reply, data),
	       "Size mismatch");

/**
 * struct mgmt_msg_notify_select - Add notification selectors for FE client.
 *
 * Add xpath prefix notification selectors to limit the notifications sent
 * to the front-end client.
 *
 * @selectors: the xpath prefixes to selectors notifications through.
 * @replace: if true replace existing selectors with `selectors`.
 */
struct mgmt_msg_notify_select {
	struct mgmt_msg_header;
	uint8_t replace;
	uint8_t resv2[7];

	alignas(8) char selectors[];
};

_Static_assert(sizeof(struct mgmt_msg_notify_select) ==
		       offsetof(struct mgmt_msg_notify_select, selectors),
	       "Size mismatch");

/**
 * struct mgmt_msg_session_req - Create or delete a front-end session.
 *
 * @refer_id: Zero for create, otherwise the session-id to delete.
 * @req_id: For create will use as client-id.
 * @client_name: For first session request the client name, otherwise empty.
 */
struct mgmt_msg_session_req {
	struct mgmt_msg_header;
	uint8_t resv2[8]; /* bug in compiler produces error w/o this */

	alignas(8) char client_name[];
};

_Static_assert(sizeof(struct mgmt_msg_session_req) ==
		       offsetof(struct mgmt_msg_session_req, client_name),
	       "Size mismatch");

/**
 * struct mgmt_msg_session_reply - Reply to session request message.
 *
 * @created: true if this is a reply to a create request, otherwise 0.
 * @refer_id: The session-id for the action (create or delete) just taken.
 */
struct mgmt_msg_session_reply {
	struct mgmt_msg_header;
	uint8_t created;
	uint8_t resv2[7];
};

/*
 * Validate that the message ends in a NUL terminating byte
 */
#define MGMT_MSG_VALIDATE_NUL_TERM(msgp, len)                                  \
	((len) >= sizeof(*msgp) + 1 && ((char *)msgp)[(len)-1] == 0)

/**
 * mgmt_msg_get_min_size() - Get minimum message size given the type
 * @code: The type of the message (MGMT_MSG_CODE_*)
 *
 * Return:
 *	The minimum size of a message of the given type or 0 if the message
 *	code is unknown.
 */
size_t mgmt_msg_get_min_size(uint code);

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

/**
 * mgmt_msg_native_alloc_msg() - Create a native appendable msg.
 * @msg_type: The message structure type.
 * @var_len: The initial additional length to add to the message.
 * @mem_type: The initial additional length to add to the message.
 *
 * This function takes a C type (e.g., `struct mgmt_msg_get_tree`) as an
 * argument and returns a new native message. The newly allocated message
 * can be used with the other `native` functions.
 *
 * Importantly the mgmt_msg_native_append() function can be used to add data
 * to the end of the message, and mgmt_msg_get_native_msg_len() can be used
 * to obtain the total length of the message (i.e., the fixed sized header plus
 * the variable length data that has been appended).
 *
 * Additionally, a dynamic array (darr) pointer can be obtained using
 * mgmt_msg_get_native_darr() which allows adding and manipulating the
 * variable data that follows the fixed sized header.
 *
 * Return: A `msg_type` object created using a dynamic_array.
 */
#define mgmt_msg_native_alloc_msg(msg_type, var_len, mem_type)                 \
	({                                                                     \
		uint8_t *buf = NULL;                                           \
		(msg_type *)darr_append_nz_mt(buf,                             \
					      sizeof(msg_type) + (var_len),    \
					      mem_type);                       \
	})

/**
 * mgmt_msg_free_native_msg() - Free a native msg.
 * @msg - pointer to message allocated by mgmt_msg_create_native_msg().
 */
#define mgmt_msg_native_free_msg(msg) darr_free(msg)

/**
 * mgmt_msg_native_get_msg_len() - Get the total length of the msg.
 * @msg: the native message.
 *
 * Return: the total length of the message, fixed + variable length.
 */
#define mgmt_msg_native_get_msg_len(msg) (darr_len((uint8_t *)(msg)))

/**
 * mgmt_msg_native_append() - Append data to the end of the msg.
 * @msg: (IN/OUT) Pointer to the native message, variable may be updated.
 * @data: data to append.
 * @len: length of data to append.
 *
 * Append @data of length @len to the native message @msg.
 *
 * NOTE: Be aware @msg pointer may change as a result of reallocating the
 * message to fit the new data. Any other pointers into the old message should
 * be discarded.
 *
 * Return: a pointer to the newly appended data.
 */
#define mgmt_msg_native_append(msg, data, len)                                 \
	({                                                                     \
		uint8_t **darrp = mgmt_msg_native_get_darrp(msg);              \
		uint8_t *p = darr_append_n(*darrp, len);                       \
		memcpy(p, data, len);                                          \
		p;                                                             \
	})

/**
 * mgmt_msg_native_add_str() - Append [another] string to the msg.
 * @msg: (IN/OUT) Pointer to the native message, variable may be updated.
 * @s: string to append.
 *
 * Append string @s to the native message @msg. @msg is assumed to have a
 * sequence of NUL-terminated strings at the end of it. This function appends
 * the string @s and it's NUL terminating octet to the message.
 *
 * NOTE: Be aware @msg pointer may change as a result of reallocating the
 * message to fit the new data. Any other pointers into the old message should
 * be discarded.
 */
#define mgmt_msg_native_add_str(msg, s)                                        \
	do {                                                                   \
		int __len = strlen(s) + 1;                                     \
		mgmt_msg_native_append(msg, s, __len);                         \
	} while (0)

/**
 * mgmt_msg_native_send_msg(msg, short_circuit_ok) - Send a native msg.
 * @conn: the mgmt_msg connection.
 * @msg: the native message.
 * @short_circuit_ok: True if short-circuit sending is required.
 *
 * Return: The error return value of msg_conn_send_msg().
 */
#define mgmt_msg_native_send_msg(conn, msg, short_circuit_ok)                  \
	msg_conn_send_msg(conn, MGMT_MSG_VERSION_NATIVE, msg,                  \
			  mgmt_msg_native_get_msg_len(msg), NULL,              \
			  short_circuit_ok)

/**
 * mgmt_msg_native_get_darrp() - Return a ptr to the dynamic array ptr.
 * @msg: Pointer to the native message.
 *
 * NOTE: Most users can simply use mgmt_msg_native_append() instead of this.
 *
 * This function obtains a pointer to the dynamic byte array for this message,
 * this array actually includes the message header if one is going to look at
 * the length value. With that in mind any of the `darr_*()` functions/API may
 * be used to manipulate the variable data at the end of the message.
 *
 * NOTE: The pointer returned is actually a pointer to the message pointer
 * passed in to this function. This pointer to pointer is required so that
 * realloc can be done inside the darr API.
 *
 * NOTE: If reallocs happen the original passed in pointer will be updated;
 * however, any other pointers into the message will become invalid and so they
 * should always be discarded after using the returned value.
 *
 * Example:
 *
 *     void append_metric_path(struct mgmt_msg_my_msg *msg)
 *     {
 *          char *xpath = msg->xpath;	// pointer into message
 *          uint8_t **darp;
 *
 *          darrp = mgmt_msg_native_get_darrp(msg);
 *          darr_in_strcat(*darrp, "/metric");
 *
 *          xpath = NULL;		// now invalid
 *          xpath = msg->xpath;
 *     }
 *
 *
 * Return: A pointer to the first argument -- which is a pointer to a pointer to
 * a dynamic array.
 */
#define mgmt_msg_native_get_darrp(msg) ((uint8_t **)&(msg))

/* ------------------------- */
/* Encode and Decode Helpers */
/* ------------------------- */

/**
 * mgmt_msg_native_xpath_encode() - encode an xpath in a xpath, data message.
 * @msg: Pointer to the native message.
 * @xpath: The xpath string to encode.
 *
 * This function starts the encoding of a message that can be decoded with
 * `mgmt_msg_native_xpath_data_decode()`. The variable length data is comprised
 * of a NUL terminated string followed by some data of any format. This starts
 * the first half of the encoding, after which one can simply append the
 * secondary data to the message.
 */
#define mgmt_msg_native_xpath_encode(msg, xpath)                               \
	do {                                                                   \
		size_t __slen = strlen(xpath) + 1;                             \
		mgmt_msg_native_append(msg, xpath, __slen);                    \
		(msg)->vsplit = __slen;                                        \
	} while (0)

/**
 * mgmt_msg_native_xpath_data_decode() - decode an xpath, data format message.
 * @msg: Pointer to the native message.
 * @msglen: Length of the message.
 * @data: [OUT] Pointer to the data section of the variable data
 *
 * This function decodes a message that was encoded with
 * `mgmt_msg_native_xpath_encode()`. The variable length data is comprised of a
 * NUL terminated string followed by some data of any format.
 *
 * Return:
 *	The xpath string or NULL if there was an error decoding (i.e., the
 *	message is corrupt).
 */
#define mgmt_msg_native_xpath_data_decode(msg, msglen, __data)                 \
	({                                                                     \
		size_t __len = (msglen) - sizeof(*msg);                        \
		const char *__s = NULL;                                        \
		if (msg->vsplit && msg->vsplit <= __len &&                     \
		    msg->data[msg->vsplit - 1] == 0) {                         \
			if (msg->vsplit < __len)                               \
				(__data) = msg->data + msg->vsplit;            \
			else                                                   \
				(__data) = NULL;                               \
			__s = msg->data;                                       \
		}                                                              \
		__s;                                                           \
	})

/**
 * mgmt_msg_native_xpath_decode() - return the xpath from xpath, data message.
 * @msg: Pointer to the native message.
 * @msglen: Length of the message.
 *
 * This function decodes the xpath from a message that was encoded with
 * `mgmt_msg_native_xpath_encode()`. The variable length data is comprised of a
 * NUL terminated string followed by some data of any format.
 *
 * Return:
 *	The xpath string or NULL if there was an error decoding (i.e., the
 *	message is corrupt).
 */
#define mgmt_msg_native_xpath_decode(msg, msglen)                              \
	({                                                                     \
		size_t __len = (msglen) - sizeof(*msg);                        \
		const char *__s = msg->data;                                   \
		if (!msg->vsplit || msg->vsplit > __len ||                     \
		    __s[msg->vsplit - 1] != 0)                                 \
			__s = NULL;                                            \
		__s;                                                           \
	})

/**
 * mgmt_msg_native_data_decode() - return the data from xpath, data message.
 * @msg: Pointer to the native message.
 * @msglen: Length of the message.
 *
 * This function decodes the secondary data from a message that was encoded with
 * `mgmt_msg_native_xpath_encode()`. The variable length data is comprised of a
 * NUL terminated string followed by some data of any format.
 *
 * Return:
 *	The secondary data or NULL if there was an error decoding (i.e., the
 *	message is corrupt).
 */
#define mgmt_msg_native_data_decode(msg, msglen)                               \
	({                                                                     \
		size_t __len = (msglen) - sizeof(*msg);                        \
		const char *__data = msg->data + msg->vsplit;                  \
		if (!msg->vsplit || msg->vsplit > __len || __data[-1] != 0)    \
			__data = NULL;                                         \
		__data;                                                        \
	})

/**
 * mgmt_msg_native_data_len_decode() - len of data in xpath, data format message.
 * @msg: Pointer to the native message.
 * @msglen: Length of the message.
 *
 * This function returns the length of the secondary variable data from a
 * message that was encoded with `mgmt_msg_native_xpath_encode()`. The variable
 * length data is comprised of a NUL terminated string followed by some data of
 * any format.
 *
 * Return:
 *	The length of the secondary variable data. The message is assumed to be
 *	validated as not corrupt already.
 */
#define mgmt_msg_native_data_len_decode(msg, msglen)                           \
	((msglen) - sizeof(*msg) - msg->vsplit)

/**
 * mgmt_msg_native_strings_decode() - Get dynamic array of str ptrs from the msg.
 * @msg: Pointer to the native message.
 * @msglen: Length of the message.
 * @sdata: pointer to the variable length string data at end of @msg.
 *
 * Given a pointer to a sequence of NUL-terminated strings allocate
 * and return a dynamic array of dynamic array strings. This function
 * can be used to decode a message that was built using
 * mgmt_msg_native_add_str().
 *
 * Return: a dynamic array (darr) of string pointers, or NULL if the message
 * is corrupt.
 */
#define mgmt_msg_native_strings_decode(msg, msg_len, sdata)                    \
	_mgmt_msg_native_strings_decode(sdata,                                 \
					(msg_len) - ((sdata) - (char *)(msg)))

extern const char **_mgmt_msg_native_strings_decode(const void *sdata,
						    int sdlen);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMT_MSG_NATIVE_H_ */
