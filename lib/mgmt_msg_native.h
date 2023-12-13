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
#include "darr.h"
#include "memory.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"

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

/*
 * Native message codes
 */
#define MGMT_MSG_CODE_ERROR	0
#define MGMT_MSG_CODE_GET_TREE	1
#define MGMT_MSG_CODE_TREE_DATA 2

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
 * struct mgmt_msg_get_tree - Message carrying xpath query request.
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
	memcpy(darr_append(*mgmt_msg_native_get_darrp(msg), len), data, len)

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

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMT_MSG_NATIVE_H_ */
