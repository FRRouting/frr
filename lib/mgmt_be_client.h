/*
 * MGMTD Backend Client Library api interfaces
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

#ifndef _FRR_MGMTD_BE_CLIENT_H_
#define _FRR_MGMTD_BE_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mgmtd/mgmt_defines.h"

/***************************************************************
 * Macros
 ***************************************************************/

#define MGMTD_BE_CLIENT_ERROR_STRING_MAX_LEN 32

#define MGMTD_BE_DEFAULT_CONN_RETRY_INTVL_SEC 5

#define MGMTD_BE_MSG_PROC_DELAY_USEC 10
#define MGMTD_BE_MAX_NUM_MSG_PROC 500

#define MGMTD_BE_MSG_WRITE_DELAY_MSEC 1
#define MGMTD_BE_MAX_NUM_MSG_WRITE 1000

#define GMGD_BE_MAX_NUM_REQ_ITEMS 64

#define MGMTD_BE_MSG_MAX_LEN 16384

#define MGMTD_SOCKET_BE_SEND_BUF_SIZE 65535
#define MGMTD_SOCKET_BE_RECV_BUF_SIZE MGMTD_SOCKET_BE_SEND_BUF_SIZE

/*
 * MGMTD_BE_MSG_MAX_LEN must be used 80%
 * since there is overhead of google protobuf
 * that gets added to sent message
 */
#define MGMTD_BE_CFGDATA_PACKING_EFFICIENCY 0.8
#define MGMTD_BE_CFGDATA_MAX_MSG_LEN                                        \
	(MGMTD_BE_MSG_MAX_LEN * MGMTD_BE_CFGDATA_PACKING_EFFICIENCY)

#define MGMTD_BE_MAX_BATCH_IDS_IN_REQ                                       \
	(MGMTD_BE_MSG_MAX_LEN - 128) / sizeof(uint64_t)

/*
 * List of name identifiers for all backend clients to
 * supply while calling mgmt_be_client_lib_init().
 */
#define MGMTD_BE_CLIENT_BGPD "bgpd"
#define MGMTD_BE_CLIENT_STATICD "staticd"


#define MGMTD_BE_CONTAINER_NODE_VAL "<<container>>"

/***************************************************************
 * Data-structures
 ***************************************************************/

enum mgmt_be_client_id {
	MGMTD_BE_CLIENT_ID_MIN = 0,
	MGMTD_BE_CLIENT_ID_STATICD = MGMTD_BE_CLIENT_ID_MIN,
	MGMTD_BE_CLIENT_ID_BGPD,
	MGMTD_BE_CLIENT_ID_MAX
};

#define FOREACH_MGMTD_BE_CLIENT_ID(id)                                      \
	for ((id) = MGMTD_BE_CLIENT_ID_MIN;                                 \
	     (id) < MGMTD_BE_CLIENT_ID_MAX; (id)++)

#define MGMTD_BE_MAX_CLIENTS_PER_XPATH_REG 32

struct mgmt_be_msg_hdr {
	uint16_t marker;
	uint16_t len; /* Includes header */
};
#define MGMTD_BE_MSG_HDR_LEN sizeof(struct mgmt_be_msg_hdr)
#define MGMTD_BE_MSG_MARKER 0xfeed

struct mgmt_be_msg {
	struct mgmt_be_msg_hdr hdr;
	uint8_t payload[];
};

struct mgmt_be_client_txn_ctx {
	uintptr_t *user_ctx;
};

/*
 * All the client-specific information this library needs to
 * initialize itself, setup connection with MGMTD BackEnd interface
 * and carry on all required procedures appropriately.
 *
 * BackEnd clients need to initialise a instance of this structure
 * with appropriate data and pass it while calling the API
 * to initialize the library (See mgmt_be_client_lib_init for
 * more details).
 */
struct mgmt_be_client_params {
	char name[MGMTD_CLIENT_NAME_MAX_LEN];
	uintptr_t user_data;
	unsigned long conn_retry_intvl_sec;

	void (*client_connect_notify)(uintptr_t lib_hndl,
				      uintptr_t usr_data,
				      bool connected);

	void (*client_subscribe_notify)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct nb_yang_xpath **xpath,
		enum mgmt_result subscribe_result[], int num_paths);

	void (*txn_notify)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx, bool destroyed);

	enum mgmt_result (*data_validate)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx,
		struct nb_yang_xpath *xpath, struct nb_yang_value *data,
		bool delete, char *error_if_any);

	enum mgmt_result (*data_apply)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx,
		struct nb_yang_xpath *xpath, struct nb_yang_value *data,
		bool delete);

	enum mgmt_result (*get_data_elem)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx,
		struct nb_yang_xpath *xpath, struct nb_yang_xpath_elem *elem);

	enum mgmt_result (*get_data)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx,
		struct nb_yang_xpath *xpath, bool keys_only,
		struct nb_yang_xpath_elem **elems, int *num_elems,
		int *next_key);

	enum mgmt_result (*get_next_data)(
		uintptr_t lib_hndl, uintptr_t usr_data,
		struct mgmt_be_client_txn_ctx *txn_ctx,
		struct nb_yang_xpath *xpath, bool keys_only,
		struct nb_yang_xpath_elem **elems, int *num_elems);
};

/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *mgmt_be_client_names[MGMTD_CLIENT_NAME_MAX_LEN];

static inline const char *mgmt_be_client_id2name(enum mgmt_be_client_id id)
{
	if (id > MGMTD_BE_CLIENT_ID_MAX)
		id = MGMTD_BE_CLIENT_ID_MAX;
	return mgmt_be_client_names[id];
}

static inline enum mgmt_be_client_id
mgmt_be_client_name2id(const char *name)
{
	enum mgmt_be_client_id id;

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (!strncmp(mgmt_be_client_names[id], name,
			     MGMTD_CLIENT_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_BE_CLIENT_ID_MAX;
}

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with MGMTD.
 *
 * params
 *    Backend client parameters.
 *
 * master_thread
 *    Thread master.
 *
 * Returns:
 *    Backend client lib handler (nothing but address of mgmt_be_client_ctx)
 */
extern uintptr_t
mgmt_be_client_lib_init(struct mgmt_be_client_params *params,
			   struct thread_master *master_thread);

/*
 * Subscribe with MGMTD for one or more YANG subtree(s).
 *
 * lib_hndl
 *    Client library handler.
 *
 * reg_yang_xpaths
 *    Yang xpath(s) that needs to be subscribed to.
 *
 * num_xpaths
 *    Number of xpaths
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result mgmt_be_subscribe_yang_data(uintptr_t lib_hndl,
						       char **reg_yang_xpaths,
						       int num_xpaths);

/*
 * Send one or more YANG notifications to MGMTD daemon.
 *
 * lib_hndl
 *    Client library handler.
 *
 * data_elems
 *    Yang data elements from data tree.
 *
 * num_elems
 *    Number of data elements.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_be_send_yang_notify(uintptr_t lib_hndl, Mgmtd__YangData **data_elems,
			    int num_elems);

/*
 * Un-subscribe with MGMTD for one or more YANG subtree(s).
 *
 * lib_hndl
 *    Client library handler.
 *
 * reg_yang_xpaths
 *    Yang xpath(s) that needs to be un-subscribed from.
 *
 * num_reg_xpaths
 *    Number of subscribed xpaths
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
enum mgmt_result mgmt_be_unsubscribe_yang_data(uintptr_t lib_hndl,
						  char **reg_yang_xpaths,
						  int num_reg_xpaths);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_be_client_lib_destroy(uintptr_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_BE_CLIENT_H_ */
