/*
 * MGMTD Frontend Client Library api interfaces
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

#ifndef _FRR_MGMTD_FE_CLIENT_H_
#define _FRR_MGMTD_FE_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mgmtd/mgmt_defines.h"
#include "mgmt_pb.h"

/***************************************************************
 * Macros
 ***************************************************************/

/*
 * The server port MGMTD daemon is listening for Backend Client
 * connections.
 */

#define MGMTD_FE_CLIENT_ERROR_STRING_MAX_LEN 32

#define MGMTD_FE_DEFAULT_CONN_RETRY_INTVL_SEC 5

#define MGMTD_FE_MSG_PROC_DELAY_USEC 10
#define MGMTD_FE_MAX_NUM_MSG_PROC 500

#define MGMTD_FE_MSG_WRITE_DELAY_MSEC 1
#define MGMTD_FE_MAX_NUM_MSG_WRITE 100

#define GMGD_FE_MAX_NUM_REQ_ITEMS 64

#define MGMTD_FE_MSG_MAX_LEN 9000

#define MGMTD_SOCKET_FE_SEND_BUF_SIZE 65535
#define MGMTD_SOCKET_FE_RECV_BUF_SIZE MGMTD_SOCKET_FE_SEND_BUF_SIZE

/***************************************************************
 * Data-structures
 ***************************************************************/

#define MGMTD_SESSION_ID_NONE 0

#define MGMTD_CLIENT_ID_NONE 0

#define MGMTD_DB_NONE MGMTD__DATABASE_ID__DB_NONE
#define MGMTD_DB_RUNNING MGMTD__DATABASE_ID__RUNNING_DB
#define MGMTD_DB_CANDIDATE MGMTD__DATABASE_ID__CANDIDATE_DB
#define MGMTD_DB_OPERATIONAL MGMTD__DATABASE_ID__OPERATIONAL_DB
#define MGMTD_DB_MAX_ID MGMTD_DB_OPERATIONAL + 1

struct mgmt_fe_msg_hdr {
	uint16_t marker;
	uint16_t len; /* Includes header */
};
#define MGMTD_FE_MSG_HDR_LEN sizeof(struct mgmt_fe_msg_hdr)
#define MGMTD_FE_MSG_MARKER 0xdeaf

struct mgmt_fe_msg {
	struct mgmt_fe_msg_hdr hdr;
	uint8_t payload[];
};

/*
 * All the client specific information this library needs to
 * initialize itself, setup connection with MGMTD FrontEnd interface
 * and carry on all required procedures appropriately.
 *
 * FrontEnd clients need to initialise a instance of this structure
 * with appropriate data and pass it while calling the API
 * to initialize the library (See mgmt_fe_client_lib_init for
 * more details).
 */
struct mgmt_fe_client_params {
	char name[MGMTD_CLIENT_NAME_MAX_LEN];
	uintptr_t user_data;
	unsigned long conn_retry_intvl_sec;

	void (*client_connect_notify)(uintptr_t lib_hndl,
				      uintptr_t user_data,
				      bool connected);

	void (*client_session_notify)(uintptr_t lib_hndl,
				      uintptr_t user_data,
				      uint64_t client_id,
				      bool create, bool success,
				      uintptr_t session_id,
				      uintptr_t user_session_ctx);

	void (*lock_db_notify)(uintptr_t lib_hndl, uintptr_t user_data,
			       uint64_t client_id, uintptr_t session_id,
			       uintptr_t user_session_ctx, uint64_t req_id,
			       bool lock_db, bool success,
			       Mgmtd__DatabaseId db_id, char *errmsg_if_any);

	void (*set_config_notify)(uintptr_t lib_hndl, uintptr_t user_data,
				  uint64_t client_id, uintptr_t session_id,
				  uintptr_t user_session_ctx, uint64_t req_id,
				  bool success, Mgmtd__DatabaseId db_id,
				  char *errmsg_if_any);

	void (*commit_config_notify)(
		uintptr_t lib_hndl, uintptr_t user_data, uint64_t client_id,
		uintptr_t session_id, uintptr_t user_session_ctx,
		uint64_t req_id, bool success, Mgmtd__DatabaseId src_db_id,
		Mgmtd__DatabaseId dst_db_id, bool validate_only,
		char *errmsg_if_any);

	enum mgmt_result (*get_data_notify)(
		uintptr_t lib_hndl, uintptr_t user_data, uint64_t client_id,
		uintptr_t session_id, uintptr_t user_session_ctx,
		uint64_t req_id, bool success, Mgmtd__DatabaseId db_id,
		Mgmtd__YangData **yang_data, size_t num_data, int next_key,
		char *errmsg_if_any);

	enum mgmt_result (*data_notify)(
		uint64_t client_id, uint64_t session_id, uintptr_t user_data,
		uint64_t req_id, Mgmtd__DatabaseId db_id,
		Mgmtd__YangData **yang_data, size_t num_data);
};

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with MGMTD FrontEnd interface.
 *
 * params
 *    Frontend client parameters.
 *
 * master_thread
 *    Thread master.
 *
 * Returns:
 *    Frontend client lib handler (nothing but address of mgmt_fe_client_ctx)
 */
extern uintptr_t
mgmt_fe_client_lib_init(struct mgmt_fe_client_params *params,
			    struct thread_master *master_thread);

/*
 * Create a new Session for a Frontend Client connection.
 *
 * lib_hndl
 *    Client library handler.
 *
 * client_id
 *    Unique identifier of client.
 *
 * user_ctx
 *    Client context.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result mgmt_fe_create_client_session(uintptr_t lib_hndl,
							  uint64_t client_id,
							  uintptr_t user_ctx);

/*
 * Delete an existing Session for a Frontend Client connection.
 *
 * lib_hndl
 *    Client library handler.
 *
 * client_id
 *    Unique identifier of client.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result mgmt_fe_destroy_client_session(uintptr_t lib_hndl,
						       uint64_t client_id);

/*
 * Send UN/LOCK_DB_REQ to MGMTD for a specific Datastore DB.
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * db_id
 *    Database ID (Running/Candidate/Oper/Startup)
 *
 * lock_db
 *    TRUE for lock request, FALSE for unlock request.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_lock_db(uintptr_t lib_hndl, uintptr_t session_id, uint64_t req_id,
		    Mgmtd__DatabaseId db_id, bool lock_db);

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * db_id
 *    Database ID (Running/Candidate/Oper/Startup)
 *
 * conf_req
 *    Details regarding the SET_CONFIG_REQ.
 *
 * num_req
 *    Number of config requests.
 *
 * implcit commit
 *    TRUE for implicit commit, FALSE otherwise.
 *
 * dst_db_id
 *    Destination Database ID where data needs to be set.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_set_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			    uint64_t req_id, Mgmtd__DatabaseId db_id,
			    Mgmtd__YangCfgDataReq **config_req, int num_req,
			    bool implicit_commit, Mgmtd__DatabaseId dst_db_id);

/*
 * Send SET_COMMMIT_REQ to MGMTD for one or more config data(s).
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * src_db_id
 *    Source database ID from where data needs to be committed from.
 *
 * dst_db_id
 *    Destination database ID where data needs to be committed to.
 *
 * validate_only
 *    TRUE if data needs to be validated only, FALSE otherwise.
 *
 * abort
 *    TRUE if need to restore Src DB back to Dest DB, FALSE otherwise.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_commit_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			       uint64_t req_id, Mgmtd__DatabaseId src_db_id,
			       Mgmtd__DatabaseId dst_db_id, bool validate_only,
			       bool abort);

/*
 * Send GET_CONFIG_REQ to MGMTD for one or more config data item(s).
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * db_id
 *    Database ID (Running/Candidate)
 *
 * data_req
 *    Get config requested.
 *
 * num_req
 *    Number of get config requests.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_get_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			    uint64_t req_id, Mgmtd__DatabaseId db_id,
			    Mgmtd__YangGetDataReq **data_req, int num_reqs);

/*
 * Send GET_DATA_REQ to MGMTD for one or more data item(s).
 *
 * Similar to get config request but supports getting data
 * from operational db aka backend clients directly.
 */
extern enum mgmt_result
mgmt_fe_get_data(uintptr_t lib_hndl, uintptr_t session_id, uint64_t req_id,
		     Mgmtd__DatabaseId db_id, Mgmtd__YangGetDataReq **data_req,
		     int num_reqs);

/*
 * Send NOTIFY_REGISTER_REQ to MGMTD daemon.
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * db_id
 *    Database ID.
 *
 * register_req
 *    TRUE if registering, FALSE otherwise.
 *
 * data_req
 *    Details of the YANG notification data.
 *
 * num_reqs
 *    Number of data requests.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_register_yang_notify(uintptr_t lib_hndl, uintptr_t session_id,
				 uint64_t req_id, Mgmtd__DatabaseId db_id,
				 bool register_req,
				 Mgmtd__YangDataXPath **data_req, int num_reqs);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_fe_client_lib_destroy(uintptr_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_FE_CLIENT_H_ */
