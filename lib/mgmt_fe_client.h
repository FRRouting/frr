// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_FE_CLIENT_H_
#define _FRR_MGMTD_FE_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mgmt_pb.h"
#include "thread.h"
#include "mgmtd/mgmt_defines.h"

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

#define MGMTD_DS_NONE MGMTD__DATASTORE_ID__DS_NONE
#define MGMTD_DS_RUNNING MGMTD__DATASTORE_ID__RUNNING_DS
#define MGMTD_DS_CANDIDATE MGMTD__DATASTORE_ID__CANDIDATE_DS
#define MGMTD_DS_OPERATIONAL MGMTD__DATASTORE_ID__OPERATIONAL_DS
#define MGMTD_DS_MAX_ID MGMTD_DS_OPERATIONAL + 1

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

	void (*lock_ds_notify)(uintptr_t lib_hndl, uintptr_t user_data,
			       uint64_t client_id, uintptr_t session_id,
			       uintptr_t user_session_ctx, uint64_t req_id,
			       bool lock_ds, bool success,
			       Mgmtd__DatastoreId ds_id, char *errmsg_if_any);

	void (*set_config_notify)(uintptr_t lib_hndl, uintptr_t user_data,
				  uint64_t client_id, uintptr_t session_id,
				  uintptr_t user_session_ctx, uint64_t req_id,
				  bool success, Mgmtd__DatastoreId ds_id,
				  char *errmsg_if_any);

	void (*commit_config_notify)(
		uintptr_t lib_hndl, uintptr_t user_data, uint64_t client_id,
		uintptr_t session_id, uintptr_t user_session_ctx,
		uint64_t req_id, bool success, Mgmtd__DatastoreId src_ds_id,
		Mgmtd__DatastoreId dst_ds_id, bool validate_only,
		char *errmsg_if_any);

	enum mgmt_result (*get_data_notify)(
		uintptr_t lib_hndl, uintptr_t user_data, uint64_t client_id,
		uintptr_t session_id, uintptr_t user_session_ctx,
		uint64_t req_id, bool success, Mgmtd__DatastoreId ds_id,
		Mgmtd__YangData **yang_data, size_t num_data, int next_key,
		char *errmsg_if_any);

	enum mgmt_result (*data_notify)(
		uint64_t client_id, uint64_t session_id, uintptr_t user_data,
		uint64_t req_id, Mgmtd__DatastoreId ds_id,
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
 * Send UN/LOCK_DS_REQ to MGMTD for a specific Datastore DS.
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
 * ds_id
 *    Datastore ID (Running/Candidate/Oper/Startup)
 *
 * lock_ds
 *    TRUE for lock request, FALSE for unlock request.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_lock_ds(uintptr_t lib_hndl, uintptr_t session_id, uint64_t req_id,
		    Mgmtd__DatastoreId ds_id, bool lock_ds);

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
 * ds_id
 *    Datastore ID (Running/Candidate/Oper/Startup)
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
 * dst_ds_id
 *    Destination Datastore ID where data needs to be set.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_set_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangCfgDataReq **config_req, int num_req,
			    bool implicit_commit, Mgmtd__DatastoreId dst_ds_id);

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
 * src_ds_id
 *    Source datastore ID from where data needs to be committed from.
 *
 * dst_ds_id
 *    Destination datastore ID where data needs to be committed to.
 *
 * validate_only
 *    TRUE if data needs to be validated only, FALSE otherwise.
 *
 * abort
 *    TRUE if need to restore Src DS back to Dest DS, FALSE otherwise.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_commit_config_data(uintptr_t lib_hndl, uintptr_t session_id,
			       uint64_t req_id, Mgmtd__DatastoreId src_ds_id,
			       Mgmtd__DatastoreId dst_ds_id, bool validate_only,
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
 * ds_id
 *    Datastore ID (Running/Candidate)
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
			    uint64_t req_id, Mgmtd__DatastoreId ds_id,
			    Mgmtd__YangGetDataReq **data_req, int num_reqs);

/*
 * Send GET_DATA_REQ to MGMTD for one or more data item(s).
 *
 * Similar to get config request but supports getting data
 * from operational ds aka backend clients directly.
 */
extern enum mgmt_result
mgmt_fe_get_data(uintptr_t lib_hndl, uintptr_t session_id, uint64_t req_id,
		     Mgmtd__DatastoreId ds_id, Mgmtd__YangGetDataReq **data_req,
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
 * ds_id
 *    Datastore ID.
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
				 uint64_t req_id, Mgmtd__DatastoreId ds_id,
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
