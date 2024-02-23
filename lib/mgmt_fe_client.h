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
#include "frrevent.h"
#include "mgmt_defines.h"
#include "mgmt_msg_native.h"

/***************************************************************
 * Macros
 ***************************************************************/

/*
 * The server port MGMTD daemon is listening for Backend Client
 * connections.
 */

#define MGMTD_FE_MSG_PROC_DELAY_USEC 10

#define MGMTD_FE_MAX_NUM_MSG_PROC  500
#define MGMTD_FE_MAX_NUM_MSG_WRITE 100
#define MGMTD_FE_MAX_MSG_LEN	   (64 * 1024)

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

struct mgmt_fe_client;


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
struct mgmt_fe_client_cbs {
	void (*client_connect_notify)(struct mgmt_fe_client *client,
				      uintptr_t user_data, bool connected);

	void (*client_session_notify)(struct mgmt_fe_client *client,
				      uintptr_t user_data, uint64_t client_id,
				      bool create, bool success,
				      uintptr_t session_id,
				      uintptr_t user_session_client);

	void (*lock_ds_notify)(struct mgmt_fe_client *client,
			       uintptr_t user_data, uint64_t client_id,
			       uintptr_t session_id,
			       uintptr_t user_session_client, uint64_t req_id,
			       bool lock_ds, bool success,
			       Mgmtd__DatastoreId ds_id, char *errmsg_if_any);

	void (*set_config_notify)(struct mgmt_fe_client *client,
				  uintptr_t user_data, uint64_t client_id,
				  uintptr_t session_id,
				  uintptr_t user_session_client,
				  uint64_t req_id, bool success,
				  Mgmtd__DatastoreId ds_id, bool implcit_commit,
				  char *errmsg_if_any);

	void (*commit_config_notify)(struct mgmt_fe_client *client,
				     uintptr_t user_data, uint64_t client_id,
				     uintptr_t session_id,
				     uintptr_t user_session_client,
				     uint64_t req_id, bool success,
				     Mgmtd__DatastoreId src_ds_id,
				     Mgmtd__DatastoreId dst_ds_id,
				     bool validate_only, char *errmsg_if_any);

	int (*get_data_notify)(struct mgmt_fe_client *client,
			       uintptr_t user_data, uint64_t client_id,
			       uintptr_t session_id,
			       uintptr_t user_session_client, uint64_t req_id,
			       bool success, Mgmtd__DatastoreId ds_id,
			       Mgmtd__YangData **yang_data, size_t num_data,
			       int next_key, char *errmsg_if_any);

	int (*data_notify)(uint64_t client_id, uint64_t session_id,
			   uintptr_t user_data, uint64_t req_id,
			   Mgmtd__DatastoreId ds_id,
			   Mgmtd__YangData **yang_data, size_t num_data);

	/* Called when get-tree result is returned */
	int (*get_tree_notify)(struct mgmt_fe_client *client,
			       uintptr_t user_data, uint64_t client_id,
			       uint64_t session_id, uintptr_t session_ctx,
			       uint64_t req_id, Mgmtd__DatastoreId ds_id,
			       LYD_FORMAT result_type, void *result, size_t len,
			       int partial_error);

	/* Called with asynchronous notifications from backends */
	int (*async_notification)(struct mgmt_fe_client *client,
				  uintptr_t user_data, uint64_t client_id,
				  uint64_t session_id, uintptr_t session_ctx,
				  const char *result);

	/* Called when new native error is returned */
	int (*error_notify)(struct mgmt_fe_client *client, uintptr_t user_data,
			    uint64_t client_id, uint64_t session_id,
			    uintptr_t session_ctx, uint64_t req_id, int error,
			    const char *errstr);
};

extern struct debug mgmt_dbg_fe_client;

/***************************************************************
 * API prototypes
 ***************************************************************/

#define debug_fe_client(fmt, ...)                                              \
	DEBUGD(&mgmt_dbg_fe_client, "FE-CLIENT: %s: " fmt, __func__,           \
	       ##__VA_ARGS__)
#define log_err_fe_client(fmt, ...)                                            \
	zlog_err("FE-CLIENT: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#define debug_check_fe_client()                                                \
	DEBUG_MODE_CHECK(&mgmt_dbg_fe_client, DEBUG_MODE_ALL)

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
 *    Frontend client lib handler (nothing but address of mgmt_fe_client)
 */
extern struct mgmt_fe_client *
mgmt_fe_client_create(const char *client_name, struct mgmt_fe_client_cbs *cbs,
		      uintptr_t user_data, struct event_loop *event_loop);

/*
 * Initialize library vty (adds debug support).
 *
 * This call should be added to your component when enabling other vty
 * code to enable mgmtd client debugs. When adding, one needs to also
 * add a their component in `xref2vtysh.py` as well.
 */
extern void mgmt_fe_client_lib_vty_init(void);

/*
 * Print enabled debugging commands.
 */
extern void mgmt_debug_fe_client_show_debug(struct vty *vty);

/*
 * Create a new Session for a Frontend Client connection.
 *
 * lib_hndl
 *    Client library handler.
 *
 * client_id
 *    Unique identifier of client.
 *
 * user_client
 *    Client context.
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern enum mgmt_result
mgmt_fe_create_client_session(struct mgmt_fe_client *client, uint64_t client_id,
			      uintptr_t user_client);

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
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern enum mgmt_result
mgmt_fe_destroy_client_session(struct mgmt_fe_client *client,
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
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern int mgmt_fe_send_lockds_req(struct mgmt_fe_client *client,
				   uint64_t session_id, uint64_t req_id,
				   Mgmtd__DatastoreId ds_id, bool lock_ds,
				   bool scok);

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
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */

extern int mgmt_fe_send_setcfg_req(struct mgmt_fe_client *client,
				   uint64_t session_id, uint64_t req_id,
				   Mgmtd__DatastoreId ds_id,
				   Mgmtd__YangCfgDataReq **config_req,
				   int num_req, bool implicit_commit,
				   Mgmtd__DatastoreId dst_ds_id);

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
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern int mgmt_fe_send_commitcfg_req(struct mgmt_fe_client *client,
				      uint64_t session_id, uint64_t req_id,
				      Mgmtd__DatastoreId src_ds_id,
				      Mgmtd__DatastoreId dst_ds_id,
				      bool validate_only, bool abort);

/*
 * Send GET_REQ to MGMTD for one or more config data item(s).
 *
 * If is_config is true gets config from the MGMTD datastore, otherwise
 * operational state is queried from the backend clients.
 *
 * lib_hndl
 *    Client library handler.
 *
 * session_id
 *    Client session ID.
 *
 * is_config
 *    True if get-config else get-data.
 *
 * req_id
 *    Client request ID.
 *
 * ds_id
 *    Datastore ID (Running/Candidate)
 *
 * data_req
 *    Get xpaths requested.
 *
 * num_req
 *    Number of get xpath requests.
 *
 * Returns:
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern int mgmt_fe_send_get_req(struct mgmt_fe_client *client,
				uint64_t session_id, uint64_t req_id,
				bool is_config, Mgmtd__DatastoreId ds_id,
				Mgmtd__YangGetDataReq **data_req, int num_reqs);


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
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern int mgmt_fe_send_regnotify_req(struct mgmt_fe_client *client,
				      uint64_t session_id, uint64_t req_id,
				      Mgmtd__DatastoreId ds_id,
				      bool register_req,
				      Mgmtd__YangDataXPath **data_req,
				      int num_reqs);

/*
 * Send GET-DATA to MGMTD daemon.
 *
 * client
 *    Client object.
 *
 * session_id
 *    Client session ID.
 *
 * req_id
 *    Client request ID.
 *
 * datastore
 *    Datastore for getting data.
 *
 * result_type
 *    The LYD_FORMAT of the result.
 *
 * flags
 *    Flags to control the behavior of the request.
 *
 * defaults
 *    Options to control the reporting of default values.
 *
 * xpath
 *    the xpath to get.
 *
 * Returns:
 *    0 on success, otherwise msg_conn_send_msg() return values.
 */
extern int mgmt_fe_send_get_data_req(struct mgmt_fe_client *client,
				     uint64_t session_id, uint64_t req_id,
				     uint8_t datastore, LYD_FORMAT result_type,
				     uint8_t flags, uint8_t defaults,
				     const char *xpath);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_fe_client_destroy(struct mgmt_fe_client *client);

/*
 * Get count of open sessions.
 */
extern uint mgmt_fe_client_session_count(struct mgmt_fe_client *client);

/*
 * True if the current handled message is being short-circuited
 */
extern bool
mgmt_fe_client_current_msg_short_circuit(struct mgmt_fe_client *client);

/**
 * Get the name of the client
 *
 * Args:
 *	The client object.
 *
 * Return:
 *	The name of the client.
 */
extern const char *mgmt_fe_client_name(struct mgmt_fe_client *client);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_FE_CLIENT_H_ */
