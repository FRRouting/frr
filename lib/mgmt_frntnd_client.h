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

#ifndef _FRR_MGMTD_FRNTND_CLIENT_H_
#define _FRR_MGMTD_FRNTND_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "northbound.h"
#include "mgmtd/mgmt_defines.h"
#include "lib/mgmt_pb.h"

/***************************************************************
 * Macros
 ***************************************************************/

/*
 * The server port MGMTD daemon is listening for Backend Client
 * connections.
 */

#define MGMTD_FRNTND_CLIENT_ERROR_STRING_MAX_LEN 32

#define MGMTD_FRNTND_DEFAULT_CONN_RETRY_INTVL_SEC 5

#define MGMTD_FRNTND_MSG_PROC_DELAY_USEC 10
#define MGMTD_FRNTND_MAX_NUM_MSG_PROC 500

#define MGMTD_FRNTND_MSG_WRITE_DELAY_MSEC 1
#define MGMTD_FRNTND_MAX_NUM_MSG_WRITE 100

#define GMGD_FRNTND_MAX_NUM_REQ_ITEMS 64

#define MGMTD_FRNTND_MSG_MAX_LEN 9000

#define MGMTD_SOCKET_FRNTND_SEND_BUF_SIZE 65535
#define MGMTD_SOCKET_FRNTND_RECV_BUF_SIZE MGMTD_SOCKET_FRNTND_SEND_BUF_SIZE

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

struct mgmt_frntnd_msg_hdr {
	uint16_t marker;
	uint16_t len; /* Includes header */
};
#define MGMTD_FRNTND_MSG_HDR_LEN sizeof(struct mgmt_frntnd_msg_hdr)
#define MGMTD_FRNTND_MSG_MARKER 0xdeaf

struct mgmt_frntnd_msg {
	struct mgmt_frntnd_msg_hdr hdr;
	uint8_t payload[];
};

/*
 * Single handler to notify connection/disconnoect to/from
 * MGMTD daemon.
 */
typedef void (*mgmt_frntnd_client_connect_notify_t)(uint64_t lib_hndl,
						    uint64_t usr_data,
						    bool connected);

/*
 * Single handler to notify results of SESSION_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_session_notify_t)(
	uint64_t lib_hndl, uint64_t usr_data, uint64_t client_id, bool create,
	bool success, uint64_t session_id, uintptr_t user_ctxt);

/*
 * Single handler to notify results of UN/LOCK_DB_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_lock_db_notify_t)(
	uint64_t lib_hndl, uint64_t usr_data, uint64_t client_id,
	uint64_t session_id, uintptr_t user_ctxt, uint64_t req_id, bool lock_db,
	bool success, Mgmtd__DatabaseId db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of SET_CONFIG_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_set_config_notify_t)(
	uint64_t lib_hndl, uint64_t usr_data, uint64_t client_id,
	uint64_t session_id, uintptr_t user_ctxt, uint64_t req_id, bool success,
	Mgmtd__DatabaseId db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of COMMIT_CONFIG_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_commit_config_notify_t)(
	uint64_t lib_hndl, uint64_t usr_data, uint64_t client_id,
	uint64_t session_id, uintptr_t user_ctxt, uint64_t req_id, bool success,
	Mgmtd__DatabaseId src_db_id, Mgmtd__DatabaseId dst_db_id,
	bool validate_only, char *errmsg_if_any);

/*
 * Single hanlder to notify all or part of the results of a GET_CONFIG_REQ,
 * or GET_OPERDATA_REQ sent earlier to MGMTD.
 */
typedef enum mgmt_result (*mgmt_frntnd_client_get_data_notify_t)(
	uint64_t lib_hndl, uint64_t usr_data, uint64_t client_id,
	uint64_t session_id, uintptr_t user_ctxt, uint64_t req_id, bool success,
	Mgmtd__DatabaseId db_id, Mgmtd__YangData * yang_data[], size_t num_data,
	int next_key, char *errmsg_if_any);

/*
 * Handler to get YANG Notifications for one or more 'notification' type
 * leaf items in YANG datastore.
 */
typedef enum mgmt_result (*mgmt_frntnd_client_data_notify_t)(
	uint64_t client_id, uint64_t session_id, uintptr_t user_ctxt,
	uint64_t req_id, Mgmtd__DatabaseId db_id, Mgmtd__YangData * yang_data[],
	size_t num_data);

/*
 * All the client specific information this library needs to
 * initialize itself, setup connection with MGMTD FrontEnd interface
 * and carry on all required procedures appropriately.
 *
 * FrontEnd clients need to initialise a instance of this structure
 * with appropriate data and pass it while calling the API
 * to initialize the library (See mgmt_frntnd_client_lib_init for
 * more details).
 */
struct mgmt_frntnd_client_params {
	char name[MGMTD_CLIENT_NAME_MAX_LEN];
	uint64_t user_data;
	unsigned long conn_retry_intvl_sec;
	mgmt_frntnd_client_connect_notify_t conn_notify_cb;
	mgmt_frntnd_client_session_notify_t sess_req_result_cb;
	mgmt_frntnd_client_lock_db_notify_t lock_db_result_cb;
	mgmt_frntnd_client_set_config_notify_t set_config_result_cb;
	mgmt_frntnd_client_commit_config_notify_t commit_cfg_result_cb;
	mgmt_frntnd_client_get_data_notify_t get_data_result_cb;
	mgmt_frntnd_client_data_notify_t notify_data_cb;
};

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with MGMTD FrontEnd interface.
 */
extern uint64_t
mgmt_frntnd_client_lib_init(struct mgmt_frntnd_client_params *params,
			    struct thread_master *master_thread);

/*
 * Create a new Session for a Frontend Client connection.
 */
extern enum mgmt_result mgmt_frntnd_create_client_session(uint64_t lib_hndl,
							  uint64_t client_id,
							  uintptr_t user_ctxt);

/*
 * Delete an existing Session for a Frontend Client connection.
 */
extern enum mgmt_result mgmt_frntnd_destroy_client_session(uint64_t lib_hndl,
							   uint64_t session_id);

/*
 * Send UN/LOCK_DB_REQ to MGMTD for a specific Datastore DB.
 */
extern enum mgmt_result
mgmt_frntnd_lock_db(uint64_t lib_hndl, uint64_t session_id, uint64_t req_id,
		    Mgmtd__DatabaseId db_id, bool lock_db);

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
extern enum mgmt_result
mgmt_frntnd_set_config_data(uint64_t lib_hndl, uint64_t session_id,
			    uint64_t req_id, Mgmtd__DatabaseId db_id,
			    Mgmtd__YangCfgDataReq **config_req, int num_req,
			    bool implicit_commit, Mgmtd__DatabaseId dst_db_id);

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
extern enum mgmt_result
mgmt_frntnd_commit_config_data(uint64_t lib_hndl, uint64_t session_id,
			       uint64_t req_id, Mgmtd__DatabaseId src_db_id,
			       Mgmtd__DatabaseId dst_db_id, bool validate_only,
			       bool abort);

/*
 * Send GET_CONFIG_REQ to MGMTD for one or more config data item(s).
 */
extern enum mgmt_result
mgmt_frntnd_get_config_data(uint64_t lib_hndl, uint64_t session_id,
			    uint64_t req_id, Mgmtd__DatabaseId db_id,
			    Mgmtd__YangGetDataReq * data_req[], int num_reqs);

/*
 * Send GET_DATA_REQ to MGMTD for one or more data item(s).
 */
extern enum mgmt_result
mgmt_frntnd_get_data(uint64_t lib_hndl, uint64_t session_id, uint64_t req_id,
		     Mgmtd__DatabaseId db_id,
		     Mgmtd__YangGetDataReq * data_req[], int num_reqs);

/*
 * Send NOTIFY_REGISTER_REQ to MGMTD daemon.
 */
extern enum mgmt_result mgmt_frntnd_register_yang_notify(
	uint64_t lib_hndl, uint64_t session_id, uint64_t req_id,
	Mgmtd__DatabaseId db_id, bool register_req,
	Mgmtd__YangDataXPath * data_req[], int num_reqs);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_frntnd_client_lib_destroy(uint64_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_FRNTND_CLIENT_H_ */
