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

#define MGMTD_FRNTND_CLIENT_ERROR_STRING_MAX_LEN		32

#define MGMTD_FRNTND_DEFAULT_CONN_RETRY_INTVL_SEC	5

#define MGMTD_FRNTND_MSG_PROC_DELAY_USEC			10
#define MGMTD_FRNTND_MAX_NUM_MSG_PROC			500

#define MGMTD_FRNTND_MSG_WRITE_DELAY_MSEC		1
#define MGMTD_FRNTND_MAX_NUM_MSG_WRITE			100

#define GMGD_FRNTND_MAX_NUM_REQ_ITEMS    		64

#define MGMTD_FRNTND_MSG_MAX_LEN		        	9000


/***************************************************************
 * Data-structures
 ***************************************************************/

typedef uintptr_t mgmt_session_id_t;
#define MGMTD_SESSION_ID_NONE	0

typedef uintptr_t mgmt_client_id_t;
#define MGMTD_CLIENT_ID_NONE	0

typedef uintptr_t mgmt_client_req_id_t;

typedef Mgmtd__DatabaseId mgmt_database_id_t;
#define MGMTD_DB_NONE		MGMTD__DATABASE_ID__DB_NONE
#define MGMTD_DB_RUNNING 	MGMTD__DATABASE_ID__RUNNING_DB
#define MGMTD_DB_CANDIDATE 	MGMTD__DATABASE_ID__CANDIDATE_DB
#define MGMTD_DB_OPERATIONAL 	MGMTD__DATABASE_ID__OPERATIONAL_DB
#define MGMTD_DB_MAX_ID		MGMTD_DB_OPERATIONAL+1

typedef struct mgmt_frntnd_msg_hdr_ {
	uint16_t		marker;
	uint16_t 		len;	/* Includes header */
} mgmt_frntnd_msg_hdr_t;
#define MGMTD_FRNTND_MSG_HDR_LEN	sizeof(mgmt_frntnd_msg_hdr_t)
#define MGMTD_FRNTND_MSG_MARKER	0xdeaf

typedef struct mgmt_frntnd_msg_ {
	mgmt_frntnd_msg_hdr_t 	hdr;
	uint8_t 		payload[];
} mgmt_frntnd_msg_t;

/*
 * Single handler to notify connection/disconnoect to/from 
 * MGMTD daemon.
 */
typedef void (*mgmt_frntnd_client_connect_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	bool connected);

/*
 * Single handler to notify results of SESSION_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_session_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_client_id_t client_id, bool create, bool success,
	mgmt_session_id_t session_id, uintptr_t user_ctxt);

/*
 * Single handler to notify results of UN/LOCK_DB_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_lock_db_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_client_id_t client_id, mgmt_session_id_t session_id,
	uintptr_t user_ctxt, mgmt_client_req_id_t req_id, bool lock_db,
	bool success, mgmt_database_id_t db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of SET_CONFIG_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_set_config_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_client_id_t client_id, mgmt_session_id_t session_id,
	uintptr_t user_ctxt, mgmt_client_req_id_t req_id, bool success,
	mgmt_database_id_t db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of COMMIT_CONFIG_REQ sent earlier to MGMTD.
 */
typedef void (*mgmt_frntnd_client_commit_config_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_client_id_t client_id, mgmt_session_id_t session_id,
	uintptr_t user_ctxt, mgmt_client_req_id_t req_id, bool success,
	mgmt_database_id_t src_db_id, mgmt_database_id_t dst_db_id,
	bool validate_only, char *errmsg_if_any);

/*
 * Single hanlder to notify all or part of the results of a GET_CONFIG_REQ,
 * or GET_OPERDATA_REQ sent earlier to MGMTD.
 */
typedef mgmt_result_t (*mgmt_frntnd_client_get_data_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_client_id_t client_id, mgmt_session_id_t session_id,
	uintptr_t user_ctxt, mgmt_client_req_id_t req_id, bool success,
	mgmt_database_id_t db_id, mgmt_yang_data_t *yang_data[],
	size_t num_data, int next_key, char *errmsg_if_any);

/*
 * Handler to get YANG Notifications for one or more 'notification' type 
 * leaf items in YANG datastore.
 */
typedef mgmt_result_t (*mgmt_frntnd_client_data_notify_t)(
	mgmt_client_id_t client_id, mgmt_session_id_t session_id,
	uintptr_t user_ctxt, mgmt_client_req_id_t req_id,
	mgmt_database_id_t db_id, mgmt_yang_data_t *yang_data[],
	size_t num_data);

typedef struct mgmt_frntnd_client_params_ {
	char			name[MGMTD_CLIENT_NAME_MAX_LEN];
	mgmt_user_data_t	user_data;
	unsigned long		conn_retry_intvl_sec;
	mgmt_frntnd_client_connect_notify_t 		conn_notify_cb;
	mgmt_frntnd_client_session_notify_t		sess_req_result_cb;
	mgmt_frntnd_client_lock_db_notify_t 		lock_db_result_cb;
	mgmt_frntnd_client_set_config_notify_t		set_config_result_cb;
	mgmt_frntnd_client_commit_config_notify_t	commit_cfg_result_cb;
	mgmt_frntnd_client_get_data_notify_t		get_data_result_cb;
	mgmt_frntnd_client_data_notify_t		notify_data_cb;
} mgmt_frntnd_client_params_t;

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with MGMTD.
 */
extern mgmt_lib_hndl_t mgmt_frntnd_client_lib_init(
	mgmt_frntnd_client_params_t *params, 
	struct thread_master *master_thread);

/*
 * Create a new Session for a Frontend Client connection.
 */
extern mgmt_result_t mgmt_frntnd_create_client_session(
	mgmt_lib_hndl_t lib_hndl, mgmt_client_id_t client_id,
	uintptr_t user_ctxt);

/*
 * Delete an existing Session for a Frontend Client connection.
 */
extern mgmt_result_t mgmt_frntnd_destroy_client_session(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id);

/*
 * Send UN/LOCK_DB_REQ to MGMTD for a specific Datastore DB.
 */
extern mgmt_result_t mgmt_frntnd_lock_db(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	bool lock_db);

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
extern mgmt_result_t mgmt_frntnd_set_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_cfgdata_req_t **config_req, int num_req, 
	bool implicit_commit, mgmt_database_id_t dst_db_id);

/*
 * Send SET_CONFIG_REQ to MGMTD for one or more config data(s).
 */
extern mgmt_result_t mgmt_frntnd_commit_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t src_db_id, 
	mgmt_database_id_t dst_db_id, bool validate_only, bool abort);

/*
 * Send GET_CONFIG_REQ to MGMTD for one or more config data item(s).
 */
extern mgmt_result_t mgmt_frntnd_get_config_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_getdata_req_t *data_req[], int num_reqs);

/*
 * Send GET_DATA_REQ to MGMTD for one or more data item(s).
 */
extern mgmt_result_t mgmt_frntnd_get_data(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	mgmt_yang_getdata_req_t *data_req[], int num_reqs);

/*
 * Send NOTIFY_REGISTER_REQ to MGMTD daemon.
 */
extern mgmt_result_t mgmt_frntnd_register_yang_notify(
	mgmt_lib_hndl_t lib_hndl, mgmt_session_id_t session_id,
	mgmt_client_req_id_t req_id, mgmt_database_id_t db_id,
	bool register_req, mgmt_yang_xpath_t *data_req[], int num_reqs);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_frntnd_client_lib_destroy(mgmt_lib_hndl_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_FRNTND_CLIENT_H_ */
