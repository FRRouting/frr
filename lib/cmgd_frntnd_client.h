/*
 * CMGD Frontend Client Library api interfaces
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

#ifndef _FRR_CMGD_FRNTND_CLIENT_H_
#define _FRR_CMGD_FRNTND_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "northbound.h"
#include "cmgd/cmgd_defines.h"
#include "lib/cmgd_pb.h"

/***************************************************************
 * Macros 
 ***************************************************************/

/*
 * The server port CMGD daemon is listening for Backend Client
 * connections.
 */

#define CMGD_FRNTND_CLIENT_ERROR_STRING_MAX_LEN		32

#define CMGD_FRNTND_DEFAULT_CONN_RETRY_INTVL_SEC	5

#define CMGD_FRNTND_MSG_PROC_DELAY_USEC			10
#define CMGD_FRNTND_MAX_NUM_MSG_PROC			500

#define CMGD_FRNTND_MSG_WRITE_DELAY_MSEC		1
#define CMGD_FRNTND_MAX_NUM_MSG_WRITE			100

#define GMGD_FRNTND_MAX_NUM_REQ_ITEMS    		64

#define CMGD_FRNTND_MSG_MAX_LEN		        	9000


/***************************************************************
 * Data-structures
 ***************************************************************/

typedef uintptr_t cmgd_session_id_t;
#define CMGD_SESSION_ID_NONE	0

typedef uintptr_t cmgd_client_id_t;
#define CMGD_CLIENT_ID_NONE	0

typedef uintptr_t cmgd_client_req_id_t;

typedef Cmgd__DatabaseId cmgd_database_id_t;
#define CMGD_DB_NONE		CMGD__DATABASE_ID__DB_NONE
#define CMGD_DB_RUNNING 	CMGD__DATABASE_ID__RUNNING_DB
#define CMGD_DB_CANDIDATE 	CMGD__DATABASE_ID__CANDIDATE_DB
#define CMGD_DB_OPERATIONAL 	CMGD__DATABASE_ID__OPERATIONAL_DB
#define CMGD_DB_MAX_ID		CMGD_DB_OPERATIONAL+1

typedef struct cmgd_frntnd_msg_hdr_ {
	uint16_t		marker;
	uint16_t 		len;	/* Includes header */
} cmgd_frntnd_msg_hdr_t;
#define CMGD_FRNTND_MSG_HDR_LEN	sizeof(cmgd_frntnd_msg_hdr_t)
#define CMGD_FRNTND_MSG_MARKER	0xdeaf

typedef struct cmgd_frntnd_msg_ {
	cmgd_frntnd_msg_hdr_t 	hdr;
	uint8_t 		payload[];
} cmgd_frntnd_msg_t;

/*
 * Single handler to notify connection/disconnoect to/from 
 * CMGD daemon.
 */
typedef void (*cmgd_frntnd_client_connect_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	bool connected);

/*
 * Single handler to notify results of SESSION_REQ sent earlier to CMGD.
 */
typedef void (*cmgd_frntnd_client_session_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, bool create, bool success,
	cmgd_session_id_t session_id, uintptr_t user_ctxt);

/*
 * Single handler to notify results of UN/LOCK_DB_REQ sent earlier to CMGD.
 */
typedef void (*cmgd_frntnd_client_lock_db_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, cmgd_session_id_t session_id,
	uintptr_t user_ctxt, cmgd_client_req_id_t req_id, bool lock_db,
	bool success, cmgd_database_id_t db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of SET_CONFIG_REQ sent earlier to CMGD.
 */
typedef void (*cmgd_frntnd_client_set_config_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, cmgd_session_id_t session_id,
	uintptr_t user_ctxt, cmgd_client_req_id_t req_id, bool success,
	cmgd_database_id_t db_id, char *errmsg_if_any);

/*
 * Single handler to notify results of COMMIT_CONFIG_REQ sent earlier to CMGD.
 */
typedef void (*cmgd_frntnd_client_commit_config_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, cmgd_session_id_t session_id,
	uintptr_t user_ctxt, cmgd_client_req_id_t req_id, bool success,
	cmgd_database_id_t src_db_id, cmgd_database_id_t dst_db_id,
	bool validate_only, char *errmsg_if_any);

/*
 * Single hanlder to notify all or part of the results of a GET_CONFIG_REQ,
 * or GET_OPERDATA_REQ sent earlier to CMGD.
 */
typedef cmgd_result_t (*cmgd_frntnd_client_get_data_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, cmgd_session_id_t session_id,
	uintptr_t user_ctxt, cmgd_client_req_id_t req_id, bool success,
	cmgd_database_id_t db_id, cmgd_yang_data_t *yang_data[],
	size_t num_data, int next_key, char *errmsg_if_any);

/*
 * Handler to get YANG Notifications for one or more 'notification' type 
 * leaf items in YANG datastore.
 */
typedef cmgd_result_t (*cmgd_frntnd_client_data_notify_t)(
	cmgd_client_id_t client_id, cmgd_session_id_t session_id,
	uintptr_t user_ctxt, cmgd_client_req_id_t req_id,
	cmgd_database_id_t db_id, cmgd_yang_data_t *yang_data[],
	size_t num_data);

typedef struct cmgd_frntnd_client_params_ {
	char			name[CMGD_CLIENT_NAME_MAX_LEN];
	cmgd_user_data_t	user_data;
	unsigned long		conn_retry_intvl_sec;
	cmgd_frntnd_client_connect_notify_t 		conn_notify_cb;
	cmgd_frntnd_client_session_notify_t		sess_req_result_cb;
	cmgd_frntnd_client_lock_db_notify_t 		lock_db_result_cb;
	cmgd_frntnd_client_set_config_notify_t		set_config_result_cb;
	cmgd_frntnd_client_commit_config_notify_t	commit_cfg_result_cb;
	cmgd_frntnd_client_get_data_notify_t		get_data_result_cb;
	cmgd_frntnd_client_data_notify_t		notify_data_cb;
} cmgd_frntnd_client_params_t;

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with CMGD.
 */
extern cmgd_lib_hndl_t cmgd_frntnd_client_lib_init(
	cmgd_frntnd_client_params_t *params, 
	struct thread_master *master_thread);

/*
 * Create a new Session for a Frontend Client connection.
 */
extern cmgd_result_t cmgd_frntnd_create_client_session(
	cmgd_lib_hndl_t lib_hndl, cmgd_client_id_t client_id,
	uintptr_t user_ctxt);

/*
 * Delete an existing Session for a Frontend Client connection.
 */
extern cmgd_result_t cmgd_frntnd_destroy_client_session(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id);

/*
 * Send UN/LOCK_DB_REQ to CMGD for a specific Datastore DB.
 */
extern cmgd_result_t cmgd_frntnd_lock_db(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	bool lock_db);

/*
 * Send SET_CONFIG_REQ to CMGD for one or more config data(s).
 */
extern cmgd_result_t cmgd_frntnd_set_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_cfgdata_req_t **config_req, int num_req, 
	bool implicit_commit, cmgd_database_id_t dst_db_id);

/*
 * Send SET_CONFIG_REQ to CMGD for one or more config data(s).
 */
extern cmgd_result_t cmgd_frntnd_commit_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t src_db_id, 
	cmgd_database_id_t dst_db_id, bool validate_only, bool abort);

/*
 * Send GET_CONFIG_REQ to CMGD for one or more config data item(s).
 */
extern cmgd_result_t cmgd_frntnd_get_config_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_getdata_req_t *data_req[], int num_reqs);

/*
 * Send GET_DATA_REQ to CMGD for one or more data item(s).
 */
extern cmgd_result_t cmgd_frntnd_get_data(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	cmgd_yang_getdata_req_t *data_req[], int num_reqs);

/*
 * Send NOTIFY_REGISTER_REQ to CMGD daemon.
 */
extern cmgd_result_t cmgd_frntnd_register_yang_notify(
	cmgd_lib_hndl_t lib_hndl, cmgd_session_id_t session_id,
	cmgd_client_req_id_t req_id, cmgd_database_id_t db_id,
	bool register_req, cmgd_yang_xpath_t *data_req[], int num_reqs);

/*
 * Destroy library and cleanup everything.
 */
extern void cmgd_frntnd_client_lib_destroy(cmgd_lib_hndl_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CMGD_FRNTND_CLIENT_H_ */
