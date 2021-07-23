/*
 * CMGD Backend Client Library api interfaces
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

#ifndef _FRR_CMGD_BCKND_CLIENT_H_
#define _FRR_CMGD_BCKND_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "northbound.h"
#include "cmgd/cmgd_defines.h"

/***************************************************************
 * Macros 
 ***************************************************************/

#define CMGD_BCKND_CLIENT_ERROR_STRING_MAX_LEN	32

#define CMGD_BCKND_DEFAULT_CONN_RETRY_INTVL_SEC	5

#define CMGD_BCKND_MSG_PROC_DELAY_MSEC		250

#define CMGD_BCKND_MAX_NUM_MSG_PROC		100

#define GMGD_BCKND_MAX_NUM_REQ_ITEMS    	64

#define CMGD_BCKND_MSG_MAX_LEN		        4096


#define CMGD_BCKND_CLIENT_BGPD			"bgpd"
#define CMGD_BCKND_CLIENT_STATICD		"staticd"

/***************************************************************
 * Data-structures
 ***************************************************************/

typedef enum cmgd_bcknd_client_id_ {
        CMGD_BCKND_CLIENT_ID_STATICD = 0,
        CMGD_BCKND_CLIENT_ID_BGPD,
        CMGD_BCKND_CLIENT_ID_MAX
} cmgd_bcknd_client_id_t;

typedef struct cmgd_bcknd_msg_hdr_ {
	uint16_t		marker;
	uint16_t 		len;	/* Includes header */
} cmgd_bcknd_msg_hdr_t;
#define CMGD_BCKND_MSG_HDR_LEN	sizeof(cmgd_bcknd_msg_hdr_t)
#define CMGD_BCKND_MSG_MARKER	0xfeed

typedef struct cmgd_bcknd_msg_ {
	cmgd_bcknd_msg_hdr_t 	hdr;
	uint8_t 		payload[];
} cmgd_bcknd_msg_t;

/*
 * Single handler to notify connection/disconnoect to/from 
 * CMGD daemon.
 */
typedef void (*cmgd_bcknd_client_connect_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	bool connected);

/*
 * Single handler to notify connection/disconnoect to/from 
 * CMGD daemon.
 */
typedef void (*cmgd_bcknd_client_subscribe_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	struct nb_yang_xpath *xpath[], cmgd_result_t subscribe_result[], 
	int num_paths);

typedef struct cmgd_bcknd_client_trxn_ctxt_ {
	uintptr_t *user_ctx;
} cmgd_bcknd_client_trxn_ctxt_t;

/*
 * Single handler to notify create/destroy of CMGD  
 * backend client transaction.
 */
typedef void (*cmgd_bcknd_client_trxn_notify_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, bool destroyed);

/*
 * Handler to validate any config data on the CMGD  
 * backend client transaction. Called for all add/update/delete.
 */
typedef cmgd_result_t (*cmgd_bcknd_client_data_validate_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_value *data, bool delete, char *error_if_any);

/*
 * Handler to apply any config data on the CMGD  
 * backend client transaction. Called for all add/update/delete.
 */
typedef cmgd_result_t (*cmgd_bcknd_client_data_apply_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_value *data, bool delete);

/*
 * Handler to get value of a specific leaf items for a container node.
 */
typedef cmgd_result_t (*cmgd_bcknd_client_get_data_elem_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_xpath_elem *elem);

/*
 * Handler to get vaues of all or key leaf items for a container node.
 */
typedef cmgd_result_t (*cmgd_bcknd_client_get_data_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	bool keys_only, struct nb_yang_xpath_elem **elems, int *num_elems, 
	int *next_key);

/*
 * Handler to get vaues of all or key leaf items for first or next 
 * entry in a list container.
 */
typedef cmgd_result_t (*cmgd_bcknd_client_get_next_data_t)(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	bool keys_only, struct nb_yang_xpath_elem **elems, int *num_elems);

typedef struct cmgd_bcknd_client_params_ {
	char			name[CMGD_CLIENT_NAME_MAX_LEN];
	cmgd_user_data_t	user_data;
	unsigned long		conn_retry_intvl_sec;
	cmgd_bcknd_client_connect_notify_t 	conn_notify_cb;
	cmgd_bcknd_client_subscribe_notify_t	subscr_notify_cb;
	cmgd_bcknd_client_trxn_notify_t		trxn_notify_cb;
	cmgd_bcknd_client_data_validate_t 	data_validate_cb;
	cmgd_bcknd_client_data_apply_t		data_apply_cb;
	cmgd_bcknd_client_get_data_elem_t	get_data_elem_cb;
	cmgd_bcknd_client_get_data_t		get_data_cb;
	cmgd_bcknd_client_get_next_data_t	get_next_data_cb;
} cmgd_bcknd_client_params_t;

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with CMGD.
 */
extern cmgd_lib_hndl_t cmgd_bcknd_client_lib_init(
	cmgd_bcknd_client_params_t *params, 
	struct thread_master *master_thread);

/*
 * Subscribe with CMGD for one or more YANG subtree(s).
 */
extern cmgd_result_t cmgd_bcknd_subscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_xpaths);

/*
 * Send one or more YANG notifications to CMGD daemon.
 */
extern cmgd_result_t cmgd_bcknd_send_yang_notify(
	cmgd_lib_hndl_t lib_hndl, cmgd_yang_data_t *data_elems[],
	int num_elems);

/*
 * Unubscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_unsubscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths);

/*
 * Destroy library and cleanup everything.
 */
extern void cmgd_bcknd_client_lib_destroy(cmgd_lib_hndl_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CMGD_BCKND_CLIENT_H_ */
