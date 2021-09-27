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

#ifndef _FRR_MGMTD_BCKND_CLIENT_H_
#define _FRR_MGMTD_BCKND_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "northbound.h"
#include "mgmtd/mgmt_defines.h"

/***************************************************************
 * Macros 
 ***************************************************************/

#define MGMTD_BCKND_CLIENT_ERROR_STRING_MAX_LEN	32

#define MGMTD_BCKND_DEFAULT_CONN_RETRY_INTVL_SEC	5

#define MGMTD_BCKND_MSG_PROC_DELAY_USEC		10
#define MGMTD_BCKND_MAX_NUM_MSG_PROC		500

#define MGMTD_BCKND_MSG_WRITE_DELAY_MSEC		1
#define MGMTD_BCKND_MAX_NUM_MSG_WRITE		1000

#define GMGD_BCKND_MAX_NUM_REQ_ITEMS    	64

#define MGMTD_BCKND_MSG_MAX_LEN		        16384

#define MGMTD_SOCKET_BCKND_SEND_BUF_SIZE		65535
#define MGMTD_SOCKET_BCKND_RECV_BUF_SIZE		MGMTD_SOCKET_BCKND_SEND_BUF_SIZE

/* MGMTD_BCKND_MSG_MAX_LEN must be used 80%
 * since there is overhead of google protobuf
 * that gets added to sent message
 */
#define MGMTD_BCKND_CFGDATA_PACKING_EFFICIENCY          0.8
#define MGMTD_BCKND_CFGDATA_MAX_MSG_LEN          \
        (MGMTD_BCKND_MSG_MAX_LEN *               \
	 MGMTD_BCKND_CFGDATA_PACKING_EFFICIENCY)

#define MGMTD_BCKND_MAX_BATCH_IDS_IN_REQ         \
	(MGMTD_BCKND_MSG_MAX_LEN-128)/		\
	sizeof(mgmt_trxn_batch_id_t)

/*
 * List of name identifiers for all backend clients to 
 * supply while calling mgmt_bcknd_client_lib_init().
 */
#define MGMTD_BCKND_CLIENT_BGPD			"bgpd"
#define MGMTD_BCKND_CLIENT_STATICD		"staticd"


#define MGMTD_BCKND_CONTAINER_NODE_VAL		"<<container>>"

/***************************************************************
 * Data-structures
 ***************************************************************/

typedef enum mgmt_bcknd_client_id_ {
	MGMTD_BCKND_CLIENT_ID_MIN = 0,
        MGMTD_BCKND_CLIENT_ID_STATICD = MGMTD_BCKND_CLIENT_ID_MIN,
        MGMTD_BCKND_CLIENT_ID_BGPD,
        MGMTD_BCKND_CLIENT_ID_MAX
} mgmt_bcknd_client_id_t;

#define FOREACH_MGMTD_BCKND_CLIENT_ID(id)			\
	for ((id) = MGMTD_BCKND_CLIENT_ID_MIN; 			\
		(id) < MGMTD_BCKND_CLIENT_ID_MAX; (id)++)

#define MGMTD_BCKND_MAX_CLIENTS_PER_XPATH_REG   32

typedef struct mgmt_bcknd_msg_hdr_ {
	uint16_t		marker;
	uint16_t 		len;	/* Includes header */
} mgmt_bcknd_msg_hdr_t;
#define MGMTD_BCKND_MSG_HDR_LEN	sizeof(mgmt_bcknd_msg_hdr_t)
#define MGMTD_BCKND_MSG_MARKER	0xfeed

typedef struct mgmt_bcknd_msg_ {
	mgmt_bcknd_msg_hdr_t 	hdr;
	uint8_t 		payload[];
} mgmt_bcknd_msg_t;

/*
 * Single handler to notify connection/disconnoect to/from 
 * MGMTD daemon.
 */
typedef void (*mgmt_bcknd_client_connect_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	bool connected);

/*
 * Single handler to notify subscribe/unsubscribe to/from 
 * MGMTD daemon.
 */
typedef void (*mgmt_bcknd_client_subscribe_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	struct nb_yang_xpath *xpath[], mgmt_result_t subscribe_result[], 
	int num_paths);

typedef struct mgmt_bcknd_client_trxn_ctxt_ {
	uintptr_t *user_ctx;
} mgmt_bcknd_client_trxn_ctxt_t;

/*
 * Single handler to notify create/destroy of MGMTD  
 * backend client transaction.
 */
typedef void (*mgmt_bcknd_client_trxn_notify_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, bool destroyed);

/*
 * Handler to validate any config data on the MGMTD  
 * backend client transaction. Called for all add/update/delete.
 */
typedef mgmt_result_t (*mgmt_bcknd_client_data_validate_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_value *data, bool delete, char *error_if_any);

/*
 * Handler to apply any config data on the MGMTD  
 * backend client transaction. Called for all add/update/delete.
 */
typedef mgmt_result_t (*mgmt_bcknd_client_data_apply_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_value *data, bool delete);

/*
 * Handler to get value of a specific leaf items for a container node.
 */
typedef mgmt_result_t (*mgmt_bcknd_client_get_data_elem_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	struct nb_yang_xpath_elem *elem);

/*
 * Handler to get vaues of all or key leaf items for a container node.
 */
typedef mgmt_result_t (*mgmt_bcknd_client_get_data_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	bool keys_only, struct nb_yang_xpath_elem **elems, int *num_elems, 
	int *next_key);

/*
 * Handler to get vaues of all or key leaf items for first or next 
 * entry in a list container.
 */
typedef mgmt_result_t (*mgmt_bcknd_client_get_next_data_t)(
	mgmt_lib_hndl_t lib_hndl, mgmt_user_data_t usr_data,
	mgmt_bcknd_client_trxn_ctxt_t *trxn_ctxt, struct nb_yang_xpath *xpath,
	bool keys_only, struct nb_yang_xpath_elem **elems, int *num_elems);

typedef struct mgmt_bcknd_client_params_ {
	char			name[MGMTD_CLIENT_NAME_MAX_LEN];
	mgmt_user_data_t	user_data;
	unsigned long		conn_retry_intvl_sec;
	mgmt_bcknd_client_connect_notify_t 	conn_notify_cb;
	mgmt_bcknd_client_subscribe_notify_t	subscr_notify_cb;
	mgmt_bcknd_client_trxn_notify_t		trxn_notify_cb;
	mgmt_bcknd_client_data_validate_t 	data_validate_cb;
	mgmt_bcknd_client_data_apply_t		data_apply_cb;
	mgmt_bcknd_client_get_data_elem_t	get_data_elem_cb;
	mgmt_bcknd_client_get_data_t		get_data_cb;
	mgmt_bcknd_client_get_next_data_t	get_next_data_cb;
} mgmt_bcknd_client_params_t;

/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *mgmt_bcknd_client_names[MGMTD_CLIENT_NAME_MAX_LEN];

static inline const char *mgmt_bknd_client_id2name(mgmt_bcknd_client_id_t id)
{
	if (id > MGMTD_BCKND_CLIENT_ID_MAX)
		id = MGMTD_BCKND_CLIENT_ID_MAX;
	return mgmt_bcknd_client_names[id];
}

static inline mgmt_bcknd_client_id_t mgmt_bknd_client_name2id(const char* name)
{
	mgmt_bcknd_client_id_t id;

	FOREACH_MGMTD_BCKND_CLIENT_ID(id) {
		if (!strncmp(mgmt_bcknd_client_names[id], name,
			MGMTD_CLIENT_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_BCKND_CLIENT_ID_MAX;
}

/***************************************************************
 * API prototypes
 ***************************************************************/

/*
 * Initialize library and try connecting with MGMTD.
 */
extern mgmt_lib_hndl_t mgmt_bcknd_client_lib_init(
	mgmt_bcknd_client_params_t *params, 
	struct thread_master *master_thread);

/*
 * Subscribe with MGMTD for one or more YANG subtree(s).
 */
extern mgmt_result_t mgmt_bcknd_subscribe_yang_data(
	mgmt_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_xpaths);

/*
 * Send one or more YANG notifications to MGMTD daemon.
 */
extern mgmt_result_t mgmt_bcknd_send_yang_notify(
	mgmt_lib_hndl_t lib_hndl, mgmt_yang_data_t *data_elems[],
	int num_elems);

/*
 * Unubscribe with MGMTD for one or more YANG subtree(s).
 */
mgmt_result_t mgmt_bcknd_unsubscribe_yang_data(
	mgmt_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths);

/*
 * Destroy library and cleanup everything.
 */
extern void mgmt_bcknd_client_lib_destroy(mgmt_lib_hndl_t lib_hndl);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_BCKND_CLIENT_H_ */
