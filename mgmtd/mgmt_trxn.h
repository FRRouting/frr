/*
 * MGMTD Transactions
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

#ifndef _FRR_MGMTD_TRXN_H_
#define _FRR_MGMTD_TRXN_H_

#include "lib/typesafe.h"
#include "mgmtd/mgmt_defines.h"
#include "lib/mgmt_pb.h"
#include "mgmtd/mgmt_bcknd_adapter.h"
#include "mgmtd/mgmt_frntnd_adapter.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_db.h"

#define MGMTD_TRXN_PROC_DELAY_MSEC               5
#define MGMTD_TRXN_PROC_DELAY_USEC               10
#define MGMTD_TRXN_MAX_NUM_SETCFG_PROC           128
#define MGMTD_TRXN_MAX_NUM_GETCFG_PROC           128
#define MGMTD_TRXN_MAX_NUM_GETDATA_PROC          128

#define MGMTD_TRXN_SEND_CFGVALIDATE_DELAY_MSEC   100
#define MGMTD_TRXN_SEND_CFGAPPLY_DELAY_MSEC      100
#define MGMTD_TRXN_CFG_COMMIT_MAX_DELAY_MSEC     30000   /* 30 seconds */

#define MGMTD_TRXN_CLEANUP_DELAY_MSEC            100
#define MGMTD_TRXN_CLEANUP_DELAY_USEC            10

/*
 * The following definition enables local validation of config
 * on the MGMTD process by loading client-defined NB callbacks
 * and calling them locally before sening CNFG_APPLY_REQ to 
 * backend for actual apply of configuration on internal state 
 * of the backend application.
 */
#define MGMTD_LOCAL_VALIDATIONS_ENABLED

PREDECL_LIST(mgmt_trxn_list);

struct mgmt_master;

struct mgmt_trxn_ctx_;
typedef struct mgmt_trxn_ctxt_ mgmt_trxn_ctxt_t;

typedef enum mgmt_trxn_type_ {
        MGMTD_TRXN_TYPE_NONE = 0,
        MGMTD_TRXN_TYPE_CONFIG,
        MGMTD_TRXN_TYPE_SHOW
} mgmt_trxn_type_t;

static inline const char* mgmt_trxn_type2str(mgmt_trxn_type_t type)
{
        switch (type) {
        case MGMTD_TRXN_TYPE_NONE:
                return "None";
                break;
        case MGMTD_TRXN_TYPE_CONFIG:
                return "CONFIG";
                break;
        case MGMTD_TRXN_TYPE_SHOW:
                return "SHOW";
                break;
        default:
                break;
        }

        return "Unknown";
}

extern int mgmt_trxn_init(struct mgmt_master *cm, struct thread_master *tm);

// extern void mgmt_trxn_lock(mgmt_trxn_ctxt_t *trxn);

// extern void mgmt_trxn_unlock(mgmt_trxn_ctxt_t **trxn);

extern mgmt_session_id_t mgmt_config_trxn_in_progress(void);

extern mgmt_trxn_id_t mgmt_create_trxn(
        mgmt_session_id_t session_id, mgmt_trxn_type_t type);

extern void mgmt_destroy_trxn(mgmt_trxn_id_t *trxn_id);

extern bool mgmt_trxn_id_is_valid(mgmt_trxn_id_t trxn_id);

extern mgmt_trxn_type_t mgmt_get_trxn_type(mgmt_trxn_id_t trxn_id);

extern int mgmt_trxn_send_set_config_req(
        mgmt_trxn_id_t trxn_id, mgmt_client_req_id_t req_id,
        mgmt_database_id_t db_id, mgmt_db_hndl_t db_hndl,
        mgmt_yang_cfgdata_req_t *cfg_req[], size_t num_req,
	bool implicit_commit, mgmt_database_id_t dst_db_id,
	mgmt_db_hndl_t dst_db_hndl);

extern int mgmt_trxn_send_commit_config_req(
        mgmt_trxn_id_t trxn_id, mgmt_client_req_id_t req_id,
        mgmt_database_id_t src_db_id, mgmt_db_hndl_t dst_db_hndl,
        mgmt_database_id_t dst_db_id, mgmt_db_hndl_t src_db_hndl,
        bool validate_only, bool abort, bool implicit);

extern int mgmt_trxn_send_commit_config_reply(
        mgmt_trxn_id_t trxn_id, bool success, const char *error_if_any);

extern int mgmt_trxn_send_get_config_req(
        mgmt_trxn_id_t trxn_id, mgmt_client_req_id_t req_id,
        mgmt_database_id_t db_id, mgmt_db_hndl_t db_hndl,
        mgmt_yang_getdata_req_t **data_req, size_t num_reqs);

extern int mgmt_trxn_send_get_data_req(
        mgmt_trxn_id_t trxn_id, mgmt_client_req_id_t req_id,
        mgmt_database_id_t db_id, mgmt_db_hndl_t db_hndl,
        mgmt_yang_getdata_req_t **data_req, size_t num_reqs);

extern int mgmt_trxn_notify_bcknd_adapter_conn(
	mgmt_bcknd_client_adapter_t *adptr, bool connect);

extern int mgmt_trxn_notify_bcknd_trxn_reply(
	mgmt_trxn_id_t trxn_id, bool create, bool success,
	mgmt_bcknd_client_adapter_t *adptr);

extern int mgmt_trxn_notify_bcknd_cfgdata_reply(
	mgmt_trxn_id_t trxn_id, mgmt_trxn_batch_id_t batch_id, bool success,
	char *error_if_any, mgmt_bcknd_client_adapter_t *adptr);

extern int mgmt_trxn_notify_bcknd_cfg_validate_reply(
	mgmt_trxn_id_t trxn_id, bool success, mgmt_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
        mgmt_bcknd_client_adapter_t *adptr);

extern int mgmt_trxn_notify_bcknd_cfg_apply_reply(
	mgmt_trxn_id_t trxn_id, bool success, mgmt_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
        mgmt_bcknd_client_adapter_t *adptr);

extern void mgmt_trxn_status_write(struct vty *vty);

extern int mgmt_trxn_rollback_trigger_cfg_apply(mgmt_db_hndl_t src_db_hndl,
	mgmt_db_hndl_t dst_db_hndl);
#endif /* _FRR_MGMTD_TRXN_H_ */
