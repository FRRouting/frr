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

#define MGMTD_TRXN_PROC_DELAY_MSEC 5
#define MGMTD_TRXN_PROC_DELAY_USEC 10
#define MGMTD_TRXN_MAX_NUM_SETCFG_PROC 128
#define MGMTD_TRXN_MAX_NUM_GETCFG_PROC 128
#define MGMTD_TRXN_MAX_NUM_GETDATA_PROC 128

#define MGMTD_TRXN_SEND_CFGVALIDATE_DELAY_MSEC 100
#define MGMTD_TRXN_SEND_CFGAPPLY_DELAY_MSEC 100
#define MGMTD_TRXN_CFG_COMMIT_MAX_DELAY_MSEC 30000 /* 30 seconds */

#define MGMTD_TRXN_CLEANUP_DELAY_MSEC 100
#define MGMTD_TRXN_CLEANUP_DELAY_USEC 10

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


enum mgmt_trxn_type {
	MGMTD_TRXN_TYPE_NONE = 0,
	MGMTD_TRXN_TYPE_CONFIG,
	MGMTD_TRXN_TYPE_SHOW
};

static inline const char *mgmt_trxn_type2str(enum mgmt_trxn_type type)
{
	switch (type) {
	case MGMTD_TRXN_TYPE_NONE:
		return "None";
	case MGMTD_TRXN_TYPE_CONFIG:
		return "CONFIG";
	case MGMTD_TRXN_TYPE_SHOW:
		return "SHOW";
	default:
		break;
	}

	return "Unknown";
}

extern int mgmt_trxn_init(struct mgmt_master *cm, struct thread_master *tm);

extern uint64_t mgmt_config_trxn_in_progress(void);

extern uint64_t mgmt_create_trxn(uint64_t session_id, enum mgmt_trxn_type type);

extern void mgmt_destroy_trxn(uint64_t *trxn_id);

extern bool mgmt_trxn_id_is_valid(uint64_t trxn_id);

extern enum mgmt_trxn_type mgmt_get_trxn_type(uint64_t trxn_id);

extern int mgmt_trxn_send_set_config_req(uint64_t trxn_id, uint64_t req_id,
					 Mgmtd__DatabaseId db_id,
					 uint64_t db_hndl,
					 Mgmtd__YangCfgDataReq * cfg_req[],
					 size_t num_req, bool implicit_commit,
					 Mgmtd__DatabaseId dst_db_id,
					 uint64_t dst_db_hndl);

extern int mgmt_trxn_send_commit_config_req(
	uint64_t trxn_id, uint64_t req_id, Mgmtd__DatabaseId src_db_id,
	uint64_t dst_db_hndl, Mgmtd__DatabaseId dst_db_id, uint64_t src_db_hndl,
	bool validate_only, bool abort, bool implicit);

extern int mgmt_trxn_send_commit_config_reply(uint64_t trxn_id,
					      enum mgmt_result result,
					      const char *error_if_any);

extern int mgmt_trxn_send_get_config_req(uint64_t trxn_id, uint64_t req_id,
					 Mgmtd__DatabaseId db_id,
					 uint64_t db_hndl,
					 Mgmtd__YangGetDataReq **data_req,
					 size_t num_reqs);

extern int mgmt_trxn_send_get_data_req(uint64_t trxn_id, uint64_t req_id,
				       Mgmtd__DatabaseId db_id,
				       uint64_t db_hndl,
				       Mgmtd__YangGetDataReq **data_req,
				       size_t num_reqs);

extern int
mgmt_trxn_notify_bcknd_adapter_conn(struct mgmt_bcknd_client_adapter *adptr,
				    bool connect);

extern int
mgmt_trxn_notify_bcknd_trxn_reply(uint64_t trxn_id, bool create, bool success,
				  struct mgmt_bcknd_client_adapter *adptr);

extern int
mgmt_trxn_notify_bcknd_cfgdata_reply(uint64_t trxn_id, uint64_t batch_id,
				     bool success, char *error_if_any,
				     struct mgmt_bcknd_client_adapter *adptr);

extern int mgmt_trxn_notify_bcknd_cfg_validate_reply(
	uint64_t trxn_id, bool success, uint64_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
	struct mgmt_bcknd_client_adapter *adptr);

extern int
mgmt_trxn_notify_bcknd_cfg_apply_reply(uint64_t trxn_id, bool success,
				       uint64_t batch_ids[],
				       size_t num_batch_ids, char *error_if_any,
				       struct mgmt_bcknd_client_adapter *adptr);

extern void mgmt_trxn_status_write(struct vty *vty);

extern int mgmt_trxn_rollback_trigger_cfg_apply(uint64_t src_db_hndl,
						uint64_t dst_db_hndl);
#endif /* _FRR_MGMTD_TRXN_H_ */
