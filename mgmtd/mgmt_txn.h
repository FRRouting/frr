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

#ifndef _FRR_MGMTD_TXN_H_
#define _FRR_MGMTD_TXN_H_

#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_db.h"

#define MGMTD_TXN_PROC_DELAY_MSEC 5
#define MGMTD_TXN_PROC_DELAY_USEC 10
#define MGMTD_TXN_MAX_NUM_SETCFG_PROC 128
#define MGMTD_TXN_MAX_NUM_GETCFG_PROC 128
#define MGMTD_TXN_MAX_NUM_GETDATA_PROC 128

#define MGMTD_TXN_SEND_CFGVALIDATE_DELAY_MSEC 100
#define MGMTD_TXN_SEND_CFGAPPLY_DELAY_MSEC 100
#define MGMTD_TXN_CFG_COMMIT_MAX_DELAY_MSEC 30000 /* 30 seconds */

#define MGMTD_TXN_CLEANUP_DELAY_MSEC 100
#define MGMTD_TXN_CLEANUP_DELAY_USEC 10

/*
 * The following definition enables local validation of config
 * on the MGMTD process by loading client-defined NB callbacks
 * and calling them locally before sening CNFG_APPLY_REQ to
 * backend for actual apply of configuration on internal state
 * of the backend application.
 *
 * #define MGMTD_LOCAL_VALIDATIONS_ENABLED
 *
 * Note: Enabled by default in configure.ac, if this needs to be
 * disabled then pass --enable-mgmtd-local-validations=no to
 * the list of arguments passed to ./configure
 */

PREDECL_LIST(mgmt_txn_list);

struct mgmt_master;

enum mgmt_txn_type {
	MGMTD_TXN_TYPE_NONE = 0,
	MGMTD_TXN_TYPE_CONFIG,
	MGMTD_TXN_TYPE_SHOW
};

static inline const char *mgmt_txn_type2str(enum mgmt_txn_type type)
{
	switch (type) {
	case MGMTD_TXN_TYPE_NONE:
		return "None";
	case MGMTD_TXN_TYPE_CONFIG:
		return "CONFIG";
	case MGMTD_TXN_TYPE_SHOW:
		return "SHOW";
	}

	return "Unknown";
}

/* Initialise transaction module. */
extern int mgmt_txn_init(struct mgmt_master *cm, struct thread_master *tm);

/* Destroy the transaction module. */
extern void mgmt_txn_destroy(void);

/*
 * Check if transaction is in progress.
 *
 * Returns:
 *    session ID if in-progress, MGMTD_SESSION_ID_NONE otherwise.
 */
extern uint64_t mgmt_config_txn_in_progress(void);

/*
 * Create transaction.
 *
 * session_id
 *    Session ID.
 *
 * type
 *    Transaction type (CONFIG/SHOW/NONE)
 *
 * Returns:
 *    transaction ID.
 */
extern uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type);

/*
 * Destroy transaction.
 *
 * txn_id
 *     Unique transaction identifier.
 */
extern void mgmt_destroy_txn(uint64_t *txn_id);

/*
 * Check if transaction is valid given an ID.
 */
extern bool mgmt_txn_id_is_valid(uint64_t txn_id);

/*
 * Returns the type of transaction given an ID.
 */
extern enum mgmt_txn_type mgmt_get_txn_type(uint64_t txn_id);

/*
 * Send set-config request to be processed later in transaction.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * req_id
 *    Unique transaction request identifier.
 *
 * db_id
 *    Database ID.
 *
 * db_hndl
 *    Database handle.
 *
 * cfg_req
 *    Config requests.
 *
 * num_req
 *    Number of config requests.
 *
 * implicit_commit
 *    TRUE if the commit is implicit, FALSE otherwise.
 *
 * dst_db_id
 *    Destination database ID.
 *
 * dst_db_handle
 *    Destination database handle.
 *
 * Returns:
 *    0 on success, -1 on failures.
 */
extern int mgmt_txn_send_set_config_req(uint64_t txn_id, uint64_t req_id,
					 Mgmtd__DatabaseId db_id,
					 struct mgmt_db_ctx *db_ctx,
					 Mgmtd__YangCfgDataReq **cfg_req,
					 size_t num_req, bool implicit_commit,
					 Mgmtd__DatabaseId dst_db_id,
					 struct mgmt_db_ctx *dst_db_ctx);

/*
 * Send commit-config request to be processed later in transaction.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * req_id
 *    Unique transaction request identifier.
 *
 * src_db_id
 *    Source database ID.
 *
 * src_db_hndl
 *    Source Database handle.
 *
 * validate_only
 *    TRUE if commit request needs to be validated only, FALSE otherwise.
 *
 * abort
 *    TRUE if need to restore Src DB back to Dest DB, FALSE otherwise.
 *
 * implicit
 *    TRUE if the commit is implicit, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failures.
 */
extern int mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id,
					    Mgmtd__DatabaseId src_db_id,
					    struct mgmt_db_ctx *dst_db_ctx,
					    Mgmtd__DatabaseId dst_db_id,
					    struct mgmt_db_ctx *src_db_ctx,
					    bool validate_only, bool abort,
					    bool implicit);

extern int mgmt_txn_send_commit_config_reply(uint64_t txn_id,
					      enum mgmt_result result,
					      const char *error_if_any);

/*
 * Send get-config request to be processed later in transaction.
 *
 * Similar to set-config request.
 */
extern int mgmt_txn_send_get_config_req(uint64_t txn_id, uint64_t req_id,
					 Mgmtd__DatabaseId db_id,
					 struct mgmt_db_ctx *db_ctx,
					 Mgmtd__YangGetDataReq **data_req,
					 size_t num_reqs);

/*
 * Send get-data request to be processed later in transaction.
 *
 * Similar to get-config request, but here data is fetched from backedn client.
 */
extern int mgmt_txn_send_get_data_req(uint64_t txn_id, uint64_t req_id,
				       Mgmtd__DatabaseId db_id,
				       struct mgmt_db_ctx *db_ctx,
				       Mgmtd__YangGetDataReq **data_req,
				       size_t num_reqs);

/*
 * Notifiy backend adapter on connection.
 */
extern int
mgmt_txn_notify_be_adapter_conn(struct mgmt_be_client_adapter *adapter,
				    bool connect);

/*
 * Reply to backend adapter about transaction create/delete.
 */
extern int
mgmt_txn_notify_be_txn_reply(uint64_t txn_id, bool create, bool success,
				  struct mgmt_be_client_adapter *adapter);

/*
 * Reply to backend adapater with config data create request.
 */
extern int
mgmt_txn_notify_be_cfgdata_reply(uint64_t txn_id, uint64_t batch_id,
				     bool success, char *error_if_any,
				     struct mgmt_be_client_adapter *adapter);

/*
 * Reply to backend adapater with config data validate request.
 */
extern int mgmt_txn_notify_be_cfg_validate_reply(
	uint64_t txn_id, bool success, uint64_t batch_ids[],
	size_t num_batch_ids, char *error_if_any,
	struct mgmt_be_client_adapter *adapter);

/*
 * Reply to backend adapater with config data apply request.
 */
extern int
mgmt_txn_notify_be_cfg_apply_reply(uint64_t txn_id, bool success,
				       uint64_t batch_ids[],
				       size_t num_batch_ids, char *error_if_any,
				       struct mgmt_be_client_adapter *adapter);

/*
 * Dump transaction status to vty.
 */
extern void mgmt_txn_status_write(struct vty *vty);

/*
 * Trigger rollback config apply.
 *
 * Creates a new transaction and commit request for rollback.
 */
extern int
mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_db_ctx *src_db_ctx,
				     struct mgmt_db_ctx *dst_db_ctx);
#endif /* _FRR_MGMTD_TXN_H_ */
