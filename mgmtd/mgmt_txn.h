// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Transactions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 */

#ifndef _FRR_MGMTD_TXN_H_
#define _FRR_MGMTD_TXN_H_

#include "lib/mgmt_msg_native.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"

#define MGMTD_TXN_PROC_DELAY_USEC 10
#define MGMTD_TXN_MAX_NUM_SETCFG_PROC 128
#define MGMTD_TXN_MAX_NUM_GETCFG_PROC 128
#define MGMTD_TXN_MAX_NUM_GETDATA_PROC 128

#define MGMTD_TXN_CFG_COMMIT_MAX_DELAY_SEC 600
#define MGMTD_TXN_GET_TREE_MAX_DELAY_SEC   600
#define MGMTD_TXN_RPC_MAX_DELAY_SEC	   60

#define MGMTD_TXN_CLEANUP_DELAY_USEC 10

#define MGMTD_TXN_ID_NONE 0

struct mgmt_master;

enum mgmt_txn_type {
	MGMTD_TXN_TYPE_NONE = 0,
	MGMTD_TXN_TYPE_CONFIG,
	MGMTD_TXN_TYPE_SHOW,
	MGMTD_TXN_TYPE_RPC,
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
	case MGMTD_TXN_TYPE_RPC:
		return "RPC";
	}

	return "Unknown";
}


static inline int16_t errno_from_nb_error(enum nb_error ret)
{
	switch (ret) {
	case NB_OK:
		return 0;
	case NB_ERR_NO_CHANGES:
		return -EALREADY;
	case NB_ERR_NOT_FOUND:
		return -ENOENT;
	case NB_ERR_EXISTS:
		return -EEXIST;
	case NB_ERR_LOCKED:
		return -EWOULDBLOCK;
	case NB_ERR_VALIDATION:
		return -EINVAL;
	case NB_ERR_RESOURCE:
		return -ENOMEM;
	case NB_ERR:
	case NB_ERR_INCONSISTENCY:
		return -EINVAL;
	case NB_YIELD:
	default:
		return -EINVAL;
	}
}

/* --------------------- */
/* Gernal Txn Functions. */
/* --------------------- */

extern void mgmt_txn_init(void);
extern void mgmt_txn_destroy(void);

extern enum mgmt_result nb_error_to_mgmt_result(enum nb_error error);

/* Dump transaction status to vty */
extern void mgmt_txn_status_write(struct vty *vty);

/* ---------------------------------------- */
/* Txn API for Backend messages and events. */
/* ---------------------------------------- */

extern bool mgmt_txn_config_in_progress(void);
extern uint64_t mgmt_txn_get_session_id(uint64_t txn_id);
extern uint64_t mgmt_create_txn(uint64_t session_id, enum mgmt_txn_type type);
extern void mgmt_destroy_txn(uint64_t *txn_id);

/**
 * mgmt_txn_send_commit_config_req() - Send commit-config to apply the config changes.
 * @txn_id: Unique transaction identifier.
 * @req_id: Unique transaction request identifier.
 * @src_ds_id: Source datastore ID.
 * @src_ds_hndl: Source Datastore handle.
 * @validate_only: TRUE if commit request needs to be validated only, FALSE otherwise.
 * @abort: TRUE if need to restore Src DS back to Dest DS, FALSE otherwise.
 * @implicit: TRUE if the commit is implicit, FALSE otherwise.
 * @unlock: pass back in the commit config reply
 * @edit: Additional info when triggered from native edit request.
 */
extern void
mgmt_txn_send_commit_config_req(uint64_t txn_id, uint64_t req_id, enum mgmt_ds_id src_ds_id,
				struct mgmt_ds_ctx *dst_ds_ctx, enum mgmt_ds_id dst_ds_id,
				struct mgmt_ds_ctx *src_ds_ctx, bool validate_only, bool abort,
				bool implicit, bool unlock, struct mgmt_edit_req *edit);

/**
 * mgmt_txn_send_get_tree() - Send get-tree to the backend `clients`.
 * @txn_id: Transaction identifier.
 * @req_id: FE client request identifier.
 * @clients: Bitmask of clients to send get-tree to.
 * @ds_id: datastore ID.
 * @result_type: LYD_FORMAT result format.
 * @flags: option flags for the request.
 * @wd_options: LYD_PRINT_WD_* flags for the result.
 * @simple_xpath: true if xpath is simple (only key predicates).
 * @ylib: libyang tree for yang-library module to be merged.
 * @xpath: The xpath to get the tree from.
 *
 * Return 0 on success.
 */
extern int mgmt_txn_send_get_tree(uint64_t txn_id, uint64_t req_id, uint64_t clients,
				  enum mgmt_ds_id ds_id, LYD_FORMAT result_type, uint8_t flags,
				  uint32_t wd_options, bool simple_xpath, struct lyd_node **ylib,
				  const char *xpath);

/**
 * mgmt_txn_send_rpc() - Send RPC request.
 * @txn_id: Transaction identifier.
 * @req_id: FE client request identifier.
 * @clients: Bitmask of clients to send RPC to.
 * @result_type: LYD_FORMAT result format.
 * @xpath: The xpath of the RPC.
 * @data: The input parameters data tree.
 * @data_len: The length of the input parameters data.
 */
extern void mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients,
			      LYD_FORMAT result_type, const char *xpath, const char *data,
			      size_t data_len);

/**
 * mgmt_txn_send_notify_selectors() - Send NOTIFY SELECT request.
 * @req_id: FE client request identifier.
 * @session_id: If non-zero the message will get sent as a `get_only` vs modifing
 *	        the selectors in the backend, and the get result will be sent
 *              back to the given session.
 * @clients: Bitmask of backend clients to send message to.
 * @selectors: Array of selectors or NULL to resend all selectors to BE clients.
 */
extern void mgmt_txn_send_notify_selectors(uint64_t req_id, uint64_t session_id, uint64_t clients,
					   const char **selectors);


/*
 * Trigger rollback config apply.
 *
 * Creates a new transaction and commit request for rollback.
 */
extern int mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_ds_ctx *src_ds_ctx,
					       struct mgmt_ds_ctx *dst_ds_ctx);

/* ---------------------------------------- */
/* Txn API for Backend messages and events. */
/* ---------------------------------------- */

extern void mgmt_txn_handle_cfg_reply(uint64_t txn_id, struct mgmt_be_client_adapter *adapter);
extern void mgmt_txn_handle_cfg_apply_reply(uint64_t txn_id,
					    struct mgmt_be_client_adapter *adapter);
extern void mgmt_txn_handle_error_reply(struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
					uint64_t req_id, int error, const char *errstr);
extern int mgmt_txn_handle_be_adapter_connect(struct mgmt_be_client_adapter *adapter, bool connect);
extern void mgmt_txn_handle_rpc_reply(struct mgmt_be_client_adapter *adapter,
				      struct mgmt_msg_rpc_reply *reply_msg, size_t msg_len);
extern void mgmt_txn_handle_tree_data_reply(struct mgmt_be_client_adapter *adapter,
					    struct mgmt_msg_tree_data *data_msg, size_t msg_len);

#endif /* _FRR_MGMTD_TXN_H_ */
