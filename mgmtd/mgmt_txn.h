// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Transactions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

PREDECL_LIST(mgmt_txns);

struct mgmt_master;
struct mgmt_edit_req;

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

/* Initialise transaction module. */
extern int mgmt_txn_init(struct mgmt_master *cm, struct event_loop *tm);

/* Destroy the transaction module. */
extern void mgmt_txn_destroy(void);

/*
 * Check if configuration transaction is in progress.
 *
 * Returns:
 *    true if in-progress, false otherwise.
 */
extern bool mgmt_config_txn_in_progress(void);

/**
 * Get the session ID associated with the given ``txn-id``.
 *
 */
extern uint64_t mgmt_txn_get_session_id(uint64_t txn_id);

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
 * Send set-config request to be processed later in transaction.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * req_id
 *    Unique transaction request identifier.
 *
 * ds_id
 *    Datastore ID.
 *
 * ds_hndl
 *    Datastore handle.
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
 * dst_ds_id
 *    Destination datastore ID.
 *
 * dst_ds_handle
 *    Destination datastore handle.
 *
 * Returns:
 *    0 on success, -1 on failures.
 */
extern int mgmt_txn_send_set_config_req(uint64_t txn_id, uint64_t req_id,
					 Mgmtd__DatastoreId ds_id,
					 struct mgmt_ds_ctx *ds_ctx,
					 Mgmtd__YangCfgDataReq **cfg_req,
					 size_t num_req, bool implicit_commit,
					 Mgmtd__DatastoreId dst_ds_id,
					 struct mgmt_ds_ctx *dst_ds_ctx);

/*
 * Send commit-config request to be processed later in transaction.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * req_id
 *    Unique transaction request identifier.
 *
 * src_ds_id
 *    Source datastore ID.
 *
 * src_ds_hndl
 *    Source Datastore handle.
 *
 * validate_only
 *    TRUE if commit request needs to be validated only, FALSE otherwise.
 *
 * abort
 *    TRUE if need to restore Src DS back to Dest DS, FALSE otherwise.
 *
 * implicit
 *    TRUE if the commit is implicit, FALSE otherwise.
 *
 * edit
 *    Additional info when triggered from native edit request.
 *
 * Returns:
 *    0 on success, -1 on failures.
 */
extern int mgmt_txn_send_commit_config_req(
	uint64_t txn_id, uint64_t req_id, Mgmtd__DatastoreId src_ds_id,
	struct mgmt_ds_ctx *dst_ds_ctx, Mgmtd__DatastoreId dst_ds_id,
	struct mgmt_ds_ctx *src_ds_ctx, bool validate_only, bool abort,
	bool implicit, struct mgmt_edit_req *edit);

/*
 * Send get-{cfg,data} request to be processed later in transaction.
 *
 * Is get-config if cfg_root is provided and the config is gathered locally,
 * otherwise it's get-data and data is fetched from backedn clients.
 */
extern int mgmt_txn_send_get_req(uint64_t txn_id, uint64_t req_id,
				 Mgmtd__DatastoreId ds_id,
				 struct nb_config *cfg_root,
				 Mgmtd__YangGetDataReq **data_req,
				 size_t num_reqs);


/**
 * Send get-tree to the backend `clients`.
 *
 * Args:
 *	txn_id: Transaction identifier.
 *	req_id: FE client request identifier.
 *	clients: Bitmask of clients to send get-tree to.
 *	ds_id: datastore ID.
 *	result_type: LYD_FORMAT result format.
 *	flags: option flags for the request.
 *	wd_options: LYD_PRINT_WD_* flags for the result.
 *	simple_xpath: true if xpath is simple (only key predicates).
 *	xpath: The xpath to get the tree from.
 *
 * Return:
 *	0 on success.
 */
extern int mgmt_txn_send_get_tree_oper(uint64_t txn_id, uint64_t req_id,
				       uint64_t clients,
				       Mgmtd__DatastoreId ds_id,
				       LYD_FORMAT result_type, uint8_t flags,
				       uint32_t wd_options, bool simple_xpath,
				       const char *xpath);

/**
 * Send edit request.
 *
 * Args:
 *	txn_id: Transaction identifier.
 *	req_id: FE client request identifier.
 *	ds_id: Datastore ID.
 *	ds_ctx: Datastore context.
 *	commit_ds_id: Commit datastore ID.
 *	commit_ds_ctx: Commit datastore context.
 *	unlock: Unlock datastores after the edit.
 *	commit: Commit the candidate datastore after the edit.
 *	request_type: LYD_FORMAT request type.
 *	flags: option flags for the request.
 *	operation: The operation to perform.
 *	xpath: The xpath of data node to edit.
 *	data: The data tree.
 */
extern int
mgmt_txn_send_edit(uint64_t txn_id, uint64_t req_id, Mgmtd__DatastoreId ds_id,
		   struct mgmt_ds_ctx *ds_ctx, Mgmtd__DatastoreId commit_ds_id,
		   struct mgmt_ds_ctx *commit_ds_ctx, bool unlock, bool commit,
		   LYD_FORMAT request_type, uint8_t flags, uint8_t operation,
		   const char *xpath, const char *data);

/**
 * Send RPC request.
 *
 * Args:
 *	txn_id: Transaction identifier.
 *	req_id: FE client request identifier.
 *	clients: Bitmask of clients to send RPC to.
 *	result_type: LYD_FORMAT result format.
 *	xpath: The xpath of the RPC.
 *	data: The input parameters data tree.
 *	data_len: The length of the input parameters data.
 *
 * Return:
 *	0 on success.
 */
extern int mgmt_txn_send_rpc(uint64_t txn_id, uint64_t req_id, uint64_t clients,
			     LYD_FORMAT result_type, const char *xpath,
			     const char *data, size_t data_len);

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
mgmt_txn_notify_be_cfgdata_reply(uint64_t txn_id, bool success,
				     char *error_if_any,
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
				       char *error_if_any,
				       struct mgmt_be_client_adapter *adapter);


/**
 * Process a reply from a backend client to our get-tree request
 *
 * Args:
 *	adapter: The adapter that received the result.
 *	txn_id: The transaction for this get-tree request.
 *	req_id: The request ID for this transaction.
 *	error: the integer error value (negative)
 *	errstr: the string description of the error.
 */
int mgmt_txn_notify_error(struct mgmt_be_client_adapter *adapter,
			  uint64_t txn_id, uint64_t req_id, int error,
			  const char *errstr);

/**
 * Process a reply from a backend client to our get-tree request
 *
 * Args:
 *	adapter: The adapter that received the result.
 *      data_msg: The message from the backend.
 *	msg_len: Total length of the message.
 */

extern int mgmt_txn_notify_tree_data_reply(struct mgmt_be_client_adapter *adapter,
					   struct mgmt_msg_tree_data *data_msg,
					   size_t msg_len);

/**
 * Process a reply from a backend client to our RPC request
 *
 * Args:
 *	adapter: The adapter that received the result.
 *	reply_msg: The message from the backend.
 *	msg_len: Total length of the message.
 */
extern int mgmt_txn_notify_rpc_reply(struct mgmt_be_client_adapter *adapter,
				     struct mgmt_msg_rpc_reply *reply_msg,
				     size_t msg_len);

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
mgmt_txn_rollback_trigger_cfg_apply(struct mgmt_ds_ctx *src_ds_ctx,
				     struct mgmt_ds_ctx *dst_ds_ctx);
#endif /* _FRR_MGMTD_TXN_H_ */
