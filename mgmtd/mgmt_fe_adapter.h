// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#ifndef _FRR_MGMTD_FE_ADAPTER_H_
#define _FRR_MGMTD_FE_ADAPTER_H_

#include "mgmt_fe_client.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"

struct mgmt_fe_client_adapter;
struct mgmt_master;

struct mgmt_commit_stats {
	struct timeval last_start;
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
	struct timeval validate_start;
#endif
	struct timeval prep_cfg_start;
	struct timeval txn_create_start;
	struct timeval apply_cfg_start;
	struct timeval apply_cfg_end;
	struct timeval txn_del_start;
	struct timeval last_end;
	unsigned long last_exec_tm;
	unsigned long max_tm;
	unsigned long min_tm;
	unsigned long last_batch_cnt;
	unsigned long last_num_cfgdata_reqs;
	unsigned long last_num_apply_reqs;
	unsigned long max_batch_cnt;
	unsigned long min_batch_cnt;
	unsigned long commit_cnt;
};

struct mgmt_setcfg_stats {
	struct timeval last_start;
	struct timeval last_end;
	unsigned long last_exec_tm;
	unsigned long max_tm;
	unsigned long min_tm;
	unsigned long avg_tm;
	unsigned long set_cfg_count;
};

PREDECL_LIST(mgmt_fe_sessions);

PREDECL_LIST(mgmt_fe_adapters);

struct mgmt_fe_client_adapter {
	struct msg_conn *conn;
	char name[MGMTD_CLIENT_NAME_MAX_LEN];

	/* List of sessions created and being maintained for this client. */
	struct mgmt_fe_sessions_head fe_sessions;

	int refcount;
	struct mgmt_commit_stats cmt_stats;
	struct mgmt_setcfg_stats setcfg_stats;

	struct mgmt_fe_adapters_item list_linkage;
};

DECLARE_LIST(mgmt_fe_adapters, struct mgmt_fe_client_adapter, list_linkage);

/* Initialise frontend adapter module */
extern void mgmt_fe_adapter_init(struct event_loop *tm);

/* Destroy frontend adapter module */
extern void mgmt_fe_adapter_destroy(void);

/* Acquire lock for frontend adapter */
extern void mgmt_fe_adapter_lock(struct mgmt_fe_client_adapter *adapter);

/* Remove lock from frontend adapter */
extern void
mgmt_fe_adapter_unlock(struct mgmt_fe_client_adapter **adapter);

/* Create frontend adapter */
extern struct msg_conn *mgmt_fe_create_adapter(int conn_fd,
					       union sockunion *su);

/*
 * Send set-config reply to the frontend client.
 *
 * session
 *    Unique session identifier.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * ds_id
 *    Datastore ID.
 *
 * req_id
 *    Config request ID.
 *
 * result
 *    Config request result (MGMT_*).
 *
 * error_if_any
 *    Buffer to store human-readable error message in case of error.
 *
 * implicit_commit
 *    TRUE if the commit is implicit, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failures.
 */
extern int mgmt_fe_send_set_cfg_reply(uint64_t session_id, uint64_t txn_id,
					  Mgmtd__DatastoreId ds_id,
					  uint64_t req_id,
					  enum mgmt_result result,
					  const char *error_if_any,
					  bool implcit_commit);

/*
 * Send commit-config reply to the frontend client.
 */
extern int mgmt_fe_send_commit_cfg_reply(
	uint64_t session_id, uint64_t txn_id, Mgmtd__DatastoreId src_ds_id,
	Mgmtd__DatastoreId dst_ds_id, uint64_t req_id, bool validate_only,
	enum mgmt_result result, const char *error_if_any);

/*
 * Send get-config/get-data reply to the frontend client.
 */
extern int mgmt_fe_send_get_reply(uint64_t session_id, uint64_t txn_id,
				  Mgmtd__DatastoreId ds_id, uint64_t req_id,
				  enum mgmt_result result,
				  Mgmtd__YangDataReply *data_resp,
				  const char *error_if_any);

/**
 * Send get-tree data reply back to client.
 *
 * This also cleans up and frees the transaction.
 *
 * Args:
 *	session_id: the session.
 *	txn_id: the txn_id this data pertains to
 *	req_id: the req id for the get_tree message
 *	result_type: the format of the result data.
 *	wd_options: with-defaults options.
 *	tree: the results.
 *	partial_error: if there were errors while gather results.
 *	short_circuit_ok: True if OK to short-circuit the call.
 *
 * Return:
 *	the return value from the underlying send function.
 *
 */
extern int
mgmt_fe_adapter_send_tree_data(uint64_t session_id, uint64_t txn_id,
			       uint64_t req_id, LYD_FORMAT result_type,
			       uint32_t wd_options, const struct lyd_node *tree,
			       int partial_error, bool short_circuit_ok);

/**
 * Send RPC reply back to client.
 *
 * This also cleans up and frees the transaction.
 *
 * Args:
 *	session_id: the session.
 *	txn_id: the txn_id this data pertains to
 *	req_id: the req id for the rpc message
 *	result_type: the format of the result data.
 *	result: the results.
 *
 * Return:
 *	the return value from the underlying send function.
 */
extern int mgmt_fe_adapter_send_rpc_reply(uint64_t session_id, uint64_t txn_id,
					  uint64_t req_id,
					  LYD_FORMAT result_type,
					  const struct lyd_node *result);

/**
 * Send edit reply back to client. If error is not 0, a native error is sent.
 *
 * This also cleans up and frees the transaction.
 *
 * Args:
 *     session_id: the session.
 *     txn_id: the txn_id this data pertains to
 *     req_id: the req id for the edit message
 *     unlock: implicit-lock flag was set in the request
 *     commit: implicit-commit flag was set in the request
 *     xpath: the xpath of the data node that was created
 *     error: the error code, zero for successful request
 *     errstr: the error string, if error is non-zero
 */
extern int mgmt_fe_adapter_send_edit_reply(uint64_t session_id, uint64_t txn_id,
					   uint64_t req_id, bool unlock,
					   bool commit, const char *xpath,
					   int16_t error, const char *errstr);

/**
 * Send an error back to the FE client using native messaging.
 *
 * This also cleans up and frees the transaction.
 *
 * Args:
 *	txn_id: the txn_id this error pertains to.
 *	short_circuit_ok: True if OK to short-circuit the call.
 *	error: An integer error value.
 *	errfmt: An error format string (i.e., printfrr)
 *      ...: args for use by the `errfmt` format string.
 *
 * Return:
 *	the return value from the underlying send function.
 *
 */
extern int mgmt_fe_adapter_txn_error(uint64_t txn_id, uint64_t req_id,
				     bool short_circuit_ok, int16_t error,
				     const char *errstr);


/* Fetch frontend client session set-config stats */
extern struct mgmt_setcfg_stats *
mgmt_fe_get_session_setcfg_stats(uint64_t session_id);

/* Fetch frontend client session commit stats */
extern struct mgmt_commit_stats *
mgmt_fe_get_session_commit_stats(uint64_t session_id);

extern void mgmt_fe_adapter_status_write(struct vty *vty, bool detail);
extern void mgmt_fe_adapter_perf_measurement(struct vty *vty, bool config);
extern void mgmt_fe_adapter_reset_perf_stats(struct vty *vty);

/* Toggle debug on or off for connected clients. */
extern void mgmt_fe_adapter_toggle_client_debug(bool set);

#endif /* _FRR_MGMTD_FE_ADAPTER_H_ */
