/*
 * MGMTD Frontend Client Connection Adapter
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

#ifndef _FRR_MGMTD_FE_ADAPTER_H_
#define _FRR_MGMTD_FE_ADAPTER_H_

struct mgmt_fe_client_adapter;
struct mgmt_master;

struct mgmt_commit_stats {
	struct timeval last_start;
#ifdef MGMTD_LOCAL_VALIDATIONS_ENABLED
	struct timeval validate_start;
#endif
	struct timeval prep_cfg_start;
	struct timeval txn_create_start;
	struct timeval send_cfg_start;
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

PREDECL_LIST(mgmt_fe_session_list);

PREDECL_LIST(mgmt_fe_adapter_list);

struct mgmt_fe_client_adapter {
	int conn_fd;
	union sockunion conn_su;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	struct thread *conn_writes_on;
	struct thread *proc_msg_ev;
	uint32_t flags;

	char name[MGMTD_CLIENT_NAME_MAX_LEN];

	/* List of sessions created and being maintained for this client. */
	struct mgmt_fe_session_list_head fe_sessions;

	/* IO streams for read and write */
	/* pthread_mutex_t ibuf_mtx; */
	struct stream_fifo *ibuf_fifo;
	/* pthread_mutex_t obuf_mtx; */
	struct stream_fifo *obuf_fifo;

	/* Private I/O buffers */
	struct stream *ibuf_work;
	struct stream *obuf_work;

	int refcount;
	uint32_t num_msg_tx;
	uint32_t num_msg_rx;
	struct mgmt_commit_stats cmt_stats;
	struct mgmt_setcfg_stats setcfg_stats;

	struct mgmt_fe_adapter_list_item list_linkage;
};

#define MGMTD_FE_ADAPTER_FLAGS_WRITES_OFF (1U << 0)

DECLARE_LIST(mgmt_fe_adapter_list, struct mgmt_fe_client_adapter,
	     list_linkage);

/* Initialise frontend adapter module */
extern int mgmt_fe_adapter_init(struct thread_master *tm,
				    struct mgmt_master *cm);

/* Destroy frontend adapter module */
extern void mgmt_fe_adapter_destroy(void);

/* Acquire lock for frontend adapter */
extern void mgmt_fe_adapter_lock(struct mgmt_fe_client_adapter *adapter);

/* Remove lock from frontend adapter */
extern void
mgmt_fe_adapter_unlock(struct mgmt_fe_client_adapter **adapter);

/* Create frontend adapter */
extern struct mgmt_fe_client_adapter *
mgmt_fe_create_adapter(int conn_fd, union sockunion *su);

/* Fetch frontend adapter given a name */
extern struct mgmt_fe_client_adapter *
mgmt_fe_get_adapter(const char *name);

/*
 * Send set-config reply to the frontend client.
 *
 * session
 *    Unique session identifier.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * db_id
 *    Database ID.
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
					  Mgmtd__DatabaseId db_id,
					  uint64_t req_id,
					  enum mgmt_result result,
					  const char *error_if_any,
					  bool implcit_commit);

/*
 * Send commit-config reply to the frontend client.
 */
extern int mgmt_fe_send_commit_cfg_reply(
	uint64_t session_id, uint64_t txn_id, Mgmtd__DatabaseId src_db_id,
	Mgmtd__DatabaseId dst_db_id, uint64_t req_id, bool validate_only,
	enum mgmt_result result, const char *error_if_any);

/*
 * Send get-config reply to the frontend client.
 */
extern int mgmt_fe_send_get_cfg_reply(uint64_t session_id, uint64_t txn_id,
					  Mgmtd__DatabaseId db_id,
					  uint64_t req_id,
					  enum mgmt_result result,
					  Mgmtd__YangDataReply *data_resp,
					  const char *error_if_any);

/*
 * Send get-data reply to the frontend client.
 */
extern int mgmt_fe_send_get_data_reply(
	uint64_t session_id, uint64_t txn_id, Mgmtd__DatabaseId db_id,
	uint64_t req_id, enum mgmt_result result,
	Mgmtd__YangDataReply *data_resp, const char *error_if_any);

/*
 * Send data notify to the frontend client.
 */
extern int mgmt_fe_send_data_notify(Mgmtd__DatabaseId db_id,
					Mgmtd__YangData * data_resp[],
					int num_data);

/* Fetch frontend client session set-config stats */
extern struct mgmt_setcfg_stats *
mgmt_fe_get_session_setcfg_stats(uint64_t session_id);

/* Fetch frontend client session commit stats */
extern struct mgmt_commit_stats *
mgmt_fe_get_session_commit_stats(uint64_t session_id);

extern void mgmt_fe_adapter_status_write(struct vty *vty, bool detail);
extern void mgmt_fe_adapter_perf_measurement(struct vty *vty, bool config);
extern void mgmt_fe_adapter_reset_perf_stats(struct vty *vty);
#endif /* _FRR_MGMTD_FE_ADAPTER_H_ */
