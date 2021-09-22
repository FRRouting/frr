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

#ifndef _FRR_MGMTD_FRNTND_ADAPTER_H_
#define _FRR_MGMTD_FRNTND_ADAPTER_H_

#include "lib/typesafe.h"
#include "mgmtd/mgmt_defines.h"
#include "mgmtd/mgmt.h"
#include "lib/mgmt_pb.h"
#include "lib/mgmt_frntnd_client.h"

struct mgmt_frntnd_client_adapter_;
struct mgmt_master;

typedef struct mgmt_commit_stats_ {
        struct timeval last_start;
        struct timeval validate_start;
        struct timeval prep_cfg_start;
        struct timeval trxn_create_start;
        struct timeval send_cfg_start;
        struct timeval apply_cfg_start;
        struct timeval apply_cfg_end;
        struct timeval trxn_del_start;
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
} mgmt_commit_stats_t;

typedef struct mgmt_setcfg_stats_ {
	struct timeval last_start;
	struct timeval last_end;
	unsigned long last_exec_tm;
	unsigned long max_tm;
	unsigned long min_tm;
	unsigned long avg_tm;
	unsigned long set_cfg_count;
} mgmt_setcfg_stats_t;

PREDECL_LIST(mgmt_frntnd_sessn_list);

PREDECL_LIST(mgmt_frntnd_adptr_list);

typedef struct mgmt_frntnd_client_adapter_ {
        int conn_fd;
        union sockunion conn_su;
        struct thread *conn_read_ev;
        struct thread *conn_write_ev;
        struct thread *conn_writes_on;
        struct thread *proc_msg_ev;
        uint32_t flags;

        char name[MGMTD_CLIENT_NAME_MAX_LEN];
        // uint8_t num_xpath_reg;
        // char xpath_reg[MGMTD_MAX_NUM_XPATH_REG][MGMTD_MAX_XPATH_LEN];

        struct mgmt_frntnd_sessn_list_head frntnd_sessns;

        /* IO streams for read and write */
	// pthread_mutex_t ibuf_mtx;
	struct stream_fifo *ibuf_fifo;
	// pthread_mutex_t obuf_mtx;
	struct stream_fifo *obuf_fifo;

	// /* Private I/O buffers */
	struct stream *ibuf_work;
	struct stream *obuf_work;

	/* Buffer of data waiting to be written to client. */
	// struct buffer *wb;

        int refcount;
        uint32_t num_msg_tx;
        uint32_t num_msg_rx;
	mgmt_commit_stats_t cmt_stats;
        mgmt_setcfg_stats_t setcfg_stats;

        struct mgmt_frntnd_adptr_list_item list_linkage;
} mgmt_frntnd_client_adapter_t;

#define MGMTD_FRNTND_ADPTR_FLAGS_WRITES_OFF	(1U << 0)

DECLARE_LIST(mgmt_frntnd_adptr_list, mgmt_frntnd_client_adapter_t, list_linkage);

extern int mgmt_frntnd_adapter_init(
        struct thread_master *tm, struct mgmt_master *cm);

extern void mgmt_frntnd_adapter_lock(mgmt_frntnd_client_adapter_t *adptr);

extern void mgmt_frntnd_adapter_unlock(mgmt_frntnd_client_adapter_t **adptr);

extern mgmt_frntnd_client_adapter_t *mgmt_frntnd_create_adapter(
        int conn_fd, union sockunion *su);

extern mgmt_frntnd_client_adapter_t *mgmt_frntnd_get_adapter(const char *name);

extern int mgmt_frntnd_send_set_cfg_reply(mgmt_session_id_t session_id,
        mgmt_trxn_id_t trxn_id, mgmt_database_id_t db_id,
        mgmt_client_req_id_t req_id, mgmt_result_t result,
        const char *error_if_any, bool implcit_commit);

extern int mgmt_frntnd_send_commit_cfg_reply(mgmt_session_id_t session_id,
        mgmt_trxn_id_t trxn_id, mgmt_database_id_t src_db_id,
        mgmt_database_id_t dst_db_id, mgmt_client_req_id_t req_id,
	bool validate_only, mgmt_result_t result,
	const char *error_if_any);

extern int mgmt_frntnd_send_get_cfg_reply(mgmt_session_id_t session_id,
        mgmt_trxn_id_t trxn_id, mgmt_database_id_t db_id,
        mgmt_client_req_id_t req_id, mgmt_result_t result,
        mgmt_yang_data_reply_t *data_resp, const char *error_if_any);

extern int mgmt_frntnd_send_get_data_reply(mgmt_session_id_t session_id,
        mgmt_trxn_id_t trxn_id, mgmt_database_id_t db_id,
        mgmt_client_req_id_t req_id, mgmt_result_t result,
        mgmt_yang_data_reply_t *data_resp, const char *error_if_any);

extern int mgmt_frntnd_send_data_notify(
        mgmt_database_id_t db_id, mgmt_yang_data_t *data_resp[], int num_data);

extern mgmt_setcfg_stats_t *mgmt_frntnd_get_sessn_setcfg_stats(
        mgmt_session_id_t session_id);

extern mgmt_commit_stats_t *mgmt_frntnd_get_sessn_commit_stats(
        mgmt_session_id_t session_id);

extern void mgmt_frntnd_adapter_status_write(struct vty *vty, bool detail);
extern void mgmt_frntnd_adapter_perf_measurement(struct vty *vty, bool config);
extern void mgmt_frntnd_adapter_reset_perf_stats(struct vty *vty);
#endif /* _FRR_MGMTD_FRNTND_ADAPTER_H_ */
