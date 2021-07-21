/*
 * CMGD Frontend Client Connection Adapter
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

#ifndef _FRR_CMGD_FRNTND_ADAPTER_H_
#define _FRR_CMGD_FRNTND_ADAPTER_H_

#include "lib/typesafe.h"
#include "cmgd/cmgd_defines.h"
#include "cmgd/cmgd.h"
#include "lib/cmgd_pb.h"
#include "lib/cmgd_frntnd_client.h"

struct cmgd_frntnd_client_adapter_;
struct cmgd_master;

PREDECL_LIST(cmgd_frntnd_sessn_list);

PREDECL_LIST(cmgd_frntnd_adptr_list);

typedef struct cmgd_frntnd_client_adapter_ {
        int conn_fd;
        union sockunion conn_su;
        struct thread *conn_read_ev;
        struct thread *conn_write_ev;
        struct thread *proc_msg_ev;
        char name[CMGD_CLIENT_NAME_MAX_LEN];
        // uint8_t num_xpath_reg;
        // char xpath_reg[CMGD_MAX_NUM_XPATH_REG][CMGD_MAX_XPATH_LEN];

        struct cmgd_frntnd_sessn_list_head frntnd_sessns;

        /* IO streams for read and write */
	// pthread_mutex_t ibuf_mtx;
	struct stream_fifo *ibuf_fifo;
	// pthread_mutex_t obuf_mtx;
	// struct stream_fifo *obuf_fifo;

	// /* Private I/O buffers */
	struct stream *ibuf_work;
	// struct stream *obuf_work;

	/* Buffer of data waiting to be written to client. */
	// struct buffer *wb;

        int refcount;

        struct cmgd_frntnd_adptr_list_item list_linkage;
} cmgd_frntnd_client_adapter_t;

DECLARE_LIST(cmgd_frntnd_adptr_list, cmgd_frntnd_client_adapter_t, list_linkage);

extern int cmgd_frntnd_adapter_init(
        struct thread_master *tm, struct cmgd_master *cm);

extern void cmgd_frntnd_adapter_lock(cmgd_frntnd_client_adapter_t *adptr);

extern void cmgd_frntnd_adapter_unlock(cmgd_frntnd_client_adapter_t **adptr);

extern cmgd_frntnd_client_adapter_t *cmgd_frntnd_create_adapter(
        int conn_fd, union sockunion *su);

extern cmgd_frntnd_client_adapter_t *cmgd_frntnd_get_adapter(const char *name);

extern int cmgd_frntnd_send_set_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        const char *error_if_any);

extern int cmgd_frntnd_send_commit_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t src_db_id,
        cmgd_database_id_t dst_db_id, cmgd_client_req_id_t req_id,
	bool validate_only, cmgd_result_t result,
	const char *error_if_any);

extern int cmgd_frntnd_send_get_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        cmgd_yang_data_t *data_resp[], int num_data,
        const char *error_if_any);

extern int cmgd_frntnd_send_get_data_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        cmgd_yang_data_t *data_resp[], int num_data,
        const char *error_if_any);

extern int cmgd_frntnd_send_data_notify(
        cmgd_database_id_t db_id, cmgd_yang_data_t *data_resp[], int num_data);

extern void cmgd_frntnd_adapter_status_write(struct vty *vty);

#endif /* _FRR_CMGD_FRNTND_ADAPTER_H_ */
