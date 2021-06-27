/*
 * CMGD Transactions
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

#ifndef _FRR_CMGD_TRXN_H_
#define _FRR_CMGD_TRXN_H_

#include "lib/typesafe.h"
#include "cmgd/cmgd_defines.h"
#include "lib/cmgd_pb.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "cmgd/cmgd_frntnd_adapter.h"

typedef enum cmgd_trxn_type_ {
        CMGD_TRXN_TYPE_NONE = 0,
        CMGD_TRXN_TYPE_CONFIG,
        CMGD_TRXN_TYPE_SHOW
} cmgd_trxn_type_t;

PREDECL_LIST(cmgd_trxn_list);

#define FOREACH_TRXN_IN_LIST(cm, trxn)					\
	for ((trxn) = cmgd_trxn_list_first(&(cm)->cmgd_trxns); (trxn);	\
		(trxn) = cmgd_trxn_list_next(&(cm)->cmgd_trxns, (trxn)))

struct cmgd_master;

typedef struct cmgd_trxn_ctxt_ {
        cmgd_session_id_t session_id; /* One transaction per client session */
        cmgd_trxn_type_t type;

	struct cmgd_master *cm;

        // struct thread *conn_read_ev;
        // struct thread *conn_write_ev;
        // struct thread *proc_msg_ev;
        // char name[CMGD_CLIENT_NAME_MAX_LEN];
        // uint8_t num_xpath_reg;
        // char xpath_reg[CMGD_MAX_NUM_XPATH_REG][CMGD_MAX_XPATH_LEN];

        /* List of backend adapters involved in this transaction */
        struct cmgd_trxn_badptr_list_head bcknd_adptrs;

        /* IO streams for read and write */
	// pthread_mutex_t ibuf_mtx;
	// struct stream_fifo *ibuf_fifo;
	// pthread_mutex_t obuf_mtx;
	// struct stream_fifo *obuf_fifo;

	// /* Private I/O buffers */
	// struct stream *ibuf_work;
	// struct stream *obuf_work;

	/* Buffer of data waiting to be written to client. */
	// struct buffer *wb;

        int refcount;

        struct cmgd_trxn_list_item list_linkage;
} cmgd_trxn_ctxt_t;

DECLARE_LIST(cmgd_trxn_list, cmgd_trxn_ctxt_t, list_linkage);

extern int cmgd_trxn_init(struct cmgd_master *cm);

extern void cmgd_trxn_lock(cmgd_trxn_ctxt_t *trxn);

extern void cmgd_trxn_unlock(cmgd_trxn_ctxt_t **trxn);

extern cmgd_trxn_id_t cmgd_create_trxn(
        cmgd_session_id_t session_id, cmgd_trxn_type_t type);

extern void cmgd_destroy_trxn(cmgd_trxn_id_t trxn_id);

extern int cmgd_trxn_send_set_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_cfgdata_req_t *cfg_req[], int num_req);

extern int cmgd_trxn_send_commit_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t src_db_id,
        cmgd_database_id_t dst_db_id);

extern int cmgd_trxn_send_get_config_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs);

extern int cmgd_trxn_send_get_data_req(
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs);

extern void cmgd_trxn_status_write(struct vty *vty);

#endif /* _FRR_CMGD_TRXN_H_ */
