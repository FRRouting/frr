/*
 * CMGD Backend Client Connection Adapter
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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

#ifndef _FRR_CMGD_BCKND_ADAPTER_H_
#define _FRR_CMGD_BCKND_ADAPTER_H_

#include "lib/typesafe.h"
#include "cmgd/cmgd_defines.h"

typedef void (*cmgd_bcknd_trxn_result_notify_t)(
        cmgd_trxn_id_t trxn_id, cmgd_result_t result);

typedef void (*cmgd_bcknd_cfg_result_notify_t)(
        cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_id,
        cmgd_result_t result, cmgd_bcknd_req_type_t orig_req);

typedef void (*cmgd_bcknd_get_data_result_notify_t)(
        cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_id,
        cmgd_result_t result, cmgd_bcknd_dataresult_t *data_resp);

typedef void (*cmgd_bcknd_data_notify_t)(
        struct nb_yang_xpath *xpaths[], int num_xpaths);

PREDECL_LIST(cmgd_adptr_list);

typedef struct cmgd_bcknd_client_adapter_ {
        int conn_fd;
        union sockunion conn_su;
        struct thread *conn_read_ev;
        struct thread *conn_write_ev;
        char name[CMGD_CLIENT_NAME_MAX_LEN];

        cmgd_bcknd_trxn_result_notify_t trxn_result_cb;
        cmgd_bcknd_cfg_result_notify_t cfgresult_cb;
        cmgd_bcknd_get_data_result_notify_t dataresult_cb;
        cmgd_bcknd_data_notify_t notifydata_cb;

        int refcount;

        struct cmgd_adptr_list_item list_linkage;
} cmgd_bcknd_client_adapter_t;

DECLARE_LIST(cmgd_adptr_list, cmgd_bcknd_client_adapter_t, list_linkage);

extern int cmgd_bcknd_adapter_init(struct thread_master *tm);

extern void cmgd_bcknd_adapter_lock(cmgd_bcknd_client_adapter_t *adptr);

extern void cmgd_bcknd_adapter_unlock(cmgd_bcknd_client_adapter_t **adptr);

extern cmgd_bcknd_client_adapter_t *cmgd_bcknd_create_adapter(
        int conn_fd, union sockunion *su);

extern cmgd_bcknd_client_adapter_t *cmgd_bcknd_get_adapter(const char *name);

extern int cmgd_bcknd_create_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id);

extern int cmgd_bcknd_destroy_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id);

extern int cmgd_bcknd_send_cfg_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_cfgreq_t *cfg_req);

extern int cmgd_bcknd_send_get_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req);

extern int cmgd_bcknd_send_get_next_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req);

#endif /* _FRR_CMGD_BCKND_ADAPTER_H_ */
