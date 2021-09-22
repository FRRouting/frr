/*
 * MGMTD Backend Client Connection Adapter
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

#ifndef _FRR_MGMTD_BCKND_ADAPTER_H_
#define _FRR_MGMTD_BCKND_ADAPTER_H_

#include "lib/typesafe.h"
#include "mgmtd/mgmt_defines.h"
#include "lib/mgmt_bcknd_client.h"
#include "mgmtd/mgmt_db.h"

#define MGMTD_BCKND_CONN_INIT_DELAY_MSEC		50

#define MGMTD_FIND_ADAPTER_BY_INDEX(adapter_index)	\
	mgmt_adaptr_ref[adapter_index]

// List of adapter clients of MGMTD
#define MGMTD_BCKND_CLIENT_INDEX_STATICD (1 << MGMTD_BCKND_CLIENT_ID_STATICD)
#define MGMTD_BCKND_CLIENT_INDEX_BGPD (1 << MGMTD_BCKND_CLIENT_ID_BGPD)

typedef enum mgmt_bcknd_req_type_ {
        MGMTD_BCKND_REQ_NONE = 0,
        MGMTD_BCKND_REQ_CFG_VALIDATE,
        MGMTD_BCKND_REQ_CFG_APPLY,
        MGMTD_BCKND_REQ_DATA_GET_ELEM,
        MGMTD_BCKND_REQ_DATA_GET_NEXT
} mgmt_bcknd_req_type_t;

typedef struct mgmt_bcknd_cfgreq_ {
        mgmt_yang_cfgdata_req_t **cfgdata_reqs;
        size_t num_reqs;
} mgmt_bcknd_cfgreq_t;

typedef struct mgmt_bcknd_datareq_ {
        mgmt_yang_getdata_req_t **getdata_reqs;
        size_t num_reqs;
} mgmt_bcknd_datareq_t;

PREDECL_LIST(mgmt_bcknd_adptr_list);
PREDECL_LIST(mgmt_trxn_badptr_list);

typedef struct mgmt_bcknd_client_adapter_ {
        mgmt_bcknd_client_id_t id;
        int conn_fd;
        union sockunion conn_su;
        struct thread *conn_init_ev;
        struct thread *conn_read_ev;
        struct thread *conn_write_ev;
        struct thread *conn_writes_on;
        struct thread *proc_msg_ev;
	uint32_t flags;
        char name[MGMTD_CLIENT_NAME_MAX_LEN];
        uint8_t num_xpath_reg;
        char xpath_reg[MGMTD_MAX_NUM_XPATH_REG][MGMTD_MAX_XPATH_LEN];

        /* IO streams for read and write */
	// pthread_mutex_t ibuf_mtx;
	struct stream_fifo *ibuf_fifo;
	// pthread_mutex_t obuf_mtx;
	struct stream_fifo *obuf_fifo;

	// /* Private I/O buffers */
	struct stream *ibuf_work;
	struct stream *obuf_work;
	uint8_t msg_buf[MGMTD_BCKND_MSG_MAX_LEN];

	/* Buffer of data waiting to be written to client. */
	// struct buffer *wb;

        // int adapter_index;
        int refcount;
        uint32_t num_msg_tx;
        uint32_t num_msg_rx;

        /*
         * List of config items that should be sent to the 
         * backend during re/connect. This is temporarily 
         * created and then freed-up as soon as the initial 
         * config items has been applied onto the backend.
         */
        struct nb_config_cbs cfg_chgs;

        struct mgmt_bcknd_adptr_list_item list_linkage;
        struct mgmt_trxn_badptr_list_item trxn_list_linkage;
} mgmt_bcknd_client_adapter_t;

#define MGMTD_BCKND_ADPTR_FLAGS_WRITES_OFF         (1U << 0)
#define MGMTD_BCKND_ADPTR_FLAGS_CFG_SYNCED         (1U << 1)

DECLARE_LIST(mgmt_bcknd_adptr_list, mgmt_bcknd_client_adapter_t, list_linkage);
DECLARE_LIST(mgmt_trxn_badptr_list, mgmt_bcknd_client_adapter_t, trxn_list_linkage);

typedef union mgmt_bcknd_xpath_subscr_info_ {
	uint8_t subscribed;
	struct {
		uint8_t validate_config:1;
		uint8_t notify_config:1;
		uint8_t own_oper_data:1;
	};
} mgmt_bcknd_xpath_subscr_info_t;

typedef struct mgmt_bcknd_client_subscr_info_ {
	mgmt_bcknd_xpath_subscr_info_t xpath_subscr[MGMTD_BCKND_CLIENT_ID_MAX];
} mgmt_bcknd_client_subscr_info_t;

extern int mgmt_bcknd_adapter_init(struct thread_master *tm);

extern void mgmt_bcknd_adapter_lock(mgmt_bcknd_client_adapter_t *adptr);

extern void mgmt_bcknd_adapter_unlock(mgmt_bcknd_client_adapter_t **adptr);

extern mgmt_bcknd_client_adapter_t *mgmt_bcknd_create_adapter(
        int conn_fd, union sockunion *su);

extern mgmt_bcknd_client_adapter_t *mgmt_bcknd_get_adapter_by_name(
        const char *name);

extern mgmt_bcknd_client_adapter_t *mgmt_bcknd_get_adapter_by_id(
        mgmt_bcknd_client_id_t id);

extern int mgmt_bcknd_get_adapter_config(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_db_hndl_t db_hndl,
	struct nb_config_cbs **cfg_chgs);

extern int mgmt_bcknd_create_trxn(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id);

extern int mgmt_bcknd_destroy_trxn(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id);

extern int mgmt_bcknd_send_cfg_data_create_req(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id,
        mgmt_trxn_batch_id_t batch_id, mgmt_bcknd_cfgreq_t *cfg_req,
        bool end_of_data);

extern int mgmt_bcknd_send_cfg_validate_req(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id,
        mgmt_trxn_batch_id_t batch_ids[], size_t num_batch_ids);

extern int mgmt_bcknd_send_cfg_apply_req(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id);

extern int mgmt_bcknd_send_get_data_req(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id,
        mgmt_trxn_batch_id_t batch_id, mgmt_bcknd_datareq_t *data_req);

extern int mgmt_bcknd_send_get_next_data_req(
        mgmt_bcknd_client_adapter_t *adptr, mgmt_trxn_id_t trxn_id,
        mgmt_trxn_batch_id_t batch_id, mgmt_bcknd_datareq_t *data_req);

extern void mgmt_bcknd_adapter_status_write(struct vty *vty);

extern void mgmt_bcknd_xpath_register_write(struct vty *vty);

extern int mgmt_bcknd_get_subscr_info_for_xpath(const char *xpath, 
	mgmt_bcknd_client_subscr_info_t *subscr_info);

extern void mgmt_bcknd_xpath_subscr_info_write(
        struct vty *vty, const char *xpath);

#endif /* _FRR_MGMTD_BCKND_ADAPTER_H_ */
