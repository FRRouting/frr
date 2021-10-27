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

#ifndef _FRR_MGMTD_BE_ADAPTER_H_
#define _FRR_MGMTD_BE_ADAPTER_H_

#include "mgmtd/mgmt_defines.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_db.h"

#define MGMTD_BE_CONN_INIT_DELAY_MSEC 50

#define MGMTD_FIND_ADAPTER_BY_INDEX(adapter_index)                             \
	mgmt_adaptr_ref[adapter_index]

/* List of adapter clients of MGMTD */
#define MGMTD_BE_CLIENT_INDEX_STATICD (1 << MGMTD_BE_CLIENT_ID_STATICD)
#define MGMTD_BE_CLIENT_INDEX_BGPD (1 << MGMTD_BE_CLIENT_ID_BGPD)

enum mgmt_be_req_type {
	MGMTD_BE_REQ_NONE = 0,
	MGMTD_BE_REQ_CFG_VALIDATE,
	MGMTD_BE_REQ_CFG_APPLY,
	MGMTD_BE_REQ_DATA_GET_ELEM,
	MGMTD_BE_REQ_DATA_GET_NEXT
};

struct mgmt_be_cfgreq {
	Mgmtd__YangCfgDataReq **cfgdata_reqs;
	size_t num_reqs;
};

struct mgmt_be_datareq {
	Mgmtd__YangGetDataReq **getdata_reqs;
	size_t num_reqs;
};

PREDECL_LIST(mgmt_be_adapter_list);
PREDECL_LIST(mgmt_txn_badapter_list);

struct mgmt_be_client_adapter {
	enum mgmt_be_client_id id;
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
	/* pthread_mutex_t ibuf_mtx; */
	struct stream_fifo *ibuf_fifo;
	/* pthread_mutex_t obuf_mtx; */
	struct stream_fifo *obuf_fifo;

	/* Private I/O buffers */
	struct stream *ibuf_work;
	struct stream *obuf_work;
	uint8_t msg_buf[MGMTD_BE_MSG_MAX_LEN];

	/* Buffer of data waiting to be written to client. */
	/* struct buffer *wb; */

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

	struct mgmt_be_adapter_list_item list_linkage;
	struct mgmt_txn_badapter_list_item txn_list_linkage;
};

#define MGMTD_BE_ADAPTER_FLAGS_WRITES_OFF (1U << 0)
#define MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED (1U << 1)

DECLARE_LIST(mgmt_be_adapter_list, struct mgmt_be_client_adapter,
	     list_linkage);
DECLARE_LIST(mgmt_txn_badapter_list, struct mgmt_be_client_adapter,
	     txn_list_linkage);

union mgmt_be_xpath_subscr_info {
	uint8_t subscribed;
	struct {
		uint8_t validate_config : 1;
		uint8_t notify_config : 1;
		uint8_t own_oper_data : 1;
	};
};

struct mgmt_be_client_subscr_info {
	union mgmt_be_xpath_subscr_info
		xpath_subscr[MGMTD_BE_CLIENT_ID_MAX];
};

/* Initialise backend adapter module. */
extern int mgmt_be_adapter_init(struct thread_master *tm);

/* Destroy the backend adapter module. */
extern void mgmt_be_adapter_destroy(void);

/* Acquire lock for backend adapter. */
extern void mgmt_be_adapter_lock(struct mgmt_be_client_adapter *adapter);

/* Remove lock from backend adapter. */
extern void mgmt_be_adapter_unlock(struct mgmt_be_client_adapter **adapter);

/* Create backend adapter. */
extern struct mgmt_be_client_adapter *
mgmt_be_create_adapter(int conn_fd, union sockunion *su);

/* Fetch backend adapter given an adapter name. */
extern struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_name(const char *name);

/* Fetch backend adapter given an client ID. */
extern struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_id(enum mgmt_be_client_id id);

/* Fetch backend adapter config. */
extern int
mgmt_be_get_adapter_config(struct mgmt_be_client_adapter *adapter,
			      struct mgmt_db_ctx *db_ctx,
			      struct nb_config_cbs **cfg_chgs);

/* Create a transaction. */
extern int mgmt_be_create_txn(struct mgmt_be_client_adapter *adapter,
				  uint64_t txn_id);

/* Destroy a transaction. */
extern int mgmt_be_destroy_txn(struct mgmt_be_client_adapter *adapter,
				   uint64_t txn_id);

/*
 * Send config data create request to backend client.
 *
 * adaptr
 *    Backend adapter information.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * batch_id
 *    Request batch ID.
 *
 * cfg_req
 *    Config data request.
 *
 * end_of_data
 *    TRUE if the data from last batch, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_be_send_cfg_data_create_req(
	struct mgmt_be_client_adapter *adapter, uint64_t txn_id,
	uint64_t batch_id, struct mgmt_be_cfgreq *cfg_req, bool end_of_data);

/*
 * Send config validate request to backend client.
 *
 * adaptr
 *    Backend adapter information.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * batch_ids
 *    List of request batch IDs.
 *
 * num_batch_ids
 *    Number of batch ids.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int
mgmt_be_send_cfg_validate_req(struct mgmt_be_client_adapter *adapter,
				 uint64_t txn_id, uint64_t batch_ids[],
				 size_t num_batch_ids);

/*
 * Send config apply request to backend client.
 *
 * adaptr
 *    Backend adapter information.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int
mgmt_be_send_cfg_apply_req(struct mgmt_be_client_adapter *adapter,
			      uint64_t txn_id);

/*
 * Dump backend adapter status to vty.
 */
extern void mgmt_be_adapter_status_write(struct vty *vty);

/*
 * Dump xpath registry for each backend client to vty.
 */
extern void mgmt_be_xpath_register_write(struct vty *vty);

/*
 * Maps a YANG dtata Xpath to one or more
 * backend clients that should be contacted for various purposes.
 */
extern int mgmt_be_get_subscr_info_for_xpath(
	const char *xpath, struct mgmt_be_client_subscr_info *subscr_info);

/*
 * Dump backend client information for a given xpath to vty.
 */
extern void mgmt_be_xpath_subscr_info_write(struct vty *vty,
					       const char *xpath);

#endif /* _FRR_MGMTD_BE_ADAPTER_H_ */
