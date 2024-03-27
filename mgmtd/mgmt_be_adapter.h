// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#ifndef _FRR_MGMTD_BE_ADAPTER_H_
#define _FRR_MGMTD_BE_ADAPTER_H_

#include "mgmt_be_client.h"
#include "mgmt_msg.h"
#include "mgmt_defines.h"
#include "mgmtd/mgmt_ds.h"

#define MGMTD_BE_CONN_INIT_DELAY_MSEC 50

#define MGMTD_FIND_ADAPTER_BY_INDEX(adapter_index)	\
	mgmt_adaptr_ref[adapter_index]

/**
 * CLIENT-ID
 *
 * Add enum value for each supported component, wrap with
 * #ifdef HAVE_COMPONENT
 */
enum mgmt_be_client_id {
	MGMTD_BE_CLIENT_ID_TESTC, /* always first */
	MGMTD_BE_CLIENT_ID_ZEBRA,
#ifdef HAVE_RIPD
	MGMTD_BE_CLIENT_ID_RIPD,
#endif
#ifdef HAVE_RIPNGD
	MGMTD_BE_CLIENT_ID_RIPNGD,
#endif
#ifdef HAVE_STATICD
	MGMTD_BE_CLIENT_ID_STATICD,
#endif
	MGMTD_BE_CLIENT_ID_MAX
};
#define MGMTD_BE_CLIENT_ID_MIN	0


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

PREDECL_LIST(mgmt_be_adapters);
PREDECL_LIST(mgmt_txn_badapters);

struct mgmt_be_client_adapter {
	struct msg_conn *conn;

	struct event *conn_init_ev;

	enum mgmt_be_client_id id;
	uint32_t flags;
	char name[MGMTD_CLIENT_NAME_MAX_LEN];

	int refcount;

	/*
	 * List of config items that should be sent to the
	 * backend during re/connect. This is temporarily
	 * created and then freed-up as soon as the initial
	 * config items has been applied onto the backend.
	 */
	struct nb_config_cbs cfg_chgs;

	struct mgmt_be_adapters_item list_linkage;
};

#define MGMTD_BE_ADAPTER_FLAGS_CFG_SYNCED (1U << 0)

DECLARE_LIST(mgmt_be_adapters, struct mgmt_be_client_adapter, list_linkage);

/*
 * MGMT_SUBSCR_xxx - flags for subscription types for xpaths registrations
 *
 * MGMT_SUBSCR_VALIDATE_CFG :: the client should be asked to validate config
 * MGMT_SUBSCR_NOTIFY_CFG :: the client should be notified of config changes
 * MGMT_SUBSCR_OPER_OWN :: the client owns the given oeprational state
 */
#define MGMT_SUBSCR_VALIDATE_CFG 0x1
#define MGMT_SUBSCR_NOTIFY_CFG 0x2
#define MGMT_SUBSCR_OPER_OWN 0x4
#define MGMT_SUBSCR_ALL 0x7

/* --------- */
/* CLIENT-ID */
/* --------- */

#define FOREACH_MGMTD_BE_CLIENT_ID(id)                                         \
	for ((id) = MGMTD_BE_CLIENT_ID_MIN; (id) < MGMTD_BE_CLIENT_ID_MAX;     \
	     (id)++)

#define IS_IDBIT_SET(v, id)   (!IS_IDBIT_UNSET(v, id))
#define IS_IDBIT_UNSET(v, id) (!((v) & (1ull << (id))))

#define __GET_NEXT_SET(id, bits)                                               \
	({                                                                     \
		enum mgmt_be_client_id __id = (id);                            \
									       \
		for (; __id < MGMTD_BE_CLIENT_ID_MAX &&                        \
		       IS_IDBIT_UNSET(bits, __id);                             \
		     __id++)                                                   \
			;                                                      \
		__id;                                                          \
	})

#define FOREACH_BE_CLIENT_BITS(id, bits)                                       \
	for ((id) = __GET_NEXT_SET(MGMTD_BE_CLIENT_ID_MIN, bits);              \
	     (id) < MGMTD_BE_CLIENT_ID_MAX;                                    \
	     (id) = __GET_NEXT_SET((id) + 1, bits))

/* ---------- */
/* Prototypes */
/* ---------- */

/* Initialise backend adapter module. */
extern void mgmt_be_adapter_init(struct event_loop *tm);

/* Destroy the backend adapter module. */
extern void mgmt_be_adapter_destroy(void);

/* Acquire lock for backend adapter. */
extern void mgmt_be_adapter_lock(struct mgmt_be_client_adapter *adapter);

/* Remove lock from backend adapter. */
extern void mgmt_be_adapter_unlock(struct mgmt_be_client_adapter **adapter);

/* Create backend adapter. */
extern struct msg_conn *mgmt_be_create_adapter(int conn_fd,
					       union sockunion *su);

/* Fetch backend adapter given an adapter name. */
extern struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_name(const char *name);

/* Fetch backend adapter given an client ID. */
extern struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_id(enum mgmt_be_client_id id);

/* Get the client name given a client ID */
extern const char *mgmt_be_client_id2name(enum mgmt_be_client_id id);

/* Toggle debug on or off for connected clients. */
extern void mgmt_be_adapter_toggle_client_debug(bool set);

/* Fetch backend adapter config. */
extern void mgmt_be_get_adapter_config(struct mgmt_be_client_adapter *adapter,
				       struct nb_config_cbs **changes);

/* Create/destroy a transaction. */
extern int mgmt_be_send_txn_req(struct mgmt_be_client_adapter *adapter,
				uint64_t txn_id, bool create);

/*
 * Send config data create request to backend client.
 *
 * adaptr
 *    Backend adapter information.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * cfgdata_reqs
 *    An array of pointer to Mgmtd__YangCfgDataReq.
 *
 * num_reqs
 *    Length of the cfgdata_reqs array.
 *
 * end_of_data
 *    TRUE if the data from last batch, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_be_send_cfgdata_req(struct mgmt_be_client_adapter *adapter,
				    uint64_t txn_id,
				    Mgmtd__YangCfgDataReq **cfgdata_reqs,
				    size_t num_reqs, bool end_of_data);

/*
 * Send config apply request to backend client.
 *
 * adapter
 *    Backend adapter information.
 *
 * txn_id
 *    Unique transaction identifier.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_be_send_cfgapply_req(struct mgmt_be_client_adapter *adapter,
				     uint64_t txn_id);

/*
 * Dump backend adapter status to vty.
 */
extern void mgmt_be_adapter_status_write(struct vty *vty);

/*
 * Dump xpath registry for each backend client to vty.
 */
extern void mgmt_be_xpath_register_write(struct vty *vty);


/**
 * Send a native message to a backend client
 *
 * Args:
 *	adapter: the client to send the message to.
 *	msg: a native message from mgmt_msg_native_alloc_msg()
 *
 * Return:
 *	Any return value from msg_conn_send_msg().
 */
extern int mgmt_be_send_native(enum mgmt_be_client_id id, void *msg);

enum mgmt_be_xpath_subscr_type {
	MGMT_BE_XPATH_SUBSCR_TYPE_CFG,
	MGMT_BE_XPATH_SUBSCR_TYPE_OPER,
	MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF,
	MGMT_BE_XPATH_SUBSCR_TYPE_RPC,
};

/**
 * Lookup the clients which are subscribed to a given `xpath`
 * and the way they are subscribed.
 *
 * Args:
 *     xpath - the xpath to check for subscription information.
 *     type - type of subscription to check for.
 */
extern uint64_t mgmt_be_interested_clients(const char *xpath,
					   enum mgmt_be_xpath_subscr_type type);

/**
 * mgmt_fe_adapter_send_notify() - notify FE clients of a notification.
 * @msg: the notify message from the backend client.
 * @msglen: the length of the notify message.
 */
extern void mgmt_fe_adapter_send_notify(struct mgmt_msg_notify_data *msg,
					size_t msglen);
/*
 * Dump backend client information for a given xpath to vty.
 */
extern void mgmt_be_show_xpath_registries(struct vty *vty, const char *xpath);

#endif /* _FRR_MGMTD_BE_ADAPTER_H_ */
