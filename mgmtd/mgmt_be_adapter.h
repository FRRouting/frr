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
#include "queue.h"

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
	MGMTD_BE_CLIENT_ID_MGMTD, /* loopback */
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


PREDECL_LIST(mgmt_be_adapters);

struct mgmt_be_client_adapter {
	struct msg_conn *conn;

	struct event *conn_init_ev;

	enum mgmt_be_client_id id;
	char name[MGMTD_CLIENT_NAME_MAX_LEN];

	struct mgmt_commit_stats cfg_stats;
	struct mgmt_be_adapters_item list_linkage;

	LIST_ENTRY(mgmt_be_client_adapter) link;
};

/* --------- */
/* CLIENT-ID */
/* --------- */

#define FOREACH_MGMTD_BE_CLIENT_ID(id)                                         \
	for ((id) = MGMTD_BE_CLIENT_ID_MIN; (id) < MGMTD_BE_CLIENT_ID_MAX;     \
	     (id)++)

#define IDBIT_MASK(id)	      (1ull << (id))
#define IS_IDBIT_UNSET(v, id) (!((v)&IDBIT_MASK(id)))
#define IS_IDBIT_SET(v, id)   (!IS_IDBIT_UNSET(v, id))
#define SET_IDBIT(v, id)      ((v) |= IDBIT_MASK(id))
#define UNSET_IDBIT(v, id)    ((v) &= ~IDBIT_MASK(id))

#define _GET_NEXT_SET(id, bits)                                                                    \
	({                                                                                         \
		enum mgmt_be_client_id _gns_id = (id);                                             \
                                                                                                   \
		for (; _gns_id < MGMTD_BE_CLIENT_ID_MAX && IS_IDBIT_UNSET(bits, _gns_id);          \
		     _gns_id++)                                                                    \
			;                                                                          \
		_gns_id;                                                                           \
	})

#define FOREACH_BE_CLIENT_BITS(id, bits)                                                           \
	for ((id) = _GET_NEXT_SET(MGMTD_BE_CLIENT_ID_MIN, bits); (id) < MGMTD_BE_CLIENT_ID_MAX;    \
	     (id) = _GET_NEXT_SET((id) + 1, bits))

/* This is required to avoid assignment in if conditional in FOREACH_BE_ADAPTER_BITS :( */
#define _GET_NEXT_SET_ADAPTER(id, adapter, bits)                                                  \
	({                                                                                        \
		enum mgmt_be_client_id _gnsa_id = (id);                                           \
                                                                                                  \
		for (; _gnsa_id < MGMTD_BE_CLIENT_ID_MAX; _gnsa_id++) {                           \
			if (IS_IDBIT_SET(bits, _gnsa_id)) {                                       \
				(adapter) = mgmt_be_get_adapter_by_id(_gnsa_id);                  \
				if ((adapter))                                                    \
					break;                                                    \
			}                                                                         \
		}                                                                                 \
		_gnsa_id;                                                                         \
	})

#define FOREACH_BE_ADAPTER_BITS(id, adapter, bits)                                                \
	for ((id) = _GET_NEXT_SET_ADAPTER(MGMTD_BE_CLIENT_ID_MIN, (adapter), (bits));             \
	     (id) < MGMTD_BE_CLIENT_ID_MAX;                                                       \
	     (id) = _GET_NEXT_SET_ADAPTER((id) + 1, (adapter), (bits)))

/* ---------- */
/* Prototypes */
/* ---------- */

/* Initialise backend adapter module. */
extern void mgmt_be_adapter_init(struct event_loop *tm);

/* Destroy the backend adapter module. */
extern void mgmt_be_adapter_destroy(void);

/* Create backend adapter. */
extern struct msg_conn *mgmt_be_create_adapter(int conn_fd,
					       union sockunion *su);

/* Fetch backend adapter given an client ID. */
extern struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_id(enum mgmt_be_client_id id);

/* Get the client name given a client ID */
extern const char *mgmt_be_client_id2name(enum mgmt_be_client_id id);

/* Toggle debug on or off for connected clients. */
extern void mgmt_be_adapter_toggle_client_debug(bool set);

/* Fetch backend adapter config. */
extern struct nb_config_cbs mgmt_be_get_adapter_config(struct mgmt_be_client_adapter *adapter);

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
extern int mgmt_be_send_native(struct mgmt_be_client_adapter *adapter, void *msg);

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

/*
 * Specials for mgmtd internally handling BE like behaviors
 */
extern bool mgmt_is_mgmtd_interested(const char *xpath);

#endif /* _FRR_MGMTD_BE_ADAPTER_H_ */
