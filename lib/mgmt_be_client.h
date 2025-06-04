// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_BE_CLIENT_H_
#define _FRR_MGMTD_BE_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "northbound.h"
#include "mgmt_defines.h"

/***************************************************************
 * Constants
 ***************************************************************/

#define MGMTD_BE_MAX_NUM_MSG_PROC  500
#define MGMTD_BE_MAX_NUM_MSG_WRITE 1000
#define MGMTD_BE_MAX_MSG_LEN	   (64 * 1024)

#define MGMTD_BE_CONTAINER_NODE_VAL "<<container>>"

/***************************************************************
 * Data-structures
 ***************************************************************/

#define MGMTD_BE_MAX_CLIENTS_PER_XPATH_REG 32

struct mgmt_be_client;

struct mgmt_be_client_txn_ctx {
	uintptr_t *user_ctx;
};

/**
 * Backend client callbacks.
 *
 * Callbacks:
 *	client_connect_notify: called when connection is made/lost to mgmtd.
 *	txn_notify: called when a txn has been created
 *	config_xpaths: config xpaths to register with mgmtd.
 *	nconfig_xpaths: number of config xpaths.
 *	oper_xpaths: oper-state xpaths to register with mgmtd.
 *	noper_xpaths: number of oper-state xpaths.
 *	notify_xpaths: notify xpaths to register with mgmtd.
 *	nnotify_xpaths: number of notify xpaths.
 *	rpc_xpaths: rpc xpaths to register with mgmtd.
 *	nrpc_xpaths: number of rpc xpaths.
 *
 */
struct mgmt_be_client_cbs {
	void (*client_connect_notify)(struct mgmt_be_client *client,
				      uintptr_t usr_data, bool connected);
	void (*txn_notify)(struct mgmt_be_client *client, uintptr_t usr_data,
			   struct mgmt_be_client_txn_ctx *txn_ctx,
			   bool destroyed);

	const char **config_xpaths;
	uint nconfig_xpaths;
	const char **oper_xpaths;
	uint noper_xpaths;
	const char **notify_xpaths;
	uint nnotify_xpaths;
	const char **rpc_xpaths;
	uint nrpc_xpaths;
};

/***************************************************************
 * Global data exported
 ***************************************************************/

extern struct debug mgmt_dbg_be_client;

extern const struct frr_yang_module_info frr_backend_info;

/***************************************************************
 * API prototypes
 ***************************************************************/

#define debug_be_client(fmt, ...)                                              \
	DEBUGD(&mgmt_dbg_be_client, "BE-CLIENT: %s: " fmt, __func__,           \
	       ##__VA_ARGS__)
#define log_err_be_client(fmt, ...)                                            \
	zlog_err("BE-CLIENT: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#define debug_check_be_client()                                                \
	DEBUG_MODE_CHECK(&mgmt_dbg_be_client, DEBUG_MODE_ALL)

/**
 * Create backend client and connect to MGMTD.
 *
 * Args:
 *	client_name: the name of the client
 *	cbs: callbacks for various events.
 *	event_loop: the main event loop.
 *
 * Returns:
 *    Backend client object.
 */
extern struct mgmt_be_client *
mgmt_be_client_create(const char *name, struct mgmt_be_client_cbs *cbs,
		      uintptr_t user_data, struct event_loop *event_loop);


/**
 * mgmt_be_send_ds_delete_notification() - Send a datastore delete notification.
 */
extern int mgmt_be_send_ds_delete_notification(const char *path);

/**
 * mgmt_be_send_ds_patch_notification() - Send a datastore YANG patch notification.
 */
extern int mgmt_be_send_ds_patch_notification(const char *path, const struct lyd_node *tree);

/**
 * mgmt_be_send_ds_replace_notification() - Send a datastore replace notification.
 */
extern int mgmt_be_send_ds_replace_notification(const char *path, const struct lyd_node *tree,
						uint64_t refer_id);

/*
 * Initialize library vty (adds debug support).
 *
 * This call should be added to your component when enabling other vty code to
 * enable mgmtd client debugs. When adding, one needs to also add a their
 * component in `xref2vtysh.py` as well.
 */
extern void mgmt_be_client_lib_vty_init(void);

/*
 * Destroy backend client and cleanup everything.
 */
extern void mgmt_be_client_destroy(struct mgmt_be_client *client);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_BE_CLIENT_H_ */
