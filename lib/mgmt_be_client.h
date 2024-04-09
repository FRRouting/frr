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
#include "mgmt_pb.h"
#include "mgmt_defines.h"

/***************************************************************
 * Constants
 ***************************************************************/

#define MGMTD_BE_MAX_NUM_MSG_PROC  500
#define MGMTD_BE_MAX_NUM_MSG_WRITE 1000
#define MGMTD_BE_MAX_MSG_LEN	   (64 * 1024)

#define MGMTD_MAX_CFG_CHANGES_IN_BATCH                                         \
	((10 * MGMTD_BE_MAX_MSG_LEN) /                                         \
	 (MGMTD_MAX_XPATH_LEN + MGMTD_MAX_YANG_VALUE_LEN))

/*
 * MGMTD_BE_MSG_MAX_LEN must be used 80%
 * since there is overhead of google protobuf
 * that gets added to sent message
 */
#define MGMTD_BE_CFGDATA_PACKING_EFFICIENCY 0.8
#define MGMTD_BE_CFGDATA_MAX_MSG_LEN                                           \
	(MGMTD_BE_MAX_MSG_LEN * MGMTD_BE_CFGDATA_PACKING_EFFICIENCY)

#define MGMTD_BE_MAX_BATCH_IDS_IN_REQ                                          \
	(MGMTD_BE_MAX_MSG_LEN - 128) / sizeof(uint64_t)

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
 *	notify_cbs: callbacks for notifications.
 *	nnotify_cbs: number of notification callbacks.
 *
 */
struct mgmt_be_client_cbs {
	void (*client_connect_notify)(struct mgmt_be_client *client,
				      uintptr_t usr_data, bool connected);
	void (*subscr_done)(struct mgmt_be_client *client, uintptr_t usr_data,
			    bool success);
	void (*txn_notify)(struct mgmt_be_client *client, uintptr_t usr_data,
			   struct mgmt_be_client_txn_ctx *txn_ctx,
			   bool destroyed);

	const char **notif_xpaths;
	uint nnotif_xpaths;
};

/***************************************************************
 * Global data exported
 ***************************************************************/

extern struct debug mgmt_dbg_be_client;

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

/*
 * Initialize library vty (adds debug support).
 *
 * This call should be added to your component when enabling other vty code to
 * enable mgmtd client debugs. When adding, one needs to also add a their
 * component in `xref2vtysh.py` as well.
 */
extern void mgmt_be_client_lib_vty_init(void);

/*
 * Print enabled debugging commands.
 */
extern void mgmt_debug_be_client_show_debug(struct vty *vty);

/*
 * [Un]-subscribe with MGMTD for one or more YANG subtree(s).
 *
 * client
 *    The client object.
 *
 * reg_yang_xpaths
 *    Yang xpath(s) that needs to be subscribed to
 *
 * num_xpaths
 *    Number of xpaths
 *
 * Returns:
 *    MGMTD_SUCCESS on success, MGMTD_* otherwise.
 */
extern int mgmt_be_send_subscr_req(struct mgmt_be_client *client_ctx,
				   int n_config_xpaths, char **config_xpaths,
				   int n_oper_xpaths, char **oper_xpaths);

/*
 * Destroy backend client and cleanup everything.
 */
extern void mgmt_be_client_destroy(struct mgmt_be_client *client);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MGMTD_BE_CLIENT_H_ */
