// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * November 17 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_txn.h"
#include "queue.h"

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_txn, "TXN: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_warn(fmt, ...) zlog_warn("%s: WARNING: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define TXN_INCREF(txn) txn_incref(txn, __FILE__, __LINE__)
#define TXN_DECREF(txn) txn_decref(txn, __FILE__, __LINE__)

/* ----------------- */
/* Txn Private Types */
/* ----------------- */

enum txn_req_type {
	TXN_REQ_TYPE_COMMIT = 1,
	TXN_REQ_TYPE_GETTREE,
	TXN_REQ_TYPE_RPC,
};

struct txn_req {
	TAILQ_ENTRY(txn_req) link;
	enum txn_req_type req_type;
	uint64_t req_id;
	struct mgmt_txn *txn;
	int16_t error;	       /* cfg: MGMTD return code, else errno */
	char *err_info;	       /* darr str */
	struct event *timeout; /* for timing out the request */
};
#define as_txn_req(xreq) (&(xreq)->req) /* Macro to coerce specific req back into txn_req */

struct mgmt_txn {
	TAILQ_ENTRY(mgmt_txn) link;
	enum mgmt_txn_type type;
	uint64_t txn_id;
	int refcount;
	uint64_t session_id; /* One transaction per client session */
	/* List of pending requests */
	TAILQ_HEAD(txn_req_head, txn_req) reqs;
};

/* ---------------------------- */
/* TXN Private Config Functions */
/* ---------------------------- */

extern void txn_cfg_cleanup(struct txn_req *txn_req);
extern void txn_cfg_handle_error(struct txn_req *txn_req, struct mgmt_be_client_adapter *adapter,
				 int error, const char *errstr);
extern int txn_cfg_be_client_connect(struct mgmt_be_client_adapter *adapter);
extern void txn_cfg_txn_be_client_disconnect(struct mgmt_txn *txn,
					     struct mgmt_be_client_adapter *adapter);
/* ---------------------------- */
/* TXN Private Shared Functions */
/* ---------------------------- */

extern struct txn_req *txn_req_alloc(struct mgmt_txn *txn, uint64_t req_id,
				     enum txn_req_type req_type, size_t size);
extern void txn_req_free(struct txn_req *txn_req);
extern struct mgmt_txn *txn_create(enum mgmt_txn_type type);
extern void mgmt_txn_cleanup_txn(struct mgmt_txn **txn);
extern struct mgmt_txn *txn_lookup(uint64_t txn_id);
extern void txn_decref(struct mgmt_txn *txn, const char *file, int line);

extern struct event_loop *mgmt_txn_tm;

/* ------------------- */
/* TXN Private Globals */
/* ------------------- */

extern struct event_loop *mgmt_txn_tm;
extern struct mgmt_master *mgmt_txn_mm;
