// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmt memory type definitions
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mgmt_memory.h"

/* this file is temporary in nature;  definitions should be moved to the
 * files they're used in
 */

DEFINE_MGROUP(MGMTD, "mgmt");
DEFINE_MTYPE(MGMTD, MGMTD, "instance");
DEFINE_MTYPE(MGMTD, MGMTD_XPATH, "xpath regex");
DEFINE_MTYPE(MGMTD, MGMTD_BE_ADPATER, "backend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_ADPATER, "frontend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_SESSION, "frontend session");
DEFINE_MTYPE(MGMTD, MGMTD_TXN, "txn");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_REQ, "txn request");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_SETCFG_REQ, "txn set-config requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_COMMCFG_REQ, "txn commit-config requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REQ, "txn get-data requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REPLY, "txn get-data replies");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETTREE_REQ, "txn get-tree requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_CFG_BATCH, "txn config batches");
DEFINE_MTYPE(MGMTD, MGMTD_CMT_INFO, "commit info");
