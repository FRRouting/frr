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
DEFINE_MTYPE(MGMTD, MGMTD_BE_ADPATER, "backend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_ADPATER, "Frontend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_SESSION, "Frontend Client Session");
DEFINE_MTYPE(MGMTD, MGMTD_TXN, "Trnsction");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_REQ, "Trnsction Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_SETCFG_REQ, "Trnsction Set-Config Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_COMMCFG_REQ, "Trnsction Commit-Config Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REQ, "Trnsction Get-Data Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REPLY, "Trnsction Get-Data Replies");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_CFG_BATCH, "Trnsction Gonfig Batches");
DEFINE_MTYPE(MGMTD, MGMTD_CMT_INFO, "info for tracking commits");
