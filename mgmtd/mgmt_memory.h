// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmt memory type declarations
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_MEMORY_H
#define _FRR_MGMTD_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(MGMTD);
DECLARE_MTYPE(MGMTD);
DECLARE_MTYPE(MGMTD_XPATH);
<<<<<<< HEAD
=======
DECLARE_MTYPE(MGMTD_ERR);
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
DECLARE_MTYPE(MGMTD_BE_ADPATER);
DECLARE_MTYPE(MGMTD_FE_ADPATER);
DECLARE_MTYPE(MGMTD_FE_SESSION);
DECLARE_MTYPE(MGMTD_TXN);
DECLARE_MTYPE(MGMTD_TXN_REQ);
DECLARE_MTYPE(MGMTD_TXN_SETCFG_REQ);
DECLARE_MTYPE(MGMTD_TXN_COMMCFG_REQ);
DECLARE_MTYPE(MGMTD_TXN_GETDATA_REQ);
DECLARE_MTYPE(MGMTD_TXN_GETDATA_REPLY);
DECLARE_MTYPE(MGMTD_TXN_GETTREE_REQ);
<<<<<<< HEAD
=======
DECLARE_MTYPE(MGMTD_TXN_RPC_REQ);
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
DECLARE_MTYPE(MGMTD_TXN_CFG_BATCH);
DECLARE_MTYPE(MGMTD_BE_ADAPTER_MSG_BUF);
DECLARE_MTYPE(MGMTD_CMT_INFO);
#endif /* _FRR_MGMTD_MEMORY_H */
