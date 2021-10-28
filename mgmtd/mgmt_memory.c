/* mgmt memory type definitions
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

#include <zebra.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mgmt_memory.h"

/* this file is temporary in nature;  definitions should be moved to the
 * files they're used in
 */

DEFINE_MGROUP(MGMTD, "mgmt");
DEFINE_MTYPE(MGMTD, MGMTD, "MGMTD instance");
DEFINE_MTYPE(MGMTD, MGMTD_BE_ADPATER, "MGMTD backend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_ADPATER, "MGMTD Frontend adapter");
DEFINE_MTYPE(MGMTD, MGMTD_FE_SESSION, "MGMTD Frontend Client Session");
DEFINE_MTYPE(MGMTD, MGMTD_TXN, "MGMTD Transaction");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_REQ, "MGMTD Transaction Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_SETCFG_REQ,
	     "MGMTD Transaction Set-Config Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_COMMCFG_REQ,
	     "MGMTD Transaction Commit-Config Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REQ,
	     "MGMTD Transaction Get-Data Requests");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_GETDATA_REPLY,
	     "MGMTD Transaction Get-Data Replies");
DEFINE_MTYPE(MGMTD, MGMTD_TXN_CFG_BATCH, "MGMTD Transaction Gonfig Batches");
DEFINE_MTYPE(MGMTD, MGMTD_CMT_INFO, "MGMTD commit info for tracking commits");
