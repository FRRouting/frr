/* cmgd memory type definitions
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cmgd_memory.h"

/* this file is temporary in nature;  definitions should be moved to the
 * files they're used in */

DEFINE_MGROUP(CMGD, "cmgd");
DEFINE_MTYPE(CMGD, CMGD, "CMGD instance");
DEFINE_MTYPE(CMGD, CMGD_BCKND_ADPATER, "CMGD backend adapter");
DEFINE_MTYPE(CMGD, CMGD_FRNTND_ADPATER, "CMGD Frontend adapter");
DEFINE_MTYPE(CMGD, CMGD_FRNTND_SESSN, "CMGD Frontend Client Session");
DEFINE_MTYPE(CMGD, CMGD_TRXN, "CMGD Transaction");
DEFINE_MTYPE(CMGD, CMGD_TRXN_REQ, "CMGD Transaction Requests");
DEFINE_MTYPE(CMGD, CMGD_TRXN_SETCFG_REQ, "CMGD Transaction Set-Config Requests");
DEFINE_MTYPE(CMGD, CMGD_TRXN_COMMCFG_REQ, "CMGD Transaction Commit-Config Requests");
DEFINE_MTYPE(CMGD, CMGD_TRXN_GETDATA_REQ, "CMGD Transaction Get-Data Requests");
DEFINE_MTYPE(CMGD, CMGD_TRXN_GETDATA_REPLY, "CMGD Transaction Get-Data Replies");
DEFINE_MTYPE(CMGD, CMGD_TRXN_CFG_BATCH, "CMGD Transaction Gonfig Batches");
DEFINE_MTYPE(CMGD, CMGD_BCKND_ADPTR_MSG_BUF, "CMGD Backend Send/Revc Buffer");
