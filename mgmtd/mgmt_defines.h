/* MGMTD public defines.
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

#ifndef _FRR_MGMTD_DEFINES_H
#define _FRR_MGMTD_DEFINES_H

#include "lib/mgmt_pb.h"

#define MGMTD_CLIENT_NAME_MAX_LEN 32

#define MGMTD_MAX_XPATH_LEN XPATH_MAXLEN

#define MGMTD_MAX_YANG_VALUE_LEN YANG_VALUE_MAXLEN

enum mgmt_result {
	MGMTD_SUCCESS = 0,
	MGMTD_INVALID_PARAM,
	MGMTD_INTERNAL_ERROR,
	MGMTD_NO_CFG_CHANGES,
	MGMTD_DB_LOCK_FAILED,
	MGMTD_DB_UNLOCK_FAILED,
	MGMTD_UNKNOWN_FAILURE
};

enum mgmt_frntnd_event {
	MGMTD_FRNTND_SERVER = 1,
	MGMTD_FRNTND_CONN_READ,
	MGMTD_FRNTND_CONN_WRITE,
	MGMTD_FRNTND_CONN_WRITES_ON,
	MGMTD_FRNTND_PROC_MSG
};

#define MGMTD_TRXN_ID_NONE 0

#endif /* _FRR_MGMTD_DEFINES_H */
