// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD public defines.
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_DEFINES_H
#define _FRR_MGMTD_DEFINES_H

#include "yang.h"

#define MGMTD_CLIENT_NAME_MAX_LEN 32

#define MGMTD_MAX_XPATH_LEN XPATH_MAXLEN

#define MGMTD_MAX_YANG_VALUE_LEN YANG_VALUE_MAXLEN

enum mgmt_result {
	MGMTD_SUCCESS = 0,
	MGMTD_INVALID_PARAM,
	MGMTD_INTERNAL_ERROR,
	MGMTD_NO_CFG_CHANGES,
	MGMTD_DS_LOCK_FAILED,
	MGMTD_DS_UNLOCK_FAILED,
	MGMTD_UNKNOWN_FAILURE
};

enum mgmt_fe_event {
	MGMTD_FE_SERVER = 1,
	MGMTD_FE_CONN_READ,
	MGMTD_FE_CONN_WRITE,
	MGMTD_FE_CONN_WRITES_ON,
	MGMTD_FE_PROC_MSG
};

#define MGMTD_TXN_ID_NONE 0

#endif /* _FRR_MGMTD_DEFINES_H */
