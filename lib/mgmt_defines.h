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

#define MGMTD_FE_SOCK_NAME "%s/mgmtd_fe.sock", frr_runstatedir
#define MGMTD_BE_SOCK_NAME "%s/mgmtd_be.sock", frr_runstatedir

#define MGMTD_CLIENT_NAME_MAX_LEN 32

#define MGMTD_MAX_XPATH_LEN XPATH_MAXLEN

#define MGMTD_MAX_YANG_VALUE_LEN YANG_VALUE_MAXLEN

#define MGMTD_MAX_NUM_XPATH_REG 128

#define MGMTD_MAX_NUM_DATA_REQ_IN_BATCH 32
#define MGMTD_MAX_NUM_DATA_REPLY_IN_BATCH 8

enum mgmt_result {
	MGMTD_SUCCESS = 0,
	MGMTD_INVALID_PARAM,
	MGMTD_INTERNAL_ERROR,
	MGMTD_NO_CFG_CHANGES,
	MGMTD_DS_LOCK_FAILED,
	MGMTD_DS_UNLOCK_FAILED,
	MGMTD_UNKNOWN_FAILURE
};

#endif /* _FRR_MGMTD_DEFINES_H */
