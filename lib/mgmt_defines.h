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

enum mgmt_result {
	MGMTD_SUCCESS = 0,
	MGMTD_INVALID_PARAM,
	MGMTD_INTERNAL_ERROR,
	MGMTD_VALIDATION_ERROR,
	MGMTD_NO_CFG_CHANGES,
	MGMTD_DS_LOCK_FAILED,
	MGMTD_DS_UNLOCK_FAILED,
	MGMTD_UNKNOWN_FAILURE
};

enum mgmt_ds_id {
	MGMTD_DS_NONE,
	MGMTD_DS_RUNNING,
	MGMTD_DS_CANDIDATE,
	MGMTD_DS_OPERATIONAL,
};
#define MGMTD_DS_MAX_ID (MGMTD_DS_OPERATIONAL + 1)

#endif /* _FRR_MGMTD_DEFINES_H */
