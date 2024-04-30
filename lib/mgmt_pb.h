// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD protobuf main header file
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_PB_H_
#define _FRR_MGMTD_PB_H_

#include "lib/mgmt.pb-c.h"

#define mgmt_yang_data_xpath_init(ptr) mgmtd__yang_data_xpath__init(ptr)

#define mgmt_yang_data_value_init(ptr) mgmtd__yang_data_value__init(ptr)

#define mgmt_yang_data_init(ptr) mgmtd__yang_data__init(ptr)

#define mgmt_yang_data_reply_init(ptr) mgmtd__yang_data_reply__init(ptr)

#define mgmt_yang_cfg_data_req_init(ptr) mgmtd__yang_cfg_data_req__init(ptr)

#define mgmt_yang_get_data_req_init(ptr) mgmtd__yang_get_data_req__init(ptr)

#endif /* _FRR_MGMTD_PB_H_ */
