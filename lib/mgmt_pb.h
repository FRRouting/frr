/*
 * MGMTD protobuf main header file
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
