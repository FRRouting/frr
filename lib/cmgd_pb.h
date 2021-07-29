/*
 * CMGD protobuf main header file
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

#ifndef _FRR_CMGD_PB_H_
#define _FRR_CMGD_PB_H_

#include "lib/cmgd.pb-c.h"

typedef Cmgd__YangDataXPath cmgd_yang_xpath_t;
#define cmgd_yang_data_xpath_init(ptr) cmgd__yang_data_xpath__init(ptr)

typedef Cmgd__YangDataValue cmgd_yang_data_value_t;
#define cmgd_yang_data_value_init(ptr) cmgd__yang_data_value__init(ptr)

typedef Cmgd__YangData cmgd_yang_data_t;
#define cmgd_yang_data_init(ptr) cmgd__yang_data__init(ptr)

typedef Cmgd__YangDataReply cmgd_yang_data_reply_t;
#define cmgd_yang_data_reply_init(ptr) cmgd__yang_data_reply__init(ptr)

typedef Cmgd__YangCfgDataReq cmgd_yang_cfgdata_req_t;
#define cmgd_yang_cfg_data_req_init(ptr) cmgd__yang_cfg_data_req__init(ptr)

typedef Cmgd__YangGetDataReq cmgd_yang_getdata_req_t;
#define cmgd_yang_get_data_req_init(ptr) cmgd__yang_get_data_req__init(ptr)

#endif /* _FRR_CMGD_PB_H_ */
