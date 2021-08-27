/* CMGD public defines.
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

#ifndef _FRR_CMGD_DEFINES_H
#define _FRR_CMGD_DEFINES_H

#include <pthread.h>

#include "hook.h"
#include "frr_pthread.h"
// #include "lib/json.h"
// #include "vrf.h"
// #include "vty.h"

/* For union sockunion.  */
#include "queue.h"
#include "sockunion.h"
// #include "routemap.h"
#include "linklist.h"
#include "defaults.h"
#include "cmgd_memory.h"
#include "bitfield.h"
// #include "vxlan.h"
#include "lib/northbound.h"
#include "lib/cmgd_pb.h"

#define CMGD_CLIENT_NAME_MAX_LEN		32

#define CMGD_MAX_XPATH_LEN                      XPATH_MAXLEN

#define CMGD_MAX_NUM_XPATH_REG                  128

#define CMGD_MAX_NUM_DATA_REQ_IN_BATCH		32
#define CMGD_MAX_NUM_DATA_REPLY_IN_BATCH	8

#define CMGD_MAX_CFG_CHANGES_IN_BATCH		10

/*
 * The following packs a buffer of size MAX_PKT_SIZE with multiple 
 * messages to minimize number of mallocs and number of write() 
 * calls.
 */
#define CMGD_PACK_TX_MSGS

typedef uintptr_t cmgd_lib_hndl_t;

typedef uintptr_t cmgd_user_data_t;

typedef enum cmgd_result_ {
	CMGD_SUCCESS = 0,
        CMGD_INVALID_PARAM, 
        CMGD_INTERNAL_ERROR,
	CMGD_UNKNOWN_FAILURE
} cmgd_result_t;

typedef enum cmgd_event_ {
	CMGD_BCKND_SERVER = 1,
	CMGD_BCKND_CONN_READ,
	CMGD_BCKND_CONN_WRITE,
	CMGD_BCKND_CONN_WRITES_ON,
	CMGD_BCKND_PROC_MSG,
	CMGD_FRNTND_SERVER,
	CMGD_FRNTND_CONN_READ,
	CMGD_FRNTND_CONN_WRITE,
	CMGD_FRNTND_CONN_WRITES_ON,
	CMGD_FRNTND_PROC_MSG
} cmgd_event_t;

typedef uintptr_t cmgd_trxn_id_t;
#define CMGD_TRXN_ID_NONE	0

typedef uintptr_t cmgd_trxn_batch_id_t;
#define CMGD_TRXN_BATCH_ID_NONE	0

#endif /* _FRR_CMGD_DEFINES_H */
