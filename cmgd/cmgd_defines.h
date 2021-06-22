/* CMGD public defines.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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
#include "lib/json.h"
#include "vrf.h"
#include "vty.h"

/* For union sockunion.  */
#include "queue.h"
#include "sockunion.h"
#include "routemap.h"
#include "linklist.h"
#include "defaults.h"
#include "cmgd_memory.h"
#include "bitfield.h"
#include "vxlan.h"
#include "lib/northbound.h"

#define CMGD_CLIENT_NAME_MAX_LEN		32

#define CMGD_BCKND_MSG_MAX_LEN		        4096

#define CMGD_MAX_XPATH_LEN                      XPATH_MAXLEN

#define CMGD_MAX_NUM_XPATH_REG                  128

typedef uintptr_t cmgd_lib_hndl_t;

typedef uintptr_t cmgd_user_data_t;

typedef enum cmgd_result_ {
	CMGD_SUCCESS = 0,
        CMGD_INVALID_PARAM, 
        CMGD_INTERNAL_ERROR,
	CMGD_UNKNOWN_FAILURE
} cmgd_result_t;

typedef uintptr_t cmgd_trxn_id_t;

typedef uintptr_t cmgd_trxn_batch_id_t;

#define GMGD_BCKND_MAX_NUM_REQ_ITEMS    64

typedef enum cmgd_bcknd_req_type_ {
        CMGD_BCKND_REQ_NONE = 0,
        CMGD_BCKND_REQ_CFG_VALIDATE,
        CMGD_BCKND_REQ_CFG_APPLY,
        CMGD_BCKND_REQ_DATA_GET_ELEM,
        CMGD_BCKND_REQ_DATA_GET_NEXT
} cmgd_bcknd_req_type_t;

typedef struct cmgd_bcknd_cfgreq_ {
        cmgd_bcknd_req_type_t req_type;
        struct nb_yang_xpath_elem elems[GMGD_BCKND_MAX_NUM_REQ_ITEMS];
        int num_elems;
} cmgd_bcknd_cfgreq_t;

typedef struct cmgd_bcknd_datareq_ {
        cmgd_bcknd_req_type_t req_type;
        struct nb_yang_xpath xpaths[GMGD_BCKND_MAX_NUM_REQ_ITEMS];
        int num_xpaths;
} cmgd_bcknd_datareq_t;

typedef struct cmgd_bcknd_dataresult_ {
        cmgd_bcknd_req_type_t req_type;
        struct nb_yang_xpath_elem elems[GMGD_BCKND_MAX_NUM_REQ_ITEMS];
        int num_elems;
        int next_data_indx;
} cmgd_bcknd_dataresult_t;

#endif /* _FRR_CMGD_DEFINES_H */
