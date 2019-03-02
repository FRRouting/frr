/*
 * OSPF-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *		Chirag Shah
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

#ifndef __OSPF_ERRORS_H__
#define __OSPF_ERRORS_H__

#include "lib/ferr.h"

enum ospf_log_refs {
	EC_OSPF_PKT_PROCESS = OSPF_FERR_START,
	EC_OSPF_ROUTER_LSA_MISMATCH,
	EC_OSPF_DOMAIN_CORRUPT,
	EC_OSPF_INIT_FAIL,
	EC_OSPF_SR_INVALID_DB,
	EC_OSPF_SR_NODE_CREATE,
	EC_OSPF_SR_INVALID_LSA_ID,
	EC_OSPF_INVALID_ALGORITHM,
	EC_OSPF_FSM_INVALID_STATE,
	EC_OSPF_SET_METRIC_PLUS,
	EC_OSPF_MD5,
	EC_OSPF_PACKET,
	EC_OSPF_LARGE_LSA,
	EC_OSPF_LSA_UNEXPECTED,
	EC_OSPF_LSA,
	EC_OSPF_OPAQUE_REGISTRATION,
	EC_OSPF_TE_UNEXPECTED,
	EC_OSPF_LSA_INSTALL_FAILURE,
	EC_OSPF_LSA_NULL,
	EC_OSPF_EXT_LSA_UNEXPECTED,
	EC_OSPF_LSA_MISSING,
	EC_OSPF_PTP_NEIGHBOR,
	EC_OSPF_LSA_SIZE,
	EC_OSPF_LARGE_HELLO,
};

extern void ospf_error_init(void);

#endif
