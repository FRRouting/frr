/*
 * bgp_errors - header for error messages that may occur in the bgp process
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Don Slice
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __BGP_ERRORS_H__
#define __BGP_ERRORS_H__

#include "ferr.h"
#include "bgp_errors.h"

enum bgp_ferr_refs {

	BGP_ERR_ATTR_FLAG = BGP_FERR_START,
	BGP_ERR_ATTR_LEN,
	BGP_ERR_ATTR_ORIGIN,
	BGP_ERR_ATTR_MAL_AS_PATH,
	BGP_ERR_ATTR_FIRST_AS,
	BGP_ERR_ATTR_MARTIAN_NH,
	BGP_ERR_ATTR_PMSI_TYPE,
	BGP_ERR_ATTR_PMSI_LEN,
	BGP_ERR_ATTR_NH_SEND_LEN,
	BGP_ERR_PEER_GROUP,
	BGP_ERR_PEER_DELETE,
	BGP_ERR_TABLE_CHUNK,
	BGP_ERR_MACIP_LEN,
	BGP_ERR_LM_ERROR,
	BGP_ERR_JSON_MEM_ERROR,
	BGP_ERR_UPDGRP_ATTR_LEN,
	BGP_ERR_UPDGRP_CREATE,
	BGP_ERR_UPDATE_SND,
	BGP_ERR_PKT_OPEN,
	BGP_ERR_SND_FAIL,
	BGP_ERR_INVALID_STATUS,
	BGP_ERR_UPDATE_RCV,
	BGP_ERR_NO_CAP,
	BGP_ERR_NOTIFY_RCV,
	BGP_ERR_KEEP_RCV,
	BGP_ERR_RFSH_RCV,
	BGP_ERR_CAP_RCV,
	BGP_ERR_NH_UPD,
	BGP_ERR_LABEL,
	BGP_ERR_MULTIPATH,
	BGP_ERR_PKT_PROCESS,
	BGP_ERR_CONNECT,
	BGP_ERR_FSM,
	BGP_ERR_VNI,
	BGP_ERR_NO_DFLT,
	BGP_ERR_VTEP_INVALID,
	BGP_ERR_ES_INVALID,
	BGP_ERR_EVPN_ROUTE_DELETE,
	BGP_ERR_EVPN_FAIL,
	BGP_ERR_EVPN_ROUTE_INVALID,
	BGP_ERR_EVPN_ROUTE_CREATE,
	BGP_ERR_ES_CREATE,
	BGP_ERR_MULTI_INSTANCE,
	BGP_ERR_EVPN_AS_MISMATCH,
	BGP_ERR_EVPN_INSTANCE_MISMATCH,
};

extern void bgp_error_init(void);

#endif
