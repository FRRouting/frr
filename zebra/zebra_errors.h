/*
 * Zebra-specific error messages.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
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

#ifndef __ZEBRA_ERRORS_H__
#define __ZEBRA_ERRORS_H__

#include "lib/ferr.h"

enum zebra_ferr_refs {
	ZEBRA_ERR_LM_RESPONSE = ZEBRA_FERR_START,
	ZEBRA_ERR_LM_NO_SUCH_CLIENT,
	ZEBRA_ERR_LM_RELAY_FAILED,
	ZEBRA_ERR_LM_NO_SOCKET,
	ZEBRA_ERR_LM_BAD_INSTANCE,
	ZEBRA_ERR_LM_RELAY_REQUEST_FAILED,
	ZEBRA_ERR_LM_CLIENT_CONNECTION_FAILED,
	ZEBRA_ERR_LM_EXHAUSTED_LABELS,
	ZEBRA_ERR_LM_DAEMON_MISMATCH,
	ZEBRA_ERR_LM_UNRELEASED_CHUNK,
	ZEBRA_ERR_DP_INVALID_RC,
	ZEBRA_ERR_WQ_NONEXISTENT,
	ZEBRA_ERR_FEC_ADD_FAILED,
	ZEBRA_ERR_FEC_RM_FAILED,
	ZEBRA_ERR_IRDP_LEN_MISMATCH,
	ZEBRA_ERR_RNH_UNKNOWN_FAMILY,
	ZEBRA_ERR_DP_INSTALL_FAIL,
	ZEBRA_ERR_TABLE_LOOKUP_FAILED,
	ZEBRA_ERR_NETLINK_NOT_AVAILABLE,
	ZEBRA_ERR_PROTOBUF_NOT_AVAILABLE,
	ZEBRA_ERR_TM_EXHAUSTED_IDS,
	ZEBRA_ERR_TM_DAEMON_MISMATCH,
	ZEBRA_ERR_TM_UNRELEASED_CHUNK,
	ZEBRA_ERR_UNKNOWN_FAMILY,
	ZEBRA_ERR_TM_WRONG_PROTO,
	ZEBRA_ERR_PROTO_OR_INSTANCE_MISMATCH,
	ZEBRA_ERR_LM_CANNOT_ASSIGN_CHUNK,
	ZEBRA_ERR_LM_ALIENS,
	ZEBRA_ERR_TM_CANNOT_ASSIGN_CHUNK,
	ZEBRA_ERR_TM_ALIENS,
	ZEBRA_ERR_RECVBUF,
	ZEBRA_ERR_UNKNOWN_NLMSG,
	ZEBRA_ERR_RECVMSG_OVERRUN,
	ZEBRA_ERR_NETLINK_LENGTH_ERROR,
	ZEBRA_ERR_UNEXPECTED_MESSAGE,
	ZEBRA_ERR_NETLINK_BAD_SEQUENCE,
	ZEBRA_ERR_BAD_MULTIPATH_NUM,
	ZEBRA_ERR_PREFIX_PARSE_ERROR,
	ZEBRA_ERR_MAC_ADD_FAILED,
	ZEBRA_ERR_VNI_DEL_FAILED,
	ZEBRA_ERR_VTEP_ADD_FAILED,
	ZEBRA_ERR_VNI_ADD_FAILED,
};

void zebra_error_init(void);

#endif /* __ZEBRA_ERRORS_H__ */
