/*
 * Library-specific error messages.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Donald Sharp
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

#ifndef __LIB_ERRORS_H__
#define __LIB_ERRORS_H__

#include "lib/ferr.h"

enum lib_log_refs {
	EC_LIB_PRIVILEGES = LIB_FERR_START,
	EC_LIB_VRF_START,
	EC_LIB_SOCKET,
	EC_LIB_ZAPI_MISSMATCH,
	EC_LIB_ZAPI_ENCODE,
	EC_LIB_ZAPI_SOCKET,
	EC_LIB_SYSTEM_CALL,
	EC_LIB_VTY,
	EC_LIB_INTERFACE,
	EC_LIB_NS,
	EC_LIB_DEVELOPMENT,
	EC_LIB_ZMQ,
	EC_LIB_UNAVAILABLE,
	EC_LIB_SNMP,
	EC_LIB_STREAM,
	EC_LIB_LINUX_NS,
	EC_LIB_SLOW_THREAD,
	EC_LIB_RMAP_RECURSION_LIMIT,
	EC_LIB_BACKUP_CONFIG,
	EC_LIB_VRF_LENGTH,
};

extern void lib_error_init(void);

#endif
