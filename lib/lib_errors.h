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

enum lib_ferr_refs {
	LIB_ERR_PRIVILEGES = LIB_FERR_START,
	LIB_ERR_VRF_START,
	LIB_ERR_SOCKET,
	LIB_ERR_ZAPI_MISSMATCH,
	LIB_ERR_ZAPI_ENCODE,
	LIB_ERR_ZAPI_SOCKET,
	LIB_ERR_SYSTEM_CALL,
	LIB_ERR_VTY,
	LIB_ERR_SNMP,
	LIB_ERR_INTERFACE,
	LIB_ERR_NS,
	LIB_ERR_DEVELOPMENT,
	LIB_ERR_ZMQ,
	LIB_ERR_UNAVAILABLE,
};

extern void lib_error_init(void);

#endif
