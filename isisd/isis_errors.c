/*
 * ISIS-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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

#include <zebra.h>

#include "lib/ferr.h"
#include "isis_errors.h"

DEFINE_LOGCAT(ISIS_ERR_PACKET, ROOT, "ISIS Packet Error",
	.description = "Isis has detected an error with a packet from a peer",
	.suggestion = "Gather log information and open an issue then restart FRR",
)
DEFINE_LOGCAT(ISIS_ERR_CONFIG, ROOT, "ISIS Configuration Error",
	.description = "Isis has detected an error within configuration for the router",
	.suggestion = "Ensure configuration is correct",
)
