/*
 * PIM-specific error messages.
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
#include "pim_errors.h"

DEFINE_LOGCAT(PIM_ERR_MSDP_PACKET, ROOT, "PIM MSDP Packet Error",
	.description = "PIM has received a packet from a peer that does not correctly decode",
	.suggestion = "Check MSDP peer and ensure it is correctly working",
)
DEFINE_LOGCAT(PIM_ERR_CONFIG, ROOT, "PIM Configuration Error",
	.description = "PIM has detected a configuration error",
	.suggestion = "Ensure the configuration is correct and apply correct configuration",
)
