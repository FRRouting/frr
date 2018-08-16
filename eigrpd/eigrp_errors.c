/*
 * EIGRP-specific error messages.
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
#include "eigrp_errors.h"

DEFINE_LOGCAT(EIGRP_ERR_PACKET, ROOT, "EIGRP Packet Error",
	.description = "EIGRP has a packet that does not correctly decode or encode",
	.suggestion = "Gather log files from both sides of the neighbor relationship and open an issue",
)
DEFINE_LOGCAT(EIGRP_ERR_CONFIG, ROOT, "EIGRP Configuration Error",
	.description = "EIGRP has detected a configuration error",
	.suggestion = "Correct the configuration issue, if it still persists open an Issue",
)
