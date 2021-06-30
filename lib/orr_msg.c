/*
 * Handling routines for BGP Optimal Route Reflection
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
 * 			Madhurilatha Kuruganti
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

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "thread.h"
#include "stream.h"
#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "orr_msg.h"

/* Library code */
DEFINE_MTYPE_STATIC(LIB, ORR_MSG_INFO, "ORR Msg info");

/*
 * orr_msg_info_create - Allocate the ORR_MSG information
 */
