/*
 * Zebra Traffic Control (TC) interaction with the kernel using socket.
 *
 * Copyright (C) 2022 Shichu Yang
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

#ifndef HAVE_NETLINK

#include "lib_errors.h"

#include "zebra/rt.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_tc.h"

enum zebra_dplane_result kernel_tc_update(struct zebra_dplane_ctx *ctx)
{
	flog_err(EC_LIB_UNAVAILABLE, "%s not Implemented for this platform",
		 __func__);
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

#endif /* !HAVE_NETLINK */
