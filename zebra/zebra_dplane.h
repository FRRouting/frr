/*
 * Zebra dataplane layer api interfaces.
 * Copyright (c) 2018 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_DPLANE_H
#define _ZEBRA_DPLANE_H 1

#include "zebra.h"
#include "zserv.h"
#include "prefix.h"
#include "nexthop.h"
#include "nexthop_group.h"


/*
 * API between the zebra dataplane system and the main zebra processing
 * context.
 */

/*
 * Enqueue a route install or update for the dataplane.
 */

/*
 * Enqueue a route removal for the dataplane.
 */

/*
 * Result codes used when returning status back to the main zebra context.
 */

/*
 * Philosophy Note:
 *
 * Flags being SET/UNSET do not belong in the South Bound
 * Interface.  This Setting belongs at the calling level
 * because we can and will have multiple different interfaces
 * and we will have potentially multiple different
 * modules/filters to call.  As such Setting/Unsetting
 * success failure should be handled by the caller.
 */
enum zebra_dplane_status {
	ZEBRA_DPLANE_STATUS_NONE = 0,
	ZEBRA_DPLANE_INSTALL_SUCCESS,
	ZEBRA_DPLANE_INSTALL_FAILURE,
	ZEBRA_DPLANE_DELETE_SUCCESS,
	ZEBRA_DPLANE_DELETE_FAILURE,

};

enum zebra_dplane_result {
	ZEBRA_DPLANE_REQUEST_QUEUED,
	ZEBRA_DPLANE_REQUEST_SUCCESS,
	ZEBRA_DPLANE_REQUEST_FAILURE,
};

#endif	/* _ZEBRA_DPLANE_H */
