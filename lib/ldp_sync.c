/*
 * ldp_sync.c: LDP-SYNC handling routines
 * Copyright (C) 2020 Volta Networks, Inc.
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
#include "ldp_sync.h"

/* Library code */
DEFINE_MTYPE_STATIC(LIB, LDP_SYNC_INFO, "LDP SYNC info");

/*
 * ldp_sync_info_create - Allocate the LDP_SYNC information
 */
struct ldp_sync_info *ldp_sync_info_create(void)
{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = XCALLOC(MTYPE_LDP_SYNC_INFO,
				sizeof(struct ldp_sync_info));
	assert(ldp_sync_info);

	ldp_sync_info->flags = 0;
	ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
	ldp_sync_info->t_holddown = NULL;
	return ldp_sync_info;
}

/*
 * ldp_sync_info_free - Free the LDP_SYNC information.
 */
void ldp_sync_info_free(struct ldp_sync_info **ldp_sync_info)
{
	if (*ldp_sync_info)
		XFREE(MTYPE_LDP_SYNC_INFO, *ldp_sync_info);
}

bool ldp_sync_if_is_enabled(struct ldp_sync_info *ldp_sync_info)
{
	/* return true if LDP-SYNC is configured on this interface */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state == LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP)
		return true;

	return false;
}

bool ldp_sync_if_down(struct ldp_sync_info *ldp_sync_info)
{
	/* Stop LDP-SYNC on this interface:
	 *   if holddown timer is running stop it
	 *   update state
	 */
	if (ldp_sync_info && ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED) {
		THREAD_OFF(ldp_sync_info->t_holddown);

		if (ldp_sync_info->state == LDP_IGP_SYNC_STATE_REQUIRED_UP)
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		return true;
	}

	return false;
}
