/**
 * pm_tracking.h: PM Tracking header file
 *
 * Copyright 2019 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PM_TRACKING_H
#define _PM_TRACKING_H
#include "hook.h"
#include "nexthop.h"

DECLARE_HOOK(pm_tracking_update_param,
	     (struct pm_session *pm),
	     (pm));

DECLARE_HOOK(pm_tracking_notify_filename,
	     (struct pm_session *pm),
	     (pm));

DECLARE_HOOK(pm_tracking_write_config,
	     (struct pm_session *pm, struct vty *vty),
	     (pm, vty));

DECLARE_HOOK(pm_tracking_release_session,
	     (struct pm_session *pm),
	     (pm));

DECLARE_HOOK(pm_tracking_new_session,
	     (struct pm_session *pm),
	     (pm));

DECLARE_HOOK(pm_tracking_get_dest_address,
	     (struct pm_session *pm,
	      union sockunion *peer),
	     (pm, peer));

DECLARE_HOOK(pm_tracking_get_gateway_address,
	     (struct pm_session *pm,
	      union sockunion *gw),
	     (pm, gw));

DECLARE_HOOK(pm_tracking_display,
	     (struct pm_session *pm, struct vty *vty,
	      struct json_object *jo),
	     (pm, vty, jo));

DECLARE_HOOK(pm_tracking_check_param,
	     (struct pm_session *pm,
	      int *ret,
	      void (*callback)(struct vty *, struct pm_session *)),
	     (pm, ret, callback));

#endif /* _PM_TRACKING_H */
