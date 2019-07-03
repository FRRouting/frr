/**
 * bfd_tracking.h: BFD Tracking header file
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

#ifndef _BFD_TRACKING_H
#define _BFD_TRACKING_H
#include "hook.h"
#include "nexthop.h"

DECLARE_HOOK(bfd_tracking_notify_filename,
	     (const struct bfd_session *pm),
	     (pm));

DECLARE_HOOK(bfd_tracking_release_session,
	     (const struct bfd_session *pm),
	     (pm));

DECLARE_HOOK(bfd_tracking_new_session,
	     (const struct bfd_session *pm),
	     (pm));

DECLARE_HOOK(bfd_tracking_set_notify_string,
	     (const struct bfd_session *bs,
	      const char *notify_string),
	     (bs, notify_string));

DECLARE_HOOK(bfd_tracking_show_notify_string,
	     (struct vty *vty, const char *notify_string),
	     (vty, notify_string));

DECLARE_HOOK(bfd_tracking_set_label_string,
	     (const struct bfd_session *bs,
	      const char *label_string),
	     (bs, label_string));

DECLARE_HOOK(bfd_tracking_show_label_string,
	     (struct vty *vty, const char *label_string),
	     (vty, label_string));

DECLARE_HOOK(bfd_tracking_show_extra_info,
	     (const struct bfd_session *bs,
	      struct vty *vty,
	      struct json_object *jo),
	     (bs, vty, jo));

#endif /* _BFD_TRACKING_H */
