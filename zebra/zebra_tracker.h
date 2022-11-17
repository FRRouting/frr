/*
 * Zebra Tracker library
 *
 * Copyright 2022 6WIND S.A.
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

#ifndef __ZEBRA_TRACKER_H__
#define __ZEBRA_TRACKER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TRACKER_NAME_SIZE 32
#define TRACKER_FILEPATTERN_SIZE 32

void cli_show_tracker(struct vty *vty, struct lyd_node *dnode,
		      bool show_defaults __attribute__((__unused__)));
extern void zebra_tracker_init(void);


#ifdef __cplusplus
}
#endif

#endif /*__ZEBRA_TRACKER_H__ */
