/*
 * Zebra NS collector and notifier for Network NameSpaces
 * Copyright (C) 2017 6WIND
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

#ifndef _NETNS_NOTIFY_H
#define _NETNS_NOTIFY_H

extern void zebra_ns_notify_init(void);
extern void zebra_ns_notify_parse(void);
extern void zebra_ns_notify_close(void);

extern struct zebra_privs_t zserv_privs;

#endif /* NETNS_NOTIFY_H */
