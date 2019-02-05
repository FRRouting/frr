/* Header file exported by if_netlink.c to zebra.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#ifndef _ZEBRA_IF_NETLINK_H
#define _ZEBRA_IF_NETLINK_H

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif

extern int netlink_interface_addr(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);
extern int netlink_link_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);
extern int interface_lookup_netlink(struct zebra_ns *zns);

/*
 * Set protodown status of interface.
 *
 * ifp
 *    Interface to set protodown on.
 *
 * down
 *    If true, set protodown on. If false, set protodown off.
 *
 * Returns:
 *    0
 */
int netlink_protodown(struct interface *ifp, bool down);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_IF_NETLINK_H */
