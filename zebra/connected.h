/*
 * Interface's address and mask.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_CONNECTED_H
#define _ZEBRA_CONNECTED_H

extern struct connected *connected_check(struct interface *ifp,
					 struct prefix *p);

extern void connected_add_ipv4(struct interface *ifp, int flags,
			       struct in_addr *addr, u_char prefixlen,
			       struct in_addr *broad, const char *label);

extern void connected_delete_ipv4(struct interface *ifp, int flags,
				  struct in_addr *addr, u_char prefixlen,
				  struct in_addr *broad);

extern void connected_delete_ipv4_unnumbered(struct connected *ifc);

extern void connected_up_ipv4(struct interface *, struct connected *);
extern void connected_down_ipv4(struct interface *, struct connected *);

extern void connected_add_ipv6(struct interface *ifp, int flags,
			       struct in6_addr *address, u_char prefixlen,
			       struct in6_addr *broad, const char *label);
extern void connected_delete_ipv6(struct interface *ifp,
				  struct in6_addr *address, u_char prefixlen,
				  struct in6_addr *broad);

extern void connected_up_ipv6(struct interface *, struct connected *);
extern void connected_down_ipv6(struct interface *ifp, struct connected *);

extern int connected_is_unnumbered(struct interface *);

#endif /*_ZEBRA_CONNECTED_H */
