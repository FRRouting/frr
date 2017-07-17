/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#ifndef OSPF6_NETWORK_H
#define OSPF6_NETWORK_H

extern int ospf6_sock;
extern struct in6_addr allspfrouters6;
extern struct in6_addr alldrouters6;

extern int ospf6_serv_sock(void);
extern int ospf6_sso(ifindex_t ifindex, struct in6_addr *group, int option);

extern int ospf6_sendmsg(struct in6_addr *, struct in6_addr *, ifindex_t *,
			 struct iovec *);
extern int ospf6_recvmsg(struct in6_addr *, struct in6_addr *, ifindex_t *,
			 struct iovec *);

#endif /* OSPF6_NETWORK_H */
