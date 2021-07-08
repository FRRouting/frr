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

extern struct in6_addr allspfrouters6;
extern struct in6_addr alldrouters6;

extern int ospf6_serv_sock(struct ospf6 *ospf6);
extern void ospf6_serv_close(int *ospf6_sock);
extern int ospf6_sso(ifindex_t ifindex, struct in6_addr *group, int option,
		     int sockfd);

extern int ospf6_sendmsg(struct in6_addr *src, struct in6_addr *dst,
			 ifindex_t ifindex, struct iovec *message,
			 int ospf6_sock);
extern int ospf6_recvmsg(struct in6_addr *src, struct in6_addr *dst,
			 ifindex_t *ifindex, struct iovec *message,
			 int ospf6_sock);

#define OSPF6_MESSAGE_WRITE_ON(oi)                                             \
	do {                                                                   \
		bool list_was_empty =                                          \
			list_isempty(oi->area->ospf6->oi_write_q);             \
		if ((oi)->on_write_q == 0) {                                   \
			listnode_add(oi->area->ospf6->oi_write_q, (oi));       \
			(oi)->on_write_q = 1;                                  \
		}                                                              \
		if (list_was_empty                                             \
		    && !list_isempty(oi->area->ospf6->oi_write_q))             \
			thread_add_write(master, ospf6_write, oi->area->ospf6, \
					 oi->area->ospf6->fd,                  \
					 &oi->area->ospf6->t_write);           \
	} while (0)

#endif /* OSPF6_NETWORK_H */
