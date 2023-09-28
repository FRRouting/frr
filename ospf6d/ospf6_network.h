// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
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
		if (list_was_empty &&                                          \
		    !list_isempty(oi->area->ospf6->oi_write_q))                \
			event_add_write(master, ospf6_write, oi->area->ospf6,  \
					oi->area->ospf6->fd,                   \
					&oi->area->ospf6->t_write);            \
	} while (0)

#endif /* OSPF6_NETWORK_H */
