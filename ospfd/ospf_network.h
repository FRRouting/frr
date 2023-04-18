// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF network related functions.
 *   Copyright (C) 1999 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_NETWORK_H
#define _ZEBRA_OSPF_NETWORK_H

/* Prototypes. */
extern int ospf_if_add_allspfrouters(struct ospf *, struct prefix *, ifindex_t);
extern int ospf_if_drop_allspfrouters(struct ospf *, struct prefix *,
				      ifindex_t);
extern int ospf_if_add_alldrouters(struct ospf *, struct prefix *, ifindex_t);
extern int ospf_if_drop_alldrouters(struct ospf *, struct prefix *, ifindex_t);
extern int ospf_if_ipmulticast(int fd, struct prefix *, ifindex_t);
extern int ospf_sock_init(struct ospf *ospf);
/* Open, close per-interface write socket */
int ospf_ifp_sock_init(struct interface *ifp);
int ospf_ifp_sock_close(struct interface *ifp);

enum ospf_sock_type_e {
	OSPF_SOCK_NONE = 0,
	OSPF_SOCK_RECV,
	OSPF_SOCK_SEND,
	OSPF_SOCK_BOTH
};

void ospf_sock_bufsize_update(const struct ospf *ospf, int sock,
			      enum ospf_sock_type_e type);

#endif /* _ZEBRA_OSPF_NETWORK_H */
