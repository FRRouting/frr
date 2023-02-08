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
extern int ospf_if_ipmulticast(struct ospf *, struct prefix *, ifindex_t);
extern int ospf_sock_init(struct ospf *ospf);

#endif /* _ZEBRA_OSPF_NETWORK_H */
