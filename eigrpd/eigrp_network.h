// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Network Related Functions.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 */

#ifndef _ZEBRA_EIGRP_NETWORK_H
#define _ZEBRA_EIGRP_NETWORK_H

/* Prototypes */

extern int eigrp_sock_init(struct vrf *vrf);
extern int eigrp_if_ipmulticast(struct eigrp *, struct prefix *, unsigned int);
extern int eigrp_network_set(struct eigrp *eigrp, struct prefix *p);
extern int eigrp_network_unset(struct eigrp *eigrp, struct prefix *p);

extern void eigrp_hello_timer(struct event *thread);
extern void eigrp_if_update(struct interface *);
extern int eigrp_if_add_allspfrouters(struct eigrp *, struct prefix *,
				      unsigned int);
extern int eigrp_if_drop_allspfrouters(struct eigrp *top, struct prefix *p,
				       unsigned int ifindex);
extern void eigrp_adjust_sndbuflen(struct eigrp *, unsigned int);

extern void eigrp_external_routes_refresh(struct eigrp *, int);

#endif /* EIGRP_NETWORK_H_ */
