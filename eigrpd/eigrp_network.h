/*
 * EIGRP Network Related Functions.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#ifndef _ZEBRA_EIGRP_NETWORK_H
#define _ZEBRA_EIGRP_NETWORK_H

/* Prototypes */

extern int eigrp_sock_init(void);
extern int eigrp_if_ipmulticast(struct eigrp *, struct prefix *, unsigned int);
extern int eigrp_network_set(struct eigrp *eigrp, struct prefix *p);
extern int eigrp_network_unset(struct eigrp *eigrp, struct prefix *p);

extern int eigrp_hello_timer(struct thread *);
extern void eigrp_if_update(struct interface *);
extern int eigrp_if_add_allspfrouters(struct eigrp *, struct prefix *,
				      unsigned int);
extern int eigrp_if_drop_allspfrouters(struct eigrp *top, struct prefix *p,
				       unsigned int ifindex);
extern void eigrp_adjust_sndbuflen(struct eigrp *, unsigned int);

extern uint32_t eigrp_calculate_metrics(struct eigrp *, struct eigrp_metrics);
extern uint32_t eigrp_calculate_total_metrics(struct eigrp *,
					      struct eigrp_nexthop_entry *);
extern uint8_t eigrp_metrics_is_same(struct eigrp_metrics,
				     struct eigrp_metrics);
extern void eigrp_external_routes_refresh(struct eigrp *, int);

#endif /* EIGRP_NETWORK_H_ */
