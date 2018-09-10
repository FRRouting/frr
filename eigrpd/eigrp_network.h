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
extern int eigrp_if_ipmulticast(eigrp_t *, struct prefix *, unsigned int);
extern int eigrp_network_set(eigrp_t *eigrp, struct prefix *p);
extern int eigrp_network_unset(eigrp_t *eigrp, struct prefix *p);

extern void eigrp_adjust_sndbuflen(eigrp_t *, unsigned int);

extern void eigrp_external_routes_refresh(eigrp_t *, int);

#endif /* EIGRP_NETWORK_H_ */
