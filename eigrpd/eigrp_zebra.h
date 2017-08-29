/*
 * Zebra connect library for EIGRP.
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

#ifndef _ZEBRA_EIGRP_ZEBRA_H_
#define _ZEBRA_EIGRP_ZEBRA_H_

#include "vty.h"
#include "vrf.h"

extern void eigrp_zebra_init(void);

extern void eigrp_zebra_route_add(struct prefix *, struct list *);
extern void eigrp_zebra_route_delete(struct prefix *);
extern int eigrp_redistribute_set(struct eigrp *, int, struct eigrp_metrics);
extern int eigrp_redistribute_unset(struct eigrp *, int);
extern int eigrp_is_type_redistributed(int);

#endif /* _ZEBRA_EIGRP_ZEBRA_H_ */
