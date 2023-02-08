// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for EIGRP.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 */

#ifndef _ZEBRA_EIGRP_ZEBRA_H_
#define _ZEBRA_EIGRP_ZEBRA_H_

#include "vty.h"
#include "vrf.h"

extern void eigrp_zebra_init(void);

extern void eigrp_zebra_route_add(struct eigrp *eigrp, struct prefix *p,
				  struct list *successors, uint32_t distance);
extern void eigrp_zebra_route_delete(struct eigrp *eigrp, struct prefix *);
extern int eigrp_redistribute_set(struct eigrp *, int, struct eigrp_metrics);
extern int eigrp_redistribute_unset(struct eigrp *, int);

#endif /* _ZEBRA_EIGRP_ZEBRA_H_ */
