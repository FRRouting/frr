/* Zebra Nexthop Group header.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __ZEBRA_NHG_H__
#define __ZEBRA_NHG_H__

#include "zebra/rib.h"
#include "lib/nexthop_group.h"

extern int nexthop_active_update(struct route_node *rn, struct route_entry *re);

struct nhg_hash_entry {
	afi_t afi;
	vrf_id_t vrf_id;

	struct nexthop_group nhg;

	uint32_t refcnt;
	uint32_t dplane_ref;
};

void zebra_nhg_init(void);
void zebra_nhg_terminate(void);

extern uint32_t zebra_nhg_hash_key(const void *arg);

extern bool zebra_nhg_hash_equal(const void *arg1, const void *arg2);

#endif
