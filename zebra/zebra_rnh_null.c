/* Zebra next hop tracking code
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_rnh.h"

int zebra_rnh_ip_default_route = 0;
int zebra_rnh_ipv6_default_route = 0;

void
zebra_free_rnh (struct rnh *rnh)
{}

void zebra_evaluate_rnh (vrf_id_t vrfid, int family, int force, rnh_type_t type,
		        struct prefix *p)
{}

void zebra_print_rnh_table (vrf_id_t vrfid, int family, struct vty *vty,
			    rnh_type_t type)
{}

void zebra_register_rnh_static_nh(vrf_id_t vrfid, struct prefix *p, struct route_node *rn)
{}

void zebra_deregister_rnh_static_nh(vrf_id_t vrfid, struct prefix *p, struct route_node *rn)
{}

void zebra_deregister_rnh_static_nexthops (vrf_id_t vrfid, struct nexthop *nexthop,
                                           struct route_node *rn)
{}
