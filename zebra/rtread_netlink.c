/*
 * Kernel routing table readup by netlink
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include <zebra.h>

#ifdef GNU_LINUX

#include "vty.h"
#include "zebra/rt.h"
#include "zebra/zebra_pbr.h"
#include "zebra/rt_netlink.h"
#include "zebra/rule_netlink.h"

void route_read(struct zebra_ns *zns)
{
	netlink_route_read(zns);
}

void macfdb_read(struct zebra_ns *zns)
{
	netlink_macfdb_read(zns);
}

void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
			    struct interface *br_if)
{
	netlink_macfdb_read_for_bridge(zns, ifp, br_if);
}

void neigh_read(struct zebra_ns *zns)
{
	netlink_neigh_read(zns);
}

void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
	netlink_neigh_read_for_vlan(zns, vlan_if);
}

void kernel_read_pbr_rules(struct zebra_ns *zns)
{
	netlink_rules_read(zns);
}

#endif /* GNU_LINUX */
