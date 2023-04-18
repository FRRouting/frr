// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel routing table readup by netlink
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX

#include "vty.h"
#include "zebra/rt.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_tc.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/tc_netlink.h"

void route_read(struct zebra_ns *zns)
{
	netlink_route_read(zns);
}

void macfdb_read(struct zebra_ns *zns)
{
	netlink_macfdb_read(zns);
}

void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
			    struct interface *br_if, vlanid_t vid)
{
	netlink_macfdb_read_for_bridge(zns, ifp, br_if, vid);
}

void macfdb_read_mcast_entry_for_vni(struct zebra_ns *zns,
				     struct interface *ifp, vni_t vni)
{
	netlink_macfdb_read_mcast_for_vni(zns, ifp, vni);
}

void macfdb_read_specific_mac(struct zebra_ns *zns, struct interface *br_if,
			      const struct ethaddr *mac, vlanid_t vid)
{
	netlink_macfdb_read_specific_mac(zns, br_if, mac, vid);
}

void neigh_read(struct zebra_ns *zns)
{
	netlink_neigh_read(zns);
}

void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
	netlink_neigh_read_for_vlan(zns, vlan_if);
}

void neigh_read_specific_ip(const struct ipaddr *ip, struct interface *vlan_if)
{
	netlink_neigh_read_specific_ip(ip, vlan_if);
}

void kernel_read_pbr_rules(struct zebra_ns *zns)
{
	netlink_rules_read(zns);
}

void kernel_read_tc_qdisc(struct zebra_ns *zns)
{
	netlink_qdisc_read(zns);
}

void vlan_read(struct zebra_ns *zns)
{
	netlink_vlan_read(zns);
}

#endif /* GNU_LINUX */
