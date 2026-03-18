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
