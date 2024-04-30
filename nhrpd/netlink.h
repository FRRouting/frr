// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP netlink/neighbor table API
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include <zebra.h>
#include <vrf.h>
#include <if.h>


extern int netlink_nflog_group;
extern int netlink_mcast_nflog_group;

void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma);
void netlink_set_nflog_group(int nlgroup);

