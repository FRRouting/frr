/* NHRP netlink/neighbor table API
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <zebra.h>
#include <vrf.h>
#include <if.h>


extern int netlink_nflog_group;
extern int netlink_mcast_nflog_group;

int netlink_configure_arp(unsigned int ifindex, int pf);
void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma);
void netlink_set_nflog_group(int nlgroup);

