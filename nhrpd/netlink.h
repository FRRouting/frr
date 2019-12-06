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

struct nhrp_vrf;

int netlink_configure_arp(unsigned int ifindex, int pf);
void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma);
void netlink_set_nflog_group(struct nhrp_vrf *nhrp_vrf, int nlgroup);

