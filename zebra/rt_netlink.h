/* Header file exported by rt_netlink.c to zebra.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RT_NETLINK_H
#define _ZEBRA_RT_NETLINK_H

#ifdef HAVE_NETLINK

#include "zebra/zebra_mpls.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NL_DEFAULT_ROUTE_METRIC 20

/*
 * Additional protocol strings to push into routes
 * If we add anything new here please make sure
 * to update:
 * zebra2proto                 Function
 * proto2zebra                 Function
 * is_selfroute                Function
 * tools/frr                   To flush the route upon exit
 *
 * Finally update this file to allow iproute2 to
 * know about this new route.
 * tools/etc/iproute2/rt_protos.d
 */
#define RTPROT_BGP         186
#define RTPROT_ISIS        187
#define RTPROT_OSPF        188
#define RTPROT_RIP         189
#define RTPROT_RIPNG       190
#if !defined(RTPROT_BABEL)
#define RTPROT_BABEL        42
#endif
#define RTPROT_NHRP        191
#define RTPROT_EIGRP       192
#define RTPROT_LDP         193
#define RTPROT_SHARP       194
#define RTPROT_PBR         195
#define RTPROT_ZSTATIC     196
#define RTPROT_OPENFABRIC  197

void rt_netlink_init(void);

/* MPLS label forwarding table change, using dataplane context information. */
extern int netlink_mpls_multipath(int cmd, struct zebra_dplane_ctx *ctx);

extern int netlink_route_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);
extern int netlink_route_read(struct zebra_ns *zns);

extern int netlink_nexthop_change(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);
extern int netlink_nexthop_read(struct zebra_ns *zns);

extern int netlink_neigh_change(struct nlmsghdr *h, ns_id_t ns_id);
extern int netlink_macfdb_read(struct zebra_ns *zns);
extern int netlink_macfdb_read_for_bridge(struct zebra_ns *zns,
					  struct interface *ifp,
					  struct interface *br_if);
extern int netlink_neigh_read(struct zebra_ns *zns);
extern int netlink_neigh_read_for_vlan(struct zebra_ns *zns,
				       struct interface *vlan_if);
extern int netlink_macfdb_read_specific_mac(struct zebra_ns *zns,
					    struct interface *br_if,
					    struct ethaddr *mac, uint16_t vid);
extern int netlink_neigh_read_specific_ip(struct ipaddr *ip,
					  struct interface *vlan_if);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_RT_NETLINK_H */
