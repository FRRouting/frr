/*
 * kernel routing table update prototype.
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

#ifndef _ZEBRA_RT_H
#define _ZEBRA_RT_H

#include "prefix.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"
#include "zebra/rib.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RKERNEL_ROUTE(type) ((type) == ZEBRA_ROUTE_KERNEL)

#define RSYSTEM_ROUTE(type)                                                    \
	((RKERNEL_ROUTE(type)) || (type) == ZEBRA_ROUTE_CONNECT)


/*
 * Update or delete a route, nexthop, LSP, pseudowire, or vxlan MAC from the
 * kernel, using info from a dataplane context.
 */
extern enum zebra_dplane_result kernel_route_update(
	struct zebra_dplane_ctx *ctx);

extern enum zebra_dplane_result
kernel_nexthop_update(struct zebra_dplane_ctx *ctx);

extern enum zebra_dplane_result kernel_lsp_update(
	struct zebra_dplane_ctx *ctx);

enum zebra_dplane_result kernel_pw_update(struct zebra_dplane_ctx *ctx);

enum zebra_dplane_result kernel_address_update_ctx(
	struct zebra_dplane_ctx *ctx);

enum zebra_dplane_result kernel_mac_update_ctx(struct zebra_dplane_ctx *ctx);

enum zebra_dplane_result kernel_neigh_update_ctx(struct zebra_dplane_ctx *ctx);

extern int kernel_neigh_update(int cmd, int ifindex, uint32_t addr, char *lla,
			       int llalen, ns_id_t ns_id);
extern int kernel_interface_set_master(struct interface *master,
				       struct interface *slave);

extern int mpls_kernel_init(void);

extern uint32_t kernel_get_speed(struct interface *ifp, int *error);
extern int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *mroute);

/*
 * Southbound Initialization routines to get initial starting
 * state.
 */
extern void interface_list(struct zebra_ns *zns);
extern void kernel_init(struct zebra_ns *zns);
extern void kernel_terminate(struct zebra_ns *zns, bool complete);
extern void macfdb_read(struct zebra_ns *zns);
extern void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
				   struct interface *br_if);
extern void macfdb_read_specific_mac(struct zebra_ns *zns,
				     struct interface *br_if,
				     struct ethaddr *mac, vlanid_t vid);
extern void neigh_read(struct zebra_ns *zns);
extern void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *ifp);
extern void neigh_read_specific_ip(struct ipaddr *ip,
				   struct interface *vlan_if);
extern void route_read(struct zebra_ns *zns);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_RT_H */
