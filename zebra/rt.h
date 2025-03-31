// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kernel routing table update prototype.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#define ROUTE_INSTALLATION_METRIC 20

#define RKERNEL_ROUTE(type) ((type) == ZEBRA_ROUTE_KERNEL)

#define RSYSTEM_ROUTE(type)                                                    \
	((RKERNEL_ROUTE(type)) || (type) == ZEBRA_ROUTE_CONNECT ||             \
	 (type) == ZEBRA_ROUTE_LOCAL)

#ifndef HAVE_NETLINK
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

extern enum zebra_dplane_result
kernel_pbr_rule_update(struct zebra_dplane_ctx *ctx);

extern enum zebra_dplane_result
kernel_intf_update(struct zebra_dplane_ctx *ctx);

extern enum zebra_dplane_result
kernel_intf_netconf_update(struct zebra_dplane_ctx *ctx);
extern enum zebra_dplane_result kernel_tc_update(struct zebra_dplane_ctx *ctx);

#endif /* !HAVE_NETLINK */

extern int kernel_neigh_update(int cmd, int ifindex, void *addr, char *lla,
			       int llalen, ns_id_t ns_id, uint8_t family,
			       bool permanent);
extern int kernel_neigh_register(vrf_id_t vrf_id, struct zserv *client,
				 bool reg);
extern int kernel_interface_set_master(struct interface *master,
				       struct interface *slave);

extern int mpls_kernel_init(void);

/* Global init and deinit for platform-/OS-specific things */
void kernel_router_init(void);
void kernel_router_terminate(void);

extern uint32_t kernel_get_speed(struct interface *ifp, int *error);
extern int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *mroute);

/*
 * Southbound Initialization routines to get initial starting
 * state.
 */
extern void interface_list(struct zebra_ns *zns);
extern void interface_list_tunneldump(struct zebra_ns *zns);
extern void interface_list_second(struct zebra_ns *zns);
extern void kernel_init(struct zebra_ns *zns);
extern void kernel_terminate(struct zebra_ns *zns, bool complete);
extern void macfdb_read(struct zebra_ns *zns);
extern void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
				   struct interface *br_if, vlanid_t vid);
extern void macfdb_read_mcast_entry_for_vni(struct zebra_ns *zns,
					    struct interface *ifp, vni_t vni);
extern void macfdb_read_specific_mac(struct zebra_ns *zns,
				     struct interface *br_if,
				     const struct ethaddr *mac, vlanid_t vid);
extern void neigh_read(struct zebra_ns *zns);
extern void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *ifp);
extern void neigh_read_specific_ip(const struct ipaddr *ip,
				   struct interface *vlan_if);
extern void route_read(struct zebra_ns *zns);
extern int kernel_upd_mac_nh(uint32_t nh_id, struct in_addr vtep_ip);
extern int kernel_del_mac_nh(uint32_t nh_id);
extern int kernel_upd_mac_nhg(uint32_t nhg_id, uint32_t nh_cnt,
		struct nh_grp *nh_ids);
extern int kernel_del_mac_nhg(uint32_t nhg_id);

/*
 * Message batching interface.
 */
extern void kernel_update_multi(struct dplane_ctx_list_head *ctx_list);

/*
 * Called by the dplane pthread to read incoming OS messages and dispatch them.
 */
int kernel_dplane_read(struct zebra_dplane_info *info);
extern void vlan_read(struct zebra_ns *zns);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_RT_H */
