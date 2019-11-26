/*
 * Zebra VxLAN (EVPN) Data structures and definitions
 * These are public definitions referenced by other files.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_VXLAN_H
#define _ZEBRA_VXLAN_H

#include <zebra.h>
#include <zebra/zebra_router.h>

#include "linklist.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#include "lib/json.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Is EVPN enabled? */
#define EVPN_ENABLED(zvrf)  (zvrf)->advertise_all_vni
static inline int is_evpn_enabled(void)
{
	struct zebra_vrf *zvrf = NULL;
	zvrf = zebra_vrf_get_evpn();
	return zvrf ? EVPN_ENABLED(zvrf) : 0;
}

static inline int
is_vxlan_flooding_head_end(void)
{
	struct zebra_vrf *zvrf = zebra_vrf_get_evpn();

	if (!zvrf)
		return 0;
	return (zvrf->vxlan_flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL);
}

/* VxLAN interface change flags of interest. */
#define ZEBRA_VXLIF_LOCAL_IP_CHANGE     (1 << 0)
#define ZEBRA_VXLIF_MASTER_CHANGE       (1 << 1)
#define ZEBRA_VXLIF_VLAN_CHANGE         (1 << 2)
#define ZEBRA_VXLIF_MCAST_GRP_CHANGE    (1 << 3)


#define VNI_STR_LEN 32

/* ZAPI message handlers */
extern void zebra_vxlan_remote_macip_add(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_remote_macip_del(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_remote_vtep_add(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_remote_vtep_del(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_flood_control(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_advertise_subnet(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_advertise_svi_macip(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_advertise_gw_macip(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_advertise_all_vni(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_dup_addr_detection(ZAPI_HANDLER_ARGS);
extern void zebra_vxlan_sg_replay(ZAPI_HANDLER_ARGS);

extern int is_l3vni_for_prefix_routes_only(vni_t vni);
extern ifindex_t get_l3vni_svi_ifindex(vrf_id_t vrf_id);
extern int zebra_vxlan_vrf_delete(struct zebra_vrf *zvrf);
extern int zebra_vxlan_vrf_enable(struct zebra_vrf *zvrf);
extern int zebra_vxlan_vrf_disable(struct zebra_vrf *zvrf);
extern int zebra_vxlan_vrf_delete(struct zebra_vrf *zvrf);
extern void zebra_vxlan_print_specific_nh_l3vni(struct vty *vty, vni_t l3vni,
						struct ipaddr *ip, bool uj);
extern void zebra_vxlan_print_evpn(struct vty *vty, bool uj);
extern void zebra_vxlan_print_specific_rmac_l3vni(struct vty *vty, vni_t l3vni,
						  struct ethaddr *rmac,
						  bool use_json);
extern void zebra_vxlan_print_macs_vni(struct vty *vty, struct zebra_vrf *zvrf,
				       vni_t vni, bool use_json);
extern void zebra_vxlan_print_macs_all_vni(struct vty *vty,
					   struct zebra_vrf *zvrf,
					   bool print_dup,
					   bool use_json);
extern void zebra_vxlan_print_macs_all_vni_detail(struct vty *vty,
						  struct zebra_vrf *zvrf,
						  bool print_dup,
						  bool use_json);
extern void zebra_vxlan_print_macs_all_vni_vtep(struct vty *vty,
						struct zebra_vrf *zvrf,
						struct in_addr vtep_ip,
						bool use_json);
extern void zebra_vxlan_print_specific_mac_vni(struct vty *vty,
					       struct zebra_vrf *zvrf,
					       vni_t vni, struct ethaddr *mac,
					       bool use_json);
extern void zebra_vxlan_print_macs_vni_vtep(struct vty *vty,
					    struct zebra_vrf *zvrf, vni_t vni,
					    struct in_addr vtep_ip,
					    bool use_json);
extern void zebra_vxlan_print_macs_vni_dad(struct vty *vty,
					   struct zebra_vrf *zvrf, vni_t vni,
					   bool use_json);
extern void zebra_vxlan_print_neigh_vni(struct vty *vty, struct zebra_vrf *zvrf,
					vni_t vni, bool use_json);
extern void zebra_vxlan_print_neigh_all_vni(struct vty *vty,
					    struct zebra_vrf *zvrf,
					    bool print_dup,
					    bool use_json);
extern void zebra_vxlan_print_neigh_all_vni_detail(struct vty *vty,
						   struct zebra_vrf *zvrf,
						   bool print_dup,
						   bool use_json);
extern void zebra_vxlan_print_specific_neigh_vni(struct vty *vty,
						 struct zebra_vrf *zvrf,
						 vni_t vni, struct ipaddr *ip,
						 bool use_json);
extern void zebra_vxlan_print_neigh_vni_vtep(struct vty *vty,
					     struct zebra_vrf *zvrf, vni_t vni,
					     struct in_addr vtep_ip,
					     bool use_json);
extern void zebra_vxlan_print_neigh_vni_dad(struct vty *vty,
					struct zebra_vrf *zvrf, vni_t vni,
					bool use_json);
extern void zebra_vxlan_print_vni(struct vty *vty, struct zebra_vrf *zvrf,
				  vni_t vni, bool use_json,
				  json_object *json_array);
extern void zebra_vxlan_print_vnis(struct vty *vty, struct zebra_vrf *zvrf,
				   bool use_json);
extern void zebra_vxlan_print_vnis_detail(struct vty *vty,
					  struct zebra_vrf *zvrf,
					  bool use_json);
extern void zebra_vxlan_print_rmacs_l3vni(struct vty *vty, vni_t vni,
					  bool use_json);
extern void zebra_vxlan_print_rmacs_all_l3vni(struct vty *vty, bool use_json);
extern void zebra_vxlan_print_nh_l3vni(struct vty *vty, vni_t vni,
				       bool use_json);
extern void zebra_vxlan_print_nh_all_l3vni(struct vty *vty, bool use_json);
extern void zebra_vxlan_print_l3vni(struct vty *vty, vni_t vni, bool use_json);
extern void zebra_vxlan_print_vrf_vni(struct vty *vty, struct zebra_vrf *zvrf,
				      json_object *json_vrfs);
extern int zebra_vxlan_add_del_gw_macip(struct interface *ifp, struct prefix *p,
					int add);
extern int zebra_vxlan_svi_up(struct interface *ifp, struct interface *link_if);
extern int zebra_vxlan_svi_down(struct interface *ifp,
				struct interface *link_if);
extern int zebra_vxlan_handle_kernel_neigh_update(
	struct interface *ifp, struct interface *link_if, struct ipaddr *ip,
	struct ethaddr *macaddr, uint16_t state, bool is_ext,
	bool is_router);
extern int zebra_vxlan_handle_kernel_neigh_del(struct interface *ifp,
				       struct interface *link_if,
				       struct ipaddr *ip);
extern int zebra_vxlan_local_mac_add_update(struct interface *ifp,
					    struct interface *br_if,
					    struct ethaddr *mac, vlanid_t vid,
					    bool sticky);
extern int zebra_vxlan_local_mac_del(struct interface *ifp,
				     struct interface *br_if,
				     struct ethaddr *mac, vlanid_t vid);
extern int zebra_vxlan_check_readd_remote_mac(struct interface *ifp,
					      struct interface *br_if,
					      struct ethaddr *mac,
					      vlanid_t vid);
extern int zebra_vxlan_check_del_local_mac(struct interface *ifp,
					   struct interface *br_if,
					   struct ethaddr *mac, vlanid_t vid);
extern int zebra_vxlan_if_up(struct interface *ifp);
extern int zebra_vxlan_if_down(struct interface *ifp);
extern int zebra_vxlan_if_add(struct interface *ifp);
extern int zebra_vxlan_if_update(struct interface *ifp, uint16_t chgflags);
extern int zebra_vxlan_if_del(struct interface *ifp);
extern int zebra_vxlan_process_vrf_vni_cmd(struct zebra_vrf *zvrf, vni_t vni,
					   char *err, int err_str_sz,
					   int filter, int add);
extern void zebra_vxlan_init_tables(struct zebra_vrf *zvrf);
extern void zebra_vxlan_close_tables(struct zebra_vrf *);
extern void zebra_vxlan_cleanup_tables(struct zebra_vrf *);
extern void zebra_vxlan_init(void);
extern void zebra_vxlan_disable(void);
extern void zebra_vxlan_evpn_vrf_route_add(vrf_id_t vrf_id,
					   struct ethaddr *rmac,
					   struct ipaddr *ip,
					   struct prefix *host_prefix);
extern void zebra_vxlan_evpn_vrf_route_del(vrf_id_t vrf_id,
					   struct ipaddr *vtep_ip,
					   struct prefix *host_prefix);
extern int zebra_vxlan_clear_dup_detect_vni_mac(struct vty *vty,
						struct zebra_vrf *zvrf,
						vni_t vni,
						struct ethaddr *macaddr);
extern int zebra_vxlan_clear_dup_detect_vni_ip(struct vty *vty,
					       struct zebra_vrf *zvrf,
					       vni_t vni, struct ipaddr *ip);
extern int zebra_vxlan_clear_dup_detect_vni_all(struct vty *vty,
						struct zebra_vrf *zvrf);
extern int zebra_vxlan_clear_dup_detect_vni(struct vty *vty,
					    struct zebra_vrf *zvrf,
					    vni_t vni);
extern void zebra_vxlan_handle_result(struct zebra_dplane_ctx *ctx);

extern void zebra_evpn_init(void);
extern void zebra_vxlan_macvlan_up(struct interface *ifp);
extern void zebra_vxlan_macvlan_down(struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VXLAN_H */
