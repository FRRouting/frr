/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef PIM_CMD_COMMON_H
#define PIM_CMD_COMMON_H

const char *pim_cli_get_vrf_name(struct vty *vty);
int pim_process_join_prune_cmd(struct vty *vty, const char *jpi_str);
int pim_process_no_join_prune_cmd(struct vty *vty);
int pim_process_spt_switchover_infinity_cmd(struct vty *vty);
int pim_process_spt_switchover_prefixlist_cmd(struct vty *vty,
					      const char *plist);
int pim_process_no_spt_switchover_cmd(struct vty *vty);
int pim_process_pim_packet_cmd(struct vty *vty, const char *packet);
int pim_process_no_pim_packet_cmd(struct vty *vty);
int pim_process_keepalivetimer_cmd(struct vty *vty, const char *kat);
int pim_process_no_keepalivetimer_cmd(struct vty *vty);
int pim_process_rp_kat_cmd(struct vty *vty, const char *rpkat);
int pim_process_no_rp_kat_cmd(struct vty *vty);
int pim_process_register_suppress_cmd(struct vty *vty, const char *rst);
int pim_process_no_register_suppress_cmd(struct vty *vty);
int pim_process_rp_cmd(struct vty *vty, const char *rp_str,
		       const char *group_str);
int pim_process_no_rp_cmd(struct vty *vty, const char *rp_str,
			  const char *group_str);
int pim_process_rp_plist_cmd(struct vty *vty, const char *rp_str,
			     const char *prefix_list);
int pim_process_no_rp_plist_cmd(struct vty *vty, const char *rp_str,
				const char *prefix_list);

int pim_process_ip_pim_cmd(struct vty *vty);
int pim_process_no_ip_pim_cmd(struct vty *vty);
int pim_process_ip_pim_drprio_cmd(struct vty *vty, const char *drpriority_str);
int pim_process_no_ip_pim_drprio_cmd(struct vty *vty);
int pim_process_ip_pim_hello_cmd(struct vty *vty, const char *hello_str,
				 const char *hold_str);
int pim_process_no_ip_pim_hello_cmd(struct vty *vty);
int pim_process_ip_pim_activeactive_cmd(struct vty *vty, const char *no);
int pim_process_ip_pim_boundary_oil_cmd(struct vty *vty, const char *oil);
int pim_process_no_ip_pim_boundary_oil_cmd(struct vty *vty);
int pim_process_ip_mroute_cmd(struct vty *vty, const char *interface,
			      const char *group_str, const char *source_str);
int pim_process_no_ip_mroute_cmd(struct vty *vty, const char *interface,
				 const char *group_str, const char *src_str);
void json_object_pim_upstream_add(json_object *json, struct pim_upstream *up);
void pim_show_rpf(struct pim_instance *pim, struct vty *vty, json_object *json);
void pim_show_neighbors_secondary(struct pim_instance *pim, struct vty *vty);
void pim_show_state(struct pim_instance *pim, struct vty *vty,
		    const char *src_or_group, const char *group,
		    json_object *json);
void pim_show_statistics(struct pim_instance *pim, struct vty *vty,
			 const char *ifname, bool uj);
void pim_show_upstream(struct pim_instance *pim, struct vty *vty,
		       pim_sgaddr *sg, json_object *json);
void pim_show_join_desired(struct pim_instance *pim, struct vty *vty, bool uj);
void pim_show_upstream_rpf(struct pim_instance *pim, struct vty *vty, bool uj);
void pim_show_rpf_refresh_stats(struct vty *vty, struct pim_instance *pim,
				time_t now, json_object *json);
bool pim_sgaddr_match(pim_sgaddr item, pim_sgaddr match);

/*
 * Special Macro to allow us to get the correct pim_instance;
 */
#define PIM_DECLVAR_CONTEXT(A, B)                                              \
	struct vrf *A = VTY_GET_CONTEXT(vrf);                                  \
	struct pim_instance *B =                                               \
		(vrf) ? vrf->info : pim_get_pim_instance(VRF_DEFAULT);         \
	vrf = (vrf) ? vrf : pim->vrf

#endif /* PIM_CMD_COMMON_H */
