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

int pim_process_ip_pim_cmd(struct vty *vty);
int pim_process_no_ip_pim_cmd(struct vty *vty);
int pim_process_ip_pim_drprio_cmd(struct vty *vty, const char *drpriority_str);
int pim_process_no_ip_pim_drprio_cmd(struct vty *vty);

#endif /* PIM_CMD_COMMON_H */
