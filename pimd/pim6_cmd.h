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
#ifndef PIM6_CMD_H
#define PIM6_CMD_H
#define PIM_STR "PIM information\n"
#define MLD_STR "MLD information\n"
#define MLD_GROUP_STR "MLD groups information\n"
#define MLD_SOURCE_STR "MLD sources information\n"
#define IFACE_MLD_STR  "Enable MLD operation\n"
#define IFACE_MLD_QUERY_INTERVAL_STR "MLD host query interval\n"
#define IFACE_MLD_QUERY_MAX_RESPONSE_TIME_STR \
	"MLD max query response value (seconds)\n"
#define IFACE_MLD_QUERY_MAX_RESPONSE_TIME_DSEC_STR \
	"MLD max query response value (deciseconds)\n"
#define IFACE_MLD_LAST_MEMBER_QUERY_INTERVAL_STR \
	"MLD last member query interval\n"
#define IFACE_MLD_LAST_MEMBER_QUERY_COUNT_STR "MLD last member query count\n"
#define MROUTE_STR "IP multicast routing table\n"
#define DEBUG_MLD_STR "MLD protocol activity\n"
#define DEBUG_MLD_EVENTS_STR "MLD protocol events\n"
#define DEBUG_MLD_PACKETS_STR "MLD protocol packets\n"
#define DEBUG_MLD_TRACE_STR "MLD internal daemon activity\n"

void pim_cmd_init(void);
/*
 * Special Macro to allow us to get the correct pim_instance;
 */
#define PIM_DECLVAR_CONTEXT(A, B) \
	do { \
		struct vrf *A = VTY_GET_CONTEXT(vrf); \
		struct pim_instance *B = \
			(vrf) ? vrf->info : pim_get_pim_instance(VRF_DEFAULT); \
		vrf = (vrf) ? vrf : pim->vrf; \
	} while (0)
#endif /* PIM6_CMD_H */
