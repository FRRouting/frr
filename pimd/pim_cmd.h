/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#ifndef PIM_CMD_H
#define PIM_CMD_H

#define PIM_STR                                "PIM information\n"
#define IGMP_STR                               "IGMP information\n"
#define IGMP_GROUP_STR                         "IGMP groups information\n"
#define IGMP_SOURCE_STR                        "IGMP sources information\n"
#define CONF_SSMPINGD_STR                      "Enable ssmpingd operation\n"
#define SHOW_SSMPINGD_STR                      "ssmpingd operation\n"
#define IFACE_PIM_STR                          "Enable PIM SSM operation\n"
#define IFACE_PIM_SM_STR                       "Enable PIM SM operation\n"
#define IFACE_PIM_HELLO_STR                    "Hello Interval\n"
#define IFACE_PIM_HELLO_TIME_STR               "Time in seconds for Hello Interval\n"
#define IFACE_PIM_HELLO_HOLD_STR               "Time in seconds for Hold Interval\n"
#define IFACE_IGMP_STR                         "Enable IGMP operation\n"
#define IFACE_IGMP_QUERY_INTERVAL_STR          "IGMP host query interval\n"
#define IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_STR      "IGMP max query response value (seconds)\n"
#define IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC_STR "IGMP max query response value (deciseconds)\n"
#define DEBUG_IGMP_STR                              "IGMP protocol activity\n"
#define DEBUG_IGMP_EVENTS_STR                       "IGMP protocol events\n"
#define DEBUG_IGMP_PACKETS_STR                      "IGMP protocol packets\n"
#define DEBUG_IGMP_TRACE_STR                        "IGMP internal daemon activity\n"
#define DEBUG_MROUTE_STR                            "PIM interaction with kernel MFC cache\n"
#define DEBUG_STATIC_STR                            "PIM Static Multicast Route activity\n"
#define DEBUG_PIM_STR                               "PIM protocol activity\n"
#define DEBUG_PIM_EVENTS_STR                        "PIM protocol events\n"
#define DEBUG_PIM_PACKETS_STR                       "PIM protocol packets\n"
#define DEBUG_PIM_HELLO_PACKETS_STR                 "PIM Hello protocol packets\n"
#define DEBUG_PIM_J_P_PACKETS_STR                   "PIM Join/Prune protocol packets\n"
#define DEBUG_PIM_PIM_REG_PACKETS_STR               "PIM Register/Reg-Stop protocol packets\n"
#define DEBUG_PIM_PACKETDUMP_STR                    "PIM packet dump\n"
#define DEBUG_PIM_PACKETDUMP_SEND_STR               "Dump sent packets\n"
#define DEBUG_PIM_PACKETDUMP_RECV_STR               "Dump received packets\n"
#define DEBUG_PIM_TRACE_STR                         "PIM internal daemon activity\n"
#define DEBUG_PIM_ZEBRA_STR                         "ZEBRA protocol activity\n"
#define DEBUG_SSMPINGD_STR                          "ssmpingd activity\n"
#define CLEAR_IP_IGMP_STR                           "IGMP clear commands\n"
#define CLEAR_IP_PIM_STR                            "PIM clear commands\n"
#define MROUTE_STR                                  "IP multicast routing table\n"
#define RIB_STR                                     "IP unicast routing table\n"
#define CFG_MSDP_STR                                "Configure multicast source discovery protocol\n"
#define MSDP_STR                                    "MSDP information\n"
#define DEBUG_MSDP_STR                              "MSDP protocol activity\n"
#define DEBUG_MSDP_EVENTS_STR                       "MSDP protocol events\n"
#define DEBUG_MSDP_INTERNAL_STR                     "MSDP protocol internal\n"
#define DEBUG_MSDP_PACKETS_STR                      "MSDP protocol packets\n"
#define DEBUG_MTRACE_STR                            "Mtrace protocol activity\n"

void pim_cmd_init(void);

/*
 * Special Macro to allow us to get the correct pim_instance;
 */
#define PIM_DECLVAR_CONTEXT(A, B)                                              \
	struct vrf *A = VTY_GET_CONTEXT(vrf);                                  \
	struct pim_instance *B =                                               \
		(vrf) ? vrf->info : pim_get_pim_instance(VRF_DEFAULT);         \
	vrf = (vrf) ? vrf : pim->vrf;

#endif /* PIM_CMD_H */
