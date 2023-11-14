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
#define IFACE_PIM_STR "Enable PIM SSM operation\n"
#define IFACE_PIM_SM_STR "Enable PIM SM operation\n"
#define IFACE_PIM_HELLO_STR "Hello Interval\n"
#define IFACE_PIM_HELLO_TIME_STR "Time in seconds for Hello Interval\n"
#define IFACE_PIM_HELLO_HOLD_STR "Time in seconds for Hold Interval\n"
#define MROUTE_STR "IP multicast routing table\n"
#define CLEAR_IP_PIM_STR "PIM clear commands\n"
#define DEBUG_MLD_STR "MLD protocol activity\n"
#define DEBUG_MLD_EVENTS_STR "MLD protocol events\n"
#define DEBUG_MLD_PACKETS_STR "MLD protocol packets\n"
#define DEBUG_MLD_TRACE_STR "MLD internal daemon activity\n"
#define CONF_SSMPINGD_STR "Enable ssmpingd operation\n"
#define DEBUG_PIMV6_STR "PIMv6 protocol activity\n"
#define DEBUG_PIMV6_EVENTS_STR "PIMv6 protocol events\n"
#define DEBUG_PIMV6_PACKETS_STR "PIMv6 protocol packets\n"
#define DEBUG_PIMV6_HELLO_PACKETS_STR "PIMv6 Hello protocol packets\n"
#define DEBUG_PIMV6_J_P_PACKETS_STR "PIMv6 Join/Prune protocol packets\n"
#define DEBUG_PIMV6_PIM_REG_PACKETS_STR                                        \
	"PIMv6 Register/Reg-Stop protocol packets\n"
#define DEBUG_PIMV6_PACKETDUMP_STR "PIMv6 packet dump\n"
#define DEBUG_PIMV6_PACKETDUMP_SEND_STR "Dump sent packets\n"
#define DEBUG_PIMV6_PACKETDUMP_RECV_STR "Dump received packets\n"
#define DEBUG_PIMV6_TRACE_STR "PIMv6 internal daemon activity\n"
#define DEBUG_PIMV6_ZEBRA_STR "ZEBRA protocol activity\n"

void pim_cmd_init(void);

#endif /* PIM6_CMD_H */
