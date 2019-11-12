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

#ifndef PIMD_H
#define PIMD_H

#include <stdint.h>
#include "zebra.h"
#include "libfrr.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

#include "pim_instance.h"
#include "pim_str.h"
#include "pim_memory.h"
#include "pim_assert.h"

#define PIMD_PROGNAME       "pimd"
#define PIMD_DEFAULT_CONFIG "pimd.conf"
#define PIMD_VTY_PORT       2611

#define PIM_IP_PROTO_IGMP             (2)
#define PIM_IP_PROTO_PIM              (103)
#define PIM_IGMP_MIN_LEN              (8)

#define PIM_ENFORCE_LOOPFREE_MFC

/*
 * PIM MSG Header Format
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |PIM Ver| Type  |   Reserved    |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define PIM_MSG_HEADER_LEN            (4)
#define PIM_PIM_MIN_LEN               PIM_MSG_HEADER_LEN

#define PIM_ENCODED_IPV4_UCAST_SIZE    (6)
#define PIM_ENCODED_IPV4_GROUP_SIZE    (8)
#define PIM_ENCODED_IPV4_SOURCE_SIZE   (8)

/*
 * J/P Message Format, Group Header
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Upstream Neighbor Address (Encoded-Unicast format)     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Reserved     | Num groups    |          Holdtime             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Multicast Group Address 1 (Encoded-Group format)      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Number of Joined Sources    |   Number of Pruned Sources    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define PIM_JP_GROUP_HEADER_SIZE                                               \
	(PIM_ENCODED_IPV4_UCAST_SIZE + 1 + 1 + 2 + PIM_ENCODED_IPV4_GROUP_SIZE \
	 + 2 + 2)

#define PIM_PROTO_VERSION             (2)

#define MCAST_ALL_SYSTEMS      "224.0.0.1"
#define MCAST_ALL_ROUTERS      "224.0.0.2"
#define MCAST_ALL_PIM_ROUTERS  "224.0.0.13"
#define MCAST_ALL_IGMP_ROUTERS "224.0.0.22"

#define PIM_FORCE_BOOLEAN(expr) ((expr) != 0)

#define PIM_NET_INADDR_ANY (htonl(INADDR_ANY))
#define PIM_INADDR_IS_ANY(addr) (addr).s_addr == PIM_NET_INADDR_ANY
#define PIM_INADDR_ISNOT_ANY(addr) ((addr).s_addr != PIM_NET_INADDR_ANY) /* struct in_addr addr */

#define max(x,y) ((x) > (y) ? (x) : (y))

#define PIM_MASK_PIM_EVENTS          (1 << 0)
#define PIM_MASK_PIM_EVENTS_DETAIL   (1 << 1)
#define PIM_MASK_PIM_PACKETS         (1 << 2)
#define PIM_MASK_PIM_PACKETDUMP_SEND (1 << 3)
#define PIM_MASK_PIM_PACKETDUMP_RECV (1 << 4)
#define PIM_MASK_PIM_TRACE           (1 << 5)
#define PIM_MASK_PIM_TRACE_DETAIL    (1 << 6)
#define PIM_MASK_IGMP_EVENTS         (1 << 7)
#define PIM_MASK_IGMP_PACKETS        (1 << 8)
#define PIM_MASK_IGMP_TRACE          (1 << 9)
#define PIM_MASK_IGMP_TRACE_DETAIL   (1 << 10)
#define PIM_MASK_ZEBRA               (1 << 11)
#define PIM_MASK_SSMPINGD            (1 << 12)
#define PIM_MASK_MROUTE              (1 << 13)
#define PIM_MASK_MROUTE_DETAIL       (1 << 14)
#define PIM_MASK_PIM_HELLO           (1 << 15)
#define PIM_MASK_PIM_J_P             (1 << 16)
#define PIM_MASK_STATIC              (1 << 17)
#define PIM_MASK_PIM_REG             (1 << 18)
#define PIM_MASK_MSDP_EVENTS         (1 << 19)
#define PIM_MASK_MSDP_PACKETS        (1 << 20)
#define PIM_MASK_MSDP_INTERNAL       (1 << 21)
#define PIM_MASK_PIM_NHT             (1 << 22)
#define PIM_MASK_PIM_NHT_DETAIL      (1 << 23)
#define PIM_MASK_PIM_NHT_RP          (1 << 24)
#define PIM_MASK_MTRACE              (1 << 25)
#define PIM_MASK_VXLAN               (1 << 26)
#define PIM_MASK_BSM_PROC            (1 << 27)
#define PIM_MASK_MLAG                (1 << 28)
/* Remember 32 bits!!! */

/* PIM error codes */
#define PIM_SUCCESS                      0
#define PIM_GROUP_BAD_ADDRESS           -2
#define PIM_GROUP_OVERLAP               -3
#define PIM_GROUP_PFXLIST_OVERLAP       -4
#define PIM_RP_BAD_ADDRESS              -5
#define PIM_RP_NO_PATH                  -6
#define PIM_RP_NOT_FOUND                -7
#define PIM_RP_PFXLIST_IN_USE           -8
#define PIM_IFACE_NOT_FOUND             -9
#define PIM_UPDATE_SOURCE_DUP           -10
#define PIM_GROUP_BAD_ADDR_MASK_COMBO   -11

const char *const PIM_ALL_SYSTEMS;
const char *const PIM_ALL_ROUTERS;
const char *const PIM_ALL_PIM_ROUTERS;
const char *const PIM_ALL_IGMP_ROUTERS;

extern struct pim_router *router;
extern struct zebra_privs_t pimd_privs;
struct in_addr qpim_all_pim_routers_addr;
extern uint8_t qpim_ecmp_enable;
extern uint8_t qpim_ecmp_rebalance_enable;

#define PIM_DEFAULT_PACKET_PROCESS 3

#define PIM_JP_HOLDTIME (router->t_periodic * 7 / 2)

/*
 * Register-Stop Timer (RST(S,G))
 * Default values
 */
#define PIM_REGISTER_SUPPRESSION_TIME_DEFAULT      (60)
#define PIM_REGISTER_PROBE_TIME_DEFAULT            (5)

#define PIM_DEBUG_PIM_EVENTS (router->debugs & PIM_MASK_PIM_EVENTS)
#define PIM_DEBUG_PIM_EVENTS_DETAIL                                            \
	(router->debugs & (PIM_MASK_PIM_EVENTS_DETAIL | PIM_MASK_PIM_EVENTS))
#define PIM_DEBUG_PIM_PACKETS (router->debugs & PIM_MASK_PIM_PACKETS)
#define PIM_DEBUG_PIM_PACKETDUMP_SEND                                          \
	(router->debugs & PIM_MASK_PIM_PACKETDUMP_SEND)
#define PIM_DEBUG_PIM_PACKETDUMP_RECV                                          \
	(router->debugs & PIM_MASK_PIM_PACKETDUMP_RECV)
#define PIM_DEBUG_PIM_TRACE (router->debugs & PIM_MASK_PIM_TRACE)
#define PIM_DEBUG_PIM_TRACE_DETAIL                                             \
	(router->debugs & (PIM_MASK_PIM_TRACE_DETAIL | PIM_MASK_PIM_TRACE))
#define PIM_DEBUG_PIM_TRACE_DETAIL_ONLY                                        \
	(router->debugs & PIM_MASK_PIM_TRACE_DETAIL)
#define PIM_DEBUG_IGMP_EVENTS (router->debugs & PIM_MASK_IGMP_EVENTS)
#define PIM_DEBUG_IGMP_PACKETS (router->debugs & PIM_MASK_IGMP_PACKETS)
#define PIM_DEBUG_IGMP_TRACE (router->debugs & PIM_MASK_IGMP_TRACE)
#define PIM_DEBUG_IGMP_TRACE_DETAIL                                            \
	(router->debugs & (PIM_MASK_IGMP_TRACE_DETAIL | PIM_MASK_IGMP_TRACE))
#define PIM_DEBUG_ZEBRA (router->debugs & PIM_MASK_ZEBRA)
#define PIM_DEBUG_MLAG (router->debugs & PIM_MASK_MLAG)
#define PIM_DEBUG_SSMPINGD (router->debugs & PIM_MASK_SSMPINGD)
#define PIM_DEBUG_MROUTE (router->debugs & PIM_MASK_MROUTE)
#define PIM_DEBUG_MROUTE_DETAIL                                                \
	(router->debugs & (PIM_MASK_MROUTE_DETAIL | PIM_MASK_MROUTE))
#define PIM_DEBUG_MROUTE_DETAIL_ONLY (router->debugs & PIM_MASK_MROUTE_DETAIL)
#define PIM_DEBUG_PIM_HELLO (router->debugs & PIM_MASK_PIM_HELLO)
#define PIM_DEBUG_PIM_J_P (router->debugs & PIM_MASK_PIM_J_P)
#define PIM_DEBUG_PIM_REG (router->debugs & PIM_MASK_PIM_REG)
#define PIM_DEBUG_STATIC (router->debugs & PIM_MASK_STATIC)
#define PIM_DEBUG_MSDP_EVENTS (router->debugs & PIM_MASK_MSDP_EVENTS)
#define PIM_DEBUG_MSDP_PACKETS (router->debugs & PIM_MASK_MSDP_PACKETS)
#define PIM_DEBUG_MSDP_INTERNAL (router->debugs & PIM_MASK_MSDP_INTERNAL)
#define PIM_DEBUG_PIM_NHT (router->debugs & PIM_MASK_PIM_NHT)
#define PIM_DEBUG_PIM_NHT_DETAIL                                               \
	(router->debugs & (PIM_MASK_PIM_NHT_DETAIL | PIM_MASK_PIM_NHT))
#define PIM_DEBUG_PIM_NHT_RP (router->debugs & PIM_MASK_PIM_NHT_RP)
#define PIM_DEBUG_MTRACE (router->debugs & PIM_MASK_MTRACE)
#define PIM_DEBUG_VXLAN (router->debugs & PIM_MASK_VXLAN)
#define PIM_DEBUG_BSM	(router->debugs & PIM_MASK_BSM_PROC)

#define PIM_DEBUG_EVENTS                                                       \
	(router->debugs                                                        \
	 & (PIM_MASK_PIM_EVENTS | PIM_MASK_IGMP_EVENTS                         \
	    | PIM_MASK_MSDP_EVENTS | PIM_MASK_BSM_PROC))
#define PIM_DEBUG_PACKETS                                                      \
	(router->debugs                                                        \
	 & (PIM_MASK_PIM_PACKETS | PIM_MASK_IGMP_PACKETS                       \
	    | PIM_MASK_MSDP_PACKETS))
#define PIM_DEBUG_TRACE                                                        \
	(router->debugs & (PIM_MASK_PIM_TRACE | PIM_MASK_IGMP_TRACE))

#define PIM_DO_DEBUG_PIM_EVENTS (router->debugs |= PIM_MASK_PIM_EVENTS)
#define PIM_DO_DEBUG_PIM_PACKETS (router->debugs |= PIM_MASK_PIM_PACKETS)
#define PIM_DO_DEBUG_PIM_PACKETDUMP_SEND                                       \
	(router->debugs |= PIM_MASK_PIM_PACKETDUMP_SEND)
#define PIM_DO_DEBUG_PIM_PACKETDUMP_RECV                                       \
	(router->debugs |= PIM_MASK_PIM_PACKETDUMP_RECV)
#define PIM_DO_DEBUG_PIM_TRACE (router->debugs |= PIM_MASK_PIM_TRACE)
#define PIM_DO_DEBUG_PIM_TRACE_DETAIL                                          \
	(router->debugs |= PIM_MASK_PIM_TRACE_DETAIL)
#define PIM_DO_DEBUG_IGMP_EVENTS (router->debugs |= PIM_MASK_IGMP_EVENTS)
#define PIM_DO_DEBUG_IGMP_PACKETS (router->debugs |= PIM_MASK_IGMP_PACKETS)
#define PIM_DO_DEBUG_IGMP_TRACE (router->debugs |= PIM_MASK_IGMP_TRACE)
#define PIM_DO_DEBUG_IGMP_TRACE_DETAIL                                         \
	(router->debugs |= PIM_MASK_IGMP_TRACE_DETAIL)
#define PIM_DO_DEBUG_ZEBRA (router->debugs |= PIM_MASK_ZEBRA)
#define PIM_DO_DEBUG_MLAG (router->debugs |= PIM_MASK_MLAG)
#define PIM_DO_DEBUG_SSMPINGD (router->debugs |= PIM_MASK_SSMPINGD)
#define PIM_DO_DEBUG_MROUTE (router->debugs |= PIM_MASK_MROUTE)
#define PIM_DO_DEBUG_MROUTE_DETAIL (router->debugs |= PIM_MASK_MROUTE_DETAIL)
#define PIM_DO_DEBUG_BSM (router->debugs |= PIM_MASK_BSM_PROC)
#define PIM_DO_DEBUG_PIM_HELLO (router->debugs |= PIM_MASK_PIM_HELLO)
#define PIM_DO_DEBUG_PIM_J_P (router->debugs |= PIM_MASK_PIM_J_P)
#define PIM_DO_DEBUG_PIM_REG (router->debugs |= PIM_MASK_PIM_REG)
#define PIM_DO_DEBUG_STATIC (router->debugs |= PIM_MASK_STATIC)
#define PIM_DO_DEBUG_MSDP_EVENTS (router->debugs |= PIM_MASK_MSDP_EVENTS)
#define PIM_DO_DEBUG_MSDP_PACKETS (router->debugs |= PIM_MASK_MSDP_PACKETS)
#define PIM_DO_DEBUG_MSDP_INTERNAL (router->debugs |= PIM_MASK_MSDP_INTERNAL)
#define PIM_DO_DEBUG_PIM_NHT (router->debugs |= PIM_MASK_PIM_NHT)
#define PIM_DO_DEBUG_PIM_NHT_RP (router->debugs |= PIM_MASK_PIM_NHT_RP)
#define PIM_DO_DEBUG_MTRACE (router->debugs |= PIM_MASK_MTRACE)
#define PIM_DO_DEBUG_VXLAN (router->debugs |= PIM_MASK_VXLAN)

#define PIM_DONT_DEBUG_PIM_EVENTS (router->debugs &= ~PIM_MASK_PIM_EVENTS)
#define PIM_DONT_DEBUG_PIM_PACKETS (router->debugs &= ~PIM_MASK_PIM_PACKETS)
#define PIM_DONT_DEBUG_PIM_PACKETDUMP_SEND                                     \
	(router->debugs &= ~PIM_MASK_PIM_PACKETDUMP_SEND)
#define PIM_DONT_DEBUG_PIM_PACKETDUMP_RECV                                     \
	(router->debugs &= ~PIM_MASK_PIM_PACKETDUMP_RECV)
#define PIM_DONT_DEBUG_PIM_TRACE (router->debugs &= ~PIM_MASK_PIM_TRACE)
#define PIM_DONT_DEBUG_PIM_TRACE_DETAIL                                        \
	(router->debugs &= ~PIM_MASK_PIM_TRACE_DETAIL)
#define PIM_DONT_DEBUG_IGMP_EVENTS (router->debugs &= ~PIM_MASK_IGMP_EVENTS)
#define PIM_DONT_DEBUG_IGMP_PACKETS (router->debugs &= ~PIM_MASK_IGMP_PACKETS)
#define PIM_DONT_DEBUG_IGMP_TRACE (router->debugs &= ~PIM_MASK_IGMP_TRACE)
#define PIM_DONT_DEBUG_IGMP_TRACE_DETAIL                                       \
	(router->debugs &= ~PIM_MASK_IGMP_TRACE_DETAIL)
#define PIM_DONT_DEBUG_ZEBRA (router->debugs &= ~PIM_MASK_ZEBRA)
#define PIM_DONT_DEBUG_MLAG (router->debugs &= ~PIM_MASK_MLAG)
#define PIM_DONT_DEBUG_SSMPINGD (router->debugs &= ~PIM_MASK_SSMPINGD)
#define PIM_DONT_DEBUG_MROUTE (router->debugs &= ~PIM_MASK_MROUTE)
#define PIM_DONT_DEBUG_MROUTE_DETAIL (router->debugs &= ~PIM_MASK_MROUTE_DETAIL)
#define PIM_DONT_DEBUG_PIM_HELLO (router->debugs &= ~PIM_MASK_PIM_HELLO)
#define PIM_DONT_DEBUG_PIM_J_P (router->debugs &= ~PIM_MASK_PIM_J_P)
#define PIM_DONT_DEBUG_PIM_REG (router->debugs &= ~PIM_MASK_PIM_REG)
#define PIM_DONT_DEBUG_STATIC (router->debugs &= ~PIM_MASK_STATIC)
#define PIM_DONT_DEBUG_MSDP_EVENTS (router->debugs &= ~PIM_MASK_MSDP_EVENTS)
#define PIM_DONT_DEBUG_MSDP_PACKETS (router->debugs &= ~PIM_MASK_MSDP_PACKETS)
#define PIM_DONT_DEBUG_MSDP_INTERNAL (router->debugs &= ~PIM_MASK_MSDP_INTERNAL)
#define PIM_DONT_DEBUG_PIM_NHT (router->debugs &= ~PIM_MASK_PIM_NHT)
#define PIM_DONT_DEBUG_PIM_NHT_RP (router->debugs &= ~PIM_MASK_PIM_NHT_RP)
#define PIM_DONT_DEBUG_MTRACE (router->debugs &= ~PIM_MASK_MTRACE)
#define PIM_DONT_DEBUG_VXLAN (router->debugs &= ~PIM_MASK_VXLAN)
#define PIM_DONT_DEBUG_BSM (router->debugs &= ~PIM_MASK_BSM_PROC)

void pim_router_init(void);
void pim_router_terminate(void);

void pim_init(void);
void pim_terminate(void);

extern void pim_route_map_init(void);
extern void pim_route_map_terminate(void);
void pim_prefix_list_update(struct prefix_list *plist);

#endif /* PIMD_H */
