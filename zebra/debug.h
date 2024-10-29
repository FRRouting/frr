// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra debug related function
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_DEBUG_H
#define _ZEBRA_DEBUG_H

#include "lib/vty.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Debug flags. */
#define ZEBRA_DEBUG_EVENT   0x01

#define ZEBRA_DEBUG_PACKET  0x01
#define ZEBRA_DEBUG_SEND    0x20
#define ZEBRA_DEBUG_RECV    0x40
#define ZEBRA_DEBUG_DETAIL  0x80

#define ZEBRA_DEBUG_KERNEL  0x01
#define ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND 0x20
#define ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV 0x40

#define ZEBRA_DEBUG_RIB     0x01
#define ZEBRA_DEBUG_RIB_DETAILED   0x02

#define ZEBRA_DEBUG_FPM     0x01

#define ZEBRA_DEBUG_NHT 0x01
#define ZEBRA_DEBUG_NHT_DETAILED 0x02

#define ZEBRA_DEBUG_MPLS             0x01
#define ZEBRA_DEBUG_MPLS_DETAILED    0x02

#define ZEBRA_DEBUG_VXLAN   0x01

#define ZEBRA_DEBUG_PW      0x01

#define ZEBRA_DEBUG_DPLANE           0x01
#define ZEBRA_DEBUG_DPLANE_DETAILED  0x02

#define ZEBRA_DEBUG_DPLANE_DPDK 0x01
#define ZEBRA_DEBUG_DPLANE_DPDK_DETAIL 0x02

#define ZEBRA_DEBUG_MLAG    0x01

#define ZEBRA_DEBUG_NHG             0x01
#define ZEBRA_DEBUG_NHG_DETAILED    0x02

#define ZEBRA_DEBUG_EVPN_MH_ES 0x01
#define ZEBRA_DEBUG_EVPN_MH_NH 0x02
#define ZEBRA_DEBUG_EVPN_MH_MAC 0x04
#define ZEBRA_DEBUG_EVPN_MH_NEIGH 0x08

#define ZEBRA_DEBUG_PBR 0x01

#define ZEBRA_DEBUG_NEIGH 0x01

#define ZEBRA_DEBUG_TC 0x01

#define ZEBRA_DEBUG_SRV6 0x01

/* Debug related macro. */
#define IS_ZEBRA_DEBUG_EVENT  (zebra_debug_event & ZEBRA_DEBUG_EVENT)

#define IS_ZEBRA_DEBUG_PACKET (zebra_debug_packet & ZEBRA_DEBUG_PACKET)
#define IS_ZEBRA_DEBUG_SEND   (zebra_debug_packet & ZEBRA_DEBUG_SEND)
#define IS_ZEBRA_DEBUG_RECV   (zebra_debug_packet & ZEBRA_DEBUG_RECV)
#define IS_ZEBRA_DEBUG_DETAIL (zebra_debug_packet & ZEBRA_DEBUG_DETAIL)

#define IS_ZEBRA_DEBUG_KERNEL (zebra_debug_kernel & ZEBRA_DEBUG_KERNEL)
#define IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND                                     \
	(zebra_debug_kernel & ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
#define IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV                                     \
	(zebra_debug_kernel & ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV)

#define IS_ZEBRA_DEBUG_RIB                                                     \
	(zebra_debug_rib & (ZEBRA_DEBUG_RIB | ZEBRA_DEBUG_RIB_DETAILED))
#define IS_ZEBRA_DEBUG_RIB_DETAILED  (zebra_debug_rib & ZEBRA_DEBUG_RIB_DETAILED)

#define IS_ZEBRA_DEBUG_FPM (zebra_debug_fpm & ZEBRA_DEBUG_FPM)

#define IS_ZEBRA_DEBUG_NHT  (zebra_debug_nht & ZEBRA_DEBUG_NHT)
#define IS_ZEBRA_DEBUG_NHT_DETAILED (zebra_debug_nht & ZEBRA_DEBUG_NHT_DETAILED)

#define IS_ZEBRA_DEBUG_MPLS  (zebra_debug_mpls & ZEBRA_DEBUG_MPLS)
#define IS_ZEBRA_DEBUG_MPLS_DETAIL \
	(zebra_debug_mpls & ZEBRA_DEBUG_MPLS_DETAILED)
#define IS_ZEBRA_DEBUG_VXLAN (zebra_debug_vxlan & ZEBRA_DEBUG_VXLAN)
#define IS_ZEBRA_DEBUG_PW  (zebra_debug_pw & ZEBRA_DEBUG_PW)

#define IS_ZEBRA_DEBUG_DPLANE (zebra_debug_dplane & ZEBRA_DEBUG_DPLANE)
#define IS_ZEBRA_DEBUG_DPLANE_DETAIL \
	(zebra_debug_dplane & ZEBRA_DEBUG_DPLANE_DETAILED)

#define IS_ZEBRA_DEBUG_DPLANE_DPDK                                             \
	(zebra_debug_dplane_dpdk & ZEBRA_DEBUG_DPLANE_DPDK)
#define IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL                                      \
	(zebra_debug_dplane_dpdk & ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)

#define IS_ZEBRA_DEBUG_MLAG (zebra_debug_mlag & ZEBRA_DEBUG_MLAG)

#define IS_ZEBRA_DEBUG_NHG (zebra_debug_nexthop & ZEBRA_DEBUG_NHG)

#define IS_ZEBRA_DEBUG_NHG_DETAIL \
	(zebra_debug_nexthop & ZEBRA_DEBUG_NHG_DETAILED)

#define IS_ZEBRA_DEBUG_EVPN_MH_ES \
	(zebra_debug_evpn_mh & ZEBRA_DEBUG_EVPN_MH_ES)
#define IS_ZEBRA_DEBUG_EVPN_MH_NH \
	(zebra_debug_evpn_mh & ZEBRA_DEBUG_EVPN_MH_NH)
#define IS_ZEBRA_DEBUG_EVPN_MH_MAC \
	(zebra_debug_evpn_mh & ZEBRA_DEBUG_EVPN_MH_MAC)
#define IS_ZEBRA_DEBUG_EVPN_MH_NEIGH \
	(zebra_debug_evpn_mh & ZEBRA_DEBUG_EVPN_MH_NEIGH)

#define IS_ZEBRA_DEBUG_PBR (zebra_debug_pbr & ZEBRA_DEBUG_PBR)

#define IS_ZEBRA_DEBUG_NEIGH (zebra_debug_neigh & ZEBRA_DEBUG_NEIGH)

#define IS_ZEBRA_DEBUG_TC (zebra_debug_tc & ZEBRA_DEBUG_TC)

#define IS_ZEBRA_DEBUG_SRV6 (zebra_debug_srv6 & ZEBRA_DEBUG_SRV6)

extern unsigned long zebra_debug_event;
extern unsigned long zebra_debug_packet;
extern unsigned long zebra_debug_kernel;
extern unsigned long zebra_debug_rib;
extern unsigned long zebra_debug_fpm;
extern unsigned long zebra_debug_nht;
extern unsigned long zebra_debug_mpls;
extern unsigned long zebra_debug_vxlan;
extern unsigned long zebra_debug_pw;
extern unsigned long zebra_debug_dplane;
extern unsigned long zebra_debug_dplane_dpdk;
extern unsigned long zebra_debug_mlag;
extern unsigned long zebra_debug_nexthop;
extern unsigned long zebra_debug_evpn_mh;
extern unsigned long zebra_debug_pbr;
extern unsigned long zebra_debug_neigh;
extern unsigned long zebra_debug_tc;
extern unsigned long zebra_debug_srv6;

extern void zebra_debug_init(void);

DECLARE_HOOK(zebra_debug_show_debugging, (struct vty *vty), (vty));

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DEBUG_H */
