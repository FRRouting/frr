// SPDX-License-Identifier: GPL-2.0-or-later
/* pimd memory type definitions
 *
 * Copyright (C) 2015  David Lamparter
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pim_memory.h"

DEFINE_MGROUP(PIMD, "pimd");
DEFINE_MTYPE(PIMD, PIM_CHANNEL_OIL, "PIM SSM (S,G) channel OIL");
DEFINE_MTYPE(PIMD, PIM_INTERFACE, "PIM interface");
DEFINE_MTYPE(PIMD, PIM_IGMP_JOIN, "PIM interface IGMP static join");
DEFINE_MTYPE(PIMD, PIM_STATIC_GROUP, "PIM interface IGMP static group");
DEFINE_MTYPE(PIMD, PIM_IGMP_SOCKET, "PIM interface IGMP socket");
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP, "PIM interface IGMP group");
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP_SOURCE, "PIM interface IGMP source");
DEFINE_MTYPE(PIMD, PIM_NEIGHBOR, "PIM interface neighbor");
DEFINE_MTYPE(PIMD, PIM_IFCHANNEL, "PIM interface (S,G) state");
DEFINE_MTYPE(PIMD, PIM_UPSTREAM, "PIM upstream (S,G) state");
DEFINE_MTYPE(PIMD, PIM_SSMPINGD, "PIM sspimgd socket");
DEFINE_MTYPE(PIMD, PIM_STATIC_ROUTE, "PIM Static Route");
DEFINE_MTYPE(PIMD, PIM_RP, "PIM RP info");
DEFINE_MTYPE(PIMD, PIM_FILTER_NAME, "PIM RP filter info");
DEFINE_MTYPE(PIMD, PIM_MSDP_PEER, "PIM MSDP peer");
DEFINE_MTYPE(PIMD, PIM_MSDP_MG_NAME, "PIM MSDP mesh-group name");
DEFINE_MTYPE(PIMD, PIM_MSDP_AUTH_KEY, "PIM MSDP authentication key");
DEFINE_MTYPE(PIMD, PIM_MSDP_SA, "PIM MSDP source-active cache");
DEFINE_MTYPE(PIMD, PIM_MSDP_MG, "PIM MSDP mesh group");
DEFINE_MTYPE(PIMD, PIM_MSDP_MG_MBR, "PIM MSDP mesh group mbr");
DEFINE_MTYPE(PIMD, PIM_SEC_ADDR, "PIM secondary address");
DEFINE_MTYPE(PIMD, PIM_JP_AGG_GROUP, "PIM JP AGG Group");
DEFINE_MTYPE(PIMD, PIM_JP_AGG_SOURCE, "PIM JP AGG Source");
DEFINE_MTYPE(PIMD, PIM_PIM_INSTANCE, "PIM global state");
DEFINE_MTYPE(PIMD, PIM_NEXTHOP_CACHE, "PIM nexthop cache state");
DEFINE_MTYPE(PIMD, PIM_SSM_INFO, "PIM SSM configuration");
DEFINE_MTYPE(PIMD, PIM_PLIST_NAME, "PIM Prefix List Names");
DEFINE_MTYPE(PIMD, PIM_VXLAN_SG, "PIM VxLAN mroute cache");
