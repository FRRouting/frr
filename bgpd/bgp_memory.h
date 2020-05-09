/* bgpd memory type declarations
 *
 * Copyright (C) 2015  David Lamparter
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_MEMORY_H
#define _QUAGGA_BGP_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(BGPD)
DECLARE_MTYPE(BGP)
DECLARE_MTYPE(BGP_LISTENER)
DECLARE_MTYPE(BGP_PEER)
DECLARE_MTYPE(BGP_PEER_HOST)
DECLARE_MTYPE(BGP_PEER_IFNAME)
DECLARE_MTYPE(PEER_GROUP)
DECLARE_MTYPE(PEER_GROUP_HOST)
DECLARE_MTYPE(PEER_DESC)
DECLARE_MTYPE(PEER_PASSWORD)
DECLARE_MTYPE(BGP_PEER_AF)
DECLARE_MTYPE(BGP_UPDGRP)
DECLARE_MTYPE(BGP_UPD_SUBGRP)
DECLARE_MTYPE(BGP_PACKET)
DECLARE_MTYPE(ATTR)
DECLARE_MTYPE(AS_PATH)
DECLARE_MTYPE(AS_SEG)
DECLARE_MTYPE(AS_SEG_DATA)
DECLARE_MTYPE(AS_STR)

DECLARE_MTYPE(BGP_TABLE)
DECLARE_MTYPE(BGP_NODE)
DECLARE_MTYPE(BGP_ROUTE)
DECLARE_MTYPE(BGP_ROUTE_EXTRA)
DECLARE_MTYPE(BGP_CONN)
DECLARE_MTYPE(BGP_STATIC)
DECLARE_MTYPE(BGP_ADVERTISE_ATTR)
DECLARE_MTYPE(BGP_ADVERTISE)
DECLARE_MTYPE(BGP_SYNCHRONISE)
DECLARE_MTYPE(BGP_ADJ_IN)
DECLARE_MTYPE(BGP_ADJ_OUT)
DECLARE_MTYPE(BGP_MPATH_INFO)

DECLARE_MTYPE(AS_LIST)
DECLARE_MTYPE(AS_FILTER)
DECLARE_MTYPE(AS_FILTER_STR)

DECLARE_MTYPE(COMMUNITY)
DECLARE_MTYPE(COMMUNITY_VAL)
DECLARE_MTYPE(COMMUNITY_STR)

DECLARE_MTYPE(ECOMMUNITY)
DECLARE_MTYPE(ECOMMUNITY_VAL)
DECLARE_MTYPE(ECOMMUNITY_STR)

DECLARE_MTYPE(COMMUNITY_LIST)
DECLARE_MTYPE(COMMUNITY_LIST_NAME)
DECLARE_MTYPE(COMMUNITY_LIST_ENTRY)
DECLARE_MTYPE(COMMUNITY_LIST_CONFIG)
DECLARE_MTYPE(COMMUNITY_LIST_HANDLER)

DECLARE_MTYPE(CLUSTER)
DECLARE_MTYPE(CLUSTER_VAL)

DECLARE_MTYPE(BGP_PROCESS_QUEUE)
DECLARE_MTYPE(BGP_CLEAR_NODE_QUEUE)

DECLARE_MTYPE(TRANSIT)
DECLARE_MTYPE(TRANSIT_VAL)

DECLARE_MTYPE(BGP_DEBUG_FILTER)
DECLARE_MTYPE(BGP_DEBUG_STR)

DECLARE_MTYPE(BGP_DISTANCE)
DECLARE_MTYPE(BGP_NEXTHOP_CACHE)
DECLARE_MTYPE(BGP_CONFED_LIST)
DECLARE_MTYPE(PEER_UPDATE_SOURCE)
DECLARE_MTYPE(PEER_CONF_IF)
DECLARE_MTYPE(BGP_DAMP_INFO)
DECLARE_MTYPE(BGP_DAMP_ARRAY)
DECLARE_MTYPE(BGP_REGEXP)
DECLARE_MTYPE(BGP_AGGREGATE)
DECLARE_MTYPE(BGP_ADDR)
DECLARE_MTYPE(TIP_ADDR)

DECLARE_MTYPE(BGP_REDIST)
DECLARE_MTYPE(BGP_FILTER_NAME)
DECLARE_MTYPE(BGP_DUMP_STR)
DECLARE_MTYPE(ENCAP_TLV)

DECLARE_MTYPE(BGP_TEA_OPTIONS)
DECLARE_MTYPE(BGP_TEA_OPTIONS_VALUE)

DECLARE_MTYPE(LCOMMUNITY)
DECLARE_MTYPE(LCOMMUNITY_STR)
DECLARE_MTYPE(LCOMMUNITY_VAL)

DECLARE_MTYPE(BGP_EVPN_MH_INFO)
DECLARE_MTYPE(BGP_EVPN_ES)
DECLARE_MTYPE(BGP_EVPN_ES_EVI)
DECLARE_MTYPE(BGP_EVPN_ES_VRF)
DECLARE_MTYPE(BGP_EVPN_ES_VTEP)
DECLARE_MTYPE(BGP_EVPN_PATH_ES_INFO)
DECLARE_MTYPE(BGP_EVPN_ES_EVI_VTEP)

DECLARE_MTYPE(BGP_EVPN)
DECLARE_MTYPE(BGP_EVPN_IMPORT_RT)
DECLARE_MTYPE(BGP_EVPN_VRF_IMPORT_RT)
DECLARE_MTYPE(BGP_EVPN_MACIP)

DECLARE_MTYPE(BGP_FLOWSPEC)
DECLARE_MTYPE(BGP_FLOWSPEC_RULE)
DECLARE_MTYPE(BGP_FLOWSPEC_RULE_STR)
DECLARE_MTYPE(BGP_FLOWSPEC_COMPILED)
DECLARE_MTYPE(BGP_FLOWSPEC_NAME)
DECLARE_MTYPE(BGP_FLOWSPEC_INDEX)

DECLARE_MTYPE(BGP_SRV6_L3VPN)
DECLARE_MTYPE(BGP_SRV6_VPN)

#endif /* _QUAGGA_BGP_MEMORY_H */
