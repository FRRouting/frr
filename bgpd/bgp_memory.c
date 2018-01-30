/* bgpd memory type definitions
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bgp_memory.h"

/* this file is temporary in nature;  definitions should be moved to the
 * files they're used in */

DEFINE_MGROUP(BGPD, "bgpd")
DEFINE_MTYPE(BGPD, BGP, "BGP instance")
DEFINE_MTYPE(BGPD, BGP_LISTENER, "BGP listen socket details")
DEFINE_MTYPE(BGPD, BGP_PEER, "BGP peer")
DEFINE_MTYPE(BGPD, BGP_PEER_HOST, "BGP peer hostname")
DEFINE_MTYPE(BGPD, BGP_PEER_IFNAME, "BGP peer ifname")
DEFINE_MTYPE(BGPD, PEER_GROUP, "Peer group")
DEFINE_MTYPE(BGPD, PEER_GROUP_HOST, "BGP Peer group hostname")
DEFINE_MTYPE(BGPD, PEER_DESC, "Peer description")
DEFINE_MTYPE(BGPD, PEER_PASSWORD, "Peer password string")
DEFINE_MTYPE(BGPD, BGP_PEER_AF, "BGP peer af")
DEFINE_MTYPE(BGPD, BGP_UPDGRP, "BGP update group")
DEFINE_MTYPE(BGPD, BGP_UPD_SUBGRP, "BGP update subgroup")
DEFINE_MTYPE(BGPD, BGP_PACKET, "BGP packet")
DEFINE_MTYPE(BGPD, ATTR, "BGP attribute")
DEFINE_MTYPE(BGPD, AS_PATH, "BGP aspath")
DEFINE_MTYPE(BGPD, AS_SEG, "BGP aspath seg")
DEFINE_MTYPE(BGPD, AS_SEG_DATA, "BGP aspath segment data")
DEFINE_MTYPE(BGPD, AS_STR, "BGP aspath str")

DEFINE_MTYPE(BGPD, BGP_TABLE, "BGP table")
DEFINE_MTYPE(BGPD, BGP_NODE, "BGP node")
DEFINE_MTYPE(BGPD, BGP_ROUTE, "BGP route")
DEFINE_MTYPE(BGPD, BGP_ROUTE_EXTRA, "BGP ancillary route info")
DEFINE_MTYPE(BGPD, BGP_CONN, "BGP connected")
DEFINE_MTYPE(BGPD, BGP_STATIC, "BGP static")
DEFINE_MTYPE(BGPD, BGP_ADVERTISE_ATTR, "BGP adv attr")
DEFINE_MTYPE(BGPD, BGP_ADVERTISE, "BGP adv")
DEFINE_MTYPE(BGPD, BGP_SYNCHRONISE, "BGP synchronise")
DEFINE_MTYPE(BGPD, BGP_ADJ_IN, "BGP adj in")
DEFINE_MTYPE(BGPD, BGP_ADJ_OUT, "BGP adj out")
DEFINE_MTYPE(BGPD, BGP_MPATH_INFO, "BGP multipath info")

DEFINE_MTYPE(BGPD, AS_LIST, "BGP AS list")
DEFINE_MTYPE(BGPD, AS_FILTER, "BGP AS filter")
DEFINE_MTYPE(BGPD, AS_FILTER_STR, "BGP AS filter str")

DEFINE_MTYPE(BGPD, COMMUNITY, "community")
DEFINE_MTYPE(BGPD, COMMUNITY_VAL, "community val")
DEFINE_MTYPE(BGPD, COMMUNITY_STR, "community str")

DEFINE_MTYPE(BGPD, ECOMMUNITY, "extcommunity")
DEFINE_MTYPE(BGPD, ECOMMUNITY_VAL, "extcommunity val")
DEFINE_MTYPE(BGPD, ECOMMUNITY_STR, "extcommunity str")

DEFINE_MTYPE(BGPD, COMMUNITY_LIST, "community-list")
DEFINE_MTYPE(BGPD, COMMUNITY_LIST_NAME, "community-list name")
DEFINE_MTYPE(BGPD, COMMUNITY_LIST_ENTRY, "community-list entry")
DEFINE_MTYPE(BGPD, COMMUNITY_LIST_CONFIG, "community-list config")
DEFINE_MTYPE(BGPD, COMMUNITY_LIST_HANDLER, "community-list handler")

DEFINE_MTYPE(BGPD, CLUSTER, "Cluster list")
DEFINE_MTYPE(BGPD, CLUSTER_VAL, "Cluster list val")

DEFINE_MTYPE(BGPD, BGP_PROCESS_QUEUE, "BGP Process queue")
DEFINE_MTYPE(BGPD, BGP_CLEAR_NODE_QUEUE, "BGP node clear queue")

DEFINE_MTYPE(BGPD, TRANSIT, "BGP transit attr")
DEFINE_MTYPE(BGPD, TRANSIT_VAL, "BGP transit val")

DEFINE_MTYPE(BGPD, BGP_DEBUG_FILTER, "BGP debug filter")
DEFINE_MTYPE(BGPD, BGP_DEBUG_STR, "BGP debug filter string")

DEFINE_MTYPE(BGPD, BGP_DISTANCE, "BGP distance")
DEFINE_MTYPE(BGPD, BGP_NEXTHOP_CACHE, "BGP nexthop")
DEFINE_MTYPE(BGPD, BGP_CONFED_LIST, "BGP confed list")
DEFINE_MTYPE(BGPD, PEER_UPDATE_SOURCE, "BGP peer update interface")
DEFINE_MTYPE(BGPD, PEER_CONF_IF, "BGP peer config interface")
DEFINE_MTYPE(BGPD, BGP_DAMP_INFO, "Dampening info")
DEFINE_MTYPE(BGPD, BGP_DAMP_ARRAY, "BGP Dampening array")
DEFINE_MTYPE(BGPD, BGP_REGEXP, "BGP regexp")
DEFINE_MTYPE(BGPD, BGP_AGGREGATE, "BGP aggregate")
DEFINE_MTYPE(BGPD, BGP_ADDR, "BGP own address")
DEFINE_MTYPE(BGPD, TIP_ADDR, "BGP own tunnel-ip address")

DEFINE_MTYPE(BGPD, BGP_REDIST, "BGP redistribution")
DEFINE_MTYPE(BGPD, BGP_FILTER_NAME, "BGP Filter Information")
DEFINE_MTYPE(BGPD, BGP_DUMP_STR, "BGP Dump String Information")
DEFINE_MTYPE(BGPD, ENCAP_TLV, "ENCAP TLV")

DEFINE_MTYPE(BGPD, BGP_TEA_OPTIONS, "BGP TEA Options")
DEFINE_MTYPE(BGPD, BGP_TEA_OPTIONS_VALUE, "BGP TEA Options Value")

DEFINE_MTYPE(BGPD, LCOMMUNITY, "Large Community")
DEFINE_MTYPE(BGPD, LCOMMUNITY_STR, "Large Community display string")
DEFINE_MTYPE(BGPD, LCOMMUNITY_VAL, "Large Community value")

DEFINE_MTYPE(BGPD, BGP_EVPN, "BGP EVPN Information")
DEFINE_MTYPE(BGPD, BGP_EVPN_IMPORT_RT, "BGP EVPN Import RT")
DEFINE_MTYPE(BGPD, BGP_EVPN_VRF_IMPORT_RT, "BGP EVPN VRF Import RT")
DEFINE_MTYPE(BGPD, BGP_EVPN_MACIP, "BGP EVPN MAC IP")
