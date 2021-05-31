/* cmgd memory type definitions
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cmgd_memory.h"

/* this file is temporary in nature;  definitions should be moved to the
 * files they're used in */

DEFINE_MGROUP(CMGD, "cmgd")
DEFINE_MTYPE(CMGD, CMGD, "CMGD instance")
DEFINE_MTYPE(CMGD, CMGD_LISTENER, "CMGD listen socket details")
DEFINE_MTYPE(CMGD, CMGD_PEER, "CMGD peer")
DEFINE_MTYPE(CMGD, CMGD_PEER_HOST, "CMGD peer hostname")
DEFINE_MTYPE(CMGD, CMGD_PEER_IFNAME, "CMGD peer ifname")
DEFINE_MTYPE(CMGD, PEER_GROUP, "Peer group")
DEFINE_MTYPE(CMGD, PEER_GROUP_HOST, "CMGD Peer group hostname")
DEFINE_MTYPE(CMGD, PEER_DESC, "Peer description")
DEFINE_MTYPE(CMGD, PEER_PASSWORD, "Peer password string")
DEFINE_MTYPE(CMGD, CMGD_PEER_AF, "CMGD peer af")
DEFINE_MTYPE(CMGD, CMGD_UPDGRP, "CMGD update group")
DEFINE_MTYPE(CMGD, CMGD_UPD_SUBGRP, "CMGD update subgroup")
DEFINE_MTYPE(CMGD, CMGD_PACKET, "CMGD packet")
DEFINE_MTYPE(CMGD, ATTR, "CMGD attribute")
DEFINE_MTYPE(CMGD, AS_PATH, "CMGD aspath")
DEFINE_MTYPE(CMGD, AS_SEG, "CMGD aspath seg")
DEFINE_MTYPE(CMGD, AS_SEG_DATA, "CMGD aspath segment data")
DEFINE_MTYPE(CMGD, AS_STR, "CMGD aspath str")

DEFINE_MTYPE(CMGD, CMGD_TABLE, "CMGD table")
DEFINE_MTYPE(CMGD, CMGD_NODE, "CMGD node")
DEFINE_MTYPE(CMGD, CMGD_ROUTE, "CMGD route")
DEFINE_MTYPE(CMGD, CMGD_ROUTE_EXTRA, "CMGD ancillary route info")
DEFINE_MTYPE(CMGD, CMGD_CONN, "CMGD connected")
DEFINE_MTYPE(CMGD, CMGD_STATIC, "CMGD static")
DEFINE_MTYPE(CMGD, CMGD_ADVERTISE_ATTR, "CMGD adv attr")
DEFINE_MTYPE(CMGD, CMGD_ADVERTISE, "CMGD adv")
DEFINE_MTYPE(CMGD, CMGD_SYNCHRONISE, "CMGD synchronise")
DEFINE_MTYPE(CMGD, CMGD_ADJ_IN, "CMGD adj in")
DEFINE_MTYPE(CMGD, CMGD_ADJ_OUT, "CMGD adj out")
DEFINE_MTYPE(CMGD, CMGD_MPATH_INFO, "CMGD multipath info")

DEFINE_MTYPE(CMGD, AS_LIST, "CMGD AS list")
DEFINE_MTYPE(CMGD, AS_FILTER, "CMGD AS filter")
DEFINE_MTYPE(CMGD, AS_FILTER_STR, "CMGD AS filter str")

DEFINE_MTYPE(CMGD, COMMUNITY, "community")
DEFINE_MTYPE(CMGD, COMMUNITY_VAL, "community val")
DEFINE_MTYPE(CMGD, COMMUNITY_STR, "community str")

DEFINE_MTYPE(CMGD, ECOMMUNITY, "extcommunity")
DEFINE_MTYPE(CMGD, ECOMMUNITY_VAL, "extcommunity val")
DEFINE_MTYPE(CMGD, ECOMMUNITY_STR, "extcommunity str")

DEFINE_MTYPE(CMGD, COMMUNITY_LIST, "community-list")
DEFINE_MTYPE(CMGD, COMMUNITY_LIST_NAME, "community-list name")
DEFINE_MTYPE(CMGD, COMMUNITY_LIST_ENTRY, "community-list entry")
DEFINE_MTYPE(CMGD, COMMUNITY_LIST_CONFIG, "community-list config")
DEFINE_MTYPE(CMGD, COMMUNITY_LIST_HANDLER, "community-list handler")

DEFINE_MTYPE(CMGD, CLUSTER, "Cluster list")
DEFINE_MTYPE(CMGD, CLUSTER_VAL, "Cluster list val")

DEFINE_MTYPE(CMGD, CMGD_PROCESS_QUEUE, "CMGD Process queue")
DEFINE_MTYPE(CMGD, CMGD_CLEAR_NODE_QUEUE, "CMGD node clear queue")

DEFINE_MTYPE(CMGD, TRANSIT, "CMGD transit attr")
DEFINE_MTYPE(CMGD, TRANSIT_VAL, "CMGD transit val")

DEFINE_MTYPE(CMGD, CMGD_DEBUG_FILTER, "CMGD debug filter")
DEFINE_MTYPE(CMGD, CMGD_DEBUG_STR, "CMGD debug filter string")

DEFINE_MTYPE(CMGD, CMGD_DISTANCE, "CMGD distance")
DEFINE_MTYPE(CMGD, CMGD_NEXTHOP_CACHE, "CMGD nexthop")
DEFINE_MTYPE(CMGD, CMGD_CONFED_LIST, "CMGD confed list")
DEFINE_MTYPE(CMGD, PEER_UPDATE_SOURCE, "CMGD peer update interface")
DEFINE_MTYPE(CMGD, PEER_CONF_IF, "CMGD peer config interface")
DEFINE_MTYPE(CMGD, CMGD_DAMP_INFO, "Dampening info")
DEFINE_MTYPE(CMGD, CMGD_DAMP_ARRAY, "CMGD Dampening array")
DEFINE_MTYPE(CMGD, CMGD_DAMP_REUSELIST, "CMGD Dampening reuse list")
DEFINE_MTYPE(CMGD, CMGD_REGEXP, "CMGD regexp")
DEFINE_MTYPE(CMGD, CMGD_AGGREGATE, "CMGD aggregate")
DEFINE_MTYPE(CMGD, CMGD_ADDR, "CMGD own address")
DEFINE_MTYPE(CMGD, TIP_ADDR, "CMGD own tunnel-ip address")

DEFINE_MTYPE(CMGD, CMGD_REDIST, "CMGD redistribution")
DEFINE_MTYPE(CMGD, CMGD_FILTER_NAME, "CMGD Filter Information")
DEFINE_MTYPE(CMGD, CMGD_DUMP_STR, "CMGD Dump String Information")
DEFINE_MTYPE(CMGD, ENCAP_TLV, "ENCAP TLV")

DEFINE_MTYPE(CMGD, CMGD_TEA_OPTIONS, "CMGD TEA Options")
DEFINE_MTYPE(CMGD, CMGD_TEA_OPTIONS_VALUE, "CMGD TEA Options Value")

DEFINE_MTYPE(CMGD, LCOMMUNITY, "Large Community")
DEFINE_MTYPE(CMGD, LCOMMUNITY_STR, "Large Community display string")
DEFINE_MTYPE(CMGD, LCOMMUNITY_VAL, "Large Community value")

DEFINE_MTYPE(CMGD, CMGD_EVPN, "CMGD EVPN Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_MH_INFO, "CMGD EVPN MH Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_ES_VTEP, "CMGD EVPN ES VTEP")
DEFINE_MTYPE(CMGD, CMGD_EVPN_PATH_ES_INFO, "CMGD EVPN PATH ES Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_ES_EVI_VTEP, "CMGD EVPN ES-EVI VTEP")
DEFINE_MTYPE(CMGD, CMGD_EVPN_ES, "CMGD EVPN ESI Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_ES_EVI, "CMGD EVPN ES-per-EVI Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_ES_VRF, "CMGD EVPN ES-per-VRF Information")
DEFINE_MTYPE(CMGD, CMGD_EVPN_IMPORT_RT, "CMGD EVPN Import RT")
DEFINE_MTYPE(CMGD, CMGD_EVPN_VRF_IMPORT_RT, "CMGD EVPN VRF Import RT")
DEFINE_MTYPE(CMGD, CMGD_EVPN_MACIP, "CMGD EVPN MAC IP")

DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC, "CMGD flowspec")
DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC_RULE, "CMGD flowspec rule")
DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC_RULE_STR, "CMGD flowspec rule str")
DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC_COMPILED, "CMGD flowspec compiled")
DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC_NAME, "CMGD flowspec name")
DEFINE_MTYPE(CMGD, CMGD_FLOWSPEC_INDEX, "CMGD flowspec index")

DEFINE_MTYPE(CMGD, CMGD_SRV6_L3VPN, "CMGD prefix-sid srv6 l3vpn servcie")
DEFINE_MTYPE(CMGD, CMGD_SRV6_VPN, "CMGD prefix-sid srv6 vpn service")
