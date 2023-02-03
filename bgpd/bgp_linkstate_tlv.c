// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State TLV Serializer/Deserializer
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>

#include "iso.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_linkstate_tlv.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_NODE, "BGP-LS Type Node");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_LINK, "BGP-LS Type Link");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_PREFIX4, "BGP-LS Type Prefix IPv4");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_PREFIX6, "BGP-LS Type Prefix IPv6");

struct bgp_linkstate_tlv_info {
	const char *descr;
	uint8_t min_size;
	uint16_t max_size;
	uint8_t multiple;
};

#define UNDEF_MIN_SZ 0xFF
#define MAX_SZ 0xFFFF
#define UNDEF_MULTPL 1

/* clang-format off */
struct bgp_linkstate_tlv_info bgp_linkstate_tlv_infos[BGP_LS_TLV_MAX] = {
	/* NLRI TLV */
	[BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS] = {"Local Node Descriptors", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS] = {"Remote Node Descriptors", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS] = {"Link Local/Remote Identifiers", 2, 2, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_INTERFACE_ADDRESS] = {"IPv4 interface address", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS] = {"IPv4 neighbor address", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV6_INTERFACE_ADDRESS] = {"IPv6 interface address", 16, 16, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS] = {"IPv6 neighbor address", 16, 16, UNDEF_MULTPL},
	[BGP_LS_TLV_OSPF_ROUTE_TYPE] = {"OSPF Route Type", 1, 1, UNDEF_MULTPL},
	[BGP_LS_TLV_IP_REACHABILITY_INFORMATION] = {"IP Reachability Information", 2, 17, UNDEF_MULTPL},
	[BGP_LS_TLV_AUTONOMOUS_SYSTEM] = {"Autonomous System", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_BGP_LS_IDENTIFIER] = {"BGP-LS Identifier", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_OSPF_AREA_ID] = {"OSPF Area-ID", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_IGP_ROUTER_ID] = {"IGP Router-ID", 4, 8, UNDEF_MULTPL},
	/* NRLI & BGP-LS Attributes */
	[BGP_LS_TLV_MULTI_TOPOLOGY_ID] = {"Multi-Topology ID", 2, MAX_SZ, 2},
	/* BGP-LS Attributes */
	[BGP_LS_TLV_NODE_MSD] = {"Node MSD", 2, MAX_SZ, 2},
	[BGP_LS_TLV_LINK_MSD] = {"Link MSD", 2, MAX_SZ, 2},
	[BGP_LS_TLV_BGP_ROUTER_ID] = {"BGP Router-ID", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_BGP_CONFEDERATION_MEMBER] = {"BGP Confederation Member", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_NODE_FLAG_BITS] = {"Node Flag Bits", 1, 1, UNDEF_MULTPL},
	[BGP_LS_TLV_OPAQUE_NODE_ATTRIBUTE] = {"Opaque Node Attribute", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_NODE_NAME] = {"Node Name", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IS_IS_AREA_IDENTIFIER] = {"IS-IS Area Identifier", 1, 13, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE] =	{"IPv4 Router-ID of Local Node", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE] = {"IPv6 Router-ID of Local Node", 16, 16, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE] = {"IPv4 Router-ID of Remote Node", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE] = {"IPv6 Router-ID of Remote Node", 16, 16, UNDEF_MULTPL},
	[BGP_LS_TLV_S_BFD_DISCRIMINATORS] = {"S-BFD Discriminators", 4, MAX_SZ, 4},
	[BGP_LS_TLV_SR_CAPABILITIES] = {"SR Capabilities", 12, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_ALGORITHM] = {"SR Algorithm", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_LOCAL_BLOCK] = {"SR Local Block", 12, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRMS_PREFERENCE] = {"SRMS Preference", 1, 1, UNDEF_MULTPL},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION] = {"Flexible Algorithm Definition", 4, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_ANY_AFFINITY] = {"Flexible Algorithm Exclude Any Affinity", 4, MAX_SZ, 4},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ANY_AFFINITY] = {"Flexible Algorithm Include Any Affinity", 4, MAX_SZ, 4},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ALL_AFFINITY] = {"Flexible Algorithm Include All Affinity", 4, MAX_SZ, 4},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION_FLAGS] = {"Flexible Algorithm Definition Flags", 4, MAX_SZ, 4},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_PREFIX_METRIC] = {"Flexible Algorithm Prefix Metric", 8, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_SRLG] = {"Flexible Algorithm Exclude SRLG", 4, MAX_SZ, 4},
	[BGP_LS_TLV_ADMINISTRATIVE_GROUP] = {"Administrative group", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_MAXIMUM_LINK_BANDWIDTH] = {"Maximum link bandwidth", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_MAX_RESERVABLE_LINK_BANDWIDTH] = {"Max. reservable link bandwidth", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_UNRESERVED_BANDWIDTH] = {"Unreserved bandwidth", 32, 32, UNDEF_MULTPL},
	[BGP_LS_TLV_TE_DEFAULT_METRIC] = {"TE Default Metric", 3, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_LINK_PROTECTION_TYPE] = {"Link Protection Type", 2, 2, UNDEF_MULTPL},
	[BGP_LS_TLV_MPLS_PROTOCOL_MASK] = {"MPLS Protocol Mask", 1, 1, UNDEF_MULTPL},
	[BGP_LS_TLV_IGP_METRIC] = {"IGP Metric", 1, 3, UNDEF_MULTPL},
	[BGP_LS_TLV_SHARED_RISK_LINK_GROUP] = {"Shared Risk Link Group", 4, MAX_SZ, 4},
	[BGP_LS_TLV_OPAQUE_LINK_ATTRIBUTE] = {"Opaque Link Attribute", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_LINK_NAME] = {"Link Name", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_ADJACENCY_SID] = {"Adjacency SID", 7, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_LAN_ADJACENCY_SID] = {"LAN Adjacency SID", 11, 14, UNDEF_MULTPL},
	[BGP_LS_TLV_PEERNODE_SID] = {"PeerNode SID", 7, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_PEERADJ_SID] = {"PeerAdj SID", 7, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_PEERSET_SID] = {"PeerSet SID", 7, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_RTM_CAPABILITY] = {"RTM Capability", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_LINK_DELAY] = {"Unidirectional Link Delay", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY] = {"Min/Max Unidirectional Link Delay", 8, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_DELAY_VARIATION] = {"Unidirectional Delay Variation", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_LINK_LOSS] = {"Unidirectional Link Loss", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_RESIDUAL_BANDWIDTH] = {"Unidirectional Residual Bandwidth", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_AVAILABLE_BANDWIDTH] = {"Unidirectional Available Bandwidth", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_UNIDIRECTIONAL_UTILIZED_BANDWIDTH] = {"Unidirectional Utilized Bandwidth", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_GRACEFUL_LINK_SHUTDOWN_TLV] = {"Graceful-Link-Shutdown TLV", 0, 0, UNDEF_MULTPL},
	[BGP_LS_TLV_APPLICATION_SPECIFIC_LINK_ATTRIBUTES] = {"Application-Specific Link Attributes", 11, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IGP_FLAGS] = {"IGP Flags", 1, 1, UNDEF_MULTPL},
	[BGP_LS_TLV_IGP_ROUTE_TAG] = {"IGP Route Tag", 4, MAX_SZ, 4},
	[BGP_LS_TLV_IGP_EXTENDED_ROUTE_TAG] = {"IGP Extended Route Tag", 8, MAX_SZ, 8},
	[BGP_LS_TLV_PREFIX_METRIC] = {"Prefix Metric", 3, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_OSPF_FORWARDING_ADDRESS] = {"OSPF Forwarding Address", 4, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_OPAQUE_PREFIX_ATTRIBUTE] = {"Opaque Prefix Attribute", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_PREFIX_SID] = {"Prefix-SID", 7, 8, UNDEF_MULTPL},
	[BGP_LS_TLV_RANGE] = {"Range", 11, 12, UNDEF_MULTPL},
	[BGP_LS_TLV_SID_LABEL] = {"SID/Label", 3, 4, UNDEF_MULTPL},
	[BGP_LS_TLV_PREFIX_ATTRIBUTES_FLAGS] = {"Prefix Attributes Flags", 1, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SOURCE_ROUTER_IDENTIFIER] = {"Source Router Identifier", 4, 16, UNDEF_MULTPL},
	[BGP_LS_TLV_L2_BUNDLE_MEMBER_ATTRIBUTES] = {"L2 Bundle Member Attributes", 4, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_EXTENDED_ADMINISTRATIVE_GROUP] = {"Extended Administrative Group", 4, MAX_SZ, 4},
	[BGP_LS_TLV_SOURCE_OSPF_ROUTER_ID] = {"Source OSPF Router-ID", 4, 4, UNDEF_MULTPL},
	/* display not yet supported */
	[BGP_LS_TLV_SRV6_SID_INFORMATION_TLV] = {"SRv6 SID Information TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_TUNNEL_ID_TLV] = {"Tunnel ID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_LSP_ID_TLV] = {"LSP ID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_6_TUNNEL_HEAD_END_ADDRESS_TLV] = {"IPv4/6 Tunnel Head-end address TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IPV4_6_TUNNEL_TAIL_END_ADDRESS_TLV] = {"IPv4/6 Tunnel Tail-end address TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_POLICY_CP_DESCRIPTOR_TLV] = {"SR Policy CP Descriptor TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_MPLS_LOCAL_CROSS_CONNECT_TLV] = {"MPLS Local Cross Connect TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_MPLS_CROSS_CONNECT_INTERFACE_TLV] = {"MPLS Cross Connect Interface TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_MPLS_CROSS_CONNECT_FEC_TLV] = {"MPLS Cross Connect FEC TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_CAPABILITIES_TLV] = {"SRv6 Capabilities TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_FLEXIBLE_ALGORITHM_UNSUPPORTED] = {"Flexible Algorithm Unsupported", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_END_X_SID_TLV] = {"SRv6 End.X SID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IS_IS_SRV6_LAN_END_X_SID_TLV] = {"IS-IS SRv6 LAN End.X SID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_OSPFV3_SRV6_LAN_END_X_SID_TLV] = {"OSPFv3 SRv6 LAN End.X SID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_IS_IS_FLOOD_REFLECTION] = {"IS-IS Flood Reflection", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_LOCATOR_TLV] = {"SRv6 Locator TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_MPLS_TE_POLICY_STATE_TLV] = {"MPLS-TE Policy State TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_BSID_TLV] = {"SR BSID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_CP_STATE_TLV] = {"SR CP State TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_CP_NAME_TLV] = {"SR CP Name TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_CP_CONSTRAINTS_TLV] = {"SR CP Constraints TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_SEGMENT_LIST_TLV] = {"SR Segment List TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_SEGMENT_SUB_TLV] = {"SR Segment sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_SEGMENT_LIST_METRIC_SUB_TLV] = {"SR Segment List Metric sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_AFFINITY_CONSTRAINT_SUB_TLV] = {"SR Affinity Constraint sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_SRLG_CONSTRAINT_SUB_TLV] = {"SR SRLG Constraint sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_BANDWIDTH_CONSTRAINT_SUB_TLV] = {"SR Bandwidth Constraint sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT_SUB_TLV] = {"SR Disjoint Group Constraint sub-TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_BSID_TLV] = {"SRv6 BSID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SR_POLICY_NAME_TLV] = {"SR Policy Name TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_ENDPOINT_FUNCTION_TLV] = {"SRv6 Endpoint Function TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_BGP_PEER_NODE_SID_TLV] = {"SRv6 BGP Peer Node SID TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
	[BGP_LS_TLV_SRV6_SID_STRUCTURE_TLV] = {"SRv6 SID Structure TLV", UNDEF_MIN_SZ, MAX_SZ, UNDEF_MULTPL},
};
/* clang-format on */

/* Return the TLV length is valid for the TLV type */
static bool bgp_ls_tlv_check_size(enum bgp_linkstate_tlv type, size_t length)
{
	if (type > BGP_LS_TLV_MAX ||
	    bgp_linkstate_tlv_infos[type].descr == NULL)
		/* TLV type is not defined. Cannot check size */
		return false;

	if (bgp_linkstate_tlv_infos[type].min_size > length)
		return false;
	if (bgp_linkstate_tlv_infos[type].max_size < length)
		return false;
	if (length % bgp_linkstate_tlv_infos[type].multiple != 0)
		return false;

	return true;
}

static uint8_t pnt_decode8(uint8_t **pnt)
{
	uint8_t data;

	data = **pnt;
	*pnt += 1;
	return data;
}

static uint16_t pnt_decode16(uint8_t **pnt)
{
	uint16_t data;

	*pnt = ptr_get_be16(*pnt, &data);

	return data;
}

static uint32_t pnt_decode24(uint8_t **pnt)
{
	uint8_t tmp1;
	uint16_t tmp2;

	memcpy(&tmp1, *pnt, sizeof(uint8_t));
	memcpy(&tmp2, *pnt + sizeof(uint8_t), sizeof(uint16_t));

	*pnt += 3;

	return (tmp1 << 16) | ntohs(tmp2);
}

static uint32_t pnt_decode32(uint8_t **pnt)
{
	uint32_t data;

	*pnt = (uint8_t *)ptr_get_be32(*pnt, &data);

	return data;
}

static uint64_t pnt_decode64(uint8_t **pnt)
{
	uint64_t data;

	*pnt = (uint8_t *)ptr_get_be64(*pnt, &data);

	return data;
}

static const char *bgp_ls_print_nlri_proto(enum bgp_ls_nlri_proto proto)
{
	switch (proto) {
	case BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1:
		return "ISIS-L1";
	case BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2:
		return "ISIS-L2";
	case BGP_LS_NLRI_PROTO_ID_OSPF:
		return "OSPFv2";
	case BGP_LS_NLRI_PROTO_ID_DIRECT:
		return "Direct";
	case BGP_LS_NLRI_PROTO_ID_STATIC:
		return "Static";
	case BGP_LS_NLRI_PROTO_ID_OSPFv3:
		return "OSPFv3";
	case BGP_LS_NLRI_PROTO_ID_UNKNOWN:
		return "Unknown";
	}
	return "Unknown";
}

static int bgp_linkstate_nlri_node_descriptor_decode(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, uint8_t *pnt,
	uint16_t len)
{
	uint8_t *lim = pnt + len;
	uint16_t type, length;

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_AUTONOMOUS_SYSTEM:
			if (CHECK_FLAG(
				    node_descr->flags,
				    BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM);
			node_descr->autonomous_system = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_BGP_LS_IDENTIFIER:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID);
			node_descr->bgp_ls_id = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_OSPF_AREA_ID:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_AREA_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_AREA_ID);
			node_descr->area_id = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			switch (length) {
			case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
				SET_FLAG(node_descr->flags,
					 BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID);
				memcpy(&node_descr->igp_router_id, pnt, length);
				node_descr->igp_router_id_size = length;
				pnt += length;
				break;
			default:
				zlog_err(
					"%s: received invalid IGP Router-ID length %hu",
					__func__, length);
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			}
			break;
		default:
			zlog_err(
				"%s: received an unexpected node descriptor TLV %hu",
				__func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
	}

	return BGP_NLRI_PARSE_OK;
}


static void bgp_linkstate_nlri_node_descriptor_encode(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, struct stream *s)
{
	size_t len_pos, len;

	/* TLV type */
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE))
		stream_putw(s, BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS);
	else if (CHECK_FLAG(node_descr->flags,
			    BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE))
		stream_putw(s, BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS);
	else
		/* should not happen */
		return;

	/* Size will be filled later */
	len_pos = stream_get_endp(s);
	stream_putw(s, 0);

	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM)) {
		stream_putw(s, BGP_LS_TLV_AUTONOMOUS_SYSTEM);
		stream_putw(s, 4);
		stream_putl(s, node_descr->autonomous_system);
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID)) {
		stream_putw(s, BGP_LS_TLV_BGP_LS_IDENTIFIER);
		stream_putw(s, 4);
		stream_putl(s, node_descr->bgp_ls_id);
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_AREA_ID)) {
		stream_putw(s, BGP_LS_TLV_OSPF_AREA_ID);
		stream_putw(s, IPV4_MAX_BYTELEN);
		stream_putl(s, node_descr->area_id);
	}
	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID)) {
		stream_putw(s, BGP_LS_TLV_IGP_ROUTER_ID);
		stream_putw(s, node_descr->igp_router_id_size);
		stream_put(s, &node_descr->igp_router_id,
			   node_descr->igp_router_id_size);
	}
	len = stream_get_endp(s) - len_pos - 2;

	stream_putw_at(s, len_pos, len);
}

static size_t bgp_linkstate_nlri_node_descriptor_display(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, char *buf, size_t size,
	bool multiline)
{
	bool first = true;

	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE))
		snprintf(buf, size, "%sLocal%s", multiline ? "\n" : " ",
			 multiline ? "  " : "{");
	else if (CHECK_FLAG(node_descr->flags,
			    BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE))
		snprintf(buf, size, "%sRemote%s", multiline ? "\n" : " ",
			 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM)) {
		snprintf(buf, size, "%sAS:%u", first ? "" : " ",
			 node_descr->autonomous_system);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID)) {
		snprintf(buf, size, "%sID:%u", first ? "" : " ",
			 node_descr->bgp_ls_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_AREA_ID)) {
		snprintf(buf, size, "%sArea:%u", first ? "" : " ",
			 node_descr->area_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID)) {
		switch (node_descr->igp_router_id_size) {
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pSY", first ? "" : " ",
				   (uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pPN", first ? "" : " ",
				   (uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pI4", first ? "" : " ",
				   (in_addr_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
			snprintfrr(
				buf, size, "%sRtr:%pI4:%pI4", first ? "" : " ",
				(in_addr_t *)&node_descr->igp_router_id,
				((in_addr_t *)&node_descr->igp_router_id + 1));
			break;
		}

		size -= strlen(buf);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static void bgp_linkstate_nlri_node_descriptor_json(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, json_object *json)
{
	json_object *json_node = NULL;

	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE)) {
		json_node = json_object_new_object();
		json_object_object_add(json, "local", json_node);
	} else if (CHECK_FLAG(node_descr->flags,
			      BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE)) {
		json_node = json_object_new_object();
		json_object_object_add(json, "remote", json_node);
	} else
		return;

	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM))
		json_object_int_add(json_node, "as",
				    node_descr->autonomous_system);

	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID))
		json_object_int_add(json_node, "identifier",
				    node_descr->bgp_ls_id);

	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_AREA_ID))
		json_object_int_add(json_node, "area", node_descr->area_id);

	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID)) {
		switch (node_descr->igp_router_id_size) {
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			json_object_string_addf(
				json_node, "routerID", "%pSY",
				(uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			json_object_string_addf(
				json_node, "routerId", "%pPN",
				(uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			json_object_string_addf(
				json_node, "routerID", "%pI4",
				(in_addr_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
			json_object_string_addf(
				json_node, "routerID", "%pI4:%pI4",
				(in_addr_t *)&node_descr->igp_router_id,
				((in_addr_t *)&node_descr->igp_router_id + 1));
			break;
		}
	}
}

static uint16_t
bgp_linkstate_nlri_node_prefixlen(struct bgp_linkstate_type_node *p_node)
{
	return sizeof(struct bgp_linkstate_type_node);
}

static int bgp_linkstate_nlri_node_decode(struct bgp_linkstate_type_node **pp,
					  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_node *p_node = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length;

	p_node->proto = pnt_decode8(&pnt);
	p_node->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_node->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_node->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_node->local_node_descr, pnt, length);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	return ret;
}

static void
bgp_linkstate_nlri_node_encode(struct bgp_linkstate_type_node *p_node,
			       struct stream *s)
{
	stream_putc(s, p_node->proto);
	stream_putq(s, p_node->identifier);

	bgp_linkstate_nlri_node_descriptor_encode(&p_node->local_node_descr, s);
}

static void
bgp_linkstate_nlri_node_display(char *buf, size_t size,
				struct bgp_linkstate_type_node *p_node,
				bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_node->proto), p_node->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	bgp_linkstate_nlri_node_descriptor_display(&p_node->local_node_descr,
						   buf, size, multiline);
}

static void bgp_linkstate_nlri_node_json(struct bgp_linkstate_type_node *p_node,
					 json_object *json)
{
	json_object_string_add(json, "protocol",
			       bgp_ls_print_nlri_proto(p_node->proto));
	json_object_string_addf(json, "identifier", "0x%" PRIx64,
				p_node->identifier);

	bgp_linkstate_nlri_node_descriptor_json(&p_node->local_node_descr,
						json);
}


static int bgp_linkstate_nlri_link_descriptor_decode(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags,
			 BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID);
		link_descr->local_remote_id = pnt_decode16(&pnt);
		break;
	case BGP_LS_TLV_IPV4_INTERFACE_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_INTERFACE4))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4);
		memcpy(&link_descr->interface4, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4);
		memcpy(&link_descr->neighbor4, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV6_INTERFACE_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_INTERFACE6))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6);
		memcpy(&link_descr->interface6, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6);
		memcpy(&link_descr->neighbor6, pnt, length);
		*pnt += length;
		break;
	default:
		assert(!"NLRI link descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static void bgp_linkstate_nlri_link_descriptor_encode(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, struct stream *s)
{
	uint16_t *pnt;

	if (CHECK_FLAG(link_descr->flags,
		       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID)) {
		stream_putw(s, BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS);
		stream_putw(s, 2);
		stream_putw(s, link_descr->local_remote_id);
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4)) {
		stream_putw(s, BGP_LS_TLV_IPV4_INTERFACE_ADDRESS);
		stream_putw(s, IPV4_MAX_BYTELEN);
		stream_put_in_addr(s, &link_descr->interface4);
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4)) {
		stream_putw(s, BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS);
		stream_putw(s, IPV4_MAX_BYTELEN);
		stream_put_in_addr(s, &link_descr->neighbor4);
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6)) {
		stream_putw(s, BGP_LS_TLV_IPV6_INTERFACE_ADDRESS);
		stream_putw(s, IPV6_MAX_BYTELEN);
		stream_put(s, &link_descr->interface6, IPV6_MAX_BYTELEN);
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6)) {
		stream_putw(s, BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS);
		stream_putw(s, IPV6_MAX_BYTELEN);
		stream_put(s, &link_descr->neighbor6, IPV6_MAX_BYTELEN);
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_MT_ID)) {
		stream_putw(s, BGP_LS_TLV_MULTI_TOPOLOGY_ID);
		stream_putw(s, link_descr->mtid.length);
		pnt = (uint16_t *)&link_descr->mtid.data;
		for (int i = 0; i < (link_descr->mtid.length / 2); i++)
			stream_putw(s, pnt[i]);
	}
}

static size_t
bgp_linkstate_nlri_mtid_display(struct bgp_ls_tlv_generic *mtid_tlv, char *buf,
				size_t size, bool first)
{
	uint16_t *mtid;

	mtid = (uint16_t *)&mtid_tlv->data;
	for (int i = 0; i < (mtid_tlv->length / 2); i++) {
		if (i == 0)
			snprintf(buf, size, "%sMT:%hu", first ? "" : " ",
				 mtid[i]);
		else
			snprintf(buf, size, ",%hu", mtid[i]);
		size -= strlen(buf);
		buf += strlen(buf);
	}
	return size;
}

static size_t bgp_linkstate_nlri_link_descriptor_display(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, char *buf, size_t size,
	bool multiline)
{
	bool first = true;

	if (link_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sLink%s", multiline ? "\n" : " ",
		 multiline ? "   " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(link_descr->flags,
		       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID)) {
		snprintf(buf, size, "%sLocal/remote:%hu", first ? "" : " ",
			 link_descr->local_remote_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4)) {
		snprintfrr(buf, size, "%sIPv4:%pI4", first ? "" : " ",
			   &link_descr->interface4);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4)) {
		snprintfrr(buf, size, "%sNeigh-IPv4:%pI4", first ? "" : " ",
			   &link_descr->neighbor4);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6)) {
		snprintfrr(buf, size, "%sIPv6:%pI6", first ? "" : " ",
			   &link_descr->interface6);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6)) {
		snprintfrr(buf, size, "%sNeigh-IPv6:%pI6", first ? "" : " ",
			   &link_descr->neighbor6);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&link_descr->mtid, buf,
						       size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static void bgp_linkstate_nlri_link_descriptor_json(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, json_object *json)
{
	json_object *json_link = NULL;
	char buf[512];

	if (link_descr->flags == 0)
		return;

	json_link = json_object_new_object();

	json_object_object_add(json, "link", json_link);

	if (CHECK_FLAG(link_descr->flags,
		       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID))
		json_object_int_add(json_link, "localRemoteID",
				    link_descr->local_remote_id);

	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4))
		json_object_string_addf(json_link, "interfaceIPv4", "%pI4",
					&link_descr->interface4);

	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4))
		json_object_string_addf(json_link, "neighborIPv4", "%pI4",
					&link_descr->neighbor4);

	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6))
		json_object_string_addf(json_link, "interfaceIPv6", "%pI6",
					&link_descr->interface6);

	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6))
		json_object_string_addf(json_link, "neighborIPv6", "%pI6",
					&link_descr->neighbor6);

	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_MT_ID)) {
		bgp_linkstate_nlri_mtid_display(&link_descr->mtid, buf,
						sizeof(buf), false);
		json_object_string_add(json_link, "mtID", buf);
	}
}

static uint16_t
bgp_linkstate_nlri_link_prefixlen(struct bgp_linkstate_type_link *p_link)
{
	return sizeof(struct bgp_linkstate_type_link) +
	       p_link->link_descr.mtid.length;
}

static int bgp_linkstate_nlri_link_decode(struct bgp_linkstate_type_link **pp,
					  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_link *p_link = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length, *dst, *src;

	p_link->proto = pnt_decode8(&pnt);
	p_link->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_link->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_link->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS:
			if (p_link->remote_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->remote_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_link->remote_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
		case BGP_LS_TLV_IPV4_INTERFACE_ADDRESS:
		case BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS:
		case BGP_LS_TLV_IPV6_INTERFACE_ADDRESS:
		case BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS:
			bgp_linkstate_nlri_link_descriptor_decode(
				&p_link->link_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_link->link_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->link_descr.flags,
				 BGP_NLRI_TLV_LINK_DESCR_MT_ID);
			*pp = XREALLOC(MTYPE_BGP_LS_TYPE_LINK, *pp,
				       sizeof(struct bgp_linkstate_type_link) +
					       length);
			p_link = *pp;
			p_link->link_descr.mtid.length = length;
			dst = (uint16_t *)&p_link->link_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_link->local_node_descr.flags == 0 ||
	    p_link->remote_node_descr.flags == 0)
		/* Local and remote nodes are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}

static void
bgp_linkstate_nlri_link_encode(struct bgp_linkstate_type_link *p_link,
			       struct stream *s)
{
	stream_putc(s, p_link->proto);
	stream_putq(s, p_link->identifier);

	bgp_linkstate_nlri_node_descriptor_encode(&p_link->local_node_descr, s);
	bgp_linkstate_nlri_node_descriptor_encode(&p_link->remote_node_descr,
						  s);
	bgp_linkstate_nlri_link_descriptor_encode(&p_link->link_descr, s);
}

static void
bgp_linkstate_nlri_link_display(char *buf, size_t size,
				struct bgp_linkstate_type_link *p_link,
				bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_link->proto), p_link->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_link->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_link->remote_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_link_descriptor_display(&p_link->link_descr, buf,
						   size, multiline);
}

static void bgp_linkstate_nlri_link_json(struct bgp_linkstate_type_link *p_link,
					 json_object *json)
{
	json_object_string_add(json, "protocol",
			       bgp_ls_print_nlri_proto(p_link->proto));
	json_object_string_addf(json, "identifier", "0x%" PRIx64,
				p_link->identifier);

	bgp_linkstate_nlri_node_descriptor_json(&p_link->local_node_descr,
						json);
	bgp_linkstate_nlri_node_descriptor_json(&p_link->remote_node_descr,
						json);
	bgp_linkstate_nlri_link_descriptor_json(&p_link->link_descr, json);
}

static int bgp_linkstate_nlri_prefix4_descriptor_decode(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		if (CHECK_FLAG(prefix4_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix4_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE);
		prefix4_descr->ospf_route_type = pnt_decode8(&pnt);
		break;
	case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
		if (CHECK_FLAG(prefix4_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix4_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY);
		prefix4_descr->ip_reachability_prefixlen = pnt_decode8(&pnt);
		memcpy(&prefix4_descr->ip_reachability_prefix.s_addr, pnt,
		       length - sizeof(prefix4_descr
					       ->ip_reachability_prefixlen));
		break;
	default:
		assert(!"NLRI prefix4 descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static void bgp_linkstate_nlri_prefix4_descriptor_encode(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, struct stream *s)
{
	uint16_t *pnt;
	uint8_t length;

	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		stream_putw(s, BGP_LS_TLV_OSPF_ROUTE_TYPE);
		stream_putw(s, 1);
		stream_putc(s, prefix4_descr->ospf_route_type);
	}
	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		/* The Type and Length fields of the TLV are defined in Table 6.
		 * The following two fields determine the reachability
		 * information of the address family.  The Prefix Length field
		 * contains the length of the prefix in bits.  The IP Prefix
		 * field contains the most significant octets of the prefix,
		 * i.e., 1 octet for prefix length 1 up to 8, 2 octets for
		 * prefix length 9 to 16, 3 octets for prefix length 17 up to
		 * 24, 4 octets for prefix length 25 up to 32, etc.
		 */
		stream_putw(s, BGP_LS_TLV_IP_REACHABILITY_INFORMATION);
		length = (prefix4_descr->ip_reachability_prefixlen - 1) / 8 + 1;
		stream_putw(
			s,
			length + sizeof(prefix4_descr
						->ip_reachability_prefixlen));
		stream_putc(s, prefix4_descr->ip_reachability_prefixlen);
		stream_put(s, &prefix4_descr->ip_reachability_prefix, length);
	}
	if (CHECK_FLAG(prefix4_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		stream_putw(s, BGP_LS_TLV_MULTI_TOPOLOGY_ID);
		stream_putw(s, prefix4_descr->mtid.length);
		pnt = (uint16_t *)&prefix4_descr->mtid.data;
		for (int i = 0; i < (prefix4_descr->mtid.length / 2); i++)
			stream_putw(s, pnt[i]);
	}
}

static size_t bgp_linkstate_nlri_prefix4_descriptor_display(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, char *buf,
	size_t size, bool multiline)
{
	bool first = true;

	if (prefix4_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sPrefix%s", multiline ? "\n" : " ",
		 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		snprintf(buf, size, "%sOSPF-Route-Type:%u", first ? "" : " ",
			 prefix4_descr->ospf_route_type);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		snprintfrr(buf, size, "%sIPv4:%pI4/%u", first ? "" : " ",
			   &prefix4_descr->ip_reachability_prefix,
			   prefix4_descr->ip_reachability_prefixlen);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix4_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&prefix4_descr->mtid,
						       buf, size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static void bgp_linkstate_nlri_prefix4_descriptor_json(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, json_object *json)
{
	json_object *json_prefix4 = NULL;
	char buf[512];

	if (prefix4_descr->flags == 0)
		return;

	json_prefix4 = json_object_new_object();
	json_object_object_add(json, "ipv4Prefix", json_prefix4);

	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE))
		json_object_int_add(json_prefix4, "ospfRouteType",
				    prefix4_descr->ospf_route_type);

	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
		json_object_string_addf(
			json_prefix4, "ipReachability", "%pI4/%u",
			&prefix4_descr->ip_reachability_prefix,
			prefix4_descr->ip_reachability_prefixlen);

	if (CHECK_FLAG(prefix4_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		bgp_linkstate_nlri_mtid_display(&prefix4_descr->mtid, buf,
						sizeof(buf), false);
		json_object_string_add(json_prefix4, "mtID", buf);
	}
}

static uint16_t bgp_linkstate_nlri_prefix4_prefixlen(
	struct bgp_linkstate_type_prefix4 *p_prefix4)
{
	return sizeof(struct bgp_linkstate_type_prefix4) +
	       p_prefix4->prefix_descr.mtid.length;
}

static int
bgp_linkstate_nlri_prefix4_decode(struct bgp_linkstate_type_prefix4 **pp,
				  uint8_t *pnt, uint16_t len)
{
	struct bgp_linkstate_type_prefix4 *p_prefix4 = *pp;
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	uint16_t *dst, *src;

	p_prefix4->proto = pnt_decode8(&pnt);
	p_prefix4->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_prefix4->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix4->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_prefix4->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
			ret = bgp_linkstate_nlri_prefix4_descriptor_decode(
				&p_prefix4->prefix_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_prefix4->prefix_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix4->prefix_descr.flags,
				 BGP_NLRI_TLV_PREFIX_DESCR_MT_ID);
			*pp = XREALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX4, *pp,
				sizeof(struct bgp_linkstate_type_prefix4) +
					length);
			p_prefix4 = *pp;
			p_prefix4->prefix_descr.mtid.length = length;
			dst = (uint16_t *)&p_prefix4->prefix_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_prefix4->local_node_descr.flags == 0 ||
	    p_prefix4->prefix_descr.flags == 0)
		/* Local node and prefix info are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}

static void
bgp_linkstate_nlri_prefix4_encode(struct bgp_linkstate_type_prefix4 *p_prefix4,
				  struct stream *s)
{
	stream_putc(s, p_prefix4->proto);
	stream_putq(s, p_prefix4->identifier);

	bgp_linkstate_nlri_node_descriptor_encode(&p_prefix4->local_node_descr,
						  s);
	bgp_linkstate_nlri_prefix4_descriptor_encode(&p_prefix4->prefix_descr,
						     s);
}

static void
bgp_linkstate_nlri_prefix4_display(char *buf, size_t size,
				   struct bgp_linkstate_type_prefix4 *p_prefix4,
				   bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_prefix4->proto),
		   p_prefix4->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_prefix4->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_prefix4_descriptor_display(&p_prefix4->prefix_descr,
						      buf, size, multiline);
}

static void
bgp_linkstate_nlri_prefix4_json(struct bgp_linkstate_type_prefix4 *p_prefix4,
				json_object *json)
{
	json_object_string_add(json, "protocol",
			       bgp_ls_print_nlri_proto(p_prefix4->proto));
	json_object_string_addf(json, "identifier", "0x%" PRIx64,
				p_prefix4->identifier);

	bgp_linkstate_nlri_node_descriptor_json(&p_prefix4->local_node_descr,
						json);

	bgp_linkstate_nlri_prefix4_descriptor_json(&p_prefix4->prefix_descr,
						   json);
}

static int bgp_linkstate_nlri_prefix6_descriptor_decode(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		if (CHECK_FLAG(prefix6_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix6_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE);
		prefix6_descr->ospf_route_type = pnt_decode8(&pnt);
		break;
	case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
		if (CHECK_FLAG(prefix6_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix6_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY);
		prefix6_descr->ip_reachability_prefixlen = pnt_decode8(&pnt);
		memcpy(&prefix6_descr->ip_reachability_prefix, pnt,
		       length - sizeof(prefix6_descr
					       ->ip_reachability_prefixlen));
		break;
	default:
		assert(!"NLRI prefix6 descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static void bgp_linkstate_nlri_prefix6_descriptor_encode(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, struct stream *s)
{
	uint16_t *pnt;
	uint8_t length;

	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		stream_putw(s, BGP_LS_TLV_OSPF_ROUTE_TYPE);
		stream_putw(s, 1);
		stream_putc(s, prefix6_descr->ospf_route_type);
	}
	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		/* The Type and Length fields of the TLV are defined in Table 6.
		 * The following two fields determine the reachability
		 * information of the address family.  The Prefix Length field
		 * contains the length of the prefix in bits.  The IP Prefix
		 * field contains the most significant octets of the prefix,
		 * i.e., 1 octet for prefix length 1 up to 8, 2 octets for
		 * prefix length 9 to 16, 3 octets for prefix length 17 up to
		 * 24, 4 octets for prefix length 25 up to 32, etc.
		 */
		stream_putw(s, BGP_LS_TLV_IP_REACHABILITY_INFORMATION);
		length = (prefix6_descr->ip_reachability_prefixlen - 1) / 8 + 1;
		stream_putw(
			s,
			length + sizeof(prefix6_descr
						->ip_reachability_prefixlen));
		stream_putc(s, prefix6_descr->ip_reachability_prefixlen);
		stream_put(s, &prefix6_descr->ip_reachability_prefix, length);
	}
	if (CHECK_FLAG(prefix6_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		stream_putw(s, BGP_LS_TLV_MULTI_TOPOLOGY_ID);
		stream_putw(s, prefix6_descr->mtid.length);
		pnt = (uint16_t *)&prefix6_descr->mtid.data;
		for (int i = 0; i < (prefix6_descr->mtid.length / 2); i++)
			stream_putw(s, pnt[i]);
	}
}

static size_t bgp_linkstate_nlri_prefix6_descriptor_display(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, char *buf,
	size_t size, bool multiline)
{
	bool first = true;

	if (prefix6_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sPrefix%s", multiline ? "\n" : " ",
		 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		snprintf(buf, size, "%sOSPF-Route-Type:%u", first ? "" : " ",
			 prefix6_descr->ospf_route_type);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		snprintfrr(buf, size, "%sIPv6:%pI6/%u", first ? "" : " ",
			   &prefix6_descr->ip_reachability_prefix,
			   prefix6_descr->ip_reachability_prefixlen);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix6_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&prefix6_descr->mtid,
						       buf, size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}


static void bgp_linkstate_nlri_prefix6_descriptor_json(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, json_object *json)
{
	json_object *json_prefix6 = NULL;
	char buf[512];

	if (prefix6_descr->flags == 0)
		return;

	json_prefix6 = json_object_new_object();
	json_object_object_add(json, "ipv6Prefix", json_prefix6);

	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE))
		json_object_int_add(json_prefix6, "ospfRouteType",
				    prefix6_descr->ospf_route_type);

	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
		json_object_string_addf(
			json_prefix6, "ipReachability", "%pI6/%u",
			&prefix6_descr->ip_reachability_prefix,
			prefix6_descr->ip_reachability_prefixlen);

	if (CHECK_FLAG(prefix6_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		bgp_linkstate_nlri_mtid_display(&prefix6_descr->mtid, buf,
						sizeof(buf), false);
		json_object_string_add(json_prefix6, "mtID", buf);
	}
}

static uint16_t bgp_linkstate_nlri_prefix6_prefixlen(
	struct bgp_linkstate_type_prefix6 *p_prefix6)
{
	return sizeof(struct bgp_linkstate_type_prefix6) +
	       p_prefix6->prefix_descr.mtid.length;
}

static int
bgp_linkstate_nlri_prefix6_decode(struct bgp_linkstate_type_prefix6 **pp,
				  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_prefix6 *p_prefix6 = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	uint16_t *dst, *src;

	p_prefix6->proto = pnt_decode8(&pnt);
	p_prefix6->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_prefix6->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix6->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_prefix6->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
			ret = bgp_linkstate_nlri_prefix6_descriptor_decode(
				&p_prefix6->prefix_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_prefix6->prefix_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix6->prefix_descr.flags,
				 BGP_NLRI_TLV_PREFIX_DESCR_MT_ID);
			*pp = XREALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX6, *pp,
				sizeof(struct bgp_linkstate_type_prefix6) +
					length);
			p_prefix6 = *pp;
			p_prefix6->prefix_descr.mtid.length = length;
			dst = (uint16_t *)&p_prefix6->prefix_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_prefix6->local_node_descr.flags == 0 ||
	    p_prefix6->prefix_descr.flags == 0)
		/* Local node and prefix info are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}


static void
bgp_linkstate_nlri_prefix6_encode(struct bgp_linkstate_type_prefix6 *p_prefix6,
				  struct stream *s)
{
	stream_putc(s, p_prefix6->proto);
	stream_putq(s, p_prefix6->identifier);

	bgp_linkstate_nlri_node_descriptor_encode(&p_prefix6->local_node_descr,
						  s);
	bgp_linkstate_nlri_prefix6_descriptor_encode(&p_prefix6->prefix_descr,
						     s);
}

static void
bgp_linkstate_nlri_prefix6_display(char *buf, size_t size,
				   struct bgp_linkstate_type_prefix6 *p_prefix6,
				   bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_prefix6->proto),
		   p_prefix6->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_prefix6->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_prefix6_descriptor_display(&p_prefix6->prefix_descr,
						      buf, size, multiline);
}

static void
bgp_linkstate_nlri_prefix6_json(struct bgp_linkstate_type_prefix6 *p_prefix6,
				json_object *json)
{
	json_object_string_add(json, "protocol",
			       bgp_ls_print_nlri_proto(p_prefix6->proto));
	json_object_string_addf(json, "identifier", "0x%" PRIx64,
				p_prefix6->identifier);

	bgp_linkstate_nlri_node_descriptor_json(&p_prefix6->local_node_descr,
						json);

	bgp_linkstate_nlri_prefix6_descriptor_json(&p_prefix6->prefix_descr,
						   json);
}

int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
			     struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint16_t psize = 0;
	struct prefix p;
	struct bgp_linkstate_type_node *p_node = NULL;
	struct bgp_linkstate_type_link *p_link = NULL;
	struct bgp_linkstate_type_prefix4 *p_prefix4 = NULL;
	struct bgp_linkstate_type_prefix6 *p_prefix6 = NULL;
	int ret;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All linkstate NLRI begin with NRLI type and length. */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		p.u.prefix_linkstate.nlri_type = pnt_decode16(&pnt);
		psize = pnt_decode16(&pnt);
		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			flog_err(
				EC_BGP_LINKSTATE_PACKET,
				"Link-State NLRI length inconsistent (size %u seen)",
				psize);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}
		p.family = AF_LINKSTATE;

		switch (p.u.prefix_linkstate.nlri_type) {
		case BGP_LINKSTATE_NODE:
			p_node =
				XCALLOC(MTYPE_BGP_LS_TYPE_NODE,
					sizeof(struct bgp_linkstate_type_node));
			ret = bgp_linkstate_nlri_node_decode(&p_node, pnt,
							     psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_NODE, p_node);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_node;
			p.prefixlen = bgp_linkstate_nlri_node_prefixlen(p_node);
			break;
		case BGP_LINKSTATE_LINK:
			p_link =
				XCALLOC(MTYPE_BGP_LS_TYPE_LINK,
					sizeof(struct bgp_linkstate_type_link));
			ret = bgp_linkstate_nlri_link_decode(&p_link, pnt,
							     psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_LINK, p_link);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_link;
			p.prefixlen = bgp_linkstate_nlri_link_prefixlen(p_link);
			break;
		case BGP_LINKSTATE_PREFIX4:
			p_prefix4 = XCALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX4,
				sizeof(struct bgp_linkstate_type_prefix4));
			ret = bgp_linkstate_nlri_prefix4_decode(&p_prefix4, pnt,
								psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_PREFIX4, p_prefix4);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_prefix4;
			p.prefixlen =
				bgp_linkstate_nlri_prefix4_prefixlen(p_prefix4);
			break;
		case BGP_LINKSTATE_PREFIX6:
			p_prefix6 = XCALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX6,
				sizeof(struct bgp_linkstate_type_prefix6));
			ret = bgp_linkstate_nlri_prefix6_decode(&p_prefix6, pnt,
								psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_PREFIX6, p_prefix6);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_prefix6;
			p.prefixlen =
				bgp_linkstate_nlri_prefix6_prefixlen(p_prefix6);
			break;
		}

		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("LS Rx %s %s %pFX",
				   withdraw ? "Withdraw" : "Update",
				   afi2str(afi), &p);
		}

		/* Process the route. */
		if (withdraw)
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		else
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);

		switch (p.u.prefix_linkstate.nlri_type) {
		case BGP_LINKSTATE_NODE:
			XFREE(MTYPE_BGP_LS_TYPE_NODE, p_node);
			break;
		case BGP_LINKSTATE_LINK:
			XFREE(MTYPE_BGP_LS_TYPE_LINK, p_link);
			break;
		case BGP_LINKSTATE_PREFIX4:
			XFREE(MTYPE_BGP_LS_TYPE_PREFIX4, p_prefix4);
			break;
		case BGP_LINKSTATE_PREFIX6:
			XFREE(MTYPE_BGP_LS_TYPE_PREFIX6, p_prefix6);
			break;
		}
	}
	return BGP_NLRI_PARSE_OK;
}

char *bgp_linkstate_nlri_prefix_display(char *buf, size_t size,
					uint16_t nlri_type, void *prefix)
{
	char *cbuf = buf;

	snprintf(buf, size, "%s", bgp_linkstate_nlri_type_2str(nlri_type));
	size -= strlen(buf);
	buf += strlen(buf);

	switch (nlri_type) {
	case BGP_LINKSTATE_NODE:
		bgp_linkstate_nlri_node_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_LINK:
		bgp_linkstate_nlri_link_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_PREFIX4:
		bgp_linkstate_nlri_prefix4_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_PREFIX6:
		bgp_linkstate_nlri_prefix6_display(buf, size, prefix, false);
		break;
	}

	return cbuf;
}

void bgp_linkstate_nlri_prefix_json(json_object *json, uint16_t nlri_type,
				    void *prefix)
{
	json_object *json_type = json_object_new_object();

	json_object_object_add(json, "linkStateNLRI", json_type);

	switch (nlri_type) {
	case BGP_LINKSTATE_NODE:
		json_object_string_add(json_type, "nlriType", "node");
		bgp_linkstate_nlri_node_json(prefix, json_type);
		break;
	case BGP_LINKSTATE_LINK:
		json_object_string_add(json_type, "nlriType", "link");
		bgp_linkstate_nlri_link_json(prefix, json_type);
		break;
	case BGP_LINKSTATE_PREFIX4:
		json_object_string_add(json_type, "nlriType", "IPv4 prefix");
		bgp_linkstate_nlri_prefix4_json(prefix, json_type);
		break;
	case BGP_LINKSTATE_PREFIX6:
		json_object_string_add(json_type, "nlriType", "IPv6 prefix");
		bgp_linkstate_nlri_prefix6_json(prefix, json_type);
		break;
	default:
		assert(!"Unsupported Link-State NLRI type");
	}
}

/*
 * Encode Link-State prefix in Update (MP_REACH)
 */
void bgp_nlri_encode_linkstate(struct stream *s, const struct prefix *p)
{
	struct prefix_linkstate *p_ls = (struct prefix_linkstate *)p;
	size_t len_pos, len;

	/* NLRI type */
	stream_putw(s, p->u.prefix_linkstate.nlri_type);

	/* Size will be filled later */
	len_pos = stream_get_endp(s);
	stream_putw(s, 0);

	switch (p_ls->prefix.nlri_type) {
	case BGP_LINKSTATE_NODE:
		bgp_linkstate_nlri_node_encode(
			(struct bgp_linkstate_type_node *)p_ls->prefix.ptr, s);
		break;
	case BGP_LINKSTATE_LINK:
		bgp_linkstate_nlri_link_encode(
			(struct bgp_linkstate_type_link *)p_ls->prefix.ptr, s);
		break;
	case BGP_LINKSTATE_PREFIX4:
		bgp_linkstate_nlri_prefix4_encode(
			(struct bgp_linkstate_type_prefix4 *)p_ls->prefix.ptr,
			s);
		break;
	case BGP_LINKSTATE_PREFIX6:
		bgp_linkstate_nlri_prefix6_encode(
			(struct bgp_linkstate_type_prefix6 *)p_ls->prefix.ptr,
			s);
		break;
	}

	len = stream_get_endp(s) - len_pos - 2;

	stream_putw_at(s, len_pos, len);
}


static uint8_t *bgp_linkstate_tlv_binary_string(char *buf, size_t buf_sz,
						uint8_t *pnt, uint16_t psize)
{
	uint8_t tmp;
	int i, j;

	for (i = 0; i < psize; i++) {
		if (i == 0)
			snprintf(buf, buf_sz, "0b");
		else
			snprintf(buf + strlen(buf), buf_sz - strlen(buf), " ");
		tmp = pnt_decode8(&pnt);
		for (j = 7; j >= 0; j--)
			snprintf(buf + strlen(buf), buf_sz - strlen(buf), "%d",
				 (tmp >> j) & 1);
	}

	return pnt;
}

/* dump bits. Their meaning is not decoded */
static uint8_t *bgp_linkstate_tlv_binary_display(struct vty *vty, uint8_t *pnt,
						 uint16_t psize,
						 json_object *json)
{
	char buf[290];
	uint8_t tmp;
	int i, j;

	if (json) {
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt,
						      psize);
		json_object_string_add(json, "data", buf);
		return pnt;
	}

	for (i = 0; i < psize; i++) {
		if (i == 0)
			vty_out(vty, "0b");
		else
			vty_out(vty, " ");
		tmp = pnt_decode8(&pnt);
		for (j = 7; j >= 0; j--)
			vty_out(vty, "%d", (tmp >> j) & 1);
	}
	vty_out(vty, "\n");

	return pnt;
}

static void bgp_linkstate_tlv_hexa_display(struct vty *vty, uint8_t *pnt,
					   uint16_t length, json_object *json)
{
	json_object *json_array = NULL;
	uint8_t *lim = pnt + length;
	char buf[11];
	int i;

	if (json) {
		if (length > 8) {
			json_array = json_object_new_array();
			json_object_object_add(json, "data", json_array);
			for (i = 0; pnt < lim; pnt++, i++) {
				if (i % 8 == 0) {
					if (i != 0)
						json_object_array_add(
							json_array,
							json_object_new_string(
								buf));
					snprintf(buf, sizeof(buf), "0x");
				}
				snprintf(buf + strlen(buf),
					 sizeof(buf) - strlen(buf), "%02x",
					 *pnt);
			}
			if (strlen(buf) > 2) /* do not only contain 0x */
				json_object_array_add(
					json_array,
					json_object_new_string(buf));
		} else {
			snprintf(buf, sizeof(buf), "0x");
			for (; pnt < lim; pnt++)
				snprintf(buf + strlen(buf),
					 sizeof(buf) - strlen(buf), "%02x",
					 *pnt);
			json_object_string_add(json, "data", buf);
		}
		return;
	}

	vty_out(vty, "0x");
	for (i = 0; pnt < lim; pnt++, i++) {
		if (i != 0 && i % 8 == 0)
			vty_out(vty, " ");
		vty_out(vty, "%02x", *pnt);
	}
	vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_integer_list_display(struct vty *vty,
						   uint8_t *pnt,
						   uint16_t length,
						   uint8_t integer_sz,
						   json_object *json)
{
	json_object *json_array = NULL;
	int i;

	if (json) {
		json_array = json_object_new_array();
		json_object_object_add(json, "data", json_array);
	}

	for (i = 0; i < (length / integer_sz); i++) {
		switch (integer_sz) {
		case 1:
			if (json) {
				json_object_array_add(
					json_array,
					json_object_new_int(pnt_decode8(&pnt)));
				break;
			}
			vty_out(vty, "%s%u", i == 0 ? "" : ", ",
				pnt_decode8(&pnt));
			break;
		case 2:
			if (json) {
				json_object_array_add(
					json_array,
					json_object_new_int(
						pnt_decode16(&pnt)));
				break;
			}
			vty_out(vty, "%s%u", i == 0 ? "" : ", ",
				pnt_decode16(&pnt));
			break;
		case 4:
			if (json) {
				json_object_array_add(
					json_array,
					json_object_new_int(
						pnt_decode32(&pnt)));
				break;
			}
			vty_out(vty, "%s%u", i == 0 ? "" : ", ",
				pnt_decode32(&pnt));
			break;
		case 8:
			if (json) {
				json_object_array_add(
					json_array,
					json_object_new_int64(
						pnt_decode64(&pnt)));
				break;
			}
			vty_out(vty, "%s%" PRIu64, i == 0 ? "" : ", ",
				pnt_decode64(&pnt));
			break;
		}
	}
	vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_integer_display(struct vty *vty, uint8_t *pnt,
					      uint16_t length,
					      json_object *json)
{
	switch (length) {
	case 1:
		if (json) {
			json_object_int_add(json, "data", pnt_decode8(&pnt));
			break;
		}
		vty_out(vty, "%u\n", pnt_decode8(&pnt));
		break;
	case 2:
		if (json) {
			json_object_int_add(json, "data", pnt_decode16(&pnt));
			break;
		}
		vty_out(vty, "%u\n", pnt_decode16(&pnt));
		break;
	case 3:
		if (json) {
			json_object_int_add(json, "data", pnt_decode24(&pnt));
			break;
		}
		vty_out(vty, "%u\n", pnt_decode24(&pnt));
		break;
	case 4:
		if (json) {
			json_object_int_add(json, "data", pnt_decode32(&pnt));
			break;
		}
		vty_out(vty, "%u\n", pnt_decode32(&pnt));
		break;
	case 8:
		if (json) {
			json_object_int_add(json, "data", pnt_decode64(&pnt));
			break;
		}
		vty_out(vty, "%" PRIu64 "\n", pnt_decode64(&pnt));
		break;
	}
}

static void bgp_linkstate_tlv_ipv4_6_address_display(struct vty *vty,
						     uint8_t *pnt,
						     uint16_t length,
						     json_object *json)
{
	if (length == IPV4_MAX_BYTELEN) {
		if (json) {
			json_object_string_addf(json, "data", "%pI4",
						(in_addr_t *)pnt);
			return;
		}
		vty_out(vty, "%pI4\n", (in_addr_t *)pnt);
	} else if (length == IPV6_MAX_BYTELEN) {
		if (json) {
			json_object_string_addf(json, "data", "%pI6",
						(struct in6_addr *)pnt);
			return;
		}
		vty_out(vty, "%pI6\n", (struct in6_addr *)pnt);
	} else
		bgp_linkstate_tlv_hexa_display(vty, pnt, length, json);
}

static void bgp_linkstate_tlv_name_display(struct vty *vty, uint8_t *pnt,
					   uint16_t length, json_object *json)
{
	char buf[length + 1];
	int i;

	buf[0] = '\0';
	for (i = 0; i < length; i++)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%c",
			 pnt_decode8(&pnt));

	if (json)
		json_object_string_add(json, "data", buf);
	else
		vty_out(vty, "%s\n", buf);
}

static void bgp_linkstate_tlv_msd_display(struct vty *vty, uint8_t *pnt,
					  uint16_t length, int indent,
					  json_object *json)
{
	json_object *json_array = NULL;
	json_object *json_data = NULL;
	int i;

	if (json) {
		json_array = json_object_new_array();
		json_object_object_add(json, "data", json_array);
	}

	for (i = 0; i < (length / 2); i++) {
		if (json) {
			json_data = json_object_new_object();
			json_object_array_add(json_array, json_data);
			json_object_int_add(json_data, "type",
					    pnt_decode8(&pnt));
			json_object_int_add(json_data, "value",
					    pnt_decode8(&pnt));
			continue;
		}
		vty_out(vty, "\n%*sType: %u Value: %u", indent, "",
			pnt_decode8(&pnt), pnt_decode8(&pnt));
	}

	if (!json)
		vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_bandwidth_display(struct vty *vty, uint8_t *pnt,
						uint16_t length,
						json_object *json)
{
	union {
		float r;
		uint32_t d;
	} float_uint32;

	float_uint32.d = pnt_decode32(&pnt);

	if (json) {
		json_object_double_add(json, "data", float_uint32.r);
		json_object_string_add(json, "dataUnit", "bps");
		return;
	}
	vty_out(vty, "%g Mbps\n", float_uint32.r / 1000 / 1000 * 8);
}

static void bgp_linkstate_tlv_unreserved_bandwidth_display(struct vty *vty,
							   uint8_t *pnt,
							   uint16_t length,
							   int indent,
							   json_object *json)
{
	json_object *json_data = NULL;
	union {
		float r;
		uint32_t d;
	} float_uint32;
	char buf[3];
	int i;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		for (i = 0; i < MAX_CLASS_TYPE; i++) {
			float_uint32.d = pnt_decode32(&pnt);
			snprintf(buf, sizeof(buf), "%d", i);
			json_object_double_add(json_data, buf, float_uint32.r);
		}
		json_object_string_add(json, "dataUnit", "bps");
		return;
	}

	for (i = 0; i < MAX_CLASS_TYPE; i += 2) {
		float_uint32.d = pnt_decode32(&pnt);
		vty_out(vty, "\n%*s[%d]: %g Mbps  ", indent, "", i,
			float_uint32.r / 1000 / 1000 * 8);
		float_uint32.d = pnt_decode32(&pnt);
		vty_out(vty, "[%d]: %g Mbps", i + 1,
			float_uint32.r / 1000 / 1000 * 8);
	}
	vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_sid_display(struct vty *vty, uint8_t *pnt,
					  uint16_t length, uint16_t code_point,
					  int indent, json_object *json)
{
	json_object *json_data = NULL;
	char buf[11];
	uint32_t sid;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
	}

	if (json) {
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt, 1);
		json_object_string_add(json_data, "flags", buf);
	} else {
		vty_out(vty, "\n%*sFlags: ", indent, "");
		pnt = bgp_linkstate_tlv_binary_display(vty, pnt, 1, json);
	}

	if (code_point == BGP_LS_TLV_PREFIX_SID) {
		if (json)
			json_object_int_add(json_data, "algorithm",
					    pnt_decode8(&pnt));
		else
			vty_out(vty, "%*sAlgorithm: %u\n", indent, "",
				pnt_decode8(&pnt));
	} else {
		if (json)
			json_object_int_add(json_data, "weight",
					    pnt_decode8(&pnt));
		else
			vty_out(vty, "%*sWeight: %u\n", indent, "",
				pnt_decode8(&pnt));
	}

	pnt += 2; /* ignore reserved 2 bytes */

	if (code_point == BGP_LS_TLV_LAN_ADJACENCY_SID) {
		vty_out(vty, "%*sNeighbor ID:", indent, "");
		if (length == 11 || length == 12) {
			/* OSPF Router-ID */
			if (json)
				json_object_string_addf(json_data, "neighborId",
							"%pI4\n",
							(in_addr_t *)pnt);
			else
				vty_out(vty, "%pI4\n", (in_addr_t *)pnt);
			pnt += 4;
		} else {
			/* IS-IS System-ID */
			if (json)
				json_object_string_addf(json_data, "neighborId",
							"%pSY\n",
							(uint8_t *)pnt);
			else
				vty_out(vty, "%pSY\n", (uint8_t *)pnt);
			pnt += 6;
		}
	}

	if (length == 7 || length == 11 || length == 13)
		sid = pnt_decode24(&pnt);
	else
		sid = pnt_decode32(&pnt);

	if (json)
		json_object_int_add(json_data, "sid", sid);
	else
		vty_out(vty, "%*sSID: %u\n", indent, "", sid);
}

static void bgp_linkstate_tlv_range_display(struct vty *vty, uint8_t *pnt,
					    uint16_t length, int indent,
					    json_object *json)
{
	json_object *json_data = NULL;
	char buf[11];

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt, 1);
		json_object_string_add(json_data, "flags", buf);
	} else {
		vty_out(vty, "\n%*sFlags: ", indent, "");
		pnt = bgp_linkstate_tlv_binary_display(vty, pnt, 1, json);
	}
	pnt++; /* ignore reserved byte */
	if (json)
		json_object_int_add(json_data, "rangeSize", pnt_decode16(&pnt));
	else
		vty_out(vty, "%*sRange Size: %u\n", indent, "",
			pnt_decode16(&pnt));

	/* RFC9085 2.3.5 is unclear. Just display a hexa dump */
	bgp_linkstate_tlv_hexa_display(vty, pnt, length - 4, json_data);
}

static void bgp_linkstate_tlv_delay_display(struct vty *vty, uint8_t *pnt,
					    uint16_t length,
					    uint16_t code_point,
					    json_object *json)
{
	json_object *json_data = NULL;
	uint32_t tmp32;
	bool anomalous;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
	}

	tmp32 = pnt_decode32(&pnt);
	anomalous = !!(tmp32 & TE_EXT_ANORMAL);

	if (json)
		json_object_boolean_add(json_data, "anomalous", anomalous);
	else if (anomalous)
		vty_out(vty, "Anomalous ");

	if (json)
		json_object_string_add(json, "dataUnit", "microseconds");

	if (code_point == BGP_LS_TLV_UNIDIRECTIONAL_LINK_DELAY ||
	    code_point == BGP_LS_TLV_UNIDIRECTIONAL_DELAY_VARIATION) {
		if (json)
			json_object_int_add(json_data, "delay",
					    tmp32 & TE_EXT_MASK);
		else
			vty_out(vty, "%u microseconds\n", tmp32 & TE_EXT_MASK);
	} else if (code_point == BGP_LS_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY) {
		if (json) {
			json_object_int_add(json_data, "minDelay",
					    tmp32 & TE_EXT_MASK);
			json_object_int_add(json_data, "maxDelay",
					    pnt_decode32(&pnt) & TE_EXT_MASK);
		} else {
			vty_out(vty, "%u", tmp32 & TE_EXT_MASK);
			vty_out(vty, "/%u microseconds\n",
				pnt_decode32(&pnt) & TE_EXT_MASK);
		}
	}
}

static void bgp_linkstate_tlv_unidirectional_link_loss_display(
	struct vty *vty, uint8_t *pnt, uint16_t length, json_object *json)
{
	json_object *json_data = NULL;
	uint32_t tmp32;
	float value;
	bool anomalous;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
	}

	tmp32 = pnt_decode32(&pnt);

	anomalous = !!(tmp32 & TE_EXT_ANORMAL);
	value = ((float)(tmp32 & TE_EXT_MASK)) * LOSS_PRECISION;

	if (json) {
		json_object_boolean_add(json_data, "anomalous", anomalous);
		json_object_double_add(json_data, "lossPercent", value);
		return;
	}

	if (anomalous)
		vty_out(vty, "Anomalous ");
	vty_out(vty, "%g%%\n", value);
}

static void bgp_linkstate_tlv_asla_display(struct vty *vty, uint8_t *pnt,
					   uint16_t length, int indent,
					   json_object *json)
{
	json_object *json_data = NULL;
	char buf[290];
	uint8_t sabm_len, udabm_len;
	struct bgp_attr_ls attr_ls;
	uint8_t *orig_pnt = pnt;

	sabm_len = pnt_decode8(&pnt);
	udabm_len = pnt_decode8(&pnt);
	pnt += 2; /* ignore reserved 2 bytes */

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt,
						      sabm_len);
		json_object_string_add(json_data, "sabmFlags", buf);
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt,
						      udabm_len);
		json_object_string_add(json_data, "udabmFlags", buf);
	} else {
		vty_out(vty, "\n%*sSABM Flags : ", indent, "");
		pnt = bgp_linkstate_tlv_binary_display(vty, pnt, sabm_len,
						       json);
		vty_out(vty, "%*sUDABM Flags: ", indent, "");
		pnt = bgp_linkstate_tlv_binary_display(vty, pnt, udabm_len,
						       json);
	}

	attr_ls.length = length - (pnt - orig_pnt);
	attr_ls.data = pnt;

	bgp_linkstate_tlv_attribute_display(vty, &attr_ls, indent, json_data);
}

static void bgp_linkstate_tlv_sr_range_display(struct vty *vty, uint8_t *pnt,
					       uint16_t length, int indent,
					       json_object *json)
{
	json_object *json_data = NULL;
	struct bgp_attr_ls attr_ls;
	uint8_t *orig_pnt = pnt;
	char buf[11];

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt, 1);
		json_object_string_add(json_data, "flags", buf);
	} else {
		vty_out(vty, "\n%*sFlags: ", indent, "");
		pnt = bgp_linkstate_tlv_binary_display(vty, pnt, 1, json);
	}
	pnt++; /* ignore reserved byte */
	if (json)
		json_object_int_add(json_data, "range", pnt_decode24(&pnt));
	else
		vty_out(vty, "%*sRange: %u\n", indent, "", pnt_decode24(&pnt));

	attr_ls.length = length - (pnt - orig_pnt);
	attr_ls.data = pnt;

	bgp_linkstate_tlv_attribute_display(vty, &attr_ls, indent, json_data);
}

static void bgp_linkstate_tlv_sid_label_display(struct vty *vty, uint8_t *pnt,
						uint16_t length,
						json_object *json)
{
	json_object *json_data = NULL;

	/* RFC9085
	 * If the length is set to 3, then the 20 rightmost bits
	 * represent a label (the total TLV size is 7), and the 4
	 * leftmost bits are set to 0. If the length is set to 4, then
	 * the value represents a 32-bit SID (the total TLV size is 8).
	 */
	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
	}

	if (length == 3) {
		if (json)
			json_object_int_add(json_data, "fromLabel",
					    pnt_decode24(&pnt) & 0x0FFFFF);
		else
			vty_out(vty, "From Label: %u\n",
				pnt_decode24(&pnt) & 0x0FFFFF);
	} else {
		if (json)
			json_object_int_add(json_data, "fromIndex",
					    pnt_decode32(&pnt));
		else
			vty_out(vty, "From Index: %u\n", pnt_decode32(&pnt));
	}
}

static void bgp_linkstate_tlv_flexible_algorithm_definition_display(
	struct vty *vty, uint8_t *pnt, uint16_t length, int indent,
	json_object *json)
{
	json_object *json_data = NULL;
	struct bgp_attr_ls attr_ls;
	uint8_t *orig_pnt = pnt;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		json_object_int_add(json_data, "flexAlgo", pnt_decode8(&pnt));
		json_object_int_add(json_data, "metricType", pnt_decode8(&pnt));
		json_object_int_add(json_data, "calcType", pnt_decode8(&pnt));
		json_object_int_add(json_data, "priority", pnt_decode8(&pnt));
	} else {
		vty_out(vty, "\n%*sFlex-Algo: %u\n", indent, "",
			pnt_decode8(&pnt));
		vty_out(vty, "%*sMetric-Type: %u\n", indent, "",
			pnt_decode8(&pnt));
		vty_out(vty, "%*sCalc-Type: %u\n", indent, "",
			pnt_decode8(&pnt));
		vty_out(vty, "%*sPriority: %u\n", indent, "",
			pnt_decode8(&pnt));
	}

	attr_ls.length = length - (pnt - orig_pnt);
	attr_ls.data = pnt;

	bgp_linkstate_tlv_attribute_display(vty, &attr_ls, indent, json_data);
}

static void bgp_linkstate_tlv_flexible_algorithm_prefix_metric_display(
	struct vty *vty, uint8_t *pnt, uint16_t length, int indent,
	json_object *json)
{
	json_object *json_data = NULL;
	char buf[11];

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		json_object_int_add(json_data, "flexAlgo", pnt_decode8(&pnt));
		pnt = bgp_linkstate_tlv_binary_string(buf, sizeof(buf), pnt, 1);
		json_object_string_add(json_data, "flags", buf);
		pnt += 2; /* ignore reserved 2 bytes */
		json_object_int_add(json_data, "metric", pnt_decode32(&pnt));
		return;
	}

	vty_out(vty, "\n%*sFlex-Algo: %u\n", indent, "", pnt_decode8(&pnt));
	vty_out(vty, "%*sFlags: ", indent, "");
	pnt = bgp_linkstate_tlv_binary_display(vty, pnt, 1, json);
	pnt += 2; /* ignore reserved 2 bytes */
	vty_out(vty, "%*sMetric: %u\n", indent, "", pnt_decode32(&pnt));
}

static void bgp_linkstate_tlv_opaque_display(struct vty *vty, uint8_t *pnt,
					     uint16_t length, int indent,
					     json_object *json)
{
	json_object *json_data = NULL;
	json_object *json_tlv = NULL;
	uint8_t *lim = pnt + length;
	uint16_t code_point = 0;
	bool ospf_tlv_header;
	uint16_t psize = 0;
	char tlv_type[6];
	int i;


	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
	}

	/* Opaque TLV carries original IGP TLVs
	 * IS-IS TLV header is 1 byte each for the TLV type and length.
	 * OSPF TLV header is 2 bytes each for the TLV type and length
	 * but the TLV type values are far from exceeding 255.
	 * Assume TLV header format is the OSPF one if first value is 0x00.
	 */
	ospf_tlv_header = (*pnt == 0);

	for (; pnt < lim; pnt += psize) {
		if (ospf_tlv_header) {
			code_point = pnt_decode16(&pnt);
			psize = pnt_decode16(&pnt);
		} else {
			code_point = pnt_decode8(&pnt);
			psize = pnt_decode8(&pnt);
		}

		if (json) {
			snprintf(tlv_type, sizeof(tlv_type), "%u", code_point);
			json_tlv = json_object_new_object();
			json_object_object_add(json_data, tlv_type, json_tlv);

			json_object_int_add(json_tlv, "type", code_point);
			json_object_int_add(json_tlv, "length", psize);

			if (pnt + psize > lim) {
				json_object_string_addf(
					json_tlv, "error",
					"too high length received: %u", psize);
				break;
			}

			bgp_linkstate_tlv_hexa_display(vty, pnt, psize,
						       json_tlv);
			continue;
		}

		vty_out(vty, "\n%*sTLV type %u: 0x", indent, "", code_point);

		if (pnt + psize > lim) {
			vty_out(vty, "Bad length received: %u\n", psize);
			break;
		}

		for (i = 0; i < psize; i++) {
			if (i != 0 && i % 8 == 0)
				vty_out(vty, " ");
			vty_out(vty, "%02x", *pnt);
		}
	}
	if (!json)
		vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_rtm_capability_display(struct vty *vty,
						     uint8_t *pnt,
						     uint16_t length,
						     json_object *json)
{
	json_object *json_data = NULL;
	json_object *json_array = NULL;
	uint8_t *lim = pnt + length;
	uint8_t tmp8;
	char buf[11];
	int i;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);

		tmp8 = pnt_decode8(&pnt);
		snprintf(buf, sizeof(buf), "0b");
		for (i = 7; i >= 5; i--)
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
				 "%d", (tmp8 >> i) & 1);
		json_object_string_add(json_data, "flags", buf);

		if (length > 8) {
			json_array = json_object_new_array();
			json_object_object_add(json, "values", json_array);
			for (i = 0; pnt < lim; pnt++, i++) {
				if (i % 8 == 0) {
					if (i != 0)
						json_object_array_add(
							json_array,
							json_object_new_string(
								buf));
					snprintf(buf, sizeof(buf), "0x");
				}
				if (i == 0)
					snprintf(buf + strlen(buf),
						 sizeof(buf) - strlen(buf),
						 "%02x", tmp8 & 0x1F);
				else
					snprintf(buf + strlen(buf),
						 sizeof(buf) - strlen(buf),
						 "%02x", *pnt);
			}
			if (strlen(buf) > 2) /* do not only contain 0x */
				json_object_array_add(
					json_array,
					json_object_new_string(buf));
		} else {
			snprintf(buf, sizeof(buf), "0x");
			for (i = 0; pnt < lim; pnt++, i++) {
				if (i == 0)
					snprintf(buf + strlen(buf),
						 sizeof(buf) - strlen(buf),
						 "%02x", tmp8 & 0x1F);
				else
					snprintf(buf + strlen(buf),
						 sizeof(buf) - strlen(buf),
						 "%02x", *pnt);
			}
			json_object_string_add(json_data, "values", buf);
		}
		return;
	}

	tmp8 = pnt_decode8(&pnt);

	vty_out(vty, "Flags: 0b");
	for (i = 7; i >= 5; i--)
		vty_out(vty, "%d", (tmp8 >> i) & 1);
	vty_out(vty, " Values: 0x%02x", tmp8 & 0x1F);
	for (; pnt < lim; pnt++)
		vty_out(vty, "%02x", *pnt);
	vty_out(vty, "\n");
}

static void bgp_linkstate_tlv_l2_member_attributes_display(struct vty *vty,
							   uint8_t *pnt,
							   uint16_t length,
							   int indent,
							   json_object *json)
{
	json_object *json_data = NULL;
	struct bgp_attr_ls attr_ls;
	uint8_t *orig_pnt = pnt;

	if (json) {
		json_data = json_object_new_object();
		json_object_object_add(json, "data", json_data);
		json_object_string_addf(json_data, "descriptor", "0x%02x",
					pnt_decode32(&pnt));
	} else
		vty_out(vty, "Descriptor: 0x%02x\n", pnt_decode32(&pnt));

	attr_ls.length = length - (pnt - orig_pnt);
	attr_ls.data = pnt;

	if (attr_ls.length == 0)
		/* No Sub-TLV */
		return;

	bgp_linkstate_tlv_attribute_display(vty, &attr_ls, indent, json_data);
}

static void bgp_linkstate_tlv_isis_area_indentifier_display(struct vty *vty,
							    uint8_t *pnt,
							    uint16_t length,
							    json_object *json)
{
	struct iso_address addr;

	addr.addr_len = length;
	memcpy(addr.area_addr, pnt, length);

	if (json)
		json_object_string_addf(json, "data", "%pIS", &addr);
	else
		vty_out(vty, "%pIS\n", &addr);
}

static void
bgp_linkstate_tlv_attribute_value_display(struct vty *vty, uint8_t *pnt,
					  uint16_t code_point, uint16_t psize,
					  int indent, json_object *json)
{
	if (!bgp_ls_tlv_check_size(code_point, psize)) {
		bgp_linkstate_tlv_hexa_display(vty, pnt, psize, json);
		return;
	}

	switch (code_point) {
	case BGP_LS_TLV_SRMS_PREFERENCE:
	case BGP_LS_TLV_IGP_METRIC:
	case BGP_LS_TLV_PREFIX_METRIC:
	case BGP_LS_TLV_TE_DEFAULT_METRIC:
		bgp_linkstate_tlv_integer_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_SR_ALGORITHM:
		bgp_linkstate_tlv_integer_list_display(vty, pnt, psize, 1,
						       json);
		break;
	case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
		bgp_linkstate_tlv_integer_list_display(vty, pnt, psize, 2,
						       json);
		break;
	case BGP_LS_TLV_IGP_ROUTE_TAG:
	case BGP_LS_TLV_SHARED_RISK_LINK_GROUP:
	case BGP_LS_TLV_S_BFD_DISCRIMINATORS:
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_SRLG:
		bgp_linkstate_tlv_integer_list_display(vty, pnt, psize, 4,
						       json);
		break;
	case BGP_LS_TLV_IGP_EXTENDED_ROUTE_TAG:
		bgp_linkstate_tlv_integer_list_display(vty, pnt, psize, 8,
						       json);
		break;
	case BGP_LS_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE:
	case BGP_LS_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE:
	case BGP_LS_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE:
	case BGP_LS_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE:
	case BGP_LS_TLV_OSPF_FORWARDING_ADDRESS:
	case BGP_LS_TLV_SOURCE_OSPF_ROUTER_ID:
	case BGP_LS_TLV_SOURCE_ROUTER_IDENTIFIER:
		bgp_linkstate_tlv_ipv4_6_address_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_NODE_NAME:
	case BGP_LS_TLV_LINK_NAME:
		bgp_linkstate_tlv_name_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_NODE_FLAG_BITS:
	case BGP_LS_TLV_IGP_FLAGS:
	case BGP_LS_TLV_PREFIX_ATTRIBUTES_FLAGS:
	case BGP_LS_TLV_MPLS_PROTOCOL_MASK:
	case BGP_LS_TLV_LINK_PROTECTION_TYPE:
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION_FLAGS:
		bgp_linkstate_tlv_binary_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_ADMINISTRATIVE_GROUP:
	case BGP_LS_TLV_EXTENDED_ADMINISTRATIVE_GROUP:
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_ANY_AFFINITY:
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ANY_AFFINITY:
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ALL_AFFINITY:
		bgp_linkstate_tlv_hexa_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_OPAQUE_NODE_ATTRIBUTE:
	case BGP_LS_TLV_OPAQUE_LINK_ATTRIBUTE:
	case BGP_LS_TLV_OPAQUE_PREFIX_ATTRIBUTE:
		bgp_linkstate_tlv_opaque_display(vty, pnt, psize, indent + 2,
						 json);
		break;
	case BGP_LS_TLV_NODE_MSD:
	case BGP_LS_TLV_LINK_MSD:
		bgp_linkstate_tlv_msd_display(vty, pnt, psize, indent + 2,
					      json);
		break;
	case BGP_LS_TLV_MAXIMUM_LINK_BANDWIDTH:
	case BGP_LS_TLV_MAX_RESERVABLE_LINK_BANDWIDTH:
	case BGP_LS_TLV_UNIDIRECTIONAL_RESIDUAL_BANDWIDTH:
	case BGP_LS_TLV_UNIDIRECTIONAL_AVAILABLE_BANDWIDTH:
	case BGP_LS_TLV_UNIDIRECTIONAL_UTILIZED_BANDWIDTH:
		bgp_linkstate_tlv_bandwidth_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_UNRESERVED_BANDWIDTH:
		bgp_linkstate_tlv_unreserved_bandwidth_display(
			vty, pnt, psize, indent + 2, json);
		break;
	case BGP_LS_TLV_IS_IS_AREA_IDENTIFIER:
		bgp_linkstate_tlv_isis_area_indentifier_display(vty, pnt, psize,
								json);
		break;
	case BGP_LS_TLV_PREFIX_SID:
	case BGP_LS_TLV_ADJACENCY_SID:
	case BGP_LS_TLV_LAN_ADJACENCY_SID:
	case BGP_LS_TLV_PEERNODE_SID:
	case BGP_LS_TLV_PEERADJ_SID:
	case BGP_LS_TLV_PEERSET_SID:
		bgp_linkstate_tlv_sid_display(vty, pnt, psize, code_point,
					      indent + 2, json);
		break;
	case BGP_LS_TLV_RANGE:
		bgp_linkstate_tlv_range_display(vty, pnt, psize, indent + 2,
						json);
		break;
	case BGP_LS_TLV_UNIDIRECTIONAL_LINK_DELAY:
	case BGP_LS_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY:
	case BGP_LS_TLV_UNIDIRECTIONAL_DELAY_VARIATION:
		bgp_linkstate_tlv_delay_display(vty, pnt, psize, code_point,
						json);
		break;
	case BGP_LS_TLV_UNIDIRECTIONAL_LINK_LOSS:
		bgp_linkstate_tlv_unidirectional_link_loss_display(vty, pnt,
								   psize, json);
		break;
	case BGP_LS_TLV_APPLICATION_SPECIFIC_LINK_ATTRIBUTES:
		bgp_linkstate_tlv_asla_display(vty, pnt, psize, indent + 2,
					       json);
		break;
	case BGP_LS_TLV_SR_CAPABILITIES:
	case BGP_LS_TLV_SR_LOCAL_BLOCK:
		bgp_linkstate_tlv_sr_range_display(vty, pnt, psize, indent + 2,
						   json);
		break;
	case BGP_LS_TLV_SID_LABEL:
		bgp_linkstate_tlv_sid_label_display(vty, pnt, psize, json);
		break;
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION:
		bgp_linkstate_tlv_flexible_algorithm_definition_display(
			vty, pnt, psize, indent + 2, json);
		break;
	case BGP_LS_TLV_FLEXIBLE_ALGORITHM_PREFIX_METRIC:
		bgp_linkstate_tlv_flexible_algorithm_prefix_metric_display(
			vty, pnt, psize, indent + 2, json);
		break;
	case BGP_LS_TLV_GRACEFUL_LINK_SHUTDOWN_TLV:
		if (!json)
			vty_out(vty, "Enabled\n"); /* TLV must have no data */
		break;
	case BGP_LS_TLV_L2_BUNDLE_MEMBER_ATTRIBUTES:
		bgp_linkstate_tlv_l2_member_attributes_display(
			vty, pnt, psize, indent + 2, json);
		break;
	case BGP_LS_TLV_RTM_CAPABILITY:
		bgp_linkstate_tlv_rtm_capability_display(vty, pnt, psize, json);
		break;
	default:
		bgp_linkstate_tlv_hexa_display(vty, pnt, psize, json);
	}
}

void bgp_linkstate_tlv_attribute_display(struct vty *vty,
					 struct bgp_attr_ls *attr_ls,
					 int indent, json_object *json)
{
	uint8_t *pnt = attr_ls->data;
	uint8_t *lim = pnt + attr_ls->length;
	uint16_t psize = 0;
	uint16_t code_point = 0;
	char tlv_type[6];
	json_object *json_tlv = NULL;

	for (; pnt < lim; pnt += psize) {
		code_point = pnt_decode16(&pnt);
		psize = pnt_decode16(&pnt);

		if (json) {
			snprintf(tlv_type, sizeof(tlv_type), "%u", code_point);

			json_tlv = json_object_new_object();
			json_object_object_add(json, tlv_type, json_tlv);

			if (code_point < BGP_LS_TLV_MAX &&
			    bgp_linkstate_tlv_infos[code_point].descr != NULL)
				json_object_string_add(
					json_tlv, "description",
					bgp_linkstate_tlv_infos[code_point]
						.descr);

			json_object_int_add(json_tlv, "type", code_point);
			json_object_int_add(json_tlv, "length", psize);

			if (pnt + psize > lim) {
				json_object_string_addf(
					json_tlv, "error",
					"too high length received: %u", psize);
				break;
			}
			if (!bgp_ls_tlv_check_size(code_point, psize))
				json_object_string_addf(
					json_tlv, "error",
					"unexpected length received: %u",
					psize);
		} else {
			if (code_point < BGP_LS_TLV_MAX &&
			    bgp_linkstate_tlv_infos[code_point].descr != NULL)
				vty_out(vty, "%*s%s: ", indent, "",
					bgp_linkstate_tlv_infos[code_point]
						.descr);
			else
				vty_out(vty, "%*sTLV type %u: ", indent, "",
					code_point);

			if (pnt + psize > lim) {
				vty_out(vty, "Bad length received: %u\n",
					psize);
				break;
			}
		}

		bgp_linkstate_tlv_attribute_value_display(
			vty, pnt, code_point, psize, indent, json_tlv);
	}
}
