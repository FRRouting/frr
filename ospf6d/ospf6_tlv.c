// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#include "ospf6_proto.h"
#include "ospf6_tlv.h"

int tlv_min_size_map[OSPF6_TLV_ENUM_END] = {
	[OSPF6_TLV_RESERVED] = 0,
	[OSPF6_TLV_ROUTER_LINK] = TLV_ROUTER_LINK_LENGTH,
	[OSPF6_TLV_ATTACHED_ROUTERS] = TLV_ATTACHED_ROUTERS_LENGTH,
	[OSPF6_TLV_INTER_AREA_PREFIX] = TLV_INTER_AREA_PREFIX_MIN_LENGTH,
	[OSPF6_TLV_INTER_AREA_ROUTER] = TLV_INTER_AREA_ROUTER_LENGTH,
	[OSPF6_TLV_EXTERNAL_PREFIX] = TLV_EXTERNAL_PREFIX_MIN_LENGTH,
	[OSPF6_TLV_INTRA_AREA_PREFIX] = TLV_INTRA_AREA_PREFIX_MIN_LENGTH,
	[OSPF6_TLV_IPV6_LL_ADDR] = TLV_IPV6_LINK_LOCAL_ADDRESS_LENGTH,
	[OSPF6_TLV_IPV4_LL_ADDR] = TLV_IPV4_LINK_LOCAL_ADDRESS_LENGTH,
};

size_t tlv_body_min_size(uint16_t tlv_type)
{
	return (tlv_type < OSPF6_TLV_ENUM_END) ? (tlv_min_size_map[tlv_type])
					       : 0;
}

struct ospf6_prefix *get_prefix_in_tlv(struct tlv_header *tlvh)
{
	return (struct ospf6_prefix *)(TLV_BODY(tlvh) +
				       tlv_body_min_size(ntohs(tlvh->type)));
}
