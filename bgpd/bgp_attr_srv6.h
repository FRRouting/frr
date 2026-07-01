// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_ATTR_SRV6_H_
#define _BGP_ATTR_SRV6_H_

/*
 * Prefix-SID
 * SRv6-Service-TLV
 * RFC 9252
 */
struct bgp_attr_srv6_service {
	uint8_t type;
	unsigned long refcnt;
	uint8_t sid_flags;
	uint16_t endpoint_behavior;
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint8_t transposition_len;
	uint8_t transposition_offset;
};
#endif /* _BGP_ATTR_SRV6_H_ */
