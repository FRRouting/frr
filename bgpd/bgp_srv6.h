// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_SRV6_H_
#define _BGP_SRV6_H_

bool is_srv6_unicast_enabled(struct bgp *bgp, afi_t afi);
void transpose_sid(struct in6_addr *sid, uint32_t label, uint8_t offset,
		   uint8_t len);
void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi);
#endif /* _BGP_SRV6_H_ */
