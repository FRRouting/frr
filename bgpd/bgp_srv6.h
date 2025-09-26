// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_SRV6_H_
#define _BGP_SRV6_H_

int bgp_srv6_configure(struct vty *vty, struct bgp *bgp, afi_t afi, bool sid_auto,
			   uint32_t sid_idx, bool sid_explicit,
			   struct in6_addr sid_value, const char *rmap_str, bool no);
struct srv6_policy *get_srv6_policy(struct bgp *bgp, afi_t afi);
bool is_srv6_unicast_enabled(struct bgp *bgp);
bool is_srv6_unicast_afi_enabled(struct bgp *bgp, afi_t afi);
bool is_srv6_unicast_vrf_enabled(struct bgp *bgp);
void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install);
void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest);
void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct srv6_policy *srv6_policy, struct bgp_path_info *bpi);
void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi);

#endif /* _BGP_SRV6_H_ */
