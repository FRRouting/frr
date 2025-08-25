// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_SRV6_H_
#define _BGP_SRV6_H_

static inline bool is_srv6_unicast_enabled(struct bgp *bgp, afi_t afi)
{
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_SRV6_UNICAST_SID_AUTO)
	    || bgp->srv6_unicast[afi].sid_explicit || bgp->srv6_unicast[afi].sid_index)
		return true;

	return false;
}

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install);
void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest);
void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct bgp_path_info *bpi);
void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi);

#endif /* _BGP_SRV6_H_ */
