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
	if (CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO) ||
	    bgp->srv6_unicast[afi].sid_explicit || bgp->srv6_unicast[afi].sid_index)
		return true;

	return false;
}

static inline bool is_srv6_unicast_dt46_enabled(struct bgp *bgp, afi_t afi)
{
	return is_srv6_unicast_enabled(bgp, afi) &&
	       CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);
}

static inline enum seg6local_action_t bgp_srv6_unicast_action(struct bgp *bgp, afi_t afi)
{
	if (is_srv6_unicast_dt46_enabled(bgp, afi))
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT46;

	return afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
}

static inline enum srv6_endpoint_behavior_codepoint
bgp_srv6_unicast_endpoint_behavior_codepoint(struct bgp *bgp, afi_t afi,
					     struct srv6_locator *locator)
{
	bool usid = CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID);

	if (is_srv6_unicast_dt46_enabled(bgp, afi))
		return usid ? SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID
			    : SRV6_ENDPOINT_BEHAVIOR_END_DT46;

	if (afi == AFI_IP)
		return usid ? SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID : SRV6_ENDPOINT_BEHAVIOR_END_DT4;

	return usid ? SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID : SRV6_ENDPOINT_BEHAVIOR_END_DT6;
}

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw_dt46(struct bgp *bgp, afi_t afi);
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
