// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_SRV6_H_
#define _BGP_SRV6_H_

#include "bgpd.h"

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

int bgp_srv6_per_locator_cache_cmp(const struct bgp_srv6_per_locator_cache *a,
				   const struct bgp_srv6_per_locator_cache *b);

struct bgp_srv6_locator_entry {
	struct bgp_srv6_locators_item item;
	struct srv6_locator *locator;
};

int bgp_srv6_locators_cmp(const struct bgp_srv6_locator_entry *a,
			  const struct bgp_srv6_locator_entry *b);

DECLARE_RBTREE_UNIQ(bgp_srv6_locators, struct bgp_srv6_locator_entry, item, bgp_srv6_locators_cmp);

struct bgp_srv6_vpn_policy {
	struct srv6_locator *tovpn_sid_locator;
	struct in6_addr *tovpn_sid;
};

struct bgp_srv6_per_locator_cache {
	/* RB-tree entry. */
	struct bgp_srv6_per_locator_cache_item entry;

	/* the locator name is the key */
	char locator_name[SRV6_LOCNAME_SIZE];

	/* number of path_vrfs */
	unsigned int path_count;

	/* back pointer to bgp instance */
	struct bgp *bgp;

	/* list of path_vrfs using it */
	LIST_HEAD(paths_list, bgp_path_info) paths;

	/* Back pointer to the cache tree this entry belongs to. */
	struct bgp_srv6_per_locator_cache_head *tree;

	/* each instance per AFI, per BGP will perform SID allocation
	 * the tuple (VRF, family, locator) will return a unique SID
	 * lets consider auto mode is default
	 * XXX extend here if we want to support multiple allocation modes
	 */
	afi_t afi;
	struct bgp_srv6_vpn_policy sid_policy;

	time_t last_update;
	bool allocation_in_progress;
};

DECLARE_RBTREE_UNIQ(bgp_srv6_per_locator_cache, struct bgp_srv6_per_locator_cache, entry,
		    bgp_srv6_per_locator_cache_cmp);

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_withdraw_dt46(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sids_forget(struct bgp *bgp);
void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install);
void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest);
void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct bgp_path_info *bpi);
void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi);
struct srv6_locator *bgp_srv6_locator_lookup_all_by_name(const char *name);
void bgp_srv6_locator_store(const struct srv6_locator *loc);
void bgp_srv6_locator_remove(const char *name);
void bgp_srv6_locators_finish(void);
void bgp_srv6_path_locator_extra_free(struct bgp_path_info_extra *extra);
void bgp_srv6_path_locator_extra_alloc(struct bgp_path_info_extra *extra, char *locator);
struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_find(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name);
void bgp_srv6_per_locator_unlink(struct bgp_path_info *path);
void bgp_srv6_locator_per_routemap_init(void);
void bgp_srv6_per_locator_cache_reset(struct bgp *bgp, afi_t afi);
struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_new(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name);
void bgp_srv6_vpn_path_withdraw(struct bgp *bgp, const struct prefix *p, afi_t afi,
				struct srv6_locator *locator);

#endif /* _BGP_SRV6_H_ */
