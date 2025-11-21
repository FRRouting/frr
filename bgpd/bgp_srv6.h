// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright 2025 6WIND S.A.
 * Loïc SANG <loic.sang@6wind.com>
 */

#ifndef _BGP_SRV6_H_
#define _BGP_SRV6_H_

#include "bgpd.h"

static inline bool is_srv6_unicast_enabled(struct bgp *bgp, afi_t afi)
{
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_SRV6_UNICAST_SID_AUTO)
	    || bgp->srv6_unicast[afi].sid_explicit || bgp->srv6_unicast[afi].sid_index)
		return true;

	return false;
}

int bgp_srv6_per_locator_cache_cmp(const struct bgp_srv6_per_locator_cache *a,
				   const struct bgp_srv6_per_locator_cache *b);

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
void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install);
void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest);
void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct bgp_path_info *bpi);
void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi);
void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi);
struct interface *get_srv6_endpoint_ifp(char *vrf_name);
void bgp_srv6_unicast_ifp_update(struct interface *ifp, bool state);
struct srv6_locator *bgp_srv6_locator_lookup_all_by_name(const char *name);
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
