// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#ifndef _BGP_NHG_H
#define _BGP_NHG_H

#include "nexthop_group.h"
#include "bgpd/bgp_table.h"

PREDECL_HASH(bgp_nhg_cache);

extern struct bgp_nhg_cache_head nhg_cache_table;

struct bgp_nhg_cache {
	struct bgp_nhg_cache_item entry;

	uint32_t id;

	/* obtained from lib/zclient.h, zapi_route->flags
	 * some flags of interest for nexthop handling :
	 * ALLOW_RECURSION, IBGP
	 */
#define BGP_NHG_FLAG_ALLOW_RECURSION (1 << 0)
#define BGP_NHG_FLAG_IBGP	     (1 << 1)
#define BGP_NHG_FLAG_SRTE_PRESENCE   (1 << 2)
	uint16_t flags;
#define BGP_NHG_STATE_INSTALLED (1 << 0)
#define BGP_NHG_STATE_REMOVED	(1 << 1)
	uint16_t state;

	/* other parameters are route attributes and are not
	 * relevant for qualifying next-hop:
	 * tag, metric, distance
	 */
	uint16_t nexthop_num;
	struct zapi_nexthop nexthops[MULTIPATH_NUM];

	LIST_HEAD(nhg_path_list, bgp_path_info) paths;

	unsigned int path_count;
	time_t last_update;
};

extern uint32_t bgp_nhg_cache_hash(const struct bgp_nhg_cache *nhg);
extern uint32_t bgp_nhg_cache_compare(const struct bgp_nhg_cache *a,
				      const struct bgp_nhg_cache *b);
DECLARE_HASH(bgp_nhg_cache, struct bgp_nhg_cache, entry, bgp_nhg_cache_compare,
	     bgp_nhg_cache_hash);

/* APIs for setting up and allocating L3 nexthop group ids */
extern uint32_t bgp_nhg_id_alloc(void);
extern void bgp_nhg_id_free(uint32_t nhg_id);
extern void bgp_nhg_init(void);
void bgp_nhg_finish(void);
extern struct bgp_nhg_cache *bgp_nhg_find(struct bgp *bgp, struct bgp_dest *dest,
					  struct bgp_path_info *pi, afi_t afi,
					  safi_t safi);
extern void bgp_nhg_path_unlink(struct bgp_path_info *pi);

extern struct bgp_nhg_cache *bgp_nhg_new(uint32_t flags, uint16_t nexthop_num,
					 struct zapi_nexthop api_nh[]);
extern void bgp_nhg_id_set_installed(uint32_t id, bool install);
extern void bgp_nhg_id_set_removed(uint32_t id);
extern void bgp_nhg_refresh_by_nexthop(struct bgp_nexthop_cache *bnc);
void bgp_nhg_vty_init(void);

#endif /* _BGP_NHG_H */
