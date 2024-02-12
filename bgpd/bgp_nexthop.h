// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_NEXTHOP_H
#define _QUAGGA_BGP_NEXTHOP_H

#include "if.h"
#include "queue.h"
#include "prefix.h"
#include "bgp_table.h"

#define NEXTHOP_FAMILY(nexthop_len)                                            \
	(((nexthop_len) == 4 || (nexthop_len) == 12                            \
		  ? AF_INET                                                    \
		  : ((nexthop_len) == 16 || (nexthop_len) == 24                \
				     || (nexthop_len) == 32                    \
				     || (nexthop_len) == 48                    \
			     ? AF_INET6                                        \
			     : AF_UNSPEC)))

#define BGP_MP_NEXTHOP_FAMILY NEXTHOP_FAMILY

PREDECL_RBTREE_UNIQ(bgp_nexthop_cache);

/* BGP nexthop cache value structure. */
struct bgp_nexthop_cache {
	afi_t afi;

	/* The ifindex of the outgoing interface *if* it's a v6 LL */
	ifindex_t ifindex_ipv6_ll;

	/* RB-tree entry. */
	struct bgp_nexthop_cache_item entry;

	/* IGP route's metric. */
	uint32_t metric;

	/* Nexthop number and nexthop linked list.*/
	uint8_t nexthop_num;

	/* This flag is set to TRUE for a bnc that is gateway IP overlay index
	 * nexthop.
	 */
	bool is_evpn_gwip_nexthop;

	uint16_t change_flags;
#define BGP_NEXTHOP_CHANGED	      (1 << 0)
#define BGP_NEXTHOP_METRIC_CHANGED    (1 << 1)
#define BGP_NEXTHOP_CONNECTED_CHANGED (1 << 2)
#define BGP_NEXTHOP_MACIP_CHANGED     (1 << 3)

	struct nexthop *nexthop;
	time_t last_update;
	uint16_t flags;

/*
 * If the nexthop is EVPN gateway IP NH, VALID flag is set only if the nexthop
 * is RIB reachable as well as MAC/IP is present
 */
#define BGP_NEXTHOP_VALID             (1 << 0)
#define BGP_NEXTHOP_REGISTERED        (1 << 1)
#define BGP_NEXTHOP_CONNECTED         (1 << 2)
#define BGP_NEXTHOP_PEER_NOTIFIED     (1 << 3)
#define BGP_STATIC_ROUTE              (1 << 4)
#define BGP_STATIC_ROUTE_EXACT_MATCH  (1 << 5)
#define BGP_NEXTHOP_LABELED_VALID     (1 << 6)

/*
 * This flag is added for EVPN gateway IP nexthops.
 * If the nexthop is RIB reachable, but a MAC/IP is not yet
 * resolved, this flag is set.
 * Following table explains the combination of L3 and L2 reachability w.r.t.
 * VALID and INCOMPLETE flags
 *
 *                | MACIP resolved | MACIP unresolved
 *----------------|----------------|------------------
 * L3 reachable   | VALID      = 1 | VALID      = 0
 *                | INCOMPLETE = 0 | INCOMPLETE = 1
 * ---------------|----------------|--------------------
 * L3 unreachable | VALID      = 0 | VALID      = 0
 *                | INCOMPLETE = 0 | INCOMPLETE = 0
 */
#define BGP_NEXTHOP_EVPN_INCOMPLETE (1 << 7)

	uint32_t srte_color;

	/* Back pointer to the cache tree this entry belongs to. */
	struct bgp_nexthop_cache_head *tree;

	struct prefix prefix;
	void *nht_info; /* In BGP, peer session */
	LIST_HEAD(path_list, bgp_path_info) paths;
	unsigned int path_count;
	struct bgp *bgp;
};

extern int bgp_nexthop_cache_compare(const struct bgp_nexthop_cache *a,
				     const struct bgp_nexthop_cache *b);
DECLARE_RBTREE_UNIQ(bgp_nexthop_cache, struct bgp_nexthop_cache, entry,
		    bgp_nexthop_cache_compare);

/* Own tunnel-ip address structure */
struct tip_addr {
	struct in_addr addr;
	int refcnt;
};

/* Forward declaration(s). */
struct peer;
struct update_subgroup;
struct bgp_dest;
struct attr;

#define BNC_FLAG_DUMP_SIZE 180
extern char *bgp_nexthop_dump_bnc_flags(struct bgp_nexthop_cache *bnc,
					char *buf, size_t len);
extern char *bgp_nexthop_dump_bnc_change_flags(struct bgp_nexthop_cache *bnc,
					       char *buf, size_t len);
extern void bgp_connected_add(struct bgp *bgp, struct connected *c);
extern void bgp_connected_delete(struct bgp *bgp, struct connected *c);
extern bool bgp_subgrp_multiaccess_check_v4(struct in_addr nexthop,
					    struct update_subgroup *subgrp,
					    struct peer *exclude);
extern bool bgp_subgrp_multiaccess_check_v6(struct in6_addr nexthop,
					    struct update_subgroup *subgrp,
					    struct peer *exclude);
extern bool bgp_multiaccess_check_v4(struct in_addr nexthop, struct peer *peer);
extern bool bgp_multiaccess_check_v6(struct in6_addr nexthop,
				     struct peer *peer);
extern int bgp_config_write_scan_time(struct vty *);
extern bool bgp_nexthop_self(struct bgp *bgp, afi_t afi, uint8_t type,
			     uint8_t sub_type, struct attr *attr,
			     struct bgp_dest *dest);
extern struct bgp_nexthop_cache *bnc_new(struct bgp_nexthop_cache_head *tree,
					 struct prefix *prefix,
					 uint32_t srte_color,
					 ifindex_t ifindex);
extern bool bnc_existing_for_prefix(struct bgp_nexthop_cache *bnc);
extern void bnc_free(struct bgp_nexthop_cache *bnc);
extern struct bgp_nexthop_cache *bnc_find(struct bgp_nexthop_cache_head *tree,
					  struct prefix *prefix,
					  uint32_t srte_color,
					  ifindex_t ifindex);
extern void bnc_nexthop_free(struct bgp_nexthop_cache *bnc);
extern void bgp_scan_init(struct bgp *bgp);
extern void bgp_scan_finish(struct bgp *bgp);
extern void bgp_scan_vty_init(void);
extern void bgp_address_init(struct bgp *bgp);
extern void bgp_address_destroy(struct bgp *bgp);
extern bool bgp_tip_add(struct bgp *bgp, struct in_addr *tip);
extern void bgp_tip_del(struct bgp *bgp, struct in_addr *tip);
extern void bgp_tip_hash_init(struct bgp *bgp);
extern void bgp_tip_hash_destroy(struct bgp *bgp);

extern void bgp_nexthop_show_address_hash(struct vty *vty, struct bgp *bgp);
#endif /* _QUAGGA_BGP_NEXTHOP_H */
