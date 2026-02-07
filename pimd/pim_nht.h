// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
 */
#ifndef PIM_NHT_H
#define PIM_NHT_H

#include "prefix.h"
#include <zebra.h>
#include "zclient.h"
#include "vrf.h"

#include "pimd.h"
#include "pim_rp.h"
#include "pim_rpf.h"

PREDECL_SORTLIST_NONUNIQ(pim_lookup_mode);

struct pim_lookup_mode {
	char *grp_plist;
	char *src_plist;
	enum pim_rpf_lookup_mode mode;
	struct pim_lookup_mode_item list;
};

/* PIM nexthop cache value structure. */
struct pim_nexthop_cache_rib {
	/* IGP route's metric. */
	uint32_t metric;
	uint32_t distance;
	uint16_t prefix_len;

	/* Nexthop number and nexthop linked list. */
	uint16_t nexthop_num;
	struct nexthop *nexthop;
	int64_t last_update;
	uint16_t flags;
#define PIM_NEXTHOP_VALID             (1 << 0)
#define PIM_NEXTHOP_ANSWER_RECEIVED   (1 << 1)
};

struct pim_nexthop_cache {
	pim_addr addr;

	struct pim_nexthop_cache_rib mrib;
	struct pim_nexthop_cache_rib urib;

	struct list *rp_list;
	struct hash *upstream_hash;

	/* bsr_count won't currently go above 1 as we only have global_scope,
	 * but if anyone adds scope support multiple scopes may NHT-track the
	 * same BSR
	 */
	uint32_t bsr_count;
	uint32_t candrp_count;
};

struct pnc_hash_walk_data {
	struct pim_instance *pim;
	struct interface *ifp;
};

/* Find the right lookup mode for the given group and/or source
 * either may be ANY (although source should realistically always be provided)
 * Find the lookup mode that has matching group and/or source prefix lists, or the global mode.
 */
enum pim_rpf_lookup_mode pim_get_lookup_mode(struct pim_instance *pim, pim_addr group,
					     pim_addr source);

/* Change the RPF lookup config, may trigger updates to RP's and Upstreams registered for matching cache entries */
void pim_nht_change_rpf_mode(struct pim_instance *pim, const char *group_plist,
			     const char *source_plist, enum pim_rpf_lookup_mode mode);

/* Write the rpf lookup mode configuration */
int pim_lookup_mode_write(struct pim_instance *pim, struct vty *vty);

/* Verify that we have nexthop information in the cache entry */
bool pim_nht_pnc_is_valid(struct pim_instance *pim, struct pim_nexthop_cache *pnc, pim_addr group);

/* Get (or add) the NH cache entry for the given address */
struct pim_nexthop_cache *pim_nht_get(struct pim_instance *pim, pim_addr addr);

/* Set the gateway address for all nexthops in the given cache entry to the given address
 * unless the gateway is already set, and only if the nexthop is through the given interface.
 */
void pim_nht_set_gateway(struct pim_instance *pim, struct pim_nexthop_cache *pnc, pim_addr addr,
			 struct interface *ifp);

/* Track a new addr, registers an upstream or RP for updates */
bool pim_nht_find_or_track(struct pim_instance *pim, pim_addr addr, struct pim_upstream *up,
			   struct rp_info *rp, struct pim_nexthop_cache *out_pnc);

/* Track a new addr, increments BSR count */
void pim_nht_bsr_add(struct pim_instance *pim, pim_addr bsr_addr);

/* Track a new addr, increments Cand RP count */
bool pim_nht_candrp_add(struct pim_instance *pim, pim_addr addr);

/* Delete a tracked addr with registered upstream or RP, if no-one else is interested, stop tracking */
void pim_nht_delete_tracked(struct pim_instance *pim, pim_addr addr, struct pim_upstream *up,
			    struct rp_info *rp);

/* Delete a tracked addr and decrement BSR count, if no-one else is interested, stop tracking */
void pim_nht_bsr_del(struct pim_instance *pim, pim_addr bsr_addr);

/* Delete a tracked addr and decrement Cand RP count, if no-one else is interested, stop tracking */
void pim_nht_candrp_del(struct pim_instance *pim, pim_addr addr);

/* RPF(bsr_addr) == src_ip%src_ifp? */
bool pim_nht_bsr_rpf_check(struct pim_instance *pim, pim_addr bsr_addr, struct interface *src_ifp,
			   pim_addr src_ip);

/* Reset the rp.source_nexthop of the given RP */
void pim_nht_rp_del(struct rp_info *rp_info);

/* Walk the NH cache and update every nexthop that uses the given interface */
void pim_nht_upstream_if_update(struct pim_instance *pim, struct interface *ifp);

/* Lookup nexthop information for src, returned in nexthop when function returns true.
 * Tries to find in cache first and does a synchronous lookup if not found in the cache.
 * If neighbor_needed is true, then nexthop is only considered valid if it's to a pim
 * neighbor.
 * Providing the group only effects the ECMP decision, if enabled
 */
bool pim_nht_lookup_ecmp(struct pim_instance *pim, struct pim_nexthop *nexthop, pim_addr src,
			 struct prefix *grp, bool neighbor_needed);

/* Very similar to pim_nht_lookup_ecmp, but does not check the nht cache and only does
 * a synchronous lookup. No ECMP decision is made.
 */
bool pim_nht_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop, pim_addr addr,
		    pim_addr group, bool neighbor_needed);

/* Similar to `pim_nht_lookup`, but uses only BGP route when `asn` is provided. */
bool pim_bgp_nht_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop, pim_addr addr,
			pim_addr group, uint32_t *asn);

/* Performs a pim_nht_lookup_ecmp and returns the mroute VIF index of the nexthop interface */
int pim_nht_lookup_ecmp_if_vif_index(struct pim_instance *pim, pim_addr src, struct prefix *grp);

/* Tracked nexthop update from zebra */
void pim_nexthop_update(struct vrf *vrf, struct prefix *match, struct zapi_route *nhr);

/* NHT init and finish funcitons */
void pim_nht_init(struct pim_instance *pim);
void pim_nht_terminate(struct pim_instance *pim);

#endif
