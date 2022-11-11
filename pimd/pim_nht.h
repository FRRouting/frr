/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

/* PIM nexthop cache value structure. */
struct pim_nexthop_cache {
	struct pim_rpf rpf;
	/* IGP route's metric. */
	uint32_t metric;
	uint32_t distance;
	/* Nexthop number and nexthop linked list. */
	uint8_t nexthop_num;
	struct nexthop *nexthop;
	int64_t last_update;
	uint16_t flags;
#define PIM_NEXTHOP_VALID             (1 << 0)
#define PIM_NEXTHOP_ANSWER_RECEIVED   (1 << 1)

	struct list *rp_list;
	struct hash *upstream_hash;

	/* bsr_count won't currently go above 1 as we only have global_scope,
	 * but if anyone adds scope support multiple scopes may NHT-track the
	 * same BSR
	 */
	uint32_t bsr_count;
};

struct pnc_hash_walk_data {
	struct pim_instance *pim;
	struct interface *ifp;
};

int pim_parse_nexthop_update(ZAPI_CALLBACK_ARGS);
int pim_find_or_track_nexthop(struct pim_instance *pim, pim_addr addr,
			      struct pim_upstream *up, struct rp_info *rp,
			      struct pim_nexthop_cache *out_pnc);
void pim_delete_tracked_nexthop(struct pim_instance *pim, pim_addr addr,
				struct pim_upstream *up, struct rp_info *rp);
struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim,
						 struct pim_rpf *rpf);
uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp);
int pim_ecmp_nexthop_lookup(struct pim_instance *pim,
			    struct pim_nexthop *nexthop, pim_addr src,
			    struct prefix *grp, int neighbor_needed);
void pim_sendmsg_zebra_rnh(struct pim_instance *pim, struct zclient *zclient,
			   struct pim_nexthop_cache *pnc, int command);
int pim_ecmp_fib_lookup_if_vif_index(struct pim_instance *pim, pim_addr src,
				     struct prefix *grp);
void pim_rp_nexthop_del(struct rp_info *rp_info);

/* for RPF check on BSM message receipt */
void pim_nht_bsr_add(struct pim_instance *pim, pim_addr bsr_addr);
void pim_nht_bsr_del(struct pim_instance *pim, pim_addr bsr_addr);
/* RPF(bsr_addr) == src_ip%src_ifp? */
bool pim_nht_bsr_rpf_check(struct pim_instance *pim, pim_addr bsr_addr,
			   struct interface *src_ifp, pim_addr src_ip);
void pim_upstream_nh_if_update(struct pim_instance *pim, struct interface *ifp);
#endif
