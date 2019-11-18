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
	/* Ideally this has to be list of scope zone. But for now we can just
	 * have as a bool variable to say bsr_tracking.
	 * Later this variable can be changed as a list of scope zones for
	 * tracking same bsr for multiple scope zones.
	 */
	bool bsr_tracking;
};

int pim_parse_nexthop_update(ZAPI_CALLBACK_ARGS);
int pim_find_or_track_nexthop(struct pim_instance *pim, struct prefix *addr,
			      struct pim_upstream *up, struct rp_info *rp,
			      bool bsr_track_needed,
			      struct pim_nexthop_cache *out_pnc);
void pim_delete_tracked_nexthop(struct pim_instance *pim, struct prefix *addr,
				struct pim_upstream *up, struct rp_info *rp,
				bool del_bsr_tracking);
struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim,
						 struct pim_rpf *rpf);
uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp);
int pim_ecmp_nexthop_lookup(struct pim_instance *pim,
			    struct pim_nexthop *nexthop, struct prefix *src,
			    struct prefix *grp, int neighbor_needed);
void pim_sendmsg_zebra_rnh(struct pim_instance *pim, struct zclient *zclient,
			   struct pim_nexthop_cache *pnc, int command);
int pim_ecmp_fib_lookup_if_vif_index(struct pim_instance *pim,
				     struct prefix *src, struct prefix *grp);
void pim_rp_nexthop_del(struct rp_info *rp_info);
bool pim_nexthop_match(struct pim_instance *pim, struct in_addr addr,
		       struct in_addr ip_src);
bool pim_nexthop_match_nht_cache(struct pim_instance *pim, struct in_addr addr,
				 struct in_addr ip_src);

#endif
