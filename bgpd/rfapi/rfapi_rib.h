// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

/*
 * File:	rfapi_rib.h
 * Purpose:	per-nve rib
 */

#ifndef QUAGGA_HGP_RFAPI_RIB_H
#define QUAGGA_HGP_RFAPI_RIB_H

/*
 * Key for indexing RIB and Pending RIB skiplists. For L3 RIBs,
 * the VN address is sufficient because it represents the actual next hop.
 *
 * For L2 RIBs, it is possible to have multiple routes to a given L2
 * prefix via a given VN address, but each route having a unique aux_prefix.
 */
struct rfapi_rib_key {
	struct prefix vn;
	struct prefix_rd rd;

	/*
	 * for L2 routes: optional IP addr
	 * .family == 0 means "none"
	 */
	struct prefix aux_prefix;
};
#include "rfapi.h"

/*
 * RFAPI Advertisement Data Block
 *
 * Holds NVE prefix advertisement information
 */
struct rfapi_adb {
	union {
		struct {
			struct prefix prefix_ip;
			struct prefix_rd prd;
			struct prefix prefix_eth;
		} s; /* mainly for legacy use */
		struct rfapi_rib_key key;
	} u;
	uint32_t lifetime;
	uint8_t cost;
	struct rfapi_l2address_option l2o;
};

struct rfapi_info {
	struct rfapi_rib_key rk; /* NVE VN addr + aux addr */
	struct prefix un;
	uint8_t cost;
	uint32_t lifetime;
	time_t last_sent_time;
	uint32_t rsp_counter; /* dedup initial responses */
	struct bgp_tea_options *tea_options;
	struct rfapi_un_option *un_options;
	struct rfapi_vn_option *vn_options;
	struct event *timer;
};

/*
 * Work item for updated responses queue
 */
struct rfapi_updated_responses_queue {
	struct rfapi_descriptor *rfd;
	afi_t afi;
};


extern void rfapiRibClear(struct rfapi_descriptor *rfd);

extern void rfapiRibFree(struct rfapi_descriptor *rfd);

extern void rfapiRibUpdatePendingNode(struct bgp *bgp,
				      struct rfapi_descriptor *rfd,
				      struct rfapi_import_table *it,
				      struct agg_node *it_node,
				      uint32_t lifetime);

extern void rfapiRibUpdatePendingNodeSubtree(struct bgp *bgp,
					     struct rfapi_descriptor *rfd,
					     struct rfapi_import_table *it,
					     struct agg_node *it_node,
					     struct agg_node *omit_subtree,
					     uint32_t lifetime);

extern int rfapiRibPreloadBi(struct agg_node *rfd_rib_node,
			     struct prefix *pfx_vn, struct prefix *pfx_un,
			     uint32_t lifetime, struct bgp_path_info *bpi);

extern struct rfapi_next_hop_entry *
rfapiRibPreload(struct bgp *bgp, struct rfapi_descriptor *rfd,
		struct rfapi_next_hop_entry *response, int use_eth_resolution);

extern void rfapiRibPendingDeleteRoute(struct bgp *bgp,
				       struct rfapi_import_table *it, afi_t afi,
				       struct agg_node *it_node);

extern void rfapiRibShowResponsesSummary(void *stream);

extern void rfapiRibShowResponsesSummaryClear(void);

extern void rfapiRibShowResponses(void *stream, struct prefix *pfx_match,
				  int show_removed);

extern int rfapiRibFTDFilterRecentPrefix(
	struct rfapi_descriptor *rfd,
	struct agg_node *it_rn,		     /* import table node */
	struct prefix *pfx_target_original); /* query target */

extern void rfapiFreeRfapiUnOptionChain(struct rfapi_un_option *p);

extern void rfapiFreeRfapiVnOptionChain(struct rfapi_vn_option *p);

extern void
rfapiRibCheckCounts(int checkstats,       /* validate rfd & global counts */
		    unsigned int offset); /* number of ri's held separately */

/* enable for debugging; disable for performance */
#if 0
#define RFAPI_RIB_CHECK_COUNTS(checkstats, offset)	rfapiRibCheckCounts(checkstats, offset)
#else
#define RFAPI_RIB_CHECK_COUNTS(checkstats, offset)
#endif

extern void rfapi_rib_key_init(struct prefix *prefix, /* may be NULL */
			       struct prefix_rd *rd,  /* may be NULL */
			       struct prefix *aux,    /* may be NULL */
			       struct rfapi_rib_key *rk);

extern int rfapi_rib_key_cmp(const void *k1, const void *k2);

extern void rfapiAdbFree(struct rfapi_adb *adb);

#endif /* QUAGGA_HGP_RFAPI_RIB_H */
