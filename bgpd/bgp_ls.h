// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State (RFC 9552) - Core Constants and Structures
 * Copyright (C) 2025 Carmine Scarpitta
 */

#ifndef _FRR_BGP_LS_H
#define _FRR_BGP_LS_H

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ls_nlri.h"

struct bgp_ls {
	/* Back-pointer to parent BGP instance */
	struct bgp *bgp;

	/* Hash table for BGP-LS NLRIs (nodes, links, prefixes) */
	struct bgp_ls_nlri_hash_head nlri_hash;

	/* Hash table for BGP-LS Attributes */
	struct bgp_ls_attr_hash_head ls_attr_hash;

	/* Traffic Engineering Database */
	struct ls_ted *ted;

	/* NLRI ID allocator */
	struct id_alloc *allocator;

	/* Link-state database registration status */
	bool registered_ls_db;

	bool enable_distribution;

	/* BGP-fabric link-state instance ID */
	uint64_t instance_id;
};

/* Function prototypes */

/*
 * ===========================================================================
 * RIB Operations
 * ===========================================================================
 */

/*
 * Install or update BGP-LS route in RIB
 *
 * This function handles locally originated BGP-LS routes from IGP.
 * It creates a synthetic prefix in the standard BGP RIB and stores
 * the full NLRI in bgp_path_info_extra->ls_nlri.
 *
 * @param bgp - BGP instance
 * @param nlri - Decoded BGP-LS NLRI
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_update(struct bgp *bgp, struct bgp_ls_nlri *nlri, struct bgp_ls_attr *ls_attr);

/*
 * Remove BGP-LS route from RIB
 *
 * This function handles withdrawal of locally originated BGP-LS routes.
 * It marks the route as removed and triggers BGP processing for
 * withdrawal advertisement to peers.
 *
 * @param bgp - BGP instance
 * @param nlri - Decoded BGP-LS NLRI
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_withdraw(struct bgp *bgp, struct bgp_ls_nlri *nlri);

/* BGP-LS NLRI parsing */
extern int bgp_nlri_parse_ls(struct peer *peer, struct attr *attr, struct bgp_nlri *packet);

/* BGP-LS registration with link-state database */
extern bool bgp_ls_register(struct bgp *bgp);
extern bool bgp_ls_unregister(struct bgp *bgp);
extern bool bgp_ls_is_registered(struct bgp *bgp);

/* BGP-LS NLRI lookup helpers */
extern struct bgp_dest *bgp_ls_lookup_nlri_by_str(struct bgp *bgp, const char *nlri_str);

/* BGP-LS NLRI helpers */
extern struct json_object *bgp_ls_nlri_to_json(struct bgp_ls_nlri *nlri);
extern void bgp_ls_nlri_format(struct bgp_ls_nlri *nlri, char *buf, size_t buf_len);

/* Module initialization and cleanup */
extern void bgp_ls_init(struct bgp *bgp);
extern void bgp_ls_cleanup(struct bgp *bgp);

/*
 * ===========================================================================
 * BGP Topology Export (BGP-only fabrics)
 * ===========================================================================
 */

/*
 * Export BGP topology as BGP-LS NLRIs
 *
 * Iterates through all BGP peers and generates Node and Link NLRIs
 * representing the BGP topology. Used for BGP-only fabrics per
 * draft-ietf-idr-bgp-ls-bgp-only-fabric.
 *
 * @param bgp - BGP instance
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_export_bgp_topology(struct bgp *bgp);
void bgp_ls_withdraw_all(struct bgp *bgp);
int bgp_ls_withdraw_bgp_link(struct bgp *bgp, struct peer *peer);
int bgp_ls_withdraw_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
			       struct bgp_path_info *path);

/*
 * ===========================================================================
 * Link State Message Processing
 * ===========================================================================
 */

extern int bgp_ls_originate_bgp_node(struct bgp *bgp);
extern int bgp_ls_originate_bgp_link(struct bgp *bgp, struct peer *peer);
extern int bgp_ls_originate_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi,
				       struct bgp_dest *dest, struct bgp_path_info *path);

#endif /* _FRR_BGP_LS_H */
