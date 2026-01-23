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

	/* Traffic Engineering Database */
	struct ls_ted *ted;

	/* NLRI ID allocator */
	struct id_alloc *allocator;

	/* Link-state database registration status */
	bool registered_ls_db;
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
extern int bgp_ls_update(struct bgp *bgp, struct bgp_ls_nlri *nlri);

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

/* BGP-LS registration with link-state database */
extern bool bgp_ls_register(struct bgp *bgp);
extern bool bgp_ls_unregister(struct bgp *bgp);
extern bool bgp_ls_is_registered(struct bgp *bgp);

/* Module initialization and cleanup */
extern void bgp_ls_init(struct bgp *bgp);
extern void bgp_ls_cleanup(struct bgp *bgp);

#endif /* _FRR_BGP_LS_H */
