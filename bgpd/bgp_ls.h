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
};

/* Function prototypes */

/* Module initialization and cleanup */
extern void bgp_ls_init(struct bgp *bgp);
extern void bgp_ls_cleanup(struct bgp *bgp);

#endif /* _FRR_BGP_LS_H */
