// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Distributed Flooding Reduction (draft-ietf-lsr-distoptflood)
 *
 * This module contains the topology snapshot and the per-LSP flooding
 * decision described in section 1.2.3 of the draft. It has no
 * knowledge of circuits or transmit queues: callers hand it the set of
 * neighbors the local IS has up adjacencies with, and it tells them
 * which of those neighbors the received LSP must be re-flooded to.
 *
 * Copyright 2026 Russ White, Nokia
 */

#ifndef ISIS_FLOOD_REDUCTION_H
#define ISIS_FLOOD_REDUCTION_H

#include "isisd/isis_constants.h"
#include "isisd/isis_lsp.h"

/* Default number of RNL members that must cover each THL member. */
#define ISIS_FR_DEFAULT_REDUNDANCY 1
#define ISIS_FR_MAX_REDUNDANCY	   8

/*
 * Immutable snapshot of the IS-IS topology for one level, built from
 * an LSPDB. Links are the two-way checked IS adjacencies found in all
 * topologies (RFC 5120), with pseudonodes collapsed into direct
 * IS-to-IS links. Metrics and the overload bit are ignored.
 */
struct isis_fr_graph;

enum isis_fr_verdict {
	/*
	 * The algorithm could not be applied (for example, the
	 * transmitting neighbor is not in the topology snapshot yet).
	 * The caller must fall back to standard flooding.
	 */
	ISIS_FR_FLOOD_ALL = 0,
	/* The per-neighbor flood[] output is valid. */
	ISIS_FR_REDUCED,
};

struct isis_fr_decision {
	enum isis_fr_verdict verdict;
	/* True if the local IS was chosen as a re-flooder (step 4B). */
	bool selected;
	/* Number of THL members left after step 1 (debug/statistics). */
	unsigned int thl_count;
	/* Number of RNL members (debug/statistics). */
	unsigned int rnl_count;
	/* Index N computed in step 3. */
	unsigned int start_index;
	/*
	 * Number of local neighbors, other than the transmitting
	 * neighbor, the LSP is not flooded to. A non-zero value means
	 * the LSP must be tracked by the partial-flooding recovery
	 * mechanism (section 1.2.4).
	 */
	unsigned int suppressed;
};

extern struct isis_fr_graph *isis_fr_graph_build(struct lspdb_head *lspdb);
extern void isis_fr_graph_free(struct isis_fr_graph **graph);
extern unsigned int isis_fr_graph_node_count(const struct isis_fr_graph *graph);

/*
 * Hash of an LSP ID used to select the first RNL member in step 4:
 * Fletcher-16 over the 8-octet LSP ID with the fragment number shifted
 * down by 3 bits, using end-around-carry folding in place of the
 * modulo operation.
 */
extern uint16_t isis_fr_lsp_hash(const uint8_t *lsp_id);

/*
 * Run the flooding decision for an LSP received from a transmitting
 * neighbor.
 *
 * local:      system ID of the calculating IS
 * tn:         system ID of the transmitting neighbor
 * lsp_id:     LSP ID of the received fragment
 * redundancy: number of RNL members that must cover each THL member
 * nbrs:       system IDs of all neighbors with up adjacencies
 * flood:      output, flood[i] tells whether to send the LSP to nbrs[i]
 *
 * Neighbors the local IS has an adjacency with that are not adjacent
 * to it in the topology snapshot are always flooded to, as the
 * calculation cannot reason about them.
 */
extern enum isis_fr_verdict isis_fr_decide(struct isis_fr_graph *graph, const uint8_t *local,
					   const uint8_t *tn, const uint8_t *lsp_id,
					   unsigned int redundancy,
					   const uint8_t nbrs[][ISIS_SYS_ID_LEN], size_t n_nbrs,
					   bool *flood, struct isis_fr_decision *decision);

#endif /* ISIS_FLOOD_REDUCTION_H */
