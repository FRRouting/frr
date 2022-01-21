// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * isis_flex_algo.h: IS-IS Flexible Algorithm
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#ifndef ISIS_FLEX_ALGO_H
#define ISIS_FLEX_ALGO_H

#include "flex_algo.h"
#include "isisd/isis_constants.h"

#ifndef FABRICD

struct isis_flex_algo_data {
	struct isis_spftree *spftree[SPFTREE_COUNT][ISIS_LEVELS];
	struct isis_area *area;
};

struct isis_flex_algo_alloc_arg {
	uint8_t algorithm;
	struct isis_area *area;
};

void *isis_flex_algo_data_alloc(void *arg);
void isis_flex_algo_data_free(void *data);

struct isis_router_cap_fad *
isis_flex_algo_elected(int algorithm, const struct isis_area *area);
bool isis_flex_algo_supported(struct flex_algo *fad);
struct isis_router_cap_fad *
isis_flex_algo_elected_supported(int algorithm, const struct isis_area *area);
struct isis_router_cap_fad *
isis_flex_algo_elected_supported_local_fad(int algorithm,
					   const struct isis_area *area,
					   struct isis_router_cap_fad **fad);
struct isis_lsp;
bool sr_algorithm_participated(const struct isis_lsp *lsp, uint8_t algorithm);

bool isis_flex_algo_constraint_drop(struct isis_spftree *spftree,
				    struct isis_lsp *lsp,
				    struct isis_extended_reach *reach);

#endif /* ifndef FABRICD */

#endif /* ISIS_FLEX_ALGO_H */
