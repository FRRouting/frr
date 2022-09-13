/*
 * IS-IS Flexible Algorithm definitions
 * Copyright (C) 2022  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2022  Masakazu Asama
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef ISIS_FLEX_ALGO_H
#define ISIS_FLEX_ALGO_H

#include "flex_algo.h"
#include "isisd/isis_constants.h"

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

struct isis_router_cap_fad *isis_flex_algo_elected(int algorithm,
						       struct isis_area *area);
bool isis_flex_algo_supported(struct flex_algo *fad);
struct isis_router_cap_fad *isis_flex_algo_elected_supported(int algorithm,
						       struct isis_area *area);
struct isis_router_cap_fad *isis_flex_algo_elected_supported_local_fad(int algorithm,
						       struct isis_area *area,
							   struct isis_router_cap_fad **fad);
bool isis_flex_algo_constraint_drop(struct isis_spftree *spftree,
				    struct isis_ext_subtlvs *subtlvs);
struct isis_lsp;
bool sr_algorithm_participated(const struct isis_lsp *lsp, uint8_t algorithm);

#endif /* ISIS_FLEX_ALGO_H */
