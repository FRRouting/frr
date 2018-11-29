/*
 * Addpath TX ID selection, and related utilities
 * Copyright (C) 2018  Amazon.com, Inc. or its affiliates
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

#ifndef _QUAGGA_BGPD_TX_ADDPATH_DATA_H
#define _QUAGGA_BGPD_TX_ADDPATH_DATA_H
#include "lib/id_alloc.h"
#include <stdint.h>

enum bgp_addpath_strat {
	BGP_ADDPATH_ALL = 0,
	BGP_ADDPATH_BEST_PER_AS,
	BGP_ADDPATH_MAX,
	BGP_ADDPATH_NONE,
};

/* TX Addpath structures */
struct bgp_addpath_bgp_data {
	unsigned int peercount[AFI_MAX][SAFI_MAX][BGP_ADDPATH_MAX];
	unsigned int total_peercount[AFI_MAX][SAFI_MAX];
	struct id_alloc *id_allocators[AFI_MAX][SAFI_MAX][BGP_ADDPATH_MAX];
};

struct bgp_addpath_node_data {
	struct id_alloc_pool *free_ids[BGP_ADDPATH_MAX];
};

struct bgp_addpath_info_data {
	uint32_t addpath_tx_id[BGP_ADDPATH_MAX];
};

struct bgp_addpath_strategy_names {
	const char *config_name;
	const char *human_name;	       /* path detail non-json */
	const char *human_description; /* non-json peer descriptions */
	const char *type_json_name;    /* json peer listings */
	const char *id_json_name;      /* path json output for tx ID# */
};

#endif
