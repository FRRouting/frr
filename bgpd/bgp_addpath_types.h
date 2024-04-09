// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Addpath TX ID selection, and related utilities
 * Copyright (C) 2018  Amazon.com, Inc. or its affiliates
 */

#ifndef _QUAGGA_BGPD_TX_ADDPATH_DATA_H
#define _QUAGGA_BGPD_TX_ADDPATH_DATA_H
#include "lib/id_alloc.h"
#include <stdint.h>

enum bgp_addpath_strat {
	BGP_ADDPATH_ALL = 0,
	BGP_ADDPATH_BEST_PER_AS,
	BGP_ADDPATH_BEST_SELECTED,
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
