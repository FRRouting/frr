// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Addpath TX ID selection, and related utilities
 * Copyright (C) 2018  Amazon.com, Inc. or its affiliates
 */

#ifndef _QUAGGA_BGPD_TX_ADDPATH_H
#define _QUAGGA_BGPD_TX_ADDPATH_H

#include <stdint.h>
#include <zebra.h>

#include "bgpd/bgp_addpath_types.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "lib/json.h"

#define BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE 1

void bgp_addpath_init_bgp_data(struct bgp_addpath_bgp_data *d);

bool bgp_addpath_is_addpath_used(struct bgp_addpath_bgp_data *d, afi_t afi,
				 safi_t safi);

void bgp_addpath_free_node_data(struct bgp_addpath_bgp_data *bd,
			      struct bgp_addpath_node_data *nd,
			      afi_t afi, safi_t safi);

void bgp_addpath_free_info_data(struct bgp_addpath_info_data *d,
			      struct bgp_addpath_node_data *nd);


bool bgp_addpath_info_has_ids(struct bgp_addpath_info_data *d);

uint32_t bgp_addpath_id_for_peer(struct peer *peer, afi_t afi, safi_t safi,
				struct bgp_addpath_info_data *d);

const struct bgp_addpath_strategy_names *
bgp_addpath_names(enum bgp_addpath_strat strat);

bool bgp_addpath_dmed_required(int strategy);

/*
 * Return true if this is a path we should advertise due to a configured
 * addpath-tx knob
 */
bool bgp_addpath_tx_path(enum bgp_addpath_strat strat,
			 struct bgp_path_info *pi);
/*
 * Change the type of addpath used for a peer.
 */
void bgp_addpath_set_peer_type(struct peer *peer, afi_t afi, safi_t safi,
			       enum bgp_addpath_strat addpath_type,
			       uint8_t paths);

void bgp_addpath_update_ids(struct bgp *bgp, struct bgp_dest *dest, afi_t afi,
			    safi_t safi);

void bgp_addpath_type_changed(struct bgp *bgp);
#endif
