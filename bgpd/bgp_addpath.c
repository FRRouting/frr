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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bgp_addpath.h"
#include "bgp_route.h"

static struct bgp_addpath_strategy_names strat_names[BGP_ADDPATH_MAX] = {
	{
		.config_name = "addpath-tx-all-paths",
		.human_name = "All",
		.human_description = "Advertise all paths via addpath",
		.type_json_name = "addpathTxAllPaths",
		.id_json_name = "addpathTxIdAll"
	},
	{
		.config_name = "addpath-tx-bestpath-per-AS",
		.human_name = "Best-Per-AS",
		.human_description = "Advertise bestpath per AS via addpath",
		.type_json_name = "addpathTxBestpathPerAS",
		.id_json_name = "addpathTxIdBestPerAS"
	}
};

static struct bgp_addpath_strategy_names unknown_names = {
	.config_name = "addpath-tx-unknown",
	.human_name = "Unknown-Addpath-Strategy",
	.human_description = "Unknown Addpath Strategy",
	.type_json_name = "addpathTxUnknown",
	.id_json_name = "addpathTxIdUnknown"
};

/*
 * Returns a structure full of strings associated with an addpath type. Will
 * never return null.
 */
struct bgp_addpath_strategy_names *
bgp_addpath_names(enum bgp_addpath_strat strat)
{
	if (strat < BGP_ADDPATH_MAX)
		return &(strat_names[strat]);
	else
		return &unknown_names;
};

/*
 * Returns if any peer is transmitting addpaths for a given afi/safi.
 */
int bgp_addpath_is_addpath_used(struct bgp_addpath_bgp_data *d, afi_t afi,
			      safi_t safi)
{
	return d->total_peercount[afi][safi] > 0;
}

/*
 * Initialize the BGP instance level data for addpath.
 */
void bgp_addpath_init_bgp_data(struct bgp_addpath_bgp_data *d)
{
	safi_t safi;
	afi_t afi;
	int i;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			for (i = 0; i < BGP_ADDPATH_MAX; i++) {
				d->id_allocators[afi][safi][i] = NULL;
				d->peercount[afi][safi][i] = 0;
			}
			d->total_peercount[afi][safi] = 0;
		}
	}
}

/*
 * Free up resources associated with BGP route info structures.
 */
void bgp_addpath_free_info_data(struct bgp_addpath_info_data *d,
			      struct bgp_addpath_node_data *nd)
{
	int i;

	for (i = 0; i < BGP_ADDPATH_MAX; i++) {
		if (d->addpath_tx_id[i] != IDALLOC_INVALID)
			idalloc_free_to_pool(&nd->free_ids[i],
					     d->addpath_tx_id[i]);
	}
}

/*
 * Return the addpath ID used to send a particular route, to a particular peer,
 * in a particular AFI/SAFI.
 */
uint32_t bgp_addpath_id_for_peer(struct peer *peer, afi_t afi, safi_t safi,
				struct bgp_addpath_info_data *d)
{
	if (peer->addpath_type[afi][safi] < BGP_ADDPATH_MAX)
		return d->addpath_tx_id[peer->addpath_type[afi][safi]];
	else
		return IDALLOC_INVALID;
}

/*
 * Returns true if the path has an assigned addpath ID for any of the addpath
 * strategies.
 */
int bgp_addpath_info_has_ids(struct bgp_addpath_info_data *d)
{
	int i;

	for (i = 0; i < BGP_ADDPATH_MAX; i++)
		if (d->addpath_tx_id[i] != 0)
			return 1;

	return 0;
}

/*
 * Releases any ID's associated with the BGP prefix.
 */
void bgp_addpath_free_node_data(struct bgp_addpath_bgp_data *bd,
			      struct bgp_addpath_node_data *nd, afi_t afi,
			      safi_t safi)
{
	int i;

	for (i = 0; i < BGP_ADDPATH_MAX; i++) {
		idalloc_drain_pool(bd->id_allocators[afi][safi][i],
				   &(nd->free_ids[i]));
	}
}

/*
 * Check to see if the addpath strategy requires DMED to be configured to work.
 */
int bgp_addpath_dmed_required(int strategy)
{
	return strategy == BGP_ADDPATH_BEST_PER_AS;
}

/*
 * Return true if this is a path we should advertise due to a
 * configured addpath-tx knob
 */
int bgp_addpath_tx_path(enum bgp_addpath_strat strat,
			    struct bgp_path_info *pi)
{
	switch (strat) {
	case BGP_ADDPATH_NONE:
		return 0;
	case BGP_ADDPATH_ALL:
		return 1;
	case BGP_ADDPATH_BEST_PER_AS:
		if (CHECK_FLAG(pi->flags, BGP_PATH_DMED_SELECTED))
			return 1;
		else
			return 0;
	default:
		return 0;
	}
}

static void bgp_addpath_flush_type_rn(struct bgp *bgp, afi_t afi, safi_t safi,
				      enum bgp_addpath_strat addpath_type,
				      struct bgp_node *rn)
{
	struct bgp_path_info *pi;

	idalloc_drain_pool(
		bgp->tx_addpath.id_allocators[afi][safi][addpath_type],
		&(rn->tx_addpath.free_ids[addpath_type]));
	for (pi = bgp_node_get_bgp_path_info(rn); pi; pi = pi->next) {
		if (pi->tx_addpath.addpath_tx_id[addpath_type]
		    != IDALLOC_INVALID) {
			idalloc_free(
				bgp->tx_addpath
					.id_allocators[afi][safi][addpath_type],
				pi->tx_addpath.addpath_tx_id[addpath_type]);
			pi->tx_addpath.addpath_tx_id[addpath_type] =
				IDALLOC_INVALID;
		}
	}
}

/*
 * Purge all addpath ID's on a BGP instance associated with the addpath
 * strategy, and afi/safi combination. This lets us let go of all memory held to
 * track ID numbers associated with an addpath type not in use. Since
 * post-bestpath ID processing is skipped for types not used, this is the only
 * chance to free this data.
 */
static void bgp_addpath_flush_type(struct bgp *bgp, afi_t afi, safi_t safi,
				   enum bgp_addpath_strat addpath_type)
{
	struct bgp_node *rn, *nrn;

	for (rn = bgp_table_top(bgp->rib[afi][safi]); rn;
	     rn = bgp_route_next(rn)) {
		if (safi == SAFI_MPLS_VPN) {
			struct bgp_table *table;

			table = bgp_node_get_bgp_table_info(rn);
			if (!table)
				continue;

			for (nrn = bgp_table_top(table); nrn;
			     nrn = bgp_route_next(nrn))
				bgp_addpath_flush_type_rn(bgp, afi, safi,
							  addpath_type, nrn);
		} else {
			bgp_addpath_flush_type_rn(bgp, afi, safi, addpath_type,
						  rn);
		}
	}

	idalloc_destroy(bgp->tx_addpath.id_allocators[afi][safi][addpath_type]);
	bgp->tx_addpath.id_allocators[afi][safi][addpath_type] = NULL;
}

/*
 * Allocate an Addpath ID for the given type on a path, if necessary.
 */
static void bgp_addpath_populate_path(struct id_alloc *allocator,
				      struct bgp_path_info *path,
				      enum bgp_addpath_strat addpath_type)
{
	if (bgp_addpath_tx_path(addpath_type, path)) {
		path->tx_addpath.addpath_tx_id[addpath_type] =
			idalloc_allocate(allocator);
	}
}

/*
 * Compute addpath ID's on a BGP instance associated with the addpath strategy,
 * and afi/safi combination. Since we won't waste the time computing addpath IDs
 * for unused strategies, the first time a peer is configured to use a strategy,
 * we have to backfill the data.
 */
static void bgp_addpath_populate_type(struct bgp *bgp, afi_t afi, safi_t safi,
				    enum bgp_addpath_strat addpath_type)
{
	struct bgp_node *rn, *nrn;
	char buf[200];
	struct id_alloc *allocator;

	snprintf(buf, sizeof(buf), "Addpath ID Allocator %s:%d/%d",
		 bgp_addpath_names(addpath_type)->config_name, (int)afi,
		 (int)safi);
	buf[sizeof(buf) - 1] = '\0';
	zlog_info("Computing addpath IDs for addpath type %s",
		bgp_addpath_names(addpath_type)->human_name);

	bgp->tx_addpath.id_allocators[afi][safi][addpath_type] =
		idalloc_new(buf);

	idalloc_reserve(bgp->tx_addpath.id_allocators[afi][safi][addpath_type],
		BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);

	allocator = bgp->tx_addpath.id_allocators[afi][safi][addpath_type];

	for (rn = bgp_table_top(bgp->rib[afi][safi]); rn;
	     rn = bgp_route_next(rn)) {
		struct bgp_path_info *bi;

		if (safi == SAFI_MPLS_VPN) {
			struct bgp_table *table;

			table = bgp_node_get_bgp_table_info(rn);
			if (!table)
				continue;

			for (nrn = bgp_table_top(table); nrn;
			     nrn = bgp_route_next(nrn))
				for (bi = bgp_node_get_bgp_path_info(nrn); bi;
				     bi = bi->next)
					bgp_addpath_populate_path(allocator, bi,
								  addpath_type);
		} else {
			for (bi = bgp_node_get_bgp_path_info(rn); bi;
			     bi = bi->next)
				bgp_addpath_populate_path(allocator, bi,
							  addpath_type);
		}
	}
}

/*
 * Handle updates to a peer or group's addpath strategy. If after adjusting
 * counts a addpath strategy is in use for the first time, or no longer in use,
 * the IDs for that strategy will be populated or flushed.
 */
void bgp_addpath_type_changed(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct listnode *node, *nnode;
	struct peer *peer;
	int peer_count[AFI_MAX][SAFI_MAX][BGP_ADDPATH_MAX];
	enum bgp_addpath_strat type;

	FOREACH_AFI_SAFI(afi, safi) {
		for (type=0; type<BGP_ADDPATH_MAX; type++) {
			peer_count[afi][safi][type] = 0;
		}
		bgp->tx_addpath.total_peercount[afi][safi] = 0;
	}

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		FOREACH_AFI_SAFI(afi, safi) {
			type = peer->addpath_type[afi][safi];
			if (type != BGP_ADDPATH_NONE) {
				peer_count[afi][safi][type] += 1;
				bgp->tx_addpath.total_peercount[afi][safi] += 1;
			}
		}
	}

	FOREACH_AFI_SAFI(afi, safi) {
		for (type=0; type<BGP_ADDPATH_MAX; type++) {
			int old = bgp->tx_addpath.peercount[afi][safi][type];
			int new = peer_count[afi][safi][type];

			bgp->tx_addpath.peercount[afi][safi][type] = new;

			if (old == 0 && new != 0) {
				bgp_addpath_populate_type(bgp, afi, safi,
					type);
			} else if (old != 0 && new == 0) {
				bgp_addpath_flush_type(bgp, afi, safi, type);
			}
		}
	}
}

/*
 * Change the addpath type assigned to a peer, or peer group. In addition to
 * adjusting the counts, peer sessions will be reset as needed to make the
 * change take effect.
 */
void bgp_addpath_set_peer_type(struct peer *peer, afi_t afi, safi_t safi,
			      enum bgp_addpath_strat addpath_type)
{
	struct bgp *bgp = peer->bgp;
	enum bgp_addpath_strat old_type = peer->addpath_type[afi][safi];
	struct listnode *node, *nnode;
	struct peer *tmp_peer;
	struct peer_group *group;

	if (addpath_type == old_type)
		return;

	if (addpath_type == BGP_ADDPATH_NONE && peer->group &&
	    !CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* A "no" config on a group member inherits group */
		addpath_type = peer->group->conf->addpath_type[afi][safi];
	}

	peer->addpath_type[afi][safi] = addpath_type;

	bgp_addpath_type_changed(bgp);

	if (addpath_type != BGP_ADDPATH_NONE) {
		if (bgp_addpath_dmed_required(addpath_type)) {
			if (!bgp_flag_check(bgp, BGP_FLAG_DETERMINISTIC_MED)) {
				zlog_warn(
					"%s: enabling bgp deterministic-med, this is required for addpath-tx-bestpath-per-AS",
					peer->host);
				bgp_flag_set(bgp, BGP_FLAG_DETERMINISTIC_MED);
				bgp_recalculate_all_bestpaths(bgp);
			}
		}
	}

	zlog_info("Resetting peer %s%s due to change in addpath config",
		  CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP) ? "group " : "",
		  peer->host);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;

		/* group will be null as peer_group_delete calls peer_delete on
		 * group->conf. That peer_delete will eventuallly end up here
		 * if the group was configured to tx addpaths.
		 */
		if (group != NULL) {
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
			     tmp_peer)) {
				if (tmp_peer->addpath_type[afi][safi] ==
				    old_type) {
					bgp_addpath_set_peer_type(tmp_peer,
								 afi,
								 safi,
								 addpath_type);
				}
			}
		}
	} else {
		peer_change_action(peer, afi, safi, peer_change_reset);
	}

}

/*
 * Intended to run after bestpath. This function will take TX IDs from paths
 * that no longer need them, and give them to paths that do. This prevents
 * best-per-as updates from needing to do a separate withdraw and update just to
 * swap out which path is sent.
 */
void bgp_addpath_update_ids(struct bgp *bgp, struct bgp_node *bn, afi_t afi,
			  safi_t safi)
{
	int i;
	struct bgp_path_info *pi;
	struct id_alloc_pool **pool_ptr;

	for (i = 0; i < BGP_ADDPATH_MAX; i++) {
		struct id_alloc *alloc =
			bgp->tx_addpath.id_allocators[afi][safi][i];
		pool_ptr = &(bn->tx_addpath.free_ids[i]);

		if (bgp->tx_addpath.peercount[afi][safi][i] == 0)
			continue;

		/* Free Unused IDs back to the pool.*/
		for (pi = bgp_node_get_bgp_path_info(bn); pi; pi = pi->next) {
			if (pi->tx_addpath.addpath_tx_id[i] != IDALLOC_INVALID
			    && !bgp_addpath_tx_path(i, pi)) {
				idalloc_free_to_pool(pool_ptr,
					pi->tx_addpath.addpath_tx_id[i]);
				pi->tx_addpath.addpath_tx_id[i] =
					IDALLOC_INVALID;
			}
		}

		/* Give IDs to paths that need them (pulling from the pool) */
		for (pi = bgp_node_get_bgp_path_info(bn); pi; pi = pi->next) {
			if (pi->tx_addpath.addpath_tx_id[i] == IDALLOC_INVALID
			    && bgp_addpath_tx_path(i, pi)) {
				pi->tx_addpath.addpath_tx_id[i] =
					idalloc_allocate_prefer_pool(
						alloc, pool_ptr);
			}
		}

		/* Free any IDs left in the pool to the main allocator */
		idalloc_drain_pool(alloc, pool_ptr);
	}
}
