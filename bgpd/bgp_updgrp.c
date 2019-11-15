/**
 * bgp_updgrp.c: BGP update group structures
 *
 * @copyright Copyright (C) 2014 Cumulus Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.net>
 * @author Rajesh Varadarajan <rajesh@sproute.net>
 * @author Pradosh Mohapatra <pradosh@sproute.net>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "command.h"
#include "sockunion.h"
#include "network.h"
#include "memory.h"
#include "filter.h"
#include "routemap.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "hash.h"
#include "jhash.h"
#include "queue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_io.h"

/********************
 * PRIVATE FUNCTIONS
 ********************/

/**
 * assign a unique ID to update group and subgroup. Mostly for display/
 * debugging purposes. It's a 64-bit space - used leisurely without a
 * worry about its wrapping and about filling gaps. While at it, timestamp
 * the creation.
 */
static void update_group_checkin(struct update_group *updgrp)
{
	updgrp->id = ++bm->updgrp_idspace;
	updgrp->uptime = bgp_clock();
}

static void update_subgroup_checkin(struct update_subgroup *subgrp,
				    struct update_group *updgrp)
{
	subgrp->id = ++bm->subgrp_idspace;
	subgrp->uptime = bgp_clock();
}

static void sync_init(struct update_subgroup *subgrp)
{
	subgrp->sync =
		XCALLOC(MTYPE_BGP_SYNCHRONISE, sizeof(struct bgp_synchronize));
	bgp_adv_fifo_init(&subgrp->sync->update);
	bgp_adv_fifo_init(&subgrp->sync->withdraw);
	bgp_adv_fifo_init(&subgrp->sync->withdraw_low);
	subgrp->hash =
		hash_create(baa_hash_key, baa_hash_cmp, "BGP SubGroup Hash");

	/* We use a larger buffer for subgrp->work in the event that:
	 * - We RX a BGP_UPDATE where the attributes alone are just
	 *   under BGP_MAX_PACKET_SIZE
	 * - The user configures an outbound route-map that does many as-path
	 *   prepends or adds many communities.  At most they can have
	 * CMD_ARGC_MAX
	 *   args in a route-map so there is a finite limit on how large they
	 * can
	 *   make the attributes.
	 *
	 * Having a buffer with BGP_MAX_PACKET_SIZE_OVERFLOW allows us to avoid
	 * bounds
	 * checking for every single attribute as we construct an UPDATE.
	 */
	subgrp->work =
		stream_new(BGP_MAX_PACKET_SIZE + BGP_MAX_PACKET_SIZE_OVERFLOW);
	subgrp->scratch = stream_new(BGP_MAX_PACKET_SIZE);
}

static void sync_delete(struct update_subgroup *subgrp)
{
	XFREE(MTYPE_BGP_SYNCHRONISE, subgrp->sync);
	subgrp->sync = NULL;
	if (subgrp->hash)
		hash_free(subgrp->hash);
	subgrp->hash = NULL;
	if (subgrp->work)
		stream_free(subgrp->work);
	subgrp->work = NULL;
	if (subgrp->scratch)
		stream_free(subgrp->scratch);
	subgrp->scratch = NULL;
}

/**
 * conf_copy
 *
 * copy only those fields that are relevant to update group match
 */
static void conf_copy(struct peer *dst, struct peer *src, afi_t afi,
		      safi_t safi)
{
	struct bgp_filter *srcfilter;
	struct bgp_filter *dstfilter;

	srcfilter = &src->filter[afi][safi];
	dstfilter = &dst->filter[afi][safi];

	dst->bgp = src->bgp;
	dst->sort = src->sort;
	dst->as = src->as;
	dst->v_routeadv = src->v_routeadv;
	dst->flags = src->flags;
	dst->af_flags[afi][safi] = src->af_flags[afi][safi];
	XFREE(MTYPE_BGP_PEER_HOST, dst->host);

	dst->host = XSTRDUP(MTYPE_BGP_PEER_HOST, src->host);
	dst->cap = src->cap;
	dst->af_cap[afi][safi] = src->af_cap[afi][safi];
	dst->afc_nego[afi][safi] = src->afc_nego[afi][safi];
	dst->orf_plist[afi][safi] = src->orf_plist[afi][safi];
	dst->addpath_type[afi][safi] = src->addpath_type[afi][safi];
	dst->local_as = src->local_as;
	dst->change_local_as = src->change_local_as;
	dst->shared_network = src->shared_network;
	memcpy(&(dst->nexthop), &(src->nexthop), sizeof(struct bgp_nexthop));

	dst->group = src->group;

	if (src->default_rmap[afi][safi].name) {
		dst->default_rmap[afi][safi].name =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME,
				src->default_rmap[afi][safi].name);
		dst->default_rmap[afi][safi].map =
			src->default_rmap[afi][safi].map;
	}

	if (DISTRIBUTE_OUT_NAME(srcfilter)) {
		DISTRIBUTE_OUT_NAME(dstfilter) = XSTRDUP(
			MTYPE_BGP_FILTER_NAME, DISTRIBUTE_OUT_NAME(srcfilter));
		DISTRIBUTE_OUT(dstfilter) = DISTRIBUTE_OUT(srcfilter);
	}

	if (PREFIX_LIST_OUT_NAME(srcfilter)) {
		PREFIX_LIST_OUT_NAME(dstfilter) = XSTRDUP(
			MTYPE_BGP_FILTER_NAME, PREFIX_LIST_OUT_NAME(srcfilter));
		PREFIX_LIST_OUT(dstfilter) = PREFIX_LIST_OUT(srcfilter);
	}

	if (FILTER_LIST_OUT_NAME(srcfilter)) {
		FILTER_LIST_OUT_NAME(dstfilter) = XSTRDUP(
			MTYPE_BGP_FILTER_NAME, FILTER_LIST_OUT_NAME(srcfilter));
		FILTER_LIST_OUT(dstfilter) = FILTER_LIST_OUT(srcfilter);
	}

	if (ROUTE_MAP_OUT_NAME(srcfilter)) {
		ROUTE_MAP_OUT_NAME(dstfilter) = XSTRDUP(
			MTYPE_BGP_FILTER_NAME, ROUTE_MAP_OUT_NAME(srcfilter));
		ROUTE_MAP_OUT(dstfilter) = ROUTE_MAP_OUT(srcfilter);
	}

	if (UNSUPPRESS_MAP_NAME(srcfilter)) {
		UNSUPPRESS_MAP_NAME(dstfilter) = XSTRDUP(
			MTYPE_BGP_FILTER_NAME, UNSUPPRESS_MAP_NAME(srcfilter));
		UNSUPPRESS_MAP(dstfilter) = UNSUPPRESS_MAP(srcfilter);
	}
}

/**
 * since we did a bunch of XSTRDUP's in conf_copy, time to free them up
 */
static void conf_release(struct peer *src, afi_t afi, safi_t safi)
{
	struct bgp_filter *srcfilter;

	srcfilter = &src->filter[afi][safi];

	XFREE(MTYPE_ROUTE_MAP_NAME, src->default_rmap[afi][safi].name);

	XFREE(MTYPE_BGP_FILTER_NAME, srcfilter->dlist[FILTER_OUT].name);

	XFREE(MTYPE_BGP_FILTER_NAME, srcfilter->plist[FILTER_OUT].name);

	XFREE(MTYPE_BGP_FILTER_NAME, srcfilter->aslist[FILTER_OUT].name);

	XFREE(MTYPE_BGP_FILTER_NAME, srcfilter->map[RMAP_OUT].name);

	XFREE(MTYPE_BGP_FILTER_NAME, srcfilter->usmap.name);

	XFREE(MTYPE_BGP_PEER_HOST, src->host);
	src->host = NULL;
}

static void peer2_updgrp_copy(struct update_group *updgrp, struct peer_af *paf)
{
	struct peer *src;
	struct peer *dst;

	if (!updgrp || !paf)
		return;

	src = paf->peer;
	dst = updgrp->conf;
	if (!src || !dst)
		return;

	updgrp->afi = paf->afi;
	updgrp->safi = paf->safi;
	updgrp->afid = paf->afid;
	updgrp->bgp = src->bgp;

	conf_copy(dst, src, paf->afi, paf->safi);
}

/**
 * auxiliary functions to maintain the hash table.
 * - updgrp_hash_alloc - to create a new entry, passed to hash_get
 * - updgrp_hash_key_make - makes the key for update group search
 * - updgrp_hash_cmp - compare two update groups.
 */
static void *updgrp_hash_alloc(void *p)
{
	struct update_group *updgrp;
	const struct update_group *in;

	in = (const struct update_group *)p;
	updgrp = XCALLOC(MTYPE_BGP_UPDGRP, sizeof(struct update_group));
	memcpy(updgrp, in, sizeof(struct update_group));
	updgrp->conf = XCALLOC(MTYPE_BGP_PEER, sizeof(struct peer));
	conf_copy(updgrp->conf, in->conf, in->afi, in->safi);
	return updgrp;
}

/**
 * The hash value for a peer is computed from the following variables:
 * v = f(
 *       1. IBGP (1) or EBGP (2)
 *       2. FLAGS based on configuration:
 *             LOCAL_AS_NO_PREPEND
 *             LOCAL_AS_REPLACE_AS
 *       3. AF_FLAGS based on configuration:
 *             Refer to definition in bgp_updgrp.h
 *       4. (AF-independent) Capability flags:
 *             AS4_RCV capability
 *       5. (AF-dependent) Capability flags:
 *             ORF_PREFIX_SM_RCV (peer can send prefix ORF)
 *       6. MRAI
 *       7. peer-group name
 *       8. Outbound route-map name (neighbor route-map <> out)
 *       9. Outbound distribute-list name (neighbor distribute-list <> out)
 *       10. Outbound prefix-list name (neighbor prefix-list <> out)
 *       11. Outbound as-list name (neighbor filter-list <> out)
 *       12. Unsuppress map name (neighbor unsuppress-map <>)
 *       13. default rmap name (neighbor default-originate route-map <>)
 *       14. encoding both global and link-local nexthop?
 *       15. If peer is configured to be a lonesoul, peer ip address
 *       16. Local-as should match, if configured.
 *      )
 */
static unsigned int updgrp_hash_key_make(const void *p)
{
	const struct update_group *updgrp;
	const struct peer *peer;
	const struct bgp_filter *filter;
	uint32_t flags;
	uint32_t key;
	afi_t afi;
	safi_t safi;

#define SEED1 999331
#define SEED2 2147483647

	updgrp = p;
	peer = updgrp->conf;
	afi = updgrp->afi;
	safi = updgrp->safi;
	flags = peer->af_flags[afi][safi];
	filter = &peer->filter[afi][safi];

	key = 0;

	key = jhash_1word(peer->sort, key); /* EBGP or IBGP */
	key = jhash_1word((peer->flags & PEER_UPDGRP_FLAGS), key);
	key = jhash_1word((flags & PEER_UPDGRP_AF_FLAGS), key);
	key = jhash_1word((uint32_t)peer->addpath_type[afi][safi], key);
	key = jhash_1word((peer->cap & PEER_UPDGRP_CAP_FLAGS), key);
	key = jhash_1word((peer->af_cap[afi][safi] & PEER_UPDGRP_AF_CAP_FLAGS),
			  key);
	key = jhash_1word(peer->v_routeadv, key);
	key = jhash_1word(peer->change_local_as, key);

	if (peer->group)
		key = jhash_1word(jhash(peer->group->name,
					strlen(peer->group->name), SEED1),
				  key);

	if (filter->map[RMAP_OUT].name)
		key = jhash_1word(jhash(filter->map[RMAP_OUT].name,
					strlen(filter->map[RMAP_OUT].name),
					SEED1),
				  key);

	if (filter->dlist[FILTER_OUT].name)
		key = jhash_1word(jhash(filter->dlist[FILTER_OUT].name,
					strlen(filter->dlist[FILTER_OUT].name),
					SEED1),
				  key);

	if (filter->plist[FILTER_OUT].name)
		key = jhash_1word(jhash(filter->plist[FILTER_OUT].name,
					strlen(filter->plist[FILTER_OUT].name),
					SEED1),
				  key);

	if (filter->aslist[FILTER_OUT].name)
		key = jhash_1word(jhash(filter->aslist[FILTER_OUT].name,
					strlen(filter->aslist[FILTER_OUT].name),
					SEED1),
				  key);

	if (filter->usmap.name)
		key = jhash_1word(jhash(filter->usmap.name,
					strlen(filter->usmap.name), SEED1),
				  key);

	if (peer->default_rmap[afi][safi].name)
		key = jhash_1word(
			jhash(peer->default_rmap[afi][safi].name,
			      strlen(peer->default_rmap[afi][safi].name),
			      SEED1),
			key);

	/* If peer is on a shared network and is exchanging IPv6 prefixes,
	 * it needs to include link-local address. That's different from
	 * non-shared-network peers (nexthop encoded with 32 bytes vs 16
	 * bytes). We create different update groups to take care of that.
	 */
	key = jhash_1word(
		(peer->shared_network && peer_afi_active_nego(peer, AFI_IP6)),
		key);

	/*
	 * There are certain peers that must get their own update-group:
	 * - lonesoul peers
	 * - peers that negotiated ORF
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_LONESOUL)
	    || CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	    || CHECK_FLAG(peer->af_cap[afi][safi],
			  PEER_CAP_ORF_PREFIX_SM_OLD_RCV))
		key = jhash_1word(jhash(peer->host, strlen(peer->host), SEED2),
				  key);

	return key;
}

static bool updgrp_hash_cmp(const void *p1, const void *p2)
{
	const struct update_group *grp1;
	const struct update_group *grp2;
	const struct peer *pe1;
	const struct peer *pe2;
	uint32_t flags1;
	uint32_t flags2;
	const struct bgp_filter *fl1;
	const struct bgp_filter *fl2;
	afi_t afi;
	safi_t safi;

	if (!p1 || !p2)
		return false;

	grp1 = p1;
	grp2 = p2;
	pe1 = grp1->conf;
	pe2 = grp2->conf;
	afi = grp1->afi;
	safi = grp1->safi;
	flags1 = pe1->af_flags[afi][safi];
	flags2 = pe2->af_flags[afi][safi];
	fl1 = &pe1->filter[afi][safi];
	fl2 = &pe2->filter[afi][safi];

	/* put EBGP and IBGP peers in different update groups */
	if (pe1->sort != pe2->sort)
		return false;

	/* check peer flags */
	if ((pe1->flags & PEER_UPDGRP_FLAGS)
	    != (pe2->flags & PEER_UPDGRP_FLAGS))
		return false;

	/* If there is 'local-as' configured, it should match. */
	if (pe1->change_local_as != pe2->change_local_as)
		return false;

	/* flags like route reflector client */
	if ((flags1 & PEER_UPDGRP_AF_FLAGS) != (flags2 & PEER_UPDGRP_AF_FLAGS))
		return false;

	if (pe1->addpath_type[afi][safi] != pe2->addpath_type[afi][safi])
		return false;

	if ((pe1->cap & PEER_UPDGRP_CAP_FLAGS)
	    != (pe2->cap & PEER_UPDGRP_CAP_FLAGS))
		return false;

	if ((pe1->af_cap[afi][safi] & PEER_UPDGRP_AF_CAP_FLAGS)
	    != (pe2->af_cap[afi][safi] & PEER_UPDGRP_AF_CAP_FLAGS))
		return false;

	if (pe1->v_routeadv != pe2->v_routeadv)
		return false;

	if (pe1->group != pe2->group)
		return false;

	/* route-map names should be the same */
	if ((fl1->map[RMAP_OUT].name && !fl2->map[RMAP_OUT].name)
	    || (!fl1->map[RMAP_OUT].name && fl2->map[RMAP_OUT].name)
	    || (fl1->map[RMAP_OUT].name && fl2->map[RMAP_OUT].name
		&& strcmp(fl1->map[RMAP_OUT].name, fl2->map[RMAP_OUT].name)))
		return false;

	if ((fl1->dlist[FILTER_OUT].name && !fl2->dlist[FILTER_OUT].name)
	    || (!fl1->dlist[FILTER_OUT].name && fl2->dlist[FILTER_OUT].name)
	    || (fl1->dlist[FILTER_OUT].name && fl2->dlist[FILTER_OUT].name
		&& strcmp(fl1->dlist[FILTER_OUT].name,
			  fl2->dlist[FILTER_OUT].name)))
		return false;

	if ((fl1->plist[FILTER_OUT].name && !fl2->plist[FILTER_OUT].name)
	    || (!fl1->plist[FILTER_OUT].name && fl2->plist[FILTER_OUT].name)
	    || (fl1->plist[FILTER_OUT].name && fl2->plist[FILTER_OUT].name
		&& strcmp(fl1->plist[FILTER_OUT].name,
			  fl2->plist[FILTER_OUT].name)))
		return false;

	if ((fl1->aslist[FILTER_OUT].name && !fl2->aslist[FILTER_OUT].name)
	    || (!fl1->aslist[FILTER_OUT].name && fl2->aslist[FILTER_OUT].name)
	    || (fl1->aslist[FILTER_OUT].name && fl2->aslist[FILTER_OUT].name
		&& strcmp(fl1->aslist[FILTER_OUT].name,
			  fl2->aslist[FILTER_OUT].name)))
		return false;

	if ((fl1->usmap.name && !fl2->usmap.name)
	    || (!fl1->usmap.name && fl2->usmap.name)
	    || (fl1->usmap.name && fl2->usmap.name
		&& strcmp(fl1->usmap.name, fl2->usmap.name)))
		return false;

	if ((pe1->default_rmap[afi][safi].name
	     && !pe2->default_rmap[afi][safi].name)
	    || (!pe1->default_rmap[afi][safi].name
		&& pe2->default_rmap[afi][safi].name)
	    || (pe1->default_rmap[afi][safi].name
		&& pe2->default_rmap[afi][safi].name
		&& strcmp(pe1->default_rmap[afi][safi].name,
			  pe2->default_rmap[afi][safi].name)))
		return false;

	if ((afi == AFI_IP6) && (pe1->shared_network != pe2->shared_network))
		return false;

	if ((CHECK_FLAG(pe1->flags, PEER_FLAG_LONESOUL)
	     || CHECK_FLAG(pe1->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	     || CHECK_FLAG(pe1->af_cap[afi][safi],
			   PEER_CAP_ORF_PREFIX_SM_OLD_RCV))
	    && !sockunion_same(&pe1->su, &pe2->su))
		return false;

	return true;
}

static void peer_lonesoul_or_not(struct peer *peer, int set)
{
	/* no change in status? */
	if (set == (CHECK_FLAG(peer->flags, PEER_FLAG_LONESOUL) > 0))
		return;

	if (set)
		SET_FLAG(peer->flags, PEER_FLAG_LONESOUL);
	else
		UNSET_FLAG(peer->flags, PEER_FLAG_LONESOUL);

	update_group_adjust_peer_afs(peer);
}

/*
 * subgroup_total_packets_enqueued
 *
 * Returns the total number of packets enqueued to a subgroup.
 */
static unsigned int
subgroup_total_packets_enqueued(struct update_subgroup *subgrp)
{
	struct bpacket *pkt;

	pkt = bpacket_queue_last(SUBGRP_PKTQ(subgrp));

	return pkt->ver - 1;
}

static int update_group_show_walkcb(struct update_group *updgrp, void *arg)
{
	struct updwalk_context *ctx = arg;
	struct vty *vty;
	struct update_subgroup *subgrp;
	struct peer_af *paf;
	struct bgp_filter *filter;
	int match = 0;

	if (!ctx)
		return CMD_SUCCESS;

	if (ctx->subgrp_id) {
		UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
			if (ctx->subgrp_id && (ctx->subgrp_id != subgrp->id))
				continue;
			else {
				match = 1;
				break;
			}
		}
	} else {
		match = 1;
	}

	if (!match) {
		/* Since this routine is invoked from a walk, we cannot signal
		 * any */
		/* error here, can only return. */
		return CMD_SUCCESS;
	}

	vty = ctx->vty;

	vty_out(vty, "Update-group %" PRIu64 ":\n", updgrp->id);
	vty_out(vty, "  Created: %s", timestamp_string(updgrp->uptime));
	filter = &updgrp->conf->filter[updgrp->afi][updgrp->safi];
	if (filter->map[RMAP_OUT].name)
		vty_out(vty, "  Outgoing route map: %s\n",
			filter->map[RMAP_OUT].name);
	vty_out(vty, "  MRAI value (seconds): %d\n", updgrp->conf->v_routeadv);
	if (updgrp->conf->change_local_as)
		vty_out(vty, "  Local AS %u%s%s\n",
			updgrp->conf->change_local_as,
			CHECK_FLAG(updgrp->conf->flags,
				   PEER_FLAG_LOCAL_AS_NO_PREPEND)
				? " no-prepend"
				: "",
			CHECK_FLAG(updgrp->conf->flags,
				   PEER_FLAG_LOCAL_AS_REPLACE_AS)
				? " replace-as"
				: "");

	UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
		if (ctx->subgrp_id && (ctx->subgrp_id != subgrp->id))
			continue;
		vty_out(vty, "\n");
		vty_out(vty, "  Update-subgroup %" PRIu64 ":\n", subgrp->id);
		vty_out(vty, "    Created: %s",
			timestamp_string(subgrp->uptime));

		if (subgrp->split_from.update_group_id
		    || subgrp->split_from.subgroup_id) {
			vty_out(vty, "    Split from group id: %" PRIu64 "\n",
				subgrp->split_from.update_group_id);
			vty_out(vty,
				"    Split from subgroup id: %" PRIu64 "\n",
				subgrp->split_from.subgroup_id);
		}

		vty_out(vty, "    Join events: %u\n", subgrp->join_events);
		vty_out(vty, "    Prune events: %u\n", subgrp->prune_events);
		vty_out(vty, "    Merge events: %u\n", subgrp->merge_events);
		vty_out(vty, "    Split events: %u\n", subgrp->split_events);
		vty_out(vty, "    Update group switch events: %u\n",
			subgrp->updgrp_switch_events);
		vty_out(vty, "    Peer refreshes combined: %u\n",
			subgrp->peer_refreshes_combined);
		vty_out(vty, "    Merge checks triggered: %u\n",
			subgrp->merge_checks_triggered);
		vty_out(vty, "    Coalesce Time: %u%s\n",
			(UPDGRP_INST(subgrp->update_group))->coalesce_time,
			subgrp->t_coalesce ? "(Running)" : "");
		vty_out(vty, "    Version: %" PRIu64 "\n", subgrp->version);
		vty_out(vty, "    Packet queue length: %d\n",
			bpacket_queue_length(SUBGRP_PKTQ(subgrp)));
		vty_out(vty, "    Total packets enqueued: %u\n",
			subgroup_total_packets_enqueued(subgrp));
		vty_out(vty, "    Packet queue high watermark: %d\n",
			bpacket_queue_hwm_length(SUBGRP_PKTQ(subgrp)));
		vty_out(vty, "    Adj-out list count: %u\n", subgrp->adj_count);
		vty_out(vty, "    Advertise list: %s\n",
			advertise_list_is_empty(subgrp) ? "empty"
							: "not empty");
		vty_out(vty, "    Flags: %s\n",
			CHECK_FLAG(subgrp->flags, SUBGRP_FLAG_NEEDS_REFRESH)
				? "R"
				: "");
		if (subgrp->peer_count > 0) {
			vty_out(vty, "    Peers:\n");
			SUBGRP_FOREACH_PEER (subgrp, paf)
				vty_out(vty, "      - %s\n", paf->peer->host);
		}
	}
	return UPDWALK_CONTINUE;
}

/*
 * Helper function to show the packet queue for each subgroup of update group.
 * Will be constrained to a particular subgroup id if id !=0
 */
static int updgrp_show_packet_queue_walkcb(struct update_group *updgrp,
					   void *arg)
{
	struct updwalk_context *ctx = arg;
	struct update_subgroup *subgrp;
	struct vty *vty;

	vty = ctx->vty;
	UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
		if (ctx->subgrp_id && (ctx->subgrp_id != subgrp->id))
			continue;
		vty_out(vty, "update group %" PRIu64 ", subgroup %" PRIu64 "\n",
			updgrp->id, subgrp->id);
		bpacket_queue_show_vty(SUBGRP_PKTQ(subgrp), vty);
	}
	return UPDWALK_CONTINUE;
}

/*
 * Show the packet queue for each subgroup of update group. Will be
 * constrained to a particular subgroup id if id !=0
 */
void update_group_show_packet_queue(struct bgp *bgp, afi_t afi, safi_t safi,
				    struct vty *vty, uint64_t id)
{
	struct updwalk_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.vty = vty;
	ctx.subgrp_id = id;
	ctx.flags = 0;
	update_group_af_walk(bgp, afi, safi, updgrp_show_packet_queue_walkcb,
			     &ctx);
}

static struct update_group *update_group_find(struct peer_af *paf)
{
	struct update_group *updgrp;
	struct update_group tmp;
	struct peer tmp_conf;

	if (!peer_established(PAF_PEER(paf)))
		return NULL;

	memset(&tmp, 0, sizeof(tmp));
	memset(&tmp_conf, 0, sizeof(tmp_conf));
	tmp.conf = &tmp_conf;
	peer2_updgrp_copy(&tmp, paf);

	updgrp = hash_lookup(paf->peer->bgp->update_groups[paf->afid], &tmp);
	conf_release(&tmp_conf, paf->afi, paf->safi);
	return updgrp;
}

static struct update_group *update_group_create(struct peer_af *paf)
{
	struct update_group *updgrp;
	struct update_group tmp;
	struct peer tmp_conf;

	memset(&tmp, 0, sizeof(tmp));
	memset(&tmp_conf, 0, sizeof(tmp_conf));
	tmp.conf = &tmp_conf;
	peer2_updgrp_copy(&tmp, paf);

	updgrp = hash_get(paf->peer->bgp->update_groups[paf->afid], &tmp,
			  updgrp_hash_alloc);
	if (!updgrp)
		return NULL;
	update_group_checkin(updgrp);

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("create update group %" PRIu64, updgrp->id);

	UPDGRP_GLOBAL_STAT(updgrp, updgrps_created) += 1;

	conf_release(&tmp_conf, paf->afi, paf->safi);
	return updgrp;
}

static void update_group_delete(struct update_group *updgrp)
{
	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("delete update group %" PRIu64, updgrp->id);

	UPDGRP_GLOBAL_STAT(updgrp, updgrps_deleted) += 1;

	hash_release(updgrp->bgp->update_groups[updgrp->afid], updgrp);
	conf_release(updgrp->conf, updgrp->afi, updgrp->safi);

	XFREE(MTYPE_BGP_PEER_HOST, updgrp->conf->host);
	updgrp->conf->host = NULL;

	XFREE(MTYPE_BGP_PEER_IFNAME, updgrp->conf->ifname);

	XFREE(MTYPE_BGP_PEER, updgrp->conf);
	XFREE(MTYPE_BGP_UPDGRP, updgrp);
}

static void update_group_add_subgroup(struct update_group *updgrp,
				      struct update_subgroup *subgrp)
{
	if (!updgrp || !subgrp)
		return;

	LIST_INSERT_HEAD(&(updgrp->subgrps), subgrp, updgrp_train);
	subgrp->update_group = updgrp;
}

static void update_group_remove_subgroup(struct update_group *updgrp,
					 struct update_subgroup *subgrp)
{
	if (!updgrp || !subgrp)
		return;

	LIST_REMOVE(subgrp, updgrp_train);
	subgrp->update_group = NULL;
	if (LIST_EMPTY(&(updgrp->subgrps)))
		update_group_delete(updgrp);
}

static struct update_subgroup *
update_subgroup_create(struct update_group *updgrp)
{
	struct update_subgroup *subgrp;

	subgrp = XCALLOC(MTYPE_BGP_UPD_SUBGRP, sizeof(struct update_subgroup));
	update_subgroup_checkin(subgrp, updgrp);
	subgrp->v_coalesce = (UPDGRP_INST(updgrp))->coalesce_time;
	sync_init(subgrp);
	bpacket_queue_init(SUBGRP_PKTQ(subgrp));
	bpacket_queue_add(SUBGRP_PKTQ(subgrp), NULL, NULL);
	TAILQ_INIT(&(subgrp->adjq));
	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("create subgroup u%" PRIu64 ":s%" PRIu64, updgrp->id,
			   subgrp->id);

	update_group_add_subgroup(updgrp, subgrp);

	UPDGRP_INCR_STAT(updgrp, subgrps_created);

	return subgrp;
}

static void update_subgroup_delete(struct update_subgroup *subgrp)
{
	if (!subgrp)
		return;

	if (subgrp->update_group)
		UPDGRP_INCR_STAT(subgrp->update_group, subgrps_deleted);

	if (subgrp->t_merge_check)
		THREAD_OFF(subgrp->t_merge_check);

	if (subgrp->t_coalesce)
		THREAD_TIMER_OFF(subgrp->t_coalesce);

	bpacket_queue_cleanup(SUBGRP_PKTQ(subgrp));
	subgroup_clear_table(subgrp);

	if (subgrp->t_coalesce)
		THREAD_TIMER_OFF(subgrp->t_coalesce);
	sync_delete(subgrp);

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS) && subgrp->update_group)
		zlog_debug("delete subgroup u%" PRIu64 ":s%" PRIu64,
			   subgrp->update_group->id, subgrp->id);

	update_group_remove_subgroup(subgrp->update_group, subgrp);

	XFREE(MTYPE_BGP_UPD_SUBGRP, subgrp);
}

void update_subgroup_inherit_info(struct update_subgroup *to,
				  struct update_subgroup *from)
{
	if (!to || !from)
		return;

	to->sflags = from->sflags;
}

/*
 * update_subgroup_check_delete
 *
 * Delete a subgroup if it is ready to be deleted.
 *
 * Returns true if the subgroup was deleted.
 */
static int update_subgroup_check_delete(struct update_subgroup *subgrp)
{
	if (!subgrp)
		return 0;

	if (!LIST_EMPTY(&(subgrp->peers)))
		return 0;

	update_subgroup_delete(subgrp);

	return 1;
}

/*
 * update_subgroup_add_peer
 *
 * @param send_enqueued_packets If true all currently enqueued packets will
 *                              also be sent to the peer.
 */
static void update_subgroup_add_peer(struct update_subgroup *subgrp,
				     struct peer_af *paf,
				     int send_enqueued_pkts)
{
	struct bpacket *pkt;

	if (!subgrp || !paf)
		return;

	LIST_INSERT_HEAD(&(subgrp->peers), paf, subgrp_train);
	paf->subgroup = subgrp;
	subgrp->peer_count++;

	if (bgp_debug_peer_updout_enabled(paf->peer->host)) {
		UPDGRP_PEER_DBG_EN(subgrp->update_group);
	}

	SUBGRP_INCR_STAT(subgrp, join_events);

	if (send_enqueued_pkts) {
		pkt = bpacket_queue_first(SUBGRP_PKTQ(subgrp));
	} else {

		/*
		 * Hang the peer off of the last, placeholder, packet in the
		 * queue. This means it won't see any of the packets that are
		 * currently the queue.
		 */
		pkt = bpacket_queue_last(SUBGRP_PKTQ(subgrp));
		assert(pkt->buffer == NULL);
	}

	bpacket_add_peer(pkt, paf);

	bpacket_queue_sanity_check(SUBGRP_PKTQ(subgrp));
	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("peer %s added to subgroup s%" PRIu64,
				paf->peer->host, subgrp->id);
}

/*
 * update_subgroup_remove_peer_internal
 *
 * Internal function that removes a peer from a subgroup, but does not
 * delete the subgroup. A call to this function must almost always be
 * followed by a call to update_subgroup_check_delete().
 *
 * @see update_subgroup_remove_peer
 */
static void update_subgroup_remove_peer_internal(struct update_subgroup *subgrp,
						 struct peer_af *paf)
{
	assert(subgrp && paf && subgrp->update_group);

	if (bgp_debug_peer_updout_enabled(paf->peer->host)) {
		UPDGRP_PEER_DBG_DIS(subgrp->update_group);
	}

	bpacket_queue_remove_peer(paf);
	LIST_REMOVE(paf, subgrp_train);
	paf->subgroup = NULL;
	subgrp->peer_count--;

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("peer %s deleted from subgroup s%"
			   PRIu64 " peer cnt %d",
			   paf->peer->host, subgrp->id, subgrp->peer_count);
	SUBGRP_INCR_STAT(subgrp, prune_events);
}

/*
 * update_subgroup_remove_peer
 */
void update_subgroup_remove_peer(struct update_subgroup *subgrp,
				 struct peer_af *paf)
{
	if (!subgrp || !paf)
		return;

	update_subgroup_remove_peer_internal(subgrp, paf);

	if (update_subgroup_check_delete(subgrp))
		return;

	/*
	 * The deletion of the peer may have caused some packets to be
	 * deleted from the subgroup packet queue. Check if the subgroup can
	 * be merged now.
	 */
	update_subgroup_check_merge(subgrp, "removed peer from subgroup");
}

static struct update_subgroup *update_subgroup_find(struct update_group *updgrp,
						    struct peer_af *paf)
{
	struct update_subgroup *subgrp = NULL;
	uint64_t version;

	if (paf->subgroup) {
		assert(0);
		return NULL;
	} else
		version = 0;

	if (!peer_established(PAF_PEER(paf)))
		return NULL;

	UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
		if (subgrp->version != version
		    || CHECK_FLAG(subgrp->sflags,
				  SUBGRP_STATUS_DEFAULT_ORIGINATE))
			continue;

		/*
		 * The version number is not meaningful on a subgroup that needs
		 * a refresh.
		 */
		if (update_subgroup_needs_refresh(subgrp))
			continue;

		break;
	}

	return subgrp;
}

/*
 * update_subgroup_ready_for_merge
 *
 * Returns true if this subgroup is in a state that allows it to be
 * merged into another subgroup.
 */
static int update_subgroup_ready_for_merge(struct update_subgroup *subgrp)
{

	/*
	 * Not ready if there are any encoded packets waiting to be written
	 * out to peers.
	 */
	if (!bpacket_queue_is_empty(SUBGRP_PKTQ(subgrp)))
		return 0;

	/*
	 * Not ready if there enqueued updates waiting to be encoded.
	 */
	if (!advertise_list_is_empty(subgrp))
		return 0;

	/*
	 * Don't attempt to merge a subgroup that needs a refresh. For one,
	 * we can't determine if the adj_out of such a group matches that of
	 * another group.
	 */
	if (update_subgroup_needs_refresh(subgrp))
		return 0;

	return 1;
}

/*
 * update_subgrp_can_merge_into
 *
 * Returns true if the first subgroup can merge into the second
 * subgroup.
 */
static int update_subgroup_can_merge_into(struct update_subgroup *subgrp,
					  struct update_subgroup *target)
{

	if (subgrp == target)
		return 0;

	/*
	 * Both must have processed the BRIB to the same point in order to
	 * be merged.
	 */
	if (subgrp->version != target->version)
		return 0;

	if (CHECK_FLAG(subgrp->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE)
	    != CHECK_FLAG(target->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE))
		return 0;

	if (subgrp->adj_count != target->adj_count)
		return 0;

	return update_subgroup_ready_for_merge(target);
}

/*
 * update_subgroup_merge
 *
 * Merge the first subgroup into the second one.
 */
static void update_subgroup_merge(struct update_subgroup *subgrp,
				  struct update_subgroup *target,
				  const char *reason)
{
	struct peer_af *paf;
	int result;
	int peer_count;

	assert(subgrp->adj_count == target->adj_count);

	peer_count = subgrp->peer_count;

	while (1) {
		paf = LIST_FIRST(&subgrp->peers);
		if (!paf)
			break;

		update_subgroup_remove_peer_internal(subgrp, paf);

		/*
		 * Add the peer to the target subgroup, while making sure that
		 * any currently enqueued packets won't be sent to it. Enqueued
		 * packets could, for example, result in an unnecessary withdraw
		 * followed by an advertise.
		 */
		update_subgroup_add_peer(target, paf, 0);
	}

	SUBGRP_INCR_STAT(target, merge_events);

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("u%" PRIu64 ":s%" PRIu64
			   " (%d peers) merged into u%" PRIu64 ":s%" PRIu64
			   ", "
			   "trigger: %s",
			   subgrp->update_group->id, subgrp->id, peer_count,
			   target->update_group->id, target->id,
			   reason ? reason : "unknown");

	result = update_subgroup_check_delete(subgrp);
	assert(result);
}

/*
 * update_subgroup_check_merge
 *
 * Merge this subgroup into another subgroup if possible.
 *
 * Returns true if the subgroup has been merged. The subgroup pointer
 * should not be accessed in this case.
 */
int update_subgroup_check_merge(struct update_subgroup *subgrp,
				const char *reason)
{
	struct update_subgroup *target;

	if (!update_subgroup_ready_for_merge(subgrp))
		return 0;

	/*
	 * Look for a subgroup to merge into.
	 */
	UPDGRP_FOREACH_SUBGRP (subgrp->update_group, target) {
		if (update_subgroup_can_merge_into(subgrp, target))
			break;
	}

	if (!target)
		return 0;

	update_subgroup_merge(subgrp, target, reason);
	return 1;
}

/*
* update_subgroup_merge_check_thread_cb
*/
static int update_subgroup_merge_check_thread_cb(struct thread *thread)
{
	struct update_subgroup *subgrp;

	subgrp = THREAD_ARG(thread);

	subgrp->t_merge_check = NULL;

	update_subgroup_check_merge(subgrp, "triggered merge check");
	return 0;
}

/*
 * update_subgroup_trigger_merge_check
 *
 * Triggers a call to update_subgroup_check_merge() on a clean context.
 *
 * @param force If true, the merge check will be triggered even if the
 *              subgroup doesn't currently look ready for a merge.
 *
 * Returns true if a merge check will be performed shortly.
 */
int update_subgroup_trigger_merge_check(struct update_subgroup *subgrp,
					int force)
{
	if (subgrp->t_merge_check)
		return 1;

	if (!force && !update_subgroup_ready_for_merge(subgrp))
		return 0;

	subgrp->t_merge_check = NULL;
	thread_add_timer_msec(bm->master, update_subgroup_merge_check_thread_cb,
			      subgrp, 0, &subgrp->t_merge_check);

	SUBGRP_INCR_STAT(subgrp, merge_checks_triggered);

	return 1;
}

/*
 * update_subgroup_copy_adj_out
 *
 * Helper function that clones the adj out (state about advertised
 * routes) from one subgroup to another. It assumes that the adj out
 * of the target subgroup is empty.
 */
static void update_subgroup_copy_adj_out(struct update_subgroup *source,
					 struct update_subgroup *dest)
{
	struct bgp_adj_out *aout, *aout_copy;

	SUBGRP_FOREACH_ADJ (source, aout) {
		/*
		 * Copy the adj out.
		 */
		aout_copy =
			bgp_adj_out_alloc(dest, aout->rn, aout->addpath_tx_id);
		aout_copy->attr =
			aout->attr ? bgp_attr_intern(aout->attr) : NULL;
	}

	dest->scount = source->scount;
}

/*
 * update_subgroup_copy_packets
 *
 * Copy packets after and including the given packet to the subgroup
 *  'dest'.
 *
 * Returns the number of packets copied.
 */
static int update_subgroup_copy_packets(struct update_subgroup *dest,
					struct bpacket *pkt)
{
	int count;

	count = 0;
	while (pkt && pkt->buffer) {
		bpacket_queue_add(SUBGRP_PKTQ(dest), stream_dup(pkt->buffer),
				  &pkt->arr);
		count++;
		pkt = bpacket_next(pkt);
	}

	bpacket_queue_sanity_check(SUBGRP_PKTQ(dest));

	return count;
}

static int updgrp_prefix_list_update(struct update_group *updgrp,
				     const char *name)
{
	struct peer *peer;
	struct bgp_filter *filter;

	peer = UPDGRP_PEER(updgrp);
	filter = &peer->filter[UPDGRP_AFI(updgrp)][UPDGRP_SAFI(updgrp)];

	if (PREFIX_LIST_OUT_NAME(filter)
	    && (strcmp(name, PREFIX_LIST_OUT_NAME(filter)) == 0)) {
		PREFIX_LIST_OUT(filter) = prefix_list_lookup(
			UPDGRP_AFI(updgrp), PREFIX_LIST_OUT_NAME(filter));
		return 1;
	}
	return 0;
}

static int updgrp_filter_list_update(struct update_group *updgrp,
				     const char *name)
{
	struct peer *peer;
	struct bgp_filter *filter;

	peer = UPDGRP_PEER(updgrp);
	filter = &peer->filter[UPDGRP_AFI(updgrp)][UPDGRP_SAFI(updgrp)];

	if (FILTER_LIST_OUT_NAME(filter)
	    && (strcmp(name, FILTER_LIST_OUT_NAME(filter)) == 0)) {
		FILTER_LIST_OUT(filter) =
			as_list_lookup(FILTER_LIST_OUT_NAME(filter));
		return 1;
	}
	return 0;
}

static int updgrp_distribute_list_update(struct update_group *updgrp,
					 const char *name)
{
	struct peer *peer;
	struct bgp_filter *filter;

	peer = UPDGRP_PEER(updgrp);
	filter = &peer->filter[UPDGRP_AFI(updgrp)][UPDGRP_SAFI(updgrp)];

	if (DISTRIBUTE_OUT_NAME(filter)
	    && (strcmp(name, DISTRIBUTE_OUT_NAME(filter)) == 0)) {
		DISTRIBUTE_OUT(filter) = access_list_lookup(
			UPDGRP_AFI(updgrp), DISTRIBUTE_OUT_NAME(filter));
		return 1;
	}
	return 0;
}

static int updgrp_route_map_update(struct update_group *updgrp,
				   const char *name, int *def_rmap_changed)
{
	struct peer *peer;
	struct bgp_filter *filter;
	int changed = 0;
	afi_t afi;
	safi_t safi;

	peer = UPDGRP_PEER(updgrp);
	afi = UPDGRP_AFI(updgrp);
	safi = UPDGRP_SAFI(updgrp);
	filter = &peer->filter[afi][safi];

	if (ROUTE_MAP_OUT_NAME(filter)
	    && (strcmp(name, ROUTE_MAP_OUT_NAME(filter)) == 0)) {
		ROUTE_MAP_OUT(filter) = route_map_lookup_by_name(name);

		changed = 1;
	}

	if (UNSUPPRESS_MAP_NAME(filter)
	    && (strcmp(name, UNSUPPRESS_MAP_NAME(filter)) == 0)) {
		UNSUPPRESS_MAP(filter) = route_map_lookup_by_name(name);
		changed = 1;
	}

	/* process default-originate route-map */
	if (peer->default_rmap[afi][safi].name
	    && (strcmp(name, peer->default_rmap[afi][safi].name) == 0)) {
		peer->default_rmap[afi][safi].map =
			route_map_lookup_by_name(name);
		if (def_rmap_changed)
			*def_rmap_changed = 1;
	}
	return changed;
}

/*
 * hash iteration callback function to process a policy change for an
 * update group. Check if the changed policy matches the updgrp's
 * outbound route-map or unsuppress-map or default-originate map or
 * filter-list or prefix-list or distribute-list.
 * Trigger update generation accordingly.
 */
static int updgrp_policy_update_walkcb(struct update_group *updgrp, void *arg)
{
	struct updwalk_context *ctx = arg;
	struct update_subgroup *subgrp;
	int changed = 0;
	int def_changed = 0;

	if (!updgrp || !ctx || !ctx->policy_name)
		return UPDWALK_CONTINUE;

	switch (ctx->policy_type) {
	case BGP_POLICY_ROUTE_MAP:
		changed = updgrp_route_map_update(updgrp, ctx->policy_name,
						  &def_changed);
		break;
	case BGP_POLICY_FILTER_LIST:
		changed = updgrp_filter_list_update(updgrp, ctx->policy_name);
		break;
	case BGP_POLICY_PREFIX_LIST:
		changed = updgrp_prefix_list_update(updgrp, ctx->policy_name);
		break;
	case BGP_POLICY_DISTRIBUTE_LIST:
		changed =
			updgrp_distribute_list_update(updgrp, ctx->policy_name);
		break;
	default:
		break;
	}

	/* If not doing route update, return after updating "config" */
	if (!ctx->policy_route_update)
		return UPDWALK_CONTINUE;

	/* If nothing has changed, return after updating "config" */
	if (!changed && !def_changed)
		return UPDWALK_CONTINUE;

	/*
	 * If something has changed, at the beginning of a route-map
	 * modification
	 * event, mark each subgroup's needs-refresh bit. For one, it signals to
	 * whoever that the subgroup needs a refresh. Second, it prevents
	 * premature
	 * merge of this subgroup with another before a complete (outbound)
	 * refresh.
	 */
	if (ctx->policy_event_start_flag) {
		UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
			update_subgroup_set_needs_refresh(subgrp, 1);
		}
		return UPDWALK_CONTINUE;
	}

	UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
		if (changed) {
			if (bgp_debug_update(NULL, NULL, updgrp, 0))
				zlog_debug(
					"u%" PRIu64 ":s%" PRIu64
					" announcing routes upon policy %s (type %d) change",
					updgrp->id, subgrp->id,
					ctx->policy_name, ctx->policy_type);
			subgroup_announce_route(subgrp);
		}
		if (def_changed) {
			if (bgp_debug_update(NULL, NULL, updgrp, 0))
				zlog_debug(
					"u%" PRIu64 ":s%" PRIu64
					" announcing default upon default routemap %s change",
					updgrp->id, subgrp->id,
					ctx->policy_name);
			subgroup_default_originate(subgrp, 0);
		}
		update_subgroup_set_needs_refresh(subgrp, 0);
	}
	return UPDWALK_CONTINUE;
}

static int update_group_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct update_group *updgrp = bucket->data;
	struct updwalk_context *wctx = arg;
	int ret = (*wctx->cb)(updgrp, wctx->context);
	return ret;
}

static int update_group_periodic_merge_walkcb(struct update_group *updgrp,
					      void *arg)
{
	struct update_subgroup *subgrp;
	struct update_subgroup *tmp_subgrp;
	const char *reason = arg;

	UPDGRP_FOREACH_SUBGRP_SAFE (updgrp, subgrp, tmp_subgrp)
		update_subgroup_check_merge(subgrp, reason);
	return UPDWALK_CONTINUE;
}

/********************
 * PUBLIC FUNCTIONS
 ********************/

/*
 * trigger function when a policy (route-map/filter-list/prefix-list/
 * distribute-list etc.) content changes. Go through all the
 * update groups and process the change.
 *
 * bgp: the bgp instance
 * ptype: the type of policy that got modified, see bgpd.h
 * pname: name of the policy
 * route_update: flag to control if an automatic update generation should
 *                occur
 * start_event: flag that indicates if it's the beginning of the change.
 *             Esp. when the user is changing the content interactively
 *             over multiple statements. Useful to set dirty flag on
 *             update groups.
 */
void update_group_policy_update(struct bgp *bgp, bgp_policy_type_e ptype,
				const char *pname, int route_update,
				int start_event)
{
	struct updwalk_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.policy_type = ptype;
	ctx.policy_name = pname;
	ctx.policy_route_update = route_update;
	ctx.policy_event_start_flag = start_event;
	ctx.flags = 0;

	update_group_walk(bgp, updgrp_policy_update_walkcb, &ctx);
}

/*
 * update_subgroup_split_peer
 *
 * Ensure that the given peer is in a subgroup of its own in the
 * specified update group.
 */
void update_subgroup_split_peer(struct peer_af *paf,
				struct update_group *updgrp)
{
	struct update_subgroup *old_subgrp, *subgrp;
	uint64_t old_id;


	old_subgrp = paf->subgroup;

	if (!updgrp)
		updgrp = old_subgrp->update_group;

	/*
	 * If the peer is alone in its subgroup, reuse the existing
	 * subgroup.
	 */
	if (old_subgrp->peer_count == 1) {
		if (updgrp == old_subgrp->update_group)
			return;

		subgrp = old_subgrp;
		old_id = old_subgrp->update_group->id;

		if (bgp_debug_peer_updout_enabled(paf->peer->host)) {
			UPDGRP_PEER_DBG_DIS(old_subgrp->update_group);
		}

		update_group_remove_subgroup(old_subgrp->update_group,
					     old_subgrp);
		update_group_add_subgroup(updgrp, subgrp);

		if (bgp_debug_peer_updout_enabled(paf->peer->host)) {
			UPDGRP_PEER_DBG_EN(updgrp);
		}
		if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
			zlog_debug("u%" PRIu64 ":s%" PRIu64
				   " peer %s moved to u%" PRIu64 ":s%" PRIu64,
				   old_id, subgrp->id, paf->peer->host,
				   updgrp->id, subgrp->id);

		/*
		 * The state of the subgroup (adj_out, advs, packet queue etc)
		 * is consistent internally, but may not be identical to other
		 * subgroups in the new update group even if the version number
		 * matches up. Make sure a full refresh is done before the
		 * subgroup is merged with another.
		 */
		update_subgroup_set_needs_refresh(subgrp, 1);

		SUBGRP_INCR_STAT(subgrp, updgrp_switch_events);
		return;
	}

	/*
	 * Create a new subgroup under the specified update group, and copy
	 * over relevant state to it.
	 */
	subgrp = update_subgroup_create(updgrp);
	update_subgroup_inherit_info(subgrp, old_subgrp);

	subgrp->split_from.update_group_id = old_subgrp->update_group->id;
	subgrp->split_from.subgroup_id = old_subgrp->id;

	/*
	 * Copy out relevant state from the old subgroup.
	 */
	update_subgroup_copy_adj_out(paf->subgroup, subgrp);
	update_subgroup_copy_packets(subgrp, paf->next_pkt_to_send);

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("u%" PRIu64 ":s%" PRIu64
			   " peer %s split and moved into u%" PRIu64
			   ":s%" PRIu64,
			   paf->subgroup->update_group->id, paf->subgroup->id,
			   paf->peer->host, updgrp->id, subgrp->id);

	SUBGRP_INCR_STAT(paf->subgroup, split_events);

	/*
	 * Since queued advs were left behind, this new subgroup needs a
	 * refresh.
	 */
	update_subgroup_set_needs_refresh(subgrp, 1);

	/*
	 * Remove peer from old subgroup, and add it to the new one.
	 */
	update_subgroup_remove_peer(paf->subgroup, paf);

	update_subgroup_add_peer(subgrp, paf, 1);
}

void update_bgp_group_init(struct bgp *bgp)
{
	int afid;

	AF_FOREACH (afid)
		bgp->update_groups[afid] =
			hash_create(updgrp_hash_key_make, updgrp_hash_cmp,
				    "BGP Update Group Hash");
}

void update_bgp_group_free(struct bgp *bgp)
{
	int afid;

	AF_FOREACH (afid) {
		if (bgp->update_groups[afid]) {
			hash_free(bgp->update_groups[afid]);
			bgp->update_groups[afid] = NULL;
		}
	}
}

void update_group_show(struct bgp *bgp, afi_t afi, safi_t safi, struct vty *vty,
		       uint64_t subgrp_id)
{
	struct updwalk_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.vty = vty;
	ctx.subgrp_id = subgrp_id;

	update_group_af_walk(bgp, afi, safi, update_group_show_walkcb, &ctx);
}

/*
 * update_group_show_stats
 *
 * Show global statistics about update groups.
 */
void update_group_show_stats(struct bgp *bgp, struct vty *vty)
{
	vty_out(vty, "Update groups created: %u\n",
		bgp->update_group_stats.updgrps_created);
	vty_out(vty, "Update groups deleted: %u\n",
		bgp->update_group_stats.updgrps_deleted);
	vty_out(vty, "Update subgroups created: %u\n",
		bgp->update_group_stats.subgrps_created);
	vty_out(vty, "Update subgroups deleted: %u\n",
		bgp->update_group_stats.subgrps_deleted);
	vty_out(vty, "Join events: %u\n", bgp->update_group_stats.join_events);
	vty_out(vty, "Prune events: %u\n",
		bgp->update_group_stats.prune_events);
	vty_out(vty, "Merge events: %u\n",
		bgp->update_group_stats.merge_events);
	vty_out(vty, "Split events: %u\n",
		bgp->update_group_stats.split_events);
	vty_out(vty, "Update group switch events: %u\n",
		bgp->update_group_stats.updgrp_switch_events);
	vty_out(vty, "Peer route refreshes combined: %u\n",
		bgp->update_group_stats.peer_refreshes_combined);
	vty_out(vty, "Merge checks triggered: %u\n",
		bgp->update_group_stats.merge_checks_triggered);
}

/*
 * update_group_adjust_peer
 */
void update_group_adjust_peer(struct peer_af *paf)
{
	struct update_group *updgrp;
	struct update_subgroup *subgrp, *old_subgrp;
	struct peer *peer;

	if (!paf)
		return;

	peer = PAF_PEER(paf);
	if (!peer_established(peer)) {
		return;
	}

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE)) {
		return;
	}

	if (!peer->afc_nego[paf->afi][paf->safi]) {
		return;
	}

	updgrp = update_group_find(paf);
	if (!updgrp) {
		updgrp = update_group_create(paf);
		if (!updgrp) {
			flog_err(EC_BGP_UPDGRP_CREATE,
				 "couldn't create update group for peer %s",
				 paf->peer->host);
			return;
		}
	}

	old_subgrp = paf->subgroup;

	if (old_subgrp) {

		/*
		 * If the update group of the peer is unchanged, the peer can
		 * stay
		 * in its existing subgroup and we're done.
		 */
		if (old_subgrp->update_group == updgrp)
			return;

		/*
		 * The peer is switching between update groups. Put it in its
		 * own subgroup under the new update group.
		 */
		update_subgroup_split_peer(paf, updgrp);
		return;
	}

	subgrp = update_subgroup_find(updgrp, paf);
	if (!subgrp) {
		subgrp = update_subgroup_create(updgrp);
		if (!subgrp)
			return;
	}

	update_subgroup_add_peer(subgrp, paf, 1);
	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		zlog_debug("u%" PRIu64 ":s%" PRIu64 " add peer %s", updgrp->id,
			   subgrp->id, paf->peer->host);

	return;
}

int update_group_adjust_soloness(struct peer *peer, int set)
{
	struct peer_group *group;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer_lonesoul_or_not(peer, set);
		if (peer->status == Established)
			bgp_announce_route_all(peer);
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			peer_lonesoul_or_not(peer, set);
			if (peer->status == Established)
				bgp_announce_route_all(peer);
		}
	}
	return 0;
}

/*
 * update_subgroup_rib
 */
struct bgp_table *update_subgroup_rib(struct update_subgroup *subgrp)
{
	struct bgp *bgp;

	bgp = SUBGRP_INST(subgrp);
	if (!bgp)
		return NULL;

	return bgp->rib[SUBGRP_AFI(subgrp)][SUBGRP_SAFI(subgrp)];
}

void update_group_af_walk(struct bgp *bgp, afi_t afi, safi_t safi,
			  updgrp_walkcb cb, void *ctx)
{
	struct updwalk_context wctx;
	int afid;

	if (!bgp)
		return;
	afid = afindex(afi, safi);
	if (afid >= BGP_AF_MAX)
		return;

	memset(&wctx, 0, sizeof(wctx));
	wctx.cb = cb;
	wctx.context = ctx;

	if (bgp->update_groups[afid])
		hash_walk(bgp->update_groups[afid], update_group_walkcb, &wctx);
}

void update_group_walk(struct bgp *bgp, updgrp_walkcb cb, void *ctx)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		update_group_af_walk(bgp, afi, safi, cb, ctx);
	}
}

void update_group_periodic_merge(struct bgp *bgp)
{
	char reason[] = "periodic merge check";

	update_group_walk(bgp, update_group_periodic_merge_walkcb,
			  (void *)reason);
}

static int
update_group_default_originate_route_map_walkcb(struct update_group *updgrp,
						void *arg)
{
	struct update_subgroup *subgrp;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	UPDGRP_FOREACH_SUBGRP (updgrp, subgrp) {
		peer = SUBGRP_PEER(subgrp);
		afi = SUBGRP_AFI(subgrp);
		safi = SUBGRP_SAFI(subgrp);

		if (peer->default_rmap[afi][safi].name) {
			subgroup_default_originate(subgrp, 0);
		}
	}

	return UPDWALK_CONTINUE;
}

int update_group_refresh_default_originate_route_map(struct thread *thread)
{
	struct bgp *bgp;
	char reason[] = "refresh default-originate route-map";

	bgp = THREAD_ARG(thread);
	update_group_walk(bgp, update_group_default_originate_route_map_walkcb,
			  reason);
	THREAD_TIMER_OFF(bgp->t_rmap_def_originate_eval);
	bgp_unlock(bgp);

	return (0);
}

/*
 * peer_af_announce_route
 *
 * Refreshes routes out to a peer_af immediately.
 *
 * If the combine parameter is true, then this function will try to
 * gather other peers in the subgroup for which a route announcement
 * is pending and efficently announce routes to all of them.
 *
 * For now, the 'combine' option has an effect only if all peers in
 * the subgroup have a route announcement pending.
 */
void peer_af_announce_route(struct peer_af *paf, int combine)
{
	struct update_subgroup *subgrp;
	struct peer_af *cur_paf;
	int all_pending;

	subgrp = paf->subgroup;
	all_pending = 0;

	if (combine) {
		/*
		 * If there are other peers in the old subgroup that also need
		 * routes to be announced, pull them into the peer's new
		 * subgroup.
		 * Combine route announcement with other peers if possible.
		 *
		 * For now, we combine only if all peers in the subgroup have an
		 * announcement pending.
		 */
		all_pending = 1;

		SUBGRP_FOREACH_PEER (subgrp, cur_paf) {
			if (cur_paf == paf)
				continue;

			if (cur_paf->t_announce_route)
				continue;

			all_pending = 0;
			break;
		}
	}
	/*
	 * Announce to the peer alone if we were not asked to combine peers,
	 * or if some peers don't have a route annoucement pending.
	 */
	if (!combine || !all_pending) {
		update_subgroup_split_peer(paf, NULL);
		subgrp = paf->subgroup;

		assert(subgrp && subgrp->update_group);
		if (bgp_debug_update(paf->peer, NULL, subgrp->update_group, 0))
			zlog_debug("u%" PRIu64 ":s%" PRIu64
				   " %s announcing routes",
				   subgrp->update_group->id, subgrp->id,
				   paf->peer->host);

		subgroup_announce_route(paf->subgroup);
		return;
	}

	/*
	 * We will announce routes the entire subgroup.
	 *
	 * First stop refresh timers on all the other peers.
	 */
	SUBGRP_FOREACH_PEER (subgrp, cur_paf) {
		if (cur_paf == paf)
			continue;

		bgp_stop_announce_route_timer(cur_paf);
	}

	if (bgp_debug_update(paf->peer, NULL, subgrp->update_group, 0))
		zlog_debug("u%" PRIu64 ":s%" PRIu64
			   " announcing routes to %s, combined into %d peers",
			   subgrp->update_group->id, subgrp->id,
			   paf->peer->host, subgrp->peer_count);

	subgroup_announce_route(subgrp);

	SUBGRP_INCR_STAT_BY(subgrp, peer_refreshes_combined,
			    subgrp->peer_count - 1);
}

void subgroup_trigger_write(struct update_subgroup *subgrp)
{
	struct peer_af *paf;

	/*
	 * For each peer in the subgroup, schedule a job to pull packets from
	 * the subgroup output queue into their own output queue. This action
	 * will trigger a write job on the I/O thread.
	 */
	SUBGRP_FOREACH_PEER (subgrp, paf)
		if (paf->peer->status == Established)
			thread_add_timer_msec(
				bm->master, bgp_generate_updgrp_packets,
				paf->peer, 0,
				&paf->peer->t_generate_updgrp_packets);
}

int update_group_clear_update_dbg(struct update_group *updgrp, void *arg)
{
	UPDGRP_PEER_DBG_OFF(updgrp);
	return UPDWALK_CONTINUE;
}

/* Return true if we should addpath encode NLRI to this peer */
int bgp_addpath_encode_tx(struct peer *peer, afi_t afi, safi_t safi)
{
	return (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_ADV)
		&& CHECK_FLAG(peer->af_cap[afi][safi],
			      PEER_CAP_ADDPATH_AF_RX_RCV));
}
