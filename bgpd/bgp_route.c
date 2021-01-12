/* BGP routing information
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2016 Job Snijders <job@instituut.net>
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
#include <math.h>

#include "printfrr.h"
#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "queue.h"
#include "memory.h"
#include "srv6.h"
#include "lib/json.h"
#include "lib_errors.h"
#include "zclient.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_trace.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#endif
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_encap_tlv.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_pbr.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "bgpd/bgp_nb.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_route_clippy.c"
#endif

/* Extern from bgp_dump.c */
extern const char *bgp_origin_str[];
extern const char *bgp_origin_long_str[];

/* PMSI strings. */
#define PMSI_TNLTYPE_STR_NO_INFO "No info"
#define PMSI_TNLTYPE_STR_DEFAULT PMSI_TNLTYPE_STR_NO_INFO
static const struct message bgp_pmsi_tnltype_str[] = {
	{PMSI_TNLTYPE_NO_INFO, PMSI_TNLTYPE_STR_NO_INFO},
	{PMSI_TNLTYPE_RSVP_TE_P2MP, "RSVP-TE P2MP"},
	{PMSI_TNLTYPE_MLDP_P2MP, "mLDP P2MP"},
	{PMSI_TNLTYPE_PIM_SSM, "PIM-SSM"},
	{PMSI_TNLTYPE_PIM_SM, "PIM-SM"},
	{PMSI_TNLTYPE_PIM_BIDIR, "PIM-BIDIR"},
	{PMSI_TNLTYPE_INGR_REPL, "Ingress Replication"},
	{PMSI_TNLTYPE_MLDP_MP2MP, "mLDP MP2MP"},
	{0}
};

#define VRFID_NONE_STR "-"

DEFINE_HOOK(bgp_process,
	    (struct bgp * bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
	     struct peer *peer, bool withdraw),
	    (bgp, afi, safi, bn, peer, withdraw))

/** Test if path is suppressed. */
static bool bgp_path_suppressed(struct bgp_path_info *pi)
{
	if (pi->extra == NULL || pi->extra->aggr_suppressors == NULL)
		return false;

	return listcount(pi->extra->aggr_suppressors) > 0;
}

struct bgp_dest *bgp_afi_node_get(struct bgp_table *table, afi_t afi,
				  safi_t safi, const struct prefix *p,
				  struct prefix_rd *prd)
{
	struct bgp_dest *dest;
	struct bgp_dest *pdest = NULL;

	assert(table);

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN)) {
		pdest = bgp_node_get(table, (struct prefix *)prd);

		if (!bgp_dest_has_bgp_path_info_data(pdest))
			bgp_dest_set_bgp_table_info(
				pdest, bgp_table_init(table->bgp, afi, safi));
		else
			bgp_dest_unlock_node(pdest);
		table = bgp_dest_get_bgp_table_info(pdest);
	}

	dest = bgp_node_get(table, p);

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN))
		dest->pdest = pdest;

	return dest;
}

struct bgp_dest *bgp_afi_node_lookup(struct bgp_table *table, afi_t afi,
				     safi_t safi, const struct prefix *p,
				     struct prefix_rd *prd)
{
	struct bgp_dest *dest;
	struct bgp_dest *pdest = NULL;

	if (!table)
		return NULL;

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN)) {
		pdest = bgp_node_lookup(table, (struct prefix *)prd);
		if (!pdest)
			return NULL;

		if (!bgp_dest_has_bgp_path_info_data(pdest)) {
			bgp_dest_unlock_node(pdest);
			return NULL;
		}

		table = bgp_dest_get_bgp_table_info(pdest);
	}

	dest = bgp_node_lookup(table, p);

	return dest;
}

/* Allocate bgp_path_info_extra */
static struct bgp_path_info_extra *bgp_path_info_extra_new(void)
{
	struct bgp_path_info_extra *new;
	new = XCALLOC(MTYPE_BGP_ROUTE_EXTRA,
		      sizeof(struct bgp_path_info_extra));
	new->label[0] = MPLS_INVALID_LABEL;
	new->num_labels = 0;
	new->bgp_fs_pbr = NULL;
	new->bgp_fs_iprule = NULL;
	return new;
}

void bgp_path_info_extra_free(struct bgp_path_info_extra **extra)
{
	struct bgp_path_info_extra *e;

	if (!extra || !*extra)
		return;

	e = *extra;
	if (e->damp_info)
		bgp_damp_info_free(e->damp_info, 0, e->damp_info->afi,
				   e->damp_info->safi);

	e->damp_info = NULL;
	if (e->parent) {
		struct bgp_path_info *bpi = (struct bgp_path_info *)e->parent;

		if (bpi->net) {
			/* FIXME: since multiple e may have the same e->parent
			 * and e->parent->net is holding a refcount for each
			 * of them, we need to do some fudging here.
			 *
			 * WARNING: if bpi->net->lock drops to 0, bpi may be
			 * freed as well (because bpi->net was holding the
			 * last reference to bpi) => write after free!
			 */
			unsigned refcount;

			bpi = bgp_path_info_lock(bpi);
			refcount = bgp_dest_get_lock_count(bpi->net) - 1;
			bgp_dest_unlock_node((struct bgp_dest *)bpi->net);
			if (!refcount)
				bpi->net = NULL;
			bgp_path_info_unlock(bpi);
		}
		bgp_path_info_unlock(e->parent);
		e->parent = NULL;
	}

	if (e->bgp_orig)
		bgp_unlock(e->bgp_orig);

	if (e->aggr_suppressors)
		list_delete(&e->aggr_suppressors);

	if (e->es_info)
		bgp_evpn_path_es_info_free(e->es_info);

	if ((*extra)->bgp_fs_iprule)
		list_delete(&((*extra)->bgp_fs_iprule));
	if ((*extra)->bgp_fs_pbr)
		list_delete(&((*extra)->bgp_fs_pbr));
	XFREE(MTYPE_BGP_ROUTE_EXTRA, *extra);
}

/* Get bgp_path_info extra information for the given bgp_path_info, lazy
 * allocated if required.
 */
struct bgp_path_info_extra *bgp_path_info_extra_get(struct bgp_path_info *pi)
{
	if (!pi->extra)
		pi->extra = bgp_path_info_extra_new();
	return pi->extra;
}

/* Free bgp route information. */
static void bgp_path_info_free(struct bgp_path_info *path)
{
	bgp_attr_unintern(&path->attr);

	bgp_unlink_nexthop(path);
	bgp_path_info_extra_free(&path->extra);
	bgp_path_info_mpath_free(&path->mpath);
	if (path->net)
		bgp_addpath_free_info_data(&path->tx_addpath,
					   &path->net->tx_addpath);

	peer_unlock(path->peer); /* bgp_path_info peer reference */

	XFREE(MTYPE_BGP_ROUTE, path);
}

struct bgp_path_info *bgp_path_info_lock(struct bgp_path_info *path)
{
	path->lock++;
	return path;
}

struct bgp_path_info *bgp_path_info_unlock(struct bgp_path_info *path)
{
	assert(path && path->lock > 0);
	path->lock--;

	if (path->lock == 0) {
#if 0
      zlog_debug ("%s: unlocked and freeing", __func__);
      zlog_backtrace (LOG_DEBUG);
#endif
		bgp_path_info_free(path);
		return NULL;
	}

#if 0
  if (path->lock == 1)
    {
      zlog_debug ("%s: unlocked to 1", __func__);
      zlog_backtrace (LOG_DEBUG);
    }
#endif

	return path;
}

/* This function sets flag BGP_NODE_SELECT_DEFER based on condition */
static int bgp_dest_set_defer_flag(struct bgp_dest *dest, bool delete)
{
	struct peer *peer;
	struct bgp_path_info *old_pi, *nextpi;
	bool set_flag = false;
	struct bgp *bgp = NULL;
	struct bgp_table *table = NULL;
	afi_t afi = 0;
	safi_t safi = 0;

	/* If the flag BGP_NODE_SELECT_DEFER is set and new path is added
	 * then the route selection is deferred
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER) && (!delete))
		return 0;

	if (CHECK_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug(
				"Route %pBD is in workqueue and being processed, not deferred.",
				dest);

		return 0;
	}

	table = bgp_dest_table(dest);
	if (table) {
		bgp = table->bgp;
		afi = table->afi;
		safi = table->safi;
	}

	for (old_pi = bgp_dest_get_bgp_path_info(dest);
	     (old_pi != NULL) && (nextpi = old_pi->next, 1); old_pi = nextpi) {
		if (CHECK_FLAG(old_pi->flags, BGP_PATH_SELECTED))
			continue;

		/* Route selection is deferred if there is a stale path which
		 * which indicates peer is in restart mode
		 */
		if (CHECK_FLAG(old_pi->flags, BGP_PATH_STALE)
		    && (old_pi->sub_type == BGP_ROUTE_NORMAL)) {
			set_flag = true;
		} else {
			/* If the peer is graceful restart capable and peer is
			 * restarting mode, set the flag BGP_NODE_SELECT_DEFER
			 */
			peer = old_pi->peer;
			if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)
			    && BGP_PEER_RESTARTING_MODE(peer)
			    && (old_pi
				&& old_pi->sub_type == BGP_ROUTE_NORMAL)) {
				set_flag = true;
			}
		}
		if (set_flag)
			break;
	}

	/* Set the flag BGP_NODE_SELECT_DEFER if route selection deferral timer
	 * is active
	 */
	if (set_flag && table) {
		if (bgp && (bgp->gr_info[afi][safi].t_select_deferral)) {
			if (!CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER))
				bgp->gr_info[afi][safi].gr_deferred++;
			SET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
			if (BGP_DEBUG(update, UPDATE_OUT))
				zlog_debug("DEFER route %pBD, dest %p", dest,
					   dest);
			return 0;
		}
	}
	return -1;
}

void bgp_path_info_add(struct bgp_dest *dest, struct bgp_path_info *pi)
{
	struct bgp_path_info *top;

	top = bgp_dest_get_bgp_path_info(dest);

	pi->next = top;
	pi->prev = NULL;
	if (top)
		top->prev = pi;
	bgp_dest_set_bgp_path_info(dest, pi);

	bgp_path_info_lock(pi);
	bgp_dest_lock_node(dest);
	peer_lock(pi->peer); /* bgp_path_info peer reference */
	bgp_dest_set_defer_flag(dest, false);
}

/* Do the actual removal of info from RIB, for use by bgp_process
   completion callback *only* */
void bgp_path_info_reap(struct bgp_dest *dest, struct bgp_path_info *pi)
{
	if (pi->next)
		pi->next->prev = pi->prev;
	if (pi->prev)
		pi->prev->next = pi->next;
	else
		bgp_dest_set_bgp_path_info(dest, pi->next);

	bgp_path_info_mpath_dequeue(pi);
	bgp_path_info_unlock(pi);
	bgp_dest_unlock_node(dest);
}

void bgp_path_info_delete(struct bgp_dest *dest, struct bgp_path_info *pi)
{
	bgp_path_info_set_flag(dest, pi, BGP_PATH_REMOVED);
	/* set of previous already took care of pcount */
	UNSET_FLAG(pi->flags, BGP_PATH_VALID);
}

/* undo the effects of a previous call to bgp_path_info_delete; typically
   called when a route is deleted and then quickly re-added before the
   deletion has been processed */
void bgp_path_info_restore(struct bgp_dest *dest, struct bgp_path_info *pi)
{
	bgp_path_info_unset_flag(dest, pi, BGP_PATH_REMOVED);
	/* unset of previous already took care of pcount */
	SET_FLAG(pi->flags, BGP_PATH_VALID);
}

/* Adjust pcount as required */
static void bgp_pcount_adjust(struct bgp_dest *dest, struct bgp_path_info *pi)
{
	struct bgp_table *table;

	assert(dest && bgp_dest_table(dest));
	assert(pi && pi->peer && pi->peer->bgp);

	table = bgp_dest_table(dest);

	if (pi->peer == pi->peer->bgp->peer_self)
		return;

	if (!BGP_PATH_COUNTABLE(pi)
	    && CHECK_FLAG(pi->flags, BGP_PATH_COUNTED)) {

		UNSET_FLAG(pi->flags, BGP_PATH_COUNTED);

		/* slight hack, but more robust against errors. */
		if (pi->peer->pcount[table->afi][table->safi])
			pi->peer->pcount[table->afi][table->safi]--;
		else
			flog_err(EC_LIB_DEVELOPMENT,
				 "Asked to decrement 0 prefix count for peer");
	} else if (BGP_PATH_COUNTABLE(pi)
		   && !CHECK_FLAG(pi->flags, BGP_PATH_COUNTED)) {
		SET_FLAG(pi->flags, BGP_PATH_COUNTED);
		pi->peer->pcount[table->afi][table->safi]++;
	}
}

static int bgp_label_index_differs(struct bgp_path_info *pi1,
				   struct bgp_path_info *pi2)
{
	return (!(pi1->attr->label_index == pi2->attr->label_index));
}

/* Set/unset bgp_path_info flags, adjusting any other state as needed.
 * This is here primarily to keep prefix-count in check.
 */
void bgp_path_info_set_flag(struct bgp_dest *dest, struct bgp_path_info *pi,
			    uint32_t flag)
{
	SET_FLAG(pi->flags, flag);

	/* early bath if we know it's not a flag that changes countability state
	 */
	if (!CHECK_FLAG(flag,
			BGP_PATH_VALID | BGP_PATH_HISTORY | BGP_PATH_REMOVED))
		return;

	bgp_pcount_adjust(dest, pi);
}

void bgp_path_info_unset_flag(struct bgp_dest *dest, struct bgp_path_info *pi,
			      uint32_t flag)
{
	UNSET_FLAG(pi->flags, flag);

	/* early bath if we know it's not a flag that changes countability state
	 */
	if (!CHECK_FLAG(flag,
			BGP_PATH_VALID | BGP_PATH_HISTORY | BGP_PATH_REMOVED))
		return;

	bgp_pcount_adjust(dest, pi);
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
static uint32_t bgp_med_value(struct attr *attr, struct bgp *bgp)
{
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
		return attr->med;
	else {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
			return BGP_MED_MAX;
		else
			return 0;
	}
}

void bgp_path_info_path_with_addpath_rx_str(struct bgp_path_info *pi, char *buf)
{
	if (pi->addpath_rx_id)
		sprintf(buf, "path %s (addpath rxid %d)", pi->peer->host,
			pi->addpath_rx_id);
	else
		sprintf(buf, "path %s", pi->peer->host);
}

/* Compare two bgp route entity.  If 'new' is preferable over 'exist' return 1.
 */
static int bgp_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
			     struct bgp_path_info *exist, int *paths_eq,
			     struct bgp_maxpaths_cfg *mpath_cfg, int debug,
			     char *pfx_buf, afi_t afi, safi_t safi,
			     enum bgp_path_selection_reason *reason)
{
	struct attr *newattr, *existattr;
	bgp_peer_sort_t new_sort;
	bgp_peer_sort_t exist_sort;
	uint32_t new_pref;
	uint32_t exist_pref;
	uint32_t new_med;
	uint32_t exist_med;
	uint32_t new_weight;
	uint32_t exist_weight;
	uint32_t newm, existm;
	struct in_addr new_id;
	struct in_addr exist_id;
	int new_cluster;
	int exist_cluster;
	int internal_as_route;
	int confed_as_route;
	int ret = 0;
	char new_buf[PATH_ADDPATH_STR_BUFFER];
	char exist_buf[PATH_ADDPATH_STR_BUFFER];
	uint32_t new_mm_seq;
	uint32_t exist_mm_seq;
	int nh_cmp;
	esi_t *exist_esi;
	esi_t *new_esi;
	bool same_esi;
	bool old_proxy;
	bool new_proxy;
	bool new_origin, exist_origin;

	*paths_eq = 0;

	/* 0. Null check. */
	if (new == NULL) {
		*reason = bgp_path_selection_none;
		if (debug)
			zlog_debug("%s: new is NULL", pfx_buf);
		return 0;
	}

	if (debug)
		bgp_path_info_path_with_addpath_rx_str(new, new_buf);

	if (exist == NULL) {
		*reason = bgp_path_selection_first;
		if (debug)
			zlog_debug("%s: %s is the initial bestpath", pfx_buf,
				   new_buf);
		return 1;
	}

	if (debug) {
		bgp_path_info_path_with_addpath_rx_str(exist, exist_buf);
		zlog_debug("%s: Comparing %s flags 0x%x with %s flags 0x%x",
			   pfx_buf, new_buf, new->flags, exist_buf,
			   exist->flags);
	}

	newattr = new->attr;
	existattr = exist->attr;

	/* For EVPN routes, we cannot just go by local vs remote, we have to
	 * look at the MAC mobility sequence number, if present.
	 */
	if (safi == SAFI_EVPN) {
		/* This is an error condition described in RFC 7432 Section
		 * 15.2. The RFC
		 * states that in this scenario "the PE MUST alert the operator"
		 * but it
		 * does not state what other action to take. In order to provide
		 * some
		 * consistency in this scenario we are going to prefer the path
		 * with the
		 * sticky flag.
		 */
		if (newattr->sticky != existattr->sticky) {
			if (!debug) {
				prefix2str(
					bgp_dest_get_prefix(new->net), pfx_buf,
					sizeof(*pfx_buf) * PREFIX2STR_BUFFER);
				bgp_path_info_path_with_addpath_rx_str(new,
								       new_buf);
				bgp_path_info_path_with_addpath_rx_str(
					exist, exist_buf);
			}

			if (newattr->sticky && !existattr->sticky) {
				*reason = bgp_path_selection_evpn_sticky_mac;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s due to sticky MAC flag",
						pfx_buf, new_buf, exist_buf);
				return 1;
			}

			if (!newattr->sticky && existattr->sticky) {
				*reason = bgp_path_selection_evpn_sticky_mac;
				if (debug)
					zlog_debug(
						"%s: %s loses to %s due to sticky MAC flag",
						pfx_buf, new_buf, exist_buf);
				return 0;
			}
		}

		new_esi = bgp_evpn_attr_get_esi(newattr);
		exist_esi = bgp_evpn_attr_get_esi(existattr);
		if (bgp_evpn_is_esi_valid(new_esi) &&
				!memcmp(new_esi, exist_esi, sizeof(esi_t))) {
			same_esi = true;
		} else {
			same_esi = false;
		}

		/* If both paths have the same non-zero ES and
		 * one path is local it wins.
		 * PS: Note the local path wins even if the remote
		 * has the higher MM seq. The local path's
		 * MM seq will be fixed up to match the highest
		 * rem seq, subsequently.
		 */
		if (same_esi) {
			char esi_buf[ESI_STR_LEN];

			if (bgp_evpn_is_path_local(bgp, new)) {
				*reason = bgp_path_selection_evpn_local_path;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s as ES %s is same and local",
						pfx_buf, new_buf, exist_buf,
						esi_to_str(new_esi, esi_buf,
						sizeof(esi_buf)));
				return 1;
			}
			if (bgp_evpn_is_path_local(bgp, exist)) {
				*reason = bgp_path_selection_evpn_local_path;
				if (debug)
					zlog_debug(
						"%s: %s loses to %s as ES %s is same and local",
						pfx_buf, new_buf, exist_buf,
						esi_to_str(new_esi, esi_buf,
						sizeof(esi_buf)));
				return 0;
			}
		}

		new_mm_seq = mac_mobility_seqnum(newattr);
		exist_mm_seq = mac_mobility_seqnum(existattr);

		if (new_mm_seq > exist_mm_seq) {
			*reason = bgp_path_selection_evpn_seq;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to MM seq %u > %u",
					pfx_buf, new_buf, exist_buf, new_mm_seq,
					exist_mm_seq);
			return 1;
		}

		if (new_mm_seq < exist_mm_seq) {
			*reason = bgp_path_selection_evpn_seq;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to MM seq %u < %u",
					pfx_buf, new_buf, exist_buf, new_mm_seq,
					exist_mm_seq);
			return 0;
		}

		/* if the sequence numbers and ESI are the same and one path
		 * is non-proxy it wins (over proxy)
		 */
		new_proxy = bgp_evpn_attr_is_proxy(newattr);
		old_proxy = bgp_evpn_attr_is_proxy(existattr);
		if (same_esi && bgp_evpn_attr_is_local_es(newattr) &&
				old_proxy != new_proxy) {
			if (!new_proxy) {
				*reason = bgp_path_selection_evpn_non_proxy;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s, same seq/es and non-proxy",
						pfx_buf, new_buf, exist_buf);
				return 1;
			}

			*reason = bgp_path_selection_evpn_non_proxy;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s, same seq/es and non-proxy",
					pfx_buf, new_buf, exist_buf);
			return 0;
		}

		/*
		 * if sequence numbers are the same path with the lowest IP
		 * wins
		 */
		nh_cmp = bgp_path_info_nexthop_cmp(new, exist);
		if (nh_cmp < 0) {
			*reason = bgp_path_selection_evpn_lower_ip;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to same MM seq %u and lower IP %pI4",
					pfx_buf, new_buf, exist_buf, new_mm_seq,
					&new->attr->nexthop);
			return 1;
		}
		if (nh_cmp > 0) {
			*reason = bgp_path_selection_evpn_lower_ip;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to same MM seq %u and higher IP %pI4",
					pfx_buf, new_buf, exist_buf, new_mm_seq,
					&new->attr->nexthop);
			return 0;
		}
	}

	/* 1. Weight check. */
	new_weight = newattr->weight;
	exist_weight = existattr->weight;

	if (new_weight > exist_weight) {
		*reason = bgp_path_selection_weight;
		if (debug)
			zlog_debug("%s: %s wins over %s due to weight %d > %d",
				   pfx_buf, new_buf, exist_buf, new_weight,
				   exist_weight);
		return 1;
	}

	if (new_weight < exist_weight) {
		*reason = bgp_path_selection_weight;
		if (debug)
			zlog_debug("%s: %s loses to %s due to weight %d < %d",
				   pfx_buf, new_buf, exist_buf, new_weight,
				   exist_weight);
		return 0;
	}

	/* 2. Local preference check. */
	new_pref = exist_pref = bgp->default_local_pref;

	if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
		new_pref = newattr->local_pref;
	if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
		exist_pref = existattr->local_pref;

	if (new_pref > exist_pref) {
		*reason = bgp_path_selection_local_pref;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to localpref %d > %d",
				pfx_buf, new_buf, exist_buf, new_pref,
				exist_pref);
		return 1;
	}

	if (new_pref < exist_pref) {
		*reason = bgp_path_selection_local_pref;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to localpref %d < %d",
				pfx_buf, new_buf, exist_buf, new_pref,
				exist_pref);
		return 0;
	}

	/* 3. Local route check. We prefer:
	 *  - BGP_ROUTE_STATIC
	 *  - BGP_ROUTE_AGGREGATE
	 *  - BGP_ROUTE_REDISTRIBUTE
	 */
	new_origin = !(new->sub_type == BGP_ROUTE_NORMAL ||
		       new->sub_type == BGP_ROUTE_IMPORTED);
	exist_origin = !(exist->sub_type == BGP_ROUTE_NORMAL ||
			 exist->sub_type == BGP_ROUTE_IMPORTED);

	if (new_origin && !exist_origin) {
		*reason = bgp_path_selection_local_route;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to preferred BGP_ROUTE type",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	if (!new_origin && exist_origin) {
		*reason = bgp_path_selection_local_route;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to preferred BGP_ROUTE type",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	/* 4. AS path length check. */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE)) {
		int exist_hops = aspath_count_hops(existattr->aspath);
		int exist_confeds = aspath_count_confeds(existattr->aspath);

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED)) {
			int aspath_hops;

			aspath_hops = aspath_count_hops(newattr->aspath);
			aspath_hops += aspath_count_confeds(newattr->aspath);

			if (aspath_hops < (exist_hops + exist_confeds)) {
				*reason = bgp_path_selection_confed_as_path;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s due to aspath (with confeds) hopcount %d < %d",
						pfx_buf, new_buf, exist_buf,
						aspath_hops,
						(exist_hops + exist_confeds));
				return 1;
			}

			if (aspath_hops > (exist_hops + exist_confeds)) {
				*reason = bgp_path_selection_confed_as_path;
				if (debug)
					zlog_debug(
						"%s: %s loses to %s due to aspath (with confeds) hopcount %d > %d",
						pfx_buf, new_buf, exist_buf,
						aspath_hops,
						(exist_hops + exist_confeds));
				return 0;
			}
		} else {
			int newhops = aspath_count_hops(newattr->aspath);

			if (newhops < exist_hops) {
				*reason = bgp_path_selection_as_path;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s due to aspath hopcount %d < %d",
						pfx_buf, new_buf, exist_buf,
						newhops, exist_hops);
				return 1;
			}

			if (newhops > exist_hops) {
				*reason = bgp_path_selection_as_path;
				if (debug)
					zlog_debug(
						"%s: %s loses to %s due to aspath hopcount %d > %d",
						pfx_buf, new_buf, exist_buf,
						newhops, exist_hops);
				return 0;
			}
		}
	}

	/* 5. Origin check. */
	if (newattr->origin < existattr->origin) {
		*reason = bgp_path_selection_origin;
		if (debug)
			zlog_debug("%s: %s wins over %s due to ORIGIN %s < %s",
				   pfx_buf, new_buf, exist_buf,
				   bgp_origin_long_str[newattr->origin],
				   bgp_origin_long_str[existattr->origin]);
		return 1;
	}

	if (newattr->origin > existattr->origin) {
		*reason = bgp_path_selection_origin;
		if (debug)
			zlog_debug("%s: %s loses to %s due to ORIGIN %s > %s",
				   pfx_buf, new_buf, exist_buf,
				   bgp_origin_long_str[newattr->origin],
				   bgp_origin_long_str[existattr->origin]);
		return 0;
	}

	/* 6. MED check. */
	internal_as_route = (aspath_count_hops(newattr->aspath) == 0
			     && aspath_count_hops(existattr->aspath) == 0);
	confed_as_route = (aspath_count_confeds(newattr->aspath) > 0
			   && aspath_count_confeds(existattr->aspath) > 0
			   && aspath_count_hops(newattr->aspath) == 0
			   && aspath_count_hops(existattr->aspath) == 0);

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED)
	    || (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED) && confed_as_route)
	    || aspath_cmp_left(newattr->aspath, existattr->aspath)
	    || aspath_cmp_left_confed(newattr->aspath, existattr->aspath)
	    || internal_as_route) {
		new_med = bgp_med_value(new->attr, bgp);
		exist_med = bgp_med_value(exist->attr, bgp);

		if (new_med < exist_med) {
			*reason = bgp_path_selection_med;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to MED %d < %d",
					pfx_buf, new_buf, exist_buf, new_med,
					exist_med);
			return 1;
		}

		if (new_med > exist_med) {
			*reason = bgp_path_selection_med;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to MED %d > %d",
					pfx_buf, new_buf, exist_buf, new_med,
					exist_med);
			return 0;
		}
	}

	/* 7. Peer type check. */
	new_sort = new->peer->sort;
	exist_sort = exist->peer->sort;

	if (new_sort == BGP_PEER_EBGP
	    && (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED)) {
		*reason = bgp_path_selection_peer;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to eBGP peer > iBGP peer",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	if (exist_sort == BGP_PEER_EBGP
	    && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED)) {
		*reason = bgp_path_selection_peer;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to iBGP peer < eBGP peer",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	/* 8. IGP metric check. */
	newm = existm = 0;

	if (new->extra)
		newm = new->extra->igpmetric;
	if (exist->extra)
		existm = exist->extra->igpmetric;

	if (newm < existm) {
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to IGP metric %d < %d",
				pfx_buf, new_buf, exist_buf, newm, existm);
		ret = 1;
	}

	if (newm > existm) {
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to IGP metric %d > %d",
				pfx_buf, new_buf, exist_buf, newm, existm);
		ret = 0;
	}

	/* 9. Same IGP metric. Compare the cluster list length as
	   representative of IGP hops metric. Rewrite the metric value
	   pair (newm, existm) with the cluster list length. Prefer the
	   path with smaller cluster list length.                       */
	if (newm == existm) {
		if (peer_sort_lookup(new->peer) == BGP_PEER_IBGP
		    && peer_sort_lookup(exist->peer) == BGP_PEER_IBGP
		    && (mpath_cfg == NULL
			|| CHECK_FLAG(
				   mpath_cfg->ibgp_flags,
				   BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))) {
			newm = BGP_CLUSTER_LIST_LENGTH(new->attr);
			existm = BGP_CLUSTER_LIST_LENGTH(exist->attr);

			if (newm < existm) {
				if (debug)
					zlog_debug(
						"%s: %s wins over %s due to CLUSTER_LIST length %d < %d",
						pfx_buf, new_buf, exist_buf,
						newm, existm);
				ret = 1;
			}

			if (newm > existm) {
				if (debug)
					zlog_debug(
						"%s: %s loses to %s due to CLUSTER_LIST length %d > %d",
						pfx_buf, new_buf, exist_buf,
						newm, existm);
				ret = 0;
			}
		}
	}

	/* 10. confed-external vs. confed-internal */
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		if (new_sort == BGP_PEER_CONFED
		    && exist_sort == BGP_PEER_IBGP) {
			*reason = bgp_path_selection_confed;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to confed-external peer > confed-internal peer",
					pfx_buf, new_buf, exist_buf);
			return 1;
		}

		if (exist_sort == BGP_PEER_CONFED
		    && new_sort == BGP_PEER_IBGP) {
			*reason = bgp_path_selection_confed;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to confed-internal peer < confed-external peer",
					pfx_buf, new_buf, exist_buf);
			return 0;
		}
	}

	/* 11. Maximum path check. */
	if (newm == existm) {
		/* If one path has a label but the other does not, do not treat
		 * them as equals for multipath
		 */
		if ((new->extra &&bgp_is_valid_label(&new->extra->label[0]))
		    != (exist->extra
			&& bgp_is_valid_label(&exist->extra->label[0]))) {
			if (debug)
				zlog_debug(
					"%s: %s and %s cannot be multipath, one has a label while the other does not",
					pfx_buf, new_buf, exist_buf);
		} else if (CHECK_FLAG(bgp->flags,
				      BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {

			/*
			 * For the two paths, all comparison steps till IGP
			 * metric
			 * have succeeded - including AS_PATH hop count. Since
			 * 'bgp
			 * bestpath as-path multipath-relax' knob is on, we
			 * don't need
			 * an exact match of AS_PATH. Thus, mark the paths are
			 * equal.
			 * That will trigger both these paths to get into the
			 * multipath
			 * array.
			 */
			*paths_eq = 1;

			if (debug)
				zlog_debug(
					"%s: %s and %s are equal via multipath-relax",
					pfx_buf, new_buf, exist_buf);
		} else if (new->peer->sort == BGP_PEER_IBGP) {
			if (aspath_cmp(new->attr->aspath,
				       exist->attr->aspath)) {
				*paths_eq = 1;

				if (debug)
					zlog_debug(
						"%s: %s and %s are equal via matching aspaths",
						pfx_buf, new_buf, exist_buf);
			}
		} else if (new->peer->as == exist->peer->as) {
			*paths_eq = 1;

			if (debug)
				zlog_debug(
					"%s: %s and %s are equal via same remote-as",
					pfx_buf, new_buf, exist_buf);
		}
	} else {
		/*
		 * TODO: If unequal cost ibgp multipath is enabled we can
		 * mark the paths as equal here instead of returning
		 */
		if (debug) {
			if (ret == 1)
				zlog_debug(
					"%s: %s wins over %s after IGP metric comparison",
					pfx_buf, new_buf, exist_buf);
			else
				zlog_debug(
					"%s: %s loses to %s after IGP metric comparison",
					pfx_buf, new_buf, exist_buf);
		}
		*reason = bgp_path_selection_igp_metric;
		return ret;
	}

	/* 12. If both paths are external, prefer the path that was received
	   first (the oldest one).  This step minimizes route-flap, since a
	   newer path won't displace an older one, even if it was the
	   preferred route based on the additional decision criteria below.  */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID)
	    && new_sort == BGP_PEER_EBGP && exist_sort == BGP_PEER_EBGP) {
		if (CHECK_FLAG(new->flags, BGP_PATH_SELECTED)) {
			*reason = bgp_path_selection_older;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to oldest external",
					pfx_buf, new_buf, exist_buf);
			return 1;
		}

		if (CHECK_FLAG(exist->flags, BGP_PATH_SELECTED)) {
			*reason = bgp_path_selection_older;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to oldest external",
					pfx_buf, new_buf, exist_buf);
			return 0;
		}
	}

	/* 13. Router-ID comparision. */
	/* If one of the paths is "stale", the corresponding peer router-id will
	 * be 0 and would always win over the other path. If originator id is
	 * used for the comparision, it will decide which path is better.
	 */
	if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
		new_id.s_addr = newattr->originator_id.s_addr;
	else
		new_id.s_addr = new->peer->remote_id.s_addr;
	if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
		exist_id.s_addr = existattr->originator_id.s_addr;
	else
		exist_id.s_addr = exist->peer->remote_id.s_addr;

	if (ntohl(new_id.s_addr) < ntohl(exist_id.s_addr)) {
		*reason = bgp_path_selection_router_id;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to Router-ID comparison",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	if (ntohl(new_id.s_addr) > ntohl(exist_id.s_addr)) {
		*reason = bgp_path_selection_router_id;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to Router-ID comparison",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	/* 14. Cluster length comparision. */
	new_cluster = BGP_CLUSTER_LIST_LENGTH(new->attr);
	exist_cluster = BGP_CLUSTER_LIST_LENGTH(exist->attr);

	if (new_cluster < exist_cluster) {
		*reason = bgp_path_selection_cluster_length;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to CLUSTER_LIST length %d < %d",
				pfx_buf, new_buf, exist_buf, new_cluster,
				exist_cluster);
		return 1;
	}

	if (new_cluster > exist_cluster) {
		*reason = bgp_path_selection_cluster_length;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to CLUSTER_LIST length %d > %d",
				pfx_buf, new_buf, exist_buf, new_cluster,
				exist_cluster);
		return 0;
	}

	/* 15. Neighbor address comparision. */
	/* Do this only if neither path is "stale" as stale paths do not have
	 * valid peer information (as the connection may or may not be up).
	 */
	if (CHECK_FLAG(exist->flags, BGP_PATH_STALE)) {
		*reason = bgp_path_selection_stale;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to latter path being STALE",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	if (CHECK_FLAG(new->flags, BGP_PATH_STALE)) {
		*reason = bgp_path_selection_stale;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to former path being STALE",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	/* locally configured routes to advertise do not have su_remote */
	if (new->peer->su_remote == NULL) {
		*reason = bgp_path_selection_local_configured;
		return 0;
	}
	if (exist->peer->su_remote == NULL) {
		*reason = bgp_path_selection_local_configured;
		return 1;
	}

	ret = sockunion_cmp(new->peer->su_remote, exist->peer->su_remote);

	if (ret == 1) {
		*reason = bgp_path_selection_neighbor_ip;
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to Neighor IP comparison",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	if (ret == -1) {
		*reason = bgp_path_selection_neighbor_ip;
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to Neighor IP comparison",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	*reason = bgp_path_selection_default;
	if (debug)
		zlog_debug("%s: %s wins over %s due to nothing left to compare",
			   pfx_buf, new_buf, exist_buf);

	return 1;
}


int bgp_evpn_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
			     struct bgp_path_info *exist, int *paths_eq)
{
	enum bgp_path_selection_reason reason;
	char pfx_buf[PREFIX2STR_BUFFER];

	return bgp_path_info_cmp(bgp, new, exist, paths_eq, NULL, 0, pfx_buf,
				AFI_L2VPN, SAFI_EVPN, &reason);
}

/* Compare two bgp route entity.  Return -1 if new is preferred, 1 if exist
 * is preferred, or 0 if they are the same (usually will only occur if
 * multipath is enabled
 * This version is compatible with */
int bgp_path_info_cmp_compatible(struct bgp *bgp, struct bgp_path_info *new,
				 struct bgp_path_info *exist, char *pfx_buf,
				 afi_t afi, safi_t safi,
				 enum bgp_path_selection_reason *reason)
{
	int paths_eq;
	int ret;
	ret = bgp_path_info_cmp(bgp, new, exist, &paths_eq, NULL, 0, pfx_buf,
				afi, safi, reason);

	if (paths_eq)
		ret = 0;
	else {
		if (ret == 1)
			ret = -1;
		else
			ret = 1;
	}
	return ret;
}

static enum filter_type bgp_input_filter(struct peer *peer,
					 const struct prefix *p,
					 struct attr *attr, afi_t afi,
					 safi_t safi)
{
	struct bgp_filter *filter;
	enum filter_type ret = FILTER_PERMIT;

	filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F, f, filter)                                        \
	if (BGP_DEBUG(update, UPDATE_IN) && !(F##_IN(filter)))                 \
		zlog_debug("%s: Could not find configured input %s-list %s!",  \
			   peer->host, #f, F##_IN_NAME(filter));

	if (DISTRIBUTE_IN_NAME(filter)) {
		FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);

		if (access_list_apply(DISTRIBUTE_IN(filter), p)
		    == FILTER_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

	if (PREFIX_LIST_IN_NAME(filter)) {
		FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);

		if (prefix_list_apply(PREFIX_LIST_IN(filter), p)
		    == PREFIX_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

	if (FILTER_LIST_IN_NAME(filter)) {
		FILTER_EXIST_WARN(FILTER_LIST, as, filter);

		if (as_list_apply(FILTER_LIST_IN(filter), attr->aspath)
		    == AS_FILTER_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

done:
	if (frrtrace_enabled(frr_bgp, input_filter)) {
		char pfxprint[PREFIX2STR_BUFFER];

		prefix2str(p, pfxprint, sizeof(pfxprint));
		frrtrace(5, frr_bgp, input_filter, peer, pfxprint, afi, safi,
			 ret == FILTER_PERMIT ? "permit" : "deny");
	}

	return ret;
#undef FILTER_EXIST_WARN
}

static enum filter_type bgp_output_filter(struct peer *peer,
					  const struct prefix *p,
					  struct attr *attr, afi_t afi,
					  safi_t safi)
{
	struct bgp_filter *filter;
	enum filter_type ret = FILTER_PERMIT;

	filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F, f, filter)                                        \
	if (BGP_DEBUG(update, UPDATE_OUT) && !(F##_OUT(filter)))               \
		zlog_debug("%s: Could not find configured output %s-list %s!", \
			   peer->host, #f, F##_OUT_NAME(filter));

	if (DISTRIBUTE_OUT_NAME(filter)) {
		FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);

		if (access_list_apply(DISTRIBUTE_OUT(filter), p)
		    == FILTER_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

	if (PREFIX_LIST_OUT_NAME(filter)) {
		FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);

		if (prefix_list_apply(PREFIX_LIST_OUT(filter), p)
		    == PREFIX_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

	if (FILTER_LIST_OUT_NAME(filter)) {
		FILTER_EXIST_WARN(FILTER_LIST, as, filter);

		if (as_list_apply(FILTER_LIST_OUT(filter), attr->aspath)
		    == AS_FILTER_DENY) {
			ret = FILTER_DENY;
			goto done;
		}
	}

	if (frrtrace_enabled(frr_bgp, output_filter)) {
		char pfxprint[PREFIX2STR_BUFFER];

		prefix2str(p, pfxprint, sizeof(pfxprint));
		frrtrace(5, frr_bgp, output_filter, peer, pfxprint, afi, safi,
			 ret == FILTER_PERMIT ? "permit" : "deny");
	}

done:
	return ret;
#undef FILTER_EXIST_WARN
}

/* If community attribute includes no_export then return 1. */
static bool bgp_community_filter(struct peer *peer, struct attr *attr)
{
	if (attr->community) {
		/* NO_ADVERTISE check. */
		if (community_include(attr->community, COMMUNITY_NO_ADVERTISE))
			return true;

		/* NO_EXPORT check. */
		if (peer->sort == BGP_PEER_EBGP
		    && community_include(attr->community, COMMUNITY_NO_EXPORT))
			return true;

		/* NO_EXPORT_SUBCONFED check. */
		if (peer->sort == BGP_PEER_EBGP
		    || peer->sort == BGP_PEER_CONFED)
			if (community_include(attr->community,
					      COMMUNITY_NO_EXPORT_SUBCONFED))
				return true;
	}
	return false;
}

/* Route reflection loop check.  */
static bool bgp_cluster_filter(struct peer *peer, struct attr *attr)
{
	struct in_addr cluster_id;
	struct cluster_list *cluster = bgp_attr_get_cluster(attr);

	if (cluster) {
		if (peer->bgp->config & BGP_CONFIG_CLUSTER_ID)
			cluster_id = peer->bgp->cluster_id;
		else
			cluster_id = peer->bgp->router_id;

		if (cluster_loop_check(cluster, cluster_id))
			return true;
	}
	return false;
}

static int bgp_input_modifier(struct peer *peer, const struct prefix *p,
			      struct attr *attr, afi_t afi, safi_t safi,
			      const char *rmap_name, mpls_label_t *label,
			      uint32_t num_labels, struct bgp_dest *dest)
{
	struct bgp_filter *filter;
	struct bgp_path_info rmap_path = { 0 };
	struct bgp_path_info_extra extra = { 0 };
	route_map_result_t ret;
	struct route_map *rmap = NULL;

	filter = &peer->filter[afi][safi];

	/* Apply default weight value. */
	if (peer->weight[afi][safi])
		attr->weight = peer->weight[afi][safi];

	if (rmap_name) {
		rmap = route_map_lookup_by_name(rmap_name);

		if (rmap == NULL)
			return RMAP_DENY;
	} else {
		if (ROUTE_MAP_IN_NAME(filter)) {
			rmap = ROUTE_MAP_IN(filter);

			if (rmap == NULL)
				return RMAP_DENY;
		}
	}

	/* Route map apply. */
	if (rmap) {
		memset(&rmap_path, 0, sizeof(struct bgp_path_info));
		/* Duplicate current value to new strucutre for modification. */
		rmap_path.peer = peer;
		rmap_path.attr = attr;
		rmap_path.extra = &extra;
		rmap_path.net = dest;

		extra.num_labels = num_labels;
		if (label && num_labels && num_labels <= BGP_MAX_LABELS)
			memcpy(extra.label, label,
				num_labels * sizeof(mpls_label_t));

		SET_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN);

		/* Apply BGP route map to the attribute. */
		ret = route_map_apply(rmap, p, &rmap_path);

		peer->rmap_type = 0;

		if (ret == RMAP_DENYMATCH)
			return RMAP_DENY;
	}
	return RMAP_PERMIT;
}

static int bgp_output_modifier(struct peer *peer, const struct prefix *p,
			       struct attr *attr, afi_t afi, safi_t safi,
			       const char *rmap_name)
{
	struct bgp_path_info rmap_path;
	route_map_result_t ret;
	struct route_map *rmap = NULL;
	uint8_t rmap_type;

	/*
	 * So if we get to this point and have no rmap_name
	 * we want to just show the output as it currently
	 * exists.
	 */
	if (!rmap_name)
		return RMAP_PERMIT;

	/* Apply default weight value. */
	if (peer->weight[afi][safi])
		attr->weight = peer->weight[afi][safi];

	rmap = route_map_lookup_by_name(rmap_name);

	/*
	 * If we have a route map name and we do not find
	 * the routemap that means we have an implicit
	 * deny.
	 */
	if (rmap == NULL)
		return RMAP_DENY;

	memset(&rmap_path, 0, sizeof(struct bgp_path_info));
	/* Route map apply. */
	/* Duplicate current value to new strucutre for modification. */
	rmap_path.peer = peer;
	rmap_path.attr = attr;

	rmap_type = peer->rmap_type;
	SET_FLAG(peer->rmap_type, PEER_RMAP_TYPE_OUT);

	/* Apply BGP route map to the attribute. */
	ret = route_map_apply(rmap, p, &rmap_path);

	peer->rmap_type = rmap_type;

	if (ret == RMAP_DENYMATCH)
		/*
		 * caller has multiple error paths with bgp_attr_flush()
		 */
		return RMAP_DENY;

	return RMAP_PERMIT;
}

/* If this is an EBGP peer with remove-private-AS */
static void bgp_peer_remove_private_as(struct bgp *bgp, afi_t afi, safi_t safi,
				       struct peer *peer, struct attr *attr)
{
	if (peer->sort == BGP_PEER_EBGP
	    && (peer_af_flag_check(peer, afi, safi,
				   PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE)
		|| peer_af_flag_check(peer, afi, safi,
				      PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE)
		|| peer_af_flag_check(peer, afi, safi,
				      PEER_FLAG_REMOVE_PRIVATE_AS_ALL)
		|| peer_af_flag_check(peer, afi, safi,
				      PEER_FLAG_REMOVE_PRIVATE_AS))) {
		// Take action on the entire aspath
		if (peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE)
		    || peer_af_flag_check(peer, afi, safi,
					  PEER_FLAG_REMOVE_PRIVATE_AS_ALL)) {
			if (peer_af_flag_check(
				    peer, afi, safi,
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
				attr->aspath = aspath_replace_private_asns(
					attr->aspath, bgp->as, peer->as);

			// The entire aspath consists of private ASNs so create
			// an empty aspath
			else if (aspath_private_as_check(attr->aspath))
				attr->aspath = aspath_empty_get();

			// There are some public and some private ASNs, remove
			// the private ASNs
			else
				attr->aspath = aspath_remove_private_asns(
					attr->aspath, peer->as);
		}

		// 'all' was not specified so the entire aspath must be private
		// ASNs
		// for us to do anything
		else if (aspath_private_as_check(attr->aspath)) {
			if (peer_af_flag_check(
				    peer, afi, safi,
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
				attr->aspath = aspath_replace_private_asns(
					attr->aspath, bgp->as, peer->as);
			else
				attr->aspath = aspath_empty_get();
		}
	}
}

/* If this is an EBGP peer with as-override */
static void bgp_peer_as_override(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct peer *peer, struct attr *attr)
{
	if (peer->sort == BGP_PEER_EBGP
	    && peer_af_flag_check(peer, afi, safi, PEER_FLAG_AS_OVERRIDE)) {
		if (aspath_single_asn_check(attr->aspath, peer->as))
			attr->aspath = aspath_replace_specific_asn(
				attr->aspath, peer->as, bgp->as);
	}
}

void bgp_attr_add_gshut_community(struct attr *attr)
{
	struct community *old;
	struct community *new;
	struct community *merge;
	struct community *gshut;

	old = attr->community;
	gshut = community_str2com("graceful-shutdown");

	assert(gshut);

	if (old) {
		merge = community_merge(community_dup(old), gshut);

		if (old->refcnt == 0)
			community_free(&old);

		new = community_uniq_sort(merge);
		community_free(&merge);
	} else {
		new = community_dup(gshut);
	}

	community_free(&gshut);
	attr->community = new;
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);

	/* When we add the graceful-shutdown community we must also
	 * lower the local-preference */
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
	attr->local_pref = BGP_GSHUT_LOCAL_PREF;
}


/* Notify BGP Conditional advertisement scanner process. */
void bgp_notify_conditional_adv_scanner(struct update_subgroup *subgrp)
{
	struct peer *temp_peer;
	struct peer *peer = SUBGRP_PEER(subgrp);
	struct listnode *temp_node, *temp_nnode = NULL;
	afi_t afi = SUBGRP_AFI(subgrp);
	safi_t safi = SUBGRP_SAFI(subgrp);
	struct bgp *bgp = SUBGRP_INST(subgrp);
	struct bgp_filter *filter = &peer->filter[afi][safi];

	if (!ADVERTISE_MAP_NAME(filter))
		return;

	for (ALL_LIST_ELEMENTS(bgp->peer, temp_node, temp_nnode, temp_peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (peer != temp_peer)
			continue;

		temp_peer->advmap_table_change = true;
		break;
	}
}


void subgroup_announce_reset_nhop(uint8_t family, struct attr *attr)
{
	if (family == AF_INET) {
		attr->nexthop.s_addr = INADDR_ANY;
		attr->mp_nexthop_global_in.s_addr = INADDR_ANY;
	}
	if (family == AF_INET6)
		memset(&attr->mp_nexthop_global, 0, IPV6_MAX_BYTELEN);
	if (family == AF_EVPN)
		memset(&attr->mp_nexthop_global_in, 0, BGP_ATTR_NHLEN_IPV4);
}

bool subgroup_announce_check(struct bgp_dest *dest, struct bgp_path_info *pi,
			     struct update_subgroup *subgrp,
			     const struct prefix *p, struct attr *attr,
			     bool skip_rmap_check)
{
	struct bgp_filter *filter;
	struct peer *from;
	struct peer *peer;
	struct peer *onlypeer;
	struct bgp *bgp;
	struct attr *piattr;
	route_map_result_t ret;
	int transparent;
	int reflect;
	afi_t afi;
	safi_t safi;
	int samepeer_safe = 0; /* for synthetic mplsvpns routes */
	bool nh_reset = false;
	uint64_t cum_bw;

	if (DISABLE_BGP_ANNOUNCE)
		return false;

	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	peer = SUBGRP_PEER(subgrp);
	onlypeer = NULL;
	if (CHECK_FLAG(peer->flags, PEER_FLAG_LONESOUL))
		onlypeer = SUBGRP_PFIRST(subgrp)->peer;

	from = pi->peer;
	filter = &peer->filter[afi][safi];
	bgp = SUBGRP_INST(subgrp);
	piattr = bgp_path_info_mpath_count(pi) ? bgp_path_info_mpath_attr(pi)
					       : pi->attr;

#ifdef ENABLE_BGP_VNC
	if (((afi == AFI_IP) || (afi == AFI_IP6)) && (safi == SAFI_MPLS_VPN)
	    && ((pi->type == ZEBRA_ROUTE_BGP_DIRECT)
		|| (pi->type == ZEBRA_ROUTE_BGP_DIRECT_EXT))) {

		/*
		 * direct and direct_ext type routes originate internally even
		 * though they can have peer pointers that reference other
		 * systems
		 */
		zlog_debug("%s: pfx %pFX bgp_direct->vpn route peer safe",
			   __func__, p);
		samepeer_safe = 1;
	}
#endif

	if (((afi == AFI_IP) || (afi == AFI_IP6))
	    && ((safi == SAFI_MPLS_VPN) || (safi == SAFI_UNICAST))
	    && (pi->type == ZEBRA_ROUTE_BGP)
	    && (pi->sub_type == BGP_ROUTE_IMPORTED)) {

		/* Applies to routes leaked vpn->vrf and vrf->vpn */

		samepeer_safe = 1;
	}

	/* With addpath we may be asked to TX all kinds of paths so make sure
	 * pi is valid */
	if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID)
	    || CHECK_FLAG(pi->flags, BGP_PATH_HISTORY)
	    || CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
		return false;
	}

	/* If this is not the bestpath then check to see if there is an enabled
	 * addpath
	 * feature that requires us to advertise it */
	if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
		if (!bgp_addpath_tx_path(peer->addpath_type[afi][safi], pi)) {
			return false;
		}
	}

	/* Aggregate-address suppress check. */
	if (bgp_path_suppressed(pi) && !UNSUPPRESS_MAP_NAME(filter))
		return false;

	/*
	 * If we are doing VRF 2 VRF leaking via the import
	 * statement, we want to prevent the route going
	 * off box as that the RT and RD created are localy
	 * significant and globaly useless.
	 */
	if (safi == SAFI_MPLS_VPN && pi->extra && pi->extra->num_labels
	    && pi->extra->label[0] == BGP_PREVENT_VRF_2_VRF_LEAK)
		return false;

	/* If it's labeled safi, make sure the route has a valid label. */
	if (safi == SAFI_LABELED_UNICAST) {
		mpls_label_t label = bgp_adv_label(dest, pi, peer, afi, safi);
		if (!bgp_is_valid_label(&label)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug("u%" PRIu64 ":s%" PRIu64
					   " %pFX is filtered - no label (%p)",
					   subgrp->update_group->id, subgrp->id,
					   p, &label);
			return false;
		}
	}

	/* Do not send back route to sender. */
	if (onlypeer && from == onlypeer) {
		return false;
	}

	/* Do not send the default route in the BGP table if the neighbor is
	 * configured for default-originate */
	if (CHECK_FLAG(peer->af_flags[afi][safi],
		       PEER_FLAG_DEFAULT_ORIGINATE)) {
		if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
			return false;
		else if (p->family == AF_INET6 && p->prefixlen == 0)
			return false;
	}

	/* Transparency check. */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT)
	    && CHECK_FLAG(from->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
		transparent = 1;
	else
		transparent = 0;

	/* If community is not disabled check the no-export and local. */
	if (!transparent && bgp_community_filter(peer, piattr)) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug("%s: community filter check fail", __func__);
		return false;
	}

	/* If the attribute has originator-id and it is same as remote
	   peer's id. */
	if (onlypeer && piattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)
	    && (IPV4_ADDR_SAME(&onlypeer->remote_id, &piattr->originator_id))) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug(
				"%s [Update:SEND] %pFX originator-id is same as remote router-id",
				onlypeer->host, p);
		return false;
	}

	/* ORF prefix-list filter check */
	if (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
	    && (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
		|| CHECK_FLAG(peer->af_cap[afi][safi],
			      PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
		if (peer->orf_plist[afi][safi]) {
			if (prefix_list_apply(peer->orf_plist[afi][safi], p)
			    == PREFIX_DENY) {
				if (bgp_debug_update(NULL, p,
						     subgrp->update_group, 0))
					zlog_debug(
						"%s [Update:SEND] %pFX is filtered via ORF",
						peer->host, p);
				return false;
			}
		}

	/* Output filter check. */
	if (bgp_output_filter(peer, p, piattr, afi, safi) == FILTER_DENY) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug("%s [Update:SEND] %pFX is filtered",
				   peer->host, p);
		return false;
	}

	/* AS path loop check. */
	if (onlypeer && onlypeer->as_path_loop_detection
	    && aspath_loop_check(piattr->aspath, onlypeer->as)) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug(
				"%s [Update:SEND] suppress announcement to peer AS %u that is part of AS path.",
				onlypeer->host, onlypeer->as);
		return false;
	}

	/* If we're a CONFED we need to loop check the CONFED ID too */
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		if (aspath_loop_check(piattr->aspath, bgp->confed_id)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
					peer->host, bgp->confed_id);
			return false;
		}
	}

	/* Route-Reflect check. */
	if (from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
		reflect = 1;
	else
		reflect = 0;

	/* IBGP reflection check. */
	if (reflect && !samepeer_safe) {
		/* A route from a Client peer. */
		if (CHECK_FLAG(from->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT)) {
			/* Reflect to all the Non-Client peers and also to the
			   Client peers other than the originator.  Originator
			   check
			   is already done.  So there is noting to do. */
			/* no bgp client-to-client reflection check. */
			if (CHECK_FLAG(bgp->flags,
				       BGP_FLAG_NO_CLIENT_TO_CLIENT))
				if (CHECK_FLAG(peer->af_flags[afi][safi],
					       PEER_FLAG_REFLECTOR_CLIENT))
					return false;
		} else {
			/* A route from a Non-client peer. Reflect to all other
			   clients. */
			if (!CHECK_FLAG(peer->af_flags[afi][safi],
					PEER_FLAG_REFLECTOR_CLIENT))
				return false;
		}
	}

	/* For modify attribute, copy it to temporary structure. */
	*attr = *piattr;

	/* If local-preference is not set. */
	if ((peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED)
	    && (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))) {
		attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
		attr->local_pref = bgp->default_local_pref;
	}

	/* If originator-id is not set and the route is to be reflected,
	   set the originator id */
	if (reflect
	    && (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))) {
		IPV4_ADDR_COPY(&(attr->originator_id), &(from->remote_id));
		SET_FLAG(attr->flag, BGP_ATTR_ORIGINATOR_ID);
	}

	/* Remove MED if its an EBGP peer - will get overwritten by route-maps
	 */
	if (peer->sort == BGP_PEER_EBGP
	    && attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) {
		if (from != bgp->peer_self && !transparent
		    && !CHECK_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_MED_UNCHANGED))
			attr->flag &=
				~(ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC));
	}

	/* Since the nexthop attribute can vary per peer, it is not explicitly
	 * set
	 * in announce check, only certain flags and length (or number of
	 * nexthops
	 * -- for IPv6/MP_REACH) are set here in order to guide the update
	 * formation
	 * code in setting the nexthop(s) on a per peer basis in
	 * reformat_peer().
	 * Typically, the source nexthop in the attribute is preserved but in
	 * the
	 * scenarios where we know it will always be overwritten, we reset the
	 * nexthop to "0" in an attempt to achieve better Update packing. An
	 * example of this is when a prefix from each of 2 IBGP peers needs to
	 * be
	 * announced to an EBGP peer (and they have the same attributes barring
	 * their nexthop).
	 */
	if (reflect)
		SET_FLAG(attr->rmap_change_flags, BATTR_REFLECTED);

#define NEXTHOP_IS_V6                                                          \
	((safi != SAFI_ENCAP && safi != SAFI_MPLS_VPN                          \
	  && (p->family == AF_INET6 || peer_cap_enhe(peer, afi, safi)))        \
	 || ((safi == SAFI_ENCAP || safi == SAFI_MPLS_VPN)                     \
	     && attr->mp_nexthop_len >= IPV6_MAX_BYTELEN))

	/* IPv6/MP starts with 1 nexthop. The link-local address is passed only
	 * if
	 * the peer (group) is configured to receive link-local nexthop
	 * unchanged
	 * and it is available in the prefix OR we're not reflecting the route,
	 * link-local nexthop address is valid and
	 * the peer (group) to whom we're going to announce is on a shared
	 * network
	 * and this is either a self-originated route or the peer is EBGP.
	 * By checking if nexthop LL address is valid we are sure that
	 * we do not announce LL address as `::`.
	 */
	if (NEXTHOP_IS_V6) {
		attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
		if ((CHECK_FLAG(peer->af_flags[afi][safi],
				PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)
		     && IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_local))
		    || (!reflect
			&& IN6_IS_ADDR_LINKLOCAL(&peer->nexthop.v6_local)
			&& peer->shared_network
			&& (from == bgp->peer_self
			    || peer->sort == BGP_PEER_EBGP))) {
			attr->mp_nexthop_len =
				BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
		}

		/* Clear off link-local nexthop in source, whenever it is not
		 * needed to
		 * ensure more prefixes share the same attribute for
		 * announcement.
		 */
		if (!(CHECK_FLAG(peer->af_flags[afi][safi],
				 PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)))
			memset(&attr->mp_nexthop_local, 0, IPV6_MAX_BYTELEN);
	}

	bgp_peer_remove_private_as(bgp, afi, safi, peer, attr);
	bgp_peer_as_override(bgp, afi, safi, peer, attr);

	/* Route map & unsuppress-map apply. */
	if (!skip_rmap_check
	    && (ROUTE_MAP_OUT_NAME(filter) || bgp_path_suppressed(pi))) {
		struct bgp_path_info rmap_path = {0};
		struct bgp_path_info_extra dummy_rmap_path_extra = {0};
		struct attr dummy_attr = {0};

		/* Fill temp path_info */
		prep_for_rmap_apply(&rmap_path, &dummy_rmap_path_extra, dest,
				    pi, peer, attr);

		/* don't confuse inbound and outbound setting */
		RESET_FLAG(attr->rmap_change_flags);

		/*
		 * The route reflector is not allowed to modify the attributes
		 * of the reflected IBGP routes unless explicitly allowed.
		 */
		if ((from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
		    && !CHECK_FLAG(bgp->flags,
				   BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
			dummy_attr = *attr;
			rmap_path.attr = &dummy_attr;
		}

		SET_FLAG(peer->rmap_type, PEER_RMAP_TYPE_OUT);

		if (bgp_path_suppressed(pi))
			ret = route_map_apply(UNSUPPRESS_MAP(filter), p,
					      &rmap_path);
		else
			ret = route_map_apply(ROUTE_MAP_OUT(filter), p,
					      &rmap_path);

		peer->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%s [Update:SEND] %pFX is filtered by route-map",
					peer->host, p);

			bgp_attr_flush(attr);
			return false;
		}
	}

	/* RFC 8212 to prevent route leaks.
	 * This specification intends to improve this situation by requiring the
	 * explicit configuration of both BGP Import and Export Policies for any
	 * External BGP (EBGP) session such as customers, peers, or
	 * confederation boundaries for all enabled address families. Through
	 * codification of the aforementioned requirement, operators will
	 * benefit from consistent behavior across different BGP
	 * implementations.
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY))
		if (!bgp_outbound_policy_exists(peer, filter))
			return false;

	/* draft-ietf-idr-deprecate-as-set-confed-set
	 * Filter routes having AS_SET or AS_CONFED_SET in the path.
	 * Eventually, This document (if approved) updates RFC 4271
	 * and RFC 5065 by eliminating AS_SET and AS_CONFED_SET types,
	 * and obsoletes RFC 6472.
	 */
	if (peer->bgp->reject_as_sets)
		if (aspath_check_as_sets(attr->aspath))
			return false;

	/* Codification of AS 0 Processing */
	if (aspath_check_as_zero(attr->aspath))
		return false;

	if (bgp_in_graceful_shutdown(bgp)) {
		if (peer->sort == BGP_PEER_IBGP
		    || peer->sort == BGP_PEER_CONFED) {
			attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
			attr->local_pref = BGP_GSHUT_LOCAL_PREF;
		} else {
			bgp_attr_add_gshut_community(attr);
		}
	}

	/* After route-map has been applied, we check to see if the nexthop to
	 * be carried in the attribute (that is used for the announcement) can
	 * be cleared off or not. We do this in all cases where we would be
	 * setting the nexthop to "ourselves". For IPv6, we only need to
	 * consider
	 * the global nexthop here; the link-local nexthop would have been
	 * cleared
	 * already, and if not, it is required by the update formation code.
	 * Also see earlier comments in this function.
	 */
	/*
	 * If route-map has performed some operation on the nexthop or the peer
	 * configuration says to pass it unchanged, we cannot reset the nexthop
	 * here, so only attempt to do it if these aren't true. Note that the
	 * route-map handler itself might have cleared the nexthop, if for
	 * example,
	 * it is configured as 'peer-address'.
	 */
	if (!bgp_rmap_nhop_changed(attr->rmap_change_flags,
				   piattr->rmap_change_flags)
	    && !transparent
	    && !CHECK_FLAG(peer->af_flags[afi][safi],
			   PEER_FLAG_NEXTHOP_UNCHANGED)) {
		/* We can reset the nexthop, if setting (or forcing) it to
		 * 'self' */
		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(peer->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF)) {
			if (!reflect
			    || CHECK_FLAG(peer->af_flags[afi][safi],
					  PEER_FLAG_FORCE_NEXTHOP_SELF)) {
				subgroup_announce_reset_nhop(
					(peer_cap_enhe(peer, afi, safi)
						 ? AF_INET6
						 : p->family),
					attr);
				nh_reset = true;
			}
		} else if (peer->sort == BGP_PEER_EBGP) {
			/* Can also reset the nexthop if announcing to EBGP, but
			 * only if
			 * no peer in the subgroup is on a shared subnet.
			 * Note: 3rd party nexthop currently implemented for
			 * IPv4 only.
			 */
			if ((p->family == AF_INET) &&
				(!bgp_subgrp_multiaccess_check_v4(
					piattr->nexthop,
					subgrp, from))) {
				subgroup_announce_reset_nhop(
					(peer_cap_enhe(peer, afi, safi)
						 ? AF_INET6
						 : p->family),
						attr);
				nh_reset = true;
			}

			if ((p->family == AF_INET6) &&
				(!bgp_subgrp_multiaccess_check_v6(
					piattr->mp_nexthop_global,
					subgrp, from))) {
				subgroup_announce_reset_nhop(
					(peer_cap_enhe(peer, afi, safi)
						? AF_INET6
						: p->family),
						attr);
				nh_reset = true;
			}



		} else if (CHECK_FLAG(pi->flags, BGP_PATH_ANNC_NH_SELF)) {
			/*
			 * This flag is used for leaked vpn-vrf routes
			 */
			int family = p->family;

			if (peer_cap_enhe(peer, afi, safi))
				family = AF_INET6;

			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%s: BGP_PATH_ANNC_NH_SELF, family=%s",
					__func__, family2str(family));
			subgroup_announce_reset_nhop(family, attr);
			nh_reset = true;
		}
	}

	/* If IPv6/MP and nexthop does not have any override and happens
	 * to
	 * be a link-local address, reset it so that we don't pass along
	 * the
	 * source's link-local IPv6 address to recipients who may not be
	 * on
	 * the same interface.
	 */
	if (p->family == AF_INET6 || peer_cap_enhe(peer, afi, safi)) {
		if (IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_global)) {
			subgroup_announce_reset_nhop(AF_INET6, attr);
				nh_reset = true;
			}
	}

	/*
	 * When the next hop is set to ourselves, if all multipaths have
	 * link-bandwidth announce the cumulative bandwidth as that makes
	 * the most sense. However, don't modify if the link-bandwidth has
	 * been explicitly set by user policy.
	 */
	if (nh_reset &&
	    bgp_path_info_mpath_chkwtd(bgp, pi) &&
	    (cum_bw = bgp_path_info_mpath_cumbw(pi)) != 0 &&
	    !CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_LINK_BW_SET))
		attr->ecommunity = ecommunity_replace_linkbw(
					bgp->as, attr->ecommunity, cum_bw);

	return true;
}

static int bgp_route_select_timer_expire(struct thread *thread)
{
	struct afi_safi_info *info;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;

	info = THREAD_ARG(thread);
	afi = info->afi;
	safi = info->safi;
	bgp = info->bgp;

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("afi %d, safi %d : route select timer expired", afi,
			   safi);

	bgp->gr_info[afi][safi].t_route_select = NULL;

	XFREE(MTYPE_TMP, info);

	/* Best path selection */
	return bgp_best_path_select_defer(bgp, afi, safi);
}

void bgp_best_selection(struct bgp *bgp, struct bgp_dest *dest,
			struct bgp_maxpaths_cfg *mpath_cfg,
			struct bgp_path_info_pair *result, afi_t afi,
			safi_t safi)
{
	struct bgp_path_info *new_select;
	struct bgp_path_info *old_select;
	struct bgp_path_info *pi;
	struct bgp_path_info *pi1;
	struct bgp_path_info *pi2;
	struct bgp_path_info *nextpi = NULL;
	int paths_eq, do_mpath, debug;
	struct list mp_list;
	char pfx_buf[PREFIX2STR_BUFFER];
	char path_buf[PATH_ADDPATH_STR_BUFFER];

	bgp_mp_list_init(&mp_list);
	do_mpath =
		(mpath_cfg->maxpaths_ebgp > 1 || mpath_cfg->maxpaths_ibgp > 1);

	debug = bgp_debug_bestpath(dest);

	if (debug)
		prefix2str(bgp_dest_get_prefix(dest), pfx_buf, sizeof(pfx_buf));

	dest->reason = bgp_path_selection_none;
	/* bgp deterministic-med */
	new_select = NULL;
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {

		/* Clear BGP_PATH_DMED_SELECTED for all paths */
		for (pi1 = bgp_dest_get_bgp_path_info(dest); pi1;
		     pi1 = pi1->next)
			bgp_path_info_unset_flag(dest, pi1,
						 BGP_PATH_DMED_SELECTED);

		for (pi1 = bgp_dest_get_bgp_path_info(dest); pi1;
		     pi1 = pi1->next) {
			if (CHECK_FLAG(pi1->flags, BGP_PATH_DMED_CHECK))
				continue;
			if (BGP_PATH_HOLDDOWN(pi1))
				continue;
			if (pi1->peer != bgp->peer_self)
				if (pi1->peer->status != Established)
					continue;

			new_select = pi1;
			if (pi1->next) {
				for (pi2 = pi1->next; pi2; pi2 = pi2->next) {
					if (CHECK_FLAG(pi2->flags,
						       BGP_PATH_DMED_CHECK))
						continue;
					if (BGP_PATH_HOLDDOWN(pi2))
						continue;
					if (pi2->peer != bgp->peer_self
					    && !CHECK_FLAG(
						    pi2->peer->sflags,
						    PEER_STATUS_NSF_WAIT))
						if (pi2->peer->status
						    != Established)
							continue;

					if (!aspath_cmp_left(pi1->attr->aspath,
							     pi2->attr->aspath)
					    && !aspath_cmp_left_confed(
						       pi1->attr->aspath,
						       pi2->attr->aspath))
						continue;

					if (bgp_path_info_cmp(
						    bgp, pi2, new_select,
						    &paths_eq, mpath_cfg, debug,
						    pfx_buf, afi, safi,
						    &dest->reason)) {
						bgp_path_info_unset_flag(
							dest, new_select,
							BGP_PATH_DMED_SELECTED);
						new_select = pi2;
					}

					bgp_path_info_set_flag(
						dest, pi2, BGP_PATH_DMED_CHECK);
				}
			}
			bgp_path_info_set_flag(dest, new_select,
					       BGP_PATH_DMED_CHECK);
			bgp_path_info_set_flag(dest, new_select,
					       BGP_PATH_DMED_SELECTED);

			if (debug) {
				bgp_path_info_path_with_addpath_rx_str(
					new_select, path_buf);
				zlog_debug(
					"%pBD: %s is the bestpath from AS %u",
					dest, path_buf,
					aspath_get_first_as(
						new_select->attr->aspath));
			}
		}
	}

	/* Check old selected route and new selected route. */
	old_select = NULL;
	new_select = NULL;
	for (pi = bgp_dest_get_bgp_path_info(dest);
	     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
		enum bgp_path_selection_reason reason;

		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			old_select = pi;

		if (BGP_PATH_HOLDDOWN(pi)) {
			/* reap REMOVED routes, if needs be
			 * selected route must stay for a while longer though
			 */
			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)
			    && (pi != old_select))
				bgp_path_info_reap(dest, pi);

			if (debug)
				zlog_debug("%s: pi %p in holddown", __func__,
					   pi);

			continue;
		}

		if (pi->peer && pi->peer != bgp->peer_self
		    && !CHECK_FLAG(pi->peer->sflags, PEER_STATUS_NSF_WAIT))
			if (pi->peer->status != Established) {

				if (debug)
					zlog_debug(
						"%s: pi %p non self peer %s not estab state",
						__func__, pi, pi->peer->host);

				continue;
			}

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)
		    && (!CHECK_FLAG(pi->flags, BGP_PATH_DMED_SELECTED))) {
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_DMED_CHECK);
			if (debug)
				zlog_debug("%s: pi %p dmed", __func__, pi);
			continue;
		}

		bgp_path_info_unset_flag(dest, pi, BGP_PATH_DMED_CHECK);

		reason = dest->reason;
		if (bgp_path_info_cmp(bgp, pi, new_select, &paths_eq, mpath_cfg,
				      debug, pfx_buf, afi, safi,
				      &dest->reason)) {
			if (new_select == NULL &&
			    reason != bgp_path_selection_none)
				dest->reason = reason;
			new_select = pi;
		}
	}

	/* Now that we know which path is the bestpath see if any of the other
	 * paths
	 * qualify as multipaths
	 */
	if (debug) {
		if (new_select)
			bgp_path_info_path_with_addpath_rx_str(new_select,
							       path_buf);
		else
			snprintf(path_buf, sizeof(path_buf), "NONE");
		zlog_debug(
			"%pBD: After path selection, newbest is %s oldbest was %s",
			dest, path_buf,
			old_select ? old_select->peer->host : "NONE");
	}

	if (do_mpath && new_select) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {

			if (debug)
				bgp_path_info_path_with_addpath_rx_str(
					pi, path_buf);

			if (pi == new_select) {
				if (debug)
					zlog_debug(
						"%pBD: %s is the bestpath, add to the multipath list",
						dest, path_buf);
				bgp_mp_list_add(&mp_list, pi);
				continue;
			}

			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (pi->peer && pi->peer != bgp->peer_self
			    && !CHECK_FLAG(pi->peer->sflags,
					   PEER_STATUS_NSF_WAIT))
				if (pi->peer->status != Established)
					continue;

			if (!bgp_path_info_nexthop_cmp(pi, new_select)) {
				if (debug)
					zlog_debug(
						"%pBD: %s has the same nexthop as the bestpath, skip it",
						dest, path_buf);
				continue;
			}

			bgp_path_info_cmp(bgp, pi, new_select, &paths_eq,
					  mpath_cfg, debug, pfx_buf, afi, safi,
					  &dest->reason);

			if (paths_eq) {
				if (debug)
					zlog_debug(
						"%pBD: %s is equivalent to the bestpath, add to the multipath list",
						dest, path_buf);
				bgp_mp_list_add(&mp_list, pi);
			}
		}
	}

	bgp_path_info_mpath_update(dest, new_select, old_select, &mp_list,
				   mpath_cfg);
	bgp_path_info_mpath_aggregate_update(new_select, old_select);
	bgp_mp_list_clear(&mp_list);

	bgp_addpath_update_ids(bgp, dest, afi, safi);

	result->old = old_select;
	result->new = new_select;

	return;
}

/*
 * A new route/change in bestpath of an existing route. Evaluate the path
 * for advertisement to the subgroup.
 */
void subgroup_process_announce_selected(struct update_subgroup *subgrp,
					struct bgp_path_info *selected,
					struct bgp_dest *dest,
					uint32_t addpath_tx_id)
{
	const struct prefix *p;
	struct peer *onlypeer;
	struct attr attr;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;
	bool advertise;

	p = bgp_dest_get_prefix(dest);
	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	bgp = SUBGRP_INST(subgrp);
	onlypeer = ((SUBGRP_PCOUNT(subgrp) == 1) ? (SUBGRP_PFIRST(subgrp))->peer
						 : NULL);

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("%s: p=%pFX, selected=%p", __func__, p, selected);

	/* First update is deferred until ORF or ROUTE-REFRESH is received */
	if (onlypeer && CHECK_FLAG(onlypeer->af_sflags[afi][safi],
				   PEER_STATUS_ORF_WAIT_REFRESH))
		return;

	memset(&attr, 0, sizeof(struct attr));
	/* It's initialized in bgp_announce_check() */

	/* Announcement to the subgroup. If the route is filtered withdraw it.
	 * If BGP_NODE_FIB_INSTALL_PENDING is set and data plane install status
	 * is pending (BGP_NODE_FIB_INSTALL_PENDING), do not advertise the
	 * route
	 */
	advertise = bgp_check_advertise(bgp, dest);

	if (selected) {
		if (subgroup_announce_check(dest, selected, subgrp, p, &attr,
					    false)) {
			/* Route is selected, if the route is already installed
			 * in FIB, then it is advertised
			 */
			if (advertise)
				bgp_adj_out_set_subgroup(dest, subgrp, &attr,
							 selected);
		} else
			bgp_adj_out_unset_subgroup(dest, subgrp, 1,
						   addpath_tx_id);
	}

	/* If selected is NULL we must withdraw the path using addpath_tx_id */
	else {
		bgp_adj_out_unset_subgroup(dest, subgrp, 1, addpath_tx_id);
	}
}

/*
 * Clear IGP changed flag and attribute changed flag for a route (all paths).
 * This is called at the end of route processing.
 */
void bgp_zebra_clear_route_change_flags(struct bgp_dest *dest)
{
	struct bgp_path_info *pi;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (BGP_PATH_HOLDDOWN(pi))
			continue;
		UNSET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);
		UNSET_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED);
	}
}

/*
 * Has the route changed from the RIB's perspective? This is invoked only
 * if the route selection returns the same best route as earlier - to
 * determine if we need to update zebra or not.
 */
bool bgp_zebra_has_route_changed(struct bgp_path_info *selected)
{
	struct bgp_path_info *mpinfo;

	/* If this is multipath, check all selected paths for any nexthop
	 * change or attribute change. Some attribute changes (e.g., community)
	 * aren't of relevance to the RIB, but we'll update zebra to ensure
	 * we handle the case of BGP nexthop change. This is the behavior
	 * when the best path has an attribute change anyway.
	 */
	if (CHECK_FLAG(selected->flags, BGP_PATH_IGP_CHANGED)
	    || CHECK_FLAG(selected->flags, BGP_PATH_MULTIPATH_CHG)
	    || CHECK_FLAG(selected->flags, BGP_PATH_LINK_BW_CHG))
		return true;

	/*
	 * If this is multipath, check all selected paths for any nexthop change
	 */
	for (mpinfo = bgp_path_info_mpath_first(selected); mpinfo;
	     mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		if (CHECK_FLAG(mpinfo->flags, BGP_PATH_IGP_CHANGED)
		    || CHECK_FLAG(mpinfo->flags, BGP_PATH_ATTR_CHANGED))
			return true;
	}

	/* Nothing has changed from the RIB's perspective. */
	return false;
}

struct bgp_process_queue {
	struct bgp *bgp;
	STAILQ_HEAD(, bgp_dest) pqueue;
#define BGP_PROCESS_QUEUE_EOIU_MARKER		(1 << 0)
	unsigned int flags;
	unsigned int queued;
};

static void bgp_process_evpn_route_injection(struct bgp *bgp, afi_t afi,
					     safi_t safi, struct bgp_dest *dest,
					     struct bgp_path_info *new_select,
					     struct bgp_path_info *old_select)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);

	if ((afi != AFI_IP && afi != AFI_IP6) || (safi != SAFI_UNICAST))
		return;

	if (advertise_type5_routes(bgp, afi) && new_select
	    && is_route_injectable_into_evpn(new_select)) {

		/* apply the route-map */
		if (bgp->adv_cmd_rmap[afi][safi].map) {
			route_map_result_t ret;
			struct bgp_path_info rmap_path;
			struct bgp_path_info_extra rmap_path_extra;
			struct attr dummy_attr;

			dummy_attr = *new_select->attr;

			/* Fill temp path_info */
			prep_for_rmap_apply(&rmap_path, &rmap_path_extra, dest,
					    new_select, new_select->peer,
					    &dummy_attr);

			RESET_FLAG(dummy_attr.rmap_change_flags);

			ret = route_map_apply(bgp->adv_cmd_rmap[afi][safi].map,
					      p, &rmap_path);

			if (ret == RMAP_DENYMATCH) {
				bgp_attr_flush(&dummy_attr);
				bgp_evpn_withdraw_type5_route(bgp, p, afi,
							      safi);
			} else
				bgp_evpn_advertise_type5_route(
					bgp, p, &dummy_attr, afi, safi);
		} else {
			bgp_evpn_advertise_type5_route(bgp, p, new_select->attr,
						       afi, safi);
		}
	} else if (advertise_type5_routes(bgp, afi) && old_select
		   && is_route_injectable_into_evpn(old_select))
		bgp_evpn_withdraw_type5_route(bgp, p, afi, safi);
}

/*
 * old_select = The old best path
 * new_select = the new best path
 *
 * if (!old_select && new_select)
 *     We are sending new information on.
 *
 * if (old_select && new_select) {
 *         if (new_select != old_select)
 *                 We have a new best path send a change
 *         else
 *                 We've received a update with new attributes that needs
 *                 to be passed on.
 * }
 *
 * if (old_select && !new_select)
 *     We have no eligible route that we can announce or the rn
 *     is being removed.
 */
static void bgp_process_main_one(struct bgp *bgp, struct bgp_dest *dest,
				 afi_t afi, safi_t safi)
{
	struct bgp_path_info *new_select;
	struct bgp_path_info *old_select;
	struct bgp_path_info_pair old_and_new;
	int debug = 0;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS)) {
		if (dest)
			debug = bgp_debug_bestpath(dest);
		if (debug)
			zlog_debug(
				"%s: bgp delete in progress, ignoring event, p=%pBD",
				__func__, dest);
		return;
	}
	/* Is it end of initial update? (after startup) */
	if (!dest) {
		quagga_timestamp(3, bgp->update_delay_zebra_resume_time,
				 sizeof(bgp->update_delay_zebra_resume_time));

		bgp->main_zebra_update_hold = 0;
		FOREACH_AFI_SAFI (afi, safi) {
			if (bgp_fibupd_safi(safi))
				bgp_zebra_announce_table(bgp, afi, safi);
		}
		bgp->main_peers_update_hold = 0;

		bgp_start_routeadv(bgp);
		return;
	}

	const struct prefix *p = bgp_dest_get_prefix(dest);

	debug = bgp_debug_bestpath(dest);
	if (debug)
		zlog_debug("%s: p=%pBD afi=%s, safi=%s start", __func__, dest,
			   afi2str(afi), safi2str(safi));

	/* The best path calculation for the route is deferred if
	 * BGP_NODE_SELECT_DEFER is set
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("SELECT_DEFER flag set for route %p", dest);
		return;
	}

	/* Best path selection. */
	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/* Do we need to allocate or free labels?
	 * Right now, since we only deal with per-prefix labels, it is not
	 * necessary to do this upon changes to best path. Exceptions:
	 * - label index has changed -> recalculate resulting label
	 * - path_info sub_type changed -> switch to/from implicit-null
	 * - no valid label (due to removed static label binding) -> get new one
	 */
	if (bgp->allocate_mpls_labels[afi][safi]) {
		if (new_select) {
			if (!old_select
			    || bgp_label_index_differs(new_select, old_select)
			    || new_select->sub_type != old_select->sub_type
			    || !bgp_is_valid_label(&dest->local_label)) {
				/* Enforced penultimate hop popping:
				 * implicit-null for local routes, aggregate
				 * and redistributed routes
				 */
				if (new_select->sub_type == BGP_ROUTE_STATIC
				    || new_select->sub_type
						== BGP_ROUTE_AGGREGATE
				    || new_select->sub_type
						== BGP_ROUTE_REDISTRIBUTE) {
					if (CHECK_FLAG(
						    dest->flags,
						    BGP_NODE_REGISTERED_FOR_LABEL)
					    || CHECK_FLAG(
						    dest->flags,
						    BGP_NODE_LABEL_REQUESTED))
						bgp_unregister_for_label(dest);
					label_ntop(MPLS_LABEL_IMPLICIT_NULL, 1,
						   &dest->local_label);
					bgp_set_valid_label(&dest->local_label);
				} else
					bgp_register_for_label(dest,
							       new_select);
			}
		} else if (CHECK_FLAG(dest->flags,
				      BGP_NODE_REGISTERED_FOR_LABEL)
			   || CHECK_FLAG(dest->flags,
					 BGP_NODE_LABEL_REQUESTED)) {
			bgp_unregister_for_label(dest);
		}
	} else if (CHECK_FLAG(dest->flags, BGP_NODE_REGISTERED_FOR_LABEL)
		   || CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED)) {
		bgp_unregister_for_label(dest);
	}

	if (debug)
		zlog_debug(
			"%s: p=%pBD afi=%s, safi=%s, old_select=%p, new_select=%p",
			__func__, dest, afi2str(afi), safi2str(safi),
			old_select, new_select);

	/* If best route remains the same and this is not due to user-initiated
	 * clear, see exactly what needs to be done.
	 */
	if (old_select && old_select == new_select
	    && !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		if (bgp_zebra_has_route_changed(old_select)) {
#ifdef ENABLE_BGP_VNC
			vnc_import_bgp_add_route(bgp, p, old_select);
			vnc_import_bgp_exterior_add_route(bgp, p, old_select);
#endif
			if (bgp_fibupd_safi(safi)
			    && !bgp_option_check(BGP_OPT_NO_FIB)) {

				if (new_select->type == ZEBRA_ROUTE_BGP
				    && (new_select->sub_type == BGP_ROUTE_NORMAL
					|| new_select->sub_type
						   == BGP_ROUTE_IMPORTED))

					bgp_zebra_announce(dest, p, old_select,
							   bgp, afi, safi);
			}
		}

		/* If there is a change of interest to peers, reannounce the
		 * route. */
		if (CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
		    || CHECK_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG)
		    || CHECK_FLAG(dest->flags, BGP_NODE_LABEL_CHANGED)) {
			group_announce_route(bgp, afi, safi, dest, new_select);

			/* unicast routes must also be annouced to
			 * labeled-unicast update-groups */
			if (safi == SAFI_UNICAST)
				group_announce_route(bgp, afi,
						     SAFI_LABELED_UNICAST, dest,
						     new_select);

			UNSET_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED);
			UNSET_FLAG(dest->flags, BGP_NODE_LABEL_CHANGED);
		}

		/* advertise/withdraw type-5 routes */
		if (CHECK_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG)
		    || CHECK_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG))
			bgp_process_evpn_route_injection(
				bgp, afi, safi, dest, old_select, old_select);

		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG);
		bgp_zebra_clear_route_change_flags(dest);
		UNSET_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED);
		return;
	}

	/* If the user did "clear ip bgp prefix x.x.x.x" this flag will be set
	 */
	UNSET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);

	/* bestpath has changed; bump version */
	if (old_select || new_select) {
		bgp_bump_version(dest);

		if (!bgp->t_rmap_def_originate_eval) {
			bgp_lock(bgp);
			thread_add_timer(
				bm->master,
				update_group_refresh_default_originate_route_map,
				bgp, RMAP_DEFAULT_ORIGINATE_EVAL_TIMER,
				&bgp->t_rmap_def_originate_eval);
		}
	}

	if (old_select)
		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		if (debug)
			zlog_debug("%s: setting SELECTED flag", __func__);
		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(dest, new_select,
					 BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(new_select->flags, BGP_PATH_LINK_BW_CHG);
	}

#ifdef ENABLE_BGP_VNC
	if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) {
		if (old_select != new_select) {
			if (old_select) {
				vnc_import_bgp_exterior_del_route(bgp, p,
								  old_select);
				vnc_import_bgp_del_route(bgp, p, old_select);
			}
			if (new_select) {
				vnc_import_bgp_exterior_add_route(bgp, p,
								  new_select);
				vnc_import_bgp_add_route(bgp, p, new_select);
			}
		}
	}
#endif

	group_announce_route(bgp, afi, safi, dest, new_select);

	/* unicast routes must also be annouced to labeled-unicast update-groups
	 */
	if (safi == SAFI_UNICAST)
		group_announce_route(bgp, afi, SAFI_LABELED_UNICAST, dest,
				     new_select);

	/* FIB update. */
	if (bgp_fibupd_safi(safi) && (bgp->inst_type != BGP_INSTANCE_TYPE_VIEW)
	    && !bgp_option_check(BGP_OPT_NO_FIB)) {
		if (new_select && new_select->type == ZEBRA_ROUTE_BGP
		    && (new_select->sub_type == BGP_ROUTE_NORMAL
			|| new_select->sub_type == BGP_ROUTE_AGGREGATE
			|| new_select->sub_type == BGP_ROUTE_IMPORTED)) {

			/* if this is an evpn imported type-5 prefix,
			 * we need to withdraw the route first to clear
			 * the nh neigh and the RMAC entry.
			 */
			if (old_select &&
			    is_route_parent_evpn(old_select))
				bgp_zebra_withdraw(p, old_select, bgp, safi);

			bgp_zebra_announce(dest, p, new_select, bgp, afi, safi);
		} else {
			/* Withdraw the route from the kernel. */
			if (old_select && old_select->type == ZEBRA_ROUTE_BGP
			    && (old_select->sub_type == BGP_ROUTE_NORMAL
				|| old_select->sub_type == BGP_ROUTE_AGGREGATE
				|| old_select->sub_type == BGP_ROUTE_IMPORTED))

				bgp_zebra_withdraw(p, old_select, bgp, safi);
		}
	}

	bgp_process_evpn_route_injection(bgp, afi, safi, dest, new_select,
					 old_select);

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(dest);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(dest, old_select);

	UNSET_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED);
	return;
}

/* Process the routes with the flag BGP_NODE_SELECT_DEFER set */
int bgp_best_path_select_defer(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	int cnt = 0;
	struct afi_safi_info *thread_info;

	if (bgp->gr_info[afi][safi].t_route_select) {
		struct thread *t = bgp->gr_info[afi][safi].t_route_select;

		thread_info = THREAD_ARG(t);
		XFREE(MTYPE_TMP, thread_info);
		BGP_TIMER_OFF(bgp->gr_info[afi][safi].t_route_select);
	}

	if (BGP_DEBUG(update, UPDATE_OUT)) {
		zlog_debug("%s: processing route for %s : cnt %d", __func__,
			   get_afi_safi_str(afi, safi, false),
			   bgp->gr_info[afi][safi].gr_deferred);
	}

	/* Process the route list */
	for (dest = bgp_table_top(bgp->rib[afi][safi]);
	     dest && bgp->gr_info[afi][safi].gr_deferred != 0;
	     dest = bgp_route_next(dest)) {
		if (!CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER))
			continue;

		UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
		bgp->gr_info[afi][safi].gr_deferred--;
		bgp_process_main_one(bgp, dest, afi, safi);
		cnt++;
		if (cnt >= BGP_MAX_BEST_ROUTE_SELECT) {
			bgp_dest_unlock_node(dest);
			break;
		}
	}

	/* Send EOR message when all routes are processed */
	if (!bgp->gr_info[afi][safi].gr_deferred) {
		bgp_send_delayed_eor(bgp);
		/* Send route processing complete message to RIB */
		bgp_zebra_update(afi, safi, bgp->vrf_id,
				 ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE);
		return 0;
	}

	thread_info = XMALLOC(MTYPE_TMP, sizeof(struct afi_safi_info));

	thread_info->afi = afi;
	thread_info->safi = safi;
	thread_info->bgp = bgp;

	/* If there are more routes to be processed, start the
	 * selection timer
	 */
	thread_add_timer(bm->master, bgp_route_select_timer_expire, thread_info,
			BGP_ROUTE_SELECT_DELAY,
			&bgp->gr_info[afi][safi].t_route_select);
	return 0;
}

static wq_item_status bgp_process_wq(struct work_queue *wq, void *data)
{
	struct bgp_process_queue *pqnode = data;
	struct bgp *bgp = pqnode->bgp;
	struct bgp_table *table;
	struct bgp_dest *dest;

	/* eoiu marker */
	if (CHECK_FLAG(pqnode->flags, BGP_PROCESS_QUEUE_EOIU_MARKER)) {
		bgp_process_main_one(bgp, NULL, 0, 0);
		/* should always have dedicated wq call */
		assert(STAILQ_FIRST(&pqnode->pqueue) == NULL);
		return WQ_SUCCESS;
	}

	while (!STAILQ_EMPTY(&pqnode->pqueue)) {
		dest = STAILQ_FIRST(&pqnode->pqueue);
		STAILQ_REMOVE_HEAD(&pqnode->pqueue, pq);
		STAILQ_NEXT(dest, pq) = NULL; /* complete unlink */
		table = bgp_dest_table(dest);
		/* note, new DESTs may be added as part of processing */
		bgp_process_main_one(bgp, dest, table->afi, table->safi);

		bgp_dest_unlock_node(dest);
		bgp_table_unlock(table);
	}

	return WQ_SUCCESS;
}

static void bgp_processq_del(struct work_queue *wq, void *data)
{
	struct bgp_process_queue *pqnode = data;

	bgp_unlock(pqnode->bgp);

	XFREE(MTYPE_BGP_PROCESS_QUEUE, pqnode);
}

void bgp_process_queue_init(struct bgp *bgp)
{
	if (!bgp->process_queue) {
		char name[BUFSIZ];

		snprintf(name, BUFSIZ, "process_queue %s", bgp->name_pretty);
		bgp->process_queue = work_queue_new(bm->master, name);
	}

	bgp->process_queue->spec.workfunc = &bgp_process_wq;
	bgp->process_queue->spec.del_item_data = &bgp_processq_del;
	bgp->process_queue->spec.max_retries = 0;
	bgp->process_queue->spec.hold = 50;
	/* Use a higher yield value of 50ms for main queue processing */
	bgp->process_queue->spec.yield = 50 * 1000L;
}

static struct bgp_process_queue *bgp_processq_alloc(struct bgp *bgp)
{
	struct bgp_process_queue *pqnode;

	pqnode = XCALLOC(MTYPE_BGP_PROCESS_QUEUE,
			 sizeof(struct bgp_process_queue));

	/* unlocked in bgp_processq_del */
	pqnode->bgp = bgp_lock(bgp);
	STAILQ_INIT(&pqnode->pqueue);

	return pqnode;
}

void bgp_process(struct bgp *bgp, struct bgp_dest *dest, afi_t afi, safi_t safi)
{
#define ARBITRARY_PROCESS_QLEN		10000
	struct work_queue *wq = bgp->process_queue;
	struct bgp_process_queue *pqnode;
	int pqnode_reuse = 0;

	/* already scheduled for processing? */
	if (CHECK_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED))
		return;

	/* If the flag BGP_NODE_SELECT_DEFER is set, do not add route to
	 * the workqueue
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("BGP_NODE_SELECT_DEFER set for route %p",
				   dest);
		return;
	}

	if (wq == NULL)
		return;

	/* Add route nodes to an existing work queue item until reaching the
	   limit only if is from the same BGP view and it's not an EOIU marker
	 */
	if (work_queue_item_count(wq)) {
		struct work_queue_item *item = work_queue_last_item(wq);
		pqnode = item->data;

		if (CHECK_FLAG(pqnode->flags, BGP_PROCESS_QUEUE_EOIU_MARKER)
		    || pqnode->bgp != bgp
		    || pqnode->queued >= ARBITRARY_PROCESS_QLEN)
			pqnode = bgp_processq_alloc(bgp);
		else
			pqnode_reuse = 1;
	} else
		pqnode = bgp_processq_alloc(bgp);
	/* all unlocked in bgp_process_wq */
	bgp_table_lock(bgp_dest_table(dest));

	SET_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED);
	bgp_dest_lock_node(dest);

	/* can't be enqueued twice */
	assert(STAILQ_NEXT(dest, pq) == NULL);
	STAILQ_INSERT_TAIL(&pqnode->pqueue, dest, pq);
	pqnode->queued++;

	if (!pqnode_reuse)
		work_queue_add(wq, pqnode);

	return;
}

void bgp_add_eoiu_mark(struct bgp *bgp)
{
	struct bgp_process_queue *pqnode;

	if (bgp->process_queue == NULL)
		return;

	pqnode = bgp_processq_alloc(bgp);

	SET_FLAG(pqnode->flags, BGP_PROCESS_QUEUE_EOIU_MARKER);
	work_queue_add(bgp->process_queue, pqnode);
}

static int bgp_maximum_prefix_restart_timer(struct thread *thread)
{
	struct peer *peer;

	peer = THREAD_ARG(thread);
	peer->t_pmax_restart = NULL;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug(
			"%s Maximum-prefix restart timer expired, restore peering",
			peer->host);

	if ((peer_clear(peer, NULL) < 0) && bgp_debug_neighbor_events(peer))
		zlog_debug("%s: %s peer_clear failed", __func__, peer->host);

	return 0;
}

static uint32_t bgp_filtered_routes_count(struct peer *peer, afi_t afi,
					  safi_t safi)
{
	uint32_t count = 0;
	bool filtered = false;
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;
	struct attr attr = {};
	struct bgp_table *table = peer->bgp->rib[afi][safi];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (ain = dest->adj_in; ain; ain = ain->next) {
			const struct prefix *rn_p = bgp_dest_get_prefix(dest);

			attr = *ain->attr;

			if (bgp_input_filter(peer, rn_p, &attr, afi, safi)
			    == FILTER_DENY)
				filtered = true;

			if (bgp_input_modifier(
				    peer, rn_p, &attr, afi, safi,
				    ROUTE_MAP_IN_NAME(&peer->filter[afi][safi]),
				    NULL, 0, NULL)
			    == RMAP_DENY)
				filtered = true;

			if (filtered)
				count++;

			bgp_attr_undup(&attr, ain->attr);
		}
	}

	return count;
}

bool bgp_maximum_prefix_overflow(struct peer *peer, afi_t afi, safi_t safi,
				 int always)
{
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;
	uint32_t pcount = (CHECK_FLAG(peer->af_flags[afi][safi],
				      PEER_FLAG_MAX_PREFIX_FORCE))
				  ? bgp_filtered_routes_count(peer, afi, safi)
					    + peer->pcount[afi][safi]
				  : peer->pcount[afi][safi];

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
		return false;

	if (pcount > peer->pmax[afi][safi]) {
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_PREFIX_LIMIT)
		    && !always)
			return false;

		zlog_info(
			"%%MAXPFXEXCEED: No. of %s prefix received from %s %u exceed, limit %u",
			get_afi_safi_str(afi, safi, false), peer->host, pcount,
			peer->pmax[afi][safi]);
		SET_FLAG(peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_MAX_PREFIX_WARNING))
			return false;

		/* Convert AFI, SAFI to values for packet. */
		pkt_afi = afi_int2iana(afi);
		pkt_safi = safi_int2iana(safi);
		{
			uint8_t ndata[7];

			ndata[0] = (pkt_afi >> 8);
			ndata[1] = pkt_afi;
			ndata[2] = pkt_safi;
			ndata[3] = (peer->pmax[afi][safi] >> 24);
			ndata[4] = (peer->pmax[afi][safi] >> 16);
			ndata[5] = (peer->pmax[afi][safi] >> 8);
			ndata[6] = (peer->pmax[afi][safi]);

			SET_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
			bgp_notify_send_with_data(peer, BGP_NOTIFY_CEASE,
						  BGP_NOTIFY_CEASE_MAX_PREFIX,
						  ndata, 7);
		}

		/* Dynamic peers will just close their connection. */
		if (peer_dynamic_neighbor(peer))
			return true;

		/* restart timer start */
		if (peer->pmax_restart[afi][safi]) {
			peer->v_pmax_restart =
				peer->pmax_restart[afi][safi] * 60;

			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Maximum-prefix restart timer started for %d secs",
					peer->host, peer->v_pmax_restart);

			BGP_TIMER_ON(peer->t_pmax_restart,
				     bgp_maximum_prefix_restart_timer,
				     peer->v_pmax_restart);
		}

		return true;
	} else
		UNSET_FLAG(peer->af_sflags[afi][safi],
			   PEER_STATUS_PREFIX_LIMIT);

	if (pcount
	    > (peer->pmax[afi][safi] * peer->pmax_threshold[afi][safi] / 100)) {
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_PREFIX_THRESHOLD)
		    && !always)
			return false;

		zlog_info(
			"%%MAXPFX: No. of %s prefix received from %s reaches %u, max %u",
			get_afi_safi_str(afi, safi, false), peer->host, pcount,
			peer->pmax[afi][safi]);
		SET_FLAG(peer->af_sflags[afi][safi],
			 PEER_STATUS_PREFIX_THRESHOLD);
	} else
		UNSET_FLAG(peer->af_sflags[afi][safi],
			   PEER_STATUS_PREFIX_THRESHOLD);
	return false;
}

/* Unconditionally remove the route from the RIB, without taking
 * damping into consideration (eg, because the session went down)
 */
void bgp_rib_remove(struct bgp_dest *dest, struct bgp_path_info *pi,
		    struct peer *peer, afi_t afi, safi_t safi)
{

	struct bgp *bgp = NULL;
	bool delete_route = false;

	bgp_aggregate_decrement(peer->bgp, bgp_dest_get_prefix(dest), pi, afi,
				safi);

	if (!CHECK_FLAG(pi->flags, BGP_PATH_HISTORY)) {
		bgp_path_info_delete(dest, pi); /* keep historical info */

		/* If the selected path is removed, reset BGP_NODE_SELECT_DEFER
		 * flag
		 */
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			delete_route = true;
		else if (bgp_dest_set_defer_flag(dest, true) < 0)
			delete_route = true;
		if (delete_route) {
			if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
				UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
				bgp = pi->peer->bgp;
				bgp->gr_info[afi][safi].gr_deferred--;
			}
		}
	}

	hook_call(bgp_process, peer->bgp, afi, safi, dest, peer, true);
	bgp_process(peer->bgp, dest, afi, safi);
}

static void bgp_rib_withdraw(struct bgp_dest *dest, struct bgp_path_info *pi,
			     struct peer *peer, afi_t afi, safi_t safi,
			     struct prefix_rd *prd)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);

	/* apply dampening, if result is suppressed, we'll be retaining
	 * the bgp_path_info in the RIB for historical reference.
	 */
	if (CHECK_FLAG(peer->bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	    && peer->sort == BGP_PEER_EBGP)
		if ((bgp_damp_withdraw(pi, dest, afi, safi, 0))
		    == BGP_DAMP_SUPPRESSED) {
			bgp_aggregate_decrement(peer->bgp, p, pi, afi,
						safi);
			return;
		}

#ifdef ENABLE_BGP_VNC
	if (safi == SAFI_MPLS_VPN) {
		struct bgp_dest *pdest = NULL;
		struct bgp_table *table = NULL;

		pdest = bgp_node_get(peer->bgp->rib[afi][safi],
				     (struct prefix *)prd);
		if (bgp_dest_has_bgp_path_info_data(pdest)) {
			table = bgp_dest_get_bgp_table_info(pdest);

			vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
				peer->bgp, prd, table, p, pi);
		}
		bgp_dest_unlock_node(pdest);
	}
	if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {

			vnc_import_bgp_del_route(peer->bgp, p, pi);
			vnc_import_bgp_exterior_del_route(peer->bgp, p, pi);
		}
	}
#endif

	/* If this is an EVPN route, process for un-import. */
	if (safi == SAFI_EVPN)
		bgp_evpn_unimport_route(peer->bgp, afi, safi, p, pi);

	bgp_rib_remove(dest, pi, peer, afi, safi);
}

struct bgp_path_info *info_make(int type, int sub_type, unsigned short instance,
				struct peer *peer, struct attr *attr,
				struct bgp_dest *dest)
{
	struct bgp_path_info *new;

	/* Make new BGP info. */
	new = XCALLOC(MTYPE_BGP_ROUTE, sizeof(struct bgp_path_info));
	new->type = type;
	new->instance = instance;
	new->sub_type = sub_type;
	new->peer = peer;
	new->attr = attr;
	new->uptime = bgp_clock();
	new->net = dest;
	return new;
}

static void overlay_index_update(struct attr *attr,
				 union gw_addr *gw_ip)
{
	if (!attr)
		return;
	if (gw_ip == NULL) {
		struct bgp_route_evpn eo;

		memset(&eo, 0, sizeof(eo));
		bgp_attr_set_evpn_overlay(attr, &eo);
	} else {
		struct bgp_route_evpn eo = {.gw_ip = *gw_ip};

		bgp_attr_set_evpn_overlay(attr, &eo);
	}
}

static bool overlay_index_equal(afi_t afi, struct bgp_path_info *path,
				union gw_addr *gw_ip)
{
	const struct bgp_route_evpn *eo = bgp_attr_get_evpn_overlay(path->attr);
	union gw_addr path_gw_ip, *path_gw_ip_remote;
	union {
		esi_t esi;
		union gw_addr ip;
	} temp;

	if (afi != AFI_L2VPN)
		return true;

	path_gw_ip = eo->gw_ip;

	if (gw_ip == NULL) {
		memset(&temp, 0, sizeof(temp));
		path_gw_ip_remote = &temp.ip;
	} else
		path_gw_ip_remote = gw_ip;

	return !!memcmp(&path_gw_ip, path_gw_ip_remote, sizeof(union gw_addr));
}

/* Check if received nexthop is valid or not. */
bool bgp_update_martian_nexthop(struct bgp *bgp, afi_t afi, safi_t safi,
				uint8_t type, uint8_t stype, struct attr *attr,
				struct bgp_dest *dest)
{
	bool ret = false;
	bool is_bgp_static_route =
		(type == ZEBRA_ROUTE_BGP && stype == BGP_ROUTE_STATIC) ? true
								       : false;

	/*
	 * Only validated for unicast and multicast currently.
	 * Also valid for EVPN where the nexthop is an IP address.
	 * If we are a bgp static route being checked then there is
	 * no need to check to see if the nexthop is martian as
	 * that it should be ok.
	 */
	if (is_bgp_static_route ||
	    (safi != SAFI_UNICAST && safi != SAFI_MULTICAST && safi != SAFI_EVPN))
		return false;

	/* If NEXT_HOP is present, validate it. */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) {
		if (attr->nexthop.s_addr == INADDR_ANY
		    || IPV4_CLASS_DE(ntohl(attr->nexthop.s_addr))
		    || bgp_nexthop_self(bgp, afi, type, stype, attr, dest))
			return true;
	}

	/* If MP_NEXTHOP is present, validate it. */
	/* Note: For IPv6 nexthops, we only validate the global (1st) nexthop;
	 * there is code in bgp_attr.c to ignore the link-local (2nd) nexthop if
	 * it is not an IPv6 link-local address.
	 *
	 * If we receive an UPDATE with nexthop length set to 32 bytes
	 * we shouldn't discard an UPDATE if it's set to (::).
	 * The link-local (2st) is validated along the code path later.
	 */
	if (attr->mp_nexthop_len) {
		switch (attr->mp_nexthop_len) {
		case BGP_ATTR_NHLEN_IPV4:
		case BGP_ATTR_NHLEN_VPNV4:
			ret = (attr->mp_nexthop_global_in.s_addr == INADDR_ANY
			       || IPV4_CLASS_DE(
				       ntohl(attr->mp_nexthop_global_in.s_addr))
			       || bgp_nexthop_self(bgp, afi, type, stype, attr,
						   dest));
			break;

		case BGP_ATTR_NHLEN_IPV6_GLOBAL:
		case BGP_ATTR_NHLEN_VPNV6_GLOBAL:
			ret = (IN6_IS_ADDR_UNSPECIFIED(
					&attr->mp_nexthop_global)
			       || IN6_IS_ADDR_LOOPBACK(&attr->mp_nexthop_global)
			       || IN6_IS_ADDR_MULTICAST(
				       &attr->mp_nexthop_global)
			       || bgp_nexthop_self(bgp, afi, type, stype, attr,
						   dest));
			break;
		case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
			ret = (IN6_IS_ADDR_LOOPBACK(&attr->mp_nexthop_global)
			       || IN6_IS_ADDR_MULTICAST(
				       &attr->mp_nexthop_global)
			       || bgp_nexthop_self(bgp, afi, type, stype, attr,
						   dest));
			break;

		default:
			ret = true;
			break;
		}
	}

	return ret;
}

int bgp_update(struct peer *peer, const struct prefix *p, uint32_t addpath_id,
	       struct attr *attr, afi_t afi, safi_t safi, int type,
	       int sub_type, struct prefix_rd *prd, mpls_label_t *label,
	       uint32_t num_labels, int soft_reconfig,
	       struct bgp_route_evpn *evpn)
{
	int ret;
	int aspath_loop_count = 0;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct attr new_attr;
	struct attr *attr_new;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct bgp_path_info_extra *extra;
	const char *reason;
	char pfx_buf[BGP_PRD_PATH_STRLEN];
	int connected = 0;
	int do_loop_check = 1;
	int has_valid_label = 0;
	afi_t nh_afi;
	uint8_t pi_type = 0;
	uint8_t pi_sub_type = 0;

	if (frrtrace_enabled(frr_bgp, process_update)) {
		char pfxprint[PREFIX2STR_BUFFER];

		prefix2str(p, pfxprint, sizeof(pfxprint));
		frrtrace(6, frr_bgp, process_update, peer, pfxprint, addpath_id,
			 afi, safi, attr);
	}

#ifdef ENABLE_BGP_VNC
	int vnc_implicit_withdraw = 0;
#endif
	int same_attr = 0;

	memset(&new_attr, 0, sizeof(struct attr));
	new_attr.label_index = BGP_INVALID_LABEL_INDEX;
	new_attr.label = MPLS_INVALID_LABEL;

	bgp = peer->bgp;
	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);
	/* TODO: Check to see if we can get rid of "is_valid_label" */
	if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		has_valid_label = (num_labels > 0) ? 1 : 0;
	else
		has_valid_label = bgp_is_valid_label(label);

	if (has_valid_label)
		assert(label != NULL);

	/* The flag BGP_NODE_FIB_INSTALL_PENDING is for the following
	 * condition :
	 * Suppress fib is enabled
	 * BGP_OPT_NO_FIB is not enabled
	 * Route type is BGP_ROUTE_NORMAL (peer learnt routes)
	 * Route is being installed first time (BGP_NODE_FIB_INSTALLED not set)
	 */
	if (BGP_SUPPRESS_FIB_ENABLED(bgp) &&
	    (sub_type == BGP_ROUTE_NORMAL) &&
	    (!bgp_option_check(BGP_OPT_NO_FIB)) &&
	    (!CHECK_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED)))
		SET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);

	/* When peer's soft reconfiguration enabled.  Record input packet in
	   Adj-RIBs-In.  */
	if (!soft_reconfig
	    && CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
	    && peer != bgp->peer_self)
		bgp_adj_in_set(dest, peer, attr, addpath_id);

	/* Check previously received route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == type
		    && pi->sub_type == sub_type
		    && pi->addpath_rx_id == addpath_id)
			break;

	/* AS path local-as loop check. */
	if (peer->change_local_as) {
		if (peer->allowas_in[afi][safi])
			aspath_loop_count = peer->allowas_in[afi][safi];
		else if (!CHECK_FLAG(peer->flags,
				     PEER_FLAG_LOCAL_AS_NO_PREPEND))
			aspath_loop_count = 1;

		if (aspath_loop_check(attr->aspath, peer->change_local_as)
		    > aspath_loop_count) {
			peer->stat_pfx_aspath_loop++;
			reason = "as-path contains our own AS A;";
			goto filtered;
		}
	}

	/* If the peer is configured for "allowas-in origin" and the last ASN in
	 * the
	 * as-path is our ASN then we do not need to call aspath_loop_check
	 */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN_ORIGIN))
		if (aspath_get_last_as(attr->aspath) == bgp->as)
			do_loop_check = 0;

	/* AS path loop check. */
	if (do_loop_check) {
		if (aspath_loop_check(attr->aspath, bgp->as)
			    > peer->allowas_in[afi][safi]
		    || (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
			&& aspath_loop_check(attr->aspath, bgp->confed_id)
				   > peer->allowas_in[afi][safi])) {
			peer->stat_pfx_aspath_loop++;
			reason = "as-path contains our own AS;";
			goto filtered;
		}
	}

	/* Route reflector originator ID check.  */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)
	    && IPV4_ADDR_SAME(&bgp->router_id, &attr->originator_id)) {
		peer->stat_pfx_originator_loop++;
		reason = "originator is us;";
		goto filtered;
	}

	/* Route reflector cluster ID check.  */
	if (bgp_cluster_filter(peer, attr)) {
		peer->stat_pfx_cluster_loop++;
		reason = "reflected from the same cluster;";
		goto filtered;
	}

	/* Apply incoming filter.  */
	if (bgp_input_filter(peer, p, attr, afi, safi) == FILTER_DENY) {
		peer->stat_pfx_filter++;
		reason = "filter;";
		goto filtered;
	}

	/* RFC 8212 to prevent route leaks.
	 * This specification intends to improve this situation by requiring the
	 * explicit configuration of both BGP Import and Export Policies for any
	 * External BGP (EBGP) session such as customers, peers, or
	 * confederation boundaries for all enabled address families. Through
	 * codification of the aforementioned requirement, operators will
	 * benefit from consistent behavior across different BGP
	 * implementations.
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY))
		if (!bgp_inbound_policy_exists(peer,
					       &peer->filter[afi][safi])) {
			reason = "inbound policy missing";
			goto filtered;
		}

	/* draft-ietf-idr-deprecate-as-set-confed-set
	 * Filter routes having AS_SET or AS_CONFED_SET in the path.
	 * Eventually, This document (if approved) updates RFC 4271
	 * and RFC 5065 by eliminating AS_SET and AS_CONFED_SET types,
	 * and obsoletes RFC 6472.
	 */
	if (peer->bgp->reject_as_sets)
		if (aspath_check_as_sets(attr->aspath)) {
			reason =
				"as-path contains AS_SET or AS_CONFED_SET type;";
			goto filtered;
		}

	new_attr = *attr;

	/* Apply incoming route-map.
	 * NB: new_attr may now contain newly allocated values from route-map
	 * "set"
	 * commands, so we need bgp_attr_flush in the error paths, until we
	 * intern
	 * the attr (which takes over the memory references) */
	if (bgp_input_modifier(peer, p, &new_attr, afi, safi, NULL, label,
			       num_labels, dest)
	    == RMAP_DENY) {
		peer->stat_pfx_filter++;
		reason = "route-map;";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

	if (pi && pi->attr->rmap_table_id != new_attr.rmap_table_id) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			/* remove from RIB previous entry */
			bgp_zebra_withdraw(p, pi, bgp, safi);
	}

	if (peer->sort == BGP_PEER_EBGP) {

		/* If we receive the graceful-shutdown community from an eBGP
		 * peer we must lower local-preference */
		if (new_attr.community
		    && community_include(new_attr.community, COMMUNITY_GSHUT)) {
			new_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
			new_attr.local_pref = BGP_GSHUT_LOCAL_PREF;

			/* If graceful-shutdown is configured then add the GSHUT
			 * community to all paths received from eBGP peers */
		} else if (bgp_in_graceful_shutdown(peer->bgp))
			bgp_attr_add_gshut_community(&new_attr);
	}

	if (pi) {
		pi_type = pi->type;
		pi_sub_type = pi->sub_type;
	}

	/* next hop check.  */
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD)
	    && bgp_update_martian_nexthop(bgp, afi, safi, pi_type, pi_sub_type,
					  &new_attr, dest)) {
		peer->stat_pfx_nh_invalid++;
		reason = "martian or self next-hop;";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

	if (bgp_mac_entry_exists(p) || bgp_mac_exist(&attr->rmac)) {
		peer->stat_pfx_nh_invalid++;
		reason = "self mac;";
		goto filtered;
	}

	/* Update Overlay Index */
	if (afi == AFI_L2VPN) {
		overlay_index_update(&new_attr,
				     evpn == NULL ? NULL : &evpn->gw_ip);
	}

	attr_new = bgp_attr_intern(&new_attr);

	/* If maximum prefix count is configured and current prefix
	 * count exeed it.
	 */
	if (bgp_maximum_prefix_overflow(peer, afi, safi, 0))
		return -1;

	/* If the update is implicit withdraw. */
	if (pi) {
		pi->uptime = bgp_clock();
		same_attr = attrhash_cmp(pi->attr, attr_new);

		hook_call(bgp_process, bgp, afi, safi, dest, peer, true);

		/* Same attribute comes in. */
		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)
		    && attrhash_cmp(pi->attr, attr_new)
		    && (!has_valid_label
			|| memcmp(&(bgp_path_info_extra_get(pi))->label, label,
				  num_labels * sizeof(mpls_label_t))
				   == 0)
		    && (overlay_index_equal(
			       afi, pi,
			       evpn == NULL ? NULL : &evpn->gw_ip))) {
			if (CHECK_FLAG(bgp->af_flags[afi][safi],
				       BGP_CONFIG_DAMPENING)
			    && peer->sort == BGP_PEER_EBGP
			    && CHECK_FLAG(pi->flags, BGP_PATH_HISTORY)) {
				if (bgp_debug_update(peer, p, NULL, 1)) {
					bgp_debug_rdpfxpath2str(
						afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, pfx_buf,
						sizeof(pfx_buf));
					zlog_debug("%s rcvd %s", peer->host,
						   pfx_buf);
				}

				if (bgp_damp_update(pi, dest, afi, safi)
				    != BGP_DAMP_SUPPRESSED) {
					bgp_aggregate_increment(bgp, p, pi, afi,
								safi);
					bgp_process(bgp, dest, afi, safi);
				}
			} else /* Duplicate - odd */
			{
				if (bgp_debug_update(peer, p, NULL, 1)) {
					if (!peer->rcvd_attr_printed) {
						zlog_debug(
							"%s rcvd UPDATE w/ attr: %s",
							peer->host,
							peer->rcvd_attr_str);
						peer->rcvd_attr_printed = 1;
					}

					bgp_debug_rdpfxpath2str(
						afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, pfx_buf,
						sizeof(pfx_buf));
					zlog_debug(
						"%s rcvd %s...duplicate ignored",
						peer->host, pfx_buf);
				}

				/* graceful restart STALE flag unset. */
				if (CHECK_FLAG(pi->flags, BGP_PATH_STALE)) {
					bgp_path_info_unset_flag(
						dest, pi, BGP_PATH_STALE);
					bgp_dest_set_defer_flag(dest, false);
					bgp_process(bgp, dest, afi, safi);
				}
			}

			bgp_dest_unlock_node(dest);
			bgp_attr_unintern(&attr_new);

			return 0;
		}

		/* Withdraw/Announce before we fully processed the withdraw */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			if (bgp_debug_update(peer, p, NULL, 1)) {
				bgp_debug_rdpfxpath2str(
					afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
				zlog_debug(
					"%s rcvd %s, flapped quicker than processing",
					peer->host, pfx_buf);
			}

			bgp_path_info_restore(dest, pi);
		}

		/* Received Logging. */
		if (bgp_debug_update(peer, p, NULL, 1)) {
			bgp_debug_rdpfxpath2str(afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, pfx_buf,
						sizeof(pfx_buf));
			zlog_debug("%s rcvd %s", peer->host, pfx_buf);
		}

		/* graceful restart STALE flag unset. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_STALE)) {
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_STALE);
			bgp_dest_set_defer_flag(dest, false);
		}

		/* The attribute is changed. */
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);

		/* implicit withdraw, decrement aggregate and pcount here.
		 * only if update is accepted, they'll increment below.
		 */
		bgp_aggregate_decrement(bgp, p, pi, afi, safi);

		/* Update bgp route dampening information.  */
		if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
		    && peer->sort == BGP_PEER_EBGP) {
			/* This is implicit withdraw so we should update
			   dampening
			   information.  */
			if (!CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
				bgp_damp_withdraw(pi, dest, afi, safi, 1);
		}
#ifdef ENABLE_BGP_VNC
		if (safi == SAFI_MPLS_VPN) {
			struct bgp_dest *pdest = NULL;
			struct bgp_table *table = NULL;

			pdest = bgp_node_get(bgp->rib[afi][safi],
					     (struct prefix *)prd);
			if (bgp_dest_has_bgp_path_info_data(pdest)) {
				table = bgp_dest_get_bgp_table_info(pdest);

				vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
					bgp, prd, table, p, pi);
			}
			bgp_dest_unlock_node(pdest);
		}
		if ((afi == AFI_IP || afi == AFI_IP6)
		    && (safi == SAFI_UNICAST)) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
				/*
				 * Implicit withdraw case.
				 */
				++vnc_implicit_withdraw;
				vnc_import_bgp_del_route(bgp, p, pi);
				vnc_import_bgp_exterior_del_route(bgp, p, pi);
			}
		}
#endif

		/* Special handling for EVPN update of an existing route. If the
		 * extended community attribute has changed, we need to
		 * un-import
		 * the route using its existing extended community. It will be
		 * subsequently processed for import with the new extended
		 * community.
		 */
		if (((safi == SAFI_EVPN) || (safi == SAFI_MPLS_VPN))
		    && !same_attr) {
			if ((pi->attr->flag
			     & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
			    && (attr_new->flag
				& ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
				int cmp;

				cmp = ecommunity_cmp(pi->attr->ecommunity,
						     attr_new->ecommunity);
				if (!cmp) {
					if (bgp_debug_update(peer, p, NULL, 1))
						zlog_debug(
							"Change in EXT-COMM, existing %s new %s",
							ecommunity_str(
								pi->attr->ecommunity),
							ecommunity_str(
								attr_new->ecommunity));
					if (safi == SAFI_EVPN)
						bgp_evpn_unimport_route(
							bgp, afi, safi, p, pi);
					else /* SAFI_MPLS_VPN */
						vpn_leak_to_vrf_withdraw(bgp,
									 pi);
				}
			}
		}

		/* Update to new attribute.  */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;

		/* Update MPLS label */
		if (has_valid_label) {
			extra = bgp_path_info_extra_get(pi);
			if (extra->label != label) {
				memcpy(&extra->label, label,
				       num_labels * sizeof(mpls_label_t));
				extra->num_labels = num_labels;
			}
			if (!(afi == AFI_L2VPN && safi == SAFI_EVPN))
				bgp_set_valid_label(&extra->label[0]);
		}

		/* Update SRv6 SID */
		if (attr->srv6_l3vpn) {
			extra = bgp_path_info_extra_get(pi);
			if (sid_diff(&extra->sid[0], &attr->srv6_l3vpn->sid)) {
				sid_copy(&extra->sid[0],
					 &attr->srv6_l3vpn->sid);
				extra->num_sids = 1;
			}
		} else if (attr->srv6_vpn) {
			extra = bgp_path_info_extra_get(pi);
			if (sid_diff(&extra->sid[0], &attr->srv6_vpn->sid)) {
				sid_copy(&extra->sid[0], &attr->srv6_vpn->sid);
				extra->num_sids = 1;
			}
		}

#ifdef ENABLE_BGP_VNC
		if ((afi == AFI_IP || afi == AFI_IP6)
		    && (safi == SAFI_UNICAST)) {
			if (vnc_implicit_withdraw) {
				/*
				 * Add back the route with its new attributes
				 * (e.g., nexthop).
				 * The route is still selected, until the route
				 * selection
				 * queued by bgp_process actually runs. We have
				 * to make this
				 * update to the VNC side immediately to avoid
				 * racing against
				 * configuration changes (e.g., route-map
				 * changes) which
				 * trigger re-importation of the entire RIB.
				 */
				vnc_import_bgp_add_route(bgp, p, pi);
				vnc_import_bgp_exterior_add_route(bgp, p, pi);
			}
		}
#endif

		/* Update bgp route dampening information.  */
		if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
		    && peer->sort == BGP_PEER_EBGP) {
			/* Now we do normal update dampening.  */
			ret = bgp_damp_update(pi, dest, afi, safi);
			if (ret == BGP_DAMP_SUPPRESSED) {
				bgp_dest_unlock_node(dest);
				return 0;
			}
		}

		/* Nexthop reachability check - for unicast and
		 * labeled-unicast.. */
		if (((afi == AFI_IP || afi == AFI_IP6)
		    && (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST))
		    || (safi == SAFI_EVPN &&
			bgp_evpn_is_prefix_nht_supported(p))) {
			if (safi != SAFI_EVPN && peer->sort == BGP_PEER_EBGP
			    && peer->ttl == BGP_DEFAULT_TTL
			    && !CHECK_FLAG(peer->flags,
					   PEER_FLAG_DISABLE_CONNECTED_CHECK)
			    && !CHECK_FLAG(bgp->flags,
					   BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
				connected = 1;
			else
				connected = 0;

			struct bgp *bgp_nexthop = bgp;

			if (pi->extra && pi->extra->bgp_orig)
				bgp_nexthop = pi->extra->bgp_orig;

			nh_afi = BGP_ATTR_NH_AFI(afi, pi->attr);

			if (bgp_find_or_add_nexthop(bgp, bgp_nexthop, nh_afi,
						    pi, NULL, connected)
			    || CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD))
				bgp_path_info_set_flag(dest, pi,
						       BGP_PATH_VALID);
			else {
				if (BGP_DEBUG(nht, NHT)) {
					zlog_debug("%s(%pI4): NH unresolved",
						   __func__,
						   (in_addr_t *)&attr_new->nexthop);
				}
				bgp_path_info_unset_flag(dest, pi,
							 BGP_PATH_VALID);
			}
		} else
			bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);

#ifdef ENABLE_BGP_VNC
		if (safi == SAFI_MPLS_VPN) {
			struct bgp_dest *pdest = NULL;
			struct bgp_table *table = NULL;

			pdest = bgp_node_get(bgp->rib[afi][safi],
					     (struct prefix *)prd);
			if (bgp_dest_has_bgp_path_info_data(pdest)) {
				table = bgp_dest_get_bgp_table_info(pdest);

				vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
					bgp, prd, table, p, pi);
			}
			bgp_dest_unlock_node(pdest);
		}
#endif

		/* If this is an EVPN route and some attribute has changed,
		 * process
		 * route for import. If the extended community has changed, we
		 * would
		 * have done the un-import earlier and the import would result
		 * in the
		 * route getting injected into appropriate L2 VNIs. If it is
		 * just
		 * some other attribute change, the import will result in
		 * updating
		 * the attributes for the route in the VNI(s).
		 */
		if (safi == SAFI_EVPN && !same_attr &&
		    CHECK_FLAG(pi->flags, BGP_PATH_VALID))
			bgp_evpn_import_route(bgp, afi, safi, p, pi);

		/* Process change. */
		bgp_aggregate_increment(bgp, p, pi, afi, safi);

		bgp_process(bgp, dest, afi, safi);
		bgp_dest_unlock_node(dest);

		if (SAFI_UNICAST == safi
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
			|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_from_vrf_update(bgp_get_default(), bgp, pi);
		}
		if ((SAFI_MPLS_VPN == safi)
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_to_vrf_update(bgp, pi);
		}

#ifdef ENABLE_BGP_VNC
		if (SAFI_MPLS_VPN == safi) {
			mpls_label_t label_decoded = decode_label(label);

			rfapiProcessUpdate(peer, NULL, p, prd, attr, afi, safi,
					   type, sub_type, &label_decoded);
		}
		if (SAFI_ENCAP == safi) {
			rfapiProcessUpdate(peer, NULL, p, prd, attr, afi, safi,
					   type, sub_type, NULL);
		}
#endif

		return 0;
	} // End of implicit withdraw

	/* Received Logging. */
	if (bgp_debug_update(peer, p, NULL, 1)) {
		if (!peer->rcvd_attr_printed) {
			zlog_debug("%s rcvd UPDATE w/ attr: %s", peer->host,
				   peer->rcvd_attr_str);
			peer->rcvd_attr_printed = 1;
		}

		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
		zlog_debug("%s rcvd %s", peer->host, pfx_buf);
	}

	/* Make new BGP info. */
	new = info_make(type, sub_type, 0, peer, attr_new, dest);

	/* Update MPLS label */
	if (has_valid_label) {
		extra = bgp_path_info_extra_get(new);
		if (extra->label != label) {
			memcpy(&extra->label, label,
			       num_labels * sizeof(mpls_label_t));
			extra->num_labels = num_labels;
		}
		if (!(afi == AFI_L2VPN && safi == SAFI_EVPN))
			bgp_set_valid_label(&extra->label[0]);
	}

	/* Update SRv6 SID */
	if (safi == SAFI_MPLS_VPN) {
		extra = bgp_path_info_extra_get(new);
		if (attr->srv6_l3vpn) {
			sid_copy(&extra->sid[0], &attr->srv6_l3vpn->sid);
			extra->num_sids = 1;
		} else if (attr->srv6_vpn) {
			sid_copy(&extra->sid[0], &attr->srv6_vpn->sid);
			extra->num_sids = 1;
		}
	}

	/* Update Overlay Index */
	if (afi == AFI_L2VPN) {
		overlay_index_update(new->attr,
				     evpn == NULL ? NULL : &evpn->gw_ip);
	}
	/* Nexthop reachability check. */
	if (((afi == AFI_IP || afi == AFI_IP6)
	    && (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST))
	    || (safi == SAFI_EVPN && bgp_evpn_is_prefix_nht_supported(p))) {
		if (safi != SAFI_EVPN && peer->sort == BGP_PEER_EBGP
		    && peer->ttl == BGP_DEFAULT_TTL
		    && !CHECK_FLAG(peer->flags,
				   PEER_FLAG_DISABLE_CONNECTED_CHECK)
		    && !CHECK_FLAG(bgp->flags,
				   BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
			connected = 1;
		else
			connected = 0;

		nh_afi = BGP_ATTR_NH_AFI(afi, new->attr);

		if (bgp_find_or_add_nexthop(bgp, bgp, nh_afi, new, NULL,
					    connected)
		    || CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD))
			bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
		else {
			if (BGP_DEBUG(nht, NHT)) {
				char buf1[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET,
					  (const void *)&attr_new->nexthop,
					  buf1, INET6_ADDRSTRLEN);
				zlog_debug("%s(%s): NH unresolved", __func__,
					   buf1);
			}
			bgp_path_info_unset_flag(dest, new, BGP_PATH_VALID);
		}
	} else
		bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);

	/* Addpath ID */
	new->addpath_rx_id = addpath_id;

	/* Increment prefix */
	bgp_aggregate_increment(bgp, p, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

#ifdef ENABLE_BGP_VNC
	if (safi == SAFI_MPLS_VPN) {
		struct bgp_dest *pdest = NULL;
		struct bgp_table *table = NULL;

		pdest = bgp_node_get(bgp->rib[afi][safi], (struct prefix *)prd);
		if (bgp_dest_has_bgp_path_info_data(pdest)) {
			table = bgp_dest_get_bgp_table_info(pdest);

			vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
				bgp, prd, table, p, new);
		}
		bgp_dest_unlock_node(pdest);
	}
#endif

	/* If this is an EVPN route, process for import. */
	if (safi == SAFI_EVPN && CHECK_FLAG(new->flags, BGP_PATH_VALID))
		bgp_evpn_import_route(bgp, afi, safi, p, new);

	hook_call(bgp_process, bgp, afi, safi, dest, peer, false);

	/* Process change. */
	bgp_process(bgp, dest, afi, safi);

	if (SAFI_UNICAST == safi
	    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
		|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
		vpn_leak_from_vrf_update(bgp_get_default(), bgp, new);
	}
	if ((SAFI_MPLS_VPN == safi)
	    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

		vpn_leak_to_vrf_update(bgp, new);
	}
#ifdef ENABLE_BGP_VNC
	if (SAFI_MPLS_VPN == safi) {
		mpls_label_t label_decoded = decode_label(label);

		rfapiProcessUpdate(peer, NULL, p, prd, attr, afi, safi, type,
				   sub_type, &label_decoded);
	}
	if (SAFI_ENCAP == safi) {
		rfapiProcessUpdate(peer, NULL, p, prd, attr, afi, safi, type,
				   sub_type, NULL);
	}
#endif

	return 0;

/* This BGP update is filtered.  Log the reason then update BGP
   entry.  */
filtered:
	hook_call(bgp_process, bgp, afi, safi, dest, peer, true);

	if (bgp_debug_update(peer, p, NULL, 1)) {
		if (!peer->rcvd_attr_printed) {
			zlog_debug("%s rcvd UPDATE w/ attr: %s", peer->host,
				   peer->rcvd_attr_str);
			peer->rcvd_attr_printed = 1;
		}

		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
		zlog_debug("%s rcvd UPDATE about %s -- DENIED due to: %s",
			   peer->host, pfx_buf, reason);
	}

	if (pi) {
		/* If this is an EVPN route, un-import it as it is now filtered.
		 */
		if (safi == SAFI_EVPN)
			bgp_evpn_unimport_route(bgp, afi, safi, p, pi);

		if (SAFI_UNICAST == safi
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
			|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp, pi);
		}
		if ((SAFI_MPLS_VPN == safi)
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_to_vrf_withdraw(bgp, pi);
		}

		bgp_rib_remove(dest, pi, peer, afi, safi);
	}

	bgp_dest_unlock_node(dest);

#ifdef ENABLE_BGP_VNC
	/*
	 * Filtered update is treated as an implicit withdrawal (see
	 * bgp_rib_remove()
	 * a few lines above)
	 */
	if ((SAFI_MPLS_VPN == safi) || (SAFI_ENCAP == safi)) {
		rfapiProcessWithdraw(peer, NULL, p, prd, NULL, afi, safi, type,
				     0);
	}
#endif

	return 0;
}

int bgp_withdraw(struct peer *peer, const struct prefix *p, uint32_t addpath_id,
		 struct attr *attr, afi_t afi, safi_t safi, int type,
		 int sub_type, struct prefix_rd *prd, mpls_label_t *label,
		 uint32_t num_labels, struct bgp_route_evpn *evpn)
{
	struct bgp *bgp;
	char pfx_buf[BGP_PRD_PATH_STRLEN];
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

#ifdef ENABLE_BGP_VNC
	if ((SAFI_MPLS_VPN == safi) || (SAFI_ENCAP == safi)) {
		rfapiProcessWithdraw(peer, NULL, p, prd, NULL, afi, safi, type,
				     0);
	}
#endif

	bgp = peer->bgp;

	/* Lookup node. */
	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	/* If peer is soft reconfiguration enabled.  Record input packet for
	 * further calculation.
	 *
	 * Cisco IOS 12.4(24)T4 on session establishment sends withdraws for all
	 * routes that are filtered.  This tanks out Quagga RS pretty badly due
	 * to
	 * the iteration over all RS clients.
	 * Since we need to remove the entry from adj_in anyway, do that first
	 * and
	 * if there was no entry, we don't need to do anything more.
	 */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
	    && peer != bgp->peer_self)
		if (!bgp_adj_in_unset(dest, peer, addpath_id)) {
			peer->stat_pfx_dup_withdraw++;

			if (bgp_debug_update(peer, p, NULL, 1)) {
				bgp_debug_rdpfxpath2str(
					afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
				zlog_debug(
					"%s withdrawing route %s not in adj-in",
					peer->host, pfx_buf);
			}
			bgp_dest_unlock_node(dest);
			return 0;
		}

	/* Lookup withdrawn route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == type
		    && pi->sub_type == sub_type
		    && pi->addpath_rx_id == addpath_id)
			break;

	/* Logging. */
	if (bgp_debug_update(peer, p, NULL, 1)) {
		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
		zlog_debug("%s rcvd UPDATE about %s -- withdrawn", peer->host,
			   pfx_buf);
	}

	/* Withdraw specified route from routing table. */
	if (pi && !CHECK_FLAG(pi->flags, BGP_PATH_HISTORY)) {
		bgp_rib_withdraw(dest, pi, peer, afi, safi, prd);
		if (SAFI_UNICAST == safi
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
			|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
			vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp, pi);
		}
		if ((SAFI_MPLS_VPN == safi)
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_to_vrf_withdraw(bgp, pi);
		}
	} else if (bgp_debug_update(peer, p, NULL, 1)) {
		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, pfx_buf,
					sizeof(pfx_buf));
		zlog_debug("%s Can't find the route %s", peer->host, pfx_buf);
	}

	/* Unlock bgp_node_get() lock. */
	bgp_dest_unlock_node(dest);

	return 0;
}

void bgp_default_originate(struct peer *peer, afi_t afi, safi_t safi,
			   int withdraw)
{
	struct update_subgroup *subgrp;
	subgrp = peer_subgroup(peer, afi, safi);
	subgroup_default_originate(subgrp, withdraw);
}


/*
 * bgp_stop_announce_route_timer
 */
void bgp_stop_announce_route_timer(struct peer_af *paf)
{
	if (!paf->t_announce_route)
		return;

	thread_cancel(&paf->t_announce_route);
}

/*
 * bgp_announce_route_timer_expired
 *
 * Callback that is invoked when the route announcement timer for a
 * peer_af expires.
 */
static int bgp_announce_route_timer_expired(struct thread *t)
{
	struct peer_af *paf;
	struct peer *peer;

	paf = THREAD_ARG(t);
	peer = paf->peer;

	if (peer->status != Established)
		return 0;

	if (!peer->afc_nego[paf->afi][paf->safi])
		return 0;

	peer_af_announce_route(paf, 1);

	/* Notify BGP conditional advertisement scanner percess */
	peer->advmap_config_change[paf->afi][paf->safi] = true;

	return 0;
}

/*
 * bgp_announce_route
 *
 * *Triggers* announcement of routes of a given AFI/SAFI to a peer.
 */
void bgp_announce_route(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer_af *paf;
	struct update_subgroup *subgrp;

	paf = peer_af_find(peer, afi, safi);
	if (!paf)
		return;
	subgrp = PAF_SUBGRP(paf);

	/*
	 * Ignore if subgroup doesn't exist (implies AF is not negotiated)
	 * or a refresh has already been triggered.
	 */
	if (!subgrp || paf->t_announce_route)
		return;

	/*
	 * Start a timer to stagger/delay the announce. This serves
	 * two purposes - announcement can potentially be combined for
	 * multiple peers and the announcement doesn't happen in the
	 * vty context.
	 */
	thread_add_timer_msec(bm->master, bgp_announce_route_timer_expired, paf,
			      (subgrp->peer_count == 1)
				      ? BGP_ANNOUNCE_ROUTE_SHORT_DELAY_MS
				      : BGP_ANNOUNCE_ROUTE_DELAY_MS,
			      &paf->t_announce_route);
}

/*
 * Announce routes from all AF tables to a peer.
 *
 * This should ONLY be called when there is a need to refresh the
 * routes to the peer based on a policy change for this peer alone
 * or a route refresh request received from the peer.
 * The operation will result in splitting the peer from its existing
 * subgroups and putting it in new subgroups.
 */
void bgp_announce_route_all(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_announce_route(peer, afi, safi);
}

static void bgp_soft_reconfig_table(struct peer *peer, afi_t afi, safi_t safi,
				    struct bgp_table *table,
				    struct prefix_rd *prd)
{
	int ret;
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;

	if (!table)
		table = peer->bgp->rib[afi][safi];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (ain = dest->adj_in; ain; ain = ain->next) {
			if (ain->peer != peer)
				continue;

			struct bgp_path_info *pi;
			uint32_t num_labels = 0;
			mpls_label_t *label_pnt = NULL;
			struct bgp_route_evpn evpn;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next)
				if (pi->peer == peer)
					break;

			if (pi && pi->extra)
				num_labels = pi->extra->num_labels;
			if (num_labels)
				label_pnt = &pi->extra->label[0];
			if (pi)
				memcpy(&evpn,
				       bgp_attr_get_evpn_overlay(pi->attr),
				       sizeof(evpn));
			else
				memset(&evpn, 0, sizeof(evpn));

			ret = bgp_update(peer, bgp_dest_get_prefix(dest),
					 ain->addpath_rx_id, ain->attr, afi,
					 safi, ZEBRA_ROUTE_BGP,
					 BGP_ROUTE_NORMAL, prd, label_pnt,
					 num_labels, 1, &evpn);

			if (ret < 0) {
				bgp_dest_unlock_node(dest);
				return;
			}
		}
}

void bgp_soft_reconfig_in(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;

	if (peer->status != Established)
		return;

	if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP)
	    && (safi != SAFI_EVPN))
		bgp_soft_reconfig_table(peer, afi, safi, NULL, NULL);
	else
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			table = bgp_dest_get_bgp_table_info(dest);

			if (table == NULL)
				continue;

			const struct prefix *p = bgp_dest_get_prefix(dest);
			struct prefix_rd prd;

			prd.family = AF_UNSPEC;
			prd.prefixlen = 64;
			memcpy(&prd.val, p->u.val, 8);

			bgp_soft_reconfig_table(peer, afi, safi, table, &prd);
		}
}


struct bgp_clear_node_queue {
	struct bgp_dest *dest;
};

static wq_item_status bgp_clear_route_node(struct work_queue *wq, void *data)
{
	struct bgp_clear_node_queue *cnq = data;
	struct bgp_dest *dest = cnq->dest;
	struct peer *peer = wq->spec.data;
	struct bgp_path_info *pi;
	struct bgp *bgp;
	afi_t afi = bgp_dest_table(dest)->afi;
	safi_t safi = bgp_dest_table(dest)->safi;

	assert(dest && peer);
	bgp = peer->bgp;

	/* It is possible that we have multiple paths for a prefix from a peer
	 * if that peer is using AddPath.
	 */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (pi->peer != peer)
			continue;

		/* graceful restart STALE flag set. */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)
		    && peer->nsf[afi][safi]
		    && !CHECK_FLAG(pi->flags, BGP_PATH_STALE)
		    && !CHECK_FLAG(pi->flags, BGP_PATH_UNUSEABLE))
			bgp_path_info_set_flag(dest, pi, BGP_PATH_STALE);
		else {
			/* If this is an EVPN route, process for
			 * un-import. */
			if (safi == SAFI_EVPN)
				bgp_evpn_unimport_route(
					bgp, afi, safi,
					bgp_dest_get_prefix(dest), pi);
			/* Handle withdraw for VRF route-leaking and L3VPN */
			if (SAFI_UNICAST == safi
			    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF ||
				bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
				vpn_leak_from_vrf_withdraw(bgp_get_default(),
							   bgp, pi);
			}
			if (SAFI_MPLS_VPN == safi &&
			    bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
				vpn_leak_to_vrf_withdraw(bgp, pi);
			}

			bgp_rib_remove(dest, pi, peer, afi, safi);
		}
	}
	return WQ_SUCCESS;
}

static void bgp_clear_node_queue_del(struct work_queue *wq, void *data)
{
	struct bgp_clear_node_queue *cnq = data;
	struct bgp_dest *dest = cnq->dest;
	struct bgp_table *table = bgp_dest_table(dest);

	bgp_dest_unlock_node(dest);
	bgp_table_unlock(table);
	XFREE(MTYPE_BGP_CLEAR_NODE_QUEUE, cnq);
}

static void bgp_clear_node_complete(struct work_queue *wq)
{
	struct peer *peer = wq->spec.data;

	/* Tickle FSM to start moving again */
	BGP_EVENT_ADD(peer, Clearing_Completed);

	peer_unlock(peer); /* bgp_clear_route */
}

static void bgp_clear_node_queue_init(struct peer *peer)
{
	char wname[sizeof("clear xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")];

	snprintf(wname, sizeof(wname), "clear %s", peer->host);
#undef CLEAR_QUEUE_NAME_LEN

	peer->clear_node_queue = work_queue_new(bm->master, wname);
	peer->clear_node_queue->spec.hold = 10;
	peer->clear_node_queue->spec.workfunc = &bgp_clear_route_node;
	peer->clear_node_queue->spec.del_item_data = &bgp_clear_node_queue_del;
	peer->clear_node_queue->spec.completion_func = &bgp_clear_node_complete;
	peer->clear_node_queue->spec.max_retries = 0;

	/* we only 'lock' this peer reference when the queue is actually active
	 */
	peer->clear_node_queue->spec.data = peer;
}

static void bgp_clear_route_table(struct peer *peer, afi_t afi, safi_t safi,
				  struct bgp_table *table)
{
	struct bgp_dest *dest;
	int force = peer->bgp->process_queue ? 0 : 1;

	if (!table)
		table = peer->bgp->rib[afi][safi];

	/* If still no table => afi/safi isn't configured at all or smth. */
	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		struct bgp_path_info *pi, *next;
		struct bgp_adj_in *ain;
		struct bgp_adj_in *ain_next;

		/* XXX:TODO: This is suboptimal, every non-empty route_node is
		 * queued for every clearing peer, regardless of whether it is
		 * relevant to the peer at hand.
		 *
		 * Overview: There are 3 different indices which need to be
		 * scrubbed, potentially, when a peer is removed:
		 *
		 * 1 peer's routes visible via the RIB (ie accepted routes)
		 * 2 peer's routes visible by the (optional) peer's adj-in index
		 * 3 other routes visible by the peer's adj-out index
		 *
		 * 3 there is no hurry in scrubbing, once the struct peer is
		 * removed from bgp->peer, we could just GC such deleted peer's
		 * adj-outs at our leisure.
		 *
		 * 1 and 2 must be 'scrubbed' in some way, at least made
		 * invisible via RIB index before peer session is allowed to be
		 * brought back up. So one needs to know when such a 'search' is
		 * complete.
		 *
		 * Ideally:
		 *
		 * - there'd be a single global queue or a single RIB walker
		 * - rather than tracking which route_nodes still need to be
		 *   examined on a peer basis, we'd track which peers still
		 *   aren't cleared
		 *
		 * Given that our per-peer prefix-counts now should be reliable,
		 * this may actually be achievable. It doesn't seem to be a huge
		 * problem at this time,
		 *
		 * It is possible that we have multiple paths for a prefix from
		 * a peer
		 * if that peer is using AddPath.
		 */
		ain = dest->adj_in;
		while (ain) {
			ain_next = ain->next;

			if (ain->peer == peer) {
				bgp_adj_in_remove(dest, ain);
				bgp_dest_unlock_node(dest);
			}

			ain = ain_next;
		}

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = next) {
			next = pi->next;
			if (pi->peer != peer)
				continue;

			if (force)
				bgp_path_info_reap(dest, pi);
			else {
				struct bgp_clear_node_queue *cnq;

				/* both unlocked in bgp_clear_node_queue_del */
				bgp_table_lock(bgp_dest_table(dest));
				bgp_dest_lock_node(dest);
				cnq = XCALLOC(
					MTYPE_BGP_CLEAR_NODE_QUEUE,
					sizeof(struct bgp_clear_node_queue));
				cnq->dest = dest;
				work_queue_add(peer->clear_node_queue, cnq);
				break;
			}
		}
	}
	return;
}

void bgp_clear_route(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;

	if (peer->clear_node_queue == NULL)
		bgp_clear_node_queue_init(peer);

	/* bgp_fsm.c keeps sessions in state Clearing, not transitioning to
	 * Idle until it receives a Clearing_Completed event. This protects
	 * against peers which flap faster than we can we clear, which could
	 * lead to:
	 *
	 * a) race with routes from the new session being installed before
	 *    clear_route_node visits the node (to delete the route of that
	 *    peer)
	 * b) resource exhaustion, clear_route_node likely leads to an entry
	 *    on the process_main queue. Fast-flapping could cause that queue
	 *    to grow and grow.
	 */

	/* lock peer in assumption that clear-node-queue will get nodes; if so,
	 * the unlock will happen upon work-queue completion; other wise, the
	 * unlock happens at the end of this function.
	 */
	if (!peer->clear_node_queue->thread)
		peer_lock(peer);

	if (safi != SAFI_MPLS_VPN && safi != SAFI_ENCAP && safi != SAFI_EVPN)
		bgp_clear_route_table(peer, afi, safi, NULL);
	else
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			bgp_clear_route_table(peer, afi, safi, table);
		}

	/* unlock if no nodes got added to the clear-node-queue. */
	if (!peer->clear_node_queue->thread)
		peer_unlock(peer);
}

void bgp_clear_route_all(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_route(peer, afi, safi);

#ifdef ENABLE_BGP_VNC
	rfapiProcessPeerDown(peer);
#endif
}

void bgp_clear_adj_in(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;
	struct bgp_adj_in *ain_next;

	table = peer->bgp->rib[afi][safi];

	/* It is possible that we have multiple paths for a prefix from a peer
	 * if that peer is using AddPath.
	 */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		ain = dest->adj_in;

		while (ain) {
			ain_next = ain->next;

			if (ain->peer == peer) {
				bgp_adj_in_remove(dest, ain);
				bgp_dest_unlock_node(dest);
			}

			ain = ain_next;
		}
	}
}

void bgp_clear_stale_route(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;

	if (safi == SAFI_MPLS_VPN) {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_dest *rm;

			/* look for neighbor in tables */
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				for (pi = bgp_dest_get_bgp_path_info(rm); pi;
				     pi = pi->next) {
					if (pi->peer != peer)
						continue;
					if (!CHECK_FLAG(pi->flags,
							BGP_PATH_STALE))
						break;

					bgp_rib_remove(rm, pi, peer, afi, safi);
					break;
				}
		}
	} else {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest))
			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;
				if (!CHECK_FLAG(pi->flags, BGP_PATH_STALE))
					break;
				bgp_rib_remove(dest, pi, peer, afi, safi);
				break;
			}
	}
}

bool bgp_outbound_policy_exists(struct peer *peer, struct bgp_filter *filter)
{
	if (peer->sort == BGP_PEER_IBGP)
		return true;

	if (peer->sort == BGP_PEER_EBGP
	    && (ROUTE_MAP_OUT_NAME(filter) || PREFIX_LIST_OUT_NAME(filter)
		|| FILTER_LIST_OUT_NAME(filter)
		|| DISTRIBUTE_OUT_NAME(filter)))
		return true;
	return false;
}

bool bgp_inbound_policy_exists(struct peer *peer, struct bgp_filter *filter)
{
	if (peer->sort == BGP_PEER_IBGP)
		return true;

	if (peer->sort == BGP_PEER_EBGP
	    && (ROUTE_MAP_IN_NAME(filter) || PREFIX_LIST_IN_NAME(filter)
		|| FILTER_LIST_IN_NAME(filter)
		|| DISTRIBUTE_IN_NAME(filter)))
		return true;
	return false;
}

static void bgp_cleanup_table(struct bgp *bgp, struct bgp_table *table,
			      safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *next;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = next) {
			const struct prefix *p = bgp_dest_get_prefix(dest);

			next = pi->next;

			/* Unimport EVPN routes from VRFs */
			if (safi == SAFI_EVPN)
				bgp_evpn_unimport_route(bgp, AFI_L2VPN,
							SAFI_EVPN, p, pi);

			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    && pi->type == ZEBRA_ROUTE_BGP
			    && (pi->sub_type == BGP_ROUTE_NORMAL
				|| pi->sub_type == BGP_ROUTE_AGGREGATE
				|| pi->sub_type == BGP_ROUTE_IMPORTED)) {

				if (bgp_fibupd_safi(safi))
					bgp_zebra_withdraw(p, pi, bgp, safi);
			}

			bgp_path_info_reap(dest, pi);
		}
}

/* Delete all kernel routes. */
void bgp_cleanup_routes(struct bgp *bgp)
{
	afi_t afi;
	struct bgp_dest *dest;
	struct bgp_table *table;

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		if (afi == AFI_L2VPN)
			continue;
		bgp_cleanup_table(bgp, bgp->rib[afi][SAFI_UNICAST],
				  SAFI_UNICAST);
		/*
		 * VPN and ENCAP and EVPN tables are two-level (RD is top level)
		 */
		if (afi != AFI_L2VPN) {
			safi_t safi;
			safi = SAFI_MPLS_VPN;
			for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
			     dest = bgp_route_next(dest)) {
				table = bgp_dest_get_bgp_table_info(dest);
				if (table != NULL) {
					bgp_cleanup_table(bgp, table, safi);
					bgp_table_finish(&table);
					bgp_dest_set_bgp_table_info(dest, NULL);
					bgp_dest_unlock_node(dest);
				}
			}
			safi = SAFI_ENCAP;
			for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
			     dest = bgp_route_next(dest)) {
				table = bgp_dest_get_bgp_table_info(dest);
				if (table != NULL) {
					bgp_cleanup_table(bgp, table, safi);
					bgp_table_finish(&table);
					bgp_dest_set_bgp_table_info(dest, NULL);
					bgp_dest_unlock_node(dest);
				}
			}
		}
	}
	for (dest = bgp_table_top(bgp->rib[AFI_L2VPN][SAFI_EVPN]); dest;
	     dest = bgp_route_next(dest)) {
		table = bgp_dest_get_bgp_table_info(dest);
		if (table != NULL) {
			bgp_cleanup_table(bgp, table, SAFI_EVPN);
			bgp_table_finish(&table);
			bgp_dest_set_bgp_table_info(dest, NULL);
			bgp_dest_unlock_node(dest);
		}
	}
}

void bgp_reset(void)
{
	vty_reset();
	bgp_zclient_reset();
	access_list_reset();
	prefix_list_reset();
}

static int bgp_addpath_encode_rx(struct peer *peer, afi_t afi, safi_t safi)
{
	return (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		&& CHECK_FLAG(peer->af_cap[afi][safi],
			      PEER_CAP_ADDPATH_AF_TX_RCV));
}

/* Parse NLRI stream.  Withdraw NLRI is recognized by NULL attr
   value. */
int bgp_nlri_parse_ip(struct peer *peer, struct attr *attr,
		      struct bgp_nlri *packet)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize;
	int ret;
	afi_t afi;
	safi_t safi;
	int addpath_encoded;
	uint32_t addpath_id;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;
	addpath_encoded = bgp_addpath_encode_rx(peer, afi, safi);

	/* RFC4771 6.3 The NLRI field in the UPDATE message is checked for
	   syntactic validity.  If the field is syntactically incorrect,
	   then the Error Subcode is set to Invalid Network Field. */
	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		if (addpath_encoded) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN >= lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		p.prefixlen = *pnt++;
		/* afi/safi validity already verified by caller,
		 * bgp_update_receive */
		p.family = afi2family(afi);

		/* Prefix length check. */
		if (p.prefixlen > prefix_blen(&p) * 8) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error (wrong prefix length %d for afi %u)",
				peer->host, p.prefixlen, packet->afi);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* Packet size overflow check. */
		psize = PSIZE(p.prefixlen);

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error (prefix length %d overflows packet)",
				peer->host, p.prefixlen);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Defensive coding, double-check the psize fits in a struct
		 * prefix */
		if (psize > (ssize_t)sizeof(p.u)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error (prefix length %d too large for prefix storage %zu)",
				peer->host, p.prefixlen, sizeof(p.u));
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		/* Fetch prefix from NLRI packet. */
		memcpy(p.u.val, pnt, psize);

		/* Check address. */
		if (afi == AFI_IP && safi == SAFI_UNICAST) {
			if (IN_CLASSD(ntohl(p.u.prefix4.s_addr))) {
				/* From RFC4271 Section 6.3:
				 *
				 * If a prefix in the NLRI field is semantically
				 * incorrect
				 * (e.g., an unexpected multicast IP address),
				 * an error SHOULD
				 * be logged locally, and the prefix SHOULD be
				 * ignored.
				 */
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv4 unicast NLRI is multicast address %pI4, ignoring",
					peer->host, &p.u.prefix4);
				continue;
			}
		}

		/* Check address. */
		if (afi == AFI_IP6 && safi == SAFI_UNICAST) {
			if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
				char buf[BUFSIZ];

				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is link-local address %s, ignoring",
					peer->host,
					inet_ntop(AF_INET6, &p.u.prefix6, buf,
						  BUFSIZ));

				continue;
			}
			if (IN6_IS_ADDR_MULTICAST(&p.u.prefix6)) {
				char buf[BUFSIZ];

				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is multicast address %s, ignoring",
					peer->host,
					inet_ntop(AF_INET6, &p.u.prefix6, buf,
						  BUFSIZ));

				continue;
			}
		}

		/* Normal process. */
		if (attr)
			ret = bgp_update(peer, &p, addpath_id, attr, afi, safi,
					 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
					 NULL, NULL, 0, 0, NULL);
		else
			ret = bgp_withdraw(peer, &p, addpath_id, attr, afi,
					   safi, ZEBRA_ROUTE_BGP,
					   BGP_ROUTE_NORMAL, NULL, NULL, 0,
					   NULL);

		/* Do not send BGP notification twice when maximum-prefix count
		 * overflow. */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
			return BGP_NLRI_PARSE_ERROR_PREFIX_OVERFLOW;

		/* Address family configuration mismatch. */
		if (ret < 0)
			return BGP_NLRI_PARSE_ERROR_ADDRESS_FAMILY;
	}

	/* Packet length consistency check. */
	if (pnt != lim) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error (prefix length mismatch with total length)",
			peer->host);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	return BGP_NLRI_PARSE_OK;
}

static struct bgp_static *bgp_static_new(void)
{
	return XCALLOC(MTYPE_BGP_STATIC, sizeof(struct bgp_static));
}

static void bgp_static_free(struct bgp_static *bgp_static)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
	route_map_counter_decrement(bgp_static->rmap.map);

	XFREE(MTYPE_ATTR, bgp_static->eth_s_id);
	XFREE(MTYPE_BGP_STATIC, bgp_static);
}

void bgp_static_update(struct bgp *bgp, const struct prefix *p,
		       struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct bgp_path_info rmap_path;
	struct attr attr;
	struct attr *attr_new;
	route_map_result_t ret;
#ifdef ENABLE_BGP_VNC
	int vnc_implicit_withdraw = 0;
#endif

	assert(bgp_static);

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);

	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);

	attr.nexthop = bgp_static->igpnexthop;
	attr.med = bgp_static->igpmetric;
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);

	if (bgp_static->atomic)
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);

	/* Store label index, if required. */
	if (bgp_static->label_index != BGP_INVALID_LABEL_INDEX) {
		attr.label_index = bgp_static->label_index;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID);
	}

	/* Apply route-map. */
	if (bgp_static->rmap.name) {
		struct attr attr_tmp = attr;

		memset(&rmap_path, 0, sizeof(struct bgp_path_info));
		rmap_path.peer = bgp->peer_self;
		rmap_path.attr = &attr_tmp;

		SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

		ret = route_map_apply(bgp_static->rmap.map, p, &rmap_path);

		bgp->peer_self->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			/* Free uninterned attribute. */
			bgp_attr_flush(&attr_tmp);

			/* Unintern original. */
			aspath_unintern(&attr.aspath);
			bgp_static_withdraw(bgp, p, afi, safi);
			return;
		}

		if (bgp_in_graceful_shutdown(bgp))
			bgp_attr_add_gshut_community(&attr_tmp);

		attr_new = bgp_attr_intern(&attr_tmp);
	} else {

		if (bgp_in_graceful_shutdown(bgp))
			bgp_attr_add_gshut_community(&attr);

		attr_new = bgp_attr_intern(&attr);
	}

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP
		    && pi->sub_type == BGP_ROUTE_STATIC)
			break;

	if (pi) {
		if (attrhash_cmp(pi->attr, attr_new)
		    && !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)
		    && !CHECK_FLAG(bgp->flags, BGP_FLAG_FORCE_STATIC_PROCESS)) {
			bgp_dest_unlock_node(dest);
			bgp_attr_unintern(&attr_new);
			aspath_unintern(&attr.aspath);
			return;
		} else {
			/* The attribute is changed. */
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);

			/* Rewrite BGP route information. */
			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, pi);
			else
				bgp_aggregate_decrement(bgp, p, pi, afi, safi);
#ifdef ENABLE_BGP_VNC
			if ((afi == AFI_IP || afi == AFI_IP6)
			    && (safi == SAFI_UNICAST)) {
				if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
					/*
					 * Implicit withdraw case.
					 * We have to do this before pi is
					 * changed
					 */
					++vnc_implicit_withdraw;
					vnc_import_bgp_del_route(bgp, p, pi);
					vnc_import_bgp_exterior_del_route(
						bgp, p, pi);
				}
			}
#endif
			bgp_attr_unintern(&pi->attr);
			pi->attr = attr_new;
			pi->uptime = bgp_clock();
#ifdef ENABLE_BGP_VNC
			if ((afi == AFI_IP || afi == AFI_IP6)
			    && (safi == SAFI_UNICAST)) {
				if (vnc_implicit_withdraw) {
					vnc_import_bgp_add_route(bgp, p, pi);
					vnc_import_bgp_exterior_add_route(
						bgp, p, pi);
				}
			}
#endif

			/* Nexthop reachability check. */
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)
			    && (safi == SAFI_UNICAST
				|| safi == SAFI_LABELED_UNICAST)) {

				struct bgp *bgp_nexthop = bgp;

				if (pi->extra && pi->extra->bgp_orig)
					bgp_nexthop = pi->extra->bgp_orig;

				if (bgp_find_or_add_nexthop(bgp, bgp_nexthop,
							    afi, pi, NULL, 0))
					bgp_path_info_set_flag(dest, pi,
							       BGP_PATH_VALID);
				else {
					if (BGP_DEBUG(nht, NHT)) {
						char buf1[INET6_ADDRSTRLEN];
						inet_ntop(p->family,
							  &p->u.prefix, buf1,
							  INET6_ADDRSTRLEN);
						zlog_debug(
							"%s(%s): Route not in table, not advertising",
							__func__, buf1);
					}
					bgp_path_info_unset_flag(
						dest, pi, BGP_PATH_VALID);
				}
			} else {
				/* Delete the NHT structure if any, if we're
				 * toggling between
				 * enabling/disabling import check. We
				 * deregister the route
				 * from NHT to avoid overloading NHT and the
				 * process interaction
				 */
				bgp_unlink_nexthop(pi);
				bgp_path_info_set_flag(dest, pi,
						       BGP_PATH_VALID);
			}
			/* Process change. */
			bgp_aggregate_increment(bgp, p, pi, afi, safi);
			bgp_process(bgp, dest, afi, safi);

			if (SAFI_UNICAST == safi
			    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
				|| bgp->inst_type
					   == BGP_INSTANCE_TYPE_DEFAULT)) {
				vpn_leak_from_vrf_update(bgp_get_default(), bgp,
							 pi);
			}

			bgp_dest_unlock_node(dest);
			aspath_unintern(&attr.aspath);
			return;
		}
	}

	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self,
			attr_new, dest);
	/* Nexthop reachability check. */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)
	    && (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST)) {
		if (bgp_find_or_add_nexthop(bgp, bgp, afi, new, NULL, 0))
			bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
		else {
			if (BGP_DEBUG(nht, NHT)) {
				char buf1[INET6_ADDRSTRLEN];
				inet_ntop(p->family, &p->u.prefix, buf1,
					  INET6_ADDRSTRLEN);
				zlog_debug(
					"%s(%s): Route not in table, not advertising",
					__func__, buf1);
			}
			bgp_path_info_unset_flag(dest, new, BGP_PATH_VALID);
		}
	} else {
		/* Delete the NHT structure if any, if we're toggling between
		 * enabling/disabling import check. We deregister the route
		 * from NHT to avoid overloading NHT and the process interaction
		 */
		bgp_unlink_nexthop(new);

		bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
	}

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, p, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, afi, safi);

	if (SAFI_UNICAST == safi
	    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
		|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
		vpn_leak_from_vrf_update(bgp_get_default(), bgp, new);
	}

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

void bgp_static_withdraw(struct bgp *bgp, const struct prefix *p, afi_t afi,
			 safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);

	/* Check selected route and self inserted route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP
		    && pi->sub_type == BGP_ROUTE_STATIC)
			break;

	/* Withdraw static BGP route from routing table. */
	if (pi) {
		if (SAFI_UNICAST == safi
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
			|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
			vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp, pi);
		}
		bgp_aggregate_decrement(bgp, p, pi, afi, safi);
		bgp_unlink_nexthop(pi);
		bgp_path_info_delete(dest, pi);
		bgp_process(bgp, dest, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
	bgp_dest_unlock_node(dest);
}

/*
 * Used for SAFI_MPLS_VPN and SAFI_ENCAP
 */
static void bgp_static_withdraw_safi(struct bgp *bgp, const struct prefix *p,
				     afi_t afi, safi_t safi,
				     struct prefix_rd *prd)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	/* Check selected route and self inserted route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP
		    && pi->sub_type == BGP_ROUTE_STATIC)
			break;

	/* Withdraw static BGP route from routing table. */
	if (pi) {
#ifdef ENABLE_BGP_VNC
		rfapiProcessWithdraw(
			pi->peer, NULL, p, prd, pi->attr, afi, safi, pi->type,
			1); /* Kill, since it is an administrative change */
#endif
		if (SAFI_MPLS_VPN == safi
		    && bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			vpn_leak_to_vrf_withdraw(bgp, pi);
		}
		bgp_aggregate_decrement(bgp, p, pi, afi, safi);
		bgp_path_info_delete(dest, pi);
		bgp_process(bgp, dest, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
	bgp_dest_unlock_node(dest);
}

static void bgp_static_update_safi(struct bgp *bgp, const struct prefix *p,
				   struct bgp_static *bgp_static, afi_t afi,
				   safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *new;
	struct attr *attr_new;
	struct attr attr = {0};
	struct bgp_path_info *pi;
#ifdef ENABLE_BGP_VNC
	mpls_label_t label = 0;
#endif
	uint32_t num_labels = 0;
	union gw_addr add;

	assert(bgp_static);

	if (bgp_static->label != MPLS_INVALID_LABEL)
		num_labels = 1;
	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p,
				&bgp_static->prd);

	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);

	attr.nexthop = bgp_static->igpnexthop;
	attr.med = bgp_static->igpmetric;
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);

	if ((safi == SAFI_EVPN) || (safi == SAFI_MPLS_VPN)
	    || (safi == SAFI_ENCAP)) {
		if (afi == AFI_IP) {
			attr.mp_nexthop_global_in = bgp_static->igpnexthop;
			attr.mp_nexthop_len = IPV4_MAX_BYTELEN;
		}
	}
	if (afi == AFI_L2VPN) {
		if (bgp_static->gatewayIp.family == AF_INET)
			add.ipv4.s_addr =
				bgp_static->gatewayIp.u.prefix4.s_addr;
		else if (bgp_static->gatewayIp.family == AF_INET6)
			memcpy(&(add.ipv6), &(bgp_static->gatewayIp.u.prefix6),
			       sizeof(struct in6_addr));
		memcpy(&attr.esi, bgp_static->eth_s_id, sizeof(esi_t));
		if (bgp_static->encap_tunneltype == BGP_ENCAP_TYPE_VXLAN) {
			struct bgp_encap_type_vxlan bet;
			memset(&bet, 0, sizeof(struct bgp_encap_type_vxlan));
			bet.vnid = p->u.prefix_evpn.prefix_addr.eth_tag;
			bgp_encap_type_vxlan_to_tlv(&bet, &attr);
		}
		if (bgp_static->router_mac) {
			bgp_add_routermac_ecom(&attr, bgp_static->router_mac);
		}
	}
	/* Apply route-map. */
	if (bgp_static->rmap.name) {
		struct attr attr_tmp = attr;
		struct bgp_path_info rmap_path;
		route_map_result_t ret;

		rmap_path.peer = bgp->peer_self;
		rmap_path.attr = &attr_tmp;

		SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

		ret = route_map_apply(bgp_static->rmap.map, p, &rmap_path);

		bgp->peer_self->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			/* Free uninterned attribute. */
			bgp_attr_flush(&attr_tmp);

			/* Unintern original. */
			aspath_unintern(&attr.aspath);
			bgp_static_withdraw_safi(bgp, p, afi, safi,
						 &bgp_static->prd);
			return;
		}

		attr_new = bgp_attr_intern(&attr_tmp);
	} else {
		attr_new = bgp_attr_intern(&attr);
	}

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP
		    && pi->sub_type == BGP_ROUTE_STATIC)
			break;

	if (pi) {
		memset(&add, 0, sizeof(union gw_addr));
		if (attrhash_cmp(pi->attr, attr_new)
		    && overlay_index_equal(afi, pi, &add)
		    && !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			bgp_dest_unlock_node(dest);
			bgp_attr_unintern(&attr_new);
			aspath_unintern(&attr.aspath);
			return;
		} else {
			/* The attribute is changed. */
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);

			/* Rewrite BGP route information. */
			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, pi);
			else
				bgp_aggregate_decrement(bgp, p, pi, afi, safi);
			bgp_attr_unintern(&pi->attr);
			pi->attr = attr_new;
			pi->uptime = bgp_clock();
#ifdef ENABLE_BGP_VNC
			if (pi->extra)
				label = decode_label(&pi->extra->label[0]);
#endif

			/* Process change. */
			bgp_aggregate_increment(bgp, p, pi, afi, safi);
			bgp_process(bgp, dest, afi, safi);

			if (SAFI_MPLS_VPN == safi
			    && bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
				vpn_leak_to_vrf_update(bgp, pi);
			}
#ifdef ENABLE_BGP_VNC
			rfapiProcessUpdate(pi->peer, NULL, p, &bgp_static->prd,
					   pi->attr, afi, safi, pi->type,
					   pi->sub_type, &label);
#endif
			bgp_dest_unlock_node(dest);
			aspath_unintern(&attr.aspath);
			return;
		}
	}


	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self,
			attr_new, dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);
	new->extra = bgp_path_info_extra_new();
	if (num_labels) {
		new->extra->label[0] = bgp_static->label;
		new->extra->num_labels = num_labels;
	}
#ifdef ENABLE_BGP_VNC
	label = decode_label(&bgp_static->label);
#endif

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, p, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);
	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, afi, safi);

	if (SAFI_MPLS_VPN == safi
	    && bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
		vpn_leak_to_vrf_update(bgp, new);
	}
#ifdef ENABLE_BGP_VNC
	rfapiProcessUpdate(new->peer, NULL, p, &bgp_static->prd, new->attr, afi,
			   safi, new->type, new->sub_type, &label);
#endif

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

/* Configure static BGP network.  When user don't run zebra, static
   route should be installed as valid.  */
int bgp_static_set(struct bgp *bgp, const char *negate, struct prefix *pfx,
		   afi_t afi, safi_t safi, const char *rmap, int backdoor,
		   uint32_t label_index, char *errmsg, size_t errmsg_len)
{
	struct prefix p;
	struct bgp_static *bgp_static;
	struct bgp_dest *dest;
	uint8_t need_update = 0;

	prefix_copy(&p, pfx);
	apply_mask(&p);

	if (negate) {

		/* Set BGP static route configuration. */
		dest = bgp_node_lookup(bgp->route[afi][safi], &p);

		if (!dest) {
			snprintf(errmsg, errmsg_len,
				 "Can't find static route specified\n");
			return -1;
		}

		bgp_static = bgp_dest_get_bgp_static_info(dest);

		if ((label_index != BGP_INVALID_LABEL_INDEX)
		    && (label_index != bgp_static->label_index)) {
			snprintf(errmsg, errmsg_len,
				 "label-index doesn't match static route\n");
			return -1;
		}

		if ((rmap && bgp_static->rmap.name)
		    && strcmp(rmap, bgp_static->rmap.name)) {
			snprintf(errmsg, errmsg_len,
				 "route-map name doesn't match static route\n");
			return -1;
		}

		/* Update BGP RIB. */
		if (!bgp_static->backdoor)
			bgp_static_withdraw(bgp, &p, afi, safi);

		/* Clear configuration. */
		bgp_static_free(bgp_static);
		bgp_dest_set_bgp_static_info(dest, NULL);
		bgp_dest_unlock_node(dest);
		bgp_dest_unlock_node(dest);
	} else {

		/* Set BGP static route configuration. */
		dest = bgp_node_get(bgp->route[afi][safi], &p);
		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static) {
			/* Configuration change. */
			/* Label index cannot be changed. */
			if (bgp_static->label_index != label_index) {
				snprintf(errmsg, errmsg_len,
					 "cannot change label-index\n");
				return -1;
			}

			/* Check previous routes are installed into BGP.  */
			if (bgp_static->valid
			    && bgp_static->backdoor != backdoor)
				need_update = 1;

			bgp_static->backdoor = backdoor;

			if (rmap) {
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp_static->rmap.name);
				route_map_counter_decrement(
					bgp_static->rmap.map);
				bgp_static->rmap.name =
					XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
				bgp_static->rmap.map =
					route_map_lookup_by_name(rmap);
				route_map_counter_increment(
					bgp_static->rmap.map);
			} else {
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp_static->rmap.name);
				route_map_counter_decrement(
					bgp_static->rmap.map);
				bgp_static->rmap.map = NULL;
				bgp_static->valid = 0;
			}
			bgp_dest_unlock_node(dest);
		} else {
			/* New configuration. */
			bgp_static = bgp_static_new();
			bgp_static->backdoor = backdoor;
			bgp_static->valid = 0;
			bgp_static->igpmetric = 0;
			bgp_static->igpnexthop.s_addr = INADDR_ANY;
			bgp_static->label_index = label_index;

			if (rmap) {
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp_static->rmap.name);
				route_map_counter_decrement(
					bgp_static->rmap.map);
				bgp_static->rmap.name =
					XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
				bgp_static->rmap.map =
					route_map_lookup_by_name(rmap);
				route_map_counter_increment(
					bgp_static->rmap.map);
			}
			bgp_dest_set_bgp_static_info(dest, bgp_static);
		}

		bgp_static->valid = 1;
		if (need_update)
			bgp_static_withdraw(bgp, &p, afi, safi);

		if (!bgp_static->backdoor)
			bgp_static_update(bgp, &p, bgp_static, afi, safi);
	}

	return 0;
}

void bgp_static_add(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	FOREACH_AFI_SAFI (afi, safi)
		for (dest = bgp_table_top(bgp->route[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			if (!bgp_dest_has_bgp_path_info_data(dest))
				continue;

			if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
			    || (safi == SAFI_EVPN)) {
				table = bgp_dest_get_bgp_table_info(dest);

				for (rm = bgp_table_top(table); rm;
				     rm = bgp_route_next(rm)) {
					bgp_static =
						bgp_dest_get_bgp_static_info(
							rm);
					bgp_static_update_safi(
						bgp, bgp_dest_get_prefix(rm),
						bgp_static, afi, safi);
				}
			} else {
				bgp_static_update(
					bgp, bgp_dest_get_prefix(dest),
					bgp_dest_get_bgp_static_info(dest), afi,
					safi);
			}
		}
}

/* Called from bgp_delete().  Delete all static routes from the BGP
   instance. */
void bgp_static_delete(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	FOREACH_AFI_SAFI (afi, safi)
		for (dest = bgp_table_top(bgp->route[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			if (!bgp_dest_has_bgp_path_info_data(dest))
				continue;

			if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
			    || (safi == SAFI_EVPN)) {
				table = bgp_dest_get_bgp_table_info(dest);

				for (rm = bgp_table_top(table); rm;
				     rm = bgp_route_next(rm)) {
					bgp_static =
						bgp_dest_get_bgp_static_info(
							rm);
					if (!bgp_static)
						continue;

					bgp_static_withdraw_safi(
						bgp, bgp_dest_get_prefix(rm),
						AFI_IP, safi,
						(struct prefix_rd *)
							bgp_dest_get_prefix(
								dest));
					bgp_static_free(bgp_static);
					bgp_dest_set_bgp_static_info(rm,
								     NULL);
					bgp_dest_unlock_node(rm);
				}
			} else {
				bgp_static = bgp_dest_get_bgp_static_info(dest);
				bgp_static_withdraw(bgp,
						    bgp_dest_get_prefix(dest),
						    afi, safi);
				bgp_static_free(bgp_static);
				bgp_dest_set_bgp_static_info(dest, NULL);
				bgp_dest_unlock_node(dest);
			}
		}
}

void bgp_static_redo_import_check(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	/* Use this flag to force reprocessing of the route */
	SET_FLAG(bgp->flags, BGP_FLAG_FORCE_STATIC_PROCESS);
	FOREACH_AFI_SAFI (afi, safi) {
		for (dest = bgp_table_top(bgp->route[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			if (!bgp_dest_has_bgp_path_info_data(dest))
				continue;

			if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
			    || (safi == SAFI_EVPN)) {
				table = bgp_dest_get_bgp_table_info(dest);

				for (rm = bgp_table_top(table); rm;
				     rm = bgp_route_next(rm)) {
					bgp_static =
						bgp_dest_get_bgp_static_info(
							rm);
					bgp_static_update_safi(
						bgp, bgp_dest_get_prefix(rm),
						bgp_static, afi, safi);
				}
			} else {
				bgp_static = bgp_dest_get_bgp_static_info(dest);
				bgp_static_update(bgp,
						  bgp_dest_get_prefix(dest),
						  bgp_static, afi, safi);
			}
		}
	}
	UNSET_FLAG(bgp->flags, BGP_FLAG_FORCE_STATIC_PROCESS);
}

static void bgp_purge_af_static_redist_routes(struct bgp *bgp, afi_t afi,
					      safi_t safi)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	/* Do not install the aggregate route if BGP is in the
	 * process of termination.
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS)
	    || (bgp->peer_self == NULL))
		return;

	table = bgp->rib[afi][safi];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (pi->peer == bgp->peer_self
			    && ((pi->type == ZEBRA_ROUTE_BGP
				 && pi->sub_type == BGP_ROUTE_STATIC)
				|| (pi->type != ZEBRA_ROUTE_BGP
				    && pi->sub_type
					       == BGP_ROUTE_REDISTRIBUTE))) {
				bgp_aggregate_decrement(
					bgp, bgp_dest_get_prefix(dest), pi, afi,
					safi);
				bgp_unlink_nexthop(pi);
				bgp_path_info_delete(dest, pi);
				bgp_process(bgp, dest, afi, safi);
			}
		}
	}
}

/*
 * Purge all networks and redistributed routes from routing table.
 * Invoked upon the instance going down.
 */
void bgp_purge_static_redist_routes(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_purge_af_static_redist_routes(bgp, afi, safi);
}

/*
 * gpz 110624
 * Currently this is used to set static routes for VPN and ENCAP.
 * I think it can probably be factored with bgp_static_set.
 */
int bgp_static_set_safi(afi_t afi, safi_t safi, struct vty *vty,
			const char *ip_str, const char *rd_str,
			const char *label_str, const char *rmap_str,
			int evpn_type, const char *esi, const char *gwip,
			const char *ethtag, const char *routermac)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest;
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_static *bgp_static;
	mpls_label_t label = MPLS_INVALID_LABEL;
	struct prefix gw_ip;

	/* validate ip prefix */
	ret = str2prefix(ip_str, &p);
	if (!ret) {
		vty_out(vty, "%% Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask(&p);
	if ((afi == AFI_L2VPN)
	    && (bgp_build_evpn_prefix(evpn_type,
				      ethtag != NULL ? atol(ethtag) : 0, &p))) {
		vty_out(vty, "%% L2VPN prefix could not be forged\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = str2prefix_rd(rd_str, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (label_str) {
		unsigned long label_val;
		label_val = strtoul(label_str, NULL, 10);
		encode_label(label_val, &label);
	}

	if (safi == SAFI_EVPN) {
		if (esi && str2esi(esi, NULL) == 0) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (routermac && prefix_str2mac(routermac, NULL) == 0) {
			vty_out(vty, "%% Malformed Router MAC\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (gwip) {
			memset(&gw_ip, 0, sizeof(struct prefix));
			ret = str2prefix(gwip, &gw_ip);
			if (!ret) {
				vty_out(vty, "%% Malformed GatewayIp\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			if ((gw_ip.family == AF_INET
			     && is_evpn_prefix_ipaddr_v6(
					(struct prefix_evpn *)&p))
			    || (gw_ip.family == AF_INET6
				&& is_evpn_prefix_ipaddr_v4(
					   (struct prefix_evpn *)&p))) {
				vty_out(vty,
					"%% GatewayIp family differs with IP prefix\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}
	pdest = bgp_node_get(bgp->route[afi][safi], (struct prefix *)&prd);
	if (!bgp_dest_has_bgp_path_info_data(pdest))
		bgp_dest_set_bgp_table_info(pdest,
					    bgp_table_init(bgp, afi, safi));
	table = bgp_dest_get_bgp_table_info(pdest);

	dest = bgp_node_get(table, &p);

	if (bgp_dest_has_bgp_path_info_data(dest)) {
		vty_out(vty, "%% Same network configuration exists\n");
		bgp_dest_unlock_node(dest);
	} else {
		/* New configuration. */
		bgp_static = bgp_static_new();
		bgp_static->backdoor = 0;
		bgp_static->valid = 0;
		bgp_static->igpmetric = 0;
		bgp_static->igpnexthop.s_addr = INADDR_ANY;
		bgp_static->label = label;
		bgp_static->prd = prd;

		if (rmap_str) {
			XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
			route_map_counter_decrement(bgp_static->rmap.map);
			bgp_static->rmap.name =
				XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);
			bgp_static->rmap.map =
				route_map_lookup_by_name(rmap_str);
			route_map_counter_increment(bgp_static->rmap.map);
		}

		if (safi == SAFI_EVPN) {
			if (esi) {
				bgp_static->eth_s_id =
					XCALLOC(MTYPE_ATTR,
						sizeof(esi_t));
				str2esi(esi, bgp_static->eth_s_id);
			}
			if (routermac) {
				bgp_static->router_mac =
					XCALLOC(MTYPE_ATTR, ETH_ALEN + 1);
				(void)prefix_str2mac(routermac,
						     bgp_static->router_mac);
			}
			if (gwip)
				prefix_copy(&bgp_static->gatewayIp, &gw_ip);
		}
		bgp_dest_set_bgp_static_info(dest, bgp_static);

		bgp_static->valid = 1;
		bgp_static_update_safi(bgp, &p, bgp_static, afi, safi);
	}

	return CMD_SUCCESS;
}

/* Configure static BGP network. */
int bgp_static_unset_safi(afi_t afi, safi_t safi, struct vty *vty,
			  const char *ip_str, const char *rd_str,
			  const char *label_str, int evpn_type, const char *esi,
			  const char *gwip, const char *ethtag)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest;
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_static *bgp_static;
	mpls_label_t label = MPLS_INVALID_LABEL;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(ip_str, &p);
	if (!ret) {
		vty_out(vty, "%% Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask(&p);
	if ((afi == AFI_L2VPN)
	    && (bgp_build_evpn_prefix(evpn_type,
				      ethtag != NULL ? atol(ethtag) : 0, &p))) {
		vty_out(vty, "%% L2VPN prefix could not be forged\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	ret = str2prefix_rd(rd_str, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed rd\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (label_str) {
		unsigned long label_val;
		label_val = strtoul(label_str, NULL, 10);
		encode_label(label_val, &label);
	}

	pdest = bgp_node_get(bgp->route[afi][safi], (struct prefix *)&prd);
	if (!bgp_dest_has_bgp_path_info_data(pdest))
		bgp_dest_set_bgp_table_info(pdest,
					    bgp_table_init(bgp, afi, safi));
	else
		bgp_dest_unlock_node(pdest);
	table = bgp_dest_get_bgp_table_info(pdest);

	dest = bgp_node_lookup(table, &p);

	if (dest) {
		bgp_static_withdraw_safi(bgp, &p, afi, safi, &prd);

		bgp_static = bgp_dest_get_bgp_static_info(dest);
		bgp_static_free(bgp_static);
		bgp_dest_set_bgp_static_info(dest, NULL);
		bgp_dest_unlock_node(dest);
		bgp_dest_unlock_node(dest);
	} else
		vty_out(vty, "%% Can't find the route\n");

	return CMD_SUCCESS;
}

static int bgp_table_map_set(struct vty *vty, afi_t afi, safi_t safi,
			     const char *rmap_name)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_rmap *rmap;

	rmap = &bgp->table_map[afi][safi];
	if (rmap_name) {
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
		route_map_counter_decrement(rmap->map);
		rmap->name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
		rmap->map = route_map_lookup_by_name(rmap_name);
		route_map_counter_increment(rmap->map);
	} else {
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
		route_map_counter_decrement(rmap->map);
		rmap->map = NULL;
	}

	if (bgp_fibupd_safi(safi))
		bgp_zebra_announce_table(bgp, afi, safi);

	return CMD_SUCCESS;
}

static int bgp_table_map_unset(struct vty *vty, afi_t afi, safi_t safi,
			       const char *rmap_name)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_rmap *rmap;

	rmap = &bgp->table_map[afi][safi];
	XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
	route_map_counter_decrement(rmap->map);
	rmap->map = NULL;

	if (bgp_fibupd_safi(safi))
		bgp_zebra_announce_table(bgp, afi, safi);

	return CMD_SUCCESS;
}

void bgp_config_write_table_map(struct vty *vty, struct bgp *bgp, afi_t afi,
				safi_t safi)
{
	if (bgp->table_map[afi][safi].name) {
		vty_out(vty, "  table-map %s\n",
			bgp->table_map[afi][safi].name);
	}
}

DEFUN (bgp_table_map,
       bgp_table_map_cmd,
       "table-map WORD",
       "BGP table to RIB route download filter\n"
       "Name of the route map\n")
{
	int idx_word = 1;
	return bgp_table_map_set(vty, bgp_node_afi(vty), bgp_node_safi(vty),
				 argv[idx_word]->arg);
}
DEFUN (no_bgp_table_map,
       no_bgp_table_map_cmd,
       "no table-map WORD",
       NO_STR
       "BGP table to RIB route download filter\n"
       "Name of the route map\n")
{
	int idx_word = 2;
	return bgp_table_map_unset(vty, bgp_node_afi(vty), bgp_node_safi(vty),
				   argv[idx_word]->arg);
}

DEFPY_YANG (bgp_network, bgp_network_cmd,
	    "[no] network \
	    <A.B.C.D/M$prefix|A.B.C.D$address [mask A.B.C.D$netmask]> \
	    [{route-map WORD$map_name|label-index (0-1048560)$label_index| \
	    backdoor$backdoor}]",
	    NO_STR
	    "Specify a network to announce via BGP\n"
	    "IPv4 prefix\n"
	    "Network number\n"
	    "Network mask\n"
	    "Network mask\n"
	    "Route-map to modify the attributes\n"
	    "Name of the route map\n"
	    "Label index to associate with the prefix\n"
	    "Label index value\n"
	    "Specify a BGP backdoor route\n")
{
	char addr_prefix_str[PREFIX_STRLEN];
	char base_xpath[XPATH_MAXLEN];
	afi_t afi;
	safi_t safi;

	if (address_str) {
		int ret;

		ret = netmask_str2prefix_str(address_str, netmask_str,
					     addr_prefix_str);
		if (!ret) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

		if (map_name)
			nb_cli_enqueue_change(vty, "./rmap-policy-export",
					      NB_OP_CREATE, map_name);
		else
			nb_cli_enqueue_change(vty, "./rmap-policy-export",
					      NB_OP_DESTROY, NULL);

		if (label_index_str)
			nb_cli_enqueue_change(vty, "./label-index",
					      NB_OP_MODIFY, label_index_str);

		nb_cli_enqueue_change(vty, "./backdoor", NB_OP_MODIFY,
				      backdoor ? "true" : "false");
	}

	snprintf(
		base_xpath, sizeof(base_xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/network-config[prefix='%s']",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi),
		address_str ? addr_prefix_str : prefix_str);

	return nb_cli_apply_changes(vty, base_xpath);
}

DEFPY_YANG (ipv6_bgp_network,
	    ipv6_bgp_network_cmd,
	    "[no] network X:X::X:X/M$prefix \
	    [{route-map WORD$map_name|label-index (0-1048560)$label_index}]",
	    NO_STR
	    "Specify a network to announce via BGP\n"
	    "IPv6 prefix\n"
	    "Route-map to modify the attributes\n"
	    "Name of the route map\n"
	    "Label index to associate with the prefix\n"
	    "Label index value\n")
{
	char base_xpath[XPATH_MAXLEN];
	afi_t afi;
	safi_t safi;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

		if (map_name)
			nb_cli_enqueue_change(vty, "./rmap-policy-export",
					      NB_OP_MODIFY, map_name);
		else
			nb_cli_enqueue_change(vty, "./rmap-policy-export",
					      NB_OP_DESTROY, NULL);

		if (label_index_str)
			nb_cli_enqueue_change(vty, "./label-index",
					      NB_OP_MODIFY, label_index_str);
	}

	snprintf(
		base_xpath, sizeof(base_xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/network-config[prefix='%s']",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi), prefix_str);

	return nb_cli_apply_changes(vty, base_xpath);
}

void cli_show_bgp_global_afi_safi_network_config(struct vty *vty,
						 struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, "  network %s", yang_dnode_get_string(dnode, "./prefix"));

	if (yang_dnode_exists(dnode, "./label-index"))
		vty_out(vty, " label-index %s",
			yang_dnode_get_string(dnode, "./label-index"));

	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./rmap-policy-export"));

	if (yang_dnode_get_bool(dnode, "./backdoor"))
		vty_out(vty, " backdoor");

	vty_out(vty, "\n");
}

static struct bgp_aggregate *bgp_aggregate_new(void)
{
	return XCALLOC(MTYPE_BGP_AGGREGATE, sizeof(struct bgp_aggregate));
}

static void bgp_aggregate_free(struct bgp_aggregate *aggregate)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, aggregate->suppress_map_name);
	route_map_counter_decrement(aggregate->suppress_map);
	XFREE(MTYPE_ROUTE_MAP_NAME, aggregate->rmap.name);
	route_map_counter_decrement(aggregate->rmap.map);
	XFREE(MTYPE_BGP_AGGREGATE, aggregate);
}

/**
 * Helper function to avoid repeated code: prepare variables for a
 * `route_map_apply` call.
 *
 * \returns `true` on route map match, otherwise `false`.
 */
static bool aggr_suppress_map_test(struct bgp *bgp,
				   struct bgp_aggregate *aggregate,
				   struct bgp_path_info *pi)
{
	const struct prefix *p = bgp_dest_get_prefix(pi->net);
	route_map_result_t rmr = RMAP_DENYMATCH;
	struct bgp_path_info rmap_path = {};
	struct attr attr = {};

	/* No route map entries created, just don't match. */
	if (aggregate->suppress_map == NULL)
		return false;

	/* Call route map matching and return result. */
	attr.aspath = aspath_empty();
	rmap_path.peer = bgp->peer_self;
	rmap_path.attr = &attr;

	SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_AGGREGATE);
	rmr = route_map_apply(aggregate->suppress_map, p, &rmap_path);
	bgp->peer_self->rmap_type = 0;

	bgp_attr_flush(&attr);

	return rmr == RMAP_PERMITMATCH;
}

/** Test whether the aggregation has suppressed this path or not. */
static bool aggr_suppress_exists(struct bgp_aggregate *aggregate,
				 struct bgp_path_info *pi)
{
	if (pi->extra == NULL || pi->extra->aggr_suppressors == NULL)
		return false;

	return listnode_lookup(pi->extra->aggr_suppressors, aggregate) != NULL;
}

/**
 * Suppress this path and keep the reference.
 *
 * \returns `true` if needs processing otherwise `false`.
 */
static bool aggr_suppress_path(struct bgp_aggregate *aggregate,
			       struct bgp_path_info *pi)
{
	struct bgp_path_info_extra *pie;

	/* Path is already suppressed by this aggregation. */
	if (aggr_suppress_exists(aggregate, pi))
		return false;

	pie = bgp_path_info_extra_get(pi);

	/* This is the first suppression, allocate memory and list it. */
	if (pie->aggr_suppressors == NULL)
		pie->aggr_suppressors = list_new();

	listnode_add(pie->aggr_suppressors, aggregate);

	/* Only mark for processing if suppressed. */
	if (listcount(pie->aggr_suppressors) == 1) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("aggregate-address suppressing: %pFX",
				   bgp_dest_get_prefix(pi->net));

		bgp_path_info_set_flag(pi->net, pi, BGP_PATH_ATTR_CHANGED);
		return true;
	}

	return false;
}

/**
 * Unsuppress this path and remove the reference.
 *
 * \returns `true` if needs processing otherwise `false`.
 */
static bool aggr_unsuppress_path(struct bgp_aggregate *aggregate,
				 struct bgp_path_info *pi)
{
	/* Path wasn't suppressed. */
	if (!aggr_suppress_exists(aggregate, pi))
		return false;

	listnode_delete(pi->extra->aggr_suppressors, aggregate);

	/* Unsuppress and free extra memory if last item. */
	if (listcount(pi->extra->aggr_suppressors) == 0) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("aggregate-address unsuppressing: %pFX",
				   bgp_dest_get_prefix(pi->net));

		list_delete(&pi->extra->aggr_suppressors);
		bgp_path_info_set_flag(pi->net, pi, BGP_PATH_ATTR_CHANGED);
		return true;
	}

	return false;
}

static bool bgp_aggregate_info_same(struct bgp_path_info *pi, uint8_t origin,
				    struct aspath *aspath,
				    struct community *comm,
				    struct ecommunity *ecomm,
				    struct lcommunity *lcomm)
{
	static struct aspath *ae = NULL;

	if (!ae)
		ae = aspath_empty();

	if (!pi)
		return false;

	if (origin != pi->attr->origin)
		return false;

	if (!aspath_cmp(pi->attr->aspath, (aspath) ? aspath : ae))
		return false;

	if (!community_cmp(pi->attr->community, comm))
		return false;

	if (!ecommunity_cmp(pi->attr->ecommunity, ecomm))
		return false;

	if (!lcommunity_cmp(pi->attr->lcommunity, lcomm))
		return false;

	if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID))
		return false;

	return true;
}

static void bgp_aggregate_install(
	struct bgp *bgp, afi_t afi, safi_t safi, const struct prefix *p,
	uint8_t origin, struct aspath *aspath, struct community *community,
	struct ecommunity *ecommunity, struct lcommunity *lcommunity,
	uint8_t atomic_aggregate, struct bgp_aggregate *aggregate)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi, *orig, *new;
	struct attr *attr;

	table = bgp->rib[afi][safi];

	dest = bgp_node_get(table, p);

	for (orig = pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP
		    && pi->sub_type == BGP_ROUTE_AGGREGATE)
			break;

	/*
	 * If we have paths with different MEDs, then don't install
	 * (or uninstall) the aggregate route.
	 */
	if (aggregate->match_med && aggregate->med_mismatched)
		goto uninstall_aggregate_route;

	if (aggregate->count > 0) {
		/*
		 * If the aggregate information has not changed
		 * no need to re-install it again.
		 */
		if (bgp_aggregate_info_same(orig, origin, aspath, community,
					    ecommunity, lcommunity)) {
			bgp_dest_unlock_node(dest);

			if (aspath)
				aspath_free(aspath);
			if (community)
				community_free(&community);
			if (ecommunity)
				ecommunity_free(&ecommunity);
			if (lcommunity)
				lcommunity_free(&lcommunity);

			return;
		}

		/*
		 * Mark the old as unusable
		 */
		if (pi)
			bgp_path_info_delete(dest, pi);

		attr = bgp_attr_aggregate_intern(
			bgp, origin, aspath, community, ecommunity, lcommunity,
			aggregate, atomic_aggregate, p);

		if (!attr) {
			bgp_aggregate_delete(bgp, p, afi, safi, aggregate);
			return;
		}

		new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, 0,
				bgp->peer_self, attr, dest);

		SET_FLAG(new->flags, BGP_PATH_VALID);

		bgp_path_info_add(dest, new);
		bgp_process(bgp, dest, afi, safi);
	} else {
	uninstall_aggregate_route:
		for (pi = orig; pi; pi = pi->next)
			if (pi->peer == bgp->peer_self
			    && pi->type == ZEBRA_ROUTE_BGP
			    && pi->sub_type == BGP_ROUTE_AGGREGATE)
				break;

		/* Withdraw static BGP route from routing table. */
		if (pi) {
			bgp_path_info_delete(dest, pi);
			bgp_process(bgp, dest, afi, safi);
		}
	}

	bgp_dest_unlock_node(dest);
}

/**
 * Check if the current path has different MED than other known paths.
 *
 * \returns `true` if the MED matched the others else `false`.
 */
static bool bgp_aggregate_med_match(struct bgp_aggregate *aggregate,
				    struct bgp *bgp, struct bgp_path_info *pi)
{
	uint32_t cur_med = bgp_med_value(pi->attr, bgp);

	/* This is the first route being analyzed. */
	if (!aggregate->med_initialized) {
		aggregate->med_initialized = true;
		aggregate->med_mismatched = false;
		aggregate->med_matched_value = cur_med;
	} else {
		/* Check if routes with different MED showed up. */
		if (cur_med != aggregate->med_matched_value)
			aggregate->med_mismatched = true;
	}

	return !aggregate->med_mismatched;
}

/**
 * Initializes and tests all routes in the aggregate address path for MED
 * values.
 *
 * \returns `true` if all MEDs are the same otherwise `false`.
 */
static bool bgp_aggregate_test_all_med(struct bgp_aggregate *aggregate,
				       struct bgp *bgp, const struct prefix *p,
				       afi_t afi, safi_t safi)
{
	struct bgp_table *table = bgp->rib[afi][safi];
	const struct prefix *dest_p;
	struct bgp_dest *dest, *top;
	struct bgp_path_info *pi;
	bool med_matched = true;

	aggregate->med_initialized = false;

	top = bgp_node_get(table, p);
	for (dest = bgp_node_get(table, p); dest;
	     dest = bgp_route_next_until(dest, top)) {
		dest_p = bgp_dest_get_prefix(dest);
		if (dest_p->prefixlen <= p->prefixlen)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;
			if (pi->sub_type == BGP_ROUTE_AGGREGATE)
				continue;
			if (!bgp_aggregate_med_match(aggregate, bgp, pi)) {
				med_matched = false;
				break;
			}
		}
		if (!med_matched)
			break;
	}
	bgp_dest_unlock_node(top);

	return med_matched;
}

/**
 * Toggles the route suppression status for this aggregate address
 * configuration.
 */
void bgp_aggregate_toggle_suppressed(struct bgp_aggregate *aggregate,
				     struct bgp *bgp, const struct prefix *p,
				     afi_t afi, safi_t safi, bool suppress)
{
	struct bgp_table *table = bgp->rib[afi][safi];
	const struct prefix *dest_p;
	struct bgp_dest *dest, *top;
	struct bgp_path_info *pi;
	bool toggle_suppression;

	/* We've found a different MED we must revert any suppressed routes. */
	top = bgp_node_get(table, p);
	for (dest = bgp_node_get(table, p); dest;
	     dest = bgp_route_next_until(dest, top)) {
		dest_p = bgp_dest_get_prefix(dest);
		if (dest_p->prefixlen <= p->prefixlen)
			continue;

		toggle_suppression = false;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;
			if (pi->sub_type == BGP_ROUTE_AGGREGATE)
				continue;

			/* We are toggling suppression back. */
			if (suppress) {
				/* Suppress route if not suppressed already. */
				if (aggr_suppress_path(aggregate, pi))
					toggle_suppression = true;
				continue;
			}

			/* Install route if there is no more suppression. */
			if (aggr_unsuppress_path(aggregate, pi))
				toggle_suppression = true;
		}

		if (toggle_suppression)
			bgp_process(bgp, dest, afi, safi);
	}
	bgp_dest_unlock_node(top);
}

/**
 * Aggregate address MED matching incremental test: this function is called
 * when the initial aggregation occurred and we are only testing a single
 * new path.
 *
 * In addition to testing and setting the MED validity it also installs back
 * suppressed routes (if summary is configured).
 *
 * Must not be called in `bgp_aggregate_route`.
 */
static void bgp_aggregate_med_update(struct bgp_aggregate *aggregate,
				     struct bgp *bgp, const struct prefix *p,
				     afi_t afi, safi_t safi,
				     struct bgp_path_info *pi, bool is_adding)
{
	/* MED matching disabled. */
	if (!aggregate->match_med)
		return;

	/* Aggregation with different MED, nothing to do. */
	if (aggregate->med_mismatched)
		return;

	/*
	 * Test the current entry:
	 *
	 * is_adding == true: if the new entry doesn't match then we must
	 * install all suppressed routes.
	 *
	 * is_adding == false: if the entry being removed was the last
	 * unmatching entry then we can suppress all routes.
	 */
	if (!is_adding) {
		if (bgp_aggregate_test_all_med(aggregate, bgp, p, afi, safi)
		    && aggregate->summary_only)
			bgp_aggregate_toggle_suppressed(aggregate, bgp, p, afi,
							safi, true);
	} else
		bgp_aggregate_med_match(aggregate, bgp, pi);

	/* No mismatches, just quit. */
	if (!aggregate->med_mismatched)
		return;

	/* Route summarization is disabled. */
	if (!aggregate->summary_only)
		return;

	bgp_aggregate_toggle_suppressed(aggregate, bgp, p, afi, safi, false);
}

/* Update an aggregate as routes are added/removed from the BGP table */
void bgp_aggregate_route(struct bgp *bgp, const struct prefix *p, afi_t afi,
			 safi_t safi, struct bgp_aggregate *aggregate)
{
	struct bgp_table *table;
	struct bgp_dest *top;
	struct bgp_dest *dest;
	uint8_t origin;
	struct aspath *aspath = NULL;
	struct community *community = NULL;
	struct ecommunity *ecommunity = NULL;
	struct lcommunity *lcommunity = NULL;
	struct bgp_path_info *pi;
	unsigned long match = 0;
	uint8_t atomic_aggregate = 0;

	/* If the bgp instance is being deleted or self peer is deleted
	 * then do not create aggregate route
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS)
	    || (bgp->peer_self == NULL))
		return;

	/* Initialize and test routes for MED difference. */
	if (aggregate->match_med)
		bgp_aggregate_test_all_med(aggregate, bgp, p, afi, safi);

	/*
	 * Reset aggregate count: we might've been called from route map
	 * update so in that case we must retest all more specific routes.
	 *
	 * \see `bgp_route_map_process_update`.
	 */
	aggregate->count = 0;
	aggregate->incomplete_origin_count = 0;
	aggregate->incomplete_origin_count = 0;
	aggregate->egp_origin_count = 0;

	/* ORIGIN attribute: If at least one route among routes that are
	   aggregated has ORIGIN with the value INCOMPLETE, then the
	   aggregated route must have the ORIGIN attribute with the value
	   INCOMPLETE. Otherwise, if at least one route among routes that
	   are aggregated has ORIGIN with the value EGP, then the aggregated
	   route must have the origin attribute with the value EGP. In all
	   other case the value of the ORIGIN attribute of the aggregated
	   route is INTERNAL. */
	origin = BGP_ORIGIN_IGP;

	table = bgp->rib[afi][safi];

	top = bgp_node_get(table, p);
	for (dest = bgp_node_get(table, p); dest;
	     dest = bgp_route_next_until(dest, top)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (dest_p->prefixlen <= p->prefixlen)
			continue;

		/* If suppress fib is enabled and route not installed
		 * in FIB, skip the route
		 */
		if (!bgp_check_advertise(bgp, dest))
			continue;

		match = 0;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (pi->attr->flag
			    & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
				atomic_aggregate = 1;

			if (pi->sub_type == BGP_ROUTE_AGGREGATE)
				continue;

			/*
			 * summary-only aggregate route suppress
			 * aggregated route announcements.
			 *
			 * MED matching:
			 * Don't create summaries if MED didn't match
			 * otherwise neither the specific routes and the
			 * aggregation will be announced.
			 */
			if (aggregate->summary_only
			    && AGGREGATE_MED_VALID(aggregate)) {
				if (aggr_suppress_path(aggregate, pi))
					match++;
			}

			/*
			 * Suppress more specific routes that match the route
			 * map results.
			 *
			 * MED matching:
			 * Don't suppress routes if MED matching is enabled and
			 * it mismatched otherwise we might end up with no
			 * routes for this path.
			 */
			if (aggregate->suppress_map_name
			    && AGGREGATE_MED_VALID(aggregate)
			    && aggr_suppress_map_test(bgp, aggregate, pi)) {
				if (aggr_suppress_path(aggregate, pi))
					match++;
			}

			aggregate->count++;

			/*
                        * If at least one route among routes that are
                        * aggregated has ORIGIN with the value INCOMPLETE,
                        * then the aggregated route MUST have the ORIGIN
                        * attribute with the value INCOMPLETE.  Otherwise, if
                        * at least one route among routes that are aggregated
                        * has ORIGIN with the value EGP, then the aggregated
                        * route MUST have the ORIGIN attribute with the value
                        * EGP.
                        */
			switch (pi->attr->origin) {
			case BGP_ORIGIN_INCOMPLETE:
				aggregate->incomplete_origin_count++;
			break;
			case BGP_ORIGIN_EGP:
				aggregate->egp_origin_count++;
			break;
			default:
				/*Do nothing.
				 */
			break;
			}

			if (!aggregate->as_set)
				continue;

			/*
			 * as-set aggregate route generate origin, as path,
			 * and community aggregation.
			 */
			/* Compute aggregate route's as-path.
			 */
			bgp_compute_aggregate_aspath_hash(aggregate,
							  pi->attr->aspath);

			/* Compute aggregate route's community.
			 */
			if (pi->attr->community)
				bgp_compute_aggregate_community_hash(
							aggregate,
							pi->attr->community);

			/* Compute aggregate route's extended community.
			 */
			if (pi->attr->ecommunity)
				bgp_compute_aggregate_ecommunity_hash(
							aggregate,
							pi->attr->ecommunity);

			/* Compute aggregate route's large community.
			 */
			if (pi->attr->lcommunity)
				bgp_compute_aggregate_lcommunity_hash(
							aggregate,
							pi->attr->lcommunity);
		}
		if (match)
			bgp_process(bgp, dest, afi, safi);
	}
	if (aggregate->as_set) {
		bgp_compute_aggregate_aspath_val(aggregate);
		bgp_compute_aggregate_community_val(aggregate);
		bgp_compute_aggregate_ecommunity_val(aggregate);
		bgp_compute_aggregate_lcommunity_val(aggregate);
	}


	bgp_dest_unlock_node(top);


	if (aggregate->incomplete_origin_count > 0)
		origin = BGP_ORIGIN_INCOMPLETE;
	else if (aggregate->egp_origin_count > 0)
		origin = BGP_ORIGIN_EGP;

	if (aggregate->origin != BGP_ORIGIN_UNSPECIFIED)
		origin = aggregate->origin;

	if (aggregate->as_set) {
		if (aggregate->aspath)
			/* Retrieve aggregate route's as-path.
			 */
			aspath = aspath_dup(aggregate->aspath);

		if (aggregate->community)
			/* Retrieve aggregate route's community.
			 */
			community = community_dup(aggregate->community);

		if (aggregate->ecommunity)
			/* Retrieve aggregate route's ecommunity.
			 */
			ecommunity = ecommunity_dup(aggregate->ecommunity);

		if (aggregate->lcommunity)
			/* Retrieve aggregate route's lcommunity.
			 */
			lcommunity = lcommunity_dup(aggregate->lcommunity);
	}

	bgp_aggregate_install(bgp, afi, safi, p, origin, aspath, community,
			      ecommunity, lcommunity, atomic_aggregate,
			      aggregate);
}

void bgp_aggregate_delete(struct bgp *bgp, const struct prefix *p, afi_t afi,
			  safi_t safi, struct bgp_aggregate *aggregate)
{
	struct bgp_table *table;
	struct bgp_dest *top;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	unsigned long match;

	table = bgp->rib[afi][safi];

	/* If routes exists below this node, generate aggregate routes. */
	top = bgp_node_get(table, p);
	for (dest = bgp_node_get(table, p); dest;
	     dest = bgp_route_next_until(dest, top)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (dest_p->prefixlen <= p->prefixlen)
			continue;
		match = 0;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (pi->sub_type == BGP_ROUTE_AGGREGATE)
				continue;

			if (aggregate->summary_only && pi->extra
			    && AGGREGATE_MED_VALID(aggregate)) {
				if (aggr_unsuppress_path(aggregate, pi))
					match++;
			}

			if (aggregate->suppress_map_name
			    && AGGREGATE_MED_VALID(aggregate)
			    && aggr_suppress_map_test(bgp, aggregate, pi)) {
				if (aggr_unsuppress_path(aggregate, pi))
					match++;
			}

			aggregate->count--;

			if (pi->attr->origin == BGP_ORIGIN_INCOMPLETE)
				aggregate->incomplete_origin_count--;
			else if (pi->attr->origin == BGP_ORIGIN_EGP)
				aggregate->egp_origin_count--;

			if (aggregate->as_set) {
				/* Remove as-path from aggregate.
				 */
				bgp_remove_aspath_from_aggregate_hash(
							aggregate,
							pi->attr->aspath);

				if (pi->attr->community)
					/* Remove community from aggregate.
					 */
					bgp_remove_comm_from_aggregate_hash(
							aggregate,
							pi->attr->community);

				if (pi->attr->ecommunity)
					/* Remove ecommunity from aggregate.
					 */
					bgp_remove_ecomm_from_aggregate_hash(
							aggregate,
							pi->attr->ecommunity);

				if (pi->attr->lcommunity)
					/* Remove lcommunity from aggregate.
					 */
					bgp_remove_lcomm_from_aggregate_hash(
							aggregate,
							pi->attr->lcommunity);
			}
		}

		/* If this node was suppressed, process the change. */
		if (match)
			bgp_process(bgp, dest, afi, safi);
	}
	if (aggregate->as_set) {
		aspath_free(aggregate->aspath);
		aggregate->aspath = NULL;
		if (aggregate->community)
			community_free(&aggregate->community);
		if (aggregate->ecommunity)
			ecommunity_free(&aggregate->ecommunity);
		if (aggregate->lcommunity)
			lcommunity_free(&aggregate->lcommunity);
	}

	bgp_dest_unlock_node(top);
}

static void bgp_add_route_to_aggregate(struct bgp *bgp,
				       const struct prefix *aggr_p,
				       struct bgp_path_info *pinew, afi_t afi,
				       safi_t safi,
				       struct bgp_aggregate *aggregate)
{
	uint8_t origin;
	struct aspath *aspath = NULL;
	uint8_t atomic_aggregate = 0;
	struct community *community = NULL;
	struct ecommunity *ecommunity = NULL;
	struct lcommunity *lcommunity = NULL;

	/* ORIGIN attribute: If at least one route among routes that are
	 * aggregated has ORIGIN with the value INCOMPLETE, then the
	 * aggregated route must have the ORIGIN attribute with the value
	 * INCOMPLETE. Otherwise, if at least one route among routes that
	 * are aggregated has ORIGIN with the value EGP, then the aggregated
	 * route must have the origin attribute with the value EGP. In all
	 * other case the value of the ORIGIN attribute of the aggregated
	 * route is INTERNAL.
	 */
	origin = BGP_ORIGIN_IGP;

	aggregate->count++;

	/*
	 * This must be called before `summary` check to avoid
	 * "suppressing" twice.
	 */
	if (aggregate->match_med)
		bgp_aggregate_med_update(aggregate, bgp, aggr_p, afi, safi,
					 pinew, true);

	if (aggregate->summary_only && AGGREGATE_MED_VALID(aggregate))
		aggr_suppress_path(aggregate, pinew);

	if (aggregate->suppress_map_name && AGGREGATE_MED_VALID(aggregate)
	    && aggr_suppress_map_test(bgp, aggregate, pinew))
		aggr_suppress_path(aggregate, pinew);

	switch (pinew->attr->origin) {
	case BGP_ORIGIN_INCOMPLETE:
		aggregate->incomplete_origin_count++;
	break;
	case BGP_ORIGIN_EGP:
		aggregate->egp_origin_count++;
	break;
	default:
		/* Do nothing.
		 */
	break;
	}

	if (aggregate->incomplete_origin_count > 0)
		origin = BGP_ORIGIN_INCOMPLETE;
	else if (aggregate->egp_origin_count > 0)
		origin = BGP_ORIGIN_EGP;

	if (aggregate->origin != BGP_ORIGIN_UNSPECIFIED)
		origin = aggregate->origin;

	if (aggregate->as_set) {
		/* Compute aggregate route's as-path.
		 */
		bgp_compute_aggregate_aspath(aggregate,
					     pinew->attr->aspath);

		/* Compute aggregate route's community.
		 */
		if (pinew->attr->community)
			bgp_compute_aggregate_community(
						aggregate,
						pinew->attr->community);

		/* Compute aggregate route's extended community.
		 */
		if (pinew->attr->ecommunity)
			bgp_compute_aggregate_ecommunity(
					aggregate,
					pinew->attr->ecommunity);

		/* Compute aggregate route's large community.
		 */
		if (pinew->attr->lcommunity)
			bgp_compute_aggregate_lcommunity(
					aggregate,
					pinew->attr->lcommunity);

		/* Retrieve aggregate route's as-path.
		 */
		if (aggregate->aspath)
			aspath = aspath_dup(aggregate->aspath);

		/* Retrieve aggregate route's community.
		 */
		if (aggregate->community)
			community = community_dup(aggregate->community);

		/* Retrieve aggregate route's ecommunity.
		 */
		if (aggregate->ecommunity)
			ecommunity = ecommunity_dup(aggregate->ecommunity);

		/* Retrieve aggregate route's lcommunity.
		 */
		if (aggregate->lcommunity)
			lcommunity = lcommunity_dup(aggregate->lcommunity);
	}

	bgp_aggregate_install(bgp, afi, safi, aggr_p, origin,
			      aspath, community, ecommunity,
			      lcommunity, atomic_aggregate, aggregate);
}

static void bgp_remove_route_from_aggregate(struct bgp *bgp, afi_t afi,
					    safi_t safi,
					    struct bgp_path_info *pi,
					    struct bgp_aggregate *aggregate,
					    const struct prefix *aggr_p)
{
	uint8_t origin;
	struct aspath *aspath = NULL;
	uint8_t atomic_aggregate = 0;
	struct community *community = NULL;
	struct ecommunity *ecommunity = NULL;
	struct lcommunity *lcommunity = NULL;
	unsigned long match = 0;

	if (BGP_PATH_HOLDDOWN(pi))
		return;

	if (pi->sub_type == BGP_ROUTE_AGGREGATE)
		return;

	if (aggregate->summary_only && AGGREGATE_MED_VALID(aggregate))
		if (aggr_unsuppress_path(aggregate, pi))
			match++;

	if (aggregate->suppress_map_name && AGGREGATE_MED_VALID(aggregate)
	    && aggr_suppress_map_test(bgp, aggregate, pi))
		if (aggr_unsuppress_path(aggregate, pi))
			match++;

	/*
	 * This must be called after `summary`, `suppress-map` check to avoid
	 * "unsuppressing" twice.
	 */
	if (aggregate->match_med)
		bgp_aggregate_med_update(aggregate, bgp, aggr_p, afi, safi, pi,
					 true);

	if (aggregate->count > 0)
		aggregate->count--;

	if (pi->attr->origin == BGP_ORIGIN_INCOMPLETE)
		aggregate->incomplete_origin_count--;
	else if (pi->attr->origin == BGP_ORIGIN_EGP)
		aggregate->egp_origin_count--;

	if (aggregate->as_set) {
		/* Remove as-path from aggregate.
		 */
		bgp_remove_aspath_from_aggregate(aggregate,
						 pi->attr->aspath);

		if (pi->attr->community)
			/* Remove community from aggregate.
			 */
			bgp_remove_community_from_aggregate(
							aggregate,
							pi->attr->community);

		if (pi->attr->ecommunity)
			/* Remove ecommunity from aggregate.
			 */
			bgp_remove_ecommunity_from_aggregate(
							aggregate,
							pi->attr->ecommunity);

		if (pi->attr->lcommunity)
			/* Remove lcommunity from aggregate.
			 */
			bgp_remove_lcommunity_from_aggregate(
							aggregate,
							pi->attr->lcommunity);
	}

	/* If this node was suppressed, process the change. */
	if (match)
		bgp_process(bgp, pi->net, afi, safi);

	origin = BGP_ORIGIN_IGP;
	if (aggregate->incomplete_origin_count > 0)
		origin = BGP_ORIGIN_INCOMPLETE;
	else if (aggregate->egp_origin_count > 0)
		origin = BGP_ORIGIN_EGP;

	if (aggregate->origin != BGP_ORIGIN_UNSPECIFIED)
		origin = aggregate->origin;

	if (aggregate->as_set) {
		/* Retrieve aggregate route's as-path.
		 */
		if (aggregate->aspath)
			aspath = aspath_dup(aggregate->aspath);

		/* Retrieve aggregate route's community.
		 */
		if (aggregate->community)
			community = community_dup(aggregate->community);

		/* Retrieve aggregate route's ecommunity.
		 */
		if (aggregate->ecommunity)
			ecommunity = ecommunity_dup(aggregate->ecommunity);

		/* Retrieve aggregate route's lcommunity.
		 */
		if (aggregate->lcommunity)
			lcommunity = lcommunity_dup(aggregate->lcommunity);
	}

	bgp_aggregate_install(bgp, afi, safi, aggr_p, origin,
			      aspath, community, ecommunity,
			      lcommunity, atomic_aggregate, aggregate);
}

void bgp_aggregate_increment(struct bgp *bgp, const struct prefix *p,
			     struct bgp_path_info *pi, afi_t afi, safi_t safi)
{
	struct bgp_dest *child;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;
	struct bgp_table *table;

	table = bgp->aggregate[afi][safi];

	/* No aggregates configured. */
	if (bgp_table_top_nolock(table) == NULL)
		return;

	if (p->prefixlen == 0)
		return;

	if (BGP_PATH_HOLDDOWN(pi))
		return;

	/* If suppress fib is enabled and route not installed
	 * in FIB, do not update the aggregate route
	 */
	if (!bgp_check_advertise(bgp, pi->net))
		return;

	child = bgp_node_get(table, p);

	/* Aggregate address configuration check. */
	for (dest = child; dest; dest = bgp_dest_parent_nolock(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		aggregate = bgp_dest_get_bgp_aggregate_info(dest);
		if (aggregate != NULL && dest_p->prefixlen < p->prefixlen) {
			bgp_add_route_to_aggregate(bgp, dest_p, pi, afi, safi,
						   aggregate);
		}
	}
	bgp_dest_unlock_node(child);
}

void bgp_aggregate_decrement(struct bgp *bgp, const struct prefix *p,
			     struct bgp_path_info *del, afi_t afi, safi_t safi)
{
	struct bgp_dest *child;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;
	struct bgp_table *table;

	table = bgp->aggregate[afi][safi];

	/* No aggregates configured. */
	if (bgp_table_top_nolock(table) == NULL)
		return;

	if (p->prefixlen == 0)
		return;

	child = bgp_node_get(table, p);

	/* Aggregate address configuration check. */
	for (dest = child; dest; dest = bgp_dest_parent_nolock(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		aggregate = bgp_dest_get_bgp_aggregate_info(dest);
		if (aggregate != NULL && dest_p->prefixlen < p->prefixlen) {
			bgp_remove_route_from_aggregate(bgp, afi, safi, del,
							aggregate, dest_p);
		}
	}
	bgp_dest_unlock_node(child);
}

/* Aggregate route attribute. */
#define AGGREGATE_SUMMARY_ONLY 1
#define AGGREGATE_AS_SET       1
#define AGGREGATE_AS_UNSET     0

static const char *bgp_origin2str(uint8_t origin)
{
	switch (origin) {
	case BGP_ORIGIN_IGP:
		return "igp";
	case BGP_ORIGIN_EGP:
		return "egp";
	case BGP_ORIGIN_INCOMPLETE:
		return "incomplete";
	}
	return "n/a";
}

int bgp_aggregate_unset(struct bgp *bgp, struct prefix *prefix, afi_t afi,
			safi_t safi, char *errmsg, size_t errmsg_len)
{
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;

	apply_mask(prefix);
	/* Old configuration check. */
	dest = bgp_node_lookup(bgp->aggregate[afi][safi], prefix);
	if (!dest) {
		snprintf(errmsg, errmsg_len,
			 "There is no aggregate-address configuration.\n");
		return -1;
	}

	aggregate = bgp_dest_get_bgp_aggregate_info(dest);
	bgp_aggregate_delete(bgp, prefix, afi, safi, aggregate);
	bgp_aggregate_install(bgp, afi, safi, prefix, 0, NULL, NULL, NULL, NULL,
			      0, aggregate);

	/* Unlock aggregate address configuration. */
	bgp_dest_set_bgp_aggregate_info(dest, NULL);

	if (aggregate->community)
		community_free(&aggregate->community);

	if (aggregate->community_hash) {
		/* Delete all communities in the hash.
		 */
		hash_clean(aggregate->community_hash,
			   bgp_aggr_community_remove);
		/* Free up the community_hash.
		 */
		hash_free(aggregate->community_hash);
	}

	if (aggregate->ecommunity)
		ecommunity_free(&aggregate->ecommunity);

	if (aggregate->ecommunity_hash) {
		/* Delete all ecommunities in the hash.
		 */
		hash_clean(aggregate->ecommunity_hash,
			   bgp_aggr_ecommunity_remove);
		/* Free up the ecommunity_hash.
		 */
		hash_free(aggregate->ecommunity_hash);
	}

	if (aggregate->lcommunity)
		lcommunity_free(&aggregate->lcommunity);

	if (aggregate->lcommunity_hash) {
		/* Delete all lcommunities in the hash.
		 */
		hash_clean(aggregate->lcommunity_hash,
			   bgp_aggr_lcommunity_remove);
		/* Free up the lcommunity_hash.
		 */
		hash_free(aggregate->lcommunity_hash);
	}

	if (aggregate->aspath)
		aspath_free(aggregate->aspath);

	if (aggregate->aspath_hash) {
		/* Delete all as-paths in the hash.
		 */
		hash_clean(aggregate->aspath_hash,
			   bgp_aggr_aspath_remove);
		/* Free up the aspath_hash.
		 */
		hash_free(aggregate->aspath_hash);
	}

	bgp_aggregate_free(aggregate);
	bgp_dest_unlock_node(dest);
	bgp_dest_unlock_node(dest);

	return 0;
}

int bgp_aggregate_set(struct bgp *bgp, struct prefix *prefix, afi_t afi,
		      safi_t safi, const char *rmap, uint8_t summary_only,
		      uint8_t as_set, uint8_t origin, bool match_med,
		      const char *suppress_map,
		      char *errmsg, size_t errmsg_len)
{
	int ret;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;
	uint8_t as_set_new = as_set;
	char buf[PREFIX2STR_BUFFER];

	if (suppress_map && summary_only) {
		snprintf(errmsg, errmsg_len,
			"'summary-only' and 'suppress-map' can't be used at the same time\n");
		return -1;
	}

	apply_mask(prefix);

	if ((afi == AFI_IP && prefix->prefixlen == IPV4_MAX_BITLEN)
	    || (afi == AFI_IP6 && prefix->prefixlen == IPV6_MAX_BITLEN)) {
		snprintf(
			errmsg, errmsg_len,
			"Specified prefix: %s will not result in any useful aggregation, disallowing\n",
			prefix2str(prefix, buf, PREFIX_STRLEN));
		return -1;
	}

	/* Old configuration check. */
	dest = bgp_node_get(bgp->aggregate[afi][safi], prefix);
	aggregate = bgp_dest_get_bgp_aggregate_info(dest);

	if (aggregate) {
		snprintf(errmsg, errmsg_len,
			 "There is already same aggregate network.\n");
		/* try to remove the old entry */
		ret = bgp_aggregate_unset(bgp, prefix, afi, safi, errmsg,
					  errmsg_len);
		if (ret) {
			snprintf(errmsg, errmsg_len,
				 "Error deleting aggregate.\n");
			bgp_dest_unlock_node(dest);
			return -1;
		}
	}

	/* Make aggregate address structure. */
	aggregate = bgp_aggregate_new();
	aggregate->summary_only = summary_only;
	aggregate->match_med = match_med;

	/* Network operators MUST NOT locally generate any new
	 * announcements containing AS_SET or AS_CONFED_SET. If they have
	 * announced routes with AS_SET or AS_CONFED_SET in them, then they
	 * SHOULD withdraw those routes and re-announce routes for the
	 * aggregate or component prefixes (i.e., the more-specific routes
	 * subsumed by the previously aggregated route) without AS_SET
	 * or AS_CONFED_SET in the updates.
	 */
	if (bgp->reject_as_sets) {
		if (as_set == AGGREGATE_AS_SET) {
			as_set_new = AGGREGATE_AS_UNSET;
			zlog_warn(
				"%s: Ignoring as-set because `bgp reject-as-sets` is enabled.",
				__func__);
			snprintf(
				errmsg, errmsg_len,
				"Ignoring as-set because `bgp reject-as-sets` is enabled.\n");
		}
	}

	aggregate->as_set = as_set_new;
	aggregate->safi = safi;
	/* Override ORIGIN attribute if defined.
	 * E.g.: Cisco and Juniper set ORIGIN for aggregated address
	 * to IGP which is not what rfc4271 says.
	 * This enables the same behavior, optionally.
	 */
	aggregate->origin = origin;

	if (rmap) {
		XFREE(MTYPE_ROUTE_MAP_NAME, aggregate->rmap.name);
		route_map_counter_decrement(aggregate->rmap.map);
		aggregate->rmap.name =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
		aggregate->rmap.map = route_map_lookup_by_name(rmap);
		route_map_counter_increment(aggregate->rmap.map);
	}

	if (suppress_map) {
		XFREE(MTYPE_ROUTE_MAP_NAME, aggregate->suppress_map_name);
		route_map_counter_decrement(aggregate->suppress_map);

		aggregate->suppress_map_name =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, suppress_map);
		aggregate->suppress_map =
			route_map_lookup_by_name(aggregate->suppress_map_name);
		route_map_counter_increment(aggregate->suppress_map);
	}

	bgp_dest_set_bgp_aggregate_info(dest, aggregate);

	/* Aggregate address insert into BGP routing table. */
	bgp_aggregate_route(bgp, prefix, afi, safi, aggregate);

	return 0;
}

DEFPY_YANG(
	aggregate_addressv4, aggregate_addressv4_cmd,
	"[no] aggregate-address <A.B.C.D/M$prefix|A.B.C.D$addr A.B.C.D$mask> {"
	"as-set$as_set_s"
	"|summary-only$summary_only"
	"|route-map WORD$rmap_name"
	"|origin <egp|igp|incomplete>$origin_s"
	"|matching-MED-only$match_med"
	"|suppress-map WORD$suppress_map"
	"}",
	NO_STR
	"Configure BGP aggregate entries\n"
	"Aggregate prefix\n"
	"Aggregate address\n"
	"Aggregate mask\n"
	"Generate AS set path information\n"
	"Filter more specific routes from updates\n"
	"Apply route map to aggregate network\n"
	"Route map name\n"
	"BGP origin code\n"
	"Remote EGP\n"
	"Local IGP\n"
	"Unknown heritage\n"
	"Only aggregate routes with matching MED\n"
	"Suppress the selected more specific routes\n"
	"Route map with the route selectors\n")
{
	char base_xpath[XPATH_MAXLEN];
	safi_t safi = bgp_node_safi(vty);
	char prefix_buf[PREFIX2STR_BUFFER];

	if (addr_str) {
		if (netmask_str2prefix_str(addr_str, mask_str, prefix_buf)
		    == 0) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		strlcpy(prefix_buf, prefix_str, sizeof(prefix_buf));
	}

	if (!no && origin_s)
		nb_cli_enqueue_change(vty, "./origin", NB_OP_MODIFY, origin_s);

	if (!no && as_set_s)
		nb_cli_enqueue_change(vty, "./as-set", NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./as-set", NB_OP_MODIFY, "false");

	if (!no && summary_only)
		nb_cli_enqueue_change(vty, "./summary-only", NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, "./summary-only", NB_OP_MODIFY,
				      "false");

	if (!no && match_med)
		nb_cli_enqueue_change(vty, "./match-med", NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./match-med", NB_OP_MODIFY,
				      "false");

	if (rmap_name)
		nb_cli_enqueue_change(vty, "./rmap-policy-export", NB_OP_MODIFY,
				      rmap_name);
	else
		nb_cli_enqueue_change(vty, "./rmap-policy-export",
				      NB_OP_DESTROY, NULL);

	if (suppress_map)
		nb_cli_enqueue_change(vty, "./suppress-map", NB_OP_MODIFY,
				      suppress_map);
	else
		nb_cli_enqueue_change(vty, "./suppress-map", NB_OP_DESTROY,
				      NULL);

	snprintf(
		base_xpath, sizeof(base_xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/aggregate-route[prefix='%s']",
		yang_afi_safi_value2identity(AFI_IP, safi),
		bgp_afi_safi_get_container_str(AFI_IP, safi), prefix_buf);

	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, base_xpath);
}

DEFPY_YANG(aggregate_addressv6, aggregate_addressv6_cmd,
	   "[no] aggregate-address X:X::X:X/M$prefix {"
	   "as-set$as_set_s"
	   "|summary-only$summary_only"
	   "|route-map WORD$rmap_name"
	   "|origin <egp|igp|incomplete>$origin_s"
	   "|matching-MED-only$match_med"
	   "|suppress-map WORD$suppress_map"
	   "}",
	   NO_STR
	   "Configure BGP aggregate entries\n"
	   "Aggregate prefix\n"
	   "Generate AS set path information\n"
	   "Filter more specific routes from updates\n"
	   "Apply route map to aggregate network\n"
	   "Route map name\n"
	   "BGP origin code\n"
	   "Remote EGP\n"
	   "Local IGP\n"
	   "Unknown heritage\n"
	   "Only aggregate routes with matching MED\n"
	   "Suppress the selected more specific routes\n"
	   "Route map with the route selectors\n")
{
	char base_xpath[XPATH_MAXLEN];
	safi_t safi = bgp_node_safi(vty);

	if (!no && origin_s)
		nb_cli_enqueue_change(vty, "./origin", NB_OP_MODIFY, origin_s);

	if (!no && as_set_s)
		nb_cli_enqueue_change(vty, "./as-set", NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./as-set", NB_OP_MODIFY, "false");

	if (!no && summary_only)
		nb_cli_enqueue_change(vty, "./summary-only", NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, "./summary-only", NB_OP_MODIFY,
				      "false");

	if (!no && match_med)
		nb_cli_enqueue_change(vty, "./match-med", NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./match-med", NB_OP_MODIFY,
				      "false");

	if (rmap_name)
		nb_cli_enqueue_change(vty, "./rmap-policy-export", NB_OP_MODIFY,
				      rmap_name);

	if (suppress_map)
		nb_cli_enqueue_change(vty, "./suppress-map", NB_OP_MODIFY,
				      suppress_map);
	else
		nb_cli_enqueue_change(vty, "./suppress-map", NB_OP_DESTROY,
				      NULL);

	snprintf(
		base_xpath, sizeof(base_xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/aggregate-route[prefix='%s']",
		yang_afi_safi_value2identity(AFI_IP6, safi),
		bgp_afi_safi_get_container_str(AFI_IP6, safi), prefix_str);

	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, base_xpath);
}

void cli_show_bgp_global_afi_safi_unicast_aggregate_route(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults)
{
	uint8_t origin;

	vty_out(vty, "  aggregate-address %s",
		yang_dnode_get_string(dnode, "./prefix"));

	if (yang_dnode_get_bool(dnode, "./as-set"))
		vty_out(vty, " as-set");

	if (yang_dnode_get_bool(dnode, "./summary-only"))
		vty_out(vty, " summary-only");

	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./rmap-policy-export"));

	origin = yang_dnode_get_enum(dnode, "./origin");
	if (origin != BGP_ORIGIN_UNSPECIFIED)
		vty_out(vty, " origin %s", bgp_origin2str(origin));

	if (yang_dnode_get_bool(dnode, "./match-med"))
		vty_out(vty, " matching-MED-only");

	vty_out(vty, "\n");
}

/* Redistribute route treatment. */
void bgp_redistribute_add(struct bgp *bgp, struct prefix *p,
			  const union g_addr *nexthop, ifindex_t ifindex,
			  enum nexthop_types_t nhtype, uint32_t metric,
			  uint8_t type, unsigned short instance,
			  route_tag_t tag)
{
	struct bgp_path_info *new;
	struct bgp_path_info *bpi;
	struct bgp_path_info rmap_path;
	struct bgp_dest *bn;
	struct attr attr;
	struct attr *new_attr;
	afi_t afi;
	route_map_result_t ret;
	struct bgp_redist *red;

	/* Make default attribute. */
	bgp_attr_default_set(&attr, BGP_ORIGIN_INCOMPLETE);
	/*
	 * This must not be NULL to satisfy Coverity SA
	 */
	assert(attr.aspath);

	switch (nhtype) {
	case NEXTHOP_TYPE_IFINDEX:
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		attr.nexthop = nexthop->ipv4;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		attr.mp_nexthop_global = nexthop->ipv6;
		attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		switch (p->family) {
		case AF_INET:
			attr.nexthop.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			memset(&attr.mp_nexthop_global, 0,
			       sizeof(attr.mp_nexthop_global));
			attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			break;
		}
		break;
	}
	attr.nh_ifindex = ifindex;

	attr.med = metric;
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	attr.tag = tag;

	afi = family2afi(p->family);

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (red) {
		struct attr attr_new;

		/* Copy attribute for modification. */
		attr_new = attr;

		if (red->redist_metric_flag)
			attr_new.med = red->redist_metric;

		/* Apply route-map. */
		if (red->rmap.name) {
			memset(&rmap_path, 0, sizeof(struct bgp_path_info));
			rmap_path.peer = bgp->peer_self;
			rmap_path.attr = &attr_new;

			SET_FLAG(bgp->peer_self->rmap_type,
				 PEER_RMAP_TYPE_REDISTRIBUTE);

			ret = route_map_apply(red->rmap.map, p, &rmap_path);

			bgp->peer_self->rmap_type = 0;

			if (ret == RMAP_DENYMATCH) {
				/* Free uninterned attribute. */
				bgp_attr_flush(&attr_new);

				/* Unintern original. */
				aspath_unintern(&attr.aspath);
				bgp_redistribute_delete(bgp, p, type, instance);
				return;
			}
		}

		if (bgp_in_graceful_shutdown(bgp))
			bgp_attr_add_gshut_community(&attr_new);

		bn = bgp_afi_node_get(bgp->rib[afi][SAFI_UNICAST], afi,
				      SAFI_UNICAST, p, NULL);

		new_attr = bgp_attr_intern(&attr_new);

		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next)
			if (bpi->peer == bgp->peer_self
			    && bpi->sub_type == BGP_ROUTE_REDISTRIBUTE)
				break;

		if (bpi) {
			/* Ensure the (source route) type is updated. */
			bpi->type = type;
			if (attrhash_cmp(bpi->attr, new_attr)
			    && !CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {
				bgp_attr_unintern(&new_attr);
				aspath_unintern(&attr.aspath);
				bgp_dest_unlock_node(bn);
				return;
			} else {
				/* The attribute is changed. */
				bgp_path_info_set_flag(bn, bpi,
						       BGP_PATH_ATTR_CHANGED);

				/* Rewrite BGP route information. */
				if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
					bgp_path_info_restore(bn, bpi);
				else
					bgp_aggregate_decrement(
						bgp, p, bpi, afi, SAFI_UNICAST);
				bgp_attr_unintern(&bpi->attr);
				bpi->attr = new_attr;
				bpi->uptime = bgp_clock();

				/* Process change. */
				bgp_aggregate_increment(bgp, p, bpi, afi,
							SAFI_UNICAST);
				bgp_process(bgp, bn, afi, SAFI_UNICAST);
				bgp_dest_unlock_node(bn);
				aspath_unintern(&attr.aspath);

				if ((bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
				    || (bgp->inst_type
					== BGP_INSTANCE_TYPE_DEFAULT)) {

					vpn_leak_from_vrf_update(
						bgp_get_default(), bgp, bpi);
				}
				return;
			}
		}

		new = info_make(type, BGP_ROUTE_REDISTRIBUTE, instance,
				bgp->peer_self, new_attr, bn);
		SET_FLAG(new->flags, BGP_PATH_VALID);

		bgp_aggregate_increment(bgp, p, new, afi, SAFI_UNICAST);
		bgp_path_info_add(bn, new);
		bgp_dest_unlock_node(bn);
		bgp_process(bgp, bn, afi, SAFI_UNICAST);

		if ((bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		    || (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_from_vrf_update(bgp_get_default(), bgp, new);
		}
	}

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

void bgp_redistribute_delete(struct bgp *bgp, struct prefix *p, uint8_t type,
			     unsigned short instance)
{
	afi_t afi;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_redist *red;

	afi = family2afi(p->family);

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (red) {
		dest = bgp_afi_node_get(bgp->rib[afi][SAFI_UNICAST], afi,
					SAFI_UNICAST, p, NULL);

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == bgp->peer_self && pi->type == type)
				break;

		if (pi) {
			if ((bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
			    || (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

				vpn_leak_from_vrf_withdraw(bgp_get_default(),
							   bgp, pi);
			}
			bgp_aggregate_decrement(bgp, p, pi, afi, SAFI_UNICAST);
			bgp_path_info_delete(dest, pi);
			bgp_process(bgp, dest, afi, SAFI_UNICAST);
		}
		bgp_dest_unlock_node(dest);
	}
}

/* Withdraw specified route type's route. */
void bgp_redistribute_withdraw(struct bgp *bgp, afi_t afi, int type,
			       unsigned short instance)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;

	table = bgp->rib[afi][SAFI_UNICAST];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == bgp->peer_self && pi->type == type
			    && pi->instance == instance)
				break;

		if (pi) {
			if ((bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
			    || (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

				vpn_leak_from_vrf_withdraw(bgp_get_default(),
							   bgp, pi);
			}
			bgp_aggregate_decrement(bgp, bgp_dest_get_prefix(dest),
						pi, afi, SAFI_UNICAST);
			bgp_path_info_delete(dest, pi);
			bgp_process(bgp, dest, afi, SAFI_UNICAST);
		}
	}
}

/* Static function to display route. */
static void route_vty_out_route(const struct prefix *p, struct vty *vty,
				json_object *json, bool wide)
{
	int len = 0;
	char buf[BUFSIZ];
	char buf2[BUFSIZ];

	if (p->family == AF_INET) {
		if (!json) {
			len = vty_out(vty, "%pFX", p);
		} else {
			json_object_string_add(json, "prefix",
					       inet_ntop(p->family,
							 &p->u.prefix, buf,
							 BUFSIZ));
			json_object_int_add(json, "prefixLen", p->prefixlen);
			prefix2str(p, buf2, PREFIX_STRLEN);
			json_object_string_add(json, "network", buf2);
		}
	} else if (p->family == AF_ETHERNET) {
		len = vty_out(vty, "%pFX", p);
	} else if (p->family == AF_EVPN) {
		if (!json)
			len = vty_out(vty, "%pFX", (struct prefix_evpn *)p);
		else
			bgp_evpn_route2json((struct prefix_evpn *)p, json);
	} else if (p->family == AF_FLOWSPEC) {
		route_vty_out_flowspec(vty, p, NULL,
			       json ?
			       NLRI_STRING_FORMAT_JSON_SIMPLE :
			       NLRI_STRING_FORMAT_MIN, json);
	} else {
		if (!json)
			len = vty_out(vty, "%pFX", p);
		else {
			json_object_string_add(json, "prefix",
						inet_ntop(p->family,
							&p->u.prefix, buf,
							BUFSIZ));
			json_object_int_add(json, "prefixLen", p->prefixlen);
			prefix2str(p, buf2, PREFIX_STRLEN);
			json_object_string_add(json, "network", buf2);
		}
	}

	if (!json) {
		len = wide ? (45 - len) : (17 - len);
		if (len < 1)
			vty_out(vty, "\n%*s", 20, " ");
		else
			vty_out(vty, "%*s", len, " ");
	}
}

enum bgp_display_type {
	normal_list,
};

static const char *
bgp_path_selection_reason2str(enum bgp_path_selection_reason reason)
{
	switch (reason) {
	case bgp_path_selection_none:
		return "Nothing to Select";
	case bgp_path_selection_first:
		return "First path received";
	case bgp_path_selection_evpn_sticky_mac:
		return "EVPN Sticky Mac";
	case bgp_path_selection_evpn_seq:
		return "EVPN sequence number";
	case bgp_path_selection_evpn_lower_ip:
		return "EVPN lower IP";
	case bgp_path_selection_evpn_local_path:
		return "EVPN local ES path";
	case bgp_path_selection_evpn_non_proxy:
		return "EVPN non proxy";
	case bgp_path_selection_weight:
		return "Weight";
	case bgp_path_selection_local_pref:
		return "Local Pref";
	case bgp_path_selection_local_route:
		return "Local Route";
	case bgp_path_selection_confed_as_path:
		return "Confederation based AS Path";
	case bgp_path_selection_as_path:
		return "AS Path";
	case bgp_path_selection_origin:
		return "Origin";
	case bgp_path_selection_med:
		return "MED";
	case bgp_path_selection_peer:
		return "Peer Type";
	case bgp_path_selection_confed:
		return "Confed Peer Type";
	case bgp_path_selection_igp_metric:
		return "IGP Metric";
	case bgp_path_selection_older:
		return "Older Path";
	case bgp_path_selection_router_id:
		return "Router ID";
	case bgp_path_selection_cluster_length:
		return "Cluser length";
	case bgp_path_selection_stale:
		return "Path Staleness";
	case bgp_path_selection_local_configured:
		return "Locally configured route";
	case bgp_path_selection_neighbor_ip:
		return "Neighbor IP";
	case bgp_path_selection_default:
		return "Nothing left to compare";
	}
	return "Invalid (internal error)";
}

/* Print the short form route status for a bgp_path_info */
static void route_vty_short_status_out(struct vty *vty,
				       struct bgp_path_info *path,
				       json_object *json_path)
{
	if (json_path) {

		/* Route status display. */
		if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED))
			json_object_boolean_true_add(json_path, "removed");

		if (CHECK_FLAG(path->flags, BGP_PATH_STALE))
			json_object_boolean_true_add(json_path, "stale");

		if (path->extra && bgp_path_suppressed(path))
			json_object_boolean_true_add(json_path, "suppressed");

		if (CHECK_FLAG(path->flags, BGP_PATH_VALID)
		    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			json_object_boolean_true_add(json_path, "valid");

		/* Selected */
		if (CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			json_object_boolean_true_add(json_path, "history");

		if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED))
			json_object_boolean_true_add(json_path, "damped");

		if (CHECK_FLAG(path->flags, BGP_PATH_SELECTED)) {
			json_object_boolean_true_add(json_path, "bestpath");
			json_object_string_add(json_path, "selectionReason",
					       bgp_path_selection_reason2str(
						       path->net->reason));
		}

		if (CHECK_FLAG(path->flags, BGP_PATH_MULTIPATH))
			json_object_boolean_true_add(json_path, "multipath");

		/* Internal route. */
		if ((path->peer->as)
		    && (path->peer->as == path->peer->local_as))
			json_object_string_add(json_path, "pathFrom",
					       "internal");
		else
			json_object_string_add(json_path, "pathFrom",
					       "external");

		return;
	}

	/* Route status display. */
	if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED))
		vty_out(vty, "R");
	else if (CHECK_FLAG(path->flags, BGP_PATH_STALE))
		vty_out(vty, "S");
	else if (bgp_path_suppressed(path))
		vty_out(vty, "s");
	else if (CHECK_FLAG(path->flags, BGP_PATH_VALID)
		 && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
		vty_out(vty, "*");
	else
		vty_out(vty, " ");

	/* Selected */
	if (CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
		vty_out(vty, "h");
	else if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED))
		vty_out(vty, "d");
	else if (CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
		vty_out(vty, ">");
	else if (CHECK_FLAG(path->flags, BGP_PATH_MULTIPATH))
		vty_out(vty, "=");
	else
		vty_out(vty, " ");

	/* Internal route. */
	if (path->peer && (path->peer->as)
	    && (path->peer->as == path->peer->local_as))
		vty_out(vty, "i");
	else
		vty_out(vty, " ");
}

static char *bgp_nexthop_hostname(struct peer *peer,
				  struct bgp_nexthop_cache *bnc)
{
	if (peer->hostname
	    && CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME))
		return peer->hostname;
	return NULL;
}

/* called from terminal list command */
void route_vty_out(struct vty *vty, const struct prefix *p,
		   struct bgp_path_info *path, int display, safi_t safi,
		   json_object *json_paths, bool wide)
{
	int len;
	struct attr *attr = path->attr;
	json_object *json_path = NULL;
	json_object *json_nexthops = NULL;
	json_object *json_nexthop_global = NULL;
	json_object *json_nexthop_ll = NULL;
	json_object *json_ext_community = NULL;
	char vrf_id_str[VRF_NAMSIZ] = {0};
	bool nexthop_self =
		CHECK_FLAG(path->flags, BGP_PATH_ANNC_NH_SELF) ? true : false;
	bool nexthop_othervrf = false;
	vrf_id_t nexthop_vrfid = VRF_DEFAULT;
	const char *nexthop_vrfname = VRF_DEFAULT_NAME;
	char *nexthop_hostname =
		bgp_nexthop_hostname(path->peer, path->nexthop);
	char esi_buf[ESI_STR_LEN];

	if (json_paths)
		json_path = json_object_new_object();

	/* short status lead text */
	route_vty_short_status_out(vty, path, json_path);

	if (!json_paths) {
		/* print prefix and mask */
		if (!display)
			route_vty_out_route(p, vty, json_path, wide);
		else
			vty_out(vty, "%*s", (wide ? 45 : 17), " ");
	} else {
		route_vty_out_route(p, vty, json_path, wide);
	}

	/*
	 * If vrf id of nexthop is different from that of prefix,
	 * set up printable string to append
	 */
	if (path->extra && path->extra->bgp_orig) {
		const char *self = "";

		if (nexthop_self)
			self = "<";

		nexthop_othervrf = true;
		nexthop_vrfid = path->extra->bgp_orig->vrf_id;

		if (path->extra->bgp_orig->vrf_id == VRF_UNKNOWN)
			snprintf(vrf_id_str, sizeof(vrf_id_str),
				"@%s%s", VRFID_NONE_STR, self);
		else
			snprintf(vrf_id_str, sizeof(vrf_id_str), "@%u%s",
				 path->extra->bgp_orig->vrf_id, self);

		if (path->extra->bgp_orig->inst_type
		    != BGP_INSTANCE_TYPE_DEFAULT)

			nexthop_vrfname = path->extra->bgp_orig->name;
	} else {
		const char *self = "";

		if (nexthop_self)
			self = "<";

		snprintf(vrf_id_str, sizeof(vrf_id_str), "%s", self);
	}

	/*
	 * For ENCAP and EVPN routes, nexthop address family is not
	 * neccessarily the same as the prefix address family.
	 * Both SAFI_MPLS_VPN and SAFI_ENCAP use the MP nexthop field
	 * EVPN routes are also exchanged with a MP nexthop. Currently,
	 * this
	 * is only IPv4, the value will be present in either
	 * attr->nexthop or
	 * attr->mp_nexthop_global_in
	 */
	if ((safi == SAFI_ENCAP) || (safi == SAFI_MPLS_VPN)) {
		char buf[BUFSIZ];
		char nexthop[128];
		int af = NEXTHOP_FAMILY(attr->mp_nexthop_len);

		switch (af) {
		case AF_INET:
			snprintf(nexthop, sizeof(nexthop), "%s",
				 inet_ntop(af, &attr->mp_nexthop_global_in, buf,
					   BUFSIZ));
			break;
		case AF_INET6:
			snprintf(nexthop, sizeof(nexthop), "%s",
				 inet_ntop(af, &attr->mp_nexthop_global, buf,
					   BUFSIZ));
			break;
		default:
			snprintf(nexthop, sizeof(nexthop), "?");
			break;
		}

		if (json_paths) {
			json_nexthop_global = json_object_new_object();

			json_object_string_add(json_nexthop_global, "ip",
					       nexthop);

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_global,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_global, "afi",
					       (af == AF_INET) ? "ipv4"
							       : "ipv6");
			json_object_boolean_true_add(json_nexthop_global,
						     "used");
		} else {
			if (nexthop_hostname)
				len = vty_out(vty, "%s(%s)%s", nexthop,
					      nexthop_hostname, vrf_id_str);
			else
				len = vty_out(vty, "%s%s", nexthop, vrf_id_str);

			len = wide ? (41 - len) : (16 - len);
			if (len < 1)
				vty_out(vty, "\n%*s", 36, " ");
			else
				vty_out(vty, "%*s", len, " ");
		}
	} else if (safi == SAFI_EVPN) {
		if (json_paths) {
			char buf[BUFSIZ] = {0};

			json_nexthop_global = json_object_new_object();

			json_object_string_add(json_nexthop_global, "ip",
					       inet_ntop(AF_INET,
							 &attr->nexthop, buf,
							 sizeof(buf)));

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_global,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_global, "afi",
					       "ipv4");
			json_object_boolean_true_add(json_nexthop_global,
						     "used");
		} else {
			if (nexthop_hostname)
				len = vty_out(vty, "%pI4(%s)%s", &attr->nexthop,
					      nexthop_hostname, vrf_id_str);
			else
				len = vty_out(vty, "%pI4%s", &attr->nexthop,
					      vrf_id_str);

			len = wide ? (41 - len) : (16 - len);
			if (len < 1)
				vty_out(vty, "\n%*s", 36, " ");
			else
				vty_out(vty, "%*s", len, " ");
		}
	} else if (safi == SAFI_FLOWSPEC) {
		if (attr->nexthop.s_addr != INADDR_ANY) {
			if (json_paths) {
				char buf[BUFSIZ] = {0};

				json_nexthop_global = json_object_new_object();

				json_object_string_add(json_nexthop_global,
						       "afi", "ipv4");
				json_object_string_add(
					json_nexthop_global, "ip",
					inet_ntop(AF_INET, &attr->nexthop, buf,
						  sizeof(buf)));

				if (path->peer->hostname)
					json_object_string_add(
						json_nexthop_global, "hostname",
						path->peer->hostname);

				json_object_boolean_true_add(
							json_nexthop_global,
							     "used");
			} else {
				if (nexthop_hostname)
					len = vty_out(vty, "%pI4(%s)%s",
						      &attr->nexthop,
						      nexthop_hostname,
						      vrf_id_str);
				else
					len = vty_out(vty, "%pI4%s",
						      &attr->nexthop,
						      vrf_id_str);

				len = wide ? (41 - len) : (16 - len);
				if (len < 1)
					vty_out(vty, "\n%*s", 36, " ");
				else
					vty_out(vty, "%*s", len, " ");
			}
		}
	} else if (p->family == AF_INET && !BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
		if (json_paths) {
			char buf[BUFSIZ] = {0};

			json_nexthop_global = json_object_new_object();

			json_object_string_add(json_nexthop_global, "ip",
					       inet_ntop(AF_INET,
							 &attr->nexthop, buf,
							 sizeof(buf)));

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_global,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_global, "afi",
					       "ipv4");
			json_object_boolean_true_add(json_nexthop_global,
						     "used");
		} else {
			if (nexthop_hostname)
				len = vty_out(vty, "%pI4(%s)%s", &attr->nexthop,
					      nexthop_hostname, vrf_id_str);
			else
				len = vty_out(vty, "%pI4%s", &attr->nexthop,
					      vrf_id_str);

			len = wide ? (41 - len) : (16 - len);
			if (len < 1)
				vty_out(vty, "\n%*s", 36, " ");
			else
				vty_out(vty, "%*s", len, " ");
		}
	}

	/* IPv6 Next Hop */
	else if (p->family == AF_INET6 || BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
		char buf[BUFSIZ];

		if (json_paths) {
			json_nexthop_global = json_object_new_object();
			json_object_string_add(
				json_nexthop_global, "ip",
				inet_ntop(AF_INET6, &attr->mp_nexthop_global,
					  buf, BUFSIZ));

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_global,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_global, "afi",
					       "ipv6");
			json_object_string_add(json_nexthop_global, "scope",
					       "global");

			/* We display both LL & GL if both have been
			 * received */
			if ((attr->mp_nexthop_len
			     == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
			    || (path->peer->conf_if)) {
				json_nexthop_ll = json_object_new_object();
				json_object_string_add(
					json_nexthop_ll, "ip",
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_local, buf,
						  BUFSIZ));

				if (path->peer->hostname)
					json_object_string_add(
						json_nexthop_ll, "hostname",
						path->peer->hostname);

				json_object_string_add(json_nexthop_ll, "afi",
						       "ipv6");
				json_object_string_add(json_nexthop_ll, "scope",
						       "link-local");

				if ((IPV6_ADDR_CMP(&attr->mp_nexthop_global,
						   &attr->mp_nexthop_local)
				     != 0)
				    && !attr->mp_nexthop_prefer_global)
					json_object_boolean_true_add(
						json_nexthop_ll, "used");
				else
					json_object_boolean_true_add(
						json_nexthop_global, "used");
			} else
				json_object_boolean_true_add(
					json_nexthop_global, "used");
		} else {
			/* Display LL if LL/Global both in table unless
			 * prefer-global is set */
			if (((attr->mp_nexthop_len
			      == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
			     && !attr->mp_nexthop_prefer_global)
			    || (path->peer->conf_if)) {
				if (path->peer->conf_if) {
					len = vty_out(vty, "%s",
						      path->peer->conf_if);
					/* len of IPv6 addr + max len of def
					 * ifname */
					len = wide ? (41 - len) : (16 - len);

					if (len < 1)
						vty_out(vty, "\n%*s", 36, " ");
					else
						vty_out(vty, "%*s", len, " ");
				} else {
					if (nexthop_hostname)
						len = vty_out(
							vty, "%pI6(%s)%s",
							&attr->mp_nexthop_local,
							nexthop_hostname,
							vrf_id_str);
					else
						len = vty_out(
							vty, "%pI6%s",
							&attr->mp_nexthop_local,
							vrf_id_str);

					len = wide ? (41 - len) : (16 - len);

					if (len < 1)
						vty_out(vty, "\n%*s", 36, " ");
					else
						vty_out(vty, "%*s", len, " ");
				}
			} else {
				if (nexthop_hostname)
					len = vty_out(vty, "%pI6(%s)%s",
						      &attr->mp_nexthop_global,
						      nexthop_hostname,
						      vrf_id_str);
				else
					len = vty_out(vty, "%pI6%s",
						      &attr->mp_nexthop_global,
						      vrf_id_str);

				len = wide ? (41 - len) : (16 - len);

				if (len < 1)
					vty_out(vty, "\n%*s", 36, " ");
				else
					vty_out(vty, "%*s", len, " ");
			}
		}
	}

	/* MED/Metric */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
		if (json_paths)
			json_object_int_add(json_path, "metric", attr->med);
		else if (wide)
			vty_out(vty, "%7u", attr->med);
		else
			vty_out(vty, "%10u", attr->med);
	else if (!json_paths) {
		if (wide)
			vty_out(vty, "%*s", 7, " ");
		else
			vty_out(vty, "%*s", 10, " ");
	}

	/* Local Pref */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
		if (json_paths)
			json_object_int_add(json_path, "locPrf",
					    attr->local_pref);
		else
			vty_out(vty, "%7u", attr->local_pref);
	else if (!json_paths)
		vty_out(vty, "       ");

	if (json_paths)
		json_object_int_add(json_path, "weight", attr->weight);
	else
		vty_out(vty, "%7u ", attr->weight);

	if (json_paths) {
		char buf[BUFSIZ];
		json_object_string_add(
			json_path, "peerId",
			sockunion2str(&path->peer->su, buf, SU_ADDRSTRLEN));
	}

	/* Print aspath */
	if (attr->aspath) {
		if (json_paths)
			json_object_string_add(json_path, "path",
					       attr->aspath->str);
		else
			aspath_print_vty(vty, "%s", attr->aspath, " ");
	}

	/* Print origin */
	if (json_paths)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[attr->origin]);
	else
		vty_out(vty, "%s", bgp_origin_str[attr->origin]);

	if (json_paths) {
		if (bgp_evpn_is_esi_valid(&attr->esi)) {
			json_object_string_add(json_path, "esi",
					esi_to_str(&attr->esi,
					esi_buf, sizeof(esi_buf)));
		}
		if (safi == SAFI_EVPN &&
		    attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) {
			json_ext_community = json_object_new_object();
			json_object_string_add(json_ext_community,
					       "string",
					       attr->ecommunity->str);
			json_object_object_add(json_path,
					       "extendedCommunity",
					       json_ext_community);
		}

		if (nexthop_self)
			json_object_boolean_true_add(json_path,
				"announceNexthopSelf");
		if (nexthop_othervrf) {
			json_object_string_add(json_path, "nhVrfName",
				nexthop_vrfname);

			json_object_int_add(json_path, "nhVrfId",
				((nexthop_vrfid == VRF_UNKNOWN)
					? -1
					: (int)nexthop_vrfid));
		}
	}

	if (json_paths) {
		if (json_nexthop_global || json_nexthop_ll) {
			json_nexthops = json_object_new_array();

			if (json_nexthop_global)
				json_object_array_add(json_nexthops,
						      json_nexthop_global);

			if (json_nexthop_ll)
				json_object_array_add(json_nexthops,
						      json_nexthop_ll);

			json_object_object_add(json_path, "nexthops",
					       json_nexthops);
		}

		json_object_array_add(json_paths, json_path);
	} else {
		vty_out(vty, "\n");

		if (safi == SAFI_EVPN) {
			struct bgp_path_es_info *path_es_info = NULL;

			if (path->extra)
				path_es_info = path->extra->es_info;

			if (bgp_evpn_is_esi_valid(&attr->esi)) {
				/* XXX - add these params to the json out */
				vty_out(vty, "%*s", 20, " ");
				vty_out(vty, "ESI:%s",
					esi_to_str(&attr->esi, esi_buf,
						   sizeof(esi_buf)));
				if (path_es_info && path_es_info->es)
					vty_out(vty, " VNI: %u",
						path_es_info->vni);
				vty_out(vty, "\n");
			}
			if (attr->flag &
				ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) {
				vty_out(vty, "%*s", 20, " ");
				vty_out(vty, "%s\n", attr->ecommunity->str);
			}
		}

#ifdef ENABLE_BGP_VNC
		/* prints an additional line, indented, with VNC info, if
		 * present */
		if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
			rfapi_vty_out_vncinfo(vty, p, path, safi);
#endif
	}
}

/* called from terminal list command */
void route_vty_out_tmp(struct vty *vty, const struct prefix *p,
		       struct attr *attr, safi_t safi, bool use_json,
		       json_object *json_ar, bool wide)
{
	json_object *json_status = NULL;
	json_object *json_net = NULL;
	int len;
	char buff[BUFSIZ];

	/* Route status display. */
	if (use_json) {
		json_status = json_object_new_object();
		json_net = json_object_new_object();
	} else {
		vty_out(vty, "*");
		vty_out(vty, ">");
		vty_out(vty, " ");
	}

	/* print prefix and mask */
	if (use_json) {
		if (safi == SAFI_EVPN)
			bgp_evpn_route2json((struct prefix_evpn *)p, json_net);
		else if (p->family == AF_INET || p->family == AF_INET6) {
			json_object_string_add(
				json_net, "addrPrefix",
				inet_ntop(p->family, &p->u.prefix, buff,
				BUFSIZ));
			json_object_int_add(json_net, "prefixLen",
				p->prefixlen);
			prefix2str(p, buff, PREFIX_STRLEN);
			json_object_string_add(json_net, "network", buff);
		}
	} else
		route_vty_out_route(p, vty, NULL, wide);

	/* Print attribute */
	if (attr) {
		if (use_json) {
			char buf[BUFSIZ] = {0};

			if (p->family == AF_INET
			    && (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
				|| !BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
				if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
					json_object_string_add(
						json_net, "nextHop",
						inet_ntop(
							AF_INET,
							&attr->mp_nexthop_global_in,
							buf, sizeof(buf)));
				else
					json_object_string_add(
						json_net, "nextHop",
						inet_ntop(AF_INET,
							  &attr->nexthop, buf,
							  sizeof(buf)));
			} else if (p->family == AF_INET6
				   || BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
				char buf[BUFSIZ];

				json_object_string_add(
					json_net, "nextHopGlobal",
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_global, buf,
						  BUFSIZ));
			} else if (p->family == AF_EVPN
				   && !BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
				char buf[BUFSIZ] = {0};

				json_object_string_add(
					json_net, "nextHop",
					inet_ntop(AF_INET,
						  &attr->mp_nexthop_global_in,
						  buf, sizeof(buf)));
			}

			if (attr->flag
			    & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
				json_object_int_add(json_net, "metric",
						    attr->med);

			if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
				json_object_int_add(json_net, "locPrf",
						    attr->local_pref);

			json_object_int_add(json_net, "weight", attr->weight);

			/* Print aspath */
			if (attr->aspath)
				json_object_string_add(json_net, "path",
						       attr->aspath->str);

			/* Print origin */
			json_object_string_add(json_net, "bgpOriginCode",
					       bgp_origin_str[attr->origin]);
		} else {
			if (p->family == AF_INET
			    && (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
				|| safi == SAFI_EVPN
				|| !BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
				if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
				    || safi == SAFI_EVPN)
					vty_out(vty, "%-16pI4",
						&attr->mp_nexthop_global_in);
				else if (wide)
					vty_out(vty, "%-41pI4", &attr->nexthop);
				else
					vty_out(vty, "%-16pI4", &attr->nexthop);
			} else if (p->family == AF_INET6
				   || BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
				char buf[BUFSIZ];

				len = vty_out(
					vty, "%s",
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_global, buf,
						  BUFSIZ));
				len = wide ? (41 - len) : (16 - len);
				if (len < 1)
					vty_out(vty, "\n%*s", 36, " ");
				else
					vty_out(vty, "%*s", len, " ");
			}
			if (attr->flag
			    & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
				if (wide)
					vty_out(vty, "%7u", attr->med);
				else
					vty_out(vty, "%10u", attr->med);
			else if (wide)
				vty_out(vty, "       ");
			else
				vty_out(vty, "          ");

			if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
				vty_out(vty, "%7u", attr->local_pref);
			else
				vty_out(vty, "       ");

			vty_out(vty, "%7u ", attr->weight);

			/* Print aspath */
			if (attr->aspath)
				aspath_print_vty(vty, "%s", attr->aspath, " ");

			/* Print origin */
			vty_out(vty, "%s", bgp_origin_str[attr->origin]);
		}
	}
	if (use_json) {
		json_object_boolean_true_add(json_status, "*");
		json_object_boolean_true_add(json_status, ">");
		json_object_object_add(json_net, "appliedStatusSymbols",
				       json_status);

		prefix2str(p, buff, PREFIX_STRLEN);
		json_object_object_add(json_ar, buff, json_net);
	} else
		vty_out(vty, "\n");
}

void route_vty_out_tag(struct vty *vty, const struct prefix *p,
		       struct bgp_path_info *path, int display, safi_t safi,
		       json_object *json)
{
	json_object *json_out = NULL;
	struct attr *attr;
	mpls_label_t label = MPLS_INVALID_LABEL;

	if (!path->extra)
		return;

	if (json)
		json_out = json_object_new_object();

	/* short status lead text */
	route_vty_short_status_out(vty, path, json_out);

	/* print prefix and mask */
	if (json == NULL) {
		if (!display)
			route_vty_out_route(p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");
	}

	/* Print attribute */
	attr = path->attr;
	if (((p->family == AF_INET)
	     && ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)))
	    || (safi == SAFI_EVPN && !BGP_ATTR_NEXTHOP_AFI_IP6(attr))
	    || (!BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
		char buf[BUFSIZ] = {0};

		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			if (json)
				json_object_string_add(
					json_out, "mpNexthopGlobalIn",
					inet_ntop(AF_INET,
						  &attr->mp_nexthop_global_in,
						  buf, sizeof(buf)));
			else
				vty_out(vty, "%-16pI4",
					&attr->mp_nexthop_global_in);
		} else {
			if (json)
				json_object_string_add(
					json_out, "nexthop",
					inet_ntop(AF_INET, &attr->nexthop, buf,
						  sizeof(buf)));
			else
				vty_out(vty, "%-16pI4", &attr->nexthop);
		}
	} else if (((p->family == AF_INET6)
		    && ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)))
		   || (safi == SAFI_EVPN && BGP_ATTR_NEXTHOP_AFI_IP6(attr))
		   || (BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
		char buf_a[512];

		if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL) {
			if (json)
				json_object_string_add(
					json_out, "mpNexthopGlobalIn",
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_global,
						  buf_a, sizeof(buf_a)));
			else
				vty_out(vty, "%s",
					inet_ntop(AF_INET6,
						  &attr->mp_nexthop_global,
						  buf_a, sizeof(buf_a)));
		} else if (attr->mp_nexthop_len
			   == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
			snprintfrr(buf_a, sizeof(buf_a), "%pI6(%pI6)",
				   &attr->mp_nexthop_global,
				   &attr->mp_nexthop_local);
			if (json)
				json_object_string_add(json_out,
						       "mpNexthopGlobalLocal",
						       buf_a);
			else
				vty_out(vty, "%s", buf_a);
		}
	}

	label = decode_label(&path->extra->label[0]);

	if (bgp_is_valid_label(&label)) {
		if (json) {
			json_object_int_add(json_out, "notag", label);
			json_object_array_add(json, json_out);
		} else {
			vty_out(vty, "notag/%d", label);
			vty_out(vty, "\n");
		}
	}
}

void route_vty_out_overlay(struct vty *vty, const struct prefix *p,
			   struct bgp_path_info *path, int display,
			   json_object *json_paths)
{
	struct attr *attr;
	char buf[BUFSIZ] = {0};
	json_object *json_path = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_overlay = NULL;

	if (!path->extra)
		return;

	if (json_paths) {
		json_path = json_object_new_object();
		json_overlay = json_object_new_object();
		json_nexthop = json_object_new_object();
	}

	/* short status lead text */
	route_vty_short_status_out(vty, path, json_path);

	/* print prefix and mask */
	if (!display)
		route_vty_out_route(p, vty, json_path, false);
	else
		vty_out(vty, "%*s", 17, " ");

	/* Print attribute */
	attr = path->attr;
	char buf1[BUFSIZ];
	int af = NEXTHOP_FAMILY(attr->mp_nexthop_len);

	switch (af) {
	case AF_INET:
		inet_ntop(af, &attr->mp_nexthop_global_in, buf, BUFSIZ);
		if (!json_path) {
			vty_out(vty, "%-16s", buf);
		} else {
			json_object_string_add(json_nexthop, "ip", buf);

			json_object_string_add(json_nexthop, "afi", "ipv4");

			json_object_object_add(json_path, "nexthop",
					       json_nexthop);
		}
		break;
	case AF_INET6:
		inet_ntop(af, &attr->mp_nexthop_global, buf, BUFSIZ);
		inet_ntop(af, &attr->mp_nexthop_local, buf1, BUFSIZ);
		if (!json_path) {
			vty_out(vty, "%s(%s)", buf, buf1);
		} else {
			json_object_string_add(json_nexthop, "ipv6Global", buf);

			json_object_string_add(json_nexthop, "ipv6LinkLocal",
					       buf1);

			json_object_string_add(json_nexthop, "afi", "ipv6");

			json_object_object_add(json_path, "nexthop",
					       json_nexthop);
		}
		break;
	default:
		if (!json_path) {
			vty_out(vty, "?");
		} else {
			json_object_string_add(json_nexthop, "Error",
					       "Unsupported address-family");
		}
	}

	const struct bgp_route_evpn *eo = bgp_attr_get_evpn_overlay(attr);

	if (is_evpn_prefix_ipaddr_v4((struct prefix_evpn *)p))
		inet_ntop(AF_INET, &eo->gw_ip.ipv4, buf, BUFSIZ);
	else if (is_evpn_prefix_ipaddr_v6((struct prefix_evpn *)p))
		inet_ntop(AF_INET6, &eo->gw_ip.ipv6, buf, BUFSIZ);

	if (!json_path)
		vty_out(vty, "/%s", buf);
	else
		json_object_string_add(json_overlay, "gw", buf);

	if (attr->ecommunity) {
		char *mac = NULL;
		struct ecommunity_val *routermac = ecommunity_lookup(
			attr->ecommunity, ECOMMUNITY_ENCODE_EVPN,
			ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC);

		if (routermac)
			mac = ecom_mac2str((char *)routermac->val);
		if (mac) {
			if (!json_path) {
				vty_out(vty, "/%s", mac);
			} else {
				json_object_string_add(json_overlay, "rmac",
						       mac);
			}
			XFREE(MTYPE_TMP, mac);
		}
	}

	if (!json_path) {
		vty_out(vty, "\n");
	} else {
		json_object_object_add(json_path, "overlay", json_overlay);

		json_object_array_add(json_paths, json_path);
	}
}

/* dampening route */
static void damp_route_vty_out(struct vty *vty, const struct prefix *p,
			       struct bgp_path_info *path, int display,
			       afi_t afi, safi_t safi, bool use_json,
			       json_object *json)
{
	struct attr *attr;
	int len;
	char timebuf[BGP_UPTIME_LEN];

	/* short status lead text */
	route_vty_short_status_out(vty, path, json);

	/* print prefix and mask */
	if (!use_json) {
		if (!display)
			route_vty_out_route(p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");
	}

	len = vty_out(vty, "%s", path->peer->host);
	len = 17 - len;
	if (len < 1) {
		if (!use_json)
			vty_out(vty, "\n%*s", 34, " ");
	} else {
		if (use_json)
			json_object_int_add(json, "peerHost", len);
		else
			vty_out(vty, "%*s", len, " ");
	}

	if (use_json)
		bgp_damp_reuse_time_vty(vty, path, timebuf, BGP_UPTIME_LEN, afi,
					safi, use_json, json);
	else
		vty_out(vty, "%s ",
			bgp_damp_reuse_time_vty(vty, path, timebuf,
						BGP_UPTIME_LEN, afi, safi,
						use_json, json));

	/* Print attribute */
	attr = path->attr;

	/* Print aspath */
	if (attr->aspath) {
		if (use_json)
			json_object_string_add(json, "asPath",
					       attr->aspath->str);
		else
			aspath_print_vty(vty, "%s", attr->aspath, " ");
	}

	/* Print origin */
	if (use_json)
		json_object_string_add(json, "origin",
				       bgp_origin_str[attr->origin]);
	else
		vty_out(vty, "%s", bgp_origin_str[attr->origin]);

	if (!use_json)
		vty_out(vty, "\n");
}

/* flap route */
static void flap_route_vty_out(struct vty *vty, const struct prefix *p,
			       struct bgp_path_info *path, int display,
			       afi_t afi, safi_t safi, bool use_json,
			       json_object *json)
{
	struct attr *attr;
	struct bgp_damp_info *bdi;
	char timebuf[BGP_UPTIME_LEN];
	int len;

	if (!path->extra)
		return;

	bdi = path->extra->damp_info;

	/* short status lead text */
	route_vty_short_status_out(vty, path, json);

	/* print prefix and mask */
	if (!use_json) {
		if (!display)
			route_vty_out_route(p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");
	}

	len = vty_out(vty, "%s", path->peer->host);
	len = 16 - len;
	if (len < 1) {
		if (!use_json)
			vty_out(vty, "\n%*s", 33, " ");
	} else {
		if (use_json)
			json_object_int_add(json, "peerHost", len);
		else
			vty_out(vty, "%*s", len, " ");
	}

	len = vty_out(vty, "%d", bdi->flap);
	len = 5 - len;
	if (len < 1) {
		if (!use_json)
			vty_out(vty, " ");
	} else {
		if (use_json)
			json_object_int_add(json, "bdiFlap", len);
		else
			vty_out(vty, "%*s", len, " ");
	}

	if (use_json)
		peer_uptime(bdi->start_time, timebuf, BGP_UPTIME_LEN, use_json,
			    json);
	else
		vty_out(vty, "%s ", peer_uptime(bdi->start_time, timebuf,
						BGP_UPTIME_LEN, 0, NULL));

	if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)
	    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY)) {
		if (use_json)
			bgp_damp_reuse_time_vty(vty, path, timebuf,
						BGP_UPTIME_LEN, afi, safi,
						use_json, json);
		else
			vty_out(vty, "%s ",
				bgp_damp_reuse_time_vty(vty, path, timebuf,
							BGP_UPTIME_LEN, afi,
							safi, use_json, json));
	} else {
		if (!use_json)
			vty_out(vty, "%*s ", 8, " ");
	}

	/* Print attribute */
	attr = path->attr;

	/* Print aspath */
	if (attr->aspath) {
		if (use_json)
			json_object_string_add(json, "asPath",
					       attr->aspath->str);
		else
			aspath_print_vty(vty, "%s", attr->aspath, " ");
	}

	/* Print origin */
	if (use_json)
		json_object_string_add(json, "origin",
				       bgp_origin_str[attr->origin]);
	else
		vty_out(vty, "%s", bgp_origin_str[attr->origin]);

	if (!use_json)
		vty_out(vty, "\n");
}

static void route_vty_out_advertised_to(struct vty *vty, struct peer *peer,
					int *first, const char *header,
					json_object *json_adv_to)
{
	char buf1[INET6_ADDRSTRLEN];
	json_object *json_peer = NULL;

	if (json_adv_to) {
		/* 'advertised-to' is a dictionary of peers we have advertised
		 * this
		 * prefix too.  The key is the peer's IP or swpX, the value is
		 * the
		 * hostname if we know it and "" if not.
		 */
		json_peer = json_object_new_object();

		if (peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       peer->hostname);

		if (peer->conf_if)
			json_object_object_add(json_adv_to, peer->conf_if,
					       json_peer);
		else
			json_object_object_add(
				json_adv_to,
				sockunion2str(&peer->su, buf1, SU_ADDRSTRLEN),
				json_peer);
	} else {
		if (*first) {
			vty_out(vty, "%s", header);
			*first = 0;
		}

		if (peer->hostname
		    && CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHOW_HOSTNAME)) {
			if (peer->conf_if)
				vty_out(vty, " %s(%s)", peer->hostname,
					peer->conf_if);
			else
				vty_out(vty, " %s(%s)", peer->hostname,
					sockunion2str(&peer->su, buf1,
						      SU_ADDRSTRLEN));
		} else {
			if (peer->conf_if)
				vty_out(vty, " %s", peer->conf_if);
			else
				vty_out(vty, " %s",
					sockunion2str(&peer->su, buf1,
						      SU_ADDRSTRLEN));
		}
	}
}

static void route_vty_out_tx_ids(struct vty *vty,
				 struct bgp_addpath_info_data *d)
{
	int i;

	for (i = 0; i < BGP_ADDPATH_MAX; i++) {
		vty_out(vty, "TX-%s %u%s", bgp_addpath_names(i)->human_name,
			d->addpath_tx_id[i],
			i < BGP_ADDPATH_MAX - 1 ? " " : "\n");
	}
}

static void route_vty_out_detail_es_info(struct vty *vty,
					 struct bgp_path_info *pi,
					 struct attr *attr,
					 json_object *json_path)
{
	char esi_buf[ESI_STR_LEN];
	bool es_local = !!CHECK_FLAG(attr->es_flags, ATTR_ES_IS_LOCAL);
	bool peer_router = !!CHECK_FLAG(attr->es_flags,
			ATTR_ES_PEER_ROUTER);
	bool peer_active = !!CHECK_FLAG(attr->es_flags,
			ATTR_ES_PEER_ACTIVE);
	bool peer_proxy = !!CHECK_FLAG(attr->es_flags,
			ATTR_ES_PEER_PROXY);
	esi_to_str(&attr->esi, esi_buf, sizeof(esi_buf));
	if (json_path) {
		json_object *json_es_info = NULL;

		json_object_string_add(
				json_path, "esi",
				esi_buf);
		if (es_local || bgp_evpn_attr_is_sync(attr)) {
			json_es_info = json_object_new_object();
			if (es_local)
				json_object_boolean_true_add(
						json_es_info, "localEs");
			if (peer_active)
				json_object_boolean_true_add(
						json_es_info, "peerActive");
			if (peer_proxy)
				json_object_boolean_true_add(
						json_es_info, "peerProxy");
			if (peer_router)
				json_object_boolean_true_add(
						json_es_info, "peerRouter");
			if (attr->mm_sync_seqnum)
				json_object_int_add(
						json_es_info, "peerSeq",
						attr->mm_sync_seqnum);
			json_object_object_add(
					json_path, "es_info",
					json_es_info);
		}
	} else {
		if (bgp_evpn_attr_is_sync(attr))
			vty_out(vty,
					"      ESI %s %s peer-info: (%s%s%sMM: %d)\n",
					esi_buf,
					es_local ? "local-es":"",
					peer_proxy ? "proxy " : "",
					peer_active ? "active ":"",
					peer_router ? "router ":"",
					attr->mm_sync_seqnum);
		else
			vty_out(vty, "      ESI %s %s\n",
					esi_buf,
					es_local ? "local-es":"");
	}
}

void route_vty_out_detail(struct vty *vty, struct bgp *bgp,
		struct bgp_dest *bn, struct bgp_path_info *path,
		afi_t afi, safi_t safi, json_object *json_paths)
{
	char buf[INET6_ADDRSTRLEN];
	char buf1[BUFSIZ];
	struct attr *attr = path->attr;
	int sockunion_vty_out(struct vty *, union sockunion *);
	time_t tbuf;
	json_object *json_bestpath = NULL;
	json_object *json_cluster_list = NULL;
	json_object *json_cluster_list_list = NULL;
	json_object *json_ext_community = NULL;
	json_object *json_last_update = NULL;
	json_object *json_pmsi = NULL;
	json_object *json_nexthop_global = NULL;
	json_object *json_nexthop_ll = NULL;
	json_object *json_nexthops = NULL;
	json_object *json_path = NULL;
	json_object *json_peer = NULL;
	json_object *json_string = NULL;
	json_object *json_adv_to = NULL;
	int first = 0;
	struct listnode *node, *nnode;
	struct peer *peer;
	int addpath_capable;
	int has_adj;
	unsigned int first_as;
	bool nexthop_self =
		CHECK_FLAG(path->flags, BGP_PATH_ANNC_NH_SELF) ? true : false;
	int i;
	char *nexthop_hostname =
		bgp_nexthop_hostname(path->peer, path->nexthop);

	if (json_paths) {
		json_path = json_object_new_object();
		json_peer = json_object_new_object();
		json_nexthop_global = json_object_new_object();
	}

	if (path->extra) {
		char tag_buf[30];

		tag_buf[0] = '\0';
		if (path->extra && path->extra->num_labels) {
			bgp_evpn_label2str(path->extra->label,
					   path->extra->num_labels, tag_buf,
					   sizeof(tag_buf));
		}
		if (safi == SAFI_EVPN) {
			if (!json_paths) {
				vty_out(vty, "  Route %pFX",
					(struct prefix_evpn *)
						bgp_dest_get_prefix(bn));
				if (tag_buf[0] != '\0')
					vty_out(vty, " VNI %s", tag_buf);
				vty_out(vty, "\n");
			} else {
				if (tag_buf[0])
					json_object_string_add(json_path, "VNI",
							       tag_buf);
			}
		}

		if (path->extra && path->extra->parent && !json_paths) {
			struct bgp_path_info *parent_ri;
			struct bgp_dest *dest, *pdest;

			parent_ri = (struct bgp_path_info *)path->extra->parent;
			dest = parent_ri->net;
			if (dest && dest->pdest) {
				pdest = dest->pdest;
				prefix_rd2str(
					(struct prefix_rd *)bgp_dest_get_prefix(
						pdest),
					buf1, sizeof(buf1));
				if (is_pi_family_evpn(parent_ri)) {
					vty_out(vty,
						"  Imported from %s:%pFX, VNI %s\n",
						buf1,
						(struct prefix_evpn *)
							bgp_dest_get_prefix(
								dest),
						tag_buf);
				} else
					vty_out(vty,
						"  Imported from %s:%pFX\n",
						buf1,
						(struct prefix_evpn *)
							bgp_dest_get_prefix(
								dest));
			}
		}
	}

	/* Line1 display AS-path, Aggregator */
	if (attr->aspath) {
		if (json_paths) {
			if (!attr->aspath->json)
				aspath_str_update(attr->aspath, true);
			json_object_lock(attr->aspath->json);
			json_object_object_add(json_path, "aspath",
					       attr->aspath->json);
		} else {
			if (attr->aspath->segments)
				aspath_print_vty(vty, "  %s", attr->aspath, "");
			else
				vty_out(vty, "  Local");
		}
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED)) {
		if (json_paths)
			json_object_boolean_true_add(json_path, "removed");
		else
			vty_out(vty, ", (removed)");
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_STALE)) {
		if (json_paths)
			json_object_boolean_true_add(json_path, "stale");
		else
			vty_out(vty, ", (stale)");
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
		if (json_paths) {
			char buf[BUFSIZ] = {0};

			json_object_int_add(json_path, "aggregatorAs",
					    attr->aggregator_as);
			json_object_string_add(json_path, "aggregatorId",
					       inet_ntop(AF_INET,
							 &attr->aggregator_addr,
							 buf, sizeof(buf)));
			if (attr->aggregator_as == BGP_AS_ZERO)
				json_object_boolean_true_add(
					json_path, "aggregatorAsMalformed");
			else
				json_object_boolean_false_add(
					json_path, "aggregatorAsMalformed");
		} else {
			if (attr->aggregator_as == BGP_AS_ZERO)
				vty_out(vty,
					", (aggregated by %u(malformed) %pI4)",
					attr->aggregator_as,
					&attr->aggregator_addr);
			else
				vty_out(vty, ", (aggregated by %u %pI4)",
					attr->aggregator_as,
					&attr->aggregator_addr);
		}
	}

	if (CHECK_FLAG(path->peer->af_flags[afi][safi],
		       PEER_FLAG_REFLECTOR_CLIENT)) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "rxedFromRrClient");
		else
			vty_out(vty, ", (Received from a RR-client)");
	}

	if (CHECK_FLAG(path->peer->af_flags[afi][safi],
		       PEER_FLAG_RSERVER_CLIENT)) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "rxedFromRsClient");
		else
			vty_out(vty, ", (Received from a RS-client)");
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_HISTORY)) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "dampeningHistoryEntry");
		else
			vty_out(vty, ", (history entry)");
	} else if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "dampeningSuppressed");
		else
			vty_out(vty, ", (suppressed due to dampening)");
	}

	if (!json_paths)
		vty_out(vty, "\n");

	/* Line2 display Next-hop, Neighbor, Router-id */
	/* Display the nexthop */
	const struct prefix *bn_p = bgp_dest_get_prefix(bn);

	if ((bn_p->family == AF_INET || bn_p->family == AF_ETHERNET
	     || bn_p->family == AF_EVPN)
	    && (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN
		|| !BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
		char buf[BUFSIZ] = {0};

		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			if (json_paths) {
				json_object_string_add(
					json_nexthop_global, "ip",
					inet_ntop(AF_INET,
						  &attr->mp_nexthop_global_in,
						  buf, sizeof(buf)));

				if (path->peer->hostname)
					json_object_string_add(
						json_nexthop_global, "hostname",
						path->peer->hostname);
			} else {
				if (nexthop_hostname)
					vty_out(vty, "    %pI4(%s)",
						&attr->mp_nexthop_global_in,
						nexthop_hostname);
				else
					vty_out(vty, "    %pI4",
						&attr->mp_nexthop_global_in);
			}
		} else {
			if (json_paths) {
				json_object_string_add(
					json_nexthop_global, "ip",
					inet_ntop(AF_INET, &attr->nexthop, buf,
						  sizeof(buf)));

				if (path->peer->hostname)
					json_object_string_add(
						json_nexthop_global, "hostname",
						path->peer->hostname);
			} else {
				if (nexthop_hostname)
					vty_out(vty, "    %pI4(%s)",
						&attr->nexthop,
						nexthop_hostname);
				else
					vty_out(vty, "    %pI4",
						&attr->nexthop);
			}
		}

		if (json_paths)
			json_object_string_add(json_nexthop_global, "afi",
					       "ipv4");
	} else {
		if (json_paths) {
			json_object_string_add(
				json_nexthop_global, "ip",
				inet_ntop(AF_INET6, &attr->mp_nexthop_global,
					  buf, INET6_ADDRSTRLEN));

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_global,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_global, "afi",
					       "ipv6");
			json_object_string_add(json_nexthop_global, "scope",
					       "global");
		} else {
			if (nexthop_hostname)
				vty_out(vty, "    %pI6(%s)",
					&attr->mp_nexthop_global,
					nexthop_hostname);
			else
				vty_out(vty, "    %pI6",
					&attr->mp_nexthop_global);
		}
	}

	/* Display the IGP cost or 'inaccessible' */
	if (!CHECK_FLAG(path->flags, BGP_PATH_VALID)) {
		if (json_paths)
			json_object_boolean_false_add(json_nexthop_global,
						      "accessible");
		else
			vty_out(vty, " (inaccessible)");
	} else {
		if (path->extra && path->extra->igpmetric) {
			if (json_paths)
				json_object_int_add(json_nexthop_global,
						    "metric",
						    path->extra->igpmetric);
			else
				vty_out(vty, " (metric %u)",
					path->extra->igpmetric);
		}

		/* IGP cost is 0, display this only for json */
		else {
			if (json_paths)
				json_object_int_add(json_nexthop_global,
						    "metric", 0);
		}

		if (json_paths)
			json_object_boolean_true_add(json_nexthop_global,
						     "accessible");
	}

	/* Display peer "from" output */
	/* This path was originated locally */
	if (path->peer == bgp->peer_self) {

		if (safi == SAFI_EVPN
		    || (bn_p->family == AF_INET
			&& !BGP_ATTR_NEXTHOP_AFI_IP6(attr))) {
			if (json_paths)
				json_object_string_add(json_peer, "peerId",
						       "0.0.0.0");
			else
				vty_out(vty, " from 0.0.0.0 ");
		} else {
			if (json_paths)
				json_object_string_add(json_peer, "peerId",
						       "::");
			else
				vty_out(vty, " from :: ");
		}

		if (json_paths) {
			char buf[BUFSIZ] = {0};

			json_object_string_add(json_peer, "routerId",
					       inet_ntop(AF_INET,
							 &bgp->router_id, buf,
							 sizeof(buf)));
		} else {
			vty_out(vty, "(%pI4)", &bgp->router_id);
		}
	}

	/* We RXed this path from one of our peers */
	else {

		if (json_paths) {
			json_object_string_add(json_peer, "peerId",
					       sockunion2str(&path->peer->su,
							     buf,
							     SU_ADDRSTRLEN));
			json_object_string_add(json_peer, "routerId",
					       inet_ntop(AF_INET,
							 &path->peer->remote_id,
							 buf1, sizeof(buf1)));

			if (path->peer->hostname)
				json_object_string_add(json_peer, "hostname",
						       path->peer->hostname);

			if (path->peer->domainname)
				json_object_string_add(json_peer, "domainname",
						       path->peer->domainname);

			if (path->peer->conf_if)
				json_object_string_add(json_peer, "interface",
						       path->peer->conf_if);
		} else {
			if (path->peer->conf_if) {
				if (path->peer->hostname
				    && CHECK_FLAG(path->peer->bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					vty_out(vty, " from %s(%s)",
						path->peer->hostname,
						path->peer->conf_if);
				else
					vty_out(vty, " from %s",
						path->peer->conf_if);
			} else {
				if (path->peer->hostname
				    && CHECK_FLAG(path->peer->bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					vty_out(vty, " from %s(%s)",
						path->peer->hostname,
						path->peer->host);
				else
					vty_out(vty, " from %s",
						sockunion2str(&path->peer->su,
							      buf,
							      SU_ADDRSTRLEN));
			}

			if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
				vty_out(vty, " (%pI4)", &attr->originator_id);
			else
				vty_out(vty, " (%s)",
					inet_ntop(AF_INET,
						  &path->peer->remote_id, buf1,
						  sizeof(buf1)));
		}
	}

	/*
	 * Note when vrfid of nexthop is different from that of prefix
	 */
	if (path->extra && path->extra->bgp_orig) {
		vrf_id_t nexthop_vrfid = path->extra->bgp_orig->vrf_id;

		if (json_paths) {
			const char *vn;

			if (path->extra->bgp_orig->inst_type
			    == BGP_INSTANCE_TYPE_DEFAULT)
				vn = VRF_DEFAULT_NAME;
			else
				vn = path->extra->bgp_orig->name;

			json_object_string_add(json_path, "nhVrfName", vn);

			if (nexthop_vrfid == VRF_UNKNOWN) {
				json_object_int_add(json_path, "nhVrfId", -1);
			} else {
				json_object_int_add(json_path, "nhVrfId",
						    (int)nexthop_vrfid);
			}
		} else {
			if (nexthop_vrfid == VRF_UNKNOWN)
				vty_out(vty, " vrf ?");
			else {
				struct vrf *vrf;

				vrf = vrf_lookup_by_id(nexthop_vrfid);
				vty_out(vty, " vrf %s(%u)",
					VRF_LOGNAME(vrf), nexthop_vrfid);
			}
		}
	}

	if (nexthop_self) {
		if (json_paths) {
			json_object_boolean_true_add(json_path,
						     "announceNexthopSelf");
		} else {
			vty_out(vty, " announce-nh-self");
		}
	}

	if (!json_paths)
		vty_out(vty, "\n");

	/* display the link-local nexthop */
	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
		if (json_paths) {
			json_nexthop_ll = json_object_new_object();
			json_object_string_add(
				json_nexthop_ll, "ip",
				inet_ntop(AF_INET6, &attr->mp_nexthop_local,
					  buf, INET6_ADDRSTRLEN));

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_ll,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_ll, "afi", "ipv6");
			json_object_string_add(json_nexthop_ll, "scope",
					       "link-local");

			json_object_boolean_true_add(json_nexthop_ll,
						     "accessible");

			if (!attr->mp_nexthop_prefer_global)
				json_object_boolean_true_add(json_nexthop_ll,
							     "used");
			else
				json_object_boolean_true_add(
					json_nexthop_global, "used");
		} else {
			vty_out(vty, "    (%s) %s\n",
				inet_ntop(AF_INET6, &attr->mp_nexthop_local,
					  buf, INET6_ADDRSTRLEN),
				attr->mp_nexthop_prefer_global
					? "(prefer-global)"
					: "(used)");
		}
	}
	/* If we do not have a link-local nexthop then we must flag the
	   global as "used" */
	else {
		if (json_paths)
			json_object_boolean_true_add(json_nexthop_global,
						     "used");
	}

	if (safi == SAFI_EVPN &&
			bgp_evpn_is_esi_valid(&attr->esi)) {
		route_vty_out_detail_es_info(vty, path, attr, json_path);
	}

	/* Line 3 display Origin, Med, Locpref, Weight, Tag, valid,
	 * Int/Ext/Local, Atomic, best */
	if (json_paths)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[attr->origin]);
	else
		vty_out(vty, "      Origin %s",
			bgp_origin_long_str[attr->origin]);

	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) {
		if (json_paths)
			json_object_int_add(json_path, "metric", attr->med);
		else
			vty_out(vty, ", metric %u", attr->med);
	}

	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
		if (json_paths)
			json_object_int_add(json_path, "locPrf",
					    attr->local_pref);
		else
			vty_out(vty, ", localpref %u", attr->local_pref);
	}

	if (attr->weight != 0) {
		if (json_paths)
			json_object_int_add(json_path, "weight", attr->weight);
		else
			vty_out(vty, ", weight %u", attr->weight);
	}

	if (attr->tag != 0) {
		if (json_paths)
			json_object_int_add(json_path, "tag", attr->tag);
		else
			vty_out(vty, ", tag %" ROUTE_TAG_PRI, attr->tag);
	}

	if (!CHECK_FLAG(path->flags, BGP_PATH_VALID)) {
		if (json_paths)
			json_object_boolean_false_add(json_path, "valid");
		else
			vty_out(vty, ", invalid");
	} else if (!CHECK_FLAG(path->flags, BGP_PATH_HISTORY)) {
		if (json_paths)
			json_object_boolean_true_add(json_path, "valid");
		else
			vty_out(vty, ", valid");
	}

	if (path->peer != bgp->peer_self) {
		if (path->peer->as == path->peer->local_as) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
				if (json_paths)
					json_object_string_add(
						json_peer, "type",
						"confed-internal");
				else
					vty_out(vty, ", confed-internal");
			} else {
				if (json_paths)
					json_object_string_add(
						json_peer, "type", "internal");
				else
					vty_out(vty, ", internal");
			}
		} else {
			if (bgp_confederation_peers_check(bgp,
							  path->peer->as)) {
				if (json_paths)
					json_object_string_add(
						json_peer, "type",
						"confed-external");
				else
					vty_out(vty, ", confed-external");
			} else {
				if (json_paths)
					json_object_string_add(
						json_peer, "type", "external");
				else
					vty_out(vty, ", external");
			}
		}
	} else if (path->sub_type == BGP_ROUTE_AGGREGATE) {
		if (json_paths) {
			json_object_boolean_true_add(json_path, "aggregated");
			json_object_boolean_true_add(json_path, "local");
		} else {
			vty_out(vty, ", aggregated, local");
		}
	} else if (path->type != ZEBRA_ROUTE_BGP) {
		if (json_paths)
			json_object_boolean_true_add(json_path, "sourced");
		else
			vty_out(vty, ", sourced");
	} else {
		if (json_paths) {
			json_object_boolean_true_add(json_path, "sourced");
			json_object_boolean_true_add(json_path, "local");
		} else {
			vty_out(vty, ", sourced, local");
		}
	}

	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "atomicAggregate");
		else
			vty_out(vty, ", atomic-aggregate");
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_MULTIPATH)
	    || (CHECK_FLAG(path->flags, BGP_PATH_SELECTED)
		&& bgp_path_info_mpath_count(path))) {
		if (json_paths)
			json_object_boolean_true_add(json_path, "multipath");
		else
			vty_out(vty, ", multipath");
	}

	// Mark the bestpath(s)
	if (CHECK_FLAG(path->flags, BGP_PATH_DMED_SELECTED)) {
		first_as = aspath_get_first_as(attr->aspath);

		if (json_paths) {
			if (!json_bestpath)
				json_bestpath = json_object_new_object();
			json_object_int_add(json_bestpath, "bestpathFromAs",
					    first_as);
		} else {
			if (first_as)
				vty_out(vty, ", bestpath-from-AS %u", first_as);
			else
				vty_out(vty, ", bestpath-from-AS Local");
		}
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_SELECTED)) {
		if (json_paths) {
			if (!json_bestpath)
				json_bestpath = json_object_new_object();
			json_object_boolean_true_add(json_bestpath, "overall");
			json_object_string_add(
				json_bestpath, "selectionReason",
				bgp_path_selection_reason2str(bn->reason));
		} else {
			vty_out(vty, ", best");
			vty_out(vty, " (%s)",
				bgp_path_selection_reason2str(bn->reason));
		}
	}

	if (json_bestpath)
		json_object_object_add(json_path, "bestpath", json_bestpath);

	if (!json_paths)
		vty_out(vty, "\n");

	/* Line 4 display Community */
	if (attr->community) {
		if (json_paths) {
			if (!attr->community->json)
				community_str(attr->community, true);
			json_object_lock(attr->community->json);
			json_object_object_add(json_path, "community",
					       attr->community->json);
		} else {
			vty_out(vty, "      Community: %s\n",
				attr->community->str);
		}
	}

	/* Line 5 display Extended-community */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) {
		if (json_paths) {
			json_ext_community = json_object_new_object();
			json_object_string_add(json_ext_community, "string",
					       attr->ecommunity->str);
			json_object_object_add(json_path, "extendedCommunity",
					       json_ext_community);
		} else {
			vty_out(vty, "      Extended Community: %s\n",
				attr->ecommunity->str);
		}
	}

	/* Line 6 display Large community */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES)) {
		if (json_paths) {
			if (!attr->lcommunity->json)
				lcommunity_str(attr->lcommunity, true);
			json_object_lock(attr->lcommunity->json);
			json_object_object_add(json_path, "largeCommunity",
					       attr->lcommunity->json);
		} else {
			vty_out(vty, "      Large Community: %s\n",
				attr->lcommunity->str);
		}
	}

	/* Line 7 display Originator, Cluster-id */
	if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	    || (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))) {
		char buf[BUFSIZ] = {0};

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) {
			if (json_paths)
				json_object_string_add(
					json_path, "originatorId",
					inet_ntop(AF_INET, &attr->originator_id,
						  buf, sizeof(buf)));
			else
				vty_out(vty, "      Originator: %pI4",
					&attr->originator_id);
		}

		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)) {
			struct cluster_list *cluster =
				bgp_attr_get_cluster(attr);
			int i;

			if (json_paths) {
				json_cluster_list = json_object_new_object();
				json_cluster_list_list =
					json_object_new_array();

				for (i = 0; i < cluster->length / 4; i++) {
					json_string = json_object_new_string(
						inet_ntop(AF_INET,
							  &cluster->list[i],
							  buf, sizeof(buf)));
					json_object_array_add(
						json_cluster_list_list,
						json_string);
				}

				/*
				 * struct cluster_list does not have
				 * "str" variable like aspath and community
				 * do.  Add this someday if someone asks
				 * for it.
				 * json_object_string_add(json_cluster_list,
				 * "string", cluster->str);
				 */
				json_object_object_add(json_cluster_list,
						       "list",
						       json_cluster_list_list);
				json_object_object_add(json_path, "clusterList",
						       json_cluster_list);
			} else {
				vty_out(vty, ", Cluster list: ");

				for (i = 0; i < cluster->length / 4; i++) {
					vty_out(vty, "%pI4 ",
						&cluster->list[i]);
				}
			}
		}

		if (!json_paths)
			vty_out(vty, "\n");
	}

	if (path->extra && path->extra->damp_info)
		bgp_damp_info_vty(vty, path, afi, safi, json_path);

	/* Remote Label */
	if (path->extra && bgp_is_valid_label(&path->extra->label[0])
	    && (safi != SAFI_EVPN && !is_route_parent_evpn(path))) {
		mpls_label_t label = label_pton(&path->extra->label[0]);

		if (json_paths)
			json_object_int_add(json_path, "remoteLabel", label);
		else
			vty_out(vty, "      Remote label: %d\n", label);
	}

	/* Remote SID */
	if (path->extra && path->extra->num_sids > 0 && safi != SAFI_EVPN) {
		inet_ntop(AF_INET6, &path->extra->sid, buf, sizeof(buf));
		if (json_paths)
			json_object_string_add(json_path, "remoteSid", buf);
		else
			vty_out(vty, "      Remote SID: %s\n", buf);
	}

	/* Label Index */
	if (attr->label_index != BGP_INVALID_LABEL_INDEX) {
		if (json_paths)
			json_object_int_add(json_path, "labelIndex",
					    attr->label_index);
		else
			vty_out(vty, "      Label Index: %d\n",
				attr->label_index);
	}

	/* Line 8 display Addpath IDs */
	if (path->addpath_rx_id
	    || bgp_addpath_info_has_ids(&path->tx_addpath)) {
		if (json_paths) {
			json_object_int_add(json_path, "addpathRxId",
					    path->addpath_rx_id);

			/* Keep backwards compatibility with the old API
			 * by putting TX All's ID in the old field
			 */
			json_object_int_add(
				json_path, "addpathTxId",
				path->tx_addpath
					.addpath_tx_id[BGP_ADDPATH_ALL]);

			/* ... but create a specific field for each
			 * strategy
			 */
			for (i = 0; i < BGP_ADDPATH_MAX; i++) {
				json_object_int_add(
					json_path,
					bgp_addpath_names(i)->id_json_name,
					path->tx_addpath.addpath_tx_id[i]);
			}
		} else {
			vty_out(vty, "      AddPath ID: RX %u, ",
				path->addpath_rx_id);

			route_vty_out_tx_ids(vty, &path->tx_addpath);
		}
	}

	/* If we used addpath to TX a non-bestpath we need to display
	 * "Advertised to" on a path-by-path basis
	 */
	if (bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		first = 1;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			addpath_capable =
				bgp_addpath_encode_tx(peer, afi, safi);
			has_adj = bgp_adj_out_lookup(
				peer, path->net,
				bgp_addpath_id_for_peer(peer, afi, safi,
							&path->tx_addpath));

			if ((addpath_capable && has_adj)
			    || (!addpath_capable && has_adj
				&& CHECK_FLAG(path->flags,
					      BGP_PATH_SELECTED))) {
				if (json_path && !json_adv_to)
					json_adv_to = json_object_new_object();

				route_vty_out_advertised_to(
					vty, peer, &first,
					"      Advertised to:", json_adv_to);
			}
		}

		if (json_path) {
			if (json_adv_to) {
				json_object_object_add(
					json_path, "advertisedTo", json_adv_to);
			}
		} else {
			if (!first) {
				vty_out(vty, "\n");
			}
		}
	}

	/* Line 9 display Uptime */
	tbuf = time(NULL) - (bgp_clock() - path->uptime);
	if (json_paths) {
		json_last_update = json_object_new_object();
		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       ctime(&tbuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	} else
		vty_out(vty, "      Last update: %s", ctime(&tbuf));

	/* Line 10 display PMSI tunnel attribute, if present */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL)) {
		const char *str = lookup_msg(bgp_pmsi_tnltype_str,
					     bgp_attr_get_pmsi_tnl_type(attr),
					     PMSI_TNLTYPE_STR_DEFAULT);

		if (json_paths) {
			json_pmsi = json_object_new_object();
			json_object_string_add(json_pmsi, "tunnelType", str);
			json_object_int_add(json_pmsi, "label",
					    label2vni(&attr->label));
			json_object_object_add(json_path, "pmsi", json_pmsi);
		} else
			vty_out(vty, "      PMSI Tunnel Type: %s, label: %d\n",
				str, label2vni(&attr->label));
	}

	/* Output some debug about internal state of the dest flags */
	if (json_paths) {
		if (CHECK_FLAG(bn->flags, BGP_NODE_PROCESS_SCHEDULED))
			json_object_boolean_true_add(json_path, "processScheduled");
		if (CHECK_FLAG(bn->flags, BGP_NODE_USER_CLEAR))
			json_object_boolean_true_add(json_path, "userCleared");
		if (CHECK_FLAG(bn->flags, BGP_NODE_LABEL_CHANGED))
			json_object_boolean_true_add(json_path, "labelChanged");
		if (CHECK_FLAG(bn->flags, BGP_NODE_REGISTERED_FOR_LABEL))
			json_object_boolean_true_add(json_path, "registeredForLabel");
		if (CHECK_FLAG(bn->flags, BGP_NODE_SELECT_DEFER))
			json_object_boolean_true_add(json_path, "selectDefered");
		if (CHECK_FLAG(bn->flags, BGP_NODE_FIB_INSTALLED))
			json_object_boolean_true_add(json_path, "fibInstalled");
		if (CHECK_FLAG(bn->flags, BGP_NODE_FIB_INSTALL_PENDING))
			json_object_boolean_true_add(json_path, "fibPending");
	}

	/* We've constructed the json object for this path, add it to the json
	 * array of paths
	 */
	if (json_paths) {
		if (json_nexthop_global || json_nexthop_ll) {
			json_nexthops = json_object_new_array();

			if (json_nexthop_global)
				json_object_array_add(json_nexthops,
						      json_nexthop_global);

			if (json_nexthop_ll)
				json_object_array_add(json_nexthops,
						      json_nexthop_ll);

			json_object_object_add(json_path, "nexthops",
					       json_nexthops);
		}

		json_object_object_add(json_path, "peer", json_peer);
		json_object_array_add(json_paths, json_path);
	}
}

#define BGP_SHOW_HEADER_CSV "Flags, Network, Next Hop, Metric, LocPrf, Weight, Path"
#define BGP_SHOW_DAMP_HEADER "   Network          From             Reuse    Path\n"
#define BGP_SHOW_FLAP_HEADER "   Network          From            Flaps Duration Reuse    Path\n"

static int bgp_show_prefix_list(struct vty *vty, struct bgp *bgp,
				const char *prefix_list_str, afi_t afi,
				safi_t safi, enum bgp_show_type type);
static int bgp_show_filter_list(struct vty *vty, struct bgp *bgp,
				const char *filter, afi_t afi, safi_t safi,
				enum bgp_show_type type);
static int bgp_show_route_map(struct vty *vty, struct bgp *bgp,
			      const char *rmap_str, afi_t afi, safi_t safi,
			      enum bgp_show_type type);
static int bgp_show_community_list(struct vty *vty, struct bgp *bgp,
				   const char *com, int exact, afi_t afi,
				   safi_t safi);
static int bgp_show_prefix_longer(struct vty *vty, struct bgp *bgp,
				  const char *prefix, afi_t afi, safi_t safi,
				  enum bgp_show_type type);
static int bgp_show_regexp(struct vty *vty, struct bgp *bgp, const char *regstr,
			   afi_t afi, safi_t safi, enum bgp_show_type type,
			   bool use_json);
static int bgp_show_community(struct vty *vty, struct bgp *bgp,
			      const char *comstr, int exact, afi_t afi,
			      safi_t safi, uint8_t show_flags);


static int bgp_show_table(struct vty *vty, struct bgp *bgp, safi_t safi,
			  struct bgp_table *table, enum bgp_show_type type,
			  void *output_arg, char *rd, int is_last,
			  unsigned long *output_cum, unsigned long *total_cum,
			  unsigned long *json_header_depth, uint8_t show_flags)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest;
	int header = 1;
	int display;
	unsigned long output_count = 0;
	unsigned long total_count = 0;
	struct prefix *p;
	json_object *json_paths = NULL;
	int first = 1;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);
	bool all = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL);

	if (output_cum && *output_cum != 0)
		header = 0;

	if (use_json && !*json_header_depth) {
		if (all)
			*json_header_depth = 1;
		else {
			vty_out(vty, "{\n");
			*json_header_depth = 2;
		}

		vty_out(vty,
			" \"vrfId\": %d,\n \"vrfName\": \"%s\",\n \"tableVersion\": %" PRId64
			",\n \"routerId\": \"%pI4\",\n \"defaultLocPrf\": %u,\n"
			" \"localAS\": %u,\n \"routes\": { ",
			bgp->vrf_id == VRF_UNKNOWN ? -1 : (int)bgp->vrf_id,
			bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
				? VRF_DEFAULT_NAME
				: bgp->name,
			table->version, &bgp->router_id,
			bgp->default_local_pref, bgp->as);
		if (rd) {
			vty_out(vty, " \"routeDistinguishers\" : {");
			++*json_header_depth;
		}
	}

	if (use_json && rd) {
		vty_out(vty, " \"%s\" : { ", rd);
	}

	/* Start processing of routes. */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi == NULL)
			continue;

		display = 0;
		if (use_json)
			json_paths = json_object_new_array();
		else
			json_paths = NULL;

		for (; pi; pi = pi->next) {
			total_count++;
			if (type == bgp_show_type_flap_statistics
			    || type == bgp_show_type_flap_neighbor
			    || type == bgp_show_type_dampend_paths
			    || type == bgp_show_type_damp_neighbor) {
				if (!(pi->extra && pi->extra->damp_info))
					continue;
			}
			if (type == bgp_show_type_regexp) {
				regex_t *regex = output_arg;

				if (bgp_regexec(regex, pi->attr->aspath)
				    == REG_NOMATCH)
					continue;
			}
			if (type == bgp_show_type_prefix_list) {
				struct prefix_list *plist = output_arg;

				if (prefix_list_apply(plist, dest_p)
				    != PREFIX_PERMIT)
					continue;
			}
			if (type == bgp_show_type_filter_list) {
				struct as_list *as_list = output_arg;

				if (as_list_apply(as_list, pi->attr->aspath)
				    != AS_FILTER_PERMIT)
					continue;
			}
			if (type == bgp_show_type_route_map) {
				struct route_map *rmap = output_arg;
				struct bgp_path_info path;
				struct attr dummy_attr;
				route_map_result_t ret;

				dummy_attr = *pi->attr;

				path.peer = pi->peer;
				path.attr = &dummy_attr;

				ret = route_map_apply(rmap, dest_p, &path);
				if (ret == RMAP_DENYMATCH)
					continue;
			}
			if (type == bgp_show_type_neighbor
			    || type == bgp_show_type_flap_neighbor
			    || type == bgp_show_type_damp_neighbor) {
				union sockunion *su = output_arg;

				if (pi->peer == NULL
				    || pi->peer->su_remote == NULL
				    || !sockunion_same(pi->peer->su_remote, su))
					continue;
			}
			if (type == bgp_show_type_cidr_only) {
				uint32_t destination;

				destination = ntohl(dest_p->u.prefix4.s_addr);
				if (IN_CLASSC(destination)
				    && dest_p->prefixlen == 24)
					continue;
				if (IN_CLASSB(destination)
				    && dest_p->prefixlen == 16)
					continue;
				if (IN_CLASSA(destination)
				    && dest_p->prefixlen == 8)
					continue;
			}
			if (type == bgp_show_type_prefix_longer) {
				p = output_arg;
				if (!prefix_match(p, dest_p))
					continue;
			}
			if (type == bgp_show_type_community_all) {
				if (!pi->attr->community)
					continue;
			}
			if (type == bgp_show_type_community) {
				struct community *com = output_arg;

				if (!pi->attr->community
				    || !community_match(pi->attr->community,
							com))
					continue;
			}
			if (type == bgp_show_type_community_exact) {
				struct community *com = output_arg;

				if (!pi->attr->community
				    || !community_cmp(pi->attr->community, com))
					continue;
			}
			if (type == bgp_show_type_community_list) {
				struct community_list *list = output_arg;

				if (!community_list_match(pi->attr->community,
							  list))
					continue;
			}
			if (type == bgp_show_type_community_list_exact) {
				struct community_list *list = output_arg;

				if (!community_list_exact_match(
					    pi->attr->community, list))
					continue;
			}
			if (type == bgp_show_type_lcommunity) {
				struct lcommunity *lcom = output_arg;

				if (!pi->attr->lcommunity
				    || !lcommunity_match(pi->attr->lcommunity,
							 lcom))
					continue;
			}

			if (type == bgp_show_type_lcommunity_exact) {
				struct lcommunity *lcom = output_arg;

				if (!pi->attr->lcommunity
				    || !lcommunity_cmp(pi->attr->lcommunity,
						      lcom))
					continue;
			}
			if (type == bgp_show_type_lcommunity_list) {
				struct community_list *list = output_arg;

				if (!lcommunity_list_match(pi->attr->lcommunity,
							   list))
					continue;
			}
			if (type
			    == bgp_show_type_lcommunity_list_exact) {
				struct community_list *list = output_arg;

				if (!lcommunity_list_exact_match(
					    pi->attr->lcommunity, list))
					continue;
			}
			if (type == bgp_show_type_lcommunity_all) {
				if (!pi->attr->lcommunity)
					continue;
			}
			if (type == bgp_show_type_dampend_paths
			    || type == bgp_show_type_damp_neighbor) {
				if (!CHECK_FLAG(pi->flags, BGP_PATH_DAMPED)
				    || CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
					continue;
			}

			if (!use_json && header) {
				vty_out(vty,
					"BGP table version is %" PRIu64
					", local router ID is %pI4, vrf id ",
					table->version, &bgp->router_id);
				if (bgp->vrf_id == VRF_UNKNOWN)
					vty_out(vty, "%s", VRFID_NONE_STR);
				else
					vty_out(vty, "%u", bgp->vrf_id);
				vty_out(vty, "\n");
				vty_out(vty, "Default local pref %u, ",
					bgp->default_local_pref);
				vty_out(vty, "local AS %u\n", bgp->as);
				vty_out(vty, BGP_SHOW_SCODE_HEADER);
				vty_out(vty, BGP_SHOW_NCODE_HEADER);
				vty_out(vty, BGP_SHOW_OCODE_HEADER);
				if (type == bgp_show_type_dampend_paths
				    || type == bgp_show_type_damp_neighbor)
					vty_out(vty, BGP_SHOW_DAMP_HEADER);
				else if (type == bgp_show_type_flap_statistics
					 || type == bgp_show_type_flap_neighbor)
					vty_out(vty, BGP_SHOW_FLAP_HEADER);
				else
					vty_out(vty, (wide ? BGP_SHOW_HEADER_WIDE
							   : BGP_SHOW_HEADER));
				header = 0;
			}
			if (rd != NULL && !display && !output_count) {
				if (!use_json)
					vty_out(vty,
						"Route Distinguisher: %s\n",
						rd);
			}
			if (type == bgp_show_type_dampend_paths
			    || type == bgp_show_type_damp_neighbor)
				damp_route_vty_out(vty, dest_p, pi, display,
						   AFI_IP, safi, use_json,
						   json_paths);
			else if (type == bgp_show_type_flap_statistics
				 || type == bgp_show_type_flap_neighbor)
				flap_route_vty_out(vty, dest_p, pi, display,
						   AFI_IP, safi, use_json,
						   json_paths);
			else
				route_vty_out(vty, dest_p, pi, display, safi,
					      json_paths, wide);
			display++;
		}

		if (display) {
			output_count++;
			if (!use_json)
				continue;

			/* encode prefix */
			if (dest_p->family == AF_FLOWSPEC) {
				char retstr[BGP_FLOWSPEC_STRING_DISPLAY_MAX];


				bgp_fs_nlri_get_string(
					(unsigned char *)
						dest_p->u.prefix_flowspec.ptr,
					dest_p->u.prefix_flowspec.prefixlen,
					retstr, NLRI_STRING_FORMAT_MIN, NULL,
					family2afi(dest_p->u
						   .prefix_flowspec.family));
				if (first)
					vty_out(vty, "\"%s/%d\": ", retstr,
						dest_p->u.prefix_flowspec
							.prefixlen);
				else
					vty_out(vty, ",\"%s/%d\": ", retstr,
						dest_p->u.prefix_flowspec
							.prefixlen);
			} else {
				if (first)
					vty_out(vty, "\"%pFX\": ", dest_p);
				else
					vty_out(vty, ",\"%pFX\": ", dest_p);
			}
			vty_out(vty, "%s",
				json_object_to_json_string_ext(
					json_paths, JSON_C_TO_STRING_PRETTY));
			json_object_free(json_paths);
			json_paths = NULL;
			first = 0;
		} else
			json_object_free(json_paths);
	}

	if (output_cum) {
		output_count += *output_cum;
		*output_cum = output_count;
	}
	if (total_cum) {
		total_count += *total_cum;
		*total_cum = total_count;
	}
	if (use_json) {
		if (rd) {
			vty_out(vty, " }%s ", (is_last ? "" : ","));
		}
		if (is_last) {
			unsigned long i;
			for (i = 0; i < *json_header_depth; ++i)
				vty_out(vty, " } ");
			if (!all)
				vty_out(vty, "\n");
		}
	} else {
		if (is_last) {
			/* No route is displayed */
			if (output_count == 0) {
				if (type == bgp_show_type_normal)
					vty_out(vty,
						"No BGP prefixes displayed, %ld exist\n",
						total_count);
			} else
				vty_out(vty,
					"\nDisplayed  %ld routes and %ld total paths\n",
					output_count, total_count);
		}
	}

	return CMD_SUCCESS;
}

int bgp_show_table_rd(struct vty *vty, struct bgp *bgp, safi_t safi,
		      struct bgp_table *table, struct prefix_rd *prd_match,
		      enum bgp_show_type type, void *output_arg, bool use_json)
{
	struct bgp_dest *dest, *next;
	unsigned long output_cum = 0;
	unsigned long total_cum = 0;
	unsigned long json_header_depth = 0;
	struct bgp_table *itable;
	bool show_msg;
	uint8_t show_flags = 0;

	show_msg = (!use_json && type == bgp_show_type_normal);

	if (use_json)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	for (dest = bgp_table_top(table); dest; dest = next) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		next = bgp_route_next(dest);
		if (prd_match && memcmp(dest_p->u.val, prd_match->val, 8) != 0)
			continue;

		itable = bgp_dest_get_bgp_table_info(dest);
		if (itable != NULL) {
			struct prefix_rd prd;
			char rd[RD_ADDRSTRLEN];

			memcpy(&prd, dest_p, sizeof(struct prefix_rd));
			prefix_rd2str(&prd, rd, sizeof(rd));
			bgp_show_table(vty, bgp, safi, itable, type, output_arg,
				       rd, next == NULL, &output_cum,
				       &total_cum, &json_header_depth,
				       show_flags);
			if (next == NULL)
				show_msg = false;
		}
	}
	if (show_msg) {
		if (output_cum == 0)
			vty_out(vty, "No BGP prefixes displayed, %ld exist\n",
				total_cum);
		else
			vty_out(vty,
				"\nDisplayed  %ld routes and %ld total paths\n",
				output_cum, total_cum);
	}
	return CMD_SUCCESS;
}
static int bgp_show(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		    enum bgp_show_type type, void *output_arg,
		    uint8_t show_flags)
{
	struct bgp_table *table;
	unsigned long json_header_depth = 0;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (bgp == NULL) {
		bgp = bgp_get_default();
	}

	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}

	table = bgp->rib[afi][safi];
	/* use MPLS and ENCAP specific shows until they are merged */
	if (safi == SAFI_MPLS_VPN) {
		return bgp_show_table_rd(vty, bgp, safi, table, NULL, type,
					 output_arg, use_json);
	}

	if (safi == SAFI_FLOWSPEC && type == bgp_show_type_detail) {
		return bgp_show_table_flowspec(vty, bgp, afi, table, type,
					       output_arg, use_json,
					       1, NULL, NULL);
	}
	/* labeled-unicast routes live in the unicast table */
	else if (safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	return bgp_show_table(vty, bgp, safi, table, type, output_arg, NULL, 1,
			      NULL, NULL, &json_header_depth, show_flags);
}

static void bgp_show_all_instances_routes_vty(struct vty *vty, afi_t afi,
					      safi_t safi, uint8_t show_flags)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	int is_first = 1;
	bool route_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		route_output = true;
		if (use_json) {
			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}
		bgp_show(vty, bgp, afi, safi, bgp_show_type_normal, NULL,
			 show_flags);
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!route_output)
		vty_out(vty, "%% BGP instance not found\n");
}

/* Header of detailed BGP route information */
void route_vty_out_detail_header(struct vty *vty, struct bgp *bgp,
				 struct bgp_dest *dest, struct prefix_rd *prd,
				 afi_t afi, safi_t safi, json_object *json)
{
	struct bgp_path_info *pi;
	const struct prefix *p;
	struct peer *peer;
	struct listnode *node, *nnode;
	char buf1[RD_ADDRSTRLEN];
	char prefix_str[BUFSIZ];
	int count = 0;
	int best = 0;
	int suppress = 0;
	int accept_own = 0;
	int route_filter_translated_v4 = 0;
	int route_filter_v4 = 0;
	int route_filter_translated_v6 = 0;
	int route_filter_v6 = 0;
	int llgr_stale = 0;
	int no_llgr = 0;
	int accept_own_nexthop = 0;
	int blackhole = 0;
	int no_export = 0;
	int no_advertise = 0;
	int local_as = 0;
	int no_peer = 0;
	int first = 1;
	int has_valid_label = 0;
	mpls_label_t label = 0;
	json_object *json_adv_to = NULL;

	p = bgp_dest_get_prefix(dest);
	has_valid_label = bgp_is_valid_label(&dest->local_label);

	if (has_valid_label)
		label = label_pton(&dest->local_label);

	if (safi == SAFI_EVPN) {

		if (!json) {
			vty_out(vty, "BGP routing table entry for %s%s%pFX\n",
				prd ? prefix_rd2str(prd, buf1, sizeof(buf1))
				    : "",
				prd ? ":" : "", (struct prefix_evpn *)p);
		} else {
			json_object_string_add(json, "rd",
				prd ? prefix_rd2str(prd, buf1, sizeof(buf1)) :
				"");
			bgp_evpn_route2json((struct prefix_evpn *)p, json);
		}
	} else {
		if (!json) {
			vty_out(vty, "BGP routing table entry for %s%s%pFX\n",
				((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
					 ? prefix_rd2str(prd, buf1,
							 sizeof(buf1))
					 : ""),
				safi == SAFI_MPLS_VPN ? ":" : "", p);

		} else
			json_object_string_add(json, "prefix",
				prefix2str(p, prefix_str, sizeof(prefix_str)));
	}

	if (has_valid_label) {
		if (json)
			json_object_int_add(json, "localLabel", label);
		else
			vty_out(vty, "Local label: %d\n", label);
	}

	if (!json)
		if (bgp_labeled_safi(safi) && safi != SAFI_EVPN)
			vty_out(vty, "not allocated\n");

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		count++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			best = count;
			if (bgp_path_suppressed(pi))
				suppress = 1;

			if (pi->attr->community == NULL)
				continue;

			no_advertise += community_include(
				pi->attr->community, COMMUNITY_NO_ADVERTISE);
			no_export += community_include(pi->attr->community,
						       COMMUNITY_NO_EXPORT);
			local_as += community_include(pi->attr->community,
						      COMMUNITY_LOCAL_AS);
			accept_own += community_include(pi->attr->community,
							COMMUNITY_ACCEPT_OWN);
			route_filter_translated_v4 += community_include(
				pi->attr->community,
				COMMUNITY_ROUTE_FILTER_TRANSLATED_v4);
			route_filter_translated_v6 += community_include(
				pi->attr->community,
				COMMUNITY_ROUTE_FILTER_TRANSLATED_v6);
			route_filter_v4 += community_include(
				pi->attr->community, COMMUNITY_ROUTE_FILTER_v4);
			route_filter_v6 += community_include(
				pi->attr->community, COMMUNITY_ROUTE_FILTER_v6);
			llgr_stale += community_include(pi->attr->community,
							COMMUNITY_LLGR_STALE);
			no_llgr += community_include(pi->attr->community,
						     COMMUNITY_NO_LLGR);
			accept_own_nexthop +=
				community_include(pi->attr->community,
						  COMMUNITY_ACCEPT_OWN_NEXTHOP);
			blackhole += community_include(pi->attr->community,
						       COMMUNITY_BLACKHOLE);
			no_peer += community_include(pi->attr->community,
						     COMMUNITY_NO_PEER);
		}
	}

	if (!json) {
		vty_out(vty, "Paths: (%d available", count);
		if (best) {
			vty_out(vty, ", best #%d", best);
			if (safi == SAFI_UNICAST) {
				if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					vty_out(vty, ", table %s",
						VRF_DEFAULT_NAME);
				else
					vty_out(vty, ", vrf %s",
						bgp->name);
			}
		} else
			vty_out(vty, ", no best path");

		if (accept_own)
			vty_out(vty,
			", accept own local route exported and imported in different VRF");
		else if (route_filter_translated_v4)
			vty_out(vty,
			", mark translated RTs for VPNv4 route filtering");
		else if (route_filter_v4)
			vty_out(vty,
			", attach RT as-is for VPNv4 route filtering");
		else if (route_filter_translated_v6)
			vty_out(vty,
			", mark translated RTs for VPNv6 route filtering");
		else if (route_filter_v6)
			vty_out(vty,
			", attach RT as-is for VPNv6 route filtering");
		else if (llgr_stale)
			vty_out(vty,
			", mark routes to be retained for a longer time. Requeres support for Long-lived BGP Graceful Restart");
		else if (no_llgr)
			vty_out(vty,
			", mark routes to not be treated according to Long-lived BGP Graceful Restart operations");
		else if (accept_own_nexthop)
			vty_out(vty,
			", accept local nexthop");
		else if (blackhole)
			vty_out(vty, ", inform peer to blackhole prefix");
		else if (no_export)
			vty_out(vty, ", not advertised to EBGP peer");
		else if (no_advertise)
			vty_out(vty, ", not advertised to any peer");
		else if (local_as)
			vty_out(vty, ", not advertised outside local AS");
		else if (no_peer)
			vty_out(vty,
			", inform EBGP peer not to advertise to their EBGP peers");

		if (suppress)
			vty_out(vty,
				", Advertisements suppressed by an aggregate.");
		vty_out(vty, ")\n");
	}

	/* If we are not using addpath then we can display Advertised to and
	 * that will
	 * show what peers we advertised the bestpath to.  If we are using
	 * addpath
	 * though then we must display Advertised to on a path-by-path basis. */
	if (!bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (bgp_adj_out_lookup(peer, dest, 0)) {
				if (json && !json_adv_to)
					json_adv_to = json_object_new_object();

				route_vty_out_advertised_to(
					vty, peer, &first,
					"  Advertised to non peer-group peers:\n ",
					json_adv_to);
			}
		}

		if (json) {
			if (json_adv_to) {
				json_object_object_add(json, "advertisedTo",
						       json_adv_to);
			}
		} else {
			if (first)
				vty_out(vty, "  Not advertised to any peer");
			vty_out(vty, "\n");
		}
	}
}

static void bgp_show_path_info(struct prefix_rd *pfx_rd,
			       struct bgp_dest *bgp_node, struct vty *vty,
			       struct bgp *bgp, afi_t afi, safi_t safi,
			       json_object *json, enum bgp_path_type pathtype,
			       int *display)
{
	struct bgp_path_info *pi;
	int header = 1;
	char rdbuf[RD_ADDRSTRLEN];
	json_object *json_header = NULL;
	json_object *json_paths = NULL;

	for (pi = bgp_dest_get_bgp_path_info(bgp_node); pi; pi = pi->next) {

		if (json && !json_paths) {
			/* Instantiate json_paths only if path is valid */
			json_paths = json_object_new_array();
			if (pfx_rd) {
				prefix_rd2str(pfx_rd, rdbuf, sizeof(rdbuf));
				json_header = json_object_new_object();
			} else
				json_header = json;
		}

		if (header) {
			route_vty_out_detail_header(
				vty, bgp, bgp_node, pfx_rd,
				AFI_IP, safi, json_header);
			header = 0;
		}
		(*display)++;

		if (pathtype == BGP_PATH_SHOW_ALL
		    || (pathtype == BGP_PATH_SHOW_BESTPATH
			&& CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
		    || (pathtype == BGP_PATH_SHOW_MULTIPATH
			&& (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH)
			    || CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))))
			route_vty_out_detail(vty, bgp, bgp_node,
					     pi, AFI_IP, safi,
					     json_paths);
	}

	if (json && json_paths) {
		json_object_object_add(json_header, "paths", json_paths);

		if (pfx_rd)
			json_object_object_add(json, rdbuf, json_header);
	}
}

/* Display specified route of BGP table. */
static int bgp_show_route_in_table(struct vty *vty, struct bgp *bgp,
				   struct bgp_table *rib, const char *ip_str,
				   afi_t afi, safi_t safi,
				   struct prefix_rd *prd, int prefix_check,
				   enum bgp_path_type pathtype, bool use_json)
{
	int ret;
	int display = 0;
	struct prefix match;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_table *table;
	json_object *json = NULL;
	json_object *json_paths = NULL;

	/* Check IP address argument. */
	ret = str2prefix(ip_str, &match);
	if (!ret) {
		vty_out(vty, "address is malformed\n");
		return CMD_WARNING;
	}

	match.family = afi2family(afi);

	if (use_json)
		json = json_object_new_object();

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP) {
		for (dest = bgp_table_top(rib); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (prd && memcmp(dest_p->u.val, prd->val, 8) != 0)
				continue;
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			if ((rm = bgp_node_match(table, &match)) == NULL)
				continue;

			const struct prefix *rm_p = bgp_dest_get_prefix(rm);
			if (prefix_check
			    && rm_p->prefixlen != match.prefixlen) {
				bgp_dest_unlock_node(rm);
				continue;
			}

			bgp_show_path_info((struct prefix_rd *)dest_p, rm, vty,
					   bgp, afi, safi, json, pathtype,
					   &display);

			bgp_dest_unlock_node(rm);
		}
	} else if (safi == SAFI_EVPN) {
		struct bgp_dest *longest_pfx;
		bool is_exact_pfxlen_match = false;

		for (dest = bgp_table_top(rib); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (prd && memcmp(&dest_p->u.val, prd->val, 8) != 0)
				continue;
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			longest_pfx = NULL;
			is_exact_pfxlen_match = false;
			/*
			 * Search through all the prefixes for a match.  The
			 * pfx's are enumerated in ascending order of pfxlens.
			 * So, the last pfx match is the longest match.  Set
			 * is_exact_pfxlen_match when we get exact pfxlen match
			 */
			for (rm = bgp_table_top(table); rm;
				rm = bgp_route_next(rm)) {
				const struct prefix *rm_p =
					bgp_dest_get_prefix(rm);
				/*
				 * Get prefixlen of the ip-prefix within type5
				 * evpn route
				 */
				if (evpn_type5_prefix_match(rm_p, &match)
				    && rm->info) {
					longest_pfx = rm;
					int type5_pfxlen =
						bgp_evpn_get_type5_prefixlen(
							rm_p);
					if (type5_pfxlen == match.prefixlen) {
						is_exact_pfxlen_match = true;
						bgp_dest_unlock_node(rm);
						break;
					}
				}
			}

			if (!longest_pfx)
				continue;

			if (prefix_check && !is_exact_pfxlen_match)
				continue;

			rm = longest_pfx;
			bgp_dest_lock_node(rm);

			bgp_show_path_info((struct prefix_rd *)dest_p, rm, vty,
					   bgp, afi, safi, json, pathtype,
					   &display);

			bgp_dest_unlock_node(rm);
		}
	} else if (safi == SAFI_FLOWSPEC) {
		if (use_json)
			json_paths = json_object_new_array();

		display = bgp_flowspec_display_match_per_ip(afi, rib,
					   &match, prefix_check,
					   vty,
					   use_json,
					   json_paths);
		if (use_json && display)
			json_object_object_add(json, "paths", json_paths);
	} else {
		if ((dest = bgp_node_match(rib, &match)) != NULL) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);
			if (!prefix_check
			    || dest_p->prefixlen == match.prefixlen) {
				bgp_show_path_info(NULL, dest, vty, bgp, afi,
						   safi, json, pathtype,
						   &display);
			}

			bgp_dest_unlock_node(dest);
		}
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY |
					     JSON_C_TO_STRING_NOSLASHESCAPE));
		json_object_free(json);
	} else {
		if (!display) {
			vty_out(vty, "%% Network not in table\n");
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

/* Display specified route of Main RIB */
static int bgp_show_route(struct vty *vty, struct bgp *bgp, const char *ip_str,
			  afi_t afi, safi_t safi, struct prefix_rd *prd,
			  int prefix_check, enum bgp_path_type pathtype,
			  bool use_json)
{
	if (!bgp) {
		bgp = bgp_get_default();
		if (!bgp) {
			if (!use_json)
				vty_out(vty, "No BGP process is configured\n");
			else
				vty_out(vty, "{}\n");
			return CMD_WARNING;
		}
	}

	/* labeled-unicast routes live in the unicast table */
	if (safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	return bgp_show_route_in_table(vty, bgp, bgp->rib[afi][safi], ip_str,
				       afi, safi, prd, prefix_check, pathtype,
				       use_json);
}

static int bgp_show_lcommunity(struct vty *vty, struct bgp *bgp, int argc,
			       struct cmd_token **argv, bool exact, afi_t afi,
			       safi_t safi, bool uj)
{
	struct lcommunity *lcom;
	struct buffer *b;
	int i;
	char *str;
	int first = 0;
	uint8_t show_flags = 0;
	int ret;

	if (uj)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	b = buffer_new(1024);
	for (i = 0; i < argc; i++) {
		if (first)
			buffer_putc(b, ' ');
		else {
			if (strmatch(argv[i]->text, "AA:BB:CC")) {
				first = 1;
				buffer_putstr(b, argv[i]->arg);
			}
		}
	}
	buffer_putc(b, '\0');

	str = buffer_getstr(b);
	buffer_free(b);

	lcom = lcommunity_str2com(str);
	XFREE(MTYPE_TMP, str);
	if (!lcom) {
		vty_out(vty, "%% Large-community malformed\n");
		return CMD_WARNING;
	}

	ret = bgp_show(vty, bgp, afi, safi,
			(exact ? bgp_show_type_lcommunity_exact
			       : bgp_show_type_lcommunity),
			lcom, show_flags);

	lcommunity_free(&lcom);
	return ret;
}

static int bgp_show_lcommunity_list(struct vty *vty, struct bgp *bgp,
				    const char *lcom, bool exact, afi_t afi,
				    safi_t safi, bool uj)
{
	struct community_list *list;
	uint8_t show_flags = 0;

	if (uj)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);


	list = community_list_lookup(bgp_clist, lcom, 0,
				     LARGE_COMMUNITY_LIST_MASTER);
	if (list == NULL) {
		vty_out(vty, "%% %s is not a valid large-community-list name\n",
			lcom);
		return CMD_WARNING;
	}

	return bgp_show(vty, bgp, afi, safi,
			(exact ? bgp_show_type_lcommunity_list_exact
			       : bgp_show_type_lcommunity_list),
			list, show_flags);
}

DEFUN (show_ip_bgp_large_community_list,
       show_ip_bgp_large_community_list_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] large-community-list <(1-500)|WORD> [exact-match] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Display routes matching the large-community-list\n"
       "large-community-list number\n"
       "large-community-list name\n"
       "Exact match of the large-communities\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	int idx = 0;
	bool exact_match = 0;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);

        if (uj)
                argc--;

        bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
                                            &bgp, uj);
        if (!idx)
                return CMD_WARNING;

	argv_find(argv, argc, "large-community-list", &idx);

	const char *clist_number_or_name = argv[++idx]->arg;

	if (++idx < argc && strmatch(argv[idx]->text, "exact-match"))
		exact_match = 1;

	return bgp_show_lcommunity_list(vty, bgp, clist_number_or_name,
					exact_match, afi, safi, uj);
}
DEFUN (show_ip_bgp_large_community,
       show_ip_bgp_large_community_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] large-community [<AA:BB:CC> [exact-match]] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Display routes matching the large-communities\n"
       "List of large-community numbers\n"
       "Exact match of the large-communities\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	int idx = 0;
	bool exact_match = 0;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);
	uint8_t show_flags = 0;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	if (argv_find(argv, argc, "AA:BB:CC", &idx)) {
		if (argv_find(argv, argc, "exact-match", &idx))
			exact_match = 1;
		return bgp_show_lcommunity(vty, bgp, argc, argv,
					exact_match, afi, safi, uj);
	} else
		return bgp_show(vty, bgp, afi, safi,
				bgp_show_type_lcommunity_all, NULL, show_flags);
}

static int bgp_table_stats_single(struct vty *vty, struct bgp *bgp, afi_t afi,
				  safi_t safi, struct json_object *json_array);
static int bgp_table_stats(struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi, struct json_object *json);


DEFUN(show_ip_bgp_statistics_all, show_ip_bgp_statistics_all_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] statistics-all [json]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR
      "Display number of prefixes for all afi/safi\n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct bgp *bgp = NULL;
	safi_t safi = SAFI_UNICAST;
	afi_t afi = AFI_IP6;
	int idx = 0;
	struct json_object *json_all = NULL;
	struct json_object *json_afi_safi = NULL;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	if (uj)
		json_all = json_object_new_object();

	FOREACH_AFI_SAFI (afi, safi) {
		/*
		 * So limit output to those afi/safi pairs that
		 * actually have something interesting in them
		 */
		if (strmatch(get_afi_safi_str(afi, safi, true),
			     "Unknown")) {
			continue;
		}
		if (uj) {
			json_afi_safi = json_object_new_array();
			json_object_object_add(
					       json_all,
					       get_afi_safi_str(afi, safi, true),
					       json_afi_safi);
		} else {
			json_afi_safi = NULL;
		}

		bgp_table_stats(vty, bgp, afi, safi, json_afi_safi);
	}

	if (uj) {
		vty_out(vty, "%s",
			json_object_to_json_string_ext(
				json_all, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_all);
	}

	return CMD_SUCCESS;
}

/* BGP route print out function without JSON */
DEFUN (show_ip_bgp_l2vpn_evpn_statistics,
       show_ip_bgp_l2vpn_evpn_statistics_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] l2vpn evpn statistics [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "BGP RIB advertisement statistics\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0, ret;
	bool uj = use_json(argc, argv);
	struct json_object *json_afi_safi = NULL, *json = NULL;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	if (uj)
		json_afi_safi = json_object_new_array();
	else
		json_afi_safi = NULL;

	ret = bgp_table_stats(vty, bgp, afi, safi, json_afi_safi);

	if (uj) {
		json = json_object_new_object();
		json_object_object_add(json, get_afi_safi_str(afi, safi, true),
				       json_afi_safi);
		vty_out(vty, "%s", json_object_to_json_string_ext(
					  json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return ret;
}

/* BGP route print out function without JSON */
DEFUN(show_ip_bgp_afi_safi_statistics, show_ip_bgp_afi_safi_statistics_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]]\
         statistics [json]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "BGP RIB advertisement statistics\n" JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0, ret;
	bool uj = use_json(argc, argv);
	struct json_object *json_afi_safi = NULL, *json = NULL;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	if (uj)
		json_afi_safi = json_object_new_array();
	else
		json_afi_safi = NULL;

	ret = bgp_table_stats(vty, bgp, afi, safi, json_afi_safi);

	if (uj) {
		json = json_object_new_object();
		json_object_object_add(json, get_afi_safi_str(afi, safi, true),
				       json_afi_safi);
		vty_out(vty, "%s",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return ret;
}

/* BGP route print out function without JSON */
DEFPY(show_ip_bgp, show_ip_bgp_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]]\
          <[all$all] dampening <parameters>\
           |route-map WORD\
           |prefix-list WORD\
           |filter-list WORD\
           |community-list <(1-500)|WORD> [exact-match]\
           |A.B.C.D/M longer-prefixes\
           |X:X::X:X/M longer-prefixes\
         >",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Display the entries for all address families\n"
      "Display detailed information about dampening\n"
      "Display detail of configured dampening parameters\n"
      "Display routes matching the route-map\n"
      "A route-map to match on\n"
      "Display routes conforming to the prefix-list\n"
      "Prefix-list name\n"
      "Display routes conforming to the filter-list\n"
      "Regular expression access list name\n"
      "Display routes matching the community-list\n"
      "community-list number\n"
      "community-list name\n"
      "Exact match of the communities\n"
      "IPv4 prefix\n"
      "Display route and more specific routes\n"
      "IPv6 prefix\n"
      "Display route and more specific routes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	int exact_match = 0;
	struct bgp *bgp = NULL;
	int idx = 0;
	uint8_t show_flags = 0;

	/* [<ipv4|ipv6> [all]] */
	if (all) {
		SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL);
		if (argv_find(argv, argc, "ipv4", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP);

		if (argv_find(argv, argc, "ipv6", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6);
	}

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	if (argv_find(argv, argc, "dampening", &idx)) {
		if (argv_find(argv, argc, "parameters", &idx))
			return bgp_show_dampening_parameters(vty, afi, safi,
							     show_flags);
	}

	if (argv_find(argv, argc, "prefix-list", &idx))
		return bgp_show_prefix_list(vty, bgp, argv[idx + 1]->arg, afi,
					    safi, bgp_show_type_prefix_list);

	if (argv_find(argv, argc, "filter-list", &idx))
		return bgp_show_filter_list(vty, bgp, argv[idx + 1]->arg, afi,
					    safi, bgp_show_type_filter_list);

	if (argv_find(argv, argc, "route-map", &idx))
		return bgp_show_route_map(vty, bgp, argv[idx + 1]->arg, afi,
					  safi, bgp_show_type_route_map);

	if (argv_find(argv, argc, "community-list", &idx)) {
		const char *clist_number_or_name = argv[++idx]->arg;
		if (++idx < argc && strmatch(argv[idx]->text, "exact-match"))
			exact_match = 1;
		return bgp_show_community_list(vty, bgp, clist_number_or_name,
					       exact_match, afi, safi);
	}
	/* prefix-longer */
	if (argv_find(argv, argc, "A.B.C.D/M", &idx)
	    || argv_find(argv, argc, "X:X::X:X/M", &idx))
		return bgp_show_prefix_longer(vty, bgp, argv[idx]->arg, afi,
					      safi,
					      bgp_show_type_prefix_longer);

	return CMD_WARNING;
}

/* BGP route print out function with JSON */
DEFPY (show_ip_bgp_json,
       show_ip_bgp_json_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]]\
          [all$all]\
          [cidr-only\
          |dampening <flap-statistics|dampened-paths>\
          |community [AA:NN|local-AS|no-advertise|no-export\
                     |graceful-shutdown|no-peer|blackhole|llgr-stale|no-llgr\
                     |accept-own|accept-own-nexthop|route-filter-v6\
                     |route-filter-v4|route-filter-translated-v6\
                     |route-filter-translated-v4] [exact-match]\
          ] [json$uj | wide$wide]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Display the entries for all address families\n"
       "Display only routes with non-natural netmasks\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display paths suppressed due to dampening\n"
       "Display routes matching the communities\n"
       COMMUNITY_AANN_STR
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Graceful shutdown (well-known community)\n"
       "Do not export to any peer (well-known community)\n"
       "Inform EBGP peers to blackhole traffic to prefix (well-known community)\n"
       "Staled Long-lived Graceful Restart VPN route (well-known community)\n"
       "Removed because Long-lived Graceful Restart was not enabled for VPN route (well-known community)\n"
       "Should accept local VPN route if exported and imported into different VRF (well-known community)\n"
       "Should accept VPN route with local nexthop (well-known community)\n"
       "RT VPNv6 route filtering (well-known community)\n"
       "RT VPNv4 route filtering (well-known community)\n"
       "RT translated VPNv6 route filtering (well-known community)\n"
       "RT translated VPNv4 route filtering (well-known community)\n"
       "Exact match of the communities\n"
       JSON_STR
       "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	enum bgp_show_type sh_type = bgp_show_type_normal;
	struct bgp *bgp = NULL;
	int idx = 0;
	int exact_match = 0;
	char *community = NULL;
	bool first = true;
	uint8_t show_flags = 0;


	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	/* [<ipv4|ipv6> [all]] */
	if (all) {
		SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL);

		if (argv_find(argv, argc, "ipv4", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP);

		if (argv_find(argv, argc, "ipv6", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6);
	}

	if (wide)
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	if (argv_find(argv, argc, "cidr-only", &idx))
		sh_type = bgp_show_type_cidr_only;

	if (argv_find(argv, argc, "dampening", &idx)) {
		if (argv_find(argv, argc, "dampened-paths", &idx))
			sh_type = bgp_show_type_dampend_paths;
		else if (argv_find(argv, argc, "flap-statistics", &idx))
			sh_type = bgp_show_type_flap_statistics;
	}

	if (argv_find(argv, argc, "community", &idx)) {
		char *maybecomm = NULL;

		if (idx + 1 < argc) {
			if (argv[idx + 1]->type == VARIABLE_TKN)
				maybecomm = argv[idx + 1]->arg;
			else
				maybecomm = argv[idx + 1]->text;
		}

		if (maybecomm && !strmatch(maybecomm, "json")
		    && !strmatch(maybecomm, "exact-match"))
			community = maybecomm;

		if (argv_find(argv, argc, "exact-match", &idx))
			exact_match = 1;

		if (!community)
			sh_type = bgp_show_type_community_all;
	}

	if (!all) {
		/* show bgp: AFI_IP6, show ip bgp: AFI_IP */
		if (community)
			return bgp_show_community(vty, bgp, community,
						  exact_match, afi, safi,
						  show_flags);
		else
			return bgp_show(vty, bgp, afi, safi, sh_type, NULL,
					show_flags);
	} else {
		/* show <ip> bgp ipv4 all: AFI_IP, show <ip> bgp ipv6 all:
		 * AFI_IP6 */

		if (uj)
			vty_out(vty, "{\n");

		if (CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
		    || CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6)) {
			afi = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
				      ? AFI_IP
				      : AFI_IP6;
			FOREACH_SAFI (safi) {
				if (!bgp_afi_safi_peer_exists(bgp, afi, safi))
					continue;

				if (uj) {
					if (first)
						first = false;
					else
						vty_out(vty, ",\n");
					vty_out(vty, "\"%s\":{\n",
						get_afi_safi_str(afi, safi,
								 true));
				} else
					vty_out(vty,
						"\nFor address family: %s\n",
						get_afi_safi_str(afi, safi,
								 false));

				if (community)
					bgp_show_community(vty, bgp, community,
							   exact_match, afi,
							   safi, show_flags);
				else
					bgp_show(vty, bgp, afi, safi, sh_type,
						 NULL, show_flags);
				if (uj)
					vty_out(vty, "}\n");
			}
		} else {
			/* show <ip> bgp all: for each AFI and SAFI*/
			FOREACH_AFI_SAFI (afi, safi) {
				if (!bgp_afi_safi_peer_exists(bgp, afi, safi))
					continue;

				if (uj) {
					if (first)
						first = false;
					else
						vty_out(vty, ",\n");

					vty_out(vty, "\"%s\":{\n",
						get_afi_safi_str(afi, safi,
								 true));
				} else
					vty_out(vty,
						"\nFor address family: %s\n",
						get_afi_safi_str(afi, safi,
								 false));

				if (community)
					bgp_show_community(vty, bgp, community,
							   exact_match, afi,
							   safi, show_flags);
				else
					bgp_show(vty, bgp, afi, safi, sh_type,
						 NULL, show_flags);
				if (uj)
					vty_out(vty, "}\n");
			}
		}
		if (uj)
			vty_out(vty, "}\n");
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]]<A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> [<bestpath|multipath>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Network in the BGP routing table to display\n"
       "IPv4 prefix\n"
       "Network in the BGP routing table to display\n"
       "IPv6 prefix\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       JSON_STR)
{
	int prefix_check = 0;

	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	char *prefix = NULL;
	struct bgp *bgp = NULL;
	enum bgp_path_type path_type;
	bool uj = use_json(argc, argv);

	int idx = 0;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	if (!bgp) {
		vty_out(vty,
			"Specified 'all' vrf's but this command currently only works per view/vrf\n");
		return CMD_WARNING;
	}

	/* <A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> */
	if (argv_find(argv, argc, "A.B.C.D", &idx)
	    || argv_find(argv, argc, "X:X::X:X", &idx))
		prefix_check = 0;
	else if (argv_find(argv, argc, "A.B.C.D/M", &idx)
		 || argv_find(argv, argc, "X:X::X:X/M", &idx))
		prefix_check = 1;

	if ((argv[idx]->type == IPV6_TKN || argv[idx]->type == IPV6_PREFIX_TKN)
	    && afi != AFI_IP6) {
		vty_out(vty,
			"%% Cannot specify IPv6 address or prefix with IPv4 AFI\n");
		return CMD_WARNING;
	}
	if ((argv[idx]->type == IPV4_TKN || argv[idx]->type == IPV4_PREFIX_TKN)
	    && afi != AFI_IP) {
		vty_out(vty,
			"%% Cannot specify IPv4 address or prefix with IPv6 AFI\n");
		return CMD_WARNING;
	}

	prefix = argv[idx]->arg;

	/* [<bestpath|multipath>] */
	if (argv_find(argv, argc, "bestpath", &idx))
		path_type = BGP_PATH_SHOW_BESTPATH;
	else if (argv_find(argv, argc, "multipath", &idx))
		path_type = BGP_PATH_SHOW_MULTIPATH;
	else
		path_type = BGP_PATH_SHOW_ALL;

	return bgp_show_route(vty, bgp, prefix, afi, safi, NULL, prefix_check,
			      path_type, uj);
}

DEFUN (show_ip_bgp_regexp,
       show_ip_bgp_regexp_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] regexp REGEX [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression (1234567890_^|[,{}() ]$*+.?-\\) to match the BGP AS paths\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);
	char *regstr = NULL;

	int idx = 0;
	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	// get index of regex
	if (argv_find(argv, argc, "REGEX", &idx))
		regstr = argv[idx]->arg;

	assert(regstr);
	return bgp_show_regexp(vty, bgp, (const char *)regstr, afi, safi,
				 bgp_show_type_regexp, uj);
}

DEFPY (show_ip_bgp_instance_all,
       show_ip_bgp_instance_all_cmd,
       "show [ip] bgp <view|vrf> all ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] [json$uj | wide$wide]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       JSON_STR
      "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0;
	uint8_t show_flags = 0;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	if (wide)
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	bgp_show_all_instances_routes_vty(vty, afi, safi, show_flags);
	return CMD_SUCCESS;
}

static int bgp_show_regexp(struct vty *vty, struct bgp *bgp, const char *regstr,
			   afi_t afi, safi_t safi, enum bgp_show_type type,
			   bool use_json)
{
	regex_t *regex;
	int rc;
	uint8_t show_flags = 0;

	if (use_json)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (!config_bgp_aspath_validate(regstr)) {
		vty_out(vty, "Invalid character in REGEX %s\n",
			regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	regex = bgp_regcomp(regstr);
	if (!regex) {
		vty_out(vty, "Can't compile regexp %s\n", regstr);
		return CMD_WARNING;
	}

	rc = bgp_show(vty, bgp, afi, safi, type, regex, show_flags);
	bgp_regex_free(regex);
	return rc;
}

static int bgp_show_prefix_list(struct vty *vty, struct bgp *bgp,
				const char *prefix_list_str, afi_t afi,
				safi_t safi, enum bgp_show_type type)
{
	struct prefix_list *plist;
	uint8_t show_flags = 0;

	plist = prefix_list_lookup(afi, prefix_list_str);
	if (plist == NULL) {
		vty_out(vty, "%% %s is not a valid prefix-list name\n",
			prefix_list_str);
		return CMD_WARNING;
	}

	return bgp_show(vty, bgp, afi, safi, type, plist, show_flags);
}

static int bgp_show_filter_list(struct vty *vty, struct bgp *bgp,
				const char *filter, afi_t afi, safi_t safi,
				enum bgp_show_type type)
{
	struct as_list *as_list;
	uint8_t show_flags = 0;

	as_list = as_list_lookup(filter);
	if (as_list == NULL) {
		vty_out(vty, "%% %s is not a valid AS-path access-list name\n",
			filter);
		return CMD_WARNING;
	}

	return bgp_show(vty, bgp, afi, safi, type, as_list, show_flags);
}

static int bgp_show_route_map(struct vty *vty, struct bgp *bgp,
			      const char *rmap_str, afi_t afi, safi_t safi,
			      enum bgp_show_type type)
{
	struct route_map *rmap;
	uint8_t show_flags = 0;

	rmap = route_map_lookup_by_name(rmap_str);
	if (!rmap) {
		vty_out(vty, "%% %s is not a valid route-map name\n", rmap_str);
		return CMD_WARNING;
	}

	return bgp_show(vty, bgp, afi, safi, type, rmap, show_flags);
}

static int bgp_show_community(struct vty *vty, struct bgp *bgp,
			      const char *comstr, int exact, afi_t afi,
			      safi_t safi, uint8_t show_flags)
{
	struct community *com;
	int ret = 0;

	com = community_str2com(comstr);
	if (!com) {
		vty_out(vty, "%% Community malformed: %s\n", comstr);
		return CMD_WARNING;
	}

	ret = bgp_show(vty, bgp, afi, safi,
		       (exact ? bgp_show_type_community_exact
			      : bgp_show_type_community),
		       com, show_flags);
	community_free(&com);

	return ret;
}

static int bgp_show_community_list(struct vty *vty, struct bgp *bgp,
				   const char *com, int exact, afi_t afi,
				   safi_t safi)
{
	struct community_list *list;
	uint8_t show_flags = 0;

	list = community_list_lookup(bgp_clist, com, 0, COMMUNITY_LIST_MASTER);
	if (list == NULL) {
		vty_out(vty, "%% %s is not a valid community-list name\n", com);
		return CMD_WARNING;
	}

	return bgp_show(vty, bgp, afi, safi,
			(exact ? bgp_show_type_community_list_exact
			       : bgp_show_type_community_list),
			list, show_flags);
}

static int bgp_show_prefix_longer(struct vty *vty, struct bgp *bgp,
				  const char *prefix, afi_t afi, safi_t safi,
				  enum bgp_show_type type)
{
	int ret;
	struct prefix *p;
	uint8_t show_flags = 0;

	p = prefix_new();

	ret = str2prefix(prefix, p);
	if (!ret) {
		vty_out(vty, "%% Malformed Prefix\n");
		return CMD_WARNING;
	}

	ret = bgp_show(vty, bgp, afi, safi, type, p, show_flags);
	prefix_free(&p);
	return ret;
}

enum bgp_stats {
	BGP_STATS_MAXBITLEN = 0,
	BGP_STATS_RIB,
	BGP_STATS_PREFIXES,
	BGP_STATS_TOTPLEN,
	BGP_STATS_UNAGGREGATEABLE,
	BGP_STATS_MAX_AGGREGATEABLE,
	BGP_STATS_AGGREGATES,
	BGP_STATS_SPACE,
	BGP_STATS_ASPATH_COUNT,
	BGP_STATS_ASPATH_MAXHOPS,
	BGP_STATS_ASPATH_TOTHOPS,
	BGP_STATS_ASPATH_MAXSIZE,
	BGP_STATS_ASPATH_TOTSIZE,
	BGP_STATS_ASN_HIGHEST,
	BGP_STATS_MAX,
};

#define TABLE_STATS_IDX_VTY 0
#define TABLE_STATS_IDX_JSON 1

static const char *table_stats_strs[][2] = {
	[BGP_STATS_PREFIXES] = {"Total Prefixes", "totalPrefixes"},
	[BGP_STATS_TOTPLEN] = {"Average prefix length", "averagePrefixLength"},
	[BGP_STATS_RIB] = {"Total Advertisements", "totalAdvertisements"},
	[BGP_STATS_UNAGGREGATEABLE] = {"Unaggregateable prefixes",
				       "unaggregateablePrefixes"},
	[BGP_STATS_MAX_AGGREGATEABLE] = {"Maximum aggregateable prefixes",
					 "maximumAggregateablePrefixes"},
	[BGP_STATS_AGGREGATES] = {"BGP Aggregate advertisements",
				  "bgpAggregateAdvertisements"},
	[BGP_STATS_SPACE] = {"Address space advertised",
			     "addressSpaceAdvertised"},
	[BGP_STATS_ASPATH_COUNT] = {"Advertisements with paths",
				    "advertisementsWithPaths"},
	[BGP_STATS_ASPATH_MAXHOPS] = {"Longest AS-Path (hops)",
				      "longestAsPath"},
	[BGP_STATS_ASPATH_MAXSIZE] = {"Largest AS-Path (bytes)",
				      "largestAsPath"},
	[BGP_STATS_ASPATH_TOTHOPS] = {"Average AS-Path length (hops)",
				      "averageAsPathLengthHops"},
	[BGP_STATS_ASPATH_TOTSIZE] = {"Average AS-Path size (bytes)",
				      "averageAsPathSizeBytes"},
	[BGP_STATS_ASN_HIGHEST] = {"Highest public ASN", "highestPublicAsn"},
	[BGP_STATS_MAX] = {NULL, NULL}
};

struct bgp_table_stats {
	struct bgp_table *table;
	unsigned long long counts[BGP_STATS_MAX];
	double total_space;
};

#if 0
#define TALLY_SIGFIG 100000
static unsigned long
ravg_tally (unsigned long count, unsigned long oldavg, unsigned long newval)
{
  unsigned long newtot = (count-1) * oldavg + (newval * TALLY_SIGFIG);
  unsigned long res = (newtot * TALLY_SIGFIG) / count;
  unsigned long ret = newtot / count;

  if ((res % TALLY_SIGFIG) > (TALLY_SIGFIG/2))
    return ret + 1;
  else
    return ret;
}
#endif

static void bgp_table_stats_rn(struct bgp_dest *dest, struct bgp_dest *top,
			       struct bgp_table_stats *ts, unsigned int space)
{
	struct bgp_dest *pdest = bgp_dest_parent_nolock(dest);
	struct bgp_path_info *pi;
	const struct prefix *rn_p;

	if (!bgp_dest_has_bgp_path_info_data(dest))
		return;

	rn_p = bgp_dest_get_prefix(dest);
	ts->counts[BGP_STATS_PREFIXES]++;
	ts->counts[BGP_STATS_TOTPLEN] += rn_p->prefixlen;

#if 0
      ts->counts[BGP_STATS_AVGPLEN]
        = ravg_tally (ts->counts[BGP_STATS_PREFIXES],
                      ts->counts[BGP_STATS_AVGPLEN],
                      rn_p->prefixlen);
#endif

	/* check if the prefix is included by any other announcements */
	while (pdest && !bgp_dest_has_bgp_path_info_data(pdest))
		pdest = bgp_dest_parent_nolock(pdest);

	if (pdest == NULL || pdest == top) {
		ts->counts[BGP_STATS_UNAGGREGATEABLE]++;
		/* announced address space */
		if (space)
			ts->total_space += pow(2.0, space - rn_p->prefixlen);
	} else if (bgp_dest_has_bgp_path_info_data(pdest))
		ts->counts[BGP_STATS_MAX_AGGREGATEABLE]++;


	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		ts->counts[BGP_STATS_RIB]++;

		if (CHECK_FLAG(pi->attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
			ts->counts[BGP_STATS_AGGREGATES]++;

		/* as-path stats */
		if (pi->attr->aspath) {
			unsigned int hops = aspath_count_hops(pi->attr->aspath);
			unsigned int size = aspath_size(pi->attr->aspath);
			as_t highest = aspath_highest(pi->attr->aspath);

			ts->counts[BGP_STATS_ASPATH_COUNT]++;

			if (hops > ts->counts[BGP_STATS_ASPATH_MAXHOPS])
				ts->counts[BGP_STATS_ASPATH_MAXHOPS] = hops;

			if (size > ts->counts[BGP_STATS_ASPATH_MAXSIZE])
				ts->counts[BGP_STATS_ASPATH_MAXSIZE] = size;

			ts->counts[BGP_STATS_ASPATH_TOTHOPS] += hops;
			ts->counts[BGP_STATS_ASPATH_TOTSIZE] += size;
#if 0
              ts->counts[BGP_STATS_ASPATH_AVGHOPS]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGHOPS],
                              hops);
              ts->counts[BGP_STATS_ASPATH_AVGSIZE]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGSIZE],
                              size);
#endif
			if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
				ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
		}
	}
}

static int bgp_table_stats_walker(struct thread *t)
{
	struct bgp_dest *dest, *ndest;
	struct bgp_dest *top;
	struct bgp_table_stats *ts = THREAD_ARG(t);
	unsigned int space = 0;

	if (!(top = bgp_table_top(ts->table)))
		return 0;

	switch (ts->table->afi) {
	case AFI_IP:
		space = IPV4_MAX_BITLEN;
		break;
	case AFI_IP6:
		space = IPV6_MAX_BITLEN;
		break;
	default:
		return 0;
	}

	ts->counts[BGP_STATS_MAXBITLEN] = space;

	for (dest = top; dest; dest = bgp_route_next(dest)) {
		if (ts->table->safi == SAFI_MPLS_VPN
		    || ts->table->safi == SAFI_ENCAP
		    || ts->table->safi == SAFI_EVPN) {
			struct bgp_table *table;

			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			top = bgp_table_top(table);
			for (ndest = bgp_table_top(table); ndest;
			     ndest = bgp_route_next(ndest))
				bgp_table_stats_rn(ndest, top, ts, space);
		} else {
			bgp_table_stats_rn(dest, top, ts, space);
		}
	}

	return 0;
}

static void bgp_table_stats_all(struct vty *vty, afi_t afi, safi_t safi,
				struct json_object *json_array)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_table_stats_single(vty, bgp, afi, safi, json_array);
}

static int bgp_table_stats_single(struct vty *vty, struct bgp *bgp, afi_t afi,
				  safi_t safi, struct json_object *json_array)
{
	struct bgp_table_stats ts;
	unsigned int i;
	int ret = CMD_SUCCESS;
	char temp_buf[20];
	struct json_object *json = NULL;

	if (json_array)
		json = json_object_new_object();

	if (!bgp->rib[afi][safi]) {
		char warning_msg[50];

		snprintf(warning_msg, sizeof(warning_msg),
			 "%% No RIB exist's for the AFI(%d)/SAFI(%d)", afi,
			 safi);

		if (!json)
			vty_out(vty, "%s\n", warning_msg);
		else
			json_object_string_add(json, "warning", warning_msg);

		ret = CMD_WARNING;
		goto end_table_stats;
	}

	if (!json)
		vty_out(vty, "BGP %s RIB statistics (%s)\n",
			get_afi_safi_str(afi, safi, false), bgp->name_pretty);
	else
		json_object_string_add(json, "instance", bgp->name_pretty);

	/* labeled-unicast routes live in the unicast table */
	if (safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	memset(&ts, 0, sizeof(ts));
	ts.table = bgp->rib[afi][safi];
	thread_execute(bm->master, bgp_table_stats_walker, &ts, 0);

	for (i = 0; i < BGP_STATS_MAX; i++) {
		if ((!json && !table_stats_strs[i][TABLE_STATS_IDX_VTY])
		    || (json && !table_stats_strs[i][TABLE_STATS_IDX_JSON]))
			continue;

		switch (i) {
#if 0
          case BGP_STATS_ASPATH_AVGHOPS:
          case BGP_STATS_ASPATH_AVGSIZE:
          case BGP_STATS_AVGPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     (float)ts.counts[i] / (float)TALLY_SIGFIG);
            break;
#endif
		case BGP_STATS_ASPATH_TOTHOPS:
		case BGP_STATS_ASPATH_TOTSIZE:
			if (!json) {
				snprintf(
					temp_buf, sizeof(temp_buf), "%12.2f",
					ts.counts[i]
						? (float)ts.counts[i]
							  / (float)ts.counts
								    [BGP_STATS_ASPATH_COUNT]
						: 0);
				vty_out(vty, "%-30s: %s",
					table_stats_strs[i]
							[TABLE_STATS_IDX_VTY],
					temp_buf);
			} else {
				json_object_double_add(
					json,
					table_stats_strs[i]
							[TABLE_STATS_IDX_JSON],
					ts.counts[i]
						? (double)ts.counts[i]
							  / (double)ts.counts
							    [BGP_STATS_ASPATH_COUNT]
						: 0);
			}
			break;
		case BGP_STATS_TOTPLEN:
			if (!json) {
				snprintf(
					temp_buf, sizeof(temp_buf), "%12.2f",
					ts.counts[i]
						? (float)ts.counts[i]
							  / (float)ts.counts
							    [BGP_STATS_PREFIXES]
						: 0);
				vty_out(vty, "%-30s: %s",
					table_stats_strs[i]
							[TABLE_STATS_IDX_VTY],
					temp_buf);
			} else {
				json_object_double_add(
					json,
					table_stats_strs[i]
							[TABLE_STATS_IDX_JSON],
					ts.counts[i]
						? (double)ts.counts[i]
							  / (double)ts.counts
							    [BGP_STATS_PREFIXES]
						: 0);
			}
			break;
		case BGP_STATS_SPACE:
			if (!json) {
				snprintf(temp_buf, sizeof(temp_buf), "%12g",
					 ts.total_space);
				vty_out(vty, "%-30s: %s\n",
					table_stats_strs[i]
							[TABLE_STATS_IDX_VTY],
					temp_buf);
			} else {
				json_object_double_add(
					json,
					table_stats_strs[i]
							[TABLE_STATS_IDX_JSON],
					(double)ts.total_space);
			}
			if (afi == AFI_IP6) {
				if (!json) {
					snprintf(temp_buf, sizeof(temp_buf),
						 "%12g",
						 ts.total_space
							 * pow(2.0, -128 + 32));
					vty_out(vty, "%30s: %s\n",
						"/32 equivalent %s\n",
						temp_buf);
				} else {
					json_object_double_add(
						json, "/32equivalent",
						(double)(ts.total_space
							 * pow(2.0,
							       -128 + 32)));
				}
				if (!json) {
					snprintf(temp_buf, sizeof(temp_buf),
						 "%12g",
						 ts.total_space
							 * pow(2.0, -128 + 48));
					vty_out(vty, "%30s: %s\n",
						"/48 equivalent %s\n",
						temp_buf);
				} else {
					json_object_double_add(
						json, "/48equivalent",
						(double)(ts.total_space
							 * pow(2.0,
							       -128 + 48)));
				}
			} else {
				if (!json) {
					snprintf(temp_buf, sizeof(temp_buf),
						 "%12.2f",
						 ts.total_space * 100.
							 * pow(2.0, -32));
					vty_out(vty, "%30s: %s\n",
						"% announced ", temp_buf);
				} else {
					json_object_double_add(
						json, "%announced",
						(double)(ts.total_space * 100.
							 * pow(2.0, -32)));
				}
				if (!json) {
					snprintf(temp_buf, sizeof(temp_buf),
						 "%12.2f",
						 ts.total_space
							 * pow(2.0, -32 + 8));
					vty_out(vty, "%30s: %s\n",
						"/8 equivalent ", temp_buf);
				} else {
					json_object_double_add(
						json, "/8equivalent",
						(double)(ts.total_space
							 * pow(2.0, -32 + 8)));
				}
				if (!json) {
					snprintf(temp_buf, sizeof(temp_buf),
						 "%12.2f",
						 ts.total_space
							 * pow(2.0, -32 + 24));
					vty_out(vty, "%30s: %s\n",
						"/24 equivalent ", temp_buf);
				} else {
					json_object_double_add(
						json, "/24equivalent",
						(double)(ts.total_space
							 * pow(2.0, -32 + 24)));
				}
			}
			break;
		default:
			if (!json) {
				snprintf(temp_buf, sizeof(temp_buf), "%12llu",
					 ts.counts[i]);
				vty_out(vty, "%-30s: %s",
					table_stats_strs[i]
							[TABLE_STATS_IDX_VTY],
					temp_buf);
			} else {
				json_object_int_add(
					json,
					table_stats_strs[i]
							[TABLE_STATS_IDX_JSON],
					ts.counts[i]);
			}
		}
		if (!json)
			vty_out(vty, "\n");
	}
end_table_stats:
	if (json)
		json_object_array_add(json_array, json);
	return ret;
}

static int bgp_table_stats(struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi, struct json_object *json_array)
{
	if (!bgp) {
		bgp_table_stats_all(vty, afi, safi, json_array);
		return CMD_SUCCESS;
	}

	return bgp_table_stats_single(vty, bgp, afi, safi, json_array);
}

enum bgp_pcounts {
	PCOUNT_ADJ_IN = 0,
	PCOUNT_DAMPED,
	PCOUNT_REMOVED,
	PCOUNT_HISTORY,
	PCOUNT_STALE,
	PCOUNT_VALID,
	PCOUNT_ALL,
	PCOUNT_COUNTED,
	PCOUNT_BPATH_SELECTED,
	PCOUNT_PFCNT, /* the figure we display to users */
	PCOUNT_MAX,
};

static const char *const pcount_strs[] = {
		[PCOUNT_ADJ_IN] = "Adj-in",
		[PCOUNT_DAMPED] = "Damped",
		[PCOUNT_REMOVED] = "Removed",
		[PCOUNT_HISTORY] = "History",
		[PCOUNT_STALE] = "Stale",
		[PCOUNT_VALID] = "Valid",
		[PCOUNT_ALL] = "All RIB",
		[PCOUNT_COUNTED] = "PfxCt counted",
		[PCOUNT_BPATH_SELECTED] = "PfxCt Best Selected",
		[PCOUNT_PFCNT] = "Useable",
		[PCOUNT_MAX] = NULL,
};

struct peer_pcounts {
	unsigned int count[PCOUNT_MAX];
	const struct peer *peer;
	const struct bgp_table *table;
	safi_t safi;
};

static void bgp_peer_count_proc(struct bgp_dest *rn, struct peer_pcounts *pc)
{
	const struct bgp_adj_in *ain;
	const struct bgp_path_info *pi;
	const struct peer *peer = pc->peer;

	for (ain = rn->adj_in; ain; ain = ain->next)
		if (ain->peer == peer)
			pc->count[PCOUNT_ADJ_IN]++;

	for (pi = bgp_dest_get_bgp_path_info(rn); pi; pi = pi->next) {

		if (pi->peer != peer)
			continue;

		pc->count[PCOUNT_ALL]++;

		if (CHECK_FLAG(pi->flags, BGP_PATH_DAMPED))
			pc->count[PCOUNT_DAMPED]++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
			pc->count[PCOUNT_HISTORY]++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			pc->count[PCOUNT_REMOVED]++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_STALE))
			pc->count[PCOUNT_STALE]++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_VALID))
			pc->count[PCOUNT_VALID]++;
		if (!CHECK_FLAG(pi->flags, BGP_PATH_UNUSEABLE))
			pc->count[PCOUNT_PFCNT]++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			pc->count[PCOUNT_BPATH_SELECTED]++;

		if (CHECK_FLAG(pi->flags, BGP_PATH_COUNTED)) {
			pc->count[PCOUNT_COUNTED]++;
			if (CHECK_FLAG(pi->flags, BGP_PATH_UNUSEABLE))
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Attempting to count but flags say it is unusable");
		} else {
			if (!CHECK_FLAG(pi->flags, BGP_PATH_UNUSEABLE))
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Not counted but flags say we should");
		}
	}
}

static int bgp_peer_count_walker(struct thread *t)
{
	struct bgp_dest *rn, *rm;
	const struct bgp_table *table;
	struct peer_pcounts *pc = THREAD_ARG(t);

	if (pc->safi == SAFI_MPLS_VPN || pc->safi == SAFI_ENCAP
	    || pc->safi == SAFI_EVPN) {
		/* Special handling for 2-level routing tables. */
		for (rn = bgp_table_top(pc->table); rn;
		     rn = bgp_route_next(rn)) {
			table = bgp_dest_get_bgp_table_info(rn);
			if (table != NULL)
				for (rm = bgp_table_top(table); rm;
				     rm = bgp_route_next(rm))
					bgp_peer_count_proc(rm, pc);
		}
	} else
		for (rn = bgp_table_top(pc->table); rn; rn = bgp_route_next(rn))
			bgp_peer_count_proc(rn, pc);

	return 0;
}

static int bgp_peer_counts(struct vty *vty, struct peer *peer, afi_t afi,
			   safi_t safi, bool use_json)
{
	struct peer_pcounts pcounts = {.peer = peer};
	unsigned int i;
	json_object *json = NULL;
	json_object *json_loop = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_loop = json_object_new_object();
	}

	if (!peer || !peer->bgp || !peer->afc[afi][safi]
	    || !peer->bgp->rib[afi][safi]) {
		if (use_json) {
			json_object_string_add(
				json, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");

		return CMD_WARNING;
	}

	memset(&pcounts, 0, sizeof(pcounts));
	pcounts.peer = peer;
	pcounts.table = peer->bgp->rib[afi][safi];
	pcounts.safi = safi;

	/* in-place call via thread subsystem so as to record execution time
	 * stats for the thread-walk (i.e. ensure this can't be blamed on
	 * on just vty_read()).
	 */
	thread_execute(bm->master, bgp_peer_count_walker, &pcounts, 0);

	if (use_json) {
		json_object_string_add(json, "prefixCountsFor", peer->host);
		json_object_string_add(json, "multiProtocol",
				       get_afi_safi_str(afi, safi, true));
		json_object_int_add(json, "pfxCounter",
				    peer->pcount[afi][safi]);

		for (i = 0; i < PCOUNT_MAX; i++)
			json_object_int_add(json_loop, pcount_strs[i],
					    pcounts.count[i]);

		json_object_object_add(json, "ribTableWalkCounters", json_loop);

		if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi]) {
			json_object_string_add(json, "pfxctDriftFor",
					       peer->host);
			json_object_string_add(
				json, "recommended",
				"Please report this bug, with the above command output");
		}
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {

		if (peer->hostname
		    && CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHOW_HOSTNAME)) {
			vty_out(vty, "Prefix counts for %s/%s, %s\n",
				peer->hostname, peer->host,
				get_afi_safi_str(afi, safi, false));
		} else {
			vty_out(vty, "Prefix counts for %s, %s\n", peer->host,
				get_afi_safi_str(afi, safi, false));
		}

		vty_out(vty, "PfxCt: %u\n", peer->pcount[afi][safi]);
		vty_out(vty, "\nCounts from RIB table walk:\n\n");

		for (i = 0; i < PCOUNT_MAX; i++)
			vty_out(vty, "%20s: %-10d\n", pcount_strs[i],
				pcounts.count[i]);

		if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi]) {
			vty_out(vty, "%s [pcount] PfxCt drift!\n", peer->host);
			vty_out(vty,
				"Please report this bug, with the above command output\n");
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_instance_neighbor_prefix_counts,
       show_ip_bgp_instance_neighbor_prefix_counts_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct peer *peer;
	int idx = 0;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);

	if (uj)
		argc--;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	argv_find(argv, argc, "neighbors", &idx);
	peer = peer_lookup_in_view(vty, bgp, argv[idx + 1]->arg, uj);
	if (!peer)
		return CMD_WARNING;

	return bgp_peer_counts(vty, peer, afi, safi, uj);
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN (show_ip_bgp_vpn_neighbor_prefix_counts,
       show_ip_bgp_vpn_neighbor_prefix_counts_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
	int idx_peer = 6;
	struct peer *peer;
	bool uj = use_json(argc, argv);

	peer = peer_lookup_in_view(vty, NULL, argv[idx_peer]->arg, uj);
	if (!peer)
		return CMD_WARNING;

	return bgp_peer_counts(vty, peer, AFI_IP, SAFI_MPLS_VPN, uj);
}

DEFUN (show_ip_bgp_vpn_all_route_prefix,
       show_ip_bgp_vpn_all_route_prefix_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all <A.B.C.D|A.B.C.D/M> [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       JSON_STR)
{
	int idx = 0;
	char *network = NULL;
	struct bgp *bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "Can't find default instance\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx))
		network = argv[idx]->arg;
	else if (argv_find(argv, argc, "A.B.C.D/M", &idx))
		network = argv[idx]->arg;
	else {
		vty_out(vty, "Unable to figure out Network\n");
		return CMD_WARNING;
	}

	return bgp_show_route(vty, bgp, network, AFI_IP, SAFI_MPLS_VPN, NULL, 0,
			      BGP_PATH_SHOW_ALL, use_json(argc, argv));
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFUN (show_bgp_l2vpn_evpn_route_prefix,
       show_bgp_l2vpn_evpn_route_prefix_cmd,
       "show bgp l2vpn evpn <A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> [json]",
       SHOW_STR
       BGP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       JSON_STR)
{
	int idx = 0;
	char *network = NULL;
	int prefix_check = 0;

	if (argv_find(argv, argc, "A.B.C.D", &idx) ||
		argv_find(argv, argc, "X:X::X:X", &idx))
		network = argv[idx]->arg;
	else if (argv_find(argv, argc, "A.B.C.D/M", &idx) ||
		argv_find(argv, argc, "X:X::X:X/M", &idx)) {
		network = argv[idx]->arg;
		prefix_check = 1;
	} else {
		vty_out(vty, "Unable to figure out Network\n");
		return CMD_WARNING;
	}
	return bgp_show_route(vty, NULL, network, AFI_L2VPN, SAFI_EVPN, NULL,
			      prefix_check, BGP_PATH_SHOW_ALL,
			      use_json(argc, argv));
}

static void show_adj_route_header(struct vty *vty, struct bgp *bgp,
				  struct bgp_table *table, int *header1,
				  int *header2, json_object *json,
				  json_object *json_scode,
				  json_object *json_ocode, bool wide)
{
	uint64_t version = table ? table->version : 0;
	char buf[BUFSIZ] = {0};

	if (*header1) {
		if (json) {
			json_object_int_add(json, "bgpTableVersion", version);
			json_object_string_add(json, "bgpLocalRouterId",
					       inet_ntop(AF_INET,
							 &bgp->router_id, buf,
							 sizeof(buf)));
			json_object_int_add(json, "defaultLocPrf",
					    bgp->default_local_pref);
			json_object_int_add(json, "localAS", bgp->as);
			json_object_object_add(json, "bgpStatusCodes",
					       json_scode);
			json_object_object_add(json, "bgpOriginCodes",
					       json_ocode);
		} else {
			vty_out(vty,
				"BGP table version is %" PRIu64
				", local router ID is %pI4, vrf id ",
				version, &bgp->router_id);
			if (bgp->vrf_id == VRF_UNKNOWN)
				vty_out(vty, "%s", VRFID_NONE_STR);
			else
				vty_out(vty, "%u", bgp->vrf_id);
			vty_out(vty, "\n");
			vty_out(vty, "Default local pref %u, ",
				bgp->default_local_pref);
			vty_out(vty, "local AS %u\n", bgp->as);
			vty_out(vty, BGP_SHOW_SCODE_HEADER);
			vty_out(vty, BGP_SHOW_NCODE_HEADER);
			vty_out(vty, BGP_SHOW_OCODE_HEADER);
		}
		*header1 = 0;
	}
	if (*header2) {
		if (!json)
			vty_out(vty, (wide ? BGP_SHOW_HEADER_WIDE
					   : BGP_SHOW_HEADER));
		*header2 = 0;
	}
}

static void show_adj_route(struct vty *vty, struct peer *peer, afi_t afi,
			   safi_t safi, enum bgp_show_adj_route_type type,
			   const char *rmap_name, json_object *json,
			   uint8_t show_flags)
{
	struct bgp_table *table;
	struct bgp_adj_in *ain;
	struct bgp_adj_out *adj;
	unsigned long output_count = 0;
	unsigned long filtered_count = 0;
	struct bgp_dest *dest;
	int header1 = 1;
	struct bgp *bgp;
	int header2 = 1;
	struct attr attr;
	int ret;
	struct update_subgroup *subgrp;
	json_object *json_scode = NULL;
	json_object *json_ocode = NULL;
	json_object *json_ar = NULL;
	struct peer_af *paf;
	bool route_filtered;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	if (use_json) {
		json_scode = json_object_new_object();
		json_ocode = json_object_new_object();
		json_ar = json_object_new_object();

		json_object_string_add(json_scode, "suppressed", "s");
		json_object_string_add(json_scode, "damped", "d");
		json_object_string_add(json_scode, "history", "h");
		json_object_string_add(json_scode, "valid", "*");
		json_object_string_add(json_scode, "best", ">");
		json_object_string_add(json_scode, "multipath", "=");
		json_object_string_add(json_scode, "internal", "i");
		json_object_string_add(json_scode, "ribFailure", "r");
		json_object_string_add(json_scode, "stale", "S");
		json_object_string_add(json_scode, "removed", "R");

		json_object_string_add(json_ocode, "igp", "i");
		json_object_string_add(json_ocode, "egp", "e");
		json_object_string_add(json_ocode, "incomplete", "?");
	}

	bgp = peer->bgp;

	if (!bgp) {
		if (use_json) {
			json_object_string_add(json, "alert", "no BGP");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
		} else
			vty_out(vty, "%% No bgp\n");
		return;
	}

	/* labeled-unicast routes live in the unicast table */
	if (safi == SAFI_LABELED_UNICAST)
		table = bgp->rib[afi][SAFI_UNICAST];
	else
		table = bgp->rib[afi][safi];

	output_count = filtered_count = 0;
	subgrp = peer_subgroup(peer, afi, safi);

	if (type == bgp_show_adj_route_advertised && subgrp
	    && CHECK_FLAG(subgrp->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE)) {
		char buf[BUFSIZ] = {0};

		if (use_json) {
			json_object_int_add(json, "bgpTableVersion",
					    table->version);
			json_object_string_add(json, "bgpLocalRouterId",
					       inet_ntop(AF_INET,
							 &bgp->router_id, buf,
							 sizeof(buf)));
			json_object_int_add(json, "defaultLocPrf",
						bgp->default_local_pref);
			json_object_int_add(json, "localAS", bgp->as);
			json_object_object_add(json, "bgpStatusCodes",
					       json_scode);
			json_object_object_add(json, "bgpOriginCodes",
					       json_ocode);
			json_object_string_add(
				json, "bgpOriginatingDefaultNetwork",
				(afi == AFI_IP) ? "0.0.0.0/0" : "::/0");
		} else {
			vty_out(vty,
				"BGP table version is %" PRIu64
				", local router ID is %pI4, vrf id ",
				table->version, &bgp->router_id);
			if (bgp->vrf_id == VRF_UNKNOWN)
				vty_out(vty, "%s", VRFID_NONE_STR);
			else
				vty_out(vty, "%u", bgp->vrf_id);
			vty_out(vty, "\n");
			vty_out(vty, "Default local pref %u, ",
				bgp->default_local_pref);
			vty_out(vty, "local AS %u\n", bgp->as);
			vty_out(vty, BGP_SHOW_SCODE_HEADER);
			vty_out(vty, BGP_SHOW_NCODE_HEADER);
			vty_out(vty, BGP_SHOW_OCODE_HEADER);

			vty_out(vty, "Originating default network %s\n\n",
				(afi == AFI_IP) ? "0.0.0.0/0" : "::/0");
		}
		header1 = 0;
	}

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		if (type == bgp_show_adj_route_received
		    || type == bgp_show_adj_route_filtered) {
			for (ain = dest->adj_in; ain; ain = ain->next) {
				if (ain->peer != peer)
					continue;

				show_adj_route_header(
					vty, bgp, table, &header1, &header2,
					json, json_scode, json_ocode, wide);

				attr = *ain->attr;
				route_filtered = false;

				/* Filter prefix using distribute list,
				 * filter list or prefix list
				 */
				const struct prefix *rn_p =
					bgp_dest_get_prefix(dest);
				if ((bgp_input_filter(peer, rn_p, &attr, afi,
						      safi))
				    == FILTER_DENY)
					route_filtered = true;

				/* Filter prefix using route-map */
				ret = bgp_input_modifier(peer, rn_p, &attr, afi,
							 safi, rmap_name, NULL,
							 0, NULL);

				if (type == bgp_show_adj_route_filtered &&
					!route_filtered && ret != RMAP_DENY) {
					bgp_attr_undup(&attr, ain->attr);
					continue;
				}

				if (type == bgp_show_adj_route_received &&
					(route_filtered || ret == RMAP_DENY))
					filtered_count++;

				route_vty_out_tmp(vty, rn_p, &attr, safi,
						  use_json, json_ar, wide);
				bgp_attr_undup(&attr, ain->attr);
				output_count++;
			}
		} else if (type == bgp_show_adj_route_advertised) {
			RB_FOREACH (adj, bgp_adj_out_rb, &dest->adj_out)
				SUBGRP_FOREACH_PEER (adj->subgroup, paf) {
					if (paf->peer != peer || !adj->attr)
						continue;

					show_adj_route_header(
						vty, bgp, table, &header1,
						&header2, json, json_scode,
						json_ocode, wide);

					const struct prefix *rn_p =
						bgp_dest_get_prefix(dest);

					attr = *adj->attr;
					ret = bgp_output_modifier(
						peer, rn_p, &attr, afi, safi,
						rmap_name);

					if (ret != RMAP_DENY) {
						route_vty_out_tmp(
							vty, rn_p, &attr, safi,
							use_json, json_ar,
							wide);
						output_count++;
					} else {
						filtered_count++;
					}

					bgp_attr_undup(&attr, adj->attr);
				}
		} else if (type == bgp_show_adj_route_bestpath) {
			struct bgp_path_info *pi;

			show_adj_route_header(vty, bgp, table, &header1,
					      &header2, json, json_scode,
					      json_ocode, wide);

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;

				if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
					continue;

				route_vty_out_tmp(vty,
						  bgp_dest_get_prefix(dest),
						  pi->attr, safi, use_json,
						  json_ar, wide);
				output_count++;
			}
		}
	}

	if (use_json) {
		json_object_object_add(json, "advertisedRoutes", json_ar);
		json_object_int_add(json, "totalPrefixCounter", output_count);
		json_object_int_add(json, "filteredPrefixCounter",
				    filtered_count);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));

		if (!output_count && !filtered_count) {
			json_object_free(json_scode);
			json_object_free(json_ocode);
		}

		json_object_free(json);
	} else if (output_count > 0) {
		if (filtered_count > 0)
			vty_out(vty,
				"\nTotal number of prefixes %ld (%ld filtered)\n",
				output_count, filtered_count);
		else
			vty_out(vty, "\nTotal number of prefixes %ld\n",
				output_count);
	}
}

static int peer_adj_routes(struct vty *vty, struct peer *peer, afi_t afi,
			   safi_t safi, enum bgp_show_adj_route_type type,
			   const char *rmap_name, uint8_t show_flags)
{
	json_object *json = NULL;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json)
		json = json_object_new_object();

	if (!peer || !peer->afc[afi][safi]) {
		if (use_json) {
			json_object_string_add(
				json, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");

		return CMD_WARNING;
	}

	if ((type == bgp_show_adj_route_received
	     || type == bgp_show_adj_route_filtered)
	    && !CHECK_FLAG(peer->af_flags[afi][safi],
			   PEER_FLAG_SOFT_RECONFIG)) {
		if (use_json) {
			json_object_string_add(
				json, "warning",
				"Inbound soft reconfiguration not enabled");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
		} else
			vty_out(vty,
				"%% Inbound soft reconfiguration not enabled\n");

		return CMD_WARNING;
	}

	show_adj_route(vty, peer, afi, safi, type, rmap_name, json, show_flags);

	return CMD_SUCCESS;
}

DEFPY (show_ip_bgp_instance_neighbor_bestpath_route,
       show_ip_bgp_instance_neighbor_bestpath_route_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] neighbors <A.B.C.D|X:X::X:X|WORD> bestpath-routes [json$uj | wide$wide]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display the routes selected by best path\n"
       JSON_STR
       "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	char *rmap_name = NULL;
	char *peerstr = NULL;
	struct bgp *bgp = NULL;
	struct peer *peer;
	enum bgp_show_adj_route_type type = bgp_show_adj_route_bestpath;
	int idx = 0;
	uint8_t show_flags = 0;

	if (uj)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (wide)
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);

	if (!idx)
		return CMD_WARNING;

	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer)
		return CMD_WARNING;

	return peer_adj_routes(vty, peer, afi, safi, type, rmap_name,
			       show_flags);
}

DEFPY (show_ip_bgp_instance_neighbor_advertised_route,
       show_ip_bgp_instance_neighbor_advertised_route_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] [all$all] neighbors <A.B.C.D|X:X::X:X|WORD> <advertised-routes|received-routes|filtered-routes> [route-map WORD] [json$uj | wide$wide]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Display the entries for all address families\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display the routes advertised to a BGP neighbor\n"
       "Display the received routes from neighbor\n"
       "Display the filtered routes received from neighbor\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n"
       JSON_STR
       "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	char *rmap_name = NULL;
	char *peerstr = NULL;
	struct bgp *bgp = NULL;
	struct peer *peer;
	enum bgp_show_adj_route_type type = bgp_show_adj_route_advertised;
	int idx = 0;
	bool first = true;
	uint8_t show_flags = 0;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	if (all) {
		SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL);
		if (argv_find(argv, argc, "ipv4", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP);

		if (argv_find(argv, argc, "ipv6", &idx))
			SET_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6);
	}

	if (wide)
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer)
		return CMD_WARNING;

	if (argv_find(argv, argc, "advertised-routes", &idx))
		type = bgp_show_adj_route_advertised;
	else if (argv_find(argv, argc, "received-routes", &idx))
		type = bgp_show_adj_route_received;
	else if (argv_find(argv, argc, "filtered-routes", &idx))
		type = bgp_show_adj_route_filtered;

	if (argv_find(argv, argc, "route-map", &idx))
		rmap_name = argv[++idx]->arg;

	if (!all)
		return peer_adj_routes(vty, peer, afi, safi, type, rmap_name,
				       show_flags);
	if (uj)
		vty_out(vty, "{\n");

	if (CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
	    || CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6)) {
		afi = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP) ? AFI_IP
								  : AFI_IP6;
		FOREACH_SAFI (safi) {
			if (!bgp_afi_safi_peer_exists(bgp, afi, safi))
				continue;

			if (uj) {
				if (first)
					first = false;
				else
					vty_out(vty, ",\n");
				vty_out(vty, "\"%s\":",
					get_afi_safi_str(afi, safi, true));
			} else
				vty_out(vty, "\nFor address family: %s\n",
					get_afi_safi_str(afi, safi, false));

			peer_adj_routes(vty, peer, afi, safi, type, rmap_name,
					show_flags);
		}
	} else {
		FOREACH_AFI_SAFI (afi, safi) {
			if (!bgp_afi_safi_peer_exists(bgp, afi, safi))
				continue;

			if (uj) {
				if (first)
					first = false;
				else
					vty_out(vty, ",\n");
				vty_out(vty, "\"%s\":",
					get_afi_safi_str(afi, safi, true));
			} else
				vty_out(vty, "\nFor address family: %s\n",
					get_afi_safi_str(afi, safi, false));

			peer_adj_routes(vty, peer, afi, safi, type, rmap_name,
					show_flags);
		}
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show [ip] bgp [<ipv4|ipv6> [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD> received prefix-filter [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n"
       JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	char *peerstr = NULL;

	char name[BUFSIZ];
	union sockunion su;
	struct peer *peer;
	int count, ret;

	int idx = 0;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<ipv4|ipv6> [unicast]] */
	if (argv_find(argv, argc, "ipv4", &idx))
		afi = AFI_IP;
	if (argv_find(argv, argc, "ipv6", &idx))
		afi = AFI_IP6;
	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	bool uj = use_json(argc, argv);

	ret = str2sockunion(peerstr, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(NULL, peerstr);
		if (!peer) {
			if (uj)
				vty_out(vty, "{}\n");
			else
				vty_out(vty,
					"%% Malformed address or name: %s\n",
					peerstr);
			return CMD_WARNING;
		}
	} else {
		peer = peer_lookup(NULL, &su);
		if (!peer) {
			if (uj)
				vty_out(vty, "{}\n");
			else
				vty_out(vty, "No peer\n");
			return CMD_WARNING;
		}
	}

	snprintf(name, sizeof(name), "%s.%d.%d", peer->host, afi, safi);
	count = prefix_bgp_show_prefix_list(NULL, afi, name, uj);
	if (count) {
		if (!uj)
			vty_out(vty, "Address Family: %s\n",
				get_afi_safi_str(afi, safi, false));
		prefix_bgp_show_prefix_list(vty, afi, name, uj);
	} else {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No functional output\n");
	}

	return CMD_SUCCESS;
}

static int bgp_show_neighbor_route(struct vty *vty, struct peer *peer,
				   afi_t afi, safi_t safi,
				   enum bgp_show_type type, bool use_json)
{
	uint8_t show_flags = 0;

	if (use_json)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (!peer || !peer->afc[afi][safi]) {
		if (use_json) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(
				json_no, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

	/* labeled-unicast routes live in the unicast table */
	if (safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	return bgp_show(vty, peer->bgp, afi, safi, type, &peer->su, show_flags);
}

DEFUN (show_ip_bgp_flowspec_routes_detailed,
       show_ip_bgp_flowspec_routes_detailed_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" flowspec] detail [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       "SAFI Flowspec\n"
       "Detailed information on flowspec entries\n"
       JSON_STR)
{
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0;
	bool uj = use_json(argc, argv);
	uint8_t show_flags = 0;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	return bgp_show(vty, bgp, afi, safi, bgp_show_type_detail, NULL,
			show_flags);
}

DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] neighbors <A.B.C.D|X:X::X:X|WORD> <flap-statistics|dampened-routes|routes> [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n"
       "Display the dampened routes received from neighbor\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
	char *peerstr = NULL;
	struct bgp *bgp = NULL;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct peer *peer;
	enum bgp_show_type sh_type = bgp_show_type_neighbor;
	int idx = 0;
	bool uj = use_json(argc, argv);

	if (uj)
		argc--;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer)
		return CMD_WARNING;

	if (argv_find(argv, argc, "flap-statistics", &idx))
		sh_type = bgp_show_type_flap_neighbor;
	else if (argv_find(argv, argc, "dampened-routes", &idx))
		sh_type = bgp_show_type_damp_neighbor;
	else if (argv_find(argv, argc, "routes", &idx))
		sh_type = bgp_show_type_neighbor;

	return bgp_show_neighbor_route(vty, peer, afi, safi, sh_type, uj);
}

struct bgp_table *bgp_distance_table[AFI_MAX][SAFI_MAX];

struct bgp_distance {
	/* Distance value for the IP source prefix. */
	uint8_t distance;

	/* Name of the access-list to be matched. */
	char *access_list;
};

DEFUN (show_bgp_afi_vpn_rd_route,
       show_bgp_afi_vpn_rd_route_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn rd ASN:NN_OR_IP-ADDRESS:NN <A.B.C.D/M|X:X::X:X/M> [json]",
       SHOW_STR
       BGP_STR
       BGP_AFI_HELP_STR
       "Address Family modifier\n"
       "Display information for a route distinguisher\n"
       "Route Distinguisher\n"
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       JSON_STR)
{
	int ret;
	struct prefix_rd prd;
	afi_t afi = AFI_MAX;
	int idx = 0;

	if (!argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		vty_out(vty, "%% Malformed Address Family\n");
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[5]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	return bgp_show_route(vty, NULL, argv[6]->arg, afi, SAFI_MPLS_VPN, &prd,
			      0, BGP_PATH_SHOW_ALL, use_json(argc, argv));
}

static struct bgp_distance *bgp_distance_new(void)
{
	return XCALLOC(MTYPE_BGP_DISTANCE, sizeof(struct bgp_distance));
}

static void bgp_distance_free(struct bgp_distance *bdistance)
{
	XFREE(MTYPE_BGP_DISTANCE, bdistance);
}

int bgp_distance_set(uint8_t distance, const char *ip_str,
		     const char *access_list_str, afi_t afi, safi_t safi,
		     char *errmsg, size_t errmsg_len)
{
	int ret;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_distance *bdistance;

	ret = str2prefix(ip_str, &p);
	if (ret == 0) {
		snprintf(errmsg, errmsg_len, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get BGP distance node. */
	dest = bgp_node_get(bgp_distance_table[afi][safi], &p);
	bdistance = bgp_dest_get_bgp_distance_info(dest);
	if (bdistance)
		bgp_dest_unlock_node(dest);
	else {
		bdistance = bgp_distance_new();
		bgp_dest_set_bgp_distance_info(dest, bdistance);
	}

	/* Set distance value. */
	bdistance->distance = distance;

	/* Reset access-list configuration. */
	XFREE(MTYPE_AS_LIST, bdistance->access_list);
	if (access_list_str)
		bdistance->access_list =
			XSTRDUP(MTYPE_AS_LIST, access_list_str);

	return CMD_SUCCESS;
}

int bgp_distance_unset(uint8_t distance, const char *ip_str,
		       const char *access_list_str, afi_t afi, safi_t safi,
		       char *errmsg, size_t errmsg_len)
{
	int ret;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_distance *bdistance;

	ret = str2prefix(ip_str, &p);
	if (ret == 0) {
		snprintf(errmsg, errmsg_len, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	dest = bgp_node_lookup(bgp_distance_table[afi][safi], &p);
	if (!dest) {
		snprintf(errmsg, errmsg_len, "Can't find specified prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bdistance = bgp_dest_get_bgp_distance_info(dest);

	if (bdistance->distance != distance) {
		snprintf(errmsg, errmsg_len,
			 "Distance does not match configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_AS_LIST, bdistance->access_list);
	bgp_distance_free(bdistance);

	bgp_dest_set_bgp_path_info(dest, NULL);
	bgp_dest_unlock_node(dest);
	bgp_dest_unlock_node(dest);

	return CMD_SUCCESS;
}

/* Apply BGP information to distance method. */
uint8_t bgp_distance_apply(const struct prefix *p, struct bgp_path_info *pinfo,
			   afi_t afi, safi_t safi, struct bgp *bgp)
{
	struct bgp_dest *dest;
	struct prefix q = {0};
	struct peer *peer;
	struct bgp_distance *bdistance;
	struct access_list *alist;
	struct bgp_static *bgp_static;

	if (!bgp)
		return 0;

	peer = pinfo->peer;

	if (pinfo->attr->distance)
		return pinfo->attr->distance;

	/* Check source address.
	 * Note: for aggregate route, peer can have unspec af type.
	 */
	if (pinfo->sub_type != BGP_ROUTE_AGGREGATE
	    && !sockunion2hostprefix(&peer->su, &q))
		return 0;

	dest = bgp_node_match(bgp_distance_table[afi][safi], &q);
	if (dest) {
		bdistance = bgp_dest_get_bgp_distance_info(dest);
		bgp_dest_unlock_node(dest);

		if (bdistance->access_list) {
			alist = access_list_lookup(afi, bdistance->access_list);
			if (alist
			    && access_list_apply(alist, p) == FILTER_PERMIT)
				return bdistance->distance;
		} else
			return bdistance->distance;
	}

	/* Backdoor check. */
	dest = bgp_node_lookup(bgp->route[afi][safi], p);
	if (dest) {
		bgp_static = bgp_dest_get_bgp_static_info(dest);
		bgp_dest_unlock_node(dest);

		if (bgp_static->backdoor) {
			if (bgp->distance_local[afi][safi])
				return bgp->distance_local[afi][safi];
			else
				return ZEBRA_IBGP_DISTANCE_DEFAULT;
		}
	}

	if (peer->sort == BGP_PEER_EBGP) {
		if (bgp->distance_ebgp[afi][safi])
			return bgp->distance_ebgp[afi][safi];
		return ZEBRA_EBGP_DISTANCE_DEFAULT;
	} else if (peer->sort == BGP_PEER_IBGP) {
		if (bgp->distance_ibgp[afi][safi])
			return bgp->distance_ibgp[afi][safi];
		return ZEBRA_IBGP_DISTANCE_DEFAULT;
	} else {
		if (bgp->distance_local[afi][safi])
			return bgp->distance_local[afi][safi];
		return ZEBRA_IBGP_DISTANCE_DEFAULT;
	}
}

/* If we enter `distance bgp (1-255) (1-255) (1-255)`,
 * we should tell ZEBRA update the routes for a specific
 * AFI/SAFI to reflect changes in RIB.
 */
void bgp_announce_routes_distance_update(struct bgp *bgp, afi_t update_afi,
					 safi_t update_safi)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;

		if (afi != update_afi && safi != update_safi)
			continue;

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: Announcing routes due to distance change afi/safi (%d/%d)",
				__func__, afi, safi);
		bgp_zebra_announce_table(bgp, afi, safi);
	}
}

DEFUN_YANG(bgp_distance, bgp_distance_cmd,
	   "distance bgp (1-255) (1-255) (1-255)",
	   "Define an administrative distance\n"
	   "BGP distance\n"
	   "Distance for routes external to the AS\n"
	   "Distance for routes internal to the AS\n"
	   "Distance for local routes\n")
{
	int idx_number = 2;
	int idx_number_2 = 3;
	int idx_number_3 = 4;
	afi_t afi;
	safi_t safi;
	char xpath[XPATH_MAXLEN];

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/external",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, argv[idx_number]->arg);
	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/internal",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      argv[idx_number_2]->arg);
	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/local",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
			      argv[idx_number_3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_distance, no_bgp_distance_cmd,
	   "no distance bgp [(1-255) (1-255) (1-255)]",
	   NO_STR
	   "Define an administrative distance\n"
	   "BGP distance\n"
	   "Distance for routes external to the AS\n"
	   "Distance for routes internal to the AS\n"
	   "Distance for local routes\n")
{
	afi_t afi;
	safi_t safi;
	char xpath[XPATH_MAXLEN];

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/external",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, NULL);
	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/internal",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, NULL);
	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance/local",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_bgp_global_afi_safi_admin_distance_config(struct vty *vty,
							struct lyd_node *dnode,
							bool show_defaults)
{
	uint8_t distance_ebgp, distance_ibgp, distance_local;

	distance_ebgp = yang_dnode_get_uint8(dnode, "./external");
	distance_ibgp = yang_dnode_get_uint8(dnode, "./internal");
	distance_local = yang_dnode_get_uint8(dnode, "./local");

	vty_out(vty, "  distance bgp %d %d %d\n", distance_ebgp, distance_ibgp,
		distance_local);
}

DEFPY_YANG(bgp_distance_source,
	   bgp_distance_source_cmd,
	   "[no] distance (1-255) <A.B.C.D/M | X:X::X:X/M>$prefix [WORD$acl]",
	   NO_STR
	   "Define an administrative distance\n"
	   "Distance value\n"
	   "IPv4 source prefix\n"
	   "IPv6 source prefix\n"
	   "Access list name\n")
{
	afi_t afi;
	safi_t safi;
	char xpath[XPATH_MAXLEN];

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./distance", NB_OP_MODIFY,
				      distance_str);
		if (acl)
			nb_cli_enqueue_change(vty,
					      "./access-list-policy-export",
					      NB_OP_CREATE, acl);
		else
			nb_cli_enqueue_change(vty,
					      "./access-list-policy-export",
					      NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}

	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/admin-distance-route[prefix='%s']",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi), prefix_str);

	return nb_cli_apply_changes(vty, xpath);
}

void cli_show_bgp_global_afi_safi_unicast_admin_distance_route(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  distance %d %s %s\n",
		yang_dnode_get_uint8(dnode, "./distance"),
		yang_dnode_get_string(dnode, "./prefix"),
		(yang_dnode_exists(dnode, "./access-list-policy-export"))
			? yang_dnode_get_string(dnode,
						"./access-list-policy-export")
			: "");
}

DEFPY_YANG(
	bgp_dampening, bgp_dampening_cmd,
	"[no] bgp dampening [(1-45)$halflife [(1-20000)$reuse (1-20000)$suppress (1-255)$max_suppress]]",
	NO_STR
	"BGP Specific commands\n"
	"Enable route-flap dampening\n"
	"Half-life time for the penalty\n"
	"Value to start reusing a route\n"
	"Value to start suppressing a route\n"
	"Maximum duration to suppress a stable route\n")
{
	afi_t afi;
	safi_t safi;
	char xpath[XPATH_MAXLEN];

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (!no) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
		if (argc == 6) {
			nb_cli_enqueue_change(vty, "./reach-decay",
					      NB_OP_MODIFY, halflife_str);
			nb_cli_enqueue_change(vty, "./reuse-above",
					      NB_OP_MODIFY, reuse_str);
			nb_cli_enqueue_change(vty, "./suppress-above",
					      NB_OP_MODIFY, suppress_str);
			nb_cli_enqueue_change(vty, "./unreach-decay",
					      NB_OP_MODIFY, max_suppress_str);
		} if (argc == 3) {
			nb_cli_enqueue_change(vty, "./reach-decay",
					      NB_OP_MODIFY, halflife_str);
		}
	} else {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "false");
	}

	snprintf(
		xpath, sizeof(xpath),
		"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/route-flap-dampening",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));

	return nb_cli_apply_changes(vty, xpath);
}

void cli_show_bgp_global_afi_safi_route_flap_dampening(struct vty *vty,
						       struct lyd_node *dnode,
						       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "./enable"))
		return;

	int half = DEFAULT_HALF_LIFE * 60;
	int reuse = DEFAULT_REUSE;
	int suppress = DEFAULT_SUPPRESS;
	int max;

	half = yang_dnode_get_uint8(dnode, "../reach-decay");
	reuse = yang_dnode_get_uint16(dnode, "../reuse-above");
	suppress = yang_dnode_get_uint16(dnode, "../suppress-above");
	max = yang_dnode_get_uint8(dnode, "../unreach-decay");

	if (half == DEFAULT_HALF_LIFE * 60 && reuse == DEFAULT_REUSE
	    && suppress == DEFAULT_SUPPRESS && max == half * 4)
		vty_out(vty, "  bgp dampening\n");
	else if (half != DEFAULT_HALF_LIFE * 60 && reuse == DEFAULT_REUSE
		 && suppress == DEFAULT_SUPPRESS && max == half * 4)
		vty_out(vty, "  bgp dampening %u\n", half);
	else
		vty_out(vty, "  bgp dampening %u %d %d %d\n", half, reuse,
			suppress, max);
}

/* Display specified route of BGP table. */
static int bgp_clear_damp_route(struct vty *vty, const char *view_name,
				const char *ip_str, afi_t afi, safi_t safi,
				struct prefix_rd *prd, int prefix_check)
{
	int ret;
	struct prefix match;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_path_info *pi;
	struct bgp_path_info *pi_temp;
	struct bgp *bgp;
	struct bgp_table *table;

	/* BGP structure lookup. */
	if (view_name) {
		bgp = bgp_lookup_by_name(view_name);
		if (bgp == NULL) {
			vty_out(vty, "%% Can't find BGP instance %s\n",
				view_name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	/* Check IP address argument. */
	ret = str2prefix(ip_str, &match);
	if (!ret) {
		vty_out(vty, "%% address is malformed\n");
		return CMD_WARNING;
	}

	match.family = afi2family(afi);

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN)) {
		for (dest = bgp_table_top(bgp->rib[AFI_IP][safi]); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (prd && memcmp(dest_p->u.val, prd->val, 8) != 0)
				continue;
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;
			if ((rm = bgp_node_match(table, &match)) == NULL)
				continue;

			const struct prefix *rm_p = bgp_dest_get_prefix(dest);

			if (!prefix_check
			    || rm_p->prefixlen == match.prefixlen) {
				pi = bgp_dest_get_bgp_path_info(rm);
				while (pi) {
					if (pi->extra && pi->extra->damp_info) {
						pi_temp = pi->next;
						bgp_damp_info_free(
							pi->extra->damp_info,
							1, afi, safi);
						pi = pi_temp;
					} else
						pi = pi->next;
				}
			}

			bgp_dest_unlock_node(rm);
		}
	} else {
		if ((dest = bgp_node_match(bgp->rib[afi][safi], &match))
		    != NULL) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (!prefix_check
			    || dest_p->prefixlen == match.prefixlen) {
				pi = bgp_dest_get_bgp_path_info(dest);
				while (pi) {
					if (pi->extra && pi->extra->damp_info) {
						pi_temp = pi->next;
						bgp_damp_info_free(
							pi->extra->damp_info,
							1, afi, safi);
						pi = pi_temp;
					} else
						pi = pi->next;
				}
			}

			bgp_dest_unlock_node(dest);
		}
	}

	return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening,
       clear_ip_bgp_dampening_cmd,
       "clear ip bgp dampening",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n")
{
	bgp_damp_info_clean(AFI_IP, SAFI_UNICAST);
	return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening_prefix,
       clear_ip_bgp_dampening_prefix_cmd,
       "clear ip bgp dampening A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "IPv4 prefix\n")
{
	int idx_ipv4_prefixlen = 4;
	return bgp_clear_damp_route(vty, NULL, argv[idx_ipv4_prefixlen]->arg,
				    AFI_IP, SAFI_UNICAST, NULL, 1);
}

DEFUN (clear_ip_bgp_dampening_address,
       clear_ip_bgp_dampening_address_cmd,
       "clear ip bgp dampening A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n")
{
	int idx_ipv4 = 4;
	return bgp_clear_damp_route(vty, NULL, argv[idx_ipv4]->arg, AFI_IP,
				    SAFI_UNICAST, NULL, 0);
}

DEFUN (clear_ip_bgp_dampening_address_mask,
       clear_ip_bgp_dampening_address_mask_cmd,
       "clear ip bgp dampening A.B.C.D A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n"
       "Network mask\n")
{
	int idx_ipv4 = 4;
	int idx_ipv4_2 = 5;
	int ret;
	char prefix_str[BUFSIZ];

	ret = netmask_str2prefix_str(argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg,
				     prefix_str);
	if (!ret) {
		vty_out(vty, "%% Inconsistent address and mask\n");
		return CMD_WARNING;
	}

	return bgp_clear_damp_route(vty, NULL, prefix_str, AFI_IP, SAFI_UNICAST,
				    NULL, 0);
}

static void show_bgp_peerhash_entry(struct hash_bucket *bucket, void *arg)
{
       struct vty *vty = arg;
       struct peer *peer = bucket->data;
       char buf[SU_ADDRSTRLEN];

       vty_out(vty, "\tPeer: %s %s\n", peer->host,
	       sockunion2str(&peer->su, buf, sizeof(buf)));
}

DEFUN (show_bgp_listeners,
       show_bgp_listeners_cmd,
       "show bgp listeners",
       SHOW_STR
       BGP_STR
       "Display Listen Sockets and who created them\n")
{
	bgp_dump_listener_info(vty);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_peerhash,
       show_bgp_peerhash_cmd,
       "show bgp peerhash",
       SHOW_STR
       BGP_STR
       "Display information about the BGP peerhash\n")
{
       struct list *instances = bm->bgp;
       struct listnode *node;
       struct bgp *bgp;

       for (ALL_LIST_ELEMENTS_RO(instances, node, bgp)) {
               vty_out(vty, "BGP: %s\n", bgp->name);
               hash_iterate(bgp->peerhash, show_bgp_peerhash_entry,
                            vty);
       }

       return CMD_SUCCESS;
}

/* also used for encap safi */
static void bgp_config_write_network_vpn(struct vty *vty, struct bgp *bgp,
					 afi_t afi, safi_t safi)
{
	struct bgp_dest *pdest;
	struct bgp_dest *dest;
	struct bgp_table *table;
	const struct prefix *p;
	const struct prefix_rd *prd;
	struct bgp_static *bgp_static;
	mpls_label_t label;
	char rdbuf[RD_ADDRSTRLEN];

	/* Network configuration. */
	for (pdest = bgp_table_top(bgp->route[afi][safi]); pdest;
	     pdest = bgp_route_next(pdest)) {
		table = bgp_dest_get_bgp_table_info(pdest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			bgp_static = bgp_dest_get_bgp_static_info(dest);
			if (bgp_static == NULL)
				continue;

			p = bgp_dest_get_prefix(dest);
			prd = (const struct prefix_rd *)bgp_dest_get_prefix(
				pdest);

			/* "network" configuration display.  */
			prefix_rd2str(prd, rdbuf, sizeof(rdbuf));
			label = decode_label(&bgp_static->label);

			vty_out(vty, "  network %pFX rd %s", p, rdbuf);
			if (safi == SAFI_MPLS_VPN)
				vty_out(vty, " label %u", label);

			if (bgp_static->rmap.name)
				vty_out(vty, " route-map %s",
					bgp_static->rmap.name);

			if (bgp_static->backdoor)
				vty_out(vty, " backdoor");

			vty_out(vty, "\n");
		}
	}
}

static void bgp_config_write_network_evpn(struct vty *vty, struct bgp *bgp,
					  afi_t afi, safi_t safi)
{
	struct bgp_dest *pdest;
	struct bgp_dest *dest;
	struct bgp_table *table;
	const struct prefix *p;
	const struct prefix_rd *prd;
	struct bgp_static *bgp_static;
	char buf[PREFIX_STRLEN * 2];
	char buf2[SU_ADDRSTRLEN];
	char rdbuf[RD_ADDRSTRLEN];
	char esi_buf[ESI_BYTES];

	/* Network configuration. */
	for (pdest = bgp_table_top(bgp->route[afi][safi]); pdest;
	     pdest = bgp_route_next(pdest)) {
		table = bgp_dest_get_bgp_table_info(pdest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			bgp_static = bgp_dest_get_bgp_static_info(dest);
			if (bgp_static == NULL)
				continue;

			char *macrouter = NULL;

			if (bgp_static->router_mac)
				macrouter = prefix_mac2str(
					bgp_static->router_mac, NULL, 0);
			if (bgp_static->eth_s_id)
				esi_to_str(bgp_static->eth_s_id,
						esi_buf, sizeof(esi_buf));
			p = bgp_dest_get_prefix(dest);
			prd = (struct prefix_rd *)bgp_dest_get_prefix(pdest);

			/* "network" configuration display.  */
			prefix_rd2str(prd, rdbuf, sizeof(rdbuf));
			if (p->u.prefix_evpn.route_type == 5) {
				char local_buf[PREFIX_STRLEN];
				uint8_t family = is_evpn_prefix_ipaddr_v4((
							 struct prefix_evpn *)p)
							 ? AF_INET
							 : AF_INET6;
				inet_ntop(family,
					  &p->u.prefix_evpn.prefix_addr.ip.ip.addr,
					  local_buf, PREFIX_STRLEN);
				snprintf(buf, sizeof(buf), "%s/%u", local_buf,
					 p->u.prefix_evpn.prefix_addr
						 .ip_prefix_length);
			} else {
				prefix2str(p, buf, sizeof(buf));
			}

			if (bgp_static->gatewayIp.family == AF_INET
			    || bgp_static->gatewayIp.family == AF_INET6)
				inet_ntop(bgp_static->gatewayIp.family,
					  &bgp_static->gatewayIp.u.prefix, buf2,
					  sizeof(buf2));
			vty_out(vty,
				"  network %s rd %s ethtag %u label %u esi %s gwip %s routermac %s\n",
				buf, rdbuf,
				p->u.prefix_evpn.prefix_addr.eth_tag,
				decode_label(&bgp_static->label), esi_buf, buf2,
				macrouter);

			XFREE(MTYPE_TMP, macrouter);
		}
	}
}

/* Configuration of static route announcement and aggregate
   information. */
void bgp_config_write_network(struct vty *vty, struct bgp *bgp, afi_t afi,
			      safi_t safi)
{
	struct bgp_dest *dest;
	const struct prefix *p;
	struct bgp_static *bgp_static;
	struct bgp_aggregate *bgp_aggregate;

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)) {
		bgp_config_write_network_vpn(vty, bgp, afi, safi);
		return;
	}

	if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
		bgp_config_write_network_evpn(vty, bgp, afi, safi);
		return;
	}

	/* Network configuration. */
	for (dest = bgp_table_top(bgp->route[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static == NULL)
			continue;

		p = bgp_dest_get_prefix(dest);

		vty_out(vty, "  network %pFX", p);

		if (bgp_static->label_index != BGP_INVALID_LABEL_INDEX)
			vty_out(vty, " label-index %u",
				bgp_static->label_index);

		if (bgp_static->rmap.name)
			vty_out(vty, " route-map %s", bgp_static->rmap.name);

		if (bgp_static->backdoor)
			vty_out(vty, " backdoor");

		vty_out(vty, "\n");
	}

	/* Aggregate-address configuration. */
	for (dest = bgp_table_top(bgp->aggregate[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		bgp_aggregate = bgp_dest_get_bgp_aggregate_info(dest);
		if (bgp_aggregate == NULL)
			continue;

		p = bgp_dest_get_prefix(dest);

		vty_out(vty, "  aggregate-address %pFX", p);

		if (bgp_aggregate->as_set)
			vty_out(vty, " as-set");

		if (bgp_aggregate->summary_only)
			vty_out(vty, " summary-only");

		if (bgp_aggregate->rmap.name)
			vty_out(vty, " route-map %s", bgp_aggregate->rmap.name);

		if (bgp_aggregate->origin != BGP_ORIGIN_UNSPECIFIED)
			vty_out(vty, " origin %s",
				bgp_origin2str(bgp_aggregate->origin));

		if (bgp_aggregate->match_med)
			vty_out(vty, " matching-MED-only");

		if (bgp_aggregate->suppress_map_name)
			vty_out(vty, " suppress-map %s",
				bgp_aggregate->suppress_map_name);

		vty_out(vty, "\n");
	}
}

void bgp_config_write_distance(struct vty *vty, struct bgp *bgp, afi_t afi,
			       safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_distance *bdistance;

	/* Distance configuration. */
	if (bgp->distance_ebgp[afi][safi] && bgp->distance_ibgp[afi][safi]
	    && bgp->distance_local[afi][safi]
	    && (bgp->distance_ebgp[afi][safi] != ZEBRA_EBGP_DISTANCE_DEFAULT
		|| bgp->distance_ibgp[afi][safi] != ZEBRA_IBGP_DISTANCE_DEFAULT
		|| bgp->distance_local[afi][safi]
			   != ZEBRA_IBGP_DISTANCE_DEFAULT)) {
		vty_out(vty, "  distance bgp %d %d %d\n",
			bgp->distance_ebgp[afi][safi],
			bgp->distance_ibgp[afi][safi],
			bgp->distance_local[afi][safi]);
	}

	for (dest = bgp_table_top(bgp_distance_table[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		bdistance = bgp_dest_get_bgp_distance_info(dest);
		if (bdistance != NULL)
			vty_out(vty, "  distance %d %pBD %s\n",
				bdistance->distance, dest,
				bdistance->access_list ? bdistance->access_list
						       : "");
	}
}

/* Allocate routing table structure and install commands. */
void bgp_route_init(void)
{
	afi_t afi;
	safi_t safi;

	/* Init BGP distance table. */
	FOREACH_AFI_SAFI (afi, safi)
		bgp_distance_table[afi][safi] = bgp_table_init(NULL, afi, safi);

	/* IPv4 BGP commands. */
	install_element(BGP_NODE, &bgp_table_map_cmd);
	install_element(BGP_NODE, &bgp_network_cmd);
	install_element(BGP_NODE, &no_bgp_table_map_cmd);

	install_element(BGP_NODE, &aggregate_addressv4_cmd);

	/* IPv4 unicast configuration.  */
	install_element(BGP_IPV4_NODE, &bgp_table_map_cmd);
	install_element(BGP_IPV4_NODE, &bgp_network_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_table_map_cmd);

	install_element(BGP_IPV4_NODE, &aggregate_addressv4_cmd);

	/* IPv4 multicast configuration.  */
	install_element(BGP_IPV4M_NODE, &bgp_table_map_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_network_cmd);
	install_element(BGP_IPV4M_NODE, &no_bgp_table_map_cmd);
	install_element(BGP_IPV4M_NODE, &aggregate_addressv4_cmd);

	/* IPv4 labeled-unicast configuration.  */
	install_element(BGP_IPV4L_NODE, &bgp_network_cmd);
	install_element(BGP_IPV4L_NODE, &aggregate_addressv4_cmd);

	install_element(VIEW_NODE, &show_ip_bgp_instance_all_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_afi_safi_statistics_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_statistics_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_json_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_route_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_regexp_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_statistics_all_cmd);

	install_element(VIEW_NODE,
			&show_ip_bgp_instance_neighbor_advertised_route_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_instance_neighbor_bestpath_route_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_neighbor_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_neighbor_received_prefix_filter_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_route_prefix_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(VIEW_NODE, &show_bgp_afi_vpn_rd_route_cmd);
	install_element(VIEW_NODE,
			&show_bgp_l2vpn_evpn_route_prefix_cmd);

	/* BGP dampening clear commands */
	install_element(ENABLE_NODE, &clear_ip_bgp_dampening_cmd);
	install_element(ENABLE_NODE, &clear_ip_bgp_dampening_prefix_cmd);

	install_element(ENABLE_NODE, &clear_ip_bgp_dampening_address_cmd);
	install_element(ENABLE_NODE, &clear_ip_bgp_dampening_address_mask_cmd);

	/* prefix count */
	install_element(ENABLE_NODE,
			&show_ip_bgp_instance_neighbor_prefix_counts_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(ENABLE_NODE,
			&show_ip_bgp_vpn_neighbor_prefix_counts_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */

	/* New config IPv6 BGP commands.  */
	install_element(BGP_IPV6_NODE, &bgp_table_map_cmd);
	install_element(BGP_IPV6_NODE, &ipv6_bgp_network_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_table_map_cmd);

	install_element(BGP_IPV6_NODE, &aggregate_addressv6_cmd);

	install_element(BGP_IPV6M_NODE, &ipv6_bgp_network_cmd);

	/* IPv6 labeled unicast address family. */
	install_element(BGP_IPV6L_NODE, &ipv6_bgp_network_cmd);
	install_element(BGP_IPV6L_NODE, &aggregate_addressv6_cmd);

	install_element(BGP_NODE, &bgp_distance_cmd);
	install_element(BGP_NODE, &no_bgp_distance_cmd);
	install_element(BGP_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV4M_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV6_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV6_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV6M_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_distance_source_cmd);

	/* BGP dampening */
	install_element(BGP_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV4_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV6_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_dampening_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_dampening_cmd);

	/* Large Communities */
	install_element(VIEW_NODE, &show_ip_bgp_large_community_list_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_large_community_cmd);

	/* show bgp ipv4 flowspec detailed */
	install_element(VIEW_NODE, &show_ip_bgp_flowspec_routes_detailed_cmd);

	install_element(VIEW_NODE, &show_bgp_listeners_cmd);
	install_element(VIEW_NODE, &show_bgp_peerhash_cmd);
}

void bgp_route_finish(void)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		bgp_table_unlock(bgp_distance_table[afi][safi]);
		bgp_distance_table[afi][safi] = NULL;
	}
}
