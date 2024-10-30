// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP routing information
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2016 Job Snijders <job@instituut.net>
 */

#include <zebra.h>
#include <math.h>

#include "printfrr.h"
#include "frrstr.h"
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
#include "frrevent.h"
#include "workqueue.h"
#include "queue.h"
#include "memory.h"
#include "srv6.h"
#include "lib/json.h"
#include "lib_errors.h"
#include "zclient.h"
#include "frrdistance.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_community_alias.h"
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
#include "bgpd/bgp_rpki.h"

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

#include "bgpd/bgp_route_clippy.c"

DEFINE_HOOK(bgp_snmp_update_stats,
	    (struct bgp_dest *rn, struct bgp_path_info *pi, bool added),
	    (rn, pi, added));

DEFINE_HOOK(bgp_rpki_prefix_status,
	    (struct peer *peer, struct attr *attr,
	     const struct prefix *prefix),
	    (peer, attr, prefix));

DEFINE_HOOK(bgp_route_update,
	    (struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
	     struct bgp_path_info *old_route, struct bgp_path_info *new_route),
	    (bgp, afi, safi, bn, old_route, new_route));

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
#define SOFT_RECONFIG_TASK_MAX_PREFIX 25000

static inline char *bgp_route_dump_path_info_flags(struct bgp_path_info *pi,
						   char *buf, size_t len)
{
	uint32_t flags = pi->flags;

	if (flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(buf, len, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
		   CHECK_FLAG(flags, BGP_PATH_IGP_CHANGED) ? "IGP Changed " : "",
		   CHECK_FLAG(flags, BGP_PATH_DAMPED) ? "Damped" : "",
		   CHECK_FLAG(flags, BGP_PATH_HISTORY) ? "History " : "",
		   CHECK_FLAG(flags, BGP_PATH_SELECTED) ? "Selected " : "",
		   CHECK_FLAG(flags, BGP_PATH_VALID) ? "Valid " : "",
		   CHECK_FLAG(flags, BGP_PATH_ATTR_CHANGED) ? "Attr Changed "
							    : "",
		   CHECK_FLAG(flags, BGP_PATH_DMED_CHECK) ? "Dmed Check " : "",
		   CHECK_FLAG(flags, BGP_PATH_DMED_SELECTED) ? "Dmed Selected "
							     : "",
		   CHECK_FLAG(flags, BGP_PATH_STALE) ? "Stale " : "",
		   CHECK_FLAG(flags, BGP_PATH_REMOVED) ? "Removed " : "",
		   CHECK_FLAG(flags, BGP_PATH_COUNTED) ? "Counted " : "",
		   CHECK_FLAG(flags, BGP_PATH_MULTIPATH) ? "Mpath " : "",
		   CHECK_FLAG(flags, BGP_PATH_MULTIPATH_CHG) ? "Mpath Chg " : "",
		   CHECK_FLAG(flags, BGP_PATH_RIB_ATTR_CHG) ? "Rib Chg " : "",
		   CHECK_FLAG(flags, BGP_PATH_ANNC_NH_SELF) ? "NH Self " : "",
		   CHECK_FLAG(flags, BGP_PATH_LINK_BW_CHG) ? "LinkBW Chg " : "",
		   CHECK_FLAG(flags, BGP_PATH_ACCEPT_OWN) ? "Accept Own " : "",
		   CHECK_FLAG(flags, BGP_PATH_MPLSVPN_LABEL_NH) ? "MPLS Label "
								: "",
		   CHECK_FLAG(flags, BGP_PATH_MPLSVPN_NH_LABEL_BIND)
			   ? "MPLS Label Bind "
			   : "",
		   CHECK_FLAG(flags, BGP_PATH_UNSORTED) ? "Unsorted " : "");

	return buf;
}

DEFINE_HOOK(bgp_process,
	    (struct bgp * bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
	     struct peer *peer, bool withdraw),
	    (bgp, afi, safi, bn, peer, withdraw));

/** Test if path is suppressed. */
bool bgp_path_suppressed(struct bgp_path_info *pi)
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
			pdest = bgp_dest_unlock_node(pdest);

		assert(pdest);
		table = bgp_dest_get_bgp_table_info(pdest);
	}

	dest = bgp_node_get(table, p);

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN))
		dest->pdest = pdest;

	return dest;
}

struct bgp_dest *bgp_safi_node_lookup(struct bgp_table *table, safi_t safi,
				      const struct prefix *p,
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
	new->flowspec = NULL;
	return new;
}

void bgp_path_info_extra_free(struct bgp_path_info_extra **extra)
{
	struct bgp_path_info_extra *e;

	if (!extra || !*extra)
		return;

	e = *extra;

	if (e->damp_info)
		bgp_damp_info_free(e->damp_info, NULL, 0);
	e->damp_info = NULL;
	if (e->vrfleak && e->vrfleak->parent) {
		struct bgp_path_info *bpi =
			(struct bgp_path_info *)e->vrfleak->parent;

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
		bgp_path_info_unlock(e->vrfleak->parent);
		e->vrfleak->parent = NULL;
	}

	if (e->vrfleak && e->vrfleak->bgp_orig)
		bgp_unlock(e->vrfleak->bgp_orig);

	if (e->vrfleak && e->vrfleak->peer_orig)
		peer_unlock(e->vrfleak->peer_orig);

	if (e->aggr_suppressors)
		list_delete(&e->aggr_suppressors);

	if (e->evpn && e->evpn->mh_info)
		bgp_evpn_path_mh_info_free(e->evpn->mh_info);

	if ((*extra)->flowspec && (*extra)->flowspec->bgp_fs_iprule)
		list_delete(&((*extra)->flowspec->bgp_fs_iprule));
	if ((*extra)->flowspec && (*extra)->flowspec->bgp_fs_pbr)
		list_delete(&((*extra)->flowspec->bgp_fs_pbr));

	if (e->evpn)
		XFREE(MTYPE_BGP_ROUTE_EXTRA_EVPN, e->evpn);
	if (e->flowspec)
		XFREE(MTYPE_BGP_ROUTE_EXTRA_FS, e->flowspec);
	if (e->vrfleak)
		XFREE(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK, e->vrfleak);
#ifdef ENABLE_BGP_VNC
	if (e->vnc)
		XFREE(MTYPE_BGP_ROUTE_EXTRA_VNC, e->vnc);
#endif

	if (e->labels)
		bgp_labels_unintern(&e->labels);

	XFREE(MTYPE_BGP_ROUTE_EXTRA, *extra);
}

/* Get bgp_path_info extra information for the given bgp_path_info, lazy
 * allocated if required.
 */
struct bgp_path_info_extra *bgp_path_info_extra_get(struct bgp_path_info *pi)
{
	if (!pi->extra)
		pi->extra = bgp_path_info_extra_new();
	if (!pi->extra->evpn && pi->net && pi->net->rn->p.family == AF_EVPN)
		pi->extra->evpn =
			XCALLOC(MTYPE_BGP_ROUTE_EXTRA_EVPN,
				sizeof(struct bgp_path_info_extra_evpn));
	return pi->extra;
}

bool bgp_path_info_has_valid_label(const struct bgp_path_info *path)
{
	if (!BGP_PATH_INFO_NUM_LABELS(path))
		return false;

	return bgp_is_valid_label(&path->extra->labels->label[0]);
}

bool bgp_path_info_labels_same(const struct bgp_path_info *bpi,
			       const mpls_label_t *label, uint32_t n)
{
	uint8_t bpi_num_labels;
	const mpls_label_t *bpi_label;

	bpi_num_labels = BGP_PATH_INFO_NUM_LABELS(bpi);
	bpi_label = bpi_num_labels ? bpi->extra->labels->label : NULL;

	return bgp_labels_same(bpi_label, bpi_num_labels,
			       (const mpls_label_t *)label, n);
}

/* Free bgp route information. */
void bgp_path_info_free_with_caller(const char *name,
				    struct bgp_path_info *path)
{
	frrtrace(2, frr_bgp, bgp_path_info_free, path, name);
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
		bgp_path_info_free(path);
		return NULL;
	}

	return path;
}

bool bgp_path_info_nexthop_changed(struct bgp_path_info *pi, struct peer *to,
				   afi_t afi)
{
	if (pi->peer->sort == BGP_PEER_IBGP && to->sort == BGP_PEER_IBGP &&
	    !CHECK_FLAG(to->af_flags[afi][SAFI_MPLS_VPN],
			PEER_FLAG_FORCE_NEXTHOP_SELF))
		/* IBGP RR with no nexthop self force configured */
		return false;

	if (to->sort == BGP_PEER_IBGP &&
	    !CHECK_FLAG(to->af_flags[afi][SAFI_MPLS_VPN],
			PEER_FLAG_NEXTHOP_SELF))
		/* IBGP RR with no nexthop self configured */
		return false;

	if (CHECK_FLAG(to->af_flags[afi][SAFI_MPLS_VPN],
		       PEER_FLAG_NEXTHOP_UNCHANGED))
		/* IBGP or EBGP with nexthop attribute unchanged */
		return false;

	return true;
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
		if (BGP_DEBUG(update, UPDATE_OUT)) {
			table = bgp_dest_table(dest);
			if (table)
				bgp = table->bgp;

			zlog_debug(
				"Route %pBD(%s) is in workqueue and being processed, not deferred.",
				dest, bgp ? bgp->name_pretty : "(Unknown)");
		}

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
				zlog_debug("DEFER route %pBD(%s), dest %p",
					   dest, bgp->name_pretty, dest);
			return 0;
		}
	}
	return -1;
}

void bgp_path_info_add_with_caller(const char *name, struct bgp_dest *dest,
				   struct bgp_path_info *pi)
{
	frrtrace(3, frr_bgp, bgp_path_info_add, dest, pi, name);
	struct bgp_path_info *top;

	top = bgp_dest_get_bgp_path_info(dest);

	pi->next = top;
	pi->prev = NULL;
	if (top)
		top->prev = pi;
	bgp_dest_set_bgp_path_info(dest, pi);

	SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
	bgp_path_info_lock(pi);
	bgp_dest_lock_node(dest);
	peer_lock(pi->peer); /* bgp_path_info peer reference */
	bgp_dest_set_defer_flag(dest, false);
	if (pi->peer)
		pi->peer->stat_pfx_loc_rib++;
	hook_call(bgp_snmp_update_stats, dest, pi, true);
}

/* Do the actual removal of info from RIB, for use by bgp_process
   completion callback *only* */
struct bgp_dest *bgp_path_info_reap(struct bgp_dest *dest,
				    struct bgp_path_info *pi)
{
	if (pi->next)
		pi->next->prev = pi->prev;
	if (pi->prev)
		pi->prev->next = pi->next;
	else
		bgp_dest_set_bgp_path_info(dest, pi->next);

	pi->next = NULL;
	pi->prev = NULL;

	if (pi->peer)
		pi->peer->stat_pfx_loc_rib--;
	hook_call(bgp_snmp_update_stats, dest, pi, false);

	bgp_path_info_unlock(pi);
	return bgp_dest_unlock_node(dest);
}

static struct bgp_dest *bgp_path_info_reap_unsorted(struct bgp_dest *dest,
						    struct bgp_path_info *pi)
{
	pi->next = NULL;
	pi->prev = NULL;

	if (pi->peer)
		pi->peer->stat_pfx_loc_rib--;
	hook_call(bgp_snmp_update_stats, dest, pi, false);
	bgp_path_info_unlock(pi);

	return bgp_dest_unlock_node(dest);
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

static bool use_bgp_med_value(struct attr *attr, struct bgp *bgp)
{
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC) ||
	    CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
		return true;

	return false;
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
static uint32_t bgp_med_value(struct attr *attr, struct bgp *bgp)
{
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
		return attr->med;
	else {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
			return BGP_MED_MAX;
		else
			return 0;
	}
}

void bgp_path_info_path_with_addpath_rx_str(struct bgp_path_info *pi, char *buf,
					    size_t buf_len)
{
	struct peer *peer;

	if (!pi) {
		snprintf(buf, buf_len, "NONE");
		return;
	}

	if (pi->sub_type == BGP_ROUTE_IMPORTED &&
	    bgp_get_imported_bpi_ultimate(pi))
		peer = bgp_get_imported_bpi_ultimate(pi)->peer;
	else
		peer = pi->peer;

	if (pi->addpath_rx_id)
		snprintf(buf, buf_len, "path %s (addpath rxid %d)", peer->host,
			 pi->addpath_rx_id);
	else
		snprintf(buf, buf_len, "path %s", peer->host);
}


/*
 * Get the ultimate path info.
 */
struct bgp_path_info *bgp_get_imported_bpi_ultimate(struct bgp_path_info *info)
{
	struct bgp_path_info *bpi_ultimate;

	if (info->sub_type != BGP_ROUTE_IMPORTED)
		return info;

	for (bpi_ultimate = info;
	     bpi_ultimate->extra && bpi_ultimate->extra->vrfleak &&
	     bpi_ultimate->extra->vrfleak->parent;
	     bpi_ultimate = bpi_ultimate->extra->vrfleak->parent)
		;

	return bpi_ultimate;
}

/* Compare two bgp route entity.  If 'new' is preferable over 'exist' return 1.
 */
int bgp_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
		      struct bgp_path_info *exist, int *paths_eq,
		      struct bgp_maxpaths_cfg *mpath_cfg, bool debug,
		      char *pfx_buf, afi_t afi, safi_t safi,
		      enum bgp_path_selection_reason *reason)
{
	const struct prefix *new_p;
	struct attr *newattr, *existattr;
	enum bgp_peer_sort new_sort;
	enum bgp_peer_sort exist_sort;
	enum bgp_peer_sub_sort new_sub_sort;
	enum bgp_peer_sub_sort exist_sub_sort;
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
	int igp_metric_ret = 0;
	int peer_sort_ret = -1;
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
	struct bgp_path_info *bpi_ultimate;
	struct peer *peer_new, *peer_exist;

	bgp->bestpath_runs++;

	*paths_eq = 0;

	/* 0. Null check. */
	if (new == NULL) {
		*reason = bgp_path_selection_none;
		if (debug)
			zlog_debug("%s: new is NULL", pfx_buf);
		return 0;
	}

	if (debug) {
		bpi_ultimate = bgp_get_imported_bpi_ultimate(new);
		bgp_path_info_path_with_addpath_rx_str(bpi_ultimate, new_buf,
						       sizeof(new_buf));
	}

	if (exist == NULL) {
		*reason = bgp_path_selection_first;
		if (debug)
			zlog_debug("%s(%s): %s is the initial bestpath",
				   pfx_buf, bgp->name_pretty, new_buf);
		return 1;
	}

	if (debug) {
		char buf1[256], buf2[256];

		bpi_ultimate = bgp_get_imported_bpi_ultimate(exist);
		bgp_path_info_path_with_addpath_rx_str(bpi_ultimate, exist_buf,
						       sizeof(exist_buf));
		zlog_debug("%s(%s): Comparing %s flags %s with %s flags %s",
			   pfx_buf, bgp->name_pretty, new_buf,
			   bgp_route_dump_path_info_flags(new, buf1,
							  sizeof(buf1)),
			   exist_buf,
			   bgp_route_dump_path_info_flags(exist, buf2,
							  sizeof(buf2)));
	}

	newattr = new->attr;
	existattr = exist->attr;

	/* A BGP speaker that has advertised the "Long-lived Graceful Restart
	 * Capability" to a neighbor MUST perform the following upon receiving
	 * a route from that neighbor with the "LLGR_STALE" community, or upon
	 * attaching the "LLGR_STALE" community itself per Section 4.2:
	 *
	 * Treat the route as the least-preferred in route selection (see
	 * below). See the Risks of Depreferencing Routes section (Section 5.2)
	 * for a discussion of potential risks inherent in doing this.
	 */
	if (bgp_attr_get_community(newattr) &&
	    community_include(bgp_attr_get_community(newattr),
			      COMMUNITY_LLGR_STALE)) {
		if (debug)
			zlog_debug(
				"%s: %s wins over %s due to LLGR_STALE community",
				pfx_buf, new_buf, exist_buf);
		return 0;
	}

	if (bgp_attr_get_community(existattr) &&
	    community_include(bgp_attr_get_community(existattr),
			      COMMUNITY_LLGR_STALE)) {
		if (debug)
			zlog_debug(
				"%s: %s loses to %s due to LLGR_STALE community",
				pfx_buf, new_buf, exist_buf);
		return 1;
	}

	new_p = bgp_dest_get_prefix(new->net);

	/* For EVPN routes, we cannot just go by local vs remote, we have to
	 * look at the MAC mobility sequence number, if present.
	 */
	if ((safi == SAFI_EVPN)
	    && (new_p->u.prefix_evpn.route_type == BGP_EVPN_MAC_IP_ROUTE)) {
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
		bool new_sticky = CHECK_FLAG(newattr->evpn_flags,
					     ATTR_EVPN_FLAG_STICKY);
		bool exist_sticky = CHECK_FLAG(existattr->evpn_flags,
					       ATTR_EVPN_FLAG_STICKY);

		if (new_sticky != exist_sticky) {
			if (new_sticky && !exist_sticky) {
				*reason = bgp_path_selection_evpn_sticky_mac;
				if (debug)
					zlog_debug(
						"%s: %s wins over %s due to sticky MAC flag",
						pfx_buf, new_buf, exist_buf);
				return 1;
			}

			if (!new_sticky && exist_sticky) {
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

	if (CHECK_FLAG(newattr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		new_pref = newattr->local_pref;
	if (CHECK_FLAG(existattr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
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

	/* If a BGP speaker supports ACCEPT_OWN and is configured for the
	 * extensions defined in this document, the following step is inserted
	 * after the LOCAL_PREF comparison step in the BGP decision process:
	 *	When comparing a pair of routes for a BGP destination, the
	 *	route with the ACCEPT_OWN community attached is preferred over
	 *	the route that does not have the community.
	 * This extra step MUST only be invoked during the best path selection
	 * process of VPN-IP routes.
	 */
	if (safi == SAFI_MPLS_VPN &&
	    (CHECK_FLAG(new->peer->af_flags[afi][safi], PEER_FLAG_ACCEPT_OWN) ||
	     CHECK_FLAG(exist->peer->af_flags[afi][safi],
			PEER_FLAG_ACCEPT_OWN))) {
		bool new_accept_own = false;
		bool exist_accept_own = false;
		uint32_t accept_own = COMMUNITY_ACCEPT_OWN;

		if (CHECK_FLAG(newattr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)))
			new_accept_own = community_include(
				bgp_attr_get_community(newattr), accept_own);
		if (CHECK_FLAG(existattr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)))
			exist_accept_own = community_include(
				bgp_attr_get_community(existattr), accept_own);

		if (new_accept_own && !exist_accept_own) {
			*reason = bgp_path_selection_accept_own;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to accept-own",
					pfx_buf, new_buf, exist_buf);
			return 1;
		}

		if (!new_accept_own && exist_accept_own) {
			*reason = bgp_path_selection_accept_own;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to accept-own",
					pfx_buf, new_buf, exist_buf);
			return 0;
		}
	}

	/* 3. Local route check. We prefer:
	 *  - BGP_ROUTE_STATIC
	 *  - BGP_ROUTE_AGGREGATE
	 *  - BGP_ROUTE_REDISTRIBUTE
	 */
	new_origin = !(new->sub_type == BGP_ROUTE_NORMAL || new->sub_type == BGP_ROUTE_IMPORTED);
	exist_origin = !(exist->sub_type == BGP_ROUTE_NORMAL ||
			 exist->sub_type == BGP_ROUTE_IMPORTED);

	if (new_origin && !exist_origin) {
		*reason = bgp_path_selection_local_route;
		if (debug)
			zlog_debug("%s: %s wins over %s due to preferred BGP_ROUTE type", pfx_buf,
				   new_buf, exist_buf);
		return 1;
	}

	if (!new_origin && exist_origin) {
		*reason = bgp_path_selection_local_route;
		if (debug)
			zlog_debug("%s: %s loses to %s due to preferred BGP_ROUTE type", pfx_buf,
				   new_buf, exist_buf);
		return 0;
	}

	/* 3.5. Tie-breaker - AIGP (Metric TLV) attribute */
	if (CHECK_FLAG(newattr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)) &&
	    CHECK_FLAG(existattr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)) &&
	    CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP)) {
		uint64_t new_aigp = bgp_aigp_metric_total(new);
		uint64_t exist_aigp = bgp_aigp_metric_total(exist);

		if (new_aigp < exist_aigp) {
			*reason = bgp_path_selection_aigp;
			if (debug)
				zlog_debug(
					"%s: %s wins over %s due to AIGP %" PRIu64
					" < %" PRIu64,
					pfx_buf, new_buf, exist_buf, new_aigp,
					exist_aigp);
			return 1;
		}

		if (new_aigp > exist_aigp) {
			*reason = bgp_path_selection_aigp;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to AIGP %" PRIu64
					" > %" PRIu64,
					pfx_buf, new_buf, exist_buf, new_aigp,
					exist_aigp);
			return 0;
		}
	}

	/* Here if these are imported routes then get ultimate pi for
	 * path compare.
	 */
	new = bgp_get_imported_bpi_ultimate(new);
	exist = bgp_get_imported_bpi_ultimate(exist);
	newattr = new->attr;
	existattr = exist->attr;

	/* 4. AS path length check. */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE)) {
		int exist_hops = aspath_count_hops(existattr->aspath);

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED)) {
			int exist_confeds = aspath_count_confeds(existattr->aspath);
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

	if (exist->sub_type == BGP_ROUTE_IMPORTED) {
		bpi_ultimate = bgp_get_imported_bpi_ultimate(exist);
		peer_exist = bpi_ultimate->peer;
	} else
		peer_exist = exist->peer;

	if (new->sub_type == BGP_ROUTE_IMPORTED) {
		bpi_ultimate = bgp_get_imported_bpi_ultimate(new);
		peer_new = bpi_ultimate->peer;
	} else
		peer_new = new->peer;

	/* 7. Peer type check. */
	new_sort = peer_new->sort;
	exist_sort = peer_exist->sort;
	new_sub_sort = peer_new->sub_sort;
	exist_sub_sort = peer_exist->sub_sort;

	if (new_sort == BGP_PEER_EBGP &&
	    (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED ||
	     exist_sub_sort == BGP_PEER_EBGP_OAD)) {
		*reason = bgp_path_selection_peer;
		if (debug)
			zlog_debug("%s: %s wins over %s due to eBGP peer > %s peer",
				   pfx_buf, new_buf, exist_buf,
				   (exist_sub_sort == BGP_PEER_EBGP_OAD)
					   ? "eBGP-OAD"
					   : "iBGP");
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
			return 1;
		peer_sort_ret = 1;
	}

	if (exist_sort == BGP_PEER_EBGP &&
	    (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED ||
	     new_sub_sort == BGP_PEER_EBGP_OAD)) {
		*reason = bgp_path_selection_peer;
		if (debug)
			zlog_debug("%s: %s loses to %s due to %s peer < eBGP peer",
				   pfx_buf, new_buf, exist_buf,
				   (exist_sub_sort == BGP_PEER_EBGP_OAD)
					   ? "eBGP-OAD"
					   : "iBGP");
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
			return 0;
		peer_sort_ret = 0;
	}

	/* 8. IGP metric check. */
	newm = existm = 0;

	if (new->extra)
		newm = new->extra->igpmetric;
	if (exist->extra)
		existm = exist->extra->igpmetric;

	if (newm < existm) {
		if (debug && peer_sort_ret < 0)
			zlog_debug(
				"%s: %s wins over %s due to IGP metric %u < %u",
				pfx_buf, new_buf, exist_buf, newm, existm);
		igp_metric_ret = 1;
	}

	if (newm > existm) {
		if (debug && peer_sort_ret < 0)
			zlog_debug(
				"%s: %s loses to %s due to IGP metric %u > %u",
				pfx_buf, new_buf, exist_buf, newm, existm);
		igp_metric_ret = 0;
	}

	/* 9. Same IGP metric. Compare the cluster list length as
	   representative of IGP hops metric. Rewrite the metric value
	   pair (newm, existm) with the cluster list length. Prefer the
	   path with smaller cluster list length.                       */
	if (newm == existm) {
		if (peer_sort_lookup(peer_new) == BGP_PEER_IBGP &&
		    peer_sort_lookup(peer_exist) == BGP_PEER_IBGP &&
		    (mpath_cfg == NULL || mpath_cfg->same_clusterlen)) {
			newm = BGP_CLUSTER_LIST_LENGTH(new->attr);
			existm = BGP_CLUSTER_LIST_LENGTH(exist->attr);

			if (newm < existm) {
				if (debug && peer_sort_ret < 0)
					zlog_debug(
						"%s: %s wins over %s due to CLUSTER_LIST length %u < %u",
						pfx_buf, new_buf, exist_buf,
						newm, existm);
				igp_metric_ret = 1;
			}

			if (newm > existm) {
				if (debug && peer_sort_ret < 0)
					zlog_debug(
						"%s: %s loses to %s due to CLUSTER_LIST length %u > %u",
						pfx_buf, new_buf, exist_buf,
						newm, existm);
				igp_metric_ret = 0;
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
			if (!CHECK_FLAG(bgp->flags,
					BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
				return 1;
			peer_sort_ret = 1;
		}

		if (exist_sort == BGP_PEER_CONFED
		    && new_sort == BGP_PEER_IBGP) {
			*reason = bgp_path_selection_confed;
			if (debug)
				zlog_debug(
					"%s: %s loses to %s due to confed-internal peer < confed-external peer",
					pfx_buf, new_buf, exist_buf);
			if (!CHECK_FLAG(bgp->flags,
					BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
				return 0;
			peer_sort_ret = 0;
		}
	}

	/* 11. Maximum path check. */
	if (newm == existm) {
		/* If one path has a label but the other does not, do not treat
		 * them as equals for multipath
		 */
		bool new_label_valid, exist_label_valid;

		new_label_valid = bgp_path_info_has_valid_label(new);
		exist_label_valid = bgp_path_info_has_valid_label(exist);

		if (new_label_valid != exist_label_valid) {
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
		} else if (peer_new->sort == BGP_PEER_IBGP) {
			if (aspath_cmp(new->attr->aspath,
				       exist->attr->aspath)) {
				*paths_eq = 1;

				if (debug)
					zlog_debug(
						"%s: %s and %s are equal via matching aspaths",
						pfx_buf, new_buf, exist_buf);
			}
		} else if (peer_new->as == peer_exist->as) {
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

		/* Prior to the addition of BGP_FLAG_PEERTYPE_MULTIPATH_RELAX,
		 * if either step 7 or 10 (peer type checks) yielded a winner,
		 * that result was returned immediately. Returning from step 10
		 * ignored the return value computed in steps 8 and 9 (IGP
		 * metric checks). In order to preserve that behavior, if
		 * peer_sort_ret is set, return that rather than igp_metric_ret.
		 */
		ret = peer_sort_ret;
		if (peer_sort_ret < 0) {
			ret = igp_metric_ret;
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
		}
		return ret;
	}

	/*
	 * At this point, the decision whether to set *paths_eq = 1 has been
	 * completed. If we deferred returning because of bestpath peer-type
	 * relax configuration, return now.
	 */
	if (peer_sort_ret >= 0)
		return peer_sort_ret;

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

	/* 13. Router-ID comparison. */
	/* If one of the paths is "stale", the corresponding peer router-id will
	 * be 0 and would always win over the other path. If originator id is
	 * used for the comparison, it will decide which path is better.
	 */
	if (CHECK_FLAG(newattr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
		new_id.s_addr = newattr->originator_id.s_addr;
	else
		new_id.s_addr = peer_new->remote_id.s_addr;
	if (CHECK_FLAG(existattr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
		exist_id.s_addr = existattr->originator_id.s_addr;
	else
		exist_id.s_addr = peer_exist->remote_id.s_addr;

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

	/* 14. Cluster length comparison. */
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

	/* 15. Neighbor address comparison. */
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
	if (peer_new->su_remote == NULL) {
		*reason = bgp_path_selection_local_configured;
		return 0;
	}

	if (peer_exist->su_remote == NULL) {
		*reason = bgp_path_selection_local_configured;
		return 1;
	}

	ret = sockunion_cmp(peer_new->su_remote, peer_exist->su_remote);

	if (ret == 1) {
		*reason = bgp_path_selection_neighbor_ip;
		if (debug)
			zlog_debug("%s: %s loses to %s due to Neighbor IP comparison",
				   pfx_buf, new_buf, exist_buf);
		return 0;
	}

	if (ret == -1) {
		*reason = bgp_path_selection_neighbor_ip;
		if (debug)
			zlog_debug("%s: %s wins over %s due to Neighbor IP comparison",
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
			   struct bgp_path_info *exist, int *paths_eq,
			   bool debug)
{
	enum bgp_path_selection_reason reason;
	char pfx_buf[PREFIX2STR_BUFFER] = {};

	if (debug)
		prefix2str(bgp_dest_get_prefix(new->net), pfx_buf,
			   sizeof(pfx_buf));

	return bgp_path_info_cmp(bgp, new, exist, paths_eq, NULL, debug,
				 pfx_buf, AFI_L2VPN, SAFI_EVPN, &reason);
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
	bool debug = false;

	ret = bgp_path_info_cmp(bgp, new, exist, &paths_eq, NULL, debug,
				pfx_buf, afi, safi, reason);

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
	if (bgp_attr_get_community(attr)) {
		/* NO_ADVERTISE check. */
		if (community_include(bgp_attr_get_community(attr),
				      COMMUNITY_NO_ADVERTISE))
			return true;

		/* NO_EXPORT check. */
		if (peer->sort == BGP_PEER_EBGP && peer->sub_sort != BGP_PEER_EBGP_OAD &&
		    community_include(bgp_attr_get_community(attr), COMMUNITY_NO_EXPORT))
			return true;

		/* NO_EXPORT_SUBCONFED check. */
		if ((peer->sort == BGP_PEER_EBGP && peer->sub_sort != BGP_PEER_EBGP_OAD) ||
		    peer->sort == BGP_PEER_CONFED)
			if (community_include(bgp_attr_get_community(attr),
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
		if (CHECK_FLAG(peer->bgp->config, BGP_CONFIG_CLUSTER_ID))
			cluster_id = peer->bgp->cluster_id;
		else
			cluster_id = peer->bgp->router_id;

		if (cluster_loop_check(cluster, cluster_id))
			return true;
	}
	return false;
}

static bool bgp_otc_filter(struct peer *peer, struct attr *attr)
{
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC))) {
		if (peer->local_role == ROLE_PROVIDER ||
		    peer->local_role == ROLE_RS_SERVER)
			return true;
		if (peer->local_role == ROLE_PEER && attr->otc != peer->as)
			return true;
		return false;
	}
	if (peer->local_role == ROLE_CUSTOMER ||
	    peer->local_role == ROLE_PEER ||
	    peer->local_role == ROLE_RS_CLIENT) {
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC));
		attr->otc = peer->as;
	}
	return false;
}

static bool bgp_otc_egress(struct peer *peer, struct attr *attr)
{
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC))) {
		if (peer->local_role == ROLE_CUSTOMER ||
		    peer->local_role == ROLE_RS_CLIENT ||
		    peer->local_role == ROLE_PEER)
			return true;
		return false;
	}
	if (peer->local_role == ROLE_PROVIDER ||
	    peer->local_role == ROLE_PEER ||
	    peer->local_role == ROLE_RS_SERVER) {
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC));
		attr->otc = peer->bgp->as;
	}
	return false;
}

static bool bgp_check_role_applicability(afi_t afi, safi_t safi)
{
	return ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST);
}

static int bgp_input_modifier(struct peer *peer, const struct prefix *p,
			      struct attr *attr, afi_t afi, safi_t safi,
			      const char *rmap_name, mpls_label_t *label,
			      uint8_t num_labels, struct bgp_dest *dest)
{
	struct bgp_filter *filter;
	struct bgp_path_info rmap_path = { 0 };
	struct bgp_path_info_extra extra = { 0 };
	struct bgp_labels bgp_labels = {};
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
		memset(&rmap_path, 0, sizeof(rmap_path));
		/* Duplicate current value to new structure for modification. */
		rmap_path.peer = peer;
		rmap_path.attr = attr;
		rmap_path.extra = &extra;
		rmap_path.net = dest;
		extra.labels = &bgp_labels;

		bgp_labels.num_labels = num_labels;
		if (label && num_labels && num_labels <= BGP_MAX_LABELS)
			memcpy(bgp_labels.label, label,
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

	memset(&rmap_path, 0, sizeof(rmap_path));
	/* Route map apply. */
	/* Duplicate current value to new structure for modification. */
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

			/*
			 * Even if the aspath consists of just private ASNs we
			 * need to walk the AS-Path to maintain all instances
			 * of the peer's ASN to break possible loops.
			 */
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
				/*
				 * Walk the aspath to retain any instances of
				 * the peer_asn
				 */
				attr->aspath = aspath_remove_private_asns(
					attr->aspath, peer->as);
		}
	}
}

/* If this is an EBGP peer with as-override */
static void bgp_peer_as_override(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct peer *peer, struct attr *attr)
{
	struct aspath *aspath;

	if (peer->sort == BGP_PEER_EBGP &&
	    peer_af_flag_check(peer, afi, safi, PEER_FLAG_AS_OVERRIDE)) {
		if (attr->aspath->refcnt)
			aspath = aspath_dup(attr->aspath);
		else
			aspath = attr->aspath;

		attr->aspath = aspath_intern(
			aspath_replace_specific_asn(aspath, peer->as, bgp->as));

		aspath_free(aspath);
	}
}

void bgp_attr_add_llgr_community(struct attr *attr)
{
	struct community *old;
	struct community *new;
	struct community *merge;
	struct community *llgr;

	old = bgp_attr_get_community(attr);
	llgr = community_str2com("llgr-stale");

	assert(llgr);

	if (old) {
		merge = community_merge(community_dup(old), llgr);

		if (old->refcnt == 0)
			community_free(&old);

		new = community_uniq_sort(merge);
		community_free(&merge);
	} else {
		new = community_dup(llgr);
	}

	community_free(&llgr);

	bgp_attr_set_community(attr, new);
}

void bgp_attr_add_gshut_community(struct attr *attr)
{
	struct community *old;
	struct community *new;
	struct community *merge;
	struct community *gshut;

	old = bgp_attr_get_community(attr);
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
	bgp_attr_set_community(attr, new);

	/* When we add the graceful-shutdown community we must also
	 * lower the local-preference */
	SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
	attr->local_pref = BGP_GSHUT_LOCAL_PREF;
}


/* Notify BGP Conditional advertisement scanner process. */
void bgp_notify_conditional_adv_scanner(struct update_subgroup *subgrp)
{
	struct peer *peer = SUBGRP_PEER(subgrp);
	afi_t afi = SUBGRP_AFI(subgrp);
	safi_t safi = SUBGRP_SAFI(subgrp);
	struct bgp_filter *filter = &peer->filter[afi][safi];

	if (!ADVERTISE_MAP_NAME(filter))
		return;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
		return;

	peer->advmap_table_change = true;
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
			     struct attr *post_attr)
{
	struct bgp_filter *filter;
	struct peer *from;
	struct peer *peer;
	struct peer *onlypeer;
	struct bgp *bgp;
	struct attr *piattr;
	route_map_result_t ret;
	int transparent;
	int ibgp_to_ibgp;
	afi_t afi;
	safi_t safi;
	int samepeer_safe = 0; /* for synthetic mplsvpns routes */
	bool nh_reset = false;
	uint64_t cum_bw;
	mpls_label_t label;
	bool global_and_ll = false;

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
	piattr = bgp_path_info_mpath_count(pi) > 1 ? bgp_path_info_mpath_attr(pi) : pi->attr;

	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT) &&
	    peer->pmax_out[afi][safi] != 0 &&
	    subgrp->pscount >= peer->pmax_out[afi][safi]) {
		if (BGP_DEBUG(update, UPDATE_OUT) ||
		    BGP_DEBUG(update, UPDATE_PREFIX)) {
			zlog_debug("%s reached maximum prefix to be send (%u)",
				   peer->host, peer->pmax_out[afi][safi]);
		}
		return false;
	}

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
	if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
		if (!bgp_addpath_capable(pi, peer, afi, safi))
			return false;

	/* Aggregate-address suppress check. */
	if (bgp_path_suppressed(pi) && !UNSUPPRESS_MAP_NAME(filter))
		return false;

	/*
	 * If we are doing VRF 2 VRF leaking via the import
	 * statement, we want to prevent the route going
	 * off box as that the RT and RD created are localy
	 * significant and globaly useless.
	 */
	if (safi == SAFI_MPLS_VPN && BGP_PATH_INFO_NUM_LABELS(pi) &&
	    pi->extra->labels->label[0] == BGP_PREVENT_VRF_2_VRF_LEAK)
		return false;

	/* If it's labeled safi, make sure the route has a valid label. */
	if (safi == SAFI_LABELED_UNICAST) {
		label = bgp_adv_label(dest, pi, peer, afi, safi);
		if (!bgp_is_valid_label(&label)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug("u%" PRIu64 ":s%" PRIu64
					   " %pFX is filtered - no label (%p)",
					   subgrp->update_group->id, subgrp->id,
					   p, &label);
			return false;
		}
	} else if (safi == SAFI_MPLS_VPN &&
		   CHECK_FLAG(pi->flags, BGP_PATH_MPLSVPN_NH_LABEL_BIND) &&
		   pi->mplsvpn.bmnc.nh_label_bind_cache && peer &&
		   pi->peer != peer && pi->sub_type != BGP_ROUTE_IMPORTED &&
		   pi->sub_type != BGP_ROUTE_STATIC &&
		   bgp_mplsvpn_path_uses_valid_mpls_label(pi) &&
		   bgp_path_info_nexthop_changed(pi, peer, afi)) {
		/* Redistributed mpls vpn route between distinct
		 * peers from 'pi->peer' to 'to',
		 * and an mpls label is used in this path,
		 * and there is a nh label bind entry,
		 * then get appropriate mpls local label
		 * and check its validity
		 */
		label = bgp_mplsvpn_nh_label_bind_get_label(pi);
		if (!bgp_is_valid_label(&label)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug("u%" PRIu64 ":s%" PRIu64
					   " %pFX is filtered - no valid label",
					   subgrp->update_group->id, subgrp->id,
					   p);
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
		if ((p->family == AF_INET || p->family == AF_INET6) && p->prefixlen == 0)
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
			zlog_debug("%s: community filter check fail for %pFX",
				   __func__, p);
		return false;
	}

	/* If the attribute has originator-id and it is same as remote
	   peer's id. */
	if (onlypeer && (CHECK_FLAG(piattr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))) &&
	    (IPV4_ADDR_SAME(&onlypeer->remote_id, &piattr->originator_id))) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug(
				"%pBP [Update:SEND] %pFX originator-id is same as remote router-id",
				onlypeer, p);
		return false;
	}

	/* ORF prefix-list filter check */
	if (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV) &&
	    CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV))
		if (peer->orf_plist[afi][safi]) {
			if (prefix_list_apply(peer->orf_plist[afi][safi], p)
			    == PREFIX_DENY) {
				if (bgp_debug_update(NULL, p,
						     subgrp->update_group, 0))
					zlog_debug(
						"%pBP [Update:SEND] %pFX is filtered via ORF",
						peer, p);
				return false;
			}
		}

	/* Output filter check. */
	if (bgp_output_filter(peer, p, piattr, afi, safi) == FILTER_DENY) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug("%pBP [Update:SEND] %pFX is filtered", peer,
				   p);
		return false;
	}

	/* AS path loop check. */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_AS_LOOP_DETECTION) &&
	    aspath_loop_check(piattr->aspath, peer->as)) {
		if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
			zlog_debug(
				"%pBP [Update:SEND] suppress announcement to peer AS %u that is part of AS path.",
				peer, peer->as);
		return false;
	}

	/* If we're a CONFED we need to loop check the CONFED ID too */
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		if (aspath_loop_check_confed(piattr->aspath, bgp->confed_id)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%pBP [Update:SEND] suppress announcement to peer AS %u is AS path.",
					peer, bgp->confed_id);
			return false;
		}
	}

	/* iBGP to iBGP check. */
	if (from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
		ibgp_to_ibgp = 1;
	else
		ibgp_to_ibgp = 0;

	/* IBGP reflection check. */
	if (ibgp_to_ibgp && !samepeer_safe) {
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

	/* For modify attribute, copy it to temporary structure.
	 * post_attr comes from BGP conditional advertisements, where
	 * attributes are already processed by advertise-map route-map,
	 * and this needs to be saved instead of overwriting from the
	 * path attributes.
	 */
	if (post_attr)
		*attr = *post_attr;
	else
		*attr = *piattr;

	/* don't confuse inbound and outbound setting */
	RESET_FLAG(attr->rmap_change_flags);

	/* If local-preference is not set. */
	if ((peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED) &&
	    (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))) {
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
		attr->local_pref = bgp->default_local_pref;
	}

	/* If originator-id is not set and the route is to be reflected,
	   set the originator id */
	if (ibgp_to_ibgp && (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))) {
		IPV4_ADDR_COPY(&(attr->originator_id), &(from->remote_id));
		SET_FLAG(attr->flag, BGP_ATTR_ORIGINATOR_ID);
	}

	/* Remove MED if its an EBGP peer - will get overwritten by route-maps
	 */
	if (peer->sort == BGP_PEER_EBGP && peer->sub_sort != BGP_PEER_EBGP_OAD &&
	    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))) {
		if (from != bgp->peer_self && !transparent
		    && !CHECK_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_MED_UNCHANGED))
			UNSET_FLAG(attr->flag, (ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)));
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
	if (ibgp_to_ibgp)
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
		if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)) {
			/* nexthop local unchanged: only include the link-local nexthop if it
			 * was already present.
			 */
			if (IN6_IS_ADDR_LINKLOCAL(&attr->mp_nexthop_local))
				global_and_ll = true;
		} else if (!ibgp_to_ibgp && !transparent &&
			   !CHECK_FLAG(from->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT) &&
			   IN6_IS_ADDR_LINKLOCAL(&peer->nexthop.v6_local) && peer->shared_network &&
			   (from == bgp->peer_self || peer->sort == BGP_PEER_EBGP))
			global_and_ll = true;

		if (global_and_ll) {
			if (safi == SAFI_MPLS_VPN)
				attr->mp_nexthop_len =
					BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL;
			else
				attr->mp_nexthop_len =
					BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
		} else
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

		/* Clear off link-local nexthop in source, whenever it is not
		 * needed to
		 * ensure more prefixes share the same attribute for
		 * announcement.
		 */
		if (!(CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)) ||
		    !IPV6_ADDR_SAME(&peer->nexthop.v6_global, &from->nexthop.v6_global))
			/* Reset if "nexthop-local unchanged" is not set or originating and destination peer
			 * does not share the same subnet.
			 */
			memset(&attr->mp_nexthop_local, 0, IPV6_MAX_BYTELEN);
	}

	if (bgp_check_role_applicability(afi, safi) &&
	    bgp_otc_egress(peer, attr))
		return false;

	if (filter->advmap.update_type == UPDATE_TYPE_WITHDRAW &&
	    filter->advmap.aname &&
	    route_map_lookup_by_name(filter->advmap.aname)) {
		struct bgp_path_info rmap_path = {0};
		struct bgp_path_info_extra dummy_rmap_path_extra = {0};
		struct attr dummy_attr = *attr;

		/* Fill temp path_info */
		prep_for_rmap_apply(&rmap_path, &dummy_rmap_path_extra, dest, pi, peer, NULL,
				    &dummy_attr);

		struct route_map *amap =
			route_map_lookup_by_name(filter->advmap.aname);

		ret = route_map_apply(amap, p, &rmap_path);

		bgp_attr_flush(&dummy_attr);

		/*
		 * The conditional advertisement mode is Withdraw and this
		 * prefix is a conditional prefix. Don't advertise it
		 */
		if (ret == RMAP_PERMITMATCH)
			return false;
	}

	/* Route map & unsuppress-map apply. */
	if (!post_attr &&
	    (ROUTE_MAP_OUT_NAME(filter) || bgp_path_suppressed(pi))) {
		struct bgp_path_info rmap_path = {0};
		struct bgp_path_info_extra dummy_rmap_path_extra = {0};
		struct attr dummy_attr = {0};

		/* Fill temp path_info.
		 * Inject the peer structure of the source peer (from).
		 * This is useful for e.g. `match peer ...` in outgoing
		 * direction.
		 */
		prep_for_rmap_apply(&rmap_path, &dummy_rmap_path_extra, dest, pi, peer, from, attr);

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

		bgp_attr_flush(&dummy_attr);
		peer->rmap_type = 0;

		if (ret == RMAP_DENYMATCH) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%pBP [Update:SEND] %pFX is filtered by route-map '%s'",
					peer, p,
					bgp_path_suppressed(pi)
						? UNSUPPRESS_MAP_NAME(filter)
						: ROUTE_MAP_OUT_NAME(filter));
			bgp_attr_flush(rmap_path.attr);
			return false;
		}
	}

	bgp_peer_remove_private_as(bgp, afi, safi, peer, attr);
	bgp_peer_as_override(bgp, afi, safi, peer, attr);

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
		if (!bgp_outbound_policy_exists(peer, filter)) {
			if (monotime_since(&bgp->ebgprequirespolicywarning,
					   NULL) > FIFTEENMINUTE2USEC ||
			    bgp->ebgprequirespolicywarning.tv_sec == 0) {
				zlog_warn(
					"EBGP inbound/outbound policy not properly setup, please configure in order for your peering to work correctly");
				monotime(&bgp->ebgprequirespolicywarning);
			}
			return false;
		}

	/* draft-ietf-idr-deprecate-as-set-confed-set
	 * Filter routes having AS_SET or AS_CONFED_SET in the path.
	 * Eventually, This document (if approved) updates RFC 4271
	 * and RFC 5065 by eliminating AS_SET and AS_CONFED_SET types,
	 * and obsoletes RFC 6472.
	 */
	if (peer->bgp->reject_as_sets)
		if (aspath_check_as_sets(attr->aspath))
			return false;

	/* If neighbor soo is configured, then check if the route has
	 * SoO extended community and validate against the configured
	 * one. If they match, do not announce, to prevent routing
	 * loops.
	 */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) && peer->soo[afi][safi]) {
		struct ecommunity *ecomm_soo = peer->soo[afi][safi];
		struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

		if ((ecommunity_lookup(ecomm, ECOMMUNITY_ENCODE_AS,
				       ECOMMUNITY_SITE_ORIGIN) ||
		     ecommunity_lookup(ecomm, ECOMMUNITY_ENCODE_AS4,
				       ECOMMUNITY_SITE_ORIGIN) ||
		     ecommunity_lookup(ecomm, ECOMMUNITY_ENCODE_IP,
				       ECOMMUNITY_SITE_ORIGIN)) &&
		    ecommunity_include(ecomm, ecomm_soo)) {
			if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
				zlog_debug(
					"%pBP [Update:SEND] %pFX is filtered by SoO extcommunity '%s'",
					peer, p, ecommunity_str(ecomm_soo));
			return false;
		}
	}

	/* Codification of AS 0 Processing */
	if (aspath_check_as_zero(attr->aspath))
		return false;

	if (bgp_in_graceful_shutdown(bgp)) {
		if (peer->sort == BGP_PEER_IBGP ||
		    peer->sort == BGP_PEER_CONFED ||
		    peer->sub_sort == BGP_PEER_EBGP_OAD) {
			SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
			attr->local_pref = BGP_GSHUT_LOCAL_PREF;
		} else {
			bgp_attr_add_gshut_community(attr);
		}
	}

	/* A BGP speaker that has advertised the "Long-lived Graceful Restart
	 * Capability" to a neighbor MUST perform the following upon receiving
	 * a route from that neighbor with the "LLGR_STALE" community, or upon
	 * attaching the "LLGR_STALE" community itself per Section 4.2:
	 *
	 * The route SHOULD NOT be advertised to any neighbor from which the
	 * Long-lived Graceful Restart Capability has not been received.
	 */
	if (bgp_attr_get_community(attr) &&
	    community_include(bgp_attr_get_community(attr),
			      COMMUNITY_LLGR_STALE) &&
	    !CHECK_FLAG(peer->cap, PEER_CAP_LLGR_RCV) &&
	    !CHECK_FLAG(peer->cap, PEER_CAP_LLGR_ADV))
		return false;

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
			if (!ibgp_to_ibgp ||
			    CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF)) {
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
					"%s: %pFX BGP_PATH_ANNC_NH_SELF, family=%s",
					__func__, p, family2str(family));
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

	/* If this is an iBGP, send Origin Validation State (OVS)
	 * extended community (rfc8097).
	 * draft-uttaro-idr-bgp-oad states:
	 *   For example, the Origin Validation State Extended Community,
	 *   defined as non-transitive in [RFC8097], can be advertised to
	 *   peers in the same OAD.
	 */
	if ((peer->sort == BGP_PEER_IBGP ||
	     peer->sub_sort == BGP_PEER_EBGP_OAD) &&
	    peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_SEND_EXT_COMMUNITY_RPKI)) {
		enum rpki_states rpki_state = RPKI_NOT_BEING_USED;

		rpki_state = hook_call(bgp_rpki_prefix_status, peer, attr, p);

		if (rpki_state != RPKI_NOT_BEING_USED)
			bgp_attr_set_ecommunity(attr,
						ecommunity_add_origin_validation_state(
							rpki_state,
							bgp_attr_get_ecommunity(
								attr)));
	}

	/*
	 * When the next hop is set to ourselves, if all multipaths have
	 * link-bandwidth announce the cumulative bandwidth as that makes
	 * the most sense. However, don't modify if the link-bandwidth has
	 * been explicitly set by user policy.
	 */
	if (nh_reset && bgp_path_info_mpath_chkwtd(bgp, pi) &&
	    (cum_bw = bgp_path_info_mpath_cumbw(pi)) != 0 &&
	    !CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_LINK_BW_SET)) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_EXTENDED_LINK_BANDWIDTH))
			bgp_attr_set_ipv6_ecommunity(
				attr,
				ecommunity_replace_linkbw(bgp->as,
							  bgp_attr_get_ipv6_ecommunity(
								  attr),
							  cum_bw, false, true));
		else
			bgp_attr_set_ecommunity(
				attr,
				ecommunity_replace_linkbw(
					bgp->as, bgp_attr_get_ecommunity(attr),
					cum_bw,
					CHECK_FLAG(peer->flags,
						   PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE),
					false));
	}

	/*
	 * Adjust AIGP for propagation when the nexthop is set to ourselves,
	 * e.g., using "set ip nexthop peer-address" or when advertising to
	 * EBGP. Note in route reflection the nexthop is usually unmodified
	 * and the AIGP should not be adjusted in that case.
	 */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)) && AIGP_TRANSMIT_ALLOWED(peer)) {
		if (nh_reset ||
		    CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_NEXTHOP_PEER_ADDRESS)) {
			uint64_t aigp = bgp_aigp_metric_total(pi);

			bgp_attr_set_aigp_metric(attr, aigp);
		}
	}

	/* Extended communities can be transitive and non-transitive.
	 * If the extended community is non-transitive, strip it off,
	 * unless it's a locally originated route (static, aggregate,
	 * redistributed, etc.).
	 */
	if (from->sort == BGP_PEER_EBGP && peer->sort == BGP_PEER_EBGP &&
	    pi->sub_type == BGP_ROUTE_NORMAL) {
		struct ecommunity *new_ecomm;
		struct ecommunity *old_ecomm;

		old_ecomm = bgp_attr_get_ecommunity(attr);
		if (old_ecomm) {
			new_ecomm = ecommunity_dup(old_ecomm);
			if (ecommunity_strip_non_transitive(new_ecomm)) {
				bgp_attr_set_ecommunity(attr, new_ecomm);
				if (!old_ecomm->refcnt)
					ecommunity_free(&old_ecomm);
				if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
					zlog_debug("%pBP: %pFX stripped non-transitive extended communities",
						   peer, p);
			} else {
				ecommunity_free(&new_ecomm);
			}
		}

		/* Extended link-bandwidth communities are encoded as IPv6
		 * address-specific extended communities.
		 */
		old_ecomm = bgp_attr_get_ipv6_ecommunity(attr);
		if (old_ecomm) {
			new_ecomm = ecommunity_dup(old_ecomm);
			if (ecommunity_strip_non_transitive(new_ecomm)) {
				bgp_attr_set_ipv6_ecommunity(attr, new_ecomm);
				if (!old_ecomm->refcnt)
					ecommunity_free(&old_ecomm);
				if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
					zlog_debug("%pBP: %pFX stripped non-transitive ipv6 extended communities",
						   peer, p);
			} else {
				ecommunity_free(&new_ecomm);
			}
		}
	}

	return true;
}

static void bgp_route_select_timer_expire(struct event *thread)
{
	struct afi_safi_info *info;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;

	info = EVENT_ARG(thread);
	afi = info->afi;
	safi = info->safi;
	bgp = info->bgp;

	bgp->gr_info[afi][safi].t_route_select = NULL;
	XFREE(MTYPE_TMP, info);

	/* Best path selection */
	bgp_best_path_select_defer(bgp, afi, safi);
}

void bgp_best_selection(struct bgp *bgp, struct bgp_dest *dest,
			struct bgp_maxpaths_cfg *mpath_cfg,
			struct bgp_path_info_pair *result, afi_t afi,
			safi_t safi)
{
	struct bgp_path_info *new_select, *look_thru;
	struct bgp_path_info *old_select, *worse, *first;
	struct bgp_path_info *pi;
	struct bgp_path_info *pi1;
	struct bgp_path_info *pi2;
	int paths_eq, do_mpath;
	bool debug, any_comparisons;
	char pfx_buf[PREFIX2STR_BUFFER] = {};
	char path_buf[PATH_ADDPATH_STR_BUFFER];
	enum bgp_path_selection_reason reason = bgp_path_selection_none;
	bool unsorted_items = true;
	uint32_t num_candidates = 0;

	do_mpath =
		(mpath_cfg->maxpaths_ebgp > 1 || mpath_cfg->maxpaths_ibgp > 1);

	debug = bgp_debug_bestpath(dest);

	if (debug)
		prefix2str(bgp_dest_get_prefix(dest), pfx_buf, sizeof(pfx_buf));

	/* bgp deterministic-med */
	new_select = NULL;
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
		/* Clear BGP_PATH_DMED_SELECTED for all paths */
		for (pi1 = bgp_dest_get_bgp_path_info(dest); pi1;
		     pi1 = pi1->next) {
			bgp_path_info_unset_flag(dest, pi1,
						 BGP_PATH_DMED_SELECTED);
			UNSET_FLAG(pi1->flags, BGP_PATH_DMED_CHECK);
		}

		for (pi1 = bgp_dest_get_bgp_path_info(dest); pi1;
		     pi1 = pi1->next) {
			if (CHECK_FLAG(pi1->flags, BGP_PATH_DMED_CHECK))
				continue;
			if (BGP_PATH_HOLDDOWN(pi1))
				continue;
			if (pi1->peer != bgp->peer_self &&
			    !CHECK_FLAG(pi1->peer->sflags,
					PEER_STATUS_NSF_WAIT)) {
				if (!peer_established(pi1->peer->connection))
					continue;
			}

			new_select = pi1;
			for (pi2 = pi1->next; pi2; pi2 = pi2->next) {
				if (CHECK_FLAG(pi2->flags, BGP_PATH_DMED_CHECK))
					continue;
				if (BGP_PATH_HOLDDOWN(pi2))
					continue;
				if (pi2->peer != bgp->peer_self &&
				    !CHECK_FLAG(pi2->peer->sflags,
						PEER_STATUS_NSF_WAIT) &&
				    !peer_established(pi2->peer->connection))
					continue;

				if (!aspath_cmp_left(pi1->attr->aspath,
						     pi2->attr->aspath) &&
				    !aspath_cmp_left_confed(pi1->attr->aspath,
							    pi2->attr->aspath))
					continue;

				if (bgp_path_info_cmp(bgp, pi2, new_select,
						      &paths_eq, mpath_cfg,
						      debug, pfx_buf, afi, safi,
						      &dest->reason)) {
					bgp_path_info_unset_flag(dest,
								 new_select,
								 BGP_PATH_DMED_SELECTED);
					new_select = pi2;
				}

				bgp_path_info_set_flag(dest, pi2,
						       BGP_PATH_DMED_CHECK);
			}
			bgp_path_info_set_flag(dest, new_select,
					       BGP_PATH_DMED_CHECK);
			bgp_path_info_set_flag(dest, new_select,
					       BGP_PATH_DMED_SELECTED);

			if (debug) {
				bgp_path_info_path_with_addpath_rx_str(
					new_select, path_buf, sizeof(path_buf));
				zlog_debug(
					"%pBD(%s): %s is the bestpath from AS %u",
					dest, bgp->name_pretty, path_buf,
					aspath_get_first_as(
						new_select->attr->aspath));
			}
		}
	}

	/*
	 * Let's grab the unsorted items from the list
	 */
	struct bgp_path_info *unsorted_list = NULL;
	struct bgp_path_info *unsorted_list_spot = NULL;
	struct bgp_path_info *unsorted_holddown = NULL;

	old_select = NULL;
	pi = bgp_dest_get_bgp_path_info(dest);
	while (pi && CHECK_FLAG(pi->flags, BGP_PATH_UNSORTED)) {
		struct bgp_path_info *next = pi->next;

		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			old_select = pi;

		/*
		 * Pull off pi off the list
		 */
		if (pi->next)
			pi->next->prev = NULL;

		bgp_dest_set_bgp_path_info(dest, pi->next);
		pi->next = NULL;
		pi->prev = NULL;

		/*
		 * Place it on the unsorted list
		 */
		if (unsorted_list_spot) {
			unsorted_list_spot->next = pi;
			pi->prev = unsorted_list_spot;
			pi->next = NULL;
		} else {
			unsorted_list = pi;

			pi->next = NULL;
			pi->prev = NULL;
		}

		unsorted_list_spot = pi;
		pi = next;
	}

	if (!old_select) {
		old_select = bgp_dest_get_bgp_path_info(dest);
		if (old_select &&
		    !CHECK_FLAG(old_select->flags, BGP_PATH_SELECTED))
			old_select = NULL;
	}

	if (!unsorted_list)
		unsorted_items = true;
	else
		unsorted_items = false;

	any_comparisons = false;
	worse = NULL;
	while (unsorted_list) {
		first = unsorted_list;
		unsorted_list = unsorted_list->next;

		if (unsorted_list)
			unsorted_list->prev = NULL;
		first->next = NULL;
		first->prev = NULL;

		/*
		 * It's not likely that the just received unsorted entry
		 * is in holddown and scheduled for removal but we should
		 * check
		 */
		if (BGP_PATH_HOLDDOWN(first)) {
			/*
			 * reap REMOVED routes, if needs be
			 * selected route must stay for a while longer though
			 */
			if (debug)
				zlog_debug("%s: %pBD(%s) pi %p from %s in holddown",
					   __func__, dest, bgp->name_pretty,
					   first, first->peer->host);

			if (old_select != first &&
			    CHECK_FLAG(first->flags, BGP_PATH_REMOVED)) {
				dest = bgp_path_info_reap_unsorted(dest, first);
				assert(dest);
			} else {
				/*
				 * We are in hold down, so we cannot sort this
				 * item yet.  Let's wait, so hold the unsorted
				 * to the side
				 */
				if (unsorted_holddown) {
					first->next = unsorted_holddown;
					unsorted_holddown->prev = first;
					unsorted_holddown = first;
				} else
					unsorted_holddown = first;

				UNSET_FLAG(first->flags, BGP_PATH_UNSORTED);
			}
			continue;
		}

		bgp_path_info_unset_flag(dest, first, BGP_PATH_DMED_CHECK);

		worse = NULL;

		struct bgp_path_info *look_thru_next;

		for (look_thru = bgp_dest_get_bgp_path_info(dest); look_thru;
		     look_thru = look_thru_next) {
			/* look thru can be reaped save the next pointer */
			look_thru_next = look_thru->next;

			/*
			 * Now we have the first unsorted and the best selected
			 * Let's do best path comparison
			 */
			if (BGP_PATH_HOLDDOWN(look_thru)) {
				/* reap REMOVED routes, if needs be
				 * selected route must stay for a while longer though
				 */
				if (debug)
					zlog_debug("%s: %pBD(%s) pi from %s %p in holddown",
						   __func__, dest,
						   bgp->name_pretty,
						   look_thru->peer->host,
						   look_thru);

				if (CHECK_FLAG(look_thru->flags,
					       BGP_PATH_REMOVED) &&
				    (look_thru != old_select)) {
					dest = bgp_path_info_reap(dest,
								  look_thru);
					assert(dest);
				}

				continue;
			}

			if (look_thru->peer &&
			    look_thru->peer != bgp->peer_self &&
			    !CHECK_FLAG(look_thru->peer->sflags,
					PEER_STATUS_NSF_WAIT))
				if (!peer_established(
					    look_thru->peer->connection)) {
					if (debug)
						zlog_debug("%s: %pBD(%s) non self peer %s not estab state",
							   __func__, dest,
							   bgp->name_pretty,
							   look_thru->peer->host);

					continue;
				}

			bgp_path_info_unset_flag(dest, look_thru,
						 BGP_PATH_DMED_CHECK);
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED) &&
			    (!CHECK_FLAG(look_thru->flags,
					 BGP_PATH_DMED_SELECTED))) {
				bgp_path_info_unset_flag(dest, look_thru,
							 BGP_PATH_DMED_CHECK);
				if (debug)
					zlog_debug("%s: %pBD(%s) pi %s dmed",
						   __func__, dest,
						   bgp->name_pretty,
						   look_thru->peer->host);

				worse = look_thru;
				continue;
			}

			reason = dest->reason;
			any_comparisons = true;
			if (bgp_path_info_cmp(bgp, first, look_thru, &paths_eq,
					      mpath_cfg, debug, pfx_buf, afi,
					      safi, &reason)) {
				first->reason = reason;
				worse = look_thru;
				/*
				 * We can stop looking
				 */
				break;
			}

			look_thru->reason = reason;
		}

		if (!any_comparisons)
			first->reason = bgp_path_selection_first;

		/*
		 * At this point worse if NON-NULL is where the first
		 * pointer should be before.  if worse is NULL then
		 * first is bestpath too.  Let's remove first from the
		 * list and place it in the right spot
		 */

		if (!worse) {
			struct bgp_path_info *end =
				bgp_dest_get_bgp_path_info(dest);

			if (end && any_comparisons) {
				for (; end && end->next != NULL; end = end->next)
					;

				if (end)
					end->next = first;
				else
					bgp_dest_set_bgp_path_info(dest, first);
				first->prev = end;
				first->next = NULL;
			} else {
				bgp_dest_set_bgp_path_info(dest, first);
				if (end)
					end->prev = first;
				first->next = end;
				first->prev = NULL;
			}

			dest->reason = first->reason;
		} else {
			if (worse->prev)
				worse->prev->next = first;
			first->next = worse;
			if (worse) {
				first->prev = worse->prev;
				worse->prev = first;
			} else
				first->prev = NULL;

			if (dest->info == worse) {
				bgp_dest_set_bgp_path_info(dest, first);
				dest->reason = first->reason;
			}
		}
		UNSET_FLAG(first->flags, BGP_PATH_UNSORTED);
	}

	if (!unsorted_items) {
		new_select = bgp_dest_get_bgp_path_info(dest);
		while (new_select && BGP_PATH_HOLDDOWN(new_select))
			new_select = new_select->next;

		if (new_select) {
			if (new_select->reason == bgp_path_selection_none)
				new_select->reason = bgp_path_selection_first;
			else if (new_select == bgp_dest_get_bgp_path_info(dest) &&
				 new_select->next == NULL)
				new_select->reason = bgp_path_selection_first;
			dest->reason = new_select->reason;
		} else
			dest->reason = bgp_path_selection_none;
	} else
		new_select = old_select;


	/*
	 * Reinsert all the unsorted_holddown items for future processing
	 * at the end of the list.
	 */
	if (unsorted_holddown) {
		struct bgp_path_info *top = bgp_dest_get_bgp_path_info(dest);
		struct bgp_path_info *prev = NULL;

		while (top != NULL) {
			prev = top;
			top = top->next;
		}

		if (prev) {
			prev->next = unsorted_holddown;
			unsorted_holddown->prev = prev;
		} else
			bgp_dest_set_bgp_path_info(dest, unsorted_holddown);
	}

	/* Now that we know which path is the bestpath see if any of the other
	 * paths
	 * qualify as multipaths
	 */
	if (debug) {
		bgp_path_info_path_with_addpath_rx_str(new_select, path_buf,
						       sizeof(path_buf));
		zlog_debug(
			"%pBD(%s): After path selection, newbest is %s oldbest was %s",
			dest, bgp->name_pretty, path_buf,
			old_select ? old_select->peer->host : "NONE");
	}

	if (do_mpath && new_select) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (debug)
				bgp_path_info_path_with_addpath_rx_str(
					pi, path_buf, sizeof(path_buf));

			if (pi == new_select) {
				if (debug)
					zlog_debug(
						"%pBD(%s): %s is the bestpath, add to the multipath list",
						dest, bgp->name_pretty,
						path_buf);
				SET_FLAG(pi->flags, BGP_PATH_MULTIPATH_NEW);
				num_candidates++;
				continue;
			}

			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (pi->peer && pi->peer != bgp->peer_self
			    && !CHECK_FLAG(pi->peer->sflags,
					   PEER_STATUS_NSF_WAIT))
				if (!peer_established(pi->peer->connection))
					continue;

			bgp_path_info_cmp(bgp, pi, new_select, &paths_eq,
					  mpath_cfg, debug, pfx_buf, afi, safi,
					  &dest->reason);

			if (paths_eq) {
				if (debug)
					zlog_debug(
						"%pBD(%s): %s is equivalent to the bestpath, add to the multipath list",
						dest, bgp->name_pretty,
						path_buf);
				SET_FLAG(pi->flags, BGP_PATH_MULTIPATH_NEW);
				num_candidates++;
			}
		}
	}

	bgp_path_info_mpath_update(bgp, dest, new_select, old_select, num_candidates, mpath_cfg);
	bgp_path_info_mpath_aggregate_update(new_select, old_select);

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
					struct bgp_dest *dest, afi_t afi,
					safi_t safi, uint32_t addpath_tx_id)
{
	const struct prefix *p;
	struct peer *onlypeer;
	struct attr attr = { 0 }, *pattr = &attr;
	struct bgp *bgp;
	bool advertise;

	p = bgp_dest_get_prefix(dest);
	bgp = SUBGRP_INST(subgrp);
	onlypeer = ((SUBGRP_PCOUNT(subgrp) == 1) ? (SUBGRP_PFIRST(subgrp))->peer
						 : NULL);

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("%s: p=%pFX, selected=%p", __func__, p, selected);

	/* First update is deferred until ORF or ROUTE-REFRESH is received */
	if (onlypeer && CHECK_FLAG(onlypeer->af_sflags[afi][safi],
				   PEER_STATUS_ORF_WAIT_REFRESH))
		return;

	memset(&attr, 0, sizeof(attr));
	/* It's initialized in bgp_announce_check() */

	/* Announcement to the subgroup. If the route is filtered withdraw it.
	 * If BGP_NODE_FIB_INSTALL_PENDING is set and data plane install status
	 * is pending (BGP_NODE_FIB_INSTALL_PENDING), do not advertise the
	 * route
	 */
	advertise = bgp_check_advertise(bgp, dest, safi);

	if (selected) {
		if (subgroup_announce_check(dest, selected, subgrp, p, pattr,
					    NULL)) {
			/* Route is selected, if the route is already installed
			 * in FIB, then it is advertised
			 */
			if (advertise) {
				if (!bgp_check_withdrawal(bgp, dest, safi)) {
					if (!bgp_adj_out_set_subgroup(dest,
								      subgrp,
								      pattr,
								      selected))
						bgp_attr_flush(pattr);
				} else {
					bgp_adj_out_unset_subgroup(
						dest, subgrp, 1, addpath_tx_id);
					bgp_attr_flush(pattr);
				}
			} else
				bgp_attr_flush(pattr);
		} else {
			bgp_adj_out_unset_subgroup(dest, subgrp, 1,
						   addpath_tx_id);
			bgp_attr_flush(pattr);
		}
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
			prep_for_rmap_apply(&rmap_path, &rmap_path_extra, dest, new_select,
					    new_select->peer, NULL, &dummy_attr);

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
 * Utility to determine whether a particular path_info should use
 * the IMPLICIT_NULL label. This is pretty specialized: it's only called
 * in a path where we basically _know_ this is a BGP-LU route.
 */
static bool bgp_lu_need_null_label(struct bgp *bgp,
				   const struct bgp_path_info *new_select,
				   afi_t afi, mpls_label_t *label)
{
	/* Certain types get imp null; so do paths where the nexthop is
	 * not labeled.
	 */
	if (new_select->sub_type == BGP_ROUTE_STATIC
	    || new_select->sub_type == BGP_ROUTE_AGGREGATE
	    || new_select->sub_type == BGP_ROUTE_REDISTRIBUTE)
		goto need_null_label;
	else if (bgp_path_info_has_valid_label(new_select))
		return false;
need_null_label:
	if (label == NULL)
		return true;
	/* Disable PHP : explicit-null */
	if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL) &&
	    afi == AFI_IP)
		*label = MPLS_LABEL_IPV4_EXPLICIT_NULL;
	else if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL) &&
		 afi == AFI_IP6)
		*label = MPLS_LABEL_IPV6_EXPLICIT_NULL;
	else
		/* Enforced PHP popping: implicit-null */
		*label = MPLS_LABEL_IMPLICIT_NULL;

	return true;
}

/* Right now, since we only deal with per-prefix labels, it is not
 * necessary to do this upon changes to best path. Exceptions:
 * - label index has changed -> recalculate resulting label
 * - path_info sub_type changed -> switch to/from null label value
 * - no valid label (due to removed static label binding) -> get new one
 */
static void bgp_lu_handle_label_allocation(struct bgp *bgp,
					   struct bgp_dest *dest,
					   struct bgp_path_info *new_select,
					   struct bgp_path_info *old_select,
					   afi_t afi)
{
	mpls_label_t mpls_label_null;

	if (bgp->allocate_mpls_labels[afi][SAFI_UNICAST]) {
		if (new_select) {
			if (!old_select ||
			    bgp_label_index_differs(new_select, old_select) ||
			    new_select->sub_type != old_select->sub_type ||
			    !bgp_is_valid_label(&dest->local_label)) {
				/* control label imposition for local
				 * routes, aggregate and redistributed
				 * routes
				 */
				mpls_label_null = MPLS_LABEL_IMPLICIT_NULL;
				if (bgp_lu_need_null_label(bgp, new_select, afi,
							   &mpls_label_null)) {
					if (CHECK_FLAG(
						    dest->flags,
						    BGP_NODE_REGISTERED_FOR_LABEL) ||
					    CHECK_FLAG(
						    dest->flags,
						    BGP_NODE_LABEL_REQUESTED))
						bgp_unregister_for_label(dest);
					dest->local_label = mpls_lse_encode(
						mpls_label_null, 0, 0, 1);
					bgp_set_valid_label(&dest->local_label);
				} else
					bgp_register_for_label(dest,
							       new_select);
			}
		} else if (CHECK_FLAG(dest->flags,
				      BGP_NODE_REGISTERED_FOR_LABEL) ||
			   CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED)) {
			bgp_unregister_for_label(dest);
		}
	} else if (CHECK_FLAG(dest->flags, BGP_NODE_REGISTERED_FOR_LABEL) ||
		   CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED)) {
		bgp_unregister_for_label(dest);
	}
}

static struct interface *
bgp_label_get_resolved_nh_iface(const struct bgp_path_info *pi)
{
	struct nexthop *nh;

	if (pi->nexthop == NULL || pi->nexthop->nexthop == NULL ||
	    !CHECK_FLAG(pi->nexthop->flags, BGP_NEXTHOP_VALID))
		/* next-hop is not valid */
		return NULL;

	nh = pi->nexthop->nexthop;
	if (nh->ifindex == IFINDEX_INTERNAL &&
	    nh->type != NEXTHOP_TYPE_IPV4_IFINDEX &&
	    nh->type != NEXTHOP_TYPE_IPV6_IFINDEX)
		/* next-hop does not contain valid interface */
		return NULL;

	return if_lookup_by_index(nh->ifindex, nh->vrf_id);
}

static void
bgp_mplsvpn_handle_label_allocation(struct bgp *bgp, struct bgp_dest *dest,
				    struct bgp_path_info *new_select,
				    struct bgp_path_info *old_select, afi_t afi)
{
	struct interface *ifp;
	struct bgp_interface *bgp_ifp;

	if (bgp->allocate_mpls_labels[afi][SAFI_MPLS_VPN] && new_select) {
		ifp = bgp_label_get_resolved_nh_iface(new_select);
		if (ifp)
			bgp_ifp = (struct bgp_interface *)(ifp->info);
		else
			bgp_ifp = NULL;
		if (bgp_ifp &&
		    CHECK_FLAG(bgp_ifp->flags,
			       BGP_INTERFACE_MPLS_L3VPN_SWITCHING) &&
		    bgp_mplsvpn_path_uses_valid_mpls_label(new_select) &&
		    new_select->sub_type != BGP_ROUTE_IMPORTED &&
		    new_select->sub_type != BGP_ROUTE_STATIC)
			bgp_mplsvpn_nh_label_bind_register_local_label(
				bgp, dest, new_select);
		else
			bgp_mplsvpn_path_nh_label_bind_unlink(new_select);
	} else {
		if (new_select)
			/* no mpls vpn allocation */
			bgp_mplsvpn_path_nh_label_bind_unlink(new_select);
		else if (old_select)
			/* unlink old selection if any */
			bgp_mplsvpn_path_nh_label_bind_unlink(old_select);
	}
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

	/*
	 * For default bgp instance, which is deleted i.e. marked hidden
	 * we are skipping SAFI_MPLS_VPN route table deletion
	 * in bgp_cleanup_routes.
	 * So, we need to delete routes from VPNV4 table.
	 * Here for !IS_BGP_INSTANCE_HIDDEN,
	 * !(SAFI_MPLS_VPN && AF_IP/AF_IP6),
	 * we ignore the event for the prefix.
	 */
	if (BGP_INSTANCE_HIDDEN_DELETE_IN_PROGRESS(bgp, afi, safi)) {
		if (dest)
			debug = bgp_debug_bestpath(dest);
		if (debug)
			zlog_debug(
				"%s: bgp delete in progress, ignoring event, p=%pBD(%s)",
				__func__, dest, bgp->name_pretty);
		return;
	}
	/* Is it end of initial update? (after startup) */
	if (!dest) {
		frr_timestamp(3, bgp->update_delay_zebra_resume_time,
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

#ifdef ENABLE_BGP_VNC
	const struct prefix *p = bgp_dest_get_prefix(dest);
#endif

	debug = bgp_debug_bestpath(dest);
	if (debug)
		zlog_debug("%s: p=%pBD(%s) afi=%s, safi=%s start", __func__,
			   dest, bgp->name_pretty, afi2str(afi),
			   safi2str(safi));

	/* The best path calculation for the route is deferred if
	 * BGP_NODE_SELECT_DEFER is set
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("SELECT_DEFER flag set for route %p(%s)",
				   dest, bgp->name_pretty);
		return;
	}

	/* Best path selection. */
	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	if (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST)
		/* label unicast path :
		 * Do we need to allocate or free labels?
		 */
		bgp_lu_handle_label_allocation(bgp, dest, new_select,
					       old_select, afi);
	else if (safi == SAFI_MPLS_VPN)
		/* mpls vpn path:
		 * Do we need to allocate or free labels?
		 */
		bgp_mplsvpn_handle_label_allocation(bgp, dest, new_select,
						    old_select, afi);

	if (debug)
		zlog_debug(
			"%s: p=%pBD(%s) afi=%s, safi=%s, old_select=%p, new_select=%p",
			__func__, dest, bgp->name_pretty, afi2str(afi),
			safi2str(safi), old_select, new_select);

	/* If best route remains the same and this is not due to user-initiated
	 * clear, see exactly what needs to be done.
	 */
	if (old_select && old_select == new_select &&
	    !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR) &&
	    !CHECK_FLAG(dest->flags, BGP_NODE_PROCESS_CLEAR) &&
	    !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED) &&
	    !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
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
					bgp_zebra_route_install(dest, old_select,
								bgp, true, NULL,
								false);
			}
		}

		/* If there is a change of interest to peers, reannounce the
		 * route. */
		if (CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED) ||
		    CHECK_FLAG(dest->flags, BGP_NODE_LABEL_CHANGED) ||
		    bgp_zebra_has_route_changed(old_select)) {
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

	/* If the process wants to force deletion this flag will be set
	 */
	UNSET_FLAG(dest->flags, BGP_NODE_PROCESS_CLEAR);

	/* bestpath has changed; bump version */
	if (old_select || new_select) {
		bgp_bump_version(dest);

		if (!bgp->t_rmap_def_originate_eval &&
		    bgp->rmap_def_originate_eval_timer)
			event_add_timer(
				bm->master,
				update_group_refresh_default_originate_route_map,
				bgp, bgp->rmap_def_originate_eval_timer,
				&bgp->t_rmap_def_originate_eval);
	}

	/* TODO BMP insert rib update hook */
	if (old_select)
		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		if (debug)
			zlog_debug("%s: %pBD setting SELECTED flag", __func__,
				   dest);
		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(dest, new_select,
					 BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(new_select->flags, BGP_PATH_LINK_BW_CHG);
	}

	/* call bmp hook for loc-rib route update / withdraw after flags were
	 * set
	 */
	if (old_select || new_select) {
		hook_call(bgp_route_update, bgp, afi, safi, dest, old_select,
			  new_select);
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
				bgp_zebra_withdraw_actual(dest, old_select, bgp);

			bgp_zebra_route_install(dest, new_select, bgp, true,
						NULL, false);
		} else {
			/* Withdraw the route from the kernel. */
			if (old_select && old_select->type == ZEBRA_ROUTE_BGP
			    && (old_select->sub_type == BGP_ROUTE_NORMAL
				|| old_select->sub_type == BGP_ROUTE_AGGREGATE
				|| old_select->sub_type == BGP_ROUTE_IMPORTED))

				bgp_zebra_route_install(dest, old_select, bgp,
							false, NULL, false);
		}
	}

	group_announce_route(bgp, afi, safi, dest, new_select);

	/* unicast routes must also be annouced to labeled-unicast update-groups
	 */
	if (safi == SAFI_UNICAST)
		group_announce_route(bgp, afi, SAFI_LABELED_UNICAST, dest,
				     new_select);


	bgp_process_evpn_route_injection(bgp, afi, safi, dest, new_select,
					 old_select);

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(dest);

	UNSET_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(dest, old_select);

	return;
}

/* Process the routes with the flag BGP_NODE_SELECT_DEFER set */
void bgp_best_path_select_defer(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	int cnt = 0;
	struct afi_safi_info *thread_info;
	bool route_sync_pending = false;

	if (bgp->gr_info[afi][safi].t_route_select) {
		struct event *t = bgp->gr_info[afi][safi].t_route_select;

		thread_info = EVENT_ARG(t);
		XFREE(MTYPE_TMP, thread_info);
		EVENT_OFF(bgp->gr_info[afi][safi].t_route_select);
	}

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART)) {
		zlog_debug("%s: processing route for %s : cnt %d", __func__,
			   get_afi_safi_str(afi, safi, false),
			   bgp->gr_info[afi][safi].gr_deferred);
	}

	/* Process the route list */
	for (dest = bgp_table_top(bgp->rib[afi][safi]);
	     dest && bgp->gr_info[afi][safi].gr_deferred != 0 &&
	     cnt < BGP_MAX_BEST_ROUTE_SELECT;
	     dest = bgp_route_next(dest)) {
		if (!CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER))
			continue;

		UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
		bgp->gr_info[afi][safi].gr_deferred--;
		bgp_process_main_one(bgp, dest, afi, safi);
		cnt++;
	}
	/* If iteration stopped before the entire table was traversed then the
	 * node needs to be unlocked.
	 */
	if (dest) {
		bgp_dest_unlock_node(dest);
		dest = NULL;
	}

	/* Send EOR message when all routes are processed */
	if (!bgp->gr_info[afi][safi].gr_deferred) {
		bgp_send_delayed_eor(bgp);
		/* Send route processing complete message to RIB */
		bgp_zebra_update(bgp, afi, safi,
				 ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE);
		bgp->gr_info[afi][safi].route_sync = true;

		/* If this instance is all done, check for GR completion overall */
		FOREACH_AFI_SAFI_NSF (afi, safi) {
			if (bgp->gr_info[afi][safi].af_enabled &&
			    !bgp->gr_info[afi][safi].route_sync) {
				route_sync_pending = true;
				break;
			}
		}

		if (!route_sync_pending) {
			bgp->gr_route_sync_pending = false;
			bgp_update_gr_completion();
		}
		return;
	}

	thread_info = XMALLOC(MTYPE_TMP, sizeof(struct afi_safi_info));

	thread_info->afi = afi;
	thread_info->safi = safi;
	thread_info->bgp = bgp;

	/* If there are more routes to be processed, start the
	 * selection timer
	 */
	event_add_timer(bm->master, bgp_route_select_timer_expire, thread_info,
			BGP_ROUTE_SELECT_DELAY,
			&bgp->gr_info[afi][safi].t_route_select);
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

static void bgp_process_internal(struct bgp *bgp, struct bgp_dest *dest,
				 struct bgp_path_info *pi, afi_t afi,
				 safi_t safi, bool early_process)
{
#define ARBITRARY_PROCESS_QLEN		10000
	struct work_queue *wq = bgp->process_queue;
	struct bgp_process_queue *pqnode;
	int pqnode_reuse = 0;

	/*
	 * Indicate that *this* pi is in an unsorted
	 * situation, even if the node is already
	 * scheduled.
	 */
	if (pi) {
		struct bgp_path_info *first = bgp_dest_get_bgp_path_info(dest);

		SET_FLAG(pi->flags, BGP_PATH_UNSORTED);

		if (pi != first) {
			if (pi->next)
				pi->next->prev = pi->prev;
			if (pi->prev)
				pi->prev->next = pi->next;

			if (first)
				first->prev = pi;
			pi->next = first;
			pi->prev = NULL;
			bgp_dest_set_bgp_path_info(dest, pi);
		}
	}

	/* already scheduled for processing? */
	if (CHECK_FLAG(dest->flags, BGP_NODE_PROCESS_SCHEDULED)) {
		bgp->node_already_on_queue++;
		return;
	}

	/* If the flag BGP_NODE_SELECT_DEFER is set, do not add route to
	 * the workqueue
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("BGP_NODE_SELECT_DEFER set for route %p",
				   dest);
		bgp->node_deferred_on_queue++;
		return;
	}

	if (CHECK_FLAG(dest->flags, BGP_NODE_SOFT_RECONFIG)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug(
				"Soft reconfigure table in progress for route %p",
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

		if (CHECK_FLAG(pqnode->flags, BGP_PROCESS_QUEUE_EOIU_MARKER) ||
		    (pqnode->queued >= ARBITRARY_PROCESS_QLEN && !early_process))
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
	if (early_process)
		STAILQ_INSERT_HEAD(&pqnode->pqueue, dest, pq);
	else
		STAILQ_INSERT_TAIL(&pqnode->pqueue, dest, pq);
	pqnode->queued++;

	if (!pqnode_reuse)
		work_queue_add(wq, pqnode);

	return;
}

void bgp_process(struct bgp *bgp, struct bgp_dest *dest,
		 struct bgp_path_info *pi, afi_t afi, safi_t safi)
{
	bgp_process_internal(bgp, dest, pi, afi, safi, false);
}

void bgp_process_early(struct bgp *bgp, struct bgp_dest *dest,
		       struct bgp_path_info *pi, afi_t afi, safi_t safi)
{
	bgp_process_internal(bgp, dest, pi, afi, safi, true);
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

static void bgp_maximum_prefix_restart_timer(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug(
			"%s Maximum-prefix restart timer expired, restore peering",
			peer->host);

	if ((peer_clear(peer, NULL) < 0) && bgp_debug_neighbor_events(peer))
		zlog_debug("%s: %s peer_clear failed", __func__, peer->host);
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

			bgp_attr_flush(&attr);
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
	struct peer_connection *connection = peer->connection;

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
		return false;

	if (pcount > peer->pmax[afi][safi]) {
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_PREFIX_LIMIT)
		    && !always)
			return false;

		zlog_info(
			"%%MAXPFXEXCEED: No. of %s prefix received from %pBP %u exceed, limit %u",
			get_afi_safi_str(afi, safi, false), peer, pcount,
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
			bgp_notify_send_with_data(connection, BGP_NOTIFY_CEASE,
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
					"%pBP Maximum-prefix restart timer started for %d secs",
					peer, peer->v_pmax_restart);

			BGP_TIMER_ON(connection->t_pmax_restart,
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
			"%%MAXPFX: No. of %s prefix received from %pBP reaches %u, max %u",
			get_afi_safi_str(afi, safi, false), peer, pcount,
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
	bgp_process(peer->bgp, dest, pi, afi, safi);
}

static void bgp_rib_withdraw(struct bgp_dest *dest, struct bgp_path_info *pi,
			     struct peer *peer, afi_t afi, safi_t safi,
			     struct prefix_rd *prd)
{
	const struct prefix *p = bgp_dest_get_prefix(dest);

	/* apply dampening, if result is suppressed, we'll be retaining
	 * the bgp_path_info in the RIB for historical reference.
	 */
	if (peer->sort == BGP_PEER_EBGP) {
		if (get_active_bdc_from_pi(pi, afi, safi)) {
			if (bgp_damp_withdraw(pi, dest, afi, safi, 0) ==
			    BGP_DAMP_SUPPRESSED) {
				bgp_aggregate_decrement(peer->bgp, p, pi, afi,
							safi);
				return;
			}
		}
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
	new->uptime = monotime(NULL);
	new->net = dest;
	return new;
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

	/* If `bgp allow-martian-nexthop` is turned on, return next-hop
	 * as good.
	 */
	if (bgp->allow_martian)
		return false;

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
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))) {
		if (attr->nexthop.s_addr == INADDR_ANY ||
		    !ipv4_unicast_valid(&attr->nexthop) ||
		    bgp_nexthop_self(bgp, afi, type, stype, attr, dest))
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
			ret = (attr->mp_nexthop_global_in.s_addr ==
				       INADDR_ANY ||
			       !ipv4_unicast_valid(
				       &attr->mp_nexthop_global_in) ||
			       bgp_nexthop_self(bgp, afi, type, stype, attr,
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

static void bgp_attr_add_no_export_community(struct attr *attr)
{
	struct community *old;
	struct community *new;
	struct community *merge;
	struct community *no_export;

	old = bgp_attr_get_community(attr);
	no_export = community_str2com("no-export");

	assert(no_export);

	if (old) {
		merge = community_merge(community_dup(old), no_export);

		if (!old->refcnt)
			community_free(&old);

		new = community_uniq_sort(merge);
		community_free(&merge);
	} else {
		new = community_dup(no_export);
	}

	community_free(&no_export);

	bgp_attr_set_community(attr, new);
}

static bool bgp_accept_own(struct peer *peer, afi_t afi, safi_t safi,
			   struct attr *attr, const struct prefix *prefix,
			   int *sub_type)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool accept_own_found = false;

	if (safi != SAFI_MPLS_VPN)
		return false;

	/* Processing of the ACCEPT_OWN community is enabled by configuration */
	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ACCEPT_OWN))
		return false;

	/* The route in question carries the ACCEPT_OWN community */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		struct community *comm = bgp_attr_get_community(attr);

		if (community_include(comm, COMMUNITY_ACCEPT_OWN))
			accept_own_found = true;
	}

	/* The route in question is targeted to one or more destination VRFs
	 * on the router (as determined by inspecting the Route Target(s)).
	 */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		if (accept_own_found &&
		    ecommunity_include(
			    bgp->vpn_policy[afi]
				    .rtlist[BGP_VPN_POLICY_DIR_TOVPN],
			    bgp_attr_get_ecommunity(attr))) {
			if (bgp_debug_update(peer, prefix, NULL, 1))
				zlog_debug(
					"%pBP prefix %pFX has ORIGINATOR_ID, but it's accepted due to ACCEPT_OWN",
					peer, prefix);

			/* Treat this route as imported, because it's leaked
			 * already from another VRF, and we got an updated
			 * version from route-reflector with ACCEPT_OWN
			 * community.
			 */
			*sub_type = BGP_ROUTE_IMPORTED;

			return true;
		}
	}

	return false;
}

static inline void
bgp_update_nexthop_reachability_check(struct bgp *bgp, struct peer *peer, struct bgp_dest *dest,
				      const struct prefix *p, afi_t afi, safi_t safi,
				      struct bgp_path_info *pi, struct attr *attr_new,
				      const struct prefix *bgp_nht_param_prefix, bool accept_own)
{
	bool connected;
	afi_t nh_afi;

	if (((afi == AFI_IP || afi == AFI_IP6) &&
	     (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST ||
	      (safi == SAFI_MPLS_VPN && pi->sub_type != BGP_ROUTE_IMPORTED))) ||
	    (safi == SAFI_EVPN && bgp_evpn_is_prefix_nht_supported(p))) {
		if (safi != SAFI_EVPN && peer->sort == BGP_PEER_EBGP &&
		    peer->ttl == BGP_DEFAULT_TTL &&
		    !CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK) &&
		    !CHECK_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
			connected = true;
		else
			connected = false;

		struct bgp *bgp_nexthop = bgp;

		if (pi->extra && pi->extra->vrfleak && pi->extra->vrfleak->bgp_orig)
			bgp_nexthop = pi->extra->vrfleak->bgp_orig;

		nh_afi = BGP_ATTR_NH_AFI(afi, pi->attr);

		if (bgp_find_or_add_nexthop(bgp, bgp_nexthop, nh_afi, safi, pi, NULL, connected,
					    bgp_nht_param_prefix) ||
		    CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD)) {
			if (accept_own)
				bgp_path_info_set_flag(dest, pi, BGP_PATH_ACCEPT_OWN);

			bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);
		} else {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug("%s(%pI4): NH unresolved for existing %pFX pi %p flags 0x%x",
					   __func__, (in_addr_t *)&attr_new->nexthop, p, pi,
					   pi->flags);
			}
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_VALID);
		}
	} else {
		/* case mpls-vpn routes with accept-own community
		 * (which have the BGP_ROUTE_IMPORTED subtype)
		 * case other afi/safi not supporting nexthop tracking
		 */
		if (accept_own)
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ACCEPT_OWN);
		bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);
	}
}

void bgp_update(struct peer *peer, const struct prefix *p, uint32_t addpath_id,
		struct attr *attr, afi_t afi, safi_t safi, int type,
		int sub_type, struct prefix_rd *prd, mpls_label_t *label,
		uint8_t num_labels, int soft_reconfig,
		struct bgp_route_evpn *evpn)
{
	int ret;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct attr new_attr = {};
	struct attr *attr_new;
	struct bgp_path_info *pi;
	struct bgp_path_info *new = NULL;
	const char *reason;
	char pfx_buf[BGP_PRD_PATH_STRLEN];
	bool force_evpn_import = false;
	safi_t orig_safi = safi;
	struct bgp_labels bgp_labels = {};
	uint8_t i;

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
	const struct prefix *bgp_nht_param_prefix;

	/* Special case for BGP-LU - map LU safi to ordinary unicast safi */
	if (orig_safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	bgp = peer->bgp;
	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	if (num_labels &&
	    ((afi == AFI_L2VPN && safi == SAFI_EVPN) || bgp_is_valid_label(&label[0]))) {
		bgp_labels.num_labels = num_labels;
		for (i = 0; i < bgp_labels.num_labels; i++)
			bgp_labels.label[i] = label[i];
	}

	/* When peer's soft reconfiguration enabled.  Record input packet in
	   Adj-RIBs-In.  */
	if (!soft_reconfig &&
	    CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG) &&
	    peer != bgp->peer_self) {
		/*
		 * If the trigger is not from soft_reconfig and if
		 * PEER_FLAG_SOFT_RECONFIG is enabled for the peer, then attr
		 * will not be interned. In which case, it is ok to update the
		 * attr->evpn_overlay, so that, this can be stored in adj_in.
		 */
		if (evpn) {
			if (afi == AFI_L2VPN)
				bgp_attr_set_evpn_overlay(attr, evpn);
			else
				evpn_overlay_free(evpn);
		}
		bgp_adj_in_set(dest, peer, attr, addpath_id, &bgp_labels);
	}

	/* Check previously received route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == type
		    && pi->sub_type == sub_type
		    && pi->addpath_rx_id == addpath_id)
			break;

	/* AS path local-as loop check. */
	if (peer->change_local_as) {
		int32_t aspath_loop_count = 0;

		/* Update permitted loop count */
		if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN))
			aspath_loop_count = peer->allowas_in[afi][safi];
		else if (!CHECK_FLAG(peer->flags,
				     PEER_FLAG_LOCAL_AS_NO_PREPEND))
			aspath_loop_count = 1;

		if (aspath_loop_check(attr->aspath, peer->change_local_as)
		    > aspath_loop_count) {
			peer->stat_pfx_aspath_loop++;
			reason = "as-path contains our own AS;";
			goto filtered;
		}
	}

	/* When using bgp ipv4 labeled session, the local prefix is
	 * received by a peer, and finds out that the proposed prefix
	 * and its next-hop are the same. To avoid a route loop locally,
	 * no nexthop entry is referenced for that prefix, and the route
	 * will not be selected.
	 *
	 * As it has been done for ipv4-unicast, apply the following fix
	 * for labeled address families: when the received peer is
	 * a route reflector, the prefix has to be selected, even if the
	 * route can not be installed locally.
	 */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT) ||
	    (safi == SAFI_UNICAST && !peer->afc[afi][safi] &&
	     peer->afc[afi][SAFI_LABELED_UNICAST] &&
	     CHECK_FLAG(peer->af_flags[afi][SAFI_LABELED_UNICAST],
			PEER_FLAG_REFLECTOR_CLIENT)))
		bgp_nht_param_prefix = NULL;
	else
		bgp_nht_param_prefix = p;

	/*
	 * If the peer is configured for "allowas-in origin" and the last ASN in
	 * the as-path is our ASN then we do not need to call aspath_loop_check
	 */
	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN_ORIGIN) ||
	    (aspath_get_last_as(attr->aspath) != bgp->as)) {
		/* AS path loop check. */
		if (aspath_loop_check(attr->aspath, bgp->as) >
		    peer->allowas_in[afi][safi]) {
			peer->stat_pfx_aspath_loop++;
			reason = "as-path contains our own AS;";
			goto filtered;
		}

		/* If we're a CONFED we need to loop check the CONFED ID too */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
			if (aspath_loop_check_confed(attr->aspath, bgp->confed_id) >
			    peer->allowas_in[afi][safi]) {
				peer->stat_pfx_aspath_loop++;
				reason = "as-path contains our own confed AS;";
				goto filtered;
			}
		}
	}

	/* Route reflector originator ID check. If ACCEPT_OWN mechanism is
	 * enabled, then take care of that too.
	 */
	bool accept_own = false;

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) &&
	    IPV4_ADDR_SAME(&bgp->router_id, &attr->originator_id)) {
		accept_own =
			bgp_accept_own(peer, afi, safi, attr, p, &sub_type);
		if (!accept_own) {
			peer->stat_pfx_originator_loop++;
			reason = "originator is us;";
			goto filtered;
		}
	}

	/* Route reflector cluster ID check.  */
	if (bgp_cluster_filter(peer, attr)) {
		peer->stat_pfx_cluster_loop++;
		reason = "reflected from the same cluster;";
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
		if (!bgp_inbound_policy_exists(peer, &peer->filter[afi][safi])) {
			reason = "inbound policy missing";
			if (monotime_since(&bgp->ebgprequirespolicywarning, NULL) >
				    FIFTEENMINUTE2USEC ||
			    bgp->ebgprequirespolicywarning.tv_sec == 0) {
				zlog_warn(
					"EBGP inbound/outbound policy not properly setup, please configure in order for your peering to work correctly");
				monotime(&bgp->ebgprequirespolicywarning);
			}
			goto filtered;
		}

	/* Apply incoming filter.  */
	if (bgp_input_filter(peer, p, attr, afi, orig_safi) == FILTER_DENY) {
		peer->stat_pfx_filter++;
		reason = "filter;";
		goto filtered;
	}

	if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_MPLS_VPN &&
	    bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT &&
	    !CHECK_FLAG(bgp->af_flags[afi][safi],
			BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL) &&
	    vpn_leak_to_vrf_no_retain_filter_check(bgp, attr, afi)) {
		reason =
			"no import. Filtered by no bgp retain route-target all";
		goto filtered;
	}

	/* If the route has Node Target Extended Communities, check
	 * if it's allowed to be installed locally.
	 */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
		struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

		if (ecommunity_lookup(ecomm, ECOMMUNITY_ENCODE_IP,
				      ECOMMUNITY_NODE_TARGET) &&
		    !ecommunity_node_target_match(ecomm, &peer->local_id)) {
			reason =
				"Node-Target Extended Communities do not contain own BGP Identifier;";
			goto filtered;
		}
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
	/*
	 * If bgp_update is called with soft_reconfig set then
	 * attr is interned. In this case, do not overwrite the
	 * attr->evpn_overlay with evpn directly. Instead memcpy
	 * evpn to new_atr.evpn_overlay before it is interned.
	 */
	if (soft_reconfig && evpn) {
		if (afi == AFI_L2VPN)
			bgp_attr_set_evpn_overlay(&new_attr, evpn);
		else
			evpn_overlay_free(evpn);
	}

	/* Apply incoming route-map.
	 * NB: new_attr may now contain newly allocated values from route-map
	 * "set"
	 * commands, so we need bgp_attr_flush in the error paths, until we
	 * intern
	 * the attr (which takes over the memory references) */
	if (bgp_input_modifier(peer, p, &new_attr, afi, orig_safi, NULL, label,
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
			bgp_zebra_route_install(dest, pi, bgp, false, NULL,
						false);
	}

	/* rfc7999:
	 * A BGP speaker receiving an announcement tagged with the
	 * BLACKHOLE community SHOULD add the NO_ADVERTISE or
	 * NO_EXPORT community as defined in RFC1997, or a
	 * similar community, to prevent propagation of the
	 * prefix outside the local AS. The community to prevent
	 * propagation SHOULD be chosen according to the operator's
	 * routing policy.
	 */
	if (bgp_attr_get_community(&new_attr) &&
	    community_include(bgp_attr_get_community(&new_attr),
			      COMMUNITY_BLACKHOLE))
		bgp_attr_add_no_export_community(&new_attr);

	if (peer->sort == BGP_PEER_EBGP) {
		/* If we receive the graceful-shutdown community from an eBGP
		 * peer we must lower local-preference */
		if (bgp_attr_get_community(&new_attr) &&
		    community_include(bgp_attr_get_community(&new_attr),
				      COMMUNITY_GSHUT)) {
			SET_FLAG(new_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
			new_attr.local_pref = BGP_GSHUT_LOCAL_PREF;

			/* If graceful-shutdown is configured globally or
			 * per neighbor, then add the GSHUT community to
			 * all paths received from eBGP peers. */
		} else if (bgp_in_graceful_shutdown(peer->bgp) ||
			   CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_SHUTDOWN))
			bgp_attr_add_gshut_community(&new_attr);
	}

	/* next hop check.  */
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD) &&
	    bgp_update_martian_nexthop(bgp, afi, safi, type, sub_type,
				       &new_attr, dest)) {
		peer->stat_pfx_nh_invalid++;
		reason = "martian or self next-hop;";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

	if (safi == SAFI_EVPN && (bgp_mac_entry_exists(p) || bgp_mac_exist(&attr->rmac))) {
		peer->stat_pfx_nh_invalid++;
		reason = "self mac;";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

	if (bgp_check_role_applicability(afi, safi) &&
	    bgp_otc_filter(peer, &new_attr)) {
		reason = "failing otc validation";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

	/* If neighbor soo is configured, tag all incoming routes with
	 * this SoO tag and then filter out advertisements in
	 * subgroup_announce_check() if it matches the configured SoO
	 * on the other peer.
	 */
	if (peer->soo[afi][safi]) {
		struct ecommunity *old_ecomm =
			bgp_attr_get_ecommunity(&new_attr);
		struct ecommunity *ecomm_soo = peer->soo[afi][safi];
		struct ecommunity *new_ecomm;

		if (old_ecomm) {
			new_ecomm = ecommunity_merge(ecommunity_dup(old_ecomm),
						     ecomm_soo);

			if (!old_ecomm->refcnt)
				ecommunity_free(&old_ecomm);
		} else {
			new_ecomm = ecommunity_dup(ecomm_soo);
		}

		bgp_attr_set_ecommunity(&new_attr, new_ecomm);
	}

	attr_new = bgp_attr_intern(&new_attr);

	/* If the update is implicit withdraw. */
	if (pi) {
		pi->uptime = monotime(NULL);
		same_attr = attrhash_cmp(pi->attr, attr_new);

		hook_call(bgp_process, bgp, afi, safi, dest, peer, true);

		/* Same attribute comes in. */
		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) && same_attr &&
		    (!bgp_labels.num_labels ||
		     bgp_path_info_labels_same(pi, bgp_labels.label,
					       bgp_labels.num_labels))) {
			if (get_active_bdc_from_pi(pi, afi, safi) &&
			    peer->sort == BGP_PEER_EBGP &&
			    CHECK_FLAG(pi->flags, BGP_PATH_HISTORY)) {
				if (bgp_debug_update(peer, p, NULL, 1)) {
					bgp_debug_rdpfxpath2str(
						afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, evpn, pfx_buf,
						sizeof(pfx_buf));
					zlog_debug("%pBP rcvd %s", peer,
						   pfx_buf);
				}

				if (bgp_damp_update(pi, dest, afi, safi)
				    != BGP_DAMP_SUPPRESSED) {
					bgp_aggregate_increment(bgp, p, pi, afi,
								safi);
					bgp_process(bgp, dest, pi, afi, safi);
				}
			} else /* Duplicate - odd */
			{
				if (bgp_debug_update(peer, p, NULL, 1)) {
					if (!peer->rcvd_attr_printed) {
						zlog_debug(
							"%pBP rcvd UPDATE w/ attr: %s",
							peer,
							peer->rcvd_attr_str);
						peer->rcvd_attr_printed = true;
					}

					bgp_debug_rdpfxpath2str(
						afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, evpn, pfx_buf,
						sizeof(pfx_buf));
					zlog_debug(
						"%pBP rcvd %s...duplicate ignored",
						peer, pfx_buf);
				}

				/* graceful restart STALE flag unset. */
				if (CHECK_FLAG(pi->flags, BGP_PATH_STALE)) {
					bgp_path_info_unset_flag(
						dest, pi, BGP_PATH_STALE);
					bgp_dest_set_defer_flag(dest, false);
					bgp_process(bgp, dest, pi, afi, safi);
				}
			}

			bgp_dest_unlock_node(dest);
			bgp_attr_unintern(&attr_new);

			return;
		}

		/* Withdraw/Announce before we fully processed the withdraw */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			if (bgp_debug_update(peer, p, NULL, 1)) {
				bgp_debug_rdpfxpath2str(
					afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, evpn,
					pfx_buf, sizeof(pfx_buf));
				zlog_debug(
					"%pBP rcvd %s, flapped quicker than processing",
					peer, pfx_buf);
			}

			bgp_path_info_restore(dest, pi);

			/*
			 * If the BGP_PATH_REMOVED flag is set, then EVPN
			 * routes would have been unimported already when a
			 * prior BGP withdraw processing happened. Such routes
			 * need to be imported again, so flag accordingly.
			 */
			force_evpn_import = true;
		} else {
			/* implicit withdraw, decrement aggregate and pcount
			 * here. only if update is accepted, they'll increment
			 * below.
			 */
			bgp_aggregate_decrement(bgp, p, pi, afi, safi);
		}

		/* Received Logging. */
		if (bgp_debug_update(peer, p, NULL, 1)) {
			bgp_debug_rdpfxpath2str(afi, safi, prd, p, label,
						num_labels, addpath_id ? 1 : 0,
						addpath_id, evpn, pfx_buf,
						sizeof(pfx_buf));
			zlog_debug("%pBP rcvd %s", peer, pfx_buf);
		}

		/* graceful restart STALE flag unset. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_STALE)) {
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_STALE);
			bgp_dest_set_defer_flag(dest, false);
		}

		/* The attribute is changed. */
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);

		/* Update bgp route dampening information.  */
		if (get_active_bdc_from_pi(pi, afi, safi) &&
		    peer->sort == BGP_PEER_EBGP) {
			/* This is implicit withdraw so we should update
			 * dampening information.
			 */
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
			if (CHECK_FLAG(pi->attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) &&
			    CHECK_FLAG(attr_new->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
				int cmp;

				cmp = ecommunity_cmp(
					bgp_attr_get_ecommunity(pi->attr),
					bgp_attr_get_ecommunity(attr_new));
				if (!cmp) {
					if (bgp_debug_update(peer, p, NULL, 1))
						zlog_debug(
							"Change in EXT-COMM, existing %s new %s",
							ecommunity_str(
								bgp_attr_get_ecommunity(
									pi->attr)),
							ecommunity_str(
								bgp_attr_get_ecommunity(
									attr_new)));
					if (safi == SAFI_EVPN)
						bgp_evpn_unimport_route(
							bgp, afi, safi, p, pi);
					else /* SAFI_MPLS_VPN */
						vpn_leak_to_vrf_withdraw(pi);
				}
			}
		}

		/* Update to new attribute.  */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;

		/* Update MPLS label */
		if (!bgp_path_info_labels_same(pi, &bgp_labels.label[0],
					       bgp_labels.num_labels)) {
			bgp_path_info_extra_get(pi);
			bgp_labels_unintern(&pi->extra->labels);
			pi->extra->labels = bgp_labels_intern(&bgp_labels);
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
		if (get_active_bdc_from_pi(pi, afi, safi) &&
		    peer->sort == BGP_PEER_EBGP) {
			/* Now we do normal update dampening.  */
			ret = bgp_damp_update(pi, dest, afi, safi);
			if (ret == BGP_DAMP_SUPPRESSED) {
				bgp_dest_unlock_node(dest);
				return;
			}
		}

		bgp_update_nexthop_reachability_check(bgp, peer, dest, p, afi, safi, pi, attr_new,
						      bgp_nht_param_prefix, accept_own);
		/* Nexthop reachability check - for unicast and
		 * labeled-unicast.. */


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
		 * or we are explicitly told to perform a route import, process
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
		if (safi == SAFI_EVPN) {
			if ((!same_attr || force_evpn_import) &&
			    CHECK_FLAG(pi->flags, BGP_PATH_VALID))
				bgp_evpn_import_route(bgp, afi, safi, p, pi);

			/* If existing path is marked invalid then unimport the
			 * path from EVPN prefix. This will ensure EVPN route
			 * has only valid paths and path refcount maintained in
			 * EVPN nexthop is decremented appropriately.
			 */
			else if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID)) {
				if (BGP_DEBUG(nht, NHT))
					zlog_debug("%s unimport EVPN %pFX as pi %p is not VALID",
						   __func__, p, pi);
				bgp_evpn_unimport_route(bgp, afi, safi, p, pi);
			}
		}

		/* Process change. */
		bgp_aggregate_increment(bgp, p, pi, afi, safi);

		bgp_process(bgp, dest, pi, afi, safi);
		bgp_dest_unlock_node(dest);

		if (SAFI_UNICAST == safi
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
			|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {

			vpn_leak_from_vrf_update(bgp_get_default(), bgp, pi);
		}
		if ((SAFI_MPLS_VPN == safi)
		    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
			vpn_leak_to_vrf_update(bgp, pi, prd);
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
		return;
	} // End of implicit withdraw

	/* Received Logging. */
	if (bgp_debug_update(peer, p, NULL, 1)) {
		if (!peer->rcvd_attr_printed) {
			zlog_debug("%pBP rcvd UPDATE w/ attr: %s", peer,
				   peer->rcvd_attr_str);
			peer->rcvd_attr_printed = true;
		}

		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, evpn,
					pfx_buf, sizeof(pfx_buf));
		zlog_debug("%pBP rcvd %s", peer, pfx_buf);
	}

	/* Make new BGP info. */
	new = info_make(type, sub_type, 0, peer, attr_new, dest);

	/* Update MPLS label */
	bgp_path_info_extra_get(new);
	new->extra->labels = bgp_labels_intern(&bgp_labels);

	bgp_update_nexthop_reachability_check(bgp, peer, dest, p, afi, safi, new, attr_new,
					      bgp_nht_param_prefix, accept_own);
	/* If maximum prefix count is configured and current prefix
	 * count exeed it.
	 */
	if (bgp_maximum_prefix_overflow(peer, afi, safi, 0)) {
		reason = "maximum-prefix overflow";
		bgp_attr_flush(&new_attr);
		goto filtered;
	}

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
	bgp_process(bgp, dest, new, afi, safi);

	if (SAFI_UNICAST == safi
	    && (bgp->inst_type == BGP_INSTANCE_TYPE_VRF
		|| bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
		vpn_leak_from_vrf_update(bgp_get_default(), bgp, new);
	}
	if ((SAFI_MPLS_VPN == safi)
	    && (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
		vpn_leak_to_vrf_update(bgp, new, prd);
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

	return;

/* This BGP update is filtered.  Log the reason then update BGP
   entry.  */
filtered:
	if (new) {
		bgp_unlink_nexthop(new);
		bgp_path_info_delete(dest, new);
		bgp_path_info_extra_free(&new->extra);
		XFREE(MTYPE_BGP_ROUTE, new);
	}

	hook_call(bgp_process, bgp, afi, safi, dest, peer, true);

	if (bgp_debug_update(peer, p, NULL, 1)) {
		if (!peer->rcvd_attr_printed) {
			zlog_debug("%pBP rcvd UPDATE w/ attr: %s", peer,
				   peer->rcvd_attr_str);
			peer->rcvd_attr_printed = true;
		}

		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, evpn,
					pfx_buf, sizeof(pfx_buf));
		zlog_debug("%pBP rcvd UPDATE about %s -- DENIED due to: %s",
			   peer, pfx_buf, reason);
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

			vpn_leak_to_vrf_withdraw(pi);
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

	return;
}

void bgp_withdraw(struct peer *peer, const struct prefix *p,
		  uint32_t addpath_id, afi_t afi, safi_t safi, int type,
		  int sub_type, struct prefix_rd *prd, mpls_label_t *label,
		  uint8_t num_labels)
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
		if (!bgp_adj_in_unset(&dest, peer, addpath_id)) {
			assert(dest);
			peer->stat_pfx_dup_withdraw++;

			if (bgp_debug_update(peer, p, NULL, 1)) {
				bgp_debug_rdpfxpath2str(
					afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, NULL,
					pfx_buf, sizeof(pfx_buf));
				zlog_debug(
					"%s withdrawing route %s not in adj-in",
					peer->host, pfx_buf);
			}
			bgp_dest_unlock_node(dest);
			return;
		}

	/* Lookup withdrawn route. */
	assert(dest);
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == type
		    && pi->sub_type == sub_type
		    && pi->addpath_rx_id == addpath_id)
			break;

	/* Logging. */
	if (bgp_debug_update(peer, p, NULL, 1)) {
		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, NULL,
					pfx_buf, sizeof(pfx_buf));
		zlog_debug("%pBP rcvd UPDATE about %s -- withdrawn", peer,
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

			vpn_leak_to_vrf_withdraw(pi);
		}
	} else if (bgp_debug_update(peer, p, NULL, 1)) {
		bgp_debug_rdpfxpath2str(afi, safi, prd, p, label, num_labels,
					addpath_id ? 1 : 0, addpath_id, NULL,
					pfx_buf, sizeof(pfx_buf));
		zlog_debug("%s Can't find the route %s", peer->host, pfx_buf);
	}

	/* Unlock bgp_node_get() lock. */
	bgp_dest_unlock_node(dest);

	return;
}

void bgp_default_originate(struct peer *peer, afi_t afi, safi_t safi,
			   bool withdraw)
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

	EVENT_OFF(paf->t_announce_route);
}

/*
 * bgp_announce_route_timer_expired
 *
 * Callback that is invoked when the route announcement timer for a
 * peer_af expires.
 */
static void bgp_announce_route_timer_expired(struct event *t)
{
	struct peer_af *paf;
	struct peer *peer;

	paf = EVENT_ARG(t);
	peer = paf->peer;

	if (!peer_established(peer->connection))
		return;

	if (!peer->afc_nego[paf->afi][paf->safi])
		return;

	peer_af_announce_route(paf, 1);

	/* Notify BGP conditional advertisement scanner percess */
	peer->advmap_config_change[paf->afi][paf->safi] = true;
}

/*
 * bgp_announce_route
 *
 * *Triggers* announcement of routes of a given AFI/SAFI to a peer.
 *
 * if force is true we will force an update even if the update
 * limiting code is attempted to kick in.
 */
void bgp_announce_route(struct peer *peer, afi_t afi, safi_t safi, bool force)
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

	if (force)
		SET_FLAG(subgrp->sflags, SUBGRP_STATUS_FORCE_UPDATES);

	/*
	 * Start a timer to stagger/delay the announce. This serves
	 * two purposes - announcement can potentially be combined for
	 * multiple peers and the announcement doesn't happen in the
	 * vty context.
	 */
	event_add_timer_msec(bm->master, bgp_announce_route_timer_expired, paf,
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
		bgp_announce_route(peer, afi, safi, false);
}

/* Flag or unflag bgp_dest to determine whether it should be treated by
 * bgp_soft_reconfig_table_task.
 * Flag if flag is true. Unflag if flag is false.
 */
static void bgp_soft_reconfig_table_flag(struct bgp_table *table, bool flag)
{
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;

	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (ain = dest->adj_in; ain; ain = ain->next) {
			if (ain->peer != NULL)
				break;
		}
		if (flag && ain != NULL && ain->peer != NULL)
			SET_FLAG(dest->flags, BGP_NODE_SOFT_RECONFIG);
		else
			UNSET_FLAG(dest->flags, BGP_NODE_SOFT_RECONFIG);
	}
}

static void bgp_soft_reconfig_table_update(struct peer *peer,
					   struct bgp_dest *dest,
					   struct bgp_adj_in *ain, afi_t afi,
					   safi_t safi, struct prefix_rd *prd)
{
	struct bgp_path_info *pi;
	uint8_t num_labels;
	mpls_label_t *label_pnt;
	struct bgp_route_evpn *bre = NULL;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer)
			break;

	num_labels = ain->labels ? ain->labels->num_labels : 0;
	label_pnt = num_labels ? &ain->labels->label[0] : NULL;

	if (pi)
		bre = bgp_attr_get_evpn_overlay(pi->attr);

	bgp_update(peer, bgp_dest_get_prefix(dest), ain->addpath_rx_id,
		   ain->attr, afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, prd,
		   label_pnt, num_labels, 1, bre);
}

static void bgp_soft_reconfig_table(struct peer *peer, afi_t afi, safi_t safi,
				    struct bgp_table *table,
				    struct prefix_rd *prd)
{
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;

	if (!table)
		table = peer->bgp->rib[afi][safi];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (ain = dest->adj_in; ain; ain = ain->next) {
			if (ain->peer != peer)
				continue;

			bgp_soft_reconfig_table_update(peer, dest, ain, afi,
						       safi, prd);
		}
}

/* Do soft reconfig table per bgp table.
 * Walk on SOFT_RECONFIG_TASK_MAX_PREFIX bgp_dest,
 * when BGP_NODE_SOFT_RECONFIG is set,
 * reconfig bgp_dest for list of table->soft_reconfig_peers peers.
 * Schedule a new thread to continue the job.
 * Without splitting the full job into several part,
 * vtysh waits for the job to finish before responding to a BGP command
 */
static void bgp_soft_reconfig_table_task(struct event *thread)
{
	uint32_t iter, max_iter;
	struct bgp_dest *dest;
	struct bgp_adj_in *ain;
	struct peer *peer;
	struct bgp_table *table;
	struct prefix_rd *prd;
	struct listnode *node, *nnode;

	table = EVENT_ARG(thread);
	prd = NULL;

	max_iter = SOFT_RECONFIG_TASK_MAX_PREFIX;
	if (table->soft_reconfig_init) {
		/* first call of the function with a new srta structure.
		 * Don't do any treatment this time on nodes
		 * in order vtysh to respond quickly
		 */
		max_iter = 0;
	}

	for (iter = 0, dest = bgp_table_top(table); (dest && iter < max_iter);
	     dest = bgp_route_next(dest)) {
		if (!CHECK_FLAG(dest->flags, BGP_NODE_SOFT_RECONFIG))
			continue;

		UNSET_FLAG(dest->flags, BGP_NODE_SOFT_RECONFIG);

		for (ain = dest->adj_in; ain; ain = ain->next) {
			for (ALL_LIST_ELEMENTS(table->soft_reconfig_peers, node,
					       nnode, peer)) {
				if (ain->peer != peer)
					continue;

				bgp_soft_reconfig_table_update(
					peer, dest, ain, table->afi,
					table->safi, prd);
				iter++;
			}
		}
	}

	/* we're either starting the initial iteration,
	 * or we're going to continue an ongoing iteration
	 */
	if (dest || table->soft_reconfig_init) {
		table->soft_reconfig_init = false;
		event_add_event(bm->master, bgp_soft_reconfig_table_task, table,
				0, &table->soft_reconfig_thread);
		return;
	}
	/* we're done, clean up the background iteration context info and
	schedule route annoucement
	*/
	for (ALL_LIST_ELEMENTS(table->soft_reconfig_peers, node, nnode, peer)) {
		listnode_delete(table->soft_reconfig_peers, peer);
		bgp_announce_route(peer, table->afi, table->safi, false);
	}

	list_delete(&table->soft_reconfig_peers);
}


/* Cancel soft_reconfig_table task matching bgp instance, bgp_table
 * and peer.
 * - bgp cannot be NULL
 * - if table and peer are NULL, cancel all threads within the bgp instance
 * - if table is NULL and peer is not,
 * remove peer in all threads within the bgp instance
 * - if peer is NULL, cancel all threads matching table within the bgp instance
 */
void bgp_soft_reconfig_table_task_cancel(const struct bgp *bgp,
					 const struct bgp_table *table,
					 const struct peer *peer)
{
	struct peer *npeer;
	struct listnode *node, *nnode;
	int afi, safi;
	struct bgp_table *ntable;

	if (!bgp)
		return;

	FOREACH_AFI_SAFI (afi, safi) {
		ntable = bgp->rib[afi][safi];
		if (!ntable)
			continue;
		if (table && table != ntable)
			continue;

		for (ALL_LIST_ELEMENTS(ntable->soft_reconfig_peers, node, nnode,
				       npeer)) {
			if (peer && peer != npeer)
				continue;
			listnode_delete(ntable->soft_reconfig_peers, npeer);
		}

		if (!ntable->soft_reconfig_peers
		    || !list_isempty(ntable->soft_reconfig_peers))
			continue;

		list_delete(&ntable->soft_reconfig_peers);
		bgp_soft_reconfig_table_flag(ntable, false);
		EVENT_OFF(ntable->soft_reconfig_thread);
	}
}

/*
 * Returns false if the peer is not configured for soft reconfig in
 */
bool bgp_soft_reconfig_in(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct listnode *node, *nnode;
	struct peer *npeer;
	struct peer_af *paf;

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
		return false;

	if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP)
	    && (safi != SAFI_EVPN)) {
		table = peer->bgp->rib[afi][safi];
		if (!table)
			return true;

		table->soft_reconfig_init = true;

		if (!table->soft_reconfig_peers)
			table->soft_reconfig_peers = list_new();
		npeer = NULL;
		/* add peer to the table soft_reconfig_peers if not already
		 * there
		 */
		for (ALL_LIST_ELEMENTS(table->soft_reconfig_peers, node, nnode,
				       npeer)) {
			if (peer == npeer)
				break;
		}
		if (peer != npeer)
			listnode_add(table->soft_reconfig_peers, peer);

		/* (re)flag all bgp_dest in table. Existing soft_reconfig_in job
		 * on table would start back at the beginning.
		 */
		bgp_soft_reconfig_table_flag(table, true);

		if (!table->soft_reconfig_thread)
			event_add_event(bm->master,
					bgp_soft_reconfig_table_task, table, 0,
					&table->soft_reconfig_thread);
		/* Cancel bgp_announce_route_timer_expired threads.
		 * bgp_announce_route_timer_expired threads have been scheduled
		 * to announce routes as soon as the soft_reconfigure process
		 * finishes.
		 * In this case, soft_reconfigure is also scheduled by using
		 * a thread but is planned after the
		 * bgp_announce_route_timer_expired threads. It means that,
		 * without cancelling the threads, the route announcement task
		 * would run before the soft reconfiguration one. That would
		 * useless and would block vtysh during several seconds. Route
		 * announcements are rescheduled as soon as the soft_reconfigure
		 * process finishes.
		 */
		paf = peer_af_find(peer, afi, safi);
		if (paf)
			bgp_stop_announce_route_timer(paf);
	} else
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

	return true;
}


struct bgp_clear_node_queue {
	struct bgp_dest *dest;
};

static wq_item_status bgp_clear_route_node(struct work_queue *wq, void *data)
{
	struct bgp_clear_node_queue *cnq = data;
	struct bgp_dest *dest = cnq->dest;
	struct peer *peer = wq->spec.data;
	struct bgp_path_info *pi, *next;
	struct bgp *bgp;
	afi_t afi = bgp_dest_table(dest)->afi;
	safi_t safi = bgp_dest_table(dest)->safi;

	assert(dest && peer);
	bgp = peer->bgp;

	/* It is possible that we have multiple paths for a prefix from a peer
	 * if that peer is using AddPath.
	 */
	for (pi = bgp_dest_get_bgp_path_info(dest);
	     (pi != NULL) && (next = pi->next, 1); pi = next) {
		if (pi->peer != peer)
			continue;

		/* graceful restart STALE flag set. */
		if (((CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)
		      && peer->nsf[afi][safi])
		     || CHECK_FLAG(peer->af_sflags[afi][safi],
				   PEER_STATUS_ENHANCED_REFRESH))
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
				vpn_leak_to_vrf_withdraw(pi);
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
	BGP_EVENT_ADD(peer->connection, Clearing_Completed);

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

			if (ain->peer == peer)
				bgp_adj_in_remove(&dest, ain);

			ain = ain_next;

			assert(dest);
		}

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = next) {
			next = pi->next;
			if (pi->peer != peer)
				continue;

			if (force) {
				dest = bgp_path_info_reap(dest, pi);
				assert(dest);
			} else {
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

			if (ain->peer == peer)
				bgp_adj_in_remove(&dest, ain);

			ain = ain_next;

			assert(dest);
		}
	}
}

/* If any of the routes from the peer have been marked with the NO_LLGR
 * community, either as sent by the peer, or as the result of a configured
 * policy, they MUST NOT be retained, but MUST be removed as per the normal
 * operation of [RFC4271].
 */
void bgp_clear_stale_route(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi, *next;
	struct bgp_table *table;

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_dest *rm;

			/* look for neighbor in tables */
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				for (pi = bgp_dest_get_bgp_path_info(rm);
				     (pi != NULL) && (next = pi->next, 1);
				     pi = next) {
					if (pi->peer != peer)
						continue;
					if (CHECK_FLAG(
						    peer->af_sflags[afi][safi],
						    PEER_STATUS_LLGR_WAIT) &&
					    bgp_attr_get_community(pi->attr) &&
					    !community_include(
						    bgp_attr_get_community(
							    pi->attr),
						    COMMUNITY_NO_LLGR))
						continue;
					if (!CHECK_FLAG(pi->flags,
							BGP_PATH_STALE))
						continue;

					/*
					 * If this is VRF leaked route
					 * process for withdraw.
					 */
					if (pi->sub_type ==
						    BGP_ROUTE_IMPORTED &&
					    peer->bgp->inst_type ==
						    BGP_INSTANCE_TYPE_DEFAULT)
						vpn_leak_to_vrf_withdraw(pi);

					bgp_rib_remove(rm, pi, peer, afi, safi);
					break;
				}
		}
	} else {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest))
			for (pi = bgp_dest_get_bgp_path_info(dest);
			     (pi != NULL) && (next = pi->next, 1); pi = next) {
				if (pi->peer != peer)
					continue;
				if (CHECK_FLAG(peer->af_sflags[afi][safi],
					       PEER_STATUS_LLGR_WAIT) &&
				    bgp_attr_get_community(pi->attr) &&
				    !community_include(
					    bgp_attr_get_community(pi->attr),
					    COMMUNITY_NO_LLGR))
					continue;
				if (!CHECK_FLAG(pi->flags, BGP_PATH_STALE))
					continue;
				if (safi == SAFI_UNICAST &&
				    (peer->bgp->inst_type ==
					     BGP_INSTANCE_TYPE_VRF ||
				     peer->bgp->inst_type ==
					     BGP_INSTANCE_TYPE_DEFAULT))
					vpn_leak_from_vrf_withdraw(
						bgp_get_default(), peer->bgp,
						pi);

				bgp_rib_remove(dest, pi, peer, afi, safi);
				break;
			}
	}
}

void bgp_set_stale_route(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest, *ndest;
	struct bgp_path_info *pi;
	struct bgp_table *table;

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			for (ndest = bgp_table_top(table); ndest;
			     ndest = bgp_route_next(ndest)) {
				for (pi = bgp_dest_get_bgp_path_info(ndest); pi;
				     pi = pi->next) {
					if (pi->peer != peer)
						continue;

					if ((CHECK_FLAG(
						    peer->af_sflags[afi][safi],
						    PEER_STATUS_ENHANCED_REFRESH))
					    && !CHECK_FLAG(pi->flags,
							   BGP_PATH_STALE)
					    && !CHECK_FLAG(
						       pi->flags,
						       BGP_PATH_UNUSEABLE)) {
						if (bgp_debug_neighbor_events(
							    peer))
							zlog_debug(
								"%pBP route-refresh for %s/%s, marking prefix %pFX as stale",
								peer,
								afi2str(afi),
								safi2str(safi),
								bgp_dest_get_prefix(
									ndest));

						bgp_path_info_set_flag(
							ndest, pi,
							BGP_PATH_STALE);
					}
				}
			}
		}
	} else {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;

				if ((CHECK_FLAG(peer->af_sflags[afi][safi],
						PEER_STATUS_ENHANCED_REFRESH))
				    && !CHECK_FLAG(pi->flags, BGP_PATH_STALE)
				    && !CHECK_FLAG(pi->flags,
						   BGP_PATH_UNUSEABLE)) {
					if (bgp_debug_neighbor_events(peer))
						zlog_debug(
							"%pBP route-refresh for %s/%s, marking prefix %pFX as stale",
							peer, afi2str(afi),
							safi2str(safi),
							bgp_dest_get_prefix(
								dest));

					bgp_path_info_set_flag(dest, pi,
							       BGP_PATH_STALE);
				}
			}
		}
	}
}

bool bgp_outbound_policy_exists(struct peer *peer, struct bgp_filter *filter)
{
	if (peer->sort == BGP_PEER_CONFED || peer->sort == BGP_PEER_IBGP ||
	    peer->sub_sort == BGP_PEER_EBGP_OAD)
		return true;

	if (peer->sort == BGP_PEER_EBGP &&
	    (ROUTE_MAP_OUT_NAME(filter) || PREFIX_LIST_OUT_NAME(filter) ||
	     FILTER_LIST_OUT_NAME(filter) || DISTRIBUTE_OUT_NAME(filter) ||
	     UNSUPPRESS_MAP_NAME(filter)))
		return true;
	return false;
}

bool bgp_inbound_policy_exists(struct peer *peer, struct bgp_filter *filter)
{
	if (peer->sort == BGP_PEER_CONFED || peer->sort == BGP_PEER_IBGP ||
	    peer->sub_sort == BGP_PEER_EBGP_OAD)
		return true;

	if (peer->sort == BGP_PEER_EBGP
	    && (ROUTE_MAP_IN_NAME(filter) || PREFIX_LIST_IN_NAME(filter)
		|| FILTER_LIST_IN_NAME(filter)
		|| DISTRIBUTE_IN_NAME(filter)))
		return true;
	return false;
}

static void bgp_cleanup_table(struct bgp *bgp, struct bgp_table *table,
			      afi_t afi, safi_t safi)
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
					bgp_zebra_withdraw_actual(dest, pi, bgp);
			}

			dest = bgp_path_info_reap(dest, pi);
			assert(dest);
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
		bgp_cleanup_table(bgp, bgp->rib[afi][SAFI_UNICAST], afi,
				  SAFI_UNICAST);
		/*
		 * VPN and ENCAP and EVPN tables are two-level (RD is top level)
		 */
		if (afi != AFI_L2VPN) {
			safi_t safi;
			safi = SAFI_MPLS_VPN;
			if (!IS_BGP_INSTANCE_HIDDEN(bgp)) {
				for (dest = bgp_table_top(bgp->rib[afi][safi]);
				     dest; dest = bgp_route_next(dest)) {
					table = bgp_dest_get_bgp_table_info(
						dest);
					if (table != NULL) {
						bgp_cleanup_table(bgp, table,
								  afi, safi);
						bgp_table_finish(&table);
						bgp_dest_set_bgp_table_info(dest,
									    NULL);
						dest = bgp_dest_unlock_node(
							dest);
						assert(dest);
					}
				}
			}
			safi = SAFI_ENCAP;
			for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
			     dest = bgp_route_next(dest)) {
				table = bgp_dest_get_bgp_table_info(dest);
				if (table != NULL) {
					bgp_cleanup_table(bgp, table, afi, safi);
					bgp_table_finish(&table);
					bgp_dest_set_bgp_table_info(dest, NULL);
					dest = bgp_dest_unlock_node(dest);

					assert(dest);
				}
			}
		}
	}
	for (dest = bgp_table_top(bgp->rib[AFI_L2VPN][SAFI_EVPN]); dest;
	     dest = bgp_route_next(dest)) {
		table = bgp_dest_get_bgp_table_info(dest);
		if (table != NULL) {
			bgp_cleanup_table(bgp, table, afi, SAFI_EVPN);
			bgp_table_finish(&table);
			bgp_dest_set_bgp_table_info(dest, NULL);
			dest = bgp_dest_unlock_node(dest);

			assert(dest);
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

bool bgp_addpath_encode_rx(struct peer *peer, afi_t afi, safi_t safi)
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
	afi_t afi;
	safi_t safi;
	bool addpath_capable;
	uint32_t addpath_id;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;
	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	/* RFC4271 6.3 The NLRI field in the UPDATE message is checked for
	   syntactic validity.  If the field is syntactically incorrect,
	   then the Error Subcode is set to Invalid Network Field. */
	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		if (addpath_capable) {

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
		 * prefix for the v4 and v6 afi's and unicast/multicast */
		if (psize > (ssize_t)sizeof(p.u.val)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error (prefix length %d too large for prefix storage %zu)",
				peer->host, p.prefixlen, sizeof(p.u.val));
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
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is link-local address %pI6, ignoring",
					peer->host, &p.u.prefix6);

				continue;
			}
			if (IN6_IS_ADDR_MULTICAST(&p.u.prefix6)) {
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is multicast address %pI6, ignoring",
					peer->host, &p.u.prefix6);

				continue;
			}
		}

		/* Normal process. */
		if (attr)
			bgp_update(peer, &p, addpath_id, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
		else
			bgp_withdraw(peer, &p, addpath_id, afi, safi,
				     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				     NULL, 0);

		/* Do not send BGP notification twice when maximum-prefix count
		 * overflow. */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
			return BGP_NLRI_PARSE_ERROR_PREFIX_OVERFLOW;
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

static void bgp_nexthop_reachability_check(afi_t afi, safi_t safi,
					   struct bgp_path_info *bpi,
					   const struct prefix *p,
					   struct bgp_dest *dest,
					   struct bgp *bgp,
					   struct bgp *bgp_nexthop)
{
	/* Nexthop reachability check. */
	if (safi == SAFI_UNICAST || safi == SAFI_LABELED_UNICAST) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)) {
			if (bgp_find_or_add_nexthop(bgp, bgp_nexthop, afi, safi,
						    bpi, NULL, 0, p))
				bgp_path_info_set_flag(dest, bpi,
						       BGP_PATH_VALID);
			else {
				if (BGP_DEBUG(nht, NHT)) {
					char buf1[INET6_ADDRSTRLEN];

					inet_ntop(p->family, &p->u.prefix, buf1,
						  sizeof(buf1));
					zlog_debug("%s(%s): Route not in table, not advertising",
						   __func__, buf1);
				}
				bgp_path_info_unset_flag(dest, bpi,
							 BGP_PATH_VALID);
			}
		} else {
			/* Delete the NHT structure if any, if we're toggling between
			* enabling/disabling import check. We deregister the route
			* from NHT to avoid overloading NHT and the process interaction
			*/
			bgp_unlink_nexthop(bpi);

			bgp_path_info_set_flag(dest, bpi, BGP_PATH_VALID);
		}
	}
}

static struct bgp_static *bgp_static_new(void)
{
	return XCALLOC(MTYPE_BGP_STATIC, sizeof(struct bgp_static));
}

static void bgp_static_free(struct bgp_static *bgp_static)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
	route_map_counter_decrement(bgp_static->rmap.map);

	if (bgp_static->prd_pretty)
		XFREE(MTYPE_BGP_NAME, bgp_static->prd_pretty);
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
	mpls_label_t label = MPLS_INVALID_LABEL;
#endif
	uint8_t num_labels = 0;
	struct bgp *bgp_nexthop = bgp;
	struct bgp_labels labels = {};

	assert(bgp_static);

	if ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) &&
	    bgp_static->label != MPLS_INVALID_LABEL)
		num_labels = 1;

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p,
				&bgp_static->prd);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);

	attr.nexthop = bgp_static->igpnexthop;

	bgp_attr_set_med(&attr, bgp_static->igpmetric);

	if (afi == AFI_IP)
		attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	if (bgp_static->atomic)
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE));

	/* Store label index, if required. */
	if (bgp_static->label_index != BGP_INVALID_LABEL_INDEX) {
		attr.label_index = bgp_static->label_index;
		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));
	}

	if (safi == SAFI_EVPN || safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP) {
		if (afi == AFI_IP) {
			attr.mp_nexthop_global_in = bgp_static->igpnexthop;
			attr.mp_nexthop_len = IPV4_MAX_BYTELEN;
		}
	}

	if (afi == AFI_L2VPN) {
		if (bgp_static->gatewayIp.family == AF_INET) {
			struct bgp_route_evpn *bre =
				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					sizeof(struct bgp_route_evpn));

			SET_IPADDR_V4(&bre->gw_ip);
			memcpy(&bre->gw_ip.ipaddr_v4,
			       &bgp_static->gatewayIp.u.prefix4,
			       IPV4_MAX_BYTELEN);
			bgp_attr_set_evpn_overlay(&attr, bre);
		} else if (bgp_static->gatewayIp.family == AF_INET6) {
			struct bgp_route_evpn *bre =
				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					sizeof(struct bgp_route_evpn));

			SET_IPADDR_V6(&bre->gw_ip);
			memcpy(&bre->gw_ip.ipaddr_v6,
			       &bgp_static->gatewayIp.u.prefix6,
			       IPV6_MAX_BYTELEN);
			bgp_attr_set_evpn_overlay(&attr, bre);
		}
		memcpy(&attr.esi, bgp_static->eth_s_id, sizeof(esi_t));
		if (bgp_static->encap_tunneltype == BGP_ENCAP_TYPE_VXLAN) {
			struct bgp_encap_type_vxlan bet;
			memset(&bet, 0, sizeof(bet));
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

		memset(&rmap_path, 0, sizeof(rmap_path));
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
			bgp_static_withdraw(bgp, p, afi, safi, &bgp_static->prd);
			bgp_dest_unlock_node(dest);
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
			if ((afi == AFI_IP || afi == AFI_IP6) &&
			    safi == SAFI_UNICAST) {
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
			pi->uptime = monotime(NULL);
#ifdef ENABLE_BGP_VNC
			if ((afi == AFI_IP || afi == AFI_IP6) &&
			    safi == SAFI_UNICAST) {
				if (vnc_implicit_withdraw) {
					vnc_import_bgp_add_route(bgp, p, pi);
					vnc_import_bgp_exterior_add_route(
						bgp, p, pi);
				}
			} else {
				if (BGP_PATH_INFO_NUM_LABELS(pi))
					label = decode_label(
						&pi->extra->labels->label[0]);
			}
#endif
			if (pi->extra && pi->extra->vrfleak->bgp_orig)
				bgp_nexthop = pi->extra->vrfleak->bgp_orig;

			bgp_nexthop_reachability_check(afi, safi, pi, p, dest,
						       bgp, bgp_nexthop);

			/* Process change. */
			bgp_aggregate_increment(bgp, p, pi, afi, safi);
			bgp_process(bgp, dest, pi, afi, safi);

			if (SAFI_MPLS_VPN == safi &&
			    bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
				vpn_leak_to_vrf_update(bgp, pi,
						       &bgp_static->prd);
			}
#ifdef ENABLE_BGP_VNC
			if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP ||
			    safi == SAFI_EVPN)
				rfapiProcessUpdate(pi->peer, NULL, p,
						   &bgp_static->prd, pi->attr,
						   afi, safi, pi->type,
						   pi->sub_type, &label);
#endif

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

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) {
		SET_FLAG(new->flags, BGP_PATH_VALID);
		bgp_path_info_extra_get(new);
		if (num_labels) {
			labels.num_labels = num_labels;
			labels.label[0] = bgp_static->label;
			new->extra->labels = bgp_labels_intern(&labels);
		}
#ifdef ENABLE_BGP_VNC
		label = decode_label(&bgp_static->label);
#endif
	}

	bgp_nexthop_reachability_check(afi, safi, new, p, dest, bgp, bgp);

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, p, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, new, afi, safi);

	if (SAFI_UNICAST == safi &&
	    (bgp->inst_type == BGP_INSTANCE_TYPE_VRF ||
	     bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
		vpn_leak_from_vrf_update(bgp_get_default(), bgp, new);
	}

	if (SAFI_MPLS_VPN == safi &&
	    bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
		vpn_leak_to_vrf_update(bgp, new, &bgp_static->prd);
	}
#ifdef ENABLE_BGP_VNC
	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN)
		rfapiProcessUpdate(new->peer, NULL, p, &bgp_static->prd,
				   new->attr, afi, safi, new->type,
				   new->sub_type, &label);
#endif

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

void bgp_static_withdraw(struct bgp *bgp, const struct prefix *p, afi_t afi,
			 safi_t safi, struct prefix_rd *prd)
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
		SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
#ifdef ENABLE_BGP_VNC
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
			rfapiProcessWithdraw(pi->peer, NULL, p, prd, pi->attr,
					     afi, safi, pi->type,
					     1); /* Kill, since it is an administrative change */
#endif
		if (SAFI_UNICAST == safi &&
		    (bgp->inst_type == BGP_INSTANCE_TYPE_VRF ||
		     bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)) {
			vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp, pi);
		}
		if (SAFI_MPLS_VPN == safi
		    && bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			vpn_leak_to_vrf_withdraw(pi);
		}
		bgp_aggregate_decrement(bgp, p, pi, afi, safi);
		bgp_unlink_nexthop(pi);
		bgp_path_info_delete(dest, pi);
		bgp_process(bgp, dest, pi, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
	bgp_dest_unlock_node(dest);
}

/* Configure static BGP network.  When user don't run zebra, static
   route should be installed as valid.  */
int bgp_static_set(struct vty *vty, bool negate, const char *ip_str,
		   const char *rd_str, const char *label_str, afi_t afi,
		   safi_t safi, const char *rmap, int backdoor,
		   uint32_t label_index, int evpn_type, const char *esi,
		   const char *gwip, const char *ethtag, const char *routermac)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix p;
	struct bgp_static *bgp_static;
	struct prefix_rd prd = {};
	struct bgp_dest *pdest;
	struct bgp_dest *dest;
	struct bgp_table *table;
	uint8_t need_update = 0;
	mpls_label_t label = MPLS_INVALID_LABEL;
	struct prefix gw_ip;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(ip_str, &p);
	if (!ret) {
		vty_out(vty, "%% Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
		vty_out(vty, "%% Malformed prefix (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&p);

	if (afi == AFI_L2VPN &&
	    (bgp_build_evpn_prefix(evpn_type, ethtag != NULL ? atol(ethtag) : 0,
				   &p))) {
		vty_out(vty, "%% L2VPN prefix could not be forged\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (safi == SAFI_MPLS_VPN || safi == SAFI_EVPN) {
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
			memset(&gw_ip, 0, sizeof(gw_ip));
			ret = str2prefix(gwip, &gw_ip);
			if (!ret) {
				vty_out(vty, "%% Malformed GatewayIp\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			if ((gw_ip.family == AF_INET &&
			     is_evpn_prefix_ipaddr_v6((struct prefix_evpn *)&p)) ||
			    (gw_ip.family == AF_INET6 &&
			     is_evpn_prefix_ipaddr_v4(
				     (struct prefix_evpn *)&p))) {
				vty_out(vty,
					"%% GatewayIp family differs with IP prefix\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	if (safi == SAFI_MPLS_VPN || safi == SAFI_EVPN) {
		pdest = bgp_node_get(bgp->route[afi][safi],
				     (struct prefix *)&prd);
		if (!bgp_dest_has_bgp_path_info_data(pdest))
			bgp_dest_set_bgp_table_info(pdest,
						    bgp_table_init(bgp, afi,
								   safi));
		table = bgp_dest_get_bgp_table_info(pdest);
	} else {
		table = bgp->route[afi][safi];
	}

	if (negate) {
		/* Set BGP static route configuration. */
		dest = bgp_node_lookup(bgp->route[afi][safi], &p);

		if (!dest) {
			vty_out(vty, "%% Can't find static route specified\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static) {
			if ((label_index != BGP_INVALID_LABEL_INDEX) &&
			    (label_index != bgp_static->label_index)) {
				vty_out(vty,
					"%% label-index doesn't match static route\n");
				bgp_dest_unlock_node(dest);
				return CMD_WARNING_CONFIG_FAILED;
			}

			if ((rmap && bgp_static->rmap.name) &&
			    strcmp(rmap, bgp_static->rmap.name)) {
				vty_out(vty,
					"%% route-map name doesn't match static route\n");
				bgp_dest_unlock_node(dest);
				return CMD_WARNING_CONFIG_FAILED;
			}

			/* Update BGP RIB. */
			if (!bgp_static->backdoor)
				bgp_static_withdraw(bgp, &p, afi, safi, NULL);

			/* Clear configuration. */
			bgp_static_free(bgp_static);
		}

		bgp_dest_set_bgp_static_info(dest, NULL);
		dest = bgp_dest_unlock_node(dest);
		assert(dest);
		bgp_dest_unlock_node(dest);
	} else {
		dest = bgp_node_get(table, &p);

		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static) {
			/* Configuration change. */
			/* Label index cannot be changed. */
			if (bgp_static->label_index != label_index) {
				vty_out(vty, "%% cannot change label-index\n");
				bgp_dest_unlock_node(dest);
				return CMD_WARNING_CONFIG_FAILED;
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
			bgp_static->label = label;
			bgp_static->prd = prd;

			if (rd_str)
				bgp_static->prd_pretty = XSTRDUP(MTYPE_BGP_NAME,
								 rd_str);

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

			if (safi == SAFI_EVPN) {
				if (esi) {
					bgp_static->eth_s_id =
						XCALLOC(MTYPE_ATTR,
							sizeof(esi_t));
					str2esi(esi, bgp_static->eth_s_id);
				}
				if (routermac) {
					bgp_static->router_mac =
						XCALLOC(MTYPE_ATTR,
							ETH_ALEN + 1);
					(void)prefix_str2mac(routermac,
							     bgp_static->router_mac);
				}
				if (gwip)
					prefix_copy(&bgp_static->gatewayIp,
						    &gw_ip);
			}

			bgp_dest_set_bgp_static_info(dest, bgp_static);
		}

		bgp_static->valid = 1;
		if (need_update)
			bgp_static_withdraw(bgp, &p, afi, safi, NULL);

		if (!bgp_static->backdoor)
			bgp_static_update(bgp, &p, bgp_static, afi, safi);
	}

	return CMD_SUCCESS;
}

void bgp_static_add(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	SET_FLAG(bgp->flags, BGP_FLAG_FORCE_STATIC_PROCESS);
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
					bgp_static_update(bgp,
							  bgp_dest_get_prefix(rm),
							  bgp_static, afi, safi);
				}
			} else {
				bgp_static_update(
					bgp, bgp_dest_get_prefix(dest),
					bgp_dest_get_bgp_static_info(dest), afi,
					safi);
			}
		}
	UNSET_FLAG(bgp->flags, BGP_FLAG_FORCE_STATIC_PROCESS);
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

					bgp_static_withdraw(bgp,
							    bgp_dest_get_prefix(
								    rm),
							    AFI_IP, safi,
							    (struct prefix_rd *)
								    bgp_dest_get_prefix(
									    dest));
					bgp_static_free(bgp_static);
					bgp_dest_set_bgp_static_info(rm,
								     NULL);
					rm = bgp_dest_unlock_node(rm);
					assert(rm);
				}
			} else {
				bgp_static = bgp_dest_get_bgp_static_info(dest);
				bgp_static_withdraw(bgp,
						    bgp_dest_get_prefix(dest),
						    afi, safi, NULL);
				bgp_static_free(bgp_static);
				bgp_dest_set_bgp_static_info(dest, NULL);
				dest = bgp_dest_unlock_node(dest);
				assert(dest);
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
					bgp_static_update(bgp,
							  bgp_dest_get_prefix(rm),
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
				bgp_process(bgp, dest, pi, afi, safi);
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

DEFPY(bgp_network,
	bgp_network_cmd,
	"[no] network \
	<A.B.C.D/M$prefix|A.B.C.D$address [mask A.B.C.D$netmask]> \
	[{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index| \
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
	char addr_prefix_str[BUFSIZ];

	if (address_str) {
		int ret;

		ret = netmask_str2prefix_str(address_str, netmask_str,
					     addr_prefix_str,
					     sizeof(addr_prefix_str));
		if (!ret) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	return bgp_static_set(vty, no,
			      address_str ? addr_prefix_str : prefix_str, NULL,
			      NULL, AFI_IP, bgp_node_safi(vty), map_name,
			      backdoor ? 1 : 0,
			      label_index ? (uint32_t)label_index
					  : BGP_INVALID_LABEL_INDEX,
			      0, NULL, NULL, NULL, NULL);
}

DEFPY(ipv6_bgp_network,
	ipv6_bgp_network_cmd,
	"[no] network X:X::X:X/M$prefix \
	[{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index}]",
	NO_STR
	"Specify a network to announce via BGP\n"
	"IPv6 prefix\n"
	"Route-map to modify the attributes\n"
	"Name of the route map\n"
	"Label index to associate with the prefix\n"
	"Label index value\n")
{
	return bgp_static_set(vty, no, prefix_str, NULL, NULL, AFI_IP6,
			      bgp_node_safi(vty), map_name, 0,
			      label_index ? (uint32_t)label_index
					  : BGP_INVALID_LABEL_INDEX,
			      0, NULL, NULL, NULL, NULL);
}

static struct bgp_aggregate *bgp_aggregate_new(void)
{
	return XCALLOC(MTYPE_BGP_AGGREGATE, sizeof(struct bgp_aggregate));
}

void bgp_aggregate_free(struct bgp_aggregate *aggregate)
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
	attr.aspath = aspath_empty(bgp->asnotation);
	rmap_path.peer = bgp->peer_self;
	rmap_path.attr = &attr;

	SET_FLAG(bgp->peer_self->rmap_type, PEER_RMAP_TYPE_AGGREGATE);
	rmr = route_map_apply(aggregate->suppress_map, p, &rmap_path);
	bgp->peer_self->rmap_type = 0;

	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);

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
	enum asnotation_mode asnotation;

	asnotation = bgp_get_asnotation(NULL);

	if (!aspath)
		ae = aspath_empty(asnotation);

	if (!pi)
		return false;

	if (origin != pi->attr->origin)
		return false;

	if (!aspath_cmp(pi->attr->aspath, (aspath) ? aspath : ae))
		return false;

	if (!community_cmp(bgp_attr_get_community(pi->attr), comm))
		return false;

	if (!ecommunity_cmp(bgp_attr_get_ecommunity(pi->attr), ecomm))
		return false;

	if (!lcommunity_cmp(bgp_attr_get_lcommunity(pi->attr), lcomm))
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
		if (pi && (!aggregate->rmap.changed &&
			   bgp_aggregate_info_same(pi, origin, aspath, community,
						   ecommunity, lcommunity))) {
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
		if (pi) {
			bgp_path_info_delete(dest, pi);
			bgp_process(bgp, dest, pi, afi, safi);
		}

		attr = bgp_attr_aggregate_intern(
			bgp, origin, aspath, community, ecommunity, lcommunity,
			aggregate, atomic_aggregate, p);

		if (!attr) {
			aspath_free(aspath);
			community_free(&community);
			ecommunity_free(&ecommunity);
			lcommunity_free(&lcommunity);
			bgp_dest_unlock_node(dest);
			bgp_aggregate_delete(bgp, p, afi, safi, aggregate);
			if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
				zlog_debug("%s: %pFX null attribute", __func__,
					   p);
			return;
		}

		new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, 0,
				bgp->peer_self, attr, dest);

		SET_FLAG(new->flags, BGP_PATH_VALID);

		bgp_path_info_add(dest, new);
		bgp_process(bgp, dest, new, afi, safi);
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
			bgp_process(bgp, dest, pi, afi, safi);
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

	/* We've found a different MED we must revert any suppressed routes. */
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

			/* We are toggling suppression back. */
			if (suppress) {
				/* Suppress route if not suppressed already. */
				if (aggr_suppress_path(aggregate, pi))
					bgp_process(bgp, dest, pi, afi, safi);
				continue;
			}

			/* Install route if there is no more suppression. */
			if (aggr_unsuppress_path(aggregate, pi))
				bgp_process(bgp, dest, pi, afi, safi);
		}
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
				     struct bgp_path_info *pi)
{
	/* MED matching disabled. */
	if (!aggregate->match_med)
		return;

	/* Aggregation with different MED, recheck if we have got equal MEDs
	 * now.
	 */
	if (aggregate->med_mismatched &&
	    bgp_aggregate_test_all_med(aggregate, bgp, p, afi, safi) &&
	    aggregate->summary_only)
		bgp_aggregate_toggle_suppressed(aggregate, bgp, p, afi, safi,
						true);
	else
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
bool bgp_aggregate_route(struct bgp *bgp, const struct prefix *p, afi_t afi,
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
	uint8_t atomic_aggregate = 0;

	/* If the bgp instance is being deleted or self peer is deleted
	 * then do not create aggregate route
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
	    bgp->peer_self == NULL)
		return false;

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
		if (!bgp_check_advertise(bgp, dest, safi))
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (CHECK_FLAG(pi->attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
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
					bgp_process(bgp, dest, pi, afi, safi);
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
					bgp_process(bgp, dest, pi, afi, safi);
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
			if (bgp_attr_get_community(pi->attr))
				bgp_compute_aggregate_community_hash(
					aggregate,
					bgp_attr_get_community(pi->attr));

			/* Compute aggregate route's extended community.
			 */
			if (bgp_attr_get_ecommunity(pi->attr))
				bgp_compute_aggregate_ecommunity_hash(
					aggregate,
					bgp_attr_get_ecommunity(pi->attr));

			/* Compute aggregate route's large community.
			 */
			if (bgp_attr_get_lcommunity(pi->attr))
				bgp_compute_aggregate_lcommunity_hash(
					aggregate,
					bgp_attr_get_lcommunity(pi->attr));
		}
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

	/* Unimport suppressed routes from EVPN */
	bgp_aggr_supp_withdraw_from_evpn(bgp, afi, safi);

	bgp_aggregate_install(bgp, afi, safi, p, origin, aspath, community,
			      ecommunity, lcommunity, atomic_aggregate,
			      aggregate);

	return true;
}

void bgp_aggregate_delete(struct bgp *bgp, const struct prefix *p, afi_t afi,
			  safi_t safi, struct bgp_aggregate *aggregate)
{
	struct bgp_table *table;
	struct bgp_dest *top;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	table = bgp->rib[afi][safi];

	/* If routes exists below this node, generate aggregate routes. */
	top = bgp_node_get(table, p);
	for (dest = bgp_node_get(table, p); dest;
	     dest = bgp_route_next_until(dest, top)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (dest_p->prefixlen <= p->prefixlen)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (BGP_PATH_HOLDDOWN(pi))
				continue;

			if (pi->sub_type == BGP_ROUTE_AGGREGATE)
				continue;

			/*
			 * This route is suppressed: attempt to unsuppress it.
			 *
			 * `aggr_unsuppress_path` will fail if this particular
			 * aggregate route was not the suppressor.
			 */
			if (pi->extra && pi->extra->aggr_suppressors &&
			    listcount(pi->extra->aggr_suppressors)) {
				if (aggr_unsuppress_path(aggregate, pi))
					bgp_process(bgp, dest, pi, afi, safi);
			}

			if (aggregate->count > 0)
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

				if (bgp_attr_get_community(pi->attr))
					/* Remove community from aggregate.
					 */
					bgp_remove_comm_from_aggregate_hash(
						aggregate,
						bgp_attr_get_community(
							pi->attr));

				if (bgp_attr_get_ecommunity(pi->attr))
					/* Remove ecommunity from aggregate.
					 */
					bgp_remove_ecomm_from_aggregate_hash(
						aggregate,
						bgp_attr_get_ecommunity(
							pi->attr));

				if (bgp_attr_get_lcommunity(pi->attr))
					/* Remove lcommunity from aggregate.
					 */
					bgp_remove_lcomm_from_aggregate_hash(
						aggregate,
						bgp_attr_get_lcommunity(
							pi->attr));
			}
		}
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

	/* If the bgp instance is being deleted or self peer is deleted
	 * then do not create aggregate route
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS)
	    || (bgp->peer_self == NULL))
		return;

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
					 pinew);

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
		if (bgp_attr_get_community(pinew->attr))
			bgp_compute_aggregate_community(
				aggregate, bgp_attr_get_community(pinew->attr));

		/* Compute aggregate route's extended community.
		 */
		if (bgp_attr_get_ecommunity(pinew->attr))
			bgp_compute_aggregate_ecommunity(
				aggregate,
				bgp_attr_get_ecommunity(pinew->attr));

		/* Compute aggregate route's large community.
		 */
		if (bgp_attr_get_lcommunity(pinew->attr))
			bgp_compute_aggregate_lcommunity(
				aggregate,
				bgp_attr_get_lcommunity(pinew->attr));

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

	/* If the bgp instance is being deleted or self peer is deleted
	 * then do not create aggregate route
	 */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS)
	    || (bgp->peer_self == NULL))
		return;

	if (BGP_PATH_HOLDDOWN(pi))
		return;

	if (pi->sub_type == BGP_ROUTE_AGGREGATE)
		return;

	if (aggregate->summary_only && AGGREGATE_MED_VALID(aggregate))
		if (aggr_unsuppress_path(aggregate, pi))
			bgp_process(bgp, pi->net, pi, afi, safi);

	if (aggregate->suppress_map_name && AGGREGATE_MED_VALID(aggregate)
	    && aggr_suppress_map_test(bgp, aggregate, pi))
		if (aggr_unsuppress_path(aggregate, pi))
			bgp_process(bgp, pi->net, pi, afi, safi);

	/*
	 * This must be called after `summary`, `suppress-map` check to avoid
	 * "unsuppressing" twice.
	 */
	if (aggregate->match_med)
		bgp_aggregate_med_update(aggregate, bgp, aggr_p, afi, safi, pi);

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

		if (bgp_attr_get_community(pi->attr))
			/* Remove community from aggregate.
			 */
			bgp_remove_community_from_aggregate(
				aggregate, bgp_attr_get_community(pi->attr));

		if (bgp_attr_get_ecommunity(pi->attr))
			/* Remove ecommunity from aggregate.
			 */
			bgp_remove_ecommunity_from_aggregate(
				aggregate, bgp_attr_get_ecommunity(pi->attr));

		if (bgp_attr_get_lcommunity(pi->attr))
			/* Remove lcommunity from aggregate.
			 */
			bgp_remove_lcommunity_from_aggregate(
				aggregate, bgp_attr_get_lcommunity(pi->attr));
	}

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
	if (!bgp_check_advertise(bgp, pi->net, safi))
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

static const char *bgp_rpki_validation2str(enum rpki_states v_state)
{
	switch (v_state) {
	case RPKI_NOT_BEING_USED:
		return "not used";
	case RPKI_VALID:
		return "valid";
	case RPKI_NOTFOUND:
		return "not found";
	case RPKI_INVALID:
		return "invalid";
	}

	assert(!"We should never get here this is a dev escape");
	return "ERROR";
}

static int bgp_aggregate_unset(struct vty *vty, const char *prefix_str,
			       afi_t afi, safi_t safi)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;

	/* Convert string to prefix structure. */
	ret = str2prefix(prefix_str, &p);
	if (!ret) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask(&p);

	/* Old configuration check. */
	dest = bgp_node_lookup(bgp->aggregate[afi][safi], &p);
	if (!dest) {
		vty_out(vty,
			"%% There is no aggregate-address configuration.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	aggregate = bgp_dest_get_bgp_aggregate_info(dest);
	bgp_aggregate_delete(bgp, &p, afi, safi, aggregate);
	bgp_aggregate_install(bgp, afi, safi, &p, 0, NULL, NULL,
			      NULL, NULL,  0, aggregate);

	/* Unlock aggregate address configuration. */
	bgp_dest_set_bgp_aggregate_info(dest, NULL);

	bgp_free_aggregate_info(aggregate);
	dest = bgp_dest_unlock_node(dest);
	assert(dest);
	bgp_dest_unlock_node(dest);

	return CMD_SUCCESS;
}

static int bgp_aggregate_set(struct vty *vty, const char *prefix_str, afi_t afi,
			     safi_t safi, const char *rmap,
			     uint8_t summary_only, uint8_t as_set,
			     uint8_t origin, bool match_med,
			     const char *suppress_map)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;
	uint8_t as_set_new = as_set;

	if (suppress_map && summary_only) {
		vty_out(vty,
			"'summary-only' and 'suppress-map' can't be used at the same time\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Convert string to prefix structure. */
	ret = str2prefix(prefix_str, &p);
	if (!ret) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask(&p);

	if ((afi == AFI_IP && p.prefixlen == IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && p.prefixlen == IPV6_MAX_BITLEN)) {
		vty_out(vty, "Specified prefix: %s will not result in any useful aggregation, disallowing\n",
			prefix_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Old configuration check. */
	dest = bgp_node_get(bgp->aggregate[afi][safi], &p);
	aggregate = bgp_dest_get_bgp_aggregate_info(dest);

	if (aggregate) {
		vty_out(vty, "There is already same aggregate network.\n");
		/* try to remove the old entry */
		ret = bgp_aggregate_unset(vty, prefix_str, afi, safi);
		if (ret) {
			vty_out(vty, "Error deleting aggregate.\n");
			bgp_dest_unlock_node(dest);
			return CMD_WARNING_CONFIG_FAILED;
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
			vty_out(vty,
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
		aggregate->rmap.changed = true;
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
	if (!bgp_aggregate_route(bgp, &p, afi, safi, aggregate)) {
		bgp_aggregate_free(aggregate);
		bgp_dest_unlock_node(dest);
	}

	return CMD_SUCCESS;
}

DEFPY(aggregate_addressv4, aggregate_addressv4_cmd,
      "[no] aggregate-address <A.B.C.D/M$prefix|A.B.C.D$addr A.B.C.D$mask> [{"
      "as-set$as_set_s"
      "|summary-only$summary_only"
      "|route-map RMAP_NAME$rmap_name"
      "|origin <egp|igp|incomplete>$origin_s"
      "|matching-MED-only$match_med"
      "|suppress-map RMAP_NAME$suppress_map"
      "}]",
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
	const char *prefix_s = NULL;
	safi_t safi = bgp_node_safi(vty);
	uint8_t origin = BGP_ORIGIN_UNSPECIFIED;
	int as_set = AGGREGATE_AS_UNSET;
	char prefix_buf[PREFIX2STR_BUFFER];

	if (addr_str) {
		if (netmask_str2prefix_str(addr_str, mask_str, prefix_buf,
					   sizeof(prefix_buf))
		    == 0) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		prefix_s = prefix_buf;
	} else
		prefix_s = prefix_str;

	if (origin_s) {
		if (strcmp(origin_s, "egp") == 0)
			origin = BGP_ORIGIN_EGP;
		else if (strcmp(origin_s, "igp") == 0)
			origin = BGP_ORIGIN_IGP;
		else if (strcmp(origin_s, "incomplete") == 0)
			origin = BGP_ORIGIN_INCOMPLETE;
	}

	if (as_set_s)
		as_set = AGGREGATE_AS_SET;

	/* Handle configuration removal, otherwise installation. */
	if (no)
		return bgp_aggregate_unset(vty, prefix_s, AFI_IP, safi);

	return bgp_aggregate_set(vty, prefix_s, AFI_IP, safi, rmap_name,
				 summary_only != NULL, as_set, origin,
				 match_med != NULL, suppress_map);
}

void bgp_free_aggregate_info(struct bgp_aggregate *aggregate)
{
	if (aggregate->community)
		community_free(&aggregate->community);

	hash_clean_and_free(&aggregate->community_hash,
			    bgp_aggr_community_remove);

	if (aggregate->ecommunity)
		ecommunity_free(&aggregate->ecommunity);

	hash_clean_and_free(&aggregate->ecommunity_hash,
			    bgp_aggr_ecommunity_remove);

	if (aggregate->lcommunity)
		lcommunity_free(&aggregate->lcommunity);

	hash_clean_and_free(&aggregate->lcommunity_hash,
			    bgp_aggr_lcommunity_remove);

	if (aggregate->aspath)
		aspath_free(aggregate->aspath);

	hash_clean_and_free(&aggregate->aspath_hash, bgp_aggr_aspath_remove);

	bgp_aggregate_free(aggregate);
}

DEFPY(aggregate_addressv6, aggregate_addressv6_cmd,
      "[no] aggregate-address X:X::X:X/M$prefix [{"
      "as-set$as_set_s"
      "|summary-only$summary_only"
      "|route-map RMAP_NAME$rmap_name"
      "|origin <egp|igp|incomplete>$origin_s"
      "|matching-MED-only$match_med"
      "|suppress-map RMAP_NAME$suppress_map"
      "}]",
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
	uint8_t origin = BGP_ORIGIN_UNSPECIFIED;
	int as_set = AGGREGATE_AS_UNSET;

	if (origin_s) {
		if (strcmp(origin_s, "egp") == 0)
			origin = BGP_ORIGIN_EGP;
		else if (strcmp(origin_s, "igp") == 0)
			origin = BGP_ORIGIN_IGP;
		else if (strcmp(origin_s, "incomplete") == 0)
			origin = BGP_ORIGIN_INCOMPLETE;
	}

	if (as_set_s)
		as_set = AGGREGATE_AS_SET;

	/* Handle configuration removal, otherwise installation. */
	if (no)
		return bgp_aggregate_unset(vty, prefix_str, AFI_IP6,
					   SAFI_UNICAST);

	return bgp_aggregate_set(vty, prefix_str, AFI_IP6, SAFI_UNICAST,
				 rmap_name, summary_only != NULL, as_set,
				 origin, match_med != NULL, suppress_map);
}

/* Redistribute route treatment. */
void bgp_redistribute_add(struct bgp *bgp, struct prefix *p,
			  const union g_addr *nexthop, ifindex_t ifindex,
			  enum nexthop_types_t nhtype, uint8_t distance,
			  enum blackhole_type bhtype, uint32_t metric,
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
	struct interface *ifp;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
	    bgp->peer_self == NULL)
		return;

	/* Make default attribute. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);
	/*
	 * This must not be NULL to satisfy Coverity SA
	 */
	assert(attr.aspath);

	if (p->family == AF_INET6)
		UNSET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));

	switch (nhtype) {
	case NEXTHOP_TYPE_IFINDEX:
		switch (p->family) {
		case AF_INET:
			attr.nexthop.s_addr = INADDR_ANY;
			attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			attr.mp_nexthop_global_in.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			memset(&attr.mp_nexthop_global, 0,
			       sizeof(attr.mp_nexthop_global));
			attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			break;
		}
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		attr.nexthop = nexthop->ipv4;
		attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
		attr.mp_nexthop_global_in = nexthop->ipv4;
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
			attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			attr.mp_nexthop_global_in.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			memset(&attr.mp_nexthop_global, 0,
			       sizeof(attr.mp_nexthop_global));
			attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			break;
		}
		attr.bh_type = bhtype;
		break;
	}
	attr.nh_type = nhtype;
	attr.nh_ifindex = ifindex;
	ifp = if_lookup_by_index(ifindex, bgp->vrf_id);
	if (ifp && if_is_operative(ifp))
		SET_FLAG(attr.nh_flags, BGP_ATTR_NH_IF_OPERSTATE);
	else
		UNSET_FLAG(attr.nh_flags, BGP_ATTR_NH_IF_OPERSTATE);

	bgp_attr_set_med(&attr, metric);
	attr.distance = distance;
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
			memset(&rmap_path, 0, sizeof(rmap_path));
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
				bpi->uptime = monotime(NULL);

				/* Process change. */
				bgp_aggregate_increment(bgp, p, bpi, afi,
							SAFI_UNICAST);
				bgp_process(bgp, bn, bpi, afi, SAFI_UNICAST);
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
		SET_FLAG(bn->flags, BGP_NODE_FIB_INSTALLED);
		bgp_process(bgp, bn, new, afi, SAFI_UNICAST);

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
			bgp_process(bgp, dest, pi, afi, SAFI_UNICAST);
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
			if (!CHECK_FLAG(bgp->flags,
					BGP_FLAG_DELETE_IN_PROGRESS))
				bgp_process(bgp, dest, pi, afi, SAFI_UNICAST);
			else {
				dest = bgp_path_info_reap(dest, pi);
				assert(dest);
			}
		}
	}
}

/* Static function to display route. */
static void route_vty_out_route(struct bgp_dest *dest, const struct prefix *p,
				struct vty *vty, json_object *json, bool wide)
{
	int len = 0;
	char buf[INET6_ADDRSTRLEN];

	if (p->family == AF_INET) {
		if (!json) {
			len = vty_out(vty, "%pFX", p);
		} else {
			json_object_string_add(json, "prefix",
					       inet_ntop(p->family,
							 &p->u.prefix, buf,
							 sizeof(buf)));
			json_object_int_add(json, "prefixLen", p->prefixlen);
			json_object_string_addf(json, "network", "%pFX", p);
			json_object_int_add(json, "version", dest->version);
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
							 sizeof(buf)));
			json_object_int_add(json, "prefixLen", p->prefixlen);
			json_object_string_addf(json, "network", "%pFX", p);
			json_object_int_add(json, "version", dest->version);
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

const char *bgp_path_selection_reason2str(enum bgp_path_selection_reason reason)
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
	case bgp_path_selection_accept_own:
		return "Accept Own";
	case bgp_path_selection_local_route:
		return "Local Route";
	case bgp_path_selection_aigp:
		return "AIGP";
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
		return "Cluster length";
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
				       const struct prefix *p,
				       json_object *json_path)
{
	enum rpki_states rpki_state = RPKI_NOT_BEING_USED;

	if (json_path) {

		/* Route status display. */
		if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED))
			json_object_boolean_true_add(json_path, "removed");

		if (CHECK_FLAG(path->flags, BGP_PATH_STALE))
			json_object_boolean_true_add(json_path, "stale");

		if (path->extra && bgp_path_suppressed(path))
			json_object_boolean_true_add(json_path, "suppressed");

		if (CHECK_FLAG(path->flags, BGP_PATH_UNSORTED))
			json_object_boolean_true_add(json_path, "unsorted");

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

	/* RPKI validation state */
	rpki_state =
		hook_call(bgp_rpki_prefix_status, path->peer, path->attr, p);

	if (rpki_state == RPKI_VALID)
		vty_out(vty, "V");
	else if (rpki_state == RPKI_INVALID)
		vty_out(vty, "I");
	else if (rpki_state == RPKI_NOTFOUND)
		vty_out(vty, "N");
	else
		vty_out(vty, " ");

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
	else if (CHECK_FLAG(path->flags, BGP_PATH_UNSORTED))
		vty_out(vty, "u");
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

	/* adding space between next column */
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
	route_vty_short_status_out(vty, path, p, json_path);

	if (!json_paths) {
		/* print prefix and mask */
		if (!display)
			route_vty_out_route(path->net, p, vty, json_path, wide);
		else
			vty_out(vty, "%*s", (wide ? 45 : 17), " ");
	} else {
		route_vty_out_route(path->net, p, vty, json_path, wide);
	}

	/*
	 * If vrf id of nexthop is different from that of prefix,
	 * set up printable string to append
	 */
	if (path->extra && path->extra->vrfleak &&
	    path->extra->vrfleak->bgp_orig) {
		const char *self = "";

		if (nexthop_self)
			self = "<";

		nexthop_othervrf = true;
		nexthop_vrfid = path->extra->vrfleak->bgp_orig->vrf_id;

		if (path->extra->vrfleak->bgp_orig->vrf_id == VRF_UNKNOWN)
			snprintf(vrf_id_str, sizeof(vrf_id_str),
				"@%s%s", VRFID_NONE_STR, self);
		else
			snprintf(vrf_id_str, sizeof(vrf_id_str), "@%u%s",
				 path->extra->vrfleak->bgp_orig->vrf_id, self);

		if (path->extra->vrfleak->bgp_orig->inst_type !=
		    BGP_INSTANCE_TYPE_DEFAULT)

			nexthop_vrfname = path->extra->vrfleak->bgp_orig->name;
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
		char nexthop[128];
		int af = NEXTHOP_FAMILY(attr->mp_nexthop_len);

		switch (af) {
		case AF_INET:
			snprintfrr(nexthop, sizeof(nexthop), "%pI4",
				   &attr->mp_nexthop_global_in);
			break;
		case AF_INET6:
			snprintfrr(nexthop, sizeof(nexthop), "%pI6",
				   &attr->mp_nexthop_global);
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
			json_nexthop_global = json_object_new_object();

			json_object_string_addf(json_nexthop_global, "ip",
						"%pI4",
						&attr->mp_nexthop_global_in);

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
				len = vty_out(vty, "%pI4(%s)%s",
					      &attr->mp_nexthop_global_in,
					      nexthop_hostname, vrf_id_str);
			else
				len = vty_out(vty, "%pI4%s",
					      &attr->mp_nexthop_global_in,
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
				json_nexthop_global = json_object_new_object();

				json_object_string_add(json_nexthop_global,
						       "afi", "ipv4");
				json_object_string_addf(json_nexthop_global,
							"ip", "%pI4",
							&attr->nexthop);

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
	} else if (p->family == AF_INET && !BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) {
		if (json_paths) {
			json_nexthop_global = json_object_new_object();

			json_object_string_addf(json_nexthop_global, "ip",
						"%pI4", &attr->nexthop);

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
	else if (p->family == AF_INET6 || BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) {
		if (json_paths) {
			json_nexthop_global = json_object_new_object();
			json_object_string_addf(json_nexthop_global, "ip",
						"%pI6",
						&attr->mp_nexthop_global);

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
				json_object_string_addf(
					json_nexthop_ll, "ip", "%pI6",
					&attr->mp_nexthop_local);

				if (path->peer->hostname)
					json_object_string_add(
						json_nexthop_ll, "hostname",
						path->peer->hostname);

				json_object_string_add(json_nexthop_ll, "afi",
						       "ipv6");
				json_object_string_add(json_nexthop_ll, "scope",
						       "link-local");

				if ((IPV6_ADDR_CMP(&attr->mp_nexthop_global,
						   &attr->mp_nexthop_local) !=
				     0) &&
				    !CHECK_FLAG(attr->nh_flags,
						BGP_ATTR_NH_MP_PREFER_GLOBAL))
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
			if (((attr->mp_nexthop_len ==
			      BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) &&
			     !CHECK_FLAG(attr->nh_flags,
					 BGP_ATTR_NH_MP_PREFER_GLOBAL)) ||
			    (path->peer->conf_if)) {
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
	if (use_bgp_med_value(attr, path->peer->bgp)) {
		uint32_t value = bgp_med_value(attr, path->peer->bgp);

		if (json_paths)
			json_object_int_add(json_path, "metric", value);
		else if (wide)
			vty_out(vty, "%7u", value);
		else
			vty_out(vty, "%10u", value);
	} else if (!json_paths) {
		if (wide)
			vty_out(vty, "%*s", 7, " ");
		else
			vty_out(vty, "%*s", 10, " ");
	}

	/* Local Pref */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
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

	if (json_paths)
		json_object_string_addf(json_path, "peerId", "%pSU",
					&path->peer->connection->su);

	/* Print aspath */
	if (attr->aspath) {
		if (json_paths)
			json_object_string_add(json_path, "path",
					       attr->aspath->str);
		else
			aspath_print_vty(vty, attr->aspath);
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
		    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
			json_ext_community = json_object_new_object();
			json_object_string_add(
				json_ext_community, "string",
				bgp_attr_get_ecommunity(attr)->str);
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
			if (bgp_evpn_is_esi_valid(&attr->esi)) {
				/* XXX - add these params to the json out */
				vty_out(vty, "%*s", 20, " ");
				vty_out(vty, "ESI:%s",
					esi_to_str(&attr->esi, esi_buf,
						   sizeof(esi_buf)));

				vty_out(vty, "\n");
			}
			if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
				vty_out(vty, "%*s", 20, " ");
				vty_out(vty, "%s\n",
					bgp_attr_get_ecommunity(attr)->str);
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
void route_vty_out_tmp(struct vty *vty, struct bgp *bgp, struct bgp_dest *dest,
		       const struct prefix *p, struct attr *attr, safi_t safi,
		       bool use_json, json_object *json_ar, bool wide)
{
	json_object *json_net = NULL;
	int len;
	char buff[BUFSIZ];

	/* Route status display. */
	if (use_json) {
		json_net = json_object_new_object();
	} else {
		vty_out(vty, " *");
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
			json_object_string_addf(json_net, "network", "%pFX", p);
		}
	} else
		route_vty_out_route(dest, p, vty, NULL, wide);

	/* Print attribute */
	if (attr) {
		if (use_json) {
			if (p->family == AF_INET &&
			    (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP ||
			     !BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
				if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
					json_object_string_addf(
						json_net, "nextHop", "%pI4",
						&attr->mp_nexthop_global_in);
				else
					json_object_string_addf(
						json_net, "nextHop", "%pI4",
						&attr->nexthop);
			} else if (p->family == AF_INET6 ||
				   BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) {
				json_object_string_addf(
					json_net, "nextHopGlobal", "%pI6",
					&attr->mp_nexthop_global);
			} else if (p->family == AF_EVPN &&
				   !BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
				json_object_string_addf(
					json_net, "nextHop", "%pI4",
					&attr->mp_nexthop_global_in);
			}

			if (use_bgp_med_value(attr, bgp)) {
				uint32_t value = bgp_med_value(attr, bgp);

				json_object_int_add(json_net, "metric", value);
			}

			if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
				json_object_int_add(json_net, "locPrf",
						    attr->local_pref);

			json_object_int_add(json_net, "weight", attr->weight);

			/* Print aspath */
			if (attr->aspath)
				json_object_string_add(json_net, "path",
						       attr->aspath->str);

			/* Print origin */
			json_object_string_add(
				json_net, "origin",
				bgp_origin_long_str[attr->origin]);
		} else {
			if (p->family == AF_INET &&
			    (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP ||
			     safi == SAFI_EVPN ||
			     !BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
				if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
				    || safi == SAFI_EVPN)
					vty_out(vty, "%-16pI4",
						&attr->mp_nexthop_global_in);
				else if (wide)
					vty_out(vty, "%-41pI4", &attr->nexthop);
				else
					vty_out(vty, "%-16pI4", &attr->nexthop);
			} else if (p->family == AF_INET6 ||
				   BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) {
				len = vty_out(vty, "%pI6",
					      &attr->mp_nexthop_global);
				len = wide ? (41 - len) : (16 - len);
				if (len < 1)
					vty_out(vty, "\n%*s", 36, " ");
				else
					vty_out(vty, "%*s", len, " ");
			}

			if (use_bgp_med_value(attr, bgp)) {
				uint32_t value = bgp_med_value(attr, bgp);

				if (wide)
					vty_out(vty, "%7u", value);
				else
					vty_out(vty, "%10u", value);
			} else if (wide)
				vty_out(vty, "       ");
			else
				vty_out(vty, "          ");

			if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
				vty_out(vty, "%7u", attr->local_pref);
			else
				vty_out(vty, "       ");

			vty_out(vty, "%7u ", attr->weight);

			/* Print aspath */
			if (attr->aspath)
				aspath_print_vty(vty, attr->aspath);

			/* Print origin */
			vty_out(vty, "%s", bgp_origin_str[attr->origin]);
		}
	}
	if (use_json) {
		struct bgp_path_info *bpi = bgp_dest_get_bgp_path_info(dest);

		json_object_boolean_true_add(json_net, "valid");
		json_object_boolean_true_add(json_net, "best");

		if (bpi && CHECK_FLAG(bpi->flags, BGP_PATH_MULTIPATH))
			json_object_boolean_true_add(json_net, "multipath");
		json_object_object_addf(json_ar, json_net, "%pFX", p);
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
	route_vty_short_status_out(vty, path, p, json_out);

	/* print prefix and mask */
	if (json == NULL) {
		if (!display)
			route_vty_out_route(path->net, p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");
	}

	/* Print attribute */
	attr = path->attr;
	if (((p->family == AF_INET) &&
	     ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP))) ||
	    (safi == SAFI_EVPN && !BGP_ATTR_NEXTHOP_AFI_IP6(attr)) ||
	    (!BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			if (json)
				json_object_string_addf(
					json_out, "mpNexthopGlobalIn", "%pI4",
					&attr->mp_nexthop_global_in);
			else
				vty_out(vty, "%-16pI4",
					&attr->mp_nexthop_global_in);
		} else {
			if (json)
				json_object_string_addf(json_out, "nexthop",
							"%pI4", &attr->nexthop);
			else
				vty_out(vty, "%-16pI4", &attr->nexthop);
		}
	} else if (((p->family == AF_INET6) &&
		    ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP))) ||
		   (safi == SAFI_EVPN && BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) ||
		   (BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
		char buf_a[512];

		if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL) {
			if (json)
				json_object_string_addf(
					json_out, "mpNexthopGlobalIn", "%pI6",
					&attr->mp_nexthop_global);
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

	if (bgp_path_info_has_valid_label(path)) {
		label = decode_label(&path->extra->labels->label[0]);
		if (json) {
			json_object_int_add(json_out, "notag", label);
			json_object_array_add(json, json_out);
		} else {
			vty_out(vty, "notag/%d", label);
			vty_out(vty, "\n");
		}
	} else if (!json)
		vty_out(vty, "\n");
}

void route_vty_out_overlay(struct vty *vty, const struct prefix *p,
			   struct bgp_path_info *path, int display,
			   json_object *json_paths)
{
	struct attr *attr;
	json_object *json_path = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_overlay = NULL;
	struct bgp_route_evpn *bre = NULL;

	if (!path->extra)
		return;

	if (json_paths) {
		json_path = json_object_new_object();
		json_overlay = json_object_new_object();
		json_nexthop = json_object_new_object();
	}

	/* short status lead text */
	route_vty_short_status_out(vty, path, p, json_path);

	/* print prefix and mask */
	if (!display)
		route_vty_out_route(path->net, p, vty, json_path, false);
	else
		vty_out(vty, "%*s", 17, " ");

	/* Print attribute */
	attr = path->attr;
	int af = NEXTHOP_FAMILY(attr->mp_nexthop_len);

	switch (af) {
	case AF_INET:
		if (!json_path) {
			vty_out(vty, "%-16pI4", &attr->mp_nexthop_global_in);
		} else {
			json_object_string_addf(json_nexthop, "ip", "%pI4",
						&attr->mp_nexthop_global_in);

			json_object_string_add(json_nexthop, "afi", "ipv4");

			json_object_object_add(json_path, "nexthop",
					       json_nexthop);
		}
		break;
	case AF_INET6:
		if (!json_path) {
			vty_out(vty, "%pI6(%pI6)", &attr->mp_nexthop_global,
				&attr->mp_nexthop_local);
		} else {
			json_object_string_addf(json_nexthop, "ipv6Global",
						"%pI6",
						&attr->mp_nexthop_global);

			json_object_string_addf(json_nexthop, "ipv6LinkLocal",
						"%pI6",
						&attr->mp_nexthop_local);

			json_object_string_add(json_nexthop, "afi", "ipv6");

			json_object_object_add(json_path, "nexthop",
					       json_nexthop);
		}
		break;
	default:
		if (!json_path) {
			vty_out(vty, "?");
		} else {
			json_object_string_add(json_nexthop, "error",
					       "Unsupported address-family");
		}
	}

	bre = bgp_attr_get_evpn_overlay(attr);
	if (bre) {
		if (!json_path)
			vty_out(vty, "/%pIA", &bre->gw_ip);
		else
			json_object_string_addf(json_overlay, "gw", "%pIA",
						&bre->gw_ip);
	}

	if (bgp_attr_get_ecommunity(attr)) {
		char *mac = NULL;
		struct ecommunity_val *routermac = ecommunity_lookup(
			bgp_attr_get_ecommunity(attr), ECOMMUNITY_ENCODE_EVPN,
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
			       json_object *json_paths)
{
	struct attr *attr = path->attr;
	int len;
	char timebuf[BGP_UPTIME_LEN] = {};
	json_object *json_path = NULL;

	if (use_json)
		json_path = json_object_new_object();

	/* short status lead text */
	route_vty_short_status_out(vty, path, p, json_path);

	/* print prefix and mask */
	if (!use_json) {
		if (!display)
			route_vty_out_route(path->net, p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");

		len = vty_out(vty, "%s", path->peer->host);
		len = 17 - len;

		if (len < 1)
			vty_out(vty, "\n%*s", 34, " ");
		else
			vty_out(vty, "%*s", len, " ");

		vty_out(vty, "%s ",
			bgp_damp_reuse_time_vty(vty, path, timebuf,
						BGP_UPTIME_LEN, afi, safi,
						use_json, NULL));

		if (attr->aspath)
			aspath_print_vty(vty, attr->aspath);

		vty_out(vty, "%s", bgp_origin_str[attr->origin]);

		vty_out(vty, "\n");
	} else {
		bgp_damp_reuse_time_vty(vty, path, timebuf, BGP_UPTIME_LEN, afi,
					safi, use_json, json_path);

		if (attr->aspath)
			json_object_string_add(json_path, "asPath",
					       attr->aspath->str);

		json_object_string_add(json_path, "origin",
				       bgp_origin_str[attr->origin]);
		json_object_string_add(json_path, "peerHost", path->peer->host);

		json_object_array_add(json_paths, json_path);
	}
}

/* flap route */
static void flap_route_vty_out(struct vty *vty, const struct prefix *p,
			       struct bgp_path_info *path, int display,
			       afi_t afi, safi_t safi, bool use_json,
			       json_object *json_paths)
{
	struct attr *attr = path->attr;
	struct bgp_damp_info *bdi;
	char timebuf[BGP_UPTIME_LEN] = {};
	int len;
	json_object *json_path = NULL;

	if (!path->extra)
		return;

	if (use_json)
		json_path = json_object_new_object();

	bdi = path->extra->damp_info;

	/* short status lead text */
	route_vty_short_status_out(vty, path, p, json_path);

	if (!use_json) {
		if (!display)
			route_vty_out_route(path->net, p, vty, NULL, false);
		else
			vty_out(vty, "%*s", 17, " ");

		len = vty_out(vty, "%s", path->peer->host);
		len = 16 - len;
		if (len < 1)
			vty_out(vty, "\n%*s", 33, " ");
		else
			vty_out(vty, "%*s", len, " ");

		len = vty_out(vty, "%d", bdi->flap);
		len = 5 - len;
		if (len < 1)
			vty_out(vty, " ");
		else
			vty_out(vty, "%*s", len, " ");

		vty_out(vty, "%s ", peer_uptime(bdi->start_time, timebuf,
						BGP_UPTIME_LEN, 0, NULL));

		if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)
		    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			vty_out(vty, "%s ",
				bgp_damp_reuse_time_vty(vty, path, timebuf,
							BGP_UPTIME_LEN, afi,
							safi, use_json, NULL));
		else
			vty_out(vty, "%*s ", 8, " ");

		if (attr->aspath)
			aspath_print_vty(vty, attr->aspath);

		vty_out(vty, "%s", bgp_origin_str[attr->origin]);

		vty_out(vty, "\n");
	} else {
		json_object_string_add(json_path, "peerHost", path->peer->host);
		json_object_int_add(json_path, "bdiFlap", bdi->flap);

		peer_uptime(bdi->start_time, timebuf, BGP_UPTIME_LEN, use_json,
			    json_path);

		if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)
		    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			bgp_damp_reuse_time_vty(vty, path, timebuf,
						BGP_UPTIME_LEN, afi, safi,
						use_json, json_path);

		if (attr->aspath)
			json_object_string_add(json_path, "asPath",
					       attr->aspath->str);

		json_object_string_add(json_path, "origin",
				       bgp_origin_str[attr->origin]);

		json_object_array_add(json_paths, json_path);
	}
}

static void route_vty_out_advertised_to(struct vty *vty, struct peer *peer,
					int *first, const char *header,
					json_object *json_adv_to)
{
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
			json_object_object_addf(json_adv_to, json_peer, "%pSU",
						&peer->connection->su);
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
				vty_out(vty, " %s(%pSU)", peer->hostname,
					&peer->connection->su);
		} else {
			if (peer->conf_if)
				vty_out(vty, " %s", peer->conf_if);
			else
				vty_out(vty, " %pSU", &peer->connection->su);
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

void route_vty_out_detail(struct vty *vty, struct bgp *bgp, struct bgp_dest *bn,
			  const struct prefix *p, struct bgp_path_info *path,
			  afi_t afi, safi_t safi,
			  enum rpki_states rpki_curr_state,
			  json_object *json_paths)
{
	char buf[INET6_ADDRSTRLEN];
	char vni_buf[30] = {};
	struct attr *attr = path->attr;
	time_t tbuf;
	char timebuf[32];
	json_object *json_bestpath = NULL;
	json_object *json_cluster_list = NULL;
	json_object *json_cluster_list_list = NULL;
	json_object *json_ext_community = NULL;
	json_object *json_ext_ipv6_community = NULL;
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
	bool addpath_capable;
	int has_adj;
	unsigned int first_as;
	bool nexthop_self =
		CHECK_FLAG(path->flags, BGP_PATH_ANNC_NH_SELF) ? true : false;
	int i;
	char *nexthop_hostname =
		bgp_nexthop_hostname(path->peer, path->nexthop);
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;
	mpls_label_t label = MPLS_INVALID_LABEL;
	struct bgp_path_info *bpi_ultimate =
		bgp_get_imported_bpi_ultimate(path);
	struct bgp_route_evpn *bre = bgp_attr_get_evpn_overlay(attr);

	if (json_paths) {
		json_path = json_object_new_object();
		json_peer = json_object_new_object();
		json_nexthop_global = json_object_new_object();
	}

	if (BGP_PATH_INFO_NUM_LABELS(path)) {
		bgp_evpn_label2str(path->extra->labels->label,
				   path->extra->labels->num_labels, vni_buf,
				   sizeof(vni_buf));
	}

	if (safi == SAFI_EVPN) {
		if (!json_paths)
			vty_out(vty, "  Route %pFX", p);

		if (vni_buf[0]) {
			if (json_paths)
				json_object_string_add(json_path, "vni",
						       vni_buf);
			else
				vty_out(vty, " VNI %s", vni_buf);
		}
	}

	if (safi == SAFI_EVPN && bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
		char gwip_buf[INET6_ADDRSTRLEN];

		ipaddr2str(&bre->gw_ip, gwip_buf, sizeof(gwip_buf));

		if (json_paths)
			json_object_string_add(json_path, "gatewayIP",
					       gwip_buf);
		else
			vty_out(vty, " Gateway IP %s", gwip_buf);
	}

	if (safi == SAFI_EVPN && !json_path)
		vty_out(vty, "\n");


	if (path->extra && path->extra->vrfleak && path->extra->vrfleak->parent) {
		struct bgp_path_info *parent_ri;
		struct bgp_dest *dest, *pdest;

		parent_ri =
			(struct bgp_path_info *)path->extra->vrfleak->parent;
		dest = parent_ri->net;
		if (dest && dest->pdest) {
			pdest = dest->pdest;
			if (is_pi_family_evpn(parent_ri)) {
				if (json_paths) {
					json_object_string_addf(
						json_path, "importedFrom",
						BGP_RD_AS_FORMAT(bgp->asnotation),
						(struct prefix_rd *)
							bgp_dest_get_prefix(
								pdest));
					if (safi != SAFI_EVPN)
						json_object_string_add(json_path,
								       "vni",
								       vni_buf);
				} else {
					vty_out(vty, "  Imported from ");
					vty_out(vty,
						BGP_RD_AS_FORMAT(bgp->asnotation),
						(struct prefix_rd *)
							bgp_dest_get_prefix(
								pdest));
					vty_out(vty, ":%pFX, VNI %s",
						(struct prefix_evpn *)
							bgp_dest_get_prefix(dest),
						vni_buf);
				}
				if (CHECK_FLAG(attr->es_flags, ATTR_ES_L3_NHG) &&
				    !json_paths) {
					vty_out(vty, ", L3NHG %s",
						CHECK_FLAG(
							attr->es_flags,
							ATTR_ES_L3_NHG_ACTIVE)
							? "active"
							: "inactive");
					vty_out(vty, "\n");
				} else if (json_paths) {
					json_object_boolean_add(
						json_path, "l3nhg",
						CHECK_FLAG(attr->es_flags,
							   ATTR_ES_L3_NHG));
					json_object_boolean_add(
						json_path, "l3nhgActive",
						CHECK_FLAG(attr->es_flags,
							   ATTR_ES_L3_NHG_ACTIVE));
				}
			} else {
				if (json_paths) {
					json_object_string_addf(
						json_path, "importedFrom",
						BGP_RD_AS_FORMAT(bgp->asnotation),
						(struct prefix_rd *)
							bgp_dest_get_prefix(
								pdest));
				} else {
					vty_out(vty, "  Imported from ");
					vty_out(vty,
						BGP_RD_AS_FORMAT(bgp->asnotation),
						(struct prefix_rd *)
							bgp_dest_get_prefix(
								pdest));
					vty_out(vty, ":%pFX\n",
						(struct prefix_evpn *)
							bgp_dest_get_prefix(
								dest));
				}
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
				vty_out(vty, "  %s", attr->aspath->str);
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
			json_object_int_add(json_path, "aggregatorAs",
					    attr->aggregator_as);
			json_object_string_addf(json_path, "aggregatorId",
						"%pI4", &attr->aggregator_addr);
		} else {
			vty_out(vty, ", (aggregated by %u %pI4)",
				attr->aggregator_as, &attr->aggregator_addr);
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

	if ((p->family == AF_INET || p->family == AF_ETHERNET ||
	     p->family == AF_EVPN) &&
	    (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN ||
	     !BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			if (json_paths) {
				json_object_string_addf(
					json_nexthop_global, "ip", "%pI4",
					&attr->mp_nexthop_global_in);

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
				json_object_string_addf(json_nexthop_global,
							"ip", "%pI4",
							&attr->nexthop);

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
			json_object_string_addf(json_nexthop_global, "ip",
						"%pI6",
						&attr->mp_nexthop_global);

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
	if (!CHECK_FLAG(bpi_ultimate->flags, BGP_PATH_VALID)) {
		bool import = CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);

		if (json_paths) {
			json_object_boolean_false_add(json_nexthop_global,
						      "accessible");
			json_object_boolean_add(json_nexthop_global,
						"importCheckEnabled", import);
		} else {
			vty_out(vty, " (inaccessible%s)",
				import ? ", import-check enabled" : "");
		}
	} else {
		if (bpi_ultimate->extra && bpi_ultimate->extra->igpmetric) {
			if (json_paths)
				json_object_int_add(
					json_nexthop_global, "metric",
					bpi_ultimate->extra->igpmetric);
			else
				vty_out(vty, " (metric %u)",
					bpi_ultimate->extra->igpmetric);
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

		if (safi == SAFI_EVPN || (p->family == AF_INET &&
					  !BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))) {
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

		if (json_paths)
			json_object_string_addf(json_peer, "routerId", "%pI4",
						&bgp->router_id);
		else
			vty_out(vty, "(%pI4)", &bgp->router_id);
	}

	/* We RXed this path from one of our peers */
	else {

		if (json_paths) {
			json_object_string_addf(json_peer, "peerId", "%pSU",
						&path->peer->connection->su);
			json_object_string_addf(json_peer, "routerId", "%pI4",
						&path->peer->remote_id);

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
					vty_out(vty, " from %pSU",
						&path->peer->connection->su);
			}

			if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
				vty_out(vty, " (%pI4)", &attr->originator_id);
			else
				vty_out(vty, " (%pI4)", &path->peer->remote_id);
		}
	}

	/*
	 * Note when vrfid of nexthop is different from that of prefix
	 */
	if (path->extra && path->extra->vrfleak &&
	    path->extra->vrfleak->bgp_orig) {
		vrf_id_t nexthop_vrfid = path->extra->vrfleak->bgp_orig->vrf_id;

		if (json_paths) {
			const char *vn;

			if (path->extra->vrfleak->bgp_orig->inst_type ==
			    BGP_INSTANCE_TYPE_DEFAULT)
				vn = VRF_DEFAULT_NAME;
			else
				vn = path->extra->vrfleak->bgp_orig->name;

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
			json_object_string_addf(json_nexthop_ll, "ip", "%pI6",
						&attr->mp_nexthop_local);

			if (path->peer->hostname)
				json_object_string_add(json_nexthop_ll,
						       "hostname",
						       path->peer->hostname);

			json_object_string_add(json_nexthop_ll, "afi", "ipv6");
			json_object_string_add(json_nexthop_ll, "scope",
					       "link-local");

			json_object_boolean_true_add(json_nexthop_ll,
						     "accessible");

			if (!CHECK_FLAG(attr->nh_flags,
					BGP_ATTR_NH_MP_PREFER_GLOBAL))
				json_object_boolean_true_add(json_nexthop_ll,
							     "used");
			else
				json_object_boolean_true_add(
					json_nexthop_global, "used");
		} else {
			vty_out(vty, "    (%s) %s\n",
				inet_ntop(AF_INET6, &attr->mp_nexthop_local,
					  buf, INET6_ADDRSTRLEN),
				CHECK_FLAG(attr->nh_flags,
					   BGP_ATTR_NH_MP_PREFER_GLOBAL)
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

	if (use_bgp_med_value(attr, bgp)) {
		uint32_t value = bgp_med_value(attr, bgp);

		if (json_paths)
			json_object_int_add(json_path, "metric", value);
		else
			vty_out(vty, ", metric %u", value);
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
		if (json_paths)
			json_object_int_add(json_path, "locPrf",
					    attr->local_pref);
		else
			vty_out(vty, ", localpref %u", attr->local_pref);
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP))) {
		if (json_paths)
			json_object_int_add(json_path, "aigpMetric",
					    bgp_attr_get_aigp_metric(attr));
		else
			vty_out(vty, ", aigp-metric %" PRIu64,
				bgp_attr_get_aigp_metric(attr));
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

	if (json_paths)
		json_object_int_add(json_path, "version", bn->version);

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
						json_peer, "type",
						(path->peer->sub_sort ==
						 BGP_PEER_EBGP_OAD)
							? "external (oad)"
							: "external");
				else
					vty_out(vty, ", %s",
						(path->peer->sub_sort ==
						 BGP_PEER_EBGP_OAD)
							? "external (oad)"
							: "external");
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

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))) {
		if (json_paths)
			json_object_boolean_true_add(json_path,
						     "atomicAggregate");
		else
			vty_out(vty, ", atomic-aggregate");
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_OTC))) {
		if (json_paths)
			json_object_int_add(json_path, "otc", attr->otc);
		else
			vty_out(vty, ", otc %u", attr->otc);
	}

	if (CHECK_FLAG(path->flags, BGP_PATH_MULTIPATH) ||
	    (CHECK_FLAG(path->flags, BGP_PATH_SELECTED) && bgp_path_info_mpath_count(path) > 1)) {
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

	if (rpki_curr_state != RPKI_NOT_BEING_USED) {
		if (json_paths)
			json_object_string_add(
				json_path, "rpkiValidationState",
				bgp_rpki_validation2str(rpki_curr_state));
		else
			vty_out(vty, ", rpki validation-state: %s",
				bgp_rpki_validation2str(rpki_curr_state));
	}

	if (json_bestpath)
		json_object_object_add(json_path, "bestpath", json_bestpath);

	if (!json_paths)
		vty_out(vty, "\n");

	/* Line 4 display Community */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		if (json_paths) {
			if (!bgp_attr_get_community(attr)->json)
				community_str(bgp_attr_get_community(attr),
					      true, true);
			json_object_lock(bgp_attr_get_community(attr)->json);
			json_object_object_add(
				json_path, "community",
				bgp_attr_get_community(attr)->json);
		} else {
			vty_out(vty, "      Community: %s\n",
				bgp_attr_get_community(attr)->str);
		}
	}

	/* Line 5 display Extended-community */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
		if (json_paths) {
			json_ext_community = json_object_new_object();
			json_object_string_add(
				json_ext_community, "string",
				bgp_attr_get_ecommunity(attr)->str);
			json_object_object_add(json_path, "extendedCommunity",
					       json_ext_community);
		} else {
			vty_out(vty, "      Extended Community: %s\n",
				bgp_attr_get_ecommunity(attr)->str);
		}
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_IPV6_EXT_COMMUNITIES))) {
		if (json_paths) {
			json_ext_ipv6_community = json_object_new_object();
			json_object_string_add(json_ext_ipv6_community, "string",
					       bgp_attr_get_ipv6_ecommunity(attr)
						       ->str);
			json_object_object_add(json_path,
					       "extendedIpv6Community",
					       json_ext_ipv6_community);
		} else {
			vty_out(vty, "      Extended IPv6 Community: %s\n",
				bgp_attr_get_ipv6_ecommunity(attr)->str);
		}
	}

	/* Line 6 display Large community */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))) {
		if (json_paths) {
			if (!bgp_attr_get_lcommunity(attr)->json)
				lcommunity_str(bgp_attr_get_lcommunity(attr),
					       true, true);
			json_object_lock(bgp_attr_get_lcommunity(attr)->json);
			json_object_object_add(
				json_path, "largeCommunity",
				bgp_attr_get_lcommunity(attr)->json);
		} else {
			vty_out(vty, "      Large Community: %s\n",
				bgp_attr_get_lcommunity(attr)->str);
		}
	}

	/* Line 7 display Originator, Cluster-id */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) ||
	    CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))) {
		char buf[BUFSIZ] = {0};

		if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))) {
			if (json_paths)
				json_object_string_addf(json_path,
							"originatorId", "%pI4",
							&attr->originator_id);
			else
				vty_out(vty, "      Originator: %pI4",
					&attr->originator_id);
		}

		if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))) {
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
		bgp_damp_info_vty(vty, bgp, path, afi, safi, json_path);

	/* Remote Label */
	if (bgp_path_info_has_valid_label(path) &&
	    (safi != SAFI_EVPN && !is_route_parent_evpn(path))) {
		mpls_lse_decode(path->extra->labels->label[0], &label, &ttl,
				&exp, &bos);

		if (json_paths)
			json_object_int_add(json_path, "remoteLabel", label);
		else
			vty_out(vty, "      Remote label: %d\n", label);
	}

	/* Remote SID */
	if ((path->attr->srv6_l3vpn || path->attr->srv6_vpn) &&
	    safi != SAFI_EVPN) {
		struct in6_addr *sid_tmp =
			path->attr->srv6_l3vpn ? (&path->attr->srv6_l3vpn->sid)
					       : (&path->attr->srv6_vpn->sid);
		if (json_paths)
			json_object_string_addf(json_path, "remoteSid", "%pI6",
						sid_tmp);
		else
			vty_out(vty, "      Remote SID: %pI6\n", sid_tmp);
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
	tbuf = time(NULL) - (monotime(NULL) - path->uptime);
	if (json_paths) {
		json_last_update = json_object_new_object();
		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       ctime_r(&tbuf, timebuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	} else
		vty_out(vty, "      Last update: %s", ctime_r(&tbuf, timebuf));

	/* Line 10 display PMSI tunnel attribute, if present */
	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL))) {
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

	if (path->peer->connection->t_gr_restart &&
	    CHECK_FLAG(path->flags, BGP_PATH_STALE)) {
		unsigned long gr_remaining = event_timer_remain_second(
			path->peer->connection->t_gr_restart);

		if (json_paths) {
			json_object_int_add(json_path,
					    "gracefulRestartSecondsRemaining",
					    gr_remaining);
		} else
			vty_out(vty,
				"      Time until Graceful Restart stale route deleted: %lu\n",
				gr_remaining);
	}

	if (path->peer->t_llgr_stale[afi][safi] &&
	    bgp_attr_get_community(attr) &&
	    community_include(bgp_attr_get_community(attr),
			      COMMUNITY_LLGR_STALE)) {
		unsigned long llgr_remaining = event_timer_remain_second(
			path->peer->t_llgr_stale[afi][safi]);

		if (json_paths) {
			json_object_int_add(json_path, "llgrSecondsRemaining",
					    llgr_remaining);
		} else
			vty_out(vty,
				"      Time until Long-lived stale route deleted: %lu\n",
				llgr_remaining);
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

static int bgp_show_regexp(struct vty *vty, struct bgp *bgp, const char *regstr,
			   afi_t afi, safi_t safi, enum bgp_show_type type,
			   bool use_json);
static int bgp_show_community(struct vty *vty, struct bgp *bgp,
			      const char *comstr, int exact, afi_t afi,
			      safi_t safi, uint16_t show_flags);

static int bgp_show_table(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
			  struct bgp_table *table, enum bgp_show_type type,
			  void *output_arg, const char *rd, int is_last,
			  unsigned long *output_cum, unsigned long *total_cum,
			  unsigned long *json_header_depth, uint16_t show_flags,
			  enum rpki_states rpki_target_state)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest;
	bool header = true;
	bool json_detail_header = false;
	int display;
	unsigned long output_count = 0;
	unsigned long total_count = 0;
	struct prefix *p;
	json_object *json_paths = NULL;
	int first = 1;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);
	bool all = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL);
	bool detail_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON_DETAIL);
	bool detail_routes = CHECK_FLAG(show_flags, BGP_SHOW_OPT_ROUTES_DETAIL);

	if (output_cum && *output_cum != 0)
		header = false;

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
			" \"localAS\": ",
			bgp->vrf_id == VRF_UNKNOWN ? -1 : (int)bgp->vrf_id,
			bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
				? VRF_DEFAULT_NAME
				: bgp->name,
			table->version, &bgp->router_id,
			bgp->default_local_pref);
		if ((bgp->asnotation == ASNOTATION_PLAIN) ||
		    ((bgp->asnotation == ASNOTATION_DOT) &&
		     (bgp->as < UINT16_MAX)))
			vty_out(vty, "%u", bgp->as);
		else {
			vty_out(vty, "\"");
			vty_out(vty, ASN_FORMAT(bgp->asnotation), &bgp->as);
			vty_out(vty, "\"");
		}
		vty_out(vty, ",\n \"routes\": { ");
		if (rd) {
			vty_out(vty, " \"routeDistinguishers\" : {");
			++*json_header_depth;
		}
	}

	if (use_json && rd) {
		vty_out(vty, " \"%s\" : { ", rd);
	}

	/* Check for 'json detail', where we need header output once per dest */
	if (use_json && detail_json && type != bgp_show_type_dampend_paths &&
	    type != bgp_show_type_damp_neighbor &&
	    type != bgp_show_type_flap_statistics &&
	    type != bgp_show_type_flap_neighbor)
		json_detail_header = true;

	/* Start processing of routes. */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);
		enum rpki_states rpki_curr_state = RPKI_NOT_BEING_USED;
		bool json_detail_header_used = false;

		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi == NULL)
			continue;

		display = 0;
		if (use_json)
			json_paths = json_object_new_array();
		else
			json_paths = NULL;

		for (; pi; pi = pi->next) {
			struct community *picomm = NULL;

			picomm = bgp_attr_get_community(pi->attr);

			total_count++;

			if (type == bgp_show_type_prefix_version) {
				uint32_t version =
					strtoul(output_arg, NULL, 10);
				if (dest->version < version)
					continue;
			}

			if (type == bgp_show_type_community_alias) {
				char *alias = output_arg;
				char **communities;
				int num;
				bool found = false;

				if (picomm) {
					frrstr_split(picomm->str, " ",
						     &communities, &num);
					for (int i = 0; i < num; i++) {
						const char *com2alias =
							bgp_community2alias(
								communities[i]);
						if (!found
						    && strcmp(alias, com2alias)
							       == 0)
							found = true;
						XFREE(MTYPE_TMP,
						      communities[i]);
					}
					XFREE(MTYPE_TMP, communities);
				}

				if (!found &&
				    bgp_attr_get_lcommunity(pi->attr)) {
					frrstr_split(bgp_attr_get_lcommunity(
							     pi->attr)
							     ->str,
						     " ", &communities, &num);
					for (int i = 0; i < num; i++) {
						const char *com2alias =
							bgp_community2alias(
								communities[i]);
						if (!found
						    && strcmp(alias, com2alias)
							       == 0)
							found = true;
						XFREE(MTYPE_TMP,
						      communities[i]);
					}
					XFREE(MTYPE_TMP, communities);
				}

				if (!found)
					continue;
			}

			if (type == bgp_show_type_rpki) {
				if (dest_p->family == AF_INET
				    || dest_p->family == AF_INET6)
					rpki_curr_state = hook_call(
						bgp_rpki_prefix_status,
						pi->peer, pi->attr, dest_p);
				if (rpki_target_state != RPKI_NOT_BEING_USED
				    && rpki_curr_state != rpki_target_state)
					continue;
			}

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
			if (type == bgp_show_type_access_list) {
				struct access_list *alist = output_arg;

				if (access_list_apply(alist, dest_p) !=
				    FILTER_PERMIT)
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
				struct bgp_path_info_extra extra;
				struct attr dummy_attr = {};
				route_map_result_t ret;

				dummy_attr = *pi->attr;

				prep_for_rmap_apply(&path, &extra, dest, pi, pi->peer, NULL,
						    &dummy_attr);

				ret = route_map_apply(rmap, dest_p, &path);
				bgp_attr_flush(&dummy_attr);
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
				if (!picomm)
					continue;
			}
			if (type == bgp_show_type_community) {
				struct community *com = output_arg;

				if (!picomm || !community_match(picomm, com))
					continue;
			}
			if (type == bgp_show_type_community_exact) {
				struct community *com = output_arg;

				if (!picomm || !community_cmp(picomm, com))
					continue;
			}
			if (type == bgp_show_type_community_list) {
				struct community_list *list = output_arg;

				if (!community_list_match(picomm, list))
					continue;
			}
			if (type == bgp_show_type_community_list_exact) {
				struct community_list *list = output_arg;

				if (!community_list_exact_match(picomm, list))
					continue;
			}
			if (type == bgp_show_type_lcommunity) {
				struct lcommunity *lcom = output_arg;

				if (!bgp_attr_get_lcommunity(pi->attr) ||
				    !lcommunity_match(
					    bgp_attr_get_lcommunity(pi->attr),
					    lcom))
					continue;
			}

			if (type == bgp_show_type_lcommunity_exact) {
				struct lcommunity *lcom = output_arg;

				if (!bgp_attr_get_lcommunity(pi->attr) ||
				    !lcommunity_cmp(
					    bgp_attr_get_lcommunity(pi->attr),
					    lcom))
					continue;
			}
			if (type == bgp_show_type_lcommunity_list) {
				struct community_list *list = output_arg;

				if (!lcommunity_list_match(
					    bgp_attr_get_lcommunity(pi->attr),
					    list))
					continue;
			}
			if (type
			    == bgp_show_type_lcommunity_list_exact) {
				struct community_list *list = output_arg;

				if (!lcommunity_list_exact_match(
					    bgp_attr_get_lcommunity(pi->attr),
					    list))
					continue;
			}
			if (type == bgp_show_type_lcommunity_all) {
				if (!bgp_attr_get_lcommunity(pi->attr))
					continue;
			}
			if (type == bgp_show_type_dampend_paths
			    || type == bgp_show_type_damp_neighbor) {
				if (!CHECK_FLAG(pi->flags, BGP_PATH_DAMPED)
				    || CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
					continue;
			}
			if (type == bgp_show_type_self_originated) {
				if (pi->peer != bgp->peer_self)
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
				vty_out(vty, "local AS ");
				vty_out(vty, ASN_FORMAT(bgp->asnotation),
					&bgp->as);
				vty_out(vty, "\n");
				if (!detail_routes) {
					vty_out(vty, BGP_SHOW_SCODE_HEADER);
					vty_out(vty, BGP_SHOW_NCODE_HEADER);
					vty_out(vty, BGP_SHOW_OCODE_HEADER);
					vty_out(vty, BGP_SHOW_RPKI_HEADER);
				}
				if (type == bgp_show_type_dampend_paths
				    || type == bgp_show_type_damp_neighbor)
					vty_out(vty, BGP_SHOW_DAMP_HEADER);
				else if (type == bgp_show_type_flap_statistics
					 || type == bgp_show_type_flap_neighbor)
					vty_out(vty, BGP_SHOW_FLAP_HEADER);
				else if (!detail_routes)
					vty_out(vty, (wide ? BGP_SHOW_HEADER_WIDE
							   : BGP_SHOW_HEADER));
				header = false;

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
						   afi, safi, use_json,
						   json_paths);
			else if (type == bgp_show_type_flap_statistics
				 || type == bgp_show_type_flap_neighbor)
				flap_route_vty_out(vty, dest_p, pi, display,
						   afi, safi, use_json,
						   json_paths);
			else {
				if (detail_routes || detail_json) {
					const struct prefix_rd *prd = NULL;

					if (dest->pdest)
						prd = bgp_rd_from_dest(
							dest->pdest, safi);

					if (!use_json)
						route_vty_out_detail_header(
							vty, bgp, dest,
							bgp_dest_get_prefix(dest),
							prd, table->afi, safi,
							NULL, false, false);

					route_vty_out_detail(
						vty, bgp, dest, dest_p, pi,
						family2afi(dest_p->family),
						safi, RPKI_NOT_BEING_USED,
						json_paths);
				} else {
					route_vty_out(vty, dest_p, pi, display,
						      safi, json_paths, wide);
				}
			}
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

			/* This is used for 'json detail' vty keywords.
			 *
			 * In plain 'json' the per-prefix header is encoded
			 * as a standalone dictionary in the first json_paths
			 * array element:
			 * "<prefix>": [{header}, {path-1}, {path-N}]
			 * (which is confusing and borderline broken)
			 *
			 * For 'json detail' this changes the value
			 * of each prefix-key to be a dictionary where each
			 * header item has its own key, and json_paths is
			 * tucked under the "paths" key:
			 * "<prefix>": {
			 *   "<header-key-1>": <header-val-1>,
			 *   "<header-key-N>": <header-val-N>,
			 *   "paths": [{path-1}, {path-N}]
			 * }
			 */
			if (json_detail_header && json_paths != NULL) {
				const struct prefix_rd *prd;

				/* Start per-prefix dictionary */
				vty_out(vty, "{\n");

				prd = bgp_rd_from_dest(dest, safi);

				route_vty_out_detail_header(vty, bgp, dest,
							    bgp_dest_get_prefix(
								    dest),
							    prd, table->afi,
							    safi, json_paths,
							    true, false);

				vty_out(vty, "\"paths\": ");
				json_detail_header_used = true;
			}

			/*
			 * We are using no_pretty here because under
			 * extremely high settings( say lots and lots of
			 * routes with lots and lots of ways to reach
			 * that route via different paths ) this can
			 * save several minutes of output when FRR
			 * is run on older cpu's or more underperforming
			 * routers out there
			 */
			vty_json_no_pretty(vty, json_paths);

			/* End per-prefix dictionary */
			if (json_detail_header_used)
				vty_out(vty, "} ");

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
					"\nDisplayed %ld routes and %ld total paths\n",
					output_count, total_count);
		}
	}

	return CMD_SUCCESS;
}

int bgp_show_table_rd(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		      struct bgp_table *table, struct prefix_rd *prd_match,
		      enum bgp_show_type type, void *output_arg,
		      uint16_t show_flags)
{
	struct bgp_dest *dest, *next;
	unsigned long output_cum = 0;
	unsigned long total_cum = 0;
	unsigned long json_header_depth = 0;
	struct bgp_table *itable;
	bool show_msg;
	bool use_json = !!CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	show_msg = (!use_json && type == bgp_show_type_normal);

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
			prefix_rd2str(&prd, rd, sizeof(rd), bgp->asnotation);
			bgp_show_table(vty, bgp, afi, safi, itable, type, output_arg,
				       rd, next == NULL, &output_cum,
				       &total_cum, &json_header_depth,
				       show_flags, RPKI_NOT_BEING_USED);
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
				"\nDisplayed %ld routes and %ld total paths\n",
				output_cum, total_cum);
	} else {
		if (use_json && output_cum == 0 && json_header_depth == 0)
			vty_out(vty, "{}\n");
	}
	return CMD_SUCCESS;
}

static int bgp_show(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		    enum bgp_show_type type, void *output_arg,
		    uint16_t show_flags, enum rpki_states rpki_target_state)
{
	struct bgp_table *table;
	unsigned long json_header_depth = 0;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (bgp == NULL) {
		bgp = bgp_get_default();
	}

	if (bgp == NULL || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}

	/* Labeled-unicast routes live in the unicast table. */
	if (safi == SAFI_LABELED_UNICAST)
		safi = SAFI_UNICAST;

	table = bgp->rib[afi][safi];
	/* use MPLS and ENCAP specific shows until they are merged */
	if (safi == SAFI_MPLS_VPN) {
		return bgp_show_table_rd(vty, bgp, afi, safi, table, NULL, type,
					 output_arg, show_flags);
	}

	if (safi == SAFI_FLOWSPEC && type == bgp_show_type_detail) {
		return bgp_show_table_flowspec(vty, bgp, afi, table, type,
					       output_arg, use_json,
					       1, NULL, NULL);
	}

	if (safi == SAFI_EVPN)
		return bgp_evpn_show_all_routes(vty, bgp, type, use_json, 0);

	return bgp_show_table(vty, bgp, afi, safi, table, type, output_arg, NULL, 1,
			      NULL, NULL, &json_header_depth, show_flags,
			      rpki_target_state);
}

static void bgp_show_all_instances_routes_vty(struct vty *vty, afi_t afi,
					      safi_t safi, uint16_t show_flags)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	int is_first = 1;
	bool route_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;
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
			 show_flags, RPKI_NOT_BEING_USED);
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!route_output)
		vty_out(vty, "%% BGP instance not found\n");
}

/* Header of detailed BGP route information */
void route_vty_out_detail_header(struct vty *vty, struct bgp *bgp,
				 struct bgp_dest *dest, const struct prefix *p,
				 const struct prefix_rd *prd, afi_t afi,
				 safi_t safi, json_object *json,
				 bool incremental_print, bool local_table)
{
	struct bgp_path_info *pi;
	struct peer *peer;
	struct listnode *node, *nnode;
	char buf1[RD_ADDRSTRLEN];
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
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;

	mpls_lse_decode(dest->local_label, &label, &ttl, &exp, &bos);

	has_valid_label = bgp_is_valid_label(&dest->local_label);

	if (safi == SAFI_EVPN) {
		if (!json) {
			vty_out(vty, "BGP routing table entry for %s%s%pFX\n",
				prd ? prefix_rd2str(prd, buf1, sizeof(buf1),
						    bgp->asnotation)
				    : "",
				prd ? ":" : "", (struct prefix_evpn *)p);
		} else {
			json_object_string_add(
				json, "rd",
				prd ? prefix_rd2str(prd, buf1, sizeof(buf1),
						    bgp->asnotation)
				    : "");
			bgp_evpn_route2json((struct prefix_evpn *)p, json);
		}
	} else {
		if (!json) {
			vty_out(vty,
				"BGP routing table entry for %s%s%pFX, version %" PRIu64
				"\n",
				(((safi == SAFI_MPLS_VPN ||
				   safi == SAFI_ENCAP) &&
				  prd)
					 ? prefix_rd2str(prd, buf1,
							 sizeof(buf1),
							 bgp->asnotation)
					 : ""),
				safi == SAFI_MPLS_VPN && prd ? ":" : "", p,
				dest->version);

		} else {
			if (incremental_print) {
				vty_out(vty, "\"prefix\": \"%pFX\",\n", p);
				vty_out(vty, "\"version\": \"%" PRIu64 "\",",
					dest->version);
			} else {
				json_object_string_addf(json, "prefix", "%pFX",
							p);
				json_object_int_add(json, "version",
						    dest->version);
			}
		}
	}

	if (has_valid_label) {
		if (json) {
			if (incremental_print)
				vty_out(vty, "\"localLabel\": \"%u\",\n",
					label);
			else
				json_object_int_add(json, "localLabel", label);
		} else
			vty_out(vty, "Local label: %d\n", label);
	}

	if (!json)
		if (bgp_labeled_safi(safi) && safi != SAFI_EVPN)
			vty_out(vty, "not allocated\n");

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		struct community *picomm = NULL;

		picomm = bgp_attr_get_community(pi->attr);

		count++;
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			best = count;
			if (bgp_path_suppressed(pi))
				suppress = 1;

			if (!picomm)
				continue;

			no_advertise += community_include(
				picomm, COMMUNITY_NO_ADVERTISE);
			no_export +=
				community_include(picomm, COMMUNITY_NO_EXPORT);
			local_as +=
				community_include(picomm, COMMUNITY_LOCAL_AS);
			accept_own +=
				community_include(picomm, COMMUNITY_ACCEPT_OWN);
			route_filter_translated_v4 += community_include(
				picomm, COMMUNITY_ROUTE_FILTER_TRANSLATED_v4);
			route_filter_translated_v6 += community_include(
				picomm, COMMUNITY_ROUTE_FILTER_TRANSLATED_v6);
			route_filter_v4 += community_include(
				picomm, COMMUNITY_ROUTE_FILTER_v4);
			route_filter_v6 += community_include(
				picomm, COMMUNITY_ROUTE_FILTER_v6);
			llgr_stale +=
				community_include(picomm, COMMUNITY_LLGR_STALE);
			no_llgr += community_include(picomm, COMMUNITY_NO_LLGR);
			accept_own_nexthop += community_include(
				picomm, COMMUNITY_ACCEPT_OWN_NEXTHOP);
			blackhole +=
				community_include(picomm, COMMUNITY_BLACKHOLE);
			no_peer += community_include(picomm, COMMUNITY_NO_PEER);
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
				", mark routes to be retained for a longer time. Requires support for Long-lived BGP Graceful Restart");
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

		if (json && json_adv_to) {
			if (incremental_print) {
				vty_out(vty, "\"advertisedTo\": ");
				vty_json(vty, json_adv_to);
				vty_out(vty, ",");
			} else
				json_object_object_add(json, "advertisedTo",
						       json_adv_to);
		} else {
			if (!json && first) {
				if (!local_table)
					vty_out(vty,
						"  Not advertised to any peer");
				else
					vty_out(vty,
						"  Local BGP table not advertised");
			}
			vty_out(vty, "\n");
		}
	}
}

static void bgp_show_path_info(const struct prefix_rd *pfx_rd,
			       struct bgp_dest *bgp_node, struct vty *vty,
			       struct bgp *bgp, afi_t afi, safi_t safi,
			       json_object *json, enum bgp_path_type pathtype,
			       int *display, enum rpki_states rpki_target_state)
{
	struct bgp_path_info *pi;
	int header = 1;
	json_object *json_header = NULL;
	json_object *json_paths = NULL;
	const struct prefix *p = bgp_dest_get_prefix(bgp_node);

	for (pi = bgp_dest_get_bgp_path_info(bgp_node); pi; pi = pi->next) {
		enum rpki_states rpki_curr_state = RPKI_NOT_BEING_USED;

		if (p->family == AF_INET || p->family == AF_INET6)
			rpki_curr_state = hook_call(bgp_rpki_prefix_status,
						    pi->peer, pi->attr, p);

		if (rpki_target_state != RPKI_NOT_BEING_USED
		    && rpki_curr_state != rpki_target_state)
			continue;

		if (json && !json_paths) {
			/* Instantiate json_paths only if path is valid */
			json_paths = json_object_new_array();
			if (pfx_rd)
				json_header = json_object_new_object();
			else
				json_header = json;
		}

		if (header) {
			route_vty_out_detail_header(vty, bgp, bgp_node,
						    bgp_dest_get_prefix(bgp_node),
						    pfx_rd, AFI_IP, safi,
						    json_header, false, false);
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
					     bgp_dest_get_prefix(bgp_node), pi,
					     afi, safi, rpki_curr_state,
					     json_paths);
	}

	if (json && json_paths) {
		json_object_object_add(json_header, "paths", json_paths);

		if (pfx_rd)
			json_object_object_addf(
				json, json_header,
				BGP_RD_AS_FORMAT(bgp->asnotation), pfx_rd);
	}
}

/*
 * Return rd based on safi
 */
const struct prefix_rd *bgp_rd_from_dest(const struct bgp_dest *dest,
					 safi_t safi)
{
	switch (safi) {
	case SAFI_MPLS_VPN:
	case SAFI_ENCAP:
	case SAFI_EVPN:
		return (struct prefix_rd *)(bgp_dest_get_prefix(dest));
	case SAFI_UNSPEC:
	case SAFI_UNICAST:
	case SAFI_MULTICAST:
	case SAFI_LABELED_UNICAST:
	case SAFI_FLOWSPEC:
	case SAFI_MAX:
		return NULL;
	}

	assert(!"Reached end of function when we were not expecting it");
}

/* Display specified route of BGP table. */
static int bgp_show_route_in_table(struct vty *vty, struct bgp *bgp,
				   struct bgp_table *rib, const char *ip_str,
				   afi_t afi, safi_t safi,
				   enum rpki_states rpki_target_state,
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

			rm = bgp_node_match(table, &match);
			if (rm == NULL)
				continue;

			const struct prefix *rm_p = bgp_dest_get_prefix(rm);
			if (prefix_check
			    && rm_p->prefixlen != match.prefixlen) {
				bgp_dest_unlock_node(rm);
				continue;
			}

			bgp_show_path_info((struct prefix_rd *)dest_p, rm, vty,
					   bgp, afi, safi, json, pathtype,
					   &display, rpki_target_state);

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
						rm = bgp_dest_unlock_node(rm);

						assert(rm);
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
					   &display, rpki_target_state);

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
		if (use_json) {
			if (display)
				json_object_object_add(json, "paths",
						       json_paths);
			else
				json_object_free(json_paths);
		}
	} else {
		dest = bgp_node_match(rib, &match);
		if (dest != NULL) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);
			if (!prefix_check
			    || dest_p->prefixlen == match.prefixlen) {
				bgp_show_path_info(NULL, dest, vty, bgp, afi,
						   safi, json, pathtype,
						   &display, rpki_target_state);
			}

			bgp_dest_unlock_node(dest);
		}
	}

	if (use_json) {
		vty_json(vty, json);
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
			  enum rpki_states rpki_target_state, bool use_json)
{
	if (!bgp) {
		bgp = bgp_get_default();
		if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
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
				       afi, safi, rpki_target_state, prd,
				       prefix_check, pathtype, use_json);
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
	uint16_t show_flags = 0;
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
		       lcom, show_flags, RPKI_NOT_BEING_USED);

	lcommunity_free(&lcom);
	return ret;
}

static int bgp_show_lcommunity_list(struct vty *vty, struct bgp *bgp,
				    const char *lcom, bool exact, afi_t afi,
				    safi_t safi, bool uj)
{
	struct community_list *list;
	uint16_t show_flags = 0;

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
			list, show_flags, RPKI_NOT_BEING_USED);
}

DEFUN (show_ip_bgp_large_community_list,
       show_ip_bgp_large_community_list_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] large-community-list <(1-500)|LCOMMUNITY_LIST_NAME> [exact-match] [json]",
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
	uint16_t show_flags = 0;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;

	if (argv_find(argv, argc, "AA:BB:CC", &idx)) {
		if (argv_find(argv, argc, "exact-match", &idx)) {
			argc--;
			exact_match = 1;
		}
		return bgp_show_lcommunity(vty, bgp, argc, argv,
					exact_match, afi, safi, uj);
	} else
		return bgp_show(vty, bgp, afi, safi,
				bgp_show_type_lcommunity_all, NULL, show_flags,
				RPKI_NOT_BEING_USED);
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

	if (uj)
		vty_json(vty, json_all);

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
					    &bgp, uj);
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
		vty_json(vty, json);
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
					    &bgp, uj);
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
		json_object_int_add(json, "bgpBestPathCalls", bgp->bestpath_runs);
		json_object_int_add(json, "bgpNodeOnQueue", bgp->node_already_on_queue);
		json_object_int_add(json, "bgpNodeDeferredOnQueue", bgp->node_deferred_on_queue);
		vty_json(vty, json);
	}
	return ret;
}

DEFPY(show_ip_bgp_dampening_params, show_ip_bgp_dampening_params_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]] [all$all] dampening parameters [json]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Display the entries for all address families\n"
      "Display detailed information about dampening\n"
      "Display detail of configured dampening parameters\n"
      JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0;
	uint16_t show_flags = 0;
	bool uj = use_json(argc, argv);

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

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, false);
	if (!idx)
		return CMD_WARNING;

	return bgp_show_dampening_parameters(vty, afi, safi, show_flags);
}

/* BGP route print out function */
DEFPY(show_ip_bgp, show_ip_bgp_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]]\
          [all$all]\
          [cidr-only\
          |dampening <flap-statistics|dampened-paths>\
          |community [AA:NN|local-AS|no-advertise|no-export\
                     |graceful-shutdown|no-peer|blackhole|llgr-stale|no-llgr\
                     |accept-own|accept-own-nexthop|route-filter-v6\
                     |route-filter-v4|route-filter-translated-v6\
                     |route-filter-translated-v4] [exact-match]\
          |community-list <(1-500)|COMMUNITY_LIST_NAME> [exact-match]\
          |filter-list AS_PATH_FILTER_NAME\
          |prefix-list WORD\
          |access-list ACCESSLIST_NAME\
          |route-map RMAP_NAME\
          |rpki <invalid|valid|notfound>\
          |version (1-4294967295)\
          |alias ALIAS_NAME\
          |A.B.C.D/M longer-prefixes\
          |X:X::X:X/M longer-prefixes\
          |"BGP_SELF_ORIG_CMD_STR"\
          |detail-routes$detail_routes\
          ] [json$uj [detail$detail_json] | wide$wide]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Display the entries for all address families\n"
      "Display only routes with non-natural netmasks\n"
      "Display detailed information about dampening\n"
      "Display flap statistics of routes\n"
      "Display paths suppressed due to dampening\n"
      "Display routes matching the communities\n" COMMUNITY_AANN_STR
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
      "Community-list number\n"
      "Community-list name\n"
      "Display routes matching the community-list\n"
      "Exact match of the communities\n"
      "Display routes conforming to the filter-list\n"
      "Regular expression access list name\n"
      "Display routes conforming to the prefix-list\n"
      "Prefix-list name\n"
      "Display routes conforming to the access-list\n"
      "Access-list name\n"
      "Display routes matching the route-map\n"
      "A route-map to match on\n"
      "RPKI route types\n"
      "A valid path as determined by rpki\n"
      "A invalid path as determined by rpki\n"
      "A path that has no rpki data\n"
      "Display prefixes with matching version numbers\n"
      "Version number and above\n"
      "Display prefixes with matching BGP community alias\n"
      "BGP community alias\n"
      "IPv4 prefix\n"
      "Display route and more specific routes\n"
      "IPv6 prefix\n"
      "Display route and more specific routes\n"
      BGP_SELF_ORIG_HELP_STR
      "Display detailed version of all routes\n"
      JSON_STR
      "Display detailed version of JSON output\n"
      "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	enum bgp_show_type sh_type = bgp_show_type_normal;
	void *output_arg = NULL;
	struct bgp *bgp = NULL;
	int idx = 0;
	int exact_match = 0;
	char *community = NULL;
	bool first = true;
	uint16_t show_flags = 0;
	enum rpki_states rpki_target_state = RPKI_NOT_BEING_USED;
	struct prefix p;

	if (uj) {
		argc--;
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	}

	if (detail_json)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON_DETAIL);

	if (detail_routes)
		SET_FLAG(show_flags, BGP_SHOW_OPT_ROUTES_DETAIL);

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

	if (argv_find(argv, argc, "community-list", &idx)) {
		const char *clist_number_or_name = argv[++idx]->arg;
		struct community_list *list;

		if (argv_find(argv, argc, "exact-match", &idx))
			exact_match = 1;

		list = community_list_lookup(bgp_clist, clist_number_or_name, 0,
					     COMMUNITY_LIST_MASTER);
		if (list == NULL) {
			vty_out(vty, "%% %s community-list not found\n",
				clist_number_or_name);
			return CMD_WARNING;
		}

		if (exact_match)
			sh_type = bgp_show_type_community_list_exact;
		else
			sh_type = bgp_show_type_community_list;
		output_arg = list;
	}

	if (argv_find(argv, argc, "filter-list", &idx)) {
		const char *filter = argv[++idx]->arg;
		struct as_list *as_list;

		as_list = as_list_lookup(filter);
		if (as_list == NULL) {
			vty_out(vty, "%% %s AS-path access-list not found\n",
				filter);
			return CMD_WARNING;
		}

		sh_type = bgp_show_type_filter_list;
		output_arg = as_list;
	}

	if (argv_find(argv, argc, "prefix-list", &idx)) {
		const char *prefix_list_str = argv[++idx]->arg;
		struct prefix_list *plist;

		plist = prefix_list_lookup(afi, prefix_list_str);
		if (plist == NULL) {
			vty_out(vty, "%% %s prefix-list not found\n",
				prefix_list_str);
			return CMD_WARNING;
		}

		sh_type = bgp_show_type_prefix_list;
		output_arg = plist;
	}

	if (argv_find(argv, argc, "access-list", &idx)) {
		const char *access_list_str = argv[++idx]->arg;
		struct access_list *alist;

		alist = access_list_lookup(afi, access_list_str);
		if (!alist) {
			vty_out(vty, "%% %s access-list not found\n",
				access_list_str);
			return CMD_WARNING;
		}

		sh_type = bgp_show_type_access_list;
		output_arg = alist;
	}

	if (argv_find(argv, argc, "route-map", &idx)) {
		const char *rmap_str = argv[++idx]->arg;
		struct route_map *rmap;

		rmap = route_map_lookup_by_name(rmap_str);
		if (!rmap) {
			vty_out(vty, "%% %s route-map not found\n", rmap_str);
			return CMD_WARNING;
		}

		sh_type = bgp_show_type_route_map;
		output_arg = rmap;
	}

	if (argv_find(argv, argc, "rpki", &idx)) {
		sh_type = bgp_show_type_rpki;
		if (argv_find(argv, argc, "valid", &idx))
			rpki_target_state = RPKI_VALID;
		else if (argv_find(argv, argc, "invalid", &idx))
			rpki_target_state = RPKI_INVALID;
		else if (argv_find(argv, argc, "notfound", &idx))
			rpki_target_state = RPKI_NOTFOUND;
	}

	/* Display prefixes with matching version numbers */
	if (argv_find(argv, argc, "version", &idx)) {
		sh_type = bgp_show_type_prefix_version;
		output_arg = argv[idx + 1]->arg;
	}

	/* Display prefixes with matching BGP community alias */
	if (argv_find(argv, argc, "alias", &idx)) {
		sh_type = bgp_show_type_community_alias;
		output_arg = argv[idx + 1]->arg;
	}

	/* prefix-longer */
	if (argv_find(argv, argc, "A.B.C.D/M", &idx)
	    || argv_find(argv, argc, "X:X::X:X/M", &idx)) {
		const char *prefix_str = argv[idx]->arg;

		if (!str2prefix(prefix_str, &p)) {
			vty_out(vty, "%% Malformed Prefix\n");
			return CMD_WARNING;
		}

		sh_type = bgp_show_type_prefix_longer;
		output_arg = &p;
	}

	/* self originated only */
	if (argv_find(argv, argc, BGP_SELF_ORIG_CMD_STR, &idx))
		sh_type = bgp_show_type_self_originated;

	if (!all) {
		/* show bgp: AFI_IP6, show ip bgp: AFI_IP */
		if (community)
			return bgp_show_community(vty, bgp, community,
						  exact_match, afi, safi,
						  show_flags);
		else
			return bgp_show(vty, bgp, afi, safi, sh_type,
					output_arg, show_flags,
					rpki_target_state);
	} else {
		struct listnode *node;
		struct bgp *abgp;
		/* show <ip> bgp ipv4 all: AFI_IP, show <ip> bgp ipv6 all:
		 * AFI_IP6 */

		if (uj)
			vty_out(vty, "{\n");

		if (CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
		    || CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6)) {
			afi = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
				      ? AFI_IP
				      : AFI_IP6;
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, abgp)) {
				FOREACH_SAFI (safi) {
					if (!bgp_afi_safi_peer_exists(abgp, afi,
								      safi))
						continue;

					if (uj) {
						if (first)
							first = false;
						else
							vty_out(vty, ",\n");
						vty_out(vty, "\"%s\":{\n",
							get_afi_safi_str(afi,
									 safi,
									 true));
					} else
						vty_out(vty,
							"\nFor address family: %s\n",
							get_afi_safi_str(
								afi, safi,
								false));

					if (community)
						bgp_show_community(
							vty, abgp, community,
							exact_match, afi, safi,
							show_flags);
					else
						bgp_show(vty, abgp, afi, safi,
							 sh_type, output_arg,
							 show_flags,
							 rpki_target_state);
					if (uj)
						vty_out(vty, "}\n");
				}
			}
		} else {
			/* show <ip> bgp all: for each AFI and SAFI*/
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, abgp)) {
				FOREACH_AFI_SAFI (afi, safi) {
					if (!bgp_afi_safi_peer_exists(abgp, afi,
								      safi))
						continue;

					if (uj) {
						if (first)
							first = false;
						else
							vty_out(vty, ",\n");

						vty_out(vty, "\"%s\":{\n",
							get_afi_safi_str(afi,
									 safi,
									 true));

						/* Adding 'routes' key to make
						 * the json output format valid
						 * for evpn
						 */
						if (safi == SAFI_EVPN)
							vty_out(vty,
								"\"routes\":");

					} else
						vty_out(vty,
							"\nFor address family: %s\n",
							get_afi_safi_str(
								afi, safi,
								false));

					if (community)
						bgp_show_community(
							vty, abgp, community,
							exact_match, afi, safi,
							show_flags);
					else
						bgp_show(vty, abgp, afi, safi,
							 sh_type, output_arg,
							 show_flags,
							 rpki_target_state);
					if (uj)
						vty_out(vty, "}\n");
				}
			}
		}
		if (uj)
			vty_out(vty, "}\n");
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]]<A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> [<bestpath|multipath>] [rpki <valid|invalid|notfound>] [json]",
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
       "Display only paths that match the specified rpki state\n"
       "A valid path as determined by rpki\n"
       "A invalid path as determined by rpki\n"
       "A path that has no rpki data\n"
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
			      path_type, RPKI_NOT_BEING_USED, uj);
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
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0;
	uint16_t show_flags = 0;

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
	uint16_t show_flags = 0;

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

	rc = bgp_show(vty, bgp, afi, safi, type, regex, show_flags,
		      RPKI_NOT_BEING_USED);
	bgp_regex_free(regex);
	return rc;
}

static int bgp_show_community(struct vty *vty, struct bgp *bgp,
			      const char *comstr, int exact, afi_t afi,
			      safi_t safi, uint16_t show_flags)
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
		       com, show_flags, RPKI_NOT_BEING_USED);
	community_free(&com);

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
	BGP_STATS_REDISTRIBUTED,
	BGP_STATS_LOCAL_AGGREGATES,
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
	[BGP_STATS_REDISTRIBUTED] = {"Redistributed routes", "totalRedistributed"},
	[BGP_STATS_LOCAL_AGGREGATES] = {"Local aggregates", "totalLocalAggregates"},
	[BGP_STATS_MAX] = {NULL, NULL}
};

struct bgp_table_stats {
	struct bgp_table *table;
	unsigned long long counts[BGP_STATS_MAX];

	unsigned long long
		prefix_len_count[MAX(EVPN_ROUTE_PREFIXLEN, IPV6_MAX_BITLEN) +
				 1];

	double total_space;
};

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

	ts->prefix_len_count[rn_p->prefixlen]++;
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

		if (pi->peer == ts->table->bgp->peer_self) {
			if (pi->sub_type == BGP_ROUTE_REDISTRIBUTE)
				ts->counts[BGP_STATS_REDISTRIBUTED]++;

			if ((pi->type == ZEBRA_ROUTE_BGP) &&
			    (pi->sub_type == BGP_ROUTE_AGGREGATE))
				ts->counts[BGP_STATS_LOCAL_AGGREGATES]++;
		}

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
			if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
				ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
		}
	}
}

static void bgp_table_stats_walker(struct event *t)
{
	struct bgp_dest *dest, *ndest;
	struct bgp_dest *top;
	struct bgp_table_stats *ts = EVENT_ARG(t);
	unsigned int space = 0;

	if (!(top = bgp_table_top(ts->table)))
		return;

	switch (ts->table->afi) {
	case AFI_IP:
		space = IPV4_MAX_BITLEN;
		break;
	case AFI_IP6:
		space = IPV6_MAX_BITLEN;
		break;
	case AFI_L2VPN:
		space = EVPN_ROUTE_PREFIXLEN;
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		return;
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
	uint32_t bitlen = 0;
	struct json_object *json_bitlen;

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
	event_execute(bm->master, bgp_table_stats_walker, &ts, 0, NULL);

	for (i = 0; i < BGP_STATS_MAX; i++) {
		if ((!json && !table_stats_strs[i][TABLE_STATS_IDX_VTY])
		    || (json && !table_stats_strs[i][TABLE_STATS_IDX_JSON]))
			continue;

		switch (i) {
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

	switch (afi) {
	case AFI_IP:
		bitlen = IPV4_MAX_BITLEN;
		break;
	case AFI_IP6:
		bitlen = IPV6_MAX_BITLEN;
		break;
	case AFI_L2VPN:
		bitlen = EVPN_ROUTE_PREFIXLEN;
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		break;
	}

	if (json) {
		json_bitlen = json_object_new_array();

		for (i = 0; i <= bitlen; i++) {
			if (!ts.prefix_len_count[i])
				continue;

			struct json_object *ind_bit = json_object_new_object();

			snprintf(temp_buf, sizeof(temp_buf), "%u", i);
			json_object_int_add(ind_bit, temp_buf,
					    ts.prefix_len_count[i]);
			json_object_array_add(json_bitlen, ind_bit);
		}
		json_object_object_add(json, "prefixLength", json_bitlen);
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
	PCOUNT_UNSORTED,
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
	[PCOUNT_UNSORTED] = "Unsorted",
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
		if (CHECK_FLAG(pi->flags, BGP_PATH_UNSORTED))
			pc->count[PCOUNT_UNSORTED]++;

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

static void bgp_peer_count_walker(struct event *t)
{
	struct bgp_dest *rn, *rm;
	const struct bgp_table *table;
	struct peer_pcounts *pc = EVENT_ARG(t);

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
			json_object_free(json_loop);
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
	event_execute(bm->master, bgp_peer_count_walker, &pcounts, 0, NULL);

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
		vty_json(vty, json);
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
	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
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
			      BGP_PATH_SHOW_ALL, RPKI_NOT_BEING_USED,
			      use_json(argc, argv));
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
			      RPKI_NOT_BEING_USED, use_json(argc, argv));
}

static void show_adj_route_header(struct vty *vty, struct peer *peer,
				  struct bgp_table *table, int *header1,
				  int *header2, json_object *json, bool wide,
				  bool detail)
{
	uint64_t version = table ? table->version : 0;

	if (*header1) {
		if (json) {
			json_object_int_add(json, "bgpTableVersion", version);
			json_object_string_addf(json, "bgpLocalRouterId",
						"%pI4", &peer->bgp->router_id);
			json_object_int_add(json, "defaultLocPrf",
					    peer->bgp->default_local_pref);
			json_object_int_add(json, "localAS",
					    peer->change_local_as
						    ? peer->change_local_as
						    : peer->local_as);
		} else {
			vty_out(vty,
				"BGP table version is %" PRIu64
				", local router ID is %pI4, vrf id ",
				version, &peer->bgp->router_id);
			if (peer->bgp->vrf_id == VRF_UNKNOWN)
				vty_out(vty, "%s", VRFID_NONE_STR);
			else
				vty_out(vty, "%u", peer->bgp->vrf_id);
			vty_out(vty, "\n");
			vty_out(vty, "Default local pref %u, ",
				peer->bgp->default_local_pref);
			vty_out(vty, "local AS %u\n",
				peer->change_local_as ? peer->change_local_as
						      : peer->local_as);
			if (!detail) {
				vty_out(vty, BGP_SHOW_SCODE_HEADER);
				vty_out(vty, BGP_SHOW_NCODE_HEADER);
				vty_out(vty, BGP_SHOW_OCODE_HEADER);
				vty_out(vty, BGP_SHOW_RPKI_HEADER);
			}
		}
		*header1 = 0;
	}
	if (*header2) {
		if (!json && !detail)
			vty_out(vty, (wide ? BGP_SHOW_HEADER_WIDE
					   : BGP_SHOW_HEADER));
		*header2 = 0;
	}
}

static void
show_adj_route(struct vty *vty, struct peer *peer, struct bgp_table *table,
	       afi_t afi, safi_t safi, enum bgp_show_adj_route_type type,
	       const char *rmap_name, json_object *json, json_object *json_ar,
	       uint16_t show_flags, int *header1, int *header2, char *rd_str,
	       const struct prefix *match, unsigned long *output_count,
	       unsigned long *filtered_count)
{
	struct bgp_adj_in *ain = NULL;
	struct bgp_adj_out *adj = NULL;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct attr attr, attr_unchanged;
	int ret;
	struct update_subgroup *subgrp;
	struct peer_af *paf = NULL;
	bool route_filtered;
	bool detail = CHECK_FLAG(show_flags, BGP_SHOW_OPT_ROUTES_DETAIL);
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);
	bool show_rd = ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
			|| (safi == SAFI_EVPN))
			       ? true
			       : false;
	int display = 0;
	json_object *json_net = NULL;

	bgp = peer->bgp;

	/* If the user supplied a prefix, look for a matching route instead
	 * of walking the whole table.
	 */
	if (match) {
		dest = bgp_node_match(table, match);
		if (!dest) {
			if (!use_json)
				vty_out(vty, "Network not in table\n");
			return;
		}

		const struct prefix *rn_p = bgp_dest_get_prefix(dest);

		if (rn_p->prefixlen != match->prefixlen) {
			if (!use_json)
				vty_out(vty, "Network not in table\n");
			bgp_dest_unlock_node(dest);
			return;
		}

		if (type == bgp_show_adj_route_received ||
		    type == bgp_show_adj_route_filtered) {
			for (ain = dest->adj_in; ain; ain = ain->next) {
				if (ain->peer == peer) {
					attr = *ain->attr;
					break;
				}
			}
			/* bail out if if adj_out is empty, or
			 * if the prefix isn't in this peer's
			 * adj_in
			 */
			if (!ain || ain->peer != peer) {
				if (!use_json)
					vty_out(vty, "Network not in table\n");
				bgp_dest_unlock_node(dest);
				return;
			}
		} else if (type == bgp_show_adj_route_advertised) {
			bool peer_found = false;

			RB_FOREACH (adj, bgp_adj_out_rb, &dest->adj_out) {
				SUBGRP_FOREACH_PEER (adj->subgroup, paf) {
					if (paf->peer == peer && adj->attr) {
						attr = *adj->attr;
						peer_found = true;
						break;
					}
				}
				if (peer_found)
					break;
			}
			/* bail out if if adj_out is empty, or
			 * if the prefix isn't in this peer's
			 * adj_out
			 */
			if (!paf || !peer_found) {
				if (!use_json)
					vty_out(vty, "Network not in table\n");
				bgp_dest_unlock_node(dest);
				return;
			}
		}

		ret = bgp_output_modifier(peer, rn_p, &attr, afi, safi,
					  rmap_name);

		if (ret != RMAP_DENY) {
			show_adj_route_header(vty, peer, table, header1,
					      header2, json, wide, detail);

			if (use_json)
				json_net = json_object_new_object();

			bgp_show_path_info(NULL /* prefix_rd */, dest, vty, bgp,
					   afi, safi, json_net,
					   BGP_PATH_SHOW_ALL, &display,
					   RPKI_NOT_BEING_USED);
			if (use_json)
				json_object_object_addf(json_ar, json_net,
							"%pFX", rn_p);
			(*output_count)++;
		} else
			(*filtered_count)++;

		bgp_attr_flush(&attr);
		bgp_dest_unlock_node(dest);
		return;
	}


	subgrp = peer_subgroup(peer, afi, safi);

	if (type == bgp_show_adj_route_advertised && subgrp
	    && CHECK_FLAG(subgrp->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE)) {
		if (use_json) {
			json_object_int_add(json, "bgpTableVersion",
					    table->version);
			json_object_string_addf(json, "bgpLocalRouterId",
						"%pI4", &bgp->router_id);
			json_object_int_add(json, "defaultLocPrf",
						bgp->default_local_pref);
			json_object_int_add(json, "localAS",
					    peer->change_local_as
						    ? peer->change_local_as
						    : peer->local_as);
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
			vty_out(vty, "local AS %u\n",
				peer->change_local_as ? peer->change_local_as
						      : peer->local_as);
			if (!detail) {
				vty_out(vty, BGP_SHOW_SCODE_HEADER);
				vty_out(vty, BGP_SHOW_NCODE_HEADER);
				vty_out(vty, BGP_SHOW_OCODE_HEADER);
				vty_out(vty, BGP_SHOW_RPKI_HEADER);
			}

			vty_out(vty, "Originating default network %s\n\n",
				(afi == AFI_IP) ? "0.0.0.0/0" : "::/0");
		}
		(*output_count)++;
		*header1 = 0;
	}

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		if (type == bgp_show_adj_route_received
		    || type == bgp_show_adj_route_filtered) {
			for (ain = dest->adj_in; ain; ain = ain->next) {
				if (ain->peer != peer)
					continue;
				show_adj_route_header(vty, peer, table, header1,
						      header2, json, wide,
						      detail);

				if ((safi == SAFI_MPLS_VPN)
				    || (safi == SAFI_ENCAP)
				    || (safi == SAFI_EVPN)) {
					if (use_json)
						json_object_string_add(
							json_ar, "rd", rd_str);
					else if (show_rd && rd_str) {
						vty_out(vty,
							"Route Distinguisher: %s\n",
							rd_str);
						show_rd = false;
					}
				}

				attr = *ain->attr;
				attr_unchanged = *ain->attr;
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
					bgp_attr_flush(&attr);
					continue;
				}

				if (type == bgp_show_adj_route_received
				    && (route_filtered || ret == RMAP_DENY))
					(*filtered_count)++;

				if (detail) {
					if (use_json)
						json_net =
							json_object_new_object();

					struct bgp_path_info bpi;
					struct bgp_dest buildit = *dest;
					struct bgp_dest *pass_in;

					if (route_filtered ||
					    ret == RMAP_DENY) {
						bpi.attr = &attr;
						bpi.peer = peer;
						buildit.info = &bpi;

						pass_in = &buildit;
					} else
						pass_in = dest;
					bgp_show_path_info(
						NULL, pass_in, vty, bgp, afi,
						safi, json_net,
						BGP_PATH_SHOW_ALL, &display,
						RPKI_NOT_BEING_USED);
					if (use_json)
						json_object_object_addf(
							json_ar, json_net,
							"%pFX", rn_p);
				} else
					route_vty_out_tmp(vty, bgp, dest, rn_p, &attr_unchanged,
							  safi, use_json, json_ar, wide);
				bgp_attr_flush(&attr);
				(*output_count)++;
			}
		} else if (type == bgp_show_adj_route_advertised) {
			RB_FOREACH (adj, bgp_adj_out_rb, &dest->adj_out)
				SUBGRP_FOREACH_PEER (adj->subgroup, paf) {
					if (paf->peer != peer || !adj->attr)
						continue;

					show_adj_route_header(vty, peer, table,
							      header1, header2,
							      json, wide,
							      detail);

					const struct prefix *rn_p =
						bgp_dest_get_prefix(dest);

					attr = *adj->attr;
					ret = bgp_output_modifier(
						peer, rn_p, &attr, afi, safi,
						rmap_name);

					if (ret != RMAP_DENY) {
						if ((safi == SAFI_MPLS_VPN)
						    || (safi == SAFI_ENCAP)
						    || (safi == SAFI_EVPN)) {
							if (use_json)
								json_object_string_add(
									json_ar,
									"rd",
									rd_str);
							else if (show_rd
								 && rd_str) {
								vty_out(vty,
									"Route Distinguisher: %s\n",
									rd_str);
								show_rd = false;
							}
						}
						if (detail) {
							if (use_json)
								json_net =
									json_object_new_object();
							bgp_show_path_info(
								NULL /* prefix_rd
								      */
								,
								dest, vty, bgp,
								afi, safi,
								json_net,
								BGP_PATH_SHOW_ALL,
								&display,
								RPKI_NOT_BEING_USED);
							if (use_json)
								json_object_object_addf(
									json_ar,
									json_net,
									"%pFX",
									rn_p);
						} else
							route_vty_out_tmp(vty,
									  bgp,
									  dest,
									  rn_p,
									  &attr,
									  safi,
									  use_json,
									  json_ar,
									  wide);
						(*output_count)++;
					} else {
						(*filtered_count)++;
					}

					bgp_attr_flush(&attr);
				}
		} else if (type == bgp_show_adj_route_bestpath) {
			struct bgp_path_info *pi;

			show_adj_route_header(vty, peer, table, header1,
					      header2, json, wide, detail);

			const struct prefix *rn_p = bgp_dest_get_prefix(dest);

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;

				if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
					continue;

				if (detail) {
					if (use_json)
						json_net =
							json_object_new_object();
					bgp_show_path_info(
						NULL /* prefix_rd */, dest, vty,
						bgp, afi, safi, json_net,
						BGP_PATH_SHOW_BESTPATH,
						&display, RPKI_NOT_BEING_USED);
					if (use_json)
						json_object_object_addf(
							json_ar, json_net,
							"%pFX", rn_p);
				} else
					route_vty_out_tmp(vty, bgp, dest, rn_p,
							  pi->attr, safi,
							  use_json, json_ar,
							  wide);
				(*output_count)++;
			}
		}
	}
}

static int peer_adj_routes(struct vty *vty, struct peer *peer, afi_t afi,
			   safi_t safi, enum bgp_show_adj_route_type type,
			   const char *rmap_name, const struct prefix *match,
			   uint16_t show_flags)
{
	struct bgp *bgp;
	struct bgp_table *table;
	json_object *json = NULL;
	json_object *json_ar = NULL;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	/* Init BGP headers here so they're only displayed once
	 * even if 'table' is 2-tier (MPLS_VPN, ENCAP, EVPN).
	 */
	int header1 = 1;
	int header2 = 1;

	/*
	 * Initialize variables for each RD
	 * All prefixes under an RD is aggregated within "json_routes"
	 */
	char rd_str[BUFSIZ] = {0};
	json_object *json_routes = NULL;


	/* For 2-tier tables, prefix counts need to be
	 * maintained across multiple runs of show_adj_route()
	 */
	unsigned long output_count_per_rd;
	unsigned long filtered_count_per_rd;
	unsigned long output_count = 0;
	unsigned long filtered_count = 0;

	if (use_json) {
		json = json_object_new_object();
		json_ar = json_object_new_object();
	}

	if (!peer || !peer->afc[afi][safi]) {
		if (use_json) {
			json_object_string_add(
				json, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
			json_object_free(json_ar);
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
			json_object_free(json_ar);
		} else
			vty_out(vty,
				"%% Inbound soft reconfiguration not enabled\n");

		return CMD_WARNING;
	}

	bgp = peer->bgp;

	/* labeled-unicast routes live in the unicast table */
	if (safi == SAFI_LABELED_UNICAST)
		table = bgp->rib[afi][SAFI_UNICAST];
	else
		table = bgp->rib[afi][safi];

	if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
	    || (safi == SAFI_EVPN)) {

		struct bgp_dest *dest;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			output_count_per_rd = 0;
			filtered_count_per_rd = 0;

			if (use_json)
				json_routes = json_object_new_object();

			const struct prefix_rd *prd;
			prd = (const struct prefix_rd *)bgp_dest_get_prefix(
				dest);

			prefix_rd2str(prd, rd_str, sizeof(rd_str),
				      bgp->asnotation);

			show_adj_route(vty, peer, table, afi, safi, type,
				       rmap_name, json, json_routes, show_flags,
				       &header1, &header2, rd_str, match,
				       &output_count_per_rd,
				       &filtered_count_per_rd);

			/* Don't include an empty RD in the output! */
			if (json_routes && (output_count_per_rd > 0))
				json_object_object_add(json_ar, rd_str,
						       json_routes);

			output_count += output_count_per_rd;
			filtered_count += filtered_count_per_rd;
		}
	} else
		show_adj_route(vty, peer, table, afi, safi, type, rmap_name,
			       json, json_ar, show_flags, &header1, &header2,
			       rd_str, match, &output_count, &filtered_count);

	if (use_json) {
		if (type == bgp_show_adj_route_advertised)
			json_object_object_add(json, "advertisedRoutes",
					       json_ar);
		else
			json_object_object_add(json, "receivedRoutes", json_ar);
		json_object_int_add(json, "totalPrefixCounter", output_count);
		json_object_int_add(json, "filteredPrefixCounter",
				    filtered_count);

                /*
                 * This is an extremely expensive operation at scale
                 * and non-pretty reduces memory footprint significantly.
                 */
                vty_json_no_pretty(vty, json);
        } else if (output_count > 0) {
		if (!match && filtered_count > 0)
			vty_out(vty,
				"\nTotal number of prefixes %ld (%ld filtered)\n",
				output_count, filtered_count);
		else
			vty_out(vty, "\nTotal number of prefixes %ld\n",
				output_count);
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_bgp_instance_neighbor_bestpath_route,
       show_ip_bgp_instance_neighbor_bestpath_route_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR " [" BGP_SAFI_WITH_LABEL_CMD_STR "]] neighbors <A.B.C.D|X:X::X:X|WORD> bestpath-routes [detail$detail] [json$uj | wide$wide]",
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
       "Display detailed version of routes\n"
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
	uint16_t show_flags = 0;

	if (detail)
		SET_FLAG(show_flags, BGP_SHOW_OPT_ROUTES_DETAIL);

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

	return peer_adj_routes(vty, peer, afi, safi, type, rmap_name, NULL,
			       show_flags);
}

DEFPY(show_ip_bgp_instance_neighbor_advertised_route,
      show_ip_bgp_instance_neighbor_advertised_route_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR " [" BGP_SAFI_WITH_LABEL_CMD_STR "]] [all$all] neighbors <A.B.C.D|X:X::X:X|WORD> <advertised-routes|received-routes|filtered-routes> [route-map RMAP_NAME$route_map] [<A.B.C.D/M|X:X::X:X/M>$prefix | detail$detail] [json$uj | wide$wide]",
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
      "IPv4 prefix\n"
      "IPv6 prefix\n"
      "Display detailed version of routes\n"
      JSON_STR
      "Increase table width for longer prefixes\n")
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	char *peerstr = NULL;
	struct bgp *bgp = NULL;
	struct peer *peer;
	enum bgp_show_adj_route_type type = bgp_show_adj_route_advertised;
	int idx = 0;
	bool first = true;
	uint16_t show_flags = 0;
	struct listnode *node;
	struct bgp *abgp;

	if (detail || prefix_str)
		SET_FLAG(show_flags, BGP_SHOW_OPT_ROUTES_DETAIL);

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

	if (!all)
		return peer_adj_routes(vty, peer, afi, safi, type, route_map,
				       prefix_str ? prefix : NULL, show_flags);
	if (uj)
		vty_out(vty, "{\n");

	if (CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
	    || CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6)) {
		afi = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP) ? AFI_IP
								  : AFI_IP6;
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, abgp)) {
			FOREACH_SAFI (safi) {
				if (!bgp_afi_safi_peer_exists(abgp, afi, safi))
					continue;

				if (uj) {
					if (first)
						first = false;
					else
						vty_out(vty, ",\n");
					vty_out(vty, "\"%s\":",
						get_afi_safi_str(afi, safi,
								 true));
				} else
					vty_out(vty,
						"\nFor address family: %s\n",
						get_afi_safi_str(afi, safi,
								 false));

				peer_adj_routes(vty, peer, afi, safi, type,
						route_map, prefix, show_flags);
			}
		}
	} else {
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, abgp)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (!bgp_afi_safi_peer_exists(abgp, afi, safi))
					continue;

				if (uj) {
					if (first)
						first = false;
					else
						vty_out(vty, ",\n");
					vty_out(vty, "\"%s\":",
						get_afi_safi_str(afi, safi,
								 true));
				} else
					vty_out(vty,
						"\nFor address family: %s\n",
						get_afi_safi_str(afi, safi,
								 false));

				peer_adj_routes(vty, peer, afi, safi, type,
						route_map, prefix, show_flags);
			}
		}
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6> [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD> received prefix-filter [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AF_STR
       BGP_AF_STR
       BGP_AF_MODIFIER_STR
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
	struct peer *peer;
	int count;
	int idx = 0;
	struct bgp *bgp = NULL;
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
	uint16_t show_flags = 0;

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

	return bgp_show(vty, peer->bgp, afi, safi, type, &peer->connection->su,
			show_flags, RPKI_NOT_BEING_USED);
}

/*
 * Used for "detailed" output for cmds like show bgp <afi> <safi> (or)
 * show bgp <vrf> (or) show bgp <vrf> <afi> <safi>
 */
DEFPY(show_ip_bgp_vrf_afi_safi_routes_detailed,
      show_ip_bgp_vrf_afi_safi_routes_detailed_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME$vrf_name] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] detail [json$uj]",
      SHOW_STR
      IP_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      BGP_AFI_HELP_STR
      BGP_SAFI_WITH_LABEL_HELP_STR
      "Detailed information\n"
      JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	int idx = 0;
	uint16_t show_flags = BGP_SHOW_OPT_ROUTES_DETAIL;

	if (uj)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx)
		return CMD_WARNING;
	/* 'vrf all' case to iterate all vrfs & show output per vrf instance */
	if (vrf_name && strmatch(vrf_name, "all")) {
		bgp_show_all_instances_routes_vty(vty, afi, safi, show_flags);
		return CMD_SUCCESS;
	}

	/* All other cases except vrf all */
	return bgp_show(vty, bgp, afi, safi, bgp_show_type_detail, NULL,
			show_flags, RPKI_NOT_BEING_USED);
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
       "show bgp "BGP_AFI_CMD_STR" vpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> <A.B.C.D/M|X:X::X:X/M> [json]",
       SHOW_STR
       BGP_STR
       BGP_AFI_HELP_STR
       BGP_AF_MODIFIER_STR
       "Display information for a route distinguisher\n"
       "Route Distinguisher\n"
       "All Route Distinguishers\n"
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

	if (!strcmp(argv[5]->arg, "all"))
		return bgp_show_route(vty, NULL, argv[6]->arg, afi,
				      SAFI_MPLS_VPN, NULL, 0, BGP_PATH_SHOW_ALL,
				      RPKI_NOT_BEING_USED,
				      use_json(argc, argv));

	ret = str2prefix_rd(argv[5]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	return bgp_show_route(vty, NULL, argv[6]->arg, afi, SAFI_MPLS_VPN, &prd,
			      0, BGP_PATH_SHOW_ALL, RPKI_NOT_BEING_USED,
			      use_json(argc, argv));
}

static struct bgp_distance *bgp_distance_new(void)
{
	return XCALLOC(MTYPE_BGP_DISTANCE, sizeof(struct bgp_distance));
}

static void bgp_distance_free(struct bgp_distance *bdistance)
{
	XFREE(MTYPE_BGP_DISTANCE, bdistance);
}

static int bgp_distance_set(struct vty *vty, const char *distance_str,
			    const char *ip_str, const char *access_list_str)
{
	int ret;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	uint8_t distance;
	struct bgp_dest *dest;
	struct bgp_distance *bdistance;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	ret = str2prefix(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	distance = atoi(distance_str);

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

static int bgp_distance_unset(struct vty *vty, const char *distance_str,
			      const char *ip_str, const char *access_list_str)
{
	int ret;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	int distance;
	struct bgp_dest *dest;
	struct bgp_distance *bdistance;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	ret = str2prefix(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	dest = bgp_node_lookup(bgp_distance_table[afi][safi], &p);
	if (!dest) {
		vty_out(vty, "Can't find specified prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bdistance = bgp_dest_get_bgp_distance_info(dest);
	distance = atoi(distance_str);

	if (bdistance->distance != distance) {
		vty_out(vty, "Distance does not match configured\n");
		bgp_dest_unlock_node(dest);
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_AS_LIST, bdistance->access_list);
	bgp_distance_free(bdistance);

	bgp_dest_set_bgp_path_info(dest, NULL);
	dest = bgp_dest_unlock_node(dest);
	assert(dest);
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
	struct bgp_path_info *bpi_ultimate;

	if (!bgp)
		return 0;

	peer = pinfo->peer;

	if (pinfo->attr->distance)
		return pinfo->attr->distance;

	/* get peer origin to calculate appropriate distance */
	if (pinfo->sub_type == BGP_ROUTE_IMPORTED) {
		bpi_ultimate = bgp_get_imported_bpi_ultimate(pinfo);
		peer = bpi_ultimate->peer;
	}

	/* Check source address.
	 * Note: for aggregate route, peer can have unspec af type.
	 */
	if (pinfo->sub_type != BGP_ROUTE_AGGREGATE &&
	    !sockunion2hostprefix(&peer->connection->su, &q))
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
static void bgp_announce_routes_distance_update(struct bgp *bgp,
						afi_t update_afi,
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

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp (1-255) (1-255) (1-255)",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 2;
	int idx_number_2 = 3;
	int idx_number_3 = 4;
	int distance_ebgp = atoi(argv[idx_number]->arg);
	int distance_ibgp = atoi(argv[idx_number_2]->arg);
	int distance_local = atoi(argv[idx_number_3]->arg);
	afi_t afi;
	safi_t safi;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (bgp->distance_ebgp[afi][safi] != distance_ebgp
	    || bgp->distance_ibgp[afi][safi] != distance_ibgp
	    || bgp->distance_local[afi][safi] != distance_local) {
		bgp->distance_ebgp[afi][safi] = distance_ebgp;
		bgp->distance_ibgp[afi][safi] = distance_ibgp;
		bgp->distance_local[afi][safi] = distance_local;
		bgp_announce_routes_distance_update(bgp, afi, safi);
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp [(1-255) (1-255) (1-255)]",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	safi_t safi;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (bgp->distance_ebgp[afi][safi] != 0
	    || bgp->distance_ibgp[afi][safi] != 0
	    || bgp->distance_local[afi][safi] != 0) {
		bgp->distance_ebgp[afi][safi] = 0;
		bgp->distance_ibgp[afi][safi] = 0;
		bgp->distance_local[afi][safi] = 0;
		bgp_announce_routes_distance_update(bgp, afi, safi);
	}
	return CMD_SUCCESS;
}


DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance (1-255) A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
	int idx_number = 1;
	int idx_ipv4_prefixlen = 2;
	bgp_distance_set(vty, argv[idx_number]->arg,
			 argv[idx_ipv4_prefixlen]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance (1-255) A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
	int idx_number = 2;
	int idx_ipv4_prefixlen = 3;
	bgp_distance_unset(vty, argv[idx_number]->arg,
			   argv[idx_ipv4_prefixlen]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance (1-255) A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
	int idx_number = 1;
	int idx_ipv4_prefixlen = 2;
	int idx_word = 3;
	bgp_distance_set(vty, argv[idx_number]->arg,
			 argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance (1-255) A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
	int idx_number = 2;
	int idx_ipv4_prefixlen = 3;
	int idx_word = 4;
	bgp_distance_unset(vty, argv[idx_number]->arg,
			   argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);
	return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_distance_source,
       ipv6_bgp_distance_source_cmd,
       "distance (1-255) X:X::X:X/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
	bgp_distance_set(vty, argv[1]->arg, argv[2]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source,
       no_ipv6_bgp_distance_source_cmd,
       "no distance (1-255) X:X::X:X/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
	bgp_distance_unset(vty, argv[2]->arg, argv[3]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_distance_source_access_list,
       ipv6_bgp_distance_source_access_list_cmd,
       "distance (1-255) X:X::X:X/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
	bgp_distance_set(vty, argv[1]->arg, argv[2]->arg, argv[3]->arg);
	return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source_access_list,
       no_ipv6_bgp_distance_source_access_list_cmd,
       "no distance (1-255) X:X::X:X/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
	bgp_distance_unset(vty, argv[2]->arg, argv[3]->arg, argv[4]->arg);
	return CMD_SUCCESS;
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening [(1-45) [(1-20000) (1-50000) (1-255)]]",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_half_life = 2;
	int idx_reuse = 3;
	int idx_suppress = 4;
	int idx_max_suppress = 5;
	int half = DEFAULT_HALF_LIFE * 60;
	int reuse = DEFAULT_REUSE;
	int suppress = DEFAULT_SUPPRESS;
	int max = 4 * half;

	if (argc == 6) {
		half = atoi(argv[idx_half_life]->arg) * 60;
		reuse = atoi(argv[idx_reuse]->arg);
		suppress = atoi(argv[idx_suppress]->arg);
		max = atoi(argv[idx_max_suppress]->arg) * 60;
	} else if (argc == 3) {
		half = atoi(argv[idx_half_life]->arg) * 60;
		max = 4 * half;
	}

	/*
	 * These can't be 0 but our SA doesn't understand the
	 * way our cli is constructed
	 */
	assert(reuse);
	assert(half);
	if (suppress < reuse) {
		vty_out(vty,
			"Suppress value cannot be less than reuse value \n");
		return 0;
	}

	return bgp_damp_enable(bgp, bgp_node_afi(vty), bgp_node_safi(vty), half,
			       reuse, suppress, max);
}

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening [(1-45) [(1-20000) (1-50000) (1-255)]]",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	return bgp_damp_disable(bgp, bgp_node_afi(vty), bgp_node_safi(vty));
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
		if (bgp == NULL || IS_BGP_INSTANCE_HIDDEN(bgp)) {
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
			rm = bgp_node_match(table, &match);
			if (rm == NULL)
				continue;

			const struct prefix *rm_p = bgp_dest_get_prefix(dest);

			if (!prefix_check
			    || rm_p->prefixlen == match.prefixlen) {
				pi = bgp_dest_get_bgp_path_info(rm);
				while (pi) {
					if (pi->extra && pi->extra->damp_info) {
						pi_temp = pi->next;
						bgp_damp_info_free(pi->extra->damp_info,
								   NULL, 1);
						pi = pi_temp;
					} else
						pi = pi->next;
				}
			}

			bgp_dest_unlock_node(rm);
		}
	} else {
		dest = bgp_node_match(bgp->rib[afi][safi], &match);
		if (!dest)
			return CMD_SUCCESS;

		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (prefix_check || dest_p->prefixlen != match.prefixlen)
			return CMD_SUCCESS;

		pi = bgp_dest_get_bgp_path_info(dest);
		while (pi) {
			if (!(pi->extra && pi->extra->damp_info)) {
				pi = pi->next;
				continue;
			}

			pi_temp = pi->next;
			struct bgp_damp_info *bdi = pi->extra->damp_info;

			if (bdi->lastrecord != BGP_RECORD_UPDATE)
				continue;

			bgp_aggregate_increment(bgp,
						bgp_dest_get_prefix(bdi->dest),
						bdi->path, bdi->afi, bdi->safi);
			bgp_process(bgp, bdi->dest, bdi->path, bdi->afi,
				    bdi->safi);

			bgp_damp_info_free(pi->extra->damp_info, NULL, 1);
			pi = pi_temp;
		}

		bgp_dest_unlock_node(dest);
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_damp_info_clean(bgp, &bgp->damp[AFI_IP][SAFI_UNICAST], AFI_IP,
			    SAFI_UNICAST);
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
				     prefix_str, sizeof(prefix_str));
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

       vty_out(vty, "\tPeer: %s %pSU\n", peer->host, &peer->connection->su);
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
	       vty_out(vty, "BGP: %s\n", bgp->name_pretty);
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
	struct bgp_static *bgp_static;
	mpls_label_t label;

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

			/* "network" configuration display.  */
			label = decode_label(&bgp_static->label);

			vty_out(vty, "  network %pFX rd %s", p,
				bgp_static->prd_pretty);
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
	struct bgp_static *bgp_static;
	char buf[PREFIX_STRLEN * 2];
	char buf2[SU_ADDRSTRLEN];
	char esi_buf[ESI_STR_LEN];

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

			/* "network" configuration display.  */
			if (p->u.prefix_evpn.route_type == 5) {
				char local_buf[PREFIX_STRLEN];

				uint8_t family = is_evpn_prefix_ipaddr_v4((
							 struct prefix_evpn *)p)
							 ? AF_INET
							 : AF_INET6;
				inet_ntop(family,
					  &p->u.prefix_evpn.prefix_addr.ip.ip
						   .addr,
					  local_buf, sizeof(local_buf));
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
				buf, bgp_static->prd_pretty,
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
	install_element(VIEW_NODE, &show_ip_bgp_afi_safi_statistics_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_statistics_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_dampening_params_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_cmd);
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
	install_element(BGP_NODE, &no_bgp_distance_source_cmd);
	install_element(BGP_NODE, &bgp_distance_source_access_list_cmd);
	install_element(BGP_NODE, &no_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_distance_source_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV4M_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_source_cmd);
	install_element(BGP_IPV4M_NODE, &no_bgp_distance_source_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV6_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV6_NODE, &ipv6_bgp_distance_source_cmd);
	install_element(BGP_IPV6_NODE, &no_ipv6_bgp_distance_source_cmd);
	install_element(BGP_IPV6_NODE,
			&ipv6_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV6_NODE,
			&no_ipv6_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_distance_cmd);
	install_element(BGP_IPV6M_NODE, &no_bgp_distance_cmd);
	install_element(BGP_IPV6M_NODE, &ipv6_bgp_distance_source_cmd);
	install_element(BGP_IPV6M_NODE, &no_ipv6_bgp_distance_source_cmd);
	install_element(BGP_IPV6M_NODE,
			&ipv6_bgp_distance_source_access_list_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_ipv6_bgp_distance_source_access_list_cmd);

	/* BGP dampening */
	install_element(BGP_NODE, &bgp_damp_set_cmd);
	install_element(BGP_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV4_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV4_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV6_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV6_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_damp_unset_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_damp_set_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_damp_unset_cmd);

	/* Large Communities */
	install_element(VIEW_NODE, &show_ip_bgp_large_community_list_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_large_community_cmd);

	/* show bgp vrf <afi> <safi> detailed */
	install_element(VIEW_NODE,
			&show_ip_bgp_vrf_afi_safi_routes_detailed_cmd);

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
