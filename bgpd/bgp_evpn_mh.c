// SPDX-License-Identifier: GPL-2.0-or-later
/* EVPN Multihoming procedures
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 *
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "zclient.h"

#include "lib/printfrr.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_trace.h"

static void bgp_evpn_local_es_down(struct bgp *bgp,
		struct bgp_evpn_es *es);
static void bgp_evpn_local_type1_evi_route_del(struct bgp *bgp,
		struct bgp_evpn_es *es);
static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_add(struct bgp *bgp,
						     struct bgp_evpn_es *es,
						     struct in_addr vtep_ip,
						     bool esr, uint8_t df_alg,
						     uint16_t df_pref);
static void bgp_evpn_es_vtep_del(struct bgp *bgp,
		struct bgp_evpn_es *es, struct in_addr vtep_ip, bool esr);
static void bgp_evpn_es_cons_checks_pend_add(struct bgp_evpn_es *es);
static void bgp_evpn_es_cons_checks_pend_del(struct bgp_evpn_es *es);
static struct bgp_evpn_es_evi *
bgp_evpn_local_es_evi_do_del(struct bgp_evpn_es_evi *es_evi);
static uint32_t bgp_evpn_es_get_active_vtep_cnt(struct bgp_evpn_es *es);
static void bgp_evpn_l3nhg_update_on_vtep_chg(struct bgp_evpn_es *es);
static struct bgp_evpn_es *bgp_evpn_es_new(struct bgp *bgp, const esi_t *esi);
static void bgp_evpn_es_free(struct bgp_evpn_es *es, const char *caller);
static void bgp_evpn_path_es_unlink(struct bgp_path_es_info *es_info);
static void bgp_evpn_mac_update_on_es_local_chg(struct bgp_evpn_es *es,
						bool is_local);

esi_t zero_esi_buf, *zero_esi = &zero_esi_buf;
static void bgp_evpn_run_consistency_checks(struct event *t);
static void bgp_evpn_path_nh_info_free(struct bgp_path_evpn_nh_info *nh_info);
static void bgp_evpn_path_nh_unlink(struct bgp_path_evpn_nh_info *nh_info);

/******************************************************************************
 * per-ES (Ethernet Segment) routing table
 *
 * Following routes are added to the ES's routing table -
 * 1. Local and remote ESR (Type-4)
 * 2. Local EAD-per-ES (Type-1).
 *
 * Key for these routes is {ESI, VTEP-IP} so the path selection is practically
 * a no-op i.e. all paths lead to same VTEP-IP (i.e. result in the same VTEP
 * being added to same ES).
 *
 * Note the following routes go into the VNI routing table (instead of the
 * ES routing table) -
 * 1. Remote EAD-per-ES
 * 2. Local and remote EAD-per-EVI
 */

/* Calculate the best path for a multi-homing (Type-1 or Type-4) route
 * installed in the ES's routing table.
 */
static int bgp_evpn_es_route_select_install(struct bgp *bgp,
					    struct bgp_evpn_es *es,
					    struct bgp_dest *dest)
{
	int ret = 0;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *old_select; /* old best */
	struct bgp_path_info *new_select; /* new best */
	struct bgp_path_info_pair old_and_new;

	/* Compute the best path. */
	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/*
	 * If the best path hasn't changed - see if something needs to be
	 * updated
	 */
	if (old_select && old_select == new_select
	    && old_select->type == ZEBRA_ROUTE_BGP
	    && old_select->sub_type == BGP_ROUTE_IMPORTED
	    && !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		if (bgp_zebra_has_route_changed(old_select)) {
			bgp_evpn_es_vtep_add(bgp, es, old_select->attr->nexthop,
					     true /*esr*/,
					     old_select->attr->df_alg,
					     old_select->attr->df_pref);
		}
		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
		bgp_zebra_clear_route_change_flags(dest);
		return ret;
	}

	/* If the user did a "clear" this flag will be set */
	UNSET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);

	/* bestpath has changed; update relevant fields and install or uninstall
	 * into the zebra RIB.
	 */
	if (old_select || new_select)
		bgp_bump_version(dest);

	if (old_select)
		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(dest, new_select,
					 BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
	}

	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
			&& new_select->sub_type == BGP_ROUTE_IMPORTED) {
		bgp_evpn_es_vtep_add(bgp, es, new_select->attr->nexthop,
				     true /*esr */, new_select->attr->df_alg,
				     new_select->attr->df_pref);
	} else {
		if (old_select && old_select->type == ZEBRA_ROUTE_BGP
				&& old_select->sub_type == BGP_ROUTE_IMPORTED)
			bgp_evpn_es_vtep_del(
					bgp, es, old_select->attr->nexthop,
					true /*esr*/);
	}

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(dest);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(dest, old_select);

	return ret;
}

/* Install Type-1/Type-4 route entry in the per-ES routing table */
static int bgp_evpn_es_route_install(struct bgp *bgp,
		struct bgp_evpn_es *es, struct prefix_evpn *p,
		struct bgp_path_info *parent_pi)
{
	int ret = 0;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;
	struct attr *attr_new = NULL;

	/* Create (or fetch) route within the VNI.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_node_get(es->route_table, (struct prefix *)p);

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Create new route with its attribute. */
		pi = info_make(parent_pi->type, BGP_ROUTE_IMPORTED, 0,
			       parent_pi->peer, attr_new, dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_extra_get(pi);
		if (!pi->extra->vrfleak)
			pi->extra->vrfleak =
				XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
					sizeof(struct bgp_path_info_extra_vrfleak));
		pi->extra->vrfleak->parent = bgp_path_info_lock(parent_pi);
		bgp_dest_lock_node((struct bgp_dest *)parent_pi->net);
		bgp_path_info_add(dest, pi);
	} else {
		if (attrhash_cmp(pi->attr, parent_pi->attr)
				&& !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			bgp_dest_unlock_node(dest);
			return 0;
		}
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(dest, pi);

		/* Mark if nexthop has changed. */
		if (!IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	}

	/* Perform route selection and update zebra, if required. */
	ret = bgp_evpn_es_route_select_install(bgp, es, dest);

	bgp_dest_unlock_node(dest);

	return ret;
}

/* Uninstall Type-1/Type-4 route entry from the ES routing table */
static int bgp_evpn_es_route_uninstall(struct bgp *bgp, struct bgp_evpn_es *es,
		struct prefix_evpn *p, struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (!es->route_table)
		return 0;

	/* Locate route within the ESI.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_node_lookup(es->route_table, (struct prefix *)p);
	if (!dest)
		return 0;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		bgp_dest_unlock_node(dest);
		return 0;
	}

	/* Mark entry for deletion */
	bgp_path_info_delete(dest, pi);

	/* Perform route selection and update zebra, if required. */
	ret = bgp_evpn_es_route_select_install(bgp, es, dest);

	/* Unlock route node. */
	bgp_dest_unlock_node(dest);

	return ret;
}

/* Install or unistall a Type-4 route in the per-ES routing table */
int bgp_evpn_es_route_install_uninstall(struct bgp *bgp, struct bgp_evpn_es *es,
		afi_t afi, safi_t safi, struct prefix_evpn *evp,
		struct bgp_path_info *pi, int install)
{
	int ret = 0;

	if (install)
		ret = bgp_evpn_es_route_install(bgp, es, evp, pi);
	else
		ret = bgp_evpn_es_route_uninstall(bgp, es, evp, pi);

	if (ret) {
		flog_err(
				EC_BGP_EVPN_FAIL,
				"%u: Failed to %s EVPN %s route in ESI %s",
				bgp->vrf_id,
				install ? "install" : "uninstall",
				"ES", es->esi_str);
		return ret;
	}
	return 0;
}

/* Delete (and withdraw) local routes for specified ES from global and ES table.
 * Also remove all remote routes from the per ES table. Invoked when ES
 * is deleted.
 */
static void bgp_evpn_es_route_del_all(struct bgp *bgp, struct bgp_evpn_es *es)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi, *nextpi;

	/* de-activate the ES */
	bgp_evpn_local_es_down(bgp, es);
	bgp_evpn_local_type1_evi_route_del(bgp, es);

	/* Walk this ES's routing table and delete all routes. */
	for (dest = bgp_table_top(es->route_table); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_path_info_delete(dest, pi);
			dest = bgp_path_info_reap(dest, pi);

			assert(dest);
		}
	}
}

/*****************************************************************************
 * Base APIs for creating MH routes (Type-1 or Type-4) on local ethernet
 * segment updates.
 */

/* create or update local EVPN type1/type4 route entry.
 *
 * This could be in -
 *     the ES table if ESR/EAD-ES (or)
 *     the VNI table if EAD-EVI (or)
 *     the global table if ESR/EAD-ES/EAD-EVI
 *
 * Note: vpn is applicable only to EAD-EVI routes (NULL for EAD-ES and
 * ESR).
 */
int bgp_evpn_mh_route_update(struct bgp *bgp, struct bgp_evpn_es *es,
			     struct bgpevpn *vpn, afi_t afi, safi_t safi,
			     struct bgp_dest *dest, struct attr *attr,
			     struct bgp_path_info **ri, int *route_changed)
{
	struct bgp_path_info *tmp_pi = NULL;
	struct bgp_path_info *local_pi = NULL;  /* local route entry if any */
	struct bgp_path_info *remote_pi = NULL; /* remote route entry if any */
	struct attr *attr_new = NULL;
	struct prefix_evpn *evp;

	*ri = NULL;
	evp = (struct prefix_evpn *)bgp_dest_get_prefix(dest);
	*route_changed = 1;

	/* locate the local and remote entries if any */
	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
	     tmp_pi = tmp_pi->next) {
		if (tmp_pi->peer == bgp->peer_self
				&& tmp_pi->type == ZEBRA_ROUTE_BGP
				&& tmp_pi->sub_type == BGP_ROUTE_STATIC)
			local_pi = tmp_pi;
		if (tmp_pi->type == ZEBRA_ROUTE_BGP
				&& tmp_pi->sub_type == BGP_ROUTE_IMPORTED
				&& CHECK_FLAG(tmp_pi->flags, BGP_PATH_VALID))
			remote_pi = tmp_pi;
	}

	/* we don't expect to see a remote_pi at this point as
	 * an ES route has {esi, vtep_ip} as the key in the ES-rt-table
	 * in the VNI-rt-table.
	 */
	if (remote_pi) {
		flog_err(
			EC_BGP_ES_INVALID,
			"%u ERROR: local es route for ESI: %s vtep %pI4 also learnt from remote",
			bgp->vrf_id, es ? es->esi_str : "Null",
			es ? &es->originator_ip : NULL);
		return -1;
	}

	/* create or update the entry */
	if (!local_pi) {

		/* Add or update attribute to hash */
		attr_new = bgp_attr_intern(attr);

		/* Create new route with its attribute. */
		tmp_pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
				   bgp->peer_self, attr_new, dest);
		SET_FLAG(tmp_pi->flags, BGP_PATH_VALID);

		if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
			bgp_path_info_extra_get(tmp_pi);
			tmp_pi->extra->num_labels = 1;
			if (vpn)
				vni2label(vpn->vni, &tmp_pi->extra->label[0]);
			else
				tmp_pi->extra->label[0] = 0;
		}

		/* add the newly created path to the route-node */
		bgp_path_info_add(dest, tmp_pi);
	} else {
		tmp_pi = local_pi;
		if (attrhash_cmp(tmp_pi->attr, attr)
				&& !CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
			*route_changed = 0;
		else {
			/* The attribute has changed.
			 * Add (or update) attribute to hash.
			 */
			attr_new = bgp_attr_intern(attr);
			bgp_path_info_set_flag(dest, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = monotime(NULL);
		}
	}

	if (*route_changed) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"local ES %s vni %u route-type %s nexthop %pI4 updated",
				es ? es->esi_str : "Null", vpn ? vpn->vni : 0,
				evp->prefix.route_type == BGP_EVPN_ES_ROUTE
					? "esr"
					: (vpn ? "ead-evi" : "ead-es"),
				&attr->mp_nexthop_global_in);
	}

	/* Return back the route entry. */
	*ri = tmp_pi;
	return 0;
}

/* Delete local EVPN ESR (type-4) and EAD (type-1) route
 *
 * Note: vpn is applicable only to EAD-EVI routes (NULL for EAD-ES and
 * ESR).
 */
static int bgp_evpn_mh_route_delete(struct bgp *bgp, struct bgp_evpn_es *es,
				    struct bgpevpn *vpn,
				    struct bgp_evpn_es_frag *es_frag,
				    struct prefix_evpn *p)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *pi;
	struct bgp_dest *dest = NULL;	     /* dest in esi table */
	struct bgp_dest *global_dest = NULL; /* dest in global table */
	struct bgp_table *rt_table;
	struct prefix_rd *prd;

	if (vpn) {
		rt_table = vpn->ip_table;
		prd = &vpn->prd;
	} else {
		rt_table = es->route_table;
		prd = &es_frag->prd;
	}

	/* First, locate the route node within the ESI or VNI.
	 * If it doesn't exist, ther is nothing to do.
	 * Note: there is no RD here.
	 */
	dest = bgp_node_lookup(rt_table, (struct prefix *)p);
	if (!dest)
		return 0;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug(
			"local ES %s vni %u route-type %s nexthop %pI4 delete",
			es->esi_str, vpn ? vpn->vni : 0,
			p->prefix.route_type == BGP_EVPN_ES_ROUTE
				? "esr"
				: (vpn ? "ead-evi" : "ead-es"),
			&es->originator_ip);

	/* Next, locate route node in the global EVPN routing table.
	 * Note that this table is a 2-level tree (RD-level + Prefix-level)
	 */
	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, p,
						  prd, NULL);
	if (global_dest) {

		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, afi, safi, global_dest, &pi);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/*
	 * Delete route entry in the ESI or VNI routing table.
	 * This can just be removed.
	 */
	delete_evpn_route_entry(bgp, afi, safi, dest, &pi);
	if (pi)
		dest = bgp_path_info_reap(dest, pi);

	assert(dest);
	bgp_dest_unlock_node(dest);

	return 0;
}

/*
 * This function is called when the VNI RD changes.
 * Delete all EAD/EVI local routes for this VNI from the global routing table.
 * These routes are scheduled for withdraw from peers.
 */
int delete_global_ead_evi_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rdrn, *bd;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Find the RD node for the VNI in the global table */
	rdrn = bgp_node_lookup(bgp->rib[afi][safi], (struct prefix *)&vpn->prd);
	if (rdrn && bgp_dest_has_bgp_path_info_data(rdrn)) {
		table = bgp_dest_get_bgp_table_info(rdrn);

		/*
		 * Iterate over all the routes in this table and delete EAD/EVI
		 * routes
		 */
		for (bd = bgp_table_top(table); bd; bd = bgp_route_next(bd)) {
			struct prefix_evpn *evp = (struct prefix_evpn *)&bd->rn->p;

			if (evp->prefix.route_type != BGP_EVPN_AD_ROUTE)
				continue;

			delete_evpn_route_entry(bgp, afi, safi, bd, &pi);
			if (pi)
				bgp_process(bgp, bd, afi, safi);
		}
	}

	/* Unlock RD node. */
	if (rdrn)
		bgp_dest_unlock_node(rdrn);

	return 0;
}

/*****************************************************************************
 * Ethernet Segment (Type-4) Routes
 * ESRs are used for DF election. Currently service-carving described in
 * RFC 7432 is NOT supported. Instead preference based DF election is
 * used by default.
 * Reference: draft-ietf-bess-evpn-pref-df
 */
/* Build extended community for EVPN ES (type-4) route */
static void bgp_evpn_type4_route_extcomm_build(struct bgp_evpn_es *es,
		struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_es_rt;
	struct ecommunity ecom_df;
	struct ecommunity_val eval;
	struct ecommunity_val eval_es_rt;
	struct ecommunity_val eval_df;
	bgp_encap_types tnl_type;
	struct ethaddr mac;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;
	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));

	/* ES import RT */
	memset(&mac, 0, sizeof(mac));
	memset(&ecom_es_rt, 0, sizeof(ecom_es_rt));
	es_get_system_mac(&es->esi, &mac);
	encode_es_rt_extcomm(&eval_es_rt, &mac);
	ecom_es_rt.size = 1;
	ecom_es_rt.unit_size = ECOMMUNITY_SIZE;
	ecom_es_rt.val = (uint8_t *)eval_es_rt.val;
	bgp_attr_set_ecommunity(
		attr,
		ecommunity_merge(bgp_attr_get_ecommunity(attr), &ecom_es_rt));

	/* DF election extended community */
	memset(&ecom_df, 0, sizeof(ecom_df));
	encode_df_elect_extcomm(&eval_df, es->df_pref);
	ecom_df.size = 1;
	ecom_df.val = (uint8_t *)eval_df.val;
	bgp_attr_set_ecommunity(
		attr,
		ecommunity_merge(bgp_attr_get_ecommunity(attr), &ecom_df));
}

/* Create or update local type-4 route */
static int bgp_evpn_type4_route_update(struct bgp *bgp,
		struct bgp_evpn_es *es, struct prefix_evpn *p)
{
	int ret = 0;
	int route_changed = 0;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct attr *attr_new = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;

	memset(&attr, 0, sizeof(attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.nexthop = es->originator_ip;
	attr.mp_nexthop_global_in = es->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	/* Set up extended community. */
	bgp_evpn_type4_route_extcomm_build(es, &attr);

	/* First, create (or fetch) route node within the ESI. */
	/* NOTE: There is no RD here. */
	dest = bgp_node_get(es->route_table, (struct prefix *)p);

	/* Create or update route entry. */
	ret = bgp_evpn_mh_route_update(bgp, es, NULL, afi, safi, dest, &attr,
				       &pi, &route_changed);
	if (ret != 0)
		flog_err(
			EC_BGP_ES_INVALID,
			"%u ERROR: Failed to updated ES route ESI: %s VTEP %pI4",
			bgp->vrf_id, es->esi_str, &es->originator_ip);

	assert(pi);
	attr_new = pi->attr;

	/* Perform route selection;
	 * this is just to set the flags correctly
	 * as local route in the ES always wins.
	 */
	bgp_evpn_es_route_select_install(bgp, es, dest);
	bgp_dest_unlock_node(dest);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_changed) {
		struct bgp_path_info *global_pi;

		dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
						p, &es->es_base_frag->prd,
						NULL);
		bgp_evpn_mh_route_update(bgp, es, NULL, afi, safi, dest,
					 attr_new, &global_pi, &route_changed);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, dest, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
	return 0;
}

/* Delete local type-4 route */
static int bgp_evpn_type4_route_delete(struct bgp *bgp,
		struct bgp_evpn_es *es, struct prefix_evpn *p)
{
	if (!es->es_base_frag)
		return -1;

	return bgp_evpn_mh_route_delete(bgp, es, NULL /* l2vni */,
					es->es_base_frag, p);
}

/* Process remote/received EVPN type-4 route (advertise or withdraw)  */
int bgp_evpn_type4_route_process(struct peer *peer, afi_t afi, safi_t safi,
		struct attr *attr, uint8_t *pfx, int psize,
		uint32_t addpath_id)
{
	esi_t esi;
	uint8_t ipaddr_len;
	struct in_addr vtep_ip;
	struct prefix_rd prd;
	struct prefix_evpn p;

	/* Type-4 route should be either 23 or 35 bytes
	 *  RD (8), ESI (10), ip-len (1), ip (4 or 16)
	 */
	if (psize != BGP_EVPN_TYPE4_V4_PSIZE &&
			psize != BGP_EVPN_TYPE4_V6_PSIZE) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
				"%u:%s - Rx EVPN Type-4 NLRI with invalid length %d",
				peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, RD_BYTES);
	pfx += RD_BYTES;

	/* get the ESI */
	memcpy(&esi, pfx, ESI_BYTES);
	pfx += ESI_BYTES;


	/* Get the IP. */
	ipaddr_len = *pfx++;
	if (ipaddr_len == IPV4_MAX_BITLEN) {
		memcpy(&vtep_ip, pfx, IPV4_MAX_BYTELEN);
	} else {
		flog_err(
				EC_BGP_EVPN_ROUTE_INVALID,
				"%u:%s - Rx EVPN Type-4 NLRI with unsupported IP address length %d",
				peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	build_evpn_type4_prefix(&p, &esi, vtep_ip);
	/* Process the route. */
	if (attr) {
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	} else {
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0,
			     NULL);
	}
	return 0;
}

/* Check if a prefix belongs to the local ES */
static bool bgp_evpn_type4_prefix_match(struct prefix_evpn *p,
		struct bgp_evpn_es *es)
{
	return (p->prefix.route_type == BGP_EVPN_ES_ROUTE) &&
		!memcmp(&p->prefix.es_addr.esi, &es->esi, sizeof(esi_t));
}

/* Import remote ESRs on local ethernet segment add  */
static int bgp_evpn_type4_remote_routes_import(struct bgp *bgp,
		struct bgp_evpn_es *es, bool install)
{
	int ret;
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this Ethernet Segment.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			struct prefix_evpn *evp =
				(struct prefix_evpn *)bgp_dest_get_prefix(dest);

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				/*
				 * Consider "valid" remote routes applicable for
				 * this ES.
				 */
				if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID)
					&& pi->type == ZEBRA_ROUTE_BGP
					&& pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (!bgp_evpn_type4_prefix_match(evp, es))
					continue;

				if (install)
					ret = bgp_evpn_es_route_install(
							bgp, es, evp, pi);
				else
					ret = bgp_evpn_es_route_uninstall(
							bgp, es, evp, pi);

				if (ret) {
					flog_err(
						EC_BGP_EVPN_FAIL,
						"Failed to %s EVPN %pFX route in ESI %s",
						install ? "install"
							: "uninstall",
						evp, es->esi_str);

					bgp_dest_unlock_node(rd_dest);
					bgp_dest_unlock_node(dest);
					return ret;
				}
			}
		}
	}
	return 0;
}

/*****************************************************************************
 * Ethernet Auto Discovery (EAD/Type-1) route handling
 * There are two types of EAD routes -
 * 1. EAD-per-ES - Key: {ESI, ET=0xffffffff}
 * 2. EAD-per-EVI - Key: {ESI, ET=0}
 */

/* Extended communities associated with EAD-per-ES */
static void
bgp_evpn_type1_es_route_extcomm_build(struct bgp_evpn_es_frag *es_frag,
				      struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_esi_label;
	struct ecommunity_val eval;
	struct ecommunity_val eval_esi_label;
	bgp_encap_types tnl_type;
	struct listnode *evi_node, *rt_node;
	struct ecommunity *ecom;
	struct bgp_evpn_es_evi *es_evi;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;
	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));

	/* ESI label */
	encode_esi_label_extcomm(&eval_esi_label,
			false /*single_active*/);
	ecom_esi_label.size = 1;
	ecom_esi_label.unit_size = ECOMMUNITY_SIZE;
	ecom_esi_label.val = (uint8_t *)eval_esi_label.val;
	bgp_attr_set_ecommunity(attr,
				ecommunity_merge(bgp_attr_get_ecommunity(attr),
						 &ecom_esi_label));

	/* Add export RTs for all L2-VNIs associated with this ES */
	/* XXX - suppress EAD-ES advertisment if there are no EVIs associated
	 * with it.
	 */
	if (listcount(bgp_mh_info->ead_es_export_rtl)) {
		for (ALL_LIST_ELEMENTS_RO(bgp_mh_info->ead_es_export_rtl,
					  rt_node, ecom))
			bgp_attr_set_ecommunity(
				attr, ecommunity_merge(attr->ecommunity, ecom));
	} else {
		for (ALL_LIST_ELEMENTS_RO(es_frag->es_evi_frag_list, evi_node,
					  es_evi)) {
			if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
				continue;
			for (ALL_LIST_ELEMENTS_RO(es_evi->vpn->export_rtl,
						  rt_node, ecom))
				bgp_attr_set_ecommunity(
					attr, ecommunity_merge(attr->ecommunity,
							       ecom));
		}
	}
}

/* Extended communities associated with EAD-per-EVI */
static void bgp_evpn_type1_evi_route_extcomm_build(struct bgp_evpn_es *es,
		struct bgpevpn *vpn, struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity_val eval;
	bgp_encap_types tnl_type;
	struct listnode *rt_node;
	struct ecommunity *ecom;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;
	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));

	/* Add export RTs for the L2-VNI */
	for (ALL_LIST_ELEMENTS_RO(vpn->export_rtl, rt_node, ecom))
		bgp_attr_set_ecommunity(
			attr,
			ecommunity_merge(bgp_attr_get_ecommunity(attr), ecom));
}

/* Update EVPN EAD (type-1) route -
 * vpn - valid for EAD-EVI routes and NULL for EAD-ES routes
 */
static int bgp_evpn_type1_route_update(struct bgp *bgp, struct bgp_evpn_es *es,
				       struct bgpevpn *vpn,
				       struct bgp_evpn_es_frag *es_frag,
				       struct prefix_evpn *p)
{
	int ret = 0;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct attr *attr_new = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;
	int route_changed = 0;
	struct prefix_rd *global_rd;

	memset(&attr, 0, sizeof(attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.nexthop = es->originator_ip;
	attr.mp_nexthop_global_in = es->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	if (vpn) {
		/* EAD-EVI route update */
		/* MPLS label */
		vni2label(vpn->vni, &(attr.label));

		/* Set up extended community */
		bgp_evpn_type1_evi_route_extcomm_build(es, vpn, &attr);

		/* First, create (or fetch) route node within the VNI. */
		dest = bgp_node_get(vpn->ip_table, (struct prefix *)p);

		/* Create or update route entry. */
		ret = bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					       &attr, &pi, &route_changed);
		if (ret != 0)
			flog_err(
				EC_BGP_ES_INVALID,
				"%u Failed to update EAD-EVI route ESI: %s VNI %u VTEP %pI4",
				bgp->vrf_id, es->esi_str, vpn->vni,
				&es->originator_ip);
		global_rd = &vpn->prd;
	} else {
		/* EAD-ES route update */
		/* MPLS label is 0 for EAD-ES route */

		/* Set up extended community */
		bgp_evpn_type1_es_route_extcomm_build(es_frag, &attr);

		/* First, create (or fetch) route node within the ES. */
		/* NOTE: There is no RD here. */
		/* XXX: fragment ID must be included as a part of the prefix. */
		dest = bgp_node_get(es->route_table, (struct prefix *)p);

		/* Create or update route entry. */
		ret = bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					       &attr, &pi, &route_changed);
		if (ret != 0) {
			flog_err(
				EC_BGP_ES_INVALID,
				"%u ERROR: Failed to updated EAD-ES route ESI: %s VTEP %pI4",
				bgp->vrf_id, es->esi_str, &es->originator_ip);
		}
		global_rd = &es_frag->prd;
	}


	assert(pi);
	attr_new = pi->attr;

	/* Perform route selection;
	 * this is just to set the flags correctly as local route in
	 * the ES always wins.
	 */
	evpn_route_select_install(bgp, vpn, dest);
	bgp_dest_unlock_node(dest);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_changed) {
		struct bgp_path_info *global_pi;

		dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
						p, global_rd, NULL);
		bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					 attr_new, &global_pi, &route_changed);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, dest, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
	return 0;
}

/*
 * This function is called when the export RT for a VNI changes.
 * Update all type-1 local routes for this VNI from VNI/ES tables and the global
 * table and advertise these routes to peers.
 */

static void bgp_evpn_ead_es_route_update(struct bgp *bgp,
					 struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct bgp_evpn_es_frag *es_frag;
	struct prefix_evpn p;

	build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG, &es->esi,
				es->originator_ip);
	for (ALL_LIST_ELEMENTS_RO(es->es_frag_list, node, es_frag)) {
		if (!listcount(es_frag->es_evi_frag_list))
			continue;

		p.prefix.ead_addr.frag_id = es_frag->rd_id;
		if (bgp_evpn_type1_route_update(bgp, es, NULL, es_frag, &p))
			flog_err(
				EC_BGP_EVPN_ROUTE_CREATE,
				"EAD-ES route creation failure for ESI %s frag %u",
				es->esi_str, es_frag->rd_id);
	}
}

static void bgp_evpn_ead_evi_route_update(struct bgp *bgp,
					  struct bgp_evpn_es *es,
					  struct bgpevpn *vpn,
					  struct prefix_evpn *p)
{
	if (bgp_evpn_type1_route_update(bgp, es, vpn, NULL, p))
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
			 "EAD-EVI route creation failure for ESI %s VNI %u",
			 es->esi_str, vpn->vni);
}

void update_type1_routes_for_evi(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct prefix_evpn p;
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;


	RB_FOREACH (es_evi, bgp_es_evi_rb_head, &vpn->es_evi_rb_tree) {
		es = es_evi->es;

		if (es_evi->vpn != vpn)
			continue;

		/* Update EAD-ES */
		if (bgp_evpn_local_es_is_active(es))
			bgp_evpn_ead_es_route_update(bgp, es);

		/* Update EAD-EVI */
		if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
			build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
						&es->esi, es->originator_ip);
			bgp_evpn_ead_evi_route_update(bgp, es, vpn, &p);
		}
	}
}

/* Delete local Type-1 route */
static void bgp_evpn_ead_es_route_delete(struct bgp *bgp,
					 struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct bgp_evpn_es_frag *es_frag;
	struct prefix_evpn p;

	build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG, &es->esi,
				es->originator_ip);
	for (ALL_LIST_ELEMENTS_RO(es->es_frag_list, node, es_frag)) {
		p.prefix.ead_addr.frag_id = es_frag->rd_id;
		bgp_evpn_mh_route_delete(bgp, es, NULL, es_frag, &p);
	}
}

static int bgp_evpn_ead_evi_route_delete(struct bgp *bgp,
					 struct bgp_evpn_es *es,
					 struct bgpevpn *vpn,
					 struct prefix_evpn *p)
{
	return bgp_evpn_mh_route_delete(bgp, es, vpn, NULL, p);
}

/* Generate EAD-EVI for all VNIs */
static void bgp_evpn_local_type1_evi_route_add(struct bgp *bgp,
		struct bgp_evpn_es *es)
{
	struct listnode *evi_node;
	struct prefix_evpn p;
	struct bgp_evpn_es_evi *es_evi;

	/* EAD-per-EVI routes have been suppressed */
	if (!bgp_mh_info->ead_evi_tx)
		return;

	if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI))
		/* EAD-EVI route add for this ES is already done */
		return;

	SET_FLAG(es->flags, BGP_EVPNES_ADV_EVI);
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
			&es->esi, es->originator_ip);

	for (ALL_LIST_ELEMENTS_RO(es->es_evi_list, evi_node, es_evi)) {
		if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
			continue;
		bgp_evpn_ead_evi_route_update(bgp, es, es_evi->vpn, &p);
	}
}

/*
 * Withdraw EAD-EVI for all VNIs
 */
static void bgp_evpn_local_type1_evi_route_del(struct bgp *bgp,
		struct bgp_evpn_es *es)
{
	struct listnode *evi_node;
	struct prefix_evpn p;
	struct bgp_evpn_es_evi *es_evi;

	/* Delete and withdraw locally learnt EAD-EVI route */
	if (!CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI))
		/* EAD-EVI route has not been advertised for this ES */
		return;

	UNSET_FLAG(es->flags, BGP_EVPNES_ADV_EVI);
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
			&es->esi, es->originator_ip);
	for (ALL_LIST_ELEMENTS_RO(es->es_evi_list, evi_node, es_evi)) {
		if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
			continue;
		if (bgp_evpn_mh_route_delete(bgp, es, es_evi->vpn, NULL, &p))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
					"%u: Type4 route creation failure for ESI %s",
					bgp->vrf_id, es->esi_str);
	}
}

/*
 * Process received EVPN type-1 route (advertise or withdraw).
 */
int bgp_evpn_type1_route_process(struct peer *peer, afi_t afi, safi_t safi,
		struct attr *attr, uint8_t *pfx, int psize,
		uint32_t addpath_id)
{
	struct prefix_rd prd;
	esi_t esi;
	uint32_t eth_tag;
	mpls_label_t label;
	struct in_addr vtep_ip;
	struct prefix_evpn p;

	if (psize != BGP_EVPN_TYPE1_PSIZE) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
				"%u:%s - Rx EVPN Type-1 NLRI with invalid length %d",
				peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, RD_BYTES);
	pfx += RD_BYTES;

	/* get the ESI */
	memcpy(&esi, pfx, ESI_BYTES);
	pfx += ESI_BYTES;

	/* Copy Ethernet Tag */
	memcpy(&eth_tag, pfx, EVPN_ETH_TAG_BYTES);
	eth_tag = ntohl(eth_tag);
	pfx += EVPN_ETH_TAG_BYTES;

	memcpy(&label, pfx, BGP_LABEL_BYTES);

	/* EAD route prefix doesn't include the nexthop in the global
	 * table
	 */
	vtep_ip.s_addr = INADDR_ANY;
	build_evpn_type1_prefix(&p, eth_tag, &esi, vtep_ip);
	/* Process the route. */
	if (attr) {
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	} else {
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0,
			     NULL);
	}
	return 0;
}

void bgp_evpn_mh_config_ead_export_rt(struct bgp *bgp,
				      struct ecommunity *ecomcfg, bool del)
{
	struct listnode *node, *nnode, *node_to_del;
	struct ecommunity *ecom;
	struct bgp_evpn_es *es;

	if (del) {
		if (ecomcfg == NULL) {
			/* Reset to default and process all routes. */
			for (ALL_LIST_ELEMENTS(bgp_mh_info->ead_es_export_rtl,
					       node, nnode, ecom)) {
				ecommunity_free(&ecom);
				list_delete_node(bgp_mh_info->ead_es_export_rtl,
						 node);
			}
		}

		/* Delete a specific export RT */
		else {
			node_to_del = NULL;

			for (ALL_LIST_ELEMENTS(bgp_mh_info->ead_es_export_rtl,
					       node, nnode, ecom)) {
				if (ecommunity_match(ecom, ecomcfg)) {
					ecommunity_free(&ecom);
					node_to_del = node;
					break;
				}
			}

			assert(node_to_del);
			list_delete_node(bgp_mh_info->ead_es_export_rtl,
					 node_to_del);
		}
	} else {
		listnode_add_sort(bgp_mh_info->ead_es_export_rtl, ecomcfg);
	}

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("local ES del/re-add EAD route on export RT change");
	/*
	 * walk through all active ESs withdraw the old EAD and
	 * generate a new one
	 */
	RB_FOREACH (es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree) {
		if (!bgp_evpn_is_es_local(es) ||
		    !bgp_evpn_local_es_is_active(es))
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"local ES %s del/re-add EAD route on export RT change",
				es->esi_str);

		/*
		 * withdraw EAD-ES. XXX - this should technically not be
		 * needed; can be removed after testing
		 */
		bgp_evpn_ead_es_route_delete(bgp, es);

		/* generate EAD-ES */
		bgp_evpn_ead_es_route_update(bgp, es);
	}
}

/*****************************************************************************/
/* Ethernet Segment Management
 * 1. Ethernet Segment is a collection of links attached to the same
 *    server (MHD) or switch (MHN)
 * 2. An Ethernet Segment can span multiple PEs and is identified by the
 *    10-byte ES-ID.
 * 3. Local ESs are configured in zebra and sent to BGP
 * 4. Remote ESs are created by BGP when one or more ES-EVIs reference it i.e.
 *    created on first reference and release on last de-reference
 * 5. An ES can be both local and remote. Infact most local ESs are expected
 *    to have an ES peer.
 */

/* A list of remote VTEPs is maintained for each ES. This list includes -
 * 1. VTEPs for which we have imported the ESR i.e. ES-peers
 * 2. VTEPs that have an "active" ES-EVI VTEP i.e. EAD-per-ES and EAD-per-EVI
 *    have been imported into one or more VNIs
 */
static int bgp_evpn_es_vtep_cmp(void *p1, void *p2)
{
	const struct bgp_evpn_es_vtep *es_vtep1 = p1;
	const struct bgp_evpn_es_vtep *es_vtep2 = p2;

	return es_vtep1->vtep_ip.s_addr - es_vtep2->vtep_ip.s_addr;
}

static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_new(struct bgp_evpn_es *es,
		struct in_addr vtep_ip)
{
	struct bgp_evpn_es_vtep *es_vtep;

	es_vtep = XCALLOC(MTYPE_BGP_EVPN_ES_VTEP, sizeof(*es_vtep));

	es_vtep->es = es;
	es_vtep->vtep_ip.s_addr = vtep_ip.s_addr;
	inet_ntop(AF_INET, &es_vtep->vtep_ip, es_vtep->vtep_str,
		  sizeof(es_vtep->vtep_str));
	listnode_init(&es_vtep->es_listnode, es_vtep);
	listnode_add_sort(es->es_vtep_list, &es_vtep->es_listnode);

	return es_vtep;
}

static void bgp_evpn_es_vtep_free(struct bgp_evpn_es_vtep *es_vtep)
{
	struct bgp_evpn_es *es = es_vtep->es;

	if (CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ESR) ||
			es_vtep->evi_cnt)
		/* as long as there is some reference we can't free it */
		return;

	list_delete_node(es->es_vtep_list, &es_vtep->es_listnode);
	XFREE(MTYPE_BGP_EVPN_ES_VTEP, es_vtep);
}

/* check if VTEP is already part of the list */
static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_find(struct bgp_evpn_es *es,
		struct in_addr vtep_ip)
{
	struct listnode *node = NULL;
	struct bgp_evpn_es_vtep *es_vtep;

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (es_vtep->vtep_ip.s_addr == vtep_ip.s_addr)
			return es_vtep;
	}
	return NULL;
}

/* Send the remote ES to zebra for NHG programming */
static int bgp_zebra_send_remote_es_vtep(struct bgp *bgp,
		struct bgp_evpn_es_vtep *es_vtep, bool add)
{
	struct bgp_evpn_es *es = es_vtep->es;
	struct stream *s;
	uint32_t flags = 0;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("No zebra instance, not installing remote es %s",
					es->esi_str);
		return 0;
	}

	if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
		flags |= ZAPI_ES_VTEP_FLAG_ESR_RXED;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
		add ? ZEBRA_REMOTE_ES_VTEP_ADD : ZEBRA_REMOTE_ES_VTEP_DEL,
		bgp->vrf_id);
	stream_put(s, &es->esi, sizeof(esi_t));
	stream_put_ipv4(s, es_vtep->vtep_ip.s_addr);
	if (add) {
		stream_putl(s, flags);
		stream_putc(s, es_vtep->df_alg);
		stream_putw(s, es_vtep->df_pref);
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("Tx %s Remote ESI %s VTEP %pI4", add ? "ADD" : "DEL",
			   es->esi_str, &es_vtep->vtep_ip);

	frrtrace(3, frr_bgp, evpn_mh_vtep_zsend, add, es, es_vtep);

	return zclient_send_message(zclient);
}

static void bgp_evpn_es_vtep_re_eval_active(struct bgp *bgp,
					    struct bgp_evpn_es_vtep *es_vtep,
					    bool param_change)
{
	bool old_active;
	bool new_active;

	old_active = CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);
	/* currently we need an active EVI reference to use the VTEP as
	 * a nexthop. this may change...
	 */
	if (es_vtep->evi_cnt)
		SET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);
	else
		UNSET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);

	new_active = CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);

	if ((old_active != new_active) || (new_active && param_change)) {

		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("es %s vtep %pI4 %s df %u/%u",
				   es_vtep->es->esi_str, &es_vtep->vtep_ip,
				   new_active ? "active" : "inactive",
				   es_vtep->df_alg, es_vtep->df_pref);

		/* send remote ES to zebra */
		bgp_zebra_send_remote_es_vtep(bgp, es_vtep, new_active);

		/* The NHG is updated first for efficient failover handling.
		 * Note the NHG can be de-activated while there are bgp
		 * routes referencing it. Zebra is capable of handling that
		 * elegantly by holding the NHG till all routes using it are
		 * removed.
		 */
		bgp_evpn_l3nhg_update_on_vtep_chg(es_vtep->es);
		/* queue up the es for background consistency checks */
		bgp_evpn_es_cons_checks_pend_add(es_vtep->es);
	}
}

static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_add(struct bgp *bgp,
						     struct bgp_evpn_es *es,
						     struct in_addr vtep_ip,
						     bool esr, uint8_t df_alg,
						     uint16_t df_pref)
{
	struct bgp_evpn_es_vtep *es_vtep;
	bool param_change = false;

	es_vtep = bgp_evpn_es_vtep_find(es, vtep_ip);

	if (!es_vtep)
		es_vtep = bgp_evpn_es_vtep_new(es, vtep_ip);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vtep %pI4 add %s df %u/%u",
			   es_vtep->es->esi_str, &es_vtep->vtep_ip,
			   esr ? "esr" : "ead", df_alg, df_pref);

	if (esr) {
		SET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ESR);
		if ((es_vtep->df_pref != df_pref)
		    || (es_vtep->df_alg != df_alg)) {
			param_change = true;
			es_vtep->df_pref = df_pref;
			es_vtep->df_alg = df_alg;
		}
	} else {
		++es_vtep->evi_cnt;
	}

	bgp_evpn_es_vtep_re_eval_active(bgp, es_vtep, param_change);

	return es_vtep;
}

static void bgp_evpn_es_vtep_do_del(struct bgp *bgp,
		struct bgp_evpn_es_vtep *es_vtep, bool esr)
{
	bool param_change = false;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vtep %pI4 del %s", es_vtep->es->esi_str,
			   &es_vtep->vtep_ip, esr ? "esr" : "ead");
	if (esr) {
		UNSET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ESR);
		if (es_vtep->df_pref || es_vtep->df_alg) {
			param_change = true;
			es_vtep->df_pref = 0;
			es_vtep->df_alg = 0;
		}
	} else {
		if (es_vtep->evi_cnt)
			--es_vtep->evi_cnt;
	}

	bgp_evpn_es_vtep_re_eval_active(bgp, es_vtep, param_change);
	bgp_evpn_es_vtep_free(es_vtep);
}

static void bgp_evpn_es_vtep_del(struct bgp *bgp,
		struct bgp_evpn_es *es, struct in_addr vtep_ip, bool esr)
{
	struct bgp_evpn_es_vtep *es_vtep;

	es_vtep = bgp_evpn_es_vtep_find(es, vtep_ip);
	if (es_vtep)
		bgp_evpn_es_vtep_do_del(bgp, es_vtep, esr);
}

/********************** ES MAC-IP paths *************************************
 * 1. Local MAC-IP routes in the VNI routing table are linked to the
 * destination ES (macip_evi_path_list) for efficient updates on ES oper
 * state changes.
 * 2. Non-local MAC-IP routes in the global routing table are linked to
 * the detination for efficient updates on -
 * a. VTEP add/del - this results in a L3NHG update.
 * b. ES-VRF add/del - this may result in the host route being migrated to
 *    L3NHG or vice versa (flat multipath list).
 ****************************************************************************/
static void bgp_evpn_path_es_info_free(struct bgp_path_es_info *es_info)
{
	bgp_evpn_path_es_unlink(es_info);
	XFREE(MTYPE_BGP_EVPN_PATH_ES_INFO, es_info);
}

void bgp_evpn_path_mh_info_free(struct bgp_path_mh_info *mh_info)
{
	if (mh_info->es_info)
		bgp_evpn_path_es_info_free(mh_info->es_info);
	if (mh_info->nh_info)
		bgp_evpn_path_nh_info_free(mh_info->nh_info);
	XFREE(MTYPE_BGP_EVPN_PATH_MH_INFO, mh_info);
}

static struct bgp_path_es_info *
bgp_evpn_path_es_info_new(struct bgp_path_info *pi, vni_t vni)
{
	struct bgp_path_info_extra *e;
	struct bgp_path_mh_info *mh_info;
	struct bgp_path_es_info *es_info;

	e = bgp_path_info_extra_get(pi);

	/* If mh_info doesn't exist allocate it */
	mh_info = e->evpn->mh_info;
	if (!mh_info)
		e->evpn->mh_info = mh_info =
			XCALLOC(MTYPE_BGP_EVPN_PATH_MH_INFO,
				sizeof(struct bgp_path_mh_info));

	/* If es_info doesn't exist allocate it */
	es_info = mh_info->es_info;
	if (!es_info) {
		mh_info->es_info = es_info =
			XCALLOC(MTYPE_BGP_EVPN_PATH_ES_INFO,
				sizeof(struct bgp_path_es_info));
		es_info->vni = vni;
		es_info->pi = pi;
	}

	return es_info;
}

static void bgp_evpn_path_es_unlink(struct bgp_path_es_info *es_info)
{
	struct bgp_evpn_es *es = es_info->es;
	struct bgp_path_info *pi;

	if (!es)
		return;

	pi = es_info->pi;
	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("vni %u path %pFX unlinked from es %s", es_info->vni,
			   &pi->net->rn->p, es->esi_str);

	if (es_info->vni)
		list_delete_node(es->macip_evi_path_list,
				 &es_info->es_listnode);
	else
		list_delete_node(es->macip_global_path_list,
				 &es_info->es_listnode);

	es_info->es = NULL;

	/* if there are no other references against the ES it
	 * needs to be freed
	 */
	bgp_evpn_es_free(es, __func__);

	/* Note we don't free the path es_info on unlink; it will be freed up
	 * along with the path.
	 */
}

void bgp_evpn_path_es_link(struct bgp_path_info *pi, vni_t vni, esi_t *esi)
{
	struct bgp_path_es_info *es_info;
	struct bgp_evpn_es *es;
	struct bgp *bgp_evpn;

	es_info = (pi->extra && pi->extra->evpn && pi->extra->evpn->mh_info)
			  ? pi->extra->evpn->mh_info->es_info
			  : NULL;
	/* if the esi is zero just unlink the path from the old es */
	if (!esi || !memcmp(esi, zero_esi, sizeof(*esi))) {
		if (es_info)
			bgp_evpn_path_es_unlink(es_info);
		return;
	}

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	/* setup es_info against the path if it doesn't aleady exist */
	if (!es_info)
		es_info = bgp_evpn_path_es_info_new(pi, vni);

	/* find-create ES */
	es = bgp_evpn_es_find(esi);
	if (!es)
		es = bgp_evpn_es_new(bgp_evpn, esi);

	/* dup check */
	if (es_info->es == es)
		return;

	/* unlink old ES if any */
	bgp_evpn_path_es_unlink(es_info);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("vni %u path %pFX linked to es %s", vni, &pi->net->rn->p,
			   es->esi_str);

	/* link mac-ip path to the new destination ES */
	es_info->es = es;
	listnode_init(&es_info->es_listnode, es_info);
	if (es_info->vni)
		listnode_add(es->macip_evi_path_list, &es_info->es_listnode);
	else
		listnode_add(es->macip_global_path_list, &es_info->es_listnode);
}

static bool bgp_evpn_is_macip_path(struct bgp_path_info *pi)
{
	struct prefix_evpn *evp;

	/* Only MAC-IP routes need to be linked (MAC-only routes can be
	 * skipped) as these lists are maintained for managing
	 * host routes in the tenant VRF
	 */
	evp = (struct prefix_evpn *)&pi->net->rn->p;
	return is_evpn_prefix_ipaddr_v4(evp) || is_evpn_prefix_ipaddr_v6(evp);
}

/* When a remote ES is added to a VRF, routes using that as
 * a destination need to be migrated to a L3NHG or viceversa.
 * This is done indirectly by re-attempting an install of the
 * route in the associated VRFs. As a part of the VRF install use
 * of l3 NHG is evaluated and this results in the
 * attr.es_flag ATTR_ES_L3_NHG_USE being set or cleared.
 */
static void
bgp_evpn_es_path_update_on_es_vrf_chg(struct bgp_evpn_es_vrf *es_vrf,
				      const char *reason)
{
	struct listnode *node;
	struct bgp_path_es_info *es_info;
	struct bgp_path_info *pi;
	struct bgp_evpn_es *es = es_vrf->es;

	if (!bgp_mh_info->host_routes_use_l3nhg)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("update paths linked to es %s on es-vrf %s %s",
			   es->esi_str, es_vrf->bgp_vrf->name_pretty, reason);

	for (ALL_LIST_ELEMENTS_RO(es->macip_global_path_list, node, es_info)) {
		pi = es_info->pi;

		if (!bgp_evpn_is_macip_path(pi))
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"update path %pFX linked to es %s on vrf chg",
				&pi->net->rn->p, es->esi_str);
		bgp_evpn_route_entry_install_if_vrf_match(es_vrf->bgp_vrf, pi,
							  1);
	}
}

static void bgp_evpn_es_frag_free(struct bgp_evpn_es_frag *es_frag)
{
	struct bgp_evpn_es *es = es_frag->es;

	if (es->es_base_frag == es_frag)
		es->es_base_frag = NULL;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s frag %u free", es->esi_str, es_frag->rd_id);
	list_delete_node(es->es_frag_list, &es_frag->es_listnode);

	/* EVIs that are advertised using the info in this fragment */
	list_delete(&es_frag->es_evi_frag_list);

	bf_release_index(bm->rd_idspace, es_frag->rd_id);


	XFREE(MTYPE_BGP_EVPN_ES_FRAG, es_frag);
}

static void bgp_evpn_es_frag_free_unused(struct bgp_evpn_es_frag *es_frag)
{
	if ((es_frag->es->es_base_frag == es_frag) ||
	    listcount(es_frag->es_evi_frag_list))
		return;

	bgp_evpn_es_frag_free(es_frag);
}

static void bgp_evpn_es_frag_free_all(struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct listnode *nnode;
	struct bgp_evpn_es_frag *es_frag;

	for (ALL_LIST_ELEMENTS(es->es_frag_list, node, nnode, es_frag))
		bgp_evpn_es_frag_free(es_frag);
}

static struct bgp_evpn_es_frag *bgp_evpn_es_frag_new(struct bgp_evpn_es *es)
{
	struct bgp_evpn_es_frag *es_frag;
	char buf[BGP_EVPN_PREFIX_RD_LEN];
	struct bgp *bgp;

	es_frag = XCALLOC(MTYPE_BGP_EVPN_ES_FRAG, sizeof(*es_frag));
	bf_assign_index(bm->rd_idspace, es_frag->rd_id);
	es_frag->prd.family = AF_UNSPEC;
	es_frag->prd.prefixlen = 64;
	bgp = bgp_get_evpn();
	snprintfrr(buf, sizeof(buf), "%pI4:%hu", &bgp->router_id,
		   es_frag->rd_id);
	(void)str2prefix_rd(buf, &es_frag->prd);

	/* EVIs that are advertised using the info in this fragment */
	es_frag->es_evi_frag_list = list_new();
	listset_app_node_mem(es_frag->es_evi_frag_list);

	/* Link the fragment to the parent ES */
	es_frag->es = es;
	listnode_init(&es_frag->es_listnode, es_frag);
	listnode_add(es->es_frag_list, &es_frag->es_listnode);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s frag %u new", es->esi_str, es_frag->rd_id);
	return es_frag;
}

static struct bgp_evpn_es_frag *
bgp_evpn_es_find_frag_with_space(struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct bgp_evpn_es_frag *es_frag;

	for (ALL_LIST_ELEMENTS_RO(es->es_frag_list, node, es_frag)) {
		if (listcount(es_frag->es_evi_frag_list) <
		    bgp_mh_info->evi_per_es_frag)
			return es_frag;
	}

	/* No frags where found with space; allocate a new one */
	return bgp_evpn_es_frag_new(es);
}

/* Link the ES-EVI to one of the ES fragments */
static void bgp_evpn_es_frag_evi_add(struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es_frag *es_frag;
	struct bgp_evpn_es *es = es_evi->es;

	if (es_evi->es_frag ||
	    !(CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL)))
		return;

	es_frag = bgp_evpn_es_find_frag_with_space(es);

	es_evi->es_frag = es_frag;
	listnode_init(&es_evi->es_frag_listnode, es_evi);
	listnode_add(es_frag->es_evi_frag_list, &es_evi->es_frag_listnode);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vni %d linked to frag %u", es->esi_str,
			   es_evi->vpn->vni, es_frag->rd_id);
}

/* UnLink the ES-EVI from the ES fragment */
static void bgp_evpn_es_frag_evi_del(struct bgp_evpn_es_evi *es_evi,
				     bool send_ead_del_if_empty)
{
	struct bgp_evpn_es_frag *es_frag = es_evi->es_frag;
	struct prefix_evpn p;
	struct bgp_evpn_es *es;
	struct bgp *bgp;

	if (!es_frag)
		return;

	es = es_frag->es;
	es_evi->es_frag = NULL;
	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vni %d unlinked from frag %u", es->esi_str,
			   es_evi->vpn->vni, es_frag->rd_id);

	list_delete_node(es_frag->es_evi_frag_list, &es_evi->es_frag_listnode);

	/*
	 * if there are no other EVIs on the fragment deleted the EAD-ES for
	 * the fragment
	 */
	if (send_ead_del_if_empty && !listcount(es_frag->es_evi_frag_list)) {
		bgp = bgp_get_evpn();

		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("es %s frag %u ead-es route delete",
				   es->esi_str, es_frag->rd_id);
		build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG, &es->esi,
					es->originator_ip);
		p.prefix.ead_addr.frag_id = es_frag->rd_id;
		bgp_evpn_mh_route_delete(bgp, es, NULL, es_frag, &p);
	}

	/* We don't attempt to coalesce frags that may not be full. Instead we
	 * only free up the frag when it is completely empty.
	 */
	bgp_evpn_es_frag_free_unused(es_frag);
}

/* Link the ES-EVIs to one of the ES fragments */
static void bgp_evpn_es_frag_evi_update_all(struct bgp_evpn_es *es, bool add)
{
	struct listnode *node;
	struct bgp_evpn_es_evi *es_evi;

	for (ALL_LIST_ELEMENTS_RO(es->es_evi_list, node, es_evi)) {
		if (add)
			bgp_evpn_es_frag_evi_add(es_evi);
		else
			bgp_evpn_es_frag_evi_del(es_evi, false);
	}
}

/* compare ES-IDs for the global ES RB tree */
static int bgp_es_rb_cmp(const struct bgp_evpn_es *es1,
		const struct bgp_evpn_es *es2)
{
	return memcmp(&es1->esi, &es2->esi, ESI_BYTES);
}
RB_GENERATE(bgp_es_rb_head, bgp_evpn_es, rb_node, bgp_es_rb_cmp);

struct bgp_evpn_es *bgp_evpn_es_find(const esi_t *esi)
{
	struct bgp_evpn_es tmp;

	memcpy(&tmp.esi, esi, sizeof(esi_t));
	return RB_FIND(bgp_es_rb_head, &bgp_mh_info->es_rb_tree, &tmp);
}

static struct bgp_evpn_es *bgp_evpn_es_new(struct bgp *bgp, const esi_t *esi)
{
	struct bgp_evpn_es *es;

	es = XCALLOC(MTYPE_BGP_EVPN_ES, sizeof(struct bgp_evpn_es));

	/* set the ESI */
	memcpy(&es->esi, esi, sizeof(esi_t));

	/* Initialise the VTEP list */
	es->es_vtep_list = list_new();
	listset_app_node_mem(es->es_vtep_list);
	es->es_vtep_list->cmp = bgp_evpn_es_vtep_cmp;

	esi_to_str(&es->esi, es->esi_str, sizeof(es->esi_str));

	/* Initialize the ES routing table */
	es->route_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);

	/* Add to rb_tree */
	RB_INSERT(bgp_es_rb_head, &bgp_mh_info->es_rb_tree, es);

	/* Initialise the ES-EVI list */
	es->es_evi_list = list_new();
	listset_app_node_mem(es->es_evi_list);

	/* Initialise the ES-VRF list used for L3NHG management */
	es->es_vrf_list = list_new();
	listset_app_node_mem(es->es_vrf_list);

	/* Initialise the route list used for efficient event handling */
	es->macip_evi_path_list = list_new();
	listset_app_node_mem(es->macip_evi_path_list);
	es->macip_global_path_list = list_new();
	listset_app_node_mem(es->macip_global_path_list);
	es->es_frag_list = list_new();
	listset_app_node_mem(es->es_frag_list);

	QOBJ_REG(es, bgp_evpn_es);

	return es;
}

/* Free a given ES -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static void bgp_evpn_es_free(struct bgp_evpn_es *es, const char *caller)
{
	if ((es->flags & (BGP_EVPNES_LOCAL | BGP_EVPNES_REMOTE))
	    || listcount(es->macip_evi_path_list)
	    || listcount(es->macip_global_path_list))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("%s: es %s free", caller, es->esi_str);

	/* cleanup resources maintained against the ES */
	list_delete(&es->es_evi_list);
	list_delete(&es->es_vrf_list);
	list_delete(&es->es_vtep_list);
	list_delete(&es->macip_evi_path_list);
	list_delete(&es->macip_global_path_list);
	list_delete(&es->es_frag_list);
	bgp_table_unlock(es->route_table);

	/* remove the entry from various databases */
	RB_REMOVE(bgp_es_rb_head, &bgp_mh_info->es_rb_tree, es);
	bgp_evpn_es_cons_checks_pend_del(es);

	QOBJ_UNREG(es);
	XFREE(MTYPE_BGP_EVPN_ES, es);
}

static inline bool bgp_evpn_is_es_local_and_non_bypass(struct bgp_evpn_es *es)
{
	return (es->flags & BGP_EVPNES_LOCAL)
	       && !(es->flags & BGP_EVPNES_BYPASS);
}

/* init local info associated with the ES */
static void bgp_evpn_es_local_info_set(struct bgp *bgp, struct bgp_evpn_es *es)
{
	bool old_is_local;
	bool is_local;

	if (CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
		return;

	old_is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	SET_FLAG(es->flags, BGP_EVPNES_LOCAL);

	listnode_init(&es->es_listnode, es);
	listnode_add(bgp_mh_info->local_es_list, &es->es_listnode);

	/* setup the first ES fragment; more fragments may be allocated based
	 * on the the number of EVI entries
	 */
	es->es_base_frag = bgp_evpn_es_frag_new(es);
	/* distribute ES-EVIs to one or more ES fragments */
	bgp_evpn_es_frag_evi_update_all(es, true);

	is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	if (old_is_local != is_local)
		bgp_evpn_mac_update_on_es_local_chg(es, is_local);
}

/* clear any local info associated with the ES */
static void bgp_evpn_es_local_info_clear(struct bgp_evpn_es *es, bool finish)
{
	bool old_is_local;
	bool is_local;

	if (!CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
		return;

	/* clear the es frag references and free them up */
	bgp_evpn_es_frag_evi_update_all(es, false);
	es->es_base_frag = NULL;
	bgp_evpn_es_frag_free_all(es);

	old_is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	UNSET_FLAG(es->flags, BGP_EVPNES_LOCAL);

	is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	if (!finish && (old_is_local != is_local))
		bgp_evpn_mac_update_on_es_local_chg(es, is_local);

	/* remove from the ES local list */
	list_delete_node(bgp_mh_info->local_es_list, &es->es_listnode);

	bgp_evpn_es_free(es, __func__);
}

/* eval remote info associated with the ES */
static void bgp_evpn_es_remote_info_re_eval(struct bgp_evpn_es *es)
{
	if (es->remote_es_evi_cnt) {
		SET_FLAG(es->flags, BGP_EVPNES_REMOTE);
	} else {
		if (CHECK_FLAG(es->flags, BGP_EVPNES_REMOTE)) {
			UNSET_FLAG(es->flags, BGP_EVPNES_REMOTE);
			bgp_evpn_es_free(es, __func__);
		}
	}
}

/* If ES is present and local it needs to be active/oper-up for
 * including L3 EC
 */
bool bgp_evpn_es_add_l3_ecomm_ok(esi_t *esi)
{
	struct bgp_evpn_es *es;

	if (!esi || !bgp_mh_info->suppress_l3_ecomm_on_inactive_es)
		return true;

	es = bgp_evpn_es_find(esi);

	return (!es || !(es->flags & BGP_EVPNES_LOCAL)
		|| bgp_evpn_local_es_is_active(es));
}

static bool bgp_evpn_is_valid_local_path(struct bgp_path_info *pi)
{
	return (CHECK_FLAG(pi->flags, BGP_PATH_VALID)
		&& pi->type == ZEBRA_ROUTE_BGP
		&& pi->sub_type == BGP_ROUTE_STATIC);
}

/* Update all local MAC-IP routes in the VNI routing table associated
 * with the ES. When the ES is down the routes are advertised without
 * the L3 extcomm
 */
static void bgp_evpn_mac_update_on_es_oper_chg(struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct bgp_path_es_info *es_info;
	struct bgp_path_info *pi;
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (!bgp_mh_info->suppress_l3_ecomm_on_inactive_es)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("update paths linked to es %s on oper chg",
			   es->esi_str);

	bgp = bgp_get_evpn();
	for (ALL_LIST_ELEMENTS_RO(es->macip_evi_path_list, node, es_info)) {
		pi = es_info->pi;

		if (!bgp_evpn_is_valid_local_path(pi))
			continue;

		if (!bgp_evpn_is_macip_path(pi))
			continue;

		vpn = bgp_evpn_lookup_vni(bgp, es_info->vni);
		if (!vpn)
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"update path %d %pFX linked to es %s on oper chg",
				es_info->vni, &pi->net->rn->p, es->esi_str);

		bgp_evpn_update_type2_route_entry(bgp, vpn, pi->net, pi,
						  __func__);
	}
}

static bool bgp_evpn_is_valid_bgp_path(struct bgp_path_info *pi)
{
	return (CHECK_FLAG(pi->flags, BGP_PATH_VALID)
		&& pi->type == ZEBRA_ROUTE_BGP
		&& pi->sub_type == BGP_ROUTE_NORMAL);
}

/* If an ES is no longer local (or becomes local) we need to re-install
 * paths using that ES as destination. This is needed as the criteria
 * for best path selection has changed.
 */
static void bgp_evpn_mac_update_on_es_local_chg(struct bgp_evpn_es *es,
						bool is_local)
{
	struct listnode *node;
	struct bgp_path_es_info *es_info;
	struct bgp_path_info *pi;
	bool tmp_local;
	struct attr *attr_new;
	struct attr attr_tmp;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("update paths linked to es %s on chg to %s",
			   es->esi_str, is_local ? "local" : "non-local");

	for (ALL_LIST_ELEMENTS_RO(es->macip_global_path_list, node, es_info)) {
		pi = es_info->pi;

		/* Consider "valid" remote routes */
		if (!bgp_evpn_is_valid_bgp_path(pi))
			continue;

		if (!pi->attr)
			continue;

		tmp_local = !!(pi->attr->es_flags & ATTR_ES_IS_LOCAL);
		if (tmp_local == is_local)
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"update path %pFX linked to es %s on chg to %s",
				&pi->net->rn->p, es->esi_str,
				is_local ? "local" : "non-local");

		attr_tmp = *pi->attr;
		if (is_local)
			attr_tmp.es_flags |= ATTR_ES_IS_LOCAL;
		else
			attr_tmp.es_flags &= ~ATTR_ES_IS_LOCAL;
		attr_new = bgp_attr_intern(&attr_tmp);
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		bgp_evpn_import_type2_route(pi, 1);
	}
}

static void bgp_evpn_local_es_deactivate(struct bgp *bgp,
					 struct bgp_evpn_es *es)
{
	struct prefix_evpn p;
	int ret;

	/* withdraw ESR */
	/* Delete and withdraw locally learnt ES route */
	build_evpn_type4_prefix(&p, &es->esi, es->originator_ip);
	ret = bgp_evpn_type4_route_delete(bgp, es, &p);
	if (ret) {
		flog_err(EC_BGP_EVPN_ROUTE_DELETE,
				"%u failed to delete type-4 route for ESI %s",
				bgp->vrf_id, es->esi_str);
	}

	/* withdraw EAD-EVI */
	if (!bgp_mh_info->ead_evi_adv_for_down_links)
		bgp_evpn_local_type1_evi_route_del(bgp, es);

	/* withdraw EAD-ES */
	bgp_evpn_ead_es_route_delete(bgp, es);

	bgp_evpn_mac_update_on_es_oper_chg(es);
}

/* Process ES link oper-down by withdrawing ES-EAD and ESR */
static void bgp_evpn_local_es_down(struct bgp *bgp, struct bgp_evpn_es *es)
{
	bool old_active;

	if (!CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP))
		return;

	old_active = bgp_evpn_local_es_is_active(es);
	UNSET_FLAG(es->flags, BGP_EVPNES_OPER_UP);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("local es %s down", es->esi_str);

	if (old_active)
		bgp_evpn_local_es_deactivate(bgp, es);
}

static void bgp_evpn_local_es_activate(struct bgp *bgp, struct bgp_evpn_es *es,
				       bool regen_ead, bool regen_esr)
{
	struct prefix_evpn p;

	if (regen_esr) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("local es %s generate ESR", es->esi_str);
		/* generate ESR */
		build_evpn_type4_prefix(&p, &es->esi, es->originator_ip);
		if (bgp_evpn_type4_route_update(bgp, es, &p))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				 "%u: Type4 route creation failure for ESI %s",
				 bgp->vrf_id, es->esi_str);
	}

	if (regen_ead) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("local es %s generate EAD", es->esi_str);
		/* generate EAD-EVI */
		bgp_evpn_local_type1_evi_route_add(bgp, es);

		/* generate EAD-ES */
		bgp_evpn_ead_es_route_update(bgp, es);
	}

	bgp_evpn_mac_update_on_es_oper_chg(es);
}

/* Process ES link oper-up by generating ES-EAD and ESR */
static void bgp_evpn_local_es_up(struct bgp *bgp, struct bgp_evpn_es *es,
				 bool regen_esr)
{
	bool regen_ead = false;
	bool active = false;

	if (!CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP)) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("local es %s up", es->esi_str);

		SET_FLAG(es->flags, BGP_EVPNES_OPER_UP);
		regen_esr = true;
		regen_ead = true;
	}

	active = bgp_evpn_local_es_is_active(es);
	if (active && (regen_ead || regen_esr))
		bgp_evpn_local_es_activate(bgp, es, regen_ead, regen_esr);
}

/* If an ethernet segment is in LACP bypass we cannot advertise
 * reachability to it i.e. EAD-per-ES and ESR is not advertised in
 * bypass state.
 * PS: EAD-per-EVI will continue to be advertised
 */
static void bgp_evpn_local_es_bypass_update(struct bgp *bgp,
					    struct bgp_evpn_es *es, bool bypass)
{
	bool old_bypass = !!(es->flags & BGP_EVPNES_BYPASS);
	bool old_active;
	bool new_active;
	bool old_is_local;
	bool is_local;

	if (bypass == old_bypass)
		return;

	old_active = bgp_evpn_local_es_is_active(es);
	old_is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	if (bypass)
		SET_FLAG(es->flags, BGP_EVPNES_BYPASS);
	else
		UNSET_FLAG(es->flags, BGP_EVPNES_BYPASS);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("local es %s bypass %s", es->esi_str,
			   bypass ? "set" : "clear");

	new_active = bgp_evpn_local_es_is_active(es);
	if (old_active != new_active) {
		if (new_active)
			bgp_evpn_local_es_activate(bgp, es, true, true);
		else
			bgp_evpn_local_es_deactivate(bgp, es);
	}

	is_local = bgp_evpn_is_es_local_and_non_bypass(es);
	if (old_is_local != is_local)
		bgp_evpn_mac_update_on_es_local_chg(es, is_local);
}

static void bgp_evpn_local_es_do_del(struct bgp *bgp, struct bgp_evpn_es *es)
{
	struct bgp_evpn_es_evi *es_evi;
	struct listnode *evi_node, *evi_next_node;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("del local es %s", es->esi_str);

	/* Delete all local EVPN ES routes from ESI table
	 * and schedule for processing (to withdraw from peers))
	 */
	bgp_evpn_es_route_del_all(bgp, es);

	/* release all local ES EVIs associated with the ES */
	for (ALL_LIST_ELEMENTS(es->es_evi_list, evi_node,
				evi_next_node, es_evi)) {
		bgp_evpn_local_es_evi_do_del(es_evi);
	}

	/* Clear local info associated with the ES and free it up if there is
	 * no remote reference
	 */
	bgp_evpn_es_local_info_clear(es, false);
}

bool bgp_evpn_is_esi_local_and_non_bypass(esi_t *esi)
{
	struct bgp_evpn_es *es = NULL;

	/* Lookup ESI hash - should exist. */
	es = bgp_evpn_es_find(esi);

	return es && bgp_evpn_is_es_local_and_non_bypass(es);
}

int bgp_evpn_local_es_del(struct bgp *bgp, esi_t *esi)
{
	struct bgp_evpn_es *es = NULL;

	/* Lookup ESI hash - should exist. */
	es = bgp_evpn_es_find(esi);
	if (!es) {
		flog_warn(EC_BGP_EVPN_ESI, "%u: ES missing at local ES DEL",
			  bgp->vrf_id);
		return -1;
	}

	bgp_evpn_local_es_do_del(bgp, es);
	return 0;
}

/* Handle device to ES id association. Results in the creation of a local
 * ES.
 */
int bgp_evpn_local_es_add(struct bgp *bgp, esi_t *esi,
			  struct in_addr originator_ip, bool oper_up,
			  uint16_t df_pref, bool bypass)
{
	struct bgp_evpn_es *es;
	bool new_es = true;
	bool regen_esr = false;

	/* create the new es */
	es = bgp_evpn_es_find(esi);
	if (es) {
		if (CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
			new_es = false;
	} else
		es = bgp_evpn_es_new(bgp, esi);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("add local es %s orig-ip %pI4 df_pref %u %s",
			   es->esi_str, &originator_ip, df_pref,
			   bypass ? "bypass" : "");

	es->originator_ip = originator_ip;
	if (df_pref != es->df_pref) {
		es->df_pref = df_pref;
		regen_esr = true;
	}
	bgp_evpn_es_local_info_set(bgp, es);

	/* import all remote Type-4 routes in the ES table */
	if (new_es)
		bgp_evpn_type4_remote_routes_import(bgp, es,
				true /* install */);

	/* create and advertise EAD-EVI routes for the ES -
	 * XXX - till an ES-EVI reference is created there is really nothing to
	 * advertise
	 */
	if (bgp_mh_info->ead_evi_adv_for_down_links)
		bgp_evpn_local_type1_evi_route_add(bgp, es);

	bgp_evpn_local_es_bypass_update(bgp, es, bypass);

	/* If the ES link is operationally up generate EAD-ES. EAD-EVI
	 * can be generated even if the link is inactive.
	 */
	if (oper_up)
		bgp_evpn_local_es_up(bgp, es, regen_esr);
	else
		bgp_evpn_local_es_down(bgp, es);

	return 0;
}

static void bgp_evpn_es_json_frag_fill(json_object *json_frags,
				       struct bgp_evpn_es *es)
{
	json_object *json_frag;
	struct listnode *node;
	struct bgp_evpn_es_frag *es_frag;

	for (ALL_LIST_ELEMENTS_RO(es->es_frag_list, node, es_frag)) {
		json_frag = json_object_new_object();

		json_object_string_addf(json_frag, "rd", "%pRDP",
					&es_frag->prd);
		json_object_int_add(json_frag, "eviCount",
				    listcount(es_frag->es_evi_frag_list));

		json_object_array_add(json_frags, json_frag);
	}
}

static void bgp_evpn_es_frag_show_detail(struct vty *vty,
					 struct bgp_evpn_es *es)
{
	struct listnode *node;
	struct bgp_evpn_es_frag *es_frag;

	for (ALL_LIST_ELEMENTS_RO(es->es_frag_list, node, es_frag)) {
		vty_out(vty, "  %pRDP EVIs: %d\n", &es_frag->prd,
			listcount(es_frag->es_evi_frag_list));
	}
}

static char *bgp_evpn_es_vteps_str(char *vtep_str, struct bgp_evpn_es *es,
				   uint8_t vtep_str_size)
{
	char vtep_flag_str[BGP_EVPN_FLAG_STR_SZ];
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;
	bool first = true;
	char ip_buf[INET_ADDRSTRLEN];

	vtep_str[0] = '\0';
	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		vtep_flag_str[0] = '\0';

		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
			strlcat(vtep_flag_str, "E", sizeof(vtep_flag_str));
		if (es_vtep->flags & BGP_EVPNES_VTEP_ACTIVE)
			strlcat(vtep_flag_str, "A", sizeof(vtep_flag_str));

		if (!strlen(vtep_flag_str))
			strlcat(vtep_flag_str, "-", sizeof(vtep_flag_str));
		if (first)
			first = false;
		else
			strlcat(vtep_str, ",", vtep_str_size);
		strlcat(vtep_str,
			inet_ntop(AF_INET, &es_vtep->vtep_ip, ip_buf,
				  sizeof(ip_buf)),
			vtep_str_size);
		strlcat(vtep_str, "(", vtep_str_size);
		strlcat(vtep_str, vtep_flag_str, vtep_str_size);
		strlcat(vtep_str, ")", vtep_str_size);
	}

	return vtep_str;
}

static void bgp_evpn_es_json_vtep_fill(json_object *json_vteps,
		struct bgp_evpn_es_vtep *es_vtep)
{
	json_object *json_vtep_entry;
	json_object *json_flags;
	char alg_buf[EVPN_DF_ALG_STR_LEN];

	json_vtep_entry = json_object_new_object();

	json_object_string_addf(json_vtep_entry, "vtep_ip", "%pI4",
				&es_vtep->vtep_ip);
	if (es_vtep->flags & (BGP_EVPNES_VTEP_ESR |
			 BGP_EVPNES_VTEP_ACTIVE)) {
		json_flags = json_object_new_array();
		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
			json_array_string_add(json_flags, "esr");
		if (es_vtep->flags & BGP_EVPNES_VTEP_ACTIVE)
			json_array_string_add(json_flags, "active");
		json_object_object_add(json_vtep_entry, "flags", json_flags);
		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR) {
			json_object_int_add(json_vtep_entry, "dfPreference",
					    es_vtep->df_pref);
			json_object_string_add(
				json_vtep_entry, "dfAlgorithm",
				evpn_es_df_alg2str(es_vtep->df_alg, alg_buf,
						   sizeof(alg_buf)));
		}
	}

	json_object_array_add(json_vteps,
			json_vtep_entry);
}

static void bgp_evpn_es_vteps_show_detail(struct vty *vty,
					  struct bgp_evpn_es *es)
{
	char vtep_flag_str[BGP_EVPN_FLAG_STR_SZ];
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;
	char alg_buf[EVPN_DF_ALG_STR_LEN];

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		vtep_flag_str[0] = '\0';
		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
			strlcat(vtep_flag_str, "E", sizeof(vtep_flag_str));
		if (es_vtep->flags & BGP_EVPNES_VTEP_ACTIVE)
			strlcat(vtep_flag_str, "A", sizeof(vtep_flag_str));

		if (!strlen(vtep_flag_str))
			strlcat(vtep_flag_str, "-", sizeof(vtep_flag_str));

		vty_out(vty, "  %pI4 flags: %s", &es_vtep->vtep_ip,
			vtep_flag_str);

		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
			vty_out(vty, " df_alg: %s df_pref: %u\n",
				evpn_es_df_alg2str(es_vtep->df_alg, alg_buf,
						   sizeof(alg_buf)),
				es_vtep->df_pref);
		else
			vty_out(vty, "\n");
	}
}

static void bgp_evpn_es_show_entry(struct vty *vty,
		struct bgp_evpn_es *es, json_object *json)
{
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;

	if (json) {
		json_object *json_vteps;
		json_object *json_types;

		json_object_string_add(json, "esi", es->esi_str);
		if (es->es_base_frag)
			json_object_string_addf(json, "rd", "%pRDP",
						&es->es_base_frag->prd);

		if (es->flags & (BGP_EVPNES_LOCAL | BGP_EVPNES_REMOTE)) {
			json_types = json_object_new_array();
			if (es->flags & BGP_EVPNES_LOCAL)
				json_array_string_add(json_types, "local");
			if (es->flags & BGP_EVPNES_REMOTE)
				json_array_string_add(json_types, "remote");
			json_object_object_add(json, "type", json_types);
		}

		if (listcount(es->es_vtep_list)) {
			json_vteps = json_object_new_array();
			for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list,
						node, es_vtep)) {
				bgp_evpn_es_json_vtep_fill(json_vteps, es_vtep);
			}
			json_object_object_add(json, "vteps", json_vteps);
		}
		json_object_int_add(json, "vniCount",
				listcount(es->es_evi_list));
	} else {
		char type_str[4];
		char vtep_str[ES_VTEP_LIST_STR_SZ + BGP_EVPN_VTEPS_FLAG_STR_SZ];

		type_str[0] = '\0';
		if (es->flags & BGP_EVPNES_BYPASS)
			strlcat(type_str, "B", sizeof(type_str));
		if (es->flags & BGP_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & BGP_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));
		if (es->inconsistencies)
			strlcat(type_str, "I", sizeof(type_str));

		bgp_evpn_es_vteps_str(vtep_str, es, sizeof(vtep_str));

		vty_out(vty, "%-30s %-5s %-21pRDP %-8d %s\n", es->esi_str,
			type_str,
			es->es_base_frag ? &es->es_base_frag->prd : NULL,
			listcount(es->es_evi_list), vtep_str);
	}
}

static void bgp_evpn_es_show_entry_detail(struct vty *vty,
		struct bgp_evpn_es *es, json_object *json)
{
	if (json) {
		json_object *json_flags;
		json_object *json_incons;
		json_object *json_vteps;
		json_object *json_frags;
		struct listnode *node;
		struct bgp_evpn_es_vtep *es_vtep;

		/* Add the "brief" info first */
		bgp_evpn_es_show_entry(vty, es, json);
		if (es->flags
		    & (BGP_EVPNES_OPER_UP | BGP_EVPNES_ADV_EVI
		       | BGP_EVPNES_BYPASS)) {
			json_flags = json_object_new_array();
			if (es->flags & BGP_EVPNES_OPER_UP)
				json_array_string_add(json_flags, "up");
			if (es->flags & BGP_EVPNES_ADV_EVI)
				json_array_string_add(json_flags,
						"advertiseEVI");
			if (es->flags & BGP_EVPNES_BYPASS)
				json_array_string_add(json_flags, "bypass");
			json_object_object_add(json, "flags", json_flags);
		}
		json_object_string_addf(json, "originator_ip", "%pI4",
					&es->originator_ip);
		json_object_int_add(json, "remoteVniCount",
				es->remote_es_evi_cnt);
		json_object_int_add(json, "vrfCount",
				    listcount(es->es_vrf_list));
		json_object_int_add(json, "macipPathCount",
				    listcount(es->macip_evi_path_list));
		json_object_int_add(json, "macipGlobalPathCount",
				    listcount(es->macip_global_path_list));
		json_object_int_add(json, "inconsistentVniVtepCount",
				es->incons_evi_vtep_cnt);
		if (es->flags & BGP_EVPNES_LOCAL)
			json_object_int_add(json, "localEsDfPreference",
					    es->df_pref);
		if (listcount(es->es_vtep_list)) {
			json_vteps = json_object_new_array();
			for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node,
						  es_vtep)) {
				bgp_evpn_es_json_vtep_fill(json_vteps, es_vtep);
			}
			json_object_object_add(json, "vteps", json_vteps);
		}
		if (listcount(es->es_frag_list)) {
			json_frags = json_object_new_array();
			bgp_evpn_es_json_frag_fill(json_frags, es);
			json_object_object_add(json, "fragments", json_frags);
		}
		if (es->inconsistencies) {
			json_incons = json_object_new_array();
			if (es->inconsistencies & BGP_EVPNES_INCONS_VTEP_LIST)
				json_array_string_add(json_incons,
						"vni-vtep-mismatch");
			json_object_object_add(json, "inconsistencies",
					json_incons);
		}
	} else {
		char incons_str[BGP_EVPNES_INCONS_STR_SZ];
		char type_str[4];

		type_str[0] = '\0';
		if (es->flags & BGP_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & BGP_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));

		vty_out(vty, "ESI: %s\n", es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " RD: %pRDP\n",
			es->es_base_frag ? &es->es_base_frag->prd : NULL);
		vty_out(vty, " Originator-IP: %pI4\n", &es->originator_ip);
		if (es->flags & BGP_EVPNES_LOCAL)
			vty_out(vty, " Local ES DF preference: %u\n",
				es->df_pref);
		if (es->flags & BGP_EVPNES_BYPASS)
			vty_out(vty, " LACP bypass: on\n");
		vty_out(vty, " VNI Count: %d\n", listcount(es->es_evi_list));
		vty_out(vty, " Remote VNI Count: %d\n",
				es->remote_es_evi_cnt);
		vty_out(vty, " VRF Count: %d\n", listcount(es->es_vrf_list));
		vty_out(vty, " MACIP EVI Path Count: %d\n",
			listcount(es->macip_evi_path_list));
		vty_out(vty, " MACIP Global Path Count: %d\n",
			listcount(es->macip_global_path_list));
		vty_out(vty, " Inconsistent VNI VTEP Count: %d\n",
				es->incons_evi_vtep_cnt);
		if (es->inconsistencies) {
			incons_str[0] = '\0';
			if (es->inconsistencies & BGP_EVPNES_INCONS_VTEP_LIST)
				strlcat(incons_str, "vni-vtep-mismatch",
					sizeof(incons_str));
		} else {
			strlcpy(incons_str, "-", sizeof(incons_str));
		}
		vty_out(vty, " Inconsistencies: %s\n",
				incons_str);
		if (listcount(es->es_frag_list)) {
			vty_out(vty, " Fragments:\n");
			bgp_evpn_es_frag_show_detail(vty, es);
		}
		if (listcount(es->es_vtep_list)) {
			vty_out(vty, " VTEPs:\n");
			bgp_evpn_es_vteps_show_detail(vty, es);
		}
		vty_out(vty, "\n");
	}
}

/* Display all ESs */
void bgp_evpn_es_show(struct vty *vty, bool uj, bool detail)
{
	struct bgp_evpn_es *es;
	json_object *json_array = NULL;
	json_object *json = NULL;

	if (uj) {
		/* create an array of ESs */
		json_array = json_object_new_array();
	} else {
		if (!detail) {
			vty_out(vty,
				"ES Flags: B - bypass, L local, R remote, I inconsistent\n");
			vty_out(vty,
				"VTEP Flags: E ESR/Type-4, A active nexthop\n");
			vty_out(vty,
				"%-30s %-5s %-21s %-8s %s\n",
				"ESI", "Flags", "RD", "#VNIs", "VTEPs");
		}
	}

	RB_FOREACH(es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree) {
		if (uj)
			/* create a separate json object for each ES */
			json = json_object_new_object();
		if (detail)
			bgp_evpn_es_show_entry_detail(vty, es, json);
		else
			bgp_evpn_es_show_entry(vty, es, json);
		/* add ES to the json array */
		if (uj)
			json_object_array_add(json_array, json);
	}

	/* print the array of json-ESs */
	if (uj)
		vty_json(vty, json_array);
}

/* Display specific ES */
void bgp_evpn_es_show_esi(struct vty *vty, esi_t *esi, bool uj)
{
	struct bgp_evpn_es *es;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	es = bgp_evpn_es_find(esi);
	if (es) {
		bgp_evpn_es_show_entry_detail(vty, es, json);
	} else {
		if (!uj)
			vty_out(vty, "ESI not found\n");
	}

	if (uj)
		vty_json(vty, json);
}

/*****************************************************************************/
/* Ethernet Segment to VRF association -
 * 1. Each ES-EVI entry is associated with a tenant VRF. This associaton
 * triggers the creation of an ES-VRF entry.
 * 2. The ES-VRF entry is maintained for the purpose of L3-NHG creation
 * 3. Type-2/MAC-IP routes are imported into a tenant VRF and programmed as
 * a /32 or host route entry in the dataplane. If the destination of
 * the host route is a remote-ES the route is programmed with the
 * corresponding (keyed in by {vrf,ES-id}) L3-NHG.
 * 4. The reason for this indirection (route->L3-NHG, L3-NHG->list-of-VTEPs)
 * is to avoid route updates to the dplane when a remote-ES link flaps i.e.
 * instead of updating all the dependent routes the NHG's contents are updated.
 * This reduces the amount of datplane updates (nhg updates vs. route updates)
 * allowing for a faster failover.
 *
 * XXX - can the L3 SVI index change without change in vpn->bgp_vrf
 * association? If yes we need to handle that by updating all the L3 NHGs
 * in that VRF.
 */
/******************************** L3 NHG management *************************/
static void bgp_evpn_l3nhg_zebra_add_v4_or_v6(struct bgp_evpn_es_vrf *es_vrf,
					      bool v4_nhg)
{
	uint32_t nhg_id = v4_nhg ? es_vrf->nhg_id : es_vrf->v6_nhg_id;
	struct bgp_evpn_es *es = es_vrf->es;
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;
	struct nexthop nh;
	struct zapi_nexthop *api_nh;
	struct zapi_nhg api_nhg = {};

	/* Skip installation of L3-NHG if host routes used */
	if (!nhg_id)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vrf %u %s nhg %u to zebra", es->esi_str,
			   es_vrf->bgp_vrf->vrf_id,
			   v4_nhg ? "v4_nhg" : "v6_nhg", nhg_id);

	frrtrace(4, frr_bgp, evpn_mh_nhg_zsend, true, v4_nhg, nhg_id, es_vrf);

	/* only the gateway ip changes for each NH. rest of the params
	 * are constant
	 */
	memset(&nh, 0, sizeof(nh));
	nh.vrf_id = es_vrf->bgp_vrf->vrf_id;
	nh.flags = NEXTHOP_FLAG_ONLINK;
	nh.ifindex = es_vrf->bgp_vrf->l3vni_svi_ifindex;
	nh.weight = 1;
	nh.type =
		v4_nhg ? NEXTHOP_TYPE_IPV4_IFINDEX : NEXTHOP_TYPE_IPV6_IFINDEX;

	api_nhg.id = nhg_id;
	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (!CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE))
			continue;

		/* Don't overrun the zapi buffer. */
		if (api_nhg.nexthop_num == MULTIPATH_NUM)
			break;

		/* overwrite the gw */
		if (v4_nhg)
			nh.gate.ipv4 = es_vtep->vtep_ip;
		else
			ipv4_to_ipv4_mapped_ipv6(&nh.gate.ipv6,
						 es_vtep->vtep_ip);

		/* convert to zapi format */
		api_nh = &api_nhg.nexthops[api_nhg.nexthop_num];
		zapi_nexthop_from_nexthop(api_nh, &nh);

		++api_nhg.nexthop_num;
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("nhg %u vtep %pI4 l3-svi %d", api_nhg.id,
				   &es_vtep->vtep_ip,
				   es_vrf->bgp_vrf->l3vni_svi_ifindex);

		frrtrace(3, frr_bgp, evpn_mh_nh_zsend, nhg_id, es_vtep, es_vrf);
	}

	if (!api_nhg.nexthop_num)
		return;

	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

static bool bgp_evpn_l3nhg_zebra_ok(struct bgp_evpn_es_vrf *es_vrf)
{
	if (!bgp_mh_info->host_routes_use_l3nhg)
		return false;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return false;

	return true;
}

static void bgp_evpn_l3nhg_zebra_add(struct bgp_evpn_es_vrf *es_vrf)
{
	if (!bgp_evpn_l3nhg_zebra_ok(es_vrf))
		return;

	bgp_evpn_l3nhg_zebra_add_v4_or_v6(es_vrf, true /*v4_nhg*/);
	bgp_evpn_l3nhg_zebra_add_v4_or_v6(es_vrf, false /*v4_nhg*/);
}

static void bgp_evpn_l3nhg_zebra_del_v4_or_v6(struct bgp_evpn_es_vrf *es_vrf,
					      bool v4_nhg)
{
	struct zapi_nhg api_nhg = {};

	api_nhg.id = v4_nhg ? es_vrf->nhg_id : es_vrf->v6_nhg_id;

	/* Skip installation of L3-NHG if host routes used */
	if (!api_nhg.id)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vrf %u %s nhg %u to zebra",
			   es_vrf->es->esi_str, es_vrf->bgp_vrf->vrf_id,
			   v4_nhg ? "v4_nhg" : "v6_nhg", api_nhg.id);


	frrtrace(4, frr_bgp, evpn_mh_nhg_zsend, false, v4_nhg, api_nhg.id,
		 es_vrf);

	zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
}

static void bgp_evpn_l3nhg_zebra_del(struct bgp_evpn_es_vrf *es_vrf)
{
	if (!bgp_evpn_l3nhg_zebra_ok(es_vrf))
		return;

	bgp_evpn_l3nhg_zebra_del_v4_or_v6(es_vrf, true /*v4_nhg*/);
	bgp_evpn_l3nhg_zebra_del_v4_or_v6(es_vrf, false /*v4_nhg*/);
}

static void bgp_evpn_l3nhg_deactivate(struct bgp_evpn_es_vrf *es_vrf)
{
	if (!(es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vrf %u nhg %u de-activate",
			   es_vrf->es->esi_str, es_vrf->bgp_vrf->vrf_id,
			   es_vrf->nhg_id);
	bgp_evpn_l3nhg_zebra_del(es_vrf);
	es_vrf->flags &= ~BGP_EVPNES_VRF_NHG_ACTIVE;
	/* MAC-IPs can now be installed via the L3NHG */
	bgp_evpn_es_path_update_on_es_vrf_chg(es_vrf, "l3nhg-deactivate");
}

static void bgp_evpn_l3nhg_activate(struct bgp_evpn_es_vrf *es_vrf, bool update)
{
	if (!bgp_evpn_es_get_active_vtep_cnt(es_vrf->es)) {
		bgp_evpn_l3nhg_deactivate(es_vrf);
		return;
	}

	if (es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE) {
		if (!update)
			return;
	} else {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("es %s vrf %u nhg %u activate",
				   es_vrf->es->esi_str, es_vrf->bgp_vrf->vrf_id,
				   es_vrf->nhg_id);
		es_vrf->flags |= BGP_EVPNES_VRF_NHG_ACTIVE;
		/* MAC-IPs can now be installed via the L3NHG */
		bgp_evpn_es_path_update_on_es_vrf_chg(es_vrf, "l3nhg_activate");
	}

	bgp_evpn_l3nhg_zebra_add(es_vrf);
}

/* when a VTEP is activated or de-activated against an ES associated
 * VRFs' NHG needs to be updated
 */
static void bgp_evpn_l3nhg_update_on_vtep_chg(struct bgp_evpn_es *es)
{
	struct bgp_evpn_es_vrf *es_vrf;
	struct listnode *es_vrf_node;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s nhg update on vtep chg", es->esi_str);

	for (ALL_LIST_ELEMENTS_RO(es->es_vrf_list, es_vrf_node, es_vrf))
		bgp_evpn_l3nhg_activate(es_vrf, true /* update */);
}

/* compare ES-IDs for the ES-VRF RB tree maintained per-VRF */
static int bgp_es_vrf_rb_cmp(const struct bgp_evpn_es_vrf *es_vrf1,
			     const struct bgp_evpn_es_vrf *es_vrf2)
{
	return memcmp(&es_vrf1->es->esi, &es_vrf2->es->esi, ESI_BYTES);
}
RB_GENERATE(bgp_es_vrf_rb_head, bgp_evpn_es_vrf, rb_node, bgp_es_vrf_rb_cmp);

/* Initialize the ES tables maintained per-tenant vrf */
void bgp_evpn_vrf_es_init(struct bgp *bgp_vrf)
{
	/* Initialize the ES-VRF RB tree */
	RB_INIT(bgp_es_vrf_rb_head, &bgp_vrf->es_vrf_rb_tree);
}

/* find the ES-VRF in the per-VRF RB tree */
static struct bgp_evpn_es_vrf *bgp_evpn_es_vrf_find(struct bgp_evpn_es *es,
						    struct bgp *bgp_vrf)
{
	struct bgp_evpn_es_vrf es_vrf;

	es_vrf.es = es;

	return RB_FIND(bgp_es_vrf_rb_head, &bgp_vrf->es_vrf_rb_tree, &es_vrf);
}

/* allocate a new ES-VRF and setup L3NHG for it */
static struct bgp_evpn_es_vrf *bgp_evpn_es_vrf_create(struct bgp_evpn_es *es,
						      struct bgp *bgp_vrf)
{
	struct bgp_evpn_es_vrf *es_vrf;

	es_vrf = XCALLOC(MTYPE_BGP_EVPN_ES_VRF, sizeof(*es_vrf));

	es_vrf->es = es;
	es_vrf->bgp_vrf = bgp_vrf;

	/* insert into the VRF-ESI rb tree */
	RB_INSERT(bgp_es_vrf_rb_head, &bgp_vrf->es_vrf_rb_tree, es_vrf);

	/* add to the ES's VRF list */
	listnode_init(&es_vrf->es_listnode, es_vrf);
	listnode_add(es->es_vrf_list, &es_vrf->es_listnode);

	/* setup the L3 NHG id for the ES */
	es_vrf->nhg_id = bgp_l3nhg_id_alloc();
	es_vrf->v6_nhg_id = bgp_l3nhg_id_alloc();

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vrf %u nhg %u v6_nhg %d create", es->esi_str,
			   bgp_vrf->vrf_id, es_vrf->nhg_id, es_vrf->v6_nhg_id);
	bgp_evpn_l3nhg_activate(es_vrf, false /* update */);

	/* update paths in the VRF that may already be associated with
	 * this destination ES
	 */
	bgp_evpn_es_path_update_on_es_vrf_chg(es_vrf, "es-vrf-create");

	return es_vrf;
}

/* remove the L3-NHG associated with the ES-VRF and free it */
static void bgp_evpn_es_vrf_delete(struct bgp_evpn_es_vrf *es_vrf)
{
	struct bgp_evpn_es *es = es_vrf->es;
	struct bgp *bgp_vrf = es_vrf->bgp_vrf;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vrf %u nhg %u delete", es->esi_str,
			   bgp_vrf->vrf_id, es_vrf->nhg_id);

	/* Remove the NHG resources */
	bgp_evpn_l3nhg_deactivate(es_vrf);
	if (es_vrf->nhg_id)
		bgp_l3nhg_id_free(es_vrf->nhg_id);
	es_vrf->nhg_id = 0;
	if (es_vrf->v6_nhg_id)
		bgp_l3nhg_id_free(es_vrf->v6_nhg_id);
	es_vrf->v6_nhg_id = 0;

	/* remove from the ES's VRF list */
	list_delete_node(es->es_vrf_list, &es_vrf->es_listnode);

	/* remove from the VRF-ESI rb tree */
	RB_REMOVE(bgp_es_vrf_rb_head, &bgp_vrf->es_vrf_rb_tree, es_vrf);

	/* update paths in the VRF that may already be associated with
	 * this destination ES
	 */
	bgp_evpn_es_path_update_on_es_vrf_chg(es_vrf, "es-vrf-delete");

	XFREE(MTYPE_BGP_EVPN_ES_VRF, es_vrf);
}

/* deref and delete if there are no references */
void bgp_evpn_es_vrf_deref(struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es_vrf *es_vrf = es_evi->es_vrf;

	if (!es_vrf)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es-evi %s vni %u vrf %u de-ref",
			   es_evi->es->esi_str, es_evi->vpn->vni,
			   es_vrf->bgp_vrf->vrf_id);

	es_evi->es_vrf = NULL;
	if (es_vrf->ref_cnt)
		--es_vrf->ref_cnt;

	if (!es_vrf->ref_cnt)
		bgp_evpn_es_vrf_delete(es_vrf);
}

/* find or create and reference */
void bgp_evpn_es_vrf_ref(struct bgp_evpn_es_evi *es_evi, struct bgp *bgp_vrf)
{
	struct bgp_evpn_es *es = es_evi->es;
	struct bgp_evpn_es_vrf *es_vrf = es_evi->es_vrf;
	struct bgp *old_bgp_vrf = NULL;

	if (es_vrf)
		old_bgp_vrf = es_vrf->bgp_vrf;

	if (old_bgp_vrf == bgp_vrf)
		return;

	/* deref the old ES-VRF */
	bgp_evpn_es_vrf_deref(es_evi);

	if (!bgp_vrf)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es-evi %s vni %u vrf %u ref", es_evi->es->esi_str,
			   es_evi->vpn->vni, bgp_vrf->vrf_id);

	/* find-create the new ES-VRF */
	es_vrf = bgp_evpn_es_vrf_find(es, bgp_vrf);
	if (!es_vrf)
		es_vrf = bgp_evpn_es_vrf_create(es, bgp_vrf);

	es_evi->es_vrf = es_vrf;
	++es_vrf->ref_cnt;
}

/* When the L2-VNI is associated with a L3-VNI/VRF update all the
 * associated ES-EVI entries
 */
void bgp_evpn_es_evi_vrf_deref(struct bgpevpn *vpn)
{
	struct bgp_evpn_es_evi *es_evi;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es-vrf de-ref for vni %u", vpn->vni);

	RB_FOREACH (es_evi, bgp_es_evi_rb_head, &vpn->es_evi_rb_tree)
		bgp_evpn_es_vrf_deref(es_evi);
}
void bgp_evpn_es_evi_vrf_ref(struct bgpevpn *vpn)
{
	struct bgp_evpn_es_evi *es_evi;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es-vrf ref for vni %u", vpn->vni);

	RB_FOREACH (es_evi, bgp_es_evi_rb_head, &vpn->es_evi_rb_tree)
		bgp_evpn_es_vrf_ref(es_evi, vpn->bgp_vrf);
}

/* 1. If ES-VRF is not present install the host route with the exploded/flat
 * multi-path list.
 * 2. If ES-VRF is present -
 * - if L3NHG has not been activated for the ES-VRF (this could be because
 *   all the PEs attached to the VRF are down) do not install the route
 *   in zebra.
 * - if L3NHG has been activated install the route via that L3NHG
 */
void bgp_evpn_es_vrf_use_nhg(struct bgp *bgp_vrf, esi_t *esi, bool *use_l3nhg,
			     bool *is_l3nhg_active,
			     struct bgp_evpn_es_vrf **es_vrf_p)
{
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_vrf *es_vrf;

	if (!bgp_mh_info->host_routes_use_l3nhg)
		return;

	es = bgp_evpn_es_find(esi);
	if (!es)
		return;

	es_vrf = bgp_evpn_es_vrf_find(es, bgp_vrf);
	if (!es_vrf)
		return;

	*use_l3nhg = true;
	if (es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE)
		*is_l3nhg_active = true;
	if (es_vrf_p)
		*es_vrf_p = es_vrf;
}

/* returns false if legacy-exploded mp needs to be used for route install */
bool bgp_evpn_path_es_use_nhg(struct bgp *bgp_vrf, struct bgp_path_info *pi,
			      uint32_t *nhg_p)
{
	esi_t *esi;
	struct bgp_evpn_es_vrf *es_vrf = NULL;
	struct bgp_path_info *parent_pi;
	struct bgp_dest *bd;
	struct prefix_evpn *evp;
	struct bgp_path_info *mpinfo;
	bool use_l3nhg = false;
	bool is_l3nhg_active = false;

	*nhg_p = 0;

	/* we don't support NHG for routes leaked from another VRF yet */
	if (pi->extra && pi->extra->vrfleak && pi->extra->vrfleak->bgp_orig)
		return false;

	parent_pi = get_route_parent_evpn(pi);
	if (!parent_pi)
		return false;

	bd = parent_pi->net;
	if (!bd)
		return false;

	evp = (struct prefix_evpn *)&bd->rn->p;
	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return false;

	/* non-es path, use legacy-exploded multipath */
	esi = bgp_evpn_attr_get_esi(parent_pi->attr);
	if (!memcmp(esi, zero_esi, sizeof(*esi)))
		return false;

	/* we don't support NHG for d-vni yet */
	if (bgp_evpn_mpath_has_dvni(bgp_vrf, pi))
		return false;

	bgp_evpn_es_vrf_use_nhg(bgp_vrf, esi, &use_l3nhg, &is_l3nhg_active,
				&es_vrf);

	/* L3NHG support is disabled, use legacy-exploded multipath */
	if (!use_l3nhg)
		return false;

	/* if the NHG has not been installed we cannot install the route yet,
	 * return a 0-NHG to indicate that
	 */
	if (!is_l3nhg_active)
		return true;

	/* this needs to be set the v6NHG if v6route */
	if (is_evpn_prefix_ipaddr_v6(evp))
		*nhg_p = es_vrf->v6_nhg_id;
	else
		*nhg_p = es_vrf->nhg_id;

	for (mpinfo = bgp_path_info_mpath_next(pi); mpinfo;
	     mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		/* if any of the paths have a different ESI we can't use
		 * the NHG associated with the ES. fallback to legacy-exploded
		 * multipath
		 */
		if (memcmp(esi, bgp_evpn_attr_get_esi(mpinfo->attr),
			   sizeof(*esi)))
			return false;
	}

	return true;
}

static void bgp_evpn_es_vrf_show_entry(struct vty *vty,
				       struct bgp_evpn_es_vrf *es_vrf,
				       json_object *json)
{
	struct bgp_evpn_es *es = es_vrf->es;
	struct bgp *bgp_vrf = es_vrf->bgp_vrf;

	if (json) {
		json_object *json_types;

		json_object_string_add(json, "esi", es->esi_str);
		json_object_string_add(json, "vrf", bgp_vrf->name_pretty);

		if (es_vrf->flags & (BGP_EVPNES_VRF_NHG_ACTIVE)) {
			json_types = json_object_new_array();
			if (es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE)
				json_array_string_add(json_types, "active");
			json_object_object_add(json, "flags", json_types);
		}

		json_object_int_add(json, "ipv4NHG", es_vrf->nhg_id);
		json_object_int_add(json, "ipv6NHG", es_vrf->v6_nhg_id);
		json_object_int_add(json, "refCount", es_vrf->ref_cnt);
	} else {
		char flags_str[4];

		flags_str[0] = '\0';
		if (es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE)
			strlcat(flags_str, "A", sizeof(flags_str));

		vty_out(vty, "%-30s %-15s %-5s %-8u %-8u %u\n", es->esi_str,
			bgp_vrf->name_pretty, flags_str, es_vrf->nhg_id,
			es_vrf->v6_nhg_id, es_vrf->ref_cnt);
	}
}

static void bgp_evpn_es_vrf_show_es(struct vty *vty, json_object *json_array,
				    struct bgp_evpn_es *es)
{
	json_object *json = NULL;
	struct listnode *es_vrf_node;
	struct bgp_evpn_es_vrf *es_vrf;

	for (ALL_LIST_ELEMENTS_RO(es->es_vrf_list, es_vrf_node, es_vrf)) {
		/* create a separate json object for each ES-VRF */
		if (json_array)
			json = json_object_new_object();
		bgp_evpn_es_vrf_show_entry(vty, es_vrf, json);
		/* add ES-VRF to the json array */
		if (json_array)
			json_object_array_add(json_array, json);
	}
}

/* Display all ES VRFs */
void bgp_evpn_es_vrf_show(struct vty *vty, bool uj, struct bgp_evpn_es *es)
{
	json_object *json_array = NULL;

	if (uj) {
		/* create an array of ESs */
		json_array = json_object_new_array();
	} else {
		vty_out(vty, "ES-VRF Flags: A Active\n");
		vty_out(vty, "%-30s %-15s %-5s %-8s %-8s %s\n", "ESI", "VRF",
			"Flags", "IPv4-NHG", "IPv6-NHG", "Ref");
	}

	if (es) {
		bgp_evpn_es_vrf_show_es(vty, json_array, es);
	} else {
		RB_FOREACH (es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree)
			bgp_evpn_es_vrf_show_es(vty, json_array, es);
	}

	/* print the array of json-ESs */
	if (uj)
		vty_json(vty, json_array);
}

/* Display specific ES VRF */
void bgp_evpn_es_vrf_show_esi(struct vty *vty, esi_t *esi, bool uj)
{
	struct bgp_evpn_es *es;

	es = bgp_evpn_es_find(esi);
	if (es) {
		bgp_evpn_es_vrf_show(vty, uj, es);
	} else {
		if (!uj)
			vty_out(vty, "ESI not found\n");
	}
}

/*****************************************************************************/
/* Ethernet Segment to EVI association -
 * 1. The ES-EVI entry is maintained as a RB tree per L2-VNI
 * (bgpevpn->es_evi_rb_tree).
 * 2. Each local ES-EVI entry is rxed from zebra and then used by BGP to
 * advertises an EAD-EVI (Type-1 EVPN) route
 * 3. The remote ES-EVI is created when a bgp_evpn_es_evi_vtep references
 * it.
 */

/* A list of remote VTEPs is maintained for each ES-EVI. This list includes -
 * 1. VTEPs for which we have imported the EAD-per-ES Type1 route
 * 2. VTEPs for which we have imported the EAD-per-EVI Type1 route
 * VTEPs for which both routes have been rxed are activated. Activation
 * creates a NHG in the parent ES.
 */
static int bgp_evpn_es_evi_vtep_cmp(void *p1, void *p2)
{
	const struct bgp_evpn_es_evi_vtep *evi_vtep1 = p1;
	const struct bgp_evpn_es_evi_vtep *evi_vtep2 = p2;

	return evi_vtep1->vtep_ip.s_addr - evi_vtep2->vtep_ip.s_addr;
}

static struct bgp_evpn_es_evi_vtep *bgp_evpn_es_evi_vtep_new(
		struct bgp_evpn_es_evi *es_evi, struct in_addr vtep_ip)
{
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	evi_vtep = XCALLOC(MTYPE_BGP_EVPN_ES_EVI_VTEP, sizeof(*evi_vtep));

	evi_vtep->es_evi = es_evi;
	evi_vtep->vtep_ip.s_addr = vtep_ip.s_addr;
	listnode_init(&evi_vtep->es_evi_listnode, evi_vtep);
	listnode_add_sort(es_evi->es_evi_vtep_list, &evi_vtep->es_evi_listnode);

	return evi_vtep;
}

static void bgp_evpn_es_evi_vtep_free(struct bgp_evpn_es_evi_vtep *evi_vtep)
{
	struct bgp_evpn_es_evi *es_evi = evi_vtep->es_evi;

	if (evi_vtep->flags & (BGP_EVPN_EVI_VTEP_EAD))
		/* as long as there is some reference we can't free it */
		return;

	list_delete_node(es_evi->es_evi_vtep_list, &evi_vtep->es_evi_listnode);
	XFREE(MTYPE_BGP_EVPN_ES_EVI_VTEP, evi_vtep);
}

/* check if VTEP is already part of the list */
static struct bgp_evpn_es_evi_vtep *bgp_evpn_es_evi_vtep_find(
		struct bgp_evpn_es_evi *es_evi, struct in_addr vtep_ip)
{
	struct listnode *node = NULL;
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	for (ALL_LIST_ELEMENTS_RO(es_evi->es_evi_vtep_list, node, evi_vtep)) {
		if (evi_vtep->vtep_ip.s_addr == vtep_ip.s_addr)
			return evi_vtep;
	}
	return NULL;
}

/* A VTEP can be added as "active" attach to an ES if EAD-per-ES and
 * EAD-per-EVI routes are rxed from it.
 */
static void bgp_evpn_es_evi_vtep_re_eval_active(struct bgp *bgp,
		struct bgp_evpn_es_evi_vtep *evi_vtep)
{
	bool old_active;
	bool new_active;
	uint32_t ead_activity_flags;

	old_active = CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

	if (bgp_mh_info->ead_evi_rx)
		/* Both EAD-per-ES and EAD-per-EVI routes must be rxed from a PE
		 * before it can be activated.
		 */
		ead_activity_flags = BGP_EVPN_EVI_VTEP_EAD;
	else
		/* EAD-per-ES is sufficent to activate the PE */
		ead_activity_flags = BGP_EVPN_EVI_VTEP_EAD_PER_ES;

	if ((evi_vtep->flags & ead_activity_flags) == ead_activity_flags)
		SET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);
	else
		UNSET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

	new_active = CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

	if (old_active == new_active)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s evi %u vtep %pI4 %s",
			   evi_vtep->es_evi->es->esi_str,
			   evi_vtep->es_evi->vpn->vni, &evi_vtep->vtep_ip,
			   new_active ? "active" : "inactive");

	/* add VTEP to parent es */
	if (new_active)
		evi_vtep->es_vtep = bgp_evpn_es_vtep_add(
			bgp, evi_vtep->es_evi->es, evi_vtep->vtep_ip,
			false /*esr*/, 0, 0);
	else {
		if (evi_vtep->es_vtep) {
			bgp_evpn_es_vtep_do_del(bgp, evi_vtep->es_vtep,
					false /*esr*/);
			evi_vtep->es_vtep = NULL;
		}
	}
	/* queue up the parent es for background consistency checks */
	bgp_evpn_es_cons_checks_pend_add(evi_vtep->es_evi->es);
}

static void bgp_evpn_es_evi_vtep_add(struct bgp *bgp,
		struct bgp_evpn_es_evi *es_evi, struct in_addr vtep_ip,
		bool ead_es)
{
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	evi_vtep = bgp_evpn_es_evi_vtep_find(es_evi, vtep_ip);

	if (!evi_vtep)
		evi_vtep = bgp_evpn_es_evi_vtep_new(es_evi, vtep_ip);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("add es %s evi %u vtep %pI4 %s",
			   evi_vtep->es_evi->es->esi_str,
			   evi_vtep->es_evi->vpn->vni, &evi_vtep->vtep_ip,
			   ead_es ? "ead_es" : "ead_evi");

	if (ead_es)
		SET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_EAD_PER_ES);
	else
		SET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_EAD_PER_EVI);

	bgp_evpn_es_evi_vtep_re_eval_active(bgp, evi_vtep);
}

static void bgp_evpn_es_evi_vtep_del(struct bgp *bgp,
		struct bgp_evpn_es_evi *es_evi, struct in_addr vtep_ip,
		bool ead_es)
{
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	evi_vtep = bgp_evpn_es_evi_vtep_find(es_evi, vtep_ip);
	if (!evi_vtep)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("del es %s evi %u vtep %pI4 %s",
			   evi_vtep->es_evi->es->esi_str,
			   evi_vtep->es_evi->vpn->vni, &evi_vtep->vtep_ip,
			   ead_es ? "ead_es" : "ead_evi");

	if (ead_es)
		UNSET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_EAD_PER_ES);
	else
		UNSET_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_EAD_PER_EVI);

	bgp_evpn_es_evi_vtep_re_eval_active(bgp, evi_vtep);
	bgp_evpn_es_evi_vtep_free(evi_vtep);
}

/* compare ES-IDs for the ES-EVI RB tree maintained per-VNI */
static int bgp_es_evi_rb_cmp(const struct bgp_evpn_es_evi *es_evi1,
		const struct bgp_evpn_es_evi *es_evi2)
{
	return memcmp(&es_evi1->es->esi, &es_evi2->es->esi, ESI_BYTES);
}
RB_GENERATE(bgp_es_evi_rb_head, bgp_evpn_es_evi, rb_node, bgp_es_evi_rb_cmp);

/* find the ES-EVI in the per-L2-VNI RB tree */
static struct bgp_evpn_es_evi *bgp_evpn_es_evi_find(struct bgp_evpn_es *es,
		struct bgpevpn *vpn)
{
	struct bgp_evpn_es_evi es_evi;

	es_evi.es = es;

	return RB_FIND(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree, &es_evi);
}

/* allocate a new ES-EVI and insert it into the per-L2-VNI and per-ES
 * tables.
 */
static struct bgp_evpn_es_evi *bgp_evpn_es_evi_new(struct bgp_evpn_es *es,
		struct bgpevpn *vpn)
{
	struct bgp_evpn_es_evi *es_evi;

	es_evi = XCALLOC(MTYPE_BGP_EVPN_ES_EVI, sizeof(*es_evi));

	es_evi->es = es;
	es_evi->vpn = vpn;

	/* Initialise the VTEP list */
	es_evi->es_evi_vtep_list = list_new();
	listset_app_node_mem(es_evi->es_evi_vtep_list);
	es_evi->es_evi_vtep_list->cmp = bgp_evpn_es_evi_vtep_cmp;

	/* insert into the VNI-ESI rb tree */
	RB_INSERT(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree, es_evi);

	/* add to the ES's VNI list */
	listnode_init(&es_evi->es_listnode, es_evi);
	listnode_add(es->es_evi_list, &es_evi->es_listnode);

	bgp_evpn_es_vrf_ref(es_evi, vpn->bgp_vrf);

	return es_evi;
}

/* remove the ES-EVI from the per-L2-VNI and per-ES tables and free
 * up the memory.
 */
static struct bgp_evpn_es_evi *
bgp_evpn_es_evi_free(struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es *es = es_evi->es;
	struct bgpevpn *vpn = es_evi->vpn;

	/* cannot free the element as long as there is a local or remote
	 * reference
	 */
	if (es_evi->flags & (BGP_EVPNES_EVI_LOCAL | BGP_EVPNES_EVI_REMOTE))
		return es_evi;
	bgp_evpn_es_frag_evi_del(es_evi, false);
	bgp_evpn_es_vrf_deref(es_evi);

	/* remove from the ES's VNI list */
	list_delete_node(es->es_evi_list, &es_evi->es_listnode);

	/* remove from the VNI-ESI rb tree */
	RB_REMOVE(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree, es_evi);

	/* free the VTEP list */
	list_delete(&es_evi->es_evi_vtep_list);

	/* remove from the VNI-ESI rb tree */
	XFREE(MTYPE_BGP_EVPN_ES_EVI, es_evi);

	return NULL;
}

/* init local info associated with the ES-EVI */
static void bgp_evpn_es_evi_local_info_set(struct bgp_evpn_es_evi *es_evi)
{
	struct bgpevpn *vpn = es_evi->vpn;

	if (CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
		return;

	SET_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL);
	listnode_init(&es_evi->l2vni_listnode, es_evi);
	listnode_add(vpn->local_es_evi_list, &es_evi->l2vni_listnode);
	bgp_evpn_es_frag_evi_add(es_evi);
}

/* clear any local info associated with the ES-EVI */
static struct bgp_evpn_es_evi *
bgp_evpn_es_evi_local_info_clear(struct bgp_evpn_es_evi *es_evi)
{
	struct bgpevpn *vpn = es_evi->vpn;

	UNSET_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL);
	list_delete_node(vpn->local_es_evi_list, &es_evi->l2vni_listnode);

	return bgp_evpn_es_evi_free(es_evi);
}

/* eval remote info associated with the ES */
static void bgp_evpn_es_evi_remote_info_re_eval(struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es *es = es_evi->es;

	/* if there are remote VTEPs the ES-EVI is classified as "remote" */
	if (listcount(es_evi->es_evi_vtep_list)) {
		if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_REMOTE)) {
			SET_FLAG(es_evi->flags, BGP_EVPNES_EVI_REMOTE);
			++es->remote_es_evi_cnt;
			/* set remote on the parent es */
			bgp_evpn_es_remote_info_re_eval(es);
		}
	} else {
		if (CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_REMOTE)) {
			UNSET_FLAG(es_evi->flags, BGP_EVPNES_EVI_REMOTE);
			if (es->remote_es_evi_cnt)
				--es->remote_es_evi_cnt;
			bgp_evpn_es_evi_free(es_evi);
			/* check if "remote" can be cleared from the
			 * parent es.
			 */
			bgp_evpn_es_remote_info_re_eval(es);
		}
	}
}

static struct bgp_evpn_es_evi *
bgp_evpn_local_es_evi_do_del(struct bgp_evpn_es_evi *es_evi)
{
	struct prefix_evpn p;
	struct bgp_evpn_es *es = es_evi->es;
	struct bgp *bgp;

	if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
		return es_evi;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("del local es %s evi %u",
				es_evi->es->esi_str,
				es_evi->vpn->vni);

	bgp = bgp_get_evpn();

	/* remove the es_evi from the es_frag before sending the update */
	bgp_evpn_es_frag_evi_del(es_evi, true);
	if (bgp) {
		/* update EAD-ES with new list of VNIs */
		if (bgp_evpn_local_es_is_active(es))
			bgp_evpn_ead_es_route_update(bgp, es);

		/* withdraw and delete EAD-EVI */
		if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
			build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
					&es->esi, es->originator_ip);
			if (bgp_evpn_ead_evi_route_delete(bgp, es, es_evi->vpn,
							  &p))
				flog_err(EC_BGP_EVPN_ROUTE_DELETE,
					"%u: EAD-EVI route deletion failure for ESI %s VNI %u",
					bgp->vrf_id, es->esi_str,
					es_evi->vpn->vni);
		}
	}

	return bgp_evpn_es_evi_local_info_clear(es_evi);
}

int bgp_evpn_local_es_evi_del(struct bgp *bgp, esi_t *esi, vni_t vni)
{
	struct bgpevpn *vpn;
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;
	char buf[ESI_STR_LEN];

	es = bgp_evpn_es_find(esi);
	if (!es) {
		flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to deref VNI %d from ESI %s; ES not present",
				bgp->vrf_id, vni,
				esi_to_str(esi, buf, sizeof(buf)));
		return -1;
	}

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to deref VNI %d from ESI %s; VNI not present",
				bgp->vrf_id, vni, es->esi_str);
		return -1;
	}

	es_evi = bgp_evpn_es_evi_find(es, vpn);
	if (!es_evi) {
		flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to deref VNI %d from ESI %s; ES-VNI not present",
				bgp->vrf_id, vni, es->esi_str);
		return -1;
	}

	bgp_evpn_local_es_evi_do_del(es_evi);
	return 0;
}

/* Create ES-EVI and advertise the corresponding EAD routes */
int bgp_evpn_local_es_evi_add(struct bgp *bgp, esi_t *esi, vni_t vni)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;
	char buf[ESI_STR_LEN];

	es = bgp_evpn_es_find(esi);
	if (!es) {
		flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to associate VNI %d with ESI %s; ES not present",
				bgp->vrf_id, vni,
				esi_to_str(esi, buf, sizeof(buf)));
		return -1;
	}

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to associate VNI %d with ESI %s; VNI not present",
				bgp->vrf_id, vni, es->esi_str);
		return -1;
	}

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("add local es %s evi %u",
				es->esi_str, vni);

	es_evi = bgp_evpn_es_evi_find(es, vpn);

	if (es_evi) {
		if (CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
			/* dup */
			return 0;
	} else
		es_evi = bgp_evpn_es_evi_new(es, vpn);

	bgp_evpn_es_evi_local_info_set(es_evi);

	/* generate an EAD-EVI for this new VNI */
	if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
		build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG, &es->esi,
					es->originator_ip);
		bgp_evpn_ead_evi_route_update(bgp, es, vpn, &p);
	}

	/* update EAD-ES */
	if (bgp_evpn_local_es_is_active(es))
		bgp_evpn_ead_es_route_update(bgp, es);

	return 0;
}

/* Add remote ES-EVI entry. This is actually the remote VTEP add and the
 * ES-EVI is implicity created on first VTEP's reference.
 */
int bgp_evpn_remote_es_evi_add(struct bgp *bgp, struct bgpevpn *vpn,
		const struct prefix_evpn *p)
{
	char buf[ESI_STR_LEN];
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;
	bool ead_es;
	const esi_t *esi = &p->prefix.ead_addr.esi;

	if (!vpn)
		/* local EAD-ES need not be sent back to zebra */
		return 0;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("add remote %s es %s evi %u vtep %pI4",
			   p->prefix.ead_addr.eth_tag ? "ead-es" : "ead-evi",
			   esi_to_str(esi, buf, sizeof(buf)), vpn->vni,
			   &p->prefix.ead_addr.ip.ipaddr_v4);

	es = bgp_evpn_es_find(esi);
	if (!es)
		es = bgp_evpn_es_new(bgp, esi);

	es_evi = bgp_evpn_es_evi_find(es, vpn);
	if (!es_evi)
		es_evi = bgp_evpn_es_evi_new(es, vpn);

	ead_es = !!p->prefix.ead_addr.eth_tag;
	bgp_evpn_es_evi_vtep_add(bgp, es_evi, p->prefix.ead_addr.ip.ipaddr_v4,
			ead_es);

	bgp_evpn_es_evi_remote_info_re_eval(es_evi);
	return 0;
}

/* A remote VTEP has withdrawn. The es-evi-vtep will be deleted and the
 * parent es-evi freed up implicitly in last VTEP's deref.
 */
int bgp_evpn_remote_es_evi_del(struct bgp *bgp, struct bgpevpn *vpn,
		const struct prefix_evpn *p)
{
	char buf[ESI_STR_LEN];
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;
	bool ead_es;

	if (!vpn)
		/* local EAD-ES need not be sent back to zebra */
		return 0;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug(
			"del remote %s es %s evi %u vtep %pI4",
			p->prefix.ead_addr.eth_tag ? "ead-es" : "ead-evi",
			esi_to_str(&p->prefix.ead_addr.esi, buf, sizeof(buf)),
			vpn->vni, &p->prefix.ead_addr.ip.ipaddr_v4);

	es = bgp_evpn_es_find(&p->prefix.ead_addr.esi);
	if (!es) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug(
				"del remote %s es %s evi %u vtep %pI4, NO es",
				p->prefix.ead_addr.eth_tag ? "ead-es"
							   : "ead-evi",
				esi_to_str(&p->prefix.ead_addr.esi, buf,
					   sizeof(buf)),
				vpn->vni, &p->prefix.ead_addr.ip.ipaddr_v4);
		return 0;
	}
	es_evi = bgp_evpn_es_evi_find(es, vpn);
	if (!es_evi) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug(
				"del remote %s es %s evi %u vtep %pI4, NO es-evi",
				p->prefix.ead_addr.eth_tag ? "ead-es"
							   : "ead-evi",
				esi_to_str(&p->prefix.ead_addr.esi, buf,
					   sizeof(buf)),
				vpn->vni,
				&p->prefix.ead_addr.ip.ipaddr_v4);
		return 0;
	}

	ead_es = !!p->prefix.ead_addr.eth_tag;
	bgp_evpn_es_evi_vtep_del(bgp, es_evi, p->prefix.ead_addr.ip.ipaddr_v4,
			ead_es);
	bgp_evpn_es_evi_remote_info_re_eval(es_evi);
	return 0;
}

/* If a VNI is being deleted we need to force del all remote VTEPs */
static void bgp_evpn_remote_es_evi_flush(struct bgp_evpn_es_evi *es_evi)
{
	struct listnode *node = NULL;
	struct listnode *nnode = NULL;
	struct bgp_evpn_es_evi_vtep *evi_vtep;
	struct bgp *bgp;

	bgp = bgp_get_evpn();
	if (!bgp)
		return;

	/* delete all VTEPs */
	for (ALL_LIST_ELEMENTS(es_evi->es_evi_vtep_list, node, nnode,
			       evi_vtep)) {
		evi_vtep->flags &= ~(BGP_EVPN_EVI_VTEP_EAD_PER_ES
				     | BGP_EVPN_EVI_VTEP_EAD_PER_EVI);
		bgp_evpn_es_evi_vtep_re_eval_active(bgp, evi_vtep);
		bgp_evpn_es_evi_vtep_free(evi_vtep);
	}
	/* delete the EVI */
	bgp_evpn_es_evi_remote_info_re_eval(es_evi);
}

/* Initialize the ES tables maintained per-L2_VNI */
void bgp_evpn_vni_es_init(struct bgpevpn *vpn)
{
	/* Initialize the ES-EVI RB tree */
	RB_INIT(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree);

	/* Initialize the local list maintained for quick walks by type */
	vpn->local_es_evi_list = list_new();
	listset_app_node_mem(vpn->local_es_evi_list);
}

/* Cleanup the ES info maintained per-L2_VNI */
void bgp_evpn_vni_es_cleanup(struct bgpevpn *vpn)
{
	struct bgp_evpn_es_evi *es_evi;
	struct bgp_evpn_es_evi *es_evi_next;

	RB_FOREACH_SAFE(es_evi, bgp_es_evi_rb_head,
			&vpn->es_evi_rb_tree, es_evi_next) {
		es_evi = bgp_evpn_local_es_evi_do_del(es_evi);
		if (es_evi)
			bgp_evpn_remote_es_evi_flush(es_evi);
	}

	list_delete(&vpn->local_es_evi_list);
}

static char *bgp_evpn_es_evi_vteps_str(char *vtep_str,
				       struct bgp_evpn_es_evi *es_evi,
				       uint8_t vtep_str_size)
{
	char vtep_flag_str[BGP_EVPN_FLAG_STR_SZ];
	struct listnode *node;
	struct bgp_evpn_es_evi_vtep *evi_vtep;
	bool first = true;
	char ip_buf[INET_ADDRSTRLEN];

	vtep_str[0] = '\0';
	for (ALL_LIST_ELEMENTS_RO(es_evi->es_evi_vtep_list, node, evi_vtep)) {
		vtep_flag_str[0] = '\0';
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_ES)
			strlcat(vtep_flag_str, "E", sizeof(vtep_flag_str));
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_EVI)
			strlcat(vtep_flag_str, "V", sizeof(vtep_flag_str));

		if (!strnlen(vtep_flag_str, sizeof(vtep_flag_str)))
			strlcpy(vtep_flag_str, "-", sizeof(vtep_flag_str));
		if (first)
			first = false;
		else
			strlcat(vtep_str, ",", vtep_str_size);
		strlcat(vtep_str,
			inet_ntop(AF_INET, &evi_vtep->vtep_ip, ip_buf,
				  sizeof(ip_buf)),
			vtep_str_size);
		strlcat(vtep_str, "(", vtep_str_size);
		strlcat(vtep_str, vtep_flag_str, vtep_str_size);
		strlcat(vtep_str, ")", vtep_str_size);
	}

	return vtep_str;
}

static void bgp_evpn_es_evi_json_vtep_fill(json_object *json_vteps,
		struct bgp_evpn_es_evi_vtep *evi_vtep)
{
	json_object *json_vtep_entry;
	json_object *json_flags;

	json_vtep_entry = json_object_new_object();

	json_object_string_addf(json_vtep_entry, "vtep_ip", "%pI4",
				&evi_vtep->vtep_ip);
	if (evi_vtep->flags & (BGP_EVPN_EVI_VTEP_EAD_PER_ES |
			 BGP_EVPN_EVI_VTEP_EAD_PER_EVI)) {
		json_flags = json_object_new_array();
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_ES)
			json_array_string_add(json_flags, "ead-per-es");
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_EVI)
			json_array_string_add(json_flags, "ead-per-evi");
		json_object_object_add(json_vtep_entry,
				"flags", json_flags);
	}

	json_object_array_add(json_vteps,
			json_vtep_entry);
}

static void bgp_evpn_es_evi_show_entry(struct vty *vty,
		struct bgp_evpn_es_evi *es_evi, json_object *json)
{
	struct listnode *node;
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	if (json) {
		json_object *json_vteps;
		json_object *json_types;

		json_object_string_add(json, "esi", es_evi->es->esi_str);
		if (es_evi->vpn)
			json_object_int_add(json, "vni", es_evi->vpn->vni);

		if (es_evi->flags & (BGP_EVPNES_EVI_LOCAL |
					BGP_EVPNES_EVI_REMOTE)) {
			json_types = json_object_new_array();
			if (es_evi->flags & BGP_EVPNES_EVI_LOCAL)
				json_array_string_add(json_types, "local");
			if (es_evi->flags & BGP_EVPNES_EVI_REMOTE)
				json_array_string_add(json_types, "remote");
			json_object_object_add(json, "type", json_types);
		}

		if (listcount(es_evi->es_evi_vtep_list)) {
			json_vteps = json_object_new_array();
			for (ALL_LIST_ELEMENTS_RO(es_evi->es_evi_vtep_list,
						node, evi_vtep)) {
				bgp_evpn_es_evi_json_vtep_fill(json_vteps,
						evi_vtep);
			}
			json_object_object_add(json, "vteps", json_vteps);
		}
	} else {
		char type_str[4];
		char vtep_str[ES_VTEP_LIST_STR_SZ + BGP_EVPN_VTEPS_FLAG_STR_SZ];

		type_str[0] = '\0';
		if (es_evi->flags & BGP_EVPNES_EVI_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es_evi->flags & BGP_EVPNES_EVI_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));
		if (es_evi->flags & BGP_EVPNES_EVI_INCONS_VTEP_LIST)
			strlcat(type_str, "I", sizeof(type_str));

		bgp_evpn_es_evi_vteps_str(vtep_str, es_evi, sizeof(vtep_str));

		vty_out(vty, "%-8d %-30s %-5s %s\n",
				es_evi->vpn->vni, es_evi->es->esi_str,
				type_str, vtep_str);
	}
}

static void bgp_evpn_es_evi_show_entry_detail(struct vty *vty,
		struct bgp_evpn_es_evi *es_evi, json_object *json)
{
	enum asnotation_mode mode;

	mode = bgp_get_asnotation(es_evi->vpn->bgp_vrf);

	if (json) {
		json_object *json_flags;

		/* Add the "brief" info first */
		bgp_evpn_es_evi_show_entry(vty, es_evi, json);
		if (es_evi->es_frag)
			json_object_string_addf(json, "esFragmentRd",
						BGP_RD_AS_FORMAT(mode),
						&es_evi->es_frag->prd);
		if (es_evi->flags & BGP_EVPNES_EVI_INCONS_VTEP_LIST) {
			json_flags = json_object_new_array();
			json_array_string_add(json_flags, "es-vtep-mismatch");
			json_object_object_add(json, "flags", json_flags);
		}
	} else {
		char vtep_str[ES_VTEP_LIST_STR_SZ + BGP_EVPN_VTEPS_FLAG_STR_SZ];
		char type_str[4];

		type_str[0] = '\0';
		if (es_evi->flags & BGP_EVPNES_EVI_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es_evi->flags & BGP_EVPNES_EVI_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));

		bgp_evpn_es_evi_vteps_str(vtep_str, es_evi, sizeof(vtep_str));
		if (!strlen(vtep_str))
			strlcpy(vtep_str, "-", sizeof(type_str));

		vty_out(vty, "VNI: %d ESI: %s\n",
				es_evi->vpn->vni, es_evi->es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		if (es_evi->es_frag) {
			vty_out(vty, " ES fragment RD: ");
			vty_out(vty, BGP_RD_AS_FORMAT(mode),
				&es_evi->es_frag->prd);
			vty_out(vty, "\n");
		}
		vty_out(vty, " Inconsistencies: %s\n",
			(es_evi->flags & BGP_EVPNES_EVI_INCONS_VTEP_LIST) ?
			"es-vtep-mismatch":"-");
		vty_out(vty, " VTEPs: %s\n", vtep_str);
		vty_out(vty, "\n");
	}
}

static void bgp_evpn_es_evi_show_one_vni(struct bgpevpn *vpn, struct vty *vty,
		json_object *json_array, bool detail)
{
	struct bgp_evpn_es_evi *es_evi;
	json_object *json = NULL;

	RB_FOREACH(es_evi, bgp_es_evi_rb_head, &vpn->es_evi_rb_tree) {
		if (json_array)
			/* create a separate json object for each ES */
			json = json_object_new_object();
		if (detail)
			bgp_evpn_es_evi_show_entry_detail(vty, es_evi, json);
		else
			bgp_evpn_es_evi_show_entry(vty, es_evi, json);
		/* add ES to the json array */
		if (json_array)
			json_object_array_add(json_array, json);
	}
}

struct es_evi_show_ctx {
	struct vty *vty;
	json_object *json;
	int detail;
};

static void bgp_evpn_es_evi_show_one_vni_hash_cb(struct hash_bucket *bucket,
		void *ctxt)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct es_evi_show_ctx *wctx = (struct es_evi_show_ctx *)ctxt;

	bgp_evpn_es_evi_show_one_vni(vpn, wctx->vty, wctx->json, wctx->detail);
}

/* Display all ES EVIs */
void bgp_evpn_es_evi_show(struct vty *vty, bool uj, bool detail)
{
	json_object *json_array = NULL;
	struct es_evi_show_ctx wctx;
	struct bgp *bgp;

	if (uj) {
		/* create an array of ES-EVIs */
		json_array = json_object_new_array();
	}

	wctx.vty = vty;
	wctx.json = json_array;
	wctx.detail = detail;

	bgp = bgp_get_evpn();

	if (!json_array && !detail) {
		vty_out(vty, "Flags: L local, R remote, I inconsistent\n");
		vty_out(vty, "VTEP-Flags: E EAD-per-ES, V EAD-per-EVI\n");
		vty_out(vty, "%-8s %-30s %-5s %s\n",
				"VNI", "ESI", "Flags", "VTEPs");
	}

	if (bgp)
		hash_iterate(bgp->vnihash,
				(void (*)(struct hash_bucket *,
				  void *))bgp_evpn_es_evi_show_one_vni_hash_cb,
				&wctx);
	if (uj)
		vty_json(vty, json_array);
}

/* Display specific ES EVI */
void bgp_evpn_es_evi_show_vni(struct vty *vty, vni_t vni,
		bool uj, bool detail)
{
	struct bgpevpn *vpn = NULL;
	json_object *json_array = NULL;
	struct bgp *bgp;

	if (uj) {
		/* create an array of ES-EVIs */
		json_array = json_object_new_array();
	}

	bgp = bgp_get_evpn();
	if (bgp)
		vpn = bgp_evpn_lookup_vni(bgp, vni);

	if (vpn) {
		if (!json_array && !detail) {
			vty_out(vty, "Flags: L local, R remote, I inconsistent\n");
			vty_out(vty, "VTEP-Flags: E EAD-per-ES, V EAD-per-EVI\n");
			vty_out(vty, "%-8s %-30s %-5s %s\n",
					"VNI", "ESI", "Flags", "VTEPs");
		}

		bgp_evpn_es_evi_show_one_vni(vpn, vty, json_array, detail);
	} else {
		if (!uj)
			vty_out(vty, "VNI not found\n");
	}

	if (uj)
		vty_json(vty, json_array);
}

/*****************************************************************************
 * Ethernet Segment Consistency checks
 *     Consistency checking is done to detect misconfig or mis-cabling. When
 * an inconsistency is detected it is simply logged (and displayed via
 * show commands) at this point. A more drastic action can be executed (based
 * on user config) in the future.
 */
static void bgp_evpn_es_cons_checks_timer_start(void)
{
	if (!bgp_mh_info->consistency_checking || bgp_mh_info->t_cons_check)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("periodic consistency checking started");

	event_add_timer(bm->master, bgp_evpn_run_consistency_checks, NULL,
			BGP_EVPN_CONS_CHECK_INTERVAL,
			&bgp_mh_info->t_cons_check);
}

/* queue up the es for background consistency checks */
static void bgp_evpn_es_cons_checks_pend_add(struct bgp_evpn_es *es)
{
	if (!bgp_mh_info->consistency_checking)
		/* consistency checking is not enabled */
		return;

	if (CHECK_FLAG(es->flags, BGP_EVPNES_CONS_CHECK_PEND))
		/* already queued for consistency checking */
		return;

	/* start the periodic timer for consistency checks if it is not
	 * already running */
	bgp_evpn_es_cons_checks_timer_start();

	SET_FLAG(es->flags, BGP_EVPNES_CONS_CHECK_PEND);
	listnode_init(&es->pend_es_listnode, es);
	listnode_add_after(bgp_mh_info->pend_es_list,
			listtail_unchecked(bgp_mh_info->pend_es_list),
			&es->pend_es_listnode);
}

/* pull the ES from the consistency check list */
static void bgp_evpn_es_cons_checks_pend_del(struct bgp_evpn_es *es)
{
	if (!CHECK_FLAG(es->flags, BGP_EVPNES_CONS_CHECK_PEND))
		return;

	UNSET_FLAG(es->flags, BGP_EVPNES_CONS_CHECK_PEND);
	list_delete_node(bgp_mh_info->pend_es_list,
			&es->pend_es_listnode);
}

/* Number of active VTEPs associated with the ES-per-EVI */
static uint32_t bgp_evpn_es_evi_get_active_vtep_cnt(
		struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es_evi_vtep *evi_vtep;
	struct listnode *node;
	uint32_t vtep_cnt = 0;

	for (ALL_LIST_ELEMENTS_RO(es_evi->es_evi_vtep_list, node, evi_vtep)) {
		if (CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE))
			++vtep_cnt;
	}

	return vtep_cnt;
}

/* Number of active VTEPs associated with the ES */
static uint32_t bgp_evpn_es_get_active_vtep_cnt(struct bgp_evpn_es *es)
{
	struct listnode *node;
	uint32_t vtep_cnt = 0;
	struct bgp_evpn_es_vtep *es_vtep;

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE))
			++vtep_cnt;
	}

	return vtep_cnt;
}

static struct bgp_evpn_es_vtep *bgp_evpn_es_get_next_active_vtep(
		struct bgp_evpn_es *es, struct bgp_evpn_es_vtep *es_vtep)
{
	struct listnode *node;
	struct bgp_evpn_es_vtep *next_es_vtep;

	if (es_vtep)
		node = listnextnode_unchecked(&es_vtep->es_listnode);
	else
		node = listhead(es->es_vtep_list);

	for (; node; node = listnextnode_unchecked(node)) {
		next_es_vtep = listgetdata(node);
		if (CHECK_FLAG(next_es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE))
			return next_es_vtep;
	}

	return NULL;
}

static struct bgp_evpn_es_evi_vtep *bgp_evpn_es_evi_get_next_active_vtep(
	struct bgp_evpn_es_evi *es_evi,
	struct bgp_evpn_es_evi_vtep *evi_vtep)
{
	struct listnode *node;
	struct bgp_evpn_es_evi_vtep *next_evi_vtep;

	if (evi_vtep)
		node = listnextnode_unchecked(&evi_vtep->es_evi_listnode);
	else
		node = listhead(es_evi->es_evi_vtep_list);

	for (; node; node = listnextnode_unchecked(node)) {
		next_evi_vtep = listgetdata(node);
		if (CHECK_FLAG(next_evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE))
			return next_evi_vtep;
	}

	return NULL;
}

static void bgp_evpn_es_evi_set_inconsistent(struct bgp_evpn_es_evi *es_evi)
{
	if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_INCONS_VTEP_LIST)) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("inconsistency detected - es %s evi %u vtep list mismatch",
					es_evi->es->esi_str,
					es_evi->vpn->vni);
		SET_FLAG(es_evi->flags, BGP_EVPNES_EVI_INCONS_VTEP_LIST);

		/* update parent ES with the incosistency setting */
		if (!es_evi->es->incons_evi_vtep_cnt &&
				BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("inconsistency detected - es %s vtep list mismatch",
					es_evi->es->esi_str);
		++es_evi->es->incons_evi_vtep_cnt;
		SET_FLAG(es_evi->es->inconsistencies,
				BGP_EVPNES_INCONS_VTEP_LIST);
	}
}

static uint32_t bgp_evpn_es_run_consistency_checks(struct bgp_evpn_es *es)
{
	int proc_cnt = 0;
	int es_active_vtep_cnt;
	int evi_active_vtep_cnt;
	struct bgp_evpn_es_evi *es_evi;
	struct listnode *evi_node;
	struct bgp_evpn_es_vtep *es_vtep;
	struct bgp_evpn_es_evi_vtep *evi_vtep;

	/* reset the inconsistencies and re-evaluate */
	es->incons_evi_vtep_cnt = 0;
	es->inconsistencies = 0;

	es_active_vtep_cnt = bgp_evpn_es_get_active_vtep_cnt(es);
	for (ALL_LIST_ELEMENTS_RO(es->es_evi_list,
				evi_node, es_evi)) {
		++proc_cnt;

		/* reset the inconsistencies on the EVI and re-evaluate*/
		UNSET_FLAG(es_evi->flags, BGP_EVPNES_EVI_INCONS_VTEP_LIST);

		evi_active_vtep_cnt =
			bgp_evpn_es_evi_get_active_vtep_cnt(es_evi);
		if (es_active_vtep_cnt != evi_active_vtep_cnt) {
			bgp_evpn_es_evi_set_inconsistent(es_evi);
			continue;
		}

		if (!es_active_vtep_cnt)
			continue;

		es_vtep = NULL;
		evi_vtep = NULL;
		while ((es_vtep = bgp_evpn_es_get_next_active_vtep(
						es, es_vtep))) {
			evi_vtep = bgp_evpn_es_evi_get_next_active_vtep(es_evi,
					evi_vtep);
			if (!evi_vtep) {
				bgp_evpn_es_evi_set_inconsistent(es_evi);
				break;
			}
			if (es_vtep->vtep_ip.s_addr !=
					evi_vtep->vtep_ip.s_addr) {
				/* inconsistency detected; set it and move
				 * to the next evi
				 */
				bgp_evpn_es_evi_set_inconsistent(es_evi);
				break;
			}
		}
	}

	return proc_cnt;
}

static void bgp_evpn_run_consistency_checks(struct event *t)
{
	int proc_cnt = 0;
	struct listnode *node;
	struct listnode *nextnode;
	struct bgp_evpn_es *es;

	for (ALL_LIST_ELEMENTS(bgp_mh_info->pend_es_list,
				node, nextnode, es)) {
		++proc_cnt;
		/* run consistency checks on the ES and remove it from the
		 * pending list
		 */
		proc_cnt += bgp_evpn_es_run_consistency_checks(es);
		bgp_evpn_es_cons_checks_pend_del(es);
		if (proc_cnt > 500)
			break;
	}

	/* restart the timer */
	event_add_timer(bm->master, bgp_evpn_run_consistency_checks, NULL,
			BGP_EVPN_CONS_CHECK_INTERVAL,
			&bgp_mh_info->t_cons_check);
}

/*****************************************************************************
 * EVPN-Nexthop and RMAC management: nexthops associated with Type-2 routes
 * that have an ES as destination are consolidated by BGP into a per-VRF
 * nh->rmac mapping which is sent to zebra. Zebra installs the nexthop
 * as a remote neigh/fdb entry with a dummy (type-1) prefix referencing it.
 *
 * This handling is needed because Type-2 routes with ES as dest use NHG
 * that is setup using EAD routes (i.e. such NHGs do not include the
 * RMAC info).
 ****************************************************************************/
static void bgp_evpn_nh_zebra_update_send(struct bgp_evpn_nh *nh, bool add)
{
	struct stream *s;
	struct bgp *bgp_vrf = nh->bgp_vrf;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp_vrf)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("No zebra instance, not %s remote nh %s",
				   add ? "adding" : "deleting", nh->nh_str);
		return;
	}

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(
		s, add ? ZEBRA_EVPN_REMOTE_NH_ADD : ZEBRA_EVPN_REMOTE_NH_DEL,
		bgp_vrf->vrf_id);
	stream_putl(s, bgp_vrf->vrf_id);
	stream_put(s, &nh->ip, sizeof(nh->ip));
	if (add)
		stream_put(s, &nh->rmac, sizeof(nh->rmac));

	stream_putw_at(s, 0, stream_get_endp(s));

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES)) {
		if (add)
			zlog_debug("evpn vrf %s nh %s rmac %pEA add to zebra",
				   nh->bgp_vrf->name_pretty, nh->nh_str,
				   &nh->rmac);
		else if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("evpn vrf %s nh %s del to zebra",
				   nh->bgp_vrf->name_pretty, nh->nh_str);
	}

	frrtrace(2, frr_bgp, evpn_mh_nh_rmac_zsend, add, nh);

	zclient_send_message(zclient);
}

static void bgp_evpn_nh_zebra_update(struct bgp_evpn_nh *nh, bool add)
{
	if (add && !is_zero_mac(&nh->rmac)) {
		nh->flags |= BGP_EVPN_NH_READY_FOR_ZEBRA;
		bgp_evpn_nh_zebra_update_send(nh, true);
	} else {
		if (!(nh->flags & BGP_EVPN_NH_READY_FOR_ZEBRA))
			return;
		nh->flags &= ~BGP_EVPN_NH_READY_FOR_ZEBRA;
		bgp_evpn_nh_zebra_update_send(nh, false);
	}
}

static void *bgp_evpn_nh_alloc(void *p)
{
	struct bgp_evpn_nh *tmp_n = p;
	struct bgp_evpn_nh *n;

	n = XCALLOC(MTYPE_BGP_EVPN_NH, sizeof(struct bgp_evpn_nh));
	*n = *tmp_n;

	return ((void *)n);
}

static struct bgp_evpn_nh *bgp_evpn_nh_find(struct bgp *bgp_vrf,
					    struct ipaddr *ip)
{
	struct bgp_evpn_nh tmp;
	struct bgp_evpn_nh *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	n = hash_lookup(bgp_vrf->evpn_nh_table, &tmp);

	return n;
}

/* Add nexthop entry - implicitly created on first path reference */
static struct bgp_evpn_nh *bgp_evpn_nh_add(struct bgp *bgp_vrf,
					   struct ipaddr *ip,
					   struct bgp_path_info *pi)
{
	struct bgp_evpn_nh tmp_n;
	struct bgp_evpn_nh *n = NULL;

	memset(&tmp_n, 0, sizeof(tmp_n));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = hash_get(bgp_vrf->evpn_nh_table, &tmp_n, bgp_evpn_nh_alloc);
	ipaddr2str(ip, n->nh_str, sizeof(n->nh_str));
	n->bgp_vrf = bgp_vrf;

	n->pi_list = list_new();
	listset_app_node_mem(n->pi_list);

	/* Setup ref_pi when the nh is created */
	if (CHECK_FLAG(pi->flags, BGP_PATH_VALID) && pi->attr) {
		n->ref_pi = pi;
		memcpy(&n->rmac, &pi->attr->rmac, ETH_ALEN);
	}

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh %s rmac %pEA add",
			   n->bgp_vrf->name_pretty, n->nh_str, &n->rmac);
	bgp_evpn_nh_zebra_update(n, true);
	return n;
}

/* Delete nexthop entry if there are no paths referencing it */
static void bgp_evpn_nh_del(struct bgp_evpn_nh *n)
{
	struct bgp_evpn_nh *tmp_n;
	struct bgp *bgp_vrf = n->bgp_vrf;

	if (listcount(n->pi_list))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh %s del to zebra",
			   bgp_vrf->name_pretty, n->nh_str);

	bgp_evpn_nh_zebra_update(n, false);
	list_delete(&n->pi_list);
	tmp_n = hash_release(bgp_vrf->evpn_nh_table, n);
	XFREE(MTYPE_BGP_EVPN_NH, tmp_n);
}

static void hash_evpn_nh_free(struct bgp_evpn_nh *ben)
{
	XFREE(MTYPE_BGP_EVPN_NH, ben);
}

static unsigned int bgp_evpn_nh_hash_keymake(const void *p)
{
	const struct bgp_evpn_nh *n = p;
	const struct ipaddr *ip = &n->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32,
		      array_size(ip->ipaddr_v6.s6_addr32), 0);
}

static bool bgp_evpn_nh_cmp(const void *p1, const void *p2)
{
	const struct bgp_evpn_nh *n1 = p1;
	const struct bgp_evpn_nh *n2 = p2;

	if (n1 == NULL && n2 == NULL)
		return true;

	if (n1 == NULL || n2 == NULL)
		return false;

	return (ipaddr_cmp(&n1->ip, &n2->ip) == 0);
}

void bgp_evpn_nh_init(struct bgp *bgp_vrf)
{
	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh init", bgp_vrf->name_pretty);
	bgp_vrf->evpn_nh_table = hash_create(
		bgp_evpn_nh_hash_keymake, bgp_evpn_nh_cmp, "BGP EVPN NH table");
}

static void bgp_evpn_nh_flush_entry(struct bgp_evpn_nh *nh)
{
	struct listnode *node;
	struct listnode *nnode;
	struct bgp_path_evpn_nh_info *nh_info;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh %s flush", nh->bgp_vrf->name_pretty,
			   nh->nh_str);

	/* force flush paths */
	for (ALL_LIST_ELEMENTS(nh->pi_list, node, nnode, nh_info))
		bgp_evpn_path_nh_del(nh->bgp_vrf, nh_info->pi);
}

static void bgp_evpn_nh_flush_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_evpn_nh *nh = (struct bgp_evpn_nh *)bucket->data;

	bgp_evpn_nh_flush_entry(nh);
}

void bgp_evpn_nh_finish(struct bgp *bgp_vrf)
{
	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh finish", bgp_vrf->name_pretty);
	hash_iterate(
		bgp_vrf->evpn_nh_table,
		(void (*)(struct hash_bucket *, void *))bgp_evpn_nh_flush_cb,
		NULL);
	hash_clean_and_free(&bgp_vrf->evpn_nh_table,
			    (void (*)(void *))hash_evpn_nh_free);
}

static void bgp_evpn_nh_update_ref_pi(struct bgp_evpn_nh *nh)
{
	struct listnode *node;
	struct bgp_path_info *pi;
	struct bgp_path_evpn_nh_info *nh_info;

	if (nh->ref_pi)
		return;

	for (ALL_LIST_ELEMENTS_RO(nh->pi_list, node, nh_info)) {
		pi = nh_info->pi;
		if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID) || !pi->attr)
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("evpn vrf %s nh %s ref_pi update",
				   nh->bgp_vrf->name_pretty, nh->nh_str);
		nh->ref_pi = pi;
		/* If we have a new pi copy rmac from it and update
		 * zebra if the new rmac is different
		 */
		if (memcmp(&nh->rmac, &nh->ref_pi->attr->rmac, ETH_ALEN)) {
			memcpy(&nh->rmac, &nh->ref_pi->attr->rmac, ETH_ALEN);
			bgp_evpn_nh_zebra_update(nh, true);
		}
		break;
	}
}

static void bgp_evpn_nh_clear_ref_pi(struct bgp_evpn_nh *nh,
				     struct bgp_path_info *pi)
{
	if (nh->ref_pi != pi)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("evpn vrf %s nh %s ref_pi clear",
			   nh->bgp_vrf->name_pretty, nh->nh_str);
	nh->ref_pi = NULL;
	/* try to find another ref_pi */
	bgp_evpn_nh_update_ref_pi(nh);
	/* couldn't find one - clear the old rmac and notify zebra */
	if (!nh->ref_pi) {
		memset(&nh->rmac, 0, ETH_ALEN);
		bgp_evpn_nh_zebra_update(nh, true);
	}
}

static void bgp_evpn_path_nh_info_free(struct bgp_path_evpn_nh_info *nh_info)
{
	bgp_evpn_path_nh_unlink(nh_info);
	XFREE(MTYPE_BGP_EVPN_PATH_NH_INFO, nh_info);
}

static struct bgp_path_evpn_nh_info *
bgp_evpn_path_nh_info_new(struct bgp_path_info *pi)
{
	struct bgp_path_info_extra *e;
	struct bgp_path_mh_info *mh_info;
	struct bgp_path_evpn_nh_info *nh_info;

	e = bgp_path_info_extra_get(pi);

	/* If mh_info doesn't exist allocate it */
	mh_info = e->evpn->mh_info;
	if (!mh_info)
		e->evpn->mh_info = mh_info =
			XCALLOC(MTYPE_BGP_EVPN_PATH_MH_INFO,
				sizeof(struct bgp_path_mh_info));

	/* If nh_info doesn't exist allocate it */
	nh_info = mh_info->nh_info;
	if (!nh_info) {
		mh_info->nh_info = nh_info =
			XCALLOC(MTYPE_BGP_EVPN_PATH_NH_INFO,
				sizeof(struct bgp_path_evpn_nh_info));
		nh_info->pi = pi;
	}

	return nh_info;
}

static void bgp_evpn_path_nh_unlink(struct bgp_path_evpn_nh_info *nh_info)
{
	struct bgp_evpn_nh *nh = nh_info->nh;
	struct bgp_path_info *pi;
	char prefix_buf[PREFIX_STRLEN];

	if (!nh)
		return;

	pi = nh_info->pi;
	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("path %s unlinked from nh %s %s",
			   pi->net ? prefix2str(&pi->net->rn->p, prefix_buf,
						sizeof(prefix_buf))
				   : "",
			   nh->bgp_vrf->name_pretty, nh->nh_str);

	list_delete_node(nh->pi_list, &nh_info->nh_listnode);

	nh_info->nh = NULL;

	/* check if the ref_pi need to be updated */
	bgp_evpn_nh_clear_ref_pi(nh, pi);

	/* if there are no other references against the nh it
	 * needs to be freed
	 */
	bgp_evpn_nh_del(nh);

	/* Note we don't free the path nh_info on unlink; it will be freed up
	 * along with the path.
	 */
}

static void bgp_evpn_path_nh_link(struct bgp *bgp_vrf, struct bgp_path_info *pi)
{
	struct bgp_path_evpn_nh_info *nh_info;
	struct bgp_evpn_nh *nh;
	struct ipaddr ip;

	/* EVPN nexthop setup in bgp has been turned off */
	if (!bgp_mh_info->bgp_evpn_nh_setup)
		return;

	if (!bgp_vrf->evpn_nh_table) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug("path %pFX linked to vrf %s failed",
				   &pi->net->rn->p, bgp_vrf->name_pretty);
		return;
	}

	nh_info = (pi->extra && pi->extra->evpn && pi->extra->evpn->mh_info)
			  ? pi->extra->evpn->mh_info->nh_info
			  : NULL;

	/* if NHG is not being used for this path we don't need to manage the
	 * nexthops in bgp (they are managed by zebra instead)
	 */
	if (!(pi->attr->es_flags & ATTR_ES_L3_NHG_USE)) {
		if (nh_info)
			bgp_evpn_path_nh_unlink(nh_info);
		return;
	}

	/* setup nh_info against the path if it doesn't aleady exist */
	if (!nh_info)
		nh_info = bgp_evpn_path_nh_info_new(pi);

	/* find-create nh */
	memset(&ip, 0, sizeof(ip));
	if (pi->net->rn->p.family == AF_INET6) {
		SET_IPADDR_V6(&ip);
		memcpy(&ip.ipaddr_v6, &pi->attr->mp_nexthop_global,
		       sizeof(ip.ipaddr_v6));
	} else {
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &pi->attr->nexthop, sizeof(ip.ipaddr_v4));
	}

	nh = bgp_evpn_nh_find(bgp_vrf, &ip);
	if (!nh)
		nh = bgp_evpn_nh_add(bgp_vrf, &ip, pi);

	/* dup check */
	if (nh_info->nh == nh) {
		/* Check if any of the paths are now valid */
		bgp_evpn_nh_update_ref_pi(nh);
		return;
	}

	/* unlink old nh if any */
	bgp_evpn_path_nh_unlink(nh_info);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("path %pFX linked to nh %s %s", &pi->net->rn->p,
			   nh->bgp_vrf->name_pretty, nh->nh_str);

	/* link mac-ip path to the new nh */
	nh_info->nh = nh;
	listnode_init(&nh_info->nh_listnode, nh_info);
	listnode_add(nh->pi_list, &nh_info->nh_listnode);
	/* If a new valid path got linked to the nh see if can get the rmac
	 * from it
	 */
	bgp_evpn_nh_update_ref_pi(nh);
	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES)) {
		if (!nh->ref_pi)
			zlog_debug(
				"path %pFX linked to nh %s %s with no valid pi",
				&pi->net->rn->p, nh->bgp_vrf->name_pretty,
				nh->nh_str);
	}
}

void bgp_evpn_path_nh_del(struct bgp *bgp_vrf, struct bgp_path_info *pi)
{
	struct bgp_path_evpn_nh_info *nh_info;

	nh_info = (pi->extra && pi->extra->evpn && pi->extra->evpn->mh_info)
			  ? pi->extra->evpn->mh_info->nh_info
			  : NULL;

	if (!nh_info)
		return;

	bgp_evpn_path_nh_unlink(nh_info);
}

void bgp_evpn_path_nh_add(struct bgp *bgp_vrf, struct bgp_path_info *pi)
{
	bgp_evpn_path_nh_link(bgp_vrf, pi);
}

static void bgp_evpn_nh_show_entry(struct bgp_evpn_nh *nh, struct vty *vty,
				   json_object *json_array)
{
	json_object *json = NULL;
	char mac_buf[ETHER_ADDR_STRLEN];
	char prefix_buf[PREFIX_STRLEN];

	if (json_array)
		/* create a separate json object for each ES */
		json = json_object_new_object();

	prefix_mac2str(&nh->rmac, mac_buf, sizeof(mac_buf));
	if (nh->ref_pi && nh->ref_pi->net)
		prefix2str(&nh->ref_pi->net->rn->p, prefix_buf, sizeof(prefix_buf));
	else
		prefix_buf[0] = '\0';
	if (json) {
		json_object_string_add(json, "vrf", nh->bgp_vrf->name_pretty);
		json_object_string_add(json, "ip", nh->nh_str);
		json_object_string_add(json, "rmac", mac_buf);
		json_object_string_add(json, "basePath", prefix_buf);
		json_object_int_add(json, "pathCount", listcount(nh->pi_list));
	} else {
		vty_out(vty, "%-15s %-15s %-17s %-10d %s\n",
			nh->bgp_vrf->name_pretty, nh->nh_str, mac_buf,
			listcount(nh->pi_list), prefix_buf);
	}

	/* add ES to the json array */
	if (json_array)
		json_object_array_add(json_array, json);
}

struct nh_show_ctx {
	struct vty *vty;
	json_object *json;
};

static void bgp_evpn_nh_show_hash_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_evpn_nh *nh = (struct bgp_evpn_nh *)bucket->data;
	struct nh_show_ctx *wctx = (struct nh_show_ctx *)ctxt;

	bgp_evpn_nh_show_entry(nh, wctx->vty, wctx->json);
}

/* Display all evpn nexthops */
void bgp_evpn_nh_show(struct vty *vty, bool uj)
{
	json_object *json_array = NULL;
	struct bgp *bgp_vrf;
	struct listnode *node;
	struct nh_show_ctx wctx;

	if (uj) {
		/* create an array of nexthops */
		json_array = json_object_new_array();
	} else {
		vty_out(vty, "%-15s %-15s %-17s %-10s %s\n", "VRF", "IP",
			"RMAC", "#Paths", "Base Path");
	}

	wctx.vty = vty;
	wctx.json = json_array;

	/* walk through all vrfs */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		hash_iterate(bgp_vrf->evpn_nh_table,
			     (void (*)(struct hash_bucket *,
				       void *))bgp_evpn_nh_show_hash_cb,
			     &wctx);
	}

	/* print the array of json-ESs */
	if (uj)
		vty_json(vty, json_array);
}

/*****************************************************************************/
void bgp_evpn_mh_init(void)
{
	bm->mh_info = XCALLOC(MTYPE_BGP_EVPN_MH_INFO, sizeof(*bm->mh_info));

	/* setup ES tables */
	RB_INIT(bgp_es_rb_head, &bgp_mh_info->es_rb_tree);
	/* local ES list */
	bgp_mh_info->local_es_list = list_new();
	listset_app_node_mem(bgp_mh_info->local_es_list);
	/* list of ESs with pending processing */
	bgp_mh_info->pend_es_list = list_new();
	listset_app_node_mem(bgp_mh_info->pend_es_list);

	bgp_mh_info->ead_evi_rx = BGP_EVPN_MH_EAD_EVI_RX_DEF;
	bgp_mh_info->ead_evi_tx = BGP_EVPN_MH_EAD_EVI_TX_DEF;
	bgp_mh_info->ead_es_export_rtl = list_new();
	bgp_mh_info->ead_es_export_rtl->cmp =
		(int (*)(void *, void *))bgp_evpn_route_target_cmp;
	bgp_mh_info->ead_es_export_rtl->del = bgp_evpn_xxport_delete_ecomm;

	/* config knobs - XXX add cli to control it */
	bgp_mh_info->ead_evi_adv_for_down_links = true;
	bgp_mh_info->consistency_checking = true;
	bgp_mh_info->host_routes_use_l3nhg = BGP_EVPN_MH_USE_ES_L3NHG_DEF;
	bgp_mh_info->suppress_l3_ecomm_on_inactive_es = true;
	bgp_mh_info->bgp_evpn_nh_setup = true;
	bgp_mh_info->evi_per_es_frag = BGP_EVPN_MAX_EVI_PER_ES_FRAG;

	memset(&zero_esi_buf, 0, sizeof(esi_t));
}

void bgp_evpn_mh_finish(void)
{
	struct bgp_evpn_es *es;
	struct bgp_evpn_es *es_next;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("evpn mh finish");

	RB_FOREACH_SAFE (es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree,
			 es_next) {
		bgp_evpn_es_local_info_clear(es, true);
	}
	if (bgp_mh_info->t_cons_check)
		EVENT_OFF(bgp_mh_info->t_cons_check);
	list_delete(&bgp_mh_info->local_es_list);
	list_delete(&bgp_mh_info->pend_es_list);
	list_delete(&bgp_mh_info->ead_es_export_rtl);

	XFREE(MTYPE_BGP_EVPN_MH_INFO, bgp_mh_info);
}

/* This function is called when disable-ead-evi-rx knob flaps */
void bgp_evpn_switch_ead_evi_rx(void)
{
	struct bgp *bgp;
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;
	struct listnode *evi_node = NULL;
	struct listnode *evi_next = NULL;
	struct bgp_evpn_es_evi_vtep *vtep;
	struct listnode *vtep_node = NULL;
	struct listnode *vtep_next = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return;

	/*
	 * Process all the remote es_evi_vteps and reevaluate if the es_evi_vtep
	 * is active.
	 */
	RB_FOREACH(es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree) {
		if (!CHECK_FLAG(es->flags, BGP_EVPNES_REMOTE))
			continue;

		for (ALL_LIST_ELEMENTS(es->es_evi_list, evi_node, evi_next,
				       es_evi)) {
			if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_REMOTE))
				continue;

			for (ALL_LIST_ELEMENTS(es_evi->es_evi_vtep_list,
					       vtep_node, vtep_next, vtep))
				bgp_evpn_es_evi_vtep_re_eval_active(bgp, vtep);
		}
	}
}
