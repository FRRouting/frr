/* EVPN Multihoming procedures
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 *
 * This file is part of FRR.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
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
static void bgp_evpn_local_es_evi_do_del(struct bgp_evpn_es_evi *es_evi);
static uint32_t bgp_evpn_es_get_active_vtep_cnt(struct bgp_evpn_es *es);
static void bgp_evpn_l3nhg_update_on_vtep_chg(struct bgp_evpn_es *es);
static struct bgp_evpn_es *bgp_evpn_es_new(struct bgp *bgp, const esi_t *esi);
static void bgp_evpn_es_free(struct bgp_evpn_es *es, const char *caller);
static void bgp_evpn_es_path_all_update(struct bgp_evpn_es_vtep *es_vtep,
					bool active);

esi_t zero_esi_buf, *zero_esi = &zero_esi_buf;

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
		if (pi->extra
				&& (struct bgp_path_info *)pi->extra->parent ==
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
		pi->extra->parent = bgp_path_info_lock(parent_pi);
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
		pi->uptime = bgp_clock();
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
		if (pi->extra
				&& (struct bgp_path_info *)pi->extra->parent ==
				parent_pi)
			break;

	if (!pi)
		return 0;

	/* Mark entry for deletion */
	bgp_path_info_delete(dest, pi);

	/* Perform route selection and update zebra, if required. */
	ret = bgp_evpn_es_route_select_install(bgp, es, dest);

	/* Unlock route node. */
	bgp_dest_unlock_node(dest);

	return ret;
}

/* Install or unistall a Tyoe-4 route in the per-ES routing table */
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
			bgp_path_info_reap(dest, pi);
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
static int bgp_evpn_mh_route_update(struct bgp *bgp, struct bgp_evpn_es *es,
				    struct bgpevpn *vpn, afi_t afi, safi_t safi,
				    struct bgp_dest *dest, struct attr *attr,
				    int add, struct bgp_path_info **ri,
				    int *route_changed)
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

	/* we don't expect to see a remote_ri at this point as
	 * an ES route has {esi, vtep_ip} as the key in the ES-rt-table
	 * in the VNI-rt-table.
	 */
	if (remote_pi) {
		flog_err(
			EC_BGP_ES_INVALID,
			"%u ERROR: local es route for ESI: %s Vtep %pI4 also learnt from remote",
			bgp->vrf_id, es->esi_str, &es->originator_ip);
		return -1;
	}

	if (!local_pi && !add)
		return 0;

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
			tmp_pi->uptime = bgp_clock();
		}
	}

	if (*route_changed) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug(
				"local ES %s vni %u route-type %s nexthop %pI4 updated",
				es->esi_str, vpn ? vpn->vni : 0,
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
		struct bgpevpn *vpn, struct prefix_evpn *p)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *pi;
	struct bgp_dest *dest = NULL;	     /* dest in esi table */
	struct bgp_dest *global_dest = NULL; /* dest in global table */
	struct bgp_table *rt_table;
	struct prefix_rd *prd;

	if (vpn) {
		rt_table = vpn->route_table;
		prd = &vpn->prd;
	} else {
		rt_table = es->route_table;
		prd = &es->prd;
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
	global_dest =
		bgp_global_evpn_node_lookup(bgp->rib[afi][safi], afi, safi,
					    (const struct prefix_evpn *)p, prd);
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
		bgp_path_info_reap(dest, pi);
	bgp_dest_unlock_node(dest);
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
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* ES import RT */
	memset(&mac, 0, sizeof(struct ethaddr));
	memset(&ecom_es_rt, 0, sizeof(ecom_es_rt));
	es_get_system_mac(&es->esi, &mac);
	encode_es_rt_extcomm(&eval_es_rt, &mac);
	ecom_es_rt.size = 1;
	ecom_es_rt.unit_size = ECOMMUNITY_SIZE;
	ecom_es_rt.val = (uint8_t *)eval_es_rt.val;
	attr->ecommunity =
		ecommunity_merge(attr->ecommunity, &ecom_es_rt);

	/* DF election extended community */
	memset(&ecom_df, 0, sizeof(ecom_df));
	encode_df_elect_extcomm(&eval_df, es->df_pref);
	ecom_df.size = 1;
	ecom_df.val = (uint8_t *)eval_df.val;
	attr->ecommunity = ecommunity_merge(attr->ecommunity, &ecom_df);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
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

	memset(&attr, 0, sizeof(struct attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	attr.nexthop = es->originator_ip;
	attr.mp_nexthop_global_in = es->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	/* Set up extended community. */
	bgp_evpn_type4_route_extcomm_build(es, &attr);

	/* First, create (or fetch) route node within the ESI. */
	/* NOTE: There is no RD here. */
	dest = bgp_node_get(es->route_table, (struct prefix *)p);

	/* Create or update route entry. */
	ret = bgp_evpn_mh_route_update(bgp, es, NULL, afi, safi, dest, &attr, 1,
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

		dest = bgp_global_evpn_node_get(bgp->rib[afi][safi], afi, safi,
						p, &es->prd);
		bgp_evpn_mh_route_update(bgp, es, NULL, afi, safi, dest,
					 attr_new, 1, &global_pi,
					 &route_changed);

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
	return bgp_evpn_mh_route_delete(bgp, es, NULL /* l2vni */, p);
}

/* Process remote/received EVPN type-4 route (advertise or withdraw)  */
int bgp_evpn_type4_route_process(struct peer *peer, afi_t afi, safi_t safi,
		struct attr *attr, uint8_t *pfx, int psize,
		uint32_t addpath_id)
{
	int ret;
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
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				&prd, NULL, 0, 0, NULL);
	} else {
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				&prd, NULL, 0, NULL);
	}
	return ret;
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
static void bgp_evpn_type1_es_route_extcomm_build(struct bgp_evpn_es *es,
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
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* ESI label */
	encode_esi_label_extcomm(&eval_esi_label,
			false /*single_active*/);
	ecom_esi_label.size = 1;
	ecom_esi_label.unit_size = ECOMMUNITY_SIZE;
	ecom_esi_label.val = (uint8_t *)eval_esi_label.val;
	attr->ecommunity =
		ecommunity_merge(attr->ecommunity, &ecom_esi_label);

	/* Add export RTs for all L2-VNIs associated with this ES */
	/* XXX - suppress EAD-ES advertisment if there are no EVIs associated
	 * with it.
	 */
	for (ALL_LIST_ELEMENTS_RO(es->es_evi_list,
				evi_node, es_evi)) {
		if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
			continue;
		for (ALL_LIST_ELEMENTS_RO(es_evi->vpn->export_rtl,
					rt_node, ecom))
			attr->ecommunity = ecommunity_merge(attr->ecommunity,
					ecom);
	}

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
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
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* Add export RTs for the L2-VNI */
	for (ALL_LIST_ELEMENTS_RO(vpn->export_rtl, rt_node, ecom))
		attr->ecommunity = ecommunity_merge(attr->ecommunity, ecom);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
}

/* Update EVPN EAD (type-1) route -
 * vpn - valid for EAD-EVI routes and NULL for EAD-ES routes
 */
static int bgp_evpn_type1_route_update(struct bgp *bgp,
		struct bgp_evpn_es *es, struct bgpevpn *vpn,
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

	memset(&attr, 0, sizeof(struct attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
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
		dest = bgp_node_get(vpn->route_table, (struct prefix *)p);

		/* Create or update route entry. */
		ret = bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					       &attr, 1, &pi, &route_changed);
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
		bgp_evpn_type1_es_route_extcomm_build(es, &attr);

		/* First, create (or fetch) route node within the ES. */
		/* NOTE: There is no RD here. */
		/* XXX: fragment ID must be included as a part of the prefix. */
		dest = bgp_node_get(es->route_table, (struct prefix *)p);

		/* Create or update route entry. */
		ret = bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					       &attr, 1, &pi, &route_changed);
		if (ret != 0) {
			flog_err(
				EC_BGP_ES_INVALID,
				"%u ERROR: Failed to updated EAD-EVI route ESI: %s VTEP %pI4",
				bgp->vrf_id, es->esi_str, &es->originator_ip);
		}
		global_rd = &es->prd;
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

		dest = bgp_global_evpn_node_get(bgp->rib[afi][safi], afi, safi,
						p, global_rd);
		bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, dest,
					 attr_new, 1, &global_pi,
					 &route_changed);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, dest, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
	return 0;
}

/* Delete local Type-1 route */
static int bgp_evpn_type1_es_route_delete(struct bgp *bgp,
		struct bgp_evpn_es *es, struct prefix_evpn *p)
{
	return bgp_evpn_mh_route_delete(bgp, es, NULL /* l2vni */, p);
}

static int bgp_evpn_type1_evi_route_delete(struct bgp *bgp,
		struct bgp_evpn_es *es, struct bgpevpn *vpn,
		struct prefix_evpn *p)
{
	return bgp_evpn_mh_route_delete(bgp, es, vpn, p);
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
		if (bgp_evpn_type1_route_update(bgp, es, es_evi->vpn, &p))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
					"%u: Type4 route creation failure for ESI %s",
					bgp->vrf_id, es->esi_str);
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
		if (bgp_evpn_mh_route_delete(bgp, es, es_evi->vpn, &p))
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
	int ret;
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
	vtep_ip.s_addr = 0;
	build_evpn_type1_prefix(&p, eth_tag, &esi, vtep_ip);
	/* Process the route. */
	if (attr) {
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				&prd, NULL, 0, 0, NULL);
	} else {
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				&prd, NULL, 0, NULL);
	}
	return ret;
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

	return zclient_send_message(zclient);
}

static void bgp_evpn_es_vtep_re_eval_active(struct bgp *bgp,
					    struct bgp_evpn_es_vtep *es_vtep,
					    bool param_change)
{
	bool old_active;
	bool new_active;

	old_active = !!CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);
	/* currently we need an active EVI reference to use the VTEP as
	 * a nexthop. this may change...
	 */
	if (es_vtep->evi_cnt)
		SET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);
	else
		UNSET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);

	new_active = !!CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE);

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
		bgp_evpn_es_path_all_update(es_vtep, new_active);

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

bool bgp_evpn_es_is_vtep_active(esi_t *esi, struct in_addr nh)
{
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_vtep *es_vtep;
	struct listnode *node = NULL;
	bool rc = false;

	if (!memcmp(esi, zero_esi, sizeof(*esi)) || !nh.s_addr)
		return true;

	es = bgp_evpn_es_find(esi);
	if (!es)
		return false;

	for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node, es_vtep)) {
		if (es_vtep->vtep_ip.s_addr == nh.s_addr) {
			if (CHECK_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ACTIVE))
				rc = true;
			break;
		}
	}
	return rc;
}

/********************** ES MAC-IP paths *************************************
 * MAC-IP routes in the VNI routing table are linked to the destination
 * ES for efficient updates on ES changes (such as VTEP add/del).
 ****************************************************************************/
void bgp_evpn_path_es_info_free(struct bgp_path_es_info *es_info)
{
	bgp_evpn_path_es_unlink(es_info);
	XFREE(MTYPE_BGP_EVPN_PATH_ES_INFO, es_info);
}

static struct bgp_path_es_info *
bgp_evpn_path_es_info_new(struct bgp_path_info *pi, vni_t vni)
{
	struct bgp_path_info_extra *e;

	e = bgp_path_info_extra_get(pi);

	/* If es_info doesn't exist allocate it */
	if (!e->es_info) {
		e->es_info = XCALLOC(MTYPE_BGP_EVPN_PATH_ES_INFO,
				     sizeof(struct bgp_path_es_info));
		e->es_info->pi = pi;
		e->es_info->vni = vni;
	}

	return e->es_info;
}

void bgp_evpn_path_es_unlink(struct bgp_path_es_info *es_info)
{
	struct bgp_evpn_es *es = es_info->es;
	struct bgp_path_info *pi;

	if (!es)
		return;

	pi = es_info->pi;
	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("vni %u path %pFX unlinked from es %s", es_info->vni,
			   &pi->net->p, es->esi_str);

	list_delete_node(es->macip_path_list, &es_info->es_listnode);
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
	struct bgp *bgp_evpn = bgp_get_evpn();

	es_info = pi->extra ? pi->extra->es_info : NULL;
	/* if the esi is zero just unlink the path from the old es */
	if (!esi || !memcmp(esi, zero_esi, sizeof(*esi))) {
		if (es_info)
			bgp_evpn_path_es_unlink(es_info);
		return;
	}

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
		zlog_debug("vni %u path %pFX linked to es %s", vni, &pi->net->p,
			   es->esi_str);

	/* link mac-ip path to the new destination ES */
	es_info->es = es;
	listnode_init(&es_info->es_listnode, es_info);
	listnode_add(es->macip_path_list, &es_info->es_listnode);
}

static void bgp_evpn_es_path_all_update(struct bgp_evpn_es_vtep *es_vtep,
					bool active)
{
	struct listnode *node;
	struct bgp_path_es_info *es_info;
	struct bgp_path_info *pi;
	struct bgp_path_info *parent_pi;
	struct bgp_evpn_es *es = es_vtep->es;
	char prefix_buf[PREFIX_STRLEN];

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		zlog_debug("update all paths linked to es %s", es->esi_str);

	for (ALL_LIST_ELEMENTS_RO(es->macip_path_list, node, es_info)) {
		pi = es_info->pi;
		if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID))
			continue;

		if (pi->sub_type != BGP_ROUTE_IMPORTED)
			continue;

		parent_pi = pi->extra ? pi->extra->parent : NULL;
		if (!parent_pi || !parent_pi->attr)
			continue;

		if (es_vtep->vtep_ip.s_addr != parent_pi->attr->nexthop.s_addr)
			continue;

		if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
			zlog_debug("update path %s linked to es %s",
				   prefix2str(&parent_pi->net->p, prefix_buf,
					      sizeof(prefix_buf)),
				   es->esi_str);
		bgp_evpn_import_route_in_vrfs(parent_pi, active ? 1 : 0);
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

	if (!bgp)
		return NULL;

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
	if (RB_INSERT(bgp_es_rb_head, &bgp_mh_info->es_rb_tree, es)) {
		XFREE(MTYPE_BGP_EVPN_ES, es);
		return NULL;
	}

	/* Initialise the ES-EVI list */
	es->es_evi_list = list_new();
	listset_app_node_mem(es->es_evi_list);

	/* Initialise the ES-VRF list used for L3NHG management */
	es->es_vrf_list = list_new();
	listset_app_node_mem(es->es_vrf_list);

	/* Initialise the route list used for efficient event handling */
	es->macip_path_list = list_new();
	listset_app_node_mem(es->macip_path_list);

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
	    || listcount(es->macip_path_list))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("%s: es %s free", caller, es->esi_str);

	/* cleanup resources maintained against the ES */
	list_delete(&es->es_evi_list);
	list_delete(&es->es_vrf_list);
	list_delete(&es->es_vtep_list);
	list_delete(&es->macip_path_list);
	bgp_table_unlock(es->route_table);

	/* remove the entry from various databases */
	RB_REMOVE(bgp_es_rb_head, &bgp_mh_info->es_rb_tree, es);
	bgp_evpn_es_cons_checks_pend_del(es);

	QOBJ_UNREG(es);
	XFREE(MTYPE_BGP_EVPN_ES, es);
}

/* init local info associated with the ES */
static void bgp_evpn_es_local_info_set(struct bgp *bgp, struct bgp_evpn_es *es)
{
	char buf[BGP_EVPN_PREFIX_RD_LEN];

	if (CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
		return;

	SET_FLAG(es->flags, BGP_EVPNES_LOCAL);
	listnode_init(&es->es_listnode, es);
	listnode_add(bgp_mh_info->local_es_list, &es->es_listnode);

	/* auto derive RD for this es */
	bf_assign_index(bm->rd_idspace, es->rd_id);
	es->prd.family = AF_UNSPEC;
	es->prd.prefixlen = 64;
	snprintfrr(buf, sizeof(buf), "%pI4:%hu", &bgp->router_id, es->rd_id);
	(void)str2prefix_rd(buf, &es->prd);
}

/* clear any local info associated with the ES */
static void bgp_evpn_es_local_info_clear(struct bgp_evpn_es *es)
{
	if (!CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
		return;

	UNSET_FLAG(es->flags, BGP_EVPNES_LOCAL);

	/* remove from the ES local list */
	list_delete_node(bgp_mh_info->local_es_list, &es->es_listnode);

	bf_release_index(bm->rd_idspace, es->rd_id);

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

/* Process ES link oper-down by withdrawing ES-EAD and ESR */
static void bgp_evpn_local_es_down(struct bgp *bgp,
		struct bgp_evpn_es *es)
{
	struct prefix_evpn p;
	int ret;

	if (!CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP))
		return;

	UNSET_FLAG(es->flags, BGP_EVPNES_OPER_UP);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("local es %s down", es->esi_str);

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
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG,
			&es->esi, es->originator_ip);
	ret = bgp_evpn_type1_es_route_delete(bgp, es, &p);
	if (ret) {
		flog_err(EC_BGP_EVPN_ROUTE_DELETE,
				"%u failed to delete type-1 route for ESI %s",
				bgp->vrf_id, es->esi_str);
	}
}

/* Process ES link oper-up by generating ES-EAD and ESR */
static void bgp_evpn_local_es_up(struct bgp *bgp, struct bgp_evpn_es *es,
				 bool regen_esr)
{
	struct prefix_evpn p;
	bool regen_ead = false;

	if (!CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP)) {
		if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
			zlog_debug("local es %s up", es->esi_str);

		SET_FLAG(es->flags, BGP_EVPNES_OPER_UP);
		regen_esr = true;
		regen_ead = true;
	}

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
		build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG, &es->esi,
					es->originator_ip);
		bgp_evpn_type1_route_update(bgp, es, NULL, &p);
	}
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
	bgp_evpn_es_local_info_clear(es);
}

bool bgp_evpn_is_esi_local(esi_t *esi)
{
	struct bgp_evpn_es *es = NULL;

	/* Lookup ESI hash - should exist. */
	es = bgp_evpn_es_find(esi);
	return es ? !!(es->flags & BGP_EVPNES_LOCAL) : false;
}

int bgp_evpn_local_es_del(struct bgp *bgp, esi_t *esi)
{
	struct bgp_evpn_es *es = NULL;

	/* Lookup ESI hash - should exist. */
	es = bgp_evpn_es_find(esi);
	if (!es) {
		flog_warn(EC_BGP_EVPN_ESI,
			  "%u: ES %s missing at local ES DEL",
			  bgp->vrf_id, es->esi_str);
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
			  uint16_t df_pref)
{
	char buf[ESI_STR_LEN];
	struct bgp_evpn_es *es;
	bool new_es = true;
	bool regen_esr = false;

	/* create the new es */
	es = bgp_evpn_es_find(esi);
	if (es) {
		if (CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL))
			new_es = false;
	} else {
		es = bgp_evpn_es_new(bgp, esi);
		if (!es) {
			flog_err(EC_BGP_ES_CREATE,
				"%u: Failed to allocate ES entry for ESI %s - at Local ES Add",
				bgp->vrf_id, esi_to_str(esi, buf, sizeof(buf)));
			return -1;
		}
	}

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("add local es %s orig-ip %pI4 df_pref %u", es->esi_str,
			   &originator_ip, df_pref);

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

	/* If the ES link is operationally up generate EAD-ES. EAD-EVI
	 * can be generated even if the link is inactive.
	 */
	if (oper_up)
		bgp_evpn_local_es_up(bgp, es, regen_esr);
	else
		bgp_evpn_local_es_down(bgp, es);

	return 0;
}

static char *bgp_evpn_es_vteps_str(char *vtep_str, struct bgp_evpn_es *es,
				   uint8_t vtep_str_size)
{
	char vtep_flag_str[BGP_EVPN_FLAG_STR_SZ];
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;
	bool first = true;
	char ip_buf[INET6_ADDRSTRLEN];

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
	char ip_buf[INET6_ADDRSTRLEN];

	json_vtep_entry = json_object_new_object();

	json_object_string_add(
		json_vtep_entry, "vtep_ip",
		inet_ntop(AF_INET, &es_vtep->vtep_ip, ip_buf, sizeof(ip_buf)));
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
			json_object_int_add(json_vtep_entry, "dfAlgorithm",
					    es_vtep->df_pref);
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
	char buf1[RD_ADDRSTRLEN];
	struct listnode *node;
	struct bgp_evpn_es_vtep *es_vtep;

	if (json) {
		json_object *json_vteps;
		json_object *json_types;

		json_object_string_add(json, "esi", es->esi_str);
		json_object_string_add(json, "rd",
				prefix_rd2str(&es->prd, buf1,
					sizeof(buf1)));

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
		if (es->flags & BGP_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & BGP_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));
		if (es->inconsistencies)
			strlcat(type_str, "I", sizeof(type_str));

		bgp_evpn_es_vteps_str(vtep_str, es, sizeof(vtep_str));

		if (es->flags & BGP_EVPNES_LOCAL)
			prefix_rd2str(&es->prd, buf1, sizeof(buf1));
		else
			strlcpy(buf1, "-", sizeof(buf1));

		vty_out(vty, "%-30s %-5s %-21s %-8d %s\n",
				es->esi_str, type_str, buf1,
				listcount(es->es_evi_list), vtep_str);
	}
}

static void bgp_evpn_es_show_entry_detail(struct vty *vty,
		struct bgp_evpn_es *es, json_object *json)
{
	char ip_buf[INET6_ADDRSTRLEN];

	if (json) {
		json_object *json_flags;
		json_object *json_incons;
		json_object *json_vteps;
		struct listnode *node;
		struct bgp_evpn_es_vtep *es_vtep;

		/* Add the "brief" info first */
		bgp_evpn_es_show_entry(vty, es, json);
		if (es->flags & (BGP_EVPNES_OPER_UP | BGP_EVPNES_ADV_EVI)) {
			json_flags = json_object_new_array();
			if (es->flags & BGP_EVPNES_OPER_UP)
				json_array_string_add(json_flags, "up");
			if (es->flags & BGP_EVPNES_ADV_EVI)
				json_array_string_add(json_flags,
						"advertiseEVI");
			json_object_object_add(json, "flags", json_flags);
		}
		json_object_string_add(json, "originator_ip",
				       inet_ntop(AF_INET, &es->originator_ip,
						 ip_buf, sizeof(ip_buf)));
		json_object_int_add(json, "remoteVniCount",
				es->remote_es_evi_cnt);
		json_object_int_add(json, "vrfCount",
				    listcount(es->es_vrf_list));
		json_object_int_add(json, "macipPathCount",
				    listcount(es->macip_path_list));
		json_object_int_add(json, "inconsistentVniVtepCount",
				es->incons_evi_vtep_cnt);
		if (listcount(es->es_vtep_list)) {
			json_vteps = json_object_new_array();
			for (ALL_LIST_ELEMENTS_RO(es->es_vtep_list, node,
						  es_vtep)) {
				bgp_evpn_es_json_vtep_fill(json_vteps, es_vtep);
			}
			json_object_object_add(json, "vteps", json_vteps);
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
		char buf1[RD_ADDRSTRLEN];

		type_str[0] = '\0';
		if (es->flags & BGP_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & BGP_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));

		if (es->flags & BGP_EVPNES_LOCAL)
			prefix_rd2str(&es->prd, buf1, sizeof(buf1));
		else
			strlcpy(buf1, "-", sizeof(buf1));

		vty_out(vty, "ESI: %s\n", es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " RD: %s\n", buf1);
		vty_out(vty, " Originator-IP: %pI4\n", &es->originator_ip);
		if (es->flags & BGP_EVPNES_LOCAL)
			vty_out(vty, " Local ES DF preference: %u\n",
				es->df_pref);
		vty_out(vty, " VNI Count: %d\n", listcount(es->es_evi_list));
		vty_out(vty, " Remote VNI Count: %d\n",
				es->remote_es_evi_cnt);
		vty_out(vty, " VRF Count: %d\n", listcount(es->es_vrf_list));
		vty_out(vty, " MACIP Path Count: %d\n",
			listcount(es->macip_path_list));
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
				"ES Flags: L local, R remote, I inconsistent\n");
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
	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					json_array, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_array);
	}
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

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
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
	}

	if (!api_nhg.nexthop_num)
		return;

	if (api_nhg.nexthop_num > MULTIPATH_NUM)
		return;

	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

static bool bgp_evpn_l3nhg_zebra_ok(struct bgp_evpn_es_vrf *es_vrf)
{
	if (!bgp_mh_info->host_routes_use_l3nhg && !bgp_mh_info->install_l3nhg)
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
	if (RB_INSERT(bgp_es_vrf_rb_head, &bgp_vrf->es_vrf_rb_tree, es_vrf)) {
		XFREE(MTYPE_BGP_EVPN_ES_VRF, es_vrf);
		return NULL;
	}

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
	if (!es_vrf)
		return;

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

/* returns false if legacy-exploded mp needs to be used for route install */
bool bgp_evpn_path_es_use_nhg(struct bgp *bgp_vrf, struct bgp_path_info *pi,
			      uint32_t *nhg_p)
{
	esi_t *esi;
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_vrf *es_vrf;
	struct bgp_path_info *parent_pi;
	struct bgp_node *rn;
	struct prefix_evpn *evp;
	struct bgp_path_info *mpinfo;

	*nhg_p = 0;

	/* L3NHG support is disabled, use legacy-exploded multipath */
	if (!bgp_mh_info->host_routes_use_l3nhg)
		return false;

	parent_pi = get_route_parent_evpn(pi);
	if (!parent_pi)
		return false;

	rn = parent_pi->net;
	if (!rn)
		return false;

	evp = (struct prefix_evpn *)&rn->p;
	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return false;

	/* non-es path, use legacy-exploded multipath */
	esi = bgp_evpn_attr_get_esi(parent_pi->attr);
	if (!memcmp(esi, zero_esi, sizeof(*esi)))
		return false;

	/* if the ES-VRF is not setup or if the NHG has not been installed
	 * we cannot install the route yet, return a 0-NHG to indicate
	 * that
	 */
	es = bgp_evpn_es_find(esi);
	if (!es)
		return true;
	es_vrf = bgp_evpn_es_vrf_find(es, bgp_vrf);
	if (!es_vrf || !(es_vrf->flags & BGP_EVPNES_VRF_NHG_ACTIVE))
		return true;

	/* this needs to be set the v6NHG if v6route */
	if (is_evpn_prefix_ipaddr_v6(evp))
		*nhg_p = es_vrf->v6_nhg_id;
	else
		*nhg_p = es_vrf->nhg_id;

	for (mpinfo = bgp_path_info_mpath_next(pi); mpinfo;
	     mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		/* if any of the paths of have a different ESI we can't use
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
		json_object_string_add(json, "vrf", bgp_vrf->name);

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
			bgp_vrf->name, flags_str, es_vrf->nhg_id,
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
	if (uj) {
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json_array, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_array);
	}
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

	old_active = !!CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

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

	new_active = !!CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

	if (old_active == new_active)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s evi %u vtep %pI4 %s",
			   evi_vtep->es_evi->es->esi_str,
			   evi_vtep->es_evi->vpn->vni, &evi_vtep->vtep_ip,
			   new_active ? "active" : "inactive");

	/* add VTEP to parent es */
	if (new_active) {
		struct bgp_evpn_es_vtep *es_vtep;

		es_vtep = bgp_evpn_es_vtep_add(bgp, evi_vtep->es_evi->es,
					       evi_vtep->vtep_ip, false /*esr*/,
					       0, 0);
		evi_vtep->es_vtep = es_vtep;
	} else {
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
	if (RB_INSERT(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree, es_evi)) {
		XFREE(MTYPE_BGP_EVPN_ES_EVI, es_evi);
		return NULL;
	}

	/* add to the ES's VNI list */
	listnode_init(&es_evi->es_listnode, es_evi);
	listnode_add(es->es_evi_list, &es_evi->es_listnode);

	bgp_evpn_es_vrf_ref(es_evi, vpn->bgp_vrf);

	return es_evi;
}

/* remove the ES-EVI from the per-L2-VNI and per-ES tables and free
 * up the memory.
 */
static void bgp_evpn_es_evi_free(struct bgp_evpn_es_evi *es_evi)
{
	struct bgp_evpn_es *es = es_evi->es;
	struct bgpevpn *vpn = es_evi->vpn;

	/* cannot free the element as long as there is a local or remote
	 * reference
	 */
	if (es_evi->flags & (BGP_EVPNES_EVI_LOCAL | BGP_EVPNES_EVI_REMOTE))
		return;

	bgp_evpn_es_vrf_deref(es_evi);

	/* remove from the ES's VNI list */
	list_delete_node(es->es_evi_list, &es_evi->es_listnode);

	/* remove from the VNI-ESI rb tree */
	RB_REMOVE(bgp_es_evi_rb_head, &vpn->es_evi_rb_tree, es_evi);

	/* free the VTEP list */
	list_delete(&es_evi->es_evi_vtep_list);

	/* remove from the VNI-ESI rb tree */
	XFREE(MTYPE_BGP_EVPN_ES_EVI, es_evi);
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
}

/* clear any local info associated with the ES-EVI */
static void bgp_evpn_es_evi_local_info_clear(struct bgp_evpn_es_evi *es_evi)
{
	struct bgpevpn *vpn = es_evi->vpn;

	if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
		return;

	UNSET_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL);
	list_delete_node(vpn->local_es_evi_list, &es_evi->l2vni_listnode);

	bgp_evpn_es_evi_free(es_evi);
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

static void bgp_evpn_local_es_evi_do_del(struct bgp_evpn_es_evi *es_evi)
{
	struct prefix_evpn p;
	struct bgp_evpn_es *es = es_evi->es;
	struct bgp *bgp;

	if (!CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("del local es %s evi %u",
				es_evi->es->esi_str,
				es_evi->vpn->vni);

	bgp = bgp_get_evpn();

	if (bgp) {
		/* update EAD-ES with new list of VNIs */
		if (CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP)) {
			build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG,
					&es->esi, es->originator_ip);
			if (bgp_evpn_type1_route_update(bgp, es, NULL, &p))
				flog_err(EC_BGP_EVPN_ROUTE_CREATE,
					"%u: EAD-ES route update failure for ESI %s VNI %u",
					bgp->vrf_id, es->esi_str,
					es_evi->vpn->vni);
		}

		/* withdraw and delete EAD-EVI */
		if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
			build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
					&es->esi, es->originator_ip);
			if (bgp_evpn_type1_evi_route_delete(bgp,
						es, es_evi->vpn, &p))
				flog_err(EC_BGP_EVPN_ROUTE_DELETE,
					"%u: EAD-EVI route deletion failure for ESI %s VNI %u",
					bgp->vrf_id, es->esi_str,
					es_evi->vpn->vni);
		}
	}

	bgp_evpn_es_evi_local_info_clear(es_evi);

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
	} else {
		es_evi = bgp_evpn_es_evi_new(es, vpn);
		if (!es_evi)
			return -1;
	}

	bgp_evpn_es_evi_local_info_set(es_evi);

	/* generate an EAD-EVI for this new VNI */
	if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
		build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG, &es->esi,
					es->originator_ip);
		if (bgp_evpn_type1_route_update(bgp, es, vpn, &p))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
					"%u: EAD-EVI route creation failure for ESI %s VNI %u",
					bgp->vrf_id, es->esi_str, vni);
	}

	/* update EAD-ES */
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG,
			&es->esi, es->originator_ip);
	if (CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP)) {
		if (bgp_evpn_type1_route_update(bgp, es, NULL, &p))
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
					"%u: EAD-ES route creation failure for ESI %s VNI %u",
					bgp->vrf_id, es->esi_str, vni);
	}

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
	if (!es) {
		es = bgp_evpn_es_new(bgp, esi);
		if (!es) {
			flog_err(EC_BGP_ES_CREATE,
				"%u: Failed to allocate ES entry for ESI %s - at remote ES Add",
				bgp->vrf_id, esi_to_str(esi, buf, sizeof(buf)));
			return -1;
		}
	}

	es_evi = bgp_evpn_es_evi_find(es, vpn);
	if (!es_evi) {
		es_evi = bgp_evpn_es_evi_new(es, vpn);
		if (!es_evi) {
			bgp_evpn_es_free(es, __func__);
			return -1;
		}
	}

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
	if (!es)
		/* XXX - error logs */
		return 0;
	es_evi = bgp_evpn_es_evi_find(es, vpn);
	if (!es_evi)
		/* XXX - error logs */
		return 0;

	ead_es = !!p->prefix.ead_addr.eth_tag;
	bgp_evpn_es_evi_vtep_del(bgp, es_evi, p->prefix.ead_addr.ip.ipaddr_v4,
			ead_es);
	bgp_evpn_es_evi_remote_info_re_eval(es_evi);
	return 0;
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
		bgp_evpn_local_es_evi_do_del(es_evi);
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
	char ip_buf[INET6_ADDRSTRLEN];

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
	char ip_buf[INET6_ADDRSTRLEN];

	json_vtep_entry = json_object_new_object();

	json_object_string_add(
		json_vtep_entry, "vtep_ip",
		inet_ntop(AF_INET, &evi_vtep->vtep_ip, ip_buf, sizeof(ip_buf)));
	if (evi_vtep->flags & (BGP_EVPN_EVI_VTEP_EAD_PER_ES |
			 BGP_EVPN_EVI_VTEP_EAD_PER_EVI)) {
		json_flags = json_object_new_array();
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_ES)
			json_array_string_add(json_flags, "ead-per-es");
		if (evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD_PER_EVI)
			json_array_string_add(json_flags, "ed-per-evi");
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
	if (json) {
		json_object *json_flags;

		/* Add the "brief" info first */
		bgp_evpn_es_evi_show_entry(vty, es_evi, json);
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
	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					json_array, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_array);
	}
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

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					json_array, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_array);
	}
}

/*****************************************************************************
 * Ethernet Segment Consistency checks
 *     Consistency checking is done to detect misconfig or mis-cabling. When
 * an inconsistency is detected it is simply logged (and displayed via
 * show commands) at this point. A more drastic action can be executed (based
 * on user config) in the future.
 */
/* queue up the es for background consistency checks */
static void bgp_evpn_es_cons_checks_pend_add(struct bgp_evpn_es *es)
{
	if (!bgp_mh_info->consistency_checking)
		/* consistency checking is not enabled */
		return;

	if (CHECK_FLAG(es->flags, BGP_EVPNES_CONS_CHECK_PEND))
		/* already queued for consistency checking */
		return;

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

static int bgp_evpn_run_consistency_checks(struct thread *t)
{
	int proc_cnt = 0;
	int es_cnt = 0;
	struct listnode *node;
	struct listnode *nextnode;
	struct bgp_evpn_es *es;

	for (ALL_LIST_ELEMENTS(bgp_mh_info->pend_es_list,
				node, nextnode, es)) {
		++es_cnt;
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
	thread_add_timer(bm->master, bgp_evpn_run_consistency_checks, NULL,
			BGP_EVPN_CONS_CHECK_INTERVAL,
			&bgp_mh_info->t_cons_check);

	return 0;
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

	/* config knobs - XXX add cli to control it */
	bgp_mh_info->ead_evi_adv_for_down_links = true;
	bgp_mh_info->consistency_checking = true;
	bgp_mh_info->install_l3nhg = false;
	bgp_mh_info->host_routes_use_l3nhg = BGP_EVPN_MH_USE_ES_L3NHG_DEF;

	if (bgp_mh_info->consistency_checking)
		thread_add_timer(bm->master, bgp_evpn_run_consistency_checks,
				NULL, BGP_EVPN_CONS_CHECK_INTERVAL,
				&bgp_mh_info->t_cons_check);

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
		bgp_evpn_es_local_info_clear(es);
	}
	thread_cancel(&bgp_mh_info->t_cons_check);
	list_delete(&bgp_mh_info->local_es_list);
	list_delete(&bgp_mh_info->pend_es_list);

	XFREE(MTYPE_BGP_EVPN_MH_INFO, bgp_mh_info);
}
