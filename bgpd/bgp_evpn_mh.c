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

static void bgp_evpn_local_es_down(struct bgp *bgp,
		struct bgp_evpn_es *es);
static void bgp_evpn_local_type1_evi_route_del(struct bgp *bgp,
		struct bgp_evpn_es *es);
static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_add(struct bgp *bgp,
		struct bgp_evpn_es *es, struct in_addr vtep_ip, bool esr);
static void bgp_evpn_es_vtep_del(struct bgp *bgp,
		struct bgp_evpn_es *es, struct in_addr vtep_ip, bool esr);
static void bgp_evpn_es_cons_checks_pend_add(struct bgp_evpn_es *es);
static void bgp_evpn_es_cons_checks_pend_del(struct bgp_evpn_es *es);
static void bgp_evpn_local_es_evi_do_del(struct bgp_evpn_es_evi *es_evi);

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
			bgp_evpn_es_vtep_add(bgp, es,
					old_select->attr->nexthop,
					true /*esr*/);
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
		bgp_evpn_es_vtep_add(bgp, es,
				new_select->attr->nexthop, true /*esr */);
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
 * ESRs are used for BUM handling. XXX - BUM support is planned for phase-2 i.e.
 * this code is just a place holder for now
 */
/* Build extended community for EVPN ES (type-4) route */
static void bgp_evpn_type4_route_extcomm_build(struct bgp_evpn_es *es,
		struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_es_rt;
	struct ecommunity_val eval;
	struct ecommunity_val eval_es_rt;
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
	if (ret != 0) {
		flog_err(
			EC_BGP_ES_INVALID,
			"%u ERROR: Failed to updated ES route ESI: %s VTEP %pI4",
			bgp->vrf_id, es->esi_str, &es->originator_ip);
	}

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
		if (ret != 0) {
			flog_err(
				EC_BGP_ES_INVALID,
				"%u Failed to update EAD-EVI route ESI: %s VNI %u VTEP %pI4",
				bgp->vrf_id, es->esi_str, vpn->vni,
				&es->originator_ip);
		}
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

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
		add ? ZEBRA_REMOTE_ES_VTEP_ADD : ZEBRA_REMOTE_ES_VTEP_DEL,
		bgp->vrf_id);
	stream_put(s, &es->esi, sizeof(esi_t));
	stream_put_ipv4(s, es_vtep->vtep_ip.s_addr);

	stream_putw_at(s, 0, stream_get_endp(s));

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("Tx %s Remote ESI %s VTEP %pI4", add ? "ADD" : "DEL",
			   es->esi_str, &es_vtep->vtep_ip);

	return zclient_send_message(zclient);
}

static void bgp_evpn_es_vtep_re_eval_active(struct bgp *bgp,
		struct bgp_evpn_es_vtep *es_vtep)
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

	if (old_active == new_active)
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vtep %pI4 %s", es_vtep->es->esi_str,
			   &es_vtep->vtep_ip,
			   new_active ? "active" : "inactive");

	/* send remote ES to zebra */
	bgp_zebra_send_remote_es_vtep(bgp, es_vtep, new_active);

	/* queue up the es for background consistency checks */
	bgp_evpn_es_cons_checks_pend_add(es_vtep->es);
}

static struct bgp_evpn_es_vtep *bgp_evpn_es_vtep_add(struct bgp *bgp,
		struct bgp_evpn_es *es, struct in_addr vtep_ip, bool esr)
{
	struct bgp_evpn_es_vtep *es_vtep;

	es_vtep = bgp_evpn_es_vtep_find(es, vtep_ip);

	if (!es_vtep)
		es_vtep = bgp_evpn_es_vtep_new(es, vtep_ip);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vtep %pI4 add %s", es_vtep->es->esi_str,
			   &es_vtep->vtep_ip, esr ? "esr" : "ead");

	if (esr)
		SET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ESR);
	else
		++es_vtep->evi_cnt;

	bgp_evpn_es_vtep_re_eval_active(bgp, es_vtep);

	return es_vtep;
}

static void bgp_evpn_es_vtep_do_del(struct bgp *bgp,
		struct bgp_evpn_es_vtep *es_vtep, bool esr)
{
	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("es %s vtep %pI4 del %s", es_vtep->es->esi_str,
			   &es_vtep->vtep_ip, esr ? "esr" : "ead");
	if (esr) {
		UNSET_FLAG(es_vtep->flags, BGP_EVPNES_VTEP_ESR);
	} else {
		if (es_vtep->evi_cnt)
			--es_vtep->evi_cnt;
	}

	bgp_evpn_es_vtep_re_eval_active(bgp, es_vtep);
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

	QOBJ_REG(es, bgp_evpn_es);

	return es;
}

/* Free a given ES -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static void bgp_evpn_es_free(struct bgp_evpn_es *es, const char *caller)
{
	if (es->flags & (BGP_EVPNES_LOCAL | BGP_EVPNES_REMOTE))
		return;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("%s: es %s free", caller, es->esi_str);

	/* cleanup resources maintained against the ES */
	list_delete(&es->es_evi_list);
	list_delete(&es->es_vtep_list);
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
static void bgp_evpn_local_es_up(struct bgp *bgp, struct bgp_evpn_es *es)
{
	struct prefix_evpn p;

	if (CHECK_FLAG(es->flags, BGP_EVPNES_OPER_UP))
		return;

	SET_FLAG(es->flags, BGP_EVPNES_OPER_UP);

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("local es %s up", es->esi_str);

	/* generate ESR */
	build_evpn_type4_prefix(&p, &es->esi, es->originator_ip);
	if (bgp_evpn_type4_route_update(bgp, es, &p))
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				"%u: Type4 route creation failure for ESI %s",
				bgp->vrf_id, es->esi_str);

	/* generate EAD-EVI */
	bgp_evpn_local_type1_evi_route_add(bgp, es);

	/* generate EAD-ES */
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_ES_ETH_TAG,
			&es->esi, es->originator_ip);
	bgp_evpn_type1_route_update(bgp, es, NULL, &p);
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
		struct in_addr originator_ip, bool oper_up)
{
	char buf[ESI_STR_LEN];
	struct bgp_evpn_es *es;
	bool new_es = true;

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
		zlog_debug("add local es %s orig-ip %pI4", es->esi_str,
			   &originator_ip);

	es->originator_ip = originator_ip;
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
		bgp_evpn_local_es_up(bgp, es);
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
	char vtep_ip[BUFSIZ] = {0};

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
			inet_ntop(AF_INET, &es_vtep->vtep_ip, vtep_ip,
				  sizeof(vtep_ip)),
			vtep_str_size);
		strlcat(vtep_str, "(", vtep_str_size);
		strlcat(vtep_str, vtep_flag_str, vtep_str_size);
		strlcat(vtep_str, ")", vtep_str_size);
	}

	return vtep_str;
}

static inline void json_array_string_add(json_object *json, const char *str)
{
	json_object_array_add(json, json_object_new_string(str));
}

static void bgp_evpn_es_json_vtep_fill(json_object *json_vteps,
		struct bgp_evpn_es_vtep *es_vtep)
{
	json_object *json_vtep_entry;
	json_object *json_flags;
	char vtep_ip[BUFSIZ] = {0};

	json_vtep_entry = json_object_new_object();

	json_object_string_add(json_vtep_entry, "vtep_ip",
			       inet_ntop(AF_INET, &es_vtep->vtep_ip, vtep_ip,
					 sizeof(vtep_ip)));

	if (es_vtep->flags & (BGP_EVPNES_VTEP_ESR |
			 BGP_EVPNES_VTEP_ACTIVE)) {
		json_flags = json_object_new_array();
		if (es_vtep->flags & BGP_EVPNES_VTEP_ESR)
			json_array_string_add(json_flags, "esr");
		if (es_vtep->flags & BGP_EVPNES_VTEP_ACTIVE)
			json_array_string_add(json_flags, "active");
		json_object_object_add(json_vtep_entry, "flags", json_flags);
	}

	json_object_array_add(json_vteps,
			json_vtep_entry);
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
	char originator_ip[BUFSIZ] = {0};

	if (json) {
		json_object *json_flags;
		json_object *json_incons;

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
						 originator_ip,
						 sizeof(originator_ip)));
		json_object_int_add(json, "remoteVniCount",
				es->remote_es_evi_cnt);
		json_object_int_add(json, "inconsistentVniVtepCount",
				es->incons_evi_vtep_cnt);
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
		char vtep_str[ES_VTEP_LIST_STR_SZ + BGP_EVPN_VTEPS_FLAG_STR_SZ];
		char buf1[RD_ADDRSTRLEN];

		type_str[0] = '\0';
		if (es->flags & BGP_EVPNES_LOCAL)
			strlcat(type_str, "L", sizeof(type_str));
		if (es->flags & BGP_EVPNES_REMOTE)
			strlcat(type_str, "R", sizeof(type_str));

		bgp_evpn_es_vteps_str(vtep_str, es, sizeof(vtep_str));
		if (!strlen(vtep_str))
			strlcpy(buf1, "-", sizeof(buf1));

		if (es->flags & BGP_EVPNES_LOCAL)
			prefix_rd2str(&es->prd, buf1, sizeof(buf1));
		else
			strlcpy(buf1, "-", sizeof(buf1));

		vty_out(vty, "ESI: %s\n", es->esi_str);
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " RD: %s\n", buf1);
		vty_out(vty, " Originator-IP: %pI4\n", &es->originator_ip);
		vty_out(vty, " VNI Count: %d\n", listcount(es->es_evi_list));
		vty_out(vty, " Remote VNI Count: %d\n",
				es->remote_es_evi_cnt);
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
		vty_out(vty, " VTEPs: %s\n", vtep_str);
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

	old_active = !!CHECK_FLAG(evi_vtep->flags, BGP_EVPN_EVI_VTEP_ACTIVE);

	/* Both EAD-per-ES and EAD-per-EVI routes must be rxed from a PE
	 * before it can be activated.
	 */
	if ((evi_vtep->flags & BGP_EVPN_EVI_VTEP_EAD) ==
			BGP_EVPN_EVI_VTEP_EAD)
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
				evi_vtep->vtep_ip, false /*esr*/);
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
	build_evpn_type1_prefix(&p, BGP_EVPN_AD_EVI_ETH_TAG,
			&es->esi, es->originator_ip);
	if (CHECK_FLAG(es->flags, BGP_EVPNES_ADV_EVI)) {
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
	char vtep_ip[BUFSIZ] = {0};

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
			inet_ntop(AF_INET, &evi_vtep->vtep_ip, vtep_ip,
				  sizeof(vtep_ip)),
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
	char vtep_ip[BUFSIZ] = {0};

	json_vtep_entry = json_object_new_object();

	json_object_string_add(json_vtep_entry, "vtep_ip",
			       inet_ntop(AF_INET, &evi_vtep->vtep_ip, vtep_ip,
					 sizeof(vtep_ip)));

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

	/* config knobs - XXX add cli to control it */
	bgp_mh_info->ead_evi_adv_for_down_links = true;
	bgp_mh_info->consistency_checking = true;

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
	thread_cancel(bgp_mh_info->t_cons_check);
	list_delete(&bgp_mh_info->local_es_list);
	list_delete(&bgp_mh_info->pend_es_list);

	XFREE(MTYPE_BGP_EVPN_MH_INFO, bgp_mh_info);
}
