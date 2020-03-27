/* EVPN Multihoming procedures
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
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

/* compare two IPV4 VTEP IPs */
static int evpn_vtep_ip_cmp(void *p1, void *p2)
{
	const struct in_addr *ip1 = p1;
	const struct in_addr *ip2 = p2;

	return ip1->s_addr - ip2->s_addr;
}

/*
 * Make hash key for ESI.
 */
unsigned int esi_hash_keymake(const void *p)
{
	const struct evpnes *pes = p;
	const void *pnt = (void *)pes->esi.val;

	return jhash(pnt, ESI_BYTES, 0xa5a5a55a);
}

/*
 * Compare two ESIs.
 */
bool esi_cmp(const void *p1, const void *p2)
{
	const struct evpnes *pes1 = p1;
	const struct evpnes *pes2 = p2;

	if (pes1 == NULL && pes2 == NULL)
		return true;

	if (pes1 == NULL || pes2 == NULL)
		return false;

	return (memcmp(pes1->esi.val, pes2->esi.val, ESI_BYTES) == 0);
}

/*
 * Build extended community for EVPN ES (type-4) route
 */
static void build_evpn_type4_route_extcomm(struct evpnes *es,
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
	ecom_encap.val = (uint8_t *)eval.val;
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* ES import RT */
	memset(&mac, 0, sizeof(struct ethaddr));
	memset(&ecom_es_rt, 0, sizeof(ecom_es_rt));
	es_get_system_mac(&es->esi, &mac);
	encode_es_rt_extcomm(&eval_es_rt, &mac);
	ecom_es_rt.size = 1;
	ecom_es_rt.val = (uint8_t *)eval_es_rt.val;
	attr->ecommunity =
		ecommunity_merge(attr->ecommunity, &ecom_es_rt);

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
}

static struct in_addr *es_vtep_new(struct in_addr vtep)
{
	struct in_addr *ip;

	ip = XCALLOC(MTYPE_BGP_EVPN_ES_VTEP, sizeof(struct in_addr));

	ip->s_addr = vtep.s_addr;
	return ip;
}

static void es_vtep_free(struct in_addr *ip)
{
	XFREE(MTYPE_BGP_EVPN_ES_VTEP, ip);
}

/* check if VTEP is already part of the list */
static int is_vtep_present_in_list(struct list *list,
				   struct in_addr vtep)
{
	struct listnode *node = NULL;
	struct in_addr *tmp;

	for (ALL_LIST_ELEMENTS_RO(list, node, tmp)) {
		if (tmp->s_addr == vtep.s_addr)
			return 1;
	}
	return 0;
}

/*
 * Best path for ES route was changed,
 * update the list of VTEPs for this ES
 */
static int evpn_es_install_vtep(struct bgp *bgp,
				struct evpnes *es,
				struct prefix_evpn *p,
				struct in_addr rvtep)
{
	struct in_addr *vtep_ip;

	if (is_vtep_present_in_list(es->vtep_list, rvtep))
		return 0;


	vtep_ip = es_vtep_new(rvtep);
	if (vtep_ip)
		listnode_add_sort(es->vtep_list, vtep_ip);
	return 0;
}

/*
 * Best path for ES route was changed,
 * update the list of VTEPs for this ES
 */
static int evpn_es_uninstall_vtep(struct bgp *bgp,
				  struct evpnes *es,
				  struct prefix_evpn *p,
				  struct in_addr rvtep)
{
	struct listnode *node, *nnode, *node_to_del = NULL;
	struct in_addr *tmp;

	for (ALL_LIST_ELEMENTS(es->vtep_list, node, nnode, tmp)) {
		if (tmp->s_addr == rvtep.s_addr) {
			es_vtep_free(tmp);
			node_to_del = node;
		}
	}

	if (node_to_del)
		list_delete_node(es->vtep_list, node_to_del);

	return 0;
}

/*
 * Calculate the best path for a ES(type-4) route.
 */
static int evpn_es_route_select_install(struct bgp *bgp,
					struct evpnes *es,
					struct bgp_node *rn)
{
	int ret = 0;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *old_select; /* old best */
	struct bgp_path_info *new_select; /* new best */
	struct bgp_path_info_pair old_and_new;

	/* Compute the best path. */
	bgp_best_selection(bgp, rn, &bgp->maxpaths[afi][safi],
			   &old_and_new, afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/*
	 * If the best path hasn't changed - see if something needs to be
	 * updated
	 */
	if (old_select && old_select == new_select
	    && old_select->type == ZEBRA_ROUTE_BGP
	    && old_select->sub_type == BGP_ROUTE_IMPORTED
	    && !CHECK_FLAG(rn->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		if (bgp_zebra_has_route_changed(old_select)) {
			ret = evpn_es_install_vtep(bgp, es,
						   (struct prefix_evpn *)&rn->p,
						   old_select->attr->nexthop);
		}
		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
		bgp_zebra_clear_route_change_flags(rn);
		return ret;
	}

	/* If the user did a "clear" this flag will be set */
	UNSET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);

	/*
	 * bestpath has changed; update relevant fields and install or uninstall
	 * into the zebra RIB.
	 */
	if (old_select || new_select)
		bgp_bump_version(rn);

	if (old_select)
		bgp_path_info_unset_flag(rn, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		bgp_path_info_set_flag(rn, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(rn, new_select, BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
	}

	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
	    && new_select->sub_type == BGP_ROUTE_IMPORTED) {
		ret = evpn_es_install_vtep(bgp, es,
					   (struct prefix_evpn *)&rn->p,
					   new_select->attr->nexthop);
	} else {
		if (old_select && old_select->type == ZEBRA_ROUTE_BGP
		    && old_select->sub_type == BGP_ROUTE_IMPORTED)
			ret = evpn_es_uninstall_vtep(
				bgp, es, (struct prefix_evpn *)&rn->p,
				old_select->attr->nexthop);
	}

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(rn);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(rn, old_select);

	return ret;
}

/*
 * create or update EVPN type4 route entry.
 * This could be in the ES table or the global table.
 * TODO: handle remote ES (type4) routes as well
 */
static int update_evpn_type4_route_entry(struct bgp *bgp, struct evpnes *es,
					 afi_t afi, safi_t safi,
					 struct bgp_node *rn, struct attr *attr,
					 int add, struct bgp_path_info **ri,
					 int *route_changed)
{
	char buf[ESI_STR_LEN];
	char buf1[INET6_ADDRSTRLEN];
	struct bgp_path_info *tmp_pi = NULL;
	struct bgp_path_info *local_pi = NULL;  /* local route entry if any */
	struct bgp_path_info *remote_pi = NULL; /* remote route entry if any */
	struct attr *attr_new = NULL;
	struct prefix_evpn *evp = NULL;

	*ri = NULL;
	*route_changed = 1;
	evp = (struct prefix_evpn *)&rn->p;

	/* locate the local and remote entries if any */
	for (tmp_pi = bgp_dest_get_bgp_path_info(rn); tmp_pi;
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

	/* we don't expect to see a remote_ri at this point.
	 * An ES route has esi + vtep_ip as the key,
	 * We shouldn't see the same route from any other vtep.
	 */
	if (remote_pi) {
		flog_err(
			EC_BGP_ES_INVALID,
			"%u ERROR: local es route for ESI: %s Vtep %s also learnt from remote",
			bgp->vrf_id,
			esi_to_str(&evp->prefix.es_addr.esi, buf, sizeof(buf)),
			ipaddr2str(&es->originator_ip, buf1, sizeof(buf1)));
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
				   bgp->peer_self, attr_new, rn);
		SET_FLAG(tmp_pi->flags, BGP_PATH_VALID);

		/* add the newly created path to the route-node */
		bgp_path_info_add(rn, tmp_pi);
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
			bgp_path_info_set_flag(rn, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(rn, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = bgp_clock();
		}
	}

	/* Return back the route entry. */
	*ri = tmp_pi;
	return 0;
}

/* update evpn es (type-4) route */
static int update_evpn_type4_route(struct bgp *bgp,
				   struct evpnes *es,
				   struct prefix_evpn *p)
{
	int ret = 0;
	int route_changed = 0;
	char buf[ESI_STR_LEN];
	char buf1[INET6_ADDRSTRLEN];
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct attr *attr_new = NULL;
	struct bgp_node *rn = NULL;
	struct bgp_path_info *pi = NULL;

	memset(&attr, 0, sizeof(struct attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	attr.nexthop = es->originator_ip.ipaddr_v4;
	attr.mp_nexthop_global_in = es->originator_ip.ipaddr_v4;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	/* Set up extended community. */
	build_evpn_type4_route_extcomm(es, &attr);

	/* First, create (or fetch) route node within the ESI. */
	/* NOTE: There is no RD here. */
	rn = bgp_node_get(es->route_table, (struct prefix *)p);

	/* Create or update route entry. */
	ret = update_evpn_type4_route_entry(bgp, es, afi, safi, rn, &attr, 1,
					    &pi, &route_changed);
	if (ret != 0) {
		flog_err(EC_BGP_ES_INVALID,
			 "%u ERROR: Failed to updated ES route ESI: %s VTEP %s",
			 bgp->vrf_id,
			 esi_to_str(&p->prefix.es_addr.esi, buf, sizeof(buf)),
			 ipaddr2str(&es->originator_ip, buf1, sizeof(buf1)));
	}

	assert(pi);
	attr_new = pi->attr;

	/* Perform route selection;
	 * this is just to set the flags correctly
	 * as local route in the ES always wins.
	 */
	evpn_es_route_select_install(bgp, es, rn);
	bgp_dest_unlock_node(rn);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_changed) {
		struct bgp_path_info *global_pi;

		rn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
				      (struct prefix *)p, &es->prd);
		update_evpn_type4_route_entry(bgp, es, afi, safi, rn, attr_new,
					      1, &global_pi, &route_changed);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, rn, afi, safi);
		bgp_dest_unlock_node(rn);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
	return 0;
}

/* Delete EVPN ES (type-4) route */
static int delete_evpn_type4_route(struct bgp *bgp,
				   struct evpnes *es,
				   struct prefix_evpn *p)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *pi;
	struct bgp_node *rn = NULL; /* rn in esi table */
	struct bgp_node *global_rn = NULL; /* rn in global table */

	/* First, locate the route node within the ESI.
	 * If it doesn't exist, ther is nothing to do.
	 * Note: there is no RD here.
	 */
	rn = bgp_node_lookup(es->route_table, (struct prefix *)p);
	if (!rn)
		return 0;

	/* Next, locate route node in the global EVPN routing table.
	 * Note that this table is a 2-level tree (RD-level + Prefix-level)
	 */
	global_rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
					(struct prefix *)p, &es->prd);
	if (global_rn) {

		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, afi, safi, global_rn, &pi);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_rn, afi, safi);
		bgp_dest_unlock_node(global_rn);
	}

	/*
	 * Delete route entry in the ESI route table.
	 * This can just be removed.
	 */
	delete_evpn_route_entry(bgp, afi, safi, rn, &pi);
	if (pi)
		bgp_path_info_reap(rn, pi);
	bgp_dest_unlock_node(rn);
	return 0;
}

/*
 * Delete all routes in per ES route-table
 */
static int delete_all_es_routes(struct bgp *bgp, struct evpnes *es)
{
	struct bgp_node *rn;
	struct bgp_path_info *pi, *nextpi;

	/* Walk this ES's route table and delete all routes. */
	for (rn = bgp_table_top(es->route_table); rn;
	     rn = bgp_route_next(rn)) {
		for (pi = bgp_dest_get_bgp_path_info(rn);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_path_info_delete(rn, pi);
			bgp_path_info_reap(rn, pi);
		}
	}

	return 0;
}

/* Delete (and withdraw) local routes for specified ES from global and ES table.
 * Also remove all other routes from the per ES table.
 * Invoked when ES is deleted.
 */
static int delete_routes_for_es(struct bgp *bgp, struct evpnes *es)
{
	int ret;
	char buf[ESI_STR_LEN];
	struct prefix_evpn p;

	/* Delete and withdraw locally learnt ES route */
	build_evpn_type4_prefix(&p, &es->esi, es->originator_ip.ipaddr_v4);
	ret = delete_evpn_type4_route(bgp, es, &p);
	if (ret) {
		flog_err(EC_BGP_EVPN_ROUTE_DELETE,
			 "%u failed to delete type-4 route for ESI %s",
			 bgp->vrf_id, esi_to_str(&es->esi, buf, sizeof(buf)));
	}

	/* Delete all routes from per ES table */
	return delete_all_es_routes(bgp, es);
}

/* Install EVPN route entry in ES */
static int install_evpn_route_entry_in_es(struct bgp *bgp, struct evpnes *es,
					  struct prefix_evpn *p,
					  struct bgp_path_info *parent_pi)
{
	int ret = 0;
	struct bgp_node *rn = NULL;
	struct bgp_path_info *pi = NULL;
	struct attr *attr_new = NULL;

	/* Create (or fetch) route within the VNI.
	 * NOTE: There is no RD here.
	 */
	rn = bgp_node_get(es->route_table, (struct prefix *)p);

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(rn); pi; pi = pi->next)
		if (pi->extra
		    && (struct bgp_path_info *)pi->extra->parent == parent_pi)
			break;

	if (!pi) {
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Create new route with its attribute. */
		pi = info_make(parent_pi->type, BGP_ROUTE_IMPORTED, 0,
			       parent_pi->peer, attr_new, rn);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_extra_get(pi);
		pi->extra->parent = parent_pi;
		bgp_path_info_add(rn, pi);
	} else {
		if (attrhash_cmp(pi->attr, parent_pi->attr)
		    && !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			bgp_dest_unlock_node(rn);
			return 0;
		}
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(rn, pi);

		/* Mark if nexthop has changed. */
		if (!IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = bgp_clock();
	}

	/* Perform route selection and update zebra, if required. */
	ret = evpn_es_route_select_install(bgp, es, rn);
	return ret;
}

/* Uninstall EVPN route entry from ES route table */
static int uninstall_evpn_route_entry_in_es(struct bgp *bgp, struct evpnes *es,
					    struct prefix_evpn *p,
					    struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_node *rn;
	struct bgp_path_info *pi;

	if (!es->route_table)
		return 0;

	/* Locate route within the ESI.
	 * NOTE: There is no RD here.
	 */
	rn = bgp_node_lookup(es->route_table, (struct prefix *)p);
	if (!rn)
		return 0;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(rn); pi; pi = pi->next)
		if (pi->extra
		    && (struct bgp_path_info *)pi->extra->parent == parent_pi)
			break;

	if (!pi)
		return 0;

	/* Mark entry for deletion */
	bgp_path_info_delete(rn, pi);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_es_route_select_install(bgp, es, rn);

	/* Unlock route node. */
	bgp_dest_unlock_node(rn);

	return ret;
}

/*
 * Given a prefix, see if it belongs to ES.
 */
static int is_prefix_matching_for_es(struct prefix_evpn *p,
				     struct evpnes *es)
{
	/* if not an ES route return false */
	if (p->prefix.route_type != BGP_EVPN_ES_ROUTE)
		return 0;

	if (memcmp(&p->prefix.es_addr.esi, &es->esi, sizeof(esi_t)) == 0)
		return 1;

	return 0;
}

static int install_uninstall_routes_for_es(struct bgp *bgp,
					   struct evpnes *es,
					   int install)
{
	int ret;
	afi_t afi;
	safi_t safi;
	char buf[PREFIX_STRLEN];
	char buf1[ESI_STR_LEN];
	struct bgp_node *rd_rn, *rn;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/*
	 * Walk entire global routing table and evaluate routes which could be
	 * imported into this VRF. Note that we need to loop through all global
	 * routes to determine which route matches the import rt on vrf
	 */
	for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn;
	     rd_rn = bgp_route_next(rd_rn)) {
		table = bgp_dest_get_bgp_table_info(rd_rn);
		if (!table)
			continue;

		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
			struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

			for (pi = bgp_dest_get_bgp_path_info(rn); pi;
			     pi = pi->next) {
				/*
				 * Consider "valid" remote routes applicable for
				 * this ES.
				 */
				if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID)
				      && pi->type == ZEBRA_ROUTE_BGP
				      && pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (!is_prefix_matching_for_es(evp, es))
					continue;

				if (install)
					ret = install_evpn_route_entry_in_es(
						bgp, es, evp, pi);
				else
					ret = uninstall_evpn_route_entry_in_es(
						bgp, es, evp, pi);

				if (ret) {
					flog_err(
						EC_BGP_EVPN_FAIL,
						"Failed to %s EVPN %s route in ESI %s",
						install ? "install"
							: "uninstall",
						prefix2str(evp, buf,
							   sizeof(buf)),
						esi_to_str(&es->esi, buf1,
							   sizeof(buf1)));
					return ret;
				}
			}
		}
	}
	return 0;
}

/* Install any existing remote ES routes applicable for this ES into its routing
 * table. This is invoked when ES comes up.
 */
static int install_routes_for_es(struct bgp *bgp, struct evpnes *es)
{
	return install_uninstall_routes_for_es(bgp, es, 1);
}

/* Install or unistall route in ES */
int install_uninstall_route_in_es(struct bgp *bgp, struct evpnes *es,
					 afi_t afi, safi_t safi,
					 struct prefix_evpn *evp,
					 struct bgp_path_info *pi, int install)
{
	int ret = 0;
	char buf[ESI_STR_LEN];

	if (install)
		ret = install_evpn_route_entry_in_es(bgp, es, evp, pi);
	else
		ret = uninstall_evpn_route_entry_in_es(bgp, es, evp, pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%u: Failed to %s EVPN %s route in ESI %s", bgp->vrf_id,
			install ? "install" : "uninstall", "ES",
			esi_to_str(&evp->prefix.es_addr.esi, buf, sizeof(buf)));
		return ret;
	}
	return 0;
}

/*
 * Process received EVPN type-4 route (advertise or withdraw).
 */
int process_type4_route(struct peer *peer, afi_t afi, safi_t safi,
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
	if (psize != 23 && psize != 35) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-4 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

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

/*
 * Lookup local ES.
 */
struct evpnes *bgp_evpn_lookup_es(struct bgp *bgp, esi_t *esi)
{
	struct evpnes *es;
	struct evpnes tmp;

	memset(&tmp, 0, sizeof(struct evpnes));
	memcpy(&tmp.esi, esi, sizeof(esi_t));
	es = hash_lookup(bgp->esihash, &tmp);
	return es;
}

/*
 * Create a new local es - invoked upon zebra notification.
 */
static struct evpnes *bgp_evpn_es_new(struct bgp *bgp,
			       esi_t *esi,
			       struct ipaddr *originator_ip)
{
	char buf[100];
	struct evpnes *es;

	if (!bgp)
		return NULL;

	es = XCALLOC(MTYPE_BGP_EVPN_ES, sizeof(struct evpnes));

	/* set the ESI and originator_ip */
	memcpy(&es->esi, esi, sizeof(esi_t));
	memcpy(&es->originator_ip, originator_ip, sizeof(struct ipaddr));

	/* Initialise the VTEP list */
	es->vtep_list = list_new();
	es->vtep_list->cmp = evpn_vtep_ip_cmp;

	/* auto derive RD for this es */
	bf_assign_index(bm->rd_idspace, es->rd_id);
	es->prd.family = AF_UNSPEC;
	es->prd.prefixlen = 64;
	sprintf(buf, "%s:%hu", inet_ntoa(bgp->router_id), es->rd_id);
	(void)str2prefix_rd(buf, &es->prd);

	/* Initialize the ES route table */
	es->route_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);

	/* Add to hash */
	if (!hash_get(bgp->esihash, es, hash_alloc_intern)) {
		XFREE(MTYPE_BGP_EVPN_ES, es);
		return NULL;
	}

	QOBJ_REG(es, evpnes);
	return es;
}

/*
 * Free a given ES -
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
static void bgp_evpn_es_free(struct bgp *bgp, struct evpnes *es)
{
	list_delete(&es->vtep_list);
	bgp_table_unlock(es->route_table);
	bf_release_index(bm->rd_idspace, es->rd_id);
	hash_release(bgp->esihash, es);
	QOBJ_UNREG(es);
	XFREE(MTYPE_BGP_EVPN_ES, es);
}

/*
 * bgp_evpn_local_es_del
 */
int bgp_evpn_local_es_del(struct bgp *bgp,
			  esi_t *esi,
			  struct ipaddr *originator_ip)
{
	char buf[ESI_STR_LEN];
	struct evpnes *es = NULL;

	if (!bgp->esihash) {
		flog_err(EC_BGP_ES_CREATE, "%u: ESI hash not yet created",
			 bgp->vrf_id);
		return -1;
	}

	/* Lookup ESI hash - should exist. */
	es = bgp_evpn_lookup_es(bgp, esi);
	if (!es) {
		flog_warn(EC_BGP_EVPN_ESI,
			  "%u: ESI hash entry for ESI %s at Local ES DEL",
			  bgp->vrf_id, esi_to_str(esi, buf, sizeof(buf)));
		return -1;
	}

	/* Delete all local EVPN ES routes from ESI table
	 * and schedule for processing (to withdraw from peers))
	 */
	delete_routes_for_es(bgp, es);

	/* free the hash entry */
	bgp_evpn_es_free(bgp, es);

	return 0;
}

/*
 * bgp_evpn_local_es_add
 */
int bgp_evpn_local_es_add(struct bgp *bgp,
			  esi_t *esi,
			  struct ipaddr *originator_ip)
{
	char buf[ESI_STR_LEN];
	struct evpnes *es = NULL;
	struct prefix_evpn p;

	if (!bgp->esihash) {
		flog_err(EC_BGP_ES_CREATE, "%u: ESI hash not yet created",
			 bgp->vrf_id);
		return -1;
	}

	/* create the new es */
	es = bgp_evpn_lookup_es(bgp, esi);
	if (!es) {
		es = bgp_evpn_es_new(bgp, esi, originator_ip);
		if (!es) {
			flog_err(
				EC_BGP_ES_CREATE,
				"%u: Failed to allocate ES entry for ESI %s - at Local ES Add",
				bgp->vrf_id, esi_to_str(esi, buf, sizeof(buf)));
			return -1;
		}
	}
	UNSET_FLAG(es->flags, EVPNES_REMOTE);
	SET_FLAG(es->flags, EVPNES_LOCAL);

	build_evpn_type4_prefix(&p, esi, originator_ip->ipaddr_v4);
	if (update_evpn_type4_route(bgp, es, &p)) {
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
			 "%u: Type4 route creation failure for ESI %s",
			 bgp->vrf_id, esi_to_str(esi, buf, sizeof(buf)));
		return -1;
	}

	/* import all remote ES routes in th ES table */
	install_routes_for_es(bgp, es);

	return 0;
}

