// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

/*
 * File:	vnc_export_bgp.c
 * Purpose:	Export routes to BGP directly (not via zebra)
 */

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/agg_table.h"
#include "lib/vty.h"
#include "lib/log.h"
#include "lib/stream.h"
#include "lib/memory.h"
#include "lib/linklist.h"
#include "lib/plist.h"
#include "lib/routemap.h"
#include "lib/lib_errors.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"

#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/vnc_export_table.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_debug.h"


static void vnc_direct_add_rn_group_rd(struct bgp *bgp,
				       struct rfapi_nve_group_cfg *rfg,
				       struct agg_node *rn, struct attr *attr,
				       afi_t afi,
				       struct rfapi_descriptor *irfd);

/***********************************************************************
 * Export methods that set nexthop to CE (from 5226 roo EC) BEGIN
 ***********************************************************************/

/*
 * Memory allocation approach: make a ghost attr that
 * has non-interned parts for the modifications. ghost attr
 * memory is allocated by caller.
 *
 *	- extract ce (=5226) EC and use as new nexthop
 *	- strip Tunnel Encap attr
 *	- copy all ECs
 */
static void encap_attr_export_ce(struct attr *new, struct attr *orig,
				 struct prefix *use_nexthop)
{
	/*
	 * Make "new" a ghost attr copy of "orig"
	 */
	memset(new, 0, sizeof(struct attr));
	*new = *orig;

	/*
	 * Set nexthop
	 */
	switch (use_nexthop->family) {
	case AF_INET:
		new->nexthop = use_nexthop->u.prefix4;
		new->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4; /* bytes */
		new->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		break;

	case AF_INET6:
		new->mp_nexthop_global = use_nexthop->u.prefix6;
		new->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL; /* bytes */
		break;

	default:
		assert(0);
		break;
	}

	/*
	 * Set MED
	 *
	 * Note that it will be deleted when BGP sends to any eBGP
	 * peer unless PEER_FLAG_MED_UNCHANGED is set:
	 *
	 *          neighbor NEIGHBOR attribute-unchanged med
	 */
	if (!CHECK_FLAG(new->flag, BGP_ATTR_MULTI_EXIT_DISC)) {
		if (CHECK_FLAG(new->flag, BGP_ATTR_LOCAL_PREF)) {
			if (new->local_pref > 255)
				new->med = 0;
			else
				new->med = 255 - new->local_pref;
		} else {
			new->med = 255; /* shouldn't happen */
		}
		new->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	}

	/*
	 * "new" is now a ghost attr:
	 *  - it owns an "extra" struct
	 *  - it owns any non-interned parts
	 *  - any references to interned parts are not counted
	 *
	 * Caller should, after using the attr, call:
	 *  - bgp_attr_flush() to free non-interned parts
	 */
}

static int getce(struct bgp *bgp, struct attr *attr, struct prefix *pfx_ce)
{
	uint8_t *ecp;
	uint32_t i;
	uint16_t localadmin = bgp->rfapi_cfg->resolve_nve_roo_local_admin;
	struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

	for (ecp = ecomm->val, i = 0; i < ecomm->size;
	     ++i, ecp += ECOMMUNITY_SIZE) {

		if (VNC_DEBUG(EXPORT_BGP_GETCE)) {
			vnc_zlog_debug_any(
				"%s: %02x %02x %02x %02x %02x %02x %02x %02x",
				__func__, ecp[0], ecp[1], ecp[2], ecp[3],
				ecp[4], ecp[5], ecp[6], ecp[7]);
		}

		/*
		 * is it ROO?
		 */
		if (ecp[0] != 1 || ecp[1] != 3) {
			continue;
		}

		/*
		 * Match local admin value?
		 */
		if (ecp[6] != ((localadmin & 0xff00) >> 8)
		    || ecp[7] != (localadmin & 0xff))
			continue;

		memset((uint8_t *)pfx_ce, 0, sizeof(*pfx_ce));
		memcpy(&pfx_ce->u.prefix4, ecp + 2, 4);
		pfx_ce->family = AF_INET;
		pfx_ce->prefixlen = IPV4_MAX_BITLEN;

		return 0;
	}
	return -1;
}


void vnc_direct_bgp_add_route_ce(struct bgp *bgp, struct agg_node *rn,
				 struct bgp_path_info *bpi)
{
	struct attr *attr = bpi->attr;
	struct peer *peer = bpi->peer;
	const struct prefix *prefix = agg_node_get_prefix(rn);
	afi_t afi = family2afi(prefix->family);
	struct bgp_dest *udest;
	struct bgp_path_info *ubpi;
	struct attr hattr;
	struct attr *iattr;
	struct prefix ce_nexthop;
	struct prefix post_routemap_nexthop;


	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi of route node",
			 __func__);
		return;
	}

	if ((bpi->type != ZEBRA_ROUTE_BGP)
	    || (bpi->sub_type != BGP_ROUTE_NORMAL
		&& bpi->sub_type != BGP_ROUTE_RFP
		&& bpi->sub_type != BGP_ROUTE_STATIC)) {

		vnc_zlog_debug_verbose(
			"%s: wrong route type/sub_type for export, skipping",
			__func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	if (!VNC_EXPORT_BGP_CE_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp ce mode not enabled, skipping",
			__func__);
		return;
	}

	/*
	 * prefix list check
	 */
	if (bgp->rfapi_cfg->plist_export_bgp[afi]) {
		if (prefix_list_apply(bgp->rfapi_cfg->plist_export_bgp[afi],
				      prefix)
		    == PREFIX_DENY) {
			vnc_zlog_debug_verbose(
				"%s: prefix list denied, skipping", __func__);
			return;
		}
	}


	/*
	 * Extract CE
	 * This works only for IPv4 because IPv6 addresses are too big
	 * to fit in an extended community
	 */
	if (getce(bgp, attr, &ce_nexthop)) {
		vnc_zlog_debug_verbose("%s: EC has no encoded CE, skipping",
				       __func__);
		return;
	}

	/*
	 * Is this route already represented in the unicast RIB?
	 * (look up prefix; compare route type, sub_type, peer, nexthop)
	 */
	udest = bgp_afi_node_get(bgp->rib[afi][SAFI_UNICAST], afi, SAFI_UNICAST,
				 prefix, NULL);
	for (ubpi = bgp_dest_get_bgp_path_info(udest); ubpi;
	     ubpi = ubpi->next) {
		struct prefix unicast_nexthop;

		if (CHECK_FLAG(ubpi->flags, BGP_PATH_REMOVED))
			continue;

		rfapiUnicastNexthop2Prefix(afi, ubpi->attr, &unicast_nexthop);

		if (ubpi->type == ZEBRA_ROUTE_VNC_DIRECT
		    && ubpi->sub_type == BGP_ROUTE_REDISTRIBUTE
		    && ubpi->peer == peer
		    && prefix_same(&unicast_nexthop, &ce_nexthop)) {

			vnc_zlog_debug_verbose(
				"%s: already have matching exported unicast route, skipping",
				__func__);
			return;
		}
	}

	/*
	 * Construct new attribute set with CE addr as
	 * nexthop and without Tunnel Encap attr
	 */
	encap_attr_export_ce(&hattr, attr, &ce_nexthop);
	if (bgp->rfapi_cfg->routemap_export_bgp) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = peer;
		info.attr = &hattr;
		ret = route_map_apply(bgp->rfapi_cfg->routemap_export_bgp,
				      prefix, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			return;
		}
	}

	iattr = bgp_attr_intern(&hattr);
	bgp_attr_flush(&hattr);

	/*
	 * Rule: disallow route-map alteration of next-hop, because it
	 * would make it too difficult to keep track of the correspondence
	 * between VPN routes and unicast routes.
	 */
	rfapiUnicastNexthop2Prefix(afi, iattr, &post_routemap_nexthop);

	if (!prefix_same(&ce_nexthop, &post_routemap_nexthop)) {
		vnc_zlog_debug_verbose(
			"%s: route-map modification of nexthop not allowed, skipping",
			__func__);
		bgp_attr_unintern(&iattr);
		return;
	}

	bgp_update(peer, prefix, 0, /* addpath_id */
		   iattr,	   /* bgp_update copies this attr */
		   afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
		   BGP_ROUTE_REDISTRIBUTE, NULL, /* RD not used for unicast */
		   NULL, 0,			 /* tag not used for unicast */
		   0, NULL);			 /* EVPN not used */
	bgp_attr_unintern(&iattr);
}


/*
 * "Withdrawing a Route" export process
 */
void vnc_direct_bgp_del_route_ce(struct bgp *bgp, struct agg_node *rn,
				 struct bgp_path_info *bpi)
{
	const struct prefix *p = agg_node_get_prefix(rn);
	afi_t afi = family2afi(p->family);
	struct bgp_path_info *vbpi;
	struct prefix ce_nexthop;

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: bad afi", __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}
	if (!VNC_EXPORT_BGP_CE_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp ce mode not enabled, skipping",
			__func__);
		return;
	}

	/*
	 * Extract CE
	 * This works only for IPv4 because IPv6 addresses are too big
	 * to fit in an extended community
	 */
	if (getce(bgp, bpi->attr, &ce_nexthop)) {
		vnc_zlog_debug_verbose("%s: EC has no encoded CE, skipping",
				       __func__);
		return;
	}

	/*
	 * Look for other VPN routes with same prefix, same 5226 CE,
	 * same peer. If at least one is present, don't remove the
	 * route from the unicast RIB
	 */

	for (vbpi = rn->info; vbpi; vbpi = vbpi->next) {
		struct prefix ce;
		if (bpi == vbpi)
			continue;
		if (bpi->peer != vbpi->peer)
			continue;
		if (getce(bgp, vbpi->attr, &ce))
			continue;
		if (prefix_same(&ce, &ce_nexthop)) {
			vnc_zlog_debug_verbose(
				"%s: still have a route via CE, not deleting unicast",
				__func__);
			return;
		}
	}

	/*
	 * withdraw the route
	 */
	bgp_withdraw(bpi->peer, p, 0, /* addpath_id */
		     afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
		     BGP_ROUTE_REDISTRIBUTE, NULL, /* RD not used for unicast */
		     NULL, 0, NULL); /* tag not used for unicast */
}

static void vnc_direct_bgp_vpn_enable_ce(struct bgp *bgp, afi_t afi)
{
	struct agg_node *rn;
	struct bgp_path_info *ri;

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (!bgp)
		return;

	if (!(bgp->rfapi_cfg))
		return;

	if (!VNC_EXPORT_BGP_CE_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export of CE routes not enabled, skipping",
			__func__);
		return;
	}

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	/*
	 * Go through entire ce import table and export to BGP unicast.
	 */
	for (rn = agg_route_top(bgp->rfapi->it_ce->imported_vpn[afi]); rn;
	     rn = agg_route_next(rn)) {
		if (!rn->info)
			continue;

		vnc_zlog_debug_verbose("%s: checking prefix %pRN", __func__,
				       rn);

		for (ri = rn->info; ri; ri = ri->next) {

			vnc_zlog_debug_verbose("%s: ri->sub_type: %d", __func__,
					       ri->sub_type);

			if (ri->sub_type == BGP_ROUTE_NORMAL
			    || ri->sub_type == BGP_ROUTE_RFP
			    || ri->sub_type == BGP_ROUTE_STATIC) {

				vnc_direct_bgp_add_route_ce(bgp, rn, ri);
			}
		}
	}
}

static void vnc_direct_bgp_vpn_disable_ce(struct bgp *bgp, afi_t afi)
{
	struct bgp_dest *dest;

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (!bgp)
		return;

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	/*
	 * Go through the entire BGP unicast table and remove routes that
	 * originated from us
	 */
	for (dest = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); dest;
	     dest = bgp_route_next(dest)) {

		struct bgp_path_info *ri;
		struct bgp_path_info *next;

		for (ri = bgp_dest_get_bgp_path_info(dest), next = NULL; ri;
		     ri = next) {

			next = ri->next;

			if (ri->type == ZEBRA_ROUTE_VNC_DIRECT
			    && ri->sub_type == BGP_ROUTE_REDISTRIBUTE) {

				bgp_withdraw(
					ri->peer, bgp_dest_get_prefix(dest),
					0,    /* addpath_id */
					AFI_IP, SAFI_UNICAST,
					ZEBRA_ROUTE_VNC_DIRECT,
					BGP_ROUTE_REDISTRIBUTE,
					NULL, /* RD not used for unicast */
					NULL, 0,
					NULL); /* tag not used for unicast */
			}
		}
	}
}

/***********************************************************************
 * Export methods that set nexthop to CE (from 5226 roo EC) END
 ***********************************************************************/

/***********************************************************************
 * Export methods that proxy nexthop BEGIN
 ***********************************************************************/

static struct ecommunity *vnc_route_origin_ecom(struct agg_node *rn)
{
	struct ecommunity *new;
	struct bgp_path_info *bpi;

	if (!rn->info)
		return NULL;

	new = ecommunity_new();

	for (bpi = rn->info; bpi; bpi = bpi->next) {

		struct ecommunity_val roec;

		switch (BGP_MP_NEXTHOP_FAMILY(bpi->attr->mp_nexthop_len)) {
		case AF_INET:
			memset(&roec, 0, sizeof(roec));
			roec.val[0] = 0x01;
			roec.val[1] = 0x03;
			memcpy(roec.val + 2,
			       &bpi->attr->mp_nexthop_global_in.s_addr, 4);
			roec.val[6] = 0;
			roec.val[7] = 0;
			ecommunity_add_val(new, &roec, false, false);
			break;
		case AF_INET6:
			/* No support for IPv6 addresses in extended communities
			 */
			break;
		}
	}

	if (!new->size) {
		ecommunity_free(&new);
		new = NULL;
	}

	return new;
}

static struct ecommunity *vnc_route_origin_ecom_single(struct in_addr *origin)
{
	struct ecommunity *new;
	struct ecommunity_val roec;

	memset(&roec, 0, sizeof(roec));
	roec.val[0] = 0x01;
	roec.val[1] = 0x03;
	memcpy(roec.val + 2, &origin->s_addr, 4);
	roec.val[6] = 0;
	roec.val[7] = 0;

	new = ecommunity_new();
	ecommunity_add_val(new, &roec, false, false);

	if (!new->size) {
		ecommunity_free(&new);
		new = NULL;
	}

	return new;
}


/*
 * New memory allocation approach: make a ghost attr that
 * has non-interned parts for the modifications. ghost attr
 * memory is allocated by caller.
 */
static int
encap_attr_export(struct attr *new, struct attr *orig,
		  struct prefix *new_nexthop,
		  struct agg_node *rn) /* for VN addrs for ecom list */
				       /* if rn is 0, use route's nexthop */
{
	struct prefix orig_nexthop;
	struct prefix *use_nexthop;
	static struct ecommunity *ecom_ro;

	if (new_nexthop) {
		use_nexthop = new_nexthop;
	} else {
		use_nexthop = &orig_nexthop;
		orig_nexthop.family =
			BGP_MP_NEXTHOP_FAMILY(orig->mp_nexthop_len);
		if (orig_nexthop.family == AF_INET) {
			orig_nexthop.prefixlen = IPV4_MAX_BITLEN;
			orig_nexthop.u.prefix4 = orig->mp_nexthop_global_in;
		} else if (orig_nexthop.family == AF_INET6) {
			orig_nexthop.prefixlen = IPV6_MAX_BITLEN;
			orig_nexthop.u.prefix6 = orig->mp_nexthop_global;
		} else {
			return -1; /* FAIL - can't compute nexthop */
		}
	}


	/*
	 * Make "new" a ghost attr copy of "orig"
	 */
	memset(new, 0, sizeof(struct attr));
	*new = *orig;

	/*
	 * Set nexthop
	 */
	switch (use_nexthop->family) {
	case AF_INET:
		new->nexthop = use_nexthop->u.prefix4;
		new->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4; /* bytes */
		new->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		break;

	case AF_INET6:
		new->mp_nexthop_global = use_nexthop->u.prefix6;
		new->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL; /* bytes */
		break;

	default:
		assert(0);
		break;
	}

	if (rn) {
		ecom_ro = vnc_route_origin_ecom(rn);
	} else {
		/* TBD  use lcom for IPv6 */
		ecom_ro = vnc_route_origin_ecom_single(&use_nexthop->u.prefix4);
	}
	if (bgp_attr_get_ecommunity(new)) {
		if (ecom_ro)
			bgp_attr_set_ecommunity(
				new,
				ecommunity_merge(ecom_ro,
						 bgp_attr_get_ecommunity(new)));
	} else {
		bgp_attr_set_ecommunity(new, ecom_ro);
	}

	/*
	 * Set MED
	 *
	 * Note that it will be deleted when BGP sends to any eBGP
	 * peer unless PEER_FLAG_MED_UNCHANGED is set:
	 *
	 *          neighbor NEIGHBOR attribute-unchanged med
	 */
	if (!CHECK_FLAG(new->flag, BGP_ATTR_MULTI_EXIT_DISC)) {
		if (CHECK_FLAG(new->flag, BGP_ATTR_LOCAL_PREF)) {
			if (new->local_pref > 255)
				new->med = 0;
			else
				new->med = 255 - new->local_pref;
		} else {
			new->med = 255; /* shouldn't happen */
		}
		new->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	}

	/*
	 * "new" is now a ghost attr:
	 *  - it owns an "extra" struct
	 *  - it owns any non-interned parts
	 *  - any references to interned parts are not counted
	 *
	 * Caller should, after using the attr, call:
	 *  - bgp_attr_flush() to free non-interned parts
	 */

	return 0;
}

/*
 * "Adding a Route" export process
 */
void vnc_direct_bgp_add_prefix(struct bgp *bgp,
			       struct rfapi_import_table *import_table,
			       struct agg_node *rn)
{
	struct attr attr = {0};
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	const struct prefix *p = agg_node_get_prefix(rn);
	afi_t afi = family2afi(p->family);

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi of route node",
			 __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	if (!VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	if (!listcount(bgp->rfapi_cfg->rfg_export_direct_bgp_l)) {
		vnc_zlog_debug_verbose(
			"%s: no bgp-direct export nve group, skipping",
			__func__);
		return;
	}

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);
	/* TBD set some configured med, see add_vnc_route() */

	vnc_zlog_debug_verbose(
		"%s: looping over nve-groups in direct-bgp export list",
		__func__);

	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			       nnode, rfgn)) {

		struct listnode *ln;

		/*
		 * If nve group is not defined yet, skip it
		 */
		if (!rfgn->rfg)
			continue;

		/*
		 * If the nve group uses a different import table, skip it
		 */
		if (import_table != rfgn->rfg->rfapi_import_table)
			continue;

		/*
		 * if no NVEs currently associated with this group, skip it
		 */
		if (rfgn->rfg->type != RFAPI_GROUP_CFG_VRF && !rfgn->rfg->nves)
			continue;

		/*
		 * per-nve-group prefix list check
		 */
		if (rfgn->rfg->plist_export_bgp[afi]) {
			if (prefix_list_apply(rfgn->rfg->plist_export_bgp[afi],
					      p)
			    == PREFIX_DENY)

				continue;
		}

		if (rfgn->rfg->type == RFAPI_GROUP_CFG_VRF) {
			vnc_direct_add_rn_group_rd(bgp, rfgn->rfg, rn, &attr,
						   afi, rfgn->rfg->rfd);
			/*
			 * yuck!
			 *  - but consistent with rest of function
			 */
			continue;
		}
		/*
		 * For each NVE that is assigned to the export nve group,
		 * generate
		 * a route with that NVE as its next hop
		 */
		for (ln = listhead(rfgn->rfg->nves); ln;
		     ln = listnextnode(ln)) {
			vnc_direct_add_rn_group_rd(bgp, rfgn->rfg, rn, &attr,
						   afi, listgetdata(ln));
		}
	}

	aspath_unintern(&attr.aspath);
}

/*
 * "Withdrawing a Route" export process
 */
void vnc_direct_bgp_del_prefix(struct bgp *bgp,
			       struct rfapi_import_table *import_table,
			       struct agg_node *rn)
{
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	const struct prefix *p = agg_node_get_prefix(rn);
	afi_t afi = family2afi(p->family);

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi route node",
			 __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	if (!VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	if (!listcount(bgp->rfapi_cfg->rfg_export_direct_bgp_l)) {
		vnc_zlog_debug_verbose(
			"%s: no bgp-direct export nve group, skipping",
			__func__);
		return;
	}

	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			       nnode, rfgn)) {

		struct listnode *ln;

		/*
		 * If nve group is not defined yet, skip it
		 */
		if (!rfgn->rfg)
			continue;

		/*
		 * if no NVEs currently associated with this group, skip it
		 */
		if (rfgn->rfg->type != RFAPI_GROUP_CFG_VRF && !rfgn->rfg->nves)
			continue;

		/*
		 * If the nve group uses a different import table,
		 * skip it
		 */
		if (import_table != rfgn->rfg->rfapi_import_table)
			continue;

		if (rfgn->rfg->type == RFAPI_GROUP_CFG_VRF) {
			struct prefix nhp;
			struct rfapi_descriptor *irfd;

			irfd = rfgn->rfg->rfd;

			if (rfapiRaddr2Qprefix(&irfd->vn_addr, &nhp))
				continue;

			bgp_withdraw(irfd->peer, p, /* prefix */
				     0,		    /* addpath_id */
				     afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
				     BGP_ROUTE_REDISTRIBUTE,
				     NULL, /* RD not used for unicast */
				     NULL, 0,
				     NULL); /* tag not used for unicast */
			/*
			 * yuck!
			 *  - but consistent with rest of function
			 */
			continue;
		}
		/*
		 * For each NVE that is assigned to the export nve group,
		 * generate
		 * a route with that NVE as its next hop
		 */
		for (ln = listhead(rfgn->rfg->nves); ln;
		     ln = listnextnode(ln)) {

			struct prefix nhp;
			struct rfapi_descriptor *irfd;

			irfd = listgetdata(ln);

			if (rfapiRaddr2Qprefix(&irfd->vn_addr, &nhp))
				continue;

			bgp_withdraw(irfd->peer, p, /* prefix */
				     0,		    /* addpath_id */
				     afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
				     BGP_ROUTE_REDISTRIBUTE,
				     NULL, /* RD not used for unicast */
				     NULL, 0,
				     NULL); /* tag not used for unicast */
		}
	}
}

void vnc_direct_bgp_add_nve(struct bgp *bgp, struct rfapi_descriptor *rfd)
{
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	struct rfapi_nve_group_cfg *rfg = rfd->rfg;
	afi_t afi = family2afi(rfd->vn_addr.addr_family);

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi of nve vn addr",
			 __func__);
		return;
	}

	if (!bgp)
		return;
	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}
	if (!VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	/*
	 * Loop over the list of NVE-Groups configured for
	 * exporting to direct-bgp and see if this new NVE's
	 * group is among them.
	 */
	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			       nnode, rfgn)) {

		/*
		 * Yes, this NVE's group is configured for export to direct-bgp
		 */
		if (rfgn->rfg == rfg) {

			struct agg_table *rt = NULL;
			struct agg_node *rn;
			struct attr attr = {0};
			struct rfapi_import_table *import_table;


			import_table = rfg->rfapi_import_table;

			if (afi == AFI_IP || afi == AFI_IP6) {
				rt = import_table->imported_vpn[afi];
			} else {
				flog_err(EC_LIB_DEVELOPMENT, "%s: bad afi %d",
					 __func__, afi);
				return;
			}

			bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);
			/* TBD set some configured med, see add_vnc_route() */

			/*
			 * Walk the NVE-Group's VNC Import table
			 */
			for (rn = agg_route_top(rt); rn;
			     rn = agg_route_next(rn)) {

				if (rn->info) {

					struct prefix nhp;
					struct rfapi_descriptor *irfd = rfd;
					struct attr hattr;
					struct attr *iattr;
					struct bgp_path_info info;
					const struct prefix *p =
						agg_node_get_prefix(rn);

					if (rfapiRaddr2Qprefix(&irfd->vn_addr,
							       &nhp))
						continue;

					/*
					 * per-nve-group prefix list check
					 */
					if (rfgn->rfg->plist_export_bgp[afi]) {
						if (prefix_list_apply(
							    rfgn->rfg->plist_export_bgp
								    [afi],
							    p)
						    == PREFIX_DENY)

							continue;
					}


					/*
					 * Construct new attribute set with
					 * NVE's VN addr as
					 * nexthop and without Tunnel Encap attr
					 */
					if (encap_attr_export(&hattr, &attr,
							      &nhp, rn))
						continue;

					if (rfgn->rfg->routemap_export_bgp) {
						route_map_result_t ret;
						info.peer = irfd->peer;
						info.attr = &hattr;
						ret = route_map_apply(
							rfgn->rfg
								->routemap_export_bgp,
							p, &info);
						if (ret == RMAP_DENYMATCH) {
							bgp_attr_flush(&hattr);
							continue;
						}
					}

					iattr = bgp_attr_intern(&hattr);
					bgp_attr_flush(&hattr);
					bgp_update(
						irfd->peer, p, /* prefix */
						0,	       /* addpath_id */
						iattr, /* bgp_update copies
							  it */
						afi, SAFI_UNICAST,
						ZEBRA_ROUTE_VNC_DIRECT,
						BGP_ROUTE_REDISTRIBUTE, NULL,
						/* RD not used for unicast */
						NULL,
						/* tag not used for unicast */
						0, 0, NULL); /* EVPN not used */

					bgp_attr_unintern(&iattr);
				}
			}

			aspath_unintern(&attr.aspath);
		}
	}
}


void vnc_direct_bgp_del_nve(struct bgp *bgp, struct rfapi_descriptor *rfd)
{
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	struct rfapi_nve_group_cfg *rfg = rfd->rfg;
	afi_t afi = family2afi(rfd->vn_addr.addr_family);

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi of nve vn addr",
			 __func__);
		return;
	}

	if (!bgp)
		return;
	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}
	if (!VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	/*
	 * Loop over the list of NVE-Groups configured for
	 * exporting to direct-bgp and see if this new NVE's
	 * group is among them.
	 */
	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			       nnode, rfgn)) {

		/*
		 * Yes, this NVE's group is configured for export to direct-bgp
		 */
		if (rfg && rfgn->rfg == rfg) {

			struct agg_table *rt = NULL;
			struct agg_node *rn;
			struct rfapi_import_table *import_table;

			import_table = rfg->rfapi_import_table;

			if (afi == AFI_IP || afi == AFI_IP6) {
				rt = import_table->imported_vpn[afi];
			} else {
				flog_err(EC_LIB_DEVELOPMENT, "%s: bad afi %d",
					 __func__, afi);
				return;
			}

			/*
			 * Walk the NVE-Group's VNC Import table
			 */
			for (rn = agg_route_top(rt); rn;
			     rn = agg_route_next(rn)) {

				if (rn->info) {
					const struct prefix *p =
						agg_node_get_prefix(rn);
					struct prefix nhp;
					struct rfapi_descriptor *irfd = rfd;

					if (rfapiRaddr2Qprefix(&irfd->vn_addr,
							       &nhp))
						continue;

					bgp_withdraw(irfd->peer, p, /* prefix */
						     0,	   /* addpath_id */
						     afi, SAFI_UNICAST,
						     ZEBRA_ROUTE_VNC_DIRECT,
						     BGP_ROUTE_REDISTRIBUTE,
						     NULL, /* RD not used for
							      unicast */
						     NULL, 0, NULL); /* tag not
								     used for
								     unicast */
				}
			}
		}
	}
}

static void vnc_direct_add_rn_group_rd(struct bgp *bgp,
				       struct rfapi_nve_group_cfg *rfg,
				       struct agg_node *rn, struct attr *attr,
				       afi_t afi, struct rfapi_descriptor *irfd)
{
	struct prefix nhp;
	struct bgp_path_info info;
	struct attr hattr;
	struct attr *iattr;
	const struct prefix *p = agg_node_get_prefix(rn);

	if (irfd == NULL && rfg->type != RFAPI_GROUP_CFG_VRF) {
		/* need new rfapi_handle, for peer strcture
		 * -- based on vnc_add_vrf_prefi */
		assert(rfg->rfd == NULL);

		if (!rfg->rt_export_list || !rfg->rfapi_import_table) {
			vnc_zlog_debug_verbose(
				"%s: VRF \"%s\" is missing RT import/export configuration.",
				__func__, rfg->name);
			return;
		}
		if (!rfg->rd.prefixlen) {
			vnc_zlog_debug_verbose(
				"%s: VRF \"%s\" is missing RD configuration.",
				__func__, rfg->name);
			return;
		}
		if (rfg->label > MPLS_LABEL_MAX) {
			vnc_zlog_debug_verbose(
				"%s: VRF \"%s\" is missing default label configuration.",
				__func__, rfg->name);
			return;
		}

		irfd = XCALLOC(MTYPE_RFAPI_DESC,
			       sizeof(struct rfapi_descriptor));
		irfd->bgp = bgp;
		rfg->rfd = irfd;
		/*
		 * leave most fields empty as will get from (dynamic) config
		 * when needed
		 */
		irfd->default_tunneltype_option.type = BGP_ENCAP_TYPE_MPLS;
		irfd->cookie = rfg;
		if (rfg->vn_prefix.family
		    && !CHECK_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF)) {
			rfapiQprefix2Raddr(&rfg->vn_prefix, &irfd->vn_addr);
		} else {
			memset(&irfd->vn_addr, 0, sizeof(struct rfapi_ip_addr));
			irfd->vn_addr.addr_family = AF_INET;
			irfd->vn_addr.addr.v4 = bgp->router_id;
		}
		irfd->un_addr = irfd->vn_addr; /* sigh, need something in UN for
						lookups */
		vnc_zlog_debug_verbose("%s: Opening RFD for VRF %s", __func__,
				       rfg->name);
		rfapi_init_and_open(bgp, irfd, rfg);
	}

	if (irfd == NULL || rfapiRaddr2Qprefix(&irfd->vn_addr, &nhp))
		return;

	/*
	 * Construct new attribute set with NVE's VN
	 * addr as
	 * nexthop and without Tunnel Encap attr
	 */
	if (encap_attr_export(&hattr, attr, &nhp, rn))
		return;

	if (VNC_DEBUG(EXPORT_BGP_DIRECT_ADD)) {
		vnc_zlog_debug_any("%s: attr follows", __func__);
		rfapiPrintAttrPtrs(NULL, attr);
		vnc_zlog_debug_any("%s: hattr follows", __func__);
		rfapiPrintAttrPtrs(NULL, &hattr);
	}

	if (rfg->routemap_export_bgp) {
		route_map_result_t ret;

		info.peer = irfd->peer;
		info.attr = &hattr;
		ret = route_map_apply(rfg->routemap_export_bgp, p, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			vnc_zlog_debug_verbose(
				"%s: route map says DENY, so not calling bgp_update",
				__func__);
			return;
		}
	}

	if (VNC_DEBUG(EXPORT_BGP_DIRECT_ADD)) {
		vnc_zlog_debug_any("%s: hattr after route_map_apply:",
				   __func__);
		rfapiPrintAttrPtrs(NULL, &hattr);
	}
	iattr = bgp_attr_intern(&hattr);
	bgp_attr_flush(&hattr);

	bgp_update(irfd->peer, p, /* prefix */
		   0,		  /* addpath_id */
		   iattr,	  /* bgp_update copies it */
		   afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
		   BGP_ROUTE_REDISTRIBUTE, NULL, /* RD not used for unicast */
		   NULL,			 /* tag not used for unicast */
		   0, 0, NULL);			 /* EVPN not used */

	bgp_attr_unintern(&iattr);

	return;
}

/*
 * Caller is responsible for ensuring that the specified nve-group
 * is actually part of the list of exported nve groups.
 */
static void vnc_direct_bgp_add_group_afi(struct bgp *bgp,
					 struct rfapi_nve_group_cfg *rfg,
					 afi_t afi)
{
	struct agg_table *rt = NULL;
	struct agg_node *rn;
	struct attr attr = {0};
	struct rfapi_import_table *import_table;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	import_table = rfg->rfapi_import_table;
	if (!import_table) {
		vnc_zlog_debug_verbose(
			"%s: import table not defined, returning", __func__);
		return;
	}

	if (afi == AFI_IP || afi == AFI_IP6) {
		rt = import_table->imported_vpn[afi];
	} else {
		flog_err(EC_LIB_DEVELOPMENT, "%s: bad afi %d", __func__, afi);
		return;
	}

	if (!rfg->nves && rfg->type != RFAPI_GROUP_CFG_VRF) {
		vnc_zlog_debug_verbose("%s: no NVEs in this group", __func__);
		return;
	}

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);
	/* TBD set some configured med, see add_vnc_route() */

	/*
	 * Walk the NVE-Group's VNC Import table
	 */
	for (rn = agg_route_top(rt); rn; rn = agg_route_next(rn)) {

		if (rn->info) {
			const struct prefix *p = agg_node_get_prefix(rn);
			struct listnode *ln;

			/*
			 * per-nve-group prefix list check
			 */
			if (rfg->plist_export_bgp[afi]) {
				if (prefix_list_apply(
					    rfg->plist_export_bgp[afi], p)
				    == PREFIX_DENY)

					continue;
			}
			if (rfg->type == RFAPI_GROUP_CFG_VRF) {
				vnc_direct_add_rn_group_rd(bgp, rfg, rn, &attr,
							   afi, rfg->rfd);
				/*
				 * yuck!
				 *  - but consistent with rest of function
				 */
				continue;
			}
			/*
			 * For each NVE that is assigned to the export nve
			 * group, generate
			 * a route with that NVE as its next hop
			 */
			for (ln = listhead(rfg->nves); ln;
			     ln = listnextnode(ln)) {
				vnc_direct_add_rn_group_rd(bgp, rfg, rn, &attr,
							   afi,
							   listgetdata(ln));
			}
		}
	}

	aspath_unintern(&attr.aspath);
}


/*
 * Caller is responsible for ensuring that the specified nve-group
 * is actually part of the list of exported nve groups.
 */
void vnc_direct_bgp_add_group(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg)
{
	vnc_direct_bgp_add_group_afi(bgp, rfg, AFI_IP);
	vnc_direct_bgp_add_group_afi(bgp, rfg, AFI_IP6);
}

static void vnc_direct_del_rn_group_rd(struct bgp *bgp,
				       struct rfapi_nve_group_cfg *rfg,
				       struct agg_node *rn, afi_t afi,
				       struct rfapi_descriptor *irfd)
{
	if (irfd == NULL)
		return;

	bgp_withdraw(irfd->peer, agg_node_get_prefix(rn), /* prefix */
		     0,					  /* addpath_id */
		     afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT,
		     BGP_ROUTE_REDISTRIBUTE, NULL, /* RD not used for unicast */
		     NULL, 0, NULL); /* tag not used for unicast */
	return;
}

/*
 * Caller is responsible for ensuring that the specified nve-group
 * was actually part of the list of exported nve groups.
 */
static void vnc_direct_bgp_del_group_afi(struct bgp *bgp,
					 struct rfapi_nve_group_cfg *rfg,
					 afi_t afi)
{
	struct agg_table *rt = NULL;
	struct agg_node *rn;
	struct rfapi_import_table *import_table;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	import_table = rfg->rfapi_import_table;
	if (!import_table) {
		vnc_zlog_debug_verbose(
			"%s: import table not defined, returning", __func__);
		return;
	}

	rt = import_table->imported_vpn[afi];

	if (!rfg->nves && rfg->type != RFAPI_GROUP_CFG_VRF) {
		vnc_zlog_debug_verbose("%s: no NVEs in this group", __func__);
		return;
	}

	/*
	 * Walk the NVE-Group's VNC Import table
	 */
	for (rn = agg_route_top(rt); rn; rn = agg_route_next(rn))
		if (rn->info) {
			if (rfg->type == RFAPI_GROUP_CFG_VRF)
				vnc_direct_del_rn_group_rd(bgp, rfg, rn, afi,
							   rfg->rfd);
			else {
				struct listnode *ln;

				/*
				 * For each NVE that is assigned to the export
				 * nve
				 * group, generate
				 * a route with that NVE as its next hop
				 */
				for (ln = listhead(rfg->nves); ln;
				     ln = listnextnode(ln))
					vnc_direct_del_rn_group_rd(
						bgp, rfg, rn, afi,
						listgetdata(ln));
			}
		}
}

/*
 * Caller is responsible for ensuring that the specified nve-group
 * was actually part of the list of exported nve groups.
 */
void vnc_direct_bgp_del_group(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg)
{
	vnc_direct_bgp_del_group_afi(bgp, rfg, AFI_IP);
	vnc_direct_bgp_del_group_afi(bgp, rfg, AFI_IP6);
}

void vnc_direct_bgp_reexport_group_afi(struct bgp *bgp,
				       struct rfapi_nve_group_cfg *rfg,
				       afi_t afi)
{
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;

	if (VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		/*
		 * look in the list of currently-exported groups
		 */
		for (ALL_LIST_ELEMENTS_RO(
			     bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			     rfgn)) {

			if (rfgn->rfg == rfg) {
				/*
				 * If it matches, reexport it
				 */
				vnc_direct_bgp_del_group_afi(bgp, rfg, afi);
				vnc_direct_bgp_add_group_afi(bgp, rfg, afi);
				break;
			}
		}
	}
}


static void vnc_direct_bgp_unexport_table(afi_t afi, struct agg_table *rt,
					  struct list *nve_list)
{
	if (nve_list) {

		struct agg_node *rn;

		for (rn = agg_route_top(rt); rn; rn = agg_route_next(rn)) {

			if (rn->info) {

				struct listnode *hln;
				struct rfapi_descriptor *irfd;

				for (ALL_LIST_ELEMENTS_RO(nve_list, hln,
							  irfd)) {

					bgp_withdraw(irfd->peer,
						     agg_node_get_prefix(rn),
						     0,	   /* addpath_id */
						     afi, SAFI_UNICAST,
						     ZEBRA_ROUTE_VNC_DIRECT,
						     BGP_ROUTE_REDISTRIBUTE,
						     NULL, /* RD not used for
							      unicast */
						     NULL, 0, NULL); /* tag not
								     used for
								     unicast,
								     EVPN
								     neither */
				}
			}
		}
	}
}

static void import_table_to_nve_list_direct_bgp(struct bgp *bgp,
						struct rfapi_import_table *it,
						struct list **nves,
						uint8_t family)
{
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;

	/*
	 * Loop over the list of NVE-Groups configured for
	 * exporting to direct-bgp.
	 *
	 * Build a list of NVEs that use this import table
	 */
	*nves = NULL;
	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {

		/*
		 * If this NVE-Group's import table matches the current one
		 */
		if (rfgn->rfg && rfgn->rfg->rfapi_import_table == it) {
			if (rfgn->rfg->nves)
				nve_group_to_nve_list(rfgn->rfg, nves, family);
			else if (rfgn->rfg->rfd
				 && rfgn->rfg->type == RFAPI_GROUP_CFG_VRF) {
				if (!*nves)
					*nves = list_new();
				listnode_add(*nves, rfgn->rfg->rfd);
			}
		}
	}
}

void vnc_direct_bgp_vpn_enable(struct bgp *bgp, afi_t afi)
{
	struct listnode *rfgn;
	struct rfapi_nve_group_cfg *rfg;

	if (!bgp)
		return;

	if (!VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	/*
	 * Policy is applied per-nve-group, so we need to iterate
	 * over the groups to add everything.
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->nve_groups_sequential, rfgn,
				  rfg)) {

		/*
		 * contains policy management
		 */
		vnc_direct_bgp_add_group_afi(bgp, rfg, afi);
	}
}


void vnc_direct_bgp_vpn_disable(struct bgp *bgp, afi_t afi)
{
	struct rfapi_import_table *it;
	uint8_t family = afi2family(afi);

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (!bgp)
		return;

	if (!bgp->rfapi) {
		vnc_zlog_debug_verbose("%s: rfapi not initialized", __func__);
		return;
	}

	if (!family || (afi != AFI_IP && afi != AFI_IP6)) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	for (it = bgp->rfapi->imports; it; it = it->next) {

		struct list *nve_list = NULL;

		import_table_to_nve_list_direct_bgp(bgp, it, &nve_list, family);

		if (nve_list) {
			vnc_direct_bgp_unexport_table(
				afi, it->imported_vpn[afi], nve_list);
			list_delete(&nve_list);
		}
	}
}


/***********************************************************************
 * Export methods that proxy nexthop END
 ***********************************************************************/


/***********************************************************************
 * Export methods that preserve original nexthop BEGIN
 * rh = "registering nve"
 ***********************************************************************/


/*
 * "Adding a Route" export process
 * TBD do we need to check bpi->type and bpi->sub_type here, or does
 * caller do it?
 */
void vnc_direct_bgp_rh_add_route(struct bgp *bgp, afi_t afi,
				 const struct prefix *prefix, struct peer *peer,
				 struct attr *attr)
{
	struct vnc_export_info *eti;
	struct attr hattr;
	struct rfapi_cfg *hc;
	struct attr *iattr;

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi of route node",
			 __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	if (!VNC_EXPORT_BGP_RH_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp RH mode not enabled, skipping",
			__func__);
		return;
	}

	/*
	 * prefix list check
	 */
	if (hc->plist_export_bgp[afi]) {
		if (prefix_list_apply(hc->plist_export_bgp[afi], prefix)
		    == PREFIX_DENY)
			return;
	}

	/*
	 * Construct new attribute set with NVE's VN addr as
	 * nexthop and without Tunnel Encap attr
	 */
	if (encap_attr_export(&hattr, attr, NULL, NULL))
		return;
	if (hc->routemap_export_bgp) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = peer;
		info.attr = &hattr;
		ret = route_map_apply(hc->routemap_export_bgp, prefix, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			return;
		}
	}

	iattr = bgp_attr_intern(&hattr);
	bgp_attr_flush(&hattr);

	/*
	 * record route information that we will need to expire
	 * this route
	 */
	eti = vnc_eti_get(bgp, EXPORT_TYPE_BGP, prefix, peer,
			  ZEBRA_ROUTE_VNC_DIRECT_RH, BGP_ROUTE_REDISTRIBUTE);
	rfapiGetVncLifetime(attr, &eti->lifetime);
	eti->lifetime = rfapiGetHolddownFromLifetime(eti->lifetime);

	/*
	 * export expiration timer is already running on
	 * this route: cancel it
	 */
	EVENT_OFF(eti->timer);

	bgp_update(peer, prefix, /* prefix */
		   0,		 /* addpath_id */
		   iattr,	/* bgp_update copies this attr */
		   afi, SAFI_UNICAST, ZEBRA_ROUTE_VNC_DIRECT_RH,
		   BGP_ROUTE_REDISTRIBUTE, NULL, /* RD not used for unicast */
		   NULL,	/* tag not used for unicast, EVPN neither */
		   0, 0, NULL); /* EVPN not used */
	bgp_attr_unintern(&iattr);
}

static void vncExportWithdrawTimer(struct event *t)
{
	struct vnc_export_info *eti = EVENT_ARG(t);
	const struct prefix *p = agg_node_get_prefix(eti->node);

	/*
	 * withdraw the route
	 */
	bgp_withdraw(eti->peer, p, 0, /* addpath_id */
		     family2afi(p->family), SAFI_UNICAST, eti->type,
		     eti->subtype, NULL, /* RD not used for unicast */
		     NULL, 0,
		     NULL); /* tag not used for unicast, EVPN neither */

	/*
	 * Free the eti
	 */
	vnc_eti_delete(eti);
}

/*
 * "Withdrawing a Route" export process
 * TBD do we need to check bpi->type and bpi->sub_type here, or does
 * caller do it?
 */
void vnc_direct_bgp_rh_del_route(struct bgp *bgp, afi_t afi,
				 const struct prefix *prefix, struct peer *peer)
{
	struct vnc_export_info *eti;

	if (!afi) {
		flog_err(EC_LIB_DEVELOPMENT, "%s: can't get afi route node",
			 __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->redist[afi][ZEBRA_ROUTE_VNC_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of VNC direct routes is off",
			__func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}
	if (!VNC_EXPORT_BGP_RH_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export-to-bgp group mode not enabled, skipping",
			__func__);
		return;
	}

	eti = vnc_eti_get(bgp, EXPORT_TYPE_BGP, prefix, peer,
			  ZEBRA_ROUTE_VNC_DIRECT_RH, BGP_ROUTE_REDISTRIBUTE);

	if (!eti->timer && eti->lifetime <= INT32_MAX) {
		eti->timer = NULL;
		event_add_timer(bm->master, vncExportWithdrawTimer, eti,
				eti->lifetime, &eti->timer);
		vnc_zlog_debug_verbose(
			"%s: set expiration timer for %u seconds", __func__,
			eti->lifetime);
	}
}


void vnc_direct_bgp_rh_vpn_enable(struct bgp *bgp, afi_t afi)
{
	struct prefix_rd prd;
	struct bgp_dest *pdest;
	struct rfapi_cfg *hc;

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (!bgp)
		return;

	if (!(hc = bgp->rfapi_cfg))
		return;

	if (!VNC_EXPORT_BGP_RH_ENABLED(bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose(
			"%s: export of RH routes not enabled, skipping",
			__func__);
		return;
	}

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	/*
	 * Go through the entire BGP VPN table and export to BGP unicast.
	 */

	vnc_zlog_debug_verbose("%s: starting RD loop", __func__);

	/* Loop over all the RDs */
	for (pdest = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); pdest;
	     pdest = bgp_route_next(pdest)) {

		struct bgp_table *table;
		struct bgp_dest *dest;
		struct bgp_path_info *ri;
		const struct prefix *pdest_p = bgp_dest_get_prefix(pdest);

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;
		memcpy(prd.val, pdest_p->u.val, 8);

		/* This is the per-RD table of prefixes */
		table = bgp_dest_get_bgp_table_info(pdest);

		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p;

			/*
			 * skip prefix list check if no routes here
			 */
			if (!bgp_dest_has_bgp_path_info_data(dest))
				continue;

			vnc_zlog_debug_verbose("%s: checking prefix %pBD",
					       __func__, dest);

			dest_p = bgp_dest_get_prefix(dest);

			/*
			 * prefix list check
			 */
			if (hc->plist_export_bgp[afi]) {
				if (prefix_list_apply(hc->plist_export_bgp[afi],
						      dest_p)
				    == PREFIX_DENY) {

					vnc_zlog_debug_verbose(
						"%s:   prefix list says DENY",
						__func__);
					continue;
				}
			}

			for (ri = bgp_dest_get_bgp_path_info(dest); ri;
			     ri = ri->next) {

				vnc_zlog_debug_verbose("%s: ri->sub_type: %d",
						       __func__, ri->sub_type);

				if (ri->sub_type == BGP_ROUTE_NORMAL
				    || ri->sub_type == BGP_ROUTE_RFP) {

					struct vnc_export_info *eti;
					struct attr hattr;
					struct attr *iattr;

					/*
					 * Construct new attribute set with
					 * NVE's VN addr as
					 * nexthop and without Tunnel Encap attr
					 */
					if (encap_attr_export(&hattr, ri->attr,
							      NULL, NULL)) {
						vnc_zlog_debug_verbose(
							"%s:   encap_attr_export failed",
							__func__);
						continue;
					}

					if (hc->routemap_export_bgp) {
						struct bgp_path_info info;
						route_map_result_t ret;

						memset(&info, 0, sizeof(info));
						info.peer = ri->peer;
						info.attr = &hattr;
						ret = route_map_apply(
							hc->routemap_export_bgp,
							dest_p, &info);
						if (ret == RMAP_DENYMATCH) {
							bgp_attr_flush(&hattr);
							vnc_zlog_debug_verbose(
								"%s:   route map says DENY",
								__func__);
							continue;
						}
					}

					iattr = bgp_attr_intern(&hattr);
					bgp_attr_flush(&hattr);

					/*
					 * record route information that we will
					 * need to expire
					 * this route
					 */
					eti = vnc_eti_get(
						bgp, EXPORT_TYPE_BGP, dest_p,
						ri->peer,
						ZEBRA_ROUTE_VNC_DIRECT_RH,
						BGP_ROUTE_REDISTRIBUTE);
					rfapiGetVncLifetime(ri->attr,
							    &eti->lifetime);

					/*
					 * export expiration timer is
					 * already running on
					 * this route: cancel it
					 */
					EVENT_OFF(eti->timer);

					vnc_zlog_debug_verbose(
						"%s: calling bgp_update",
						__func__);

					bgp_update(
						ri->peer, dest_p, /* prefix */
						0,     /* addpath_id */
						iattr, /* bgp_update copies
							  it */
						AFI_IP, SAFI_UNICAST,
						ZEBRA_ROUTE_VNC_DIRECT_RH,
						BGP_ROUTE_REDISTRIBUTE, NULL,
						/* RD not used for unicast */
						NULL,
						/* tag not used for unicast,
						   or EVPN */
						0, 0, NULL); /* EVPN not used */

					bgp_attr_unintern(&iattr);
				}
			}
		}
	}
}

void vnc_direct_bgp_rh_vpn_disable(struct bgp *bgp, afi_t afi)
{
	struct bgp_dest *dest;

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (!bgp)
		return;

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi: %d", __func__, afi);
		return;
	}

	/*
	 * Go through the entire BGP unicast table and remove routes that
	 * originated from us
	 */
	for (dest = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); dest;
	     dest = bgp_route_next(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);
		struct bgp_path_info *ri;
		struct bgp_path_info *next;

		for (ri = bgp_dest_get_bgp_path_info(dest), next = NULL; ri;
		     ri = next) {

			next = ri->next;

			if (ri->type == ZEBRA_ROUTE_VNC_DIRECT_RH
			    && ri->sub_type == BGP_ROUTE_REDISTRIBUTE) {

				struct vnc_export_info *eti;

				/*
				 * Delete routes immediately (no timer)
				 */
				eti = vnc_eti_checktimer(
					bgp, EXPORT_TYPE_BGP, dest_p, ri->peer,
					ZEBRA_ROUTE_VNC_DIRECT_RH,
					BGP_ROUTE_REDISTRIBUTE);
				if (eti) {
					EVENT_OFF(eti->timer);
					vnc_eti_delete(eti);
				}

				bgp_withdraw(ri->peer, dest_p, /* prefix */
					     0,		       /* addpath_id */
					     AFI_IP, SAFI_UNICAST,
					     ZEBRA_ROUTE_VNC_DIRECT_RH,
					     BGP_ROUTE_REDISTRIBUTE,
					     NULL, /* RD not used for unicast */
					     NULL, 0, NULL); /* tag not used for
							     unicast, EVPN
							     neither */
			}
		}
	}
}

void vnc_direct_bgp_rh_reexport(struct bgp *bgp, afi_t afi)
{
	if (VNC_EXPORT_BGP_RH_ENABLED(bgp->rfapi_cfg)) {
		vnc_direct_bgp_rh_vpn_disable(bgp, afi);
		vnc_direct_bgp_rh_vpn_enable(bgp, afi);
	}
}

/***********************************************************************
 * Generic Export methods
 ***********************************************************************/

/*
 * Assumes the correct mode bits are already turned on. Thus it
 * is OK to call this function from, e.g., bgp_redistribute_set()
 * without caring if export is enabled or not
 */
void vnc_export_bgp_enable(struct bgp *bgp, afi_t afi)
{
	if (!bgp->rfapi_cfg)
		return;

	switch (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) {
	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_NONE:
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP:
		vnc_direct_bgp_vpn_enable(bgp, afi);
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH:
		vnc_direct_bgp_rh_vpn_enable(bgp, afi);
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE:
		vnc_direct_bgp_vpn_enable_ce(bgp, afi);
		break;
	}
}

void vnc_export_bgp_disable(struct bgp *bgp, afi_t afi)
{
	if (!bgp->rfapi_cfg)
		return;

	switch (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) {
	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_NONE:
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP:
		vnc_direct_bgp_vpn_disable(bgp, afi);
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH:
		vnc_direct_bgp_rh_vpn_disable(bgp, afi);
		break;

	case BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE:
		vnc_direct_bgp_vpn_disable_ce(bgp, afi);
		break;
	}
}

void vnc_export_bgp_prechange(struct bgp *bgp)
{
	vnc_export_bgp_disable(bgp, AFI_IP);
	vnc_export_bgp_disable(bgp, AFI_IP6);
}

void vnc_export_bgp_postchange(struct bgp *bgp)
{
	vnc_export_bgp_enable(bgp, AFI_IP);
	vnc_export_bgp_enable(bgp, AFI_IP6);
}

void vnc_direct_bgp_reexport(struct bgp *bgp, afi_t afi)
{
	vnc_export_bgp_disable(bgp, afi);
	vnc_export_bgp_enable(bgp, afi);
}
