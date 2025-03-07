// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Route-target constrain feature
 * Copyright (C) 2025 Cisco Systems Inc.
 */

#include "lib/zebra.h"
#include "lib/typesafe.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rtc.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_ecommunity.h"

/* RTC per-peer filtering */
DEFINE_MTYPE_STATIC(BGPD, BGP_RTC, "RTC data");

static int rtc_peer_entry_cmp(const struct peer_rtc_entry *e1,
			      const struct peer_rtc_entry *e2);
DECLARE_RBTREE_UNIQ(rtc_filter, struct peer_rtc_entry, rblink,
		    rtc_peer_entry_cmp);

/* Populate RTC prefix with RT data from 'as' and 'rtval' */
static void rtc_prefix_from_rt(struct prefix *p, uint32_t as_num,
			       const uint8_t *rtval, int prefixlen);
/* Helper to create static advertisement for RTC prefix */
static void rtc_advertise_static(struct bgp *bgp, const struct prefix *p);
/* Populate 'p' with RT ecomm value for lookup/comparison */
static void rtc_prefix_from_eval(struct prefix_rtc *p,
				 const struct ecommunity_val *eval);

/* VPN afi/safis */
static struct {
	afi_t afi;
	safi_t safi;
} rtc_safis[] = {
	{AFI_IP, SAFI_MPLS_VPN},
	{AFI_IP6, SAFI_MPLS_VPN},
	{AFI_L2VPN, SAFI_EVPN},
	{AFI_UNSPEC, 0}
};


/*
 * Helper to form RTC prefix from RT data
 */
static void rtc_prefix_from_rt(struct prefix *p, uint32_t as_num,
			       const uint8_t *rtval, int prefixlen)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_RTC;
	p->prefixlen = prefixlen;
	p->u.prefix_rtc.origin_as = as_num;
	memcpy(p->u.prefix_rtc.route_target, rtval, 8);
}

/*
 * Helper to create static advertisement for RTC prefix
 */
static void rtc_advertise_static(struct bgp *bgp, const struct prefix *p)
{
	struct bgp_static *bgp_static;

	/* Set up static route context */
	bgp_static = bgp_static_new();
	bgp_static->backdoor = 0;
	bgp_static->valid = 0;
	bgp_static->igpmetric = 0;
	bgp_static->igpnexthop.s_addr = INADDR_ANY;
	bgp_static->label = MPLS_INVALID_LABEL;
	bgp_static->label_index = BGP_INVALID_LABEL_INDEX;

	bgp_static_update(bgp, p, bgp_static, AFI_IP, SAFI_RTC);
}

/*
 * Helper to check whether some instance other than 'bgp_orig' is using
 * 'rtval'. When an RT is removed from an instance, we don't want to remove
 * the RTC rib entry if someone else is still using the RT.
 */
static bool rtc_check_rt(const struct bgp *bgp_orig,
			 const struct ecommunity_val *rtval)
{
	bool ret = true;
	struct bgp *bgp_evpn;
	struct bgp *tbgp;
	struct bgpevpn *evpn;
	struct listnode *node, *nnode;
	struct vrf_irt_node *virt;
	struct vrf_irt_node vtmp;
	struct irt_node *irt;
	struct irt_node tmp;
	struct ecommunity *ecomm;
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;
	afi_t afis[] = {AFI_IP, AFI_IP6, AFI_L2VPN, AFI_MAX};
	int i;

	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn) {
		/* Check EVPN VNI hash */
		memset(&tmp, 0, sizeof(tmp));
		memcpy(&tmp.rt, rtval->val, ECOMMUNITY_SIZE);
		irt = hash_lookup(bgp_evpn->import_rt_hash, &tmp);
		if (irt) {
			for (ALL_LIST_ELEMENTS(irt->vnis, node, nnode, evpn)) {
				if (evpn->bgp_vrf != bgp_orig)
					goto done;
			}
		}

		/* Check EVPN VRF hash */
		memset(&vtmp, 0, sizeof(vtmp));
		memcpy(&vtmp.rt, rtval->val, ECOMMUNITY_SIZE);
		virt = hash_lookup(bgp_evpn->vrf_import_rt_hash, &vtmp);
		if (virt) {
			for (ALL_LIST_ELEMENTS(virt->vrfs, node, nnode, tbgp)) {
				if (tbgp != bgp_orig)
					goto done;
			}
		}
	}

	/* Check other VRF bgps... */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, tbgp)) {
		/* Look for other bgps... */
		if (tbgp->inst_type != BGP_INSTANCE_TYPE_VRF ||
		    tbgp == bgp_orig)
			continue;

		/* Check for RT in this vrf. */
		for (i = 0; afis[i] != AFI_MAX; i++) {
			ecomm = tbgp->vpn_policy[afis[i]].rtlist[dir];
			if (ecomm &&
			    ecommunity_include_val(ecomm, (uint8_t *)rtval->val))
				goto done;
		}
	}

	ret = false;

done:
	return ret;
}

/*
 * Helper to advertise or withdraw one RT from 'orig_bgp'
 * for the RTC rib in the default instance 'bgp'
 */
static void rtc_add_del_one_rt(struct bgp *bgp, const struct bgp *orig_bgp,
			       const struct ecommunity_val *rtval, bool add_p)
{
	struct prefix p;
	struct bgp_dest *dest;

	/* TODO -- using max prefixlen for now */
	rtc_prefix_from_rt(&p, bgp->as, (const uint8_t *)rtval,
			   BGP_RTC_PREFIX_MAXLEN);

	if (bgp_debug_neighbor_events(NULL))
		zlog_debug("%s: %s %pFX", __func__, add_p ? "Add" : "Del", &p);

	if (add_p) {
		/* Create advertisement if necessary */
		dest = bgp_node_lookup(bgp->route[AFI_IP][SAFI_RTC], &p);
		if (dest == NULL)
			rtc_advertise_static(bgp, &p);
		else
			bgp_dest_unlock_node(dest);
	} else {
		/* Only remove RTC entry if this RT is not in use */
		if (!rtc_check_rt(orig_bgp, rtval))
			bgp_static_withdraw(bgp, &p, AFI_IP, SAFI_RTC, NULL);
	}
}

/*
 * Check RTC prefixes based on the RTs in 'ecomm' from 'orig_bgp',
 * install/uninstall in 'bgp'
 */
static void rtc_add_del_from_ecomm(struct bgp *bgp, const struct bgp *orig_bgp,
				   const struct ecommunity *ecomm, bool add_p)
{
	uint32_t idx;
	const struct ecommunity_val *ptr;

	/* Examine the list of RTs, handle each one */
	idx = 0;
	ptr = ecommunity_idx(ecomm, idx);
	while (ptr != NULL) {
		if (ptr->val[1] != ECOMMUNITY_ROUTE_TARGET)
			goto do_next;

		rtc_add_del_one_rt(bgp, orig_bgp, ptr, add_p);

do_next:
		idx++;
		ptr = ecommunity_idx(ecomm, idx);
	}
}

/* Hash iteration context struct */
struct rtc_rt_hash_ctx {
	struct bgp *bgp;
	bool add_p;
};

/* Hash iteration for EVPN L3 hash */
static void rtc_vrf_irt_hash_cb(struct hash_bucket *bkt, void *arg)
{
	struct rtc_rt_hash_ctx *ctx;
	struct vrf_irt_node *irt = bkt->data;

	ctx = arg;

	rtc_add_del_one_rt(ctx->bgp, ctx->bgp, &irt->rt, ctx->add_p);
}

/* Hash iteration for EVPN L2 hash */
static void rtc_irt_hash_cb(struct hash_bucket *bkt, void *arg)
{
	struct rtc_rt_hash_ctx *ctx;
	struct irt_node *irt = bkt->data;

	ctx = arg;

	rtc_add_del_one_rt(ctx->bgp, ctx->bgp, &irt->rt, ctx->add_p);
}

/*
 * Helper to install or withdraw evpn RTs, usually called when the
 * RTC safi peer is first activated or last deactivated.
 */
static void rtc_activate_evpn(struct bgp *bgp)
{
	struct bgp *bgp_evpn;
	struct rtc_rt_hash_ctx ctx = {};

	/* Locate evpn hashes */
	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn == NULL)
		return;

	/* There are, sigh, two different hashes and two slightly different
	 * objects in the hashes, so we need two different iterator callbacks.
	 */
	ctx.bgp = bgp;
	ctx.add_p = true;

	/* Iterate over L3/VRF hash */
	hash_iterate(bgp_evpn->vrf_import_rt_hash, rtc_vrf_irt_hash_cb, &ctx);

	/* Iterate over L2/VNI hash */
	hash_iterate(bgp_evpn->import_rt_hash, rtc_irt_hash_cb, &ctx);
}

/*
 * TODO -- if the SAFI is being unconfigured, with no peers,
 * we need to "force" removal of RTC prefixes,
 * even though the RTs will still be present: need
 * to iterate through the static entries in SAFI_RTC.
 */
static void rtc_safi_remove_all(struct bgp *bgp)
{
}

/*
 * Helper to handle de/installation of one bgp instance's RTs; default
 * instance is 'defbgp'.
 */
static int rtc_handle_one_bgp(struct bgp *bgp, struct bgp *defbgp, bool active)
{
	int ret = 0;
	struct ecommunity *ecomm;
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;
	afi_t afi_array[] = {AFI_IP, AFI_IP6, AFI_L2VPN, AFI_MAX};
	int i;

	if (bgp_debug_neighbor_events(NULL))
		zlog_debug("%s: %s RTC SAFI", bgp->name_pretty,
			   active ? "Activating" : "Deactivating");

	/* Check the VPN afi/safis' RTs */
	for (i = 0; afi_array[i] != AFI_MAX; i++) {
		ecomm = bgp->vpn_policy[afi_array[i]].rtlist[dir];
		if (ecomm)
			rtc_add_del_from_ecomm(defbgp, bgp, ecomm, active);
	}

	return ret;
}

/*
 * Finer-grained RT change for RTC: add or remove one RT, which aligns with some
 * of the vpn/evpn code.
 */
int bgp_rtc_import_change(struct bgp *bgp, const struct ecommunity_val *eval,
			  bool add_p)
{
	int ret = 0;
	struct bgp *defbgp; /* Default instance */

	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
		defbgp = bgp;
	} else {
		defbgp = bgp_get_default();
		if (defbgp == NULL)
			goto done;
	}

	/* Check for peer with active config in the RTC SAFI */
	if (!bgp_afi_safi_peer_exists(defbgp, AFI_IP, SAFI_RTC))
		goto done;

	/* Update the RTC rib */
	rtc_add_del_one_rt(defbgp, bgp, eval, add_p);

done:

	return ret;
}

/*
 * Handle peer activate/deactivate in the RTC safi
 */
int bgp_rtc_peer_update(struct peer *peer, afi_t afi, safi_t safi, bool active)
{
	int ret = 0;
	struct bgp *bgp = peer->bgp;
	struct bgp *tbgp;
	const struct peer *tpeer;
	struct listnode *node, *nnode;

	/* Must be a safi we care about. */
	if (afi != AFI_IP || safi != SAFI_RTC)
		goto done;

	/* We only use peers in the default instance. */
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		goto done;

	if (active) {
		/* If this is the first peer to be activated,
		 * examine the import RT lists for the VPN afi/safis;
		 * ensure they're represented in the RTC safi RIB.
		 */
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, tpeer)) {
			if (tpeer->afc[afi][safi] && tpeer != peer)
				goto done;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%pBP: First activated in RTC SAFI", peer);

		rtc_handle_one_bgp(bgp, bgp, true /*Active*/);

		/* Check the other bgp vrf instances. */
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, tbgp)) {
			if (tbgp->inst_type == BGP_INSTANCE_TYPE_VRF &&
			    tbgp != bgp)
				rtc_handle_one_bgp(tbgp, bgp, true);
		}

		/* Check the EVPN RT hashes too... */
		rtc_activate_evpn(bgp);

	} else {
		/* Clear any RTC filter data */
		bgp_rtc_peer_delete(peer);

		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, tpeer)) {
			if (tpeer->afc[afi][safi] && tpeer != peer)
				goto done;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%pBP: Last deactivated in RTC SAFI", peer);

		/* TODO -- if the SAFI is being unconfigured, with no peers,
		 * we need to force removal of RTC prefixes; need
		 * to iterate through the static entries in SAFI_RTC.
		 */
		rtc_safi_remove_all(bgp);
	}

done:

	return ret;
}

/*
 * RT import list change in instance 'bgp'; may trigger RTC SAFI changes.
 */
int bgp_rtc_import_update(struct bgp *bgp, const struct ecommunity *oldcomm,
			  const struct ecommunity *newcomm, bool update)
{
	int ret = 0;
	uint32_t oldidx;
	const struct ecommunity_val *eval;
	const uint8_t *ptr;
	struct bgp *defbgp; /* Default instance */

	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
		defbgp = bgp;
	} else {
		defbgp = bgp_get_default();
		if (defbgp == NULL)
			goto done;
	}

	/* Check for peer with active config in the RTC SAFI */
	if (!bgp_afi_safi_peer_exists(defbgp, AFI_IP, SAFI_RTC))
		goto done;

	if (bgp_debug_update(NULL, NULL, NULL, 1))
		zlog_debug("%s: oldcomm %p, newcomm %p, %s", __func__, oldcomm,
			   newcomm, update ? "update" : "del");

	if (update) {
		/* Add/update new RTC prefixes */
		rtc_add_del_from_ecomm(defbgp, bgp, newcomm, true /*Add*/);

		if (oldcomm) {
			/* Need to figure out what has changed in the RT list
			 * and remove prefixes to match.
			 */
			oldidx = 0;
			eval = ecommunity_idx(oldcomm, oldidx);
			while (eval != NULL) {
				ptr = (void *)eval;
				if (!ecommunity_include_val(newcomm, ptr)) {
					/* Remove prefix */
					rtc_add_del_one_rt(defbgp, bgp, eval,
							   false /*Del*/);
				}

				oldidx++;
				eval = ecommunity_idx(oldcomm, oldidx);
			}
		}
	} else {
		/* Delete: determine which RTs are being deleted. */
		rtc_add_del_from_ecomm(defbgp, bgp, oldcomm, false /*Del*/);
	}

done:
	return ret;
}

/*
 * RTC advertisement update from peer: maintain peer's outbound filter
 */

/*
 * Helper that creates a v6 prefix from an RTC prefix for comparison
 */
static void rtc_prefix_to_v6(struct prefix_ipv6 *p6,
			     const struct prefix_rtc *prtc)
{
	memset(p6, 0, sizeof(struct prefix_ipv6));
	p6->family = AF_INET6;
	if (prtc->prefixlen >= 32)
		p6->prefixlen = prtc->prefixlen - 32;
	memcpy(&(p6->prefix), prtc->prefix.route_target, ECOMMUNITY_SIZE);
}

/*
 * Comparison function for peer filter rbtree.
 * This is sort of complicated, because we use this rbtree for two purposes:
 *   1) it holds one entry for each RTC prefix from the peer
 *   2) it's used for prefix-style matching on the RTC prefixes' RT values
 *      during outbound filtering.
 * We compare the RTC prefixes in two parts: we test the RT "prefix" first,
 * then test the origin-AS.
 */
static int rtc_peer_entry_cmp(const struct peer_rtc_entry *e1,
			      const struct peer_rtc_entry *e2)
{
	int ret = 0;
	struct prefix_ipv6 p1 = {}, p2 = {};

	/* Note that we're not comparing the 'origin AS' part of the
	 * RTC prefix here: for outbound filtering, we only test the RT value.
	 */

	/* Make fake v6 prefixes so we can use the prefix lib
	 * and test the RT values in the RTC prefixes.
	 */
	rtc_prefix_to_v6(&p1, &(e1->p));
	rtc_prefix_to_v6(&p2, &(e2->p));

	/* Distinguish between exact match, say when managing a peer's
	 * RTC SAFI "routes", and an RT match, where "prefix" matching applies;
	 * also note special handling for the "default" prefix.
	 */
	/* e1 is the incoming key */
	if (CHECK_FLAG(e1->flags, PEER_RTC_ENTRY_FLAG_PREFIX)) {
		if (e2->p.prefixlen == 0 || e1->p.prefixlen == 0)
			return 0;

		/* Note the different argument ordering:
		 * "match" asks "does p2 contain p1?", but "cmp" compares
		 * p1 and p2.
		 */
		if (prefix_match(&p2, &p1))
			return 0;

		ret = prefix_cmp(&p1, &p2);

	} else {
		/* Look up an RTC prefix: compare RTs first, then order by
		 * the AS part of the prefix.
		 */
		ret = prefix_cmp(&p1, &p2);
		if (ret != 0)
			return ret;

		ret = e1->p.prefix.origin_as - e2->p.prefix.origin_as;
	}

	return ret;
}

/*
 * Helper for RTC prefix add: need to re-scan VPN routes and possibly
 * advertise some that were excluded.
 */
static void rtc_handle_peer_filter_add(struct peer *peer,
				       const struct peer_rtc_entry *rtc)
{
	/*
	 * TODO -- it would be better to be able to do less work, say
	 * by using a custom rib-walker and using a list of added RT
	 * filters.
	 */

	/* This api does schedule an event, so it's partially async */
	bgp_announce_route(peer, AFI_IP, SAFI_MPLS_VPN, false);
	bgp_announce_route(peer, AFI_IP6, SAFI_MPLS_VPN, false);
	bgp_announce_route(peer, AFI_L2VPN, SAFI_EVPN, false);
}

/*
 * Helper for filter-del processing: process the adj_out for one AFI/SAFI
 */
static void rtc_del_check_afi_safi(struct peer *peer, afi_t afi, safi_t safi)
{
	bool debug_p = false;
	struct update_subgroup *subgrp;
	struct peer_af *paf;
	struct bgp_adj_out *aout, *aout_tmp;
	struct bgp_dest *dest;
	struct attr *attr;
	int afid;

	afid = afindex(afi, safi);
	if (afid >= BGP_AF_MAX)
		return;
	paf = peer->peer_af_array[afid];
	if (paf == NULL)
		return;

	if (bgp_debug_update(peer, NULL, NULL, 1))
		debug_p = true;

	/* Examine the peer_af */
	subgrp = paf->subgroup;
	SUBGRP_FOREACH_ADJ_SAFE (subgrp, aout, aout_tmp) {
		dest = aout->dest;

		/* See if 'dest' would be filtered now that the RTC
		 * filters have changed.
		 */
		attr = aout->attr;
		if (attr == NULL)
			continue;

		if (!bgp_rtc_peer_filter_check(peer, attr, afi, safi)) {
			if (debug_p)
				zlog_debug("%s: %pBD filtered out", __func__,
					   dest);

			/* Withdraw */
			bgp_adj_out_unset_subgroup(dest, subgrp, 1,
						   aout->addpath_tx_id);
		}
	}
}

/*
 * Adding an RT filter: if this was the first prefix
 * for an RT, need to re-scan the rib-outs for this peer
 * and possibly withdraw some routes in the VPN SAFIs.
 */
static void rtc_handle_peer_filter_del(struct peer *peer,
				       const struct peer_rtc_entry *rtc)
{
	struct peer_rtc_entry lookup = {};
	const struct peer_rtc_entry *p;
	char buf[PREFIX_STRLEN] = "\0";

	/* Prepare filter lookup */
	lookup.p.family = AF_RTC;
	lookup.p.prefixlen = rtc->p.prefixlen;
	lookup.p.prefix = rtc->p.prefix;
	/* Ask for 'prefix matching' */
	SET_FLAG(lookup.flags, PEER_RTC_ENTRY_FLAG_PREFIX);

	/* If this RT would still be permitted by some existing entry,
	 * there's nothing to do.
	 */
	p = rtc_filter_find(&(peer->rtc_filter), &lookup);
	if (p) {
		if (bgp_debug_update(peer, NULL, NULL, 1)) {
			prefix_rtc2str(&(p->p), buf, sizeof(buf));
			zlog_debug("%s: ignoring: matched by: %s", __func__,
				   buf);
		}
		return;
	}

	/* Check the VPN SAFIs... */
	rtc_del_check_afi_safi(peer, AFI_IP, SAFI_MPLS_VPN);
	rtc_del_check_afi_safi(peer, AFI_IP6, SAFI_MPLS_VPN);
	rtc_del_check_afi_safi(peer, AFI_L2VPN, SAFI_EVPN);
}

/*
 * Handler for RTC SAFI prefix updates
 */
int bgp_rtc_prefix_update(struct bgp_dest *dest,
			  const struct bgp_path_info *oldpi,
			  const struct bgp_path_info *newpi)
{
	int ret = 0;
	struct peer_rtc_entry lookup = {};
	struct peer_rtc_entry *rtc = NULL;
	char buf[PREFIX_STRLEN] = "\0";
	bool debug_p = false;
	struct peer *old_peer = NULL, *new_peer = NULL;
	const struct prefix *p;

	if (oldpi)
		old_peer = oldpi->peer;
	if (newpi)
		new_peer = newpi->peer;

	/* Don't have any special handling for updates */
	if ((oldpi == newpi) || (old_peer == new_peer))
		goto done;

	/* Prepare filter lookup */
	p = bgp_dest_get_prefix(dest);

	lookup.p.family = AF_RTC;
	lookup.p.prefixlen = p->prefixlen;
	lookup.p.prefix = p->u.prefix_rtc;

	if ((old_peer && bgp_debug_update(old_peer, NULL, NULL, 1)) ||
	    (new_peer && bgp_debug_update(new_peer, NULL, NULL, 1))) {
		debug_p = true;
		prefix_rtc2str(&(lookup.p), buf, sizeof(buf));
	}

	if (old_peer) {
		/* Remove from peer's filters */
		rtc = rtc_filter_find(&old_peer->rtc_filter, &lookup);
		if (rtc) {
			if (debug_p)
				zlog_debug("%s: %pBP: del filter %s", __func__,
					   old_peer, buf);

			rtc_filter_del(&old_peer->rtc_filter, rtc);
			XFREE(MTYPE_BGP_RTC, rtc);

			/* Removing an RT filter: if this was the only prefix
			 * allowing an RT, need to re-scan the rib-out
			 * for this peer and possibly withdraw some routes
			 * in the VPN SAFIs.
			 */
			rtc_handle_peer_filter_del(old_peer, &lookup);
		}
	}

	if (new_peer) {
		/* Add to peer's filters */
		rtc = rtc_filter_find(&new_peer->rtc_filter, &lookup);
		if (rtc == NULL) {
			/* Adding an RT filter: may need to re-scan
			 * VPN routes and possibly advertise
			 * some that were excluded.
			 */
			rtc = XCALLOC(MTYPE_BGP_RTC,
				      sizeof(struct peer_rtc_entry));
			rtc->p.family = AF_RTC;
			rtc->p.prefixlen = p->prefixlen;
			rtc->p.prefix = p->u.prefix_rtc;

			if (debug_p)
				zlog_debug("%s: %pBP: add filter %s", __func__,
					   new_peer, buf);

			rtc_filter_add(&new_peer->rtc_filter, rtc);

			/* Currently handling after the new filter exists */
			rtc_handle_peer_filter_add(new_peer, &lookup);
		}
	}

done:
	return ret;
}

/*
 * Special handling for peer advertising the RTC default prefix
 */
int bgp_rtc_default_update(struct peer *peer, const struct prefix *p,
			   bool add_p)
{
	int ret = 0;
	struct peer_rtc_entry lookup = {.p.family = AF_RTC};
	struct peer_rtc_entry *rtc = NULL;
	char buf[PREFIX_STRLEN] = "\0";
	bool debug_p = false;

	if (bgp_debug_update(peer, NULL, NULL, 1)) {
		debug_p = true;
		prefix_rtc2str(&(lookup.p), buf, sizeof(buf));
	}

	rtc = rtc_filter_find(&peer->rtc_filter, &lookup);

	if (add_p) {
		if (rtc == NULL) {
			rtc = XCALLOC(MTYPE_BGP_RTC,
				      sizeof(struct peer_rtc_entry));
			rtc->p.family = AF_RTC;

			if (debug_p)
				zlog_debug("%s: %pBP: add filter %s", __func__,
					   peer, buf);

			rtc_filter_add(&peer->rtc_filter, rtc);
		}
	} else if (rtc) {
		if (debug_p)
			zlog_debug("%s: %pBP: del filter %s", __func__, peer,
				   buf);

		rtc_filter_del(&peer->rtc_filter, rtc);
		XFREE(MTYPE_BGP_RTC, rtc);
	}

	return ret;
}

/*
 * Initialize RTC prefix from RT value
 */
static void rtc_prefix_from_eval(struct prefix_rtc *p,
				 const struct ecommunity_val *eval)
{
	/* Lookup existing entry */
	p->family = AF_RTC;
	/* TODO -- using max prefix for now */
	p->prefixlen = BGP_RTC_PREFIX_MAXLEN;
	memcpy(p->prefix.route_target, eval->val, ECOMMUNITY_SIZE);
}

/* Check peer's filter for one RT value: return false to filter/reject the
 * ecommunity
 */
static bool rtc_filter_check_one(struct peer *peer,
				 const struct ecommunity_val *eval)
{
	struct peer_rtc_entry lookup = {};
	struct peer_rtc_entry *rtc;

	/* Lookup existing entry */
	rtc_prefix_from_eval(&lookup.p, eval);

	/* Ask for 'prefix matching' */
	SET_FLAG(lookup.flags, PEER_RTC_ENTRY_FLAG_PREFIX);

	rtc = rtc_filter_find(&peer->rtc_filter, &lookup);

	return (rtc != NULL);
}

/*
 * Check peer's outbound RTC filter; return 'false' if 'p' should be filtered.
 */
bool bgp_rtc_peer_filter_check(struct peer *peer, const struct attr *attr,
			       afi_t afi, safi_t safi)
{
	uint32_t idx, counter = 0;
	const struct ecommunity *ecomm;
	const struct ecommunity_val *eval;

	/* Only care about certain afi/safis */
	if (safi != SAFI_MPLS_VPN && safi != SAFI_EVPN)
		return true;

	/* If no RTs, nothing to check */
	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return true;

	/* No filter: should the default be "all", or "none"?
	 * For now, it's "none"; use "default-originate" to enable wildcard
	 */
	if (rtc_filter_count(&peer->rtc_filter) == 0)
		return false;

	/* Look through the route's attributes for RTs */
	ecomm = bgp_attr_get_ecommunity(attr);

	idx = 0;
	eval = ecommunity_idx(ecomm, idx);
	while (eval != NULL) {
		if (eval->val[1] == ECOMMUNITY_ROUTE_TARGET) {
			counter++;

			/* Check outbound filter */
			if (rtc_filter_check_one(peer, eval))
				return true;
		}

		idx++;
		eval = ecommunity_idx(ecomm, idx);
	}

	/* Don't filter if no RTs in the ecomm */
	if (counter == 0)
		return true;
	else
		return false;
}

/*
 * Clear peer's RTC filter data; this may be called when 'peer' is unconfigured,
 * or deleted.
 */
void bgp_rtc_peer_delete(struct peer *peer)
{
	struct peer_rtc_entry *rtc;

	while ((rtc = rtc_filter_pop(&(peer->rtc_filter))) != NULL)
		XFREE(MTYPE_BGP_RTC, rtc);

	/* Stop "defer" timer */
	event_cancel(&(peer->t_rtc_defer));
}

/*
 * Init peer's RTC filter data; called during peer initialization
 */
void bgp_rtc_peer_init(struct peer *peer)
{
	rtc_filter_init(&(peer->rtc_filter));
}

/*
 * Show helper for RTC data
 */
void bgp_rtc_show_peer(const struct peer *peer, struct vty *vty,
		       json_object *jneigh)
{
	const struct peer_rtc_entry *rtc;
	json_object *jlist = NULL;
	char buf[PREFIX_STRLEN];
	bool first_p = true;

	/* Outbound filter info */
	if (rtc_filter_count(&peer->rtc_filter) == 0)
		return;

	frr_each (rtc_filter_const, &peer->rtc_filter, rtc) {
		buf[0] = '\0';
		prefix_rtc2str(&(rtc->p), buf, sizeof(buf));
		if (jneigh) {
			if (jlist == NULL)
				jlist = json_object_new_array();
			json_object_array_add(jlist,
					      json_object_new_string(buf));
		} else {
			if (first_p) {
				vty_out(vty, "RTC outbound filters:\n");
				first_p = false;
			}
			vty_out(vty, "  %s\n", buf);
		}
	}

	/* End */
	if (jlist) {
		json_object_object_add(jneigh, "rtcFilters", jlist);
	} else {
		vty_out(vty, "\n");
	}
}

/*
 * Helper to restart deferred VPN SAFI updates
 */
static void rtc_defer_complete(struct peer *peer)
{
	int i;

	for (i = 0; rtc_safis[i].afi != AFI_UNSPEC; i++) {
		if (CHECK_FLAG(peer->af_sflags[rtc_safis[i].afi]
			       [rtc_safis[i].safi],
			       PEER_STATUS_RTC_WAIT)) {
			    UNSET_FLAG(peer->af_sflags[rtc_safis[i].afi]
				       [rtc_safis[i].safi],
				       PEER_STATUS_RTC_WAIT);

			    /* Initiate processing */
			    bgp_announce_route(peer, rtc_safis[i].afi,
					       rtc_safis[i].safi, false);
		}
	}
}

/*
 * Handler for expired 'defer' timer
 */
static void rtc_handle_defer_timer(struct event *e)
{
	struct peer *peer = e->arg;

	/* Allow any deferred VPN safis to process updates */

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP: RTC defer timer expired", peer);

	rtc_defer_complete(peer);
}

/*
 * Handle peer session establish event
 */
void bgp_rtc_handle_establish(struct peer *peer)
{
	int i;
	bool defer_p = false;

	/* If RTC feature was negotiated, defer VPN SAFIs until RTC SAFI is
	 * announced.
	 */
	if (!(peer->afc_nego[AFI_IP][SAFI_RTC]))
		return;

	for (i = 0; rtc_safis[i].afi != AFI_UNSPEC; i++) {
		if (peer->afc_nego[rtc_safis[i].afi][rtc_safis[i].safi]) {
			defer_p = true;

			SET_FLAG(peer->af_sflags[rtc_safis[i].afi]
				 [rtc_safis[i].safi],
				 PEER_STATUS_RTC_WAIT);

			if (bgp_debug_neighbor_events(peer))
				zlog_debug("%pBP: defer %s/%s for RTC", peer,
					   afi2str(rtc_safis[i].afi),
					   safi2str(rtc_safis[i].safi));
		}
	}

	/* Set defer timer */
	if (defer_p) {
		event_add_timer(bm->master, rtc_handle_defer_timer, peer,
				BGP_RTC_DEFER_DEFAULT_SECS, &peer->t_rtc_defer);
	}
}

/*
 * Handle EOR received in the RTC SAFI
 */
void bgp_rtc_handle_eor(struct peer *peer, afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_RTC) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%pBP: RTC SAFI EOR: restart deferred updates",
				   peer);

		/* Stop "defer" timer */
		event_cancel(&(peer->t_rtc_defer));
		/* Restart any deferred VPN SAFIs */
		rtc_defer_complete(peer);
	}
}
