// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#include <zebra.h>

#include "log.h"
#include "zclient.h"

#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgpd.h"

extern struct zclient *bgp_zclient;

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi)
{
	uint32_t sid_func;
	safi_t safi = SAFI_UNICAST;
	struct srv6_sid_ctx ctx = {};
	bool unicast_sid_auto = false;
	uint32_t unicast_sid_index = 0;
	struct in6_addr unicast_sid = {};
	struct srv6_locator *locator_bgp;
	bool unicast_sid_explicit = false;

	/* no configured */
	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	/* already allocated */
	if (bgp->srv6_unicast[afi].sid)
		return;

	locator_bgp = bgp->srv6_locator;
	/* locator no set */
	if (!locator_bgp)
		return;

	unicast_sid_index = bgp->srv6_unicast[afi].sid_index;
	unicast_sid_auto = CHECK_FLAG(bgp->af_flags[afi][safi],
				      BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	unicast_sid_explicit = bgp->srv6_unicast[afi].sid_explicit;

	if ((unicast_sid_index != 0 && unicast_sid_auto) ||
	    (unicast_sid_index != 0 && unicast_sid_explicit) ||
	    (unicast_sid_auto && unicast_sid_explicit)) {
		zlog_err("%s: more than one mode selected among index-mode, auto-mode and explicit-mode. ignored.",
			 __func__);
		return;
	}

	if (!unicast_sid_auto && !unicast_sid_explicit) {
		if (!srv6_sid_compose(&unicast_sid, locator_bgp, unicast_sid_index)) {
			zlog_err("%s: failed to compose unicast sid %s: afi %s",
				 __func__, bgp->name_pretty, afi2str(afi));
			return;
		}
	} else if (unicast_sid_explicit) {
		unicast_sid = *(bgp->srv6_unicast[afi].sid_explicit);
	} else if (!unicast_sid_auto) {
		zlog_err("%s: neither index, auto, nor explicit mode is selected.",  __func__);
		return;
	}

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	if (!bgp_zebra_request_srv6_sid(&ctx, &unicast_sid, locator_bgp->name, &sid_func)) {
		zlog_err("%s: failed to request sid for bgp %s: afi %s", __func__,
			 bgp->name_pretty, afi2str(afi));
	}
}

void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install)
{
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *unicast_sid_ls = NULL;

	if (!bgp->srv6_unicast[afi].sid)
		return;

	ctx.block_len = bgp->srv6_unicast[afi].sid_locator->block_bits_length;
	ctx.node_len = bgp->srv6_unicast[afi].sid_locator->node_bits_length;
	ctx.function_len = bgp->srv6_unicast[afi].sid_locator->function_bits_length;
	ctx.argument_len = bgp->srv6_unicast[afi].sid_locator->argument_bits_length;

	if (install) {
		if (CHECK_FLAG(bgp->srv6_unicast[afi].sid_locator->flags, SRV6_LOCATOR_USID))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		ctx.table = ifp->vrf->data.l.table_id;
		act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 :
			ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_ADD, bgp->srv6_unicast[afi].sid,
				      IPV6_MAX_BITLEN, ifp->ifindex, act, &ctx);
		unicast_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		*unicast_sid_ls = *bgp->srv6_unicast[afi].sid;
		if (bgp->srv6_unicast[afi].zebra_sid_last_sent)
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
		bgp->srv6_unicast[afi].zebra_sid_last_sent = unicast_sid_ls;

	} else {
		zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE,
				      bgp->srv6_unicast[afi].zebra_sid_last_sent, IPV6_MAX_BITLEN,
				      ifp->ifindex, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, &ctx);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
		bgp->srv6_unicast[afi].zebra_sid_last_sent = NULL;
	}
}

void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};
	int debug = BGP_DEBUG(zebra, ZEBRA);

	if (bgp->vrf_id != VRF_DEFAULT)
		return;

	if (debug)
		zlog_debug("%s: vrf %s: deleting sid %pI6 for vrf id %d", __func__,
			   bgp->name_pretty, bgp->srv6_unicast[afi].sid, bgp->vrf_id);

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, nothing to uninstall",
			  DEFAULT_SRV6_IFNAME);
		return;
	}

	if (bgp->srv6_unicast[afi].zebra_sid_last_sent)
		bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	ctx.vrf_id = bgp->vrf_id;
	bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);
}

void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};

	if (!bgp || bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	if (bgp->srv6_unicast[afi].sid) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (ifp && bgp->srv6_unicast[afi].zebra_sid_last_sent)
			bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

		ctx.vrf_id = bgp->vrf_id;
		ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);

		sid_unregister(bgp, bgp->srv6_unicast[afi].sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
	}

	if (bgp->srv6_unicast[afi].sid_explicit)
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid_explicit);

	if (bgp->srv6_unicast[afi].rmap_name)
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);

	srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
	bgp->srv6_unicast[afi].sid_locator = NULL;
	UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		   BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
}

void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;

	if (!bgp->srv6_unicast[afi].sid)
		return;

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, can not install SRV6 endpoint behavior",
			  DEFAULT_SRV6_IFNAME);
		return;
	}
	if (!if_is_up(ifp))
		return;

	bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, true);
}

void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest)
{
	XFREE(MTYPE_BGP_SRV6_L3SERVICE, dest->srv6_unicast);
	dest->srv6_unicast = NULL;
}

void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct bgp_path_info *bpi)
{
	struct attr attr_tmp;
	const struct prefix *p;
	struct route_map *rmap;
	route_map_result_t ret;
	struct bgp_path_info info;
	struct srv6_locator *locator;

	if (!bpi) {
		if (dest->srv6_unicast)
			bgp_srv6_unicast_unregister_route(dest);

		return;
	}

	if (bpi->attr->srv6_l3service)
		return;

	if (!bgp->srv6_unicast[afi].sid_locator)
		return;

	if (bgp->srv6_unicast[afi].rmap_name) {
		rmap = route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name);
		if (rmap) {
			attr_tmp = *bpi->attr;
			info.attr = &attr_tmp;
			info.peer = bgp->peer_self;
			memset(&info, 0, sizeof(info));
			p = bgp_dest_get_prefix(bpi->net);

			ret = route_map_apply(rmap, p, &info);

			if (ret == RMAP_DENYMATCH) {
				if (dest->srv6_unicast)
					bgp_srv6_unicast_unregister_route(dest);

				if (BGP_DEBUG(update, UPDATE_OUT))
					zlog_debug("srv6 unicast prefix %pBD denied", dest);

				return;
			}
		} else {
			zlog_warn("route-map %s was no found, ignored",
				  bgp->srv6_unicast[afi].rmap_name);
		}
	}

	if (dest->srv6_unicast && sid_same(bgp->srv6_unicast[afi].sid, &dest->srv6_unicast->sid))
		return;

	locator = bgp->srv6_unicast[afi].sid_locator;
	dest->srv6_unicast = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE,
				     sizeof(struct bgp_attr_srv6_l3service));
	dest->srv6_unicast->sid_flags = 0x00;
	dest->srv6_unicast->endpoint_behavior =
			afi == AFI_IP ? (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
						 ? SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID
						 : SRV6_ENDPOINT_BEHAVIOR_END_DT4)
				      : (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
						 ? SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID
						 : SRV6_ENDPOINT_BEHAVIOR_END_DT6);
	dest->srv6_unicast->loc_block_len = locator->block_bits_length;
	dest->srv6_unicast->loc_node_len = locator->node_bits_length;
	dest->srv6_unicast->func_len = locator->function_bits_length;
	dest->srv6_unicast->arg_len = locator->argument_bits_length;
	memcpy(&dest->srv6_unicast->sid, bgp->srv6_unicast[afi].sid,
	       sizeof(struct in6_addr));
}

void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi)
{
	struct peer *peer;
	struct bgp_dest *pdest;
	struct bgp_path_info *bpi;
	safi_t safi = SAFI_UNICAST;
	struct listnode *node, *nnode;

	if (!bgp->srv6_unicast[afi].sid_locator)
		return;

	for (pdest = bgp_table_top(bgp->rib[afi][safi]); pdest; pdest = bgp_route_next(pdest)) {
		for (bpi = bgp_dest_get_bgp_path_info(pdest); bpi; bpi = bpi->next) {
			if (!CHECK_FLAG(bpi->flags, BGP_PATH_SELECTED))
				continue;

			if (bpi->attr->srv6_l3service)
				continue;

			bgp_srv6_unicast_register_route(bgp, afi, pdest, bpi);
			break;
		}
	}

	/* force to resend all routes */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}

void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi)
{
	struct peer *peer;
	struct bgp_dest *pdest;
	safi_t safi = SAFI_UNICAST;
	struct listnode *node, *nnode;

	for (pdest = bgp_table_top(bgp->rib[afi][safi]); pdest; pdest = bgp_route_next(pdest)) {
		if (!pdest->srv6_unicast)
			continue;

		bgp_srv6_unicast_unregister_route(pdest);
	}

	/* force to resend all routes */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}
