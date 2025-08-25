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

