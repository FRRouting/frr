// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#include <zebra.h>

#include "log.h"
#include "vty.h"
#include "zclient.h"

#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgpd.h"

#include "bgpd/bgp_srv6_clippy.c"

DEFINE_MTYPE_STATIC(BGPD, SRV6_LOCATOR_EXTRA, "BGP SRv6 Extra locator");
DEFINE_MTYPE_STATIC(BGPD, SRV6_PER_LOCATOR_CACHE, "BGP SRv6 per locator cache");
DEFINE_MTYPE_STATIC(BGPD, BGP_SRV6_LOCATOR, "BGP SRv6 locator");

extern struct zclient *bgp_zclient;

static bool bgp_srv6_unicast_dt46_needs_sid_request(struct bgp *bgp, afi_t afi)
{
	afi_t other_afi = (afi == AFI_IP) ? AFI_IP6 : AFI_IP;

	/* DT46 is not enabled on both AFIs, so this AFI must request its own SID. */
	if (!is_srv6_unicast_dt46_enabled(bgp, afi) ||
	    !is_srv6_unicast_dt46_enabled(bgp, other_afi))
		return true;

	/* Other AFI already owns the shared SID: copy and reuse it. */
	if (bgp->srv6_unicast[other_afi].sid && bgp->srv6_unicast[other_afi].sid_locator) {
		/* Free any stale state before (re-)assigning. */
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
		srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
		bgp->srv6_unicast[afi].sid_locator = NULL;
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);

		bgp->srv6_unicast[afi].sid = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		*bgp->srv6_unicast[afi].sid = *bgp->srv6_unicast[other_afi].sid;

		bgp->srv6_unicast[afi].sid_locator =
			srv6_locator_alloc(bgp->srv6_unicast[other_afi].sid_locator->name);
		srv6_locator_copy(bgp->srv6_unicast[afi].sid_locator,
				  bgp->srv6_unicast[other_afi].sid_locator);

		/*
		 * The other AFI already installed this local SID, so this AFI must
		 * not send another ROUTE_ADD.
		 * Set zebra_sid_last_sent to remember that this SID is already
		 * installed in zebra.
		 */
		bgp->srv6_unicast[afi].zebra_sid_last_sent = XCALLOC(MTYPE_BGP_SRV6_SID,
								     sizeof(struct in6_addr));
		*bgp->srv6_unicast[afi].zebra_sid_last_sent = *bgp->srv6_unicast[afi].sid;
		bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent =
			bgp->srv6_unicast[other_afi].zebra_sid_alloc_mode_last_sent;

		return false;
	}

	/*
	 * Other AFI has no SID yet. Let only AFI_IP send the SID Manager request;
	 * AFI_IP6 defers until the ALLOCATED callback fires.
	 */
	return afi == AFI_IP;
}

void bgp_srv6_unicast_sid_withdraw_dt46(struct bgp *bgp, afi_t afi)
{
	afi_t other_afi = afi == AFI_IP ? AFI_IP6 : AFI_IP;
	bool sid_still_used;
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};

	if (!CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46))
		return;

	sid_still_used = bgp->srv6_unicast[afi].sid &&
			 is_srv6_unicast_dt46_enabled(bgp, other_afi) &&
			 sid_same(bgp->srv6_unicast[afi].sid, bgp->srv6_unicast[other_afi].sid);

	if (!sid_still_used) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (ifp && bgp->srv6_unicast[afi].zebra_sid_last_sent)
			bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

		if (bgp->srv6_unicast[afi].sid_locator) {
			ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
			ctx.vrf_id = bgp->vrf_id;
			ctx.alloc_mode = bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent;
			bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);
		}
		if (bgp->srv6_unicast[afi].sid)
			sid_unregister(bgp, bgp->srv6_unicast[afi].sid);
	}

	srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
	bgp->srv6_unicast[afi].sid_locator = NULL;
	bgp_srv6_unicast_withdraw(bgp, afi);
	XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
	XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
}

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi)
{
	uint32_t sid_func;
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

	if (!bgp_srv6_unicast_dt46_needs_sid_request(bgp, afi)) {
		bgp_srv6_unicast_announce(bgp, afi);
		return;
	}

	unicast_sid_index = bgp->srv6_unicast[afi].sid_index;
	unicast_sid_auto = CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
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
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_EXPLICIT;
	} else if (unicast_sid_explicit) {
		unicast_sid = *(bgp->srv6_unicast[afi].sid_explicit);
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_EXPLICIT;
	} else if (unicast_sid_auto) {
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_DYNAMIC;
	} else {
		zlog_err("%s: neither index, auto, nor explicit mode is selected.",  __func__);
		return;
	}

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = bgp_srv6_unicast_action(bgp, afi);
	if (!bgp_zebra_request_srv6_sid(&ctx, &unicast_sid, locator_bgp->name, &sid_func)) {
		zlog_err("%s: failed to request sid for bgp %s: afi %s", __func__,
			 bgp->name_pretty, afi2str(afi));
		return;
	}
	bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent = ctx.alloc_mode;
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
		act = bgp_srv6_unicast_action(bgp, afi);
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

	if (CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46)) {
		bgp_srv6_unicast_sid_withdraw_dt46(bgp, afi);
		return;
	}

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, nothing to uninstall",
			  DEFAULT_SRV6_IFNAME);
		return;
	}

	if (bgp->srv6_unicast[afi].zebra_sid_last_sent)
		bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

	ctx.behavior = bgp_srv6_unicast_action(bgp, afi);
	ctx.vrf_id = bgp->vrf_id;
	ctx.alloc_mode = bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent;
	bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);
}

/*
 * A restarted zebra has lost the SRv6 unicast SIDs and their local SIDs: forget
 * them without releasing them, so that they are requested again once the
 * locator is received.
 */
void bgp_srv6_unicast_sids_forget(struct bgp *bgp)
{
	afi_t afi;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		if (bgp->srv6_unicast[afi].sid) {
			sid_unregister(bgp, bgp->srv6_unicast[afi].sid);
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
		}
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
		srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
		bgp->srv6_unicast[afi].sid_locator = NULL;
	}
}

void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};

	if (!bgp || bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	if (CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46)) {
		bgp_srv6_unicast_sid_withdraw_dt46(bgp, afi);

		if (bgp->srv6_unicast[afi].sid_explicit)
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid_explicit);

		if (bgp->srv6_unicast[afi].rmap_name) {
			route_map_counter_decrement(
				route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
			XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
		}

		UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);
		UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
		return;
	}

	if (bgp->srv6_unicast[afi].sid) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (ifp && bgp->srv6_unicast[afi].zebra_sid_last_sent)
			bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

		ctx.vrf_id = bgp->vrf_id;
		ctx.behavior = bgp_srv6_unicast_action(bgp, afi);
		ctx.alloc_mode = bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent;

		bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);

		sid_unregister(bgp, bgp->srv6_unicast[afi].sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
	}

	if (bgp->srv6_unicast[afi].sid_explicit)
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid_explicit);

	if (bgp->srv6_unicast[afi].rmap_name) {
		route_map_counter_decrement(
			route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
	}

	srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
	bgp->srv6_unicast[afi].sid_locator = NULL;
	UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
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

	if (bgp_attr_get_srv6_l3service(bpi->attr))
		return;

	if (!bgp->srv6_unicast[afi].sid_locator)
		return;

	if (bgp->srv6_unicast[afi].rmap_name) {
		rmap = route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name);
		if (rmap) {
			struct bgp_path_info_extra extra;

			bgp_attr_dup_into(&attr_tmp, bpi->attr);
			p = bgp_dest_get_prefix(bpi->net);

			prep_for_rmap_apply(&info, &extra, dest, bpi, bgp->peer_self, NULL,
					    &attr_tmp);
			ret = route_map_apply(rmap, p, &info);
			cleanup_after_rmap_apply(&info);
			bgp_attr_flush(&attr_tmp);

			if (ret == RMAP_DENYMATCH) {
				if (dest->srv6_unicast)
					bgp_srv6_unicast_unregister_route(dest);

				if (BGP_DEBUG(update, UPDATE_OUT)) {
					struct bgp_debug_vrf dv = bgp_dest_debug_vrf(dest);

					zlog_debug("srv6 unicast prefix (%s:%u:%u)%pBD denied",
						   dv.name, dv.id, dv.table_id, dest);
				}

				return;
			}
		} else {
			zlog_warn("route-map %s was not found, ignored",
				  bgp->srv6_unicast[afi].rmap_name);
		}
	}

	if (dest->srv6_unicast && sid_same(bgp->srv6_unicast[afi].sid, &dest->srv6_unicast->sid))
		return;

	/*
	 * If a previous SID was installed on this dest (e.g. the operator
	 * reconfigured the unicast SID without first walking/withdrawing the
	 * RIB), free the old descriptor before allocating a new one.  Without
	 * this the previous XCALLOC is leaked across "no sid export ..." +
	 * re-add sequences that change the SID value.
	 */
	if (dest->srv6_unicast)
		bgp_srv6_unicast_unregister_route(dest);

	locator = bgp->srv6_unicast[afi].sid_locator;
	dest->srv6_unicast = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE,
				     sizeof(struct bgp_attr_srv6_l3service));
	dest->srv6_unicast->sid_flags = 0x00;
	dest->srv6_unicast->endpoint_behavior =
		bgp_srv6_unicast_endpoint_behavior_codepoint(bgp, afi, locator);
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

			if (bgp_attr_get_srv6_l3service(bpi->attr))
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

int bgp_srv6_locators_cmp(const struct bgp_srv6_locator_entry *a,
			  const struct bgp_srv6_locator_entry *b)
{
	return strncmp(a->locator->name, b->locator->name, SRV6_LOCNAME_SIZE);
}

static struct bgp_srv6_locator_entry *bgp_srv6_locator_entry_find(const char *name)
{
	struct srv6_locator loc = {};
	struct bgp_srv6_locator_entry key = { .locator = &loc };

	strlcpy(loc.name, name, sizeof(loc.name));

	return bgp_srv6_locators_find(&bm->srv6_locators, &key);
}

/**
 * Return the SRv6 locator by name
 *
 * @param name Locator name
 * @return srv6_locator
 */
struct srv6_locator *bgp_srv6_locator_lookup_all_by_name(const char *name)
{
	struct bgp_srv6_locator_entry *entry;

	entry = bgp_srv6_locator_entry_find(name);

	return entry ? entry->locator : NULL;
}

void bgp_srv6_locator_store(const struct srv6_locator *loc)
{
	struct bgp_srv6_locator_entry *entry;

	entry = bgp_srv6_locator_entry_find(loc->name);
	if (!entry) {
		entry = XCALLOC(MTYPE_BGP_SRV6_LOCATOR, sizeof(*entry));
		entry->locator = srv6_locator_alloc(loc->name);
		bgp_srv6_locators_add(&bm->srv6_locators, entry);
	}
	srv6_locator_copy(entry->locator, loc);
}

static void bgp_srv6_locator_entry_free(struct bgp_srv6_locator_entry *entry)
{
	srv6_locator_free(entry->locator);
	XFREE(MTYPE_BGP_SRV6_LOCATOR, entry);
}

void bgp_srv6_locator_remove(const char *name)
{
	struct bgp_srv6_locator_entry *entry;

	entry = bgp_srv6_locator_entry_find(name);
	if (!entry)
		return;
	bgp_srv6_locators_del(&bm->srv6_locators, entry);
	bgp_srv6_locator_entry_free(entry);
}

void bgp_srv6_locators_finish(void)
{
	struct bgp_srv6_locator_entry *entry;

	while ((entry = bgp_srv6_locators_pop(&bm->srv6_locators)))
		bgp_srv6_locator_entry_free(entry);
	bgp_srv6_locators_fini(&bm->srv6_locators);
}

void bgp_srv6_path_locator_extra_free(struct bgp_path_info_extra *extra)
{
	if (!extra)
		return;
	XFREE(MTYPE_SRV6_LOCATOR_EXTRA, extra->srv6_locator);
}

void bgp_srv6_path_locator_extra_alloc(struct bgp_path_info_extra *extra, char *locator)
{
	extra->srv6_locator = XSTRDUP(MTYPE_SRV6_LOCATOR_EXTRA, locator);
}

static void bgp_srv6_per_locator_free(struct bgp_srv6_per_locator_cache *bslc)
{
	if (!bslc)
		return;

	assert(bslc->tree);

	bslc = bgp_srv6_per_locator_cache_del(bslc->tree, bslc);
	if (bslc)
		XFREE(MTYPE_SRV6_PER_LOCATOR_CACHE, bslc);
}

/* code derived from vpn_leak_zebra_vrf_sid_withdraw_per_af() */
static void bgp_srv6_per_locator_cache_vrf_sid_withdraw(struct bgp_srv6_per_locator_cache *bslc)
{
	struct seg6local_context ctx = {};
	struct interface *ifp;

	if (!bslc->sid_policy.tovpn_zebra_sid_last_sent)
		return;

	ifp = if_get_vrf_loopback(bslc->bgp->vrf_id);
	if (ifp) {
		if (bslc->sid_policy.tovpn_sid_locator) {
			ctx.block_len = bslc->sid_policy.tovpn_sid_locator->block_bits_length;
			ctx.node_len = bslc->sid_policy.tovpn_sid_locator->node_bits_length;
			ctx.function_len = bslc->sid_policy.tovpn_sid_locator->function_bits_length;
			ctx.argument_len = bslc->sid_policy.tovpn_sid_locator->argument_bits_length;
		}
		zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE,
				      bslc->sid_policy.tovpn_zebra_sid_last_sent, IPV6_MAX_BITLEN,
				      ifp->ifindex, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, &ctx);
	}
	XFREE(MTYPE_BGP_SRV6_SID, bslc->sid_policy.tovpn_zebra_sid_last_sent);
}

/* code derived from ensure_vrf_tovpn_sid(), applied to auto mode only */
void bgp_srv6_per_locator_cache_delete_tovpn_sid(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct srv6_sid_ctx ctx = {};

	if (debug)
		zlog_debug("%s: try to remove SID for vrf %s: afi %s locator %s, mode %s",
			   __func__, bslc->bgp->name_pretty, afi2str(bslc->afi), bslc->locator_name,
			   srv6_sid_alloc_mode2str(
				   bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent));

	bgp_srv6_per_locator_cache_vrf_sid_withdraw(bslc);

	if (bslc->sid_policy.tovpn_sid) {
		ctx.vrf_id = bslc->bgp->vrf_id;
		ctx.behavior = bslc->afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
						   : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		ctx.alloc_mode = bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent;
		bgp_zebra_release_srv6_sid(&ctx, bslc->locator_name);
		sid_unregister(bgp_get_default(), bslc->sid_policy.tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bslc->sid_policy.tovpn_sid);
	}
	bslc->sid_policy.tovpn_sid = NULL;
	bslc->sid_policy.tovpn_sid_transpose_label = 0;
	bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent = SRV6_SID_ALLOC_MODE_UNSPEC;
	srv6_locator_free(bslc->sid_policy.tovpn_sid_locator);
	bslc->sid_policy.tovpn_sid_locator = NULL;

	if (bslc->bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf sid", __func__,
				   bslc->bgp->name_pretty);
	}
}

struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_new(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name)
{
	struct bgp_srv6_per_locator_cache *bslc;

	bslc = XCALLOC(MTYPE_SRV6_PER_LOCATOR_CACHE, sizeof(struct bgp_srv6_per_locator_cache));
	bslc->tree = tree;
	strlcpy(bslc->locator_name, locator_name, sizeof(bslc->locator_name));
	LIST_INIT(&(bslc->paths));
	bgp_srv6_per_locator_cache_add(tree, bslc);

	return bslc;
}

int bgp_srv6_per_locator_cache_cmp(const struct bgp_srv6_per_locator_cache *a,
				   const struct bgp_srv6_per_locator_cache *b)
{
	return strncmp(a->locator_name, b->locator_name, sizeof(a->locator_name));
}

struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_find(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name)
{
	struct bgp_srv6_per_locator_cache bslc = {};

	assert(tree);

	strlcpy(bslc.locator_name, locator_name, sizeof(bslc.locator_name));

	return bgp_srv6_per_locator_cache_find(tree, &bslc);
}

/* detach locator when bgp path is removed */
static void bgp_srv6_per_locator_unlink_and_free(struct bgp_path_info *pi, bool free_bslc)
{
	struct bgp_srv6_per_locator_cache *bslc;

	bslc = pi->srv6_vpn.bslc;
	if (!bslc)
		return;

	LIST_REMOVE(pi, srv6_vpn.srv6_locator_thread);
	bslc->path_count--;
	pi->srv6_vpn.bslc = NULL;

	if (free_bslc && LIST_EMPTY(&(bslc->paths))) {
		bgp_srv6_per_locator_cache_delete_tovpn_sid(bslc);
		bgp_srv6_per_locator_free(bslc);
	}
}

void bgp_srv6_per_locator_unlink(struct bgp_path_info *pi)
{
	bgp_srv6_per_locator_unlink_and_free(pi, true);
}

/* Reset and free all BGP nexthop cache */
void bgp_srv6_per_locator_cache_reset(struct bgp *bgp, afi_t afi)
{
	struct bgp_srv6_per_locator_cache *bslc;
	struct bgp_srv6_per_locator_cache_head *tree;

	tree = &bgp->srv6_locators_per_routemap[afi];

	while (bgp_srv6_per_locator_cache_count(tree) > 0) {
		bslc = bgp_srv6_per_locator_cache_first(tree);

		while (!LIST_EMPTY(&(bslc->paths)))
			bgp_srv6_per_locator_unlink_and_free(LIST_FIRST(&(bslc->paths)), false);
		bgp_srv6_per_locator_cache_delete_tovpn_sid(bslc);
		bgp_srv6_per_locator_free(bslc);
	}
}

static void show_bgp_srv6_locators_per_routemap_afi(struct vty *vty, afi_t afi, struct bgp *bgp,
						    bool detail, json_object *json_list)
{
	struct bgp_srv6_per_locator_cache_head *tree;
	struct bgp_srv6_per_locator_cache *iter;
	struct srv6_locator *locator;
	safi_t safi;
	char buf[PREFIX2STR_BUFFER];
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	struct bgp *bgp_path;
	struct bgp_table *table;
	json_object *json;
	json_object *json_path_list, *json_path_entry;

	if (json_list == NULL)
		vty_out(vty, "Current BGP SRv6 locator per route-map for %s, %s\n", afi2str(afi),
			bgp->name_pretty);

	tree = &bgp->srv6_locators_per_routemap[afi];
	frr_each (bgp_srv6_per_locator_cache, tree, iter) {
		if (json_list) {
			json = json_object_new_object();

			json_object_string_add(json, "afi", afi2str(afi));
			json_object_string_add(json, "locatorName", iter->locator_name);
			locator = bgp_srv6_locator_lookup_all_by_name(iter->locator_name);
			if (locator)
				json_object_string_addf(json, "locatorPrefix", "%pFX",
							&locator->prefix);
			json_object_int_add(json, "pathCount", iter->path_count);
			json_object_string_add(json, "lastUpdate",
					       time_to_string_json(iter->last_update, buf));
			if (iter->sid_policy.tovpn_sid) {
				json_object_string_addf(json, "sid", "%pI6",
							iter->sid_policy.tovpn_sid);
				json_object_int_add(json, "label",
						    iter->sid_policy.tovpn_sid_transpose_label);
			}
			json_object_array_add(json_list, json);

			if (!detail)
				continue;

			json_path_list = json_object_new_array();

			LIST_FOREACH (path, &(iter->paths), srv6_vpn.srv6_locator_thread) {
				dest = path->net;
				table = bgp_dest_table(dest);
				assert(dest && table);
				afi = family2afi(bgp_dest_get_prefix(dest)->family);
				safi = table->safi;
				bgp_path = table->bgp;
				json_path_entry = json_object_new_object();
				json_object_string_add(json_path_entry, "afi", afi2str(afi));
				json_object_string_add(json_path_entry, "safi", safi2str(safi));
				json_object_string_addf(json_path_entry, "prefix", "%pBD", dest);
				json_object_string_add(json_path_entry, "bgpName",
						       bgp_path->name_pretty);
				json_object_string_addf(json_path_entry, "flags", "%08x",
							path->flags);
				if (dest->pdest)
					json_object_string_addf(json_path_entry,
								"route-distinguisher",
								BGP_RD_AS_FORMAT(bgp->asnotation),
								(struct prefix_rd *)
									bgp_dest_get_prefix(
										dest->pdest));
				json_object_array_add(json_path_list, json_path_entry);
			}
			json_object_object_add(json, "pathList", json_path_list);
			continue;
		}

		vty_out(vty, " %s, #paths %u\n", iter->locator_name, iter->path_count);
		vty_out(vty, "  Last update: %s\n", time_to_string_json(iter->last_update, buf));
		if (iter->sid_policy.tovpn_sid)
			vty_out(vty, "  SID %pI6, label %u\n", iter->sid_policy.tovpn_sid,
				iter->sid_policy.tovpn_sid_transpose_label);
		if (!detail)
			continue;
		vty_out(vty, "  Paths:\n");
		LIST_FOREACH (path, &(iter->paths), srv6_vpn.srv6_locator_thread) {
			dest = path->net;
			table = bgp_dest_table(dest);
			assert(dest && table);
			afi = family2afi(bgp_dest_get_prefix(dest)->family);
			safi = table->safi;
			bgp_path = table->bgp;

			if (dest->pdest) {
				vty_out(vty, "    %d/%d %pBD RD ", afi, safi, dest);

				vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
					(struct prefix_rd *)bgp_dest_get_prefix(dest->pdest));
				vty_out(vty, " %s flags 0x%x\n", bgp_path->name_pretty,
					path->flags);
			} else
				vty_out(vty, "    %d/%d %pBD %s flags 0x%x\n", afi, safi, dest,
					bgp_path->name_pretty, path->flags);
		}
	}
}

DEFPY(show_bgp_srv6_locator_per_routemap, show_bgp_srv6_locator_per_routemap_cmd,
      "show bgp [vrf VRFNAME] locator-routemap [detail] [json]",
      SHOW_STR BGP_STR VRF_CMD_HELP_STR
      "BGP locator from route-map table\n"
      "Show detailed information\n"
      JSON_STR)
{
	int idx = 0;
	char *vrf = NULL;
	struct bgp *bgp;
	bool detail = false;
	int afi;
	struct json_object *json_list = NULL;

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[++idx]->arg;
		bgp = bgp_lookup_by_name(vrf);
	} else
		bgp = bgp_get_default();

	if (!bgp) {
		if (use_json(argc, argv))
			vty_out(vty, "{}\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (use_json(argc, argv))
		json_list = json_object_new_array();

	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		show_bgp_srv6_locators_per_routemap_afi(vty, afi, bgp, detail, json_list);

	if (json_list)
		vty_json(vty, json_list);

	return CMD_SUCCESS;
}

void bgp_srv6_locator_per_routemap_init(void)
{
	install_element(VIEW_NODE, &show_bgp_srv6_locator_per_routemap_cmd);
}

/* code derived from ensure_vrf_tovpn_sid(), applied to auto mode only */
void bgp_srv6_per_locator_cache_ensure_tovpn_sid(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct in6_addr tovpn_sid = {};
	struct srv6_sid_ctx ctx = {};
	uint32_t sid_func;
	struct srv6_locator *locator;

	if (!bslc)
		return;

	/* auto mode is always configured.
	 * XXX when allocation mode are extended, more controls will be added here
	 */
	if (bslc->sid_policy.tovpn_sid)
		return;
	if (bslc->bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf SRv6 SID",
				   __func__, bslc->bgp->name_pretty);
		return;
	}
	locator = bgp_srv6_locator_lookup_all_by_name(bslc->locator_name);
	if (!bslc->sid_policy.tovpn_sid_locator && locator) {
		bslc->sid_policy.tovpn_sid_locator = srv6_locator_alloc(bslc->locator_name);
		srv6_locator_copy(bslc->sid_policy.tovpn_sid_locator, locator);
	}
	if (!bslc->sid_policy.tovpn_sid_locator)
		return;
	ctx.vrf_id = bslc->bgp->vrf_id;
	ctx.behavior = bslc->afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					   : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	ctx.alloc_mode = SRV6_SID_ALLOC_MODE_DYNAMIC;
	if (!bgp_zebra_request_srv6_sid(&ctx, &tovpn_sid, bslc->sid_policy.tovpn_sid_locator->name,
					&sid_func)) {
		zlog_err("%s: failed to request sid for vrf %s: afi %s locator %s", __func__,
			 bslc->bgp->name_pretty, afi2str(bslc->afi),
			 bslc->sid_policy.tovpn_sid_locator->name);
		return;
	}
	bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent = ctx.alloc_mode;
	if (debug)
		zlog_debug("%s: allocating new SID for vrf %s: afi %s, locator %s", __func__,
			   bslc->bgp->name_pretty, afi2str(bslc->afi),
			   bslc->sid_policy.tovpn_sid_locator->name);
}

void bgp_srv6_per_locator_cache_vrf_sid_update(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *tovpn_sid;
	struct in6_addr *tovpn_sid_ls = NULL;
	struct vrf *vrf;
	struct interface *ifp;
	struct bgp *bgp;
	afi_t afi;

	if (!bslc)
		return;

	tovpn_sid = bslc->sid_policy.tovpn_sid;
	if (!bslc->sid_policy.tovpn_sid)
		return;
	if (sid_same(bslc->sid_policy.tovpn_sid, bslc->sid_policy.tovpn_zebra_sid_last_sent))
		return;
	bgp = bslc->bgp;
	afi = bslc->afi;
	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: afi %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp->name_pretty, afi2str(afi));
		return;
	}

	if (debug)
		zlog_debug("%s: vrf %s: afi %s: setting sid %pI6 for vrf id %d", __func__,
			   bgp->name_pretty, afi2str(afi), tovpn_sid, bgp->vrf_id);

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return;

	ifp = if_get_vrf_loopback(bgp->vrf_id);
	if (!ifp)
		return;

	if (bslc->sid_policy.tovpn_sid_locator) {
		ctx.block_len = bslc->sid_policy.tovpn_sid_locator->block_bits_length;
		ctx.node_len = bslc->sid_policy.tovpn_sid_locator->node_bits_length;
		ctx.function_len = bslc->sid_policy.tovpn_sid_locator->function_bits_length;
		ctx.argument_len = bslc->sid_policy.tovpn_sid_locator->argument_bits_length;
		if (CHECK_FLAG(bslc->sid_policy.tovpn_sid_locator->flags, SRV6_LOCATOR_USID))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
	}
	ctx.table = vrf->data.l.table_id;
	act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	/* remove the local SID of the previous SID, if any */
	bgp_srv6_per_locator_cache_vrf_sid_withdraw(bslc);
	zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_ADD, tovpn_sid, IPV6_MAX_BITLEN,
			      ifp->ifindex, act, &ctx);

	tovpn_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*tovpn_sid_ls = *tovpn_sid;
	bslc->sid_policy.tovpn_zebra_sid_last_sent = tovpn_sid_ls;
}
