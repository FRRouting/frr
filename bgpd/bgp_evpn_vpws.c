// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * bgp_evpn_vpws.c: EVPN-VPWS service object + EAD-per-EVI origination.
 *
 * The cross-connect SID (End.DX2) is allocated per VPWS instance via
 * `interface <ac> sid auto` and stored on the vpws object.
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/memory.h"
#include "lib/linklist.h"
#include "lib/prefix.h"
#include "lib/stream.h"
#include "lib/if.h"
#include "lib/srv6.h"
#include "lib/zclient.h" /* zclient_send_localsid */

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_vpws.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_zebra.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_VPWS, "EVPN VPWS instance");
DEFINE_QOBJ_TYPE(bgp_evpn_vpws);

/* ---------- helpers ---------- */

static bool vpws_required_config_present(const struct bgp_evpn_vpws *vpws)
{
	return vpws->evi != 0 && vpws->source_ac_id != 0 && vpws->target_ac_id != 0 &&
	       vpws->prd_set && vpws->import_rtl && vpws->export_rtl;
}

static bool vpws_xc_sid_ready(const struct bgp_evpn_vpws *vpws)
{
	return vpws && vpws->bgp && vpws->bgp->evpn_encap == BGP_EVPN_ENCAP_MODE_SRV6 &&
	       vpws->ac_ifindex_valid && vpws->sid_allocated && vpws->sid_locator;
}

/* Build the SRv6 SID context used to talk to zebra. The (behavior, oif,
 * dt2_vni) triple is the key zebra uses for SID alloc/release, so each
 * VPWS instance gets a distinct SID even though all share End.DX2.
 */
static void vpws_build_sid_ctx(const struct bgp_evpn_vpws *vpws, struct srv6_sid_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DX2;
	ctx->oif = vpws->ac_ifindex;
	ctx->dt2_vni = vpws->evi;
	/* vrf_id stays 0 (default) - this BGP instance lives in default VRF.
	 * If you support per-VRF EVPN-VPWS later, set this.
	 */
}

/*
 * Install / remove the local End.DX2 decap SID through the RIB, exactly as
 * bgp_evpn_srv6_install_local_decap() does for End.DT2U/DT2M.  Ownership of the
 * decap route lives in bgpd (zclient_send_localsid); zebra's normal RIB/dplane
 * path programs and reconciles it, so it shows in "show ipv6 route" and needs
 * no raw-netlink install or orphan-flush in zebra.
 */
static void bgp_evpn_vpws_install_local_decap(struct bgp_evpn_vpws *vpws)
{
	struct seg6local_context ctx = {};
	const struct srv6_locator *loc;

	if (!vpws_xc_sid_ready(vpws) || vpws->decap_installed)
		return;

	loc = vpws->sid_locator;
	ctx.block_len = loc->block_bits_length;
	ctx.node_len = loc->node_bits_length;
	ctx.function_len = loc->function_bits_length;
	ctx.argument_len = loc->argument_bits_length;
	if (CHECK_FLAG(loc->flags, SRV6_LOCATOR_USID))
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
	/* End.DX2 encodes its cross-connect output (the AC) as SEG6_LOCAL_OIF. */
	ctx.oif = vpws->ac_ifindex;

	zlog_info("VPWS %s: installing End.DX2 SID %pI6 oif %u", vpws->name, &vpws->local_sid,
		  vpws->ac_ifindex);
	zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_ADD, &vpws->local_sid, IPV6_MAX_BITLEN,
			      vpws->ac_ifindex, ZEBRA_SEG6_LOCAL_ACTION_END_DX2, &ctx);
	vpws->decap_installed = true;
}

static void bgp_evpn_vpws_uninstall_local_decap(struct bgp_evpn_vpws *vpws)
{
	struct seg6local_context ctx = {};

	if (!vpws->decap_installed || IN6_IS_ADDR_UNSPECIFIED(&vpws->local_sid))
		return;

	ctx.oif = vpws->ac_ifindex;
	zlog_info("VPWS %s: removing End.DX2 SID %pI6", vpws->name, &vpws->local_sid);
	zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE, &vpws->local_sid, IPV6_MAX_BITLEN,
			      vpws->ac_ifindex, ZEBRA_SEG6_LOCAL_ACTION_END_DX2, &ctx);
	vpws->decap_installed = false;
}

/*
 * Ask zebra to allocate an SRv6 End.DX2 SID for this VPWS instance.
 *
 * This is the Option B flow: zebra is the authoritative allocator. The
 * SID arrives asynchronously via ZAPI notify; bgp_evpn_vpws_handle_sid_notify()
 * stores it on the vpws struct and calls bgp_evpn_vpws_originate().
 */
static void vpws_request_sid(struct bgp_evpn_vpws *vpws)
{
	struct srv6_sid_ctx ctx;
	uint32_t sid_func = 0;
	const char *loc_name;

	if (!vpws || !vpws->bgp) {
		zlog_warn("VPWS req_sid: NULL vpws/bgp");
		return;
	}
	if (!vpws->sid_auto) {
		zlog_debug("VPWS %s: req_sid skipped (sid_auto=0)", vpws->name);
		return;
	}
	if (!vpws->ac_ifindex_valid) {
		zlog_debug("VPWS %s: req_sid skipped (AC not resolved)", vpws->name);
		return;
	}
	if (vpws->sid_requested || vpws->sid_allocated) {
		zlog_debug("VPWS %s: req_sid skipped (requested=%d allocated=%d)", vpws->name,
			   vpws->sid_requested, vpws->sid_allocated);
		return;
	}

	/* Per-instance locator (mirrors `evi N locator X`) takes precedence;
	 * fall back to the BGP-instance-wide locator for backward compat.
	 */
	loc_name = (vpws->locator_name[0] != '\0') ? vpws->locator_name
						   : vpws->bgp->srv6_locator_name;
	if (!loc_name || !loc_name[0]) {
		zlog_warn("VPWS %s: no SRv6 locator bound (instance or BGP), cannot allocate SID",
			  vpws->name);
		return;
	}

	vpws_build_sid_ctx(vpws, &ctx);

	zlog_debug("VPWS %s: sending ZAPI SID request: behavior=End.DX2 oif=%u dt2_vni=%u locator=%s",
		   vpws->name, ctx.oif, ctx.dt2_vni, loc_name);


	/* Dynamic allocation: pass a pointer to a zero struct rather than
	 * NULL. srv6_manager_get_sid() in zclient.c reads through the
	 * pointer (sid_zero_ipv6 / sid_same / memcmp) and crashes or sets
	 * the HAS_SID_VALUE flag spuriously if given NULL, which would
	 * flip the mode from DYNAMIC to EXPLICIT and make zebra reject
	 * the request with "parent block/locator not found for SID ::".
	 */
	{
		struct in6_addr sid_zero = {};

		if (bgp_zebra_request_srv6_sid(&ctx, &sid_zero, loc_name, &sid_func)) {
			vpws->sid_requested = true;
			zlog_debug("VPWS %s: ZAPI SID request accepted, awaiting notify",
				   vpws->name);
		} else {
			zlog_warn("VPWS %s: ZAPI SID request FAILED at send time", vpws->name);
		}
	}
}

static void vpws_release_sid(struct bgp_evpn_vpws *vpws)
{
	struct srv6_sid_ctx ctx;

	if (!vpws || !vpws->bgp)
		return;
	if (!vpws->sid_requested && !vpws->sid_allocated)
		return;

	vpws_build_sid_ctx(vpws, &ctx);
	/* Release under the same locator the SID was allocated from
	 * (per-instance if bound, else the BGP-instance-wide locator).
	 */
	bgp_zebra_release_srv6_sid(&ctx, (vpws->locator_name[0] != '\0')
						 ? vpws->locator_name
						 : vpws->bgp->srv6_locator_name);

	if (vpws->sid_locator) {
		srv6_locator_free(vpws->sid_locator);
		vpws->sid_locator = NULL;
	}
	memset(&vpws->local_sid, 0, sizeof(vpws->local_sid));
	vpws->sid_requested = false;
	vpws->sid_allocated = false;
	zlog_debug("VPWS %s: ZAPI SID released", vpws->name);
}

/*
 * Bind (or clear) a per-instance SRv6 locator for this VPWS service, mirroring
 * the L2 EVPN `evi N locator X` model.  When set, the End.DX2 SID is drawn from
 * this locator instead of the BGP-instance-wide one.  Changing the locator
 * releases the SID held under the old locator and re-requests from the new one.
 * Pass NULL/empty to clear (revert to the instance-wide locator).
 */
int bgp_evpn_vpws_set_locator(struct bgp_evpn_vpws *vpws, const char *locname)
{
	bool want = (locname && locname[0] != '\0');

	if (!vpws)
		return -1;

	/* Idempotent: no change. */
	if (want) {
		if (strncmp(vpws->locator_name, locname, sizeof(vpws->locator_name)) == 0)
			return 0;
	} else if (vpws->locator_name[0] == '\0') {
		return 0;
	}

	/* Release the SID held under the *current* locator before switching. */
	vpws_release_sid(vpws);

	if (want)
		snprintf(vpws->locator_name, sizeof(vpws->locator_name), "%s", locname);
	else
		vpws->locator_name[0] = '\0';

	/* Re-request from the new locator (no-op until prerequisites are met). */
	vpws_request_sid(vpws);
	return 0;
}

/*
 * Build the Type-1 EAD-EVI NLRI prefix for this VPWS service.
 * Ethernet Tag = local source AC-ID, ESI = zero (single-homed).
 */
static void vpws_build_prefix(const struct bgp_evpn_vpws *vpws, struct prefix_evpn *p)
{
	esi_t zero_esi_local = {};
	struct ipaddr originator_ip = {};

	/* 10.6: build_evpn_type1_prefix() takes the originator as a
	 * struct ipaddr (by value); wrap the IPv4 router-id.
	 */
	originator_ip.ipa_type = IPADDR_V4;
	originator_ip.ipaddr_v4 = vpws->bgp->router_id;

	build_evpn_type1_prefix(p, vpws->source_ac_id, &zero_esi_local, originator_ip);
}

/*
 * Build the BGP path attribute for the outbound EAD-EVI: encap = VXLAN
 * extcomm (this is what existing EVPN paths attach), export RTs, label
 * derived from the EVI, and the cross-connect SID attached as
 * attr->srv6_l2vpn so the Prefix-SID encoder emits the L2 Service TLV
 * with End.DX2.
 */
static void vpws_build_attr(const struct bgp_evpn_vpws *vpws, struct attr *attr)
{
	struct bgp *bgp = vpws->bgp;
	struct ecommunity ecom_encap;
	struct ecommunity_val eval;
	struct srv6_locator *xc_loc;
	struct in6_addr *xc_sid;

	memset(attr, 0, sizeof(*attr));
	bgp_attr_default_set(attr, bgp, BGP_ORIGIN_IGP);

	/* IPv4 nexthop = router-id; matches the existing EAD path */
	attr->nexthop.s_addr = bgp->router_id.s_addr;
	attr->mp_nexthop_global_in.s_addr = bgp->router_id.s_addr;
	attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	/* MPLS label derived from EVI, same convention as ELAN */
	vni2label(vpws->evi, &(attr->label));

	/* Encap extcommunity = VXLAN (consistent with existing EVPN code;
	 * the SRv6 binding rides as a separate Prefix-SID attribute).
	 */
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(BGP_ENCAP_TYPE_VXLAN, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;
	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));

	/* Add export RTs (single struct ecommunity, may carry multiple RT
	 * values).
	 */
	if (vpws->export_rtl)
		bgp_attr_set_ecommunity(attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
							       vpws->export_rtl));

	/* Attach SRv6 L2 Service TLV with this VPWS instance's End.DX2 SID.
	 * Source is now per-instance state (vpws->local_sid / sid_locator),
	 * not the per-AFI cross-connect policy slot.
	 */
	xc_loc = vpws->sid_locator;
	xc_sid = &((struct bgp_evpn_vpws *)vpws)->local_sid; /* drop const */

	struct bgp_attr_srv6_l3service *srv6_l2vpn =
		XCALLOC(MTYPE_BGP_SRV6_L3SERVICE, sizeof(struct bgp_attr_srv6_l3service));
	srv6_l2vpn->sid_flags = 0x00;
	/* Bug-fix: select the uSID-flavoured endpoint_behavior codepoint
	 * (uDX2) when the cross-connect locator has the SRV6_LOCATOR_USID
	 * flag set (set by either `behavior usid` or `format usid-f3216`
	 * after the Bug-1 flag-sync fix in zebra_srv6_locator_format_set).
	 */
	srv6_l2vpn->endpoint_behavior =
		CHECK_FLAG(xc_loc->flags, SRV6_LOCATOR_USID)
			? bgp_evpn_srv6_l2_usid_behavior(SRV6_ENDPOINT_BEHAVIOR_END_DX2_USID)
			: SRV6_ENDPOINT_BEHAVIOR_END_DX2;
	srv6_l2vpn->loc_block_len = xc_loc->block_bits_length;
	srv6_l2vpn->loc_node_len = xc_loc->node_bits_length;
	srv6_l2vpn->func_len = xc_loc->function_bits_length;
	srv6_l2vpn->arg_len = xc_loc->argument_bits_length;
	srv6_l2vpn->transposition_len = 0;
	srv6_l2vpn->transposition_offset = 0;
	memcpy(&srv6_l2vpn->sid, xc_sid, sizeof(struct in6_addr));
	bgp_attr_set_srv6_l2vpn(attr, srv6_l2vpn);
}

/* ---------- lifecycle ---------- */

int bgp_evpn_vpws_init(struct bgp *bgp)
{
	if (!bgp)
		return -1;
	if (bgp->evpn_vpws_inited)
		return 0;
	evpn_vpws_list_init(&bgp->evpn_vpws_list);
	bgp->evpn_vpws_inited = true;
	return 0;
}

void bgp_evpn_vpws_finish(struct bgp *bgp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return;

	frr_each_safe (evpn_vpws_list, &bgp->evpn_vpws_list, vpws)
		bgp_evpn_vpws_delete(vpws);

	evpn_vpws_list_fini(&bgp->evpn_vpws_list);
	bgp->evpn_vpws_inited = false;
}

/* ---------- find / create / delete ---------- */

struct bgp_evpn_vpws *bgp_evpn_vpws_find(struct bgp *bgp, const char *name)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited || !name)
		return NULL;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws)
		if (strncmp(vpws->name, name, sizeof(vpws->name)) == 0)
			return vpws;
	return NULL;
}

bool bgp_evpn_vpws_sid_is_local(struct bgp *bgp, const struct in6_addr *sid)
{
	struct bgp_evpn_vpws *vpws;
	struct prefix_ipv6 sid_p;

	if (!bgp || !bgp->evpn_vpws_inited || !sid)
		return false;

	sid_p.family = AF_INET6;
	sid_p.prefixlen = IPV6_MAX_BITLEN;
	sid_p.prefix = *sid;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		/* Exact match against this instance's own allocated SID. */
		if (vpws->sid_allocated && IPV6_ADDR_SAME(&vpws->local_sid, sid))
			return true;

		/* Or any SID under this instance's per-instance locator
		 * (LOC-R2/LOC-R3/...), which the BGP-wide locator check misses.
		 */
		if (vpws->sid_locator &&
		    prefix_match((const struct prefix *)&vpws->sid_locator->prefix,
				 (const struct prefix *)&sid_p))
			return true;
	}
	return false;
}

struct bgp_evpn_vpws *bgp_evpn_vpws_find_by_target(struct bgp *bgp, uint32_t evi, uint32_t eth_tag)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return NULL;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		if (vpws->evi != evi)
			continue;
		if (vpws->target_ac_id != eth_tag)
			continue;
		return vpws;
	}
	return NULL;
}

struct bgp_evpn_vpws *bgp_evpn_vpws_create(struct bgp *bgp, const char *name)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !name)
		return NULL;
	if (bgp_evpn_vpws_find(bgp, name))
		return NULL;
	if (!bgp->evpn_vpws_inited)
		bgp_evpn_vpws_init(bgp);

	vpws = XCALLOC(MTYPE_BGP_EVPN_VPWS, sizeof(*vpws));
	vpws->bgp = bgp;
	strlcpy(vpws->name, name, sizeof(vpws->name));

	QOBJ_REG(vpws, bgp_evpn_vpws);
	evpn_vpws_list_add_tail(&bgp->evpn_vpws_list, vpws);
	return vpws;
}

void bgp_evpn_vpws_delete(struct bgp_evpn_vpws *vpws)
{
	struct bgp *bgp;

	if (!vpws)
		return;

	bgp = vpws->bgp;

	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);

	bgp_evpn_vpws_uninstall_local_decap(vpws);
	bgp_zebra_send_vpws_remote_del(vpws->name);
	bgp_zebra_send_vpws_local_del(vpws->name);
	vpws_release_sid(vpws);

	/*
	 * Uninstall the IPv6 underlay /128 we installed for our peer SID.
	 *
	 * During bgpd shutdown, bgp_delete() frees all peers (peer_delete)
	 * before bgp_evpn_vpws_finish() runs, so vpws->peer_peer_snap would be
	 * a dangling pointer (use-after-free) inside
	 * bgp_evpn_program_srv6_ipv6_route().  Skip the withdraw in that case -
	 * zebra purges every bgpd-owned route when bgpd disconnects, so the
	 * /128 is removed regardless.
	 */
	if (vpws->peer_present && vpws->peer_attr_snap) {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
			bgp_evpn_program_srv6_ipv6_route(bgp, &vpws->peer_sid, vpws->peer_attr_snap,
							 vpws->peer_peer_snap, false);
		bgp_attr_unintern(&vpws->peer_attr_snap);
	}
	vpws->peer_attr_snap = NULL;
	vpws->peer_peer_snap = NULL;
	vpws->peer_present = false;

	if (vpws->import_rtl)
		ecommunity_free(&vpws->import_rtl);
	if (vpws->export_rtl)
		ecommunity_free(&vpws->export_rtl);

	if (bgp && bgp->evpn_vpws_inited)
		evpn_vpws_list_del(&bgp->evpn_vpws_list, vpws);

	QOBJ_UNREG(vpws);
	XFREE(MTYPE_BGP_EVPN_VPWS, vpws);
}

/* ---------- setters ---------- */

/*
 * Walk the global L2VPN/EVPN RIB and re-feed any already-installed
 * EAD-per-EVI route into the VPWS handler. Used when a vpws-instance
 * is created/updated after the routes were imported - without this,
 * the operator has to `clear bgp ... in` to force re-parse.
 */
static void vpws_replay_existing_ead(struct bgp *bgp)
{
	struct bgp_table *table;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (!bgp || !bgp->rib[afi][safi])
		return;

	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
			const struct prefix *p = bgp_dest_get_prefix(dest);
			const struct prefix_evpn *evp = (const struct prefix_evpn *)p;

			if (evp->prefix.route_type != BGP_EVPN_AD_ROUTE)
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
				/* Only locally-installed (i.e., already RT-imported)
				 * paths. Skip our own originations.
				 */
				if (pi->peer == bgp->peer_self)
					continue;
				if (!pi->attr || !bgp_attr_get_srv6_l2vpn(pi->attr))
					continue;

				bgp_evpn_vpws_handle_remote_ead(bgp, evp,
								bgp_attr_get_srv6_l2vpn(pi->attr),
								pi->attr, pi->peer);
			}
		}
	}
}

int bgp_evpn_vpws_set_ac_ids(struct bgp_evpn_vpws *vpws, uint32_t source, uint32_t target)
{
	if (!vpws || source == 0 || target == 0)
		return -1;
	if (vpws->source_ac_id == source && vpws->target_ac_id == target)
		return 0;
	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);
	vpws->source_ac_id = source;
	vpws->target_ac_id = target;
	bgp_evpn_vpws_originate(vpws);

	/* Replay any previously-imported EAD-EVI routes through the
	 * handler now that we know our target_ac_id.
	 */
	vpws_replay_existing_ead(vpws->bgp);

	return 0;
}

int bgp_evpn_vpws_set_evi(struct bgp_evpn_vpws *vpws, uint32_t evi)
{
	if (!vpws || evi == 0)
		return -1;
	if (vpws->evi == evi)
		return 0;
	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);
	vpws->evi = evi;
	bgp_evpn_vpws_originate(vpws);
	return 0;
}

int bgp_evpn_vpws_set_rd(struct bgp_evpn_vpws *vpws, const struct prefix_rd *prd)
{
	if (!vpws || !prd)
		return -1;
	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);
	vpws->prd = *prd;
	vpws->prd_set = true;
	bgp_evpn_vpws_originate(vpws);
	return 0;
}

int bgp_evpn_vpws_set_rt(struct bgp_evpn_vpws *vpws, struct ecommunity *rt, int direction)
{
	if (!vpws || !rt)
		return -1;

	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);

	if (direction & 1) {
		if (vpws->import_rtl)
			ecommunity_free(&vpws->import_rtl);
		vpws->import_rtl = ecommunity_dup(rt);
	}
	if (direction & 2) {
		if (vpws->export_rtl)
			ecommunity_free(&vpws->export_rtl);
		vpws->export_rtl = ecommunity_dup(rt);
	}

	bgp_evpn_vpws_originate(vpws);
	return 0;
}

int bgp_evpn_vpws_clear_rt(struct bgp_evpn_vpws *vpws, int direction)
{
	if (!vpws)
		return -1;
	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);
	if ((direction & 1) && vpws->import_rtl)
		ecommunity_free(&vpws->import_rtl);
	if ((direction & 2) && vpws->export_rtl)
		ecommunity_free(&vpws->export_rtl);
	return 0;
}

/* ---------- origination / withdraw ---------- */

int bgp_evpn_vpws_originate(struct bgp_evpn_vpws *vpws)
{
	struct bgp *bgp;
	struct prefix_evpn p;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (!vpws)
		return -1;

	bgp = vpws->bgp;

	if (!vpws_required_config_present(vpws)) {
		zlog_debug("VPWS %s: incomplete config, skip originate", vpws->name);
		return 0;
	}
	if (!vpws_xc_sid_ready(vpws)) {
		zlog_debug("VPWS %s: cross-connect SID not ready, skip originate", vpws->name);
		return 0;
	}

	memset(&p, 0, sizeof(p));
	vpws_build_prefix(vpws, &p);
	vpws_build_attr(vpws, &attr);

	attr_new = bgp_attr_intern(&attr);

	/* Insert into the global L2VPN/EVPN RIB under the configured RD. */
	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, (struct prefix *)&p, &vpws->prd);

	/* Look for an existing local path; replace if attr differs. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_STATIC)
			break;
	}

	if (pi) {
		/*
		 * If a withdraw earlier in the same operation (e.g.
		 * bgp_evpn_vpws_on_locator_update() does withdraw then
		 * re-originate before bgp_process() runs) marked this local
		 * path BGP_PATH_REMOVED, the path is still on the dest list but
		 * flagged for deletion. Reusing it as-is would let the deferred
		 * bgp_process() withdraw it, so the re-advertised EAD is never
		 * selected (bestpath selected=0x0) and the peer only sees an
		 * MP_UNREACH. Restore it first so the update is advertised.
		 */
		bool was_removed = CHECK_FLAG(pi->flags, BGP_PATH_REMOVED);

		if (was_removed)
			bgp_path_info_restore(dest, pi);

		/* Update. Skip the no-op shortcut if we just restored a path
		 * that was pending deletion - it must be re-processed so the
		 * route is re-advertised even when the attr is unchanged.
		 */
		if (!was_removed && attrhash_cmp(pi->attr, attr_new)) {
			bgp_attr_unintern(&attr_new);
			bgp_dest_unlock_node(dest);
			aspath_unintern(&attr.aspath);
			bgp_attr_extra_discard(&attr);
			return 0;
		}
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	} else {
		/* New */
		pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self, attr_new,
			       dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_add(dest, pi);
	}

	bgp_process(bgp, dest, pi, afi, safi);
	bgp_dest_unlock_node(dest);
	aspath_unintern(&attr.aspath);
	/* Release the stack attr's extra (SRv6 L2 Service SID); on a duplicate
	 * intern it is not transferred and would otherwise leak.
	 */
	bgp_attr_extra_discard(&attr);

	vpws->advertised = true;
	zlog_debug("VPWS %s: EAD-EVI advertised (evi=%u source=%u)", vpws->name, vpws->evi,
		   vpws->source_ac_id);

	/* Re-feed any already-imported peer EAD-EVI routes through the
	 * handler. Required when this vpws-instance was configured AFTER
	 * the peer's Type-1 was already in the RIB (otherwise the handler
	 * ran once at import-time, found no matching instance, and dropped
	 * the route - `Peer SID : -` would persist until a session bounce).
	 */
	vpws_replay_existing_ead(vpws->bgp);

	return 0;
}

void bgp_evpn_vpws_withdraw(struct bgp_evpn_vpws *vpws)
{
	struct bgp *bgp;
	struct prefix_evpn p;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (!vpws || !vpws->advertised)
		return;
	if (!vpws->prd_set || vpws->evi == 0 || vpws->source_ac_id == 0)
		return;

	bgp = vpws->bgp;

	memset(&p, 0, sizeof(p));
	vpws_build_prefix(vpws, &p);

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, (struct prefix *)&p, &vpws->prd);
	if (!dest) {
		vpws->advertised = false;
		return;
	}

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_STATIC) {
			bgp_path_info_mark_for_delete(dest, pi);
			bgp_process(bgp, dest, pi, afi, safi);
			break;
		}
	}

	bgp_dest_unlock_node(dest);
	vpws->advertised = false;
	zlog_debug("VPWS %s: EAD-EVI withdrawn", vpws->name);
}

void bgp_evpn_vpws_reorigin_all(struct bgp *bgp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		if (vpws->advertised)
			bgp_evpn_vpws_withdraw(vpws);
		bgp_evpn_vpws_originate(vpws);
	}
}

/* ---------- config write ---------- */

static void vpws_config_write_one(struct vty *vty, const struct bgp_evpn_vpws *vpws)
{
	char rd_buf[RD_ADDRSTRLEN];
	char *rt_str;

	vty_out(vty, "  vpws-instance %s\n", vpws->name);

	if (vpws->source_ac_id || vpws->target_ac_id)
		vty_out(vty, "   vpws-id source %u target %u\n", vpws->source_ac_id,
			vpws->target_ac_id);

	if (vpws->evi)
		vty_out(vty, "   vpws-evi %u\n", vpws->evi);

	if (vpws->prd_set) {
		prefix_rd2str(&vpws->prd, rd_buf, sizeof(rd_buf),
			      vpws->bgp ? vpws->bgp->asnotation : ASNOTATION_PLAIN);
		vty_out(vty, "   rd %s\n", rd_buf);
	}

	/* Collapse to `route-target both` when import and export match,
	 * else print them separately.
	 */
	if (vpws->import_rtl && vpws->export_rtl &&
	    ecommunity_cmp(vpws->import_rtl, vpws->export_rtl)) {
		rt_str = ecommunity_ecom2str(vpws->import_rtl, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		if (rt_str) {
			vty_out(vty, "   route-target both %s\n", rt_str);
			ecommunity_strfree(&rt_str);
		}
	} else {
		if (vpws->import_rtl) {
			rt_str = ecommunity_ecom2str(vpws->import_rtl, ECOMMUNITY_FORMAT_ROUTE_MAP,
						     0);
			if (rt_str) {
				vty_out(vty, "   route-target import %s\n", rt_str);
				ecommunity_strfree(&rt_str);
			}
		}
		if (vpws->export_rtl) {
			rt_str = ecommunity_ecom2str(vpws->export_rtl, ECOMMUNITY_FORMAT_ROUTE_MAP,
						     0);
			if (rt_str) {
				vty_out(vty, "   route-target export %s\n", rt_str);
				ecommunity_strfree(&rt_str);
			}
		}
	}

	if (vpws->ac_ifname[0])
		vty_out(vty, "   interface %s%s\n", vpws->ac_ifname,
			vpws->sid_auto ? " sid auto" : "");

	if (vpws->locator_name[0])
		vty_out(vty, "   locator %s\n", vpws->locator_name);

	vty_out(vty, "  exit-vpws-instance\n");
}

void bgp_evpn_vpws_config_write_all(struct vty *vty, struct bgp *bgp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return;


	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws)
		vpws_config_write_one(vty, vpws);
}

/* ---------- inbound hook ----------
 *
 * Called from bgp_evpn_mh.c on Type-1 EAD-EVI install / uninstall paths.
 * For VPWS we only consume EAD-EVI routes whose Ethernet Tag matches
 * our configured target_ac_id AND whose EVI matches.
 *
 * On match we record the peer SID and (in a follow-on patch) trigger
 * zebra to set up the AC->srl2 cross-connect mapping.
 */
void bgp_evpn_vpws_handle_remote_ead(struct bgp *bgp, const struct prefix_evpn *p,
				     const struct bgp_attr_srv6_l3service *svc, struct attr *attr,
				     struct peer *peer)
{
	struct bgp_evpn_vpws *vpws;
	uint32_t eth_tag;

	if (!bgp || !p || !svc)
		return;

	/* Only EAD routes are interesting. Tag is in the ead_addr. */
	if (p->prefix.route_type != BGP_EVPN_AD_ROUTE)
		return;

	eth_tag = p->prefix.ead_addr.eth_tag;

	/*
	 * For single-homed VPWS, the EVI scoping is implicit through the
	 * RT match (the inbound path has already imported on RT). We
	 * additionally cross-check on (evi, target) so a different RT
	 * sharing the same tag space doesn't accidentally bind.
	 */
	vpws = bgp_evpn_vpws_find_by_target(bgp, /*evi*/ 0, eth_tag);
	if (!vpws) {
		/* Try any EVI match; in single-instance mode this is fine. */
		struct bgp_evpn_vpws *v;

		frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, v)
			if (v->target_ac_id == eth_tag) {
				vpws = v;
				break;
			}
	}
	if (!vpws)
		return;

	/*
	 * If the peer SID changed (e.g. legacy<->uSID locator flip on the
	 * remote PE), withdraw the underlay /128 for the OLD peer SID before
	 * we overwrite it. This EAD arrives as an attribute change on the same
	 * NLRI (not a withdraw), so the EAD-withdraw path never runs and the
	 * old /128 would otherwise be stranded in the kernel.
	 */
	if (vpws->peer_present && !IN6_IS_ADDR_UNSPECIFIED(&vpws->peer_sid) &&
	    memcmp(&vpws->peer_sid, &svc->sid, sizeof(vpws->peer_sid)) != 0 &&
	    vpws->peer_attr_snap) {
		zlog_debug("VPWS %s: peer SID changed (%pI6 -> %pI6), withdrawing old underlay /128",
			   vpws->name, &vpws->peer_sid, &svc->sid);
		bgp_evpn_program_srv6_ipv6_route(bgp, &vpws->peer_sid, vpws->peer_attr_snap,
						 vpws->peer_peer_snap, false);
	}

	vpws->peer_present = true;
	vpws->peer_sid = svc->sid;
	vpws->peer_behavior = svc->endpoint_behavior;

	/* NEW: push peer dataplane (create srl2 with peer SID, enslave to bridge) */
	bgp_zebra_send_vpws_remote(vpws->name, &vpws->peer_sid);

	/*
	 * Install the IPv6 underlay /128 to the peer DX2 SID so the srl2
	 * encap has a route to the remote endpoint. process_type1_route()
	 * also installs this, but only when a fresh EAD UPDATE is received.

	 * On a local reconfigure (peer's EAD already in the RIB, no new
	 * UPDATE) that path does not re-run, while this hook does - so
	 * (re)install here to keep the underlay symmetric with the srl2
	 * create above and with the teardown flush.
	 */
	if (attr)
		bgp_evpn_program_srv6_ipv6_route(bgp, &vpws->peer_sid, attr, peer, true);

	if (vpws->peer_attr_snap)
		bgp_attr_unintern(&vpws->peer_attr_snap);

	vpws->peer_attr_snap = attr ? bgp_attr_intern(attr) : NULL;
	vpws->peer_peer_snap = peer;

	zlog_debug("VPWS %s: peer SID learned (eth_tag=%u behavior=0x%04x)", vpws->name, eth_tag,
		   svc->endpoint_behavior);
}

void bgp_evpn_vpws_handle_remote_ead_withdraw(struct bgp *bgp, const struct prefix_evpn *p)
{
	struct bgp_evpn_vpws *vpws;
	uint32_t eth_tag;
	struct bgp_evpn_vpws *v;

	if (!bgp || !p)
		return;
	if (p->prefix.route_type != BGP_EVPN_AD_ROUTE)
		return;

	eth_tag = p->prefix.ead_addr.eth_tag;

	vpws = NULL;
	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, v)
		if (v->target_ac_id == eth_tag) {
			vpws = v;
			break;
		}
	if (!vpws)
		return;

	vpws->peer_present = false;
	struct in6_addr saved_sid = vpws->peer_sid;

	memset(&vpws->peer_sid, 0, sizeof(vpws->peer_sid));

	bgp_zebra_send_vpws_remote_del(vpws->name);

	if (vpws->peer_attr_snap) {
		bgp_evpn_program_srv6_ipv6_route(bgp, &saved_sid, vpws->peer_attr_snap,
						 vpws->peer_peer_snap, false);
		bgp_attr_unintern(&vpws->peer_attr_snap);
		vpws->peer_attr_snap = NULL;
		vpws->peer_peer_snap = NULL;
	}

	zlog_debug("VPWS %s: peer SID withdrawn (eth_tag=%u)", vpws->name, eth_tag);
}

/* ---------- per-instance AC + SID setters ---------- */

int bgp_evpn_vpws_set_interface(struct bgp_evpn_vpws *vpws, const char *ifname, bool sid_auto)
{
	struct interface *ifp;

	if (!vpws || !ifname || !ifname[0])
		return -1;

	/* If we already had a SID, withdraw the route and release it before
	 * switching AC. The new ifindex changes the srv6_sid_ctx.oif and
	 * therefore changes the SID identity in zebra.
	 */
	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);
	if (vpws->sid_requested || vpws->sid_allocated)
		vpws_release_sid(vpws);

	strlcpy(vpws->ac_ifname, ifname, sizeof(vpws->ac_ifname));
	vpws->sid_auto = sid_auto;

	/* Resolve ifindex now if possible. If the interface is not yet
	 * present, ifindex stays invalid; the interface-up hook from
	 * bgp_zebra.c will pick it up later. Lookup in the default VRF
	 * (matches what existing EVPN AC lookups use).
	 */
	ifp = if_lookup_by_name(ifname, vpws->bgp->vrf_id);
	if (ifp && if_is_operative(ifp)) {
		vpws->ac_ifindex = ifp->ifindex;
		vpws->ac_ifindex_valid = true;
	} else {
		vpws->ac_ifindex = 0;
		vpws->ac_ifindex_valid = false;
		zlog_debug("VPWS %s: interface %s not yet operational, deferring SID request",
			   vpws->name, ifname);
	}

	if (vpws->ac_ifindex_valid && vpws->sid_auto)
		vpws_request_sid(vpws);
	/* Origination will fire from the SID notify handler when zebra
	 * responds.
	 */
	return 0;
}

int bgp_evpn_vpws_clear_interface(struct bgp_evpn_vpws *vpws)
{
	struct bgp *bgp;

	if (!vpws)
		return -1;

	bgp = vpws->bgp;

	if (vpws->advertised)
		bgp_evpn_vpws_withdraw(vpws);

	if (vpws->peer_attr_snap) {
		bgp_evpn_program_srv6_ipv6_route(bgp, &vpws->peer_sid, vpws->peer_attr_snap,
						 vpws->peer_peer_snap, false);
		bgp_attr_unintern(&vpws->peer_attr_snap);
		vpws->peer_attr_snap = NULL;
		vpws->peer_peer_snap = NULL;
	}
	vpws->peer_present = false;
	memset(&vpws->peer_sid, 0, sizeof(vpws->peer_sid));

	bgp_zebra_send_vpws_remote_del(vpws->name);
	bgp_zebra_send_vpws_local_del(vpws->name);
	vpws_release_sid(vpws);

	vpws->ac_ifname[0] = '\0';
	vpws->ac_ifindex = 0;
	vpws->ac_ifindex_valid = false;
	vpws->sid_auto = false;

	return 0;
}

/* ---------- ZAPI SID notify dispatch ----------
 *
 * Called from bgp_zebra.c::bgp_zebra_srv6_sid_notify() before its
 * existing per-AFI DX2 handling. If the notify (behavior, oif, evi)
 * matches a configured VPWS instance, consume it here and return true.
 * Otherwise return false so the caller can run the per-AFI logic.
 */
bool bgp_evpn_vpws_handle_sid_notify(struct bgp *bgp, ifindex_t oif, uint32_t evi,
				     uint16_t behavior, const struct in6_addr *sid_addr,
				     const struct srv6_locator *locator, bool allocated)
{
	struct bgp_evpn_vpws *vpws = NULL;
	struct bgp_evpn_vpws *v;

	zlog_debug("VPWS notify-dispatch: behavior=0x%04x oif=%u evi=%u sid=%pI6 allocated=%d",
		   behavior, oif, evi, sid_addr, allocated);

	if (!bgp || !bgp->evpn_vpws_inited || !sid_addr || !locator) {
		zlog_debug("VPWS notify-dispatch: skipped (NULL inputs or empty list)");
		return false;
	}
	if (behavior != ZEBRA_SEG6_LOCAL_ACTION_END_DX2) {
		zlog_debug("VPWS notify-dispatch: skipped (behavior 0x%04x != END_DX2)", behavior);
		return false;
	}
	if (oif == 0) {
		zlog_debug("VPWS notify-dispatch: skipped (oif==0, per-AFI path)");
		return false;
	}

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, v) {
		zlog_debug("VPWS notify-dispatch: candidate %s ac_ifindex=%u valid=%d evi=%u",
			   v->name, v->ac_ifindex, v->ac_ifindex_valid, v->evi);
		if (v->ac_ifindex_valid && v->ac_ifindex == oif && v->evi == evi) {
			vpws = v;
			break;
		}
	}
	if (!vpws) {
		zlog_info(
			"VPWS notify-dispatch: no matching VPWS, falling through to per-AFI handler");
		return false;
	}

	zlog_debug("VPWS notify-dispatch: matched %s, consuming notify", vpws->name);

	if (allocated) {
		/* On a SID change (e.g. locator legacy<->uSID migration), remove the
		 * decap for the previous SID before local_sid is overwritten below.
		 */
		bgp_evpn_vpws_uninstall_local_decap(vpws);

		if (vpws->sid_locator) {
			srv6_locator_free(vpws->sid_locator);
			vpws->sid_locator = NULL;
		}
		vpws->sid_locator = srv6_locator_alloc(locator->name);
		srv6_locator_copy(vpws->sid_locator, locator);
		/*
		 * The notify dispatcher (bgp_zebra.c) passes the BGP instance's
		 * default locator struct, but this VPWS SID was actually
		 * allocated from the instance's own configured locator
		 * (vpws->locator_name) when one is set.  srv6_locator_copy()
		 * just overwrote the name with the default's, so restore the
		 * per-instance name — otherwise `show ... srv6` attributes every
		 * VPWS instance to the default locator even though their SIDs
		 * come from different locators.
		 */
		if (vpws->locator_name[0])
			strlcpy(vpws->sid_locator->name, vpws->locator_name,
				sizeof(vpws->sid_locator->name));
		vpws->local_sid = *sid_addr;
		vpws->sid_requested = false;
		vpws->sid_allocated = true;
		zlog_debug("VPWS %s: SRv6 SID %pI6 allocated (oif=%u evi=%u)", vpws->name,
			   sid_addr, oif, evi);
		bgp_evpn_vpws_originate(vpws);

		/* NEW: push VPWS dataplane setup to zebra */
		bgp_zebra_send_vpws_local(vpws->name, vpws->ac_ifname, &vpws->local_sid);

		/* Install the local End.DX2 decap SID through the RIB (bgpd-owned,
		 * mirrors End.DT2U/DT2M) instead of a raw netlink install in zebra.
		 */
		bgp_evpn_vpws_install_local_decap(vpws);

		/*
		 * If LOCAL_DEL was previously sent (e.g. during locator format
		 * migration), zebra freed the zsrv6_vpws struct and lost the
		 * remote peer state.  The new LOCAL_ADD above re-created the
		 * struct with remote_present=false, so the auto-recreate path
		 * inside zebra_srv6_vpws_local_add() will not fire.
		 * Re-send REMOTE_ADD explicitly to restore the vpws-srl2 kernel
		 * interface with the peer's current SID.
		 */
		if (vpws->peer_present && !IN6_IS_ADDR_UNSPECIFIED(&vpws->peer_sid)) {
			zlog_debug("VPWS %s: new local SID %pI6 installed re-sending REMOTE_ADD for peer SID %pI6",
				   vpws->name, &vpws->local_sid, &vpws->peer_sid);
			bgp_zebra_send_vpws_remote(vpws->name, &vpws->peer_sid);
		}

	} else {
		/* SID released - remove the End.DX2 decap while local_sid is still valid. */
		bgp_evpn_vpws_uninstall_local_decap(vpws);

		if (vpws->advertised)
			bgp_evpn_vpws_withdraw(vpws);
		if (vpws->sid_locator) {
			srv6_locator_free(vpws->sid_locator);
			vpws->sid_locator = NULL;
		}
		memset(&vpws->local_sid, 0, sizeof(vpws->local_sid));
		vpws->sid_requested = false;
		vpws->sid_allocated = false;
		zlog_debug("VPWS %s: SRv6 SID released (oif=%u evi=%u)", vpws->name, oif, evi);
		bgp_zebra_send_vpws_local_del(vpws->name);
	}
	return true;
}

/*
 * Resolve a VPWS AC whose interface was not operational when configured.
 * bgp_evpn_vpws_set_interface() defers the SID request in that case (and
 * leaves a note that "the interface-up hook will pick it up later"); this
 * is that hook.  Called from bgp_zebra.c on interface add / up.
 */
void bgp_evpn_vpws_on_interface_up(struct bgp *bgp, struct interface *ifp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited || !ifp)
		return;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		if (vpws->ac_ifindex_valid)
			continue;
		if (strcmp(vpws->ac_ifname, ifp->name) != 0)
			continue;
		if (!if_is_operative(ifp))
			continue;

		vpws->ac_ifindex = ifp->ifindex;
		vpws->ac_ifindex_valid = true;
		vpws->sid_requested = false; /* drop any rejected pre-locator request */
		zlog_debug("VPWS %s: AC %s now operational (ifindex %u), requesting SID",
			   vpws->name, ifp->name, ifp->ifindex);
		vpws_request_sid(vpws);
		/* If the SID was already allocated (AC came up after the notify),
		 * the request above is a no-op; install the decap now that the oif
		 * is known.  Guarded by vpws_xc_sid_ready().
		 */
		bgp_evpn_vpws_install_local_decap(vpws);
	}
}

/*
 * Retry the End.DX2 SID request for every VPWS instance that does not yet
 * have one.  Called from the locator-notify handler when the SRv6 locator
 * becomes available.  Covers the boot config-order case: the interface-time
 * request was SENT but rejected by zebra because the locator was not yet
 * instantiated, leaving sid_requested stuck true.  Clearing it lets
 * vpws_request_sid() retry now.  Instances that already have a SID are
 * skipped, so this is churn-free on a steady-state locator refresh.
 */
void bgp_evpn_vpws_request_missing_sids(struct bgp *bgp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		if (vpws->sid_allocated)
			continue;
		vpws->sid_requested = false; /* drop the rejected boot request */
		vpws_request_sid(vpws);
	}
}

/*
 * bgp_evpn_vpws_on_locator_update - called when the SRv6 locator format
 * changes (e.g. legacy <-> uSID transition).
 *
 * Iterates every VPWS instance on @bgp, releases any currently-allocated
 * DX2 SID (so the old non-uSID / stale uSID function is returned to zebra),
 * then immediately re-requests a fresh SID from the new locator.  The new
 * SID arrives asynchronously through bgp_evpn_vpws_handle_sid_notify() which
 * re-originates the Type-1 EAD-EVI route with the corrected codepoint.
 */
void bgp_evpn_vpws_on_locator_update(struct bgp *bgp)
{
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited)
		return;

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		if (!vpws->sid_auto)
			continue;

		zlog_debug("VPWS %s: locator format changed, releasing DX2 SID %pI6 for reallocation",
			   vpws->name, &vpws->local_sid);

		/* Withdraw the BGP Type-1 EAD-EVI route so peers get a
		 * clean withdraw before we re-originate with the new SID.
		 */
		if (vpws->advertised)
			bgp_evpn_vpws_withdraw(vpws);

		/*
		 * Remove NS1's local vpws-srl2 (which points to the peer's SID)
		 * BEFORE sending LOCAL_DEL.  LOCAL_DEL frees the zsrv6_vpws struct
		 * inside zebra; any REMOTE_DEL processed after that would find NULL
		 * via vpws_find() and silently do nothing.  By sending REMOTE_DEL
		 * first (ZAPI is a FIFO), zebra tears down the srl2 cleanly while
		 * the struct is still alive.
		 */
		bgp_zebra_send_vpws_remote_del(vpws->name);

		/* Remove the old seg6local kernel route for the local DX2 SID.
		 * Without this the old route (e.g. 2001:db8:1:3::) stays in
		 * the kernel after the SID changes to the new format.
		 * This also frees the zsrv6_vpws struct in zebra, so it must
		 * come AFTER the REMOTE_DEL above.
		 */
		bgp_zebra_send_vpws_local_del(vpws->name);

		vpws_release_sid(vpws);
		vpws_request_sid(vpws);
	}
}
