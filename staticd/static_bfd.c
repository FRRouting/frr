// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static daemon BFD integration.
 *
 * Copyright (C) 2020-2022 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include <zebra.h>

#include "frrevent.h"
#include "lib/bfd.h"
#include "lib/printfrr.h"
#include "lib/srcdest_table.h"
#include "lib/json.h"

#include "staticd/static_routes.h"
#include "staticd/static_zebra.h"
#include "staticd/static_debug.h"
#include "staticd/static_trace.h"

#include "lib/openbsd-queue.h"

enum static_bfd_holddown_cancel_reason {
	STATIC_BFD_HLDN_CANCEL_ADMIN_DOWN = 0,
	STATIC_BFD_HLDN_CANCEL_BFD_UP = 1,
	STATIC_BFD_HLDN_CANCEL_REARM = 2,
	STATIC_BFD_HLDN_CANCEL_MONITOR_OFF = 3,
};

static void static_bfd_holddown_timer_cancel(
	struct static_nexthop *sn,
	enum static_bfd_holddown_cancel_reason reason)
{
	if (!sn->t_bfd_admin_holddown)
		return;

	event_cancel(&sn->t_bfd_admin_holddown);

	switch (reason) {
	case STATIC_BFD_HLDN_CANCEL_BFD_UP:
		DEBUGD(&static_dbg_bfd,
		       "%s: BFD up, cancelling admin-down hold-down timer",
		       __func__);
		break;
	case STATIC_BFD_HLDN_CANCEL_ADMIN_DOWN:
		DEBUGD(&static_dbg_bfd,
		       "%s: BFD admin-down, cancelling pending admin-down hold-down timer",
		       __func__);
		break;
	case STATIC_BFD_HLDN_CANCEL_REARM:
		/* Caller logs the replacement hold-down arm. */
		break;
	case STATIC_BFD_HLDN_CANCEL_MONITOR_OFF:
		DEBUGD(&static_dbg_bfd,
		       "%s: BFD monitor disabled, cancelling admin-down hold-down timer",
		       __func__);
		break;
	}

	frrtrace(2, frr_static, static_bfd_holddown_cancel, (uintptr_t)sn,
		 (uint8_t)reason);
}

/*
 * Hold-down time (in seconds) after an Admin Down -> Down transition.
 *
 * When BFD exits admin-down, the session briefly enters the Down state
 * before (potentially) reaching Up.  During this window we cannot tell
 * whether the peer is genuinely unreachable or just hasn't responded yet.
 *
 * If the session does not reach Up within this interval, we assume the
 * peer is unreachable and remove the route.
 */
#define BFD_ADMIN_HOLDDOWN_SEC 5

/*
 * Timer callback: the hold-down period after Admin Down -> Down has
 * expired and BFD never reached Up.  The peer is genuinely unreachable,
 * so remove the route now.
 */
static void static_bfd_admin_holddown_expire(struct event *event)
{
	struct static_nexthop *sn = EVENT_ARG(event);

	if (sn->bsp && bfd_sess_status(sn->bsp) == BSS_ADMIN_DOWN) {
		DEBUGD(&static_dbg_bfd,
		       "%s: admin-down hold-down expired while BFD is admin-down; "
		       "ignoring (route stays installed)",
		       __func__);
		frrtrace(2, frr_static, static_bfd_holddown_expire, (uintptr_t)sn,
			 (uint8_t)1);
		return;
	}

	DEBUGD(&static_dbg_bfd,
	       "%s: admin-down hold-down expired, peer unreachable, removing route",
	       __func__);

	frrtrace(2, frr_static, static_bfd_holddown_expire, (uintptr_t)sn,
		 (uint8_t)0);

	sn->path_down = true;
	static_zebra_route_add(sn->pn, true);
}

/*
 * Next hop BFD monitoring settings.
 */
static void static_next_hop_bfd_change(struct static_nexthop *sn,
				       const struct bfd_session_status *bss)
{
	DEBUGD(&static_dbg_bfd,
	       "%s: BFD session status changed, state: %d, previous_state: %d, path_down: %d",
	       __func__, bss->state, bss->previous_state, sn->path_down);
	frrtrace(4, frr_static, static_bfd_session_change, (uintptr_t)sn,
		 (uint32_t)bss->state, (uint32_t)bss->previous_state,
		 (uint8_t)(sn->path_down ? 1 : 0));
	switch (bss->state) {
	case BSS_UNKNOWN:
		/* FALLTHROUGH: no known state yet. */
	case BSS_ADMIN_DOWN:
		/*
		 * We or the remote end administratively shutdown.
		 * Drop any pending post-admin-down hold-down: the transient
		 * Down->Up window is no longer relevant once admin-down is
		 * reasserted.
		 */
		static_bfd_holddown_timer_cancel(sn,
						 STATIC_BFD_HLDN_CANCEL_ADMIN_DOWN);
		break;
	case BSS_DOWN:
		/*
		 * If transitioning from Admin Down to Down, the session is
		 * likely on its way to Up (transient state).  Start a
		 * hold-down timer instead of removing the route immediately.
		 * If BFD reaches Up before the timer fires, the timer is
		 * cancelled and no route churn occurs.  If the timer expires,
		 * the peer is genuinely unreachable and the route is removed.
		 */
		if (bss->previous_state == BSS_ADMIN_DOWN && !sn->path_down) {
			uint8_t rearm = sn->t_bfd_admin_holddown ? 1 : 0;

			static_bfd_holddown_timer_cancel(sn,
							 STATIC_BFD_HLDN_CANCEL_REARM);
			DEBUGD(&static_dbg_bfd,
			       "%s: BFD transitioning from Admin Down to Down, starting hold-down timer (%ds)%s",
			       __func__, BFD_ADMIN_HOLDDOWN_SEC,
			       rearm ? " (after replacing prior timer)" : "");
			frrtrace(3, frr_static, static_bfd_holddown_arm, (uintptr_t)sn,
				 (uint32_t)BFD_ADMIN_HOLDDOWN_SEC, rearm);
			event_add_timer(master,
					static_bfd_admin_holddown_expire, sn,
					BFD_ADMIN_HOLDDOWN_SEC,
					&sn->t_bfd_admin_holddown);
			break;
		}
		/* Peer went down, remove this next hop. */
		DEBUGD(&static_dbg_bfd,
		       "%s: next hop is down, remove it from RIB", __func__);
		frrtrace(1, frr_static, static_bfd_down_remove_rib, (uintptr_t)sn);
		sn->path_down = true;
		static_zebra_route_add(sn->pn, true);
		break;
	case BSS_UP:
		static_bfd_holddown_timer_cancel(sn, STATIC_BFD_HLDN_CANCEL_BFD_UP);
		/* If route is already installed, no action needed. */
		if (!sn->path_down) {
			DEBUGD(&static_dbg_bfd,
			       "%s: next hop is up, route already installed",
			       __func__);
			frrtrace(2, frr_static, static_bfd_up_rib, (uintptr_t)sn,
				 (uint8_t)0);
			break;
		}
		/* Peer is back up, add this next hop. */
		DEBUGD(&static_dbg_bfd, "%s: next hop is up, add it to RIB",
		       __func__);
		frrtrace(2, frr_static, static_bfd_up_rib, (uintptr_t)sn,
			 (uint8_t)1);
		sn->path_down = false;
		static_zebra_route_add(sn->pn, true);
		break;
	}
}

static void static_next_hop_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	static_next_hop_bfd_change(arg, bss);
}

static inline int
static_next_hop_type_to_family(const struct static_nexthop *sn)
{
	switch (sn->type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		if (sn->type == STATIC_IPV4_GATEWAY ||
		    sn->type == STATIC_IPV4_GATEWAY_IFNAME)
			return AF_INET;
		else
			return AF_INET6;
		break;
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	default:
		zlog_err("%s: invalid next hop type", __func__);
		break;
	}

	return AF_UNSPEC;
}

void static_next_hop_bfd_monitor_enable(struct static_nexthop *sn,
					const struct lyd_node *dnode)
{
	bool use_interface;
	bool use_profile;
	bool use_source;
	bool onlink;
	bool mhop;
	int family;
	struct ipaddr source;
	struct vrf *vrf = NULL;

	use_interface = false;
	use_source = yang_dnode_exists(dnode, "source");
	use_profile = yang_dnode_exists(dnode, "profile");
	onlink = yang_dnode_exists(dnode, "../onlink") &&
		 yang_dnode_get_bool(dnode, "../onlink");
	mhop = yang_dnode_get_bool(dnode, "multi-hop");
	vrf = vrf_lookup_by_name(yang_dnode_get_string(dnode, "../vrf"));

	family = static_next_hop_type_to_family(sn);
	if (family == AF_UNSPEC)
		return;

	if (sn->type == STATIC_IPV4_GATEWAY_IFNAME ||
	    sn->type == STATIC_IPV6_GATEWAY_IFNAME)
		use_interface = true;

	/* Reconfigure or allocate new memory. */
	if (sn->bsp == NULL)
		sn->bsp = bfd_sess_new(static_next_hop_bfd_updatecb, sn);

	/* Configure the session. */
	if (use_source)
		yang_dnode_get_ip(&source, dnode, "source");

	if (onlink || mhop == false)
		bfd_sess_set_auto_source(sn->bsp, false);
	else
		bfd_sess_set_auto_source(sn->bsp, !use_source);

	/* Configure the session.*/
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp,
					use_source ? &source.ip._v4_addr : NULL,
					&sn->addr.ipv4);
	else if (family == AF_INET6)
		bfd_sess_set_ipv6_addrs(sn->bsp,
					use_source ? &source.ip._v6_addr : NULL,
					&sn->addr.ipv6);

	bfd_sess_set_interface(sn->bsp, use_interface ? sn->ifname : NULL);

	bfd_sess_set_profile(sn->bsp, use_profile ? yang_dnode_get_string(
							    dnode, "./profile")
						  : NULL);
	if (vrf && vrf->vrf_id != VRF_UNKNOWN)
		bfd_sess_set_vrf(sn->bsp, vrf->vrf_id);

	bfd_sess_set_hop_count(sn->bsp, (onlink || mhop == false) ? 1 : 254);

	/* Install or update the session. */
	bfd_sess_install(sn->bsp);

	/* Update current path status. */
	sn->path_down = (bfd_sess_status(sn->bsp) != BSS_UP);
}

void static_next_hop_bfd_monitor_disable(struct static_nexthop *sn)
{
	static_bfd_holddown_timer_cancel(sn, STATIC_BFD_HLDN_CANCEL_MONITOR_OFF);
	bfd_sess_free(&sn->bsp);

	/* Reset path status. */
	sn->path_down = false;
}

void static_next_hop_bfd_source(struct static_nexthop *sn,
				const struct ipaddr *source)
{
	int family;

	if (sn->bsp == NULL)
		return;

	family = static_next_hop_type_to_family(sn);
	if (family == AF_UNSPEC)
		return;

	bfd_sess_set_auto_source(sn->bsp, false);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp, &source->ip._v4_addr,
					&sn->addr.ipv4);
	else if (family == AF_INET6)
		bfd_sess_set_ipv6_addrs(sn->bsp, &source->ip._v6_addr,
					&sn->addr.ipv6);

	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_auto_source(struct static_nexthop *sn)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_auto_source(sn->bsp, true);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_multi_hop(struct static_nexthop *sn, bool mhop)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_hop_count(sn->bsp, mhop ? 254 : 1);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_profile(struct static_nexthop *sn, const char *name)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_profile(sn->bsp, name);
	bfd_sess_install(sn->bsp);
}

void static_bfd_initialize(struct zclient *zc, struct event_loop *tm)
{
	/* Initialize BFD integration library. */
	bfd_protocol_integration_init(zc, tm);
}

/*
 * Display functions
 */
static void static_bfd_show_nexthop_json(struct vty *vty,
					 struct json_object *jo,
					 const struct static_nexthop *sn)
{
	const struct prefix *dst_p, *src_p;
	struct json_object *jo_nh;

	jo_nh = json_object_new_object();

	srcdest_rnode_prefixes(sn->rn, &dst_p, &src_p);
	if (src_p)
		json_object_string_addf(jo_nh, "from", "%pFX", src_p);

	json_object_string_addf(jo_nh, "prefix", "%pFX", dst_p);
	json_object_string_add(jo_nh, "vrf", sn->nh_vrfname);

	json_object_boolean_add(jo_nh, "installed", !sn->path_down);

	/* Add peer address based on nexthop type */
	if (sn->type == STATIC_IPV4_GATEWAY || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
		json_object_string_addf(jo_nh, "peer", "%pI4", &sn->addr.ipv4);
	else if (sn->type == STATIC_IPV6_GATEWAY || sn->type == STATIC_IPV6_GATEWAY_IFNAME)
		json_object_string_addf(jo_nh, "peer", "%pI6", &sn->addr.ipv6);

	json_object_array_add(jo, jo_nh);
}

static void static_bfd_show_path_json(struct vty *vty, struct json_object *jo,
				      struct route_table *rt)
{
	struct route_node *rn;

	for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
		struct static_route_info *si = static_route_info_from_rnode(rn);
		struct static_path *sp;

		if (si == NULL)
			continue;

		frr_each (static_path_list, &si->path_list, sp) {
			struct static_nexthop *sn;

			frr_each (static_nexthop_list, &sp->nexthop_list, sn) {
				/* Skip non configured BFD sessions. */
				if (sn->bsp == NULL)
					continue;

				static_bfd_show_nexthop_json(vty, jo, sn);
			}
		}
	}
}

static void static_bfd_show_json(struct vty *vty)
{
	struct json_object *jo, *jo_path, *jo_afi_safi;
	struct static_vrf *svrf;

	jo = json_object_new_object();
	jo_path = json_object_new_object();

	json_object_object_add(jo, "path-list", jo_path);
	RB_FOREACH (svrf, svrf_name_head, &svrfs) {
		struct route_table *rt;

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv4-unicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv4-multicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP][SAFI_MULTICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv6-unicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP6][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);
	}

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

static void static_bfd_show_nexthop(struct vty *vty,
				    const struct static_nexthop *sn)
{
	vty_out(vty, "        %pRN", sn->rn);

	if (sn->bsp == NULL) {
		vty_out(vty, "\n");
		return;
	}

	if (sn->type == STATIC_IPV4_GATEWAY ||
	    sn->type == STATIC_IPV4_GATEWAY_IFNAME)
		vty_out(vty, " peer %pI4", &sn->addr.ipv4);
	else if (sn->type == STATIC_IPV6_GATEWAY ||
		 sn->type == STATIC_IPV6_GATEWAY_IFNAME)
		vty_out(vty, " peer %pI6", &sn->addr.ipv6);
	else
		vty_out(vty, " peer unknown");

	vty_out(vty, " (status: %s)\n",
		sn->path_down ? "uninstalled" : "installed");
}

static void static_bfd_show_path(struct vty *vty, struct route_table *rt)
{
	struct route_node *rn;

	for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
		struct static_route_info *si = static_route_info_from_rnode(rn);
		struct static_path *sp;

		if (si == NULL)
			continue;

		frr_each (static_path_list, &si->path_list, sp) {
			struct static_nexthop *sn;

			frr_each (static_nexthop_list, &sp->nexthop_list, sn) {
				/* Skip non configured BFD sessions. */
				if (sn->bsp == NULL)
					continue;

				static_bfd_show_nexthop(vty, sn);
			}
		}
	}
}

void static_bfd_show(struct vty *vty, bool json)
{
	struct static_vrf *svrf;

	if (json) {
		static_bfd_show_json(vty);
		return;
	}

	vty_out(vty, "Showing BFD monitored static routes:\n");
	vty_out(vty, "\n  Next hops:\n");
	RB_FOREACH (svrf, svrf_name_head, &svrfs) {
		struct route_table *rt;

		vty_out(vty, "    VRF %s IPv4 Unicast:\n", svrf->name);
		rt = svrf->stable[AFI_IP][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path(vty, rt);

		vty_out(vty, "\n    VRF %s IPv4 Multicast:\n", svrf->name);
		rt = svrf->stable[AFI_IP][SAFI_MULTICAST];
		if (rt)
			static_bfd_show_path(vty, rt);

		vty_out(vty, "\n    VRF %s IPv6 Unicast:\n", svrf->name);
		rt = svrf->stable[AFI_IP6][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path(vty, rt);
	}

	vty_out(vty, "\n");
}
