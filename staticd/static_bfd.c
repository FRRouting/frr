// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static daemon BFD integration.
 *
 * Copyright (C) 2020-2022 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include <zebra.h>

#include "lib/bfd.h"
#include "lib/printfrr.h"
#include "lib/srcdest_table.h"

#include "staticd/static_routes.h"
#include "staticd/static_zebra.h"
#include "staticd/static_debug.h"

#include "lib/openbsd-queue.h"

/*
 * Next hop BFD monitoring settings.
 */
static void static_next_hop_bfd_change(struct static_nexthop *sn,
				       const struct bfd_session_status *bss)
{
	switch (bss->state) {
	case BSS_UNKNOWN:
		/* FALLTHROUGH: no known state yet. */
	case BSS_ADMIN_DOWN:
		/* NOTHING: we or the remote end administratively shutdown. */
		break;
	case BSS_DOWN:
		/* Peer went down, remove this next hop. */
		DEBUGD(&static_dbg_bfd,
		       "%s: next hop is down, remove it from RIB", __func__);
		sn->path_down = true;
		static_zebra_route_add(sn->pn, true);
		break;
	case BSS_UP:
		/* Peer is back up, add this next hop. */
		DEBUGD(&static_dbg_bfd, "%s: next hop is up, add it to RIB",
		       __func__);
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

static int static_bfd_choose_src_ip(struct interface *ifp, int family,
				    struct in6_addr *src_ip)
{
	struct connected *ifc;
	struct in_addr *src_v4 = (struct in_addr *)src_ip;

	frr_each (if_connected, ifp->connected, ifc) {
		if (!ifc->address)
			continue;
		if (family != ifc->address->family)
			continue;
		if (family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6))
			continue;
		if (family == AF_INET)
			*src_v4 = ifc->address->u.prefix4;
		else
			memcpy(src_ip, &ifc->address->u.prefix6,
			       sizeof(struct in6_addr));
		return 0;
	}

	return -1;
}

static int static_bfd_family_from_sn(struct static_nexthop *sn)
{
        if (sn->type == STATIC_IPV4_GATEWAY
            || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
                return AF_INET;
        if (sn->type == STATIC_IPV6_GATEWAY
            || sn->type == STATIC_IPV6_GATEWAY_IFNAME)
                return AF_INET6;
        return AF_UNSPEC;
}

static int static_bfd_build_prefix_from_sn(struct static_nexthop *sn, struct prefix *p)
{
	p->family = static_bfd_family_from_sn(sn);
	if (p->family == AF_INET) {
		p->prefixlen = IPV4_MAX_BITLEN;
		p->u.prefix4 = (struct in_addr)sn->addr.ipv4;
	} else if (p->family == AF_INET6){
		p->prefixlen = IPV6_MAX_BITLEN;
		memcpy(&p->u.prefix6, &sn->addr.ipv6, sizeof(struct in6_addr));
	} else
		return -1;

	return 0;
}

void static_next_hop_bfd_monitor_enable(struct static_nexthop *sn,
					const struct lyd_node *dnode)
{
	struct prefix src_p = {};
	bool use_interface;
	bool use_profile;
	bool use_source;
	bool onlink;
	bool mhop;
	bool connected;
	bool autohop;
	int family;
	struct ipaddr source;
	struct vrf *vrf = NULL;

	use_interface = false;
	use_source = yang_dnode_exists(dnode, "source");
	use_profile = yang_dnode_exists(dnode, "profile");
	onlink = yang_dnode_exists(dnode, "../onlink") &&
		 yang_dnode_get_bool(dnode, "../onlink");
	mhop = yang_dnode_exists(dnode, "multi-hop") &&
	       yang_dnode_get_bool(dnode, "multi-hop");
	vrf = vrf_lookup_by_name(yang_dnode_get_string(dnode, "../vrf"));
	autohop = yang_dnode_exists(dnode, "auto-hop") &&
		  yang_dnode_get_bool(dnode, "auto-hop");

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

	bfd_sess_set_bfd_autohop(sn->bsp, autohop);

	if (autohop) {
		if (static_bfd_build_prefix_from_sn(sn, &src_p) < 0)
			return;
		connected = static_zebra_prefix_is_connected((const struct prefix *)&src_p,
							     sn->nh_vrf_id);
		bfd_sess_set_hop_count(sn->bsp,
				       connected ? 1 : 254);

	} else
		bfd_sess_set_hop_count(sn->bsp, (onlink || mhop == false) ? 1 : 254);

	if (onlink || (autohop && connected) || (mhop == false && !autohop))
		bfd_sess_set_auto_source(sn->bsp, false);
	else
		bfd_sess_set_auto_source(sn->bsp, !use_source);

	/* Install or update the session. */
	bfd_sess_install(sn->bsp);

	/* Update current path status. */
	sn->path_down = (bfd_sess_status(sn->bsp) != BSS_UP);
}

void static_next_hop_bfd_monitor_disable(struct static_nexthop *sn)
{
	bfd_sess_free(&sn->bsp);

	/* Reset path status. */
	sn->path_down = false;
}

void static_next_hop_bfd_source(struct static_nexthop *sn,
				const struct ipaddr *source)
{
	int family;
	uint8_t ttl;
	struct prefix p_dst = {};
	struct interface *ifp;
	struct in6_addr ia_srcp = {};

	if (sn->bsp == NULL)
		return;

	family = static_next_hop_type_to_family(sn);
	if (family == AF_UNSPEC)
		return;

	bfd_sess_set_auto_source(sn->bsp, false);
	ttl = bfd_sess_hop_count(sn->bsp);
	if (!source && ttl > 1) {
		if (static_bfd_build_prefix_from_sn(sn, &p_dst) < 0)
			return;
		/* XXX vrf route leak case */
		ifp = static_zebra_get_interface(&p_dst, sn->nh_vrf_id);
		if (!ifp)
			return;

		if (static_bfd_choose_src_ip(ifp, family, &ia_srcp) < 0)
			return;
	} else if (source) {
		memcpy(&ia_srcp, &(source->ip), sizeof(struct in6_addr));
	}

	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp,
				source ? (struct in_addr *)&ia_srcp : NULL, &sn->addr.ipv4);
	else if (family == AF_INET6)
		bfd_sess_set_ipv6_addrs(sn->bsp,
				source ? &ia_srcp : NULL, &sn->addr.ipv6);
	else
		return;

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

void static_next_hop_bfd_auto_hop(struct static_nexthop *sn, bool autohop,
				  bool onlink, bool mhop)
{
	struct prefix src_p = {};
	bool connected;

	if (sn->bsp == NULL)
		return;

	bfd_sess_set_bfd_autohop(sn->bsp, autohop);

	if (autohop) {
		if (static_bfd_build_prefix_from_sn(sn, &src_p) < 0)
			return;
		connected = static_zebra_prefix_is_connected((const struct prefix *)&src_p,
							     sn->nh_vrf_id);
		bfd_sess_set_hop_count(sn->bsp, connected ? 1 : 254);

	} else
		bfd_sess_set_hop_count(sn->bsp, (!onlink && mhop) ? 254 : 1);

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
static void static_bfd_source_update_from_ifindex(struct static_nexthop *nh,
						  int family, ifindex_t oif_idx,
						  vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct in6_addr src_ip = {};

	/* update addresses */
	ifp = if_lookup_by_index(oif_idx, vrf_id);
	if (!ifp)
		return;
	static_bfd_choose_src_ip(ifp, family, &src_ip);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(nh->bsp, (struct in_addr *)&src_ip,
					&nh->addr.ipv4);
	else
		bfd_sess_set_ipv6_addrs(nh->bsp, &src_ip, &nh->addr.ipv6);
	bfd_sess_install(nh->bsp);
}

void static_bfd_source_update(ifindex_t oif_idx, struct prefix *dp,
			      vrf_id_t vrf_id, bool connected)
{
	struct route_table *stable;
	struct static_route_info *si;
	struct vrf *vrf;
	struct static_vrf *svrf;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	char buf[PREFIX2STR_BUFFER];
	afi_t afi;

	/* get vrf where prefix is */
	prefix2str(dp, buf, sizeof(buf));

	/* XXX vrf route leaks are not looked up */
	vrf = vrf_lookup_by_id(vrf_id);
	assert(vrf);
	svrf = vrf->info;

	if (dp->family == AF_INET)
		afi = AFI_IP;
	else if (dp->family == AF_INET6)
		afi = AFI_IP6;
	else
		assert(0);

	/* walk nexthops and parse BFD configured sessions to update source interface index */
	stable = static_vrf_static_table(afi, SAFI_UNICAST, svrf);
	if (!stable)
		return;
	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = rn->info;
		if (!si)
			continue;
		frr_each (static_path_list, &si->path_list, pn) {
			frr_each (static_nexthop_list, &pn->nexthop_list, nh) {
				if (!nh->bsp)
					continue;

				if (!bfd_sess_bfd_autohop(nh->bsp))
					continue;

				if (nh->nh_vrf_id != vrf_id)
					continue;

				if (nh->type != STATIC_IPV4_GATEWAY &&
				    nh->type != STATIC_IPV4_GATEWAY_IFNAME &&
				    nh->type != STATIC_IPV6_GATEWAY &&
				    nh->type != STATIC_IPV6_GATEWAY_IFNAME)
					continue;

				if (dp->family == AF_INET &&
				    (nh->type == STATIC_IPV6_GATEWAY ||
				     nh->type == STATIC_IPV6_GATEWAY_IFNAME))
					continue;

				if (dp->family == AF_INET6 &&
				    (nh->type == STATIC_IPV4_GATEWAY ||
				     nh->type == STATIC_IPV4_GATEWAY_IFNAME))
					continue;

				if (dp->family == AF_INET &&
				    !IPV4_ADDR_SAME(&dp->u.prefix4,
						    &nh->addr.ipv4))
					continue;

				if (dp->family == AF_INET6 &&
				    !IPV6_ADDR_SAME(&dp->u.prefix6,
						    &nh->addr.ipv6))
					continue;

				if (oif_idx == IFINDEX_INTERNAL)
					continue;

				bfd_sess_set_hop_count(nh->bsp,
						       connected ? 1 : 254);
				static_bfd_source_update_from_ifindex(nh,
								      dp->family,
								      oif_idx,
								      vrf_id);
			}
		}
	}
}
