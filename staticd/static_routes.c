// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - route code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include <lib/nexthop.h>
#include <lib/memory.h>
#include <lib/srcdest_table.h>
#include <lib/if.h>
#include <lib/vty.h>
#include <lib/vrf.h>
#include <lib/memory.h>

#include "printfrr.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_debug.h"

DEFINE_MGROUP(STATIC, "staticd");

DEFINE_MTYPE_STATIC(STATIC, STATIC_ROUTE,   "Static Route Info");
DEFINE_MTYPE_STATIC(STATIC, STATIC_PATH,    "Static Path");
DEFINE_MTYPE_STATIC(STATIC, STATIC_NEXTHOP, "Static Nexthop");

void zebra_stable_node_cleanup(struct route_table *table,
			       struct route_node *node)
{
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;
	struct route_table *src_table;
	struct route_node *src_node;
	struct static_path *src_pn;
	struct static_route_info *src_si;

	si = node->info;

	if (si) {
		frr_each_safe(static_path_list, &si->path_list, pn) {
			frr_each_safe(static_nexthop_list, &pn->nexthop_list,
				       nh) {
				static_nexthop_list_del(&pn->nexthop_list, nh);
				XFREE(MTYPE_STATIC_NEXTHOP, nh);
			}
			static_path_list_del(&si->path_list, pn);
			XFREE(MTYPE_STATIC_PATH, pn);
		}

		/* clean up for dst table */
		src_table = srcdest_srcnode_table(node);
		if (src_table) {
			/* This means the route_node is part of the top
			 * hierarchy and refers to a destination prefix.
			 */
			for (src_node = route_top(src_table); src_node;
			     src_node = route_next(src_node)) {
				src_si = src_node->info;

				frr_each_safe(static_path_list,
					      &src_si->path_list, src_pn) {
					frr_each_safe(static_nexthop_list,
						      &src_pn->nexthop_list,
						      nh) {
						static_nexthop_list_del(
							&src_pn->nexthop_list,
							nh);
						XFREE(MTYPE_STATIC_NEXTHOP, nh);
					}
					static_path_list_del(&src_si->path_list,
							     src_pn);
					XFREE(MTYPE_STATIC_PATH, src_pn);
				}

				XFREE(MTYPE_STATIC_ROUTE, src_node->info);
			}
		}

		XFREE(MTYPE_STATIC_ROUTE, node->info);
	}
}

/* Install static path into rib. */
void static_install_path(struct static_path *pn)
{
	struct static_nexthop *nh;

	frr_each(static_nexthop_list, &pn->nexthop_list, nh)
		static_zebra_nht_register(nh, true);

	if (static_nexthop_list_count(&pn->nexthop_list))
		static_zebra_route_add(pn, true);
}

/* Uninstall static path from RIB. */
static void static_uninstall_path(struct static_path *pn)
{
	if (static_nexthop_list_count(&pn->nexthop_list))
		static_zebra_route_add(pn, true);
	else
		static_zebra_route_add(pn, false);
}

struct route_node *static_add_route(afi_t afi, safi_t safi, struct prefix *p,
				    struct prefix_ipv6 *src_p,
				    struct static_vrf *svrf)
{
	struct route_node *rn;
	struct static_route_info *si;
	struct route_table *stable = svrf->stable[afi][safi];

	assert(stable);

	/* Lookup static route prefix. */
	rn = srcdest_rnode_get(stable, p, src_p);

	si = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(struct static_route_info));

	si->svrf = svrf;
	si->safi = safi;
	static_path_list_init(&(si->path_list));

	rn->info = si;

	return rn;
}

/* To delete the srcnodes */
static void static_del_src_route(struct route_node *rn)
{
	struct static_path *pn;
	struct static_route_info *si;

	si = rn->info;

	frr_each_safe(static_path_list, &si->path_list, pn) {
		static_del_path(pn);
	}

	XFREE(MTYPE_STATIC_ROUTE, rn->info);
	route_unlock_node(rn);
}

void static_del_route(struct route_node *rn)
{
	struct static_path *pn;
	struct static_route_info *si;
	struct route_table *src_table;
	struct route_node *src_node;

	si = rn->info;

	frr_each_safe(static_path_list, &si->path_list, pn) {
		static_del_path(pn);
	}

	/* clean up for dst table */
	src_table = srcdest_srcnode_table(rn);
	if (src_table) {
		/* This means the route_node is part of the top hierarchy
		 * and refers to a destination prefix.
		 */
		for (src_node = route_top(src_table); src_node;
		     src_node = route_next(src_node)) {
			static_del_src_route(src_node);
		}
	}
	XFREE(MTYPE_STATIC_ROUTE, rn->info);
	route_unlock_node(rn);
}

bool static_add_nexthop_validate(const char *nh_vrf_name,
				 enum static_nh_type type,
				 struct ipaddr *ipaddr)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_name(nh_vrf_name);
	if (!vrf)
		return true;

	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		if (if_address_is_local(&ipaddr->ipaddr_v4, AF_INET,
					vrf->vrf_id))
			return false;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		if (if_address_is_local(&ipaddr->ipaddr_v6, AF_INET6,
					vrf->vrf_id))
			return false;
		break;
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		break;
	}

	return true;
}

struct static_path *static_add_path(struct route_node *rn, uint32_t table_id,
				    uint8_t distance)
{
	struct static_path *pn;
	struct static_route_info *si;

	route_lock_node(rn);

	/* Make new static route structure. */
	pn = XCALLOC(MTYPE_STATIC_PATH, sizeof(struct static_path));

	pn->rn = rn;
	pn->distance = distance;
	pn->table_id = table_id;
	static_nexthop_list_init(&(pn->nexthop_list));

	si = rn->info;
	static_path_list_add_head(&(si->path_list), pn);

	return pn;
}

void static_del_path(struct static_path *pn)
{
	struct route_node *rn = pn->rn;
	struct static_route_info *si;
	struct static_nexthop *nh;

	si = rn->info;

	static_path_list_del(&si->path_list, pn);

	frr_each_safe(static_nexthop_list, &pn->nexthop_list, nh) {
		static_delete_nexthop(nh);
	}

	route_unlock_node(rn);

	XFREE(MTYPE_STATIC_PATH, pn);
}

struct static_nexthop *static_add_nexthop(struct static_path *pn,
					  enum static_nh_type type,
					  struct ipaddr *ipaddr,
					  const char *ifname,
					  const char *nh_vrf, uint32_t color)
{
	struct route_node *rn = pn->rn;
	struct static_nexthop *nh;
	struct static_vrf *nh_svrf;
	struct interface *ifp;
	struct static_nexthop *cp;

	route_lock_node(rn);

	nh_svrf = static_vrf_lookup_by_name(nh_vrf);

	/* Make new static route structure. */
	nh = XCALLOC(MTYPE_STATIC_NEXTHOP, sizeof(struct static_nexthop));

	/* Copy back pointers. */
	nh->rn = rn;
	nh->pn = pn;

	nh->type = type;
	nh->color = color;

	if (nh->type == STATIC_BLACKHOLE)
		nh->bh_type = STATIC_BLACKHOLE_NULL;

	nh->nh_vrf_id = nh_svrf ? nh_svrf->vrf->vrf_id : VRF_UNKNOWN;
	strlcpy(nh->nh_vrfname, nh_vrf, sizeof(nh->nh_vrfname));

	if (ifname)
		strlcpy(nh->ifname, ifname, sizeof(nh->ifname));
	nh->ifindex = IFINDEX_INTERNAL;

	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		nh->addr.ipv4 = ipaddr->ipaddr_v4;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		nh->addr.ipv6 = ipaddr->ipaddr_v6;
		break;
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		break;
	}
	/*
	 * Add new static route information to the tree with sort by
	 * gateway address.
	 */
	frr_each(static_nexthop_list, &pn->nexthop_list, cp) {
		if (nh->type == STATIC_IPV4_GATEWAY
		    && cp->type == STATIC_IPV4_GATEWAY) {
			if (ntohl(nh->addr.ipv4.s_addr)
			    < ntohl(cp->addr.ipv4.s_addr))
				break;
			if (ntohl(nh->addr.ipv4.s_addr)
			    > ntohl(cp->addr.ipv4.s_addr))
				continue;
		}
	}
	static_nexthop_list_add_after(&(pn->nexthop_list), cp, nh);

	if (nh->nh_vrf_id == VRF_UNKNOWN) {
		zlog_warn(
			"Static Route to %pFX not installed currently because dependent config not fully available",
			&rn->p);
		return nh;
	}

	/* check whether interface exists in system & install if it does */
	switch (nh->type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
	case STATIC_BLACKHOLE:
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IFNAME:
		ifp = if_lookup_by_name(ifname, nh->nh_vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL)
			nh->ifindex = ifp->ifindex;
		else
			zlog_warn(
				"Static Route using %s interface not installed because the interface does not exist in specified vrf",
				ifname);
		break;
	}

	return nh;
}

void static_install_nexthop(struct static_nexthop *nh)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	struct interface *ifp;

	if (nh->nh_vrf_id == VRF_UNKNOWN) {
		char nexthop_str[NEXTHOP_STR];

		static_get_nh_str(nh, nexthop_str, sizeof(nexthop_str));
		DEBUGD(&static_dbg_route,
		       "Static Route %pFX not installed for %s vrf %s is unknown",
		       &rn->p, nexthop_str, nh->nh_vrfname);
		return;
	}

	/* check whether interface exists in system & install if it does */
	switch (nh->type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		static_zebra_nht_register(nh, true);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		static_zebra_nht_register(nh, true);
		break;
	case STATIC_BLACKHOLE:
		static_install_path(pn);
		break;
	case STATIC_IFNAME:
		ifp = if_lookup_by_name(nh->ifname, nh->nh_vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL)
			static_install_path(pn);

		break;
	}
}

void static_delete_nexthop(struct static_nexthop *nh)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;

	static_nexthop_list_del(&(pn->nexthop_list), nh);
	/* Remove BFD session/configuration if any. */
	bfd_sess_free(&nh->bsp);

	if (nh->nh_vrf_id == VRF_UNKNOWN)
		goto EXIT;

	static_zebra_nht_register(nh, false);
	/*
	 * If we have other si nodes then route replace
	 * else delete the route
	 */
	static_uninstall_path(pn);

EXIT:
	route_unlock_node(rn);
	/* Free static route configuration. */
	XFREE(MTYPE_STATIC_NEXTHOP, nh);
}

static void static_ifindex_update_nh(struct interface *ifp, bool up,
				     struct route_node *rn,
				     struct static_path *pn,
				     struct static_nexthop *nh,
				     struct static_vrf *svrf, safi_t safi)
{
	if (!nh->ifname[0])
		return;
	if (up) {
		if (strcmp(nh->ifname, ifp->name))
			return;
		if (nh->nh_vrf_id != ifp->vrf->vrf_id)
			return;
		nh->ifindex = ifp->ifindex;
	} else {
		if (nh->ifindex != ifp->ifindex)
			return;
		if (nh->nh_vrf_id != ifp->vrf->vrf_id)
			return;
		nh->ifindex = IFINDEX_INTERNAL;
	}

	/* Remove previously configured route if any. */
	static_uninstall_path(pn);
	static_install_path(pn);
}

static void static_ifindex_update_af(struct interface *ifp, bool up, afi_t afi,
				     safi_t safi)
{
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct vrf *vrf;
	struct static_route_info *si;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;

		stable = static_vrf_static_table(afi, safi, svrf);
		if (!stable)
			continue;
		for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
			si = static_route_info_from_rnode(rn);
			if (!si)
				continue;
			frr_each(static_path_list, &si->path_list, pn) {
				frr_each(static_nexthop_list,
					  &pn->nexthop_list, nh) {
					static_ifindex_update_nh(ifp, up, rn,
								 pn, nh, svrf,
								 safi);
				}
			}
		}
	}
}

/*
 * This function looks at a svrf's stable and notices if any of the
 * nexthops we are using are part of the vrf coming up.
 * If we are using them then cleanup the nexthop vrf id
 * to be the new value and then re-installs them
 *
 *
 * stable -> The table we are looking at.
 * svrf -> The newly changed vrf.
 * afi -> The afi to look at
 * safi -> the safi to look at
 */
static void static_fixup_vrf(struct static_vrf *svrf,
			     struct route_table *stable, afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct interface *ifp;
	struct static_path *pn;
	struct static_route_info *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (strcmp(svrf->vrf->name, nh->nh_vrfname)
				    != 0)
					continue;

				nh->nh_vrf_id = svrf->vrf->vrf_id;
				nh->nh_registered = false;
				if (nh->ifindex) {
					ifp = if_lookup_by_name(nh->ifname,
								nh->nh_vrf_id);
					if (ifp)
						nh->ifindex = ifp->ifindex;
					else
						continue;
				}

				static_install_path(pn);
			}
		}
	}
}

/*
 * This function enables static routes in a svrf as it
 * is coming up.  It sets the new vrf_id as appropriate.
 *
 * svrf -> The svrf that is being brought up and enabled by the kernel
 * stable -> The stable we are looking at.
 * afi -> the afi in question
 * safi -> the safi in question
 */
static void static_enable_vrf(struct static_vrf *svrf,
			      struct route_table *stable, afi_t afi,
			      safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct interface *ifp;
	struct static_path *pn;
	struct static_route_info *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (nh->ifindex) {
					ifp = if_lookup_by_name(nh->ifname,
								nh->nh_vrf_id);
					if (ifp)
						nh->ifindex = ifp->ifindex;
					else
						continue;
				}
				if (nh->nh_vrf_id == VRF_UNKNOWN)
					continue;
				static_install_path(pn);
			}
		}
	}
}

/*
 * When a vrf is being enabled by the kernel, go through all the
 * static routes in the system that use this vrf (both nexthops vrfs
 * and the routes vrf )
 *
 * enable_svrf -> the vrf being enabled
 */
void static_fixup_vrf_ids(struct static_vrf *enable_svrf)
{
	struct route_table *stable;
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;
		/* Install any static routes configured for this VRF. */
		FOREACH_AFI_SAFI (afi, safi) {
			stable = svrf->stable[afi][safi];
			if (!stable)
				continue;

			static_fixup_vrf(enable_svrf, stable, afi, safi);

			if (enable_svrf == svrf)
				static_enable_vrf(svrf, stable, afi, safi);
		}
	}
}

/*
 * Look at the specified stable and if any of the routes in
 * this table are using the svrf as the nexthop, uninstall
 * those routes.
 *
 * svrf -> the vrf being disabled
 * stable -> the table we need to look at.
 * afi -> the afi in question
 * safi -> the safi in question
 */
static void static_cleanup_vrf(struct static_vrf *svrf,
			       struct route_table *stable,
			       afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (strcmp(svrf->vrf->name, nh->nh_vrfname)
				    != 0)
					continue;

				static_uninstall_path(pn);
			}
		}
	}
}

/*
 * Look at all static routes in this table and uninstall
 * them.
 *
 * stable -> The table to uninstall from
 * afi -> The afi in question
 * safi -> the safi in question
 */
static void static_disable_vrf(struct route_table *stable,
			       afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				static_uninstall_path(pn);
			}
		}
	}
}

/*
 * When the disable_svrf is shutdown by the kernel, we call
 * this function and it cleans up all static routes using
 * this vrf as a nexthop as well as all static routes
 * in it's stables.
 *
 * disable_svrf - The vrf being disabled
 */
void static_cleanup_vrf_ids(struct static_vrf *disable_svrf)
{
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;

		/* Uninstall any static routes configured for this VRF. */
		FOREACH_AFI_SAFI (afi, safi) {
			struct route_table *stable;

			stable = svrf->stable[afi][safi];
			if (!stable)
				continue;

			static_cleanup_vrf(disable_svrf, stable, afi, safi);

			if (disable_svrf == svrf)
				static_disable_vrf(stable, afi, safi);
		}
	}
}

/*
 * This function enables static routes when an interface it relies
 * on in a different vrf is coming up.
 *
 * stable -> The stable we are looking at.
 * ifp -> interface coming up
 * afi -> the afi in question
 * safi -> the safi in question
 */
static void static_fixup_intf_nh(struct route_table *stable,
				 struct interface *ifp,
				 afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (nh->nh_vrf_id != ifp->vrf->vrf_id)
					continue;

				if (nh->ifindex != ifp->ifindex)
					continue;

				static_install_path(pn);
			}
		}
	}
}

/*
 * This function enables static routes that rely on an interface in
 * a different vrf when that interface comes up.
 */
void static_install_intf_nh(struct interface *ifp)
{
	struct route_table *stable;
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf = vrf->info;

		/* Not needed if same vrf since happens naturally */
		if (vrf->vrf_id == ifp->vrf->vrf_id)
			continue;

		/* Install any static routes configured for this interface. */
		FOREACH_AFI_SAFI (afi, safi) {
			stable = svrf->stable[afi][safi];
			if (!stable)
				continue;

			static_fixup_intf_nh(stable, ifp, afi, safi);
		}
	}
}

/* called from if_{add,delete}_update, i.e. when ifindex becomes [in]valid */
void static_ifindex_update(struct interface *ifp, bool up)
{
	static_ifindex_update_af(ifp, up, AFI_IP, SAFI_UNICAST);
	static_ifindex_update_af(ifp, up, AFI_IP, SAFI_MULTICAST);
	static_ifindex_update_af(ifp, up, AFI_IP6, SAFI_UNICAST);
	static_ifindex_update_af(ifp, up, AFI_IP6, SAFI_MULTICAST);
}

struct stable_info *static_get_stable_info(struct route_node *rn)
{
	struct route_table *table;

	table = srcdest_rnode_table(rn);
	return table->info;
}

void static_get_nh_str(struct static_nexthop *nh, char *nexthop, size_t size)
{
	switch (nh->type) {
	case STATIC_IFNAME:
		snprintfrr(nexthop, size, "ifindex : %s", nh->ifname);
		break;
	case STATIC_IPV4_GATEWAY:
		snprintfrr(nexthop, size, "ip4 : %pI4", &nh->addr.ipv4);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
		snprintfrr(nexthop, size, "ip4-ifindex : %pI4 : %s",
			   &nh->addr.ipv4, nh->ifname);
		break;
	case STATIC_BLACKHOLE:
		snprintfrr(nexthop, size, "blackhole : %d", nh->bh_type);
		break;
	case STATIC_IPV6_GATEWAY:
		snprintfrr(nexthop, size, "ip6 : %pI6", &nh->addr.ipv6);
		break;
	case STATIC_IPV6_GATEWAY_IFNAME:
		snprintfrr(nexthop, size, "ip6-ifindex : %pI6 : %s",
			   &nh->addr.ipv6, nh->ifname);
		break;
	};
}
