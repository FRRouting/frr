/*
 * STATICd - route code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <lib/nexthop.h>
#include <lib/memory.h>
#include <lib/srcdest_table.h>
#include <lib/if.h>
#include <lib/vty.h>
#include <lib/vrf.h>
#include <lib/memory.h>

#include "static_vrf.h"
#include "static_routes.h"
#include "static_memory.h"
#include "static_zebra.h"

/* Install static route into rib. */
void static_install_route(struct route_node *rn, struct static_route_info *ri,
			  safi_t safi, struct static_vrf *svrf)
{
	struct static_nexthop *si;

	for (si = ri->nh; si; si = si->next)
		static_zebra_nht_register(rn, si, true);

	if (ri->nh && svrf && svrf->vrf)
		static_zebra_route_add(rn, ri, svrf->vrf->vrf_id, safi, true);
}

/* Uninstall static route from RIB. */
static void static_uninstall_route(struct route_node *rn,
				   struct static_route_info *ri, safi_t safi,
				   struct static_vrf *svrf)
{
	struct static_nexthop *si;

	si = ri->nh;

	if (si)
		static_zebra_route_add(rn, ri, svrf->vrf->vrf_id, safi, true);
	else
		static_zebra_route_add(rn, ri, svrf->vrf->vrf_id, safi, false);
}

struct route_node *static_add_route(afi_t afi, safi_t safi, struct prefix *p,
				    struct prefix_ipv6 *src_p,
				    struct static_vrf *svrf)
{
	struct route_node *rn;
	struct route_table *stable = svrf->stable[afi][safi];
	int ret;
	bool negate = false;

	if (!stable)
		return NULL;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_get(stable, p, src_p);

	/* Mark as having FRR configuration */
	vrf_set_user_cfged(svrf->vrf);

	if (svrf->vrf->vrf_id == VRF_UNKNOWN) {
		ret = zebra_static_route_holdem(rn, NULL, NULL, safi, svrf,
						negate);
		if (!ret) {
			zlog_warn("rn creation failed");
			return NULL;
		}
	}

	return rn;
}

void static_del_route(struct route_node *rn, safi_t safi,
		      struct static_vrf *svrf)
{
	struct static_route_info *ri;
	struct static_route_info *ri_next;
	bool negate = true;
	int ret;

	if (svrf->vrf->vrf_id == VRF_UNKNOWN) {
		ret = zebra_static_route_holdem(rn, NULL, NULL, safi, svrf,
						negate);
		if (!ret)
			zlog_warn("rn deletion failed");
	}

	RNODE_FOREACH_PATH(rn, ri, ri_next)
	{
		static_del_route_info(rn, ri, safi, svrf);
	}

	XFREE(MTYPE_STATIC_ROUTE_INFO, rn->info);
	route_unlock_node(rn);
	/* If no other FRR config for this VRF, mark accordingly. */
	if (!static_vrf_has_config(svrf))
		vrf_reset_user_cfged(svrf->vrf);
}

bool static_add_nexthop_validate(struct static_vrf *svrf, static_types type,
				 struct ipaddr *ipaddr)
{
	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		if (if_lookup_exact_address(&ipaddr->ipaddr_v4, AF_INET,
					    svrf->vrf->vrf_id))
			return false;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		if (if_lookup_exact_address(&ipaddr->ipaddr_v6, AF_INET6,
					    svrf->vrf->vrf_id))
			return false;
		break;
	default:
		break;
	}

	return true;
}

struct static_route_info *static_add_route_info(struct route_node *rn,
						uint8_t distance,
						route_tag_t tag,
						uint32_t table_id)
{
	struct static_route_info *ri;
	struct static_route_info *head;

	route_lock_node(rn);

	/* Make new static route structure. */
	ri = XCALLOC(MTYPE_STATIC_ROUTE_INFO, sizeof(struct static_route_info));

	ri->distance = distance;
	ri->tag = tag;
	ri->table_id = table_id;

	head = rn->info;

	ri->next = head;
	ri->prev = NULL;

	if (head != NULL)
		head->prev = ri;

	rn->info = ri;

	return ri;
}

bool static_del_route_info(struct route_node *rn, struct static_route_info *ri,
			   safi_t safi, struct static_vrf *svrf)
{
	struct static_route_info *head;
	struct static_nexthop *nh;
	struct static_nexthop *nh_next;

	head = rn->info;

	if (head == ri)
		rn->info = ri->next;

	if (ri->next != NULL)
		ri->next->prev = ri->prev;

	if (ri->prev != NULL)
		ri->prev->next = ri->next;

	RNODE_FOREACH_PATH_NH(ri, nh, nh_next)
	{
		static_delete_nexthop(rn, ri, safi, svrf, nh);
	}

	route_unlock_node(rn);

	free(ri);

	return true;
}

struct static_nexthop *
static_add_nexthop(struct route_node *rn, struct static_route_info *ri,
		   safi_t safi, struct static_vrf *svrf, static_types type,
		   struct ipaddr *ipaddr, const char *ifname,
		   const char *nh_vrf)
{
	struct static_nexthop *si;
	struct static_nexthop *pp;
	struct static_nexthop *cp;
	struct static_vrf *nh_svrf;
	struct interface *ifp;
	int ret;
	bool negate = false;

	route_lock_node(rn);

	nh_svrf = static_vty_get_unknown_vrf(nh_vrf);

	if (!nh_svrf)
		return NULL;

	/* Make new static route structure. */
	si = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(struct static_nexthop));

	si->type = type;

	si->nh_vrf_id = nh_svrf->vrf->vrf_id;
	strlcpy(si->nh_vrfname, nh_svrf->vrf->name, sizeof(si->nh_vrfname));

	if (ifname)
		strlcpy(si->ifname, ifname, sizeof(si->ifname));
	si->ifindex = IFINDEX_INTERNAL;

	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		si->addr.ipv4 = ipaddr->ipaddr_v4;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		si->addr.ipv6 = ipaddr->ipaddr_v6;
		break;
	default:
		break;
	}

	/*
	 * Add new static route information to the tree with sort by
	 * gateway address.
	 */
	for (pp = NULL, cp = ri->nh; cp; pp = cp, cp = cp->next) {
		if (si->type == STATIC_IPV4_GATEWAY
		    && cp->type == STATIC_IPV4_GATEWAY) {
			if (ntohl(si->addr.ipv4.s_addr)
			    < ntohl(cp->addr.ipv4.s_addr))
				break;
			if (ntohl(si->addr.ipv4.s_addr)
			    > ntohl(cp->addr.ipv4.s_addr))
				continue;
		}
	}

	/* Make linked list. */
	if (pp)
		pp->next = si;
	else
		ri->nh = si;
	if (cp)
		cp->prev = si;
	si->prev = pp;
	si->next = cp;

	if (nh_svrf->vrf->vrf_id == VRF_UNKNOWN) {
		ret = zebra_static_route_holdem(rn, ri, si, safi, svrf, negate);
		if (!ret)
			zlog_warn("nh creation failed");
		return si;
	}

	/* check whether interface exists in system & install if it does */
	switch (si->type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		static_zebra_nht_register(rn, si, true);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		ifp = if_lookup_by_name(ifname, nh_svrf->vrf->vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL)
			si->ifindex = ifp->ifindex;
		else
			zlog_warn(
				"Static Route using %s interface not installed because the interface does not exist in specified vrf",
				ifname);

		static_zebra_nht_register(rn, si, true);
		break;
	case STATIC_BLACKHOLE:
		static_install_route(rn, ri, safi, svrf);
		break;
	case STATIC_IFNAME:
		ifp = if_lookup_by_name(ifname, nh_svrf->vrf->vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL) {
			si->ifindex = ifp->ifindex;
			static_install_route(rn, ri, safi, svrf);
		} else
			zlog_warn(
				"Static Route using %s interface not installed because the interface does not exist in specified vrf",
				ifname);

		break;
	}

	return si;
}

int static_delete_nexthop(struct route_node *rn, struct static_route_info *ri,
			  safi_t safi, struct static_vrf *svrf,
			  struct static_nexthop *si)
{
	struct static_vrf *nh_svrf;
	int ret;
	bool negate = true;

	nh_svrf = static_vrf_lookup_by_name(si->nh_vrfname);

	/* Unlink static route from linked list. */
	if (si->prev)
		si->prev->next = si->next;
	else
		ri->nh = si->next;
	if (si->next)
		si->next->prev = si->prev;

	if (nh_svrf->vrf->vrf_id == VRF_UNKNOWN) {
		ret = zebra_static_route_holdem(rn, ri, si, safi, svrf, negate);
		if (!ret)
			zlog_warn("nh deletion failed");
		goto EXIT;
	}

	static_zebra_nht_register(rn, si, false);
	/*
	 * If we have other si nodes then route replace
	 * else delete the route
	 */
	static_uninstall_route(rn, ri, safi, svrf);

	route_unlock_node(rn);

EXIT:
	/* Free static route configuration. */
	XFREE(MTYPE_STATIC_ROUTE, si);

	return 1;
}

static void static_ifindex_update_af(struct interface *ifp, bool up, afi_t afi,
				     safi_t safi)
{
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_route_info *ri;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;

		stable = static_vrf_static_table(afi, safi, svrf);
		if (!stable)
			continue;

		for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
			RNODE_FOREACH_PATH_RO(rn, ri)
			{
				RNODE_FOREACH_PATH_NH_RO(ri, nh)
				{
					if (!nh->ifname[0])
						continue;
					if (up) {
						if (strcmp(nh->ifname,
							ifp->name))
							continue;
						if (nh->nh_vrf_id
							!= ifp->vrf_id)
							continue;
						nh->ifindex = ifp->ifindex;
					} else {
						if (nh->ifindex != ifp->ifindex)
							continue;
						if (nh->nh_vrf_id
							!= ifp->vrf_id)
							continue;
						nh->ifindex = IFINDEX_INTERNAL;
					}

					static_install_route(rn, ri, safi,
							     svrf);
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
	struct static_route_info *ri;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
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

				static_install_route(rn, ri, safi, svrf);
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
	struct static_route_info *ri;
	struct vrf *vrf = svrf->vrf;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
				nh->vrf_id = vrf->vrf_id;
				if (nh->ifindex) {
					ifp = if_lookup_by_name(nh->ifname,
								nh->nh_vrf_id);
					if (ifp)
						nh->ifindex = ifp->ifindex;
					else
						continue;
				}
				static_install_route(rn, ri, safi, svrf);
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
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
				stable = svrf->stable[afi][safi];
				if (!stable)
					continue;

				static_fixup_vrf(enable_svrf, stable,
						 afi, safi);

				if (enable_svrf == svrf)
					static_enable_vrf(svrf, stable,
							  afi, safi);
			}
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
			       struct route_table *stable, afi_t afi,
			       safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_route_info *ri;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
				if (strcmp(svrf->vrf->name, nh->nh_vrfname)
				    != 0)
					continue;

				static_uninstall_route(rn, ri, safi, svrf);
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
static void static_disable_vrf(struct route_table *stable, afi_t afi,
			       safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_route_info *ri;
	struct stable_info *info;

	info = route_table_get_info(stable);

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
				static_uninstall_route(rn, ri, safi,
						       info->svrf);
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
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
				struct route_table *stable;

				stable = svrf->stable[afi][safi];
				if (!stable)
					continue;

				static_cleanup_vrf(disable_svrf, stable,
						   afi, safi);

				if (disable_svrf == svrf)
					static_disable_vrf(stable, afi, safi);
			}
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
				 struct interface *ifp, afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct stable_info *info;
	struct static_nexthop *nh;
	struct static_route_info *ri;

	info = route_table_get_info(stable);

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
				if (nh->nh_vrf_id != ifp->vrf_id)
					continue;

				if (nh->ifindex != ifp->ifindex)
					continue;

				static_install_route(rn, ri, safi, info->svrf);
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
		if (vrf->vrf_id == ifp->vrf_id)
			continue;

		/* Install any static routes configured for this interface. */
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
				stable = svrf->stable[afi][safi];
				if (!stable)
					continue;

				static_fixup_intf_nh(stable, ifp, afi, safi);
			}
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

void static_get_nh_type(static_types stype, char *type, size_t size)
{
	switch (stype) {
	case STATIC_IFNAME:
		strlcpy(type, "ifindex", size);
		break;
	case STATIC_IPV4_GATEWAY:
		strlcpy(type, "ip4", size);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
		strlcpy(type, "ip4-ifindex", size);
		break;
	case STATIC_BLACKHOLE:
		strlcpy(type, "blackhole", size);
		break;
	case STATIC_IPV6_GATEWAY:
		strlcpy(type, "ip6", size);
		break;
	case STATIC_IPV6_GATEWAY_IFNAME:
		strlcpy(type, "ip6-ifindex", size);
		break;
	};
}

/* This API is necessary as libyang does not support the auto deletion
 * of node; if it's all child nodes gets deleted. like prefix is not
 * deleted automatically if all it's nexthops gets deleted.
 */
bool static_get_route_delete(afi_t afi, safi_t safi, uint8_t type,
			     struct prefix *p, struct prefix_ipv6 *src_p,
			     const char *vrf)
{
	struct route_node *rn;
	struct route_table *stable;
	struct static_vrf *svrf;
	unsigned int src_count;
	bool ret = false;

	svrf = static_vrf_lookup_by_name(vrf);

	/* Lookup table.  */
	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return ret;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_lookup(stable, p, src_p);
	if (!rn)
		return ret;
	src_count = (rn->lock) - 1;
	if (src_count == 3)
		ret = true;

	route_unlock_node(rn);
	return ret;
}

bool static_get_src_route_delete(afi_t afi, safi_t safi, uint8_t type,
				 struct prefix *p, const char *vrf)
{
	struct route_node *rn;
	struct route_table *stable;
	struct static_vrf *svrf;
	unsigned int src_count;
	bool ret = false;

	svrf = static_vrf_lookup_by_name(vrf);

	/* Lookup table.  */
	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return ret;

	/* Lookup static route prefix. */
	rn = route_node_lookup_maynull(stable, p);
	if (!rn)
		return ret;
	src_count = (rn->lock) - 1;
	if (src_count == 2)
		ret = true;

	route_unlock_node(rn);
	return ret;
}

bool static_get_path_delete(afi_t afi, safi_t safi, uint8_t type,
			    struct prefix *p, struct prefix_ipv6 *src_p,
			    const char *vrf, uint8_t distance, route_tag_t tag,
			    uint32_t table_id)
{
	struct route_node *rn;
	struct route_table *stable;
	struct static_route_info *ri;
	struct static_vrf *svrf;
	bool ret = false;

	svrf = static_vrf_lookup_by_name(vrf);

	/* Lookup table.  */
	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return -1;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_lookup(stable, p, src_p);
	if (!rn)
		return 0;

	RNODE_FOREACH_PATH_RO(rn, ri)
	{
		if (ri->distance == distance && ri->tag == tag
		    && ri->table_id == table_id)
			break;
	}

	if (ri && ri->nh && ri->nh->next == NULL)
		ret = true;

	route_unlock_node(rn);
	return ret;
}

struct static_hold_route {
	struct static_vrf *svrf;
	struct route_node *rn;
	struct static_route_info *ri;
	struct static_nexthop *nh;
	safi_t safi;
};

static struct list *static_list;

static void static_list_delete(struct static_hold_route *shr)
{
	XFREE(MTYPE_STATIC_ROUTE, shr);
}

static int static_list_compare(void *arg1, void *arg2)
{
	struct static_hold_route *shr1 = arg1;
	struct static_hold_route *shr2 = arg2;

	if (shr1->rn != shr2->rn)
		return 1;
	if (shr1->nh != shr2->nh)
		return 1;
	if (shr1->ri != shr2->ri)
		return 1;

	return 0;
}

void static_list_init(void)
{
	static_list = list_new();
	static_list->cmp = (int (*)(void *, void *))static_list_compare;
	static_list->del = (void (*)(void *))static_list_delete;
}

int zebra_static_route_holdem(struct route_node *rn,
			      struct static_route_info *ri,
			      struct static_nexthop *nh, safi_t safi,
			      struct static_vrf *svrf, bool negate)
{
	struct static_hold_route *shr, *lookup;
	struct listnode *node;

	zlog_warn("Static Route to not installed currently because dependent config not fully available");

	shr = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(*shr));
	shr->rn = rn;
	shr->nh = nh;
	shr->ri = ri;
	shr->safi = safi;
	shr->svrf = svrf;

	for (ALL_LIST_ELEMENTS_RO(static_list, node, lookup)) {
		if (static_list_compare(shr, lookup) == 0)
			break;
	}

	if (lookup) {
		if (negate) {
			listnode_delete(static_list, lookup);
			static_list_delete(shr);
			static_list_delete(lookup);
			return 1;
		}

		/*
		 * If a person enters the same line again
		 * we need to silently accept it
		 */
		goto shr_cleanup;
	}

	if (!negate) {
		listnode_add_sort(static_list, shr);
		return 1;
	}

shr_cleanup:
	XFREE(MTYPE_STATIC_ROUTE, shr);

	return 1;
}

void static_config_install_delayed_routes(struct static_vrf *svrf)
{
	struct listnode *node, *nnode;
	struct static_hold_route *shr;
	struct static_vrf *osvrf, *nh_svrf = NULL;
	struct static_route_info *ri;

	for (ALL_LIST_ELEMENTS(static_list, node, nnode, shr)) {
		osvrf = shr->svrf;
		if (shr->nh)
			nh_svrf =
				static_vrf_lookup_by_name(shr->nh->nh_vrfname);

		if (osvrf != svrf && nh_svrf != svrf)
			continue;

		if ((osvrf && osvrf->vrf && osvrf->vrf->vrf_id == VRF_UNKNOWN)
		    || (nh_svrf && nh_svrf->vrf->vrf_id == VRF_UNKNOWN))
			continue;
		if (shr->ri) {
			static_install_route(shr->rn, shr->ri, shr->safi,
					     shr->svrf);
		} else {
			RNODE_FOREACH_PATH_RO(shr->rn, ri)
			{
				static_install_route(shr->rn, ri, shr->safi,
						     shr->svrf);
			}
		}
		listnode_delete(static_list, shr);
		static_list_delete(shr);
	}
}
