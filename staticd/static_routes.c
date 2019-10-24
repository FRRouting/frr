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
static void static_install_route(struct route_node *rn,
				 struct static_route *si_changed, safi_t safi)
{
	struct static_route *si;

	for (si = rn->info; si; si = si->next)
		static_zebra_nht_register(rn, si, true);

	si = rn->info;
	if (si)
		static_zebra_route_add(rn, si_changed, si->vrf_id, safi, true);

}

/* Uninstall static route from RIB. */
static void static_uninstall_route(vrf_id_t vrf_id, safi_t safi,
				   struct route_node *rn,
				   struct static_route *si_changed)
{

	if (rn->info)
		static_zebra_route_add(rn, si_changed, vrf_id, safi, true);
	else
		static_zebra_route_add(rn, si_changed, vrf_id, safi, false);
}

int static_add_route(afi_t afi, safi_t safi, uint8_t type, struct prefix *p,
		     struct prefix_ipv6 *src_p, union g_addr *gate,
		     const char *ifname, enum static_blackhole_type bh_type,
		     route_tag_t tag, uint8_t distance, struct static_vrf *svrf,
		     struct static_vrf *nh_svrf,
		     struct static_nh_label *snh_label, uint32_t table_id,
		     bool onlink)
{
	struct route_node *rn;
	struct static_route *si;
	struct static_route *pp;
	struct static_route *cp;
	struct static_route *update = NULL;
	struct route_table *stable = svrf->stable[afi][safi];
	struct interface *ifp;

	if (!stable)
		return -1;

	if (!gate && (type == STATIC_IPV4_GATEWAY
		      || type == STATIC_IPV4_GATEWAY_IFNAME
		      || type == STATIC_IPV6_GATEWAY
		      || type == STATIC_IPV6_GATEWAY_IFNAME))
		return -1;

	if (!ifname
	    && (type == STATIC_IFNAME || type == STATIC_IPV4_GATEWAY_IFNAME
		|| type == STATIC_IPV6_GATEWAY_IFNAME))
		return -1;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_get(stable, p, src_p);

	/* Do nothing if there is a same static route.  */
	for (si = rn->info; si; si = si->next) {
		if (type == si->type
		    && (!gate
			|| ((afi == AFI_IP
			     && IPV4_ADDR_SAME(&gate->ipv4, &si->addr.ipv4))
			    || (afi == AFI_IP6
				&& IPV6_ADDR_SAME(gate, &si->addr.ipv6))))
		    && (!strcmp(ifname ? ifname : "", si->ifname))
		    && nh_svrf->vrf->vrf_id == si->nh_vrf_id) {
			if ((distance == si->distance) && (tag == si->tag)
			    && (table_id == si->table_id)
			    && !memcmp(&si->snh_label, snh_label,
				       sizeof(struct static_nh_label))
			    && si->bh_type == bh_type && si->onlink == onlink) {
				route_unlock_node(rn);
				return 0;
			}
			update = si;
		}
	}

	/* Distance or tag or label changed, delete existing first. */
	if (update)
		static_delete_route(afi, safi, type, p, src_p, gate, ifname,
				    update->tag, update->distance, svrf,
				    &update->snh_label, table_id);

	/* Make new static route structure. */
	si = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(struct static_route));

	si->type = type;
	si->distance = distance;
	si->bh_type = bh_type;
	si->tag = tag;
	si->vrf_id = svrf->vrf->vrf_id;
	si->nh_vrf_id = nh_svrf->vrf->vrf_id;
	strlcpy(si->nh_vrfname, nh_svrf->vrf->name, sizeof(si->nh_vrfname));
	si->table_id = table_id;
	si->onlink = onlink;

	if (ifname)
		strlcpy(si->ifname, ifname, sizeof(si->ifname));
	si->ifindex = IFINDEX_INTERNAL;

	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		si->addr.ipv4 = gate->ipv4;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		si->addr.ipv6 = gate->ipv6;
		break;
	case STATIC_IFNAME:
		break;
	}

	/* Save labels, if any. */
	memcpy(&si->snh_label, snh_label, sizeof(struct static_nh_label));

	/*
	 * Add new static route information to the tree with sort by
	 * distance value and gateway address.
	 */
	for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next) {
		if (si->distance < cp->distance)
			break;
		if (si->distance > cp->distance)
			continue;
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
		rn->info = si;
	if (cp)
		cp->prev = si;
	si->prev = pp;
	si->next = cp;

	/* check whether interface exists in system & install if it does */
	switch (si->type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		static_zebra_nht_register(rn, si, true);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		ifp =  if_lookup_by_name(ifname, nh_svrf->vrf->vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL)
			si->ifindex = ifp->ifindex;
		else
			zlog_warn("Static Route using %s interface not installed because the interface does not exist in specified vrf",
				  ifname);

		static_zebra_nht_register(rn, si, true);
		break;
	case STATIC_BLACKHOLE:
		static_install_route(rn, si, safi);
		break;
	case STATIC_IFNAME:
		ifp = if_lookup_by_name(ifname, nh_svrf->vrf->vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL) {
			si->ifindex = ifp->ifindex;
			static_install_route(rn, si, safi);
		} else
			zlog_warn("Static Route using %s interface not installed because the interface does not exist in specified vrf",
				  ifname);

		break;
	}

	return 1;
}

int static_delete_route(afi_t afi, safi_t safi, uint8_t type, struct prefix *p,
			struct prefix_ipv6 *src_p, union g_addr *gate,
			const char *ifname, route_tag_t tag, uint8_t distance,
			struct static_vrf *svrf,
			struct static_nh_label *snh_label,
			uint32_t table_id)
{
	struct route_node *rn;
	struct static_route *si;
	struct route_table *stable;

	/* Lookup table.  */
	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return -1;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_lookup(stable, p, src_p);
	if (!rn)
		return 0;

	/* Find same static route is the tree */
	for (si = rn->info; si; si = si->next)
		if (type == si->type
		    && (!gate
			|| ((afi == AFI_IP
			     && IPV4_ADDR_SAME(&gate->ipv4, &si->addr.ipv4))
			    || (afi == AFI_IP6
				&& IPV6_ADDR_SAME(gate, &si->addr.ipv6))))
		    && (!strcmp(ifname ? ifname : "", si->ifname))
		    && (!tag || (tag == si->tag))
		    && (table_id == si->table_id)
		    && (!snh_label->num_labels
			|| !memcmp(&si->snh_label, snh_label,
				   sizeof(struct static_nh_label))))
			break;

	/* Can't find static route. */
	if (!si) {
		route_unlock_node(rn);
		return 0;
	}

	static_zebra_nht_register(rn, si, false);

	/* Unlink static route from linked list. */
	if (si->prev)
		si->prev->next = si->next;
	else
		rn->info = si->next;
	if (si->next)
		si->next->prev = si->prev;

	/*
	 * If we have other si nodes then route replace
	 * else delete the route
	 */
	static_uninstall_route(si->vrf_id, safi, rn, si);
	route_unlock_node(rn);

	/* Free static route configuration. */
	XFREE(MTYPE_STATIC_ROUTE, si);

	route_unlock_node(rn);

	return 1;
}

static void static_ifindex_update_af(struct interface *ifp, bool up, afi_t afi,
				     safi_t safi)
{
	struct route_table *stable;
	struct route_node *rn;
	struct static_route *si;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;

		stable = static_vrf_static_table(afi, safi, svrf);
		if (!stable)
			continue;

		for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
			for (si = rn->info; si; si = si->next) {
				if (!si->ifname[0])
					continue;
				if (up) {
					if (strcmp(si->ifname, ifp->name))
						continue;
					if (si->nh_vrf_id != ifp->vrf_id)
						continue;
					si->ifindex = ifp->ifindex;
				} else {
					if (si->ifindex != ifp->ifindex)
						continue;
					if (si->nh_vrf_id != ifp->vrf_id)
						continue;
					si->ifindex = IFINDEX_INTERNAL;
				}

				static_install_route(rn, si, safi);
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
	struct static_route *si;
	struct interface *ifp;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		for (si = rn->info; si; si = si->next) {
			if (strcmp(svrf->vrf->name, si->nh_vrfname) != 0)
				continue;

			si->nh_vrf_id = svrf->vrf->vrf_id;
			si->nh_registered = false;
			if (si->ifindex) {
				ifp = if_lookup_by_name(si->ifname,
							si->nh_vrf_id);
				if (ifp)
					si->ifindex = ifp->ifindex;
				else
					continue;
			}

			static_install_route(rn, si, safi);
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
			      struct route_table *stable,
			      afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_route *si;
	struct interface *ifp;
	struct vrf *vrf = svrf->vrf;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		for (si = rn->info; si; si = si->next) {
			si->vrf_id = vrf->vrf_id;
			if (si->ifindex) {
				ifp = if_lookup_by_name(si->ifname,
							si->nh_vrf_id);
				if (ifp)
					si->ifindex = ifp->ifindex;
				else
					continue;
			}
			static_install_route(rn, si, safi);
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
			       struct route_table *stable,
			       afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_route *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		for (si = rn->info; si; si = si->next) {
			if (strcmp(svrf->vrf->name, si->nh_vrfname) != 0)
				continue;

			static_uninstall_route(si->vrf_id, safi, rn, si);
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
	struct static_route *si;

	for (rn = route_top(stable); rn; rn = route_next(rn))
		for (si = rn->info; si; si = si->next)
			static_uninstall_route(si->vrf_id, safi, rn, si);
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
				 struct interface *ifp,
				 afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_route *si;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		for (si = rn->info; si; si = si->next) {
			if (si->nh_vrf_id != ifp->vrf_id)
				continue;

			if (si->ifindex != ifp->ifindex)
				continue;

			static_install_route(rn, si, safi);
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
