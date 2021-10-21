/**
 * static_pm.c: STATIC PM handling routines
 *
 * Copyright 2019 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "pm_lib.h"
#include "json.h"
#include "table.h"
#include "srcdest_table.h"
#include "zclient.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_pm.h"

extern struct zclient *zclient;

/* Zeroed array with the size of an IPv6 address. */
struct in6_addr zero_addr;

static time_t static_clock(void)
{
	struct timeval tv;

	monotime(&tv);
	return tv.tv_sec;
}

static int static_pm_af_inet_type(struct static_nexthop *nh)
{
	switch (nh->type) {
	case STATIC_BLACKHOLE:
		return AF_UNSPEC;
	case STATIC_IFNAME:
		/* should lookup prefix AFI. TODO */
		return AF_UNSPEC;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		return AF_INET;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static void static_next_hop_pm_change(struct static_nexthop *sn,
				      int status)
{
	struct pm_info *pm_info;

	if (!sn->pm_info)
		return;
	pm_info = (struct pm_info *)sn->pm_info;

	if (pm_info->status == status)
		return;

	pm_info->status = status;
	pm_info->last_update = static_clock();

	switch(status) {
	case PM_STATUS_UP:
		/* Peer is back up, add this next hop. */
		sn->path_down = false;
		static_zebra_route_add(sn->rn, sn->sp, sn->safi, true);
		break;
	case PM_STATUS_DOWN:
		/* Peer went down, remove this next hop. */
		sn->path_down = true;
		static_zebra_route_add(sn->rn, sn->sp, sn->safi, true);
		break;
	}

}

static void *static_pm_choose_src_ip(struct interface *ifp,
				     int family,
				     union g_addr *addr)
{
	struct connected *ifc;
	struct listnode *node;
	static void *src_ip = NULL;

	if (!ifp)
		return NULL;
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		if (!ifc->address)
			continue;
		if (family != ifc->address->family)
			continue;
		if (family == AF_INET) {
			src_ip = &ifc->address->u.prefix4;
			break;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && IN6_IS_ADDR_LINKLOCAL(addr)) {
			src_ip = &ifc->address->u.prefix6;
			break;
		}
		if (!IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && !IN6_IS_ADDR_LINKLOCAL(addr)) {
			src_ip = &ifc->address->u.prefix6;
			break;
		}
	}
	return src_ip;
}

static uint16_t static_next_hop_pkt_size_from_next_hop(struct static_nexthop *sn)
{
	uint16_t pkt_size = 0;

	switch (sn->type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		pkt_size = PM_DEF_PACKET_SIZE;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		pkt_size = PM_DEF_IPV6_PACKET_SIZE;
		break;
	default:
		break;
	}
	return pkt_size;
}

static void static_pm_sendmsg(struct static_nexthop *nh, int cmd)
{
	int command = 0;
	int family = static_pm_af_inet_type(nh);
	struct pm_info *pm_info;
	void *dst_ip, *src_ip = NULL;
	struct interface *ifp = NULL;
	uint16_t pkt_size;
	char *ifname = NULL;
	const struct prefix *dst_p, *src_p;

	nh->pm = true;

	if (nh->nh_vrf_id == VRF_UNKNOWN)
		return;

	/* next-hop IP validity */
	if (family == AF_INET) {
		if (!nh->addr.ipv4.s_addr)
			return;
	} else if (family == AF_INET6) {
		if (memcmp(&nh->addr.ipv6.s6_addr, &zero_addr,
			   sizeof(struct in6_addr)) == 0)
			return;
	} else
		return;

	if (cmd == ZEBRA_PM_DEST_DEREGISTER) {
		if (!nh->pm_info)
			return;
		pm_info = nh->pm_info;
		if (pm_info->ifname[0] != '\0')
			ifname = (char *)&pm_info->ifname;
		if (memcmp(&zero_addr, &pm_info->src_ip, sizeof(pm_info->src_ip)))
			src_ip = &pm_info->src_ip;
		else
			src_ip = NULL;
	} else {
		/* interface validity */
		if ((nh->type == STATIC_IPV4_GATEWAY_IFNAME
		     || nh->type == STATIC_IPV6_GATEWAY_IFNAME)) {
			ifp = if_lookup_by_name(nh->ifname, nh->nh_vrf_id);
			if (ifp)
				ifname = ifp->name;
		} else {
			srcdest_rnode_prefixes(nh->rn, &dst_p, &src_p);
			ifp = static_zebra_get_interface(dst_p, nh->nh_vrf_id);
		}
		if (!ifp || ifp->ifindex == IFINDEX_INTERNAL)
			return;
		src_ip = static_pm_choose_src_ip(ifp, family, &nh->addr);
		if (!src_ip)
			return;
	}

	if (nh->pm_info) {
		command = cmd;
	} else {
		pkt_size = static_next_hop_pkt_size_from_next_hop(nh);
		pm_set_param((struct pm_info **)&(nh->pm_info), PM_DEF_INTERVAL, PM_DEF_TIMEOUT,
			     pkt_size, PM_DEF_TOS_VAL, &command);
		assert(command);
	}
	pm_info = nh->pm_info;

	if (family == AF_INET)
		dst_ip =  &nh->addr.ipv4;
	else
		dst_ip =  &nh->addr.ipv6;

	pm_peer_sendmsg(zclient, pm_info, family,
			dst_ip, src_ip, NULL, ifname,
			command, 1, nh->nh_vrf_id);
}

/*
 * static_pm_register - register a peer with PM through zebra
 *                      for monitoring the peer rechahability.
 */
static void static_pm_register(struct static_nexthop *nh)
{
	struct pm_info *pm_info;

	if (!nh->pm_info)
		return;
	pm_info = (struct pm_info *)nh->pm_info;

	/* Check if PM is enabled and peer has already been registered with PM
	 */
	if (CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
		return;

	static_pm_sendmsg(nh, ZEBRA_PM_DEST_REGISTER);
}

/**
 * static_pm_deregister - deregister a peer with PM through zebra
 *                           for stopping the monitoring of the peer
 *                           rechahability.
 */
static void static_pm_deregister(struct static_nexthop *nh)
{
	struct pm_info *pm_info;

	if (!nh->pm_info) {
		zlog_err("%s(): PM context not available", __func__);
		return;
	}
	pm_info = (struct pm_info *)nh->pm_info;

	/* Check if PM is eanbled and peer has not been registered */
	if (!CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG)) {
		zlog_err("%s(): PM context not registered", __func__);
		return;
	}
	pm_info->status = PM_STATUS_UNKNOWN;
	pm_info->last_update = static_clock();

	static_pm_sendmsg(nh, ZEBRA_PM_DEST_DEREGISTER);
}

/*
 * static_pm_update_si - update peer with PM with new PM paramters
 *                       through zebra.
 */
void static_pm_update_si(struct static_nexthop *nh, bool install)
{
	struct pm_info *pm_info;

	if (!nh->pm_info)
		return;
	pm_info = (struct pm_info *)nh->pm_info;

	if (install) {
		/* register it */
		if (!CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
			static_pm_register(nh);
		else
			static_pm_sendmsg(nh, ZEBRA_PM_DEST_UPDATE);
	} else {
		/* unregister it. one reason is that nht failed */
		static_pm_deregister(nh);
	}
}

/*
 * static_pm_dest_replay - Replay all the peers that have PM enabled
 *                       to zebra
 */
static int static_pm_dest_replay(int command, struct zclient *client,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;
	int afi;

	zlog_debug("Zebra: PM Dest replay request");

	/* Send the client registration */
	pm_client_sendmsg(zclient, ZEBRA_PM_CLIENT_REGISTER, vrf_id);

	/* Replay the peer, if PM is enabled in staticd */
	svrf = vrf_info_get(vrf_id);
	if (!svrf)
		return 0;
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		stable = static_vrf_static_table(afi, SAFI_UNICAST, svrf);
		if (!stable)
			continue;
		for (rn = route_top(stable); rn; rn = route_next(rn)) {
			si = rn->info;
			if (!si)
				continue;

			frr_each(static_path_list, &si->path_list, pn) {
				frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
					if (!nh->pm_info)
						continue;
					static_pm_update_si(nh, true);
				}
			}
		}
	}
	return 0;
}

static void static_pm_update_from_idx(struct static_nexthop *nh, int family,
				      ifindex_t oif_idx, vrf_id_t vrf_id)
{
	struct interface *ifp = NULL;
	void *src = NULL;
	void *dst;
	int command = ZEBRA_PM_DEST_REGISTER;
	uint16_t pkt_size;

	/* update addresses */
	ifp = if_lookup_by_index(oif_idx, vrf_id);
	if (!ifp)
		return;
	src = static_pm_choose_src_ip(ifp, family, &nh->addr);
	if (!src)
		return;

	if (family == AF_INET)
		dst = &nh->addr.ipv4;
	else
		dst = &nh->addr.ipv6;

	if ((nh->type == STATIC_IPV4_GATEWAY_IFNAME
	     || nh->type == STATIC_IPV6_GATEWAY_IFNAME)) {
		ifp = if_lookup_by_name(nh->ifname, nh->nh_vrf_id);
		if (!ifp || ifp->ifindex == IFINDEX_INTERNAL)
			return;
	}

	if (!nh->pm_info) {
		pkt_size = static_next_hop_pkt_size_from_next_hop(nh);
		pm_set_param((struct pm_info **)&(nh->pm_info), PM_DEF_INTERVAL, PM_DEF_TIMEOUT,
			     pkt_size, PM_DEF_TOS_VAL, &command);
		assert(command);
	}

	pm_peer_sendmsg(zclient, nh->pm_info, family,
			dst, src, NULL, ifp ? ifp->name : NULL,
			command, 1, nh->nh_vrf_id);
}

static void static_pm_update(ifindex_t idx, struct prefix *dp,
			     vrf_id_t nh_vrf_id, int status, bool deregister)
{
	struct route_table *stable;
	struct static_route_info *si;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_vrf *svrf;
	struct route_node *rn;
	char buf[PREFIX2STR_BUFFER];
	afi_t afi;

	prefix2str(dp, buf, sizeof(buf));
	svrf = vrf_info_get(nh_vrf_id);
	if (!svrf)
		return;

	if (dp->family == AF_INET)
		afi = AFI_IP;
	else if (dp->family == AF_INET6)
		afi = AFI_IP6;
	else
		return;

	stable = static_vrf_static_table(afi, SAFI_UNICAST, svrf);
	if (!stable)
		return;
	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = rn->info;
		if (!si)
			continue;

		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (!nh->pm)
					continue;
				if (nh->nh_vrf_id != nh_vrf_id)
					continue;
				if (nh->type != STATIC_IPV4_GATEWAY
				    && nh->type != STATIC_IPV4_GATEWAY_IFNAME
				    && nh->type != STATIC_IPV6_GATEWAY
				    && nh->type != STATIC_IPV6_GATEWAY_IFNAME)
					continue;
				if (dp->family == AF_INET
				    && (nh->type == STATIC_IPV6_GATEWAY
					|| nh->type == STATIC_IPV6_GATEWAY_IFNAME)) {
					continue;
				}
				if (dp->family == AF_INET6
				    && (nh->type == STATIC_IPV4_GATEWAY
					|| nh->type == STATIC_IPV4_GATEWAY_IFNAME)) {
					continue;
				}
				if (dp->family == AF_INET
				    && !IPV4_ADDR_SAME(&dp->u.prefix4, &nh->addr.ipv4))
					continue;
				if (dp->family == AF_INET6
				    && !IPV6_ADDR_SAME(&dp->u.prefix6, &nh->addr.ipv6))
					continue;
				if (status != PM_STATUS_UNKNOWN) {
					static_next_hop_pm_change(nh, status);
				} else if (idx != IFINDEX_INTERNAL) {
					if (deregister)
						static_pm_deregister(nh);
					static_pm_update_from_idx(nh, dp->family,
								  idx, nh_vrf_id);
				}
			}
		}
	}
}

/*
 * static_pm_dest_update - Find the peer for which the PM status
 *                       has changed and bring down the peer
 *                       connectivity if the PM session went down.
 */
static int static_pm_dest_update(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct prefix dp;
	struct prefix sp;
	int status;
	char buf[2][PREFIX2STR_BUFFER];

	ifp = pm_get_peer_info(zclient->ibuf, &dp, &sp, &status, vrf_id);

	prefix2str(&dp, buf[0], sizeof(buf[0]));
	if (ifp) {
		zlog_debug(
			   "STATIC-PM: vrf %u interface %s pm destination %s %s",
			   vrf_id, ifp->name, buf[0],
			   pm_get_status_str(status));
	} else {
		prefix2str(&sp, buf[1], sizeof(buf[1]));
		zlog_debug(
			   "STATIC-PM: vrf %u source %s pm destination %s %s",
			   vrf_id, buf[1], buf[0],
			   pm_get_status_str(status));
	}

	/* Bring the route down if PM is enabled in static */
	static_pm_update_status(&dp, vrf_id, status);
	return 0;
}

void static_pm_update_interface(ifindex_t idx, struct prefix *dp,
				vrf_id_t nh_vrf_id, ifindex_t old_idx)
{
	bool deregister = old_idx != IFINDEX_INTERNAL && idx != old_idx;

	static_pm_update(idx, dp, nh_vrf_id, PM_STATUS_UNKNOWN, deregister);
}

void static_pm_update_status(struct prefix *dp, vrf_id_t nh_vrf_id,
			     int status)
{
	static_pm_update(IFINDEX_INTERNAL, dp, nh_vrf_id, status, false);
}

void static_next_hop_pm_destroy(struct static_nexthop *sn)
{
	if (!sn->pm_info)
		return;

	static_pm_deregister(sn);
	pm_info_free(&(sn->pm_info));
	sn->pm = false;
}

void static_next_hop_pm_update(struct static_nexthop *sn)
{
	sn->pm = true;
	static_pm_sendmsg(sn, ZEBRA_PM_DEST_REGISTER);
}

static void static_pm_info_vrf(struct vty *vty, struct vrf *vrf, afi_t afi)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;
	char buf[SRCDEST2STR_BUFFER];
	struct route_node *rn;

	if (!vrf || !vrf->info)
		return;

	svrf = vrf->info;
	stable = svrf->stable[afi][SAFI_UNICAST];
	if (stable == NULL)
		return;

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
		si = rn->info;
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (!nh->pm_info)
					continue;
				if (nh->type == STATIC_BLACKHOLE ||
				    nh->type == STATIC_IFNAME)
					continue;
				vty_out(vty, "vrf %s, ", vrf->name);
				vty_out(vty, "pfx %s, ",
					srcdest_rnode2str(rn, buf, sizeof(buf)));
				if (afi == AFI_IP)
					vty_out(vty, "gateway %s\n",
						inet_ntop(AF_INET, &nh->addr.ipv4, buf,
							  sizeof(buf)));
				else
					vty_out(vty, "gateway %s\n",
						inet_ntop(AF_INET6, &nh->addr.ipv6, buf,
							  sizeof(buf)));

				pm_show_info(vty, nh->pm_info, 0, false, NULL);
			}
		}
	}
}

DEFUN (show_static_pm_info,
       show_static_pm_info_cmd,
       "show static routing pm [vrf NAME]",
       SHOW_STR
       "Static routing information\n"
       "routing information\n"
       "PM Information\n"
       VRF_CMD_HELP_STR)
{
	int idx_vrf = 5;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct vrf *vrf;

	if (argc > 4) {
		VRF_GET_ID (vrf_id, argv[idx_vrf]->arg, false);
		vrf = vrf_lookup_by_id(vrf_id);
		static_pm_info_vrf(vty, vrf, AFI_IP);
		static_pm_info_vrf(vty, vrf, AFI_IP6);
		return CMD_SUCCESS;
	}
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		static_pm_info_vrf(vty, vrf, AFI_IP);
		static_pm_info_vrf(vty, vrf, AFI_IP6);
	}
	return CMD_SUCCESS;
}

void static_pm_init(void)
{
	pm_gbl_init();

	/* Initialize PM client functions */
	zclient->interface_pm_dest_update = static_pm_dest_update;
	zclient->pm_dest_replay = static_pm_dest_replay;

	install_element(VIEW_NODE, &show_static_pm_info_cmd);
}
