/**
 * static_pm.c: STATIC PM handling routines
 *
 * Copyright (C) 6WIND 2019
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

#include "static_vrf.h"
#include "static_routes.h"
#include "static_memory.h"
#include "static_zebra.h"
#include "static_pm.h"

static time_t static_clock(void)
{
	struct timeval tv;

	monotime(&tv);
	return tv.tv_sec;
}

static int static_pm_af_inet_type(struct static_route *si)
{
	switch (si->type) {
	case STATIC_BLACKHOLE:
		return -1;
	case STATIC_IFNAME:
		/* should lookup prefix AFI. TODO */
		return -1;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		return AF_INET;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		return AF_INET6;
	default:
		return -1;
	}
}

static void *static_pm_choose_src_ip(struct interface *ifp,
				     int family,
				     union g_addr *addr)
{
	struct connected *ifc;
	struct listnode *node;
	void *src_ip = NULL;

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

/*
 * static_pm_sendmsg - Format and send a Peer cfg/unconfig
 *                        command to Zebra to be forwarded to PM
 */
static void static_pm_sendmsg(struct static_route *si, int command)
{
	struct pm_info *pm_info;
	vrf_id_t vrf_id;
	struct interface *ifp = NULL;
	int family;
	void *src_ip = NULL;
	union g_addr src;

	pm_info = (struct pm_info *)si->pm_info;

	vrf_id = si->nh_vrf_id;

	family = static_pm_af_inet_type(si);
	if (family < 0)
		return;
	if (si->ifindex != IFINDEX_INTERNAL) {
		ifp = if_lookup_by_index(si->ifindex, si->nh_vrf_id);
		if (!ifp || ifp->ifindex == IFINDEX_INTERNAL)
			return;
		src_ip = static_pm_choose_src_ip(ifp, family, &si->addr);
		if (src_ip) {
			memcpy(&src, src_ip, sizeof(union g_addr));
			src_ip = &src;
		}
	}
	if (si->ifname[0]) {
		ifp = if_lookup_by_name(si->ifname, si->nh_vrf_id);
		if (!ifp)
			return;
	}

	if (family == AF_INET)
		pm_peer_sendmsg(zclient, pm_info, AF_INET, &si->addr.ipv4,
				 src_ip, ifp ? ifp->name : NULL,
				 command, 1, vrf_id);
	else if (family == AF_INET6)
		pm_peer_sendmsg(zclient, pm_info, AF_INET6, &si->addr.ipv6,
				 src_ip, ifp ? ifp->name : NULL,
				 command, 1, vrf_id);
}

static void static_pm_update_si_source(struct static_route *si,
				       ifindex_t idx)
{
	if (!si->pm_info)
		return;
	si->ifindex = idx;
}

/*
 * static_pm_register - register a peer with PM through zebra
 *                      for monitoring the peer rechahability.
 */
static void static_pm_register(struct static_route *si)
{
	struct pm_info *pm_info;

	if (!si->pm_info)
		return;
	pm_info = (struct pm_info *)si->pm_info;

	/* Check if PM is enabled and peer has already been registered with PM
	 */
	if (CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
		return;

	static_pm_sendmsg(si, ZEBRA_PM_DEST_REGISTER);
}

/**
 * static_pm_deregister - deregister a peer with PM through zebra
 *                           for stopping the monitoring of the peer
 *                           rechahability.
 */
static void static_pm_deregister(struct static_route *si)
{
	struct pm_info *pm_info;

	if (!si->pm_info)
		return;
	pm_info = (struct pm_info *)si->pm_info;

	/* Check if PM is eanbled and peer has not been registered */
	if (!CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
		return;

	pm_info->status = PM_STATUS_UNKNOWN;
	pm_info->last_update = static_clock();

	si->nh_pm_valid = true;

	static_pm_sendmsg(si, ZEBRA_PM_DEST_DEREGISTER);
}

/*
 * static_pm_update_si - update peer with PM with new PM paramters
 *                       through zebra.
 */
void static_pm_update_si(struct static_route *si, bool install)
{
	struct pm_info *pm_info;

	if (!si->pm_info)
		return;
	pm_info = (struct pm_info *)si->pm_info;

	if (install) {
		/* register it */
		if (!CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
			static_pm_register(si);
		else
			static_pm_sendmsg(si, ZEBRA_PM_DEST_UPDATE);
	} else {
		/* unregister it. one reason is that nht failed */
		static_pm_deregister(si);
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
	struct static_route *si;

	zlog_debug("Zebra: PM Dest replay request");

	/* Send the client registration */
	pm_client_sendmsg(zclient, ZEBRA_PM_CLIENT_REGISTER, vrf_id);

	/* Replay the peer, if PM is enabled in staticd */
	svrf = vrf_info_get(vrf_id);
	if (!svrf)
		return 0;
	stable = static_vrf_static_table(AFI_IP, SAFI_UNICAST, svrf);
	if (stable) {
		for (rn = route_top(stable); rn; rn = route_next(rn)) {
			for (si = rn->info; si; si = si->next) {
				if (!si->pm)
					continue;
				static_pm_update_si(si, true);
			}
		}
	}
	stable = static_vrf_static_table(AFI_IP6, SAFI_UNICAST, svrf);
	if (stable) {
		for (rn = route_top(stable); rn; rn = route_next(rn)) {
			for (si = rn->info; si; si = si->next) {
				if (!si->pm)
					continue;
				static_pm_update_si(si, true);
			}
		}
	}
	return 0;
}

static void static_pm_update_status(struct static_route *si, int status)
{
	struct pm_info *pm_info;

	pm_info = si->pm_info;

	if (!pm_info)
		return;

	if (pm_info->status == status)
		return;

	pm_info->status = status;
	pm_info->last_update = static_clock();
}

static void static_pm_update(struct prefix *dp, vrf_id_t nh_vrf_id,
			      int status, ifindex_t idx)
{
	struct route_table *stable;
	struct static_route *si;
	struct static_vrf *svrf;
	struct route_node *rn;
	char buf[PREFIX2STR_BUFFER];
	afi_t afi;
	bool change;
	struct pm_info *pm_info;

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
		change = false;
		for (si = rn->info; si; si = si->next) {
			if (!si->pm)
				continue;

			if (si->nh_vrf_id != nh_vrf_id)
				continue;

			if (si->type != STATIC_IPV4_GATEWAY
			    && si->type != STATIC_IPV4_GATEWAY_IFNAME
			    && si->type != STATIC_IPV6_GATEWAY
			    && si->type != STATIC_IPV6_GATEWAY_IFNAME)
				continue;

			if (dp->family == AF_INET &&
			    (si->type == STATIC_IPV6_GATEWAY ||
			     si->type == STATIC_IPV6_GATEWAY_IFNAME)) {
				continue;
			}
			if (dp->family == AF_INET6 &&
			    (si->type == STATIC_IPV4_GATEWAY ||
			     si->type == STATIC_IPV4_GATEWAY_IFNAME)) {
				continue;
			}
			if ((dp->family == AF_INET &&
			     !IPV4_ADDR_SAME(&dp->u.prefix4, &si->addr.ipv4)) ||
			    (dp->family == AF_INET6 &&
			     !IPV6_ADDR_SAME(&dp->u.prefix6, &si->addr.ipv6)))
				continue;
			if (idx != IFINDEX_INTERNAL) {
				static_pm_update_si_source(si, idx);
				static_pm_update_si(si, true);
			}
			if (status == PM_STATUS_UNKNOWN)
				continue;
			/* if not registered yet,
			 * ignore the event
			 */
			pm_info = si->pm_info;
			if (!pm_info)
				continue;
			if (!CHECK_FLAG(pm_info->flags, PM_FLAG_PM_REG))
				continue;
			if (status == PM_STATUS_DOWN &&
			    si->nh_pm_valid) {
				si->nh_pm_valid = false;
				change = true;
			} else if (status == PM_STATUS_UP &&
				   !si->nh_pm_valid) {
				si->nh_pm_valid = true;
				change = true;
			}
			if (change) {
				zlog_debug("[%s]: PM %s", buf,
					   pm_get_status_str(status));
				static_pm_update_status(si, status);
				static_zebra_route_add(rn, si,
						       svrf->vrf->vrf_id,
						       SAFI_UNICAST,
						       true);
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
			   "Zebra: vrf %u interface %s pm destination %s %s",
			   vrf_id, ifp->name, buf[0],
			   pm_get_status_str(status));
	} else {
		prefix2str(&sp, buf[1], sizeof(buf[1]));
		zlog_debug(
			   "Zebra: vrf %u source %s pm destination %s %s",
			   vrf_id, buf[1], buf[0],
			   pm_get_status_str(status));
	}

	/* Bring the route down if PM is enabled in static */
	static_pm_update(&dp, vrf_id, status, IFINDEX_INTERNAL);
	return 0;
}

/*
 * static_pm_param_set - Set the configured PM paramter values for peer.
 */
int static_pm_param_set(struct static_route *si, uint32_t frequency,
			uint32_t timeout, uint16_t packet_size,
			uint8_t tos_val)
{
	int command = 0;
	int family = static_pm_af_inet_type(si);
	struct pm_info *pm_info;
	void *dst_ip, *src_ip = NULL;
	struct interface *ifp = NULL;
	union g_addr src;

	pm_set_param((struct pm_info **)&(si->pm_info), frequency, timeout,
		     packet_size, tos_val, &command);
	pm_info = si->pm_info;

	/* dont register with peer, while nh is not valid */
	if (!si->nh_valid)
		return 0;

	if (family == AF_INET) {
		dst_ip =  &si->addr.ipv4;
		if (!si->addr.ipv4.s_addr)
			return 0;
	} else if (family == AF_INET6) {
		dst_ip =  &si->addr.ipv6;
	} else
		return 0;

	if (si->ifindex != IFINDEX_INTERNAL) {
		ifp = if_lookup_by_index(si->ifindex, si->nh_vrf_id);
		if (!ifp || ifp->ifindex == IFINDEX_INTERNAL)
			return 0;
		src_ip = static_pm_choose_src_ip(ifp, family, &si->addr);
		if (src_ip) {
			memcpy(&src, src_ip, sizeof(union g_addr));
			src_ip = &src;
		}
	}
	if (si->ifname[0]) {
		ifp = if_lookup_by_name(si->ifname, si->nh_vrf_id);
		if (!ifp || ifp->ifindex == IFINDEX_INTERNAL)
			return 0;
		pm_peer_sendmsg(zclient, pm_info, family,
				 dst_ip, src_ip, ifp->name,
				 command, 0, si->nh_vrf_id);
	} else {
		pm_peer_sendmsg(zclient, pm_info, family,
				dst_ip, src_ip, NULL,
				command, 0, si->nh_vrf_id);
	}
	return 0;
}

/*
 * static_pm_param_unset - Delete the configured PM paramter values for
 * that entry.
 */
int static_pm_param_unset(struct static_route *si)
{
	if (!si->pm_info)
		return 0;

	static_pm_deregister(si);
	pm_info_free(&(si->pm_info));
	return 0;
}

static void static_pm_info_vrf(struct vty *vty, struct vrf *vrf, afi_t afi)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct static_route *si;
	char buf[SRCDEST2STR_BUFFER];
	struct route_node *rn;

	if (!vrf || !vrf->info)
		return;
	svrf = vrf->info;
	stable = svrf->stable[afi][SAFI_UNICAST];
	if (stable == NULL)
		return;
	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn))
		for (si = rn->info; si; si = si->next) {
			if (!si->pm_info)
				continue;
			if (si->type == STATIC_BLACKHOLE ||
			    si->type == STATIC_IFNAME)
				continue;
			vty_out(vty, "vrf %s, ", vrf->name);
			vty_out(vty, "pfx %s, ",
				srcdest_rnode2str(rn, buf, sizeof(buf)));
			if (afi == AFI_IP6)
				vty_out(vty, "gateway %s\n",
					inet_ntop(AF_INET6, &si->addr.ipv6, buf,
						  sizeof(buf)));
			else
				vty_out(vty, "gateway %s\n",
					inet_ntop(AF_INET, &si->addr.ipv4, buf,
						  sizeof(buf)));
			pm_show_info(vty, si->pm_info, 0, false, NULL);
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

void static_pm_update_connected(struct zapi_route *nhr,
				struct prefix *dp, vrf_id_t vrf_id)
{
	int i;
	ifindex_t idx = IFINDEX_INTERNAL;

	/* look nexthop num with ifindex type */
	for (i = 0; i < nhr->nexthop_num; i++) {
		idx = nhr->nexthops[i].ifindex;
		if (idx != IFINDEX_INTERNAL) {
			static_pm_update(dp, vrf_id, PM_STATUS_UNKNOWN, idx);
			break;
		}
	}
}
