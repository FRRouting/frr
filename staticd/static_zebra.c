/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "srcdest_table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"

/* Zebra structure to hold current status. */
struct zclient *zclient;

static struct interface *zebra_interface_if_lookup(struct stream *s)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name(ifname_tmp, VRF_DEFAULT);
}

/* Inteface addition message from zebra. */
static int interface_add(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (!ifp)
		return 0;

	static_ifindex_update(ifp, true);
	return 0;
}

static int interface_delete(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;
	/* zebra_interface_state_read () updates interface structure in iflist
	 */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if_set_index(ifp, IFINDEX_INTERNAL);

	static_ifindex_update(ifp, false);
	return 0;
}

static int interface_address_add(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(c);
	return 0;
}

static int interface_state_up(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_if_lookup(zclient->ibuf);

	if (if_is_vrf(ifp)) {
		struct static_vrf *svrf = static_vrf_lookup_by_id(vrf_id);

		static_fixup_vrf_ids(svrf);
		static_config_install_delayed_routes(svrf);
	}

	return 0;
}

static int interface_state_down(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	zebra_interface_state_read(zclient->ibuf, vrf_id);

	return 0;
}

static int route_notify_owner(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	char buf[PREFIX_STRLEN];

	prefix2str(&p, buf, sizeof(buf));

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_warn("%s: Route %s failed to install for table: %u",
			  __PRETTY_FUNCTION__, buf, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_warn("%s: Route %s over-ridden by better route for table: %u",
			  __PRETTY_FUNCTION__, buf, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		break;
	case ZAPI_ROUTE_REMOVED:
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		zlog_warn("%s: Route %s failure to remove for table: %u",
			  __PRETTY_FUNCTION__, buf, table_id);
		break;
	}

	return 0;
}
static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}


static int static_zebra_nexthop_update(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route nhr;
	afi_t afi = AFI_IP;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("Failure to decode nexthop update message");
		return 1;
	}

	if (nhr.prefix.family == AF_INET6)
		afi = AFI_IP6;

	static_nht_update(&nhr.prefix, nhr.nexthop_num, afi, vrf_id);
	return 1;
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
}

void static_zebra_nht_register(struct static_route *si, bool reg)
{
	uint32_t cmd;
	struct prefix p;

	cmd = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	if (si->nh_registered && reg)
		return;

	if (!si->nh_registered && !reg)
		return;

	memset(&p, 0, sizeof(p));
	switch (si->type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	case STATIC_IPV6_GATEWAY_IFNAME:
		return;
	case STATIC_IPV4_GATEWAY:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = si->addr.ipv4;
		break;
	case STATIC_IPV6_GATEWAY:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = si->addr.ipv6;
		break;
	}

	if (zclient_send_rnh(zclient, cmd, &p, false, si->nh_vrf_id) < 0)
		zlog_warn("%s: Failure to send nexthop to zebra",
			  __PRETTY_FUNCTION__);

	si->nh_registered = reg;
}

extern void static_zebra_route_add(struct route_node *rn, vrf_id_t vrf_id,
				   safi_t safi, bool install)
{
	struct static_route *si = rn->info;
	const struct prefix *p, *src_pp;
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	uint32_t nh_num = 0;

	p = src_pp = NULL;
	srcdest_rnode_prefixes(rn, &p, &src_pp);

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_STATIC;
	api.safi = safi;
	memcpy(&api.prefix, p, sizeof(api.prefix));

	if (src_pp) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_pp, sizeof(api.src_prefix));
	}

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	for (/*loaded above*/; si; si = si->next) {
		api_nh = &api.nexthops[nh_num];
		if (si->nh_vrf_id == VRF_UNKNOWN)
			continue;

		/*
		 * If we create a ecmp static route the
		 * last distance and tag entered wins.  Why because
		 * this cli choosen sucks
		 */
		if (si->distance) {
			SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
			api.distance = si->distance;
		}
		if (si->tag) {
			SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
			api.tag = si->tag;
		}

		api.tableid = si->table_id;

		api_nh->vrf_id = si->nh_vrf_id;
		switch (si->type) {
		case STATIC_IFNAME:
			if (si->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = si->ifindex;
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			break;
		case STATIC_IPV4_GATEWAY:
			if (!si->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate = si->addr;
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			if (si->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = si->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = si->addr;
			break;
		case STATIC_IPV6_GATEWAY:
			if (!si->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate = si->addr;
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			if (si->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = si->ifindex;
			api_nh->gate = si->addr;
			break;
		case STATIC_BLACKHOLE:
			api_nh->type = NEXTHOP_TYPE_BLACKHOLE;
			switch (si->bh_type) {
			case STATIC_BLACKHOLE_DROP:
			case STATIC_BLACKHOLE_NULL:
				api_nh->bh_type = BLACKHOLE_NULL;
				break;
			case STATIC_BLACKHOLE_REJECT:
				api_nh->bh_type = BLACKHOLE_REJECT;
			}
			break;
		}

		if (si->snh_label.num_labels) {
			int i;

			SET_FLAG(api.message, ZAPI_MESSAGE_LABEL);
			api_nh->label_num = si->snh_label.num_labels;
			for (i = 0; i < api_nh->label_num; i++)
				api_nh->labels[i] = si->snh_label.label[i];
		}
		nh_num++;
	}

	api.nexthop_num = nh_num;

	/*
	 * If we have been given an install but nothing is valid
	 * go ahead and delete the route for double plus fun
	 */
	if (!nh_num && install)
		install = false;

	zclient_route_send(install ?
			   ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}
void static_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	zclient = zclient_new_notify(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	zclient->zebra_capabilities = static_zebra_capabilities;
	zclient->zebra_connected = zebra_connected;
	zclient->interface_add = interface_add;
	zclient->interface_delete = interface_delete;
	zclient->interface_up = interface_state_up;
	zclient->interface_down = interface_state_down;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->route_notify_owner = route_notify_owner;
	zclient->nexthop_update = static_zebra_nexthop_update;
}
