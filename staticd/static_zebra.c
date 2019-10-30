/*
 * Zebra connect code.
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
#include "hash.h"
#include "jhash.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"

bool debug;

/* Zebra structure to hold current status. */
struct zclient *zclient;
static struct hash *static_nht_hash;

/* Inteface addition message from zebra. */
static int static_ifp_create(struct interface *ifp)
{
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_destroy(struct interface *ifp)
{
	static_ifindex_update(ifp, false);
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int static_ifp_up(struct interface *ifp)
{
	if (if_is_vrf(ifp)) {
		struct static_vrf *svrf = static_vrf_lookup_by_id(ifp->vrf_id);

		static_fixup_vrf_ids(svrf);
		static_config_install_delayed_routes(svrf);
	}

	/* Install any static reliant on this interface coming up */
	static_install_intf_nh(ifp);
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_down(struct interface *ifp)
{
	static_ifindex_update(ifp, false);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	char buf[PREFIX_STRLEN];

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note))
		return -1;

	prefix2str(&p, buf, sizeof(buf));

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %s failed to install for table: %u",
			  __PRETTY_FUNCTION__, buf, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %s over-ridden by better route for table: %u",
			  __PRETTY_FUNCTION__, buf, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		static_nht_mark_state(&p, vrf_id, STATIC_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVED:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		static_nht_mark_state(&p, vrf_id, STATIC_INSTALLED);
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

struct static_nht_data {
	struct prefix *nh;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t nh_num;
};

/* API to check whether the configured nexthop address is
 * one of its local connected address or not.
 */
static bool
static_nexthop_is_local(vrf_id_t vrfid, struct prefix *addr, int family)
{
	if (family == AF_INET) {
		if (if_lookup_exact_address(&addr->u.prefix4,
					AF_INET,
					vrfid))
			return true;
	} else if (family == AF_INET6) {
		if (if_lookup_exact_address(&addr->u.prefix6,
					AF_INET6,
					vrfid))
			return true;
	}
	return false;
}
static int static_zebra_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct static_nht_data *nhtd, lookup;
	struct zapi_route nhr;
	afi_t afi = AFI_IP;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("Failure to decode nexthop update message");
		return 1;
	}

	if (nhr.prefix.family == AF_INET6)
		afi = AFI_IP6;

	if (nhr.type == ZEBRA_ROUTE_CONNECT) {
		if (static_nexthop_is_local(vrf_id, &nhr.prefix,
					nhr.prefix.family))
			nhr.nexthop_num = 0;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &nhr.prefix;
	lookup.nh_vrf_id = vrf_id;

	nhtd = hash_lookup(static_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr.nexthop_num;

		static_nht_reset_start(&nhr.prefix, afi, nhtd->nh_vrf_id);
		static_nht_update(NULL, &nhr.prefix, nhr.nexthop_num, afi,
				  nhtd->nh_vrf_id);
	} else
		zlog_err("No nhtd?");

	return 1;
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
}

static unsigned int static_nht_hash_key(const void *data)
{
	const struct static_nht_data *nhtd = data;
	unsigned int key = 0;

	key = prefix_hash_key(nhtd->nh);
	return jhash_1word(nhtd->nh_vrf_id, key);
}

static bool static_nht_hash_cmp(const void *d1, const void *d2)
{
	const struct static_nht_data *nhtd1 = d1;
	const struct static_nht_data *nhtd2 = d2;

	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return false;

	return prefix_same(nhtd1->nh, nhtd2->nh);
}

static void *static_nht_hash_alloc(void *data)
{
	struct static_nht_data *copy = data;
	struct static_nht_data *new;

	new = XMALLOC(MTYPE_TMP, sizeof(*new));

	new->nh = prefix_new();
	prefix_copy(new->nh, copy->nh);
	new->refcount = 0;
	new->nh_num = 0;
	new->nh_vrf_id = copy->nh_vrf_id;

	return new;
}

static void static_nht_hash_free(void *data)
{
	struct static_nht_data *nhtd = data;

	prefix_free(&nhtd->nh);
	XFREE(MTYPE_TMP, nhtd);
}

void static_zebra_nht_register(struct route_node *rn,
			       struct static_route *si, bool reg)
{
	struct static_nht_data *nhtd, lookup;
	uint32_t cmd;
	struct prefix p;
	afi_t afi = AFI_IP;

	cmd = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	if (si->nh_registered && reg)
		return;

	if (!si->nh_registered && !reg)
		return;

	memset(&p, 0, sizeof(p));
	switch (si->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		return;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = si->addr.ipv4;
		afi = AFI_IP;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = si->addr.ipv6;
		afi = AFI_IP6;
		break;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &p;
	lookup.nh_vrf_id = si->nh_vrf_id;

	si->nh_registered = reg;

	if (reg) {
		nhtd = hash_get(static_nht_hash, &lookup,
				static_nht_hash_alloc);
		nhtd->refcount++;

		if (debug)
			zlog_debug("Registered nexthop(%pFX) for %pRN %d", &p,
				   rn, nhtd->nh_num);
		if (nhtd->refcount > 1 && nhtd->nh_num) {
			static_nht_update(&rn->p, nhtd->nh, nhtd->nh_num,
					  afi, si->nh_vrf_id);
			return;
		}
	} else {
		nhtd = hash_lookup(static_nht_hash, &lookup);
		if (!nhtd)
			return;

		nhtd->refcount--;
		if (nhtd->refcount >= 1)
			return;

		hash_release(static_nht_hash, nhtd);
		static_nht_hash_free(nhtd);
	}

	if (zclient_send_rnh(zclient, cmd, &p, false, si->nh_vrf_id) < 0)
		zlog_warn("%s: Failure to send nexthop to zebra",
			  __PRETTY_FUNCTION__);
}

extern void static_zebra_route_add(struct route_node *rn,
				   struct static_route *si_changed,
				   vrf_id_t vrf_id, safi_t safi, bool install)
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
	SET_FLAG(api.flags, ZEBRA_FLAG_RR_USE_DISTANCE);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	if (si_changed->distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = si_changed->distance;
	}
	if (si_changed->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = si_changed->tag;
	}
	if (si_changed->table_id != 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = si_changed->table_id;
	}
	for (/*loaded above*/; si; si = si->next) {
		api_nh = &api.nexthops[nh_num];
		if (si->nh_vrf_id == VRF_UNKNOWN)
			continue;

		if (si->distance != si_changed->distance)
			continue;

		if (si->table_id != si_changed->table_id)
			continue;

		api_nh->vrf_id = si->nh_vrf_id;
		api_nh->onlink = si->onlink;

		si->state = STATIC_SENT_TO_ZEBRA;

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

	if_zapi_callbacks(static_ifp_create, static_ifp_up,
			  static_ifp_down, static_ifp_destroy);

	zclient = zclient_new(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	zclient->zebra_capabilities = static_zebra_capabilities;
	zclient->zebra_connected = zebra_connected;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->route_notify_owner = route_notify_owner;
	zclient->nexthop_update = static_zebra_nexthop_update;

	static_nht_hash = hash_create(static_nht_hash_key,
				      static_nht_hash_cmp,
				      "Static Nexthop Tracking hash");
}

void static_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_reg_requests(zclient, vrf->vrf_id);
}

void static_zebra_vrf_unregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_dereg_requests(zclient, vrf->vrf_id);
}
