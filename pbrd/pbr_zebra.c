// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 * Portions:
 *		Copyright (c) 2021 The MITRE Corporation.
 *		Copyright (c) 2023 LabN Consulting, L.L.C.
 */
#include <zebra.h>

#include "frrevent.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "pbr.h"

#include "pbr_nht.h"
#include "pbr_map.h"
#include "pbr_memory.h"
#include "pbr_zebra.h"
#include "pbr_debug.h"
#include "pbr_vrf.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_INTERFACE, "PBR Interface");

/* Zebra structure to hold current status. */
struct zclient *zclient;

struct pbr_interface *pbr_if_new(struct interface *ifp)
{
	struct pbr_interface *pbr_ifp;

	assert(ifp);
	assert(!ifp->info);

	pbr_ifp = XCALLOC(MTYPE_PBR_INTERFACE, sizeof(*pbr_ifp));

	ifp->info = pbr_ifp;
	return pbr_ifp;
}

void pbr_if_del(struct interface *ifp)
{
	XFREE(MTYPE_PBR_INTERFACE, ifp->info);
}

/* Interface addition message from zebra. */
int pbr_ifp_create(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s: %s", __func__, ifp->name);

	if (!ifp->info)
		pbr_if_new(ifp);

	pbr_nht_interface_update(ifp);
	/* Update nexthops tracked from a `set nexthop` command */
	pbr_nht_nexthop_interface_update(ifp);

	pbr_map_policy_interface_update(ifp, true);

	return 0;
}

int pbr_ifp_destroy(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s: %s", __func__, ifp->name);

	pbr_map_policy_interface_update(ifp, false);

	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	char buf[PREFIX_STRLEN];

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	DEBUGD(&pbr_dbg_zebra, "%s: %s added %s", __func__,
	       c ? c->ifp->name : "Unknown",
	       c ? prefix2str(c->address, buf, sizeof(buf)) : "Unknown");

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	DEBUGD(&pbr_dbg_zebra, "%s: %s deleted %pFX", __func__, c->ifp->name,
	       c->address);

	connected_free(&c);
	return 0;
}

int pbr_ifp_up(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s: %s is up", __func__, ifp->name);

	pbr_nht_nexthop_interface_update(ifp);

	return 0;
}

int pbr_ifp_down(struct interface *ifp)
{
	DEBUGD(&pbr_dbg_zebra, "%s: %s is down", __func__, ifp->name);

	pbr_nht_nexthop_interface_update(ifp);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note,
				      NULL, NULL))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: [%pFX] Route install failure for table: %u",
		       __func__, &p, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: [%pFX] Route better admin distance won for table: %u",
		       __func__, &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: [%pFX] Route installed succeeded for table: %u",
		       __func__, &p, table_id);
		pbr_nht_route_installed_for_table(table_id);
		break;
	case ZAPI_ROUTE_REMOVED:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: [%pFX] Route Removed succeeded for table: %u",
		       __func__, &p, table_id);
		pbr_nht_route_removed_for_table(table_id);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: [%pFX] Route remove fail for table: %u", __func__,
		       &p, table_id);
		break;
	}

	return 0;
}

static int rule_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t seqno, priority, unique;
	enum zapi_rule_notify_owner note;
	struct pbr_map_sequence *pbrms;
	struct pbr_map_interface *pmi;
	char ifname[INTERFACE_NAMSIZ + 1];
	uint64_t installed;

	if (!zapi_rule_notify_decode(zclient->ibuf, &seqno, &priority, &unique,
				     ifname, &note))
		return -1;

	pmi = NULL;
	pbrms = pbrms_lookup_unique(unique, ifname, &pmi);
	if (!pbrms) {
		DEBUGD(&pbr_dbg_zebra,
		       "%s: Failure to lookup pbrms based upon %u", __func__,
		       unique);
		return 0;
	}

	installed = 1 << pmi->install_bit;

	switch (note) {
	case ZAPI_RULE_FAIL_INSTALL:
		pbrms->installed &= ~installed;
		break;
	case ZAPI_RULE_INSTALLED:
		pbrms->installed |= installed;
		break;
	case ZAPI_RULE_FAIL_REMOVE:
		/* Don't change state on rule removal failure */
		break;
	case ZAPI_RULE_REMOVED:
		pbrms->installed &= ~installed;
		break;
	}

	DEBUGD(&pbr_dbg_zebra, "%s: Received %s: %" PRIu64, __func__,
	       zapi_rule_notify_owner2str(note), pbrms->installed);

	pbr_map_final_interface_deletion(pbrms->parent, pmi);

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	DEBUGD(&pbr_dbg_zebra, "%s: Registering for fun and profit", __func__);
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static void route_add_helper(struct zapi_route *api, struct nexthop_group nhg,
			     uint8_t install_afi)
{
	struct zapi_nexthop *api_nh;
	struct nexthop *nhop;
	int i;

	api->prefix.family = install_afi;

	DEBUGD(&pbr_dbg_zebra, "    Encoding %pFX", &api->prefix);

	i = 0;
	for (ALL_NEXTHOPS(nhg, nhop)) {
		api_nh = &api->nexthops[i];
		api_nh->vrf_id = nhop->vrf_id;
		api_nh->type = nhop->type;
		api_nh->weight = nhop->weight;
		switch (nhop->type) {
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate.ipv4 = nhop->gate.ipv4;
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6,
			       IPV6_MAX_BYTELEN);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->ifindex = nhop->ifindex;
			memcpy(&api_nh->gate.ipv6, &nhop->gate.ipv6,
			       IPV6_MAX_BYTELEN);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nhop->bh_type;
			break;
		}
		i++;
	}
	api->nexthop_num = i;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, api);
}

/*
 * This function assumes a default route is being
 * installed into the appropriate tableid
 */
void route_add(struct pbr_nexthop_group_cache *pnhgc, struct nexthop_group nhg,
	       afi_t install_afi)
{
	struct zapi_route api;

	DEBUGD(&pbr_dbg_zebra, "%s for Table: %d", __func__, pnhgc->table_id);

	memset(&api, 0, sizeof(api));

	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;
	/*
	 * Sending a default route
	 */
	api.tableid = pnhgc->table_id;
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	switch (install_afi) {
	case AFI_MAX:
		route_add_helper(&api, nhg, AF_INET);
		route_add_helper(&api, nhg, AF_INET6);
		break;
	case AFI_IP:
		route_add_helper(&api, nhg, AF_INET);
		break;
	case AFI_IP6:
		route_add_helper(&api, nhg, AF_INET6);
		break;
	case AFI_L2VPN:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: Asked to install unsupported route type: L2VPN",
		       __func__);
		break;
	case AFI_UNSPEC:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: Asked to install unspecified route type", __func__);
		break;
	}
}

/*
 * This function assumes a default route is being
 * removed from the appropriate tableid
 */
void route_delete(struct pbr_nexthop_group_cache *pnhgc, afi_t afi)
{
	struct zapi_route api;

	DEBUGD(&pbr_dbg_zebra, "%s for Table: %d", __func__, pnhgc->table_id);

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_PBR;
	api.safi = SAFI_UNICAST;

	api.tableid = pnhgc->table_id;
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);

	switch (afi) {
	case AFI_IP:
		api.prefix.family = AF_INET;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_IP6:
		api.prefix.family = AF_INET6;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_MAX:
		api.prefix.family = AF_INET;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		api.prefix.family = AF_INET6;
		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
		break;
	case AFI_L2VPN:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: Asked to delete unsupported route type: L2VPN",
		       __func__);
		break;
	case AFI_UNSPEC:
		DEBUGD(&pbr_dbg_zebra,
		       "%s: Asked to delete unspecified route type", __func__);
		break;
	}
}

static int pbr_zebra_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route nhr;
	struct prefix matched;
	uint32_t i;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &matched, &nhr)) {
		zlog_err("Failure to decode Nexthop update message");
		return 0;
	}

	if (DEBUG_MODE_CHECK(&pbr_dbg_zebra, DEBUG_MODE_ALL)) {

		DEBUGD(&pbr_dbg_zebra,
		       "%s: Received Nexthop update: %pFX against %pFX",
		       __func__, &matched, &nhr.prefix);

		DEBUGD(&pbr_dbg_zebra, "%s:   (Nexthops(%u)", __func__,
		       nhr.nexthop_num);

		for (i = 0; i < nhr.nexthop_num; i++) {
			DEBUGD(&pbr_dbg_zebra,
			       "%s:     Type: %d: vrf: %d, ifindex: %d gate: %pI4",
			       __func__, nhr.nexthops[i].type,
			       nhr.nexthops[i].vrf_id, nhr.nexthops[i].ifindex,
			       &nhr.nexthops[i].gate.ipv4);
		}
	}

	nhr.prefix = matched;
	pbr_nht_nexthop_update(&nhr);
	return 1;
}

extern struct zebra_privs_t pbr_privs;

static zclient_handler *const pbr_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_RULE_NOTIFY_OWNER] = rule_notify_owner,
	[ZEBRA_NEXTHOP_UPDATE] = pbr_zebra_nexthop_update,
};

void pbr_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	zclient = zclient_new(master, &opt, pbr_handlers,
			      array_size(pbr_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_PBR, 0, &pbr_privs);
	zclient->zebra_connected = zebra_connected;
}

void pbr_send_rnh(struct nexthop *nhop, bool reg)
{
	uint32_t command;
	struct prefix p;

	command = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	memset(&p, 0, sizeof(p));
	switch (nhop->type) {
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		p.family = AF_INET;
		p.u.prefix4.s_addr = nhop->gate.ipv4.s_addr;
		p.prefixlen = IPV4_MAX_BITLEN;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		p.family = AF_INET6;
		memcpy(&p.u.prefix6, &nhop->gate.ipv6, IPV6_MAX_BYTELEN);
		p.prefixlen = IPV6_MAX_BITLEN;
		if (IN6_IS_ADDR_LINKLOCAL(&nhop->gate.ipv6))
			/*
			 * Don't bother tracking link locals, just track their
			 * interface state.
			 */
			return;
		break;
	}

	if (zclient_send_rnh(zclient, command, &p, SAFI_UNICAST, false, false,
			     nhop->vrf_id)
	    == ZCLIENT_SEND_FAILURE) {
		zlog_warn("%s: Failure to send nexthop to zebra", __func__);
	}
}


static uint32_t pbr_map_sequence_vrf(const struct pbr_map_sequence *pbrms,
				     const struct interface *ifp)
{
	struct pbr_vrf *pbr_vrf;

	if (pbrms->vrf_unchanged)
		pbr_vrf = ifp->vrf->info;
	else
		pbr_vrf = pbr_vrf_lookup_by_name(pbrms->vrf_name);

	if (!pbr_vrf) {
		DEBUGD(&pbr_dbg_zebra, "%s: VRF not found", __func__);
		return 0;
	}

	return pbr_vrf->vrf->data.l.table_id;

}

/*
 * 230716 gpz note: it would be worthwhile for pbrd to represent
 * its rules internally using the lib/pbr.h structures to help
 * move toward a more common structure across pbrd, bgpd, and zebra.
 */
static bool pbr_encode_pbr_map_sequence(struct stream *s,
					struct pbr_map_sequence *pbrms,
					struct interface *ifp)
{

	struct pbr_rule r;
	uint8_t family;

	/*
	 * Opportunistic address family field is set when any of the IP
	 * address match/set fields is set, or when a NH/NHG is resolved.
	 * The value is needed by zebra for the underlying netlink
	 * messaging, particularly in delete operations, because it
	 * selects the rule database (IPv4 vs. IPv6).
	 *
	 * Historically the value has been encoded into any unused
	 * "match src/dst address" fields and picked off in zebra.
	 */
	family = AF_INET;
	if (pbrms->family)
		family = pbrms->family;

	if (pbrms->src)
		assert(family == pbrms->src->family);
	if (pbrms->dst)
		assert(family == pbrms->dst->family);

	/*
	 * Convert struct pbr_map_sequence to canonical form
	 */
	memset(&r, 0, sizeof(r));
	r.seq = pbrms->seqno;
	r.priority = pbrms->ruleno;
	r.unique = pbrms->unique;

	r.family = pbrms->family;

	/* filter */
	r.filter.filter_bm = pbrms->filter_bm;
	if (pbrms->src)
		r.filter.src_ip = *pbrms->src;
	else
		r.filter.src_ip.family = family;
	if (pbrms->dst)
		r.filter.dst_ip = *pbrms->dst;
	else
		r.filter.dst_ip.family = family;
	r.filter.src_port = pbrms->src_prt;
	r.filter.dst_port = pbrms->dst_prt;
	r.filter.pcp = pbrms->match_pcp;
	r.filter.vlan_id = pbrms->match_vlan_id;
	r.filter.vlan_flags = pbrms->match_vlan_flags;
	r.filter.dsfield = pbrms->dsfield;
	r.filter.fwmark = pbrms->mark;
	r.filter.ip_proto = pbrms->ip_proto;

	r.filter.filter_bm = pbrms->filter_bm;

	/* actions */

	r.action.flags = pbrms->action_bm;

	SET_FLAG(r.action.flags, PBR_ACTION_TABLE); /* always valid */

	/*
	 * if the user does not use the command "set vrf name unchanged"
	 * then pbr_encode_pbr_map_sequence_vrf will not be called
	 */
	if (pbrms->vrf_unchanged || pbrms->vrf_lookup)
		r.action.table = pbr_map_sequence_vrf(pbrms, ifp);
	else if (pbrms->nhgrp_name)
		r.action.table = pbr_nht_get_table(pbrms->nhgrp_name);
	else if (pbrms->nhg)
		r.action.table = pbr_nht_get_table(pbrms->internal_nhg_name);
	else {
		/* Not valid for install without table */
		return false;
	}

	r.action.queue_id = pbrms->action_queue_id;

	r.action.src_ip = pbrms->action_src;
	r.action.dst_ip = pbrms->action_dst;

	r.action.src_port = pbrms->action_src_port;
	r.action.dst_port = pbrms->action_dst_port;

	r.action.dscp = pbrms->action_dscp;
	r.action.ecn = pbrms->action_ecn;

	r.action.pcp = pbrms->action_pcp;
	r.action.vlan_id = pbrms->action_vlan_id;

	strlcpy(r.ifname, ifp->name, sizeof(r.ifname));

	zapi_pbr_rule_encode(s, &r);

	return true;
}

bool pbr_send_pbr_map(struct pbr_map_sequence *pbrms,
		      struct pbr_map_interface *pmi, bool install, bool changed)
{
	struct pbr_map *pbrm = pbrms->parent;
	struct stream *s;
	uint64_t is_installed = (uint64_t)1 << pmi->install_bit;

	is_installed &= pbrms->installed;

	/*
	 * If we are installed and asked to do so again and the config
	 * has not changed, just return.
	 *
	 * If we are not installed and asked
	 * to delete just return.
	 */
	if (install && is_installed && !changed)
		return false;

	if (!install && !is_installed)
		return false;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_RULE_ADD : ZEBRA_RULE_DELETE,
			      VRF_DEFAULT);

	DEBUGD(&pbr_dbg_zebra, "%s:    %s %s seq %u %d %s %u", __func__,
	       install ? "Installing" : "Deleting", pbrm->name, pbrms->seqno,
	       install, pmi->ifp->name, pmi->delete);

	if (pbr_encode_pbr_map_sequence(s, pbrms, pmi->ifp)) {
		stream_putw_at(s, 0, stream_get_endp(s));
		zclient_send_message(zclient);
	} else {
		DEBUGD(&pbr_dbg_zebra, "%s: %s seq %u encode failed, skipped",
		       __func__, pbrm->name, pbrms->seqno);
	}

	return true;
}
