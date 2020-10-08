/*
 * IS-IS Rout(e)ing protocol - isis_zebra.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
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
#include "memory.h"
#include "log.h"
#include "lib_errors.h"
#include "if.h"
#include "network.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"
#include "libfrr.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_te.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_ldp_sync.h"

struct zclient *zclient;
static struct zclient *zclient_sync;

/* Router-id update message from zebra. */
static int isis_router_id_update_zebra(ZAPI_CALLBACK_ARGS)
{
	struct isis_area *area;
	struct listnode *node;
	struct prefix router_id;
	struct isis *isis = NULL;

	isis = isis_lookup_by_vrfid(vrf_id);

	if (isis == NULL) {
		return -1;
	}

	zebra_router_id_update_read(zclient->ibuf, &router_id);
	if (isis->router_id == router_id.u.prefix4.s_addr)
		return 0;

	isis->router_id = router_id.u.prefix4.s_addr;
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if (listcount(area->area_addrs) > 0)
			lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

static int isis_zebra_if_address_add(ZAPI_CALLBACK_ARGS)
{
	struct isis_circuit *circuit;
	struct connected *c;
#ifdef EXTREME_DEBUG
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

#ifdef EXTREME_DEBUG
	p = c->address;
	prefix2str(p, buf, sizeof(buf));

	if (p->family == AF_INET)
		zlog_debug("connected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("connected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */

	if (if_is_operative(c->ifp)) {
		circuit = circuit_scan_by_ifp(c->ifp);
		if (circuit)
			isis_circuit_add_addr(circuit, c);
	}

	return 0;
}

static int isis_zebra_if_address_del(ZAPI_CALLBACK_ARGS)
{
	struct isis_circuit *circuit;
	struct connected *c;
#ifdef EXTREME_DEBUG
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

#ifdef EXTREME_DEBUG
	p = c->address;
	prefix2str(p, buf, sizeof(buf));

	if (p->family == AF_INET)
		zlog_debug("disconnected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("disconnected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */

	if (if_is_operative(c->ifp)) {
		circuit = circuit_scan_by_ifp(c->ifp);
		if (circuit)
			isis_circuit_del_addr(circuit, c);
	}

	connected_free(&c);

	return 0;
}

static int isis_zebra_link_params(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;

	ifp = zebra_interface_link_params_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	/* Update TE TLV */
	isis_mpls_te_update(ifp);

	return 0;
}

void isis_zebra_route_add_route(struct isis *isis,
				struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct isis_nexthop *nexthop;
	struct listnode *node;
	int count = 0;

	if (zclient->sock < 0)
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = isis->vrf_id;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = *prefix;
	if (src_p && src_p->prefixlen) {
		api.src_prefix = *src_p;
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
	}
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = route_info->cost;
#if 0
	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	api.distance = route_info->depth;
#endif

	/* Nexthops */
	for (ALL_LIST_ELEMENTS_RO(route_info->nexthops, node, nexthop)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		if (fabricd)
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		api_nh->vrf_id = isis->vrf_id;

		switch (nexthop->family) {
		case AF_INET:
			/* FIXME: can it be ? */
			if (nexthop->ip.ipv4.s_addr != INADDR_ANY) {
				api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				api_nh->gate.ipv4 = nexthop->ip.ipv4;
			} else {
				api_nh->type = NEXTHOP_TYPE_IFINDEX;
			}
			break;
		case AF_INET6:
			if (!IN6_IS_ADDR_LINKLOCAL(&nexthop->ip.ipv6)
			    && !IN6_IS_ADDR_UNSPECIFIED(&nexthop->ip.ipv6)) {
				continue;
			}
			api_nh->gate.ipv6 = nexthop->ip.ipv6;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address family [%d]", __func__,
				 nexthop->family);
			exit(1);
		}

		api_nh->ifindex = nexthop->ifindex;
		count++;
	}
	if (!count)
		return;

	api.nexthop_num = count;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void isis_zebra_route_del_route(struct isis *isis,
				struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info)
{
	struct zapi_route api;

	if (zclient->sock < 0)
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = isis->vrf_id;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = *prefix;
	if (src_p && src_p->prefixlen) {
		api.src_prefix = *src_p;
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
	}

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

/**
 * Install Prefix-SID in the forwarding plane through Zebra.
 *
 * @param srp	Segment Routing Prefix-SID
 */
static void isis_zebra_prefix_install_prefix_sid(const struct sr_prefix *srp)
{
	struct zapi_labels zl;
	struct zapi_nexthop *znh;
	struct listnode *node;
	struct isis_nexthop *nexthop;
	struct interface *ifp;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->input_label;

	switch (srp->type) {
	case ISIS_SR_PREFIX_LOCAL:
		ifp = if_lookup_by_name("lo", VRF_DEFAULT);
		if (!ifp) {
			zlog_warn(
				"%s: couldn't install Prefix-SID %pFX: loopback interface not found",
				__func__, &srp->prefix);
			return;
		}

		znh = &zl.nexthops[zl.nexthop_num++];
		znh->type = NEXTHOP_TYPE_IFINDEX;
		znh->ifindex = ifp->ifindex;
		znh->label_num = 1;
		znh->labels[0] = MPLS_LABEL_IMPLICIT_NULL;
		break;
	case ISIS_SR_PREFIX_REMOTE:
		/* Update route in the RIB too. */
		SET_FLAG(zl.message, ZAPI_LABELS_FTN);
		zl.route.prefix = srp->prefix;
		zl.route.type = ZEBRA_ROUTE_ISIS;
		zl.route.instance = 0;

		for (ALL_LIST_ELEMENTS_RO(srp->u.remote.rinfo->nexthops, node,
					  nexthop)) {
			if (nexthop->sr.label == MPLS_INVALID_LABEL)
				continue;

			if (zl.nexthop_num >= MULTIPATH_NUM)
				break;

			znh = &zl.nexthops[zl.nexthop_num++];
			znh->type = (srp->prefix.family == AF_INET)
					    ? NEXTHOP_TYPE_IPV4_IFINDEX
					    : NEXTHOP_TYPE_IPV6_IFINDEX;
			znh->gate = nexthop->ip;
			znh->ifindex = nexthop->ifindex;
			znh->label_num = 1;
			znh->labels[0] = nexthop->sr.label;
		}
		break;
	}

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
}

/**
 * Uninstall Prefix-SID from the forwarding plane through Zebra.
 *
 * @param srp	Segment Routing Prefix-SID
 */
static void isis_zebra_uninstall_prefix_sid(const struct sr_prefix *srp)
{
	struct zapi_labels zl;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->input_label;

	if (srp->type == ISIS_SR_PREFIX_REMOTE) {
		/* Update route in the RIB too. */
		SET_FLAG(zl.message, ZAPI_LABELS_FTN);
		zl.route.prefix = srp->prefix;
		zl.route.type = ZEBRA_ROUTE_ISIS;
		zl.route.instance = 0;
	}

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE, &zl);
}

/**
 * Send Prefix-SID to ZEBRA for installation or deletion.
 *
 * @param cmd	ZEBRA_MPLS_LABELS_REPLACE or ZEBRA_ROUTE_DELETE
 * @param srp	Segment Routing Prefix-SID
 */
void isis_zebra_send_prefix_sid(int cmd, const struct sr_prefix *srp)
{

	if (cmd != ZEBRA_MPLS_LABELS_REPLACE
	    && cmd != ZEBRA_MPLS_LABELS_DELETE) {
		flog_warn(EC_LIB_DEVELOPMENT, "%s: wrong ZEBRA command",
			  __func__);
		return;
	}

	sr_debug("  |- %s label %u for prefix %pFX",
		 cmd == ZEBRA_MPLS_LABELS_REPLACE ? "Update" : "Delete",
		 srp->input_label, &srp->prefix);

	if (cmd == ZEBRA_MPLS_LABELS_REPLACE)
		isis_zebra_prefix_install_prefix_sid(srp);
	else
		isis_zebra_uninstall_prefix_sid(srp);
}

/**
 * Send (LAN)-Adjacency-SID to ZEBRA for installation or deletion.
 *
 * @param cmd	ZEBRA_MPLS_LABELS_ADD or ZEBRA_ROUTE_DELETE
 * @param sra	Segment Routing Adjacency-SID
 */
void isis_zebra_send_adjacency_sid(int cmd, const struct sr_adjacency *sra)
{
	struct zapi_labels zl;
	struct zapi_nexthop *znh;

	if (cmd != ZEBRA_MPLS_LABELS_ADD && cmd != ZEBRA_MPLS_LABELS_DELETE) {
		flog_warn(EC_LIB_DEVELOPMENT, "%s: wrong ZEBRA command",
			  __func__);
		return;
	}

	sr_debug("  |- %s label %u for interface %s",
		 cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
		 sra->nexthop.label, sra->adj->circuit->interface->name);

	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = sra->nexthop.label;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	znh->gate = sra->nexthop.address;
	znh->type = (sra->nexthop.family == AF_INET)
			    ? NEXTHOP_TYPE_IPV4_IFINDEX
			    : NEXTHOP_TYPE_IPV6_IFINDEX;
	znh->ifindex = sra->adj->circuit->interface->ifindex;
	znh->label_num = 1;
	znh->labels[0] = MPLS_LABEL_IMPLICIT_NULL;

	(void)zebra_send_mpls_labels(zclient, cmd, &zl);
}

static int isis_zebra_read(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;
	struct isis *isis = NULL;

	isis = isis_lookup_by_vrfid(vrf_id);

	if (isis == NULL)
		return -1;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	if (api.prefix.family == AF_INET6
	    && IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;

	/*
	 * Avoid advertising a false default reachability. (A default
	 * route installed by IS-IS gets redistributed from zebra back
	 * into IS-IS causing us to start advertising default reachabity
	 * without this check)
	 */
	if (api.prefix.prefixlen == 0
	    && api.src_prefix.prefixlen == 0
	    && api.type == PROTO_TYPE) {
		cmd = ZEBRA_REDISTRIBUTE_ROUTE_DEL;
	}

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		isis_redist_add(isis, api.type, &api.prefix, &api.src_prefix,
				api.distance, api.metric);
	else
		isis_redist_delete(isis, api.type, &api.prefix,
				   &api.src_prefix);

	return 0;
}

int isis_distribute_list_update(int routetype)
{
	return 0;
}

void isis_zebra_redistribute_set(afi_t afi, int type)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
					     zclient, afi, VRF_DEFAULT);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				     0, VRF_DEFAULT);
}

void isis_zebra_redistribute_unset(afi_t afi, int type)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
					     zclient, afi, VRF_DEFAULT);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
				     type, 0, VRF_DEFAULT);
}

/* Label Manager Functions */

/**
 * Check if Label Manager is Ready or not.
 *
 * @return	True if Label Manager is ready, False otherwise
 */
bool isis_zebra_label_manager_ready(void)
{
	return (zclient_sync->sock > 0);
}

/**
 * Request Label Range to the Label Manager.
 *
 * @param base		base label of the label range to request
 * @param chunk_size	size of the label range to request
 *
 * @return 	0 on success, -1 on failure
 */
int isis_zebra_request_label_range(uint32_t base, uint32_t chunk_size)
{
	int ret;
	uint32_t start, end;

	if (zclient_sync->sock < 0)
		return -1;

	ret = lm_get_label_chunk(zclient_sync, 0, base, chunk_size, &start,
				 &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label range!", __func__);
		return -1;
	}

	return 0;
}

/**
 * Release Label Range to the Label Manager.
 *
 * @param start		start of label range to release
 * @param end		end of label range to release
 *
 * @return		0 on success, -1 otherwise
 */
int isis_zebra_release_label_range(uint32_t start, uint32_t end)
{
	int ret;

	if (zclient_sync->sock < 0)
		return -1;

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0) {
		zlog_warn("%s: error releasing label range!", __func__);
		return -1;
	}

	return 0;
}

/**
 * Connect to the Label Manager.
 *
 * @return	0 on success, -1 otherwise
 */
int isis_zebra_label_manager_connect(void)
{
	/* Connect to label manager. */
	if (zclient_socket_connect(zclient_sync) < 0) {
		zlog_warn("%s: failed connecting synchronous zclient!",
			  __func__);
		return -1;
	}
	/* make socket non-blocking */
	set_nonblocking(zclient_sync->sock);

	/* Send hello to notify zebra this is a synchronous client */
	if (zclient_send_hello(zclient_sync) < 0) {
		zlog_warn("%s: failed sending hello for synchronous zclient!",
			  __func__);
		close(zclient_sync->sock);
		zclient_sync->sock = -1;
		return -1;
	}

	/* Connect to label manager */
	if (lm_label_manager_connect(zclient_sync, 0) != 0) {
		zlog_warn("%s: failed connecting to label manager!", __func__);
		if (zclient_sync->sock > 0) {
			close(zclient_sync->sock);
			zclient_sync->sock = -1;
		}
		return -1;
	}

	sr_debug("ISIS-Sr: Successfully connected to the Label Manager");

	return 0;
}

void isis_zebra_vrf_register(struct isis *isis)
{
	if (!zclient || zclient->sock < 0 || !isis)
		return;

	if (isis->vrf_id != VRF_UNKNOWN) {
		if (IS_DEBUG_EVENTS)
			zlog_debug("%s: Register VRF %s id %u", __func__,
				   isis->name, isis->vrf_id);
		zclient_send_reg_requests(zclient, isis->vrf_id);
	}
}


static void isis_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

/*
 * opaque messages between processes
 */
static int isis_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_msg info;
	struct ldp_igp_sync_if_state state;
	struct ldp_igp_sync_announce announce;
	struct ldp_igp_sync_hello hello;
	int ret = 0;

	s = zclient->ibuf;
	if (zclient_opaque_decode(s, &info) != 0)
		return -1;

	switch (info.type) {
	case LDP_IGP_SYNC_IF_STATE_UPDATE:
		STREAM_GET(&state, s, sizeof(state));
		ret = isis_ldp_sync_state_update(state);
		break;
	case LDP_IGP_SYNC_ANNOUNCE_UPDATE:
		STREAM_GET(&announce, s, sizeof(announce));
		ret = isis_ldp_sync_announce_update(announce);
		break;
	case LDP_IGP_SYNC_HELLO_UPDATE:
		STREAM_GET(&hello, s, sizeof(hello));
		ret = isis_ldp_sync_hello_update(hello);
		break;
	default:
		break;
	}

stream_failure:

	return ret;
}

void isis_zebra_init(struct thread_master *master, int instance)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, PROTO_TYPE, 0, &isisd_privs);
	zclient->zebra_connected = isis_zebra_connected;
	zclient->router_id_update = isis_router_id_update_zebra;
	zclient->interface_address_add = isis_zebra_if_address_add;
	zclient->interface_address_delete = isis_zebra_if_address_del;
	zclient->interface_link_params = isis_zebra_link_params;
	zclient->redistribute_route_add = isis_zebra_read;
	zclient->redistribute_route_del = isis_zebra_read;

	/* Initialize special zclient for synchronous message exchanges. */
	struct zclient_options options = zclient_options_default;
	options.synchronous = true;
	zclient_sync = zclient_new(master, &options);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_ISIS;
	zclient_sync->instance = instance;
	/*
	 * session_id must be different from default value (0) to distinguish
	 * the asynchronous socket from the synchronous one
	 */
	zclient_sync->session_id = 1;
	zclient_sync->privs = &isisd_privs;

	zclient->opaque_msg_handler = isis_opaque_msg_handler;
}

void isis_zebra_stop(void)
{
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
	zclient_stop(zclient);
	zclient_free(zclient);
	frr_fini();
}
