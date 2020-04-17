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
#include "isisd/isis_te.h"
#include "isisd/isis_sr.h"

struct zclient *zclient;
static struct zclient *zclient_sync;

/* List of chunks of labels externally assigned by zebra. */
static struct list *label_chunk_list;
static struct listnode *current_label_chunk;

static void isis_zebra_label_manager_connect(void);

/* Router-id update message from zebra. */
static int isis_router_id_update_zebra(ZAPI_CALLBACK_ARGS)
{
	struct isis_area *area;
	struct listnode *node;
	struct prefix router_id;

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
	struct connected *c;
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	p = c->address;

	prefix2str(p, buf, sizeof(buf));
#ifdef EXTREME_DEBUG
	if (p->family == AF_INET)
		zlog_debug("connected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("connected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */
	if (if_is_operative(c->ifp))
		isis_circuit_add_addr(circuit_scan_by_ifp(c->ifp), c);

	return 0;
}

static int isis_zebra_if_address_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	struct interface *ifp;
#ifdef EXTREME_DEBUG
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	ifp = c->ifp;

#ifdef EXTREME_DEBUG
	p = c->address;
	prefix2str(p, buf, sizeof(buf));

	if (p->family == AF_INET)
		zlog_debug("disconnected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("disconnected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */

	if (if_is_operative(ifp))
		isis_circuit_del_addr(circuit_scan_by_ifp(ifp), c);
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

void isis_zebra_route_add_route(struct prefix *prefix,
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
	api.vrf_id = VRF_DEFAULT;
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
		api_nh->vrf_id = VRF_DEFAULT;

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

void isis_zebra_route_del_route(struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info)
{
	struct zapi_route api;

	if (zclient->sock < 0)
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = *prefix;
	if (src_p && src_p->prefixlen) {
		api.src_prefix = *src_p;
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
	}

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

/* Install Prefix-SID in the forwarding plane. */
void isis_zebra_install_prefix_sid(const struct sr_prefix *srp)
{
	struct zapi_labels zl;
	struct zapi_nexthop *znh;
	struct listnode *node;
	struct isis_nexthop *nexthop;
	struct interface *ifp;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->local_label;

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

/* Uninstall Prefix-SID from the forwarding plane. */
void isis_zebra_uninstall_prefix_sid(const struct sr_prefix *srp)
{
	struct zapi_labels zl;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->local_label;

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

static int isis_zebra_read(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;

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
		isis_redist_add(api.type, &api.prefix, &api.src_prefix,
				api.distance, api.metric);
	else
		isis_redist_delete(api.type, &api.prefix, &api.src_prefix);

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

/* Label Manager Requests. */
int isis_zebra_request_label_range(uint32_t base, uint32_t chunk_size)
{
	int ret;
	uint32_t start, end;

	if (zclient_sync->sock == -1)
		isis_zebra_label_manager_connect();

	ret = lm_get_label_chunk(zclient_sync, 0, base, chunk_size, &start,
				 &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label range!", __func__);
		return -1;
	}

	return 0;
}

void isis_zebra_release_label_range(uint32_t start, uint32_t end)
{
	int ret;

	if (zclient_sync->sock == -1)
		isis_zebra_label_manager_connect();

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0)
		zlog_warn("%s: error releasing label range!", __func__);
}

static int isis_zebra_get_label_chunk(void)
{
	int ret;
	uint32_t start, end;
	struct label_chunk *new_label_chunk;

	if (zclient_sync->sock == -1)
		isis_zebra_label_manager_connect();

	ret = lm_get_label_chunk(zclient_sync, 0, MPLS_LABEL_BASE_ANY,
				 CHUNK_SIZE, &start, &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label chunk!", __func__);
		return -1;
	}

	new_label_chunk = calloc(1, sizeof(struct label_chunk));
	if (!new_label_chunk) {
		zlog_warn("%s: error trying to allocate label chunk %u - %u",
			  __func__, start, end);
		return -1;
	}

	new_label_chunk->start = start;
	new_label_chunk->end = end;
	new_label_chunk->used_mask = 0;

	listnode_add(label_chunk_list, (void *)new_label_chunk);

	/* let's update current if needed */
	if (!current_label_chunk)
		current_label_chunk = listtail(label_chunk_list);

	return 0;
}

mpls_label_t isis_zebra_request_dynamic_label(void)
{
	struct label_chunk *label_chunk;
	uint32_t i, size;
	uint64_t pos;
	uint32_t label = MPLS_INVALID_LABEL;

	while (current_label_chunk) {
		label_chunk = listgetdata(current_label_chunk);
		if (!label_chunk)
			goto end;

		/* try to get next free label in currently used label chunk */
		size = label_chunk->end - label_chunk->start + 1;
		for (i = 0, pos = 1; i < size; i++, pos <<= 1) {
			if (!(pos & label_chunk->used_mask)) {
				label_chunk->used_mask |= pos;
				label = label_chunk->start + i;
				goto end;
			}
		}
		current_label_chunk = listnextnode(current_label_chunk);
	}

end:
	/*
	 * we moved till the last chunk, or were not able to find a label, so
	 * let's ask for another one.
	 */
	if (!current_label_chunk
	    || current_label_chunk == listtail(label_chunk_list)
	    || label == MPLS_INVALID_LABEL) {
		if (isis_zebra_get_label_chunk() != 0)
			zlog_warn("%s: error getting label chunk!", __func__);
	}

	return label;
}

static void isis_zebra_del_label_chunk(void *val)
{
	free(val);
}

static int isis_zebra_release_label_chunk(uint32_t start, uint32_t end)
{
	int ret;

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0) {
		zlog_warn("%s: error releasing label chunk!", __func__);
		return -1;
	}

	return 0;
}

void isis_zebra_release_dynamic_label(mpls_label_t label)
{
	struct listnode *node;
	struct label_chunk *label_chunk;
	uint64_t pos;

	for (ALL_LIST_ELEMENTS_RO(label_chunk_list, node, label_chunk)) {
		if (!(label <= label_chunk->end && label >= label_chunk->start))
			continue;

		pos = 1ULL << (label - label_chunk->start);
		label_chunk->used_mask &= ~pos;

		/*
		 * If nobody is using this chunk and it's not
		 * current_label_chunk, then free it.
		 */
		if (!label_chunk->used_mask && (current_label_chunk != node)) {
			if (isis_zebra_release_label_chunk(label_chunk->start,
							   label_chunk->end)
			    != 0)
				zlog_warn("%s: error releasing label chunk!",
					  __func__);
			else {
				listnode_delete(label_chunk_list, label_chunk);
				isis_zebra_del_label_chunk(label_chunk);
			}
		}
		break;
	}
}

static void isis_zebra_label_manager_connect(void)
{
	/* Connect to label manager. */
	while (zclient_socket_connect(zclient_sync) < 0) {
		zlog_warn("%s: error connecting synchronous zclient!",
			  __func__);
		sleep(1);
	}
	set_nonblocking(zclient_sync->sock);
	while (lm_label_manager_connect(zclient_sync, 0) != 0) {
		zlog_warn("%s: error connecting to label manager!", __func__);
		sleep(1);
	}

	label_chunk_list = list_new();
	label_chunk_list->del = isis_zebra_del_label_chunk;
	while (isis_zebra_get_label_chunk() != 0) {
		zlog_warn("%s: error getting first label chunk!", __func__);
		sleep(1);
	}
}

static void isis_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
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
	zclient_sync = zclient_new(master, &zclient_options_default);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_ISIS;
	zclient_sync->instance = instance;
	zclient_sync->privs = &isisd_privs;
}

void isis_zebra_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
	frr_fini();
}
