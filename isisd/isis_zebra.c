// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_zebra.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
 */

#include <zebra.h>

#include "frrevent.h"
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
#include "bfd.h"
#include "link_state.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
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

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

#ifdef EXTREME_DEBUG
	if (c->address->family == AF_INET)
		zlog_debug("connected IP address %pFX", c->address);
	if (c->address->family == AF_INET6)
		zlog_debug("connected IPv6 address %pFX", c->address);
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

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

#ifdef EXTREME_DEBUG
	if (c->address->family == AF_INET)
		zlog_debug("disconnected IP address %pFX", c->address);
	if (c->address->family == AF_INET6)
		zlog_debug("disconnected IPv6 address %pFX", c->address);
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
	bool changed = false;

	ifp = zebra_interface_link_params_read(zclient->ibuf, vrf_id, &changed);

	if (ifp == NULL || !changed)
		return 0;

	/* Update TE TLV */
	isis_mpls_te_update(ifp);

	return 0;
}

enum isis_zebra_nexthop_type {
	ISIS_NEXTHOP_MAIN = 0,
	ISIS_NEXTHOP_BACKUP,
};

static int isis_zebra_add_nexthops(struct isis *isis, struct list *nexthops,
				   struct zapi_nexthop zapi_nexthops[],
				   enum isis_zebra_nexthop_type type,
				   bool mpls_lsp, uint8_t backup_nhs)
{
	struct isis_nexthop *nexthop;
	struct listnode *node;
	int count = 0;

	/* Nexthops */
	for (ALL_LIST_ELEMENTS_RO(nexthops, node, nexthop)) {
		struct zapi_nexthop *api_nh;

		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &zapi_nexthops[count];
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

		/* Add MPLS label(s). */
		if (nexthop->label_stack) {
			api_nh->label_num = nexthop->label_stack->num_labels;
			memcpy(api_nh->labels, nexthop->label_stack->label,
			       sizeof(mpls_label_t) * api_nh->label_num);
		} else if (nexthop->sr.present) {
			api_nh->label_num = 1;
			api_nh->labels[0] = nexthop->sr.label;
		} else if (mpls_lsp) {
			switch (type) {
			case ISIS_NEXTHOP_MAIN:
				/*
				 * Do not use non-SR enabled nexthops to prevent
				 * broken LSPs from being formed.
				 */
				continue;
			case ISIS_NEXTHOP_BACKUP:
				/*
				 * This is necessary because zebra requires
				 * the nexthops of MPLS LSPs to be labeled.
				 */
				api_nh->label_num = 1;
				api_nh->labels[0] = MPLS_LABEL_IMPLICIT_NULL;
				break;
			}
		}

		/* Backup nexthop handling. */
		if (backup_nhs) {
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP);
			/*
			 * If the backup has multiple nexthops, all of them
			 * protect the same primary nexthop since ECMP routes
			 * have no backups.
			 */
			api_nh->backup_num = backup_nhs;
			for (int i = 0; i < backup_nhs; i++)
				api_nh->backup_idx[i] = i;
		}
		count++;
	}

	return count;
}

void isis_zebra_route_add_route(struct isis *isis, struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info)
{
	struct zapi_route api;
	int count = 0;

	if (zclient->sock < 0)
		return;

	/* Uninstall the route if it doesn't have any valid nexthop. */
	if (list_isempty(route_info->nexthops)) {
		isis_zebra_route_del_route(isis, prefix, src_p, route_info);
		return;
	}

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

	/* Add backup nexthops first. */
	if (route_info->backup) {
		count = isis_zebra_add_nexthops(
			isis, route_info->backup->nexthops, api.backup_nexthops,
			ISIS_NEXTHOP_BACKUP, false, 0);
		if (count > 0) {
			SET_FLAG(api.message, ZAPI_MESSAGE_BACKUP_NEXTHOPS);
			api.backup_nexthop_num = count;
		}
	}

	/* Add primary nexthops. */
	count = isis_zebra_add_nexthops(isis, route_info->nexthops,
					api.nexthops, ISIS_NEXTHOP_MAIN, false,
					count);
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
 * Install Prefix-SID label entry in the forwarding plane through Zebra.
 *
 * @param area		IS-IS area
 * @param prefix	Route prefix
 * @param rinfo		Route information
 * @param psid		Prefix-SID information
 */
void isis_zebra_prefix_sid_install(struct isis_area *area,
				   struct prefix *prefix,
				   struct isis_sr_psid_info *psid)
{
	struct zapi_labels zl;
	int count = 0;

	sr_debug("ISIS-Sr (%s): update label %u for prefix %pFX algorithm %u",
		 area->area_tag, psid->label, prefix, psid->algorithm);

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = psid->label;

	/* Local routes don't have any nexthop and require special handling. */
	if (list_isempty(psid->nexthops)) {
		struct zapi_nexthop *znh;
		struct interface *ifp;

		ifp = if_lookup_by_name("lo", VRF_DEFAULT);
		if (!ifp) {
			zlog_warn(
				"%s: couldn't install Prefix-SID %pFX: loopback interface not found",
				__func__, prefix);
			return;
		}

		znh = &zl.nexthops[zl.nexthop_num++];
		znh->type = NEXTHOP_TYPE_IFINDEX;
		znh->ifindex = ifp->ifindex;
		znh->label_num = 1;
		znh->labels[0] = MPLS_LABEL_IMPLICIT_NULL;
	} else {
		/* Add backup nexthops first. */
		if (psid->nexthops_backup) {
			count = isis_zebra_add_nexthops(
				area->isis, psid->nexthops_backup,
				zl.backup_nexthops, ISIS_NEXTHOP_BACKUP, true,
				0);
			if (count > 0) {
				SET_FLAG(zl.message, ZAPI_LABELS_HAS_BACKUPS);
				zl.backup_nexthop_num = count;
			}
		}

		/* Add primary nexthops. */
		count = isis_zebra_add_nexthops(area->isis, psid->nexthops,
						zl.nexthops, ISIS_NEXTHOP_MAIN,
						true, count);
		if (!count)
			return;
		zl.nexthop_num = count;
	}

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
}

/**
 * Uninstall Prefix-SID label entry from the forwarding plane through Zebra.
 *
 * @param area		IS-IS area
 * @param prefix	Route prefix
 * @param rinfo		Route information
 * @param psid		Prefix-SID information
 */
void isis_zebra_prefix_sid_uninstall(struct isis_area *area,
				     struct prefix *prefix,
				     struct isis_route_info *rinfo,
				     struct isis_sr_psid_info *psid)
{
	struct zapi_labels zl;

	sr_debug("ISIS-Sr (%s): delete label %u for prefix %pFX algorithm %u",
		 area->area_tag, psid->label, prefix, psid->algorithm);

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = psid->label;

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE, &zl);
}

/**
 * Send (LAN)-Adjacency-SID to ZEBRA for installation or deletion.
 *
 * @param cmd	ZEBRA_MPLS_LABELS_ADD or ZEBRA_ROUTE_DELETE
 * @param sra	Segment Routing Adjacency-SID
 */
void isis_zebra_send_adjacency_sid(int cmd, const struct sr_adjacency *sra)
{
	struct isis *isis = sra->adj->circuit->area->isis;
	struct zapi_labels zl;
	struct zapi_nexthop *znh;

	if (cmd != ZEBRA_MPLS_LABELS_ADD && cmd != ZEBRA_MPLS_LABELS_DELETE) {
		flog_warn(EC_LIB_DEVELOPMENT, "%s: wrong ZEBRA command",
			  __func__);
		return;
	}

	sr_debug("  |- %s label %u for interface %s",
		 cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
		 sra->input_label, sra->adj->circuit->interface->name);

	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = sra->input_label;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	znh->gate = sra->nexthop.address;
	znh->type = (sra->nexthop.family == AF_INET)
			    ? NEXTHOP_TYPE_IPV4_IFINDEX
			    : NEXTHOP_TYPE_IPV6_IFINDEX;
	znh->ifindex = sra->adj->circuit->interface->ifindex;
	znh->label_num = 1;
	znh->labels[0] = MPLS_LABEL_IMPLICIT_NULL;

	/* Set backup nexthops. */
	if (sra->type == ISIS_SR_LAN_BACKUP) {
		int count;

		count = isis_zebra_add_nexthops(isis, sra->backup_nexthops,
						zl.backup_nexthops,
						ISIS_NEXTHOP_BACKUP, true, 0);
		if (count > 0) {
			SET_FLAG(zl.message, ZAPI_LABELS_HAS_BACKUPS);
			zl.backup_nexthop_num = count;

			SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP);
			znh->backup_num = count;
			for (int i = 0; i < count; i++)
				znh->backup_idx[i] = i;
		}
	}

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
				api.distance, api.metric, api.tag);
	else
		isis_redist_delete(isis, api.type, &api.prefix,
				   &api.src_prefix);

	return 0;
}

int isis_distribute_list_update(int routetype)
{
	return 0;
}

void isis_zebra_redistribute_set(afi_t afi, int type, vrf_id_t vrf_id)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
					     zclient, afi, vrf_id);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				     0, vrf_id);
}

void isis_zebra_redistribute_unset(afi_t afi, int type, vrf_id_t vrf_id)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
					     zclient, afi, vrf_id);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
				     type, 0, vrf_id);
}

/**
 * Register RLFA with LDP.
 */
int isis_zebra_rlfa_register(struct isis_spftree *spftree, struct rlfa *rlfa)
{
	struct isis_area *area = spftree->area;
	struct zapi_rlfa_request zr = {};
	int ret;

	if (!zclient)
		return 0;

	zr.igp.vrf_id = area->isis->vrf_id;
	zr.igp.protocol = ZEBRA_ROUTE_ISIS;
	strlcpy(zr.igp.isis.area_tag, area->area_tag,
		sizeof(zr.igp.isis.area_tag));
	zr.igp.isis.spf.tree_id = spftree->tree_id;
	zr.igp.isis.spf.level = spftree->level;
	zr.igp.isis.spf.run_id = spftree->runcount;
	zr.destination = rlfa->prefix;
	zr.pq_address = rlfa->pq_address;

	zlog_debug("ISIS-LFA: registering RLFA %pFX@%pI4 with LDP",
		   &rlfa->prefix, &rlfa->pq_address);

	ret = zclient_send_opaque_unicast(zclient, LDP_RLFA_REGISTER,
					  ZEBRA_ROUTE_LDP, 0, 0,
					  (const uint8_t *)&zr, sizeof(zr));
	if (ret == ZCLIENT_SEND_FAILURE) {
		zlog_warn("ISIS-LFA: failed to register RLFA with LDP");
		return -1;
	}

	return 0;
}

/**
 * Unregister all RLFAs from the given SPF tree with LDP.
 */
void isis_zebra_rlfa_unregister_all(struct isis_spftree *spftree)
{
	struct isis_area *area = spftree->area;
	struct zapi_rlfa_igp igp = {};
	int ret;

	if (!zclient || spftree->type != SPF_TYPE_FORWARD
	    || CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES))
		return;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: unregistering all RLFAs with LDP");

	igp.vrf_id = area->isis->vrf_id;
	igp.protocol = ZEBRA_ROUTE_ISIS;
	strlcpy(igp.isis.area_tag, area->area_tag, sizeof(igp.isis.area_tag));
	igp.isis.spf.tree_id = spftree->tree_id;
	igp.isis.spf.level = spftree->level;
	igp.isis.spf.run_id = spftree->runcount;

	ret = zclient_send_opaque_unicast(zclient, LDP_RLFA_UNREGISTER_ALL,
					  ZEBRA_ROUTE_LDP, 0, 0,
					  (const uint8_t *)&igp, sizeof(igp));
	if (ret == ZCLIENT_SEND_FAILURE)
		zlog_warn("ISIS-LFA: failed to unregister RLFA with LDP");
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
	if (zclient_send_hello(zclient_sync) == ZCLIENT_SEND_FAILURE) {
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

void isis_zebra_vrf_deregister(struct isis *isis)
{
	if (!zclient || zclient->sock < 0 || !isis)
		return;

	if (isis->vrf_id != VRF_UNKNOWN) {
		if (IS_DEBUG_EVENTS)
			zlog_debug("%s: Deregister VRF %s id %u", __func__,
				   isis->name, isis->vrf_id);
		zclient_send_dereg_requests(zclient, isis->vrf_id);
	}
}

static void isis_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zclient_register_opaque(zclient, LDP_RLFA_LABELS);
	zclient_register_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE);
	zclient_register_opaque(zclient, LDP_IGP_SYNC_ANNOUNCE_UPDATE);
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);
}

/**
 * Register / unregister Link State ZAPI Opaque Message
 *
 * @param up	True to register, false to unregister
 *
 * @return	0 if success, -1 otherwise
 */
int isis_zebra_ls_register(bool up)
{
	int rc;

	if (up)
		rc = ls_register(zclient, true);
	else
		rc = ls_unregister(zclient, true);

	return rc;
}

/*
 * opaque messages between processes
 */
static int isis_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_msg info;
	struct zapi_opaque_reg_info dst;
	struct ldp_igp_sync_if_state state;
	struct ldp_igp_sync_announce announce;
	struct zapi_rlfa_response rlfa;
	int ret = 0;

	s = zclient->ibuf;
	if (zclient_opaque_decode(s, &info) != 0)
		return -1;

	switch (info.type) {
	case LINK_STATE_SYNC:
		STREAM_GETC(s, dst.proto);
		STREAM_GETW(s, dst.instance);
		STREAM_GETL(s, dst.session_id);
		dst.type = LINK_STATE_SYNC;
		ret = isis_te_sync_ted(dst);
		break;
	case LDP_IGP_SYNC_IF_STATE_UPDATE:
		STREAM_GET(&state, s, sizeof(state));
		ret = isis_ldp_sync_state_update(state);
		break;
	case LDP_IGP_SYNC_ANNOUNCE_UPDATE:
		STREAM_GET(&announce, s, sizeof(announce));
		ret = isis_ldp_sync_announce_update(announce);
		break;
	case LDP_RLFA_LABELS:
		STREAM_GET(&rlfa, s, sizeof(rlfa));
		isis_rlfa_process_ldp_response(&rlfa);
		break;
	default:
		break;
	}

stream_failure:

	return ret;
}

static int isis_zebra_client_close_notify(ZAPI_CALLBACK_ARGS)
{
	int ret = 0;

	struct zapi_client_close_info info;

	if (zapi_client_close_notify_decode(zclient->ibuf, &info) < 0)
		return -1;

	isis_ldp_sync_handle_client_close(&info);
	isis_ldp_rlfa_handle_client_close(&info);

	return ret;
}

static zclient_handler *const isis_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = isis_router_id_update_zebra,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = isis_zebra_if_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = isis_zebra_if_address_del,
	[ZEBRA_INTERFACE_LINK_PARAMS] = isis_zebra_link_params,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = isis_zebra_read,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = isis_zebra_read,

	[ZEBRA_OPAQUE_MESSAGE] = isis_opaque_msg_handler,

	[ZEBRA_CLIENT_CLOSE_NOTIFY] = isis_zebra_client_close_notify,
};

void isis_zebra_init(struct event_loop *master, int instance)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default, isis_handlers,
			      array_size(isis_handlers));
	zclient_init(zclient, PROTO_TYPE, 0, &isisd_privs);
	zclient->zebra_connected = isis_zebra_connected;

	/* Initialize special zclient for synchronous message exchanges. */
	struct zclient_options options = zclient_options_default;
	options.synchronous = true;
	zclient_sync = zclient_new(master, &options, NULL, 0);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_ISIS;
	zclient_sync->instance = instance;
	/*
	 * session_id must be different from default value (0) to distinguish
	 * the asynchronous socket from the synchronous one
	 */
	zclient_sync->session_id = 1;
	zclient_sync->privs = &isisd_privs;
}

void isis_zebra_stop(void)
{
	zclient_unregister_opaque(zclient, LDP_RLFA_LABELS);
	zclient_unregister_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE);
	zclient_unregister_opaque(zclient, LDP_IGP_SYNC_ANNOUNCE_UPDATE);
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
	zclient_stop(zclient);
	zclient_free(zclient);
	frr_fini();
}
