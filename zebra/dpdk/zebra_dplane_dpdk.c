// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 */

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include "lib/libfrr.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"
#include "zebra/zebra_pbr.h"

#include "zebra/dpdk/zebra_dplane_dpdk_private.h"

static const char *plugin_name = "zebra_dplane_dpdk";

static struct zd_dpdk_ctx dpdk_ctx_buf, *dpdk_ctx = &dpdk_ctx_buf;
#define dpdk_stat (&dpdk_ctx->stats)

static struct zd_dpdk_port *zd_dpdk_port_find_by_index(int ifindex);

DEFINE_MTYPE_STATIC(ZEBRA, DPDK_PORTS, "ZD DPDK port database");

void zd_dpdk_stat_show(struct vty *vty)
{
	uint32_t tmp_cnt;

	vty_out(vty, "%30s\n%30s\n", "Dataplane DPDK counters",
		"=======================");

#define ZD_DPDK_SHOW_COUNTER(label, counter)                                   \
	do {                                                                   \
		tmp_cnt =                                                      \
			atomic_load_explicit(&counter, memory_order_relaxed);  \
		vty_out(vty, "%28s: %u\n", (label), (tmp_cnt));                \
	} while (0)

	ZD_DPDK_SHOW_COUNTER("PBR rule adds", dpdk_stat->rule_adds);
	ZD_DPDK_SHOW_COUNTER("PBR rule dels", dpdk_stat->rule_dels);
	ZD_DPDK_SHOW_COUNTER("Ignored updates", dpdk_stat->ignored_updates);
}


static void zd_dpdk_flow_stat_show(struct vty *vty, int in_ifindex,
				   intptr_t dp_flow_ptr)
{
	struct rte_flow_action_count count = { .id = 0 };
	const struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_COUNT,
			.conf = &count,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	int rc;
	struct zd_dpdk_port *in_dport;
	struct rte_flow_query_count query;
	struct rte_flow_error error;
	uint64_t hits, bytes;

	in_dport = zd_dpdk_port_find_by_index(in_ifindex);
	if (!in_dport) {
		vty_out(vty, "PBR dpdk flow query failed; in_port %d missing\n",
			in_ifindex);
		return;
	}
	memset(&query, 0, sizeof(query));
	rc = rte_flow_query(in_dport->port_id, (struct rte_flow *)dp_flow_ptr,
			    actions, &query, &error);
	if (rc) {
		vty_out(vty,
			"PBR dpdk flow query failed; in_ifindex %d rc %d\n",
			in_ifindex, error.type);
		return;
	}
	hits = (query.hits_set) ? query.hits : 0;
	bytes = (query.bytes_set) ? query.bytes : 0;
	vty_out(vty, "  DPDK stats: packets %" PRIu64 " bytes %" PRIu64 "\n",
		hits, bytes);
}


static int zd_dpdk_pbr_show_rules_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_rule *rule = (struct zebra_pbr_rule *)bucket->data;
	struct vty *vty = (struct vty *)arg;
	struct vrf *vrf;
	struct interface *ifp = NULL;
	struct zebra_pbr_action *zaction = &rule->action;

	zebra_pbr_show_rule_unit(rule, vty);
	if (zaction->dp_flow_ptr) {
		vrf = vrf_lookup_by_id(rule->vrf_id);
		if (vrf)
			ifp = if_lookup_by_name_vrf(rule->ifname, vrf);

		if (ifp)
			zd_dpdk_flow_stat_show(vty, ifp->ifindex, zaction->dp_flow_ptr);
	}
	return HASHWALK_CONTINUE;
}


void zd_dpdk_pbr_flows_show(struct vty *vty)
{
	hash_walk(zrouter.rules_hash, zd_dpdk_pbr_show_rules_walkcb, vty);
}


static void zd_dpdk_rule_add(struct zebra_dplane_ctx *ctx)
{
	static struct rte_flow_attr attrs = {.ingress = 1, .transfer = 1};
	uint32_t filter_bm = dplane_ctx_rule_get_filter_bm(ctx);
	int in_ifindex = dplane_ctx_get_ifindex(ctx);
	int out_ifindex = dplane_ctx_rule_get_out_ifindex(ctx);
	struct rte_flow_item_eth eth, eth_mask;
	struct rte_flow_item_ipv4 ip, ip_mask;
	struct rte_flow_item_udp udp, udp_mask;
	struct rte_flow_action_count conf_count;
	struct rte_flow_action_set_mac conf_smac, conf_dmac;
	struct rte_flow_action_port_id conf_port;
	struct rte_flow_item items[ZD_PBR_PATTERN_MAX];
	struct rte_flow_action actions[ZD_PBR_ACTION_MAX];
	int item_cnt = 0;
	int act_cnt = 0;
	struct in_addr tmp_mask;
	const struct ethaddr *mac;
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct zd_dpdk_port *in_dport;
	struct zd_dpdk_port *out_dport;
	uint32_t pri = dplane_ctx_rule_get_priority(ctx);
	int seq = dplane_ctx_rule_get_seq(ctx);
	int unique = dplane_ctx_rule_get_unique(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug(
			"PBR dpdk flow create ifname %s seq %d pri %u unique %d\n",
			dplane_ctx_rule_get_ifname(ctx), seq, pri, unique);
	in_dport = zd_dpdk_port_find_by_index(in_ifindex);
	if (!in_dport) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
			zlog_debug(
				"PBR dpdk flow create ifname %s seq %d pri %u unique %d failed; in_port %d missing\n",
				dplane_ctx_rule_get_ifname(ctx), seq, pri, unique, in_ifindex);
		return;
	}

	out_dport = zd_dpdk_port_find_by_index(out_ifindex);
	if (!out_dport) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
			zlog_debug(
				"PBR dpdk flow create ifname %s seq %d pri %u unique %d failed; out_port %d missing\n",
				dplane_ctx_rule_get_ifname(ctx), seq, pri, unique, out_ifindex);
		return;
	}

	/*********************** match items **************************/
	memset(&eth, 0, sizeof(eth));
	memset(&eth_mask, 0, sizeof(eth_mask));
	eth.type = eth_mask.type = htons(RTE_ETHER_TYPE_IPV4);
	items[item_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[item_cnt].spec = &eth;
	items[item_cnt].mask = &eth_mask;
	items[item_cnt].last = NULL;
	++item_cnt;

	memset(&ip, 0, sizeof(ip));
	memset(&ip_mask, 0, sizeof(ip_mask));
	if (CHECK_FLAG(filter_bm, PBR_FILTER_SRC_IP)) {
		const struct prefix *src_ip;

		src_ip = dplane_ctx_rule_get_src_ip(ctx);
		ip.hdr.src_addr = src_ip->u.prefix4.s_addr;
		masklen2ip(src_ip->prefixlen, &tmp_mask);
		ip_mask.hdr.src_addr = tmp_mask.s_addr;
	}
	if (CHECK_FLAG(filter_bm, PBR_FILTER_DST_IP)) {
		const struct prefix *dst_ip;

		dst_ip = dplane_ctx_rule_get_dst_ip(ctx);
		ip.hdr.dst_addr = dst_ip->u.prefix4.s_addr;
		masklen2ip(dst_ip->prefixlen, &tmp_mask);
		ip_mask.hdr.dst_addr = tmp_mask.s_addr;
	}
	if (CHECK_FLAG(filter_bm, PBR_FILTER_IP_PROTOCOL)) {
		ip.hdr.next_proto_id = dplane_ctx_rule_get_ipproto(ctx);
		ip_mask.hdr.next_proto_id = UINT8_MAX;
	}
	items[item_cnt].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[item_cnt].spec = &ip;
	items[item_cnt].mask = &ip_mask;
	items[item_cnt].last = NULL;
	++item_cnt;

	if (CHECK_FLAG(filter_bm, (PBR_FILTER_SRC_PORT | PBR_FILTER_DST_PORT))) {
		memset(&udp, 0, sizeof(udp));
		memset(&udp_mask, 0, sizeof(udp_mask));
		if (CHECK_FLAG(filter_bm, PBR_FILTER_SRC_PORT)) {
			udp.hdr.src_port = RTE_BE16(dplane_ctx_rule_get_src_port(ctx));
			udp_mask.hdr.src_port = UINT16_MAX;
		}
		if (CHECK_FLAG(filter_bm, PBR_FILTER_DST_PORT)) {
			udp.hdr.dst_port = RTE_BE16(dplane_ctx_rule_get_dst_port(ctx));
			udp_mask.hdr.dst_port = UINT16_MAX;
		}
		items[item_cnt].type = RTE_FLOW_ITEM_TYPE_UDP;
		items[item_cnt].spec = &udp;
		items[item_cnt].mask = &udp_mask;
		items[item_cnt].last = NULL;
		++item_cnt;
	}

	items[item_cnt].type = RTE_FLOW_ITEM_TYPE_END;

	/*************************** actions *****************************/
	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_COUNT;
	memset(&conf_count, 0, sizeof(conf_count));
	actions[act_cnt].conf = &conf_count;
	++act_cnt;

	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_DEC_TTL;
	++act_cnt;

	mac = dplane_ctx_rule_get_smac(ctx);
	memcpy(conf_smac.mac_addr, mac, RTE_ETHER_ADDR_LEN);
	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
	actions[act_cnt].conf = &conf_smac;
	++act_cnt;

	mac = dplane_ctx_rule_get_dmac(ctx);
	memcpy(conf_dmac.mac_addr, mac, RTE_ETHER_ADDR_LEN);
	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
	actions[act_cnt].conf = &conf_dmac;
	++act_cnt;

	memset(&conf_port, 0, sizeof(conf_port));
	conf_port.id = out_dport->port_id;
	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	actions[act_cnt].conf = &conf_port;
	++act_cnt;

	actions[act_cnt].type = RTE_FLOW_ACTION_TYPE_END;

	frr_with_privs (&zserv_privs) {
		flow = rte_flow_create(in_dport->port_id, &attrs, items,
				       actions, &error);
	}

	if (flow) {
		dplane_ctx_rule_set_dp_flow_ptr(ctx, (intptr_t)flow);
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
			zlog_debug(
				"PBR dpdk flow 0x%" PRIxPTR
				" created ifname %s seq %d pri %u unique %d\n",
				(intptr_t)flow, dplane_ctx_rule_get_ifname(ctx),
				seq, pri, unique);
	} else {
		zlog_warn(
			"PBR dpdk flow create failed ifname %s seq %d pri %u unique %d; rc %d\n",
			dplane_ctx_rule_get_ifname(ctx), seq, pri, unique, error.type);
	}
}


static void zd_dpdk_rule_del(struct zebra_dplane_ctx *ctx, const char *ifname,
			     int in_ifindex, intptr_t dp_flow_ptr)
{
	struct zd_dpdk_port *in_dport;
	struct rte_flow_error error;
	int rc;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug(
			"PBR dpdk flow delete ifname %s ifindex %d dp_flow 0x%" PRIxPTR
			"\n",
			ifname, in_ifindex, dp_flow_ptr);

	if (!dp_flow_ptr) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
			zlog_debug(
				"PBR dpdk flow delete failed; ifname %s ifindex %d dp_flow 0x%" PRIxPTR
				"; empty dp\n",
				ifname, in_ifindex, dp_flow_ptr);
		return;
	}

	dplane_ctx_rule_set_dp_flow_ptr(ctx, (intptr_t)NULL);
	in_dport = zd_dpdk_port_find_by_index(in_ifindex);
	if (!in_dport) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
			zlog_debug(
				"PBR dpdk flow delete failed; ifname %s ifindex %d dp_flow 0x%" PRIxPTR
				" in port missing\n",
				ifname, in_ifindex, dp_flow_ptr);
		return;
	}

	frr_with_privs (&zserv_privs) {
		rc = rte_flow_destroy(in_dport->port_id,
				      (struct rte_flow *)dp_flow_ptr, &error);
	}

	if (rc)
		zlog_warn(
			"PBR dpdk flow delete failed; ifname %s ifindex %d dp_flow 0x%" PRIxPTR
			"\n",
			ifname, in_ifindex, dp_flow_ptr);
}


static void zd_dpdk_rule_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	int in_ifindex;
	intptr_t dp_flow_ptr;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug("Dplane %s", dplane_op2str(dplane_ctx_get_op(ctx)));


	op = dplane_ctx_get_op(ctx);
	switch (op) {
	case DPLANE_OP_RULE_ADD:
		atomic_fetch_add_explicit(&dpdk_stat->rule_adds, 1,
					  memory_order_relaxed);
		zd_dpdk_rule_add(ctx);
		break;

	case DPLANE_OP_RULE_UPDATE:
		/* delete old rule and install new one */
		atomic_fetch_add_explicit(&dpdk_stat->rule_adds, 1,
					  memory_order_relaxed);
		in_ifindex = dplane_ctx_get_ifindex(ctx);
		dp_flow_ptr = dplane_ctx_rule_get_old_dp_flow_ptr(ctx);
		zd_dpdk_rule_del(ctx, dplane_ctx_rule_get_ifname(ctx),
				 in_ifindex, dp_flow_ptr);
		zd_dpdk_rule_add(ctx);
		break;

	case DPLANE_OP_RULE_DELETE:
		atomic_fetch_add_explicit(&dpdk_stat->rule_dels, 1,
					  memory_order_relaxed);
		in_ifindex = dplane_ctx_get_ifindex(ctx);
		dp_flow_ptr = dplane_ctx_rule_get_dp_flow_ptr(ctx);
		zd_dpdk_rule_del(ctx, dplane_ctx_rule_get_ifname(ctx),
				 in_ifindex, dp_flow_ptr);
		break;

	case DPLANE_OP_NONE:
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_PIC_CONTEXT_INSTALL:
	case DPLANE_OP_PIC_CONTEXT_UPDATE:
	case DPLANE_OP_PIC_CONTEXT_DELETE:
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_VLAN_INSTALL,
		break;
	}
}


/* DPDK provider callback.
 */
static void zd_dpdk_process_update(struct zebra_dplane_ctx *ctx)
{
	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_RULE_DELETE:
		zd_dpdk_rule_update(ctx);
		break;
	case DPLANE_OP_NONE:
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_PIC_CONTEXT_INSTALL:
	case DPLANE_OP_PIC_CONTEXT_UPDATE:
	case DPLANE_OP_PIC_CONTEXT_DELETE:
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_VLAN_INSTALL,
		atomic_fetch_add_explicit(&dpdk_stat->ignored_updates, 1,
					  memory_order_relaxed);

		break;
	}
}


static int zd_dpdk_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	int counter, limit;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug("processing %s", dplane_provider_get_name(prov));

	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		zd_dpdk_process_update(ctx);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static void zd_dpdk_port_show_entry(struct zd_dpdk_port *dport, struct vty *vty,
				    int detail)
{
	struct rte_eth_dev_info *dev_info;

	dev_info = &dport->dev_info;
	if (detail) {
		vty_out(vty, "DPDK port: %u\n", dport->port_id);
		vty_out(vty, " Device: %s\n",
			dev_info->device ? rte_dev_name(dev_info->device) : "-");
		vty_out(vty, " Driver: %s\n",
			dev_info->driver_name ? rte_driver_name(rte_dev_driver(
							dev_info->device))
					      : "-");
		vty_out(vty, " Interface: %s (%d)\n",
			ifindex2ifname(dev_info->if_index, VRF_DEFAULT),
			dev_info->if_index);
		vty_out(vty, " Switch: %s Domain: %u Port: %u\n",
			dev_info->switch_info.name,
			dev_info->switch_info.domain_id,
			dev_info->switch_info.port_id);
		vty_out(vty, "\n");
	} else {
		vty_out(vty, "%-4u %-16s %-16s %-16d %s,%u,%u\n", dport->port_id,
			dev_info->device ? rte_dev_name(dev_info->device) : "-",
			ifindex2ifname(dev_info->if_index, VRF_DEFAULT),
			dev_info->if_index, dev_info->switch_info.name,
			dev_info->switch_info.domain_id,
			dev_info->switch_info.port_id);
	}
}


static struct zd_dpdk_port *zd_dpdk_port_find_by_index(int ifindex)
{
	int count;
	struct zd_dpdk_port *dport;
	struct rte_eth_dev_info *dev_info;

	for (count = 0; count < RTE_MAX_ETHPORTS; ++count) {
		dport = &dpdk_ctx->dpdk_ports[count];
		if (!(dport->flags & ZD_DPDK_PORT_FLAG_INITED))
			continue;
		dev_info = &dport->dev_info;
		if (dev_info->if_index == (uint32_t)ifindex)
			return dport;
	}

	return NULL;
}


void zd_dpdk_port_show(struct vty *vty, uint16_t port_id, bool uj, int detail)
{
	int count;
	struct zd_dpdk_port *dport;

	/* XXX - support for json is yet to be added */
	if (uj)
		return;

	if (!detail) {
		vty_out(vty, "%-4s %-16s %-16s %-16s %s\n", "Port", "Device",
			"IfName", "IfIndex", "sw,domain,port");
	}

	for (count = 0; count < RTE_MAX_ETHPORTS; ++count) {
		dport = &dpdk_ctx->dpdk_ports[count];
		if (CHECK_FLAG(dport->flags, ZD_DPDK_PORT_FLAG_INITED))
			zd_dpdk_port_show_entry(dport, vty, detail);
	}
}


static void zd_dpdk_port_init(void)
{
	struct zd_dpdk_port *dport;
	uint16_t port_id;
	struct rte_eth_dev_info *dev_info;
	int count;
	int rc;
	struct rte_flow_error error;

	/* allocate a list of ports */
	dpdk_ctx->dpdk_ports =
		XCALLOC(MTYPE_DPDK_PORTS,
			sizeof(struct zd_dpdk_port) * RTE_MAX_ETHPORTS);

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("dpdk port init");
	count = 0;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("dpdk port init %d", port_id);
		dport = &dpdk_ctx->dpdk_ports[count];
		count++;
		dport->port_id = port_id;
		SET_FLAG(dport->flags, ZD_DPDK_PORT_FLAG_PROBED);
		dev_info = &dport->dev_info;
		if (rte_eth_dev_info_get(port_id, dev_info) < 0) {
			zlog_warn("failed to get dev info for %u, %s", port_id,
				  rte_strerror(rte_errno));
			continue;
		}
		SET_FLAG(dport->flags, ZD_DPDK_PORT_FLAG_INITED);
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("port %u, dev %s, ifI %d, sw_name %s, sw_domain %u, sw_port %u",
				   port_id,
				   dev_info->device
					   ? rte_dev_name(dev_info->device)
					   : "-",
				   dev_info->if_index,
				   dev_info->switch_info.name,
				   dev_info->switch_info.domain_id,
				   dev_info->switch_info.port_id);
		if (rte_flow_isolate(port_id, 1, &error)) {
			if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
				zlog_debug(
					"Flow isolate on port %u failed %d", port_id, error.type);
		} else {
			if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
				zlog_debug("Flow isolate on port %u", port_id);
		}
		rc = rte_eth_dev_start(port_id);
		if (rc) {
			zlog_warn("DPDK port %d start error: %s", port_id,
				  rte_strerror(-rc));
			continue;
		}
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("DPDK port %d started in promiscuous mode ", port_id);
	}

	if (!count) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("no probed ethernet devices");
	}
}


static int zd_dpdk_init(void)
{
	int rc;
	static const char *argv[] = {(char *)"/usr/lib/frr/zebra", (char *)"--"};

	zd_dpdk_vty_init();

	frr_with_privs (&zserv_privs) {
		rc = rte_eal_init(array_size(argv), (char **)argv);
	}
	if (rc < 0) {
		zlog_warn("EAL init failed %s", rte_strerror(rte_errno));
		return -1;
	}

	frr_with_privs (&zserv_privs) {
		zd_dpdk_port_init();
	}
	return 0;
}


static int zd_dpdk_start(struct zebra_dplane_provider *prov)
{
	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s start", dplane_provider_get_name(prov));

	return zd_dpdk_init();
}


static int zd_dpdk_finish(struct zebra_dplane_provider *prov, bool early)
{
	int rc;

	if (early) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("%s early finish", dplane_provider_get_name(prov));

		return 0;
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s finish", dplane_provider_get_name(prov));


	frr_with_privs (&zserv_privs) {
		rc = rte_eal_cleanup();
	}
	if (rc < 0)
		zlog_warn("EAL cleanup failed %s", rte_strerror(rte_errno));

	return 0;
}


static int zd_dpdk_plugin_init(struct event_loop *tm)
{
	int ret;

	ret = dplane_provider_register(
		plugin_name, DPLANE_PRIO_KERNEL, DPLANE_PROV_FLAGS_DEFAULT,
		zd_dpdk_start, zd_dpdk_process, zd_dpdk_finish, dpdk_ctx, NULL);

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s register status %d", plugin_name, ret);

	return 0;
}


static int zd_dpdk_module_init(void)
{
	hook_register(frr_late_init, zd_dpdk_plugin_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "dplane_dpdk", .version = "0.0.1",
		 .description = "Data plane plugin using dpdk for hw offload",
		 .init = zd_dpdk_module_init);
