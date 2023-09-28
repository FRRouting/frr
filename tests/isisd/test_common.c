// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_mt.h"

#include "test_common.h"

struct event_loop *master;
struct zebra_privs_t isisd_privs;

int isis_sock_init(struct isis_circuit *circuit)
{
	return 0;
}

const struct isis_test_node *
test_topology_find_node(const struct isis_topology *topology,
			const char *hostname, uint8_t pseudonode_id)
{
	for (size_t i = 0; topology->nodes[i].hostname[0]; i++)
		if (strmatch(hostname, topology->nodes[i].hostname)
		    && pseudonode_id == topology->nodes[i].pseudonode_id)
			return &topology->nodes[i];

	return NULL;
}

const struct isis_topology *
test_topology_find(struct isis_topology *test_topologies, uint16_t number)
{
	for (size_t i = 0; test_topologies[i].number; i++)
		if (test_topologies[i].number == number)
			return &test_topologies[i];

	return NULL;
}

static const struct isis_test_node *
test_find_adjacency(const struct isis_test_node *tnode, const char *hostname)
{
	for (size_t i = 0; tnode->adjacencies[i].hostname[0]; i++) {
		const struct isis_test_adj *tadj;

		tadj = &tnode->adjacencies[i];
		if (strmatch(hostname, tadj->hostname))
			return tnode;
	}

	return NULL;
}

mpls_label_t test_topology_node_ldp_label(const struct isis_topology *topology,
					  struct in_addr router_id)
{
	for (size_t i = 0; topology->nodes[i].hostname[0]; i++) {
		const struct isis_test_node *tnode = &topology->nodes[i];
		struct in_addr node_router_id;

		if (!tnode->router_id)
			continue;

		(void)inet_pton(AF_INET, tnode->router_id, &node_router_id);
		if (IPV4_ADDR_SAME(&router_id, &node_router_id))
			return (50000 + (i + 1) * 100);
	}

	return MPLS_INVALID_LABEL;
}

static struct isis_lsp *lsp_add(struct lspdb_head *lspdb,
				struct isis_area *area, int level,
				const uint8_t *sysid, uint8_t pseudonode_id)
{
	struct isis_lsp *lsp;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];

	memcpy(lspid, sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lspid) = pseudonode_id;
	LSP_FRAGMENT(lspid) = 0;

	lsp = lsp_new(area, lspid, 6000, 1, 0, 0, NULL, level);
	lsp->tlvs = isis_alloc_tlvs();
	lspdb_add(lspdb, lsp);

	return lsp;
}

static void lsp_add_ip_reach(struct isis_lsp *lsp,
			     const struct isis_test_node *tnode,
			     const char *prefix_str, uint32_t *next_sid_index)
{
	struct prefix prefix;
	struct sr_prefix_cfg pcfg = {};
	struct sr_prefix_cfg *pcfg_p[SR_ALGORITHM_COUNT] = {NULL};

	if (str2prefix(prefix_str, &prefix) != 1) {
		zlog_debug("%s: invalid network: %s", __func__, prefix_str);
		return;
	}

	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR)) {
		pcfg_p[SR_ALGORITHM_SPF] = &pcfg;

		pcfg.sid = *next_sid_index;
		*next_sid_index = *next_sid_index + 1;
		pcfg.sid_type = SR_SID_VALUE_TYPE_INDEX;
		pcfg.node_sid = true;
		pcfg.last_hop_behavior = SR_LAST_HOP_BEHAVIOR_PHP;
	}

	if (prefix.family == AF_INET)
		isis_tlvs_add_extended_ip_reach(lsp->tlvs,
						(struct prefix_ipv4 *)&prefix,
						10, false, pcfg_p);
	else
		isis_tlvs_add_ipv6_reach(lsp->tlvs, ISIS_MT_IPV6_UNICAST,
					 (struct prefix_ipv6 *)&prefix, 10,
					 false, pcfg_p);
}

static void lsp_add_reach(struct isis_lsp *lsp,
			  const struct isis_test_node *tnode,
			  const uint8_t *ne_id, uint8_t pseudonode_id,
			  uint32_t metric, int family, mpls_label_t *next_label)
{
	uint8_t nodeid[ISIS_SYS_ID_LEN + 1];
	uint16_t mtid;
	struct isis_ext_subtlvs *ext = NULL;

	memcpy(nodeid, ne_id, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(nodeid) = pseudonode_id;

	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR)) {
		struct isis_adj_sid *adj_sid;

		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->family = family;
		SET_FLAG(adj_sid->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG);
		SET_FLAG(adj_sid->flags, EXT_SUBTLV_LINK_ADJ_SID_LFLG);
		if (family == AF_INET6)
			SET_FLAG(adj_sid->flags, EXT_SUBTLV_LINK_ADJ_SID_FFLG);
		adj_sid->weight = 0;
		adj_sid->sid = *next_label;
		*next_label = *next_label + 1;

		ext = isis_alloc_ext_subtlvs();
		isis_tlvs_add_adj_sid(ext, adj_sid);
	}

	mtid = (family == AF_INET) ? ISIS_MT_IPV4_UNICAST
				   : ISIS_MT_IPV6_UNICAST;

	isis_tlvs_add_extended_reach(lsp->tlvs, mtid, nodeid, metric, ext);
}

static void lsp_add_router_capability(struct isis_lsp *lsp,
				      const struct isis_test_node *tnode)
{
	struct isis_router_cap *cap;

	if (!tnode->router_id)
		return;

	cap = isis_tlvs_init_router_capability(lsp->tlvs);

	if (inet_pton(AF_INET, tnode->router_id, &cap->router_id) != 1) {
		zlog_debug("%s: invalid router-id: %s", __func__,
			   tnode->router_id);
		return;
	}

	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR)) {
		cap->srgb.flags =
			ISIS_SUBTLV_SRGB_FLAG_I | ISIS_SUBTLV_SRGB_FLAG_V;
		cap->srgb.lower_bound = tnode->srgb.lower_bound
						? tnode->srgb.lower_bound
						: SRGB_DFTL_LOWER_BOUND;
		cap->srgb.range_size = tnode->srgb.range_size
					       ? tnode->srgb.range_size
					       : SRGB_DFTL_RANGE_SIZE;
		cap->algo[0] = SR_ALGORITHM_SPF;
		cap->algo[1] = SR_ALGORITHM_UNSET;
	}

}

static void lsp_add_mt_router_info(struct isis_lsp *lsp,
				   const struct isis_test_node *tnode)
{
	if (tnode->protocols.ipv4)
		isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV4_UNICAST, 0,
					     false);
	if (tnode->protocols.ipv6)
		isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV6_UNICAST, 0,
					     false);
}

static void lsp_add_protocols_supported(struct isis_lsp *lsp,
					const struct isis_test_node *tnode)
{
	struct nlpids nlpids = {};

	if (!tnode->protocols.ipv4 && !tnode->protocols.ipv6)
		return;

	if (tnode->protocols.ipv4) {
		nlpids.nlpids[nlpids.count] = NLPID_IP;
		nlpids.count++;
	}
	if (tnode->protocols.ipv6) {
		nlpids.nlpids[nlpids.count] = NLPID_IPV6;
		nlpids.count++;
	}
	isis_tlvs_set_protocols_supported(lsp->tlvs, &nlpids);
}

static int topology_load_node_level(const struct isis_topology *topology,
				    const struct isis_test_node *tnode,
				    size_t tnode_index, struct isis_area *area,
				    struct lspdb_head *lspdb, int level)
{
	struct isis_lsp *lsp;
	uint32_t next_sid_index = (tnode_index + 1) * 10;
	mpls_label_t next_label = 16;

	lsp = lsp_add(lspdb, area, level, tnode->sysid, tnode->pseudonode_id);
	lsp_add_mt_router_info(lsp, tnode);
	lsp_add_protocols_supported(lsp, tnode);
	lsp_add_router_capability(lsp, tnode);

	/* Add IP Reachability Information. */
	for (size_t i = 0; tnode->networks[i]; i++) {
		if (i > MAX_NETWORKS) {
			zlog_debug(
				"%s: node has too many networks (maximum is %u)",
				__func__, MAX_NETWORKS);
			return -1;
		}
		lsp_add_ip_reach(lsp, tnode, tnode->networks[i],
				 &next_sid_index);
	}

	/* Add IS Reachability Information. */
	for (size_t i = 0; tnode->adjacencies[i].hostname[0]; i++) {
		const struct isis_test_adj *tadj;
		const struct isis_test_node *tadj_node;

		if (i > MAX_ADJACENCIES) {
			zlog_debug(
				"%s: node has too many adjacencies (maximum is %u)",
				__func__, MAX_ADJACENCIES);
			return -1;
		}

		tadj = &tnode->adjacencies[i];
		tadj_node = test_topology_find_node(topology, tadj->hostname,
						    tadj->pseudonode_id);
		if (!tadj_node) {
			zlog_debug(
				"%s: node \"%s\" has an adjacency with non-existing node \"%s\"",
				__func__, tnode->hostname, tadj->hostname);
			return -1;
		}
		if (!test_find_adjacency(tadj_node, tnode->hostname)) {
			zlog_debug(
				"%s: node \"%s\" has an one-way adjacency with node \"%s\"",
				__func__, tnode->hostname, tadj->hostname);
			return -1;
		}

		if (tnode->pseudonode_id || tadj_node->pseudonode_id
		    || (tnode->protocols.ipv4 && tadj_node->protocols.ipv4))
			lsp_add_reach(lsp, tnode, tadj_node->sysid,
				      tadj_node->pseudonode_id, tadj->metric,
				      AF_INET, &next_label);
		if (tadj_node->pseudonode_id
		    || (tnode->protocols.ipv6 && tadj_node->protocols.ipv6))
			lsp_add_reach(lsp, tnode, tadj_node->sysid,
				      tadj_node->pseudonode_id, tadj->metric,
				      AF_INET6, &next_label);
	}

	return 0;
}

static int topology_load_node(const struct isis_topology *topology,
			      const struct isis_test_node *tnode,
			      size_t tnode_index, struct isis_area *area,
			      struct lspdb_head lspdb[])
{
	int ret;

	isis_dynhn_insert(area->isis, tnode->sysid, tnode->hostname,
			  tnode->level);

	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
		if ((tnode->level & level) == 0)
			continue;

		ret = topology_load_node_level(topology, tnode, tnode_index,
					       area, &lspdb[level - 1], level);
		if (ret != 0)
			return ret;
	}

	return 0;
}

int test_topology_load(const struct isis_topology *topology,
		       struct isis_area *area, struct lspdb_head lspdb[])
{
	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++)
		lsp_db_init(&lspdb[level - 1]);

	for (size_t i = 0; topology->nodes[i].hostname[0]; i++) {
		const struct isis_test_node *tnode = &topology->nodes[i];
		int ret;

		if (i > MAX_NODES) {
			zlog_debug(
				"%s: topology has too many nodes (maximum is %u)",
				__func__, MAX_NODES);
			return -1;
		}

		ret = topology_load_node(topology, tnode, i, area, lspdb);
		if (ret != 0)
			return ret;
	}

	return 0;
}
