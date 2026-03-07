// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_srv6.h"
#include "isisd/isis_tlvs.h"

#include "test_common.h"

struct event_loop *master;
struct zebra_privs_t isisd_privs;

int isis_sock_init(struct isis_circuit *circuit)
{
	return 0;
}

const struct isis_test_node *test_topology_find_node(const struct isis_topology *topology,
						     const char *hostname, uint8_t pseudonode_id)
{
	for (size_t i = 0; topology->nodes[i].hostname[0]; i++)
		if (strmatch(hostname, topology->nodes[i].hostname) &&
		    pseudonode_id == topology->nodes[i].pseudonode_id)
			return &topology->nodes[i];

	return NULL;
}

const struct isis_topology *test_topology_find(struct isis_topology *topologies, uint16_t number)
{
	for (size_t i = 0; topologies[i].number; i++)
		if (topologies[i].number == number)
			return &topologies[i];

	return NULL;
}

static const struct isis_test_node *test_find_adjacency(const struct isis_test_node *tnode,
							const char *hostname)
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

static struct isis_lsp *lsp_add(struct lspdb_head *lspdb, struct isis_area *area, int level,
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

static void lsp_add_ip_reach(struct isis_lsp *lsp, const struct isis_test_node *tnode,
			     const char *prefix_str, uint32_t *next_sid_index)
{
	struct prefix prefix;
	struct sr_prefix_cfg pcfg = {};
	struct sr_prefix_cfg *pcfg_p[SR_ALGORITHM_COUNT] = { NULL };

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
		isis_tlvs_add_extended_ip_reach(lsp->tlvs, (struct prefix_ipv4 *)&prefix, 10,
						false, pcfg_p);
	else
		isis_tlvs_add_ipv6_reach(lsp->tlvs, ISIS_MT_IPV6_UNICAST,
					 (struct prefix_ipv6 *)&prefix, 10, false, pcfg_p);
}

static void lsp_add_reach(struct isis_lsp *lsp, const struct isis_test_node *tnode,
			  const struct isis_test_adj *tadj, const uint8_t *ne_id,
			  uint8_t pseudonode_id, uint32_t metric, int family,
			  mpls_label_t *next_label, struct in6_addr *next_srv6_sid)
{
	uint8_t nodeid[ISIS_SYS_ID_LEN + 1];
	uint16_t mtid;
	struct isis_ext_subtlvs *ext = NULL;

	memcpy(nodeid, ne_id, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(nodeid) = pseudonode_id;

	/* Allocate extended subtlvs if we have SR, SRv6, or SRLG */
	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR) ||
	    CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SRV6) || (tadj && tadj->srlg_count > 0)) {
		ext = isis_alloc_ext_subtlvs();
	}

	/* Add SR-MPLS Adj-SID */
	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR) && ext) {
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

		isis_tlvs_add_adj_sid(ext, adj_sid);
	}

	/* Add SRv6 End.X SID (only for IPv6 family) */
	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SRV6) && ext && family == AF_INET6 &&
	    next_srv6_sid) {
		struct isis_srv6_endx_sid_subtlv *endx_sid;

		endx_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*endx_sid));
		SET_FLAG(endx_sid->flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG);
		SET_FLAG(endx_sid->flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG);
		endx_sid->behavior = SRV6_ENDPOINT_BEHAVIOR_END_X;
		endx_sid->sid = *next_srv6_sid;
		/* Increment the SID function part */
		next_srv6_sid->s6_addr[15]++;

		isis_tlvs_add_srv6_endx_sid(ext, endx_sid);
	}

	/* Add SRLG sub-TLV if present */
	if (tadj && tadj->srlg_count > 0 && ext) {
		for (int i = 0; i < tadj->srlg_count && i < MAX_SRLGS; i++)
			ext->srlgs[i] = tadj->srlgs[i];
		ext->srlg_num = tadj->srlg_count;
		SET_SUBTLV(ext, EXT_SRLG);
	}

	mtid = (family == AF_INET) ? ISIS_MT_IPV4_UNICAST : ISIS_MT_IPV6_UNICAST;

	isis_tlvs_add_extended_reach(lsp->tlvs, mtid, nodeid, metric, ext);
	isis_del_ext_subtlvs(ext);
}

static void lsp_add_router_capability(struct isis_lsp *lsp, const struct isis_test_node *tnode)
{
	struct isis_router_cap *cap;

	if (!tnode->router_id)
		return;

	cap = isis_tlvs_init_router_capability(lsp->tlvs);

	if (inet_pton(AF_INET, tnode->router_id, &cap->router_id) != 1) {
		zlog_debug("%s: invalid router-id: %s", __func__, tnode->router_id);
		return;
	}

	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SR)) {
		cap->srgb.flags = ISIS_SUBTLV_SRGB_FLAG_I | ISIS_SUBTLV_SRGB_FLAG_V;
		cap->srgb.lower_bound = tnode->srgb.lower_bound ? tnode->srgb.lower_bound
								: SRGB_DFTL_LOWER_BOUND;
		cap->srgb.range_size = tnode->srgb.range_size ? tnode->srgb.range_size
							      : SRGB_DFTL_RANGE_SIZE;
		cap->algo[0] = SR_ALGORITHM_SPF;
		cap->algo[1] = SR_ALGORITHM_UNSET;
	}

	/* Add SRv6 capability */
	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SRV6)) {
		cap->srv6_cap.is_srv6_capable = true;
		cap->algo[0] = SR_ALGORITHM_SPF;
		cap->algo[1] = SR_ALGORITHM_UNSET;
	}
}

static void lsp_add_srv6_locator_with_algo(struct isis_lsp *lsp, const char *locator_str,
					   const char *end_sid_str, uint8_t algorithm)
{
	struct isis_srv6_locator *loc;
	struct isis_srv6_sid *sid;
	struct prefix_ipv6 locator_prefix;

	if (!locator_str || !end_sid_str)
		return;

	/* Parse locator prefix */
	if (str2prefix_ipv6(locator_str, &locator_prefix) != 1) {
		zlog_debug("%s: invalid SRv6 locator: %s", __func__, locator_str);
		return;
	}

	/* Create SRv6 locator (use MTYPE_TMP for test purposes) */
	loc = XCALLOC(MTYPE_TMP, sizeof(*loc));
	loc->prefix = locator_prefix;
	loc->metric = 1;
	loc->algorithm = algorithm;
	isis_srv6_sid_list_init(&loc->srv6_sid);

	/* Create End SID */
	sid = XCALLOC(MTYPE_TMP, sizeof(*sid));
	if (inet_pton(AF_INET6, end_sid_str, &sid->sid) != 1) {
		zlog_debug("%s: invalid SRv6 End SID: %s", __func__, end_sid_str);
		XFREE(MTYPE_TMP, sid);
		isis_srv6_sid_list_fini(&loc->srv6_sid);
		XFREE(MTYPE_TMP, loc);
		return;
	}
	sid->behavior = SRV6_ENDPOINT_BEHAVIOR_END;
	sid->structure.loc_block_len = 32;
	sid->structure.loc_node_len = 16;
	sid->structure.func_len = 16;
	sid->structure.arg_len = 0;
	isis_srv6_sid_list_add_tail(&loc->srv6_sid, sid);

	/* Add locator TLV */
	isis_tlvs_add_srv6_locator(lsp->tlvs, ISIS_MT_IPV6_UNICAST, loc);

	/* Cleanup */
	isis_srv6_sid_list_fini(&loc->srv6_sid);
	XFREE(MTYPE_TMP, sid);
	XFREE(MTYPE_TMP, loc);
}

static void lsp_add_srv6_locator(struct isis_lsp *lsp, const struct isis_test_node *tnode,
				 size_t tnode_index)
{
	int i;

	if (!CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SRV6))
		return;

	/* Add primary locator with algorithm 0 (SPF) */
	lsp_add_srv6_locator_with_algo(lsp, tnode->srv6.locator, tnode->srv6.end_sid,
				       SR_ALGORITHM_SPF);

	/* Add extra locators with their specified algorithms */
	for (i = 0; i < tnode->srv6.extra_locator_count && i < MAX_SRV6_LOCATORS; i++) {
		const struct isis_test_srv6_locator *extra = &tnode->srv6.extra_locators[i];

		lsp_add_srv6_locator_with_algo(lsp, extra->locator, extra->end_sid,
					       extra->algorithm);
	}
}

static void lsp_add_mt_router_info(struct isis_lsp *lsp, const struct isis_test_node *tnode)
{
	if (tnode->protocols.ipv4)
		isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV4_UNICAST, 0, false);
	if (tnode->protocols.ipv6)
		isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV6_UNICAST, 0, false);
}

static void lsp_add_protocols_supported(struct isis_lsp *lsp, const struct isis_test_node *tnode)
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
				    const struct isis_test_node *tnode, size_t tnode_index,
				    struct isis_area *area, struct lspdb_head *lspdb, int level)
{
	struct isis_lsp *lsp;
	uint32_t next_sid_index = (tnode_index + 1) * 10;
	mpls_label_t next_label = 16;
	struct in6_addr next_srv6_sid;

	/* Initialize SRv6 End.X SID base from node's End SID */
	memset(&next_srv6_sid, 0, sizeof(next_srv6_sid));
	if (CHECK_FLAG(tnode->flags, F_ISIS_TEST_NODE_SRV6) && tnode->srv6.end_sid) {
		inet_pton(AF_INET6, tnode->srv6.end_sid, &next_srv6_sid);
		/* End.X SIDs start at function 0x10 */
		next_srv6_sid.s6_addr[15] = 0x10;
	}

	lsp = lsp_add(lspdb, area, level, tnode->sysid, tnode->pseudonode_id);
	lsp_add_mt_router_info(lsp, tnode);
	lsp_add_protocols_supported(lsp, tnode);
	lsp_add_router_capability(lsp, tnode);
	lsp_add_srv6_locator(lsp, tnode, tnode_index);

	/* Add IP Reachability Information. */
	for (size_t i = 0; tnode->networks[i]; i++) {
		if (i > MAX_NETWORKS) {
			zlog_debug("%s: node has too many networks (maximum is %u)", __func__,
				   MAX_NETWORKS);
			return -1;
		}
		lsp_add_ip_reach(lsp, tnode, tnode->networks[i], &next_sid_index);
	}

	/* Add IS Reachability Information. */
	for (size_t i = 0; tnode->adjacencies[i].hostname[0]; i++) {
		const struct isis_test_adj *tadj;
		const struct isis_test_node *tadj_node;

		if (i > MAX_ADJACENCIES) {
			zlog_debug("%s: node has too many adjacencies (maximum is %u)", __func__,
				   MAX_ADJACENCIES);
			return -1;
		}

		tadj = &tnode->adjacencies[i];
		tadj_node = test_topology_find_node(topology, tadj->hostname, tadj->pseudonode_id);
		if (!tadj_node) {
			zlog_debug("%s: node \"%s\" has an adjacency with non-existing node \"%s\"",
				   __func__, tnode->hostname, tadj->hostname);
			return -1;
		}
		if (!test_find_adjacency(tadj_node, tnode->hostname)) {
			zlog_debug("%s: node \"%s\" has an one-way adjacency with node \"%s\"",
				   __func__, tnode->hostname, tadj->hostname);
			return -1;
		}

		if (tnode->pseudonode_id || tadj_node->pseudonode_id ||
		    (tnode->protocols.ipv4 && tadj_node->protocols.ipv4))
			lsp_add_reach(lsp, tnode, tadj, tadj_node->sysid, tadj_node->pseudonode_id,
				      tadj->metric, AF_INET, &next_label, NULL);
		if (tadj_node->pseudonode_id ||
		    (tnode->protocols.ipv6 && tadj_node->protocols.ipv6))
			lsp_add_reach(lsp, tnode, tadj, tadj_node->sysid, tadj_node->pseudonode_id,
				      tadj->metric, AF_INET6, &next_label, &next_srv6_sid);
	}

	return 0;
}

static int topology_load_node(const struct isis_topology *topology,
			      const struct isis_test_node *tnode, size_t tnode_index,
			      struct isis_area *area, struct lspdb_head lspdb[])
{
	int ret;

	isis_dynhn_insert(area->isis, tnode->sysid, tnode->hostname, tnode->level);

	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
		if ((tnode->level & level) == 0)
			continue;

		ret = topology_load_node_level(topology, tnode, tnode_index, area,
					       &lspdb[level - 1], level);
		if (ret != 0)
			return ret;
	}

	return 0;
}

int test_topology_load(const struct isis_topology *topology, struct isis_area *area,
		       struct lspdb_head lspdb[])
{
	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++)
		lsp_db_init(&lspdb[level - 1]);

	for (size_t i = 0; topology->nodes[i].hostname[0]; i++) {
		const struct isis_test_node *tnode = &topology->nodes[i];
		int ret;

		if (i > MAX_NODES) {
			zlog_debug("%s: topology has too many nodes (maximum is %u)", __func__,
				   MAX_NODES);
			return -1;
		}

		ret = topology_load_node(topology, tnode, i, area, lspdb);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/*
 * Grid Topology Generator for Large-Scale Testing
 *
 * Generates a rows x cols grid topology where each node connects to its
 * neighbors (up, down, left, right). Supports up to 256 nodes.
 *
 * Grid layout (10x20 = 200 nodes):
 *
 *   rt1  -- rt2  -- rt3  -- ... -- rt20
 *    |       |       |              |
 *   rt21 -- rt22 -- rt23 -- ... -- rt40
 *    |       |       |              |
 *   ...     ...     ...            ...
 *    |       |       |              |
 *   rt181-- rt182-- rt183-- ... -- rt200
 */

/* Global grid topology instance */
static struct isis_grid_topology grid_topo_18;

void test_grid_topology_init(struct isis_grid_topology *grid, uint16_t number, uint16_t rows,
			     uint16_t cols, bool srv6_enabled)
{
	uint16_t node_count = rows * cols;

	if (node_count > GRID_MAX_NODES) {
		zlog_debug("%s: grid too large (%u nodes, max %u)", __func__, node_count,
			   GRID_MAX_NODES);
		return;
	}

	memset(grid, 0, sizeof(*grid));
	grid->number = number;
	grid->rows = rows;
	grid->cols = cols;
	grid->node_count = node_count;

	/* Generate all nodes */
	for (uint16_t row = 0; row < rows; row++) {
		for (uint16_t col = 0; col < cols; col++) {
			uint16_t id = row * cols + col + 1;
			struct isis_test_grid_node *node = &grid->nodes[id - 1];

			node->id = id;
			node->level = IS_LEVEL_1;
			node->adj_count = 0;

			/* Hostname: rt1, rt2, ..., rt200 */
			snprintf(node->hostname, sizeof(node->hostname), "rt%u", id);

			/* System ID: encode node ID in last 2 bytes */
			memset(node->sysid, 0, ISIS_SYS_ID_LEN);
			node->sysid[4] = (id >> 8) & 0xff;
			node->sysid[5] = id & 0xff;

			/* Router ID: 10.row.col.1 (simplified) */
			snprintf(node->router_id, sizeof(node->router_id), "10.%u.%u.1", row, col);

			/* IPv4 network */
			snprintf(node->ipv4_net, sizeof(node->ipv4_net), "10.%u.%u.1/32", row, col);

			/* IPv6 network */
			snprintf(node->ipv6_net, sizeof(node->ipv6_net), "2001:db8:%u:%u::1/128",
				 row, col);

			/* SRv6 configuration */
			if (srv6_enabled) {
				node->flags = F_ISIS_TEST_NODE_SRV6;
				snprintf(node->srv6_locator, sizeof(node->srv6_locator),
					 "fc00:%u:%u::/48", row, col);
				snprintf(node->srv6_end_sid, sizeof(node->srv6_end_sid),
					 "fc00:%u:%u::1", row, col);
			}

			/* Add adjacencies to neighbors */
			/* Up: (row-1, col) */
			if (row > 0) {
				uint16_t up_id = (row - 1) * cols + col + 1;

				node->adjacencies[node->adj_count].neighbor_id = up_id;
				node->adjacencies[node->adj_count].metric = 10;
				node->adj_count++;
			}
			/* Down: (row+1, col) */
			if (row < rows - 1) {
				uint16_t down_id = (row + 1) * cols + col + 1;

				node->adjacencies[node->adj_count].neighbor_id = down_id;
				node->adjacencies[node->adj_count].metric = 10;
				node->adj_count++;
			}
			/* Left: (row, col-1) */
			if (col > 0) {
				uint16_t left_id = row * cols + (col - 1) + 1;

				node->adjacencies[node->adj_count].neighbor_id = left_id;
				node->adjacencies[node->adj_count].metric = 10;
				node->adj_count++;
			}
			/* Right: (row, col+1) */
			if (col < cols - 1) {
				uint16_t right_id = row * cols + (col + 1) + 1;

				node->adjacencies[node->adj_count].neighbor_id = right_id;
				node->adjacencies[node->adj_count].metric = 10;
				node->adj_count++;
			}
		}
	}
}

const struct isis_test_grid_node *
test_grid_topology_find_node(const struct isis_grid_topology *grid, const char *hostname)
{
	for (uint16_t i = 0; i < grid->node_count; i++) {
		if (strmatch(hostname, grid->nodes[i].hostname))
			return &grid->nodes[i];
	}
	return NULL;
}

struct isis_grid_topology *test_grid_topology_get(uint16_t number)
{
	/* Topology 18 is a 10x20 grid (200 nodes) with SRv6 */
	if (number == 18) {
		static bool initialized;

		if (!initialized) {
			test_grid_topology_init(&grid_topo_18, 18, 10, 20, true);
			initialized = true;
		}
		return &grid_topo_18;
	}

	return NULL;
}

/* Load a grid node into the LSPDB */
static int grid_load_node_level(const struct isis_grid_topology *grid,
				const struct isis_test_grid_node *gnode, struct isis_area *area,
				struct lspdb_head *lspdb, int level)
{
	struct isis_lsp *lsp;
	uint8_t nodeid[ISIS_SYS_ID_LEN + 1];
	uint16_t mtid;
	struct nlpids nlpids = {};
	struct isis_router_cap *cap;
	struct prefix prefix;
	struct in6_addr next_srv6_sid;

	lsp = lsp_add(lspdb, area, level, gnode->sysid, 0);

	/* Add MT Router Info for IPv4 and IPv6 */
	isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV4_UNICAST, 0, false);
	isis_tlvs_add_mt_router_info(lsp->tlvs, ISIS_MT_IPV6_UNICAST, 0, false);

	/* Add protocols supported */
	nlpids.nlpids[0] = NLPID_IP;
	nlpids.nlpids[1] = NLPID_IPV6;
	nlpids.count = 2;
	isis_tlvs_set_protocols_supported(lsp->tlvs, &nlpids);

	/* Add router capability */
	cap = isis_tlvs_init_router_capability(lsp->tlvs);
	if (inet_pton(AF_INET, gnode->router_id, &cap->router_id) != 1)
		zlog_debug("%s: invalid router-id: %s", __func__, gnode->router_id);

	/* Add SRv6 capability */
	if (CHECK_FLAG(gnode->flags, F_ISIS_TEST_NODE_SRV6)) {
		cap->srv6_cap.is_srv6_capable = true;
		cap->algo[0] = SR_ALGORITHM_SPF;
		cap->algo[1] = SR_ALGORITHM_UNSET;

		/* Add SRv6 locator */
		struct isis_srv6_locator *loc;
		struct isis_srv6_sid *sid;
		struct prefix_ipv6 locator_prefix;

		if (str2prefix_ipv6(gnode->srv6_locator, &locator_prefix) == 1) {
			loc = XCALLOC(MTYPE_TMP, sizeof(*loc));
			loc->prefix = locator_prefix;
			loc->metric = 1;
			loc->algorithm = SR_ALGORITHM_SPF;
			isis_srv6_sid_list_init(&loc->srv6_sid);

			sid = XCALLOC(MTYPE_TMP, sizeof(*sid));
			inet_pton(AF_INET6, gnode->srv6_end_sid, &sid->sid);
			sid->behavior = SRV6_ENDPOINT_BEHAVIOR_END;
			sid->structure.loc_block_len = 32;
			sid->structure.loc_node_len = 16;
			sid->structure.func_len = 16;
			sid->structure.arg_len = 0;
			isis_srv6_sid_list_add_tail(&loc->srv6_sid, sid);

			isis_tlvs_add_srv6_locator(lsp->tlvs, ISIS_MT_IPV6_UNICAST, loc);

			isis_srv6_sid_list_fini(&loc->srv6_sid);
			XFREE(MTYPE_TMP, sid);
			XFREE(MTYPE_TMP, loc);
		}
	}

	/* Add IPv4 reachability */
	if (str2prefix(gnode->ipv4_net, &prefix) == 1) {
		isis_tlvs_add_extended_ip_reach(lsp->tlvs, (struct prefix_ipv4 *)&prefix, 10,
						false, NULL);
	}

	/* Add IPv6 reachability */
	if (str2prefix(gnode->ipv6_net, &prefix) == 1) {
		isis_tlvs_add_ipv6_reach(lsp->tlvs, ISIS_MT_IPV6_UNICAST,
					 (struct prefix_ipv6 *)&prefix, 10, false, NULL);
	}

	/* Initialize SRv6 End.X SID base */
	memset(&next_srv6_sid, 0, sizeof(next_srv6_sid));
	if (CHECK_FLAG(gnode->flags, F_ISIS_TEST_NODE_SRV6)) {
		inet_pton(AF_INET6, gnode->srv6_end_sid, &next_srv6_sid);
		next_srv6_sid.s6_addr[15] = 0x10;
	}

	/* Add IS reachability for each adjacency */
	for (uint8_t i = 0; i < gnode->adj_count; i++) {
		const struct isis_test_grid_node *neighbor;
		struct isis_ext_subtlvs *ext = NULL;

		neighbor = &grid->nodes[gnode->adjacencies[i].neighbor_id - 1];

		memcpy(nodeid, neighbor->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(nodeid) = 0;

		/* Add SRv6 End.X SID for IPv6 */
		if (CHECK_FLAG(gnode->flags, F_ISIS_TEST_NODE_SRV6)) {
			struct isis_srv6_endx_sid_subtlv *endx_sid;

			ext = isis_alloc_ext_subtlvs();
			endx_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*endx_sid));
			SET_FLAG(endx_sid->flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG);
			SET_FLAG(endx_sid->flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG);
			endx_sid->behavior = SRV6_ENDPOINT_BEHAVIOR_END_X;
			endx_sid->sid = next_srv6_sid;
			next_srv6_sid.s6_addr[15]++;
			isis_tlvs_add_srv6_endx_sid(ext, endx_sid);
		}

		/* IPv4 IS reach */
		mtid = ISIS_MT_IPV4_UNICAST;
		isis_tlvs_add_extended_reach(lsp->tlvs, mtid, nodeid, gnode->adjacencies[i].metric,
					     NULL);

		/* IPv6 IS reach with SRv6 End.X SID */
		mtid = ISIS_MT_IPV6_UNICAST;
		isis_tlvs_add_extended_reach(lsp->tlvs, mtid, nodeid, gnode->adjacencies[i].metric,
					     ext);
		isis_del_ext_subtlvs(ext);
	}

	return 0;
}

int test_grid_topology_load(const struct isis_grid_topology *grid, struct isis_area *area,
			    struct lspdb_head lspdb[])
{
	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++)
		lsp_db_init(&lspdb[level - 1]);

	for (uint16_t i = 0; i < grid->node_count; i++) {
		const struct isis_test_grid_node *gnode = &grid->nodes[i];
		int ret;

		/* Add dynamic hostname mapping */
		isis_dynhn_insert(area->isis, gnode->sysid, gnode->hostname, gnode->level);

		/* Load only level-1 for now */
		ret = grid_load_node_level(grid, gnode, area, &lspdb[0], IS_LEVEL_1);
		if (ret != 0)
			return ret;
	}

	return 0;
}
