// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _COMMON_ISIS_H
#define _COMMON_ISIS_H

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"

#define MAX_HOSTNAME	16
#define MAX_NETWORKS	8
#define MAX_ADJACENCIES 8
#define MAX_NODES	12
#define MAX_SRLGS	4

/* Large-scale topology limits */
#define GRID_MAX_NODES	     256
#define GRID_MAX_ADJACENCIES 4

#define SRGB_DFTL_LOWER_BOUND 16000
#define SRGB_DFTL_RANGE_SIZE  8000

/* SRv6 test configuration */
struct isis_test_srv6 {
	const char *locator; /* e.g., "fc00:0:1::/48" */
	const char *end_sid; /* e.g., "fc00:0:1::1" */
};

struct isis_test_adj {
	char hostname[MAX_HOSTNAME];
	uint8_t pseudonode_id;
	uint32_t metric;
	uint32_t srlgs[MAX_SRLGS]; /* SRLG values for this adjacency */
	uint8_t srlg_count;
};

struct isis_test_node {
	char hostname[MAX_HOSTNAME];
	uint8_t sysid[ISIS_SYS_ID_LEN];
	uint8_t pseudonode_id;
	int level;
	struct {
		bool ipv4;
		bool ipv6;
	} protocols;
	const char *router_id;
	struct {
		uint32_t lower_bound;
		uint32_t range_size;
	} srgb;
	struct isis_test_srv6 srv6; /* SRv6 configuration */
	const char *networks[MAX_NETWORKS + 1];
	struct isis_test_adj adjacencies[MAX_ADJACENCIES + 1];
	uint8_t flags;
};
#define F_ISIS_TEST_NODE_SR   0x01
#define F_ISIS_TEST_NODE_SRV6 0x02

struct isis_topology {
	uint16_t number;
	struct isis_test_node nodes[MAX_NODES + 1];
};

/*
 * Grid topology node structure for large-scale testing.
 * Supports up to GRID_MAX_NODES nodes with up to 4 adjacencies each.
 */
struct isis_test_grid_adj {
	uint16_t neighbor_id; /* Node ID (1-based) */
	uint32_t metric;
};

struct isis_test_grid_node {
	uint16_t id; /* Node ID (1-based) */
	char hostname[MAX_HOSTNAME];
	uint8_t sysid[ISIS_SYS_ID_LEN];
	int level;
	char router_id[20];    /* "10.0.X.Y" */
	char ipv4_net[24];     /* "10.0.X.Y/32" */
	char ipv6_net[48];     /* "2001:db8::X:Y/128" */
	char srv6_locator[32]; /* "fc00:X:Y::/48" */
	char srv6_end_sid[48]; /* "fc00:X:Y::1" */
	struct isis_test_grid_adj adjacencies[GRID_MAX_ADJACENCIES];
	uint8_t adj_count;
	uint8_t flags;
};

struct isis_grid_topology {
	uint16_t number;
	uint16_t rows;
	uint16_t cols;
	uint16_t node_count;
	struct isis_test_grid_node nodes[GRID_MAX_NODES];
};

/* Prototypes. */
extern int isis_sock_init(struct isis_circuit *circuit);
extern const struct isis_test_node *test_topology_find_node(const struct isis_topology *topology,
							    const char *hostname,
							    uint8_t pseudonode_id);
extern const struct isis_topology *test_topology_find(struct isis_topology *test_topologies,
						      uint16_t number);
extern mpls_label_t test_topology_node_ldp_label(const struct isis_topology *topology,
						 struct in_addr router_id);
extern int test_topology_load(const struct isis_topology *topology, struct isis_area *area,
			      struct lspdb_head lspdb[]);

/* Grid topology functions */
extern void test_grid_topology_init(struct isis_grid_topology *grid, uint16_t number,
				    uint16_t rows, uint16_t cols, bool srv6_enabled);
extern const struct isis_test_grid_node *
test_grid_topology_find_node(const struct isis_grid_topology *grid, const char *hostname);
extern int test_grid_topology_load(const struct isis_grid_topology *grid, struct isis_area *area,
				   struct lspdb_head lspdb[]);
extern struct isis_grid_topology *test_grid_topology_get(uint16_t number);

/* Global variables. */
extern struct event_loop *master;
extern struct zebra_privs_t isisd_privs;
extern struct isis_topology test_topologies[];

#endif /* _COMMON_ISIS_H */
