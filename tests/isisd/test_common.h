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

#define MAX_HOSTNAME 16
#define MAX_NETWORKS 8
#define MAX_ADJACENCIES 8
#define MAX_NODES 12

#define SRGB_DFTL_LOWER_BOUND 16000
#define SRGB_DFTL_RANGE_SIZE 8000

struct isis_test_adj {
	char hostname[MAX_HOSTNAME];
	uint8_t pseudonode_id;
	uint32_t metric;
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
	const char *networks[MAX_NETWORKS + 1];
	struct isis_test_adj adjacencies[MAX_ADJACENCIES + 1];
	uint8_t flags;
};
#define F_ISIS_TEST_NODE_SR 0x01

struct isis_topology {
	uint16_t number;
	struct isis_test_node nodes[MAX_NODES + 1];
};

/* Prototypes. */
extern int isis_sock_init(struct isis_circuit *circuit);
extern const struct isis_test_node *
test_topology_find_node(const struct isis_topology *topology,
			const char *hostname, uint8_t pseudonode_id);
extern const struct isis_topology *
test_topology_find(struct isis_topology *test_topologies, uint16_t number);
extern mpls_label_t
test_topology_node_ldp_label(const struct isis_topology *topology,
			     struct in_addr router_id);
extern int test_topology_load(const struct isis_topology *topology,
			      struct isis_area *area,
			      struct lspdb_head lspdb[]);

/* Global variables. */
extern struct event_loop *master;
extern struct zebra_privs_t isisd_privs;
extern struct isis_topology test_topologies[];

#endif /* _COMMON_ISIS_H */
