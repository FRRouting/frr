#ifndef _COMMON_OSPF_H
#define _COMMON_OSPF_H

#define MAX_ADJACENCIES 8
#define MAX_NODES 12

struct ospf_test_adj {
	char hostname[256];
	char network[256];
	uint32_t metric;
	mpls_label_t label;
};

struct ospf_test_node {
	char hostname[256];
	const char *router_id;
	mpls_label_t label;
	struct ospf_test_adj adjacencies[MAX_ADJACENCIES + 1];
};

struct ospf_topology {
	struct ospf_test_node nodes[MAX_NODES + 1];
};

/* Prototypes. */
extern struct ospf_topology *test_find_topology(const char *name);
extern struct ospf_test_node *test_find_node(struct ospf_topology *topology,
					     const char *hostname);
extern int topology_load(struct vty *vty, struct ospf_topology *topology,
			 struct ospf_test_node *root, struct ospf *ospf);

/* Global variables. */
extern struct event_loop *master;
extern struct ospf_topology topo1;
extern struct ospf_topology topo2;
extern struct ospf_topology topo3;
extern struct ospf_topology topo4;
extern struct ospf_topology topo5;
extern struct zebra_privs_t ospfd_privs;

/* For stable order in unit tests */
extern int sort_paths(const void **path1, const void **path2);

/* Print the routing table */
extern void print_route_table(struct vty *vty, struct route_table *rt);

#endif /* _COMMON_OSPF_H */
