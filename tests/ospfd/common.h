#ifndef _COMMON_OSPF_H
#define _COMMON_OSPF_H

#define MAX_ADJACENCIES 8
#define MAX_NODES 12

struct ospf_test_adj {
	char hostname[256];
	char network[256];
	uint32_t metric;
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
extern struct thread_master *master;
extern struct ospf_topology topo1;
extern struct ospf_topology topo2;
extern struct ospf_topology topo3;
extern struct zebra_privs_t ospfd_privs;

#endif /* _COMMON_OSPF_H */
