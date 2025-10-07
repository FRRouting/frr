// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF calculation.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_OSPF_SPF_H
#define _QUAGGA_OSPF_SPF_H

#include "typesafe.h"

/* values for vertex->type */
#define OSPF_VERTEX_ROUTER  1  /* for a Router-LSA */
#define OSPF_VERTEX_NETWORK 2  /* for a Network-LSA */

/* values for vertex->flags */
#define OSPF_VERTEX_PROCESSED      0x01

/* The "root" is the node running the SPF calculation */

PREDECL_SKIPLIST_NONUNIQ(vertex_pqueue);
/* A router or network in an area */
struct vertex {
	struct vertex_pqueue_item pqi;
	uint8_t flags;
	uint8_t type;		/* copied from LSA header */
	struct in_addr id;      /* copied from LSA header */
	struct ospf_lsa *lsa_p;
	struct lsa_header *lsa; /* Router or Network LSA */
	uint32_t distance;      /* from root to this vertex */
	struct list *parents;   /* list of parents in SPF tree */
	struct list *children;  /* list of children in SPF tree*/
};

struct vertex_nexthop {
	struct in_addr router;     /* router address to send to */
	int lsa_pos; /* LSA position for resolving the interface */
};

struct vertex_parent {
	struct vertex_nexthop *nexthop; /* nexthop taken on the root node */
	struct vertex_nexthop *local_nexthop; /* local nexthop of the parent */
	struct vertex *parent;		      /* parent vertex */
	int backlink; /* index back to parent for router-lsa's */
};

/* What triggered the SPF ? */
typedef enum {
	SPF_FLAG_ROUTER_LSA_INSTALL = 1,
	SPF_FLAG_NETWORK_LSA_INSTALL,
	SPF_FLAG_SUMMARY_LSA_INSTALL,
	SPF_FLAG_ASBR_SUMMARY_LSA_INSTALL,
	SPF_FLAG_MAXAGE,
	SPF_FLAG_ABR_STATUS_CHANGE,
	SPF_FLAG_ASBR_STATUS_CHANGE,
	SPF_FLAG_CONFIG_CHANGE,
	SPF_FLAG_GR_FINISH,
} ospf_spf_reason_t;

extern void ospf_spf_calculate_schedule(struct ospf *, ospf_spf_reason_t);
extern void ospf_spf_calculate(struct ospf_area *area,
			       struct ospf_lsa *root_lsa,
			       struct route_table *new_table,
			       struct route_table *all_rtrs,
			       struct route_table *new_rtrs, bool is_dry_run,
			       bool is_root_node);
extern void ospf_spf_calculate_area(struct ospf *ospf, struct ospf_area *area,
				    struct route_table *new_table,
				    struct route_table *all_rtrs,
				    struct route_table *new_rtrs);
extern void ospf_spf_calculate_areas(struct ospf *ospf,
				     struct route_table *new_table,
				     struct route_table *all_rtrs,
				     struct route_table *new_rtrs);
extern void ospf_rtrs_free(struct route_table *);
extern void ospf_spf_cleanup(struct vertex *spf, struct list *vertex_list);
extern void ospf_spf_copy(struct vertex *vertex, struct list *vertex_list);
extern void ospf_spf_remove_resource(struct vertex *vertex,
				     struct list *vertex_list,
				     struct protected_resource *resource);
extern struct vertex *ospf_spf_vertex_find(struct in_addr id,
					   struct list *vertex_list);
extern struct vertex *ospf_spf_vertex_by_nexthop(struct vertex *root,
						 struct in_addr *nexthop);
extern struct vertex_parent *ospf_spf_vertex_parent_find(struct in_addr id,
							 struct vertex *vertex);
extern int vertex_parent_cmp(void *aa, void *bb);

extern void ospf_spf_print(struct vty *vty, struct vertex *v, int i);
extern void ospf_restart_spf(struct ospf *ospf);
/* void ospf_spf_calculate_timer_add (); */
#endif /* _QUAGGA_OSPF_SPF_H */
