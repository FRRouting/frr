// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF routing table.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_ROUTE_H
#define _ZEBRA_OSPF_ROUTE_H

#define OSPF_DESTINATION_ROUTER		1
#define OSPF_DESTINATION_NETWORK	2
#define OSPF_DESTINATION_DISCARD	3

#define OSPF_PATH_MIN			0
#define OSPF_PATH_INTRA_AREA		1
#define OSPF_PATH_INTER_AREA		2
#define OSPF_PATH_TYPE1_EXTERNAL	3
#define OSPF_PATH_TYPE2_EXTERNAL	4
#define OSPF_PATH_MAX			5

/* Segment Routing information to complement ospf_path structure */
struct sr_nexthop_info {
	/* Output label associated to this route */
	mpls_label_t label_out;
	/*
	 * Pointer to SR Node which is the next hop for this route
	 * or NULL if next hop is the destination of the prefix
	 */
	struct sr_node *nexthop;

	/* TI-LFA */
	struct mpls_label_stack *backup_label_stack;
	struct in_addr backup_nexthop;
};

/* OSPF Path. */
struct ospf_path {
	struct in_addr nexthop;
	struct in_addr adv_router;
	ifindex_t ifindex;
	unsigned char unnumbered;
	struct sr_nexthop_info srni;
};

/* Below is the structure linked to every
   route node. Note that for Network routing
   entries a single ospf_route is kept, while
   for ABRs and ASBRs (Router routing entries),
   we link an instance of ospf_router_route
   where a list of paths is maintained, so

   nr->info is a (struct ospf_route *) for OSPF_DESTINATION_NETWORK
   but
   nr->info is a (struct ospf_router_route *) for OSPF_DESTINATION_ROUTER
*/

struct route_standard {
	/* Link Sate Origin. */
	struct lsa_header *origin;

	/* Associated Area. */
	struct in_addr area_id; /* The area the route belongs to */

	/*  Area Type */
	int external_routing;

	/* Optional Capability. */
	uint8_t options; /* Get from LSA header. */

	/*  */
	uint8_t flags; /* From router-LSA */

	bool transit; /* Transit network or not */
};

struct route_external {
	/* Link State Origin. */
	struct ospf_lsa *origin;

	/* Link State Cost Type2. */
	uint32_t type2_cost;

	/* Tag value. */
	uint32_t tag;

	/* ASBR route. */
	struct ospf_route *asbr;
};

struct ospf_route {
	/* Destination Type. */
	uint8_t type;

	/* Destination ID. */ /* i.e. Link State ID. */
	struct in_addr id;

	/* Address Mask. */
	struct in_addr mask; /* Only valid for networks. */

	/* Path Type. */
	uint8_t path_type;

	/* List of Paths. */
	struct list *paths;

	/* Link State Cost. */
	uint32_t cost; /* i.e. metric. */

	/* Route specific info. */
	union {
		struct route_standard std;
		struct route_external ext;
	} u;

	bool changed;
};

extern const char *ospf_path_type_name(int path_type);
extern struct ospf_path *ospf_path_new(void);
extern void ospf_path_free(struct ospf_path *);
extern struct ospf_path *ospf_path_lookup(struct list *, struct ospf_path *);
extern struct ospf_route *ospf_route_new(void);
extern void ospf_route_free(struct ospf_route *);
extern void ospf_route_delete(struct ospf *, struct route_table *);
extern void ospf_route_table_free(struct route_table *);

extern void ospf_route_install(struct ospf *, struct route_table *);
extern void ospf_route_table_dump(struct route_table *);
extern void ospf_router_route_table_dump(struct route_table *rt);

extern void ospf_intra_add_router(struct route_table *rt, struct vertex *v,
				  struct ospf_area *area, bool add_all);

extern void ospf_intra_add_transit(struct route_table *, struct vertex *,
				   struct ospf_area *);

extern void ospf_intra_add_stub(struct route_table *, struct router_lsa_link *,
				struct vertex *, struct ospf_area *,
				int parent_is_root, int);

extern int ospf_route_cmp(struct ospf *, struct ospf_route *,
			  struct ospf_route *);
extern void ospf_route_copy_nexthops(struct ospf_route *, struct list *);
extern void ospf_route_copy_nexthops_from_vertex(struct ospf_area *area,
						 struct ospf_route *,
						 struct vertex *);

extern void ospf_route_subst(struct route_node *, struct ospf_route *,
			     struct ospf_route *);
extern void ospf_route_add(struct route_table *, struct prefix_ipv4 *,
			   struct ospf_route *, struct ospf_route *);

extern void ospf_route_subst_nexthops(struct ospf_route *, struct list *);
extern void ospf_prune_unreachable_networks(struct route_table *);
extern void ospf_prune_unreachable_routers(struct route_table *);
extern int ospf_add_discard_route(struct ospf *, struct route_table *,
				  struct ospf_area *, struct prefix_ipv4 *,
				  bool);
extern void ospf_delete_discard_route(struct ospf *, struct route_table *,
				      struct prefix_ipv4 *, bool);
extern int ospf_route_match_same(struct route_table *, struct prefix_ipv4 *,
				 struct ospf_route *);

#endif /* _ZEBRA_OSPF_ROUTE_H */
