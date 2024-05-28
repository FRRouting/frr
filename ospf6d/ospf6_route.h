// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_ROUTE_H
#define OSPF6_ROUTE_H

#include "command.h"
#include "zclient.h"
#include "lib/json.h"
#include "lib/nexthop.h"

#define OSPF6_MULTI_PATH_LIMIT    4

/* Debug option */
extern unsigned char conf_debug_ospf6_route;
#define OSPF6_DEBUG_ROUTE_TABLE   0x01
#define OSPF6_DEBUG_ROUTE_INTRA   0x02
#define OSPF6_DEBUG_ROUTE_INTER   0x04
#define OSPF6_DEBUG_ROUTE_MEMORY  0x08
#define OSPF6_DEBUG_ROUTE_ALL                                                  \
	(OSPF6_DEBUG_ROUTE_TABLE | OSPF6_DEBUG_ROUTE_INTRA                     \
	 | OSPF6_DEBUG_ROUTE_INTER | OSPF6_DEBUG_ROUTE_MEMORY)
#define OSPF6_DEBUG_ROUTE_ON(level) (conf_debug_ospf6_route |= (level))
#define OSPF6_DEBUG_ROUTE_OFF(level) (conf_debug_ospf6_route &= ~(level))
#define IS_OSPF6_DEBUG_ROUTE(e) (conf_debug_ospf6_route & OSPF6_DEBUG_ROUTE_##e)

/* Nexthop */
struct ospf6_nexthop {
	/* Interface index */
	ifindex_t ifindex;

	/* IP address, if any */
	struct in6_addr address;

	/** Next-hop type information. */
	enum nexthop_types_t type;
};

static inline bool ospf6_nexthop_is_set(const struct ospf6_nexthop *nh)
{
	return nh->type != 0;
}

static inline bool ospf6_nexthop_is_same(const struct ospf6_nexthop *nha,
					 const struct ospf6_nexthop *nhb)
{
	if (nha->type != nhb->type)
		return false;

	switch (nha->type) {
	case NEXTHOP_TYPE_BLACKHOLE:
		/* NOTHING */
		break;

	case NEXTHOP_TYPE_IFINDEX:
		if (nha->ifindex != nhb->ifindex)
			return false;
		break;

	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		/* OSPFv3 does not support IPv4 next hops. */
		return false;

	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (nha->ifindex != nhb->ifindex)
			return false;
		fallthrough;
	case NEXTHOP_TYPE_IPV6:
		if (!IN6_ARE_ADDR_EQUAL(&nha->address, &nhb->address))
			return false;
		break;
	}

	return true;
}

static inline void ospf6_nexthop_clear(struct ospf6_nexthop *nh)
{
	memset(nh, 0, sizeof(*nh));
}

static inline void ospf6_nexthop_copy(struct ospf6_nexthop *nha,
				      const struct ospf6_nexthop *nhb)
{
	memcpy(nha, nhb, sizeof(*nha));
}

/* Path */
struct ospf6_ls_origin {
	uint16_t type;
	in_addr_t id;
	in_addr_t adv_router;
};

struct ospf6_path {
	/* Link State Origin */
	struct ospf6_ls_origin origin;

	/* Router bits */
	uint8_t router_bits;

	/* Optional Capabilities */
	uint8_t options[3];

	/* Associated Area */
	in_addr_t area_id;

	/* Path-type */
	uint8_t type;
	uint8_t subtype; /* only used for redistribute i.e ZEBRA_ROUTE_XXX */

	/* Cost */
	uint8_t metric_type;
	uint32_t cost;

	struct prefix ls_prefix;

	union {
		uint32_t cost_e2;
		uint32_t cost_config;
	} u;
	uint32_t tag;

	/* nh list for this path */
	struct list *nh_list;
};

#define OSPF6_PATH_TYPE_NONE         0
#define OSPF6_PATH_TYPE_INTRA        1
#define OSPF6_PATH_TYPE_INTER        2
#define OSPF6_PATH_TYPE_EXTERNAL1    3
#define OSPF6_PATH_TYPE_EXTERNAL2    4
#define OSPF6_PATH_TYPE_MAX          5

#define OSPF6_PATH_SUBTYPE_DEFAULT_RT   1

#define OSPF6_PATH_COST_IS_CONFIGURED(path) (path.u.cost_config != OSPF_AREA_RANGE_COST_UNSPEC)

#include "prefix.h"
#include "table.h"
#include "bitfield.h"

struct ospf6_route {
	struct route_node *rnode;
	struct ospf6_route_table *table;
	struct ospf6_route *prev;
	struct ospf6_route *next;

	/* Back pointer to ospf6 */
	struct ospf6 *ospf6;

	unsigned int lock;

	/* Destination Type */
	uint8_t type;

	/* XXX: It would likely be better to use separate struct in_addr's
	 * for the advertising router-ID and prefix IDs, instead of stuffing
	 * them
	 * into one. See also XXX below.
	 */
	/* Destination ID */
	struct prefix prefix;

	/* Time */
	struct timeval installed;
	struct timeval changed;

	/* flag */
	uint16_t flag;

	/* Prefix Options */
	uint8_t prefix_options;

	/* route option */
	void *route_option;

	/* link state id for advertising */
	uint32_t linkstate_id;

	/* path */
	struct ospf6_path path;

	/* List of Paths. */
	struct list *paths;

	/* nexthop */
	struct list *nh_list;

	/* points to the summarised route */
	struct ospf6_external_aggr_rt *aggr_route;

	/* For Aggr routes */
	bool to_be_processed;
};

#define OSPF6_DEST_TYPE_NONE       0
#define OSPF6_DEST_TYPE_ROUTER     1
#define OSPF6_DEST_TYPE_NETWORK    2
#define OSPF6_DEST_TYPE_DISCARD    3
#define OSPF6_DEST_TYPE_LINKSTATE  4
#define OSPF6_DEST_TYPE_RANGE      5
#define OSPF6_DEST_TYPE_MAX        6

#define OSPF6_ROUTE_CHANGE           0x0001
#define OSPF6_ROUTE_ADD              0x0002
#define OSPF6_ROUTE_REMOVE           0x0004
#define OSPF6_ROUTE_BEST             0x0008
#define OSPF6_ROUTE_ACTIVE_SUMMARY   0x0010
#define OSPF6_ROUTE_DO_NOT_ADVERTISE 0x0020
#define OSPF6_ROUTE_WAS_REMOVED      0x0040
#define OSPF6_ROUTE_BLACKHOLE_ADDED  0x0080
#define OSPF6_ROUTE_NSSA_RANGE       0x0100
struct ospf6;

struct ospf6_route_table {
	int scope_type;
	int table_type;
	void *scope;

	/* patricia tree */
	struct route_table *table;

	uint32_t count;

	/* hooks */
	void (*hook_add)(struct ospf6_route *);
	void (*hook_change)(struct ospf6_route *);
	void (*hook_remove)(struct ospf6_route *);
};

#define OSPF6_SCOPE_TYPE_NONE      0
#define OSPF6_SCOPE_TYPE_GLOBAL    1
#define OSPF6_SCOPE_TYPE_AREA      2
#define OSPF6_SCOPE_TYPE_INTERFACE 3

#define OSPF6_TABLE_TYPE_NONE              0
#define OSPF6_TABLE_TYPE_ROUTES            1
#define OSPF6_TABLE_TYPE_BORDER_ROUTERS    2
#define OSPF6_TABLE_TYPE_CONNECTED_ROUTES  3
#define OSPF6_TABLE_TYPE_EXTERNAL_ROUTES   4
#define OSPF6_TABLE_TYPE_SPF_RESULTS       5
#define OSPF6_TABLE_TYPE_PREFIX_RANGES     6
#define OSPF6_TABLE_TYPE_SUMMARY_PREFIXES  7
#define OSPF6_TABLE_TYPE_SUMMARY_ROUTERS   8

#define OSPF6_ROUTE_TABLE_CREATE(s, t)                                         \
	ospf6_route_table_create(OSPF6_SCOPE_TYPE_##s, OSPF6_TABLE_TYPE_##t)

extern const char *const ospf6_dest_type_str[OSPF6_DEST_TYPE_MAX];
extern const char *const ospf6_dest_type_substr[OSPF6_DEST_TYPE_MAX];
#define OSPF6_DEST_TYPE_NAME(x)                                                \
	(0 < (x) && (x) < OSPF6_DEST_TYPE_MAX ? ospf6_dest_type_str[(x)]       \
					      : ospf6_dest_type_str[0])
#define OSPF6_DEST_TYPE_SUBSTR(x)                                              \
	(0 < (x) && (x) < OSPF6_DEST_TYPE_MAX ? ospf6_dest_type_substr[(x)]    \
					      : ospf6_dest_type_substr[0])

extern const char *const ospf6_path_type_str[OSPF6_PATH_TYPE_MAX];
extern const char *const ospf6_path_type_substr[OSPF6_PATH_TYPE_MAX];
#define OSPF6_PATH_TYPE_NAME(x)                                                \
	(0 < (x) && (x) < OSPF6_PATH_TYPE_MAX ? ospf6_path_type_str[(x)]       \
					      : ospf6_path_type_str[0])
#define OSPF6_PATH_TYPE_SUBSTR(x)                                              \
	(0 < (x) && (x) < OSPF6_PATH_TYPE_MAX ? ospf6_path_type_substr[(x)]    \
					      : ospf6_path_type_substr[0])
#define OSPF6_PATH_TYPE_JSON(x)                                                \
	(0 < (x) && (x) < OSPF6_PATH_TYPE_MAX ? ospf6_path_type_json[(x)]      \
					      : ospf6_path_type_json[0])

#define OSPF6_ROUTE_ADDRESS_STR "Display the route bestmatches the address\n"
#define OSPF6_ROUTE_PREFIX_STR  "Display the route\n"
#define OSPF6_ROUTE_MATCH_STR   "Display the route matches the prefix\n"

#define ospf6_route_is_prefix(p, r) (prefix_same(p, &(r)->prefix))
#define ospf6_route_is_same(ra, rb) (prefix_same(&(ra)->prefix, &(rb)->prefix))
#define ospf6_route_is_same_origin(ra, rb)                                     \
	((ra)->path.area_id == (rb)->path.area_id                              \
	 && (ra)->path.origin.type == (rb)->path.origin.type                   \
	 && (ra)->path.origin.id == (rb)->path.origin.id                       \
	 && (ra)->path.origin.adv_router == (rb)->path.origin.adv_router)
#define ospf6_route_is_identical(ra, rb)                                       \
	((ra)->type == (rb)->type &&                                           \
	 prefix_same(&(ra)->prefix, &(rb)->prefix) &&                          \
	 (ra)->path.type == (rb)->path.type &&                                 \
	 (ra)->path.cost == (rb)->path.cost &&                                 \
	 (ra)->path.router_bits == (rb)->path.router_bits &&                   \
	 (ra)->path.u.cost_e2 == (rb)->path.u.cost_e2 &&                       \
	 listcount(ra->paths) == listcount(rb->paths) &&                       \
	 ospf6_route_cmp_nexthops(ra, rb))

#define ospf6_route_is_best(r) (CHECK_FLAG ((r)->flag, OSPF6_ROUTE_BEST))

#define ospf6_linkstate_prefix_adv_router(x) ((x)->u.lp.id.s_addr)
#define ospf6_linkstate_prefix_id(x) ((x)->u.lp.adv_router.s_addr)

#define ADV_ROUTER_IN_PREFIX(x) ((x)->u.lp.id.s_addr)

/* Function prototype */
extern void ospf6_linkstate_prefix(uint32_t adv_router, uint32_t id,
				   struct prefix *prefix);
extern void ospf6_linkstate_prefix2str(struct prefix *prefix, char *buf,
				       int size);

extern struct ospf6_nexthop *ospf6_nexthop_create(void);
extern int ospf6_nexthop_cmp(struct ospf6_nexthop *a, struct ospf6_nexthop *b);
extern void ospf6_nexthop_delete(struct ospf6_nexthop *nh);
extern void ospf6_clear_nexthops(struct list *nh_list);
extern int ospf6_num_nexthops(struct list *nh_list);
extern void ospf6_copy_nexthops(struct list *dst, struct list *src);
extern void ospf6_merge_nexthops(struct list *dst, struct list *src);
extern void ospf6_add_nexthop(struct list *nh_list, int ifindex,
			      const struct in6_addr *addr);
extern void ospf6_add_route_nexthop_blackhole(struct ospf6_route *route);
extern int ospf6_num_nexthops(struct list *nh_list);
extern bool ospf6_route_cmp_nexthops(struct ospf6_route *a,
				     struct ospf6_route *b);
extern void ospf6_route_zebra_copy_nexthops(struct ospf6_route *route,
					    struct zapi_nexthop nexthops[],
					    int entries, vrf_id_t vrf_id);
extern int ospf6_route_get_first_nh_index(struct ospf6_route *route);

/* Hide abstraction of nexthop implementation in route from outsiders */
#define ospf6_route_copy_nexthops(dst, src) ospf6_copy_nexthops(dst->nh_list, src->nh_list)
#define ospf6_route_merge_nexthops(dst, src) ospf6_merge_nexthops(dst->nh_list, src->nh_list)
#define ospf6_route_num_nexthops(route) ospf6_num_nexthops(route->nh_list)
#define ospf6_route_add_nexthop(route, ifindex, addr)                          \
	ospf6_add_nexthop(route->nh_list, ifindex, addr)

extern struct ospf6_route *ospf6_route_create(struct ospf6 *ospf6);
extern void ospf6_route_delete(struct ospf6_route *route);
extern struct ospf6_route *ospf6_route_copy(struct ospf6_route *route);
extern int ospf6_route_cmp(struct ospf6_route *ra, struct ospf6_route *rb);

extern void ospf6_route_lock(struct ospf6_route *route);
extern void ospf6_route_unlock(struct ospf6_route *route);
extern struct ospf6_route *ospf6_route_lookup(struct prefix *prefix,
					      struct ospf6_route_table *table);
extern struct ospf6_route *
ospf6_route_lookup_identical(struct ospf6_route *route,
			     struct ospf6_route_table *table);
extern struct ospf6_route *
ospf6_route_lookup_bestmatch(struct prefix *prefix,
			     struct ospf6_route_table *table);

extern struct ospf6_route *ospf6_route_add(struct ospf6_route *route,
					   struct ospf6_route_table *table);
extern void ospf6_route_remove(struct ospf6_route *route,
			       struct ospf6_route_table *table);

extern struct ospf6_route *ospf6_route_head(struct ospf6_route_table *table);
extern struct ospf6_route *ospf6_route_next(struct ospf6_route *route);
extern struct ospf6_route *ospf6_route_best_next(struct ospf6_route *route);

extern struct ospf6_route *
ospf6_route_match_head(struct prefix *prefix, struct ospf6_route_table *table);
extern struct ospf6_route *ospf6_route_match_next(struct prefix *prefix,
						  struct ospf6_route *route);

extern void ospf6_route_remove_all(struct ospf6_route_table *table);
extern struct ospf6_route_table *ospf6_route_table_create(int s, int t);
extern void ospf6_route_table_delete(struct ospf6_route_table *table);
extern void ospf6_route_dump(struct ospf6_route_table *table);


extern void ospf6_route_show(struct vty *vty, struct ospf6_route *route,
			     json_object *json, bool use_json);
extern void ospf6_route_show_detail(struct vty *vty, struct ospf6_route *route,
				    json_object *json, bool use_json);


extern int ospf6_route_table_show(struct vty *vty, int argc_start, int argc,
				  struct cmd_token **argv,
				  struct ospf6_route_table *table,
				  bool use_json);
extern int ospf6_linkstate_table_show(struct vty *vty, int idx_ipv4, int argc,
				      struct cmd_token **argv,
				      struct ospf6_route_table *table);

extern void ospf6_brouter_show_header(struct vty *vty);
extern void ospf6_brouter_show(struct vty *vty, struct ospf6_route *route);

extern int config_write_ospf6_debug_route(struct vty *vty);
extern void install_element_ospf6_debug_route(void);
extern void ospf6_route_init(void);
extern void ospf6_path_free(struct ospf6_path *op);
extern struct ospf6_path *ospf6_path_dup(struct ospf6_path *path);
extern void ospf6_copy_paths(struct list *dst, struct list *src);

#endif /* OSPF6_ROUTE_H */
