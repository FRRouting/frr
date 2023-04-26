// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol               - isis_route.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
 */
#ifndef _ZEBRA_ISIS_ROUTE_H
#define _ZEBRA_ISIS_ROUTE_H

#include "lib/nexthop.h"

struct isis_nexthop {
	ifindex_t ifindex;
	int family;
	union g_addr ip;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	struct isis_sr_psid_info sr;
	struct mpls_label_stack *label_stack;
};

struct isis_route_info {
#define ISIS_ROUTE_FLAG_ACTIVE       0x01  /* active route for the prefix */
#define ISIS_ROUTE_FLAG_ZEBRA_SYNCED 0x02  /* set when route synced to zebra */
#define ISIS_ROUTE_FLAG_ZEBRA_RESYNC 0x04  /* set when route needs to sync */
	uint8_t flag;
	uint32_t cost;
	uint32_t depth;
	struct isis_sr_psid_info sr_algo[SR_ALGORITHM_COUNT];
	struct isis_sr_psid_info sr_algo_previous[SR_ALGORITHM_COUNT];
	struct list *nexthops;
	struct isis_route_info *backup;
};

struct isis_route_table_info {
	uint8_t algorithm;
};

DECLARE_HOOK(isis_route_update_hook,
	     (struct isis_area * area, struct prefix *prefix,
	      struct isis_route_info *route_info),
	     (area, prefix, route_info));

void isis_nexthop_delete(struct isis_nexthop *nexthop);
void adjinfo2nexthop(int family, struct list *nexthops,
		     struct isis_adjacency *adj, struct isis_sr_psid_info *sr,
		     struct mpls_label_stack *label_stack);
struct isis_route_info *
isis_route_create(struct prefix *prefix, struct prefix_ipv6 *src_p,
		  uint32_t cost, uint32_t depth, struct isis_sr_psid_info *sr,
		  struct list *adjacencies, bool allow_ecmp,
		  struct isis_area *area, struct route_table *table);
void isis_route_delete(struct isis_area *area, struct route_node *rode,
		       struct route_table *table);

/* Walk the given table and install new routes to zebra and remove old ones.
 * route status is tracked using ISIS_ROUTE_FLAG_ACTIVE */
void isis_route_verify_table(struct isis_area *area, struct route_table *table,
			     struct route_table *table_backup, int tree);

/* Same as isis_route_verify_table, but merge L1 and L2 routes before */
void isis_route_verify_merge(struct isis_area *area,
			     struct route_table *level1_table,
			     struct route_table *level1_table_backup,
			     struct route_table *level2_table,
			     struct route_table *level2_table_backup, int tree);

/* Unset ISIS_ROUTE_FLAG_ACTIVE on all routes. Used before running spf. */
void isis_route_invalidate_table(struct isis_area *area,
				 struct route_table *table);

/* Cleanup route node when freeing routing table. */
void isis_route_node_cleanup(struct route_table *table,
			     struct route_node *node);


void isis_route_switchover_nexthop(struct isis_area *area,
				   struct route_table *table, int family,
				   union g_addr *nexthop_addr,
				   ifindex_t ifindex);

struct isis_route_table_info *isis_route_table_info_alloc(uint8_t algorithm);
void isis_route_table_info_free(void *info);
uint8_t isis_route_table_algorithm(const struct route_table *table);

#endif /* _ZEBRA_ISIS_ROUTE_H */
