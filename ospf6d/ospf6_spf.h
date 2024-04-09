// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_SPF_H
#define OSPF6_SPF_H

#include "typesafe.h"
#include "ospf6_top.h"
#include "lib/json.h"

/* Debug option */
extern unsigned char conf_debug_ospf6_spf;
#define OSPF6_DEBUG_SPF_PROCESS   0x01
#define OSPF6_DEBUG_SPF_TIME      0x02
#define OSPF6_DEBUG_SPF_DATABASE  0x04
#define OSPF6_DEBUG_SPF_ON(level) (conf_debug_ospf6_spf |= (level))
#define OSPF6_DEBUG_SPF_OFF(level) (conf_debug_ospf6_spf &= ~(level))
#define IS_OSPF6_DEBUG_SPF(level)                                              \
	(conf_debug_ospf6_spf & OSPF6_DEBUG_SPF_##level)

#define OSPF6_ASE_CALC_INTERVAL 1

PREDECL_SKIPLIST_NONUNIQ(vertex_pqueue);
/* Transit Vertex */
struct ospf6_vertex {
	/* type of this vertex */
	uint8_t type;

	/* Vertex Identifier */
	struct prefix vertex_id;

	struct vertex_pqueue_item pqi;

	/* Identifier String */
	char name[128];

	/* Associated Area */
	struct ospf6_area *area;

	/* Associated LSA */
	struct ospf6_lsa *lsa;

	/* Distance from Root (i.e. Cost) */
	uint32_t cost;

	/* Router hops to this node */
	uint8_t hops;

	/* capability bits */
	uint8_t capability;

	/* Optional capabilities */
	uint8_t options[3];

	/* For tree display */
	struct ospf6_vertex *parent;
	struct list *child_list;

	/* nexthops to this node */
	struct list *nh_list;
	uint32_t link_id;
};

#define OSPF6_VERTEX_TYPE_ROUTER  0x01
#define OSPF6_VERTEX_TYPE_NETWORK 0x02
#define VERTEX_IS_TYPE(t, v) ((v)->type == OSPF6_VERTEX_TYPE_##t ? 1 : 0)

/* What triggered the SPF? */
#define OSPF6_SPF_FLAGS_ROUTER_LSA_ADDED         (1 << 0)
#define OSPF6_SPF_FLAGS_ROUTER_LSA_REMOVED       (1 << 1)
#define OSPF6_SPF_FLAGS_NETWORK_LSA_ADDED        (1 << 2)
#define OSPF6_SPF_FLAGS_NETWORK_LSA_REMOVED      (1 << 3)
#define OSPF6_SPF_FLAGS_LINK_LSA_ADDED           (1 << 4)
#define OSPF6_SPF_FLAGS_LINK_LSA_REMOVED         (1 << 5)
#define OSPF6_SPF_FLAGS_ROUTER_LSA_ORIGINATED    (1 << 6)
#define OSPF6_SPF_FLAGS_NETWORK_LSA_ORIGINATED   (1 << 7)
#define OSPF6_SPF_FLAGS_CONFIG_CHANGE            (1 << 8)
#define OSPF6_SPF_FLAGS_ASBR_STATUS_CHANGE       (1 << 9)
#define OSPF6_SPF_FLAGS_GR_FINISH                (1 << 10)

static inline void ospf6_set_spf_reason(struct ospf6 *ospf, unsigned int reason)
{
	ospf->spf_reason |= reason;
}

static inline void ospf6_reset_spf_reason(struct ospf6 *ospf)
{
	ospf->spf_reason = 0;
}

static inline unsigned int ospf6_lsadd_to_spf_reason(struct ospf6_lsa *lsa)
{
	unsigned int reason = 0;

	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_ROUTER:
		reason = OSPF6_SPF_FLAGS_ROUTER_LSA_ADDED;
		break;
	case OSPF6_LSTYPE_NETWORK:
		reason = OSPF6_SPF_FLAGS_NETWORK_LSA_ADDED;
		break;
	case OSPF6_LSTYPE_LINK:
		reason = OSPF6_SPF_FLAGS_LINK_LSA_ADDED;
		break;
	default:
		break;
	}
	return (reason);
}

static inline unsigned int ospf6_lsremove_to_spf_reason(struct ospf6_lsa *lsa)
{
	unsigned int reason = 0;

	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_ROUTER:
		reason = OSPF6_SPF_FLAGS_ROUTER_LSA_REMOVED;
		break;
	case OSPF6_LSTYPE_NETWORK:
		reason = OSPF6_SPF_FLAGS_NETWORK_LSA_REMOVED;
		break;
	case OSPF6_LSTYPE_LINK:
		reason = OSPF6_SPF_FLAGS_LINK_LSA_REMOVED;
		break;
	default:
		break;
	}
	return (reason);
}

extern void ospf6_spf_table_finish(struct ospf6_route_table *result_table);
extern void ospf6_spf_calculation(uint32_t router_id,
				  struct ospf6_route_table *result_table,
				  struct ospf6_area *oa);
extern void ospf6_spf_schedule(struct ospf6 *ospf, unsigned int reason);

extern void ospf6_spf_display_subtree(struct vty *vty, const char *prefix,
				      int rest, struct ospf6_vertex *v,
				      json_object *json_obj, bool use_json);

extern void ospf6_spf_config_write(struct vty *vty, struct ospf6 *ospf6);
extern int config_write_ospf6_debug_spf(struct vty *vty);
extern void install_element_ospf6_debug_spf(void);
extern void ospf6_spf_init(void);
extern void ospf6_spf_reason_string(unsigned int reason, char *buf, int size);
extern struct ospf6_lsa *ospf6_create_single_router_lsa(struct ospf6_area *area,
							struct ospf6_lsdb *lsdb,
							uint32_t adv_router);
extern void ospf6_remove_temp_router_lsa(struct ospf6_area *area);
extern void ospf6_ase_calculate_timer_add(struct ospf6 *ospf6);
extern int ospf6_ase_calculate_route(struct ospf6 *ospf6, struct ospf6_lsa *lsa,
				     struct ospf6_area *area);
extern bool
ospf6_merge_parents_nh_to_child(struct ospf6_vertex *v,
				struct ospf6_route *route,
				struct ospf6_route_table *result_table);
#endif /* OSPF6_SPF_H */
