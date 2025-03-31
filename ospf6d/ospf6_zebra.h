// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_ZEBRA_H
#define OSPF6_ZEBRA_H

#include "zclient.h"

#define DEFAULT_ROUTE ZEBRA_ROUTE_MAX

/* Debug option */
extern unsigned char conf_debug_ospf6_zebra;
#define OSPF6_DEBUG_ZEBRA_SEND 0x01
#define OSPF6_DEBUG_ZEBRA_RECV 0x02
#define OSPF6_DEBUG_ZEBRA_ON(level) (conf_debug_ospf6_zebra |= level)
#define OSPF6_DEBUG_ZEBRA_OFF(level) (conf_debug_ospf6_zebra &= ~(level))
#define IS_OSPF6_DEBUG_ZEBRA(e) (conf_debug_ospf6_zebra & OSPF6_DEBUG_ZEBRA_##e)

/* OSPF6 distance */
struct ospf6_distance {
	/* Distance value for the IP source prefix */
	uint8_t distance;

	/* Name of the access-list to be matched */
	char *access_list;
};

extern struct zclient *zclient;
struct ospf6;

extern void ospf6_zebra_route_update_add(struct ospf6_route *request,
					 struct ospf6 *ospf6);
extern void ospf6_zebra_route_update_remove(struct ospf6_route *request,
					    struct ospf6 *ospf6);

extern void ospf6_zebra_redistribute(int, vrf_id_t vrf_id);
extern void ospf6_zebra_no_redistribute(int, vrf_id_t vrf_id);
#define ospf6_zebra_is_redistribute(type, vrf_id)                              \
	vrf_bitmap_check(&zclient->redist[AFI_IP6][type], vrf_id)
extern void ospf6_zebra_init(struct event_loop *tm);
extern void ospf6_zebra_import_default_route(struct ospf6 *ospf6, bool unreg);
extern void ospf6_zebra_add_discard(struct ospf6_route *request,
				    struct ospf6 *ospf6);
extern void ospf6_zebra_delete_discard(struct ospf6_route *request,
				       struct ospf6 *ospf6);

extern void ospf6_distance_reset(struct ospf6 *ospf6);
extern uint8_t ospf6_distance_apply(struct prefix_ipv6 *p,
				    struct ospf6_route * or,
				    struct ospf6 *ospf6);

extern int ospf6_zebra_gr_enable(struct ospf6 *ospf6, uint32_t stale_time);
extern int ospf6_zebra_gr_disable(struct ospf6 *ospf6);
extern int ospf6_distance_set(struct vty *vty, struct ospf6 *ospf6,
			      const char *distance_str, const char *ip_str,
			      const char *access_list_str);
extern int ospf6_distance_unset(struct vty *vty, struct ospf6 *ospf6,
				const char *distance_str, const char *ip_str,
				const char *access_list_str);

extern int config_write_ospf6_debug_zebra(struct vty *vty);
extern void install_element_ospf6_debug_zebra(void);
extern void ospf6_zebra_vrf_register(struct ospf6 *ospf6);
extern void ospf6_zebra_vrf_deregister(struct ospf6 *ospf6);
#endif /*OSPF6_ZEBRA_H*/
