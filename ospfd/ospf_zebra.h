// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_ZEBRA_H
#define _ZEBRA_OSPF_ZEBRA_H

#include "vty.h"
#include "hook.h"

#define EXTERNAL_METRIC_TYPE_1      0
#define EXTERNAL_METRIC_TYPE_2      1

#define DEFAULT_ROUTE		    ZEBRA_ROUTE_MAX
#define DEFAULT_ROUTE_TYPE(T) ((T) == DEFAULT_ROUTE)

/* OSPF distance. */
struct ospf_distance {
	/* Distance value for the IP source prefix. */
	uint8_t distance;

	/* Name of the access-list to be matched. */
	char *access_list;
};

/* Prototypes */
struct ospf_route;
extern void ospf_zebra_add(struct ospf *ospf, struct prefix_ipv4 *,
			   struct ospf_route *);
extern void ospf_zebra_delete(struct ospf *ospf, struct prefix_ipv4 *,
			      struct ospf_route *);

extern void ospf_zebra_add_discard(struct ospf *ospf, struct prefix_ipv4 *);
extern void ospf_zebra_delete_discard(struct ospf *ospf, struct prefix_ipv4 *);

extern int ospf_redistribute_check(struct ospf *, struct external_info *,
				   int *);
extern int ospf_distribute_check_connected(struct ospf *,
					   struct external_info *);
extern void ospf_distribute_list_update(struct ospf *, int, unsigned short);

extern int ospf_is_type_redistributed(struct ospf *, int, unsigned short);
extern void ospf_distance_reset(struct ospf *);
extern uint8_t ospf_distance_apply(struct ospf *ospf, struct prefix_ipv4 *,
				   struct ospf_route *);
extern struct ospf_external *ospf_external_lookup(struct ospf *, uint8_t,
						  unsigned short);
extern struct ospf_external *ospf_external_add(struct ospf *, uint8_t,
					       unsigned short);

struct sr_prefix;
struct sr_nhlfe;
extern void ospf_zebra_update_prefix_sid(const struct sr_prefix *srp);
extern void ospf_zebra_delete_prefix_sid(const struct sr_prefix *srp);
extern void ospf_zebra_send_adjacency_sid(int cmd, struct sr_nhlfe nhlfe);

extern void ospf_external_del(struct ospf *, uint8_t, unsigned short);
extern struct ospf_redist *ospf_redist_lookup(struct ospf *, uint8_t,
					      unsigned short);
extern struct ospf_redist *ospf_redist_add(struct ospf *, uint8_t,
					   unsigned short);
extern void ospf_redist_del(struct ospf *, uint8_t, unsigned short);

extern int ospf_redistribute_update(struct ospf *, struct ospf_redist *, int,
				    unsigned short, int, int);
extern int ospf_redistribute_set(struct ospf *, struct ospf_redist *, int,
				 unsigned short, int, int);
extern int ospf_redistribute_unset(struct ospf *, int, unsigned short);
extern int ospf_redistribute_default_set(struct ospf *, int, int, int);
extern void ospf_zebra_import_default_route(struct ospf *ospf, bool unreg);
extern int ospf_distribute_list_out_set(struct ospf *, int, const char *);
extern int ospf_distribute_list_out_unset(struct ospf *, int, const char *);
extern void ospf_routemap_set(struct ospf_redist *, const char *);
extern void ospf_routemap_unset(struct ospf_redist *);
extern int ospf_zebra_gr_enable(struct ospf *ospf, uint32_t stale_time);
extern int ospf_zebra_gr_disable(struct ospf *ospf);
extern int ospf_distance_set(struct vty *, struct ospf *, const char *,
			     const char *, const char *);
extern int ospf_distance_unset(struct vty *, struct ospf *, const char *,
			       const char *, const char *);
extern void ospf_zebra_init(struct event_loop *m, unsigned short instance);
extern void ospf_zebra_vrf_register(struct ospf *ospf);
extern void ospf_zebra_vrf_deregister(struct ospf *ospf);
bool ospf_external_default_routemap_apply_walk(
	struct ospf *ospf, struct list *ext_list,
	struct external_info *default_ei);
int ospf_external_info_apply_default_routemap(struct ospf *ospf,
					      struct external_info *ei,
					      struct external_info *default_ei);

extern void ospf_zebra_send_arp(const struct interface *ifp,
				const struct prefix *p);
bool ospf_zebra_label_manager_ready(void);
int ospf_zebra_label_manager_connect(void);
int ospf_zebra_request_label_range(uint32_t base, uint32_t chunk_size);
int ospf_zebra_release_label_range(uint32_t start, uint32_t end);
#endif /* _ZEBRA_OSPF_ZEBRA_H */
