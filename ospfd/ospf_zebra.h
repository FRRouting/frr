/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
extern void ospf_external_del(struct ospf *, uint8_t, unsigned short);
extern struct ospf_redist *ospf_redist_lookup(struct ospf *, uint8_t,
					      unsigned short);
extern struct ospf_redist *ospf_redist_add(struct ospf *, uint8_t,
					   unsigned short);
extern void ospf_redist_del(struct ospf *, uint8_t, unsigned short);


extern int ospf_redistribute_set(struct ospf *, int, unsigned short, int, int);
extern int ospf_redistribute_unset(struct ospf *, int, unsigned short);
extern int ospf_redistribute_default_set(struct ospf *, int, int, int);
extern int ospf_redistribute_default_unset(struct ospf *);
extern int ospf_distribute_list_out_set(struct ospf *, int, const char *);
extern int ospf_distribute_list_out_unset(struct ospf *, int, const char *);
extern void ospf_routemap_set(struct ospf_redist *, const char *);
extern void ospf_routemap_unset(struct ospf_redist *);
extern int ospf_distance_set(struct vty *, struct ospf *, const char *,
			     const char *, const char *);
extern int ospf_distance_unset(struct vty *, struct ospf *, const char *,
			       const char *, const char *);
extern void ospf_zebra_init(struct thread_master *, unsigned short);
extern void ospf_zebra_vrf_register(struct ospf *ospf);
extern void ospf_zebra_vrf_deregister(struct ospf *ospf);

DECLARE_HOOK(ospf_if_update, (struct interface * ifp), (ifp))
DECLARE_HOOK(ospf_if_delete, (struct interface * ifp), (ifp))

#endif /* _ZEBRA_OSPF_ZEBRA_H */
