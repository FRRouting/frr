/*
 * OSPF6 Area Data Structure
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#ifndef OSPF_AREA_H
#define OSPF_AREA_H

/* This file defines area parameters and data structures. */

#define OSPF6_AREA_RANGE_ADVERTISE     0
#define OSPF6_AREA_RANGE_NOT_ADVERTISE 1

#include "ospf6_spf.h"
#include "ospf6_top.h"

struct ospf6_area
{
  char            str[16];

  struct ospf6   *ospf6;      /* back pointer */
  u_int32_t       area_id;
  u_char          options[3]; /* OSPF Option including ExternalCapability */

  list            if_list; /* OSPF interface to this area */

  struct ospf6_lsdb *lsdb;

  struct thread  *spf_calc;
  struct thread  *route_calc;
  int             stat_spf_execed;
  int             stat_route_execed;

  struct route_table *table; /* new route table */

  struct prefix_ipv6 area_range;
  struct ospf6_spftree *spf_tree;

  struct ospf6_route_table *route_table;
  struct ospf6_route_table *table_topology;

  void (*foreach_if)  (struct ospf6_area *, void *, int,
                       void (*func) (void *, int, void *));
  void (*foreach_nei) (struct ospf6_area *, void *, int,
                       void (*func) (void *, int, void *));

  struct thread *maxage_remover;

  struct thread *thread_router_lsa;
};


/* prototypes */

int
ospf6_area_count_neighbor_in_state (u_char state, struct ospf6_area *o6a);

void
ospf6_area_schedule_maxage_remover (void *arg, int val, void *obj);

int ospf6_area_is_stub (struct ospf6_area *o6a);
int ospf6_area_is_transit (struct ospf6_area *o6a);
struct ospf6_area *ospf6_area_lookup (u_int32_t, struct ospf6 *);
struct ospf6_area *ospf6_area_create (u_int32_t);
void ospf6_area_delete (struct ospf6_area *);
void ospf6_area_show (struct vty *, struct ospf6_area *);
void
ospf6_area_statistics_show (struct vty *vty, struct ospf6_area *o6a);

void ospf6_area_init ();

#endif /* OSPF_AREA_H */

