/*
 * OSPFv3 Top Level Data Structure
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

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "routemap.h"

/* ospfv3 top level data structure */
struct ospf6
{
  /* process id */
  u_long process_id;

  /* start time */
  struct timeval starttime;

  /* ospf version must be 3 */
  unsigned char version;

  /* my router id */
  u_int32_t router_id;

  /* list of areas */
  list area_list;

  /* AS scope link state database */
  struct ospf6_lsdb *lsdb;

  /* redistribute route-map */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[ZEBRA_ROUTE_MAX];

  struct thread *t_route_calculation;
  u_int stat_route_calculation_execed;

  struct ospf6_route_table *route_table;
  struct ospf6_route_table *topology_table;
  struct ospf6_route_table *external_table;

  void (*foreach_area) (struct ospf6 *, void *arg, int val,
                        void (*func) (void *, int, void *));
  void (*foreach_if)   (struct ospf6 *, void *arg, int val,
                        void (*func) (void *, int, void *));
  void (*foreach_nei)  (struct ospf6 *, void *arg, int val,
                        void (*func) (void *, int, void *));

  struct thread *maxage_remover;

  list nexthop_list;
};
 
extern struct ospf6 *ospf6;

/* prototypes */
int
ospf6_top_count_neighbor_in_state (u_char state, struct ospf6 *o6);

void
ospf6_top_schedule_maxage_remover (void *arg, int val, struct ospf6 *o6);

void ospf6_show (struct vty *);
void ospf6_statistics_show (struct vty *vty, struct ospf6 *o6);

struct ospf6 *ospf6_start ();
void ospf6_stop ();

void ospf6_delete (struct ospf6 *);
int ospf6_is_asbr (struct ospf6 *);

void ospf6_top_init ();

#endif /* OSPF6_TOP_H */

