/*
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

#ifndef OSPF6_SPF_H
#define OSPF6_SPF_H

#include "prefix.h"

/* Transit Vertex */
struct ospf6_vertex
{
  /* type of this vertex */
  u_int8_t type;

  /* Vertex Identifier */
  struct prefix_ls vertex_id;

  /* Identifier String */
  char string[128];

  /* Associated LSA */
  struct ospf6_lsa *lsa;

  /* Distance from Root (Cost) */
  u_int16_t distance;

  /* Depth of this node */
  u_char depth;

  /* nexthops to this node */
  struct linklist *nexthop_list;

  /* upper nodes in spf tree */
  list parent_list;

  /* lower nodes in spf tree */
  list path_list;

  /* capability bits */
  u_char capability_bits;

  /* Optional capabilities */
  u_char opt_capability[3];
};

#define OSPF6_VERTEX_TYPE_ROUTER  0x01
#define OSPF6_VERTEX_TYPE_NETWORK 0x02

struct ospf6_spftree
{
  /* calculation thread */
  struct thread *t_spf_calculation;

  /* root of this tree */
  struct ospf6_vertex *root;

  /* list for search */
  list list;

  /* statistics */
  u_int32_t timerun;

  struct timeval runtime_total;
  struct timeval runtime_min;
  struct timeval runtime_max;

  struct timeval updated_time;
  struct timeval interval_total;
  struct timeval interval_min;
  struct timeval interval_max;
};

int ospf6_spf_calculate_route (void *);

void
ospf6_spf_calculation_schedule (u_int32_t area_id);
struct ospf6_spftree *ospf6_spftree_create ();
void
ospf6_spf_statistics_show (struct vty *vty, struct ospf6_spftree *spf_tree);
void ospf6_spftree_delete (struct ospf6_spftree *spf_tree);

void ospf6_spf_database_hook (struct ospf6_lsa *old, struct ospf6_lsa *new);

void ospf6_spf_init ();

#endif /* OSPF6_SPF_H */

