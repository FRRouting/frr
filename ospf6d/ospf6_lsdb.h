/*
 * Copyright (C) 2002 Yasuhiro Ohara
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

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#include "prefix.h"
#include "table.h"

#include "ospf6_prefix.h"
#include "ospf6_lsa.h"

struct ospf6_lsdb_node
{
  struct prefix_ipv6 key;

  struct route_node *node;
  struct route_node *next;

  struct ospf6_lsa *lsa;
};

struct ospf6_lsdb
{
  struct route_table *table;
  u_int32_t count;
  void (*hook) (struct ospf6_lsa *);
};

/* int  ospf6_lsdb_is_end (struct ospf6_lsdb_node *lsdb_node); */
#define ospf6_lsdb_is_end(lsdb_node) ((lsdb_node)->node == NULL ? 1 : 0)

/* global holding hooks for each LS type */
struct ospf6_lsdb_hook_t
{
  void (*hook) (struct ospf6_lsa *old, struct ospf6_lsa *new);
};
extern struct ospf6_lsdb_hook_t *ospf6_lsdb_hook;

/* Function Prototypes */
struct ospf6_lsdb * ospf6_lsdb_create ();
void ospf6_lsdb_delete (struct ospf6_lsdb *lsdb);

void ospf6_lsdb_remove_maxage (struct ospf6_lsdb *lsdb);

struct ospf6_lsa *
ospf6_lsdb_lookup (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   void *scope);

void ospf6_lsdb_install (struct ospf6_lsa *new);

void ospf6_lsdb_head (struct ospf6_lsdb_node *node, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_type (struct ospf6_lsdb_node *node, u_int16_t type,
                      struct ospf6_lsdb *lsdb);
void ospf6_lsdb_type_router (struct ospf6_lsdb_node *node, u_int16_t type,
                             u_int32_t adv_router, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_next (struct ospf6_lsdb_node *node);

void ospf6_lsdb_add (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_remove (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_remove_all (struct ospf6_lsdb *lsdb);

struct ospf6_lsa *
ospf6_lsdb_lookup_lsdb (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                        struct ospf6_lsdb *lsdb);

void ospf6_lsdb_init ();

#endif /* OSPF6_LSDB_H */

