/*
 * Copyright (C) 2001 Yasuhiro Ohara
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

#include <zebra.h>

#include "log.h"
#include "memory.h"

#include "ospf6_hook.h"

struct ospf6_hook_master neighbor_hook;
struct ospf6_hook_master interface_hook;
struct ospf6_hook_master area_hook;
struct ospf6_hook_master top_hook;
struct ospf6_hook_master database_hook;
struct ospf6_hook_master intra_topology_hook;
struct ospf6_hook_master inter_topology_hook;
struct ospf6_hook_master route_hook;
struct ospf6_hook_master redistribute_hook;

static struct ospf6_hook *
ospf6_hook_create ()
{
  struct ospf6_hook *new;
  new = XMALLOC (MTYPE_OSPF6_OTHER, sizeof (struct ospf6_hook));
  if (new == NULL)
    return NULL;
  memset (new, 0, sizeof (struct ospf6_hook));
  return new;
}

static void
ospf6_hook_delete (struct ospf6_hook *hook)
{
  XFREE (MTYPE_OSPF6_OTHER, hook);
}

static int
ospf6_hook_issame (struct ospf6_hook *hook1, struct ospf6_hook *hook2)
{
  if (hook1->name && hook2->name &&
      strcmp (hook1->name, hook2->name) != 0)
    return 0;
  if (hook1->hook_add != hook2->hook_add)
    return 0;
  if (hook1->hook_change != hook2->hook_change)
    return 0;
  if (hook1->hook_remove != hook2->hook_remove)
    return 0;
  return 1;
}

void
ospf6_hook_register (struct ospf6_hook *hook,
                     struct ospf6_hook_master *master)
{
  struct ospf6_hook *new;

  new = ospf6_hook_create ();

  if (hook->name)
    new->name = strdup (hook->name);
  new->hook_add = hook->hook_add;
  new->hook_change = hook->hook_change;
  new->hook_remove = hook->hook_remove;

  new->prev = master->tail;
  if (master->tail)
    master->tail->next = new;

  master->tail = new;
  if (! master->head)
    master->head = new;

  master->count++;

  if (IS_OSPF6_DUMP_HOOK)
    {
      zlog_info ("HOOK: Register hook%s%s%s%s",
                 (hook->name ? " " : ""),
                 (hook->name ? hook->name : ""),
                 (master->name ? " to " : ""),
                 (master->name ? master->name : ""));
    }
}

void
ospf6_hook_unregister (struct ospf6_hook *req,
                       struct ospf6_hook_master *master)
{
  struct ospf6_hook *hook;

  for (hook = master->head; hook; hook = hook->next)
    {
      if (ospf6_hook_issame (hook, req))
        break;
    }
  if (! hook)
    return;

  if (hook->prev)
    hook->prev->next = hook->next;
  if (hook->next)
    hook->next->prev = hook->prev;
  if (master->head == hook)
    master->head = hook->next;
  if (master->tail == hook)
    master->tail = hook->prev;

  master->count--;

  if (IS_OSPF6_DUMP_HOOK)
    {
      zlog_info ("HOOK: Unregister hook%s%s%s%s",
                 (hook->name ? " " : ""),
                 (hook->name ? hook->name : ""),
                 (master->name ? " to " : ""),
                 (master->name ? master->name : ""));
    }

  if (hook->name)
    free (hook->name);
  ospf6_hook_delete (hook);
}

void
ospf6_hook_unregister_all (struct ospf6_hook_master *master)
{
  struct ospf6_hook *hook, *next;

  for (hook = master->head; hook; hook = next)
    {
      next = hook->next;
      ospf6_hook_delete (hook);
    }

  master->head = NULL;
  master->tail = NULL;
  master->count = 0;
}


void
ospf6_hook_init ()
{
  neighbor_hook.name       =      "Neighbor Hooklist";
  interface_hook.name      =     "Interface Hooklist";
  area_hook.name           =          "Area Hooklist";
  top_hook.name            =           "Top Hooklist";
  database_hook.name       =      "Database Hooklist";
  intra_topology_hook.name = "IntraTopology Hooklist";
  inter_topology_hook.name = "InterTopology Hooklist";
  route_hook.name          =         "Route Hooklist";
}


