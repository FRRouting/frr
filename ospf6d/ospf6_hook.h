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

#ifndef OSPF6_HOOK_H
#define OSPF6_HOOK_H

#include "ospf6_dump.h"

struct ospf6_hook
{
  struct ospf6_hook *prev;
  struct ospf6_hook *next;

  char *name;
  int (*hook_add) (void *);
  int (*hook_change) (void *);
  int (*hook_remove) (void *);
};

struct ospf6_hook_master
{
  char *name;
  struct ospf6_hook *head;
  struct ospf6_hook *tail;
  int count;
};

#define CALL_HOOKS(master,hookname,hookstr,data) \
  {\
    struct ospf6_hook *hook;\
    for (hook = (master)->head; hook; hook = hook->next)\
      {\
        if (hook->hookname)\
          {\
            if (IS_OSPF6_DUMP_HOOK)\
              zlog_info ("HOOK: Call %s hook: %s", (hookstr), hook->name);\
            (*(hook->hookname)) (data);\
          }\
      }\
  }
#define CALL_ADD_HOOK(master,data) \
  { CALL_HOOKS ((master), hook_add, "ADD", (data)) }
#define CALL_CHANGE_HOOK(master,data) \
  { CALL_HOOKS ((master), hook_change, "CHANGE", (data)) }
#define CALL_REMOVE_HOOK(master,data) \
  { CALL_HOOKS ((master), hook_remove, "REMOVE", (data)) }

#define IS_HOOK_SET(hook) \
  ((hook)->hook_add || (hook)->hook_change || (hook)->hook_remove)

extern struct ospf6_hook_master neighbor_hook;
extern struct ospf6_hook_master interface_hook;
extern struct ospf6_hook_master area_hook;
extern struct ospf6_hook_master top_hook;
extern struct ospf6_hook_master database_hook;
extern struct ospf6_hook_master intra_topology_hook;
extern struct ospf6_hook_master inter_topology_hook;
extern struct ospf6_hook_master route_hook;
extern struct ospf6_hook_master redistribute_hook;

void ospf6_hook_register (struct ospf6_hook *,
                          struct ospf6_hook_master *);
void ospf6_hook_unregister (struct ospf6_hook *,
                            struct ospf6_hook_master *);
void ospf6_hook_unregister_all (struct ospf6_hook_master *);
void ospf6_hook_init ();

#endif /*OSPF6_HOOK_H*/

