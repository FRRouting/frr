/*
 * OSPF6 Area Data Structure
 * Copyright (C) 1999-2002 Yasuhiro Ohara
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

#include "ospf6d.h"

static int area_index;
#define IS_OSPF6_DUMP_AREA (ospf6_dump_is_on (area_index))

static void
ospf6_area_foreach_interface (struct ospf6_area *o6a, void *arg, int val,
                              void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_interface *o6i;

  for (node = listhead (o6a->if_list); node; nextnode (node))
    {
      o6i = (struct ospf6_interface *) getdata (node);
      (*func) (arg, val, o6i);
    }
}

static void
ospf6_area_foreach_neighbor (struct ospf6_area *o6a, void *arg, int val,
                             void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_interface *o6i;

  for (node = listhead (o6a->if_list); node; nextnode (node))
    {
      o6i = (struct ospf6_interface *) getdata (node);
      (*o6i->foreach_nei) (o6i, arg, val, func);
    }
}

static int
ospf6_area_maxage_remover (struct thread *t)
{
  int count;
  struct ospf6_area *o6a = (struct ospf6_area *) THREAD_ARG (t);

  o6a->maxage_remover = (struct thread *) NULL;

  count = 0;
  o6a->foreach_nei (o6a, &count, NBS_EXCHANGE, ospf6_count_state);
  o6a->foreach_nei (o6a, &count, NBS_LOADING, ospf6_count_state);
  if (count != 0)
    return 0;

  ospf6_lsdb_remove_maxage (o6a->lsdb);
  return 0;
}

void
ospf6_area_schedule_maxage_remover (void *arg, int val, void *obj)
{
  struct ospf6_area *o6a = (struct ospf6_area *) obj;

  if (o6a->maxage_remover != NULL)
    return;

  o6a->maxage_remover =
    thread_add_event (master, ospf6_area_maxage_remover, o6a, 0);
}

int
ospf6_area_is_stub (struct ospf6_area *o6a)
{
  if (OSPF6_OPT_ISSET (o6a->options, OSPF6_OPT_E))
    return 0;
  return 1;
}

int
ospf6_area_is_transit (struct ospf6_area *o6a)
{
  return 0;
}



void
ospf6_area_route_add (void *data)
{
  struct ospf6_route_req *route = data;
  struct in6_addr local;

  inet_pton (AF_INET6, "::1", &local);
  if (! memcmp (&route->nexthop.address, &local, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_AREA)
        zlog_info ("AREA: Self-originated route add, ignore");
      return;
    }

  ospf6_route_add (route, ospf6->route_table);
}

void
ospf6_area_route_remove (void *data)
{
  struct ospf6_route_req *route = data;
  struct in6_addr local;

  inet_pton (AF_INET6, "::1", &local);
  if (! memcmp (&route->nexthop.address, &local, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_AREA)
        zlog_info ("AREA: Self-originated route remove, ignore");
      return;
    }

  ospf6_route_remove (route, ospf6->route_table);
}

/* Make new area structure */
struct ospf6_area *
ospf6_area_create (u_int32_t area_id)
{
  struct ospf6_area *o6a;
  char namebuf[64];

  /* allocate memory */
  o6a = XCALLOC (MTYPE_OSPF6_AREA, sizeof (struct ospf6_area));

  /* initialize */
  inet_ntop (AF_INET, &area_id, o6a->str, sizeof (o6a->str));
  o6a->area_id = area_id;
  o6a->if_list = list_new ();

  o6a->lsdb = ospf6_lsdb_create ();
  o6a->spf_tree = ospf6_spftree_create ();

  snprintf (namebuf, sizeof (namebuf), "Area %s's route table", o6a->str);
  o6a->route_table = ospf6_route_table_create (namebuf);
  o6a->route_table->hook_add = ospf6_area_route_add;
  o6a->route_table->hook_change = ospf6_area_route_add;
  o6a->route_table->hook_remove = ospf6_area_route_remove;

  snprintf (namebuf, sizeof (namebuf), "Area %s's topology table", o6a->str);
  o6a->table_topology = ospf6_route_table_create (namebuf);
  o6a->table_topology->hook_add = ospf6_intra_topology_add;
  o6a->table_topology->hook_change = ospf6_intra_topology_add;
  o6a->table_topology->hook_remove = ospf6_intra_topology_remove;

  /* xxx, set options */
  OSPF6_OPT_SET (o6a->options, OSPF6_OPT_V6);
  OSPF6_OPT_SET (o6a->options, OSPF6_OPT_E);
  OSPF6_OPT_SET (o6a->options, OSPF6_OPT_R);

  o6a->foreach_if = ospf6_area_foreach_interface;
  o6a->foreach_nei = ospf6_area_foreach_neighbor;

  return o6a;
}

void
ospf6_area_bind_top (struct ospf6_area *o6a, struct ospf6 *o6)
{
  o6a->ospf6 = o6;
  CALL_CHANGE_HOOK (&area_hook, o6a);
  return;
}

void
ospf6_area_delete (struct ospf6_area *o6a)
{
  listnode n;
  struct ospf6_interface *o6i;

  CALL_REMOVE_HOOK (&area_hook, o6a);

  /* ospf6 interface list */
  for (n = listhead (o6a->if_list); n; nextnode (n))
    {
      o6i = (struct ospf6_interface *) getdata (n);
      /* ospf6_interface_delete (o6i); */
    }
  list_delete (o6a->if_list);

  /* terminate LSDB */
  ospf6_lsdb_remove_all (o6a->lsdb);

  /* spf tree terminate */
  /* xxx */

  /* threads */
  if (o6a->spf_calc)
    thread_cancel (o6a->spf_calc);
  o6a->spf_calc = (struct thread *) NULL;
  if (o6a->route_calc)
    thread_cancel (o6a->route_calc);
  o6a->route_calc = (struct thread *) NULL;

  /* new */
  ospf6_route_table_delete (o6a->route_table);

  ospf6_spftree_delete (o6a->spf_tree);
  ospf6_route_table_delete (o6a->table_topology);

  /* free area */
  XFREE (MTYPE_OSPF6_AREA, o6a);
}

struct ospf6_area *
ospf6_area_lookup (u_int32_t area_id, struct ospf6 *o6)
{
  struct ospf6_area *o6a;
  listnode n;

  for (n = listhead (o6->area_list); n; nextnode (n))
    {
      o6a = (struct ospf6_area *) getdata (n);
      if (o6a->area_id == area_id)
        return o6a;
    }

  return (struct ospf6_area *) NULL;
}

void
ospf6_area_show (struct vty *vty, struct ospf6_area *o6a)
{
  listnode i;
  struct ospf6_interface *o6i;

  vty_out (vty, " Area %s%s", o6a->str, VTY_NEWLINE);
  vty_out (vty, "     Number of Area scoped LSAs is %u%s",
           o6a->lsdb->count, VTY_NEWLINE);

  ospf6_spf_statistics_show (vty, o6a->spf_tree);

  vty_out (vty, "     Interface attached to this area:");
  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);
      vty_out (vty, " %s", o6i->interface->name);
    }
  vty_out (vty, "%s", VTY_NEWLINE);

  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);
      if (listcount (o6i->neighbor_list) != 0)
        ospf6_interface_statistics_show (vty, o6i);
    }
}

void
ospf6_area_statistics_show (struct vty *vty, struct ospf6_area *o6a)
{
#if 0
  listnode node;
  struct ospf6_interface *o6i;

  vty_out (vty, "  Statistics of Area %s%s", o6a->str, VTY_NEWLINE);
#endif
}

DEFUN (show_ipv6_ospf6_area_route,
       show_ipv6_ospf6_area_route_cmd,
       "show ipv6 ospf6 area A.B.C.D route",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       ROUTE_STR
       )
{
  struct ospf6_area *o6a;
  u_int32_t area_id;

  OSPF6_CMD_CHECK_RUNNING ();

  inet_pton (AF_INET, argv[0], &area_id);
  o6a = ospf6_area_lookup (area_id, ospf6);

  if (! o6a)
    return CMD_SUCCESS;

  argc -= 1;
  argv += 1;

  return ospf6_route_table_show (vty, argc, argv, o6a->route_table);
}

ALIAS (show_ipv6_ospf6_area_route,
       show_ipv6_ospf6_area_route_prefix_cmd,
       "show ipv6 ospf6 area A.B.C.D route (X::X|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       ROUTE_STR
       "Specify IPv6 address\n"
       "Detailed information\n"
       )

void
ospf6_area_init ()
{
  area_index = ospf6_dump_install ("area", "Area information\n");

  install_element (VIEW_NODE, &show_ipv6_ospf6_area_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_route_prefix_cmd);
}


