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

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "vty.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "command.h"

#include "ospf6_hook.h"
#include "ospf6_proto.h"
#include "ospf6_prefix.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_area.h"
#include "ospf6_top.h"

#include "ospf6_route.h"
#include "ospf6_zebra.h"

#include "ospf6_nsm.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"

#define HEADER_DEPENDENCY
#include "ospf6d.h"
#undef HEADER_DEPENDENCY

/* global ospf6d variable */
struct ospf6 *ospf6;

static void
ospf6_top_foreach_area (struct ospf6 *o6, void *arg, int val,
                        void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_area *o6a;

  for (node = listhead (o6->area_list); node; nextnode (node))
    {
      o6a = (struct ospf6_area *) getdata (node);
      (*func) (arg, val, o6a);
    }
}

static void
ospf6_top_foreach_interface (struct ospf6 *o6, void *arg, int val,
                             void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_area *o6a;

  for (node = listhead (o6->area_list); node; nextnode (node))
    {
      o6a = (struct ospf6_area *) getdata (node);
      (*o6a->foreach_if) (o6a, arg, val, func);
    }
}

static void
ospf6_top_foreach_neighbor (struct ospf6 *o6, void *arg, int val,
                            void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_area *o6a;

  for (node = listhead (o6->area_list); node; nextnode (node))
    {
      o6a = (struct ospf6_area *) getdata (node);
      (*o6a->foreach_nei) (o6a, arg, val, func);
    }
}

static int
ospf6_top_maxage_remover (struct thread *t)
{
  int count;
  struct ospf6 *o6 = (struct ospf6 *) THREAD_ARG (t);

  o6->maxage_remover = (struct thread *) NULL;

  count = 0;
  o6->foreach_nei (o6, &count, NBS_EXCHANGE, ospf6_count_state);
  o6->foreach_nei (o6, &count, NBS_LOADING, ospf6_count_state);
  if (count != 0)
    return 0;

  ospf6_lsdb_remove_maxage (o6->lsdb);
  return 0;
}

void
ospf6_top_schedule_maxage_remover (void *arg, int val, struct ospf6 *o6)
{
  if (o6->maxage_remover != NULL)
    return;

  o6->maxage_remover =
    thread_add_event (master, ospf6_top_maxage_remover, o6, 0);
}

void
ospf6_show (struct vty *vty)
{
  listnode n;
  struct ospf6_area *area;
  char id_string[32];
  unsigned long day, hour, min, sec;
  struct timeval now, running;

  /* process id, router id */
  inet_ntop (AF_INET, &ospf6->router_id, id_string, sizeof (id_string));
  vty_out (vty, " Routing Process (%lu) with ID %s%s",
           ospf6->process_id, id_string, VTY_NEWLINE);

  /* running time */
  gettimeofday (&now, (struct timezone *)NULL);
  ospf6_timeval_sub (&now, &ospf6->starttime, &running);
  ospf6_timeval_decode (&running, &day, &hour, &min, &sec, NULL, NULL);
  vty_out (vty, " Running %ld days %ld hours %ld minutes %ld seconds%s",
           day, hour, min, sec, VTY_NEWLINE);

  vty_out (vty, " Supports only single TOS(TOS0) routes%s", VTY_NEWLINE);

  /* Redistribute config */
  ospf6_redistribute_show_config (vty);

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           ospf6->lsdb->count, VTY_NEWLINE);
  vty_out (vty, " Route calculation executed %d times%s",
           ospf6->stat_route_calculation_execed, VTY_NEWLINE);

  /* Route Statistics */
#if 0
  ospf6_route_statistics_show (vty, ospf6->route_table);
#endif

  /* Areas */
  vty_out (vty, " Number of areas in this router is %u%s",
           listcount (ospf6->area_list), VTY_NEWLINE);
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct ospf6_area *) getdata (n);
      ospf6_area_show (vty, area);
    }
}

void
ospf6_statistics_show (struct vty *vty, struct ospf6 *o6)
{
  listnode node;
  struct ospf6_area *o6a;
  char running_time[128];
  struct timeval now, running;

  gettimeofday (&now, (struct timezone *) NULL);
  ospf6_timeval_sub (&now, &o6->starttime, &running);
  ospf6_timeval_string (&running, running_time, sizeof (running_time));

  vty_out (vty, "Statistics of OSPF process %ld%s",
           o6->process_id, VTY_NEWLINE);
  vty_out (vty, "  Running: %s%s", running_time, VTY_NEWLINE);

#if 0
  ospf6_route_statistics_show (vty, o6->route_table);
#endif

  for (node = listhead (o6->area_list); node; nextnode (node))
    {
      o6a = (struct ospf6_area *) getdata (node);
      ospf6_area_statistics_show (vty, o6a);
    }
}

static struct ospf6 *
ospf6_new ()
{
  struct ospf6 *new;
  new = XMALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));
  if (new)
    memset (new, 0, sizeof (struct ospf6));
  return new;
}

void
ospf6_free (struct ospf6 *ospf6)
{
  XFREE (MTYPE_OSPF6_TOP, ospf6);
}

void
ospf6_top_topology_add (struct ospf6_route_req *request)
{
  assert (request->route.type == OSPF6_DEST_TYPE_ROUTER);
  if (CHECK_FLAG (request->path.router_bits, OSPF6_ROUTER_LSA_BIT_E))
    ospf6_asbr_asbr_entry_add (request);
}

void
ospf6_top_topology_remove (struct ospf6_route_req *request)
{
  assert (request->route.type == OSPF6_DEST_TYPE_ROUTER);
  if (CHECK_FLAG (request->path.router_bits, OSPF6_ROUTER_LSA_BIT_E))
    ospf6_asbr_asbr_entry_remove (request);
}

struct ospf6 *
ospf6_create (unsigned long process_id)
{
  struct ospf6 *o6;
  char namebuf[64];

  o6 = ospf6_new ();

  /* initialize */
  gettimeofday (&o6->starttime, (struct timezone *)NULL);
  o6->process_id = process_id;
  o6->version = OSPF6_VERSION;
  o6->area_list = list_new ();

  o6->lsdb = ospf6_lsdb_create ();

  o6->foreach_area = ospf6_top_foreach_area;
  o6->foreach_if = ospf6_top_foreach_interface;
  o6->foreach_nei = ospf6_top_foreach_neighbor;

  snprintf (namebuf, sizeof (namebuf), "InterTopology table");
  o6->topology_table = ospf6_route_table_create (namebuf);
  ospf6_route_hook_register (ospf6_top_topology_add,
                             ospf6_top_topology_add,
                             ospf6_top_topology_remove,
                             o6->topology_table);

#if 0
  snprintf (namebuf, sizeof (namebuf), "External table");
  o6->external_table = ospf6_route_table_create (namebuf);
  ospf6_route_hook_register (ospf6_asbr_external_route_add,
                             ospf6_asbr_external_route_add,
                             ospf6_asbr_external_route_remove,
                             o6->external_table);
#endif /*0*/

  snprintf (namebuf, sizeof (namebuf), "Top route table");
  o6->route_table = ospf6_route_table_create (namebuf);
  ospf6_route_hook_register (ospf6_zebra_route_update_add,
                             ospf6_zebra_route_update_add,
                             ospf6_zebra_route_update_remove,
                             o6->route_table);
  ospf6_route_hook_register (ospf6_abr_route_add,
                             ospf6_abr_route_add,
                             ospf6_abr_route_remove,
                             o6->route_table);

  return o6;
}

void
ospf6_delete (struct ospf6 *ospf6)
{
  ospf6_route_remove_all (ospf6->route_table);
  ospf6_free (ospf6);
}

struct ospf6 *
ospf6_start ()
{
  if (ospf6)
    return ospf6;

  ospf6 = ospf6_create (0);
  return ospf6;
}

void
ospf6_stop ()
{
  if (!ospf6)
    return;

  ospf6_delete (ospf6);
  ospf6 = NULL;
}

int
ospf6_is_asbr (struct ospf6 *o6)
{
  int i = 0;
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_SYSTEM);
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_CONNECT);
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_STATIC);
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_KERNEL);
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_RIPNG);
  i |= ospf6_zebra_is_redistribute (ZEBRA_ROUTE_BGP);
  return (i);
}

DEFUN (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_cmd,
       "show ipv6 ospf6 route",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Routing table\n"
       )
{
  OSPF6_CMD_CHECK_RUNNING ();
  return ospf6_route_table_show (vty, argc, argv, ospf6->route_table);
}

ALIAS (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_prefix_cmd,
       "show ipv6 ospf6 route (X::X|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Routing table\n"
       "match IPv6 prefix\n"
       )

DEFUN (show_ipv6_ospf6_topology,
       show_ipv6_ospf6_topology_cmd,
       "show ipv6 ospf6 topology",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Inter Area topology information\n"
       )
{
  OSPF6_CMD_CHECK_RUNNING ();
  return ospf6_route_table_show (vty, argc, argv, ospf6->topology_table);
}

ALIAS (show_ipv6_ospf6_topology,
       show_ipv6_ospf6_topology_router_cmd,
       "show ipv6 ospf6 topology (A.B.C.D|<0-4294967295>|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Inter Area topology information\n"
       OSPF6_ROUTER_ID_STR
       OSPF6_ROUTER_ID_STR
       "Detailed information\n"
       )

ALIAS (show_ipv6_ospf6_topology,
       show_ipv6_ospf6_topology_router_lsid_cmd,
       "show ipv6 ospf6 topology (A.B.C.D|<0-4294967295>) (A.B.C.D|<0-4294967295>)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Inter Area topology information\n"
       OSPF6_ROUTER_ID_STR
       OSPF6_ROUTER_ID_STR
       OSPF6_LS_ID_STR
       OSPF6_LS_ID_STR
       )

void
ospf6_top_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_topology_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_topology_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_topology_router_lsid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_topology_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_topology_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_topology_router_lsid_cmd);
}

