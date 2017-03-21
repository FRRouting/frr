/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6_spf.h"
#include "ospf6d.h"

DEFINE_QOBJ_TYPE(ospf6)

/* global ospf6d variable */
struct ospf6 *ospf6;

static void ospf6_disable (struct ospf6 *o);

static void
ospf6_top_lsdb_hook_add (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
      case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_add (lsa);
        break;

      default:
        break;
    }
}

static void
ospf6_top_lsdb_hook_remove (struct ospf6_lsa *lsa)
{
  switch (ntohs (lsa->header->type))
    {
      case OSPF6_LSTYPE_AS_EXTERNAL:
        ospf6_asbr_lsa_remove (lsa);
        break;

      default:
        break;
    }
}

static void
ospf6_top_route_hook_add (struct ospf6_route *route)
{
  ospf6_abr_originate_summary (route);
  ospf6_zebra_route_update_add (route);
}

static void
ospf6_top_route_hook_remove (struct ospf6_route *route)
{
  route->flag |= OSPF6_ROUTE_REMOVE;
  ospf6_abr_originate_summary (route);
  ospf6_zebra_route_update_remove (route);
}

static void
ospf6_top_brouter_hook_add (struct ospf6_route *route)
{
  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_add (route);
  ospf6_abr_originate_summary (route);
}

static void
ospf6_top_brouter_hook_remove (struct ospf6_route *route)
{
  route->flag |= OSPF6_ROUTE_REMOVE;
  ospf6_abr_examin_brouter (ADV_ROUTER_IN_PREFIX (&route->prefix));
  ospf6_asbr_lsentry_remove (route);
  ospf6_abr_originate_summary (route);
}

static struct ospf6 *
ospf6_create (void)
{
  struct ospf6 *o;

  o = XCALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));

  /* initialize */
  monotime(&o->starttime);
  o->area_list = list_new ();
  o->area_list->cmp = ospf6_area_cmp;
  o->lsdb = ospf6_lsdb_create (o);
  o->lsdb_self = ospf6_lsdb_create (o);
  o->lsdb->hook_add = ospf6_top_lsdb_hook_add;
  o->lsdb->hook_remove = ospf6_top_lsdb_hook_remove;

  o->spf_delay = OSPF_SPF_DELAY_DEFAULT;
  o->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;
  o->spf_max_holdtime = OSPF_SPF_MAX_HOLDTIME_DEFAULT;
  o->spf_hold_multiplier = 1;

  /* LSA timers value init */
  o->lsa_minarrival = OSPF_MIN_LS_ARRIVAL;

  o->route_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, ROUTES);
  o->route_table->scope = o;
  o->route_table->hook_add = ospf6_top_route_hook_add;
  o->route_table->hook_remove = ospf6_top_route_hook_remove;

  o->brouter_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, BORDER_ROUTERS);
  o->brouter_table->scope = o;
  o->brouter_table->hook_add = ospf6_top_brouter_hook_add;
  o->brouter_table->hook_remove = ospf6_top_brouter_hook_remove;

  o->external_table = OSPF6_ROUTE_TABLE_CREATE (GLOBAL, EXTERNAL_ROUTES);
  o->external_table->scope = o;

  o->external_id_table = route_table_init ();

  o->ref_bandwidth = OSPF6_REFERENCE_BANDWIDTH;

  o->distance_table = route_table_init ();

  /* Enable "log-adjacency-changes" */
  SET_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
  QOBJ_REG (o, ospf6);

  return o;
}

void
ospf6_delete (struct ospf6 *o)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  QOBJ_UNREG (o);
  ospf6_disable (ospf6);

  for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
    ospf6_area_delete (oa);


  list_delete (o->area_list);

  ospf6_lsdb_delete (o->lsdb);
  ospf6_lsdb_delete (o->lsdb_self);

  ospf6_route_table_delete (o->route_table);
  ospf6_route_table_delete (o->brouter_table);

  ospf6_route_table_delete (o->external_table);
  route_table_finish (o->external_id_table);

  ospf6_distance_reset (o);
  route_table_finish (o->distance_table);

  XFREE (MTYPE_OSPF6_TOP, o);
}

static void
ospf6_disable (struct ospf6 *o)
{
  struct listnode *node, *nnode;
  struct ospf6_area *oa;

  if (! CHECK_FLAG (o->flag, OSPF6_DISABLED))
    {
      SET_FLAG (o->flag, OSPF6_DISABLED);
      
      for (ALL_LIST_ELEMENTS (o->area_list, node, nnode, oa))
        ospf6_area_disable (oa);

      /* XXX: This also changes persistent settings */
      ospf6_asbr_redistribute_reset();

      ospf6_lsdb_remove_all (o->lsdb);
      ospf6_route_remove_all (o->route_table);
      ospf6_route_remove_all (o->brouter_table);

      THREAD_OFF(o->maxage_remover);
      THREAD_OFF(o->t_spf_calc);
      THREAD_OFF(o->t_ase_calc);
    }
}

static int
ospf6_maxage_remover (struct thread *thread)
{
  struct ospf6 *o = (struct ospf6 *) THREAD_ARG (thread);
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  struct listnode *i, *j, *k;
  int reschedule = 0;

  o->maxage_remover = (struct thread *) NULL;

  for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
        {
          for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, k, on))
            {
              if (on->state != OSPF6_NEIGHBOR_EXCHANGE &&
                  on->state != OSPF6_NEIGHBOR_LOADING)
		  continue;

	      ospf6_maxage_remove (o);
              return 0;
            }
        }
    }

  for (ALL_LIST_ELEMENTS_RO (o->area_list, i, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, j, oi))
	{
	  if (ospf6_lsdb_maxage_remover (oi->lsdb))
	    {
	      reschedule = 1;
	    }
	}
      
      if (ospf6_lsdb_maxage_remover (oa->lsdb))
	{
	    reschedule = 1;
	}
    }

  if (ospf6_lsdb_maxage_remover (o->lsdb))
    {
      reschedule = 1;
    }

  if (reschedule)
    {
      ospf6_maxage_remove (o);
    }

  return 0;
}

void
ospf6_maxage_remove (struct ospf6 *o)
{
  if (o && ! o->maxage_remover)
    o->maxage_remover = thread_add_timer (master, ospf6_maxage_remover, o,
					  OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT);
}

/* start ospf6 */
DEFUN (router_ospf6,
       router_ospf6_cmd,
       "router ospf6",
       ROUTER_STR
       OSPF6_STR)
{
  if (ospf6 == NULL)
    ospf6 = ospf6_create ();

  /* set current ospf point. */
  VTY_PUSH_CONTEXT(OSPF6_NODE, ospf6);

  return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN (no_router_ospf6,
       no_router_ospf6_cmd,
       "no router ospf6",
       NO_STR
       ROUTER_STR
       OSPF6_STR)
{
  /* return to config node . */
  VTY_PUSH_CONTEXT_NULL(CONFIG_NODE);

  return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (ospf6_router_id,
       ospf6_router_id_cmd,
       "router-id A.B.C.D",
       "Configure OSPF Router-ID\n"
       V4NOTATION_STR)
{
  VTY_DECLVAR_CONTEXT(ospf6, o);
  int idx_ipv4 = 1;
  int ret;
  u_int32_t router_id;

  ret = inet_pton (AF_INET, argv[idx_ipv4]->arg, &router_id);
  if (ret == 0)
    {
      vty_out (vty, "malformed OSPF Router-ID: %s%s", argv[idx_ipv4]->arg, VNL);
      return CMD_SUCCESS;
    }

  o->router_id_static = router_id;
  if (o->router_id  == 0)
    o->router_id  = router_id;

  return CMD_SUCCESS;
}

DEFUN (ospf6_log_adjacency_changes,
       ospf6_log_adjacency_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf6);

  SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
  UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
  return CMD_SUCCESS;
}

DEFUN (ospf6_log_adjacency_changes_detail,
       ospf6_log_adjacency_changes_detail_cmd,
       "log-adjacency-changes detail",
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf6);

  SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
  SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes,
       no_ospf6_log_adjacency_changes_cmd,
       "no log-adjacency-changes",
       NO_STR
       "Log changes in adjacency state\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf6);

  UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
  UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes_detail,
       no_ospf6_log_adjacency_changes_detail_cmd,
       "no log-adjacency-changes detail",
       NO_STR
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf6);

  UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
  UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
  return CMD_SUCCESS;
}

DEFUN (ospf6_timers_lsa,
       ospf6_timers_lsa_cmd,
       "timers lsa min-arrival (0-600000)",
       "Adjust routing timers\n"
       "OSPF6 LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf);
  int idx_number = 3;
  unsigned int minarrival;

  VTY_GET_INTEGER ("LSA min-arrival", minarrival, argv[idx_number]->arg);
  ospf->lsa_minarrival = minarrival;

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_timers_lsa,
       no_ospf6_timers_lsa_cmd,
       "no timers lsa min-arrival [(0-600000)]",
       NO_STR
       "Adjust routing timers\n"
       "OSPF6 LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, ospf);
  int idx_number = 4;
  unsigned int minarrival;

  if (argc == 5)
    {
      VTY_GET_INTEGER ("LSA min-arrival", minarrival, argv[idx_number]->arg);

      if (ospf->lsa_minarrival != minarrival ||
	  minarrival == OSPF_MIN_LS_ARRIVAL)
	return CMD_SUCCESS;
    }

  ospf->lsa_minarrival = OSPF_MIN_LS_ARRIVAL;

  return CMD_SUCCESS;
}


DEFUN (ospf6_distance,
       ospf6_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "OSPF6 Administrative distance\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);

  o->distance_all = atoi (argv[1]->arg);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_distance,
       no_ospf6_distance_cmd,
       "no distance (1-255)",
       NO_STR
       "Administrative distance\n"
       "OSPF6 Administrative distance\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);

  o->distance_all = 0;

  return CMD_SUCCESS;
}

DEFUN (ospf6_distance_ospf6,
       ospf6_distance_ospf6_cmd,
       "distance ospf6 <intra-area (1-255)|inter-area (1-255)|external (1-255)> <intra-area (1-255)|inter-area (1-255)|external (1-255)> <intra-area (1-255)|inter-area (1-255)|external (1-255)>",
       "Administrative distance\n"
       "OSPF6 distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);

  char *intra, *inter, *external;
  intra = inter = external = NULL;

  int idx = 0;
  if (argv_find (argv, argc, "intra-area", &idx))
    intra = argv[++idx]->arg;
  if (argv_find (argv, argc, "intra-area", &idx))
  {
    vty_out (vty, "%% Cannot specify intra-area distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  idx = 0;
  if (argv_find (argv, argc, "inter-area", &idx))
    inter = argv[++idx]->arg;
  if (argv_find (argv, argc, "inter-area", &idx))
  {
    vty_out (vty, "%% Cannot specify inter-area distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  idx = 0;
  if (argv_find (argv, argc, "external", &idx))
    external = argv[++idx]->arg;
  if (argv_find (argv, argc, "external", &idx))
  {
    vty_out (vty, "%% Cannot specify external distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }


  if (intra)
    o->distance_intra = atoi (intra);

  if (inter)
    o->distance_inter = atoi (inter);

  if (external)
    o->distance_external = atoi (external);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_distance_ospf6,
       no_ospf6_distance_ospf6_cmd,
       "no distance ospf6 [<intra-area (1-255)|inter-area (1-255)|external (1-255)> <intra-area (1-255)|inter-area (1-255)|external (1-255)> <intra-area (1-255)|inter-area (1-255)|external (1-255)>]",
       NO_STR
       "Administrative distance\n"
       "OSPF6 distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);

  char *intra, *inter, *external;
  intra = inter = external = NULL;

  if (argc == 3)
  {
    /* If no arguments are given, clear all distance information */
    o->distance_intra = 0;
    o->distance_inter = 0;
    o->distance_external = 0;
    return CMD_SUCCESS;
  }

  int idx = 0;
  if (argv_find (argv, argc, "intra-area", &idx))
    intra = argv[++idx]->arg;
  if (argv_find (argv, argc, "intra-area", &idx))
  {
    vty_out (vty, "%% Cannot specify intra-area distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  idx = 0;
  if (argv_find (argv, argc, "inter-area", &idx))
    inter = argv[++idx]->arg;
  if (argv_find (argv, argc, "inter-area", &idx))
  {
    vty_out (vty, "%% Cannot specify inter-area distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  idx = 0;
  if (argv_find (argv, argc, "external", &idx))
    external = argv[++idx]->arg;
  if (argv_find (argv, argc, "external", &idx))
  {
    vty_out (vty, "%% Cannot specify external distance twice%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (argc < 3) /* should not happen */
    return CMD_WARNING;

  if (intra)
    o->distance_intra = 0;

  if (inter)
    o->distance_inter = 0;

  if (external)
    o->distance_external = 0;

  return CMD_SUCCESS;
}

#if 0
DEFUN (ospf6_distance_source,
       ospf6_distance_source_cmd,
       "distance (1-255) X:X::X:X/M [WORD]",
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);
  char *alname = (argc == 4) ? argv[3]->arg : NULL;
  ospf6_distance_set (vty, o, argv[1]->arg, argv[2]->arg, alname);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_distance_source,
       no_ospf6_distance_source_cmd,
       "no distance (1-255) X:X::X:X/M [WORD]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
  VTY_DECLVAR_CONTEXT(ospf6, o);
  char *alname = (argc == 5) ? argv[4]->arg : NULL;
  ospf6_distance_unset (vty, o, argv[2]->arg, argv[3]->arg, alname);

  return CMD_SUCCESS;
}
#endif

DEFUN (ospf6_interface_area,
       ospf6_interface_area_cmd,
       "interface IFNAME area A.B.C.D",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
      )
{
  VTY_DECLVAR_CONTEXT(ospf6, o);
  int idx_ifname = 1;
  int idx_ipv4 = 3;
  struct ospf6_area *oa;
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t area_id;

  /* find/create ospf6 interface */
  ifp = if_get_by_name (argv[idx_ifname]->arg, VRF_DEFAULT);
  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  if (oi->area)
    {
      vty_out (vty, "%s already attached to Area %s%s",
               oi->interface->name, oi->area->name, VNL);
      return CMD_SUCCESS;
    }

  /* parse Area-ID */
  if (inet_pton (AF_INET, argv[idx_ipv4]->arg, &area_id) != 1)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[idx_ipv4]->arg, VNL);
      return CMD_SUCCESS;
    }

  /* find/create ospf6 area */
  oa = ospf6_area_lookup (area_id, o);
  if (oa == NULL)
    oa = ospf6_area_create (area_id, o);

  /* attach interface to area */
  listnode_add (oa->if_list, oi); /* sort ?? */
  oi->area = oa;

  SET_FLAG (oa->flag, OSPF6_AREA_ENABLE);

  /* ospf6 process is currently disabled, not much more to do */
  if (CHECK_FLAG (o->flag, OSPF6_DISABLED))
    return CMD_SUCCESS;

  /* start up */
  ospf6_interface_enable (oi);

  /* If the router is ABR, originate summary routes */
  if (ospf6_is_router_abr (o))
    ospf6_abr_enable_area (oa);

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_interface_area,
       no_ospf6_interface_area_cmd,
       "no interface IFNAME area A.B.C.D",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       )
{
  int idx_ifname = 2;
  int idx_ipv4 = 4;
  struct ospf6_interface *oi;
  struct ospf6_area *oa;
  struct interface *ifp;
  u_int32_t area_id;

  ifp = if_lookup_by_name (argv[idx_ifname]->arg, VRF_DEFAULT);
  if (ifp == NULL)
    {
      vty_out (vty, "No such interface %s%s", argv[idx_ifname]->arg, VNL);
      return CMD_SUCCESS;
    }

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    {
      vty_out (vty, "Interface %s not enabled%s", ifp->name, VNL);
      return CMD_SUCCESS;
    }

  /* parse Area-ID */
  if (inet_pton (AF_INET, argv[idx_ipv4]->arg, &area_id) != 1)
    {
      vty_out (vty, "Invalid Area-ID: %s%s", argv[idx_ipv4]->arg, VNL);
      return CMD_SUCCESS;
    }

  /* Verify Area */
  if (oi->area == NULL)
    {
      vty_out (vty, "No such Area-ID: %s%s", argv[idx_ipv4]->arg, VNL);
      return CMD_SUCCESS;
    }

  if (oi->area->area_id != area_id)
    {
      vty_out (vty, "Wrong Area-ID: %s is attached to area %s%s",
               oi->interface->name, oi->area->name, VNL);
      return CMD_SUCCESS;
    }

  thread_execute (master, interface_down, oi, 0);

  oa = oi->area;
  listnode_delete (oi->area->if_list, oi);
  oi->area = (struct ospf6_area *) NULL;

  /* Withdraw inter-area routes from this area, if necessary */
  if (oa->if_list->count == 0)
    {
      UNSET_FLAG (oa->flag, OSPF6_AREA_ENABLE);
      ospf6_abr_disable_area (oa);
    }

  return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_admin,
       ospf6_stub_router_admin_cmd,
       "stub-router administrative",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Administratively applied, for an indefinite period\n")
{
  struct listnode *node;
  struct ospf6_area *oa;

  if (!CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
      for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
	{
	   OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_V6);
	   OSPF6_OPT_CLEAR (oa->options, OSPF6_OPT_R);
	   OSPF6_ROUTER_LSA_SCHEDULE (oa);
	}
      SET_FLAG (ospf6->flag, OSPF6_STUB_ROUTER);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_admin,
       no_ospf6_stub_router_admin_cmd,
       "no stub-router administrative",
       NO_STR
       "Make router a stub router\n"
       "Advertise ability to be a transit router\n"
       "Administratively applied, for an indefinite period\n")
{
  struct listnode *node;
  struct ospf6_area *oa;

  if (CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
      for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
	{
	   OSPF6_OPT_SET (oa->options, OSPF6_OPT_V6);
	   OSPF6_OPT_SET (oa->options, OSPF6_OPT_R);
	   OSPF6_ROUTER_LSA_SCHEDULE (oa);
	}
      UNSET_FLAG (ospf6->flag, OSPF6_STUB_ROUTER);
    }

  return CMD_SUCCESS;
}

#if 0
DEFUN (ospf6_stub_router_startup,
       ospf6_stub_router_startup_cmd,
       "stub-router on-startup (5-86400)",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router on startup of OSPF6\n"
       "Time (seconds) to advertise self as stub-router\n")
{
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_startup,
       no_ospf6_stub_router_startup_cmd,
       "no stub-router on-startup",
       NO_STR
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router on startup of OSPF6\n"
       "Time (seconds) to advertise self as stub-router\n")
{
  return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_shutdown,
       ospf6_stub_router_shutdown_cmd,
       "stub-router on-shutdown (5-86400)",
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router before shutdown\n"
       "Time (seconds) to advertise self as stub-router\n")
{
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_shutdown,
       no_ospf6_stub_router_shutdown_cmd,
       "no stub-router on-shutdown",
       NO_STR
       "Make router a stub router\n"
       "Advertise inability to be a transit router\n"
       "Automatically advertise as stub-router before shutdown\n"
       "Time (seconds) to advertise self as stub-router\n")
{
  return CMD_SUCCESS;
}
#endif

static void
ospf6_show (struct vty *vty, struct ospf6 *o)
{
  struct listnode *n;
  struct ospf6_area *oa;
  char router_id[16], duration[32];
  struct timeval now, running, result;
  char buf[32], rbuf[32];

  /* process id, router id */
  inet_ntop (AF_INET, &o->router_id, router_id, sizeof (router_id));
  vty_out (vty, " OSPFv3 Routing Process (0) with Router-ID %s%s",
           router_id, VNL);

  /* running time */
  monotime(&now);
  timersub (&now, &o->starttime, &running);
  timerstring (&running, duration, sizeof (duration));
  vty_out (vty, " Running %s%s", duration, VNL);

  /* Redistribute configuration */
  /* XXX */

  vty_out (vty, " LSA minimum arrival %d msecs%s", o->lsa_minarrival,
           VTY_NEWLINE);

  /* Show SPF parameters */
  vty_out(vty, " Initial SPF scheduling delay %d millisec(s)%s"
	  " Minimum hold time between consecutive SPFs %d millsecond(s)%s"
	  " Maximum hold time between consecutive SPFs %d millsecond(s)%s"
	  " Hold time multiplier is currently %d%s",
	  o->spf_delay, VNL,
	  o->spf_holdtime, VNL,
	  o->spf_max_holdtime, VNL,
	  o->spf_hold_multiplier, VNL);

  vty_out(vty, " SPF algorithm ");
  if (o->ts_spf.tv_sec || o->ts_spf.tv_usec)
    {
      timersub(&now, &o->ts_spf, &result);
      timerstring(&result, buf, sizeof(buf));
      ospf6_spf_reason_string(o->last_spf_reason, rbuf, sizeof(rbuf));
      vty_out(vty, "last executed %s ago, reason %s%s", buf, rbuf, VNL);
      vty_out (vty, " Last SPF duration %lld sec %lld usec%s",
               (long long)o->ts_spf_duration.tv_sec,
               (long long)o->ts_spf_duration.tv_usec, VNL);
    }
  else
    vty_out(vty, "has not been run$%s", VNL);
  threadtimer_string(now, o->t_spf_calc, buf, sizeof(buf));
  vty_out (vty, " SPF timer %s%s%s",
	   (o->t_spf_calc ? "due in " : "is "), buf, VNL);

  if (CHECK_FLAG (o->flag, OSPF6_STUB_ROUTER))
    vty_out (vty, " Router Is Stub Router%s", VNL);

  /* LSAs */
  vty_out (vty, " Number of AS scoped LSAs is %u%s",
           o->lsdb->count, VNL);

  /* Areas */
  vty_out (vty, " Number of areas in this router is %u%s",
           listcount (o->area_list), VNL);

  if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_CHANGES))
    {
      if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_DETAIL))
	vty_out(vty, " All adjacency changes are logged%s",VTY_NEWLINE);
      else
	vty_out(vty, " Adjacency changes are logged%s",VTY_NEWLINE);
    }

  vty_out (vty, "%s",VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS_RO (o->area_list, n, oa))
    ospf6_area_show (vty, oa);
}

/* show top level structures */
DEFUN (show_ipv6_ospf6,
       show_ipv6_ospf6_cmd,
       "show ipv6 ospf6",
       SHOW_STR
       IP6_STR
       OSPF6_STR)
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_show (vty, ospf6);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route,
       show_ipv6_ospf6_route_cmd,
       "show ipv6 ospf6 route [<intra-area|inter-area|external-1|external-2|X:X::X:X|X:X::X:X/M|detail|summary>]",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
       "Specify IPv6 address\n"
       "Specify IPv6 prefix\n"
       "Detailed information\n"
       "Summary of route table\n")
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_route_table_show (vty, 4, argc, argv, ospf6->route_table);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route_match,
       show_ipv6_ospf6_route_match_cmd,
       "show ipv6 ospf6 route X:X::X:X/M <match|longer>",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
       "Display routes longer than the specified route\n")
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_route_table_show (vty, 4, argc, argv, ospf6->route_table);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_route_match_detail,
       show_ipv6_ospf6_route_match_detail_cmd,
       "show ipv6 ospf6 route X:X::X:X/M match detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Specify IPv6 prefix\n"
       "Display routes which match the specified route\n"
       "Detailed information\n"
       )
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_route_table_show (vty, 4, argc, argv, ospf6->route_table);
  return CMD_SUCCESS;
}



DEFUN (show_ipv6_ospf6_route_type_detail,
       show_ipv6_ospf6_route_type_detail_cmd,
       "show ipv6 ospf6 route <intra-area|inter-area|external-1|external-2> detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       ROUTE_STR
       "Display Intra-Area routes\n"
       "Display Inter-Area routes\n"
       "Display Type-1 External routes\n"
       "Display Type-2 External routes\n"
       "Detailed information\n"
       )
{
  OSPF6_CMD_CHECK_RUNNING ();

  ospf6_route_table_show (vty, 4, argc, argv, ospf6->route_table);
  return CMD_SUCCESS;
}

static void
ospf6_stub_router_config_write (struct vty *vty)
{
  if (CHECK_FLAG (ospf6->flag, OSPF6_STUB_ROUTER))
    {
      vty_out (vty, " stub-router administrative%s", VNL);
    }
    return;
}

static int
ospf6_distance_config_write (struct vty *vty)
{
  struct route_node *rn;
  struct ospf6_distance *odistance;

  if (ospf6->distance_all)
    vty_out (vty, " distance %u%s", ospf6->distance_all, VTY_NEWLINE);

  if (ospf6->distance_intra
      || ospf6->distance_inter
      || ospf6->distance_external)
    {
      vty_out (vty, " distance ospf6");

      if (ospf6->distance_intra)
        vty_out (vty, " intra-area %u", ospf6->distance_intra);
      if (ospf6->distance_inter)
        vty_out (vty, " inter-area %u", ospf6->distance_inter);
      if (ospf6->distance_external)
        vty_out (vty, " external %u", ospf6->distance_external);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

  for (rn = route_top (ospf6->distance_table); rn; rn = route_next (rn))
    if ((odistance = rn->info) != NULL)
      {
	char buf[PREFIX_STRLEN];

        vty_out (vty, " distance %u %s %s%s", odistance->distance,
		 prefix2str (&rn->p, buf, sizeof (buf)),
                 odistance->access_list ? odistance->access_list : "",
                 VTY_NEWLINE);
      }
  return 0;
}

/* OSPF configuration write function. */
static int
config_write_ospf6 (struct vty *vty)
{
  char router_id[16];
  struct listnode *j, *k;
  struct ospf6_area *oa;
  struct ospf6_interface *oi;

  /* OSPFv3 configuration. */
  if (ospf6 == NULL)
    return CMD_SUCCESS;

  inet_ntop (AF_INET, &ospf6->router_id_static, router_id, sizeof (router_id));
  vty_out (vty, "router ospf6%s", VNL);
  if (ospf6->router_id_static != 0)
    vty_out (vty, " router-id %s%s", router_id, VNL);

  /* log-adjacency-changes flag print. */
  if (CHECK_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES))
    {
      if (CHECK_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL))
        vty_out(vty, " log-adjacency-changes detail%s", VTY_NEWLINE);
    }
  else
    {
      vty_out(vty, " no log-adjacency-changes%s", VTY_NEWLINE);
    }

  if (ospf6->ref_bandwidth != OSPF6_REFERENCE_BANDWIDTH)
    vty_out (vty, " auto-cost reference-bandwidth %d%s", ospf6->ref_bandwidth,
             VNL);

  /* LSA timers print. */
  if (ospf6->lsa_minarrival != OSPF_MIN_LS_ARRIVAL)
    vty_out (vty, " timers lsa min-arrival %d%s", ospf6->lsa_minarrival,
             VTY_NEWLINE);

  ospf6_stub_router_config_write (vty);
  ospf6_redistribute_config_write (vty);
  ospf6_area_config_write (vty);
  ospf6_spf_config_write (vty);
  ospf6_distance_config_write (vty);

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, j, oa))
    {
      for (ALL_LIST_ELEMENTS_RO (oa->if_list, k, oi))
        vty_out (vty, " interface %s area %s%s",
                 oi->interface->name, oa->name, VNL);
    }
  vty_out (vty, "!%s", VNL);
  return 0;
}

/* OSPF6 node structure. */
static struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# ",
  1 /* VTYSH */
};

/* Install ospf related commands. */
void
ospf6_top_init (void)
{
  /* Install ospf6 top node. */
  install_node (&ospf6_node, config_write_ospf6);

  install_element (VIEW_NODE, &show_ipv6_ospf6_cmd);
  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &no_router_ospf6_cmd);

  install_element (VIEW_NODE, &show_ipv6_ospf6_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_route_type_detail_cmd);

  install_default (OSPF6_NODE);
  install_element (OSPF6_NODE, &ospf6_router_id_cmd);
  install_element (OSPF6_NODE, &ospf6_log_adjacency_changes_cmd);
  install_element (OSPF6_NODE, &ospf6_log_adjacency_changes_detail_cmd);
  install_element (OSPF6_NODE, &no_ospf6_log_adjacency_changes_cmd);
  install_element (OSPF6_NODE, &no_ospf6_log_adjacency_changes_detail_cmd);

  /* LSA timers commands */
  install_element (OSPF6_NODE, &ospf6_timers_lsa_cmd);
  install_element (OSPF6_NODE, &no_ospf6_timers_lsa_cmd);

  install_element (OSPF6_NODE, &ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &no_ospf6_interface_area_cmd);
  install_element (OSPF6_NODE, &ospf6_stub_router_admin_cmd);
  install_element (OSPF6_NODE, &no_ospf6_stub_router_admin_cmd);
  /* For a later time */
#if 0
  install_element (OSPF6_NODE, &ospf6_stub_router_startup_cmd);
  install_element (OSPF6_NODE, &no_ospf6_stub_router_startup_cmd);
  install_element (OSPF6_NODE, &ospf6_stub_router_shutdown_cmd);
  install_element (OSPF6_NODE, &no_ospf6_stub_router_shutdown_cmd);
#endif

  install_element (OSPF6_NODE, &ospf6_distance_cmd);
  install_element (OSPF6_NODE, &no_ospf6_distance_cmd);
  install_element (OSPF6_NODE, &ospf6_distance_ospf6_cmd);
  install_element (OSPF6_NODE, &no_ospf6_distance_ospf6_cmd);
#if 0
  install_element (OSPF6_NODE, &ospf6_distance_source_cmd);
  install_element (OSPF6_NODE, &no_ospf6_distance_source_cmd);
#endif
}
