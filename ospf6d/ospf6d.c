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

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6d.h"
#include "ospf6_proto.h"
#include "ospf6_network.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"

char ospf6_daemon_version[] = OSPF6_DAEMON_VERSION;

void
ospf6_debug ()
{
}

static struct route_node *
_route_next_until (struct route_node *node, struct route_node *limit)
{
  struct route_node *next;
  struct route_node *start;

  /* Node may be deleted from route_unlock_node so we have to preserve
     next node's pointer. */

  if (node->l_left)
    {
      next = node->l_left;
      if (next == limit)
        {
          route_unlock_node (node);
          return NULL;
        }
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }
  if (node->l_right)
    {
      next = node->l_right;
      if (next == limit)
        {
          route_unlock_node (node);
          return NULL;
        }
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }

  start = node;
  while (node->parent)
    {
      if (node->parent->l_left == node && node->parent->l_right)
	{
	  next = node->parent->l_right;
          if (next == limit)
            {
              route_unlock_node (start);
              return NULL;
            }
	  route_lock_node (next);
	  route_unlock_node (start);
	  return next;
	}
      node = node->parent;
    }

  route_unlock_node (start);
  return NULL;
}

struct route_node *
route_prev (struct route_node *node)
{
  struct route_node *end;
  struct route_node *prev = NULL;

  if (node->parent == NULL)
    {
      route_unlock_node (node);
      return NULL;
    }

  if (node->parent->l_left == node)
    {
      prev = node->parent;
      route_lock_node (prev);
      route_unlock_node (node);
      return prev;
    }

  end = node;
  node = node->parent;
  route_lock_node (node);
  while (node)
    {
      prev = node;
      node = _route_next_until (node, end);
    }
  route_unlock_node (end);
  route_lock_node (prev);

  return prev;
}

DEFUN (show_version_ospf6,
       show_version_ospf6_cmd,
       "show version ospf6",
       SHOW_STR
       "Displays ospf6d version\n"
      )
{
  vty_out (vty, "Zebra OSPF6d Version: %s%s",
           ospf6_daemon_version, VTY_NEWLINE);

  return CMD_SUCCESS;
}

struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""
};

int
config_write_ospf6_debug (struct vty *vty)
{
  config_write_ospf6_debug_message (vty);
  config_write_ospf6_debug_lsa (vty);
  config_write_ospf6_debug_zebra (vty);
  config_write_ospf6_debug_interface (vty);
  config_write_ospf6_debug_neighbor (vty);
  config_write_ospf6_debug_spf (vty);
  config_write_ospf6_debug_route (vty);
  config_write_ospf6_debug_asbr (vty);
  vty_out (vty, "!%s", VTY_NEWLINE);
  return 0;
}

DEFUN (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc)
    {
      if (! strncmp (argv[0], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[0], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[0], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  LSDB_FOREACH_LSA (vty, showfunc, o->lsdb);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA (vty, showfunc, oa->lsdb);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA (vty, showfunc, oi->lsdb);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_detail_cmd,
       "show ipv6 ospf6 database (detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type,
       show_ipv6_ospf6_database_type_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 1)
    {
      if (! strncmp (argv[1], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[1], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[1], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  LSDB_FOREACH_LSA_T (vty, showfunc, o->lsdb, type);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_T (vty, showfunc, oa->lsdb, type);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_T (vty, showfunc, oi->lsdb, type);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type,
       show_ipv6_ospf6_database_type_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_id,
       show_ipv6_ospf6_database_id_cmd,
       "show ipv6 ospf6 database * A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Specify Link state ID as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int32_t id = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 1)
    {
      if (! strncmp (argv[1], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[1], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[1], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if ((inet_pton (AF_INET, argv[0], &id)) != 1)
    {
      vty_out (vty, "Link State ID is not parsable: %s%s",
               argv[0], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_I (vty, showfunc, o->lsdb, id);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_I (vty, showfunc, oa->lsdb, id);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_I (vty, showfunc, oi->lsdb, id);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_id,
       show_ipv6_ospf6_database_id_detail_cmd,
       "show ipv6 ospf6 database * A.B.C.D "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Any Link state ID\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_router,
       show_ipv6_ospf6_database_router_cmd,
       "show ipv6 ospf6 database * * A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Any Link state ID\n"
       "Specify Advertising Router as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int32_t router = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 1)
    {
      if (! strncmp (argv[1], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[1], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[1], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if ((inet_pton (AF_INET, argv[0], &router)) != 1)
    {
      vty_out (vty, "Advertising Router is not parsable: %s%s",
               argv[0], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_R (vty, showfunc, o->lsdb, router);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_R (vty, showfunc, oa->lsdb, router);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_R (vty, showfunc, oi->lsdb, router);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_router,
       show_ipv6_ospf6_database_router_detail_cmd,
       "show ipv6 ospf6 database * * A.B.C.D "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Any Link state ID\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type_id,
       show_ipv6_ospf6_database_type_id_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;
  u_int32_t id = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 2)
    {
      if (! strncmp (argv[2], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[2], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[2], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  if ((inet_pton (AF_INET, argv[1], &id)) != 1)
    {
      vty_out (vty, "Link state ID is not parsable: %s%s",
               argv[1], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_TI (vty, showfunc, o->lsdb, type, id);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_TI (vty, showfunc, oa->lsdb, type, id);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_TI (vty, showfunc, oi->lsdb, type, id);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_id,
       show_ipv6_ospf6_database_type_id_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type_router,
       show_ipv6_ospf6_database_type_router_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) * A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Any Link state ID\n"
       "Specify Advertising Router as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;
  u_int32_t router = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 2)
    {
      if (! strncmp (argv[2], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[2], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[2], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  if ((inet_pton (AF_INET, argv[1], &router)) != 1)
    {
      vty_out (vty, "Advertising Router is not parsable: %s%s",
               argv[1], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_TR (vty, showfunc, o->lsdb, type, router);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_TR (vty, showfunc, oa->lsdb, type, router);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_TR (vty, showfunc, oi->lsdb, type, router);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_router,
       show_ipv6_ospf6_database_type_router_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) * A.B.C.D "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Any Link state ID\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_id_router,
       show_ipv6_ospf6_database_id_router_cmd,
       "show ipv6 ospf6 database * A.B.C.D A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Specify Advertising Router as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int32_t id = 0;
  u_int32_t router = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 2)
    {
      if (! strncmp (argv[2], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[2], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[2], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if ((inet_pton (AF_INET, argv[0], &id)) != 1)
    {
      vty_out (vty, "Link state ID is not parsable: %s%s",
               argv[1], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if ((inet_pton (AF_INET, argv[1], &router)) != 1)
    {
      vty_out (vty, "Advertising Router is not parsable: %s%s",
               argv[1], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_IR (vty, showfunc, o->lsdb, id, router);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_IR (vty, showfunc, oa->lsdb, id, router);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_IR (vty, showfunc, oi->lsdb, id, router);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_id_router,
       show_ipv6_ospf6_database_id_router_detail_cmd,
       "show ipv6 ospf6 database * A.B.C.D A.B.C.D "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Any Link state Type\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type_id_router,
       show_ipv6_ospf6_database_type_id_router_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D A.B.C.D",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Specify Advertising Router as IPv4 address notation\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;
  u_int32_t id = 0;
  u_int32_t router = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 3)
    {
      if (! strncmp (argv[3], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[3], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  if ((inet_pton (AF_INET, argv[1], &id)) != 1)
    {
      vty_out (vty, "Link state ID is not parsable: %s%s",
               argv[1], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if ((inet_pton (AF_INET, argv[2], &router)) != 1)
    {
      vty_out (vty, "Advertising Router is not parsable: %s%s",
               argv[2], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_TIR (vty, showfunc, o->lsdb, type, id, router);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_TIR (vty, showfunc, oa->lsdb, type, id, router);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_TIR (vty, showfunc, oi->lsdb, type, id, router);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_id_router,
       show_ipv6_ospf6_database_type_id_router_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D A.B.C.D "
       "(dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Specify Advertising Router as IPv4 address notation\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_self_originated,
       show_ipv6_ospf6_database_self_originated_cmd,
       "show ipv6 ospf6 database self-originated",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Self-originated LSAs\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 0)
    {
      if (! strncmp (argv[0], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[0], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[0], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  LSDB_FOREACH_LSA_R (vty, showfunc, o->lsdb, o->router_id);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_R (vty, showfunc, oa->lsdb, o->router_id);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_R (vty, showfunc, oi->lsdb, o->router_id);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_self_originated,
       show_ipv6_ospf6_database_self_originated_detail_cmd,
       "show ipv6 ospf6 database self-originated "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Self-originated LSAs\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type_self_originated,
       show_ipv6_ospf6_database_type_self_originated_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) self-originated",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Display Self-originated LSAs\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 1)
    {
      if (! strncmp (argv[1], "de", 2))
        showfunc = ospf6_lsa_show;
      else if (! strncmp (argv[1], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[1], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show_summary;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  LSDB_FOREACH_LSA_TR (vty, showfunc, o->lsdb, type, o->router_id);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_TR (vty, showfunc, oa->lsdb, type, o->router_id);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_TR (vty, showfunc, oi->lsdb, type, o->router_id);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_self_originated,
       show_ipv6_ospf6_database_type_self_originated_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) self-originated "
       "(detail|dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Display Self-originated LSAs\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );

DEFUN (show_ipv6_ospf6_database_type_id_self_originated,
       show_ipv6_ospf6_database_type_id_self_originated_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D self-originated",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display Self-originated LSAs\n"
      )
{
  listnode i, j;
  struct ospf6 *o = ospf6;
  void (*showfunc) (struct vty *, struct ospf6_lsa *) = NULL;
  u_int16_t type = 0;
  u_int32_t id = 0;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc > 2)
    {
      if (! strncmp (argv[2], "du", 2))
        showfunc = ospf6_lsa_show_dump;
      else if (! strncmp (argv[2], "in", 2))
        showfunc = ospf6_lsa_show_internal;
    }
  else
    showfunc = ospf6_lsa_show;

  if (showfunc == ospf6_lsa_show_summary)
    ospf6_lsa_show_summary_header (vty);

  if (! strcmp (argv[0], "router"))
    type = htons (OSPF6_LSTYPE_ROUTER);
  else if (! strcmp (argv[0], "network"))
    type = htons (OSPF6_LSTYPE_NETWORK);
  else if (! strcmp (argv[0], "as-external"))
    type = htons (OSPF6_LSTYPE_AS_EXTERNAL);
  else if (! strcmp (argv[0], "intra-prefix"))
    type = htons (OSPF6_LSTYPE_INTRA_PREFIX);
  else if (! strcmp (argv[0], "inter-router"))
    type = htons (OSPF6_LSTYPE_INTER_ROUTER);
  else if (! strcmp (argv[0], "inter-prefix"))
    type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  else if (! strcmp (argv[0], "link"))
    type = htons (OSPF6_LSTYPE_LINK);

  if ((inet_pton (AF_INET, argv[1], &id)) != 1)
    {
      vty_out (vty, "Link State ID is not parsable: %s%s",
               argv[0], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  LSDB_FOREACH_LSA_TIR (vty, showfunc, o->lsdb, type, id, o->router_id);
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      LSDB_FOREACH_LSA_TIR (vty, showfunc, oa->lsdb, type, id, o->router_id);
    }
  for (i = listhead (o->area_list); i; nextnode (i))
    {
      struct ospf6_area *oa = (struct ospf6_area *) getdata (i);
      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          struct ospf6_interface *oi = (struct ospf6_interface *) getdata (j);
          LSDB_FOREACH_LSA_TIR (vty, showfunc, oi->lsdb, type, id, o->router_id);
        }
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_id_self_originated,
       show_ipv6_ospf6_database_type_id_self_originated_detail_cmd,
       "show ipv6 ospf6 database "
       "(router|network|inter-prefix|inter-router|as-external|"
       "group-membership|type-7|link|intra-prefix) A.B.C.D self-originated "
       "(dump|internal)",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Display Link state database\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Area-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Group-Membership LSAs\n"
       "Display Type-7 LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Specify Link state ID as IPv4 address notation\n"
       "Display Self-originated LSAs\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n"
      );



/* Install ospf related commands. */
void
ospf6_init ()
{
  install_node (&debug_node, config_write_ospf6_debug);

  install_element_ospf6_debug_message ();
  install_element_ospf6_debug_lsa ();
  install_element_ospf6_debug_interface ();
  install_element_ospf6_debug_neighbor ();
  install_element_ospf6_debug_zebra ();
  install_element_ospf6_debug_spf ();
  install_element_ospf6_debug_route ();
  install_element_ospf6_debug_asbr ();

  install_element (VIEW_NODE, &show_version_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_id_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_id_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_router_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_router_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_id_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_id_router_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_router_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_self_originated_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_self_originated_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_self_originated_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_self_originated_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_self_originated_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_self_originated_detail_cmd);

  install_element (ENABLE_NODE, &show_version_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_id_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_id_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_router_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_router_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_id_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_id_router_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_router_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_self_originated_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_self_originated_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_self_originated_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_self_originated_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_self_originated_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_self_originated_detail_cmd);

  ospf6_top_init ();
  ospf6_area_init ();
  ospf6_interface_init ();
  ospf6_neighbor_init ();
  ospf6_zebra_init ();

  ospf6_lsa_init ();
  ospf6_spf_init ();
  ospf6_intra_init ();
  ospf6_asbr_init ();

  /* Make ospf protocol socket. */
  ospf6_serv_sock ();
  thread_add_read (master, ospf6_receive, NULL, ospf6_sock);
}


