/*
 * OSPFv3 Route-Map
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
#include "linklist.h"
#include "prefix.h"
#include "command.h"
#include "vty.h"
#include "routemap.h"
#include "table.h"
#include "plist.h"

#include "ospf6_route.h"
#include "ospf6_prefix.h"
#include "ospf6_lsa.h"
#include "ospf6_asbr.h"

route_map_result_t
ospf6_routemap_rule_match_address_prefixlist (void *rule,
                                              struct prefix *prefix,
                                              route_map_object_t type,
                                              void *object)
{
  struct prefix_list *plist;

  if (type != RMAP_OSPF6)
    return RMAP_NOMATCH;

  plist = prefix_list_lookup (AFI_IP6, (char *) rule);

  if (plist == NULL)
    return RMAP_NOMATCH;

  return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
          RMAP_NOMATCH : RMAP_MATCH);
}

void *
ospf6_routemap_rule_match_address_prefixlist_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
ospf6_routemap_rule_match_address_prefixlist_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
ospf6_routemap_rule_match_address_prefixlist_cmd =
{
  "ipv6 address prefix-list",
  ospf6_routemap_rule_match_address_prefixlist,
  ospf6_routemap_rule_match_address_prefixlist_compile,
  ospf6_routemap_rule_match_address_prefixlist_free,
};

route_map_result_t
ospf6_routemap_rule_set_metric_type (void *rule, struct prefix *prefix,
                                     route_map_object_t type, void *object)
{
  char *metric_type = rule;
  struct ospf6_external_info *info = object;

  if (type != RMAP_OSPF6)
    return RMAP_OKAY;

  if (strcmp (metric_type, "type-2") == 0)
    info->metric_type = 2;
  else
    info->metric_type = 1;

  return RMAP_OKAY;
}

void *
ospf6_routemap_rule_set_metric_type_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
ospf6_routemap_rule_set_metric_type_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
ospf6_routemap_rule_set_metric_type_cmd =
{
  "metric-type",
  ospf6_routemap_rule_set_metric_type,
  ospf6_routemap_rule_set_metric_type_compile,
  ospf6_routemap_rule_set_metric_type_free,
};

route_map_result_t
ospf6_routemap_rule_set_metric (void *rule, struct prefix *prefix,
                                route_map_object_t type, void *object)
{
  char *metric = rule;
  struct ospf6_external_info *info = object;

  if (type != RMAP_OSPF6)
    return RMAP_OKAY;

  info->metric = atoi (metric);
  return RMAP_OKAY;
}

void *
ospf6_routemap_rule_set_metric_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
ospf6_routemap_rule_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
ospf6_routemap_rule_set_metric_cmd =
{
  "metric",
  ospf6_routemap_rule_set_metric,
  ospf6_routemap_rule_set_metric_compile,
  ospf6_routemap_rule_set_metric_free,
};

route_map_result_t
ospf6_routemap_rule_set_forwarding (void *rule, struct prefix *prefix,
                                    route_map_object_t type, void *object)
{
  char *forwarding = rule;
  struct ospf6_external_info *info = object;

  if (type != RMAP_OSPF6)
    return RMAP_OKAY;

  if (inet_pton (AF_INET6, forwarding, &info->forwarding) != 1)
    {
      memset (&info->forwarding, 0, sizeof (struct in6_addr));
      return RMAP_ERROR;
    }

  return RMAP_OKAY;
}

void *
ospf6_routemap_rule_set_forwarding_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

void
ospf6_routemap_rule_set_forwarding_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd
ospf6_routemap_rule_set_forwarding_cmd =
{
  "forwarding-address",
  ospf6_routemap_rule_set_forwarding,
  ospf6_routemap_rule_set_forwarding_compile,
  ospf6_routemap_rule_set_forwarding_free,
};

int
route_map_command_status (struct vty *vty, int ret)
{
  if (! ret)
    return CMD_SUCCESS;

  switch (ret)
    {
    case RMAP_RULE_MISSING:
      vty_out (vty, "Can't find rule.%s", VTY_NEWLINE);
      break;
    case RMAP_COMPILE_ERROR:
      vty_out (vty, "Argument is malformed.%s", VTY_NEWLINE);
      break;
    default:                          
      vty_out (vty, "route-map add set failed.%s", VTY_NEWLINE);
      break;
    }
  return CMD_WARNING;
}

/* add "match address" */
DEFUN (match_ipv6_address_prefix_list,
       match_ipv6_address_prefix_list_cmd,
       "match ipv6 address prefix-list WORD",
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  int ret = route_map_add_match ((struct route_map_index *) vty->index,
                                 "ipv6 address prefix-list", argv[0]);
  return route_map_command_status (vty, ret);
}

/* delete "match address" */
DEFUN (no_match_ipv6_address_prefix_list,
       no_match_ipv6_address_prefix_list_cmd,
       "no match ipv6 address prefix-list WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  int ret = route_map_delete_match ((struct route_map_index *) vty->index,
                                    "ipv6 address prefix-list", argv[0]);
  return route_map_command_status (vty, ret);
}

/* add "set metric-type" */
DEFUN (set_metric_type,
       set_metric_type_cmd,
       "set metric-type (type-1|type-2)",
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
  int ret = route_map_add_set ((struct route_map_index *) vty->index,
                               "metric-type", argv[0]);
  return route_map_command_status (vty, ret);
}

/* delete "set metric-type" */
DEFUN (no_set_metric_type,
       no_set_metric_type_cmd,
       "no set metric-type",
       NO_STR
       SET_STR
       "Type of metric for destination routing protocol\n")
{
  int ret;
  if (argc == 0)
    ret = route_map_delete_set ((struct route_map_index *) vty->index,
                                  "metric-type", NULL);
  else
    ret = route_map_delete_set ((struct route_map_index *) vty->index,
                                  "metric-type", argv[0]);
  return route_map_command_status (vty, ret);
}

ALIAS (no_set_metric_type,
       no_set_metric_type_val_cmd,
       "no set metric-type (type-1|type-2)",
       NO_STR
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")

/* add "set metric" */
DEFUN (set_metric,
       set_metric_cmd,
       "set metric <0-4294967295>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  int ret = route_map_add_set ((struct route_map_index *) vty->index,
                               "metric", argv[0]);
  return route_map_command_status (vty, ret);
}

/* delete "set metric" */
DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n")
{
  int ret;
  if (argc == 0)
    ret = route_map_delete_set ((struct route_map_index *) vty->index,
                                  "metric", NULL);
  else
    ret = route_map_delete_set ((struct route_map_index *) vty->index,
                                  "metric", argv[0]);
  return route_map_command_status (vty, ret);
}

ALIAS (no_set_metric,
       no_set_metric_val_cmd,
       "no set metric <0-4294967295>",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")

/* add "set forwarding-address" */
DEFUN (ospf6_routemap_set_forwarding,
       ospf6_routemap_set_forwarding_cmd,
       "set forwarding-address X:X::X:X",
       "Set value\n"
       "Forwarding Address\n"
       "IPv6 Address\n")
{
  int ret = route_map_add_set ((struct route_map_index *) vty->index,
                               "forwarding-address", argv[0]);
  return route_map_command_status (vty, ret);
}

/* delete "set forwarding-address" */
DEFUN (ospf6_routemap_no_set_forwarding,
       ospf6_routemap_no_set_forwarding_cmd,
       "no set forwarding-address X:X::X:X",
       NO_STR
       "Set value\n"
       "Forwarding Address\n"
       "IPv6 Address\n")
{
  int ret = route_map_delete_set ((struct route_map_index *) vty->index,
                                  "forwarding-address", argv[0]);
  return route_map_command_status (vty, ret);
}

void
ospf6_routemap_init ()
{
  route_map_init ();
  route_map_init_vty ();
  route_map_add_hook (ospf6_asbr_routemap_update);
  route_map_delete_hook (ospf6_asbr_routemap_update);

  route_map_install_match (&ospf6_routemap_rule_match_address_prefixlist_cmd);
  route_map_install_set (&ospf6_routemap_rule_set_metric_type_cmd);
  route_map_install_set (&ospf6_routemap_rule_set_metric_cmd);
  route_map_install_set (&ospf6_routemap_rule_set_forwarding_cmd);

  /* Match address prefix-list */
  install_element (RMAP_NODE, &match_ipv6_address_prefix_list_cmd);
  install_element (RMAP_NODE, &no_match_ipv6_address_prefix_list_cmd);

  /* ASE Metric Type (e.g. Type-1/Type-2) */
  install_element (RMAP_NODE, &set_metric_type_cmd);
  install_element (RMAP_NODE, &no_set_metric_type_cmd);
  install_element (RMAP_NODE, &no_set_metric_type_val_cmd);

  /* ASE Metric */
  install_element (RMAP_NODE, &set_metric_cmd);
  install_element (RMAP_NODE, &no_set_metric_cmd);
  install_element (RMAP_NODE, &no_set_metric_val_cmd);

  /* ASE Metric */
  install_element (RMAP_NODE, &ospf6_routemap_set_forwarding_cmd);
  install_element (RMAP_NODE, &ospf6_routemap_no_set_forwarding_cmd);
}

