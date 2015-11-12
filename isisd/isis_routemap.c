/*
 * IS-IS Rout(e)ing protocol - isis_routemap.c
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "hash.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "plist.h"
#include "routemap.h"
#include "table.h"
#include "thread.h"
#include "vty.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "dict.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_zebra.h"
#include "isis_routemap.h"

static route_map_result_t
route_match_ip_address(void *rule, struct prefix *prefix,
                       route_map_object_t type, void *object)
{
  struct access_list *alist;

  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;

  alist = access_list_lookup(AFI_IP, (char*)rule);
  if (access_list_apply(alist, prefix) != FILTER_DENY)
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

static void *
route_match_ip_address_compile(const char *arg)
{
  return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_ip_address_free(void *rule)
{
  XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_address_compile,
  route_match_ip_address_free
};

/* ------------------------------------------------------------*/

static route_map_result_t
route_match_ip_address_prefix_list(void *rule, struct prefix *prefix,
                                   route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;

  plist = prefix_list_lookup(AFI_IP, (char*)rule);
  if (prefix_list_apply(plist, prefix) != PREFIX_DENY)
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

static void *
route_match_ip_address_prefix_list_compile(const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_ip_address_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd =
{
  "ip address prefix-list",
  route_match_ip_address_prefix_list,
  route_match_ip_address_prefix_list_compile,
  route_match_ip_address_prefix_list_free
};

/* ------------------------------------------------------------*/

static route_map_result_t
route_match_ipv6_address(void *rule, struct prefix *prefix,
                         route_map_object_t type, void *object)
{
  struct access_list *alist;

  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;

  alist = access_list_lookup(AFI_IP6, (char*)rule);
  if (access_list_apply(alist, prefix) != FILTER_DENY)
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

static void *
route_match_ipv6_address_compile(const char *arg)
{
  return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_ipv6_address_free(void *rule)
{
  XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ipv6_address_cmd =
{
  "ipv6 address",
  route_match_ipv6_address,
  route_match_ipv6_address_compile,
  route_match_ipv6_address_free
};

/* ------------------------------------------------------------*/

static route_map_result_t
route_match_ipv6_address_prefix_list(void *rule, struct prefix *prefix,
                                     route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type != RMAP_ISIS)
    return RMAP_NOMATCH;

  plist = prefix_list_lookup(AFI_IP6, (char*)rule);
  if (prefix_list_apply(plist, prefix) != PREFIX_DENY)
    return RMAP_MATCH;

  return RMAP_NOMATCH;
}

static void *
route_match_ipv6_address_prefix_list_compile(const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_ipv6_address_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_address_prefix_list_cmd =
{
  "ipv6 address prefix-list",
  route_match_ipv6_address_prefix_list,
  route_match_ipv6_address_prefix_list_compile,
  route_match_ipv6_address_prefix_list_free
};

/* ------------------------------------------------------------*/

static route_map_result_t
route_set_metric(void *rule, struct prefix *prefix,
                 route_map_object_t type, void *object)
{
  uint32_t *metric;
  struct isis_ext_info *info;

  if (type == RMAP_ISIS)
    {
      metric = rule;
      info = object;

      info->metric = *metric;
    }
  return RMAP_OKAY;
}

static void *
route_set_metric_compile(const char *arg)
{
  unsigned long metric;
  char *endp;
  uint32_t *ret;

  metric = strtoul(arg, &endp, 10);
  if (arg[0] == '\0' || *endp != '\0' || metric > MAX_WIDE_PATH_METRIC)
    return NULL;

  ret = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(ret));
  *ret = metric;

  return ret;
}

static void
route_set_metric_free(void *rule)
{
  XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_set_metric_cmd =
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free
};

/* ------------------------------------------------------------*/

static int
isis_route_match_add(struct vty *vty, struct route_map_index *index,
                      const char *command, const char *arg)
{
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

static int
isis_route_match_delete(struct vty *vty, struct route_map_index *index,
                        const char *command, const char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

static int
isis_route_set_add(struct vty *vty, struct route_map_index *index,
                   const char *command, const char *arg)
{
  int ret;

  ret = route_map_add_set(index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

static int
isis_route_set_delete (struct vty *vty, struct route_map_index *index,
		       const char *command, const char *arg)
{
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

/* ------------------------------------------------------------*/

DEFUN(match_ip_address,
      match_ip_address_cmd,
      "match ip address (<1-199>|<1300-2699>|WORD)",
      MATCH_STR
      IP_STR
      "Match address of route\n"
      "IP access-list number\n"
      "IP access-list number (expanded range)\n"
      "IP Access-list name\n")
{
  return isis_route_match_add(vty, vty->index, "ip address", argv[0]);
}

DEFUN(no_match_ip_address,
      no_match_ip_address_val_cmd,
      "no match ip address (<1-199>|<1300-2699>|WORD)",
      NO_STR
      MATCH_STR
      IP_STR
      "Match address of route\n"
      "IP access-list number\n"
      "IP access-list number (expanded range)\n"
      "IP Access-list name\n")
{
  if (argc == 0)
    return isis_route_match_delete(vty, vty->index, "ip address", NULL);
  return isis_route_match_delete(vty, vty->index, "ip address", argv[0]);
}

ALIAS(no_match_ip_address,
      no_match_ip_address_cmd,
      "no match ip address",
      NO_STR
      MATCH_STR
      IP_STR
      "Match address of route\n"
);

/* ------------------------------------------------------------*/

DEFUN(match_ip_address_prefix_list,
      match_ip_address_prefix_list_cmd,
      "match ip address prefix-list WORD",
      MATCH_STR
      IP_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n"
      "IP prefix-list name\n")
{
  return isis_route_match_add(vty, vty->index, "ip address prefix-list", argv[0]);
}

DEFUN(no_match_ip_address_prefix_list,
      no_match_ip_address_prefix_list_cmd,
      "no match ip address prefix-list",
      NO_STR
      MATCH_STR
      IP_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n")
{
  if (argc == 0)
    return isis_route_match_delete (vty, vty->index, "ip address prefix-list", NULL);
  return isis_route_match_delete (vty, vty->index, "ip address prefix-list", argv[0]);
}

ALIAS(no_match_ip_address_prefix_list,
      no_match_ip_address_prefix_list_val_cmd,
      "no match ip address prefix-list WORD",
      NO_STR
      MATCH_STR
      IP_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n"
      "IP prefix-list name\n"
);

/* ------------------------------------------------------------*/

DEFUN(match_ipv6_address,
      match_ipv6_address_cmd,
      "match ipv6 address WORD",
      MATCH_STR
      IPV6_STR
      "Match IPv6 address of route\n"
      "IPv6 access-list name\n")
{
  return isis_route_match_add(vty, vty->index, "ipv6 address", argv[0]);
}

DEFUN(no_match_ipv6_address,
      no_match_ipv6_address_val_cmd,
      "no match ipv6 address WORD",
      NO_STR
      MATCH_STR
      IPV6_STR
      "Match IPv6 address of route\n"
      "IPv6 access-list name\n")
{
  if (argc == 0)
    return isis_route_match_delete(vty, vty->index, "ipv6 address", NULL);
  return isis_route_match_delete(vty, vty->index, "ipv6 address", argv[0]);
}

ALIAS(no_match_ipv6_address,
      no_match_ipv6_address_cmd,
      "no match ipv6 address",
      NO_STR
      MATCH_STR
      IPV6_STR
      "Match IPv6 address of route\n"
);

/* ------------------------------------------------------------*/

DEFUN(match_ipv6_address_prefix_list,
      match_ipv6_address_prefix_list_cmd,
      "match ipv6 address prefix-list WORD",
      MATCH_STR
      IPV6_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n"
      "IP prefix-list name\n")
{
  return isis_route_match_add(vty, vty->index, "ipv6 address prefix-list", argv[0]);
}

DEFUN(no_match_ipv6_address_prefix_list,
      no_match_ipv6_address_prefix_list_cmd,
      "no match ipv6 address prefix-list",
      NO_STR
      MATCH_STR
      IPV6_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n")
{
  if (argc == 0)
    return isis_route_match_delete (vty, vty->index, "ipv6 address prefix-list", NULL);
  return isis_route_match_delete (vty, vty->index, "ipv6 address prefix-list", argv[0]);
}

ALIAS(no_match_ipv6_address_prefix_list,
      no_match_ipv6_address_prefix_list_val_cmd,
      "no match ipv6 address prefix-list WORD",
      NO_STR
      MATCH_STR
      IPV6_STR
      "Match address of route\n"
      "Match entries of prefix-lists\n"
      "IP prefix-list name\n"
);

/* ------------------------------------------------------------*/

/* set metric already exists e.g. in the ospf routemap. vtysh doesn't cope well with different
 * commands at the same node, therefore add set metric with the same 32-bit range as ospf and
 * verify that the input is a valid isis metric */
DEFUN(set_metric,
      set_metric_cmd,
      "set metric <0-4294967295>",
      SET_STR
      "Metric vale for destination routing protocol\n"
      "Metric value\n")
{
  return isis_route_set_add(vty, vty->index, "metric", argv[0]);
}

DEFUN(no_set_metric,
      no_set_metric_val_cmd,
      "no set metric <0-4294967295>",
      NO_STR
      SET_STR
      "Metric value for destination routing protocol\n"
      "Metric value\n")
{
  if (argc == 0)
    return isis_route_set_delete(vty, vty->index, "metric", NULL);
  return isis_route_set_delete(vty, vty->index, "metric", argv[0]);
}

ALIAS(no_set_metric,
      no_set_metric_cmd,
      "no set metric",
      NO_STR
      SET_STR
      "Metric vale for destination routing protocol\n"
);

void
isis_route_map_init(void)
{
  route_map_init();
  route_map_init_vty();

  route_map_install_match(&route_match_ip_address_cmd);
  install_element(RMAP_NODE, &match_ip_address_cmd);
  install_element(RMAP_NODE, &no_match_ip_address_val_cmd);
  install_element(RMAP_NODE, &no_match_ip_address_cmd);

  route_map_install_match(&route_match_ip_address_prefix_list_cmd);
  install_element(RMAP_NODE, &match_ip_address_prefix_list_cmd);
  install_element(RMAP_NODE, &no_match_ip_address_prefix_list_val_cmd);
  install_element(RMAP_NODE, &no_match_ip_address_prefix_list_cmd);

  route_map_install_match(&route_match_ipv6_address_cmd);
  install_element(RMAP_NODE, &match_ipv6_address_cmd);
  install_element(RMAP_NODE, &no_match_ipv6_address_val_cmd);
  install_element(RMAP_NODE, &no_match_ipv6_address_cmd);

  route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
  install_element(RMAP_NODE, &match_ipv6_address_prefix_list_cmd);
  install_element(RMAP_NODE, &no_match_ipv6_address_prefix_list_val_cmd);
  install_element(RMAP_NODE, &no_match_ipv6_address_prefix_list_cmd);

  route_map_install_set(&route_set_metric_cmd);
  install_element(RMAP_NODE, &set_metric_cmd);
  install_element(RMAP_NODE, &no_set_metric_val_cmd);
  install_element(RMAP_NODE, &no_set_metric_cmd);
}
