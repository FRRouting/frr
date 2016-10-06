/*
 * Route map function of ospfd.
 * Copyright (C) 2000 IP Infusion Inc.
 *
 * Written by Toshiaki Takada.
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "log.h"
#include "plist.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"

/* Hook function for updating route_map assignment. */
static void
ospf_route_map_update (const char *name)
{
  struct ospf *ospf;
  int type;

  /* If OSPF instatnce does not exist, return right now. */
  ospf = ospf_lookup ();
  if (ospf == NULL)
    return;

  /* Update route-map */
  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      struct list *red_list;
      struct listnode *node;
      struct ospf_redist *red;

      red_list = ospf->redist[type];
      if (!red_list)
        continue;

      for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
        {
          if (ROUTEMAP_NAME (red)
              && strcmp (ROUTEMAP_NAME (red), name) == 0)
            {
              /* Keep old route-map. */
              struct route_map *old = ROUTEMAP (red);

              /* Update route-map. */
              ROUTEMAP (red) =
                route_map_lookup_by_name (ROUTEMAP_NAME (red));

              /* No update for this distribute type. */
              if (old == NULL && ROUTEMAP (red) == NULL)
                continue;

              ospf_distribute_list_update (ospf, type, red->instance);
            }
        }
    }
}

static void
ospf_route_map_event (route_map_event_t event, const char *name)
{
  struct ospf *ospf;
  int type;

  /* If OSPF instatnce does not exist, return right now. */
  ospf = ospf_lookup ();
  if (ospf == NULL)
    return;

  for (type = 0; type <= ZEBRA_ROUTE_MAX; type++)
    {
      struct list *red_list;
      struct listnode *node;
      struct ospf_redist *red;

      red_list = ospf->redist[type];
      if (!red_list)
        continue;

      for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
        {
          if (ROUTEMAP_NAME (red) &&  ROUTEMAP (red)
              && !strcmp (ROUTEMAP_NAME (red), name))
            {
              ospf_distribute_list_update (ospf, type, red->instance);
            }
        }
    }
}

/* Delete rip route map rule. */
static int
ospf_route_match_delete (struct vty *vty, struct route_map_index *index,
			 const char *command, const char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% OSPF Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% OSPF Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

static int
ospf_route_match_add (struct vty *vty, struct route_map_index *index,
		      const char *command, const char *arg)
{                                                                              
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% OSPF Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;
        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% OSPF Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

/* `match ip netxthop ' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_ip_nexthop (void *rule, struct prefix *prefix,
			route_map_object_t type, void *object)
{
  struct access_list *alist;
  struct external_info *ei = object;
  struct prefix_ipv4 p;

  if (type == RMAP_OSPF)
    {
      p.family = AF_INET;
      p.prefix = ei->nexthop;
      p.prefixlen = IPV4_MAX_BITLEN;

      alist = access_list_lookup (AFI_IP, (char *) rule);
      if (alist == NULL)
        return RMAP_NOMATCH;

      return (access_list_apply (alist, &p) == FILTER_DENY ?
              RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement. `arg' should be
   access-list name. */
static void *
route_match_ip_nexthop_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void
route_match_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_ip_nexthop_cmd =
{
  "ip next-hop",
  route_match_ip_nexthop,
  route_match_ip_nexthop_compile,
  route_match_ip_nexthop_free
};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_next_hop_prefix_list (void *rule, struct prefix *prefix,
                                    route_map_object_t type, void *object)
{
  struct prefix_list *plist;
  struct external_info *ei = object;
  struct prefix_ipv4 p;

  if (type == RMAP_OSPF)
    {
      p.family = AF_INET;
      p.prefix = ei->nexthop;
      p.prefixlen = IPV4_MAX_BITLEN;

      plist = prefix_list_lookup (AFI_IP, (char *) rule);
      if (plist == NULL)
        return RMAP_NOMATCH;

      return (prefix_list_apply (plist, &p) == PREFIX_DENY ?
              RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

static void *
route_match_ip_next_hop_prefix_list_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_ip_next_hop_prefix_list_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_next_hop_prefix_list_cmd =
{
  "ip next-hop prefix-list",
  route_match_ip_next_hop_prefix_list,
  route_match_ip_next_hop_prefix_list_compile,
  route_match_ip_next_hop_prefix_list_free
};

/* `match ip address IP_ACCESS_LIST' */
/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t
route_match_ip_address (void *rule, struct prefix *prefix,
                        route_map_object_t type, void *object)
{
  struct access_list *alist;
  /* struct prefix_ipv4 match; */

  if (type == RMAP_OSPF)
    {
      alist = access_list_lookup (AFI_IP, (char *) rule);
      if (alist == NULL)
        return RMAP_NOMATCH;

      return (access_list_apply (alist, prefix) == FILTER_DENY ?
              RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
static void *
route_match_ip_address_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void
route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_address_compile,
  route_match_ip_address_free
};

/* `match ip address prefix-list PREFIX_LIST' */
static route_map_result_t
route_match_ip_address_prefix_list (void *rule, struct prefix *prefix,
                                    route_map_object_t type, void *object)
{
  struct prefix_list *plist;

  if (type == RMAP_OSPF)
    {
      plist = prefix_list_lookup (AFI_IP, (char *) rule);
      if (plist == NULL)
        return RMAP_NOMATCH;

      return (prefix_list_apply (plist, prefix) == PREFIX_DENY ?
              RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

static void *
route_match_ip_address_prefix_list_compile (const char *arg)
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

/* `match interface IFNAME' */
/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t
route_match_interface (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  struct interface *ifp;
  struct external_info *ei;

  if (type == RMAP_OSPF)
    {
      ei = object;
      ifp = if_lookup_by_name ((char *)rule);

      if (ifp == NULL || ifp->ifindex != ei->ifindex)
	return RMAP_NOMATCH;

      return RMAP_MATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `interface' match statement.  `arg' should be
   interface name. */
static void *
route_match_interface_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `interface' value. */
static void
route_match_interface_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_interface_cmd =
{
  "interface",
  route_match_interface,
  route_match_interface_compile,
  route_match_interface_free
};

/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_tag (void *rule, struct prefix *prefix,
                 route_map_object_t type, void *object)
{
  u_short *tag;
  struct external_info *ei;

  if (type == RMAP_OSPF)
    {
      tag = rule;
      ei = object;

      return ((ei->tag == *tag)? RMAP_MATCH : RMAP_NOMATCH);
    }

  return RMAP_NOMATCH;
}

/*  Route map `match tag' match statement. `arg' is TAG value */
static void *
route_match_tag_compile (const char *arg)
{
  u_short *tag;
  u_short tmp;

  /* tag value shoud be integer. */
  if (! all_digit (arg))
    return NULL;

  tmp = atoi(arg);
  if (tmp < 1)
    return NULL;

  tag = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_short));

  if (!tag)
    return tag;

  *tag = tmp;

  return tag;
}

/* Free route map's compiled 'match tag' value. */
static void
route_match_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for tag matching. */
struct route_map_rule_cmd route_match_tag_cmd =
{
  "tag",
  route_match_tag,
  route_match_tag_compile,
  route_match_tag_free,
};


/* `set metric METRIC' */
/* Set metric to attribute. */
static route_map_result_t
route_set_metric (void *rule, struct prefix *prefix,
                  route_map_object_t type, void *object)
{
  u_int32_t *metric;
  struct external_info *ei;

  if (type == RMAP_OSPF)
    {
      /* Fetch routemap's rule information. */
      metric = rule;
      ei = object;

      /* Set metric out value. */
      ei->route_map_set.metric = *metric;
    }
  return RMAP_OKAY;
}

/* set metric compilation. */
static void *
route_set_metric_compile (const char *arg)
{
  u_int32_t *metric;
  int32_t ret;

  /* OSPF doesn't support the +/- in
     set metric <+/-metric> check
     Ignore the +/- component */
  if (! all_digit (arg))
    {
      if ((strncmp (arg, "+", 1) == 0 || strncmp (arg, "-", 1) == 0) &&
	  all_digit (arg+1))
	{
	  zlog_warn ("OSPF does not support 'set metric +/-'");
	  arg++;
	}
      else
	{
	  return NULL;
	}
    }
  metric = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  ret = atoi (arg);

  if (ret >= 0)
    {
      *metric = (u_int32_t)ret;
      return metric;
    }

  XFREE (MTYPE_ROUTE_MAP_COMPILED, metric);
  return NULL;
}

/* Free route map's compiled `set metric' value. */
static void
route_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_cmd =
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};

/* `set metric-type TYPE' */
/* Set metric-type to attribute. */
static route_map_result_t
route_set_metric_type (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  u_int32_t *metric_type;
  struct external_info *ei;

  if (type == RMAP_OSPF)
    {
      /* Fetch routemap's rule information. */
      metric_type = rule;
      ei = object;

      /* Set metric out value. */
      ei->route_map_set.metric_type = *metric_type;
    }
  return RMAP_OKAY;
}

/* set metric-type compilation. */
static void *
route_set_metric_type_compile (const char *arg)
{
  u_int32_t *metric_type;

  metric_type = XCALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  if (strcmp (arg, "type-1") == 0)
    *metric_type = EXTERNAL_METRIC_TYPE_1;
  else if (strcmp (arg, "type-2") == 0)
    *metric_type = EXTERNAL_METRIC_TYPE_2;

  if (*metric_type == EXTERNAL_METRIC_TYPE_1 ||
      *metric_type == EXTERNAL_METRIC_TYPE_2)
    return metric_type;

  XFREE (MTYPE_ROUTE_MAP_COMPILED, metric_type);
  return NULL;
}

/* Free route map's compiled `set metric-type' value. */
static void
route_set_metric_type_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_type_cmd =
{
  "metric-type",
  route_set_metric_type,
  route_set_metric_type_compile,
  route_set_metric_type_free,
};

static route_map_result_t
route_set_tag (void *rule, struct prefix *prefix,
               route_map_object_t type, void *object)
{
  u_short *tag;
  struct external_info *ei;

  if (type == RMAP_OSPF)
    {
      tag = rule;
      ei = object;

      /* Set tag value */
      ei->tag=*tag;
    }

  return RMAP_OKAY;
}

/* Route map `tag' compile function.  Given string is converted to u_short. */
static void *
route_set_tag_compile (const char *arg)
{
  u_short *tag;
  u_short tmp;

  /* tag value shoud be integer. */
  if (! all_digit (arg))
    return NULL;

  tmp = atoi(arg);

  if (tmp < 1)
      return NULL;

  tag = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_short));

  if (!tag)
    return tag;

  *tag = tmp;

  return tag;
}

/* Free route map's tag value. */
static void
route_set_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for tag set. */
struct route_map_rule_cmd route_set_tag_cmd =
{
  "tag",
  route_set_tag,
  route_set_tag_compile,
  route_set_tag_free,
};

DEFUN (match_ip_nexthop,
       match_ip_nexthop_cmd,
       "match ip next-hop <(1-199)|(1300-2699)|WORD>",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP access-list name\n")
{
  int idx_acl = 3;
  return ospf_route_match_add (vty, vty->index, "ip next-hop", argv[idx_acl]->arg);
}

DEFUN (no_match_ip_nexthop,
       no_match_ip_nexthop_cmd,
       "no match ip next-hop [<(1-199)|(1300-2699)|WORD>]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP access-list name\n")
{
  char *al = (argc == 5) ? argv[4]->arg : NULL;
  return ospf_route_match_delete (vty, vty->index, "ip next-hop", al);
}


DEFUN (set_metric_type,
       set_metric_type_cmd,
       "set metric-type <type-1|type-2>",
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
  char *ext = argv[2]->text;
  return generic_set_add (vty, vty->index, "metric-type", ext);
}

DEFUN (no_set_metric_type,
       no_set_metric_type_cmd,
       "no set metric-type [<type-1|type-2>]",
       NO_STR
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
  char *ext = (argc == 4) ? argv[3]->text : NULL;
  return generic_set_delete (vty, vty->index, "metric-type", ext);
}

/* Route-map init */
void
ospf_route_map_init (void)
{
  route_map_init ();
  route_map_init_vty ();

  route_map_add_hook (ospf_route_map_update);
  route_map_delete_hook (ospf_route_map_update);
  route_map_event_hook (ospf_route_map_event);

  route_map_match_interface_hook (generic_match_add);
  route_map_no_match_interface_hook (generic_match_delete);

  route_map_match_ip_address_hook (generic_match_add);
  route_map_no_match_ip_address_hook (generic_match_delete);

  route_map_match_ip_address_prefix_list_hook (generic_match_add);
  route_map_no_match_ip_address_prefix_list_hook (generic_match_delete);

  route_map_match_ip_next_hop_prefix_list_hook (generic_match_add);
  route_map_no_match_ip_next_hop_prefix_list_hook (generic_match_delete);

  route_map_match_tag_hook (generic_match_add);
  route_map_no_match_tag_hook (generic_match_delete);

  route_map_set_metric_hook (generic_set_add);
  route_map_no_set_metric_hook (generic_set_delete);

  route_map_set_tag_hook (generic_set_add);
  route_map_no_set_tag_hook (generic_set_delete);
  
  route_map_install_match (&route_match_ip_nexthop_cmd);
  route_map_install_match (&route_match_ip_next_hop_prefix_list_cmd);
  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_address_prefix_list_cmd);
  route_map_install_match (&route_match_interface_cmd);
  route_map_install_match (&route_match_tag_cmd);

  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_metric_type_cmd);
  route_map_install_set (&route_set_tag_cmd);

  install_element (RMAP_NODE, &match_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_match_ip_nexthop_cmd);

  install_element (RMAP_NODE, &set_metric_type_cmd);
  install_element (RMAP_NODE, &no_set_metric_type_cmd);
}
