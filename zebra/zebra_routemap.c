/* zebra routemap.
 * Copyright (C) 2006 IBM Corporation
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
#include "zebra_memory.h"
#include "prefix.h"
#include "rib.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "nexthop.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"

static u_int32_t zebra_rmap_update_timer = ZEBRA_RMAP_DEFAULT_UPDATE_TIMER;
static struct thread *zebra_t_rmap_update = NULL;
char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];	/* "any" == ZEBRA_ROUTE_MAX */
/* NH Tracking route map */
char *nht_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];	/* "any" == ZEBRA_ROUTE_MAX */
char *zebra_import_table_routemap[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

struct nh_rmap_obj
{
  struct nexthop *nexthop;
  vrf_id_t vrf_id;
  u_int32_t source_protocol;
  int metric;
  route_tag_t tag;
};

static void zebra_route_map_set_delay_timer(u_int32_t value);

/* Add zebra route map rule */
static int
zebra_route_match_add(struct vty *vty,
		      const char *command, const char *arg,
		      route_map_event_t type)
{
  VTY_DECLVAR_CONTEXT (route_map_index, index);
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "%% Zebra Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "%% Zebra Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (type != RMAP_EVENT_MATCH_ADDED)
    {
      route_map_upd8_dependency (type, arg, index->map->name);
    }
  return CMD_SUCCESS;
}

/* Delete zebra route map rule. */
static int
zebra_route_match_delete (struct vty *vty,
			  const char *command, const char *arg,
			  route_map_event_t type)
{
  VTY_DECLVAR_CONTEXT (route_map_index, index);
  int ret;
  char *dep_name = NULL;
  const char *tmpstr;
  char *rmap_name = NULL;

  if (type != RMAP_EVENT_MATCH_DELETED)
    {
      /* ignore the mundane, the types without any dependency */
      if (arg == NULL)
	{
	  if ((tmpstr = route_map_get_match_arg(index, command)) != NULL)
	    dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, tmpstr);
	}
      else
	{
	  dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, arg);
	}
      rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
    }

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "%% Zebra Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "%% Zebra Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (type != RMAP_EVENT_MATCH_DELETED && dep_name)
    route_map_upd8_dependency(type, dep_name, rmap_name);

  if (dep_name)
    XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
  if (rmap_name)
    XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

  return CMD_SUCCESS;
}

/* Add zebra route map rule. */
static int
zebra_route_set_add (struct vty *vty,
		   const char *command, const char *arg)
{
  VTY_DECLVAR_CONTEXT (route_map_index, index);
  int ret;

  ret = route_map_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "%% Zebra Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "%% Zebra Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  return CMD_SUCCESS;
}

/* Delete zebra route map rule. */
static int
zebra_route_set_delete (struct vty *vty,
		      const char *command, const char *arg)
{
  VTY_DECLVAR_CONTEXT (route_map_index, index);
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case RMAP_RULE_MISSING:
	  vty_out (vty, "%% Zebra Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case RMAP_COMPILE_ERROR:
	  vty_out (vty, "%% Zebra Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  return CMD_SUCCESS;
}

/* 'match tag TAG'
 * Match function return 1 if match is success else return 0
 */
static route_map_result_t
route_match_tag (void *rule, struct prefix *prefix,
		 route_map_object_t type, void *object)
{
  route_tag_t *tag;
  struct nh_rmap_obj *nh_data;

  if (type == RMAP_ZEBRA)
    {
      tag = rule;
      nh_data = object;

      if (nh_data->tag == *tag)
	return RMAP_MATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map commands for tag matching */
static struct route_map_rule_cmd route_match_tag_cmd =
{
  "tag",
  route_match_tag,
  route_map_rule_tag_compile,
  route_map_rule_tag_free,
};


/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_interface (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  struct nh_rmap_obj *nh_data;
  char *ifname = rule;
  ifindex_t ifindex;

  if (type == RMAP_ZEBRA)
    {
      if (strcasecmp(ifname, "any") == 0)
	return RMAP_MATCH;
      nh_data = object;
      if (!nh_data || !nh_data->nexthop)
	return RMAP_NOMATCH;
      ifindex = ifname2ifindex_vrf (ifname, nh_data->vrf_id);
      if (ifindex == 0)
	return RMAP_NOMATCH;
      if (nh_data->nexthop->ifindex == ifindex)
	return RMAP_MATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
static void *
route_match_interface_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `match interface' value. */
static void
route_match_interface_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for interface matching */
struct route_map_rule_cmd route_match_interface_cmd =
{
   "interface",
   route_match_interface,
   route_match_interface_compile,
   route_match_interface_free
};

DEFUN (match_interface,
       match_interface_cmd,
       "match interface WORD",
       MATCH_STR
       "match first hop interface of route\n"
       "Interface name\n")
{
  return zebra_route_match_add (vty, "interface", argv[0],
				RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_interface,
       no_match_interface_cmd,
       "no match interface",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty, "interface", NULL, RMAP_EVENT_MATCH_DELETED);

  return zebra_route_match_delete (vty, "interface", argv[0], RMAP_EVENT_MATCH_DELETED);
}

ALIAS (no_match_interface,
       no_match_interface_val_cmd,
       "no match interface WORD",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")

DEFUN (match_tag,
       match_tag_cmd,
       "match tag <1-4294967295>",
       MATCH_STR
       "Match tag of route\n"
       "Tag value\n")
{
  return zebra_route_match_add (vty, "tag", argv[0],
                                RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_tag,
       no_match_tag_cmd,
       "no match tag",
       NO_STR
       MATCH_STR
       "Match tag of route\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty, "tag", NULL,
                                     RMAP_EVENT_MATCH_DELETED);

  return zebra_route_match_delete (vty, "tag", argv[0],
                                   RMAP_EVENT_MATCH_DELETED);
}

ALIAS (no_match_tag,
       no_match_tag_val_cmd,
       "no match tag <1-4294967295>",
       NO_STR
       MATCH_STR
       "Match tag of route\n")

DEFUN (match_ip_next_hop,
       match_ip_next_hop_cmd,
       "match ip next-hop (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
  return zebra_route_match_add (vty, "ip next-hop", argv[0], RMAP_EVENT_FILTER_ADDED);
}

DEFUN (no_match_ip_next_hop,
       no_match_ip_next_hop_cmd,
       "no match ip next-hop",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty, "ip next-hop", NULL,
				     RMAP_EVENT_FILTER_DELETED);

  return zebra_route_match_delete (vty, "ip next-hop", argv[0],
				   RMAP_EVENT_FILTER_DELETED);
}

ALIAS (no_match_ip_next_hop,
       no_match_ip_next_hop_val_cmd,
       "no match ip next-hop (<1-199>|<1300-2699>|WORD)",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")

DEFUN (match_ip_next_hop_prefix_list,
       match_ip_next_hop_prefix_list_cmd,
       "match ip next-hop prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return zebra_route_match_add (vty, "ip next-hop prefix-list",
				argv[0], RMAP_EVENT_PLIST_ADDED);
}

DEFUN (no_match_ip_next_hop_prefix_list,
       no_match_ip_next_hop_prefix_list_cmd,
       "no match ip next-hop prefix-list",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty,
				     "ip next-hop prefix-list", NULL,
				     RMAP_EVENT_PLIST_DELETED);

  return zebra_route_match_delete (vty,
				   "ip next-hop prefix-list", argv[0],
				   RMAP_EVENT_PLIST_DELETED);
}

ALIAS (no_match_ip_next_hop_prefix_list,
       no_match_ip_next_hop_prefix_list_val_cmd,
       "no match ip next-hop prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFUN (match_ip_address,
       match_ip_address_cmd,
       "match ip address (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")

{
  return zebra_route_match_add (vty, "ip address", argv[0],
				RMAP_EVENT_FILTER_ADDED);
}

DEFUN (no_match_ip_address, 
       no_match_ip_address_cmd,
       "no match ip address",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty, "ip address", NULL,
				     RMAP_EVENT_FILTER_DELETED);

  return zebra_route_match_delete (vty, "ip address", argv[0],
				   RMAP_EVENT_FILTER_DELETED);
}

ALIAS (no_match_ip_address,
       no_match_ip_address_val_cmd,
       "no match ip address (<1-199>|<1300-2699>|WORD)",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")

DEFUN (match_ip_address_prefix_list, 
       match_ip_address_prefix_list_cmd,
       "match ip address prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return zebra_route_match_add (vty, "ip address prefix-list",
				argv[0], RMAP_EVENT_PLIST_ADDED);
}

DEFUN (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_cmd,
       "no match ip address prefix-list",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty,
				     "ip address prefix-list", NULL,
				     RMAP_EVENT_PLIST_DELETED);

  return zebra_route_match_delete (vty,
				   "ip address prefix-list", argv[0],
				   RMAP_EVENT_PLIST_DELETED);
}

ALIAS (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_val_cmd,
       "no match ip address prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFUN (match_ip_address_prefix_len,
       match_ip_address_prefix_len_cmd,
       "match ip address prefix-len NUMBER",
       MATCH_STR
       IP_STR
       "Match prefix length of ip address\n"
       "Match prefix length of ip address\n"
       "Prefix length\n")
{
  return zebra_route_match_add (vty, "ip address prefix-len",
				argv[0], RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ip_address_prefix_len,
       no_match_ip_address_prefix_len_cmd,
       "no match ip address prefix-len",
       NO_STR
       MATCH_STR
       IP_STR
       "Match prefixlen of ip address of route\n"
       "prefix length of ip address\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty,
				     "ip address prefix-len", NULL,
				     RMAP_EVENT_MATCH_DELETED);

  return zebra_route_match_delete (vty,
				   "ip address prefix-len", argv[0],
				   RMAP_EVENT_MATCH_DELETED);
}

ALIAS (no_match_ip_address_prefix_len,
       no_match_ip_address_prefix_len_val_cmd,
       "no match ip address prefix-len NUMBER",
       NO_STR
       MATCH_STR
       IP_STR
       "Match prefixlen of ip address of route\n"
       "prefix length of ip address\n")

DEFUN (match_ip_nexthop_prefix_len,
       match_ip_nexthop_prefix_len_cmd,
       "match ip next-hop prefix-len NUMBER",
       MATCH_STR
       IP_STR
       "Match prefixlen of nexthop ip address\n"
       "Match prefixlen of given nexthop\n"
       "Prefix length\n")
{
  return zebra_route_match_add (vty, "ip next-hop prefix-len",
				argv[0], RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ip_nexthop_prefix_len,
       no_match_ip_nexthop_prefix_len_cmd,
       "no match ip next-hop prefix-len",
       NO_STR
       MATCH_STR
       IP_STR
       "Match prefixlen of nexthop ip address\n"
       "Match prefix length of nexthop\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty,
				     "ip next-hop prefix-len", NULL,
				     RMAP_EVENT_MATCH_DELETED);

  return zebra_route_match_delete (vty,
				   "ip next-hop prefix-len", argv[0],
				   RMAP_EVENT_MATCH_DELETED);
}

ALIAS (no_match_ip_nexthop_prefix_len,
       no_match_ip_nexthop_prefix_len_val_cmd,
       "no match ip next-hop prefix-len NUMBER",
       MATCH_STR
       "Match prefixlen of ip address of route\n"
       "prefix length of ip address\n")

DEFUN (match_source_protocol,
       match_source_protocol_cmd,
       "match source-protocol (bgp|ospf|rip|ripng|isis|ospf6|connected|system|kernel|static)",
       MATCH_STR
       "Match protocol via which the route was learnt\n")
{
  int i;

  i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  return zebra_route_match_add (vty, "source-protocol",
				argv[0], RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_source_protocol,
       no_match_source_protocol_cmd,
       "no match source-protocol (bgp|ospf|rip|ripng|isis|ospf6|connected|system|kernel|static)",
       NO_STR
       MATCH_STR
       "No match protocol via which the route was learnt\n")
{
  int i;

  if (argc >= 1)
    {
      i = proto_name2num(argv[0]);
      if (i < 0)
	{
	  vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  return zebra_route_match_delete (vty,
				   "source-protocol", argv[0] ? argv[0] : NULL,
				   RMAP_EVENT_MATCH_DELETED);
}

/* set functions */

DEFUN (set_src,
       set_src_cmd,
       "set src (A.B.C.D|X:X::X:X)",
       SET_STR
       "src address for route\n"
       "src address\n")
{
  union g_addr src;
  struct interface *pif = NULL;
  int family;
  struct prefix p;
  vrf_iter_t iter;

  if (inet_pton(AF_INET, argv[0], &src.ipv4) != 1)
    {
      if (inet_pton(AF_INET6, argv[0], &src.ipv6) != 1)
	{
	  vty_out (vty, "%% not a valid IPv4/v6 address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      p.family = family = AF_INET6;
      p.u.prefix6 = src.ipv6;
      p.prefixlen = IPV6_MAX_BITLEN;
    }
  else
    {
      p.family = family = AF_INET;
      p.u.prefix4 = src.ipv4;
      p.prefixlen = IPV4_MAX_BITLEN;
    }

  if (!zebra_check_addr(&p))
    {
	  vty_out (vty, "%% not a valid source IPv4/v6 address%s", VTY_NEWLINE);
	  return CMD_WARNING;
    }

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if (family == AF_INET)
        pif = if_lookup_exact_address_vrf ((void *)&src.ipv4, AF_INET,
                                           vrf_iter2id (iter));
      else if (family == AF_INET6)
        pif = if_lookup_exact_address_vrf ((void *)&src.ipv6, AF_INET6,
                                           vrf_iter2id (iter));

      if (pif != NULL)
        break;
    }

  if (!pif)
    {
      vty_out (vty, "%% not a local address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return zebra_route_set_add (vty, "src", argv[0]);
}

DEFUN (no_set_src,
       no_set_src_cmd,
       "no set src {A.B.C.D|X:X::X:X}",
       NO_STR
       SET_STR
       "Source address for route\n")
{
  if (argc == 0)
    return zebra_route_set_delete (vty, "src", NULL);

  return zebra_route_set_delete (vty, "src", argv[0]);
}

DEFUN (zebra_route_map_timer,
       zebra_route_map_timer_cmd,
       "zebra route-map delay-timer <0-600>",
       "Time to wait before route-map updates are processed\n"
       "0 means event-driven updates are disabled\n")
{
  u_int32_t rmap_delay_timer;

  VTY_GET_INTEGER_RANGE ("delay-timer", rmap_delay_timer, argv[0], 0, 600);
  zebra_route_map_set_delay_timer(rmap_delay_timer);

  return (CMD_SUCCESS);
}

DEFUN (no_zebra_route_map_timer,
       no_zebra_route_map_timer_cmd,
       "no zebra route-map delay-timer",
       NO_STR
       "Time to wait before route-map updates are processed\n"
       "Reset delay-timer to default value, 30 secs\n")
{
  zebra_route_map_set_delay_timer(ZEBRA_RMAP_DEFAULT_UPDATE_TIMER);

  return (CMD_SUCCESS);
}

ALIAS (no_zebra_route_map_timer,
       no_zebra_route_map_timer_val_cmd,
       "no zebra route-map delay-timer <0-600>",
       NO_STR
       "Time to wait before route-map updates are processed\n"
       "Reset delay-timer to default value, 30 secs\n"
       "0 means event-driven updates are disabled\n")

DEFUN (ip_protocol,
       ip_protocol_cmd,
       "ip protocol " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP_STR
       "Filter routing info exchanged between zebra and protocol\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (proto_rm[AFI_IP][i])
    {
      if (strcmp(proto_rm[AFI_IP][i], argv[1]) == 0)
	return CMD_SUCCESS;

      XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
    }
  proto_rm[AFI_IP][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);

  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    zlog_debug ("%u: IPv4 Routemap config for protocol %s, scheduling RIB processing",
                VRF_DEFAULT, argv[0]);

  rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
  return CMD_SUCCESS;
}

DEFUN (no_ip_protocol,
       no_ip_protocol_cmd,
       "no ip protocol " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA,
       NO_STR
       IP_STR
       "Stop filtering routing info between zebra and protocol\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Protocol from which to stop filtering routes\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
     return CMD_WARNING;
    }
  if (!proto_rm[AFI_IP][i])
    return CMD_SUCCESS;

  if ((argc == 2 && strcmp(argv[1], proto_rm[AFI_IP][i]) == 0) ||
      (argc < 2))
    {
      XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
      proto_rm[AFI_IP][i] = NULL;

      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        zlog_debug ("%u: IPv4 Routemap unconfig for protocol %s, scheduling RIB processing",
                    VRF_DEFAULT, argv[0]);
      rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_ip_protocol,
       no_ip_protocol_val_cmd,
       "no ip protocol " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       NO_STR
       IP_STR
       "Stop filtering routing info between zebra and protocol\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "route map name")

DEFUN (show_ip_protocol,
       show_ip_protocol_cmd,
       "show ip protocol",
        SHOW_STR
        IP_STR
       "IP protocol filtering status\n")
{
    int i;

    vty_out(vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out(vty, "------------------------%s", VTY_NEWLINE);
    for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
        if (proto_rm[AFI_IP][i])
          vty_out (vty, "%-10s  : %-10s%s", zebra_route_string(i),
					proto_rm[AFI_IP][i],
					VTY_NEWLINE);
        else
          vty_out (vty, "%-10s  : none%s", zebra_route_string(i), VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP][i])
      vty_out (vty, "%-10s  : %-10s%s", "any", proto_rm[AFI_IP][i],
					VTY_NEWLINE);
    else
      vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (ipv6_protocol,
       ipv6_protocol_cmd,
       "ipv6 protocol " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP6_STR
       "Filter IPv6 routing info exchanged between zebra and protocol\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (proto_rm[AFI_IP6][i])
    {
      if (strcmp(proto_rm[AFI_IP6][i], argv[1]) == 0)
	return CMD_SUCCESS;

      XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP6][i]);
    }
  proto_rm[AFI_IP6][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);

  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    zlog_debug ("%u: IPv6 Routemap config for protocol %s, scheduling RIB processing",
                VRF_DEFAULT, argv[0]);

  rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_protocol,
       no_ipv6_protocol_cmd,
       "no ipv6 protocol " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA,
       NO_STR
       IP6_STR
       "Stop filtering IPv6 routing info between zebra and protocol\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Protocol from which to stop filtering routes\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
     return CMD_WARNING;
    }
  if (!proto_rm[AFI_IP6][i])
    return CMD_SUCCESS;

  if ((argc == 2 && strcmp(argv[1], proto_rm[AFI_IP6][i]) == 0) ||
      (argc < 2))
    {
      XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP6][i]);
      proto_rm[AFI_IP6][i] = NULL;

      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        zlog_debug ("%u: IPv6 Routemap unconfig for protocol %s, scheduling RIB processing",
                    VRF_DEFAULT, argv[0]);

      rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_ipv6_protocol,
       no_ipv6_protocol_val_cmd,
       "no ipv6 protocol " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       NO_STR
       IP6_STR
       "Stop filtering IPv6 routing info between zebra and protocol\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "route map name")

DEFUN (show_ipv6_protocol,
       show_ipv6_protocol_cmd,
       "show ipv6 protocol",
        SHOW_STR
        IP6_STR
       "IPv6 protocol filtering status\n")
{
    int i;

    vty_out(vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out(vty, "------------------------%s", VTY_NEWLINE);
    for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
        if (proto_rm[AFI_IP6][i])
          vty_out (vty, "%-10s  : %-10s%s", zebra_route_string(i),
					proto_rm[AFI_IP6][i],
					VTY_NEWLINE);
        else
          vty_out (vty, "%-10s  : none%s", zebra_route_string(i), VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP6][i])
      vty_out (vty, "%-10s  : %-10s%s", "any", proto_rm[AFI_IP6][i],
					VTY_NEWLINE);
    else
      vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (ip_protocol_nht_rmap,
       ip_protocol_nht_rmap_cmd,
       "ip nht " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (nht_rm[AFI_IP][i])
    {
      if (strcmp(nht_rm[AFI_IP][i], argv[1]) == 0)
	return CMD_SUCCESS;

      XFREE (MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP][i]);
    }

  nht_rm[AFI_IP][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);
  zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_ip_protocol_nht_rmap,
       no_ip_protocol_nht_rmap_cmd,
       "no ip nht " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA,
       NO_STR
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA)
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
     return CMD_WARNING;
    }
  if (!nht_rm[AFI_IP][i])
    return CMD_SUCCESS;

  if ((argc == 2 && strcmp(argv[1], nht_rm[AFI_IP][i]) == 0) ||
      (argc < 2))
    {
      XFREE (MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP][i]);
      nht_rm[AFI_IP][i] = NULL;
      zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
    }
  return CMD_SUCCESS;
}

ALIAS (no_ip_protocol_nht_rmap,
       no_ip_protocol_nht_rmap_val_cmd,
       "no ip nht " QUAGGA_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")

DEFUN (show_ip_protocol_nht,
       show_ip_protocol_nht_cmd,
       "show ip nht route-map",
        SHOW_STR
        IP_STR
       "IP Next Hop tracking filtering status\n")
{
    int i;

    vty_out(vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out(vty, "------------------------%s", VTY_NEWLINE);
    for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
        if (nht_rm[AFI_IP][i])
          vty_out (vty, "%-10s  : %-10s%s", zebra_route_string(i),
					nht_rm[AFI_IP][i],
					VTY_NEWLINE);
        else
          vty_out (vty, "%-10s  : none%s", zebra_route_string(i), VTY_NEWLINE);
    }
    if (nht_rm[AFI_IP][i])
      vty_out (vty, "%-10s  : %-10s%s", "any", nht_rm[AFI_IP][i],
					VTY_NEWLINE);
    else
      vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (ipv6_protocol_nht_rmap,
       ipv6_protocol_nht_rmap_cmd,
       "ipv6 nht " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (nht_rm[AFI_IP6][i])
    XFREE (MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP6][i]);
  nht_rm[AFI_IP6][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);
  zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_protocol_nht_rmap,
       no_ipv6_protocol_nht_rmap_cmd,
       "no ipv6 nht " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA,
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA)
{
  int i;

  if (strcasecmp(argv[0], "any") == 0)
    i = ZEBRA_ROUTE_MAX;
  else
    i = proto_name2num(argv[0]);
  if (i < 0)
    {
      vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "",
               VTY_NEWLINE);
     return CMD_WARNING;
    }

  if (nht_rm[AFI_IP6][i] && argc == 2 && strcmp(argv[1], nht_rm[AFI_IP6][i]))
    {
      vty_out (vty, "invalid route-map \"%s\"%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (nht_rm[AFI_IP6][i])
    {
      XFREE (MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP6][i]);
      nht_rm[AFI_IP6][i] = NULL;
    }

  zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

  return CMD_SUCCESS;
}

ALIAS (no_ipv6_protocol_nht_rmap,
       no_ipv6_protocol_nht_rmap_val_cmd,
       "no ipv6 nht " QUAGGA_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       QUAGGA_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Route map name\n")

DEFUN (show_ipv6_protocol_nht,
       show_ipv6_protocol_nht_cmd,
       "show ipv6 nht route-map",
        SHOW_STR
        IP6_STR
       "IPv6 protocol Next Hop filtering status\n")
{
    int i;

    vty_out(vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out(vty, "------------------------%s", VTY_NEWLINE);
    for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
        if (nht_rm[AFI_IP6][i])
          vty_out (vty, "%-10s  : %-10s%s", zebra_route_string(i),
					nht_rm[AFI_IP6][i],
					VTY_NEWLINE);
        else
          vty_out (vty, "%-10s  : none%s", zebra_route_string(i), VTY_NEWLINE);
    }
    if (nht_rm[AFI_IP][i])
      vty_out (vty, "%-10s  : %-10s%s", "any", nht_rm[AFI_IP6][i],
					VTY_NEWLINE);
    else
      vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXX*/

/* `match ip next-hop IP_ACCESS_LIST' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_ip_next_hop (void *rule, struct prefix *prefix,
			route_map_object_t type, void *object)
{
  struct access_list *alist;
  struct nh_rmap_obj *nh_data;
  struct prefix_ipv4 p;

  if (type == RMAP_ZEBRA)
    {
      nh_data = object;
      if (!nh_data)
	return RMAP_DENYMATCH;

      switch (nh_data->nexthop->type) {
      case NEXTHOP_TYPE_IFINDEX:
        /* Interface routes can't match ip next-hop */
        return RMAP_NOMATCH;
      case NEXTHOP_TYPE_IPV4_IFINDEX:
      case NEXTHOP_TYPE_IPV4:
        p.family = AF_INET;
        p.prefix = nh_data->nexthop->gate.ipv4;
        p.prefixlen = IPV4_MAX_BITLEN;
        break;
      default:
        return RMAP_NOMATCH;
      }
      alist = access_list_lookup (AFI_IP, (char *) rule);
      if (alist == NULL)
	return RMAP_NOMATCH;

      return (access_list_apply (alist, &p) == FILTER_DENY ?
	      RMAP_NOMATCH : RMAP_MATCH);
    }
  return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement.  `arg' should be
   access-list name. */
static void *
route_match_ip_next_hop_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `. */
static void
route_match_ip_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
static struct route_map_rule_cmd route_match_ip_next_hop_cmd =
{
  "ip next-hop",
  route_match_ip_next_hop,
  route_match_ip_next_hop_compile,
  route_match_ip_next_hop_free
};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_next_hop_prefix_list (void *rule, struct prefix *prefix,
                                    route_map_object_t type, void *object)
{
  struct prefix_list *plist;
  struct nh_rmap_obj *nh_data;
  struct prefix_ipv4 p;

  if (type == RMAP_ZEBRA)
    {
      nh_data = (struct nh_rmap_obj *)object;
      if (!nh_data)
	return RMAP_DENYMATCH;

      switch (nh_data->nexthop->type) {
      case NEXTHOP_TYPE_IFINDEX:
        /* Interface routes can't match ip next-hop */
        return RMAP_NOMATCH;
      case NEXTHOP_TYPE_IPV4_IFINDEX:
      case NEXTHOP_TYPE_IPV4:
        p.family = AF_INET;
        p.prefix = nh_data->nexthop->gate.ipv4;
        p.prefixlen = IPV4_MAX_BITLEN;
        break;
      default:
        return RMAP_NOMATCH;
      }
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

static struct route_map_rule_cmd route_match_ip_next_hop_prefix_list_cmd =
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

  if (type == RMAP_ZEBRA)
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
static struct route_map_rule_cmd route_match_ip_address_cmd =
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

  if (type == RMAP_ZEBRA)
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

static struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd =
{
  "ip address prefix-list",
  route_match_ip_address_prefix_list,
  route_match_ip_address_prefix_list_compile,
  route_match_ip_address_prefix_list_free
};


/* `match ip address prefix-len PREFIXLEN' */

static route_map_result_t
route_match_ip_address_prefix_len (void *rule, struct prefix *prefix,
				    route_map_object_t type, void *object)
{
  u_int32_t *prefixlen = (u_int32_t *)rule;

  if (type == RMAP_ZEBRA)
    {
      return ((prefix->prefixlen == *prefixlen) ? RMAP_MATCH : RMAP_NOMATCH);
    }
  return RMAP_NOMATCH;
}

static void *
route_match_ip_address_prefix_len_compile (const char *arg)
{
  u_int32_t *prefix_len;
  char *endptr = NULL;
  unsigned long tmpval;

  /* prefix len value shoud be integer. */
  if (! all_digit (arg))
    return NULL;

  errno = 0;
  tmpval = strtoul (arg, &endptr, 10);
  if (*endptr != '\0' || errno || tmpval > UINT32_MAX)
    return NULL;

  prefix_len = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));

  if (!prefix_len)
    return prefix_len;

  *prefix_len = tmpval;
  return prefix_len;
}

static void
route_match_ip_address_prefix_len_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_address_prefix_len_cmd =
{
  "ip address prefix-len",
  route_match_ip_address_prefix_len,
  route_match_ip_address_prefix_len_compile,
  route_match_ip_address_prefix_len_free
};


/* `match ip nexthop prefix-len PREFIXLEN' */

static route_map_result_t
route_match_ip_nexthop_prefix_len (void *rule, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
  u_int32_t *prefixlen = (u_int32_t *)rule;
  struct nh_rmap_obj *nh_data;
  struct prefix_ipv4 p;

  if (type == RMAP_ZEBRA)
    {
      nh_data = (struct nh_rmap_obj *)object;
      if (!nh_data || !nh_data->nexthop)
	return RMAP_DENYMATCH;

      switch (nh_data->nexthop->type) {
      case NEXTHOP_TYPE_IFINDEX:
        /* Interface routes can't match ip next-hop */
        return RMAP_NOMATCH;
      case NEXTHOP_TYPE_IPV4_IFINDEX:
      case NEXTHOP_TYPE_IPV4:
        p.family = AF_INET;
        p.prefix = nh_data->nexthop->gate.ipv4;
        p.prefixlen = IPV4_MAX_BITLEN;
        break;
      default:
        return RMAP_NOMATCH;
      }
      return ((p.prefixlen == *prefixlen) ? RMAP_MATCH : RMAP_NOMATCH);
    }
  return RMAP_NOMATCH;
}

static struct route_map_rule_cmd route_match_ip_nexthop_prefix_len_cmd =
{
  "ip next-hop prefix-len",
  route_match_ip_nexthop_prefix_len,
  route_match_ip_address_prefix_len_compile, /* reuse */
  route_match_ip_address_prefix_len_free     /* reuse */
};

/* `match source-protocol PROTOCOL' */

static route_map_result_t
route_match_source_protocol (void *rule, struct prefix *prefix,
			     route_map_object_t type, void *object)
{
  u_int32_t *rib_type = (u_int32_t *)rule;
  struct nh_rmap_obj *nh_data;

  if (type == RMAP_ZEBRA)
    {
      nh_data = (struct nh_rmap_obj *)object;
      if (!nh_data)
	return RMAP_DENYMATCH;

      return ((nh_data->source_protocol == *rib_type)
	      ? RMAP_MATCH : RMAP_NOMATCH);
    }
  return RMAP_NOMATCH;
}

static void *
route_match_source_protocol_compile (const char *arg)
{
  u_int32_t *rib_type;
  int i;

  i = proto_name2num(arg);
  rib_type = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));

  *rib_type = i;

  return rib_type;
}

static void
route_match_source_protocol_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_source_protocol_cmd =
{
  "source-protocol",
  route_match_source_protocol,
  route_match_source_protocol_compile,
  route_match_source_protocol_free
};

/* `set src A.B.C.D' */

/* Set src. */
static route_map_result_t
route_set_src (void *rule, struct prefix *prefix, 
		  route_map_object_t type, void *object)
{
  struct nh_rmap_obj *nh_data;

  if (type == RMAP_ZEBRA)
    {
      nh_data = (struct nh_rmap_obj *)object;
      nh_data->nexthop->rmap_src = *(union g_addr *)rule;
    }
  return RMAP_OKAY;
}

/* set src compilation. */
static void *
route_set_src_compile (const char *arg)
{
  union g_addr src, *psrc;

  if (
#ifdef HAVE_IPV6
      (inet_pton(AF_INET6, arg, &src.ipv6) == 1) ||
#endif /* HAVE_IPV6 */
      (src.ipv4.s_addr && (inet_pton(AF_INET, arg, &src.ipv4) == 1)))
    {
      psrc = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (union g_addr));
      *psrc = src;
      return psrc;
    }
  return NULL;
}

/* Free route map's compiled `set src' value. */
static void
route_set_src_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set src rule structure. */
static struct route_map_rule_cmd route_set_src_cmd = 
{
  "src",
  route_set_src,
  route_set_src_compile,
  route_set_src_free,
};

static int
zebra_route_map_update_timer (struct thread *thread)
{
  zebra_t_rmap_update = NULL;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug("Event driven route-map update triggered");

  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    zlog_debug ("%u: Routemap update-timer fired, scheduling RIB processing",
                VRF_DEFAULT);

  zebra_import_table_rm_update ();
  rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
  zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
  zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

  return (0);
}

static void
zebra_route_map_set_delay_timer(u_int32_t value)
{
  zebra_rmap_update_timer = value;
  if (!value && zebra_t_rmap_update)
    {
      /* Event driven route map updates is being disabled */
      /* But there's a pending timer. Fire it off now */
      thread_cancel(zebra_t_rmap_update);
      zebra_route_map_update_timer(zebra_t_rmap_update);
    }
}

void
zebra_route_map_write_delay_timer (struct vty *vty)
{
  if (vty && (zebra_rmap_update_timer != ZEBRA_RMAP_DEFAULT_UPDATE_TIMER))
    vty_out (vty, "zebra route-map delay-timer %d%s", zebra_rmap_update_timer,
	     VTY_NEWLINE);
  return;
}

route_map_result_t
zebra_route_map_check (int family, int rib_type, struct prefix *p,
		       struct nexthop *nexthop, vrf_id_t vrf_id, route_tag_t tag)
{
  struct route_map *rmap = NULL;
  route_map_result_t ret = RMAP_MATCH;
  struct nh_rmap_obj nh_obj;

  nh_obj.nexthop = nexthop;
  nh_obj.vrf_id = vrf_id;
  nh_obj.source_protocol = rib_type;
  nh_obj.metric = 0;
  nh_obj.tag = tag;

  if (rib_type >= 0 && rib_type < ZEBRA_ROUTE_MAX)
    rmap = route_map_lookup_by_name (proto_rm[family][rib_type]);
  if (!rmap && proto_rm[family][ZEBRA_ROUTE_MAX])
    rmap = route_map_lookup_by_name (proto_rm[family][ZEBRA_ROUTE_MAX]);
  if (rmap) {
      ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
  }

  return (ret);
}

char *
zebra_get_import_table_route_map (afi_t afi, uint32_t table)
{
  return zebra_import_table_routemap[afi][table];
}

void
zebra_add_import_table_route_map (afi_t afi, const char *rmap_name, uint32_t table)
{
  zebra_import_table_routemap[afi][table] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, rmap_name);
}

void
zebra_del_import_table_route_map (afi_t afi, uint32_t table)
{
  XFREE (MTYPE_ROUTE_MAP_NAME, zebra_import_table_routemap[afi][table]);
}

route_map_result_t
zebra_import_table_route_map_check (int family, int rib_type, struct prefix *p,
                struct nexthop *nexthop, vrf_id_t vrf_id, route_tag_t tag, const char *rmap_name)
{
  struct route_map *rmap = NULL;
  route_map_result_t ret = RMAP_DENYMATCH;
  struct nh_rmap_obj nh_obj;

  nh_obj.nexthop = nexthop;
  nh_obj.vrf_id = vrf_id;
  nh_obj.source_protocol = rib_type;
  nh_obj.metric = 0;
  nh_obj.tag = tag;

  if (rib_type >= 0 && rib_type < ZEBRA_ROUTE_MAX)
    rmap = route_map_lookup_by_name (rmap_name);
  if (rmap) {
      ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
  }

  return (ret);
}

route_map_result_t
zebra_nht_route_map_check (int family, int client_proto, struct prefix *p,
			   struct rib * rib, struct nexthop *nexthop)
{
  struct route_map *rmap = NULL;
  route_map_result_t ret = RMAP_MATCH;
  struct nh_rmap_obj nh_obj;

  nh_obj.nexthop = nexthop;
  nh_obj.vrf_id = rib->vrf_id;
  nh_obj.source_protocol = rib->type;
  nh_obj.metric = rib->metric;
  nh_obj.tag = rib->tag;

  if (client_proto >= 0 && client_proto < ZEBRA_ROUTE_MAX)
    rmap = route_map_lookup_by_name (nht_rm[family][client_proto]);
  if (!rmap && nht_rm[family][ZEBRA_ROUTE_MAX])
    rmap = route_map_lookup_by_name (nht_rm[family][ZEBRA_ROUTE_MAX]);
  if (rmap) {
      ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
  }

  return (ret);
}

static void
zebra_route_map_mark_update (const char *rmap_name)
{
  /* rmap_update_timer of 0 means don't do route updates */
  if (zebra_rmap_update_timer && !zebra_t_rmap_update)
    zebra_t_rmap_update =
      thread_add_timer(zebrad.master, zebra_route_map_update_timer, NULL,
		       zebra_rmap_update_timer);
}

static void
zebra_route_map_add (const char *rmap_name)
{
  zebra_route_map_mark_update(rmap_name);
  route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void
zebra_route_map_delete (const char *rmap_name)
{
  zebra_route_map_mark_update(rmap_name);
  route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void
zebra_route_map_event (route_map_event_t event, const char *rmap_name)
{
  zebra_route_map_mark_update(rmap_name);
  route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

/* ip protocol configuration write function */
void
zebra_routemap_config_write_protocol (struct vty *vty)
{
  int i;

  for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
      if (proto_rm[AFI_IP][i])
        vty_out (vty, "ip protocol %s route-map %s%s", zebra_route_string(i),
                 proto_rm[AFI_IP][i], VTY_NEWLINE);

      if (proto_rm[AFI_IP6][i])
        vty_out (vty, "ipv6 protocol %s route-map %s%s", zebra_route_string(i),
                 proto_rm[AFI_IP6][i], VTY_NEWLINE);

      if (nht_rm[AFI_IP][i])
        vty_out (vty, "ip nht %s route-map %s%s", zebra_route_string(i),
                 nht_rm[AFI_IP][i], VTY_NEWLINE);

      if (nht_rm[AFI_IP6][i])
        vty_out (vty, "ipv6 nht %s route-map %s%s", zebra_route_string(i),
                 nht_rm[AFI_IP6][i], VTY_NEWLINE);
    }

  if (proto_rm[AFI_IP][ZEBRA_ROUTE_MAX])
      vty_out (vty, "ip protocol %s route-map %s%s", "any",
               proto_rm[AFI_IP][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

  if (proto_rm[AFI_IP6][ZEBRA_ROUTE_MAX])
      vty_out (vty, "ipv6 protocol %s route-map %s%s", "any",
               proto_rm[AFI_IP6][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

  if (nht_rm[AFI_IP][ZEBRA_ROUTE_MAX])
      vty_out (vty, "ip nht %s route-map %s%s", "any",
               nht_rm[AFI_IP][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

  if (nht_rm[AFI_IP6][ZEBRA_ROUTE_MAX])
      vty_out (vty, "ipv6 nht %s route-map %s%s", "any",
               nht_rm[AFI_IP6][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

  if (zebra_rmap_update_timer != ZEBRA_RMAP_DEFAULT_UPDATE_TIMER)
    vty_out (vty, "zebra route-map delay-timer %d%s", zebra_rmap_update_timer,
	     VTY_NEWLINE);
}

void
zebra_route_map_init ()
{
  install_element (CONFIG_NODE, &ip_protocol_cmd);
  install_element (CONFIG_NODE, &no_ip_protocol_cmd);
  install_element (CONFIG_NODE, &no_ip_protocol_val_cmd);
  install_element (VIEW_NODE, &show_ip_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_protocol_cmd);
  install_element (CONFIG_NODE, &ipv6_protocol_cmd);
  install_element (CONFIG_NODE, &no_ipv6_protocol_cmd);
  install_element (CONFIG_NODE, &no_ipv6_protocol_val_cmd);
  install_element (VIEW_NODE, &show_ipv6_protocol_cmd);
  install_element (ENABLE_NODE, &show_ipv6_protocol_cmd);
  install_element (CONFIG_NODE, &ip_protocol_nht_rmap_cmd);
  install_element (CONFIG_NODE, &no_ip_protocol_nht_rmap_cmd);
  install_element (CONFIG_NODE, &no_ip_protocol_nht_rmap_val_cmd);
  install_element (VIEW_NODE, &show_ip_protocol_nht_cmd);
  install_element (ENABLE_NODE, &show_ip_protocol_nht_cmd);
  install_element (CONFIG_NODE, &ipv6_protocol_nht_rmap_cmd);
  install_element (CONFIG_NODE, &no_ipv6_protocol_nht_rmap_cmd);
  install_element (CONFIG_NODE, &no_ipv6_protocol_nht_rmap_val_cmd);
  install_element (VIEW_NODE, &show_ipv6_protocol_nht_cmd);
  install_element (ENABLE_NODE, &show_ipv6_protocol_nht_cmd);
  install_element (CONFIG_NODE, &zebra_route_map_timer_cmd);
  install_element (CONFIG_NODE, &no_zebra_route_map_timer_cmd);
  install_element (CONFIG_NODE, &no_zebra_route_map_timer_val_cmd);

  route_map_init ();
  route_map_init_vty ();

  route_map_add_hook (zebra_route_map_add);
  route_map_delete_hook (zebra_route_map_delete);
  route_map_event_hook (zebra_route_map_event);

  route_map_install_match (&route_match_tag_cmd);
  route_map_install_match (&route_match_interface_cmd);
  route_map_install_match (&route_match_ip_next_hop_cmd);
  route_map_install_match (&route_match_ip_next_hop_prefix_list_cmd);
  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_address_prefix_list_cmd);
  route_map_install_match (&route_match_ip_address_prefix_len_cmd);
  route_map_install_match (&route_match_ip_nexthop_prefix_len_cmd);
  route_map_install_match (&route_match_source_protocol_cmd);
/* */
  route_map_install_set (&route_set_src_cmd);
/* */
  install_element (RMAP_NODE, &match_tag_cmd);
  install_element (RMAP_NODE, &no_match_tag_cmd);
  install_element (RMAP_NODE, &no_match_tag_val_cmd);
  install_element (RMAP_NODE, &match_interface_cmd);
  install_element (RMAP_NODE, &no_match_interface_cmd); 
  install_element (RMAP_NODE, &no_match_interface_val_cmd); 
  install_element (RMAP_NODE, &match_ip_next_hop_cmd); 
  install_element (RMAP_NODE, &no_match_ip_next_hop_cmd); 
  install_element (RMAP_NODE, &no_match_ip_next_hop_val_cmd); 
  install_element (RMAP_NODE, &match_ip_next_hop_prefix_list_cmd); 
  install_element (RMAP_NODE, &no_match_ip_next_hop_prefix_list_cmd); 
  install_element (RMAP_NODE, &no_match_ip_next_hop_prefix_list_val_cmd); 
  install_element (RMAP_NODE, &match_ip_address_cmd); 
  install_element (RMAP_NODE, &no_match_ip_address_cmd); 
  install_element (RMAP_NODE, &no_match_ip_address_val_cmd); 
  install_element (RMAP_NODE, &match_ip_address_prefix_list_cmd); 
  install_element (RMAP_NODE, &no_match_ip_address_prefix_list_cmd); 
  install_element (RMAP_NODE, &no_match_ip_address_prefix_list_val_cmd);
  install_element (RMAP_NODE, &match_ip_nexthop_prefix_len_cmd);
  install_element (RMAP_NODE, &no_match_ip_nexthop_prefix_len_cmd);
  install_element (RMAP_NODE, &no_match_ip_nexthop_prefix_len_val_cmd);
  install_element (RMAP_NODE, &match_ip_address_prefix_len_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_prefix_len_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_prefix_len_val_cmd);
  install_element (RMAP_NODE, &match_source_protocol_cmd);
  install_element (RMAP_NODE, &no_match_source_protocol_cmd);
 /* */
  install_element (RMAP_NODE, &set_src_cmd);
  install_element (RMAP_NODE, &no_set_src_cmd);
}
