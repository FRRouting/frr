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
#include "prefix.h"
#include "rib.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "nexthop.h"

#include "zebra/zserv.h"
#include "zebra/debug.h"

static u_int32_t zebra_rmap_update_timer = ZEBRA_RMAP_DEFAULT_UPDATE_TIMER;
static struct thread *zebra_t_rmap_update = NULL;
char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];	/* "any" == ZEBRA_ROUTE_MAX */

extern struct zebra_t zebrad;

/* Add zebra route map rule */
static int
zebra_route_match_add(struct vty *vty, struct route_map_index *index,
		      const char *command, const char *arg,
		      route_map_event_t type)
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

  if (type != RMAP_EVENT_MATCH_ADDED)
    {
      route_map_upd8_dependency (type, arg, index->map->name);
    }
  return CMD_SUCCESS;
}

/* Delete zebra route map rule. */
static int
zebra_route_match_delete (struct vty *vty, struct route_map_index *index,
			  const char *command, const char *arg,
			  route_map_event_t type)
{
  int ret;
  char *dep_name = (char *)arg;
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
      rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
    }

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

  if (type != RMAP_EVENT_MATCH_DELETED && dep_name)
    route_map_upd8_dependency(type, dep_name, rmap_name);

  if (arg == NULL && dep_name)
    XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
  if (rmap_name)
    XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

  return CMD_SUCCESS;
}

/* Add zebra route map rule. */
static int
zebra_route_set_add (struct vty *vty, struct route_map_index *index,
		   const char *command, const char *arg)
{
  int ret;

  ret = route_map_add_set (index, command, arg);
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

/* Delete zebra route map rule. */
static int
zebra_route_set_delete (struct vty *vty, struct route_map_index *index,
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


/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_interface (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  struct nexthop *nexthop;
  char *ifname = rule;
  unsigned int ifindex;

  if (type == RMAP_ZEBRA)
    {
      if (strcasecmp(ifname, "any") == 0)
	return RMAP_MATCH;
      ifindex = ifname2ifindex(ifname);
      if (ifindex == 0)
	return RMAP_NOMATCH;
      nexthop = object;
      if (!nexthop)
	return RMAP_NOMATCH;
      if (nexthop->ifindex == ifindex)
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
  return zebra_route_match_add (vty, vty->index, "interface", argv[0],
				RMAP_EVENT_FILTER_ADDED);
}

DEFUN (no_match_interface,
       no_match_interface_cmd,
       "no match interface",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n")
{
  if (argc == 0)
    return zebra_route_match_delete (vty, vty->index, "interface", NULL, RMAP_EVENT_MATCH_DELETED);

  return zebra_route_match_delete (vty, vty->index, "interface", argv[0], RMAP_EVENT_MATCH_DELETED);
}

ALIAS (no_match_interface,
       no_match_interface_val_cmd,
       "no match interface WORD",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")

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
  return zebra_route_match_add (vty, vty->index, "ip next-hop", argv[0], RMAP_EVENT_FILTER_ADDED);
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
    return zebra_route_match_delete (vty, vty->index, "ip next-hop", NULL,
				     RMAP_EVENT_FILTER_DELETED);

  return zebra_route_match_delete (vty, vty->index, "ip next-hop", argv[0],
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
  return zebra_route_match_add (vty, vty->index, "ip next-hop prefix-list",
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
    return zebra_route_match_delete (vty, vty->index,
				     "ip next-hop prefix-list", NULL,
				     RMAP_EVENT_PLIST_DELETED);

  return zebra_route_match_delete (vty, vty->index,
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
  return zebra_route_match_add (vty, vty->index, "ip address", argv[0],
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
    return zebra_route_match_delete (vty, vty->index, "ip address", NULL,
				     RMAP_EVENT_FILTER_DELETED);

  return zebra_route_match_delete (vty, vty->index, "ip address", argv[0],
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
  return zebra_route_match_add (vty, vty->index, "ip address prefix-list",
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
    return zebra_route_match_delete (vty, vty->index,
				     "ip address prefix-list", NULL,
				     RMAP_EVENT_PLIST_DELETED);

  return zebra_route_match_delete (vty, vty->index,
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

/* set functions */

DEFUN (set_src,
       set_src_cmd,
       "set src A.B.C.D",
       SET_STR
       "src address for route\n"
       "src address\n")
{
  struct in_addr src;
  struct interface *pif;

  if (inet_pton(AF_INET, argv[0], &src) <= 0)
    {
      vty_out (vty, "%% not a local address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

    pif = if_lookup_exact_address (src);
    if (!pif)
      {
        vty_out (vty, "%% not a local address%s", VTY_NEWLINE);
        return CMD_WARNING;
      }
  return zebra_route_set_add (vty, vty->index, "src", argv[0]);
}

DEFUN (no_set_src,
       no_set_src_cmd,
       "no set src",
       NO_STR
       SET_STR
       "Source address for route\n")
{
  if (argc == 0)
    return zebra_route_set_delete (vty, vty->index, "src", NULL);

  return zebra_route_set_delete (vty, vty->index, "src", argv[0]);
}

ALIAS (no_set_src,
       no_set_src_val_cmd,
       "no set src (A.B.C.D)",
       NO_STR
       SET_STR
       "src address for route\n"
       "src address\n")

DEFUN (zebra_route_map_timer,
       zebra_route_map_timer_cmd,
       "zebra route-map delay-timer <0-600>",
       "Time to wait before route-map updates are\n"
       "processed. 0 means disable event driven\n"
       "route-map updates. Set this to a larger\n"
       "value than protocol route-map delay timer\n"
       "to avoid unnecessary churn in routing tables\n")
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
       "Reset delay-timer to default value, 30 secs\n")
{
  zebra_route_map_set_delay_timer(ZEBRA_RMAP_DEFAULT_UPDATE_TIMER);

  return (CMD_SUCCESS);
}

DEFUN (ip_protocol,
       ip_protocol_cmd,
       "ip protocol PROTO route-map ROUTE-MAP",
       NO_STR
       "Apply route map to PROTO\n"
       "Protocol name\n"
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
  rib_update();
  return CMD_SUCCESS;
}

DEFUN (no_ip_protocol,
       no_ip_protocol_cmd,
       "no ip protocol PROTO",
       NO_STR
       "Remove route map from PROTO\n"
       "Protocol name\n")
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

  XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
  proto_rm[AFI_IP][i] = NULL;
  rib_update();
  return CMD_SUCCESS;
}

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

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXX*/

/* `match ip next-hop IP_ACCESS_LIST' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_ip_next_hop (void *rule, struct prefix *prefix,
			route_map_object_t type, void *object)
{
  struct access_list *alist;
  struct nexthop *nexthop;
  struct prefix_ipv4 p;

  if (type == RMAP_ZEBRA)
    {
      nexthop = object;
      switch (nexthop->type) {
      case NEXTHOP_TYPE_IFINDEX:
      case NEXTHOP_TYPE_IFNAME:
        /* Interface routes can't match ip next-hop */
        return RMAP_NOMATCH;
      case NEXTHOP_TYPE_IPV4_IFINDEX:
      case NEXTHOP_TYPE_IPV4_IFNAME:
      case NEXTHOP_TYPE_IPV4:
        p.family = AF_INET;
        p.prefix = nexthop->gate.ipv4;
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
  struct nexthop *nexthop;
  struct prefix_ipv4 p;

  if (type == RMAP_ZEBRA)
    {
      nexthop = object;
      switch (nexthop->type) {
      case NEXTHOP_TYPE_IFINDEX:
      case NEXTHOP_TYPE_IFNAME:
        /* Interface routes can't match ip next-hop */
        return RMAP_NOMATCH;
      case NEXTHOP_TYPE_IPV4_IFINDEX:
      case NEXTHOP_TYPE_IPV4_IFNAME:
      case NEXTHOP_TYPE_IPV4:
        p.family = AF_INET;
        p.prefix = nexthop->gate.ipv4;
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


/* `set src A.B.C.D' */

/* Set src. */
static route_map_result_t
route_set_src (void *rule, struct prefix *prefix, 
		  route_map_object_t type, void *object)
{
  if (type == RMAP_ZEBRA)
    {
      struct nexthop *nexthop;

      nexthop = object;
      nexthop->src = *(union g_addr *)rule;
    }
  return RMAP_OKAY;
}

/* set src compilation. */
static void *
route_set_src_compile (const char *arg)
{
  union g_addr src, *psrc;

  if (inet_pton(AF_INET, arg, &src.ipv4) != 1
#ifdef HAVE_IPV6
      && inet_pton(AF_INET6, arg, &src.ipv6) != 1
#endif /* HAVE_IPV6 */
     )
    return NULL;

  psrc = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (union g_addr));
  *psrc = src;

  return psrc;
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

  rib_update();
}

void
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
		       struct nexthop *nexthop)
{
  struct route_map *rmap = NULL;
  route_map_result_t ret = RMAP_MATCH;

  if (rib_type >= 0 && rib_type < ZEBRA_ROUTE_MAX)
    rmap = route_map_lookup_by_name (proto_rm[family][rib_type]);
  if (!rmap && proto_rm[family][ZEBRA_ROUTE_MAX])
    rmap = route_map_lookup_by_name (proto_rm[family][ZEBRA_ROUTE_MAX]);
  if (rmap) {
      ret = route_map_apply(rmap, p, RMAP_ZEBRA, nexthop);
  }

  return (ret);
}

static void
zebra_route_map_mark_update (char *rmap_name)
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
static int config_write_protocol(struct vty *vty)
{
  int i;

  for (i=0;i<ZEBRA_ROUTE_MAX;i++)
    {
      if (proto_rm[AFI_IP][i])
        vty_out (vty, "ip protocol %s route-map %s%s", zebra_route_string(i),
                 proto_rm[AFI_IP][i], VTY_NEWLINE);
    }
  if (proto_rm[AFI_IP][ZEBRA_ROUTE_MAX])
      vty_out (vty, "ip protocol %s route-map %s%s", "any",
               proto_rm[AFI_IP][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

  if (zebra_rmap_update_timer != ZEBRA_RMAP_DEFAULT_UPDATE_TIMER)
    vty_out (vty, "zebra route-map delay-timer %d%s", zebra_rmap_update_timer,
	     VTY_NEWLINE);
  return 1;
}
/* table node for protocol filtering */
static struct cmd_node protocol_node = { PROTOCOL_NODE, "", 1 };

void
zebra_route_map_init ()
{
  install_node (&protocol_node, config_write_protocol);
  install_element (CONFIG_NODE, &ip_protocol_cmd);
  install_element (CONFIG_NODE, &no_ip_protocol_cmd);
  install_element (VIEW_NODE, &show_ip_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_protocol_cmd);
  install_element (CONFIG_NODE, &zebra_route_map_timer_cmd);
  install_element (CONFIG_NODE, &no_zebra_route_map_timer_cmd);

  route_map_init ();
  route_map_init_vty ();

  route_map_add_hook (zebra_route_map_add);
  route_map_delete_hook (zebra_route_map_delete);
  route_map_event_hook (zebra_route_map_event);

  route_map_install_match (&route_match_interface_cmd);
  route_map_install_match (&route_match_ip_next_hop_cmd);
  route_map_install_match (&route_match_ip_next_hop_prefix_list_cmd);
  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_address_prefix_list_cmd);
/* */
  route_map_install_set (&route_set_src_cmd);
/* */
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
/* */
  install_element (RMAP_NODE, &set_src_cmd);
  install_element (RMAP_NODE, &no_set_src_cmd);
}
