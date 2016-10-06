/* RIPng routemap.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include "if.h"
#include "memory.h"
#include "prefix.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "sockunion.h"

#include "ripngd/ripngd.h"

struct rip_metric_modifier
{
  enum 
  {
    metric_increment,
    metric_decrement,
    metric_absolute
  } type;

  u_char metric;
};

/* `match metric METRIC' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_metric (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_int32_t *metric;
  struct ripng_info *rinfo;

  if (type == RMAP_RIPNG)
    {
      metric = rule;
      rinfo = object;
    
      if (rinfo->metric == *metric)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match metric' match statement. `arg' is METRIC value */
static void *
route_match_metric_compile (const char *arg)
{
  u_int32_t *metric;

  metric = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *metric = atoi (arg);

  if(*metric > 0)
    return metric;

  XFREE (MTYPE_ROUTE_MAP_COMPILED, metric);
  return NULL;
}

/* Free route map's compiled `match metric' value. */
static void
route_match_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
static struct route_map_rule_cmd route_match_metric_cmd =
{
  "metric",
  route_match_metric,
  route_match_metric_compile,
  route_match_metric_free
};

/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_interface (void *rule, struct prefix *prefix,
		       route_map_object_t type, void *object)
{
  struct ripng_info *rinfo;
  struct interface *ifp;
  char *ifname;

  if (type == RMAP_RIPNG)
    {
      ifname = rule;
      ifp = if_lookup_by_name(ifname);

      if (!ifp)
	return RMAP_NOMATCH;

      rinfo = object;

      if (rinfo->ifindex == ifp->ifindex)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
static void *
route_match_interface_compile (const char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void
route_match_interface_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_interface_cmd =
{
  "interface",
  route_match_interface,
  route_match_interface_compile,
  route_match_interface_free
};

/* `match tag TAG' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t
route_match_tag (void *rule, struct prefix *prefix, 
		    route_map_object_t type, void *object)
{
  u_short *tag;
  struct ripng_info *rinfo;

  if (type == RMAP_RIPNG)
    {
      tag = rule;
      rinfo = object;

      /* The information stored by rinfo is host ordered. */
      if (rinfo->tag == *tag)
	return RMAP_MATCH;
      else
	return RMAP_NOMATCH;
    }
  return RMAP_NOMATCH;
}

/* Route map `match tag' match statement. `arg' is TAG value */
static void *
route_match_tag_compile (const char *arg)
{
  u_short *tag;

  tag = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_short));
  *tag = atoi (arg);

  return tag;
}

/* Free route map's compiled `match tag' value. */
static void
route_match_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for tag matching. */
static struct route_map_rule_cmd route_match_tag_cmd =
{
  "tag",
  route_match_tag,
  route_match_tag_compile,
  route_match_tag_free
};

/* `set metric METRIC' */

/* Set metric to attribute. */
static route_map_result_t
route_set_metric (void *rule, struct prefix *prefix, 
		  route_map_object_t type, void *object)
{
  if (type == RMAP_RIPNG)
    {
      struct rip_metric_modifier *mod;
      struct ripng_info *rinfo;

      mod = rule;
      rinfo = object;

      if (mod->type == metric_increment)
	rinfo->metric_out += mod->metric;
      else if (mod->type == metric_decrement)
	rinfo->metric_out-= mod->metric;
      else if (mod->type == metric_absolute)
	rinfo->metric_out = mod->metric;

      if (rinfo->metric_out < 1)
	rinfo->metric_out = 1;
      if (rinfo->metric_out > RIPNG_METRIC_INFINITY)
	rinfo->metric_out = RIPNG_METRIC_INFINITY;

      rinfo->metric_set = 1;
    }
  return RMAP_OKAY;
}

/* set metric compilation. */
static void *
route_set_metric_compile (const char *arg)
{
  int len;
  const char *pnt;
  int type;
  long metric;
  char *endptr = NULL;
  struct rip_metric_modifier *mod;

  len = strlen (arg);
  pnt = arg;

  if (len == 0)
    return NULL;

  /* Examine first character. */
  if (arg[0] == '+')
    {
      type = metric_increment;
      pnt++;
    }
  else if (arg[0] == '-')
    {
      type = metric_decrement;
      pnt++;
    }
  else
    type = metric_absolute;

  /* Check beginning with digit string. */
  if (*pnt < '0' || *pnt > '9')
    return NULL;

  /* Convert string to integer. */
  metric = strtol (pnt, &endptr, 10);

  if (metric == LONG_MAX || *endptr != '\0')
    return NULL;
  /* Commented out by Hasso Tepper, to avoid problems in vtysh. */
  /* if (metric < 0 || metric > RIPNG_METRIC_INFINITY) */
  if (metric < 0)
    return NULL;

  mod = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, 
		 sizeof (struct rip_metric_modifier));
  mod->type = type;
  mod->metric = metric;

  return mod;
}

/* Free route map's compiled `set metric' value. */
static void
route_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_set_metric_cmd = 
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};

/* `set ipv6 next-hop local IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
static route_map_result_t
route_set_ipv6_nexthop_local (void *rule, struct prefix *prefix, 
		      route_map_object_t type, void *object)
{
  struct in6_addr *address;
  struct ripng_info *rinfo;

  if(type == RMAP_RIPNG)
    {
      /* Fetch routemap's rule information. */
      address = rule;
      rinfo = object;
    
      /* Set next hop value. */ 
      rinfo->nexthop_out = *address;
    }

  return RMAP_OKAY;
}

/* Route map `ipv6 nexthop local' compile function.  Given string is converted
   to struct in6_addr structure. */
static void *
route_set_ipv6_nexthop_local_compile (const char *arg)
{
  int ret;
  struct in6_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ipv6 nexthop local' value. */
static void
route_set_ipv6_nexthop_local_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ipv6 nexthop local set. */
static struct route_map_rule_cmd route_set_ipv6_nexthop_local_cmd =
{
  "ipv6 next-hop local",
  route_set_ipv6_nexthop_local,
  route_set_ipv6_nexthop_local_compile,
  route_set_ipv6_nexthop_local_free
};

/* `set tag TAG' */

/* Set tag to object.  ojbect must be pointer to struct attr. */
static route_map_result_t
route_set_tag (void *rule, struct prefix *prefix, 
		      route_map_object_t type, void *object)
{
  u_short *tag;
  struct ripng_info *rinfo;

  if(type == RMAP_RIPNG)
    {
      /* Fetch routemap's rule information. */
      tag = rule;
      rinfo = object;
    
      /* Set next hop value. */ 
      rinfo->tag_out = *tag;
    }

  return RMAP_OKAY;
}

/* Route map `tag' compile function.  Given string is converted
   to u_short. */
static void *
route_set_tag_compile (const char *arg)
{
  u_short *tag;

  tag = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_short));
  *tag = atoi (arg);

  return tag;
}

/* Free route map's compiled `ip nexthop' value. */
static void
route_set_tag_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for tag set. */
static struct route_map_rule_cmd route_set_tag_cmd =
{
  "tag",
  route_set_tag,
  route_set_tag_compile,
  route_set_tag_free
};

#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"

void
ripng_route_map_reset ()
{
  /* XXX ??? */
  ;
}

void
ripng_route_map_init ()
{
  route_map_init ();
  route_map_init_vty ();

  route_map_match_interface_hook (generic_match_add);
  route_map_no_match_interface_hook (generic_match_delete);

  route_map_match_metric_hook (generic_match_add);
  route_map_no_match_metric_hook (generic_match_delete);

  route_map_match_tag_hook (generic_match_add);
  route_map_no_match_tag_hook (generic_match_delete);

  route_map_set_ipv6_nexthop_local_hook (generic_set_add);
  route_map_no_set_ipv6_nexthop_local_hook (generic_set_delete);

  route_map_set_metric_hook (generic_set_add);
  route_map_no_set_metric_hook (generic_set_delete);

  route_map_set_tag_hook (generic_set_add);
  route_map_no_set_tag_hook (generic_set_delete);

  route_map_install_match (&route_match_metric_cmd);
  route_map_install_match (&route_match_interface_cmd);
  route_map_install_match (&route_match_tag_cmd);
  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_local_cmd);
  route_map_install_set (&route_set_tag_cmd);
}
