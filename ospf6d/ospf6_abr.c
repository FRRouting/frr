/*
 * Area Border Router function.
 * Copyright (C) 2004 Yasuhiro Ohara
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
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "linklist.h"
#include "command.h"

#include "ospf6_proto.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_route.h"
#include "ospf6_lsdb.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_abr.h"
#include "ospf6d.h"

unsigned char conf_debug_ospf6_abr;

/* RFC 2328 12.4.3. Summary-LSAs */
void
ospf6_abr_originate_prefix_to_area (struct ospf6_route *route,
                                    struct ospf6_area *area)
{
  struct ospf6_lsa *lsa, *old = NULL;
  struct ospf6_interface *oi;
  struct ospf6_route *summary, *range = NULL;
  struct ospf6_area *route_area;
  char buffer[OSPF6_MAX_LSASIZE];
  struct ospf6_lsa_header *lsa_header;
  caddr_t p;
  struct ospf6_inter_prefix_lsa *prefix_lsa;

  summary = ospf6_route_lookup (&route->prefix, area->summary_table);
  if (summary)
    old = ospf6_lsdb_lookup (htons (OSPF6_LSTYPE_INTER_PREFIX),
                             summary->path.origin.id,
                             area->ospf6->router_id, area->lsdb);

  /* if this route has just removed, remove corresponding LSA */
  if (CHECK_FLAG (route->flag, OSPF6_ROUTE_REMOVE))
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* Only destination type network and address range are considered */
  if (route->type != OSPF6_DEST_TYPE_NETWORK)
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* AS External routes are never considered */
  if (route->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
      route->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* do not generate if the route cost is greater or equal to LSInfinity */
  if (route->path.cost >= LS_INFINITY)
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* if this is an inter-area route */
  if (route->path.type == OSPF6_PATH_TYPE_INTRA)
    {
      /* search for configured address range for the route's area */
      route_area = ospf6_area_lookup (route->path.area_id, area->ospf6);
      assert (route_area);
      range = ospf6_route_lookup_bestmatch (&route->prefix,
                                            route_area->summary_table);
    }

  /* ranges are ignored when originate backbone routes to transit area.
     Otherwise, if ranges are configured, the route is suppressed. */
  if (range && (route->path.area_id != htonl (0) || ! area->transit_capability))
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      if (range->path.cost < route->path.cost)
        range->path.cost = route->path.cost;
      SET_FLAG (range->flag, OSPF6_ROUTE_HAVE_LONGER);
      return;
    }

  /* do not generate if the path's area is the same as target area */
  if (route->path.area_id == area->area_id)
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* do not generate if the nexthops belongs to the target area */
  oi = ospf6_interface_lookup_by_ifindex (route->nexthop[0].ifindex);
  if (oi && oi->area && oi->area->area_id == area->area_id)
    {
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* the route is going to be originated. store it in area's summary_table */
  if (summary == NULL)
    {
      summary = ospf6_route_copy (route);
      summary->path.origin.type = htons (OSPF6_LSTYPE_INTER_PREFIX);
      summary->path.origin.adv_router = area->ospf6->router_id;
      summary->path.origin.id =
        ospf6_new_ls_id (summary->path.origin.type,
                         summary->path.origin.adv_router, area->lsdb);
      ospf6_route_add (summary, area->summary_table);
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  lsa_header = (struct ospf6_lsa_header *) buffer;
  prefix_lsa = (struct ospf6_inter_prefix_lsa *)
    ((caddr_t) lsa_header + sizeof (struct ospf6_lsa_header));
  p = (caddr_t) prefix_lsa + sizeof (struct ospf6_inter_prefix_lsa);

  /* Fill Inter-Area-Prefix-LSA */
  OSPF6_ABR_SUMMARY_METRIC_SET (prefix_lsa, route->path.cost);

  /* prefixlen */
  prefix_lsa->prefix.prefix_length = route->prefix.prefixlen;

  /* PrefixOptions */
  prefix_lsa->prefix.prefix_options = route->path.prefix_options;

  /* set Prefix */
  memcpy (p, &route->prefix.u.prefix6,
          OSPF6_PREFIX_SPACE (route->prefix.prefixlen));
  ospf6_prefix_apply_mask (&prefix_lsa->prefix);
  p += OSPF6_PREFIX_SPACE (route->prefix.prefixlen);

  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = htons (OSPF6_LSTYPE_INTER_PREFIX);
  lsa_header->id = summary->path.origin.id;
  lsa_header->adv_router = area->ospf6->router_id;
  lsa_header->seqnum =
    ospf6_new_ls_seqnum (lsa_header->type, lsa_header->id,
                         lsa_header->adv_router, area->lsdb);
  lsa_header->length = htons ((caddr_t) p - (caddr_t) lsa_header);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create (lsa_header);
  lsa->scope = area;
  SET_FLAG (lsa->flag, OSPF6_LSA_REFRESH); /* XXX */

  /* Originate */
  ospf6_lsa_originate (lsa);
}

void
ospf6_abr_originate_prefix (struct ospf6_route *route, struct ospf6 *o)
{
  listnode node;
  struct ospf6_area *oa;

  for (node = listhead (o->area_list); node; nextnode (node))
    {
      oa = (struct ospf6_area *) getdata (node);
      ospf6_abr_originate_prefix_to_area (route, oa);
    }
}

/* RFC 2328 16.2. Calculating the inter-area routes */
void
ospf6_abr_examin_summary (struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
  struct prefix prefix, abr_prefix;
  struct ospf6_route_table *table = NULL;
  struct ospf6_route *range, *route, *old = NULL;
  struct ospf6_route *abr_entry;
  u_char type;
  char options[3] = {0, 0, 0};
  u_int8_t prefix_options = 0;
  u_int32_t cost = 0;
  int i;

  if (lsa->header->type == htons (OSPF6_LSTYPE_INTER_PREFIX))
    {
      struct ospf6_inter_prefix_lsa *prefix_lsa;
      prefix_lsa = (struct ospf6_inter_prefix_lsa *)
        OSPF6_LSA_HEADER_END (lsa->header);
      prefix.family = AF_INET6;
      prefix.prefixlen = prefix_lsa->prefix.prefix_length;
      ospf6_prefix_in6_addr (&prefix.u.prefix6, &prefix_lsa->prefix);
      table = oa->ospf6->route_table;
      type = OSPF6_DEST_TYPE_NETWORK;
      prefix_options = prefix_lsa->prefix.prefix_options;
      cost = OSPF6_ABR_SUMMARY_METRIC (prefix_lsa);
    }
  else if (lsa->header->type == htons (OSPF6_LSTYPE_INTER_ROUTER))
    {
      struct ospf6_inter_router_lsa *router_lsa;
      router_lsa = (struct ospf6_inter_router_lsa *)
        OSPF6_LSA_HEADER_END (lsa->header);
      ospf6_linkstate_prefix (router_lsa->router_id, htonl (0), &prefix);
      table = oa->ospf6->brouter_table;
      type = OSPF6_DEST_TYPE_ROUTER;
      options[0] = router_lsa->options[0];
      options[1] = router_lsa->options[1];
      options[2] = router_lsa->options[2];
      cost = OSPF6_ABR_SUMMARY_METRIC (router_lsa);
    }
  else
    assert (0);

  for (route = ospf6_route_lookup (&prefix, table);
       route && ospf6_route_is_prefix (&prefix, route);
       route = ospf6_route_next (route))
    {
      if (route->path.area_id == oa->area_id &&
          route->path.origin.type == lsa->header->type &&
          route->path.origin.id == lsa->header->id &&
          route->path.origin.adv_router == lsa->header->adv_router)
        old = route;
    }

  /* (1) if cost == LSInfinity or if the LSA is MaxAge */
  if (cost == LS_INFINITY || OSPF6_LSA_IS_MAXAGE (lsa))
    {
      if (old)
        ospf6_route_remove (old, oa->ospf6->route_table);
      return;
    }

  /* (2) if the LSA is self-originated, ignore */
  if (lsa->header->adv_router == oa->ospf6->router_id)
    {
      if (old)
        ospf6_route_remove (old, oa->ospf6->route_table);
      return;
    }

  /* (3) if the prefix is equal to an active configured address range */
  range = ospf6_route_lookup (&prefix, oa->summary_table);
  if (range && CHECK_FLAG (range->flag, OSPF6_ROUTE_HAVE_LONGER))
    {
      if (old)
        ospf6_route_remove (old, oa->ospf6->route_table);
      return;
    }

  /* (4) if the routing table entry for the ABR does not exist */
  ospf6_linkstate_prefix (lsa->header->adv_router, htonl (0), &abr_prefix);
  abr_entry = ospf6_route_lookup (&abr_prefix, oa->ospf6->brouter_table);
  if (abr_entry == NULL)
    {
      if (old)
        ospf6_route_remove (old, oa->ospf6->route_table);
      return;
    }

  /* (5),(6),(7) the path preference is handled by the sorting
     in the routing table. Always install the path by substituting
     old route (if any). */
  if (old)
    route = old;
  else
    route = ospf6_route_create ();

  route->type = type;
  route->prefix = prefix;
  route->path.origin.type = lsa->header->type;
  route->path.origin.id = lsa->header->id;
  route->path.origin.adv_router = lsa->header->adv_router;
  route->path.options[0] = options[0];
  route->path.options[1] = options[1];
  route->path.options[2] = options[2];
  route->path.prefix_options = prefix_options;
  route->path.area_id = oa->area_id;
  route->path.type = OSPF6_PATH_TYPE_INTER;
  route->path.cost = abr_entry->path.cost + cost;
  for (i = 0; i < OSPF6_MULTI_PATH_LIMIT; i++)
    route->nexthop[i] = abr_entry->nexthop[i];

  ospf6_route_add (route, table);
}

int
dummy (struct ospf6_lsa *lsa)
{
}


/* Display functions */
int
ospf6_inter_area_prefix_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_prefix_lsa *prefix_lsa;
  struct in6_addr in6;
  char buf[64];

  prefix_lsa = (struct ospf6_inter_prefix_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  vty_out (vty, "     Metric: %lu%s",
           (u_long) OSPF6_ABR_SUMMARY_METRIC (prefix_lsa), VNL);

  ospf6_prefix_options_printbuf (prefix_lsa->prefix.prefix_options,
                                 buf, sizeof (buf));
  vty_out (vty, "     Prefix Options: %s%s", buf, VNL);

  ospf6_prefix_in6_addr (&in6, &prefix_lsa->prefix);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  vty_out (vty, "     Prefix: %s/%d%s", buf,
           prefix_lsa->prefix.prefix_length, VNL);

  return 0;
}

int
ospf6_inter_area_router_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_router_lsa *router_lsa;
  char buf[64];

  router_lsa = (struct ospf6_inter_router_lsa *)
    OSPF6_LSA_HEADER_END (lsa->header);

  ospf6_options_printbuf (router_lsa->options, buf, sizeof (buf));
  vty_out (vty, "     Options: %s%s", buf, VNL);
  vty_out (vty, "     Metric: %lu%s",
           (u_long) OSPF6_ABR_SUMMARY_METRIC (router_lsa), VNL);
  inet_ntop (AF_INET, &router_lsa->router_id, buf, sizeof (buf));
  vty_out (vty, "     Destination Router ID: %s%s", buf, VNL);

  return 0;
}

/* Debug commands */
DEFUN (debug_ospf6_abr,
       debug_ospf6_abr_cmd,
       "debug ospf6 abr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
  OSPF6_DEBUG_ABR_ON ();
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_abr,
       no_debug_ospf6_abr_cmd,
       "no debug ospf6 abr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
  OSPF6_DEBUG_ABR_OFF ();
  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_abr (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_ABR)
    vty_out (vty, "debug ospf6 abr%s", VNL);
  return 0;
}

void
install_element_ospf6_debug_abr ()
{
  install_element (ENABLE_NODE, &debug_ospf6_abr_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_abr_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_abr_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_abr_cmd);
}

void
ospf6_abr_init ()
{
  ospf6_lstype[3].name = "Inter-Area-Prefix-LSA";
  ospf6_lstype[3].reoriginate = dummy;
  ospf6_lstype[3].show = ospf6_inter_area_prefix_lsa_show;
  ospf6_lstype[4].name = "Inter-Area-Router-LSA";
  ospf6_lstype[4].reoriginate = dummy;
  ospf6_lstype[4].show = ospf6_inter_area_router_lsa_show;
}


