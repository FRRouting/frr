/*
 * Copyright (C) 2001 Yasuhiro Ohara
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

#include "ospf6d.h"

#include "ospf6_dump.h"
#include "ospf6_abr.h"

static int abr_index;
#define IS_OSPF6_DUMP_ABR (ospf6_dump_is_on (abr_index))

#define ADD    0
#define CHANGE 1
#define REMOVE 2

/* Inter-Area-Prefix-LSA Calculation */

static struct ospf6_route_req *
ospf6_abr_entry_lookup (struct ospf6_route_req *abr_entry,
                        u_int32_t router_id, struct ospf6_area *area)
{
  struct prefix_ls abr_id;
  char router_string[32];

  inet_ntop (AF_INET, &router_id, router_string, sizeof (router_string));

  //zlog_info ("ABR:   Finding router %s in area %s", router_string, area->str);

  memset (&abr_id, 0, sizeof (abr_id));
  abr_id.family = AF_UNSPEC;
  abr_id.prefixlen = 64; /* xxx */
  abr_id.id.s_addr = htonl (0);
  abr_id.adv_router.s_addr = router_id;

  ospf6_route_lookup (abr_entry, (struct prefix *) &abr_id,
                      area->table_topology);

  if (ospf6_route_end (abr_entry))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR:   Router %s not found in area %s",
                   router_string, area->str);
      return NULL;
    }

  if (abr_entry->path.area_id != area->area_id)
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: ABR area id mismatch");
      return NULL;
    }

  if (! CHECK_FLAG (abr_entry->path.router_bits, OSPF6_ROUTER_LSA_BIT_B))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: ABR entry's B bit off");
      return NULL;
    }

  return abr_entry;
}

static int
ospf6_abr_prefix_lsa_to_route (struct ospf6_lsa *lsa,
                               struct ospf6_route_req *request)
{
  struct ospf6_inter_area_prefix_lsa *iep;
  struct ospf6_route_req abr_entry;

  if (lsa->header->type != htons (OSPF6_LSA_TYPE_INTER_PREFIX))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: LSA type mismatch");
      return -1;
    }

  if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: LSA MaxAge");
      return -1;
    }

  if (! ospf6_abr_entry_lookup (&abr_entry, lsa->header->adv_router,
                                (struct ospf6_area *) lsa->scope))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: ABR check failed");
      return -1;
    }

  iep = OSPF6_LSA_HEADER_END (lsa->header);

  memset (request, 0, sizeof (struct ospf6_route_req));
  request->route.type = OSPF6_DEST_TYPE_NETWORK;
  request->route.prefix.family = AF_INET6;
  request->route.prefix.prefixlen = iep->prefix.prefix_length;
  ospf6_prefix_in6_addr (&iep->prefix, &request->route.prefix.u.prefix6);

  request->path.cost = abr_entry.path.cost +
                      (ntohl (iep->metric) & ntohl (0x000fffff));
  request->path.type = OSPF6_PATH_TYPE_INTER;
  request->path.origin.type = lsa->header->type;
  request->path.origin.id = lsa->header->id;
  request->path.origin.adv_router = lsa->header->adv_router;
  memcpy (&request->nexthop.address, &abr_entry.nexthop.address,
          sizeof (request->nexthop.address));
  request->nexthop.ifindex = abr_entry.nexthop.ifindex;

  return 0;
}

void
ospf6_abr_prefix_lsa_add (struct ospf6_lsa *lsa)
{
  struct ospf6_route_req request;
  int ret;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Calculate %s", lsa->str);

  ret = ospf6_abr_prefix_lsa_to_route (lsa, &request);
  if (ret < 0)
    return;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Inter Area Route add for %s", lsa->str);

  ospf6_route_add (&request, ospf6->route_table);
}

void
ospf6_abr_prefix_lsa_remove (struct ospf6_lsa *lsa)
{
  struct ospf6_inter_area_prefix_lsa *iep;
  struct prefix_ipv6 prefix6;
  struct ospf6_route_req request;

  iep = OSPF6_LSA_HEADER_END (lsa->header);

  prefix6.family = AF_INET6;
  prefix6.prefixlen = iep->prefix.prefix_length;
  ospf6_prefix_in6_addr (&iep->prefix, &prefix6.prefix);

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Inter Area Route remove for %s", lsa->str);

  for (ospf6_route_lookup (&request, (struct prefix *) &prefix6,
                           ospf6->route_table);
       ! ospf6_route_end (&request);
       ospf6_route_next (&request))
   {
     if (memcmp (&prefix6, &request.route.prefix, sizeof (prefix6)))
       break;
     if (request.path.origin.type != htons (OSPF6_LSA_TYPE_INTER_PREFIX) ||
         request.path.origin.adv_router != lsa->header->adv_router ||
         request.path.origin.id != lsa->header->id)
       continue;

     ospf6_route_remove (&request, ospf6->route_table);
   }
}

static int
ospf6_abr_router_lsa_to_route (struct ospf6_lsa *lsa,
                               struct ospf6_route_req *request)
{
  struct ospf6_inter_area_router_lsa *ier;
  struct ospf6_route_req abr_entry;

  if (lsa->header->type != htons (OSPF6_LSA_TYPE_INTER_ROUTER))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: LSA type mismatch");
      return -1;
    }

  if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: LSA MaxAge");
      return -1;
    }

  if (! ospf6_abr_entry_lookup (&abr_entry, lsa->header->adv_router,
                                (struct ospf6_area *) lsa->scope))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: Advertising router check failed");
      return -1;
    }

  ier = OSPF6_LSA_HEADER_END (lsa->header);

  memset (request, 0, sizeof (struct ospf6_route_req));
  request->route.type = OSPF6_DEST_TYPE_ROUTER;
  request->route.prefix.family = AF_UNSPEC;
  request->route.prefix.prefixlen = 64; /* XXX */
  ((struct prefix_ls *) &request->route.prefix)->adv_router.s_addr
    = ier->router_id;

  request->path.cost = abr_entry.path.cost +
                      (ntohl (ier->metric & htonl (0x000fffff)));
  request->path.type = OSPF6_PATH_TYPE_INTER;
  request->path.origin.type = lsa->header->type;
  request->path.origin.id = lsa->header->id;
  request->path.origin.adv_router = lsa->header->adv_router;
  SET_FLAG (request->path.router_bits, OSPF6_ROUTER_LSA_BIT_E);
  request->path.capability[0] = ier->options[0];
  request->path.capability[1] = ier->options[1];
  request->path.capability[2] = ier->options[2];

  memcpy (&request->nexthop.address, &abr_entry.nexthop.address,
          sizeof (request->nexthop.address));
  request->nexthop.ifindex = abr_entry.nexthop.ifindex;

  return 0;
}

void
ospf6_abr_router_lsa_add (struct ospf6_lsa *lsa)
{
  struct ospf6_route_req request;
  int ret;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Calculate %s", lsa->str);

  ret = ospf6_abr_router_lsa_to_route (lsa, &request);
  if (ret < 0)
    return;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Inter Area Router add for %s", lsa->str);

  ospf6_route_add (&request, ospf6->topology_table);
}

void
ospf6_abr_router_lsa_remove (struct ospf6_lsa *lsa)
{
  struct ospf6_inter_area_router_lsa *ier;
  struct prefix_ls prefix_ls;
  struct ospf6_route_req request;

  ier = OSPF6_LSA_HEADER_END (lsa->header);

  memset (&prefix_ls, 0, sizeof (prefix_ls));
  prefix_ls.family = AF_INET6;
  prefix_ls.prefixlen = 64; /* XXX */
  prefix_ls.adv_router.s_addr = ier->router_id;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Inter Area Route remove for %s", lsa->str);

  for (ospf6_route_lookup (&request, (struct prefix *) &prefix_ls,
                           ospf6->route_table);
       ! ospf6_route_end (&request);
       ospf6_route_next (&request))
   {
     if (memcmp (&prefix_ls, &request.route.prefix, sizeof (prefix_ls)))
       break;
     if (request.path.origin.type != htons (OSPF6_LSA_TYPE_INTER_ROUTER) ||
         request.path.origin.adv_router != lsa->header->adv_router ||
         request.path.origin.id != lsa->header->id)
       continue;

     ospf6_route_remove (&request, ospf6->route_table);
   }
}


void
ospf6_abr_abr_entry_add (struct ospf6_route_req *abr_entry)
{
  struct ospf6_lsdb_node node;
  struct prefix_ls *abr_id;
  struct ospf6_route_req request;
  struct ospf6_area *area;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: New Area Border Router found");

  area = ospf6_area_lookup (abr_entry->path.area_id, ospf6);
  if (! area)
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: Can't find associated area");
      return;
    }

  abr_id = (struct prefix_ls *) &abr_entry->route.prefix;
  if (! ospf6_abr_entry_lookup (&request, abr_id->adv_router.s_addr, area))
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: back check failed");
      return;
    }

  /* for each inter-prefix LSA this ABR originated */
  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_INTER_PREFIX),
                               abr_id->adv_router.s_addr, area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_abr_prefix_lsa_add (node.lsa);

  /* for each inter-router LSA this ABR originated */
  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_INTER_ROUTER),
                               abr_id->adv_router.s_addr, area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_abr_router_lsa_add (node.lsa);
}

void
ospf6_abr_abr_entry_remove (struct ospf6_route_req *abr_entry)
{
  struct ospf6_lsdb_node node;
  struct prefix_ls *abr_id;
  struct ospf6_area *area;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("ABR: Area Border Router removed");

  abr_id = (struct prefix_ls *) &abr_entry->route.prefix;

  area = ospf6_area_lookup (abr_entry->path.area_id, ospf6);
  if (! area)
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: Can't find associated area");
      return;
    }

  /* for each inter-prefix LSA this ABR originated */
  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_INTER_PREFIX),
                               abr_id->adv_router.s_addr, area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_abr_prefix_lsa_remove (node.lsa);

  /* for each inter-router LSA this ABR originated */
  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_INTER_ROUTER),
                               abr_id->adv_router.s_addr, area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_abr_router_lsa_remove (node.lsa);
}

/* Inter-Area-Prefix-LSA Origination */

static void
ospf6_abr_prefix_lsa_update_add (struct ospf6_route_req *request,
                                 struct ospf6_area *area)
{
  char buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_inter_area_prefix_lsa *iep;
  char *p;

  if (IS_OSPF6_DUMP_ABR)
    zlog_info ("Update Inter-Prefix for %s: ID: %lu",
               area->str, (u_long) ntohl (request->route_id));

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  size = sizeof (struct ospf6_inter_area_prefix_lsa);
  iep = (struct ospf6_inter_area_prefix_lsa *) buffer;
  p = (char *) (iep + 1);

  /* prefixlen */
  iep->prefix.prefix_length = request->route.prefix.prefixlen;

  /* PrefixOptions */
  iep->prefix.prefix_options = request->path.prefix_options;

  /* set Prefix */
  memcpy (p, &request->route.prefix.u.prefix6,
          OSPF6_PREFIX_SPACE (request->route.prefix.prefixlen));
  ospf6_prefix_apply_mask (&iep->prefix);
  size += OSPF6_PREFIX_SPACE (request->route.prefix.prefixlen);

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_INTER_PREFIX),
                       htonl (request->route_id), ospf6->router_id,
                       (char *) iep, size, area);
}

static void
ospf6_abr_prefix_lsa_update_remove (struct ospf6_route_req *request,
                                    struct ospf6_area *area)
{
  struct ospf6_lsa *lsa;
  lsa = ospf6_lsdb_lookup_lsdb (htons (OSPF6_LSA_TYPE_INTER_PREFIX),
                                htonl (request->route_id),
                                ospf6->router_id, area->lsdb);
  if (lsa)
    ospf6_lsa_premature_aging (lsa);
}

static void
ospf6_abr_prefix_lsa_update (int type, struct ospf6_route_req *request)
{
  struct ospf6_route_req route, target;
  listnode node;
  struct ospf6_area *area;
  struct ospf6_interface *o6i;

  if (request->route.type != OSPF6_DEST_TYPE_NETWORK)
    return;

  /* assert this is best path; if not, return */
  ospf6_route_lookup (&route, &request->route.prefix, request->table);
  if (memcmp (&route.path, &request->path, sizeof (route.path)))
    return;

  if (target.path.cost >= LS_INFINITY ||
      target.path.cost_e2 >= LS_INFINITY)
    {
      if (IS_OSPF6_DUMP_ABR)
        zlog_info ("ABR: Exceeds LS Infinity, ignore");
      return;
    }

  ospf6_route_lookup (&target, &request->route.prefix, request->table);
  if (type == REMOVE)
    {
      ospf6_route_next (&route);
      if (! memcmp (&route.route, &request->route, sizeof (route.route)))
        {
          type = ADD;
          ospf6_route_next (&target);
        }
    }

  for (node = listhead (ospf6->area_list); node; nextnode (node))
    {
      area = getdata (node);

      if (target.path.area_id == area->area_id)
        continue;

      o6i = ospf6_interface_lookup_by_index (target.nexthop.ifindex);
      if (o6i && o6i->area && o6i->area->area_id == area->area_id)
        {
          zlog_info ("ABR: Logical equivalent of split horizon, skip for %s",
                     area->str);
          continue;
        }

      if (area->area_id == ntohs (0) && /* Backbone */
          target.path.type != OSPF6_PATH_TYPE_INTRA)
        continue;

      /* XXX, stub area check */

      /* XXX, aggregate */
        /* if either the area of the route or the area trying to
           advertise is backbone, do not aggregate */

      if (type == ADD)
        ospf6_abr_prefix_lsa_update_add (&target, area);
      else
        ospf6_abr_prefix_lsa_update_remove (&target, area);
    }
}

void
ospf6_abr_route_add (struct ospf6_route_req *request)
{
  ospf6_abr_prefix_lsa_update (ADD, request);
}

void
ospf6_abr_route_remove (struct ospf6_route_req *request)
{
  ospf6_abr_prefix_lsa_update (REMOVE, request);
}

int
ospf6_abr_prefix_lsa_refresh (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_inter_area_prefix_lsa *ier;
  struct prefix_ipv6 prefix6;
  struct ospf6_route_req route;

  ier = OSPF6_LSA_HEADER_END (lsa->header);
  memset (&prefix6, 0, sizeof (prefix6));
  prefix6.family = AF_INET6;
  prefix6.prefixlen = ier->prefix.prefix_length;
  ospf6_prefix_in6_addr (&ier->prefix, &prefix6.prefix);

  ospf6_route_lookup (&route, (struct prefix *) &prefix6,
                      ospf6->route_table);
  assert (! ospf6_route_end (&route));

  ospf6_abr_prefix_lsa_update (ADD, &route);
  return 0;
}

int
ospf6_abr_prefix_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_inter_area_prefix_lsa *ier;
  char prefix[128];

  assert (lsa->header);
  ier = OSPF6_LSA_HEADER_END (lsa->header);

  ospf6_prefix_string (&ier->prefix, prefix, sizeof (prefix));

  vty_out (vty, "     Metric: %d%s",
           ntohl (ier->metric & htonl (0x000fffff)), VTY_NEWLINE);
  vty_out (vty, "     Prefix: %s%s", prefix, VTY_NEWLINE);

  return 0;
}

int
ospf6_abr_prefix_lsa_hook_add (void *data)
{
  struct ospf6_lsa *lsa = data;
  ospf6_abr_prefix_lsa_add (lsa);
  return 0;
}

int
ospf6_abr_prefix_lsa_hook_remove (void *data)
{
  struct ospf6_lsa *lsa = data;
  ospf6_abr_prefix_lsa_remove (lsa);
  return 0;
}

void
ospf6_abr_database_hook_inter_prefix (struct ospf6_lsa *old,
                                      struct ospf6_lsa *new)
{
  if (old)
    ospf6_abr_prefix_lsa_hook_remove (old);
  if (new && ! IS_LSA_MAXAGE (new))
    ospf6_abr_prefix_lsa_hook_add (new);
}

void
ospf6_abr_register_inter_prefix ()
{
  struct ospf6_lsa_slot slot;

  memset (&slot, 0, sizeof (slot));
  slot.type         = htons (OSPF6_LSA_TYPE_INTER_PREFIX);
  slot.name         = "Inter-Prefix";
  slot.func_show    = ospf6_abr_prefix_lsa_show;
  slot.func_refresh = ospf6_abr_prefix_lsa_refresh;
  ospf6_lsa_slot_register (&slot);

  ospf6_lsdb_hook[OSPF6_LSA_TYPE_INTER_PREFIX & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_abr_database_hook_inter_prefix;
}

int
ospf6_abr_router_lsa_hook_add (void *data)
{
  struct ospf6_lsa *lsa = data;
  ospf6_abr_router_lsa_add (lsa);
  return 0;
}

int
ospf6_abr_router_lsa_hook_remove (void *data)
{
  struct ospf6_lsa *lsa = data;
  ospf6_abr_router_lsa_remove (lsa);
  return 0;
}

int
ospf6_abr_router_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  return 0;
}

int
ospf6_abr_router_lsa_refresh (void *data)
{
  return 0;
}

void
ospf6_abr_database_hook_inter_router (struct ospf6_lsa *old,
                                      struct ospf6_lsa *new)
{
  if (old)
    ospf6_abr_router_lsa_hook_remove (old);
  if (new && ! IS_LSA_MAXAGE (new))
    ospf6_abr_router_lsa_hook_add (new);
}

void
ospf6_abr_register_inter_router ()
{
  struct ospf6_lsa_slot slot;

  memset (&slot, 0, sizeof (slot));
  slot.type         = htons (OSPF6_LSA_TYPE_INTER_ROUTER);
  slot.name         = "Inter-Router";
  slot.func_show    = ospf6_abr_router_lsa_show;
  slot.func_refresh = ospf6_abr_router_lsa_refresh;
  ospf6_lsa_slot_register (&slot);

  ospf6_lsdb_hook[OSPF6_LSA_TYPE_INTER_ROUTER & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_abr_database_hook_inter_router;
}

void
ospf6_abr_inter_route_calculation (struct ospf6_area *area)
{
  struct ospf6_lsdb_node node;

  /* for each inter-prefix LSA */
  for (ospf6_lsdb_type (&node, htons (OSPF6_LSA_TYPE_INTER_PREFIX),
                        area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_abr_prefix_lsa_add (node.lsa);
}

void
ospf6_abr_init ()
{
  abr_index = ospf6_dump_install ("abr", "Area Border Router Function\n");

  ospf6_abr_register_inter_prefix ();
  ospf6_abr_register_inter_router ();
}


