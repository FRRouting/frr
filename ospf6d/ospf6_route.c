/*
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

#include "ospf6d.h"

char *
dtype_name[OSPF6_DEST_TYPE_MAX] =
{
  "Unknown", "Router", "Network", "Discard"
};
#define DTYPE_NAME(x) \
  (0 < (x) && (x) < sizeof (dtype_name) ? \
   dtype_name[(x)] : dtype_name[0])

char *
dtype_abname[OSPF6_DEST_TYPE_MAX] =
{
  "?", "R", "N", "D"
};
#define DTYPE_ABNAME(x) \
  (0 < (x) && (x) < sizeof (dtype_abname) ? \
   dtype_abname[(x)] : dtype_abname[0])

char *
ptype_name[OSPF6_PATH_TYPE_MAX] =
{
  "Unknown", "Intra", "Inter", "External-1", "External-2",
  "System", "Kernel", "Connect", "Static", "RIP", "RIPng",
  "OSPF", "OSPF6", "BGP"
};
#define PTYPE_NAME(x) \
  (0 < (x) && (x) < sizeof (ptype_name) ? \
   ptype_name[(x)] : ptype_name[0])

char *
ptype_abname[OSPF6_PATH_TYPE_MAX] =
{
  "??", "Ia", "Ie", "E1", "E2",
  "-X", "-K", "-C", "-S", "-R", "-R",
  "-O", "-O", "-B"
};
#define PTYPE_ABNAME(x) \
  (0 < (x) && (x) < sizeof (ptype_abname) ? \
   ptype_abname[(x)] : ptype_abname[0])



int
ospf6_path_cmp (void *arg1, void *arg2)
{
  struct ospf6_path_node *pn1 = arg1;
  struct ospf6_path_node *pn2 = arg2;
  struct ospf6_path *p1 = &pn1->path;
  struct ospf6_path *p2 = &pn2->path;

  if (p1->type < p2->type)
    return -1;
  else if (p1->type > p2->type)
    return 1;

  if (p1->type == OSPF6_PATH_TYPE_EXTERNAL2)
    {
      if (p1->cost_e2 < p2->cost_e2)
        return -1;
      else if (p1->cost_e2 > p2->cost_e2)
        return 1;
    }

  if (p1->cost < p2->cost)
    return -1;
  else if (p1->cost > p2->cost)
    return 1;

  /* if from the same source, recognize as identical
     (and treat this as update) */
  if (! memcmp (&p1->origin, &p2->origin, sizeof (struct ls_origin)) &&
      p1->area_id == p2->area_id)
    return 0;

  /* else, always prefer left */
  return -1;
}

int
ospf6_nexthop_cmp (void *arg1, void *arg2)
{
  int i, ret = 0;
  struct ospf6_nexthop_node *nn1 = arg1;
  struct ospf6_nexthop_node *nn2 = arg2;
  struct ospf6_nexthop *n1 = &nn1->nexthop;
  struct ospf6_nexthop *n2 = &nn2->nexthop;

  if (memcmp (n1, n2, sizeof (struct ospf6_nexthop)) == 0)
    return 0;

  for (i = 0; i < sizeof (struct in6_addr); i++)
    {
      if (nn1->nexthop.address.s6_addr[i] != nn2->nexthop.address.s6_addr[i])
        {
          ret = nn1->nexthop.address.s6_addr[i] -
                nn2->nexthop.address.s6_addr[i];
          break;
        }
    }

  if (ret == 0)
    ret = -1;

  return ret;
}

static void
ospf6_route_request (struct ospf6_route_req *request,
                     struct ospf6_route_node   *rn,
                     struct ospf6_path_node    *pn,
                     struct ospf6_nexthop_node *nn)
{
  assert (request);
  assert (rn && pn && nn);

  request->route_node = rn->route_node;

  linklist_head (rn->path_list, &request->path_lnode);
  while (request->path_lnode.data != pn)
    {
      //assert (! linklist_end (&request->path_lnode));
      if (linklist_end (&request->path_lnode))
        {
          struct linklist_node node;

          zlog_info ("rn: %p, pn: %p", rn, pn);
          zlog_info ("origin: %hx %x %x bits: %x opt: %x%x%x popt: %x area: %x type: %d cost  %d %d %d",
          pn->path.origin.type, pn->path.origin.id, pn->path.origin.adv_router, (int)pn->path.router_bits, (int)pn->path.capability[0],
          (int)pn->path.capability[1], (int)pn->path.capability[2],
          (int)pn->path.prefix_options, pn->path.area_id,
          pn->path.type, pn->path.metric_type, pn->path.cost, pn->path.cost_e2);

          for (linklist_head (rn->path_list, &node); ! linklist_end (&node);
               linklist_next (&node))
            {
              struct ospf6_path_node *pn2 = node.data;

              zlog_info (" %p: path data with pn(%p): %s", pn2, pn,
                         (memcmp (&pn->path, &pn2->path,
                                  sizeof (struct ospf6_path)) ?
                          "different" : "same"));

          zlog_info ("  origin: %hx %x %x bits: %x opt: %x%x%x popt: %x area: %x type: %d cost  %d %d %d",
          pn2->path.origin.type, pn2->path.origin.id, pn2->path.origin.adv_router, (int)pn2->path.router_bits, (int)pn2->path.capability[0],
          (int)pn2->path.capability[1], (int)pn2->path.capability[2],
          (int)pn2->path.prefix_options, pn2->path.area_id,
          pn2->path.type, pn2->path.metric_type, pn2->path.cost, pn2->path.cost_e2);

              if (! memcmp (&pn->path, &pn2->path, sizeof (struct ospf6_path)))
                {
                  pn = pn2;
                  request->nexthop_lnode.data = pn2;
                }
            }
          break;
        }
      linklist_next (&request->path_lnode);
    }
  assert (request->path_lnode.data == pn);

  linklist_head (pn->nexthop_list, &request->nexthop_lnode);
  while (request->nexthop_lnode.data != nn)
    {
      assert (! linklist_end (&request->nexthop_lnode));
      linklist_next (&request->nexthop_lnode);
    }
  assert (request->nexthop_lnode.data == nn);

  request->table = rn->table;
  request->count = rn->count;
  request->route_id = rn->route_id;
  memcpy (&request->route,   &rn->route,   sizeof (struct ospf6_route));
  memcpy (&request->path,    &pn->path,    sizeof (struct ospf6_path));
  memcpy (&request->nexthop, &nn->nexthop, sizeof (struct ospf6_nexthop));
}

int
ospf6_route_count (struct ospf6_route_req *request)
{
  return request->count;
}

int
ospf6_route_lookup (struct ospf6_route_req *request,
                    struct prefix *prefix,
                    struct ospf6_route_table *table)
{
  struct route_node *node;
  struct ospf6_route_node   *rn = NULL;
  struct ospf6_path_node    *pn = NULL;
  struct ospf6_nexthop_node *nn = NULL;
  struct linklist_node lnode;

  if (request)
    memset ((void *) request, 0, sizeof (struct ospf6_route_req));

  node = route_node_lookup (table->table, prefix);
  if (! node)
    return 0;

  rn = (struct ospf6_route_node *) node->info;
  if (! rn)
    return 0;

  if (request)
    {
      linklist_head (rn->path_list, &lnode);
      pn = lnode.data;
      linklist_head (pn->nexthop_list, &lnode);
      nn = lnode.data;

      ospf6_route_request (request, rn, pn, nn);
    }

  return 1;
}

void
ospf6_route_head (struct ospf6_route_req *request,
                  struct ospf6_route_table *table)
{
  struct route_node *node;
  struct ospf6_route_node   *rn = NULL;
  struct ospf6_path_node    *pn = NULL;
  struct ospf6_nexthop_node *nn = NULL;
  struct linklist_node lnode;

  if (request)
    memset (request, 0, sizeof (struct ospf6_route_req));

  node = route_top (table->table);
  if (! node)
    return;

  while (node && node->info == NULL)
    node = route_next (node);
  if (! node)
    return;

  rn = (struct ospf6_route_node *) node->info;
  linklist_head (rn->path_list, &lnode);
  pn = lnode.data;
  linklist_head (pn->nexthop_list, &lnode);
  nn = lnode.data;

  ospf6_route_request (request, rn, pn, nn);
}

int
ospf6_route_end (struct ospf6_route_req *request)
{
  if (request->route_node == NULL &&
      linklist_end (&request->path_lnode) &&
      linklist_end (&request->nexthop_lnode) &&
      request->nexthop.ifindex == 0 &&
      IN6_IS_ADDR_UNSPECIFIED (&request->nexthop.address))
    return 1;
  return 0;
}

void
ospf6_route_next (struct ospf6_route_req *request)
{
  struct ospf6_route_node   *route_node = NULL;
  struct ospf6_path_node    *path_node = NULL;
  struct ospf6_nexthop_node *nexthop_node = NULL;

  linklist_next (&request->nexthop_lnode);
  if (linklist_end (&request->nexthop_lnode))
    {
      linklist_next (&request->path_lnode);
      if (linklist_end (&request->path_lnode))
        {
          request->route_node = route_next (request->route_node);
          while (request->route_node && request->route_node->info == NULL)
            request->route_node = route_next (request->route_node);
          if (request->route_node)
            {
              route_node = request->route_node->info;
              if (route_node)
                linklist_head (route_node->path_list, &request->path_lnode);
            }
        }

      path_node = request->path_lnode.data;
      if (path_node)
        linklist_head (path_node->nexthop_list, &request->nexthop_lnode);
    }

  nexthop_node = request->nexthop_lnode.data;

  if (nexthop_node == NULL)
    {
      assert (path_node == NULL);
      assert (route_node == NULL);

      memset (&request->route,   0, sizeof (struct ospf6_route));
      memset (&request->path,    0, sizeof (struct ospf6_path));
      memset (&request->nexthop, 0, sizeof (struct ospf6_nexthop));
    }
  else
    {
      path_node = request->path_lnode.data;
      route_node = request->route_node->info;

      assert (path_node != NULL);
      assert (route_node != NULL);

      memcpy (&request->route,   &route_node->route,
              sizeof (struct ospf6_route));
      memcpy (&request->path,    &path_node->path,
              sizeof (struct ospf6_path));
      memcpy (&request->nexthop, &nexthop_node->nexthop,
              sizeof (struct ospf6_nexthop));
    }
}

#define ADD    0
#define CHANGE 1
#define REMOVE 2

void
ospf6_route_hook_call (int type,
                       struct ospf6_route_req *request,
                       struct ospf6_route_table *table)
{
  struct linklist_node node;
  void (*func) (struct ospf6_route_req *);

  for (linklist_head (table->hook_list[type], &node);
       ! linklist_end (&node);
       linklist_next (&node))
    {
      func = node.data;
      (*func) (request);
    }
}

void
ospf6_route_hook_register (void (*add)    (struct ospf6_route_req *),
                           void (*change) (struct ospf6_route_req *),
                           void (*remove) (struct ospf6_route_req *),
                           struct ospf6_route_table *table)
{
  linklist_add (add,    table->hook_list[ADD]);
  linklist_add (change, table->hook_list[CHANGE]);
  linklist_add (remove, table->hook_list[REMOVE]);
}

void
ospf6_route_hook_unregister (void (*add)    (struct ospf6_route_req *),
                             void (*change) (struct ospf6_route_req *),
                             void (*remove) (struct ospf6_route_req *),
                             struct ospf6_route_table *table)
{
  linklist_remove (add,    table->hook_list[ADD]);
  linklist_remove (change, table->hook_list[CHANGE]);
  linklist_remove (remove, table->hook_list[REMOVE]);
}


int
prefix_ls2str (struct prefix *p, char *str, int size)
{
  char id[BUFSIZ], adv_router[BUFSIZ];
  struct prefix_ls *pl = (struct prefix_ls *) p;

  inet_ntop (AF_INET, &pl->id, id, BUFSIZ);
  inet_ntop (AF_INET, &pl->adv_router, adv_router, BUFSIZ);
  snprintf (str, size, "%s-%s", adv_router, id);
  return 0;
}

void
ospf6_route_log_request (char *what, char *where,
                         struct ospf6_route_req *request)
{
  char prefix[64];
  char area_id[16];
  char type[16], id[16], adv[16];
  char address[64], ifname[IFNAMSIZ];

  if (request->route.prefix.family != AF_INET &&
      request->route.prefix.family != AF_INET6)
    prefix_ls2str (&request->route.prefix, prefix, sizeof (prefix));
  else
    prefix2str (&request->route.prefix, prefix, sizeof (prefix));

  inet_ntop (AF_INET, &request->path.area_id, area_id, sizeof (area_id));

  ospf6_lsa_type_string (request->path.origin.type, type, sizeof (type));
  inet_ntop (AF_INET, &request->path.origin.id, id, sizeof (id));
  inet_ntop (AF_INET, &request->path.origin.adv_router, adv, sizeof (adv));

  inet_ntop (AF_INET6, &request->nexthop.address, address, sizeof (address));

  zlog_info ("ROUTE: %s %s %s %s %s",
             what, DTYPE_ABNAME (request->route.type), prefix,
             ((strcmp ("Add", what) == 0) ? "to" : "from"), where);
  zlog_info ("ROUTE:     Area: %s type: %s cost: %lu (E2: %lu)",
             area_id, PTYPE_NAME (request->path.type),
             (u_long) request->path.cost, (u_long) request->path.cost_e2);
  zlog_info ("ROUTE:     Origin: Type: %s", type);
  zlog_info ("ROUTE:     Origin: Id: %s Adv: %s", id, adv);
  zlog_info ("ROUTE:     Nexthop: %s", address);
  zlog_info ("ROUTE:     Nexthop: Ifindex: %u (%s)",
             request->nexthop.ifindex,
             if_indextoname (request->nexthop.ifindex, ifname));
}

struct ospf6_path_node *
ospf6_route_find_path_node (struct ospf6_route_req *request,
                            struct ospf6_route_node *rn)
{
  struct linklist_node node;

  for (linklist_head (rn->path_list, &node); ! linklist_end (&node);
       linklist_next (&node))
    {
      struct ospf6_path_node *path_node = node.data;

      if (path_node->path.area_id == request->path.area_id &&
          path_node->path.origin.type == request->path.origin.type &&
          path_node->path.origin.id == request->path.origin.id &&
          path_node->path.origin.adv_router == request->path.origin.adv_router)
        return path_node;
    }

#if 0
  zlog_info ("req path : area: %#x origin: type: %d, id: %d, adv_router: %#x",
             request->path.area_id, request->path.origin.type,
             request->path.origin.id, request->path.origin.adv_router);
  for (linklist_head (rn->path_list, &node); ! linklist_end (&node);
       linklist_next (&node))
    {
      struct ospf6_path_node *path_node = node.data;
      zlog_info ("  path : area: %#x origin: type: %d, id: %d, adv_router: %#x",
                 path_node->path.area_id, path_node->path.origin.type,
                 path_node->path.origin.id, path_node->path.origin.adv_router);
    }
#endif

  return NULL;
}

struct ospf6_nexthop_node *
ospf6_route_find_nexthop_node (struct ospf6_route_req *request,
                               struct ospf6_path_node *pn)
{
  struct linklist_node node;
  for (linklist_head (pn->nexthop_list, &node); ! linklist_end (&node);
       linklist_next (&node))
    {
      struct ospf6_nexthop_node *nexthop_node = node.data;

      if (! memcmp (&nexthop_node->nexthop, &request->nexthop,
          sizeof (struct ospf6_nexthop)))
        return nexthop_node;
    }
  return NULL;
}

void
ospf6_route_add (struct ospf6_route_req *request,
                 struct ospf6_route_table *table)
{
  struct ospf6_route_node   *rn;
  struct ospf6_path_node    *pn;
  struct ospf6_nexthop_node *nn;
  struct route_node *route_node;

  struct ospf6_route_req route;

  int route_change   = 0;
  int path_change    = 0;
  int nexthop_change = 0;

  /* find the requested route */
  route_node = route_node_get (table->table, &request->route.prefix);
  rn = (struct ospf6_route_node *) route_node->info;

  if (rn)
    {
      if (memcmp (&rn->route, &request->route, sizeof (struct ospf6_route)))
        {
          memcpy (&rn->route, &request->route, sizeof (struct ospf6_route));
          route_change++;
        }
    }
  else
    {
      rn = XCALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_route_node));
      rn->table = table;
      rn->route_node = route_node;
      rn->route_id = table->route_id++;
      rn->path_list = linklist_create ();
      rn->path_list->cmp = ospf6_path_cmp;
      memcpy (&rn->route, &request->route, sizeof (struct ospf6_route));
      route_node->info = rn;
    }

  /* find the same path */
  pn = ospf6_route_find_path_node (request, rn);

  if (pn)
    {
      if (memcmp (&pn->path, &request->path, sizeof (struct ospf6_path)))
        {
          memcpy (&pn->path, &request->path, sizeof (struct ospf6_path));
          path_change++;
        }
    }
  else
    {
      pn = XCALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_path_node));
      pn->route_node = rn;
      pn->nexthop_list = linklist_create ();
      pn->nexthop_list->cmp = ospf6_nexthop_cmp;
      memcpy (&pn->path, &request->path, sizeof (struct ospf6_path));
      linklist_add (pn, rn->path_list);
    }

  /* find the same nexthop */
  nn = ospf6_route_find_nexthop_node (request, pn);

  if (nn)
    {
      if (memcmp (&nn->nexthop, &request->nexthop,
                  sizeof (struct ospf6_nexthop)))
        {
          memcpy (&nn->nexthop, &request->nexthop,
                  sizeof (struct ospf6_nexthop));
          nexthop_change++;
          gettimeofday (&nn->installed, (struct timezone *) NULL);
        }
    }
  else
    {
      nn = XCALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_nexthop_node));
      nn->path_node = pn;
      memcpy (&nn->nexthop, &request->nexthop, sizeof (struct ospf6_nexthop));
      linklist_add (nn, pn->nexthop_list);
      rn->count++;
      gettimeofday (&nn->installed, (struct timezone *) NULL);
    }

  SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ADD);
  if (route_change)
    SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ROUTE_CHANGE);
  if (path_change)
    SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_PATH_CHANGE);
  if (nexthop_change)
    SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE);

  if (table->freeze)
    return;

  if (IS_OSPF6_DUMP_ROUTE)
    {
      ospf6_route_log_request ("Add", table->name, request);

      if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ROUTE_CHANGE))
        zlog_info ("ROUTE:   route attribute change");
      if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_PATH_CHANGE))
        zlog_info ("ROUTE:   path attribute change");
      if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE))
        zlog_info ("ROUTE:   nexthop attribute change");
    }

  if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ROUTE_CHANGE) ||
      CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_PATH_CHANGE))
    SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE);

  /* Call hooks */
  ospf6_route_request (&route, rn, pn, nn);
  if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ADD))
    ospf6_route_hook_call (ADD, &route, table);
  else if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE))
    ospf6_route_hook_call (CHANGE, &route, table);

  if (table->hook_add &&
      CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ADD))
    (*table->hook_add) (&route);
  else if (table->hook_change &&
           CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE))
    (*table->hook_change) (&route);

  /* clear flag */
  nn->flag = 0;
}

void
ospf6_route_remove (struct ospf6_route_req *request,
                    struct ospf6_route_table *table)
{
  struct ospf6_route_node   *rn;
  struct ospf6_path_node    *pn;
  struct ospf6_nexthop_node *nn;
  struct route_node *route_node;
  struct ospf6_route_req route;

  /* find the requested route */
  route_node = route_node_get (table->table, &request->route.prefix);
  rn = (struct ospf6_route_node *) route_node->info;

  if (! rn)
    {
      if (IS_OSPF6_DUMP_ROUTE)
        {
          ospf6_route_log_request ("Remove", table->name, request);
          zlog_info ("ROUTE:   Can't remove: No such route");
        }
      return;
    }

  pn = ospf6_route_find_path_node (request, rn);
  if (! pn)
    {
      if (IS_OSPF6_DUMP_ROUTE)
        {
          ospf6_route_log_request ("Remove", table->name, request);
          zlog_info ("ROUTE:   Can't remove: No such path");
        }
      return;
    }

  if (pn->path.area_id != request->path.area_id ||
      pn->path.origin.type != request->path.origin.type ||
      pn->path.origin.id != request->path.origin.id ||
      pn->path.origin.adv_router != request->path.origin.adv_router)
    {
      if (IS_OSPF6_DUMP_ROUTE)
        {
          ospf6_route_log_request ("Remove", table->name, request);
          zlog_info ("ROUTE:   Can't remove: Path differ");
          {
            char *s, *e, *c;
            char line[512], *p;

            p = line;
            s = (char *) &pn->path;
            e = s + sizeof (struct ospf6_path);
            for (c = s; c < e; c++)
              {
                if ((c - s) % 4 == 0)
                  snprintf (p++, line + sizeof (line) - p, " ");
                snprintf (p, line + sizeof (line) - p, "%02x", *c);
                p += 2;
              }
            zlog_info ("ROUTE:     path: %s", line);

            p = line;
            s = (char *) &request->path;
            e = s + sizeof (struct ospf6_path);
            for (c = s; c < e; c++)
              {
                if ((c - s) % 4 == 0)
                  snprintf (p++, line + sizeof (line) - p, " ");
                snprintf (p, line + sizeof (line) - p, "%02x", *c);
                p += 2;
              }
            zlog_info ("ROUTE:     req : %s", line);

          }
        }
      return;
    }

  nn = ospf6_route_find_nexthop_node (request, pn);
  if (! nn)
    {
      if (IS_OSPF6_DUMP_ROUTE)
        {
          ospf6_route_log_request ("Remove", table->name, request);
          zlog_info ("ROUTE:   Can't remove: No such nexthop");
        }
      return;
    }

  if (memcmp (&nn->nexthop, &request->nexthop, sizeof (struct ospf6_nexthop)))
    {
      if (IS_OSPF6_DUMP_ROUTE)
        {
          ospf6_route_log_request ("Remove", table->name, request);
          zlog_info ("ROUTE:   Can't remove: Nexthop differ");
        }
      return;
    }

  SET_FLAG (nn->flag, OSPF6_ROUTE_FLAG_REMOVE);

  if (table->freeze)
    return;

  if (IS_OSPF6_DUMP_ROUTE)
    ospf6_route_log_request ("Remove", table->name, request);

  ospf6_route_request (&route, rn, pn, nn);
  ospf6_route_hook_call (REMOVE, &route, table);
  if (table->hook_remove)
    (*table->hook_remove) (&route);

  /* clear flag */
  nn->flag = 0;

  /* remove nexthop */
  linklist_remove (nn, pn->nexthop_list);
  rn->count--;
  XFREE (MTYPE_OSPF6_ROUTE, nn);

  /* remove path if there's no nexthop for the path */
  if (pn->nexthop_list->count != 0)
    return;
  linklist_remove (pn, rn->path_list);
  linklist_delete (pn->nexthop_list);
  XFREE (MTYPE_OSPF6_ROUTE, pn);

  /* remove route if there's no path for the route */
  if (rn->path_list->count != 0)
    return;
  route_node->info = NULL;
  linklist_delete (rn->path_list);
  XFREE (MTYPE_OSPF6_ROUTE, rn);
}

void
ospf6_route_remove_all (struct ospf6_route_table *table)
{
  struct ospf6_route_req request;

  for (ospf6_route_head (&request, table); ! ospf6_route_end (&request);
       ospf6_route_next (&request))
    ospf6_route_remove (&request, table);
}


struct ospf6_route_table *
ospf6_route_table_create (char *name)
{
  int i;
  struct ospf6_route_table *new;

  new = XCALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_route_table));
  snprintf (new->name, sizeof (new->name), "%s", name);

  new->table = route_table_init ();
  for (i = 0; i < 3; i++)
    new->hook_list[i] = linklist_create ();

  return new;
}

void
ospf6_route_table_delete (struct ospf6_route_table *table)
{
  int i;

  ospf6_route_remove_all (table);
  route_table_finish (table->table);
  for (i = 0; i < 3; i++)
    linklist_delete (table->hook_list[i]);
  XFREE (MTYPE_OSPF6_ROUTE, table);
}

void
ospf6_route_table_freeze (struct ospf6_route_table *route_table)
{
  if (IS_OSPF6_DUMP_ROUTE)
    zlog_info ("ROUTE: Table freeze: %s", route_table->name);
  assert (route_table->freeze == 0);
  route_table->freeze = 1;
}

void
ospf6_route_table_thaw (struct ospf6_route_table *route_table)
{
  struct route_node *node;
  struct linklist_node pnode;
  struct linklist_node nnode;

  struct ospf6_route_node   *rn;
  struct ospf6_path_node    *pn;
  struct ospf6_nexthop_node *nn;

  struct ospf6_route_req request;

  if (IS_OSPF6_DUMP_ROUTE)
    zlog_info ("ROUTE: Table thaw: %s", route_table->name);

  assert (route_table->freeze == 1);
  route_table->freeze = 0;

  for (node = route_top (route_table->table); node;
       node = route_next (node))
    {
      rn = node->info;
      if (! rn)
        continue;

      for (linklist_head (rn->path_list, &pnode);
           ! linklist_end (&pnode);
           linklist_next (&pnode))
        {
          pn = pnode.data;

          for (linklist_head (pn->nexthop_list, &nnode);
               ! linklist_end (&nnode);
               linklist_next (&nnode))
            {
              nn = nnode.data;

              /* if the add and remove flag set without change flag,
                 do nothing with this route */
              if (! CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE) &&
                  CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ADD) &&
                  CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_REMOVE))
                {
                  nn->flag = 0;
                  continue;
                }

              memset (&request, 0, sizeof (request));
              memcpy (&request.route, &rn->route, sizeof (rn->route));
              memcpy (&request.path, &pn->path, sizeof (pn->path));
              memcpy (&request.nexthop, &nn->nexthop, sizeof (nn->nexthop));

              if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_ADD) ||
                  CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_CHANGE))
                ospf6_route_add (&request, route_table);
              else if (CHECK_FLAG (nn->flag, OSPF6_ROUTE_FLAG_REMOVE))
                ospf6_route_remove (&request, route_table);
            }
        }
    }
}


/* VTY commands */

void
ospf6_route_show (struct vty *vty, struct ospf6_route_node *rn)
{
  struct linklist_node pnode;
  struct linklist_node nnode;
  struct ospf6_path_node    *pn;
  struct ospf6_nexthop_node *nn;

  struct timeval now, res;
  char duration[16];

  u_int pc = 0;
  u_int nc = 0;
#define HEAD (pc == 0 && nc == 0)

  char prefix[64], nexthop[64], ifname[IFNAMSIZ];

  gettimeofday (&now, (struct timezone *) NULL);

  /* destination */
  if (rn->route.prefix.family == AF_INET ||
      rn->route.prefix.family == AF_INET6)
    prefix2str (&rn->route.prefix, prefix, sizeof (prefix));
  else
    prefix_ls2str (&rn->route.prefix, prefix, sizeof (prefix));

  for (linklist_head (rn->path_list, &pnode); ! linklist_end (&pnode);
       linklist_next (&pnode))
    {
      pn = pnode.data;

      for (linklist_head (pn->nexthop_list, &nnode); ! linklist_end (&nnode);
           linklist_next (&nnode))
        {
          nn = nnode.data;

          inet_ntop (AF_INET6, &nn->nexthop.address, nexthop,
                     sizeof (nexthop));
          if (! if_indextoname (nn->nexthop.ifindex, ifname))
            snprintf (ifname, sizeof (ifname), "%d", nn->nexthop.ifindex);

          ospf6_timeval_sub (&now, &nn->installed, &res);
          ospf6_timeval_string_summary (&res, duration, sizeof (duration));

          vty_out (vty, "%c%1s %2s %-30s %-25s %6s %s%s",
                   (HEAD ? '*' : ' '),
                   DTYPE_ABNAME (rn->route.type),
                   PTYPE_ABNAME (pn->path.type),
                   prefix, nexthop, ifname, duration, VTY_NEWLINE);

          nc++;
        }
      pc++;
    }
}

void
ospf6_route_show_detail (struct vty *vty, struct ospf6_route_node *rn)
{
  struct linklist_node pnode;
  struct linklist_node nnode;
  struct ospf6_path_node    *pn;
  struct ospf6_nexthop_node *nn;

  u_int pc = 0;
  u_int nc = 0;

  char prefix[64], nexthop[64], ifname[IFNAMSIZ];
  char area_id[16], type[16], id[16], adv[16];
  char capa[64];

  /* destination */
  if (rn->route.prefix.family == AF_INET ||
      rn->route.prefix.family == AF_INET6)
    prefix2str (&rn->route.prefix, prefix, sizeof (prefix));
  else
    prefix_ls2str (&rn->route.prefix, prefix, sizeof (prefix));

  vty_out (vty, "%s%s%s", VTY_NEWLINE, prefix, VTY_NEWLINE);
  vty_out (vty, "    Destination Type: %s%s",
           DTYPE_NAME (rn->route.type), VTY_NEWLINE);

  for (linklist_head (rn->path_list, &pnode); ! linklist_end (&pnode);
       linklist_next (&pnode))
    {
      pn = pnode.data;

      inet_ntop (AF_INET, &pn->path.area_id, area_id, sizeof (area_id));
      ospf6_lsa_type_string (pn->path.origin.type, type, sizeof (type));
      inet_ntop (AF_INET, &pn->path.origin.id, id, sizeof (id));
      inet_ntop (AF_INET, &pn->path.origin.adv_router, adv, sizeof (adv));
      ospf6_options_string (pn->path.capability, capa, sizeof (capa));

      vty_out (vty, "  Path:%s", VTY_NEWLINE);
      vty_out (vty, "    Associated Area: %s%s", area_id, VTY_NEWLINE);
      vty_out (vty, "    LS Origin: %s ID: %s Adv: %s%s",
               type, id, adv, VTY_NEWLINE);
      vty_out (vty, "    Path Type: %s%s",
               PTYPE_NAME (pn->path.type), VTY_NEWLINE);
      vty_out (vty, "    Metric Type: %d%s",
               pn->path.metric_type, VTY_NEWLINE);
      vty_out (vty, "    Cost: Type-1: %lu Type-2: %lu%s",
               (u_long) pn->path.cost, (u_long) pn->path.cost_e2,
               VTY_NEWLINE);
      vty_out (vty, "    Router Bits: %s|%s|%s|%s%s",
               (CHECK_FLAG (pn->path.router_bits, OSPF6_ROUTER_LSA_BIT_W) ?
                "W" : "-"),
               (CHECK_FLAG (pn->path.router_bits, OSPF6_ROUTER_LSA_BIT_V) ?
                "V" : "-"),
               (CHECK_FLAG (pn->path.router_bits, OSPF6_ROUTER_LSA_BIT_E) ?
                "E" : "-"),
               (CHECK_FLAG (pn->path.router_bits, OSPF6_ROUTER_LSA_BIT_B) ?
                "B" : "-"), VTY_NEWLINE);
      vty_out (vty, "    Optional Capabilities: %s%s", capa, VTY_NEWLINE);
      vty_out (vty, "    Prefix Options: %s%s", "xxx", VTY_NEWLINE);
      vty_out (vty, "    Next Hops:%s", VTY_NEWLINE);

      for (linklist_head (pn->nexthop_list, &nnode); ! linklist_end (&nnode);
           linklist_next (&nnode))
        {
          nn = nnode.data;

          inet_ntop (AF_INET6, &nn->nexthop.address, nexthop,
                     sizeof (nexthop));
          if (! if_indextoname (nn->nexthop.ifindex, ifname))
            snprintf (ifname, sizeof (ifname), "%d", nn->nexthop.ifindex);

          vty_out (vty, "       %c%s%%%s%s",
                   (HEAD ? '*' : ' '), nexthop, ifname, VTY_NEWLINE);

          nc++;
        }
      pc++;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

int
ospf6_route_table_show (struct vty *vty, int argc, char **argv,
                        struct ospf6_route_table *table)
{
  int i, ret;
  unsigned long ret_ul;
  char *endptr;
  struct prefix prefix;
  int detail = 0;
  int arg_ipv6  = 0;
  int arg_ipv4  = 0;
  int arg_digit = 0;
  struct prefix_ipv6 *p6 = (struct prefix_ipv6 *) &prefix;
  struct prefix_ls   *pl = (struct prefix_ls *) &prefix;
  struct route_node *node;

  u_int route_count = 0;
  u_int path_count = 0;
  u_int route_redundant = 0;

  memset (&prefix, 0, sizeof (struct prefix));

  for (i = 0; i < argc; i++)
    {
      if (! strcmp (argv[i], "detail"))
        {
          detail++;
          break;
        }

      if (! arg_ipv6 && ! arg_ipv4 && ! arg_digit)
        {

          if ((ret = inet_pton (AF_INET6, argv[i], &p6->prefix)) == 1)
            {
              p6->family = AF_INET6;
              p6->prefixlen = 128;
              arg_ipv6++;
              continue;
            }
          else if ((ret = inet_pton (AF_INET, argv[i], &pl->adv_router)) == 1)
            {
              pl->family = AF_UNSPEC;
              pl->prefixlen = 64; /* xxx */
              arg_ipv4++;
              continue;
            }
          else
            {
              ret_ul = strtoul (argv[i], &endptr, 10);
              if (*endptr == '\0')
                {
                  pl->adv_router.s_addr = htonl (ret_ul);
                  pl->family = AF_UNSPEC;
                  pl->prefixlen = 64; /* xxx */
                  arg_digit++;
                  continue;
                }
              else
                {
                  vty_out (vty, "Malformed argument: %s%s",
                           argv[i], VTY_NEWLINE);
                  return CMD_SUCCESS;
                }
            }
        }

      if (arg_ipv4 || arg_digit)
        {
          if ((ret = inet_pton (AF_INET, argv[i], &pl->id)) == 1)
            {
              arg_ipv4++;
            }
          else
            {
              ret_ul = strtoul (argv[i], &endptr, 10);
              if (*endptr == '\0')
                {
                  pl->id.s_addr = htonl (ret_ul);
                  arg_digit++;
                }
              else
                {
                  vty_out (vty, "Malformed argument: %s%s",
                           argv[i], VTY_NEWLINE);
                  return CMD_SUCCESS;
                }
            }
        }
    }

  if (arg_ipv4 || arg_ipv6 || arg_digit)
    {
      node = route_node_match (table->table, &prefix);
      if (node && node->info)
        ospf6_route_show_detail (vty, node->info);
      return CMD_SUCCESS;
    }

  if (! detail)
    {
      vty_out (vty, "%s%c%1s %2s %-30s %-25s %6s%s", VTY_NEWLINE,
               ' ', " ", " ", "Destination", "Gateway", "I/F", VTY_NEWLINE);
      vty_out (vty, "---------------------------%s", VTY_NEWLINE);
    }

  for (node = route_top (table->table); node; node = route_next (node))
    {
      struct ospf6_route_node *route = node->info;

      if (! route)
        continue;

      if (detail)
        ospf6_route_show_detail (vty, route);
      else
        ospf6_route_show (vty, route);

      route_count++;
      path_count += route->path_list->count;
      if (route->path_list->count > 1)
        route_redundant++;
    }

  vty_out (vty, "===========%s", VTY_NEWLINE);
  vty_out (vty, "Route: %d Path: %d Redundant: %d%s",
           route_count, path_count, route_redundant, VTY_NEWLINE);

  return CMD_SUCCESS;
}

