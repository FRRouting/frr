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
/* Shortest Path First calculation for OSPFv3 */

#include "ospf6d.h"

#include "linklist.h"
#include "prefix.h"
#include "table.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_area.h"

#include "ospf6_bintree.h"
#include "ospf6_linklist.h"

struct bintree *_candidate_list;
struct linklist *nexthop_list;

struct ospf6_spf_candidate_node
{
  u_int32_t cost;
  struct linklist *list;
};

int
ospf6_spf_candidate_node_cmp (void *a, void *b)
{
  struct ospf6_spf_candidate_node *ca = a;
  struct ospf6_spf_candidate_node *cb = b;
  return ca->cost - cb->cost;
}

int
ospf6_spf_vertex_cmp (void *a, void *b)
{
  return 1;
}

void
ospf6_spf_candidate_node_print (int indent_num, void *node)
{
  struct ospf6_spf_candidate_node *cn = node;
  char format[256];

  snprintf (format, sizeof (format), "%%%ds %%d (num: %%d)",
            indent_num * 2 + 1);
  zlog_info (format, " ", cn->cost, cn->list->count);
}

void
ospf6_spf_candidate_init ()
{
  _candidate_list = bintree_create ();
  _candidate_list->cmp = ospf6_spf_candidate_node_cmp;
}

u_int32_t
ospf6_spf_candidate_count ()
{
  u_int32_t count = 0;
  struct bintree_node node;
  struct ospf6_spf_candidate_node *cnode;

  for (bintree_head (_candidate_list, &node); ! bintree_end (&node);
       bintree_next (&node))
    {
      cnode = node.data;
      count += cnode->list->count;
    }

  return count;
}

void
ospf6_spf_candidate_print ()
{
  zlog_info ("---------------------------");
  bintree_print (ospf6_spf_candidate_node_print, _candidate_list);
  zlog_info ("---------------------------");
}

void
ospf6_spf_candidate_enqueue (struct ospf6_vertex *v)
{
  struct ospf6_spf_candidate_node req, *node;

  memset (&req, 0, sizeof (req));
  req.cost = v->distance;
  node = bintree_lookup (&req, _candidate_list);

  if (node == NULL)
    {
      node = malloc (sizeof (struct ospf6_spf_candidate_node));
      node->cost = v->distance;
      node->list = linklist_create ();
      node->list->cmp = ospf6_spf_vertex_cmp;
      bintree_add (node, _candidate_list);
    }

  linklist_add (v, node->list);

#if 0
  if (IS_OSPF6_DUMP_SPF)
    ospf6_spf_candidate_print ();
#endif
}

struct ospf6_vertex *
ospf6_spf_candidate_dequeue ()
{
  struct ospf6_spf_candidate_node *node;
  struct linklist_node lnode;
  struct ospf6_vertex *ret;

  node = bintree_lookup_min (_candidate_list);
  if (node == NULL)
    return NULL;

  linklist_head (node->list, &lnode);
  ret = lnode.data;

  linklist_remove (ret, node->list);
  if (node->list->count == 0)
    {
      linklist_delete (node->list);
      bintree_remove (node, _candidate_list);
    }

#if 0
  if (IS_OSPF6_DUMP_SPF)
    ospf6_spf_candidate_print ();
#endif

  return ret;
}

void
ospf6_spf_candidate_remove (struct ospf6_vertex *v)
{
  struct bintree_node node;
  struct ospf6_spf_candidate_node *cnode = NULL;

  for (bintree_head (_candidate_list, &node); ! bintree_end (&node);
       bintree_next (&node))
    {
      cnode = node.data;
      if (linklist_lookup (v, cnode->list))
        {
          linklist_remove (v, cnode->list);
          break;
        }
    }

  if (cnode->list->count == 0)
    {
      linklist_delete (cnode->list);
      bintree_remove (cnode, _candidate_list);
    }
}


#define TIMER_SEC_MICRO 1000000

/* timeval calculation */
static void
ospf6_timeval_add (const struct timeval *t1, const struct timeval *t2,
                   struct timeval *result)
{
  long moveup = 0;

  result->tv_usec = t1->tv_usec + t2->tv_usec;
  while (result->tv_usec > TIMER_SEC_MICRO)
    {
      result->tv_usec -= TIMER_SEC_MICRO;
      moveup ++;
    }

  result->tv_sec = t1->tv_sec + t2->tv_sec + moveup;
}

static void
ospf6_timeval_add_equal (const struct timeval *t, struct timeval *result)
{
  struct timeval tmp;
  ospf6_timeval_add (t, result, &tmp);
  result->tv_sec = tmp.tv_sec;
  result->tv_usec = tmp.tv_usec;
}

/* Compare timeval a and b.  It returns an integer less than, equal
   to, or great than zero if a is found, respectively, to be less
   than, to match, or be greater than b.  */
static int
ospf6_timeval_cmp (const struct timeval t1, const struct timeval t2)
{
  return (t1.tv_sec == t2.tv_sec
	  ? t1.tv_usec - t2.tv_usec : t1.tv_sec - t2.tv_sec);
}


static int
ospf6_spf_lsd_num (struct ospf6_vertex *V, struct ospf6_area *o6a)
{
  u_int16_t type;
  u_int32_t id, adv_router;
  struct ospf6_lsa *lsa;

  if (V->vertex_id.id.s_addr)
    type = htons (OSPF6_LSA_TYPE_NETWORK);
  else
    type = htons (OSPF6_LSA_TYPE_ROUTER);
  id = V->vertex_id.id.s_addr;
  adv_router = V->vertex_id.adv_router.s_addr;

  lsa = ospf6_lsdb_lookup_lsdb (type, id, adv_router, o6a->lsdb);
  if (! lsa)
    {
      zlog_err ("SPF: Can't find associated LSA for %s", V->string);
      return 0;
    }

  return ospf6_lsa_lsd_num ((struct ospf6_lsa_header *) lsa->header);
}

/* RFC2328 section 16.1.1:
   Check if there is at least one router in the path
   from the root to this vertex. */
static int
ospf6_spf_is_router_to_root (struct ospf6_vertex *c,
                             struct ospf6_spftree *spf_tree)
{
  listnode node;
  struct ospf6_vertex *p;

  if (spf_tree->root == c)
    return 0;

  for (node = listhead (c->parent_list); node; nextnode (node))
    {
      p = (struct ospf6_vertex *) getdata (node);

      if (p == spf_tree->root)
        return 0;

      if (p->vertex_id.id.s_addr == 0) /* this is router */
        continue;
      else if (ospf6_spf_is_router_to_root (p, spf_tree))
        continue;

      return 0;
    }

  return 1;
}

static struct in6_addr *
ospf6_spf_get_ipaddr (u_int32_t id, u_int32_t adv_router, u_int32_t ifindex)
{
  char buf[64], nhbuf[64];
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n;
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb_node node;

  o6i = ospf6_interface_lookup_by_index (ifindex);
  if (! o6i)
    {
      zlog_err ("SPF: Can't find interface: index %d", ifindex);
      return (struct in6_addr *) NULL;
    }

  /* Find Link-LSA of the vertex in question */
  lsa = NULL;
  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_LINK),
                               adv_router, o6i->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    lsa = node.lsa;

  /* return Linklocal Address field if the Link-LSA exists */
  if (lsa && lsa->header->adv_router == adv_router)
    {
      struct ospf6_link_lsa *link_lsa;
      link_lsa = (struct ospf6_link_lsa *) (lsa->header + 1);
      return &link_lsa->llsa_linklocal;
    }

  zlog_warn ("SPF: Can't find Link-LSA for %s",
             inet_ntop (AF_INET, &adv_router, buf, sizeof (buf)));

  o6n = ospf6_neighbor_lookup (adv_router, o6i);
  if (! o6n)
    {
      inet_ntop (AF_INET, &adv_router, buf, sizeof (buf));
      zlog_err ("SPF: Can't find neighbor %s in %s, "
                "unable to find his linklocal address",
                buf, o6i->interface->name);
      return (struct in6_addr *) NULL;
    }

  zlog_warn ("SPF: use packet's source address for %s's nexthop: %s",
             inet_ntop (AF_INET, &adv_router, buf, sizeof (buf)),
             inet_ntop (AF_INET6, &o6n->hisaddr, nhbuf, sizeof (nhbuf)));

  return &o6n->hisaddr;
}

static int
ospf6_spf_nexthop_calculation (struct ospf6_vertex *W,
                               u_int32_t ifindex,
                               struct ospf6_vertex *V,
                               struct ospf6_spftree *spf_tree)
{
  struct ospf6_nexthop *nexthop, *n;
  u_int32_t adv_router, id;
  struct in6_addr nexthop_ipaddr, *ipaddr;
  unsigned int nexthop_ifindex;
  struct linklist_node node;

  /* until this, nexthop_list should be untouched */
  assert (list_isempty (W->nexthop_list));

  /* If ther is at least one intervening router from root to W */
  if (ospf6_spf_is_router_to_root (W, spf_tree))
    {
      /* Create no new nexthop, Inherit from the intervening router */
      for (linklist_head (V->nexthop_list, &node); ! linklist_end (&node);
           linklist_next (&node))
        linklist_add (node.data, W->nexthop_list);
      return 0;
    }

  /* Create new nexthop */

  adv_router = W->vertex_id.adv_router.s_addr;
  id = W->vertex_id.id.s_addr;

  nexthop_ifindex = 0;
  memset (&nexthop_ipaddr, 0, sizeof (struct in6_addr));
  if (spf_tree->root && V == spf_tree->root)
    {
      nexthop_ifindex = ifindex;
      if (! id) /* xxx, if V is router */
        {
          ipaddr = ospf6_spf_get_ipaddr (id, adv_router, ifindex);
          if (! ipaddr)
            {
              /* xxx, should trigger error and quit SPF calculation... */
              memset (&nexthop_ipaddr, 0xff, sizeof (struct in6_addr));
              return -1;
            }
          else
            memcpy (&nexthop_ipaddr, ipaddr, sizeof (struct in6_addr));
        }
    }
  else
    {
      /* V is broadcast network, W is router */
      assert (V->vertex_id.id.s_addr != 0);
      assert (W->vertex_id.id.s_addr == 0);
 
      linklist_head (V->nexthop_list, &node);
      n = (struct ospf6_nexthop *) node.data;
      nexthop_ifindex = n->ifindex;
      ipaddr = ospf6_spf_get_ipaddr (id, adv_router, n->ifindex);
      if (! ipaddr)
        {
          /* xxx, should trigger error and quit SPF calculation... */
          memset (&nexthop_ipaddr, 0xff, sizeof (struct in6_addr));
          return -1;
        }
      else
        memcpy (&nexthop_ipaddr, ipaddr, sizeof (struct in6_addr));
    }

  nexthop = XCALLOC (MTYPE_OSPF6_VERTEX, sizeof (struct ospf6_nexthop));
  nexthop->ifindex = nexthop_ifindex;
  memcpy (&nexthop->address, &nexthop_ipaddr, sizeof (nexthop->address));

  linklist_add (nexthop, W->nexthop_list);

  /* to hold malloced memory */
  linklist_add (nexthop, nexthop_list);

  return 0;
}

static struct ospf6_vertex *
ospf6_spf_vertex_create (int index, struct ospf6_vertex *V,
                         struct ospf6_area *o6a)
{
  struct ospf6_lsa *lsa;
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsd *router_lsd;
  struct ospf6_network_lsa *network_lsa;
  struct ospf6_network_lsd *network_lsd;
  u_int32_t id, adv_router;
  u_int16_t type;
  void *lsd;
  struct ospf6_vertex *W;
  u_int16_t distance;
  u_int32_t ifindex;
  int backreference, lsdnum, i;
  char buf_router[16], buf_id[16];

  type = id = adv_router = 0;

  /* Get Linkstate description */
  lsd = ospf6_lsa_lsd_get (index, (struct ospf6_lsa_header *) V->lsa->header);
  if (! lsd)
    {
      zlog_err ("SPF: Can't find %dth Link description from %s",
                index, V->lsa->str);
      return (struct ospf6_vertex *) NULL;
    }

  /* Check Link state description */
  distance = 0;
  ifindex = 0;
  if (V->lsa->header->type == htons (OSPF6_LSA_TYPE_ROUTER))
    {
      router_lsd = lsd;
      if (router_lsd->type == OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT)
        {
          type = htons (OSPF6_LSA_TYPE_ROUTER);
          id = htonl (0);
        }
      else if (router_lsd->type == OSPF6_ROUTER_LSD_TYPE_TRANSIT_NETWORK)
        {
          type = htons (OSPF6_LSA_TYPE_NETWORK);
          id = router_lsd->neighbor_interface_id;
        }
      adv_router = router_lsd->neighbor_router_id;
      distance = ntohs (router_lsd->metric);
      ifindex = ntohl (router_lsd->interface_id);
    }
  else if (V->lsa->header->type == htons (OSPF6_LSA_TYPE_NETWORK))
    {
      network_lsd = lsd;
      type = htons (OSPF6_LSA_TYPE_ROUTER);
      id = htonl (0);
      adv_router = network_lsd->adv_router;
    }

  /* Avoid creating candidate of myself */
  if (adv_router == o6a->ospf6->router_id &&
      type == htons (OSPF6_LSA_TYPE_ROUTER))
    {
      return (struct ospf6_vertex *) NULL;
    }

  /* Find Associated LSA for W */
  lsa = ospf6_lsdb_lookup_lsdb (type, id, adv_router, o6a->lsdb);

  if (! lsa)
    {
      inet_ntop (AF_INET, &adv_router, buf_router, sizeof (buf_router));
      inet_ntop (AF_INET, &id, buf_id, sizeof (buf_id));

      if (IS_OSPF6_DUMP_SPF)
        {
          if (type == htons (OSPF6_LSA_TYPE_ROUTER))
            zlog_info ("SPF: Can't find LSA for W (%s *): not found",
                      buf_router);
          else
            zlog_info ("SPF: Can't find LSA for W (%s %s): not found",
                      buf_router, buf_id);
        }
      return (struct ospf6_vertex *) NULL;
    }

  if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_OSPF6_DUMP_SPF)
        zlog_info ("SPF: Associated LSA for W is MaxAge: %s", lsa->str);
      return (struct ospf6_vertex *) NULL;
    }

  /* Check back reference from W's lsa to V's lsa */
  backreference = 0;
  lsdnum = ospf6_lsa_lsd_num ((struct ospf6_lsa_header *) lsa->header);
  for (i = 0; i < lsdnum; i++)
    {
      if (ospf6_lsa_lsd_is_refer_ok (i, (struct ospf6_lsa_header *) lsa->header,
                                     index, (struct ospf6_lsa_header *) V->lsa->header))
        backreference++;
    }
  if (! backreference)
    {
      if (IS_OSPF6_DUMP_SPF)
        zlog_info ("SPF: Back reference failed: V: %s, W: %s",
                   V->lsa->str, lsa->str);
      return (struct ospf6_vertex *) NULL;
    }

  /* Allocate new ospf6_vertex for W */
  W = (struct ospf6_vertex *) XMALLOC (MTYPE_OSPF6_VERTEX,
                                       sizeof (struct ospf6_vertex));
  if (! W)
    {
      zlog_err ("SPF: Can't allocate memory for Vertex");
      return (struct ospf6_vertex *) NULL;
    }
  memset (W, 0, sizeof (struct ospf6_vertex));

  /* Initialize */
  W->vertex_id.family = AF_UNSPEC;
  W->vertex_id.prefixlen = 64; /* xxx */
  W->lsa = lsa;
  if (type == htons (OSPF6_LSA_TYPE_ROUTER))
    W->vertex_id.id.s_addr = htonl (0); /* XXX */
  else
    W->vertex_id.id.s_addr = W->lsa->header->id;
  W->vertex_id.adv_router.s_addr = W->lsa->header->adv_router;
  W->nexthop_list = linklist_create ();
  W->path_list = list_new ();
  W->parent_list = list_new ();
  W->distance = V->distance + distance;
  W->depth = V->depth + 1;

  inet_ntop (AF_INET, &W->vertex_id.adv_router.s_addr,
             buf_router, sizeof (buf_router));
  inet_ntop (AF_INET, &W->vertex_id.id.s_addr, buf_id, sizeof (buf_id));
  snprintf (W->string, sizeof (W->string), "[%s-%s (%d)]",
            buf_router, buf_id, W->distance);

  /* capability bits and optional capabilities */
  if (W->vertex_id.id.s_addr == 0)
    {
      router_lsa = (struct ospf6_router_lsa *) (W->lsa->header + 1);
      W->capability_bits = router_lsa->bits;
      memcpy (W->opt_capability, router_lsa->options,
              sizeof (W->opt_capability));
    }
  else
    {
      network_lsa = (struct ospf6_network_lsa *) (W->lsa->header + 1);
      W->capability_bits = network_lsa->reserved;
      memcpy (W->opt_capability, network_lsa->options,
              sizeof (W->opt_capability));
    }

  /* Link to Parent node */
  listnode_add (W->parent_list, V);

  /* Nexthop Calculation */
  if (ospf6_spf_nexthop_calculation (W, ifindex, V, o6a->spf_tree) < 0)
    return NULL;

  return W;
}

static void
ospf6_spf_vertex_delete (struct ospf6_vertex *v)
{
  linklist_delete (v->nexthop_list);
  list_delete (v->path_list);
  list_delete (v->parent_list);
  XFREE (MTYPE_OSPF6_VERTEX, v);
}

static void
ospf6_spf_vertex_merge (struct ospf6_vertex *w, struct ospf6_vertex *x)
{
  listnode node;
  struct linklist_node lnode;

  /* merge should be done on two nodes which are
     almost the same */

  /* these w and x should be both candidate.
     candidate should not have any children */
  assert (list_isempty (w->path_list));
  assert (list_isempty (x->path_list));

  /* merge parent list */
  for (node = listhead (w->parent_list); node; nextnode (node))
    {
      if (listnode_lookup (x->parent_list, getdata (node)))
        continue;
      listnode_add (x->parent_list, getdata (node));
    }

  /* merge nexthop list */
  for (linklist_head (w->nexthop_list, &lnode); ! linklist_end (&lnode);
       linklist_next (&lnode))
    linklist_add (lnode.data, x->nexthop_list);
}

static void
ospf6_spf_initialize (list candidate_list, struct ospf6_area *o6a)
{
  listnode node;
  struct ospf6_vertex *v;
  struct ospf6_lsa *lsa;
  u_int16_t type;
  u_int32_t id, adv_router;
  struct linklist_node lnode;

  struct ospf6_nexthop *nexthop;
  struct interface *ifp;
  char buf_router[64], buf_id[64];

  /* delete topology routing table for this area */
  ospf6_route_remove_all (o6a->table_topology);

  /* Delete previous spf tree */
  for (node = listhead (o6a->spf_tree->list); node; nextnode (node))
    {
      v = (struct ospf6_vertex *) getdata (node);
      ospf6_spf_vertex_delete (v);
    }
  list_delete_all_node (o6a->spf_tree->list);

  for (linklist_head (nexthop_list, &lnode); ! linklist_end (&lnode);
       linklist_next (&lnode))
    XFREE (MTYPE_OSPF6_VERTEX, lnode.data);
  linklist_remove_all (nexthop_list);

  /* Find self originated Router-LSA */
  type = htons (OSPF6_LSA_TYPE_ROUTER);
  id = htonl (0);
  adv_router = ospf6->router_id;

  lsa = ospf6_lsdb_lookup_lsdb (type, id, adv_router, o6a->lsdb);

  if (! lsa)
    {
      if (IS_OSPF6_DUMP_SPF)
        zlog_info ("SPF: Can't find self originated Router-LSA");
      return;
    }
  if (IS_LSA_MAXAGE (lsa))
    {
      zlog_err ("SPF: MaxAge self originated Router-LSA");
      return;
    }

  /* Create root vertex */
  v = (struct ospf6_vertex *) XMALLOC (MTYPE_OSPF6_VERTEX,
                                       sizeof (struct ospf6_vertex));
  if (! v)
    {
      zlog_err ("SPF: Can't allocate memory for root vertex");
      return;
    }
  memset (v, 0, sizeof (struct ospf6_vertex));

  v->vertex_id.family = AF_UNSPEC; /* XXX */
  v->vertex_id.prefixlen = 64; /* XXX */
  v->vertex_id.id.s_addr = htonl (0);
  v->vertex_id.adv_router.s_addr = ospf6->router_id;
  if (ospf6_is_asbr (ospf6))
    OSPF6_OPT_SET (v->opt_capability, OSPF6_OPT_E);
  OSPF6_OPT_SET (v->opt_capability, OSPF6_OPT_V6);
  OSPF6_OPT_SET (v->opt_capability, OSPF6_OPT_R);
  v->nexthop_list = linklist_create ();
  v->path_list = list_new ();
  v->parent_list = list_new ();
  v->distance = 0;
  v->depth = 0;
  v->lsa = lsa;

  inet_ntop (AF_INET, &v->vertex_id.adv_router.s_addr,
             buf_router, sizeof (buf_router));
  inet_ntop (AF_INET, &v->vertex_id.id.s_addr, buf_id, sizeof (buf_id));
  snprintf (v->string, sizeof (v->string), "[%s-%s (%d)]",
            buf_router, buf_id, v->distance);

  nexthop = XCALLOC (MTYPE_OSPF6_VERTEX, sizeof (struct ospf6_nexthop));
  ifp = if_lookup_by_name ("lo0");
  if (ifp)
    nexthop->ifindex = ifp->ifindex;
  inet_pton (AF_INET6, "::1", &nexthop->address);
  linklist_add (nexthop, v->nexthop_list);
  linklist_add (nexthop, nexthop_list);

  o6a->spf_tree->root = v;
  listnode_add (candidate_list, v);

  ospf6_spf_candidate_enqueue (v);
}

static struct ospf6_vertex *
ospf6_spf_get_closest_candidate (list candidate_list)
{
  listnode node;
  struct ospf6_vertex *candidate, *closest;

  closest = (struct ospf6_vertex *) NULL;
  for (node = listhead (candidate_list); node; nextnode (node))
    {
      candidate = (struct ospf6_vertex *) getdata (node);

      if (closest && candidate->distance > closest->distance)
        continue;

      /* always choose network vertices if those're the same cost */
      if (closest && candidate->distance == closest->distance
          && closest->vertex_id.id.s_addr != 0)
        continue;

      closest = candidate;
    }

  return closest;
}

static struct ospf6_vertex *
ospf6_spf_get_same_candidate (struct ospf6_vertex *w, list candidate_list)
{
  listnode node;
  struct ospf6_vertex *c, *same;

  same = (struct ospf6_vertex *) NULL;
  for (node = listhead (candidate_list); node; nextnode (node))
    {
      c = (struct ospf6_vertex *) getdata (node);
      if (w->vertex_id.adv_router.s_addr != c->vertex_id.adv_router.s_addr)
        continue;
      if (w->vertex_id.id.s_addr != c->vertex_id.id.s_addr)
        continue;

      if (same)
        zlog_warn ("SPF: duplicate candidates in candidate_list");

      same = c;
    }

  return same;
}

static void
ospf6_spf_install (struct ospf6_vertex *vertex, struct ospf6_area *o6a)
{
  listnode node;
  struct ospf6_vertex *parent;
  struct ospf6_nexthop *nexthop;
  struct ospf6_route_req request;
  struct linklist_node lnode;

  struct ospf6_router_lsa *router_lsa;
  struct ospf6_network_lsa *network_lsa;

  router_lsa = OSPF6_LSA_HEADER_END (vertex->lsa->header);
  network_lsa = OSPF6_LSA_HEADER_END (vertex->lsa->header);

  if (IS_OSPF6_DUMP_SPF)
    {
      zlog_info ("SPF: Install: %s", vertex->string);
    }

  listnode_add (o6a->spf_tree->list, vertex);

  for (node = listhead (vertex->parent_list); node; nextnode (node))
    {
      parent = (struct ospf6_vertex *) getdata (node);
      listnode_add (parent->path_list, vertex);
      vertex->depth = parent->depth + 1;
    }

#if 0
  if (vertex == o6a->spf_tree->root)
    return;
#endif /*0*/

  /* install route to topology table */
  memset (&request, 0, sizeof (request));
  if (vertex->vertex_id.id.s_addr) /* xxx */
    request.route.type = OSPF6_DEST_TYPE_NETWORK;
  else
    request.route.type = OSPF6_DEST_TYPE_ROUTER;
  memcpy (&request.route.prefix, &vertex->vertex_id,
          sizeof (struct prefix));

  request.path.area_id = o6a->area_id;
  request.path.type = OSPF6_PATH_TYPE_INTRA;
  request.path.cost = vertex->distance;
  request.path.cost_e2 = 0;
  request.path.origin.type = vertex->lsa->header->type;
  request.path.origin.id = vertex->lsa->header->id;
  request.path.origin.adv_router = vertex->lsa->header->adv_router;
  if (vertex->lsa->header->type == htons (OSPF6_LSA_TYPE_ROUTER))
    request.path.router_bits = router_lsa->bits;
  memcpy (&request.path.capability, vertex->opt_capability,
          sizeof (request.path.capability));

#if 0
  if (IS_OSPF6_DUMP_SPF)
    zlog_info ("SPF:   install %d nexthops for %s",
               listcount (vertex->nexthop_list), vertex->string);
#endif

  for (linklist_head (vertex->nexthop_list, &lnode); ! linklist_end (&lnode);
       linklist_next (&lnode))
    {
      nexthop = lnode.data;

      request.nexthop.ifindex = nexthop->ifindex;
      memcpy (&request.nexthop.address, &nexthop->address,
              sizeof (request.nexthop.address));

      ospf6_route_add (&request, o6a->table_topology);
    }
}

struct ospf6_vertex *
ospf6_spf_lookup (struct ospf6_vertex *w, struct ospf6_area *o6a)
{
  listnode node;
  struct ospf6_vertex *v;

  for (node = listhead (o6a->spf_tree->list); node; nextnode (node))
    {
      v = (struct ospf6_vertex *) getdata (node);

      if (w->vertex_id.adv_router.s_addr != v->vertex_id.adv_router.s_addr)
        continue;
      if (w->vertex_id.id.s_addr != v->vertex_id.id.s_addr)
        continue;

      return v;
    }

  return (struct ospf6_vertex *) NULL;
}

u_int32_t stat_node = 0;
u_int32_t stat_candidate = 0;
u_int32_t stat_candidate_max = 0;
u_int32_t stat_spf = 0;


/* RFC2328 section 16.1 , RFC2740 section 3.8.1 */
static int
ospf6_spf_calculation (struct ospf6_area *o6a)
{
  list candidate_list;
  struct ospf6_vertex *V, *W, *X;
  int ldnum, i;

  if (! o6a || ! o6a->spf_tree)
    {
      zlog_err ("SPF: Can't calculate SPF tree: malformed area");
      return -1;
    }

  stat_spf ++;
  stat_node = 0;
  stat_candidate = 0;
  stat_candidate_max = 0;

  if (IS_OSPF6_DUMP_SPF)
    zlog_info ("SPF: Calculation for area %s", o6a->str);

  ospf6_route_table_freeze (o6a->table_topology);
  ospf6_route_remove_all (o6a->table_topology);

  /* (1): Initialize the algorithm's data structures */
  candidate_list = list_new ();
  ospf6_spf_initialize (candidate_list, o6a);
  stat_candidate ++;

  /* (3): Install closest from candidate list; if empty, break */
  while (listcount (candidate_list))
    {
      V = ospf6_spf_get_closest_candidate (candidate_list);
      listnode_delete (candidate_list, V);

      {
        struct ospf6_vertex *V_;

        if (stat_candidate_max < ospf6_spf_candidate_count ())
          stat_candidate_max = ospf6_spf_candidate_count ();

        V_ = ospf6_spf_candidate_dequeue ();

#if 0
        if (IS_OSPF6_DUMP_SPF)
          {
            zlog_info ("Candidate list count: %lu",
                       (u_long)ospf6_spf_candidate_count ());
            zlog_info ("*** Candidate %s: %p <-> %p",
                       (V == V_ ? "same" : "*** differ ***"), V, V_);
            zlog_info ("  %p: %s", V, V->string);
            zlog_info ("  %p: %s", V_, V_->string);
          }
#endif

      }

      stat_node++;
      ospf6_spf_install (V, o6a);

      /* (2): Examin LSA of just added vertex */
      ldnum = ospf6_spf_lsd_num (V, o6a);
      for (i = 0; i < ldnum; i++)
        {
          /* (b): If no LSA, or MaxAge, or LinkBack fail, examin next */
          W = ospf6_spf_vertex_create (i, V, o6a);
          if (! W)
            continue;

          stat_candidate ++;

          /* (c) */
          if (ospf6_spf_lookup (W, o6a))
            {
              if (IS_OSPF6_DUMP_SPF)
                zlog_info ("SPF:   %s: Already in SPF tree", W->string);
              ospf6_spf_vertex_delete (W);
              continue;
            }

          /* (d) */
          X = ospf6_spf_get_same_candidate (W, candidate_list);
          if (X && X->distance < W->distance)
            {
              if (IS_OSPF6_DUMP_SPF)
                zlog_info ("SPF:   %s: More closer found", W->string);
              ospf6_spf_vertex_delete (W);
              continue;
            }
          if (X && X->distance == W->distance)
            {
              if (IS_OSPF6_DUMP_SPF)
                zlog_info ("SPF:   %s: new ECMP candidate", W->string);
              ospf6_spf_vertex_merge (W, X);
              ospf6_spf_vertex_delete (W);
              continue;
            }

          if (X)
            {
              if (IS_OSPF6_DUMP_SPF)
                zlog_info ("SPF:   %s: Swap with old candidate", W->string);
              listnode_delete (candidate_list, X);
              ospf6_spf_candidate_remove (X);
              ospf6_spf_vertex_delete (X);
            }
          else
            {
              if (IS_OSPF6_DUMP_SPF)
                zlog_info ("SPF:   %s: New Candidate", W->string);
            }

          if (stat_candidate_max < ospf6_spf_candidate_count ())
            stat_candidate_max = ospf6_spf_candidate_count ();

          listnode_add (candidate_list, W);
          ospf6_spf_candidate_enqueue (W);
        }
    }

  assert (listcount (candidate_list) == 0);
  list_free (candidate_list);
  assert (ospf6_spf_candidate_count () == 0);

  /* Clear thread timer */
  o6a->spf_tree->t_spf_calculation = (struct thread *) NULL;

  if (IS_OSPF6_DUMP_SPF)
    {
      zlog_info ("SPF: Calculation for area %s done", o6a->str);
      zlog_info ("SPF:   Statistics: %luth", (u_long)stat_spf);
      zlog_info ("SPF:   Node Number: %lu", (u_long)stat_node);
      zlog_info ("SPF:   Candidate Number: %lu Max: %lu",
                 (u_long) stat_candidate, (u_long) stat_candidate_max);
    }

  ospf6_route_table_thaw (o6a->table_topology);
  return 0;
}

int
ospf6_spf_calculation_thread (struct thread *t)
{
  struct ospf6_area *o6a;
  struct timeval start, end, runtime, interval;

  o6a = (struct ospf6_area *) THREAD_ARG (t);
  if (! o6a)
    {
      zlog_err ("SPF: Thread error");
      return -1;
    }

  if (! o6a->spf_tree)
    {
      zlog_err ("SPF: Can't find SPF Tree for area: %s", o6a->str);
      return -1;
    }

  /* execute SPF calculation */
  gettimeofday (&start, (struct timezone *) NULL);
  ospf6_spf_calculation (o6a);
  gettimeofday (&end, (struct timezone *) NULL);

  /* update statistics */
  o6a->spf_tree->timerun ++;
  ospf6_timeval_sub (&end, &start, &runtime);
  ospf6_timeval_add_equal (&runtime, &o6a->spf_tree->runtime_total);

  if (o6a->spf_tree->timerun == 1)
    {
      o6a->spf_tree->runtime_min.tv_sec = runtime.tv_sec;
      o6a->spf_tree->runtime_min.tv_usec = runtime.tv_usec;
      o6a->spf_tree->runtime_max.tv_sec = runtime.tv_sec;
      o6a->spf_tree->runtime_max.tv_usec = runtime.tv_usec;
    }
  if (ospf6_timeval_cmp (o6a->spf_tree->runtime_min, runtime) > 0)
    {
      o6a->spf_tree->runtime_min.tv_sec = runtime.tv_sec;
      o6a->spf_tree->runtime_min.tv_usec = runtime.tv_usec;
    }
  if (ospf6_timeval_cmp (runtime, o6a->spf_tree->runtime_max) > 0)
    {
      o6a->spf_tree->runtime_max.tv_sec = runtime.tv_sec;
      o6a->spf_tree->runtime_max.tv_usec = runtime.tv_usec;
    }

  if (o6a->spf_tree->timerun == 1)
    {
      ospf6_timeval_sub (&start, &ospf6->starttime, &interval);
      ospf6_timeval_add_equal (&interval, &o6a->spf_tree->interval_total);
      o6a->spf_tree->interval_min.tv_sec = interval.tv_sec;
      o6a->spf_tree->interval_min.tv_usec = interval.tv_usec;
      o6a->spf_tree->interval_max.tv_sec = interval.tv_sec;
      o6a->spf_tree->interval_max.tv_usec = interval.tv_usec;
    }
  else
    {
      ospf6_timeval_sub (&start, &o6a->spf_tree->updated_time, &interval);
      ospf6_timeval_add_equal (&interval, &o6a->spf_tree->interval_total);
      if (ospf6_timeval_cmp (o6a->spf_tree->interval_min, interval) > 0)
        {
          o6a->spf_tree->interval_min.tv_sec = interval.tv_sec;
          o6a->spf_tree->interval_min.tv_usec = interval.tv_usec;
        }
      if (ospf6_timeval_cmp (interval, o6a->spf_tree->interval_max) > 0)
        {
          o6a->spf_tree->interval_max.tv_sec = interval.tv_sec;
          o6a->spf_tree->interval_max.tv_usec = interval.tv_usec;
        }
    }
  o6a->spf_tree->updated_time.tv_sec = end.tv_sec;
  o6a->spf_tree->updated_time.tv_usec = end.tv_usec;

  /* clear thread */
  o6a->spf_tree->t_spf_calculation = (struct thread *) NULL;

  return 0;
}

void
ospf6_spf_database_hook (struct ospf6_lsa *old, struct ospf6_lsa *new)
{
  struct ospf6_area *o6a = NULL;
  struct ospf6_interface *o6i = NULL;

  if (new->header->type == htons (OSPF6_LSA_TYPE_ROUTER) ||
      new->header->type == htons (OSPF6_LSA_TYPE_NETWORK))
    o6a = new->scope;
  else if (new->header->type == htons (OSPF6_LSA_TYPE_LINK))
    {
      o6i = new->scope;
      o6a = o6i->area;
    }

  if (o6a)
    ospf6_spf_calculation_schedule (o6a->area_id);
}

void
ospf6_spf_calculation_schedule (u_int32_t area_id)
{
  struct ospf6_area *o6a;
  char buf[64];

  o6a = ospf6_area_lookup (area_id, ospf6);
  if (! o6a)
    {
      inet_ntop (AF_INET, &area_id, buf, sizeof (buf));
      zlog_err ("SPF: Can't find area: %s", buf);
      return;
    }

  if (! o6a->spf_tree)
    {
      zlog_err ("SPF: Can't find SPF Tree for area: %s", o6a->str);
      return;
    }

  if (o6a->spf_tree->t_spf_calculation)
    return;

  o6a->spf_tree->t_spf_calculation =
    thread_add_event (master, ospf6_spf_calculation_thread, o6a, 0);
}

struct ospf6_spftree *
ospf6_spftree_create ()
{
  struct ospf6_spftree *spf_tree;
  spf_tree = (struct ospf6_spftree *) XMALLOC (MTYPE_OSPF6_SPFTREE,
                                               sizeof (struct ospf6_spftree));
  if (! spf_tree)
    {
      zlog_err ("SPF: Can't allocate memory for SPF tree");
      return (struct ospf6_spftree *) NULL;
    }
  memset (spf_tree, 0, sizeof (spf_tree));

  spf_tree->list = list_new ();

  return spf_tree;
}

void
ospf6_spftree_delete (struct ospf6_spftree *spf_tree)
{
  listnode node;
  struct ospf6_vertex *v;

  /* Delete spf tree */
  for (node = listhead (spf_tree->list); node; nextnode (node))
    {
      v = (struct ospf6_vertex *) getdata (node);
      ospf6_spf_vertex_delete (v);
    }
  list_delete_all_node (spf_tree->list);

  XFREE (MTYPE_OSPF6_SPFTREE, spf_tree);
}

void
ospf6_nexthop_show (struct vty *vty, struct ospf6_nexthop *nexthop)
{
  char buf[128], *ifname;
  struct ospf6_interface *o6i;

  ifname = NULL;

  o6i = ospf6_interface_lookup_by_index (nexthop->ifindex);
  if (! o6i)
    {
      zlog_err ("Spf: invalid ifindex %d in nexthop", nexthop->ifindex);
    }
  else
    ifname = o6i->interface->name;

  inet_ntop (AF_INET6, &nexthop->address, buf, sizeof (buf));
  vty_out (vty, "    %s%%%s(%d)%s", buf, ifname,
           nexthop->ifindex, VTY_NEWLINE);
}

void
ospf6_vertex_show (struct vty *vty, struct ospf6_vertex *vertex)
{
  listnode node;
  struct ospf6_vertex *v;
  struct linklist_node lnode;

  vty_out (vty, "SPF node %s%s", vertex->string, VTY_NEWLINE);
  vty_out (vty, "  cost to this node: %d%s", vertex->distance, VTY_NEWLINE);
  vty_out (vty, "  hops to this node: %d%s", vertex->depth, VTY_NEWLINE);

  vty_out (vty, "  nexthops reachable to this node:%s", VTY_NEWLINE);
  for (linklist_head (vertex->nexthop_list, &lnode);
       ! linklist_end (&lnode);
       linklist_next (&lnode))
    ospf6_nexthop_show (vty, (struct ospf6_nexthop *) lnode.data);

  vty_out (vty, "  parent nodes to this node:%s", VTY_NEWLINE);
  if (! list_isempty (vertex->parent_list))
    vty_out (vty, "    ");
  for (node = listhead (vertex->parent_list); node; nextnode (node))
    {
      v = (struct ospf6_vertex *) getdata (node);
      vty_out (vty, "%s ", v->string);
    }
  if (! list_isempty (vertex->parent_list))
    vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "  child nodes to this node:%s", VTY_NEWLINE);
  if (! list_isempty (vertex->path_list))
    vty_out (vty, "    ");
  for (node = listhead (vertex->path_list); node; nextnode (node))
    {
      v = (struct ospf6_vertex *) getdata (node);
      vty_out (vty, "%s ", v->string);
    }
  if (! list_isempty (vertex->path_list))
    vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "%s", VTY_NEWLINE);
}

void
ospf6_spf_statistics_show (struct vty *vty, struct ospf6_spftree *spf_tree)
{
  listnode node;
  struct ospf6_vertex *vertex;
  u_int router_count, network_count, maxdepth;
  struct timeval runtime_avg, interval_avg, last_updated, now;
  char rmin[64], rmax[64], ravg[64];
  char imin[64], imax[64], iavg[64];
  char last_updated_string[64];

  maxdepth = router_count = network_count = 0;
  for (node = listhead (spf_tree->list); node; nextnode (node))
    {
      vertex = (struct ospf6_vertex *) getdata (node);
      if (vertex->vertex_id.id.s_addr)
        network_count++;
      else
        router_count++;
      if (maxdepth < vertex->depth)
        maxdepth = vertex->depth;
    }

  ospf6_timeval_div (&spf_tree->runtime_total, spf_tree->timerun,
                     &runtime_avg);
  ospf6_timeval_string (&spf_tree->runtime_min, rmin, sizeof (rmin));
  ospf6_timeval_string (&spf_tree->runtime_max, rmax, sizeof (rmax));
  ospf6_timeval_string (&runtime_avg, ravg, sizeof (ravg));

  ospf6_timeval_div (&spf_tree->interval_total, spf_tree->timerun,
                     &interval_avg);
  ospf6_timeval_string (&spf_tree->interval_min, imin, sizeof (imin));
  ospf6_timeval_string (&spf_tree->interval_max, imax, sizeof (imax));
  ospf6_timeval_string (&interval_avg, iavg, sizeof (iavg));

  gettimeofday (&now, (struct timezone *) NULL);
  ospf6_timeval_sub (&now, &spf_tree->updated_time, &last_updated);
  ospf6_timeval_string (&last_updated, last_updated_string,
                        sizeof (last_updated_string));

  vty_out (vty, "     SPF algorithm executed %d times%s", 
           spf_tree->timerun, VTY_NEWLINE);
  vty_out (vty, "     Average time to run SPF: %s%s",
           ravg, VTY_NEWLINE);
  vty_out (vty, "     Maximum time to run SPF: %s%s",
           rmax, VTY_NEWLINE);
  vty_out (vty, "     Average interval of SPF: %s%s",
           iavg, VTY_NEWLINE);
  vty_out (vty, "     SPF last updated: %s ago%s",
           last_updated_string, VTY_NEWLINE);
  vty_out (vty, "     Current SPF node count: %d%s",
           listcount (spf_tree->list), VTY_NEWLINE);
  vty_out (vty, "       Router: %d Network: %d%s",
           router_count, network_count, VTY_NEWLINE);
  vty_out (vty, "       Maximum of Hop count to nodes: %d%s",
           maxdepth, VTY_NEWLINE);
}

DEFUN (show_ipv6_ospf6_area_spf_node,
       show_ipv6_ospf6_area_spf_node_cmd,
       "show ipv6 ospf6 area A.B.C.D spf node",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       "Shortest Path First caculation\n"
       "vertex infomation\n"
       )
{
  listnode i;
  u_int32_t area_id;
  struct ospf6_area *o6a;
  struct ospf6_vertex *vertex;

  OSPF6_CMD_CHECK_RUNNING ();

  inet_pton (AF_INET, argv[0], &area_id);
  o6a = ospf6_area_lookup (area_id, ospf6);
  if (! o6a)
    return CMD_SUCCESS;

  for (i = listhead (o6a->spf_tree->list); i; nextnode (i))
    {
      vertex = (struct ospf6_vertex *) getdata (i);
      ospf6_vertex_show (vty, vertex);
    }

  return CMD_SUCCESS;
}

static void
ospf6_spftree_show (struct vty *vty, char *prefix, int current_rest,
                    struct ospf6_vertex *v)
{
  char *p;
  int psize;
  int restnum;
  listnode node;

  vty_out (vty, "%s+-%s%s", prefix, v->string, VTY_NEWLINE);

  if (listcount (v->path_list) == 0)
    return;

  psize = strlen (prefix) + 3;
  p = malloc (psize);
  if (!p)
    {
      vty_out (vty, "depth too long ...%s", VTY_NEWLINE);
      return;
    }

  restnum = listcount (v->path_list);
  for (node = listhead (v->path_list); node; nextnode (node))
    {
      --restnum;
      snprintf (p, psize, "%s%s", prefix, (current_rest ? "| " : "  "));
      ospf6_spftree_show (vty, p, restnum,
                          (struct ospf6_vertex *) getdata (node));
    }

  free (p);
}

DEFUN (show_ipv6_ospf6_area_spf_tree,
       show_ipv6_ospf6_area_spf_tree_cmd,
       "show ipv6 ospf6 area A.B.C.D spf tree",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       "Shortest Path First caculation\n"
       "Displays spf tree\n")
{
  u_int32_t area_id;
  struct ospf6_area *o6a;

  OSPF6_CMD_CHECK_RUNNING ();

  inet_pton (AF_INET, argv[0], &area_id);
  o6a = ospf6_area_lookup (area_id, ospf6);
  if (! o6a)
    return CMD_SUCCESS;

  vty_out (vty, "%s        SPF tree for Area %s%s%s",
           VTY_NEWLINE, o6a->str, VTY_NEWLINE, VTY_NEWLINE);

  if (! o6a->spf_tree->root)
    return CMD_SUCCESS;

  ospf6_spftree_show (vty, "", 0, o6a->spf_tree->root);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_area_topology,
       show_ipv6_ospf6_area_topology_cmd,
       "show ipv6 ospf6 area A.B.C.D topology",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       OSPF6_SPF_STR
       "Displays SPF topology table\n")
{
  struct ospf6_area *o6a;
  u_int32_t area_id;

  OSPF6_CMD_CHECK_RUNNING ();

  inet_pton (AF_INET, argv[0], &area_id);
  o6a = ospf6_area_lookup (area_id, ospf6);

  if (! o6a)
    return CMD_SUCCESS;

  argc -= 1;
  argv += 1;

  return ospf6_route_table_show (vty, argc, argv, o6a->table_topology);
}

ALIAS (show_ipv6_ospf6_area_topology,
       show_ipv6_ospf6_area_topology_router_cmd,
       "show ipv6 ospf6 area A.B.C.D topology (A.B.C.D|<0-4294967295>|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       OSPF6_SPF_STR
       "Displays SPF topology table\n"
       OSPF6_ROUTER_ID_STR
       OSPF6_ROUTER_ID_STR
       )

ALIAS (show_ipv6_ospf6_area_topology,
       show_ipv6_ospf6_area_topology_router_lsid_cmd,
       "show ipv6 ospf6 area A.B.C.D topology (A.B.C.D|<0-4294967295>) (A.B.C.D|<0-4294967295>)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       OSPF6_AREA_STR
       OSPF6_AREA_ID_STR
       OSPF6_SPF_STR
       "Displays SPF topology table\n"
       OSPF6_ROUTER_ID_STR
       OSPF6_ROUTER_ID_STR
       OSPF6_LS_ID_STR
       OSPF6_LS_ID_STR
       )

void
ospf6_spf_init ()
{
  nexthop_list = linklist_create ();
  ospf6_spf_candidate_init ();
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_spf_node_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_topology_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_topology_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_area_topology_router_lsid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_spf_node_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_topology_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_topology_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_area_topology_router_lsid_cmd);
}

