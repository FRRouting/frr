/*
 * Copyright (C) 2001-2002 Yasuhiro Ohara
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
#include "prefix.h"
#include "command.h"
#include "vty.h"
#include "routemap.h"
#include "table.h"
#include "plist.h"
#include "thread.h"

#include "ospf6_prefix.h"  /* xxx for ospf6_asbr.h */
#include "ospf6_lsa.h"     /* xxx for ospf6_asbr.h */
#include "ospf6_route.h"   /* xxx for ospf6_asbr.h, ospf6_zebra.h */
#include "ospf6_zebra.h"
#include "ospf6_asbr.h"
#include "ospf6_damp.h"
#include "ospf6_top.h"
#include "ospf6_lsdb.h"
#include "ospf6_proto.h"

extern struct thread_master *master;

struct route_table *external_table;
struct
{
  char *name;
  struct route_map *map;
} rmap [ZEBRA_ROUTE_MAX];

static u_int32_t link_state_id = 0;

char *
zroute_name[] =
{ 
  "system", "kernel", "connected", "static",
  "rip", "ripng", "ospf", "ospf6", "isis", "bgp", "unknown"
};
char *
zroute_abname[] =
{
  "X", "K", "C", "S", "R", "R", "O", "O", "I", "B", "?"
};

#define ZROUTE_NAME(x) \
  (0 < (x) && (x) < ZEBRA_ROUTE_MAX ? \
   zroute_name[(x)] : zroute_name[ZEBRA_ROUTE_MAX])

#define ZROUTE_ABNAME(x) \
  (0 < (x) && (x) < ZEBRA_ROUTE_MAX ? \
   zroute_abname[(x)] : zroute_abname[ZEBRA_ROUTE_MAX])

/* redistribute function */
void
ospf6_asbr_routemap_set (int type, char *mapname)
{
  if (rmap[type].name)
    free (rmap[type].name);

  rmap[type].name = strdup (mapname);
  rmap[type].map = route_map_lookup_by_name (mapname);
}

void
ospf6_asbr_routemap_unset (int type)
{
  if (rmap[type].name)
    free (rmap[type].name);
  rmap[type].name = NULL;
  rmap[type].map = NULL;
}

void
ospf6_asbr_routemap_update ()
{
  int i;
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if (rmap[i].name)
        rmap[i].map = route_map_lookup_by_name (rmap[i].name);
      else
        rmap[i].map = NULL;
    }
}

DEFUN (ospf6_redistribute,
       ospf6_redistribute_cmd,
       "redistribute (static|kernel|connected|ripng|bgp)",
       "Redistribute\n"
       "Static route\n"
       "Kernel route\n"
       "Connected route\n"
       "RIPng route\n"
       "BGP route\n"
      )
{
  int type = 0;

  if (strncmp (argv[0], "sta", 3) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "ker", 3) == 0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "con", 3) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "rip", 3) == 0)
    type = ZEBRA_ROUTE_RIPNG;
  else if (strncmp (argv[0], "bgp", 3) == 0)
    type = ZEBRA_ROUTE_BGP;

  ospf6_zebra_no_redistribute (type);
  ospf6_asbr_routemap_unset (type);
  ospf6_zebra_redistribute (type);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_routemap,
       ospf6_redistribute_routemap_cmd,
       "redistribute (static|kernel|connected|ripng|bgp) route-map WORD",
       "Redistribute\n"
       "Static routes\n"
       "Kernel route\n"
       "Connected route\n"
       "RIPng route\n"
       "BGP route\n"
       "Route map reference\n"
       "Route map name\n"
      )
{
  int type = 0;

  if (strncmp (argv[0], "sta", 3) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "ker", 3) == 0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "con", 3) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "rip", 3) == 0)
    type = ZEBRA_ROUTE_RIPNG;
  else if (strncmp (argv[0], "bgp", 3) == 0)
    type = ZEBRA_ROUTE_BGP;

  ospf6_zebra_no_redistribute (type);
  ospf6_asbr_routemap_set (type, argv[1]);
  ospf6_zebra_redistribute (type);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute,
       no_ospf6_redistribute_cmd,
       "no redistribute (static|kernel|connected|ripng|bgp)",
       NO_STR
       "Redistribute\n"
       "Static route\n"
       "Kernel route\n"
       "Connected route\n"
       "RIPng route\n"
       "BGP route\n"
      )
{
  int type = 0;
  struct route_node *node;
  struct ospf6_external_route *route;
  struct ospf6_external_info *info, *info_next = NULL;

  if (strncmp (argv[0], "sta", 3) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else if (strncmp (argv[0], "ker", 3) == 0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "con", 3) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "rip", 3) == 0)
    type = ZEBRA_ROUTE_RIPNG;
  else if (strncmp (argv[0], "bgp", 3) == 0)
    type = ZEBRA_ROUTE_BGP;

  ospf6_zebra_no_redistribute (type);
  ospf6_asbr_routemap_unset (type);

  /* remove redistributed route */
  for (node = route_top (external_table); node; node = route_next (node))
    {
      route = node->info;
      if (! route)
        continue;
      for (info = route->info_head; info; info = info_next)
        {
          info_next = info->next;
          if (info->type != type)
            continue;
          ospf6_asbr_route_remove (info->type, info->ifindex,
                                   &route->prefix);
        }
    }

  return CMD_SUCCESS;
}


int
ospf6_redistribute_config_write (struct vty *vty)
{
  int i;

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if (i == ZEBRA_ROUTE_OSPF6)
        continue;

      if (! ospf6_zebra_is_redistribute (i))
        continue;

      if (rmap[i].map)
        vty_out (vty, " redistribute %s route-map %s%s",
                 ZROUTE_NAME(i), rmap[i].name, VTY_NEWLINE);
      else
        vty_out (vty, " redistribute %s%s",
                 ZROUTE_NAME(i), VTY_NEWLINE);
    }

  return 0;
}

void
ospf6_redistribute_show_config (struct vty *vty)
{
  int i;

  if (! ospf6_zebra_is_redistribute(ZEBRA_ROUTE_SYSTEM) &&
      ! ospf6_zebra_is_redistribute(ZEBRA_ROUTE_KERNEL) &&
      ! ospf6_zebra_is_redistribute(ZEBRA_ROUTE_STATIC) &&
      ! ospf6_zebra_is_redistribute(ZEBRA_ROUTE_RIPNG) &&
      ! ospf6_zebra_is_redistribute(ZEBRA_ROUTE_BGP))
    return;

  vty_out (vty, " Redistributing External Routes from,%s", VTY_NEWLINE);
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
      if (i == ZEBRA_ROUTE_OSPF6)
        continue;
      if (! ospf6_zebra_is_redistribute (i))
        continue;

      if (rmap[i].map)
        vty_out (vty, "    %s with route-map %s%s",
                 ZROUTE_NAME(i), rmap[i].name, VTY_NEWLINE);
      else
        vty_out (vty, "    %s%s", ZROUTE_NAME(i), VTY_NEWLINE);
    }
}

/* AS External LSA origination */
int
ospf6_asbr_external_lsa_originate (struct thread *thread)
{
  struct ospf6_external_info *info;
  char buffer [MAXLSASIZE];
  struct ospf6_lsa_as_external *e;
  char *p;

  info = THREAD_ARG (thread);

  /* clear thread */
  info->thread_originate = NULL;

  if (info->is_removed)
    {
      if (IS_OSPF6_DUMP_ASBR)
        {
          char pbuf[64];
          prefix2str (&info->route->prefix, pbuf, sizeof (pbuf));
          zlog_info ("ASBR: quit redistribution %s: state is down",
                     pbuf);
        }
      return 0;
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  e = (struct ospf6_lsa_as_external *) buffer;
  p = (char *) (e + 1);

  if (info->metric_type == 2)
    SET_FLAG (e->bits_metric, OSPF6_ASBR_BIT_E);   /* type2 */
  else
    UNSET_FLAG (e->bits_metric, OSPF6_ASBR_BIT_E); /* type1, default */

  /* forwarding address */
  if (! IN6_IS_ADDR_UNSPECIFIED (&info->forwarding))
    SET_FLAG (e->bits_metric, OSPF6_ASBR_BIT_F);
  else
    UNSET_FLAG (e->bits_metric, OSPF6_ASBR_BIT_F);

  /* external route tag */
  UNSET_FLAG (e->bits_metric, OSPF6_ASBR_BIT_T);

  /* set metric. note: related to E bit */
  OSPF6_ASBR_METRIC_SET (e, info->metric);

  /* prefixlen */
  e->prefix.prefix_length = info->route->prefix.prefixlen;

  /* PrefixOptions */
  e->prefix.prefix_options = info->prefix_options;

  /* don't use refer LS-type */
  e->prefix.prefix_refer_lstype = htons (0);

  /* set Prefix */
  memcpy (p, &info->route->prefix.u.prefix6,
          OSPF6_PREFIX_SPACE (info->route->prefix.prefixlen));
  ospf6_prefix_apply_mask (&e->prefix);
  p += OSPF6_PREFIX_SPACE (info->route->prefix.prefixlen);

  /* Forwarding address */
  if (CHECK_FLAG (e->bits_metric, OSPF6_ASBR_BIT_F))
    {
      memcpy (p, &info->forwarding, sizeof (struct in6_addr));
      p += sizeof (struct in6_addr);
    }

  /* External Route Tag */
  if (CHECK_FLAG (e->bits_metric, OSPF6_ASBR_BIT_T))
    {
      /* xxx */
    }

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_AS_EXTERNAL),
                       htonl (info->id), ospf6->router_id,
                       (char *) buffer, p - buffer, ospf6);
  return 0;
}

int
ospf6_asbr_schedule_external (void *data)
{
  struct ospf6_external_info *info = data;
  u_long elasped_time, time = 0;

  if (info->thread_originate)
    {
      if (IS_OSPF6_DUMP_ASBR)
        {
          char pbuf[64];
          prefix2str (&info->route->prefix, pbuf, sizeof (pbuf));
          zlog_info ("ASBR: schedule redistribution %s: another thread",
                     pbuf);
        }
      return 0;
    }

  elasped_time =
    ospf6_lsa_has_elasped (htons (OSPF6_LSA_TYPE_AS_EXTERNAL),
                           htonl (info->id), ospf6->router_id, ospf6);
  if (elasped_time < OSPF6_MIN_LS_INTERVAL)
    time = OSPF6_MIN_LS_INTERVAL - elasped_time;
  else
    time = 0;

  //if (IS_OSPF6_DUMP_ASBR)
    {
      char pbuf[64];
      prefix2str (&info->route->prefix, pbuf, sizeof (pbuf));
      zlog_info ("ASBR: schedule redistribution %s as LS-ID %ld after %lu sec",
                 pbuf, (u_long) info->id, time);
    }

  if (time)
    info->thread_originate =
      thread_add_timer (master, ospf6_asbr_external_lsa_originate, info, time);
  else
    info->thread_originate =
      thread_add_timer (master, ospf6_asbr_external_lsa_originate, info, 0);

  return 0;
}

int
ospf6_asbr_external_lsa_flush (void *data)
{
  struct ospf6_lsa *lsa = data;
  if (lsa)
    ospf6_lsa_premature_aging (lsa);
  return 0;
}

int
ospf6_asbr_external_lsa_refresh (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_lsa_as_external *e;
  struct prefix prefix;
  struct route_node *node;
  struct ospf6_external_route *route = NULL;
  struct ospf6_external_info *info = NULL;
  struct ospf6_external_info *match = NULL;

  if (IS_OSPF6_DUMP_ASBR)
    zlog_info ("ASBR: refresh %s", lsa->str);

  e = (struct ospf6_lsa_as_external *) (lsa->header + 1);
  ospf6_prefix_in6_addr (&e->prefix, &prefix.u.prefix6);
  prefix.prefixlen = e->prefix.prefix_length;
  prefix.family = AF_INET6;
  apply_mask_ipv6 ((struct prefix_ipv6 *) &prefix);

  for (node = route_top (external_table); node; node = route_next (node))
    {
      route = node->info;
      if (route == NULL)
        continue;

      for (info = route->info_head; info; info = info->next)
        {
          if (lsa->header->id == htonl (info->id))
            match = info;
        }
    }

  if (match == NULL)
    {
      ospf6_lsa_premature_aging (lsa);
      return 0;
    }

  ospf6_asbr_schedule_external (match);
  return 0;

#if 0
  node = route_node_lookup (external_table, &prefix);
  if (! node || ! node->info)
    {
      char pname[64];

      prefix2str (&prefix, pname, sizeof (pname));
      if (IS_OSPF6_DUMP_ASBR)
        zlog_info ("ASBR: could not find %s: premature age", pname);
      ospf6_lsa_premature_aging (lsa);
      return 0;
    }

  /* find external_info */
  route = node->info;
  for (info = route->info_head; info; info = info->next)
    {
      if (lsa->header->id == htonl (info->id))
        break;
    }

  if (info)
    ospf6_asbr_schedule_external (info);
  else
    ospf6_lsa_premature_aging (lsa);

  return 0;
#endif
}

void
ospf6_asbr_route_add (int type, int ifindex, struct prefix *prefix,
                      u_int nexthop_num, struct in6_addr *nexthop)
{
  int ret;
  struct route_node *node;
  struct ospf6_external_route *route;
  struct ospf6_external_info *info, tinfo;

#if defined (MUSICA) || defined (LINUX)
  /* XXX As long as the OSPFv3 redistribution is applied to all the connected
   *     routes, one needs to filter the ::/96 prefixes.
   *     However it could be a wanted case, it will be removed soon.
   */
  struct prefix_ipv6 *p = (prefix_ipv6 *)prefix;

  if ((IN6_IS_ADDR_V4COMPAT(&p->prefix)) ||
      (IN6_IS_ADDR_UNSPECIFIED (&p->prefix) && (p->prefixlen == 96))) 
    return;
#endif /* MUSICA or LINUX */

  if (! ospf6_zebra_is_redistribute (type))
    return;

  /* apply route-map */
  memset (&tinfo, 0, sizeof (struct ospf6_external_info));
  if (rmap[type].map)
    {
      ret = route_map_apply (rmap[type].map, prefix, RMAP_OSPF6, &tinfo);
      if (ret == RMAP_DENYMATCH)
        {
          if (IS_OSPF6_DUMP_ASBR)
            zlog_info ("ASBR: denied by route-map %s", rmap[type].name);
          return;
        }
    }

  node = route_node_get (external_table, prefix);
  route = node->info;

  if (! route)
    {
      route = XMALLOC (MTYPE_OSPF6_EXTERNAL_INFO,
                       sizeof (struct ospf6_external_route));
      memset (route, 0, sizeof (struct ospf6_external_route));

      memcpy (&route->prefix, prefix, sizeof (struct prefix));

      node->info = route;
      route->node = node;
    }

  for (info = route->info_head; info; info = info->next)
    {
      if (info->type == type && info->ifindex == ifindex)
        break;
    }

  if (! info)
    {
      info = XMALLOC (MTYPE_OSPF6_EXTERNAL_INFO,
                      sizeof (struct ospf6_external_info));
      memset (info, 0, sizeof (struct ospf6_external_info));

      info->route = route;
      /* add tail */
      info->prev = route->info_tail;
      if (route->info_tail)
        route->info_tail->next = info;
      else
        route->info_head = info;
      route->info_tail = info;

      info->id = link_state_id++;
    }

  /* copy result of route-map */
  info->metric_type = tinfo.metric_type;
  info->metric = tinfo.metric;
  memcpy (&info->forwarding, &tinfo.forwarding,
          sizeof (struct in6_addr));

  info->type = type;
  info->ifindex = ifindex;

  if (nexthop_num && nexthop)
    {
      info->nexthop_num = nexthop_num;

      if (info->nexthop)
        XFREE (MTYPE_OSPF6_EXTERNAL_INFO, info->nexthop);

      info->nexthop = (struct in6_addr *)
        XMALLOC (MTYPE_OSPF6_EXTERNAL_INFO,
                 nexthop_num * sizeof (struct in6_addr));
      memcpy (info->nexthop, nexthop,
              nexthop_num * sizeof (struct in6_addr));
    }

  info->is_removed = 0;

  //if (IS_OSPF6_DUMP_ASBR)
    {
      char pbuf[64];
      struct timeval now;
      prefix2str (&info->route->prefix, pbuf, sizeof (pbuf));
      gettimeofday (&now, NULL);
      zlog_info ("ASBR: start redistributing %s as LS-ID %ld: %ld.%06ld",
                 pbuf, (u_long) info->id, now.tv_sec, now.tv_usec);
    }

#ifdef HAVE_OSPF6_DAMP
  ospf6_damp_event_up (OSPF6_DAMP_TYPE_ROUTE, prefix,
                       ospf6_asbr_schedule_external, info);
#else /*HAVE_OSPF6_DAMP*/
  ospf6_asbr_schedule_external (info);
#endif /*HAVE_OSPF6_DAMP*/
}

void
ospf6_asbr_route_remove (int type, int ifindex, struct prefix *prefix)
{
  struct route_node *node;
  struct ospf6_external_route *route;
  struct ospf6_external_info *info;
  struct ospf6_lsa *lsa;

#if defined (MUSICA) || defined (LINUX)
  /* XXX As long as the OSPFv3 redistribution is applied to all the connected
   *     routes, one needs to filter the ::/96 prefixes.
   *     However it could be a wanted case, it will be removed soon.
   */
  struct prefix_ipv6 *p = (prefix_ipv6 *)prefix;

  if ((IN6_IS_ADDR_V4COMPAT(&p->prefix)) ||
      (IN6_IS_ADDR_UNSPECIFIED (&p->prefix) && (p->prefixlen == 96))) 
    return;
#endif /* MUSICA or LINUX */

  node = route_node_get (external_table, prefix);
  route = node->info;

  if (! route)
    return;

  for (info = route->info_head; info; info = info->next)
    {
      if (info->type == type && info->ifindex == ifindex)
        break;
    }

  if (! info)
    return;

  //if (IS_OSPF6_DUMP_ASBR)
    {
      char pbuf[64];
      struct timeval now;
      prefix2str (&info->route->prefix, pbuf, sizeof (pbuf));
      gettimeofday (&now, NULL);
      zlog_info ("ASBR: quit redistributing %s as LS-ID %ld: %ld.%06ld",
                 pbuf, (u_long) info->id, now.tv_sec, now.tv_usec);
    }

  if (info->thread_originate)
    thread_cancel (info->thread_originate);
  info->thread_originate = NULL;

  lsa = ospf6_lsdb_lookup (htons (OSPF6_LSA_TYPE_AS_EXTERNAL),
                           htonl (info->id), ospf6->router_id, ospf6);
#ifdef HAVE_OSPF6_DAMP
  ospf6_damp_event_down (OSPF6_DAMP_TYPE_ROUTE, &info->route->prefix,
                         ospf6_asbr_external_lsa_flush, lsa);
#else /*HAVE_OSPF6_DAMP*/
  ospf6_asbr_external_lsa_flush (lsa);
#endif /*HAVE_OSPF6_DAMP*/

#if 1
  info->is_removed = 1;
#else
  /* remove from route */
  if (info->prev)
    info->prev->next = info->next;
  else
    info->route->info_head = info->next;
  if (info->next)
    info->next->prev = info->prev;
  else
    info->route->info_tail = info->prev;

  /* if no info, free route */
  if (! info->route->info_head && ! info->route->info_tail)
    {
      info->route->node->info = NULL;
      free (info->route);
    }

  if (info->nexthop)
    free (info->nexthop);
  free (info);
#endif /*0*/
}

void
ospf6_asbr_external_lsa_add (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa_as_external *external;
  struct prefix_ls asbr_id;
  struct ospf6_route_req asbr_entry;
  struct ospf6_route_req request;

  external = OSPF6_LSA_HEADER_END (lsa->header);

  if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_OSPF6_DUMP_ASBR)
        zlog_info ("ASBR: maxage external lsa: %s seq: %lx",
                   lsa->str, (u_long)ntohl (lsa->header->seqnum));
      ospf6_asbr_external_lsa_remove (lsa);
      return;
    }

  if (IS_OSPF6_DUMP_ASBR)
    zlog_info ("ASBR: new external lsa: %s seq: %lx",
               lsa->str, (u_long)ntohl (lsa->header->seqnum));

  if (lsa->header->adv_router == ospf6->router_id)
    {
      if (IS_OSPF6_DUMP_ASBR)
        zlog_info ("ASBR: my external LSA, ignore");
      return;
    }

  if (OSPF6_ASBR_METRIC (external) == LS_INFINITY)
    {
      if (IS_OSPF6_DUMP_ASBR)
        zlog_info ("ASBR: metric is infinity, ignore");
      return;
    }

  memset (&asbr_id, 0, sizeof (asbr_id));
  asbr_id.family = AF_UNSPEC;
  asbr_id.prefixlen = 64; /* xxx */
  asbr_id.adv_router.s_addr = lsa->header->adv_router;

  ospf6_route_lookup (&asbr_entry, (struct prefix *) &asbr_id,
                      ospf6->topology_table);

  if (ospf6_route_end (&asbr_entry))
    {
      if (IS_OSPF6_DUMP_ASBR)
        {
          char buf[64];
          inet_ntop (AF_INET, &asbr_id.adv_router, buf, sizeof (buf));
          zlog_info ("ASBR: router %s not found, ignore", buf);
        }
      return;
    }

  memset (&request, 0, sizeof (request));
  request.route.type = OSPF6_DEST_TYPE_NETWORK;
  request.route.prefix.family = AF_INET6;
  request.route.prefix.prefixlen = external->prefix.prefix_length;
  memcpy (&request.route.prefix.u.prefix6, (char *)(external + 1),
          OSPF6_PREFIX_SPACE (request.route.prefix.prefixlen));

  request.path.area_id = asbr_entry.path.area_id;
  request.path.origin.type = htons (OSPF6_LSA_TYPE_AS_EXTERNAL);
  request.path.origin.id = lsa->header->id;
  request.path.origin.adv_router = lsa->header->adv_router;
  if (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_E))
    {
      request.path.type = OSPF6_PATH_TYPE_EXTERNAL2;
      request.path.metric_type = 2;
      request.path.cost = asbr_entry.path.cost;
      request.path.cost_e2 = OSPF6_ASBR_METRIC (external);
    }
  else
    {
      request.path.type = OSPF6_PATH_TYPE_EXTERNAL1;
      request.path.metric_type = 1;
      request.path.cost = asbr_entry.path.cost
                          + OSPF6_ASBR_METRIC (external);
      request.path.cost_e2 = 0;
    }
  request.path.prefix_options = external->prefix.prefix_options;

  while (((struct prefix_ls *)&asbr_entry.route.prefix)->adv_router.s_addr ==
         asbr_id.adv_router.s_addr &&
         asbr_entry.route.type == OSPF6_DEST_TYPE_ROUTER)
    {
      memcpy (&request.nexthop, &asbr_entry.nexthop,
              sizeof (struct ospf6_nexthop));
      if (IS_OSPF6_DUMP_ASBR)
        {
          char buf[64], nhop[64], ifname[IFNAMSIZ];
          prefix2str (&request.route.prefix, buf, sizeof (buf));
          inet_ntop (AF_INET6, &request.nexthop.address, nhop, sizeof (nhop));
          if_indextoname (request.nexthop.ifindex, ifname);
          zlog_info ("ASBR: add route: %s %s%%%s", buf, nhop, ifname);
        }
      ospf6_route_add (&request, ospf6->route_table);
      ospf6_route_next (&asbr_entry);
    }
}

void
ospf6_asbr_external_lsa_remove (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa_as_external *external;
  struct prefix dest;
  char buf[64];
  struct ospf6_route_req request;

  if (IS_OSPF6_DUMP_ASBR)
    zlog_info ("ASBR: withdraw external lsa: %s seq: %lx",
               lsa->str, (u_long)ntohl (lsa->header->seqnum));

  if (lsa->header->adv_router == ospf6->router_id)
    {
      if (IS_OSPF6_DUMP_ASBR)
        zlog_info ("ASBR: my external LSA, ignore");
      return;
    }

  external = OSPF6_LSA_HEADER_END (lsa->header);
  memset (&dest, 0, sizeof (dest));
  dest.family = AF_INET6;
  dest.prefixlen = external->prefix.prefix_length;
  memcpy (&dest.u.prefix6, (char *)(external + 1),
          OSPF6_PREFIX_SPACE (dest.prefixlen));

  ospf6_route_lookup (&request, &dest, ospf6->route_table);
  if (ospf6_route_end (&request))
    {
      if (IS_OSPF6_DUMP_ASBR)
        {
          prefix2str (&dest, buf, sizeof (buf));
          zlog_info ("ASBR: %s not found", buf);
        }
      return;
    }

  while (request.path.origin.id != lsa->header->id ||
         request.path.origin.adv_router != lsa->header->adv_router)
    {
      if (prefix_same (&request.route.prefix, &dest) != 1)
        {
          if (IS_OSPF6_DUMP_ASBR)
            zlog_info ("ASBR:   Can't find the entry matches the origin");
          return;
        }
      ospf6_route_next (&request);
    }
  assert (request.path.origin.id == lsa->header->id);
  assert (request.path.origin.adv_router == request.path.origin.adv_router);

  while (request.path.origin.id == lsa->header->id &&
         request.path.origin.adv_router == lsa->header->adv_router &&
         prefix_same (&request.route.prefix, &dest) == 1)
    {
      if (IS_OSPF6_DUMP_ASBR)
        {
          char nhop[64], ifname[IFNAMSIZ];
          prefix2str (&dest, buf, sizeof (buf));
          inet_ntop (AF_INET6, &request.nexthop.address, nhop, sizeof (nhop));
          if_indextoname (request.nexthop.ifindex, ifname);
          zlog_info ("ASBR: remove route: %s %s%%%s", buf, nhop, ifname);
        }

      ospf6_route_remove (&request, ospf6->route_table);
      ospf6_route_next (&request);
    }
}

void
ospf6_asbr_external_lsa_change (struct ospf6_lsa *old, struct ospf6_lsa *new)
{
  assert (old || new);

  if (old == NULL)
    ospf6_asbr_external_lsa_add (new);
  else if (new == NULL)
    ospf6_asbr_external_lsa_remove (old);
  else
    {
      ospf6_route_table_freeze (ospf6->route_table);
      ospf6_asbr_external_lsa_remove (old);
      ospf6_asbr_external_lsa_add (new);
      ospf6_route_table_thaw (ospf6->route_table);
    }
}

void
ospf6_asbr_asbr_entry_add (struct ospf6_route_req *topo_entry)
{
  struct ospf6_lsdb_node node;

  struct prefix_ls *inter_router;
  u_int32_t id, adv_router;

  inter_router = (struct prefix_ls *) &topo_entry->route.prefix;
  id = inter_router->id.s_addr;
  adv_router = inter_router->adv_router.s_addr;

  if (IS_OSPF6_DUMP_ASBR)
    {
      char buf[64];
      inet_ntop (AF_INET, &inter_router->adv_router, buf, sizeof (buf));
      zlog_info ("ASBR: new router found: %s", buf);
    }

  if (ntohl (id) != 0 ||
      ! OSPF6_OPT_ISSET (topo_entry->path.capability, OSPF6_OPT_E))
    {
      zlog_warn ("ASBR: Inter topology table malformed");
      return;
    }

  for (ospf6_lsdb_type_router (&node, htons (OSPF6_LSA_TYPE_AS_EXTERNAL),
                               adv_router, ospf6->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_asbr_external_lsa_add (node.lsa);
}

void
ospf6_asbr_asbr_entry_remove (struct ospf6_route_req *topo_entry)
{
  struct prefix_ls *inter_router;
  u_int32_t id, adv_router;
  struct ospf6_route_req request;

  inter_router = (struct prefix_ls *) &topo_entry->route.prefix;
  id = inter_router->id.s_addr;
  adv_router = inter_router->adv_router.s_addr;

  if (IS_OSPF6_DUMP_ASBR)
    {
      char buf[64];
      inet_ntop (AF_INET, &inter_router->adv_router, buf, sizeof (buf));
      zlog_info ("ASBR: router disappearing: %s", buf);
    }

  if (ntohl (id) != 0 ||
      ! OSPF6_OPT_ISSET (topo_entry->path.capability, OSPF6_OPT_E))
    {
      zlog_warn ("ASBR: Inter topology table malformed");
    }

  for (ospf6_route_head (&request, ospf6->route_table);
       ! ospf6_route_end (&request);
       ospf6_route_next (&request))
    {
      if (request.path.type != OSPF6_PATH_TYPE_EXTERNAL1 &&
          request.path.type != OSPF6_PATH_TYPE_EXTERNAL2)
        continue;
      if (request.path.area_id != topo_entry->path.area_id)
        continue;
      if (request.path.origin.adv_router != topo_entry->path.origin.adv_router)
        continue;
      if (memcmp (&topo_entry->nexthop, &request.nexthop,
                  sizeof (struct ospf6_nexthop)))
        continue;

      ospf6_route_remove (&request, ospf6->route_table);
    }
}

int
ospf6_asbr_external_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_lsa_as_external *external;
  char buf[128], *ptr;
  struct in6_addr in6;

  assert (lsa->header);
  external = (struct ospf6_lsa_as_external *)(lsa->header + 1);
  
  /* bits */
  snprintf (buf, sizeof (buf), "%s%s%s",
            (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_E) ?
             "E" : "-"),
            (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_F) ?
             "F" : "-"),
            (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_T) ?
             "T" : "-"));

  vty_out (vty, "     Bits: %s%s", buf, VTY_NEWLINE);
  vty_out (vty, "     Metric: %5lu%s", (u_long)OSPF6_ASBR_METRIC (external),
           VTY_NEWLINE);

  ospf6_prefix_options_str (external->prefix.prefix_options,
                            buf, sizeof (buf));
  vty_out (vty, "     Prefix Options: %s%s", buf, VTY_NEWLINE);

  vty_out (vty, "     Referenced LSType: %d%s",
           ntohs (external->prefix.prefix_refer_lstype), VTY_NEWLINE);

  ospf6_prefix_in6_addr (&external->prefix, &in6);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
  vty_out (vty, "     Prefix: %s/%d%s",
           buf, external->prefix.prefix_length, VTY_NEWLINE);

  /* Forwarding-Address */
  if (CHECK_FLAG (external->bits_metric, OSPF6_ASBR_BIT_F))
    {
      ptr = ((char *)(external + 1))
            + OSPF6_PREFIX_SPACE (external->prefix.prefix_length);
      inet_ntop (AF_INET6, (struct in6_addr *) ptr, buf, sizeof (buf));
      vty_out (vty, "     Forwarding-Address: %s%s", buf, VTY_NEWLINE);
    }

  return 0;
}

void
ospf6_asbr_database_hook (struct ospf6_lsa *old, struct ospf6_lsa *new)
{
  if (old)
    ospf6_asbr_external_lsa_remove (old);
  if (new && ! IS_LSA_MAXAGE (new))
    ospf6_asbr_external_lsa_add (new);
}

void
ospf6_asbr_register_as_external ()
{
  struct ospf6_lsa_slot slot;

  memset (&slot, 0, sizeof (slot));
  slot.type              = htons (OSPF6_LSA_TYPE_AS_EXTERNAL);
  slot.name              = "AS-External";
  slot.func_show         = ospf6_asbr_external_show;
  slot.func_refresh      = ospf6_asbr_external_lsa_refresh;
  ospf6_lsa_slot_register (&slot);

  ospf6_lsdb_hook[OSPF6_LSA_TYPE_AS_EXTERNAL & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_asbr_database_hook;
}

void
ospf6_asbr_external_info_show (struct vty *vty,
                               struct ospf6_external_info *info)
{
  char prefix_buf[64], id_buf[16];
  struct in_addr id;

  if (info->is_removed)
    return;

  id.s_addr = ntohl (info->id);
  inet_ntop (AF_INET, &id, id_buf, sizeof (id_buf));
  prefix2str (&info->route->prefix, prefix_buf, sizeof (prefix_buf));
  vty_out (vty, "%s %-32s %3d %-15s %3d %lu(type-%d)%s",
           ZROUTE_ABNAME(info->type), prefix_buf, info->ifindex, id_buf,
           info->nexthop_num, (u_long) info->metric, info->metric_type,
           VTY_NEWLINE);
}

void
ospf6_asbr_external_route_show (struct vty *vty,
                                struct ospf6_external_route *route)
{
  struct ospf6_external_info *info;
  for (info = route->info_head; info; info = info->next)
    ospf6_asbr_external_info_show (vty, info);
}

DEFUN (show_ipv6_route_ospf6_external,
       show_ipv6_route_ospf6_external_cmd,
       "show ipv6 ospf6 route redistribute",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "redistributing External information\n"
       )
{
  struct route_node *node;
  struct ospf6_external_route *route;

  vty_out (vty, "%s %-32s %3s %-15s %3s %s%s",
           " ", "Prefix", "I/F", "LS-Id", "#NH", "Metric",
           VTY_NEWLINE);
  for (node = route_top (external_table); node; node = route_next (node))
    {
      route = node->info;
      if (route)
        ospf6_asbr_external_route_show (vty, route);
    }
  return CMD_SUCCESS;
}

void
ospf6_asbr_init ()
{
  external_table = route_table_init ();
  link_state_id = 0;

  ospf6_asbr_register_as_external ();

  install_element (VIEW_NODE, &show_ipv6_route_ospf6_external_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_external_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_routemap_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_cmd);
}


