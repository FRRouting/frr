/*
 * Copyright (C) 2002 Yasuhiro Ohara
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

static int intra_index;
#define IS_OSPF6_DUMP_INTRA (ospf6_dump_is_on (intra_index))

#define ADD    0
#define REMOVE 1

static void
ospf6_intra_route_calculate (int type, struct ospf6_lsa *lsa,
                             struct ospf6_route_req *topo_entry)
{
  struct ospf6_intra_area_prefix_lsa *intra_prefix;
  char *start, *end;
  struct ospf6_prefix *ospf6_prefix;
  struct ospf6_route_req request;
  struct ospf6_area *area;

  if (IS_OSPF6_DUMP_INTRA)
    {
      char buf[64];
      struct prefix_ls *p_ls;
      p_ls = (struct prefix_ls *) &topo_entry->route.prefix;
      inet_ntop (AF_INET, &p_ls->adv_router, buf, sizeof (buf));
      zlog_info ("INTRA: Calculate [%s] %s and %s",
                 (type == ADD ? "add" : "remove"), lsa->str, buf);
    }

  intra_prefix = OSPF6_LSA_HEADER_END (lsa->header);

  area = lsa->scope;
  assert (area);

  start = (char *) (intra_prefix + 1);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (ospf6_prefix = (struct ospf6_prefix *) start;
       (char *) ospf6_prefix < end;
       ospf6_prefix = OSPF6_NEXT_PREFIX (ospf6_prefix))
    {
      memset (&request, 0, sizeof (request));

      request.route.type = OSPF6_DEST_TYPE_NETWORK;
      request.route.prefix.family = AF_INET6;
      request.route.prefix.prefixlen = ospf6_prefix->prefix_length;
      ospf6_prefix_in6_addr (ospf6_prefix, &request.route.prefix.u.prefix6);

      request.path.type = OSPF6_PATH_TYPE_INTRA;
      request.path.area_id = area->area_id;
      request.path.origin.type = lsa->header->type;
      request.path.origin.id = lsa->header->id;
      request.path.origin.adv_router = lsa->header->adv_router;
      request.path.cost = topo_entry->path.cost +
                          ntohs (ospf6_prefix->prefix_metric);
      request.path.capability[0] = topo_entry->path.capability[0];
      request.path.capability[1] = topo_entry->path.capability[1];
      request.path.capability[2] = topo_entry->path.capability[2];

      memcpy (&request.nexthop.address, &topo_entry->nexthop.address,
              sizeof (request.nexthop.address));
      request.nexthop.ifindex = topo_entry->nexthop.ifindex;

      if (type == ADD)
        ospf6_route_add (&request, area->route_table);
      else if (type == REMOVE)
        ospf6_route_remove (&request, area->route_table);
      else
        assert (0);
    }
}

int
ospf6_intra_prefix_database_hook_remove (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_area *area;
  struct ospf6_intra_area_prefix_lsa *iap;
  struct prefix_ls prefix_ls;
  struct ospf6_route_req topo_entry;

  if (lsa->header->type != htons (OSPF6_LSA_TYPE_INTRA_PREFIX))
    return 0;

  area = (struct ospf6_area *) lsa->scope;
  assert (area);

  if (IS_OSPF6_DUMP_INTRA)
    zlog_info ("INTRA: area %s remove: %s", area->str, lsa->str);

  iap = OSPF6_LSA_HEADER_END (lsa->header);
  memset (&prefix_ls, 0, sizeof (prefix_ls));
  prefix_ls.prefixlen = 64;
  prefix_ls.adv_router.s_addr = iap->refer_advrtr;
  prefix_ls.id.s_addr = iap->refer_lsid;

  if (iap->refer_lstype == htons (OSPF6_LSA_TYPE_ROUTER) &&
      iap->refer_lsid != htonl (0))
    {
      zlog_warn ("SPF: Malformed ID %lu of Router reference in %s",
                 (u_long) ntohl (iap->refer_lsid), lsa->str);
      prefix_ls.id.s_addr = htonl (0);
    }

  ospf6_route_lookup (&topo_entry, (struct prefix *) &prefix_ls,
                      area->table_topology);

  while (iap->refer_lstype == topo_entry.path.origin.type &&
         iap->refer_lsid == topo_entry.path.origin.id &&
         iap->refer_advrtr == topo_entry.path.origin.adv_router)
    {
      ospf6_intra_route_calculate (REMOVE, lsa, &topo_entry);
      ospf6_route_next (&topo_entry);
    }
  return 0;
}

int
ospf6_intra_prefix_database_hook_add (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_area *area;
  struct ospf6_intra_area_prefix_lsa *iap;
  struct prefix_ls prefix_ls;
  struct ospf6_route_req topo_entry;

  if (lsa->header->type != htons (OSPF6_LSA_TYPE_INTRA_PREFIX))
    return 0;

  area = (struct ospf6_area *) lsa->scope;
  assert (area);

  if (IS_LSA_MAXAGE (lsa))
    {
      ospf6_intra_prefix_database_hook_remove (lsa);
      return 0;
    }

  if (IS_OSPF6_DUMP_INTRA)
    zlog_info ("INTRA: area %s add: %s", area->str, lsa->str);

  iap = OSPF6_LSA_HEADER_END (lsa->header);

  memset (&prefix_ls, 0, sizeof (struct prefix_ls));
  prefix_ls.prefixlen = 64;
  prefix_ls.adv_router.s_addr = iap->refer_advrtr;
  prefix_ls.id.s_addr = iap->refer_lsid;

  if (iap->refer_lstype == htons (OSPF6_LSA_TYPE_ROUTER) &&
      iap->refer_lsid != htonl (0))
    {
      zlog_warn ("INTRA: Malformed ID %lu of Router reference in %s",
                 (u_long) ntohl (iap->refer_lsid), lsa->str);
      prefix_ls.id.s_addr = htonl (0);
    }

  ospf6_route_lookup (&topo_entry, (struct prefix *) &prefix_ls,
                      area->table_topology);

  while (iap->refer_lstype == topo_entry.path.origin.type &&
         iap->refer_lsid == topo_entry.path.origin.id &&
         iap->refer_advrtr == topo_entry.path.origin.adv_router)
    {
      ospf6_intra_route_calculate (ADD, lsa, &topo_entry);
      ospf6_route_next (&topo_entry);
    }
  return 0;
}

void
ospf6_intra_topology_add (void *data)
{
  struct ospf6_route_req *topo_entry = data;
  struct ospf6_area *area;
  struct ospf6_intra_area_prefix_lsa *iap;
  struct ospf6_lsdb_node node;

  area = ospf6_area_lookup (topo_entry->path.area_id, ospf6);
  if (! area)
    return;

  if (topo_entry->route.type == OSPF6_DEST_TYPE_ROUTER &&
      (CHECK_FLAG (topo_entry->path.router_bits, OSPF6_ROUTER_LSA_BIT_B) ||
       CHECK_FLAG (topo_entry->path.router_bits, OSPF6_ROUTER_LSA_BIT_E)))
    ospf6_route_add (topo_entry, ospf6->topology_table);

  for (ospf6_lsdb_type (&node, htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                        area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      if (IS_LSA_MAXAGE (node.lsa))
        continue;

      iap = OSPF6_LSA_HEADER_END (node.lsa->header);

      if (iap->refer_lstype == htons (OSPF6_LSA_TYPE_ROUTER) &&
          iap->refer_lsid != htonl (0))
        {
          zlog_warn ("INTRA: Malformed ID %lu of Router reference in %s",
                     (u_long) ntohl (iap->refer_lsid), node.lsa->str);
        }

      if (iap->refer_lstype != topo_entry->path.origin.type ||
          iap->refer_lsid != topo_entry->path.origin.id ||
          iap->refer_advrtr != topo_entry->path.origin.adv_router)
        continue;

      ospf6_intra_route_calculate (ADD, node.lsa, topo_entry);
    }
}

void
ospf6_intra_topology_remove (void *data)
{
  struct ospf6_route_req *topo_entry = data;
  struct ospf6_area *area;
  struct ospf6_intra_area_prefix_lsa *iap;
  struct ospf6_lsdb_node node;

  area = ospf6_area_lookup (topo_entry->path.area_id, ospf6);
  if (! area)
    return;

  if (topo_entry->route.type == OSPF6_DEST_TYPE_ROUTER &&
      (CHECK_FLAG (topo_entry->path.router_bits, OSPF6_ROUTER_LSA_BIT_B) ||
       CHECK_FLAG (topo_entry->path.router_bits, OSPF6_ROUTER_LSA_BIT_E)))
    ospf6_route_remove (topo_entry, ospf6->topology_table);

  for (ospf6_lsdb_type (&node, htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                        area->lsdb);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      if (IS_LSA_MAXAGE (node.lsa))
        continue;

      iap = OSPF6_LSA_HEADER_END (node.lsa->header);

      if (iap->refer_lstype == htons (OSPF6_LSA_TYPE_ROUTER) &&
          iap->refer_lsid != htonl (0))
        zlog_warn ("SPF: Malformed ID %lu of Router reference in %s",
                   (u_long) ntohl (iap->refer_lsid), node.lsa->str);

      if (iap->refer_lstype != topo_entry->path.origin.type ||
          iap->refer_lsid != topo_entry->path.origin.id ||
          iap->refer_advrtr != topo_entry->path.origin.adv_router)
        continue;

      ospf6_intra_route_calculate (REMOVE, node.lsa, topo_entry);
    }
}


/*****************************************/
/* RFC2740 3.4.3.7 Intra-Area-Prefix-LSA */
/*****************************************/

#define CONTINUE_IF_ADDRESS_LINKLOCAL(addr)\
  if (IN6_IS_ADDR_LINKLOCAL (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_PREFIX)\
        zlog_info ("  Filter out Linklocal: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_UNSPECIFIED(addr)\
  if (IN6_IS_ADDR_UNSPECIFIED (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_PREFIX)\
        zlog_info ("  Filter out Unspecified: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_LOOPBACK(addr)\
  if (IN6_IS_ADDR_LOOPBACK (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_PREFIX)\
        zlog_info ("  Filter out Loopback: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_V4COMPAT(addr)\
  if (IN6_IS_ADDR_V4COMPAT (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_PREFIX)\
        zlog_info ("  Filter out V4Compat: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_V4MAPPED(addr)\
  if (IN6_IS_ADDR_V4MAPPED (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_PREFIX)\
        zlog_info ("  Filter out V4Mapped: %s", buf);\
      continue;\
    }


int
ospf6_lsa_intra_prefix_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_intra_area_prefix_lsa *iap_lsa;
  struct ospf6_prefix *prefix;
  unsigned short prefixnum;
  char buf[128], type[32], id[32], adv_router[32];
  struct in6_addr in6;
  char *start, *end, *current;

  assert (lsa->header);
  iap_lsa = (struct ospf6_intra_area_prefix_lsa *) (lsa->header + 1);

  prefixnum = ntohs (iap_lsa->prefix_number);
  ospf6_lsa_type_string (iap_lsa->refer_lstype, type, sizeof (type));
  inet_ntop (AF_INET, &iap_lsa->refer_lsid, id, sizeof (id));
  inet_ntop (AF_INET, &iap_lsa->refer_advrtr, adv_router,
             sizeof (adv_router));

  vty_out (vty, "     Number of Prefix: %d%s", prefixnum, VTY_NEWLINE);
  vty_out (vty, "     Referenced LS Type: %s%s", type, VTY_NEWLINE);
  vty_out (vty, "     Referenced LS ID: %s%s", id, VTY_NEWLINE);
  vty_out (vty, "     Referenced Advertising Router: %s%s", adv_router,
           VTY_NEWLINE);

  start = (char *) lsa->header + sizeof (struct ospf6_lsa_header)
          + sizeof (struct ospf6_intra_area_prefix_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);

  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
      prefix = (struct ospf6_prefix *) current;
      if (current + OSPF6_PREFIX_SIZE (prefix) > end)
        {
          vty_out (vty, "    Trailing %d byte garbage ... Malformed%s",
                   end - current, VTY_NEWLINE);
          return -1;
        }

      ospf6_prefix_options_str (prefix->prefix_options, buf, sizeof (buf));
      vty_out (vty, "     Prefix Options: %s%s", buf, VTY_NEWLINE);

      ospf6_prefix_in6_addr (prefix, &in6);
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      vty_out (vty, "     Prefix: %s/%d%s",
               buf, prefix->prefix_length, VTY_NEWLINE);
    }

  return 0;
}

void
ospf6_lsa_intra_prefix_update_transit (char *ifname)
{
  char buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_lsa *old;
  struct interface *ifp;
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n;

  struct ospf6_intra_area_prefix_lsa *iap;
  struct ospf6_lsdb_node n;
  listnode node;
  char *start, *end, *current;
  struct ospf6_prefix *prefix, *dup, *src, *dst;
  struct ospf6_link_lsa *link;
  char buf[128];
  int count, prefix_num;

  list adv_list;

  ifp = if_lookup_by_name (ifname);
  if (! ifp)
    {
      zlog_warn ("Update Intra-Prefix (Transit): No such Interface: %s",
                  ifname);
      return;
    }

  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i || ! o6i->area)
    {
      zlog_warn ("Update Intra-Prefix (Transit): Interface not enabled: %s",
                  ifname);
      return;
    }

  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                           htonl (o6i->if_id), ospf6->router_id,
                           o6i->area);

  /* Don't originate Network-LSA if not DR */
  if (o6i->state != IFS_DR)
    {
      if (old)
        {
          if (IS_OSPF6_DUMP_PREFIX)
            zlog_info ("Update Intra-Prefix (Transit): %s not DR",
                       o6i->interface->name);
          ospf6_lsa_premature_aging (old);
        }
      return;
    }

  /* If none of neighbor is adjacent to us */
  count = 0;
  o6i->foreach_nei (o6i, &count, NBS_FULL, ospf6_count_state);
  if (count == 0)
    {
      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("Update Intra-Prefix (Transit): %s is Stub",
                   o6i->interface->name);
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  if (IS_OSPF6_DUMP_PREFIX)
    zlog_info ("Update Intra-Prefix (Transit): Interface %s",
               o6i->interface->name);

  adv_list = list_new ();

  /* foreach Link-LSA associated with this Link */
  for (ospf6_lsdb_type (&n, htons (OSPF6_LSA_TYPE_LINK), o6i->lsdb);
       ! ospf6_lsdb_is_end (&n); ospf6_lsdb_next (&n))
    {
      if (IS_LSA_MAXAGE (n.lsa))
        continue;

      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("Update Intra-Prefix (Transit): Checking %s",
                    n.lsa->str);

      /* Check status of the advertising router */
      if (n.lsa->header->adv_router != o6i->area->ospf6->router_id)
        {
          o6n = ospf6_neighbor_lookup (n.lsa->header->adv_router, o6i);
          if (! o6n)
            {
              if (IS_OSPF6_DUMP_PREFIX)
                zlog_info ("Update Intra-Prefix (Transit): neighbor not found");
              continue;
            }

          if (o6n->state != NBS_FULL)
            {
              if (IS_OSPF6_DUMP_PREFIX)
                zlog_info ("Update Intra-Prefix (Transit): %s not FULL",
                           o6n->str);
              continue;
            }
        }

      /* For each Prefix in this Link-LSA */
      link = (struct ospf6_link_lsa *) (n.lsa->header + 1);
      prefix_num = ntohl (link->llsa_prefix_num);

      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("  Prefix #%d", prefix_num);

      start = (char *) (link + 1);
      end = (char *) (n.lsa->header) + ntohs (n.lsa->header->length);
      prefix = (struct ospf6_prefix *) start;
      for (current = start; current < end;
           current += OSPF6_PREFIX_SIZE (prefix))
        {
          prefix = (struct ospf6_prefix *) current;
          ospf6_prefix_string (prefix, buf, sizeof (buf));

          /* Check duplicate prefix */
          dup = ospf6_prefix_lookup (adv_list, prefix);
          if (dup)
            {
              if (IS_OSPF6_DUMP_PREFIX)
                zlog_info ("  Duplicate %s", buf);
              dup->prefix_options |= prefix->prefix_options;
              continue;
            }

          if (prefix_num <= 0)
            {
              zlog_warn ("  Wong prefix number ...");
              break;
            }

          if (IS_OSPF6_DUMP_PREFIX)
            zlog_info ("  Prefix %s", buf);

          /* copy prefix to advertise list */
          ospf6_prefix_add (adv_list, prefix);

          prefix_num --;
        }
    }

  /* if no prefix to advertise, return */
  if (listcount (adv_list) == 0)
    {
      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("  No Prefix to advertise");
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  size = sizeof (struct ospf6_intra_area_prefix_lsa);
  iap = (struct ospf6_intra_area_prefix_lsa *) buffer;

  /* Set Referenced LSA field */
  iap->refer_lstype = htons (OSPF6_LSA_TYPE_NETWORK);
  iap->refer_lsid = htonl (o6i->if_id);
  iap->refer_advrtr = o6i->area->ospf6->router_id;

  dst = (struct ospf6_prefix *) (iap + 1);
  for (node = listhead (adv_list); node; nextnode (node))
    {
      src = (struct ospf6_prefix *) getdata (node);

      memcpy (dst, src, OSPF6_PREFIX_SIZE (src));

      size += OSPF6_PREFIX_SIZE (dst);
      dst = OSPF6_NEXT_PREFIX (dst);
    }
  iap->prefix_number = htons (listcount (adv_list));

  while ((node = listhead (adv_list)) != NULL)
    {
      prefix = getdata (node);
      ospf6_prefix_delete (prefix);
      listnode_delete (adv_list, prefix);
    }
  list_delete (adv_list);

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                       htonl (o6i->if_id), ospf6->router_id,
                       buffer, size, o6i->area);
}

void
ospf6_lsa_intra_prefix_update_stub (u_int32_t area_id)
{
  char buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_lsa *old;
  struct ospf6_area *o6a;
  int count;

  struct ospf6_intra_area_prefix_lsa *iap;
  listnode i,j;
  struct ospf6_interface *o6i = NULL;
  struct ospf6_prefix *prefix, *dst, *src;
  struct connected *c;
  char buf[128];

  list adv_list;
  listnode node;
  char prefix_buf[sizeof (struct ospf6_prefix) + sizeof (struct in6_addr)];

  o6a = ospf6_area_lookup (area_id, ospf6);
  if (! o6a)
    {
      char tmp[16];
      inet_ntop (AF_INET, &area_id, tmp, sizeof (tmp));
      zlog_warn ("Update Intra-Prefix (Stub): No such area: %s", tmp);
      return;
    }
  else if (IS_OSPF6_DUMP_PREFIX)
    {
      zlog_info ("Update Intra-Prefix (Stub): area: %s", o6a->str);
    }

  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                           htonl (0), ospf6->router_id,
                           o6a); /* xxx, ls-id */

  adv_list = list_new ();

  /* Examin for each interface */
  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);

      if (o6i->state == IFS_DOWN)
        {
          if (IS_OSPF6_DUMP_PREFIX)
            zlog_info ("    Interface %s: down", o6i->interface->name);
          continue;
        }

      count = 0;
      o6i->foreach_nei (o6i, &count, NBS_FULL, ospf6_count_state);
      if (o6i->state != IFS_LOOPBACK && o6i->state != IFS_PTOP &&
          count != 0)
        {
          /* This interface's prefix will be included in DR's */
          if (IS_OSPF6_DUMP_PREFIX)
            zlog_info ("    Interface %s: not stub", o6i->interface->name);
          continue;
        }

      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("    Interface %s:", o6i->interface->name);

      /* copy foreach address prefix */
      for (j = listhead (o6i->interface->connected); j; nextnode (j))
        {
          c = (struct connected *) getdata (j);

          /* filter prefix not IPv6 */
          if (c->address->family != AF_INET6)
            continue;

          /* for log */
          prefix2str (c->address, buf, sizeof (buf));

          CONTINUE_IF_ADDRESS_LINKLOCAL (c->address);
          CONTINUE_IF_ADDRESS_UNSPECIFIED (c->address);
          CONTINUE_IF_ADDRESS_LOOPBACK (c->address);
          CONTINUE_IF_ADDRESS_V4COMPAT (c->address);
          CONTINUE_IF_ADDRESS_V4MAPPED (c->address);

          /* filter prefix specified by configuration */
          if (o6i->plist_name)
            {
              struct prefix_list *plist;
              enum prefix_list_type result = PREFIX_PERMIT;

              plist = prefix_list_lookup (AFI_IP6, o6i->plist_name);
              if (plist)
                result = prefix_list_apply (plist, c->address);
              else
                zlog_warn ("Update Intra-Prefix (Stub): "
                           "Prefix list \"%s\" not found",
                           o6i->plist_name);

              if (result == PREFIX_DENY)
                {
                  if (IS_OSPF6_DUMP_PREFIX)
                    zlog_info ("    %s: Filtered by %s",
                               buf, o6i->plist_name);
                  continue;
                }
            }

          /* initialize buffer for ospf6 prefix */
          memset (prefix_buf, 0, sizeof (prefix_buf));
          prefix = (struct ospf6_prefix *) prefix_buf;

          /* set ospf6 prefix according to its state */
          /* xxx, virtual links */
          if (! CHECK_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_FORCE_PREFIX) &&
              (o6i->state == IFS_LOOPBACK || o6i->state == IFS_PTOP
              /* xxx, PoinToMultiPoint I/F type */ ))
            {
              prefix->prefix_length = 128;
              prefix->prefix_options = OSPF6_PREFIX_OPTION_LA;
              prefix->prefix_metric = htons (0);
              memcpy (prefix + 1, &c->address->u.prefix6,
                      OSPF6_PREFIX_SPACE (prefix->prefix_length));
            }
          else
            {
              struct prefix_ipv6 prefix_ipv6;
              /* apply mask */
              prefix_copy ((struct prefix *) &prefix_ipv6, c->address);
              apply_mask_ipv6 (&prefix_ipv6);

              prefix->prefix_length = prefix_ipv6.prefixlen;
              prefix->prefix_options = 0;  /* xxx, no options yet */
              prefix->prefix_metric = htons (o6i->cost);
              memcpy (prefix + 1, &prefix_ipv6.prefix,
                      OSPF6_PREFIX_SPACE (prefix->prefix_length));
            }

          ospf6_prefix_string (prefix, buf, sizeof (buf));
          if (IS_OSPF6_DUMP_PREFIX)
            zlog_info ("    Advertise %s", buf);

          /* check in the prefix to advertising prefix list */
          ospf6_prefix_add (adv_list, prefix);
        }
    }

  /* If no prefix to advertise */
  if (listcount (adv_list) == 0)
    {
      if (IS_OSPF6_DUMP_PREFIX)
        zlog_info ("    No prefix to advertise");
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  size = sizeof (struct ospf6_intra_area_prefix_lsa);
  iap = (struct ospf6_intra_area_prefix_lsa *) buffer;

  /* Set Referenced LSA field */
  iap->refer_lstype = htons (OSPF6_LSA_TYPE_ROUTER);
  iap->refer_lsid = htonl (0);
  iap->refer_advrtr = o6a->ospf6->router_id;

  dst = (struct ospf6_prefix *) (iap + 1);
  for (node = listhead (adv_list); node; nextnode (node))
    {
      src = (struct ospf6_prefix *) getdata (node);

      memcpy (dst, src, OSPF6_PREFIX_SIZE (src));

      size += OSPF6_PREFIX_SIZE (dst);
      dst = OSPF6_NEXT_PREFIX (dst);
    }
  iap->prefix_number = htons (listcount (adv_list));

  while ((node = listhead (adv_list)) != NULL)
    {
      prefix = getdata (node);
      ospf6_prefix_delete (prefix);
      listnode_delete (adv_list, prefix);
    }
  list_delete (adv_list);

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_INTRA_PREFIX),
                       htonl (0) /* xxx */, ospf6->router_id,
                       buffer, size, o6a);
}

int
ospf6_lsa_intra_prefix_hook_interface (void *interface)
{
  struct ospf6_interface *o6i = interface;
  if (o6i->area)
    {
      ospf6_lsa_intra_prefix_update_transit (o6i->interface->name);
      ospf6_lsa_intra_prefix_update_stub (o6i->area->area_id);
    }
  return 0;
}

int
ospf6_lsa_intra_prefix_hook_neighbor (void *neighbor)
{
  struct ospf6_neighbor *o6n = neighbor;
  if (o6n->ospf6_interface->area)
    {
      ospf6_lsa_intra_prefix_update_transit (o6n->ospf6_interface->interface->name);
      ospf6_lsa_intra_prefix_update_stub (o6n->ospf6_interface->area->area_id);
    }
  return 0;
}

int
ospf6_intra_prefix_link_database_hook (void *new)
{
  struct ospf6_lsa *lsa = new;
  struct ospf6_interface *o6i;

  if (lsa->header->type != htons (OSPF6_LSA_TYPE_LINK))
    return 0;

  o6i = lsa->scope;
  if (o6i->state != IFS_DR)
    return 0;

  ospf6_lsa_intra_prefix_update_transit (o6i->interface->name);
  ospf6_lsa_intra_prefix_update_stub (o6i->area->area_id);
  return 0;
}

int
ospf6_lsa_intra_prefix_refresh (void *old)
{
  struct ospf6_lsa *lsa = old;
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;
  u_int32_t id;

  id = ntohl (lsa->header->id);
  if (id)
    {
      o6i = ospf6_interface_lookup_by_index (id);
      if (o6i)
        ospf6_lsa_intra_prefix_update_transit (o6i->interface->name);
      else
        ospf6_lsa_premature_aging (lsa);
    }
  else
    {
      o6a = lsa->scope;
      ospf6_lsa_intra_prefix_update_stub (o6a->area_id);
    }

  return 0;
}

void
ospf6_intra_prefix_register ()
{
  struct ospf6_lsa_slot slot, *sp;
  struct ospf6_hook hook;

  memset (&slot, 0, sizeof (struct ospf6_lsa_slot));
  slot.type              = htons (OSPF6_LSA_TYPE_INTRA_PREFIX);
  slot.name              = "Intra-Prefix";
  slot.func_show         = ospf6_lsa_intra_prefix_show;
  slot.func_refresh      = ospf6_lsa_intra_prefix_refresh;
  ospf6_lsa_slot_register (&slot);

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateIntraPrefix";
  hook.hook_add = ospf6_lsa_intra_prefix_hook_interface;
  hook.hook_change = ospf6_lsa_intra_prefix_hook_interface;
  hook.hook_remove = NULL; /* XXX */
  ospf6_hook_register (&hook, &interface_hook);

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateIntraPrefix";
  hook.hook_add = ospf6_lsa_intra_prefix_hook_neighbor;
  hook.hook_change = ospf6_lsa_intra_prefix_hook_neighbor;
  hook.hook_remove = ospf6_lsa_intra_prefix_hook_neighbor;
  ospf6_hook_register (&hook, &neighbor_hook);

  sp = ospf6_lsa_slot_get (htons (OSPF6_LSA_TYPE_INTRA_PREFIX));
  hook.name = "CalculateIntraPrefix";
  hook.hook_add = ospf6_intra_prefix_database_hook_add;
  hook.hook_change = ospf6_intra_prefix_database_hook_add;
  hook.hook_remove = ospf6_intra_prefix_database_hook_remove;
  ospf6_hook_register (&hook, &sp->database_hook);
}

void
ospf6_intra_database_hook_intra_prefix (struct ospf6_lsa *old,
                                        struct ospf6_lsa *new)
{
  if (old)
    ospf6_intra_prefix_database_hook_remove (old);
  if (new && ! IS_LSA_MAXAGE (new))
    ospf6_intra_prefix_database_hook_add (new);
}

void
ospf6_intra_database_hook_link (struct ospf6_lsa *old,
                                struct ospf6_lsa *new)
{
  ospf6_intra_prefix_link_database_hook (new);
  ospf6_spf_database_hook (old, new);
}

void
ospf6_intra_init ()
{
  ospf6_lsdb_hook[OSPF6_LSA_TYPE_INTRA_PREFIX & OSPF6_LSTYPE_CODE_MASK].hook =
    ospf6_intra_database_hook_intra_prefix;
  ospf6_lsdb_hook[OSPF6_LSA_TYPE_LINK & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_intra_database_hook_link;

  intra_index = ospf6_dump_install ("intra-area", "Intra-area calculation\n");
  ospf6_intra_prefix_register ();
}


