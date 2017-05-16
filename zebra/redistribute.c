/* Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "zclient.h"
#include "linklist.h"
#include "log.h"
#include "vrf.h"
#include "srcdest_table.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_routemap.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/zebra_memory.h"

#define ZEBRA_PTM_SUPPORT

/* array holding redistribute info about table redistribution */
/* bit AFI is set if that AFI is redistributing routes from this table */
static int zebra_import_table_used[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];
static u_int32_t zebra_import_table_distance[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

int
is_zebra_import_table_enabled(afi_t afi, u_int32_t table_id)
{
  if (is_zebra_valid_kernel_table(table_id))
    return zebra_import_table_used[afi][table_id];
  return 0;
}

int
is_default (struct prefix *p)
{
  if (p->family == AF_INET)
    if (p->u.prefix4.s_addr == 0 && p->prefixlen == 0)
      return 1;
#if 0  /* IPv6 default separation is now pending until protocol daemon
          can handle that. */
  if (p->family == AF_INET6)
    if (IN6_IS_ADDR_UNSPECIFIED (&p->u.prefix6) && p->prefixlen == 0)
      return 1;
#endif /* 0 */
  return 0;
}

static void
zebra_redistribute_default (struct zserv *client, vrf_id_t vrf_id)
{
  int afi;
  struct prefix p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *newrib;

  for (afi = AFI_IP; afi <= AFI_IP6; afi++)
    {
      /* Lookup table.  */
      table = zebra_vrf_table (afi, SAFI_UNICAST, vrf_id);
      if (! table)
	continue;

      /* Lookup default route. */
      memset (&p, 0, sizeof (p));
      p.family = afi2family (afi);
      rn = route_node_lookup (table, &p);
      if (! rn)
	continue;

      RNODE_FOREACH_RIB (rn, newrib)
	if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
	    && newrib->distance != DISTANCE_INFINITY)
	  zsend_redistribute_route (1, client, &rn->p, NULL, newrib);

      route_unlock_node (rn);
    }
}

/* Redistribute routes. */
static void
zebra_redistribute (struct zserv *client, int type, u_short instance, vrf_id_t vrf_id)
{
  struct rib *newrib;
  struct route_table *table;
  struct route_node *rn;
  int afi;

  for (afi = AFI_IP; afi <= AFI_IP6; afi++)
    {
      table = zebra_vrf_table (afi, SAFI_UNICAST, vrf_id);
      if (! table)
	continue;

      for (rn = route_top (table); rn; rn = route_next (rn))
	RNODE_FOREACH_RIB (rn, newrib)
	  {
	    struct prefix *dst_p, *src_p;
	    srcdest_rnode_prefixes(rn, &dst_p, &src_p);

	    if (IS_ZEBRA_DEBUG_EVENT)
	      zlog_debug("%s: checking: selected=%d, type=%d, distance=%d, "
			 "zebra_check_addr=%d", __func__,
			 CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED),
			 newrib->type, newrib->distance,
			 zebra_check_addr (dst_p));

	    if (! CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED))
	      continue;
	    if ((type != ZEBRA_ROUTE_ALL &&
		 (newrib->type != type || newrib->instance != instance)))
	      continue;
	    if (newrib->distance == DISTANCE_INFINITY)
	      continue;
	    if (! zebra_check_addr (dst_p))
	      continue;

	    zsend_redistribute_route (1, client, dst_p, src_p, newrib);
	  }
    }
}

/* Either advertise a route for redistribution to registered clients or */
/* withdraw redistribution if add cannot be done for client */
void
redistribute_update (struct prefix *p, struct prefix *src_p,
                     struct rib *rib, struct rib *prev_rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  int send_redistribute;
  int afi;
  char buf[INET6_ADDRSTRLEN];

  if (IS_ZEBRA_DEBUG_RIB)
    {
      inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
      zlog_debug ("%u:%s/%d: Redist update rib %p (type %d), old %p (type %d)",
                  rib->vrf_id, buf, p->prefixlen, rib, rib->type,
                  prev_rib, prev_rib ? prev_rib->type : -1);
    }

  afi = family2afi(p->family);
  if (!afi)
    {
      zlog_warn("%s: Unknown AFI/SAFI prefix received\n", __FUNCTION__);
      return;
    }

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      send_redistribute = 0;

      if (is_default (p) && vrf_bitmap_check (client->redist_default, rib->vrf_id))
	send_redistribute = 1;
      else if (vrf_bitmap_check (client->redist[afi][ZEBRA_ROUTE_ALL], rib->vrf_id))
	send_redistribute = 1;
      else if (rib->instance && redist_check_instance (&client->mi_redist[afi][rib->type],
						       rib->instance))
	send_redistribute = 1;
      else if (vrf_bitmap_check (client->redist[afi][rib->type], rib->vrf_id))
	send_redistribute = 1;

      if (send_redistribute)
	{
	  zsend_redistribute_route (1, client, p, src_p, rib);
	}
      else if (prev_rib &&
	       ((rib->instance &&
                redist_check_instance(&client->mi_redist[afi][prev_rib->type],
                                      rib->instance)) ||
                vrf_bitmap_check (client->redist[afi][prev_rib->type], rib->vrf_id))) 
	{
	  zsend_redistribute_route (0, client, p, src_p, prev_rib);
	}
    }
}

void
redistribute_delete (struct prefix *p, struct prefix *src_p, struct rib *rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  char buf[INET6_ADDRSTRLEN];
  int afi;

  if (IS_ZEBRA_DEBUG_RIB)
    {
      inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
      zlog_debug ("%u:%s/%d: Redist delete rib %p (type %d)",
                  rib->vrf_id, buf, p->prefixlen, rib, rib->type);
    }

  /* Add DISTANCE_INFINITY check. */
  if (rib->distance == DISTANCE_INFINITY)
    return;

  afi = family2afi(p->family);
  if (!afi)
    {
      zlog_warn("%s: Unknown AFI/SAFI prefix received\n", __FUNCTION__);
      return;
    }

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      if ((is_default (p) &&
           vrf_bitmap_check (client->redist_default, rib->vrf_id)) ||
	  vrf_bitmap_check (client->redist[afi][ZEBRA_ROUTE_ALL], rib->vrf_id) ||
          (rib->instance &&
           redist_check_instance(&client->mi_redist[afi][rib->type],
                                 rib->instance)) ||
          vrf_bitmap_check (client->redist[afi][rib->type], rib->vrf_id))
	{
	  zsend_redistribute_route (0, client, p, src_p, rib);
	}
    }
}

void
zebra_redistribute_add (int command, struct zserv *client, int length,
			struct zebra_vrf *zvrf)
{
  afi_t afi;
  int type;
  u_short instance;

  afi = stream_getc (client->ibuf);
  type = stream_getc (client->ibuf);
  instance = stream_getw (client->ibuf);

  if (type == 0 || type >= ZEBRA_ROUTE_MAX)
    return;

  if (instance)
    {
      if (! redist_check_instance (&client->mi_redist[afi][type], instance))
	{
	  redist_add_instance (&client->mi_redist[afi][type], instance);
	  zebra_redistribute (client, type, instance, zvrf_id (zvrf));
	}
    } else {
	if (! vrf_bitmap_check (client->redist[afi][type], zvrf_id (zvrf)))
	  {
	    vrf_bitmap_set (client->redist[afi][type], zvrf_id (zvrf));
	    zebra_redistribute (client, type, 0, zvrf_id (zvrf));
	  }
    }
}

void
zebra_redistribute_delete (int command, struct zserv *client, int length,
			   struct zebra_vrf *zvrf)
{
  afi_t afi;
  int type;
  u_short instance;

  afi = stream_getc (client->ibuf);
  type = stream_getc (client->ibuf);
  instance = stream_getw (client->ibuf);

  if (type == 0 || type >= ZEBRA_ROUTE_MAX)
    return;

  /*
   * NOTE: no need to withdraw the previously advertised routes. The clients
   * themselves should keep track of the received routes from zebra and
   * withdraw them when necessary.
   */
  if (instance)
    redist_del_instance (&client->mi_redist[afi][type], instance);
  else
    vrf_bitmap_unset (client->redist[afi][type], zvrf_id (zvrf));
}

void
zebra_redistribute_default_add (int command, struct zserv *client, int length,
				struct zebra_vrf *zvrf)
{
  vrf_bitmap_set (client->redist_default, zvrf_id (zvrf));
  zebra_redistribute_default (client, zvrf_id (zvrf));
}     

void
zebra_redistribute_default_delete (int command, struct zserv *client,
				   int length, struct zebra_vrf *zvrf)
{
  vrf_bitmap_unset (client->redist_default, zvrf_id (zvrf));
}     

/* Interface up information. */
void
zebra_interface_up_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_UP %s", ifp->name);

  if (ifp->ptm_status || !ifp->ptm_enable) {
    for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
      if (client->ifinfo)
	{
	  zsend_interface_update (ZEBRA_INTERFACE_UP, client, ifp);
	  zsend_interface_link_params (client, ifp);
	}
  }
}

/* Interface down information. */
void
zebra_interface_down_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_DOWN %s", ifp->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      zsend_interface_update (ZEBRA_INTERFACE_DOWN, client, ifp);
    }
}

/* Interface information update. */
void
zebra_interface_add_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADD %s[%d]", ifp->name, ifp->vrf_id);
    
  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo)
      {
	client->ifadd_cnt++;
	zsend_interface_add (client, ifp);
        zsend_interface_link_params (client, ifp);
      }
}

void
zebra_interface_delete_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_DELETE %s", ifp->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      client->ifdel_cnt++;
      zsend_interface_delete (client, ifp);
    }
}

/* Interface address addition. */
void
zebra_interface_address_add_update (struct interface *ifp,
				    struct connected *ifc)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  struct prefix *p;

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      char buf[PREFIX_STRLEN];

      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_ADD %s on %s",
		  prefix2str (p, buf, sizeof(buf)),
		  ifc->ifp->name);
    }

  if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
    zlog_warn("WARNING: advertising address to clients that is not yet usable.");

  router_id_add_address(ifc);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
      {
	client->connected_rt_add_cnt++;
	zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_ADD, client, ifp, ifc);
      }
}

/* Interface address deletion. */
void
zebra_interface_address_delete_update (struct interface *ifp,
				       struct connected *ifc)
{
  struct listnode *node, *nnode;
  struct zserv *client;
  struct prefix *p;

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      char buf[PREFIX_STRLEN];

      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_DELETE %s on %s",
		  prefix2str (p, buf, sizeof(buf)),
		  ifc->ifp->name);
    }

  router_id_del_address(ifc);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
      {
	client->connected_rt_del_cnt++;
	zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_DELETE, client, ifp, ifc);
      }
}

/* Interface VRF change. May need to delete from clients not interested in
 * the new VRF. Note that this function is invoked *prior* to the VRF change.
 */
void
zebra_interface_vrf_update_del (struct interface *ifp, vrf_id_t new_vrf_id)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_VRF_UPDATE/DEL %s VRF Id %u -> %u",
                ifp->name, ifp->vrf_id, new_vrf_id);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      /* Need to delete if the client is not interested in the new VRF. */
      zsend_interface_update (ZEBRA_INTERFACE_DOWN, client, ifp);
      client->ifdel_cnt++;
      zsend_interface_delete (client, ifp);
      zsend_interface_vrf_update (client, ifp, new_vrf_id);
    }
}

/* Interface VRF change. This function is invoked *post* VRF change and sends an
 * add to clients who are interested in the new VRF but not in the old VRF.
 */
void
zebra_interface_vrf_update_add (struct interface *ifp, vrf_id_t old_vrf_id)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_VRF_UPDATE/ADD %s VRF Id %u -> %u",
                ifp->name, old_vrf_id, ifp->vrf_id);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      /* Need to add if the client is interested in the new VRF. */
      client->ifadd_cnt++;
      zsend_interface_add (client, ifp);
      zsend_interface_addresses (client, ifp);
    }
}

int
zebra_add_import_table_entry (struct route_node *rn, struct rib *rib, const char *rmap_name)
{
  struct rib *newrib;
  struct rib *same;
  struct prefix p;
  struct nexthop *nhop;
  union g_addr *gate;
  route_map_result_t ret = RMAP_MATCH;

  if (rmap_name)
    ret = zebra_import_table_route_map_check (AFI_IP, rib->type, &rn->p, rib->nexthop, rib->vrf_id,
                                              rib->tag, rmap_name);

  if (ret == RMAP_MATCH)
    {
      if (rn->p.family == AF_INET)
        {
          p.family = AF_INET;
          p.prefixlen = rn->p.prefixlen;
          p.u.prefix4 = rn->p.u.prefix4;

          RNODE_FOREACH_RIB (rn, same)
            {
              if (CHECK_FLAG (same->status, RIB_ENTRY_REMOVED))
                continue;

              if (same->type == rib->type && same->instance == rib->instance
                  && same->table == rib->table
                  && same->type != ZEBRA_ROUTE_CONNECT)
                break;
            }

          if (same)
            zebra_del_import_table_entry (rn, same);


          if (rib->nexthop_num == 1)
	    {
	      nhop = rib->nexthop;
	      if (nhop->type == NEXTHOP_TYPE_IFINDEX)
	        gate = NULL;
	      else
	        gate = (union g_addr *)&nhop->gate.ipv4;

	      rib_add (AFI_IP, SAFI_UNICAST, rib->vrf_id, ZEBRA_ROUTE_TABLE,
		       rib->table, 0, &p, NULL, gate, (union g_addr *)&nhop->src.ipv4,
		       nhop->ifindex, zebrad.rtm_table_default,
		       rib->metric, rib->mtu,
		       zebra_import_table_distance[AFI_IP][rib->table]);
	    }
          else if (rib->nexthop_num > 1)
	    {
	      newrib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
	      newrib->type = ZEBRA_ROUTE_TABLE;
	      newrib->distance = zebra_import_table_distance[AFI_IP][rib->table];
	      newrib->flags = rib->flags;
	      newrib->metric = rib->metric;
	      newrib->mtu = rib->mtu;
	      newrib->table = zebrad.rtm_table_default;
	      newrib->nexthop_num = 0;
	      newrib->uptime = time(NULL);
	      newrib->instance = rib->table;

	      /* Assuming these routes are never recursive */
	      for (nhop = rib->nexthop; nhop; nhop = nhop->next)
	        rib_copy_nexthops(newrib, nhop);

	      rib_add_multipath(AFI_IP, SAFI_UNICAST, &p, NULL, newrib);
	    }
        }
    }
  else
    {
      zebra_del_import_table_entry (rn, rib);
    }
  /* DD: Add IPv6 code */
  return 0;
}

int
zebra_del_import_table_entry (struct route_node *rn, struct rib *rib)
{
  struct prefix p;

  if (rn->p.family == AF_INET)
    {
      p.family = AF_INET;
      p.prefixlen = rn->p.prefixlen;
      p.u.prefix4 = rn->p.u.prefix4;

      rib_delete (AFI_IP, SAFI_UNICAST, rib->vrf_id, ZEBRA_ROUTE_TABLE,
		  rib->table, rib->flags, &p, NULL, NULL,
		  0, zebrad.rtm_table_default);
    }
  /* DD: Add IPv6 code */

  return 0;
}

/* Assuming no one calls this with the main routing table */
int
zebra_import_table (afi_t afi, u_int32_t table_id, u_int32_t distance, const char *rmap_name, int add)
{
  struct route_table *table;
  struct rib *rib;
  struct route_node *rn;

  if (!is_zebra_valid_kernel_table(table_id) ||
      ((table_id == RT_TABLE_MAIN) || (table_id == zebrad.rtm_table_default)))
    return (-1);

  if (afi >= AFI_MAX)
    return (-1);

  table = zebra_vrf_other_route_table(afi, table_id, VRF_DEFAULT);
  if (table == NULL)
    {
      return 0;
    }
  else if (IS_ZEBRA_DEBUG_RIB)
    {
      zlog_debug ("%s routes from table %d",
		  add ? "Importing" : "Unimporting", table_id);
    }

  if (add)
    {
      if (rmap_name)
        zebra_add_import_table_route_map (afi, rmap_name, table_id);
      else
        {
          rmap_name = zebra_get_import_table_route_map (afi, table_id);
          if (rmap_name)
            zebra_del_import_table_route_map (afi, table_id);
        }

      zebra_import_table_used[afi][table_id] = 1;
      zebra_import_table_distance[afi][table_id] = distance;
    }
  else
    {
      zebra_import_table_used[afi][table_id] = 0;
      zebra_import_table_distance[afi][table_id] = ZEBRA_TABLE_DISTANCE_DEFAULT;

      rmap_name = zebra_get_import_table_route_map (afi, table_id);
      if (rmap_name)
        zebra_del_import_table_route_map (afi, table_id);
    }

  for (rn = route_top(table); rn; rn = route_next(rn))
    {
      /* For each entry in the non-default routing table,
       * add the entry in the main table
       */
      if (!rn->info)
	continue;

      RNODE_FOREACH_RIB (rn, rib)
	{
	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;
	  break;
	}

      if (!rib)
	continue;

      if (((afi == AFI_IP) && (rn->p.family == AF_INET)) ||
	  ((afi == AFI_IP6) && (rn->p.family == AF_INET6)))
	{
	  if (add)
	    zebra_add_import_table_entry (rn, rib, rmap_name);
	  else
	    zebra_del_import_table_entry (rn, rib);
	}
    }
  return 0;
}

int
zebra_import_table_config (struct vty *vty)
{
  int i;
  afi_t afi;
  int write = 0;
  char afi_str[AFI_MAX][10] = {"", "ip", "ipv6", "ethernet"};
  const char *rmap_name;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++)
	{
	  if (is_zebra_import_table_enabled(afi, i))
	    {
	      if (zebra_import_table_distance[afi][i] != ZEBRA_TABLE_DISTANCE_DEFAULT)
		{
		  vty_out(vty, "%s import-table %d distance %d", afi_str[afi],
			  i, zebra_import_table_distance[afi][i]);
		}
	      else
		{
		  vty_out(vty, "%s import-table %d", afi_str[afi], i);
		}

	      rmap_name = zebra_get_import_table_route_map (afi, i);
              if (rmap_name)
	        vty_out(vty, " route-map %s", rmap_name);

	      vty_out(vty, "%s", VTY_NEWLINE);
	      write = 1;
	    }
	}
    }

  return write;
}

void
zebra_import_table_rm_update ()
{
  afi_t afi;
  int i;
  struct route_table *table;
  struct rib *rib;
  struct route_node *rn;
  const char *rmap_name;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++)
	{
	  if (is_zebra_import_table_enabled(afi, i))
	    {
              rmap_name = zebra_get_import_table_route_map (afi, i);
              if (!rmap_name)
                return;

              table = zebra_vrf_other_route_table(afi, i, VRF_DEFAULT);
              for (rn = route_top(table); rn; rn = route_next(rn))
                {
                  /* For each entry in the non-default routing table,
                   * add the entry in the main table
                   */
                  if (!rn->info)
                    continue;

                  RNODE_FOREACH_RIB (rn, rib)
                    {
                      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
                        continue;
                      break;
                    }

                 if (!rib)
                   continue;

                 if (((afi == AFI_IP) && (rn->p.family == AF_INET)) ||
                   ((afi == AFI_IP6) && (rn->p.family == AF_INET6)))
                   zebra_add_import_table_entry (rn, rib, rmap_name);
                }
	    }
	}
    }

  return;
}

/* Interface parameters update */
void
zebra_interface_parameters_update (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_LINK_PARAMS %s", ifp->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo)
      zsend_interface_link_params (client, ifp);
}
