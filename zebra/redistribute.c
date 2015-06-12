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

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"

#define ZEBRA_PTM_SUPPORT


/* master zebra server structure */
extern struct zebra_t zebrad;

/* array holding redistribute info about table redistribution */
/* bit AFI is set if that AFI is redistributing routes from this table */
static u_char zebra_import_table_used[ZEBRA_KERNEL_TABLE_MAX];
static u_int32_t zebra_import_table_distance[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

int
is_zebra_import_table_enabled(afi_t afi, u_int32_t table_id)
{
  if (is_zebra_valid_kernel_table(table_id))
    {
      if (CHECK_FLAG(zebra_import_table_used[table_id], (u_char)afi))
	return 1;
      else
	return 0;
    }

  return 0;
}

int
zebra_check_addr (struct prefix *p)
{
  if (p->family == AF_INET)
    {
      u_int32_t addr;

      addr = p->u.prefix4.s_addr;
      addr = ntohl (addr);

      if (IPV4_NET127 (addr)
          || IN_CLASSD (addr)
          || IPV4_LINKLOCAL(addr))
	return 0;
    }
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK (&p->u.prefix6))
	return 0;
      if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
	return 0;
    }
#endif /* HAVE_IPV6 */
  return 1;
}

static int
is_default (struct prefix *p)
{
  if (p->family == AF_INET)
    if (p->u.prefix4.s_addr == 0 && p->prefixlen == 0)
      return 1;
#ifdef HAVE_IPV6
#if 0  /* IPv6 default separation is now pending until protocol daemon
          can handle that. */
  if (p->family == AF_INET6)
    if (IN6_IS_ADDR_UNSPECIFIED (&p->u.prefix6) && p->prefixlen == 0)
      return 1;
#endif /* 0 */
#endif /* HAVE_IPV6 */
  return 0;
}

static void
zebra_redistribute_default (struct zserv *client)
{
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *newrib;
#ifdef HAVE_IPV6
  struct prefix_ipv6 p6;
#endif /* HAVE_IPV6 */


  /* Lookup default route. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;

  /* Lookup table.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    {
      rn = route_node_lookup (table, (struct prefix *)&p);
      if (rn)
	{
	  RNODE_FOREACH_RIB (rn, newrib)
	    if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
		&& newrib->distance != DISTANCE_INFINITY)
	      zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, &rn->p, newrib);
	  route_unlock_node (rn);
	}
    }

#ifdef HAVE_IPV6
  /* Lookup default route. */
  memset (&p6, 0, sizeof (struct prefix_ipv6));
  p6.family = AF_INET6;

  /* Lookup table.  */
  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    {
      rn = route_node_lookup (table, (struct prefix *)&p6);
      if (rn)
	{
	  RNODE_FOREACH_RIB (rn, newrib)
	    if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
		&& newrib->distance != DISTANCE_INFINITY)
	      zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, &rn->p, newrib);
	  route_unlock_node (rn);
	}
    }
#endif /* HAVE_IPV6 */
}

/* Redistribute routes. */
static void
zebra_redistribute (struct zserv *client, int type, u_short instance)
{
  struct rib *newrib;
  struct route_table *table;
  struct route_node *rn;

  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB (rn, newrib)
	if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED) 
	    && newrib->type == type
            && newrib->instance == instance
	    && newrib->distance != DISTANCE_INFINITY
	    && zebra_check_addr (&rn->p))
	  {
	    client->redist_v4_add_cnt++;
	    zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, &rn->p, newrib);
	  }
  
#ifdef HAVE_IPV6
  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB (rn, newrib)
	if (CHECK_FLAG (newrib->flags, ZEBRA_FLAG_SELECTED)
	    && newrib->type == type
            && newrib->instance == instance
	    && newrib->distance != DISTANCE_INFINITY
	    && zebra_check_addr (&rn->p))
	  {
	    client->redist_v6_add_cnt++;
	    zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, &rn->p, newrib);
	  }
#endif /* HAVE_IPV6 */
}

void
redistribute_add (struct prefix *p, struct rib *rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      if (is_default (p))
        {
          if ((p->family == AF_INET) &&
              (client->redist_default ||
              redist_check_instance(&client->redist[AFI_IP][rib->type],
                                    rib->instance)))
	    {
	      client->redist_v4_add_cnt++;
              zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, p, rib);
            }
#ifdef HAVE_IPV6
          if ((p->family == AF_INET6) &&
              (client->redist_default ||
              redist_check_instance(&client->redist[AFI_IP6][rib->type],
                                    rib->instance)))
            {
              client->redist_v6_add_cnt++;
              zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, p, rib);
            }
#endif /* HAVE_IPV6 */	  
        }
      else
        {
           if ((p->family == AF_INET) &&
              redist_check_instance(&client->redist[AFI_IP][rib->type],
                                    rib->instance))
	    {
	      client->redist_v4_add_cnt++;
              zsend_route_multipath (ZEBRA_IPV4_ROUTE_ADD, client, p, rib);
            }
#ifdef HAVE_IPV6
          if ((p->family == AF_INET6) &&
              redist_check_instance(&client->redist[AFI_IP6][rib->type],
                                    rib->instance))
            {
              client->redist_v6_add_cnt++;
              zsend_route_multipath (ZEBRA_IPV6_ROUTE_ADD, client, p, rib);
            }
#endif /* HAVE_IPV6 */	  
        }
    }
}

void
redistribute_delete (struct prefix *p, struct rib *rib)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  /* Add DISTANCE_INFINITY check. */
  if (rib->distance == DISTANCE_INFINITY)
    return;

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      if (is_default (p))
	{
	  if ((p->family == AF_INET) &&
              (client->redist_default ||
               redist_check_instance(&client->redist[AFI_IP][rib->type],
                                     rib->instance)))
            zsend_route_multipath (ZEBRA_IPV4_ROUTE_DELETE, client, p,
				       rib);
#ifdef HAVE_IPV6
	  if ((p->family == AF_INET6) &&
              (client->redist_default ||
               redist_check_instance(&client->redist[AFI_IP6][rib->type],
                                     rib->instance)))
            zsend_route_multipath (ZEBRA_IPV6_ROUTE_DELETE, client, p,
				       rib);
#endif /* HAVE_IPV6 */
	}
      else
        {
          if ((p->family == AF_INET) &&
               redist_check_instance(&client->redist[AFI_IP][rib->type],
                                     rib->instance))
            zsend_route_multipath (ZEBRA_IPV4_ROUTE_DELETE, client, p,
				       rib);
#ifdef HAVE_IPV6
	  if ((p->family == AF_INET6) &&
               redist_check_instance(&client->redist[AFI_IP6][rib->type],
                                     rib->instance))
            zsend_route_multipath (ZEBRA_IPV6_ROUTE_DELETE, client, p,
				       rib);
#endif /* HAVE_IPV6 */
	}
    }
}

void
zebra_redistribute_add (int command, struct zserv *client, int length)
{
  afi_t afi;
  int type;
  u_short instance;

  afi = stream_getc (client->ibuf);
  type = stream_getc (client->ibuf);
  instance = stream_getw (client->ibuf);

  if (type == 0 || type >= ZEBRA_ROUTE_MAX)
    return;

  if (!redist_check_instance(&client->redist[afi][type], instance))
    {
      redist_add_instance(&client->redist[afi][type], instance);
      zebra_redistribute (client, type, instance);
    }
}

void
zebra_redistribute_delete (int command, struct zserv *client, int length)
{
  afi_t afi;
  int type;
  u_short instance;

  afi = stream_getc (client->ibuf);
  type = stream_getc (client->ibuf);
  instance = stream_getw (client->ibuf);

  if (type == 0 || type >= ZEBRA_ROUTE_MAX)
    return;

  if (redist_check_instance(&client->redist[afi][type], instance))
    {
      redist_del_instance(&client->redist[afi][type], instance);
      //Pending: why no reaction here?
    }
}

void
zebra_redistribute_default_add (int command, struct zserv *client, int length)
{
  client->redist_default = 1;
  zebra_redistribute_default (client);
}     

void
zebra_redistribute_default_delete (int command, struct zserv *client,
				   int length)
{
  client->redist_default = 0;;
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
      {
	zsend_interface_update (ZEBRA_INTERFACE_UP, client, ifp);
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
    zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADD %s", ifp->name);
    
  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo)
      {
	client->ifadd_cnt++;
	zsend_interface_add (client, ifp);
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
    if (client->ifinfo)
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
      char buf[INET6_ADDRSTRLEN];

      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_ADD %s/%d on %s",
		  inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN),
		  p->prefixlen, ifc->ifp->name);
    }

  if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
    zlog_warn("WARNING: advertising address to clients that is not yet usable.");

  router_id_add_address(ifc);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo && CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
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
      char buf[INET6_ADDRSTRLEN];

      p = ifc->address;
      zlog_debug ("MESSAGE: ZEBRA_INTERFACE_ADDRESS_DELETE %s/%d on %s",
		  inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN),
		 p->prefixlen, ifc->ifp->name);
    }

  router_id_del_address(ifc);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    if (client->ifinfo && CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
      {
	client->connected_rt_del_cnt++;
	zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_DELETE, client, ifp, ifc);
      }
}

int
zebra_add_import_table_entry (struct route_node *rn, struct rib *rib)
{
  struct rib *newrib;
  struct prefix_ipv4 p4;
  struct nexthop *nhop;
  struct in_addr *gate;

  if (rn->p.family == AF_INET)
    {
      p4.family = AF_INET;
      p4.prefixlen = rn->p.prefixlen;
      p4.prefix = rn->p.u.prefix4;

      if (rib->nexthop_num == 1)
	{
	  nhop = rib->nexthop;
	  if ((nhop->type == NEXTHOP_TYPE_IFINDEX) ||
	      (nhop->type == NEXTHOP_TYPE_IFNAME))
	    gate = NULL;
	  else
	    gate = &nhop->gate.ipv4;

	  rib_add_ipv4(ZEBRA_ROUTE_TABLE, rib->table, 0, &p4,
		       gate, &nhop->src.ipv4,
		       nhop->ifindex, zebrad.rtm_table_default,
		       rib->metric,
		       zebra_import_table_distance[AFI_IP][rib->table],
		       SAFI_UNICAST);
	}
      else if (rib->nexthop_num > 1)
	{
	  newrib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
	  newrib->type = ZEBRA_ROUTE_TABLE;
	  newrib->distance = zebra_import_table_distance[AFI_IP][rib->table];
	  newrib->flags = rib->flags;
	  newrib->metric = rib->metric;
	  newrib->table = zebrad.rtm_table_default;
	  newrib->nexthop_num = 0;
	  newrib->uptime = time(NULL);
	  newrib->instance = rib->table;

	  /* Assuming these routes are never recursive */
	  for (nhop = rib->nexthop; nhop; nhop = nhop->next)
	    copy_nexthops(newrib, nhop);

	  rib_add_ipv4_multipath(&p4, newrib, SAFI_UNICAST);
	}
    }
  /* DD: Add IPv6 code */
  return 0;
}

int
zebra_del_import_table_entry (struct route_node *rn, struct rib *rib)
{
  struct prefix_ipv4 p4;

  if (rn->p.family == AF_INET)
    {
      p4.family = AF_INET;
      p4.prefixlen = rn->p.prefixlen;
      p4.prefix = rn->p.u.prefix4;

      rib_delete_ipv4(ZEBRA_ROUTE_TABLE, rib->table, rib->flags, &p4, NULL,
		      0, zebrad.rtm_table_default, SAFI_UNICAST);
    }
  /* DD: Add IPv6 code */

  return 0;
}

/* Assuming no one calls this with the main routing table */
int
zebra_import_table (afi_t afi, u_int32_t table_id, u_int32_t distance, int add)
{
  struct route_table *table;
  struct rib *rib;
  struct route_node *rn;

  if (!is_zebra_valid_kernel_table(table_id) ||
      ((table_id == RT_TABLE_MAIN) || (table_id == zebrad.rtm_table_default)))
    return (-1);

  if (afi >= AFI_MAX)
    return (-1);

  table = vrf_other_route_table(afi, table_id, 0);
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
      SET_FLAG(zebra_import_table_used[table_id], afi);
      zebra_import_table_distance[afi][table_id] = distance;
    }
  else
    {
      UNSET_FLAG(zebra_import_table_used[table_id], (u_char)afi);
      zebra_import_table_distance[afi][table_id] = ZEBRA_TABLE_DISTANCE_DEFAULT;
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
	    zebra_add_import_table_entry (rn, rib);
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
  char afi_str[AFI_MAX][6] = {"", "ip", "ipv6"};

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++)
	{
	  if (is_zebra_import_table_enabled(afi, i))
	    {
	      if (zebra_import_table_distance[afi][i] != ZEBRA_TABLE_DISTANCE_DEFAULT)
		{
		  vty_out(vty, "%s import-table %d distance %d%s", afi_str[afi],
			  i, zebra_import_table_distance[afi][i], VTY_NEWLINE);
		}
	      else
		{
		  vty_out(vty, "%s import-table %d%s", afi_str[afi], i,
			  VTY_NEWLINE);
		}
	      write = 1;
	    }
	}
    }

  return write;
}
