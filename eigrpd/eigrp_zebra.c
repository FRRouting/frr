/*
 * Zebra connect library for EIGRP.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"

static int eigrp_interface_add (int , struct zclient *, zebra_size_t, vrf_id_t);
static int eigrp_interface_delete (int , struct zclient *,
                                   zebra_size_t, vrf_id_t);
static int eigrp_interface_address_add (int, struct zclient *,
                                        zebra_size_t, vrf_id_t vrf_id);
static int eigrp_interface_address_delete (int, struct zclient *,
                                           zebra_size_t, vrf_id_t vrf_id);
static int eigrp_interface_state_up (int, struct zclient *,
                                     zebra_size_t, vrf_id_t vrf_id);
static int eigrp_interface_state_down (int, struct zclient *,
                                       zebra_size_t, vrf_id_t vrf_id);
static struct interface * zebra_interface_if_lookup (struct stream *);

static int eigrp_zebra_read_ipv4 (int , struct zclient *,
				  zebra_size_t, vrf_id_t vrf_id);

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int
eigrp_router_id_update_zebra (int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
  struct eigrp *eigrp;
  struct prefix router_id;
  zebra_router_id_update_read (zclient->ibuf,&router_id);

  router_id_zebra = router_id.u.prefix4;

  eigrp = eigrp_lookup ();

  if (eigrp != NULL)
    eigrp_router_id_update (eigrp);

  return 0;
}

static void
eigrp_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

void
eigrp_zebra_init (void)
{
  zclient = zclient_new (master);

  zclient_init (zclient, ZEBRA_ROUTE_EIGRP, 0);
  zclient->zebra_connected = eigrp_zebra_connected;
  zclient->router_id_update = eigrp_router_id_update_zebra;
  zclient->interface_add = eigrp_interface_add;
  zclient->interface_delete = eigrp_interface_delete;
  zclient->interface_up = eigrp_interface_state_up;
  zclient->interface_down = eigrp_interface_state_down;
  zclient->interface_address_add = eigrp_interface_address_add;
  zclient->interface_address_delete = eigrp_interface_address_delete;
  zclient->redistribute_route_ipv4_add = eigrp_zebra_read_ipv4;
  zclient->redistribute_route_ipv4_del = eigrp_zebra_read_ipv4;
}


/* Zebra route add and delete treatment. */
static int
eigrp_zebra_read_ipv4 (int command, struct zclient *zclient,
		       zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *s;
  struct zapi_ipv4 api;
  struct prefix_ipv4 p;
  struct eigrp *eigrp;

  s = zclient->ibuf;

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.instance = stream_getw (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  if (IPV4_NET127(ntohl(p.prefix.s_addr)))
    return 0;

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      /* XXX assert(api.ifindex_num == 1); */
      stream_getl (s);  /* ifindex, unused */
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);

  eigrp = eigrp_lookup ();
  if (eigrp == NULL)
    return 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {

    }
  else                          /* if (command == ZEBRA_IPV4_ROUTE_DELETE) */
    {

    }

  return 0;
}

/* Inteface addition message from zebra. */
static int
eigrp_interface_add (int command, struct zclient *zclient, zebra_size_t length,
		     vrf_id_t vrf_id)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf, vrf_id);

  assert (ifp->info);

  if (!EIGRP_IF_PARAM_CONFIGURED (IF_DEF_PARAMS (ifp), type))
    {
      SET_IF_PARAM (IF_DEF_PARAMS (ifp), type);
      IF_DEF_PARAMS (ifp)->type = eigrp_default_iftype (ifp);
    }

  eigrp_if_update (ifp);

  return 0;
}

static int
eigrp_interface_delete (int command, struct zclient *zclient,
			zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct stream *s;
  struct route_node *rn;

  s = zclient->ibuf;
  /* zebra_interface_state_read () updates interface structure in iflist */
  ifp = zebra_interface_state_read (s, vrf_id);

  if (ifp == NULL)
    return 0;

  if (if_is_up (ifp))
    zlog_warn ("Zebra: got delete of %s, but interface is still up",
               ifp->name);

  if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
    zlog_debug("Zebra: interface delete %s index %d flags %llx metric %d mtu %d",
       ifp->name, ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
    if (rn->info)
      eigrp_if_free ((struct eigrp_interface *) rn->info, INTERFACE_DOWN_BY_ZEBRA);

  ifp->ifindex = IFINDEX_INTERNAL;
  return 0;
}

static int
eigrp_interface_address_add (int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;

  c = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (c == NULL)
    return 0;

  if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
    {
      char buf[128];
      prefix2str (c->address, buf, sizeof (buf));
      zlog_debug ("Zebra: interface %s address add %s", c->ifp->name, buf);
    }

  eigrp_if_update (c->ifp);

  return 0;
}

static int
eigrp_interface_address_delete (int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;
  struct interface *ifp;
  struct eigrp_interface *ei;
  struct route_node *rn;
  struct prefix p;

  c = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (c == NULL)
    return 0;

  if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
    {
      char buf[128];
      prefix2str (c->address, buf, sizeof (buf));
      zlog_debug ("Zebra: interface %s address delete %s", c->ifp->name, buf);
    }

  ifp = c->ifp;
  p = *c->address;
  p.prefixlen = IPV4_MAX_PREFIXLEN;

  rn = route_node_lookup (IF_OIFS (ifp), &p);
  if (!rn)
    {
      connected_free (c);
      return 0;
    }

  assert (rn->info);
  ei = rn->info;

  /* Call interface hook functions to clean up */
  eigrp_if_free (ei, INTERFACE_DOWN_BY_ZEBRA);

  connected_free (c);

  return 0;
}

static int
eigrp_interface_state_up (int command, struct zclient *zclient,
			  zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct eigrp_interface *ei;
  struct route_node *rn;

  ifp = zebra_interface_if_lookup (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  /* Interface is already up. */
  if (if_is_operative (ifp))
    {
      /* Temporarily keep ifp values. */
      struct interface if_tmp;
      memcpy (&if_tmp, ifp, sizeof (struct interface));

      zebra_interface_if_set_value (zclient->ibuf, ifp);

      if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
        zlog_debug ("Zebra: Interface[%s] state update.", ifp->name);

      if (if_tmp.bandwidth != ifp->bandwidth)
        {
          if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
            zlog_debug ("Zebra: Interface[%s] bandwidth change %d -> %d.",
                       ifp->name, if_tmp.bandwidth, ifp->bandwidth);

//          eigrp_if_recalculate_output_cost (ifp);
        }

      if (if_tmp.mtu != ifp->mtu)
        {
          if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
            zlog_debug ("Zebra: Interface[%s] MTU change %u -> %u.",
			ifp->name, if_tmp.mtu, ifp->mtu);

          /* Must reset the interface (simulate down/up) when MTU changes. */
          eigrp_if_reset (ifp);
        }
      return 0;
    }

  zebra_interface_if_set_value (zclient->ibuf, ifp);

  if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
    zlog_debug ("Zebra: Interface[%s] state change to up.", ifp->name);

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
    {
      if ((ei = rn->info) == NULL)
        continue;

      eigrp_if_up (ei);
    }

  return 0;
}

static int
eigrp_interface_state_down (int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct eigrp_interface *ei;
  struct route_node *node;

  ifp = zebra_interface_state_read (zclient->ibuf, vrf_id);

  if (ifp == NULL)
    return 0;

  if (IS_DEBUG_EIGRP (zebra, ZEBRA_INTERFACE))
    zlog_debug ("Zebra: Interface[%s] state change to down.", ifp->name);

  for (node = route_top (IF_OIFS (ifp)); node; node = route_next (node))
    {
      if ((ei = node->info) == NULL)
        continue;
      eigrp_if_down (ei);
    }

  return 0;
}

static struct interface *
zebra_interface_if_lookup (struct stream *s)
{
  char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* And look it up. */
  return if_lookup_by_name_len (ifname_tmp,
                               strnlen (ifname_tmp, INTERFACE_NAMSIZ));
}

void
eigrp_zebra_route_add (struct prefix_ipv4 *p, struct eigrp_neighbor_entry *te)
{
  u_char message;
  u_char flags;
  int psize;
  struct stream *s;

  if (zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
    {
      message = 0;
      flags = 0;

      /* EIGRP pass nexthop and metric */
      SET_FLAG (message, ZAPI_MESSAGE_NEXTHOP);
      SET_FLAG (message, ZAPI_MESSAGE_METRIC);

      /* Distance value. */
//      distance = eigrp_distance_apply (p, er);
//      if (distance)
//        SET_FLAG (message, ZAPI_MESSAGE_DISTANCE);

      /* Make packet. */
      s = zclient->obuf;
      stream_reset (s);

      /* Put command, type, flags, message. */
      zclient_create_header (s, ZEBRA_IPV4_ROUTE_ADD, VRF_DEFAULT);
      stream_putc (s, ZEBRA_ROUTE_EIGRP);
      stream_putc (s, flags);
      stream_putc (s, message);
      stream_putw (s, SAFI_UNICAST);

      /* Put prefix information. */
      psize = PSIZE (p->prefixlen);
      stream_putc (s, p->prefixlen);
      stream_write (s, (u_char *) & p->prefix, psize);

      /* Nexthop count. */
      stream_putc (s, 1);

      /* Nexthop, ifindex, distance and metric information. */
      stream_putc (s, NEXTHOP_TYPE_IPV4_IFINDEX);
      stream_put_in_addr (s, &te->adv_router->src);
      stream_putl (s, te->ei->ifp->ifindex);

      if (IS_DEBUG_EIGRP (zebra, ZEBRA_REDISTRIBUTE))
        {
          char buf[2][INET_ADDRSTRLEN];
          zlog_debug ("Zebra: Route add %s/%d nexthop %s",
		      inet_ntop(AF_INET, &p->prefix, buf[0], sizeof (buf[0])),
		      p->prefixlen,
		      inet_ntop(AF_INET, 0 /*&p->nexthop*/, buf[1], sizeof (buf[1])));
        }

      stream_putl (s, te->distance);
      stream_putw_at (s, 0, stream_get_endp (s));

      zclient_send_message (zclient);
    }
}

void
eigrp_zebra_route_delete (struct prefix_ipv4 *p, struct eigrp_neighbor_entry *te)
{
  u_char message;
  u_char flags;
  int psize;
  struct stream *s;

  if (zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
    {
      message = 0;
      flags = 0;
      /* Make packet. */
      s = zclient->obuf;
      stream_reset (s);

      /* Put command, type, flags, message. */
      zclient_create_header (s, ZEBRA_IPV4_ROUTE_DELETE, VRF_DEFAULT);
      stream_putc (s, ZEBRA_ROUTE_EIGRP);
      stream_putc (s, flags);
      stream_putc (s, message);
      stream_putw (s, SAFI_UNICAST);

      /* Put prefix information. */
      psize = PSIZE (p->prefixlen);
      stream_putc (s, p->prefixlen);
      stream_write (s, (u_char *) & p->prefix, psize);

      /* Nexthop count. */
      stream_putc (s, 1);

      /* Nexthop, ifindex, distance and metric information. */
      stream_putc (s, NEXTHOP_TYPE_IPV4_IFINDEX);
      stream_put_in_addr (s, &te->adv_router->src);
      stream_putl (s, te->ei->ifp->ifindex);

      if (IS_DEBUG_EIGRP (zebra, ZEBRA_REDISTRIBUTE))
        {
          char buf[2][INET_ADDRSTRLEN];
          zlog_debug ("Zebra: Route del %s/%d nexthop %s",
		      inet_ntop (AF_INET, &p->prefix,  buf[0], sizeof (buf[0])),
		      p->prefixlen,
		      inet_ntop (AF_INET, 0 /*&p->nexthop*/, buf[1], sizeof (buf[1])));
        }


      if (CHECK_FLAG (message, ZAPI_MESSAGE_METRIC))
        {
          stream_putl (s, te->distance);
        }

      stream_putw_at (s, 0, stream_get_endp (s));

      zclient_send_message (zclient);
    }
}

vrf_bitmap_t
eigrp_is_type_redistributed (int type)
{
  return (DEFAULT_ROUTE_TYPE (type)) ?
    zclient->default_information : zclient->redist[AFI_IP][type];
}

int
eigrp_redistribute_set (struct eigrp *eigrp, int type, struct eigrp_metrics metric)
{

  if (eigrp_is_type_redistributed (type))
    {
      if (eigrp_metrics_is_same(&metric, &eigrp->dmetric[type]))
        {
          eigrp->dmetric[type] = metric;
        }

      eigrp_external_routes_refresh (eigrp, type);

//      if (IS_DEBUG_EIGRP(zebra, ZEBRA_REDISTRIBUTE))
//        zlog_debug ("Redistribute[%s]: Refresh  Type[%d], Metric[%d]",
//                   eigrp_redist_string(type),
//                   metric_type (eigrp, type), metric_value (eigrp, type));
      return CMD_SUCCESS;
    }

  eigrp->dmetric[type] = metric;

  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient,
			AFI_IP, type, 0, VRF_DEFAULT);

//  if (IS_DEBUG_EIGRP (zebra, ZEBRA_REDISTRIBUTE))
//    zlog_debug ("Redistribute[%s]: Start  Type[%d], Metric[%d]",
//               ospf_redist_string(type),
//               metric_type (ospf, type), metric_value (ospf, type));

  ++eigrp->redistribute;

  return CMD_SUCCESS;
}

int
eigrp_redistribute_unset (struct eigrp *eigrp, int type)
{

  if (eigrp_is_type_redistributed (type))
    {
      memset(&eigrp->dmetric[type], 0, sizeof(struct eigrp_metrics));
      zclient_redistribute (ZEBRA_REDISTRIBUTE_DELETE, zclient,
			    AFI_IP, type, 0, VRF_DEFAULT);
      --eigrp->redistribute;
    }

//  if (IS_DEBUG_EIGRP (zebra, ZEBRA_REDISTRIBUTE))
//    zlog_debug ("Redistribute[%s]: Start  Type[%d], Metric[%d]",
//               ospf_redist_string(type),
//               metric_type (ospf, type), metric_value (ospf, type));

  return CMD_SUCCESS;
}

