/*
 * IS-IS Rout(e)ing protocol - isis_zebra.c   
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "network.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_te.h"

struct zclient *zclient = NULL;

/* Router-id update message from zebra. */
static int
isis_router_id_update_zebra (int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
  struct isis_area *area;
  struct listnode *node;
  struct prefix router_id;

  /*
   * If ISIS TE is enable, TE Router ID is set through specific command.
   * See mpls_te_router_addr() command in isis_te.c
   */
  if (IS_MPLS_TE(isisMplsTE))
    return 0;

  zebra_router_id_update_read (zclient->ibuf, &router_id);
  if (isis->router_id == router_id.u.prefix4.s_addr)
    return 0;

  isis->router_id = router_id.u.prefix4.s_addr;
  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    if (listcount (area->area_addrs) > 0)
      lsp_regenerate_schedule (area, area->is_type, 0);

  return 0;
}

static int
isis_zebra_if_add (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf, vrf_id);

  if (isis->debugs & DEBUG_ZEBRA)
    zlog_debug ("Zebra I/F add: %s index %d flags %ld metric %d mtu %d",
		ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric, ifp->mtu);

  if (if_is_operative (ifp))
    isis_csm_state_change (IF_UP_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  return 0;
}

static int
isis_zebra_if_del (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);

  if (!ifp)
    return 0;

  if (if_is_operative (ifp))
    zlog_warn ("Zebra: got delete of %s, but interface is still up",
	       ifp->name);

  if (isis->debugs & DEBUG_ZEBRA)
    zlog_debug ("Zebra I/F delete: %s index %d flags %ld metric %d mtu %d",
		ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric, ifp->mtu);

  isis_csm_state_change (IF_DOWN_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  /* Cannot call if_delete because we should retain the pseudo interface
     in case there is configuration info attached to it. */
  if_delete_retain(ifp);

  ifp->ifindex = IFINDEX_DELETED;

  return 0;
}

static int
isis_zebra_if_state_up (int command, struct zclient *zclient,
			zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf, vrf_id);

  if (ifp == NULL)
    return 0;

  isis_csm_state_change (IF_UP_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  return 0;
}

static int
isis_zebra_if_state_down (int command, struct zclient *zclient,
			  zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct isis_circuit *circuit;

  ifp = zebra_interface_state_read (zclient->ibuf, vrf_id);

  if (ifp == NULL)
    return 0;

  circuit = isis_csm_state_change (IF_DOWN_FROM_Z, circuit_scan_by_ifp (ifp),
                                   ifp);
  if (circuit)
    SET_FLAG(circuit->flags, ISIS_CIRCUIT_FLAPPED_AFTER_SPF);

  return 0;
}

static int
isis_zebra_if_address_add (int command, struct zclient *zclient,
			   zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;
  struct prefix *p;
  char buf[PREFIX2STR_BUFFER];

  c = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_ADD,
				    zclient->ibuf, vrf_id);

  if (c == NULL)
    return 0;

  p = c->address;

  prefix2str (p, buf, sizeof (buf));
#ifdef EXTREME_DEBUG
  if (p->family == AF_INET)
    zlog_debug ("connected IP address %s", buf);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    zlog_debug ("connected IPv6 address %s", buf);
#endif /* HAVE_IPV6 */
#endif /* EXTREME_DEBUG */
  if (if_is_operative (c->ifp))
    isis_circuit_add_addr (circuit_scan_by_ifp (c->ifp), c);

  return 0;
}

static int
isis_zebra_if_address_del (int command, struct zclient *client,
			   zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;
  struct interface *ifp;
#ifdef EXTREME_DEBUG
  struct prefix *p;
  char buf[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */

  c = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_DELETE,
				    zclient->ibuf, vrf_id);

  if (c == NULL)
    return 0;

  ifp = c->ifp;

#ifdef EXTREME_DEBUG
  p = c->address;
  prefix2str (p, buf, sizeof (buf));

  if (p->family == AF_INET)
    zlog_debug ("disconnected IP address %s", buf);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    zlog_debug ("disconnected IPv6 address %s", buf);
#endif /* HAVE_IPV6 */
#endif /* EXTREME_DEBUG */

  if (if_is_operative (ifp))
    isis_circuit_del_addr (circuit_scan_by_ifp (ifp), c);
  connected_free (c);

  return 0;
}

static int
isis_zebra_link_params (int command, struct zclient *zclient,
                        zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_link_params_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  /* Update TE TLV */
  isis_mpls_te_update(ifp);

  return 0;
}

static void
isis_zebra_route_add_ipv4 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  u_char message, flags;
  int psize;
  struct stream *stream;
  struct isis_nexthop *nexthop;
  struct listnode *node;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
    return;

  if (vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_ISIS], VRF_DEFAULT))
    {
      message = 0;
      flags = 0;

      SET_FLAG (message, ZAPI_MESSAGE_NEXTHOP);
      SET_FLAG (message, ZAPI_MESSAGE_METRIC);
#if 0
      SET_FLAG (message, ZAPI_MESSAGE_DISTANCE);
#endif

      stream = zclient->obuf;
      stream_reset (stream);
      zclient_create_header (stream, ZEBRA_IPV4_ROUTE_ADD, VRF_DEFAULT);
      /* type */
      stream_putc (stream, ZEBRA_ROUTE_ISIS);
      /* instance */
      stream_putw (stream, 0);
      /* flags */
      stream_putc (stream, flags);
      /* message */
      stream_putc (stream, message);
      /* SAFI */
      stream_putw (stream, SAFI_UNICAST);
      /* prefix information */
      psize = PSIZE (prefix->prefixlen);
      stream_putc (stream, prefix->prefixlen);
      stream_write (stream, (u_char *) & prefix->u.prefix4, psize);

      stream_putc (stream, listcount (route_info->nexthops));

      /* Nexthop, ifindex, distance and metric information */
      for (ALL_LIST_ELEMENTS_RO (route_info->nexthops, node, nexthop))
	{
	  /* FIXME: can it be ? */
	  if (nexthop->ip.s_addr != INADDR_ANY)
	    {
	      stream_putc (stream, NEXTHOP_TYPE_IPV4);
	      stream_put_in_addr (stream, &nexthop->ip);
	    }
	  else
	    {
	      stream_putc (stream, NEXTHOP_TYPE_IFINDEX);
	      stream_putl (stream, nexthop->ifindex);
	    }
	}
#if 0
      if (CHECK_FLAG (message, ZAPI_MESSAGE_DISTANCE))
	stream_putc (stream, route_info->depth);
#endif
      if (CHECK_FLAG (message, ZAPI_MESSAGE_METRIC))
	stream_putl (stream, route_info->cost);

      stream_putw_at (stream, 0, stream_get_endp (stream));
      zclient_send_message(zclient);
      SET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
      UNSET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
    }
}

static void
isis_zebra_route_del_ipv4 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv4 api;
  struct prefix_ipv4 prefix4;

  if (vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_ISIS], VRF_DEFAULT))
    {
      api.vrf_id = VRF_DEFAULT;
      api.type = ZEBRA_ROUTE_ISIS;
      api.instance = 0;
      api.flags = 0;
      api.message = 0;
      api.safi = SAFI_UNICAST;
      prefix4.family = AF_INET;
      prefix4.prefixlen = prefix->prefixlen;
      prefix4.prefix = prefix->u.prefix4;
      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient, &prefix4, &api);
    }
  UNSET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);

  return;
}

#ifdef HAVE_IPV6
static void
isis_zebra_route_add_ipv6 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv6 api;
  struct in6_addr **nexthop_list;
  ifindex_t *ifindex_list;
  struct isis_nexthop6 *nexthop6;
  int i, size;
  struct listnode *node;
  struct prefix_ipv6 prefix6;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
    return;

  api.vrf_id = VRF_DEFAULT;
  api.type = ZEBRA_ROUTE_ISIS;
  api.instance = 0;
  api.flags = 0;
  api.message = 0;
  api.safi = SAFI_UNICAST;
  SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
  SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
  SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
  api.metric = route_info->cost;
#if 0
  SET_FLAG (api.message, ZAPI_MESSAGE_DISTANCE);
  api.distance = route_info->depth;
#endif
  api.nexthop_num = listcount (route_info->nexthops6);
  api.ifindex_num = listcount (route_info->nexthops6);

  /* allocate memory for nexthop_list */
  size = sizeof (struct isis_nexthop6 *) * listcount (route_info->nexthops6);
  nexthop_list = (struct in6_addr **) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!nexthop_list)
    {
      zlog_err ("isis_zebra_add_route_ipv6: out of memory!");
      return;
    }

  /* allocate memory for ifindex_list */
  size = sizeof (unsigned int) * listcount (route_info->nexthops6);
  ifindex_list = (ifindex_t *) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!ifindex_list)
    {
      zlog_err ("isis_zebra_add_route_ipv6: out of memory!");
      XFREE (MTYPE_ISIS_TMP, nexthop_list);
      return;
    }

  /* for each nexthop */
  i = 0;
  for (ALL_LIST_ELEMENTS_RO (route_info->nexthops6, node, nexthop6))
    {
      if (!IN6_IS_ADDR_LINKLOCAL (&nexthop6->ip6) &&
	  !IN6_IS_ADDR_UNSPECIFIED (&nexthop6->ip6))
	{
	  api.nexthop_num--;
	  api.ifindex_num--;
	  continue;
	}

      nexthop_list[i] = &nexthop6->ip6;
      ifindex_list[i] = nexthop6->ifindex;
      i++;
    }

  api.nexthop = nexthop_list;
  api.ifindex = ifindex_list;

  if (api.nexthop_num && api.ifindex_num)
    {
      prefix6.family = AF_INET6;
      prefix6.prefixlen = prefix->prefixlen;
      memcpy (&prefix6.prefix, &prefix->u.prefix6, sizeof (struct in6_addr));
      zapi_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, zclient, &prefix6, &api);
      SET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
      UNSET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
    }

  XFREE (MTYPE_ISIS_TMP, nexthop_list);
  XFREE (MTYPE_ISIS_TMP, ifindex_list);

  return;
}

static void
isis_zebra_route_del_ipv6 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv6 api;
  struct in6_addr **nexthop_list;
  ifindex_t *ifindex_list;
  struct isis_nexthop6 *nexthop6;
  int i, size;
  struct listnode *node;
  struct prefix_ipv6 prefix6;

  if (!CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
    return;

  api.vrf_id = VRF_DEFAULT;
  api.type = ZEBRA_ROUTE_ISIS;
  api.instance = 0;
  api.flags = 0;
  api.message = 0;
  api.safi = SAFI_UNICAST;
  SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
  SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
  api.nexthop_num = listcount (route_info->nexthops6);
  api.ifindex_num = listcount (route_info->nexthops6);

  /* allocate memory for nexthop_list */
  size = sizeof (struct isis_nexthop6 *) * listcount (route_info->nexthops6);
  nexthop_list = (struct in6_addr **) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!nexthop_list)
    {
      zlog_err ("isis_zebra_route_del_ipv6: out of memory!");
      return;
    }

  /* allocate memory for ifindex_list */
  size = sizeof (unsigned int) * listcount (route_info->nexthops6);
  ifindex_list = (ifindex_t *) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!ifindex_list)
    {
      zlog_err ("isis_zebra_route_del_ipv6: out of memory!");
      XFREE (MTYPE_ISIS_TMP, nexthop_list);
      return;
    }

  /* for each nexthop */
  i = 0;
  for (ALL_LIST_ELEMENTS_RO (route_info->nexthops6, node, nexthop6))
    {
      if (!IN6_IS_ADDR_LINKLOCAL (&nexthop6->ip6) &&
	  !IN6_IS_ADDR_UNSPECIFIED (&nexthop6->ip6))
	{
	  api.nexthop_num--;
	  api.ifindex_num--;
	  continue;
	}

      nexthop_list[i] = &nexthop6->ip6;
      ifindex_list[i] = nexthop6->ifindex;
      i++;
    }

  api.nexthop = nexthop_list;
  api.ifindex = ifindex_list;

  if (api.nexthop_num && api.ifindex_num)
    {
      prefix6.family = AF_INET6;
      prefix6.prefixlen = prefix->prefixlen;
      memcpy (&prefix6.prefix, &prefix->u.prefix6, sizeof (struct in6_addr));
      zapi_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, zclient, &prefix6, &api);
      UNSET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
    }

  XFREE (MTYPE_ISIS_TMP, nexthop_list);
  XFREE (MTYPE_ISIS_TMP, ifindex_list);
}

#endif /* HAVE_IPV6 */

void
isis_zebra_route_update (struct prefix *prefix,
			 struct isis_route_info *route_info)
{
  if (zclient->sock < 0)
    return;

  if ((prefix->family == AF_INET && !vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_ISIS], VRF_DEFAULT)) ||
      (prefix->family == AF_INET6 && !vrf_bitmap_check (zclient->redist[AFI_IP6][ZEBRA_ROUTE_ISIS], VRF_DEFAULT)))
    return;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ACTIVE))
    {
      if (prefix->family == AF_INET)
	isis_zebra_route_add_ipv4 (prefix, route_info);
#ifdef HAVE_IPV6
      else if (prefix->family == AF_INET6)
	isis_zebra_route_add_ipv6 (prefix, route_info);
#endif /* HAVE_IPV6 */
    }
  else
    {
      if (prefix->family == AF_INET)
	isis_zebra_route_del_ipv4 (prefix, route_info);
#ifdef HAVE_IPV6
      else if (prefix->family == AF_INET6)
	isis_zebra_route_del_ipv6 (prefix, route_info);
#endif /* HAVE_IPV6 */
    }
  return;
}

static int
isis_zebra_read_ipv4 (int command, struct zclient *zclient,
		      zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *stream;
  struct zapi_ipv4 api;
  struct prefix_ipv4 p;
  struct prefix *p_generic = (struct prefix*)&p;

  stream = zclient->ibuf;
  memset(&api, 0, sizeof(api));
  memset (&p, 0, sizeof (struct prefix_ipv4));

  api.type = stream_getc (stream);
  api.instance = stream_getw (stream);
  api.flags = stream_getc (stream);
  api.message = stream_getc (stream);

  p.family = AF_INET;
  p.prefixlen = stream_getc (stream);
  stream_get (&p.prefix, stream, PSIZE (p.prefixlen));

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (stream);
      (void)stream_get_ipv4 (stream);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (stream);
      stream_getl (stream);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (stream);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (stream);

  /*
   * Avoid advertising a false default reachability. (A default
   * route installed by IS-IS gets redistributed from zebra back
   * into IS-IS causing us to start advertising default reachabity
   * without this check)
   */
  if (p.prefixlen == 0 && api.type == ZEBRA_ROUTE_ISIS)
    command = ZEBRA_IPV4_ROUTE_DELETE;

  if (command == ZEBRA_REDISTRIBUTE_IPV4_ADD)
    isis_redist_add(api.type, p_generic, api.distance, api.metric);
  else
    isis_redist_delete(api.type, p_generic);

  return 0;
}

static int
isis_zebra_read_ipv6 (int command, struct zclient *zclient,
		      zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *stream;
  struct zapi_ipv6 api;
  struct prefix_ipv6 p;
  struct prefix *p_generic = (struct prefix*)&p;
  struct in6_addr nexthop;
  unsigned long ifindex __attribute__((unused));

  stream = zclient->ibuf;
  memset(&api, 0, sizeof(api));
  memset(&p, 0, sizeof(struct prefix_ipv6));
  memset(&nexthop, 0, sizeof(nexthop));
  ifindex = 0;

  api.type = stream_getc(stream);
  api.flags = stream_getc(stream);
  api.message = stream_getc(stream);

  p.family = AF_INET6;
  p.prefixlen = stream_getc(stream);
  stream_get(&p.prefix, stream, PSIZE(p.prefixlen));

  if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc(stream); /* this is always 1 */
      stream_get(&nexthop, stream, sizeof(nexthop));
    }
  if (CHECK_FLAG(api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc(stream);
      ifindex = stream_getl(stream);
    }
  if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc(stream);
  if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl(stream);

  /*
   * Avoid advertising a false default reachability. (A default
   * route installed by IS-IS gets redistributed from zebra back
   * into IS-IS causing us to start advertising default reachabity
   * without this check)
   */
  if (p.prefixlen == 0 && api.type == ZEBRA_ROUTE_ISIS)
    command = ZEBRA_IPV6_ROUTE_DELETE;

  if (command == ZEBRA_IPV6_ROUTE_ADD)
    isis_redist_add(api.type, p_generic, api.distance, api.metric);
  else
    isis_redist_delete(api.type, p_generic);

  return 0;
}

int
isis_distribute_list_update (int routetype)
{
  return 0;
}

void
isis_zebra_redistribute_set(int type)
{
  if (type == DEFAULT_ROUTE)
    zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD, zclient, VRF_DEFAULT);
  else
    zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP, type, 0, VRF_DEFAULT);
}

void
isis_zebra_redistribute_unset(int type)
{
  if (type == DEFAULT_ROUTE)
    zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE, zclient, VRF_DEFAULT);
  else
    zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP, type, 0, VRF_DEFAULT);
}

static void
isis_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

void
isis_zebra_init (struct thread_master *master)
{
  zclient = zclient_new (master);
  zclient_init (zclient, ZEBRA_ROUTE_ISIS, 0);
  zclient->zebra_connected = isis_zebra_connected;
  zclient->router_id_update = isis_router_id_update_zebra;
  zclient->interface_add = isis_zebra_if_add;
  zclient->interface_delete = isis_zebra_if_del;
  zclient->interface_up = isis_zebra_if_state_up;
  zclient->interface_down = isis_zebra_if_state_down;
  zclient->interface_address_add = isis_zebra_if_address_add;
  zclient->interface_address_delete = isis_zebra_if_address_del;
  zclient->interface_link_params = isis_zebra_link_params;
  zclient->redistribute_route_ipv4_add = isis_zebra_read_ipv4;
  zclient->redistribute_route_ipv4_del = isis_zebra_read_ipv4;
#ifdef HAVE_IPV6
  zclient->redistribute_route_ipv6_add = isis_zebra_read_ipv6;
  zclient->redistribute_route_ipv6_del = isis_zebra_read_ipv6;
#endif /* HAVE_IPV6 */

  return;
}
