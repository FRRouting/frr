/*
 * IS-IS Rout(e)ing protocol - isis_zebra.c   
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
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

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"

struct zclient *zclient = NULL;

extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
int
isis_router_id_update_zebra (int command, struct zclient *zclient,
			     zebra_size_t length)
{
  struct prefix router_id;

  zebra_router_id_update_read (zclient->ibuf,&router_id);
  router_id_zebra = router_id.u.prefix4;

  /* FIXME: Do we react somehow? */
  return 0;
}

int
isis_zebra_if_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);


  zlog_debug ("Zebra I/F add: %s index %d flags %ld metric %d mtu %d",
	      ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  if (if_is_operative (ifp))
    isis_csm_state_change (IF_UP_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  return 0;
}

int
isis_zebra_if_del (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;
  struct stream *s;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);

  if (!ifp)
    return 0;

  if (if_is_operative (ifp))
    zlog_warn ("Zebra: got delete of %s, but interface is still up",
	       ifp->name);

  zlog_debug ("Zebra I/F delete: %s index %d flags %ld metric %d mtu %d",
	      ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  if_delete (ifp);

  isis_csm_state_change (IF_DOWN_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  return 0;
}

struct interface *
zebra_interface_if_lookup (struct stream *s)
{
  struct interface *ifp;
  u_char ifname_tmp[INTERFACE_NAMSIZ];

  /* Read interface name. */
  stream_get (ifname_tmp, s, INTERFACE_NAMSIZ);

  /* Lookup this by interface index. */
  ifp = if_lookup_by_name ((char *) ifname_tmp);

  /* If such interface does not exist, indicate an error */
  if (!ifp)
    return NULL;

  return ifp;
}

int
isis_zebra_if_state_up (int command, struct zclient *zclient,
			zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_if_lookup (zclient->ibuf);

  if (!ifp)
    return 0;

  if (if_is_operative (ifp))
    {
      zebra_interface_if_set_value (zclient->ibuf, ifp);
      /* HT: This is wrong actually. We can't assume that circuit exist
       * if we delete circuit during if_state_down event. Needs rethink.
       * TODO */
      isis_circuit_update_params (circuit_scan_by_ifp (ifp), ifp);
      return 0;
    }

  zebra_interface_if_set_value (zclient->ibuf, ifp);
  isis_csm_state_change (IF_UP_FROM_Z, circuit_scan_by_ifp (ifp), ifp);

  return 0;
}

int
isis_zebra_if_state_down (int command, struct zclient *zclient,
			  zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_if_lookup (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  if (if_is_operative (ifp))
    {
      zebra_interface_if_set_value (zclient->ibuf, ifp);
      isis_csm_state_change (IF_DOWN_FROM_Z, circuit_scan_by_ifp (ifp), ifp);
    }

  return 0;
}

int
isis_zebra_if_address_add (int command, struct zclient *zclient,
			   zebra_size_t length)
{
  struct connected *c;
  struct prefix *p;
  char buf[BUFSIZ];

  c = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_ADD,
				    zclient->ibuf);

  if (c == NULL)
    return 0;

  p = c->address;

  prefix2str (p, buf, BUFSIZ);
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

int
isis_zebra_if_address_del (int command, struct zclient *client,
			   zebra_size_t length)
{
  struct connected *c;
  struct interface *ifp;
#ifdef EXTREME_DEBUG
  struct prefix *p;
  u_char buf[BUFSIZ];
#endif /* EXTREME_DEBUG */

  c = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_DELETE,
				    zclient->ibuf);

  if (c == NULL)
    return 0;

  ifp = c->ifp;

#ifdef EXTREME_DEBUG
  p = c->address;
  prefix2str (p, buf, BUFSIZ);

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

void
isis_zebra_route_add_ipv4 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  u_char message, flags;
  int psize;
  struct stream *stream;
  struct isis_nexthop *nexthop;
  struct listnode *node;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC))
    return;

  if (zclient->redist[ZEBRA_ROUTE_ISIS])
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
      /* Length place holder. */
      stream_putw (stream, 0);
      /* command */
      stream_putc (stream, ZEBRA_IPV4_ROUTE_ADD);
      /* type */
      stream_putc (stream, ZEBRA_ROUTE_ISIS);
      /* flags */
      stream_putc (stream, flags);
      /* message */
      stream_putc (stream, message);
      /* prefix information */
      psize = PSIZE (prefix->prefixlen);
      stream_putc (stream, prefix->prefixlen);
      stream_write (stream, (u_char *) & prefix->u.prefix4, psize);

      stream_putc (stream, listcount (route_info->nexthops));

      /* Nexthop, ifindex, distance and metric information */
      for (node = listhead (route_info->nexthops); node; nextnode (node))
	{
	  nexthop = getdata (node);
	  /* FIXME: can it be ? */
	  if (nexthop->ip.s_addr != INADDR_ANY)
	    {
	      stream_putc (stream, ZEBRA_NEXTHOP_IPV4);
	      stream_put_in_addr (stream, &nexthop->ip);
	    }
	  else
	    {
	      stream_putc (stream, ZEBRA_NEXTHOP_IFINDEX);
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
      writen (zclient->sock, stream->data, stream_get_endp (stream));
    }
}

void
isis_zebra_route_del_ipv4 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv4 api;
  struct prefix_ipv4 prefix4;

  if (zclient->redist[ZEBRA_ROUTE_ISIS])
    {
      api.type = ZEBRA_ROUTE_ISIS;
      api.flags = 0;
      api.message = 0;
      prefix4.family = AF_INET;
      prefix4.prefixlen = prefix->prefixlen;
      prefix4.prefix = prefix->u.prefix4;
      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient, &prefix4, &api);
    }

  return;
}

#ifdef HAVE_IPV6
void
isis_zebra_route_add_ipv6 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv6 api;
  struct in6_addr **nexthop_list;
  unsigned int *ifindex_list;
  struct isis_nexthop6 *nexthop6;
  int i, size;
  struct listnode *node;
  struct prefix_ipv6 prefix6;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC))
    return;

  api.type = ZEBRA_ROUTE_ISIS;
  api.flags = 0;
  api.message = 0;
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
  ifindex_list = (unsigned int *) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!ifindex_list)
    {
      zlog_err ("isis_zebra_add_route_ipv6: out of memory!");
      XFREE (MTYPE_ISIS_TMP, nexthop_list);
      return;
    }

  /* for each nexthop */
  i = 0;
  for (node = listhead (route_info->nexthops6); node; nextnode (node))
    {
      nexthop6 = getdata (node);

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
      SET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC);
    }

  XFREE (MTYPE_ISIS_TMP, nexthop_list);
  XFREE (MTYPE_ISIS_TMP, ifindex_list);

  return;
}

void
isis_zebra_route_del_ipv6 (struct prefix *prefix,
			   struct isis_route_info *route_info)
{
  struct zapi_ipv6 api;
  struct in6_addr **nexthop_list;
  unsigned int *ifindex_list;
  struct isis_nexthop6 *nexthop6;
  int i, size;
  struct listnode *node;
  struct prefix_ipv6 prefix6;

  if (CHECK_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC))
    return;

  api.type = ZEBRA_ROUTE_ISIS;
  api.flags = 0;
  api.message = 0;
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
  ifindex_list = (unsigned int *) XMALLOC (MTYPE_ISIS_TMP, size);
  if (!ifindex_list)
    {
      zlog_err ("isis_zebra_route_del_ipv6: out of memory!");
      XFREE (MTYPE_ISIS_TMP, nexthop_list);
      return;
    }

  /* for each nexthop */
  i = 0;
  for (node = listhead (route_info->nexthops6); node; nextnode (node))
    {
      nexthop6 = getdata (node);

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
      UNSET_FLAG (route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNC);
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

  if (!zclient->redist[ZEBRA_ROUTE_ISIS])
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

int
isis_zebra_read_ipv4 (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  struct stream *stream;
  struct zapi_ipv4 api;
  struct prefix_ipv4 p;
  unsigned long ifindex;
  struct in_addr nexthop;

  stream = zclient->ibuf;
  memset (&p, 0, sizeof (struct prefix_ipv4));
  ifindex = 0;

  api.type = stream_getc (stream);
  api.flags = stream_getc (stream);
  api.message = stream_getc (stream);

  p.family = AF_INET;
  p.prefixlen = stream_getc (stream);
  stream_get (&p.prefix, stream, PSIZE (p.prefixlen));

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (stream);
      nexthop.s_addr = stream_get_ipv4 (stream);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (stream);
      ifindex = stream_getl (stream);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (stream);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (stream);
  else
    api.metric = 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {
      zlog_debug ("IPv4 Route add from Z");
    }

  return 0;
}

int
isis_zebra_read_ipv6 (int command, struct zclient *zclient,
		      zebra_size_t length)
{
  return 0;
}

#define ISIS_TYPE_IS_REDISTRIBUTED(T) \
T == ZEBRA_ROUTE_MAX ? zclient->default_information : zclient->redist[type]

int
isis_distribute_list_update (int routetype)
{
  return 0;
}

int
isis_redistribute_default_set (int routetype, int metric_type,
			       int metric_value)
{
  return 0;
}

void
isis_zebra_init ()
{
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_ISIS);
  zclient->router_id_update = isis_router_id_update_zebra;
  zclient->interface_add = isis_zebra_if_add;
  zclient->interface_delete = isis_zebra_if_del;
  zclient->interface_up = isis_zebra_if_state_up;
  zclient->interface_down = isis_zebra_if_state_down;
  zclient->interface_address_add = isis_zebra_if_address_add;
  zclient->interface_address_delete = isis_zebra_if_address_del;
  zclient->ipv4_route_add = isis_zebra_read_ipv4;
  zclient->ipv4_route_delete = isis_zebra_read_ipv4;
#ifdef HAVE_IPV6
  zclient->ipv6_route_add = isis_zebra_read_ipv6;
  zclient->ipv6_route_delete = isis_zebra_read_ipv6;
#endif /* HAVE_IPV6 */

  return;
}

void
isis_zebra_finish ()
{
  zclient_stop (zclient);
  zclient_free (zclient);
  zclient = (struct zclient *) NULL;

  return;
}
