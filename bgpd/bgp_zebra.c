/* zebra client
   Copyright (C) 1997, 98, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"
#include "routemap.h"
#include "thread.h"
#include "queue.h"
#include "memory.h"
#include "lib/json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_bfd.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Growable buffer for nexthops sent to zebra */
struct stream *bgp_nexthop_buf = NULL;
struct stream *bgp_ifindices_buf = NULL;

/* These array buffers are used in making a copy of the attributes for
   route-map apply. Arrays are being used here to minimize mallocs and
   frees for the temporary copy of the attributes.
   Given the zapi api expects the nexthop buffer to contain pointer to
   pointers for nexthops, we couldnt have used a single nexthop variable
   on the stack, hence we had two options:
     1. maintain a linked-list and free it after zapi_*_route call
     2. use an array to avoid number of mallocs.
   Number of supported next-hops are finite, use of arrays should be ok. */
struct attr attr_cp[MULTIPATH_NUM];
struct attr_extra attr_extra_cp[MULTIPATH_NUM];
int    attr_index = 0;

/* Once per address-family initialization of the attribute array */
#define BGP_INFO_ATTR_BUF_INIT()\
do {\
  memset(attr_cp, 0, MULTIPATH_NUM * sizeof(struct attr));\
  memset(attr_extra_cp, 0, MULTIPATH_NUM * sizeof(struct attr_extra));\
  attr_index = 0;\
} while (0)

#define BGP_INFO_ATTR_BUF_COPY(info_src, info_dst)\
do { \
  *info_dst = *info_src; \
  assert(attr_index != MULTIPATH_NUM);\
  attr_cp[attr_index].extra = &attr_extra_cp[attr_index]; \
  bgp_attr_dup (&attr_cp[attr_index], info_src->attr); \
  bgp_attr_deep_dup (&attr_cp[attr_index], info_src->attr); \
  info_dst->attr = &attr_cp[attr_index]; \
  attr_index++;\
} while (0)

#define BGP_INFO_ATTR_BUF_FREE(info) \
do { \
  bgp_attr_deep_free(info->attr); \
} while (0)


/* Can we install into zebra? */
static inline int
bgp_install_info_to_zebra (struct bgp *bgp)
{
  if (zclient->sock <= 0)
    return 0;

  if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
    return 0;

  return 1;
}

/* Router-id update message from zebra. */
static int
bgp_router_id_update (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct prefix router_id;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  zebra_router_id_update_read(zclient->ibuf,&router_id);

  if (BGP_DEBUG (zebra, ZEBRA))
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(&router_id, buf, sizeof(buf));
      zlog_debug("Rx Router Id update VRF %u Id %s", vrf_id, buf);
    }

  if (vrf_id == VRF_DEFAULT)
    {
      /* Router-id change for default VRF has to also update all views. */
      for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
        {
          if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
            continue;

          bgp->router_id_zebra = router_id.u.prefix4;

          if (!bgp->router_id_static.s_addr)
            bgp_router_id_set (bgp, &router_id.u.prefix4);
        }
    }
  else
    {
      bgp = bgp_lookup_by_vrf_id (vrf_id);
      if (bgp)
        {
          bgp->router_id_zebra = router_id.u.prefix4;

          if (!bgp->router_id_static.s_addr)
            bgp_router_id_set (bgp, &router_id.u.prefix4);
        }
    }

  return 0;
}

/* Nexthop update message from zebra. */
static int
bgp_read_nexthop_update (int command, struct zclient *zclient,
			 zebra_size_t length, vrf_id_t vrf_id)
{
  bgp_parse_nexthop_update(command, vrf_id);
  return 0;
}

static int
bgp_read_import_check_update(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
  bgp_parse_nexthop_update(command, vrf_id);
  return 0;
}

/* Set or clear interface on which unnumbered neighbor is configured. This
 * would in turn cause BGP to initiate or turn off IPv6 RAs on this
 * interface.
 */
static void
bgp_update_interface_nbrs (struct bgp *bgp, struct interface *ifp,
                           struct interface *upd_ifp)
{
  struct listnode *node, *nnode;
  struct peer *peer;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->conf_if &&
          (strcmp (peer->conf_if, ifp->name) == 0))
        {
          if (upd_ifp)
	    {
	      peer->ifp = upd_ifp;
	      bgp_zebra_initiate_radv (bgp, peer);
	    }
          else
	    {
	      bgp_zebra_terminate_radv (bgp, peer);
	      peer->ifp = upd_ifp;
	    }
        }
    }
}

static void
bgp_start_interface_nbrs (struct bgp *bgp, struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct peer *peer;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->conf_if &&
          (strcmp (peer->conf_if, ifp->name) == 0) &&
          peer->status != Established)
        {
          if (peer_active(peer))
            BGP_EVENT_ADD (peer, BGP_Stop);
          BGP_EVENT_ADD (peer, BGP_Start);
        }
    }
}

static void
bgp_nbr_connected_add (struct bgp *bgp, struct nbr_connected *ifc)
{
  struct listnode *node;
  struct connected *connected;
  struct interface *ifp;
  struct prefix *p;

  /* Kick-off the FSM for any relevant peers only if there is a
   * valid local address on the interface.
   */
  ifp = ifc->ifp;
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, connected))
    {
      p = connected->address;
      if (p->family == AF_INET6 &&
          IN6_IS_ADDR_LINKLOCAL (&p->u.prefix6))
        break;
    }
  if (!connected)
    return;

  bgp_start_interface_nbrs (bgp, ifp);
}

static void
bgp_nbr_connected_delete (struct bgp *bgp, struct nbr_connected *ifc, int del)
{
  struct listnode *node, *nnode;
  struct peer *peer;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->conf_if && (strcmp (peer->conf_if, ifc->ifp->name) == 0))
        {
          peer->last_reset = PEER_DOWN_NBR_ADDR_DEL;
          BGP_EVENT_ADD (peer, BGP_Stop);
        }
    }
  /* Free neighbor also, if we're asked to. */
  if (del)
    {
      ifp = ifc->ifp;
      listnode_delete (ifp->nbr_connected, ifc);
      nbr_connected_free (ifc);
    }
}

/* Inteface addition message from zebra. */
static int
bgp_interface_add (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct interface *ifp;
  struct bgp *bgp;

  ifp = zebra_interface_add_read (zclient->ibuf, vrf_id);
  if (!ifp) // unexpected
    return 0;

  if (BGP_DEBUG (zebra, ZEBRA) && ifp)
    zlog_debug("Rx Intf add VRF %u IF %s", vrf_id, ifp->name);

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  bgp_update_interface_nbrs (bgp, ifp, ifp);
  return 0;
}

static int
bgp_interface_delete (int command, struct zclient *zclient,
		      zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;
  struct bgp *bgp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);
  if (!ifp) /* This may happen if we've just unregistered for a VRF. */
    return 0;

  ifp->ifindex = IFINDEX_DELETED;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Rx Intf del VRF %u IF %s", vrf_id, ifp->name);

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  bgp_update_interface_nbrs (bgp, ifp, NULL);
  return 0;
}

static int
bgp_interface_up (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct nbr_connected *nc;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);

  if (! ifp)
    return 0;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Rx Intf up VRF %u IF %s", vrf_id, ifp->name);

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_add (bgp, c);

  for (ALL_LIST_ELEMENTS (ifp->nbr_connected, node, nnode, nc))
    bgp_nbr_connected_add (bgp, nc);

  return 0;
}

static int
bgp_interface_down (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct nbr_connected *nc;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);
  if (! ifp)
    return 0;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Rx Intf down VRF %u IF %s", vrf_id, ifp->name);

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_delete (bgp, c);

  for (ALL_LIST_ELEMENTS (ifp->nbr_connected, node, nnode, nc))
    bgp_nbr_connected_delete (bgp, nc, 1);

  /* Fast external-failover */
  {
    struct peer *peer;

    if (CHECK_FLAG (bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
      return 0;

    for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
      {
        if ((peer->ttl != 1) && (peer->gtsm_hops != 1))
          continue;

        if (ifp == peer->nexthop.ifp)
          {
            BGP_EVENT_ADD (peer, BGP_Stop);
            peer->last_reset = PEER_DOWN_IF_DOWN;
          }
      }
  }

  return 0;
}

static int
bgp_interface_address_add (int command, struct zclient *zclient,
			   zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (bgp_debug_zebra(ifc->address))
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Rx Intf address add VRF %u IF %s addr %s",
                 vrf_id, ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    {
      struct bgp *bgp;

      bgp = bgp_lookup_by_vrf_id (vrf_id);
      if (!bgp)
        return 0;

      bgp_connected_add (bgp, ifc);
      /* If we have learnt of any neighbors on this interface,
       * check to kick off any BGP interface-based neighbors,
       * but only if this is a link-local address.
       */
      if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6) &&
          !list_isempty(ifc->ifp->nbr_connected))
        bgp_start_interface_nbrs (bgp, ifc->ifp);
    }

  return 0;
}

static int
bgp_interface_address_delete (int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *ifc;
  struct bgp *bgp;

  ifc = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (bgp_debug_zebra(ifc->address))
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Rx Intf address del VRF %u IF %s addr %s",
                 vrf_id, ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    {
      bgp = bgp_lookup_by_vrf_id (vrf_id);
      if (bgp)
        bgp_connected_delete (bgp, ifc);
    }

  connected_free (ifc);

  return 0;
}

static int
bgp_interface_nbr_address_add (int command, struct zclient *zclient,
			   zebra_size_t length, vrf_id_t vrf_id)
{
  struct nbr_connected *ifc = NULL;
  struct bgp *bgp;

  ifc = zebra_interface_nbr_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (bgp_debug_zebra(ifc->address))
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Rx Intf neighbor add VRF %u IF %s addr %s",
                 vrf_id, ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    {
      bgp = bgp_lookup_by_vrf_id (vrf_id);
      if (bgp)
        bgp_nbr_connected_add (bgp, ifc);
    }

  return 0;
}

static int
bgp_interface_nbr_address_delete (int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
  struct nbr_connected *ifc = NULL;
  struct bgp *bgp;

  ifc = zebra_interface_nbr_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (bgp_debug_zebra(ifc->address))
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(ifc->address, buf, sizeof(buf));
      zlog_debug("Rx Intf neighbor del VRF %u IF %s addr %s",
                 vrf_id, ifc->ifp->name, buf);
    }

  if (if_is_operative (ifc->ifp))
    {
      bgp = bgp_lookup_by_vrf_id (vrf_id);
      if (bgp)
        bgp_nbr_connected_delete (bgp, ifc, 0);
    }

  nbr_connected_free (ifc);

  return 0;
}

/* VRF update for an interface. */
static int
bgp_interface_vrf_update (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct interface *ifp;
  vrf_id_t new_vrf_id;
  struct connected *c;
  struct nbr_connected *nc;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  ifp = zebra_interface_vrf_update_read (zclient->ibuf, vrf_id, &new_vrf_id);
  if (! ifp)
    return 0;

  if (BGP_DEBUG (zebra, ZEBRA) && ifp)
    zlog_debug("Rx Intf VRF change VRF %u IF %s NewVRF %u",
               vrf_id, ifp->name, new_vrf_id);

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_delete (bgp, c);

  for (ALL_LIST_ELEMENTS (ifp->nbr_connected, node, nnode, nc))
    bgp_nbr_connected_delete (bgp, nc, 1);

  /* Fast external-failover */
  {
    struct peer *peer;

    if (CHECK_FLAG (bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
      return 0;

    for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
      {
        if ((peer->ttl != 1) && (peer->gtsm_hops != 1))
          continue;

        if (ifp == peer->nexthop.ifp)
          BGP_EVENT_ADD (peer, BGP_Stop);
      }
  }

  if_update_vrf (ifp, ifp->name, strlen (ifp->name), new_vrf_id);

  bgp = bgp_lookup_by_vrf_id (new_vrf_id);
  if (!bgp)
    return 0;

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_add (bgp, c);

  for (ALL_LIST_ELEMENTS (ifp->nbr_connected, node, nnode, nc))
    bgp_nbr_connected_add (bgp, nc);
  return 0;
}

/* Zebra route add and delete treatment. */
static int
zebra_read_ipv4 (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct stream *s;
  struct zapi_ipv4 api;
  struct in_addr nexthop;
  struct prefix_ipv4 p;
  unsigned int ifindex;
  int i;
  struct bgp *bgp;

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  s = zclient->ibuf;
  nexthop.s_addr = 0;

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

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      nexthop.s_addr = stream_get_ipv4 (s);
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s); /* ifindex, unused */
    }
  else
    {
      ifindex = 0;
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_TAG))
    api.tag = stream_getw (s);
  else
    api.tag = 0;

  if (command == ZEBRA_REDISTRIBUTE_IPV4_ADD)
    {
      if (bgp_debug_zebra((struct prefix *)&p))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Rx IPv4 route add VRF %u %s[%d] %s/%d nexthop %s metric %u tag %d",
                     vrf_id,
		     zebra_route_string(api.type), api.instance,
		     inet_ntop(AF_INET, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric,
		     api.tag);
	}

      /*
       * The ADD message is actually an UPDATE and there is no explicit DEL
       * for a prior redistributed route, if any. So, perform an implicit
       * DEL processing for the same redistributed route from any other
       * source type.
       */
      for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
        {
          if (i != api.type)
            bgp_redistribute_delete(bgp, (struct prefix *)&p, i, api.instance);
        }

      /* Now perform the add/update. */
      bgp_redistribute_add(bgp, (struct prefix *)&p, &nexthop, NULL, ifindex,
			   api.metric, api.type, api.instance, api.tag);
    }
  else if (command == ZEBRA_REDISTRIBUTE_IPV4_DEL)
    {
      if (bgp_debug_zebra((struct prefix *)&p))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Rx IPv4 route delete VRF %u %s[%d] %s/%d "
		     "nexthop %s metric %u tag %d",
                     vrf_id,
		     zebra_route_string(api.type), api.instance,
		     inet_ntop(AF_INET, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric,
		     api.tag);
	}
      bgp_redistribute_delete(bgp, (struct prefix *)&p, api.type, api.instance);
    }

  return 0;
}

#ifdef HAVE_IPV6
/* Zebra route add and delete treatment. */
static int
zebra_read_ipv6 (int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
  struct stream *s;
  struct zapi_ipv6 api;
  struct in6_addr nexthop;
  struct prefix_ipv6 p;
  unsigned int ifindex;
  int i;
  struct bgp *bgp;

  bgp = bgp_lookup_by_vrf_id (vrf_id);
  if (!bgp)
    return 0;

  s = zclient->ibuf;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.instance = stream_getw (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv6 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get (&nexthop, s, 16);
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s); /* ifindex, unused */
    }
  else
    {
      ifindex = 0;
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_TAG))
    api.tag = stream_getw (s);
  else
    api.tag = 0;

  /* Simply ignore link-local address. */
  if (IN6_IS_ADDR_LINKLOCAL (&p.prefix))
    return 0;

  if (command == ZEBRA_REDISTRIBUTE_IPV6_ADD)
    {
      if (bgp_debug_zebra((struct prefix *)&p))
	{
	  char buf[2][INET6_ADDRSTRLEN];
	  zlog_debug("Rx IPv6 route add VRF %u %s[%d] %s/%d nexthop %s metric %u tag %d",
                     vrf_id,
		     zebra_route_string(api.type), api.instance,
		     inet_ntop(AF_INET6, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric,
		     api.tag);
	}

      /*
       * The ADD message is actually an UPDATE and there is no explicit DEL
       * for a prior redistributed route, if any. So, perform an implicit
       * DEL processing for the same redistributed route from any other
       * source type.
       */
      for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
        {
          if (i != api.type)
            bgp_redistribute_delete(bgp, (struct prefix *)&p, i, api.instance);
        }

      bgp_redistribute_add (bgp, (struct prefix *)&p, NULL, &nexthop, ifindex,
			    api.metric, api.type, api.instance, api.tag);
    }
  else if (command == ZEBRA_REDISTRIBUTE_IPV6_DEL)
    {
      if (bgp_debug_zebra((struct prefix *)&p))
	{
	  char buf[2][INET6_ADDRSTRLEN];
	  zlog_debug("Rx IPv6 route delete VRF %u %s[%d] %s/%d "
		     "nexthop %s metric %u tag %d",
                     vrf_id,
		     zebra_route_string(api.type), api.instance,
		     inet_ntop(AF_INET6, &p.prefix, buf[0], sizeof(buf[0])),
		     p.prefixlen,
		     inet_ntop(AF_INET6, &nexthop, buf[1], sizeof(buf[1])),
		     api.metric,
                     api.tag);
	}
      bgp_redistribute_delete (bgp, (struct prefix *) &p, api.type, api.instance);
    }
  
  return 0;
}
#endif /* HAVE_IPV6 */

struct interface *
if_lookup_by_ipv4 (struct in_addr *addr, vrf_id_t vrf_id)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv4 p;
  struct prefix *cp; 
  
  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist(vrf_id), ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET)
	    if (prefix_match (cp, (struct prefix *)&p))
	      return ifp;
	}
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv4_exact (struct in_addr *addr, vrf_id_t vrf_id)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist(vrf_id), ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET)
	    if (IPV4_ADDR_SAME (&cp->u.prefix4, addr))
	      return ifp;
	}
    }
  return NULL;
}

#ifdef HAVE_IPV6
struct interface *
if_lookup_by_ipv6 (struct in6_addr *addr, unsigned int ifindex, vrf_id_t vrf_id)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv6 p;
  struct prefix *cp; 
  
  p.family = AF_INET6;
  p.prefix = *addr;
  p.prefixlen = IPV6_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist(vrf_id), ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    if (prefix_match (cp, (struct prefix *)&p))
	      {
		if (IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6.s6_addr32[0]))
		  {
		    if (ifindex == ifp->ifindex)
		      return ifp;
		  }
		else
		  return ifp;
	      }
	}
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv6_exact (struct in6_addr *addr, unsigned int ifindex, vrf_id_t vrf_id)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp; 

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist(vrf_id), ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
	{
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    if (IPV6_ADDR_SAME (&cp->u.prefix6, addr))
	      {
		if (IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6))
		  {
		    if (ifindex == ifp->ifindex)
		      return ifp;
		  }
		else
		  return ifp;
	      }
	}
    }
  return NULL;
}

static int
if_get_ipv6_global (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (! IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}

static int
if_get_ipv6_local (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}
#endif /* HAVE_IPV6 */

static int
if_get_ipv4_address (struct interface *ifp, struct in_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp;

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;
      if ((cp->family == AF_INET) && !ipv4_martian(&(cp->u.prefix4)))
	  {
	    *addr = cp->u.prefix4;
	    return 1;
	  }
    }
  return 0;
}

int
bgp_nexthop_set (union sockunion *local, union sockunion *remote, 
		 struct bgp_nexthop *nexthop, struct peer *peer)
{
  int ret = 0;
  struct interface *ifp = NULL;

  memset (nexthop, 0, sizeof (struct bgp_nexthop));

  if (!local)
    return -1;
  if (!remote)
    return -1;

  if (local->sa.sa_family == AF_INET)
    {
      nexthop->v4 = local->sin.sin_addr;
      if (peer->update_if)
        ifp = if_lookup_by_name_vrf (peer->update_if, peer->bgp->vrf_id);
      else
        ifp = if_lookup_by_ipv4_exact (&local->sin.sin_addr, peer->bgp->vrf_id);
    }
#ifdef HAVE_IPV6
  if (local->sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  if (peer->conf_if || peer->ifname)
	    ifp = if_lookup_by_index_vrf (if_nametoindex (peer->conf_if ? peer->conf_if : peer->ifname), peer->bgp->vrf_id);
	}
      else if (peer->update_if)
        ifp = if_lookup_by_name_vrf (peer->update_if, peer->bgp->vrf_id);
      else
        ifp = if_lookup_by_ipv6_exact (&local->sin6.sin6_addr,
				       local->sin6.sin6_scope_id,
                                       peer->bgp->vrf_id);
    }
#endif /* HAVE_IPV6 */

  if (!ifp)
    return -1;

  nexthop->ifp = ifp;

  /* IPv4 connection, fetch and store IPv6 local address(es) if any. */
  if (local->sa.sa_family == AF_INET)
    {
#ifdef HAVE_IPV6
      /* IPv6 nexthop*/
      ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

      if (!ret)
        {
          /* There is no global nexthop. Use link-local address as both the
           * global and link-local nexthop. In this scenario, the expectation
           * for interop is that the network admin would use a route-map to
           * specify the global IPv6 nexthop.
           */
          if_get_ipv6_local (ifp, &nexthop->v6_global);
          memcpy (&nexthop->v6_local, &nexthop->v6_global,
                  IPV6_MAX_BYTELEN);
        }
      else
	if_get_ipv6_local (ifp, &nexthop->v6_local);

      if (if_lookup_by_ipv4 (&remote->sin.sin_addr, peer->bgp->vrf_id))
        peer->shared_network = 1;
      else
        peer->shared_network = 0;
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* IPv6 connection, fetch and store IPv4 local address if any. */
  if (local->sa.sa_family == AF_INET6)
    {
      struct interface *direct = NULL;

      /* IPv4 nexthop. */
      ret = if_get_ipv4_address(ifp, &nexthop->v4);
      if (!ret && peer->local_id.s_addr)
	nexthop->v4 = peer->local_id;

      /* Global address*/
      if (! IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		  IPV6_MAX_BYTELEN);

	  /* If directory connected set link-local address. */
	  direct = if_lookup_by_ipv6 (&remote->sin6.sin6_addr,
				      remote->sin6.sin6_scope_id, peer->bgp->vrf_id);
	  if (direct)
	    if_get_ipv6_local (ifp, &nexthop->v6_local);
	}
      else
	/* Link-local address. */
	{
	  ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

	  /* If there is no global address.  Set link-local address as
             global.  I know this break RFC specification... */
          /* In this scenario, the expectation for interop is that the
           * network admin would use a route-map to specify the global
           * IPv6 nexthop.
           */
	  if (!ret)
	    memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		    IPV6_MAX_BYTELEN);
          /* Always set the link-local address */
          memcpy (&nexthop->v6_local, &local->sin6.sin6_addr,
                  IPV6_MAX_BYTELEN);
	}

      if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr) ||
          if_lookup_by_ipv6 (&remote->sin6.sin6_addr, remote->sin6.sin6_scope_id,
                             peer->bgp->vrf_id))
        peer->shared_network = 1;
      else
        peer->shared_network = 0;
    }

  /* KAME stack specific treatment.  */
#ifdef KAME
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_global)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_global))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_global, 0);
    }
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_local)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_local))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_local, 0);
    }
#endif /* KAME */
#endif /* HAVE_IPV6 */

  /* If we have identified the local interface, there is no error for now. */
  return 0;
}

static struct in6_addr *
bgp_info_to_ipv6_nexthop (struct bgp_info *info)
{
  struct in6_addr *nexthop = NULL;

  /* Only global address nexthop exists. */
  if (info->attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL)
    nexthop = &info->attr->extra->mp_nexthop_global;

  /* If both global and link-local address present. */
  if (info->attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
    {
      /* Workaround for Cisco's nexthop bug.  */
      if (IN6_IS_ADDR_UNSPECIFIED (&info->attr->extra->mp_nexthop_global)
          && info->peer->su_remote->sa.sa_family == AF_INET6)
        nexthop = &info->peer->su_remote->sin6.sin6_addr;
      else
        nexthop = &info->attr->extra->mp_nexthop_local;
    }

  return nexthop;
}

static int
bgp_table_map_apply (struct route_map *map, struct prefix *p,
                     struct bgp_info *info)
{
  if (route_map_apply(map, p, RMAP_BGP, info) != RMAP_DENYMATCH)
    return 1;

  if (bgp_debug_zebra(p))
    {
      if (p->family == AF_INET)
        {
          char buf[2][INET_ADDRSTRLEN];
          zlog_debug("Zebra rmap deny: IPv4 route %s/%d nexthop %s",
                     inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
                     p->prefixlen,
                     inet_ntop(AF_INET, &info->attr->nexthop, buf[1],
                               sizeof(buf[1])));
        }
      if (p->family == AF_INET6)
        {
          char buf[2][INET6_ADDRSTRLEN];
          zlog_debug("Zebra rmap deny: IPv6 route %s/%d nexthop %s",
                     inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
                     p->prefixlen,
                     inet_ntop(AF_INET6, bgp_info_to_ipv6_nexthop(info), buf[1],
                               sizeof(buf[1])));
        }
    }
  return 0;
}

void
bgp_zebra_announce (struct prefix *p, struct bgp_info *info, struct bgp *bgp,
                    afi_t afi, safi_t safi)
{
  int flags;
  u_char distance;
  struct peer *peer;
  struct bgp_info *mpinfo;
  size_t oldsize, newsize;
  u_int32_t nhcount, metric;
  struct bgp_info local_info;
  struct bgp_info *info_cp = &local_info;
  u_short tag;

  /* Don't try to install if we're not connected to Zebra or Zebra doesn't
   * know of this instance.
   */
  if (!bgp_install_info_to_zebra (bgp))
    return;

  if ((p->family == AF_INET &&
       !vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_BGP], bgp->vrf_id))
      || (p->family == AF_INET6 &&
       !vrf_bitmap_check (zclient->redist[AFI_IP6][ZEBRA_ROUTE_BGP], bgp->vrf_id)))
    return;

  if (bgp->main_zebra_update_hold)
    return;

  flags = 0;
  peer = info->peer;

  if ((info->attr->extra) && (info->attr->extra->tag != 0))
    tag = info->attr->extra->tag;
  else
    tag = 0;

  /* When we create an aggregate route we must also install a Null0 route in
   * the RIB */
  if (info->sub_type == BGP_ROUTE_AGGREGATE)
      SET_FLAG (flags, ZEBRA_FLAG_BLACKHOLE);

  if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED ||
      info->sub_type == BGP_ROUTE_AGGREGATE)
    {
      SET_FLAG (flags, ZEBRA_FLAG_IBGP);
      SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);
    }

  if ((peer->sort == BGP_PEER_EBGP && peer->ttl != 1)
      || CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
      || bgp_flag_check(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))

    SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);

  nhcount = 1 + bgp_info_mpath_count (info);

  if (p->family == AF_INET && !BGP_ATTR_NEXTHOP_AFI_IP6(info->attr))
    {
      struct zapi_ipv4 api;
      struct in_addr *nexthop;
      char buf[2][INET_ADDRSTRLEN];
      int valid_nh_count = 0;

      /* resize nexthop buffer size if necessary */
      if ((oldsize = stream_get_size (bgp_nexthop_buf)) <
          (sizeof (struct in_addr *) * nhcount))
        {
          newsize = (sizeof (struct in_addr *) * nhcount);
          newsize = stream_resize (bgp_nexthop_buf, newsize);
          if (newsize == oldsize)
            {
	          zlog_err ("can't resize nexthop buffer");
	          return;
            }
        }
      stream_reset (bgp_nexthop_buf);
      nexthop = NULL;

      /* Metric is currently based on the best-path only. */
      metric = info->attr->med;

      if (bgp->table_map[afi][safi].name)
        {
          BGP_INFO_ATTR_BUF_INIT();

          /* Copy info and attributes, so the route-map apply doesn't modify the
             BGP route info. */
          BGP_INFO_ATTR_BUF_COPY(info, info_cp);
          if (bgp_table_map_apply(bgp->table_map[afi][safi].map, p, info_cp))
            {
              metric = info_cp->attr->med;
              nexthop = &info_cp->attr->nexthop;

              if (info_cp->attr->extra)
                tag = info_cp->attr->extra->tag;
            }
          BGP_INFO_ATTR_BUF_FREE(info_cp);
        }
      else
        {
          nexthop = &info->attr->nexthop;
        }

      if (nexthop)
        {
          stream_put (bgp_nexthop_buf, &nexthop, sizeof (struct in_addr *));
          valid_nh_count++;
        }

      for (mpinfo = bgp_info_mpath_first (info); mpinfo;
           mpinfo = bgp_info_mpath_next (mpinfo))
        {
          nexthop = NULL;

          if (bgp->table_map[afi][safi].name)
            {
              /* Copy info and attributes, so the route-map apply doesn't modify the
                 BGP route info. */
              BGP_INFO_ATTR_BUF_COPY(mpinfo, info_cp);
              if (bgp_table_map_apply(bgp->table_map[afi][safi].map, p, info_cp))
                nexthop = &info_cp->attr->nexthop;
              BGP_INFO_ATTR_BUF_FREE(info_cp);
            }
          else
            {
              nexthop = &mpinfo->attr->nexthop;
            }

          if (nexthop == NULL)
            continue;

          stream_put (bgp_nexthop_buf, &nexthop, sizeof (struct in_addr *));
          valid_nh_count++;
        }

      api.vrf_id = bgp->vrf_id;
      api.flags = flags;
      api.type = ZEBRA_ROUTE_BGP;
      api.instance = 0;
      api.message = 0;
      api.safi = safi;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);

      /* Note that this currently only applies to Null0 routes for aggregates.
       * ZEBRA_FLAG_BLACKHOLE signals zapi_ipv4_route to encode a special
       * BLACKHOLE nexthop. We want to set api.nexthop_num to zero since we
       * do not want to also encode the 0.0.0.0 nexthop for the aggregate route.
       */
      if (CHECK_FLAG(flags, ZEBRA_FLAG_BLACKHOLE))
        api.nexthop_num = 0;
      else
        api.nexthop_num = valid_nh_count;

      api.nexthop = (struct in_addr **)STREAM_DATA (bgp_nexthop_buf);
      api.ifindex_num = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = metric;
      api.tag = 0;

      if (tag)
        {
          SET_FLAG (api.message, ZAPI_MESSAGE_TAG);
          api.tag = tag;
        }

      distance = bgp_distance_apply (p, info, bgp);

      if (distance)
	{
	  SET_FLAG (api.message, ZAPI_MESSAGE_DISTANCE);
	  api.distance = distance;
	}

      if (bgp_debug_zebra(p))
        {
          int i;
          zlog_debug("Tx IPv4 route %s VRF %u %s/%d metric %u tag %d"
                     " count %d", (valid_nh_count ? "add":"delete"),
                     bgp->vrf_id,
                     inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
                     p->prefixlen, api.metric, api.tag, api.nexthop_num);
          for (i = 0; i < api.nexthop_num; i++)
            zlog_debug("  IPv4 [nexthop %d] %s", i+1,
                       inet_ntop(AF_INET, api.nexthop[i], buf[1], sizeof(buf[1])));
        }

      zapi_ipv4_route (valid_nh_count ? ZEBRA_IPV4_ROUTE_ADD: ZEBRA_IPV4_ROUTE_DELETE,
                       zclient, (struct prefix_ipv4 *) p, &api);
    }
#ifdef HAVE_IPV6

  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6 ||
      (p->family == AF_INET && BGP_ATTR_NEXTHOP_AFI_IP6(info->attr)))
    {
      unsigned int ifindex;
      struct in6_addr *nexthop;
      struct zapi_ipv6 api;
      int valid_nh_count = 0;
	    char buf[2][INET6_ADDRSTRLEN];

      /* resize nexthop buffer size if necessary */
      if ((oldsize = stream_get_size (bgp_nexthop_buf)) <
          (sizeof (struct in6_addr *) * nhcount))
        {
          newsize = (sizeof (struct in6_addr *) * nhcount);
          newsize = stream_resize (bgp_nexthop_buf, newsize);
          if (newsize == oldsize)
            {
              zlog_err ("can't resize nexthop buffer");
              return;
            }
        }
      stream_reset (bgp_nexthop_buf);

      /* resize ifindices buffer size if necessary */
      if ((oldsize = stream_get_size (bgp_ifindices_buf)) <
          (sizeof (unsigned int) * nhcount))
        {
          newsize = (sizeof (unsigned int) * nhcount);
          newsize = stream_resize (bgp_ifindices_buf, newsize);
          if (newsize == oldsize)
            {
              zlog_err ("can't resize nexthop buffer");
              return;
            }
        }
      stream_reset (bgp_ifindices_buf);

      ifindex = 0;
      nexthop = NULL;

      assert (info->attr->extra);

      /* Metric is currently based on the best-path only. */
      metric = info->attr->med;

      if (bgp->table_map[afi][safi].name)
        {
          BGP_INFO_ATTR_BUF_INIT();

          /* Copy info and attributes, so the route-map apply doesn't modify the
             BGP route info. */
          BGP_INFO_ATTR_BUF_COPY(info, info_cp);
          if (bgp_table_map_apply(bgp->table_map[afi][safi].map, p, info_cp))
            {
              metric = info_cp->attr->med;
              nexthop = bgp_info_to_ipv6_nexthop(info_cp);

              if (info_cp->attr->extra)
                tag = info_cp->attr->extra->tag;
            }
          BGP_INFO_ATTR_BUF_FREE(info_cp);
        }
      else
        {
           nexthop = bgp_info_to_ipv6_nexthop(info);
        }

      if (nexthop)
        {
          if (info->attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
            if (info->peer->nexthop.ifp)
              ifindex = info->peer->nexthop.ifp->ifindex;

          if (!ifindex)
	    {
	      if (info->peer->conf_if || info->peer->ifname)
		ifindex = if_nametoindex (info->peer->conf_if ? info->peer->conf_if : info->peer->ifname);
	      else if (info->peer->nexthop.ifp)
		ifindex = info->peer->nexthop.ifp->ifindex;
	    }
          stream_put (bgp_nexthop_buf, &nexthop, sizeof (struct in6_addr *));
          stream_put (bgp_ifindices_buf, &ifindex, sizeof (unsigned int));
          valid_nh_count++;
        }

      for (mpinfo = bgp_info_mpath_first (info); mpinfo;
           mpinfo = bgp_info_mpath_next (mpinfo))
        {
          ifindex = 0;
          nexthop = NULL;

          if (bgp->table_map[afi][safi].name)
            {
              /* Copy info and attributes, so the route-map apply doesn't modify the
                 BGP route info. */
              BGP_INFO_ATTR_BUF_COPY(mpinfo, info_cp);
              if (bgp_table_map_apply(bgp->table_map[afi][safi].map, p, info_cp))
                nexthop = bgp_info_to_ipv6_nexthop(info_cp);
              BGP_INFO_ATTR_BUF_FREE(info_cp);
            }
          else
            {
              nexthop = bgp_info_to_ipv6_nexthop(mpinfo);
            }

          if (nexthop == NULL)
            continue;

          if (mpinfo->attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
            if (mpinfo->peer->nexthop.ifp)
              ifindex = mpinfo->peer->nexthop.ifp->ifindex;

          if (!ifindex)
	    {
	      if (mpinfo->peer->conf_if || mpinfo->peer->ifname)
		ifindex = if_nametoindex (mpinfo->peer->conf_if ? mpinfo->peer->conf_if : mpinfo->peer->ifname);
	      else if (mpinfo->peer->nexthop.ifp)
		ifindex = mpinfo->peer->nexthop.ifp->ifindex;
	    }
          if (ifindex == 0)
            continue;

          stream_put (bgp_nexthop_buf, &nexthop, sizeof (struct in6_addr *));
          stream_put (bgp_ifindices_buf, &ifindex, sizeof (unsigned int));
          valid_nh_count++;
        }

      /* Make Zebra API structure. */
      api.vrf_id = bgp->vrf_id;
      api.flags = flags;
      api.type = ZEBRA_ROUTE_BGP;
      api.instance = 0;
      api.message = 0;
      api.safi = safi;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);

      /* Note that this currently only applies to Null0 routes for aggregates.
       * ZEBRA_FLAG_BLACKHOLE signals zapi_ipv6_route to encode a special
       * BLACKHOLE nexthop. We want to set api.nexthop_num to zero since we
       * do not want to also encode the :: nexthop for the aggregate route.
       */
      if (CHECK_FLAG(flags, ZEBRA_FLAG_BLACKHOLE))
        api.nexthop_num = 0;
      else
        api.nexthop_num = valid_nh_count;

      api.nexthop = (struct in6_addr **)STREAM_DATA (bgp_nexthop_buf);
      SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
      api.ifindex_num = valid_nh_count;
      api.ifindex = (unsigned int *)STREAM_DATA (bgp_ifindices_buf);
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = metric;
      api.tag = 0;

      if (tag)
        {
          SET_FLAG (api.message, ZAPI_MESSAGE_TAG);
          api.tag = tag;
        }

      if (p->family == AF_INET)
        {
          if (bgp_debug_zebra(p))
            {
              int i;
              zlog_debug("Tx IPv4 route %s VRF %u %s/%d metric %u tag %d",
                         valid_nh_count ? "add" : "delete", bgp->vrf_id,
                         inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
                         p->prefixlen, api.metric, api.tag);
              for (i = 0; i < api.nexthop_num; i++)
                zlog_debug("  IPv6 [nexthop %d] %s", i+1,
                           inet_ntop(AF_INET6, api.nexthop[i], buf[1], sizeof(buf[1])));
            }

          if (valid_nh_count)
            zapi_ipv4_route_ipv6_nexthop (ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD,
                                          zclient, (struct prefix_ipv4 *) p,
					  (struct zapi_ipv6 *)&api);
          else
            zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE,
                             zclient, (struct prefix_ipv4 *) p, (struct zapi_ipv4 *)&api);
        }
      else
        {
          if (bgp_debug_zebra(p))
            {
              int i;
              zlog_debug("Tx IPv6 route %s VRF %u %s/%d metric %u tag %d",
                         valid_nh_count ? "add" : "delete", bgp->vrf_id,
                         inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
                         p->prefixlen, api.metric, api.tag);
              for (i = 0; i < api.nexthop_num; i++)
                zlog_debug("  IPv6 [nexthop %d] %s", i+1,
                           inet_ntop(AF_INET6, api.nexthop[i], buf[1], sizeof(buf[1])));
            }

          zapi_ipv6_route (valid_nh_count ?
                           ZEBRA_IPV6_ROUTE_ADD : ZEBRA_IPV6_ROUTE_DELETE,
                           zclient, (struct prefix_ipv6 *) p, &api);
        }
    }
#endif /* HAVE_IPV6 */
}

/* Announce all routes of a table to zebra */
void
bgp_zebra_announce_table (struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  /* Don't try to install if we're not connected to Zebra or Zebra doesn't
   * know of this instance.
   */
  if (!bgp_install_info_to_zebra (bgp))
    return;

  table = bgp->rib[afi][safi];
  if (!table) return;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ri = rn->info; ri; ri = ri->next)
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
          && ri->type == ZEBRA_ROUTE_BGP
          && ri->sub_type == BGP_ROUTE_NORMAL)
        bgp_zebra_announce (&rn->p, ri, bgp, afi, safi);
}

void
bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info, safi_t safi)
{
  int flags;
  struct peer *peer;

  peer = info->peer;
  assert(peer);

  /* Don't try to install if we're not connected to Zebra or Zebra doesn't
   * know of this instance.
   */
  if (!bgp_install_info_to_zebra (peer->bgp))
    return;

  if ((p->family == AF_INET &&
       !vrf_bitmap_check (zclient->redist[AFI_IP][ZEBRA_ROUTE_BGP], peer->bgp->vrf_id))
      || (p->family == AF_INET6 &&
       !vrf_bitmap_check (zclient->redist[AFI_IP6][ZEBRA_ROUTE_BGP], peer->bgp->vrf_id)))
    return;

  flags = 0;

  if (peer->sort == BGP_PEER_IBGP)
    {
      SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);
      SET_FLAG (flags, ZEBRA_FLAG_IBGP);
    }

  if ((peer->sort == BGP_PEER_EBGP && peer->ttl != 1)
      || CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
      || bgp_flag_check(peer->bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
    SET_FLAG (flags, ZEBRA_FLAG_INTERNAL);

  if (p->family == AF_INET)
    {
      struct zapi_ipv4 api;

      api.vrf_id = peer->bgp->vrf_id;
      api.flags = flags;

      api.type = ZEBRA_ROUTE_BGP;
      api.instance = 0;
      api.message = 0;
      api.safi = safi;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 0;
      api.nexthop = NULL;
      api.ifindex_num = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;
      api.tag = 0;

      if ((info->attr->extra) && (info->attr->extra->tag != 0))
        {
          SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
          api.tag = info->attr->extra->tag;
        }

      if (bgp_debug_zebra(p))
	{
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_debug("Tx IPv4 route delete VRF %u %s/%d metric %u tag %d",
                     peer->bgp->vrf_id,
		     inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
		     p->prefixlen, api.metric, api.tag);
	}

      zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient, 
                       (struct prefix_ipv4 *) p, &api);
    }
#ifdef HAVE_IPV6
  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6)
    {
      struct zapi_ipv6 api;
      
      assert (info->attr->extra);
      
      api.vrf_id = peer->bgp->vrf_id;
      api.flags = flags;
      api.type = ZEBRA_ROUTE_BGP;
      api.instance = 0;
      api.message = 0;
      api.safi = safi;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      api.nexthop_num = 0;
      api.nexthop = NULL;
      api.ifindex_num = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = info->attr->med;
      api.tag = 0;

      if ((info->attr->extra) && (info->attr->extra->tag != 0))
        {
          SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
          api.tag = info->attr->extra->tag;
        }

      if (bgp_debug_zebra(p))
	{
	  char buf[2][INET6_ADDRSTRLEN];
	  zlog_debug("Tx IPv6 route delete VRF %u %s/%d metric %u tag %d",
                     peer->bgp->vrf_id,
		     inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
		     p->prefixlen, api.metric, api.tag);
	}

      zapi_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, zclient, 
                       (struct prefix_ipv6 *) p, &api);
    }
#endif /* HAVE_IPV6 */
}
struct bgp_redist *
bgp_redist_lookup (struct bgp *bgp, afi_t afi, u_char type, u_short instance)
{
  struct list *red_list;
  struct listnode *node;
  struct bgp_redist *red;

  red_list = bgp->redist[afi][type];
  if (!red_list)
    return(NULL);

  for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
    if (red->instance == instance)
      return red;

  return NULL;
}

struct bgp_redist *
bgp_redist_add (struct bgp *bgp, afi_t afi, u_char type, u_short instance)
{
  struct list *red_list;
  struct bgp_redist *red;

  red = bgp_redist_lookup(bgp, afi, type, instance);
  if (red)
    return red;

  if (!bgp->redist[afi][type])
    bgp->redist[afi][type] = list_new();

  red_list = bgp->redist[afi][type];
  red = (struct bgp_redist *)XCALLOC(MTYPE_BGP_REDIST, sizeof(struct bgp_redist));
  red->instance = instance;

  listnode_add(red_list, red);

  return red;
}

static void
bgp_redist_del (struct bgp *bgp, afi_t afi, u_char type, u_short instance)
{
  struct bgp_redist *red;

  red = bgp_redist_lookup(bgp, afi, type, instance);

  if (red)
    {
      listnode_delete(bgp->redist[afi][type], red);
      if (!bgp->redist[afi][type]->count)
        {
          list_free(bgp->redist[afi][type]);
          bgp->redist[afi][type] = NULL;
        }
    }
}

/* Other routes redistribution into BGP. */
int
bgp_redistribute_set (struct bgp *bgp, afi_t afi, int type, u_short instance)
{

  /* Return if already redistribute flag is set. */
  if (instance)
    {
      if (redist_check_instance(&zclient->mi_redist[afi][type], instance))
        return CMD_WARNING;

      redist_add_instance(&zclient->mi_redist[afi][type], instance);
    }
  else
    {
      if (vrf_bitmap_check (zclient->redist[afi][type], bgp->vrf_id))
        return CMD_WARNING;

      vrf_bitmap_set (zclient->redist[afi][type], bgp->vrf_id);
    }

  /* Don't try to register if we're not connected to Zebra or Zebra doesn't
   * know of this instance.
   */
  if (!bgp_install_info_to_zebra (bgp))
    return CMD_WARNING;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Tx redistribute add VRF %u afi %d %s %d",
               bgp->vrf_id, afi,
               zebra_route_string(type), instance);

  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
                           instance, bgp->vrf_id);

  return CMD_SUCCESS;
}

int
bgp_redistribute_resend (struct bgp *bgp, afi_t afi, int type, u_short instance)
{
  /* Don't try to send if we're not connected to Zebra or Zebra doesn't
   * know of this instance.
   */
  if (!bgp_install_info_to_zebra (bgp))
    return -1;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Tx redistribute del/add VRF %u afi %d %s %d",
               bgp->vrf_id, afi,
               zebra_route_string(type), instance);

  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, afi, type,
                           instance, bgp->vrf_id);
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
                           instance, bgp->vrf_id);

  return 0;
}

/* Redistribute with route-map specification.  */
int
bgp_redistribute_rmap_set (struct bgp_redist *red, const char *name)
{
  if (red->rmap.name
      && (strcmp (red->rmap.name, name) == 0))
    return 0;

  if (red->rmap.name)
    XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
  red->rmap.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
  red->rmap.map = route_map_lookup_by_name (name);

  return 1;
}

/* Redistribute with metric specification.  */
int
bgp_redistribute_metric_set (struct bgp *bgp, struct bgp_redist *red, afi_t afi,
			     int type, u_int32_t metric)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  if (red->redist_metric_flag
      && red->redist_metric == metric)
    return 0;

  red->redist_metric_flag = 1;
  red->redist_metric = metric;

  for (rn = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); rn; rn = bgp_route_next(rn)) {
    for (ri = rn->info; ri; ri = ri->next) {
      if (ri->sub_type == BGP_ROUTE_REDISTRIBUTE && ri->type == type &&
	  ri->instance == red->instance) {
	  ri->attr->med = red->redist_metric;
	  bgp_info_set_flag(rn, ri, BGP_INFO_ATTR_CHANGED);
	  bgp_process(bgp, rn, afi, SAFI_UNICAST);
      }
    }
  }

  return 1;
}

/* Unset redistribution.  */
int
bgp_redistribute_unreg (struct bgp *bgp, afi_t afi, int type, u_short instance)
{
  struct bgp_redist *red;

  red = bgp_redist_lookup(bgp, afi, type, instance);
  if (!red)
    return CMD_SUCCESS;

  /* Return if zebra connection is disabled. */
  if (instance)
    {
      if (!redist_check_instance(&zclient->mi_redist[afi][type], instance))
        return CMD_WARNING;
      redist_del_instance(&zclient->mi_redist[afi][type], instance);
    }
  else
    {
      if (! vrf_bitmap_check (zclient->redist[afi][type], bgp->vrf_id))
        return CMD_WARNING;
      vrf_bitmap_unset (zclient->redist[afi][type], bgp->vrf_id);
    }

  if (bgp_install_info_to_zebra (bgp))
    {
      /* Send distribute delete message to zebra. */
      if (BGP_DEBUG (zebra, ZEBRA))
	zlog_debug("Tx redistribute del VRF %u afi %d %s %d",
		   bgp->vrf_id, afi, zebra_route_string(type), instance);
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, afi, type, instance,
                               bgp->vrf_id);
    }
  
  /* Withdraw redistributed routes from current BGP's routing table. */
  bgp_redistribute_withdraw (bgp, afi, type, instance);

  return CMD_SUCCESS;
}

/* Unset redistribution.  */
int
bgp_redistribute_unset (struct bgp *bgp, afi_t afi, int type, u_short instance)
{
  struct bgp_redist *red;

  red = bgp_redist_lookup(bgp, afi, type, instance);
  if (!red)
    return CMD_SUCCESS;

  bgp_redistribute_unreg(bgp, afi, type, instance);

  /* Unset route-map. */
  if (red->rmap.name)
    XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
  red->rmap.name = NULL;
  red->rmap.map = NULL;

  /* Unset metric. */
  red->redist_metric_flag = 0;
  red->redist_metric = 0;

  bgp_redist_del(bgp, afi, type, instance);

  return CMD_SUCCESS;
}

void
bgp_zclient_reset (void)
{
  zclient_reset (zclient);
}

/* Register this instance with Zebra. Invoked upon connect (for
 * default instance) and when other VRFs are learnt (or created and
 * already learnt).
 */
void
bgp_zebra_instance_register (struct bgp *bgp)
{
  /* Don't try to register if we're not connected to Zebra */
  if (!zclient || zclient->sock < 0)
    return;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Registering VRF %u", bgp->vrf_id);

  /* Register for router-id, interfaces, redistributed routes. */
  zclient_send_reg_requests (zclient, bgp->vrf_id);
}

/* Deregister this instance with Zebra. Invoked upon the instance
 * being deleted (default or VRF) and it is already registered.
 */
void
bgp_zebra_instance_deregister (struct bgp *bgp)
{
  /* Don't try to deregister if we're not connected to Zebra */
  if (zclient->sock < 0)
    return;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Deregistering VRF %u", bgp->vrf_id);

  /* Deregister for router-id, interfaces, redistributed routes. */
  zclient_send_dereg_requests (zclient, bgp->vrf_id);
}

void
bgp_zebra_initiate_radv (struct bgp *bgp, struct peer *peer)
{
  int ra_interval = BGP_UNNUM_DEFAULT_RA_INTERVAL;

  /* Don't try to initiate if we're not connected to Zebra */
  if (zclient->sock < 0)
    return;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("%u: Initiating RA for peer %s", bgp->vrf_id, peer->host);

  zclient_send_interface_radv_req (zclient, bgp->vrf_id, peer->ifp, 1, ra_interval);
}

void
bgp_zebra_terminate_radv (struct bgp *bgp, struct peer *peer)
{
  /* Don't try to terminate if we're not connected to Zebra */
  if (zclient->sock < 0)
    return;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("%u: Terminating RA for peer %s", bgp->vrf_id, peer->host);

  zclient_send_interface_radv_req (zclient, bgp->vrf_id, peer->ifp, 0, 0);
}

/* BGP has established connection with Zebra. */
static void
bgp_zebra_connected (struct zclient *zclient)
{
  struct bgp *bgp;

  /* At this point, we may or may not have BGP instances configured, but
   * we're only interested in the default VRF (others wouldn't have learnt
   * the VRF from Zebra yet.)
   */
  bgp = bgp_get_default();
  if (!bgp)
    return;

  bgp_zebra_instance_register (bgp);

  /* TODO - What if we have peers and networks configured, do we have to
   * kick-start them?
   */
}


void
bgp_zebra_init (struct thread_master *master)
{
  /* Set default values. */
  zclient = zclient_new (master);
  zclient_init (zclient, ZEBRA_ROUTE_BGP, 0);
  zclient->zebra_connected = bgp_zebra_connected;
  zclient->router_id_update = bgp_router_id_update;
  zclient->interface_add = bgp_interface_add;
  zclient->interface_delete = bgp_interface_delete;
  zclient->interface_address_add = bgp_interface_address_add;
  zclient->interface_address_delete = bgp_interface_address_delete;
  zclient->interface_nbr_address_add = bgp_interface_nbr_address_add;
  zclient->interface_nbr_address_delete = bgp_interface_nbr_address_delete;
  zclient->interface_vrf_update = bgp_interface_vrf_update;
  zclient->ipv4_route_add = zebra_read_ipv4;
  zclient->ipv4_route_delete = zebra_read_ipv4;
  zclient->redistribute_route_ipv4_add = zebra_read_ipv4;
  zclient->redistribute_route_ipv4_del = zebra_read_ipv4;
  zclient->interface_up = bgp_interface_up;
  zclient->interface_down = bgp_interface_down;
  zclient->ipv6_route_add = zebra_read_ipv6;
  zclient->ipv6_route_delete = zebra_read_ipv6;
  zclient->redistribute_route_ipv6_add = zebra_read_ipv6;
  zclient->redistribute_route_ipv6_del = zebra_read_ipv6;
  zclient->nexthop_update = bgp_read_nexthop_update;
  zclient->import_check_update = bgp_read_import_check_update;

  bgp_nexthop_buf = stream_new(BGP_NEXTHOP_BUF_SIZE);
  bgp_ifindices_buf = stream_new(BGP_IFINDICES_BUF_SIZE);
}
