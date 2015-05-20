/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
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

#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_nht.h"

extern struct zclient *zclient;
extern struct bgp_table *bgp_nexthop_cache_table[AFI_MAX];

static void register_nexthop(struct bgp_nexthop_cache *bnc);
static void unregister_nexthop (struct bgp_nexthop_cache *bnc);
static void evaluate_paths(struct bgp_nexthop_cache *bnc);
static int make_prefix(int afi, struct bgp_info *ri, struct prefix *p);
static void path_nh_map(struct bgp_info *path, struct bgp_nexthop_cache *bnc,
			int keep);

int
bgp_find_nexthop (struct bgp_info *path, int connected)
{
  struct bgp_nexthop_cache *bnc = path->nexthop;

  if (!bnc)
    return 0;

  if (connected && !(CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)))
    return 0;

  return (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID));
}

void
bgp_unlink_nexthop (struct bgp_info *path)
{
  struct bgp_nexthop_cache *bnc = path->nexthop;

  if (!bnc)
    return;

  path_nh_map(path, NULL, 0);

  if (LIST_EMPTY(&(bnc->paths)) && !bnc->nht_info)
    {
      if (BGP_DEBUG(nht, NHT))
	{
	  char buf[INET6_ADDRSTRLEN];
	  zlog_debug("bgp_unlink_nexthop: freeing bnc %s",
		     bnc_str(bnc, buf, INET6_ADDRSTRLEN));
	}
      unregister_nexthop(bnc);
      bnc->node->info = NULL;
      bgp_unlock_node(bnc->node);
      bnc_free(bnc);
    }
}

int
bgp_find_or_add_nexthop (struct bgp *bgp, afi_t afi, struct bgp_info *ri,
                         struct peer *peer, int connected)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  struct prefix p;

  if (ri)
    {
      if (make_prefix(afi, ri, &p) < 0)
	return 1;
    }
  else if (peer)
    {
      if (afi == AFI_IP)
	{
	  p.family = AF_INET;
	  p.prefixlen = IPV4_MAX_BITLEN;
	  p.u.prefix4 = peer->su.sin.sin_addr;
	}
      else if (afi == AFI_IP6)
	{
	  p.family = AF_INET6;
	  p.prefixlen = IPV6_MAX_BITLEN;
	  p.u.prefix6 = peer->su.sin6.sin6_addr;
	}
    }

  rn = bgp_node_get (bgp_nexthop_cache_table[afi], &p);

  if (!rn->info)
    {
      bnc = bnc_new();
      rn->info = bnc;
      bnc->node = rn;
      bnc->bgp = bgp;
      bgp_lock_node(rn);
      if (connected)
	SET_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED);
      if (BGP_DEBUG(nht, NHT))
        {
          char buf[INET6_ADDRSTRLEN];

          zlog_debug("Allocated bnc %s peer %p",
                     bnc_str(bnc, buf, INET6_ADDRSTRLEN), peer);
        }
    }

  bnc = rn->info;
  bgp_unlock_node (rn);

  if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
    register_nexthop(bnc);

  if (ri)
    {
      path_nh_map(ri, bnc, 1);

      if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) && bnc->metric)
	(bgp_info_extra_get(ri))->igpmetric = bnc->metric;
      else if (ri->extra)
	ri->extra->igpmetric = 0;
    }
  else if (peer)
    bnc->nht_info = (void *)peer;

  return (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID));
}

void
bgp_delete_connected_nexthop (afi_t afi, struct peer *peer)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  struct prefix p;

  if (afi == AFI_IP)
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = peer->su.sin.sin_addr;
    }
  else if (afi == AFI_IP6)
    {
      p.family = AF_INET6;
      p.prefixlen = IPV6_MAX_BITLEN;
      p.u.prefix6 = peer->su.sin6.sin6_addr;
    }

  rn = bgp_node_lookup(bgp_nexthop_cache_table[family2afi(p.family)], &p);
  if (!rn || !rn->info)
    {
      if (BGP_DEBUG(nht, NHT))
        zlog_debug("Cannot find connected NHT node for peer %s", peer->host);
      if (rn)
        bgp_unlock_node (rn);
      return;
    }

  bnc = rn->info;
  bgp_unlock_node(rn);

  if (bnc->nht_info != peer)
    {
      if (BGP_DEBUG(nht, NHT))
        zlog_debug("Connected NHT %p node for peer %s points to %p",
                    bnc, peer->host, bnc->nht_info);
      return;
    }

  bnc->nht_info = NULL;

  if (LIST_EMPTY(&(bnc->paths)))
    {
      if (BGP_DEBUG(nht, NHT))
        zlog_debug("Freeing connected NHT node %p for peer %s",
                    bnc,  peer->host);
      unregister_nexthop(bnc);
      bnc->node->info = NULL;
      bgp_unlock_node(bnc->node);
      bnc_free(bnc);
    }
}

void
bgp_parse_nexthop_update (void)
{
  struct stream *s;
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  struct nexthop *nexthop;
  struct nexthop *oldnh;
  struct nexthop *nhlist_head = NULL;
  struct nexthop *nhlist_tail = NULL;
  uint32_t metric;
  u_char nexthop_num;
  struct prefix p;
  int i;

  s = zclient->ibuf;

  memset(&p, 0, sizeof(struct prefix));
  p.family = stream_getw(s);
  p.prefixlen = stream_getc(s);
  switch (p.family)
    {
    case AF_INET:
      p.u.prefix4.s_addr = stream_get_ipv4 (s);
      break;
    case AF_INET6:
      stream_get(&p.u.prefix6, s, 16);
      break;
    default:
      break;
    }

  rn = bgp_node_lookup(bgp_nexthop_cache_table[family2afi(p.family)], &p);
  if (!rn || !rn->info)
    {
      if (BGP_DEBUG(nht, NHT))
	{
	  char buf[INET6_ADDRSTRLEN];
	  prefix2str(&p, buf, INET6_ADDRSTRLEN);
	  zlog_debug("parse nexthop update(%s): rn not found", buf);
	}
      return;
    }

  bnc = rn->info;
  bnc->last_update = bgp_clock();
  bnc->change_flags = 0;
  metric = stream_getl (s);
  nexthop_num = stream_getc (s);

  /* debug print the input */
  if (BGP_DEBUG(nht, NHT))
    {
      char buf[INET6_ADDRSTRLEN];
      prefix2str(&p, buf, INET6_ADDRSTRLEN);
      zlog_debug("parse nexthop update(%s): metric=%d, #nexthop=%d", buf,
		 metric, nexthop_num);
    }

  if (metric != bnc->metric)
    bnc->change_flags |= BGP_NEXTHOP_METRIC_CHANGED;

  if(nexthop_num != bnc->nexthop_num)
    bnc->change_flags |= BGP_NEXTHOP_CHANGED;

  if (nexthop_num)
    {
      bnc->flags |= BGP_NEXTHOP_VALID;
      bnc->metric = metric;
      bnc->nexthop_num = nexthop_num;

      for (i = 0; i < nexthop_num; i++)
	{
	  nexthop = nexthop_new();
	  nexthop->type = stream_getc (s);
	  switch (nexthop->type)
	    {
	    case ZEBRA_NEXTHOP_IPV4:
	      nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
	      break;
	    case ZEBRA_NEXTHOP_IFINDEX:
	    case ZEBRA_NEXTHOP_IFNAME:
	      nexthop->ifindex = stream_getl (s);
	      break;
            case ZEBRA_NEXTHOP_IPV4_IFINDEX:
	    case ZEBRA_NEXTHOP_IPV4_IFNAME:
	      nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
	      nexthop->ifindex = stream_getl (s);
	      break;
#ifdef HAVE_IPV6
            case ZEBRA_NEXTHOP_IPV6:
	      stream_get (&nexthop->gate.ipv6, s, 16);
	      break;
            case ZEBRA_NEXTHOP_IPV6_IFINDEX:
	    case ZEBRA_NEXTHOP_IPV6_IFNAME:
	      stream_get (&nexthop->gate.ipv6, s, 16);
	      nexthop->ifindex = stream_getl (s);
	      break;
#endif
            default:
              /* do nothing */
              break;
	    }

	  if (nhlist_tail)
	    {
	      nhlist_tail->next = nexthop;
	      nhlist_tail = nexthop;
	    }
	  else
	    {
	      nhlist_tail = nexthop;
	      nhlist_head = nexthop;
	    }

	  /* No need to evaluate the nexthop if we have already determined
	   * that there has been a change.
	   */
	  if (bnc->change_flags & BGP_NEXTHOP_CHANGED)
	    continue;

	  for (oldnh = bnc->nexthop; oldnh; oldnh = oldnh->next)
	      if (nexthop_same_no_recurse(oldnh, nexthop))
		  break;

	  if (!oldnh)
	    bnc->change_flags |= BGP_NEXTHOP_CHANGED;
	}
      bnc_nexthop_free(bnc);
      bnc->nexthop = nhlist_head;
    }
  else
    {
      bnc->flags &= ~BGP_NEXTHOP_VALID;
      UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
      bnc_nexthop_free(bnc);
      bnc->nexthop = NULL;
    }

  evaluate_paths(bnc);
}

/**
 * make_prefix - make a prefix structure from the path (essentially
 * path's node.
 */
static int
make_prefix (int afi, struct bgp_info *ri, struct prefix *p)
{
  memset (p, 0, sizeof (struct prefix));
  switch (afi)
    {
    case AFI_IP:
      p->family = AF_INET;
      p->prefixlen = IPV4_MAX_BITLEN;
      p->u.prefix4 = ri->attr->nexthop;
      break;
#ifdef HAVE_IPV6
    case AFI_IP6:
      if (ri->attr->extra->mp_nexthop_len != 16
	  || IN6_IS_ADDR_LINKLOCAL (&ri->attr->extra->mp_nexthop_global))
	return -1;

      p->family = AF_INET6;
      p->prefixlen = IPV6_MAX_BITLEN;
      p->u.prefix6 = ri->attr->extra->mp_nexthop_global;
      break;
#endif
    default:
      break;
    }
  return 0;
}

/**
 * sendmsg_nexthop -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 *   int command -- either ZEBRA_NEXTHOP_REGISTER or ZEBRA_NEXTHOP_UNREGISTER
 * RETURNS:
 *   void.
 */
static void
sendmsg_nexthop (struct bgp_nexthop_cache *bnc, int command)
{
  struct stream *s;
  struct prefix *p;
  int ret;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    {
      zlog_debug("%s: Can't send NH register, Zebra client not established",
		 __FUNCTION__);
      return;
    }

  p = &(bnc->node->p);
  s = zclient->obuf;
  stream_reset (s);
  zclient_create_header (s, command);
  if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
    stream_putc(s, 1);
  else
    stream_putc(s, 0);

  stream_putw(s, PREFIX_FAMILY(p));
  stream_putc(s, p->prefixlen);
  switch (PREFIX_FAMILY(p))
    {
    case AF_INET:
      stream_put_in_addr (s, &p->u.prefix4);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      stream_put(s, &(p->u.prefix6), 16);
      break;
#endif
    default:
      break;
    }
  stream_putw_at (s, 0, stream_get_endp (s));

  ret = zclient_send_message(zclient);
  /* TBD: handle the failure */
  if (ret < 0)
    zlog_warn("sendmsg_nexthop: zclient_send_message() failed");

  if (command == ZEBRA_NEXTHOP_REGISTER)
    SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
  else if (command == ZEBRA_NEXTHOP_UNREGISTER)
    UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
  return;
}

/**
 * register_nexthop - register a nexthop with Zebra for notification
 *    when the route to the nexthop changes.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 * RETURNS:
 *   void.
 */
static void
register_nexthop (struct bgp_nexthop_cache *bnc)
{
  /* Check if we have already registered */
  if (bnc->flags & BGP_NEXTHOP_REGISTERED)
    return;
  sendmsg_nexthop(bnc, ZEBRA_NEXTHOP_REGISTER);
}

/**
 * unregister_nexthop -- Unregister the nexthop from Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 * RETURNS:
 *   void.
 */
static void
unregister_nexthop (struct bgp_nexthop_cache *bnc)
{
  /* Check if we have already registered */
  if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
    return;

  sendmsg_nexthop(bnc, ZEBRA_NEXTHOP_UNREGISTER);
}

/**
 * evaluate_paths - Evaluate the paths/nets associated with a nexthop.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 * RETURNS:
 *   void.
 */
static void
evaluate_paths (struct bgp_nexthop_cache *bnc)
{
  struct bgp_node *rn;
  struct bgp_info *path;
  struct bgp *bgp = bnc->bgp;
  int afi;
  struct peer *peer = (struct peer *)bnc->nht_info;

  LIST_FOREACH(path, &(bnc->paths), nh_thread)
    {
      if (!(path->type == ZEBRA_ROUTE_BGP &&
	    path->sub_type == BGP_ROUTE_NORMAL))
	continue;

      rn = path->net;
      afi = family2afi(rn->p.family);

      /* Path becomes valid/invalid depending on whether the nexthop
       * reachable/unreachable.
       */
      if ((CHECK_FLAG(path->flags, BGP_INFO_VALID) ? 1 : 0) !=
	  (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) ? 1 : 0))
	{
	  if (CHECK_FLAG (path->flags, BGP_INFO_VALID))
	    {
	      bgp_aggregate_decrement (bgp, &rn->p, path,
				       afi, SAFI_UNICAST);
	      bgp_info_unset_flag (rn, path, BGP_INFO_VALID);
	    }
	  else
	    {
	      bgp_info_set_flag (rn, path, BGP_INFO_VALID);
	      bgp_aggregate_increment (bgp, &rn->p, path,
				       afi, SAFI_UNICAST);
	    }
	}

      /* Copy the metric to the path. Will be used for bestpath computation */
      if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) && bnc->metric)
	(bgp_info_extra_get(path))->igpmetric = bnc->metric;
      else if (path->extra)
	path->extra->igpmetric = 0;

      if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_METRIC_CHANGED) ||
	  CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CHANGED))
	SET_FLAG(path->flags, BGP_INFO_IGP_CHANGED);

      bgp_process(bgp, rn, afi, SAFI_UNICAST);
    }

  if (peer && !CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED))
    {
      if (BGP_DEBUG(nht, NHT))
	zlog_debug("%s: Updating peer (%s) status with NHT", __FUNCTION__, peer->host);
      bgp_fsm_nht_update(peer, CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID));
      SET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
    }

  RESET_FLAG(bnc->change_flags);
}

/**
 * path_nh_map - make or break path-to-nexthop association.
 * ARGUMENTS:
 *   path - pointer to the path structure
 *   bnc - pointer to the nexthop structure
 *   make - if set, make the association. if unset, just break the existing
 *          association.
 */
static void
path_nh_map (struct bgp_info *path, struct bgp_nexthop_cache *bnc, int make)
{
  if (path->nexthop)
    {
      LIST_REMOVE(path, nh_thread);
      path->nexthop->path_count--;
      path->nexthop = NULL;
    }
  if (make)
    {
      LIST_INSERT_HEAD(&(bnc->paths), path, nh_thread);
      path->nexthop = bnc;
      path->nexthop->path_count++;
    }
}
