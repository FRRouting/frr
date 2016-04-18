/*
 * Static Routing Information code
 * Copyright (C) 2016 Cumulus Networks
 *               Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include <lib/nexthop.h>
#include <lib/memory.h>

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_static.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_memory.h"

/* Install static route into rib. */
void
static_install_route (afi_t afi, safi_t safi, struct prefix *p, struct static_route *si)
{
  struct rib *rib;
  struct route_node *rn;
  struct route_table *table;
  struct prefix nh_p;

  /* Lookup table.  */
  table = zebra_vrf_table (afi, safi, si->vrf_id);
  if (! table)
    return;

  /* Lookup existing route */
  rn = route_node_get (table, p);
  RNODE_FOREACH_RIB (rn, rib)
    {
       if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
         continue;

       if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
         break;
    }

  if (rib)
    {
      /* if tag value changed , update old value in RIB */
      if (rib->tag != si->tag)
        rib->tag = si->tag;

      /* Same distance static route is there.  Update it with new
         nexthop. */
      route_unlock_node (rn);
      switch (si->type)
        {
	case STATIC_IPV4_GATEWAY:
	  rib_nexthop_ipv4_add (rib, &si->addr.ipv4, NULL);
	  nh_p.family = AF_INET;
	  nh_p.prefixlen = IPV4_MAX_BITLEN;
	  nh_p.u.prefix4 = si->addr.ipv4;
	  zebra_register_rnh_static_nh(si->vrf_id, &nh_p, rn);
	  break;
	case STATIC_IFINDEX:
	  rib_nexthop_ifindex_add (rib, si->ifindex);
	  break;
	case STATIC_IPV4_BLACKHOLE:
	  rib_nexthop_blackhole_add (rib);
	  break;
	case STATIC_IPV6_GATEWAY:
	  rib_nexthop_ipv6_add (rib, &si->addr.ipv6);
	  nh_p.family = AF_INET6;
	  nh_p.prefixlen = IPV6_MAX_BITLEN;
	  nh_p.u.prefix6 = si->addr.ipv6;
	  zebra_register_rnh_static_nh(si->vrf_id, &nh_p, rn);
	  break;
	case STATIC_IPV6_GATEWAY_IFINDEX:
	  rib_nexthop_ipv6_ifindex_add (rib, &si->addr.ipv6, si->ifindex);
	  break;
        }

      if (IS_ZEBRA_DEBUG_RIB)
        {
          char buf[INET6_ADDRSTRLEN];
          if (IS_ZEBRA_DEBUG_RIB)
            {
              inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
              zlog_debug ("%u:%s/%d: Modifying route rn %p, rib %p (type %d)",
                          si->vrf_id, buf, p->prefixlen, rn, rib, rib->type);
            }
        }
      /* Schedule route for processing or invoke NHT, as appropriate. */
      if (si->type == STATIC_IPV4_GATEWAY ||
          si->type == STATIC_IPV6_GATEWAY)
        zebra_evaluate_rnh(si->vrf_id, nh_p.family, 1, RNH_NEXTHOP_TYPE, &nh_p);
      else
        rib_queue_add (rn);
    }
  else
    {
      /* This is new static route. */
      rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

      rib->type = ZEBRA_ROUTE_STATIC;
      rib->instance = 0;
      rib->distance = si->distance;
      rib->metric = 0;
      rib->mtu = 0;
      rib->vrf_id = si->vrf_id;
      rib->table =  si->vrf_id ? (zebra_vrf_lookup(si->vrf_id))->table_id : zebrad.rtm_table_default;
      rib->nexthop_num = 0;
      rib->tag = si->tag;

      switch (si->type)
        {
	case STATIC_IPV4_GATEWAY:
	  rib_nexthop_ipv4_add (rib, &si->addr.ipv4, NULL);
	  nh_p.family = AF_INET;
	  nh_p.prefixlen = IPV4_MAX_BITLEN;
	  nh_p.u.prefix4 = si->addr.ipv4;
	  zebra_register_rnh_static_nh(si->vrf_id, &nh_p, rn);
	  break;
	case STATIC_IFINDEX:
	  rib_nexthop_ifindex_add (rib, si->ifindex);
	  break;
	case STATIC_IPV4_BLACKHOLE:
	  rib_nexthop_blackhole_add (rib);
	  break;
	case STATIC_IPV6_GATEWAY:
	  rib_nexthop_ipv6_add (rib, &si->addr.ipv6);
	  nh_p.family = AF_INET6;
	  nh_p.prefixlen = IPV6_MAX_BITLEN;
	  nh_p.u.prefix6 = si->addr.ipv6;
	  zebra_register_rnh_static_nh(si->vrf_id, &nh_p, rn);
	  break;
	case STATIC_IPV6_GATEWAY_IFINDEX:
	  rib_nexthop_ipv6_ifindex_add (rib, &si->addr.ipv6, si->ifindex);
	  break;
        }

      /* Save the flags of this static routes (reject, blackhole) */
      rib->flags = si->flags;

      if (IS_ZEBRA_DEBUG_RIB)
        {
          char buf[INET6_ADDRSTRLEN];
          if (IS_ZEBRA_DEBUG_RIB)
            {
              inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
              zlog_debug ("%u:%s/%d: Inserting route rn %p, rib %p (type %d)",
                          si->vrf_id, buf, p->prefixlen, rn, rib, rib->type);
            }
        }
      /* Link this rib to the tree. Schedule for processing or invoke NHT,
       * as appropriate.
       */
      if (si->type == STATIC_IPV4_GATEWAY ||
          si->type == STATIC_IPV6_GATEWAY)
        {
          rib_addnode (rn, rib, 0);
          zebra_evaluate_rnh(si->vrf_id, nh_p.family, 1, RNH_NEXTHOP_TYPE, &nh_p);
        }
      else
        rib_addnode (rn, rib, 1);
    }
}

static int
static_nexthop_same (struct nexthop *nexthop, struct static_route *si)
{
  if (nexthop->type == NEXTHOP_TYPE_IPV4
      && si->type == STATIC_IPV4_GATEWAY
      && IPV4_ADDR_SAME (&nexthop->gate.ipv4, &si->addr.ipv4))
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IFINDEX
      && si->type == STATIC_IFINDEX
      && nexthop->ifindex == si->ifindex)
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE
      && si->type == STATIC_IPV4_BLACKHOLE)
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IPV6
      && si->type == STATIC_IPV6_GATEWAY
      && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->addr.ipv6))
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX
      && si->type == STATIC_IPV6_GATEWAY_IFINDEX
      && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->addr.ipv6)
      && nexthop->ifindex == si->ifindex)
    return 1;
  return 0;
}

/* Uninstall static route from RIB. */
void
static_uninstall_route (afi_t afi, safi_t safi, struct prefix *p, struct static_route *si)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;
  struct route_table *table;
  struct prefix nh_p;

  /* Lookup table.  */
  table = zebra_vrf_table (afi, safi, si->vrf_id);
  if (! table)
    return;

  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (table, p);
  if (! rn)
    return;

  RNODE_FOREACH_RIB (rn, rib)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance &&
          rib->tag == si->tag)
        break;
    }

  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (static_nexthop_same (nexthop, si))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }

  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    rib_delnode (rn, rib);
  else
    {
      /* Mark this nexthop as inactive and reinstall the route. Then, delete
       * the nexthop. There is no need to re-evaluate the route for this
       * scenario.
       */
      if (IS_ZEBRA_DEBUG_RIB)
        {
          char buf[INET6_ADDRSTRLEN];
          if (IS_ZEBRA_DEBUG_RIB)
            {
              inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
              zlog_debug ("%u:%s/%d: Modifying route rn %p, rib %p (type %d)",
                          si->vrf_id, buf, p->prefixlen, rn, rib, rib->type);
            }
        }
      UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        {
          /* If there are other active nexthops, do an update. */
          if (rib->nexthop_active_num > 1)
            {
              rib_install_kernel (rn, rib, 1);
              redistribute_update (&rn->p, rib, NULL);
            }
          else
            {
              redistribute_delete (&rn->p, rib);
              rib_uninstall_kernel (rn, rib);
            }
        }

      if (afi == AFI_IP)
	{
	  /* Delete the nexthop and dereg from NHT */
	  nh_p.family = AF_INET;
	  nh_p.prefixlen = IPV4_MAX_BITLEN;
	  nh_p.u.prefix4 = nexthop->gate.ipv4;
	}
      else
	{
	  nh_p.family = AF_INET6;
	  nh_p.prefixlen = IPV6_MAX_BITLEN;
	  nh_p.u.prefix6 = nexthop->gate.ipv6;
	}
      rib_nexthop_delete (rib, nexthop);
      zebra_deregister_rnh_static_nh(si->vrf_id, &nh_p, rn);
      nexthop_free (nexthop);
    }
  /* Unlock node. */
  route_unlock_node (rn);
}

int
static_add_route (afi_t afi, safi_t safi, u_char type, struct prefix *p,
		  union g_addr *gate, ifindex_t ifindex,
		  const char *ifname, u_char flags, u_short tag,
		  u_char distance, struct zebra_vrf *zvrf,
		  struct static_nh_label *snh_label)
{
  struct route_node *rn;
  struct static_route *si;
  struct static_route *pp;
  struct static_route *cp;
  struct static_route *update = NULL;
  struct route_table *stable = zvrf->stable[afi][safi];

  if (! stable)
    return -1;

  if (!gate &&
      (type == STATIC_IPV4_GATEWAY ||
       type == STATIC_IPV6_GATEWAY ||
       type == STATIC_IPV6_GATEWAY_IFINDEX))
    return -1;

  if (!ifindex &&
      (type == STATIC_IFINDEX ||
       type == STATIC_IPV6_GATEWAY_IFINDEX))
    return -1;

  /* Lookup static route prefix. */
  rn = route_node_get (stable, p);

  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    {
      if (type == si->type
	  && (! gate ||
	      ((afi == AFI_IP && IPV4_ADDR_SAME (gate, &si->addr.ipv4)) ||
	       (afi == AFI_IP6 && IPV6_ADDR_SAME (gate, &si->addr.ipv6))))
	  && (! ifindex || ifindex == si->ifindex))
	{
	  if ((distance == si->distance) && (tag == si->tag) &&
	      !memcmp (&si->snh_label, snh_label, sizeof (struct static_nh_label)))
	    {
	      route_unlock_node (rn);
	      return 0;
	    }
	  else
	    update = si;
	}
    }

  /* Distance or tag or label changed, delete existing first. */
  if (update)
    static_delete_route (afi, safi, type, p, gate, ifindex, update->tag,
			 update->distance, zvrf, &update->snh_label);

  /* Make new static route structure. */
  si = XCALLOC (MTYPE_STATIC_ROUTE, sizeof (struct static_route));

  si->type = type;
  si->distance = distance;
  si->flags = flags;
  si->tag = tag;
  si->vrf_id = zvrf->vrf_id;
  si->ifindex = ifindex;
  if (si->ifindex)
    strcpy(si->ifname, ifname);

  switch (type)
    {
    case STATIC_IPV4_GATEWAY:
      si->addr.ipv4 = gate->ipv4;
      break;
    case STATIC_IPV6_GATEWAY:
      si->addr.ipv6 = gate->ipv6;
      break;
    case STATIC_IPV6_GATEWAY_IFINDEX:
      si->addr.ipv6 = gate->ipv6;
      break;
    case STATIC_IFINDEX:
      break;
    }

  /* Save labels, if any. */
  memcpy (&si->snh_label, snh_label, sizeof (struct static_nh_label));

  /* Add new static route information to the tree with sort by
     distance value and gateway address. */
  for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
      if (si->distance < cp->distance)
	break;
      if (si->distance > cp->distance)
	continue;
      if (si->type == STATIC_IPV4_GATEWAY && cp->type == STATIC_IPV4_GATEWAY)
	{
	  if (ntohl (si->addr.ipv4.s_addr) < ntohl (cp->addr.ipv4.s_addr))
	    break;
	  if (ntohl (si->addr.ipv4.s_addr) > ntohl (cp->addr.ipv4.s_addr))
	    continue;
	}
    }

  /* Make linked list. */
  if (pp)
    pp->next = si;
  else
    rn->info = si;
  if (cp)
    cp->prev = si;
  si->prev = pp;
  si->next = cp;

  /* Install into rib. */
  static_install_route (afi, safi, p, si);

  return 1;
}

int
static_delete_route (afi_t afi, safi_t safi, u_char type, struct prefix *p,
		     union g_addr *gate, ifindex_t ifindex,
		     u_short tag, u_char distance, struct zebra_vrf *zvrf,
		     struct static_nh_label *snh_label)
{
  struct route_node *rn;
  struct static_route *si;
  struct route_table *stable;

  /* Lookup table.  */
  stable = zebra_vrf_static_table (afi, safi, zvrf);
  if (! stable)
    return -1;

  /* Lookup static route prefix. */
  rn = route_node_lookup (stable, p);
  if (! rn)
    return 0;

  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (type == si->type
	&& (! gate || (
		       (afi == AFI_IP && IPV4_ADDR_SAME (gate, &si->addr.ipv4)) ||
		       (afi == AFI_IP6 && IPV6_ADDR_SAME (gate, &si->addr.ipv6))))
	&& (! ifindex || ifindex == si->ifindex)
	&& (! tag || (tag == si->tag))
	&& (! snh_label->num_labels ||
	    !memcmp (&si->snh_label, snh_label, sizeof (struct static_nh_label))))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  static_uninstall_route (AFI_IP, safi, p, si);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  route_unlock_node (rn);

  /* Free static route configuration. */
  XFREE (MTYPE_STATIC_ROUTE, si);

  route_unlock_node (rn);

  return 1;
}
