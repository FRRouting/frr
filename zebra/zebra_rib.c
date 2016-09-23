/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
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

#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "str.h"
#include "command.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/debug.h"
#include "zebra/zebra_fpm.h"
#include "zebra/zebra_rnh.h"
#include "zebra/interface.h"
#include "zebra/connected.h"

/* Should we allow non Quagga processes to delete our routes */
extern int allow_delete;

/* Hold time for RIB process, should be very minimal.
 * it is useful to able to set it otherwise for testing, hence exported
 * as global here for test-rig code.
 */
int rib_process_hold_time = 10;

/* Each route type's string and default distance value. */
static const struct
{  
  int key;
  int distance;
} route_info[ZEBRA_ROUTE_MAX] =
{
  [ZEBRA_ROUTE_SYSTEM]  = {ZEBRA_ROUTE_SYSTEM,    0},
  [ZEBRA_ROUTE_KERNEL]  = {ZEBRA_ROUTE_KERNEL,    0},
  [ZEBRA_ROUTE_CONNECT] = {ZEBRA_ROUTE_CONNECT,   0},
  [ZEBRA_ROUTE_STATIC]  = {ZEBRA_ROUTE_STATIC,    1},
  [ZEBRA_ROUTE_RIP]     = {ZEBRA_ROUTE_RIP,     120},
  [ZEBRA_ROUTE_RIPNG]   = {ZEBRA_ROUTE_RIPNG,   120},
  [ZEBRA_ROUTE_OSPF]    = {ZEBRA_ROUTE_OSPF,    110},
  [ZEBRA_ROUTE_OSPF6]   = {ZEBRA_ROUTE_OSPF6,   110},
  [ZEBRA_ROUTE_ISIS]    = {ZEBRA_ROUTE_ISIS,    115},
  [ZEBRA_ROUTE_BGP]     = {ZEBRA_ROUTE_BGP,      20  /* IBGP is 200. */},
  /* no entry/default: 150 */
};

/* RPF lookup behaviour */
static enum multicast_mode ipv4_multicast_mode = MCAST_NO_CONFIG;


static void __attribute__((format (printf, 5, 6)))
_rnode_zlog(const char *_func, vrf_id_t vrf_id, struct route_node *rn, int priority,
	    const char *msgfmt, ...)
{
  char buf[PREFIX_STRLEN + 8];
  char msgbuf[512];
  va_list ap;

  va_start(ap, msgfmt);
  vsnprintf(msgbuf, sizeof(msgbuf), msgfmt, ap);
  va_end(ap);

  if (rn)
    {
      rib_table_info_t *info = rn->table->info;

      prefix2str(&rn->p, buf, sizeof(buf));
      if (info->safi == SAFI_MULTICAST)
        strcat(buf, " (MRIB)");
    }
  else
    {
      snprintf(buf, sizeof(buf), "{(route_node *) NULL}");
    }

  zlog (NULL, priority, "%s: %d:%s: %s", _func, vrf_id, buf, msgbuf);
}

#define rnode_debug(node, vrf_id, ...) \
	_rnode_zlog(__func__, vrf_id, node, LOG_DEBUG, __VA_ARGS__)
#define rnode_info(node, ...) \
	_rnode_zlog(__func__, vrf_id, node, LOG_INFO, __VA_ARGS__)

u_char
route_distance (int type)
{
  u_char distance;

  if ((unsigned)type >= array_size(route_info))
    distance = 150;
  else
    distance = route_info[type].distance;

  return distance;
}

int
is_zebra_valid_kernel_table(u_int32_t table_id)
{
  if ((table_id > ZEBRA_KERNEL_TABLE_MAX))
    return 0;

#ifdef linux
  if ((table_id == RT_TABLE_UNSPEC) ||
      (table_id == RT_TABLE_LOCAL) ||
      (table_id == RT_TABLE_COMPAT))
    return 0;
#endif

  return 1;
}

int
is_zebra_main_routing_table(u_int32_t table_id)
{
  if ((table_id == RT_TABLE_MAIN) || (table_id == zebrad.rtm_table_default))
    return 1;
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
  if (p->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK (&p->u.prefix6))
	return 0;
      if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
	return 0;
    }
  return 1;
}

/* Add nexthop to the end of a rib node's nexthop list */
void
rib_nexthop_add (struct rib *rib, struct nexthop *nexthop)
{
  nexthop_add(&rib->nexthop, nexthop);
  rib->nexthop_num++;
}



/**
 * copy_nexthop - copy a nexthop to the rib structure.
 */
void
rib_copy_nexthops (struct rib *rib, struct nexthop *nh)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->flags = nh->flags;
  nexthop->type = nh->type;
  nexthop->ifindex = nh->ifindex;
  memcpy(&(nexthop->gate), &(nh->gate), sizeof(union g_addr));
  memcpy(&(nexthop->src), &(nh->src), sizeof(union g_addr));
  if (nh->nh_label)
    nexthop_add_labels (nexthop, nh->nh_label_type, nh->nh_label->num_labels,
                        &nh->nh_label->label[0]);
  rib_nexthop_add(rib, nexthop);
  if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE))
    copy_nexthops(&nexthop->resolved, nh->resolved);
}

/* Delete specified nexthop from the list. */
void
rib_nexthop_delete (struct rib *rib, struct nexthop *nexthop)
{
  if (nexthop->next)
    nexthop->next->prev = nexthop->prev;
  if (nexthop->prev)
    nexthop->prev->next = nexthop->next;
  else
    rib->nexthop = nexthop->next;
  rib->nexthop_num--;
}



struct nexthop *
rib_nexthop_ifindex_add (struct rib *rib, ifindex_t ifindex)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_IFINDEX;
  nexthop->ifindex = ifindex;

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
rib_nexthop_ipv4_add (struct rib *rib, struct in_addr *ipv4, struct in_addr *src)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_IPV4;
  nexthop->gate.ipv4 = *ipv4;
  if (src)
    nexthop->src.ipv4 = *src;

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
rib_nexthop_ipv4_ifindex_add (struct rib *rib, struct in_addr *ipv4,
			      struct in_addr *src, ifindex_t ifindex)
{
  struct nexthop *nexthop;
  struct interface *ifp;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
  nexthop->gate.ipv4 = *ipv4;
  if (src)
    nexthop->src.ipv4 = *src;
  nexthop->ifindex = ifindex;
  ifp = if_lookup_by_index (nexthop->ifindex);
  /*Pending: need to think if null ifp here is ok during bootup?
    There was a crash because ifp here was coming to be NULL */
  if (ifp)
  if (connected_is_unnumbered(ifp)) {
    SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);
   }

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
rib_nexthop_ipv6_add (struct rib *rib, struct in6_addr *ipv6)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_IPV6;
  nexthop->gate.ipv6 = *ipv6;

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
rib_nexthop_ipv6_ifindex_add (struct rib *rib, struct in6_addr *ipv6,
			      ifindex_t ifindex)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
  nexthop->gate.ipv6 = *ipv6;
  nexthop->ifindex = ifindex;

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
rib_nexthop_blackhole_add (struct rib *rib)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->type = NEXTHOP_TYPE_BLACKHOLE;
  SET_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE);

  rib_nexthop_add (rib, nexthop);

  return nexthop;
}

/* This method checks whether a recursive nexthop has at
 * least one resolved nexthop in the fib.
 */
int
nexthop_has_fib_child(struct nexthop *nexthop)
{
  struct nexthop *nh;

  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
    return 0;

  for (nh = nexthop->resolved; nh; nh = nh->next)
    if (CHECK_FLAG (nh->flags, NEXTHOP_FLAG_FIB))
      return 1;

  return 0;
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int
nexthop_active_ipv4 (struct rib *rib, struct nexthop *nexthop, int set,
		     struct route_node *top)
{
  struct prefix_ipv4 p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  int resolved;
  struct nexthop *newhop, *tnewhop;
  struct nexthop *resolved_hop;
  int recursing = 0;
  struct interface *ifp;

  if (nexthop->type == NEXTHOP_TYPE_IPV4)
    nexthop->ifindex = 0;

  if (set)
    {
      UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
      zebra_deregister_rnh_static_nexthops(rib->vrf_id, nexthop->resolved, top);
      nexthops_free(nexthop->resolved);
      nexthop->resolved = NULL;
      rib->nexthop_mtu = 0;
    }

  /* Skip nexthops that have been filtered out due to route-map */
  /* The nexthops are specific to this route and so the same */
  /* nexthop for a different route may not have this flag set */
  if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED))
    return 0;

  /*
   * Check to see if we should trust the passed in information
   * for UNNUMBERED interfaces as that we won't find the GW
   * address in the routing table.
   */
  if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
    {
      ifp = if_lookup_by_index (nexthop->ifindex);
      if (ifp && connected_is_unnumbered(ifp))
	{
	  if (if_is_operative(ifp))
	    return 1;
	  else
	    return 0;
	}
      else
	return 0;
    }

  /* Make lookup prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv4;

  /* Lookup table.  */
  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, rib->vrf_id);
  if (! table)
    return 0;

  rn = route_node_match (table, (struct prefix *) &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immediately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      /* However, do not resolve over default route unless explicitly allowed. */
      if (is_default_prefix (&rn->p) &&
          !nh_resolve_via_default (p.family))
        return 0;

      RNODE_FOREACH_RIB (rn, match)
	{
	  if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	    continue;

          /* if the next hop is imported from another table, skip it */
          if (match->type == ZEBRA_ROUTE_TABLE)
            continue;
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	    break;
	}

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  /* If the longest prefix match for the nexthop yields
	   * a blackhole, mark it as inactive. */
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_BLACKHOLE)
	      || CHECK_FLAG (match->flags, ZEBRA_FLAG_REJECT))
	    return 0;

	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    {
	      /* Directly point connected route. */
	      newhop = match->nexthop;
	      if (newhop && nexthop->type == NEXTHOP_TYPE_IPV4)
		nexthop->ifindex = newhop->ifindex;
	      
	      return 1;
	    }
	  else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
	    {
	      resolved = 0;
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			SET_FLAG(rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);

			resolved_hop = nexthop_new();
			SET_FLAG (resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
			/* If the resolving route specifies a gateway, use it */
			if (newhop->type == NEXTHOP_TYPE_IPV4
			    || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
			  {
			    resolved_hop->type = newhop->type;
			    resolved_hop->gate.ipv4 = newhop->gate.ipv4;

			    if (newhop->ifindex)
			      {
				resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				resolved_hop->ifindex = newhop->ifindex;
				if (newhop->flags & NEXTHOP_FLAG_ONLINK)
				  resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
			      }
			  }

			/* If the resolving route is an interface route,
			 * it means the gateway we are looking up is connected
			 * to that interface. (The actual network is _not_ onlink).
			 * Therefore, the resolved route should have the original
			 * gateway as nexthop as it is directly connected.
			 *
			 * On Linux, we have to set the onlink netlink flag because
			 * otherwise, the kernel won't accept the route. */
			if (newhop->type == NEXTHOP_TYPE_IFINDEX)
			  {
			    resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
			    resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			    resolved_hop->gate.ipv4 = nexthop->gate.ipv4;
			    resolved_hop->ifindex = newhop->ifindex;
			  }

			nexthop_add(&nexthop->resolved, resolved_hop);
		      }
		    resolved = 1;
		  }
	      return resolved;
	    }
	  else if (rib->type == ZEBRA_ROUTE_STATIC)
	    {
	      resolved = 0;
	      for (ALL_NEXTHOPS_RO(match->nexthop, newhop, tnewhop, recursing))
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

			resolved_hop = nexthop_new();
			SET_FLAG (resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
			/* If the resolving route specifies a gateway, use it */
			if (newhop->type == NEXTHOP_TYPE_IPV4
			    || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
			  {
			    resolved_hop->type = newhop->type;
			    resolved_hop->gate.ipv4 = newhop->gate.ipv4;

			    if (newhop->ifindex)
			      {
				resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				resolved_hop->ifindex = newhop->ifindex;
				if (newhop->flags & NEXTHOP_FLAG_ONLINK)
				  resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
			      }
			  }

			/* If the resolving route is an interface route,
			 * it means the gateway we are looking up is connected
			 * to that interface. (The actual network is _not_ onlink).
			 * Therefore, the resolved route should have the original
			 * gateway as nexthop as it is directly connected.
			 *
			 * On Linux, we have to set the onlink netlink flag because
			 * otherwise, the kernel won't accept the route.
			 */
			if (newhop->type == NEXTHOP_TYPE_IFINDEX)
			  {
			    resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
			    resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			    resolved_hop->gate.ipv4 = nexthop->gate.ipv4;
			    resolved_hop->ifindex = newhop->ifindex;
			  }

			nexthop_add(&nexthop->resolved, resolved_hop);
		      }
		    resolved = 1;
		  }
              if (resolved && set)
                rib->nexthop_mtu = match->mtu;
	      return resolved;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int
nexthop_active_ipv6 (struct rib *rib, struct nexthop *nexthop, int set,
		     struct route_node *top)
{
  struct prefix_ipv6 p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  int resolved;
  struct nexthop *newhop, *tnewhop;
  int recursing = 0;
  struct nexthop *resolved_hop;

  if (nexthop->type == NEXTHOP_TYPE_IPV6)
    nexthop->ifindex = 0;

  if (set)
    {
      UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
      zebra_deregister_rnh_static_nexthops (rib->vrf_id, nexthop->resolved, top);
      nexthops_free(nexthop->resolved);
      nexthop->resolved = NULL;
    }

  /* Skip nexthops that have been filtered out due to route-map */
  /* The nexthops are specific to this route and so the same */
  /* nexthop for a different route may not have this flag set */
  if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED))
    return 0;

  /* Make lookup prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv6;

  /* Lookup table.  */
  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, rib->vrf_id);
  if (! table)
    return 0;

  rn = route_node_match (table, (struct prefix *) &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immediately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      /* However, do not resolve over default route unless explicitly allowed. */
      if (is_default_prefix (&rn->p) &&
          !nh_resolve_via_default (p.family))
        return 0;

      RNODE_FOREACH_RIB (rn, match)
	{
	  if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	    continue;
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	    break;
	}

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  /* If the longest prefix match for the nexthop yields
	   * a blackhole, mark it as inactive. */
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_BLACKHOLE)
	      || CHECK_FLAG (match->flags, ZEBRA_FLAG_REJECT))
	    return 0;

	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    {
	      /* Directly point connected route. */
	      newhop = match->nexthop;

	      if (newhop && nexthop->type == NEXTHOP_TYPE_IPV6)
		nexthop->ifindex = newhop->ifindex;
	      
	      return 1;
	    }
	  else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
	    {
	      resolved = 0;
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			SET_FLAG(rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);

			resolved_hop = nexthop_new();
			SET_FLAG (resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
			/* See nexthop_active_ipv4 for a description how the
			 * resolved nexthop is constructed. */
			if (newhop->type == NEXTHOP_TYPE_IPV6
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
			  {
			    resolved_hop->type = newhop->type;
			    resolved_hop->gate.ipv6 = newhop->gate.ipv6;

			    if (newhop->ifindex)
			      {
				resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				resolved_hop->ifindex = newhop->ifindex;
			      }
			  }

			if (newhop->type == NEXTHOP_TYPE_IFINDEX)
			  {
				resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
				resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				resolved_hop->gate.ipv6 = nexthop->gate.ipv6;
				resolved_hop->ifindex = newhop->ifindex;
			  }

			nexthop_add(&nexthop->resolved, resolved_hop);
		      }
		    resolved = 1;
		  }
	      return resolved;
	    }
	  else if (rib->type == ZEBRA_ROUTE_STATIC)
	    {
	      resolved = 0;
	      for (ALL_NEXTHOPS_RO(match->nexthop, newhop, tnewhop, recursing))
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

			resolved_hop = nexthop_new();
			SET_FLAG (resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
			/* See nexthop_active_ipv4 for a description how the
			 * resolved nexthop is constructed. */
			if (newhop->type == NEXTHOP_TYPE_IPV6
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
			  {
			    resolved_hop->type = newhop->type;
			    resolved_hop->gate.ipv6 = newhop->gate.ipv6;

			    if (newhop->ifindex)
			      {
				resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				resolved_hop->ifindex = newhop->ifindex;
			      }
			  }

			if (newhop->type == NEXTHOP_TYPE_IFINDEX)
			  {
				resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
				resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				resolved_hop->gate.ipv6 = nexthop->gate.ipv6;
				resolved_hop->ifindex = newhop->ifindex;
			  }

			nexthop_add(&nexthop->resolved, resolved_hop);
		      }
		    resolved = 1;
		  }
	      return resolved;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

struct rib *
rib_match (afi_t afi, safi_t safi, vrf_id_t vrf_id,
	   union g_addr *addr, struct route_node **rn_out)
{
  struct prefix p;
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop, *tnewhop;
  int recursing;

  /* Lookup table.  */
  table = zebra_vrf_table (afi, safi, vrf_id);
  if (! table)
    return 0;

  memset (&p, 0, sizeof (struct prefix));
  p.family = afi;
  if (afi == AFI_IP)
    {
      p.u.prefix4 = addr->ipv4;
      p.prefixlen = IPV4_MAX_PREFIXLEN;
    }
  else
    {
      p.u.prefix6 = addr->ipv6;
      p.prefixlen = IPV6_MAX_PREFIXLEN;
    }

  rn = route_node_match (table, (struct prefix *) &p);

  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      RNODE_FOREACH_RIB (rn, match)
	{
	  if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	    continue;
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	    break;
	}

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type != ZEBRA_ROUTE_CONNECT)
	    {
	      int found = 0;
	      for (ALL_NEXTHOPS_RO(match->nexthop, newhop, tnewhop, recursing))
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  {
		    found = 1;
		    break;
		  }
	      if (!found)
		return NULL;
	    }

	  if (rn_out)
	    *rn_out = rn;
	  return match;
	}
    }
  return NULL;
}

struct rib *
rib_match_ipv4_multicast (vrf_id_t vrf_id, struct in_addr addr, struct route_node **rn_out)
{
  struct rib *rib = NULL, *mrib = NULL, *urib = NULL;
  struct route_node *m_rn = NULL, *u_rn = NULL;
  union g_addr gaddr = { .ipv4 = addr };

  switch (ipv4_multicast_mode)
    {
    case MCAST_MRIB_ONLY:
      return rib_match (AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, rn_out);
    case MCAST_URIB_ONLY:
      return rib_match (AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, rn_out);
    case MCAST_NO_CONFIG:
    case MCAST_MIX_MRIB_FIRST:
      rib = mrib = rib_match (AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, &m_rn);
      if (!mrib)
	rib = urib = rib_match (AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, &u_rn);
      break;
    case MCAST_MIX_DISTANCE:
      mrib = rib_match (AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, &m_rn);
      urib = rib_match (AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, &u_rn);
      if (mrib && urib)
	rib = urib->distance < mrib->distance ? urib : mrib;
      else if (mrib)
	rib = mrib;
      else if (urib)
	rib = urib;
      break;
    case MCAST_MIX_PFXLEN:
      mrib = rib_match (AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, &m_rn);
      urib = rib_match (AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, &u_rn);
      if (mrib && urib)
	rib = u_rn->p.prefixlen > m_rn->p.prefixlen ? urib : mrib;
      else if (mrib)
	rib = mrib;
      else if (urib)
	rib = urib;
      break;
  }

  if (rn_out)
    *rn_out = (rib == mrib) ? m_rn : u_rn;

  if (IS_ZEBRA_DEBUG_RIB)
    {
      char buf[BUFSIZ];
      inet_ntop (AF_INET, &addr, buf, BUFSIZ);

      zlog_debug("%s: %s: found %s, using %s",
		 __func__, buf,
                 mrib ? (urib ? "MRIB+URIB" : "MRIB") :
                         urib ? "URIB" : "nothing",
		 rib == urib ? "URIB" : rib == mrib ? "MRIB" : "none");
    }
  return rib;
}

void
multicast_mode_ipv4_set (enum multicast_mode mode)
{
  if (IS_ZEBRA_DEBUG_RIB)
    zlog_debug("%s: multicast lookup mode set (%d)", __func__, mode);
  ipv4_multicast_mode = mode;
}

enum multicast_mode
multicast_mode_ipv4_get (void)
{
  return ipv4_multicast_mode;
}

struct rib *
rib_lookup_ipv4 (struct prefix_ipv4 *p, vrf_id_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop, *tnexthop;
  int recursing;

  /* Lookup table.  */
  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return 0;

  rn = route_node_lookup (table, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
    return NULL;

  /* Unlock node. */
  route_unlock_node (rn);

  RNODE_FOREACH_RIB (rn, match)
    {
      if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	continue;
      if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	break;
    }

  if (! match)
    return NULL;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return match;
  
  for (ALL_NEXTHOPS_RO(match->nexthop, nexthop, tnexthop, recursing))
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
      return match;

  return NULL;
}

/*
 * This clone function, unlike its original rib_lookup_ipv4(), checks
 * if specified IPv4 route record (prefix/mask -> gate) exists in
 * the whole RIB and has ZEBRA_FLAG_SELECTED set.
 *
 * Return values:
 * -1: error
 * 0: exact match found
 * 1: a match was found with a different gate
 * 2: connected route found
 * 3: no matches found
 */
int
rib_lookup_ipv4_route (struct prefix_ipv4 *p, union sockunion * qgate,
    vrf_id_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop, *tnexthop;
  int recursing;
  int nexthops_active;

  /* Lookup table.  */
  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
    return ZEBRA_RIB_LOOKUP_ERROR;

  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
    return ZEBRA_RIB_NOTFOUND;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Find out if a "selected" RR for the discovered RIB entry exists ever. */
  RNODE_FOREACH_RIB (rn, match)
    {
      if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	continue;
      if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	break;
    }

  /* None such found :( */
  if (!match)
    return ZEBRA_RIB_NOTFOUND;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return ZEBRA_RIB_FOUND_CONNECTED;
  
  /* Ok, we have a cood candidate, let's check it's nexthop list... */
  nexthops_active = 0;
  for (ALL_NEXTHOPS_RO(match->nexthop, nexthop, tnexthop, recursing))
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
      {
        nexthops_active = 1;
        if (nexthop->gate.ipv4.s_addr == sockunion2ip (qgate))
          return ZEBRA_RIB_FOUND_EXACT;
        if (IS_ZEBRA_DEBUG_RIB)
          {
            char gate_buf[INET_ADDRSTRLEN], qgate_buf[INET_ADDRSTRLEN];
            inet_ntop (AF_INET, &nexthop->gate.ipv4.s_addr, gate_buf, INET_ADDRSTRLEN);
            inet_ntop (AF_INET, &sockunion2ip(qgate), qgate_buf, INET_ADDRSTRLEN);
            zlog_debug ("%s: qgate == %s, %s == %s", __func__,
                        qgate_buf, recursing ? "rgate" : "gate", gate_buf);
          }
      }

  if (nexthops_active)
    return ZEBRA_RIB_FOUND_NOGATE;

  return ZEBRA_RIB_NOTFOUND;
}

#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. If the 4th parameter, 'set', is non-zero,
 * nexthop->ifindex will be updated appropriately as well.
 * An existing route map can turn (otherwise active) nexthop into inactive, but
 * not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */

static unsigned
nexthop_active_check (struct route_node *rn, struct rib *rib,
		      struct nexthop *nexthop, int set)
{
  rib_table_info_t *info = rn->table->info;
  struct interface *ifp;
  route_map_result_t ret = RMAP_MATCH;
  int family;
  char buf[INET6_ADDRSTRLEN+1];

  if (rn->p.family == AF_INET)
    family = AFI_IP;
  else if (rn->p.family == AF_INET6)
    family = AFI_IP6;
  else
    family = 0;
  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IFINDEX:
      ifp = if_lookup_by_index_vrf (nexthop->ifindex, rib->vrf_id);
      if (ifp && if_is_operative(ifp))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IPV4:
    case NEXTHOP_TYPE_IPV4_IFINDEX:
      family = AFI_IP;
      if (nexthop_active_ipv4 (rib, nexthop, set, rn))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IPV6:
      family = AFI_IP6;
      if (nexthop_active_ipv6 (rib, nexthop, set, rn))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      /* RFC 5549, v4 prefix with v6 NH */
      if (rn->p.family != AF_INET)
	family = AFI_IP6;
      if (IN6_IS_ADDR_LINKLOCAL (&nexthop->gate.ipv6))
	{
	  ifp = if_lookup_by_index_vrf (nexthop->ifindex, rib->vrf_id);
	  if (ifp && if_is_operative(ifp))
	    SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	  else
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      else
	{
	  if (nexthop_active_ipv6 (rib, nexthop, set, rn))
	    SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	  else
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      break;
    case NEXTHOP_TYPE_BLACKHOLE:
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    default:
      break;
    }
  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
    return 0;

  /* XXX: What exactly do those checks do? Do we support
   * e.g. IPv4 routes with IPv6 nexthops or vice versa? */
  if (RIB_SYSTEM_ROUTE(rib) ||
      (family == AFI_IP && rn->p.family != AF_INET) ||
      (family == AFI_IP6 && rn->p.family != AF_INET6))
    return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);

  /* The original code didn't determine the family correctly
   * e.g. for NEXTHOP_TYPE_IFINDEX. Retrieve the correct afi
   * from the rib_table_info in those cases.
   * Possibly it may be better to use only the rib_table_info
   * in every case.
   */
  if (!family)
    family = info->afi;

  memset(&nexthop->rmap_src.ipv6, 0, sizeof(union g_addr));

  /* It'll get set if required inside */
  ret = zebra_route_map_check(family, rib->type, &rn->p, nexthop, rib->vrf_id,
                              rib->tag);
  if (ret == RMAP_DENYMATCH)
    {
      if (IS_ZEBRA_DEBUG_RIB)
	{
	  inet_ntop (rn->p.family, &rn->p.u.prefix, buf, sizeof (buf));
	  zlog_debug("%u:%s/%d: Filtering out with NH out %s due to route map",
		     rib->vrf_id, buf, rn->p.prefixlen,
		     ifindex2ifname_vrf (nexthop->ifindex, rib->vrf_id));
	}
      UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    }
  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/* Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. rib->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole rib structure
 * is flagged with RIB_ENTRY_CHANGED. The 4th 'set' argument is
 * transparently passed to nexthop_active_check().
 *
 * Return value is the new number of active nexthops.
 */

static int
nexthop_active_update (struct route_node *rn, struct rib *rib, int set)
{
  struct nexthop *nexthop;
  union g_addr prev_src;
  unsigned int prev_active, new_active, old_num_nh;
  ifindex_t prev_index;
  old_num_nh = rib->nexthop_active_num;

  rib->nexthop_active_num = 0;
  UNSET_FLAG (rib->status, RIB_ENTRY_CHANGED);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
  {
    /* No protocol daemon provides src and so we're skipping tracking it */
    prev_src = nexthop->rmap_src;
    prev_active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    prev_index = nexthop->ifindex;
    if ((new_active = nexthop_active_check (rn, rib, nexthop, set)))
      rib->nexthop_active_num++;
    /* Don't allow src setting on IPv6 addr for now */
    if (prev_active != new_active ||
	prev_index != nexthop->ifindex ||
	((nexthop->type >= NEXTHOP_TYPE_IFINDEX &&
	  nexthop->type < NEXTHOP_TYPE_IPV6) &&
	 prev_src.ipv4.s_addr != nexthop->rmap_src.ipv4.s_addr) ||
	((nexthop->type >= NEXTHOP_TYPE_IPV6 &&
	  nexthop->type < NEXTHOP_TYPE_BLACKHOLE) &&
	 !(IPV6_ADDR_SAME (&prev_src.ipv6, &nexthop->rmap_src.ipv6))))
      {
	SET_FLAG (rib->status, RIB_ENTRY_CHANGED);
	SET_FLAG (rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);
      }
  }

  if (old_num_nh != rib->nexthop_active_num)
    SET_FLAG (rib->status, RIB_ENTRY_CHANGED);

  if (CHECK_FLAG (rib->status, RIB_ENTRY_CHANGED))
    {
      SET_FLAG (rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);
    }

  return rib->nexthop_active_num;
}



/* Update flag indicates whether this is a "replace" or not. Currently, this
 * is only used for IPv4.
 */
int
rib_install_kernel (struct route_node *rn, struct rib *rib, int update)
{
  int ret = 0;
  struct nexthop *nexthop, *tnexthop;
  rib_table_info_t *info = rn->table->info;
  int recursing;

  if (info->safi != SAFI_UNICAST)
    {
      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
      return ret;
    }

  /*
   * Make sure we update the FPM any time we send new information to
   * the kernel.
   */
  zfpm_trigger_update (rn, "installing in kernel");
  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      if (update)
        ret = kernel_update_ipv4 (&rn->p, rib);
      else
        ret = kernel_add_ipv4 (&rn->p, rib);
      break;
    case AF_INET6:
      if (update)
        ret = kernel_update_ipv6 (&rn->p, rib);
      else
        ret = kernel_add_ipv6 (&rn->p, rib);
      break;
    }

  /* If install succeeds, update FIB flag for nexthops. */
  if (!ret)
    {
      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        {
          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            continue;

          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
          else
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
        }
    }

  return ret;
}

/* Uninstall the route from kernel. */
int
rib_uninstall_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop, *tnexthop;
  rib_table_info_t *info = rn->table->info;
  int recursing;

  if (info->safi != SAFI_UNICAST)
    {
      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
      return ret;
    }

  /*
   * Make sure we update the FPM any time we send new information to
   * the kernel.
   */
  zfpm_trigger_update (rn, "uninstalling from kernel");

  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      ret = kernel_delete_ipv4 (&rn->p, rib);
      break;
    case AF_INET6:
      ret = kernel_delete_ipv6 (&rn->p, rib);
      break;
    }

  for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  return ret;
}

/* Uninstall the route from kernel. */
static void
rib_uninstall (struct route_node *rn, struct rib *rib)
{
  rib_table_info_t *info = rn->table->info;

  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      if (info->safi == SAFI_UNICAST)
        zfpm_trigger_update (rn, "rib_uninstall");

      redistribute_delete (&rn->p, rib);
      if (! RIB_SYSTEM_ROUTE (rib))
	rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }
}

static void rib_unlink (struct route_node *, struct rib *);

/*
 * rib_can_delete_dest
 *
 * Returns TRUE if the given dest can be deleted from the table.
 */
static int
rib_can_delete_dest (rib_dest_t *dest)
{
  if (dest->routes)
    {
      return 0;
    }

  /*
   * Don't delete the dest if we have to update the FPM about this
   * prefix.
   */
  if (CHECK_FLAG (dest->flags, RIB_DEST_UPDATE_FPM) ||
      CHECK_FLAG (dest->flags, RIB_DEST_SENT_TO_FPM))
    return 0;

  return 1;
}

/*
 * rib_gc_dest
 *
 * Garbage collect the rib dest corresponding to the given route node
 * if appropriate.
 *
 * Returns TRUE if the dest was deleted, FALSE otherwise.
 */
int
rib_gc_dest (struct route_node *rn)
{
  rib_dest_t *dest;
  struct zebra_vrf *zvrf;

  dest = rib_dest_from_rnode (rn);
  if (!dest)
    return 0;

  if (!rib_can_delete_dest (dest))
    return 0;

  zvrf = rib_dest_vrf (dest);
  if (IS_ZEBRA_DEBUG_RIB)
    rnode_debug (rn, zvrf->vrf_id, "removing dest from table");

  dest->rnode = NULL;
  XFREE (MTYPE_RIB_DEST, dest);
  rn->info = NULL;

  /*
   * Release the one reference that we keep on the route node.
   */
  route_unlock_node (rn);
  return 1;
}

static void
rib_process_add_route (struct zebra_vrf *zvrf, struct route_node *rn,
                       struct rib *select)
{
  char buf[INET6_ADDRSTRLEN];
  int installed = 1;

  zfpm_trigger_update (rn, "new route selected");

  /* Update real nexthop. This may actually determine if nexthop is active or not. */
  if (!nexthop_active_update (rn, select, 1))
    {
      UNSET_FLAG(select->status, RIB_ENTRY_CHANGED);
      return;
    }

  SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
  if (IS_ZEBRA_DEBUG_RIB)
    {
      inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
      zlog_debug ("%u:%s/%d: Adding route rn %p, rib %p (type %d)",
                   zvrf->vrf_id, buf, rn->p.prefixlen, rn, select, select->type);
    }

  if (!RIB_SYSTEM_ROUTE (select))
    {
      if (rib_install_kernel (rn, select, 0))
        {
          installed = 0;
          inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
          zlog_warn ("%u:%s/%d: Route install failed",
                     zvrf->vrf_id, buf, rn->p.prefixlen);
        }
    }

  /* Update for redistribution. */
  if (installed)
    redistribute_update (&rn->p, select, NULL);
  UNSET_FLAG(select->status, RIB_ENTRY_CHANGED);
}

static void
rib_process_del_route (struct zebra_vrf *zvrf, struct route_node *rn,
                       struct rib *fib)
{
  char buf[INET6_ADDRSTRLEN];

  zfpm_trigger_update (rn, "removing existing route");

  /* Withdraw redistribute and uninstall from kernel. */
  if (IS_ZEBRA_DEBUG_RIB)
    {
      inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
      zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d)",
                  zvrf->vrf_id, buf, rn->p.prefixlen, rn, fib, fib->type);
    }

  redistribute_delete(&rn->p, fib);
  if (!RIB_SYSTEM_ROUTE (fib))
    rib_uninstall_kernel (rn, fib);

  UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

  /* Update nexthop for route, reset changed flag. */
  nexthop_active_update (rn, fib, 1);
  UNSET_FLAG(fib->status, RIB_ENTRY_CHANGED);
}

static void
rib_process_update_route (struct zebra_vrf *zvrf, struct route_node *rn,
                          struct rib *select, struct rib *fib)
{
  char buf[INET6_ADDRSTRLEN];
  struct nexthop *nexthop = NULL, *tnexthop;
  int recursing;
  int nh_active = 0;
  int installed = 1;

  if (IS_ZEBRA_DEBUG_RIB)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

  /*
   * We have to install or update if a new route has been selected or
   * something has changed.
   */
  if (select != fib ||
      CHECK_FLAG (select->status, RIB_ENTRY_CHANGED))
    {
      zfpm_trigger_update (rn, "updating existing route");

      /* Update the nexthop; we could determine here that nexthop is inactive. */
      if (nexthop_active_update (rn, select, 1))
        nh_active = 1;

      /* If nexthop is active, install the selected route, if appropriate. If
       * the install succeeds, cleanup flags for prior route, if different from
       * newly selected.
       */
      if (nh_active)
        {
          if (IS_ZEBRA_DEBUG_RIB)
            {
              if (select != fib)
                zlog_debug ("%u:%s/%d: Updating route rn %p, rib %p (type %d) "
                            "old %p (type %d)", zvrf->vrf_id, buf, rn->p.prefixlen,
                            rn, select, select->type, fib, fib->type);
              else
                zlog_debug ("%u:%s/%d: Updating route rn %p, rib %p (type %d)",
                        zvrf->vrf_id, buf, rn->p.prefixlen, rn, select, select->type);
            }
          /* Non-system route should be installed. */
          if (!RIB_SYSTEM_ROUTE (select))
            {
              if (rib_install_kernel (rn, select, 1))
                {
                  installed = 0;
                  inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
                  zlog_warn ("%u:%s/%d: Route install failed",
                             zvrf->vrf_id, buf, rn->p.prefixlen);
                }
            }

          /* If install succeeded or system route, cleanup flags for prior route. */
          if (installed && select != fib)
            {
              if (RIB_SYSTEM_ROUTE(select))
                {
                  if (!RIB_SYSTEM_ROUTE (fib))
                    rib_uninstall_kernel (rn, fib);
                }
              else
                {
                  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
                    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }
            }

          /* Update for redistribution. */
          if (installed)
            {
              SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
              redistribute_update (&rn->p, select, (select == fib) ? NULL : fib);
            }
        }

      /*
       * If nexthop for selected route is not active or install failed, we
       * may need to uninstall and delete for redistribution.
       */
      if (!nh_active || !installed)
        {
          struct rib *del;

          if (IS_ZEBRA_DEBUG_RIB)
            {
              if (select != fib)
                zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d) "
                            "old %p (type %d) - %s", zvrf->vrf_id, buf, rn->p.prefixlen,
                            rn, select, select->type, fib, fib->type,
                            nh_active ? "install failed" : "nexthop inactive");
              else
                zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d) - %s",
                            zvrf->vrf_id, buf, rn->p.prefixlen, rn, select, select->type,
                            nh_active ? "install failed" : "nexthop inactive");
            }

          del = (select == fib) ? select : fib;

          redistribute_delete(&rn->p, del);

          if (!RIB_SYSTEM_ROUTE (del))
            rib_uninstall_kernel (rn, del);
          UNSET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
        }
    }
  else
    {
      /*
       * Same route selected; check if in the FIB and if not, re-install. This
       * is housekeeping code to deal with race conditions in kernel with linux
       * netlink reporting interface up before IPv4 or IPv6 protocol is ready
       * to add routes.
       */
      if (!RIB_SYSTEM_ROUTE (select))
        {
          int in_fib = 0;

          for (ALL_NEXTHOPS_RO(select->nexthop, nexthop, tnexthop, recursing))
            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
              {
                in_fib = 1;
                break;
              }
          if (!in_fib)
            rib_install_kernel (rn, select, 0);
        }
    }

  /* Update prior route. */
  if (select != fib)
    {
      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
      UNSET_FLAG(fib->status, RIB_ENTRY_CHANGED);
    }

  /* Clear changed flag. */
  UNSET_FLAG(select->status, RIB_ENTRY_CHANGED);
}

/* Check if 'alternate' RIB entry is better than 'current'. */
static struct rib *
rib_choose_best (struct rib *current, struct rib *alternate)
{
  if (current == NULL)
    return alternate;

  /* filter route selection in following order:
   * - connected beats other types
   * - lower distance beats higher
   * - lower metric beats higher for equal distance
   * - last, hence oldest, route wins tie break.
   */

  /* Connected routes. Pick the last connected
   * route of the set of lowest metric connected routes.
   */
  if (alternate->type == ZEBRA_ROUTE_CONNECT)
    {
      if (current->type != ZEBRA_ROUTE_CONNECT
          || alternate->metric <= current->metric)
        return alternate;

      return current;
    }

  if (current->type == ZEBRA_ROUTE_CONNECT)
    return current;

  /* higher distance loses */
  if (alternate->distance < current->distance)
    return alternate;
  if (current->distance < alternate->distance)
    return current;

  /* metric tie-breaks equal distance */
  if (alternate->metric <= current->metric)
    return alternate;

  return current;
}

/* Core function for processing routing information base. */
static void
rib_process (struct route_node *rn)
{
  struct rib *rib;
  struct rib *next;
  struct rib *fib = NULL;
  struct rib *select = NULL;
  struct rib *del = NULL;
  struct rib *best = NULL;
  char buf[INET6_ADDRSTRLEN];
  rib_dest_t *dest;
  struct zebra_vrf *zvrf = NULL;
  vrf_id_t vrf_id = VRF_UNKNOWN;
  rib_table_info_t *info;

  assert (rn);
  info = rn->table->info;
  
  dest = rib_dest_from_rnode (rn);
  if (dest)
    {
      zvrf = rib_dest_vrf (dest);
      vrf_id = zvrf->vrf_id;
    }
  
  if (IS_ZEBRA_DEBUG_RIB)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    zlog_debug ("%u:%s/%d: Processing rn %p", vrf_id, buf, rn->p.prefixlen, rn);

  RNODE_FOREACH_RIB_SAFE (rn, rib, next)
    {
      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        zlog_debug ("%u:%s/%d: Examine rib %p (type %d) status %x flags %x "
                    "dist %d metric %d",
                    vrf_id, buf, rn->p.prefixlen, rib, rib->type, rib->status,
                    rib->flags, rib->distance, rib->metric);

      UNSET_FLAG(rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);

      /* Currently installed rib. */
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        {
          assert (fib == NULL);
          fib = rib;
        }

      /* Unlock removed routes, so they'll be freed, bar the FIB entry,
       * which we need to do do further work with below.
       */
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
          if (rib != fib)
            {
              if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug (rn, vrf_id, "rn %p, removing rib %p",
			     (void *)rn, (void *)rib);
	      rib_unlink (rn, rib);
            }
          else
            del = rib;
          
          continue;
        }
      
      /* Skip unreachable nexthop. */
      /* This first call to nexthop_active_update is merely to determine if
       * there's any change to nexthops associated with this RIB entry. Now,
       * rib_process() can be invoked due to an external event such as link
       * down or due to next-hop-tracking evaluation. In the latter case,
       * a decision has already been made that the NHs have changed. So, no
       * need to invoke a potentially expensive call again. Further, since
       * the change might be in a recursive NH which is not caught in
       * the nexthop_active_update() code. Thus, we might miss changes to
       * recursive NHs.
       */
      if (!CHECK_FLAG(rib->status, RIB_ENTRY_CHANGED) &&
          ! nexthop_active_update (rn, rib, 0))
        {
          if (rib->type == ZEBRA_ROUTE_TABLE)
            {
              /* This entry was denied by the 'ip protocol table' route-map, we
               * need to delete it */
	      if (rib != fib)
		{
		  if (IS_ZEBRA_DEBUG_RIB)
		    zlog_debug ("%s: %s/%d: imported via import-table but denied "
				"by the ip protocol table route-map",
				__func__, buf, rn->p.prefixlen);
		  rib_unlink (rn, rib);
		}
	      else
		del = rib;
            }

          continue;
        }

      if (info->safi == SAFI_MULTICAST)
	continue;

      /* Infinite distance. */
      if (rib->distance == DISTANCE_INFINITY)
        {
          UNSET_FLAG (rib->status, RIB_ENTRY_CHANGED);
          continue;
        }

      best = rib_choose_best(select, rib);
      if (select && best != select)
        UNSET_FLAG (select->status, RIB_ENTRY_CHANGED);
      if (best != rib)
        UNSET_FLAG (rib->status, RIB_ENTRY_CHANGED);
      select = best;
    } /* RNODE_FOREACH_RIB_SAFE */

  /* After the cycle is finished, the following pointers will be set:
   * select --- the winner RIB entry, if any was found, otherwise NULL
   * fib    --- the SELECTED RIB entry, if any, otherwise NULL
   * del    --- equal to fib, if fib is queued for deletion, NULL otherwise
   * rib    --- NULL
   */
  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    zlog_debug ("%u:%s/%d: After processing: select %p fib %p del %p",
                vrf_id, buf, rn->p.prefixlen, select, fib, del);

  /* Same RIB entry is selected. Update FIB and finish. */
  if (select && select == fib)
    rib_process_update_route (zvrf, rn, select, select);
  else if (select && fib)
    rib_process_update_route (zvrf, rn, select, fib);
  else if (select)
    rib_process_add_route (zvrf, rn, select);
  else if (fib)
    rib_process_del_route (zvrf, rn, fib);

#if 0
  if (select && select == fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
	rnode_debug (rn, vrf_id, "Updating existing route, select %p, fib %p",
                     (void *)select, (void *)fib);
      if (CHECK_FLAG (select->status, RIB_ENTRY_CHANGED))
        {
          if (info->safi == SAFI_UNICAST)
	    zfpm_trigger_update (rn, "updating existing route");

          /* Set real nexthop. */
	  /* Need to check if any NHs are active to clear the
	   * the selected flag
	   */
          if (nexthop_active_update (rn, select, 1))
	    {
              if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%u:%s/%d: Updating route rn %p, rib %p (type %d)",
                            vrf_id, buf, rn->p.prefixlen, rn, select, select->type);
	      if (! RIB_SYSTEM_ROUTE (select))
                {
                  /* Clear FIB flag if performing a replace, will get set again
                   * as part of install.
                   */
                  for (nexthop = select->nexthop; nexthop; nexthop = nexthop->next)
                    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                  rib_install_kernel (rn, select, 1);
                }

	      /* assuming that the receiver knows how to dedup */
              redistribute_update (&rn->p, select, NULL);
	    }
	  else
	    {
              if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d) "
                            "- nexthop inactive",
                            vrf_id, buf, rn->p.prefixlen, rn, select, select->type);

	      /* Withdraw unreachable redistribute route */
	      redistribute_delete(&rn->p, select);

              /* Do the uninstall here, if not done earlier. */
	      if (! RIB_SYSTEM_ROUTE (select))
                rib_uninstall_kernel (rn, select);
	      UNSET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
	    }
	  UNSET_FLAG (select->status, RIB_ENTRY_CHANGED);
	}
      else if (! RIB_SYSTEM_ROUTE (select))
        {
          /* Housekeeping code to deal with 
             race conditions in kernel with linux
             netlink reporting interface up before IPv4 or IPv6 protocol
             is ready to add routes.
             This makes sure the routes are IN the kernel.
           */

          for (ALL_NEXTHOPS_RO(select->nexthop, nexthop, tnexthop, recursing))
            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            {
              installed = 1;
              break;
            }
          if (! installed) 
            rib_install_kernel (rn, select, 0);
        }
      goto end;
    }

  /* At this point we either haven't found the best RIB entry or it is
   * different from what we currently intend to flag with SELECTED. In both
   * cases, if a RIB block is present in FIB, it should be withdrawn.
   */
  if (fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        rnode_debug (rn, vrf_id, "Removing existing route, fib %p", (void *)fib);

      if (info->safi == SAFI_UNICAST)
        zfpm_trigger_update (rn, "removing existing route");

      /* If there's no route to replace this with, withdraw redistribute and
       * uninstall from kernel.
       */
      if (!select)
        {
          if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d)",
                        vrf_id, buf, rn->p.prefixlen, rn, fib, fib->type);

	  redistribute_delete(&rn->p, fib);
          if (! RIB_SYSTEM_ROUTE (fib))
            rib_uninstall_kernel (rn, fib);
        }

      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
      UNSET_FLAG(fib->status, RIB_ENTRY_CHANGED);
    }

  /* Regardless of some RIB entry being SELECTED or not before, now we can
   * tell, that if a new winner exists, FIB is still not updated with this
   * data, but ready to be.
   */
  if (select)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        rnode_debug (rn, "Adding route, select %p", (void *)select);

      if (info->safi == SAFI_UNICAST)
        zfpm_trigger_update (rn, "new route selected");

      /* Set real nexthop. */
      if (nexthop_active_update (rn, select, 1))
	{
          if (IS_ZEBRA_DEBUG_RIB)
            {
              if (fib)
                zlog_debug ("%u:%s/%d: Updating route rn %p, rib %p (type %d) "
                            "old %p (type %d)", vrf_id, buf, rn->p.prefixlen, rn,
                            select, select->type, fib, fib->type);
              else
                zlog_debug ("%u:%s/%d: Adding route rn %p, rib %p (type %d)",
                            vrf_id, buf, rn->p.prefixlen, rn, select, select->type);
            }

          if (! RIB_SYSTEM_ROUTE (select))
            {
              /* Clear FIB flag if performing a replace, will get set again
               * as part of install.
               */
              if (fib)
                {
                  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
                    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }
              rib_install_kernel (rn, select, fib? 1 : 0);
            }
          else
            {
              /* Uninstall prior route here, if needed. */
              if (fib && !RIB_SYSTEM_ROUTE (fib))
                rib_uninstall_kernel (rn, fib);
            }

	  SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
	  /* Unconditionally announce, this part is exercised by new routes */
	  /* If we cannot add, for example route added is learnt by the */
	  /* protocol we're trying to redistribute to, delete the redist */
	  /* This is notified by setting the is_update to 1 */
	  redistribute_update (&rn->p, select, fib);
	}
      else
	{
          /* Uninstall prior route here and do redist delete, if needed. */
          if (fib)
            {
              if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%u:%s/%d: Deleting route rn %p, rib %p (type %d) "
                            "- nexthop inactive",
                            vrf_id, buf, rn->p.prefixlen, rn, fib, fib->type);

              if (!RIB_SYSTEM_ROUTE (fib))
                rib_uninstall_kernel (rn, fib);
              redistribute_delete(&rn->p, fib);
	    }
	}
      UNSET_FLAG(select->status, RIB_ENTRY_CHANGED);
    }
#endif

  /* FIB route was removed, should be deleted */
  if (del)
    {
      if (IS_ZEBRA_DEBUG_RIB)
	rnode_debug (rn, vrf_id, "Deleting fib %p, rn %p", (void *)del, (void *)rn);
      rib_unlink (rn, del);
    }

  /*
   * Check if the dest can be deleted now.
   */
  rib_gc_dest (rn);
}

/* Take a list of route_node structs and return 1, if there was a record
 * picked from it and processed by rib_process(). Don't process more, 
 * than one RN record; operate only in the specified sub-queue.
 */
static unsigned int
process_subq (struct list * subq, u_char qindex)
{
  struct listnode *lnode  = listhead (subq);
  struct route_node *rnode;
  char buf[INET6_ADDRSTRLEN];
  rib_dest_t *dest;
  struct zebra_vrf *zvrf = NULL;

  if (!lnode)
    return 0;

  rnode = listgetdata (lnode);
  dest = rib_dest_from_rnode (rnode);
  if (dest)
    zvrf = rib_dest_vrf (dest);

  rib_process (rnode);

  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
    {
      inet_ntop (rnode->p.family, &rnode->p.u.prefix, buf, INET6_ADDRSTRLEN);
      zlog_debug ("%u:%s/%d: rn %p dequeued from sub-queue %u",
                  zvrf ? zvrf->vrf_id : 0, buf, rnode->p.prefixlen, rnode, qindex);
    }

  if (rnode->info)
    UNSET_FLAG (rib_dest_from_rnode (rnode)->flags, RIB_ROUTE_QUEUED (qindex));

#if 0
  else
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, rnode, rnode->lock);
      zlog_backtrace(LOG_DEBUG);
    }
#endif
  route_unlock_node (rnode);
  list_delete_node (subq, lnode);
  return 1;
}

/*
 * All meta queues have been processed. Trigger next-hop evaluation.
 */
static void
meta_queue_process_complete (struct work_queue *dummy)
{
  vrf_iter_t iter;
  struct zebra_vrf *zvrf;

  /* Evaluate nexthops for those VRFs which underwent route processing. This
   * should limit the evaluation to the necessary VRFs in most common
   * situations.
   */
  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if (((zvrf = vrf_iter2info (iter)) != NULL) &&
          (zvrf->flags & ZEBRA_VRF_RIB_SCHEDULED))
        {
          zvrf->flags &= ~ZEBRA_VRF_RIB_SCHEDULED;
          zebra_evaluate_rnh(zvrf->vrf_id, AF_INET, 0, RNH_NEXTHOP_TYPE, NULL);
          zebra_evaluate_rnh(zvrf->vrf_id, AF_INET, 0, RNH_IMPORT_CHECK_TYPE, NULL);
          zebra_evaluate_rnh(zvrf->vrf_id, AF_INET6, 0, RNH_NEXTHOP_TYPE, NULL);
          zebra_evaluate_rnh(zvrf->vrf_id, AF_INET6, 0, RNH_IMPORT_CHECK_TYPE, NULL);
        }
    }

  /* Schedule LSPs for processing, if needed. */
  zvrf = vrf_info_lookup(VRF_DEFAULT);
  if (mpls_should_lsps_be_processed(zvrf))
    {
      if (IS_ZEBRA_DEBUG_MPLS)
        zlog_debug ("%u: Scheduling all LSPs upon RIB completion", zvrf->vrf_id);
      zebra_mpls_lsp_schedule (zvrf);
      mpls_unmark_lsps_for_processing(zvrf);
    }
}

/* Dispatch the meta queue by picking, processing and unlocking the next RN from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and data
 * is pointed to the meta queue structure.
 */
static wq_item_status
meta_queue_process (struct work_queue *dummy, void *data)
{
  struct meta_queue * mq = data;
  unsigned i;

  for (i = 0; i < MQ_SIZE; i++)
    if (process_subq (mq->subq[i], i))
      {
	mq->size--;
	break;
      }
  return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}

/*
 * Map from rib types to queue type (priority) in meta queue
 */
static const u_char meta_queue_map[ZEBRA_ROUTE_MAX] = {
  [ZEBRA_ROUTE_SYSTEM]  = 4,
  [ZEBRA_ROUTE_KERNEL]  = 0,
  [ZEBRA_ROUTE_CONNECT] = 0,
  [ZEBRA_ROUTE_STATIC]  = 1,
  [ZEBRA_ROUTE_RIP]     = 2,
  [ZEBRA_ROUTE_RIPNG]   = 2,
  [ZEBRA_ROUTE_OSPF]    = 2,
  [ZEBRA_ROUTE_OSPF6]   = 2,
  [ZEBRA_ROUTE_ISIS]    = 2,
  [ZEBRA_ROUTE_BGP]     = 3,
  [ZEBRA_ROUTE_HSLS]    = 4,
  [ZEBRA_ROUTE_TABLE]   = 1,
};

/* Look into the RN and queue it into one or more priority queues,
 * increasing the size for each data push done.
 */
static void
rib_meta_queue_add (struct meta_queue *mq, struct route_node *rn)
{
  struct rib *rib;

  RNODE_FOREACH_RIB (rn, rib)
    {
      u_char qindex = meta_queue_map[rib->type];
      struct zebra_vrf *zvrf;

      /* Invariant: at this point we always have rn->info set. */
      if (CHECK_FLAG (rib_dest_from_rnode (rn)->flags,
		      RIB_ROUTE_QUEUED (qindex)))
	{
	  if (IS_ZEBRA_DEBUG_RIB_DETAILED)
	    rnode_debug (rn, rib->vrf_id,  "rn %p is already queued in sub-queue %u",
			 (void *)rn, qindex);
	  continue;
	}

      SET_FLAG (rib_dest_from_rnode (rn)->flags, RIB_ROUTE_QUEUED (qindex));
      listnode_add (mq->subq[qindex], rn);
      route_lock_node (rn);
      mq->size++;

      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
	rnode_debug (rn, rib->vrf_id, "queued rn %p into sub-queue %u",
		     (void *)rn, qindex);

      zvrf = zebra_vrf_lookup (rib->vrf_id);
      if (zvrf)
          zvrf->flags |= ZEBRA_VRF_RIB_SCHEDULED;
    }
}

/* Add route_node to work queue and schedule processing */
void
rib_queue_add (struct route_node *rn)
{
  assert (rn);
  
  /* Pointless to queue a route_node with no RIB entries to add or remove */
  if (!rnode_to_ribs (rn))
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, (void *)rn, rn->lock);
      zlog_backtrace(LOG_DEBUG);
      return;
    }

  if (zebrad.ribq == NULL)
    {
      zlog_err ("%s: work_queue does not exist!", __func__);
      return;
    }

  /*
   * The RIB queue should normally be either empty or holding the only
   * work_queue_item element. In the latter case this element would
   * hold a pointer to the meta queue structure, which must be used to
   * actually queue the route nodes to process. So create the MQ
   * holder, if necessary, then push the work into it in any case.
   * This semantics was introduced after 0.99.9 release.
   */
  if (!zebrad.ribq->items->count)
    work_queue_add (zebrad.ribq, zebrad.mq);

  rib_meta_queue_add (zebrad.mq, rn);

  return;
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *
meta_queue_new (void)
{
  struct meta_queue *new;
  unsigned i;

  new = XCALLOC (MTYPE_WORK_QUEUE, sizeof (struct meta_queue));
  assert(new);

  for (i = 0; i < MQ_SIZE; i++)
    {
      new->subq[i] = list_new ();
      assert(new->subq[i]);
    }

  return new;
}

/* initialise zebra rib work queue */
static void
rib_queue_init (struct zebra_t *zebra)
{
  assert (zebra);
  
  if (! (zebra->ribq = work_queue_new (zebra->master, 
                                       "route_node processing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  /* fill in the work queue spec */
  zebra->ribq->spec.workfunc = &meta_queue_process;
  zebra->ribq->spec.errorfunc = NULL;
  zebra->ribq->spec.completion_func = &meta_queue_process_complete;
  /* XXX: TODO: These should be runtime configurable via vty */
  zebra->ribq->spec.max_retries = 3;
  zebra->ribq->spec.hold = rib_process_hold_time;
  
  if (!(zebra->mq = meta_queue_new ()))
  {
    zlog_err ("%s: could not initialise meta queue!", __func__);
    return;
  }
  return;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * RIBs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install_route (when an existing RIB is updated)
 * and then submit route_node to queue for best-path selection later.
 * Order of add/delete state changes are preserved for any given RIB.
 *
 * Deleted RIBs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset RIB_ENTRY_REMOVE        |->Update kernel with
 *       |-------->|                             |  best RIB, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 * |-> set RIB_ENTRY_REMOVE                           |
 * rib_delnode                                  (RIB freed)
 *
 * The 'info' pointer of a route_node points to a rib_dest_t
 * ('dest'). Queueing state for a route_node is kept on the dest. The
 * dest is created on-demand by rib_link() and is kept around at least
 * as long as there are ribs hanging off it (@see rib_gc_dest()).
 * 
 * Refcounting (aka "locking" throughout the GNU Zebra and Quagga code):
 *
 * - route_nodes: refcounted by:
 *   - dest attached to route_node:
 *     - managed by: rib_link/rib_gc_dest
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */
 
/* Add RIB to head of the route node. */
static void
rib_link (struct route_node *rn, struct rib *rib, int process)
{
  struct rib *head;
  rib_dest_t *dest;
  afi_t afi;
  const char *rmap_name;

  assert (rib && rn);
  
  dest = rib_dest_from_rnode (rn);
  if (!dest)
    {
      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        rnode_debug (rn, rib->vrf_id, "rn %p adding dest", rn);

      dest = XCALLOC (MTYPE_RIB_DEST, sizeof (rib_dest_t));
      route_lock_node (rn); /* rn route table reference */
      rn->info = dest;
      dest->rnode = rn;
    }

  head = dest->routes;
  if (head)
    {
      head->prev = rib;
    }
  rib->next = head;
  dest->routes = rib;

  afi = (rn->p.family == AF_INET) ? AFI_IP :
    (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
  if (is_zebra_import_table_enabled (afi, rib->table))
    {
      rmap_name = zebra_get_import_table_route_map (afi, rib->table);
      zebra_add_import_table_entry(rn, rib, rmap_name);
    }
  else
    if (process)
      rib_queue_add (rn);
}

void
rib_addnode (struct route_node *rn, struct rib *rib, int process)
{
  /* RIB node has been un-removed before route-node is processed. 
   * route_node must hence already be on the queue for processing.. 
   */
  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
    {
      if (IS_ZEBRA_DEBUG_RIB)
	  rnode_debug (rn, rib->vrf_id, "rn %p, un-removed rib %p", (void *)rn, (void *)rib);

      UNSET_FLAG (rib->status, RIB_ENTRY_REMOVED);
      return;
    }
  rib_link (rn, rib, process);
}

/*
 * rib_unlink
 *
 * Detach a rib structure from a route_node.
 *
 * Note that a call to rib_unlink() should be followed by a call to
 * rib_gc_dest() at some point. This allows a rib_dest_t that is no
 * longer required to be deleted.
 */
static void
rib_unlink (struct route_node *rn, struct rib *rib)
{
  rib_dest_t *dest;

  assert (rn && rib);

  if (IS_ZEBRA_DEBUG_RIB)
	  rnode_debug (rn, rib->vrf_id, "rn %p, rib %p", (void *)rn, (void *)rib);

  dest = rib_dest_from_rnode (rn);

  if (rib->next)
    rib->next->prev = rib->prev;

  if (rib->prev)
    rib->prev->next = rib->next;
  else
    {
      dest->routes = rib->next;
    }

  /* free RIB and nexthops */
  zebra_deregister_rnh_static_nexthops (rib->vrf_id, rib->nexthop, rn);
  nexthops_free(rib->nexthop);
  XFREE (MTYPE_RIB, rib);

}

void
rib_delnode (struct route_node *rn, struct rib *rib)
{
  afi_t afi;

  if (IS_ZEBRA_DEBUG_RIB)
    rnode_debug (rn, rib->vrf_id, "rn %p, rib %p, removing", (void *)rn, (void *)rib);
  SET_FLAG (rib->status, RIB_ENTRY_REMOVED);

  afi = (rn->p.family == AF_INET) ? AFI_IP :
          (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
  if (is_zebra_import_table_enabled (afi, rib->table))
    {
      zebra_del_import_table_entry(rn, rib);
      /* Just clean up if non main table */
      if (IS_ZEBRA_DEBUG_RIB)
        {
          char buf[INET6_ADDRSTRLEN];
          if (IS_ZEBRA_DEBUG_RIB)
            {
              inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
              zlog_debug ("%u:%s/%d: Freeing route rn %p, rib %p (type %d)",
                          rib->vrf_id, buf, rn->p.prefixlen, rn, rib, rib->type);
            }
        }

      rib_unlink(rn, rib);
    }
  else
    {
      rib_queue_add (rn);
    }
}

/* This function dumps the contents of a given RIB entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */

void _rib_dump (const char * func,
		union prefix46constptr pp, const struct rib * rib)
{
  const struct prefix *p = pp.p;
  char straddr[PREFIX_STRLEN];
  struct nexthop *nexthop, *tnexthop;
  int recursing;

  zlog_debug ("%s: dumping RIB entry %p for %s vrf %u", func, (const void *)rib,
              prefix2str(pp, straddr, sizeof(straddr)), rib->vrf_id);
  zlog_debug
  (
    "%s: refcnt == %lu, uptime == %lu, type == %u, instance == %d, table == %d",
    func,
    rib->refcnt,
    (unsigned long) rib->uptime,
    rib->type,
    rib->instance,
    rib->table
  );
  zlog_debug
  (
    "%s: metric == %u, mtu == %u, distance == %u, flags == %u, status == %u",
    func,
    rib->metric,
    rib->mtu,
    rib->distance,
    rib->flags,
    rib->status
  );
  zlog_debug
  (
    "%s: nexthop_num == %u, nexthop_active_num == %u, nexthop_fib_num == %u",
    func,
    rib->nexthop_num,
    rib->nexthop_active_num,
    rib->nexthop_fib_num
  );

  for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
    {
      inet_ntop (p->family, &nexthop->gate, straddr, INET6_ADDRSTRLEN);
      zlog_debug
      (
        "%s: %s %s with flags %s%s%s",
        func,
        (recursing ? "  NH" : "NH"),
        straddr,
        (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) ? "ACTIVE " : ""),
        (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? "FIB " : ""),
        (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ? "RECURSIVE" : "")
      );
    }
  zlog_debug ("%s: dump complete", func);
}

/* This is an exported helper to rtm_read() to dump the strange
 * RIB entry found by rib_lookup_ipv4_route()
 */

void rib_lookup_and_dump (struct prefix_ipv4 * p, vrf_id_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  char prefix_buf[INET_ADDRSTRLEN];

  /* Lookup table.  */
  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (! table)
  {
    zlog_err ("%s: zebra_vrf_table() returned NULL", __func__);
    return;
  }

  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
  {
    zlog_debug ("%s: lookup failed for %s", __func__,
                prefix2str((struct prefix*) p, prefix_buf, sizeof(prefix_buf)));
    return;
  }

  /* Unlock node. */
  route_unlock_node (rn);

  /* let's go */
  RNODE_FOREACH_RIB (rn, rib)
  {
    zlog_debug
    (
      "%s: rn %p, rib %p: %s, %s",
      __func__,
      (void *)rn,
      (void *)rib,
      (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED) ? "removed" : "NOT removed"),
      (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) ? "selected" : "NOT selected")
    );
    rib_dump (p, rib);
  }
}

/* Check if requested address assignment will fail due to another
 * route being installed by zebra in FIB already. Take necessary
 * actions, if needed: remove such a route from FIB and deSELECT
 * corresponding RIB entry. Then put affected RN into RIBQ head.
 */
void rib_lookup_and_pushup (struct prefix_ipv4 * p, vrf_id_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  unsigned changed = 0;

  if (NULL == (table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id)))
  {
    zlog_err ("%s: zebra_vrf_table() returned NULL", __func__);
    return;
  }

  /* No matches would be the simplest case. */
  if (NULL == (rn = route_node_lookup (table, (struct prefix *) p)))
    return;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Check all RIB entries. In case any changes have to be done, requeue
   * the RN into RIBQ head. If the routing message about the new connected
   * route (generated by the IP address we are going to assign very soon)
   * comes before the RIBQ is processed, the new RIB entry will join
   * RIBQ record already on head. This is necessary for proper revalidation
   * of the rest of the RIB.
   */
  RNODE_FOREACH_RIB (rn, rib)
  {
    if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) &&
      ! RIB_SYSTEM_ROUTE (rib))
    {
      changed = 1;
      if (IS_ZEBRA_DEBUG_RIB)
      {
        char buf[PREFIX_STRLEN];
        zlog_debug ("%u:%s: freeing way for connected prefix",
                    rib->vrf_id, prefix2str(&rn->p, buf, sizeof(buf)));
        rib_dump (&rn->p, rib);
      }
      rib_uninstall (rn, rib);
    }
  }
  if (changed)
    rib_queue_add (rn);
}

int
rib_add_multipath (afi_t afi, safi_t safi, struct prefix *p,
		   struct rib *rib)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *same;
  struct nexthop *nexthop;
  int ret = 0;
  int family;

  if (!rib)
    return 0;

  if (p->family == AF_INET)
    family = AFI_IP;
  else
    family = AFI_IP6;

  /* Lookup table.  */
  table = zebra_vrf_table_with_table_id (family, safi, rib->vrf_id, rib->table);
  if (! table)
    return 0;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (rib->distance == 0)
    {
      rib->distance = route_info[rib->type].distance;

      /* iBGP distance is 200. */
      if (rib->type == ZEBRA_ROUTE_BGP 
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
	rib->distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (table, p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  RNODE_FOREACH_RIB (rn, same)
    {
      if (CHECK_FLAG (same->status, RIB_ENTRY_REMOVED))
        continue;
      
      if (same->type == rib->type && same->instance == rib->instance
          && same->table == rib->table
	  && same->type != ZEBRA_ROUTE_CONNECT)
        break;
    }
  
  /* If this route is kernel route, set FIB flag to the route. */
  if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  if (IS_ZEBRA_DEBUG_RIB)
    {
      char buf[INET6_ADDRSTRLEN];
      if (IS_ZEBRA_DEBUG_RIB)
        {
          inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
          zlog_debug ("%u:%s/%d: Inserting route rn %p, rib %p (type %d) "
                      "existing %p",
                      rib->vrf_id, buf, p->prefixlen, (void *)rn,
		      (void *)rib, rib->type, (void *)same);
        }

      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        rib_dump ((struct prefix *)p, rib);
    }
  rib_addnode (rn, rib, 1);
  ret = 1;

  /* Free implicit route.*/
  if (same)
    {
      rib_delnode (rn, same);
      ret = -1;
    }
  
  route_unlock_node (rn);
  return ret;
}

int
rib_delete (afi_t afi, safi_t safi, vrf_id_t vrf_id, int type, u_short instance,
	    int flags, struct prefix *p, union g_addr *gate, ifindex_t ifindex,
	    u_int32_t table_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct rib *fib = NULL;
  struct rib *same = NULL;
  struct nexthop *nexthop, *tnexthop;
  int recursing;
  char buf1[PREFIX_STRLEN];
  char buf2[INET6_ADDRSTRLEN];

  /* Lookup table.  */
  table = zebra_vrf_table_with_table_id (afi, safi, vrf_id, table_id);
  if (! table)
    return 0;

  /* Apply mask. */
  apply_mask (p);

  /* Lookup route node. */
  rn = route_node_lookup (table, p);
  if (! rn)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%u:%s: doesn't exist in rib",
                    vrf_id, prefix2str (p, buf1, sizeof(buf1)));
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  RNODE_FOREACH_RIB (rn, rib)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      if (rib->type != type)
	continue;
      if (rib->instance != instance)
	continue;
      if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) &&
	  nexthop->type == NEXTHOP_TYPE_IFINDEX)
	{
	  if (nexthop->ifindex != ifindex)
	    continue;
	  if (rib->refcnt)
	    {
	      rib->refcnt--;
	      route_unlock_node (rn);
	      route_unlock_node (rn);
	      return 0;
	    }
	  same = rib;
	  break;
	}
      /* Make sure that the route found has the same gateway. */
      else
        {
          if (gate == NULL)
            {
              same = rib;
              break;
            }
          for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
            if (IPV4_ADDR_SAME (&nexthop->gate.ipv4, gate) ||
	        IPV6_ADDR_SAME (&nexthop->gate.ipv6, gate))
              {
                same = rib;
                break;
              }
          if (same)
            break;
        }
    }
  /* If same type of route can't be found and this message is from
     kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL &&
          CHECK_FLAG(flags, ZEBRA_FLAG_SELFROUTE))
        {
          if (IS_ZEBRA_DEBUG_RIB)
            {
              zlog_debug ("%u:%s: rn %p, rib %p (type %d) was deleted "
                          "from kernel, adding",
			  vrf_id, prefix2str(p, buf1, INET6_ADDRSTRLEN),
                          rn, fib, fib->type);
            }
	  if (allow_delete)
	    {
	      /* Unset flags. */
	      for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
		UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
	    }
	  else
	    {
	      /* This means someone else, other than Zebra, has deleted
	       * a Zebra router from the kernel. We will add it back */
	      rib_install_kernel(rn, fib, 0);
	    }
        }
      else
	{
	  if (IS_ZEBRA_DEBUG_RIB)
	    {
	      if (gate)
		zlog_debug ("%u:%s: via %s ifindex %d type %d "
			   "doesn't exist in rib",
			    vrf_id, prefix2str (p, buf1, sizeof(buf1)),
			    inet_ntop (family2afi(afi), gate, buf2, INET_ADDRSTRLEN),
			    ifindex,
			    type);
	      else
		zlog_debug ("%u:%s: ifindex %d type %d doesn't exist in rib",
			    vrf_id, prefix2str (p, buf1, sizeof(buf1)),
			    ifindex,
			    type);
	    }
	  route_unlock_node (rn);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }
  
  if (same)
    rib_delnode (rn, same);
  
  route_unlock_node (rn);
  return 0;
}



int
rib_add (afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
	 u_short instance, int flags, struct prefix *p,
	 union g_addr *gate, union g_addr *src, ifindex_t ifindex,
	 u_int32_t table_id, u_int32_t metric, u_int32_t mtu,
	 u_char distance)
{
  struct rib *rib;
  struct rib *same = NULL;
  struct route_table *table;
  struct route_node *rn;
  struct nexthop *nexthop;

  /* Lookup table.  */
  table = zebra_vrf_table_with_table_id (afi, safi, vrf_id, table_id);
  if (! table)
    return 0;

  /* Make sure mask is applied. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (distance == 0)
    {
      if ((unsigned)type >= array_size(route_info))
	distance = 150;
      else
        distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (table,  p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  RNODE_FOREACH_RIB (rn, rib)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (rib->type != type)
	continue;
      if (rib->instance != instance)
	continue;
      if (rib->type != ZEBRA_ROUTE_CONNECT)
	{
	  same = rib;
	  break;
	}
      /* Duplicate connected route comes in. */
      else if ((nexthop = rib->nexthop) &&
	       nexthop->type == NEXTHOP_TYPE_IFINDEX &&
	       nexthop->ifindex == ifindex &&
	       !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	{
	  rib->refcnt++;
	  return 0 ;
	}
    }

  /* Allocate new rib structure. */
  rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
  
  rib->type = type;
  rib->instance = instance;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->mtu = mtu;
  rib->table = table_id;
  rib->vrf_id = vrf_id;
  rib->nexthop_num = 0;
  rib->uptime = time (NULL);

  /* Nexthop settings. */
  if (gate)
    {
      if (afi == AFI_IP6)
	{
	  if (ifindex)
	    rib_nexthop_ipv6_ifindex_add (rib, &gate->ipv6, ifindex);
	  else
	    rib_nexthop_ipv6_add (rib, &gate->ipv6);
	}
      else
	{
	  if (ifindex)
	    rib_nexthop_ipv4_ifindex_add (rib, &gate->ipv4, &src->ipv4, ifindex);
	  else
	    rib_nexthop_ipv4_add (rib, &gate->ipv4, &src->ipv4);
	}
    }
  else
    rib_nexthop_ifindex_add (rib, ifindex);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  if (IS_ZEBRA_DEBUG_RIB)
    {
      char buf[INET6_ADDRSTRLEN];
      if (IS_ZEBRA_DEBUG_RIB)
        {
          inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN);
          zlog_debug ("%u:%s/%d: Inserting route rn %p, rib %p (type %d) "
                      "existing %p",
                      vrf_id, buf, p->prefixlen, (void *)rn,
		      (void *)rib, rib->type, (void *)same);
        }

      if (IS_ZEBRA_DEBUG_RIB_DETAILED)
        rib_dump (p, rib);
    }
  rib_addnode (rn, rib, 1);

  /* Free implicit route.*/
  if (same)
    rib_delnode (rn, same);
  
  route_unlock_node (rn);
  return 0;
}

/* Schedule routes of a particular table (address-family) based on event. */
static void
rib_update_table (struct route_table *table, rib_update_event_t event)
{
  struct route_node *rn;
  struct rib *rib, *next;

  /* Walk all routes and queue for processing, if appropriate for
   * the trigger event.
   */
  for (rn = route_top (table); rn; rn = route_next (rn))
    {
      switch (event)
        {
        case RIB_UPDATE_IF_CHANGE:
          /* Examine all routes that won't get processed by the protocol or
           * triggered by nexthop evaluation (NHT). This would be system,
           * kernel and certain static routes. Note that NHT will get
           * triggered upon an interface event as connected routes always
           * get queued for processing.
           */
          RNODE_FOREACH_RIB_SAFE (rn, rib, next)
            {
              if (rib->type == ZEBRA_ROUTE_OSPF ||
                  rib->type == ZEBRA_ROUTE_OSPF6 ||
                  rib->type == ZEBRA_ROUTE_BGP)
                continue; /* protocol will handle. */
              else if (rib->type == ZEBRA_ROUTE_STATIC)
                {
                  struct nexthop *nh;
                  for (nh = rib->nexthop; nh; nh = nh->next)
                    if (!(nh->type == NEXTHOP_TYPE_IPV4 ||
                        nh->type == NEXTHOP_TYPE_IPV6))
                      break;

                  /* If we only have nexthops to a gateway, NHT will
                   * take care.
                   */
                  if (nh)
                    rib_queue_add (rn);
                }
              else
                  rib_queue_add (rn);
            }
          break;

        case RIB_UPDATE_RMAP_CHANGE:
        case RIB_UPDATE_OTHER:
          /* Right now, examine all routes. Can restrict to a protocol in
           * some cases (TODO).
           */
          if (rnode_to_ribs (rn))
            rib_queue_add (rn);
          break;

        default:
          break;
        }
    }
}

/* RIB update function. */
void
rib_update (vrf_id_t vrf_id, rib_update_event_t event)
{
  struct route_table *table;

  /* Process routes of interested address-families. */
  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, vrf_id);
  if (table)
    rib_update_table (table, event);

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, vrf_id);
  if (table)
    rib_update_table (table, event);
}

/* Remove all routes which comes from non main table.  */
static void
rib_weed_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB_SAFE (rn, rib, next)
	{
	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->table != zebrad.rtm_table_default &&
	      rib->table != RT_TABLE_MAIN)
            rib_delnode (rn, rib);
	}
}

/* Delete all routes from non main table. */
void
rib_weed_tables (void)
{
  vrf_iter_t iter;
  struct zebra_vrf *zvrf;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      {
        rib_weed_table (zvrf->table[AFI_IP][SAFI_UNICAST]);
        rib_weed_table (zvrf->table[AFI_IP6][SAFI_UNICAST]);
      }
}

/* Delete self installed routes after zebra is relaunched.  */
static void
rib_sweep_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;
  int ret = 0;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB_SAFE (rn, rib, next)
	{
	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->type == ZEBRA_ROUTE_KERNEL && 
	      CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
	    {
	      ret = rib_uninstall_kernel (rn, rib);
	      if (! ret)
                rib_delnode (rn, rib);
	    }
	}
}

/* Sweep all RIB tables.  */
void
rib_sweep_route (void)
{
  vrf_iter_t iter;
  struct zebra_vrf *zvrf;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      {
        rib_sweep_table (zvrf->table[AFI_IP][SAFI_UNICAST]);
        rib_sweep_table (zvrf->table[AFI_IP6][SAFI_UNICAST]);
      }
}

/* Remove specific by protocol routes from 'table'. */
static unsigned long
rib_score_proto_table (u_char proto, u_short instance, struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;
  unsigned long n = 0;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB_SAFE (rn, rib, next)
        {
          if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;
          if (rib->type == proto && rib->instance == instance)
            {
              rib_delnode (rn, rib);
              n++;
            }
        }

  return n;
}

/* Remove specific by protocol routes. */
unsigned long
rib_score_proto (u_char proto, u_short instance)
{
  vrf_iter_t iter;
  struct zebra_vrf *zvrf;
  unsigned long cnt = 0;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    if ((zvrf = vrf_iter2info (iter)) != NULL)
      cnt += rib_score_proto_table (proto, instance, zvrf->table[AFI_IP][SAFI_UNICAST])
            +rib_score_proto_table (proto, instance, zvrf->table[AFI_IP6][SAFI_UNICAST]);

  return cnt;
}

/* Close RIB and clean up kernel routes. */
void
rib_close_table (struct route_table *table)
{
  struct route_node *rn;
  rib_table_info_t *info = table->info;
  struct rib *rib;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      RNODE_FOREACH_RIB (rn, rib)
        {
          if (!CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	    continue;

          if (info->safi == SAFI_UNICAST)
            zfpm_trigger_update (rn, NULL);

	  if (! RIB_SYSTEM_ROUTE (rib))
	    rib_uninstall_kernel (rn, rib);
        }
}

/* Close all RIB tables.  */
void
rib_close (void)
{
  vrf_iter_t iter;
  struct zebra_vrf *zvrf;
  struct listnode *node;
  struct interface *ifp;
  u_int32_t table_id;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) != NULL)
        {
          rib_close_table (zvrf->table[AFI_IP][SAFI_UNICAST]);
          rib_close_table (zvrf->table[AFI_IP6][SAFI_UNICAST]);
        }
      for (ALL_LIST_ELEMENTS_RO (vrf_iter2iflist (iter), node, ifp))
        if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);
    }

  /* If we do multiple tables per vrf, need to move this to loop above */
  zvrf = vrf_info_lookup (VRF_DEFAULT);

  for (table_id = 0; table_id < ZEBRA_KERNEL_TABLE_MAX; table_id++)
    {
      if (zvrf->other_table[AFI_IP][table_id])
        rib_close_table (zvrf->other_table[AFI_IP][table_id]);

      if (zvrf->other_table[AFI_IP6][table_id])
        rib_close_table (zvrf->other_table[AFI_IP6][table_id]);
    }

  zebra_mpls_close_tables(zvrf);

}

/* Routing information base initialize. */
void
rib_init (void)
{
  rib_queue_init (&zebrad);
}

/*
 * vrf_id_get_next
 *
 * Get the first vrf id that is greater than the given vrf id if any.
 *
 * Returns TRUE if a vrf id was found, FALSE otherwise.
 */
static inline int
vrf_id_get_next (vrf_id_t vrf_id, vrf_id_t *next_id_p)
{
  vrf_iter_t iter = vrf_iterator (vrf_id);
  struct zebra_vrf *zvrf = vrf_iter2info (iter);

  /* The same one ? Then find out the next. */
  if (zvrf && (zvrf->vrf_id == vrf_id))
    zvrf = vrf_iter2info (vrf_next (iter));

  if (zvrf)
    {
      *next_id_p = zvrf->vrf_id;
      return 1;
    }

  return 0;
}

/*
 * rib_tables_iter_next
 *
 * Returns the next table in the iteration.
 */
struct route_table *
rib_tables_iter_next (rib_tables_iter_t *iter)
{
  struct route_table *table;

  /*
   * Array that helps us go over all AFI/SAFI combinations via one
   * index.
   */
  static struct {
    afi_t afi;
    safi_t safi;
  } afi_safis[] = {
    { AFI_IP, SAFI_UNICAST },
    { AFI_IP, SAFI_MULTICAST },
    { AFI_IP6, SAFI_UNICAST },
    { AFI_IP6, SAFI_MULTICAST },
  };

  table = NULL;

  switch (iter->state)
    {

    case RIB_TABLES_ITER_S_INIT:
      iter->vrf_id = VRF_DEFAULT;
      iter->afi_safi_ix = -1;

      /* Fall through */

    case RIB_TABLES_ITER_S_ITERATING:
      iter->afi_safi_ix++;
      while (1)
	{

	  while (iter->afi_safi_ix < (int) ZEBRA_NUM_OF (afi_safis))
	    {
	      table = zebra_vrf_table (afi_safis[iter->afi_safi_ix].afi,
				 afi_safis[iter->afi_safi_ix].safi,
				 iter->vrf_id);
	      if (table)
		break;

	      iter->afi_safi_ix++;
	    }

	  /*
	   * Found another table in this vrf.
	   */
	  if (table)
	    break;

	  /*
	   * Done with all tables in the current vrf, go to the next
	   * one.
	   */
	  if (!vrf_id_get_next (iter->vrf_id, &iter->vrf_id))
	    break;

	  iter->afi_safi_ix = 0;
	}

      break;

    case RIB_TABLES_ITER_S_DONE:
      return NULL;
    }

  if (table)
    iter->state = RIB_TABLES_ITER_S_ITERATING;
  else
    iter->state = RIB_TABLES_ITER_S_DONE;

  return table;
}

