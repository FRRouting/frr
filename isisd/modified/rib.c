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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "vty.h"
#include "str.h"
#include "command.h"
#include "linklist.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"

/* Routing information base and static table for IPv4. */
struct route_table *rib_table_ipv4;
struct route_table *static_table_ipv4;

/* Routing information base and static table for IPv6. */
#ifdef HAVE_IPV6
struct route_table *rib_table_ipv6;
struct route_table *static_table_ipv6;
#endif /* HAVE_IPV6 */

/* Default rtm_table for all clients */
extern int rtm_table_default;

/* Each route type's string and default distance value. */
struct
{  
  int key;
  char c;
  char *str;
  int distance;
} route_info[] =
{
  {ZEBRA_ROUTE_SYSTEM,  'X', "system",      0},
  {ZEBRA_ROUTE_KERNEL,  'K', "kernel",      0},
  {ZEBRA_ROUTE_CONNECT, 'C', "connected",   0},
  {ZEBRA_ROUTE_STATIC,  'S', "static",      1},
  {ZEBRA_ROUTE_RIP,     'R', "rip",       120},
  {ZEBRA_ROUTE_RIPNG,   'R', "ripng",     120},
  {ZEBRA_ROUTE_OSPF,    'O', "ospf",      110},
  {ZEBRA_ROUTE_OSPF6,   'O', "ospf6",     110},
  {ZEBRA_ROUTE_ISIS,    'I', "isis",      115},
  {ZEBRA_ROUTE_BGP,     'B', "bgp",        20  /* IBGP is 200. */}
};

/* Add nexthop to the end of the list.  */
void
nexthop_add (struct rib *rib, struct nexthop *nexthop)
{
  struct nexthop *last;

  for (last = rib->nexthop; last && last->next; last = last->next)
    ;
  if (last)
    last->next = nexthop;
  else
    rib->nexthop = nexthop;
  nexthop->prev = last;

  rib->nexthop_num++;
}

/* Delete specified nexthop from the list. */
void
nexthop_delete (struct rib *rib, struct nexthop *nexthop)
{
  if (nexthop->next)
    nexthop->next->prev = nexthop->prev;
  if (nexthop->prev)
    nexthop->prev->next = nexthop->next;
  else
    rib->nexthop = nexthop->next;
  rib->nexthop_num--;
}

/* Free nexthop. */
void
nexthop_free (struct nexthop *nexthop)
{
  if (nexthop->type == NEXTHOP_TYPE_IFNAME && nexthop->ifname)
    free (nexthop->ifname);
  XFREE (MTYPE_NEXTHOP, nexthop);
}

struct nexthop *
nexthop_ifindex_add (struct rib *rib, unsigned int ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IFINDEX;
  nexthop->ifindex = ifindex;

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ifname_add (struct rib *rib, char *ifname)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IFNAME;
  nexthop->ifname = strdup (ifname);

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ipv4_add (struct rib *rib, struct in_addr *ipv4)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IPV4;
  nexthop->gate.ipv4 = *ipv4;

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ipv4_ifindex_add (struct rib *rib, struct in_addr *ipv4, 
			  unsigned int ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
  nexthop->gate.ipv4 = *ipv4;
  nexthop->ifindex = ifindex;

  nexthop_add (rib, nexthop);

  return nexthop;
}

#ifdef HAVE_IPV6
struct nexthop *
nexthop_ipv6_add (struct rib *rib, struct in6_addr *ipv6)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IPV6;
  nexthop->gate.ipv6 = *ipv6;

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ipv6_ifname_add (struct rib *rib, struct in6_addr *ipv6,
			 char *ifname)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IPV6_IFNAME;
  nexthop->gate.ipv6 = *ipv6;
  nexthop->ifname = XSTRDUP (0, ifname);

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ipv6_ifindex_add (struct rib *rib, struct in6_addr *ipv6,
			  unsigned int ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
  nexthop->gate.ipv6 = *ipv6;
  nexthop->ifindex = ifindex;

  nexthop_add (rib, nexthop);

  return nexthop;
}
#endif /* HAVE_IPV6 */

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
int
nexthop_active_ipv4 (struct rib *rib, struct nexthop *nexthop, int set,
		     struct route_node *top)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  if (nexthop->type == NEXTHOP_TYPE_IPV4)
    nexthop->ifindex = 0;

  if (set)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

  /* Make lookup prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv4;

  rn = route_node_match (rib_table_ipv4, (struct prefix *) &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immidiately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
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
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			nexthop->rtype = newhop->type;
			if (newhop->type == NEXTHOP_TYPE_IPV4 ||
			    newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
			  nexthop->rgate.ipv4 = newhop->gate.ipv4;
			if (newhop->type == NEXTHOP_TYPE_IFINDEX
			    || newhop->type == NEXTHOP_TYPE_IFNAME
			    || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
			  nexthop->rifindex = newhop->ifindex;
		      }
		    return 1;
		  }
	      return 0;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

#ifdef HAVE_IPV6
/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
int
nexthop_active_ipv6 (struct rib *rib, struct nexthop *nexthop, int set,
		     struct route_node *top)
{
  struct prefix_ipv6 p;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  if (nexthop->type == NEXTHOP_TYPE_IPV6)
    nexthop->ifindex = 0;

  if (set)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

  /* Make lookup prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv6;

  rn = route_node_match (rib_table_ipv6, (struct prefix *) &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immidiately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
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
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			nexthop->rtype = newhop->type;
			if (newhop->type == NEXTHOP_TYPE_IPV6
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFNAME)
			  nexthop->rgate.ipv6 = newhop->gate.ipv6;
			if (newhop->type == NEXTHOP_TYPE_IFINDEX
			    || newhop->type == NEXTHOP_TYPE_IFNAME
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX
			    || newhop->type == NEXTHOP_TYPE_IPV6_IFNAME)
			  nexthop->rifindex = newhop->ifindex;
		      }
		    return 1;
		  }
	      return 0;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}
#endif /* HAVE_IPV6 */

struct rib *
rib_match_ipv4 (struct in_addr addr)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = addr;

  rn = route_node_match (rib_table_ipv4, (struct prefix *) &p);

  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    /* Directly point connected route. */
	    return match;
	  else
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  return match;
	      return NULL;
	    }
	}
    }
  return NULL;
}

struct rib *
rib_lookup_ipv4 (struct prefix_ipv4 *p)
{
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop;

  rn = route_node_lookup (rib_table_ipv4, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
    return NULL;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Pick up selected route. */
  for (match = rn->info; match; match = match->next)
    if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
      break;

  if (! match || match->type == ZEBRA_ROUTE_BGP)
    return NULL;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return match;
  
  for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
      return match;

  return NULL;
}

#ifdef HAVE_IPV6
struct rib *
rib_match_ipv6 (struct in6_addr *addr)
{
  struct prefix_ipv6 p;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  IPV6_ADDR_COPY (&p.prefix, addr);

  rn = route_node_match (rib_table_ipv6, (struct prefix *) &p);

  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    /* Directly point connected route. */
	    return match;
	  else
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  return match;
	      return NULL;
	    }
	}
    }
  return NULL;
}
#endif /* HAVE_IPV6 */

int
nexthop_active_check (struct route_node *rn, struct rib *rib,
		      struct nexthop *nexthop, int set)
{
  struct interface *ifp;

  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IFINDEX:
      ifp = if_lookup_by_index (nexthop->ifindex);
      if (ifp && if_is_up (ifp))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IFNAME:
    case NEXTHOP_TYPE_IPV6_IFNAME:
      ifp = if_lookup_by_name (nexthop->ifname);
      if (ifp && if_is_up (ifp))
	{
	  if (set)
	    nexthop->ifindex = ifp->ifindex;
	  SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      else
	{
	  if (set)
	    nexthop->ifindex = 0;
	  UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      break;
    case NEXTHOP_TYPE_IPV4:
    case NEXTHOP_TYPE_IPV4_IFINDEX:
      if (nexthop_active_ipv4 (rib, nexthop, set, rn))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
#ifdef HAVE_IPV6
    case NEXTHOP_TYPE_IPV6:
      if (nexthop_active_ipv6 (rib, nexthop, set, rn))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      if (IN6_IS_ADDR_LINKLOCAL (&nexthop->gate.ipv6))
	{
	  ifp = if_lookup_by_index (nexthop->ifindex);
	  if (ifp && if_is_up (ifp))
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
#endif /* HAVE_IPV6 */
    default:
      break;
    }
  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

int
nexthop_active_update (struct route_node *rn, struct rib *rib, int set)
{
  struct nexthop *nexthop;
  int active;

  rib->nexthop_active_num = 0;
  UNSET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      rib->nexthop_active_num += nexthop_active_check (rn, rib, nexthop, set);
      if (active != CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
    }
  return rib->nexthop_active_num;
}

#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

void
newrib_free (struct rib *rib)
{
  struct nexthop *nexthop;
  struct nexthop *next;

  for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      nexthop_free (nexthop);
    }
  XFREE (MTYPE_RIB, rib);
}

void
rib_install_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      ret = kernel_add_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = kernel_add_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  if (ret < 0)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}

/* Uninstall the route from kernel. */
int
rib_uninstall_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
      ret = kernel_delete_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = kernel_delete_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  return ret;
}

/* Uninstall the route from kernel. */
void
rib_uninstall (struct route_node *rn, struct rib *rib)
{
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      redistribute_delete (&rn->p, rib);
      if (! RIB_SYSTEM_ROUTE (rib))
	rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }
}

/* Core function for processing routing information base. */
void
rib_process (struct route_node *rn, struct rib *del)
{
  struct rib *rib;
  struct rib *next;
  struct rib *fib = NULL;
  struct rib *select = NULL;

  for (rib = rn->info; rib; rib = next)
    {
      next = rib->next;

      /* Currently installed rib. */
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      /* Skip unreachable nexthop. */
      if (! nexthop_active_update (rn, rib, 0))
	continue;

      /* Infinit distance. */
      if (rib->distance == DISTANCE_INFINITY)
	continue;

      /* Newly selected rib. */
      if (! select || rib->distance < select->distance 
	  || rib->type == ZEBRA_ROUTE_CONNECT)
	select = rib;
    }

  /* Deleted route check. */
  if (del && CHECK_FLAG (del->flags, ZEBRA_FLAG_SELECTED))
    fib = del;

  /* Same route is selected. */
  if (select && select == fib)
    {
      if (CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED))
	{
	  redistribute_delete (&rn->p, select);
	  if (! RIB_SYSTEM_ROUTE (select))
	    rib_uninstall_kernel (rn, select);

	  /* Set real nexthop. */
	  nexthop_active_update (rn, select, 1);
  
	  if (! RIB_SYSTEM_ROUTE (select))
	    rib_install_kernel (rn, select);
	  redistribute_add (&rn->p, select);
	}
      return;
    }

  /* Uninstall old rib from forwarding table. */
  if (fib)
    {
      redistribute_delete (&rn->p, fib);
      if (! RIB_SYSTEM_ROUTE (fib))
	rib_uninstall_kernel (rn, fib);
      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
    }

  /* Install new rib into forwarding table. */
  if (select)
    {
      /* Set real nexthop. */
      nexthop_active_update (rn, select, 1);

      if (! RIB_SYSTEM_ROUTE (select))
	rib_install_kernel (rn, select);
      SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
      redistribute_add (&rn->p, select);
    }
}

/* Add RIB to head of the route node. */
void
rib_addnode (struct route_node *rn, struct rib *rib)
{
  struct rib *head;

  head = rn->info;
  if (head)
    head->prev = rib;
  rib->next = head;
  rn->info = rib;
}

void
rib_delnode (struct route_node *rn, struct rib *rib)
{
  if (rib->next)
    rib->next->prev = rib->prev;
  if (rib->prev)
    rib->prev->next = rib->next;
  else
    rn->info = rib->next;
}

int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table,
	      u_int32_t metric, u_char distance)
{
  struct rib *rib;
  struct rib *same = NULL;
  struct route_node *rn;
  struct nexthop *nexthop;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask_ipv4 (p);

  /* Set default distance by route type. */
  if (distance == 0)
    {
      distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (rib_table_ipv4, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (rib->type == ZEBRA_ROUTE_CONNECT)
	{
	  nexthop = rib->nexthop;

	  /* Duplicate connected route comes in. */
	  if (rib->type == type
	      && (! table || rib->table == table)
	      && nexthop && nexthop->type == NEXTHOP_TYPE_IFINDEX
	      && nexthop->ifindex == ifindex)
	    {
	      rib->refcnt++;
	      return 0 ;
	    }
	}
      else if (rib->type == type
	       && (! table || rib->table == table))
	{
	  same = rib;
	  rib_delnode (rn, same);
	  route_unlock_node (rn);
	  break;
	}
    }

  /* Allocate new rib structure. */
  rib = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  memset (rib, 0, sizeof (struct rib));
  rib->type = type;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->table = table;
  rib->nexthop_num = 0;
  rib->uptime = time (NULL);

  /* Nexthop settings. */
  if (gate)
    {
      if (ifindex)
	nexthop_ipv4_ifindex_add (rib, gate, ifindex);
      else
	nexthop_ipv4_add (rib, gate);
    }
  else
    nexthop_ifindex_add (rib, ifindex);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);

  /* Process this route node. */
  rib_process (rn, same);

  /* Free implicit route.*/
  if (same)
    newrib_free (same);

  return 0;
}

int
rib_add_ipv4_multipath (struct prefix_ipv4 *p, struct rib *rib)
{
  struct route_node *rn;
  struct rib *same;
  struct nexthop *nexthop;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask_ipv4 (p);

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
  rn = route_node_get (rib_table_ipv4, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (same = rn->info; same; same = same->next)
    {
      if (same->type == rib->type && same->table == rib->table
	  && same->type != ZEBRA_ROUTE_CONNECT)
	{
	  rib_delnode (rn, same);
	  route_unlock_node (rn);
	  break;
	}
    }

  /* If this route is kernel route, set FIB flag to the route. */
  if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);

  /* Process this route node. */
  rib_process (rn, same);

  /* Free implicit route.*/
  if (same)
    newrib_free (same);

  return 0;
}

int
rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *fib = NULL;
  struct rib *same = NULL;
  struct nexthop *nexthop;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];

  /* Apply mask. */
  apply_mask_ipv4 (p);

  /* Lookup route node. */
  rn = route_node_lookup (rib_table_ipv4, (struct prefix *) p);
  if (! rn)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
	{
	  if (gate)
	    zlog_info ("route %s/%d via %s ifindex %d doesn't exist in rib",
		       inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       inet_ntop (AF_INET, gate, buf2, BUFSIZ),
		       ifindex);
	  else
	    zlog_info ("route %s/%d ifindex %d doesn't exist in rib",
		       inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       ifindex);
	}
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      if (rib->type == ZEBRA_ROUTE_CONNECT)
	{
	  nexthop = rib->nexthop;

	  if (rib->type == type
	      && (! table || rib->table == table)
	      && nexthop && nexthop->type == NEXTHOP_TYPE_IFINDEX
	      && nexthop->ifindex == ifindex)
	    {
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
	}
      else
	{
	  if (rib->type == type
	      && (!table || rib->table == table))
	    {
	      same = rib;
	      break;
	    }
	}
    }

  /* If same type of route can't be found and this message is from
     kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL)
	{
	  /* Unset flags. */
	  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	  UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    {
	      if (gate)
		zlog_info ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
			   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
			   p->prefixlen,
			   inet_ntop (AF_INET, gate, buf2, BUFSIZ),
			   ifindex,
			   type);
	      else
		zlog_info ("route %s/%d ifindex %d type %d doesn't exist in rib",
			   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
			   p->prefixlen,
			   ifindex,
			   type);
	    }
	  route_unlock_node (rn);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }

  if (same)
    rib_delnode (rn, same);

  /* Process changes. */
  rib_process (rn, same);

  if (same)
    {
      newrib_free (same);
      route_unlock_node (rn);
    }

  route_unlock_node (rn);

  return 0;
}

/* Delete all added route and close rib. */
void
rib_close_ipv4 ()
{
  struct route_node *rn;
  struct rib *rib;

  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (! RIB_SYSTEM_ROUTE (rib)
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	rib_uninstall_kernel (rn, rib);
}

/* Install static route into rib. */
void
static_ipv4_install (struct prefix_ipv4 *p, struct static_ipv4 *si)
{
  struct rib *rib;
  struct route_node *rn;

  /* Lookup existing route */
  rn = route_node_get (rib_table_ipv4, (struct prefix *) p);
  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;

  if (rib)
    {
      /* Same distance static route is there.  Update it with new
         nexthop. */
      rib_uninstall (rn, rib);
      route_unlock_node (rn);

      switch (si->type)
	{
	case STATIC_IPV4_GATEWAY:
	  nexthop_ipv4_add (rib, &si->gate.ipv4);
	  break;
	case STATIC_IPV4_IFNAME:
	  nexthop_ifname_add (rib, si->gate.ifname);
	  break;
	}
      rib_process (rn, NULL);
    }
  else
    {
      /* This is new static route. */
      rib = XMALLOC (MTYPE_RIB, sizeof (struct rib));
      memset (rib, 0, sizeof (struct rib));

      rib->type = ZEBRA_ROUTE_STATIC;
      rib->distance = si->distance;
      rib->metric = 0;
      rib->nexthop_num = 0;

      switch (si->type)
	{
	case STATIC_IPV4_GATEWAY:
	  nexthop_ipv4_add (rib, &si->gate.ipv4);
	  break;
	case STATIC_IPV4_IFNAME:
	  nexthop_ifname_add (rib, si->gate.ifname);
	  break;
	}

      /* Link this rib to the tree. */
      rib_addnode (rn, rib);

      /* Process this prefix. */
      rib_process (rn, NULL);
    }
}

int
static_ipv4_nexthop_same (struct nexthop *nexthop, struct static_ipv4 *si)
{
  if (nexthop->type == NEXTHOP_TYPE_IPV4
      && si->type == STATIC_IPV4_GATEWAY
      && IPV4_ADDR_SAME (&nexthop->gate.ipv4, &si->gate.ipv4))
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IFNAME
      && si->type == STATIC_IPV4_IFNAME
      && strcmp (nexthop->ifname, si->gate.ifname) == 0)
    return 1;
  return 0;;
}

/* Uninstall static route from RIB. */
void
static_ipv4_uninstall (struct prefix_ipv4 *p, struct static_ipv4 *si)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;

  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (rib_table_ipv4, (struct prefix *) p);
  if (! rn)
    return;

  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;
  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (static_ipv4_nexthop_same (nexthop, si))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }
  
  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    {
      rib_delnode (rn, rib);
      rib_process (rn, rib);
      newrib_free (rib);
      route_unlock_node (rn);
    }
  else
    {
      rib_uninstall (rn, rib);
      nexthop_delete (rib, nexthop);
      nexthop_free (nexthop);
      rib_process (rn, rib);
    }

  /* Unlock node. */
  route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int
static_ipv4_add (struct prefix_ipv4 *p, struct in_addr *gate, char *ifname,
		 u_char distance, int table)
{
  u_char type = 0;
  struct route_node *rn;
  struct static_ipv4 *si;
  struct static_ipv4 *pp;
  struct static_ipv4 *cp;
  
  /* Lookup static route prefix. */
  rn = route_node_get (static_table_ipv4, (struct prefix *) p);

  /* Make flags. */
  if (gate)
    type = STATIC_IPV4_GATEWAY;
  if (ifname)
    type = STATIC_IPV4_IFNAME;

  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    {
      if (distance == si->distance 
	  && type == si->type
	  && (! gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4))
	  && (! ifname || strcmp (ifname, si->gate.ifname) == 0))
	{
	  route_unlock_node (rn);
	  return 0;
	}
    }

  /* Make new static route structure. */
  si = XMALLOC (MTYPE_STATIC_IPV4, sizeof (struct static_ipv4));
  memset (si, 0, sizeof (struct static_ipv4));

  si->type = type;
  si->distance = distance;

  if (gate)
    si->gate.ipv4 = *gate;
  if (ifname)
    si->gate.ifname = XSTRDUP (0, ifname);

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
	  if (ntohl (si->gate.ipv4.s_addr) < ntohl (cp->gate.ipv4.s_addr))
	    break;
	  if (ntohl (si->gate.ipv4.s_addr) > ntohl (cp->gate.ipv4.s_addr))
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
  static_ipv4_install (p, si);

  return 1;
}

/* Delete static route from static route configuration. */
int
static_ipv4_delete (struct prefix_ipv4 *p, struct in_addr *gate, char *ifname,
		    u_char distance, int table)
{
  u_char type = 0;
  struct route_node *rn;
  struct static_ipv4 *si;

  /* Lookup static route prefix. */
  rn = route_node_lookup (static_table_ipv4, (struct prefix *) p);
  if (! rn)
    return 0;

  /* Make flags. */
  if (gate)
    type = STATIC_IPV4_GATEWAY;
  if (ifname)
    type = STATIC_IPV4_IFNAME;

  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (distance == si->distance 
	&& type == si->type
	&& (! gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4))
	&& (! ifname || strcmp (ifname, si->gate.ifname) == 0))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  static_ipv4_uninstall (p, si);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  
  /* Free static route configuration. */
  XFREE (MTYPE_STATIC_IPV4, si);

  return 1;
}

/* Write IPv4 static route configuration. */
int
static_ipv4_write (struct vty *vty)
{
  struct route_node *rn;
  struct static_ipv4 *si;  
  int write;

  write = 0;

  for (rn = route_top (static_table_ipv4); rn; rn = route_next (rn))
    for (si = rn->info; si; si = si->next)
      {
	vty_out (vty, "ip route %s/%d", inet_ntoa (rn->p.u.prefix4),
		 rn->p.prefixlen);

	switch (si->type)
	  {
	  case STATIC_IPV4_GATEWAY:
	    vty_out (vty, " %s", inet_ntoa (si->gate.ipv4));
	    break;
	  case STATIC_IPV4_IFNAME:
	    vty_out (vty, " %s", si->gate.ifname);
	    break;
	  }

	if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
	  vty_out (vty, " %d", si->distance);
	vty_out (vty, "%s", VTY_NEWLINE);

	write = 1;
      }
  return write;
}

/* General fucntion for static route. */
int
static_ipv4_func (struct vty *vty, int add_cmd,
		  char *dest_str, char *mask_str, char *gate_str,
		  char *distance_str)
{
  int ret;
  u_char distance;
  struct prefix_ipv4 p;
  struct in_addr gate;
  struct in_addr mask;
  char *ifname;
  int table = rtm_table_default;
  
  ret = str2prefix_ipv4 (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Cisco like mask notation. */
  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (ret == 0)
	{
	  vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      p.prefixlen = ip_masklen (mask);
    }

  /* Apply mask for given prefix. */
  apply_mask_ipv4 (&p);

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* When gateway is A.B.C.D format, gate is treated as nexthop
     address other case gate is treated as interface name. */
  ret = inet_aton (gate_str, &gate);
  if (ret)
    ifname = NULL;
  else
    ifname = gate_str;

  if (add_cmd)
    static_ipv4_add (&p, ifname ? NULL : &gate, ifname, distance, table);
  else
    static_ipv4_delete (&p, ifname ? NULL : &gate, ifname, distance, table);

  return CMD_SUCCESS;
}

/* Static route configuration. */
DEFUN (ip_route, 
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 1, argv[0], NULL, argv[1], NULL);
}

DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 1, argv[0], argv[1], argv[2], NULL);
}

DEFUN (ip_route_pref,
       ip_route_pref_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 1, argv[0], NULL, argv[1], argv[2]);
}

DEFUN (ip_route_mask_pref,
       ip_route_mask_pref_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 1, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 0, argv[0], NULL, argv[1], NULL);
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 0, argv[0], argv[1], argv[2], NULL);
}

DEFUN (no_ip_route_pref,
       no_ip_route_pref_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 0, argv[0], NULL, argv[1], argv[2]);
}

DEFUN (no_ip_route_mask_pref,
       no_ip_route_mask_pref_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 0, argv[0], argv[1], argv[2], argv[3]);
}

/* New RIB.  Detailed information for IPv4 route. */
void
vty_show_ip_route_detail (struct vty *vty, struct route_node *rn)
{
  struct rib *rib;
  struct nexthop *nexthop;

  for (rib = rn->info; rib; rib = rib->next)
    {
      vty_out (vty, "Routing entry for %s/%d%s", 
	       inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
	       VTY_NEWLINE);
      vty_out (vty, "  Known via \"%s\"", route_info[rib->type].str);
      vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	vty_out (vty, ", best");
      if (rib->refcnt)
	vty_out (vty, ", refcnt %ld", rib->refcnt);
      vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

	  vty_out (vty, "  Last update ");

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  "%02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, "%dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, "%02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	  vty_out (vty, " ago%s", VTY_NEWLINE);
	}

      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	{
	  vty_out (vty, "  %c",
		   CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

	  switch (nexthop->type)
	    {
	    case NEXTHOP_TYPE_IPV4:
	    case NEXTHOP_TYPE_IPV4_IFINDEX:
	      vty_out (vty, " %s", inet_ntoa (nexthop->gate.ipv4));
	      if (nexthop->ifindex)
		vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	      vty_out (vty, " directly connected, %s",
		       ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " directly connected, %s",
		       nexthop->ifname);
	      break;
	    default:
	      break;
	    }
	  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	    vty_out (vty, " inactive");

	  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	    {
	      vty_out (vty, " (recursive");
		
	      switch (nexthop->rtype)
		{
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		  vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
		  break;
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_IFNAME:
		  vty_out (vty, " is directly connected, %s)",
			   ifindex2ifname (nexthop->rifindex));
		  break;
		default:
		  break;
		}
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

void
vty_show_ip_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
  struct nexthop *nexthop;
  int len = 0;
  char buf[BUFSIZ];

  /* Nexthop information. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      if (nexthop == rib->nexthop)
	{
	  /* Prefix information. */
	  len = vty_out (vty, "%c%c%c %s/%d",
			 route_info[rib->type].c,
			 CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
			 ? '>' : ' ',
			 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
			 ? '*' : ' ',
			 inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ),
			 rn->p.prefixlen);
		
	  /* Distance and metric display. */
	  if (rib->type != ZEBRA_ROUTE_CONNECT 
	      && rib->type != ZEBRA_ROUTE_KERNEL)
	    len += vty_out (vty, " [%d/%d]", rib->distance,
			    rib->metric);
	}
      else
	vty_out (vty, "  %c%*c",
		 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
		 ? '*' : ' ',
		 len - 3, ' ');

      switch (nexthop->type)
	{
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	  vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
	  if (nexthop->ifindex)
	    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFINDEX:
	  vty_out (vty, " is directly connected, %s",
		   ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFNAME:
	  vty_out (vty, " is directly connected, %s",
		   nexthop->ifname);
	  break;
	default:
	  break;
	}
      if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	vty_out (vty, " inactive");

      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	{
	  vty_out (vty, " (recursive");
		
	  switch (nexthop->rtype)
	    {
	    case NEXTHOP_TYPE_IPV4:
	    case NEXTHOP_TYPE_IPV4_IFINDEX:
	      vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " is directly connected, %s)",
		       ifindex2ifname (nexthop->rifindex));
	      break;
	    default:
	      break;
	    }
	}

      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  ", %02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, ", %dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, ", %02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

#define SHOW_ROUTE_V4_HEADER "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF,%s I - IS-IS, %s       B - BGP, > - selected route, * - FIB route%s%s"

DEFUN (show_ip_route,
       show_ip_route_cmd,
       "show ip route",
       SHOW_STR
       IP_STR
       "IP routing table\n")
{
  struct route_node *rn;
  struct rib *rib;
  int first = 1;

  /* Show all IPv4 routes. */
  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      {
	if (first)
	  {
	    vty_out (vty, SHOW_ROUTE_V4_HEADER, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	    first = 0;
	  }
	vty_show_ip_route (vty, rn, rib);
      }
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix_longer,
       show_ip_route_prefix_longer_cmd,
       "show ip route A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  int ret;
  int first = 1;

  ret = str2prefix (argv[0], &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Show matched type IPv4 routes. */
  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (prefix_match (&p, &rn->p))
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V4_HEADER, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_supernets,
       show_ip_route_supernets_cmd,
       "show ip route supernets-only",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Show supernet entries only\n")
{
  struct route_node *rn;
  struct rib *rib;
  u_int32_t addr; 
  int first = 1;


  /* Show matched type IPv4 routes. */
  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      {
	addr = ntohl (rn->p.u.prefix4.s_addr);

	if ((IN_CLASSC (addr) && rn->p.prefixlen < 24)
	   || (IN_CLASSB (addr) && rn->p.prefixlen < 16)
	   || (IN_CLASSA (addr) && rn->p.prefixlen < 8)) 
	  {
	    if (first)
	      {
		vty_out (vty, SHOW_ROUTE_V4_HEADER, VTY_NEWLINE, VTY_NEWLINE, 
                         VTY_NEWLINE, VTY_NEWLINE);
		first = 0;
	      }
	    vty_show_ip_route (vty, rn, rib);
	  }
      }
  return CMD_SUCCESS;
}


DEFUN (show_ip_route_protocol,
       show_ip_route_protocol_cmd,
       "show ip route (bgp|connected|kernel|ospf|isis|rip|static)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Border Gateway Protocol (BGP)\n"
       "Connected\n"
       "Kernel\n"
       "Open Shortest Path First (OSPF)\n"
       "ISO IS-IS (ISIS)\n"
       "Routing Information Protocol (RIP)\n"
       "Static routes\n")
{
  int type;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;

  if (strncmp (argv[0], "b", 1) == 0)
    type = ZEBRA_ROUTE_BGP;
  else if (strncmp (argv[0], "c", 1) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "k", 1) ==0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "o", 1) == 0)
    type = ZEBRA_ROUTE_OSPF;
  else if (strncmp (argv[0], "i", 1) == 0)
    type = ZEBRA_ROUTE_ISIS;
  else if (strncmp (argv[0], "r", 1) == 0)
    type = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "s", 1) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else 
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Show matched type IPv4 routes. */
  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (rib->type == type)
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V4_HEADER, VTY_NEWLINE, VTY_NEWLINE, 
                       VTY_NEWLINE, VTY_NEWLINE);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_addr,
       show_ip_route_addr_cmd,
       "show ip route A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *rn;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (rib_table_ipv4, (struct prefix *) &p);
  if (! rn)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix,
       show_ip_route_prefix_cmd,
       "show ip route A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *rn;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (rib_table_ipv4, (struct prefix *) &p);
  if (! rn || rn->p.prefixlen != p.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
int
rib_bogus_ipv6 (int type, struct prefix_ipv6 *p,
		struct in6_addr *gate, unsigned int ifindex, int table)
{
  if (type == ZEBRA_ROUTE_CONNECT && IN6_IS_ADDR_UNSPECIFIED (&p->prefix))
    return 1;
  if (type == ZEBRA_ROUTE_KERNEL && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)
      && p->prefixlen == 96 && gate && IN6_IS_ADDR_UNSPECIFIED (gate))
    {
      kernel_delete_ipv6_old (p, gate, ifindex, 0, table);
      return 1;
    }
  return 0;
}

int
rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table)
{
  struct rib *rib;
  struct rib *same = NULL;
  struct route_node *rn;
  struct nexthop *nexthop;

  int distance;
  u_int32_t metric = 0;

  /* Make sure mask is applied. */
  apply_mask_ipv6 (p);

  /* Set default distance by route type. */
  distance = route_info[type].distance;
  
  if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
    distance = 200;

  /* Make new rib. */
  if (!table)
    table = RT_TABLE_MAIN;

  /* Filter bogus route. */
  if (rib_bogus_ipv6 (type, p, gate, ifindex, table))
    return 0;

  /* Lookup route node.*/
  rn = route_node_get (rib_table_ipv6, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (rib->type == ZEBRA_ROUTE_CONNECT)
	{
	  nexthop = rib->nexthop;

	  if (rib->type == type
	      && (! table || rib->table == table)
	      && nexthop && nexthop->type == NEXTHOP_TYPE_IFINDEX
	      && nexthop->ifindex == ifindex)
	  {
	    rib->refcnt++;
	    return 0;
	  }
	}
      else if (rib->type == type
	       && (! table || (rib->table == table)))
	{
	  same = rib;
	  rib_delnode (rn, same);
	  route_unlock_node (rn);
	  break;
	}
    }

  /* Allocate new rib structure. */
  rib = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  memset (rib, 0, sizeof (struct rib));
  rib->type = type;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->table = table;
  rib->nexthop_num = 0;
  rib->uptime = time (NULL);

  /* Nexthop settings. */
  if (gate)
    {
      if (ifindex)
	nexthop_ipv6_ifindex_add (rib, gate, ifindex);
      else
	nexthop_ipv6_add (rib, gate);
    }
  else
    nexthop_ifindex_add (rib, ifindex);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);

  /* Process this route node. */
  rib_process (rn, same);

  /* Free implicit route.*/
  if (same)
    newrib_free (same);

  return 0;
}

int
rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, int table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *fib = NULL;
  struct rib *same = NULL;
  struct nexthop *nexthop;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];

  /* Apply mask. */
  apply_mask_ipv6 (p);

  /* Lookup route node. */
  rn = route_node_lookup (rib_table_ipv6, (struct prefix *) p);
  if (! rn)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
	{
	  if (gate)
	    zlog_info ("route %s/%d via %s ifindex %d doesn't exist in rib",
		       inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       inet_ntop (AF_INET6, gate, buf2, BUFSIZ),
		       ifindex);
	  else
	    zlog_info ("route %s/%d ifindex %d doesn't exist in rib",
		       inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       ifindex);
	}
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      if (rib->type == ZEBRA_ROUTE_CONNECT)
	{
	  nexthop = rib->nexthop;

	  if (rib->type == type
	      && (! table || rib->table == table)
	      && nexthop && nexthop->type == NEXTHOP_TYPE_IFINDEX
	      && nexthop->ifindex == ifindex)
	    {
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
	}
      else
	{
	  if (rib->type == type
	      && (! table || rib->table == table))
	    {
	      same = rib;
	      break;
	    }
	}
    }

  /* If same type of route can't be found and this message is from
     kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL)
	{
	  /* Unset flags. */
	  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	  UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    {
	      if (gate)
		zlog_info ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
			   inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ),
			   p->prefixlen,
			   inet_ntop (AF_INET6, gate, buf2, BUFSIZ),
			   ifindex,
			   type);
	      else
		zlog_info ("route %s/%d ifindex %d type %d doesn't exist in rib",
			   inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ),
			   p->prefixlen,
			   ifindex,
			   type);
	    }
	  route_unlock_node (rn);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }

  if (same)
    rib_delnode (rn, same);

  /* Process changes. */
  rib_process (rn, same);

  if (same)
    {
      newrib_free (same);
      route_unlock_node (rn);
    }

  route_unlock_node (rn);

  return 0;
}

/* Delete non system routes. */
void
rib_close_ipv6 ()
{
  struct route_node *rn;
  struct rib *rib;

  for (rn = route_top (rib_table_ipv6); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (! RIB_SYSTEM_ROUTE (rib)
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	rib_uninstall_kernel (rn, rib);
}

/* Install static route into rib. */
void
static_ipv6_install (struct prefix_ipv6 *p, struct static_ipv6 *si)
{
  struct rib *rib;
  struct route_node *rn;

  /* Lookup existing route */
  rn = route_node_get (rib_table_ipv6, (struct prefix *) p);
  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;

  if (rib)
    {
      /* Same distance static route is there.  Update it with new
         nexthop. */
      rib_uninstall (rn, rib);
      route_unlock_node (rn);

      switch (si->type)
	{
	case STATIC_IPV6_GATEWAY:
	  nexthop_ipv6_add (rib, &si->ipv6);
	  break;
	case STATIC_IPV6_IFNAME:
	  nexthop_ifname_add (rib, si->ifname);
	  break;
	case STATIC_IPV6_GATEWAY_IFNAME:
	  nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
	  break;
	}
      rib_process (rn, NULL);
    }
  else
    {
      /* This is new static route. */
      rib = XMALLOC (MTYPE_RIB, sizeof (struct rib));
      memset (rib, 0, sizeof (struct rib));

      rib->type = ZEBRA_ROUTE_STATIC;
      rib->distance = si->distance;
      rib->metric = 0;
      rib->nexthop_num = 0;

      switch (si->type)
	{
	case STATIC_IPV6_GATEWAY:
	  nexthop_ipv6_add (rib, &si->ipv6);
	  break;
	case STATIC_IPV6_IFNAME:
	  nexthop_ifname_add (rib, si->ifname);
	  break;
	case STATIC_IPV6_GATEWAY_IFNAME:
	  nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
	  break;
	}

      /* Link this rib to the tree. */
      rib_addnode (rn, rib);

      /* Process this prefix. */
      rib_process (rn, NULL);
    }
}

int
static_ipv6_nexthop_same (struct nexthop *nexthop, struct static_ipv6 *si)
{
  if (nexthop->type == NEXTHOP_TYPE_IPV6
      && si->type == STATIC_IPV6_GATEWAY
      && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->ipv6))
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IFNAME
      && si->type == STATIC_IPV6_IFNAME
      && strcmp (nexthop->ifname, si->ifname) == 0)
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME
      && si->type == STATIC_IPV6_GATEWAY_IFNAME
      && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->ipv6)
      && strcmp (nexthop->ifname, si->ifname) == 0)
    return 1;
  return 0;;
}

void
static_ipv6_uninstall (struct prefix_ipv6 *p, struct static_ipv6 *si)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;

  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (rib_table_ipv6, (struct prefix *) p);
  if (! rn)
    return;

  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;
  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (static_ipv6_nexthop_same (nexthop, si))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }
  
  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    {
      rib_delnode (rn, rib);
      rib_process (rn, rib);
      newrib_free (rib);
      route_unlock_node (rn);
    }
  else
    {
      rib_uninstall (rn, rib);
      nexthop_delete (rib, nexthop);
      nexthop_free (nexthop);
      rib_process (rn, rib);
    }

  /* Unlock node. */
  route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int
static_ipv6_add (struct prefix_ipv6 *p, u_char type, struct in6_addr *gate,
		 char *ifname, u_char distance, int table)
{
  struct route_node *rn;
  struct static_ipv6 *si;
  struct static_ipv6 *pp;
  struct static_ipv6 *cp;
  
  /* Lookup static route prefix. */
  rn = route_node_get (static_table_ipv6, (struct prefix *) p);

  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    {
      if (distance == si->distance 
	  && type == si->type
	  && (! gate || IPV6_ADDR_SAME (gate, &si->ipv6))
	  && (! ifname || strcmp (ifname, si->ifname) == 0))
	{
	  route_unlock_node (rn);
	  return 0;
	}
    }

  /* Make new static route structure. */
  si = XMALLOC (MTYPE_STATIC_IPV6, sizeof (struct static_ipv6));
  memset (si, 0, sizeof (struct static_ipv6));

  si->type = type;
  si->distance = distance;

  switch (type)
    {
    case STATIC_IPV6_GATEWAY:
      si->ipv6 = *gate;
      break;
    case STATIC_IPV6_IFNAME:
      si->ifname = XSTRDUP (0, ifname);
      break;
    case STATIC_IPV6_GATEWAY_IFNAME:
      si->ipv6 = *gate;
      si->ifname = XSTRDUP (0, ifname);
      break;
    }

  /* Add new static route information to the tree with sort by
     distance value and gateway address. */
  for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
      if (si->distance < cp->distance)
	break;
      if (si->distance > cp->distance)
	continue;
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
  static_ipv6_install (p, si);

  return 1;
}

/* Delete static route from static route configuration. */
int
static_ipv6_delete (struct prefix_ipv6 *p, u_char type, struct in6_addr *gate,
		    char *ifname, u_char distance, int table)
{
  struct route_node *rn;
  struct static_ipv6 *si;

  /* Lookup static route prefix. */
  rn = route_node_lookup (static_table_ipv6, (struct prefix *) p);
  if (! rn)
    return 0;

  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (distance == si->distance 
	&& type == si->type
	&& (! gate || IPV6_ADDR_SAME (gate, &si->ipv6))
	&& (! ifname || strcmp (ifname, si->ifname) == 0))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  static_ipv6_uninstall (p, si);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  
  /* Free static route configuration. */
  XFREE (MTYPE_STATIC_IPV6, si);

  return 1;
}

/* General fucntion for IPv6 static route. */
int
static_ipv6_func (struct vty *vty, int add_cmd, char *dest_str,
		  char *gate_str, char *ifname, char *distance_str)
{
  int ret;
  u_char distance;
  struct prefix_ipv6 p;
  struct in6_addr *gate = NULL;
  struct in6_addr gate_addr;
  u_char type = 0;
  int table = rtm_table_default;
  
  ret = str2prefix_ipv6 (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Apply mask for given prefix. */
  apply_mask_ipv6 (&p);

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* When gateway is valid IPv6 addrees, then gate is treated as
     nexthop address other case gate is treated as interface name. */
  ret = inet_pton (AF_INET6, gate_str, &gate_addr);

  if (ifname)
    {
      /* When ifname is specified.  It must be come with gateway
         address. */
      if (ret != 1)
	{
	  vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      type = STATIC_IPV6_GATEWAY_IFNAME;
      gate = &gate_addr;
    }
  else
    {
      if (ret == 1)
	{
	  type = STATIC_IPV6_GATEWAY;
	  gate = &gate_addr;
	}
      else
	{
	  type = STATIC_IPV6_IFNAME;
	  ifname = gate_str;
	}
    }

  if (add_cmd)
    static_ipv6_add (&p, type, gate, ifname, distance, table);
  else
    static_ipv6_delete (&p, type, gate, ifname, distance, table);

  return CMD_SUCCESS;
}

/* Write IPv6 static route configuration. */
int
static_ipv6_write (struct vty *vty)
{
  struct route_node *rn;
  struct static_ipv6 *si;  
  int write;
  char buf[BUFSIZ];

  write = 0;

  for (rn = route_top (static_table_ipv6); rn; rn = route_next (rn))
    for (si = rn->info; si; si = si->next)
      {
	vty_out (vty, "ipv6 route %s/%d",
		 inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
		 rn->p.prefixlen);

	switch (si->type)
	  {
	  case STATIC_IPV6_GATEWAY:
	    vty_out (vty, " %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ));
	    break;
	  case STATIC_IPV6_IFNAME:
	    vty_out (vty, " %s", si->ifname);
	    break;
	  case STATIC_IPV6_GATEWAY_IFNAME:
	    vty_out (vty, " %s %s",
		     inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ), si->ifname);
	    break;
	  }

	if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
	  vty_out (vty, " %d", si->distance);
	vty_out (vty, "%s", VTY_NEWLINE);

	write = 1;
      }
  return write;
}

DEFUN (ipv6_route,
       ipv6_route_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL);
}

DEFUN (ipv6_route_ifname,
       ipv6_route_ifname_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL);
}

DEFUN (ipv6_route_pref,
       ipv6_route_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2]);
}

DEFUN (ipv6_route_ifname_pref,
       ipv6_route_ifname_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL);
}

DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL);
}

DEFUN (no_ipv6_route_pref,
       no_ipv6_route_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, argv[2]);
}

DEFUN (no_ipv6_route_ifname_pref,
       no_ipv6_route_ifname_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], argv[3]);
}

/* New RIB.  Detailed information for IPv4 route. */
void
vty_show_ipv6_route_detail (struct vty *vty, struct route_node *rn)
{
  struct rib *rib;
  struct nexthop *nexthop;
  char buf[BUFSIZ];

  for (rib = rn->info; rib; rib = rib->next)
    {
      vty_out (vty, "Routing entry for %s/%d%s", 
	       inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
	       rn->p.prefixlen,
	       VTY_NEWLINE);
      vty_out (vty, "  Known via \"%s\"", route_info[rib->type].str);
      vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	vty_out (vty, ", best");
      if (rib->refcnt)
	vty_out (vty, ", refcnt %ld", rib->refcnt);
      vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
      if (rib->type == ZEBRA_ROUTE_RIPNG
	  || rib->type == ZEBRA_ROUTE_OSPF6
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

	  vty_out (vty, "  Last update ");

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  "%02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, "%dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, "%02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	  vty_out (vty, " ago%s", VTY_NEWLINE);
	}

      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	{
	  vty_out (vty, "  %c",
		   CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

	  switch (nexthop->type)
	    {
	    case NEXTHOP_TYPE_IPV6:
	    case NEXTHOP_TYPE_IPV6_IFINDEX:
	    case NEXTHOP_TYPE_IPV6_IFNAME:
	      vty_out (vty, " %s",
		       inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
	      if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
		vty_out (vty, ", %s", nexthop->ifname);
	      else if (nexthop->ifindex)
		vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	      vty_out (vty, " directly connected, %s",
		       ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " directly connected, %s",
		       nexthop->ifname);
	      break;
	    default:
	      break;
	    }
	  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	    vty_out (vty, " inactive");

	  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	    {
	      vty_out (vty, " (recursive");
		
	      switch (nexthop->rtype)
		{
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFNAME:
		  vty_out (vty, " via %s)",
			   inet_ntop (AF_INET6, &nexthop->rgate.ipv6,
				      buf, BUFSIZ));
		  if (nexthop->rifindex)
		    vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
		  break;
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_IFNAME:
		  vty_out (vty, " is directly connected, %s)",
			   ifindex2ifname (nexthop->rifindex));
		  break;
		default:
		  break;
		}
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

void
vty_show_ipv6_route (struct vty *vty, struct route_node *rn,
		     struct rib *rib)
{
  struct nexthop *nexthop;
  int len = 0;
  char buf[BUFSIZ];

  /* Nexthop information. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      if (nexthop == rib->nexthop)
	{
	  /* Prefix information. */	  
	  len = vty_out (vty, "%c%c%c %s/%d",
			 route_info[rib->type].c,
			 CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
			 ? '>' : ' ',
			 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
			 ? '*' : ' ',
			 inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
			 rn->p.prefixlen);

	  /* Distance and metric display. */
	  if (rib->type != ZEBRA_ROUTE_CONNECT 
	      && rib->type != ZEBRA_ROUTE_KERNEL)
	    len += vty_out (vty, " [%d/%d]", rib->distance,
			    rib->metric);
	}
      else
	vty_out (vty, "  %c%*c",
		 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
		 ? '*' : ' ',
		 len - 3, ' ');

      switch (nexthop->type)
	{
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_IPV6_IFNAME:
	  vty_out (vty, " via %s",
		   inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
	  if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
	    vty_out (vty, ", %s", nexthop->ifname);
	  else if (nexthop->ifindex)
	    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFINDEX:
	  vty_out (vty, " is directly connected, %s",
		   ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFNAME:
	  vty_out (vty, " is directly connected, %s",
		   nexthop->ifname);
	  break;
	default:
	  break;
	}
      if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	vty_out (vty, " inactive");

      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	{
	  vty_out (vty, " (recursive");
		
	  switch (nexthop->rtype)
	    {
	    case NEXTHOP_TYPE_IPV6:
	    case NEXTHOP_TYPE_IPV6_IFINDEX:
	    case NEXTHOP_TYPE_IPV6_IFNAME:
	      vty_out (vty, " via %s)",
		       inet_ntop (AF_INET6, &nexthop->rgate.ipv6,
				  buf, BUFSIZ));
	      if (nexthop->rifindex)
		vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " is directly connected, %s)",
		       ifindex2ifname (nexthop->rifindex));
	      break;
	    default:
	      break;
	    }
	}

      if (rib->type == ZEBRA_ROUTE_RIPNG
	  || rib->type == ZEBRA_ROUTE_OSPF6
	  || rib->type == ZEBRA_ROUTE_ISIS
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  ", %02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, ", %dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, ", %02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

#define SHOW_ROUTE_V6_HEADER "Codes: K - kernel route, C - connected, S - static, R - RIPng, O - OSPFv3, I - IS-IS,%s       B - BGP, * - FIB route.%s%s"

DEFUN (show_ipv6_route,
       show_ipv6_route_cmd,
       "show ipv6 route",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n")
{
  struct route_node *rn;
  struct rib *rib;
  int first = 1;

  /* Show all IPv6 route. */
  for (rn = route_top (rib_table_ipv6); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      {
	if (first)
	  {
	    vty_out (vty, SHOW_ROUTE_V6_HEADER, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	    first = 0;
	  }
	vty_show_ipv6_route (vty, rn, rib);
      }
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix_longer,
       show_ipv6_route_prefix_longer_cmd,
       "show ipv6 route X:X::X:X/M longer-prefixes",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n")
{
  struct route_node *rn;
  struct rib *rib;
  struct prefix p;
  int ret;
  int first = 1;

  ret = str2prefix (argv[0], &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Show matched type IPv6 routes. */
  for (rn = route_top (rib_table_ipv6); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (prefix_match (&p, &rn->p))
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V6_HEADER, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	      first = 0;
	    }
	  vty_show_ipv6_route (vty, rn, rib);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_protocol,
       show_ipv6_route_protocol_cmd,
       "show ipv6 route (bgp|connected|kernel|ospf6|isis|ripng|static)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Border Gateway Protocol (BGP)\n"
       "Connected\n"
       "Kernel\n"
       "Open Shortest Path First (OSPFv3)\n"
       "ISO IS-IS (ISIS)\n"
       "Routing Information Protocol (RIPng)\n"
       "Static routes\n")
{
  int type;
  struct route_node *rn;
  struct rib *rib;
  int first = 1;

  if (strncmp (argv[0], "b", 1) == 0)
    type = ZEBRA_ROUTE_BGP;
  else if (strncmp (argv[0], "c", 1) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "k", 1) ==0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "o", 1) == 0)
    type = ZEBRA_ROUTE_OSPF6;
  else if (strncmp (argv[0], "i", 1) == 0)
    type = ZEBRA_ROUTE_ISIS;
  else if (strncmp (argv[0], "r", 1) == 0)
    type = ZEBRA_ROUTE_RIPNG;
  else if (strncmp (argv[0], "s", 1) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else 
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Show matched type IPv6 routes. */
  for (rn = route_top (rib_table_ipv6); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (rib->type == type)
	{
	  if (first)
	    {
	      vty_out (vty, SHOW_ROUTE_V6_HEADER, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	      first = 0;
	    }
	  vty_show_ipv6_route (vty, rn, rib);
	}
  return CMD_SUCCESS;
}


DEFUN (show_ipv6_route_addr,
       show_ipv6_route_addr_cmd,
       "show ipv6 route X:X::X:X",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 Address\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_node *rn;

  ret = str2prefix_ipv6 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (rib_table_ipv6, (struct prefix *) &p);
  if (! rn)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ipv6_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix,
       show_ipv6_route_prefix_cmd,
       "show ipv6 route X:X::X:X/M",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 prefix\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_node *rn;

  ret = str2prefix_ipv6 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (rib_table_ipv6, (struct prefix *) &p);
  if (! rn || rn->p.prefixlen != p.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ipv6_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* RIB update function. */
void
rib_update ()
{
  struct route_node *rn;

  for (rn = route_top (rib_table_ipv4); rn; rn = route_next (rn))
    /* Update reachability. */
    rib_process (rn, NULL);

#ifdef HAVE_IPV6
  for (rn = route_top (rib_table_ipv6); rn; rn = route_next (rn))
    rib_process (rn, NULL);
#endif /* HAVE_IPV6 */
}

/* Interface goes up. */
void
rib_if_up (struct interface *ifp)
{
  rib_update ();
}

/* Interface goes down. */
void
rib_if_down (struct interface *ifp)
{
  rib_update ();
}

/* Clean up routines. */
void
rib_weed_table (struct route_table *rib_table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;

  for (rn = route_top (rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = next)
      {
	next = rib->next;

        if (rib->table != rtm_table_default &&
	    rib->table != RT_TABLE_MAIN)
	  {
	    rib_delnode (rn, rib);
	    newrib_free (rib);
	    route_unlock_node (rn);
	  }
      }
}

/* Delete all routes from unmanaged tables. */
void
rib_weed_tables ()
{
  rib_weed_table (rib_table_ipv4);
#ifdef HAVE_IPV6
  rib_weed_table (rib_table_ipv6);
#endif /* HAVE_IPV6 */
}

void
rib_sweep_table (struct route_table *rib_table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;
  int ret = 0;

  for (rn = route_top (rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = next)
      {
	next = rib->next;

        if ((rib->type == ZEBRA_ROUTE_KERNEL) && 
	    CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
          {
	    ret = rib_uninstall_kernel (rn, rib);

	    if (! ret)
	      {
		rib_delnode (rn, rib);
		newrib_free (rib);
		route_unlock_node (rn);
	      }
          }
      }
}

void
rib_sweep_route ()
{
  rib_sweep_table (rib_table_ipv4);
#ifdef HAVE_IPV6  
  rib_sweep_table (rib_table_ipv6);
#endif /* HAVE_IPV6 */
}

/* Close rib when zebra terminates. */
void
rib_close ()
{
  rib_close_ipv4 ();
#ifdef HAVE_IPV6
  rib_close_ipv6 ();
#endif /* HAVE_IPV6 */
}

/* Static ip route configuration write function. */
int
config_write_ip (struct vty *vty)
{
  int write = 0;

  write += static_ipv4_write (vty);
#ifdef HAVE_IPV6
  write += static_ipv6_write (vty);
#endif /* HAVE_IPV6 */

  return write;
}

/* IP node for static routes. */
struct cmd_node ip_node =
{
  IP_NODE,
  "",				/* This node has no interface. */
  1
};

/* Routing information base initialize. */
void
rib_init ()
{
  install_node (&ip_node, config_write_ip);

  rib_table_ipv4 = route_table_init ();
  static_table_ipv4 = route_table_init ();

  install_element (VIEW_NODE, &show_ip_route_cmd);
  install_element (VIEW_NODE, &show_ip_route_addr_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
  install_element (VIEW_NODE, &show_ip_route_supernets_cmd);
  install_element (ENABLE_NODE, &show_ip_route_cmd);
  install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_route_supernets_cmd);
  install_element (CONFIG_NODE, &ip_route_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_cmd);
  install_element (CONFIG_NODE, &no_ip_route_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_cmd);
  install_element (CONFIG_NODE, &ip_route_pref_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_pref_cmd);
  install_element (CONFIG_NODE, &no_ip_route_pref_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_pref_cmd);

#ifdef HAVE_IPV6
  rib_table_ipv6 = route_table_init ();
  static_table_ipv6 = route_table_init ();

  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &ipv6_route_pref_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_pref_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_pref_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_protocol_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_addr_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_prefix_longer_cmd);
#endif /* HAVE_IPV6 */
}
