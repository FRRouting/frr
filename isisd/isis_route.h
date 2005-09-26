/*
 * IS-IS Rout(e)ing protocol               - isis_route.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
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
#ifndef _ZEBRA_ISIS_ROUTE_H
#define _ZEBRA_ISIS_ROUTE_H

#ifdef HAVE_IPV6
struct isis_nexthop6
{
  unsigned int ifindex;
  struct in6_addr ip6;
  unsigned int lock;
};
#endif /* HAVE_IPV6 */

struct isis_nexthop
{
  unsigned int ifindex;
  struct in_addr ip;
  unsigned int lock;
};

struct isis_route_info
{
#define ISIS_ROUTE_FLAG_ZEBRA_SYNC 0x01
#define ISIS_ROUTE_FLAG_ACTIVE     0x02
  u_char flag;
  u_int32_t cost;
  u_int32_t depth;
  struct list *nexthops;
#ifdef HAVE_IPV6
  struct list *nexthops6;
#endif				/* HAVE_IPV6 */
};

struct isis_route_info *isis_route_create (struct prefix *prefix,
					   u_int32_t cost, u_int32_t depth,
					   struct list *adjacencies,
					   struct isis_area *area, int level);

int isis_route_validate (struct thread *thread);

#endif /* _ZEBRA_ISIS_ROUTE_H */
