/*
 * Nexthop structure definition.
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

#ifndef _LIB_NEXTHOP_H
#define _LIB_NEXTHOP_H

#include "prefix.h"

union g_addr {
  struct in_addr ipv4;
#ifdef HAVE_IPV6
  struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
};

enum nexthop_types_t
{
  NEXTHOP_TYPE_IFINDEX = 1,      /* Directly connected.  */
  NEXTHOP_TYPE_IFNAME,           /* Interface route.  */
  NEXTHOP_TYPE_IPV4,             /* IPv4 nexthop.  */
  NEXTHOP_TYPE_IPV4_IFINDEX,     /* IPv4 nexthop with ifindex.  */
  NEXTHOP_TYPE_IPV4_IFNAME,      /* IPv4 nexthop with ifname.  */
  NEXTHOP_TYPE_IPV6,             /* IPv6 nexthop.  */
  NEXTHOP_TYPE_IPV6_IFINDEX,     /* IPv6 nexthop with ifindex.  */
  NEXTHOP_TYPE_IPV6_IFNAME,      /* IPv6 nexthop with ifname.  */
  NEXTHOP_TYPE_BLACKHOLE,        /* Null0 nexthop.  */
};

/* Nexthop structure. */
struct nexthop
{
  struct nexthop *next;
  struct nexthop *prev;

  /* Interface index. */
  char *ifname;
  unsigned int ifindex;

  enum nexthop_types_t type;

  u_char flags;
#define NEXTHOP_FLAG_ACTIVE     (1 << 0) /* This nexthop is alive. */
#define NEXTHOP_FLAG_FIB        (1 << 1) /* FIB nexthop. */
#define NEXTHOP_FLAG_RECURSIVE  (1 << 2) /* Recursive nexthop. */
#define NEXTHOP_FLAG_ONLINK     (1 << 3) /* Nexthop should be installed onlink. */
#define NEXTHOP_FLAG_MATCHED    (1 << 4) /* Already matched vs a nexthop */
#define NEXTHOP_FLAG_FILTERED   (1 << 5) /* rmap filtered, used by static only */

  /* Nexthop address */
  union g_addr gate;
  union g_addr src;
  union g_addr rmap_src;	/* Src is set via routemap */

  /* Nexthops obtained by recursive resolution.
   *
   * If the nexthop struct needs to be resolved recursively,
   * NEXTHOP_FLAG_RECURSIVE will be set in flags and the nexthops
   * obtained by recursive resolution will be added to `resolved'.
   * Only one level of recursive resolution is currently supported. */
  struct nexthop *resolved;
};

#define nexthop_new()                                                   \
({                                                                      \
  struct nexthop *n = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop)); \
  n;                                                                    \
})

extern const char *nexthop_type_to_str (enum nexthop_types_t nh_type);
extern int nexthop_same_no_recurse (struct nexthop *next1, struct nexthop *next2);

#endif /*_LIB_NEXTHOP_H */
