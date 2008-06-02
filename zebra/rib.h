/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#include "prefix.h"

#define DISTANCE_INFINITY  255

/* Routing information base. */

union g_addr {
  struct in_addr ipv4;
#ifdef HAVE_IPV6
  struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
};

struct rib
{
  /* Status Flags for the *route_node*, but kept in the head RIB.. */
  u_char rn_status;
#define RIB_ROUTE_QUEUED(x)	(1 << (x))

  /* Link list. */
  struct rib *next;
  struct rib *prev;
  
  /* Nexthop structure */
  struct nexthop *nexthop;
  
  /* Refrence count. */
  unsigned long refcnt;
  
  /* Uptime. */
  time_t uptime;

  /* Type fo this route. */
  int type;

  /* Which routing table */
  int table;			

  /* Metric */
  u_int32_t metric;

  /* Distance. */
  u_char distance;

  /* Flags of this route.
   * This flag's definition is in lib/zebra.h ZEBRA_FLAG_* and is exposed
   * to clients via Zserv
   */
  u_char flags;

  /* RIB internal status */
  u_char status;
#define RIB_ENTRY_REMOVED	(1 << 0)

  /* Nexthop information. */
  u_char nexthop_num;
  u_char nexthop_active_num;
  u_char nexthop_fib_num;
};

/* meta-queue structure:
 * sub-queue 0: connected, kernel
 * sub-queue 1: static
 * sub-queue 2: RIP, RIPng, OSPF, OSPF6, IS-IS
 * sub-queue 3: iBGP, eBGP
 * sub-queue 4: any other origin (if any)
 */
#define MQ_SIZE 5
struct meta_queue
{
  struct list *subq[MQ_SIZE];
  u_int32_t size; /* sum of lengths of all subqueues */
};

/* Static route information. */
struct static_ipv4
{
  /* For linked list. */
  struct static_ipv4 *prev;
  struct static_ipv4 *next;

  /* Administrative distance. */
  u_char distance;

  /* Flag for this static route's type. */
  u_char type;
#define STATIC_IPV4_GATEWAY     1
#define STATIC_IPV4_IFNAME      2
#define STATIC_IPV4_BLACKHOLE   3

  /* Nexthop value. */
  union 
  {
    struct in_addr ipv4;
    char *ifname;
  } gate;

  /* bit flags */
  u_char flags;
/*
 see ZEBRA_FLAG_REJECT
     ZEBRA_FLAG_BLACKHOLE
 */
};

#ifdef HAVE_IPV6
/* Static route information. */
struct static_ipv6
{
  /* For linked list. */
  struct static_ipv6 *prev;
  struct static_ipv6 *next;

  /* Administrative distance. */
  u_char distance;

  /* Flag for this static route's type. */
  u_char type;
#define STATIC_IPV6_GATEWAY          1
#define STATIC_IPV6_GATEWAY_IFNAME   2
#define STATIC_IPV6_IFNAME           3

  /* Nexthop value. */
  struct in6_addr ipv6;
  char *ifname;

  /* bit flags */
  u_char flags;
/*
 see ZEBRA_FLAG_REJECT
     ZEBRA_FLAG_BLACKHOLE
 */
};
#endif /* HAVE_IPV6 */

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

  /* Nexthop address or interface name. */
  union g_addr gate;

  /* Recursive lookup nexthop. */
  u_char rtype;
  unsigned int rifindex;
  union g_addr rgate;
  union g_addr src;
};

/* Routing table instance.  */
struct vrf
{
  /* Identifier.  This is same as routing table vector index.  */
  u_int32_t id;

  /* Routing table name.  */
  char *name;

  /* Description.  */
  char *desc;

  /* FIB identifier.  */
  u_char fib_id;

  /* Routing table.  */
  struct route_table *table[AFI_MAX][SAFI_MAX];

  /* Static route configuration.  */
  struct route_table *stable[AFI_MAX][SAFI_MAX];
};

extern struct nexthop *nexthop_ifindex_add (struct rib *, unsigned int);
extern struct nexthop *nexthop_ifname_add (struct rib *, char *);
extern struct nexthop *nexthop_blackhole_add (struct rib *);
extern struct nexthop *nexthop_ipv4_add (struct rib *, struct in_addr *,
					 struct in_addr *);
extern void rib_lookup_and_dump (struct prefix_ipv4 *);
extern void rib_lookup_and_pushup (struct prefix_ipv4 *);
extern void rib_dump (const char *, const struct prefix_ipv4 *, const struct rib *);
extern int rib_lookup_ipv4_route (struct prefix_ipv4 *, union sockunion *);
#define ZEBRA_RIB_LOOKUP_ERROR -1
#define ZEBRA_RIB_FOUND_EXACT 0
#define ZEBRA_RIB_FOUND_NOGATE 1
#define ZEBRA_RIB_FOUND_CONNECTED 2
#define ZEBRA_RIB_NOTFOUND 3

#ifdef HAVE_IPV6
extern struct nexthop *nexthop_ipv6_add (struct rib *, struct in6_addr *);
#endif /* HAVE_IPV6 */

extern struct vrf *vrf_lookup (u_int32_t);
extern struct route_table *vrf_table (afi_t afi, safi_t safi, u_int32_t id);
extern struct route_table *vrf_static_table (afi_t afi, safi_t safi, u_int32_t id);

/* NOTE:
 * All rib_add_ipv[46]* functions will not just add prefix into RIB, but
 * also implicitly withdraw equal prefix of same type. */
extern int rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
			 struct in_addr *gate, struct in_addr *src,
			 unsigned int ifindex, u_int32_t vrf_id,
			 u_int32_t, u_char);

extern int rib_add_ipv4_multipath (struct prefix_ipv4 *, struct rib *);

extern int rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		            struct in_addr *gate, unsigned int ifindex, 
		            u_int32_t);

extern struct rib *rib_match_ipv4 (struct in_addr);

extern struct rib *rib_lookup_ipv4 (struct prefix_ipv4 *);

extern void rib_update (void);
extern void rib_weed_tables (void);
extern void rib_sweep_route (void);
extern void rib_close (void);
extern void rib_init (void);

extern int
static_add_ipv4 (struct prefix *p, struct in_addr *gate, const char *ifname,
       u_char flags, u_char distance, u_int32_t vrf_id);

extern int
static_delete_ipv4 (struct prefix *p, struct in_addr *gate, const char *ifname,
		    u_char distance, u_int32_t vrf_id);

#ifdef HAVE_IPV6
extern int
rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id,
	      u_int32_t metric, u_char distance);

extern int
rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id);

extern struct rib *rib_lookup_ipv6 (struct in6_addr *);

extern struct rib *rib_match_ipv6 (struct in6_addr *);

extern struct route_table *rib_table_ipv6;

extern int
static_add_ipv6 (struct prefix *p, u_char type, struct in6_addr *gate,
		 const char *ifname, u_char flags, u_char distance,
		 u_int32_t vrf_id);

extern int
static_delete_ipv6 (struct prefix *p, u_char type, struct in6_addr *gate,
		    const char *ifname, u_char distance, u_int32_t vrf_id);

#endif /* HAVE_IPV6 */

#endif /*_ZEBRA_RIB_H */
