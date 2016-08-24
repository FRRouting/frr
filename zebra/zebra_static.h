/*
 * Static Routing Information header
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
#ifndef __ZEBRA_STATIC_H__
#define __ZEBRA_STATIC_H__

/* Static route information. */
struct static_route
{
  /* For linked list. */
  struct static_route *prev;
  struct static_route *next;

  /* VRF identifier. */
  vrf_id_t vrf_id;

  /* Administrative distance. */
  u_char distance;

  /* Tag */
  u_short tag;

  /* Flag for this static route's type. */
  u_char type;
#define STATIC_IFINDEX               1
#define STATIC_IPV4_GATEWAY          2
#define STATIC_IPV4_BLACKHOLE        3
#define STATIC_IPV6_GATEWAY          4
#define STATIC_IPV6_GATEWAY_IFINDEX  5

  /*
   * Nexthop value.
   *
   * Under IPv4 addr and ifindex are
   * used independentyly.
   * STATIC_IPV4_GATEWAY uses addr
   * STATIC_IFINDEX uses ifindex
   */
  union g_addr addr;
  ifindex_t ifindex;

  char ifname[INTERFACE_NAMSIZ + 1];

  /* bit flags */
  u_char flags;
/*
 see ZEBRA_FLAG_REJECT
     ZEBRA_FLAG_BLACKHOLE
 */
};

extern void
static_install_route (afi_t afi, safi_t safi, struct prefix *p, struct static_route *si);
extern void
static_uninstall_route (afi_t afi, safi_t safi, struct prefix *p, struct static_route *si);

extern int
static_add_ipv4 (safi_t safi, struct prefix *p, struct in_addr *gate, ifindex_t ifindex,
                 const char *ifname, u_char flags, u_short tag,
		 u_char distance, struct zebra_vrf *zvrf);

extern int
static_delete_route (afi_t, safi_t safi, u_char type, struct prefix *p,
		     union g_addr *gate, ifindex_t ifindex,
		     u_short tag, u_char distance,
		     struct zebra_vrf *zvrf);

extern int
static_add_ipv6 (struct prefix *p, u_char type, struct in6_addr *gate,
		 ifindex_t ifindex, const char *ifname, u_char flags,
		 u_short tag, u_char distance, struct zebra_vrf *zvrf);

#endif
