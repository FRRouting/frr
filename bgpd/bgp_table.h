/* BGP routing table
   Copyright (C) 1998, 2001 Kunihiro Ishiguro

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
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_TABLE_H
#define _QUAGGA_BGP_TABLE_H

typedef enum
{
  BGP_TABLE_MAIN,
  BGP_TABLE_RSCLIENT,
} bgp_table_t;

struct bgp_table
{
  bgp_table_t type;
  
  /* afi/safi of this table */
  afi_t afi;
  safi_t safi;
  
  int lock;

  /* The owner of this 'bgp_table' structure. */
  struct peer *owner;

  struct bgp_node *top;
  
  unsigned long count;
};

struct bgp_node
{
  struct prefix p;

  struct bgp_table *table;
  struct bgp_node *parent;
  struct bgp_node *link[2];
#define l_left   link[0]
#define l_right  link[1]

  void *info;

  struct bgp_adj_out *adj_out;

  struct bgp_adj_in *adj_in;

  struct bgp_node *prn;

  int lock;

  u_char flags;
#define BGP_NODE_PROCESS_SCHEDULED	(1 << 0)
};

extern struct bgp_table *bgp_table_init (afi_t, safi_t);
extern void bgp_table_lock (struct bgp_table *);
extern void bgp_table_unlock (struct bgp_table *);
extern void bgp_table_finish (struct bgp_table **);
extern void bgp_unlock_node (struct bgp_node *node);
extern struct bgp_node *bgp_table_top (const struct bgp_table *const);
extern struct bgp_node *bgp_route_next (struct bgp_node *);
extern struct bgp_node *bgp_route_next_until (struct bgp_node *, struct bgp_node *);
extern struct bgp_node *bgp_node_get (struct bgp_table *const, struct prefix *);
extern struct bgp_node *bgp_node_lookup (const struct bgp_table *const, struct prefix *);
extern struct bgp_node *bgp_lock_node (struct bgp_node *node);
extern struct bgp_node *bgp_node_match (const struct bgp_table *, struct prefix *);
extern struct bgp_node *bgp_node_match_ipv4 (const struct bgp_table *,
					  struct in_addr *);
#ifdef HAVE_IPV6
extern struct bgp_node *bgp_node_match_ipv6 (const struct bgp_table *,
					  struct in6_addr *);
#endif /* HAVE_IPV6 */
extern unsigned long bgp_table_count (const struct bgp_table *const);
#endif /* _QUAGGA_BGP_TABLE_H */
