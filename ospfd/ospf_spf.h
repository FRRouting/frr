/*
 * OSPF calculation.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

/* values for vertex->type */
#define OSPF_VERTEX_ROUTER  1  /* for a Router-LSA */
#define OSPF_VERTEX_NETWORK 2  /* for a Network-LSA */

/* values for vertex->flags */
#define OSPF_VERTEX_PROCESSED      0x01

/* The "root" is the node running the SPF calculation */

/* A router or network in an area */
struct vertex
{
  u_char flags;
  u_char type;		/* copied from LSA header */
  struct in_addr id;	/* copied from LSA header */
  struct lsa_header *lsa; /* Router or Network LSA */
  u_int32_t distance;	/* from root to this vertex */
  int backlink;        /* link index of back-link */
  struct list *child;		/* list of vertex: children in SPF tree*/
  struct list *nexthop;		/* list of vertex_nexthop from root to this vertex */
};

/* A nexthop taken on the root node to get to this (parent) vertex */
struct vertex_nexthop
{
  struct ospf_interface *oi;	/* output intf on root node */
  struct in_addr router;	/* router address to send to */
  struct vertex *parent;	/* parent in SPF tree */
};

void ospf_spf_calculate_schedule (struct ospf *);
void ospf_rtrs_free (struct route_table *);

/* void ospf_spf_calculate_timer_add (); */
