/*
 * Copyright (C) 2001 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#ifndef OSPF6_ASBR_H
#define OSPF6_ASBR_H

#include "thread.h"

struct ospf6_external_info
{
  int is_removed;
  struct thread *thread_originate;

  struct ospf6_external_route *route;

  struct ospf6_external_info *prev;
  struct ospf6_external_info *next;

  /* external route type */
  int type;

  /* external route ifindex */
  int ifindex;

  /* LS-ID */
  u_int32_t id;

  /* nexthops */
  u_int nexthop_num;
  struct in6_addr *nexthop;

  u_int8_t  prefix_options;

  u_int8_t  metric_type;
  u_int32_t metric;
  struct in6_addr forwarding;
  /* u_int32_t tag; */
};

struct ospf6_external_route
{
  struct route_node *node;

  /* prefix */
  struct prefix prefix;

  /* external information */
  struct ospf6_external_info *info_head;
  struct ospf6_external_info *info_tail;
};

/* AS-External-LSA */
struct ospf6_lsa_as_external
{
  u_int32_t bits_metric;

  struct ospf6_prefix prefix;
  /* followed by none or one forwarding address */
  /* followed by none or one external route tag */
  /* followed by none or one referenced LS-ID */
};

#define OSPF6_ASBR_BIT_T  ntohl (0x01000000)
#define OSPF6_ASBR_BIT_F  ntohl (0x02000000)
#define OSPF6_ASBR_BIT_E  ntohl (0x04000000)

#define OSPF6_ASBR_METRIC(E) (ntohl ((E)->bits_metric & htonl (0x00ffffff)))
#define OSPF6_ASBR_METRIC_SET(E,C) \
  { (E)->bits_metric &= htonl (0xff000000); \
    (E)->bits_metric |= htonl (0x00ffffff) & htonl (C); }

void ospf6_asbr_routemap_update ();

int ospf6_redistribute_config_write (struct vty *vty);
void ospf6_redistribute_show_config (struct vty *vty);

void
ospf6_asbr_route_add (int type, int ifindex, struct prefix *prefix,
                      u_int nexthop_num, struct in6_addr *nexthop);
void
ospf6_asbr_route_remove (int type, int ifindex, struct prefix *prefix);

void ospf6_asbr_external_lsa_add (struct ospf6_lsa *lsa);
void ospf6_asbr_external_lsa_remove (struct ospf6_lsa *lsa);
void ospf6_asbr_external_lsa_change (struct ospf6_lsa *old,
                                     struct ospf6_lsa *new);

void ospf6_asbr_asbr_entry_add (struct ospf6_route_req *topo_entry);
void ospf6_asbr_asbr_entry_remove (struct ospf6_route_req *topo_entry);

void ospf6_asbr_init ();

#endif /* OSPF6_ASBR_H */

