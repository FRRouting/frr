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

#ifndef OSPF6_ABR_H
#define OSPF6_ABR_H

/* Inter-Area-Prefix-LSA */
struct ospf6_inter_area_prefix_lsa
{
  u_int32_t metric;           /* 12bits reserved, 20bits metric */
  struct ospf6_prefix prefix; /* followed by one address prefix */
};

/* Inter-Area-Router-LSA */
struct ospf6_inter_area_router_lsa
{
  u_char reserved;
  u_char options[3];      /* Optional Capability */
  u_int32_t metric;       /* 12bits reserved, 20bits metric */
  u_int32_t router_id;    /* Destination Router ID */
};

void ospf6_abr_prefix_lsa_add (struct ospf6_lsa *);
void ospf6_abr_prefix_lsa_remove (struct ospf6_lsa *);
void ospf6_abr_prefix_lsa_change (struct ospf6_lsa *, struct ospf6_lsa *);

void ospf6_abr_abr_entry_add (struct ospf6_route_req *);
void ospf6_abr_abr_entry_remove (struct ospf6_route_req *);

void ospf6_abr_route_add (struct ospf6_route_req *);
void ospf6_abr_route_remove (struct ospf6_route_req *);

void ospf6_abr_inter_route_calculation (struct ospf6_area *);

void ospf6_abr_init ();

#endif /* OSPF6_ABR_H */

