/*
 * Copyright (C) 1999 Yasuhiro Ohara
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

#ifndef OSPF6_ZEBRA_H
#define OSPF6_ZEBRA_H

extern struct zclient *zclient;

void ospf6_zebra_redistribute (int);
void ospf6_zebra_no_redistribute (int);
int ospf6_zebra_is_redistribute (int);

int ospf6_zebra_get_interface (int, struct zclient *, zebra_size_t);
int ospf6_zebra_read (struct thread *); 
void ospf6_zebra_init ();
void ospf6_zebra_finish ();
void ospf6_zebra_start ();

int ospf6_zebra_read_ipv6 (int, struct zclient *, zebra_size_t);

extern const char *zebra_route_name[ZEBRA_ROUTE_MAX];
extern const char *zebra_route_abname[ZEBRA_ROUTE_MAX];

void ospf6_zebra_route_update_add (struct ospf6_route_req *request);
void ospf6_zebra_route_update_remove (struct ospf6_route_req *request);

#endif /*OSPF6_ZEBRA_H*/

