/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#ifndef OSPF6_FLOOD_H
#define OSPF6_FLOOD_H

/* Function Prototypes */
void *ospf6_get_lsa_scope (u_int16_t type, struct ospf6_neighbor *from);
struct ospf6_lsdb *ospf6_get_scoped_lsdb (u_int16_t type, void *scope);

void ospf6_flood_clear (struct ospf6_lsa *lsa);
void ospf6_flood_lsa (struct ospf6_lsa *lsa, struct ospf6_neighbor *from);
void ospf6_install_lsa (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
void ospf6_receive_lsa (struct ospf6_lsa_header *header,
                        struct ospf6_neighbor *from);

#endif /* OSPF6_FLOOD_H */


