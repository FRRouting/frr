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

#ifndef OSPF6_DBEX_H
#define OSPF6_DBEX_H

/* for ack_type() */
#define NO_ACK       0
#define DELAYED_ACK  1
#define DIRECT_ACK   2

/* Function Prototypes */
void
ospf6_add_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);
void
ospf6_remove_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);
void ospf6_lsa_delayed_ack_remove_all (struct ospf6_lsa *lsa);

void ospf6_dbex_prepare_summary (struct ospf6_neighbor *);

int
ospf6_dbex_check_dbdesc_lsa_header (struct ospf6_lsa_header *lsa_header,
                                    struct ospf6_neighbor *from);

void
ospf6_dbex_acknowledge_delayed (struct ospf6_lsa *lsa,
                                struct ospf6_interface *o6i);

void
ospf6_dbex_receive_lsa (struct ospf6_lsa_header *,
                        struct ospf6_neighbor *);

int ack_type (struct ospf6_lsa *, int, struct ospf6_neighbor *);

void ospf6_dbex_flood (struct ospf6_lsa *, struct ospf6_neighbor *);

void
ospf6_dbex_remove_from_all_retrans_list (struct ospf6_lsa *lsa);

#endif /* OSPF6_DBEX_H */

