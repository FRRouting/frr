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

#ifndef OSPF6_NSM_H
#define OSPF6_NSM_H

/* Neighbor state */
#define NBS_DOWN                      1
#define OSPF6_NEIGHBOR_STATE_DOWN     1
#define NBS_ATTEMPT                   2
#define OSPF6_NEIGHBOR_STATE_ATTEMPT  2
#define NBS_INIT                      3
#define OSPF6_NEIGHBOR_STATE_INIT     3
#define NBS_TWOWAY                    4
#define OSPF6_NEIGHBOR_STATE_TWOWAY   4
#define NBS_EXSTART                   5
#define OSPF6_NEIGHBOR_STATE_EXSTART  5
#define NBS_EXCHANGE                  6
#define OSPF6_NEIGHBOR_STATE_EXCHANGE 6
#define NBS_LOADING                   7
#define OSPF6_NEIGHBOR_STATE_LOADING  7
#define NBS_FULL                      8
#define OSPF6_NEIGHBOR_STATE_FULL     8



/* Function Prototypes */

#include "ospf6_types.h"

int need_adjacency (struct ospf6_neighbor *);


/* Neighbor event */
int hello_received (struct thread *);
int twoway_received (struct thread *);
int negotiation_done (struct thread *);
int exchange_done (struct thread *);
int loading_done (struct thread *);
int adj_ok (struct thread *);
int seqnumber_mismatch (struct thread *);
int bad_lsreq (struct thread *);
int oneway_received (struct thread *);
int inactivity_timer (struct thread *);

int dr_election (struct ospf6_interface *);

#endif /* OSPF6_NSM_H */

