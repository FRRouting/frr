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

#ifndef OSPF6_ISM_H
#define OSPF6_ISM_H

/* interface state */
#define IFS_NONE     0
#define IFS_DOWN     1
#define IFS_LOOPBACK 2
#define IFS_WAITING  3
#define IFS_PTOP     4
#define IFS_DROTHER  5
#define IFS_BDR      6
#define IFS_DR       7
#define IFS_MAX      8



/* Function Prototypes */
/* interface event */
int interface_up (struct thread *);
int interface_down (struct thread *);
int wait_timer (struct thread *);
int backup_seen (struct thread *);
int neighbor_change (struct thread *);


#include "ospf6_types.h"

int dr_change (struct ospf6_interface *);
int ifs_change (state_t, char *, struct ospf6_interface *);

#endif /* OSPF6_ISM_H */

