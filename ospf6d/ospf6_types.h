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

#ifndef OSPF6_TYPES_H
#define OSPF6_TYPES_H

typedef unsigned char  msgtype_t;
typedef unsigned char  instance_id_t;
typedef unsigned char  state_t;
typedef unsigned char  vers_t;
typedef unsigned char  opt_t;
typedef unsigned char  rtr_pri_t;
typedef unsigned char  prefixlen_t;
typedef unsigned char  ddbits_t;
typedef unsigned long  ddseqnum_t;
typedef unsigned long  rtr_id_t;
typedef unsigned long  ifid_t;
typedef unsigned long  cost_t;
typedef unsigned long  rxmt_int_t;
typedef unsigned short hello_int_t;
typedef unsigned short rtr_dead_int_t;
typedef unsigned long  area_id_t;

#endif /* OSPF6_TYPES_H */

