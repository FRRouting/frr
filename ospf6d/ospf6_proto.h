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

#ifndef OSPF6_PROTO_H
#define OSPF6_PROTO_H

/* OSPF protocol version */
#define OSPF6_VERSION		3

/* OSPF protocol number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif

/* TOS field normaly null */
#define OSPF6_TOS_VALUE               0x0

/* Architectural Constants */
#define OSPF6_LS_REFRESH_TIME         1800       /* 30 min */
#define OSPF6_MIN_LS_INTERVAL         5
#define OSPF6_MIN_LS_ARRIVAL          1
#define MAXAGE                  3600       /* 1 hour */
#define CHECK_AGE               300        /* 5 min */
#define MAX_AGE_DIFF            900        /* 15 min */
#define LS_INFINITY             0xffffff   /* 24-bit binary value */
#define INITIAL_SEQUENCE_NUMBER 0x80000001 /* signed 32-bit integer */
#define MAX_SEQUENCE_NUMBER     0x7fffffff /* signed 32-bit integer */

#define MAXOSPFMESSAGELEN         4096

#define ALLSPFROUTERS6 "ff02::5"
#define ALLDROUTERS6   "ff02::6"

/* Configurable Constants */

#define DEFAULT_HELLO_INTERVAL    10
#define DEFAULT_ROUTER_DEAD_TIMER 40

/* OSPF options */
/* present in HELLO, DD, LSA */
#define OSPF6_OPT_SET(x,opt)   ((x)[2] |=  (opt))
#define OSPF6_OPT_ISSET(x,opt) ((x)[2] &   (opt))
#define OSPF6_OPT_CLEAR(x,opt) ((x)[2] &= ~(opt))
#define OSPF6_OPT_CLEAR_ALL(x) ((x)[0] = (x)[1] = (x)[2] = 0)

#define OSPF6_OPT_V6 (1 << 0)   /* IPv6 forwarding Capability */
#define OSPF6_OPT_E  (1 << 1)   /* AS External Capability */
#define OSPF6_OPT_MC (1 << 2)   /* Multicasting Capability */
#define OSPF6_OPT_N  (1 << 3)   /* Handling Type-7 LSA Capability */
#define OSPF6_OPT_R  (1 << 4)   /* Forwarding Capability (Any Protocol) */
#define OSPF6_OPT_DC (1 << 5)   /* Demand Circuit handling Capability */

char *
ospf6_options_string (u_char opt_capability[3], char *buffer, int size);

#endif /* OSPF6_PROTO_H */

