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

#ifndef OSPF6D_H
#define OSPF6D_H

#include <zebra.h>
#include "linklist.h"

#ifndef HEADER_DEPENDENCY
/* Include other stuffs */
#include "version.h"
#include "log.h"
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "filter.h"
#include "zclient.h"
#include "table.h"
#include "plist.h"

/* OSPF stuffs */
#include "ospf6_hook.h"
#include "ospf6_types.h"
#include "ospf6_prefix.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

#include "ospf6_message.h"
#include "ospf6_proto.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_ism.h"
#include "ospf6_nsm.h"
#include "ospf6_route.h"
#include "ospf6_dbex.h"
#include "ospf6_network.h"
#include "ospf6_zebra.h"
#include "ospf6_dump.h"
#include "ospf6_routemap.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#endif /*HEADER_DEPENDENCY*/

#define HASHVAL 64
#define MAXIOVLIST 1024

#define OSPF6_DAEMON_VERSION    "0.9.6p"

#define AF_LINKSTATE  0xff

/* global variables */
extern char *progname;
extern int errno;
extern int daemon_mode;
extern struct thread_master *master;
extern list iflist;
extern list nexthoplist;
extern struct sockaddr_in6 allspfrouters6;
extern struct sockaddr_in6 alldrouters6;
extern int ospf6_sock;
extern char *recent_reason;

/* Default configuration file name for ospfd. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

#ifdef INRIA_IPV6
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO IPV6_RECVPKTINFO
#endif /* IPV6_PKTINFO */
#endif /* INRIA_IPV6 */

/* Historycal for KAME.  */
#ifndef IPV6_JOIN_GROUP
#ifdef IPV6_ADD_MEMBERSHIP
#define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
#endif /* IPV6_ADD_MEMBERSHIP. */
#ifdef IPV6_JOIN_MEMBERSHIP
#define IPV6_JOIN_GROUP  IPV6_JOIN_MEMBERSHIP
#endif /* IPV6_JOIN_MEMBERSHIP. */
#endif /* ! IPV6_JOIN_GROUP*/

#ifndef IPV6_LEAVE_GROUP
#ifdef IPV6_DROP_MEMBERSHIP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif /* IPV6_DROP_MEMBERSHIP */
#endif /* ! IPV6_LEAVE_GROUP */

#define OSPF6_CMD_CHECK_RUNNING() \
  if (ospf6 == NULL) \
    { \
      vty_out (vty, "OSPFv3 is not running%s", VTY_NEWLINE); \
      return CMD_SUCCESS; \
    }

#define OSPF6_LEVEL_NONE      0
#define OSPF6_LEVEL_NEIGHBOR  1
#define OSPF6_LEVEL_INTERFACE 2
#define OSPF6_LEVEL_AREA      3
#define OSPF6_LEVEL_TOP       4
#define OSPF6_LEVEL_MAX       5

#define OSPF6_PASSIVE_STR \
  "Suppress routing updates on an interface\n"
#define OSPF6_PREFIX_LIST_STR \
  "Advertise I/F Address only match entries of prefix-list\n"

#define OSPF6_AREA_STR      "Area information\n"
#define OSPF6_AREA_ID_STR   "Area ID (as an IPv4 notation)\n"
#define OSPF6_SPF_STR       "Shortest Path First tree information\n"
#define OSPF6_ROUTER_ID_STR "Specify Router-ID\n"
#define OSPF6_LS_ID_STR     "Specify Link State ID\n"


/* Function Prototypes */
void
ospf6_timeval_sub (const struct timeval *t1, const struct timeval *t2,
                   struct timeval *result);
void
ospf6_timeval_div (const struct timeval *t1, u_int by,
                   struct timeval *result);
void
ospf6_timeval_sub_equal (const struct timeval *t, struct timeval *result);
void
ospf6_timeval_decode (const struct timeval *t, long *dayp, long *hourp,
                      long *minp, long *secp, long *msecp, long *usecp);
void
ospf6_timeval_string (struct timeval *tv, char *buf, int size);
void
ospf6_timeval_string_summary (struct timeval *tv, char *buf, int size);

void
ospf6_count_state (void *arg, int val, void *obj);

void ospf6_init ();
void ospf6_terminate ();

void ospf6_maxage_remover ();

void *ospf6_lsa_get_scope (u_int16_t type, struct ospf6_interface *o6i);

#endif /* OSPF6D_H */

