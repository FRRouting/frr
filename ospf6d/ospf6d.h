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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef OSPF6D_H
#define OSPF6D_H

#include "libospf.h"
#include "thread.h"

#include "ospf6_memory.h"

/* global variables */
extern struct thread_master *master;

/* Historical for KAME.  */
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

#define MSG_OK    0
#define MSG_NG    1

/* cast macro: XXX - these *must* die, ick ick. */
#define OSPF6_PROCESS(x) ((struct ospf6 *) (x))
#define OSPF6_AREA(x) ((struct ospf6_area *) (x))
#define OSPF6_INTERFACE(x) ((struct ospf6_interface *) (x))
#define OSPF6_NEIGHBOR(x) ((struct ospf6_neighbor *) (x))

/* operation on timeval structure */
#define timerstring(tv, buf, size)                                             \
	do {                                                                   \
		if ((tv)->tv_sec / 60 / 60 / 24)                               \
			snprintf(buf, size, "%lldd%02lld:%02lld:%02lld",       \
				 (tv)->tv_sec / 60LL / 60 / 24,                \
				 (tv)->tv_sec / 60LL / 60 % 24,                \
				 (tv)->tv_sec / 60LL % 60,                     \
				 (tv)->tv_sec % 60LL);                         \
		else                                                           \
			snprintf(buf, size, "%02lld:%02lld:%02lld",            \
				 (tv)->tv_sec / 60LL / 60 % 24,                \
				 (tv)->tv_sec / 60LL % 60,                     \
				 (tv)->tv_sec % 60LL);                         \
	} while (0)

#define threadtimer_string(now, t, buf, size)                                  \
	do {                                                                   \
		struct timeval result;                                         \
		if (!t)                                                        \
			snprintf(buf, size, "inactive");                       \
		else {                                                         \
			timersub(&t->u.sands, &now, &result);                  \
			timerstring(&result, buf, size);                       \
		}                                                              \
	} while (0)

/* for commands */
#define OSPF6_AREA_STR      "Area information\n"
#define OSPF6_AREA_ID_STR   "Area ID (as an IPv4 notation)\n"
#define OSPF6_SPF_STR       "Shortest Path First tree information\n"
#define OSPF6_ROUTER_ID_STR "Specify Router-ID\n"
#define OSPF6_LS_ID_STR     "Specify Link State ID\n"

#define OSPF6_CMD_CHECK_RUNNING()                                              \
	if (ospf6 == NULL) {                                                   \
		vty_out(vty, "OSPFv3 is not running\n");                       \
		return CMD_SUCCESS;                                            \
	}

extern struct zebra_privs_t ospf6d_privs;

/* Function Prototypes */
extern struct route_node *route_prev(struct route_node *node);

extern void ospf6_debug(void);
extern void ospf6_init(void);

#endif /* OSPF6D_H */
