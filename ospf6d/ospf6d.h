// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6D_H
#define OSPF6D_H

#include "libospf.h"
#include "frrevent.h"
#include "memory.h"

DECLARE_MGROUP(OSPF6D);

/* global variables */
extern struct event_loop *master;

/* OSPF config processing timer thread */
extern struct event *t_ospf6_cfg;

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

#define OSPF6_SUCCESS 1
#define OSPF6_FAILURE 0
#define OSPF6_INVALID -1

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
		struct timeval _result;                                        \
		if (!t)                                                        \
			snprintf(buf, size, "inactive");                       \
		else {                                                         \
			timersub(&t->u.sands, &now, &_result);                 \
			timerstring(&_result, buf, size);                      \
		}                                                              \
	} while (0)

/* for commands */
#define OSPF6_AREA_STR      "Area information\n"
#define OSPF6_AREA_ID_STR   "Area ID (as an IPv4 notation)\n"
#define OSPF6_SPF_STR       "Shortest Path First tree information\n"
#define OSPF6_ROUTER_ID_STR "Specify Router-ID\n"
#define OSPF6_LS_ID_STR     "Specify Link State ID\n"

#define OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6)                                \
	do {                                                                   \
		if (uj == false && all_vrf == false && ospf6 == NULL) {        \
			vty_out(vty, "%% OSPFv3 instance not found\n");        \
			return CMD_SUCCESS;                                    \
		}                                                              \
	} while (0)

#define IS_OSPF6_ASBR(O) ((O)->flag & OSPF6_FLAG_ASBR)
#define OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf)            \
	do {                                                                   \
		if (argv_find(argv, argc, "vrf", &idx_vrf)) {                  \
			vrf_name = argv[idx_vrf + 1]->arg;                     \
			all_vrf = strmatch(vrf_name, "all");                   \
		} else {                                                       \
			vrf_name = VRF_DEFAULT_NAME;                           \
		}                                                              \
	} while (0)

#define OSPF6_FALSE false
#define OSPF6_TRUE true
#define OSPF6_SUCCESS 1
#define OSPF6_FAILURE 0
#define OSPF6_INVALID -1

extern struct zebra_privs_t ospf6d_privs;

/* Event Debug option */
extern unsigned char conf_debug_ospf6_event;
#define OSPF6_DEBUG_EVENT_ON() (conf_debug_ospf6_event = 1)
#define OSPF6_DEBUG_EVENT_OFF() (conf_debug_ospf6_event = 0)
#define IS_OSPF6_DEBUG_EVENT (conf_debug_ospf6_event)

/* Function Prototypes */
extern struct route_node *route_prev(struct route_node *node);

extern void ospf6_debug(void);
extern void ospf6_init(struct event_loop *master);

#endif /* OSPF6D_H */
