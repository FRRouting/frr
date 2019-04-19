/*
 * header for path monitoring daemon
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __PM_H__
#define __PM_H__

#include "lib/libfrr.h"
#include "lib/qobj.h"
#include "lib/sockunion.h"
#include "lib/pm_lib.h"

#define MAXNAMELEN 36

struct pm_session_key {
	union sockunion peer;
	union sockunion local;
	char ifname[MAXNAMELEN];
	char vrfname[MAXNAMELEN];
};

#define PM_SET_FLAG(field, flag) (field |= flag)
#define PM_UNSET_FLAG(field, flag) (field &= ~flag)
#define PM_CHECK_FLAG(field, flag) (field & flag)

enum pm_probe_type {
	PM_ICMP_ECHO = 0, /* for RTT & connectivity */
	PM_ICMP_TIMESTAMP = 1, /* for RTT & oneway delay, & connectivity */
};

struct pm_session {
	struct pm_session_key key;
	/* VTY context data. */
#define PM_SESS_FLAG_SHUTDOWN      (1 << 0)
#define PM_SESS_FLAG_VALIDATE      (1 << 1)
#define PM_SESS_FLAG_CONFIG        (1 << 2)
#define PM_SESS_FLAG_RUN           (1 << 3)
	uint32_t flags;
	enum pm_probe_type type;
#define PM_PACKET_SIZE_DEFAULT PM_DEF_PACKET_SIZE
#define PM_PACKET_SIZE_DEFAULT_IPV6 PM_DEF_IPV6_PACKET_SIZE
	int packet_size;
#define PM_INTERVAL_DEFAULT PM_DEF_INTERVAL
	int interval;
#define PM_PACKET_TOS_DEFAULT PM_DEF_TOS_VAL
	uint8_t tos_val;
#define PM_TIMEOUT_DEFAULT PM_DEF_TIMEOUT
	int timeout;

	QOBJ_FIELDS;

};

DECLARE_QOBJ_TYPE(pm_session);

extern struct hash *pm_session_list;

extern void pm_init(void);
extern void pm_shutdown(void);
extern void pm_initialise(struct pm_session *pm, bool validate_only,
			  char *ebuf, size_t size);

extern struct pm_session *pm_lookup_session(union sockunion *peer,
					    const char *local,
					    const char *ifname,
					    const char *vrfname,
					    bool create,
					    char *ebuf, size_t ebuflen);

extern struct zebra_privs_t pm_privs;

extern struct thread_master *master;

extern void pm_try_run(struct vty *vty, struct pm_session *pm);

extern char *pm_get_probe_type(struct pm_session *pm, char *buf,
			       size_t len);

extern void pm_sessions_update(void);
extern void pm_sessions_change_interface(struct interface *ifp, bool ret);

extern int pm_get_default_packet_size(struct pm_session *pm);

#endif
