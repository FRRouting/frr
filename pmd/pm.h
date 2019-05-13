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
#define PM_SESS_FLAG_NH_VALID      (1 << 4)
#define PM_SESS_FLAG_NH_REGISTERED (1 << 5)
	uint32_t flags;
	union sockunion nh;
	enum pm_probe_type type;
#define PM_PACKET_SIZE_DEFAULT PM_DEF_PACKET_SIZE
#define PM_PACKET_SIZE_DEFAULT_IPV6 PM_DEF_IPV6_PACKET_SIZE
	int packet_size;
#define PM_INTERVAL_DEFAULT PM_DEF_INTERVAL
	int interval;
#define PM_PACKET_TOS_DEFAULT PM_DEF_TOS_VAL
	uint8_t tos_val;
#define PM_PACKET_RETRIES_DOWN_DEFAULT 1
	uint8_t retries_down;
#define PM_PACKET_RETRIES_UP_DEFAULT 1
	uint8_t retries_up;
#define PM_TIMEOUT_DEFAULT PM_DEF_TIMEOUT
	int timeout;

	void *oper_ctxt;

	struct timeval last_time_change;
	uint64_t refcount; /* number of pointers referencing this. */
#define PM_ADM_DOWN 0
#define PM_DOWN 1
#define PM_INIT 2
#define PM_UP 3
	uint8_t ses_state;

	QOBJ_FIELDS;

};

DECLARE_QOBJ_TYPE(pm_session);

extern struct hash *pm_session_list;
extern struct hash *pm_id_list;

extern void pm_init(void);
extern void pm_shutdown(void);
extern void pm_initialise(struct pm_session *pm, bool validate_only,
			  char *ebuf, size_t size);
extern void pm_set_sess_state(struct pm_session *pm, uint8_t ses_state);

extern struct pm_session *pm_lookup_session(union sockunion *peer,
					    const char *local,
					    const char *ifname,
					    const char *vrfname,
					    bool create,
					    char *ebuf, size_t ebuflen);

extern uint32_t pm_id_list_gen_id(void);
struct pm_echo;
extern bool pm_id_list_insert(struct pm_echo *pm);
extern void pm_id_list_delete(struct pm_echo *pm);
struct vty;
extern void pm_try_run(struct vty *vty, struct pm_session *pm);

extern struct zebra_privs_t pm_privs;

extern struct thread_master *master;

extern void pm_try_run(struct vty *vty, struct pm_session *pm);

extern char *pm_get_probe_type(struct pm_session *pm, char *buf,
			       size_t len);

extern void pm_sessions_update(void);
extern void pm_sessions_change_interface(struct interface *ifp, bool ret);

extern int pm_get_default_packet_size(struct pm_session *pm);
extern char *pm_get_state_str(struct pm_session *pm, char *buf, size_t len);
extern void pm_nht_update(struct prefix *p, uint32_t nh_num, afi_t afi,
			  vrf_id_t nh_vrf_id, struct vty *vty);

extern void pm_get_peer(struct pm_session *pm, union sockunion *peer);
extern void pm_get_gw(struct pm_session *pm, union sockunion *gw);

extern void pm_vrf_init(void);
extern void pm_vrf_terminate(void);

#endif
