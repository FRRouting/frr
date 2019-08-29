/*
 * header for path monitoring daemon
 * Copyright 2019 6WIND S.A.
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
#include "lib/command.h"
#include "lib/resolver.h"

#define MAXNAMELEN 36

struct pm_session_key {
	char peer[HOSTNAME_LEN];
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
#define PM_SESS_FLAG_RESOLUTION_ON (1 << 6)
	uint32_t flags;
	union sockunion peer;
	struct resolver_query dns_resolve;
	struct thread *t_resolve;
	afi_t afi_resolve;
	union sockunion nh;
	enum pm_probe_type type;
#define PM_PACKET_SIZE_DEFAULT PM_DEF_PACKET_SIZE
#define PM_PACKET_SIZE_DEFAULT_IPV6 PM_DEF_IPV6_PACKET_SIZE
	int packet_size;
#define PM_INTERVAL_DEFAULT PM_DEF_INTERVAL
	int interval;
#define PM_PACKET_TOS_DEFAULT PM_DEF_TOS_VAL
	uint8_t tos_val;
#define PM_RETRIES_MODE_CONSECUTIVE 1
#define PM_RETRIES_MODE_THRESHOLD   2
	uint8_t retries_mode;
#define PM_PACKET_RETRIES_CONSECUTIVE_DOWN_DEFAULT 1
	uint8_t retries_consecutive_down;
#define PM_PACKET_RETRIES_CONSECUTIVE_UP_DEFAULT 1
	uint8_t retries_consecutive_up;
#define PM_PACKET_RETRIES_THRESHOLD_DEFAULT 1
	uint8_t retries_threshold;
#define PM_PACKET_RETRIES_TOTAL_DEFAULT 1
	uint8_t retries_total;
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
	/* in case no source IP mentioned,
	 * the source IP will be picked up from that interface
	 */
	ifindex_t ifindex_out;

	QOBJ_FIELDS;

};

DECLARE_QOBJ_TYPE(pm_session);

/* Peer status */
enum pm_peer_status {
	BPS_SHUTDOWN = 0, /* == PM_ADM_DOWN, "adm-down" */
	BPS_DOWN = 1,     /* == PM_DOWN, "down" */
	BPS_INIT = 2,     /* == PM_INIT, "init" */
	BPS_UP = 3,       /* == PM_UP, "up" */
};

struct pm_peer_cfg {
	bool bpc_ipv4;
	union sockunion bpc_peer;
	union sockunion bpc_local;

	bool bpc_has_localif;
	char bpc_localif[MAXNAMELEN + 1];

	bool bpc_has_vrfname;
	char bpc_vrfname[MAXNAMELEN + 1];

	bool bpc_has_interval;
	uint32_t bpc_interval;

	bool bpc_has_timeout;
	uint32_t bpc_timeout;

	bool bpc_has_packet_size;
	uint16_t bpc_packet_size;

	bool bpc_has_tos_val;
	uint8_t bpc_tos_val;

	union sockunion bpc_nexthop;

	bool bpc_shutdown;

	/* Status information */
	enum pm_peer_status bpc_bps;
	uint64_t bpc_lastevent;
};

extern struct hash *pm_session_list;
extern struct hash *pm_id_list;

extern void pm_init(void);
extern void pm_shutdown(void);
extern void pm_initialise(struct pm_session *pm, bool validate_only,
			  char *ebuf, size_t size);
extern void pm_set_sess_state(struct pm_session *pm, uint8_t ses_state);

extern struct pm_session *pm_lookup_session(const char *peer,
					    const char *local,
					    const char *ifname,
					    const char *vrfname,
					    bool create,
					    char *ebuf, size_t ebuflen);
extern struct pm_session *pm_create_session(const char *peer,
					    const char *local,
					    const char *ifname,
					    const char *vrfname);
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
			  vrf_id_t nh_vrf_id, struct vty *vty, ifindex_t idx);

extern void pm_get_peer(struct pm_session *pm, union sockunion *peer);
extern void pm_get_gw(struct pm_session *pm, union sockunion *gw);

extern void pm_vrf_init(void);
extern void pm_vrf_terminate(void);

#endif
