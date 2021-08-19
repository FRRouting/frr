/* CMGD message definition header.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_CMGD_H
#define _FRR_CMGD_H

#include "qobj.h"
#include <pthread.h>

#include "hook.h"
#include "frr_pthread.h"
#include "lib/compiler.h"
#include "lib/json.h"
#include "vrf.h"
#include "vty.h"
#include "iana_afi.h"

/* For union sockunion.  */
#include "queue.h"
#include "sockunion.h"
#include "routemap.h"
#include "linklist.h"
#include "defaults.h"
#include "cmgd_memory.h"
#include "bitfield.h"
#include "vxlan.h"
#include "cmgd/cmgd_defines.h"
#include "cmgd/cmgd_trxn.h"
#include "cmgd/cmgd_db.h"

// #define CMGD_MAX_HOSTNAME 64	/* Linux max, is larger than most other sys */

#define CMGD_VTY_PORT			2622
#define CMGD_SOCKET_SNDBUF_SIZE 	65536

#define max(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a > _b ? _a : _b;                                             \
	})

// #define REDIRECT_DEBUG_TO_STDERR

// extern struct frr_pthread *cmgd_pth_io;
// extern struct frr_pthread *cmgd_pth_ka;

extern bool cmgd_debug_bcknd;
extern bool cmgd_debug_frntnd;
extern bool cmgd_debug_db;
extern bool cmgd_debug_trxn;

/* CMGD master for system wide configurations and variables.  */
struct cmgd_master {
	/* CMGD instance list.  */
	struct list *cmgd;

	/* CMGD thread master.  */
	struct thread_master *master;

	/* Listening sockets */
	struct list *listen_sockets;

	/* CMGD port number.  */
	uint16_t port;

	/* Listener addresses */
	// struct list *addresses;

	/* CMGD start time.  */
	time_t start_time;

	/* Various CMGD global configuration.  */
	uint8_t options;
#define CMGD_OPT_NO_FIB                   (1 << 0)
#define CMGD_OPT_NO_LISTEN                (1 << 1)
#define CMGD_OPT_NO_ZEBRA                 (1 << 2)

	/* How big should we set the socket buffer size */
	uint32_t socket_buffer;

	/* List of all transactions currently underway */
	struct cmgd_trxn_list_head cmgd_trxns;

	/* The single instance of config transaction allowed at any time */
	cmgd_trxn_ctxt_t *cfg_trxn;

	/* Databases */
	cmgd_db_hndl_t running_db;
	cmgd_db_hndl_t candidate_db;
	cmgd_db_hndl_t oper_db;

	bool terminating;	/* global flag that sigint terminate seen */
	// QOBJ_FIELDS
};
// DECLARE_QOBJ_TYPE(cmgd_master)

/* CMGD instance structure.  */
struct cmgd {
	/* Name of this CMGD instance.  */
	char *name;
	char *name_pretty;	/* printable "VRF|VIEW name|default" */

	/* VRF id. */
	vrf_id_t vrf_id;

	/* Reference count */
	int lock;

#if 0
	/* Self peer.  */
	struct peer *peer_self;

	/* CMGD peer. */
	struct list *peer;
	struct hash *peerhash;

	/*
	 * Global statistics for update groups.
	 */
	struct {
		uint32_t join_events;
		uint32_t prune_events;
		uint32_t merge_events;
		uint32_t split_events;
		uint32_t updgrp_switch_events;
		uint32_t peer_refreshes_combined;
		uint32_t adj_count;
		uint32_t merge_checks_triggered;

		uint32_t updgrps_created;
		uint32_t updgrps_deleted;
		uint32_t subgrps_created;
		uint32_t subgrps_deleted;
	} update_group_stats;
#endif

	/* Process Queue for handling routes */
	struct work_queue *process_queue;

	// QOBJ_FIELDS
};
// DECLARE_QOBJ_TYPE(cmgd)

// DECLARE_HOOK(cmgd_inst_delete, (struct cmgd *cmgd), (cmgd))
// DECLARE_HOOK(cmgd_inst_config_write,
// 		(struct cmgd *cmgd, struct vty *vty),
// 		(cmgd, vty))

extern struct cmgd_master *cm;

/* Inline functions */
static inline void cmgd_remove_trailing_separator(char *str, char sep)
{
	size_t len;
	
	len = strlen(str);
	if (len && str[len - 1] == sep)
		str[len - 1] = '\0';
}

/* Prototypes. */
extern void cmgd_terminate(void);
extern void cmgd_reset(void);
extern time_t cmgd_clock(void);

#if 0
extern void cmgd_zclient_reset(void);
extern struct cmgd *cmgd_get_default(void);
extern struct cmgd *cmgd_lookup(as_t, const char *);
extern struct cmgd *cmgd_lookup_by_name(const char *);
extern struct cmgd *cmgd_lookup_by_vrf_id(vrf_id_t);
#endif

extern int cmgd_config_write(struct vty *);

extern void cmgd_master_init(struct thread_master *master, const int buffer_size,
			    struct list *addresses);

extern void cmgd_init(void);
extern void cmgd_pthreads_run(void);
extern void cmgd_pthreads_finish(void);

extern void cmgd_instance_up(struct cmgd *);
extern void cmgd_instance_down(struct cmgd *);
extern int cmgd_delete(struct cmgd *);

extern int cmgd_handle_socket(struct cmgd *cmgd, struct vrf *vrf,
			     vrf_id_t old_vrf_id, bool create);

extern void cmgd_timers_set(struct cmgd *, uint32_t keepalive, uint32_t holdtime,
			   uint32_t connect_retry, uint32_t delayopen);
extern void cmgd_timers_unset(struct cmgd *);

extern int cmgd_listen_limit_set(struct cmgd *, int);
extern int cmgd_listen_limit_unset(struct cmgd *);

extern void cmgd_shutdown_enable(struct cmgd *cmgd, const char *msg);
extern void cmgd_shutdown_disable(struct cmgd *cmgd);

extern void cmgd_close(void);
extern void cmgd_free(struct cmgd *);

static inline struct cmgd *cmgd_lock(struct cmgd *cmgd)
{
	cmgd->lock++;
	return cmgd;
}

static inline void cmgd_unlock(struct cmgd *cmgd)
{
	assert(cmgd->lock > 0);
	if (--cmgd->lock == 0)
		cmgd_free(cmgd);
}

static inline char *timestamp_string(time_t ts)
{
	time_t tbuf;
	tbuf = time(NULL) - (cmgd_clock() - ts);
	return ctime(&tbuf);
}

/* Link CMGD instance to VRF. */
static inline void cmgd_vrf_link(struct cmgd *cmgd, struct vrf *vrf)
{
	cmgd->vrf_id = vrf->vrf_id;
	if (vrf->info != (void *)cmgd)
		vrf->info = (void *)cmgd_lock(cmgd);
}

/* Unlink CMGD instance from VRF. */
static inline void cmgd_vrf_unlink(struct cmgd *cmgd, struct vrf *vrf)
{
	if (vrf->info == (void *)cmgd) {
		vrf->info = NULL;
		cmgd_unlock(cmgd);
	}
	cmgd->vrf_id = VRF_UNKNOWN;
}

extern void cmgd_unset_redist_vrf_bitmaps(struct cmgd *, vrf_id_t);



#endif /* _FRR_CMGD_H */
