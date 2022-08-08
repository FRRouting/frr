/*
 * Zebra privileges header.
 *
 * Copyright (C) 2003 Paul Jakma.
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

#ifndef _ZEBRA_PRIVS_H
#define _ZEBRA_PRIVS_H

#include <pthread.h>
#include <stdint.h>
#include "lib/queue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* list of zebra capabilities */
typedef enum {
	ZCAP_SETID,
	ZCAP_BIND,
	ZCAP_NET_ADMIN,
	ZCAP_SYS_ADMIN,
	ZCAP_NET_RAW,
	ZCAP_CHROOT,
	ZCAP_NICE,
	ZCAP_PTRACE,
	ZCAP_DAC_OVERRIDE,
	ZCAP_READ_SEARCH,
	ZCAP_FOWNER,
	ZCAP_IPC_LOCK,
	ZCAP_SYS_RAWIO,
	ZCAP_MAX
} zebra_capabilities_t;

typedef enum {
	ZPRIVS_LOWERED,
	ZPRIVS_RAISED,
	ZPRIVS_UNKNOWN,
} zebra_privs_current_t;

typedef enum {
	ZPRIVS_RAISE,
	ZPRIVS_LOWER,
} zebra_privs_ops_t;

struct zebra_privs_refs_t {
	STAILQ_ENTRY(zebra_privs_refs_t) entry;
	pthread_t tid;
	uint32_t refcount;
	const char *raised_in_funcname;
};

struct zebra_privs_t {
	zebra_capabilities_t *caps_p; /* caps required for operation */
	zebra_capabilities_t *caps_i; /* caps to allow inheritance of */
	int cap_num_p;		      /* number of caps in arrays */
	int cap_num_i;

	/* Mutex and counter used to avoid race conditions in multi-threaded
	 * processes. If privs status is process-wide, we need to
	 * control changes to the privilege status among threads.
	 * If privs changes are per-thread, we need to be able to
	 * manage that too.
	 */
	pthread_mutex_t mutex;
	struct zebra_privs_refs_t process_refs;

	STAILQ_HEAD(thread_refs_q, zebra_privs_refs_t) thread_refs;

	const char *user; /* user and group to run as */
	const char *group;
	const char *vty_group; /* group to chown vty socket to */
	/* methods */
	int (*change)(zebra_privs_ops_t); /* change privileges, 0 on success */
	zebra_privs_current_t (*current_state)(
		void); /* current privilege state */
};

struct zprivs_ids_t {
	/* -1 is undefined */
	uid_t uid_priv;   /* privileged uid */
	uid_t uid_normal; /* normal uid */
	gid_t gid_priv;   /* privileged uid */
	gid_t gid_normal; /* normal uid */
	gid_t gid_vty;    /* vty gid */
};

extern struct zebra_privs_t *lib_privs;

/* initialise zebra privileges */
extern void zprivs_preinit(struct zebra_privs_t *zprivs);
extern void zprivs_init(struct zebra_privs_t *zprivs);
/* drop all and terminate privileges */
extern void zprivs_terminate(struct zebra_privs_t *);
/* query for runtime uid's and gid's, eg vty needs this */
extern void zprivs_get_ids(struct zprivs_ids_t *);

/*
 * Wrapper around zprivs, to be used as:
 *   frr_with_privs(&privs) {
 *     ... code ...
 *     if (error)
 *       break;         -- break can be used to get out of the block
 *     ... code ...
 *   }
 *
 * The argument to frr_with_privs() can be NULL to leave privileges as-is
 * (mostly useful for conditional privilege-raising, i.e.:)
 *   frr_with_privs(cond ? &privs : NULL) {}
 *
 * NB: The code block is always executed, regardless of whether privileges
 * could be raised or not, or whether NULL was given or not.  This is fully
 * intentional;  the user may have configured some RBAC or similar that we
 * are not aware of, but that allows our code to proceed without privileges.
 *
 * The point of this wrapper is to prevent accidental bugs where privileges
 * are elevated but then not dropped.  This can happen when, for example, a
 * "return", "goto" or "break" in the middle of the elevated-privilege code
 * skips past the privilege dropping call.
 *
 * The macro below uses variable cleanup to drop privileges as soon as the
 * code block is left in any way (and thus the _privs variable goes out of
 * scope.)  _once is just a trick to run the loop exactly once.
 */
extern struct zebra_privs_t *_zprivs_raise(struct zebra_privs_t *privs,
					   const char *funcname);
extern void _zprivs_lower(struct zebra_privs_t **privs);

#define frr_with_privs(privs)                                               \
	for (struct zebra_privs_t *_once = NULL,                               \
				  *_privs __attribute__(                       \
					  (unused, cleanup(_zprivs_lower))) =  \
					  _zprivs_raise(privs, __func__);      \
	     _once == NULL; _once = (void *)1)

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PRIVS_H */
