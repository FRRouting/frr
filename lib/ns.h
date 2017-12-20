/*
 * NS related header.
 * Copyright (C) 2014 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _ZEBRA_NS_H
#define _ZEBRA_NS_H

#include "openbsd-tree.h"
#include "linklist.h"
#include "vty.h"
#include "vrf.h"

typedef u_int32_t ns_id_t;

/* the default NS ID */
#define NS_DEFAULT 0
#define NS_UNKNOWN UINT32_MAX

/* Default netns directory (Linux) */
#define NS_RUN_DIR         "/var/run/netns"

struct ns {
	RB_ENTRY(ns) entry;

	/* Identifier, same as the vector index */
	ns_id_t ns_id;

	/* Name */
	char *name;

	/* File descriptor */
	int fd;

	/* Master list of interfaces belonging to this NS */
	struct list *iflist;

	/* Back Pointer to VRF */
	void *vrf_ctxt;

	/* User data */
	void *info;
};
RB_HEAD(ns_head, ns);
RB_PROTOTYPE(ns_head, ns, entry, ns_compare)

extern struct ns_head ns_tree;

/*
 * NS hooks
 */

#define NS_NEW_HOOK        0   /* a new logical-router is just created */
#define NS_DELETE_HOOK     1   /* a logical-router is to be deleted */
#define NS_ENABLE_HOOK     2   /* a logical-router is ready to use */
#define NS_DISABLE_HOOK    3   /* a logical-router is to be unusable */

/*
 * Add a specific hook ns module.
 * @param1: hook type
 * @param2: the callback function
 *          - param 1: the NS ID
 *          - param 2: the address of the user data pointer (the user data
 *                     can be stored in or freed from there)
 */
extern void ns_add_hook(int, int (*)(struct ns *));

/*
 * NS initializer/destructor
 */
extern void ns_init(void);
extern void ns_init_zebra(void);
extern void ns_terminate(void);

/*
 * NS utilities
 */

/* Create a socket serving for the given NS */
extern int ns_socket(int, int, int, ns_id_t);
extern void ns_cmd_init(void);
extern int ns_handler_create(struct vty *vty, struct vrf *vrf,
			     char *pathname, ns_id_t ns_id);
extern char *ns_netns_pathname(struct vty *vty, const char *name);
extern void *ns_info_lookup(ns_id_t ns_id);
extern void ns_walk_func(int (*func)(struct ns *));
extern const char *ns_get_name(struct ns *ns);

/* API that can be used by all daemons */
extern int ns_switchback_to_initial(void);
extern int ns_switch_to_netns(const char *);
extern void ns_init(void);

#endif /*_ZEBRA_NS_H*/
