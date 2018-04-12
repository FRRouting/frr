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

typedef uint32_t ns_id_t;

/* the default NS ID */
#define NS_UNKNOWN UINT32_MAX

/* Default netns directory (Linux) */
#define NS_RUN_DIR         "/var/run/netns"

#ifdef HAVE_NETNS
#define NS_DEFAULT_NAME    "/proc/self/ns/net"
#else  /* !HAVE_NETNS */
#define NS_DEFAULT_NAME    "Default-logical-router"
#endif /* HAVE_NETNS */

struct ns {
	RB_ENTRY(ns) entry;

	/* Identifier, same as the vector index */
	ns_id_t ns_id;

	/* Identifier, mapped on the NSID value */
	ns_id_t internal_ns_id;

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
 * API for managing NETNS. eg from zebra daemon
 * one want to manage the list of NETNS, etc...
 */

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
extern void ns_add_hook(int type, int (*)(struct ns *));


/*
 * NS initializer/destructor
 */

extern void ns_terminate(void);

/* API to initialize NETNS managerment
 * parameter is the default ns_id
 */
extern void ns_init_management(ns_id_t ns_id, ns_id_t internal_ns_idx);


/*
 * NS utilities
 */

/* Create a socket serving for the given NS
 */
int ns_socket(int domain, int type, int protocol, ns_id_t ns_id);

/* return the path of the NETNS */
extern char *ns_netns_pathname(struct vty *vty, const char *name);

/* Parse and execute a function on all the NETNS */
extern void ns_walk_func(int (*func)(struct ns *));

/* API to get the NETNS name, from the ns pointer */
extern const char *ns_get_name(struct ns *ns);

/* only called from vrf ( when removing netns from vrf)
 * or at VRF or logical router termination
 */
extern void ns_delete(struct ns *ns);

/* return > 0 if netns is available
 * called by VRF to check netns backend is available for VRF
 */
extern int ns_have_netns(void);

/* API to get context information of a NS */
extern void *ns_info_lookup(ns_id_t ns_id);

/* API to map internal ns id value with
 * user friendly ns id external value
 */
extern ns_id_t ns_map_nsid_with_external(ns_id_t ns_id, bool map);

/*
 * NS init routine
 * should be called from backendx
 */
extern void ns_init(void);

/* API to retrieve default NS */
extern ns_id_t ns_get_default_id(void);

#define NS_DEFAULT ns_get_default_id()

/* API that can be used to change from NS */
extern int ns_switchback_to_initial(void);
extern int ns_switch_to_netns(const char *netns_name);

/*
 * NS handling routines.
 * called by modules that use NS backend
 */

/* API to search for already present NETNS */
extern struct ns *ns_lookup(ns_id_t ns_id);
extern struct ns *ns_lookup_name(const char *name);

/* API to handle NS : creation, enable, disable
 * for enable, a callback function is passed as parameter
 * the callback belongs to the module that uses NS as backend
 * upon enabling the NETNS, the upper layer is informed
 */
extern int ns_enable(struct ns *ns, void (*func)(ns_id_t, void *));
extern struct ns *ns_get_created(struct ns *ns, char *name, ns_id_t ns_id);
extern void ns_disable(struct ns *ns);

#endif /*_ZEBRA_NS_H*/
