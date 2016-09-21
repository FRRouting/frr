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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _ZEBRA_NS_H
#define _ZEBRA_NS_H

#include "linklist.h"

typedef u_int16_t ns_id_t;

/* The default NS ID */
#define NS_DEFAULT 0

/*
 * The command strings
 */
#define NS_RUN_DIR         "/var/run/netns"
#define NS_CMD_STR         "logical-router <0-65535>"
#define NS_CMD_HELP_STR    "Specify the Logical-Router\nThe Logical-Router ID\n"

#define NS_ALL_CMD_STR         "logical-router all"
#define NS_ALL_CMD_HELP_STR    "Specify the logical-router\nAll logical-router's\n"

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
extern void ns_add_hook (int, int (*)(ns_id_t, void **));

/*
 * NS iteration
 */

typedef void *              ns_iter_t;
#define NS_ITER_INVALID    NULL    /* invalid value of the iterator */

/*
 * NS iteration utilities. Example for the usage:
 *
 *   ns_iter_t iter = ns_first();
 *   for (; iter != NS_ITER_INVALID; iter = ns_next (iter))
 *
 * or
 *
 *   ns_iter_t iter = ns_iterator (<a given NS ID>);
 *   for (; iter != NS_ITER_INVALID; iter = ns_next (iter))
 */

/* Return the iterator of the first NS. */
extern ns_iter_t ns_first (void);
/* Return the next NS iterator to the given iterator. */
extern ns_iter_t ns_next (ns_iter_t);
/* Return the NS iterator of the given NS ID. If it does not exist,
 * the iterator of the next existing NS is returned. */
extern ns_iter_t ns_iterator (ns_id_t);

/*
 * NS iterator to properties
 */
extern ns_id_t ns_iter2id (ns_iter_t);
extern void *ns_iter2info (ns_iter_t);
extern struct list *ns_iter2iflist (ns_iter_t);

/*
 * Utilities to obtain the user data
 */

/* Get the data pointer of the specified NS. If not found, create one. */
extern void *ns_info_get (ns_id_t);
/* Look up the data pointer of the specified NS. */
extern void *ns_info_lookup (ns_id_t);

/*
 * Utilities to obtain the interface list
 */

/* Look up the interface list of the specified NS. */
extern struct list *ns_iflist (ns_id_t);
/* Get the interface list of the specified NS. Create one if not find. */
extern struct list *ns_iflist_get (ns_id_t);

/*
 * NS bit-map: maintaining flags, one bit per NS ID
 */

typedef void *              ns_bitmap_t;
#define NS_BITMAP_NULL     NULL

extern ns_bitmap_t ns_bitmap_init (void);
extern void ns_bitmap_free (ns_bitmap_t);
extern void ns_bitmap_set (ns_bitmap_t, ns_id_t);
extern void ns_bitmap_unset (ns_bitmap_t, ns_id_t);
extern int ns_bitmap_check (ns_bitmap_t, ns_id_t);

/*
 * NS initializer/destructor
 */
/* Please add hooks before calling ns_init(). */
extern void ns_init (void);
extern void ns_terminate (void);

/*
 * NS utilities
 */

/* Create a socket serving for the given NS */
extern int ns_socket (int, int, int, ns_id_t);

#endif /*_ZEBRA_NS_H*/

