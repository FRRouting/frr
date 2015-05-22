/*
 * VRF related header.
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

#ifndef _ZEBRA_VRF_H
#define _ZEBRA_VRF_H

/* The default VRF ID */
#define VRF_DEFAULT 0

/*
 * VRF hooks
 */

#define VRF_NEW_HOOK        0   /* a new VRF is just created */
#define VRF_DELETE_HOOK     1   /* a VRF is to be deleted */

/*
 * Add a specific hook to VRF module.
 * @param1: hook type
 * @param2: the callback function
 *          - param 1: the VRF ID
 *          - param 2: the address of the user data pointer (the user data
 *                     can be stored in or freed from there)
 */
extern void vrf_add_hook (int, int (*)(vrf_id_t, void **));

/*
 * VRF iteration
 */

typedef void *              vrf_iter_t;
#define VRF_ITER_INVALID    NULL    /* invalid value of the iterator */

/*
 * VRF iteration utilities. Example for the usage:
 *
 *   vrf_iter_t iter = vrf_first();
 *   for (; iter != VRF_ITER_INVALID; iter = vrf_next (iter))
 *
 * or
 *
 *   vrf_iter_t iter = vrf_iterator (<a given VRF ID>);
 *   for (; iter != VRF_ITER_INVALID; iter = vrf_next (iter))
 */

/* Return the iterator of the first VRF. */
extern vrf_iter_t vrf_first (void);
/* Return the next VRF iterator to the given iterator. */
extern vrf_iter_t vrf_next (vrf_iter_t);
/* Return the VRF iterator of the given VRF ID. If it does not exist,
 * the iterator of the next existing VRF is returned. */
extern vrf_iter_t vrf_iterator (vrf_id_t);

/*
 * VRF iterator to properties
 */
extern vrf_id_t vrf_iter2id (vrf_iter_t);
extern void *vrf_iter2info (vrf_iter_t);

/*
 * Utilities to obtain the user data
 */

/* Get the data pointer of the specified VRF. If not found, create one. */
extern void *vrf_info_get (vrf_id_t);
/* Look up the data pointer of the specified VRF. */
extern void *vrf_info_lookup (vrf_id_t);

/*
 * VRF initializer/destructor
 */
/* Please add hooks before calling vrf_init(). */
extern void vrf_init (void);
extern void vrf_terminate (void);

#endif /*_ZEBRA_VRF_H*/

