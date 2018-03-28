/*
 * Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _QUAGGA_PLIST_H
#define _QUAGGA_PLIST_H

#include <zebra.h>

#include "stream.h"
#include "vty.h"

enum prefix_list_type {
	PREFIX_DENY,
	PREFIX_PERMIT,
};

struct prefix_list;

struct orf_prefix {
	uint32_t seq;
	uint8_t ge;
	uint8_t le;
	struct prefix p;
};

/* Prototypes. */
extern void prefix_list_init(void);
extern void prefix_list_reset(void);
extern void prefix_list_add_hook(void (*func)(struct prefix_list *));
extern void prefix_list_delete_hook(void (*func)(struct prefix_list *));

extern const char *prefix_list_name(struct prefix_list *);
extern afi_t prefix_list_afi(struct prefix_list *);
extern struct prefix_list *prefix_list_lookup(afi_t, const char *);

/*
 * prefix_list_apply_which_prefix
 *
 * Allow calling function to learn which prefix
 * caused the DENY or PERMIT.
 *
 * If no pointer is sent in, do not return anything.
 * If it is a empty plist return a NULL pointer.
 */
extern enum prefix_list_type
prefix_list_apply_which_prefix(struct prefix_list *plist, struct prefix **which,
			       void *object);
#define prefix_list_apply(A, B) prefix_list_apply_which_prefix((A), NULL, (B))

extern struct prefix_list *prefix_bgp_orf_lookup(afi_t, const char *);
extern struct stream *prefix_bgp_orf_entry(struct stream *,
					   struct prefix_list *, uint8_t,
					   uint8_t, uint8_t);
extern int prefix_bgp_orf_set(char *, afi_t, struct orf_prefix *, int, int);
extern void prefix_bgp_orf_remove_all(afi_t, char *);
extern int prefix_bgp_show_prefix_list(struct vty *, afi_t, char *, uint8_t);

#endif /* _QUAGGA_PLIST_H */
