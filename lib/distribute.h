/* Distribute list functions header
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

#ifndef _ZEBRA_DISTRIBUTE_H
#define _ZEBRA_DISTRIBUTE_H

#include <zebra.h>
#include "if.h"
#include "filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Disctirubte list types. */
enum distribute_type {
	DISTRIBUTE_V4_IN,
	DISTRIBUTE_V6_IN,
	DISTRIBUTE_V4_OUT,
	DISTRIBUTE_V6_OUT,
	DISTRIBUTE_MAX
};

struct distribute {
	/* Name of the interface. */
	char *ifname;

	/* Filter name of `in' and `out' */
	char *list[DISTRIBUTE_MAX];

	/* prefix-list name of `in' and `out' */
	char *prefix[DISTRIBUTE_MAX];
};

struct distribute_ctx {
	/* Hash of distribute list. */
	struct hash *disthash;

	/* Hook functions. */
	void (*distribute_add_hook)(struct distribute_ctx *ctx,
				    struct distribute *dist);
	void (*distribute_delete_hook)(struct distribute_ctx *ctx,
				       struct distribute *dist);

	/* vrf information */
	struct vrf *vrf;
};

/* Prototypes for distribute-list. */
extern void distribute_list_init(int node);
extern struct distribute_ctx *distribute_list_ctx_create(struct vrf *vrf);
extern void distribute_list_delete(struct distribute_ctx **ctx);
extern void distribute_list_add_hook(struct distribute_ctx *ctx,
				     void (*)(struct distribute_ctx *ctx,
					      struct distribute *));
extern void distribute_list_delete_hook(struct distribute_ctx *ctx,
					void (*)(struct distribute_ctx *ctx,
						 struct distribute *));
extern struct distribute *distribute_lookup(struct distribute_ctx *ctx,
					    const char *ifname);
extern int config_write_distribute(struct vty *vty,
				   struct distribute_ctx *ctx);
extern int config_show_distribute(struct vty *vty,
				  struct distribute_ctx *ctx);

extern enum filter_type distribute_apply_in(struct interface *,
					    struct prefix *);
extern enum filter_type distribute_apply_out(struct interface *,
					     struct prefix *);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DISTRIBUTE_H */
