// SPDX-License-Identifier: GPL-2.0-or-later
/* Distribute list functions header
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_DISTRIBUTE_H
#define _ZEBRA_DISTRIBUTE_H

#include <zebra.h>
#include "if.h"
#include "filter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Distribute list types. */
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

extern int distribute_list_parser(bool prefix, bool v4, const char *dir,
				  const char *list, const char *ifname);
extern int distribute_list_no_parser(struct vty *vty, bool prefix, bool v4,
				     const char *dir, const char *list,
				     const char *ifname);
#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DISTRIBUTE_H */
