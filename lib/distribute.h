// SPDX-License-Identifier: GPL-2.0-or-later
/* Distribute list functions header
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_DISTRIBUTE_H
#define _ZEBRA_DISTRIBUTE_H

#include <zebra.h>
#include "if.h"
#include "filter.h"
#include "northbound.h"

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

extern int distribute_list_parser(struct distribute_ctx *ctx, bool prefix,
				  bool v4, const char *dir, const char *list,
				  const char *ifname);
extern int distribute_list_no_parser(struct distribute_ctx *ctx,
				     struct vty *vty, bool prefix, bool v4,
				     const char *dir, const char *list,
				     const char *ifname);

/*
 * Northbound
 */

/*
 * Define your own create callback and then call thes helper with your
 * distribute list context when a list entry is created. Additionally, plug the
 * destroy callback into the frr_module_yang_info struct, or call it if you have
 * your own callback destroy function.
 */
extern int group_distribute_list_create_helper(struct nb_cb_create_args *args,
					       struct distribute_ctx *ctx);
extern int group_distribute_list_destroy(struct nb_cb_destroy_args *args);

/*
 * Plug 3 of these handlers in for your distribute-list for all the northbound
 * distribute_list leaf callbacks. If you need multi-protocol then use the
 * grouping twice under 2 different containers.
 */
extern int group_distribute_list_ipv4_modify(struct nb_cb_modify_args *args);
extern int group_distribute_list_ipv4_destroy(struct nb_cb_destroy_args *args);
extern void group_distribute_list_ipv4_cli_show(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults);
extern int group_distribute_list_ipv6_modify(struct nb_cb_modify_args *args);
extern int group_distribute_list_ipv6_destroy(struct nb_cb_destroy_args *args);
extern void group_distribute_list_ipv6_cli_show(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults);
#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DISTRIBUTE_H */
