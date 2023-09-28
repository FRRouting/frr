// SPDX-License-Identifier: GPL-2.0-or-later
/* route-map for interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_IF_RMAP_H
#define _ZEBRA_IF_RMAP_H

#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lyd_node;
struct vty;

enum if_rmap_type { IF_RMAP_IN, IF_RMAP_OUT, IF_RMAP_MAX };

struct if_rmap {
	/* Name of the interface. */
	const char *ifname;

	char *routemap[IF_RMAP_MAX];
};

struct if_rmap_ctx {
	/* if_rmap */
	struct hash *ifrmaphash;

	/* Hook functions. */
	void (*if_rmap_add_hook)(struct if_rmap_ctx *ctx,
				    struct if_rmap *ifrmap);
	void (*if_rmap_delete_hook)(struct if_rmap_ctx *ctx,
				       struct if_rmap *ifrmap);

	/* naming information */
	char *name;
};

extern struct if_rmap_ctx *if_rmap_ctx_create(const char *name);
extern void if_rmap_ctx_delete(struct if_rmap_ctx *ctx);
extern void if_rmap_init(int node);
extern void if_rmap_terminate(void);
void if_rmap_hook_add(struct if_rmap_ctx *ctx,
		      void (*func)(struct if_rmap_ctx *ctx,
				   struct if_rmap *));
void if_rmap_hook_delete(struct if_rmap_ctx *ctx,
			 void (*func)(struct if_rmap_ctx *ctx,
				      struct if_rmap *));
extern struct if_rmap *if_rmap_lookup(struct if_rmap_ctx *ctx,
				      const char *ifname);
extern void if_rmap_yang_modify_cb(struct if_rmap_ctx *ctx,
				   const struct lyd_node *dnode,
				   enum if_rmap_type type, bool del);
extern void if_rmap_yang_destroy_cb(struct if_rmap_ctx *ctx,
				    const struct lyd_node *dnode);
extern int config_write_if_rmap(struct vty *, struct if_rmap_ctx *ctx);
void cli_show_if_route_map(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_IF_RMAP_H */
