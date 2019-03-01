/* route-map for interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_IF_RMAP_H
#define _ZEBRA_IF_RMAP_H

#ifdef __cplusplus
extern "C" {
#endif

enum if_rmap_type { IF_RMAP_IN, IF_RMAP_OUT, IF_RMAP_MAX };

struct if_rmap {
	/* Name of the interface. */
	char *ifname;

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
extern int config_write_if_rmap(struct vty *, struct if_rmap_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_IF_RMAP_H */
