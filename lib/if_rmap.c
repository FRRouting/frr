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

#include <zebra.h>

#include "hash.h"
#include "command.h"
#include "memory.h"
#include "if.h"
#include "if_rmap.h"

DEFINE_MTYPE_STATIC(LIB, IF_RMAP_CTX, "Interface route map container")
DEFINE_MTYPE_STATIC(LIB, IF_RMAP_CTX_NAME, "Interface route map container name")
DEFINE_MTYPE_STATIC(LIB, IF_RMAP, "Interface route map")
DEFINE_MTYPE_STATIC(LIB, IF_RMAP_NAME, "I.f. route map name")

struct list *if_rmap_ctx_list;

static struct if_rmap *if_rmap_new(void)
{
	struct if_rmap *new;

	new = XCALLOC(MTYPE_IF_RMAP, sizeof(struct if_rmap));

	return new;
}

static void if_rmap_free(struct if_rmap *if_rmap)
{
	if (if_rmap->ifname)
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->ifname);

	if (if_rmap->routemap[IF_RMAP_IN])
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_IN]);
	if (if_rmap->routemap[IF_RMAP_OUT])
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_OUT]);

	XFREE(MTYPE_IF_RMAP, if_rmap);
}

struct if_rmap *if_rmap_lookup(struct if_rmap_ctx *ctx, const char *ifname)
{
	struct if_rmap key;
	struct if_rmap *if_rmap;

	/* temporary copy */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_IF_RMAP_NAME, ifname) : NULL;

	if_rmap = hash_lookup(ctx->ifrmaphash, &key);

	if (key.ifname)
		XFREE(MTYPE_IF_RMAP_NAME, key.ifname);

	return if_rmap;
}

void if_rmap_hook_add(struct if_rmap_ctx *ctx,
		      void (*func)(struct if_rmap_ctx *ctx,
				   struct if_rmap *))
{
	ctx->if_rmap_add_hook = func;
}

void if_rmap_hook_delete(struct if_rmap_ctx *ctx,
			 void (*func)(struct if_rmap_ctx *ctx,
				      struct if_rmap *))
{
	ctx->if_rmap_delete_hook = func;
}

static void *if_rmap_hash_alloc(void *arg)
{
	struct if_rmap *ifarg = (struct if_rmap *)arg;
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_new();
	if_rmap->ifname = XSTRDUP(MTYPE_IF_RMAP_NAME, ifarg->ifname);

	return if_rmap;
}

static struct if_rmap *if_rmap_get(struct if_rmap_ctx *ctx, const char *ifname)
{
	struct if_rmap key;
	struct if_rmap *ret;

	/* temporary copy */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_IF_RMAP_NAME, ifname) : NULL;

	ret = hash_get(ctx->ifrmaphash, &key, if_rmap_hash_alloc);

	if (key.ifname)
		XFREE(MTYPE_IF_RMAP_NAME, key.ifname);

	return ret;
}

static unsigned int if_rmap_hash_make(void *data)
{
	const struct if_rmap *if_rmap = data;

	return string_hash_make(if_rmap->ifname);
}

static bool if_rmap_hash_cmp(const void *arg1, const void *arg2)
{
	const struct if_rmap *if_rmap1 = arg1;
	const struct if_rmap *if_rmap2 = arg2;

	return strcmp(if_rmap1->ifname, if_rmap2->ifname) == 0;
}

static struct if_rmap *if_rmap_set(struct if_rmap_ctx *ctx,
				   const char *ifname, enum if_rmap_type type,
				   const char *routemap_name)
{
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_get(ctx, ifname);

	if (type == IF_RMAP_IN) {
		if (if_rmap->routemap[IF_RMAP_IN])
			XFREE(MTYPE_IF_RMAP_NAME,
			      if_rmap->routemap[IF_RMAP_IN]);
		if_rmap->routemap[IF_RMAP_IN] =
			XSTRDUP(MTYPE_IF_RMAP_NAME, routemap_name);
	}
	if (type == IF_RMAP_OUT) {
		if (if_rmap->routemap[IF_RMAP_OUT])
			XFREE(MTYPE_IF_RMAP_NAME,
			      if_rmap->routemap[IF_RMAP_OUT]);
		if_rmap->routemap[IF_RMAP_OUT] =
			XSTRDUP(MTYPE_IF_RMAP_NAME, routemap_name);
	}

	if (ctx->if_rmap_add_hook)
		(ctx->if_rmap_add_hook)(ctx, if_rmap);

	return if_rmap;
}

static int if_rmap_unset(struct if_rmap_ctx *ctx,
			 const char *ifname, enum if_rmap_type type,
			 const char *routemap_name)
{
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_lookup(ctx, ifname);
	if (!if_rmap)
		return 0;

	if (type == IF_RMAP_IN) {
		if (!if_rmap->routemap[IF_RMAP_IN])
			return 0;
		if (strcmp(if_rmap->routemap[IF_RMAP_IN], routemap_name) != 0)
			return 0;

		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_IN]);
		if_rmap->routemap[IF_RMAP_IN] = NULL;
	}

	if (type == IF_RMAP_OUT) {
		if (!if_rmap->routemap[IF_RMAP_OUT])
			return 0;
		if (strcmp(if_rmap->routemap[IF_RMAP_OUT], routemap_name) != 0)
			return 0;

		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_OUT]);
		if_rmap->routemap[IF_RMAP_OUT] = NULL;
	}

	if (ctx->if_rmap_delete_hook)
		ctx->if_rmap_delete_hook(ctx, if_rmap);

	if (if_rmap->routemap[IF_RMAP_IN] == NULL
	    && if_rmap->routemap[IF_RMAP_OUT] == NULL) {
		hash_release(ctx->ifrmaphash, if_rmap);
		if_rmap_free(if_rmap);
	}

	return 1;
}

DEFUN (if_rmap,
       if_rmap_cmd,
       "route-map RMAP_NAME <in|out> IFNAME",
       "Route map set\n"
       "Route map name\n"
       "Route map set for input filtering\n"
       "Route map set for output filtering\n"
       "Route map interface name\n")
{
	int idx_rmap_name = 1;
	int idx_in_out = 2;
	int idx_ifname = 3;
	enum if_rmap_type type;
	struct if_rmap_ctx *ctx =
		(struct if_rmap_ctx *)listnode_head(if_rmap_ctx_list);

	if (strncmp(argv[idx_in_out]->text, "in", 1) == 0)
		type = IF_RMAP_IN;
	else if (strncmp(argv[idx_in_out]->text, "out", 1) == 0)
		type = IF_RMAP_OUT;
	else {
		vty_out(vty, "route-map direction must be [in|out]\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if_rmap_set(ctx, argv[idx_ifname]->arg,
		    type, argv[idx_rmap_name]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_if_rmap,
       no_if_rmap_cmd,
       "no route-map ROUTEMAP_NAME <in|out> IFNAME",
       NO_STR
       "Route map unset\n"
       "Route map name\n"
       "Route map for input filtering\n"
       "Route map for output filtering\n"
       "Route map interface name\n")
{
	int idx_routemap_name = 2;
	int idx_in_out = 3;
	int idx_ifname = 4;
	int ret;
	enum if_rmap_type type;
	struct if_rmap_ctx *ctx =
		(struct if_rmap_ctx *)listnode_head(if_rmap_ctx_list);

	if (strncmp(argv[idx_in_out]->arg, "i", 1) == 0)
		type = IF_RMAP_IN;
	else if (strncmp(argv[idx_in_out]->arg, "o", 1) == 0)
		type = IF_RMAP_OUT;
	else {
		vty_out(vty, "route-map direction must be [in|out]\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = if_rmap_unset(ctx, argv[idx_ifname]->arg, type,
			    argv[idx_routemap_name]->arg);
	if (!ret) {
		vty_out(vty, "route-map doesn't exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}


/* Configuration write function. */
int config_write_if_rmap(struct vty *vty,
			 struct if_rmap_ctx *ctx)
{
	unsigned int i;
	struct hash_bucket *mp;
	int write = 0;
	struct hash *ifrmaphash = ctx->ifrmaphash;

	for (i = 0; i < ifrmaphash->size; i++)
		for (mp = ifrmaphash->index[i]; mp; mp = mp->next) {
			struct if_rmap *if_rmap;

			if_rmap = mp->data;

			if (if_rmap->routemap[IF_RMAP_IN]) {
				vty_out(vty, " route-map %s in %s\n",
					if_rmap->routemap[IF_RMAP_IN],
					if_rmap->ifname);
				write++;
			}

			if (if_rmap->routemap[IF_RMAP_OUT]) {
				vty_out(vty, " route-map %s out %s\n",
					if_rmap->routemap[IF_RMAP_OUT],
					if_rmap->ifname);
				write++;
			}
		}
	return write;
}

void if_rmap_ctx_delete(struct if_rmap_ctx *ctx)
{
	hash_clean(ctx->ifrmaphash, (void (*)(void *))if_rmap_free);
	if (ctx->name)
		XFREE(MTYPE_IF_RMAP_CTX_NAME, ctx);
	XFREE(MTYPE_IF_RMAP_CTX, ctx);
}

/* name is optional: either vrf name, or other */
struct if_rmap_ctx *if_rmap_ctx_create(const char *name)
{
	struct if_rmap_ctx *ctx;

	ctx = XCALLOC(MTYPE_IF_RMAP_CTX, sizeof(struct if_rmap_ctx));

	if (ctx->name)
		ctx->name = XSTRDUP(MTYPE_IF_RMAP_CTX_NAME, name);
	ctx->ifrmaphash = hash_create_size(4, if_rmap_hash_make, if_rmap_hash_cmp,
					   "Interface Route-Map Hash");
	if (!if_rmap_ctx_list)
		if_rmap_ctx_list = list_new();
	listnode_add(if_rmap_ctx_list, ctx);
	return ctx;
}

void if_rmap_init(int node)
{
	if (node == RIPNG_NODE) {
	} else if (node == RIP_NODE) {
		install_element(RIP_NODE, &if_rmap_cmd);
		install_element(RIP_NODE, &no_if_rmap_cmd);
	}
	if_rmap_ctx_list = list_new();
}

void if_rmap_terminate(void)
{
	if (!if_rmap_ctx_list)
		return;
	list_delete(&if_rmap_ctx_list);
}
