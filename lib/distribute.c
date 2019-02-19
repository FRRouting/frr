/* Distribute list functions
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "filter.h"
#include "command.h"
#include "distribute.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_CTX, "Distribute ctx")
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE, "Distribute list")
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_IFNAME, "Dist-list ifname")
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_NAME, "Dist-list name")

struct list *dist_ctx_list;

static struct distribute *distribute_new(void)
{
	return XCALLOC(MTYPE_DISTRIBUTE, sizeof(struct distribute));
}

/* Free distribute object. */
static void distribute_free(struct distribute *dist)
{
	int i = 0;

	if (dist->ifname)
		XFREE(MTYPE_DISTRIBUTE_IFNAME, dist->ifname);

	for (i = 0; i < DISTRIBUTE_MAX; i++)
		if (dist->list[i])
			XFREE(MTYPE_DISTRIBUTE_NAME, dist->list[i]);

	for (i = 0; i < DISTRIBUTE_MAX; i++)
		if (dist->prefix[i])
			XFREE(MTYPE_DISTRIBUTE_NAME, dist->prefix[i]);

	XFREE(MTYPE_DISTRIBUTE, dist);
}

static void distribute_free_if_empty(struct distribute_ctx *ctx,
				     struct distribute *dist)
{
	int i;

	for (i = 0; i < DISTRIBUTE_MAX; i++)
		if (dist->list[i] != NULL || dist->prefix[i] != NULL)
			return;

	hash_release(ctx->disthash, dist);
	distribute_free(dist);
}

/* Lookup interface's distribute list. */
struct distribute *distribute_lookup(struct distribute_ctx *ctx,
				     const char *ifname)
{
	struct distribute key;
	struct distribute *dist;

	/* temporary reference */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_DISTRIBUTE_IFNAME, ifname) : NULL;

	dist = hash_lookup(ctx->disthash, &key);

	if (key.ifname)
		XFREE(MTYPE_DISTRIBUTE_IFNAME, key.ifname);

	return dist;
}

void distribute_list_add_hook(struct distribute_ctx *ctx,
			      void (*func)(struct distribute_ctx *ctx,
					   struct distribute *))
{
	ctx->distribute_add_hook = func;
}

void distribute_list_delete_hook(struct distribute_ctx *ctx,
				 void (*func)(struct distribute_ctx *ctx,
					      struct distribute *))
{
	ctx->distribute_delete_hook = func;
}

static void *distribute_hash_alloc(struct distribute *arg)
{
	struct distribute *dist;

	dist = distribute_new();
	if (arg->ifname)
		dist->ifname = XSTRDUP(MTYPE_DISTRIBUTE_IFNAME, arg->ifname);
	else
		dist->ifname = NULL;
	return dist;
}

/* Make new distribute list and push into hash. */
static struct distribute *distribute_get(struct distribute_ctx *ctx,
					 const char *ifname)
{
	struct distribute key;
	struct distribute *ret;

	/* temporary reference */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_DISTRIBUTE_IFNAME, ifname) : NULL;

	ret = hash_get(ctx->disthash, &key,
		       (void *(*)(void *))distribute_hash_alloc);

	if (key.ifname)
		XFREE(MTYPE_DISTRIBUTE_IFNAME, key.ifname);

	return ret;
}

static unsigned int distribute_hash_make(void *arg)
{
	const struct distribute *dist = arg;

	return dist->ifname ? string_hash_make(dist->ifname) : 0;
}

/* If two distribute-list have same value then return 1 else return
   0. This function is used by hash package. */
static bool distribute_cmp(const struct distribute *dist1,
			  const struct distribute *dist2)
{
	if (dist1->ifname && dist2->ifname)
		if (strcmp(dist1->ifname, dist2->ifname) == 0)
			return true;
	if (!dist1->ifname && !dist2->ifname)
		return true;
	return false;
}

/* Set access-list name to the distribute list. */
static void distribute_list_set(struct distribute_ctx *ctx,
				const char *ifname, enum distribute_type type,
				const char *alist_name)
{
	struct distribute *dist;

	dist = distribute_get(ctx, ifname);

	if (dist->list[type])
		XFREE(MTYPE_DISTRIBUTE_NAME, dist->list[type]);
	dist->list[type] = XSTRDUP(MTYPE_DISTRIBUTE_NAME, alist_name);

	/* Apply this distribute-list to the interface. */
	(ctx->distribute_add_hook)(ctx, dist);
}

/* Unset distribute-list.  If matched distribute-list exist then
   return 1. */
static int distribute_list_unset(struct distribute_ctx *ctx,
				 const char *ifname,
				 enum distribute_type type,
				 const char *alist_name)
{
	struct distribute *dist;

	dist = distribute_lookup(ctx, ifname);
	if (!dist)
		return 0;

	if (!dist->list[type])
		return 0;
	if (strcmp(dist->list[type], alist_name) != 0)
		return 0;

	XFREE(MTYPE_DISTRIBUTE_NAME, dist->list[type]);
	dist->list[type] = NULL;

	/* Apply this distribute-list to the interface. */
	(ctx->distribute_delete_hook)(ctx, dist);

	/* If all dist are NULL, then free distribute list. */
	distribute_free_if_empty(ctx, dist);
	return 1;
}

/* Set access-list name to the distribute list. */
static void distribute_list_prefix_set(struct distribute_ctx *ctx,
				       const char *ifname,
				       enum distribute_type type,
				       const char *plist_name)
{
	struct distribute *dist;

	dist = distribute_get(ctx, ifname);

	if (dist->prefix[type])
		XFREE(MTYPE_DISTRIBUTE_NAME, dist->prefix[type]);
	dist->prefix[type] = XSTRDUP(MTYPE_DISTRIBUTE_NAME, plist_name);

	/* Apply this distribute-list to the interface. */
	(ctx->distribute_add_hook)(ctx, dist);
}

/* Unset distribute-list.  If matched distribute-list exist then
   return 1. */
static int distribute_list_prefix_unset(struct distribute_ctx *ctx,
					const char *ifname,
					enum distribute_type type,
					const char *plist_name)
{
	struct distribute *dist;

	dist = distribute_lookup(ctx, ifname);
	if (!dist)
		return 0;

	if (!dist->prefix[type])
		return 0;
	if (strcmp(dist->prefix[type], plist_name) != 0)
		return 0;

	XFREE(MTYPE_DISTRIBUTE_NAME, dist->prefix[type]);
	dist->prefix[type] = NULL;

	/* Apply this distribute-list to the interface. */
	(ctx->distribute_delete_hook)(ctx, dist);

	/* If all dist are NULL, then free distribute list. */
	distribute_free_if_empty(ctx, dist);
	return 1;
}

DEFUN (distribute_list,
       distribute_list_cmd,
       "distribute-list [prefix] WORD <in|out> [WORD]",
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	int prefix = (argv[1]->type == WORD_TKN) ? 1 : 0;
	/* Check of distribute list type. */
	enum distribute_type type = argv[2 + prefix]->arg[0] == 'i'
					    ? DISTRIBUTE_V4_IN
					    : DISTRIBUTE_V4_OUT;

	/* Set appropriate function call */
	void (*distfn)(struct distribute_ctx *, const char *,
		       enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_set : &distribute_list_set;
	struct distribute_ctx *ctx =
		(struct distribute_ctx *)listnode_head(dist_ctx_list);

	/* if interface is present, get name */
	const char *ifname = NULL;
	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	/* Get interface name corresponding distribute list. */
	distfn(ctx, ifname, type, argv[1 + prefix]->arg);

	return CMD_SUCCESS;
}

DEFUN (ipv6_distribute_list,
       ipv6_distribute_list_cmd,
       "ipv6 distribute-list [prefix] WORD <in|out> [WORD]",
       "IPv6\n"
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	int prefix = (argv[2]->type == WORD_TKN) ? 1 : 0;
	/* Check of distribute list type. */
	enum distribute_type type = argv[3 + prefix]->arg[0] == 'i'
					    ? DISTRIBUTE_V6_IN
					    : DISTRIBUTE_V6_OUT;

	/* Set appropriate function call */
	void (*distfn)(struct distribute_ctx *, const char *,
		       enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_set : &distribute_list_set;
	struct distribute_ctx *ctx = listnode_head(dist_ctx_list);

	/* if interface is present, get name */
	const char *ifname = NULL;
	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	/* Get interface name corresponding distribute list. */
	distfn(ctx, ifname, type, argv[2 + prefix]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_distribute_list,
       no_distribute_list_cmd,
       "no distribute-list [prefix] WORD <in|out> [WORD]",
       NO_STR
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	int prefix = (argv[2]->type == WORD_TKN) ? 1 : 0;
	int idx_alname = 2 + prefix;
	int idx_disttype = idx_alname + 1;
	enum distribute_type type =
		argv[idx_disttype]->arg[0] == 'i' ?
		DISTRIBUTE_V4_IN : DISTRIBUTE_V4_OUT;

	/* Set appropriate function call */
	int (*distfn)(struct distribute_ctx *, const char *,
		       enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_unset : &distribute_list_unset;
	struct distribute_ctx *ctx = listnode_head(dist_ctx_list);

	/* if interface is present, get name */
	const char *ifname = NULL;
	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;
	/* Get interface name corresponding distribute list. */
	int ret = distfn(ctx, ifname, type, argv[2 + prefix]->arg);

	if (!ret) {
		vty_out(vty, "distribute list doesn't exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_ipv6_distribute_list,
       no_ipv6_distribute_list_cmd,
       "no ipv6 distribute-list [prefix] WORD <in|out> [WORD]",
       NO_STR
       "IPv6\n"
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	int prefix = (argv[3]->type == WORD_TKN) ? 1 : 0;
	int idx_alname = 3 + prefix;
	int idx_disttype = idx_alname + 1;

	enum distribute_type type =
		argv[idx_disttype]->arg[0] == 'i' ?
		DISTRIBUTE_V6_IN : DISTRIBUTE_V6_OUT;
	struct distribute_ctx *ctx = listnode_head(dist_ctx_list);

	/* Set appropriate function call */
	int (*distfn)(struct distribute_ctx *, const char *,
		       enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_unset : &distribute_list_unset;

	/* if interface is present, get name */
	const char *ifname = NULL;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;
	/* Get interface name corresponding distribute list. */
	int ret = distfn(ctx, ifname, type, argv[3 + prefix]->arg);

	if (!ret) {
		vty_out(vty, "distribute list doesn't exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

static int distribute_print(struct vty *vty, char *tab[], int is_prefix,
			    enum distribute_type type, int has_print)
{
	if (tab[type]) {
		vty_out(vty, "%s %s%s", has_print ? "," : "",
			is_prefix ? "(prefix-list) " : "", tab[type]);
		return 1;
	}
	return has_print;
}

int config_show_distribute(struct vty *vty, struct distribute_ctx *dist_ctxt)
{
	unsigned int i;
	int has_print = 0;
	struct hash_bucket *mp;
	struct distribute *dist;

	/* Output filter configuration. */
	dist = distribute_lookup(dist_ctxt, NULL);
	vty_out(vty, "  Outgoing update filter list for all interface is");
	has_print = 0;
	if (dist) {
		has_print = distribute_print(vty, dist->list, 0,
					     DISTRIBUTE_V4_OUT, has_print);
		has_print = distribute_print(vty, dist->prefix, 1,
					     DISTRIBUTE_V4_OUT, has_print);
		has_print = distribute_print(vty, dist->list, 0,
					     DISTRIBUTE_V6_OUT, has_print);
		has_print = distribute_print(vty, dist->prefix, 1,
					     DISTRIBUTE_V6_OUT, has_print);
	}
	if (has_print)
		vty_out(vty, "\n");
	else
		vty_out(vty, " not set\n");

	for (i = 0; i < dist_ctxt->disthash->size; i++)
		for (mp = dist_ctxt->disthash->index[i]; mp; mp = mp->next) {
			dist = mp->data;
			if (dist->ifname) {
				vty_out(vty, "    %s filtered by",
					dist->ifname);
				has_print = 0;
				has_print = distribute_print(vty, dist->list, 0,
							     DISTRIBUTE_V4_OUT,
							     has_print);
				has_print = distribute_print(
					vty, dist->prefix, 1, DISTRIBUTE_V4_OUT,
					has_print);
				has_print = distribute_print(vty, dist->list, 0,
							     DISTRIBUTE_V6_OUT,
							     has_print);
				has_print = distribute_print(
					vty, dist->prefix, 1, DISTRIBUTE_V6_OUT,
					has_print);
				if (has_print)
					vty_out(vty, "\n");
				else
					vty_out(vty, " nothing\n");
			}
		}


	/* Input filter configuration. */
	dist = distribute_lookup(dist_ctxt, NULL);
	vty_out(vty, "  Incoming update filter list for all interface is");
	has_print = 0;
	if (dist) {
		has_print = distribute_print(vty, dist->list, 0,
					     DISTRIBUTE_V4_IN, has_print);
		has_print = distribute_print(vty, dist->prefix, 1,
					     DISTRIBUTE_V4_IN, has_print);
		has_print = distribute_print(vty, dist->list, 0,
					     DISTRIBUTE_V6_IN, has_print);
		has_print = distribute_print(vty, dist->prefix, 1,
					     DISTRIBUTE_V6_IN, has_print);
	}
	if (has_print)
		vty_out(vty, "\n");
	else
		vty_out(vty, " not set\n");

	for (i = 0; i < dist_ctxt->disthash->size; i++)
		for (mp = dist_ctxt->disthash->index[i]; mp; mp = mp->next) {
			dist = mp->data;
			if (dist->ifname) {
				vty_out(vty, "    %s filtered by",
					dist->ifname);
				has_print = 0;
				has_print = distribute_print(vty, dist->list, 0,
							     DISTRIBUTE_V4_IN,
							     has_print);
				has_print = distribute_print(
					vty, dist->prefix, 1, DISTRIBUTE_V4_IN,
					has_print);
				has_print = distribute_print(vty, dist->list, 0,
							     DISTRIBUTE_V6_IN,
							     has_print);
				has_print = distribute_print(
					vty, dist->prefix, 1, DISTRIBUTE_V6_IN,
					has_print);
				if (has_print)
					vty_out(vty, "\n");
				else
					vty_out(vty, " nothing\n");
			}
		}
	return 0;
}

/* Configuration write function. */
int config_write_distribute(struct vty *vty,
			    struct distribute_ctx *dist_ctxt)
{
	unsigned int i;
	int j;
	int output, v6;
	struct hash_bucket *mp;
	int write = 0;

	for (i = 0; i < dist_ctxt->disthash->size; i++)
		for (mp = dist_ctxt->disthash->index[i]; mp; mp = mp->next) {
			struct distribute *dist;

			dist = mp->data;

			for (j = 0; j < DISTRIBUTE_MAX; j++)
				if (dist->list[j]) {
					output = j == DISTRIBUTE_V4_OUT
						 || j == DISTRIBUTE_V6_OUT;
					v6 = j == DISTRIBUTE_V6_IN
					     || j == DISTRIBUTE_V6_OUT;
					vty_out(vty,
						" %sdistribute-list %s %s %s\n",
						v6 ? "ipv6 " : "",
						dist->list[j],
						output ? "out" : "in",
						dist->ifname ? dist->ifname
							     : "");
					write++;
				}

			for (j = 0; j < DISTRIBUTE_MAX; j++)
				if (dist->prefix[j]) {
					output = j == DISTRIBUTE_V4_OUT
						 || j == DISTRIBUTE_V6_OUT;
					v6 = j == DISTRIBUTE_V6_IN
					     || j == DISTRIBUTE_V6_OUT;
					vty_out(vty,
						" %sdistribute-list prefix %s %s %s\n",
						v6 ? "ipv6 " : "",
						dist->prefix[j],
						output ? "out" : "in",
						dist->ifname ? dist->ifname
							     : "");
					write++;
				}
		}
	return write;
}

void distribute_list_delete(struct distribute_ctx **ctx)
{
	if ((*ctx)->disthash) {
		hash_clean((*ctx)->disthash, (void (*)(void *))distribute_free);
	}
	if (!dist_ctx_list)
		dist_ctx_list = list_new();
	listnode_delete(dist_ctx_list, *ctx);
	if (list_isempty(dist_ctx_list))
		list_delete(&dist_ctx_list);
	XFREE(MTYPE_DISTRIBUTE_CTX, (*ctx));
}

/* Initialize distribute list container */
struct distribute_ctx *distribute_list_ctx_create(struct vrf *vrf)
{
	struct distribute_ctx *ctx;

	ctx = XCALLOC(MTYPE_DISTRIBUTE_CTX, sizeof(struct distribute_ctx));
	ctx->vrf = vrf;
	ctx->disthash = hash_create(
		distribute_hash_make,
		(bool (*)(const void *, const void *))distribute_cmp, NULL);
	if (!dist_ctx_list)
		dist_ctx_list = list_new();
	listnode_add(dist_ctx_list, ctx);
	return ctx;
}

/* Initialize distribute list vty commands */
void distribute_list_init(int node)
{
	/* vtysh command-extraction doesn't grok install_element(node, ) */
	if (node == RIP_NODE) {
		install_element(RIP_NODE, &distribute_list_cmd);
		install_element(RIP_NODE, &no_distribute_list_cmd);
	} else if (node == RIPNG_NODE) {
		install_element(RIPNG_NODE, &distribute_list_cmd);
		install_element(RIPNG_NODE, &no_distribute_list_cmd);
		/* install v6 */
		install_element(RIPNG_NODE, &ipv6_distribute_list_cmd);
		install_element(RIPNG_NODE, &no_ipv6_distribute_list_cmd);
	}

	/* TODO: install v4 syntax command for v6 only protocols. */
	/* if (node == RIPNG_NODE) {
	 *   install_element (node, &ipv6_as_v4_distribute_list_all_cmd);
	 *   install_element (node, &no_ipv6_as_v4_distribute_list_all_cmd);
	 *   install_element (node, &ipv6_as_v4_distribute_list_cmd);
	 *   install_element (node, &no_ipv6_as_v4_distribute_list_cmd);
	 *   install_element (node, &ipv6_as_v4_distribute_list_prefix_all_cmd);
	 *   install_element (node,
	 &no_ipv6_as_v4_distribute_list_prefix_all_cmd);
	 *   install_element (node, &ipv6_as_v4_distribute_list_prefix_cmd);
	 *   install_element (node, &no_ipv6_as_v4_distribute_list_prefix_cmd);
	   }*/
}
