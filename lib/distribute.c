// SPDX-License-Identifier: GPL-2.0-or-later
/* Distribute list functions
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "filter.h"
#include "command.h"
#include "distribute.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_CTX, "Distribute ctx");
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE, "Distribute list");
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_IFNAME, "Dist-list ifname");
DEFINE_MTYPE_STATIC(LIB, DISTRIBUTE_NAME, "Dist-list name");

static struct distribute *distribute_new(void)
{
	return XCALLOC(MTYPE_DISTRIBUTE, sizeof(struct distribute));
}

/* Free distribute object. */
static void distribute_free(struct distribute *dist)
{
	int i = 0;

	XFREE(MTYPE_DISTRIBUTE_IFNAME, dist->ifname);

	for (i = 0; i < DISTRIBUTE_MAX; i++) {
		XFREE(MTYPE_DISTRIBUTE_NAME, dist->list[i]);
	}

	for (i = 0; i < DISTRIBUTE_MAX; i++) {
		XFREE(MTYPE_DISTRIBUTE_NAME, dist->prefix[i]);
	}

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

	XFREE(MTYPE_DISTRIBUTE_IFNAME, key.ifname);

	return ret;
}

static unsigned int distribute_hash_make(const void *arg)
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

	/* Apply this distribute-list to the interface. */
	(ctx->distribute_delete_hook)(ctx, dist);

	/* If all dist are NULL, then free distribute list. */
	distribute_free_if_empty(ctx, dist);
	return 1;
}

static enum distribute_type distribute_direction(const char *dir, bool v4)
{
	if (dir[0] == 'i') {
		if (v4)
			return DISTRIBUTE_V4_IN;
		else
			return DISTRIBUTE_V6_IN;
	} else if (dir[0] == 'o') {
		if (v4)
			return DISTRIBUTE_V4_OUT;
		else
			return DISTRIBUTE_V6_OUT;
	}

	assert(!"Expecting in or out only, fix your code");

	__builtin_unreachable();
}

int distribute_list_parser(struct distribute_ctx *ctx, bool prefix, bool v4,
			   const char *dir, const char *list, const char *ifname)
{
	enum distribute_type type = distribute_direction(dir, v4);

	void (*distfn)(struct distribute_ctx *, const char *,
		       enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_set : &distribute_list_set;

	distfn(ctx, ifname, type, list);

	return CMD_SUCCESS;
}


int distribute_list_no_parser(struct distribute_ctx *ctx, struct vty *vty,
			      bool prefix, bool v4, const char *dir,
			      const char *list, const char *ifname)
{
	enum distribute_type type = distribute_direction(dir, v4);
	int ret;

	int (*distfn)(struct distribute_ctx *, const char *,
		      enum distribute_type, const char *) =
		prefix ? &distribute_list_prefix_unset : &distribute_list_unset;


	ret = distfn(ctx, ifname, type, list);
	if (!ret) {
		if (vty)
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

/* ---------- */
/* Northbound */
/* ---------- */

int group_distribute_list_create_helper(
	struct nb_cb_create_args *args, struct distribute_ctx *ctx)
{
	nb_running_set_entry(args->dnode, ctx);
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distribute-lists/distribute-list/{in,out}/{access,prefix}-list
 */

int group_distribute_list_destroy(struct nb_cb_destroy_args *args)
{
	nb_running_unset_entry(args->dnode);
	return NB_OK;
}

static int distribute_list_leaf_update(const struct lyd_node *dnode,
				       int ip_version, bool no)
{
	struct distribute_ctx *ctx;
	struct lyd_node *dir_node = lyd_parent(dnode);
	struct lyd_node_inner *list_node = dir_node->parent;
	struct lyd_node *intf_key = list_node->child;
	bool ipv4 = ip_version == 4 ? true : false;
	bool prefix;

	ctx = nb_running_get_entry_non_rec(&list_node->node, NULL, false);

	prefix = dnode->schema->name[0] == 'p' ? true : false;
	if (no)
		distribute_list_no_parser(ctx, NULL, prefix, ipv4,
					  dir_node->schema->name,
					  lyd_get_value(dnode),
					  lyd_get_value(intf_key));
	else
		distribute_list_parser(ctx, prefix, ipv4,
				       dir_node->schema->name,
				       lyd_get_value(dnode),
				       lyd_get_value(intf_key));
	return NB_OK;
}

static int distribute_list_leaf_modify(struct nb_cb_modify_args *args,
				       int ip_version)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return distribute_list_leaf_update(args->dnode, ip_version, false);
}

static int distribute_list_leaf_destroy(struct nb_cb_destroy_args *args,
					int ip_version)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return distribute_list_leaf_update(args->dnode, ip_version, true);
}

int group_distribute_list_ipv4_modify(struct nb_cb_modify_args *args)
{
	return distribute_list_leaf_modify(args, 4);
}
int group_distribute_list_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	return distribute_list_leaf_destroy(args, 4);
}
int group_distribute_list_ipv6_modify(struct nb_cb_modify_args *args)
{
	return distribute_list_leaf_modify(args, 6);
}
int group_distribute_list_ipv6_destroy(struct nb_cb_destroy_args *args)
{
	return distribute_list_leaf_destroy(args, 6);
}

static int distribute_list_leaf_cli_show(struct vty *vty,
					 const struct lyd_node *dnode,
					 int ip_version)
{
	struct lyd_node *dir_node = lyd_parent(dnode);
	struct lyd_node_inner *list_node = dir_node->parent;
	struct lyd_node *intf_key = list_node->child;
	bool ipv6 = ip_version == 6 ? true : false;
	bool prefix;

	prefix = dnode->schema->name[0] == 'p' ? true : false;
	vty_out(vty,
		" %sdistribute-list %s%s %s %s\n",
		ipv6 ? "ipv6 " : "",
		prefix ? "prefix " : "",
		lyd_get_value(dnode),
		dir_node->schema->name,
		lyd_get_value(intf_key));

	return NB_OK;
}

void group_distribute_list_ipv4_cli_show(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults)
{
	distribute_list_leaf_cli_show(vty, dnode, 4);
}
void group_distribute_list_ipv6_cli_show(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults)
{
	distribute_list_leaf_cli_show(vty, dnode, 6);
}

/* ------------- */
/* Setup/Cleanup */
/* ------------- */

void distribute_list_delete(struct distribute_ctx **ctx)
{
	hash_clean_and_free(&(*ctx)->disthash,
			    (void (*)(void *))distribute_free);

	XFREE(MTYPE_DISTRIBUTE_CTX, (*ctx));
}

/* Initialize distribute list container */
struct distribute_ctx *distribute_list_ctx_create(struct vrf *vrf)
{
	struct distribute_ctx *ctx;

	ctx = XCALLOC(MTYPE_DISTRIBUTE_CTX, sizeof(struct distribute_ctx));
	ctx->vrf = vrf;
	ctx->disthash =
		hash_create(distribute_hash_make,
			    (bool (*)(const void *, const void *))distribute_cmp,
			    NULL);
	return ctx;
}
