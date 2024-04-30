// SPDX-License-Identifier: GPL-2.0-or-later
/* route-map for interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
 * Copyright (C) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "hash.h"
#include "command.h"
#include "memory.h"
#include "if.h"
#include "if_rmap.h"
#include "northbound_cli.h"

#include "lib/if_rmap_clippy.c"

DEFINE_MTYPE_STATIC(LIB, IF_RMAP_CTX, "Interface route map container");
DEFINE_MTYPE_STATIC(LIB, IF_RMAP_CTX_NAME,
		    "Interface route map container name");
DEFINE_MTYPE_STATIC(LIB, IF_RMAP, "Interface route map");
DEFINE_MTYPE_STATIC(LIB, IF_RMAP_NAME, "I.f. route map name");

static struct if_rmap *if_rmap_new(void)
{
	struct if_rmap *new;

	new = XCALLOC(MTYPE_IF_RMAP, sizeof(struct if_rmap));

	return new;
}

static void if_rmap_free(struct if_rmap *if_rmap)
{
	char *no_const_ifname = (char *)if_rmap->ifname;

	XFREE(MTYPE_IF_RMAP_NAME, no_const_ifname);

	XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_IN]);
	XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_OUT]);

	XFREE(MTYPE_IF_RMAP, if_rmap);
}

struct if_rmap *if_rmap_lookup(struct if_rmap_ctx *ctx, const char *ifname)
{
	struct if_rmap key = {.ifname = ifname};
	struct if_rmap *if_rmap;

	if_rmap = hash_lookup(ctx->ifrmaphash, &key);

	return if_rmap;
}

void if_rmap_hook_add(struct if_rmap_ctx *ctx,
		      void (*func)(struct if_rmap_ctx *ctx, struct if_rmap *))
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
	struct if_rmap key = {.ifname = ifname};
	struct if_rmap *ret;

	ret = hash_get(ctx->ifrmaphash, &key, if_rmap_hash_alloc);

	return ret;
}

static unsigned int if_rmap_hash_make(const void *data)
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

static void if_rmap_set(struct if_rmap_ctx *ctx, const char *ifname,
			enum if_rmap_type type, const char *routemap_name)
{
	struct if_rmap *if_rmap = if_rmap_get(ctx, ifname);

	assert(type == IF_RMAP_IN || type == IF_RMAP_OUT);
	XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[type]);
	if_rmap->routemap[type] = XSTRDUP(MTYPE_IF_RMAP_NAME, routemap_name);

	if (ctx->if_rmap_add_hook)
		(ctx->if_rmap_add_hook)(ctx, if_rmap);
}

static void if_rmap_unset(struct if_rmap_ctx *ctx, const char *ifname,
			  enum if_rmap_type type)
{
	struct if_rmap *if_rmap = if_rmap_lookup(ctx, ifname);

	if (!if_rmap)
		return;

	assert(type == IF_RMAP_IN || type == IF_RMAP_OUT);
	if (!if_rmap->routemap[type])
		return;

	XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[type]);

	if (ctx->if_rmap_delete_hook)
		ctx->if_rmap_delete_hook(ctx, if_rmap);

	if (if_rmap->routemap[IF_RMAP_IN] == NULL &&
	    if_rmap->routemap[IF_RMAP_OUT] == NULL) {
		hash_release(ctx->ifrmaphash, if_rmap);
		if_rmap_free(if_rmap);
	}
}

static int if_route_map_handler(struct vty *vty, bool no, const char *dir,
				const char *other_dir, const char *ifname,
				const char *route_map)
{
	enum nb_operation op = no ? NB_OP_DESTROY : NB_OP_MODIFY;
	const struct lyd_node *dnode;
	char xpath[XPATH_MAXLEN];

	if (!no) {
		snprintf(
			xpath, sizeof(xpath),
			"./if-route-maps/if-route-map[interface='%s']/%s-route-map",
			ifname, dir);
	} else {
		/*
		 * If we are deleting the last policy for this interface,
		 * (i.e., no `in` or `out` policy). delete the interface list
		 * node instead.
		 */
		dnode = yang_dnode_get(vty->candidate_config->dnode,
				       VTY_CURR_XPATH);
		if (yang_dnode_existsf(
			    dnode,
			    "./if-route-maps/if-route-map[interface='%s']/%s-route-map",
			    ifname, other_dir)) {
			snprintf(
				xpath, sizeof(xpath),
				"./if-route-maps/if-route-map[interface='%s']/%s-route-map",
				ifname, dir);
		} else {
			/* both dir will be empty so delete the list node */
			snprintf(xpath, sizeof(xpath),
				 "./if-route-maps/if-route-map[interface='%s']",
				 ifname);
		}
	}
	nb_cli_enqueue_change(vty, xpath, op, route_map);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(if_ipv4_route_map, if_ipv4_route_map_cmd,
	   "route-map ROUTE-MAP <in$in|out> IFNAME",
	   "Route map set\n"
	   "Route map name\n"
	   "Route map set for input filtering\n"
	   "Route map set for output filtering\n" INTERFACE_STR)
{
	const char *dir = in ? "in" : "out";
	const char *other_dir = in ? "out" : "in";

	return if_route_map_handler(vty, false, dir, other_dir, ifname,
				    route_map);
}

DEFPY_YANG(no_if_ipv4_route_map, no_if_ipv4_route_map_cmd,
	   "no route-map [ROUTE-MAP] <in$in|out> IFNAME",
	   NO_STR
	   "Route map set\n"
	   "Route map name\n"
	   "Route map set for input filtering\n"
	   "Route map set for output filtering\n" INTERFACE_STR)
{
	const char *dir = in ? "in" : "out";
	const char *other_dir = in ? "out" : "in";

	return if_route_map_handler(vty, true, dir, other_dir, ifname,
				    route_map);
}

/*
 * CLI infra requires new handlers for ripngd
 */
DEFPY_YANG(if_ipv6_route_map, if_ipv6_route_map_cmd,
	   "route-map ROUTE-MAP <in$in|out> IFNAME",
	   "Route map set\n"
	   "Route map name\n"
	   "Route map set for input filtering\n"
	   "Route map set for output filtering\n" INTERFACE_STR)
{
	const char *dir = in ? "in" : "out";
	const char *other_dir = in ? "out" : "in";

	return if_route_map_handler(vty, false, dir, other_dir, ifname,
				    route_map);
}

DEFPY_YANG(no_if_ipv6_route_map, no_if_ipv6_route_map_cmd,
	   "no route-map [ROUTE-MAP] <in$in|out> IFNAME",
	   NO_STR
	   "Route map set\n"
	   "Route map name\n"
	   "Route map set for input filtering\n"
	   "Route map set for output filtering\n" INTERFACE_STR)
{
	const char *dir = in ? "in" : "out";
	const char *other_dir = in ? "out" : "in";

	return if_route_map_handler(vty, true, dir, other_dir, ifname,
				    route_map);
}

void cli_show_if_route_map(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (yang_dnode_exists(dnode, "in-route-map"))
		vty_out(vty, " route-map %s in %s\n",
			yang_dnode_get_string(dnode, "in-route-map"),
			yang_dnode_get_string(dnode, "interface"));
	if (yang_dnode_exists(dnode, "out-route-map"))
		vty_out(vty, " route-map %s out %s\n",
			yang_dnode_get_string(dnode, "out-route-map"),
			yang_dnode_get_string(dnode, "interface"));
}

void if_rmap_yang_modify_cb(struct if_rmap_ctx *ctx,
			    const struct lyd_node *dnode,
			    enum if_rmap_type type, bool del)
{

	const char *mapname = yang_dnode_get_string(dnode, NULL);
	const char *ifname = yang_dnode_get_string(dnode, "../interface");

	if (del)
		if_rmap_unset(ctx, ifname, type);
	else
		if_rmap_set(ctx, ifname, type, mapname);
}

void if_rmap_yang_destroy_cb(struct if_rmap_ctx *ctx,
			     const struct lyd_node *dnode)
{
	const char *ifname = yang_dnode_get_string(dnode, "interface");
	if_rmap_unset(ctx, ifname, IF_RMAP_IN);
	if_rmap_unset(ctx, ifname, IF_RMAP_OUT);
}

void if_rmap_ctx_delete(struct if_rmap_ctx *ctx)
{
	hash_clean_and_free(&ctx->ifrmaphash, (void (*)(void *))if_rmap_free);
	XFREE(MTYPE_IF_RMAP_CTX_NAME, ctx->name);
	XFREE(MTYPE_IF_RMAP_CTX, ctx);
}

/* name is optional: either vrf name, or other */
struct if_rmap_ctx *if_rmap_ctx_create(const char *name)
{
	struct if_rmap_ctx *ctx;

	ctx = XCALLOC(MTYPE_IF_RMAP_CTX, sizeof(struct if_rmap_ctx));

	ctx->name = XSTRDUP(MTYPE_IF_RMAP_CTX_NAME, name);
	ctx->ifrmaphash =
		hash_create_size(4, if_rmap_hash_make, if_rmap_hash_cmp,
				 "Interface Route-Map Hash");
	return ctx;
}

void if_rmap_init(int node)
{
	if (node == RIP_NODE) {
		install_element(RIP_NODE, &if_ipv4_route_map_cmd);
		install_element(RIP_NODE, &no_if_ipv4_route_map_cmd);
	} else if (node == RIPNG_NODE) {
		install_element(RIPNG_NODE, &if_ipv6_route_map_cmd);
		install_element(RIPNG_NODE, &no_if_ipv6_route_map_cmd);
	}
}

void if_rmap_terminate(void)
{
}
