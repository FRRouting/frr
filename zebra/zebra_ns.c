// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra NS Routines
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 * Copyright (C) 2017/2018 6WIND
 */
#include "zebra.h"

#include "lib/ns.h"
#include "lib/vrf.h"
#include "lib/prefix.h"
#include "lib/memory.h"

#include "zebra_ns.h"
#include "zebra_vrf.h"
#include "rt.h"
#include "zebra_vxlan.h"
#include "debug.h"
#include "zebra_netns_notify.h"
#include "zebra_netns_id.h"
#include "zebra_pbr.h"
#include "zebra_tc.h"
#include "rib.h"
#include "table_manager.h"
#include "zebra_errors.h"
#include "zebra_dplane.h"

extern struct zebra_privs_t zserv_privs;

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_NS, "Zebra Name Space");
DEFINE_MTYPE_STATIC(ZEBRA, ZNS_IFP, "Zebra NS Ifp");

static int ifp_tree_cmp(const struct ifp_tree_link *a, const struct ifp_tree_link *b);

DECLARE_RBTREE_UNIQ(ifp_tree, struct ifp_tree_link, link, ifp_tree_cmp);

static struct zebra_ns *dzns;

static int ifp_tree_cmp(const struct ifp_tree_link *a, const struct ifp_tree_link *b)
{
	return (a->ifindex - b->ifindex);
}

/*
 * Link an ifp into its parent NS
 */
void zebra_ns_link_ifp(struct zebra_ns *zns, struct interface *ifp)
{
	struct zebra_if *zif;
	struct ifp_tree_link *link, tlink = {};

	zif = ifp->info;
	assert(zif != NULL);

	if (zif->ns_tree_link) {
		assert(zif->ns_tree_link->zns == zns);
		assert(zif->ns_tree_link->ifp == ifp);
		return;
	}

	/* Lookup first - already linked? */
	tlink.ifindex = ifp->ifindex;
	link = ifp_tree_find(&zns->ifp_tree, &tlink);
	if (link) {
		assert(link->ifp == ifp);
		return;
	}

	/* Allocate new linkage struct and add */
	link = XCALLOC(MTYPE_ZNS_IFP, sizeof(struct ifp_tree_link));
	link->ifp = ifp;
	link->ifindex = ifp->ifindex;
	link->zns = zns;

	ifp_tree_add(&zns->ifp_tree, link);

	zif->ns_tree_link = link;
}

/*
 * Unlink an ifp from its parent NS (probably because the ifp is being deleted)
 */
void zebra_ns_unlink_ifp(struct interface *ifp)
{
	struct zebra_if *zif;
	struct ifp_tree_link *link;
	struct zebra_ns *zns;

	zif = ifp->info;
	if (zif && zif->ns_tree_link) {
		link = zif->ns_tree_link;
		zns = link->zns;

		ifp_tree_del(&zns->ifp_tree, link);

		zif->ns_tree_link = NULL;

		XFREE(MTYPE_ZNS_IFP, link);
	}
}

/*
 * ifp lookup apis
 */
struct interface *zebra_ns_lookup_ifp(struct zebra_ns *zns, uint32_t ifindex)
{
	struct interface *ifp = NULL;
	struct ifp_tree_link *link, tlink = {};

	/* Init temp struct for lookup */
	tlink.ifindex = ifindex;

	link = ifp_tree_find(&zns->ifp_tree, &tlink);
	if (link)
		ifp = link->ifp;

	return ifp;
}

static int lookup_ifp_name_cb(struct interface *ifp, void *arg);

struct ifp_name_ctx {
	const char *ifname;
	struct interface *ifp;
};

struct interface *zebra_ns_lookup_ifp_name(struct zebra_ns *zns, const char *ifname)
{
	struct ifp_name_ctx ctx = {};

	/* Hand context struct into walker function for use in its callback */
	ctx.ifname = ifname;
	zebra_ns_ifp_walk(zns, lookup_ifp_name_cb, &ctx);

	return ctx.ifp;
}

static int lookup_ifp_name_cb(struct interface *ifp, void *arg)
{
	struct ifp_name_ctx *pctx = arg;

	if (strcmp(ifp->name, pctx->ifname) == 0) {
		pctx->ifp = ifp;
		return NS_WALK_STOP;
	}

	return NS_WALK_CONTINUE;
}

/* Iterate collection of ifps, calling application's callback. Callback uses
 * return semantics from lib/ns.h: return NS_WALK_STOP to stop the iteration.
 * Caller's 'arg' is included in each callback.
 */
int zebra_ns_ifp_walk(struct zebra_ns *zns,
		      int (*func)(struct interface *ifp, void *arg), void *arg)
{
	struct ifp_tree_link *link;
	int ret = NS_WALK_CONTINUE;

	frr_each (ifp_tree, &zns->ifp_tree, link) {
		ret = (func)(link->ifp, arg);
		if (ret == NS_WALK_STOP)
			break;
	}

	if (ret == NS_WALK_STOP)
		return NS_WALK_STOP;
	else
		return NS_WALK_CONTINUE;
}

/*
 * Walk all NSes, and all ifps for each NS.
 */
struct ns_ifp_walk_ctx {
	int (*func)(struct interface *ifp, void *arg);
	void *arg;
	int ret;
};

static int ns_ifp_walker(struct ns *ns, void *in_param, void **unused);

void zebra_ns_ifp_walk_all(int (*func)(struct interface *ifp, void *arg), void *arg)
{
	struct ns_ifp_walk_ctx ctx = {};

	ctx.func = func;
	ctx.arg = arg;

	ns_walk_func(ns_ifp_walker, &ctx, NULL);
}

static int ns_ifp_walker(struct ns *ns, void *in_param, void **unused)
{
	struct zebra_ns *zns;
	struct ns_ifp_walk_ctx *ctx = in_param;
	int ret = NS_WALK_CONTINUE;

	zns = ns->info;
	if (zns == NULL)
		goto done;

	ret = zebra_ns_ifp_walk(zns, ctx->func, ctx->arg);

done:

	return ret;
}

static int zebra_ns_disable_internal(struct zebra_ns *zns, bool complete);

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id)
{
	if (ns_id == NS_DEFAULT)
		return dzns;
	struct zebra_ns *info = (struct zebra_ns *)ns_info_lookup(ns_id);

	return (info == NULL) ? dzns : info;
}

static int zebra_ns_new(struct ns *ns)
{
	struct zebra_ns *zns;

	if (!ns)
		return -1;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (created)", ns->name, ns->ns_id);

	zns = XCALLOC(MTYPE_ZEBRA_NS, sizeof(struct zebra_ns));
	ns->info = zns;
	zns->ns = ns;
	zns->ns_id = ns->ns_id;

	/* Do any needed per-NS data structure allocation. */
	ifp_tree_init(&zns->ifp_tree);

	return 0;
}

static int zebra_ns_delete(struct ns *ns)
{
	struct zebra_ns *zns = (struct zebra_ns *)ns->info;
	struct zebra_if *zif;
	struct ifp_tree_link *link;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (deleted)", ns->name, ns->ns_id);
	if (!zns)
		return 0;

	/* Clean up ifp tree */
	while ((link = ifp_tree_pop(&zns->ifp_tree)) != NULL) {
		zif = link->ifp->info;

		zif->ns_tree_link = NULL;
		XFREE(MTYPE_ZNS_IFP, link);
	}

	XFREE(MTYPE_ZEBRA_NS, ns->info);
	return 0;
}

static int zebra_ns_enabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (enabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_enable(ns->ns_id, (void **)&zns);
}

int zebra_ns_disabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (disabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_disable_internal(zns, true);
}

void zebra_ns_startup_continue(struct zebra_dplane_ctx *ctx)
{
	struct zebra_ns *zns = zebra_ns_lookup(dplane_ctx_get_ns_id(ctx));
	enum zebra_dplane_startup_notifications spot;

	if (!zns) {
		zlog_err("%s: No Namespace associated with %u", __func__,
			 dplane_ctx_get_ns_id(ctx));
		return;
	}

	spot = dplane_ctx_get_startup_spot(ctx);

	switch (spot) {
	case ZEBRA_DPLANE_INTERFACES_READ:
		interface_list_tunneldump(zns);
		break;
	case ZEBRA_DPLANE_TUNNELS_READ:
		interface_list_second(zns);
		break;
	case ZEBRA_DPLANE_ADDRESSES_READ:
		route_read(zns);

		vlan_read(zns);
		kernel_read_pbr_rules(zns);
		kernel_read_tc_qdisc(zns);
		break;
	}
}

/* Do global enable actions - open sockets, read kernel config etc. */
int zebra_ns_enable(ns_id_t ns_id, void **info)
{
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

	zns->ns_id = ns_id;

	kernel_init(zns);
	zebra_dplane_ns_enable(zns, true);
	interface_list(zns);

	return 0;
}

/* Common handler for ns disable - this can be called during ns config,
 * or during zebra shutdown.
 */
static int zebra_ns_disable_internal(struct zebra_ns *zns, bool complete)
{
	zebra_dplane_ns_enable(zns, false /*Disable*/);

	kernel_terminate(zns, complete);

	zns->ns_id = NS_DEFAULT;

	return 0;
}

/* During zebra shutdown, do partial cleanup while the async dataplane
 * is still running.
 */
int zebra_ns_early_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;

	if (zns == NULL)
		return 0;

	zebra_ns_disable_internal(zns, false);
	return NS_WALK_CONTINUE;
}

/* During zebra shutdown, do kernel cleanup
 * netlink sockets, ..
 */
int zebra_ns_kernel_shutdown(struct ns *ns, void *param_in __attribute__((unused)),
			     void **param_out __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;

	if (zns == NULL)
		return NS_WALK_CONTINUE;

	kernel_terminate(zns, true);

	return NS_WALK_CONTINUE;
}

/* During zebra shutdown, do final cleanup
 * after all dataplane work is complete.
 */
int zebra_ns_final_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)))
{
	struct zebra_ns *zns = ns->info;

	if (zns == NULL)
		return NS_WALK_CONTINUE;

	zebra_ns_delete(ns);

	return NS_WALK_CONTINUE;
}

int zebra_ns_init(void)
{
	struct ns *default_ns;
	ns_id_t ns_id;
	ns_id_t ns_id_external;
	struct ns *ns;

	frr_with_privs(&zserv_privs) {
		ns_id = zebra_ns_id_get_default();
	}
	ns_id_external = ns_map_nsid_with_external(ns_id, true);
	ns_init_management(ns_id_external, ns_id);
	ns = ns_get_default();
	if (ns)
		ns->relative_default_ns = ns_id;

	default_ns = ns_lookup(NS_DEFAULT);
	if (!default_ns) {
		flog_err(EC_ZEBRA_NS_NO_DEFAULT,
			 "%s: failed to find default ns", __func__);
		exit(EXIT_FAILURE); /* This is non-recoverable */
	}

	/* Do any needed per-NS data structure allocation. */
	zebra_ns_new(default_ns);
	dzns = default_ns->info;

	/* Register zebra VRF callbacks, create and activate default VRF. */
	zebra_vrf_init();

	/* Default NS is activated */
	zebra_ns_enable(ns_id_external, (void **)&dzns);

	if (vrf_is_backend_netns()) {
		ns_add_hook(NS_NEW_HOOK, zebra_ns_new);
		ns_add_hook(NS_ENABLE_HOOK, zebra_ns_enabled);
		ns_add_hook(NS_DISABLE_HOOK, zebra_ns_disabled);
		ns_add_hook(NS_DELETE_HOOK, zebra_ns_delete);
		zebra_ns_notify_parse();
		zebra_ns_notify_init();
	}

	return 0;
}
