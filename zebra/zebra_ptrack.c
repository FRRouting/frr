// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra prefix tracking (ptrack) code
 *
 * Copyright (C) 2026 Nokia
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "typesafe.h"
#include "vrf.h"
#include "log.h"
#include "hook.h"
#include "stream.h"
#include "frrevent.h"
#include "zclient.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_ptrack.h"

DEFINE_MTYPE_STATIC(ZEBRA, PTRACK_VRF_CTX, "Ptrack VRF context");
DEFINE_MTYPE_STATIC(ZEBRA, PTRACK_VRF_CLIENT, "Ptrack per-VRF client");
DEFINE_MTYPE_STATIC(ZEBRA, PTRACK_ENTRY, "Ptrack prefix entry");
DEFINE_MTYPE_STATIC(ZEBRA, PTRACK_CLIENT, "Ptrack per-prefix client");
DEFINE_MTYPE_STATIC(ZEBRA, PTRACK_COOKIE, "Ptrack cookie");

/* Cookies per prefix per client */
PREDECL_RBTREE_UNIQ(ptrack_cookies);

struct ptrack_cookie {
	struct ptrack_cookies_item item;

	uint64_t cookie;
};

static int ptrack_cookie_cmp(const struct ptrack_cookie *a,
			     const struct ptrack_cookie *b)
{
	return numcmp(a->cookie, b->cookie);
}

DECLARE_RBTREE_UNIQ(ptrack_cookies, struct ptrack_cookie, item,
		    ptrack_cookie_cmp);

/* Client(s) subscribed per prefix */
PREDECL_RBTREE_UNIQ(ptrack_clients);

struct ptrack_client {
	struct ptrack_clients_item item;

	struct zserv *client;
	struct ptrack_cookies_head cookies;
};

static int ptrack_client_cmp(const struct ptrack_client *a,
			     const struct ptrack_client *b)
{
	return numcmp((uintptr_t)a->client, (uintptr_t)b->client);
}

DECLARE_RBTREE_UNIQ(ptrack_clients, struct ptrack_client, item,
		    ptrack_client_cmp);

/* Cookies of a client in a VRF, all its prefixes together, for the limit */
PREDECL_RBTREE_UNIQ(ptrack_vrf_clients);

struct ptrack_vrf_client {
	struct ptrack_vrf_clients_item item;

	struct zserv *client;
	uint32_t cookie_count;
};

static int ptrack_vrf_client_cmp(const struct ptrack_vrf_client *a,
				 const struct ptrack_vrf_client *b)
{
	return numcmp((uintptr_t)a->client, (uintptr_t)b->client);
}

DECLARE_RBTREE_UNIQ(ptrack_vrf_clients, struct ptrack_vrf_client, item,
		    ptrack_vrf_client_cmp);

/* All the VRF contexts, keyed by VRF name */
PREDECL_RBTREE_UNIQ(ptrack_registry);

struct ptrack_vrf_ctx {
	struct ptrack_registry_item item;

	char vrf_name[VRF_NAMSIZ];

	struct ptrack_vrf_clients_head vrf_clients;

	/* Only AFI_IP and AFI_IP6 are used */
	struct route_table *table[AFI_MAX];
};

static int ptrack_vrf_ctx_cmp(const struct ptrack_vrf_ctx *a,
			      const struct ptrack_vrf_ctx *b)
{
	return strcmp(a->vrf_name, b->vrf_name);
}

DECLARE_RBTREE_UNIQ(ptrack_registry, struct ptrack_vrf_ctx, item,
		    ptrack_vrf_ctx_cmp);

static struct ptrack_registry_head ptrack_registry;
static bool ptrack_held;
static struct event *t_ptrack_release_timer;

struct ptrack_entry {
	enum zapi_ptrack_state state;

	struct ptrack_clients_head clients;
};


static void ptrack_client_free(struct ptrack_client *pc)
{
	struct ptrack_cookie *pck;

	while ((pck = ptrack_cookies_pop(&pc->cookies)))
		XFREE(MTYPE_PTRACK_COOKIE, pck);

	ptrack_cookies_fini(&pc->cookies);
	XFREE(MTYPE_PTRACK_CLIENT, pc);
}

static void ptrack_entry_free(struct ptrack_entry *entry)
{
	struct ptrack_client *pc;

	while ((pc = ptrack_clients_pop(&entry->clients)))
		ptrack_client_free(pc);

	ptrack_clients_fini(&entry->clients);
	XFREE(MTYPE_PTRACK_ENTRY, entry);
}

static void ptrack_ctx_free(struct ptrack_vrf_ctx *ctx)
{
	struct ptrack_vrf_client *pvc;
	afi_t afi;

	ptrack_registry_del(&ptrack_registry, ctx);

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		if (!ctx->table[afi])
			continue;

		route_table_finish(ctx->table[afi]);
		ctx->table[afi] = NULL;
	}

	while ((pvc = ptrack_vrf_clients_pop(&ctx->vrf_clients)))
		XFREE(MTYPE_PTRACK_VRF_CLIENT, pvc);

	ptrack_vrf_clients_fini(&ctx->vrf_clients);
	XFREE(MTYPE_PTRACK_VRF_CTX, ctx);
}

static void ptrack_table_node_cleanup(struct route_table *table,
				      struct route_node *node)
{
	if (node->info) {
		ptrack_entry_free(node->info);
		node->info = NULL;
	}
}

struct ptrack_vrf_ctx *zebra_ptrack_ctx_lookup(const char *vrf_name)
{
	struct ptrack_vrf_ctx lookup;

	if (!vrf_name || strlen(vrf_name) >= sizeof(lookup.vrf_name))
		return NULL;

	strlcpy(lookup.vrf_name, vrf_name, sizeof(lookup.vrf_name));

	return ptrack_registry_find(&ptrack_registry, &lookup);
}

struct ptrack_vrf_ctx *zebra_ptrack_ctx_get(const char *vrf_name)
{
	struct ptrack_vrf_ctx *ctx;
	afi_t afi;

	if (!vrf_name || vrf_name[0] == '\0')
		return NULL;

	ctx = zebra_ptrack_ctx_lookup(vrf_name);
	if (ctx)
		return ctx;

	if (strlen(vrf_name) >= sizeof(ctx->vrf_name))
		return NULL;

	ctx = XCALLOC(MTYPE_PTRACK_VRF_CTX, sizeof(*ctx));
	strlcpy(ctx->vrf_name, vrf_name, sizeof(ctx->vrf_name));
	ptrack_vrf_clients_init(&ctx->vrf_clients);

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		ctx->table[afi] = route_table_init();
		ctx->table[afi]->cleanup = ptrack_table_node_cleanup;
	}

	ptrack_registry_add(&ptrack_registry, ctx);

	return ctx;
}

/* Number of cookies requested (duplicates ignored) */
static uint32_t ptrack_count_new_cookies(struct ptrack_client *pc,
					 const uint64_t *cookies, uint16_t count)
{
	struct ptrack_cookie lookup;
	uint32_t new_count = 0;
	uint16_t i, j;

	for (i = 0; i < count; i++) {
		lookup.cookie = cookies[i];
		if (pc && ptrack_cookies_find(&pc->cookies, &lookup))
			continue;

		for (j = 0; j < i; j++)
			if (cookies[j] == cookies[i])
				break;

		if (j == i)
			new_count++;
	}

	return new_count;
}

static struct ptrack_client *ptrack_client_find(struct ptrack_entry *entry,
						struct zserv *client)
{
	struct ptrack_client lookup;

	lookup.client = client;

	return ptrack_clients_find(&entry->clients, &lookup);
}

static struct ptrack_vrf_client *
ptrack_vrf_client_find(struct ptrack_vrf_ctx *ctx, struct zserv *client)
{
	struct ptrack_vrf_client lookup;

	lookup.client = client;

	return ptrack_vrf_clients_find(&ctx->vrf_clients, &lookup);
}

/* Add client cookies per prefix (check limit) */
enum zebra_ptrack_result
zebra_ptrack_add_cookies(struct ptrack_vrf_ctx *ctx, struct zserv *client,
			 const struct prefix *p, const uint64_t *cookies,
			 uint16_t count, struct ptrack_entry **entry)
{
	struct ptrack_entry *pe;
	struct ptrack_client *pc = NULL;
	struct ptrack_vrf_client *pvc;
	struct ptrack_cookie *pck;
	struct ptrack_cookie lookup;
	struct route_table *table;
	struct route_node *rn;
	struct prefix pfx;
	uint64_t total;
	afi_t afi;
	uint16_t i;

	*entry = NULL;

	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return ZEBRA_PTRACK_INVALID;

	table = ctx->table[afi];

	/* Mask Prefix */
	prefix_copy(&pfx, p);
	apply_mask(&pfx);

	/* Check threshold */
	rn = route_node_lookup(table, &pfx);
	pe = rn ? rn->info : NULL;
	if (pe)
		pc = ptrack_client_find(pe, client);

	total = ptrack_count_new_cookies(pc, cookies, count);
	if (rn)
		route_unlock_node(rn);

	if (count == 0) {
		*entry = pe;
		return ZEBRA_PTRACK_SUCCESS;
	}

	pvc = ptrack_vrf_client_find(ctx, client);
	total += pvc ? pvc->cookie_count : 0;
	if (total > ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT)
		return ZEBRA_PTRACK_LIMIT;

	rn = route_node_get(table, &pfx);
	if (!rn->info) {
		pe = XCALLOC(MTYPE_PTRACK_ENTRY, sizeof(*pe));
		pe->state = ZAPI_PTRACK_UNREACHABLE;
		ptrack_clients_init(&pe->clients);
		rn->info = pe;
		route_lock_node(rn);
	}
	pe = rn->info;

	pc = ptrack_client_find(pe, client);
	if (!pc) {
		pc = XCALLOC(MTYPE_PTRACK_CLIENT, sizeof(*pc));
		pc->client = client;
		ptrack_cookies_init(&pc->cookies);
		ptrack_clients_add(&pe->clients, pc);
	}

	if (!pvc) {
		pvc = XCALLOC(MTYPE_PTRACK_VRF_CLIENT, sizeof(*pvc));
		pvc->client = client;
		ptrack_vrf_clients_add(&ctx->vrf_clients, pvc);
	}

	for (i = 0; i < count; i++) {
		lookup.cookie = cookies[i];
		if (ptrack_cookies_find(&pc->cookies, &lookup))
			continue;

		pck = XCALLOC(MTYPE_PTRACK_COOKIE, sizeof(*pck));
		pck->cookie = cookies[i];
		ptrack_cookies_add(&pc->cookies, pck);
		pvc->cookie_count++;
	}

	route_unlock_node(rn);

	*entry = pe;

	return ZEBRA_PTRACK_SUCCESS;
}

/* Remove client cookies per prefix */
void zebra_ptrack_del_cookies(struct ptrack_vrf_ctx *ctx, struct zserv *client,
			      const struct prefix *p, const uint64_t *cookies,
			      uint16_t count)
{
	struct ptrack_entry *pe;
	struct ptrack_client *pc;
	struct ptrack_vrf_client *pvc;
	struct ptrack_cookie *pck;
	struct ptrack_cookie lookup;
	struct route_node *rn;
	struct prefix pfx;
	afi_t afi;
	uint16_t i;

	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	/* Mask Prefix */
	prefix_copy(&pfx, p);
	apply_mask(&pfx);

	rn = route_node_lookup(ctx->table[afi], &pfx);
	if (!rn)
		return;

	pe = rn->info;
	pc = pe ? ptrack_client_find(pe, client) : NULL;
	if (!pc) {
		route_unlock_node(rn);
		return;
	}

	pvc = ptrack_vrf_client_find(ctx, client);
	assert(pvc);

	for (i = 0; i < count; i++) {
		lookup.cookie = cookies[i];
		pck = ptrack_cookies_find(&pc->cookies, &lookup);
		if (!pck)
			continue;

		ptrack_cookies_del(&pc->cookies, pck);
		XFREE(MTYPE_PTRACK_COOKIE, pck);
		pvc->cookie_count--;
	}

	if (ptrack_cookies_count(&pc->cookies) == 0) {
		ptrack_clients_del(&pe->clients, pc);
		ptrack_client_free(pc);
	}

	if (ptrack_clients_count(&pe->clients) == 0) {
		ptrack_entry_free(pe);
		rn->info = NULL;
		route_unlock_node(rn);
	}

	if (pvc->cookie_count == 0) {
		ptrack_vrf_clients_del(&ctx->vrf_clients, pvc);
		XFREE(MTYPE_PTRACK_VRF_CLIENT, pvc);
	}

	route_unlock_node(rn);
}

/* Check entry of the prefix (masked) */
struct ptrack_entry *zebra_ptrack_entry_lookup(struct ptrack_vrf_ctx *ctx,
					       const struct prefix *p)
{
	struct route_node *rn;
	struct prefix pfx;
	afi_t afi;

	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return NULL;

	prefix_copy(&pfx, p);
	apply_mask(&pfx);

	rn = route_node_lookup(ctx->table[afi], &pfx);
	if (!rn)
		return NULL;

	/* The entry holds its own lock on the node */
	route_unlock_node(rn);

	return rn->info;
}

enum zapi_ptrack_state zebra_ptrack_entry_get_state(const struct ptrack_entry *entry)
{
	return entry->state;
}

void zebra_ptrack_entry_set_state(struct ptrack_entry *entry,
				  enum zapi_ptrack_state state)
{
	entry->state = state;
}

uint32_t zebra_ptrack_client_cookie_count(struct ptrack_vrf_ctx *ctx,
					  struct zserv *client)
{
	struct ptrack_vrf_client *pvc = ptrack_vrf_client_find(ctx, client);

	return pvc ? pvc->cookie_count : 0;
}

/* REACHABLE if VRF is enabled or the exact prefix has a non-removed route */
static enum zapi_ptrack_state ptrack_prefix_state(struct zebra_vrf *zvrf,
						  const struct prefix *p)
{
	enum zapi_ptrack_state state = ZAPI_PTRACK_UNREACHABLE;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;

	if (!vrf_is_enabled(zvrf->vrf))
		return state;

	table = zvrf->table[family2afi(p->family)][SAFI_UNICAST];
	if (!table)
		return state;

	rn = route_node_lookup(table, p);
	if (!rn)
		return state;

	RNODE_FOREACH_RE (rn, re) {
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			state = ZAPI_PTRACK_REACHABLE;
			break;
		}
	}

	route_unlock_node(rn);

	return state;
}

/* Send state update to client */
static bool ptrack_send_msg(struct zserv *client, const struct zapi_ptrack *api)
{
	struct stream *s;

	if (!zebra_rib_startup_done()) {
		ptrack_held = true;
		return false;
	}

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	if (zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, api)) {
		stream_free(s);
		return false;
	}

	zserv_send_message(client, s);

	return true;
}

/* Send prefix state, split into multiple messages if required */
static void ptrack_send_update(struct zserv *client, const char *vrf_name,
			       const struct prefix *p,
			       enum zapi_ptrack_state state,
			       const uint64_t *cookies, uint16_t count)
{
	struct zapi_ptrack api;
	size_t sent = 0;
	size_t n;

	strlcpy(api.vrf_name, vrf_name, sizeof(api.vrf_name));
	prefix_copy(&api.prefix, p);
	api.state = state;

	while (sent < count) {
		n = MIN((size_t)count - sent, (size_t)ZAPI_PTRACK_MAX_COOKIES);

		api.cookie_count = n;
		memcpy(api.cookies, cookies + sent, n * sizeof(*cookies));

		if (!ptrack_send_msg(client, &api))
			return;

		sent += n;
	}
}

/* Send prefix state to client for cookies on prefix */
static void ptrack_notify_client(struct ptrack_client *pc,
				 const char *vrf_name, const struct prefix *p,
				 enum zapi_ptrack_state state)
{
	struct zapi_ptrack api;
	struct ptrack_cookie *pck;

	strlcpy(api.vrf_name, vrf_name, sizeof(api.vrf_name));
	prefix_copy(&api.prefix, p);
	api.state = state;
	api.cookie_count = 0;

	frr_each (ptrack_cookies, &pc->cookies, pck) {
		api.cookies[api.cookie_count++] = pck->cookie;

		if (api.cookie_count < ZAPI_PTRACK_MAX_COOKIES)
			continue;

		if (!ptrack_send_msg(pc->client, &api))
			return;
		api.cookie_count = 0;
	}

	if (api.cookie_count)
		ptrack_send_msg(pc->client, &api);
}

/*
 * Sync ptrack context with the zebra_vrf
 */
static void ptrack_zvrf_sync(struct zebra_vrf *zvrf, struct ptrack_vrf_ctx *ctx)
{
	if (!zvrf)
		return;

	if (ctx && ptrack_vrf_clients_count(&ctx->vrf_clients) > 0)
		zvrf->ptrack = ctx;
	else if (zvrf->ptrack == ctx)
		zvrf->ptrack = NULL;
}

bool zebra_ptrack_ctx_free_if_unused(struct ptrack_vrf_ctx *ctx)
{
	if (ptrack_vrf_clients_count(&ctx->vrf_clients) > 0)
		return false;

	ptrack_ctx_free(ctx);

	return true;
}

static void ptrack_ctx_put(struct zebra_vrf *zvrf, struct ptrack_vrf_ctx *ctx)
{
	if (zvrf && zvrf->ptrack == ctx)
		zvrf->ptrack = NULL;

	if (!zebra_ptrack_ctx_free_if_unused(ctx))
		ptrack_zvrf_sync(zvrf, ctx);
}

/* Add client cookies for prefix */
void zebra_ptrack_register(struct zserv *client, const struct zapi_ptrack *api)
{
	struct zebra_vrf *zvrf;
	struct ptrack_vrf_ctx *ctx;
	struct ptrack_entry *entry;
	struct prefix p;
	enum zapi_ptrack_state state;

	zvrf = zebra_vrf_lookup_by_name(api->vrf_name);
	ctx = zebra_ptrack_ctx_get(api->vrf_name);

	if (!ctx) {
		zlog_debug("%s: client %s: invalid VRF name, dropping the request",
			   __func__, zebra_route_string(client->proto));
		return;
	}

	switch (zebra_ptrack_add_cookies(ctx, client, &api->prefix, api->cookies,
					 api->cookie_count, &entry)) {
	case ZEBRA_PTRACK_SUCCESS:
		break;
	case ZEBRA_PTRACK_LIMIT:
		zlog_warn("%s: client %s: %u cookies would exceed the limit of %u in VRF %s, dropping the request",
			  __func__, zebra_route_string(client->proto),
			  api->cookie_count, ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT,
			  api->vrf_name);
		ptrack_ctx_put(zvrf, ctx);
		return;
	case ZEBRA_PTRACK_INVALID:
		zlog_debug("%s: client %s: invalid prefix family %d, dropping the request",
			   __func__, zebra_route_string(client->proto),
			   api->prefix.family);
		ptrack_ctx_put(zvrf, ctx);
		return;
	}

	/* A request without cookies tracks nothing */
	if (!entry) {
		ptrack_ctx_put(zvrf, ctx);
		return;
	}

	ptrack_zvrf_sync(zvrf, ctx);

	/* No update if vrf is not present */
	if (!zvrf)
		return;

	prefix_copy(&p, &api->prefix);
	apply_mask(&p);

	state = ptrack_prefix_state(zvrf, &p);
	zebra_ptrack_entry_set_state(entry, state);

	ptrack_send_update(client, api->vrf_name, &p, state, api->cookies,
			   api->cookie_count);
}

/* Remove client cookies for prefix */
void zebra_ptrack_unregister(struct zserv *client,
			     const struct zapi_ptrack *api)
{
	struct ptrack_vrf_ctx *ctx;

	ctx = zebra_ptrack_ctx_lookup(api->vrf_name);
	if (!ctx) {
		zlog_debug("%s: client %s: nothing is tracked in VRF %s",
			   __func__, zebra_route_string(client->proto),
			   api->vrf_name);
		return;
	}

	zebra_ptrack_del_cookies(ctx, client, &api->prefix, api->cookies,
				 api->cookie_count);

	ptrack_ctx_put(zebra_vrf_lookup_by_name(api->vrf_name), ctx);
}

/*
 * Update prefix reachability, notify subscribed client(s)
 */
static void ptrack_entry_update(struct ptrack_vrf_ctx *ctx,
				struct ptrack_entry *entry,
				const struct prefix *p,
				enum zapi_ptrack_state state)
{
	struct ptrack_client *pc;

	if (state == entry->state)
		return;

	entry->state = state;

	frr_each (ptrack_clients, &entry->clients, pc)
		ptrack_notify_client(pc, ctx->vrf_name, p, state);
}

/* Evaluate the tracked prefix state */
void zebra_ptrack_evaluate(struct zebra_vrf *zvrf, struct route_node *rn)
{
	struct ptrack_vrf_ctx *ctx = zvrf->ptrack;
	struct ptrack_entry *entry;
	afi_t afi;

	if (!ctx)
		return;

	/* Only nodes of the VRF unicast table are tracked, not srcdest nodes */
	afi = family2afi(rn->p.family);
	if ((afi != AFI_IP && afi != AFI_IP6) ||
	    rn->table != zvrf->table[afi][SAFI_UNICAST])
		return;

	entry = zebra_ptrack_entry_lookup(ctx, &rn->p);
	if (!entry)
		return;

	ptrack_entry_update(ctx, entry, &rn->p,
			    ptrack_prefix_state(zvrf, &rn->p));
}

/* Update state for all tracked prefixes */
static void ptrack_ctx_update_all(struct zebra_vrf *zvrf,
				  struct ptrack_vrf_ctx *ctx, bool recompute)
{
	enum zapi_ptrack_state state;
	struct ptrack_entry *pe;
	struct route_node *rn;
	afi_t afi;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (rn = route_top(ctx->table[afi]); rn; rn = route_next(rn)) {
			pe = rn->info;
			if (!pe)
				continue;

			state = ZAPI_PTRACK_UNREACHABLE;
			if (recompute)
				state = ptrack_prefix_state(zvrf, &rn->p);

			ptrack_entry_update(ctx, pe, &rn->p, state);
		}
	}
}

/* Handle vrf enable */
void zebra_ptrack_vrf_enable(struct zebra_vrf *zvrf)
{
	struct ptrack_vrf_ctx *ctx;

	ctx = zebra_ptrack_ctx_lookup(zvrf_name(zvrf));
	ptrack_zvrf_sync(zvrf, ctx);

	if (!ctx || ptrack_vrf_clients_count(&ctx->vrf_clients) == 0)
		return;

	ptrack_ctx_update_all(zvrf, ctx, true);
}

/* Handle vrf disable */
void zebra_ptrack_vrf_disable(struct zebra_vrf *zvrf)
{
	if (!zvrf->ptrack)
		return;

	ptrack_ctx_update_all(zvrf, zvrf->ptrack, false);
}

/* Send the RIB state for all prefixes, once context released */
static void ptrack_release_held(struct event *event)
{
	struct ptrack_vrf_ctx *ctx;
	struct ptrack_client *pc;
	struct ptrack_entry *pe;
	struct zebra_vrf *zvrf;
	struct route_node *rn;
	afi_t afi;

	ptrack_held = false;

	frr_each (ptrack_registry, &ptrack_registry, ctx) {
		zvrf = zebra_vrf_lookup_by_name(ctx->vrf_name);

		for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
			for (rn = route_top(ctx->table[afi]); rn;
			     rn = route_next(rn)) {
				pe = rn->info;
				if (!pe)
					continue;

				pe->state = ZAPI_PTRACK_UNREACHABLE;
				if (zvrf)
					pe->state = ptrack_prefix_state(zvrf, &rn->p);

				frr_each (ptrack_clients, &pe->clients, pc)
					ptrack_notify_client(pc, ctx->vrf_name,
							     &rn->p, pe->state);
			}
		}
	}
}

void zebra_ptrack_rib_sweep(void)
{
	/* Nothing was held (after GR) */
	if (!ptrack_held)
		return;

	event_add_event(zrouter.master, ptrack_release_held, NULL, 0,
			&t_ptrack_release_timer);
}

/* Remove a client from all prefixes */
static void ptrack_ctx_del_client(struct ptrack_vrf_ctx *ctx,
				  struct zserv *client)
{
	struct ptrack_vrf_client *pvc;
	struct ptrack_entry *pe;
	struct ptrack_client *pc;
	struct route_node *rn;
	afi_t afi;

	pvc = ptrack_vrf_client_find(ctx, client);
	if (!pvc)
		return;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (rn = route_top(ctx->table[afi]); rn; rn = route_next(rn)) {
			pe = rn->info;
			if (!pe)
				continue;

			pc = ptrack_client_find(pe, client);
			if (!pc)
				continue;

			ptrack_clients_del(&pe->clients, pc);
			ptrack_client_free(pc);

			if (ptrack_clients_count(&pe->clients) == 0) {
				ptrack_entry_free(pe);
				rn->info = NULL;
				/*
				 * The lock that was taken when the entry was
				 * stored, the walk still holds its own.
				 */
				route_unlock_node(rn);
			}
		}
	}

	ptrack_vrf_clients_del(&ctx->vrf_clients, pvc);
	XFREE(MTYPE_PTRACK_VRF_CLIENT, pvc);
}

/* Drop subscriptions of closing client in all VRFs */
static int ptrack_client_cleanup(struct zserv *client)
{
	struct ptrack_vrf_ctx *ctx;

	frr_each_safe (ptrack_registry, &ptrack_registry, ctx) {
		ptrack_ctx_del_client(ctx, client);

		ptrack_ctx_put(zebra_vrf_lookup_by_name(ctx->vrf_name), ctx);
	}

	return 0;
}

/* Initialze ptrack */
void zebra_ptrack_init(void)
{
	ptrack_registry_init(&ptrack_registry);

	hook_register(zserv_client_close, ptrack_client_cleanup);
}

/* Remove ptrack data on zebra shutdown */
void zebra_ptrack_terminate(void)
{
	struct ptrack_vrf_ctx *ctx;

	event_cancel(&t_ptrack_release_timer);

	while ((ctx = ptrack_registry_first(&ptrack_registry)))
		ptrack_ctx_free(ctx);

	ptrack_registry_fini(&ptrack_registry);
}
