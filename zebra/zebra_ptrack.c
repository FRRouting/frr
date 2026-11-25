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

/* Cookies of one client on one prefix, keyed by the cookie (opaque to zebra) */
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

/* Clients subscribed to one prefix, keyed by the client */
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

/* Stored in route_node->info of the table of the VRF context */
struct ptrack_entry {
	enum zapi_ptrack_state state;

	struct ptrack_clients_head clients;
};

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
static uint32_t ptrack_cookie_limit = ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT;

/* A message was held back because zebra was still starting up */
static bool ptrack_held;
static struct event *t_ptrack_release;

/* Free a client of a prefix with all its cookies */
static void ptrack_client_free(struct ptrack_client *pc)
{
	struct ptrack_cookie *pck;

	while ((pck = ptrack_cookies_pop(&pc->cookies)))
		XFREE(MTYPE_PTRACK_COOKIE, pck);

	ptrack_cookies_fini(&pc->cookies);
	XFREE(MTYPE_PTRACK_CLIENT, pc);
}

/* Free a prefix entry with all its clients and cookies */
static void ptrack_entry_free(struct ptrack_entry *entry)
{
	struct ptrack_client *pc;

	while ((pc = ptrack_clients_pop(&entry->clients)))
		ptrack_client_free(pc);

	ptrack_clients_fini(&entry->clients);
	XFREE(MTYPE_PTRACK_ENTRY, entry);
}

/*
 * Called when a node of a ptrack table is freed (the context is freed). The
 * per-VRF counters go away with the context, so they are not adjusted here.
 */
static void ptrack_table_node_cleanup(struct route_table *table,
				      struct route_node *node)
{
	if (node->info) {
		ptrack_entry_free(node->info);
		node->info = NULL;
	}
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

bool zebra_ptrack_ctx_free_if_unused(struct ptrack_vrf_ctx *ctx)
{
	if (ptrack_vrf_clients_count(&ctx->vrf_clients) > 0)
		return false;

	ptrack_ctx_free(ctx);

	return true;
}

/*
 * Number of cookies that are not on the prefix yet. Duplicates ignored
 */
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

	/* The tables are keyed by the masked prefix */
	prefix_copy(&pfx, p);
	apply_mask(&pfx);

	/* First pass, nothing is changed before the limit is checked */
	rn = route_node_lookup(table, &pfx);
	pe = rn ? rn->info : NULL;
	if (pe)
		pc = ptrack_client_find(pe, client);

	total = ptrack_count_new_cookies(pc, cookies, count);
	if (rn)
		route_unlock_node(rn);

	/* Nothing to add, do not create an entry for it */
	if (count == 0) {
		*entry = pe;
		return ZEBRA_PTRACK_SUCCESS;
	}

	pvc = ptrack_vrf_client_find(ctx, client);
	total += pvc ? pvc->cookie_count : 0;
	if (total > ptrack_cookie_limit)
		return ZEBRA_PTRACK_LIMIT;

	/* Second pass */
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

enum zapi_ptrack_state zebra_ptrack_entry_state(const struct ptrack_entry *entry)
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

/*
 * The prefix is REACHABLE if the VRF is active and the exact prefix has at
 * least one route entry in the default table of the VRF that is not being
 * removed. Route type, nexthops, selection and FIB installation are ignored.
 */
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

/*
 * Send one UPDATE message to a client, every message goes through here.
 *
 * Returns false if it was not sent: nothing is sent until zebra finished its
 * startup, the entries are still stored and updated meanwhile and everything
 * is sent once, see zebra_ptrack_rib_sweep(). It also returns false if
 * the message can't be encoded.
 */
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

/*
 * Send the state of a prefix to a client for the given cookies. The cookies
 * are split in several messages, with the same prefix and state, if they do
 * not fit in one ZAPI message.
 */
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

/*
 * Send the state of a prefix to a client for all the cookies the client has
 * on it, split like ptrack_send_update(). The cookies are copied from the
 * tree straight into the message, there is no temporary array.
 */
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
 * Sync ptrack context with the zebra_vrf.
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

/*
 * Free the context if it has no subscription left. The pointer of the
 * zebra_vrf is cleared first, it must not point to a freed context.
 */
static void ptrack_ctx_put(struct zebra_vrf *zvrf, struct ptrack_vrf_ctx *ctx)
{
	if (zvrf && zvrf->ptrack == ctx)
		zvrf->ptrack = NULL;

	if (!zebra_ptrack_ctx_free_if_unused(ctx))
		ptrack_zvrf_sync(zvrf, ctx);
}

void zebra_ptrack_register(struct zserv *client, const struct zapi_ptrack *api)
{
	struct zebra_vrf *zvrf;
	struct ptrack_vrf_ctx *ctx;
	struct ptrack_entry *entry;
	struct prefix p;
	enum zapi_ptrack_state state;

	/* The ptrack request never creates a VRF */
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
			  api->cookie_count, ptrack_cookie_limit,
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

	/*
	 * No initial UPDATE until the zebra_vrf exists: UNREACHABLE in the
	 * protocol means the VRF was evaluated, not merely absent at register.
	 */
	if (!zvrf)
		return;

	/* The state is sent with the masked prefix, like the entry is keyed */
	prefix_copy(&p, &api->prefix);
	apply_mask(&p);

	state = ptrack_prefix_state(zvrf, &p);
	zebra_ptrack_entry_set_state(entry, state);

	ptrack_send_update(client, api->vrf_name, &p, state, api->cookies,
			   api->cookie_count);
}

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

	/* The VRF may be gone, then there is no pointer to clear */
	ptrack_ctx_put(zebra_vrf_lookup_by_name(api->vrf_name), ctx);
}

/*
 * Store a new state of a prefix and notify its clients if it flipped, there
 * is no message if the state is the same.
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

void zebra_ptrack_evaluate(struct zebra_vrf *zvrf, struct route_node *rn)
{
	struct ptrack_vrf_ctx *ctx = zvrf->ptrack;
	struct ptrack_entry *entry;
	afi_t afi;

	/* Nothing is tracked in this VRF, the common case */
	if (!ctx)
		return;

	/*
	 * Only the unicast table of the VRF is tracked. A node of another
	 * table, or a source node of an IPv6 srcdest table, is not.
	 */
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

/*
 * Set the state of every tracked prefix of a context to the given state, or,
 * if recompute is set, to the state the RIB gives now. Flips are notified.
 */
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

void zebra_ptrack_vrf_enable(struct zebra_vrf *zvrf)
{
	struct ptrack_vrf_ctx *ctx;

	/* The ctx outlives the zebra_vrf, find it again by the VRF name */
	ctx = zebra_ptrack_ctx_lookup(zvrf_name(zvrf));
	ptrack_zvrf_sync(zvrf, ctx);

	if (!ctx || ptrack_vrf_clients_count(&ctx->vrf_clients) == 0)
		return;

	/* Retained routes produce no RIB event, so look at all the prefixes */
	ptrack_ctx_update_all(zvrf, ctx, true);
}

void zebra_ptrack_vrf_disable(struct zebra_vrf *zvrf)
{
	if (!zvrf->ptrack)
		return;

	/* Whatever routes are retained, a prefix of a down VRF is UNREACHABLE */
	ptrack_ctx_update_all(zvrf, zvrf->ptrack, false);
}

/*
 * Send the current state of every tracked prefix to all its clients and
 * cookies. Everything that was subscribed or flipped while the messages were
 * held is pending, there is no flag per cookie. The state is taken from the
 * RIB again, the sweep just marked the stale routes as removed.
 */
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
		/* The VRF may be gone, its prefixes are UNREACHABLE then */
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
	/* Nothing was held, always the case after a graceful restart */
	if (!ptrack_held)
		return;

	/* An event keeps the sweep short, the messages can be many */
	event_add_event(zrouter.master, ptrack_release_held, NULL, 0,
			&t_ptrack_release);
}

/* Remove a client from all the prefixes of a context */
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

/* A client is closing, drop all its subscriptions in all the VRFs */
static int ptrack_client_cleanup(struct zserv *client)
{
	struct ptrack_vrf_ctx *ctx;

	frr_each_safe (ptrack_registry, &ptrack_registry, ctx) {
		ptrack_ctx_del_client(ctx, client);

		/* The VRF may be gone, then there is no pointer to clear */
		ptrack_ctx_put(zebra_vrf_lookup_by_name(ctx->vrf_name), ctx);
	}

	return 0;
}

void zebra_ptrack_init(void)
{
	ptrack_registry_init(&ptrack_registry);

	hook_register(zserv_client_close, ptrack_client_cleanup);
}

void zebra_ptrack_terminate(void)
{
	struct ptrack_vrf_ctx *ctx;

	event_cancel(&t_ptrack_release);

	while ((ctx = ptrack_registry_first(&ptrack_registry)))
		ptrack_ctx_free(ctx);

	ptrack_registry_fini(&ptrack_registry);
}
