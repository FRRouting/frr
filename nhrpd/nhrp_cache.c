/* NHRP cache
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "zebra.h"
#include "memory.h"
#include "thread.h"
#include "hash.h"
#include "nhrpd.h"

#include "netlink.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_CACHE, "NHRP cache entry")

unsigned long nhrp_cache_counts[NHRP_CACHE_NUM_TYPES];

const char *const nhrp_cache_type_str[] = {
		[NHRP_CACHE_INVALID] = "invalid",
		[NHRP_CACHE_INCOMPLETE] = "incomplete",
		[NHRP_CACHE_NEGATIVE] = "negative",
		[NHRP_CACHE_CACHED] = "cached",
		[NHRP_CACHE_DYNAMIC] = "dynamic",
		[NHRP_CACHE_NHS] = "nhs",
		[NHRP_CACHE_STATIC] = "static",
		[NHRP_CACHE_LOCAL] = "local",
};

static unsigned int nhrp_cache_protocol_key(void *peer_data)
{
	struct nhrp_cache *p = peer_data;
	return sockunion_hash(&p->remote_addr);
}

static int nhrp_cache_protocol_cmp(const void *cache_data, const void *key_data)
{
	const struct nhrp_cache *a = cache_data;
	const struct nhrp_cache *b = key_data;
	return sockunion_same(&a->remote_addr, &b->remote_addr);
}

static void *nhrp_cache_alloc(void *data)
{
	struct nhrp_cache *p, *key = data;

	p = XMALLOC(MTYPE_NHRP_CACHE, sizeof(struct nhrp_cache));
	if (p) {
		*p = (struct nhrp_cache){
			.cur.type = NHRP_CACHE_INVALID,
			.new.type = NHRP_CACHE_INVALID,
			.remote_addr = key->remote_addr,
			.ifp = key->ifp,
			.notifier_list =
				NOTIFIER_LIST_INITIALIZER(&p->notifier_list),
		};
		nhrp_cache_counts[p->cur.type]++;
	}

	return p;
}

static void nhrp_cache_free(struct nhrp_cache *c)
{
	struct nhrp_interface *nifp = c->ifp->info;

	zassert(c->cur.type == NHRP_CACHE_INVALID && c->cur.peer == NULL);
	zassert(c->new.type == NHRP_CACHE_INVALID && c->new.peer == NULL);
	nhrp_cache_counts[c->cur.type]--;
	notifier_call(&c->notifier_list, NOTIFY_CACHE_DELETE);
	zassert(!notifier_active(&c->notifier_list));
	hash_release(nifp->cache_hash, c);
	XFREE(MTYPE_NHRP_CACHE, c);
}

struct nhrp_cache *nhrp_cache_get(struct interface *ifp,
				  union sockunion *remote_addr, int create)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_cache key;

	if (!nifp->cache_hash) {
		nifp->cache_hash =
			hash_create(nhrp_cache_protocol_key,
				    nhrp_cache_protocol_cmp, "NHRP Cache");
		if (!nifp->cache_hash)
			return NULL;
	}

	key.remote_addr = *remote_addr;
	key.ifp = ifp;

	return hash_get(nifp->cache_hash, &key,
			create ? nhrp_cache_alloc : NULL);
}

static int nhrp_cache_do_free(struct thread *t)
{
	struct nhrp_cache *c = THREAD_ARG(t);
	c->t_timeout = NULL;
	nhrp_cache_free(c);
	return 0;
}

static int nhrp_cache_do_timeout(struct thread *t)
{
	struct nhrp_cache *c = THREAD_ARG(t);
	c->t_timeout = NULL;
	if (c->cur.type != NHRP_CACHE_INVALID)
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL);
	return 0;
}

static void nhrp_cache_update_route(struct nhrp_cache *c)
{
	struct prefix pfx;
	struct nhrp_peer *p = c->cur.peer;

	sockunion2hostprefix(&c->remote_addr, &pfx);

	if (p && nhrp_peer_check(p, 1)) {
		netlink_update_binding(p->ifp, &c->remote_addr,
				       &p->vc->remote.nbma);
		nhrp_route_announce(1, c->cur.type, &pfx, c->ifp, NULL,
				    c->cur.mtu);
		if (c->cur.type >= NHRP_CACHE_DYNAMIC) {
			nhrp_route_update_nhrp(&pfx, c->ifp);
			c->nhrp_route_installed = 1;
		} else if (c->nhrp_route_installed) {
			nhrp_route_update_nhrp(&pfx, NULL);
			c->nhrp_route_installed = 0;
		}
		if (!c->route_installed) {
			notifier_call(&c->notifier_list, NOTIFY_CACHE_UP);
			c->route_installed = 1;
		}
	} else {
		if (c->nhrp_route_installed) {
			nhrp_route_update_nhrp(&pfx, NULL);
			c->nhrp_route_installed = 0;
		}
		if (c->route_installed) {
			sockunion2hostprefix(&c->remote_addr, &pfx);
			notifier_call(&c->notifier_list, NOTIFY_CACHE_DOWN);
			nhrp_route_announce(0, c->cur.type, &pfx, NULL, NULL,
					    0);
			c->route_installed = 0;
		}
	}
}

static void nhrp_cache_peer_notifier(struct notifier_block *n,
				     unsigned long cmd)
{
	struct nhrp_cache *c =
		container_of(n, struct nhrp_cache, peer_notifier);

	switch (cmd) {
	case NOTIFY_PEER_UP:
		nhrp_cache_update_route(c);
		break;
	case NOTIFY_PEER_DOWN:
	case NOTIFY_PEER_IFCONFIG_CHANGED:
		notifier_call(&c->notifier_list, NOTIFY_CACHE_DOWN);
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL);
		break;
	case NOTIFY_PEER_NBMA_CHANGING:
		if (c->cur.type == NHRP_CACHE_DYNAMIC)
			c->cur.peer->vc->abort_migration = 1;
		break;
	}
}

static void nhrp_cache_reset_new(struct nhrp_cache *c)
{
	THREAD_OFF(c->t_auth);
	if (list_hashed(&c->newpeer_notifier.notifier_entry))
		nhrp_peer_notify_del(c->new.peer, &c->newpeer_notifier);
	nhrp_peer_unref(c->new.peer);
	memset(&c->new, 0, sizeof(c->new));
	c->new.type = NHRP_CACHE_INVALID;
}

static void nhrp_cache_update_timers(struct nhrp_cache *c)
{
	THREAD_OFF(c->t_timeout);

	switch (c->cur.type) {
	case NHRP_CACHE_INVALID:
		if (!c->t_auth)
			thread_add_timer_msec(master, nhrp_cache_do_free, c, 10,
					      &c->t_timeout);
		break;
	default:
		if (c->cur.expires)
			thread_add_timer(master, nhrp_cache_do_timeout, c,
					 c->cur.expires - monotime(NULL),
					 &c->t_timeout);
		break;
	}
}

static void nhrp_cache_authorize_binding(struct nhrp_reqid *r, void *arg)
{
	struct nhrp_cache *c = container_of(r, struct nhrp_cache, eventid);
	char buf[SU_ADDRSTRLEN];

	debugf(NHRP_DEBUG_COMMON, "cache: %s %s: %s", c->ifp->name,
	       sockunion2str(&c->remote_addr, buf, sizeof buf),
	       (const char *)arg);

	nhrp_reqid_free(&nhrp_event_reqid, r);

	if (arg && strcmp(arg, "accept") == 0) {
		if (c->cur.peer) {
			netlink_update_binding(c->cur.peer->ifp,
					       &c->remote_addr, NULL);
			nhrp_peer_notify_del(c->cur.peer, &c->peer_notifier);
			nhrp_peer_unref(c->cur.peer);
		}
		nhrp_cache_counts[c->cur.type]--;
		nhrp_cache_counts[c->new.type]++;
		c->cur = c->new;
		c->cur.peer = nhrp_peer_ref(c->cur.peer);
		nhrp_cache_reset_new(c);
		if (c->cur.peer)
			nhrp_peer_notify_add(c->cur.peer, &c->peer_notifier,
					     nhrp_cache_peer_notifier);
		nhrp_cache_update_route(c);
		notifier_call(&c->notifier_list, NOTIFY_CACHE_BINDING_CHANGE);
	} else {
		nhrp_cache_reset_new(c);
	}

	nhrp_cache_update_timers(c);
}

static int nhrp_cache_do_auth_timeout(struct thread *t)
{
	struct nhrp_cache *c = THREAD_ARG(t);
	c->t_auth = NULL;
	nhrp_cache_authorize_binding(&c->eventid, (void *)"timeout");
	return 0;
}

static void nhrp_cache_newpeer_notifier(struct notifier_block *n,
					unsigned long cmd)
{
	struct nhrp_cache *c =
		container_of(n, struct nhrp_cache, newpeer_notifier);

	switch (cmd) {
	case NOTIFY_PEER_UP:
		if (nhrp_peer_check(c->new.peer, 1)) {
			evmgr_notify("authorize-binding", c,
				     nhrp_cache_authorize_binding);
			thread_add_timer(master, nhrp_cache_do_auth_timeout, c,
					 10, &c->t_auth);
		}
		break;
	case NOTIFY_PEER_DOWN:
	case NOTIFY_PEER_IFCONFIG_CHANGED:
		nhrp_cache_reset_new(c);
		break;
	}
}

int nhrp_cache_update_binding(struct nhrp_cache *c, enum nhrp_cache_type type,
			      int holding_time, struct nhrp_peer *p,
			      uint32_t mtu, union sockunion *nbma_oa)
{
	if (c->cur.type > type || c->new.type > type) {
		nhrp_peer_unref(p);
		return 0;
	}

	/* Sanitize MTU */
	switch (sockunion_family(&c->remote_addr)) {
	case AF_INET:
		if (mtu < 576 || mtu >= 1500)
			mtu = 0;
		/* Opennhrp announces nbma mtu, but we use protocol mtu.
		 * This heuristic tries to fix up it. */
		if (mtu > 1420)
			mtu = (mtu & -16) - 80;
		break;
	default:
		mtu = 0;
		break;
	}

	nhrp_cache_reset_new(c);
	if (c->cur.type == type && c->cur.peer == p && c->cur.mtu == mtu) {
		if (holding_time > 0)
			c->cur.expires = monotime(NULL) + holding_time;
		if (nbma_oa)
			c->cur.remote_nbma_natoa = *nbma_oa;
		else
			memset(&c->cur.remote_nbma_natoa, 0,
			       sizeof c->cur.remote_nbma_natoa);
		nhrp_peer_unref(p);
	} else {
		c->new.type = type;
		c->new.peer = p;
		c->new.mtu = mtu;
		if (nbma_oa)
			c->new.remote_nbma_natoa = *nbma_oa;

		if (holding_time > 0)
			c->new.expires = monotime(NULL) + holding_time;
		else if (holding_time < 0)
			nhrp_cache_reset_new(c);

		if (c->new.type == NHRP_CACHE_INVALID
		    || c->new.type >= NHRP_CACHE_STATIC || c->map) {
			nhrp_cache_authorize_binding(&c->eventid,
						     (void *)"accept");
		} else {
			nhrp_peer_notify_add(c->new.peer, &c->newpeer_notifier,
					     nhrp_cache_newpeer_notifier);
			nhrp_cache_newpeer_notifier(&c->newpeer_notifier,
						    NOTIFY_PEER_UP);
			thread_add_timer(master, nhrp_cache_do_auth_timeout, c,
					 60, &c->t_auth);
		}
	}
	nhrp_cache_update_timers(c);

	return 1;
}

void nhrp_cache_set_used(struct nhrp_cache *c, int used)
{
	c->used = used;
	if (c->used)
		notifier_call(&c->notifier_list, NOTIFY_CACHE_USED);
}

struct nhrp_cache_iterator_ctx {
	void (*cb)(struct nhrp_cache *, void *);
	void *ctx;
};

static void nhrp_cache_iterator(struct hash_backet *b, void *ctx)
{
	struct nhrp_cache_iterator_ctx *ic = ctx;
	ic->cb(b->data, ic->ctx);
}

void nhrp_cache_foreach(struct interface *ifp,
			void (*cb)(struct nhrp_cache *, void *), void *ctx)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_cache_iterator_ctx ic = {
		.cb = cb, .ctx = ctx,
	};

	if (nifp->cache_hash)
		hash_iterate(nifp->cache_hash, nhrp_cache_iterator, &ic);
}

void nhrp_cache_notify_add(struct nhrp_cache *c, struct notifier_block *n,
			   notifier_fn_t fn)
{
	notifier_add(n, &c->notifier_list, fn);
}

void nhrp_cache_notify_del(struct nhrp_cache *c, struct notifier_block *n)
{
	notifier_del(n);
}
