// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP cache
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"
#include "memory.h"
#include "frrevent.h"
#include "hash.h"
#include "nhrpd.h"

#include "netlink.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_CACHE, "NHRP cache entry");
DEFINE_MTYPE_STATIC(NHRPD, NHRP_CACHE_CONFIG, "NHRP cache config entry");

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

static unsigned int nhrp_cache_protocol_key(const void *peer_data)
{
	const struct nhrp_cache *p = peer_data;
	return sockunion_hash(&p->remote_addr);
}

static bool nhrp_cache_protocol_cmp(const void *cache_data,
				    const void *key_data)
{
	const struct nhrp_cache *a = cache_data;
	const struct nhrp_cache *b = key_data;

	return sockunion_same(&a->remote_addr, &b->remote_addr);
}

static void *nhrp_cache_alloc(void *data)
{
	struct nhrp_cache *p, *key = data;

	p = XMALLOC(MTYPE_NHRP_CACHE, sizeof(struct nhrp_cache));

	*p = (struct nhrp_cache){
		.cur.type = NHRP_CACHE_INVALID,
		.new.type = NHRP_CACHE_INVALID,
		.remote_addr = key->remote_addr,
		.ifp = key->ifp,
		.notifier_list =
		NOTIFIER_LIST_INITIALIZER(&p->notifier_list),
	};
	nhrp_cache_counts[p->cur.type]++;

	return p;
}

static void nhrp_cache_free(struct nhrp_cache *c)
{
	struct nhrp_interface *nifp = c->ifp->info;

	debugf(NHRP_DEBUG_COMMON, "Deleting cache entry");
	nhrp_cache_counts[c->cur.type]--;
	notifier_call(&c->notifier_list, NOTIFY_CACHE_DELETE);
	assert(!notifier_active(&c->notifier_list));
	hash_release(nifp->cache_hash, c);
	if (c->cur.peer)
		nhrp_peer_notify_del(c->cur.peer, &c->peer_notifier);
	nhrp_peer_unref(c->cur.peer);
	nhrp_peer_unref(c->new.peer);
	EVENT_OFF(c->t_timeout);
	EVENT_OFF(c->t_auth);
	XFREE(MTYPE_NHRP_CACHE, c);
}

static unsigned int nhrp_cache_config_protocol_key(const void *peer_data)
{
	const struct nhrp_cache_config *p = peer_data;
	return sockunion_hash(&p->remote_addr);
}

static bool nhrp_cache_config_protocol_cmp(const void *cache_data,
					   const void *key_data)
{
	const struct nhrp_cache_config *a = cache_data;
	const struct nhrp_cache_config *b = key_data;

	if (!sockunion_same(&a->remote_addr, &b->remote_addr))
		return false;
	if (a->ifp != b->ifp)
		return false;
	return true;
}

static void *nhrp_cache_config_alloc(void *data)
{
	struct nhrp_cache_config *p, *key = data;

	p = XCALLOC(MTYPE_NHRP_CACHE_CONFIG, sizeof(struct nhrp_cache_config));

	*p = (struct nhrp_cache_config){
		.remote_addr = key->remote_addr,
		.ifp = key->ifp,
	};
	return p;
}

void nhrp_cache_config_free(struct nhrp_cache_config *c)
{
	struct nhrp_interface *nifp = c->ifp->info;

	hash_release(nifp->cache_config_hash, c);
	XFREE(MTYPE_NHRP_CACHE_CONFIG, c);
}

struct nhrp_cache_config *nhrp_cache_config_get(struct interface *ifp,
						union sockunion *remote_addr,
						int create)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_cache_config key;

	if (!nifp->cache_config_hash) {
		nifp->cache_config_hash =
			hash_create(nhrp_cache_config_protocol_key,
				    nhrp_cache_config_protocol_cmp,
				    "NHRP Config Cache");
		if (!nifp->cache_config_hash)
			return NULL;
	}
	key.remote_addr = *remote_addr;
	key.ifp = ifp;

	return hash_get(nifp->cache_config_hash, &key,
			create ? nhrp_cache_config_alloc : NULL);
}

static void do_nhrp_cache_free(struct hash_bucket *hb,
			       void *arg __attribute__((__unused__)))
{
	struct nhrp_cache *c = hb->data;

	nhrp_cache_free(c);
}

static void do_nhrp_cache_config_free(struct hash_bucket *hb,
				      void *arg __attribute__((__unused__)))
{
	struct nhrp_cache_config *cc = hb->data;

	nhrp_cache_config_free(cc);
}

void nhrp_cache_interface_del(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	debugf(NHRP_DEBUG_COMMON, "Cleaning up undeleted cache entries (%lu)",
	       nifp->cache_hash ? nifp->cache_hash->count : 0);

	if (nifp->cache_hash) {
		hash_iterate(nifp->cache_hash, do_nhrp_cache_free, NULL);
		hash_free(nifp->cache_hash);
	}

	if (nifp->cache_config_hash) {
		hash_iterate(nifp->cache_config_hash, do_nhrp_cache_config_free,
			     NULL);
		hash_free(nifp->cache_config_hash);
	}
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

static void nhrp_cache_do_free(struct event *t)
{
	struct nhrp_cache *c = EVENT_ARG(t);

	c->t_timeout = NULL;
	nhrp_cache_free(c);
}

static void nhrp_cache_do_timeout(struct event *t)
{
	struct nhrp_cache *c = EVENT_ARG(t);

	c->t_timeout = NULL;
	if (c->cur.type != NHRP_CACHE_INVALID)
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL,
					  NULL);
}

static void nhrp_cache_update_route(struct nhrp_cache *c)
{
	struct prefix pfx;
	struct nhrp_peer *p = c->cur.peer;
	struct nhrp_interface *nifp;

	if (!sockunion2hostprefix(&c->remote_addr, &pfx))
		return;

	if (p && nhrp_peer_check(p, 1)) {
		if (sockunion_family(&c->cur.remote_nbma_natoa) != AF_UNSPEC) {
			/* remote_nbma_natoa is already set. Therefore, binding
			 * should be updated to this value and not vc's remote
			 * nbma.
			 */
			debugf(NHRP_DEBUG_COMMON,
			       "cache (remote_nbma_natoa set): Update binding for %pSU dev %s from (deleted) peer.vc.nbma %pSU to %pSU",
			       &c->remote_addr, p->ifp->name,
			       &p->vc->remote.nbma, &c->cur.remote_nbma_natoa);

			netlink_update_binding(p->ifp, &c->remote_addr,
					       &c->cur.remote_nbma_natoa);
		} else {
			/* update binding to peer->vc->remote->nbma */
			debugf(NHRP_DEBUG_COMMON,
			       "cache (remote_nbma_natoa unspec): Update binding for %pSU dev %s from (deleted) to peer.vc.nbma %pSU",
			       &c->remote_addr, p->ifp->name,
			       &p->vc->remote.nbma);

			netlink_update_binding(p->ifp, &c->remote_addr,
					       &p->vc->remote.nbma);
		}

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
		/* debug the reason for peer check fail */
		if (p) {
			nifp = p->ifp->info;
			debugf(NHRP_DEBUG_COMMON,
			       "cache (peer check failed: online?%d requested?%d ipsec?%d)",
			       p->online, p->requested,
			       nifp->ipsec_profile ? 1 : 0);
		} else
			debugf(NHRP_DEBUG_COMMON,
			       "cache (peer check failed: no p)");

		if (c->nhrp_route_installed) {
			nhrp_route_update_nhrp(&pfx, NULL);
			c->nhrp_route_installed = 0;
		}
		if (c->route_installed) {
			assert(sockunion2hostprefix(&c->remote_addr, &pfx));
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
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL,
					  NULL);
		break;
	case NOTIFY_PEER_NBMA_CHANGING:
		if (c->cur.type == NHRP_CACHE_DYNAMIC)
			c->cur.peer->vc->abort_migration = 1;
		break;
	}
}

static void nhrp_cache_reset_new(struct nhrp_cache *c)
{
	EVENT_OFF(c->t_auth);
	if (notifier_list_anywhere(&c->newpeer_notifier))
		nhrp_peer_notify_del(c->new.peer, &c->newpeer_notifier);
	nhrp_peer_unref(c->new.peer);
	memset(&c->new, 0, sizeof(c->new));
	c->new.type = NHRP_CACHE_INVALID;
}

static void nhrp_cache_update_timers(struct nhrp_cache *c)
{
	EVENT_OFF(c->t_timeout);

	switch (c->cur.type) {
	case NHRP_CACHE_INVALID:
		if (!c->t_auth)
			event_add_timer_msec(master, nhrp_cache_do_free, c, 10,
					     &c->t_timeout);
		break;
	case NHRP_CACHE_INCOMPLETE:
	case NHRP_CACHE_NEGATIVE:
	case NHRP_CACHE_CACHED:
	case NHRP_CACHE_DYNAMIC:
	case NHRP_CACHE_NHS:
	case NHRP_CACHE_STATIC:
	case NHRP_CACHE_LOCAL:
	case NHRP_CACHE_NUM_TYPES:
		if (c->cur.expires)
			event_add_timer(master, nhrp_cache_do_timeout, c,
					c->cur.expires - monotime(NULL),
					&c->t_timeout);
		break;
	}
}

static void nhrp_cache_authorize_binding(struct nhrp_reqid *r, void *arg)
{
	struct nhrp_cache *c = container_of(r, struct nhrp_cache, eventid);
	char buf[3][SU_ADDRSTRLEN];

	debugf(NHRP_DEBUG_COMMON, "cache: %s %pSU: %s", c->ifp->name,
	       &c->remote_addr, (const char *)arg);

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

		if (sockunion_family(&c->cur.remote_nbma_natoa) != AF_UNSPEC) {
			debugf(NHRP_DEBUG_COMMON,
			       "cache: update binding for %pSU dev %s from (deleted) peer.vc.nbma %s to %pSU",
			       &c->remote_addr, c->ifp->name,
			       (c->cur.peer ? sockunion2str(
					&c->cur.peer->vc->remote.nbma, buf[1],
					sizeof(buf[1]))
					    : "(no peer)"),
			       &c->cur.remote_nbma_natoa);

			if (c->cur.peer)
				netlink_update_binding(
					c->cur.peer->ifp, &c->remote_addr,
					&c->cur.remote_nbma_natoa);
		}

		nhrp_cache_update_route(c);
		notifier_call(&c->notifier_list, NOTIFY_CACHE_BINDING_CHANGE);
	} else {
		nhrp_cache_reset_new(c);
	}

	nhrp_cache_update_timers(c);
}

static void nhrp_cache_do_auth_timeout(struct event *t)
{
	struct nhrp_cache *c = EVENT_ARG(t);
	c->t_auth = NULL;
	nhrp_cache_authorize_binding(&c->eventid, (void *)"timeout");
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
			event_add_timer(master, nhrp_cache_do_auth_timeout, c,
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
			      uint32_t mtu, union sockunion *nbma_oa,
			      union sockunion *nbma_claimed)
{
	char buf[2][SU_ADDRSTRLEN];

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

	sockunion2str(&c->cur.remote_nbma_natoa, buf[0], sizeof(buf[0]));
	if (nbma_oa)
		sockunion2str(nbma_oa, buf[1], sizeof(buf[1]));

	nhrp_cache_reset_new(c);
	if (c->cur.type == type && c->cur.peer == p && c->cur.mtu == mtu) {
		debugf(NHRP_DEBUG_COMMON,
		       "cache: same type %u, updating expiry and changing nbma addr from %s to %s",
		       type, buf[0], nbma_oa ? buf[1] : "(NULL)");
		if (holding_time > 0)
			c->cur.expires = monotime(NULL) + holding_time;

		if (nbma_oa)
			c->cur.remote_nbma_natoa = *nbma_oa;
		else
			memset(&c->cur.remote_nbma_natoa, 0,
			       sizeof(c->cur.remote_nbma_natoa));

		if (nbma_claimed)
			c->cur.remote_nbma_claimed = *nbma_claimed;
		else
			memset(&c->cur.remote_nbma_claimed, 0,
			       sizeof(c->cur.remote_nbma_claimed));

		nhrp_peer_unref(p);
	} else {
		debugf(NHRP_DEBUG_COMMON,
		       "cache: new type %u/%u, or peer %s, or mtu %u/%u, nbma %s --> %s (map %d)",
		       c->cur.type, type, (c->cur.peer == p) ? "same" : "diff",
		       c->cur.mtu, mtu, buf[0], nbma_oa ? buf[1] : "(NULL)",
		       c->map);
		c->new.type = type;
		c->new.peer = p;
		c->new.mtu = mtu;
		c->new.holding_time = holding_time;
		if (nbma_oa)
			c->new.remote_nbma_natoa = *nbma_oa;

		if (nbma_claimed)
			c->new.remote_nbma_claimed = *nbma_claimed;

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
			event_add_timer(master, nhrp_cache_do_auth_timeout, c,
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

struct nhrp_cache_config_iterator_ctx {
	void (*cb)(struct nhrp_cache_config *, void *);
	void *ctx;
};

static void nhrp_cache_iterator(struct hash_bucket *b, void *ctx)
{
	struct nhrp_cache_iterator_ctx *ic = ctx;
	ic->cb(b->data, ic->ctx);
}

static void nhrp_cache_config_iterator(struct hash_bucket *b, void *ctx)
{
	struct nhrp_cache_config_iterator_ctx *ic = ctx;
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

void nhrp_cache_config_foreach(struct interface *ifp,
			       void (*cb)(struct nhrp_cache_config *, void *), void *ctx)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_cache_config_iterator_ctx ic = {
		.cb = cb, .ctx = ctx,
	};

	if (nifp->cache_config_hash)
		hash_iterate(nifp->cache_config_hash, nhrp_cache_config_iterator, &ic);
}

void nhrp_cache_notify_add(struct nhrp_cache *c, struct notifier_block *n,
			   notifier_fn_t fn)
{
	notifier_add(n, &c->notifier_list, fn);
}

void nhrp_cache_notify_del(struct nhrp_cache *c, struct notifier_block *n)
{
	notifier_del(n, &c->notifier_list);
}
