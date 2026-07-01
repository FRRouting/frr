// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP multicast OIL -- per-NBMA subscriber cache.
 *
 * See nhrp_mcast_oil.h for the contract. This implementation keeps a
 * single hash of OIL entries keyed by (src, grp, ifindex). Each entry
 * carries a list of subscriber NBMAs with individual expiry timers so
 * one neighbor's Join keeps its slot live while another's lapses.
 *
 * Copyright (c) 2026 Onyx Networks.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "hash.h"
#include "jhash.h"
#include "memory.h"
#include "monotime.h"
#include "sockunion.h"
#include "vty.h"
#include "frrevent.h"

#include "nhrpd.h"
#include "nhrp_mcast_oil.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_MCAST_OIL, "NHRP Multicast OIL entry");
DEFINE_MTYPE_STATIC(NHRPD, NHRP_MCAST_OIL_NBMA, "NHRP Multicast OIL NBMA");

struct oil_nbma {
	union sockunion nbma;	/* peer's NBMA address */
	time_t expires_at;	/* monotonic epoch seconds */
	struct oil_nbma *next;
};

struct oil_key {
	union sockunion src;	/* PIM (S, G) source; ANY for wildcard */
	union sockunion grp;
	ifindex_t ifindex;
};

struct oil_entry {
	struct oil_key key;
	struct oil_nbma *nbmas;	/* singly-linked list, small N per (S,G) */
};

static struct hash *oil_hash;
static struct event *oil_sweep_thread;

static unsigned int oil_key_hash(const void *p)
{
	const struct oil_entry *e = p;
	unsigned int h;

	h = jhash(sockunion_get_addr(&e->key.src),
		  sockunion_get_addrlen(&e->key.src), 0x4321);
	h = jhash(sockunion_get_addr(&e->key.grp),
		  sockunion_get_addrlen(&e->key.grp), h);
	h = jhash_1word((uint32_t)e->key.ifindex, h);
	return h;
}

static bool oil_key_cmp(const void *a, const void *b)
{
	const struct oil_entry *ea = a, *eb = b;

	if (ea->key.ifindex != eb->key.ifindex)
		return false;
	if (!sockunion_same(&ea->key.src, &eb->key.src))
		return false;
	if (!sockunion_same(&ea->key.grp, &eb->key.grp))
		return false;
	return true;
}

static void oil_entry_free_nbmas(struct oil_entry *e)
{
	struct oil_nbma *n, *nx;

	for (n = e->nbmas; n; n = nx) {
		nx = n->next;
		XFREE(MTYPE_NHRP_MCAST_OIL_NBMA, n);
	}
	e->nbmas = NULL;
}

static void oil_entry_free(void *p)
{
	struct oil_entry *e = p;

	oil_entry_free_nbmas(e);
	XFREE(MTYPE_NHRP_MCAST_OIL, e);
}

static void *oil_entry_alloc(void *arg)
{
	struct oil_entry *proto = arg, *e;

	e = XCALLOC(MTYPE_NHRP_MCAST_OIL, sizeof(*e));
	e->key = proto->key;
	return e;
}

static struct oil_entry *oil_lookup(union sockunion *src,
				    union sockunion *grp, ifindex_t ifindex,
				    bool create)
{
	struct oil_entry proto;

	memset(&proto, 0, sizeof(proto));
	proto.key.src = *src;
	proto.key.grp = *grp;
	proto.key.ifindex = ifindex;

	if (create)
		return hash_get(oil_hash, &proto, oil_entry_alloc);
	return hash_lookup(oil_hash, &proto);
}

static struct oil_nbma *oil_find_nbma(struct oil_entry *e,
				      union sockunion *nbma)
{
	struct oil_nbma *n;

	for (n = e->nbmas; n; n = n->next) {
		if (sockunion_same(&n->nbma, nbma))
			return n;
	}
	return NULL;
}

/* Periodic sweeper: expire stale NBMAs + drop entries with empty lists.
 * Runs every 30 seconds -- good enough resolution given PIM's 210 s
 * default holdtime.
 */
static void oil_sweep_cb(struct event *t);

static int oil_sweep_walker(struct hash_bucket *b, void *arg)
{
	struct oil_entry *e = b->data;
	time_t now = *(time_t *)arg;
	struct oil_nbma **pp, *n;

	pp = &e->nbmas;
	while ((n = *pp)) {
		if (n->expires_at <= now) {
			*pp = n->next;
			XFREE(MTYPE_NHRP_MCAST_OIL_NBMA, n);
		} else {
			pp = &n->next;
		}
	}

	if (!e->nbmas) {
		/* mark for removal; hash_walk doesn't let us delete
		 * during iteration, so we collect keys and drop after.
		 * Simpler here: release and tell hash_clean_and_free? No --
		 * just leave empties; the next lookup returns an empty
		 * list and the replication filter drops everything, which
		 * is fail-closed correct. A later patch can garbage-collect
		 * empties properly.
		 */
	}

	return HASHWALK_CONTINUE;
}

static void oil_sweep_cb(struct event *t)
{
	time_t now = monotime(NULL);

	if (oil_hash)
		hash_walk(oil_hash, oil_sweep_walker, &now);

	event_add_timer(master, oil_sweep_cb, NULL, 30, &oil_sweep_thread);
}

/* Public API -------------------------------------------------------- */

void nhrp_mcast_oil_init(void)
{
	oil_hash = hash_create_size(64, oil_key_hash, oil_key_cmp,
				    "NHRP Multicast OIL");
	event_add_timer(master, oil_sweep_cb, NULL, 30, &oil_sweep_thread);
}

void nhrp_mcast_oil_terminate(void)
{
	event_cancel(&oil_sweep_thread);
	if (oil_hash)
		hash_clean_and_free(&oil_hash, oil_entry_free);
}

bool nhrp_mcast_is_linklocal(union sockunion *grp_addr)
{
	if (sockunion_family(grp_addr) != AF_INET)
		return false;
	/* 224.0.0.0/24 -- link-local multicast, must never be filtered. */
	const uint8_t *b =
		(const uint8_t *)sockunion_get_addr(grp_addr);
	return b[0] == 224 && b[1] == 0 && b[2] == 0;
}

static void oil_add_nbma(struct oil_entry *e, union sockunion *nbma,
			 uint16_t holdtime)
{
	struct oil_nbma *n;
	time_t now = monotime(NULL);
	time_t expiry;

	if (holdtime == 0)
		holdtime = NHRP_MCAST_OIL_DEFAULT_HOLDTIME;
	/* PIM holdtime is a uint16 on the wire (RFC 7761 sect.4.9.5) and
	 * `holdtime` is typed accordingly, so the upper bound
	 * NHRP_MCAST_OIL_MAX_HOLDTIME (65535 = UINT16_MAX) is enforced
	 * by the type itself -- an explicit `holdtime > MAX` check would
	 * be provably false and is rejected by gcc -Werror=type-limits.
	 * Keep the constant in the header as documentation.
	 */
	expiry = now + holdtime;

	n = oil_find_nbma(e, nbma);
	if (n) {
		if (expiry > n->expires_at)
			n->expires_at = expiry;
		return;
	}

	n = XCALLOC(MTYPE_NHRP_MCAST_OIL_NBMA, sizeof(*n));
	n->nbma = *nbma;
	n->expires_at = expiry;
	n->next = e->nbmas;
	e->nbmas = n;
}

static void oil_remove_nbma(struct oil_entry *e, union sockunion *nbma)
{
	struct oil_nbma **pp, *n;

	pp = &e->nbmas;
	while ((n = *pp)) {
		if (sockunion_same(&n->nbma, nbma)) {
			*pp = n->next;
			XFREE(MTYPE_NHRP_MCAST_OIL_NBMA, n);
			return;
		}
		pp = &n->next;
	}
}

/* Map a PIM sender's tunnel (protocol) IP to its NBMA via the NHRP
 * cache. Returns NULL if we don't have a cached peer for this tunnel
 * IP -- in that case the Join is dropped (we can't route it anyway).
 */
static struct nhrp_peer *resolve_sender_to_peer(struct interface *ifp,
						union sockunion *tunnel_ip)
{
	struct nhrp_cache *c = nhrp_cache_get(ifp, tunnel_ip, 0);

	if (!c || !c->cur.peer || c->cur.type < NHRP_CACHE_DYNAMIC)
		return NULL;
	return nhrp_peer_ref(c->cur.peer);
}

void nhrp_mcast_oil_join(struct interface *ifp,
			 union sockunion *src_addr,
			 union sockunion *grp_addr,
			 union sockunion *sender_tunnel_ip,
			 uint16_t holdtime,
			 bool wc_bit)
{
	struct nhrp_peer *peer;
	struct oil_entry *e;
	union sockunion key_src;

	/* Never track link-local groups -- they're always fanned out. */
	if (nhrp_mcast_is_linklocal(grp_addr))
		return;

	peer = resolve_sender_to_peer(ifp, sender_tunnel_ip);
	if (!peer) {
		debugf(NHRP_DEBUG_COMMON,
		       "mcast-oil: Join from %pSU on %s -- no NHRP peer; ignoring",
		       sender_tunnel_ip, ifp->name);
		return;
	}

	/* (*,G) Joins are stored with src=ANY; (S,G) with explicit source. */
	if (wc_bit) {
		memset(&key_src, 0, sizeof(key_src));
		key_src.sa.sa_family = sockunion_family(src_addr);
	} else {
		key_src = *src_addr;
	}

	e = oil_lookup(&key_src, grp_addr, ifp->ifindex, true);
	oil_add_nbma(e, &peer->vc->remote.nbma, holdtime);

	debugf(NHRP_DEBUG_COMMON,
	       "mcast-oil: +Join (S=%pSU,G=%pSU) iface=%s peer_nbma=%pSU holdtime=%u",
	       &key_src, grp_addr, ifp->name, &peer->vc->remote.nbma,
	       (unsigned int)holdtime);

	nhrp_peer_unref(peer);
}

void nhrp_mcast_oil_prune(struct interface *ifp,
			  union sockunion *src_addr,
			  union sockunion *grp_addr,
			  union sockunion *sender_tunnel_ip,
			  bool wc, bool rpt)
{
	struct nhrp_peer *peer;
	struct oil_entry *e;
	union sockunion key_src;

	peer = resolve_sender_to_peer(ifp, sender_tunnel_ip);
	if (!peer)
		return;

	/* PIM Prune flag combinations (RFC 7761 sect.4.9.5.1):
	 *   wc=1, rpt=1:  (*,G)    Prune  -> drop NBMA from (*,G) OIL
	 *   wc=0, rpt=0:  (S,G)    Prune  -> drop NBMA from (S,G) OIL
	 *   wc=0, rpt=1: (S,G,rpt) Prune  -> SPT switchover; we don't
	 *                                   track (S,G,rpt) state, so
	 *                                   leave both (*,G) and (S,G)
	 *                                   alone. Removing from (*,G)
	 *                                   here was the previous bug:
	 *                                   it stripped shared-tree
	 *                                   coverage on every SPT
	 *                                   transition.
	 */
	if (wc && rpt) {
		memset(&key_src, 0, sizeof(key_src));
		key_src.sa.sa_family = sockunion_family(src_addr);
		e = oil_lookup(&key_src, grp_addr, ifp->ifindex, false);
		if (e)
			oil_remove_nbma(e, &peer->vc->remote.nbma);
	} else if (!wc && !rpt) {
		e = oil_lookup(src_addr, grp_addr, ifp->ifindex, false);
		if (e)
			oil_remove_nbma(e, &peer->vc->remote.nbma);
	}
	/* (wc=0, rpt=1): no OIL change. */

	debugf(NHRP_DEBUG_COMMON,
	       "mcast-oil: -Prune (S=%pSU,G=%pSU) iface=%s peer_nbma=%pSU wc=%d rpt=%d",
	       src_addr, grp_addr, ifp->name, &peer->vc->remote.nbma,
	       wc, rpt);

	nhrp_peer_unref(peer);
}

bool nhrp_mcast_oil_contains(struct interface *ifp,
			     union sockunion *src_addr,
			     union sockunion *grp_addr,
			     union sockunion *peer_nbma,
			     bool default_fanout)
{
	struct oil_entry *e;
	time_t now = monotime(NULL);
	union sockunion key_src;
	bool have_any = false;

	/* Link-local always forwarded (fanout). */
	if (nhrp_mcast_is_linklocal(grp_addr))
		return true;

	/* (S,G) lookup first. */
	e = oil_lookup(src_addr, grp_addr, ifp->ifindex, false);
	if (e) {
		struct oil_nbma *n;

		have_any = true;
		for (n = e->nbmas; n; n = n->next) {
			if (n->expires_at <= now)
				continue;
			if (sockunion_same(&n->nbma, peer_nbma))
				return true;
		}
	}

	/* (*,G) shared-tree fallback. */
	memset(&key_src, 0, sizeof(key_src));
	key_src.sa.sa_family = sockunion_family(src_addr);
	e = oil_lookup(&key_src, grp_addr, ifp->ifindex, false);
	if (e) {
		struct oil_nbma *n;

		have_any = true;
		for (n = e->nbmas; n; n = n->next) {
			if (n->expires_at <= now)
				continue;
			if (sockunion_same(&n->nbma, peer_nbma))
				return true;
		}
	}

	if (!have_any)
		return default_fanout;
	return false;
}

static int oil_show_walker(struct hash_bucket *b, void *arg)
{
	struct oil_entry *e = b->data;
	struct vty *vty = arg;
	struct oil_nbma *n;
	time_t now = monotime(NULL);

	vty_out(vty, "  (%pSU, %pSU) iface-idx=%u\n",
		&e->key.src, &e->key.grp, e->key.ifindex);

	for (n = e->nbmas; n; n = n->next) {
		long remain = (long)(n->expires_at - now);

		vty_out(vty, "      nbma=%pSU  expires_in=%lds%s\n",
			&n->nbma, remain, (remain <= 0 ? "  [STALE]" : ""));
	}

	return HASHWALK_CONTINUE;
}

void nhrp_mcast_oil_show(struct vty *vty)
{
	vty_out(vty, "NHRP Multicast OIL cache:\n");
	if (!oil_hash || oil_hash->count == 0) {
		vty_out(vty, "  (empty)\n");
		return;
	}
	hash_walk(oil_hash, oil_show_walker, vty);
}
