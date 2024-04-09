// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP virtual connection
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "frrevent.h"
#include "jhash.h"

#include "nhrpd.h"
#include "os.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_VC, "NHRP virtual connection");

PREDECL_DLIST(childlist);

struct child_sa {
	uint32_t id;
	struct nhrp_vc *vc;
	struct childlist_item childlist_entry;
};

DECLARE_DLIST(childlist, struct child_sa, childlist_entry);

static struct hash *nhrp_vc_hash;
static struct childlist_head childlist_head[512];

static unsigned int nhrp_vc_key(const void *peer_data)
{
	const struct nhrp_vc *vc = peer_data;
	return jhash_2words(sockunion_hash(&vc->local.nbma),
			    sockunion_hash(&vc->remote.nbma), 0);
}

static bool nhrp_vc_cmp(const void *cache_data, const void *key_data)
{
	const struct nhrp_vc *a = cache_data;
	const struct nhrp_vc *b = key_data;

	return sockunion_same(&a->local.nbma, &b->local.nbma)
	       && sockunion_same(&a->remote.nbma, &b->remote.nbma);
}

static void *nhrp_vc_alloc(void *data)
{
	struct nhrp_vc *vc, *key = data;

	vc = XMALLOC(MTYPE_NHRP_VC, sizeof(struct nhrp_vc));

	*vc = (struct nhrp_vc){
		.local.nbma = key->local.nbma,
		.remote.nbma = key->remote.nbma,
		.notifier_list =
		NOTIFIER_LIST_INITIALIZER(&vc->notifier_list),
	};

	return vc;
}

static void nhrp_vc_free(void *data)
{
	XFREE(MTYPE_NHRP_VC, data);
}

struct nhrp_vc *nhrp_vc_get(const union sockunion *src,
			    const union sockunion *dst, int create)
{
	struct nhrp_vc key;
	key.local.nbma = *src;
	key.remote.nbma = *dst;
	return hash_get(nhrp_vc_hash, &key, create ? nhrp_vc_alloc : 0);
}

static void nhrp_vc_check_delete(struct nhrp_vc *vc)
{
	if (vc->updating || vc->ipsec || notifier_active(&vc->notifier_list))
		return;
	hash_release(nhrp_vc_hash, vc);
	nhrp_vc_free(vc);
}

static void nhrp_vc_update(struct nhrp_vc *vc, long cmd)
{
	vc->updating = 1;
	notifier_call(&vc->notifier_list, cmd);
	vc->updating = 0;
	nhrp_vc_check_delete(vc);
}

static void nhrp_vc_ipsec_reset(struct nhrp_vc *vc)
{
	vc->local.id[0] = 0;
	vc->local.certlen = 0;
	vc->remote.id[0] = 0;
	vc->remote.certlen = 0;
}

int nhrp_vc_ipsec_updown(uint32_t child_id, struct nhrp_vc *vc)
{
	struct child_sa *sa = NULL, *lsa;
	uint32_t child_hash = child_id % array_size(childlist_head);
	int abort_migration = 0;

	frr_each (childlist, &childlist_head[child_hash], lsa) {
		if (lsa->id == child_id) {
			sa = lsa;
			break;
		}
	}

	if (!sa) {
		if (!vc)
			return 0;

		sa = XMALLOC(MTYPE_NHRP_VC, sizeof(struct child_sa));

		*sa = (struct child_sa){
			.id = child_id,
			.vc = NULL,
		};
		childlist_add_tail(&childlist_head[child_hash], sa);
	}

	if (sa->vc == vc)
		return 0;

	if (vc) {
		/* Attach first to new VC */
		vc->ipsec++;
		nhrp_vc_update(vc, NOTIFY_VC_IPSEC_CHANGED);
	}
	if (sa->vc && vc) {
		/* Notify old VC of migration */
		sa->vc->abort_migration = 0;
		debugf(NHRP_DEBUG_COMMON, "IPsec NBMA change of %pSU to %pSU",
		       &sa->vc->remote.nbma, &vc->remote.nbma);
		nhrp_vc_update(sa->vc, NOTIFY_VC_IPSEC_UPDATE_NBMA);
		abort_migration = sa->vc->abort_migration;
	}
	if (sa->vc) {
		/* Deattach old VC */
		sa->vc->ipsec--;
		if (!sa->vc->ipsec)
			nhrp_vc_ipsec_reset(sa->vc);
		nhrp_vc_update(sa->vc, NOTIFY_VC_IPSEC_CHANGED);
	}

	/* Update */
	sa->vc = vc;
	if (!vc) {
		childlist_del(&childlist_head[child_hash], sa);
		XFREE(MTYPE_NHRP_VC, sa);
	}

	return abort_migration;
}

void nhrp_vc_notify_add(struct nhrp_vc *vc, struct notifier_block *n,
			notifier_fn_t action)
{
	notifier_add(n, &vc->notifier_list, action);
}

void nhrp_vc_notify_del(struct nhrp_vc *vc, struct notifier_block *n)
{
	notifier_del(n, &vc->notifier_list);
	nhrp_vc_check_delete(vc);
}


struct nhrp_vc_iterator_ctx {
	void (*cb)(struct nhrp_vc *, void *);
	void *ctx;
};

static void nhrp_vc_iterator(struct hash_bucket *b, void *ctx)
{
	struct nhrp_vc_iterator_ctx *ic = ctx;
	ic->cb(b->data, ic->ctx);
}

void nhrp_vc_foreach(void (*cb)(struct nhrp_vc *, void *), void *ctx)
{
	struct nhrp_vc_iterator_ctx ic = {
		.cb = cb, .ctx = ctx,
	};
	hash_iterate(nhrp_vc_hash, nhrp_vc_iterator, &ic);
}

void nhrp_vc_init(void)
{
	size_t i;

	nhrp_vc_hash = hash_create(nhrp_vc_key, nhrp_vc_cmp, "NHRP VC hash");
	for (i = 0; i < array_size(childlist_head); i++)
		childlist_init(&childlist_head[i]);
}

void nhrp_vc_reset(void)
{
	struct child_sa *sa;
	size_t i;

	for (i = 0; i < array_size(childlist_head); i++) {
		frr_each_safe (childlist, &childlist_head[i], sa)
			nhrp_vc_ipsec_updown(sa->id, 0);
	}
}

void nhrp_vc_terminate(void)
{
	nhrp_vc_reset();
	hash_clean(nhrp_vc_hash, nhrp_vc_free);
	hash_free(nhrp_vc_hash);
}
