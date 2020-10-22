/* NHRP virtual connection
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "zebra.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "thread.h"
#include "jhash.h"

#include "nhrpd.h"
#include "os.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_VC, "NHRP virtual connection");

struct child_sa {
	/* child SA unique id */
	uint32_t id;
	/* IKE SA unique id */
	uint32_t ike_uniqueid;
	struct nhrp_vc *vc;
	struct list_head childlist_entry;
};

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
		.nhrp_vrf = key->nhrp_vrf,
	};

	return vc;
}

static void nhrp_vc_free(void *data)
{
	XFREE(MTYPE_NHRP_VC, data);
}

struct nhrp_vc_if {
	struct interface *ifp;
	struct child_sa *sa;
	struct nhrp_vrf *nhrp_vrf;
	struct nhrp_vc *vc;
};

static void nhrp_vc_free_per_interface_walker(struct hash_bucket *b, void *data)
{
	struct nhrp_vc_if *ctx = (struct nhrp_vc_if *)data;
	struct nhrp_peer *p = (struct nhrp_peer *)b->data;

	if (!ctx)
		return;
	if (p->ifp == ctx->ifp && p->vc == ctx->vc)
		XFREE(MTYPE_NHRP_VC, data);
	return;
}

void nhrp_vc_free_per_interface(struct hash_bucket *b, void *data)
{
	struct interface *ifp = (struct interface *)data;
	struct nhrp_vc *vc = (struct nhrp_vc *)b->data;
	struct nhrp_vc_if ctx;
	struct nhrp_interface *nifp;

	if (!ifp)
		return;
	nifp = ifp->info;
	if (!nifp || !nifp->peer_hash)
		return;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ifp = ifp;
	ctx.vc = vc;
	hash_iterate(nifp->peer_hash, nhrp_vc_free_per_interface_walker, &ctx);
}

struct nhrp_vc *nhrp_vc_get(const union sockunion *src,
			    const union sockunion *dst, int create,
			    struct nhrp_vrf *nhrp_vrf)
{
	struct nhrp_vc key;

	key.local.nbma = *src;
	key.remote.nbma = *dst;
	key.nhrp_vrf = nhrp_vrf;
	return hash_get(nhrp_vrf->nhrp_vc_hash, &key, create ? nhrp_vc_alloc : 0);
}

static void nhrp_vc_check_delete(struct nhrp_vc *vc)
{
	if (vc->updating || vc->ipsec || notifier_active(&vc->notifier_list))
		return;
	hash_release(vc->nhrp_vrf->nhrp_vc_hash, vc);
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

void nhrp_vc_force_ipsec_down(struct nhrp_vc *vc)
{
	struct nhrp_vrf *nhrp_vrf = vc->nhrp_vrf;
	size_t i = 0;
	struct child_sa *lsa, *n, *lsa_save;
	struct vici_conn *vici;
	uint32_t ike_uniqueid;
	struct list_head ike_list_head;

	if (!vc || !vc->ipsec || !nhrp_vrf || !nhrp_vrf->vici_connection)
		return;

	/* Find all child SAs used by the vc, and terminate their parent IKE SAs.
	 * Temporarily maintain the list 'list_ike' of child SA whose IKE SAs were
	 * terminated to avoid duplicate requests.
	 */
	list_init(&ike_list_head);

	vici = nhrp_vrf->vici_connection;

	for (i = 0; i < array_size(nhrp_vrf->childlist_head); i++) {
		list_for_each_entry_safe(lsa, n, &nhrp_vrf->childlist_head[i],
					 childlist_entry) {
			bool found_lsa = false;

			if (lsa->vc != vc)
				continue;
			ike_uniqueid = lsa->ike_uniqueid;
			/* Update by dereferencing the lsa from childlist
			 * Also, decrement vc ipsec counter
			 */
			vc->ipsec--;
			lsa->vc = NULL;
			list_del(&lsa->childlist_entry);
			list_for_each_entry(lsa_save, &ike_list_head, childlist_entry) {
				if (lsa_save->ike_uniqueid == ike_uniqueid) {
					found_lsa = true;
					break;
				}
			}
			/* store temporarily struct child_sa in list_ike
			 * and flush ike_sa associated
			 */
			if (!found_lsa) {
				list_add_tail(&lsa->childlist_entry,
					      &ike_list_head);
				vici_terminate_ike(vici, ike_uniqueid);
			} else {
				/* flush struct lsa since
				 * ike_id already referenced in list_ike
				 */
				XFREE(MTYPE_NHRP_VC, lsa);
			}
		}
	}
	/* flush vc if ipsec is the last entry */
	if (!vc->ipsec)
		nhrp_vc_ipsec_reset(vc);
	/* flush remaining struct child_sa */
	list_for_each_entry_safe(lsa_save, n, &ike_list_head, childlist_entry) {
		list_del(&lsa_save->childlist_entry);
		XFREE(MTYPE_NHRP_VC, lsa_save);
	}
	return;
}

int nhrp_vc_ipsec_updown(uint32_t child_id,
			 struct nhrp_vrf *nhrp_vrf,
			 struct nhrp_vc *vc,
			 uint32_t ike_uniqueid)
{
	struct child_sa *sa = NULL, *lsa;
	uint32_t child_hash = child_id % array_size(nhrp_vrf->childlist_head);
	int abort_migration = 0;

	list_for_each_entry(lsa, &nhrp_vrf->childlist_head[child_hash], childlist_entry)
	{
		if (lsa->id == child_id) {
			sa = lsa;
			sa->ike_uniqueid = ike_uniqueid;
			break;
		}
	}

	if (!sa) {
		if (!vc)
			return 0;

		sa = XMALLOC(MTYPE_NHRP_VC, sizeof(struct child_sa));

		*sa = (struct child_sa){
			.id = child_id,
			.childlist_entry =
				LIST_INITIALIZER(sa->childlist_entry),
			.vc = NULL,
			.ike_uniqueid = ike_uniqueid,
		};
		list_add_tail(&sa->childlist_entry,
			      &vc->nhrp_vrf->childlist_head[child_hash]);
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
		list_del(&sa->childlist_entry);
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
	notifier_del(n);
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

void nhrp_vc_foreach(void (*cb)(struct nhrp_vc *, void *), void *ctx,
		     struct nhrp_vrf *nhrp_vrf)
{
	struct nhrp_vc_iterator_ctx ic = {
		.cb = cb, .ctx = ctx
	};
	hash_iterate(nhrp_vrf->nhrp_vc_hash, nhrp_vc_iterator, &ic);
}

unsigned long nhrp_vc_count(struct nhrp_vrf *nhrp_vrf)
{
	return hashcount(nhrp_vrf->nhrp_vc_hash);
}

void nhrp_vc_init(struct nhrp_vrf *nhrp_vrf)
{
	size_t i;

	nhrp_vrf->nhrp_vc_hash = hash_create(nhrp_vc_key, nhrp_vc_cmp, "NHRP VC hash");
	for (i = 0; i < array_size(nhrp_vrf->childlist_head); i++)
		list_init(&nhrp_vrf->childlist_head[i]);
}

static void nhrp_vc_reset_per_interface_walker(struct hash_bucket *b, void *data)
{
	struct nhrp_vc_if *ctx = (struct nhrp_vc_if *)data;
	struct nhrp_peer *p = (struct nhrp_peer *)b->data;
	struct nhrp_vc *vc;

	if (!ctx || !ctx->sa || !ctx->sa->vc || !ctx->ifp)
		return;
	vc = ctx->sa->vc;
	if (p->vc == vc && p->ifp == ctx->ifp)
		nhrp_vc_ipsec_updown(ctx->sa->id, ctx->nhrp_vrf, 0, ctx->sa->ike_uniqueid);
	return;
}

/* parse peer interface to see if vc is impacted by ifp
 * struct nhrp_peer contains both vc and ifp
 * if both are contained in nhrp_peer, then this vc entry
 * should be updated
 */
static void nhrp_vc_reset_match(struct nhrp_vrf *nhrp_vrf, struct child_sa *sa, struct interface *ifp)
{
	struct nhrp_vc_if ctx;
	struct nhrp_interface *nifp;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ifp = ifp;
	ctx.sa = sa;
	ctx.nhrp_vrf = nhrp_vrf;

	nifp = ifp->info;

	if (!nifp || !nifp->peer_hash)
		return;
	hash_iterate(nifp->peer_hash, nhrp_vc_reset_per_interface_walker, &ctx);
}

void nhrp_vc_reset(struct nhrp_vrf *nhrp_vrf, struct interface *ifp)
{
	struct child_sa *sa, *n;
	size_t i;

	for (i = 0; i < array_size(nhrp_vrf->childlist_head); i++) {
		list_for_each_entry_safe(sa, n, &nhrp_vrf->childlist_head[i],
					 childlist_entry) {
			if (ifp)
				nhrp_vc_reset_match(nhrp_vrf, sa, ifp);
			else
				nhrp_vc_ipsec_updown(sa->id, nhrp_vrf, 0, sa->ike_uniqueid);
		}
	}
}

void nhrp_vc_terminate(struct nhrp_vrf *nhrp_vrf)
{
	nhrp_vc_reset(nhrp_vrf, NULL);
	hash_clean(nhrp_vrf->nhrp_vc_hash, nhrp_vc_free);
}
