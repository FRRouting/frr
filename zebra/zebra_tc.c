// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) main handling.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#include <zebra.h>

#include <jhash.h>
#include <hash.h>
#include <memory.h>
#include <hook.h>
#include <typesafe.h>

#include <vty.h>
#include <json.h>

#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_tc.h"
#include "zebra/zebra_ns.h"
#include "zebra/interface.h"
#include "zebra/debug.h"

DEFINE_MTYPE_STATIC(ZEBRA, TC_QDISC, "TC queue discipline");
DEFINE_MTYPE_STATIC(ZEBRA, TC_CLASS, "TC class");
DEFINE_MTYPE_STATIC(ZEBRA, TC_FILTER, "TC filter");
DEFINE_MTYPE_STATIC(ZEBRA, TC_CLSACT, "TC clsact reference");

const struct message tc_qdisc_kinds[] = {
	{ TC_QDISC_HTB, "htb" },
	{ TC_QDISC_NOQUEUE, "noqueue" },
	{ TC_QDISC_CLSACT, "clsact" },
	{ 0 },
};

const struct message tc_filter_kinds[] = {
	{TC_FILTER_BPF, "bpf"},
	{TC_FILTER_FLOW, "flow"},
	{TC_FILTER_FLOWER, "flower"},
	{TC_FILTER_U32, "u32"},
	{0},
};

const struct message *tc_class_kinds = tc_qdisc_kinds;

static uint32_t lookup_key(const struct message *mz, const char *msg,
			   uint32_t nf)
{
	static struct message nt = {0};
	uint32_t rz = nf ? nf : UINT32_MAX;
	const struct message *pnt;

	for (pnt = mz; memcmp(pnt, &nt, sizeof(struct message)); pnt++)
		if (strcmp(pnt->str, msg) == 0) {
			rz = pnt->key;
			break;
		}
	return rz;
}

const char *tc_qdisc_kind2str(uint32_t type)
{
	return lookup_msg(tc_qdisc_kinds, type, "Unrecognized QDISC Type");
}

enum tc_qdisc_kind tc_qdisc_str2kind(const char *type)
{
	return lookup_key(tc_qdisc_kinds, type, TC_QDISC_UNSPEC);
}

uint32_t zebra_tc_qdisc_hash_key(const void *arg)
{
	const struct zebra_tc_qdisc *qdisc;
	uint32_t key;

	qdisc = arg;

	key = jhash_1word(qdisc->qdisc.ifindex, 0);

	return key;
}

bool zebra_tc_qdisc_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_tc_qdisc *q1, *q2;

	q1 = (const struct zebra_tc_qdisc *)arg1;
	q2 = (const struct zebra_tc_qdisc *)arg2;

	if (q1->qdisc.ifindex != q2->qdisc.ifindex)
		return false;

	return true;
}

struct tc_qdisc_ifindex_lookup {
	struct zebra_tc_qdisc *qdisc;
	ifindex_t ifindex;
};


static int tc_qdisc_lookup_ifindex_walker(struct hash_bucket *b, void *data)
{
	struct tc_qdisc_ifindex_lookup *lookup = data;
	struct zebra_tc_qdisc *qdisc = b->data;

	if (lookup->ifindex == qdisc->qdisc.ifindex) {
		lookup->qdisc = qdisc;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static struct zebra_tc_qdisc *
tc_qdisc_lookup_ifindex(struct zebra_tc_qdisc *qdisc)
{
	struct tc_qdisc_ifindex_lookup lookup;

	lookup.ifindex = qdisc->qdisc.ifindex;
	lookup.qdisc = NULL;
	hash_walk(zrouter.qdisc_hash, &tc_qdisc_lookup_ifindex_walker, &lookup);

	return lookup.qdisc;
}

static void *tc_qdisc_alloc_intern(void *arg)
{
	struct zebra_tc_qdisc *ztq;
	struct zebra_tc_qdisc *new;

	ztq = (struct zebra_tc_qdisc *)arg;

	new = XCALLOC(MTYPE_TC_QDISC, sizeof(*new));

	memcpy(new, ztq, sizeof(*ztq));

	return new;
}

void zebra_tc_qdisc_free(struct zebra_tc_qdisc *qdisc)
{
	XFREE(MTYPE_TC_QDISC, qdisc);
}

static struct zebra_tc_qdisc *tc_qdisc_free(struct zebra_tc_qdisc *hash_data,
					    bool free_data)
{
	hash_release(zrouter.qdisc_hash, hash_data);

	if (free_data) {
		zebra_tc_qdisc_free(hash_data);
		return NULL;
	}

	return hash_data;
}

static struct zebra_tc_qdisc *tc_qdisc_release(struct zebra_tc_qdisc *qdisc,
					       bool free_data)
{
	struct zebra_tc_qdisc *lookup;

	lookup = hash_lookup(zrouter.qdisc_hash, qdisc);

	if (!lookup)
		return NULL;

	return tc_qdisc_free(lookup, free_data);
}

void zebra_tc_qdisc_install(struct zebra_tc_qdisc *qdisc)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: install tc qdisc ifindex %d kind %s", __func__,
			   qdisc->qdisc.ifindex,
			   tc_qdisc_kind2str(qdisc->qdisc.kind));

	struct zebra_tc_qdisc *found;
	struct zebra_tc_qdisc *old;
	struct zebra_tc_qdisc *new;

	found = tc_qdisc_lookup_ifindex(qdisc);

	if (found) {
		if (!zebra_tc_qdisc_hash_equal(qdisc, found)) {
			old = tc_qdisc_release(found, false);
			(void)dplane_tc_qdisc_uninstall(old);
			new = hash_get(zrouter.qdisc_hash, qdisc,
				       tc_qdisc_alloc_intern);
			(void)dplane_tc_qdisc_install(new);
			zebra_tc_qdisc_free(old);
		}
	} else {
		new = hash_get(zrouter.qdisc_hash, qdisc,
			       tc_qdisc_alloc_intern);
		(void)dplane_tc_qdisc_install(new);
	}
}

void zebra_tc_qdisc_uninstall(struct zebra_tc_qdisc *qdisc)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: uninstall tc qdisc ifindex %d kind %s",
			   __func__, qdisc->qdisc.ifindex,
			   tc_qdisc_kind2str(qdisc->qdisc.kind));

	(void)dplane_tc_qdisc_uninstall(qdisc);

	if (tc_qdisc_release(qdisc, true))
		zlog_debug("%s: tc qdisc being deleted we know nothing about",
			   __func__);
}

uint32_t zebra_tc_class_hash_key(const void *arg)
{
	const struct zebra_tc_class *class;
	uint32_t key;

	class = arg;

	key = jhash_2words(class->class.ifindex, class->class.handle, 0);

	return key;
}

bool zebra_tc_class_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_tc_class *c1, *c2;

	c1 = (const struct zebra_tc_class *)arg1;
	c2 = (const struct zebra_tc_class *)arg2;

	if (c1->class.ifindex != c2->class.ifindex)
		return false;

	if (c1->class.handle != c2->class.handle)
		return false;

	return true;
}

static void *tc_class_alloc_intern(void *arg)
{
	struct zebra_tc_class *class;
	struct zebra_tc_class *new;

	class = (struct zebra_tc_class *)arg;

	new = XCALLOC(MTYPE_TC_CLASS, sizeof(*new));

	memcpy(new, class, sizeof(*class));

	return new;
}

void zebra_tc_class_free(struct zebra_tc_class *class)
{
	XFREE(MTYPE_TC_CLASS, class);
}

static struct zebra_tc_class *tc_class_free(struct zebra_tc_class *hash_data,
					    bool free_data)
{
	hash_release(zrouter.class_hash, hash_data);

	if (free_data) {
		zebra_tc_class_free(hash_data);
		return NULL;
	}

	return hash_data;
}

static struct zebra_tc_class *tc_class_release(struct zebra_tc_class *class,
					       bool free_data)
{
	struct zebra_tc_class *lookup;

	lookup = hash_lookup(zrouter.class_hash, class);

	if (!lookup)
		return NULL;

	return tc_class_free(lookup, free_data);
}

void zebra_tc_class_add(struct zebra_tc_class *class)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug(
			"%s: add tc class ifindex %d handle %04x:%04x kind %s",
			__func__, class->class.ifindex,
			(class->class.handle & 0xffff0000u) >> 16,
			class->class.handle & 0x0000ffffu,
			tc_qdisc_kind2str(class->class.kind));

	struct zebra_tc_class *found;
	struct zebra_tc_class *new;

	/*
	 * We find the class in the hash by (ifindex, handle) directly, and by
	 * testing their deep equality to seek out whether it's an update.
	 *
	 * Currently deep equality is not checked since it will be okay to
	 * update the totally same class again.
	 */
	found = hash_lookup(zrouter.class_hash, class);
	new = hash_get(zrouter.class_hash, class, tc_class_alloc_intern);

	if (found)
		(void)dplane_tc_class_update(new);
	else
		(void)dplane_tc_class_add(new);
}

void zebra_tc_class_delete(struct zebra_tc_class *class)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug(
			"%s: delete tc class ifindex %d handle %04x:%04x kind %s",
			__func__, class->class.ifindex,
			(class->class.handle & 0xffff0000u) >> 16,
			class->class.handle & 0x0000ffffu,
			tc_qdisc_kind2str(class->class.kind));

	(void)dplane_tc_class_delete(class);

	if (tc_class_release(class, true))
		zlog_debug("%s: tc class being deleted we know nothing about",
			   __func__);
}

const char *tc_filter_kind2str(uint32_t type)
{
	return lookup_msg(tc_filter_kinds, type, "Unrecognized TFILTER Type");
}

enum tc_qdisc_kind tc_filter_str2kind(const char *type)
{
	return lookup_key(tc_filter_kinds, type, TC_FILTER_UNSPEC);
}

uint32_t zebra_tc_filter_hash_key(const void *arg)
{
	const struct zebra_tc_filter *filter;
	uint32_t key;

	filter = arg;

	key = jhash_3words(filter->filter.ifindex, filter->filter.handle, filter->filter.attach, 0);

	return key;
}

bool zebra_tc_filter_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_tc_filter *f1, *f2;

	f1 = (const struct zebra_tc_filter *)arg1;
	f2 = (const struct zebra_tc_filter *)arg2;

	if (f1->filter.ifindex != f2->filter.ifindex)
		return false;

	if (f1->filter.handle != f2->filter.handle)
		return false;

	if (f1->filter.attach != f2->filter.attach)
		return false;

	return true;
}

struct zebra_tc_filter *zebra_tc_filter_lookup(ifindex_t ifindex, uint32_t handle,
					       enum tc_filter_attach attach)
{
	struct zebra_tc_filter lookup = {};

	lookup.filter.ifindex = ifindex;
	lookup.filter.handle = handle;
	lookup.filter.attach = attach;

	return hash_lookup(zrouter.filter_hash, &lookup);
}

void zebra_tc_filter_free(struct zebra_tc_filter *filter)
{
	XFREE(MTYPE_TC_FILTER, filter);
}

static struct zebra_tc_filter *tc_filter_free(struct zebra_tc_filter *hash_data,
					      bool free_data)
{
	hash_release(zrouter.filter_hash, hash_data);

	if (free_data) {
		zebra_tc_filter_free(hash_data);
		return NULL;
	}

	return hash_data;
}

static struct zebra_tc_filter *tc_filter_release(struct zebra_tc_filter *filter,
						 bool free_data)
{
	struct zebra_tc_filter *lookup;

	lookup = hash_lookup(zrouter.filter_hash, filter);

	if (!lookup)
		return NULL;

	return tc_filter_free(lookup, free_data);
}

static void *tc_filter_alloc_intern(void *arg)
{
	struct zebra_tc_filter *ztf;
	struct zebra_tc_filter *new;

	ztf = (struct zebra_tc_filter *)arg;

	new = XCALLOC(MTYPE_TC_FILTER, sizeof(*new));

	memcpy(new, ztf, sizeof(*ztf));

	return new;
}

void zebra_tc_filter_add(struct zebra_tc_filter *filter)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug(
			"%s: add tc filter ifindex %d priority %u handle %08x kind %s",
			__func__, filter->filter.ifindex,
			filter->filter.priority, filter->filter.handle,
			tc_filter_kind2str(filter->filter.kind));

	struct zebra_tc_filter *found;
	struct zebra_tc_filter *new;

	found = hash_lookup(zrouter.filter_hash, filter);
	if (found) {
		/*
		 * The kernel finds a filter by pref, protocol and parent, so
		 * when any of them changes the update (delete + add with the new
		 * values) would miss the old one.  Delete it with its own data
		 * before the stored copy is overwritten.
		 */
		bool moved = found->filter.priority != filter->filter.priority ||
			     found->filter.protocol != filter->filter.protocol ||
			     found->filter.kind != filter->filter.kind;

		if (moved)
			(void)dplane_tc_filter_delete(found);

		found->filter = filter->filter;
		found->sock = filter->sock;
		found->owner = filter->owner;
		found->status = ZEBRA_TC_STATUS_QUEUED;

		if (moved)
			(void)dplane_tc_filter_add(found);
		else
			(void)dplane_tc_filter_update(found);
		return;
	}

	new = hash_get(zrouter.filter_hash, filter, tc_filter_alloc_intern);
	new->status = ZEBRA_TC_STATUS_QUEUED;
	(void)dplane_tc_filter_add(new);
}

void zebra_tc_filter_forget(struct zebra_tc_filter *filter)
{
	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: forget tc filter ifindex %d priority %u handle %08x", __func__,
			   filter->filter.ifindex, filter->filter.priority, filter->filter.handle);

	tc_filter_release(filter, true);
}

void zebra_tc_filter_delete(struct zebra_tc_filter *filter)
{
	if (IS_ZEBRA_DEBUG_PBR)
		zlog_debug(
			"%s: delete tc filter ifindex %d priority %u handle %08x kind %s",
			__func__, filter->filter.ifindex,
			filter->filter.priority, filter->filter.handle,
			tc_filter_kind2str(filter->filter.kind));

	(void)dplane_tc_filter_delete(filter);

	if (tc_filter_release(filter, true))
		zlog_debug("%s: tc filter being deleted we know nothing about",
			   __func__);
}

/*
 * clsact qdisc bookkeeping.
 *
 * A clsact qdisc has a fixed handle (ffff:), so unlike zebra's htb root
 * qdisc it cannot be marked as zebra's by its handle.  Instead zebra
 * tracks, per interface, whether the kernel already has a clsact qdisc
 * (from the startup dump and RTNLGRP_TC notifications) and whether zebra
 * itself created the one in use.  Only a zebra-created clsact is removed
 * when the last zebra filter on the interface goes away.
 */
PREDECL_HASH(tc_clsact_htab);

struct zebra_tc_clsact {
	struct tc_clsact_htab_item htab_item;

	ifindex_t ifindex;
	uint32_t refcnt;	   /* zebra filters attached to ingress/egress */
	bool owned;		   /* zebra created the qdisc (create confirmed) */
	bool kernel_present;	   /* the kernel reported a clsact qdisc */
	bool create_pending;	   /* exclusive create queued, result not seen */
	bool remove_when_created; /* last filter went away while pending */
};

static int tc_clsact_htab_cmp(const struct zebra_tc_clsact *a, const struct zebra_tc_clsact *b)
{
	return numcmp(a->ifindex, b->ifindex);
}

static uint32_t tc_clsact_htab_hash(const struct zebra_tc_clsact *c)
{
	return jhash_1word(c->ifindex, 0);
}

DECLARE_HASH(tc_clsact_htab, struct zebra_tc_clsact, htab_item, tc_clsact_htab_cmp,
	     tc_clsact_htab_hash);

static struct tc_clsact_htab_head tc_clsact_table[1];

static struct zebra_tc_clsact *tc_clsact_get(ifindex_t ifindex, bool create)
{
	struct zebra_tc_clsact lookup = { .ifindex = ifindex };
	struct zebra_tc_clsact *c;

	c = tc_clsact_htab_find(tc_clsact_table, &lookup);
	if (c || !create)
		return c;

	c = XCALLOC(MTYPE_TC_CLSACT, sizeof(*c));
	c->ifindex = ifindex;
	tc_clsact_htab_add(tc_clsact_table, c);

	return c;
}

static void tc_clsact_maybe_release(struct zebra_tc_clsact *c)
{
	if (c->refcnt || c->kernel_present || c->create_pending)
		return;

	tc_clsact_htab_del(tc_clsact_table, c);
	XFREE(MTYPE_TC_CLSACT, c);
}

static void tc_clsact_qdisc_op(ifindex_t ifindex, bool install)
{
	struct zebra_tc_qdisc qdisc = {};

	qdisc.qdisc.ifindex = ifindex;
	qdisc.qdisc.kind = TC_QDISC_CLSACT;

	if (install)
		(void)dplane_tc_qdisc_install(&qdisc);
	else
		(void)dplane_tc_qdisc_uninstall(&qdisc);
}

struct tc_mark_removed_ctx {
	ifindex_t ifindex;
	unsigned int count;
};

static int tc_mark_removed_walker(struct hash_bucket *b, void *arg)
{
	struct tc_mark_removed_ctx *mc = arg;
	struct zebra_tc_filter *f = b->data;

	if (f->filter.ifindex != mc->ifindex || f->filter.attach == TC_ATTACH_ROOT ||
	    f->status != ZEBRA_TC_STATUS_INSTALLED)
		return HASHWALK_CONTINUE;

	f->status = ZEBRA_TC_STATUS_REMOVED;
	mc->count++;

	return HASHWALK_CONTINUE;
}

static void tc_clsact_kernel_update(ifindex_t ifindex, bool present)
{
	struct zebra_tc_clsact *c = tc_clsact_get(ifindex, present);

	/*
	 * Deleting a clsact qdisc deletes the filters on its hooks: show the
	 * zebra filters there as removed rather than installed, so the lost
	 * classification is visible in show zebra tc.
	 */
	if (!present) {
		struct tc_mark_removed_ctx mc = { .ifindex = ifindex };

		hash_walk(zrouter.filter_hash, tc_mark_removed_walker, &mc);
		if (mc.count && IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: clsact on ifindex %d deleted, %u filter(s) marked removed",
				   __func__, ifindex, mc.count);
	}

	if (!c)
		return;

	if (!present && c->refcnt && c->kernel_present)
		zlog_warn("%s: clsact qdisc on ifindex %d was removed outside zebra; %u zebra filter(s) on it are gone",
			  __func__, ifindex, c->refcnt);

	c->kernel_present = present;
	if (!present)
		c->owned = false;

	tc_clsact_maybe_release(c);
}

void zebra_tc_clsact_ref(ifindex_t ifindex)
{
	struct zebra_tc_clsact *c = tc_clsact_get(ifindex, true);

	if (c->refcnt++ > 0)
		return;

	/* back before our own create was answered: keep the qdisc */
	if (c->create_pending) {
		c->remove_when_created = false;
		return;
	}

	if (c->owned || c->kernel_present) {
		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: ifindex %d already has a clsact qdisc, using it", __func__,
				   ifindex);
		return;
	}

	if (IS_ZEBRA_DEBUG_TC)
		zlog_debug("%s: install clsact qdisc on ifindex %d", __func__, ifindex);

	/*
	 * The create is exclusive (NLM_F_EXCL).  Ownership is taken only when
	 * it succeeds (zebra_tc_dplane_result()): if someone else creates a
	 * clsact first, the create fails with EEXIST and theirs is used, and
	 * never removed, as an external one.
	 */
	c->create_pending = true;
	tc_clsact_qdisc_op(ifindex, true);
}

void zebra_tc_clsact_unref(ifindex_t ifindex, bool ifp_gone)
{
	struct zebra_tc_clsact *c = tc_clsact_get(ifindex, false);

	if (!c || !c->refcnt)
		return;

	if (--c->refcnt > 0)
		return;

	/* Not known yet whether the qdisc is ours: decide on the create result */
	if (c->create_pending) {
		c->remove_when_created = !ifp_gone;
		return;
	}

	if (c->owned) {
		if (!ifp_gone) {
			if (IS_ZEBRA_DEBUG_TC)
				zlog_debug("%s: remove clsact qdisc from ifindex %d", __func__,
					   ifindex);
			tc_clsact_qdisc_op(ifindex, false);
		}
		/* We know it is gone; don't wait for the notification */
		c->owned = false;
		c->kernel_present = false;
	}

	tc_clsact_maybe_release(c);
}

/* Result of the exclusive clsact create queued by zebra_tc_clsact_ref() */
static void tc_clsact_create_result(ifindex_t ifindex, bool success)
{
	struct zebra_tc_clsact *c = tc_clsact_get(ifindex, false);

	if (!c || !c->create_pending)
		return;

	c->create_pending = false;

	if (success) {
		c->owned = true;
		c->kernel_present = true;
		if (c->remove_when_created && !c->refcnt) {
			tc_clsact_qdisc_op(ifindex, false);
			c->owned = false;
			c->kernel_present = false;
		}
	} else {
		/*
		 * Most likely EEXIST: a clsact appeared before our create.  Use it
		 * as an external qdisc; zebra never removes it.
		 */
		if (IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: clsact create on ifindex %d failed, treating the qdisc as external",
				   __func__, ifindex);
		c->owned = false;
		if (c->refcnt)
			c->kernel_present = true;
	}

	c->remove_when_created = false;
	tc_clsact_maybe_release(c);
}

void zebra_tc_clsact_init(void)
{
	tc_clsact_htab_init(tc_clsact_table);
}

void zebra_tc_clsact_terminate(void)
{
	struct zebra_tc_clsact *c;

	while ((c = tc_clsact_htab_pop(tc_clsact_table)))
		XFREE(MTYPE_TC_CLSACT, c);
	tc_clsact_htab_fini(tc_clsact_table);
}

const char *zebra_tc_status2str(enum zebra_tc_status status)
{
	switch (status) {
	case ZEBRA_TC_STATUS_QUEUED:
		return "queued";
	case ZEBRA_TC_STATUS_INSTALLED:
		return "installed";
	case ZEBRA_TC_STATUS_FAILED:
		return "failed";
	case ZEBRA_TC_STATUS_REMOVED:
		return "removed";
	}

	return "unknown";
}

/*
 * Results of TC dataplane operations.  Only filter results are kept: they
 * are what `show zebra tc` reports per filter.
 */
void zebra_tc_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	enum zebra_dplane_result res = dplane_ctx_get_status(ctx);
	struct zebra_tc_filter *f;

	/* a failed exclusive clsact create is expected (EEXIST), not an error */
	if (op == DPLANE_OP_TC_QDISC_INSTALL &&
	    dplane_ctx_tc_qdisc_get_kind(ctx) == TC_QDISC_CLSACT) {
		tc_clsact_create_result(dplane_ctx_get_ifindex(ctx),
					res == ZEBRA_DPLANE_REQUEST_SUCCESS);
		return;
	}

	if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
		zlog_warn("%s: %s failed on ifindex %d (%s)", __func__, dplane_op2str(op),
			  dplane_ctx_get_ifindex(ctx), dplane_res2str(res));

	if (op != DPLANE_OP_TC_FILTER_ADD && op != DPLANE_OP_TC_FILTER_UPDATE)
		return;

	f = zebra_tc_filter_lookup(dplane_ctx_get_ifindex(ctx),
				   dplane_ctx_tc_filter_get_handle(ctx),
				   dplane_ctx_tc_filter_get_attach(ctx));
	if (f)
		f->status = (res == ZEBRA_DPLANE_REQUEST_SUCCESS) ? ZEBRA_TC_STATUS_INSTALLED
								  : ZEBRA_TC_STATUS_FAILED;
}

static const char *tc_attach2str(enum tc_filter_attach attach)
{
	switch (attach) {
	case TC_ATTACH_ROOT:
		return "root";
	case TC_ATTACH_INGRESS:
		return "ingress";
	case TC_ATTACH_EGRESS:
		return "egress";
	}

	return "unknown";
}

static const char *tc_ifname(ifindex_t ifindex)
{
	struct interface *ifp;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT), ifindex);

	return ifp ? ifp->name : "unknown";
}

struct tc_show_ctx {
	struct vty *vty;
	ifindex_t ifindex;
	json_object *json;
};

static void tc_show_flower(struct vty *vty, json_object *jf, const struct tc_filter *f)
{
	const struct tc_flower *fl = &f->u.flower;

	if (fl->filter_bm & TC_FLOWER_VLAN_ID) {
		if (jf)
			json_object_int_add(jf, "vlanId", fl->vlan_id);
		else
			vty_out(vty, " vlan_id %u", fl->vlan_id);
	}
	if (fl->filter_bm & TC_FLOWER_VLAN_PRIO) {
		if (jf)
			json_object_int_add(jf, "vlanPrio", fl->vlan_prio);
		else
			vty_out(vty, " vlan_prio %u", fl->vlan_prio);
	}
	if (fl->filter_bm & TC_FLOWER_VLAN_ETH_TYPE) {
		if (jf)
			json_object_int_add(jf, "vlanEthType", fl->vlan_eth_type);
		else
			vty_out(vty, " vlan_ethtype 0x%04x", fl->vlan_eth_type);
	}
	if (fl->filter_bm & TC_FLOWER_IP_PROTOCOL) {
		if (jf)
			json_object_int_add(jf, "ipProto", fl->ip_proto);
		else
			vty_out(vty, " ip_proto %u", fl->ip_proto);
	}
	if (fl->filter_bm & TC_FLOWER_SRC_IP) {
		if (jf)
			json_object_string_addf(jf, "srcIp", "%pFX", &fl->src_ip);
		else
			vty_out(vty, " src_ip %pFX", &fl->src_ip);
	}
	if (fl->filter_bm & TC_FLOWER_DST_IP) {
		if (jf)
			json_object_string_addf(jf, "dstIp", "%pFX", &fl->dst_ip);
		else
			vty_out(vty, " dst_ip %pFX", &fl->dst_ip);
	}
	if (fl->filter_bm & TC_FLOWER_SRC_PORT) {
		if (jf) {
			json_object_int_add(jf, "srcPortMin", fl->src_port_min);
			json_object_int_add(jf, "srcPortMax", fl->src_port_max);
		} else
			vty_out(vty, " src_port %u-%u", fl->src_port_min, fl->src_port_max);
	}
	if (fl->filter_bm & TC_FLOWER_DST_PORT) {
		if (jf) {
			json_object_int_add(jf, "dstPortMin", fl->dst_port_min);
			json_object_int_add(jf, "dstPortMax", fl->dst_port_max);
		} else
			vty_out(vty, " dst_port %u-%u", fl->dst_port_min, fl->dst_port_max);
	}
	if (fl->filter_bm & TC_FLOWER_DSFIELD) {
		if (jf) {
			json_object_int_add(jf, "ipTos", fl->dsfield);
			json_object_int_add(jf, "ipTosMask", fl->dsfield_mask);
		} else
			vty_out(vty, " ip_tos 0x%02x/0x%02x", fl->dsfield, fl->dsfield_mask);
	}
}

static int tc_show_filter_walker(struct hash_bucket *b, void *data)
{
	struct tc_show_ctx *sc = data;
	struct zebra_tc_filter *zf = b->data;
	const struct tc_filter *f = &zf->filter;
	struct vty *vty = sc->vty;
	json_object *jf = NULL;

	if (sc->ifindex != IFINDEX_INTERNAL && f->ifindex != sc->ifindex)
		return HASHWALK_CONTINUE;

	if (sc->json) {
		jf = json_object_new_object();
		json_object_string_add(jf, "interface", tc_ifname(f->ifindex));
		json_object_int_add(jf, "ifindex", f->ifindex);
		json_object_string_add(jf, "attach", tc_attach2str(f->attach));
		json_object_int_add(jf, "pref", f->priority);
		json_object_int_add(jf, "protocol", f->protocol);
		json_object_string_addf(jf, "handle", "0x%08x", f->handle);
		json_object_string_add(jf, "kind", tc_filter_kind2str(f->kind));
		json_object_string_add(jf, "owner",
				       zf->owner == ZEBRA_TC_OWNER_PBR ? "pbr" : "zapi");
		json_object_string_add(jf, "status", zebra_tc_status2str(zf->status));
	} else {
		vty_out(vty, "  %s %s pref %u protocol 0x%04x handle 0x%08x %s owner %s [%s]\n",
			tc_ifname(f->ifindex), tc_attach2str(f->attach), f->priority, f->protocol,
			f->handle, tc_filter_kind2str(f->kind),
			zf->owner == ZEBRA_TC_OWNER_PBR ? "pbr" : "zapi",
			zebra_tc_status2str(zf->status));
		vty_out(vty, "    match:");
	}

	if (f->kind == TC_FILTER_FLOWER)
		tc_show_flower(vty, jf, f);

	if (f->has_action) {
		if (jf) {
			json_object *ja = json_object_new_object();

			json_object_string_add(ja, "kind", "skbedit");
			if (f->skbedit.set_priority)
				json_object_int_add(ja, "priority", f->skbedit.priority);
			if (f->skbedit.set_mark) {
				json_object_string_addf(ja, "mark", "0x%x", f->skbedit.mark);
				json_object_string_addf(ja, "markMask", "0x%x",
							f->skbedit.mark_mask);
			}
			json_object_object_add(jf, "action", ja);
		} else {
			vty_out(vty, "\n    action: skbedit");
			if (f->skbedit.set_priority)
				vty_out(vty, " priority %u", f->skbedit.priority);
			if (f->skbedit.set_mark)
				vty_out(vty, " mark 0x%x/0x%x", f->skbedit.mark,
					f->skbedit.mark_mask);
		}
	} else if (f->kind == TC_FILTER_FLOWER) {
		if (jf)
			json_object_string_addf(jf, "classid", "%x:%x", TC_QDISC_MAJOR_ZEBRA >> 16,
						f->u.flower.classid);
		else
			vty_out(vty, "\n    classid %x:%x", TC_QDISC_MAJOR_ZEBRA >> 16,
				f->u.flower.classid);
	}

	if (jf)
		json_object_array_add(sc->json, jf);
	else
		vty_out(vty, "\n");

	return HASHWALK_CONTINUE;
}

static int tc_show_qdisc_walker(struct hash_bucket *b, void *data)
{
	struct tc_show_ctx *sc = data;
	struct zebra_tc_qdisc *q = b->data;

	if (sc->ifindex != IFINDEX_INTERNAL && q->qdisc.ifindex != sc->ifindex)
		return HASHWALK_CONTINUE;

	vty_out(sc->vty, "  %s root %s handle %x:\n", tc_ifname(q->qdisc.ifindex),
		tc_qdisc_kind2str(q->qdisc.kind), TC_QDISC_MAJOR_ZEBRA >> 16);

	return HASHWALK_CONTINUE;
}

static const char *tc_clsact_owner2str(const struct zebra_tc_clsact *c)
{
	if (c->owned)
		return "zebra";
	if (c->create_pending)
		return "pending";
	return "external";
}

static void tc_show_clsact(struct tc_show_ctx *sc, const struct zebra_tc_clsact *c)
{
	json_object *jc;

	if (sc->ifindex != IFINDEX_INTERNAL && c->ifindex != sc->ifindex)
		return;

	if (sc->json) {
		jc = json_object_new_object();
		json_object_string_add(jc, "interface", tc_ifname(c->ifindex));
		json_object_int_add(jc, "ifindex", c->ifindex);
		json_object_int_add(jc, "filters", c->refcnt);
		json_object_string_add(jc, "owner", tc_clsact_owner2str(c));
		json_object_array_add(sc->json, jc);
	} else
		vty_out(sc->vty, "  %s clsact filters %u owner %s\n", tc_ifname(c->ifindex),
			c->refcnt, tc_clsact_owner2str(c));
}

void zebra_tc_show(struct vty *vty, ifindex_t ifindex, json_object *json)
{
	struct tc_show_ctx sc = { .vty = vty, .ifindex = ifindex };
	struct zebra_tc_clsact *c;
	json_object *jq = NULL, *jf = NULL;

	if (json) {
		jq = json_object_new_array();
		jf = json_object_new_array();
		sc.json = jq;
		frr_each (tc_clsact_htab, tc_clsact_table, c)
			tc_show_clsact(&sc, c);
		sc.json = jf;
		hash_walk(zrouter.filter_hash, tc_show_filter_walker, &sc);
		json_object_object_add(json, "clsact", jq);
		json_object_object_add(json, "filters", jf);
		return;
	}

	vty_out(vty, "Qdiscs:\n");
	hash_walk(zrouter.qdisc_hash, tc_show_qdisc_walker, &sc);
	frr_each (tc_clsact_htab, tc_clsact_table, c)
		tc_show_clsact(&sc, c);
	vty_out(vty, "Filters:\n");
	hash_walk(zrouter.filter_hash, tc_show_filter_walker, &sc);
}

/*
 * Decision-side handler for TC qdisc kernel notifications. Runs in
 * the zebra master pthread off a DPLANE_OP_TC_QDISC_NOTIFY context
 * that the dplane thread parsed and translated into a generic
 * dplane_tc_qdisc_notify_e value. The dplane is purely the decoder;
 * all policy lives here.
 */
void zebra_tc_qdisc_handle_notify(struct zebra_dplane_ctx *ctx)
{
	enum dplane_tc_qdisc_notify_e notify_type = dplane_ctx_tc_qdisc_notify_get_type(ctx);
	uint32_t major = dplane_ctx_tc_qdisc_notify_get_major_handle(ctx);
	bool startup = dplane_ctx_get_startup(ctx);
	ifindex_t ifindex = dplane_ctx_tc_qdisc_notify_get_ifindex(ctx);
	int kind = dplane_ctx_tc_qdisc_notify_get_kind(ctx);
	struct zebra_tc_qdisc qdisc = { 0 };

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s: %s ifindex %d major 0x%x kind %s startup %d", __func__,
			   notify_type == DPLANE_TC_QDISC_NOTIFY_NEW ? "new" : "del", ifindex,
			   major, tc_qdisc_kind2str(kind), startup);

	/* Track which interfaces already have a clsact qdisc */
	if (kind == TC_QDISC_CLSACT) {
		tc_clsact_kernel_update(ifindex, notify_type == DPLANE_TC_QDISC_NOTIFY_NEW);
		return;
	}

	/*
	 * Only act on new-qdisc notifications observed during the
	 * startup read: if the kernel still has a qdisc whose major
	 * handle matches zebra's "owned" value, that's a leftover from
	 * a previous zebra run and we should clean it up. Anything
	 * else (other major handles, deletes, post-startup
	 * notifications) is informational only.
	 */
	if (notify_type != DPLANE_TC_QDISC_NOTIFY_NEW || !startup || major != TC_QDISC_MAJOR_ZEBRA)
		return;

	qdisc.qdisc.ifindex = ifindex;
	qdisc.qdisc.kind = kind;

	dplane_tc_qdisc_uninstall(&qdisc);
}
