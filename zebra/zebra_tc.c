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

#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_tc.h"
#include "zebra/debug.h"

DEFINE_MTYPE_STATIC(ZEBRA, TC_QDISC, "TC queue discipline");
DEFINE_MTYPE_STATIC(ZEBRA, TC_CLASS, "TC class");
DEFINE_MTYPE_STATIC(ZEBRA, TC_FILTER, "TC filter");

const struct message tc_qdisc_kinds[] = {
	{TC_QDISC_HTB, "htb"},
	{TC_QDISC_NOQUEUE, "noqueue"},
	{0},
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
	hash_walk(zrouter.rules_hash, &tc_qdisc_lookup_ifindex_walker, &lookup);

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

	key = jhash_2words(filter->filter.ifindex, filter->filter.handle, 0);

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

	return true;
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
	new = hash_get(zrouter.filter_hash, filter, tc_filter_alloc_intern);

	if (found)
		(void)dplane_tc_filter_update(new);
	else
		(void)dplane_tc_filter_add(new);
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
