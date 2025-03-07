// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-2018  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "atomlist.h"
#include "seqlock.h"
#include "monotime.h"
#include "printfrr.h"

/*
 * maybe test:
 * - alist_del_hint
 * - alist_next_safe
 * - asort_del_hint
 * - asort_next_safe
 */

static struct seqlock sqlo;

PREDECL_ATOMLIST(alist);
PREDECL_ATOMSORT_UNIQ(asort);
struct item {
	uint64_t val1;
	struct alist_item chain;
	struct asort_item sortc;
	uint64_t val2;
};
DECLARE_ATOMLIST(alist, struct item, chain);

static int icmp(const struct item *a, const struct item *b);
DECLARE_ATOMSORT_UNIQ(asort, struct item, sortc, icmp);

static int icmp(const struct item *a, const struct item *b)
{
	if (a->val1 > b->val1)
		return 1;
	if (a->val1 < b->val1)
		return -1;
	return 0;
}

#define NITEM 10000
struct item itm[NITEM];

static struct alist_head ahead;
static struct asort_head shead;

#define NTHREADS 4
static struct testthread {
	pthread_t pt;
	struct seqlock sqlo;
	_Atomic size_t counter, nullops;
} thr[NTHREADS];

struct testrun {
	struct testrun *next;
	int lineno;
	const char *desc;
	ssize_t prefill;
	bool sorted;
	void (*func)(unsigned int offset);
};
struct testrun *runs = NULL;

#define NOCLEAR -1

#define deftestrun(name, _desc, _prefill, _sorted) \
static void trfunc_##name(unsigned int offset); \
struct testrun tr_##name = { \
	.desc = _desc, \
	.lineno = __LINE__, \
	.prefill = _prefill, \
	.func = &trfunc_##name, \
	.sorted = _sorted }; \
static void __attribute__((constructor)) trsetup_##name(void) \
{ \
	struct testrun **inspos = &runs; \
	while (*inspos && (*inspos)->lineno < tr_##name.lineno) \
		inspos = &(*inspos)->next; \
	tr_##name.next = *inspos; \
	*inspos = &tr_##name; \
} \
static void trfunc_##name(unsigned int offset) \
{ \
	size_t i = 0, n = 0;

#define endtestrun                                                             \
	atomic_store_explicit(&thr[offset].counter, i, memory_order_seq_cst);  \
	atomic_store_explicit(&thr[offset].nullops, n, memory_order_seq_cst);  \
	}

deftestrun(add, "add vs. add", 0, false)
	for (; i < NITEM / NTHREADS; i++)
		alist_add_head(&ahead, &itm[i * NTHREADS + offset]);
endtestrun

deftestrun(del, "del vs. del", NOCLEAR, false)
	for (; i < NITEM / NTHREADS / 10; i++)
		alist_del(&ahead, &itm[i * NTHREADS + offset]);
endtestrun

deftestrun(addtail, "add_tail vs. add_tail", 0, false)
	for (; i < NITEM / NTHREADS; i++)
		alist_add_tail(&ahead, &itm[i * NTHREADS + offset]);
endtestrun

deftestrun(pop, "pop vs. pop", NOCLEAR, false)
	for (; i < NITEM / NTHREADS; )
		if (alist_pop(&ahead))
			i++;
		else
			n++;
endtestrun

deftestrun(headN_vs_pop1, "add_head(N) vs. pop(1)", 1, false);
	if (offset == 0) {
		struct item *dr = NULL;

		for (i = n = 0; i < NITEM; ) {
			dr = alist_pop(&ahead);
			if (dr)
				i++;
			else
				n++;
		}
	} else {
		for (i = offset; i < NITEM; i += NTHREADS)
			alist_add_head(&ahead, &itm[i]);
		i = 0;
	}
endtestrun

deftestrun(head1_vs_popN, "add_head(1) vs. pop(N)", 0, false);
	if (offset < NTHREADS - 1) {
		struct item *dr = NULL;

		for (i = n = 0; i < NITEM / NTHREADS; ) {
			dr = alist_pop(&ahead);
			if (dr)
				i++;
			else
				n++;
		}
	} else {
		for (i = 0; i < NITEM; i++)
			alist_add_head(&ahead, &itm[i]);
		i = 0;
	}
endtestrun

deftestrun(headN_vs_popN, "add_head(N) vs. pop(N)", NTHREADS / 2, false)
	if (offset < NTHREADS / 2) {
		struct item *dr = NULL;

		for (i = n = 0; i < NITEM * 2 / NTHREADS; ) {
			dr = alist_pop(&ahead);
			if (dr)
				i++;
			else
				n++;
		}
	} else {
		for (i = offset; i < NITEM; i += NTHREADS)
			alist_add_head(&ahead, &itm[i]);
		i = 0;
	}
endtestrun

deftestrun(tailN_vs_pop1, "add_tail(N) vs. pop(1)", 1, false)
	if (offset == 0) {
		struct item *dr = NULL;

		for (i = n = 0; i < NITEM - (NITEM / NTHREADS); ) {
			dr = alist_pop(&ahead);
			if (dr)
				i++;
			else
				n++;
		}
	} else {
		for (i = offset; i < NITEM; i += NTHREADS)
			alist_add_tail(&ahead, &itm[i]);
		i = 0;
	}
endtestrun

deftestrun(tail1_vs_popN, "add_tail(1) vs. pop(N)", 0, false)
	if (offset < NTHREADS - 1) {
		struct item *dr = NULL;

		for (i = n = 0; i < NITEM / NTHREADS; ) {
			dr = alist_pop(&ahead);
			if (dr)
				i++;
			else
				n++;
		}
	} else {
		for (i = 0; i < NITEM; i++)
			alist_add_tail(&ahead, &itm[i]);
		i = 0;
	}
endtestrun

deftestrun(sort_add, "add_sort vs. add_sort", 0, true)
	for (; i < NITEM / NTHREADS / 10; i++)
		asort_add(&shead, &itm[i * NTHREADS + offset]);
endtestrun

deftestrun(sort_del, "del_sort vs. del_sort", NOCLEAR, true)
	for (; i < NITEM / NTHREADS / 10; i++)
		asort_del(&shead, &itm[i * NTHREADS + offset]);
endtestrun

deftestrun(sort_add_del, "add_sort vs. del_sort", NTHREADS / 2, true)
	if (offset < NTHREADS / 2) {
		for (; i < NITEM / NTHREADS / 10; i++)
			asort_del(&shead, &itm[i * NTHREADS + offset]);
	} else {
		for (; i < NITEM / NTHREADS / 10; i++)
			asort_add(&shead, &itm[i * NTHREADS + offset]);
	}
endtestrun

static void *thr1func(void *arg)
{
	struct testthread *p = arg;
	unsigned int offset = (unsigned int)(p - &thr[0]);
	seqlock_val_t sv;
	struct testrun *tr;

	for (tr = runs; tr; tr = tr->next) {
		sv = seqlock_bump(&p->sqlo) - SEQLOCK_INCR;
		seqlock_wait(&sqlo, sv);

		tr->func(offset);
	}
	seqlock_bump(&p->sqlo);

	return NULL;
}

static void clear_list(size_t prefill)
{
	size_t i;

	memset(&ahead, 0, sizeof(ahead));
	memset(&shead, 0, sizeof(shead));
	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++) {
		itm[i].val1 = itm[i].val2 = i;
		if ((i % NTHREADS) < prefill) {
			alist_add_tail(&ahead, &itm[i]);
			asort_add(&shead, &itm[i]);
		}
	}
}

static void run_tr(struct testrun *tr)
{
	const char *desc = tr->desc;
	struct timeval tv;
	int64_t delta;
	seqlock_val_t sv;
	size_t c = 0, s = 0, n = 0;
	struct item *item, *prev, dummy;

	printfrr("[%02u] %35s %s\n", seqlock_cur(&sqlo) >> 2, "", desc);
	fflush(stdout);

	if (tr->prefill != NOCLEAR)
		clear_list(tr->prefill);

	monotime(&tv);
	sv = seqlock_bump(&sqlo) - SEQLOCK_INCR;
	for (size_t i = 0; i < NTHREADS; i++) {
		seqlock_wait(&thr[i].sqlo, seqlock_cur(&sqlo));
		s += atomic_load_explicit(&thr[i].counter, memory_order_seq_cst);
		n += atomic_load_explicit(&thr[i].nullops, memory_order_seq_cst);
		atomic_store_explicit(&thr[i].counter, 0, memory_order_seq_cst);
		atomic_store_explicit(&thr[i].nullops, 0, memory_order_seq_cst);
	}

	delta = monotime_since(&tv, NULL);
	if (tr->sorted) {
		uint64_t prevval = 0;

		frr_each(asort, &shead, item) {
			assert(item->val1 >= prevval);
			prevval = item->val1;
			c++;
		}
		assert(c == asort_count(&shead));
	} else {
		prev = &dummy;
		frr_each(alist, &ahead, item) {
			assert(item != prev);
			prev = item;
			c++;
			assert(c <= NITEM);
		}
		assert(c == alist_count(&ahead));
	}
	printfrr("\033[1A[%02u] %9"PRId64"us c=%5zu s=%5zu n=%5zu %s\n",
		sv >> 2, delta, c, s, n, desc);
}

#ifdef BASIC_TESTS
static void dump(const char *lbl)
{
	struct item *item, *safe;
	size_t ctr = 0;

	printfrr("dumping %s:\n", lbl);
	frr_each_safe(alist, &ahead, item) {
		printfrr("%s %3zu %p %3"PRIu64" %3"PRIu64"\n", lbl, ctr++,
				(void *)item, item->val1, item->val2);
	}
}

static void basic_tests(void)
{
	size_t i;

	memset(&ahead, 0, sizeof(ahead));
	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val1 = itm[i].val2 = i;

	assert(alist_first(&ahead) == NULL);
	dump("");
	alist_add_head(&ahead, &itm[0]);
	dump("");
	alist_add_head(&ahead, &itm[1]);
	dump("");
	alist_add_tail(&ahead, &itm[2]);
	dump("");
	alist_add_tail(&ahead, &itm[3]);
	dump("");
	alist_del(&ahead, &itm[1]);
	dump("");
	printfrr("POP: %p\n", alist_pop(&ahead));
	dump("");
	printfrr("POP: %p\n", alist_pop(&ahead));
	printfrr("POP: %p\n", alist_pop(&ahead));
	printfrr("POP: %p\n", alist_pop(&ahead));
	printfrr("POP: %p\n", alist_pop(&ahead));
	dump("");
}
#else
#define basic_tests() do { } while (0)
#endif

int main(int argc, char **argv)
{
	size_t i;

	basic_tests();

	seqlock_init(&sqlo);
	seqlock_acquire_val(&sqlo, SEQLOCK_STARTVAL);

	for (i = 0; i < NTHREADS; i++) {
		seqlock_init(&thr[i].sqlo);
		seqlock_acquire(&thr[i].sqlo, &sqlo);
		thr[i].counter = 0;
		thr[i].nullops = 0;

		pthread_create(&thr[i].pt, NULL, thr1func, &thr[i]);
	}

	struct testrun *tr;

	for (tr = runs; tr; tr = tr->next)
		run_tr(tr);

	for (i = 0; i < NTHREADS; i++)
		pthread_join(thr[i].pt, NULL);

	return 0;
}
