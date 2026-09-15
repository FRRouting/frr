// SPDX-License-Identifier: ISC
/* lock-free hash table tests
 * Copyright (c) 2025-2026  David Lamparter, for NetDEF, Inc.
 */

/* this test must be run manually, and is only useful if you understand the
 * actual lock-free hash table code.  There are a lot of variables that need
 * fine tuning in order to trigger specific conditions that might cause bugs.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdalign.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sched.h>
#include <semaphore.h>
#include <getopt.h>

/* gettid */
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#ifdef linux
#include <sys/syscall.h>
#endif

#include "lib/seqlock.h"
#include "lib/monotime.h"
#include "lib/typesafe.h"
#include "lib/printfrr.h"
#include "lib/frrcu.h"
#include "lib/jhash.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/atomptr.h"

#include "tests/helpers/c/prng.h"

#define CACHELINESIZE 64

#define thread_local _Thread_local __attribute__((tls_model("local-exec")))
#define alignas	     _Alignas
#define atomic	     _Atomic

#define DEBUG_ATOMHASH

struct rcu_atomhash_shrink;
struct amop_journal;

static void hijack_atomhash_unlink_level(struct rcu_atomhash_shrink *arg);
static void hijack_atomhash_free_level(struct rcu_atomhash_shrink *arg);
#define atomhash_rcu_call(func, ptr, field) rcu_call(hijack_##func, ptr, field)

/****************************************
 * build mode 1: atomic ops slowed down *
 ****************************************/
#ifdef TEST_HIJACK_ATOMICS
/* can't be enabled at the same time */
#undef TEST_JOURNAL_ATOMICS
struct slow_parameters;
static struct slow_parameters general;
static struct slow_parameters resize;
static __attribute__((noinline)) void slowdown_rd(const struct slow_parameters *params);
static __attribute__((noinline)) void slowdown_op(const struct slow_parameters *params);

/* clang-format off */
#define atomic__load(...)		({ slowdown_rd(&atomhash_part); atomic_load_explicit(__VA_ARGS__); })

#define atomic__store(...)		({ slowdown_op(&atomhash_part); atomic_store_explicit(__VA_ARGS__); })
#define atomic__exchange(...)		({ slowdown_op(&atomhash_part); atomic_exchange_explicit(__VA_ARGS__); })
#define atomic__cmpxchg_strong(...)	({ slowdown_op(&atomhash_part); atomic_compare_exchange_strong_explicit(__VA_ARGS__); })
#define atomic__cmpxchg_weak(...)	({ slowdown_op(&atomhash_part); atomic_compare_exchange_weak_explicit(__VA_ARGS__); })
#define atomic__fetch_or(...)		({ slowdown_op(&atomhash_part); atomic_fetch_or_explicit(__VA_ARGS__); })
#define atomic__fetch_and(...)		({ slowdown_op(&atomhash_part); atomic_fetch_and_explicit(__VA_ARGS__); })
#define atomic__fetch_add(...)		({ slowdown_op(&atomhash_part); atomic_fetch_add_explicit(__VA_ARGS__); })
#define atomic__fetch_sub(...)		({ slowdown_op(&atomhash_part); atomic_fetch_sub_explicit(__VA_ARGS__); })
/* clang-format on */

/***************************************
 * build mode 2: atomic ops journalled *
 ***************************************/
#elif defined(TEST_JOURNAL_ATOMICS)
#ifndef AMOP_JSIZE
#define AMOP_JSIZE 1048576
#endif

enum amop_journal_ent {
	AMOP_STORE,
	AMOP_XCHG,
	AMOP_CMPXCHG_SUCCESS,
	AMOP_CMPXCHG_FAIL,
	AMOP_FETCH_OR,
	AMOP_FETCH_AND,
};
struct amop_journal {
	enum amop_journal_ent op;
	uint32_t pos;
	void *addr;
	uint64_t vals[3];
};

static thread_local struct amop_journal *amop_journal;
static thread_local size_t amop_pos;
/* for gdb */
int amop_jsize = AMOP_JSIZE;

static inline struct amop_journal *amop_setup(void)
{
	amop_journal = calloc(AMOP_JSIZE, sizeof(amop_journal[0]));
	return amop_journal;
}

static inline void amop_record(enum amop_journal_ent op, void *addr, uint64_t val1, uint64_t val2,
			       uint64_t val3)
{
	struct amop_journal *je = &amop_journal[(amop_pos++) & (AMOP_JSIZE - 1)];

	je->op = op;
	je->pos = amop_pos >> 20;
	je->addr = addr;
	je->vals[0] = val1;
	je->vals[1] = val2;
	je->vals[2] = val3;
}

/* load, fetch_add & fetch_sub just waste journal entries */
#define atomic__load(...)      ({ atomic_load_explicit(__VA_ARGS__); })
#define atomic__fetch_add(...) ({ atomic_fetch_add_explicit(__VA_ARGS__); })
#define atomic__fetch_sub(...) ({ atomic_fetch_sub_explicit(__VA_ARGS__); })

#define atomic__store(ptr, val, o)                                                                \
	({                                                                                        \
		__auto_type ptr_ = (ptr);                                                         \
		__auto_type val_ = (val);                                                         \
		atomic_store_explicit(ptr_, val_, o);                                             \
		amop_record(AMOP_STORE, ptr_, val_, 0, 0);                                        \
	})
#define atomic__exchange(ptr, val, o)                                                             \
	({                                                                                        \
		__auto_type ptr_ = (ptr);                                                         \
		__auto_type val_ = (val);                                                         \
		__auto_type ret = atomic_exchange_explicit(ptr_, val_, o);                        \
		amop_record(AMOP_XCHG, ptr_, val_, ret, 0);                                       \
		ret;                                                                              \
	})
#define atomic__cmpxchg_strong(ptr, expect, want, o1, o2)                                         \
	({                                                                                        \
		__auto_type ptr_ = (ptr);                                                         \
		__auto_type expect_ = (expect);                                                   \
		__auto_type before_ = *expect_;                                                   \
		__auto_type want_ = (want);                                                       \
		__auto_type ret = atomic_compare_exchange_strong_explicit(ptr_, expect_, want_,   \
									  o1, o2);                \
		amop_record(ret ? AMOP_CMPXCHG_SUCCESS : AMOP_CMPXCHG_FAIL, ptr_, before_, want_, \
			    *expect_);                                                            \
		ret;                                                                              \
	})
#define atomic__fetch_or(ptr, val, o)                                                             \
	({                                                                                        \
		__auto_type ptr_ = (ptr);                                                         \
		__auto_type val_ = (val);                                                         \
		__auto_type ret = atomic_fetch_or_explicit(ptr_, val_, o);                        \
		amop_record(AMOP_FETCH_OR, ptr_, val_, ret, 0);                                   \
		ret;                                                                              \
	})
#define atomic__fetch_and(ptr, val, o)                                                            \
	({                                                                                        \
		__auto_type ptr_ = (ptr);                                                         \
		__auto_type val_ = (val);                                                         \
		__auto_type ret = atomic_fetch_and_explicit(ptr_, val_, o);                       \
		amop_record(AMOP_FETCH_AND, ptr_, val_, ret, 0);                                  \
		ret;                                                                              \
	})

/* suppress definitions in atomhash.c */
#define TEST_HIJACK_ATOMICS
#endif /* TEST_HIJACK_ATOMICS, TEST_JOURNAL_ATOMICS */

#ifndef TEST_JOURNAL_ATOMICS
#define amop_setup() NULL
#endif

#define ATOMHASH_GROW_STOCHASTIC_THRESHOLD 3

/* dynamic linking works without this.  static linking would get symbol
 * redefinition errors.  rename atomhash.c's public symbols to avoid that
 */
#define atomhash_add   t_atomhash_add
#define atomhash_del   t_atomhash_del
#define atomhash_fini  t_atomhash_fini
#define atomhash_first t_atomhash_first
#define atomhash_get   t_atomhash_get
#define atomhash_init  t_atomhash_init
#define atomhash_next  t_atomhash_next
#define atomhash_pop   t_atomhash_pop

/* prevent inlining */
#define extern __attribute__((noinline)) extern

/*****************************************************************************/
#include "lib/atomhash.h"
#undef extern
#include "lib/atomhash.c"
/*****************************************************************************/


#ifdef TEST_HIJACK_ATOMICS
/* undo hijack */
/* clang-format off */
#undef atomic__load
#undef atomic__store
#undef atomic__exchange
#undef atomic__cmpxchg_strong
#undef atomic__cmpxchg_weak
#undef atomic__fetch_or
#undef atomic__fetch_and
#undef atomic__fetch_add
#undef atomic__fetch_sub
#define atomic__load           atomic_load_explicit
#define atomic__store          atomic_store_explicit
#define atomic__exchange       atomic_exchange_explicit
#define atomic__cmpxchg_strong atomic_compare_exchange_strong_explicit
#define atomic__cmpxchg_weak   atomic_compare_exchange_weak_explicit
#define atomic__fetch_or       atomic_fetch_or_explicit
#define atomic__fetch_and      atomic_fetch_and_explicit
#define atomic__fetch_add      atomic_fetch_add_explicit
#define atomic__fetch_sub      atomic_fetch_sub_explicit
/* clang-format on */
#endif /* TEST_HIJACK_ATOMICS */

#ifdef TEST_JOURNAL_ATOMICS
#undef TEST_HIJACK_ATOMICS
#endif

static uint32_t prng_seed;
thread_local static struct prng *prng;

enum slow_level {
	SLOW_NONE = 0,
	SLOW_LOOP,
	SLOW_LOOP1,
	SLOW_LOOP2,
	SLOW_SYSCALL,
	SLOW_YIELD,
};

static const char *const slow_names[] = {
	/* clang-format off */
	[SLOW_NONE] = "none",
	[SLOW_LOOP] = "loop",
	[SLOW_LOOP1] = "loop+",
	[SLOW_LOOP2] = "loop++",
	[SLOW_SYSCALL] = "syscall",
	[SLOW_YIELD] = "sched_yield",
	/* clang-format on */
};

static inline void slowdown(enum slow_level level)
{
	int r = 0;

	switch (level) {
	case SLOW_NONE:
		return;
	case SLOW_LOOP2:
		r += 100 + (prng_rand(prng) & 0x7ff);
		fallthrough;
	case SLOW_LOOP1:
		r += 20 + (prng_rand(prng) & 0x7f);
#pragma GCC unroll 0
		for (int i = 0; i < r; i++)
			asm volatile("");
		break;
	case SLOW_LOOP:
		r += prng_rand(prng) & 0x3f;
#pragma GCC unroll 0
		for (int i = 0; i < r; i++)
			asm volatile("");
		return;
	case SLOW_SYSCALL:
		getsid(0);
		return;
	case SLOW_YIELD:
		sched_yield();
		return;
	}
}

/* slowdown for atomic ops */

#ifdef TEST_HIJACK_ATOMICS
struct slow_parameters {
	enum slow_level rd, op;
};
static struct slow_parameters general = { SLOW_NONE, SLOW_NONE };
static struct slow_parameters resize = { SLOW_NONE, SLOW_NONE };

static __attribute__((noinline)) void slowdown_rd(const struct slow_parameters *params)
{
	slowdown(params->rd);
}

static __attribute__((noinline)) void slowdown_op(const struct slow_parameters *params)
{
	slowdown(params->op);
}
#endif /* TEST_HIJACK_ATOMICS */

#pragma GCC optimize("O3")

/* actual test code starts here */

static _Alignas(64) atomic int ctl_c;

static unsigned int rcu_freq;
static int shrink_adjust = 1;

static enum slow_level slow_loop = SLOW_NONE;
static unsigned int slow_loop_freq;

static size_t itercount = 1000000;
static size_t thread_item_arena_size;

static inline bool freq_apply(unsigned long i, unsigned int freq)
{
	unsigned int tz = i ? __builtin_ctzl(i) : 64;

	return tz >= freq;
}

/*
 * items - there's a global item_state table (n_items entries), but each thread
 * has its own "struct item" arena (to avoid congesting on RCU)
 */

enum state {
	OFFLIST = 0,
	ADDING = 1,
	ONLIST = 2,
	REMOVING = 3,

	FIND = 0x100,

	BUSY_MASK = 0x101,
};
#define state_next(s) (((s) + 1) & 0x3)

#ifdef _FRR_ATTRIBUTE_PRINTFRR
// clang-format off
#pragma FRR printfrr_ext "%dST" (int)
#pragma FRR printfrr_ext "%pAI" (struct atomhash_item *)
#pragma FRR printfrr_ext "%pIT" (struct item *)
#pragma FRR printfrr_ext "%pIS" (struct item_state *)
// clang-format on
#endif

printfrr_ext_autoreg_i("ST", printfrr_st);
static ssize_t printfrr_st(struct fbuf *buf, struct printfrr_eargs *ea, uintmax_t val)
{
	ssize_t ret = 0;

	if (val & FIND) {
		ret += bputs(buf, "FIND|");
		val &= ~FIND;
	}
	switch (val) {
		/* clang-format off */
#define ITEM(n) case n: return ret + bputs(buf, #n)
	ITEM(OFFLIST);
	ITEM(ADDING);
	ITEM(ONLIST);
	ITEM(REMOVING);
#undef ITEM
		/* clang-format on */
	default:
		return ret + bprintfrr(buf, "%#jx?", val);
	}
}

#define assert_statechg(v, from, to, fmt, ...)                                                    \
	do {                                                                                      \
		uint32_t state_check = atomic_exchange_explicit(&v->state, (to),                  \
								memory_order_acq_rel);            \
		assertf(state_check == (from), fmt " %p want %dST->%dST but is %dST!",            \
			##__VA_ARGS__, v, (int)(from), (int)(to), (int)state_check);              \
	} while (0)

struct item {
	struct atomhash_item item;

	uint32_t val;

	atomic uint32_t state;

	seqlock_val_t rcu_last_used;
};

static int icmp(const struct atomhash_item *a, const struct atomhash_item *b)
{
	const struct item *ai = container_of(a, struct item, item);
	const struct item *bi = container_of(b, struct item, item);

	return numcmp(ai->val, bi->val);
}

printfrr_ext_autoreg_p("AI", printfrr_ai);
static ssize_t printfrr_ai(struct fbuf *buf, struct printfrr_eargs *ea, const void *arg)
{
	atomptr_t p = (atomptr_t)arg;
	const struct atomhash_item *ai = atomptr_p(p);

	return bprintfrr(buf, "%p%s%s=(atomhash_i){ .hashval=%08x, .item.next=%#tx }", ai,
			 atomptr_u(p) ? ",U" : "", atomptr_l(p) ? ",L" : "", ai->hashval, ai->next);
}

printfrr_ext_autoreg_p("IT", printfrr_it);
static ssize_t printfrr_it(struct fbuf *buf, struct printfrr_eargs *ea, const void *arg)
{
	const struct item *it = arg;

	return bprintfrr(buf,
			 "%p=(item      ){ .hashval=%08x, .item.next=%#tx, .state=%8dST, .val=%4d }",
			 it, it->item.hashval, it->item.next, (int)it->state, it->val);
}

/*
 * global item state array
 */

PREDECL_HEAP(itemstates);
struct item_state {
	alignas(CACHELINESIZE) atomic uint32_t state;
	uint32_t _pad0;

	uint32_t val;
	uint32_t hashval;

	struct itemstates_item heapitem;

	struct item *active;
};
static_assert(alignof(struct item_state) % CACHELINESIZE == 0, "alignment mishap");

static int itemstates_cmp(const struct item_state *a, const struct item_state *b)
{
	if (a->hashval != b->hashval)
		return numcmp(a->hashval, b->hashval);

	return numcmp(a->val, b->val);
}
DECLARE_HEAP(itemstates, struct item_state, heapitem, itemstates_cmp);

static _Alignas(64) size_t n_items;
static struct item_state *item_states;

printfrr_ext_autoreg_p("IS", printfrr_is);
static ssize_t printfrr_is(struct fbuf *buf, struct printfrr_eargs *ea, const void *arg)
{
	const struct item_state *is = arg;

	return bprintfrr(buf,
			 "%p=(item_state){ .hashval=%08x, .state=%8dST, .val=%4d, .active=%p }",
			 is, is->hashval, (int)is->state, is->val, is->active);
}

/*
 * event counters - mostly to see which code paths are getting hit & how much
 */

enum stats {
	STAT_NONE,
	STAT_CHECK,
	STAT_ITER,
	STAT_RCU_HOT,
	STAT_ADD,
	STAT_ADD_DONE,
	STAT_ADD_BUSY_G,
	STAT_ADD_BUSY_L,
	STAT_ADDCOL,
	STAT_ADDCOL_DONE,
	STAT_ADDCOL_BUSY_G,
	STAT_DEL,
	STAT_DEL_DONE,
	STAT_DEL_BUSY_G,
	STAT_FIND,
	STAT_FIND_DONE,
	STAT_FIND_NEG,
	STAT_FIND_BUSY_G,
	STAT_GROW,
	STAT_GROW_DONE,
	STAT_GROW_NOOP = STAT_GROW_DONE + RESIZE_NOOP,
	STAT_GROW_COLLISION = STAT_GROW_DONE + RESIZE_RACED,
	STAT_GROW_FUDGED = STAT_GROW_DONE + RESIZE_FUDGED,
	STAT_GROW_CEILING,
	STAT_GROW_FAKE,
	STAT_GROW_FAKE_DONE,
	STAT_GROW_FAKE_COLLISION,
	STAT_GROW_FAKE_CEILING,
	STAT_GROW_FADD,
	STAT_GROW_FADD_DONE,
	STAT_GROW_FADD_EMPTY,
	STAT_GROW_FADD_BUSY_L,
	STAT_GROW_FADD_SKIPPED,
	STAT_GROW_FADD_SKIPDEL,
	STAT_GROW_FADD_NEWLVL,
	STAT_SHRINK,
	STAT_SHRINK_PROBABILITY,
	STAT_SHRINK_DONE,
	STAT_SHRINK_NOOP = STAT_SHRINK_DONE + RESIZE_NOOP,
	STAT_SHRINK_COLLISION = STAT_SHRINK_DONE + RESIZE_RACED,
	STAT_SHRINK_RCURATELIMIT = STAT_SHRINK_DONE + RESIZE_FUDGED,
	STAT_SHRINK_FLOOR,
	STAT_RCU_SAMPLES,
	STAT_RCU_IDLE,
	STAT_RCU_SHRINK_UNLINK,
	STAT_RCU_SHRINK_FREE,
};
/* time spent in test code */
#define STAT_AUX 0x1000

static const char *const stats_names[] = {
	[STAT_NONE] = "housekeeping",
	[STAT_CHECK] = "check",
	[STAT_ITER] = "iterate",
	[STAT_RCU_HOT] = "item blocked in RCU",
	[STAT_ADD] = "add",
	[STAT_ADD_DONE] = "add: success",
	[STAT_ADD_BUSY_G] = "add: failed to find empty slot",
	[STAT_ADD_BUSY_L] = "add: failed to find empty item",
	[STAT_ADDCOL] = "add-collide",
	[STAT_ADDCOL_DONE] = "add-coll: success",
	[STAT_ADDCOL_BUSY_G] = "add-coll: failed to find non-empty slot",
	[STAT_DEL] = "del",
	[STAT_DEL_DONE] = "del: success",
	[STAT_DEL_BUSY_G] = "del: failed to find non-empty slot",
	[STAT_FIND] = "find",
	[STAT_FIND_DONE] = "find: success",
	[STAT_FIND_NEG] = "find: success (negative)",
	[STAT_FIND_BUSY_G] = "find: failed to find slot",
	[STAT_GROW] = "grow",
	[STAT_GROW_DONE] = "grow: success",
	[STAT_GROW_NOOP] = "grow: no-op",
	[STAT_GROW_COLLISION] = "grow: collision",
	[STAT_GROW_FUDGED] = "grow: probability declined",
	[STAT_GROW_CEILING] = "grow: level ceiling",
	[STAT_GROW_FAKE] = "grow (empty)",
	[STAT_GROW_FAKE_DONE] = "grow (empty): success",
	[STAT_GROW_FAKE_COLLISION] = "grow (empty): collision",
	[STAT_GROW_FAKE_CEILING] = "grow (empty): level ceiling",
	[STAT_GROW_FADD] = "grow+add",
	[STAT_GROW_FADD_DONE] = "grow+add: done",
	[STAT_GROW_FADD_EMPTY] = "grow+add: empty level",
	[STAT_GROW_FADD_SKIPPED] = "grow+add: skipped adds",
	[STAT_GROW_FADD_SKIPDEL] = "grow+add: skipped dels",
	[STAT_GROW_FADD_BUSY_L] = "grow+add: failed to find empty item",
	[STAT_GROW_FADD_NEWLVL] = "grow+add: gained level",
	[STAT_SHRINK] = "shrink",
	[STAT_SHRINK_DONE] = "shrink: success",
	[STAT_SHRINK_NOOP] = "shrink: no-op",
	[STAT_SHRINK_COLLISION] = "shrink: collision",
	[STAT_SHRINK_RCURATELIMIT] = "shrink: RCU ratelimit",
	[STAT_SHRINK_FLOOR] = "shrink: level floor",
	[STAT_SHRINK_PROBABILITY] = "shrink: size-based probability negative",
	[STAT_RCU_SAMPLES] = "(RCU thread) all samples",
	[STAT_RCU_IDLE] = "(RCU thread) idle",
	[STAT_RCU_SHRINK_UNLINK] = "(RCU thread) shrink: unlink",
	[STAT_RCU_SHRINK_FREE] = "(RCU thread) shrink: free",
};

static bool stats_is_base[array_size(stats_names) + 1] = {
	/* clang-format off */
	[STAT_NONE] = true,
	[STAT_CHECK] = true,
	[STAT_ITER] = true,
	[STAT_RCU_HOT] = true,

	[STAT_ADD] = true,
	[STAT_ADDCOL] = true,
	[STAT_DEL] = true,
	[STAT_FIND] = true,
	[STAT_GROW] = true,
	[STAT_GROW_FAKE] = true,
	[STAT_GROW_FADD] = true,
	[STAT_SHRINK] = true,
	[STAT_RCU_SAMPLES] = true,
	/* clang-format on */
};

static inline bool stat_has_counters(enum stats stat)
{
	return stat != STAT_NONE && stat < STAT_RCU_SAMPLES;
}

/*
 * each thread has one of these, including the RCU thread
 */
struct thread_info {
	pthread_t pt;
	sem_t start_lock;
	struct seqlock run_lock;
	atomic bool stopped;
	struct timespec stop_since;

	struct rcu_thread *rt;
	long thread_num;
	struct item *items;
	size_t n_items, item_pos;
	struct amop_journal *amop_journal;

	alignas(CACHELINESIZE) atomic int what;
	atomic_size_t pos;

	size_t stats[array_size(stats_names)];
};
static thread_local struct thread_info *thread_info;

static thread_local bool is_rcu_thread;
static struct thread_info rcu_thread_info = {
	.what = STAT_RCU_IDLE | STAT_AUX,
};

static inline void _set_what(struct thread_info *ti, int val)
{
	atomic_store_explicit(&ti->what, val, memory_order_relaxed);
}
#define set_what(val) _set_what(ti, val)

bool mmap_mode = true;

static void thread_setup_items(struct thread_info *ti)
{
	size_t pagesize = getpagesize();
	size_t itemsize;
	char *buf, *end;

	ti->n_items = thread_item_arena_size;

	itemsize = ti->n_items * sizeof(ti->items[0]);
	itemsize = (itemsize + pagesize - 1) & ~(pagesize - 1);
	assertf((itemsize % pagesize) == 0, "itemsize=%zu pagesize=%zu", itemsize, pagesize);

	if (mmap_mode) {
		buf = mmap(NULL, pagesize * 2 + itemsize, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assertf(buf != (void *)-1, "mmap: %m");
		/* guard pages */
		assertf(!mprotect(buf, pagesize, PROT_NONE), "%m");
		assertf(!mprotect(buf + pagesize + itemsize, pagesize, PROT_NONE), "%m");

		buf += pagesize;
	} else {
		assert(!posix_memalign((void **)&buf, pagesize, itemsize));
	}

	ti->items = (struct item *)buf;

	end = buf + itemsize;
	/* force memory pages into RAM */
	for (; buf < end; buf += pagesize)
		*buf = '\0';
}

/*
 * actual hash table head
 */

static struct atomhash_head head[1];

static size_t levels_min, levels_max;
static atomic size_t n_ul;
static unsigned int poison_freq;

/*
 * RCU trickery
 */

struct rcu_dummy_del {
	struct rcu_head head;
};

static void rcu_dummy_del(struct rcu_dummy_del *rcu)
{
	free(rcu);
}

struct rcu_poison {
	struct rcu_head head;
	struct item *item;
};

static void rcu_poison(struct rcu_poison *rcu)
{
	memset(&rcu->item->item, 0xcc, sizeof(rcu->item->item));
	free(rcu);
}

static void mark_del(struct item *item)
{
	struct rcu_local_state rcu_state;

	rcu_state = rcu_local_state();
	item->rcu_last_used = rcu_state.seq_head;

	if (poison_freq) {
		unsigned int n = prng_rand(prng);

		if (freq_apply(n, poison_freq)) {
			struct rcu_poison *poison = calloc(1, sizeof(*poison));

			poison->item = item;
			rcu_call(rcu_poison, poison, head);
		}
	}
}

static bool can_use(struct item *item)
{
	struct rcu_local_state rcu_state;
	seqlock_val_t item_rcu;

	item_rcu = item->rcu_last_used;
	if (!(item_rcu & SEQLOCK_HELD))
		return true;

	rcu_state = rcu_local_state();
	if ((int32_t)(rcu_state.seq_tail - item_rcu) > 0)
		return true;

	return false;
}

/*
 * core test functions
 */

static void test_check(struct thread_info *ti, unsigned int r)
{
	struct atomhash_item *item, *prev = NULL;
	atomptr_t next_a;
	size_t level_size, _n_ul = 0;
	uint32_t prev_hash = 0;
	uint32_t hash_val, hash_inc;

	for (size_t level = 0; level < array_size(head->levels); level++) {
		struct atomhash_array *array;

		array = level_ptr(atomic_load_explicit(&head->levels[level], memory_order_acquire));
		if (!array)
			continue;

		if (!level) {
			hash_val = 0;
			hash_inc = 1 << (32 - ATOMHASH_LOWEST_BITS);
			level_size = 1 << ATOMHASH_LOWEST_BITS;
		} else {
			hash_val = 1 << (32 - ATOMHASH_LOWEST_BITS - level);
			hash_inc = hash_val << 1;
			level_size = 1 << (ATOMHASH_LOWEST_BITS + level - 1);
		}

		for (size_t i = 0; i < level_size; i++) {
			uint32_t hash_read;

			item = &array->stubs[i];
			next_a = atomic_load_explicit(&item->next, memory_order_acquire);
			/* the atomic here is theoretical / UB avoidance */
			hash_read = atomic_load_explicit((atomic uint32_t *)&item->hashval,
							 memory_order_acquire);

			assertf(hash_read == hash_val || !next_a,
				"level=%zu i=%zu next_a=%#tx hash_val=%08x hash_read=%08x hash_inc=%08x",
				level, i, next_a, hash_val, hash_read, hash_inc);

			hash_val += hash_inc;

			if (atomptr_is_ul(next_a))
				_n_ul++;
		}
	}
	atomic_fetch_add_explicit(&n_ul, _n_ul, memory_order_relaxed);

	next_a = (atomptr_t)&level_ptr(head->levels[0])->stubs[0];

	for (item = atomptr_p(next_a); item != head->sentinel_end; item = atomptr_p(next_a)) {
		next_a = atomic_load_explicit(&item->next, memory_order_acquire);
		assertf(item->hashval >= prev_hash,
			"prev=%p item=%p hashval=%08x next_a=%#tx prev_hash = %08x", prev, item,
			item->hashval, next_a, prev_hash);
		prev_hash = item->hashval;
		prev = item;
	}
}

static void test_iter(struct thread_info *ti, unsigned int r)
{
	const struct atomhash_item *ai;
	uint32_t prev_hash = 0;

	frr_each (atomhash, head, ai) {
		assertf(ai->hashval >= prev_hash, "%p %08x %08x", ai, prev_hash, ai->hashval);

		prev_hash = ai->hashval;
	}
}

static void test_grow_real(struct thread_info *ti, unsigned int r)
{
	uint_fast32_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	enum resize_result rv;

	if (level++ == levels_max) {
		ti->stats[STAT_GROW_CEILING]++;
		return;
	}

	set_what(STAT_GROW);
	rv = atomhash_resize_grow(head, 1U << (level + 3));
	set_what(STAT_GROW | STAT_AUX);
	ti->stats[STAT_GROW_DONE + rv]++;
}

static void test_grow_fake(struct thread_info *ti, unsigned int r)
{
	struct atomhash_array *array;
	size_t n;
	uint_fast32_t level_hint, level_hint_adj;
	uint_fast32_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	atomptr_t replace = ATOMPTR_NULL;

	if (level++ == levels_max) {
		ti->stats[STAT_GROW_FAKE_CEILING]++;
		return;
	}

	assert(level > 0);
	n = level_size(level);

	array = XCALLOC(MTYPE_ATOMHASH_TABLE, sizeof(array->stubs[0]) * n);
	if (!atomic__cmpxchg_strong(&head->levels[level], &replace, atomptr_i(array),
				    memory_order_release, memory_order_relaxed)) {
		XFREE(MTYPE_ATOMHASH_TABLE, array);
		ti->stats[STAT_GROW_FAKE_COLLISION]++;
		return;
	}

	level_hint = atomic__load(&head->level_hint, memory_order_relaxed);
	do {
		level_hint_adj = MAX(level_hint, (size_t)level);
		if (level_hint_adj == level_hint)
			break;
	} while (!atomic__cmpxchg_strong(&head->level_hint, &level_hint, level_hint_adj,
					 memory_order_relaxed, memory_order_relaxed));

	ti->stats[STAT_GROW_FAKE_DONE]++;
}

static void test_shrink(struct thread_info *ti, unsigned int r)
{
	uint_fast32_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	enum resize_result rv;

	if (level == levels_min) {
		ti->stats[STAT_SHRINK_FLOOR]++;
		return;
	}
	if ((r & ((1 << MAX(0, (int)levels_max - (int)level + shrink_adjust)) - 1))) {
		ti->stats[STAT_SHRINK_PROBABILITY]++;
		return;
	}

	//atomic__load(&head->levels[level], memory_order_acquire)))
	set_what(STAT_SHRINK);
	rv = atomhash_resize_shrink(head, 0); //(1 << level) - 1))
	set_what(STAT_SHRINK | STAT_AUX);
	ti->stats[STAT_SHRINK_DONE + rv]++;
}

#define RETRY_STATE 50
#define RETRY_ITEM  1000

static struct item_state *state_find_item_state(size_t start_idx, uint32_t prevstate,
						uint32_t nextstate, bool any_nonbusy)
{
	size_t retry = 0;
	size_t i;
	struct item_state *istate;
	uint32_t prevstate_xchg;

	i = start_idx % n_items;

	do {
		if (retry++ > RETRY_STATE)
			return NULL;

		istate = &item_states[i];

		i++;
		if (i == n_items)
			i = 0;

		if (!any_nonbusy)
			prevstate_xchg = prevstate;
		else {
			prevstate_xchg = atomic_load_explicit(&istate->state, memory_order_relaxed);
			prevstate_xchg &= ~BUSY_MASK;
			nextstate = prevstate_xchg | FIND;
		}
	} while (!atomic_compare_exchange_strong_explicit(&istate->state, &prevstate_xchg,
							  nextstate, memory_order_acq_rel,
							  memory_order_relaxed));

	return istate;
}

static void rcu_bump_dummy(void)
{
	struct rcu_dummy_del *dummy_del = malloc(sizeof(*dummy_del));

	rcu_call(rcu_dummy_del, dummy_del, head);
}

static struct item *thread_find_item_state(struct thread_info *ti, uint32_t prevstate,
					   uint32_t nextstate)
{
	size_t retry = 0;
	size_t i;
	struct item *item;
	uint32_t prevstate_xchg;

	i = ti->item_pos;
	while (1) {
		do {
			if (retry++ > RETRY_ITEM) {
				ti->item_pos = i;
				return NULL;
			}

			item = &ti->items[i];

			i++;
			if (i == ti->n_items)
				i = 0;

			prevstate_xchg = prevstate;
		} while (!atomic_compare_exchange_strong_explicit(&item->state, &prevstate_xchg,
								  nextstate, memory_order_acq_rel,
								  memory_order_relaxed));

		if (can_use(item))
			break;

		assert_statechg(item, nextstate, prevstate, "val=%u", item->val);
		ti->stats[STAT_RCU_HOT]++;
	}

	ti->item_pos = i;
	return item;
}

static void test_add(struct thread_info *ti, unsigned int r)
{
	struct item_state *istate;
	struct item *item;

	istate = state_find_item_state(r, OFFLIST, ADDING, false);
	if (!istate) {
		ti->stats[STAT_ADD_BUSY_G]++;
		return;
	}
	assertf(!istate->active, "istate=%p val=%u active=%p", istate, istate->val, istate->active);

	item = thread_find_item_state(ti, OFFLIST, ADDING);
	if (!item) {
		assert_statechg(istate, ADDING, OFFLIST, "val=%u", istate->val);
		ti->stats[STAT_ADD_BUSY_L]++;
		return;
	}

	struct atomhash_item *ret, *ai;

	ai = &item->item;
	item->val = istate->val;
	ai->hashval = istate->hashval;

	set_what(STAT_ADD);
	ret = atomhash_add(head, ai, icmp);
	set_what(STAT_ADD | STAT_AUX);

	assert(!ret);
	istate->active = item;

	assert_statechg(item, ADDING, ONLIST, "val=%u", item->val);
	assert_statechg(istate, ADDING, ONLIST, "val=%u", istate->val);

	ti->stats[STAT_ADD_DONE]++;
}

static void test_addcol(struct thread_info *ti, unsigned int r)
{
	struct item_state *istate;
	struct item local_item;

	istate = state_find_item_state(r, ONLIST, ONLIST | FIND, false);
	if (!istate) {
		ti->stats[STAT_ADDCOL_BUSY_G]++;
		return;
	}
	assertf(istate->active, "istate=%p val=%u active=%p", istate, istate->val, istate->active);

	struct atomhash_item *ret, *ai;

	memset(&local_item, 0xcc, sizeof(local_item));
	ai = &local_item.item;
	local_item.val = istate->val;
	ai->hashval = istate->hashval;

	set_what(STAT_ADDCOL);
	ret = atomhash_add(head, ai, icmp);
	set_what(STAT_ADDCOL | STAT_AUX);

	struct item *reti = container_of(ret, struct item, item);

	assertf(reti == istate->active, "istate=%p val=%u active=%p ret=%p", istate, istate->val,
		istate->active, reti);

	assert_statechg(istate, ONLIST | FIND, ONLIST, "val=%u", istate->val);

	ti->stats[STAT_ADDCOL_DONE]++;
}


static void test_del(struct thread_info *ti, unsigned int r)
{
	struct item_state *istate;
	struct item *item;

	istate = state_find_item_state(r, ONLIST, REMOVING, false);
	if (!istate) {
		ti->stats[STAT_DEL_BUSY_G]++;
		return;
	}
	assertf(istate->active, "istate=%p val=%u active=%p", istate, istate->val, istate->active);

	item = istate->active;
	assertf(item->val == istate->val, "item->val=%u istate->val=%u", item->val, istate->val);
	assert_statechg(item, ONLIST, REMOVING, "val=%u", item->val);

	set_what(STAT_DEL);
	atomhash_del(head, &item->item);
	set_what(STAT_DEL | STAT_AUX);

	istate->active = NULL;
	mark_del(item);

	assert_statechg(item, REMOVING, OFFLIST, "val=%u", item->val);
	assert_statechg(istate, REMOVING, OFFLIST, "val=%u", istate->val);

	ti->stats[STAT_DEL_DONE]++;
}

#if 0
/* pop() cannot easily be tested :( */
static bool test_pop(unsigned int r)
{
	return false;
}
#endif

static void test_find(struct thread_info *ti, unsigned int r)
{
	struct item_state *istate;
	struct item ref;
	bool active;
	uint32_t state;

	istate = state_find_item_state(r, 0, 0, true);
	if (!istate) {
		ti->stats[STAT_FIND_BUSY_G]++;
		return;
	}

	state = istate->state;
	assertf(state == (ONLIST | FIND) || state == (OFFLIST | FIND), "%dST", (int)state);
	active = istate->state == (ONLIST | FIND);

	assertf(active == !!istate->active, "istate=%p val=%u state=%dST active=%p", istate,
		istate->val, (int)istate->state, istate->active);

	memset(&ref, 0xcc, sizeof(ref));
	ref.item.hashval = istate->hashval;
	ref.val = istate->val;

	struct atomhash_item *ret;

	set_what(STAT_FIND);
	ret = atomhash_get(head, &ref.item, istate->hashval, icmp);
	set_what(STAT_FIND | STAT_AUX);

	struct item *reti = container_of_null(ret, struct item, item);

	assertf(active ? (reti == istate->active) : (reti == NULL),
		"istate=%p val=%u active=%p ret=%p", istate, istate->val, istate->active, reti);

	ti->stats[STAT_FIND_DONE]++;
	if (!active)
		ti->stats[STAT_FIND_NEG]++;
	assert_statechg(istate, state, state & ~FIND, "val=%u", istate->val);
}

#define FAKE_OP_COUNT (n_items / 12)
/*
 * this is specifically designed to test lazy insertion array updates
 */
static void test_grow_fake_add(struct thread_info *ti, unsigned int r)
{
	size_t have_add, n_add = FAKE_OP_COUNT;
	struct item_state *istates[n_add];
	struct item *items[n_add];

	size_t have_del, n_del = FAKE_OP_COUNT;
	struct item_state *istadel[n_del];

	size_t prev_idx = r;
	struct atomhash_array *array, *old;
	uint_fast32_t level;
	size_t n;

	level = atomic__load(&head->level_hint, memory_order_relaxed);
	if (level == 0) {
		ti->stats[STAT_GROW_FADD_EMPTY]++;
		return;
	}

	for (have_add = 0; have_add < n_add; have_add++) {
		istates[have_add] = state_find_item_state(prev_idx, OFFLIST, ADDING, false);
		if (!istates[have_add]) {
			ti->stats[STAT_GROW_FADD_SKIPPED]++;
			prev_idx += RETRY_STATE;
			continue;
		}
		prev_idx = istates[have_add] - item_states;

		items[have_add] = thread_find_item_state(ti, OFFLIST, ADDING);
		if (!items[have_add]) {
			assert_statechg(istates[have_add], ADDING, OFFLIST, "");
			istates[have_add] = NULL;
			ti->stats[STAT_GROW_FADD_BUSY_L]++;
			continue;
		}
	}

	for (have_del = 0; have_del < n_del; have_del++) {
		istadel[have_del] = state_find_item_state(prev_idx, ONLIST, REMOVING, false);
		if (!istadel[have_del]) {
			ti->stats[STAT_GROW_FADD_SKIPDEL]++;
			prev_idx += RETRY_STATE;
			continue;
		}
		prev_idx = istadel[have_del] - item_states;

		assert_statechg(istadel[have_del]->active, ONLIST, REMOVING, "");
	}

	level = ((r >> 16) % level) + 1;

	n = level_size(level);

	array = XCALLOC(MTYPE_ATOMHASH_TABLE, sizeof(array->stubs[0]) * n);
	old = level_ptr(
		atomic__exchange(&head->levels[level], atomptr_i(array), memory_order_acq_rel));

	for (size_t i = 0; i < have_add || i < have_del; i++) {
		struct item_state *istate = istates[i];
		struct item *item = items[i];

		if (i < have_add && istate) {
			struct atomhash_item *ret, *ai;

			ai = &item->item;
			item->val = istate->val;
			ai->hashval = istate->hashval;

			set_what(STAT_GROW_FADD);
			ret = atomhash_add(head, ai, icmp);
			set_what(STAT_GROW_FADD | STAT_AUX);

			assert(!ret);
			istate->active = item;

			assert_statechg(item, ADDING, ONLIST, "val=%u", item->val);
			assert_statechg(istate, ADDING, ONLIST, "val=%u", istate->val);
		}

		istate = istadel[i];
		if (i < have_del && istate) {
			struct atomhash_item *ai;

			item = istate->active;
			ai = &item->item;

			set_what(STAT_GROW_FADD);
			atomhash_del(head, ai);
			set_what(STAT_GROW_FADD | STAT_AUX);

			istate->active = NULL;
			mark_del(item);

			assert_statechg(item, REMOVING, OFFLIST, "val=%u", item->val);
			assert_statechg(istate, REMOVING, OFFLIST, "val=%u", istate->val);
		}
	}

	if (old) {
		atomic_fetch_add_explicit(&head->inflight_shrinks, 1, memory_order_relaxed);
		atomhash_teardown_actual(head, old, level);
	} else
		ti->stats[STAT_GROW_FADD_NEWLVL]++;

	ti->stats[STAT_GROW_FADD_DONE]++;
}

struct test_action {
	float chance;
	const char *name;
	int stat_flag;
	void (*func)(struct thread_info *ti, unsigned int r);
	uint32_t chance_u32;
};

/* clang-format off */
static struct test_action actions[] = {
	{  4,     "check",     STAT_CHECK,     test_check },
	{  0.5,   "iter",      STAT_ITER,      test_iter },
	{  0.010, "grow_real", STAT_GROW,      test_grow_real },
	{  0.005, "grow_fake", STAT_GROW_FAKE, test_grow_fake },
	{  0.002, "grow_fadd", STAT_GROW_FADD, test_grow_fake_add },
	{  0.023, "shrink",    STAT_SHRINK,    test_shrink },
	{ 18,     "add",       STAT_ADD,       test_add },
	{ 18,     "del",       STAT_DEL,       test_del },
	{  5,     "addcol",    STAT_ADDCOL,    test_addcol },
	{ 56,     "find",      STAT_FIND,      test_find },
};
/* clang-format on */

/* *synchronous* stop */
static seqlock_ctr_t sync_seq_expect = SEQLOCK_STARTVAL;
static struct seqlock sync_seq;

/* *asynchronous* stop (SIGUSR1) */
static seqlock_ctr_t async_seq_expect = SEQLOCK_STARTVAL;
static struct seqlock async_seq;

static sigset_t usr1_set;

static void sigusr1(int sig)
{
	seqlock_val_t wait_seq = atomic_load_explicit(&async_seq_expect, memory_order_relaxed);

	if (!thread_info) {
		fprintf(stderr, "SIGUSR1: no thread info!\n\n\n");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &thread_info->stop_since);
	atomic_store_explicit(&thread_info->stopped, true, memory_order_relaxed);

	seqlock_acquire_val(&thread_info->run_lock, wait_seq + SEQLOCK_INCR);
	seqlock_wait(&async_seq, wait_seq);

	atomic_store_explicit(&thread_info->stopped, false, memory_order_relaxed);
}

static void thread_prio_down(void)
{
#ifdef linux
	long tid = -1;

	tid = syscall(__NR_gettid);
	setpriority(PRIO_PROCESS, tid, 10);
#endif
}

static void *thread_func(void *arg)
{
	struct thread_info *ti = thread_info = arg;
	long thread_num = ti->thread_num;
	size_t i, j;
	seqlock_val_t sync_seq_do;
	/* had cacheline pingpong problems with these */
	enum slow_level slow_loop_l = slow_loop;
	unsigned int slow_loop_freq_l = slow_loop_freq;
	unsigned int rcu_freq_l = rcu_freq;

	seqlock_init(&ti->run_lock);
	seqlock_acquire_val(&ti->run_lock, SEQLOCK_STARTVAL);
	ti->amop_journal = amop_setup();

	rcu_thread_start(ti->rt);
	rcu_assert_read_locked();

	/* make the RCU thread run preferentially before this */
	thread_prio_down();

	prng = prng_new(0xcafef00d * (thread_num + 2342) + prng_seed);

	rcu_read_unlock();
	pthread_sigmask(SIG_UNBLOCK, &usr1_set, NULL);
	sem_post(&ti->start_lock);

	sync_seq_do = atomic_load_explicit(&sync_seq_expect, memory_order_relaxed);
	seqlock_wait(&sync_seq, sync_seq_do);

	set_what(STAT_NONE | STAT_AUX);

	for (i = 0; i < itercount; i++) {
		seqlock_val_t sync_seq_next;

		if (freq_apply(i, rcu_freq_l)) {
			rcu_read_lock();
			rcu_bump_dummy();
			rcu_read_unlock();
		}

		sync_seq_next = atomic_load_explicit(&sync_seq_expect, memory_order_relaxed);
		if (sync_seq_next != sync_seq_do) {
			sync_seq_do = sync_seq_next;
			seqlock_wait(&sync_seq, sync_seq_do);
		}

		/* NB: range is only 0..2^31 */
		uint32_t action = prng_rand(prng);

		rcu_read_lock();
		for (j = 0; j < array_size(actions); j++) {
			if (action < actions[j].chance_u32) {
				ti->stats[actions[j].stat_flag]++;
				set_what(actions[j].stat_flag | STAT_AUX);
				actions[j].func(ti, prng_rand(prng));
				set_what(STAT_NONE | STAT_AUX);
				break;
			}
			action -= actions[j].chance_u32;
		}
		rcu_read_unlock();

		atomic_store(&ti->pos, i);

		if (unlikely(slow_loop_l != SLOW_NONE && freq_apply(i, slow_loop_freq_l)))
			slowdown(slow_loop_l);

		if (atomic_load_explicit(&ctl_c, memory_order_relaxed))
			goto out_cancel;
	}

	atomic_store(&ti->pos, ~0ULL);

out_cancel:
	prng_free(prng);

	pthread_sigmask(SIG_BLOCK, &usr1_set, NULL);

	seqlock_release(&ti->run_lock);
	return NULL;
}

static void hijack_atomhash_unlink_level(struct rcu_atomhash_shrink *arg)
{
	atomic_store_explicit(&rcu_thread_info.what, STAT_RCU_SHRINK_UNLINK, memory_order_relaxed);
	atomhash_unlink_level(arg);
	atomic_store_explicit(&rcu_thread_info.what, STAT_RCU_IDLE | STAT_AUX,
			      memory_order_relaxed);
}

static void hijack_atomhash_free_level(struct rcu_atomhash_shrink *arg)
{
	atomic_store_explicit(&rcu_thread_info.what, STAT_RCU_SHRINK_FREE, memory_order_relaxed);
	atomhash_free_level(arg);
	atomic_store_explicit(&rcu_thread_info.what, STAT_RCU_IDLE | STAT_AUX,
			      memory_order_relaxed);
}

static struct amop_journal *rcu_amop_journal, *main_amop_journal;

struct rcu_prng {
	struct rcu_head rcu;
	int close_fd;
};

static void rcu_set_prng(struct rcu_prng *rcu)
{
	thread_info = &rcu_thread_info;
	thread_info->pt = pthread_self();
	thread_info->thread_num = -1;
	seqlock_init(&thread_info->run_lock);
	seqlock_acquire_val(&thread_info->run_lock, SEQLOCK_STARTVAL);

	pthread_sigmask(SIG_UNBLOCK, &usr1_set, NULL);

	is_rcu_thread = true;
	rcu_amop_journal = amop_setup();
	prng = prng_new(0xf00ba75f + prng_seed);
	close(rcu->close_fd);
}

static void rcu_prepare(void)
{
	struct rcu_prng rcu_prng;
	int prngpipe[2];
	char dummy;

	/* force RCU start */
	rcu_thread_unprepare(rcu_thread_prepare());

	rcu_assert_read_locked();

	pipe(prngpipe);
	rcu_prng.close_fd = prngpipe[1];
	rcu_call(rcu_set_prng, &rcu_prng, rcu);

	rcu_read_unlock();

	read(prngpipe[0], &dummy, 1);
	close(prngpipe[0]);

	rcu_read_lock();
}

static uint32_t rcu_seqno_in;
static atomic uint32_t rcu_seqno_out;

struct rcu_ping {
	struct rcu_head head;
	uint32_t seqno;
};

static void rcu_ping_fn(struct rcu_ping *ping)
{
	atomic_store_explicit(&rcu_seqno_out, ping->seqno, memory_order_relaxed);
	XFREE(MTYPE_TMP, ping);
}

struct coloritem {
	unsigned long long maxval;
	const char *color;
} delta_colors[] = {
	{ 62, "\033[95m" },
	{ 30, "\033[91m" },
	{ 14, "\033[93m" },
	{ 6, "\033[92m" },
	{ 2, "\033[96m" },
	{ 0, "\033[97m" },
}, qlen_colors[] = {
	{ 151875, "\033[95m" },
	{ 10125, "\033[91m" },
	{ 675, "\033[93m" },
	{ 45, "\033[92m" },
	{ 3, "\033[96m" },
	{ 0, "\033[97m" },
};

static const char *colorize(const struct coloritem *table, unsigned long long value)
{
	const struct coloritem *i;

	for (i = table; i->color; i++)
		if (value >= i->maxval)
			break;
	return i->color;
}

static useconds_t sampler_interval = 100;
static size_t sample_stats[array_size(stats_names)];
static size_t sample_stats_aux[array_size(stats_names)];
static size_t stop_check_rate = 10;

struct sampler_args {
	long n_threads;
	struct thread_info *threads;
};

struct stop_stats {
	union {
		struct {
			size_t total;
			size_t ul_through_list;
			size_t ul_off_list;
			size_t ul_off_list_outdated;
			size_t items_shrinking;
			size_t items_deleted;
		};
		size_t vals[6];
	};
};
static struct stop_stats stop_stats;

#define trace(...)                                                                                \
	do {                                                                                      \
	} while (0)

static void stop_check_inner(void)
{
	struct itemstates_head heap[1];
	struct item_state *stateref;
	struct atomhash_item *levels[array_size(head->levels)];
	struct atomhash_item *levels_end[array_size(head->levels)];
	uint32_t levels_hval[array_size(head->levels)];
	size_t level_limit = 0;

	struct atomhash_item *pos;
	uint32_t hashval = 0;
	struct stop_stats stats = { .total = 1 };

	if (!head->levels[0])
		return;

	itemstates_init(heap);
	for (size_t i = 0; i < n_items; i++)
		itemstates_add(heap, &item_states[i]);

	stateref = itemstates_pop(heap);

	atomic_thread_fence(memory_order_acquire);

	for (size_t i = 0; i < array_size(head->levels); i++) {
		struct atomhash_array *array = level_ptr(head->levels[i]);

		if (array) {
			levels[i] = &array->stubs[0];
			levels_end[i] = levels[i] + level_size(i);
			levels_hval[i] = i ? (1 << (32 - ATOMHASH_LOWEST_BITS - i)) : 0;
			level_limit = i + 1;

			assertf(levels[i]->next == ATOMPTR_NULL || atomptr_u(levels[i]->next),
				"i=%zu levels[i]=%p levels[i]->next=%#tx", i, levels[i],
				levels[i]->next);
		} else
			levels[i] = levels_end[i] = NULL;
	}

	for (pos = levels[0]; pos != head->sentinel_end; pos = atomptr_p(pos->next)) {
		bool lvl_found = false;
		uint32_t hash_inc = 1 << (32 - ATOMHASH_LOWEST_BITS);

		assertf(pos->hashval >= hashval && pos->next, "pos=%pAI", pos);
		hashval = pos->hashval;

		for (size_t i = 0; i < level_limit; i++) {
			while (levels[i] && pos != levels[i] && hashval > levels_hval[i]) {
				if (levels[i]->next != ATOMPTR_NULL) {
					struct atomhash_item *check;

					assertf(atomptr_is_ul(levels[i]->next), "i=%zu", i);

					check = levels[i];
					while (check != pos) {
						check = atomptr_p(check->next);

						assert(check);
						if (check == head->sentinel_end)
							break;
						if (check->hashval > hashval)
							break;
					}

					if (check != pos)
						stats.ul_off_list_outdated++;
					else
						stats.ul_off_list++;
				}

				levels[i]++;
				levels_hval[i] += hash_inc;
				if (levels[i] == levels_end[i]) {
					levels[i] = NULL;
					assert(levels_hval[i] < (1 << (32 - ATOMHASH_LOWEST_BITS)));
				}
			}
			if (i)
				hash_inc >>= 1;
		}

		while (stateref && stateref->hashval < hashval) {
			assertf((stateref->state & 3) != ONLIST, "stateref=%pIS pos=%pAI",
				stateref, pos);

			trace("\033[90mskip over %pIS\033[m\n", stateref);
			stateref = itemstates_pop(heap);
		}

		if (!atomptr_u(pos->next)) {
			/* normal item */
			struct item *positem;

			if (atomptr_l(pos->next)) {
				stats.items_deleted++;
				trace("deleting  %pAI\n", pos);
				continue;
			}

			positem = container_of(pos, struct item, item);
			trace("item >>>> %pIT\n", positem);

			assertf((positem->state & 3) != OFFLIST, "%pIT", positem);
			assert(stateref);

			while (stateref->hashval < hashval ||
			       (stateref->hashval == hashval && stateref->val < positem->val)) {
				assertf((stateref->state & 3) != ONLIST, "stateref=%pIS pos=%pIT",
					stateref, positem);

				trace("skip over %pIS\n", stateref);
				stateref = itemstates_pop(heap);
				assert(stateref);
			}

			assertf(stateref->hashval == hashval && stateref->val == positem->val,
				"stateref=%pIS pos=%pIT", stateref, positem);
			assertf((stateref->state & 3) != OFFLIST, "stateref=%pIS pos=%pIT",
				stateref, positem);
			trace("\033[90m^ matches %pIS\033[m\n", stateref);

			for (size_t i = 0; i < level_limit; i++)
				assertf(!levels[i] || hashval <= levels_hval[i],
					"%pAI hashval=%08x>%08x", levels[i], hashval,
					levels_hval[i]);

			stateref = itemstates_pop(heap);
			continue;
		}

		trace("stub >>>> %pAI\n", pos);

		hash_inc = 1 << (32 - ATOMHASH_LOWEST_BITS);

		for (size_t i = 0; i < level_limit; i++) {
			if (levels[i] == pos) {
				assert(levels[i]->next != ATOMPTR_NULL);
				assert(levels[i]->hashval == levels_hval[i]);
				lvl_found = true;

				assertf(levels[i]->hashval >= hashval && atomptr_u(levels[i]->next),
					"i=%zu levels[i]=%p ->hashval=%08x ->next=%#tx", i,
					levels[i], levels[i]->hashval, levels[i]->next);

				if (atomptr_l(levels[i]->next))
					stats.ul_through_list++;

				levels[i]++;
				levels_hval[i] += hash_inc;
				if (levels[i] == levels_end[i]) {
					levels[i] = NULL;
					assert(levels_hval[i] < (1 << (32 - ATOMHASH_LOWEST_BITS)));
				}
				continue;
			}

			if (i)
				hash_inc >>= 1;
		}
		if (!lvl_found)
			stats.items_shrinking++;
	}

	for (size_t j = 0; j < array_size(stop_stats.vals); j++)
		stop_stats.vals[j] += stats.vals[j];
}

static void stop_check(struct thread_info *threads, long n_threads)
{
	seqlock_val_t wait_seq = atomic_load_explicit(&async_seq_expect, memory_order_relaxed);
	struct thread_info *stop_order[n_threads + 1];

	for (long i = 0; i < n_threads; i++)
		stop_order[i] = threads + i;

	prng_permute(prng, (void **)stop_order, array_size(stop_order) - 1);
	stop_order[n_threads] = &rcu_thread_info;

	for (size_t i = 0; i < array_size(stop_order); i++)
		pthread_kill(stop_order[i]->pt, SIGUSR1);
	for (size_t i = 0; i < array_size(stop_order); i++)
		seqlock_wait(&stop_order[i]->run_lock, wait_seq);

	stop_check_inner();
	async_seq_expect = seqlock_bump(&async_seq);
}

static void *sampler_func(void *arg)
{
	struct sampler_args *sa = arg;
	size_t si = 0;

	async_seq_expect = SEQLOCK_STARTVAL;
	seqlock_init(&async_seq);
	seqlock_acquire_val(&async_seq, SEQLOCK_STARTVAL);

	prng = prng_new(0x42231337 + prng_seed);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	for (long i = 0; i < sa->n_threads; i++)
		sem_wait(&sa->threads[i].start_lock);

	do {
		usleep(sampler_interval);
		pthread_testcancel();

		for (long i = 0; i < sa->n_threads; i++) {
			size_t pos, what;

			pos = atomic_load_explicit(&sa->threads[i].pos, memory_order_relaxed);
			if (pos == 0 || pos == ~0ULL)
				continue;

			what = atomic_load_explicit(&sa->threads[i].what, memory_order_relaxed);
			if (what & STAT_AUX)
				sample_stats_aux[what & ~STAT_AUX]++;
			else
				sample_stats[what]++;
		}

		int rcu_what = atomic_load_explicit(&rcu_thread_info.what, memory_order_relaxed);

		sample_stats_aux[STAT_RCU_SAMPLES]++;
		if (rcu_what & STAT_AUX)
			sample_stats_aux[rcu_what & ~STAT_AUX]++;
		else
			sample_stats[rcu_what]++;

		if (stop_check_rate && !(si % stop_check_rate)) {
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			stop_check(sa->threads, sa->n_threads);
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		}
		si++;
	} while (1);

	return NULL;
}

static void mt_tests(long n_threads, size_t levels_init)
{
	pthread_t sampler_thread;
	struct thread_info threads[n_threads];
	size_t total = n_threads * itercount;
	size_t prev_done, speed;
	long n_busy;
	size_t lvl_hist[10] = {};
	size_t lvl_hist_pos = 0;
	pthread_attr_t pt_attr;
	struct sched_param sp = {
		.sched_priority = 10,
	};
	seqlock_val_t sync_seq_at;
	bool stopped = false;
	struct timespec stop_t = {};

	levels_min = MAX(lrint(log2(n_items) - 3.5 - 4), 0);
	levels_max = lrint(log2(n_items) + 2.5 - 4);

	printf("levels_min=%zu, levels_max=%zu\n\n\n", levels_min, levels_max);

	atomhash_init(head);
	head->freeze_size = true;

	main_amop_journal = amop_setup();

	atomhash_setup_level0(head);
	for (size_t i = 1; i <= levels_init; i++)
		atomhash_setup_level(head, i, ATOMPTR_NULL);

	pthread_attr_init(&pt_attr);
	pthread_attr_setschedparam(&pt_attr, &sp);

	seqlock_init(&sync_seq);
	seqlock_acquire_val(&sync_seq, SEQLOCK_STARTVAL);

	memset(threads, 0, sizeof(threads));

	for (long i = 0; i < n_threads; i++) {
		threads[i].thread_num = i;
		sem_init(&threads[i].start_lock, 0, 0);
		seqlock_init(&threads[i].run_lock);
		seqlock_acquire_val(&threads[i].run_lock, SEQLOCK_STARTVAL);
		thread_setup_items(&threads[i]);
		threads[i].rt = rcu_thread_prepare();
		pthread_create(&threads[i].pt, NULL, &thread_func, &threads[i]);
	}

	struct sampler_args sa = {
		.n_threads = n_threads,
		.threads = threads,
	};
	if (sampler_interval)
		pthread_create(&sampler_thread, NULL, sampler_func, &sa);

	pthread_attr_destroy(&pt_attr);

	usleep(10);
	sync_seq_at = seqlock_bump(&sync_seq);

	printf("\n");
	prev_done = speed = 0;
	do {
		struct timespec t;
		size_t done;
		struct rusage ru;
		struct rcu_stats rcudbg;
		struct rcu_ping *rcu_ping = XMALLOC(MTYPE_TMP, sizeof(*rcu_ping));
		char stopbuf[96];
		struct fbuf fb_stopped = { .buf = stopbuf, .pos = stopbuf, .len = sizeof(stopbuf) };

		if (atomic_load(&rcu_thread_info.stopped))
			bprintfrr(&fb_stopped, " async-stop:[RCU:%pTSMs",
				  &rcu_thread_info.stop_since);

		n_busy = 0;
		done = 0;
		for (long i = 0; i < n_threads; i++) {
			size_t pos = atomic_load(&threads[i].pos);

			if (pos != ~0ULL) {
				n_busy++;
				done += pos;
			} else
				done += itercount;

			if (atomic_load(&threads[i].stopped)) {
				if (fb_stopped.pos != fb_stopped.buf)
					bputs(&fb_stopped, ", ");
				else
					bputs(&fb_stopped, " async-stop:[");
				FMT_NSTD(bprintfrr(&fb_stopped, "%ld:%.3pTSMsd", i,
						   &threads[i].stop_since));
			}
		}
		if (fb_stopped.pos != fb_stopped.buf)
			bputs(&fb_stopped, "]");

		uint_fast32_t level_hint = atomic_load_explicit(&head->level_hint,
								memory_order_relaxed);

		lvl_hist[lvl_hist_pos++] = level_hint;
		if (lvl_hist_pos == array_size(lvl_hist))
			lvl_hist_pos = 0;

		size_t lvl_min = SIZE_MAX, lvl_max = 0, lvl_sum = 0;

		for (size_t i = 0; i < array_size(lvl_hist); i++) {
			lvl_min = MIN(lvl_min, lvl_hist[i]);
			lvl_max = MAX(lvl_max, lvl_hist[i]);
			lvl_sum += lvl_hist[i];
		}

		float avglvl = lvl_sum / (float)array_size(lvl_hist);

		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
		getrusage(RUSAGE_SELF, &ru);

		speed *= 31;
		speed += (done - prev_done) * 5;
		speed /= 32;

		rcu_stats(&rcudbg);

		char stop_state[64] = "";

		if (stopped)
			FMT_NSTD(snprintfrr(stop_state, sizeof(stop_state),
					    " \033[91;1m[stop %.3pTSMsd]\033[m", &stop_t));

		const char *delta_color = colorize(delta_colors, MAX(0, rcudbg.seq_delta));
		const char *qlen_color = colorize(qlen_colors, rcudbg.qlen);
		unsigned int inflight_shrinks = atomic_load_explicit(&head->inflight_shrinks,
								     memory_order_relaxed);

		printfrr("\033[2A%4ld.%03ld %10zu/%10zu %7zu/s (%5.1f%%) lvl[%zu,%.1f(=%.0f),%zu -%u inflight], %ld busy, maxrss=%7zu, RCU %u%s%+d\033[m/%zu/c%zu%sq%zu\033[m (%u)%pFB%s\033[K\n",
			 (long)t.tv_sec, (long)t.tv_nsec / 1000000, done, total, speed,
			 done * 100. / total, lvl_min, avglvl, powf(2.0, 3.0 + avglvl), lvl_max,
			 inflight_shrinks, n_busy, (size_t){ ru.ru_maxrss }, rcudbg.seq_head,
			 delta_color, rcudbg.seq_delta, rcudbg.holding, rcudbg.completed,
			 qlen_color, rcudbg.qlen, rcu_seqno_in - rcu_seqno_out, &fb_stopped,
			 stop_state);
		printfrr("U,L on-list: %6zu  off-list: %6zu  off-outdated: %6zu  shrinking: %6zu  deleted: %6zu\033[K\n",
			 stop_stats.ul_through_list, stop_stats.ul_off_list,
			 stop_stats.ul_off_list_outdated, stop_stats.items_shrinking,
			 stop_stats.items_deleted);

		if (rcudbg.qlen > 2000 && !stopped) {
			atomic_store_explicit(&sync_seq_expect, sync_seq_at, memory_order_relaxed);
			clock_gettime(CLOCK_MONOTONIC, &stop_t);
			stopped = true;
			printf("\n");
		}
		if (rcudbg.qlen < 10 && stopped) {
			sync_seq_at = seqlock_bump(&sync_seq);
			stopped = false;
			printf("\n");
		}
		fflush(stdout);

		rcu_ping->seqno = ++rcu_seqno_in;
		rcu_call(rcu_ping_fn, rcu_ping, head);
		rcu_read_unlock();
		usleep(100 * 1000);
		rcu_read_lock();

		prev_done = done;
	} while (n_busy && !atomic_load_explicit(&ctl_c, memory_order_relaxed));

	seqlock_release(&sync_seq);

	size_t stats[array_size(stats_names)] = {};
	size_t total_done = 0, total_samples = 0;
	size_t pos;

	printf("\r%s\033[K\n", ctl_c ? "interrupted" : "done");

	if (sampler_interval) {
		pthread_cancel(sampler_thread);
		pthread_join(sampler_thread, NULL);
	}

	for (long i = 0; i < n_threads; i++) {
		pthread_join(threads[i].pt, NULL);

		pos = atomic_load(&threads[i].pos);

		total_done += (pos != ~0ULL) ? pos : itercount;

		for (size_t j = 0; j < array_size(stats_names); j++)
			stats[j] += threads[i].stats[j];
	}

	for (size_t j = 0; j < array_size(sample_stats); j++)
		total_samples += sample_stats[j] + sample_stats_aux[j];

	size_t sample_sum = 0, rel_sum = 0;

	printf(" ------- event ------- ");
	if (sampler_interval)
		printf("-- cpu/time --- ");
	printf("----- description -----\n");
	printf("    count     share     ");
	if (sampler_interval)
		printf("  hash    test  ");
	printf("\n");
	for (size_t j = 0; j < array_size(stats_names); j++) {
		const char *pre = stats_is_base[j] ? "" : stats_is_base[j + 1] ? "   └─" : "   ├─";
		const char *post = stats_is_base[j] ? "     " : "";

		if (stats_is_base[j]) {
			sample_sum = total_samples;
			if (j < STAT_RCU_SAMPLES)
				sample_sum = total_samples / n_threads;
			rel_sum = total_done;
		}

		float this_stat = stats[j] / (float)rel_sum;
		const char *cc = "";

		switch (j) {
		case STAT_FIND_NEG:
			this_stat = 1.0 - fabs(this_stat - 0.5) * 3;
			fallthrough;
		case STAT_ADD_DONE:
		case STAT_ADDCOL_DONE:
		case STAT_DEL_DONE:
			if (this_stat >= 0.985)
				cc = "\033[36m";
			else if (this_stat >= 0.97)
				cc = "\033[32m";
			else if (this_stat >= 0.955)
				cc = "\033[33m";
			else
				cc = "\033[31m";
			break;
		}

		if (!stat_has_counters(j))
			printf("%23s", "");
		else
			printf("%9zu %s%s%6.2f%%\033[m%s ", stats[j], pre, cc,
			       100. * stats[j] / (float)rel_sum, post);

		if (sampler_interval) {
			if (sample_stats[j])
				printf("%6.2f%% ", 100. * sample_stats[j] / (float)sample_sum);
			else
				printf("%8s", "");
			if (sample_stats_aux[j])
				printf("%6.2f%% ", 100. * sample_stats_aux[j] / (float)sample_sum);
			else
				printf("%8s", "");
		}

		printf("%s\n", stats_names[j]);

		if (stats_is_base[j]) {
			sample_sum = sample_stats[j] + sample_stats_aux[j];
			rel_sum = stats[j];
		}
	}
	printf("%9zd %*stotal grow - shrink\n",
	       stats[STAT_GROW_DONE] + stats[STAT_GROW_FAKE_DONE] + stats[STAT_GROW_FADD_NEWLVL] -
		       stats[STAT_SHRINK_DONE],
	       sampler_interval ? 29 : 13, "");

	if (ctl_c)
		printf("\033[93mTEST INTERRUPTED\033[m\n");
	else
		printf("\033[92mTEST PASSED\033[m\n");
}

void _zlog_assert_failed(const struct xref_assert *xref, const char *extra, ...)
{
	va_list ap;
	static bool in_assert;
	int cc = ctl_c ? 33 : 31;

	if (ctl_c)
		printfrr("\033[97;1massertion failure after interrupt may be random\033[m\n");

	if (extra) {
		struct va_format vaf;

		va_start(ap, extra);
		vaf.fmt = extra;
		vaf.va = &ap;

		printfrr("\033[%dm%s:%d: %s(): assert(\033[%d;1m%s\033[%d;22m) failed, extra info: \033[97m%pVA\033[m\n",
			 cc, xref->xref.file, xref->xref.line, xref->xref.func, cc + 60,
			 xref->expr, cc, &vaf);

		va_end(ap);
	} else
		printfrr("\033[%dm%s:%d: %s(): assert(\033[%d;1m%s\033[%d;4m) failed\033[m\n", cc,
			 xref->xref.file, xref->xref.line, xref->xref.func, cc + 60, xref->expr,
			 cc);

	if (ctl_c)
		pthread_exit(NULL);
	if (!in_assert) {
		in_assert = true;
		printfrr("running consistency check...\n");
		test_check(NULL, 0);
		printfrr("\033[33mconsistency check passed, #UL=%zu\033[m\n", n_ul);
	} else {
		printfrr("\033[31mconsistency check FAILED\033[m\n");
	}

	abort();
}

static void sigint(int signo)
{
	atomic_store_explicit(&ctl_c, 1, memory_order_relaxed);
	signal(SIGINT, SIG_DFL);
}

/* option processing */

static unsigned long long si_num(const char *arg)
{
	char *endp = NULL;
	unsigned long long num = strtoul(arg, &endp, 0);

	if (!*arg || endp == arg) {
		fprintf(stderr, "invalid number: \"%s\"\n", arg);
		exit(2);
	}
	while (*endp) {
		switch (*endp) {
		case 'k':
			num *= 1000;
			break;
		case 'M':
			num *= 1000000;
			break;
		case 'G':
			num *= 1000000000;
			break;
		default:
			fprintf(stderr, "invalid number: \"%s\"\n", arg);
			exit(2);
		}
		endp++;
	}

	return num;
}

static void handle_slow_opt(enum slow_level *dst, const char *arg)
{
	for (unsigned int i = 0; i < array_size(slow_names); i++) {
		if (strcmp(slow_names[i], arg))
			continue;

		*dst = i;
		return;
	}

	fprintf(stderr, "invalid slowdown option \"%s\"\n", arg);
	exit(2);
}

static intmax_t opt_num(const char *arg, intmax_t min, intmax_t max)
{
	char *endp = NULL;
	intmax_t val;

	errno = 0;
	val = strtoimax(arg, &endp, 0);
	if (!*arg || (endp && *endp) || errno) {
		fprintf(stderr, "invalid number: \"%s\"\n", arg);
		exit(2);
	}
	if (val < min || val > max) {
		fprintf(stderr, "value %jd out of range [%jd,%jd]\n", val, min, max);
		exit(2);
	}

	return val;
}

enum {
	OPTION_NO_MMAP = 1000,
	OPTION_SLOW_LOOP,
	OPTION_SLOW_LOOP_FREQ,
#ifdef TEST_HIJACK_ATOMICS
	OPTION_SLOW_GENERAL_RD,
	OPTION_SLOW_GENERAL_OP,
	OPTION_SLOW_RESIZE_RD,
	OPTION_SLOW_RESIZE_OP,
	OPTION_SLOW_GENERAL,
	OPTION_SLOW_RESIZE,
	OPTION_SLOW_RD,
	OPTION_SLOW_OP,
	OPTION_SLOW,
#endif
	OPTION_POISON_FREQ,
	OPTION_RCU_FREQ,
	OPTION_SAMPLER_USEC,
	OPTION_STOP_CHECK,
};

static struct option longopts[] = {
	{ "no-mmap", no_argument, NULL, OPTION_NO_MMAP },
	{ "slow-loop", required_argument, NULL, OPTION_SLOW_LOOP },
	{ "slow-loop-logn", required_argument, NULL, OPTION_SLOW_LOOP_FREQ },

#ifdef TEST_HIJACK_ATOMICS
	{ "slow-general-read", required_argument, NULL, OPTION_SLOW_GENERAL_RD },
	{ "slow-general-oper", required_argument, NULL, OPTION_SLOW_GENERAL_OP },
	{ "slow-resize-read", required_argument, NULL, OPTION_SLOW_RESIZE_RD },
	{ "slow-resize-oper", required_argument, NULL, OPTION_SLOW_RESIZE_OP },
	{ "slow-general", required_argument, NULL, OPTION_SLOW_GENERAL },
	{ "slow-resize", required_argument, NULL, OPTION_SLOW_RESIZE },
	{ "slow-read", required_argument, NULL, OPTION_SLOW_RD },
	{ "slow-oper", required_argument, NULL, OPTION_SLOW_OP },
	{ "slow", required_argument, NULL, OPTION_SLOW },
#endif

	{ "random-values", no_argument, NULL, 'r' },
	{ "no-collisions", no_argument, NULL, 'C' },
	{ "help", no_argument, NULL, 'h' },

	/* logarithmic (2^n) options */
	{ "poison-logn", required_argument, NULL, OPTION_POISON_FREQ },
	{ "rcu-logn", required_argument, NULL, OPTION_RCU_FREQ },

	{ "sampler-usec", required_argument, NULL, OPTION_SAMPLER_USEC },
	{ "sampler-stop-check", required_argument, NULL, OPTION_STOP_CHECK },
	{},
};

int main(int argc, char **argv)
{
	size_t levels_init = 0;
	bool collisions = true, rand_mode = false;
	long n_threads = 8;
	int opt;
	struct timespec ts;

	rcu_freq = 16;
	n_items = 250;

	while ((opt = getopt_long(argc, argv, "rCn:N:t:i:l:L:Xx:h", longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			printf("You're on your own.\n");
			break;

		case OPTION_NO_MMAP:
			mmap_mode = false;
			break;

		case OPTION_SLOW_LOOP:
			handle_slow_opt(&slow_loop, optarg);
			break;

		case OPTION_SLOW_LOOP_FREQ:
			slow_loop_freq = opt_num(optarg, 0, 32);
			break;

#ifdef TEST_HIJACK_ATOMICS
		case OPTION_SLOW_GENERAL_RD:
			handle_slow_opt(&general.rd, optarg);
			break;

		case OPTION_SLOW_GENERAL_OP:
			handle_slow_opt(&general.op, optarg);
			break;

		case OPTION_SLOW_RESIZE_RD:
			handle_slow_opt(&resize.rd, optarg);
			break;

		case OPTION_SLOW_RESIZE_OP:
			handle_slow_opt(&resize.op, optarg);
			break;

		case OPTION_SLOW_GENERAL:
			handle_slow_opt(&general.rd, optarg);
			handle_slow_opt(&general.op, optarg);
			break;

		case OPTION_SLOW_RESIZE:
			handle_slow_opt(&resize.rd, optarg);
			handle_slow_opt(&resize.op, optarg);
			break;

		case OPTION_SLOW_RD:
			handle_slow_opt(&general.rd, optarg);
			handle_slow_opt(&resize.rd, optarg);
			break;

		case OPTION_SLOW_OP:
			handle_slow_opt(&general.op, optarg);
			handle_slow_opt(&resize.op, optarg);
			break;

		case OPTION_SLOW:
			handle_slow_opt(&general.rd, optarg);
			handle_slow_opt(&general.op, optarg);
			handle_slow_opt(&resize.rd, optarg);
			handle_slow_opt(&resize.op, optarg);
			break;
#endif /* TEST_HIJACK_ATOMICS */

		case OPTION_POISON_FREQ:
			poison_freq = opt_num(optarg, 0, 32);
			break;

		case OPTION_SAMPLER_USEC:
			sampler_interval = opt_num(optarg, 0, LONG_MAX);
			break;

		case OPTION_STOP_CHECK:
			stop_check_rate = opt_num(optarg, 0, LONG_MAX);
			break;

		case OPTION_RCU_FREQ:
			rcu_freq = opt_num(optarg, 0, 32);
			break;

		case 'n':
			n_items = si_num(optarg);
			if (n_items > 1000)
				fprintf(stderr,
					"\033[91;1mWARNING: high item counts reduce the probability of race conditions!  Less is more.\033[m\n");
			break;

		case 'N':
			thread_item_arena_size = si_num(optarg);
			break;

		case 't':
			n_threads = opt_num(optarg, 1, LONG_MAX);
			break;

		case 'i':
			itercount = si_num(optarg);
			break;

		case 'r':
			rand_mode = true;
			break;

		case 'C':
			collisions = false;
			break;

		case 'l':
			shrink_adjust = opt_num(optarg, -3, 5);
			break;

		case 'L':
			levels_init = opt_num(optarg, 0, 32);
			break;

		case 'x':
			prng_seed = opt_num(optarg, 0, UINT32_MAX);
			break;

		case 'X':
			clock_gettime(CLOCK_REALTIME, &ts);
			prng_seed = ts.tv_nsec;
			break;

		default:
			fprintf(stderr, "invalid option %c\n", opt);
			exit(2);
		}
	}

	while (optind < argc) {
		const char *arg = argv[optind++];
		const char *eq = strchr(arg, '=');
		char *endp = NULL;
		struct test_action *ta;

		if (!eq || !eq[1]) {
			fprintf(stderr, "invalid setting: %s\n", arg);
			return 1;
		}

		for (ta = actions; ta < actions + array_size(actions); ta++)
			if (strlen(ta->name) == (size_t)(eq - arg) &&
			    !memcmp(ta->name, arg, eq - arg))
				break;
		if (ta == actions + array_size(actions)) {
			fprintf(stderr, "invalid item: %.*s\n", (int)(eq - arg), arg);
			return 1;
		}

		ta->chance = strtof(eq + 1, &endp);
		if ((endp && *endp) || ta->chance < 0.0) {
			fprintf(stderr, "invalid probability: %s\n", eq + 1);
			return 1;
		}
	}

	float running_sum = 0.0, u32f = 1. / (1U << 31);

	for (struct test_action *ta = actions; ta < actions + array_size(actions); ta++)
		running_sum += ta->chance;

	running_sum = (1U << 31) / running_sum;

	for (struct test_action *ta = actions; ta < actions + array_size(actions); ta++) {
		ta->chance_u32 = lrint(ta->chance * running_sum);
		printf("%9.5f%%  (%9.5f×) %s\n", 100. * u32f * ta->chance_u32, ta->chance,
		       ta->name);
	}

	if (!thread_item_arena_size)
		thread_item_arena_size = MAX(16384U, (1ULL << rcu_freq) * 4U);

	prng = prng_new(0xcafef00d + prng_seed);

	if (optind < argc) {
		fprintf(stderr, "invalid options\n");
		exit(2);
	}

	printf("%zu items, %zu thread item arena, %zu iterations, %lu threads, slow %s 1:%llu, RCU 1:%llu\n",
	       n_items, thread_item_arena_size, itercount, n_threads, slow_names[slow_loop],
	       (1ULL << slow_loop_freq), (1ULL << rcu_freq));
#ifdef TEST_HIJACK_ATOMICS
	printf("atomic ops slowdown: general[read: %s, oper: %s] resize[read: %s, oper: %s]\n",
	       slow_names[general.rd], slow_names[general.op], slow_names[resize.rd],
	       slow_names[resize.op]);
#endif

	if (posix_memalign((void **)&item_states, CACHELINESIZE, n_items * sizeof(item_states[0]))) {
		perror("posix_memalign");
		exit(1);
	}
	memset(item_states, 0, n_items * sizeof(item_states[0]));
	for (size_t i = 0; i < n_items; i++) {
		uint32_t val = rand_mode ? (uint32_t)prng_rand(prng) : i;
		uint32_t hashval = jhash_1word(val, 0xd00dbabe);

		if (collisions) {
			/* force some collisions */
			if (!(i & 0x7))
				hashval &= 0xa8888888;
			if (!(i & 0xf)) {
				hashval |= hashval >> 1;
				hashval |= (hashval >> 2) & 0x03333333;
			}
		}

		item_states[i].val = val;
		item_states[i].hashval = hashval;
	}

	signal(SIGINT, sigint);
	signal(SIGUSR1, sigusr1);

	sigemptyset(&usr1_set);
	sigaddset(&usr1_set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &usr1_set, NULL);

	rcu_prepare();
	mt_tests(n_threads, levels_init);
	rcu_shutdown();

	return ctl_c ? 3 : 0;
}
