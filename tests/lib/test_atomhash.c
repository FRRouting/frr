// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-2018  David Lamparter, for NetDEF, Inc.
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
#include <pthread.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sched.h>

/* gettid */
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#ifdef linux
#include <sys/syscall.h>
#endif

#include "atomhash.h"
#include "seqlock.h"
#include "monotime.h"
#include "printfrr.h"
#include "frrcu.h"
#include "jhash.h"

#include "tests/helpers/c/prng.h"

#define DEBUG_ATOMHASH
#define TEST_HIJACK_ATOMICS

#ifdef TEST_HIJACK_ATOMICS
/* clang-format off */
#define atomic__load(...)		({ atomic_load_explicit(__VA_ARGS__); })
#define atomic__store(...)		({ atomic_store_explicit(__VA_ARGS__); })
#define atomic__exchange(...)		({ spin_cpu(); atomic_exchange_explicit(__VA_ARGS__); })
#define atomic__cmpxchg_strong(...)	({ spin_cpu(); atomic_compare_exchange_strong_explicit(__VA_ARGS__); })
#define atomic__cmpxchg_weak(...)	({ spin_cpu(); atomic_compare_exchange_weak_explicit(__VA_ARGS__); })
#define atomic__fetch_or(...)		({ spin_cpu(); atomic_fetch_or_explicit(__VA_ARGS__); })
#define atomic__fetch_and(...)		({ spin_cpu(); atomic_fetch_and_explicit(__VA_ARGS__); })
#define atomic__fetch_add(...)		({ spin_cpu(); atomic_fetch_add_explicit(__VA_ARGS__); })
#define atomic__fetch_sub(...)		({ spin_cpu(); atomic_fetch_sub_explicit(__VA_ARGS__); })
/* clang-format on */
#endif

#define ATOMHASH_GROW_STOCHASTIC_THRESHOLD 3

#define thread_local _Thread_local
#define alignas	     _Alignas
#define noinline     __attribute__((noinline))

struct rcu_atomhash_shrink;

static int slow_level, spin_level;
thread_local static struct prng *prng;
thread_local static bool is_rcu_thread;
static atomic int ctl_c;
static uint32_t prng_seed;

static noinline void spin_cpu(void)
{
	if (spin_level >= 3) {
		sched_yield();
	} else if (spin_level >= 2) {
		getsid(0);
	} else if (spin_level >= 1) {
		int r = prng_rand(prng) & 0x3f;

		for (int i = 0; i < r; i++)
			asm volatile("");
	}
}

#include "lib/atomhash.c"

enum state {
	OFFLIST = 0,
	ADDING = 1,
	ONLIST = 2,
	REMOVING = 3,

	FIND = 0x100,

	BUSY_MASK = 0x101,
};
#define state_next(s) (((s) + 1) & 0x3)

#define CACHELINESIZE 64
#define RCU_DITHER    64

struct inner_item {
	struct atomhash_item item;
	uint32_t val;
	int32_t offs;
};

struct item {
	struct inner_item cycle[RCU_DITHER];

	alignas(CACHELINESIZE) atomic uint32_t state;
	uint32_t last_used;
	uint32_t dither;
};
static_assert(alignof(struct item) % CACHELINESIZE == 0, "alignment mishap");

static int icmp(const struct atomhash_item *a, const struct atomhash_item *b)
{
	const struct inner_item *ai = container_of(a, struct inner_item, item);
	const struct inner_item *bi = container_of(b, struct inner_item, item);

	return numcmp(ai->val, bi->val);
}

enum stats {
	STAT_ADD,
	STAT_DEL,
	STAT_ADDDEL_BUSY,
	STAT_ADDDEL_RCU_HOT,
	STAT_ADDDEL_RACE,
	STAT_ADDCOL,
	STAT_ADDCOL_BUSY,
	STAT_ADDCOL_RACE,
	STAT_FIND,
	STAT_FIND_BUSY,
	STAT_FIND_RACE,
	STAT_GROW,
	STAT_GROW_NOOP = STAT_GROW + RESIZE_NOOP,
	STAT_GROW_COLLISION = STAT_GROW + RESIZE_RACED,
	STAT_GROW_FUDGED = STAT_GROW + RESIZE_FUDGED,
	STAT_GROW_FAKE,
	STAT_GROW_CEILING,
	STAT_SHRINK,
	STAT_SHRINK_NOOP = STAT_SHRINK + RESIZE_NOOP,
	STAT_SHRINK_COLLISION = STAT_SHRINK + RESIZE_RACED,
	STAT_SHRINK_RCURATELIMIT = STAT_SHRINK + RESIZE_FUDGED,
	STAT_SHRINK_FLOOR,
	STAT_SHRINK_PROBABILITY,
};

const char *const stats_names[] = {
	[STAT_ADD] = "add",
	[STAT_DEL] = "del",
	[STAT_ADDDEL_BUSY] = "add/del: item busy",
	[STAT_ADDDEL_RCU_HOT] = "add/del: item blocked in RCU",
	[STAT_ADDDEL_RACE] = "add/del: test raced",
	[STAT_ADDCOL] = "add-collide",
	[STAT_ADDCOL_BUSY] = "add-coll: item busy",
	[STAT_ADDCOL_RACE] = "add-coll: test raced",
	[STAT_FIND] = "find",
	[STAT_FIND_BUSY] = "find: item busy",
	[STAT_FIND_RACE] = "find: test raced",
	[STAT_GROW] = "grow",
	[STAT_GROW_NOOP] = "grow: no-op",
	[STAT_GROW_COLLISION] = "grow: collision",
	[STAT_GROW_FUDGED] = "grow: probability declined",
	[STAT_GROW_FAKE] = "grow (empty alloc)",
	[STAT_GROW_CEILING] = "grow: level ceiling",
	[STAT_SHRINK] = "shrink",
	[STAT_SHRINK_NOOP] = "shrink: no-op",
	[STAT_SHRINK_COLLISION] = "shrink: collision",
	[STAT_SHRINK_RCURATELIMIT] = "shrink: RCU ratelimit",
	[STAT_SHRINK_FLOOR] = "shrink: level floor",
	[STAT_SHRINK_PROBABILITY] = "shrink: probability fudge",
};

struct thread_info {
	pthread_t pt;
	struct rcu_thread *rt;
	long thread_num;
	atomic_size_t pos;

	size_t stats[array_size(stats_names)];
};
static thread_local struct thread_info *thread_info;

static struct atomhash_head head[1];

static size_t n_items;
static struct item *itm;

static size_t itercount = 1000000;
static size_t levels_min, levels_max;
static atomic size_t n_ul;

struct rcu_dummy_del {
	struct rcu_head head;
};

static void rcu_dummy_del(struct rcu_dummy_del *rcu)
{
	free(rcu);
}

static void mark_del(struct item *item)
{
	struct rcu_stats rcudbg;

	rcu_stats(&rcudbg);

	if (++item->dither == RCU_DITHER) {
		struct rcu_dummy_del *dummy_del = malloc(sizeof(*dummy_del));

		item->dither = 0;
		item->last_used = rcudbg.seq_head;
		rcu_call(rcu_dummy_del, dummy_del, head);
	}
}

static bool can_add(struct item *item)
{
	struct rcu_stats rcudbg;
	uint32_t cur;
	bool rv;

	if (item->dither != 0)
		return true;

	rcu_stats(&rcudbg);
	cur = rcudbg.seq_head - rcudbg.seq_delta * SEQLOCK_INCR;

	rv = (int32_t)(cur - item->last_used) > 0 || !item->last_used;
	if (!rv)
		thread_info->stats[STAT_ADDDEL_RCU_HOT]++;
	return rv;
}

static void test_check(unsigned int r)
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
			hash_read = atomic_load_explicit(&item->hashval, memory_order_acquire);

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

	thread_info->stats[STAT_FIND]++;
}

static void test_grow_real(unsigned int r)
{
	size_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	enum resize_result rv;

	if (level++ == levels_max) {
		thread_info->stats[STAT_GROW_CEILING]++;
		return;
	}

	rv = atomhash_resize_grow(head, (1 << (level + 3)) - 4);
	thread_info->stats[STAT_GROW + rv]++;
}

static void test_grow_fake(unsigned int r)
{
	struct atomhash_array *array;
	size_t n;
	size_t level_hint, level_hint_adj;
	size_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	atomptr_t replace = ATOMPTR_NULL;

	if (level++ == levels_max) {
		thread_info->stats[STAT_GROW_CEILING]++;
		return;
	}

	assert(level > 0);
	n = level_size(level);

	array = XCALLOC(MTYPE_ATOMHASH_TABLE, sizeof(array->stubs[0]) * n);
	if (!atomic__cmpxchg_strong(&head->levels[level], &replace, atomptr_i(array),
				    memory_order_release, memory_order_relaxed)) {
		XFREE(MTYPE_ATOMHASH_TABLE, array);
		thread_info->stats[STAT_GROW_COLLISION]++;
		return;
	}

	level_hint = atomic__load(&head->level_hint, memory_order_relaxed);
	do {
		level_hint_adj = MAX(level_hint, (size_t)level);
		if (level_hint_adj == level_hint)
			break;
	} while (!atomic__cmpxchg_strong(&head->level_hint, &level_hint, level_hint_adj,
					 memory_order_relaxed, memory_order_relaxed));

	thread_info->stats[STAT_GROW_FAKE]++;
}

static void test_shrink(unsigned int r)
{
	size_t level = atomic__load(&head->level_hint, memory_order_relaxed);
	enum resize_result rv;

	if (level == levels_min) {
		thread_info->stats[STAT_SHRINK_FLOOR]++;
		return;
	}
	if ((r & ((1 << (levels_max - level + 1)) - 1))) {
		thread_info->stats[STAT_SHRINK_PROBABILITY]++;
		return;
	}

	//atomic__load(&head->levels[level], memory_order_acquire)))
	rv = atomhash_resize_shrink(head, 0); //(1 << level) - 1))
	thread_info->stats[STAT_SHRINK + rv]++;
}

static void test_adddel(unsigned int r)
{
	size_t retry = 0;
	ssize_t i = r % n_items;
	int dir = (r & (1 << 31)) ? -1 : 1;
	struct item *item;
	uint32_t prevstate, state;
	struct atomhash_item *ret, *ai;

	do {
		rcu_read_unlock();
		rcu_read_lock();
		if (retry++ > 50) {
			thread_info->stats[STAT_ADDDEL_BUSY]++;
			return;
		}

		item = &itm[i];
		i += dir;
		if (i == (ssize_t)n_items)
			i = 0;
		if (i == -1)
			i = n_items - 1;

		prevstate = atomic_load_explicit(&item->state, memory_order_relaxed);
	} while (prevstate & BUSY_MASK || (prevstate == OFFLIST && !can_add(item)));

	state = state_next(prevstate);
	if (!atomic_compare_exchange_strong_explicit(&item->state, &prevstate, state,
						     memory_order_relaxed, memory_order_relaxed)) {
		thread_info->stats[STAT_ADDDEL_RACE]++;
		return;
	}

	ai = &item->cycle[item->dither].item;

	switch (state) {
	case ADDING:
		if (!can_add(item)) {
			atomic_exchange_explicit(&item->state, prevstate, memory_order_relaxed);
			thread_info->stats[STAT_ADDDEL_BUSY]++;
			return;
		}
		ret = atomhash_add(head, ai, icmp);
		assert(!ret);
		thread_info->stats[STAT_ADD]++;
		break;
	case REMOVING:
		atomhash_del(head, ai);
		mark_del(item);
		thread_info->stats[STAT_DEL]++;
		break;
	default:
		assert(false);
	}

	prevstate = state;
	state = state_next(state);

	state = atomic_exchange_explicit(&item->state, state, memory_order_relaxed);
	assert(state == prevstate);
}

static void test_addcol(unsigned int r)
{
	size_t retry = 0;
	ssize_t i = r % n_items;
	int dir = (r & (1 << 31)) ? -1 : 1;
	struct item *item;
	struct inner_item fake = {};
	uint32_t prevstate, state;
	struct atomhash_item *ret, *ai;

	do {
		if (retry++ > 50) {
			thread_info->stats[STAT_ADDCOL_BUSY]++;
			return;
		}

		item = &itm[i];
		i += dir;
		if (i == (ssize_t)n_items)
			i = 0;
		if (i == -1)
			i = n_items - 1;

		prevstate = atomic_load_explicit(&item->state, memory_order_relaxed);
	} while (prevstate != ONLIST);

	state = prevstate | FIND;
	if (!atomic_compare_exchange_strong_explicit(&item->state, &prevstate, state,
						     memory_order_seq_cst, memory_order_relaxed)) {
		thread_info->stats[STAT_ADDCOL_RACE]++;
		return;
	}

	ai = &item->cycle[item->dither].item;
	fake.val = item->cycle[0].val;
	fake.offs = 0;
	fake.item.hashval = ai->hashval;

	ret = atomhash_add(head, &fake.item, icmp);
	assertf(ret == ai, "item=%p ret=%p hashval=%08x", item, ret, fake.item.hashval);

	state = atomic_exchange_explicit(&item->state, prevstate, memory_order_seq_cst);
	assert(state == (prevstate | FIND));

	thread_info->stats[STAT_ADDCOL]++;
}

#if 0
/* pop() cannot easily be tested :( */
static bool test_pop(unsigned int r)
{
	return false;
}
#endif

static void test_find(unsigned int r)
{
	size_t i = r % n_items;
	struct item *item = &itm[i];
	struct inner_item ref = { .val = i };
	uint32_t prevstate, state;
	struct atomhash_item *result, *inuse;
	bool expected, actual;

	prevstate = atomic_load_explicit(&item->state, memory_order_relaxed);
	if (prevstate & BUSY_MASK) {
		thread_info->stats[STAT_FIND_BUSY]++;
		return;
	}
	state = prevstate | FIND;
	if (!atomic_compare_exchange_strong_explicit(&item->state, &prevstate, state,
						     memory_order_seq_cst, memory_order_relaxed)) {
		thread_info->stats[STAT_FIND_RACE]++;
		return;
	}

	inuse = &itm[i].cycle[itm[i].dither].item;
	result = atomhash_get(head, &ref.item, inuse->hashval, icmp);

	state = atomic_exchange_explicit(&item->state, prevstate, memory_order_seq_cst);
	assert(state == (prevstate | FIND));

	expected = (prevstate == ONLIST);
	assertf(result == NULL || result == inuse, "result=%p inuse=%p hashval=%08x", result,
		inuse, inuse->hashval);
	actual = (result != NULL);
	assertf(actual == expected, "result=%p inuse=%p state=%d hashval=%08x", result, inuse,
		prevstate, inuse->hashval);

	thread_info->stats[STAT_FIND]++;
}

struct test_action {
	float chance;
	const char *name;
	void (*func)(unsigned int r);
};

/* clang-format off */
static struct test_action actions[] = {
	{ 0.04,    "check",     test_check },
	{ 0.0010,  "grow_real", test_grow_real },
	{ 0.0005,  "grow_fake", test_grow_fake },
	{ 0.0023,  "shrink",    test_shrink },
	{ 0.35,    "adddel",    test_adddel },
	{ 0.05,    "addcol",    test_addcol },
	{ 1.0,     "find",      test_find },
};
/* clang-format on */

static struct seqlock sync_seq;

static void thread_prio_down(void)
{
#if linux
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
	char thread_name[256];

	snprintf(thread_name, sizeof(thread_name), "ATOMHASH/%ld", thread_num);
	pthread_setname_np(pthread_self(), thread_name);

	rcu_thread_start(ti->rt);
	rcu_assert_read_locked();
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	/* make the RCU thread run preferentially before this */
	thread_prio_down();

	prng = prng_new(0xcafef00d * (thread_num + 2342) + prng_seed);

	seqlock_wait(&sync_seq, SEQLOCK_STARTVAL + SEQLOCK_INCR);
	rcu_read_unlock();

	for (i = 0; i < itercount; i++) {
		int r = prng_rand(prng);
		float action = r / (float)(1ULL << 32);

		rcu_read_lock();
		for (j = 0; j < array_size(actions); j++) {
			if (action < actions[j].chance) {
				actions[j].func(prng_rand(prng));
				break;
			}
			action -= actions[j].chance;
		}
		rcu_read_unlock();

		atomic_store(&ti->pos, i);

		if (!(i & 0x00)) {
			if (slow_level >= 2)
				sched_yield();
			else if (slow_level >= 1)
				getsid(0);
		}

		pthread_testcancel();
	}

	atomic_store(&ti->pos, ~0ULL);

	prng_free(prng);
	return NULL;
}

struct rcu_prng {
	struct rcu_head rcu;
	int close_fd;
};

static void rcu_set_prng(struct rcu_prng *rcu)
{
	is_rcu_thread = true;
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

static void mt_tests(long n_threads)
{
	struct thread_info threads[n_threads];
	size_t total = n_threads * itercount;
	size_t prev_done, speed;
	long n_busy;
	size_t lvl_size_cnt = 0;
	size_t lvl_size_sum = 0;
	pthread_attr_t pt_attr;
	struct sched_param sp = {
		.sched_priority = 10,
	};

	levels_min = MAX(lrint(log2(n_items) - 3.5 - 4), 0);
	levels_max = lrint(log2(n_items) + 2.5 - 4);

	printf("levels_min=%zu, levels_max=%zu\n", levels_min, levels_max);

	atomhash_init(head);
	head->freeze_size = true;

	atomhash_setup_level0(head);
	for (size_t i = 1; i <= levels_min; i++)
		atomhash_setup_level(head, i, ATOMPTR_NULL);

	pthread_attr_init(&pt_attr);
	pthread_attr_setschedparam(&pt_attr, &sp);

	seqlock_init(&sync_seq);
	seqlock_acquire_val(&sync_seq, SEQLOCK_STARTVAL);

	memset(threads, 0, sizeof(threads));
	for (long i = 0; i < n_threads; i++) {
		threads[i].thread_num = i;
		threads[i].rt = rcu_thread_prepare();
		pthread_create(&threads[i].pt, NULL, &thread_func, &threads[i]);
	}

	pthread_attr_destroy(&pt_attr);

	usleep(10);
	seqlock_release(&sync_seq);

	printf("\n");
	prev_done = speed = 0;
	do {
		struct timespec t;
		size_t done, ul;
		struct rusage ru;
		struct rcu_stats rcudbg;
		struct rcu_ping *rcu_ping = XMALLOC(MTYPE_TMP, sizeof(*rcu_ping));

		n_busy = 0;
		done = 0;
		for (long i = 0; i < n_threads; i++) {
			size_t pos = atomic_load(&threads[i].pos);

			if (pos != ~0ULL) {
				n_busy++;
				done += pos;
			} else
				done += itercount;
		}

		lvl_size_cnt++;
		lvl_size_sum += atomic_load_explicit(&head->level_hint, memory_order_relaxed);

		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
		getrusage(RUSAGE_SELF, &ru);

		speed *= 31;
		speed += (done - prev_done) * 5;
		speed /= 32;

		rcu_stats(&rcudbg);
		ul = atomic_load_explicit(&n_ul, memory_order_relaxed);
		printf("\033[1A%4ld.%03ld %zu/%zu %zu/s (%.1f%%) ΣUL=%zu avglvl=%.1f, %ld busy, maxrss=%zu, RCU %u%+d/%zu/c%zuq%zu (%u)\033[K\n",
		       (long)t.tv_sec, (long)t.tv_nsec / 1000000, done, total, speed,
		       done * 100. / total, ul, lvl_size_sum / (float)lvl_size_cnt, n_busy,
		       (size_t)ru.ru_maxrss, rcudbg.seq_head, rcudbg.seq_delta, rcudbg.holding,
		       rcudbg.completed, rcudbg.qlen, rcu_seqno_in - rcu_seqno_out);
		fflush(stdout);

		rcu_ping->seqno = ++rcu_seqno_in;
		rcu_call(rcu_ping_fn, rcu_ping, head);
		rcu_read_unlock();
		usleep(200 * 1000);
		rcu_read_lock();

		prev_done = done;
	} while (n_busy && !atomic_load_explicit(&ctl_c, memory_order_relaxed));

	size_t stats[array_size(stats_names)] = {};

	printf("\r%s\033[K\n", ctl_c ? "interrupted" : "done");
	for (long i = 0; i < n_threads; i++) {
		if (ctl_c)
			pthread_cancel(threads[i].pt);
		pthread_join(threads[i].pt, NULL);
		for (size_t j = 0; j < array_size(stats_names); j++)
			stats[j] += threads[i].stats[j];
	}

	for (size_t j = 0; j < array_size(stats_names); j++)
		printf("%9zu %s\n", stats[j], stats_names[j]);

	if (ctl_c)
		printf("\033[93mTEST INTERRUPTED\033[m\n");
	else
		printf("\033[92mTEST PASSED\033[m\n");
}

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
		test_check(0);
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

int main(int argc, char **argv)
{
	unsigned long n_threads = 8;
	int opt;
	struct timespec ts;

	spin_level = 1;
	n_items = 250;

	while ((opt = getopt(argc, argv, "n:t:i:s:S:Xx:")) != -1) {
		switch (opt) {
		case 'n':
			n_items = si_num(optarg);
			break;

		case 't':
			n_threads = si_num(optarg);
			break;

		case 'i':
			itercount = si_num(optarg);
			break;

		case 's':
			slow_level = atoi(optarg);
			break;

		case 'S':
			spin_level = atoi(optarg);
			break;

		case 'x':
			prng_seed = atoi(optarg);
			break;

		case 'X':
			clock_gettime(CLOCK_REALTIME, &ts);
			prng_seed = ts.tv_nsec;
			break;

		default:
			fprintf(stderr, "invalid option\n");
			exit(2);
		}
	}

	prng = prng_new(0xcafef00d + prng_seed);

	if (optind < argc) {
		fprintf(stderr, "invalid options\n");
		exit(2);
	}

	printf("%zu items, %zu iterations, %lu threads, slow %d, spin %d\n", n_items, itercount,
	       n_threads, slow_level, spin_level);

	if (posix_memalign((void **)&itm, CACHELINESIZE, n_items * sizeof(struct item))) {
		perror("posix_memalign");
		exit(1);
	}
	memset(itm, 0, n_items * sizeof(*itm));
	for (size_t i = 0; i < n_items; i++) {
		uint32_t hashval = jhash_1word(i, 0xd00dbabe);
		/* force some collisions */
		if (!(i & 0x7))
			hashval &= 0xa8888888;
		if (!(i & 0xf)) {
			hashval |= hashval >> 1;
			hashval |= (hashval >> 2) & 0x03333333;
		}

		for (size_t j = 0; j < RCU_DITHER; j++) {
			itm[i].cycle[j].val = i;
			itm[i].cycle[j].offs = j;
			itm[i].cycle[j].item.hashval = hashval;
		}
	}

	signal(SIGINT, sigint);

	rcu_prepare();
	mt_tests(n_threads);
	rcu_shutdown();
	return ctl_c ? 3 : 0;
}
