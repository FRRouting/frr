/*
 * Copyright (c) 2017-19  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* implementation notes:  this is an epoch-based RCU implementation.  rcu_seq
 * (global variable) counts the current epoch.  Threads hold a specific epoch
 * in rcu_read_lock().  This is the oldest epoch a thread might be accessing
 * data from.
 *
 * The rcu_seq global is only pushed forward on rcu_read_lock() and
 * rcu_read_unlock() calls.  This makes things a tad more efficient since
 * those are the only places it matters:
 * - on rcu_read_lock, we don't want to hold an old epoch pointlessly
 * - on rcu_read_unlock, we want to make sure we're not stuck on an old epoch
 *   when heading into a long idle period where no thread holds RCU
 *
 * rcu_thread structures themselves are RCU-free'd.
 *
 * rcu_head structures are the most iffy;  normally for an ATOMLIST we would
 * need to make sure we use rcu_free or pthread_rwlock to deallocate old items
 * to prevent ABA or use-after-free problems.  However, our ATOMLIST code
 * guarantees that if the list remains non-empty in all cases, we only need
 * the "last" pointer to do an "add_tail()", i.e. we can't run into ABA/UAF
 * issues - but we do need to keep at least 1 item on the list.
 *
 * (Search the atomlist code for all uses of "last")
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "frrcu.h"
#include "seqlock.h"
#include "atomlist.h"

DEFINE_MTYPE_STATIC(LIB, RCU_THREAD,    "RCU thread")
DEFINE_MTYPE_STATIC(LIB, RCU_NEXT,      "RCU sequence barrier")

DECLARE_ATOMLIST(rcu_heads, struct rcu_head, head)

PREDECL_ATOMLIST(rcu_threads)
struct rcu_thread {
	struct rcu_threads_item head;

	struct rcu_head rcu_head;

	struct seqlock rcu;

	/* only accessed by thread itself, not atomic */
	unsigned depth;
};
DECLARE_ATOMLIST(rcu_threads, struct rcu_thread, head)

static const struct rcu_action rcua_next  = { .type = RCUA_NEXT };
static const struct rcu_action rcua_end   = { .type = RCUA_END };
static const struct rcu_action rcua_close = { .type = RCUA_CLOSE };

struct rcu_next {
	struct rcu_head head_free;
	struct rcu_head head_next;
};

#define rcu_free_internal(mtype, ptr, field)                                   \
	do {                                                                   \
		typeof(ptr) _ptr = (ptr);                                      \
		struct rcu_head *_rcu_head = &_ptr->field;                     \
		static const struct rcu_action _rcu_action = {                 \
			.type = RCUA_FREE,                                     \
			.u.free = {                                            \
				.mt = mtype,                                   \
				.offset = offsetof(typeof(*_ptr), field),      \
			},                                                     \
		};                                                             \
		_rcu_head->action = &_rcu_action;                              \
		rcu_heads_add_tail(&rcu_heads, _rcu_head);                     \
	} while (0)

/* primary global RCU position */
static struct seqlock rcu_seq;
/* this is set to rcu_seq whenever something is added on the RCU queue.
 * rcu_read_lock() and rcu_read_unlock() will then bump rcu_seq up one step.
 */
static _Atomic seqlock_val_t rcu_dirty;

static struct rcu_threads_head rcu_threads;
static struct rcu_heads_head rcu_heads;

/* main thread & RCU sweeper have pre-setup rcu_thread structures.  The
 * reasons are different:
 *
 * - rcu_thread_main is there because the main thread isn't started like
 *   other threads, it's implicitly created when the program is started.  So
 *   rcu_thread_main matches up implicitly.
 *
 * - rcu_thread_rcu isn't actually put on the rcu_threads list (makes no
 *   sense really), it only exists so we can call RCU-using functions from
 *   the RCU thread without special handling in rcu_read_lock/unlock.
 */
static struct rcu_thread rcu_thread_main;
static struct rcu_thread rcu_thread_rcu;

static pthread_t rcu_pthread;
static pthread_key_t rcu_thread_key;
static bool rcu_active;

static void rcu_start(void);
static void rcu_bump(void);

/*
 * preinitialization for main thread
 */
static void rcu_thread_end(void *rcu_thread);

static void rcu_preinit(void) __attribute__((constructor));
static void rcu_preinit(void)
{
	struct rcu_thread *rt;

	rt = &rcu_thread_main;
	rt->depth = 1;
	seqlock_init(&rt->rcu);
	seqlock_acquire_val(&rt->rcu, SEQLOCK_STARTVAL);

	pthread_key_create(&rcu_thread_key, rcu_thread_end);
	pthread_setspecific(rcu_thread_key, rt);

	rcu_threads_add_tail(&rcu_threads, rt);

	/* RCU sweeper's rcu_thread is a dummy, NOT added to rcu_threads */
	rt = &rcu_thread_rcu;
	rt->depth = 1;

	seqlock_init(&rcu_seq);
	seqlock_acquire_val(&rcu_seq, SEQLOCK_STARTVAL);
}

static struct rcu_thread *rcu_self(void)
{
	return (struct rcu_thread *)pthread_getspecific(rcu_thread_key);
}

/*
 * thread management (for the non-main thread)
 */
struct rcu_thread *rcu_thread_prepare(void)
{
	struct rcu_thread *rt, *cur;

	rcu_assert_read_locked();

	if (!rcu_active)
		rcu_start();

	cur = rcu_self();
	assert(cur->depth);

	/* new thread always starts with rcu_read_lock held at depth 1, and
	 * holding the same epoch as the parent (this makes it possible to
	 * use RCU for things passed into the thread through its arg)
	 */
	rt = XCALLOC(MTYPE_RCU_THREAD, sizeof(*rt));
	rt->depth = 1;

	seqlock_init(&rt->rcu);
	seqlock_acquire(&rt->rcu, &cur->rcu);

	rcu_threads_add_tail(&rcu_threads, rt);

	return rt;
}

void rcu_thread_start(struct rcu_thread *rt)
{
	pthread_setspecific(rcu_thread_key, rt);
}

void rcu_thread_unprepare(struct rcu_thread *rt)
{
	if (rt == &rcu_thread_rcu)
		return;

	rt->depth = 1;
	seqlock_acquire(&rt->rcu, &rcu_seq);

	rcu_bump();
	if (rt != &rcu_thread_main)
		/* this free() happens after seqlock_release() below */
		rcu_free_internal(&_mt_RCU_THREAD, rt, rcu_head);

	rcu_threads_del(&rcu_threads, rt);
	seqlock_release(&rt->rcu);
}

static void rcu_thread_end(void *rtvoid)
{
	struct rcu_thread *rt = rtvoid;
	rcu_thread_unprepare(rt);
}

/*
 * main RCU control aspects
 */

static void rcu_bump(void)
{
	struct rcu_next *rn;

	rn = XMALLOC(MTYPE_RCU_NEXT, sizeof(*rn));

	/* note: each RCUA_NEXT item corresponds to exactly one seqno bump.
	 * This means we don't need to communicate which seqno is which
	 * RCUA_NEXT, since we really don't care.
	 */

	/*
	 * Important race condition:  while rcu_heads_add_tail is executing,
	 * there is an intermediate point where the rcu_heads "last" pointer
	 * already points to rn->head_next, but rn->head_next isn't added to
	 * the list yet.  That means any other "add_tail" calls append to this
	 * item, which isn't fully on the list yet.  Freeze this thread at
	 * that point and look at another thread doing a rcu_bump.  It adds
	 * these two items and then does a seqlock_bump.  But the rcu_heads
	 * list is still "interrupted" and there's no RCUA_NEXT on the list
	 * yet (from either the frozen thread or the second thread).  So
	 * rcu_main() might actually hit the end of the list at the
	 * "interrupt".
	 *
	 * This situation is prevented by requiring that rcu_read_lock is held
	 * for any calls to rcu_bump, since if we're holding the current RCU
	 * epoch, that means rcu_main can't be chewing on rcu_heads and hit
	 * that interruption point.  Only by the time the thread has continued
	 * to rcu_read_unlock() - and therefore completed the add_tail - the
	 * RCU sweeper gobbles up the epoch and can be sure to find at least
	 * the RCUA_NEXT and RCUA_FREE items on rcu_heads.
	 */
	rn->head_next.action = &rcua_next;
	rcu_heads_add_tail(&rcu_heads, &rn->head_next);

	/* free rn that we allocated above.
	 *
	 * This is INTENTIONALLY not built into the RCUA_NEXT action.  This
	 * ensures that after the action above is popped off the queue, there
	 * is still at least 1 item on the RCU queue.  This means we never
	 * delete the last item, which is extremely important since it keeps
	 * the atomlist ->last pointer alive and well.
	 *
	 * If we were to "run dry" on the RCU queue, add_tail may run into the
	 * "last item is being deleted - start over" case, and then we may end
	 * up accessing old RCU queue items that are already free'd.
	 */
	rcu_free_internal(&_mt_RCU_NEXT, rn, head_free);

	/* Only allow the RCU sweeper to run after these 2 items are queued.
	 *
	 * If another thread enqueues some RCU action in the intermediate
	 * window here, nothing bad happens - the queued action is associated
	 * with a larger seq# than strictly necessary.  Thus, it might get
	 * executed a bit later, but that's not a problem.
	 *
	 * If another thread acquires the read lock in this window, it holds
	 * the previous epoch, but its RCU queue actions will be in the next
	 * epoch.  This isn't a problem either, just a tad inefficient.
	 */
	seqlock_bump(&rcu_seq);
}

static void rcu_bump_maybe(void)
{
	seqlock_val_t dirty;

	dirty = atomic_load_explicit(&rcu_dirty, memory_order_relaxed);
	/* no problem if we race here and multiple threads bump rcu_seq;
	 * bumping too much causes no issues while not bumping enough will
	 * result in delayed cleanup
	 */
	if (dirty == seqlock_cur(&rcu_seq))
		rcu_bump();
}

void rcu_read_lock(void)
{
	struct rcu_thread *rt = rcu_self();

	assert(rt);
	if (rt->depth++ > 0)
		return;

	seqlock_acquire(&rt->rcu, &rcu_seq);
	/* need to hold RCU for bump ... */
	rcu_bump_maybe();
	/* ... but no point in holding the old epoch if we just bumped */
	seqlock_acquire(&rt->rcu, &rcu_seq);
}

void rcu_read_unlock(void)
{
	struct rcu_thread *rt = rcu_self();

	assert(rt && rt->depth);
	if (--rt->depth > 0)
		return;
	rcu_bump_maybe();
	seqlock_release(&rt->rcu);
}

void rcu_assert_read_locked(void)
{
	struct rcu_thread *rt = rcu_self();
	assert(rt && rt->depth && seqlock_held(&rt->rcu));
}

void rcu_assert_read_unlocked(void)
{
	struct rcu_thread *rt = rcu_self();
	assert(rt && !rt->depth && !seqlock_held(&rt->rcu));
}

/*
 * RCU resource-release thread
 */

static void *rcu_main(void *arg);

static void rcu_start(void)
{
	/* ensure we never handle signals on the RCU thread by blocking
	 * everything here (new thread inherits signal mask)
	 */
	sigset_t oldsigs, blocksigs;

	sigfillset(&blocksigs);
	pthread_sigmask(SIG_BLOCK, &blocksigs, &oldsigs);

	rcu_active = true;

	assert(!pthread_create(&rcu_pthread, NULL, rcu_main, NULL));

	pthread_sigmask(SIG_SETMASK, &oldsigs, NULL);

#ifdef HAVE_PTHREAD_SETNAME_NP
# ifdef GNU_LINUX
	pthread_setname_np(rcu_pthread, "RCU sweeper");
# elif defined(__NetBSD__)
	pthread_setname_np(rcu_pthread, "RCU sweeper", NULL);
# endif
#elif defined(HAVE_PTHREAD_SET_NAME_NP)
	pthread_set_name_np(rcu_pthread, "RCU sweeper");
#endif
}

static void rcu_do(struct rcu_head *rh)
{
	struct rcu_head_close *rhc;
	void *p;

	switch (rh->action->type) {
	case RCUA_FREE:
		p = (char *)rh - rh->action->u.free.offset;
		if (rh->action->u.free.mt)
			qfree(rh->action->u.free.mt, p);
		else
			free(p);
		break;
	case RCUA_CLOSE:
		rhc = container_of(rh, struct rcu_head_close,
				   rcu_head);
		close(rhc->fd);
		break;
	case RCUA_CALL:
		p = (char *)rh - rh->action->u.call.offset;
		rh->action->u.call.fptr(p);
		break;

	case RCUA_INVALID:
	case RCUA_NEXT:
	case RCUA_END:
	default:
		assert(0);
	}
}

static void rcu_watchdog(struct rcu_thread *rt)
{
#if 0
	/* future work: print a backtrace for the thread that's holding up
	 * RCU.  The only (good) way of doing that is to send a signal to the
	 * other thread, save away the backtrace in the signal handler, and
	 * block here until the signal is done processing.
	 *
	 * Just haven't implemented that yet.
	 */
	fprintf(stderr, "RCU watchdog %p\n", rt);
#endif
}

static void *rcu_main(void *arg)
{
	struct rcu_thread *rt;
	struct rcu_head *rh = NULL;
	bool end = false;
	struct timespec maxwait;

	seqlock_val_t rcuval = SEQLOCK_STARTVAL;

	pthread_setspecific(rcu_thread_key, &rcu_thread_rcu);

	while (!end) {
		seqlock_wait(&rcu_seq, rcuval);

		/* RCU watchdog timeout, TODO: configurable value */
		clock_gettime(CLOCK_MONOTONIC, &maxwait);
		maxwait.tv_nsec += 100 * 1000 * 1000;
		if (maxwait.tv_nsec >= 1000000000) {
			maxwait.tv_sec++;
			maxwait.tv_nsec -= 1000000000;
		}

		frr_each (rcu_threads, &rcu_threads, rt)
			if (!seqlock_timedwait(&rt->rcu, rcuval, &maxwait)) {
				rcu_watchdog(rt);
				seqlock_wait(&rt->rcu, rcuval);
			}

		while ((rh = rcu_heads_pop(&rcu_heads))) {
			if (rh->action->type == RCUA_NEXT)
				break;
			else if (rh->action->type == RCUA_END)
				end = true;
			else
				rcu_do(rh);
		}

		rcuval += SEQLOCK_INCR;
	}

	/* rcu_shutdown can only be called singlethreaded, and it does a
	 * pthread_join, so it should be impossible that anything ended up
	 * on the queue after RCUA_END
	 */
#if 1
	assert(!rcu_heads_first(&rcu_heads));
#else
	while ((rh = rcu_heads_pop(&rcu_heads)))
		if (rh->action->type >= RCUA_FREE)
			rcu_do(rh);
#endif
	return NULL;
}

void rcu_shutdown(void)
{
	static struct rcu_head rcu_head_end;
	struct rcu_thread *rt = rcu_self();
	void *retval;

	if (!rcu_active)
		return;

	rcu_assert_read_locked();
	assert(rcu_threads_count(&rcu_threads) == 1);

	rcu_enqueue(&rcu_head_end, &rcua_end);

	rt->depth = 0;
	seqlock_release(&rt->rcu);
	seqlock_release(&rcu_seq);
	rcu_active = false;

	/* clearing rcu_active is before pthread_join in case we hang in
	 * pthread_join & get a SIGTERM or something - in that case, just
	 * ignore the maybe-still-running RCU thread
	 */
	if (pthread_join(rcu_pthread, &retval) == 0) {
		seqlock_acquire_val(&rcu_seq, SEQLOCK_STARTVAL);
		seqlock_acquire_val(&rt->rcu, SEQLOCK_STARTVAL);
		rt->depth = 1;
	}
}

/*
 * RCU'd free functions
 */

void rcu_enqueue(struct rcu_head *rh, const struct rcu_action *action)
{
	/* refer to rcu_bump() for why we need to hold RCU when adding items
	 * to rcu_heads
	 */
	rcu_assert_read_locked();

	rh->action = action;

	if (!rcu_active) {
		rcu_do(rh);
		return;
	}
	rcu_heads_add_tail(&rcu_heads, rh);
	atomic_store_explicit(&rcu_dirty, seqlock_cur(&rcu_seq),
			      memory_order_relaxed);
}

void rcu_close(struct rcu_head_close *rhc, int fd)
{
	rhc->fd = fd;
	rcu_enqueue(&rhc->rcu_head, &rcua_close);
}
