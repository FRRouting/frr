// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Utilities and interfaces for managing POSIX threads within FRR.
 * Copyright (C) 2017  Cumulus Networks, Inc.
 */

#include <zebra.h>

#include <signal.h>

#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <sched.h>

#include "frr_pthread.h"
#include "memory.h"
#include "linklist.h"
#include "zlog.h"
#include "libfrr.h"
#include "libfrr_trace.h"

DEFINE_MTYPE_STATIC(LIB, FRR_PTHREAD, "FRR POSIX Thread");
DEFINE_MTYPE_STATIC(LIB, PTHREAD_PRIM, "POSIX sync primitives");

/* default frr_pthread start/stop routine prototypes */
static void *fpt_run(void *arg);
static int fpt_halt(struct frr_pthread *fpt, void **res);

/* misc sigs */
static void frr_pthread_destroy_nolock(struct frr_pthread *fpt);

/* default frr_pthread attributes */
const struct frr_pthread_attr frr_pthread_attr_default = {
	.start = fpt_run,
	.stop = fpt_halt,
};

/* list to keep track of all frr_pthreads */
static pthread_mutex_t frr_pthread_list_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct list *frr_pthread_list;

/* ------------------------------------------------------------------------ */

void frr_pthread_init(void)
{
	frr_with_mutex (&frr_pthread_list_mtx) {
		frr_pthread_list = list_new();
	}
}

void frr_pthread_finish(void)
{
	frr_pthread_stop_all();

	frr_with_mutex (&frr_pthread_list_mtx) {
		struct listnode *n, *nn;
		struct frr_pthread *fpt;

		for (ALL_LIST_ELEMENTS(frr_pthread_list, n, nn, fpt)) {
			listnode_delete(frr_pthread_list, fpt);
			frr_pthread_destroy_nolock(fpt);
		}

		list_delete(&frr_pthread_list);
	}
}

struct frr_pthread *frr_pthread_new(const struct frr_pthread_attr *attr,
				    const char *name, const char *os_name)
{
	struct frr_pthread *fpt = NULL;

	attr = attr ? attr : &frr_pthread_attr_default;

	fpt = XCALLOC(MTYPE_FRR_PTHREAD, sizeof(struct frr_pthread));
	/* initialize mutex */
	pthread_mutex_init(&fpt->mtx, NULL);
	/* create new thread master */
	fpt->master = event_master_create(name);
	/* set attributes */
	fpt->attr = *attr;
	name = (name ? name : "Anonymous thread");
	fpt->name = XSTRDUP(MTYPE_FRR_PTHREAD, name);
	if (os_name)
		strlcpy(fpt->os_name, os_name, OS_THREAD_NAMELEN);
	else
		strlcpy(fpt->os_name, name, OS_THREAD_NAMELEN);
	/* initialize startup synchronization primitives */
	fpt->running_cond_mtx = XCALLOC(
		MTYPE_PTHREAD_PRIM, sizeof(pthread_mutex_t));
	fpt->running_cond = XCALLOC(MTYPE_PTHREAD_PRIM,
				    sizeof(pthread_cond_t));
	pthread_mutex_init(fpt->running_cond_mtx, NULL);
	pthread_cond_init(fpt->running_cond, NULL);

	frr_with_mutex (&frr_pthread_list_mtx) {
		listnode_add(frr_pthread_list, fpt);
	}

	return fpt;
}

static void frr_pthread_destroy_nolock(struct frr_pthread *fpt)
{
	event_master_free(fpt->master);
	pthread_mutex_destroy(&fpt->mtx);
	pthread_mutex_destroy(fpt->running_cond_mtx);
	pthread_cond_destroy(fpt->running_cond);
	XFREE(MTYPE_FRR_PTHREAD, fpt->name);
	XFREE(MTYPE_PTHREAD_PRIM, fpt->running_cond_mtx);
	XFREE(MTYPE_PTHREAD_PRIM, fpt->running_cond);
	XFREE(MTYPE_FRR_PTHREAD, fpt);
}

void frr_pthread_destroy(struct frr_pthread *fpt)
{
	frr_with_mutex (&frr_pthread_list_mtx) {
		listnode_delete(frr_pthread_list, fpt);
	}

	frr_pthread_destroy_nolock(fpt);
}

int frr_pthread_set_name(struct frr_pthread *fpt)
{
	int ret = 0;

#ifdef HAVE_PTHREAD_SETNAME_NP
# ifdef GNU_LINUX
	ret = pthread_setname_np(fpt->thread, fpt->os_name);
# elif defined(__NetBSD__)
	ret = pthread_setname_np(fpt->thread, fpt->os_name, NULL);
# endif
#elif defined(HAVE_PTHREAD_SET_NAME_NP)
	pthread_set_name_np(fpt->thread, fpt->os_name);
#endif

	return ret;
}

static void *frr_pthread_inner(void *arg)
{
	struct frr_pthread *fpt = arg;

	rcu_thread_start(fpt->rcu_thread);
	return fpt->attr.start(fpt);
}

int frr_pthread_run(struct frr_pthread *fpt, const pthread_attr_t *attr)
{
	int ret;
	sigset_t oldsigs, blocksigs;

	assert(frr_is_after_fork || !"trying to start thread before fork()");

	/* Ensure we never handle signals on a background thread by blocking
	 * everything here (new thread inherits signal mask)
	 */
	sigfillset(&blocksigs);
	pthread_sigmask(SIG_BLOCK, &blocksigs, &oldsigs);

	frrtrace(1, frr_libfrr, frr_pthread_run, fpt->name);

	fpt->rcu_thread = rcu_thread_prepare();
	ret = pthread_create(&fpt->thread, attr, frr_pthread_inner, fpt);

	/* Restore caller's signals */
	pthread_sigmask(SIG_SETMASK, &oldsigs, NULL);

	/*
	 * Per pthread_create(3), the contents of fpt->thread are undefined if
	 * pthread_create() did not succeed. Reset this value to zero.
	 */
	if (ret < 0) {
		rcu_thread_unprepare(fpt->rcu_thread);
		memset(&fpt->thread, 0x00, sizeof(fpt->thread));
	}

	return ret;
}

void frr_pthread_wait_running(struct frr_pthread *fpt)
{
	frr_with_mutex (fpt->running_cond_mtx) {
		while (!fpt->running)
			pthread_cond_wait(fpt->running_cond,
					  fpt->running_cond_mtx);
	}
}

void frr_pthread_notify_running(struct frr_pthread *fpt)
{
	frr_with_mutex (fpt->running_cond_mtx) {
		fpt->running = true;
		pthread_cond_signal(fpt->running_cond);
	}
}

int frr_pthread_stop(struct frr_pthread *fpt, void **result)
{
	frrtrace(1, frr_libfrr, frr_pthread_stop, fpt->name);

	int ret = (*fpt->attr.stop)(fpt, result);
	memset(&fpt->thread, 0x00, sizeof(fpt->thread));
	return ret;
}

void frr_pthread_stop_all(void)
{
	frr_with_mutex (&frr_pthread_list_mtx) {
		struct listnode *n;
		struct frr_pthread *fpt;
		for (ALL_LIST_ELEMENTS_RO(frr_pthread_list, n, fpt)) {
			if (atomic_load_explicit(&fpt->running,
						 memory_order_relaxed))
				frr_pthread_stop(fpt, NULL);
		}
	}
}

static void *frr_pthread_attr_non_controlled_start(void *arg)
{
	struct frr_pthread *fpt = arg;

	fpt->running = true;

	return NULL;
}

/* Create a FRR pthread context from a non FRR pthread initialized from an
 * external library in order to allow logging */
int frr_pthread_non_controlled_startup(pthread_t thread, const char *name,
				       const char *os_name)
{
	struct rcu_thread *rcu_thread = rcu_thread_new(NULL);

	rcu_thread_start(rcu_thread);

	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_non_controlled_start,
		.stop = frr_pthread_attr_default.stop,
	};
	struct frr_pthread *fpt;

	fpt = frr_pthread_new(&attr, name, os_name);
	if (!fpt)
		return -1;

	fpt->thread = thread;
	fpt->rcu_thread = rcu_thread;
	frr_pthread_inner(fpt);

	return 0;
}

/*
 * ----------------------------------------------------------------------------
 * Default Event Loop
 * ----------------------------------------------------------------------------
 */

/* dummy task for sleeper pipe */
static void fpt_dummy(struct event *thread)
{
}

/* poison pill task to end event loop */
static void fpt_finish(struct event *thread)
{
	struct frr_pthread *fpt = EVENT_ARG(thread);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
}

/* stop function, called from other threads to halt this one */
static int fpt_halt(struct frr_pthread *fpt, void **res)
{
	event_add_event(fpt->master, &fpt_finish, fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}

/*
 * Entry pthread function & main event loop.
 *
 * Upon thread start the following actions occur:
 *
 * - frr_pthread's owner field is set to pthread ID.
 * - All signals are blocked (except for unblockable signals).
 * - Pthread's threadmaster is set to never handle pending signals
 * - Poker pipe for poll() is created and queued as I/O source
 * - The frr_pthread->running_cond condition variable is signalled to indicate
 *   that the previous actions have completed. It is not safe to assume any of
 *   the above have occurred before receiving this signal.
 *
 * After initialization is completed, the event loop begins running. Each tick,
 * the following actions are performed before running the usual event system
 * tick function:
 *
 * - Verify that the running boolean is set
 * - Verify that there are no pending cancellation requests
 * - Verify that there are tasks scheduled
 *
 * So long as the conditions are met, the event loop tick is run and the
 * returned task is executed.
 *
 * If any of these conditions are not met, the event loop exits, closes the
 * pipes and dies without running any cleanup functions.
 */
static void *fpt_run(void *arg)
{
	struct frr_pthread *fpt = arg;
	fpt->master->owner = pthread_self();

	zlog_tls_buffer_init();

	int sleeper[2];
	pipe(sleeper);
	event_add_read(fpt->master, &fpt_dummy, NULL, sleeper[0], NULL);

	fpt->master->handle_signals = false;

	frr_pthread_set_name(fpt);

	frr_pthread_notify_running(fpt);

	struct event task;
	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		pthread_testcancel();
		if (event_fetch(fpt->master, &task)) {
			event_call(&task);
		}
	}

	close(sleeper[1]);
	close(sleeper[0]);

	zlog_tls_buffer_fini();

	return NULL;
}
