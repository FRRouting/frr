/*
 * Utilities and interfaces for managing POSIX threads within FRR.
 * Copyright (C) 2017  Cumulus Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <sched.h>

#include "frr_pthread.h"
#include "memory.h"
#include "linklist.h"

DEFINE_MTYPE(LIB, FRR_PTHREAD, "FRR POSIX Thread");
DEFINE_MTYPE(LIB, PTHREAD_PRIM, "POSIX synchronization primitives");

/* default frr_pthread start/stop routine prototypes */
static void *fpt_run(void *arg);
static int fpt_halt(struct frr_pthread *fpt, void **res);

/* default frr_pthread attributes */
struct frr_pthread_attr frr_pthread_attr_default = {
	.start = fpt_run,
	.stop = fpt_halt,
};

/* list to keep track of all frr_pthreads */
static pthread_mutex_t frr_pthread_list_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct list *frr_pthread_list;

/* ------------------------------------------------------------------------ */

void frr_pthread_init(void)
{
	pthread_mutex_lock(&frr_pthread_list_mtx);
	{
		frr_pthread_list = list_new();
		frr_pthread_list->del = (void (*)(void *))&frr_pthread_destroy;
	}
	pthread_mutex_unlock(&frr_pthread_list_mtx);
}

void frr_pthread_finish(void)
{
	pthread_mutex_lock(&frr_pthread_list_mtx);
	{
		list_delete(&frr_pthread_list);
	}
	pthread_mutex_unlock(&frr_pthread_list_mtx);
}

struct frr_pthread *frr_pthread_new(struct frr_pthread_attr *attr,
				    const char *name, const char *os_name)
{
	struct frr_pthread *fpt = NULL;

	attr = attr ? attr : &frr_pthread_attr_default;

	fpt = XCALLOC(MTYPE_FRR_PTHREAD, sizeof(struct frr_pthread));
	/* initialize mutex */
	pthread_mutex_init(&fpt->mtx, NULL);
	/* create new thread master */
	fpt->master = thread_master_create(name);
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

	pthread_mutex_lock(&frr_pthread_list_mtx);
	{
		listnode_add(frr_pthread_list, fpt);
	}
	pthread_mutex_unlock(&frr_pthread_list_mtx);

	return fpt;
}

void frr_pthread_destroy(struct frr_pthread *fpt)
{
	thread_master_free(fpt->master);

	pthread_mutex_destroy(&fpt->mtx);
	pthread_mutex_destroy(fpt->running_cond_mtx);
	pthread_cond_destroy(fpt->running_cond);
	if (fpt->name)
		XFREE(MTYPE_FRR_PTHREAD, fpt->name);
	XFREE(MTYPE_PTHREAD_PRIM, fpt->running_cond_mtx);
	XFREE(MTYPE_PTHREAD_PRIM, fpt->running_cond);
	XFREE(MTYPE_FRR_PTHREAD, fpt);
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

int frr_pthread_run(struct frr_pthread *fpt, const pthread_attr_t *attr)
{
	int ret;

	ret = pthread_create(&fpt->thread, attr, fpt->attr.start, fpt);

	/*
	 * Per pthread_create(3), the contents of fpt->thread are undefined if
	 * pthread_create() did not succeed. Reset this value to zero.
	 */
	if (ret < 0)
		memset(&fpt->thread, 0x00, sizeof(fpt->thread));

	return ret;
}

void frr_pthread_wait_running(struct frr_pthread *fpt)
{
	pthread_mutex_lock(fpt->running_cond_mtx);
	{
		while (!fpt->running)
			pthread_cond_wait(fpt->running_cond,
					  fpt->running_cond_mtx);
	}
	pthread_mutex_unlock(fpt->running_cond_mtx);
}

void frr_pthread_notify_running(struct frr_pthread *fpt)
{
	pthread_mutex_lock(fpt->running_cond_mtx);
	{
		fpt->running = true;
		pthread_cond_signal(fpt->running_cond);
	}
	pthread_mutex_unlock(fpt->running_cond_mtx);
}

int frr_pthread_stop(struct frr_pthread *fpt, void **result)
{
	int ret = (*fpt->attr.stop)(fpt, result);
	memset(&fpt->thread, 0x00, sizeof(fpt->thread));
	return ret;
}

void frr_pthread_stop_all(void)
{
	pthread_mutex_lock(&frr_pthread_list_mtx);
	{
		struct listnode *n;
		struct frr_pthread *fpt;
		for (ALL_LIST_ELEMENTS_RO(frr_pthread_list, n, fpt))
			frr_pthread_stop(fpt, NULL);
	}
	pthread_mutex_unlock(&frr_pthread_list_mtx);
}

/*
 * ----------------------------------------------------------------------------
 * Default Event Loop
 * ----------------------------------------------------------------------------
 */

/* dummy task for sleeper pipe */
static int fpt_dummy(struct thread *thread)
{
	return 0;
}

/* poison pill task to end event loop */
static int fpt_finish(struct thread *thread)
{
	struct frr_pthread *fpt = THREAD_ARG(thread);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}

/* stop function, called from other threads to halt this one */
static int fpt_halt(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master, &fpt_finish, fpt, 0, NULL);
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

	int sleeper[2];
	pipe(sleeper);
	thread_add_read(fpt->master, &fpt_dummy, NULL, sleeper[0], NULL);

	fpt->master->handle_signals = false;

	frr_pthread_set_name(fpt);

	frr_pthread_notify_running(fpt);

	struct thread task;
	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		pthread_testcancel();
		if (thread_fetch(fpt->master, &task)) {
			thread_call(&task);
		}
	}

	close(sleeper[1]);
	close(sleeper[0]);

	return NULL;
}
