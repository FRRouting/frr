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
#include <sched.h>

#include "frr_pthread.h"
#include "memory.h"
#include "hash.h"

DEFINE_MTYPE(LIB, FRR_PTHREAD, "FRR POSIX Thread");
DEFINE_MTYPE(LIB, PTHREAD_PRIM, "POSIX synchronization primitives");

/* id for next created pthread */
static _Atomic uint32_t next_id = 0;

/* default frr_pthread start/stop routine prototypes */
static void *fpt_run(void *arg);
static int fpt_halt(struct frr_pthread *fpt, void **res);

/* default frr_pthread attributes */
struct frr_pthread_attr frr_pthread_attr_default = {
	.id = 0,
	.start = fpt_run,
	.stop = fpt_halt,
};

/* hash table to keep track of all frr_pthreads */
static struct hash *frr_pthread_hash;
static pthread_mutex_t frr_pthread_hash_mtx = PTHREAD_MUTEX_INITIALIZER;

/* frr_pthread_hash->hash_cmp */
static int frr_pthread_hash_cmp(const void *value1, const void *value2)
{
	const struct frr_pthread *tq1 = value1;
	const struct frr_pthread *tq2 = value2;

	return (tq1->attr.id == tq2->attr.id);
}

/* frr_pthread_hash->hash_key */
static unsigned int frr_pthread_hash_key(void *value)
{
	return ((struct frr_pthread *)value)->attr.id;
}

/* ------------------------------------------------------------------------ */

void frr_pthread_init()
{
	pthread_mutex_lock(&frr_pthread_hash_mtx);
	{
		frr_pthread_hash = hash_create(frr_pthread_hash_key,
					       frr_pthread_hash_cmp, NULL);
	}
	pthread_mutex_unlock(&frr_pthread_hash_mtx);
}

void frr_pthread_finish()
{
	pthread_mutex_lock(&frr_pthread_hash_mtx);
	{
		hash_clean(frr_pthread_hash,
			   (void (*)(void *))frr_pthread_destroy);
		hash_free(frr_pthread_hash);
	}
	pthread_mutex_unlock(&frr_pthread_hash_mtx);
}

struct frr_pthread *frr_pthread_new(struct frr_pthread_attr *attr,
				    const char *name)
{
	static struct frr_pthread holder = {};
	struct frr_pthread *fpt = NULL;

	attr = attr ? attr : &frr_pthread_attr_default;

	pthread_mutex_lock(&frr_pthread_hash_mtx);
	{
		holder.attr.id = attr->id;

		if (!hash_lookup(frr_pthread_hash, &holder)) {
			fpt = XCALLOC(MTYPE_FRR_PTHREAD,
				      sizeof(struct frr_pthread));
			/* initialize mutex */
			pthread_mutex_init(&fpt->mtx, NULL);
			/* create new thread master */
			fpt->master = thread_master_create(name);
			/* set attributes */
			fpt->attr = *attr;
			name = (name ? name : "Anonymous thread");
			fpt->name = XSTRDUP(MTYPE_FRR_PTHREAD, name);
			if (attr == &frr_pthread_attr_default)
				fpt->attr.id = frr_pthread_get_id();
			/* initialize startup synchronization primitives */
			fpt->running_cond_mtx = XCALLOC(
				MTYPE_PTHREAD_PRIM, sizeof(pthread_mutex_t));
			fpt->running_cond = XCALLOC(MTYPE_PTHREAD_PRIM,
						    sizeof(pthread_cond_t));
			pthread_mutex_init(fpt->running_cond_mtx, NULL);
			pthread_cond_init(fpt->running_cond, NULL);

			/* insert into global thread hash */
			hash_get(frr_pthread_hash, fpt, hash_alloc_intern);
		}
	}
	pthread_mutex_unlock(&frr_pthread_hash_mtx);

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

void frr_pthread_set_name(struct frr_pthread *fpt, const char *name)
{
	pthread_mutex_lock(&fpt->mtx);
	{
		if (fpt->name)
			XFREE(MTYPE_FRR_PTHREAD, fpt->name);
		fpt->name = XSTRDUP(MTYPE_FRR_PTHREAD, name);
	}
	pthread_mutex_unlock(&fpt->mtx);
	thread_master_set_name(fpt->master, name);
}

struct frr_pthread *frr_pthread_get(uint32_t id)
{
	static struct frr_pthread holder = {};
	struct frr_pthread *fpt;

	pthread_mutex_lock(&frr_pthread_hash_mtx);
	{
		holder.attr.id = id;
		fpt = hash_lookup(frr_pthread_hash, &holder);
	}
	pthread_mutex_unlock(&frr_pthread_hash_mtx);

	return fpt;
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

/*
 * Callback for hash_iterate to stop all frr_pthread's.
 */
static void frr_pthread_stop_all_iter(struct hash_backet *hb, void *arg)
{
	struct frr_pthread *fpt = hb->data;
	frr_pthread_stop(fpt, NULL);
}

void frr_pthread_stop_all()
{
	pthread_mutex_lock(&frr_pthread_hash_mtx);
	{
		hash_iterate(frr_pthread_hash, frr_pthread_stop_all_iter, NULL);
	}
	pthread_mutex_unlock(&frr_pthread_hash_mtx);
}

uint32_t frr_pthread_get_id(void)
{
	_Atomic uint32_t nxid;
	nxid = atomic_fetch_add_explicit(&next_id, 1, memory_order_seq_cst);
	/* just a sanity check, this should never happen */
	assert(nxid <= (UINT32_MAX - 1));
	return nxid;
}

void frr_pthread_yield(void)
{
	(void)sched_yield();
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

/* entry pthread function & main event loop */
static void *fpt_run(void *arg)
{
	struct frr_pthread *fpt = arg;
	fpt->master->owner = pthread_self();

	int sleeper[2];
	pipe(sleeper);
	thread_add_read(fpt->master, &fpt_dummy, NULL, sleeper[0], NULL);

	fpt->master->handle_signals = false;

	frr_pthread_notify_running(fpt);

	struct thread task;
	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		if (thread_fetch(fpt->master, &task)) {
			thread_call(&task);
		}
	}

	close(sleeper[1]);
	close(sleeper[0]);

	return NULL;
}
