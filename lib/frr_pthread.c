/*
 * Utilities and interfaces for managing POSIX threads
 * Copyright (C) 2017  Cumulus Networks
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

DEFINE_MTYPE_STATIC(LIB, FRR_PTHREAD, "FRR POSIX Thread");
DEFINE_MTYPE(LIB, PTHREAD_PRIM, "POSIX synchronization primitives");

static unsigned int next_id = 0;

/* Hash table of all frr_pthreads along with synchronization primitive(s) and
 * hash table callbacks.
 * ------------------------------------------------------------------------ */
static struct hash *pthread_table;
static pthread_mutex_t pthread_table_mtx = PTHREAD_MUTEX_INITIALIZER;

/* pthread_table->hash_cmp */
static int pthread_table_hash_cmp(const void *value1, const void *value2)
{
	const struct frr_pthread *tq1 = value1;
	const struct frr_pthread *tq2 = value2;

	return (tq1->id == tq2->id);
}

/* pthread_table->hash_key */
static unsigned int pthread_table_hash_key(void *value)
{
	return ((struct frr_pthread *)value)->id;
}
/* ------------------------------------------------------------------------ */

void frr_pthread_init()
{
	pthread_mutex_lock(&pthread_table_mtx);
	{
		pthread_table = hash_create(pthread_table_hash_key,
					    pthread_table_hash_cmp, NULL);
	}
	pthread_mutex_unlock(&pthread_table_mtx);
}

void frr_pthread_finish()
{
	pthread_mutex_lock(&pthread_table_mtx);
	{
		hash_clean(pthread_table,
			   (void (*)(void *))frr_pthread_destroy);
		hash_free(pthread_table);
	}
	pthread_mutex_unlock(&pthread_table_mtx);
}

struct frr_pthread *frr_pthread_new(const char *name, unsigned int id,
				    void *(*start_routine)(void *),
				    int (*stop_routine)(void **,
							struct frr_pthread *))
{
	static struct frr_pthread holder = {0};
	struct frr_pthread *fpt = NULL;

	pthread_mutex_lock(&pthread_table_mtx);
	{
		holder.id = id;

		if (!hash_lookup(pthread_table, &holder)) {
			struct frr_pthread *fpt = XCALLOC(
				MTYPE_FRR_PTHREAD, sizeof(struct frr_pthread));
			fpt->id = id;
			fpt->master = thread_master_create(name);
			fpt->start_routine = start_routine;
			fpt->stop_routine = stop_routine;
			fpt->name = XSTRDUP(MTYPE_FRR_PTHREAD, name);

			hash_get(pthread_table, fpt, hash_alloc_intern);
		}
	}
	pthread_mutex_unlock(&pthread_table_mtx);

	return fpt;
}

void frr_pthread_destroy(struct frr_pthread *fpt)
{
	thread_master_free(fpt->master);
	XFREE(MTYPE_FRR_PTHREAD, fpt->name);
	XFREE(MTYPE_FRR_PTHREAD, fpt);
}

struct frr_pthread *frr_pthread_get(unsigned int id)
{
	static struct frr_pthread holder = {0};
	struct frr_pthread *fpt;

	pthread_mutex_lock(&pthread_table_mtx);
	{
		holder.id = id;
		fpt = hash_lookup(pthread_table, &holder);
	}
	pthread_mutex_unlock(&pthread_table_mtx);

	return fpt;
}

int frr_pthread_run(unsigned int id, const pthread_attr_t *attr, void *arg)
{
	struct frr_pthread *fpt = frr_pthread_get(id);
	int ret;

	if (!fpt)
		return -1;

	ret = pthread_create(&fpt->thread, attr, fpt->start_routine, arg);

	/* Per pthread_create(3), the contents of fpt->thread are undefined if
	 * pthread_create() did not succeed. Reset this value to zero. */
	if (ret < 0)
		memset(&fpt->thread, 0x00, sizeof(fpt->thread));

	return ret;
}

/**
 * Calls the stop routine for the frr_pthread and resets any relevant fields.
 *
 * @param fpt - the frr_pthread to stop
 * @param result - pointer to result pointer
 * @return the return code from the stop routine
 */
static int frr_pthread_stop_actual(struct frr_pthread *fpt, void **result)
{
	int ret = (*fpt->stop_routine)(result, fpt);
	memset(&fpt->thread, 0x00, sizeof(fpt->thread));
	return ret;
}

int frr_pthread_stop(unsigned int id, void **result)
{
	struct frr_pthread *fpt = frr_pthread_get(id);
	return frr_pthread_stop_actual(fpt, result);
}

/**
 * Callback for hash_iterate to stop all frr_pthread's.
 */
static void frr_pthread_stop_all_iter(struct hash_backet *hb, void *arg)
{
	struct frr_pthread *fpt = hb->data;
	frr_pthread_stop_actual(fpt, NULL);
}

void frr_pthread_stop_all()
{
	pthread_mutex_lock(&pthread_table_mtx);
	{
		hash_iterate(pthread_table, frr_pthread_stop_all_iter, NULL);
	}
	pthread_mutex_unlock(&pthread_table_mtx);
}

unsigned int frr_pthread_get_id()
{
	return next_id++;
}

void frr_pthread_yield(void)
{
	(void)sched_yield();
}
