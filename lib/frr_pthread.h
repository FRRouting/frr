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

#ifndef _FRR_PTHREAD_H
#define _FRR_PTHREAD_H

#include <pthread.h>
#include "memory.h"
#include "thread.h"

DECLARE_MTYPE(PTHREAD_PRIM);

struct frr_pthread {

	/* pthread id */
	pthread_t thread;

	/* frr thread identifier */
	unsigned int id;

	/* thread master for this pthread's thread.c event loop */
	struct thread_master *master;

	/* start routine */
	void *(*start_routine)(void *);

	/* stop routine */
	int (*stop_routine)(void **, struct frr_pthread *);

	/* the (hopefully descriptive) name of this thread */
	char *name;
};

/* Initializes this module.
 *
 * Must be called before using any of the other functions.
 */
void frr_pthread_init(void);

/* Uninitializes this module.
 *
 * Destroys all registered frr_pthread's and internal data structures.
 *
 * It is safe to call frr_pthread_init() after this function to reinitialize
 * the module.
 */
void frr_pthread_finish(void);

/* Creates a new frr_pthread.
 *
 * If the provided ID is already assigned to an existing frr_pthread, the
 * return value will be NULL.
 *
 * @param name - the name of the thread. Doesn't have to be unique, but it
 * probably should be. This value is copied and may be safely free'd upon
 * return.
 *
 * @param id - the integral ID of the thread. MUST be unique. The caller may
 * use this id to retrieve the thread.
 *
 * @param start_routine - start routine for the pthread, will be passed to
 * pthread_create (see those docs for details)
 *
 * @param stop_routine - stop routine for the pthread, called to terminate the
 * thread. This function should gracefully stop the pthread and clean up any
 * thread-specific resources. The passed pointer is used to return a data
 * result.
 *
 * @return the created frr_pthread upon success, or NULL upon failure
 */
struct frr_pthread *frr_pthread_new(const char *name, unsigned int id,
				    void *(*start_routine)(void *),
				    int (*stop_routine)(void **,
							struct frr_pthread *));

/* Destroys an frr_pthread.
 *
 * Assumes that the associated pthread, if any, has already terminated.
 *
 * @param fpt - the frr_pthread to destroy
 */
void frr_pthread_destroy(struct frr_pthread *fpt);

/* Gets an existing frr_pthread by its id.
 *
 * @return frr_thread associated with the provided id, or NULL on error
 */
struct frr_pthread *frr_pthread_get(unsigned int id);

/* Creates a new pthread and binds it to a frr_pthread.
 *
 * This function is a wrapper for pthread_create. The first parameter is the
 * frr_pthread to bind the created pthread to. All subsequent arguments are
 * passed unmodified to pthread_create().
 *
 * This function returns the same code as pthread_create(). If the value is
 * zero, the provided frr_pthread is bound to a running POSIX thread. If the
 * value is less than zero, the provided frr_pthread is guaranteed to be a
 * clean instance that may be susbsequently passed to frr_pthread_run().
 *
 * @param id - frr_pthread to bind the created pthread to
 * @param attr - see pthread_create(3)
 * @param arg - see pthread_create(3)
 *
 * @return see pthread_create(3)
 */
int frr_pthread_run(unsigned int id, const pthread_attr_t *attr, void *arg);

/* Stops an frr_pthread with a result.
 *
 * @param id - frr_pthread to stop
 * @param result - where to store the thread's result, if any. May be NULL if a
 * result is not needed.
 */
int frr_pthread_stop(unsigned int id, void **result);

/* Stops all frr_pthread's. */
void frr_pthread_stop_all(void);

/* Yields the current thread of execution */
void frr_pthread_yield(void);

/* Returns a unique identifier for use with frr_pthread_new().
 *
 * Internally, this is an integer that increments after each call to this
 * function. Because the number of pthreads created should never exceed INT_MAX
 * during the life of the program, there is no overflow protection. If by
 * chance this function returns an ID which is already in use,
 * frr_pthread_new() will fail when it is provided.
 *
 * @return unique identifier
 */
unsigned int frr_pthread_get_id(void);

#endif /* _FRR_PTHREAD_H */
