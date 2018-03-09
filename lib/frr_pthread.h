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

#ifndef _FRR_PTHREAD_H
#define _FRR_PTHREAD_H

#include <pthread.h>
#include "frratomic.h"
#include "memory.h"
#include "thread.h"

DECLARE_MTYPE(FRR_PTHREAD);
DECLARE_MTYPE(PTHREAD_PRIM);

struct frr_pthread;
struct frr_pthread_attr;

struct frr_pthread_attr {
	_Atomic uint32_t id;
	void *(*start)(void *);
	int (*stop)(struct frr_pthread *, void **);
};

struct frr_pthread {

	/*
	 * Mutex protecting this structure. Must be taken for reading some
	 * fields, denoted by a 'Requires: mtx'.
	 */
	pthread_mutex_t mtx;

	/* pthread id */
	pthread_t thread;

	/* thread master for this pthread's thread.c event loop */
	struct thread_master *master;

	/* caller-specified data; start & stop funcs, name, id */
	struct frr_pthread_attr attr;

	/*
	 * Notification mechanism for allowing pthreads to notify their parents
	 * when they are ready to do work. This mechanism has two associated
	 * functions:
	 *
	 * - frr_pthread_wait_running()
	 *   This function should be called by the spawning thread after
	 *   frr_pthread_run(). It safely waits until the spawned thread
	 *   indicates that is ready to do work by posting to the condition
	 *   variable.
	 *
	 * - frr_pthread_notify_running()
	 *   This function should be called by the spawned thread when it is
	 *   ready to do work. It will wake up any threads waiting on the
	 *   previously described condition.
	 */
	pthread_cond_t *running_cond;
	pthread_mutex_t *running_cond_mtx;
	_Atomic bool running;

	/*
	 * Fake thread-specific storage. No constraints on usage. Helpful when
	 * creating reentrant pthread implementations. Can be used to pass
	 * argument to pthread entry function.
	 *
	 * Requires: mtx
	 */
	void *data;

	/*
	 * Human-readable thread name.
	 *
	 * Requires: mtx
	 */
	char *name;
};

extern struct frr_pthread_attr frr_pthread_attr_default;

/*
 * Initializes this module.
 *
 * Must be called before using any of the other functions.
 */
void frr_pthread_init(void);

/*
 * Uninitializes this module.
 *
 * Destroys all registered frr_pthread's and internal data structures.
 *
 * It is safe to call frr_pthread_init() after this function to reinitialize
 * the module.
 */
void frr_pthread_finish(void);

/*
 * Creates a new frr_pthread with the given attributes.
 *
 * The 'attr' argument should be filled out with the desired attributes,
 * including ID, start and stop functions and the desired name. Alternatively,
 * if attr is NULL, the default attributes will be used. The pthread will be
 * set up to run a basic threadmaster loop and the name will be "Anonymous".
 * Scheduling tasks onto the threadmaster in the 'master' field of the returned
 * frr_pthread will cause them to run on that pthread.
 *
 * @param attr - the thread attributes
 * @param name - Human-readable name
 * @return the created frr_pthread upon success, or NULL upon failure
 */
struct frr_pthread *frr_pthread_new(struct frr_pthread_attr *attr,
				    const char *name);

/*
 * Changes the name of the frr_pthread.
 *
 * @param fpt - the frr_pthread to operate on
 * @param name - Human-readable name
 */
void frr_pthread_set_name(struct frr_pthread *fpt, const char *name);

/*
 * Destroys an frr_pthread.
 *
 * Assumes that the associated pthread, if any, has already terminated.
 *
 * @param fpt - the frr_pthread to destroy
 */
void frr_pthread_destroy(struct frr_pthread *fpt);

/*
 * Gets an existing frr_pthread by its id.
 *
 * @return frr_thread associated with the provided id, or NULL on error
 */
struct frr_pthread *frr_pthread_get(uint32_t id);

/*
 * Creates a new pthread and binds it to a frr_pthread.
 *
 * This function is a wrapper for pthread_create. The first parameter is the
 * frr_pthread to bind the created pthread to. All subsequent arguments are
 * passed unmodified to pthread_create(). The frr_pthread * provided will be
 * used as the argument to the pthread entry function. If it is necessary to
 * pass additional data, the 'data' field in the frr_pthread may be used.
 *
 * This function returns the same code as pthread_create(). If the value is
 * zero, the provided frr_pthread is bound to a running POSIX thread. If the
 * value is less than zero, the provided frr_pthread is guaranteed to be a
 * clean instance that may be susbsequently passed to frr_pthread_run().
 *
 * @param fpt - frr_pthread * to run
 * @param attr - see pthread_create(3)
 *
 * @return see pthread_create(3)
 */
int frr_pthread_run(struct frr_pthread *fpt, const pthread_attr_t *attr);

/*
 * Waits until the specified pthread has finished setting up and is ready to
 * begin work.
 *
 * If the pthread's code makes use of the startup synchronization mechanism,
 * this function should be called before attempting to use the functionality
 * exposed by the pthread. It waits until the 'running' condition is satisfied
 * (see struct definition of frr_pthread).
 *
 * @param fpt - the frr_pthread * to wait on
 */
void frr_pthread_wait_running(struct frr_pthread *fpt);

/*
 * Notifies other pthreads that the calling thread has finished setting up and
 * is ready to begin work.
 *
 * This will allow any other pthreads waiting in 'frr_pthread_wait_running' to
 * proceed.
 *
 * @param fpt - the frr_pthread * that has finished setting up
 */
void frr_pthread_notify_running(struct frr_pthread *fpt);

/*
 * Stops a frr_pthread with a result.
 *
 * @param fpt - frr_pthread * to stop
 * @param result - where to store the thread's result, if any. May be NULL if a
 * result is not needed.
 */
int frr_pthread_stop(struct frr_pthread *fpt, void **result);

/* Stops all frr_pthread's. */
void frr_pthread_stop_all(void);

/* Yields the current thread of execution */
void frr_pthread_yield(void);

/*
 * Returns a unique identifier for use with frr_pthread_new().
 *
 * Internally, this is an integer that increments after each call to this
 * function. Because the number of pthreads created should never exceed INT_MAX
 * during the life of the program, there is no overflow protection. If by
 * chance this function returns an ID which is already in use,
 * frr_pthread_new() will fail when it is provided.
 *
 * @return unique identifier
 */
uint32_t frr_pthread_get_id(void);

#endif /* _FRR_PTHREAD_H */
