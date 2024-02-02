// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Utilities and interfaces for managing POSIX threads within FRR.
 * Copyright (C) 2017  Cumulus Networks, Inc.
 */

#ifndef _FRR_PTHREAD_H
#define _FRR_PTHREAD_H

#include <pthread.h>
#include "frratomic.h"
#include "memory.h"
#include "frrcu.h"
#include "frrevent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OS_THREAD_NAMELEN 16

struct frr_pthread;
struct frr_pthread_attr;

struct frr_pthread_attr {
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

	struct rcu_thread *rcu_thread;

	/* thread master for this pthread's thread.c event loop */
	struct event_loop *master;

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
	atomic_bool running;

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

	/* Used in pthread_set_name max 16 characters */
	char os_name[OS_THREAD_NAMELEN];
};

extern const struct frr_pthread_attr frr_pthread_attr_default;

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
 * @param os_name - 16 characters (including '\0') thread name to set in os,
 * @return the created frr_pthread upon success, or NULL upon failure
 */
struct frr_pthread *frr_pthread_new(const struct frr_pthread_attr *attr,
				    const char *name, const char *os_name);

/*
 * Changes the name of the frr_pthread as reported by the operating
 * system.
 *
 * @param fpt - the frr_pthread to operate on
 * @return -  on success returns 0 otherwise nonzero error number.
 */
int frr_pthread_set_name(struct frr_pthread *fpt);

/*
 * Destroys an frr_pthread.
 *
 * Assumes that the associated pthread, if any, has already terminated.
 *
 * @param fpt - the frr_pthread to destroy
 */
void frr_pthread_destroy(struct frr_pthread *fpt);

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

#ifndef HAVE_PTHREAD_CONDATTR_SETCLOCK
#define pthread_condattr_setclock(A, B)
#endif

int frr_pthread_non_controlled_startup(pthread_t thread, const char *name,
				       const char *os_name);

/* mutex auto-lock/unlock */

/* variant 1:
 * (for short blocks, multiple mutexes supported)
 * break & return can be used for aborting the block
 *
 * frr_with_mutex(&mtx, &mtx2) {
 *    if (error)
 *       break;
 *    ...
 * }
 */
#define _frr_with_mutex(mutex)                                                 \
	*NAMECTR(_mtx_) __attribute__((                                        \
		unused, cleanup(_frr_mtx_unlock))) = _frr_mtx_lock(mutex),     \
	/* end */

#define frr_with_mutex(...)                                                    \
	for (pthread_mutex_t MACRO_REPEAT(_frr_with_mutex, ##__VA_ARGS__)      \
	     *_once = NULL; _once == NULL; _once = (void *)1)                  \
	/* end */

/* variant 2:
 * (more suitable for long blocks, no extra indentation)
 *
 * frr_mutex_lock_autounlock(&mtx);
 * ...
 */
#define frr_mutex_lock_autounlock(mutex)                                       \
	pthread_mutex_t *NAMECTR(_mtx_)                                        \
		__attribute__((unused, cleanup(_frr_mtx_unlock))) =            \
				    _frr_mtx_lock(mutex)                       \
	/* end */

static inline pthread_mutex_t *_frr_mtx_lock(pthread_mutex_t *mutex)
{
	pthread_mutex_lock(mutex);
	return mutex;
}

static inline void _frr_mtx_unlock(pthread_mutex_t **mutex)
{
	if (!*mutex)
		return;
	pthread_mutex_unlock(*mutex);
	*mutex = NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* _FRR_PTHREAD_H */
