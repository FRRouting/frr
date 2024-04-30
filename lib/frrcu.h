// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2017-19  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRRCU_H
#define _FRRCU_H

#include <assert.h>

#include "memory.h"
#include "atomlist.h"

#ifdef __cplusplus
extern "C" {
#endif

/* quick RCU primer:
 *   There's a global sequence counter.  Whenever a thread does a
 *   rcu_read_lock(), it is marked as holding the current sequence counter.
 *   When something is cleaned with RCU, the global sequence counter is
 *   increased and the item is queued for cleanup - *after* all threads are
 *   at a more recent sequence counter (or no sequence counter / unheld).
 *
 *   So, by delaying resource cleanup, RCU ensures that things don't go away
 *   while another thread may hold a (stale) reference.
 *
 *   Note that even if a thread is in rcu_read_lock(), it is invalid for that
 *   thread to access bits after rcu_free() & co on them.  This is a design
 *   choice to allow no-op'ing out the entire RCU mechanism if we're running
 *   singlethreaded.  (Also allows some optimization on the counter bumping.)
 *
 * differences from Linux Kernel RCU:
 *   - there's no rcu_synchronize(), if you really need to defer something
 *     use rcu_call() (and double check it's really necessary)
 *   - rcu_dereference() and rcu_assign_pointer() don't exist, use atomic_*
 *     instead (ATOM* list structures do the right thing)
 */

/* opaque */
struct rcu_thread;

/* sets up rcu thread info
 *
 * return value must be passed into the thread's call to rcu_thread_start()
 */
extern struct rcu_thread *rcu_thread_new(void *arg);

/* called before new thread creation, sets up rcu thread info for new thread
 * before it actually exits.  This ensures possible RCU references are held
 * for thread startup.
 *
 * return value must be passed into the new thread's call to rcu_thread_start()
 */
extern struct rcu_thread *rcu_thread_prepare(void);

/* cleanup in case pthread_create() fails */
extern void rcu_thread_unprepare(struct rcu_thread *rcu_thread);

/* called early in the new thread, with the return value from the above.
 * NB: new thread is initially in RCU-held state! (at depth 1)
 *
 * TBD: maybe inherit RCU state from rcu_thread_prepare()?
 */
extern void rcu_thread_start(struct rcu_thread *rcu_thread);

/* thread exit is handled through pthread_key_create's destructor function */

/* global RCU shutdown - must be called with only 1 active thread left.  waits
 * until remaining RCU actions are done & RCU thread has exited.
 *
 * This is mostly here to get a clean exit without memleaks.
 */
extern void rcu_shutdown(void);

/* enter / exit RCU-held state.  counter-based, so can be called nested. */
extern void rcu_read_lock(void);
extern void rcu_read_unlock(void);

/* for debugging / safety checks */
extern void rcu_assert_read_locked(void);
extern void rcu_assert_read_unlocked(void);

enum rcu_action_type {
	RCUA_INVALID = 0,
	/* used internally by the RCU code, shouldn't ever show up outside */
	RCUA_NEXT,
	RCUA_END,
	/* normal RCU actions, for outside use */
	RCUA_FREE,
	RCUA_CLOSE,
	RCUA_CALL,
};

/* since rcu_head is intended to be embedded into structs which may exist
 * with lots of copies, rcu_head is shrunk down to its absolute minimum -
 * the atomlist pointer + a pointer to this action struct.
 */
struct rcu_action {
	enum rcu_action_type type;

	union {
		struct {
			struct memtype *mt;
			ptrdiff_t offset;
		} free;

		struct {
			void (*fptr)(void *arg);
			ptrdiff_t offset;
		} call;
	} u;
};

/* RCU cleanup function queue item */
PREDECL_ATOMLIST(rcu_heads);
struct rcu_head {
	struct rcu_heads_item head;
	const struct rcu_action *action;
};

/* special RCU head for delayed fd-close */
struct rcu_head_close {
	struct rcu_head rcu_head;
	int fd;
};

/* enqueue RCU action - use the macros below to get the rcu_action set up */
extern void rcu_enqueue(struct rcu_head *head, const struct rcu_action *action);

/* RCU free() and file close() operations.
 *
 * freed memory / closed fds become _immediately_ unavailable to the calling
 * thread, but will remain available for other threads until they have passed
 * into RCU-released state.
 */

/* may be called with NULL mt to do non-MTYPE free() */
#define rcu_free(mtype, ptr, field)                                            \
	do {                                                                   \
		typeof(ptr) _ptr = (ptr);                                      \
		if (!_ptr)                                                     \
			break;                                                 \
		struct rcu_head *_rcu_head = &_ptr->field;                     \
		static const struct rcu_action _rcu_action = {                 \
			.type = RCUA_FREE,                                     \
			.u.free = {                                            \
				.mt = mtype,                                   \
				.offset = offsetof(typeof(*_ptr), field),      \
			},                                                     \
		};                                                             \
		rcu_enqueue(_rcu_head, &_rcu_action);                          \
	} while (0)

/* use this sparingly, it runs on (and blocks) the RCU thread */
#define rcu_call(func, ptr, field)                                             \
	do {                                                                   \
		typeof(ptr) _ptr = (ptr);                                      \
		void (*fptype)(typeof(ptr));                                   \
		struct rcu_head *_rcu_head = &_ptr->field;                     \
		static const struct rcu_action _rcu_action = {                 \
			.type = RCUA_CALL,                                     \
			.u.call = {                                            \
				.fptr = (void *)func,                          \
				.offset = offsetof(typeof(*_ptr), field),      \
			},                                                     \
		};                                                             \
		(void)(_fptype = func);                                        \
		rcu_enqueue(_rcu_head, &_rcu_action);                          \
	} while (0)

extern void rcu_close(struct rcu_head_close *head, int fd);

#ifdef __cplusplus
}
#endif

#endif /* _FRRCU_H */
