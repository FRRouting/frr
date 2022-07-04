/* Thread management routine header.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_THREAD_H
#define _ZEBRA_THREAD_H

#include <zebra.h>
#include <pthread.h>
#include <poll.h>
#include "monotime.h"
#include "frratomic.h"
#include "typesafe.h"
#include "xref.h"

#ifdef __cplusplus
extern "C" {
#endif

extern bool cputime_enabled;
extern unsigned long cputime_threshold;
/* capturing wallclock time is always enabled since it is fast (reading
 * hardware TSC w/o syscalls)
 */
extern unsigned long walltime_threshold;

struct rusage_t {
#ifdef HAVE_CLOCK_THREAD_CPUTIME_ID
	struct timespec cpu;
#else
	struct rusage cpu;
#endif
	struct timeval real;
};
#define RUSAGE_T        struct rusage_t

#define GETRUSAGE(X) thread_getrusage(X)

PREDECL_LIST(thread_list);
PREDECL_HEAP(thread_timer_list);

struct fd_handler {
	/* number of pfd that fit in the allocated space of pfds. This is a
	 * constant and is the same for both pfds and copy.
	 */
	nfds_t pfdsize;

	/* file descriptors to monitor for i/o */
	struct pollfd *pfds;
	/* number of pollfds stored in pfds */
	nfds_t pfdcount;

	/* chunk used for temp copy of pollfds */
	struct pollfd *copy;
	/* number of pollfds stored in copy */
	nfds_t copycount;
};

struct xref_threadsched {
	struct xref xref;

	const char *funcname;
	const char *dest;
	uint32_t thread_type;
};

/* Master of the theads. */
struct thread_master {
	char *name;

	struct thread **read;
	struct thread **write;
	struct thread_timer_list_head timer;
	struct thread_list_head event, ready, unuse;
	struct list *cancel_req;
	bool canceled;
	pthread_cond_t cancel_cond;
	struct hash *cpu_record;
	int io_pipe[2];
	int fd_limit;
	struct fd_handler handler;
	unsigned long alloc;
	long selectpoll_timeout;
	bool spin;
	bool handle_signals;
	pthread_mutex_t mtx;
	pthread_t owner;

	bool ready_run_loop;
	RUSAGE_T last_getrusage;
};

/* Thread itself. */
struct thread {
	uint8_t type;		  /* thread type */
	uint8_t add_type;	  /* thread type */
	struct thread_list_item threaditem;
	struct thread_timer_list_item timeritem;
	struct thread **ref;	  /* external reference (if given) */
	struct thread_master *master; /* pointer to the struct thread_master */
	void (*func)(struct thread *); /* event function */
	void *arg;		      /* event argument */
	union {
		int val;	      /* second argument of the event. */
		int fd;		      /* file descriptor in case of r/w */
		struct timeval sands; /* rest of time sands value. */
	} u;
	struct timeval real;
	struct cpu_thread_history *hist; /* cache pointer to cpu_history */
	unsigned long yield;		 /* yield time in microseconds */
	const struct xref_threadsched *xref;   /* origin location */
	pthread_mutex_t mtx;   /* mutex for thread.c functions */
	bool ignore_timer_late;
};

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pTH" (struct thread *)
#endif

struct cpu_thread_history {
	void (*func)(struct thread *);
	atomic_size_t total_cpu_warn;
	atomic_size_t total_wall_warn;
	atomic_size_t total_starv_warn;
	atomic_size_t total_calls;
	atomic_size_t total_active;
	struct time_stats {
		atomic_size_t total, max;
	} real;
	struct time_stats cpu;
	atomic_uint_fast32_t types;
	const char *funcname;
};

/* Struct timeval's tv_usec one second value.  */
#define TIMER_SECOND_MICRO 1000000L

/* Thread types. */
#define THREAD_READ           0
#define THREAD_WRITE          1
#define THREAD_TIMER          2
#define THREAD_EVENT          3
#define THREAD_READY          4
#define THREAD_UNUSED         5
#define THREAD_EXECUTE        6

/* Thread yield time.  */
#define THREAD_YIELD_TIME_SLOT     10 * 1000L /* 10ms */

#define THREAD_TIMER_STRLEN 12

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

/*
 * Please consider this macro deprecated, and do not use it in new code.
 */
#define THREAD_OFF(thread)                                             \
	do {                                                           \
		if ((thread))                                          \
			thread_cancel(&(thread));                      \
	} while (0)

/*
 * Macro wrappers to generate xrefs for all thread add calls.  Includes
 * file/line/function info for debugging/tracing.
 */
#include "lib/xref.h"

#define _xref_t_a(addfn, type, m, f, a, v, t)                                  \
	({                                                                     \
		static const struct xref_threadsched _xref                     \
				__attribute__((used)) = {                      \
			.xref = XREF_INIT(XREFT_THREADSCHED, NULL, __func__),  \
			.funcname = #f,                                        \
			.dest = #t,                                            \
			.thread_type = THREAD_ ## type,                        \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_thread_add_ ## addfn(&_xref, m, f, a, v, t);                  \
	})                                                                     \
	/* end */

#define thread_add_read(m,f,a,v,t)       _xref_t_a(read_write, READ,  m,f,a,v,t)
#define thread_add_write(m,f,a,v,t)      _xref_t_a(read_write, WRITE, m,f,a,v,t)
#define thread_add_timer(m,f,a,v,t)      _xref_t_a(timer,      TIMER, m,f,a,v,t)
#define thread_add_timer_msec(m,f,a,v,t) _xref_t_a(timer_msec, TIMER, m,f,a,v,t)
#define thread_add_timer_tv(m,f,a,v,t)   _xref_t_a(timer_tv,   TIMER, m,f,a,v,t)
#define thread_add_event(m,f,a,v,t)      _xref_t_a(event,      EVENT, m,f,a,v,t)

#define thread_execute(m,f,a,v)                                                \
	({                                                                     \
		static const struct xref_threadsched _xref                     \
				__attribute__((used)) = {                      \
			.xref = XREF_INIT(XREFT_THREADSCHED, NULL, __func__),  \
			.funcname = #f,                                        \
			.dest = NULL,                                          \
			.thread_type = THREAD_EXECUTE,                         \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_thread_execute(&_xref, m, f, a, v);                           \
	}) /* end */

/* Prototypes. */
extern struct thread_master *thread_master_create(const char *);
void thread_master_set_name(struct thread_master *master, const char *name);
extern void thread_master_free(struct thread_master *);
extern void thread_master_free_unused(struct thread_master *);

extern void _thread_add_read_write(const struct xref_threadsched *xref,
				   struct thread_master *master,
				   void (*fn)(struct thread *), void *arg,
				   int fd, struct thread **tref);

extern void _thread_add_timer(const struct xref_threadsched *xref,
			      struct thread_master *master,
			      void (*fn)(struct thread *), void *arg, long t,
			      struct thread **tref);

extern void _thread_add_timer_msec(const struct xref_threadsched *xref,
				   struct thread_master *master,
				   void (*fn)(struct thread *), void *arg,
				   long t, struct thread **tref);

extern void _thread_add_timer_tv(const struct xref_threadsched *xref,
				 struct thread_master *master,
				 void (*fn)(struct thread *), void *arg,
				 struct timeval *tv, struct thread **tref);

extern void _thread_add_event(const struct xref_threadsched *xref,
			      struct thread_master *master,
			      void (*fn)(struct thread *), void *arg, int val,
			      struct thread **tref);

extern void _thread_execute(const struct xref_threadsched *xref,
			    struct thread_master *master,
			    void (*fn)(struct thread *), void *arg, int val);

extern void thread_cancel(struct thread **event);
extern void thread_cancel_async(struct thread_master *, struct thread **,
				void *);
/* Cancel ready tasks with an arg matching 'arg' */
extern void thread_cancel_event_ready(struct thread_master *m, void *arg);
/* Cancel all tasks with an arg matching 'arg', including timers and io */
extern void thread_cancel_event(struct thread_master *m, void *arg);
extern struct thread *thread_fetch(struct thread_master *, struct thread *);
extern void thread_call(struct thread *);
extern unsigned long thread_timer_remain_second(struct thread *);
extern struct timeval thread_timer_remain(struct thread *);
extern unsigned long thread_timer_remain_msec(struct thread *);
extern int thread_should_yield(struct thread *);
/* set yield time for thread */
extern void thread_set_yield_time(struct thread *, unsigned long);

/* Internal libfrr exports */
extern void thread_getrusage(RUSAGE_T *);
extern void thread_cmd_init(void);

/* Returns elapsed real (wall clock) time. */
extern unsigned long thread_consumed_time(RUSAGE_T *after, RUSAGE_T *before,
					  unsigned long *cpu_time_elapsed);

/* only for use in logging functions! */
extern pthread_key_t thread_current;
extern char *thread_timer_to_hhmmss(char *buf, int buf_size,
		struct thread *t_timer);

static inline bool thread_is_scheduled(struct thread *thread)
{
	if (thread)
		return true;

	return false;
}

/* Debug signal mask */
void debug_signals(const sigset_t *sigs);

static inline void thread_ignore_late_timer(struct thread *thread)
{
	thread->ignore_timer_late = true;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_THREAD_H */
