// SPDX-License-Identifier: GPL-2.0-or-later
/* Event management routine header.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_THREAD_H
#define _ZEBRA_THREAD_H

#include <signal.h>
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

#define CONSUMED_TIME_CHECK 5000000

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
#define RUSAGE_T struct rusage_t

#define GETRUSAGE(X) event_getrusage(X)

PREDECL_LIST(event_list);
PREDECL_HEAP(event_timer_list);

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

struct xref_eventsched {
	struct xref xref;

	const char *funcname;
	const char *dest;
	uint32_t event_type;
};

PREDECL_HASH(cpu_records);

/* Master of the theads. */
struct event_loop {
	char *name;

	struct event **read;
	struct event **write;
	struct event_timer_list_head timer;
	struct event_list_head event, ready, unuse;
	struct list *cancel_req;
	bool canceled;
	pthread_cond_t cancel_cond;
	struct cpu_records_head cpu_records[1];
	int io_pipe[2];
	int fd_limit;
	struct fd_handler handler;
	long selectpoll_timeout;
	bool spin;
	bool handle_signals;
	pthread_mutex_t mtx;
	pthread_t owner;

	nfds_t last_read;

	bool ready_run_loop;
	RUSAGE_T last_getrusage;
};

/* Event types. */
enum event_types {
	EVENT_READ,
	EVENT_WRITE,
	EVENT_TIMER,
	EVENT_EVENT,
	EVENT_READY,
	EVENT_UNUSED,
	EVENT_EXECUTE,
};

/* Event itself. */
struct event {
	enum event_types type;	   /* event type */
	enum event_types add_type; /* event type */
	struct event_list_item eventitem;
	struct event_timer_list_item timeritem;
	struct event **ref;	      /* external reference (if given) */
	struct event_loop *master;    /* pointer to the struct event_loop */
	void (*func)(struct event *e); /* event function */
	void *arg;		      /* event argument */
	union {
		int val;	      /* second argument of the event. */
		int fd;		      /* file descriptor in case of r/w */
		struct timeval sands; /* rest of time sands value. */
	} u;
	struct timeval real;
	struct cpu_event_history *hist;	    /* cache pointer to cpu_history */
	unsigned long yield;		    /* yield time in microseconds */
	const struct xref_eventsched *xref; /* origin location */
	pthread_mutex_t mtx;		    /* mutex for thread.c functions */
	bool ignore_timer_late;
};

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pTH"(struct event *)
#endif

struct cpu_event_history {
	struct cpu_records_item item;

	void (*func)(struct event *e);
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

static inline unsigned long timeval_elapsed(struct timeval a, struct timeval b)
{
	return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
		+ (a.tv_usec - b.tv_usec));
}

/* Event yield time.  */
#define EVENT_YIELD_TIME_SLOT 10 * 1000L /* 10ms */

#define EVENT_TIMER_STRLEN 12

/* Macros. */
#define EVENT_ARG(X) ((X)->arg)
#define EVENT_FD(X) ((X)->u.fd)
#define EVENT_VAL(X) ((X)->u.val)

/*
 * Please consider this macro deprecated, and do not use it in new code.
 */
#define EVENT_OFF(thread)                                                      \
	do {                                                                   \
		if ((thread))                                                  \
			event_cancel(&(thread));                               \
	} while (0)

/*
 * Macro wrappers to generate xrefs for all thread add calls.  Includes
 * file/line/function info for debugging/tracing.
 */
#include "lib/xref.h"

#define _xref_t_a(addfn, type, m, f, a, v, t)                                  \
	({                                                                     \
		static const struct xref_eventsched _xref __attribute__(       \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_EVENTSCHED, NULL, __func__),   \
			.funcname = #f,                                        \
			.dest = #t,                                            \
			.event_type = EVENT_##type,                            \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_event_add_##addfn(&_xref, m, f, a, v, t);                     \
	}) /* end */

#define event_add_read(m, f, a, v, t) _xref_t_a(read_write, READ, m, f, a, v, t)
#define event_add_write(m, f, a, v, t)                                         \
	_xref_t_a(read_write, WRITE, m, f, a, v, t)
#define event_add_timer(m, f, a, v, t) _xref_t_a(timer, TIMER, m, f, a, v, t)
#define event_add_timer_msec(m, f, a, v, t)                                    \
	_xref_t_a(timer_msec, TIMER, m, f, a, v, t)
#define event_add_timer_tv(m, f, a, v, t)                                      \
	_xref_t_a(timer_tv, TIMER, m, f, a, v, t)
#define event_add_event(m, f, a, v, t) _xref_t_a(event, EVENT, m, f, a, v, t)

#define event_execute(m, f, a, v, p)                                           \
	({                                                                     \
		static const struct xref_eventsched _xref __attribute__(       \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_EVENTSCHED, NULL, __func__),   \
			.funcname = #f,                                        \
			.dest = NULL,                                          \
			.event_type = EVENT_EXECUTE,                           \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_event_execute(&_xref, m, f, a, v, p);                         \
	}) /* end */

/* Prototypes. */
extern struct event_loop *event_master_create(const char *name);
void event_master_set_name(struct event_loop *master, const char *name);
extern void event_master_free(struct event_loop *m);

extern void _event_add_read_write(const struct xref_eventsched *xref,
				  struct event_loop *master,
				  void (*fn)(struct event *), void *arg, int fd,
				  struct event **tref);

extern void _event_add_timer(const struct xref_eventsched *xref,
			     struct event_loop *master,
			     void (*fn)(struct event *), void *arg, long t,
			     struct event **tref);

extern void _event_add_timer_msec(const struct xref_eventsched *xref,
				  struct event_loop *master,
				  void (*fn)(struct event *), void *arg, long t,
				  struct event **tref);

extern void _event_add_timer_tv(const struct xref_eventsched *xref,
				struct event_loop *master,
				void (*fn)(struct event *), void *arg,
				struct timeval *tv, struct event **tref);

extern void _event_add_event(const struct xref_eventsched *xref,
			     struct event_loop *master,
			     void (*fn)(struct event *), void *arg, int val,
			     struct event **tref);

extern void _event_execute(const struct xref_eventsched *xref,
			   struct event_loop *master,
			   void (*fn)(struct event *), void *arg, int val,
			   struct event **eref);

extern void event_cancel(struct event **event);
extern void event_cancel_async(struct event_loop *m, struct event **eptr,
			       void *data);
/* Cancel ready tasks with an arg matching 'arg' */
extern void event_cancel_event_ready(struct event_loop *m, void *arg);
/* Cancel all tasks with an arg matching 'arg', including timers and io */
extern void event_cancel_event(struct event_loop *m, void *arg);
extern struct event *event_fetch(struct event_loop *m, struct event *event);
extern void event_call(struct event *event);
extern unsigned long event_timer_remain_second(struct event *event);
extern struct timeval event_timer_remain(struct event *event);
extern unsigned long event_timer_remain_msec(struct event *event);
extern int event_should_yield(struct event *event);
/* set yield time for thread */
extern void event_set_yield_time(struct event *event, unsigned long ytime);

/* Internal libfrr exports */
extern void event_getrusage(RUSAGE_T *r);
extern void event_cmd_init(void);

/* Returns elapsed real (wall clock) time. */
extern unsigned long event_consumed_time(RUSAGE_T *after, RUSAGE_T *before,
					 unsigned long *cpu_time_elapsed);

/* only for use in logging functions! */
extern pthread_key_t thread_current;
extern char *event_timer_to_hhmmss(char *buf, int buf_size,
				   struct event *t_timer);

static inline bool event_is_scheduled(struct event *thread)
{
	if (thread)
		return true;

	return false;
}

/* Debug signal mask */
void debug_signals(const sigset_t *sigs);

static inline void event_ignore_late_timer(struct event *event)
{
	event->ignore_timer_late = true;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_THREAD_H */
