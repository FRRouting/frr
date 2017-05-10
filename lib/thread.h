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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_THREAD_H
#define _ZEBRA_THREAD_H

#include <zebra.h>
#include "monotime.h"
#include <pthread.h>

struct rusage_t
{
  struct rusage cpu;
  struct timeval real;
};
#define RUSAGE_T        struct rusage_t

#define GETRUSAGE(X) thread_getrusage(X)

/* Linked list of thread. */
struct thread_list
{
  struct thread *head;
  struct thread *tail;
  int count;
};

struct pqueue;

/*
 * Abstract it so we can use different methodologies to
 * select on data.
 */
typedef fd_set thread_fd_set;

#if defined(HAVE_POLL_CALL)
#include <poll.h>
struct fd_handler
{
  /* number of pfd stored in pfds */
  nfds_t pfdcount;
  /* number of pfd stored in pfds + number of snmp pfd */
  nfds_t pfdcountsnmp;
  /* number of pfd that fit in the allocated space of pfds */
  nfds_t pfdsize;
  struct pollfd *pfds;
};
#else
struct fd_handler
{
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
};
#endif

/* Master of the theads. */
struct thread_master
{
  struct thread **read;
  struct thread **write;
  struct pqueue *timer;
  struct thread_list event;
  struct thread_list ready;
  struct thread_list unuse;
  struct pqueue *background;
  int fd_limit;
  struct fd_handler handler;
  unsigned long alloc;
  long selectpoll_timeout;
  bool spin;
  bool handle_signals;
  pthread_mutex_t mtx;
};

typedef unsigned char thread_type;

/* Thread itself. */
struct thread
{
  thread_type type;                 /* thread type */
  thread_type add_type;             /* thread type */
  struct thread *next;              /* next pointer of the thread */
  struct thread *prev;              /* previous pointer of the thread */
  struct thread **ref;              /* external reference (if given) */
  struct thread_master *master;     /* pointer to the struct thread_master */
  int (*func) (struct thread *);    /* event function */
  void *arg;                        /* event argument */
  union {
    int val;                        /* second argument of the event. */
    int fd;                         /* file descriptor in case of r/w */
    struct timeval sands;           /* rest of time sands value. */
  } u;
  int index;                        /* queue position for timers */
  struct timeval real;
  struct cpu_thread_history *hist;  /* cache pointer to cpu_history */
  unsigned long yield;              /* yield time in microseconds */
  const char *funcname;             /* name of thread function */
  const char *schedfrom;            /* source file thread was scheduled from */
  int schedfrom_line;               /* line number of source file */
  pthread_mutex_t mtx;              /* mutex for thread.c functions */
};

struct cpu_thread_history 
{
  int (*func)(struct thread *);
  unsigned int total_calls;
  unsigned int total_active;
  struct time_stats
  {
    unsigned long total, max;
  } real;
  struct time_stats cpu;
  thread_type types;
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
#define THREAD_BACKGROUND     5
#define THREAD_UNUSED         6
#define THREAD_EXECUTE        7

/* Thread yield time.  */
#define THREAD_YIELD_TIME_SLOT     10 * 1000L /* 10ms */

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

#define THREAD_OFF(thread) \
  do { \
    if (thread) \
      { \
        thread_cancel (thread); \
        thread = NULL; \
      } \
  } while (0)

#define THREAD_READ_OFF(thread)  THREAD_OFF(thread)
#define THREAD_WRITE_OFF(thread)  THREAD_OFF(thread)
#define THREAD_TIMER_OFF(thread)  THREAD_OFF(thread)

#define debugargdef  const char *funcname, const char *schedfrom, int fromln

#define thread_add_read(m,f,a,v,t) funcname_thread_add_read_write(THREAD_READ,m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_add_write(m,f,a,v,t) funcname_thread_add_read_write(THREAD_WRITE,m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_add_timer(m,f,a,v,t) funcname_thread_add_timer(m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_add_timer_msec(m,f,a,v,t) funcname_thread_add_timer_msec(m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_add_timer_tv(m,f,a,v,t) funcname_thread_add_timer_tv(m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_add_event(m,f,a,v,t) funcname_thread_add_event(m,f,a,v,t,#f,__FILE__,__LINE__)
#define thread_execute(m,f,a,v) funcname_thread_execute(m,f,a,v,#f,__FILE__,__LINE__)

/* The 4th arg to thread_add_background is the # of milliseconds to delay. */
#define thread_add_background(m,f,a,v,t) funcname_thread_add_background(m,f,a,v,t,#f,__FILE__,__LINE__)

/* Prototypes. */
extern struct thread_master *thread_master_create (void);
extern void thread_master_free (struct thread_master *);
extern void thread_master_free_unused(struct thread_master *);

extern void funcname_thread_add_read_write (int dir, struct thread_master *,
    int (*)(struct thread *), void *, int, struct thread **, debugargdef);

extern void funcname_thread_add_timer (struct thread_master *,
    int (*)(struct thread *), void *, long, struct thread **, debugargdef);

extern void funcname_thread_add_timer_msec (struct thread_master *,
    int (*)(struct thread *), void *, long, struct thread **, debugargdef);

extern void funcname_thread_add_timer_tv (struct thread_master *,
    int (*)(struct thread *), void *, struct timeval *, struct thread **, debugargdef);

extern void funcname_thread_add_event (struct thread_master *,
    int (*)(struct thread *), void *, int, struct thread **, debugargdef);

extern void funcname_thread_add_background (struct thread_master *,
    int (*)(struct thread *), void *, long, struct thread **, debugargdef);

extern void funcname_thread_execute (struct thread_master *,
    int (*)(struct thread *), void *, int, debugargdef);
#undef debugargdef

extern void thread_cancel (struct thread *);
extern unsigned int thread_cancel_event (struct thread_master *, void *);
extern struct thread *thread_fetch (struct thread_master *, struct thread *);
extern void thread_call (struct thread *);
extern unsigned long thread_timer_remain_second (struct thread *);
extern struct timeval thread_timer_remain(struct thread*);
extern int thread_should_yield (struct thread *);
/* set yield time for thread */
extern void thread_set_yield_time (struct thread *, unsigned long);

/* Internal libfrr exports */
extern void thread_getrusage (RUSAGE_T *);
extern void thread_cmd_init (void);

/* Returns elapsed real (wall clock) time. */
extern unsigned long thread_consumed_time(RUSAGE_T *after, RUSAGE_T *before,
					  unsigned long *cpu_time_elapsed);

/* only for use in logging functions! */
extern struct thread *thread_current;

#endif /* _ZEBRA_THREAD_H */
