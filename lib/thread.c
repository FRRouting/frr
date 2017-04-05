/* Thread management routine
 * Copyright (C) 1998, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

/* #define DEBUG */

#include <zebra.h>
#include <sys/resource.h>

#include "thread.h"
#include "memory.h"
#include "log.h"
#include "hash.h"
#include "pqueue.h"
#include "command.h"
#include "sigevent.h"

DEFINE_MTYPE_STATIC(LIB, THREAD,        "Thread")
DEFINE_MTYPE_STATIC(LIB, THREAD_MASTER, "Thread master")
DEFINE_MTYPE_STATIC(LIB, THREAD_STATS,  "Thread stats")

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

/* Relative time, since startup */
static struct hash *cpu_record = NULL;

static unsigned long
timeval_elapsed (struct timeval a, struct timeval b)
{
  return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
	  + (a.tv_usec - b.tv_usec));
}

static unsigned int
cpu_record_hash_key (struct cpu_thread_history *a)
{
  return (uintptr_t) a->func;
}

static int 
cpu_record_hash_cmp (const struct cpu_thread_history *a,
		     const struct cpu_thread_history *b)
{
  return a->func == b->func;
}

static void *
cpu_record_hash_alloc (struct cpu_thread_history *a)
{
  struct cpu_thread_history *new;
  new = XCALLOC (MTYPE_THREAD_STATS, sizeof (struct cpu_thread_history));
  new->func = a->func;
  new->funcname = a->funcname;
  return new;
}

static void
cpu_record_hash_free (void *a)
{
  struct cpu_thread_history *hist = a;
 
  XFREE (MTYPE_THREAD_STATS, hist);
}

static void 
vty_out_cpu_thread_history(struct vty* vty,
			   struct cpu_thread_history *a)
{
  vty_out(vty, "%5d %10ld.%03ld %9d %8ld %9ld %8ld %9ld",
	  a->total_active, a->cpu.total/1000, a->cpu.total%1000, a->total_calls,
	  a->cpu.total/a->total_calls, a->cpu.max,
	  a->real.total/a->total_calls, a->real.max);
  vty_out(vty, " %c%c%c%c%c%c %s%s",
	  a->types & (1 << THREAD_READ) ? 'R':' ',
	  a->types & (1 << THREAD_WRITE) ? 'W':' ',
	  a->types & (1 << THREAD_TIMER) ? 'T':' ',
	  a->types & (1 << THREAD_EVENT) ? 'E':' ',
	  a->types & (1 << THREAD_EXECUTE) ? 'X':' ',
	  a->types & (1 << THREAD_BACKGROUND) ? 'B' : ' ',
	  a->funcname, VTY_NEWLINE);
}

static void
cpu_record_hash_print(struct hash_backet *bucket, 
		      void *args[])
{
  struct cpu_thread_history *totals = args[0];
  struct vty *vty = args[1];
  thread_type *filter = args[2];
  struct cpu_thread_history *a = bucket->data;

  if ( !(a->types & *filter) )
       return;
  vty_out_cpu_thread_history(vty,a);
  totals->total_active += a->total_active;
  totals->total_calls += a->total_calls;
  totals->real.total += a->real.total;
  if (totals->real.max < a->real.max)
    totals->real.max = a->real.max;
  totals->cpu.total += a->cpu.total;
  if (totals->cpu.max < a->cpu.max)
    totals->cpu.max = a->cpu.max;
}

static void
cpu_record_print(struct vty *vty, thread_type filter)
{
  struct cpu_thread_history tmp;
  void *args[3] = {&tmp, vty, &filter};

  memset(&tmp, 0, sizeof tmp);
  tmp.funcname = "TOTAL";
  tmp.types = filter;

  vty_out(vty, "%21s %18s %18s%s",
	  "", "CPU (user+system):", "Real (wall-clock):", VTY_NEWLINE);
  vty_out(vty, "Active   Runtime(ms)   Invoked Avg uSec Max uSecs");
  vty_out(vty, " Avg uSec Max uSecs");
  vty_out(vty, "  Type  Thread%s", VTY_NEWLINE);
  hash_iterate(cpu_record,
	       (void(*)(struct hash_backet*,void*))cpu_record_hash_print,
	       args);

  if (tmp.total_calls > 0)
    vty_out_cpu_thread_history(vty, &tmp);
}

DEFUN (show_thread_cpu,
       show_thread_cpu_cmd,
       "show thread cpu [FILTER]",
       SHOW_STR
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtexb)\n")
{
  int idx_filter = 3;
  int i = 0;
  thread_type filter = (thread_type) -1U;

  if (argc > 3)
    {
      filter = 0;
      while (argv[idx_filter]->arg[i] != '\0')
	{
	  switch ( argv[idx_filter]->arg[i] )
	    {
	    case 'r':
	    case 'R':
	      filter |= (1 << THREAD_READ);
	      break;
	    case 'w':
	    case 'W':
	      filter |= (1 << THREAD_WRITE);
	      break;
	    case 't':
	    case 'T':
	      filter |= (1 << THREAD_TIMER);
	      break;
	    case 'e':
	    case 'E':
	      filter |= (1 << THREAD_EVENT);
	      break;
	    case 'x':
	    case 'X':
	      filter |= (1 << THREAD_EXECUTE);
	      break;
	    case 'b':
	    case 'B':
	      filter |= (1 << THREAD_BACKGROUND);
	      break;
	    default:
	      break;
	    }
	  ++i;
	}
      if (filter == 0)
	{
	  vty_out(vty, "Invalid filter \"%s\" specified,"
                  " must contain at least one of 'RWTEXB'%s",
		  argv[idx_filter]->arg, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  cpu_record_print(vty, filter);
  return CMD_SUCCESS;
}

static void
cpu_record_hash_clear (struct hash_backet *bucket, 
		      void *args)
{
  thread_type *filter = args;
  struct cpu_thread_history *a = bucket->data;

  if ( !(a->types & *filter) )
       return;
  
  hash_release (cpu_record, bucket->data);
}

static void
cpu_record_clear (thread_type filter)
{
  thread_type *tmp = &filter;
  hash_iterate (cpu_record,
	        (void (*) (struct hash_backet*,void*)) cpu_record_hash_clear,
	        tmp);
}

DEFUN (clear_thread_cpu,
       clear_thread_cpu_cmd,
       "clear thread cpu [FILTER]",
       "Clear stored data\n"
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtexb)\n")
{
  int idx_filter = 3;
  int i = 0;
  thread_type filter = (thread_type) -1U;

  if (argc > 3)
    {
      filter = 0;
      while (argv[idx_filter]->arg[i] != '\0')
	{
	  switch ( argv[idx_filter]->arg[i] )
	    {
	    case 'r':
	    case 'R':
	      filter |= (1 << THREAD_READ);
	      break;
	    case 'w':
	    case 'W':
	      filter |= (1 << THREAD_WRITE);
	      break;
	    case 't':
	    case 'T':
	      filter |= (1 << THREAD_TIMER);
	      break;
	    case 'e':
	    case 'E':
	      filter |= (1 << THREAD_EVENT);
	      break;
	    case 'x':
	    case 'X':
	      filter |= (1 << THREAD_EXECUTE);
	      break;
	    case 'b':
	    case 'B':
	      filter |= (1 << THREAD_BACKGROUND);
	      break;
	    default:
	      break;
	    }
	  ++i;
	}
      if (filter == 0)
	{
	  vty_out(vty, "Invalid filter \"%s\" specified,"
                  " must contain at least one of 'RWTEXB'%s",
		  argv[idx_filter]->arg, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  cpu_record_clear (filter);
  return CMD_SUCCESS;
}

void
thread_cmd_init (void)
{
  install_element (VIEW_NODE, &show_thread_cpu_cmd);
  install_element (ENABLE_NODE, &clear_thread_cpu_cmd);
}

static int
thread_timer_cmp(void *a, void *b)
{
  struct thread *thread_a = a;
  struct thread *thread_b = b;

  if (timercmp (&thread_a->u.sands, &thread_b->u.sands, <))
    return -1;
  if (timercmp (&thread_a->u.sands, &thread_b->u.sands, >))
    return 1;
  return 0;
}

static void
thread_timer_update(void *node, int actual_position)
{
  struct thread *thread = node;

  thread->index = actual_position;
}

/* Allocate new thread master.  */
struct thread_master *
thread_master_create (void)
{
  struct thread_master *rv;
  struct rlimit limit;

  getrlimit(RLIMIT_NOFILE, &limit);

  if (cpu_record == NULL) 
    cpu_record 
      = hash_create ((unsigned int (*) (void *))cpu_record_hash_key,
		     (int (*) (const void *, const void *))cpu_record_hash_cmp);

  rv = XCALLOC (MTYPE_THREAD_MASTER, sizeof (struct thread_master));
  if (rv == NULL)
    {
      return NULL;
    }

  rv->fd_limit = (int)limit.rlim_cur;
  rv->read = XCALLOC (MTYPE_THREAD, sizeof (struct thread *) * rv->fd_limit);
  if (rv->read == NULL)
    {
      XFREE (MTYPE_THREAD_MASTER, rv);
      return NULL;
    }

  rv->write = XCALLOC (MTYPE_THREAD, sizeof (struct thread *) * rv->fd_limit);
  if (rv->write == NULL)
    {
      XFREE (MTYPE_THREAD, rv->read);
      XFREE (MTYPE_THREAD_MASTER, rv);
      return NULL;
    }

  /* Initialize the timer queues */
  rv->timer = pqueue_create();
  rv->background = pqueue_create();
  rv->timer->cmp = rv->background->cmp = thread_timer_cmp;
  rv->timer->update = rv->background->update = thread_timer_update;

#if defined(HAVE_POLL)
  rv->handler.pfdsize = rv->fd_limit;
  rv->handler.pfdcount = 0;
  rv->handler.pfds = XCALLOC (MTYPE_THREAD_MASTER,
                              sizeof (struct pollfd) * rv->handler.pfdsize);
#endif
  return rv;
}

/* Add a new thread to the list.  */
static void
thread_list_add (struct thread_list *list, struct thread *thread)
{
  thread->next = NULL;
  thread->prev = list->tail;
  if (list->tail)
    list->tail->next = thread;
  else
    list->head = thread;
  list->tail = thread;
  list->count++;
}

/* Delete a thread from the list. */
static struct thread *
thread_list_delete (struct thread_list *list, struct thread *thread)
{
  if (thread->next)
    thread->next->prev = thread->prev;
  else
    list->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  else
    list->head = thread->next;
  thread->next = thread->prev = NULL;
  list->count--;
  return thread;
}

static void
thread_delete_fd (struct thread **thread_array, struct thread *thread)
{
  thread_array[thread->u.fd] = NULL;
}

static void
thread_add_fd (struct thread **thread_array, struct thread *thread)
{
  thread_array[thread->u.fd] = thread;
}

/* Thread list is empty or not.  */
static int
thread_empty (struct thread_list *list)
{
  return  list->head ? 0 : 1;
}

/* Delete top of the list and return it. */
static struct thread *
thread_trim_head (struct thread_list *list)
{
  if (!thread_empty (list))
    return thread_list_delete (list, list->head);
  return NULL;
}

/* Move thread to unuse list. */
static void
thread_add_unuse (struct thread_master *m, struct thread *thread)
{
  assert (m != NULL && thread != NULL);
  assert (thread->next == NULL);
  assert (thread->prev == NULL);

  thread->type = THREAD_UNUSED;
  thread->hist->total_active--;
  thread_list_add (&m->unuse, thread);
}

/* Free all unused thread. */
static void
thread_list_free (struct thread_master *m, struct thread_list *list)
{
  struct thread *t;
  struct thread *next;

  for (t = list->head; t; t = next)
    {
      next = t->next;
      XFREE (MTYPE_THREAD, t);
      list->count--;
      m->alloc--;
    }
}

static void
thread_array_free (struct thread_master *m, struct thread **thread_array)
{
  struct thread *t;
  int index;

  for (index = 0; index < m->fd_limit; ++index)
    {
      t = thread_array[index];
      if (t)
        {
          thread_array[index] = NULL;
          XFREE (MTYPE_THREAD, t);
          m->alloc--;
        }
    }
  XFREE (MTYPE_THREAD, thread_array);
}

static void
thread_queue_free (struct thread_master *m, struct pqueue *queue)
{
  int i;

  for (i = 0; i < queue->size; i++)
    XFREE(MTYPE_THREAD, queue->array[i]);

  m->alloc -= queue->size;
  pqueue_delete(queue);
}

/*
 * thread_master_free_unused
 *
 * As threads are finished with they are put on the
 * unuse list for later reuse.
 * If we are shutting down, Free up unused threads
 * So we can see if we forget to shut anything off
 */
void
thread_master_free_unused (struct thread_master *m)
{
  struct thread *t;
  while ((t = thread_trim_head(&m->unuse)) != NULL)
    {
      XFREE(MTYPE_THREAD, t);
    }
}

/* Stop thread scheduler. */
void
thread_master_free (struct thread_master *m)
{
  thread_array_free (m, m->read);
  thread_array_free (m, m->write);
  thread_queue_free (m, m->timer);
  thread_list_free (m, &m->event);
  thread_list_free (m, &m->ready);
  thread_list_free (m, &m->unuse);
  thread_queue_free (m, m->background);

#if defined(HAVE_POLL)
  XFREE (MTYPE_THREAD_MASTER, m->handler.pfds);
#endif
  XFREE (MTYPE_THREAD_MASTER, m);

  if (cpu_record)
    {
      hash_clean (cpu_record, cpu_record_hash_free);
      hash_free (cpu_record);
      cpu_record = NULL;
    }
}

/* Return remain time in second. */
unsigned long
thread_timer_remain_second (struct thread *thread)
{
  int64_t remain = monotime_until(&thread->u.sands, NULL) / 1000000LL;
  return remain < 0 ? 0 : remain;
}

#define debugargdef  const char *funcname, const char *schedfrom, int fromln
#define debugargpass funcname, schedfrom, fromln

struct timeval
thread_timer_remain(struct thread *thread)
{
  struct timeval remain;
  monotime_until(&thread->u.sands, &remain);
  return remain;
}

/* Get new thread.  */
static struct thread *
thread_get (struct thread_master *m, u_char type,
	    int (*func) (struct thread *), void *arg, debugargdef)
{
  struct thread *thread = thread_trim_head (&m->unuse);
  struct cpu_thread_history tmp;

  if (! thread)
    {
      thread = XCALLOC (MTYPE_THREAD, sizeof (struct thread));
      m->alloc++;
    }
  thread->type = type;
  thread->add_type = type;
  thread->master = m;
  thread->arg = arg;
  thread->index = -1;
  thread->yield = THREAD_YIELD_TIME_SLOT; /* default */

  /*
   * So if the passed in funcname is not what we have
   * stored that means the thread->hist needs to be
   * updated.  We keep the last one around in unused
   * under the assumption that we are probably
   * going to immediately allocate the same
   * type of thread.
   * This hopefully saves us some serious
   * hash_get lookups.
   */
  if (thread->funcname != funcname ||
      thread->func != func)
    {
      tmp.func = func;
      tmp.funcname = funcname;
      thread->hist = hash_get (cpu_record, &tmp,
			       (void * (*) (void *))cpu_record_hash_alloc);
    }
  thread->hist->total_active++;
  thread->func = func;
  thread->funcname = funcname;
  thread->schedfrom = schedfrom;
  thread->schedfrom_line = fromln;

  return thread;
}

#if defined (HAVE_POLL)

#define fd_copy_fd_set(X) (X)

/* generic add thread function */
static struct thread *
generic_thread_add(struct thread_master *m, int (*func) (struct thread *),
		   void *arg, int fd, int dir, debugargdef)
{
  struct thread *thread;

  u_char type;
  short int event;

  if (dir == THREAD_READ)
    {
      event = (POLLIN | POLLHUP);
      type = THREAD_READ;
    }
  else
    {
      event = (POLLOUT | POLLHUP);
      type = THREAD_WRITE;
    }

  nfds_t queuepos = m->handler.pfdcount;
  nfds_t i=0;
  for (i=0; i<m->handler.pfdcount; i++)
    if (m->handler.pfds[i].fd == fd)
      {
        queuepos = i;
        break;
      }

  /* is there enough space for a new fd? */
  assert (queuepos < m->handler.pfdsize);

  thread = thread_get (m, type, func, arg, debugargpass);
  m->handler.pfds[queuepos].fd = fd;
  m->handler.pfds[queuepos].events |= event;
  if (queuepos == m->handler.pfdcount)
    m->handler.pfdcount++;

  return thread;
}
#else

#define fd_copy_fd_set(X) (X)
#endif

static int
fd_select (struct thread_master *m, int size, thread_fd_set *read, thread_fd_set *write, thread_fd_set *except, struct timeval *timer_wait)
{
  int num;
#if defined(HAVE_POLL)
  /* recalc timeout for poll. Attention NULL pointer is no timeout with
  select, where with poll no timeount is -1 */
  int timeout = -1;
  if (timer_wait != NULL)
    timeout = (timer_wait->tv_sec*1000) + (timer_wait->tv_usec/1000);

  num = poll (m->handler.pfds, m->handler.pfdcount + m->handler.pfdcountsnmp, timeout);
#else
  num = select (size, read, write, except, timer_wait);
#endif

  return num;
}

static int
fd_is_set (struct thread *thread, thread_fd_set *fdset, int pos)
{
#if defined(HAVE_POLL)
  return 1;
#else
  return FD_ISSET (THREAD_FD (thread), fdset);
#endif
}

static int
fd_clear_read_write (struct thread *thread)
{
#if !defined(HAVE_POLL)
  thread_fd_set *fdset = NULL;
  int fd = THREAD_FD (thread);

  if (thread->type == THREAD_READ)
    fdset = &thread->master->handler.readfd;
  else
    fdset = &thread->master->handler.writefd;

  if (!FD_ISSET (fd, fdset))
    return 0;

  FD_CLR (fd, fdset);
#endif
  return 1;
}

/* Add new read thread. */
struct thread *
funcname_thread_add_read_write (int dir, struct thread_master *m,
				int (*func) (struct thread *), void *arg, int fd,
				debugargdef)
{
  struct thread *thread = NULL;

#if !defined(HAVE_POLL)
  thread_fd_set *fdset = NULL;
  if (dir == THREAD_READ)
    fdset = &m->handler.readfd;
  else
    fdset = &m->handler.writefd;
#endif

#if defined (HAVE_POLL)
  thread = generic_thread_add(m, func, arg, fd, dir, debugargpass);

  if (thread == NULL)
    return NULL;
#else
  if (FD_ISSET (fd, fdset))
    {
      zlog_warn ("There is already %s fd [%d]",
                 (dir == THREAD_READ) ? "read" : "write", fd);
      return NULL;
    }

  FD_SET (fd, fdset);
  thread = thread_get (m, dir, func, arg, debugargpass);
#endif

  thread->u.fd = fd;
  if (dir == THREAD_READ)
    thread_add_fd (m->read, thread);
  else
    thread_add_fd (m->write, thread);

  return thread;
}

static struct thread *
funcname_thread_add_timer_timeval (struct thread_master *m,
                                   int (*func) (struct thread *), 
                                  int type,
                                  void *arg, 
                                  struct timeval *time_relative,
				  debugargdef)
{
  struct thread *thread;
  struct pqueue *queue;

  assert (m != NULL);

  assert (type == THREAD_TIMER || type == THREAD_BACKGROUND);
  assert (time_relative);
  
  queue = ((type == THREAD_TIMER) ? m->timer : m->background);
  thread = thread_get (m, type, func, arg, debugargpass);

  monotime(&thread->u.sands);
  timeradd(&thread->u.sands, time_relative, &thread->u.sands);

  pqueue_enqueue(thread, queue);
  return thread;
}


/* Add timer event thread. */
struct thread *
funcname_thread_add_timer (struct thread_master *m,
		           int (*func) (struct thread *), 
		           void *arg, long timer,
			   debugargdef)
{
  struct timeval trel;

  assert (m != NULL);

  trel.tv_sec = timer;
  trel.tv_usec = 0;

  return funcname_thread_add_timer_timeval (m, func, THREAD_TIMER, arg, 
                                            &trel, debugargpass);
}

/* Add timer event thread with "millisecond" resolution */
struct thread *
funcname_thread_add_timer_msec (struct thread_master *m,
                                int (*func) (struct thread *), 
                                void *arg, long timer,
				debugargdef)
{
  struct timeval trel;

  assert (m != NULL);

  trel.tv_sec = timer / 1000;
  trel.tv_usec = 1000*(timer % 1000);

  return funcname_thread_add_timer_timeval (m, func, THREAD_TIMER, 
                                            arg, &trel, debugargpass);
}

/* Add timer event thread with "millisecond" resolution */
struct thread *
funcname_thread_add_timer_tv (struct thread_master *m,
                              int (*func) (struct thread *),
                              void *arg, struct timeval *tv,
                              debugargdef)
{
  return funcname_thread_add_timer_timeval (m, func, THREAD_TIMER,
                                            arg, tv, debugargpass);
}

/* Add a background thread, with an optional millisec delay */
struct thread *
funcname_thread_add_background (struct thread_master *m,
                                int (*func) (struct thread *),
                                void *arg, long delay,
				debugargdef)
{
  struct timeval trel;
  
  assert (m != NULL);
  
  if (delay)
    {
      trel.tv_sec = delay / 1000;
      trel.tv_usec = 1000*(delay % 1000);
    }
  else
    {
      trel.tv_sec = 0;
      trel.tv_usec = 0;
    }

  return funcname_thread_add_timer_timeval (m, func, THREAD_BACKGROUND,
                                            arg, &trel, debugargpass);
}

/* Add simple event thread. */
struct thread *
funcname_thread_add_event (struct thread_master *m,
		  int (*func) (struct thread *), void *arg, int val,
		  debugargdef)
{
  struct thread *thread;

  assert (m != NULL);

  thread = thread_get (m, THREAD_EVENT, func, arg, debugargpass);
  thread->u.val = val;
  thread_list_add (&m->event, thread);

  return thread;
}

static void
thread_cancel_read_or_write (struct thread *thread, short int state)
{
#if defined(HAVE_POLL)
  nfds_t i;

  for (i=0;i<thread->master->handler.pfdcount;++i)
    if (thread->master->handler.pfds[i].fd == thread->u.fd)
      {
        thread->master->handler.pfds[i].events &= ~(state);

        /* remove thread fds from pfd list */
        if (thread->master->handler.pfds[i].events == 0)
          {
            memmove(thread->master->handler.pfds+i,
                    thread->master->handler.pfds+i+1,
                    (thread->master->handler.pfdsize-i-1) * sizeof(struct pollfd));
            thread->master->handler.pfdcount--;
            return;
          }
      }
#endif

  fd_clear_read_write (thread);
}

/* Cancel thread from scheduler. */
void
thread_cancel (struct thread *thread)
{
  struct thread_list *list = NULL;
  struct pqueue *queue = NULL;
  struct thread **thread_array = NULL;
  
  switch (thread->type)
    {
    case THREAD_READ:
#if defined (HAVE_POLL)
      thread_cancel_read_or_write (thread, POLLIN | POLLHUP);
#else
      thread_cancel_read_or_write (thread, 0);
#endif
      thread_array = thread->master->read;
      break;
    case THREAD_WRITE:
#if defined (HAVE_POLL)
      thread_cancel_read_or_write (thread, POLLOUT | POLLHUP);
#else
      thread_cancel_read_or_write (thread, 0);
#endif
      thread_array = thread->master->write;
      break;
    case THREAD_TIMER:
      queue = thread->master->timer;
      break;
    case THREAD_EVENT:
      list = &thread->master->event;
      break;
    case THREAD_READY:
      list = &thread->master->ready;
      break;
    case THREAD_BACKGROUND:
      queue = thread->master->background;
      break;
    default:
      return;
      break;
    }

  if (queue)
    {
      assert(thread->index >= 0);
      assert(thread == queue->array[thread->index]);
      pqueue_remove_at(thread->index, queue);
    }
  else if (list)
    {
      thread_list_delete (list, thread);
    }
  else if (thread_array)
    {
      thread_delete_fd (thread_array, thread);
    }
  else
    {
      assert(!"Thread should be either in queue or list or array!");
    }

  thread_add_unuse (thread->master, thread);
}

/* Delete all events which has argument value arg. */
unsigned int
thread_cancel_event (struct thread_master *m, void *arg)
{
  unsigned int ret = 0;
  struct thread *thread;

  thread = m->event.head;
  while (thread)
    {
      struct thread *t;

      t = thread;
      thread = t->next;

      if (t->arg == arg)
        {
          ret++;
          thread_list_delete (&m->event, t);
          thread_add_unuse (m, t);
        }
    }

  /* thread can be on the ready list too */
  thread = m->ready.head;
  while (thread)
    {
      struct thread *t;

      t = thread;
      thread = t->next;

      if (t->arg == arg)
        {
          ret++;
          thread_list_delete (&m->ready, t);
          thread_add_unuse (m, t);
        }
    }
  return ret;
}

static struct timeval *
thread_timer_wait (struct pqueue *queue, struct timeval *timer_val)
{
  if (queue->size)
    {
      struct thread *next_timer = queue->array[0];
      monotime_until(&next_timer->u.sands, timer_val);
      return timer_val;
    }
  return NULL;
}

static struct thread *
thread_run (struct thread_master *m, struct thread *thread,
	    struct thread *fetch)
{
  *fetch = *thread;
  thread_add_unuse (m, thread);
  return fetch;
}

static int
thread_process_fds_helper (struct thread_master *m, struct thread *thread, thread_fd_set *fdset, short int state, int pos)
{
  struct thread **thread_array;

  if (!thread)
    return 0;

  if (thread->type == THREAD_READ)
    thread_array = m->read;
  else
    thread_array = m->write;

  if (fd_is_set (thread, fdset, pos))
    {
      fd_clear_read_write (thread);
      thread_delete_fd (thread_array, thread);
      thread_list_add (&m->ready, thread);
      thread->type = THREAD_READY;
#if defined(HAVE_POLL)
      thread->master->handler.pfds[pos].events &= ~(state);
#endif
      return 1;
    }
  return 0;
}

#if defined(HAVE_POLL)

/* check poll events */
static void
check_pollfds(struct thread_master *m, fd_set *readfd, int num)
{
  nfds_t i = 0;
  int ready = 0;
  for (i = 0; i < m->handler.pfdcount && ready < num ; ++i)
    {
      /* no event for current fd? immideatly continue */
      if(m->handler.pfds[i].revents == 0)
        continue;

      ready++;

      /* POLLIN / POLLOUT process event */
      if (m->handler.pfds[i].revents & POLLIN)
        thread_process_fds_helper(m, m->read[m->handler.pfds[i].fd], NULL, POLLIN, i);
      if (m->handler.pfds[i].revents & POLLOUT)
        thread_process_fds_helper(m, m->write[m->handler.pfds[i].fd], NULL, POLLOUT, i);

      /* remove fd from list on POLLNVAL */
      if (m->handler.pfds[i].revents & POLLNVAL ||
          m->handler.pfds[i].revents & POLLHUP)
        {
           memmove(m->handler.pfds+i,
                   m->handler.pfds+i+1,
                   (m->handler.pfdsize-i-1) * sizeof(struct pollfd));
           m->handler.pfdcount--;
           i--;
        }
      else
          m->handler.pfds[i].revents = 0;
    }
}
#endif

static void
thread_process_fds (struct thread_master *m, thread_fd_set *rset, thread_fd_set *wset, int num)
{
#if defined (HAVE_POLL)
  check_pollfds (m, rset, num);
#else
  int ready = 0, index;

  for (index = 0; index < m->fd_limit && ready < num; ++index)
    {
      ready += thread_process_fds_helper (m, m->read[index], rset, 0, 0);
      ready += thread_process_fds_helper (m, m->write[index], wset, 0, 0);
    }
#endif
}

/* Add all timers that have popped to the ready list. */
static unsigned int
thread_timer_process (struct pqueue *queue, struct timeval *timenow)
{
  struct thread *thread;
  unsigned int ready = 0;
  
  while (queue->size)
    {
      thread = queue->array[0];
      if (timercmp (timenow, &thread->u.sands, <))
        return ready;
      pqueue_dequeue(queue);
      thread->type = THREAD_READY;
      thread_list_add (&thread->master->ready, thread);
      ready++;
    }
  return ready;
}

/* process a list en masse, e.g. for event thread lists */
static unsigned int
thread_process (struct thread_list *list)
{
  struct thread *thread;
  struct thread *next;
  unsigned int ready = 0;
  
  for (thread = list->head; thread; thread = next)
    {
      next = thread->next;
      thread_list_delete (list, thread);
      thread->type = THREAD_READY;
      thread_list_add (&thread->master->ready, thread);
      ready++;
    }
  return ready;
}


/* Fetch next ready thread. */
struct thread *
thread_fetch (struct thread_master *m, struct thread *fetch)
{
  struct thread *thread;
  thread_fd_set readfd;
  thread_fd_set writefd;
  thread_fd_set exceptfd;
  struct timeval now;
  struct timeval timer_val = { .tv_sec = 0, .tv_usec = 0 };
  struct timeval timer_val_bg;
  struct timeval *timer_wait = &timer_val;
  struct timeval *timer_wait_bg;

  while (1)
    {
      int num = 0;

      /* Signals pre-empt everything */
      quagga_sigevent_process ();
       
      /* Drain the ready queue of already scheduled jobs, before scheduling
       * more.
       */
      if ((thread = thread_trim_head (&m->ready)) != NULL)
        return thread_run (m, thread, fetch);
      
      /* To be fair to all kinds of threads, and avoid starvation, we
       * need to be careful to consider all thread types for scheduling
       * in each quanta. I.e. we should not return early from here on.
       */
       
      /* Normal event are the next highest priority.  */
      thread_process (&m->event);
      
      /* Structure copy.  */
#if !defined(HAVE_POLL)
      readfd = fd_copy_fd_set(m->handler.readfd);
      writefd = fd_copy_fd_set(m->handler.writefd);
      exceptfd = fd_copy_fd_set(m->handler.exceptfd);
#endif
      
      /* Calculate select wait timer if nothing else to do */
      if (m->ready.count == 0)
        {
          timer_wait = thread_timer_wait (m->timer, &timer_val);
          timer_wait_bg = thread_timer_wait (m->background, &timer_val_bg);
          
          if (timer_wait_bg &&
              (!timer_wait || (timercmp (timer_wait, timer_wait_bg, >))))
            timer_wait = timer_wait_bg;
        }

      if (timer_wait && timer_wait->tv_sec < 0)
        {
          timerclear(&timer_val);
          timer_wait = &timer_val;
        }

      num = fd_select (m, FD_SETSIZE, &readfd, &writefd, &exceptfd, timer_wait);
      
      /* Signals should get quick treatment */
      if (num < 0)
        {
          if (errno == EINTR)
            continue; /* signal received - process it */
          zlog_warn ("select() error: %s", safe_strerror (errno));
          return NULL;
        }

      /* Check foreground timers.  Historically, they have had higher
         priority than I/O threads, so let's push them onto the ready
	 list in front of the I/O threads. */
      monotime(&now);
      thread_timer_process (m->timer, &now);
      
      /* Got IO, process it */
      if (num > 0)
        thread_process_fds (m, &readfd, &writefd, num);

#if 0
      /* If any threads were made ready above (I/O or foreground timer),
         perhaps we should avoid adding background timers to the ready
	 list at this time.  If this is code is uncommented, then background
	 timer threads will not run unless there is nothing else to do. */
      if ((thread = thread_trim_head (&m->ready)) != NULL)
        return thread_run (m, thread, fetch);
#endif

      /* Background timer/events, lowest priority */
      thread_timer_process (m->background, &now);
      
      if ((thread = thread_trim_head (&m->ready)) != NULL)
        return thread_run (m, thread, fetch);
    }
}

unsigned long
thread_consumed_time (RUSAGE_T *now, RUSAGE_T *start, unsigned long *cputime)
{
  /* This is 'user + sys' time.  */
  *cputime = timeval_elapsed (now->cpu.ru_utime, start->cpu.ru_utime) +
	     timeval_elapsed (now->cpu.ru_stime, start->cpu.ru_stime);
  return timeval_elapsed (now->real, start->real);
}

/* We should aim to yield after yield milliseconds, which defaults
   to THREAD_YIELD_TIME_SLOT .
   Note: we are using real (wall clock) time for this calculation.
   It could be argued that CPU time may make more sense in certain
   contexts.  The things to consider are whether the thread may have
   blocked (in which case wall time increases, but CPU time does not),
   or whether the system is heavily loaded with other processes competing
   for CPU time.  On balance, wall clock time seems to make sense. 
   Plus it has the added benefit that gettimeofday should be faster
   than calling getrusage. */
int
thread_should_yield (struct thread *thread)
{
  return monotime_since(&thread->real, NULL) > (int64_t)thread->yield;
}

void
thread_set_yield_time (struct thread *thread, unsigned long yield_time)
{
  thread->yield = yield_time;
}

void
thread_getrusage (RUSAGE_T *r)
{
  monotime(&r->real);
  getrusage(RUSAGE_SELF, &(r->cpu));
}

struct thread *thread_current = NULL;

/* We check thread consumed time. If the system has getrusage, we'll
   use that to get in-depth stats on the performance of the thread in addition
   to wall clock time stats from gettimeofday. */
void
thread_call (struct thread *thread)
{
  unsigned long realtime, cputime;
  RUSAGE_T before, after;

  GETRUSAGE (&before);
  thread->real = before.real;

  thread_current = thread;
  (*thread->func) (thread);
  thread_current = NULL;

  GETRUSAGE (&after);

  realtime = thread_consumed_time (&after, &before, &cputime);
  thread->hist->real.total += realtime;
  if (thread->hist->real.max < realtime)
    thread->hist->real.max = realtime;
  thread->hist->cpu.total += cputime;
  if (thread->hist->cpu.max < cputime)
    thread->hist->cpu.max = cputime;

  ++(thread->hist->total_calls);
  thread->hist->types |= (1 << thread->add_type);

#ifdef CONSUMED_TIME_CHECK
  if (realtime > CONSUMED_TIME_CHECK)
    {
      /*
       * We have a CPU Hog on our hands.
       * Whinge about it now, so we're aware this is yet another task
       * to fix.
       */
      zlog_warn ("SLOW THREAD: task %s (%lx) ran for %lums (cpu time %lums)",
		 thread->funcname,
		 (unsigned long) thread->func,
		 realtime/1000, cputime/1000);
    }
#endif /* CONSUMED_TIME_CHECK */
}

/* Execute thread */
struct thread *
funcname_thread_execute (struct thread_master *m,
                int (*func)(struct thread *), 
                void *arg,
                int val,
		debugargdef)
{
  struct cpu_thread_history tmp;
  struct thread dummy;

  memset (&dummy, 0, sizeof (struct thread));

  dummy.type = THREAD_EVENT;
  dummy.add_type = THREAD_EXECUTE;
  dummy.master = NULL;
  dummy.arg = arg;
  dummy.u.val = val;

  tmp.func = dummy.func = func;
  tmp.funcname = dummy.funcname = funcname;
  dummy.hist = hash_get (cpu_record, &tmp,
			 (void * (*) (void *))cpu_record_hash_alloc);

  dummy.schedfrom = schedfrom;
  dummy.schedfrom_line = fromln;

  thread_call (&dummy);

  return NULL;
}
