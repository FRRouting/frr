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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* #define DEBUG */

#include <zebra.h>
#include <sys/resource.h>

#include "thread.h"
#include "memory.h"
#include "frrcu.h"
#include "log.h"
#include "hash.h"
#include "command.h"
#include "sigevent.h"
#include "network.h"
#include "jhash.h"
#include "frratomic.h"
#include "frr_pthread.h"
#include "lib_errors.h"

DEFINE_MTYPE_STATIC(LIB, THREAD, "Thread")
DEFINE_MTYPE_STATIC(LIB, THREAD_MASTER, "Thread master")
DEFINE_MTYPE_STATIC(LIB, THREAD_POLL, "Thread Poll Info")
DEFINE_MTYPE_STATIC(LIB, THREAD_STATS, "Thread stats")

DECLARE_LIST(thread_list, struct thread, threaditem)

static int thread_timer_cmp(const struct thread *a, const struct thread *b)
{
	if (a->u.sands.tv_sec < b->u.sands.tv_sec)
		return -1;
	if (a->u.sands.tv_sec > b->u.sands.tv_sec)
		return 1;
	if (a->u.sands.tv_usec < b->u.sands.tv_usec)
		return -1;
	if (a->u.sands.tv_usec > b->u.sands.tv_usec)
		return 1;
	return 0;
}

DECLARE_HEAP(thread_timer_list, struct thread, timeritem,
		thread_timer_cmp)

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

#define AWAKEN(m)                                                              \
	do {                                                                   \
		static unsigned char wakebyte = 0x01;                          \
		write(m->io_pipe[1], &wakebyte, 1);                            \
	} while (0);

/* control variable for initializer */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
pthread_key_t thread_current;

static pthread_mutex_t masters_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct list *masters;

static void thread_free(struct thread_master *master, struct thread *thread);

/* CLI start ---------------------------------------------------------------- */
static unsigned int cpu_record_hash_key(const struct cpu_thread_history *a)
{
	int size = sizeof(a->func);

	return jhash(&a->func, size, 0);
}

static bool cpu_record_hash_cmp(const struct cpu_thread_history *a,
			       const struct cpu_thread_history *b)
{
	return a->func == b->func;
}

static void *cpu_record_hash_alloc(struct cpu_thread_history *a)
{
	struct cpu_thread_history *new;
	new = XCALLOC(MTYPE_THREAD_STATS, sizeof(struct cpu_thread_history));
	new->func = a->func;
	new->funcname = a->funcname;
	return new;
}

static void cpu_record_hash_free(void *a)
{
	struct cpu_thread_history *hist = a;

	XFREE(MTYPE_THREAD_STATS, hist);
}

#ifndef EXCLUDE_CPU_TIME
static void vty_out_cpu_thread_history(struct vty *vty,
				       struct cpu_thread_history *a)
{
	vty_out(vty, "%5zu %10zu.%03zu %9zu %8zu %9zu %8zu %9zu",
		(size_t)a->total_active,
		a->cpu.total / 1000, a->cpu.total % 1000,
		(size_t)a->total_calls,
		a->cpu.total / a->total_calls, a->cpu.max,
		a->real.total / a->total_calls, a->real.max);
	vty_out(vty, " %c%c%c%c%c %s\n",
		a->types & (1 << THREAD_READ) ? 'R' : ' ',
		a->types & (1 << THREAD_WRITE) ? 'W' : ' ',
		a->types & (1 << THREAD_TIMER) ? 'T' : ' ',
		a->types & (1 << THREAD_EVENT) ? 'E' : ' ',
		a->types & (1 << THREAD_EXECUTE) ? 'X' : ' ', a->funcname);
}

static void cpu_record_hash_print(struct hash_bucket *bucket, void *args[])
{
	struct cpu_thread_history *totals = args[0];
	struct cpu_thread_history copy;
	struct vty *vty = args[1];
	uint8_t *filter = args[2];

	struct cpu_thread_history *a = bucket->data;

	copy.total_active =
		atomic_load_explicit(&a->total_active, memory_order_seq_cst);
	copy.total_calls =
		atomic_load_explicit(&a->total_calls, memory_order_seq_cst);
	copy.cpu.total =
		atomic_load_explicit(&a->cpu.total, memory_order_seq_cst);
	copy.cpu.max = atomic_load_explicit(&a->cpu.max, memory_order_seq_cst);
	copy.real.total =
		atomic_load_explicit(&a->real.total, memory_order_seq_cst);
	copy.real.max =
		atomic_load_explicit(&a->real.max, memory_order_seq_cst);
	copy.types = atomic_load_explicit(&a->types, memory_order_seq_cst);
	copy.funcname = a->funcname;

	if (!(copy.types & *filter))
		return;

	vty_out_cpu_thread_history(vty, &copy);
	totals->total_active += copy.total_active;
	totals->total_calls += copy.total_calls;
	totals->real.total += copy.real.total;
	if (totals->real.max < copy.real.max)
		totals->real.max = copy.real.max;
	totals->cpu.total += copy.cpu.total;
	if (totals->cpu.max < copy.cpu.max)
		totals->cpu.max = copy.cpu.max;
}

static void cpu_record_print(struct vty *vty, uint8_t filter)
{
	struct cpu_thread_history tmp;
	void *args[3] = {&tmp, vty, &filter};
	struct thread_master *m;
	struct listnode *ln;

	memset(&tmp, 0, sizeof tmp);
	tmp.funcname = "TOTAL";
	tmp.types = filter;

	frr_with_mutex(&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, ln, m)) {
			const char *name = m->name ? m->name : "main";

			char underline[strlen(name) + 1];
			memset(underline, '-', sizeof(underline));
			underline[sizeof(underline) - 1] = '\0';

			vty_out(vty, "\n");
			vty_out(vty, "Showing statistics for pthread %s\n",
				name);
			vty_out(vty, "-------------------------------%s\n",
				underline);
			vty_out(vty, "%21s %18s %18s\n", "",
				"CPU (user+system):", "Real (wall-clock):");
			vty_out(vty,
				"Active   Runtime(ms)   Invoked Avg uSec Max uSecs");
			vty_out(vty, " Avg uSec Max uSecs");
			vty_out(vty, "  Type  Thread\n");

			if (m->cpu_record->count)
				hash_iterate(
					m->cpu_record,
					(void (*)(struct hash_bucket *,
						  void *))cpu_record_hash_print,
					args);
			else
				vty_out(vty, "No data to display yet.\n");

			vty_out(vty, "\n");
		}
	}

	vty_out(vty, "\n");
	vty_out(vty, "Total thread statistics\n");
	vty_out(vty, "-------------------------\n");
	vty_out(vty, "%21s %18s %18s\n", "",
		"CPU (user+system):", "Real (wall-clock):");
	vty_out(vty, "Active   Runtime(ms)   Invoked Avg uSec Max uSecs");
	vty_out(vty, " Avg uSec Max uSecs");
	vty_out(vty, "  Type  Thread\n");

	if (tmp.total_calls > 0)
		vty_out_cpu_thread_history(vty, &tmp);
}
#endif

static void cpu_record_hash_clear(struct hash_bucket *bucket, void *args[])
{
	uint8_t *filter = args[0];
	struct hash *cpu_record = args[1];

	struct cpu_thread_history *a = bucket->data;

	if (!(a->types & *filter))
		return;

	hash_release(cpu_record, bucket->data);
}

static void cpu_record_clear(uint8_t filter)
{
	uint8_t *tmp = &filter;
	struct thread_master *m;
	struct listnode *ln;

	frr_with_mutex(&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, ln, m)) {
			frr_with_mutex(&m->mtx) {
				void *args[2] = {tmp, m->cpu_record};
				hash_iterate(
					m->cpu_record,
					(void (*)(struct hash_bucket *,
						  void *))cpu_record_hash_clear,
					args);
			}
		}
	}
}

static uint8_t parse_filter(const char *filterstr)
{
	int i = 0;
	int filter = 0;

	while (filterstr[i] != '\0') {
		switch (filterstr[i]) {
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
		default:
			break;
		}
		++i;
	}
	return filter;
}

#ifndef EXCLUDE_CPU_TIME
DEFUN (show_thread_cpu,
       show_thread_cpu_cmd,
       "show thread cpu [FILTER]",
       SHOW_STR
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtex)\n")
{
	uint8_t filter = (uint8_t)-1U;
	int idx = 0;

	if (argv_find(argv, argc, "FILTER", &idx)) {
		filter = parse_filter(argv[idx]->arg);
		if (!filter) {
			vty_out(vty,
				"Invalid filter \"%s\" specified; must contain at least"
				"one of 'RWTEXB'\n",
				argv[idx]->arg);
			return CMD_WARNING;
		}
	}

	cpu_record_print(vty, filter);
	return CMD_SUCCESS;
}
#endif

static void show_thread_poll_helper(struct vty *vty, struct thread_master *m)
{
	const char *name = m->name ? m->name : "main";
	char underline[strlen(name) + 1];
	struct thread *thread;
	uint32_t i;

	memset(underline, '-', sizeof(underline));
	underline[sizeof(underline) - 1] = '\0';

	vty_out(vty, "\nShowing poll FD's for %s\n", name);
	vty_out(vty, "----------------------%s\n", underline);
	vty_out(vty, "Count: %u/%d\n", (uint32_t)m->handler.pfdcount,
		m->fd_limit);
	for (i = 0; i < m->handler.pfdcount; i++) {
		vty_out(vty, "\t%6d fd:%6d events:%2d revents:%2d\t\t", i,
			m->handler.pfds[i].fd, m->handler.pfds[i].events,
			m->handler.pfds[i].revents);

		if (m->handler.pfds[i].events & POLLIN) {
			thread = m->read[m->handler.pfds[i].fd];

			if (!thread)
				vty_out(vty, "ERROR ");
			else
				vty_out(vty, "%s ", thread->funcname);
		} else
			vty_out(vty, " ");

		if (m->handler.pfds[i].events & POLLOUT) {
			thread = m->write[m->handler.pfds[i].fd];

			if (!thread)
				vty_out(vty, "ERROR\n");
			else
				vty_out(vty, "%s\n", thread->funcname);
		} else
			vty_out(vty, "\n");
	}
}

DEFUN (show_thread_poll,
       show_thread_poll_cmd,
       "show thread poll",
       SHOW_STR
       "Thread information\n"
       "Show poll FD's and information\n")
{
	struct listnode *node;
	struct thread_master *m;

	frr_with_mutex(&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, node, m)) {
			show_thread_poll_helper(vty, m);
		}
	}

	return CMD_SUCCESS;
}


DEFUN (clear_thread_cpu,
       clear_thread_cpu_cmd,
       "clear thread cpu [FILTER]",
       "Clear stored data in all pthreads\n"
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtexb)\n")
{
	uint8_t filter = (uint8_t)-1U;
	int idx = 0;

	if (argv_find(argv, argc, "FILTER", &idx)) {
		filter = parse_filter(argv[idx]->arg);
		if (!filter) {
			vty_out(vty,
				"Invalid filter \"%s\" specified; must contain at least"
				"one of 'RWTEXB'\n",
				argv[idx]->arg);
			return CMD_WARNING;
		}
	}

	cpu_record_clear(filter);
	return CMD_SUCCESS;
}

void thread_cmd_init(void)
{
#ifndef EXCLUDE_CPU_TIME
	install_element(VIEW_NODE, &show_thread_cpu_cmd);
#endif
	install_element(VIEW_NODE, &show_thread_poll_cmd);
	install_element(ENABLE_NODE, &clear_thread_cpu_cmd);
}
/* CLI end ------------------------------------------------------------------ */


static void cancelreq_del(void *cr)
{
	XFREE(MTYPE_TMP, cr);
}

/* initializer, only ever called once */
static void initializer(void)
{
	pthread_key_create(&thread_current, NULL);
}

struct thread_master *thread_master_create(const char *name)
{
	struct thread_master *rv;
	struct rlimit limit;

	pthread_once(&init_once, &initializer);

	rv = XCALLOC(MTYPE_THREAD_MASTER, sizeof(struct thread_master));

	/* Initialize master mutex */
	pthread_mutex_init(&rv->mtx, NULL);
	pthread_cond_init(&rv->cancel_cond, NULL);

	/* Set name */
	rv->name = name ? XSTRDUP(MTYPE_THREAD_MASTER, name) : NULL;

	/* Initialize I/O task data structures */
	getrlimit(RLIMIT_NOFILE, &limit);
	rv->fd_limit = (int)limit.rlim_cur;
	rv->read = XCALLOC(MTYPE_THREAD_POLL,
			   sizeof(struct thread *) * rv->fd_limit);

	rv->write = XCALLOC(MTYPE_THREAD_POLL,
			    sizeof(struct thread *) * rv->fd_limit);

	rv->cpu_record = hash_create_size(
		8, (unsigned int (*)(const void *))cpu_record_hash_key,
		(bool (*)(const void *, const void *))cpu_record_hash_cmp,
		"Thread Hash");

	thread_list_init(&rv->event);
	thread_list_init(&rv->ready);
	thread_list_init(&rv->unuse);
	thread_timer_list_init(&rv->timer);

	/* Initialize thread_fetch() settings */
	rv->spin = true;
	rv->handle_signals = true;

	/* Set pthread owner, should be updated by actual owner */
	rv->owner = pthread_self();
	rv->cancel_req = list_new();
	rv->cancel_req->del = cancelreq_del;
	rv->canceled = true;

	/* Initialize pipe poker */
	pipe(rv->io_pipe);
	set_nonblocking(rv->io_pipe[0]);
	set_nonblocking(rv->io_pipe[1]);

	/* Initialize data structures for poll() */
	rv->handler.pfdsize = rv->fd_limit;
	rv->handler.pfdcount = 0;
	rv->handler.pfds = XCALLOC(MTYPE_THREAD_MASTER,
				   sizeof(struct pollfd) * rv->handler.pfdsize);
	rv->handler.copy = XCALLOC(MTYPE_THREAD_MASTER,
				   sizeof(struct pollfd) * rv->handler.pfdsize);

	/* add to list of threadmasters */
	frr_with_mutex(&masters_mtx) {
		if (!masters)
			masters = list_new();

		listnode_add(masters, rv);
	}

	return rv;
}

void thread_master_set_name(struct thread_master *master, const char *name)
{
	frr_with_mutex(&master->mtx) {
		XFREE(MTYPE_THREAD_MASTER, master->name);
		master->name = XSTRDUP(MTYPE_THREAD_MASTER, name);
	}
}

#define THREAD_UNUSED_DEPTH 10

/* Move thread to unuse list. */
static void thread_add_unuse(struct thread_master *m, struct thread *thread)
{
	pthread_mutex_t mtxc = thread->mtx;

	assert(m != NULL && thread != NULL);

	thread->hist->total_active--;
	memset(thread, 0, sizeof(struct thread));
	thread->type = THREAD_UNUSED;

	/* Restore the thread mutex context. */
	thread->mtx = mtxc;

	if (thread_list_count(&m->unuse) < THREAD_UNUSED_DEPTH) {
		thread_list_add_tail(&m->unuse, thread);
		return;
	}

	thread_free(m, thread);
}

/* Free all unused thread. */
static void thread_list_free(struct thread_master *m,
		struct thread_list_head *list)
{
	struct thread *t;

	while ((t = thread_list_pop(list)))
		thread_free(m, t);
}

static void thread_array_free(struct thread_master *m,
			      struct thread **thread_array)
{
	struct thread *t;
	int index;

	for (index = 0; index < m->fd_limit; ++index) {
		t = thread_array[index];
		if (t) {
			thread_array[index] = NULL;
			thread_free(m, t);
		}
	}
	XFREE(MTYPE_THREAD_POLL, thread_array);
}

/*
 * thread_master_free_unused
 *
 * As threads are finished with they are put on the
 * unuse list for later reuse.
 * If we are shutting down, Free up unused threads
 * So we can see if we forget to shut anything off
 */
void thread_master_free_unused(struct thread_master *m)
{
	frr_with_mutex(&m->mtx) {
		struct thread *t;
		while ((t = thread_list_pop(&m->unuse)))
			thread_free(m, t);
	}
}

/* Stop thread scheduler. */
void thread_master_free(struct thread_master *m)
{
	struct thread *t;

	frr_with_mutex(&masters_mtx) {
		listnode_delete(masters, m);
		if (masters->count == 0) {
			list_delete(&masters);
		}
	}

	thread_array_free(m, m->read);
	thread_array_free(m, m->write);
	while ((t = thread_timer_list_pop(&m->timer)))
		thread_free(m, t);
	thread_list_free(m, &m->event);
	thread_list_free(m, &m->ready);
	thread_list_free(m, &m->unuse);
	pthread_mutex_destroy(&m->mtx);
	pthread_cond_destroy(&m->cancel_cond);
	close(m->io_pipe[0]);
	close(m->io_pipe[1]);
	list_delete(&m->cancel_req);
	m->cancel_req = NULL;

	hash_clean(m->cpu_record, cpu_record_hash_free);
	hash_free(m->cpu_record);
	m->cpu_record = NULL;

	XFREE(MTYPE_THREAD_MASTER, m->name);
	XFREE(MTYPE_THREAD_MASTER, m->handler.pfds);
	XFREE(MTYPE_THREAD_MASTER, m->handler.copy);
	XFREE(MTYPE_THREAD_MASTER, m);
}

/* Return remain time in miliseconds. */
unsigned long thread_timer_remain_msec(struct thread *thread)
{
	int64_t remain;

	frr_with_mutex(&thread->mtx) {
		remain = monotime_until(&thread->u.sands, NULL) / 1000LL;
	}

	return remain < 0 ? 0 : remain;
}

/* Return remain time in seconds. */
unsigned long thread_timer_remain_second(struct thread *thread)
{
	return thread_timer_remain_msec(thread) / 1000LL;
}

#define debugargdef  const char *funcname, const char *schedfrom, int fromln
#define debugargpass funcname, schedfrom, fromln

struct timeval thread_timer_remain(struct thread *thread)
{
	struct timeval remain;
	frr_with_mutex(&thread->mtx) {
		monotime_until(&thread->u.sands, &remain);
	}
	return remain;
}

/* Get new thread.  */
static struct thread *thread_get(struct thread_master *m, uint8_t type,
				 int (*func)(struct thread *), void *arg,
				 debugargdef)
{
	struct thread *thread = thread_list_pop(&m->unuse);
	struct cpu_thread_history tmp;

	if (!thread) {
		thread = XCALLOC(MTYPE_THREAD, sizeof(struct thread));
		/* mutex only needs to be initialized at struct creation. */
		pthread_mutex_init(&thread->mtx, NULL);
		m->alloc++;
	}

	thread->type = type;
	thread->add_type = type;
	thread->master = m;
	thread->arg = arg;
	thread->yield = THREAD_YIELD_TIME_SLOT; /* default */
	thread->ref = NULL;

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
	if (thread->funcname != funcname || thread->func != func) {
		tmp.func = func;
		tmp.funcname = funcname;
		thread->hist =
			hash_get(m->cpu_record, &tmp,
				 (void *(*)(void *))cpu_record_hash_alloc);
	}
	thread->hist->total_active++;
	thread->func = func;
	thread->funcname = funcname;
	thread->schedfrom = schedfrom;
	thread->schedfrom_line = fromln;

	return thread;
}

static void thread_free(struct thread_master *master, struct thread *thread)
{
	/* Update statistics. */
	assert(master->alloc > 0);
	master->alloc--;

	/* Free allocated resources. */
	pthread_mutex_destroy(&thread->mtx);
	XFREE(MTYPE_THREAD, thread);
}

static int fd_poll(struct thread_master *m, struct pollfd *pfds, nfds_t pfdsize,
		   nfds_t count, const struct timeval *timer_wait)
{
	/* If timer_wait is null here, that means poll() should block
	 * indefinitely,
	 * unless the thread_master has overridden it by setting
	 * ->selectpoll_timeout.
	 * If the value is positive, it specifies the maximum number of
	 * milliseconds
	 * to wait. If the timeout is -1, it specifies that we should never wait
	 * and
	 * always return immediately even if no event is detected. If the value
	 * is
	 * zero, the behavior is default. */
	int timeout = -1;

	/* number of file descriptors with events */
	int num;

	if (timer_wait != NULL
	    && m->selectpoll_timeout == 0) // use the default value
		timeout = (timer_wait->tv_sec * 1000)
			  + (timer_wait->tv_usec / 1000);
	else if (m->selectpoll_timeout > 0) // use the user's timeout
		timeout = m->selectpoll_timeout;
	else if (m->selectpoll_timeout
		 < 0) // effect a poll (return immediately)
		timeout = 0;

	rcu_read_unlock();
	rcu_assert_read_unlocked();

	/* add poll pipe poker */
	assert(count + 1 < pfdsize);
	pfds[count].fd = m->io_pipe[0];
	pfds[count].events = POLLIN;
	pfds[count].revents = 0x00;

	num = poll(pfds, count + 1, timeout);

	unsigned char trash[64];
	if (num > 0 && pfds[count].revents != 0 && num--)
		while (read(m->io_pipe[0], &trash, sizeof(trash)) > 0)
			;

	rcu_read_lock();

	return num;
}

/* Add new read thread. */
struct thread *funcname_thread_add_read_write(int dir, struct thread_master *m,
					      int (*func)(struct thread *),
					      void *arg, int fd,
					      struct thread **t_ptr,
					      debugargdef)
{
	struct thread *thread = NULL;
	struct thread **thread_array;

	assert(fd >= 0 && fd < m->fd_limit);
	frr_with_mutex(&m->mtx) {
		if (t_ptr && *t_ptr)
			// thread is already scheduled; don't reschedule
			break;

		/* default to a new pollfd */
		nfds_t queuepos = m->handler.pfdcount;

		if (dir == THREAD_READ)
			thread_array = m->read;
		else
			thread_array = m->write;

		/* if we already have a pollfd for our file descriptor, find and
		 * use it */
		for (nfds_t i = 0; i < m->handler.pfdcount; i++)
			if (m->handler.pfds[i].fd == fd) {
				queuepos = i;

#ifdef DEV_BUILD
				/*
				 * What happens if we have a thread already
				 * created for this event?
				 */
				if (thread_array[fd])
					assert(!"Thread already scheduled for file descriptor");
#endif
				break;
			}

		/* make sure we have room for this fd + pipe poker fd */
		assert(queuepos + 1 < m->handler.pfdsize);

		thread = thread_get(m, dir, func, arg, debugargpass);

		m->handler.pfds[queuepos].fd = fd;
		m->handler.pfds[queuepos].events |=
			(dir == THREAD_READ ? POLLIN : POLLOUT);

		if (queuepos == m->handler.pfdcount)
			m->handler.pfdcount++;

		if (thread) {
			frr_with_mutex(&thread->mtx) {
				thread->u.fd = fd;
				thread_array[thread->u.fd] = thread;
			}

			if (t_ptr) {
				*t_ptr = thread;
				thread->ref = t_ptr;
			}
		}

		AWAKEN(m);
	}

	return thread;
}

static struct thread *
funcname_thread_add_timer_timeval(struct thread_master *m,
				  int (*func)(struct thread *), int type,
				  void *arg, struct timeval *time_relative,
				  struct thread **t_ptr, debugargdef)
{
	struct thread *thread;

	assert(m != NULL);

	assert(type == THREAD_TIMER);
	assert(time_relative);

	frr_with_mutex(&m->mtx) {
		if (t_ptr && *t_ptr)
			// thread is already scheduled; don't reschedule
			return NULL;

		thread = thread_get(m, type, func, arg, debugargpass);

		frr_with_mutex(&thread->mtx) {
			monotime(&thread->u.sands);
			timeradd(&thread->u.sands, time_relative,
				 &thread->u.sands);
			thread_timer_list_add(&m->timer, thread);
			if (t_ptr) {
				*t_ptr = thread;
				thread->ref = t_ptr;
			}
		}

		AWAKEN(m);
	}

	return thread;
}


/* Add timer event thread. */
struct thread *funcname_thread_add_timer(struct thread_master *m,
					 int (*func)(struct thread *),
					 void *arg, long timer,
					 struct thread **t_ptr, debugargdef)
{
	struct timeval trel;

	assert(m != NULL);

	trel.tv_sec = timer;
	trel.tv_usec = 0;

	return funcname_thread_add_timer_timeval(m, func, THREAD_TIMER, arg,
						 &trel, t_ptr, debugargpass);
}

/* Add timer event thread with "millisecond" resolution */
struct thread *funcname_thread_add_timer_msec(struct thread_master *m,
					      int (*func)(struct thread *),
					      void *arg, long timer,
					      struct thread **t_ptr,
					      debugargdef)
{
	struct timeval trel;

	assert(m != NULL);

	trel.tv_sec = timer / 1000;
	trel.tv_usec = 1000 * (timer % 1000);

	return funcname_thread_add_timer_timeval(m, func, THREAD_TIMER, arg,
						 &trel, t_ptr, debugargpass);
}

/* Add timer event thread with "millisecond" resolution */
struct thread *funcname_thread_add_timer_tv(struct thread_master *m,
					    int (*func)(struct thread *),
					    void *arg, struct timeval *tv,
					    struct thread **t_ptr, debugargdef)
{
	return funcname_thread_add_timer_timeval(m, func, THREAD_TIMER, arg, tv,
						 t_ptr, debugargpass);
}

/* Add simple event thread. */
struct thread *funcname_thread_add_event(struct thread_master *m,
					 int (*func)(struct thread *),
					 void *arg, int val,
					 struct thread **t_ptr, debugargdef)
{
	struct thread *thread = NULL;

	assert(m != NULL);

	frr_with_mutex(&m->mtx) {
		if (t_ptr && *t_ptr)
			// thread is already scheduled; don't reschedule
			break;

		thread = thread_get(m, THREAD_EVENT, func, arg, debugargpass);
		frr_with_mutex(&thread->mtx) {
			thread->u.val = val;
			thread_list_add_tail(&m->event, thread);
		}

		if (t_ptr) {
			*t_ptr = thread;
			thread->ref = t_ptr;
		}

		AWAKEN(m);
	}

	return thread;
}

/* Thread cancellation ------------------------------------------------------ */

/**
 * NOT's out the .events field of pollfd corresponding to the given file
 * descriptor. The event to be NOT'd is passed in the 'state' parameter.
 *
 * This needs to happen for both copies of pollfd's. See 'thread_fetch'
 * implementation for details.
 *
 * @param master
 * @param fd
 * @param state the event to cancel. One or more (OR'd together) of the
 * following:
 *   - POLLIN
 *   - POLLOUT
 */
static void thread_cancel_rw(struct thread_master *master, int fd, short state)
{
	bool found = false;

	/* Cancel POLLHUP too just in case some bozo set it */
	state |= POLLHUP;

	/* find the index of corresponding pollfd */
	nfds_t i;

	for (i = 0; i < master->handler.pfdcount; i++)
		if (master->handler.pfds[i].fd == fd) {
			found = true;
			break;
		}

	if (!found) {
		zlog_debug(
			"[!] Received cancellation request for nonexistent rw job");
		zlog_debug("[!] threadmaster: %s | fd: %d",
			   master->name ? master->name : "", fd);
		return;
	}

	/* NOT out event. */
	master->handler.pfds[i].events &= ~(state);

	/* If all events are canceled, delete / resize the pollfd array. */
	if (master->handler.pfds[i].events == 0) {
		memmove(master->handler.pfds + i, master->handler.pfds + i + 1,
			(master->handler.pfdcount - i - 1)
				* sizeof(struct pollfd));
		master->handler.pfdcount--;
		master->handler.pfds[master->handler.pfdcount].fd = 0;
		master->handler.pfds[master->handler.pfdcount].events = 0;
	}

	/* If we have the same pollfd in the copy, perform the same operations,
	 * otherwise return. */
	if (i >= master->handler.copycount)
		return;

	master->handler.copy[i].events &= ~(state);

	if (master->handler.copy[i].events == 0) {
		memmove(master->handler.copy + i, master->handler.copy + i + 1,
			(master->handler.copycount - i - 1)
				* sizeof(struct pollfd));
		master->handler.copycount--;
		master->handler.copy[master->handler.copycount].fd = 0;
	        master->handler.copy[master->handler.copycount].events = 0;
	}
}

/**
 * Process cancellation requests.
 *
 * This may only be run from the pthread which owns the thread_master.
 *
 * @param master the thread master to process
 * @REQUIRE master->mtx
 */
static void do_thread_cancel(struct thread_master *master)
{
	struct thread_list_head *list = NULL;
	struct thread **thread_array = NULL;
	struct thread *thread;

	struct cancel_req *cr;
	struct listnode *ln;
	for (ALL_LIST_ELEMENTS_RO(master->cancel_req, ln, cr)) {
		/* If this is an event object cancellation, linear search
		 * through event
		 * list deleting any events which have the specified argument.
		 * We also
		 * need to check every thread in the ready queue. */
		if (cr->eventobj) {
			struct thread *t;

			frr_each_safe(thread_list, &master->event, t) {
				if (t->arg != cr->eventobj)
					continue;
				thread_list_del(&master->event, t);
				if (t->ref)
					*t->ref = NULL;
				thread_add_unuse(master, t);
			}

			frr_each_safe(thread_list, &master->ready, t) {
				if (t->arg != cr->eventobj)
					continue;
				thread_list_del(&master->ready, t);
				if (t->ref)
					*t->ref = NULL;
				thread_add_unuse(master, t);
			}
			continue;
		}

		/* The pointer varies depending on whether the cancellation
		 * request was
		 * made asynchronously or not. If it was, we need to check
		 * whether the
		 * thread even exists anymore before cancelling it. */
		thread = (cr->thread) ? cr->thread : *cr->threadref;

		if (!thread)
			continue;

		/* Determine the appropriate queue to cancel the thread from */
		switch (thread->type) {
		case THREAD_READ:
			thread_cancel_rw(master, thread->u.fd, POLLIN);
			thread_array = master->read;
			break;
		case THREAD_WRITE:
			thread_cancel_rw(master, thread->u.fd, POLLOUT);
			thread_array = master->write;
			break;
		case THREAD_TIMER:
			thread_timer_list_del(&master->timer, thread);
			break;
		case THREAD_EVENT:
			list = &master->event;
			break;
		case THREAD_READY:
			list = &master->ready;
			break;
		default:
			continue;
			break;
		}

		if (list) {
			thread_list_del(list, thread);
		} else if (thread_array) {
			thread_array[thread->u.fd] = NULL;
		}

		if (thread->ref)
			*thread->ref = NULL;

		thread_add_unuse(thread->master, thread);
	}

	/* Delete and free all cancellation requests */
	list_delete_all_node(master->cancel_req);

	/* Wake up any threads which may be blocked in thread_cancel_async() */
	master->canceled = true;
	pthread_cond_broadcast(&master->cancel_cond);
}

/**
 * Cancel any events which have the specified argument.
 *
 * MT-Unsafe
 *
 * @param m the thread_master to cancel from
 * @param arg the argument passed when creating the event
 */
void thread_cancel_event(struct thread_master *master, void *arg)
{
	assert(master->owner == pthread_self());

	frr_with_mutex(&master->mtx) {
		struct cancel_req *cr =
			XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));
		cr->eventobj = arg;
		listnode_add(master->cancel_req, cr);
		do_thread_cancel(master);
	}
}

/**
 * Cancel a specific task.
 *
 * MT-Unsafe
 *
 * @param thread task to cancel
 */
void thread_cancel(struct thread *thread)
{
	struct thread_master *master = thread->master;

	assert(master->owner == pthread_self());

	frr_with_mutex(&master->mtx) {
		struct cancel_req *cr =
			XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));
		cr->thread = thread;
		listnode_add(master->cancel_req, cr);
		do_thread_cancel(master);
	}
}

/**
 * Asynchronous cancellation.
 *
 * Called with either a struct thread ** or void * to an event argument,
 * this function posts the correct cancellation request and blocks until it is
 * serviced.
 *
 * If the thread is currently running, execution blocks until it completes.
 *
 * The last two parameters are mutually exclusive, i.e. if you pass one the
 * other must be NULL.
 *
 * When the cancellation procedure executes on the target thread_master, the
 * thread * provided is checked for nullity. If it is null, the thread is
 * assumed to no longer exist and the cancellation request is a no-op. Thus
 * users of this API must pass a back-reference when scheduling the original
 * task.
 *
 * MT-Safe
 *
 * @param master the thread master with the relevant event / task
 * @param thread pointer to thread to cancel
 * @param eventobj the event
 */
void thread_cancel_async(struct thread_master *master, struct thread **thread,
			 void *eventobj)
{
	assert(!(thread && eventobj) && (thread || eventobj));
	assert(master->owner != pthread_self());

	frr_with_mutex(&master->mtx) {
		master->canceled = false;

		if (thread) {
			struct cancel_req *cr =
				XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));
			cr->threadref = thread;
			listnode_add(master->cancel_req, cr);
		} else if (eventobj) {
			struct cancel_req *cr =
				XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));
			cr->eventobj = eventobj;
			listnode_add(master->cancel_req, cr);
		}
		AWAKEN(master);

		while (!master->canceled)
			pthread_cond_wait(&master->cancel_cond, &master->mtx);
	}
}
/* ------------------------------------------------------------------------- */

static struct timeval *thread_timer_wait(struct thread_timer_list_head *timers,
					 struct timeval *timer_val)
{
	if (!thread_timer_list_count(timers))
		return NULL;

	struct thread *next_timer = thread_timer_list_first(timers);
	monotime_until(&next_timer->u.sands, timer_val);
	return timer_val;
}

static struct thread *thread_run(struct thread_master *m, struct thread *thread,
				 struct thread *fetch)
{
	*fetch = *thread;
	thread_add_unuse(m, thread);
	return fetch;
}

static int thread_process_io_helper(struct thread_master *m,
				    struct thread *thread, short state,
				    short actual_state, int pos)
{
	struct thread **thread_array;

	/*
	 * poll() clears the .events field, but the pollfd array we
	 * pass to poll() is a copy of the one used to schedule threads.
	 * We need to synchronize state between the two here by applying
	 * the same changes poll() made on the copy of the "real" pollfd
	 * array.
	 *
	 * This cleans up a possible infinite loop where we refuse
	 * to respond to a poll event but poll is insistent that
	 * we should.
	 */
	m->handler.pfds[pos].events &= ~(state);

	if (!thread) {
		if ((actual_state & (POLLHUP|POLLIN)) != POLLHUP)
			flog_err(EC_LIB_NO_THREAD,
				 "Attempting to process an I/O event but for fd: %d(%d) no thread to handle this!\n",
				 m->handler.pfds[pos].fd, actual_state);
		return 0;
	}

	if (thread->type == THREAD_READ)
		thread_array = m->read;
	else
		thread_array = m->write;

	thread_array[thread->u.fd] = NULL;
	thread_list_add_tail(&m->ready, thread);
	thread->type = THREAD_READY;

	return 1;
}

/**
 * Process I/O events.
 *
 * Walks through file descriptor array looking for those pollfds whose .revents
 * field has something interesting. Deletes any invalid file descriptors.
 *
 * @param m the thread master
 * @param num the number of active file descriptors (return value of poll())
 */
static void thread_process_io(struct thread_master *m, unsigned int num)
{
	unsigned int ready = 0;
	struct pollfd *pfds = m->handler.copy;

	for (nfds_t i = 0; i < m->handler.copycount && ready < num; ++i) {
		/* no event for current fd? immediately continue */
		if (pfds[i].revents == 0)
			continue;

		ready++;

		/* Unless someone has called thread_cancel from another pthread,
		 * the only
		 * thing that could have changed in m->handler.pfds while we
		 * were
		 * asleep is the .events field in a given pollfd. Barring
		 * thread_cancel()
		 * that value should be a superset of the values we have in our
		 * copy, so
		 * there's no need to update it. Similarily, barring deletion,
		 * the fd
		 * should still be a valid index into the master's pfds. */
		if (pfds[i].revents & (POLLIN | POLLHUP)) {
			thread_process_io_helper(m, m->read[pfds[i].fd], POLLIN,
						 pfds[i].revents, i);
		}
		if (pfds[i].revents & POLLOUT)
			thread_process_io_helper(m, m->write[pfds[i].fd],
						 POLLOUT, pfds[i].revents, i);

		/* if one of our file descriptors is garbage, remove the same
		 * from
		 * both pfds + update sizes and index */
		if (pfds[i].revents & POLLNVAL) {
			memmove(m->handler.pfds + i, m->handler.pfds + i + 1,
				(m->handler.pfdcount - i - 1)
					* sizeof(struct pollfd));
			m->handler.pfdcount--;
			m->handler.pfds[m->handler.pfdcount].fd = 0;
			m->handler.pfds[m->handler.pfdcount].events = 0;

			memmove(pfds + i, pfds + i + 1,
				(m->handler.copycount - i - 1)
					* sizeof(struct pollfd));
			m->handler.copycount--;
			m->handler.copy[m->handler.copycount].fd = 0;
			m->handler.copy[m->handler.copycount].events = 0;

			i--;
		}
	}
}

/* Add all timers that have popped to the ready list. */
static unsigned int thread_process_timers(struct thread_timer_list_head *timers,
					  struct timeval *timenow)
{
	struct thread *thread;
	unsigned int ready = 0;

	while ((thread = thread_timer_list_first(timers))) {
		if (timercmp(timenow, &thread->u.sands, <))
			return ready;
		thread_timer_list_pop(timers);
		thread->type = THREAD_READY;
		thread_list_add_tail(&thread->master->ready, thread);
		ready++;
	}
	return ready;
}

/* process a list en masse, e.g. for event thread lists */
static unsigned int thread_process(struct thread_list_head *list)
{
	struct thread *thread;
	unsigned int ready = 0;

	while ((thread = thread_list_pop(list))) {
		thread->type = THREAD_READY;
		thread_list_add_tail(&thread->master->ready, thread);
		ready++;
	}
	return ready;
}


/* Fetch next ready thread. */
struct thread *thread_fetch(struct thread_master *m, struct thread *fetch)
{
	struct thread *thread = NULL;
	struct timeval now;
	struct timeval zerotime = {0, 0};
	struct timeval tv;
	struct timeval *tw = NULL;

	int num = 0;

	do {
		/* Handle signals if any */
		if (m->handle_signals)
			quagga_sigevent_process();

		pthread_mutex_lock(&m->mtx);

		/* Process any pending cancellation requests */
		do_thread_cancel(m);

		/*
		 * Attempt to flush ready queue before going into poll().
		 * This is performance-critical. Think twice before modifying.
		 */
		if ((thread = thread_list_pop(&m->ready))) {
			fetch = thread_run(m, thread, fetch);
			if (fetch->ref)
				*fetch->ref = NULL;
			pthread_mutex_unlock(&m->mtx);
			break;
		}

		/* otherwise, tick through scheduling sequence */

		/*
		 * Post events to ready queue. This must come before the
		 * following block since events should occur immediately
		 */
		thread_process(&m->event);

		/*
		 * If there are no tasks on the ready queue, we will poll()
		 * until a timer expires or we receive I/O, whichever comes
		 * first. The strategy for doing this is:
		 *
		 * - If there are events pending, set the poll() timeout to zero
		 * - If there are no events pending, but there are timers
		 * pending, set the
		 *   timeout to the smallest remaining time on any timer
		 * - If there are neither timers nor events pending, but there
		 * are file
		 *   descriptors pending, block indefinitely in poll()
		 * - If nothing is pending, it's time for the application to die
		 *
		 * In every case except the last, we need to hit poll() at least
		 * once per loop to avoid starvation by events
		 */
		if (!thread_list_count(&m->ready))
			tw = thread_timer_wait(&m->timer, &tv);

		if (thread_list_count(&m->ready) ||
				(tw && !timercmp(tw, &zerotime, >)))
			tw = &zerotime;

		if (!tw && m->handler.pfdcount == 0) { /* die */
			pthread_mutex_unlock(&m->mtx);
			fetch = NULL;
			break;
		}

		/*
		 * Copy pollfd array + # active pollfds in it. Not necessary to
		 * copy the array size as this is fixed.
		 */
		m->handler.copycount = m->handler.pfdcount;
		memcpy(m->handler.copy, m->handler.pfds,
		       m->handler.copycount * sizeof(struct pollfd));

		pthread_mutex_unlock(&m->mtx);
		{
			num = fd_poll(m, m->handler.copy, m->handler.pfdsize,
				      m->handler.copycount, tw);
		}
		pthread_mutex_lock(&m->mtx);

		/* Handle any errors received in poll() */
		if (num < 0) {
			if (errno == EINTR) {
				pthread_mutex_unlock(&m->mtx);
				/* loop around to signal handler */
				continue;
			}

			/* else die */
			flog_err(EC_LIB_SYSTEM_CALL, "poll() error: %s",
				 safe_strerror(errno));
			pthread_mutex_unlock(&m->mtx);
			fetch = NULL;
			break;
		}

		/* Post timers to ready queue. */
		monotime(&now);
		thread_process_timers(&m->timer, &now);

		/* Post I/O to ready queue. */
		if (num > 0)
			thread_process_io(m, num);

		pthread_mutex_unlock(&m->mtx);

	} while (!thread && m->spin);

	return fetch;
}

static unsigned long timeval_elapsed(struct timeval a, struct timeval b)
{
	return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
		+ (a.tv_usec - b.tv_usec));
}

unsigned long thread_consumed_time(RUSAGE_T *now, RUSAGE_T *start,
				   unsigned long *cputime)
{
	/* This is 'user + sys' time.  */
	*cputime = timeval_elapsed(now->cpu.ru_utime, start->cpu.ru_utime)
		   + timeval_elapsed(now->cpu.ru_stime, start->cpu.ru_stime);
	return timeval_elapsed(now->real, start->real);
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
int thread_should_yield(struct thread *thread)
{
	int result;
	frr_with_mutex(&thread->mtx) {
		result = monotime_since(&thread->real, NULL)
			 > (int64_t)thread->yield;
	}
	return result;
}

void thread_set_yield_time(struct thread *thread, unsigned long yield_time)
{
	frr_with_mutex(&thread->mtx) {
		thread->yield = yield_time;
	}
}

void thread_getrusage(RUSAGE_T *r)
{
#if defined RUSAGE_THREAD
#define FRR_RUSAGE RUSAGE_THREAD
#else
#define FRR_RUSAGE RUSAGE_SELF
#endif
	monotime(&r->real);
#ifndef EXCLUDE_CPU_TIME
	getrusage(FRR_RUSAGE, &(r->cpu));
#endif
}

/*
 * Call a thread.
 *
 * This function will atomically update the thread's usage history. At present
 * this is the only spot where usage history is written. Nevertheless the code
 * has been written such that the introduction of writers in the future should
 * not need to update it provided the writers atomically perform only the
 * operations done here, i.e. updating the total and maximum times. In
 * particular, the maximum real and cpu times must be monotonically increasing
 * or this code is not correct.
 */
void thread_call(struct thread *thread)
{
#ifndef EXCLUDE_CPU_TIME
	_Atomic unsigned long realtime, cputime;
	unsigned long exp;
	unsigned long helper;
#endif
	RUSAGE_T before, after;

	GETRUSAGE(&before);
	thread->real = before.real;

	pthread_setspecific(thread_current, thread);
	(*thread->func)(thread);
	pthread_setspecific(thread_current, NULL);

	GETRUSAGE(&after);

#ifndef EXCLUDE_CPU_TIME
	realtime = thread_consumed_time(&after, &before, &helper);
	cputime = helper;

	/* update realtime */
	atomic_fetch_add_explicit(&thread->hist->real.total, realtime,
				  memory_order_seq_cst);
	exp = atomic_load_explicit(&thread->hist->real.max,
				   memory_order_seq_cst);
	while (exp < realtime
	       && !atomic_compare_exchange_weak_explicit(
			  &thread->hist->real.max, &exp, realtime,
			  memory_order_seq_cst, memory_order_seq_cst))
		;

	/* update cputime */
	atomic_fetch_add_explicit(&thread->hist->cpu.total, cputime,
				  memory_order_seq_cst);
	exp = atomic_load_explicit(&thread->hist->cpu.max,
				   memory_order_seq_cst);
	while (exp < cputime
	       && !atomic_compare_exchange_weak_explicit(
			  &thread->hist->cpu.max, &exp, cputime,
			  memory_order_seq_cst, memory_order_seq_cst))
		;

	atomic_fetch_add_explicit(&thread->hist->total_calls, 1,
				  memory_order_seq_cst);
	atomic_fetch_or_explicit(&thread->hist->types, 1 << thread->add_type,
				 memory_order_seq_cst);

#ifdef CONSUMED_TIME_CHECK
	if (realtime > CONSUMED_TIME_CHECK) {
		/*
		 * We have a CPU Hog on our hands.
		 * Whinge about it now, so we're aware this is yet another task
		 * to fix.
		 */
		flog_warn(
			EC_LIB_SLOW_THREAD,
			"SLOW THREAD: task %s (%lx) ran for %lums (cpu time %lums)",
			thread->funcname, (unsigned long)thread->func,
			realtime / 1000, cputime / 1000);
	}
#endif /* CONSUMED_TIME_CHECK */
#endif /* Exclude CPU Time */
}

/* Execute thread */
void funcname_thread_execute(struct thread_master *m,
			     int (*func)(struct thread *), void *arg, int val,
			     debugargdef)
{
	struct thread *thread;

	/* Get or allocate new thread to execute. */
	frr_with_mutex(&m->mtx) {
		thread = thread_get(m, THREAD_EVENT, func, arg, debugargpass);

		/* Set its event value. */
		frr_with_mutex(&thread->mtx) {
			thread->add_type = THREAD_EXECUTE;
			thread->u.val = val;
			thread->ref = &thread;
		}
	}

	/* Execute thread doing all accounting. */
	thread_call(thread);

	/* Give back or free thread. */
	thread_add_unuse(m, thread);
}
