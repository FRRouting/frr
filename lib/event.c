// SPDX-License-Identifier: GPL-2.0-or-later
/* Thread management routine
 * Copyright (C) 1998, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

/* #define DEBUG */

#include <zebra.h>

#include <signal.h>
#include <sys/resource.h>

#include "frrevent.h"
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
#include "libfrr_trace.h"
#include "libfrr.h"

DEFINE_MTYPE_STATIC(LIB, THREAD, "Thread");
DEFINE_MTYPE_STATIC(LIB, EVENT_MASTER, "Thread master");
DEFINE_MTYPE_STATIC(LIB, EVENT_POLL, "Thread Poll Info");
DEFINE_MTYPE_STATIC(LIB, EVENT_STATS, "Thread stats");

DECLARE_LIST(event_list, struct event, eventitem);

struct cancel_req {
	int flags;
	struct event *thread;
	void *eventobj;
	struct event **threadref;
};

/* Flags for task cancellation */
#define EVENT_CANCEL_FLAG_READY 0x01

static int event_timer_cmp(const struct event *a, const struct event *b)
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

DECLARE_HEAP(event_timer_list, struct event, timeritem, event_timer_cmp);

#define AWAKEN(m)                                                              \
	do {                                                                   \
		const unsigned char wakebyte = 0x01;                           \
		write(m->io_pipe[1], &wakebyte, 1);                            \
	} while (0)

/* control variable for initializer */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
pthread_key_t thread_current;

static pthread_mutex_t masters_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct list *masters;

static void thread_free(struct event_loop *master, struct event *thread);

bool cputime_enabled = true;
unsigned long cputime_threshold = CONSUMED_TIME_CHECK;
unsigned long walltime_threshold = CONSUMED_TIME_CHECK;

/* CLI start ---------------------------------------------------------------- */
#include "lib/event_clippy.c"

static uint32_t cpu_record_hash_key(const struct cpu_event_history *a)
{
	int size = sizeof(a->func);

	return jhash(&a->func, size, 0);
}

static int cpu_record_hash_cmp(const struct cpu_event_history *a,
			       const struct cpu_event_history *b)
{
	return numcmp((uintptr_t)a->func, (uintptr_t)b->func);
}

DECLARE_HASH(cpu_records, struct cpu_event_history, item, cpu_record_hash_cmp,
	     cpu_record_hash_key);

static struct cpu_event_history *cpu_records_get(struct event_loop *loop,
						 void (*func)(struct event *e),
						 const char *funcname)
{
	struct cpu_event_history ref = { .func = func }, *res;

	res = cpu_records_find(loop->cpu_records, &ref);
	if (!res) {
		res = XCALLOC(MTYPE_EVENT_STATS, sizeof(*res));
		res->func = func;
		res->funcname = funcname;
		cpu_records_add(loop->cpu_records, res);
	}
	return res;
}

static void cpu_records_free(struct cpu_event_history **p)
{
	XFREE(MTYPE_EVENT_STATS, *p);
}

static void vty_out_cpu_event_history(struct vty *vty,
				      struct cpu_event_history *a)
{
	vty_out(vty,
		"%5zu %10zu.%03zu %9zu %8zu %9zu %8zu %9zu %9zu %9zu %10zu",
		a->total_active, a->cpu.total / 1000, a->cpu.total % 1000,
		a->total_calls, (a->cpu.total / a->total_calls), a->cpu.max,
		(a->real.total / a->total_calls), a->real.max,
		a->total_cpu_warn, a->total_wall_warn, a->total_starv_warn);
	vty_out(vty, "  %c%c%c%c%c  %s\n",
		a->types & (1 << EVENT_READ) ? 'R' : ' ',
		a->types & (1 << EVENT_WRITE) ? 'W' : ' ',
		a->types & (1 << EVENT_TIMER) ? 'T' : ' ',
		a->types & (1 << EVENT_EVENT) ? 'E' : ' ',
		a->types & (1 << EVENT_EXECUTE) ? 'X' : ' ', a->funcname);
}

static void cpu_record_print_one(struct vty *vty, uint8_t filter,
				 struct cpu_event_history *totals,
				 const struct cpu_event_history *a)
{
	struct cpu_event_history copy;

	copy.total_active =
		atomic_load_explicit(&a->total_active, memory_order_seq_cst);
	copy.total_calls =
		atomic_load_explicit(&a->total_calls, memory_order_seq_cst);
	copy.total_cpu_warn =
		atomic_load_explicit(&a->total_cpu_warn, memory_order_seq_cst);
	copy.total_wall_warn =
		atomic_load_explicit(&a->total_wall_warn, memory_order_seq_cst);
	copy.total_starv_warn = atomic_load_explicit(&a->total_starv_warn,
						     memory_order_seq_cst);
	copy.cpu.total =
		atomic_load_explicit(&a->cpu.total, memory_order_seq_cst);
	copy.cpu.max = atomic_load_explicit(&a->cpu.max, memory_order_seq_cst);
	copy.real.total =
		atomic_load_explicit(&a->real.total, memory_order_seq_cst);
	copy.real.max =
		atomic_load_explicit(&a->real.max, memory_order_seq_cst);
	copy.types = atomic_load_explicit(&a->types, memory_order_seq_cst);
	copy.funcname = a->funcname;

	if (!(copy.types & filter))
		return;

	vty_out_cpu_event_history(vty, &copy);
	totals->total_active += copy.total_active;
	totals->total_calls += copy.total_calls;
	totals->total_cpu_warn += copy.total_cpu_warn;
	totals->total_wall_warn += copy.total_wall_warn;
	totals->total_starv_warn += copy.total_starv_warn;
	totals->real.total += copy.real.total;
	if (totals->real.max < copy.real.max)
		totals->real.max = copy.real.max;
	totals->cpu.total += copy.cpu.total;
	if (totals->cpu.max < copy.cpu.max)
		totals->cpu.max = copy.cpu.max;
}

static void cpu_record_print(struct vty *vty, uint8_t filter)
{
	struct cpu_event_history tmp;
	struct event_loop *m;
	struct listnode *ln;

	if (!cputime_enabled)
		vty_out(vty,
			"\n"
			"Collecting CPU time statistics is currently disabled.  Following statistics\n"
			"will be zero or may display data from when collection was enabled.  Use the\n"
			"  \"service cputime-stats\"  command to start collecting data.\n"
			"\nCounters and wallclock times are always maintained and should be accurate.\n");

	memset(&tmp, 0, sizeof(tmp));
	tmp.funcname = "TOTAL";
	tmp.types = filter;

	frr_with_mutex (&masters_mtx) {
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
			vty_out(vty, "%30s %18s %18s\n", "",
				"CPU (user+system):", "Real (wall-clock):");
			vty_out(vty,
				"Active   Runtime(ms)   Invoked Avg uSec Max uSecs");
			vty_out(vty, " Avg uSec Max uSecs");
			vty_out(vty,
				"  CPU_Warn Wall_Warn Starv_Warn   Type  Event\n");

			if (cpu_records_count(m->cpu_records)) {
				struct cpu_event_history *rec;

				frr_each (cpu_records, m->cpu_records, rec)
					cpu_record_print_one(vty, filter, &tmp,
							     rec);
			} else
				vty_out(vty, "No data to display yet.\n");

			vty_out(vty, "\n");
		}
	}

	vty_out(vty, "\n");
	vty_out(vty, "Total Event statistics\n");
	vty_out(vty, "-------------------------\n");
	vty_out(vty, "%30s %18s %18s\n", "",
		"CPU (user+system):", "Real (wall-clock):");
	vty_out(vty, "Active   Runtime(ms)   Invoked Avg uSec Max uSecs");
	vty_out(vty, " Avg uSec Max uSecs  CPU_Warn Wall_Warn Starv_Warn");
	vty_out(vty, "   Type  Event\n");

	if (tmp.total_calls > 0)
		vty_out_cpu_event_history(vty, &tmp);
}

static void cpu_record_clear(uint8_t filter)
{
	struct event_loop *m;
	struct listnode *ln;

	frr_with_mutex (&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, ln, m)) {
			frr_with_mutex (&m->mtx) {
				struct cpu_event_history *item;
				struct cpu_records_head old[1];

				cpu_records_init(old);
				cpu_records_swap_all(old, m->cpu_records);

				while ((item = cpu_records_pop(old))) {
					if (item->types & filter)
						cpu_records_free(&item);
					else
						cpu_records_add(m->cpu_records,
								item);
				}

				cpu_records_fini(old);
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
			filter |= (1 << EVENT_READ);
			break;
		case 'w':
		case 'W':
			filter |= (1 << EVENT_WRITE);
			break;
		case 't':
		case 'T':
			filter |= (1 << EVENT_TIMER);
			break;
		case 'e':
		case 'E':
			filter |= (1 << EVENT_EVENT);
			break;
		case 'x':
		case 'X':
			filter |= (1 << EVENT_EXECUTE);
			break;
		default:
			break;
		}
		++i;
	}
	return filter;
}

DEFUN_NOSH (show_event_cpu,
            show_event_cpu_cmd,
            "show event cpu [FILTER]",
            SHOW_STR
            "Event information\n"
            "Event CPU usage\n"
            "Display filter (rwtexb)\n")
{
	uint8_t filter = (uint8_t)-1U;
	int idx = 0;

	if (argv_find(argv, argc, "FILTER", &idx)) {
		filter = parse_filter(argv[idx]->arg);
		if (!filter) {
			vty_out(vty,
				"Invalid filter \"%s\" specified; must contain at leastone of 'RWTEXB'\n",
				argv[idx]->arg);
			return CMD_WARNING;
		}
	}

	cpu_record_print(vty, filter);
	return CMD_SUCCESS;
}

DEFPY (service_cputime_stats,
       service_cputime_stats_cmd,
       "[no] service cputime-stats",
       NO_STR
       "Set up miscellaneous service\n"
       "Collect CPU usage statistics\n")
{
	cputime_enabled = !no;
	return CMD_SUCCESS;
}

DEFPY (service_cputime_warning,
       service_cputime_warning_cmd,
       "[no] service cputime-warning ![(1-4294967295)]",
       NO_STR
       "Set up miscellaneous service\n"
       "Warn for tasks exceeding CPU usage threshold\n"
       "Warning threshold in milliseconds\n")
{
	if (no)
		cputime_threshold = 0;
	else
		cputime_threshold = cputime_warning * 1000;
	return CMD_SUCCESS;
}

DEFPY (service_walltime_warning,
       service_walltime_warning_cmd,
       "[no] service walltime-warning ![(1-4294967295)]",
       NO_STR
       "Set up miscellaneous service\n"
       "Warn for tasks exceeding total wallclock threshold\n"
       "Warning threshold in milliseconds\n")
{
	if (no)
		walltime_threshold = 0;
	else
		walltime_threshold = walltime_warning * 1000;
	return CMD_SUCCESS;
}

static void show_event_poll_helper(struct vty *vty, struct event_loop *m)
{
	const char *name = m->name ? m->name : "main";
	char underline[strlen(name) + 1];
	struct event *thread;
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
				vty_out(vty, "%s ", thread->xref->funcname);
		} else
			vty_out(vty, " ");

		if (m->handler.pfds[i].events & POLLOUT) {
			thread = m->write[m->handler.pfds[i].fd];

			if (!thread)
				vty_out(vty, "ERROR\n");
			else
				vty_out(vty, "%s\n", thread->xref->funcname);
		} else
			vty_out(vty, "\n");
	}
}

DEFUN_NOSH (show_event_poll,
            show_event_poll_cmd,
            "show event poll",
            SHOW_STR
            "Event information\n"
            "Event Poll Information\n")
{
	struct listnode *node;
	struct event_loop *m;

	frr_with_mutex (&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, node, m))
			show_event_poll_helper(vty, m);
	}

	return CMD_SUCCESS;
}

#if CONFDATE > 20241231
CPP_NOTICE("Remove `clear thread cpu` command")
#endif
DEFUN (clear_event_cpu,
       clear_event_cpu_cmd,
       "clear event cpu [FILTER]",
       "Clear stored data in all pthreads\n"
       "Event information\n"
       "Event CPU usage\n"
       "Display filter (rwtexb)\n")
{
	uint8_t filter = (uint8_t)-1U;
	int idx = 0;

	if (argv_find(argv, argc, "FILTER", &idx)) {
		filter = parse_filter(argv[idx]->arg);
		if (!filter) {
			vty_out(vty,
				"Invalid filter \"%s\" specified; must contain at leastone of 'RWTEXB'\n",
				argv[idx]->arg);
			return CMD_WARNING;
		}
	}

	cpu_record_clear(filter);
	return CMD_SUCCESS;
}

ALIAS (clear_event_cpu,
       clear_thread_cpu_cmd,
       "clear thread cpu [FILTER]",
       "Clear stored data in all pthreads\n"
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtexb)\n")

static void show_event_timers_helper(struct vty *vty, struct event_loop *m)
{
	const char *name = m->name ? m->name : "main";
	char underline[strlen(name) + 1];
	struct event *thread;

	memset(underline, '-', sizeof(underline));
	underline[sizeof(underline) - 1] = '\0';

	vty_out(vty, "\nShowing timers for %s\n", name);
	vty_out(vty, "-------------------%s\n", underline);

	frr_each (event_timer_list, &m->timer, thread) {
		vty_out(vty, "  %-50s%pTH\n", thread->hist->funcname, thread);
	}
}

DEFPY_NOSH (show_event_timers,
            show_event_timers_cmd,
            "show event timers",
            SHOW_STR
            "Event information\n"
            "Show all timers and how long they have in the system\n")
{
	struct listnode *node;
	struct event_loop *m;

	frr_with_mutex (&masters_mtx) {
		for (ALL_LIST_ELEMENTS_RO(masters, node, m))
			show_event_timers_helper(vty, m);
	}

	return CMD_SUCCESS;
}

void event_cmd_init(void)
{
	install_element(VIEW_NODE, &show_event_cpu_cmd);
	install_element(VIEW_NODE, &show_event_poll_cmd);
	install_element(ENABLE_NODE, &clear_thread_cpu_cmd);
	install_element(ENABLE_NODE, &clear_event_cpu_cmd);

	install_element(CONFIG_NODE, &service_cputime_stats_cmd);
	install_element(CONFIG_NODE, &service_cputime_warning_cmd);
	install_element(CONFIG_NODE, &service_walltime_warning_cmd);

	install_element(VIEW_NODE, &show_event_timers_cmd);
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

#define STUPIDLY_LARGE_FD_SIZE 100000
struct event_loop *event_master_create(const char *name)
{
	struct event_loop *rv;
	struct rlimit limit;

	pthread_once(&init_once, &initializer);

	rv = XCALLOC(MTYPE_EVENT_MASTER, sizeof(struct event_loop));

	/* Initialize master mutex */
	pthread_mutex_init(&rv->mtx, NULL);
	pthread_cond_init(&rv->cancel_cond, NULL);

	/* Set name */
	name = name ? name : "default";
	rv->name = XSTRDUP(MTYPE_EVENT_MASTER, name);

	/* Initialize I/O task data structures */

	/* Use configured limit if present, ulimit otherwise. */
	rv->fd_limit = frr_get_fd_limit();
	if (rv->fd_limit == 0) {
		getrlimit(RLIMIT_NOFILE, &limit);
		rv->fd_limit = (int)limit.rlim_cur;
	}

	if (rv->fd_limit > STUPIDLY_LARGE_FD_SIZE) {
		if (frr_is_daemon())
			zlog_warn("FD Limit set: %u is stupidly large.  Is this what you intended?  Consider using --limit-fds also limiting size to %u",
				  rv->fd_limit, STUPIDLY_LARGE_FD_SIZE);

		rv->fd_limit = STUPIDLY_LARGE_FD_SIZE;
	}

	rv->read = XCALLOC(MTYPE_EVENT_POLL,
			   sizeof(struct event *) * rv->fd_limit);

	rv->write = XCALLOC(MTYPE_EVENT_POLL,
			    sizeof(struct event *) * rv->fd_limit);

	char tmhashname[strlen(name) + 32];

	snprintf(tmhashname, sizeof(tmhashname), "%s - threadmaster event hash",
		 name);
	cpu_records_init(rv->cpu_records);

	event_list_init(&rv->event);
	event_list_init(&rv->ready);
	event_list_init(&rv->unuse);
	event_timer_list_init(&rv->timer);

	/* Initialize event_fetch() settings */
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
	rv->handler.pfds = XCALLOC(MTYPE_EVENT_MASTER,
				   sizeof(struct pollfd) * rv->handler.pfdsize);
	rv->handler.copy = XCALLOC(MTYPE_EVENT_MASTER,
				   sizeof(struct pollfd) * rv->handler.pfdsize);

	/* add to list of threadmasters */
	frr_with_mutex (&masters_mtx) {
		if (!masters)
			masters = list_new();

		listnode_add(masters, rv);
	}

	return rv;
}

void event_master_set_name(struct event_loop *master, const char *name)
{
	frr_with_mutex (&master->mtx) {
		XFREE(MTYPE_EVENT_MASTER, master->name);
		master->name = XSTRDUP(MTYPE_EVENT_MASTER, name);
	}
}

#define EVENT_UNUSED_DEPTH 10

/* Move thread to unuse list. */
static void thread_add_unuse(struct event_loop *m, struct event *thread)
{
	pthread_mutex_t mtxc = thread->mtx;

	assert(m != NULL && thread != NULL);

	thread->hist->total_active--;
	memset(thread, 0, sizeof(struct event));
	thread->type = EVENT_UNUSED;

	/* Restore the thread mutex context. */
	thread->mtx = mtxc;

	if (event_list_count(&m->unuse) < EVENT_UNUSED_DEPTH) {
		event_list_add_tail(&m->unuse, thread);
		return;
	}

	thread_free(m, thread);
}

/* Free all unused thread. */
static void thread_list_free(struct event_loop *m, struct event_list_head *list)
{
	struct event *t;

	while ((t = event_list_pop(list)))
		thread_free(m, t);
}

static void thread_array_free(struct event_loop *m, struct event **thread_array)
{
	struct event *t;
	int index;

	for (index = 0; index < m->fd_limit; ++index) {
		t = thread_array[index];
		if (t) {
			thread_array[index] = NULL;
			thread_free(m, t);
		}
	}
	XFREE(MTYPE_EVENT_POLL, thread_array);
}

/* Stop thread scheduler. */
void event_master_free(struct event_loop *m)
{
	struct cpu_event_history *record;
	struct event *t;

	frr_with_mutex (&masters_mtx) {
		listnode_delete(masters, m);
		if (masters->count == 0)
			list_delete(&masters);
	}

	thread_array_free(m, m->read);
	thread_array_free(m, m->write);
	while ((t = event_timer_list_pop(&m->timer)))
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

	while ((record = cpu_records_pop(m->cpu_records)))
		cpu_records_free(&record);
	cpu_records_fini(m->cpu_records);

	XFREE(MTYPE_EVENT_MASTER, m->name);
	XFREE(MTYPE_EVENT_MASTER, m->handler.pfds);
	XFREE(MTYPE_EVENT_MASTER, m->handler.copy);
	XFREE(MTYPE_EVENT_MASTER, m);
}

/* Return remain time in milliseconds. */
unsigned long event_timer_remain_msec(struct event *thread)
{
	int64_t remain;

	if (!event_is_scheduled(thread))
		return 0;

	frr_with_mutex (&thread->mtx) {
		remain = monotime_until(&thread->u.sands, NULL) / 1000LL;
	}

	return remain < 0 ? 0 : remain;
}

/* Return remain time in seconds. */
unsigned long event_timer_remain_second(struct event *thread)
{
	return event_timer_remain_msec(thread) / 1000LL;
}

struct timeval event_timer_remain(struct event *thread)
{
	struct timeval remain;

	frr_with_mutex (&thread->mtx) {
		monotime_until(&thread->u.sands, &remain);
	}
	return remain;
}

static int time_hhmmss(char *buf, int buf_size, long sec)
{
	long hh;
	long mm;
	int wr;

	assert(buf_size >= 8);

	hh = sec / 3600;
	sec %= 3600;
	mm = sec / 60;
	sec %= 60;

	wr = snprintf(buf, buf_size, "%02ld:%02ld:%02ld", hh, mm, sec);

	return wr != 8;
}

char *event_timer_to_hhmmss(char *buf, int buf_size, struct event *t_timer)
{
	if (t_timer)
		time_hhmmss(buf, buf_size, event_timer_remain_second(t_timer));
	else
		snprintf(buf, buf_size, "--:--:--");

	return buf;
}

/* Get new thread.  */
static struct event *thread_get(struct event_loop *m, uint8_t type,
				void (*func)(struct event *), void *arg,
				const struct xref_eventsched *xref)
{
	struct event *thread = event_list_pop(&m->unuse);

	if (!thread) {
		thread = XCALLOC(MTYPE_THREAD, sizeof(struct event));
		/* mutex only needs to be initialized at struct creation. */
		pthread_mutex_init(&thread->mtx, NULL);
	}

	thread->type = type;
	thread->add_type = type;
	thread->master = m;
	thread->arg = arg;
	thread->yield = EVENT_YIELD_TIME_SLOT; /* default */
	/* thread->ref is zeroed either by XCALLOC above or by memset before
	 * being put on the "unuse" list by thread_add_unuse().
	 * Setting it here again makes coverity complain about a missing
	 * lock :(
	 */
	/* thread->ref = NULL; */
	thread->ignore_timer_late = false;

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
	if ((thread->xref && thread->xref->funcname != xref->funcname)
	    || thread->func != func)
		thread->hist = cpu_records_get(m, func, xref->funcname);

	thread->hist->total_active++;
	thread->func = func;
	thread->xref = xref;

	return thread;
}

static void thread_free(struct event_loop *master, struct event *thread)
{
	/* Free allocated resources. */
	pthread_mutex_destroy(&thread->mtx);
	XFREE(MTYPE_THREAD, thread);
}

static int fd_poll(struct event_loop *m, const struct timeval *timer_wait,
		   bool *eintr_p)
{
	sigset_t origsigs;
	unsigned char trash[64];
	nfds_t count = m->handler.copycount;

	/*
	 * If timer_wait is null here, that means poll() should block
	 * indefinitely, unless the event_master has overridden it by setting
	 * ->selectpoll_timeout.
	 *
	 * If the value is positive, it specifies the maximum number of
	 * milliseconds to wait. If the timeout is -1, it specifies that
	 * we should never wait and always return immediately even if no
	 * event is detected. If the value is zero, the behavior is default.
	 */
	int timeout = -1;

	/* number of file descriptors with events */
	int num;

	if (timer_wait != NULL && m->selectpoll_timeout == 0) {
		/* use the default value */
		timeout = (timer_wait->tv_sec * 1000)
			  + (timer_wait->tv_usec / 1000);
	} else if (m->selectpoll_timeout > 0) {
		/* use the user's timeout */
		timeout = m->selectpoll_timeout;
	} else if (m->selectpoll_timeout < 0) {
		/* effect a poll (return immediately) */
		timeout = 0;
	}

	zlog_tls_buffer_flush();
	rcu_read_unlock();
	rcu_assert_read_unlocked();

	/* add poll pipe poker */
	assert(count + 1 < m->handler.pfdsize);
	m->handler.copy[count].fd = m->io_pipe[0];
	m->handler.copy[count].events = POLLIN;
	m->handler.copy[count].revents = 0x00;

	/* We need to deal with a signal-handling race here: we
	 * don't want to miss a crucial signal, such as SIGTERM or SIGINT,
	 * that may arrive just before we enter poll(). We will block the
	 * key signals, then check whether any have arrived - if so, we return
	 * before calling poll(). If not, we'll re-enable the signals
	 * in the ppoll() call.
	 */

	sigemptyset(&origsigs);
	if (m->handle_signals) {
		/* Main pthread that handles the app signals */
		if (frr_sigevent_check(&origsigs)) {
			/* Signal to process - restore signal mask and return */
			pthread_sigmask(SIG_SETMASK, &origsigs, NULL);
			num = -1;
			*eintr_p = true;
			goto done;
		}
	} else {
		/* Don't make any changes for the non-main pthreads */
		pthread_sigmask(SIG_SETMASK, NULL, &origsigs);
	}

#if defined(HAVE_PPOLL)
	struct timespec ts, *tsp;

	if (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	} else
		tsp = NULL;

	num = ppoll(m->handler.copy, count + 1, tsp, &origsigs);
	pthread_sigmask(SIG_SETMASK, &origsigs, NULL);
#else
	/* Not ideal - there is a race after we restore the signal mask */
	pthread_sigmask(SIG_SETMASK, &origsigs, NULL);
	num = poll(m->handler.copy, count + 1, timeout);
#endif

done:

	if (num < 0 && errno == EINTR)
		*eintr_p = true;

	if (num > 0 && m->handler.copy[count].revents != 0 && num--)
		while (read(m->io_pipe[0], &trash, sizeof(trash)) > 0)
			;

	rcu_read_lock();

	return num;
}

/* Add new read thread. */
void _event_add_read_write(const struct xref_eventsched *xref,
			   struct event_loop *m, void (*func)(struct event *),
			   void *arg, int fd, struct event **t_ptr)
{
	int dir = xref->event_type;
	struct event *thread = NULL;
	struct event **thread_array;

	if (dir == EVENT_READ)
		frrtrace(9, frr_libfrr, schedule_read, m,
			 xref->funcname, xref->xref.file, xref->xref.line,
			 t_ptr, fd, 0, arg, 0);
	else
		frrtrace(9, frr_libfrr, schedule_write, m,
			 xref->funcname, xref->xref.file, xref->xref.line,
			 t_ptr, fd, 0, arg, 0);

	assert(fd >= 0);
	if (fd >= m->fd_limit)
		assert(!"Number of FD's open is greater than FRR currently configured to handle, aborting");

	frr_with_mutex (&m->mtx) {
		/* Thread is already scheduled; don't reschedule */
		if (t_ptr && *t_ptr)
			break;

		/* default to a new pollfd */
		nfds_t queuepos = m->handler.pfdcount;

		if (dir == EVENT_READ)
			thread_array = m->read;
		else
			thread_array = m->write;

		/*
		 * if we already have a pollfd for our file descriptor, find and
		 * use it
		 */
		for (nfds_t i = 0; i < m->handler.pfdcount; i++) {
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
			/*
			 * We are setting the fd = -1 for the
			 * case when a read/write event is going
			 * away.  if we find a -1 we can stuff it
			 * into that spot, so note it
			 */
			if (m->handler.pfds[i].fd == -1 && queuepos == m->handler.pfdcount)
				queuepos = i;
		}

		/* make sure we have room for this fd + pipe poker fd */
		assert(queuepos + 1 < m->handler.pfdsize);

		thread = thread_get(m, dir, func, arg, xref);

		m->handler.pfds[queuepos].fd = fd;
		m->handler.pfds[queuepos].events |=
			(dir == EVENT_READ ? POLLIN : POLLOUT);

		if (queuepos == m->handler.pfdcount)
			m->handler.pfdcount++;

		if (thread) {
			frr_with_mutex (&thread->mtx) {
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
}

static void _event_add_timer_timeval(const struct xref_eventsched *xref,
				     struct event_loop *m,
				     void (*func)(struct event *), void *arg,
				     struct timeval *time_relative,
				     struct event **t_ptr)
{
	struct event *thread;
	struct timeval t;

	assert(m != NULL);

	assert(time_relative);

	frrtrace(9, frr_libfrr, schedule_timer, m,
		 xref->funcname, xref->xref.file, xref->xref.line,
		 t_ptr, 0, 0, arg, (long)time_relative->tv_sec);

	/* Compute expiration/deadline time. */
	monotime(&t);
	timeradd(&t, time_relative, &t);

	frr_with_mutex (&m->mtx) {
		if (t_ptr && *t_ptr)
			/* thread is already scheduled; don't reschedule */
			return;

		thread = thread_get(m, EVENT_TIMER, func, arg, xref);

		frr_with_mutex (&thread->mtx) {
			thread->u.sands = t;
			event_timer_list_add(&m->timer, thread);
			if (t_ptr) {
				*t_ptr = thread;
				thread->ref = t_ptr;
			}
		}

		/* The timer list is sorted - if this new timer
		 * might change the time we'll wait for, give the pthread
		 * a chance to re-compute.
		 */
		if (event_timer_list_first(&m->timer) == thread)
			AWAKEN(m);
	}
#define ONEYEAR2SEC (60 * 60 * 24 * 365)
	if (time_relative->tv_sec > ONEYEAR2SEC)
		flog_err(
			EC_LIB_TIMER_TOO_LONG,
			"Timer: %pTHD is created with an expiration that is greater than 1 year",
			thread);
}


/* Add timer event thread. */
void _event_add_timer(const struct xref_eventsched *xref, struct event_loop *m,
		      void (*func)(struct event *), void *arg, long timer,
		      struct event **t_ptr)
{
	struct timeval trel;

	assert(m != NULL);

	trel.tv_sec = timer;
	trel.tv_usec = 0;

	_event_add_timer_timeval(xref, m, func, arg, &trel, t_ptr);
}

/* Add timer event thread with "millisecond" resolution */
void _event_add_timer_msec(const struct xref_eventsched *xref,
			   struct event_loop *m, void (*func)(struct event *),
			   void *arg, long timer, struct event **t_ptr)
{
	struct timeval trel;

	assert(m != NULL);

	trel.tv_sec = timer / 1000;
	trel.tv_usec = 1000 * (timer % 1000);

	_event_add_timer_timeval(xref, m, func, arg, &trel, t_ptr);
}

/* Add timer event thread with "timeval" resolution */
void _event_add_timer_tv(const struct xref_eventsched *xref,
			 struct event_loop *m, void (*func)(struct event *),
			 void *arg, struct timeval *tv, struct event **t_ptr)
{
	_event_add_timer_timeval(xref, m, func, arg, tv, t_ptr);
}

/* Add simple event thread. */
void _event_add_event(const struct xref_eventsched *xref, struct event_loop *m,
		      void (*func)(struct event *), void *arg, int val,
		      struct event **t_ptr)
{
	struct event *thread = NULL;

	frrtrace(9, frr_libfrr, schedule_event, m,
		 xref->funcname, xref->xref.file, xref->xref.line,
		 t_ptr, 0, val, arg, 0);

	assert(m != NULL);

	frr_with_mutex (&m->mtx) {
		if (t_ptr && *t_ptr)
			/* thread is already scheduled; don't reschedule */
			break;

		thread = thread_get(m, EVENT_EVENT, func, arg, xref);
		frr_with_mutex (&thread->mtx) {
			thread->u.val = val;
			event_list_add_tail(&m->event, thread);
		}

		if (t_ptr) {
			*t_ptr = thread;
			thread->ref = t_ptr;
		}

		AWAKEN(m);
	}
}

/* Thread cancellation ------------------------------------------------------ */

/**
 * NOT's out the .events field of pollfd corresponding to the given file
 * descriptor. The event to be NOT'd is passed in the 'state' parameter.
 *
 * This needs to happen for both copies of pollfd's. See 'event_fetch'
 * implementation for details.
 *
 * @param master
 * @param fd
 * @param state the event to cancel. One or more (OR'd together) of the
 * following:
 *   - POLLIN
 *   - POLLOUT
 */
static void event_cancel_rw(struct event_loop *master, int fd, short state,
			    int idx_hint)
{
	bool found = false;

	/* find the index of corresponding pollfd */
	nfds_t i;

	/* Cancel POLLHUP too just in case some bozo set it */
	state |= POLLHUP;

	/* Some callers know the index of the pfd already */
	if (idx_hint >= 0) {
		i = idx_hint;
		found = true;
	} else {
		/* Have to look for the fd in the pfd array */
		for (i = 0; i < master->handler.pfdcount; i++)
			if (master->handler.pfds[i].fd == fd) {
				found = true;
				break;
			}
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

	/*
	 * If we have the same pollfd in the copy, perform the same operations,
	 * otherwise return.
	 */
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

/*
 * Process task cancellation given a task argument: iterate through the
 * various lists of tasks, looking for any that match the argument.
 */
static void cancel_arg_helper(struct event_loop *master,
			      const struct cancel_req *cr)
{
	struct event *t;
	nfds_t i;
	int fd;
	struct pollfd *pfd;

	/* We're only processing arg-based cancellations here. */
	if (cr->eventobj == NULL)
		return;

	/* First process the ready lists. */
	frr_each_safe (event_list, &master->event, t) {
		if (t->arg != cr->eventobj)
			continue;
		event_list_del(&master->event, t);
		if (t->ref)
			*t->ref = NULL;
		thread_add_unuse(master, t);
	}

	frr_each_safe (event_list, &master->ready, t) {
		if (t->arg != cr->eventobj)
			continue;
		event_list_del(&master->ready, t);
		if (t->ref)
			*t->ref = NULL;
		thread_add_unuse(master, t);
	}

	/* If requested, stop here and ignore io and timers */
	if (CHECK_FLAG(cr->flags, EVENT_CANCEL_FLAG_READY))
		return;

	/* Check the io tasks */
	for (i = 0; i < master->handler.pfdcount;) {
		pfd = master->handler.pfds + i;

		/*
		 * Skip this spot, nothing here to see
		 */
		if (pfd->fd == -1) {
			i++;
			continue;
		}

		if (pfd->events & POLLIN)
			t = master->read[pfd->fd];
		else
			t = master->write[pfd->fd];

		if (t && t->arg == cr->eventobj) {
			fd = pfd->fd;

			/* Found a match to cancel: clean up fd arrays */
			event_cancel_rw(master, pfd->fd, pfd->events, i);

			/* Clean up thread arrays */
			master->read[fd] = NULL;
			master->write[fd] = NULL;

			/* Clear caller's ref */
			if (t->ref)
				*t->ref = NULL;

			thread_add_unuse(master, t);

			/* Don't increment 'i' since the cancellation will have
			 * removed the entry from the pfd array
			 */
		} else
			i++;
	}

	/* Check the timer tasks */
	t = event_timer_list_first(&master->timer);
	while (t) {
		struct event *t_next;

		t_next = event_timer_list_next(&master->timer, t);

		if (t->arg == cr->eventobj) {
			event_timer_list_del(&master->timer, t);
			if (t->ref)
				*t->ref = NULL;
			thread_add_unuse(master, t);
		}

		t = t_next;
	}
}

/**
 * Process cancellation requests.
 *
 * This may only be run from the pthread which owns the event_master.
 *
 * @param master the thread master to process
 * @REQUIRE master->mtx
 */
static void do_event_cancel(struct event_loop *master)
{
	struct event_list_head *list = NULL;
	struct event **thread_array = NULL;
	struct event *thread;
	struct cancel_req *cr;
	struct listnode *ln;

	for (ALL_LIST_ELEMENTS_RO(master->cancel_req, ln, cr)) {
		/*
		 * If this is an event object cancellation, search
		 * through task lists deleting any tasks which have the
		 * specified argument - use this handy helper function.
		 */
		if (cr->eventobj) {
			cancel_arg_helper(master, cr);
			continue;
		}

		/*
		 * The pointer varies depending on whether the cancellation
		 * request was made asynchronously or not. If it was, we
		 * need to check whether the thread even exists anymore
		 * before cancelling it.
		 */
		thread = (cr->thread) ? cr->thread : *cr->threadref;

		if (!thread)
			continue;

		list = NULL;
		thread_array = NULL;

		/* Determine the appropriate queue to cancel the thread from */
		switch (thread->type) {
		case EVENT_READ:
			event_cancel_rw(master, thread->u.fd, POLLIN, -1);
			thread_array = master->read;
			break;
		case EVENT_WRITE:
			event_cancel_rw(master, thread->u.fd, POLLOUT, -1);
			thread_array = master->write;
			break;
		case EVENT_TIMER:
			event_timer_list_del(&master->timer, thread);
			break;
		case EVENT_EVENT:
			list = &master->event;
			break;
		case EVENT_READY:
			list = &master->ready;
			break;
		case EVENT_UNUSED:
		case EVENT_EXECUTE:
			continue;
			break;
		}

		if (list)
			event_list_del(list, thread);
		else if (thread_array)
			thread_array[thread->u.fd] = NULL;

		if (thread->ref)
			*thread->ref = NULL;

		thread_add_unuse(thread->master, thread);
	}

	/* Delete and free all cancellation requests */
	if (master->cancel_req)
		list_delete_all_node(master->cancel_req);

	/* Wake up any threads which may be blocked in event_cancel_async() */
	master->canceled = true;
	pthread_cond_broadcast(&master->cancel_cond);
}

/*
 * Helper function used for multiple flavors of arg-based cancellation.
 */
static void cancel_event_helper(struct event_loop *m, void *arg, int flags)
{
	struct cancel_req *cr;

	assert(m->owner == pthread_self());

	/* Only worth anything if caller supplies an arg. */
	if (arg == NULL)
		return;

	cr = XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));

	cr->flags = flags;

	frr_with_mutex (&m->mtx) {
		cr->eventobj = arg;
		listnode_add(m->cancel_req, cr);
		do_event_cancel(m);
	}
}

/**
 * Cancel any events which have the specified argument.
 *
 * MT-Unsafe
 *
 * @param m the event_master to cancel from
 * @param arg the argument passed when creating the event
 */
void event_cancel_event(struct event_loop *master, void *arg)
{
	cancel_event_helper(master, arg, 0);
}

/*
 * Cancel ready tasks with an arg matching 'arg'
 *
 * MT-Unsafe
 *
 * @param m the event_master to cancel from
 * @param arg the argument passed when creating the event
 */
void event_cancel_event_ready(struct event_loop *m, void *arg)
{

	/* Only cancel ready/event tasks */
	cancel_event_helper(m, arg, EVENT_CANCEL_FLAG_READY);
}

/**
 * Cancel a specific task.
 *
 * MT-Unsafe
 *
 * @param thread task to cancel
 */
void event_cancel(struct event **thread)
{
	struct event_loop *master;

	if (thread == NULL || *thread == NULL)
		return;

	master = (*thread)->master;

	frrtrace(9, frr_libfrr, event_cancel, master, (*thread)->xref->funcname,
		 (*thread)->xref->xref.file, (*thread)->xref->xref.line, NULL,
		 (*thread)->u.fd, (*thread)->u.val, (*thread)->arg,
		 (*thread)->u.sands.tv_sec);

	assert(master->owner == pthread_self());

	frr_with_mutex (&master->mtx) {
		struct cancel_req *cr =
			XCALLOC(MTYPE_TMP, sizeof(struct cancel_req));
		cr->thread = *thread;
		listnode_add(master->cancel_req, cr);
		do_event_cancel(master);

		*thread = NULL;
	}
}

/**
 * Asynchronous cancellation.
 *
 * Called with either a struct event ** or void * to an event argument,
 * this function posts the correct cancellation request and blocks until it is
 * serviced.
 *
 * If the thread is currently running, execution blocks until it completes.
 *
 * The last two parameters are mutually exclusive, i.e. if you pass one the
 * other must be NULL.
 *
 * When the cancellation procedure executes on the target event_master, the
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
void event_cancel_async(struct event_loop *master, struct event **thread,
			void *eventobj)
{
	assert(!(thread && eventobj) && (thread || eventobj));

	if (thread && *thread)
		frrtrace(9, frr_libfrr, event_cancel_async, master,
			 (*thread)->xref->funcname, (*thread)->xref->xref.file,
			 (*thread)->xref->xref.line, NULL, (*thread)->u.fd,
			 (*thread)->u.val, (*thread)->arg,
			 (*thread)->u.sands.tv_sec);
	else
		frrtrace(9, frr_libfrr, event_cancel_async, master, NULL, NULL,
			 0, NULL, 0, 0, eventobj, 0);

	assert(master->owner != pthread_self());

	frr_with_mutex (&master->mtx) {
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

	if (thread)
		*thread = NULL;
}
/* ------------------------------------------------------------------------- */

static struct timeval *thread_timer_wait(struct event_timer_list_head *timers,
					 struct timeval *timer_val)
{
	if (!event_timer_list_count(timers))
		return NULL;

	struct event *next_timer = event_timer_list_first(timers);

	monotime_until(&next_timer->u.sands, timer_val);
	return timer_val;
}

static struct event *thread_run(struct event_loop *m, struct event *thread,
				struct event *fetch)
{
	*fetch = *thread;
	thread_add_unuse(m, thread);
	return fetch;
}

static int thread_process_io_helper(struct event_loop *m, struct event *thread,
				    short state, short actual_state, int pos)
{
	struct event **thread_array;

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
	/*
	 * ppoll man page says that a fd of -1 causes the particular
	 * array item to be skipped.  So let's skip it
	 */
	if (m->handler.pfds[pos].events == 0)
		m->handler.pfds[pos].fd = -1;

	if (!thread) {
		if ((actual_state & (POLLHUP|POLLIN)) != POLLHUP)
			flog_err(EC_LIB_NO_THREAD,
				 "Attempting to process an I/O event but for fd: %d(%d) no thread to handle this!",
				 m->handler.pfds[pos].fd, actual_state);
		return 0;
	}

	if (thread->type == EVENT_READ)
		thread_array = m->read;
	else
		thread_array = m->write;

	thread_array[thread->u.fd] = NULL;
	event_list_add_tail(&m->ready, thread);
	thread->type = EVENT_READY;

	return 1;
}

static inline void thread_process_io_inner_loop(struct event_loop *m,
						unsigned int num,
						struct pollfd *pfds, nfds_t *i,
						uint32_t *ready)
{
	/* no event for current fd? immediately continue */
	if (pfds[*i].revents == 0)
		return;

	*ready = *ready + 1;

	/*
	 * Unless someone has called event_cancel from another
	 * pthread, the only thing that could have changed in
	 * m->handler.pfds while we were asleep is the .events
	 * field in a given pollfd. Barring event_cancel() that
	 * value should be a superset of the values we have in our
	 * copy, so there's no need to update it. Similarily,
	 * barring deletion, the fd should still be a valid index
	 * into the master's pfds.
	 *
	 * We are including POLLERR here to do a READ event
	 * this is because the read should fail and the
	 * read function should handle it appropriately
	 */
	if (pfds[*i].revents & (POLLIN | POLLHUP | POLLERR)) {
		thread_process_io_helper(m, m->read[pfds[*i].fd], POLLIN,
					 pfds[*i].revents, *i);
	}
	if (pfds[*i].revents & POLLOUT)
		thread_process_io_helper(m, m->write[pfds[*i].fd], POLLOUT,
					 pfds[*i].revents, *i);

	/*
	 * if one of our file descriptors is garbage, remove the same
	 * from both pfds + update sizes and index
	 */
	if (pfds[*i].revents & POLLNVAL) {
		memmove(m->handler.pfds + *i, m->handler.pfds + *i + 1,
			(m->handler.pfdcount - *i - 1) * sizeof(struct pollfd));
		m->handler.pfdcount--;
		m->handler.pfds[m->handler.pfdcount].fd = 0;
		m->handler.pfds[m->handler.pfdcount].events = 0;

		memmove(pfds + *i, pfds + *i + 1,
			(m->handler.copycount - *i - 1) * sizeof(struct pollfd));
		m->handler.copycount--;
		m->handler.copy[m->handler.copycount].fd = 0;
		m->handler.copy[m->handler.copycount].events = 0;

		*i = *i - 1;
	}
}

/**
 * Process I/O events.
 *
 * Walks through file descriptor array looking for those pollfds whose .revents
 * field has something interesting. Deletes any invalid file descriptors.
 *
 * Try to impart some impartiality to handling of io.  The event
 * system will cycle through the fd's available for io
 * giving each one a chance to go first.
 *
 * @param m the thread master
 * @param num the number of active file descriptors (return value of poll())
 */
static void thread_process_io(struct event_loop *m, unsigned int num)
{
	unsigned int ready = 0;
	struct pollfd *pfds = m->handler.copy;
	nfds_t i, last_read = m->last_read % m->handler.copycount;

	for (i = last_read; i < m->handler.copycount && ready < num; ++i)
		thread_process_io_inner_loop(m, num, pfds, &i, &ready);

	for (i = 0; i < last_read && ready < num; ++i)
		thread_process_io_inner_loop(m, num, pfds, &i, &ready);

	m->last_read++;
}

/* Add all timers that have popped to the ready list. */
static unsigned int thread_process_timers(struct event_loop *m,
					  struct timeval *timenow)
{
	struct timeval prev = *timenow;
	bool displayed = false;
	struct event *thread;
	unsigned int ready = 0;

	while ((thread = event_timer_list_first(&m->timer))) {
		if (timercmp(timenow, &thread->u.sands, <))
			break;
		prev = thread->u.sands;
		prev.tv_sec += 4;
		/*
		 * If the timer would have popped 4 seconds in the
		 * past then we are in a situation where we are
		 * really getting behind on handling of events.
		 * Let's log it and do the right thing with it.
		 */
		if (timercmp(timenow, &prev, >)) {
			atomic_fetch_add_explicit(
				&thread->hist->total_starv_warn, 1,
				memory_order_seq_cst);
			if (!displayed && !thread->ignore_timer_late) {
				flog_warn(
					EC_LIB_STARVE_THREAD,
					"Thread Starvation: %pTHD was scheduled to pop greater than 4s ago",
					thread);
				displayed = true;
			}
		}

		event_timer_list_pop(&m->timer);
		thread->type = EVENT_READY;
		event_list_add_tail(&m->ready, thread);
		ready++;
	}

	return ready;
}

/* process a list en masse, e.g. for event thread lists */
static unsigned int thread_process(struct event_list_head *list)
{
	struct event *thread;
	unsigned int ready = 0;

	while ((thread = event_list_pop(list))) {
		thread->type = EVENT_READY;
		event_list_add_tail(&thread->master->ready, thread);
		ready++;
	}
	return ready;
}


/* Fetch next ready thread. */
struct event *event_fetch(struct event_loop *m, struct event *fetch)
{
	struct event *thread = NULL;
	struct timeval now;
	struct timeval zerotime = {0, 0};
	struct timeval tv;
	struct timeval *tw = NULL;
	bool eintr_p = false;
	int num = 0;

	do {
		/* Handle signals if any */
		if (m->handle_signals)
			frr_sigevent_process();

		pthread_mutex_lock(&m->mtx);

		/* Process any pending cancellation requests */
		do_event_cancel(m);

		/*
		 * Attempt to flush ready queue before going into poll().
		 * This is performance-critical. Think twice before modifying.
		 */
		if ((thread = event_list_pop(&m->ready))) {
			fetch = thread_run(m, thread, fetch);
			if (fetch->ref)
				*fetch->ref = NULL;
			pthread_mutex_unlock(&m->mtx);
			if (!m->ready_run_loop)
				GETRUSAGE(&m->last_getrusage);
			m->ready_run_loop = true;
			break;
		}

		m->ready_run_loop = false;
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
		 * pending, set the timeout to the smallest remaining time on
		 * any timer.
		 * - If there are neither timers nor events pending, but there
		 * are file descriptors pending, block indefinitely in poll()
		 * - If nothing is pending, it's time for the application to die
		 *
		 * In every case except the last, we need to hit poll() at least
		 * once per loop to avoid starvation by events
		 */
		if (!event_list_count(&m->ready))
			tw = thread_timer_wait(&m->timer, &tv);

		if (event_list_count(&m->ready) ||
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
			eintr_p = false;
			num = fd_poll(m, tw, &eintr_p);
		}
		pthread_mutex_lock(&m->mtx);

		/* Handle any errors received in poll() */
		if (num < 0) {
			if (eintr_p) {
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
		thread_process_timers(m, &now);

		/* Post I/O to ready queue. */
		if (num > 0)
			thread_process_io(m, num);

		pthread_mutex_unlock(&m->mtx);

	} while (!thread && m->spin);

	return fetch;
}

unsigned long event_consumed_time(RUSAGE_T *now, RUSAGE_T *start,
				  unsigned long *cputime)
{
#ifdef HAVE_CLOCK_THREAD_CPUTIME_ID

#ifdef __FreeBSD__
	/*
	 * FreeBSD appears to have an issue when calling clock_gettime
	 * with CLOCK_THREAD_CPUTIME_ID really close to each other
	 * occassionally the now time will be before the start time.
	 * This is not good and FRR is ending up with CPU HOG's
	 * when the subtraction wraps to very large numbers
	 *
	 * What we are going to do here is cheat a little bit
	 * and notice that this is a problem and just correct
	 * it so that it is impossible to happen
	 */
	if (start->cpu.tv_sec == now->cpu.tv_sec &&
	    start->cpu.tv_nsec > now->cpu.tv_nsec)
		now->cpu.tv_nsec = start->cpu.tv_nsec + 1;
	else if (start->cpu.tv_sec > now->cpu.tv_sec) {
		now->cpu.tv_sec = start->cpu.tv_sec;
		now->cpu.tv_nsec = start->cpu.tv_nsec + 1;
	}
#endif
	*cputime = (now->cpu.tv_sec - start->cpu.tv_sec) * TIMER_SECOND_MICRO
		   + (now->cpu.tv_nsec - start->cpu.tv_nsec) / 1000;
#else
	/* This is 'user + sys' time.  */
	*cputime = timeval_elapsed(now->cpu.ru_utime, start->cpu.ru_utime)
		   + timeval_elapsed(now->cpu.ru_stime, start->cpu.ru_stime);
#endif
	return timeval_elapsed(now->real, start->real);
}

/*
 * We should aim to yield after yield milliseconds, which defaults
 * to EVENT_YIELD_TIME_SLOT .
 * Note: we are using real (wall clock) time for this calculation.
 * It could be argued that CPU time may make more sense in certain
 * contexts.  The things to consider are whether the thread may have
 * blocked (in which case wall time increases, but CPU time does not),
 * or whether the system is heavily loaded with other processes competing
 * for CPU time.  On balance, wall clock time seems to make sense.
 * Plus it has the added benefit that gettimeofday should be faster
 * than calling getrusage.
 */
int event_should_yield(struct event *thread)
{
	int result;

	frr_with_mutex (&thread->mtx) {
		result = monotime_since(&thread->real, NULL)
			 > (int64_t)thread->yield;
	}
	return result;
}

void event_set_yield_time(struct event *thread, unsigned long yield_time)
{
	frr_with_mutex (&thread->mtx) {
		thread->yield = yield_time;
	}
}

void event_getrusage(RUSAGE_T *r)
{
	monotime(&r->real);
	if (!cputime_enabled) {
		memset(&r->cpu, 0, sizeof(r->cpu));
		return;
	}

#ifdef HAVE_CLOCK_THREAD_CPUTIME_ID
	/* not currently implemented in Linux's vDSO, but maybe at some point
	 * in the future?
	 */
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &r->cpu);
#else /* !HAVE_CLOCK_THREAD_CPUTIME_ID */
#if defined RUSAGE_THREAD
#define FRR_RUSAGE RUSAGE_THREAD
#else
#define FRR_RUSAGE RUSAGE_SELF
#endif
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
void event_call(struct event *thread)
{
	RUSAGE_T before, after;
	bool suppress_warnings = EVENT_ARG(thread);

	/* if the thread being called is the CLI, it may change cputime_enabled
	 * ("service cputime-stats" command), which can result in nonsensical
	 * and very confusing warnings
	 */
	bool cputime_enabled_here = cputime_enabled;

	if (thread->master->ready_run_loop)
		before = thread->master->last_getrusage;
	else
		GETRUSAGE(&before);

	thread->real = before.real;

	frrtrace(9, frr_libfrr, event_call, thread->master,
		 thread->xref->funcname, thread->xref->xref.file,
		 thread->xref->xref.line, NULL, thread->u.fd, thread->u.val,
		 thread->arg, thread->u.sands.tv_sec);

	pthread_setspecific(thread_current, thread);
	(*thread->func)(thread);
	pthread_setspecific(thread_current, NULL);

	GETRUSAGE(&after);
	thread->master->last_getrusage = after;

	unsigned long walltime, cputime;
	unsigned long exp;

	walltime = event_consumed_time(&after, &before, &cputime);

	/* update walltime */
	atomic_fetch_add_explicit(&thread->hist->real.total, walltime,
				  memory_order_seq_cst);
	exp = atomic_load_explicit(&thread->hist->real.max,
				   memory_order_seq_cst);
	while (exp < walltime
	       && !atomic_compare_exchange_weak_explicit(
		       &thread->hist->real.max, &exp, walltime,
		       memory_order_seq_cst, memory_order_seq_cst))
		;

	if (cputime_enabled_here && cputime_enabled) {
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
	}

	atomic_fetch_add_explicit(&thread->hist->total_calls, 1,
				  memory_order_seq_cst);
	atomic_fetch_or_explicit(&thread->hist->types, 1 << thread->add_type,
				 memory_order_seq_cst);

	if (suppress_warnings)
		return;

	if (cputime_enabled_here && cputime_enabled && cputime_threshold
	    && cputime > cputime_threshold) {
		/*
		 * We have a CPU Hog on our hands.  The time FRR has spent
		 * doing actual work (not sleeping) is greater than 5 seconds.
		 * Whinge about it now, so we're aware this is yet another task
		 * to fix.
		 */
		atomic_fetch_add_explicit(&thread->hist->total_cpu_warn,
					  1, memory_order_seq_cst);
		flog_warn(
			EC_LIB_SLOW_THREAD_CPU,
			"CPU HOG: task %s (%lx) ran for %lums (cpu time %lums)",
			thread->xref->funcname, (unsigned long)thread->func,
			walltime / 1000, cputime / 1000);

	} else if (walltime_threshold && walltime > walltime_threshold) {
		/*
		 * The runtime for a task is greater than 5 seconds, but the
		 * cpu time is under 5 seconds.  Let's whine about this because
		 * this could imply some sort of scheduling issue.
		 */
		atomic_fetch_add_explicit(&thread->hist->total_wall_warn,
					  1, memory_order_seq_cst);
		flog_warn(
			EC_LIB_SLOW_THREAD_WALL,
			"STARVATION: task %s (%lx) ran for %lums (cpu time %lums)",
			thread->xref->funcname, (unsigned long)thread->func,
			walltime / 1000, cputime / 1000);
	}
}

/* Execute thread */
void _event_execute(const struct xref_eventsched *xref, struct event_loop *m,
		    void (*func)(struct event *), void *arg, int val,
		    struct event **eref)
{
	struct event *thread;

	/* Cancel existing scheduled task TODO -- nice to do in 1 lock cycle */
	if (eref)
		event_cancel(eref);

	/* Get or allocate new thread to execute. */
	frr_with_mutex (&m->mtx) {
		thread = thread_get(m, EVENT_EVENT, func, arg, xref);

		/* Set its event value. */
		frr_with_mutex (&thread->mtx) {
			thread->add_type = EVENT_EXECUTE;
			thread->u.val = val;
			thread->ref = &thread;
		}
	}

	/* Execute thread doing all accounting. */
	event_call(thread);

	/* Give back or free thread. */
	thread_add_unuse(m, thread);
}

/* Debug signal mask - if 'sigs' is NULL, use current effective mask. */
void debug_signals(const sigset_t *sigs)
{
	int i, found;
	sigset_t tmpsigs;
	char buf[300];

	/*
	 * We're only looking at the non-realtime signals here, so we need
	 * some limit value. Platform differences mean at some point we just
	 * need to pick a reasonable value.
	 */
#if defined SIGRTMIN
#  define LAST_SIGNAL SIGRTMIN
#else
#  define LAST_SIGNAL 32
#endif


	if (sigs == NULL) {
		sigemptyset(&tmpsigs);
		pthread_sigmask(SIG_BLOCK, NULL, &tmpsigs);
		sigs = &tmpsigs;
	}

	found = 0;
	buf[0] = '\0';

	for (i = 0; i < LAST_SIGNAL; i++) {
		char tmp[20];

		if (sigismember(sigs, i) > 0) {
			if (found > 0)
				strlcat(buf, ",", sizeof(buf));
			snprintf(tmp, sizeof(tmp), "%d", i);
			strlcat(buf, tmp, sizeof(buf));
			found++;
		}
	}

	if (found == 0)
		snprintf(buf, sizeof(buf), "<none>");

	zlog_debug("%s: %s", __func__, buf);
}

static ssize_t printfrr_thread_dbg(struct fbuf *buf, struct printfrr_eargs *ea,
				   const struct event *thread)
{
	static const char *const types[] = {
		[EVENT_READ] = "read",	  [EVENT_WRITE] = "write",
		[EVENT_TIMER] = "timer",  [EVENT_EVENT] = "event",
		[EVENT_READY] = "ready",  [EVENT_UNUSED] = "unused",
		[EVENT_EXECUTE] = "exec",
	};
	ssize_t rv = 0;
	char info[16] = "";

	if (!thread)
		return bputs(buf, "{(thread *)NULL}");

	rv += bprintfrr(buf, "{(thread *)%p arg=%p", thread, thread->arg);

	if (thread->type < array_size(types) && types[thread->type])
		rv += bprintfrr(buf, " %-6s", types[thread->type]);
	else
		rv += bprintfrr(buf, " INVALID(%u)", thread->type);

	switch (thread->type) {
	case EVENT_READ:
	case EVENT_WRITE:
		snprintfrr(info, sizeof(info), "fd=%d", thread->u.fd);
		break;

	case EVENT_TIMER:
		snprintfrr(info, sizeof(info), "r=%pTVMud", &thread->u.sands);
		break;
	case EVENT_READY:
	case EVENT_EVENT:
	case EVENT_UNUSED:
	case EVENT_EXECUTE:
		break;
	}

	rv += bprintfrr(buf, " %-12s %s() %s from %s:%d}", info,
			thread->xref->funcname, thread->xref->dest,
			thread->xref->xref.file, thread->xref->xref.line);
	return rv;
}

printfrr_ext_autoreg_p("TH", printfrr_thread);
static ssize_t printfrr_thread(struct fbuf *buf, struct printfrr_eargs *ea,
			       const void *ptr)
{
	const struct event *thread = ptr;
	struct timespec remain = {};

	if (ea->fmt[0] == 'D') {
		ea->fmt++;
		return printfrr_thread_dbg(buf, ea, thread);
	}

	if (!thread) {
		/* need to jump over time formatting flag characters in the
		 * input format string, i.e. adjust ea->fmt!
		 */
		printfrr_time(buf, ea, &remain,
			      TIMEFMT_TIMER_DEADLINE | TIMEFMT_SKIP);
		return bputch(buf, '-');
	}

	TIMEVAL_TO_TIMESPEC(&thread->u.sands, &remain);
	return printfrr_time(buf, ea, &remain, TIMEFMT_TIMER_DEADLINE);
}
