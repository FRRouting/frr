/* Quagga signal handling functions.
 * Copyright (C) 2004 Paul Jakma,
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <sigevent.h>
#include <log.h>
#include <memory.h>

#ifdef SA_SIGINFO
#ifdef HAVE_UCONTEXT_H
#ifdef GNU_LINUX
/* get REG_EIP from ucontext.h */
#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
#endif /* GNU_LINUX */
#include <ucontext.h>
#endif /* HAVE_UCONTEXT_H */
#endif /* SA_SIGINFO */


/* master signals descriptor struct */
struct quagga_sigevent_master_t {
	struct thread *t;

	struct quagga_signal_t *signals;
	int sigc;

	volatile sig_atomic_t caught;
} sigmaster;

/* Generic signal handler
 * Schedules signal event thread
 */
static void quagga_signal_handler(int signo)
{
	int i;
	struct quagga_signal_t *sig;

	for (i = 0; i < sigmaster.sigc; i++) {
		sig = &(sigmaster.signals[i]);

		if (sig->signal == signo)
			sig->caught = 1;
	}

	sigmaster.caught = 1;
}

/* check if signals have been caught and run appropriate handlers */
int quagga_sigevent_process(void)
{
	struct quagga_signal_t *sig;
	int i;
#ifdef SIGEVENT_BLOCK_SIGNALS
	/* shouldnt need to block signals, but potentially may be needed */
	sigset_t newmask, oldmask;

	/*
	 * Block most signals, but be careful not to defer SIGTRAP because
	 * doing so breaks gdb, at least on NetBSD 2.0.  Avoid asking to
	 * block SIGKILL, just because we shouldn't be able to do so.
	 */
	sigfillset(&newmask);
	sigdelset(&newmask, SIGTRAP);
	sigdelset(&newmask, SIGKILL);

	if ((sigprocmask(SIG_BLOCK, &newmask, &oldmask)) < 0) {
		zlog_err("quagga_signal_timer: couldnt block signals!");
		return -1;
	}
#endif /* SIGEVENT_BLOCK_SIGNALS */

	if (sigmaster.caught > 0) {
		sigmaster.caught = 0;
		/* must not read or set sigmaster.caught after here,
		 * race condition with per-sig caught flags if one does
		 */

		for (i = 0; i < sigmaster.sigc; i++) {
			sig = &(sigmaster.signals[i]);

			if (sig->caught > 0) {
				sig->caught = 0;
				if (sig->handler)
					sig->handler();
			}
		}
	}

#ifdef SIGEVENT_BLOCK_SIGNALS
	if (sigprocmask(SIG_UNBLOCK, &oldmask, NULL) < 0)
		;
	return -1;
#endif /* SIGEVENT_BLOCK_SIGNALS */

	return 0;
}

#ifdef SIGEVENT_SCHEDULE_THREAD
/* timer thread to check signals. Shouldnt be needed */
int quagga_signal_timer(struct thread *t)
{
	struct quagga_sigevent_master_t *sigm;

	sigm = THREAD_ARG(t);
	sigm->t = NULL;
	thread_add_timer(sigm->t->master, quagga_signal_timer, &sigmaster,
			 QUAGGA_SIGNAL_TIMER_INTERVAL, &sigm->t);
	return quagga_sigevent_process();
}
#endif /* SIGEVENT_SCHEDULE_THREAD */

/* Initialization of signal handles. */
/* Signal wrapper. */
static int signal_set(int signo)
{
	int ret;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = &quagga_signal_handler;
	sigfillset(&sig.sa_mask);
	sig.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
		sig.sa_flags |= SA_INTERRUPT; /* SunOS */
#endif
	} else {
#ifdef SA_RESTART
		sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */
	}

	ret = sigaction(signo, &sig, &osig);
	if (ret < 0)
		return ret;
	else
		return 0;
}

#ifdef SA_SIGINFO

/* XXX This function should be enhanced to support more platforms
       (it currently works only on Linux/x86). */
static void *program_counter(void *context)
{
#ifdef HAVE_UCONTEXT_H
#ifdef GNU_LINUX
/* these are from GNU libc, rather than Linux, strictly speaking */
#if defined(REG_EIP)
#  define REG_INDEX REG_EIP
#elif defined(REG_RIP)
#  define REG_INDEX REG_RIP
#elif defined(__powerpc__)
#  define REG_INDEX 32
#endif
#elif defined(SUNOS_5) /* !GNU_LINUX */
# define REG_INDEX REG_PC
#endif		       /* GNU_LINUX */

#ifdef REG_INDEX
#ifdef HAVE_UCONTEXT_T_UC_MCONTEXT_GREGS
#  define REGS gregs[REG_INDEX]
#elif defined(HAVE_UCONTEXT_T_UC_MCONTEXT_UC_REGS)
#  define REGS uc_regs->gregs[REG_INDEX]
#endif /* HAVE_UCONTEXT_T_UC_MCONTEXT_GREGS */
#endif /* REG_INDEX */

#ifdef REGS
	if (context)
		return (void *)(((ucontext_t *)context)->uc_mcontext.REGS);
#elif defined(HAVE_UCONTEXT_T_UC_MCONTEXT_REGS__NIP)
	/* older Linux / struct pt_regs ? */
	if (context)
		return (void *)(((ucontext_t *)context)->uc_mcontext.regs->nip);
#endif /* REGS */

#endif /* HAVE_UCONTEXT_H */
	return NULL;
}

#endif /* SA_SIGINFO */

static void __attribute__((noreturn))
exit_handler(int signo
#ifdef SA_SIGINFO
	     ,
	     siginfo_t *siginfo, void *context
#endif
	     )
{
	zlog_signal(signo, "exiting..."
#ifdef SA_SIGINFO
		    ,
		    siginfo, program_counter(context)
#endif
			    );
	_exit(128 + signo);
}

static void __attribute__((noreturn))
core_handler(int signo
#ifdef SA_SIGINFO
	     ,
	     siginfo_t *siginfo, void *context
#endif
	     )
{
	/* make sure we don't hang in here.  default for SIGALRM is terminate.
	 * - if we're in backtrace for more than a second, abort. */
	struct sigaction sa_default = {.sa_handler = SIG_DFL};
	sigaction(SIGALRM, &sa_default, NULL);

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	alarm(1);

	zlog_signal(signo, "aborting..."
#ifdef SA_SIGINFO
		    ,
		    siginfo, program_counter(context)
#endif
			    );
	/* dump memory stats on core */
	log_memstats(stderr, "core_handler");
	abort();
}

static void trap_default_signals(void)
{
	static const int core_signals[] = {
		SIGQUIT, SIGILL,
#ifdef SIGEMT
		SIGEMT,
#endif
		SIGFPE,  SIGBUS, SIGSEGV,
#ifdef SIGSYS
		SIGSYS,
#endif
#ifdef SIGXCPU
		SIGXCPU,
#endif
#ifdef SIGXFSZ
		SIGXFSZ,
#endif
	};
	static const int exit_signals[] = {
		SIGHUP,    SIGINT, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2,
#ifdef SIGPOLL
		SIGPOLL,
#endif
#ifdef SIGVTALRM
		SIGVTALRM,
#endif
#ifdef SIGSTKFLT
		SIGSTKFLT,
#endif
	};
	static const int ignore_signals[] = {
		SIGPIPE,
	};
	static const struct {
		const int *sigs;
		unsigned int nsigs;
		void (*handler)(int signo
#ifdef SA_SIGINFO
				,
				siginfo_t *info, void *context
#endif
				);
	} sigmap[] = {
		{core_signals, array_size(core_signals), core_handler},
		{exit_signals, array_size(exit_signals), exit_handler},
		{ignore_signals, array_size(ignore_signals), NULL},
	};
	unsigned int i;

	for (i = 0; i < array_size(sigmap); i++) {
		unsigned int j;

		for (j = 0; j < sigmap[i].nsigs; j++) {
			struct sigaction oact;
			if ((sigaction(sigmap[i].sigs[j], NULL, &oact) == 0)
			    && (oact.sa_handler == SIG_DFL)) {
				struct sigaction act;
				sigfillset(&act.sa_mask);
				if (sigmap[i].handler == NULL) {
					act.sa_handler = SIG_IGN;
					act.sa_flags = 0;
				} else {
#ifdef SA_SIGINFO
					/* Request extra arguments to signal
					 * handler. */
					act.sa_sigaction = sigmap[i].handler;
					act.sa_flags = SA_SIGINFO;
#else
					act.sa_handler = sigmap[i].handler;
					act.sa_flags = 0;
#endif
#ifdef SA_RESETHAND
					/* don't try to print backtraces
					 * recursively */
					if (sigmap[i].handler == core_handler)
						act.sa_flags |= SA_RESETHAND;
#endif
				}
				if (sigaction(sigmap[i].sigs[j], &act, NULL)
				    < 0)
					zlog_warn(
						"Unable to set signal handler for signal %d: %s",
						sigmap[i].sigs[j],
						safe_strerror(errno));
			}
		}
	}
}

void signal_init(struct thread_master *m, int sigc,
		 struct quagga_signal_t signals[])
{

	int i = 0;
	struct quagga_signal_t *sig;

	/* First establish some default handlers that can be overridden by
	   the application. */
	trap_default_signals();

	while (i < sigc) {
		sig = &signals[i];
		if (signal_set(sig->signal) < 0)
			exit(-1);
		i++;
	}

	sigmaster.sigc = sigc;
	sigmaster.signals = signals;

#ifdef SIGEVENT_SCHEDULE_THREAD
	sigmaster.t = NULL;
	thread_add_timer(m, quagga_signal_timer, &sigmaster,
			 QUAGGA_SIGNAL_TIMER_INTERVAL, &sigmaster.t);
#endif /* SIGEVENT_SCHEDULE_THREAD */
}
