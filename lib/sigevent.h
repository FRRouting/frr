// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Quagga Signal handling header.
 *
 * Copyright (C) 2004 Paul Jakma.
 */

#ifndef _FRR_SIGNAL_H
#define _FRR_SIGNAL_H

#include <frrevent.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FRR_SIGNAL_TIMER_INTERVAL 2L

struct frr_signal_t {
	int signal;	    /* signal number    */
	void (*handler)(void); /* handler to call  */

	volatile sig_atomic_t caught; /* private member   */
};

/* initialise sigevent system
 * takes:
 * - pointer to valid struct event_loop
 * - number of elements in passed in signals array
 * - array of frr_signal_t's describing signals to handle
 *   and handlers to use for each signal
 */
extern void signal_init(struct event_loop *m, int sigc,
			struct frr_signal_t *signals);


/*
 * Check whether any signals have been received and are pending. This is done
 * with the application's key signals blocked. The complete set of signals
 * is returned in 'setp', so the caller can restore them when appropriate.
 * If there are pending signals, returns 'true', 'false' otherwise.
 */
bool frr_sigevent_check(sigset_t *setp);

/* check whether there are signals to handle, process any found */
extern int frr_sigevent_process(void);

/* Ensure we don't handle "application-type" signals on a secondary thread by
 * blocking these signals when creating threads
 *
 * NB: SIGSEGV, SIGABRT, etc. must be allowed on all threads or we get no
 * crashlogs.  Since signals vary a little bit between platforms, below is a
 * list of known things to go to the main thread.  Any unknown signals should
 * stay thread-local.
 */
static inline void frr_sigset_add_mainonly(sigset_t *blocksigs)
{
	/* signals we actively handle */
	sigaddset(blocksigs, SIGHUP);
	sigaddset(blocksigs, SIGINT);
	sigaddset(blocksigs, SIGTERM);
	sigaddset(blocksigs, SIGUSR1);

	/* signals we don't actively use but that semantically belong */
	sigaddset(blocksigs, SIGUSR2);
	sigaddset(blocksigs, SIGQUIT);
	sigaddset(blocksigs, SIGCHLD);
	sigaddset(blocksigs, SIGPIPE);
	sigaddset(blocksigs, SIGTSTP);
	sigaddset(blocksigs, SIGTTIN);
	sigaddset(blocksigs, SIGTTOU);
	sigaddset(blocksigs, SIGWINCH);
}

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SIGNAL_H */
