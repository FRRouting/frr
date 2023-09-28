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

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SIGNAL_H */
