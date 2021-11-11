/*
 * Quagga Signal handling header.
 *
 * Copyright (C) 2004 Paul Jakma.
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

#ifndef _FRR_SIGNAL_H
#define _FRR_SIGNAL_H

#include <thread.h>

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
 * - pointer to valid struct thread_master
 * - number of elements in passed in signals array
 * - array of frr_signal_t's describing signals to handle
 *   and handlers to use for each signal
 */
extern void signal_init(struct thread_master *m, int sigc,
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
