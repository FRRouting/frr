// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * testing log message generator
 * Copyright (C) 2019-2020  David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>
#include <sys/resource.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "nexthop.h"
#include "log.h"
#include "frrevent.h"
#include "vrf.h"
#include "zclient.h"
#include "frr_pthread.h"

#include "sharpd/sharp_vty.h"

/* this is quite hacky, but then again it's a test tool and it does its job. */
static struct frr_pthread *lpt;

static unsigned long lp_duration;
static unsigned lp_frequency;
static unsigned lp_burst;
static size_t lp_ctr, lp_expect;
static struct rusage lp_rusage;
static struct vty *lp_vty;

extern struct event_loop *master;

static void logpump_done(struct event *thread)
{
	double x;

	vty_out(lp_vty, "\nlogpump done\n");
	vty_out(lp_vty, "%9zu messages written\n", lp_ctr);
	x = (double)lp_ctr / (double)lp_expect * 100.;
	vty_out(lp_vty, "%9zu messages targeted = %5.1lf%%\n", lp_expect, x);

	x = lp_rusage.ru_utime.tv_sec * 1000000 + lp_rusage.ru_utime.tv_usec;
	x /= (double)lp_ctr;
	vty_out(lp_vty, "%6llu.%06u usr %9.1lfns/msg\n",
		(unsigned long long)lp_rusage.ru_utime.tv_sec,
		(unsigned)lp_rusage.ru_utime.tv_usec, x * 1000.);

	x = lp_rusage.ru_stime.tv_sec * 1000000 + lp_rusage.ru_stime.tv_usec;
	x /= (double)lp_ctr;
	vty_out(lp_vty, "%6llu.%06u sys %9.1lfns/msg\n",
		(unsigned long long)lp_rusage.ru_stime.tv_sec,
		(unsigned)lp_rusage.ru_stime.tv_usec, x * 1000.);

	frr_pthread_stop(lpt, NULL);
	frr_pthread_destroy(lpt);
	lpt = NULL;
}

static void *logpump_run(void *arg)
{
	struct timespec start, next, now;
	unsigned long delta, period;

	period = 1000000000L / lp_frequency;

	zlog_tls_buffer_init();

	clock_gettime(CLOCK_MONOTONIC, &start);
	next = start;
	do {
		for (size_t inburst = 0; inburst < lp_burst; inburst++)
			zlog_debug("log pump: %zu (burst %zu)",
				   lp_ctr++, inburst);

		clock_gettime(CLOCK_MONOTONIC, &now);
		delta = (now.tv_sec - start.tv_sec) * 1000000000L
			+ (now.tv_nsec - start.tv_nsec);

		next.tv_nsec += period;
		if (next.tv_nsec > 1000000000L) {
			next.tv_sec++;
			next.tv_nsec -= 1000000000L;
		}
#ifdef HAVE_CLOCK_NANOSLEEP
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
#else
		struct timespec slpdur;

		slpdur.tv_sec = next.tv_sec - now.tv_sec;
		slpdur.tv_nsec = next.tv_nsec - now.tv_nsec;
		if (slpdur.tv_nsec < 0) {
			slpdur.tv_sec--;
			slpdur.tv_nsec += 1000000000L;
		}

		nanosleep(&slpdur, NULL);
#endif
	} while (delta < lp_duration);

	zlog_tls_buffer_fini();

#ifdef RUSAGE_THREAD
	getrusage(RUSAGE_THREAD, &lp_rusage);
#else
	getrusage(RUSAGE_SELF, &lp_rusage);
#endif

	event_add_timer_msec(master, logpump_done, NULL, 0, NULL);
	return NULL;
}

static int logpump_halt(struct frr_pthread *fpt, void **res)
{
	return 0;
}

/* default frr_pthread attributes */
static const struct frr_pthread_attr attr = {
	.start = logpump_run,
	.stop = logpump_halt,
};

void sharp_logpump_run(struct vty *vty, unsigned duration, unsigned frequency,
		       unsigned burst)
{
	if (lpt != NULL) {
		vty_out(vty, "logpump already running\n");
		return;
	}

	vty_out(vty, "starting logpump...\n");
	vty_out(vty, "keep this VTY open and press Enter to see results\n");

	lp_vty = vty;
	lp_duration = duration * 1000000000UL;
	lp_frequency = frequency;
	lp_burst = burst;
	lp_expect = duration * frequency * burst;
	lp_ctr = 0;

	lpt = frr_pthread_new(&attr, "logpump", "logpump");
	frr_pthread_run(lpt, NULL);
}
