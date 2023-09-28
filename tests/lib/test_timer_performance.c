// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test program which measures the time it takes to schedule and
 * remove timers.
 *
 * Copyright (C) 2013 by Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include <stdio.h>
#include <unistd.h>

#include "frrevent.h"
#include "prng.h"

#define SCHEDULE_TIMERS 1000000
#define REMOVE_TIMERS    500000

struct event_loop *master;

static void dummy_func(struct event *thread)
{
}

int main(int argc, char **argv)
{
	struct prng *prng;
	int i;
	struct event **timers;
	struct timeval tv_start, tv_lap, tv_stop;
	unsigned long t_schedule, t_remove;

	master = event_master_create(NULL);
	prng = prng_new(0);
	timers = calloc(SCHEDULE_TIMERS, sizeof(*timers));

	/* create thread structures so they won't be allocated during the
	 * time measurement */
	for (i = 0; i < SCHEDULE_TIMERS; i++) {
		event_add_timer_msec(master, dummy_func, NULL, 0, &timers[i]);
	}
	for (i = 0; i < SCHEDULE_TIMERS; i++)
		event_cancel(&timers[i]);

	monotime(&tv_start);

	for (i = 0; i < SCHEDULE_TIMERS; i++) {
		long interval_msec;

		interval_msec = prng_rand(prng) % (100 * SCHEDULE_TIMERS);
		event_add_timer_msec(master, dummy_func, NULL, interval_msec,
				     &timers[i]);
	}

	monotime(&tv_lap);

	for (i = 0; i < REMOVE_TIMERS; i++) {
		int index;

		index = prng_rand(prng) % SCHEDULE_TIMERS;
		event_cancel(&timers[index]);
	}

	monotime(&tv_stop);

	t_schedule = 1000 * (tv_lap.tv_sec - tv_start.tv_sec);
	t_schedule += (tv_lap.tv_usec - tv_start.tv_usec) / 1000;

	t_remove = 1000 * (tv_stop.tv_sec - tv_lap.tv_sec);
	t_remove += (tv_stop.tv_usec - tv_lap.tv_usec) / 1000;

	printf("Scheduling %d random timers took %lu.%03lu seconds.\n",
	       SCHEDULE_TIMERS, t_schedule / 1000, t_schedule % 1000);
	printf("Removing %d random timers took %lu.%03lu seconds.\n",
	       REMOVE_TIMERS, t_remove / 1000, t_remove % 1000);
	fflush(stdout);

	free(timers);
	event_master_free(master);
	prng_free(prng);
	return 0;
}
