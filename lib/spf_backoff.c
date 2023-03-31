// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of the IETF SPF delay algorithm
 * as explained in draft-ietf-rtgwg-backoff-algo-04
 *
 * Created: 25-01-2017 by S. Litkowski
 *
 * Copyright (C) 2017 Orange Labs http://www.orange.com/
 * Copyright (C) 2017 by Christian Franke, Open Source Routing / NetDEF Inc.
 *
 * This file is part of FRRouting (FRR)
 */

#include <zebra.h>

#include "spf_backoff.h"

#include "command.h"
#include "memory.h"
#include "frrevent.h"
#include "vty.h"

DEFINE_MTYPE_STATIC(LIB, SPF_BACKOFF, "SPF backoff");
DEFINE_MTYPE_STATIC(LIB, SPF_BACKOFF_NAME, "SPF backoff name");

static bool debug_spf_backoff = false;
#define backoff_debug(...)                                                     \
	do {                                                                   \
		if (debug_spf_backoff)                                         \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

enum spf_backoff_state {
	SPF_BACKOFF_QUIET,
	SPF_BACKOFF_SHORT_WAIT,
	SPF_BACKOFF_LONG_WAIT
};

struct spf_backoff {
	struct event_loop *m;

	/* Timers as per draft */
	long init_delay;
	long short_delay;
	long long_delay;
	long holddown;
	long timetolearn;

	/* State machine */
	enum spf_backoff_state state;
	struct event *t_holddown;
	struct event *t_timetolearn;

	/* For debugging */
	char *name;
	struct timeval first_event_time;
	struct timeval last_event_time;
};

static const char *spf_backoff_state2str(enum spf_backoff_state state)
{
	switch (state) {
	case SPF_BACKOFF_QUIET:
		return "QUIET";
	case SPF_BACKOFF_SHORT_WAIT:
		return "SHORT_WAIT";
	case SPF_BACKOFF_LONG_WAIT:
		return "LONG_WAIT";
	}
	return "???";
}

struct spf_backoff *spf_backoff_new(struct event_loop *m, const char *name,
				    long init_delay, long short_delay,
				    long long_delay, long holddown,
				    long timetolearn)
{
	struct spf_backoff *rv;

	rv = XCALLOC(MTYPE_SPF_BACKOFF, sizeof(*rv));
	rv->m = m;

	rv->init_delay = init_delay;
	rv->short_delay = short_delay;
	rv->long_delay = long_delay;
	rv->holddown = holddown;
	rv->timetolearn = timetolearn;

	rv->state = SPF_BACKOFF_QUIET;

	rv->name = XSTRDUP(MTYPE_SPF_BACKOFF_NAME, name);
	return rv;
}

void spf_backoff_free(struct spf_backoff *backoff)
{
	if (!backoff)
		return;

	event_cancel(&backoff->t_holddown);
	event_cancel(&backoff->t_timetolearn);
	XFREE(MTYPE_SPF_BACKOFF_NAME, backoff->name);

	XFREE(MTYPE_SPF_BACKOFF, backoff);
}

static void spf_backoff_timetolearn_elapsed(struct event *thread)
{
	struct spf_backoff *backoff = EVENT_ARG(thread);

	backoff->state = SPF_BACKOFF_LONG_WAIT;
	backoff_debug("SPF Back-off(%s) TIMETOLEARN elapsed, move to state %s",
		      backoff->name, spf_backoff_state2str(backoff->state));
}

static void spf_backoff_holddown_elapsed(struct event *thread)
{
	struct spf_backoff *backoff = EVENT_ARG(thread);

	EVENT_OFF(backoff->t_timetolearn);
	timerclear(&backoff->first_event_time);
	backoff->state = SPF_BACKOFF_QUIET;
	backoff_debug("SPF Back-off(%s) HOLDDOWN elapsed, move to state %s",
		      backoff->name, spf_backoff_state2str(backoff->state));
}

long spf_backoff_schedule(struct spf_backoff *backoff)
{
	long rv = 0;
	struct timeval now;

	gettimeofday(&now, NULL);

	backoff_debug("SPF Back-off(%s) schedule called in state %s",
		      backoff->name, spf_backoff_state2str(backoff->state));

	backoff->last_event_time = now;

	switch (backoff->state) {
	case SPF_BACKOFF_QUIET:
		backoff->state = SPF_BACKOFF_SHORT_WAIT;
		event_add_timer_msec(
			backoff->m, spf_backoff_timetolearn_elapsed, backoff,
			backoff->timetolearn, &backoff->t_timetolearn);
		event_add_timer_msec(backoff->m, spf_backoff_holddown_elapsed,
				     backoff, backoff->holddown,
				     &backoff->t_holddown);
		backoff->first_event_time = now;
		rv = backoff->init_delay;
		break;
	case SPF_BACKOFF_SHORT_WAIT:
	case SPF_BACKOFF_LONG_WAIT:
		event_cancel(&backoff->t_holddown);
		event_add_timer_msec(backoff->m, spf_backoff_holddown_elapsed,
				     backoff, backoff->holddown,
				     &backoff->t_holddown);
		if (backoff->state == SPF_BACKOFF_SHORT_WAIT)
			rv = backoff->short_delay;
		else
			rv = backoff->long_delay;
		break;
	}

	backoff_debug(
		"SPF Back-off(%s) changed state to %s and returned %ld delay",
		backoff->name, spf_backoff_state2str(backoff->state), rv);
	return rv;
}

static const char *timeval_format(struct timeval *tv)
{
	struct tm tm_store;
	struct tm *tm;
	static char timebuf[256];

	if (!tv->tv_sec && !tv->tv_usec)
		return "(never)";

	tm = localtime_r(&tv->tv_sec, &tm_store);
	if (!tm
	    || strftime(timebuf, sizeof(timebuf), "%Z %a %Y-%m-%d %H:%M:%S", tm)
		       == 0) {
		return "???";
	}

	size_t offset = strlen(timebuf);
	snprintf(timebuf + offset, sizeof(timebuf) - offset, ".%ld",
		 (long int)tv->tv_usec);

	return timebuf;
}

void spf_backoff_show(struct spf_backoff *backoff, struct vty *vty,
		      const char *prefix)
{
	vty_out(vty, "%sCurrent state:     %s\n", prefix,
		spf_backoff_state2str(backoff->state));
	vty_out(vty, "%sInit timer:        %ld msec\n", prefix,
		backoff->init_delay);
	vty_out(vty, "%sShort timer:       %ld msec\n", prefix,
		backoff->short_delay);
	vty_out(vty, "%sLong timer:        %ld msec\n", prefix,
		backoff->long_delay);
	vty_out(vty, "%sHolddown timer:    %ld msec\n", prefix,
		backoff->holddown);
	if (backoff->t_holddown) {
		struct timeval remain = event_timer_remain(backoff->t_holddown);

		vty_out(vty, "%s                   Still runs for %lld msec\n",
			prefix,
			(long long)remain.tv_sec * 1000
				+ remain.tv_usec / 1000);
	} else {
		vty_out(vty, "%s                   Inactive\n", prefix);
	}

	vty_out(vty, "%sTimeToLearn timer: %ld msec\n", prefix,
		backoff->timetolearn);
	if (backoff->t_timetolearn) {
		struct timeval remain =
			event_timer_remain(backoff->t_timetolearn);
		vty_out(vty, "%s                   Still runs for %lld msec\n",
			prefix,
			(long long)remain.tv_sec * 1000
				+ remain.tv_usec / 1000);
	} else {
		vty_out(vty, "%s                   Inactive\n", prefix);
	}

	vty_out(vty, "%sFirst event:       %s\n", prefix,
		timeval_format(&backoff->first_event_time));
	vty_out(vty, "%sLast event:        %s\n", prefix,
		timeval_format(&backoff->last_event_time));
}

DEFUN(spf_backoff_debug,
      spf_backoff_debug_cmd,
      "debug spf-delay-ietf",
      DEBUG_STR
      "SPF Back-off Debugging\n")
{
	debug_spf_backoff = true;
	return CMD_SUCCESS;
}

DEFUN(no_spf_backoff_debug,
      no_spf_backoff_debug_cmd,
      "no debug spf-delay-ietf",
      NO_STR
      DEBUG_STR
      "SPF Back-off Debugging\n")
{
	debug_spf_backoff = false;
	return CMD_SUCCESS;
}

int spf_backoff_write_config(struct vty *vty)
{
	int written = 0;

	if (debug_spf_backoff) {
		vty_out(vty, "debug spf-delay-ietf\n");
		written++;
	}

	return written;
}

void spf_backoff_cmd_init(void)
{
	install_element(ENABLE_NODE, &spf_backoff_debug_cmd);
	install_element(CONFIG_NODE, &spf_backoff_debug_cmd);
	install_element(ENABLE_NODE, &no_spf_backoff_debug_cmd);
	install_element(CONFIG_NODE, &no_spf_backoff_debug_cmd);
}

long spf_backoff_init_delay(struct spf_backoff *backoff)
{
	return backoff->init_delay;
}

long spf_backoff_short_delay(struct spf_backoff *backoff)
{
	return backoff->short_delay;
}

long spf_backoff_long_delay(struct spf_backoff *backoff)
{
	return backoff->long_delay;
}

long spf_backoff_holddown(struct spf_backoff *backoff)
{
	return backoff->holddown;
}

long spf_backoff_timetolearn(struct spf_backoff *backoff)
{
	return backoff->timetolearn;
}
