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
#ifndef _ZEBRA_SPF_BACKOFF_H
#define _ZEBRA_SPF_BACKOFF_H

#ifdef __cplusplus
extern "C" {
#endif

struct spf_backoff;
struct event_loop;
struct vty;

struct spf_backoff *spf_backoff_new(struct event_loop *m, const char *name,
				    long init_delay, long short_delay,
				    long long_delay, long holddown,
				    long timetolearn);

void spf_backoff_free(struct spf_backoff *backoff);

/* Called whenever an IGP event is received, returns how many
 * milliseconds routing table computation should be delayed */
long spf_backoff_schedule(struct spf_backoff *backoff);

/* Shows status of SPF backoff instance */
void spf_backoff_show(struct spf_backoff *backoff, struct vty *vty,
		      const char *prefix);

/* Writes out global SPF backoff debug config */
int spf_backoff_write_config(struct vty *vty);

/* Registers global SPF backoff debug commands */
void spf_backoff_cmd_init(void);

/* Accessor functions for SPF backoff parameters */
long spf_backoff_init_delay(struct spf_backoff *backoff);
long spf_backoff_short_delay(struct spf_backoff *backoff);
long spf_backoff_long_delay(struct spf_backoff *backoff);
long spf_backoff_holddown(struct spf_backoff *backoff);
long spf_backoff_timetolearn(struct spf_backoff *backoff);

#ifdef __cplusplus
}
#endif

#endif
