/*
 * This is an implementation of the IETF SPF delay algorithm
 * as explained in draft-ietf-rtgwg-backoff-algo-04
 *
 * Created: 25-01-2017 by S. Litkowski
 *
 * Copyright (C) 2017 Orange Labs http://www.orange.com/
 * Copyright (C) 2017 by Christian Franke, Open Source Routing / NetDEF Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _ZEBRA_SPF_BACKOFF_H
#define _ZEBRA_SPF_BACKOFF_H

struct spf_backoff;
struct thread_master;
struct vty;

struct spf_backoff *spf_backoff_new(struct thread_master *m, const char *name,
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

#endif
