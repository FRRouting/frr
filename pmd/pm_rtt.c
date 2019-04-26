/*
 * PMD - Path Monitoring RTT stats
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
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
#include <zebra.h>

#include <memory.h>

#include <sys/time.h>

#include "pmd/pm.h"
#include "pmd/pm_memory.h"
#include "pmd/pm_echo.h"
#include "pmd/pm_rtt.h"
/* definitions */

void pm_rtt_calculate(struct timeval *start, struct timeval *stop,
		      struct timeval *result, uint32_t *result_ms)
{
	time_t result_sec = stop->tv_sec - start->tv_sec;
	int usecs = stop->tv_sec - start->tv_sec;

	if (usecs < 0) {
		usecs = 1000000 + usecs;
		result_sec--;
	}
	if (result) {
		result->tv_sec = result_sec;
		result->tv_usec = usecs;
	}
	if (result_ms) {
		*result_ms = result_sec * 1000;
		*result_ms += usecs/1000;
	}
}

void pm_rtt_free_ctx(struct pm_rtt_stats *ctx)
{
	XFREE(MTYPE_PM_RTT_STATS, ctx);
}

struct pm_rtt_stats *pm_rtt_allocate_ctx(void)
{
	return XCALLOC(MTYPE_PM_RTT_STATS, sizeof(struct pm_rtt_stats));
}

void pm_rtt_update_stats(struct pm_rtt_stats *rtt_stats,
			 struct timeval *rtt, uint32_t *rtt_ms)
{
	uint32_t value_ms;

	if (!rtt_stats)
		return;
	rtt_stats->total_count++;
	/* convert in ms */
	if (!rtt_ms && rtt)
		value_ms = rtt->tv_sec * 1000 + rtt->tv_usec / 1000000;
	else
		value_ms = *rtt_ms;
	rtt_stats->sum_rtt += value_ms;
	if (!(rtt_stats->flags & RTT_STATS_MIN_SET)) {
		rtt_stats->min_rtt = value_ms;
		rtt_stats->flags |= RTT_STATS_MIN_SET;
	} else if (value_ms < rtt_stats->min_rtt) {
		rtt_stats->min_rtt = value_ms;
	}
	if (!(rtt_stats->flags & RTT_STATS_MAX_SET)) {
		rtt_stats->max_rtt = value_ms;
		rtt_stats->flags |= RTT_STATS_MAX_SET;
	} else if (value_ms > rtt_stats->max_rtt) {
		rtt_stats->max_rtt = value_ms;
	}
}

void pm_rtt_display_stats(struct vty *vty, struct pm_rtt_stats *rtt_stats)
{
	if (!rtt_stats)
		return;
	if (rtt_stats->total_count)
		rtt_stats->avg_rtt = rtt_stats->sum_rtt
			/ rtt_stats->total_count;
	vty_out(vty,
		"rtt calculated total %u, min %u ms, max %u ms"
		"avg %u ms\r\n",
		rtt_stats->total_count, rtt_stats->min_rtt,
		rtt_stats->max_rtt, rtt_stats->avg_rtt);
}
