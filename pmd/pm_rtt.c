/*
 * PMD - Path Monitoring RTT stats
 * Copyright 2019 6WIND S.A.
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
	suseconds_t usecs = stop->tv_usec - start->tv_usec;

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

/*
 * Return the difference between start and stop in micro-seconds (usec).
 */

static inline uint32_t pm_rtt_from_timevals(struct timeval *start,
					    struct timeval *stop)
{
	return (stop->tv_sec - start->tv_sec) * 1000000
	       + (stop->tv_usec - start->tv_usec);
}

void pm_rtt_update_bulk_stats(struct pm_echo *pme)
{
	uint32_t rtt = pm_rtt_from_timevals(&pme->start, &pme->stop[0]);

	pme->rtt_bulk_stats->min_rtt = rtt;
	pme->rtt_bulk_stats->max_rtt = rtt;
	pme->rtt_bulk_stats->sum_rtt = rtt;
	if (pme->stop[0].tv_sec != 0 || pme->stop[0].tv_usec != 0)
		pme->rtt_bulk_stats->total_count = 1;
	else
		pme->rtt_bulk_stats->total_count = 0;
	for (int i = 1; i < pme->count; ++i) {
		rtt = pm_rtt_from_timevals(&pme->start, &pme->stop[i]);
		if (rtt < pme->rtt_bulk_stats->min_rtt)
			pme->rtt_bulk_stats->min_rtt = rtt;
		else if (rtt > pme->rtt_bulk_stats->max_rtt)
			pme->rtt_bulk_stats->max_rtt = rtt;
		pme->rtt_bulk_stats->sum_rtt += rtt;
		++pme->rtt_bulk_stats->total_count;
	}
	pme->rtt_bulk_stats->avg_rtt =
		pme->rtt_bulk_stats->sum_rtt / pme->rtt_bulk_stats->total_count;
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

const char *pm_rtt_tvtostr(struct timeval *tv)
{
	struct tm *nowtm;
	static char buf[64];

	buf[0] = '\0';

	nowtm = localtime(&tv->tv_sec);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ".%06ld", tv->tv_usec);

	return buf;
}

void pm_rtt_display_bulk_stats(struct vty *vty, struct pm_echo *pme)
{
	int loss_ratio;

	if (!pme->rtt_bulk_stats)
		return;
	loss_ratio =
		100 - (pme->rtt_bulk_stats->total_count * 100 / pme->count);
	vty_out(vty,
		"\tlast bulk of %u started at %s\r\n"
		"\trtt calculated min %u us, max %u us, avg %u us\r\n"
		"\tloss ratio: %u%%\r\n",
		pme->count, pm_rtt_tvtostr(&pme->bulk_start), pme->rtt_bulk_stats->min_rtt,
		pme->rtt_bulk_stats->max_rtt, pme->rtt_bulk_stats->avg_rtt,
		loss_ratio);
}
