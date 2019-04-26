/*
 * header for path monitoring rtt stats
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
#ifndef __PM_RTT_H__
#define __PM_RTT_H__

#include "lib/vty.h"
#include <sys/time.h>

struct pm_rtt_stats {
#define RTT_STATS_MIN_SET 1 << 0
#define RTT_STATS_MAX_SET 1 << 1
	int flags;
	uint32_t total_count;
	uint32_t sum_rtt;
	uint32_t avg_rtt;
	uint32_t min_rtt;
	uint32_t max_rtt;
};

extern struct pm_rtt_stats *pm_rtt_allocate_ctx(void);
extern void pm_rtt_free_ctx(struct pm_rtt_stats *ctx);

/* start and stop params are mandatory
 * result or result_ms is optional
 */
extern void pm_rtt_calculate(struct timeval *start, struct timeval *stop,
			     struct timeval *result, uint32_t *result_ms);

extern void pm_rtt_update_stats(struct pm_rtt_stats *rtt_stats,
				struct timeval *rtt, uint32_t *rtt_ms);

extern void pm_rtt_display_stats(struct vty *vty,
				 struct pm_rtt_stats *rtt_stats);

#endif
