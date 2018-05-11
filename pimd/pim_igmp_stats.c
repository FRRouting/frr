/*
 * PIM for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "pim_igmp_stats.h"

void igmp_stats_init(struct igmp_stats *stats)
{
	memset(stats, 0, sizeof(struct igmp_stats));
}

void igmp_stats_add(struct igmp_stats *a, struct igmp_stats *b)
{
	if (!a || !b)
		return;

	a->query_v1 += b->query_v1;
	a->query_v2 += b->query_v2;
	a->query_v3 += b->query_v3;
	a->report_v1 += b->report_v1;
	a->report_v2 += b->report_v2;
	a->report_v3 += b->report_v3;
	a->leave_v2 += b->leave_v2;
	a->mtrace_rsp += b->mtrace_rsp;
	a->mtrace_req += b->mtrace_req;
	a->unsupported += b->unsupported;
}
