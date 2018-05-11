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

#ifndef PIM_IGMP_STATS_H
#define PIM_IGMP_STATS_H

#include <zebra.h>

struct igmp_stats {
	uint32_t	query_v1;
	uint32_t	query_v2;
	uint32_t	query_v3;
	uint32_t	report_v1;
	uint32_t	report_v2;
	uint32_t	report_v3;
	uint32_t	leave_v2;
	uint32_t	mtrace_rsp;
	uint32_t	mtrace_req;
	uint32_t	unsupported;
};

void igmp_stats_init(struct igmp_stats *stats);
void igmp_stats_add(struct igmp_stats *a, struct igmp_stats *b);

#endif /* PIM_IGMP_STATS_H */
