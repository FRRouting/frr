// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 */

#ifndef PIM_IGMP_STATS_H
#define PIM_IGMP_STATS_H

#include <zebra.h>

struct igmp_stats {
	uint32_t query_v1;
	uint32_t query_v2;
	uint32_t query_v3;
	uint32_t report_v1;
	uint32_t report_v2;
	uint32_t report_v3;
	uint32_t leave_v2;
	uint32_t mtrace_rsp;
	uint32_t mtrace_req;
	uint32_t unsupported;
	uint32_t peak_groups;
	uint32_t total_groups;
	uint32_t total_source_groups;
	uint32_t joins_sent;
	uint32_t joins_failed;
	uint32_t general_queries_sent;
	uint32_t group_queries_sent;
	uint32_t total_recv_messages;
};

#if PIM_IPV == 4
void igmp_stats_init(struct igmp_stats *stats);
void igmp_stats_add(struct igmp_stats *a, struct igmp_stats *b);
#else
static inline void igmp_stats_init(struct igmp_stats *stats)
{
}

static inline void igmp_stats_add(struct igmp_stats *a, struct igmp_stats *b)
{
}
#endif

#endif /* PIM_IGMP_STATS_H */
