// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
	a->peak_groups += b->peak_groups;
	a->total_groups += b->total_groups;
	a->total_source_groups += b->total_source_groups;
	a->joins_sent += b->joins_sent;
	a->joins_failed += b->joins_failed;
	a->general_queries_sent += b->general_queries_sent;
	a->group_queries_sent += b->group_queries_sent;
	a->total_recv_messages += b->query_v1 + b->query_v2 + b->query_v3 +
				  b->report_v1 + b->report_v2 + b->report_v3 +
				  b->leave_v2 + b->mtrace_rsp + b->mtrace_req;
}
