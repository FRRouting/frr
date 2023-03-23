// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF inter-area routing.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_IA_H
#define _ZEBRA_OSPF_IA_H

/* Macros. */
#define OSPF_EXAMINE_SUMMARIES_ALL(A, N, R)                                    \
	{                                                                      \
		ospf_examine_summaries((A), SUMMARY_LSDB((A)), (N), (R));      \
		ospf_examine_summaries((A), ASBR_SUMMARY_LSDB((A)), (N), (R)); \
	}

#define OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL(A, N, R)                            \
	{                                                                      \
		ospf_examine_transit_summaries((A), SUMMARY_LSDB((A)), (N),    \
					       (R));                           \
		ospf_examine_transit_summaries((A), ASBR_SUMMARY_LSDB((A)),    \
					       (N), (R));                      \
	}

extern void ospf_ia_routing(struct ospf *, struct route_table *,
			    struct route_table *);
extern int ospf_area_is_transit(struct ospf_area *);

#endif /* _ZEBRA_OSPF_IA_H */
