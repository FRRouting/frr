// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRR - J/P Aggregation
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
 */
#ifndef __PIM_JP_AGG_H__
#define __PIM_JP_AGG_H__

#include "pim_rpf.h"

struct pim_jp_sources {
	struct pim_upstream *up;
	int is_join;
};

struct pim_jp_agg_group {
	pim_addr group;
	struct list *sources;
};

void pim_jp_agg_upstream_verification(struct pim_upstream *up, bool ignore);
int pim_jp_agg_is_in_list(struct list *group, struct pim_upstream *up);

void pim_jp_agg_group_list_free(struct pim_jp_agg_group *jag);
int pim_jp_agg_group_list_cmp(void *arg1, void *arg2);

void pim_jp_agg_clear_group(struct list *group);
void pim_jp_agg_remove_group(struct list *group, struct pim_upstream *up,
		struct pim_neighbor *nbr);

void pim_jp_agg_add_group(struct list *group, struct pim_upstream *up,
		bool is_join, struct pim_neighbor *nbr);

void pim_jp_agg_switch_interface(struct pim_rpf *orpf, struct pim_rpf *nrpf,
				 struct pim_upstream *up);

void pim_jp_agg_single_upstream_send(struct pim_rpf *rpf,
				     struct pim_upstream *up, bool is_join);
#endif
