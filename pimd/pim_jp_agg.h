/*
 * PIM for FRR - J/P Aggregation
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
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
#ifndef __PIM_JP_AGG_H__
#define __PIM_JP_AGG_H__

struct pim_jp_sources {
	struct pim_upstream *up;
	int is_join;
};

struct pim_jp_agg_group {
	struct in_addr group;
	struct list *sources;
};

void pim_jp_agg_upstream_verification(struct pim_upstream *up, bool ignore);
int pim_jp_agg_is_in_list(struct list *group, struct pim_upstream *up);

void pim_jp_agg_group_list_free(struct pim_jp_agg_group *jag);
int pim_jp_agg_group_list_cmp(void *arg1, void *arg2);

void pim_jp_agg_clear_group(struct list *group);
void pim_jp_agg_remove_group(struct list *group, struct pim_upstream *up);

void pim_jp_agg_add_group(struct list *group, struct pim_upstream *up,
			  bool is_join);

void pim_jp_agg_switch_interface(struct pim_rpf *orpf, struct pim_rpf *nrpf,
				 struct pim_upstream *up);

void pim_jp_agg_single_upstream_send(struct pim_rpf *rpf,
				     struct pim_upstream *up, bool is_join);
#endif
