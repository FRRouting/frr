/*
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_MPATH_H
#define _QUAGGA_BGP_MPATH_H

/* Supplemental information linked to bgp_path_info for keeping track of
 * multipath selections, lazily allocated to save memory
 */
struct bgp_path_info_mpath {
	/* Points to the first multipath (on bestpath) or the next multipath */
	struct bgp_path_info_mpath *mp_next;

	/* Points to the previous multipath or NULL on bestpath */
	struct bgp_path_info_mpath *mp_prev;

	/* Points to bgp_path_info associated with this multipath info */
	struct bgp_path_info *mp_info;

	/* When attached to best path, the number of selected multipaths */
	uint32_t mp_count;

	/* Aggregated attribute for advertising multipath route */
	struct attr *mp_attr;
};

/* Functions to support maximum-paths configuration */
extern int bgp_maximum_paths_set(struct bgp *, afi_t, safi_t, int, uint16_t,
				 uint16_t);
extern int bgp_maximum_paths_unset(struct bgp *, afi_t, safi_t, int);

/* Functions used by bgp_best_selection to record current
 * multipath selections
 */
extern int bgp_path_info_nexthop_cmp(struct bgp_path_info *bpi1,
				     struct bgp_path_info *bpi2);
extern void bgp_mp_list_init(struct list *);
extern void bgp_mp_list_clear(struct list *);
extern void bgp_mp_list_add(struct list *mp_list, struct bgp_path_info *mpinfo);
extern void bgp_mp_dmed_deselect(struct bgp_path_info *dmed_best);
extern void bgp_path_info_mpath_update(struct bgp_node *rn,
				       struct bgp_path_info *new_best,
				       struct bgp_path_info *old_best,
				       struct list *mp_list,
				       struct bgp_maxpaths_cfg *mpath_cfg);
extern void
bgp_path_info_mpath_aggregate_update(struct bgp_path_info *new_best,
				     struct bgp_path_info *old_best);

/* Unlink and free multipath information associated with a bgp_path_info */
extern void bgp_path_info_mpath_dequeue(struct bgp_path_info *path);
extern void bgp_path_info_mpath_free(struct bgp_path_info_mpath **mpath);

/* Walk list of multipaths associated with a best path */
extern struct bgp_path_info *
bgp_path_info_mpath_first(struct bgp_path_info *path);
extern struct bgp_path_info *
bgp_path_info_mpath_next(struct bgp_path_info *path);

/* Accessors for multipath information */
extern uint32_t bgp_path_info_mpath_count(struct bgp_path_info *path);
extern struct attr *bgp_path_info_mpath_attr(struct bgp_path_info *path);

#endif /* _QUAGGA_BGP_MPATH_H */
