// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *
 * This file is part of Quagga
 */

#ifndef _FRR_BGP_MPATH_H
#define _FRR_BGP_MPATH_H

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
	uint16_t mp_count;

	/* Flags - relevant as noted. */
	uint16_t mp_flags;
#define BGP_MP_LB_PRESENT 0x1 /* Link-bandwidth present for >= 1 path */
#define BGP_MP_LB_ALL 0x2 /* Link-bandwidth present for all multipaths */

	/* Aggregated attribute for advertising multipath route */
	struct attr *mp_attr;

	/* Cumulative bandiwdth of all multipaths - attached to best path. */
	uint64_t cum_bw;
};

/* Functions to support maximum-paths configuration */
extern int bgp_maximum_paths_set(struct bgp *bgp, afi_t afi, safi_t safi,
				 int peertype, uint16_t maxpaths,
				 bool clusterlen);
extern int bgp_maximum_paths_unset(struct bgp *bgp, afi_t afi, safi_t safi,
				   int peertype);

/* Functions used by bgp_best_selection to record current
 * multipath selections
 */
extern int bgp_path_info_nexthop_cmp(struct bgp_path_info *bpi1,
				     struct bgp_path_info *bpi2);
extern void bgp_mp_list_init(struct list *mp_list);
extern void bgp_mp_list_clear(struct list *mp_list);
extern void bgp_mp_list_add(struct list *mp_list, struct bgp_path_info *mpinfo);
extern void bgp_mp_dmed_deselect(struct bgp_path_info *dmed_best);
extern void bgp_path_info_mpath_update(struct bgp *bgp, struct bgp_dest *dest,
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
extern bool bgp_path_info_mpath_chkwtd(struct bgp *bgp,
				       struct bgp_path_info *path);
extern uint64_t bgp_path_info_mpath_cumbw(struct bgp_path_info *path);

#endif /* _FRR_BGP_MPATH_H */
