/* BGP flap dampening
 * Copyright (C) 2001 IP Infusion Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <math.h>

#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "log.h"
#include "thread.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_vty.h"

static void bgp_reuselist_add(struct reuselist *list,
			      struct bgp_damp_info *info)
{
	struct reuselist_node *new_node;

	assert(info);
	new_node = XCALLOC(MTYPE_BGP_DAMP_REUSELIST, sizeof(*new_node));
	new_node->info = info;
	SLIST_INSERT_HEAD(list, new_node, entry);
}

static void bgp_reuselist_del(struct reuselist *list,
			      struct reuselist_node **node)
{
	if ((*node) == NULL)
		return;
	assert(list && node && *node);
	SLIST_REMOVE(list, (*node), reuselist_node, entry);
	XFREE(MTYPE_BGP_DAMP_REUSELIST, (*node));
	*node = NULL;
}

static void bgp_reuselist_switch(struct reuselist *source,
				 struct reuselist_node *node,
				 struct reuselist *target)
{
	assert(source && target && node);
	SLIST_REMOVE(source, node, reuselist_node, entry);
	SLIST_INSERT_HEAD(target, node, entry);
}

static void bgp_reuselist_free(struct reuselist *list)
{
	struct reuselist_node *rn;

	assert(list);
	while ((rn = SLIST_FIRST(list)) != NULL)
		bgp_reuselist_del(list, &rn);
}

static struct reuselist_node *bgp_reuselist_find(struct reuselist *list,
						 struct bgp_damp_info *info)
{
	struct reuselist_node *rn;

	assert(list && info);
	SLIST_FOREACH (rn, list, entry) {
		if (rn->info == info)
			return rn;
	}
	return NULL;
}

static void bgp_damp_info_unclaim(struct bgp_damp_info *bdi)
{
	struct reuselist_node *node;

	assert(bdi && bdi->config);
	if (bdi->index == BGP_DAMP_NO_REUSE_LIST_INDEX) {
		node = bgp_reuselist_find(&bdi->config->no_reuse_list, bdi);
		if (node)
			bgp_reuselist_del(&bdi->config->no_reuse_list, &node);
	} else {
		node = bgp_reuselist_find(&bdi->config->reuse_list[bdi->index],
					  bdi);
		if (node)
			bgp_reuselist_del(&bdi->config->reuse_list[bdi->index],
					  &node);
	}
	bdi->config = NULL;
}

static void bgp_damp_info_claim(struct bgp_damp_info *bdi,
				struct bgp_damp_config *bdc)
{
	assert(bdc && bdi);
	if (bdi->config == NULL) {
		bdi->config = bdc;
		return;
	}
	bgp_damp_info_unclaim(bdi);
	bdi->config = bdc;
	bdi->afi = bdc->afi;
	bdi->safi = bdc->safi;
}

struct bgp_damp_config *get_active_bdc_from_pi(struct bgp_path_info *pi,
					       afi_t afi, safi_t safi)
{
	if (!pi)
		return NULL;
	if (CHECK_FLAG(pi->peer->af_flags[afi][safi],
		       PEER_FLAG_CONFIG_DAMPENING))
		return &pi->peer->damp[afi][safi];
	if (peer_group_active(pi->peer))
		if (CHECK_FLAG(pi->peer->group->conf->af_flags[afi][safi],
			       PEER_FLAG_CONFIG_DAMPENING))
			return &pi->peer->group->conf->damp[afi][safi];
	if (CHECK_FLAG(pi->peer->bgp->af_flags[afi][safi],
		       BGP_CONFIG_DAMPENING))
		return &pi->peer->bgp->damp[afi][safi];
	return NULL;
}

/* Calculate reuse list index by penalty value.  */
static int bgp_reuse_index(int penalty, struct bgp_damp_config *bdc)
{
	unsigned int i;
	unsigned int index;

	/*
	 * reuse_limit can't be zero, this is for Coverity
	 * to bypass division by zero test.
	 */
	assert(bdc->reuse_limit);

	i = (int)(((double)penalty / bdc->reuse_limit - 1.0)
		  * bdc->scale_factor);

	if (i >= bdc->reuse_index_size)
		i = bdc->reuse_index_size - 1;

	index = bdc->reuse_index[i] - bdc->reuse_index[0];

	return (bdc->reuse_offset + index) % bdc->reuse_list_size;
}

/* Add BGP dampening information to reuse list.  */
static void bgp_reuse_list_add(struct bgp_damp_info *bdi,
			       struct bgp_damp_config *bdc)
{
	bgp_damp_info_claim(bdi, bdc);
	bdi->index = bgp_reuse_index(bdi->penalty, bdc);
	bgp_reuselist_add(&bdc->reuse_list[bdi->index], bdi);
}

/* Delete BGP dampening information from reuse list.  */
static void bgp_reuse_list_delete(struct bgp_damp_info *bdi,
				  struct bgp_damp_config *bdc)
{
	struct reuselist *list;
	struct reuselist_node *rn;

	list = &bdc->reuse_list[bdi->index];
	rn = bgp_reuselist_find(list, bdi);
	bgp_damp_info_unclaim(bdi);
	bgp_reuselist_del(list, &rn);
}

static void bgp_no_reuse_list_add(struct bgp_damp_info *bdi,
				  struct bgp_damp_config *bdc)
{
	bgp_damp_info_claim(bdi, bdc);
	bdi->index = BGP_DAMP_NO_REUSE_LIST_INDEX;
	bgp_reuselist_add(&bdc->no_reuse_list, bdi);
}

static void bgp_no_reuse_list_delete(struct bgp_damp_info *bdi,
				     struct bgp_damp_config *bdc)
{
	struct reuselist_node *rn;

	assert(bdc && bdi);
	if (bdi->config == NULL) {
		bgp_damp_info_unclaim(bdi);
		return;
	}
	bdi->config = NULL;
	rn = bgp_reuselist_find(&bdc->no_reuse_list, bdi);
	bgp_reuselist_del(&bdc->no_reuse_list, &rn);
}

/* Return decayed penalty value.  */
int bgp_damp_decay(time_t tdiff, int penalty, struct bgp_damp_config *bdc)
{
	unsigned int i;

	i = (int)((double)tdiff / DELTA_T);

	if (i == 0)
		return penalty;

	if (i >= bdc->decay_array_size)
		return 0;

	return (int)(penalty * bdc->decay_array[i]);
}

/* Handler of reuse timer event.  Each route in the current reuse-list
   is evaluated.  RFC2439 Section 4.8.7.  */
static int bgp_reuse_timer(struct thread *t)
{
	struct bgp_damp_config *bdc = THREAD_ARG(t);
	struct bgp_damp_info *bdi;
	struct reuselist plist;
	struct reuselist_node *node;
	struct bgp *bgp;
	time_t t_now, t_diff;

	thread_add_timer(bm->master, bgp_reuse_timer, bdc, DELTA_REUSE,
			 &bdc->t_reuse);

	t_now = bgp_clock();

	/* 1.  save a pointer to the current queue head and zero the list head
	 * list head entry. */
	assert(bdc->reuse_offset < bdc->reuse_list_size);
	plist = bdc->reuse_list[bdc->reuse_offset];
	node = SLIST_FIRST(&plist);
	SLIST_INIT(&bdc->reuse_list[bdc->reuse_offset]);

	/* 2.  set offset = modulo reuse-list-size ( offset + 1 ), thereby
	   rotating the circular queue of list-heads.  */
	bdc->reuse_offset = (bdc->reuse_offset + 1) % bdc->reuse_list_size;
	assert(bdc->reuse_offset < bdc->reuse_list_size);

	/* 3. if ( the saved list head pointer is non-empty ) */
	while ((node = SLIST_FIRST(&plist)) != NULL) {
		bdi = node->info;
		bgp = bdi->path->peer->bgp;

		/* Set t-diff = t-now - t-updated.  */
		t_diff = t_now - bdi->t_updated;

		/* Set figure-of-merit = figure-of-merit * decay-array-ok
		 * [t-diff] */
		bdi->penalty = bgp_damp_decay(t_diff, bdi->penalty, bdc);

		/* Set t-updated = t-now.  */
		bdi->t_updated = t_now;

		/* if (figure-of-merit < reuse).  */
		if (bdi->penalty < bdc->reuse_limit) {
			/* Reuse the route.  */
			bgp_path_info_unset_flag(bdi->dest, bdi->path,
						 BGP_PATH_DAMPED);
			bdi->suppress_time = 0;

			if (bdi->lastrecord == BGP_RECORD_UPDATE) {
				bgp_path_info_unset_flag(bdi->dest, bdi->path,
							 BGP_PATH_HISTORY);
				bgp_aggregate_increment(
					bgp, bgp_dest_get_prefix(bdi->dest),
					bdi->path, bdi->afi, bdi->safi);
				bgp_process(bgp, bdi->dest, bdi->afi,
					    bdi->safi);
			}

			if (bdi->penalty <= bdc->reuse_limit / 2.0) {
				bgp_damp_info_free(&bdi, bdc, 1, bdi->afi,
						   bdi->safi);
				bgp_reuselist_del(&plist, &node);
			} else {
				node->info->index =
					BGP_DAMP_NO_REUSE_LIST_INDEX;
				bgp_reuselist_switch(&plist, node,
						     &bdc->no_reuse_list);
			}
		} else {
			/* Re-insert into another list (See RFC2439 Section
			 * 4.8.6).  */
			bdi->index = bgp_reuse_index(bdi->penalty, bdc);
			bgp_reuselist_switch(&plist, node,
					     &bdc->reuse_list[bdi->index]);
		}
	}

	assert(SLIST_EMPTY(&plist));

	return 0;
}

/* A route becomes unreachable (RFC2439 Section 4.8.2).  */
int bgp_damp_withdraw(struct bgp_path_info *path, struct bgp_dest *dest,
		      afi_t afi, safi_t safi, int attr_change)
{
	time_t t_now;
	struct bgp_damp_info *bdi = NULL;
	unsigned int last_penalty = 0;
	struct bgp_damp_config *bdc;

	bdc = get_active_bdc_from_pi(path, afi, safi);
	if (!bdc)
		return BGP_DAMP_USED;

	t_now = bgp_clock();
	/* Processing Unreachable Messages.  */
	if (path->extra)
		bdi = path->extra->damp_info;

	if (bdi == NULL) {
		/* If there is no previous stability history. */

		/* RFC2439 said:
		   1. allocate a damping structure.
		   2. set figure-of-merit = 1.
		   3. withdraw the route.  */

		bdi = XCALLOC(MTYPE_BGP_DAMP_INFO,
			      sizeof(struct bgp_damp_info));
		bdi->path = path;
		bdi->dest = dest;
		bdi->penalty =
			(attr_change ? DEFAULT_PENALTY / 2 : DEFAULT_PENALTY);
		bdi->flap = 1;
		bdi->start_time = t_now;
		bdi->suppress_time = 0;
		bdi->index = BGP_DAMP_NO_REUSE_LIST_INDEX;
		bdi->afi = afi;
		bdi->safi = safi;
		(bgp_path_info_extra_get(path))->damp_info = bdi;
		bgp_no_reuse_list_add(bdi, bdc);
	} else {
		bgp_damp_info_claim(bdi, bdc);
		last_penalty = bdi->penalty;

		/* 1. Set t-diff = t-now - t-updated.  */
		bdi->penalty = (bgp_damp_decay(t_now - bdi->t_updated,
					       bdi->penalty, bdc)
				+ (attr_change ? DEFAULT_PENALTY / 2
					       : DEFAULT_PENALTY));

		if (bdi->penalty > bdc->ceiling)
			bdi->penalty = bdc->ceiling;

		bdi->flap++;
	}

	assert((dest == bdi->dest) && (path == bdi->path));

	bdi->lastrecord = BGP_RECORD_WITHDRAW;
	bdi->t_updated = t_now;

	/* Make this route as historical status.  */
	bgp_path_info_set_flag(dest, path, BGP_PATH_HISTORY);

	/* Remove the route from a reuse list if it is on one.  */
	if (CHECK_FLAG(bdi->path->flags, BGP_PATH_DAMPED)) {
		/* If decay rate isn't equal to 0, reinsert brn. */
		if (bdi->penalty != last_penalty) {
			bgp_reuse_list_delete(bdi, bdc);
			bgp_reuse_list_add(bdi, bdc);
		}
		return BGP_DAMP_SUPPRESSED;
	}

	/* If not suppressed before, do annonunce this withdraw and
	   insert into reuse_list.  */
	if (bdi->penalty >= bdc->suppress_value) {
		bgp_path_info_set_flag(dest, path, BGP_PATH_DAMPED);
		bdi->suppress_time = t_now;
		bgp_no_reuse_list_delete(bdi, bdc);
		bgp_reuse_list_add(bdi, bdc);
	}
	return BGP_DAMP_USED;
}

int bgp_damp_update(struct bgp_path_info *path, struct bgp_dest *dest,
		    afi_t afi, safi_t safi)
{
	time_t t_now;
	struct bgp_damp_info *bdi;
	int status;
	struct bgp_damp_config *bdc;

	bdc = get_active_bdc_from_pi(path, afi, safi);
	assert(bdc);

	if (!path->extra || !((bdi = path->extra->damp_info)))
		return BGP_DAMP_USED;

	t_now = bgp_clock();
	bgp_path_info_unset_flag(dest, path, BGP_PATH_HISTORY);

	bdi->lastrecord = BGP_RECORD_UPDATE;
	bdi->penalty =
		bgp_damp_decay(t_now - bdi->t_updated, bdi->penalty, bdc);

	if (!CHECK_FLAG(bdi->path->flags, BGP_PATH_DAMPED)
	    && (bdi->penalty < bdc->suppress_value))
		status = BGP_DAMP_USED;
	else if (CHECK_FLAG(bdi->path->flags, BGP_PATH_DAMPED)
		 && (bdi->penalty < bdc->reuse_limit)) {
		bgp_path_info_unset_flag(dest, path, BGP_PATH_DAMPED);
		bgp_reuse_list_delete(bdi, bdc);
		bgp_no_reuse_list_add(bdi, bdc);
		bdi->suppress_time = 0;
		status = BGP_DAMP_USED;
	} else
		status = BGP_DAMP_SUPPRESSED;

	if (bdi->penalty > bdc->reuse_limit / 2.0)
		bdi->t_updated = t_now;
	else {
		bgp_damp_info_unclaim(bdi);
		bgp_damp_info_free(&bdi, bdc, 0, afi, safi);
	}

	return status;
}

void bgp_damp_info_free(struct bgp_damp_info **bdi, struct bgp_damp_config *bdc,
			int withdraw, afi_t afi, safi_t safi)
{
	assert(bdc && bdi && *bdi);

	if ((*bdi)->path == NULL) {
		XFREE(MTYPE_BGP_DAMP_INFO, (*bdi));
		return;
	}

	(*bdi)->path->extra->damp_info = NULL;
	bgp_path_info_unset_flag((*bdi)->dest, (*bdi)->path,
				 BGP_PATH_HISTORY | BGP_PATH_DAMPED);
	if ((*bdi)->lastrecord == BGP_RECORD_WITHDRAW && withdraw)
		bgp_path_info_delete((*bdi)->dest, (*bdi)->path);
}

static void bgp_damp_parameter_set(int hlife, int reuse, int sup, int maxsup,
				   struct bgp_damp_config *bdc)
{
	double reuse_max_ratio;
	unsigned int i;
	double j;

	bdc->suppress_value = sup;
	bdc->half_life = hlife;
	bdc->reuse_limit = reuse;
	bdc->max_suppress_time = maxsup;

	/* Initialize params per bgp_damp_config. */
	bdc->reuse_index_size = REUSE_ARRAY_SIZE;

	bdc->ceiling = (int)(bdc->reuse_limit
			     * (pow(2, (double)bdc->max_suppress_time
					       / bdc->half_life)));

	/* Decay-array computations */
	bdc->decay_array_size = ceil((double)bdc->max_suppress_time / DELTA_T);
	bdc->decay_array = XMALLOC(MTYPE_BGP_DAMP_ARRAY,
				   sizeof(double) * (bdc->decay_array_size));
	bdc->decay_array[0] = 1.0;
	bdc->decay_array[1] =
		exp((1.0 / ((double)bdc->half_life / DELTA_T)) * log(0.5));

	/* Calculate decay values for all possible times */
	for (i = 2; i < bdc->decay_array_size; i++)
		bdc->decay_array[i] =
			bdc->decay_array[i - 1] * bdc->decay_array[1];

	/* Reuse-list computations */
	i = ceil((double)bdc->max_suppress_time / DELTA_REUSE) + 1;
	if (i > REUSE_LIST_SIZE || i == 0)
		i = REUSE_LIST_SIZE;
	bdc->reuse_list_size = i;

	bdc->reuse_list =
		XCALLOC(MTYPE_BGP_DAMP_ARRAY,
			bdc->reuse_list_size * sizeof(struct reuselist));
	/* Reuse-array computations */
	bdc->reuse_index = XCALLOC(MTYPE_BGP_DAMP_ARRAY,
				   sizeof(int) * bdc->reuse_index_size);

	reuse_max_ratio = (double)bdc->ceiling / bdc->reuse_limit;
	j = (exp((double)bdc->max_suppress_time / bdc->half_life) * log10(2.0));
	if (reuse_max_ratio > j && j != 0)
		reuse_max_ratio = j;

	bdc->scale_factor =
		(double)bdc->reuse_index_size / (reuse_max_ratio - 1);

	for (i = 0; i < bdc->reuse_index_size; i++) {
		bdc->reuse_index[i] =
			(int)(((double)bdc->half_life / DELTA_REUSE)
			      * log10(1.0
				      / (bdc->reuse_limit
					 * (1.0
					    + ((double)i / bdc->scale_factor))))
			      / log10(0.5));
	}
}

int bgp_damp_enable(struct bgp *bgp, afi_t afi, safi_t safi, time_t half,
		    unsigned int reuse, unsigned int suppress, time_t max)
{
	struct bgp_damp_config *bdc = &bgp->damp[afi][safi];

	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)) {
		if (bdc->half_life == half && bdc->reuse_limit == reuse
		    && bdc->suppress_value == suppress
		    && bdc->max_suppress_time == max)
			return 0;
		bgp_damp_disable(bgp, afi, safi);
	}

	SET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING);
	bgp_damp_parameter_set(half, reuse, suppress, max, bdc);
	bdc->afi = afi;
	bdc->safi = safi;

	/* Register reuse timer.  */
	thread_add_timer(bm->master, bgp_reuse_timer, bdc, DELTA_REUSE,
			 &bdc->t_reuse);

	return 0;
}

/* Clean all the bgp_damp_info stored in reuse_list and no_reuse_list. */
void bgp_damp_info_clean(struct bgp_damp_config *bdc, afi_t afi, safi_t safi)
{
	struct bgp_damp_info *bdi;
	struct reuselist_node *rn;
	struct reuselist *list;
	unsigned int i;

	bdc->reuse_offset = 0;
	for (i = 0; i < bdc->reuse_list_size; ++i) {
		list = &bdc->reuse_list[i];
		while ((rn = SLIST_FIRST(list)) != NULL) {
			bdi = rn->info;
			bgp_reuselist_del(list, &rn);
			bgp_damp_info_free(&bdi, bdc, 1, afi, safi);
		}
	}

	while ((rn = SLIST_FIRST(&bdc->no_reuse_list)) != NULL) {
		bdi = rn->info;
		bgp_reuselist_del(&bdc->no_reuse_list, &rn);
		bgp_damp_info_free(&bdi, bdc, 1, afi, safi);
	}

	/* Free decay array */
	XFREE(MTYPE_BGP_DAMP_ARRAY, bdc->decay_array);
	bdc->decay_array_size = 0;

	/* Free reuse index array */
	XFREE(MTYPE_BGP_DAMP_ARRAY, bdc->reuse_index);
	bdc->reuse_index_size = 0;

	/* Free reuse list array. */
	for (i = 0; i < bdc->reuse_list_size; ++i)
		bgp_reuselist_free(&bdc->reuse_list[i]);

	XFREE(MTYPE_BGP_DAMP_ARRAY, bdc->reuse_list);
	bdc->reuse_list_size = 0;

	THREAD_OFF(bdc->t_reuse);
}

/* Disable route flap dampening for a bgp instance.
 *
 * Please note that this function also gets used to free memory when deleting a
 * bgp instance.
 */
int bgp_damp_disable(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_damp_config *bdc;

	bdc = &bgp->damp[afi][safi];
	if (!bdc)
		return 0;

	/* If it wasn't enabled, there's nothing to do. */
	if (!CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING))
		return 0;

	/* Cancel reuse event. */
	thread_cancel(&bdc->t_reuse);

	/* Clean BGP dampening information.  */
	bgp_damp_info_clean(bdc, afi, safi);

	UNSET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING);

	return 0;
}

void bgp_config_write_damp(struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi)
{
	struct bgp_damp_config *bdc;

	bdc = &bgp->damp[afi][safi];
	if (bdc->half_life == DEFAULT_HALF_LIFE * 60
	    && bdc->reuse_limit == DEFAULT_REUSE
	    && bdc->suppress_value == DEFAULT_SUPPRESS
	    && bdc->max_suppress_time == bdc->half_life * 4)
		vty_out(vty, "  bgp dampening\n");
	else if (bdc->half_life != DEFAULT_HALF_LIFE * 60
		 && bdc->reuse_limit == DEFAULT_REUSE
		 && bdc->suppress_value == DEFAULT_SUPPRESS
		 && bdc->max_suppress_time == bdc->half_life * 4)
		vty_out(vty, "  bgp dampening %lld\n", bdc->half_life / 60LL);
	else
		vty_out(vty, "  bgp dampening %lld %d %d %lld\n",
			bdc->half_life / 60LL, bdc->reuse_limit,
			bdc->suppress_value, bdc->max_suppress_time / 60LL);
}

static const char *bgp_get_reuse_time(struct bgp_damp_config *bdc,
				      unsigned int penalty, char *buf,
				      size_t len, bool use_json,
				      json_object *json)
{
	time_t reuse_time = 0;
	struct tm tm;
	int time_store = 0;

	if (penalty > bdc->reuse_limit) {
		reuse_time = (int)(DELTA_T
				   * ((log((double)bdc->reuse_limit / penalty))
				      / (log(bdc->decay_array[1]))));

		if (reuse_time > bdc->max_suppress_time)
			reuse_time = bdc->max_suppress_time;

		gmtime_r(&reuse_time, &tm);
	} else
		reuse_time = 0;

	/* Making formatted timer strings. */
	if (reuse_time == 0) {
		if (use_json)
			json_object_int_add(json, "reuseTimerMsecs", 0);
		else
			snprintf(buf, len, "00:00:00");
	} else if (reuse_time < ONE_DAY_SECOND) {
		if (use_json) {
			time_store = (3600000 * tm.tm_hour)
				     + (60000 * tm.tm_min)
				     + (1000 * tm.tm_sec);
			json_object_int_add(json, "reuseTimerMsecs",
					    time_store);
		} else
			snprintf(buf, len, "%02d:%02d:%02d", tm.tm_hour,
				 tm.tm_min, tm.tm_sec);
	} else if (reuse_time < ONE_WEEK_SECOND) {
		if (use_json) {
			time_store = (86400000 * tm.tm_yday)
				     + (3600000 * tm.tm_hour)
				     + (60000 * tm.tm_min)
				     + (1000 * tm.tm_sec);
			json_object_int_add(json, "reuseTimerMsecs",
					    time_store);
		} else
			snprintf(buf, len, "%dd%02dh%02dm", tm.tm_yday,
				 tm.tm_hour, tm.tm_min);
	} else {
		if (use_json) {
			time_store =
				(604800000 * tm.tm_yday / 7)
				+ (86400000
				   * (tm.tm_yday - ((tm.tm_yday / 7) * 7)))
				+ (3600000 * tm.tm_hour) + (60000 * tm.tm_min)
				+ (1000 * tm.tm_sec);
			json_object_int_add(json, "reuseTimerMsecs",
					    time_store);
		} else
			snprintf(buf, len, "%02dw%dd%02dh", tm.tm_yday / 7,
				 tm.tm_yday - ((tm.tm_yday / 7) * 7),
				 tm.tm_hour);
	}

	return buf;
}

void bgp_damp_info_vty(struct vty *vty, struct bgp *bgp,
		       struct bgp_path_info *path, afi_t afi, safi_t safi,
		       json_object *json_path)
{
	struct bgp_damp_info *bdi;
	time_t t_now, t_diff;
	char timebuf[BGP_UPTIME_LEN];
	int penalty;
	struct bgp_damp_config *bdc = &bgp->damp[afi][safi];

	if (!path->extra)
		return;

	/* BGP dampening information.  */
	bdi = path->extra->damp_info;

	/* If dampening is not enabled or there is no dampening information,
	   return immediately.  */
	if (!bdc || !bdi)
		return;

	/* Calculate new penalty.  */
	t_now = bgp_clock();
	t_diff = t_now - bdi->t_updated;
	penalty = bgp_damp_decay(t_diff, bdi->penalty, bdc);

	if (json_path) {
		json_object_int_add(json_path, "dampeningPenalty", penalty);
		json_object_int_add(json_path, "dampeningFlapCount", bdi->flap);
		peer_uptime(bdi->start_time, timebuf, BGP_UPTIME_LEN, 1,
			    json_path);

		if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)
		    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			bgp_get_reuse_time(bdc, penalty, timebuf,
					   BGP_UPTIME_LEN, 1, json_path);
	} else {
		vty_out(vty,
			"      Dampinfo: penalty %d, flapped %d times in %s",
			penalty, bdi->flap,
			peer_uptime(bdi->start_time, timebuf, BGP_UPTIME_LEN, 0,
				    json_path));

		if (CHECK_FLAG(path->flags, BGP_PATH_DAMPED)
		    && !CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			vty_out(vty, ", reuse in %s",
				bgp_get_reuse_time(bdc, penalty, timebuf,
						   BGP_UPTIME_LEN, 0,
						   json_path));

		vty_out(vty, "\n");
	}
}


const char *bgp_damp_reuse_time_vty(struct vty *vty, struct bgp_path_info *path,
				    char *timebuf, size_t len, afi_t afi,
				    safi_t safi, bool use_json,
				    json_object *json)
{
	struct bgp_damp_info *bdi;
	time_t t_now, t_diff;
	int penalty;
	struct bgp_damp_config *bdc;

	bdc = get_active_bdc_from_pi(path, afi, safi);
	if (!bdc)
		return NULL;

	if (!path->extra)
		return NULL;

	/* BGP dampening information.  */
	bdi = path->extra->damp_info;

	/* If dampening is not enabled or there is no dampening information,
	   return immediately.  */
	if (!bdc || !bdi)
		return NULL;

	/* Calculate new penalty.  */
	t_now = bgp_clock();
	t_diff = t_now - bdi->t_updated;
	penalty = bgp_damp_decay(t_diff, bdi->penalty, bdc);

	return bgp_get_reuse_time(bdc, penalty, timebuf, len, use_json, json);
}


static int bgp_print_dampening_parameters(struct bgp *bgp, struct vty *vty,
					  afi_t afi, safi_t safi)
{
	struct bgp_damp_config *bdc;
	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)) {
		bdc = &bgp->damp[afi][safi];
		vty_out(vty, "Half-life time: %lld min\n",
			(long long)bdc->half_life / 60);
		vty_out(vty, "Reuse penalty: %d\n", bdc->reuse_limit);
		vty_out(vty, "Suppress penalty: %d\n", bdc->suppress_value);
		vty_out(vty, "Max suppress time: %lld min\n",
			(long long)bdc->max_suppress_time / 60);
		vty_out(vty, "Max suppress penalty: %u\n", bdc->ceiling);
		vty_out(vty, "\n");
	} else
		vty_out(vty, "dampening not enabled for %s\n",
			get_afi_safi_str(afi, safi, false));

	return CMD_SUCCESS;
}

int bgp_show_dampening_parameters(struct vty *vty, afi_t afi, safi_t safi,
				  uint8_t show_flags)
{
	struct bgp *bgp;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		vty_out(vty, "No BGP process is configured\n");
		return CMD_WARNING;
	}

	if (!CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_ALL))
		return bgp_print_dampening_parameters(bgp, vty, afi, safi);

	if (CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP)
	    || CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP6)) {
		afi = CHECK_FLAG(show_flags, BGP_SHOW_OPT_AFI_IP) ? AFI_IP
								  : AFI_IP6;
		FOREACH_SAFI (safi) {
			if (strmatch(get_afi_safi_str(afi, safi, true),
				     "Unknown"))
				continue;

			if (!CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON))
				vty_out(vty, "\nFor address family: %s\n\n",
					get_afi_safi_str(afi, safi, false));

			bgp_print_dampening_parameters(bgp, vty, afi, safi);
		}
	} else {
		FOREACH_AFI_SAFI (afi, safi) {
			if (strmatch(get_afi_safi_str(afi, safi, true),
				     "Unknown"))
				continue;

			if (!CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON))
				vty_out(vty, "\nFor address family: %s\n",
					get_afi_safi_str(afi, safi, false));

			bgp_print_dampening_parameters(bgp, vty, afi, safi);
		}
	}
	return CMD_SUCCESS;
}

void bgp_peer_damp_enable(struct peer *peer, afi_t afi, safi_t safi,
			  time_t half, unsigned int reuse,
			  unsigned int suppress, time_t max)
{
	struct bgp_damp_config *bdc;

	if (!peer)
		return;
	bdc = &peer->damp[afi][safi];
	if (peer_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_DAMPENING)) {
		if (bdc->half_life == half && bdc->reuse_limit == reuse
		    && bdc->suppress_value == suppress
		    && bdc->max_suppress_time == max)
			return;
		bgp_peer_damp_disable(peer, afi, safi);
	}
	SET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_CONFIG_DAMPENING);
	bgp_damp_parameter_set(half, reuse, suppress, max, bdc);
	bdc->afi = afi;
	bdc->safi = safi;
	thread_add_timer(bm->master, bgp_reuse_timer, bdc, DELTA_REUSE,
			 &bdc->t_reuse);
}

/* Disable route flap dampening for a peer.
 *
 * Please note that this function also gets used to free memory when deleting a
 * peer or peer group.
 */
void bgp_peer_damp_disable(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_damp_config *bdc;

	if (!peer_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_DAMPENING))
		return;
	bdc = &peer->damp[afi][safi];
	if (!bdc)
		return;
	bgp_damp_info_clean(bdc, afi, safi);
	UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_CONFIG_DAMPENING);
}

void bgp_config_write_peer_damp(struct vty *vty, struct peer *peer, afi_t afi,
				safi_t safi)
{
	struct bgp_damp_config *bdc;

	bdc = &peer->damp[afi][safi];
	if (bdc->half_life == DEFAULT_HALF_LIFE * 60
	    && bdc->reuse_limit == DEFAULT_REUSE
	    && bdc->suppress_value == DEFAULT_SUPPRESS
	    && bdc->max_suppress_time == bdc->half_life * 4)
		vty_out(vty, "  neighbor %s dampening\n", peer->host);
	else if (bdc->half_life != DEFAULT_HALF_LIFE * 60
		 && bdc->reuse_limit == DEFAULT_REUSE
		 && bdc->suppress_value == DEFAULT_SUPPRESS
		 && bdc->max_suppress_time == bdc->half_life * 4)
		vty_out(vty, "  neighbor %s dampening %lld\n", peer->host,
			bdc->half_life / 60LL);
	else
		vty_out(vty, "  neighbor %s dampening %lld %d %d %lld\n",
			peer->host, bdc->half_life / 60LL, bdc->reuse_limit,
			bdc->suppress_value, bdc->max_suppress_time / 60LL);
}

static void bgp_print_peer_dampening_parameters(struct vty *vty,
						struct peer *peer, afi_t afi,
						safi_t safi, bool use_json,
						json_object *json)
{
	struct bgp_damp_config *bdc;

	if (!peer)
		return;
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_CONFIG_DAMPENING)) {
		bdc = &peer->damp[afi][safi];
		if (!bdc)
			return;
		if (use_json) {
			json_object_int_add(json, "halfLifeSecs",
					    bdc->half_life);
			json_object_int_add(json, "reusePenalty",
					    bdc->reuse_limit);
			json_object_int_add(json, "suppressPenalty",
					    bdc->suppress_value);
			json_object_int_add(json, "maxSuppressTimeSecs",
					    bdc->max_suppress_time);
			json_object_int_add(json, "maxSuppressPenalty",
					    bdc->ceiling);
		} else {
			vty_out(vty, "Half-life time: %lld min\n",
				(long long)bdc->half_life / 60);
			vty_out(vty, "Reuse penalty: %d\n", bdc->reuse_limit);
			vty_out(vty, "Suppress penalty: %d\n",
				bdc->suppress_value);
			vty_out(vty, "Max suppress time: %lld min\n",
				(long long)bdc->max_suppress_time / 60);
			vty_out(vty, "Max suppress penalty: %u\n",
				bdc->ceiling);
			vty_out(vty, "\n");
		}
	} else if (!use_json)
		vty_out(vty, "neighbor dampening not enabled for %s\n",
			get_afi_safi_str(afi, safi, false));
}

void bgp_show_peer_dampening_parameters(struct vty *vty, struct peer *peer,
					afi_t afi, safi_t safi, bool use_json)
{
	json_object *json;

	if (use_json) {
		json = json_object_new_object();
		json_object_string_add(json, "addressFamily",
				       get_afi_safi_str(afi, safi, false));
		bgp_print_peer_dampening_parameters(vty, peer, afi, safi, true,
						    json);
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		vty_out(vty, "\nFor address family: %s\n",
			get_afi_safi_str(afi, safi, false));
		bgp_print_peer_dampening_parameters(vty, peer, afi, safi, false,
						    NULL);
	}
}
