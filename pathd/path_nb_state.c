/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sascha Kattelmann
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "northbound.h"
#include "libfrr.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
const void *pathd_te_segment_list_get_next(struct nb_cb_get_next_args *args)
{
	struct te_segment_list *te_segment_list =
		(struct te_segment_list *)args->list_entry;

	if (args->list_entry == NULL)
		te_segment_list = RB_MIN(te_segment_list_instance_head,
					 &te_segment_list_instances);
	else
		te_segment_list =
			RB_NEXT(te_segment_list_instance_head, te_segment_list);

	return te_segment_list;
}

int pathd_te_segment_list_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct te_segment_list *te_segment_list =
		(struct te_segment_list *)args->list_entry;

	args->keys->num = 1;

	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%s",
		 te_segment_list->name);

	return NB_OK;
}

const void *
pathd_te_segment_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return te_segment_list_get(args->keys->key[0]);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
const void *pathd_te_sr_policy_get_next(struct nb_cb_get_next_args *args)
{
	struct te_sr_policy *te_sr_policy = (struct te_sr_policy *)args->list_entry;

	if (args->list_entry == NULL)
		te_sr_policy = RB_MIN(te_sr_policy_instance_head,
				      &te_sr_policy_instances);
	else
		te_sr_policy =
			RB_NEXT(te_sr_policy_instance_head, te_sr_policy);

	return te_sr_policy;
}

int pathd_te_sr_policy_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct te_sr_policy *te_sr_policy =
		(struct te_sr_policy *)args->list_entry;

	args->keys->num = 2;

	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 te_sr_policy->color);

	(void)inet_ntop(AF_INET, &te_sr_policy->endpoint, args->keys->key[1],
			sizeof(args->keys->key[1]));

	return NB_OK;
}

const void *pathd_te_sr_policy_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	uint32_t color;
	struct ipaddr endpoint;

	color = yang_str2uint32(args->keys->key[0]);
	yang_str2ip(args->keys->key[1], &endpoint);

	return te_sr_policy_get(color, &endpoint);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
const void *
pathd_te_sr_policy_candidate_path_get_next(struct nb_cb_get_next_args *args)
{
	struct te_sr_policy *te_sr_policy =
		(struct te_sr_policy *)args->parent_list_entry;
	struct te_candidate_path *te_candidate_path =
		(struct te_candidate_path *)args->list_entry;

	if (args->list_entry == NULL)
		te_candidate_path = RB_MIN(te_candidate_path_instance_head,
					   &te_sr_policy->candidate_paths);
	else
		te_candidate_path = RB_NEXT(te_candidate_path_instance_head,
					    te_candidate_path);

	return te_candidate_path;
}

int pathd_te_sr_policy_candidate_path_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct te_candidate_path *te_candidate_path =
		(struct te_candidate_path *)args->list_entry;

	args->keys->num = 1;

	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 te_candidate_path->preference);

	return NB_OK;
}

const void *pathd_te_sr_policy_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	uint32_t preference;

	struct te_sr_policy *te_sr_policy =
		(struct te_sr_policy *)args->parent_list_entry;

	preference = yang_str2uint32(args->keys->key[0]);

	return find_candidate_path(te_sr_policy, preference);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate_path/is-best-candidate-path
 */
struct yang_data *
pathd_te_sr_policy_candidate_path_is_best_candidate_path_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct te_candidate_path *te_candidate_path =
		(struct te_candidate_path *)args->list_entry;

	return yang_data_new_bool(args->xpath,
				  te_candidate_path->is_best_candidate_path);
}
