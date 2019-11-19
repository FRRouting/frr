/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "northbound.h"
#include "libfrr.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
int pathd_te_segment_list_create(struct nb_cb_create_args *args)
{
	struct te_segment_list *te_segment_list;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./name");
	te_segment_list = te_segment_list_create(strdup(name));
	nb_running_set_entry(args->dnode, te_segment_list);

	return NB_OK;
}

int pathd_te_segment_list_destroy(struct nb_cb_destroy_args *args)
{
	struct te_segment_list *te_segment_list;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list = nb_running_unset_entry(args->dnode);
	te_segment_list_del(te_segment_list);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/label
 */
int pathd_te_segment_list_label_create(struct nb_cb_create_args *args)
{
	mpls_label_t label;
	struct te_segment_list *te_segment_list;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list = nb_running_get_entry(args->dnode, NULL, true);
	label = yang_dnode_get_uint32(args->dnode, NULL);
	te_segment_list_label_add(te_segment_list, label);

	return NB_OK;
}

int pathd_te_segment_list_label_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int pathd_te_segment_list_label_move(struct nb_cb_move_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
int pathd_te_sr_policy_create(struct nb_cb_create_args *args)
{
	struct te_sr_policy *te_sr_policy;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./name");
	te_sr_policy = te_sr_policy_create(strdup(name));
	nb_running_set_entry(args->dnode, te_sr_policy);

	return NB_OK;
}

int pathd_te_sr_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct te_sr_policy *te_sr_policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_unset_entry(args->dnode);
	te_sr_policy_del(te_sr_policy);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/color
 */
int pathd_te_sr_policy_color_modify(struct nb_cb_modify_args *args)
{
	uint32_t color;
	struct te_sr_policy *te_sr_policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(args->dnode, NULL, true);
	color = yang_dnode_get_uint32(args->dnode, NULL);
	te_sr_policy_color_add(te_sr_policy, color);

	return NB_OK;
}

int pathd_te_sr_policy_color_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/endpoint
 */
int pathd_te_sr_policy_endpoint_modify(struct nb_cb_modify_args *args)
{
	struct ipaddr endpoint;
	struct te_sr_policy *te_sr_policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ip(&endpoint, args->dnode, NULL);
	te_sr_policy_endpoint_add(te_sr_policy, &endpoint);

	return NB_OK;
}

int pathd_te_sr_policy_endpoint_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
int pathd_te_sr_policy_binding_sid_modify(struct nb_cb_modify_args *args)
{
	mpls_label_t binding_sid;
	struct te_sr_policy *te_sr_policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(args->dnode, NULL, true);
	binding_sid = yang_dnode_get_uint32(args->dnode, NULL);
	te_sr_policy_binding_sid_add(te_sr_policy, binding_sid);

	return NB_OK;
}

int pathd_te_sr_policy_binding_sid_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
int pathd_te_sr_policy_candidate_path_create(struct nb_cb_create_args *args)
{
	struct te_sr_policy *te_sr_policy;
	uint32_t preference;
	const char *segment_list_name;
	enum te_protocol_origin protocol_origin;
	struct ipaddr originator;
	bool dynamic_flag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(args->dnode, NULL, true);
	preference = yang_dnode_get_uint32(args->dnode, "./preference");
	segment_list_name = yang_dnode_get_string(args->dnode,
						  "./segment-list-name");
	protocol_origin = yang_dnode_get_enum(args->dnode, "./protocol-origin");
	yang_dnode_get_ip(&originator, args->dnode, "./originator");
	dynamic_flag = yang_dnode_get_bool(args->dnode, "./dynamic-flag");
	te_sr_policy_candidate_path_add(
		te_sr_policy, preference, strdup(segment_list_name),
		protocol_origin, &originator, dynamic_flag);

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/protocol-origin
 */
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_protocol_origin_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/originator
 */
int pathd_te_sr_policy_candidate_path_originator_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_originator_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/dynamic-flag
 */
int pathd_te_sr_policy_candidate_path_dynamic_flag_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_dynamic_flag_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/segment-list-name
 */
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}
