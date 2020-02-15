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
	struct srte_segment_list *segment_list;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./name");
	segment_list = srte_segment_list_add(name);
	nb_running_set_entry(args->dnode, segment_list);

	return NB_OK;
}

int pathd_te_segment_list_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_segment_list *segment_list;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_unset_entry(args->dnode);
	srte_segment_list_del(segment_list);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
int pathd_te_segment_list_segment_create(struct nb_cb_create_args *args)
{
	struct srte_segment_list *segment_list;
	struct srte_segment_entry *segment;
	uint32_t index;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(args->dnode, NULL, true);
	index = yang_dnode_get_uint32(args->dnode, "./index");
	segment = srte_segment_entry_add(segment_list, index);
	nb_running_set_entry(args->dnode, segment);

	return NB_OK;
}

int pathd_te_segment_list_segment_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_segment_list *segment_list;
	struct srte_segment_entry *segment;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(args->dnode, NULL, true);
	segment = nb_running_unset_entry(args->dnode);
	srte_segment_entry_del(segment_list, segment);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment/sid-value
 */
int pathd_te_segment_list_segment_sid_value_modify(
	struct nb_cb_modify_args *args)
{
	mpls_label_t sid_value;
	struct srte_segment_entry *segment;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment = nb_running_get_entry(args->dnode, NULL, true);
	sid_value = yang_dnode_get_uint32(args->dnode, NULL);
	segment->sid_value = sid_value;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
int pathd_te_sr_policy_create(struct nb_cb_create_args *args)
{
	struct srte_policy *policy;
	uint32_t color;
	struct ipaddr endpoint;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	color = yang_dnode_get_uint32(args->dnode, "./color");
	yang_dnode_get_ip(&endpoint, args->dnode, "./endpoint");
	policy = srte_policy_add(color, &endpoint);

	nb_running_set_entry(args->dnode, policy);

	return NB_OK;
}

int pathd_te_sr_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_unset_entry(args->dnode);
	srte_policy_del(policy);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/name
 */
int pathd_te_sr_policy_name_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(policy->name, name, sizeof(policy->name));

	return NB_OK;
}

int pathd_te_sr_policy_name_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	policy->name[0] = '\0';

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
int pathd_te_sr_policy_binding_sid_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	mpls_label_t binding_sid;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	binding_sid = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (path_zebra_request_label(binding_sid) < 0)
			return NB_ERR_RESOURCE;
		break;
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srte_policy_update_binding_sid(policy, binding_sid);
		break;
	}

	return NB_OK;
}

int pathd_te_sr_policy_binding_sid_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	srte_policy_update_binding_sid(policy, MPLS_LABEL_NONE);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
int pathd_te_sr_policy_candidate_path_create(struct nb_cb_create_args *args)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;
	uint32_t preference;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	preference = yang_dnode_get_uint32(args->dnode, "./preference");
	candidate = srte_candidate_add(policy, preference);
	nb_running_set_entry(args->dnode, candidate);

	return NB_OK;
}

void pathd_te_sr_policy_candidate_path_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct srte_candidate *candidate;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	srte_candidate_set_active(candidate->policy, candidate);
}

int pathd_te_sr_policy_candidate_path_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	srte_candidate_del(candidate);

	srte_candidate_set_active(candidate->policy, candidate);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/name
 */
int pathd_te_sr_policy_candidate_path_name_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(candidate->name, name, sizeof(candidate->name));

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/protocol-origin
 */
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	enum srte_protocol_origin protocol_origin;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	protocol_origin = yang_dnode_get_enum(args->dnode, NULL);
	candidate->protocol_origin = protocol_origin;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/originator
 */
int pathd_te_sr_policy_candidate_path_originator_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	struct ipaddr originator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ip(&originator, args->dnode, NULL);
	candidate->originator = originator;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/discriminator
 */
int pathd_te_sr_policy_candidate_path_discriminator_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	uint32_t discriminator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	discriminator = yang_dnode_get_uint32(args->dnode, NULL);
	candidate->discriminator = discriminator;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/type
 */
int pathd_te_sr_policy_candidate_path_type_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	enum srte_candidate_type type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, NULL);
	candidate->type = type;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/segment-list-name
 */
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	const char *segment_list_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	segment_list_name = yang_dnode_get_string(args->dnode, NULL);
	candidate->segment_list = srte_segment_list_find(segment_list_name);
	assert(candidate->segment_list);

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	candidate->segment_list = NULL;

	return NB_OK;
}
