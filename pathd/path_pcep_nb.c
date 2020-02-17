/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#include <northbound.h>
#include <yang.h>
#include <printfrr.h>
#include "pathd/pathd.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define MAX_XPATH 256

struct path_nb_list_path_cb_arg {
	void *arg;
	path_list_cb_t cb;
};


static int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg);
static struct path_hop *
path_nb_list_path_hops(struct srte_segment_list *segment_list);

static int path_nb_commit_candidate_config(struct nb_config *candidate_config,
					   const char *comment);
static void path_nb_edit_candidate_config(struct nb_config *candidate_config,
					  const char *xpath,
					  enum nb_operation operation,
					  const char *value);
static void path_nb_add_segment_list_segment(struct nb_config *config,
					     const char *segment_list_name,
					     uint32_t index, uint32_t label);
static void path_nb_create_segment_list(struct nb_config *config,
					const char *segment_list_name);
static void path_nb_add_candidate_path(struct nb_config *config, uint32_t color,
				       struct ipaddr *endpoint,
				       struct ipaddr *originator,
				       uint32_t discriminator,
				       uint32_t preference,
				       const char *segment_list_name);
static enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status);


struct path *path_nb_get_path(uint32_t color, struct ipaddr endpoint,
			      uint32_t preference)
{
	char xpath[XPATH_MAXLEN];
	char endpoint_str[40];
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	ipaddr2str(&endpoint, endpoint_str, sizeof(endpoint_str));
	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/sr-policy[color='%d'][endpoint='%s']", color,
		 endpoint_str);

	policy = nb_running_get_entry(NULL, xpath, false);
	if (NULL == policy)
		return NULL;

	candidate = srte_candidate_find(policy, preference);
	if (NULL == candidate)
		return NULL;

	return candidate_to_path(candidate);
}

void path_nb_list_path(path_list_cb_t cb, void *arg)
{
	struct path_nb_list_path_cb_arg int_arg = {.arg = arg, .cb = cb};
	yang_dnode_iterate(path_nb_list_path_cb, &int_arg,
			   running_config->dnode, "/frr-pathd:pathd/sr-policy");
}

int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg)
{
	struct path *path;
	path_list_cb_t cb = ((struct path_nb_list_path_cb_arg *)int_arg)->cb;
	void *ext_arg = ((struct path_nb_list_path_cb_arg *)int_arg)->arg;
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	policy = nb_running_get_entry(dnode, NULL, true);
	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) {
		path = candidate_to_path(candidate);
		if (!cb(path, ext_arg))
			return 0;
	}

	return 1;
}

struct path *candidate_to_path(struct srte_candidate *candidate)
{
	char *name;
	struct path *path;
	struct path_hop *hop;
	struct srte_policy *policy;
	struct srte_segment_list *segment_list, key = {};
	enum pcep_lsp_operational_status status;
	bool is_delegated;

	policy = candidate->policy;
	hop = NULL;

	if (NULL != candidate->segment_list) {
		strlcpy(key.name, candidate->segment_list->name,
			sizeof(key.name));
		segment_list = RB_FIND(srte_segment_list_head,
				       &srte_segment_lists, &key);
		assert(NULL != segment_list);
		hop = path_nb_list_path_hops(segment_list);
	}
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	name = asprintfrr(MTYPE_PCEP, "%s-%s", policy->name, candidate->name);
	if (candidate->is_best_candidate_path) {
		status = status_int_to_ext(policy->status);
	} else {
		status = PCEP_LSP_OPERATIONAL_DOWN;
	}
	switch (candidate->type) {
	case SRTE_CANDIDATE_TYPE_DYNAMIC:
		is_delegated = true;
		break;
	case SRTE_CANDIDATE_TYPE_EXPLICIT:
	default:
		is_delegated = false;
		break;
	}
	*path = (struct path){
		.nbkey = (struct lsp_nb_key){.color = policy->color,
					     .endpoint = policy->endpoint,
					     .preference =
						     candidate->preference},
		.plsp_id = 0,
		.name = name,
		.srp_id = 0,
		.status = status,
		.do_remove = false,
		.go_active = false,
		.was_created = candidate->protocol_origin == SRTE_ORIGIN_PCEP,
		.was_removed = false,
		.is_synching = false,
		.is_delegated = is_delegated,
		.first = hop};

	return path;
}

struct path_hop *path_nb_list_path_hops(struct srte_segment_list *segment_list)
{
	struct srte_segment_entry *segment;
	struct path_hop *hop, *last_hop = NULL;
	RB_FOREACH_REVERSE (segment, srte_segment_entry_head,
			    &segment_list->segments) {
		hop = XCALLOC(MTYPE_PCEP, sizeof(*hop));
		*hop = (struct path_hop){
			.next = last_hop,
			.is_loose = false,
			.has_sid = true,
			.is_mpls = true,
			.has_attribs = false,
			.sid = {.mpls = {.label = segment->sid_value}},
			.has_nai = false};
		last_hop = hop;
	}
	return hop;
}

void path_nb_update_path(struct path *path)
{
	assert(NULL != path);
	assert(0 != path->nbkey.preference);
	assert(IPADDR_V4 == path->nbkey.endpoint.ipa_type);

	struct path_hop *hop;
	int index;
	char segment_list_name_buff[11];
	char *segment_list_name = NULL;
	struct nb_config *config = nb_config_dup(running_config);

	if (NULL != path->first) {
		snprintf(segment_list_name_buff, sizeof(segment_list_name_buff),
			 "%u", (uint32_t)rand());
		segment_list_name = segment_list_name_buff;
		path_nb_create_segment_list(config, segment_list_name);
		for (hop = path->first, index = 10; NULL != hop;
		     hop = hop->next, index += 10) {
			assert(hop->has_sid);
			assert(hop->is_mpls);
			path_nb_add_segment_list_segment(
				config, segment_list_name, index,
				hop->sid.mpls.label);
		}
	}

	path_nb_add_candidate_path(
		config, path->nbkey.color, &path->nbkey.endpoint, &path->sender,
		(uint32_t)rand(), path->nbkey.preference, segment_list_name);

	path_nb_commit_candidate_config(config, "SR Policy Candidate Path");
	nb_config_free(config);
}

int path_nb_commit_candidate_config(struct nb_config *candidate_config,
				    const char *comment)
{
	int ret = nb_candidate_commit(candidate_config, NB_CLIENT_PCEP, NULL,
				      false, comment, NULL);
	if (ret != NB_OK && ret != NB_ERR_NO_CHANGES)
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

void path_nb_edit_candidate_config(struct nb_config *candidate_config,
				   const char *xpath,
				   enum nb_operation operation,
				   const char *value)
{
	struct nb_node *nb_node;
	struct yang_data *data;

	/* Find the northbound node associated to the data path. */
	nb_node = nb_node_find(xpath);

	data = yang_data_new(xpath, value);

	/*
	 * Ignore "not found" errors when editing the candidate
	 * configuration.
	 */
	nb_candidate_edit(candidate_config, nb_node, operation, xpath, NULL,
			  data);

	yang_data_free(data);
}

void path_nb_add_segment_list_segment(struct nb_config *config,
				      const char *segment_list_name,
				      uint32_t index, uint32_t label)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char label_str[(sizeof(uint32_t) * 8) + 1];

	snprintf(label_str, sizeof(label_str), "%u", label);

	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']",
		 segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/sid-value", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, label_str);
}

void path_nb_create_segment_list(struct nb_config *config,
				 const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']", segment_list_name);
	path_nb_edit_candidate_config(config, xpath, NB_OP_CREATE, NULL);
}

void path_nb_add_candidate_path(struct nb_config *config, uint32_t color,
				struct ipaddr *endpoint,
				struct ipaddr *originator,
				uint32_t discriminator, uint32_t preference,
				const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	char xpath_base[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];
	char originator_str[INET_ADDRSTRLEN];
	char discriminator_str[(sizeof(uint32_t) * 8) + 1];

	ipaddr2str(endpoint, endpoint_str, sizeof(endpoint_str));
	ipaddr2str(originator, originator_str, sizeof(originator_str));
	snprintf(discriminator_str, sizeof(discriminator_str), "%u",
		 discriminator);

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']",
		color, endpoint_str, preference);

	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/segment-list-name", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      segment_list_name);

	snprintf(xpath, sizeof(xpath), "%s/protocol-origin", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, "pcep");

	snprintf(xpath, sizeof(xpath), "%s/originator", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      originator_str);

	snprintf(xpath, sizeof(xpath), "%s/discriminator", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      discriminator_str);

	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, "dynamic");
}

enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status)
{
	switch (status) {
	case SRTE_POLICY_STATUS_UP:
		return PCEP_LSP_OPERATIONAL_ACTIVE;
	case SRTE_POLICY_STATUS_GOING_UP:
		return PCEP_LSP_OPERATIONAL_GOING_UP;
	case SRTE_POLICY_STATUS_GOING_DOWN:
		return PCEP_LSP_OPERATIONAL_GOING_DOWN;
	default:
		return PCEP_LSP_OPERATIONAL_DOWN;
	}
}
