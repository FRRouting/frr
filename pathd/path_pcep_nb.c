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

typedef struct path_nb_list_path_cb_arg_t_ {
	void *arg;
	path_list_cb_t cb;
} path_nb_list_path_cb_arg_t;


static int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg);
static path_hop_t *path_nb_list_path_hops(struct te_segment_list *segment_list);

void path_nb_list_path(path_list_cb_t cb, void *arg)
{
	path_nb_list_path_cb_arg_t int_arg = {.arg = arg, .cb = cb};
	yang_dnode_iterate(path_nb_list_path_cb, &int_arg,
			   running_config->dnode, "/frr-pathd:pathd/sr-policy");
}

int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg)
{
	char *name;
	path_t *path;
	path_hop_t *hop;
	path_list_cb_t cb = ((path_nb_list_path_cb_arg_t *)int_arg)->cb;
	void *ext_arg = ((path_nb_list_path_cb_arg_t *)int_arg)->arg;
	struct te_sr_policy *policy;
	struct te_candidate_path *candidate;
	struct te_segment_list *segment_list, key;
	enum pcep_lsp_operational_status status;

	policy = nb_running_get_entry(dnode, NULL, true);
	PCEP_DEBUG("== POLICY: %s", policy->name);
	RB_FOREACH (candidate, te_candidate_path_instance_head,
		    &policy->candidate_paths) {
		PCEP_DEBUG("== CANDIDATE: %s", candidate->name);
		key = (struct te_segment_list){
			.name = candidate->segment_list_name};
		segment_list = RB_FIND(te_segment_list_instance_head,
				       &te_segment_list_instances, &key);
		assert(NULL != segment_list);
		PCEP_DEBUG("== SEGMENTS: %s", segment_list->name);
		hop = path_nb_list_path_hops(segment_list);
		path = XCALLOC(MTYPE_PCEP, sizeof(*path));
		name = asprintfrr(MTYPE_PCEP, "%s/%s", policy->name,
				  candidate->name);
		// FIXME: operational status should come from the operational
		// data
		if (candidate->is_best_candidate_path) {
			status = PCEP_LSP_OPERATIONAL_UP;
		} else {
			status = PCEP_LSP_OPERATIONAL_DOWN;
		}
		*path = (path_t){
			.nbkey = (lsp_nb_key_t){.color = policy->color,
						.endpoint = policy->endpoint,
						.preference =
							candidate->preference},
			.plsp_id = 0,
			.name = name,
			.srp_id = 0,
			.status = status,
			.do_remove = false,
			.go_active = false,
			.was_created = false,
			.was_removed = false,
			.is_synching = true,
			.is_delegated = false,
			.first = hop};
		if (!cb(path, ext_arg))
			return 0;
	}

	// RB_FIND(bgp_adj_out_rb, &rn->adj_out, &lookup);

	// hop1 = XCALLOC(MTYPE_PCEP, sizeof(*hop1));
	// *hop1 = (path_hop_t) {
	// 	.next = NULL,
	// 	.is_loose = false,
	// 	.has_sid = true,
	// 	.is_mpls = true,
	// 	.has_attribs = false,
	// 	.sid = {
	// 		.mpls = {
	// 			.label = 16060,
	// 			.traffic_class = 0,
	// 			.is_bottom = true,
	// 			.ttl = 0
	// 		}
	// 	},
	// 	.has_nai = true,
	// 	.nai_type = PCEP_SR_SUBOBJ_NAI_IPV4_NODE,
	// 	.nai = { .ipv4_node = { .addr = addr_r6 } }
	// };
	// path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	// *path = (path_t) {
	// 	.name = XSTRDUP(MTYPE_PCEP, "foob"),
	// 	.srp_id = 0,
	// 	.plsp_id = 42,
	// 	.status = PCEP_LSP_OPERATIONAL_UP,
	// 	.do_remove = false,
	// 	.go_active = false,
	// 	.was_created = false,
	// 	.was_removed = false,
	// 	.is_synching = true,
	// 	.is_delegated = true,
	// 	.first = hop1
	// };

	return 1;
}

path_hop_t *path_nb_list_path_hops(struct te_segment_list *segment_list)
{
	return NULL;
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

int path_nb_add_segment_list_segment(const char *segment_list_name,
				     uint32_t index, uint32_t label)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char label_str[(sizeof(uint32_t) * 8) + 1];
	int ret;

	struct nb_config *candidate_config = nb_config_dup(running_config);

	snprintf(label_str, sizeof(label_str), "%u", label);

	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']",
		 segment_list_name, index);
	path_nb_edit_candidate_config(candidate_config, xpath_base,
				      NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/sid-value", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      label_str);

	ret = path_nb_commit_candidate_config(candidate_config,
					      "Segment List Label");

	nb_config_free(candidate_config);

	return ret;
}

int path_nb_create_segment_list(const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	struct nb_config *candidate_config = nb_config_dup(running_config);

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']", segment_list_name);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_CREATE,
				      NULL);

	ret = path_nb_commit_candidate_config(candidate_config, "Segment List");

	nb_config_free(candidate_config);

	return ret;
}

int path_nb_add_candidate_path(uint32_t color, struct ipaddr *endpoint,
			       struct ipaddr *originator,
			       uint32_t discriminator, uint32_t preference,
			       const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	char xpath_base[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];
	char originator_str[INET_ADDRSTRLEN];
	char discriminator_str[(sizeof(uint32_t) * 8) + 1];
	int ret;

	ipaddr2str(endpoint, endpoint_str, sizeof(endpoint_str));
	ipaddr2str(originator, originator_str, sizeof(originator_str));
	snprintf(discriminator_str, sizeof(discriminator_str), "%u",
		 discriminator);

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']",
		color, endpoint_str, preference);

	struct nb_config *candidate_config = nb_config_dup(running_config);

	path_nb_edit_candidate_config(candidate_config, xpath_base,
				      NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/segment-list-name", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      segment_list_name);

	snprintf(xpath, sizeof(xpath), "%s/protocol-origin", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      "pcep");

	snprintf(xpath, sizeof(xpath), "%s/originator", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      originator_str);

	snprintf(xpath, sizeof(xpath), "%s/discriminator", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      discriminator_str);

	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      "dynamic");

	ret = path_nb_commit_candidate_config(candidate_config,
					      "SR Policy Candidate Path");

	nb_config_free(candidate_config);

	return ret;
}
