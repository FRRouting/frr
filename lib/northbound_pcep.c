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

#include "libfrr.h"
#include "log.h"
#include "lib_errors.h"
#include "debug.h"
#include "yang_translator.h"
#include "northbound.h"
#include "northbound_pcep.h"
#include "pathd/pathd.h"

int nb_pcep_commit_candidate_config(struct nb_config *candidate_config,
				    const char *comment)
{
	int ret = nb_candidate_commit(candidate_config, NB_CLIENT_PCEP, NULL,
				      false, comment, NULL);
	if (ret != NB_OK && ret != NB_ERR_NO_CHANGES)
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

void nb_pcep_edit_candidate_config(struct nb_config *candidate_config,
				   const char *xpath,
				   enum nb_operation operation,
				   const char *value)
{
	struct nb_node *nb_node;
	struct yang_data *data;
	int ret;

	/* Find the northbound node associated to the data path. */
	nb_node = nb_node_find(xpath);
	if (!nb_node)
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);

	data = yang_data_new(xpath, value);

	/*
	 * Ignore "not found" errors when editing the candidate
	 * configuration.
	 */
	ret = nb_candidate_edit(candidate_config, nb_node, operation, xpath,
				NULL, data);
	if (ret != NB_OK && ret != NB_ERR_NOT_FOUND)
		flog_warn(
			EC_LIB_NB_CANDIDATE_EDIT_ERROR,
			"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
			__func__, nb_operation_name(operation), xpath);

	yang_data_free(data);
}

int nb_pcep_add_segment_list_label(const char *segment_list_name,
				   const char *label_str)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	struct nb_config *candidate_config = nb_config_dup(running_config);

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']/label",
		 segment_list_name);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_CREATE,
				      label_str);

	ret = nb_pcep_commit_candidate_config(candidate_config,
					      "Segment List Label");

	nb_config_free(candidate_config);

	return ret;
}

int nb_pcep_create_segment_list(const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	struct nb_config *candidate_config = nb_config_dup(running_config);

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']", segment_list_name);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_CREATE,
				      segment_list_name);

	ret = nb_pcep_commit_candidate_config(candidate_config, "Segment List");

	nb_config_free(candidate_config);

	return ret;
}

int nb_pcep_add_candidate_path(const char *color_str, const char *endpoint_str,
			       const char *originator_str,
			       const char *preference_str,
			       const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	char xpath_base[XPATH_MAXLEN];
	int ret;

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/sr-policy[color='%s'][endpoint='%s']/candidate-path[preference='%s']",
		color_str, endpoint_str, preference_str);

	struct nb_config *candidate_config = nb_config_dup(running_config);

	nb_pcep_edit_candidate_config(candidate_config, xpath_base,
				      NB_OP_CREATE, preference_str);

	snprintf(xpath, sizeof(xpath), "%s/segment-list-name", xpath_base);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      segment_list_name);

	snprintf(xpath, sizeof(xpath), "%s/protocol-origin", xpath_base);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      "pcep");

	snprintf(xpath, sizeof(xpath), "%s/originator", xpath_base);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      originator_str);

	snprintf(xpath, sizeof(xpath), "%s/dynamic-flag", xpath_base);
	nb_pcep_edit_candidate_config(candidate_config, xpath, NB_OP_MODIFY,
				      "false");

	ret = nb_pcep_commit_candidate_config(candidate_config,
					      "SR Policy Candidate Path");

	nb_config_free(candidate_config);

	return ret;
}

struct te_sr_policy *nb_pcep_get_sr_policy(const char *color_str,
					   const char *endpoint_str)
{
	char xpath_sr_policy[XPATH_MAXLEN];
	struct te_sr_policy *te_sr_policy;

	snprintf(xpath_sr_policy, sizeof(xpath_sr_policy),
		 "/frr-pathd:pathd/sr-policy[color='%s'][endpoint='%s']",
		 color_str, endpoint_str);
	te_sr_policy = nb_running_get_entry(running_config->dnode,
					    xpath_sr_policy, true);

	return te_sr_policy;
}

struct te_segment_list *nb_pcep_get_segment_list(const char *name)
{
	char xpath_segment_list[XPATH_MAXLEN];
	struct te_segment_list *te_segment_list;

	snprintf(xpath_segment_list, sizeof(xpath_segment_list),
		 "/frr-pathd:pathd/segment-list[name='%s']", name);
	te_segment_list = nb_running_get_entry(running_config->dnode,
					       xpath_segment_list, true);

	return te_segment_list;
}
