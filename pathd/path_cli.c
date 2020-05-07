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

#include <float.h>
#include <math.h>
#include <zebra.h>

#include "log.h"
#include "command.h"
#include "mpls.h"
#include "northbound_cli.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"
#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_cli_clippy.c"
#endif

static int config_write_segment_lists(struct vty *vty);
static int config_write_sr_policies(struct vty *vty);

/* Vty node structures. */
static struct cmd_node segment_list_node = {
        .name = "segment-list",
        .node = SEGMENT_LIST_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-segment-list)# ",
        .config_write = config_write_segment_lists,
};

static struct cmd_node sr_policy_node = {
        .name = "sr-policy",
        .node = SR_POLICY_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-sr-policy)# ",
        .config_write = config_write_sr_policies,
};

/*
 * Show SR-TE info
 */
DEFPY(show_srte_policy, show_srte_policy_cmd, "show sr-te policy",
      SHOW_STR
      "SR-TE info\n"
      "SR-TE Policy\n")
{
	struct ttable *tt;
	struct srte_policy *policy;
	char *table;

	if (RB_EMPTY(srte_policy_head, &srte_policies)) {
		vty_out(vty, "No SR Policies to display.\n\n");
		return CMD_SUCCESS;
	}

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Endpoint|Color|Name|BSID|Status");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		char endpoint[46];
		char binding_sid[16] = "-";

		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		if (policy->binding_sid != MPLS_LABEL_NONE)
			snprintf(binding_sid, sizeof(binding_sid), "%u",
				 policy->binding_sid);

		ttable_add_row(tt, "%s|%u|%s|%s|%s", endpoint, policy->color,
			       policy->name, binding_sid,
			       policy->status == SRTE_POLICY_STATUS_UP
				       ? "Active"
				       : "Inactive");
	}

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_del(tt);

	return CMD_SUCCESS;
}

/*
 * Show detailed SR-TE info
 */
DEFPY(show_srte_policy_detail, show_srte_policy_detail_cmd,
      "show sr-te policy detail",
      SHOW_STR
      "SR-TE info\n"
      "SR-TE Policy\n"
      "Show a detailed summary\n")
{
	struct srte_policy *policy;

	if (RB_EMPTY(srte_policy_head, &srte_policies)) {
		vty_out(vty, "No SR Policies to display.\n\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "\n");
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;
		char endpoint[46];
		char binding_sid[16] = "-";

		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		if (policy->binding_sid != MPLS_LABEL_NONE)
			snprintf(binding_sid, sizeof(binding_sid), "%u",
				 policy->binding_sid);
		vty_out(vty,
			"Endpoint: %s  Color: %u  Name: %s  BSID: %s  Status: %s\n",
			endpoint, policy->color, policy->name, binding_sid,
			policy->status == SRTE_POLICY_STATUS_UP ? "Active"
								: "Inactive");

		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
			vty_out(vty,
				"  %s Preference: %d  Name: %s  Type: %s  Segment-List: %s  Protocol-Origin: %s\n",
				CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)
					? "*"
					: " ",
				candidate->preference, candidate->name,
				candidate->type == SRTE_CANDIDATE_TYPE_EXPLICIT
					? "explicit"
					: "dynamic",
				candidate->segment_list == NULL
					? "(undefined)"
					: candidate->segment_list->name,
				srte_origin2str(candidate->protocol_origin));
		}

		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
DEFPY_NOSH(te_path_segment_list, te_path_segment_list_cmd,
	   "segment-list WORD$name",
	   "Segment List\n"
	   "Segment List Name\n")
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath_base, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/protocol-origin", xpath_base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "local");
	snprintf(xpath, sizeof(xpath), "%s/originator", xpath_base);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "config");

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SEGMENT_LIST_NODE, xpath_base);

	return ret;
}

DEFPY(no_te_path_segment_list, no_te_path_segment_list_cmd,
      "no segment-list WORD$name",
      NO_STR
      "Segment List\n"
      "Segment List Name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_segment_list(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	enum srte_protocol_origin origin;
	origin = yang_dnode_get_enum(dnode, "./protocol-origin");
	if (origin != SRTE_ORIGIN_LOCAL)
		return;

	vty_out(vty, "segment-list %s\n",
		yang_dnode_get_string(dnode, "./name"));
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
DEFPY(te_path_segment_list_segment, te_path_segment_list_segment_cmd,
      "index (0-4294967295)$index mpls label (16-1048575)$label "
      "[nai$has_nai <"
      "node <A.B.C.D$node_ipv4|X:X::X:X$node_ipv6>"
      ">]",
      "Index\n"
      "Index Value\n"
      "MPLS or IP Label\n"
      "Label\n"
      "Label Value\n"
      "Segment NAI\n"
      "NAI node identifier\n"
      "NAI IPv4 node identifier\n"
      "NAI IPv6 node identifier\n")
{
	char xpath[XPATH_MAXLEN];
	const char *node_id;

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']/sid-value",
		 index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, label_str);

	if (has_nai != NULL) {
		snprintf(xpath, sizeof(xpath), "./segment[index='%s']/nai/type",
			 index_str);
		if (node_ipv4_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv4_node");
			node_id = node_ipv4_str;
		} else if (node_ipv6_str != NULL) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY,
					      "ipv6_node");
			node_id = node_ipv6_str;
		} else {
			return CMD_ERR_NO_MATCH;
		}
		snprintf(xpath, sizeof(xpath),
			 "./segment[index='%s']/nai/local-address", index_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, node_id);
	} else {
		snprintf(xpath, sizeof(xpath), "./segment[index='%s']/nai",
			 index_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_te_path_segment_list_segment, no_te_path_segment_list_segment_cmd,
      "no index (0-4294967295)$index",
      NO_STR
      "Index\n"
      "Index Value\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_segment_list_segment(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults)
{
	enum srte_protocol_origin origin;
	origin = yang_dnode_get_enum(dnode, "../protocol-origin");
	if (origin != SRTE_ORIGIN_LOCAL)
		return;

	vty_out(vty, " index %s mpls label %s",
		yang_dnode_get_string(dnode, "./index"),
		yang_dnode_get_string(dnode, "./sid-value"));
	if (yang_dnode_exists(dnode, "./nai")) {
		struct ipaddr addr;
		switch (yang_dnode_get_enum(dnode, "./nai/type")) {
		case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
			yang_dnode_get_ip(&addr, dnode, "./nai/local-address");
			vty_out(vty, " nai node %pI4", &addr.ipaddr_v4);
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
			yang_dnode_get_ip(&addr, dnode, "./nai/local-address");
			vty_out(vty, " nai node %pI6", &addr.ipaddr_v6);
			break;
		default:
			break;
		}
	}
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
DEFPY_NOSH(
	te_path_sr_policy, te_path_sr_policy_cmd,
	"sr-policy color (0-4294967295)$num endpoint <A.B.C.D|X:X::X:X>$endpoint",
	"Segment Routing Policy\n"
	"SR Policy color\n"
	"SR Policy color value\n"
	"SR Policy endpoint\n"
	"SR Policy endpoint IPv4 address\n"
	"SR Policy endpoint IPv6 address\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/sr-policy[color='%s'][endpoint='%s']",
		 num_str, endpoint_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SR_POLICY_NODE, xpath);

	return ret;
}

DEFPY(no_te_path_sr_policy, no_te_path_sr_policy_cmd,
      "no sr-policy color (0-4294967295)$num endpoint <A.B.C.D|X:X::X:X>$endpoint",
      NO_STR
      "Segment Routing Policy\n"
      "SR Policy color\n"
      "SR Policy color value\n"
      "SR Policy endpoint\n"
      "SR Policy endpoint IPv4 address\n"
      "SR Policy endpoint IPv6 address\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/sr-policy[color='%s'][endpoint='%s']",
		 num_str, endpoint_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, "sr-policy color %s endpoint %s\n",
		yang_dnode_get_string(dnode, "./color"),
		yang_dnode_get_string(dnode, "./endpoint"));
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/name
 */
DEFPY(te_path_sr_policy_name, te_path_sr_policy_name_cmd, "name WORD$name",
      "Segment Routing Policy name\n"
      "SR Policy name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_CREATE, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_te_path_sr_policy_name, no_te_path_sr_policy_name_cmd,
      "no name [WORD]",
      NO_STR
      "Segment Routing Policy name\n"
      "SR Policy name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


void cli_show_te_path_sr_policy_name(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, " name %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
DEFPY(te_path_sr_policy_binding_sid, te_path_sr_policy_binding_sid_cmd,
      "binding-sid (16-1048575)$label",
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	nb_cli_enqueue_change(vty, "./binding-sid", NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_te_path_sr_policy_binding_sid, no_te_path_sr_policy_binding_sid_cmd,
      "no binding-sid [(16-1048575)]",
      NO_STR
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	nb_cli_enqueue_change(vty, "./binding-sid", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy_binding_sid(struct vty *vty,
					    struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " binding-sid %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
DEFPY(te_path_sr_policy_candidate_path, te_path_sr_policy_candidate_path_cmd,
      "candidate-path\
	preference (0-4294967295)$preference\
	name WORD$name\
	<\
	  explicit$type segment-list WORD$list_name\
	  |dynamic$type\
	>\
	[{\
	  [no$no_metrics] metrics\
	  {\
	    [bound$bound_abc] abc$metric_abc [METRIC$metric_abc_value]\
	    |[bound$bound_te] te$metric_te [METRIC$metric_te_value]\
	  }\
	|\
	  [no$no_bandwidth] bandwidth$bandwidth_tag [BANDWIDTH$bandwidth_value]\
	}]",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Explicit Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n"
      "Dynamic Path\n"
      "No metrics\n"
      "Metrics\n"
      "Bound Agreggate Bandwidth Consumption metric\n"
      "Agreggate Bandwidth Consumption metric\n"
      "Agreggate Bandwidth Consumption metric value\n"
      "Bound Traffic engineering metric\n"
      "Traffic engineering metric\n"
      "Traffic engineering metric value\n"
      "No bandwidth requirements\n"
      "Candidate path bandwidth requirements\n"
      "Bandwidth value in bytes per second\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "local");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, type);

	if (no_bandwidth != NULL) {
		nb_cli_enqueue_change(vty, "./bandwidth", NB_OP_DESTROY, NULL);
	} else if (bandwidth_tag != NULL) {
		nb_cli_enqueue_change(vty, "./bandwidth", NB_OP_MODIFY,
		      (bandwidth_value != NULL) ? bandwidth_value : "0");
	}

	if (no_metrics != NULL) {
		if (metric_abc != NULL) {
			nb_cli_enqueue_change(vty, "./metrics[type='abc']",
					      NB_OP_DESTROY, NULL);
		}
		if (metric_te != NULL) {
			nb_cli_enqueue_change(vty, "./metrics[type='te']",
					      NB_OP_DESTROY, NULL);
		}
	} else {
		if (metric_abc != NULL) {
			nb_cli_enqueue_change(
				vty, "./metrics[type='abc']/value",
				NB_OP_MODIFY,
				metric_abc_value ? metric_abc_value : "0");
			if (bound_abc != NULL)
				nb_cli_enqueue_change(
					vty, "./metrics[type='abc']/is-bound",
					NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(
					vty, "./metrics[type='abc']/is-bound",
					NB_OP_MODIFY, "false");
		}

		if (metric_te != NULL) {
			nb_cli_enqueue_change(
				vty, "./metrics[type='te']/value", NB_OP_MODIFY,
				metric_te_value ? metric_te_value : "0");
			if (bound_te != NULL)
				nb_cli_enqueue_change(
					vty, "./metrics[type='te']/is-bound",
					NB_OP_MODIFY, "true");
			else
				nb_cli_enqueue_change(
					vty, "./metrics[type='te']/is-bound",
					NB_OP_MODIFY, "false");
		}
	}

	if (strmatch(type, "explicit"))
		nb_cli_enqueue_change(vty, "./segment-list-name", NB_OP_MODIFY,
				      list_name);

	char discriminator[(sizeof(uint32_t) * 8) + 1];
	snprintf(discriminator, sizeof(discriminator), "%u", rand());
	nb_cli_enqueue_change(vty, "./discriminator", NB_OP_MODIFY,
			      discriminator);

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY(no_te_path_sr_policy_candidate_path,
      no_te_path_sr_policy_candidate_path_cmd,
      "no candidate-path\
	preference (0-4294967295)$preference\
	[name WORD\
	<\
	  explicit segment-list WORD\
	  |dynamic\
	>]",
      NO_STR
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Explicit Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n"
      "Dynamic Path\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

static const char *metric_type_name(enum srte_candidate_metric_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		return "abc";
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		return "te";
	default:
		return NULL;
	}
}

static void config_write_metric(struct vty *vty,
				enum srte_candidate_metric_type type,
				float value, bool is_bound)
{
	if (fabs(value) <= FLT_EPSILON) {
		vty_out(vty, " %s%s", is_bound ? "bound " : "",
			metric_type_name(type));
		return;
	}

	if (fabs(truncf(value) - value) < FLT_EPSILON) {
		vty_out(vty, " %s%s %d", is_bound ? "bound " : "",
			metric_type_name(type), (int)value);
		return;
	}

	vty_out(vty, " %s%s %f", is_bound ? "bound " : "",
		metric_type_name(type), value);
}

/* FIXME: Enable this back when the candidate path are only containing
 * configuration data */
// static int config_write_metric_cb(const struct lyd_node *dnode, void *arg)
// {
// 	struct vty *vty = arg;
// 	enum srte_candidate_metric_type type;
// 	bool is_bound = false;
// 	float value;

// 	type = yang_dnode_get_enum(dnode, "./type");
// 	value = (float)yang_dnode_get_dec64(dnode, "./value");
// 	if (yang_dnode_exists(dnode, "./is-bound"))
// 		is_bound = yang_dnode_get_bool(dnode, "./is-bound");

// 	config_write_metric(vty, type, value, is_bound);
// 	return YANG_ITER_CONTINUE;
// }

void cli_show_te_path_sr_policy_candidate_path(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *type = yang_dnode_get_string(dnode, "./type");

	vty_out(vty, " candidate-path preference %s name %s %s",
		yang_dnode_get_string(dnode, "./preference"),
		yang_dnode_get_string(dnode, "./name"), type);
	if (strmatch(type, "explicit"))
		vty_out(vty, " segment-list %s",
			yang_dnode_get_string(dnode, "./segment-list-name"));
	if (yang_dnode_exists(dnode, "./metrics"))
		vty_out(vty, " metrics");

	/* FIXME: Candidate path contains both configuration and transient
	 * data. This is not what we want os until it is fixed we need to
	 * hack around it */
	// yang_dnode_iterate(config_write_metric_cb, vty, dnode, "./metrics");
	struct srte_candidate *candidate;
	bool is_bound;
	candidate = nb_running_get_entry(dnode, NULL, true);
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_ABC)) {
		is_bound = CHECK_FLAG(candidate->flags,
				      F_CANDIDATE_METRIC_ABC_BOUND);
		config_write_metric(vty, SRTE_CANDIDATE_METRIC_TYPE_ABC,
				    candidate->metric_abc, is_bound);
	}
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_TE)) {
		is_bound = CHECK_FLAG(candidate->flags,
				      F_CANDIDATE_METRIC_TE_BOUND);
		config_write_metric(vty, SRTE_CANDIDATE_METRIC_TYPE_TE,
				    candidate->metric_te, is_bound);
	}
	vty_out(vty, "\n");
}

static int config_write_dnode(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;

	nb_cli_show_dnode_cmds(vty, (struct lyd_node *)dnode, false);

	return YANG_ITER_CONTINUE;
}

int config_write_segment_lists(struct vty *vty)
{
	yang_dnode_iterate(config_write_dnode, vty, running_config->dnode,
			   "/frr-pathd:pathd/segment-list");

	return 1;
}

int config_write_sr_policies(struct vty *vty)
{
	yang_dnode_iterate(config_write_dnode, vty, running_config->dnode,
			   "/frr-pathd:pathd/sr-policy");

	return 1;
}

void path_cli_init(void)
{
	install_node(&segment_list_node);
	install_node(&sr_policy_node);
	install_default(SEGMENT_LIST_NODE);
	install_default(SR_POLICY_NODE);

	install_element(ENABLE_NODE, &show_srte_policy_cmd);
	install_element(ENABLE_NODE, &show_srte_policy_detail_cmd);

	install_element(CONFIG_NODE, &te_path_segment_list_cmd);
	install_element(CONFIG_NODE, &no_te_path_segment_list_cmd);
	install_element(SEGMENT_LIST_NODE, &te_path_segment_list_segment_cmd);
	install_element(SEGMENT_LIST_NODE,
			&no_te_path_segment_list_segment_cmd);
	install_element(CONFIG_NODE, &te_path_sr_policy_cmd);
	install_element(CONFIG_NODE, &no_te_path_sr_policy_cmd);
	install_element(SR_POLICY_NODE, &te_path_sr_policy_name_cmd);
	install_element(SR_POLICY_NODE, &no_te_path_sr_policy_name_cmd);
	install_element(SR_POLICY_NODE, &te_path_sr_policy_binding_sid_cmd);
	install_element(SR_POLICY_NODE, &no_te_path_sr_policy_binding_sid_cmd);
	install_element(SR_POLICY_NODE, &te_path_sr_policy_candidate_path_cmd);
	install_element(SR_POLICY_NODE,
			&no_te_path_sr_policy_candidate_path_cmd);
}
