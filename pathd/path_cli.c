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
	struct te_sr_policy *policy;
	char endpoint[46];
	char *table;

	if (RB_EMPTY(te_sr_policy_instance_head, &te_sr_policy_instances)) {
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

	RB_FOREACH (policy, te_sr_policy_instance_head,
		    &te_sr_policy_instances) {
		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		ttable_add_row(tt, "%s|%d|%s|%d|%s", endpoint, policy->color,
			       policy->name, policy->binding_sid,
			       policy->status == TE_POLICY_UP ? "Active"
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
	struct te_sr_policy *policy;
	struct te_candidate_path *candidate_path;
	char endpoint[46];

	if (RB_EMPTY(te_sr_policy_instance_head, &te_sr_policy_instances)) {
		vty_out(vty, "No SR Policies to display.\n\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "\n");

	RB_FOREACH (policy, te_sr_policy_instance_head,
		    &te_sr_policy_instances) {

		ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
		vty_out(vty,
			"Endpoint: %s  Color: %d  Name: %s  BSID: %d  Status: %s\n",
			endpoint, policy->color, policy->name,
			policy->binding_sid,
			policy->status == TE_POLICY_UP ? "Active" : "Inactive");

		RB_FOREACH (candidate_path, te_candidate_path_instance_head,
			    &policy->candidate_paths) {
			vty_out(vty,
				"  %s Preference: %d  Name: %s  Type: %s  Segment-List: %s  Protocol-Origin: %s\n",
				candidate_path->is_best_candidate_path ? "*"
								       : " ",
				candidate_path->preference,
				candidate_path->name,
				candidate_path->type
						== TE_CANDIDATE_PATH_EXPLICIT
					? "explicit"
					: "dynamic",
				candidate_path->segment_list_name == NULL
					? "(undefined)"
					: candidate_path->segment_list_name,
				candidate_path->protocol_origin
						== TE_ORIGIN_PCEP
					? "PCEP"
					: "Config");
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
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/segment-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SEGMENT_LIST_NODE, xpath);

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
	vty_out(vty, "segment-list %s\n",
		yang_dnode_get_string(dnode, "./name"));
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
DEFPY(te_path_segment_list_segment, te_path_segment_list_segment_cmd,
      "index (0-4294967295)$index mpls label (16-1048575)$label",
      "Index\n"
      "Index Value\n"
      "MPLS or IP Label\n"
      "Label\n"
      "Label Value\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']", index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "./segment[index='%s']/sid-value",
		 index_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, label_str);

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
	vty_out(vty, " index %s mpls label %s\n",
		yang_dnode_get_string(dnode, "./index"),
		yang_dnode_get_string(dnode, "./sid-value"));
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
      "binding-sid (0-1048575)$label",
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	nb_cli_enqueue_change(vty, "./binding-sid", NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_te_path_sr_policy_binding_sid, no_te_path_sr_policy_binding_sid_cmd,
      "no binding-sid [(0-1048575)]",
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
DEFPY(te_path_sr_policy_candidate_path_explicit,
      te_path_sr_policy_candidate_path_explicit_cmd,
      "candidate-path\
        preference (0-4294967295)$preference\
        name WORD$name\
        explicit segment-list WORD$list_name",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "'explicit' or 'dynamic' Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./segment-list-name", NB_OP_MODIFY,
			      list_name);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "127.0.0.1");

	char discriminator[(sizeof(uint32_t) * 8) + 1];
	snprintf(discriminator, sizeof(discriminator), "%u", rand());
	nb_cli_enqueue_change(vty, "./discriminator", NB_OP_MODIFY,
			      discriminator);

	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "explicit");

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY(te_path_sr_policy_candidate_path_dynamic,
      te_path_sr_policy_candidate_path_dynamic_cmd,
      "candidate-path\
        preference (0-4294967295)$preference\
        name WORD$name\
        dynamic",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "'explicit' or 'dynamic' Path\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "127.0.0.1");

	char discriminator[(sizeof(uint32_t) * 8) + 1];
	snprintf(discriminator, sizeof(discriminator), "%u", rand());
	nb_cli_enqueue_change(vty, "./discriminator", NB_OP_MODIFY,
			      discriminator);

	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "dynamic");

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY(no_te_path_sr_policy_candidate_path,
      no_te_path_sr_policy_candidate_path_cmd,
      "no candidate-path\
        preference (0-4294967295)$preference",
      NO_STR
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

void cli_show_te_path_sr_policy_candidate_path(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults)
{
	if (!strcmp("explicit", yang_dnode_get_string(dnode, "./type")))
		vty_out(vty,
			" candidate-path preference %s name %s explicit segment-list %s\n",
			yang_dnode_get_string(dnode, "./preference"),
			yang_dnode_get_string(dnode, "./name"),
			yang_dnode_get_string(dnode, "./segment-list-name"));
	else
		vty_out(vty, " candidate-path preference %s name %s dynamic\n",
			yang_dnode_get_string(dnode, "./preference"),
			yang_dnode_get_string(dnode, "./name"));
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
	install_element(SR_POLICY_NODE,
			&te_path_sr_policy_candidate_path_explicit_cmd);
	install_element(SR_POLICY_NODE,
			&te_path_sr_policy_candidate_path_dynamic_cmd);
	install_element(SR_POLICY_NODE,
			&no_te_path_sr_policy_candidate_path_cmd);
}
