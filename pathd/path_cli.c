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
 * XPath: /frr-pathd:pathd/segment-list/label
 */
DEFPY(te_path_segment_list_label, te_path_segment_list_label_cmd,
      "mpls label (16-1048575)$label",
      "MPLS or IP Label\n"
      "Label\n"
      "Label Value\n")
{
	nb_cli_enqueue_change(vty, "./label", NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_te_path_segment_list_label, no_te_path_segment_list_label_cmd,
      "no mpls label (16-1048575)$label",
      NO_STR
      "MPLS or IP Label\n"
      "Label\n"
      "Label Value\n")
{
	nb_cli_enqueue_change(vty, "./label", NB_OP_DESTROY, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_segment_list_label(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " mpls label %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
DEFPY_NOSH(te_path_sr_policy, te_path_sr_policy_cmd,
	   "sr-policy color (0-4294967295)$num endpoint A.B.C.D$endpoint",
	   "Segment Routing Policy\n"
	   "SR Policy color\n"
	   "SR Policy color value\n"
	   "SR Policy endpoint\n"
	   "SR Policy endpoint IP\n")
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
      "no sr-policy color (0-4294967295)$num endpoint A.B.C.D$endpoint",
      NO_STR
      "Segment Routing Policy\n"
      "SR Policy color\n"
      "SR Policy color value\n"
      "SR Policy endpoint\n"
      "SR Policy endpoint IP\n")
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
      "no name WORD$name",
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
DEFPY(te_path_sr_policy_candidate_path, te_path_sr_policy_candidate_path_cmd,
      "candidate-path\
        preference (0-4294967295)$preference\
        explicit segment-list WORD$list_name",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "'explicit' or 'dynamic' Path\n"
      "List of SIDs\n"
      "Name of the Segment List\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./segment-list-name", NB_OP_MODIFY,
			      list_name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "config");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "127.0.0.1");
	nb_cli_enqueue_change(vty, "./dynamic-flag", NB_OP_MODIFY, "false");

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
	vty_out(vty, " candidate-path preference %s explicit segment-list %s\n",
		yang_dnode_get_string(dnode, "./preference"),
		yang_dnode_get_string(dnode, "./segment-list-name"));
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

	install_element(CONFIG_NODE, &te_path_segment_list_cmd);
	install_element(CONFIG_NODE, &no_te_path_segment_list_cmd);
	install_element(SEGMENT_LIST_NODE, &te_path_segment_list_label_cmd);
	install_element(SEGMENT_LIST_NODE, &no_te_path_segment_list_label_cmd);
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
