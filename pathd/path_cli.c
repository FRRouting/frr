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

static int config_write_paths(struct vty *vty);

/* TE path node structure. */
static struct cmd_node te_path_node = {
        .name = "te-path",
        .node = TE_PATH_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-te-path)# ",
        .config_write = config_write_paths,
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
		VTY_PUSH_XPATH(TE_PATH_NODE, xpath);

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
	const char *name;

	name = yang_dnode_get_string(dnode, "./name");

	vty_out(vty, "segment-list %s\n", name);
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
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./label");
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_segment_list_label(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults)
{
	uint32_t label;

	label = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " mpls label %u\n", label);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
DEFPY_NOSH(te_path_sr_policy, te_path_sr_policy_cmd, "sr-policy WORD$name",
	   "Segment Routing Policy\n"
	   "SR Policy name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath), "/frr-pathd:pathd/sr-policy[name='%s']",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(TE_PATH_NODE, xpath);

	return ret;
}

DEFPY(no_te_path_sr_policy, no_te_path_sr_policy_cmd, "no sr-policy WORD$name",
      NO_STR
      "Segment Routing Policy\n"
      "SR Policy name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-pathd:pathd/sr-policy[name='%s']",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	const char *name;

	name = yang_dnode_get_string(dnode, "./name");

	vty_out(vty, "sr-policy %s\n", name);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/color
 */
DEFPY(te_path_sr_policy_color, te_path_sr_policy_color_cmd,
      "color (0-4294967295)$num",
      "Segment Routing Policy Color\n"
      "SR Policy color\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./color");
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, num_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy_color(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	uint32_t color;

	color = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " color %u\n", color);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/endpoint
 */
DEFPY(te_path_sr_policy_endpoint, te_path_sr_policy_endpoint_cmd,
      "endpoint A.B.C.D$endpoint",
      "Segment Routing Policy Endpoint\n"
      "SR Policy endpoint IP\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./endpoint");
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, endpoint_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy_endpoint(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults)
{
	struct ipaddr *endpoint = malloc(sizeof(struct ipaddr));
	char *endpoint_str = malloc(sizeof(char) * MAX_IP_STR_LENGTH);

	yang_dnode_get_ip(endpoint, dnode, NULL);
	ipaddr2str(endpoint, endpoint_str, sizeof(endpoint_str));

	vty_out(vty, " endpoint %s\n", endpoint_str);

	free(endpoint);
	free(endpoint_str);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
DEFPY(te_path_sr_policy_binding_sid, te_path_sr_policy_binding_sid_cmd,
      "binding-sid (0-1048575)$label",
      "Segment Routing Policy Binding-SID\n"
      "SR Policy Binding-SID label\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./binding-sid");
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, label_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy_binding_sid(struct vty *vty,
					    struct lyd_node *dnode,
					    bool show_defaults)
{
	uint32_t binding_sid;

	binding_sid = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " binding-sid %u\n", binding_sid);
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
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./candidate-path[preference='%s']",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, preference_str);

	snprintf(xpath, sizeof(xpath),
		 "./candidate-path[preference='%s']/segment-list-name",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, list_name);

	snprintf(xpath, sizeof(xpath),
		 "./candidate-path[preference='%s']/protocol-origin",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, "config");

	snprintf(xpath, sizeof(xpath),
		 "./candidate-path[preference='%s']/originator",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, "127.0.0.1");

	snprintf(xpath, sizeof(xpath),
		 "./candidate-path[preference='%s']/dynamic-flag",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, "false");

	return nb_cli_apply_changes(vty, NULL);
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
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./candidate-path[preference='%s']",
		 preference_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_te_path_sr_policy_candidate_path(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults)
{
	uint32_t preference;
	const char *segment_list_name;

	preference = yang_dnode_get_uint32(dnode, "./preference");
	segment_list_name = yang_dnode_get_string(dnode, "./segment-list-name");

	vty_out(vty, " candidate-path preference %u explicit segment-list %s\n",
		preference, segment_list_name);
}

int config_write_paths(struct vty *vty)
{
	struct lyd_node *dnode;

	dnode = yang_dnode_get(running_config->dnode, "/frr-pathd:pathd");
	assert(dnode);
	nb_cli_show_dnode_cmds(vty, dnode, false);

	return 1;
}

void path_cli_init(void)
{
	install_node(&te_path_node);
	install_default(TE_PATH_NODE);

	install_element(CONFIG_NODE, &te_path_segment_list_cmd);
	install_element(CONFIG_NODE, &no_te_path_segment_list_cmd);
	install_element(TE_PATH_NODE, &te_path_segment_list_label_cmd);
	install_element(CONFIG_NODE, &te_path_sr_policy_cmd);
	install_element(CONFIG_NODE, &no_te_path_sr_policy_cmd);
	install_element(TE_PATH_NODE, &te_path_sr_policy_color_cmd);
	install_element(TE_PATH_NODE, &te_path_sr_policy_endpoint_cmd);
	install_element(TE_PATH_NODE, &te_path_sr_policy_binding_sid_cmd);
	install_element(TE_PATH_NODE, &te_path_sr_policy_candidate_path_cmd);
	install_element(TE_PATH_NODE, &no_te_path_sr_policy_candidate_path_cmd);
}
