/* Triggered SRTE config
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"
#include "stream.h"
#include "zclient.h"
#include "srte.h"
#include "zapi_triggered_srte.h"
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "memory.h"
#include "zapi_fae.h"
#include "vty.h"
#include "lib_errors.h"

#include "pathd/pathd.h"
#include "pathd/path_tsrte.h"
#include "pathd/path_template.h"
#include "pathd/path_triggered.h"

#include "pathd/path_tsrte_config_clippy.c"

static int dummy_destroy(struct nb_cb_destroy_args *args);

#define XPATH_POLICY_TEMPLATE_BASELEN 100

#include "pathd/path_tsrte.h"

extern struct zclient *zclient;

/* clang-format off */
const struct frr_yang_module_info frr_pathd_triggered_srte_info = {
	.name = "frr-pathd-triggered-srte",
	.nodes = {
		  {
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template",
			.cbs = {
				.create = pathd_srte_policy_template_create,
				.cli_show = cli_show_srte_policy_template,
				.destroy = pathd_srte_policy_template_destroy,
				.get_next = pathd_srte_policy_template_get_next,
				.get_keys = pathd_srte_policy_template_get_keys,
				.lookup_entry = pathd_srte_policy_template_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path",
			.cbs = {
				.create = pathd_srte_policy_template_candidate_path_create,
				.cli_show = cli_show_srte_policy_template_candidate_path,
				.destroy = pathd_srte_policy_template_candidate_path_destroy,
				.get_next = pathd_srte_policy_template_candidate_path_get_next,
				.get_keys = pathd_srte_policy_template_candidate_path_get_keys,
				.lookup_entry = pathd_srte_policy_template_candidate_path_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/name",
			.cbs = {
				.modify = pathd_srte_policy_template_name_modify,
				.cli_show = cli_show_srte_policy_template_name,
				.destroy = pathd_srte_policy_template_name_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/name",
			.cbs = {
				.modify = pathd_srte_policy_template_candidate_path_name_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/protocol-origin",
			.cbs = {
				.modify = pathd_srte_policy_template_candidate_path_protocol_origin_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/originator",
			.cbs = {
				.modify = pathd_srte_policy_template_candidate_path_originator_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/type",
			.cbs = {
				.modify = pathd_srte_policy_template_candidate_path_type_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/flex-algo-number",
			.cbs = {
				.modify = pathd_srte_policy_template_candidate_path_flex_algo_number_modify,
				.destroy = dummy_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

int path_zebra_handle_tsrte_bgp_ready(struct zclient *zclient,
				      struct stream *s)
{
	zlog_debug("%s(): received BGP_TE_READY, sending back reply", __func__);
	zapi_tsrte_client_ready_send(zclient,
				     srte_triggered_get_protocol_origin());
	return 0;
}

int path_zebra_send_te_ready(enum srte_protocol_origin protocol_origin)
{
	return zapi_tsrte_client_ready_send(zclient, protocol_origin);
}

static struct cmd_node srte_policy_template_node = {
	.name = "srte policy template",
	.node = SR_POLICY_TEMPLATE_NODE,
	.parent_node = SR_TRAFFIC_ENG_NODE,
	.prompt = "%s(config-sr-te-policy-template)# ",
};

DEFPY(show_srte_policy_template,
      show_srte_policy_template_cmd,
      "show sr-te policy-template",
      SHOW_STR
      "SR-TE info\n"
      "SR-TE Policy template\n")
{
	struct srte_policy_template *policy;

	if (RB_EMPTY(srte_policy_template_head, &srte_policies_template)) {
		vty_out(vty, "No SR Policies template_to display.\n\n");
		return CMD_SUCCESS;
	}
	vty_out(vty, "\n");
	RB_FOREACH (policy, srte_policy_template_head,
		    &srte_policies_template) {
		struct srte_candidate_template *candidate;

		vty_out(vty, "Color: %u\n", policy->color);

		RB_FOREACH (candidate, srte_candidate_template_head,
			    &policy->candidate_paths) {
			if (candidate->type != SRTE_CANDIDATE_TYPE_FLEX_ALGO)
				continue;

			vty_out(vty,
				"  %s Preference: %d  Name: %s  Type: flex-algo %u\n",
				CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)
					? "*"
					: " ",
				candidate->preference, candidate->name,
				candidate->flex_algo_number);
		}

		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template
 */
DEFPY_NOSH(
	srte_policy_template,
	srte_policy_template_cmd,
	"policy-template color (0-4294967295)$num",
	"Segment Routing Policy Template\n"
	"SR Policy Template color\n"
	"SR Policy Template color value\n")
{
	char xpath[XPATH_POLICY_TEMPLATE_BASELEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template[color='%s']", num_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(SR_POLICY_TEMPLATE_NODE, xpath);

	return ret;
}

DEFPY(srte_no_policy_template,
      srte_no_policy_template_cmd,
      "no policy-template color (0-4294967295)$num",
      NO_STR
      "Segment Routing Policy Template\n"
      "SR Policy Template color\n"
      "SR Policy Template color value\n")
{
	char xpath[XPATH_POLICY_TEMPLATE_BASELEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template[color='%s']", num_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_srte_policy_template(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, "  policy-template color %s\n",
		yang_dnode_get_string(dnode, "./color"));
}

void cli_show_srte_policy_template_name(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "   name %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/name
 */
DEFPY(srte_policy_template_name,
      srte_policy_template_name_cmd,
      "name WORD$name",
      "Segment Routing Policy Template name\n"
      "SR Policy name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_CREATE, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(srte_policy_template_no_name,
      srte_policy_template_no_name_cmd,
      "no name [WORD]",
      NO_STR
      "Segment Routing Policy Template name\n"
      "SR Policy template name value\n")
{
	nb_cli_enqueue_change(vty, "./name", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path
 */
DEFPY(srte_policy_template_candidate_flexalgo,
      srte_policy_template_candidate_flexalgo_cmd,
      "candidate-path preference (0-4294967295)$preference name WORD$name flex-algo (128-255)$algorithm",
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Flex Algo\n"
      "Algorithm Number\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, preference_str);
	nb_cli_enqueue_change(vty, "./name", NB_OP_MODIFY, name);
	nb_cli_enqueue_change(vty, "./protocol-origin", NB_OP_MODIFY, "bgp");
	nb_cli_enqueue_change(vty, "./originator", NB_OP_MODIFY, "bgp");
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "flex-algo");
	nb_cli_enqueue_change(vty, "./flex-algo-number", NB_OP_MODIFY,
			      algorithm_str);
	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
			     preference_str);
}

DEFPY(srte_policy_template_no_candidate,
      srte_policy_template_no_candidate_cmd,
      "no candidate-path\
	preference (0-4294967295)$preference\
	[name WORD\
	<\
	  flex-algo\
	>]",
      NO_STR
      "Segment Routing Policy Candidate Path\n"
      "Segment Routing Policy Candidate Path Preference\n"
      "Administrative Preference\n"
      "Segment Routing Policy Candidate Path Name\n"
      "Symbolic Name\n"
      "Flex-Algo Dynamic Path\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./candidate-path[preference='%s']",
				    preference_str);
}

DEFPY (debug_path_template,
       debug_path_template_cmd,
       "[no] debug pathd template",
       NO_STR
       DEBUG_STR
       "path debugging\n"
       "template debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no_debug = (no != NULL);

	DEBUG_MODE_SET(&path_template_debug, mode, !no);
	DEBUG_FLAGS_SET(&path_template_debug, PATH_TEMPLATE_DEBUG_BASIC,
			!no_debug);
	return CMD_SUCCESS;
}

void cli_show_srte_policy_template_candidate_path(struct vty *vty,
						  const struct lyd_node *dnode,
						  bool show_defaults)
{
	uint8_t algorithm;
	const char *type = yang_dnode_get_string(dnode, "./type");

	if (!strmatch(type, "flex-algo"))
		return;

	algorithm = yang_dnode_get_uint8(dnode, "./flex-algo-number");

	vty_out(vty, "   candidate-path preference %s name %s %s %u\n",
		yang_dnode_get_string(dnode, "./preference"),
		yang_dnode_get_string(dnode, "./name"), type, algorithm);
}


static int path_template_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&path_template_debug, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&path_template_debug,
				      PATH_TEMPLATE_DEBUG_BASIC))
			vty_out(vty, "debug pathd template\n");
		return 1;
	}
	return 0;
}

static int path_template_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&path_template_debug, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&path_template_debug, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&path_template_debug);

	return 0;
}

/* cli initialisation triggered srte */
void path_tsrte_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      path_template_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, path_template_cli_debug_set_all);

	install_node(&srte_policy_template_node);
	install_default(SR_POLICY_TEMPLATE_NODE);
	install_element(ENABLE_NODE, &show_srte_policy_template_cmd);

	install_element(SR_TRAFFIC_ENG_NODE, &srte_policy_template_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &srte_no_policy_template_cmd);
	install_element(ENABLE_NODE, &debug_path_template_cmd);
	install_element(CONFIG_NODE, &debug_path_template_cmd);
	install_element(SR_POLICY_TEMPLATE_NODE,
			&srte_policy_template_name_cmd);
	install_element(SR_POLICY_TEMPLATE_NODE,
			&srte_policy_template_no_name_cmd);
	install_element(SR_POLICY_TEMPLATE_NODE,
			&srte_policy_template_candidate_flexalgo_cmd);
	install_element(SR_POLICY_TEMPLATE_NODE,
			&srte_policy_template_no_candidate_cmd);
}

/* northbound configuration */
/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template
 */
int pathd_srte_policy_template_create(struct nb_cb_create_args *args)
{
	struct srte_policy_template *policy;
	uint32_t color;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	color = yang_dnode_get_uint32(args->dnode, "./color");
	policy = srte_policy_template_add(color);
	srte_triggered_update();

	nb_running_set_entry(args->dnode, policy);
	SET_FLAG(policy->flags, F_POLICY_NEW);

	return NB_OK;
}

int pathd_srte_policy_template_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy_template *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_unset_entry(args->dnode);
	SET_FLAG(policy->flags, F_POLICY_DELETED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path
 */
int pathd_srte_policy_template_candidate_path_create(
	struct nb_cb_create_args *args)
{
	struct srte_policy_template *policy;
	struct srte_candidate_template *candidate;
	uint32_t preference;
	enum srte_protocol_origin protocol_origin;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	preference = yang_dnode_get_uint32(args->dnode, "./preference");
	protocol_origin = yang_dnode_get_enum(args->dnode, "./protocol-origin");
	candidate = srte_candidate_template_add(policy, preference);
	candidate->protocol_origin = protocol_origin;
	nb_running_set_entry(args->dnode, candidate);
	SET_FLAG(candidate->flags, F_CANDIDATE_NEW);

	return NB_OK;
}

int pathd_srte_policy_template_candidate_path_destroy(
	struct nb_cb_destroy_args *args)
{
	struct srte_candidate_template *candidate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_unset_entry(args->dnode);
	SET_FLAG(candidate->flags, F_CANDIDATE_DELETED);
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/name
 */
int pathd_srte_policy_template_candidate_path_name_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate_template *candidate;
	const char *name;
	char xpath[XPATH_MAXLEN];
	char xpath_buf[XPATH_MAXLEN - 3];

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* the candidate name is fixed after setting it once, this is checked
	 * here */
	if (args->event == NB_EV_VALIDATE) {
		/* first get the precise path to the candidate path */
		yang_dnode_get_path(args->dnode, xpath_buf, sizeof(xpath_buf));
		snprintf(xpath, sizeof(xpath), "%s%s", xpath_buf, "/..");

		candidate = nb_running_get_entry_non_rec(NULL, xpath, false);

		/* then check if it exists and if the name was provided */
		if (candidate && strlen(candidate->name) > 0) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The candidate name is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(candidate->name, name, sizeof(candidate->name));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/protocol-origin
 */
int pathd_srte_policy_template_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate_template *candidate;
	enum srte_protocol_origin protocol_origin;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	protocol_origin = yang_dnode_get_enum(args->dnode, NULL);
	candidate->protocol_origin = protocol_origin;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path/originator
 */
int pathd_srte_policy_template_candidate_path_originator_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate_template *candidate;
	const char *originator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	originator = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(candidate->originator, originator,
		sizeof(candidate->originator));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/candidate-path/type
 */
int pathd_srte_policy_template_candidate_path_type_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate_template *candidate;
	enum srte_candidate_type type;
	char xpath[XPATH_MAXLEN];
	char xpath_buf[XPATH_MAXLEN - 3];

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* the candidate type is fixed after setting it once, which is checked
	 * here */
	if (args->event == NB_EV_VALIDATE) {
		/* first get the precise path to the candidate path */
		yang_dnode_get_path(args->dnode, xpath_buf, sizeof(xpath_buf));
		snprintf(xpath, sizeof(xpath), "%s%s", xpath_buf, "/..");

		candidate = nb_running_get_entry_non_rec(NULL, xpath, false);

		/* then check if it exists and if the type was provided */
		if (candidate
		    && candidate->type != SRTE_CANDIDATE_TYPE_UNDEFINED) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The candidate type is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	type = yang_dnode_get_enum(args->dnode, NULL);
	candidate->type = type;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/srte/policy/candidate-path/flex-algo-number
 */
int pathd_srte_policy_template_candidate_path_flex_algo_number_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate_template *candidate;
	uint8_t flex_algo_number;

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	/*
	 * Once the flex-algo number is set, it can't be changed (doing it
	 * this way ensures endpoint registration/unregistration has all
	 * the needed info)
	 */
	if (args->event == NB_EV_VALIDATE) {
		if (CHECK_FLAG(candidate->flags,
			       F_CANDIDATE_HAS_FLEX_ALGO_NUMBER)) {

			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"The candidate template already has a flex-algo number");
			return NB_ERR_RESOURCE;
		}
		return NB_OK;
	}

	flex_algo_number = yang_dnode_get_uint8(args->dnode, NULL);

	candidate->flex_algo_number = flex_algo_number;
	SET_FLAG(candidate->flags, F_CANDIDATE_HAS_FLEX_ALGO_NUMBER);

	/*
	 * Current implementation (2022-May) does not allow per-candidate
	 * IGP paremeters to be set, so always set this flag
	 */
	SET_FLAG(candidate->flags, F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS);

	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/name
 */
int pathd_srte_policy_template_name_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy_template *policy;
	const char *name;

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (args->event == NB_EV_VALIDATE) {
		/* the policy name is fixed after setting it once */
		if (strlen(policy->name) > 0) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The SR Policy name is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(policy->name, name, sizeof(policy->name));
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

int pathd_srte_policy_template_name_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy_template *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	policy->name[0] = '\0';
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template
 */
const void *
pathd_srte_policy_template_get_next(struct nb_cb_get_next_args *args)
{
	struct srte_policy_template *policy =
		(struct srte_policy_template *)args->list_entry;

	if (args->list_entry == NULL)
		policy = RB_MIN(srte_policy_template_head,
				&srte_policies_template);
	else
		policy = RB_NEXT(srte_policy_template_head, policy);

	return policy;
}

int pathd_srte_policy_template_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct srte_policy_template *policy =
		(struct srte_policy_template *)args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 policy->color);

	return NB_OK;
}

const void *
pathd_srte_policy_template_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	uint32_t color;

	color = yang_str2uint32(args->keys->key[0]);

	return srte_policy_template_find(color);
}

/*
 * XPath: /frr-pathd:pathd/frr-pathd:srte/frr-pathd-triggered-srte:policy-template/candidate-path
 */
const void *pathd_srte_policy_template_candidate_path_get_next(
	struct nb_cb_get_next_args *args)
{
	struct srte_policy_template *policy =
		(struct srte_policy_template *)args->parent_list_entry;
	struct srte_candidate_template *candidate =
		(struct srte_candidate_template *)args->list_entry;

	if (args->list_entry == NULL)
		candidate = RB_MIN(srte_candidate_template_head,
				   &policy->candidate_paths);
	else
		candidate = RB_NEXT(srte_candidate_template_head, candidate);

	return candidate;
}

int pathd_srte_policy_template_candidate_path_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct srte_candidate_template *candidate =
		(struct srte_candidate_template *)args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 candidate->preference);

	return NB_OK;
}

const void *pathd_srte_policy_template_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct srte_policy_template *policy =
		(struct srte_policy_template *)args->parent_list_entry;
	uint32_t preference;

	preference = yang_str2uint32(args->keys->key[0]);

	return srte_candidate_template_find(policy, preference);
}

static int dummy_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}
