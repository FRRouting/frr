/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
#include "version.h"
#include "log.h"
#include "lib_errors.h"
#include "command.h"
#include "termtable.h"
#include "db.h"
#include "debug.h"
#include "yang_translator.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "northbound_db.h"
#ifndef VTYSH_EXTRACT_PL
#include "lib/northbound_cli_clippy.c"
#endif

struct debug nb_dbg_cbs_config = {0, "Northbound callbacks: configuration"};
struct debug nb_dbg_cbs_state = {0, "Northbound callbacks: state"};
struct debug nb_dbg_cbs_rpc = {0, "Northbound callbacks: RPCs"};
struct debug nb_dbg_notif = {0, "Northbound notifications"};
struct debug nb_dbg_events = {0, "Northbound events"};
struct debug nb_dbg_libyang = {0, "libyang debugging"};

struct nb_config *vty_shared_candidate_config;
static struct thread_master *master;

static void vty_show_libyang_errors(struct vty *vty, struct ly_ctx *ly_ctx)
{
	struct ly_err_item *ei;
	const char *path;

	ei = ly_err_first(ly_ctx);
	if (!ei)
		return;

	for (; ei; ei = ei->next)
		vty_out(vty, "%s\n", ei->msg);

	path = ly_errpath(ly_ctx);
	if (path)
		vty_out(vty, "YANG path: %s\n", path);

	ly_err_clean(ly_ctx, NULL);
}

void nb_cli_enqueue_change(struct vty *vty, const char *xpath,
			   enum nb_operation operation, const char *value)
{
	struct vty_cfg_change *change;

	if (vty->num_cfg_changes == VTY_MAXCFGCHANGES) {
		/* Not expected to happen. */
		vty_out(vty,
			"%% Exceeded the maximum number of changes (%u) for a single command\n\n",
			VTY_MAXCFGCHANGES);
		return;
	}

	change = &vty->cfg_changes[vty->num_cfg_changes++];
	strlcpy(change->xpath, xpath, sizeof(change->xpath));
	change->operation = operation;
	change->value = value;
}

int nb_cli_apply_changes(struct vty *vty, const char *xpath_base_fmt, ...)
{
	char xpath_base[XPATH_MAXLEN] = {};
	bool error = false;
	int ret;

	VTY_CHECK_XPATH;

	/* Parse the base XPath format string. */
	if (xpath_base_fmt) {
		va_list ap;

		va_start(ap, xpath_base_fmt);
		vsnprintf(xpath_base, sizeof(xpath_base), xpath_base_fmt, ap);
		va_end(ap);
	}

	/* Edit candidate configuration. */
	for (size_t i = 0; i < vty->num_cfg_changes; i++) {
		struct vty_cfg_change *change = &vty->cfg_changes[i];
		struct nb_node *nb_node;
		char xpath[XPATH_MAXLEN];
		struct yang_data *data;

		/* Handle relative XPaths. */
		memset(xpath, 0, sizeof(xpath));
		if (vty->xpath_index > 0
		    && ((xpath_base_fmt && xpath_base[0] == '.')
			|| change->xpath[0] == '.'))
			strlcpy(xpath, VTY_CURR_XPATH, sizeof(xpath));
		if (xpath_base_fmt) {
			if (xpath_base[0] == '.')
				strlcat(xpath, xpath_base + 1, sizeof(xpath));
			else
				strlcat(xpath, xpath_base, sizeof(xpath));
		}
		if (change->xpath[0] == '.')
			strlcat(xpath, change->xpath + 1, sizeof(xpath));
		else
			strlcpy(xpath, change->xpath, sizeof(xpath));

		/* Find the northbound node associated to the data path. */
		nb_node = nb_node_find(xpath);
		if (!nb_node) {
			flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
				  "%s: unknown data path: %s", __func__, xpath);
			error = true;
			continue;
		}

		/* If the value is not set, get the default if it exists. */
		if (change->value == NULL)
			change->value = yang_snode_get_default(nb_node->snode);
		data = yang_data_new(xpath, change->value);

		/*
		 * Ignore "not found" errors when editing the candidate
		 * configuration.
		 */
		ret = nb_candidate_edit(vty->candidate_config, nb_node,
					change->operation, xpath, NULL, data);
		yang_data_free(data);
		if (ret != NB_OK && ret != NB_ERR_NOT_FOUND) {
			flog_warn(
				EC_LIB_NB_CANDIDATE_EDIT_ERROR,
				"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
				__func__, nb_operation_name(change->operation),
				xpath);
			error = true;
			continue;
		}
	}

	if (error) {
		/*
		 * Failure to edit the candidate configuration should never
		 * happen in practice, unless there's a bug in the code. When
		 * that happens, log the error but otherwise ignore it.
		 */
		vty_out(vty, "%% Failed to edit configuration.\n\n");
		vty_show_libyang_errors(vty, ly_native_ctx);
	}

	/* Do an implicit "commit" when using the classic CLI mode. */
	if (frr_get_cli_mode() == FRR_CLI_CLASSIC) {
		ret = nb_candidate_commit(vty->candidate_config, NB_CLIENT_CLI,
					  vty, false, NULL, NULL);
		if (ret != NB_OK && ret != NB_ERR_NO_CHANGES) {
			vty_out(vty, "%% Configuration failed: %s.\n\n",
				nb_err_name(ret));
			vty_out(vty,
				"Please check the logs for more details.\n");

			/* Regenerate candidate for consistency. */
			nb_config_replace(vty->candidate_config, running_config,
					  true);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	return CMD_SUCCESS;
}

int nb_cli_rpc(const char *xpath, struct list *input, struct list *output)
{
	struct nb_node *nb_node;
	int ret;

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return CMD_WARNING;
	}

	ret = nb_callback_rpc(nb_node, xpath, input, output);
	switch (ret) {
	case NB_OK:
		return CMD_SUCCESS;
	default:
		return CMD_WARNING;
	}
}

void nb_cli_confirmed_commit_clean(struct vty *vty)
{
	THREAD_TIMER_OFF(vty->t_confirmed_commit_timeout);
	nb_config_free(vty->confirmed_commit_rollback);
	vty->confirmed_commit_rollback = NULL;
}

int nb_cli_confirmed_commit_rollback(struct vty *vty)
{
	uint32_t transaction_id;
	int ret;

	/* Perform the rollback. */
	ret = nb_candidate_commit(
		vty->confirmed_commit_rollback, NB_CLIENT_CLI, vty, true,
		"Rollback to previous configuration - confirmed commit has timed out",
		&transaction_id);
	if (ret == NB_OK)
		vty_out(vty,
			"Rollback performed successfully (Transaction ID #%u).\n",
			transaction_id);
	else
		vty_out(vty, "Failed to rollback to previous configuration.\n");

	return ret;
}

static int nb_cli_confirmed_commit_timeout(struct thread *thread)
{
	struct vty *vty = THREAD_ARG(thread);

	/* XXX: broadcast this message to all logged-in users? */
	vty_out(vty,
		"\nConfirmed commit has timed out, rolling back to previous configuration.\n\n");

	nb_cli_confirmed_commit_rollback(vty);
	nb_cli_confirmed_commit_clean(vty);

	return 0;
}

static int nb_cli_commit(struct vty *vty, bool force,
			 unsigned int confirmed_timeout, char *comment)
{
	uint32_t transaction_id = 0;
	int ret;

	/* Check if there's a pending confirmed commit. */
	if (vty->t_confirmed_commit_timeout) {
		if (confirmed_timeout) {
			/* Reset timeout if "commit confirmed" is used again. */
			vty_out(vty,
				"%% Resetting confirmed-commit timeout to %u minute(s)\n\n",
				confirmed_timeout);

			THREAD_TIMER_OFF(vty->t_confirmed_commit_timeout);
			thread_add_timer(master,
					 nb_cli_confirmed_commit_timeout, vty,
					 confirmed_timeout * 60,
					 &vty->t_confirmed_commit_timeout);
		} else {
			/* Accept commit confirmation. */
			vty_out(vty, "%% Commit complete.\n\n");
			nb_cli_confirmed_commit_clean(vty);
		}
		return CMD_SUCCESS;
	}

	/* "force" parameter. */
	if (!force && nb_candidate_needs_update(vty->candidate_config)) {
		vty_out(vty,
			"%% Candidate configuration needs to be updated before commit.\n\n");
		vty_out(vty,
			"Use the \"update\" command or \"commit force\".\n");
		return CMD_WARNING;
	}

	/* "confirm" parameter. */
	if (confirmed_timeout) {
		vty->confirmed_commit_rollback = nb_config_dup(running_config);

		vty->t_confirmed_commit_timeout = NULL;
		thread_add_timer(master, nb_cli_confirmed_commit_timeout, vty,
				 confirmed_timeout * 60,
				 &vty->t_confirmed_commit_timeout);
	}

	ret = nb_candidate_commit(vty->candidate_config, NB_CLIENT_CLI, vty,
				  true, comment, &transaction_id);

	/* Map northbound return code to CLI return code. */
	switch (ret) {
	case NB_OK:
		nb_config_replace(vty->candidate_config_base, running_config,
				  true);
		vty_out(vty,
			"%% Configuration committed successfully (Transaction ID #%u).\n\n",
			transaction_id);
		return CMD_SUCCESS;
	case NB_ERR_NO_CHANGES:
		vty_out(vty, "%% No configuration changes to commit.\n\n");
		return CMD_SUCCESS;
	default:
		vty_out(vty,
			"%% Failed to commit candidate configuration: %s.\n\n",
			nb_err_name(ret));
		vty_out(vty, "Please check the logs for more details.\n");
		return CMD_WARNING;
	}
}

static int nb_cli_candidate_load_file(struct vty *vty,
				      enum nb_cfg_format format,
				      struct yang_translator *translator,
				      const char *path, bool replace)
{
	struct nb_config *loaded_config = NULL;
	struct lyd_node *dnode;
	struct ly_ctx *ly_ctx;
	int ly_format;

	switch (format) {
	case NB_CFG_FMT_CMDS:
		loaded_config = nb_config_new(NULL);
		if (!vty_read_config(loaded_config, path, config_default)) {
			vty_out(vty, "%% Failed to load configuration.\n\n");
			vty_out(vty,
				"Please check the logs for more details.\n");
			nb_config_free(loaded_config);
			return CMD_WARNING;
		}
		break;
	case NB_CFG_FMT_JSON:
	case NB_CFG_FMT_XML:
		ly_format = (format == NB_CFG_FMT_JSON) ? LYD_JSON : LYD_XML;

		ly_ctx = translator ? translator->ly_ctx : ly_native_ctx;
		dnode = lyd_parse_path(ly_ctx, path, ly_format, LYD_OPT_EDIT);
		if (!dnode) {
			flog_warn(EC_LIB_LIBYANG, "%s: lyd_parse_path() failed",
				  __func__);
			vty_out(vty, "%% Failed to load configuration:\n\n");
			vty_show_libyang_errors(vty, ly_ctx);
			return CMD_WARNING;
		}
		if (translator
		    && yang_translate_dnode(translator,
					    YANG_TRANSLATE_TO_NATIVE, &dnode)
			       != YANG_TRANSLATE_SUCCESS) {
			vty_out(vty, "%% Failed to translate configuration\n");
			yang_dnode_free(dnode);
			return CMD_WARNING;
		}
		loaded_config = nb_config_new(dnode);
		break;
	}

	if (replace)
		nb_config_replace(vty->candidate_config, loaded_config, false);
	else if (nb_config_merge(vty->candidate_config, loaded_config, false)
		 != NB_OK) {
		vty_out(vty,
			"%% Failed to merge the loaded configuration:\n\n");
		vty_show_libyang_errors(vty, ly_native_ctx);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

static int nb_cli_candidate_load_transaction(struct vty *vty,
					     uint32_t transaction_id,
					     bool replace)
{
	struct nb_config *loaded_config;

	loaded_config = nb_db_transaction_load(transaction_id);
	if (!loaded_config) {
		vty_out(vty, "%% Transaction %u does not exist.\n\n",
			transaction_id);
		return CMD_WARNING;
	}

	if (replace)
		nb_config_replace(vty->candidate_config, loaded_config, false);
	else if (nb_config_merge(vty->candidate_config, loaded_config, false)
		 != NB_OK) {
		vty_out(vty,
			"%% Failed to merge the loaded configuration:\n\n");
		vty_show_libyang_errors(vty, ly_native_ctx);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/*
 * ly_iter_next_is_up: detects when iterating up on the yang model.
 *
 * This function detects whether next node in the iteration is upwards,
 * then return the node otherwise return NULL.
 */
static struct lyd_node *ly_iter_next_up(const struct lyd_node *elem)
{
	/* Are we going downwards? Is this still not a leaf? */
	if (!(elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)))
		return NULL;

	/* Are there still leaves in this branch? */
	if (elem->next != NULL)
		return NULL;

	return elem->parent;
}

/* Prepare the configuration for display. */
void nb_cli_show_config_prepare(struct nb_config *config, bool with_defaults)
{
	/* Nothing to do for daemons that don't implement any YANG module. */
	if (config->dnode == NULL)
		return;

	lyd_schema_sort(config->dnode, 1);

	/*
	 * When "with-defaults" is used, call lyd_validate() only to create
	 * default child nodes, ignoring any possible validation error. This
	 * doesn't need to be done when displaying the running configuration
	 * since it's always fully validated.
	 */
	if (with_defaults && config != running_config)
		(void)lyd_validate(&config->dnode,
				   LYD_OPT_CONFIG | LYD_OPT_WHENAUTODEL,
				   ly_native_ctx);
}

void nb_cli_show_dnode_cmds(struct vty *vty, struct lyd_node *root,
			    bool with_defaults)
{
	struct lyd_node *next, *child, *parent;

	LY_TREE_DFS_BEGIN (root, next, child) {
		struct nb_node *nb_node;

		nb_node = child->schema->priv;
		if (!nb_node->cbs.cli_show)
			goto next;

		/* Skip default values. */
		if (!with_defaults && yang_dnode_is_default_recursive(child))
			goto next;

		(*nb_node->cbs.cli_show)(vty, child, with_defaults);
	next:
		/*
		 * When transiting upwards in the yang model we should
		 * give the previous container/list node a chance to
		 * print its close vty output (e.g. "!" or "end-family"
		 * etc...).
		 */
		parent = ly_iter_next_up(child);
		if (parent != NULL) {
			nb_node = parent->schema->priv;
			if (nb_node->cbs.cli_show_end)
				(*nb_node->cbs.cli_show_end)(vty, parent);
		}

		LY_TREE_DFS_END(root, next, child);
	}
}

static void nb_cli_show_config_cmds(struct vty *vty, struct nb_config *config,
				    bool with_defaults)
{
	struct lyd_node *root;

	vty_out(vty, "Configuration:\n");
	vty_out(vty, "!\n");
	vty_out(vty, "frr version %s\n", FRR_VER_SHORT);
	vty_out(vty, "frr defaults %s\n", DFLT_NAME);

	LY_TREE_FOR (config->dnode, root)
		nb_cli_show_dnode_cmds(vty, root, with_defaults);

	vty_out(vty, "!\n");
	vty_out(vty, "end\n");
}

static int nb_cli_show_config_libyang(struct vty *vty, LYD_FORMAT format,
				      struct nb_config *config,
				      struct yang_translator *translator,
				      bool with_defaults)
{
	struct lyd_node *dnode;
	char *strp;
	int options = 0;

	dnode = yang_dnode_dup(config->dnode);
	if (translator
	    && yang_translate_dnode(translator, YANG_TRANSLATE_FROM_NATIVE,
				    &dnode)
		       != YANG_TRANSLATE_SUCCESS) {
		vty_out(vty, "%% Failed to translate configuration\n");
		yang_dnode_free(dnode);
		return CMD_WARNING;
	}

	SET_FLAG(options, LYP_FORMAT | LYP_WITHSIBLINGS);
	if (with_defaults)
		SET_FLAG(options, LYP_WD_ALL);
	else
		SET_FLAG(options, LYP_WD_TRIM);

	if (lyd_print_mem(&strp, dnode, format, options) == 0 && strp) {
		vty_out(vty, "%s", strp);
		free(strp);
	}

	yang_dnode_free(dnode);

	return CMD_SUCCESS;
}

static int nb_cli_show_config(struct vty *vty, struct nb_config *config,
			      enum nb_cfg_format format,
			      struct yang_translator *translator,
			      bool with_defaults)
{
	nb_cli_show_config_prepare(config, with_defaults);

	switch (format) {
	case NB_CFG_FMT_CMDS:
		nb_cli_show_config_cmds(vty, config, with_defaults);
		break;
	case NB_CFG_FMT_JSON:
		return nb_cli_show_config_libyang(vty, LYD_JSON, config,
						  translator, with_defaults);
	case NB_CFG_FMT_XML:
		return nb_cli_show_config_libyang(vty, LYD_XML, config,
						  translator, with_defaults);
	}

	return CMD_SUCCESS;
}

static int nb_write_config(struct nb_config *config, enum nb_cfg_format format,
			   struct yang_translator *translator, char *path,
			   size_t pathlen)
{
	int fd;
	struct vty *file_vty;
	int ret = 0;

	snprintf(path, pathlen, "/tmp/frr.tmp.XXXXXXXX");
	fd = mkstemp(path);
	if (fd < 0) {
		flog_warn(EC_LIB_SYSTEM_CALL, "%s: mkstemp() failed: %s",
			  __func__, safe_strerror(errno));
		return -1;
	}

	/* Make vty for configuration file. */
	file_vty = vty_new();
	file_vty->wfd = fd;
	file_vty->type = VTY_FILE;
	if (config)
		ret = nb_cli_show_config(file_vty, config, format, translator,
					 false);
	vty_close(file_vty);

	return ret;
}

static int nb_cli_show_config_compare(struct vty *vty,
				      struct nb_config *config1,
				      struct nb_config *config2,
				      enum nb_cfg_format format,
				      struct yang_translator *translator)
{
	char config1_path[256];
	char config2_path[256];
	char command[BUFSIZ];
	FILE *fp;
	char line[1024];
	int lineno = 0;

	if (nb_write_config(config1, format, translator, config1_path,
			    sizeof(config1_path))
	    != 0) {
		vty_out(vty, "%% Failed to process configurations.\n\n");
		return CMD_WARNING;
	}
	if (nb_write_config(config2, format, translator, config2_path,
			    sizeof(config2_path))
	    != 0) {
		vty_out(vty, "%% Failed to process configurations.\n\n");
		unlink(config1_path);
		return CMD_WARNING;
	}

	snprintf(command, sizeof(command), "diff -u %s %s", config1_path,
		 config2_path);
	fp = popen(command, "r");
	if (!fp) {
		vty_out(vty, "%% Failed to generate configuration diff.\n\n");
		unlink(config1_path);
		unlink(config2_path);
		return CMD_WARNING;
	}
	/* Print diff line by line. */
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (lineno++ < 2)
			continue;
		vty_out(vty, "%s", line);
	}
	pclose(fp);

	unlink(config1_path);
	unlink(config2_path);

	return CMD_SUCCESS;
}

/* Configure exclusively from this terminal. */
DEFUN (config_exclusive,
       config_exclusive_cmd,
       "configure exclusive",
       "Configuration from vty interface\n"
       "Configure exclusively from this terminal\n")
{
	return vty_config_enter(vty, true, true);
}

/* Configure using a private candidate configuration. */
DEFUN (config_private,
       config_private_cmd,
       "configure private",
       "Configuration from vty interface\n"
       "Configure using a private candidate configuration\n")
{
	return vty_config_enter(vty, true, false);
}

DEFPY (config_commit,
       config_commit_cmd,
       "commit [{force$force|confirmed (1-60)}]",
       "Commit changes into the running configuration\n"
       "Force commit even if the candidate is outdated\n"
       "Rollback this commit unless there is a confirming commit\n"
       "Timeout in minutes for the commit to be confirmed\n")
{
	return nb_cli_commit(vty, !!force, confirmed, NULL);
}

DEFPY (config_commit_comment,
       config_commit_comment_cmd,
       "commit [{force$force|confirmed (1-60)}] comment LINE...",
       "Commit changes into the running configuration\n"
       "Force commit even if the candidate is outdated\n"
       "Rollback this commit unless there is a confirming commit\n"
       "Timeout in minutes for the commit to be confirmed\n"
       "Assign a comment to this commit\n"
       "Comment for this commit (Max 80 characters)\n")
{
	char *comment;
	int idx = 0;
	int ret;

	argv_find(argv, argc, "LINE", &idx);
	comment = argv_concat(argv, argc, idx);
	ret = nb_cli_commit(vty, !!force, confirmed, comment);
	XFREE(MTYPE_TMP, comment);

	return ret;
}

DEFPY (config_commit_check,
       config_commit_check_cmd,
       "commit check",
       "Commit changes into the running configuration\n"
       "Check if the configuration changes are valid\n")
{
	int ret;

	ret = nb_candidate_validate(vty->candidate_config);
	if (ret != NB_OK) {
		vty_out(vty,
			"%% Failed to validate candidate configuration.\n\n");
		vty_show_libyang_errors(vty, ly_native_ctx);
		return CMD_WARNING;
	}

	vty_out(vty, "%% Candidate configuration validated successfully.\n\n");

	return CMD_SUCCESS;
}

DEFPY (config_update,
       config_update_cmd,
       "update",
       "Update candidate configuration\n")
{
	if (!nb_candidate_needs_update(vty->candidate_config)) {
		vty_out(vty, "%% Update is not necessary.\n\n");
		return CMD_SUCCESS;
	}

	if (nb_candidate_update(vty->candidate_config) != NB_OK) {
		vty_out(vty,
			"%% Failed to update the candidate configuration.\n\n");
		vty_out(vty, "Please check the logs for more details.\n");
		return CMD_WARNING;
	}

	nb_config_replace(vty->candidate_config_base, running_config, true);

	vty_out(vty, "%% Candidate configuration updated successfully.\n\n");

	return CMD_SUCCESS;
}

DEFPY (config_discard,
       config_discard_cmd,
       "discard",
       "Discard changes in the candidate configuration\n")
{
	nb_config_replace(vty->candidate_config, vty->candidate_config_base,
			  true);

	return CMD_SUCCESS;
}

DEFPY (config_load,
       config_load_cmd,
       "configuration load\
          <\
	    file [<json$json|xml$xml> [translate WORD$translator_family]] FILENAME$filename\
	    |transaction (1-4294967295)$tid\
	  >\
	  [replace$replace]",
       "Configuration related settings\n"
       "Load configuration into candidate\n"
       "Load configuration file into candidate\n"
       "Load configuration file in JSON format\n"
       "Load configuration file in XML format\n"
       "Translate configuration file\n"
       "YANG module translator\n"
       "Configuration file name (full path)\n"
       "Load configuration from transaction into candidate\n"
       "Transaction ID\n"
       "Replace instead of merge\n")
{
	if (filename) {
		enum nb_cfg_format format;
		struct yang_translator *translator = NULL;

		if (json)
			format = NB_CFG_FMT_JSON;
		else if (xml)
			format = NB_CFG_FMT_XML;
		else
			format = NB_CFG_FMT_CMDS;

		if (translator_family) {
			translator = yang_translator_find(translator_family);
			if (!translator) {
				vty_out(vty,
					"%% Module translator \"%s\" not found\n",
					translator_family);
				return CMD_WARNING;
			}
		}

		return nb_cli_candidate_load_file(vty, format, translator,
						  filename, !!replace);
	}

	return nb_cli_candidate_load_transaction(vty, tid, !!replace);
}

DEFPY (show_config_running,
       show_config_running_cmd,
       "show configuration running\
          [<json$json|xml$xml> [translate WORD$translator_family]]\
	  [with-defaults$with_defaults]",
       SHOW_STR
       "Configuration information\n"
       "Running configuration\n"
       "Change output format to JSON\n"
       "Change output format to XML\n"
       "Translate output\n"
       "YANG module translator\n"
       "Show default values\n")

{
	enum nb_cfg_format format;
	struct yang_translator *translator = NULL;

	if (json)
		format = NB_CFG_FMT_JSON;
	else if (xml)
		format = NB_CFG_FMT_XML;
	else
		format = NB_CFG_FMT_CMDS;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			return CMD_WARNING;
		}
	}

	nb_cli_show_config(vty, running_config, format, translator,
			   !!with_defaults);

	return CMD_SUCCESS;
}

DEFPY (show_config_candidate,
       show_config_candidate_cmd,
       "show configuration candidate\
          [<json$json|xml$xml> [translate WORD$translator_family]]\
          [<\
	    with-defaults$with_defaults\
	    |changes$changes\
	   >]",
       SHOW_STR
       "Configuration information\n"
       "Candidate configuration\n"
       "Change output format to JSON\n"
       "Change output format to XML\n"
       "Translate output\n"
       "YANG module translator\n"
       "Show default values\n"
       "Show changes applied in the candidate configuration\n")

{
	enum nb_cfg_format format;
	struct yang_translator *translator = NULL;

	if (json)
		format = NB_CFG_FMT_JSON;
	else if (xml)
		format = NB_CFG_FMT_XML;
	else
		format = NB_CFG_FMT_CMDS;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			return CMD_WARNING;
		}
	}

	if (changes)
		return nb_cli_show_config_compare(
			vty, vty->candidate_config_base, vty->candidate_config,
			format, translator);

	nb_cli_show_config(vty, vty->candidate_config, format, translator,
			   !!with_defaults);

	return CMD_SUCCESS;
}

DEFPY (show_config_candidate_section,
       show_config_candidate_section_cmd,
       "show",
       SHOW_STR)
{
	struct lyd_node *dnode;

	/* Top-level configuration node, display everything. */
	if (vty->xpath_index == 0)
		return nb_cli_show_config(vty, vty->candidate_config,
					  NB_CFG_FMT_CMDS, NULL, false);

	/* Display only the current section of the candidate configuration. */
	dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!dnode)
		/* Shouldn't happen. */
		return CMD_WARNING;

	nb_cli_show_dnode_cmds(vty, dnode, 0);
	vty_out(vty, "!\n");

	return CMD_SUCCESS;
}

DEFPY (show_config_compare,
       show_config_compare_cmd,
       "show configuration compare\
          <\
	    candidate$c1_candidate\
	    |running$c1_running\
	    |transaction (1-4294967295)$c1_tid\
	  >\
          <\
	    candidate$c2_candidate\
	    |running$c2_running\
	    |transaction (1-4294967295)$c2_tid\
	  >\
	  [<json$json|xml$xml> [translate WORD$translator_family]]",
       SHOW_STR
       "Configuration information\n"
       "Compare two different configurations\n"
       "Candidate configuration\n"
       "Running configuration\n"
       "Configuration transaction\n"
       "Transaction ID\n"
       "Candidate configuration\n"
       "Running configuration\n"
       "Configuration transaction\n"
       "Transaction ID\n"
       "Change output format to JSON\n"
       "Change output format to XML\n"
       "Translate output\n"
       "YANG module translator\n")
{
	enum nb_cfg_format format;
	struct yang_translator *translator = NULL;
	struct nb_config *config1, *config_transaction1 = NULL;
	struct nb_config *config2, *config_transaction2 = NULL;
	int ret = CMD_WARNING;

	if (c1_candidate)
		config1 = vty->candidate_config;
	else if (c1_running)
		config1 = running_config;
	else {
		config_transaction1 = nb_db_transaction_load(c1_tid);
		if (!config_transaction1) {
			vty_out(vty, "%% Transaction %u does not exist\n\n",
				(unsigned int)c1_tid);
			goto exit;
		}
		config1 = config_transaction1;
	}

	if (c2_candidate)
		config2 = vty->candidate_config;
	else if (c2_running)
		config2 = running_config;
	else {
		config_transaction2 = nb_db_transaction_load(c2_tid);
		if (!config_transaction2) {
			vty_out(vty, "%% Transaction %u does not exist\n\n",
				(unsigned int)c2_tid);
			goto exit;
		}
		config2 = config_transaction2;
	}

	if (json)
		format = NB_CFG_FMT_JSON;
	else if (xml)
		format = NB_CFG_FMT_XML;
	else
		format = NB_CFG_FMT_CMDS;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			goto exit;
		}
	}

	ret = nb_cli_show_config_compare(vty, config1, config2, format,
					 translator);
exit:
	if (config_transaction1)
		nb_config_free(config_transaction1);
	if (config_transaction2)
		nb_config_free(config_transaction2);

	return ret;
}

/*
 * Stripped down version of the "show configuration compare" command.
 * The "candidate" option is not present so the command can be installed in
 * the enable node.
 */
ALIAS (show_config_compare,
       show_config_compare_without_candidate_cmd,
       "show configuration compare\
          <\
	    running$c1_running\
	    |transaction (1-4294967295)$c1_tid\
	  >\
          <\
	    running$c2_running\
	    |transaction (1-4294967295)$c2_tid\
	  >\
	 [<json$json|xml$xml> [translate WORD$translator_family]]",
       SHOW_STR
       "Configuration information\n"
       "Compare two different configurations\n"
       "Running configuration\n"
       "Configuration transaction\n"
       "Transaction ID\n"
       "Running configuration\n"
       "Configuration transaction\n"
       "Transaction ID\n"
       "Change output format to JSON\n"
       "Change output format to XML\n"
       "Translate output\n"
       "YANG module translator\n")

DEFPY (clear_config_transactions,
       clear_config_transactions_cmd,
       "clear configuration transactions oldest (1-100)$n",
       CLEAR_STR
       "Configuration activity\n"
       "Delete transactions from the transactions log\n"
       "Delete oldest <n> transactions\n"
       "Number of transactions to delete\n")
{
#ifdef HAVE_CONFIG_ROLLBACKS
	if (nb_db_clear_transactions(n) != NB_OK) {
		vty_out(vty, "%% Failed to delete transactions.\n\n");
		return CMD_WARNING;
	}
#else
	vty_out(vty,
		"%% FRR was compiled without --enable-config-rollbacks.\n\n");
#endif /* HAVE_CONFIG_ROLLBACKS */

	return CMD_SUCCESS;
}

DEFPY (config_database_max_transactions,
       config_database_max_transactions_cmd,
       "configuration database max-transactions (1-100)$max",
       "Configuration related settings\n"
       "Configuration database\n"
       "Set the maximum number of transactions to store\n"
       "Number of transactions\n")
{
#ifdef HAVE_CONFIG_ROLLBACKS
	if (nb_db_set_max_transactions(max) != NB_OK) {
		vty_out(vty,
			"%% Failed to update the maximum number of transactions.\n\n");
		return CMD_WARNING;
	}
	vty_out(vty,
		"%% Maximum number of transactions updated successfully.\n\n");
#else
	vty_out(vty,
		"%% FRR was compiled without --enable-config-rollbacks.\n\n");
#endif /* HAVE_CONFIG_ROLLBACKS */

	return CMD_SUCCESS;
}

DEFPY (yang_module_translator_load,
       yang_module_translator_load_cmd,
       "yang module-translator load FILENAME$filename",
       "YANG related settings\n"
       "YANG module translator\n"
       "Load YANG module translator\n"
       "File name (full path)\n")
{
	struct yang_translator *translator;

	translator = yang_translator_load(filename);
	if (!translator) {
		vty_out(vty, "%% Failed to load \"%s\"\n\n", filename);
		vty_out(vty, "Please check the logs for more details.\n");
		return CMD_WARNING;
	}

	vty_out(vty, "%% Module translator \"%s\" loaded successfully.\n\n",
		translator->family);

	return CMD_SUCCESS;
}

DEFPY (yang_module_translator_unload_family,
       yang_module_translator_unload_cmd,
       "yang module-translator unload WORD$translator_family",
       "YANG related settings\n"
       "YANG module translator\n"
       "Unload YANG module translator\n"
       "Name of the module translator\n")
{
	struct yang_translator *translator;

	translator = yang_translator_find(translator_family);
	if (!translator) {
		vty_out(vty, "%% Module translator \"%s\" not found\n",
			translator_family);
		return CMD_WARNING;
	}

	yang_translator_unload(translator);

	return CMD_SUCCESS;
}

#ifdef HAVE_CONFIG_ROLLBACKS
static void nb_cli_show_transactions_cb(void *arg, int transaction_id,
					const char *client_name,
					const char *date, const char *comment)
{
	struct ttable *tt = arg;

	ttable_add_row(tt, "%d|%s|%s|%s", transaction_id, client_name, date,
		       comment);
}

static int nb_cli_show_transactions(struct vty *vty)
{
	struct ttable *tt;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Transaction ID|Client|Date|Comment");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	/* Fetch transactions from the northbound database. */
	if (nb_db_transactions_iterate(nb_cli_show_transactions_cb, tt)
	    != NB_OK) {
		vty_out(vty,
			"%% Failed to fetch configuration transactions.\n");
		return CMD_WARNING;
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	} else
		vty_out(vty, "No configuration transactions to display.\n\n");

	ttable_del(tt);

	return CMD_SUCCESS;
}
#endif /* HAVE_CONFIG_ROLLBACKS */

DEFPY (show_config_transaction,
       show_config_transaction_cmd,
       "show configuration transaction\
          [\
	    (1-4294967295)$transaction_id\
	    [<json$json|xml$xml> [translate WORD$translator_family]]\
            [<\
	      with-defaults$with_defaults\
	      |changes$changes\
	     >]\
	  ]",
       SHOW_STR
       "Configuration information\n"
       "Configuration transaction\n"
       "Transaction ID\n"
       "Change output format to JSON\n"
       "Change output format to XML\n"
       "Translate output\n"
       "YANG module translator\n"
       "Show default values\n"
       "Show changes compared to the previous transaction\n")
{
#ifdef HAVE_CONFIG_ROLLBACKS
	if (transaction_id) {
		struct nb_config *config;
		enum nb_cfg_format format;
		struct yang_translator *translator = NULL;

		if (json)
			format = NB_CFG_FMT_JSON;
		else if (xml)
			format = NB_CFG_FMT_XML;
		else
			format = NB_CFG_FMT_CMDS;

		if (translator_family) {
			translator = yang_translator_find(translator_family);
			if (!translator) {
				vty_out(vty,
					"%% Module translator \"%s\" not found\n",
					translator_family);
				return CMD_WARNING;
			}
		}

		config = nb_db_transaction_load(transaction_id);
		if (!config) {
			vty_out(vty, "%% Transaction %u does not exist.\n\n",
				(unsigned int)transaction_id);
			return CMD_WARNING;
		}

		if (changes) {
			struct nb_config *prev_config;
			int ret;

			/* NOTE: this can be NULL. */
			prev_config =
				nb_db_transaction_load(transaction_id - 1);

			ret = nb_cli_show_config_compare(
				vty, prev_config, config, format, translator);
			if (prev_config)
				nb_config_free(prev_config);
			nb_config_free(config);

			return ret;
		}

		nb_cli_show_config(vty, config, format, translator,
				   !!with_defaults);
		nb_config_free(config);

		return CMD_SUCCESS;
	}

	return nb_cli_show_transactions(vty);
#else
	vty_out(vty,
		"%% FRR was compiled without --enable-config-rollbacks.\n\n");
	return CMD_WARNING;
#endif /* HAVE_CONFIG_ROLLBACKS */
}

static int nb_cli_oper_data_cb(const struct lys_node *snode,
			       struct yang_translator *translator,
			       struct yang_data *data, void *arg)
{
	struct lyd_node *dnode = arg;
	struct ly_ctx *ly_ctx;

	if (translator) {
		int ret;

		ret = yang_translate_xpath(translator,
					   YANG_TRANSLATE_FROM_NATIVE,
					   data->xpath, sizeof(data->xpath));
		switch (ret) {
		case YANG_TRANSLATE_SUCCESS:
			break;
		case YANG_TRANSLATE_NOTFOUND:
			goto exit;
		case YANG_TRANSLATE_FAILURE:
			goto error;
		}

		ly_ctx = translator->ly_ctx;
	} else
		ly_ctx = ly_native_ctx;

	ly_errno = 0;
	dnode = lyd_new_path(dnode, ly_ctx, data->xpath, (void *)data->value, 0,
			     LYD_PATH_OPT_UPDATE);
	if (!dnode && ly_errno) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_new_path() failed",
			  __func__);
		goto error;
	}

exit:
	yang_data_free(data);
	return NB_OK;

error:
	yang_data_free(data);
	return NB_ERR;
}

DEFPY (show_yang_operational_data,
       show_yang_operational_data_cmd,
       "show yang operational-data XPATH$xpath\
         [{\
	   format <json$json|xml$xml>\
	   |translate WORD$translator_family\
	 }]",
       SHOW_STR
       "YANG information\n"
       "Show YANG operational data\n"
       "XPath expression specifying the YANG data path\n"
       "Set the output format\n"
       "JavaScript Object Notation\n"
       "Extensible Markup Language\n"
       "Translate operational data\n"
       "YANG module translator\n")
{
	LYD_FORMAT format;
	struct yang_translator *translator = NULL;
	struct ly_ctx *ly_ctx;
	struct lyd_node *dnode;
	char *strp;

	if (xml)
		format = LYD_XML;
	else
		format = LYD_JSON;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			return CMD_WARNING;
		}

		ly_ctx = translator->ly_ctx;
	} else
		ly_ctx = ly_native_ctx;

	/* Obtain data. */
	dnode = yang_dnode_new(ly_ctx, false);
	if (nb_oper_data_iterate(xpath, translator, 0, nb_cli_oper_data_cb,
				 dnode)
	    != NB_OK) {
		vty_out(vty, "%% Failed to fetch operational data.\n");
		yang_dnode_free(dnode);
		return CMD_WARNING;
	}
	lyd_validate(&dnode, LYD_OPT_GET, ly_ctx);

	/* Display the data. */
	if (lyd_print_mem(&strp, dnode, format,
			  LYP_FORMAT | LYP_WITHSIBLINGS | LYP_WD_ALL)
		    != 0
	    || !strp) {
		vty_out(vty, "%% Failed to display operational data.\n");
		yang_dnode_free(dnode);
		return CMD_WARNING;
	}
	vty_out(vty, "%s", strp);
	free(strp);
	yang_dnode_free(dnode);

	return CMD_SUCCESS;
}

DEFPY (show_yang_module,
       show_yang_module_cmd,
       "show yang module [module-translator WORD$translator_family]",
       SHOW_STR
       "YANG information\n"
       "Show loaded modules\n"
       "YANG module translator\n"
       "YANG module translator\n")
{
	struct ly_ctx *ly_ctx;
	struct yang_translator *translator = NULL;
	const struct lys_module *module;
	struct ttable *tt;
	uint32_t idx = 0;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			return CMD_WARNING;
		}
		ly_ctx = translator->ly_ctx;
	} else
		ly_ctx = ly_native_ctx;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Module|Version|Revision|Flags|Namespace");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	while ((module = ly_ctx_get_module_iter(ly_ctx, &idx))) {
		char flags[8];

		snprintf(flags, sizeof(flags), "%c%c",
			 module->implemented ? 'I' : ' ',
			 (module->deviated == 1) ? 'D' : ' ');

		ttable_add_row(tt, "%s|%s|%s|%s|%s", module->name,
			       (module->version == 2) ? "1.1" : "1.0",
			       (module->rev_size > 0) ? module->rev[0].date
						      : "-",
			       flags, module->ns);
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		vty_out(vty, " Flags: I - Implemented, D - Deviated\n\n");

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	} else
		vty_out(vty, "No YANG modules to display.\n\n");

	ttable_del(tt);

	return CMD_SUCCESS;
}

DEFPY (show_yang_module_detail,
       show_yang_module_detail_cmd,
       "show yang module\
          [module-translator WORD$translator_family]\
          WORD$module_name <summary|tree$tree|yang$yang|yin$yin>",
       SHOW_STR
       "YANG information\n"
       "Show loaded modules\n"
       "YANG module translator\n"
       "YANG module translator\n"
       "Module name\n"
       "Display summary information about the module\n"
       "Display module in the tree (RFC 8340) format\n"
       "Display module in the YANG format\n"
       "Display module in the YIN format\n")
{
	struct ly_ctx *ly_ctx;
	struct yang_translator *translator = NULL;
	const struct lys_module *module;
	LYS_OUTFORMAT format;
	char *strp;

	if (translator_family) {
		translator = yang_translator_find(translator_family);
		if (!translator) {
			vty_out(vty, "%% Module translator \"%s\" not found\n",
				translator_family);
			return CMD_WARNING;
		}
		ly_ctx = translator->ly_ctx;
	} else
		ly_ctx = ly_native_ctx;

	module = ly_ctx_get_module(ly_ctx, module_name, NULL, 0);
	if (!module) {
		vty_out(vty, "%% Module \"%s\" not found\n", module_name);
		return CMD_WARNING;
	}

	if (yang)
		format = LYS_OUT_YANG;
	else if (yin)
		format = LYS_OUT_YIN;
	else if (tree)
		format = LYS_OUT_TREE;
	else
		format = LYS_OUT_INFO;

	if (lys_print_mem(&strp, module, format, NULL, 0, 0) == 0) {
		vty_out(vty, "%s\n", strp);
		free(strp);
	} else {
		/* Unexpected. */
		vty_out(vty, "%% Error generating module information\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY (show_yang_module_translator,
       show_yang_module_translator_cmd,
       "show yang module-translator",
       SHOW_STR
       "YANG information\n"
       "Show loaded YANG module translators\n")
{
	struct yang_translator *translator;
	struct ttable *tt;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Family|Module|Deviations|Coverage (%%)");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	RB_FOREACH (translator, yang_translators, &yang_translators) {
		struct yang_tmodule *tmodule;
		struct listnode *ln;

		for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
			ttable_add_row(tt, "%s|%s|%s|%.2f", translator->family,
				       tmodule->module->name,
				       tmodule->deviations->name,
				       tmodule->coverage);
		}
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	} else
		vty_out(vty, "No YANG module translators to display.\n\n");

	ttable_del(tt);

	return CMD_SUCCESS;
}

#ifdef HAVE_CONFIG_ROLLBACKS
static int nb_cli_rollback_configuration(struct vty *vty,
					 uint32_t transaction_id)
{
	struct nb_config *candidate;
	char comment[80];
	int ret;

	candidate = nb_db_transaction_load(transaction_id);
	if (!candidate) {
		vty_out(vty, "%% Transaction %u does not exist.\n\n",
			transaction_id);
		return CMD_WARNING;
	}

	snprintf(comment, sizeof(comment), "Rollback to transaction %u",
		 transaction_id);

	ret = nb_candidate_commit(candidate, NB_CLIENT_CLI, vty, true, comment,
				  NULL);
	nb_config_free(candidate);
	switch (ret) {
	case NB_OK:
		vty_out(vty,
			"%% Configuration was successfully rolled back.\n\n");
		return CMD_SUCCESS;
	case NB_ERR_NO_CHANGES:
		vty_out(vty,
			"%% Aborting - no configuration changes detected.\n\n");
		return CMD_WARNING;
	default:
		vty_out(vty, "%% Rollback failed.\n\n");
		vty_out(vty, "Please check the logs for more details.\n");
		return CMD_WARNING;
	}
}
#endif /* HAVE_CONFIG_ROLLBACKS */

DEFPY (rollback_config,
       rollback_config_cmd,
       "rollback configuration (1-4294967295)$transaction_id",
       "Rollback to a previous state\n"
       "Running configuration\n"
       "Transaction ID\n")
{
#ifdef HAVE_CONFIG_ROLLBACKS
	return nb_cli_rollback_configuration(vty, transaction_id);
#else
	vty_out(vty,
		"%% FRR was compiled without --enable-config-rollbacks.\n\n");
	return CMD_SUCCESS;
#endif /* HAVE_CONFIG_ROLLBACKS */
}

/* Debug CLI commands. */
static struct debug *nb_debugs[] = {
	&nb_dbg_cbs_config, &nb_dbg_cbs_state, &nb_dbg_cbs_rpc,
	&nb_dbg_notif,      &nb_dbg_events,    &nb_dbg_libyang,
};

static const char *const nb_debugs_conflines[] = {
	"debug northbound callbacks configuration",
	"debug northbound callbacks state",
	"debug northbound callbacks rpc",
	"debug northbound notifications",
	"debug northbound events",
	"debug northbound libyang",
};

DEFINE_HOOK(nb_client_debug_set_all, (uint32_t flags, bool set), (flags, set));

static void nb_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(nb_debugs); i++) {
		DEBUG_FLAGS_SET(nb_debugs[i], flags, set);

		/* If all modes have been turned off, don't preserve options. */
		if (!DEBUG_MODE_CHECK(nb_debugs[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(nb_debugs[i]);
	}

	hook_call(nb_client_debug_set_all, flags, set);
}

DEFPY (debug_nb,
       debug_nb_cmd,
       "[no] debug northbound\
          [<\
	    callbacks$cbs [{configuration$cbs_cfg|state$cbs_state|rpc$cbs_rpc}]\
	    |notifications$notifications\
	    |events$events\
	    |libyang$libyang\
          >]",
       NO_STR
       DEBUG_STR
       "Northbound debugging\n"
       "Callbacks\n"
       "Configuration\n"
       "State\n"
       "RPC\n"
       "Notifications\n"
       "Events\n"
       "libyang debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	if (cbs) {
		bool none = (!cbs_cfg && !cbs_state && !cbs_rpc);

		if (none || cbs_cfg)
			DEBUG_MODE_SET(&nb_dbg_cbs_config, mode, !no);
		if (none || cbs_state)
			DEBUG_MODE_SET(&nb_dbg_cbs_state, mode, !no);
		if (none || cbs_rpc)
			DEBUG_MODE_SET(&nb_dbg_cbs_rpc, mode, !no);
	}
	if (notifications)
		DEBUG_MODE_SET(&nb_dbg_notif, mode, !no);
	if (events)
		DEBUG_MODE_SET(&nb_dbg_events, mode, !no);
	if (libyang) {
		DEBUG_MODE_SET(&nb_dbg_libyang, mode, !no);
		yang_debugging_set(!no);
	}

	/* no specific debug --> act on all of them */
	if (strmatch(argv[argc - 1]->text, "northbound")) {
		nb_debug_set_all(mode, !no);
		yang_debugging_set(!no);
	}

	return CMD_SUCCESS;
}

DEFINE_HOOK(nb_client_debug_config_write, (struct vty *vty), (vty));

static int nb_debug_config_write(struct vty *vty)
{
	for (unsigned int i = 0; i < array_size(nb_debugs); i++)
		if (DEBUG_MODE_CHECK(nb_debugs[i], DEBUG_MODE_CONF))
			vty_out(vty, "%s\n", nb_debugs_conflines[i]);

	hook_call(nb_client_debug_config_write, vty);

	return 1;
}

static struct debug_callbacks nb_dbg_cbs = {.debug_set_all = nb_debug_set_all};
static struct cmd_node nb_debug_node = {NORTHBOUND_DEBUG_NODE, "", 1};

void nb_cli_install_default(int node)
{
	install_element(node, &show_config_candidate_section_cmd);

	if (frr_get_cli_mode() != FRR_CLI_TRANSACTIONAL)
		return;

	install_element(node, &config_commit_cmd);
	install_element(node, &config_commit_comment_cmd);
	install_element(node, &config_commit_check_cmd);
	install_element(node, &config_update_cmd);
	install_element(node, &config_discard_cmd);
	install_element(node, &show_config_running_cmd);
	install_element(node, &show_config_candidate_cmd);
	install_element(node, &show_config_compare_cmd);
	install_element(node, &show_config_transaction_cmd);
}

/* YANG module autocomplete. */
static void yang_module_autocomplete(vector comps, struct cmd_token *token)
{
	const struct lys_module *module;
	struct yang_translator *module_tr;
	uint32_t idx;

	idx = 0;
	while ((module = ly_ctx_get_module_iter(ly_native_ctx, &idx)))
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, module->name));

	RB_FOREACH (module_tr, yang_translators, &yang_translators) {
		idx = 0;
		while ((module = ly_ctx_get_module_iter(module_tr->ly_ctx,
							&idx)))
			vector_set(comps,
				   XSTRDUP(MTYPE_COMPLETION, module->name));
	}
}

/* YANG module translator autocomplete. */
static void yang_translator_autocomplete(vector comps, struct cmd_token *token)
{
	struct yang_translator *module_tr;

	RB_FOREACH (module_tr, yang_translators, &yang_translators)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, module_tr->family));
}

static const struct cmd_variable_handler yang_var_handlers[] = {
	{.varname = "module_name", .completions = yang_module_autocomplete},
	{.varname = "translator_family",
	 .completions = yang_translator_autocomplete},
	{.completions = NULL}};

void nb_cli_init(struct thread_master *tm)
{
	master = tm;

	/* Initialize the shared candidate configuration. */
	vty_shared_candidate_config = nb_config_new(NULL);

	debug_init(&nb_dbg_cbs);

	install_node(&nb_debug_node, nb_debug_config_write);
	install_element(ENABLE_NODE, &debug_nb_cmd);
	install_element(CONFIG_NODE, &debug_nb_cmd);

	/* Install commands specific to the transaction-base mode. */
	if (frr_get_cli_mode() == FRR_CLI_TRANSACTIONAL) {
		install_element(ENABLE_NODE, &config_exclusive_cmd);
		install_element(ENABLE_NODE, &config_private_cmd);
		install_element(ENABLE_NODE, &show_config_running_cmd);
		install_element(ENABLE_NODE,
				&show_config_compare_without_candidate_cmd);
		install_element(ENABLE_NODE, &show_config_transaction_cmd);
		install_element(ENABLE_NODE, &rollback_config_cmd);
		install_element(ENABLE_NODE, &clear_config_transactions_cmd);

		install_element(CONFIG_NODE, &config_load_cmd);
		install_element(CONFIG_NODE,
				&config_database_max_transactions_cmd);
	}

	/* Other commands. */
	install_element(CONFIG_NODE, &yang_module_translator_load_cmd);
	install_element(CONFIG_NODE, &yang_module_translator_unload_cmd);
	install_element(ENABLE_NODE, &show_yang_operational_data_cmd);
	install_element(ENABLE_NODE, &show_yang_module_cmd);
	install_element(ENABLE_NODE, &show_yang_module_detail_cmd);
	install_element(ENABLE_NODE, &show_yang_module_translator_cmd);
	cmd_variable_handler_register(yang_var_handlers);
}

void nb_cli_terminate(void)
{
	nb_config_free(vty_shared_candidate_config);
}
