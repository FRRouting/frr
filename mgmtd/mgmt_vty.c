// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD VTY Interface
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>

#include "affinitymap.h"
#include "command.h"
#include "filter.h"
#include "json.h"
#include "keychain.h"
#include "network.h"
#include "northbound_cli.h"
#include "routemap.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_adapter.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_history.h"

#include "mgmtd/mgmt_vty_clippy.c"
#include "ripd/rip_nb.h"
#include "ripngd/ripng_nb.h"
#include "staticd/static_vty.h"
#include "zebra/zebra_cli.h"

extern struct frr_daemon_info *mgmt_daemon_info;

DEFPY(show_mgmt_be_adapter,
      show_mgmt_be_adapter_cmd,
      "show mgmt backend-adapter all",
      SHOW_STR
      MGMTD_STR
      MGMTD_BE_ADAPTER_STR
      "Display all Backend Adapters\n")
{
	mgmt_be_adapter_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_be_xpath_reg,
      show_mgmt_be_xpath_reg_cmd,
      "show mgmt backend-yang-xpath-registry",
      SHOW_STR
      MGMTD_STR
      "Backend Adapter YANG Xpath Registry\n")
{
	mgmt_be_xpath_register_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_fe_adapter, show_mgmt_fe_adapter_cmd,
      "show mgmt frontend-adapter all [detail$detail]",
      SHOW_STR
      MGMTD_STR
      MGMTD_FE_ADAPTER_STR
      "Display all Frontend Adapters\n"
      "Display more details\n")
{
	mgmt_fe_adapter_status_write(vty, !!detail);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(mgmt_performance_measurement,
	     mgmt_performance_measurement_cmd,
	     "[no] mgmt performance-measurement",
	     NO_STR
	     MGMTD_STR
	     "Enable performance measurement\n")
{
	if (no)
		mgmt_fe_adapter_perf_measurement(vty, false);
	else
		mgmt_fe_adapter_perf_measurement(vty, true);

	return CMD_SUCCESS;
}

DEFPY(mgmt_reset_performance_stats,
      mgmt_reset_performance_stats_cmd,
      "mgmt reset-statistics",
      MGMTD_STR
      "Reset the Performance measurement statistics\n")
{
	mgmt_fe_adapter_reset_perf_stats(vty);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_txn,
      show_mgmt_txn_cmd,
      "show mgmt transaction all",
      SHOW_STR
      MGMTD_STR
      MGMTD_TXN_STR
      "Display all Transactions\n")
{
	mgmt_txn_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_ds,
      show_mgmt_ds_cmd,
      "show mgmt datastore [all|candidate|operational|running]$dsname",
      SHOW_STR
      MGMTD_STR
      MGMTD_DS_STR
      "All datastores (default)\n"
      "Candidate datastore\n"
      "Operational datastore\n"
      "Running datastore\n")
{
	struct mgmt_ds_ctx *ds_ctx;

	if (!dsname || dsname[0] == 'a') {
		mgmt_ds_status_write(vty);
		return CMD_SUCCESS;
	}
	ds_ctx = mgmt_ds_get_ctx_by_id(mm, mgmt_ds_name2id(dsname));
	if (!ds_ctx) {
		vty_out(vty, "ERROR: Could not access %s datastore!\n", dsname);
		return CMD_ERR_NO_MATCH;
	}
	mgmt_ds_status_write_one(vty, ds_ctx);

	return CMD_SUCCESS;
}

DEFPY(mgmt_commit,
      mgmt_commit_cmd,
      "mgmt commit <check|apply|abort>$type",
      MGMTD_STR
      "Commit action\n"
      "Validate the set of config commands\n"
      "Validate and apply the set of config commands\n"
      "Abort and drop the set of config commands recently added\n")
{
	bool validate_only = type[0] == 'c';
	bool abort = type[1] == 'b';

	if (vty_mgmt_send_commit_config(vty, validate_only, abort) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(mgmt_create_config_data, mgmt_create_config_data_cmd,
      "mgmt create-config WORD$path VALUE",
      MGMTD_STR
      "Create configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "Value of the data to create\n")
{
	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = value;
	vty->cfg_changes[0].operation = NB_OP_CREATE_EXCL;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, NULL, false);
	return CMD_SUCCESS;
}

DEFPY(mgmt_set_config_data, mgmt_set_config_data_cmd,
      "mgmt set-config WORD$path VALUE",
      MGMTD_STR
      "Set configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "Value of the data to set\n")
{
	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = value;
	vty->cfg_changes[0].operation = NB_OP_MODIFY;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, NULL, false);
	return CMD_SUCCESS;
}

DEFPY(mgmt_delete_config_data, mgmt_delete_config_data_cmd,
      "mgmt delete-config WORD$path",
      MGMTD_STR
      "Delete configuration data\n"
      "XPath expression specifying the YANG data path\n")
{

	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = NULL;
	vty->cfg_changes[0].operation = NB_OP_DELETE;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, NULL, false);
	return CMD_SUCCESS;
}

DEFPY(mgmt_remove_config_data, mgmt_remove_config_data_cmd,
      "mgmt remove-config WORD$path",
      MGMTD_STR
      "Remove configuration data\n"
      "XPath expression specifying the YANG data path\n")
{

	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = NULL;
	vty->cfg_changes[0].operation = NB_OP_DESTROY;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, NULL, false);
	return CMD_SUCCESS;
}

DEFPY(mgmt_replace_config_data, mgmt_replace_config_data_cmd,
      "mgmt replace-config WORD$path VALUE",
      MGMTD_STR
      "Replace configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "Value of the data to set\n")
{

	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = value;
	vty->cfg_changes[0].operation = NB_OP_REPLACE;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, NULL, false);
	return CMD_SUCCESS;
}

DEFPY(mgmt_edit, mgmt_edit_cmd,
      "mgmt edit {create|delete|merge|replace|remove}$op XPATH [json|xml]$fmt [lock$lock] [commit$commit] [DATA]",
      MGMTD_STR
      "Edit configuration data\n"
      "Create data\n"
      "Delete data\n"
      "Merge data\n"
      "Replace data\n"
      "Remove data\n"
      "XPath expression specifying the YANG data path\n"
      "JSON input format (default)\n"
      "XML input format\n"
      "Lock the datastores automatically\n"
      "Commit the changes automatically\n"
      "Data tree\n")
{
	LYD_FORMAT format = (fmt && fmt[0] == 'x') ? LYD_XML : LYD_JSON;
	uint8_t operation;
	uint8_t flags = 0;

	switch (op[2]) {
	case 'e':
		operation = NB_OP_CREATE_EXCL;
		break;
	case 'l':
		operation = NB_OP_DELETE;
		break;
	case 'r':
		operation = NB_OP_MODIFY;
		break;
	case 'p':
		operation = NB_OP_REPLACE;
		break;
	case 'm':
		operation = NB_OP_DESTROY;
		break;
	default:
		vty_out(vty, "Invalid operation!\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!data && (operation == NB_OP_CREATE_EXCL ||
		      operation == NB_OP_MODIFY || operation == NB_OP_REPLACE)) {
		vty_out(vty, "Data tree is missing!\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (lock)
		flags |= EDIT_FLAG_IMPLICIT_LOCK;

	if (commit)
		flags |= EDIT_FLAG_IMPLICIT_COMMIT;

	vty_mgmt_send_edit_req(vty, MGMT_MSG_DATASTORE_CANDIDATE, format, flags,
			       operation, xpath, data);
	return CMD_SUCCESS;
}

DEFPY(mgmt_rpc, mgmt_rpc_cmd,
      "mgmt rpc XPATH [json|xml]$fmt [DATA]",
      MGMTD_STR
      "Invoke RPC\n"
      "XPath expression specifying the YANG data path\n"
      "JSON input format (default)\n"
      "XML input format\n"
      "Input data tree\n")
{
	LYD_FORMAT format = (fmt && fmt[0] == 'x') ? LYD_XML : LYD_JSON;

	vty_mgmt_send_rpc_req(vty, format, xpath, data);
	return CMD_SUCCESS;
}

DEFPY(show_mgmt_get_config, show_mgmt_get_config_cmd,
      "show mgmt get-config [candidate|operational|running]$dsname WORD$path",
      SHOW_STR MGMTD_STR
      "Get configuration data from a specific configuration datastore\n"
      "Candidate datastore (default)\n"
      "Operational datastore\n"
      "Running datastore\n"
      "XPath expression specifying the YANG data path\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	Mgmtd__DatastoreId datastore = MGMTD_DS_CANDIDATE;

	if (dsname)
		datastore = mgmt_ds_name2id(dsname);

	xpath_list[0] = path;
	vty_mgmt_send_get_req(vty, true, datastore, xpath_list, 1);
	return CMD_SUCCESS;
}

DEFPY(show_mgmt_get_data, show_mgmt_get_data_cmd,
      "show mgmt get-data WORD$path [datastore <candidate|running|operational>$ds] [with-config|only-config]$content [exact]$exact [with-defaults <trim|all-tag|all>$wd] [json|xml]$fmt",
      SHOW_STR
      MGMTD_STR
      "Get a data from the operational datastore\n"
      "XPath expression specifying the YANG data root\n"
      "Specify datastore to get data from (operational by default)\n"
      "Candidate datastore\n"
      "Running datastore\n"
      "Operational datastore\n"
      "Include \"config true\" data\n"
      "Get only \"config true\" data\n"
      "Get exact node instead of the whole data tree\n"
      "Configure 'with-defaults' mode per RFC 6243 (\"explicit\" mode by default)\n"
      "Use \"trim\" mode\n"
      "Use \"report-all-tagged\" mode\n"
      "Use \"report-all\" mode\n"
      "JSON output format\n"
      "XML output format\n")
{
	LYD_FORMAT format = (fmt && fmt[0] == 'x') ? LYD_XML : LYD_JSON;
	int plen = strlen(path);
	char *xpath = NULL;
	uint8_t flags = content ? GET_DATA_FLAG_CONFIG : GET_DATA_FLAG_STATE;
	uint8_t defaults = GET_DATA_DEFAULTS_EXPLICIT;
	uint8_t datastore = MGMT_MSG_DATASTORE_OPERATIONAL;

	if (content && content[0] == 'w')
		flags |= GET_DATA_FLAG_STATE;

	if (exact)
		flags |= GET_DATA_FLAG_EXACT;

	if (wd) {
		if (wd[0] == 't')
			defaults = GET_DATA_DEFAULTS_TRIM;
		else if (wd[3] == '-')
			defaults = GET_DATA_DEFAULTS_ALL_ADD_TAG;
		else
			defaults = GET_DATA_DEFAULTS_ALL;
	}

	if (ds) {
		if (ds[0] == 'c')
			datastore = MGMT_MSG_DATASTORE_CANDIDATE;
		else if (ds[0] == 'r')
			datastore = MGMT_MSG_DATASTORE_RUNNING;
	}

	/* get rid of extraneous trailing slash-* or single '/' unless root */
	if (plen > 2 && ((path[plen - 2] == '/' && path[plen - 1] == '*') ||
			 (path[plen - 2] != '/' && path[plen - 1] == '/'))) {
		plen = path[plen - 1] == '/' ? plen - 1 : plen - 2;
		xpath = XSTRDUP(MTYPE_TMP, path);
		xpath[plen] = 0;
		path = xpath;
	}

	vty_mgmt_send_get_data_req(vty, datastore, format, flags, defaults,
				   path);

	if (xpath)
		XFREE(MTYPE_TMP, xpath);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_dump_data,
      show_mgmt_dump_data_cmd,
      "show mgmt datastore-contents [candidate|operational|running]$dsname [xpath WORD$path] [file WORD$filepath] <json|xml>$fmt",
      SHOW_STR
      MGMTD_STR
      "Get Datastore contents from a specific datastore\n"
      "Candidate datastore (default)\n"
      "Operational datastore\n"
      "Running datastore\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n"
      "Dump the contents to a file\n"
      "Full path of the file\n"
      "json output\n"
      "xml output\n")
{
	struct mgmt_ds_ctx *ds_ctx;
	Mgmtd__DatastoreId datastore = MGMTD_DS_CANDIDATE;
	LYD_FORMAT format = fmt[0] == 'j' ? LYD_JSON : LYD_XML;
	FILE *f = NULL;

	if (dsname)
		datastore = mgmt_ds_name2id(dsname);

	ds_ctx = mgmt_ds_get_ctx_by_id(mm, datastore);
	if (!ds_ctx) {
		vty_out(vty, "ERROR: Could not access datastore!\n");
		return CMD_ERR_NO_MATCH;
	}

	if (filepath) {
		f = fopen(filepath, "w");
		if (!f) {
			vty_out(vty,
				"Could not open file pointed by filepath %s\n",
				filepath);
			return CMD_SUCCESS;
		}
	}

	mgmt_ds_dump_tree(vty, ds_ctx, path, f, format);

	if (f)
		fclose(f);
	return CMD_SUCCESS;
}

DEFPY(show_mgmt_map_xpath,
      show_mgmt_map_xpath_cmd,
      "show mgmt yang-xpath-subscription WORD$path",
      SHOW_STR
      MGMTD_STR
      "Get YANG Backend Subscription\n"
      "XPath expression specifying the YANG data path\n")
{
	mgmt_be_show_xpath_registries(vty, path);
	return CMD_SUCCESS;
}

DEFPY(mgmt_load_config,
      mgmt_load_config_cmd,
      "mgmt load-config WORD$filepath <merge|replace>$type",
      MGMTD_STR
      "Load configuration onto Candidate Datastore\n"
      "Full path of the file\n"
      "Merge configuration with contents of Candidate Datastore\n"
      "Replace the existing contents of Candidate datastore\n")
{
	bool merge = type[0] == 'm' ? true : false;
	struct mgmt_ds_ctx *ds_ctx;
	int ret;

	if (access(filepath, F_OK) == -1) {
		vty_out(vty, "ERROR: File %s : %s\n", filepath,
			strerror(errno));
		return CMD_ERR_NO_FILE;
	}

	ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_CANDIDATE);
	if (!ds_ctx) {
		vty_out(vty, "ERROR: Could not access Candidate datastore!\n");
		return CMD_ERR_NO_MATCH;
	}

	ret = mgmt_ds_load_config_from_file(ds_ctx, filepath, merge);
	if (ret != 0)
		vty_out(vty, "Error with parsing the file with error code %d\n",
			ret);
	return CMD_SUCCESS;
}

DEFPY(mgmt_save_config,
      mgmt_save_config_cmd,
      "mgmt save-config <candidate|running>$dsname WORD$filepath",
      MGMTD_STR
      "Save configuration from datastore\n"
      "Candidate datastore\n"
      "Running datastore\n"
      "Full path of the file\n")
{
	Mgmtd__DatastoreId datastore = mgmt_ds_name2id(dsname);
	struct mgmt_ds_ctx *ds_ctx;
	FILE *f;

	ds_ctx = mgmt_ds_get_ctx_by_id(mm, datastore);
	if (!ds_ctx) {
		vty_out(vty, "ERROR: Could not access the '%s' datastore!\n",
			dsname);
		return CMD_ERR_NO_MATCH;
	}

	if (!filepath) {
		vty_out(vty, "ERROR: No file path mentioned!\n");
		return CMD_ERR_NO_MATCH;
	}

	f = fopen(filepath, "w");
	if (!f) {
		vty_out(vty, "Could not open file pointed by filepath %s\n",
			filepath);
		return CMD_SUCCESS;
	}

	mgmt_ds_dump_tree(vty, ds_ctx, "/", f, LYD_JSON);

	fclose(f);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_cmt_hist,
      show_mgmt_cmt_hist_cmd,
      "show mgmt commit-history",
      SHOW_STR
      MGMTD_STR
      "Show commit history\n")
{
	show_mgmt_cmt_history(vty);
	return CMD_SUCCESS;
}

DEFPY(mgmt_rollback,
      mgmt_rollback_cmd,
      "mgmt rollback <commit-id WORD$commit | last [(1-10)]$last>",
      MGMTD_STR
      "Rollback commits\n"
      "Rollback to commit ID\n"
      "Commit-ID\n"
      "Rollbak n commits\n"
      "Number of commits\n")
{
	if (commit)
		mgmt_history_rollback_by_id(vty, commit);
	else
		mgmt_history_rollback_n(vty, last);

	return CMD_SUCCESS;
}

int config_write_mgmt_debug(struct vty *vty);
static struct cmd_node debug_node = {
	.name = "mgmt debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_mgmt_debug,
};

static int write_mgmt_debug_helper(struct vty *vty, bool config)
{
	uint32_t mode = config ? DEBUG_MODE_CONF : DEBUG_MODE_ALL;
	bool be = DEBUG_MODE_CHECK(&mgmt_debug_be, mode);
	bool ds = DEBUG_MODE_CHECK(&mgmt_debug_ds, mode);
	bool fe = DEBUG_MODE_CHECK(&mgmt_debug_fe, mode);
	bool txn = DEBUG_MODE_CHECK(&mgmt_debug_txn, mode);

	if (!(be || ds || fe || txn))
		return 0;

	vty_out(vty, "debug mgmt");
	if (be)
		vty_out(vty, " backend");
	if (ds)
		vty_out(vty, " datastore");
	if (fe)
		vty_out(vty, " frontend");
	if (txn)
		vty_out(vty, " transaction");

	vty_out(vty, "\n");

	return 0;
}

int config_write_mgmt_debug(struct vty *vty)
{
	return write_mgmt_debug_helper(vty, true);
}

DEFPY_NOSH(show_debugging_mgmt, show_debugging_mgmt_cmd,
	   "show debugging [mgmt]", SHOW_STR DEBUG_STR "MGMT Information\n")
{
	vty_out(vty, "MGMT debugging status:\n");

	write_mgmt_debug_helper(vty, false);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

DEFPY(debug_mgmt, debug_mgmt_cmd,
      "[no$no] debug mgmt {backend$be|datastore$ds|frontend$fe|transaction$txn}",
      NO_STR DEBUG_STR MGMTD_STR
      "Backend debug\n"
      "Datastore debug\n"
      "Frontend debug\n"
      "Transaction debug\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	if (be) {
		DEBUG_MODE_SET(&mgmt_debug_be, mode, !no);
		mgmt_be_adapter_toggle_client_debug(
			DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL));
	}
	if (ds)
		DEBUG_MODE_SET(&mgmt_debug_ds, mode, !no);
	if (fe) {
		DEBUG_MODE_SET(&mgmt_debug_fe, mode, !no);
		mgmt_fe_adapter_toggle_client_debug(
			DEBUG_MODE_CHECK(&mgmt_debug_fe, DEBUG_MODE_ALL));
	}
	if (txn)
		DEBUG_MODE_SET(&mgmt_debug_txn, mode, !no);

	return CMD_SUCCESS;
}

static void mgmt_config_read_in(struct event *event)
{
	if (vty_mgmt_fe_enabled())
		mgmt_vty_read_configs();
	else {
		zlog_warn("%s: no connection to front-end server, retry in 1s",
			  __func__);
		event_add_timer(mm->master, mgmt_config_read_in, NULL, 1,
				&mgmt_daemon_info->read_in);
	}
}

static int mgmtd_config_write(struct vty *vty)
{
	struct lyd_node *root;

	LY_LIST_FOR (running_config->dnode, root) {
		nb_cli_show_dnode_cmds(vty, root, false);
	}

	return 1;
}

static struct cmd_node mgmtd_node = {
	.name = "mgmtd",
	.node = MGMTD_NODE,
	.prompt = "",
	.config_write = mgmtd_config_write,
};

void mgmt_vty_init(void)
{
	/*
	 * Library based CLI handlers
	 */
	filter_cli_init();
	route_map_cli_init();
	affinity_map_init();
	keychain_cli_init();

	/*
	 * Initialize command handling from VTYSH connection.
	 * Call command initialization routines defined by
	 * backend components that are moved to new MGMTD infra
	 * here one by one.
	 */
	zebra_cli_init();
#ifdef HAVE_RIPD
	rip_cli_init();
#endif
#ifdef HAVE_RIPNGD
	ripng_cli_init();
#endif
#ifdef HAVE_STATICD
	static_vty_init();
#endif

	event_add_event(mm->master, mgmt_config_read_in, NULL, 0,
			&mgmt_daemon_info->read_in);

	install_node(&debug_node);
	install_node(&mgmtd_node);

	install_element(VIEW_NODE, &show_mgmt_be_adapter_cmd);
	install_element(VIEW_NODE, &show_mgmt_be_xpath_reg_cmd);
	install_element(VIEW_NODE, &show_mgmt_fe_adapter_cmd);
	install_element(VIEW_NODE, &show_mgmt_txn_cmd);
	install_element(VIEW_NODE, &show_mgmt_ds_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_config_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_data_cmd);
	install_element(VIEW_NODE, &show_mgmt_dump_data_cmd);
	install_element(VIEW_NODE, &show_mgmt_map_xpath_cmd);
	install_element(VIEW_NODE, &show_mgmt_cmt_hist_cmd);

	install_element(CONFIG_NODE, &mgmt_commit_cmd);
	install_element(CONFIG_NODE, &mgmt_create_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_set_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_delete_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_remove_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_replace_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_edit_cmd);
	install_element(CONFIG_NODE, &mgmt_rpc_cmd);
	install_element(CONFIG_NODE, &mgmt_load_config_cmd);
	install_element(CONFIG_NODE, &mgmt_save_config_cmd);
	install_element(CONFIG_NODE, &mgmt_rollback_cmd);

	install_element(VIEW_NODE, &debug_mgmt_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_cmd);

	/* Enable view */
	install_element(ENABLE_NODE, &mgmt_performance_measurement_cmd);
	install_element(ENABLE_NODE, &mgmt_reset_performance_stats_cmd);

	install_element(ENABLE_NODE, &show_debugging_mgmt_cmd);

	mgmt_fe_client_lib_vty_init();
	/*
	 * TODO: Register and handlers for auto-completion here.
	 */
}
