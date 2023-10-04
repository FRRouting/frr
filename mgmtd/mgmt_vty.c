// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD VTY Interface
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>

#include "command.h"
#include "json.h"
#include "network.h"
#include "northbound_cli.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_adapter.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_history.h"

#include "mgmtd/mgmt_vty_clippy.c"

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
	vty->cfg_changes[0].operation = NB_OP_CREATE;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, false);
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
	vty->cfg_changes[0].operation = NB_OP_DESTROY;
	vty->num_cfg_changes = 1;

	vty_mgmt_send_config_data(vty, false);
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
      "show mgmt get-data [candidate|operational|running]$dsname WORD$path",
      SHOW_STR MGMTD_STR
      "Get data from a specific datastore\n"
      "Candidate datastore\n"
      "Operational datastore (default)\n"
      "Running datastore\n"
      "XPath expression specifying the YANG data path\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	Mgmtd__DatastoreId datastore = MGMTD_DS_OPERATIONAL;

	if (dsname)
		datastore = mgmt_ds_name2id(dsname);

	xpath_list[0] = path;
	vty_mgmt_send_get_req(vty, false, datastore, xpath_list, 1);
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
	mgmt_be_xpath_subscr_info_write(vty, path);
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
	.name = "debug",
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

	if (be)
		DEBUG_MODE_SET(&mgmt_debug_be, mode, !no);
	if (ds)
		DEBUG_MODE_SET(&mgmt_debug_ds, mode, !no);
	if (fe)
		DEBUG_MODE_SET(&mgmt_debug_fe, mode, !no);
	if (txn)
		DEBUG_MODE_SET(&mgmt_debug_txn, mode, !no);

	return CMD_SUCCESS;
}

static void mgmt_config_read_in(struct event *event)
{
	mgmt_vty_read_configs();
}

void mgmt_vty_init(void)
{
	/*
	 * Initialize command handling from VTYSH connection.
	 * Call command initialization routines defined by
	 * backend components that are moved to new MGMTD infra
	 * here one by one.
	 */
#if HAVE_STATICD
	extern void static_vty_init(void);
	static_vty_init();
#endif

	event_add_event(mm->master, mgmt_config_read_in, NULL, 0,
			&mgmt_daemon_info->read_in);

	install_node(&debug_node);

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
	install_element(CONFIG_NODE, &mgmt_set_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_delete_config_data_cmd);
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
