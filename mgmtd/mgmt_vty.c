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
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_server.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_server.h"
#include "mgmtd/mgmt_fe_adapter.h"
#include "mgmtd/mgmt_ds.h"

#include "mgmtd/mgmt_vty_clippy.c"

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

	vty->no_implicit_commit = true;
	vty_mgmt_send_config_data(vty);
	vty->no_implicit_commit = false;
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

	vty->no_implicit_commit = true;
	vty_mgmt_send_config_data(vty);
	vty->no_implicit_commit = false;
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
	vty_mgmt_send_get_config(vty, datastore, xpath_list, 1);
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
	vty_mgmt_send_get_data(vty, datastore, xpath_list, 1);
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

	if (datastore)
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

static int config_write_mgmt_debug(struct vty *vty)
{
	int n = mgmt_debug_be + mgmt_debug_fe + mgmt_debug_ds + mgmt_debug_txn;
	if (!n)
		return 0;
	if (n == 4) {
		vty_out(vty, "debug mgmt all\n");
		return 0;
	}

	vty_out(vty, "debug mgmt");
	if (mgmt_debug_be)
		vty_out(vty, " backend");
	if (mgmt_debug_ds)
		vty_out(vty, " datastore");
	if (mgmt_debug_fe)
		vty_out(vty, " frontend");
	if (mgmt_debug_txn)
		vty_out(vty, " transaction");

	vty_out(vty, "\n");

	return 0;
}
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_mgmt_debug,
};

DEFPY(debug_mgmt,
      debug_mgmt_cmd,
      "[no$no] debug mgmt <all$all|{backend$be|datastore$ds|frontend$fe|transaction$txn}>",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "All debug\n"
      "Back-end debug\n"
      "Datastore debug\n"
      "Front-end debug\n"
      "Transaction debug\n")
{
	bool set = !no;
	if (all)
		be = fe = ds = txn = set ? all : NULL;

	if (be)
		mgmt_debug_be = set;
	if (ds)
		mgmt_debug_ds = set;
	if (fe)
		mgmt_debug_fe = set;
	if (txn)
		mgmt_debug_txn = set;

	return CMD_SUCCESS;
}

void mgmt_vty_init(void)
{
	/*
	 * Initialize command handling from VTYSH connection.
	 * Call command initialization routines defined by
	 * backend components that are moved to new MGMTD infra
	 * here one by one.
	 */
#if 0
#if HAVE_STATICD
	extern void static_vty_init(void);
	static_vty_init();
#endif
#endif

	install_node(&debug_node);

	install_element(VIEW_NODE, &show_mgmt_be_adapter_cmd);
	install_element(VIEW_NODE, &show_mgmt_be_xpath_reg_cmd);
	install_element(VIEW_NODE, &show_mgmt_fe_adapter_cmd);
	install_element(VIEW_NODE, &show_mgmt_ds_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_config_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_data_cmd);
	install_element(VIEW_NODE, &show_mgmt_dump_data_cmd);
	install_element(VIEW_NODE, &show_mgmt_map_xpath_cmd);

	install_element(CONFIG_NODE, &mgmt_commit_cmd);
	install_element(CONFIG_NODE, &mgmt_set_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_delete_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_load_config_cmd);
	install_element(CONFIG_NODE, &mgmt_save_config_cmd);

	install_element(VIEW_NODE, &debug_mgmt_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_cmd);

	/*
	 * TODO: Register and handlers for auto-completion here (if any).
	 */
}
