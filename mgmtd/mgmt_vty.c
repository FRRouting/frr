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
#include "mgmtd/mgmt_ds.h"

#ifndef VTYSH_EXTRACT_PL
#include "mgmtd/mgmt_vty_clippy.c"
#endif

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

DEFPY(show_mgmt_dump_data,
      show_mgmt_dump_data_cmd,
      "show mgmt datastore-contents WORD$dsname [xpath WORD$path] [file WORD$filepath] <json|xml>$fmt",
      SHOW_STR
      MGMTD_STR
      "Get Datastore contents from a specific datastore\n"
      "<candidate | running | operational>\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n"
      "Dump the contents to a file\n"
      "Full path of the file\n"
      "json|xml\n")
{
	enum mgmt_datastore_id datastore = MGMTD_DS_CANDIDATE;
	struct mgmt_ds_ctx *ds_ctx;
	LYD_FORMAT format = fmt[0] == 'j' ? LYD_JSON : LYD_XML;
	FILE *f = NULL;

	datastore = mgmt_ds_name2id(dsname);

	if (datastore == MGMTD_DS_NONE) {
		vty_out(vty,
			"DS Name %s does not matches any existing datastore\n",
			dsname);
		return CMD_SUCCESS;
	}

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

DEFPY(mgmt_load_config,
      mgmt_load_config_cmd,
      "mgmt load-config file WORD$filepath <merge|replace>",
      MGMTD_STR
      "Load configuration onto Candidate Datastore\n"
      "Read the configuration from a file\n"
      "Full path of the file\n"
      "Merge configuration with contents of Candidate Datastore\n"
      "Replace the existing contents of Candidate datastore\n")
{
	bool merge = false;
	int idx_merge = 4;
	int ret;
	struct mgmt_ds_ctx *ds_ctx;

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

	if (strncmp(argv[idx_merge]->arg, "merge", sizeof("merge")) == 0)
		merge = true;
	else if (strncmp(argv[idx_merge]->arg, "replace", sizeof("replace"))
		 == 0)
		merge = false;
	else {
		vty_out(vty, "Chosen option: %s not valid\n",
			argv[idx_merge]->arg);
		return CMD_SUCCESS;
	}

	ret = mgmt_ds_load_config_from_file(ds_ctx, filepath, merge);
	if (ret != 0)
		vty_out(vty, "Error with parsing the file with error code %d\n",
			ret);
	return CMD_SUCCESS;
}

DEFPY(mgmt_save_config,
      mgmt_save_config_cmd,
      "mgmt save-config datastore WORD$dsname file WORD$filepath",
      MGMTD_STR
      "Save configuration from datastore\n"
      "Datastore keyword\n"
      "<candidate|running>\n"
      "Write the configuration to a file\n"
      "Full path of the file\n")
{
	struct mgmt_ds_ctx *ds_ctx;
	enum mgmt_datastore_id datastore;
	FILE *f;

	datastore = mgmt_ds_name2id(dsname);

	if (datastore == MGMTD_DS_NONE) {
		vty_out(vty,
			"DS Name %s does not matches any existing datastore\n",
			dsname);
		return CMD_SUCCESS;
	}

	if (datastore != MGMTD_DS_CANDIDATE && datastore != MGMTD_DS_RUNNING) {
		vty_out(vty, "DS Name %s is not a configuration datastore\n",
			dsname);
		return CMD_SUCCESS;
	}

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
	install_node(&debug_node);

	install_element(VIEW_NODE, &show_mgmt_ds_cmd);
	install_element(VIEW_NODE, &show_mgmt_dump_data_cmd);

	install_element(CONFIG_NODE, &mgmt_load_config_cmd);
	install_element(CONFIG_NODE, &mgmt_save_config_cmd);

	install_element(VIEW_NODE, &debug_mgmt_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_cmd);

	/*
	 * TODO: Register and handlers for auto-completion here (if any).
	 */
}
