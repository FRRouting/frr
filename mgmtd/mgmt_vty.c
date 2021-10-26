/*
 * MGMTD VTY Interface
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

#include "command.h"
#include "lib/json.h"
#include "lib_errors.h"
#include "lib/libfrr.h"
#include "lib/zclient.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "stream.h"
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "lib_vty.h"
#include "hash.h"
#include "queue.h"
#include "filter.h"
#include "frrstr.h"

#define INCLUDE_MGMTD_CMDDEFS_ONLY

#include "lib/command.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_vty.h"
#include "mgmtd/mgmt_frntnd_server.h"
#include "mgmtd/mgmt_frntnd_adapter.h"
#include "mgmtd/mgmt_db.h"

#ifndef VTYSH_EXTRACT_PL
#include "mgmtd/mgmt_vty_clippy.c"
#endif

DEFPY(show_mgmt_frntnd_adapter,
      show_mgmt_frntnd_adapter_cmd,
      "show mgmt frontend-adapter all",
      SHOW_STR
      MGMTD_STR
      MGMTD_FRNTND_ADPTR_STR
      "Display all Frontend Adapters\n")
{
	mgmt_frntnd_adapter_status_write(vty, false);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_frntnd_adapter_detail,
      show_mgmt_frntnd_adapter_detail_cmd,
      "show mgmt frontend-adapter all detail",
      SHOW_STR
      MGMTD_STR
      MGMTD_FRNTND_ADPTR_STR
      "Display all Frontend Adapters\n"
      "Details of commit stats\n")
{
	mgmt_frntnd_adapter_status_write(vty, true);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_db_all,
      show_mgmt_db_all_cmd,
      "show mgmt database all",
      SHOW_STR
      MGMTD_STR
      MGMTD_DB_STR
      "Display all Databases\n")
{
	mgmt_db_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_db_runn,
      show_mgmt_db_runn_cmd,
      "show mgmt database running",
      SHOW_STR
      MGMTD_STR
      MGMTD_DB_STR
      "Display Running Database\n")
{
	uint64_t db_hndl;

	db_hndl = mgmt_db_get_hndl_by_id(mm, MGMTD_DB_RUNNING);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Coul dnot access running database!\n");
		return CMD_ERR_NO_MATCH;
	}

	mgmt_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_db_cand,
      show_mgmt_db_cand_cmd,
      "show mgmt database candidate",
      SHOW_STR
      MGMTD_STR
      MGMTD_DB_STR
      "Display Candidate Database\n")
{
	uint64_t db_hndl;

	db_hndl = mgmt_db_get_hndl_by_id(mm, MGMTD_DB_CANDIDATE);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Could not access candidate database!\n");
		return CMD_ERR_NO_MATCH;
	}

	mgmt_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(show_mgmt_db_oper,
      show_mgmt_db_oper_cmd,
      "show mgmt database operational",
      SHOW_STR
      MGMTD_STR
      MGMTD_DB_STR
      "Display Operational Database\n")
{
	uint64_t db_hndl;

	db_hndl = mgmt_db_get_hndl_by_id(mm, MGMTD_DB_OPERATIONAL);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Could not access operational database!\n");
		return CMD_ERR_NO_MATCH;
	}

	mgmt_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(mgmt_commit_apply,
      mgmt_commit_apply_cmd,
      "mgmt commit-apply",
      MGMTD_STR
      "Validate and apply the set of config commands\n")
{
	if (vty_mgmt_send_commit_config(vty, false, false) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(mgmt_commit_check,
      mgmt_commit_check_cmd,
      "mgmt commit-check",
      MGMTD_STR
      "Validate the set of config commands only\n")
{
	if (vty_mgmt_send_commit_config(vty, true, false) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(mgmt_commit_abort,
      mgmt_commit_abort_cmd,
      "mgmt commit-abort",
      MGMTD_STR
      "Abort and drop the set of config commands recently added\n")
{
	if (vty_mgmt_send_commit_config(vty, false, true) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(mgmt_set_config_data,
      mgmt_set_config_data_cmd,
      "mgmt set-config xpath WORD$path value WORD$val",
      MGMTD_STR
      "Set configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n"
      "Value of the data to set to\n"
      "<value of the data>\n")
{

	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = val;
	vty->cfg_changes[0].operation = NB_OP_CREATE;
	vty->num_cfg_changes = 1;

	vty->no_implicit_commit = true;
	vty_mgmt_send_config_data(vty);
	vty->no_implicit_commit = false;
	return CMD_SUCCESS;
}

DEFPY(mgmt_delete_config_data,
      mgmt_delete_config_data_cmd,
      "mgmt delete-config xpath WORD$path",
      MGMTD_STR
      "Delete configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n")
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

DEFPY(show_mgmt_get_config,
      show_mgmt_get_config_cmd,
      "show mgmt get-config [db-name WORD$dbname] xpath WORD$path",
      SHOW_STR
      MGMTD_STR
      "Get configuration data from a specific configuration database\n"
      "DB name\n"
      "<candidate running operational>\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	Mgmtd__DatabaseId database = MGMTD_DB_CANDIDATE;

	if (dbname)
		database = mgmt_db_name2id(dbname);

	if (database == MGMTD_DB_NONE) {
		vty_out(vty,
			"DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	xpath_list[0] = path;
	vty_mgmt_send_get_config(vty, database, xpath_list, 1);
	return CMD_SUCCESS;
}

DEFPY(show_mgmt_get_data,
      show_mgmt_get_data_cmd,
      "show mgmt get-data [db-name WORD$dbname] xpath WORD$path",
      SHOW_STR
      MGMTD_STR
      "Get data from a specific database\n"
      "DB name\n"
      "<candidate running operational>\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	Mgmtd__DatabaseId database = MGMTD_DB_CANDIDATE;

	if (dbname)
		database = mgmt_db_name2id(dbname);

	if (database == MGMTD_DB_NONE) {
		vty_out(vty,
			"DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	xpath_list[0] = path;
	vty_mgmt_send_get_data(vty, database, xpath_list, 1);
	return CMD_SUCCESS;
}



DEFPY(show_mgmt_dump_data,
      show_mgmt_dump_data_cmd,
      "show mgmt database-contents db-name WORD$dbname [xpath WORD$path] [file WORD$filepath] format WORD$format_str",
      SHOW_STR
      MGMTD_STR
      "Get Database contents from a specific database\n"
      "DB name\n"
      "<candidate | running | operational>\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n"
      "Dump the contents to a file\n"
      "Full path of the file\n"
      "Format of the output\n"
      "json|xml")
{
	Mgmtd__DatabaseId database = MGMTD_DB_CANDIDATE;
	uint64_t db_hndl;
	LYD_FORMAT format = LYD_UNKNOWN;
	FILE *f = NULL;

	database = mgmt_db_name2id(dbname);

	if (database == MGMTD_DB_NONE) {
		vty_out(vty,
			"DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	db_hndl = mgmt_db_get_hndl_by_id(mm, database);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Could not access database!\n");
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

	format = mgmt_str2format(format_str);
	if (format == LYD_UNKNOWN) {
		vty_out(vty,
			"String Format %s does not matches existing format\n",
			format_str);
		return CMD_SUCCESS;
	}

	mgmt_db_dump_tree(vty, db_hndl, path, f, format);

	if (f)
		fclose(f);
	return CMD_SUCCESS;
}

DEFPY(mgmt_load_config,
      mgmt_load_config_cmd,
      "mgmt load-config file WORD$filepath <merge|replace>",
      MGMTD_STR
      "Load configuration onto Candidate Database\n"
      "Read the configuration from a file\n"
      "Full path of the file\n"
      "Merge configuration with contents of Candidate Database\n"
      "Replace the existing contents of Candidate database")
{
	bool merge = false;
	int idx_merge = 4;
	int ret;
	uint64_t db_hndl;

	if (access(filepath, F_OK) == -1) {
		vty_out(vty, "ERROR: File %s : %s\n", filepath,
			strerror(errno));
		return CMD_ERR_NO_FILE;
	}

	db_hndl = mgmt_db_get_hndl_by_id(mm, MGMTD_DB_CANDIDATE);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Could not access Candidate database!\n");
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

	ret = mgmt_db_load_config_from_file(db_hndl, filepath, merge);
	if (ret != 0)
		vty_out(vty, "Error with parsing the file with error code %d\n",
			ret);
	return CMD_SUCCESS;
}

DEFPY(mgmt_save_config,
      mgmt_save_config_cmd,
      "mgmt save-config db-name WORD$dbname file WORD$filepath",
      MGMTD_STR
      "Save configuration from database\n"
      "Name of the database\n"
      "<candidate|running>"
      "Write the configuration to a file\n"
      "Full path of the file")
{
	uint64_t db_hndl;
	Mgmtd__DatabaseId database;
	FILE *f;

	database = mgmt_db_name2id(dbname);

	if (database == MGMTD_DB_NONE) {
		vty_out(vty,
			"DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	if (database != MGMTD_DB_CANDIDATE && database != MGMTD_DB_RUNNING) {
		vty_out(vty, "DB Name %s is not a configuration database\n",
			dbname);
		return CMD_SUCCESS;
	}

	db_hndl = mgmt_db_get_hndl_by_id(mm, database);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Could not access the '%s' database!\n",
			dbname);
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

	mgmt_db_dump_tree(vty, db_hndl, "/", f, LYD_JSON);

	fclose(f);

	return CMD_SUCCESS;
}

static int config_write_mgmt_debug(struct vty *vty)
{
	if (mgmt_debug_bcknd && mgmt_debug_frntnd && mgmt_debug_db
	    && mgmt_debug_trxn) {
		vty_out(vty, "debug mgmt all\n");
		return 0;
	}
	if (mgmt_debug_bcknd)
		vty_out(vty, "debug mgmt backend\n");
	if (mgmt_debug_frntnd)
		vty_out(vty, "debug mgmt frontend\n");
	if (mgmt_debug_db)
		vty_out(vty, "debug mgmt database\n");
	if (mgmt_debug_trxn)
		vty_out(vty, "debug mgmt transaction\n");

	return 0;
}
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_mgmt_debug,
};

DEFPY(debug_mgmt_bcknd,
      debug_mgmt_bcknd_cmd,
      "[no$no] debug mgmt backend",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "Debug Backend Functionality")
{
	if (no)
		mgmt_debug_bcknd = false;
	else
		mgmt_debug_bcknd = true;

	return CMD_SUCCESS;
}

DEFPY(debug_mgmt_frntnd,
      debug_mgmt_frntnd_cmd,
      "[no$no] debug mgmt frontend",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "Debug Frontend Functionality")
{
	if (no)
		mgmt_debug_frntnd = false;
	else
		mgmt_debug_frntnd = true;

	return CMD_SUCCESS;
}

DEFPY(debug_mgmt_db,
      debug_mgmt_db_cmd,
      "[no$no] debug mgmt database",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "Debug Database Functionality")
{
	if (no)
		mgmt_debug_db = false;
	else
		mgmt_debug_db = true;

	return CMD_SUCCESS;
}

DEFPY(debug_mgmt_trxn,
      debug_mgmt_trxn_cmd,
      "[no$no] debug mgmt transaction",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "Debug Transaction Functionality")
{
	if (no)
		mgmt_debug_trxn = false;
	else
		mgmt_debug_trxn = true;

	return CMD_SUCCESS;
}
DEFPY(debug_mgmt_all,
      debug_mgmt_all_cmd,
      "[no$no] debug mgmt all",
      NO_STR
      DEBUG_STR
      MGMTD_STR
      "Debug All Functionality")
{
	if (no) {
		mgmt_debug_bcknd = false;
		mgmt_debug_frntnd = false;
		mgmt_debug_db = false;
		mgmt_debug_trxn = false;
	} else {
		mgmt_debug_bcknd = true;
		mgmt_debug_frntnd = true;
		mgmt_debug_db = true;
		mgmt_debug_trxn = true;
	}

	return CMD_SUCCESS;
}

void mgmt_vty_init(void)
{
	install_node(&debug_node);

	install_element(VIEW_NODE, &show_mgmt_frntnd_adapter_cmd);
	install_element(VIEW_NODE, &show_mgmt_frntnd_adapter_detail_cmd);
	install_element(VIEW_NODE, &show_mgmt_db_all_cmd);
	install_element(VIEW_NODE, &show_mgmt_db_runn_cmd);
	install_element(VIEW_NODE, &show_mgmt_db_cand_cmd);
	install_element(VIEW_NODE, &show_mgmt_db_oper_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_config_cmd);
	install_element(VIEW_NODE, &show_mgmt_get_data_cmd);
	install_element(VIEW_NODE, &show_mgmt_dump_data_cmd);

	install_element(CONFIG_NODE, &mgmt_commit_apply_cmd);
	install_element(CONFIG_NODE, &mgmt_commit_abort_cmd);
	install_element(CONFIG_NODE, &mgmt_commit_check_cmd);
	install_element(CONFIG_NODE, &mgmt_set_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_delete_config_data_cmd);
	install_element(CONFIG_NODE, &mgmt_load_config_cmd);
	install_element(CONFIG_NODE, &mgmt_save_config_cmd);

	install_element(VIEW_NODE, &debug_mgmt_bcknd_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_bcknd_cmd);
	install_element(VIEW_NODE, &debug_mgmt_frntnd_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_frntnd_cmd);
	install_element(VIEW_NODE, &debug_mgmt_db_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_db_cmd);
	install_element(VIEW_NODE, &debug_mgmt_trxn_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_trxn_cmd);
	install_element(VIEW_NODE, &debug_mgmt_all_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_all_cmd);

	/*
	 * TODO: Register and handlers for auto-completion here (if any).
	 */
}
