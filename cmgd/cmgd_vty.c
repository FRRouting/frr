/*
 * CMGD VTY Interface
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

#define INCLUDE_CMGD_CMDDEFS_ONLY

#include "lib/command.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_vty.h"
#include "cmgd/cmgd_bcknd_server.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "cmgd/cmgd_frntnd_server.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "cmgd/cmgd_db.h"

#ifndef VTYSH_EXTRACT_PL
#include "cmgd/cmgd_vty_clippy.c"
#endif


/* 
 * Declare prototypes for command initialization routines defined by
 * backend components that have been moved to new CMGD infra here 
 * one by one.
 */
extern void static_vty_init(void);

/*
 * cmgd_enqueue_nb_command
 *
 * Add a config command from VTYSH for further processing. 
 * 
 * NOTE: This function is ALWAYS called from one of the
 * command handlers installed on CMGD daemon that is invoked
 * by lib/vty.c on receiving a command from VTYSH.
 */
void cmgd_enqueue_vty_nb_command(struct vty *vty, const char *xpath,
				enum nb_operation operation,
				const char *value)
{
	switch (operation) {
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
	case NB_OP_DESTROY:
	case NB_OP_MOVE:
	case NB_OP_PRE_VALIDATE:
		/* Process on CMGD daemon itself */
		zlog_err("%s, cmd: '%s', '%s' xpath: '%s' ==> '%s'",
			__func__, vty->buf, nb_operation_name(operation),
			xpath, value ? value : "Nil");
		// vty_out(vty, "CMGD: Equeued XPATH '%s' ==> '%s'\n", xpath,
		// 	value ? value : "Nil");
		nb_cli_enqueue_change(vty, xpath, operation, value);
		break;
	case NB_OP_APPLY_FINISH:
	case NB_OP_GET_ELEM:
	case NB_OP_GET_NEXT:
	case NB_OP_GET_KEYS:
		/* To be sent to backend for processing */
		break;
	case NB_OP_LOOKUP_ENTRY:
	case NB_OP_RPC:
	default:
		break;
	}
}

/*
 * cmgd_apply_nb_commands
 *
 * Apply all config command enqueued from VTYSH so far for further
 * processing. 
 * 
 * NOTE: This function is ALWAYS called from one of the
 * command handlers installed on CMGD daemon that is invoked
 * by lib/vty.c on receiving a command from VTYSH.
 */
int cmgd_apply_vty_nb_commands(struct vty *vty, const char *xpath_base_fmt,
				...)
{
	char xpath_base[XPATH_MAXLEN] = {};

	/* Parse the base XPath format string. */
	if (xpath_base_fmt) {
		va_list ap;

		va_start(ap, xpath_base_fmt);
		vsnprintf(xpath_base, sizeof(xpath_base), xpath_base_fmt, ap);
		va_end(ap);
	}

	zlog_err("%s, cmd: '%s'", __func__, vty->buf);
	// vty_out(vty, "CMGD: Applying command '%s'\n", xpath_base);
#if 0
	return nb_cli_apply_changes(vty, xpath_base);
#else
	vty_cmgd_send_config_data(vty);
	return 0;
#endif
}

int cmgd_hndl_bknd_cmd(const struct cmd_element *cmd, struct vty *vty,
			int argc, struct cmd_token *argv[])
{
	vty_out(vty, "%s: %s, got the command '%s'\n", 
		frr_get_progname(), __func__, vty->buf);
	zlog_err("%s: %s, got the command '%s'", 
		frr_get_progname(), __func__, vty->buf);
	return 0;
}

DEFPY(show_cmgd_bcknd_adapter,
	show_cmgd_bcknd_adapter_cmd,
	"show cmgd backend-adapter all",
	SHOW_STR
	CMGD_STR
	CMGD_BCKND_ADPTR_STR
	"Display all Backend Adapters\n")
{
	cmgd_bcknd_adapter_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_bcknd_xpath_reg,
	show_cmgd_bcknd_xpath_reg_cmd,
	"show cmgd backend-yang-xpath-registry",
	SHOW_STR
	CMGD_STR
	"Backend Adapter YANG Xpath Registry\n")
{
	cmgd_bcknd_xpath_register_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_frntnd_adapter,
	show_cmgd_frntnd_adapter_cmd,
	"show cmgd frontend-adapter all",
	SHOW_STR
	CMGD_STR
	CMGD_FRNTND_ADPTR_STR
	"Display all Frontend Adapters\n")
{
	cmgd_frntnd_adapter_status_write(vty, false);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_frntnd_adapter_detail,
	show_cmgd_frntnd_adapter_detail_cmd,
	"show cmgd frontend-adapter all detail",
	SHOW_STR
	CMGD_STR
	CMGD_FRNTND_ADPTR_STR
	"Display all Frontend Adapters\n"
	"Details of commit stats\n")
{
	cmgd_frntnd_adapter_status_write(vty, true);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_trxn,
	show_cmgd_trxn_cmd,
	"show cmgd transaction all",
	SHOW_STR
	CMGD_STR
	CMGD_TRXN_STR
	"Display all Transactions\n")
{
	cmgd_trxn_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_db_all,
	show_cmgd_db_all_cmd,
	"show cmgd database all",
	SHOW_STR
	CMGD_STR
	CMGD_TRXN_STR
	"Display all Databases\n")
{
	cmgd_db_status_write(vty);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_db_runn,
	show_cmgd_db_runn_cmd,
	"show cmgd database running",
	SHOW_STR
	CMGD_STR
	CMGD_TRXN_STR
	"Display Running Database\n")
{
	cmgd_db_hndl_t db_hndl;

	db_hndl = cmgd_db_get_hndl_by_id(cm, CMGD_DB_RUNNING);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Couldnot access running database!\n");
		return CMD_ERR_NO_MATCH;
	}

	cmgd_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_db_cand,
	show_cmgd_db_cand_cmd,
	"show cmgd database candidate",
	SHOW_STR
	CMGD_STR
	CMGD_DB_STR
	"Display Candidate Database\n")
{
	cmgd_db_hndl_t db_hndl;

	db_hndl = cmgd_db_get_hndl_by_id(cm, CMGD_DB_CANDIDATE);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Couldnot access candidate database!\n");
		return CMD_ERR_NO_MATCH;
	}

	cmgd_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(show_cmgd_db_oper,
	show_cmgd_db_oper_cmd,
	"show cmgd database operational",
	SHOW_STR
	CMGD_STR
	CMGD_DB_STR
	"Display Operational Database\n")
{
	cmgd_db_hndl_t db_hndl;

	db_hndl = cmgd_db_get_hndl_by_id(cm, CMGD_DB_OPERATIONAL);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Couldnot access operational database!\n");
		return CMD_ERR_NO_MATCH;
	}

	cmgd_db_status_write_one(vty, db_hndl);

	return CMD_SUCCESS;
}

DEFPY(cmgd_commit_apply,
      cmgd_commit_apply_cmd,
      "cmgd commit-apply",
      CMGD_STR
      "Validate and apply the set of config commands\n")
{
	if (vty_cmgd_send_commit_config(vty, false, false) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(cmgd_commit_check,
      cmgd_commit_check_cmd,
      "cmgd commit-check",
      CMGD_STR
      "Validate the set of config commands only\n")
{
	if (vty_cmgd_send_commit_config(vty, true, false) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(cmgd_commit_abort,
      cmgd_commit_abort_cmd,
      "cmgd commit-abort",
      CMGD_STR
      "Abort and drop the set of config commands recently added\n")
{
	if (vty_cmgd_send_commit_config(vty, false, true) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(cmgd_set_config_data,
      cmgd_set_config_data_cmd,
      "cmgd set-config xpath WORD$path value WORD$val",
      CMGD_STR
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

	vty_cmgd_send_config_data(vty);
	return CMD_SUCCESS;
}

DEFPY(cmgd_delete_config_data,
      cmgd_delete_config_data_cmd,
      "cmgd delete-config xpath WORD$path",
      CMGD_STR
      "Delete configuration data\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n")
{

	strlcpy(vty->cfg_changes[0].xpath, path,
		sizeof(vty->cfg_changes[0].xpath));
	vty->cfg_changes[0].value = NULL;
	vty->cfg_changes[0].operation = NB_OP_DESTROY;
	vty->num_cfg_changes = 1;

	vty_cmgd_send_config_data(vty);
	return CMD_SUCCESS;
}

DEFPY(show_cmgd_get_config,
	  show_cmgd_get_config_cmd,
	  "show cmgd get-config [db-name WORD$dbname] xpath WORD$path",
	  SHOW_STR
	  CMGD_STR
	  "Get configuration data from a specific configuration database\n"
	  "DB name\n"
	  "<candidate running operational>\n"
	  "XPath expression specifying the YANG data path\n"
	  "XPath string\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	cmgd_database_id_t database = CMGD_DB_CANDIDATE;

	if (dbname)
		database = cmgd_db_name2id(dbname);

	if (database == CMGD_DB_NONE) {
		vty_out(vty, "DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	xpath_list[0] = path;
	vty_cmgd_send_get_data(vty, database, xpath_list, 1);
	return CMD_SUCCESS;
}

DEFPY(show_cmgd_get_data,
	  show_cmgd_get_data_cmd,
	  "show cmgd get-data [db-name WORD$dbname] xpath WORD$path",
	  SHOW_STR
	  CMGD_STR
	  "Get data from a specific database\n"
	  "DB name\n"
	  "<candidate running operational>\n"
	  "XPath expression specifying the YANG data path\n"
	  "XPath string\n")
{
	const char *xpath_list[VTY_MAXCFGCHANGES] = {0};
	cmgd_database_id_t database = CMGD_DB_CANDIDATE;

	if (dbname)
		database = cmgd_db_name2id(dbname);

	if (database == CMGD_DB_NONE) {
		vty_out(vty, "DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	xpath_list[0] = path;
	vty_cmgd_send_get_data(vty, database, xpath_list, 1);
	return CMD_SUCCESS;
}

DEFPY(show_cmgd_dump_data,
      show_cmgd_dump_data_cmd,
      "show cmgd database-contents db-name WORD$dbname [xpath WORD$path] [filepath WORD$filepath] format WORD$format_str",
      SHOW_STR
      CMGD_STR
      "Get Database Contenents from a specific database\n"
      "DB name\n"
      "<candidate running operational\n"
      "XPath expression specifying the YANG data path\n"
      "XPath string\n"
      "Path to the file\n"
      "Path string\n"
      "Format the output\n"
      "JSON|XML")
{
	cmgd_database_id_t database = CMGD_DB_CANDIDATE;
	cmgd_db_hndl_t db_hndl;
	LYD_FORMAT format = LYD_UNKNOWN;
	FILE *f = NULL;

	database = cmgd_db_name2id(dbname);

	if (database == CMGD_DB_NONE) {
		vty_out(vty, "DB Name %s does not matches any existing database\n",
			dbname);
		return CMD_SUCCESS;
	}

	db_hndl = cmgd_db_get_hndl_by_id(cm, database);
	if (!db_hndl) {
		vty_out(vty, "ERROR: Couldnot access database!\n");
		return CMD_ERR_NO_MATCH;
	}

	if (filepath) {
		f = fopen(filepath, "w");
		if (!f) {
			vty_out(vty, "Could not open file pointed by filepath %s\n",
				filepath);
			return CMD_SUCCESS;
		}
	}

	format = cmgd_str2format(format_str);
	if (format == LYD_UNKNOWN) {
		vty_out(vty, "String Format %s does not matches existing format\n",
			format_str);
		return CMD_SUCCESS;
	}

	cmgd_db_dump_tree(vty, db_hndl, path, f, format);

	if (f)
		fclose(f);
	return CMD_SUCCESS;
}

DEFPY(show_cmgd_map_xpath,
	  show_cmgd_map_xpath_cmd,
	  "show cmgd yang-xpath-subscription WORD$path",
	  SHOW_STR
	  CMGD_STR
	  "Get YANG Backend Subscription\n"
	  "XPath expression specifying the YANG data path\n")
{
	cmgd_bcknd_xpath_subscr_info_write(vty, path);
	return CMD_SUCCESS;
}

DEFPY(cmgd_lock_db_candidate,
      cmgd_lock_db_cand_cmd,
      "cmgd lock-database candidate",
      CMGD_STR
      "Lock the database\n"
      "Candidate database\n")
{
	if (vty_cmgd_send_lockdb_req(vty, CMGD_DB_CANDIDATE, true) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

DEFPY(cmgd_unlock_db_candidate,
      cmgd_unlock_db_cand_cmd,
      "cmgd unlock-database candidate",
      CMGD_STR
      "Unlock the database\n"
      "Candidate database\n")
{
	if (vty_cmgd_send_lockdb_req(vty, CMGD_DB_CANDIDATE, false) != 0)
		return CMD_WARNING_CONFIG_FAILED;
	return CMD_SUCCESS;
}

void cmgd_vty_init(void)
{
	/* 
	 * Initialize command handling from VTYSH connection. 
	 * Call command initialization routines defined by
	 * backend components that are moved new CMGD infra
	 * here one by one.
	 */
	static_vty_init();

	install_element(VIEW_NODE, &show_cmgd_bcknd_adapter_cmd);
	install_element(VIEW_NODE, &show_cmgd_bcknd_xpath_reg_cmd);
	install_element(VIEW_NODE, &show_cmgd_frntnd_adapter_cmd);
	install_element(VIEW_NODE, &show_cmgd_frntnd_adapter_detail_cmd);
	install_element(VIEW_NODE, &show_cmgd_trxn_cmd);
	install_element(VIEW_NODE, &show_cmgd_db_all_cmd);
	install_element(VIEW_NODE, &show_cmgd_db_runn_cmd);
	install_element(VIEW_NODE, &show_cmgd_db_cand_cmd);
	install_element(VIEW_NODE, &show_cmgd_db_oper_cmd);
	install_element(VIEW_NODE, &show_cmgd_get_config_cmd);
	install_element(VIEW_NODE, &show_cmgd_get_data_cmd);
	install_element(VIEW_NODE, &show_cmgd_dump_data_cmd);
	install_element(VIEW_NODE, &show_cmgd_map_xpath_cmd);

	install_element(CONFIG_NODE, &cmgd_commit_apply_cmd);
	install_element(CONFIG_NODE, &cmgd_commit_abort_cmd);
	install_element(CONFIG_NODE, &cmgd_commit_check_cmd);
	install_element(CONFIG_NODE, &cmgd_lock_db_cand_cmd);
	install_element(CONFIG_NODE, &cmgd_unlock_db_cand_cmd);
	install_element(CONFIG_NODE, &cmgd_set_config_data_cmd);
	install_element(CONFIG_NODE, &cmgd_delete_config_data_cmd);

	/*
	 * TODO: Register and handlers for auto-completion here.
	 */
	// cmd_variable_handler_register(cmgd_viewvrf_var_handlers);
}
