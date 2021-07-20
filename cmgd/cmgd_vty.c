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

DEFPY(show_cmgd_frntnd_adapter,
	show_cmgd_frntnd_adapter_cmd,
	"show cmgd frontend-adapter all",
	SHOW_STR
	CMGD_STR
	CMGD_FRNTND_ADPTR_STR
	"Display all Frontend Adapters\n")
{
	cmgd_frntnd_adapter_status_write(vty);

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

DEFPY(show_cmgd_db,
	show_cmgd_db_cmd,
	"show cmgd database all",
	SHOW_STR
	CMGD_STR
	CMGD_TRXN_STR
	"Display all Databases\n")
{
	cmgd_db_status_write(vty);

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
	install_element(VIEW_NODE, &show_cmgd_frntnd_adapter_cmd);
	install_element(VIEW_NODE, &show_cmgd_trxn_cmd);
	install_element(VIEW_NODE, &show_cmgd_db_cmd);

	/*
	 * TODO: Register and handlers for auto-completion here.
	 */
	// cmd_variable_handler_register(cmgd_viewvrf_var_handlers);
}
