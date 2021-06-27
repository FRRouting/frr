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

// #define INCLUDE_CMGD_CMDDEFS_ONLY

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
 * Client-specific command definitions first.
 */
// #include "staticd/static_vty.c"

void cmgd_enqueue_nb_commands(struct vty *vty, const char *xpath,
				enum nb_operation operation,
				const char *value)
{
	zlog_err("%s, cmd: '%s', xpath: '%s' ", __func__, vty->buf, xpath);

}

int cmgd_apply_nb_commands(struct vty *vty, const char *xpath_base_fmt,
				...)
{
	zlog_err("%s, cmd: '%s'", __func__, vty->buf);
	return 0;
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

void cmgd_vty_init(void)
{
	/* Initialize command handling from VTYSH connection */
	cmgd_init_bcknd_cmd();

	install_element(VIEW_NODE, &show_cmgd_bcknd_adapter_cmd);
	install_element(VIEW_NODE, &show_cmgd_frntnd_adapter_cmd);
	install_element(VIEW_NODE, &show_cmgd_trxn_cmd);

	/* Initialize CMGD Transaction module */
	cmgd_trxn_init(cm);

	/* Initialize the CMGD Backend Adapter Module */
	cmgd_bcknd_adapter_init(cm->master);

	/* Start the CMGD Backend Server for clients to connect */
	cmgd_bcknd_server_init(cm->master);
	
	/* Initialize the CMGD Frontend Adapter Module */
	cmgd_frntnd_adapter_init(cm->master);

	/* Start the CMGD Frontend Server for clients to connect */
	cmgd_frntnd_server_init(cm->master);
}
