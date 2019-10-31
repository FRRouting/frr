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

#ifndef _FRR_NORTHBOUND_CLI_H_
#define _FRR_NORTHBOUND_CLI_H_

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Possible formats in which a configuration can be displayed. */
enum nb_cfg_format {
	NB_CFG_FMT_CMDS = 0,
	NB_CFG_FMT_JSON,
	NB_CFG_FMT_XML,
};

extern struct nb_config *vty_shared_candidate_config;

/*
 * Enqueue change to be applied in the candidate configuration.
 *
 * vty
 *    The vty context.
 *
 * xpath
 *    XPath (absolute or relative) of the configuration option being edited.
 *
 * operation
 *    Operation to apply (either NB_OP_CREATE, NB_OP_MODIFY or NB_OP_DELETE).
 *
 * value
 *    New value of the configuration option. Should be NULL for typeless YANG
 *    data (e.g. presence-containers). For convenience, NULL can also be used
 *    to restore a leaf to its default value.
 */
extern void nb_cli_enqueue_change(struct vty *vty, const char *xpath,
				  enum nb_operation operation,
				  const char *value);

/*
 * Apply enqueued changes to the candidate configuration.
 *
 * vty
 *    The vty context.
 *
 * xpath_base_fmt
 *    Prepend the given XPath (absolute or relative) to all enqueued
 *    configuration changes. This is an optional parameter.
 *
 * Returns:
 *    CMD_SUCCESS on success, CMD_WARNING_CONFIG_FAILED otherwise.
 */
extern int nb_cli_apply_changes(struct vty *vty, const char *xpath_base_fmt,
				...);

/*
 * Execute a YANG RPC or Action.
 *
 * xpath
 *    XPath of the YANG RPC or Action node.
 *
 * input
 *    List of 'yang_data' structures containing the RPC input parameters. It
 *    can be set to NULL when there are no input parameters.
 *
 * output
 *    List of 'yang_data' structures used to retrieve the RPC output parameters.
 *    It can be set to NULL when it's known that the given YANG RPC or Action
 *    doesn't have any output parameters.
 *
 * Returns:
 *    CMD_SUCCESS on success, CMD_WARNING otherwise.
 */
extern int nb_cli_rpc(const char *xpath, struct list *input,
		      struct list *output);

/*
 * Show CLI commands associated to the given YANG data node.
 *
 * vty
 *    The vty terminal to dump the configuration to.
 *
 * dnode
 *    libyang data node that should be shown in the form of CLI commands.
 *
 * show_defaults
 *    Specify whether to display default configuration values or not.
 */
extern void nb_cli_show_dnode_cmds(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);

/* Prototypes of internal functions. */
extern void nb_cli_show_config_prepare(struct nb_config *config,
				       bool with_defaults);
extern void nb_cli_confirmed_commit_clean(struct vty *vty);
extern int nb_cli_confirmed_commit_rollback(struct vty *vty);
extern void nb_cli_install_default(int node);
extern void nb_cli_init(struct thread_master *tm);
extern void nb_cli_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_CLI_H_ */
