// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
 *    Operation to apply (either NB_OP_CREATE, NB_OP_MODIFY or NB_OP_DESTROY).
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
 * Apply enqueued changes to the candidate configuration, do not batch,
 * and apply any pending commits along with the currently enqueued.
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
extern int nb_cli_apply_changes_clear_pending(struct vty *vty,
					      const char *xpath_base_fmt, ...)
	PRINTFRR(2, 3);

/*
 * Apply enqueued changes to the candidate configuration, this function
 * may not immediately apply the changes, instead adding them to a pending
 * queue.
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
				...) PRINTFRR(2, 3);

/*
 * Add an input child node for an RPC or an action.
 *
 * vty
 *    The vty context.
 *
 * xpath
 *    XPath of the child being added, relative to the input container.
 *
 * value
 *    Value of the child being added. Can be NULL for containers and leafs of
 *    type 'empty'.
 */
extern int nb_cli_rpc_enqueue(struct vty *vty, const char *xpath,
			      const char *value);

/*
 * Execute a YANG RPC or Action using the enqueued input parameters.
 *
 * vty
 *    The vty terminal to dump any error.
 *
 * xpath
 *    XPath of the YANG RPC or Action node.
 *
 * output_p
 *    A pointer to the libyang data node that will hold the output data tree.
 *    It can be set to NULL if the caller is not interested in processing the
 *    output. The caller is responsible for freeing the output data tree.
 *
 * Returns:
 *    CMD_SUCCESS on success, CMD_WARNING otherwise.
 */
extern int nb_cli_rpc(struct vty *vty, const char *xpath,
		      struct lyd_node **output_p);

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
extern void nb_cli_show_dnode_cmds(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);

/*
 * Perform pending commit, if any.
 *
 * vty
 *    The vty context.
 *
 * Returns
 *    CMD_SUCCESS on success (or no pending), CMD_WARNING_CONFIG_FAILED
 *    otherwise.
 */
extern int nb_cli_pending_commit_check(struct vty *vty);

/* Prototypes of internal functions. */
extern void nb_cli_show_config_prepare(struct nb_config *config,
				       bool with_defaults);
extern void nb_cli_confirmed_commit_clean(struct vty *vty);
extern int nb_cli_confirmed_commit_rollback(struct vty *vty);
extern void nb_cli_install_default(int node);
extern void nb_cli_init(struct event_loop *tm);
extern void nb_cli_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_CLI_H_ */
