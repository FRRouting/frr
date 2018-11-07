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

struct cli_config_change {
	/*
	 * XPath (absolute or relative) of the configuration option being
	 * edited.
	 */
	char xpath[XPATH_MAXLEN];

	/*
	 * Operation to apply (either NB_OP_CREATE, NB_OP_MODIFY or
	 * NB_OP_DELETE).
	 */
	enum nb_operation operation;

	/*
	 * New value of the configuration option. Should be NULL for typeless
	 * YANG data (e.g. presence-containers). For convenience, NULL can also
	 * be used to restore a leaf to its default value.
	 */
	const char *value;
};

/* Possible formats in which a configuration can be displayed. */
enum nb_cfg_format {
	NB_CFG_FMT_CMDS = 0,
	NB_CFG_FMT_JSON,
	NB_CFG_FMT_XML,
};

extern struct nb_config *vty_shared_candidate_config;

/* Prototypes. */
extern int nb_cli_cfg_change(struct vty *vty, char *xpath_list,
			     struct cli_config_change changes[], size_t size);
extern int nb_cli_rpc(const char *xpath, struct list *input,
		      struct list *output);
extern void nb_cli_show_dnode_cmds(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
extern void nb_cli_install_default(int node);
extern void nb_cli_init(void);
extern void nb_cli_terminate(void);

#endif /* _FRR_NORTHBOUND_CLI_H_ */
