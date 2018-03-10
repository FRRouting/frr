/*
 * Logical Router functions.
 * Copyright (C) 2018 6WIND S.A.
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

#include "ns.h"
#include "log.h"
#include "memory.h"

#include "command.h"
#include "vty.h"
#include "logicalrouter.h"

/* Comment that useless define to avoid compilation error
 * in order to use it, one could provide the kind of NETNS to NS backend
 * so that the allocation will match the logical router
 * DEFINE_MTYPE_STATIC(LIB, LOGICALROUTER, "LogicalRouter Context")
 */
DEFINE_MTYPE_STATIC(LIB, LOGICALROUTER_NAME, "Logical Router Name")

/* Logical Router node has no interface. */
static struct cmd_node logicalrouter_node = {LOGICALROUTER_NODE, "", 1};

static int logicalrouter_backend;

/* Get a NS. If not found, create one. */
static struct ns *logicalrouter_get(ns_id_t ns_id)
{
	struct ns *ns;

	ns = ns_lookup(ns_id);
	if (ns)
		return (ns);
	ns = ns_get_created(ns, NULL, ns_id);
	return ns;
}

static int logicalrouter_is_backend_netns(void)
{
	return (logicalrouter_backend == LOGICALROUTER_BACKEND_NETNS);
}


DEFUN_NOSH (logicalrouter,
       logicalrouter_cmd,
       "logical-router (1-65535) ns NAME",
       "Enable a logical-router\n"
       "Specify the logical-router indentifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 1;
	int idx_name = 3;
	ns_id_t ns_id;
	struct ns *ns = NULL;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;

	ns_id = strtoul(argv[idx_number]->arg, NULL, 10);
	ns = logicalrouter_get(ns_id);

	if (ns->name && strcmp(ns->name, pathname) != 0) {
		vty_out(vty, "NS %u is already configured with NETNS %s\n",
			ns->ns_id, ns->name);
		return CMD_WARNING;
	}

	if (!ns->name)
		ns->name = XSTRDUP(MTYPE_LOGICALROUTER_NAME, pathname);

	if (!ns_enable(ns, NULL)) {
		vty_out(vty, "Can not associate NS %u with NETNS %s\n",
			ns->ns_id, ns->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_logicalrouter,
       no_logicalrouter_cmd,
       "no logical-router (1-65535) ns NAME",
       NO_STR
       "Enable a Logical-Router\n"
       "Specify the Logical-Router identifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 2;
	int idx_name = 4;
	ns_id_t ns_id;
	struct ns *ns = NULL;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;

	ns_id = strtoul(argv[idx_number]->arg, NULL, 10);
	ns = ns_lookup(ns_id);

	if (!ns) {
		vty_out(vty, "NS %u is not found\n", ns_id);
		return CMD_SUCCESS;
	}

	if (ns->name && strcmp(ns->name, pathname) != 0) {
		vty_out(vty, "Incorrect NETNS file name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ns_disable(ns);

	if (ns->name) {
		XFREE(MTYPE_LOGICALROUTER_NAME, ns->name);
		ns->name = NULL;
	}

	return CMD_SUCCESS;
}

/* Initialize NS module. */
void logicalrouter_init(int (*writefunc)(struct vty *vty))
{
	if (ns_have_netns() && logicalrouter_is_backend_netns()) {
		/* Install LogicalRouter commands. */
		install_node(&logicalrouter_node, writefunc);
		install_element(CONFIG_NODE, &logicalrouter_cmd);
		install_element(CONFIG_NODE, &no_logicalrouter_cmd);
	}
}

void logicalrouter_terminate(void)
{
	ns_terminate();
}

void logicalrouter_configure_backend(int backend_netns)
{
	logicalrouter_backend = backend_netns;
}
