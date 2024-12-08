// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#include <zebra.h>

#include "lib/hook.h"
#include "lib/libagentx.h"
#include "command.h"

DEFINE_HOOK(agentx_cli_enabled, (), ());
DEFINE_HOOK(agentx_cli_disabled, (), ());

bool agentx_enabled;

/* AgentX node. */
static int config_write_agentx(struct vty *vty)
{
	if (agentx_enabled)
		vty_out(vty, "agentx\n");
	return 1;
}

static struct cmd_node agentx_node = {
	.name = "smux",
	.node = SMUX_NODE,
	.prompt = "",
	.config_write = config_write_agentx,
};

DEFUN(agentx_enable, agentx_enable_cmd, "agentx",
      "SNMP AgentX protocol settings\n")
{
	if (!hook_have_hooks(agentx_cli_enabled)) {
		zlog_info(
			"agentx specified but the agentx Module is not loaded, is this intentional?");

		return CMD_SUCCESS;
	}

	hook_call(agentx_cli_enabled);

	return CMD_SUCCESS;
}

DEFUN(no_agentx, no_agentx_cmd, "no agentx",
      NO_STR "SNMP AgentX protocol settings\n")
{
	vty_out(vty, "SNMP AgentX support cannot be disabled once enabled\n");
	if (!hook_call(agentx_cli_disabled))
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

void libagentx_init(void)
{
	agentx_enabled = false;

	install_node(&agentx_node);
	install_element(CONFIG_NODE, &agentx_enable_cmd);
	install_element(CONFIG_NODE, &no_agentx_cmd);
}
