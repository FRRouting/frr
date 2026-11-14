// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#include <zebra.h>

#include "lib/hook.h"
#include "lib/libagentx.h"
#include "lib/debug.h"
#include "command.h"
#include "lib/json.h"

#include "lib/libagentx_clippy.c"

DEFINE_HOOK(agentx_cli_enabled, (), ());
DEFINE_HOOK(agentx_cli_disabled, (), ());
DEFINE_HOOK(agentx_cli_show, (struct agentx_cli_status *status), (status));

bool agentx_enabled;

/*
 * Lives in libfrr rather than the SNMP module so the command is accepted by
 * every daemon vtysh sends it to, whether or not the module is loaded.
 */
struct debug agentx_dbg = {
	.conf = "debug agentx",
	.desc = "SNMP AgentX",
};

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

DEFPY(debug_agentx,
      debug_agentx_cmd,
      "[no] debug agentx",
      NO_STR DEBUG_STR
      "SNMP AgentX subagent activity\n")
{
	DEBUG_MODE_SET(&agentx_dbg, DEBUG_NODE2MODE(vty->node), !no);

	return CMD_SUCCESS;
}

static int agentx_show_json(struct vty *vty, bool module_loaded,
			    const struct agentx_cli_status *status)
{
	struct json_object *json;

	json = json_object_new_object();
	if (!json)
		return CMD_WARNING;

	json_object_boolean_add(json, "moduleLoaded", module_loaded);
	if (!module_loaded)
		return vty_json(vty, json);

	json_object_boolean_add(json, "enabled", status->enabled);
	json_object_boolean_add(json, "connected", status->connected);
	json_object_int_add(json, "pendingNotifications", status->pending);
	json_object_int_add(json, "droppedNotifications", (int64_t)status->dropped);

	if (status->socket_fd_valid)
		json_object_int_add(json, "socketFd", status->socket_fd);

	if (status->send_queued_valid)
		json_object_int_add(json, "socketSendQueued", status->send_queued);

	if (status->send_maximum_valid)
		json_object_int_add(json, "socketSendMaximum", status->send_maximum);

	return vty_json(vty, json);
}

static void agentx_show_text(struct vty *vty, bool module_loaded,
			     const struct agentx_cli_status *status)
{
	if (!module_loaded) {
		vty_out(vty, "AgentX module is not loaded\n");
		return;
	}

	vty_out(vty, "Enabled: %s\n", status->enabled ? "yes" : "no");
	vty_out(vty, "Master session: %s\n", status->connected ? "up" : "down");
	vty_out(vty, "Pending notifications: %" PRIu32 "\n", status->pending);
	vty_out(vty, "Dropped notifications: %" PRIu64 "\n", status->dropped);

	if (status->socket_fd_valid)
		vty_out(vty, "Socket fd: %d\n", status->socket_fd);

	if (status->send_queued_valid)
		vty_out(vty, "Socket send queued: %d bytes\n", status->send_queued);

	if (status->send_maximum_valid)
		vty_out(vty, "Socket send maximum: %d bytes\n", status->send_maximum);

	if (!status->send_queued_valid && !status->send_maximum_valid)
		vty_out(vty, "Socket send buffer: %s\n",
			status->connected ? "unavailable" : "not connected");
}

/* NOSH: vtysh installs the operator command and wraps one object per client. */
DEFPY_NOSH(show_agentx, show_agentx_cmd,
	   "show agentx status [json$json]",
	   SHOW_STR
	   "SNMP AgentX subagent\n"
	   "AgentX subagent status\n"
	   JSON_STR)
{
	struct agentx_cli_status status = {};
	bool module_loaded;

	/*
	 * agentx_cli_show_cb() in agentx.c fills status. It is registered
	 * from smux_init(); no hook means the SNMP module is not loaded.
	 */
	module_loaded = hook_have_hooks(agentx_cli_show);
	if (module_loaded)
		hook_call(agentx_cli_show, &status);

	if (json)
		return agentx_show_json(vty, module_loaded, &status);

	agentx_show_text(vty, module_loaded, &status);

	return CMD_SUCCESS;
}

void libagentx_init(void)
{
	agentx_enabled = false;

	install_node(&agentx_node);
	install_element(CONFIG_NODE, &agentx_enable_cmd);
	install_element(CONFIG_NODE, &no_agentx_cmd);

	debug_install(&agentx_dbg);
	install_element(ENABLE_NODE, &debug_agentx_cmd);
	install_element(CONFIG_NODE, &debug_agentx_cmd);

	install_element(VIEW_NODE, &show_agentx_cmd);
}
