// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 19 2025, fenglei <fengleiljx@gmail.com>
 *
 */

#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_cli.h"

#include "ospfd/ospfd.h"
#include "lib/command.h"

#include "northbound_cli.h"
#include "ospfd/ospf_cli_clippy.c"

static int ospf_router_cmd_parse(struct vty *vty, struct cmd_token *argv[], const int argc,
				 unsigned short *instance, const char **vrf_name)
{
	int idx_vrf = 0, idx_inst = 0;

	*instance = 0;
	if (argv_find(argv, argc, "(1-65535)", &idx_inst)) {
		if (ospf_instance == 0) {
			vty_out(vty, "%% OSPF is not running in instance mode\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		*instance = strtoul(argv[idx_inst]->arg, NULL, 10);
	}

	*vrf_name = VRF_DEFAULT_NAME;
	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		if (ospf_instance != 0) {
			vty_out(vty, "%% VRF is not supported in instance mode\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		*vrf_name = argv[idx_vrf + 1]->arg;
	}

	return CMD_SUCCESS;
}

/*
 * XPath: /frr-ospfd:ospf/instance
 */
DEFPY_YANG_NOSH (router_ospf,
       router_ospf_cmd,
       "router ospf [{(1-65535)|vrf NAME}]",
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR)
{
	struct ospf *obj;
	char xpath[XPATH_MAXLEN];
	int ret;

	unsigned short instance;
	const char *vrf_name;

	ret = ospf_router_cmd_parse(vty, argv, argc, &instance, &vrf_name);
	if (ret != CMD_SUCCESS)
		return ret;

	if (instance != ospf_instance) {
		VTY_PUSH_CONTEXT_NULL(OSPF_NODE);
		return CMD_NOT_MY_INSTANCE;
	}

	snprintf(xpath, sizeof(xpath), "/frr-ospfd:ospf/instance[id='%u'][vrf='%s']", instance,
		 vrf_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(OSPF_NODE, xpath);

	/* this steps is pretty imporment, notify this vty client ospf instance */
	obj = ospf_lookup_instance(instance);
	VTY_PUSH_CONTEXT(OSPF_NODE, obj);

	return ret;
}

DEFPY_YANG (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf [{(1-65535)|vrf NAME}]",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	unsigned short instance;
	const char *vrf_name;

	if (ospf_router_cmd_parse(vty, argv, argc, &instance, &vrf_name) != CMD_SUCCESS)
		return CMD_WARNING_CONFIG_FAILED;

	if (instance != ospf_instance) {
		VTY_PUSH_CONTEXT_NULL(OSPF_NODE);
		return CMD_NOT_MY_INSTANCE;
	}

	snprintf(xpath, sizeof(xpath), "/frr-ospfd:ospf/instance[id='%u'][vrf='%s']", ospf_instance,
		 vrf_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

void cli_show_ospf_instance(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}


/* Install OSPF related cli commands. */
void ospf_cli_init(void)
{
	/* "router ospf" commands. */
	install_element(CONFIG_NODE, &router_ospf_cmd);
	install_element(CONFIG_NODE, &no_router_ospf_cmd);
}
