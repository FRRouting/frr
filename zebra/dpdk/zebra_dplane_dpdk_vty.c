// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Donald Sharp
 */
#include <zebra.h>

#include "lib/json.h"
#include "zebra/dpdk/zebra_dplane_dpdk.h"

#include "zebra/dpdk/zebra_dplane_dpdk_vty_clippy.c"

#define ZD_STR "Zebra dataplane information\n"
#define ZD_DPDK_STR "DPDK offload information\n"

DEFPY(zd_dpdk_show_counters, zd_dpdk_show_counters_cmd,
      "show dplane dpdk counters",
      SHOW_STR ZD_STR ZD_DPDK_STR "show counters\n")
{
	zd_dpdk_stat_show(vty);

	return CMD_SUCCESS;
}


DEFPY (zd_dpdk_show_ports,
       zd_dpdk_show_ports_cmd,
       "show dplane dpdk port [(1-32)$port_id] [detail$detail] [json$json]",
       SHOW_STR
       ZD_STR
       ZD_DPDK_STR
       "show port info\n"
       "DPDK port identifier\n"
       "Detailed information\n"
       JSON_STR)
{
	bool uj = !!json;
	bool ud = !!detail;

	if (!port_id)
		port_id = ZD_DPDK_INVALID_PORT;
	zd_dpdk_port_show(vty, port_id, uj, ud);

	return CMD_SUCCESS;
}


DEFPY (zd_dpdk_show_pbr_flows,
       zd_dpdk_show_pbr_flows_cmd,
       "show dplane dpdk pbr flows",
       SHOW_STR
       ZD_STR
       ZD_DPDK_STR
       "show pbr info\n"
       "DPDK flows\n")
{
	zd_dpdk_pbr_flows_show(vty);

	return CMD_SUCCESS;
}


void zd_dpdk_vty_init(void)
{
	install_element(VIEW_NODE, &zd_dpdk_show_counters_cmd);
	install_element(VIEW_NODE, &zd_dpdk_show_ports_cmd);
	install_element(VIEW_NODE, &zd_dpdk_show_pbr_flows_cmd);
}
