/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/json.h"
#include "zebra/dpdk/zebra_dplane_dpdk.h"

#ifndef VTYSH_EXTRACT_PL
#include "zebra/dpdk/zebra_dplane_dpdk_vty_clippy.c"
#endif

#define ZD_STR "Zebra dataplane information\n"
#define ZD_DPDK_STR "DPDK offload information\n"

DEFPY(zd_dpdk_show_counters, zd_dpdk_show_counters_cmd,
      "show dplane dpdk counters",
      SHOW_STR ZD_STR ZD_DPDK_STR "show counters\n")
{
	zd_dpdk_stat_show(vty);

	return CMD_SUCCESS;
}

void zd_dpdk_vty_init(void)
{
	install_element(VIEW_NODE, &zd_dpdk_show_counters_cmd);
}
