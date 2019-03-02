/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#include "log.h"
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"
#include "hash.h"
#include "jhash.h"
#include "vrf.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_cmd.h"
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_pim.h"
#include "pim_ssmpingd.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_ssm.h"
#include "pim_zlookup.h"
#include "pim_zebra.h"

const char *const PIM_ALL_SYSTEMS = MCAST_ALL_SYSTEMS;
const char *const PIM_ALL_ROUTERS = MCAST_ALL_ROUTERS;
const char *const PIM_ALL_PIM_ROUTERS = MCAST_ALL_PIM_ROUTERS;
const char *const PIM_ALL_IGMP_ROUTERS = MCAST_ALL_IGMP_ROUTERS;

DEFINE_MTYPE_STATIC(PIMD, ROUTER, "PIM Router information");

struct pim_router *router = NULL;

void pim_prefix_list_update(struct prefix_list *plist)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		if (!pim)
			continue;

		pim_rp_prefix_list_update(pim, plist);
		pim_ssm_prefix_list_update(pim, plist);
		pim_upstream_spt_prefix_list_update(pim, plist);
	}
}

static void pim_free(void)
{
	pim_route_map_terminate();

	zclient_lookup_free();
}

void pim_router_init(void)
{
	router = XCALLOC(MTYPE_ROUTER, sizeof(*router));

	router->debugs = 0;
	router->master = frr_init();
	router->t_periodic = PIM_DEFAULT_T_PERIODIC;

	/*
	  RFC 4601: 4.6.3.  Assert Metrics

	  assert_metric
	  infinite_assert_metric() {
	  return {1,infinity,infinity,0}
	  }
	*/
	router->infinite_assert_metric.rpt_bit_flag = 1;
	router->infinite_assert_metric.metric_preference =
		PIM_ASSERT_METRIC_PREFERENCE_MAX;
	router->infinite_assert_metric.route_metric =
		PIM_ASSERT_ROUTE_METRIC_MAX;
	router->infinite_assert_metric.ip_address.s_addr = INADDR_ANY;
	router->rpf_cache_refresh_delay_msec = 50;
	router->register_suppress_time = PIM_REGISTER_SUPPRESSION_TIME_DEFAULT;
	router->packet_process = PIM_DEFAULT_PACKET_PROCESS;
	router->register_probe_time = PIM_REGISTER_PROBE_TIME_DEFAULT;
	router->vrf_id = VRF_DEFAULT;
}

void pim_router_terminate(void)
{
	XFREE(MTYPE_ROUTER, router);
}

void pim_init(void)
{
	if (!inet_aton(PIM_ALL_PIM_ROUTERS, &qpim_all_pim_routers_addr)) {
		flog_err(
			EC_LIB_SOCKET,
			"%s %s: could not solve %s to group address: errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__, PIM_ALL_PIM_ROUTERS,
			errno, safe_strerror(errno));
		zassert(0);
		return;
	}

	pim_cmd_init();
}

void pim_terminate(void)
{
	struct zclient *zclient;

	pim_free();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	pim_vrf_terminate();

	zclient = pim_zebra_zclient_get();
	if (zclient) {
		zclient_stop(zclient);
		zclient_free(zclient);
	}

	pim_router_terminate();
	frr_fini();
}
