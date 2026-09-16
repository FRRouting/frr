// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
#include "bfd.h"
#include "filter.h"

#include "pimd.h"
#if PIM_IPV == 4
#include "pim_cmd.h"
#else
#include "pim6_cmd.h"
#endif
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_pim.h"
#include "pim_ssmpingd.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_ssm.h"
#include "pim_vxlan.h"
#include "pim_zlookup.h"
#include "pim_zebra.h"
#include "pim_mlag.h"
#include "pim_autorp.h"
#include "pim_iface.h"

#if MAXVIFS > 256
CPP_NOTICE("Work needs to be done to make this work properly via the pim mroute socket\n");
#endif /* MAXVIFS > 256 */

DEFINE_MTYPE_STATIC(PIMD, ROUTER, "PIM Router information");

struct pim_router *router = NULL;

#if PIM_IPV == 4
#if BYTE_ORDER == LITTLE_ENDIAN
const pim_addr qpim_all_systems_addr = { .s_addr = 0x010000E0 };     /* 224.0.0.1 */
const pim_addr qpim_all_routers_addr = { .s_addr = 0x020000E0 };     /* 224.0.0.2 */
const pim_addr qpim_all_pim_routers_addr = { .s_addr = 0x0D0000E0 }; /* 224.0.0.13 */
const pim_addr qpim_all_gmp_routers_addr = { .s_addr = 0x160000E0 }; /* 224.0.0.22 */
#else
const pim_addr qpim_all_systems_addr = { .s_addr = 0xE0000001 };     /* 224.0.0.1 */
const pim_addr qpim_all_routers_addr = { .s_addr = 0xE0000002 };     /* 224.0.0.2 */
const pim_addr qpim_all_pim_routers_addr = { .s_addr = 0xE000000D }; /* 224.0.0.13 */
const pim_addr qpim_all_gmp_routers_addr = { .s_addr = 0xE0000016 }; /* 224.0.0.22 */
#endif
#else
const pim_addr qpim_all_systems_addr = { .s6_addr = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						      0, 0, 1 } };
const pim_addr qpim_all_routers_addr = { .s6_addr = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						      0, 0, 2 } };
const pim_addr qpim_all_pim_routers_addr = { .s6_addr = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							  0, 0, 0, 0x0D } };
const pim_addr qpim_all_gmp_routers_addr = { .s6_addr = { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							  0, 0, 0, 0x16 } };
#endif

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
#if PIM_IPV == 4
		pim_autorp_prefix_list_update(pim, plist);
#endif
	}

	pim_boundary_prefix_list_update(plist);
}

void pim_access_list_update(struct access_list *access)
{
	pim_filter_ref_update();
	pim_boundary_access_list_update(access);
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
	router->t_prune_limit = PIM_DEFAULT_T_PRUNE_LIMIT;
	router->multipath = MULTIPATH_NUM;

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
	router->infinite_assert_metric.ip_address = PIMADDR_ANY;
	router->rpf_cache_refresh_delay_msec = 50;
	router->register_suppress_time = PIM_REGISTER_SUPPRESSION_TIME_DEFAULT;
	router->packet_process = PIM_DEFAULT_PACKET_PROCESS;
	router->register_probe_time = PIM_REGISTER_PROBE_TIME_DEFAULT;
	router->vrf_id = VRF_DEFAULT;
	router->pim_mlag_intf_cnt = 0;
	router->connected_to_mlag = false;
}

void pim_router_terminate(void)
{
	XFREE(MTYPE_ROUTER, router);
}

void pim_init(void)
{
	pim_cmd_init();
}

void pim_terminate(void)
{
	struct zclient *zclient;

	bfd_protocol_integration_set_shutdown(true);

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();
	access_list_reset();

	pim_vxlan_terminate();
	pim_vrf_terminate();

	zclient = pim_zebra_zclient_get();
	if (zclient) {
		zclient_stop(zclient);
		zclient_free(zclient);
	}

	pim_free();
	pim_mlag_terminate();
	pim_router_terminate();

	frr_fini();
}
