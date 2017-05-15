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

#include "pimd.h"
#include "pim_cmd.h"
#include "pim_iface.h"
#include "pim_zebra.h"
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_pim.h"
#include "pim_upstream.h"
#include "pim_rpf.h"
#include "pim_ssmpingd.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_ssm.h"
#include "pim_zlookup.h"
#include "pim_nht.h"

const char *const PIM_ALL_SYSTEMS = MCAST_ALL_SYSTEMS;
const char *const PIM_ALL_ROUTERS = MCAST_ALL_ROUTERS;
const char *const PIM_ALL_PIM_ROUTERS = MCAST_ALL_PIM_ROUTERS;
const char *const PIM_ALL_IGMP_ROUTERS = MCAST_ALL_IGMP_ROUTERS;

struct thread_master *master = NULL;
uint32_t qpim_debugs = 0;
int qpim_t_periodic =
	PIM_DEFAULT_T_PERIODIC; /* Period between Join/Prune Messages */
struct pim_assert_metric qpim_infinite_assert_metric;
long qpim_rpf_cache_refresh_delay_msec = 50;
struct thread *qpim_rpf_cache_refresher = NULL;
int64_t qpim_rpf_cache_refresh_requests = 0;
int64_t qpim_rpf_cache_refresh_events = 0;
int64_t qpim_rpf_cache_refresh_last = 0;
struct list *qpim_ssmpingd_list = NULL;
struct in_addr qpim_ssmpingd_group_addr;
int64_t qpim_scan_oil_events = 0;
int64_t qpim_scan_oil_last = 0;
struct list *qpim_static_route_list = NULL;
unsigned int qpim_keep_alive_time = PIM_KEEPALIVE_PERIOD;
signed int qpim_rp_keep_alive_time = 0;
int64_t qpim_nexthop_lookups = 0;
int qpim_packet_process = PIM_DEFAULT_PACKET_PROCESS;
uint8_t qpim_ecmp_enable = 0;
uint8_t qpim_ecmp_rebalance_enable = 0;
struct pim_instance *pimg = NULL;

int32_t qpim_register_suppress_time = PIM_REGISTER_SUPPRESSION_TIME_DEFAULT;
int32_t qpim_register_probe_time = PIM_REGISTER_PROBE_TIME_DEFAULT;

static struct pim_instance *pim_instance_init(struct vrf *vrf);
static void pim_instance_terminate(struct pim_instance *pim);

static int pim_vrf_new(struct vrf *vrf)
{
	zlog_debug("VRF Created: %s(%d)", vrf->name, vrf->vrf_id);
	return 0;
}

static int pim_vrf_delete(struct vrf *vrf)
{
	zlog_debug("VRF Deletion: %s(%d)", vrf->name, vrf->vrf_id);
	return 0;
}

static int pim_vrf_enable(struct vrf *vrf)
{
	struct pim_instance *pim;

	zlog_debug("%s: for %s", __PRETTY_FUNCTION__, vrf->name);
	pim = pim_instance_init(vrf);
	if (pim == NULL) {
		zlog_err("%s %s: pim class init failure ", __FILE__,
			 __PRETTY_FUNCTION__);
		/*
		 * We will crash and burn otherwise
		 */
		exit(1);
	}

	vrf->info = (void *)pim;

	if (vrf->vrf_id == VRF_DEFAULT)
		pimg = pim;

	return 0;
}

static int pim_vrf_disable(struct vrf *vrf)
{
	pim_instance_terminate((struct pim_instance *)vrf->info);

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

void pim_vrf_init(void)
{
	vrf_init(pim_vrf_new, pim_vrf_enable, pim_vrf_disable, pim_vrf_delete);
}

static void pim_vrf_terminate(void)
{
	vrf_terminate();
}

/* Key generate for pim->rpf_hash */
static unsigned int pim_rpf_hash_key(void *arg)
{
	struct pim_nexthop_cache *r = (struct pim_nexthop_cache *)arg;

	return jhash_1word(r->rpf.rpf_addr.u.prefix4.s_addr, 0);
}

/* Compare pim->rpf_hash node data */
static int pim_rpf_equal(const void *arg1, const void *arg2)
{
	const struct pim_nexthop_cache *r1 =
		(const struct pim_nexthop_cache *)arg1;
	const struct pim_nexthop_cache *r2 =
		(const struct pim_nexthop_cache *)arg2;

	return prefix_same(&r1->rpf.rpf_addr, &r2->rpf.rpf_addr);
}

/* Cleanup pim->rpf_hash each node data */
static void pim_rp_list_hash_clean(void *data)
{
	struct pim_nexthop_cache *pnc;

	pnc = (struct pim_nexthop_cache *)data;
	if (pnc->rp_list->count)
		list_delete_all_node(pnc->rp_list);
	if (pnc->upstream_list->count)
		list_delete_all_node(pnc->upstream_list);
}

void pim_prefix_list_update(struct prefix_list *plist)
{
	pim_rp_prefix_list_update(plist);
	pim_ssm_prefix_list_update(plist);
	pim_upstream_spt_prefix_list_update(plist);
}

struct pim_instance *pim_get_pim_instance(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	if (vrf)
		return vrf->info;

	return NULL;
}

static void pim_instance_terminate(struct pim_instance *pim)
{
	/* Traverse and cleanup rpf_hash */
	if (pim->rpf_hash) {
		hash_clean(pim->rpf_hash, (void *)pim_rp_list_hash_clean);
		hash_free(pim->rpf_hash);
		pim->rpf_hash = NULL;
	}

	if (pim->ssm_info) {
		pim_ssm_terminate(pim->ssm_info);
		pim->ssm_info = NULL;
	}

	XFREE(MTYPE_PIM_PIM_INSTANCE, pimg);
}

static void pim_free()
{
	pim_ssmpingd_destroy();

	pim_oil_terminate();

	pim_upstream_terminate();

	if (qpim_static_route_list)
		list_free(qpim_static_route_list);

	pim_if_terminate();
	pim_rp_free();

	pim_route_map_terminate();

	zclient_lookup_free();

	zprivs_terminate(&pimd_privs);
}

static struct pim_instance *pim_instance_init(struct vrf *vrf)
{
	struct pim_instance *pim;

	pim = XCALLOC(MTYPE_PIM_PIM_INSTANCE, sizeof(struct pim_instance));
	if (!pim)
		return NULL;

	pim->vrf_id = vrf->vrf_id;
	pim->vrf = vrf;

	pim->spt.switchover = PIM_SPT_IMMEDIATE;
	pim->spt.plist = NULL;

	pim->rpf_hash =
		hash_create_size(256, pim_rpf_hash_key, pim_rpf_equal, NULL);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: NHT rpf hash init ", __PRETTY_FUNCTION__);

	pim->ssm_info = pim_ssm_init();
	if (!pim->ssm_info) {
		pim_instance_terminate(pim);
		return NULL;
	}

	pim->send_v6_secondary = 1;

	if (vrf->vrf_id == VRF_DEFAULT)
		pimg = pim;

	pim_mroute_socket_enable(pim);

	return pim;
}

void pim_init()
{
	qpim_rp_keep_alive_time = PIM_RP_KEEPALIVE_PERIOD;

	pim_rp_init();

	if (!inet_aton(PIM_ALL_PIM_ROUTERS, &qpim_all_pim_routers_addr)) {
		zlog_err(
			"%s %s: could not solve %s to group address: errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__, PIM_ALL_PIM_ROUTERS,
			errno, safe_strerror(errno));
		zassert(0);
		return;
	}

	pim_oil_init();

	pim_upstream_init();

	qpim_static_route_list = list_new();
	if (!qpim_static_route_list) {
		zlog_err("%s %s: failure: static_route_list=list_new()",
			 __FILE__, __PRETTY_FUNCTION__);
		return;
	}
	qpim_static_route_list->del = (void (*)(void *))pim_static_route_free;

	/*
	  RFC 4601: 4.6.3.  Assert Metrics

	  assert_metric
	  infinite_assert_metric() {
	  return {1,infinity,infinity,0}
	  }
	*/
	qpim_infinite_assert_metric.rpt_bit_flag = 1;
	qpim_infinite_assert_metric.metric_preference =
		PIM_ASSERT_METRIC_PREFERENCE_MAX;
	qpim_infinite_assert_metric.route_metric = PIM_ASSERT_ROUTE_METRIC_MAX;
	qpim_infinite_assert_metric.ip_address.s_addr = INADDR_ANY;

	pim_if_init();
	pim_cmd_init();
	pim_ssmpingd_init();
}

void pim_terminate()
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
}
