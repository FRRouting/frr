// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Router Code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#include "zebra.h"

#include <pthread.h>
#include "lib/frratomic.h"
#include "lib/hook.h"

#include "zebra_router.h"
#include "zebra_pbr.h"
#include "zebra_vxlan.h"
#include "zebra_mlag.h"
#include "zebra_nhg.h"
#include "zebra_neigh.h"
#include "zebra/zebra_tc.h"
#include "debug.h"
#include "zebra_script.h"
#include "wheel.h"

DEFINE_MTYPE_STATIC(ZEBRA, RIB_TABLE_INFO, "RIB table info");
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_RT_TABLE, "Zebra VRF table");

struct zebra_router zrouter = {
	.zav.multipath_num = MULTIPATH_NUM,
};

DEFINE_HOOK(nos_initialize_data, (struct zebra_architectural_values *zav), (zav));

static inline int
zebra_router_table_entry_compare(const struct zebra_router_table *e1,
				 const struct zebra_router_table *e2);

RB_GENERATE(zebra_router_table_head, zebra_router_table,
	    zebra_router_table_entry, zebra_router_table_entry_compare);


static inline int
zebra_router_table_entry_compare(const struct zebra_router_table *e1,
				 const struct zebra_router_table *e2)
{
	if (e1->tableid < e2->tableid)
		return -1;
	if (e1->tableid > e2->tableid)
		return 1;
	if (e1->ns_id < e2->ns_id)
		return -1;
	if (e1->ns_id > e2->ns_id)
		return 1;
	if (e1->afi < e2->afi)
		return -1;
	if (e1->afi > e2->afi)
		return 1;
	return (e1->safi - e2->safi);
}

struct zebra_router_table *zebra_router_find_zrt(struct zebra_vrf *zvrf,
						 uint32_t tableid, afi_t afi,
						 safi_t safi)
{
	struct zebra_router_table finder;
	struct zebra_router_table *zrt;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_FIND(zebra_router_table_head, &zrouter.tables, &finder);

	return zrt;
}

struct zebra_router_table *zebra_router_find_next_zrt(struct zebra_vrf *zvrf,
						      uint32_t tableid,
						      afi_t afi, safi_t safi)
{
	struct zebra_router_table finder;
	struct zebra_router_table *zrt;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_NFIND(zebra_router_table_head, &zrouter.tables, &finder);
	if (!zrt)
		return NULL;

	if (zrt->afi == afi && zrt->safi == safi && zrt->tableid == tableid &&
	    zrt->ns_id == finder.ns_id)
		zrt = RB_NEXT(zebra_router_table_head, zrt);

	return zrt;
}

struct route_table *zebra_router_find_table(struct zebra_vrf *zvrf,
					    uint32_t tableid, afi_t afi,
					    safi_t safi)
{
	struct zebra_router_table finder;
	struct zebra_router_table *zrt;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_FIND(zebra_router_table_head, &zrouter.tables, &finder);

	if (zrt)
		return zrt->table;
	else
		return NULL;
}

struct route_table *zebra_router_get_table(struct zebra_vrf *zvrf,
					   uint32_t tableid, afi_t afi,
					   safi_t safi)
{
	struct zebra_router_table finder;
	struct zebra_router_table *zrt;
	struct rib_table_info *info;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_FIND(zebra_router_table_head, &zrouter.tables, &finder);

	if (zrt)
		return zrt->table;

	zrt = XCALLOC(MTYPE_ZEBRA_RT_TABLE, sizeof(*zrt));
	zrt->tableid = tableid;
	zrt->afi = afi;
	zrt->safi = safi;
	zrt->ns_id = zvrf->zns->ns_id;
	zrt->table =
		(afi == AFI_IP6) ? srcdest_table_init() : route_table_init();

	info = XCALLOC(MTYPE_RIB_TABLE_INFO, sizeof(*info));
	info->zvrf = zvrf;
	info->afi = afi;
	info->safi = safi;
	info->table_id = tableid;
	route_table_set_info(zrt->table, info);
	zrt->table->cleanup = zebra_rtable_node_cleanup;

	RB_INSERT(zebra_router_table_head, &zrouter.tables, zrt);
	return zrt->table;
}

void zebra_router_show_table_summary(struct vty *vty)
{
	struct zebra_router_table *zrt;

	vty_out(vty,
		"VRF             NS ID    VRF ID     AFI            SAFI    Table      Count\n");
	vty_out(vty,
		"---------------------------------------------------------------------------\n");
	RB_FOREACH (zrt, zebra_router_table_head, &zrouter.tables) {
		struct rib_table_info *info = route_table_get_info(zrt->table);

		vty_out(vty, "%-16s%5d %9d %7s %15s %8d %10lu\n", info->zvrf->vrf->name,
			zrt->ns_id, info->zvrf->vrf->vrf_id,
			afi2str(zrt->afi), safi2str(zrt->safi),
			zrt->tableid,
			zrt->table->count);
	}
}

void zebra_router_sweep_route(void)
{
	struct zebra_router_table *zrt;

	RB_FOREACH (zrt, zebra_router_table_head, &zrouter.tables) {
		if (zrt->ns_id != NS_DEFAULT)
			continue;
		rib_sweep_table(zrt->table);
	}
}

void zebra_router_sweep_nhgs(void)
{
	zebra_nhg_sweep_table(zrouter.nhgs_id, false);
}

static void zebra_router_free_table(struct zebra_router_table *zrt)
{
	void *table_info;

	table_info = route_table_get_info(zrt->table);
	route_table_finish(zrt->table);
	RB_REMOVE(zebra_router_table_head, &zrouter.tables, zrt);

	XFREE(MTYPE_RIB_TABLE_INFO, table_info);
	XFREE(MTYPE_ZEBRA_RT_TABLE, zrt);
}

void zebra_router_release_table(struct zebra_vrf *zvrf, uint32_t tableid,
				afi_t afi, safi_t safi)
{
	struct zebra_router_table finder;
	struct zebra_router_table *zrt;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_FIND(zebra_router_table_head, &zrouter.tables, &finder);

	if (!zrt)
		return;

	zebra_router_free_table(zrt);
}

uint32_t zebra_router_get_next_sequence(void)
{
	return 1
	       + atomic_fetch_add_explicit(&zrouter.sequence_num, 1,
					   memory_order_relaxed);
}

static inline unsigned int interface_hash_key(const void *arg)
{
	const struct interface *ifp = arg;

	return ifp->ifindex;
}

void zebra_router_terminate(void)
{
	struct zebra_router_table *zrt, *tmp;

	if (zrouter.ra_wheel) {
		wheel_delete(zrouter.ra_wheel);
		zrouter.ra_wheel = NULL;
	}

	event_cancel(&zrouter.t_rib_sweep);

	RB_FOREACH_SAFE (zrt, zebra_router_table_head, &zrouter.tables, tmp)
		zebra_router_free_table(zrt);

	work_queue_free_and_null(&zrouter.ribq);
	meta_queue_free(zrouter.mq, NULL);

	zebra_vxlan_disable();
	zebra_mlag_terminate();
	zebra_neigh_terminate();

	/* Free NHE in ID table only since it has unhashable entries as well */
	hash_iterate(zrouter.nhgs_id, zebra_nhg_hash_free_zero_id, NULL);
	hash_clean_and_free(&zrouter.nhgs_id, zebra_nhg_hash_free);
	hash_clean_and_free(&zrouter.nhgs, NULL);

	hash_clean_and_free(&zrouter.rules_hash, zebra_pbr_rules_free);

	hash_clean_and_free(&zrouter.ipset_entry_hash,
			    zebra_pbr_ipset_entry_free);
	hash_clean_and_free(&zrouter.ipset_hash, zebra_pbr_ipset_free);
	hash_clean_and_free(&zrouter.iptable_hash, zebra_pbr_iptable_free);
	hash_clean_and_free(&zrouter.filter_hash, (void (*)(void *)) zebra_tc_filter_free);
	hash_clean_and_free(&zrouter.qdisc_hash, (void (*)(void *)) zebra_tc_qdisc_free);
	hash_clean_and_free(&zrouter.class_hash, (void (*)(void *)) zebra_tc_class_free);

#ifdef HAVE_SCRIPTING
	zebra_script_destroy();
#endif

	zebra_vxlan_terminate();
	/* OS-specific deinit */
	kernel_router_terminate();
}

bool zebra_router_notify_on_ack(void)
{
	return !zrouter.zav.asic_offloaded || zrouter.zav.notify_on_ack;
}

void zebra_router_init(bool asic_offload, bool notify_on_ack, bool v6_with_v4_nexthop,
		       bool nexthop_weight_16_bit)
{
	zrouter.sequence_num = 0;

	zrouter.protodown_r_bit = FRR_PROTODOWN_REASON_DEFAULT_BIT;

	zrouter.allow_delete = false;

	zrouter.packets_to_process = ZEBRA_ZAPI_PACKETS_TO_PROCESS;

	zrouter.nhg_keep = ZEBRA_DEFAULT_NHG_KEEP_TIMER;

	zrouter.gr_stale_cleanup_time_recorded = false;
	zrouter.gr_update_pending_time_recorded = false;

	/* Initialize the red-black tree for router tables */
	RB_INIT(zebra_router_table_head, &zrouter.tables);

	/*Init V6 RA batching stuffs*/
	zrouter.ra_wheel = wheel_init(zrouter.master, RTADV_TIMER_WHEEL_PERIOD_MS,
				      RTADV_TIMER_WHEEL_SLOTS_NO, interface_hash_key, process_rtadv,
				      NULL);

	zebra_vxlan_init();
	zebra_mlag_init();
	zebra_neigh_init();

	zrouter.rules_hash = hash_create_size(8, zebra_pbr_rules_hash_key,
					      zebra_pbr_rules_hash_equal,
					      "Rules Hash");

	zrouter.ipset_hash =
		hash_create_size(8, zebra_pbr_ipset_hash_key,
				 zebra_pbr_ipset_hash_equal, "IPset Hash");

	zrouter.ipset_entry_hash = hash_create_size(
		8, zebra_pbr_ipset_entry_hash_key,
		zebra_pbr_ipset_entry_hash_equal, "IPset Hash Entry");

	zrouter.iptable_hash = hash_create_size(8, zebra_pbr_iptable_hash_key,
						zebra_pbr_iptable_hash_equal,
						"IPtable Hash Entry");

	zrouter.nhgs =
		hash_create_size(8, zebra_nhg_hash_key, zebra_nhg_hash_equal,
				 "Zebra Router Nexthop Groups");
	zrouter.nhgs_id =
		hash_create_size(8, zebra_nhg_id_key, zebra_nhg_hash_id_equal,
				 "Zebra Router Nexthop Groups ID index");

	zrouter.qdisc_hash =
		hash_create_size(8, zebra_tc_qdisc_hash_key,
				 zebra_tc_qdisc_hash_equal, "TC (qdisc) Hash");
	zrouter.class_hash = hash_create_size(8, zebra_tc_class_hash_key,
					      zebra_tc_class_hash_equal,
					      "TC (classes) Hash");
	zrouter.filter_hash = hash_create_size(8, zebra_tc_filter_hash_key,
					       zebra_tc_filter_hash_equal,
					       "TC (filter) Hash");

	zrouter.zav.asic_offloaded = asic_offload;
	zrouter.zav.notify_on_ack = notify_on_ack;
	zrouter.zav.v6_with_v4_nexthop = v6_with_v4_nexthop;
	zrouter.zav.nexthop_weight_is_16bit = nexthop_weight_16_bit;

	zrouter.backup_nhs_installed = false;

	hook_call(nos_initialize_data, &zrouter.zav);

	if (!zrouter.zav.nexthop_weight_is_16bit)
		zrouter.nexthop_weight_scale_value = 255;
	else
		zrouter.nexthop_weight_scale_value = 0xFFFF;

#ifdef HAVE_SCRIPTING
	zebra_script_init();
#endif

	/* OS-specific init */
	kernel_router_init();
}
