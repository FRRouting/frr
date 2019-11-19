/* Zebra Router Code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include "zebra.h"

#include <pthread.h>
#include "lib/frratomic.h"

#include "zebra_router.h"
#include "zebra_memory.h"
#include "zebra_pbr.h"
#include "zebra_vxlan.h"
#include "zebra_mlag.h"
#include "zebra_nhg_private.h"
#include "debug.h"

DEFINE_MTYPE_STATIC(ZEBRA, RIB_TABLE_INFO, "RIB table info")

struct zebra_router zrouter = {
	.multipath_num = MULTIPATH_NUM,
	.ipv4_multicast_mode = MCAST_NO_CONFIG,
};

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
	rib_table_info_t *info;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.safi = safi;
	finder.tableid = tableid;
	finder.ns_id = zvrf->zns->ns_id;
	zrt = RB_FIND(zebra_router_table_head, &zrouter.tables, &finder);

	if (zrt)
		return zrt->table;

	zrt = XCALLOC(MTYPE_ZEBRA_NS, sizeof(*zrt));
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
		rib_table_info_t *info = route_table_get_info(zrt->table);

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
	zebra_nhg_sweep_table(zrouter.nhgs_id);
}

static void zebra_router_free_table(struct zebra_router_table *zrt)
{
	void *table_info;

	table_info = route_table_get_info(zrt->table);
	route_table_finish(zrt->table);
	RB_REMOVE(zebra_router_table_head, &zrouter.tables, zrt);

	XFREE(MTYPE_RIB_TABLE_INFO, table_info);
	XFREE(MTYPE_ZEBRA_NS, zrt);
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

void multicast_mode_ipv4_set(enum multicast_mode mode)
{
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: multicast lookup mode set (%d)", __func__,
			   mode);
	zrouter.ipv4_multicast_mode = mode;
}

enum multicast_mode multicast_mode_ipv4_get(void)
{
	return zrouter.ipv4_multicast_mode;
}

void zebra_router_terminate(void)
{
	struct zebra_router_table *zrt, *tmp;

	RB_FOREACH_SAFE (zrt, zebra_router_table_head, &zrouter.tables, tmp)
		zebra_router_free_table(zrt);

	work_queue_free_and_null(&zrouter.ribq);
	meta_queue_free(zrouter.mq);

	zebra_vxlan_disable();
	zebra_mlag_terminate();

	hash_clean(zrouter.nhgs, zebra_nhg_free);
	hash_free(zrouter.nhgs);
	hash_clean(zrouter.nhgs_id, NULL);
	hash_free(zrouter.nhgs_id);

	hash_clean(zrouter.rules_hash, zebra_pbr_rules_free);
	hash_free(zrouter.rules_hash);

	hash_clean(zrouter.ipset_entry_hash, zebra_pbr_ipset_entry_free),
		hash_clean(zrouter.ipset_hash, zebra_pbr_ipset_free);
	hash_free(zrouter.ipset_hash);
	hash_free(zrouter.ipset_entry_hash);
	hash_clean(zrouter.iptable_hash, zebra_pbr_iptable_free);
	hash_free(zrouter.iptable_hash);
}

void zebra_router_init(void)
{
	zrouter.sequence_num = 0;

	zrouter.packets_to_process = ZEBRA_ZAPI_PACKETS_TO_PROCESS;

	zrouter.rtadv_sock = -1;

	zebra_vxlan_init();
	zebra_mlag_init();

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
}
