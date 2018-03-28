/* zebra NS Routines
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 * Copyright (C) 2017/2018 6WIND
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"

#include "lib/ns.h"
#include "lib/vrf.h"
#include "lib/logicalrouter.h"
#include "lib/prefix.h"
#include "lib/memory.h"

#include "rtadv.h"
#include "zebra_ns.h"
#include "zebra_vrf.h"
#include "zebra_memory.h"
#include "rt.h"
#include "zebra_vxlan.h"
#include "debug.h"
#include "zebra_netns_notify.h"
#include "zebra_netns_id.h"
#include "zebra_pbr.h"
#include "rib.h"
#include "table_manager.h"

extern struct zebra_privs_t zserv_privs;

DEFINE_MTYPE(ZEBRA, ZEBRA_NS, "Zebra Name Space")

static inline int zebra_ns_table_entry_compare(const struct zebra_ns_table *e1,
					       const struct zebra_ns_table *e2);

RB_GENERATE(zebra_ns_table_head, zebra_ns_table, zebra_ns_table_entry,
	    zebra_ns_table_entry_compare);

static struct zebra_ns *dzns;

static inline int zebra_ns_table_entry_compare(const struct zebra_ns_table *e1,
					       const struct zebra_ns_table *e2)
{
	if (e1->tableid < e2->tableid)
		return -1;
	if (e1->tableid > e2->tableid)
		return 1;
	if (e1->ns_id < e2->ns_id)
		return -1;
	if (e1->ns_id > e2->ns_id)
		return 1;
	return (e1->afi - e2->afi);
}

static int logicalrouter_config_write(struct vty *vty);

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id)
{
	if (ns_id == NS_DEFAULT)
		return dzns;
	struct zebra_ns *info = (struct zebra_ns *)ns_info_lookup(ns_id);

	return (info == NULL) ? dzns : info;
}

static struct zebra_ns *zebra_ns_alloc(void)
{
	return XCALLOC(MTYPE_ZEBRA_NS, sizeof(struct zebra_ns));
}

static int zebra_ns_new(struct ns *ns)
{
	struct zebra_ns *zns;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (created)", ns->name, ns->ns_id);

	zns = zebra_ns_alloc();
	ns->info = zns;
	zns->ns = ns;

	/* Do any needed per-NS data structure allocation. */
	zns->if_table = route_table_init();
	zebra_vxlan_ns_init(zns);

	return 0;
}

static int zebra_ns_delete(struct ns *ns)
{
	struct zebra_ns *zns = (struct zebra_ns *)ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (deleted)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	XFREE(MTYPE_ZEBRA_NS, zns);
	return 0;
}

static int zebra_ns_enabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (enabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_enable(ns->ns_id, (void **)&zns);
}

int zebra_ns_disabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (disabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_disable(ns->ns_id, (void **)&zns);
}

/* Do global enable actions - open sockets, read kernel config etc. */
int zebra_ns_enable(ns_id_t ns_id, void **info)
{
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

	zns->ns_id = ns_id;

	zns->rules_hash =
		hash_create_size(8, zebra_pbr_rules_hash_key,
				 zebra_pbr_rules_hash_equal, "Rules Hash");

	zns->ipset_hash =
		hash_create_size(8, zebra_pbr_ipset_hash_key,
				 zebra_pbr_ipset_hash_equal, "IPset Hash");

	zns->ipset_entry_hash =
		hash_create_size(8, zebra_pbr_ipset_entry_hash_key,
				 zebra_pbr_ipset_entry_hash_equal,
				 "IPset Hash Entry");

	zns->iptable_hash =
		hash_create_size(8, zebra_pbr_iptable_hash_key,
				 zebra_pbr_iptable_hash_equal,
				 "IPtable Hash Entry");

#if defined(HAVE_RTADV)
	rtadv_init(zns);
#endif

	kernel_init(zns);
	interface_list(zns);
	route_read(zns);

	/* Initiate Table Manager per ZNS */
	table_manager_enable(ns_id);

	return 0;
}

struct route_table *zebra_ns_find_table(struct zebra_ns *zns, uint32_t tableid,
					afi_t afi)
{
	struct zebra_ns_table finder;
	struct zebra_ns_table *znst;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.tableid = tableid;
	finder.ns_id = zns->ns_id;
	znst = RB_FIND(zebra_ns_table_head, &zns->ns_tables, &finder);

	if (znst)
		return znst->table;
	else
		return NULL;
}

unsigned long zebra_ns_score_proto(uint8_t proto, unsigned short instance)
{
	struct zebra_ns *zns;
	struct zebra_ns_table *znst;
	unsigned long cnt = 0;

	zns = zebra_ns_lookup(NS_DEFAULT);

	RB_FOREACH (znst, zebra_ns_table_head, &zns->ns_tables) {
		if (znst->ns_id != NS_DEFAULT)
			continue;
		cnt += rib_score_proto_table(proto, instance, znst->table);
	}
	return cnt;
}

void zebra_ns_sweep_route(void)
{
	struct zebra_ns_table *znst;
	struct zebra_ns *zns;

	zns = zebra_ns_lookup(NS_DEFAULT);

	RB_FOREACH (znst, zebra_ns_table_head, &zns->ns_tables) {
		if (znst->ns_id != NS_DEFAULT)
			continue;
		rib_sweep_table(znst->table);
	}
}

struct route_table *zebra_ns_get_table(struct zebra_ns *zns,
				       struct zebra_vrf *zvrf, uint32_t tableid,
				       afi_t afi)
{
	struct zebra_ns_table finder;
	struct zebra_ns_table *znst;
	rib_table_info_t *info;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.tableid = tableid;
	finder.ns_id = zns->ns_id;
	znst = RB_FIND(zebra_ns_table_head, &zns->ns_tables, &finder);

	if (znst)
		return znst->table;

	znst = XCALLOC(MTYPE_ZEBRA_NS, sizeof(*znst));
	znst->tableid = tableid;
	znst->afi = afi;
	znst->ns_id = zns->ns_id;
	znst->table =
		(afi == AFI_IP6) ? srcdest_table_init() : route_table_init();

	info = XCALLOC(MTYPE_RIB_TABLE_INFO, sizeof(*info));
	info->zvrf = zvrf;
	info->afi = afi;
	info->safi = SAFI_UNICAST;
	znst->table->info = info;
	znst->table->cleanup = zebra_rtable_node_cleanup;

	RB_INSERT(zebra_ns_table_head, &zns->ns_tables, znst);
	return znst->table;
}

static void zebra_ns_free_table(struct zebra_ns_table *znst)
{
	void *table_info;

	rib_close_table(znst->table);

	table_info = znst->table->info;
	route_table_finish(znst->table);
	XFREE(MTYPE_RIB_TABLE_INFO, table_info);
	XFREE(MTYPE_ZEBRA_NS, znst);
}

int zebra_ns_disable(ns_id_t ns_id, void **info)
{
	struct zebra_ns_table *znst, *tmp;
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

	hash_clean(zns->rules_hash, zebra_pbr_rules_free);
	hash_free(zns->rules_hash);
	hash_clean(zns->ipset_entry_hash,
		   zebra_pbr_ipset_entry_free),
	hash_clean(zns->ipset_hash, zebra_pbr_ipset_free);
	hash_free(zns->ipset_hash);
	hash_free(zns->ipset_entry_hash);
	hash_clean(zns->iptable_hash,
		   zebra_pbr_iptable_free);
	hash_free(zns->iptable_hash);

	RB_FOREACH_SAFE (znst, zebra_ns_table_head, &zns->ns_tables, tmp) {
		if (znst->ns_id != ns_id)
			continue;
		RB_REMOVE(zebra_ns_table_head, &zns->ns_tables, znst);
		zebra_ns_free_table(znst);
	}

	route_table_finish(zns->if_table);
	zebra_vxlan_ns_disable(zns);
#if defined(HAVE_RTADV)
	rtadv_terminate(zns);
#endif

	kernel_terminate(zns);

	table_manager_disable(zns->ns_id);

	zns->ns_id = NS_DEFAULT;

	return 0;
}


int zebra_ns_init(void)
{
	ns_id_t ns_id;
	ns_id_t ns_id_external;

	dzns = zebra_ns_alloc();

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	ns_id = zebra_ns_id_get_default();
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");
	ns_id_external = ns_map_nsid_with_external(ns_id, true);
	ns_init_management(ns_id_external, ns_id);

	logicalrouter_init(logicalrouter_config_write);

	/* Do any needed per-NS data structure allocation. */
	dzns->if_table = route_table_init();
	zebra_vxlan_ns_init(dzns);

	/* Register zebra VRF callbacks, create and activate default VRF. */
	zebra_vrf_init();

	/* Default NS is activated */
	zebra_ns_enable(ns_id_external, (void **)&dzns);

	if (vrf_is_backend_netns()) {
		ns_add_hook(NS_NEW_HOOK, zebra_ns_new);
		ns_add_hook(NS_ENABLE_HOOK, zebra_ns_enabled);
		ns_add_hook(NS_DISABLE_HOOK, zebra_ns_disabled);
		ns_add_hook(NS_DELETE_HOOK, zebra_ns_delete);
		zebra_ns_notify_parse();
		zebra_ns_notify_init();
	}
	return 0;
}

static int logicalrouter_config_write(struct vty *vty)
{
	struct ns *ns;
	int write = 0;

	RB_FOREACH (ns, ns_head, &ns_tree) {
		if (ns->ns_id == NS_DEFAULT || ns->name == NULL)
			continue;
		vty_out(vty, "logical-router %u netns %s\n", ns->ns_id,
			ns->name);
		write = 1;
	}
	return write;
}

int zebra_ns_config_write(struct vty *vty, struct ns *ns)
{
	if (ns && ns->name != NULL)
		vty_out(vty, " netns %s\n", ns->name);
	return 0;
}
