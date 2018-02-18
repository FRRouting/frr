/* zebra NS Routines
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
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
#include "lib/prefix.h"
#include "lib/memory.h"

#include "rtadv.h"
#include "zebra_ns.h"
#include "zebra_vrf.h"
#include "zebra_memory.h"
#include "rt.h"
#include "zebra_vxlan.h"

DEFINE_MTYPE(ZEBRA, ZEBRA_NS, "Zebra Name Space")

static __inline int
zebra_ns_table_entry_compare(const struct zebra_ns_table *e1,
			     const struct zebra_ns_table *e2);

RB_GENERATE(zebra_ns_table_head, zebra_ns_table, zebra_ns_table_entry,
	    zebra_ns_table_entry_compare);

static struct zebra_ns *dzns;

static __inline int
zebra_ns_table_entry_compare(const struct zebra_ns_table *e1,
			     const struct zebra_ns_table *e2)
{
	if (e1->tableid == e2->tableid)
		return (e1->afi - e2->afi);

	return e1->tableid - e2->tableid;
}

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id)
{
	return dzns;
}

/* Do global enable actions - open sockets, read kernel config etc. */
int zebra_ns_enable(ns_id_t ns_id, void **info)
{
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

#if defined(HAVE_RTADV)
	rtadv_init(zns);
#endif

	kernel_init(zns);
	interface_list(zns);
	route_read(zns);

	return 0;
}

struct route_table *zebra_ns_find_table(struct zebra_ns *zns,
					uint32_t tableid, afi_t afi)
{
	struct zebra_ns_table finder;
	struct zebra_ns_table *znst;

	memset(&finder, 0, sizeof(finder));
	finder.afi = afi;
	finder.tableid = tableid;
	znst = RB_FIND(zebra_ns_table_head, &zns->ns_tables, &finder);

	if (znst)
		return znst->table;
	else
		return NULL;
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
	znst = RB_FIND(zebra_ns_table_head, &zns->ns_tables, &finder);

	if (znst)
		return znst->table;

	znst = XCALLOC(MTYPE_ZEBRA_NS, sizeof(*znst));
	znst->tableid = tableid;
	znst->afi = afi;
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

static struct zebra_ns_table *zebra_ns_free_table(struct zebra_ns_table *znst)
{
	void *table_info;
	rib_close_table(znst->table);

	table_info = znst->table->info;
	route_table_finish(znst->table);
	XFREE(MTYPE_RIB_TABLE_INFO, table_info);
	XFREE(MTYPE_ZEBRA_NS, znst);
	return NULL;
}

int zebra_ns_disable(ns_id_t ns_id, void **info)
{
	struct zebra_ns_table *znst;
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

	while (!RB_EMPTY(zebra_ns_table_head, &zns->ns_tables)) {
		znst = RB_ROOT(zebra_ns_table_head, &zns->ns_tables);

		RB_REMOVE(zebra_ns_table_head, &zns->ns_tables, znst);
		znst = zebra_ns_free_table(znst);
	}
	route_table_finish(zns->if_table);
	zebra_vxlan_ns_disable(zns);
#if defined(HAVE_RTADV)
	rtadv_terminate(zns);
#endif

	kernel_terminate(zns);

	return 0;
}


int zebra_ns_init(void)
{
	dzns = XCALLOC(MTYPE_ZEBRA_NS, sizeof(struct zebra_ns));

	ns_init();

	/* Do any needed per-NS data structure allocation. */
	dzns->if_table = route_table_init();
	zebra_vxlan_ns_init(dzns);

	/* Register zebra VRF callbacks, create and activate default VRF. */
	zebra_vrf_init();

	/* Default NS is activated */
	zebra_ns_enable(NS_DEFAULT, (void **)&dzns);

	return 0;
}
