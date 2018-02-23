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

static struct zebra_ns *dzns;

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

int zebra_ns_disable(ns_id_t ns_id, void **info)
{
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

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
