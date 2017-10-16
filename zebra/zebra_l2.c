/*
 * Zebra Layer-2 interface handling code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_vxlan.h"

/* definitions */

/* static function declarations */

/* Private functions */
static void map_slaves_to_bridge(struct interface *br_if, int link)
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_if *zif;
			struct zebra_l2info_brslave *br_slave;

			if (ifp->ifindex == IFINDEX_INTERNAL || !ifp->info)
				continue;
			if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
				continue;

			/* NOTE: This assumes 'zebra_l2info_brslave' is the
			 * first field
			 * for any L2 interface.
			 */
			zif = (struct zebra_if *)ifp->info;
			br_slave = &zif->brslave_info;

			if (link) {
				if (br_slave->bridge_ifindex == br_if->ifindex)
					br_slave->br_if = br_if;
			} else {
				if (br_slave->br_if == br_if)
					br_slave->br_if = NULL;
			}
		}
	}
}

/* Public functions */
void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave)
{
	struct interface *br_if;

	/* TODO: Handle change of master */
	br_if = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					  br_slave->bridge_ifindex);
	if (br_if)
		br_slave->br_if = br_if;
}

void zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave)
{
	br_slave->br_if = NULL;
}

/*
 * Handle Bridge interface add or update. Update relevant info,
 * map slaves (if any) to the bridge.
 */
void zebra_l2_bridge_add_update(struct interface *ifp,
				struct zebra_l2info_bridge *bridge_info,
				int add)
{
	struct zebra_if *zif;

	zif = ifp->info;
	assert(zif);

	/* Copy over the L2 information. */
	memcpy(&zif->l2info.br, bridge_info, sizeof(*bridge_info));

	/* Link all slaves to this bridge */
	map_slaves_to_bridge(ifp, 1);
}

/*
 * Handle Bridge interface delete.
 */
void zebra_l2_bridge_del(struct interface *ifp)
{
	/* Unlink all slaves to this bridge */
	map_slaves_to_bridge(ifp, 0);
}

/*
 * Update L2 info for a VLAN interface. Only relevant parameter is the
 * VLAN Id and this cannot change.
 */
void zebra_l2_vlanif_update(struct interface *ifp,
			    struct zebra_l2info_vlan *vlan_info)
{
	struct zebra_if *zif;

	zif = ifp->info;
	assert(zif);

	/* Copy over the L2 information. */
	memcpy(&zif->l2info.vl, vlan_info, sizeof(*vlan_info));
}

/*
 * Update L2 info for a VxLAN interface. This is called upon interface
 * addition as well as update. Upon add, need to invoke the VNI create
 * function. Upon update, the params of interest are the local tunnel
 * IP and VLAN mapping, but the latter is handled separately.
 */
void zebra_l2_vxlanif_add_update(struct interface *ifp,
				 struct zebra_l2info_vxlan *vxlan_info, int add)
{
	struct zebra_if *zif;
	struct in_addr old_vtep_ip;

	zif = ifp->info;
	assert(zif);

	if (add) {
		memcpy(&zif->l2info.vxl, vxlan_info, sizeof(*vxlan_info));
		zebra_vxlan_if_add(ifp);
		return;
	}

	old_vtep_ip = zif->l2info.vxl.vtep_ip;
	if (IPV4_ADDR_SAME(&old_vtep_ip, &vxlan_info->vtep_ip))
		return;

	zif->l2info.vxl.vtep_ip = vxlan_info->vtep_ip;
	zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_LOCAL_IP_CHANGE);
}

/*
 * Handle change to VLAN to VNI mapping.
 */
void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
					 vlanid_t access_vlan)
{
	struct zebra_if *zif;
	vlanid_t old_access_vlan;

	zif = ifp->info;
	assert(zif);

	old_access_vlan = zif->l2info.vxl.access_vlan;
	if (old_access_vlan == access_vlan)
		return;

	zif->l2info.vxl.access_vlan = access_vlan;
	zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_VLAN_CHANGE);
}

/*
 * Handle VxLAN interface delete.
 */
void zebra_l2_vxlanif_del(struct interface *ifp)
{
	zebra_vxlan_if_del(ifp);
}

/*
 * Map or unmap interface from bridge.
 * NOTE: It is currently assumped that an interface has to be unmapped
 * from a bridge before it can be mapped to another bridge.
 */
void zebra_l2if_update_bridge_slave(struct interface *ifp,
				    ifindex_t bridge_ifindex)
{
	struct zebra_if *zif;
	ifindex_t old_bridge_ifindex;

	zif = ifp->info;
	assert(zif);

	old_bridge_ifindex = zif->brslave_info.bridge_ifindex;
	if (old_bridge_ifindex == bridge_ifindex)
		return;

	zif->brslave_info.bridge_ifindex = bridge_ifindex;

	/* Set up or remove link with master */
	if (bridge_ifindex != IFINDEX_INTERNAL) {
		zebra_l2_map_slave_to_bridge(&zif->brslave_info);
		/* In the case of VxLAN, invoke the handler for EVPN. */
		if (zif->zif_type == ZEBRA_IF_VXLAN)
			zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_MASTER_CHANGE);
	} else if (old_bridge_ifindex != IFINDEX_INTERNAL) {
		/*
		 * In the case of VxLAN, invoke the handler for EVPN.
		 * Note that this should be done *prior*
		 * to unmapping the interface from the bridge.
		 */
		if (zif->zif_type == ZEBRA_IF_VXLAN)
			zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_MASTER_CHANGE);
		zebra_l2_unmap_slave_from_bridge(&zif->brslave_info);
	}
}
