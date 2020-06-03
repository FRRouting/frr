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
#include "zebra/interface.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"

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

void zebra_l2_map_slave_to_bond(struct zebra_if *zif, vrf_id_t vrf_id)
{
	struct interface *bond_if;
	struct zebra_if *bond_zif;
	struct zebra_l2info_bondslave *bond_slave = &zif->bondslave_info;

	bond_if = if_lookup_by_index_all_vrf(bond_slave->bond_ifindex);
	if (bond_if == bond_slave->bond_if)
		return;

	/* unlink the slave from the old master */
	zebra_l2_unmap_slave_from_bond(zif);

	/* If the bond is present and ready link the bond-member
	 * to it
	 */
	if (bond_if && (bond_zif = bond_if->info)) {
		if (bond_zif->bond_info.mbr_zifs) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES ||
					IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("bond mbr %s linked to %s",
					zif->ifp->name, bond_if->name);
			bond_slave->bond_if = bond_if;
			/* link the slave to the new bond master */
			listnode_add(bond_zif->bond_info.mbr_zifs, zif);
			/* inherit protodown flags from the es-bond */
			if (zebra_evpn_is_es_bond(bond_if))
				zebra_evpn_mh_update_protodown_bond_mbr(zif,
					false /*clear*/, __func__);
		}
	} else {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond mbr %s link to bond skipped",
				zif->ifp->name);
	}
}

void zebra_l2_unmap_slave_from_bond(struct zebra_if *zif)
{
	struct zebra_l2info_bondslave *bond_slave = &zif->bondslave_info;
	struct zebra_if *bond_zif;

	if (!bond_slave->bond_if) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond mbr %s unlink from bond skipped",
				zif->ifp->name);
		return;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bond mbr %s un-linked from %s",
			zif->ifp->name, bond_slave->bond_if->name);

	/* unlink the slave from the bond master */
	bond_zif = bond_slave->bond_if->info;
	/* clear protodown flags */
	if (zebra_evpn_is_es_bond(bond_zif->ifp))
		zebra_evpn_mh_update_protodown_bond_mbr(zif,
			true /*clear*/, __func__);
	listnode_delete(bond_zif->bond_info.mbr_zifs, zif);
	bond_slave->bond_if = NULL;
}

void zebra_l2if_update_bond(struct interface *ifp, bool add)
{
	struct zebra_if *zif;
	struct zebra_l2info_bond *bond;

	zif = ifp->info;
	assert(zif);
	bond = &zif->bond_info;

	if (add) {
		if (!bond->mbr_zifs) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("bond %s mbr list create",
						ifp->name);
			bond->mbr_zifs = list_new();
		}
	} else {
		struct listnode *node;
		struct listnode *nnode;
		struct zebra_if *bond_mbr;

		if (!bond->mbr_zifs)
			return;

		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond %s mbr list delete",
					ifp->name);
		for (ALL_LIST_ELEMENTS(bond->mbr_zifs, node, nnode, bond_mbr))
			zebra_l2_unmap_slave_from_bond(bond_mbr);

		list_delete(&bond->mbr_zifs);
	}
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
	uint16_t chgflags = 0;

	zif = ifp->info;
	assert(zif);

	if (add) {
		memcpy(&zif->l2info.vxl, vxlan_info, sizeof(*vxlan_info));
		zebra_evpn_vl_vxl_ref(zif->l2info.vxl.access_vlan, zif);
		zebra_vxlan_if_add(ifp);
		return;
	}

	old_vtep_ip = zif->l2info.vxl.vtep_ip;

	if (!IPV4_ADDR_SAME(&old_vtep_ip, &vxlan_info->vtep_ip)) {
		chgflags |= ZEBRA_VXLIF_LOCAL_IP_CHANGE;
		zif->l2info.vxl.vtep_ip = vxlan_info->vtep_ip;
	}

	if (!IPV4_ADDR_SAME(&zif->l2info.vxl.mcast_grp,
				&vxlan_info->mcast_grp)) {
		chgflags |= ZEBRA_VXLIF_MCAST_GRP_CHANGE;
		zif->l2info.vxl.mcast_grp = vxlan_info->mcast_grp;
	}

	if (chgflags)
		zebra_vxlan_if_update(ifp, chgflags);
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

	zebra_evpn_vl_vxl_deref(old_access_vlan, zif);
	zebra_evpn_vl_vxl_ref(zif->l2info.vxl.access_vlan, zif);
	zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_VLAN_CHANGE);
}

/*
 * Handle VxLAN interface delete.
 */
void zebra_l2_vxlanif_del(struct interface *ifp)
{
	struct zebra_if *zif;

	zif = ifp->info;
	assert(zif);

	zebra_evpn_vl_vxl_deref(zif->l2info.vxl.access_vlan, zif);
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
		if (zif->es_info.es)
			zebra_evpn_es_local_br_port_update(zif);
	} else if (old_bridge_ifindex != IFINDEX_INTERNAL) {
		/*
		 * In the case of VxLAN, invoke the handler for EVPN.
		 * Note that this should be done *prior*
		 * to unmapping the interface from the bridge.
		 */
		if (zif->zif_type == ZEBRA_IF_VXLAN)
			zebra_vxlan_if_update(ifp, ZEBRA_VXLIF_MASTER_CHANGE);
		if (zif->es_info.es)
			zebra_evpn_es_local_br_port_update(zif);
		zebra_l2_unmap_slave_from_bridge(&zif->brslave_info);
	}
}

void zebra_l2if_update_bond_slave(struct interface *ifp, ifindex_t bond_ifindex)
{
	struct zebra_if *zif;
	ifindex_t old_bond_ifindex;

	zif = ifp->info;
	assert(zif);

	old_bond_ifindex = zif->bondslave_info.bond_ifindex;
	if (old_bond_ifindex == bond_ifindex)
		return;

	zif->bondslave_info.bond_ifindex = bond_ifindex;

	/* Set up or remove link with master */
	if (bond_ifindex != IFINDEX_INTERNAL)
		zebra_l2_map_slave_to_bond(zif, ifp->vrf_id);
	else if (old_bond_ifindex != IFINDEX_INTERNAL)
		zebra_l2_unmap_slave_from_bond(zif);
}

void zebra_vlan_bitmap_compute(struct interface *ifp,
		uint32_t vid_start, uint16_t vid_end)
{
	uint32_t vid;
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	assert(zif);

	for (vid = vid_start; vid <= vid_end; ++vid)
		bf_set_bit(zif->vlan_bitmap, vid);
}

void zebra_vlan_mbr_re_eval(struct interface *ifp, bitfield_t old_vlan_bitmap)
{
	uint32_t vid;
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	assert(zif);

	if (!bf_cmp(zif->vlan_bitmap, old_vlan_bitmap))
		/* no change */
		return;

	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX) {
		/* if not already set create new reference */
		if (!bf_test_index(old_vlan_bitmap, vid))
			zebra_evpn_vl_mbr_ref(vid, zif);

		/* also clear from the old vlan bitmap */
		bf_release_index(old_vlan_bitmap, vid);
	}

	/* any bits remaining in the old vlan bitmap are stale references */
	bf_for_each_set_bit(old_vlan_bitmap, vid, IF_VLAN_BITMAP_MAX) {
		zebra_evpn_vl_mbr_deref(vid, zif);
	}
}
