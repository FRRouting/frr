// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Layer-2 interface handling code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/interface.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn_mh.h"

/* definitions */

/* static function declarations */

/* Private functions */
static void map_slaves_to_bridge(struct interface *br_if, int link,
				 bool update_slave, uint8_t chgflags)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_vrf *zvrf;
	struct zebra_ns *zns;

	zvrf = br_if->vrf->info;
	assert(zvrf);
	zns = zvrf->zns;
	assert(zns);
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
				if (br_slave->bridge_ifindex == br_if->ifindex
				    && br_slave->ns_id == zns->ns_id) {
					br_slave->br_if = br_if;
					if (update_slave) {
						zebra_l2if_update_bridge_slave(
							ifp,
							br_slave->bridge_ifindex,
							br_slave->ns_id,
							chgflags);
					}
				}
			} else {
				if (br_slave->br_if == br_if)
					br_slave->br_if = NULL;
			}
		}
	}
}

/* Public functions */
void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave,
				  struct zebra_ns *zns)
{
	struct interface *br_if;

	/* TODO: Handle change of master */
	assert(zns);
	br_if = if_lookup_by_index_per_ns(zebra_ns_lookup(zns->ns_id),
					  br_slave->bridge_ifindex);
	if (br_if)
		br_slave->br_if = br_if;
}

void zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave)
{
	br_slave->br_if = NULL;
}

/* If any of the bond members are in bypass state the bond is placed
 * in bypass state
 */
static void zebra_l2_bond_lacp_bypass_eval(struct zebra_if *bond_zif)
{
	struct listnode *node;
	struct zebra_if *bond_mbr;
	bool old_bypass = !!CHECK_FLAG(bond_zif->flags, ZIF_FLAG_LACP_BYPASS);
	bool new_bypass = false;

	if (bond_zif->bond_info.mbr_zifs) {
		for (ALL_LIST_ELEMENTS_RO(bond_zif->bond_info.mbr_zifs, node,
					  bond_mbr)) {
			if (CHECK_FLAG(bond_mbr->flags, ZIF_FLAG_LACP_BYPASS)) {
				new_bypass = true;
				break;
			}
		}
	}

	if (old_bypass == new_bypass)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bond %s lacp bypass changed to %s",
			   bond_zif->ifp->name, new_bypass ? "on" : "off");

	if (new_bypass)
		SET_FLAG(bond_zif->flags, ZIF_FLAG_LACP_BYPASS);
	else
		UNSET_FLAG(bond_zif->flags, ZIF_FLAG_LACP_BYPASS);

	if (bond_zif->es_info.es)
		zebra_evpn_es_bypass_update(bond_zif->es_info.es, bond_zif->ifp,
					    new_bypass);
}

/* Returns true if member was newly linked to bond */
void zebra_l2_map_slave_to_bond(struct zebra_if *zif, vrf_id_t vrf_id)
{
	struct interface *bond_if;
	struct zebra_if *bond_zif;
	struct zebra_l2info_bondslave *bond_slave = &zif->bondslave_info;

	bond_if = if_lookup_by_index(bond_slave->bond_ifindex, vrf_id);
	if (bond_if == bond_slave->bond_if)
		return;

	/* unlink the slave from the old master */
	zebra_l2_unmap_slave_from_bond(zif);

	/* If the bond is present and ready link the bond-member
	 * to it
	 */
	if (bond_if && (bond_zif = bond_if->info)) {
		if (bond_zif->bond_info.mbr_zifs) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("bond mbr %s linked to %s",
					   zif->ifp->name, bond_if->name);
			bond_slave->bond_if = bond_if;
			/* link the slave to the new bond master */
			listnode_add(bond_zif->bond_info.mbr_zifs, zif);
			/* inherit protodown flags from the es-bond */
			if (zebra_evpn_is_es_bond(bond_if))
				zebra_evpn_mh_update_protodown_bond_mbr(
					zif, false /*clear*/, __func__);
			zebra_l2_bond_lacp_bypass_eval(bond_zif);
		}
	} else {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond mbr %s link to bond skipped", zif->ifp->name);
	}
}

void zebra_l2_unmap_slave_from_bond(struct zebra_if *zif)
{
	struct zebra_l2info_bondslave *bond_slave = &zif->bondslave_info;
	struct zebra_if *bond_zif;

	if (!bond_slave->bond_if) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond mbr %s unlink from bond skipped", zif->ifp->name);
		return;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bond mbr %s un-linked from %s", zif->ifp->name,
			   bond_slave->bond_if->name);

	/* unlink the slave from the bond master */
	bond_zif = bond_slave->bond_if->info;
	/* clear protodown flags */
	if (zebra_evpn_is_es_bond(bond_zif->ifp))
		zebra_evpn_mh_update_protodown_bond_mbr(zif, true /*clear*/,
							__func__);
	listnode_delete(bond_zif->bond_info.mbr_zifs, zif);
	bond_slave->bond_if = NULL;
	zebra_l2_bond_lacp_bypass_eval(bond_zif);
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
				zlog_debug("bond %s mbr list create", ifp->name);
			bond->mbr_zifs = list_new();
		}
	} else {
		struct listnode *node;
		struct listnode *nnode;
		struct zebra_if *bond_mbr;

		if (!bond->mbr_zifs)
			return;

		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond %s mbr list delete", ifp->name);
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
				const struct zebra_l2info_bridge *bridge_info)
{
	struct zebra_if *zif;
	struct zebra_l2_bridge_if *br;

	zif = ifp->info;
	assert(zif);

	br = BRIDGE_FROM_ZEBRA_IF(zif);
	br->vlan_aware = bridge_info->bridge.vlan_aware;
	zebra_l2_bridge_if_add(ifp);

	/* Link all slaves to this bridge */
	map_slaves_to_bridge(ifp, 1, false, ZEBRA_BRIDGE_NO_ACTION);
}

/*
 * Handle Bridge interface delete.
 */
void zebra_l2_bridge_del(struct interface *ifp)
{
	zebra_l2_bridge_if_del(ifp);

	/* Unlink all slaves to this bridge */
	map_slaves_to_bridge(ifp, 0, false, ZEBRA_BRIDGE_NO_ACTION);
}

void zebra_l2if_update_bridge(struct interface *ifp, uint8_t chgflags)
{
	if (!chgflags)
		return;
	map_slaves_to_bridge(ifp, 1, true, chgflags);
}

/*
 * Update L2 info for a VLAN interface. Only relevant parameter is the
 * VLAN Id and this cannot change.
 */
void zebra_l2_vlanif_update(struct interface *ifp,
			    const struct zebra_l2info_vlan *vlan_info)
{
	struct zebra_if *zif;

	zif = ifp->info;
	assert(zif);

	/* Copy over the L2 information. */
	memcpy(&zif->l2info.vl, vlan_info, sizeof(*vlan_info));
}

/*
 * Update L2 info for a GRE interface. This is called upon interface
 * addition as well as update. Upon add/update, need to inform
 * clients about GRE information.
 */
void zebra_l2_greif_add_update(struct interface *ifp,
			       const struct zebra_l2info_gre *gre_info, int add)
{
	struct zebra_if *zif;
	struct in_addr old_vtep_ip;

	zif = ifp->info;
	assert(zif);

	if (add) {
		memcpy(&zif->l2info.gre, gre_info, sizeof(*gre_info));
		return;
	}

	old_vtep_ip = zif->l2info.gre.vtep_ip;
	if (IPV4_ADDR_SAME(&old_vtep_ip, &gre_info->vtep_ip))
		return;

	zif->l2info.gre.vtep_ip = gre_info->vtep_ip;
}

/*
 * Update L2 info for a VxLAN interface. This is called upon interface
 * addition as well as update. Upon add, need to invoke the VNI create
 * function. Upon update, the params of interest are the local tunnel
 * IP and VLAN mapping, but the latter is handled separately.
 */
void zebra_l2_vxlanif_add_update(struct interface *ifp,
				 const struct zebra_l2info_vxlan *vxlan_info,
				 int add)
{
	struct zebra_if *zif;
	uint16_t chgflags = 0;
	struct zebra_vxlan_if_update_ctx ctx;

	zif = ifp->info;
	assert(zif);

	if (add) {
		memcpy(&zif->l2info.vxl, vxlan_info, sizeof(*vxlan_info));
		zebra_vxlan_if_add(ifp);
		return;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.old_vtep_ip = zif->l2info.vxl.vtep_ip;

	if (!IPV4_ADDR_SAME(&ctx.old_vtep_ip, &vxlan_info->vtep_ip)) {
		SET_FLAG(chgflags, ZEBRA_VXLIF_LOCAL_IP_CHANGE);
		zif->l2info.vxl.vtep_ip = vxlan_info->vtep_ip;
	}

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		ctx.old_vni = vxlan_info->vni_info.vni;
		if (!IPV4_ADDR_SAME(&zif->l2info.vxl.vni_info.vni.mcast_grp,
				    &vxlan_info->vni_info.vni.mcast_grp)) {
			SET_FLAG(chgflags, ZEBRA_VXLIF_MCAST_GRP_CHANGE);
			zif->l2info.vxl.vni_info.vni.mcast_grp =
				vxlan_info->vni_info.vni.mcast_grp;
		}
	}

	if (chgflags) {
		ctx.chgflags = chgflags;
		zebra_vxlan_if_update(ifp, &ctx);
	}
}

/*
 * Handle change to VLAN to VNI mapping.
 */
void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
					 vlanid_t access_vlan)
{
	struct zebra_if *zif;
	vlanid_t old_access_vlan;
	struct zebra_vxlan_vni *vni;
	struct zebra_vxlan_if_update_ctx ctx;


	zif = ifp->info;
	assert(zif);

	/* This would be called only in non svd case */
	if (!IS_ZEBRA_VXLAN_IF_VNI(zif))
		return;

	old_access_vlan = zif->l2info.vxl.vni_info.vni.access_vlan;

	if (old_access_vlan == access_vlan)
		return;

	memset(&ctx, 0, sizeof(ctx));
	vni = zebra_vxlan_if_vni_find(zif, 0);
	ctx.old_vni = *vni;
	ctx.chgflags = ZEBRA_VXLIF_VLAN_CHANGE;
	vni->access_vlan = access_vlan;

	zebra_evpn_vl_vxl_deref(old_access_vlan, vni->vni, zif);
	zebra_evpn_vl_vxl_ref(access_vlan, vni->vni, zif);
	zebra_vxlan_if_update(ifp, &ctx);
}

/*
 * Handle VxLAN interface delete.
 */
void zebra_l2_vxlanif_del(struct interface *ifp)
{
	struct zebra_if *zif;

	zif = ifp->info;
	assert(zif);

	zebra_vxlan_if_del(ifp);
}

/*
 * Map or unmap interface from bridge.
 * NOTE: It is currently assumped that an interface has to be unmapped
 * from a bridge before it can be mapped to another bridge.
 */
void zebra_l2if_update_bridge_slave(struct interface *ifp,
				    ifindex_t bridge_ifindex, ns_id_t ns_id,
				    uint8_t chgflags)
{
	struct zebra_if *zif;
	ifindex_t old_bridge_ifindex;
	ns_id_t old_ns_id;
	struct zebra_vrf *zvrf;
	struct zebra_vxlan_if_update_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	zif = ifp->info;
	assert(zif);

	zvrf = ifp->vrf->info;
	if (!zvrf)
		return;

	if (zif->zif_type == ZEBRA_IF_VXLAN
	    && chgflags != ZEBRA_BRIDGE_NO_ACTION) {
		if (CHECK_FLAG(chgflags, ZEBRA_BRIDGE_MASTER_MAC_CHANGE)) {
			ctx.chgflags = ZEBRA_VXLIF_MASTER_MAC_CHANGE;
			zebra_vxlan_if_update(ifp, &ctx);
		}
		if (CHECK_FLAG(chgflags, ZEBRA_BRIDGE_MASTER_UP)) {
			ctx.chgflags = ZEBRA_VXLIF_MASTER_CHANGE;
			zebra_vxlan_if_update(ifp, &ctx);
		}
	}
	old_bridge_ifindex = zif->brslave_info.bridge_ifindex;
	old_ns_id = zif->brslave_info.ns_id;
	if (old_bridge_ifindex == bridge_ifindex &&
	    old_ns_id == zif->brslave_info.ns_id)
		return;

	ctx.chgflags = ZEBRA_VXLIF_MASTER_CHANGE;


	zif->brslave_info.ns_id = ns_id;
	zif->brslave_info.bridge_ifindex = bridge_ifindex;
	/* Set up or remove link with master */
	if (bridge_ifindex != IFINDEX_INTERNAL) {
		zebra_l2_map_slave_to_bridge(&zif->brslave_info, zvrf->zns);
		/* In the case of VxLAN, invoke the handler for EVPN. */
		if (zif->zif_type == ZEBRA_IF_VXLAN)
			zebra_vxlan_if_update(ifp, &ctx);
		if (zif->es_info.es)
			zebra_evpn_es_local_br_port_update(zif);
	} else if (old_bridge_ifindex != IFINDEX_INTERNAL) {
		/*
		 * In the case of VxLAN, invoke the handler for EVPN.
		 * Note that this should be done *prior*
		 * to unmapping the interface from the bridge.
		 */
		if (zif->zif_type == ZEBRA_IF_VXLAN)
			zebra_vxlan_if_update(ifp, &ctx);
		if (zif->es_info.es)
			zebra_evpn_es_local_br_port_update(zif);
		zebra_l2_unmap_slave_from_bridge(&zif->brslave_info);
	}
}

void zebra_l2if_update_bond_slave(struct interface *ifp, ifindex_t bond_ifindex,
				  bool new_bypass)
{
	struct zebra_if *zif;
	ifindex_t old_bond_ifindex;
	bool old_bypass;
	struct zebra_l2info_bondslave *bond_mbr;

	zif = ifp->info;
	assert(zif);

	old_bypass = !!CHECK_FLAG(zif->flags, ZIF_FLAG_LACP_BYPASS);
	if (old_bypass != new_bypass) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("bond-mbr %s lacp bypass changed to %s",
				   zif->ifp->name, new_bypass ? "on" : "off");

		if (new_bypass)
			SET_FLAG(zif->flags, ZIF_FLAG_LACP_BYPASS);
		else
			UNSET_FLAG(zif->flags, ZIF_FLAG_LACP_BYPASS);

		bond_mbr = &zif->bondslave_info;
		if (bond_mbr->bond_if) {
			struct zebra_if *bond_zif = bond_mbr->bond_if->info;

			zebra_l2_bond_lacp_bypass_eval(bond_zif);
		}
	}

	old_bond_ifindex = zif->bondslave_info.bond_ifindex;
	if (old_bond_ifindex == bond_ifindex)
		return;

	zif->bondslave_info.bond_ifindex = bond_ifindex;

	/* Set up or remove link with master */
	if (bond_ifindex != IFINDEX_INTERNAL)
		zebra_l2_map_slave_to_bond(zif, ifp->vrf->vrf_id);
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
