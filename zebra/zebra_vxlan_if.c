/*
 * Zebra EVPN for VxLAN interface handling
 *
 * Copyright (C) 2021 Cumulus Networks, Inc.
 * Vivek Venkatraman, Stephen Worley, Sharath Ramamurthy
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
 */

#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "vlan.h"
#include "vxlan.h"
#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_vxlan.h"
#include "zebra/zebra_router.h"

static unsigned int zebra_vxlan_vni_hash_keymake(const void *p)
{
	const struct zebra_vxlan_vni *vni;

	vni = (const struct zebra_vxlan_vni *)p;
	return jhash_1word(vni->vni, 0);
}

static bool zebra_vxlan_vni_hash_cmp(const void *p1, const void *p2)
{
	const struct zebra_vxlan_vni *vni1;
	const struct zebra_vxlan_vni *vni2;

	vni1 = (const struct zebra_vxlan_vni *)p1;
	vni2 = (const struct zebra_vxlan_vni *)p2;

	return (vni1->vni == vni2->vni);
}

static int zebra_vxlan_if_vni_walk_callback(struct hash_bucket *bucket,
					    void *ctxt)
{
	int ret;
	struct zebra_vxlan_vni *vni;
	struct zebra_vxlan_if_ctx *ctx;

	vni = (struct zebra_vxlan_vni *)bucket->data;
	ctx = (struct zebra_vxlan_if_ctx *)ctxt;

	ret = ctx->func(ctx->zif, vni, ctx->arg);
	return ret;
}

static void zebra_vxlan_if_vni_iterate_callback(struct hash_bucket *bucket,
						void *ctxt)
{
	struct zebra_vxlan_vni *vni;
	struct zebra_vxlan_if_ctx *ctx;

	vni = (struct zebra_vxlan_vni *)bucket->data;
	ctx = (struct zebra_vxlan_if_ctx *)ctxt;

	ctx->func(ctx->zif, vni, ctx->arg);
}

static int zebra_vxlan_if_del_vni(struct interface *ifp,
				  struct zebra_vxlan_vni *vnip)
{
	vni_t vni;
	struct zebra_if *zif;
	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;
	struct interface *br_if;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vni = vnip->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L3-VNI %u intf %s(%u)", vni, ifp->name,
				   ifp->ifindex);

		/* process oper-down for l3-vni */
		zebra_vxlan_process_l3vni_oper_down(zl3vni);

		/* remove the association with vxlan_if */
		memset(&zl3vni->local_vtep_ip, 0, sizeof(struct in_addr));
		zl3vni->vxlan_if = NULL;
		zl3vni->vid = 0;
		br_if = zif->brslave_info.br_if;
		zl3vni_bridge_if_set(zl3vni, br_if, false /* unset */);
	} else {

		/* process if-del for l2-vni*/
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Del L2-VNI %u intf %s(%u)", vni, ifp->name,
				   ifp->ifindex);

		/* Locate hash entry; it is expected to exist. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn) {
			zlog_debug(
				"Failed to locate VNI hash at del, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return 0;
		}

		/* remove from l3-vni list */
		zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
		if (zl3vni)
			listnode_delete(zl3vni->l2vnis, zevpn);
		/* Delete VNI from BGP. */
		zebra_evpn_send_del_to_client(zevpn);

		/* Free up all neighbors and MAC, if any. */
		zebra_evpn_neigh_del_all(zevpn, 1, 0, DEL_ALL_NEIGH);
		zebra_evpn_mac_del_all(zevpn, 1, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zebra_evpn_vtep_del_all(zevpn, 1);

		/* Delete the hash entry. */
		if (zebra_evpn_vxlan_del(zevpn)) {
			flog_err(EC_ZEBRA_VNI_DEL_FAILED,
				 "Failed to del EVPN hash %p, IF %s(%u) VNI %u",
				 zevpn, ifp->name, ifp->ifindex, zevpn->vni);
			return -1;
		}
	}
	return 0;
}

static int zebra_vxlan_if_update_vni(struct interface *ifp,
				     struct zebra_vxlan_vni *vnip,
				     struct zebra_vxlan_if_update_ctx *ctx)
{
	vni_t vni;
	uint16_t chgflags;
	vlanid_t access_vlan;
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;
	struct interface *vlan_if;
	struct interface *br_if;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vnip->vni;
	chgflags = ctx->chgflags;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Update L3-VNI %u intf %s(%u) VLAN %u local IP %pI4 master %u chg 0x%x",
				vni, ifp->name, ifp->ifindex, vnip->access_vlan,
				&vxl->vtep_ip, zif->brslave_info.bridge_ifindex,
				chgflags);

		/* Removed from bridge? Cleanup and return */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_MASTER_CHANGE) &&
		    (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
			zebra_vxlan_process_l3vni_oper_down(zl3vni);
			return 0;
		}

		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_MASTER_MAC_CHANGE) &&
		    if_is_operative(ifp) && is_l3vni_oper_up(zl3vni)) {
			zebra_vxlan_process_l3vni_oper_down(zl3vni);
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
			return 0;
		}

		/* access-vlan change - process oper down, associate with new
		 * svi_if and then process oper up again
		 */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_VLAN_CHANGE)) {
			if (if_is_operative(ifp)) {
				zebra_vxlan_process_l3vni_oper_down(zl3vni);
				zl3vni->svi_if = NULL;
				zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);
				zl3vni->mac_vlan_if =
					zl3vni_map_to_mac_vlan_if(zl3vni);
				zl3vni->local_vtep_ip = vxl->vtep_ip;
				if (is_l3vni_oper_up(zl3vni))
					zebra_vxlan_process_l3vni_oper_up(
						zl3vni);
			}
		}

		/*
		 * local-ip change - process oper down, associate with new
		 * local-ip and then process oper up again
		 */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_LOCAL_IP_CHANGE)) {
			if (if_is_operative(ifp)) {
				zebra_vxlan_process_l3vni_oper_down(zl3vni);
				zl3vni->local_vtep_ip = vxl->vtep_ip;
				if (is_l3vni_oper_up(zl3vni))
					zebra_vxlan_process_l3vni_oper_up(
						zl3vni);
			}
		}

		/* Update local tunnel IP. */
		zl3vni->local_vtep_ip = vxl->vtep_ip;

		zl3vni->vid = (zl3vni->vid != vnip->access_vlan)
				      ? vnip->access_vlan
				      : zl3vni->vid;
		br_if = zif->brslave_info.br_if;
		zl3vni_bridge_if_set(zl3vni, br_if, true /* set */);

		/* if we have a valid new master, process l3-vni oper up */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_MASTER_CHANGE)) {
			if (if_is_operative(ifp) && is_l3vni_oper_up(zl3vni))
				zebra_vxlan_process_l3vni_oper_up(zl3vni);
		}
	} else {

		/* Update VNI hash. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn) {
			zlog_debug(
				"Failed to find EVPN hash on update, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Update L2-VNI %u intf %s(%u) VLAN %u local IP %pI4 master %u chg 0x%x",
				vni, ifp->name, ifp->ifindex, vnip->access_vlan,
				&vxl->vtep_ip, zif->brslave_info.bridge_ifindex,
				chgflags);

		/* Removed from bridge? Cleanup and return */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_MASTER_CHANGE) &&
		    (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
			/* Delete from client, remove all remote VTEPs */
			/* Also, free up all MACs and neighbors. */
			zevpn->svi_if = NULL;
			zebra_evpn_send_del_to_client(zevpn);
			zebra_evpn_neigh_del_all(zevpn, 1, 0, DEL_ALL_NEIGH);
			zebra_evpn_mac_del_all(zevpn, 1, 0, DEL_ALL_MAC);
			zebra_evpn_vtep_del_all(zevpn, 1);
			return 0;
		}

		/* Handle other changes. */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_VLAN_CHANGE)) {
			/* Remove all existing local neigh and MACs for this VNI
			 * (including from BGP)
			 */
			access_vlan = vnip->access_vlan;
			vnip->access_vlan = ctx->old_vni.access_vlan;
			zebra_evpn_neigh_del_all(zevpn, 0, 1, DEL_LOCAL_MAC);
			zebra_evpn_mac_del_all(zevpn, 0, 1, DEL_LOCAL_MAC);
			zebra_evpn_rem_mac_uninstall_all(zevpn);
			vnip->access_vlan = access_vlan;
		}

		if (zevpn->local_vtep_ip.s_addr != vxl->vtep_ip.s_addr ||
		    zevpn->mcast_grp.s_addr != vnip->mcast_grp.s_addr) {
			zebra_vxlan_sg_deref(zevpn->local_vtep_ip,
					     zevpn->mcast_grp);
			zebra_vxlan_sg_ref(vxl->vtep_ip, vnip->mcast_grp);
			zevpn->local_vtep_ip = vxl->vtep_ip;
			zevpn->mcast_grp = vnip->mcast_grp;
			/* on local vtep-ip check if ES orig-ip
			 * needs to be updated
			 */
			zebra_evpn_es_set_base_evpn(zevpn);
		}
		zevpn_vxlan_if_set(zevpn, ifp, true /* set */);
		zevpn->vid = (zevpn->vid != vnip->access_vlan)
				     ? vnip->access_vlan
				     : zevpn->vid;
		br_if = zif->brslave_info.br_if;
		zevpn_bridge_if_set(zevpn, br_if, true /* set */);

		vlan_if = zvni_map_to_svi(vnip->access_vlan, br_if);
		if (vlan_if)
			zevpn->svi_if = vlan_if;

		/* Take further actions needed.
		 * Note that if we are here, there is a change of interest.
		 */
		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		/* Inform BGP, if there is a change of interest. */
		if (CHECK_FLAG(chgflags, (ZEBRA_VXLIF_MASTER_CHANGE |
					  ZEBRA_VXLIF_LOCAL_IP_CHANGE |
					  ZEBRA_VXLIF_MCAST_GRP_CHANGE |
					  ZEBRA_VXLIF_VLAN_CHANGE)))
			zebra_evpn_send_add_to_client(zevpn);

		/* If there is a valid new master or a VLAN mapping change,
		 * read and populate local MACs and neighbors.
		 * Also, reinstall any remote MACs and neighbors
		 * for this VNI (based on new VLAN).
		 */
		if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_MASTER_CHANGE))
			zebra_evpn_read_mac_neigh(zevpn, ifp);
		else if (CHECK_FLAG(chgflags, ZEBRA_VXLIF_VLAN_CHANGE)) {
			struct neigh_walk_ctx n_wctx;

			zebra_evpn_read_mac_neigh(zevpn, ifp);

			zebra_evpn_rem_mac_install_all(zevpn);

			memset(&n_wctx, 0, sizeof(n_wctx));
			n_wctx.zevpn = zevpn;
			hash_iterate(zevpn->neigh_table,
				     zebra_evpn_install_neigh_hash, &n_wctx);
		}
	}

	return 0;
}

static int zebra_vxlan_if_add_vni(struct interface *ifp,
				  struct zebra_vxlan_vni *vnip)
{
	vni_t vni;
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;
	struct interface *br_if;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vxl = &zif->l2info.vxl;
	vni = vnip->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		/* process if-add for l3-vni*/
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Add L3-VNI %u intf %s(%u) VLAN %u local IP %pI4 master %u",
				vni, ifp->name, ifp->ifindex, vnip->access_vlan,
				&vxl->vtep_ip,
				zif->brslave_info.bridge_ifindex);

		/* associate with vxlan_if */
		zl3vni->local_vtep_ip = vxl->vtep_ip;
		zl3vni->vxlan_if = ifp;

		/*
		 * Associate with SVI, if any. We can associate with svi-if only
		 * after association with vxlan_if is complete
		 */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		zl3vni->mac_vlan_if = zl3vni_map_to_mac_vlan_if(zl3vni);

		zl3vni->vid = vnip->access_vlan;
		br_if = zif->brslave_info.br_if;
		zl3vni_bridge_if_set(zl3vni, br_if, true /* set */);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {

		/* process if-add for l2-vni */
		struct interface *vlan_if = NULL;

		/* Create or update EVPN hash. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn)
			zevpn = zebra_evpn_add(vni);

		if (zevpn->local_vtep_ip.s_addr != vxl->vtep_ip.s_addr ||
		    zevpn->mcast_grp.s_addr != vnip->mcast_grp.s_addr) {
			zebra_vxlan_sg_deref(zevpn->local_vtep_ip,
					     zevpn->mcast_grp);
			zebra_vxlan_sg_ref(vxl->vtep_ip, vnip->mcast_grp);
			zevpn->local_vtep_ip = vxl->vtep_ip;
			zevpn->mcast_grp = vnip->mcast_grp;
			/* on local vtep-ip check if ES orig-ip
			 * needs to be updated
			 */
			zebra_evpn_es_set_base_evpn(zevpn);
		}
		zevpn_vxlan_if_set(zevpn, ifp, true /* set */);
		br_if = zif->brslave_info.br_if;
		zevpn_bridge_if_set(zevpn, br_if, true /* set */);
		vlan_if = zvni_map_to_svi(vnip->access_vlan, br_if);
		if (vlan_if) {
			zevpn->vid = vnip->access_vlan;
			zevpn->svi_if = vlan_if;
			zevpn->vrf_id = vlan_if->vrf->vrf_id;
			zl3vni = zl3vni_from_vrf(vlan_if->vrf->vrf_id);
			if (zl3vni)
				listnode_add_sort_nodup(zl3vni->l2vnis, zevpn);
		}

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Add L2-VNI %u VRF %s intf %s(%u) VLAN %u local IP %pI4 mcast_grp %pI4 master %u",
				vni,
				vlan_if ? vlan_if->vrf->name : VRF_DEFAULT_NAME,
				ifp->name, ifp->ifindex, vnip->access_vlan,
				&vxl->vtep_ip, &vnip->mcast_grp,
				zif->brslave_info.bridge_ifindex);

		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		/* Inform BGP */
		zebra_evpn_send_add_to_client(zevpn);

		/* Read and populate local MACs and neighbors */
		zebra_evpn_read_mac_neigh(zevpn, ifp);
	}

	return 0;
}

static void zebra_vxlan_if_vni_entry_del(struct zebra_if *zif,
					 struct zebra_vxlan_vni *vni)
{
	if (vni) {
		zebra_evpn_vl_vxl_deref(vni->access_vlan, vni->vni, zif);
		zebra_vxlan_if_del_vni(zif->ifp, vni);
	}
}

static int zebra_vxlan_if_vni_entry_add(struct zebra_if *zif,
					struct zebra_vxlan_vni *vni)
{
	zebra_evpn_vl_vxl_ref(vni->access_vlan, vni->vni, zif);
	return zebra_vxlan_if_add_vni(zif->ifp, vni);
}

static int zebra_vxlan_if_add_update_vni(struct zebra_if *zif,
					 struct zebra_vxlan_vni *vni,
					 void *ctxt)
{
	struct zebra_vxlan_vni vni_tmp;
	struct zebra_vxlan_if_update_ctx *ctx;
	struct zebra_vxlan_vni *old_vni = NULL;

	ctx = (struct zebra_vxlan_if_update_ctx *)ctxt;
	memcpy(&vni_tmp, vni, sizeof(*vni));

	if ((hashcount(ctx->old_vni_table) == 0) ||
	    !(old_vni = hash_release(ctx->old_vni_table, &vni_tmp))) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s vxlan %s adding vni(%d, %d)", __func__,
				   zif->ifp->name, vni->vni, vni->access_vlan);

		zebra_vxlan_if_vni_entry_add(zif, &vni_tmp);
		return 0;
	}

	ctx->old_vni = *old_vni;
	ctx->chgflags = ZEBRA_VXLIF_VLAN_CHANGE;

	/* copy mcast group from old_vni as thats not being changed here */
	vni->mcast_grp = old_vni->mcast_grp;

	if (old_vni->access_vlan != vni->access_vlan) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s vxlan %s updating vni(%d, %d) -> vni(%d, %d)",
				   __func__, zif->ifp->name, old_vni->vni,
				   old_vni->access_vlan, vni->vni,
				   vni->access_vlan);

		zebra_evpn_vl_vxl_deref(old_vni->access_vlan, old_vni->vni,
					zif);
		zebra_evpn_vl_vxl_ref(vni->access_vlan, vni->vni, zif);
		zebra_vxlan_if_update_vni(zif->ifp, vni, ctx);
		zebra_vxlan_vni_free(old_vni);
	} else {
		int ret;

		ret = zebra_evpn_vl_vxl_bridge_lookup(vni->access_vlan, zif);
		/* Here ret value 0 implied bridge vlan mapping is not present
		 * repopulated. Ignore ret value 1 as it means vlan mapping is
		 * present in bridge table.
		 */
		if (ret < 0) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s vxlan %s vni %u has error accessing bridge table.",
					   __func__, zif->ifp->name, vni->vni);
		} else if (ret == 0) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s vxlan %s vni (%u, %u) not present in bridge table",
					   __func__, zif->ifp->name, vni->vni,
					   vni->access_vlan);
			zebra_evpn_vl_vxl_deref(old_vni->access_vlan,
						old_vni->vni, zif);
			zebra_evpn_vl_vxl_ref(vni->access_vlan, vni->vni, zif);
			zebra_vxlan_if_update_vni(zif->ifp, vni, ctx);
			zebra_vxlan_vni_free(old_vni);
		}
	}

	return 0;
}

static int zebra_vxlan_if_vni_entry_update_callback(struct zebra_if *zif,
						    struct zebra_vxlan_vni *vni,
						    void *ctxt)
{
	struct zebra_vxlan_if_update_ctx *ctx;

	ctx = (struct zebra_vxlan_if_update_ctx *)ctxt;
	return zebra_vxlan_if_update_vni(zif->ifp, vni, ctx);
}

static int zebra_vxlan_if_vni_entry_del_callback(struct zebra_if *zif,
						 struct zebra_vxlan_vni *vni,
						 void *ctxt)
{
	zebra_vxlan_if_vni_entry_del(zif, vni);
	return 0;
}

static int zebra_vxlan_if_vni_entry_down_callback(struct zebra_if *zif,
						  struct zebra_vxlan_vni *vni,
						  void *ctxt)
{
	return zebra_vxlan_if_vni_down(zif->ifp, vni);
}

static int zebra_vxlan_if_vni_entry_up_callback(struct zebra_if *zif,
						struct zebra_vxlan_vni *vni,
						void *ctxt)
{
	return zebra_vxlan_if_vni_up(zif->ifp, vni);
}

static void zebra_vxlan_if_vni_clean(struct hash_bucket *bucket, void *arg)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni *vni;

	zif = (struct zebra_if *)arg;
	vni = (struct zebra_vxlan_vni *)bucket->data;
	zebra_vxlan_if_vni_entry_del(zif, vni);
}

void zebra_vxlan_vni_free(void *arg)
{
	struct zebra_vxlan_vni *vni;

	vni = (struct zebra_vxlan_vni *)arg;

	XFREE(MTYPE_TMP, vni);
}

void *zebra_vxlan_vni_alloc(void *p)
{
	struct zebra_vxlan_vni *vni;
	const struct zebra_vxlan_vni *vnip;

	vnip = (const struct zebra_vxlan_vni *)p;
	vni = XCALLOC(MTYPE_TMP, sizeof(*vni));
	vni->vni = vnip->vni;
	vni->access_vlan = vnip->access_vlan;
	vni->mcast_grp = vnip->mcast_grp;

	return (void *)vni;
}

struct hash *zebra_vxlan_vni_table_create(void)
{
	return hash_create(zebra_vxlan_vni_hash_keymake,
			   zebra_vxlan_vni_hash_cmp, "Zebra Vxlan VNI Table");
}

void zebra_vxlan_vni_table_destroy(struct hash *vni_table)
{
	hash_clean_and_free(&vni_table, zebra_vxlan_vni_free);
}

int zebra_vxlan_if_vni_table_destroy(struct zebra_if *zif)
{
	struct zebra_vxlan_vni_info *vni_info;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	if (vni_info->vni_table) {
		zebra_vxlan_if_vni_iterate(
			zif, zebra_vxlan_if_vni_entry_del_callback, NULL);
		zebra_vxlan_vni_table_destroy(vni_info->vni_table);
		vni_info->vni_table = NULL;
	}
	return 0;
}

int zebra_vxlan_if_vni_table_create(struct zebra_if *zif)
{
	struct zebra_vxlan_vni_info *vni_info;

	if (!IS_ZEBRA_VXLAN_IF_SVD(zif))
		return 0;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	vni_info->vni_table = zebra_vxlan_vni_table_create();
	if (!vni_info->vni_table)
		return -ENOMEM;

	return 0;
}

struct zebra_vxlan_vni *zebra_vxlan_if_vni_find(const struct zebra_if *zif,
						vni_t vni)
{
	struct zebra_vxlan_vni *vnip = NULL;
	const struct zebra_vxlan_vni_info *vni_info;
	struct zebra_vxlan_vni vni_tmp;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vnip = (struct zebra_vxlan_vni *)&vni_info->vni;
		assert(vnip);
		if (vni && (vnip->vni != vni))
			vnip = NULL;

		return vnip;
	}

	/* For SVD, the VNI value is a required parameter. */
	assert(vni);

	memset(&vni_tmp, 0, sizeof(vni_tmp));
	vni_tmp.vni = vni;
	vnip = (struct zebra_vxlan_vni *)hash_lookup(vni_info->vni_table,
						     (void *)&vni_tmp);

	/* TODO: For debugging. Remove later */
	if (vnip)
		assert(vnip->vni == vni);

	return vnip;
}

static int zif_vlanid_vni_walker(struct zebra_if *zif,
				 struct zebra_vxlan_vni *vnip, void *arg)
{
	struct zebra_vxlan_if_vlan_ctx *ctx;

	ctx = (struct zebra_vxlan_if_vlan_ctx *)arg;

	if (vnip->access_vlan == ctx->vid) {
		ctx->vni = vnip;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

struct zebra_vxlan_vni *zebra_vxlan_if_vlanid_vni_find(struct zebra_if *zif,
						       vlanid_t vid)
{
	struct zebra_vxlan_if_vlan_ctx ctx = {};

	if (!IS_ZEBRA_VXLAN_IF_SVD(zif))
		return NULL;

	ctx.vid = vid;

	zebra_vxlan_if_vni_walk(zif, zif_vlanid_vni_walker, &ctx);

	return ctx.vni;
}

void zebra_vxlan_if_vni_iterate(struct zebra_if *zif,
				int (*func)(struct zebra_if *zif,
					    struct zebra_vxlan_vni *, void *),
				void *arg)
{
	struct zebra_vxlan_vni_info *vni_info;
	struct zebra_vxlan_vni *vni = NULL;
	struct zebra_vxlan_if_ctx ctx;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni = zebra_vxlan_if_vni_find(zif, 0);
		func(zif, vni, arg);
		return;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.zif = zif;
	ctx.func = func;
	ctx.arg = arg;
	hash_iterate(vni_info->vni_table, zebra_vxlan_if_vni_iterate_callback,
		     &ctx);
}

void zebra_vxlan_if_vni_walk(struct zebra_if *zif,
			     int (*func)(struct zebra_if *zif,
					 struct zebra_vxlan_vni *, void *),
			     void *arg)
{
	struct zebra_vxlan_vni_info *vni_info;
	struct zebra_vxlan_vni *vni = NULL;
	struct zebra_vxlan_if_ctx ctx;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni = zebra_vxlan_if_vni_find(zif, 0);
		func(zif, vni, arg);
		return;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.zif = zif;
	ctx.func = func;
	ctx.arg = arg;
	hash_walk(vni_info->vni_table, zebra_vxlan_if_vni_walk_callback, &ctx);
}

vni_t zebra_vxlan_if_access_vlan_vni_find(struct zebra_if *zif,
					  struct interface *br_if)
{
	struct zebra_vxlan_vni *vni = NULL;

	/* Expected to be called only for vlan-unware bridges. In this case,
	 * we only support a per-VNI VXLAN interface model.
	 */
	if (!IS_ZEBRA_VXLAN_IF_VNI(zif))
		return 0;

	vni = zebra_vxlan_if_vni_find(zif, 0);
	assert(vni);

	return vni->vni;
}

/* SVD VLAN-VNI mapping update */
int zebra_vxlan_if_vni_table_add_update(struct interface *ifp,
					struct hash *vni_table)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;
	struct zebra_vxlan_if_update_ctx ctx;

	zif = (struct zebra_if *)ifp->info;

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);

	memset(&ctx, 0, sizeof(ctx));
	ctx.old_vni_table = vni_info->vni_table;
	vni_info->vni_table = vni_table;

	zebra_vxlan_if_vni_iterate(zif, zebra_vxlan_if_add_update_vni, &ctx);

	/* release kernel deleted vnis */
	if (ctx.old_vni_table) {
		if (hashcount(ctx.old_vni_table)) {
			/* UGLY HACK: Put back the old table so that delete of
			 * MACs goes through and then flip back.
			 */
			vni_info->vni_table = ctx.old_vni_table;
			hash_iterate(ctx.old_vni_table,
				     zebra_vxlan_if_vni_clean, zif);
			vni_info->vni_table = vni_table;
		}
		zebra_vxlan_vni_table_destroy(ctx.old_vni_table);
		ctx.old_vni_table = NULL;
	}

	return 0;
}

int zebra_vxlan_if_vni_mcast_group_add_update(struct interface *ifp,
					      vni_t vni_id,
					      struct in_addr *mcast_group)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni *vni;
	struct zebra_vxlan_if_update_ctx ctx;

	zif = (struct zebra_if *)ifp->info;

	if (!IS_ZEBRA_VXLAN_IF_SVD(zif))
		return 0;

	vni = zebra_vxlan_if_vni_find(zif, vni_id);
	if (!vni)
		return 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.old_vni.mcast_grp = vni->mcast_grp;
	ctx.chgflags = ZEBRA_VXLIF_MCAST_GRP_CHANGE;

	vni->mcast_grp = *mcast_group;

	return zebra_vxlan_if_update_vni(ifp, vni, &ctx);
}

int zebra_vxlan_if_vni_mcast_group_del(struct interface *ifp, vni_t vni_id,
				       struct in_addr *mcast_group)
{
	struct zebra_if *zif = NULL;
	struct zebra_vxlan_vni *vni;
	struct zebra_vxlan_if_update_ctx ctx;

	zif = (struct zebra_if *)ifp->info;

	if (!IS_ZEBRA_VXLAN_IF_SVD(zif))
		return 0;

	vni = zebra_vxlan_if_vni_find(zif, vni_id);
	if (!vni)
		return 0;

	if (memcmp(mcast_group, &vni->mcast_grp, sizeof(*mcast_group)))
		return 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.old_vni.mcast_grp = vni->mcast_grp;
	ctx.chgflags = ZEBRA_VXLIF_MCAST_GRP_CHANGE;

	memset(&vni->mcast_grp, 0, sizeof(vni->mcast_grp));

	return zebra_vxlan_if_update_vni(ifp, vni, &ctx);
}

int zebra_vxlan_if_vni_down(struct interface *ifp, struct zebra_vxlan_vni *vnip)
{
	vni_t vni;
	struct zebra_if *zif;
	struct zebra_l3vni *zl3vni;
	struct zebra_evpn *zevpn;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vni = vnip->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {
		/* process-if-down for l3-vni */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L3-VNI %u is DOWN", ifp->name,
				   ifp->ifindex, vni);

		zebra_vxlan_process_l3vni_oper_down(zl3vni);
	} else {
		/* process if-down for l2-vni */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L2-VNI %u is DOWN", ifp->name,
				   ifp->ifindex, vni);

		/* Locate hash entry; it is expected to exist. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn) {
			zlog_debug(
				"Failed to locate VNI hash at DOWN, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		assert(zevpn->vxlan_if == ifp);

		/* remove from l3-vni list */
		zl3vni = zl3vni_from_vrf(zevpn->vrf_id);
		if (zl3vni)
			listnode_delete(zl3vni->l2vnis, zevpn);

		zebra_evpn_vl_vxl_deref(vnip->access_vlan, vnip->vni, zif);

		/* Delete this VNI from BGP. */
		zebra_evpn_send_del_to_client(zevpn);

		/* Free up all neighbors and MACs, if any. */
		zebra_evpn_neigh_del_all(zevpn, 1, 0, DEL_ALL_NEIGH);
		zebra_evpn_mac_del_all(zevpn, 1, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zebra_evpn_vtep_del_all(zevpn, 1);
	}
	return 0;
}

/*
 * Handle VxLAN interface down
 */
int zebra_vxlan_if_down(struct interface *ifp)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
		return zebra_vxlan_if_vni_down(ifp, &vni_info->vni);
	}

	zebra_vxlan_if_vni_iterate(zif, zebra_vxlan_if_vni_entry_down_callback,
				   NULL);

	return 0;
}

int zebra_vxlan_if_vni_up(struct interface *ifp, struct zebra_vxlan_vni *vnip)
{
	vni_t vni;
	struct zebra_if *zif;
	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vni = vnip->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {
		/* we need to associate with SVI, if any, we can associate with
		 * svi-if only after association with vxlan-intf is complete
		 */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);
		zl3vni->mac_vlan_if = zl3vni_map_to_mac_vlan_if(zl3vni);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Intf %s(%u) L3-VNI %u is UP svi_if %s mac_vlan_if %s",
				ifp->name, ifp->ifindex, vni,
				zl3vni->svi_if ? zl3vni->svi_if->name : "NIL",
				zl3vni->mac_vlan_if ? zl3vni->mac_vlan_if->name
						    : "NIL");

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {
		/* Handle L2-VNI add */
		struct interface *vlan_if = NULL;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Intf %s(%u) L2-VNI %u is UP", ifp->name,
				   ifp->ifindex, vni);

		/* Locate hash entry; it is expected to exist. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn) {
			zlog_debug(
				"Failed to locate EVPN hash at UP, IF %s(%u) VNI %u",
				ifp->name, ifp->ifindex, vni);
			return -1;
		}

		assert(zevpn->vxlan_if == ifp);
		zebra_evpn_vl_vxl_ref(vnip->access_vlan, vnip->vni, zif);
		vlan_if = zvni_map_to_svi(vnip->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if) {
			zevpn->svi_if = vlan_if;
			zevpn->vrf_id = vlan_if->vrf->vrf_id;
			zl3vni = zl3vni_from_vrf(vlan_if->vrf->vrf_id);
			if (zl3vni)
				listnode_add_sort_nodup(zl3vni->l2vnis, zevpn);
		}

		/* If part of a bridge, inform BGP about this VNI. */
		/* Also, read and populate local MACs and neighbors. */
		if (zif->brslave_info.br_if) {
			zebra_evpn_send_add_to_client(zevpn);
			zebra_evpn_read_mac_neigh(zevpn, ifp);
		}
	}

	return 0;
}

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int zebra_vxlan_if_up(struct interface *ifp)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
		return zebra_vxlan_if_vni_up(ifp, &vni_info->vni);
	}

	zebra_vxlan_if_vni_iterate(zif, zebra_vxlan_if_vni_entry_up_callback,
				   NULL);

	return 0;
}

int zebra_vxlan_if_vni_del(struct interface *ifp, vni_t vni)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni *vnip;
	struct zebra_vxlan_vni vni_tmp;
	struct zebra_vxlan_vni_info *vni_info;

	zif = ifp->info;
	assert(zif);

	/* This should be called in SVD context only */
	assert(IS_ZEBRA_VXLAN_IF_SVD(zif));

	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	memset(&vni_tmp, 0, sizeof(vni_tmp));
	vni_tmp.vni = vni;

	vnip = hash_release(vni_info->vni_table, &vni_tmp);
	if (vnip) {
		zebra_vxlan_if_vni_entry_del(zif, vnip);
		zebra_vxlan_vni_free(vnip);
	}
	return 0;
}

/*
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int zebra_vxlan_if_del(struct interface *ifp)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	zif = ifp->info;
	assert(zif);

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
		zebra_evpn_vl_vxl_deref(vni_info->vni.access_vlan,
					vni_info->vni.vni, zif);
		return zebra_vxlan_if_del_vni(ifp, &vni_info->vni);
	}

	zebra_vxlan_if_vni_table_destroy(zif);

	return 0;
}

/*
 * Handle VxLAN interface update - change to tunnel IP, master or VLAN.
 */
int zebra_vxlan_if_update(struct interface *ifp,
			  struct zebra_vxlan_if_update_ctx *ctx)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	zif = ifp->info;
	assert(zif);

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
		return zebra_vxlan_if_update_vni(ifp, &vni_info->vni, ctx);
	}

	zebra_vxlan_if_vni_iterate(
		zif, zebra_vxlan_if_vni_entry_update_callback, ctx);

	return 0;
}

int zebra_vxlan_if_vni_add(struct interface *ifp, struct zebra_vxlan_vni *vni)
{
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	zif = ifp->info;
	assert(zif);

	/* This should be called in SVD context only */
	assert(IS_ZEBRA_VXLAN_IF_SVD(zif));

	/* First insert into the table */
	vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
	hash_get(vni_info->vni_table, (void *)vni, zebra_vxlan_vni_alloc);

	return zebra_vxlan_if_vni_entry_add(zif, vni);
}

/*
 * Handle VxLAN interface add.
 */
int zebra_vxlan_if_add(struct interface *ifp)
{
	int ret;
	struct zebra_if *zif;
	struct zebra_vxlan_vni_info *vni_info;

	zif = ifp->info;
	assert(zif);

	if (IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		vni_info = VNI_INFO_FROM_ZEBRA_IF(zif);
		zebra_evpn_vl_vxl_ref(vni_info->vni.access_vlan,
				      vni_info->vni.vni, zif);
		return zebra_vxlan_if_add_vni(ifp, &vni_info->vni);
	}

	ret = zebra_vxlan_if_vni_table_create(zif);
	if (ret < 0)
		return ret;

	return 0;
}
