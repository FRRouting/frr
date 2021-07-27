/*
 * Zebra EVPN for VxLAN interface handling
 *
 * Copyright (C) 2020 Cumulus Networks, Inc.
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

/*
 * Handle VxLAN interface down
 */
int zebra_vxlan_if_down(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_evpn *zevpn;
	struct zebra_vxlan_vni *vnip;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vnip = zebra_vxlan_if_vni_find(zif, 0);
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
 * Handle VxLAN interface up - update BGP if required.
 */
int zebra_vxlan_if_up(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_vxlan_vni *vnip;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vnip = zebra_vxlan_if_vni_find(zif, 0);
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
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int zebra_vxlan_if_del(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_vxlan_vni *vnip;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vnip = zebra_vxlan_if_vni_find(zif, 0);
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
		zebra_evpn_neigh_del_all(zevpn, 0, 0, DEL_ALL_NEIGH);
		zebra_evpn_mac_del_all(zevpn, 0, 0, DEL_ALL_MAC);

		/* Free up all remote VTEPs, if any. */
		zebra_evpn_vtep_del_all(zevpn, 0);

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

/*
 * Handle VxLAN interface update - change to tunnel IP, master or VLAN.
 */
int zebra_vxlan_if_update(struct interface *ifp, uint16_t chgflags)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct interface *vlan_if = NULL;
	struct zebra_vxlan_vni *vnip;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vnip = zebra_vxlan_if_vni_find(zif, 0);
	vni = vnip->vni;

	zl3vni = zl3vni_lookup(vni);
	if (zl3vni) {

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Update L3-VNI %u intf %s(%u) VLAN %u local IP %pI4 master %u chg 0x%x",
				vni, ifp->name, ifp->ifindex, vnip->access_vlan,
				&vxl->vtep_ip, zif->brslave_info.bridge_ifindex,
				chgflags);

		/* Removed from bridge? Cleanup and return */
		if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		    && (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
			zebra_vxlan_process_l3vni_oper_down(zl3vni);
			return 0;
		}

		if ((chgflags & ZEBRA_VXLIF_MASTER_MAC_CHANGE)
		    && if_is_operative(ifp) && is_l3vni_oper_up(zl3vni)) {
			zebra_vxlan_process_l3vni_oper_down(zl3vni);
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
			return 0;
		}

		/* access-vlan change - process oper down, associate with new
		 * svi_if and then process oper up again
		 */
		if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
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
		if (chgflags & ZEBRA_VXLIF_LOCAL_IP_CHANGE) {
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

		/* if we have a valid new master, process l3-vni oper up */
		if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE) {
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
		if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
		    && (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL)) {
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
		if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
			/* Remove all existing local neigh and MACs for this VNI
			 * (including from BGP)
			 */
			zebra_evpn_neigh_del_all(zevpn, 0, 1, DEL_LOCAL_MAC);
			zebra_evpn_mac_del_all(zevpn, 0, 1, DEL_LOCAL_MAC);
		}

		if (zevpn->local_vtep_ip.s_addr != vxl->vtep_ip.s_addr
		    || zevpn->mcast_grp.s_addr != vnip->mcast_grp.s_addr) {
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
		vlan_if = zvni_map_to_svi(vnip->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if)
			zevpn->svi_if = vlan_if;

		/* Take further actions needed.
		 * Note that if we are here, there is a change of interest.
		 */
		/* If down or not mapped to a bridge, we're done. */
		if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
			return 0;

		/* Inform BGP, if there is a change of interest. */
		if (chgflags &
		    (ZEBRA_VXLIF_MASTER_CHANGE | ZEBRA_VXLIF_LOCAL_IP_CHANGE |
		     ZEBRA_VXLIF_MCAST_GRP_CHANGE | ZEBRA_VXLIF_VLAN_CHANGE))
			zebra_evpn_send_add_to_client(zevpn);

		/* If there is a valid new master or a VLAN mapping change,
		 * read and populate local MACs and neighbors.
		 * Also, reinstall any remote MACs and neighbors
		 * for this VNI (based on new VLAN).
		 */
		if (chgflags & ZEBRA_VXLIF_MASTER_CHANGE)
			zebra_evpn_read_mac_neigh(zevpn, ifp);
		else if (chgflags & ZEBRA_VXLIF_VLAN_CHANGE) {
			struct mac_walk_ctx m_wctx;
			struct neigh_walk_ctx n_wctx;

			zebra_evpn_read_mac_neigh(zevpn, ifp);

			memset(&m_wctx, 0, sizeof(m_wctx));
			m_wctx.zevpn = zevpn;
			hash_iterate(zevpn->mac_table,
				     zebra_evpn_install_mac_hash, &m_wctx);

			memset(&n_wctx, 0, sizeof(n_wctx));
			n_wctx.zevpn = zevpn;
			hash_iterate(zevpn->neigh_table,
				     zebra_evpn_install_neigh_hash, &n_wctx);
		}
	}

	return 0;
}

/*
 * Handle VxLAN interface add.
 */
int zebra_vxlan_if_add(struct interface *ifp)
{
	vni_t vni;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	struct zebra_vxlan_vni *vnip;

	/* Check if EVPN is enabled. */
	if (!is_evpn_enabled())
		return 0;

	zif = ifp->info;
	assert(zif);
	vnip = zebra_vxlan_if_vni_find(zif, 0);
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

		/* Associate with SVI, if any. We can associate with svi-if only
		 * after association with vxlan_if is complete */
		zl3vni->svi_if = zl3vni_map_to_svi_if(zl3vni);

		zl3vni->mac_vlan_if = zl3vni_map_to_mac_vlan_if(zl3vni);

		if (is_l3vni_oper_up(zl3vni))
			zebra_vxlan_process_l3vni_oper_up(zl3vni);
	} else {

		/* process if-add for l2-vni */
		struct interface *vlan_if = NULL;

		/* Create or update EVPN hash. */
		zevpn = zebra_evpn_lookup(vni);
		if (!zevpn)
			zevpn = zebra_evpn_add(vni);

		if (zevpn->local_vtep_ip.s_addr != vxl->vtep_ip.s_addr
		    || zevpn->mcast_grp.s_addr != vnip->mcast_grp.s_addr) {
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
		vlan_if = zvni_map_to_svi(vnip->access_vlan,
					  zif->brslave_info.br_if);
		if (vlan_if) {
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
