/*
 * Zebra EVPN for VxLAN code
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

#include "hash.h"
#include "interface.h"
#include "jhash.h"
#include "memory.h"
#include "prefix.h"
#include "vlan.h"
#include "json.h"

#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"

DEFINE_MTYPE_STATIC(ZEBRA, MAC, "EVPN MAC");

/*
 * Return number of valid MACs in an EVPN's MAC hash table - all
 * remote MACs and non-internal (auto) local MACs count.
 */
uint32_t num_valid_macs(zebra_evpn_t *zevpn)
{
	unsigned int i;
	uint32_t num_macs = 0;
	struct hash *hash;
	struct hash_bucket *hb;
	zebra_mac_t *mac;

	hash = zevpn->mac_table;
	if (!hash)
		return num_macs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			mac = (zebra_mac_t *)hb->data;
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
			    || CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
			    || !CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
				num_macs++;
		}
	}

	return num_macs;
}

uint32_t num_dup_detected_macs(zebra_evpn_t *zevpn)
{
	unsigned int i;
	uint32_t num_macs = 0;
	struct hash *hash;
	struct hash_bucket *hb;
	zebra_mac_t *mac;

	hash = zevpn->mac_table;
	if (!hash)
		return num_macs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			mac = (zebra_mac_t *)hb->data;
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
				num_macs++;
		}
	}

	return num_macs;
}

/*
 * Install remote MAC into the forwarding plane.
 */
int zebra_evpn_rem_mac_install(zebra_evpn_t *zevpn, zebra_mac_t *mac,
			       bool was_static)
{
	const struct zebra_if *zif, *br_zif;
	const struct zebra_l2info_vxlan *vxl;
	bool sticky;
	enum zebra_dplane_result res;
	const struct interface *br_ifp;
	vlanid_t vid;
	uint32_t nhg_id;
	struct in_addr vtep_ip;

	zif = zevpn->vxlan_if->info;
	if (!zif)
		return -1;

	br_ifp = zif->brslave_info.br_if;
	if (br_ifp == NULL)
		return -1;

	vxl = &zif->l2info.vxl;

	sticky = !!CHECK_FLAG(mac->flags,
			      (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));

	/* If nexthop group for the FDB entry is inactive (not programmed in
	 * the dataplane) the MAC entry cannot be installed
	 */
	if (mac->es) {
		if (!(mac->es->flags & ZEBRA_EVPNES_NHG_ACTIVE))
			return -1;
		nhg_id = mac->es->nhg_id;
		vtep_ip.s_addr = 0;
	} else {
		nhg_id = 0;
		vtep_ip = mac->fwd_info.r_vtep_ip;
	}

	br_zif = (const struct zebra_if *)(br_ifp->info);

	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		vid = vxl->access_vlan;
	else
		vid = 0;

	res = dplane_rem_mac_add(zevpn->vxlan_if, br_ifp, vid, &mac->macaddr,
				 vtep_ip, sticky, nhg_id, was_static);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/*
 * Uninstall remote MAC from the forwarding plane.
 */
int zebra_evpn_rem_mac_uninstall(zebra_evpn_t *zevpn, zebra_mac_t *mac,
		bool force)
{
	const struct zebra_if *zif, *br_zif;
	const struct zebra_l2info_vxlan *vxl;
	struct in_addr vtep_ip;
	const struct interface *ifp, *br_ifp;
	vlanid_t vid;
	enum zebra_dplane_result res;

	/* If the MAC was not installed there is no need to uninstall it */
	if (!force && mac->es &&
			!(mac->es->flags & ZEBRA_EVPNES_NHG_ACTIVE))
		return -1;

	if (!zevpn->vxlan_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"VNI %u hash %p couldn't be uninstalled - no intf",
				zevpn->vni, zevpn);
		return -1;
	}

	zif = zevpn->vxlan_if->info;
	if (!zif)
		return -1;

	br_ifp = zif->brslave_info.br_if;
	if (br_ifp == NULL)
		return -1;

	vxl = &zif->l2info.vxl;

	br_zif = (const struct zebra_if *)br_ifp->info;

	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		vid = vxl->access_vlan;
	else
		vid = 0;

	ifp = zevpn->vxlan_if;
	vtep_ip = mac->fwd_info.r_vtep_ip;

	res = dplane_rem_mac_del(ifp, br_ifp, vid, &mac->macaddr, vtep_ip);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/*
 * Decrement neighbor refcount of MAC; uninstall and free it if
 * appropriate.
 */
void zebra_evpn_deref_ip2mac(zebra_evpn_t *zevpn, zebra_mac_t *mac)
{
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
		return;

	/* If all remote neighbors referencing a remote MAC go away,
	 * we need to uninstall the MAC.
	 */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
	    && remote_neigh_count(mac) == 0) {
		zebra_evpn_rem_mac_uninstall(zevpn, mac,
				false /*force*/);
		zebra_evpn_es_mac_deref_entry(mac);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
	}

	/* If no neighbors, delete the MAC. */
	if (list_isempty(mac->neigh_list))
		zebra_evpn_mac_del(zevpn, mac);
}

static void zebra_evpn_mac_get_access_info(zebra_mac_t *mac,
					   struct interface **ifpP,
					   vlanid_t *vid)
{
	/* if the mac is associated with an ES we must get the access
	 * info from the ES
	 */
	if (mac->es) {
		struct zebra_if *zif;

		/* get the access port from the es */
		*ifpP = mac->es->zif ? mac->es->zif->ifp : NULL;
		/* get the vlan from the EVPN */
		if (mac->zevpn->vxlan_if) {
			zif = mac->zevpn->vxlan_if->info;
			*vid = zif->l2info.vxl.access_vlan;
		} else {
			*vid = 0;
		}
	} else {
		struct zebra_ns *zns;

		*vid = mac->fwd_info.local.vid;
		zns = zebra_ns_lookup(mac->fwd_info.local.ns_id);
		*ifpP = if_lookup_by_index_per_ns(zns,
						  mac->fwd_info.local.ifindex);
	}
}

static int zebra_evpn_dad_mac_auto_recovery_exp(struct thread *t)
{
	struct zebra_vrf *zvrf = NULL;
	zebra_mac_t *mac = NULL;
	zebra_evpn_t *zevpn = NULL;
	struct listnode *node = NULL;
	zebra_neigh_t *nbr = NULL;
	char buf[ETHER_ADDR_STRLEN];

	mac = THREAD_ARG(t);

	/* since this is asynchronous we need sanity checks*/
	zvrf = vrf_info_lookup(mac->zevpn->vrf_id);
	if (!zvrf)
		return 0;

	zevpn = zebra_evpn_lookup(mac->zevpn->vni);
	if (!zevpn)
		return 0;

	mac = zebra_evpn_mac_lookup(zevpn, &mac->macaddr);
	if (!mac)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%s: duplicate addr mac %s flags 0x%x learn count %u host count %u auto recovery expired",
			__func__,
			prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			mac->flags, mac->dad_count, listcount(mac->neigh_list));

	/* Remove all IPs as duplicate associcated with this MAC */
	for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, nbr)) {
		if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
			if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL))
				ZEBRA_NEIGH_SET_INACTIVE(nbr);
			else if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE))
				zebra_evpn_rem_neigh_install(
					zevpn, nbr, false /*was_static*/);
		}

		UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
		nbr->dad_count = 0;
		nbr->detect_start_time.tv_sec = 0;
		nbr->dad_dup_detect_time = 0;
	}

	UNSET_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE);
	mac->dad_count = 0;
	mac->detect_start_time.tv_sec = 0;
	mac->detect_start_time.tv_usec = 0;
	mac->dad_dup_detect_time = 0;
	mac->dad_mac_auto_recovery_timer = NULL;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		/* Inform to BGP */
		if (zebra_evpn_mac_send_add_to_client(zevpn->vni, &mac->macaddr,
						      mac->flags, mac->loc_seq,
						      mac->es))
			return -1;

		/* Process all neighbors associated with this MAC. */
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac, 0,
							     0 /*es_change*/);

	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);

		/* Install the entry. */
		zebra_evpn_rem_mac_install(zevpn, mac, false /* was_static */);
	}

	return 0;
}

static void zebra_evpn_dup_addr_detect_for_mac(struct zebra_vrf *zvrf,
					       zebra_mac_t *mac,
					       struct in_addr vtep_ip,
					       bool do_dad, bool *is_dup_detect,
					       bool is_local)
{
	zebra_neigh_t *nbr;
	struct listnode *node = NULL;
	struct timeval elapsed = {0, 0};
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	bool reset_params = false;

	if (!(zebra_evpn_do_dup_addr_detect(zvrf) && do_dad))
		return;

	/* MAC is detected as duplicate,
	 * Local MAC event -> hold on advertising to BGP.
	 * Remote MAC event -> hold on installing it.
	 */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: duplicate addr MAC %s flags 0x%x skip update to client, learn count %u recover time %u",
				__func__,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				mac->flags, mac->dad_count,
				zvrf->dad_freeze_time);

		/* For duplicate MAC do not update
		 * client but update neigh due to
		 * this MAC update.
		 */
		if (zvrf->dad_freeze)
			*is_dup_detect = true;

		return;
	}

	/* Check if detection time (M-secs) expired.
	 * Reset learn count and detection start time.
	 */
	monotime_since(&mac->detect_start_time, &elapsed);
	reset_params = (elapsed.tv_sec > zvrf->dad_time);
	if (is_local && !reset_params) {
		/* RFC-7432: A PE/VTEP that detects a MAC mobility
		 * event via LOCAL learning starts an M-second timer.
		 *
		 * NOTE: This is the START of the probe with count is
		 * 0 during LOCAL learn event.
		 * (mac->dad_count == 0 || elapsed.tv_sec >= zvrf->dad_time)
		 */
		reset_params = !mac->dad_count;
	}

	if (reset_params) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: duplicate addr MAC %s flags 0x%x detection time passed, reset learn count %u",
				__func__,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				mac->flags, mac->dad_count);

		mac->dad_count = 0;
		/* Start dup. addr detection (DAD) start time,
		 * ONLY during LOCAL learn.
		 */
		if (is_local)
			monotime(&mac->detect_start_time);

	} else if (!is_local) {
		/* For REMOTE MAC, increment detection count
		 * ONLY while in probe window, once window passed,
		 * next local learn event should trigger DAD.
		 */
		mac->dad_count++;
	}

	/* For LOCAL MAC learn event, once count is reset above via either
	 * initial/start detection time or passed the probe time, the count
	 * needs to be incremented.
	 */
	if (is_local)
		mac->dad_count++;

	if (mac->dad_count >= zvrf->dad_max_moves) {
		flog_warn(EC_ZEBRA_DUP_MAC_DETECTED,
			  "VNI %u: MAC %s detected as duplicate during %s VTEP %s",
			  mac->zevpn->vni,
			  prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			  is_local ? "local update, last" :
			  "remote update, from", inet_ntoa(vtep_ip));

		SET_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE);

		/* Capture Duplicate detection time */
		mac->dad_dup_detect_time = monotime(NULL);

		/* Mark all IPs/Neighs as duplicate
		 * associcated with this MAC
		 */
		for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, nbr)) {

			/* Ony Mark IPs which are Local */
			if (!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL))
				continue;

			SET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);

			nbr->dad_dup_detect_time = monotime(NULL);

			flog_warn(EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
				  "VNI %u: MAC %s IP %s detected as duplicate during %s update, inherit duplicate from MAC",
				  mac->zevpn->vni,
				  prefix_mac2str(&mac->macaddr,
						 buf, sizeof(buf)),
				  ipaddr2str(&nbr->ip, buf1, sizeof(buf1)),
				  is_local ? "local" : "remote");
		}

		/* Start auto recovery timer for this MAC */
		THREAD_OFF(mac->dad_mac_auto_recovery_timer);
		if (zvrf->dad_freeze && zvrf->dad_freeze_time) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s: duplicate addr MAC %s flags 0x%x auto recovery time %u start",
					__func__,
					prefix_mac2str(&mac->macaddr, buf,
						       sizeof(buf)),
					mac->flags, zvrf->dad_freeze_time);

			thread_add_timer(zrouter.master,
					 zebra_evpn_dad_mac_auto_recovery_exp,
					 mac, zvrf->dad_freeze_time,
					 &mac->dad_mac_auto_recovery_timer);
		}

		/* In case of local update, do not inform to client (BGPd),
		 * upd_neigh for neigh sequence change.
		 */
		if (zvrf->dad_freeze)
			*is_dup_detect = true;
	}
}

/*
 * Print a specific MAC entry.
 */
void zebra_evpn_print_mac(zebra_mac_t *mac, void *ctxt, json_object *json)
{
	struct vty *vty;
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct zebra_vrf *zvrf;
	struct timeval detect_start_time = {0, 0};
	char timebuf[MONOTIME_STRLEN];
	char thread_buf[THREAD_TIMER_STRLEN];

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return;

	vty = (struct vty *)ctxt;
	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	if (json) {
		json_object *json_mac = json_object_new_object();

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			struct interface *ifp;
			vlanid_t vid;

			zebra_evpn_mac_get_access_info(mac, &ifp, &vid);
			json_object_string_add(json_mac, "type", "local");
			if (ifp) {
				json_object_string_add(json_mac, "intf",
						       ifp->name);
				json_object_int_add(json_mac, "ifindex",
						    ifp->ifindex);
			}
			if (vid)
				json_object_int_add(json_mac, "vlan", vid);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
			json_object_string_add(json_mac, "type", "remote");
			json_object_string_add(
				json_mac, "remoteVtep",
				inet_ntoa(mac->fwd_info.r_vtep_ip));
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
			json_object_string_add(json_mac, "type", "auto");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
			json_object_boolean_true_add(json_mac, "stickyMac");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW))
			json_object_boolean_true_add(json_mac,
						     "defaultGateway");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW))
			json_object_boolean_true_add(json_mac,
						     "remoteGatewayMac");

		json_object_int_add(json_mac, "localSequence", mac->loc_seq);
		json_object_int_add(json_mac, "remoteSequence", mac->rem_seq);

		json_object_int_add(json_mac, "detectionCount", mac->dad_count);
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
			json_object_boolean_true_add(json_mac, "isDuplicate");
		else
			json_object_boolean_false_add(json_mac, "isDuplicate");

		json_object_int_add(json_mac, "syncNeighCount",
				    mac->sync_neigh_cnt);
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE))
			json_object_boolean_true_add(json_mac, "localInactive");
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY))
			json_object_boolean_true_add(json_mac, "peerProxy");
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
			json_object_boolean_true_add(json_mac, "peerActive");
		if (mac->hold_timer)
			json_object_string_add(
				json_mac, "peerActiveHold",
				thread_timer_to_hhmmss(thread_buf,
						       sizeof(thread_buf),
						       mac->hold_timer));
		/* print all the associated neigh */
		if (!listcount(mac->neigh_list))
			json_object_string_add(json_mac, "neighbors", "none");
		else {
			json_object *json_active_nbrs = json_object_new_array();
			json_object *json_inactive_nbrs =
				json_object_new_array();
			json_object *json_nbrs = json_object_new_object();

			for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, n)) {
				if (IS_ZEBRA_NEIGH_ACTIVE(n))
					json_object_array_add(
						json_active_nbrs,
						json_object_new_string(
							ipaddr2str(
								&n->ip, buf2,
								sizeof(buf2))));
				else
					json_object_array_add(
						json_inactive_nbrs,
						json_object_new_string(
							ipaddr2str(
								&n->ip, buf2,
								sizeof(buf2))));
			}

			json_object_object_add(json_nbrs, "active",
					       json_active_nbrs);
			json_object_object_add(json_nbrs, "inactive",
					       json_inactive_nbrs);
			json_object_object_add(json_mac, "neighbors",
					       json_nbrs);
		}

		json_object_object_add(json, buf1, json_mac);
	} else {
		vty_out(vty, "MAC: %s\n", buf1);

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			struct interface *ifp;
			vlanid_t vid;

			zebra_evpn_mac_get_access_info(mac, &ifp, &vid);

			if (mac->es)
				vty_out(vty, " ESI: %s\n", mac->es->esi_str);

			if (ifp)
				vty_out(vty, " Intf: %s(%u)", ifp->name,
					ifp->ifindex);
			else
				vty_out(vty, " Intf: -");
			vty_out(vty, " VLAN: %u", vid);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
			if (mac->es)
				vty_out(vty, " Remote ES: %s",
					mac->es->esi_str);
			else
				vty_out(vty, " Remote VTEP: %s",
					inet_ntoa(mac->fwd_info.r_vtep_ip));
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)) {
			vty_out(vty, " Auto Mac ");
		}

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
			vty_out(vty, " Sticky Mac ");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW))
			vty_out(vty, " Default-gateway Mac ");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW))
			vty_out(vty, " Remote-gateway Mac ");

		vty_out(vty, "\n");
		vty_out(vty, " Sync-info: neigh#: %u", mac->sync_neigh_cnt);
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE))
			vty_out(vty, " local-inactive");
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY))
			vty_out(vty, " peer-proxy");
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
			vty_out(vty, " peer-active");
		if (mac->hold_timer)
			vty_out(vty, " (ht: %s)",
				thread_timer_to_hhmmss(thread_buf,
						       sizeof(thread_buf),
						       mac->hold_timer));
		vty_out(vty, "\n");
		vty_out(vty, " Local Seq: %u Remote Seq: %u", mac->loc_seq,
			mac->rem_seq);
		vty_out(vty, "\n");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)) {
			vty_out(vty, " Duplicate, detected at %s",
				time_to_string(mac->dad_dup_detect_time,
					       timebuf));
		} else if (mac->dad_count) {
			monotime_since(&mac->detect_start_time,
				       &detect_start_time);
			if (detect_start_time.tv_sec <= zvrf->dad_time) {
				time_to_string(mac->detect_start_time.tv_sec,
					       timebuf);
				vty_out(vty,
					" Duplicate detection started at %s, detection count %u\n",
					timebuf, mac->dad_count);
			}
		}

		/* print all the associated neigh */
		vty_out(vty, " Neighbors:\n");
		if (!listcount(mac->neigh_list))
			vty_out(vty, "    No Neighbors\n");
		else {
			for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, n)) {
				vty_out(vty, "    %s %s\n",
					ipaddr2str(&n->ip, buf2, sizeof(buf2)),
					(IS_ZEBRA_NEIGH_ACTIVE(n)
						 ? "Active"
						 : "Inactive"));
			}
		}

		vty_out(vty, "\n");
	}
}

static char *zebra_evpn_print_mac_flags(zebra_mac_t *mac, char *flags_buf)
{
	sprintf(flags_buf, "%s%s%s%s", mac->sync_neigh_cnt ? "N" : "",
		(mac->flags & ZEBRA_MAC_ES_PEER_ACTIVE) ? "P" : "",
		(mac->flags & ZEBRA_MAC_ES_PEER_PROXY) ? "X" : "",
		(mac->flags & ZEBRA_MAC_LOCAL_INACTIVE) ? "I" : "");

	return flags_buf;
}

/*
 * Print MAC hash entry - called for display of all MACs.
 */
void zebra_evpn_print_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json_mac_hdr = NULL, *json_mac = NULL;
	zebra_mac_t *mac;
	char buf1[ETHER_ADDR_STRLEN];
	struct mac_walk_ctx *wctx = ctxt;
	char flags_buf[6];

	vty = wctx->vty;
	json_mac_hdr = wctx->json;
	mac = (zebra_mac_t *)bucket->data;

	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	if (json_mac_hdr)
		json_mac = json_object_new_object();

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		struct interface *ifp;
		vlanid_t vid;

		if (wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP)
			return;

		zebra_evpn_mac_get_access_info(mac, &ifp, &vid);
		if (json_mac_hdr == NULL) {
			vty_out(vty, "%-17s %-6s %-5s %-30s", buf1, "local",
				zebra_evpn_print_mac_flags(mac, flags_buf),
				ifp ? ifp->name : "-");
		} else {
			json_object_string_add(json_mac, "type", "local");
			if (ifp)
				json_object_string_add(json_mac, "intf",
						       ifp->name);
		}
		if (vid) {
			if (json_mac_hdr == NULL)
				vty_out(vty, " %-5u", vid);
			else
				json_object_int_add(json_mac, "vlan", vid);
		} else /* No vid? fill out the space */
			if (json_mac_hdr == NULL)
			vty_out(vty, " %-5s", "");
		if (json_mac_hdr == NULL) {
			vty_out(vty, " %u/%u", mac->loc_seq, mac->rem_seq);
			vty_out(vty, "\n");
		} else {
			json_object_int_add(json_mac, "localSequence",
					    mac->loc_seq);
			json_object_int_add(json_mac, "remoteSequence",
					    mac->rem_seq);
			json_object_int_add(json_mac, "detectionCount",
					    mac->dad_count);
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
				json_object_boolean_true_add(json_mac,
							     "isDuplicate");
			else
				json_object_boolean_false_add(json_mac,
							      "isDuplicate");
			json_object_object_add(json_mac_hdr, buf1, json_mac);
		}

		wctx->count++;

	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {

		if ((wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP)
		    && !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
				       &wctx->r_vtep_ip))
			return;

		if (json_mac_hdr == NULL) {
			if ((wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP)
			    && (wctx->count == 0)) {
				vty_out(vty, "\nVNI %u\n\n", wctx->zevpn->vni);
				vty_out(vty, "%-17s %-6s %-5s%-30s %-5s %s\n",
					"MAC", "Type", "Flags",
					"Intf/Remote ES/VTEP", "VLAN",
					"Seq #'s");
			}
			vty_out(vty, "%-17s %-6s %-5s %-30s %-5s %u/%u\n", buf1,
				"remote",
				zebra_evpn_print_mac_flags(mac, flags_buf),
				mac->es ? mac->es->esi_str
					: inet_ntoa(mac->fwd_info.r_vtep_ip),
				"", mac->loc_seq, mac->rem_seq);
		} else {
			json_object_string_add(json_mac, "type", "remote");
			json_object_string_add(
				json_mac, "remoteVtep",
				inet_ntoa(mac->fwd_info.r_vtep_ip));
			json_object_object_add(json_mac_hdr, buf1, json_mac);
			json_object_int_add(json_mac, "localSequence",
					    mac->loc_seq);
			json_object_int_add(json_mac, "remoteSequence",
					    mac->rem_seq);
			json_object_int_add(json_mac, "detectionCount",
					    mac->dad_count);
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
				json_object_boolean_true_add(json_mac,
							     "isDuplicate");
			else
				json_object_boolean_false_add(json_mac,
							      "isDuplicate");
		}

		wctx->count++;
	}
}

/*
 * Print MAC hash entry in detail - called for display of all MACs.
 */
void zebra_evpn_print_mac_hash_detail(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json_mac_hdr = NULL;
	zebra_mac_t *mac;
	struct mac_walk_ctx *wctx = ctxt;
	char buf1[ETHER_ADDR_STRLEN];

	vty = wctx->vty;
	json_mac_hdr = wctx->json;
	mac = (zebra_mac_t *)bucket->data;
	if (!mac)
		return;

	wctx->count++;
	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	zebra_evpn_print_mac(mac, vty, json_mac_hdr);
}

/*
 * Inform BGP about local MACIP.
 */
int zebra_evpn_macip_send_msg_to_client(vni_t vni, struct ethaddr *macaddr,
					struct ipaddr *ip, uint8_t flags,
					uint32_t seq, int state,
					struct zebra_evpn_es *es, uint16_t cmd)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	int ipa_len;
	struct zserv *client = NULL;
	struct stream *s = NULL;
	esi_t *esi = es ? &es->esi : zero_esi;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, zebra_vrf_get_evpn_id());
	stream_putl(s, vni);
	stream_put(s, macaddr->octet, ETH_ALEN);
	if (ip) {
		ipa_len = 0;
		if (IS_IPADDR_V4(ip))
			ipa_len = IPV4_MAX_BYTELEN;
		else if (IS_IPADDR_V6(ip))
			ipa_len = IPV6_MAX_BYTELEN;

		stream_putl(s, ipa_len); /* IP address length */
		if (ipa_len)
			stream_put(s, &ip->ip.addr, ipa_len); /* IP address */
	} else
		stream_putl(s, 0); /* Just MAC. */

	if (cmd == ZEBRA_MACIP_ADD) {
		stream_putc(s, flags); /* sticky mac/gateway mac */
		stream_putl(s, seq);   /* sequence number */
		stream_put(s, esi, sizeof(esi_t));
	} else {
		stream_putl(s, state); /* state - active/inactive */
	}


	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Send MACIP %s f 0x%x MAC %s IP %s seq %u L2-VNI %u ESI %s to %s",
			(cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del", flags,
			prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)), seq, vni,
			es ? es->esi_str : "-",
			zebra_route_string(client->proto));

	if (cmd == ZEBRA_MACIP_ADD)
		client->macipadd_cnt++;
	else
		client->macipdel_cnt++;

	return zserv_send_message(client, s);
}

static unsigned int mac_hash_keymake(const void *p)
{
	const zebra_mac_t *pmac = p;
	const void *pnt = (void *)pmac->macaddr.octet;

	return jhash(pnt, ETH_ALEN, 0xa5a5a55a);
}

/*
 * Compare two MAC addresses.
 */
static bool mac_cmp(const void *p1, const void *p2)
{
	const zebra_mac_t *pmac1 = p1;
	const zebra_mac_t *pmac2 = p2;

	if (pmac1 == NULL && pmac2 == NULL)
		return true;

	if (pmac1 == NULL || pmac2 == NULL)
		return false;

	return (memcmp(pmac1->macaddr.octet, pmac2->macaddr.octet, ETH_ALEN)
		== 0);
}

/*
 * Callback to allocate MAC hash entry.
 */
static void *zebra_evpn_mac_alloc(void *p)
{
	const zebra_mac_t *tmp_mac = p;
	zebra_mac_t *mac;

	mac = XCALLOC(MTYPE_MAC, sizeof(zebra_mac_t));
	*mac = *tmp_mac;

	return ((void *)mac);
}

/*
 * Add MAC entry.
 */
zebra_mac_t *zebra_evpn_mac_add(zebra_evpn_t *zevpn, struct ethaddr *macaddr)
{
	zebra_mac_t tmp_mac;
	zebra_mac_t *mac = NULL;

	memset(&tmp_mac, 0, sizeof(zebra_mac_t));
	memcpy(&tmp_mac.macaddr, macaddr, ETH_ALEN);
	mac = hash_get(zevpn->mac_table, &tmp_mac, zebra_evpn_mac_alloc);
	assert(mac);

	mac->zevpn = zevpn;
	mac->dad_mac_auto_recovery_timer = NULL;

	mac->neigh_list = list_new();
	mac->neigh_list->cmp = neigh_list_cmp;

	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char buf[ETHER_ADDR_STRLEN];

		zlog_debug("%s: MAC %s flags 0x%x", __func__,
			   prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			   mac->flags);
	}
	return mac;
}

/*
 * Delete MAC entry.
 */
int zebra_evpn_mac_del(zebra_evpn_t *zevpn, zebra_mac_t *mac)
{
	zebra_mac_t *tmp_mac;
	char buf[ETHER_ADDR_STRLEN];

	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char buf[ETHER_ADDR_STRLEN];

		zlog_debug("%s: MAC %s flags 0x%x", __func__,
			   prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			   mac->flags);
	}

	/* If the MAC is freed before the neigh we will end up
	 * with a stale pointer against the neigh
	 */
	if (!list_isempty(mac->neigh_list))
		zlog_warn("%s: MAC %s flags 0x%x neigh list not empty %d", __func__,
			   prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			   mac->flags, listcount(mac->neigh_list));

	/* force de-ref any ES entry linked to the MAC */
	zebra_evpn_es_mac_deref_entry(mac);

	/* Cancel proxy hold timer */
	zebra_evpn_mac_stop_hold_timer(mac);

	/* Cancel auto recovery */
	THREAD_OFF(mac->dad_mac_auto_recovery_timer);

	list_delete(&mac->neigh_list);

	/* Free the VNI hash entry and allocated memory. */
	tmp_mac = hash_release(zevpn->mac_table, mac);
	XFREE(MTYPE_MAC, tmp_mac);

	return 0;
}

static bool zebra_evpn_check_mac_del_from_db(struct mac_walk_ctx *wctx,
					     zebra_mac_t *mac)
{
	if ((wctx->flags & DEL_LOCAL_MAC) && (mac->flags & ZEBRA_MAC_LOCAL))
		return true;
	else if ((wctx->flags & DEL_REMOTE_MAC)
		 && (mac->flags & ZEBRA_MAC_REMOTE))
		return true;
	else if ((wctx->flags & DEL_REMOTE_MAC_FROM_VTEP)
		 && (mac->flags & ZEBRA_MAC_REMOTE)
		 && IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &wctx->r_vtep_ip))
		return true;
	else if ((wctx->flags & DEL_LOCAL_MAC) && (mac->flags & ZEBRA_MAC_AUTO)
		 && !listcount(mac->neigh_list)) {
		if (IS_ZEBRA_DEBUG_VXLAN) {
			char buf[ETHER_ADDR_STRLEN];

			zlog_debug(
				"%s: Del MAC %s flags 0x%x", __func__,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				mac->flags);
		}
		wctx->uninstall = 0;

		return true;
	}

	return false;
}

/*
 * Free MAC hash entry (callback)
 */
static void zebra_evpn_mac_del_hash_entry(struct hash_bucket *bucket, void *arg)
{
	struct mac_walk_ctx *wctx = arg;
	zebra_mac_t *mac = bucket->data;

	if (zebra_evpn_check_mac_del_from_db(wctx, mac)) {
		if (wctx->upd_client && (mac->flags & ZEBRA_MAC_LOCAL)) {
			zebra_evpn_mac_send_del_to_client(wctx->zevpn->vni,
							  &mac->macaddr,
							  mac->flags, false);
		}
		if (wctx->uninstall) {
			if (zebra_evpn_mac_is_static(mac))
				zebra_evpn_sync_mac_dp_install(
					mac, false /* set_inactive */,
					true /* force_clear_static */,
					__func__);

			if (mac->flags & ZEBRA_MAC_REMOTE)
				zebra_evpn_rem_mac_uninstall(wctx->zevpn,
						mac, false /*force*/);
		}

		zebra_evpn_mac_del(wctx->zevpn, mac);
	}

	return;
}

/*
 * Delete all MAC entries for this EVPN.
 */
void zebra_evpn_mac_del_all(zebra_evpn_t *zevpn, int uninstall, int upd_client,
			    uint32_t flags)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zevpn = zevpn;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(zevpn->mac_table, zebra_evpn_mac_del_hash_entry, &wctx);
}

/*
 * Look up MAC hash entry.
 */
zebra_mac_t *zebra_evpn_mac_lookup(zebra_evpn_t *zevpn, struct ethaddr *mac)
{
	zebra_mac_t tmp;
	zebra_mac_t *pmac;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.macaddr, mac, ETH_ALEN);
	pmac = hash_lookup(zevpn->mac_table, &tmp);

	return pmac;
}

/*
 * Inform BGP about local MAC addition.
 */
int zebra_evpn_mac_send_add_to_client(vni_t vni, struct ethaddr *macaddr,
				      uint32_t mac_flags, uint32_t seq,
				      struct zebra_evpn_es *es)
{
	uint8_t flags = 0;

	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_LOCAL_INACTIVE)) {
		/* host reachability has not been verified locally */

		/* if no ES peer is claiming reachability we can't advertise the
		 * entry
		 */
		if (!CHECK_FLAG(mac_flags, ZEBRA_MAC_ES_PEER_ACTIVE))
			return 0;

		/* ES peers are claiming reachability; we will
		 * advertise the entry but with a proxy flag
		 */
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT);
	}

	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_STICKY))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	if (CHECK_FLAG(mac_flags, ZEBRA_MAC_DEF_GW))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	return zebra_evpn_macip_send_msg_to_client(vni, macaddr, NULL, flags,
						   seq, ZEBRA_NEIGH_ACTIVE, es,
						   ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local MAC deletion.
 */
int zebra_evpn_mac_send_del_to_client(vni_t vni, struct ethaddr *macaddr,
				      uint32_t flags, bool force)
{
	if (!force) {
		if (CHECK_FLAG(flags, ZEBRA_MAC_LOCAL_INACTIVE)
		    && !CHECK_FLAG(flags, ZEBRA_MAC_ES_PEER_ACTIVE))
			/* the host was not advertised - nothing  to delete */
			return 0;
	}

	return zebra_evpn_macip_send_msg_to_client(
		vni, macaddr, NULL, 0 /* flags */, 0 /* seq */,
		ZEBRA_NEIGH_ACTIVE, NULL, ZEBRA_MACIP_DEL);
}

/*
 * wrapper to create a MAC hash table
 */
struct hash *zebra_mac_db_create(const char *desc)
{
	return hash_create(mac_hash_keymake, mac_cmp, desc);
}

/* program sync mac flags in the dataplane  */
int zebra_evpn_sync_mac_dp_install(zebra_mac_t *mac, bool set_inactive,
				    bool force_clear_static, const char *caller)
{
	char macbuf[ETHER_ADDR_STRLEN];
	struct interface *ifp;
	bool sticky;
	bool set_static;
	zebra_evpn_t *zevpn = mac->zevpn;
	vlanid_t vid;
	struct zebra_if *zif;
	struct interface *br_ifp;

	/* get the access vlan from the vxlan_device */
	zebra_evpn_mac_get_access_info(mac, &ifp, &vid);

	if (!ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"%s: dp-install sync-mac vni %u mac %s es %s 0x%x %sskipped, no access-port",
				caller, zevpn->vni,
				prefix_mac2str(&mac->macaddr, macbuf,
					       sizeof(macbuf)),
				mac->es ? mac->es->esi_str : "-", mac->flags,
				set_inactive ? "inactive " : "");
		return -1;
	}

	zif = ifp->info;
	br_ifp = zif->brslave_info.br_if;
	if (!br_ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"%s: dp-install sync-mac vni %u mac %s es %s 0x%x %sskipped, no br",
				caller, zevpn->vni,
				prefix_mac2str(&mac->macaddr, macbuf,
					       sizeof(macbuf)),
				mac->es ? mac->es->esi_str : "-", mac->flags,
				set_inactive ? "inactive " : "");
		return -1;
	}

	sticky = !!CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY);
	if (force_clear_static)
		set_static = false;
	else
		set_static = zebra_evpn_mac_is_static(mac);

	/* We can install a local mac that has been synced from the peer
	 * over the VxLAN-overlay/network-port if fast failover is not
	 * supported and if the local ES is oper-down.
	 */
	if (mac->es &&
		zebra_evpn_es_local_mac_via_network_port(mac->es)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("dp-%s sync-nw-mac vni %u mac %s es %s 0x%x %s",
					set_static ? "install" : "uninstall",
					zevpn->vni,
					prefix_mac2str(&mac->macaddr, macbuf,
						sizeof(macbuf)),
					mac->es ?
					mac->es->esi_str : "-", mac->flags,
					set_inactive ? "inactive " : "");
		if (set_static)
			/* XXX - old_static needs to be computed more
			 * accurately
			 */
			zebra_evpn_rem_mac_install(zevpn, mac,
					true /* old_static */);
		else
			zebra_evpn_rem_mac_uninstall(zevpn, mac,
					false /* force */);

		return 0;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug(
			"dp-install sync-mac vni %u mac %s es %s 0x%x %s%s",
			zevpn->vni,
			prefix_mac2str(&mac->macaddr, macbuf, sizeof(macbuf)),
			mac->es ? mac->es->esi_str : "-", mac->flags,
			set_static ? "static " : "",
			set_inactive ? "inactive " : "");

	dplane_local_mac_add(ifp, br_ifp, vid, &mac->macaddr, sticky,
			     set_static, set_inactive);
	return 0;
}

void zebra_evpn_mac_send_add_del_to_client(zebra_mac_t *mac, bool old_bgp_ready,
					   bool new_bgp_ready)
{
	if (new_bgp_ready)
		zebra_evpn_mac_send_add_to_client(mac->zevpn->vni,
						  &mac->macaddr, mac->flags,
						  mac->loc_seq, mac->es);
	else if (old_bgp_ready)
		zebra_evpn_mac_send_del_to_client(mac->zevpn->vni,
						  &mac->macaddr, mac->flags,
						  true /* force */);
}

/* MAC hold timer is used to age out peer-active flag.
 *
 * During this wait time we expect the dataplane component or an
 * external neighmgr daemon to probe existing hosts to independently
 * establish their presence on the ES.
 */
static int zebra_evpn_mac_hold_exp_cb(struct thread *t)
{
	zebra_mac_t *mac;
	bool old_bgp_ready;
	bool new_bgp_ready;
	bool old_static;
	bool new_static;
	char macbuf[ETHER_ADDR_STRLEN];

	mac = THREAD_ARG(t);
	/* the purpose of the hold timer is to age out the peer-active
	 * flag
	 */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
		return 0;

	old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	old_static = zebra_evpn_mac_is_static(mac);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE);
	new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	new_static = zebra_evpn_mac_is_static(mac);

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug(
			"sync-mac vni %u mac %s es %s 0x%x hold expired",
			mac->zevpn->vni,
			prefix_mac2str(&mac->macaddr, macbuf, sizeof(macbuf)),
			mac->es ? mac->es->esi_str : "-", mac->flags);

	/* re-program the local mac in the dataplane if the mac is no
	 * longer static
	 */
	if (old_static != new_static)
		zebra_evpn_sync_mac_dp_install(mac, false /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);

	/* inform bgp if needed */
	if (old_bgp_ready != new_bgp_ready)
		zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
						      new_bgp_ready);

	return 0;
}

static inline void zebra_evpn_mac_start_hold_timer(zebra_mac_t *mac)
{
	char macbuf[ETHER_ADDR_STRLEN];

	if (mac->hold_timer)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug(
			"sync-mac vni %u mac %s es %s 0x%x hold started",
			mac->zevpn->vni,
			prefix_mac2str(&mac->macaddr, macbuf, sizeof(macbuf)),
			mac->es ? mac->es->esi_str : "-", mac->flags);
	thread_add_timer(zrouter.master, zebra_evpn_mac_hold_exp_cb, mac,
			 zmh_info->mac_hold_time, &mac->hold_timer);
}

void zebra_evpn_mac_stop_hold_timer(zebra_mac_t *mac)
{
	char macbuf[ETHER_ADDR_STRLEN];

	if (!mac->hold_timer)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug(
			"sync-mac vni %u mac %s es %s 0x%x hold stopped",
			mac->zevpn->vni,
			prefix_mac2str(&mac->macaddr, macbuf, sizeof(macbuf)),
			mac->es ? mac->es->esi_str : "-", mac->flags);
	THREAD_OFF(mac->hold_timer);
}

void zebra_evpn_sync_mac_del(zebra_mac_t *mac)
{
	char macbuf[ETHER_ADDR_STRLEN];
	bool old_static;
	bool new_static;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug(
			"sync-mac del vni %u mac %s es %s seq %d f 0x%x",
			mac->zevpn->vni,
			prefix_mac2str(&mac->macaddr, macbuf, sizeof(macbuf)),
			mac->es ? mac->es->esi_str : "-", mac->loc_seq,
			mac->flags);
	old_static = zebra_evpn_mac_is_static(mac);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY);
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
		zebra_evpn_mac_start_hold_timer(mac);
	new_static = zebra_evpn_mac_is_static(mac);

	if (old_static != new_static)
		/* program the local mac in the kernel */
		zebra_evpn_sync_mac_dp_install(mac, false /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);
}

static inline bool zebra_evpn_mac_is_bgp_seq_ok(zebra_evpn_t *zevpn,
						zebra_mac_t *mac, uint32_t seq,
						uint16_t ipa_len,
						struct ipaddr *ipaddr)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	uint32_t tmp_seq;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		tmp_seq = mac->loc_seq;
	else
		tmp_seq = mac->rem_seq;

	if (seq < tmp_seq) {
		/* if the mac was never advertised to bgp we must accept
		 * whatever sequence number bgp sends
		 * XXX - check with Vivek
		 */
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
		    && !zebra_evpn_mac_is_ready_for_bgp(mac->flags)) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
				zlog_debug(
					"sync-macip accept vni %u mac %s%s%s lower seq %u f 0x%x",
					zevpn->vni,
					prefix_mac2str(&mac->macaddr, macbuf,
						       sizeof(macbuf)),
					ipa_len ? " IP " : "",
					ipa_len ? ipaddr2str(ipaddr, ipbuf,
							     sizeof(ipbuf))
						: "",
					tmp_seq, mac->flags);
			return true;
		}

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"sync-macip ignore vni %u mac %s%s%s as existing has higher seq %u f 0x%x",
				zevpn->vni,
				prefix_mac2str(&mac->macaddr, macbuf,
					       sizeof(macbuf)),
				ipa_len ? " IP " : "",
				ipa_len ? ipaddr2str(ipaddr, ipbuf,
						     sizeof(ipbuf))
					: "",
				tmp_seq, mac->flags);
		return false;
	}

	return true;
}

zebra_mac_t *
zebra_evpn_proc_sync_mac_update(zebra_evpn_t *zevpn, struct ethaddr *macaddr,
				uint16_t ipa_len, struct ipaddr *ipaddr,
				uint8_t flags, uint32_t seq, esi_t *esi,
				struct sync_mac_ip_ctx *ctx)
{
	zebra_mac_t *mac;
	bool inform_bgp = false;
	bool inform_dataplane = false;
	bool seq_change = false;
	bool es_change = false;
	uint32_t tmp_seq;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	bool old_local = false;
	bool old_bgp_ready;
	bool new_bgp_ready;

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		/* if it is a new local path we need to inform both
		 * the control protocol and the data-plane
		 */
		inform_bgp = true;
		inform_dataplane = true;
		ctx->mac_created = true;
		ctx->mac_inactive = true;

		/* create the MAC and associate it with the dest ES */
		mac = zebra_evpn_mac_add(zevpn, macaddr);
		zebra_evpn_es_mac_ref(mac, esi);

		/* local mac activated by an ES peer */
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
		/* if mac-only route setup peer flags */
		if (!ipa_len) {
			if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
				SET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY);
			else
				SET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE);
		}
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);
		old_bgp_ready = false;
		new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	} else {
		uint32_t old_flags;
		uint32_t new_flags;
		bool old_static;
		bool new_static;
		bool sticky;
		bool remote_gw;

		old_flags = mac->flags;
		sticky = !!CHECK_FLAG(old_flags, ZEBRA_MAC_STICKY);
		remote_gw = !!CHECK_FLAG(old_flags, ZEBRA_MAC_REMOTE_DEF_GW);
		if (sticky || remote_gw) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
				zlog_debug(
					"Ignore sync-macip vni %u mac %s%s%s%s%s",
					zevpn->vni,
					prefix_mac2str(macaddr, macbuf,
						       sizeof(macbuf)),
					ipa_len ? " IP " : "",
					ipa_len ? ipaddr2str(ipaddr, ipbuf,
							     sizeof(ipbuf))
						: "",
					sticky ? " sticky" : "",
					remote_gw ? " remote_gw" : "");
			ctx->ignore_macip = true;
			return NULL;
		}
		if (!zebra_evpn_mac_is_bgp_seq_ok(zevpn, mac, seq, ipa_len,
						  ipaddr)) {
			ctx->ignore_macip = true;
			return NULL;
		}

		old_local = !!CHECK_FLAG(old_flags, ZEBRA_MAC_LOCAL);
		old_static = zebra_evpn_mac_is_static(mac);

		/* re-build the mac flags */
		new_flags = 0;
		SET_FLAG(new_flags, ZEBRA_MAC_LOCAL);
		/* retain old local activity flag */
		if (old_flags & ZEBRA_MAC_LOCAL) {
			new_flags |= (old_flags & ZEBRA_MAC_LOCAL_INACTIVE);
		} else {
			new_flags |= ZEBRA_MAC_LOCAL_INACTIVE;
			ctx->mac_inactive = true;
		}
		if (ipa_len) {
			/* if mac-ip route do NOT update the peer flags
			 * i.e. retain only flags as is
			 */
			new_flags |= (old_flags & ZEBRA_MAC_ALL_PEER_FLAGS);
		} else {
			/* if mac-only route update peer flags */
			if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT)) {
				SET_FLAG(new_flags, ZEBRA_MAC_ES_PEER_PROXY);
				/* if the mac was peer-active previously we
				 * need to keep the flag and start the
				 * holdtimer on it. the peer-active flag is
				 * cleared on holdtimer expiry.
				 */
				if (CHECK_FLAG(old_flags,
					       ZEBRA_MAC_ES_PEER_ACTIVE)) {
					SET_FLAG(new_flags,
						 ZEBRA_MAC_ES_PEER_ACTIVE);
					zebra_evpn_mac_start_hold_timer(mac);
				}
			} else {
				SET_FLAG(new_flags, ZEBRA_MAC_ES_PEER_ACTIVE);
				/* stop hold timer if a peer has verified
				 * reachability
				 */
				zebra_evpn_mac_stop_hold_timer(mac);
			}
		}
		mac->rem_seq = 0;
		memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
		mac->flags = new_flags;

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC && (old_flags != new_flags))
			zlog_debug(
				"sync-mac vni %u mac %s old_f 0x%x new_f 0x%x",
				zevpn->vni,
				prefix_mac2str(macaddr, macbuf, sizeof(macbuf)),
				old_flags, mac->flags);

		/* update es */
		es_change = zebra_evpn_es_mac_ref(mac, esi);
		/* if mac dest change - inform both sides */
		if (es_change) {
			inform_bgp = true;
			inform_dataplane = true;
			ctx->mac_inactive = true;
		}
		/* if peer-flag is being set notify dataplane that the
		 * entry must not be expired because of local inactivity
		 */
		new_static = zebra_evpn_mac_is_static(mac);
		if (old_static != new_static)
			inform_dataplane = true;

		old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(old_flags);
		new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
		if (old_bgp_ready != new_bgp_ready)
			inform_bgp = true;
	}


	/* update sequence number; if that results in a new local sequence
	 * inform bgp
	 */
	tmp_seq = MAX(mac->loc_seq, seq);
	if (tmp_seq != mac->loc_seq) {
		mac->loc_seq = tmp_seq;
		seq_change = true;
		inform_bgp = true;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("sync-mac %s vni %u mac %s es %s seq %d f 0x%x%s%s",
			   ctx->mac_created ? "created" : "updated", zevpn->vni,
			   prefix_mac2str(macaddr, macbuf, sizeof(macbuf)),
			   mac->es ? mac->es->esi_str : "-", mac->loc_seq,
			   mac->flags, inform_bgp ? " inform_bgp" : "",
			   inform_dataplane ? " inform_dp" : "");

	if (inform_bgp)
		zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
						      new_bgp_ready);

	/* neighs using the mac may need to be re-sent to
	 * bgp with updated info
	 */
	if (seq_change || es_change || !old_local)
		zebra_evpn_process_neigh_on_local_mac_change(
			zevpn, mac, seq_change, es_change);

	if (inform_dataplane) {
		if (ipa_len)
			/* if the mac is being created as a part of MAC-IP
			 * route wait for the neigh to be updated or
			 * created before programming the mac
			 */
			ctx->mac_dp_update_deferred = true;
		else
			/* program the local mac in the kernel. when the ES
			 * change we need to force the dataplane to reset
			 * the activity as we are yet to establish activity
			 * locally
			 */
			zebra_evpn_sync_mac_dp_install(
				mac, ctx->mac_inactive,
				false /* force_clear_static */, __func__);
	}

	return mac;
}

/* update local fowarding info. return true if a dest-ES change
 * is detected
 */
static bool zebra_evpn_local_mac_update_fwd_info(zebra_mac_t *mac,
						 struct interface *ifp,
						 vlanid_t vid)
{
	struct zebra_if *zif = ifp->info;
	bool es_change;
	ns_id_t local_ns_id = NS_DEFAULT;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(ifp->vrf_id);
	if (zvrf && zvrf->zns)
		local_ns_id = zvrf->zns->ns_id;

	memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));

	es_change = zebra_evpn_es_mac_ref_entry(mac, zif->es_info.es);

	if (!mac->es) {
		/* if es is set fwd_info is not-relevant/taped-out */
		mac->fwd_info.local.ifindex = ifp->ifindex;
		mac->fwd_info.local.ns_id = local_ns_id;
		mac->fwd_info.local.vid = vid;
	}

	return es_change;
}

/* Notify Local MACs to the clienti, skips GW MAC */
static void zebra_evpn_send_mac_hash_entry_to_client(struct hash_bucket *bucket,
						     void *arg)
{
	struct mac_walk_ctx *wctx = arg;
	zebra_mac_t *zmac = bucket->data;

	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_DEF_GW))
		return;

	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_LOCAL))
		zebra_evpn_mac_send_add_to_client(wctx->zevpn->vni,
						  &zmac->macaddr, zmac->flags,
						  zmac->loc_seq, zmac->es);
}

/* Iterator to Notify Local MACs of a EVPN */
void zebra_evpn_send_mac_list_to_client(zebra_evpn_t *zevpn)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zevpn = zevpn;

	hash_iterate(zevpn->mac_table, zebra_evpn_send_mac_hash_entry_to_client,
		     &wctx);
}

void zebra_evpn_rem_mac_del(zebra_evpn_t *zevpn, zebra_mac_t *mac)
{
	zebra_evpn_process_neigh_on_remote_mac_del(zevpn, mac);
	/* the remote sequence number in the auto mac entry
	 * needs to be reset to 0 as the mac entry may have
	 * been removed on all VTEPs (including
	 * the originating one)
	 */
	mac->rem_seq = 0;

	/* If all remote neighbors referencing a remote MAC
	 * go away, we need to uninstall the MAC.
	 */
	if (remote_neigh_count(mac) == 0) {
		zebra_evpn_rem_mac_uninstall(zevpn, mac,
				false /*force*/);
		zebra_evpn_es_mac_deref_entry(mac);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
	}

	if (list_isempty(mac->neigh_list))
		zebra_evpn_mac_del(zevpn, mac);
	else
		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
}

/* Print Duplicate MAC */
void zebra_evpn_print_dad_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_mac_t *mac;

	mac = (zebra_mac_t *)bucket->data;
	if (!mac)
		return;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
		zebra_evpn_print_mac_hash(bucket, ctxt);
}

/* Print Duplicate MAC in detail */
void zebra_evpn_print_dad_mac_hash_detail(struct hash_bucket *bucket,
					  void *ctxt)
{
	zebra_mac_t *mac;

	mac = (zebra_mac_t *)bucket->data;
	if (!mac)
		return;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
		zebra_evpn_print_mac_hash_detail(bucket, ctxt);
}

int process_mac_remote_macip_add(zebra_evpn_t *zevpn, struct zebra_vrf *zvrf,
				 struct ethaddr *macaddr, uint16_t ipa_len,
				 struct ipaddr *ipaddr, zebra_mac_t **macp,
				 struct in_addr vtep_ip, uint8_t flags,
				 uint32_t seq, esi_t *esi)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	uint32_t tmp_seq;
	bool sticky;
	bool remote_gw;
	int update_mac = 0;
	bool do_dad = false;
	bool is_dup_detect = false;
	esi_t *old_esi;
	bool old_static = false;
	zebra_mac_t *mac;

	sticky = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	remote_gw = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);

	/* Ignore if the mac is already present as a gateway mac */
	if (mac && CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW)
	    && CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Ignore remote MACIP ADD VNI %u MAC %s%s%s as MAC is already configured as gateway MAC",
				zevpn->vni,
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ipa_len ? " IP " : "",
				ipa_len ? ipaddr2str(ipaddr, buf1, sizeof(buf1))
					: "");
		return -1;
	}

	old_esi = (mac && mac->es) ? &mac->es->esi : zero_esi;

	/* check if the remote MAC is unknown or has a change.
	 * If so, that needs to be updated first. Note that client could
	 * install MAC and MACIP separately or just install the latter.
	 */
	if (!mac || !CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
	    || sticky != !!CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)
	    || remote_gw != !!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW)
	    || !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &vtep_ip)
	    || memcmp(old_esi, esi, sizeof(esi_t)) || seq != mac->rem_seq)
		update_mac = 1;

	if (update_mac) {
		if (!mac) {
			mac = zebra_evpn_mac_add(zevpn, macaddr);
			if (!mac) {
				zlog_warn(
					"Failed to add MAC %s VNI %u Remote VTEP %s",
					prefix_mac2str(macaddr, buf,
						       sizeof(buf)),
					zevpn->vni, inet_ntoa(vtep_ip));
				return -1;
			}

			zebra_evpn_es_mac_ref(mac, esi);

			/* Is this MAC created for a MACIP? */
			if (ipa_len)
				SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
		} else {
			zebra_evpn_es_mac_ref(mac, esi);

			/* When host moves but changes its (MAC,IP)
			 * binding, BGP may install a MACIP entry that
			 * corresponds to "older" location of the host
			 * in transient situations (because {IP1,M1}
			 * is a different route from {IP1,M2}). Check
			 * the sequence number and ignore this update
			 * if appropriate.
			 */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
				tmp_seq = mac->loc_seq;
			else
				tmp_seq = mac->rem_seq;

			if (seq < tmp_seq) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"Ignore remote MACIP ADD VNI %u MAC %s%s%s as existing MAC has higher seq %u flags 0x%x",
						zevpn->vni,
						prefix_mac2str(macaddr, buf,
							       sizeof(buf)),
						ipa_len ? " IP " : "",
						ipa_len ? ipaddr2str(
								  ipaddr, buf1,
								  sizeof(buf1))
							: "",
						tmp_seq, mac->flags);
				return -1;
			}
		}

		/* Check MAC's curent state is local (this is the case
		 * where MAC has moved from L->R) and check previous
		 * detection started via local learning.
		 * RFC-7432: A PE/VTEP that detects a MAC mobility
		 * event via local learning starts an M-second timer.
		 *
		 * VTEP-IP or seq. change alone is not considered
		 * for dup. detection.
		 *
		 * MAC is already marked duplicate set dad, then
		 * is_dup_detect will be set to not install the entry.
		 */
		if ((!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
		     && mac->dad_count)
		    || CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
			do_dad = true;

		/* Remove local MAC from BGP. */
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			/* force drop the sync flags */
			old_static = zebra_evpn_mac_is_static(mac);
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
				zlog_debug(
					"sync-mac->remote vni %u mac %s es %s seq %d f 0x%x",
					zevpn->vni,
					prefix_mac2str(macaddr, buf,
						       sizeof(buf)),
					mac->es ? mac->es->esi_str : "-",
					mac->loc_seq, mac->flags);
			zebra_evpn_mac_clear_sync_info(mac);
			zebra_evpn_mac_send_del_to_client(zevpn->vni, macaddr,
							  mac->flags,
							  false /* force */);
		}

		/* Set "auto" and "remote" forwarding info. */
		UNSET_FLAG(mac->flags, ZEBRA_MAC_ALL_LOCAL_FLAGS);
		memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
		SET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
		mac->fwd_info.r_vtep_ip = vtep_ip;

		if (sticky)
			SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
		else
			UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);

		if (remote_gw)
			SET_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW);
		else
			UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW);

		zebra_evpn_dup_addr_detect_for_mac(
			zvrf, mac, mac->fwd_info.r_vtep_ip, do_dad,
			&is_dup_detect, false);

		if (!is_dup_detect) {
			zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);
			/* Install the entry. */
			zebra_evpn_rem_mac_install(zevpn, mac, old_static);
		}
	}

	/* Update seq number. */
	mac->rem_seq = seq;

	/* If there is no IP, return after clearing AUTO flag of MAC. */
	if (!ipa_len) {
		UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
		return -1;
	}
	*macp = mac;
	return 0;
}

int zebra_evpn_add_update_local_mac(struct zebra_vrf *zvrf, zebra_evpn_t *zevpn,
				    struct interface *ifp,
				    struct ethaddr *macaddr, vlanid_t vid,
				    bool sticky, bool local_inactive,
				    bool dp_static)
{
	zebra_mac_t *mac;
	char buf[ETHER_ADDR_STRLEN];
	bool mac_sticky = false;
	bool inform_client = false;
	bool upd_neigh = false;
	bool is_dup_detect = false;
	struct in_addr vtep_ip = {.s_addr = 0};
	bool es_change = false;
	bool new_bgp_ready;
	/* assume inactive if not present or if not local */
	bool old_local_inactive = true;
	bool old_bgp_ready = false;
	bool inform_dataplane = false;
	bool new_static = false;

	/* Check if we need to create or update or it is a NO-OP. */
	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"ADD %sMAC %s intf %s(%u) VID %u -> VNI %u%s",
				sticky ? "sticky " : "",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, vid, zevpn->vni,
				local_inactive ? " local-inactive" : "");

		mac = zebra_evpn_mac_add(zevpn, macaddr);
		if (!mac) {
			flog_err(
				EC_ZEBRA_MAC_ADD_FAILED,
				"Failed to add MAC %s intf %s(%u) VID %u VNI %u",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, vid, zevpn->vni);
			return -1;
		}
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
		es_change = zebra_evpn_local_mac_update_fwd_info(mac, ifp, vid);
		if (sticky)
			SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
		inform_client = true;
	} else {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"UPD %sMAC %s intf %s(%u) VID %u -> VNI %u %scurFlags 0x%x",
				sticky ? "sticky " : "",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, vid, zevpn->vni,
				local_inactive ? "local-inactive " : "",
				mac->flags);

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			struct interface *old_ifp;
			vlanid_t old_vid;
			bool old_static;

			zebra_evpn_mac_get_access_info(mac, &old_ifp, &old_vid);
			old_bgp_ready =
				zebra_evpn_mac_is_ready_for_bgp(mac->flags);
			old_local_inactive =
				!!(mac->flags & ZEBRA_MAC_LOCAL_INACTIVE);
			old_static = zebra_evpn_mac_is_static(mac);
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
				mac_sticky = true;

			/*
			 * Update any changes and if changes are relevant to
			 * BGP, note it.
			 */
			if (mac_sticky == sticky && old_ifp == ifp
			    && old_vid == vid
			    && old_local_inactive == local_inactive
			    && dp_static == old_static) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"        Add/Update %sMAC %s intf %s(%u) VID %u -> VNI %u%s, "
						"entry exists and has not changed ",
						sticky ? "sticky " : "",
						prefix_mac2str(macaddr, buf,
							       sizeof(buf)),
						ifp->name, ifp->ifindex, vid,
						zevpn->vni,
						local_inactive
							? " local_inactive"
							: "");
				return 0;
			}
			if (mac_sticky != sticky) {
				if (sticky)
					SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
				else
					UNSET_FLAG(mac->flags,
						   ZEBRA_MAC_STICKY);
				inform_client = true;
			}

			es_change = zebra_evpn_local_mac_update_fwd_info(
				mac, ifp, vid);
			/* If an es_change is detected we need to advertise
			 * the route with a sequence that is one
			 * greater. This is need to indicate a mac-move
			 * to the ES peers
			 */
			if (es_change) {
				mac->loc_seq = mac->loc_seq + 1;
				/* force drop the peer/sync info as it is
				 * simply no longer relevant
				 */
				if (CHECK_FLAG(mac->flags,
					       ZEBRA_MAC_ALL_PEER_FLAGS)) {
					zebra_evpn_mac_clear_sync_info(mac);
					new_static =
						zebra_evpn_mac_is_static(mac);
					/* if we clear peer-flags we
					 * also need to notify the dataplane
					 * to drop the static flag
					 */
					if (old_static != new_static)
						inform_dataplane = true;
				}
			}
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)
			   || CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)) {
			bool do_dad = false;

			/*
			 * MAC has either moved or was "internally" created due
			 * to a neighbor learn and is now actually learnt. If
			 * it was learnt as a remote sticky MAC, this is an
			 * operator error.
			 */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)) {
				flog_warn(
					EC_ZEBRA_STICKY_MAC_ALREADY_LEARNT,
					"MAC %s already learnt as remote sticky MAC behind VTEP %s VNI %u",
					prefix_mac2str(macaddr, buf,
						       sizeof(buf)),
					inet_ntoa(mac->fwd_info.r_vtep_ip),
					zevpn->vni);
				return 0;
			}

			/* If an actual move, compute MAC's seq number */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
				mac->loc_seq =
					MAX(mac->rem_seq + 1, mac->loc_seq);
				vtep_ip = mac->fwd_info.r_vtep_ip;
				/* Trigger DAD for remote MAC */
				do_dad = true;
			}

			UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
			UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
			es_change = zebra_evpn_local_mac_update_fwd_info(
				mac, ifp, vid);
			if (sticky)
				SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
			else
				UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
			/*
			 * We have to inform BGP of this MAC as well as process
			 * all neighbors.
			 */
			inform_client = true;
			upd_neigh = true;

			zebra_evpn_dup_addr_detect_for_mac(
				zvrf, mac, vtep_ip, do_dad, &is_dup_detect,
				true);
			if (is_dup_detect) {
				inform_client = false;
				upd_neigh = false;
				es_change = false;
			}
		}
	}

	/* if the dataplane thinks the entry is sync but it is
	 * not sync in zebra we need to re-install to fixup
	 */
	if (dp_static) {
		new_static = zebra_evpn_mac_is_static(mac);
		if (!new_static)
			inform_dataplane = true;
	}

	if (local_inactive)
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);
	else
		UNSET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);

	new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	/* if local-activity has changed we need update bgp
	 * even if bgp already knows about the mac
	 */
	if ((old_local_inactive != local_inactive)
	    || (new_bgp_ready != old_bgp_ready)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"local mac vni %u mac %s es %s seq %d f 0x%x%s",
				zevpn->vni,
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				mac->es ? mac->es->esi_str : "", mac->loc_seq,
				mac->flags,
				local_inactive ? " local-inactive" : "");
		if (!is_dup_detect)
			inform_client = true;
	}

	if (es_change) {
		inform_client = true;
		upd_neigh = true;
	}

	/* Inform dataplane if required. */
	if (inform_dataplane)
		zebra_evpn_sync_mac_dp_install(mac, false /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);

	/* Inform BGP if required. */
	if (inform_client)
		zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
						      new_bgp_ready);

	/* Process all neighbors associated with this MAC, if required. */
	if (upd_neigh)
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac, 0,
							     es_change);

	return 0;
}

int zebra_evpn_del_local_mac(zebra_evpn_t *zevpn, zebra_mac_t *mac)
{
	char buf[ETHER_ADDR_STRLEN];
	bool old_bgp_ready;
	bool new_bgp_ready;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("DEL MAC %s VNI %u seq %u flags 0x%x nbr count %u",
			   prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
			   zevpn->vni, mac->loc_seq, mac->flags,
			   listcount(mac->neigh_list));

	old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	if (zebra_evpn_mac_is_static(mac)) {
		/* this is a synced entry and can only be removed when the
		 * es-peers stop advertising it.
		 */
		memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"re-add sync-mac vni %u mac %s es %s seq %d f 0x%x",
				zevpn->vni,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				mac->es ? mac->es->esi_str : "-", mac->loc_seq,
				mac->flags);

		/* inform-bgp about change in local-activity if any */
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE)) {
			SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);
			new_bgp_ready =
				zebra_evpn_mac_is_ready_for_bgp(mac->flags);
			zebra_evpn_mac_send_add_del_to_client(
				mac, old_bgp_ready, new_bgp_ready);
		}

		/* re-install the inactive entry in the kernel */
		zebra_evpn_sync_mac_dp_install(mac, true /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);

		return 0;
	}

	/* Update all the neigh entries associated with this mac */
	zebra_evpn_process_neigh_on_local_mac_del(zevpn, mac);

	/* Remove MAC from BGP. */
	zebra_evpn_mac_send_del_to_client(zevpn->vni, &mac->macaddr, mac->flags,
					  false /* force */);

	zebra_evpn_es_mac_deref_entry(mac);

	/*
	 * If there are no neigh associated with the mac delete the mac
	 * else mark it as AUTO for forward reference
	 */
	if (!listcount(mac->neigh_list)) {
		zebra_evpn_mac_del(zevpn, mac);
	} else {
		UNSET_FLAG(mac->flags, ZEBRA_MAC_ALL_LOCAL_FLAGS);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	}

	return 0;
}

int zebra_evpn_mac_gw_macip_add(struct interface *ifp, zebra_evpn_t *zevpn,
				struct ipaddr *ip, zebra_mac_t **macp,
				struct ethaddr *macaddr, vlanid_t vlan_id)
{
	char buf[ETHER_ADDR_STRLEN];
	zebra_mac_t *mac;
	ns_id_t local_ns_id = NS_DEFAULT;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(ifp->vrf_id);
	if (zvrf && zvrf->zns)
		local_ns_id = zvrf->zns->ns_id;

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		mac = zebra_evpn_mac_add(zevpn, macaddr);
		if (!mac) {
			flog_err(EC_ZEBRA_MAC_ADD_FAILED,
				 "Failed to add MAC %s intf %s(%u) VID %u",
				 prefix_mac2str(macaddr, buf, sizeof(buf)),
				 ifp->name, ifp->ifindex, vlan_id);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
	SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	SET_FLAG(mac->flags, ZEBRA_MAC_DEF_GW);
	memset(&mac->fwd_info, 0, sizeof(mac->fwd_info));
	mac->fwd_info.local.ifindex = ifp->ifindex;
	mac->fwd_info.local.ns_id = local_ns_id;
	mac->fwd_info.local.vid = vlan_id;

	*macp = mac;

	return 0;
}
