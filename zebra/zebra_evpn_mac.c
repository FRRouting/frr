// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "hash.h"
#include "interface.h"
#include "jhash.h"
#include "memory.h"
#include "prefix.h"
#include "vlan.h"
#include "json.h"
#include "printfrr.h"

#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"

DEFINE_MTYPE_STATIC(ZEBRA, MAC, "EVPN MAC");

/*
 * Return number of valid MACs in an EVPN's MAC hash table - all
 * remote MACs and non-internal (auto) local MACs count.
 */
uint32_t num_valid_macs(struct zebra_evpn *zevpn)
{
	unsigned int i;
	uint32_t num_macs = 0;
	struct hash *hash;
	struct hash_bucket *hb;
	struct zebra_mac *mac;

	hash = zevpn->mac_table;
	if (!hash)
		return num_macs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			mac = (struct zebra_mac *)hb->data;
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) ||
			    CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL) ||
			    !CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
				num_macs++;
		}
	}

	return num_macs;
}

uint32_t num_dup_detected_macs(struct zebra_evpn *zevpn)
{
	unsigned int i;
	uint32_t num_macs = 0;
	struct hash *hash;
	struct hash_bucket *hb;
	struct zebra_mac *mac;

	hash = zevpn->mac_table;
	if (!hash)
		return num_macs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			mac = (struct zebra_mac *)hb->data;
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
				num_macs++;
		}
	}

	return num_macs;
}

/* Setup mac_list against the access port. This is done when a mac uses
 * the ifp as destination for the first time
 */
static void zebra_evpn_mac_ifp_new(struct zebra_if *zif)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("MAC list created for ifp %s (%u)", zif->ifp->name,
			   zif->ifp->ifindex);

	zif->mac_list = list_new();
	listset_app_node_mem(zif->mac_list);
}

/* Unlink local mac from a destination access port */
static void zebra_evpn_mac_ifp_unlink(struct zebra_mac *zmac)
{
	struct zebra_if *zif;
	struct interface *ifp = zmac->ifp;

	if (!ifp)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("VNI %d MAC %pEA unlinked from ifp %s (%u)",
			   zmac->zevpn->vni, &zmac->macaddr, ifp->name,
			   ifp->ifindex);

	zif = ifp->info;
	list_delete_node(zif->mac_list, &zmac->ifp_listnode);
	zmac->ifp = NULL;
}

/* Free up the mac_list if any as a part of the interface del/cleanup */
void zebra_evpn_mac_ifp_del(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct listnode *node;
	struct zebra_mac *zmac;

	if (!zif->mac_list)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("MAC list deleted for ifp %s (%u)", zif->ifp->name,
			   zif->ifp->ifindex);

	for (ALL_LIST_ELEMENTS_RO(zif->mac_list, node, zmac))
		zebra_evpn_mac_ifp_unlink(zmac);

	list_delete(&zif->mac_list);
}

/* Link local mac to destination access port. This is done only if the
 * local mac is associated with a zero ESI i.e. single attach or lacp-bypass
 * bridge port member
 */
static void zebra_evpn_mac_ifp_link(struct zebra_mac *zmac,
				    struct interface *ifp)
{
	struct zebra_if *zif;

	if (!CHECK_FLAG(zmac->flags, ZEBRA_MAC_LOCAL))
		return;

	/* already linked to the destination */
	if (zmac->ifp == ifp)
		return;

	/* unlink the mac from any old destination */
	if (zmac->ifp)
		zebra_evpn_mac_ifp_unlink(zmac);

	if (!ifp)
		return;

	zif = ifp->info;
	/* the interface mac_list is created on first mac link attempt */
	if (!zif->mac_list)
		zebra_evpn_mac_ifp_new(zif);

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		zlog_debug("VNI %d MAC %pEA linked to ifp %s (%u)",
			   zmac->zevpn->vni, &zmac->macaddr, ifp->name,
			   ifp->ifindex);

	zmac->ifp = ifp;
	listnode_init(&zmac->ifp_listnode, zmac);
	listnode_add(zif->mac_list, &zmac->ifp_listnode);
}

/* If the mac is a local mac clear links to destination access port */
void zebra_evpn_mac_clear_fwd_info(struct zebra_mac *zmac)
{
	zebra_evpn_mac_ifp_unlink(zmac);
	memset(&zmac->fwd_info, 0, sizeof(zmac->fwd_info));
}

/*
 * Install remote MAC into the forwarding plane.
 */
int zebra_evpn_rem_mac_install(struct zebra_evpn *zevpn, struct zebra_mac *mac,
			       bool was_static)
{
	const struct zebra_if *zif, *br_zif;
	const struct zebra_vxlan_vni *vni;
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

	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return -1;

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
		vid = vni->access_vlan;
	else
		vid = 0;

	res = dplane_rem_mac_add(zevpn->vxlan_if, br_ifp, vid, &mac->macaddr,
				 vni->vni, vtep_ip, sticky, nhg_id, was_static);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/*
 * Uninstall remote MAC from the forwarding plane.
 */
int zebra_evpn_rem_mac_uninstall(struct zebra_evpn *zevpn,
				 struct zebra_mac *mac, bool force)
{
	const struct zebra_if *zif, *br_zif;
	struct zebra_vxlan_vni *vni;
	struct in_addr vtep_ip;
	const struct interface *ifp, *br_ifp;
	vlanid_t vid;
	enum zebra_dplane_result res;

	/* If the MAC was not installed there is no need to uninstall it */
	if (!force && mac->es &&
	    !CHECK_FLAG(mac->es->flags, ZEBRA_EVPNES_NHG_ACTIVE))
		return -1;

	if (!zevpn->vxlan_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VNI %u hash %p couldn't be uninstalled - no intf",
				   zevpn->vni, zevpn);
		return -1;
	}

	zif = zevpn->vxlan_if->info;
	if (!zif)
		return -1;

	br_ifp = zif->brslave_info.br_if;
	if (br_ifp == NULL)
		return -1;

	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return -1;

	br_zif = (const struct zebra_if *)br_ifp->info;

	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		vid = vni->access_vlan;
	else
		vid = 0;

	ifp = zevpn->vxlan_if;
	vtep_ip = mac->fwd_info.r_vtep_ip;

	res = dplane_rem_mac_del(ifp, br_ifp, vid, &mac->macaddr, vni->vni,
				 vtep_ip);
	if (res != ZEBRA_DPLANE_REQUEST_FAILURE)
		return 0;
	else
		return -1;
}

/*
 * Decrement neighbor refcount of MAC; uninstall and free it if
 * appropriate.
 */
void zebra_evpn_deref_ip2mac(struct zebra_evpn *zevpn, struct zebra_mac *mac)
{
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
		return;

	/* If all remote neighbors referencing a remote MAC go away,
	 * we need to uninstall the MAC.
	 */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) &&
	    remote_neigh_count(mac) == 0) {
		zebra_evpn_rem_mac_uninstall(zevpn, mac, false);
		zebra_evpn_es_mac_deref_entry(mac);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
	}

	/* If no references, delete the MAC. */
	if (!zebra_evpn_mac_in_use(mac))
		zebra_evpn_mac_del(zevpn, mac);
}

static void zebra_evpn_mac_get_access_info(struct zebra_mac *mac,
					   struct interface **p_ifp,
					   vlanid_t *vid)
{
	struct zebra_vxlan_vni *vni;

	/* if the mac is associated with an ES we must get the access
	 * info from the ES
	 */
	if (mac->es) {
		struct zebra_if *zif;

		/* get the access port from the es */
		*p_ifp = mac->es->zif ? mac->es->zif->ifp : NULL;
		/* get the vlan from the EVPN */
		if (mac->zevpn->vxlan_if) {
			zif = mac->zevpn->vxlan_if->info;
			vni = zebra_vxlan_if_vni_find(zif, mac->zevpn->vni);
			*vid = vni->access_vlan;
		} else {
			*vid = 0;
		}
	} else {
		struct zebra_ns *zns;

		*vid = mac->fwd_info.local.vid;
		zns = zebra_ns_lookup(mac->fwd_info.local.ns_id);
		*p_ifp = if_lookup_by_index_per_ns(zns,
						   mac->fwd_info.local.ifindex);
	}
}

#define MAC_BUF_SIZE 256
static char *zebra_evpn_zebra_mac_flag_dump(struct zebra_mac *mac, char *buf,
					    size_t len)
{
	if (mac->flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(buf, len, "%s%s%s%s%s%s%s%s%s%s%s%s",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL) ? "LOC " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) ? "REM " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO) ? "AUTO " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ? "STICKY " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_RMAC) ? "REM Router "
								 : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW) ? "Default GW " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW)
			   ? "REM DEF GW "
			   : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE) ? "DUP " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_FPM_SENT) ? "FPM " : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE)
			   ? "PEER Active "
			   : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY) ? "PROXY "
								   : "",
		   CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE)
			   ? "LOC Inactive "
			   : "");
	return buf;
}

static void zebra_evpn_dad_mac_auto_recovery_exp(struct event *t)
{
	struct zebra_vrf *zvrf = NULL;
	struct zebra_mac *mac = NULL;
	struct zebra_evpn *zevpn = NULL;
	struct listnode *node = NULL;
	struct zebra_neigh *nbr = NULL;

	mac = EVENT_ARG(t);

	/* since this is asynchronous we need sanity checks*/
	zvrf = zebra_vrf_lookup_by_id(mac->zevpn->vrf_id);
	if (!zvrf)
		return;

	zevpn = zebra_evpn_lookup(mac->zevpn->vni);
	if (!zevpn)
		return;

	mac = zebra_evpn_mac_lookup(zevpn, &mac->macaddr);
	if (!mac)
		return;

	if (IS_ZEBRA_DEBUG_VXLAN) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("%s: duplicate addr mac %pEA flags %slearn count %u host count %u auto recovery expired",
			   __func__, &mac->macaddr,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)),
			   mac->dad_count, listcount(mac->neigh_list));
	}

	/* Remove all IPs as duplicate associcated with this MAC */
	for (ALL_LIST_ELEMENTS_RO(mac->neigh_list, node, nbr)) {
		if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
			if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL))
				ZEBRA_NEIGH_SET_INACTIVE(nbr);
			else if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE))
				zebra_evpn_rem_neigh_install(zevpn, nbr, false);
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
			return;

		/* Process all neighbors associated with this MAC. */
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac, 0, 0);

	} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
		zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);

		/* Install the entry. */
		zebra_evpn_rem_mac_install(zevpn, mac, false /* was_static */);
	}
}

static void zebra_evpn_dup_addr_detect_for_mac(struct zebra_vrf *zvrf,
					       struct zebra_mac *mac,
					       struct in_addr vtep_ip,
					       bool do_dad, bool *is_dup_detect,
					       bool is_local)
{
	struct zebra_neigh *nbr;
	struct listnode *node = NULL;
	struct timeval elapsed = { 0, 0 };
	bool reset_params = false;

	if (!(zebra_evpn_do_dup_addr_detect(zvrf) && do_dad))
		return;

	/* MAC is detected as duplicate,
	 * Local MAC event -> hold on advertising to BGP.
	 * Remote MAC event -> hold on installing it.
	 */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)) {
		if (IS_ZEBRA_DEBUG_VXLAN) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("%s: duplicate addr MAC %pEA flags %sskip update to client, learn count %u recover time %u",
				   __func__, &mac->macaddr,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   mac->dad_count, zvrf->dad_freeze_time);
		}
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
		if (IS_ZEBRA_DEBUG_VXLAN) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("%s: duplicate addr MAC %pEA flags %sdetection time passed, reset learn count %u",
				   __func__, &mac->macaddr,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   mac->dad_count);
		}

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
			  "VNI %u: MAC %pEA detected as duplicate during %s VTEP %pI4",
			  mac->zevpn->vni, &mac->macaddr,
			  is_local ? "local update, last"
				   : "remote update, from",
			  &vtep_ip);

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
				  "VNI %u: MAC %pEA IP %pIA detected as duplicate during %s update, inherit duplicate from MAC",
				  mac->zevpn->vni, &mac->macaddr, &nbr->ip,
				  is_local ? "local" : "remote");
		}

		/* Start auto recovery timer for this MAC */
		EVENT_OFF(mac->dad_mac_auto_recovery_timer);
		if (zvrf->dad_freeze && zvrf->dad_freeze_time) {
			if (IS_ZEBRA_DEBUG_VXLAN) {
				char mac_buf[MAC_BUF_SIZE];

				zlog_debug("%s: duplicate addr MAC %pEA flags %sauto recovery time %u start",
					   __func__, &mac->macaddr,
					   zebra_evpn_zebra_mac_flag_dump(
						   mac, mac_buf,
						   sizeof(mac_buf)),
					   zvrf->dad_freeze_time);
			}

			event_add_timer(zrouter.master,
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
void zebra_evpn_print_mac(struct zebra_mac *mac, void *ctxt, json_object *json)
{
	struct vty *vty;
	struct zebra_neigh *n = NULL;
	struct listnode *node = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct zebra_vrf *zvrf;
	struct timeval detect_start_time = { 0, 0 };
	char timebuf[MONOTIME_STRLEN];
	char thread_buf[EVENT_TIMER_STRLEN];
	time_t uptime;
	char up_str[MONOTIME_STRLEN];

	zvrf = zebra_vrf_get_evpn();
	vty = (struct vty *)ctxt;
	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	uptime = monotime(NULL);
	uptime -= mac->uptime;

	frrtime_to_interval(uptime, up_str, sizeof(up_str));

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
			if (mac->es)
				json_object_string_add(json_mac, "remoteEs",
						       mac->es->esi_str);
			else
				json_object_string_addf(json_mac, "remoteVtep",
							"%pI4",
							&mac->fwd_info.r_vtep_ip);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO))
			json_object_string_add(json_mac, "type", "auto");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
			json_object_boolean_true_add(json_mac, "stickyMac");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_SVI))
			json_object_boolean_true_add(json_mac, "sviMac");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW))
			json_object_boolean_true_add(json_mac, "defaultGateway");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW))
			json_object_boolean_true_add(json_mac,
						     "remoteGatewayMac");

		json_object_string_add(json_mac, "uptime", up_str);
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
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      mac->hold_timer));
		if (mac->es)
			json_object_string_add(json_mac, "esi",
					       mac->es->esi_str);
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
							ipaddr2str(&n->ip, buf2,
								   sizeof(buf2))));
				else
					json_object_array_add(
						json_inactive_nbrs,
						json_object_new_string(
							ipaddr2str(&n->ip, buf2,
								   sizeof(buf2))));
			}

			json_object_object_add(json_nbrs, "active",
					       json_active_nbrs);
			json_object_object_add(json_nbrs, "inactive",
					       json_inactive_nbrs);
			json_object_object_add(json_mac, "neighbors", json_nbrs);
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
				vty_out(vty, " Remote ES: %s", mac->es->esi_str);
			else
				vty_out(vty, " Remote VTEP: %pI4",
					&mac->fwd_info.r_vtep_ip);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)) {
			vty_out(vty, " Auto Mac ");
		}

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
			vty_out(vty, " Sticky Mac ");

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_SVI))
			vty_out(vty, " SVI-Mac ");

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
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      mac->hold_timer));
		vty_out(vty, "\n");
		vty_out(vty, " Local Seq: %u Remote Seq: %u\n", mac->loc_seq,
			mac->rem_seq);
		vty_out(vty, " Uptime: %s\n", up_str);

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
					(IS_ZEBRA_NEIGH_ACTIVE(n) ? "Active"
								  : "Inactive"));
			}
		}

		vty_out(vty, "\n");
	}
}

static char *zebra_evpn_print_mac_flags(struct zebra_mac *mac, char *flags_buf,
					size_t flags_buf_sz)
{
	snprintf(flags_buf, flags_buf_sz, "%s%s%s%s",
		 mac->sync_neigh_cnt ? "N" : "",
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE) ? "P" : "",
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY) ? "X" : "",
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE) ? "I" : "");

	return flags_buf;
}

/*
 * Print MAC hash entry - called for display of all MACs.
 */
void zebra_evpn_print_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json_mac_hdr = NULL, *json_mac = NULL;
	struct zebra_mac *mac;
	char buf1[ETHER_ADDR_STRLEN];
	char addr_buf[PREFIX_STRLEN];
	struct mac_walk_ctx *wctx = ctxt;
	char flags_buf[6];

	vty = wctx->vty;
	json_mac_hdr = wctx->json;
	mac = (struct zebra_mac *)bucket->data;

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
				zebra_evpn_print_mac_flags(mac, flags_buf,
							   sizeof(flags_buf)),
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
		if (CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP) &&
		    !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &wctx->r_vtep_ip))
			return;

		if (json_mac_hdr == NULL) {
			if (CHECK_FLAG(wctx->flags, SHOW_REMOTE_MAC_FROM_VTEP) &&
			    (wctx->count == 0)) {
				vty_out(vty, "\nVNI %u\n\n", wctx->zevpn->vni);
				vty_out(vty, "%-17s %-6s %-5s%-30s %-5s %s\n",
					"MAC", "Type", "Flags",
					"Intf/Remote ES/VTEP", "VLAN",
					"Seq #'s");
			}
			if (mac->es == NULL)
				inet_ntop(AF_INET, &mac->fwd_info.r_vtep_ip,
					  addr_buf, sizeof(addr_buf));

			vty_out(vty, "%-17s %-6s %-5s %-30s %-5s %u/%u\n", buf1,
				"remote",
				zebra_evpn_print_mac_flags(mac, flags_buf,
							   sizeof(flags_buf)),
				mac->es ? mac->es->esi_str : addr_buf, "",
				mac->loc_seq, mac->rem_seq);
		} else {
			json_object_string_add(json_mac, "type", "remote");
			if (mac->es)
				json_object_string_add(json_mac, "remoteEs",
						       mac->es->esi_str);
			else
				json_object_string_addf(json_mac, "remoteVtep",
							"%pI4",
							&mac->fwd_info.r_vtep_ip);
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
	struct zebra_mac *mac;
	struct mac_walk_ctx *wctx = ctxt;
	char buf1[ETHER_ADDR_STRLEN];

	vty = wctx->vty;
	json_mac_hdr = wctx->json;
	mac = (struct zebra_mac *)bucket->data;
	if (!mac)
		return;

	wctx->count++;
	prefix_mac2str(&mac->macaddr, buf1, sizeof(buf1));

	zebra_evpn_print_mac(mac, vty, json_mac_hdr);
}

/*
 * Inform BGP about local MACIP.
 */
int zebra_evpn_macip_send_msg_to_client(vni_t vni, const struct ethaddr *macaddr,
					const struct ipaddr *ip, uint8_t flags,
					uint32_t seq, int state,
					struct zebra_evpn_es *es, uint16_t cmd)
{
	int ipa_len;
	struct zserv *client = NULL;
	struct stream *s = NULL;
	esi_t *esi = es ? &es->esi : zero_esi;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

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

	if (IS_ZEBRA_DEBUG_VXLAN) {
		char flag_buf[MACIP_BUF_SIZE];

		zlog_debug("Send MACIP %s f %s state %u MAC %pEA IP %pIA seq %u L2-VNI %u ESI %s to %s",
			   (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			   zclient_evpn_dump_macip_flags(flags, flag_buf,
							 sizeof(flag_buf)),
			   state, macaddr, ip, seq, vni, es ? es->esi_str : "-",
			   zebra_route_string(client->proto));
	}

	if (cmd == ZEBRA_MACIP_ADD)
		client->macipadd_cnt++;
	else
		client->macipdel_cnt++;

	return zserv_send_message(client, s);
}

static unsigned int mac_hash_keymake(const void *p)
{
	const struct zebra_mac *pmac = p;
	const void *pnt = (void *)pmac->macaddr.octet;

	return jhash(pnt, ETH_ALEN, 0xa5a5a55a);
}

/*
 * Compare two MAC addresses.
 */
static bool mac_cmp(const void *p1, const void *p2)
{
	const struct zebra_mac *pmac1 = p1;
	const struct zebra_mac *pmac2 = p2;

	if (pmac1 == NULL && pmac2 == NULL)
		return true;

	if (pmac1 == NULL || pmac2 == NULL)
		return false;

	return (memcmp(pmac1->macaddr.octet, pmac2->macaddr.octet, ETH_ALEN) ==
		0);
}

/*
 * Callback to allocate MAC hash entry.
 */
static void *zebra_evpn_mac_alloc(void *p)
{
	const struct zebra_mac *tmp_mac = p;
	struct zebra_mac *mac;

	mac = XCALLOC(MTYPE_MAC, sizeof(struct zebra_mac));
	*mac = *tmp_mac;

	return ((void *)mac);
}

/*
 * Add MAC entry.
 */
struct zebra_mac *zebra_evpn_mac_add(struct zebra_evpn *zevpn,
				     const struct ethaddr *macaddr)
{
	struct zebra_mac tmp_mac;
	struct zebra_mac *mac = NULL;

	memset(&tmp_mac, 0, sizeof(tmp_mac));
	memcpy(&tmp_mac.macaddr, macaddr, ETH_ALEN);
	mac = hash_get(zevpn->mac_table, &tmp_mac, zebra_evpn_mac_alloc);

	mac->zevpn = zevpn;
	mac->dad_mac_auto_recovery_timer = NULL;

	mac->neigh_list = list_new();
	mac->neigh_list->cmp = neigh_list_cmp;

	mac->uptime = monotime(NULL);
	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("%s: MAC %pEA flags %s", __func__, &mac->macaddr,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}
	return mac;
}

/*
 * Delete MAC entry.
 */
int zebra_evpn_mac_del(struct zebra_evpn *zevpn, struct zebra_mac *mac)
{
	struct zebra_mac *tmp_mac;

	if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("%s: MAC %pEA flags %s", __func__, &mac->macaddr,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}

	/* force de-ref any ES entry linked to the MAC */
	zebra_evpn_es_mac_deref_entry(mac);

	/* remove links to the destination access port */
	zebra_evpn_mac_clear_fwd_info(mac);

	/* Cancel proxy hold timer */
	zebra_evpn_mac_stop_hold_timer(mac);

	/* Cancel auto recovery */
	EVENT_OFF(mac->dad_mac_auto_recovery_timer);

	/* If the MAC is freed before the neigh we will end up
	 * with a stale pointer against the neigh.
	 * The situation can arise when a MAC is in remote state
	 * and its associated neigh is local state.
	 * zebra_evpn_cfg_cleanup() cleans up remote neighs and MACs.
	 * Instead of deleting remote MAC, if its neigh list is non-empty
	 * (associated to local neighs), mark the MAC as AUTO.
	 */
	if (!list_isempty(mac->neigh_list)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("MAC %pEA (flags 0x%x vni %u) has non-empty neigh list "
				   "count %u, mark MAC as AUTO",
				   &mac->macaddr, mac->flags, zevpn->vni,
				   listcount(mac->neigh_list));

		SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
		return 0;
	}

	list_delete(&mac->neigh_list);

	/* Free the VNI hash entry and allocated memory. */
	tmp_mac = hash_release(zevpn->mac_table, mac);
	XFREE(MTYPE_MAC, tmp_mac);

	return 0;
}

/*
 * Add Auto MAC entry.
 */
struct zebra_mac *zebra_evpn_mac_add_auto(struct zebra_evpn *zevpn,
					  const struct ethaddr *macaddr)
{
	struct zebra_mac *mac;

	mac = zebra_evpn_mac_add(zevpn, macaddr);
	if (!mac)
		return NULL;

	zebra_evpn_mac_clear_fwd_info(mac);
	memset(&mac->flags, 0, sizeof(uint32_t));
	SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);

	return mac;
}

static bool zebra_evpn_check_mac_del_from_db(struct mac_walk_ctx *wctx,
					     struct zebra_mac *mac)
{
	if (CHECK_FLAG(wctx->flags, DEL_LOCAL_MAC) &&
	    CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
		return true;
	else if (CHECK_FLAG(wctx->flags, DEL_REMOTE_MAC) &&
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		return true;
	else if (CHECK_FLAG(wctx->flags, DEL_REMOTE_MAC_FROM_VTEP) &&
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) &&
		 IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &wctx->r_vtep_ip))
		return true;
	else if (CHECK_FLAG(wctx->flags, DEL_LOCAL_MAC) &&
		 CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO) &&
		 !listcount(mac->neigh_list)) {
		if (IS_ZEBRA_DEBUG_VXLAN) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("%s: Del MAC %pEA flags %s", __func__,
				   &mac->macaddr,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)));
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
	struct zebra_mac *mac = bucket->data;

	if (!zebra_evpn_check_mac_del_from_db(wctx, mac))
		return;

	if (wctx->upd_client && CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		zebra_evpn_mac_send_del_to_client(wctx->zevpn->vni,
						  &mac->macaddr, mac->flags,
						  false);
	}
	if (wctx->uninstall) {
		if (zebra_evpn_mac_is_static(mac))
			zebra_evpn_sync_mac_dp_install(mac, false, true,
						       __func__);

		if (mac->flags & ZEBRA_MAC_REMOTE)
			zebra_evpn_rem_mac_uninstall(wctx->zevpn, mac, false);
	}

	zebra_evpn_mac_del(wctx->zevpn, mac);

	return;
}

/*
 * Delete all MAC entries for this EVPN.
 */
void zebra_evpn_mac_del_all(struct zebra_evpn *zevpn, int uninstall,
			    int upd_client, uint32_t flags)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(zevpn->mac_table, zebra_evpn_mac_del_hash_entry, &wctx);
}

/*
 * Look up MAC hash entry.
 */
struct zebra_mac *zebra_evpn_mac_lookup(struct zebra_evpn *zevpn,
					const struct ethaddr *mac)
{
	struct zebra_mac tmp;
	struct zebra_mac *pmac;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.macaddr, mac, ETH_ALEN);
	pmac = hash_lookup(zevpn->mac_table, &tmp);

	return pmac;
}

/*
 * Inform BGP about local MAC addition.
 */
int zebra_evpn_mac_send_add_to_client(vni_t vni, const struct ethaddr *macaddr,
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
int zebra_evpn_mac_send_del_to_client(vni_t vni, const struct ethaddr *macaddr,
				      uint32_t flags, bool force)
{
	int state = ZEBRA_NEIGH_ACTIVE;

	if (!force) {
		if (CHECK_FLAG(flags, ZEBRA_MAC_LOCAL_INACTIVE) &&
		    !CHECK_FLAG(flags, ZEBRA_MAC_ES_PEER_ACTIVE))
			/* the host was not advertised - nothing  to delete */
			return 0;

		/* MAC is LOCAL and DUP_DETECTED, this local mobility event
		 * is not known to bgpd. Upon receiving local delete
		 * ask bgp to reinstall the best route (remote entry).
		 */
		if (CHECK_FLAG(flags, ZEBRA_MAC_LOCAL) &&
		    CHECK_FLAG(flags, ZEBRA_MAC_DUPLICATE))
			state = ZEBRA_NEIGH_INACTIVE;
	}

	return zebra_evpn_macip_send_msg_to_client(vni, macaddr, NULL, 0, 0,
						   state, NULL, ZEBRA_MACIP_DEL);
}

/*
 * wrapper to create a MAC hash table
 */
struct hash *zebra_mac_db_create(const char *desc)
{
	return hash_create_size(8, mac_hash_keymake, mac_cmp, desc);
}

/* program sync mac flags in the dataplane  */
int zebra_evpn_sync_mac_dp_install(struct zebra_mac *mac, bool set_inactive,
				   bool force_clear_static, const char *caller)
{
	struct interface *ifp;
	bool sticky;
	bool set_static;
	struct zebra_evpn *zevpn = mac->zevpn;
	vlanid_t vid;
	struct zebra_if *zif;
	struct interface *br_ifp;

	/* If the ES-EVI doesn't exist defer install. When the ES-EVI is
	 * created we will attempt to install the mac entry again
	 */
	if (mac->es) {
		struct zebra_evpn_es_evi *es_evi;

		es_evi = zebra_evpn_es_evi_find(mac->es, mac->zevpn);
		if (!es_evi) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
				zlog_debug("%s: dp-install sync-mac vni %u mac %pEA es %s 0x%x %sskipped, no es-evi",
					   caller, zevpn->vni, &mac->macaddr,
					   mac->es ? mac->es->esi_str : "-",
					   mac->flags,
					   set_inactive ? "inactive " : "");
			return -1;
		}
	}

	/* get the access vlan from the vxlan_device */
	zebra_evpn_mac_get_access_info(mac, &ifp, &vid);

	if (!ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("%s: dp-install sync-mac vni %u mac %pEA es %s %s%sskipped, no access-port",
				   caller, zevpn->vni, &mac->macaddr,
				   mac->es ? mac->es->esi_str : "-",
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   set_inactive ? "inactive " : "");
		}
		return -1;
	}

	zif = ifp->info;
	br_ifp = zif->brslave_info.br_if;
	if (!br_ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("%s: dp-install sync-mac vni %u mac %pEA es %s %s%sskipped, no br",
				   caller, zevpn->vni, &mac->macaddr,
				   mac->es ? mac->es->esi_str : "-",
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   set_inactive ? "inactive " : "");
		}
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
	if (mac->es && zebra_evpn_es_local_mac_via_network_port(mac->es)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("dp-%s sync-nw-mac vni %u mac %pEA es %s %s%s",
				   set_static ? "install" : "uninstall",
				   zevpn->vni, &mac->macaddr,
				   mac->es ? mac->es->esi_str : "-",
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   set_inactive ? "inactive " : "");
		}
		if (set_static)
			/* XXX - old_static needs to be computed more
			 * accurately
			 */
			zebra_evpn_rem_mac_install(zevpn, mac, true);
		else
			zebra_evpn_rem_mac_uninstall(zevpn, mac, false);

		return 0;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("dp-install sync-mac vni %u mac %pEA es %s %s%s%s",
			   zevpn->vni, &mac->macaddr,
			   mac->es ? mac->es->esi_str : "-",
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)),
			   set_static ? "static " : "",
			   set_inactive ? "inactive " : "");
	}

	dplane_local_mac_add(ifp, br_ifp, vid, &mac->macaddr, sticky,
			     set_static, set_inactive);
	return 0;
}

void zebra_evpn_mac_send_add_del_to_client(struct zebra_mac *mac,
					   bool old_bgp_ready,
					   bool new_bgp_ready)
{
	if (new_bgp_ready)
		zebra_evpn_mac_send_add_to_client(mac->zevpn->vni,
						  &mac->macaddr, mac->flags,
						  mac->loc_seq, mac->es);
	else if (old_bgp_ready)
		zebra_evpn_mac_send_del_to_client(mac->zevpn->vni, &mac->macaddr,
						  mac->flags, true);
}

/* MAC hold timer is used to age out peer-active flag.
 *
 * During this wait time we expect the dataplane component or an
 * external neighmgr daemon to probe existing hosts to independently
 * establish their presence on the ES.
 */
static void zebra_evpn_mac_hold_exp_cb(struct event *t)
{
	struct zebra_mac *mac;
	bool old_bgp_ready;
	bool new_bgp_ready;
	bool old_static;
	bool new_static;

	mac = EVENT_ARG(t);
	/* the purpose of the hold timer is to age out the peer-active
	 * flag
	 */
	if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
		return;

	old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	old_static = zebra_evpn_mac_is_static(mac);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE);
	new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	new_static = zebra_evpn_mac_is_static(mac);

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("sync-mac vni %u mac %pEA es %s %shold expired",
			   mac->zevpn->vni, &mac->macaddr,
			   mac->es ? mac->es->esi_str : "-",
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}

	/* re-program the local mac in the dataplane if the mac is no
	 * longer static
	 */
	if (old_static != new_static)
		zebra_evpn_sync_mac_dp_install(mac, false, false, __func__);

	/* inform bgp if needed */
	if (old_bgp_ready != new_bgp_ready)
		zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
						      new_bgp_ready);
}

static inline void zebra_evpn_mac_start_hold_timer(struct zebra_mac *mac)
{
	if (mac->hold_timer)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("sync-mac vni %u mac %pEA es %s %shold started",
			   mac->zevpn->vni, &mac->macaddr,
			   mac->es ? mac->es->esi_str : "-",
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}
	event_add_timer(zrouter.master, zebra_evpn_mac_hold_exp_cb, mac,
			zmh_info->mac_hold_time, &mac->hold_timer);
}

void zebra_evpn_mac_stop_hold_timer(struct zebra_mac *mac)
{
	if (!mac->hold_timer)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("sync-mac vni %u mac %pEA es %s %shold stopped",
			   mac->zevpn->vni, &mac->macaddr,
			   mac->es ? mac->es->esi_str : "-",
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}

	EVENT_OFF(mac->hold_timer);
}

void zebra_evpn_sync_mac_del(struct zebra_mac *mac)
{
	bool old_static;
	bool new_static;

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("sync-mac del vni %u mac %pEA es %s seq %d f %s",
			   mac->zevpn->vni, &mac->macaddr,
			   mac->es ? mac->es->esi_str : "-", mac->loc_seq,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}

	old_static = zebra_evpn_mac_is_static(mac);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_PROXY);
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_ES_PEER_ACTIVE))
		zebra_evpn_mac_start_hold_timer(mac);
	new_static = zebra_evpn_mac_is_static(mac);

	if (old_static != new_static)
		/* program the local mac in the kernel */
		zebra_evpn_sync_mac_dp_install(mac, false, false, __func__);
}

static inline bool zebra_evpn_mac_is_bgp_seq_ok(struct zebra_evpn *zevpn,
						struct zebra_mac *mac,
						uint32_t seq, bool sync)
{
	char mac_buf[MAC_BUF_SIZE];
	uint32_t tmp_seq;
	const char *n_type;
	bool is_local = false;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
		tmp_seq = mac->loc_seq;
		n_type = "local";
		is_local = true;
	} else {
		tmp_seq = mac->rem_seq;
		n_type = "remote";
	}

	if (seq >= tmp_seq)
		return true;

	if (is_local && !zebra_evpn_mac_is_ready_for_bgp(mac->flags)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC || IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s-macip not ready vni %u %s-mac %pEA lower seq %u f 0x%x",
				   sync ? "sync" : "rem", zevpn->vni, n_type,
				   &mac->macaddr, tmp_seq, mac->flags);
		return true;
	}

	/* if the mac was never advertised to bgp we must accept
	 * whatever sequence number bgp sends
	 */
	if (!is_local && zebra_vxlan_get_accept_bgp_seq()) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC || IS_ZEBRA_DEBUG_VXLAN) {
			zlog_debug("%s-macip accept vni %u %s-mac %pEA lower seq %u f %s",
				   (sync ? "sync" : "rem"), zevpn->vni, n_type,
				   &mac->macaddr, tmp_seq,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)));
		}

		return true;
	}

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC || IS_ZEBRA_DEBUG_VXLAN) {
		zlog_debug("%s-macip ignore vni %u %s-mac %pEA as existing has higher seq %u f %s",
			   (sync ? "sync" : "rem"), zevpn->vni, n_type,
			   &mac->macaddr, tmp_seq,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)));
	}

	return false;
}

struct zebra_mac *zebra_evpn_proc_sync_mac_update(struct zebra_evpn *zevpn,
						  const struct ethaddr *macaddr,
						  uint16_t ipa_len,
						  const struct ipaddr *ipaddr,
						  uint8_t flags, uint32_t seq,
						  const esi_t *esi)
{
	struct zebra_mac *mac;
	bool inform_bgp = false;
	bool inform_dataplane = false;
	bool mac_inactive = false;
	bool seq_change = false;
	bool es_change = false;
	uint32_t tmp_seq;
	char ipbuf[INET6_ADDRSTRLEN];
	bool old_local = false;
	bool old_bgp_ready;
	bool new_bgp_ready;
	bool created = false;

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		/* if it is a new local path we need to inform both
		 * the control protocol and the data-plane
		 */
		inform_bgp = true;
		inform_dataplane = true;
		mac_inactive = true;

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
		created = true;
	} else {
		uint32_t old_flags;
		uint32_t new_flags;
		bool old_static;
		bool new_static;
		bool sticky;
		bool remote_gw;

		mac->uptime = monotime(NULL);

		old_flags = mac->flags;
		sticky = !!CHECK_FLAG(old_flags, ZEBRA_MAC_STICKY);
		remote_gw = !!CHECK_FLAG(old_flags, ZEBRA_MAC_REMOTE_DEF_GW);
		if (sticky || remote_gw) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
				zlog_debug("Ignore sync-macip vni %u mac %pEA%s%s%s%s",
					   zevpn->vni, macaddr,
					   ipa_len ? " IP " : "",
					   ipa_len ? ipaddr2str(ipaddr, ipbuf,
								sizeof(ipbuf))
						   : "",
					   sticky ? " sticky" : "",
					   remote_gw ? " remote_gw" : "");
			return NULL;
		}
		if (!zebra_evpn_mac_is_bgp_seq_ok(zevpn, mac, seq, true))
			return NULL;

		old_local = !!CHECK_FLAG(old_flags, ZEBRA_MAC_LOCAL);
		old_static = zebra_evpn_mac_is_static(mac);

		/* re-build the mac flags */
		new_flags = 0;
		SET_FLAG(new_flags, ZEBRA_MAC_LOCAL);
		/* retain old local activity flag */
		if (CHECK_FLAG(old_flags, ZEBRA_MAC_LOCAL))
			SET_FLAG(new_flags,
				 CHECK_FLAG(old_flags,
					    ZEBRA_MAC_LOCAL_INACTIVE));
		else
			SET_FLAG(new_flags, ZEBRA_MAC_LOCAL_INACTIVE);

		if (ipa_len) {
			/* if mac-ip route do NOT update the peer flags
			 * i.e. retain only flags as is
			 */
			SET_FLAG(new_flags,
				 CHECK_FLAG(old_flags,
					    ZEBRA_MAC_ALL_PEER_FLAGS));
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
		zebra_evpn_mac_clear_fwd_info(mac);
		mac->flags = new_flags;

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC && (old_flags != new_flags)) {
			char mac_buf[MAC_BUF_SIZE], omac_buf[MAC_BUF_SIZE];
			struct zebra_mac omac;

			omac.flags = old_flags;
			zlog_debug("sync-mac vni %u mac %pEA old_f %snew_f %s",
				   zevpn->vni, macaddr,
				   zebra_evpn_zebra_mac_flag_dump(&omac,
								  omac_buf,
								  sizeof(omac_buf)),
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)));
		}

		/* update es */
		es_change = zebra_evpn_es_mac_ref(mac, esi);
		/* if mac dest change - inform both sides */
		if (es_change) {
			inform_bgp = true;
			inform_dataplane = true;
			mac_inactive = true;
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

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		char mac_buf[MAC_BUF_SIZE];

		zlog_debug("sync-mac %s vni %u mac %pEA es %s seq %d f %s%s%s",
			   created ? "created" : "updated", zevpn->vni, macaddr,
			   mac->es ? mac->es->esi_str : "-", mac->loc_seq,
			   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
							  sizeof(mac_buf)),
			   inform_bgp ? "inform_bgp" : "",
			   inform_dataplane ? " inform_dp" : "");
	}

	if (inform_bgp)
		zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
						      new_bgp_ready);

	/* neighs using the mac may need to be re-sent to
	 * bgp with updated info
	 */
	if (seq_change || es_change || !old_local)
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, mac,
							     seq_change,
							     es_change);

	if (inform_dataplane && !ipa_len) {
		/* program the local mac in the kernel. when the ES
		 * change we need to force the dataplane to reset
		 * the activity as we are yet to establish activity
		 * locally
		 */
		zebra_evpn_sync_mac_dp_install(mac, mac_inactive, false,
					       __func__);
	}

	return mac;
}

/* update local forwarding info. return true if a dest-ES change
 * is detected
 */
static bool zebra_evpn_local_mac_update_fwd_info(struct zebra_mac *mac,
						 struct interface *ifp,
						 vlanid_t vid)
{
	struct zebra_if *zif = ifp->info;
	bool es_change;
	ns_id_t local_ns_id = NS_DEFAULT;
	struct zebra_vrf *zvrf;
	struct zebra_evpn_es *es;

	zvrf = ifp->vrf->info;
	if (zvrf && zvrf->zns)
		local_ns_id = zvrf->zns->ns_id;

	zebra_evpn_mac_clear_fwd_info(mac);

	es = zif->es_info.es;
	if (es && (es->flags & ZEBRA_EVPNES_BYPASS))
		es = NULL;
	es_change = zebra_evpn_es_mac_ref_entry(mac, es);

	if (!mac->es) {
		/* if es is set fwd_info is not-relevant/taped-out */
		mac->fwd_info.local.ifindex = ifp->ifindex;
		mac->fwd_info.local.ns_id = local_ns_id;
		mac->fwd_info.local.vid = vid;
		zebra_evpn_mac_ifp_link(mac, ifp);
	}

	return es_change;
}

/* Notify Local MACs to the clienti, skips GW MAC */
static void zebra_evpn_send_mac_hash_entry_to_client(struct hash_bucket *bucket,
						     void *arg)
{
	struct mac_walk_ctx *wctx = arg;
	struct zebra_mac *zmac = bucket->data;

	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_DEF_GW))
		return;

	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_LOCAL))
		zebra_evpn_mac_send_add_to_client(wctx->zevpn->vni,
						  &zmac->macaddr, zmac->flags,
						  zmac->loc_seq, zmac->es);
}

/* Iterator to Notify Local MACs of a EVPN */
void zebra_evpn_send_mac_list_to_client(struct zebra_evpn *zevpn)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;

	hash_iterate(zevpn->mac_table, zebra_evpn_send_mac_hash_entry_to_client,
		     &wctx);
}

void zebra_evpn_rem_mac_del(struct zebra_evpn *zevpn, struct zebra_mac *mac)
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
		zebra_evpn_rem_mac_uninstall(zevpn, mac, false);
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
	struct zebra_mac *mac;

	mac = (struct zebra_mac *)bucket->data;
	if (!mac)
		return;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
		zebra_evpn_print_mac_hash(bucket, ctxt);
}

/* Print Duplicate MAC in detail */
void zebra_evpn_print_dad_mac_hash_detail(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_mac *mac;

	mac = (struct zebra_mac *)bucket->data;
	if (!mac)
		return;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
		zebra_evpn_print_mac_hash_detail(bucket, ctxt);
}

int zebra_evpn_mac_remote_macip_add(struct zebra_evpn *zevpn,
				    struct zebra_vrf *zvrf,
				    const struct ethaddr *macaddr,
				    struct in_addr vtep_ip, uint8_t flags,
				    uint32_t seq, const esi_t *esi)
{
	bool sticky;
	bool remote_gw;
	int update_mac = 0;
	bool do_dad = false;
	bool is_dup_detect = false;
	esi_t *old_esi;
	bool old_static = false;
	struct zebra_mac *mac;
	bool old_es_present;
	bool new_es_present;

	sticky = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	remote_gw = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW);

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);

	/* Ignore if the mac is already present as a gateway mac */
	if (mac && CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW) &&
	    CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Ignore remote MACIP ADD VNI %u MAC %pEA as MAC is already configured as gateway MAC",
				   zevpn->vni, macaddr);
		return -1;
	}

	old_esi = (mac && mac->es) ? &mac->es->esi : zero_esi;

	/* check if the remote MAC is unknown or has a change.
	 * If so, that needs to be updated first. Note that client could
	 * install MAC and MACIP separately or just install the latter.
	 */
	if (!mac || !CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) ||
	    sticky != !!CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY) ||
	    remote_gw != !!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE_DEF_GW) ||
	    !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &vtep_ip) ||
	    memcmp(old_esi, esi, sizeof(esi_t)) || seq != mac->rem_seq)
		update_mac = 1;

	if (update_mac) {
		if (!mac) {
			mac = zebra_evpn_mac_add(zevpn, macaddr);
			zebra_evpn_es_mac_ref(mac, esi);
		} else {
			/* When host moves but changes its (MAC,IP)
			 * binding, BGP may install a MACIP entry that
			 * corresponds to "older" location of the host
			 * in transient situations (because {IP1,M1}
			 * is a different route from {IP1,M2}). Check
			 * the sequence number and ignore this update
			 * if appropriate.
			 */
			if (!zebra_evpn_mac_is_bgp_seq_ok(zevpn, mac, seq,
							  false))
				return -1;

			old_es_present = !!mac->es;
			zebra_evpn_es_mac_ref(mac, esi);
			new_es_present = !!mac->es;
			/* XXX - dataplane is curently not able to handle a MAC
			 * replace if the destination changes from L2-NHG to
			 * single VTEP and vice-versa. So delete the old entry
			 * and re-install
			 */
			if (old_es_present != new_es_present)
				zebra_evpn_rem_mac_uninstall(zevpn, mac, false);
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
		if ((!CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) &&
		     mac->dad_count) ||
		    CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE))
			do_dad = true;

		/* Remove local MAC from BGP. */
		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			/* force drop the sync flags */
			old_static = zebra_evpn_mac_is_static(mac);
			if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
				char mac_buf[MAC_BUF_SIZE];

				zlog_debug("sync-mac->remote vni %u mac %pEA es %s seq %d f %s",
					   zevpn->vni, macaddr,
					   mac->es ? mac->es->esi_str : "-",
					   mac->loc_seq,
					   zebra_evpn_zebra_mac_flag_dump(
						   mac, mac_buf,
						   sizeof(mac_buf)));
			}

			zebra_evpn_mac_clear_sync_info(mac);
			zebra_evpn_mac_send_del_to_client(zevpn->vni, macaddr,
							  mac->flags, false);
		}

		/* Set "auto" and "remote" forwarding info. */
		zebra_evpn_mac_clear_fwd_info(mac);
		UNSET_FLAG(mac->flags, ZEBRA_MAC_ALL_LOCAL_FLAGS);
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

		zebra_evpn_dup_addr_detect_for_mac(zvrf, mac,
						   mac->fwd_info.r_vtep_ip,
						   do_dad, &is_dup_detect,
						   false);

		if (!is_dup_detect) {
			zebra_evpn_process_neigh_on_remote_mac_add(zevpn, mac);
			/* Install the entry. */
			zebra_evpn_rem_mac_install(zevpn, mac, old_static);
		}
	}

	/* Update seq number. */
	mac->rem_seq = seq;

	UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	return 0;
}

int zebra_evpn_add_update_local_mac(struct zebra_vrf *zvrf,
				    struct zebra_evpn *zevpn,
				    struct interface *ifp,
				    const struct ethaddr *macaddr, vlanid_t vid,
				    bool sticky, bool local_inactive,
				    bool dp_static, struct zebra_mac *mac)
{
	bool mac_sticky = false;
	bool inform_client = false;
	bool upd_neigh = false;
	bool is_dup_detect = false;
	struct in_addr vtep_ip = { .s_addr = 0 };
	bool es_change = false;
	bool new_bgp_ready;
	/* assume inactive if not present or if not local */
	bool old_local_inactive = true;
	bool old_bgp_ready = false;
	bool inform_dataplane = false;
	bool new_static = false;

	assert(ifp);
	/* Check if we need to create or update or it is a NO-OP. */
	if (!mac)
		mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!mac) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug("ADD %sMAC %pEA intf %s(%u) VID %u -> VNI %u%s",
				   sticky ? "sticky " : "", macaddr, ifp->name,
				   ifp->ifindex, vid, zevpn->vni,
				   local_inactive ? " local-inactive" : "");

		mac = zebra_evpn_mac_add(zevpn, macaddr);
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
		es_change = zebra_evpn_local_mac_update_fwd_info(mac, ifp, vid);
		if (sticky)
			SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
		inform_client = true;
	} else {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("UPD %sMAC %pEA intf %s(%u) VID %u -> VNI %u %scurFlags %s",
				   sticky ? "sticky " : "", macaddr, ifp->name,
				   ifp->ifindex, vid, zevpn->vni,
				   local_inactive ? "local-inactive " : "",
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)));
		}

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			struct interface *old_ifp;
			vlanid_t old_vid;
			bool old_static;

			zebra_evpn_mac_get_access_info(mac, &old_ifp, &old_vid);
			old_bgp_ready =
				zebra_evpn_mac_is_ready_for_bgp(mac->flags);
			old_local_inactive = !!(mac->flags &
						ZEBRA_MAC_LOCAL_INACTIVE);
			old_static = zebra_evpn_mac_is_static(mac);
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY))
				mac_sticky = true;
			es_change = zebra_evpn_local_mac_update_fwd_info(mac,
									 ifp,
									 vid);

			/*
			 * Update any changes and if changes are relevant to
			 * BGP, note it.
			 */
			if (mac_sticky == sticky && old_ifp == ifp &&
			    old_vid == vid &&
			    old_local_inactive == local_inactive &&
			    dp_static == old_static && !es_change) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug("        Add/Update %sMAC %pEA intf %s(%u) VID %u -> VNI %u%s, "
						   "entry exists and has not changed ",
						   sticky ? "sticky " : "",
						   macaddr, ifp->name,
						   ifp->ifindex, vid, zevpn->vni,
						   local_inactive
							   ? " local_inactive"
							   : "");
				return 0;
			}
			if (mac_sticky != sticky) {
				if (sticky)
					SET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
				else
					UNSET_FLAG(mac->flags, ZEBRA_MAC_STICKY);
				inform_client = true;
			}

			/* If an es_change is detected we need to advertise
			 * the route with a sequence that is one
			 * greater. This is need to indicate a mac-move
			 * to the ES peers
			 */
			if (es_change) {
				/* update the sequence number only if the entry
				 * is locally active
				 */
				if (!local_inactive)
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
		} else if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE) ||
			   CHECK_FLAG(mac->flags, ZEBRA_MAC_AUTO)) {
			bool do_dad = false;

			/*
			 * MAC has either moved or was "internally" created due
			 * to a neighbor learn and is now actually learnt. If
			 * it was learnt as a remote sticky MAC, this is an
			 * operator error.
			 */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_STICKY)) {
				flog_warn(EC_ZEBRA_STICKY_MAC_ALREADY_LEARNT,
					  "MAC %pEA already learnt as remote sticky MAC behind VTEP %pI4 VNI %u",
					  macaddr, &mac->fwd_info.r_vtep_ip,
					  zevpn->vni);
				return 0;
			}

			/* If an actual move, compute MAC's seq number */
			if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
				mac->loc_seq = MAX(mac->rem_seq + 1,
						   mac->loc_seq);
				vtep_ip = mac->fwd_info.r_vtep_ip;
				/* Trigger DAD for remote MAC */
				do_dad = true;
			}

			UNSET_FLAG(mac->flags, ZEBRA_MAC_REMOTE);
			UNSET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
			SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
			es_change = zebra_evpn_local_mac_update_fwd_info(mac,
									 ifp,
									 vid);
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

			zebra_evpn_dup_addr_detect_for_mac(zvrf, mac, vtep_ip,
							   do_dad,
							   &is_dup_detect, true);
			if (is_dup_detect) {
				inform_client = false;
				upd_neigh = false;
				es_change = false;
			}
		}
	}

	/* if the dataplane thinks the entry is sync but it is
	 * not sync in zebra (or vice-versa) we need to re-install
	 * to fixup
	 */
	new_static = zebra_evpn_mac_is_static(mac);
	if (dp_static != new_static)
		inform_dataplane = true;

	if (local_inactive)
		SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);
	else
		UNSET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);

	new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	/* if local-activity has changed we need update bgp
	 * even if bgp already knows about the mac
	 */
	if ((old_local_inactive != local_inactive) ||
	    (new_bgp_ready != old_bgp_ready)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("local mac vni %u mac %pEA es %s seq %d f %s%s",
				   zevpn->vni, macaddr,
				   mac->es ? mac->es->esi_str : "", mac->loc_seq,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)),
				   local_inactive ? "local-inactive" : "");
		}

		if (!is_dup_detect)
			inform_client = true;
	}

	if (es_change) {
		inform_client = true;
		upd_neigh = true;
	}

	/* Inform dataplane if required. */
	if (inform_dataplane)
		zebra_evpn_sync_mac_dp_install(mac, false, false, __func__);

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

int zebra_evpn_del_local_mac(struct zebra_evpn *zevpn, struct zebra_mac *mac,
			     bool clear_static)
{
	bool old_bgp_ready;
	bool new_bgp_ready;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("DEL MAC %pEA VNI %u seq %u flags 0x%x nbr count %u",
			   &mac->macaddr, zevpn->vni, mac->loc_seq, mac->flags,
			   listcount(mac->neigh_list));

	old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	if (!clear_static && zebra_evpn_mac_is_static(mac)) {
		/* this is a synced entry and can only be removed when the
		 * es-peers stop advertising it.
		 */
		zebra_evpn_mac_clear_fwd_info(mac);

		if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
			char mac_buf[MAC_BUF_SIZE];

			zlog_debug("re-add sync-mac vni %u mac %pEA es %s seq %d f %s",
				   zevpn->vni, &mac->macaddr,
				   mac->es ? mac->es->esi_str : "-",
				   mac->loc_seq,
				   zebra_evpn_zebra_mac_flag_dump(mac, mac_buf,
								  sizeof(mac_buf)));
		}

		/* inform-bgp about change in local-activity if any */
		if (!CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE)) {
			SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL_INACTIVE);
			new_bgp_ready =
				zebra_evpn_mac_is_ready_for_bgp(mac->flags);
			zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready,
							      new_bgp_ready);
		}

		/* re-install the inactive entry in the kernel */
		zebra_evpn_sync_mac_dp_install(mac, true, false, __func__);

		return 0;
	}

	/* flush the peer info */
	zebra_evpn_mac_clear_sync_info(mac);

	/* Update all the neigh entries associated with this mac */
	zebra_evpn_process_neigh_on_local_mac_del(zevpn, mac);

	/* Remove MAC from BGP. */
	zebra_evpn_mac_send_del_to_client(zevpn->vni, &mac->macaddr, mac->flags,
					  clear_static);

	zebra_evpn_es_mac_deref_entry(mac);

	/* remove links to the destination access port */
	zebra_evpn_mac_clear_fwd_info(mac);

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

void zebra_evpn_mac_gw_macip_add(struct interface *ifp, struct zebra_evpn *zevpn,
				 const struct ipaddr *ip,
				 struct zebra_mac **macp,
				 const struct ethaddr *macaddr,
				 vlanid_t vlan_id, bool def_gw)
{
	struct zebra_mac *mac;
	ns_id_t local_ns_id = NS_DEFAULT;
	struct zebra_vrf *zvrf;

	zvrf = ifp->vrf->info;
	if (zvrf && zvrf->zns)
		local_ns_id = zvrf->zns->ns_id;

	if (!*macp) {
		mac = zebra_evpn_mac_lookup(zevpn, macaddr);
		if (!mac)
			mac = zebra_evpn_mac_add(zevpn, macaddr);
		*macp = mac;
	} else
		mac = *macp;

	/* Set "local" forwarding info. */
	zebra_evpn_mac_clear_fwd_info(mac);
	SET_FLAG(mac->flags, ZEBRA_MAC_LOCAL);
	SET_FLAG(mac->flags, ZEBRA_MAC_AUTO);
	if (def_gw)
		SET_FLAG(mac->flags, ZEBRA_MAC_DEF_GW);
	else
		SET_FLAG(mac->flags, ZEBRA_MAC_SVI);
	mac->fwd_info.local.ifindex = ifp->ifindex;
	mac->fwd_info.local.ns_id = local_ns_id;
	mac->fwd_info.local.vid = vlan_id;
}

void zebra_evpn_mac_svi_del(struct interface *ifp, struct zebra_evpn *zevpn)
{
	struct zebra_mac *mac;
	struct ethaddr macaddr;
	bool old_bgp_ready;

	if (!zebra_evpn_mh_do_adv_svi_mac())
		return;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);
	mac = zebra_evpn_mac_lookup(zevpn, &macaddr);

	if (!mac || CHECK_FLAG(mac->flags, ZEBRA_MAC_SVI))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("SVI %s mac free", ifp->name);

	old_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	UNSET_FLAG(mac->flags, ZEBRA_MAC_SVI);
	zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready, false);
	zebra_evpn_deref_ip2mac(mac->zevpn, mac);
}

void zebra_evpn_mac_svi_add(struct interface *ifp, struct zebra_evpn *zevpn)
{
	struct zebra_mac *mac = NULL;
	struct ethaddr macaddr;
	struct zebra_if *zif = ifp->info;
	bool old_bgp_ready;
	bool new_bgp_ready;

	if (!zebra_evpn_mh_do_adv_svi_mac() ||
	    !zebra_evpn_send_to_client_ok(zevpn))
		return;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	/* dup check */
	mac = zebra_evpn_mac_lookup(zevpn, &macaddr);
	if (mac && CHECK_FLAG(mac->flags, ZEBRA_MAC_SVI))
		return;

	/* add/update mac */
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("SVI %s mac add", zif->ifp->name);

	old_bgp_ready = (mac && zebra_evpn_mac_is_ready_for_bgp(mac->flags))
				? true
				: false;

	zebra_evpn_mac_gw_macip_add(ifp, zevpn, NULL, &mac, &macaddr, 0, false);

	new_bgp_ready = zebra_evpn_mac_is_ready_for_bgp(mac->flags);
	zebra_evpn_mac_send_add_del_to_client(mac, old_bgp_ready, new_bgp_ready);
}
