/* SPDX-License-Identifier: GPL-2.0-or-later
 * L2-VPN VPWS/VPLS File
 * Copyright 2026 6WIND S.A.
 *
 * This file is part of FRRouting
 */
#include "lib/zebra.h"
#include "lib/l2vpn_svc.h"

#include "zebra/zebra_l2vpn_svc.h"

#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_l2vpn.h"
#include "bgp_evpn.h"
#include "bgpd/bgpd.h"

static void bgp_l2vpn_vpws_run(struct l2vpn_svc *l2vpn_svc);
static void bgp_l2vpn_vpws_local_withdraw(struct bgp *bgp, struct l2vpn_svc *l2vpn_svc,
					  struct bgpevpn *vpn);
static bool is_l2vpn_vpws_ready(struct bgp *bgp, struct l2vpn *l2vpn, struct l2vpn_svc *l2vpn_svc,
				char *errmsg, size_t len);
static void svc_to_zebra_l2vpn(struct l2vpn_svc *svc, struct zapi_l2vpn_svc *zebra_l2vpn);
static bool bgp_l2vpn_vpws_zebra_add(struct l2vpn_svc *l2vpn_svc, bool add);

extern struct zclient *zclient;

static void bgp_l2vpn_entry_added(const char *l2vpn_name)
{
	struct l2vpn *l2vpn;

	l2vpn = l2vpn_find(&l2vpn_tree_config, l2vpn_name, L2VPN_TYPE_VPWS);
	if (!l2vpn)
		return;

	l2vpn->pw_type = PW_TYPE_ETHERNET_TAGGED;
}

static void bgp_l2vpn_entry_deleted(const char *l2vpn_name)
{
	struct l2vpn *l2vpn;
	struct bgpevpn *vpn;
	struct bgp *bgp = bgp_get_evpn();
	struct l2vpn_svc *l2vpn_svc, *l2vpn_svc_iter;

	l2vpn = l2vpn_find(&l2vpn_tree_config, l2vpn_name, L2VPN_TYPE_VPWS);
	if (!l2vpn)
		return;
	if (!bgp)
		return;

	RB_FOREACH_SAFE (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc_iter) {
		vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
		if (!vpn)
			continue;
		bgp_l2vpn_vpws_zebra_add(l2vpn_svc, false);
		bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_svc, vpn);
		l2vpn_svc->enabled = false;

		RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc);
		RB_INSERT(l2vpn_svc_head, &l2vpn->svc_inactive_tree, l2vpn_svc);
		UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);
	}
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/evi
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/local-ac-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/remote-ac-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/vni
 */
static void bgp_l2vpn_entry_event(struct l2vpn_svc *l2vpn_svc)
{
	char errmsg[BUFSIZ];
	bool running_change;
	struct bgpevpn *vpn;
	struct bgp *bgp = bgp_get_evpn();
	struct l2vpn *l2vpn = l2vpn_svc->l2vpn;

	if (l2vpn->type != L2VPN_TYPE_VPWS)
		return;

	if (!bgp)
		return;

	running_change = RB_FIND(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc) ? true : false;

	/* Try move inactive svc to active */
	if (!running_change) {
		if (!is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_svc, errmsg, sizeof(errmsg))) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("%s: VPWS local-ac %u remote-ac %u no ready, reason: %s",
					   __func__, l2vpn_svc->local_ac_id,
					   l2vpn_svc->remote_ac_id, errmsg);
			return;
		}

		RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_inactive_tree, l2vpn_svc);
		RB_INSERT(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc);
		bgp_l2vpn_vpws_zebra_add(l2vpn_svc, true);
		l2vpn_svc->local_status = EVPN_LOCAL_TX_FAULT;
		l2vpn_svc->remote_status = EVPN_NOT_FORWARDING;

		return;
	}

	/* Update running svc */
	if (l2vpn_svc->enabled &&
	    is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_svc, errmsg, sizeof(errmsg)))
		return;

	RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc);
	RB_INSERT(l2vpn_svc_head, &l2vpn->svc_inactive_tree, l2vpn_svc);

	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
	bgp_l2vpn_vpws_zebra_add(l2vpn_svc, false);
	if (vpn) {
		bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_svc, vpn);

		if (!CHECK_FLAG(l2vpn_svc->flags, F_EVPN_VNI))
			UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);
	}
}

void bgp_l2vpn_vpws_zebra_set(struct bgp *bgp, struct l2vpn_svc *l2vpn_svc, bool on)
{
	struct zapi_l2vpn_svc zebra_l2vpn;

	svc_to_zebra_l2vpn(l2vpn_svc, &zebra_l2vpn);
	if (!on) {
		zebra_send_l2vpn(zclient, ZEBRA_L2VPN_SVC_UNSET, &zebra_l2vpn);
		l2vpn_svc->remote_status = EVPN_NOT_FORWARDING;
		l2vpn_svc->reason = F_L2VPN_REMOTE_NOT_FWD;

		return;
	}

	if (zebra_send_l2vpn(zclient, ZEBRA_L2VPN_SVC_SET, &zebra_l2vpn) ==
	    ZCLIENT_SEND_FAILURE) {
		l2vpn_svc->remote_status = EVPN_NOT_FORWARDING;
		l2vpn_svc->reason = F_L2VPN_LOCAL_NOT_FWD;
	} else {
		l2vpn_svc->remote_status = EVPN_FORWARDING;
		l2vpn_svc->reason = F_L2VPN_NO_ERR;
	}
}

static bool bgp_l2vpn_vpws_zebra_add(struct l2vpn_svc *l2vpn_svc, bool add)
{
	struct zapi_l2vpn_svc zebra_l2vpn;
	zebra_message_types_t m_type;

	m_type = add ? ZEBRA_L2VPN_SVC_ADD : ZEBRA_L2VPN_SVC_DELETE;

	svc_to_zebra_l2vpn(l2vpn_svc, &zebra_l2vpn);

	return zebra_send_l2vpn(zclient, m_type, &zebra_l2vpn) == ZCLIENT_SEND_FAILURE;
}

/* for VPWS VXLAN, the following characters are of importance
 * - ifname and ifindex (vxlan interface)
 * - EVPN vni
 * - l2vpn type, vni, data.bgp.local_ac
 * - data.bgp.vpn_name is derived from l2vpn name, and never changes
 * - af is ignored but hardset to AF_INET for correct processing when reading stream
 */
static void svc_to_zebra_l2vpn(struct l2vpn_svc *svc, struct zapi_l2vpn_svc *zebra_l2vpn)
{
	memset(zebra_l2vpn, 0, sizeof(*zebra_l2vpn));
	strlcpy(zebra_l2vpn->ifname, svc->ifname, sizeof(zebra_l2vpn->ifname));
	zebra_l2vpn->ifindex = svc->ifindex;
	zebra_l2vpn->type = svc->l2vpn->pw_type;
	zebra_l2vpn->af = AF_INET;
	zebra_l2vpn->local_label = MPLS_INVALID_LABEL;
	zebra_l2vpn->remote_label = MPLS_INVALID_LABEL;
	zebra_l2vpn->nexthop.ipv4 = svc->addr.ipv4;
	if (CHECK_FLAG(svc->flags, F_PW_CWORD))
		zebra_l2vpn->flags = F_PSEUDOWIRE_CWORD;
	zebra_l2vpn->data.bgp.vni = svc->vni;
	strlcpy(zebra_l2vpn->data.bgp.local_ac, svc->local_ac, IFNAMSIZ);
	strlcpy(zebra_l2vpn->data.bgp.vpn_name, svc->l2vpn->name,
		sizeof(zebra_l2vpn->data.bgp.vpn_name));
}

void bgp_l2vpn_init(void)
{
	l2vpn_init();
	l2vpn_register_hook(bgp_l2vpn_entry_added, bgp_l2vpn_entry_deleted, bgp_l2vpn_entry_event,
			    NULL);
}

static bool is_l2vpn_vpws_ready(struct bgp *bgp, struct l2vpn *l2vpn, struct l2vpn_svc *l2vpn_svc,
				char *errmsg, size_t len)
{
	struct bgpevpn *vpn;
	struct interface *ifp;

	if (!l2vpn_svc->enabled) {
		snprintf(errmsg, len, "status disabled");
		return false;
	}

	if (!l2vpn_svc->evi) {
		snprintf(errmsg, len, "Missing EVPN instance identifier");
		return false;
	}

	if (!l2vpn_svc->local_ac_id || !l2vpn_svc->remote_ac_id) {
		snprintf(errmsg, len, "Missing local/remote ac id");
		return false;
	}

	if (!l2vpn_svc->vni) {
		snprintf(errmsg, len, "Missing BGP EVPN VNI config");
		return false;
	}

	if (l2vpn_svc->vni == bgp->l3vni) {
		snprintf(errmsg, len, "BGP EVPN VNI %u is a L3VNI", l2vpn_svc->vni);
		return false;
	}

	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
	if (!vpn) {
		snprintf(errmsg, len, "Can not find VPN for vni");
		return false;
	}
	l2vpn->br_ifindex = vpn->svi_ifindex;

	ifp = if_lookup_by_name(l2vpn_svc->ifname, bgp->vrf_id);
	if (!ifp) {
		snprintf(errmsg, len, "EVPN VPWS interface %s not found", l2vpn_svc->ifname);
		return false;
	}
	l2vpn_svc->ifindex = ifp->ifindex;

	return true;
}

static void bgp_l2vpn_vpws_run(struct l2vpn_svc *l2vpn_svc)
{
	bool mh;
	uint8_t flag;
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct bgp_evpn_es *es;
	struct ecommunity_val eval;
	struct bgp_interface *binfo;
	struct listnode *node = NULL;
	struct interface *ifp, *local_ifp;
	struct bgp_evpn_es_evi *evi_match;
	struct bgp_evpn_es_evi_vtep *es_evi_vtep;

	if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
		zlog_debug("Running EVPN VPWS: local-ac %u (%s) remote-ac %u evi %u vni %u",
			   l2vpn_svc->local_ac_id, l2vpn_svc->local_ac, l2vpn_svc->remote_ac_id,
			   l2vpn_svc->evi, l2vpn_svc->vni);

	bgp = bgp_get_evpn();
	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
	ifp = if_lookup_by_name(l2vpn_svc->ifname, bgp->vrf_id);

	if (!CHECK_FLAG(vpn->flags, VNI_FLAG_VPWS)) {
		delete_routes_for_vni(bgp, vpn);
		SET_FLAG(vpn->flags, VNI_FLAG_VPWS);
	}

	if (!memcmp(&l2vpn_svc->esi, zero_esi, sizeof(esi_t))) {
		mh = false;
		es = bgp_evpn_es_find(&l2vpn_svc->esi);
		if (!es) {
			es = bgp_evpn_es_new(bgp, zero_esi);
			bgp_evpn_es_local_info_set(bgp, es);
		}
		SET_FLAG(es->flags, BGP_EVPNES_ADV_EVI);
		local_ifp = if_lookup_by_name(l2vpn_svc->local_ac, bgp->vrf_id);
		if (!local_ifp) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("VPWS: can not find single homed interface %s",
					   l2vpn_svc->local_ac);

			return;
		}
		binfo = local_ifp->info;
		SET_FLAG(binfo->flags, BGP_INTERFACE_EVPN_SINGLE_HOMED);
		if (!if_is_operative(local_ifp)) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("VPWS: single homed interface %s is not active",
					   local_ifp->name);

			return;
		}
		flag = 0;
	} else {
		mh = true;
		es = bgp_evpn_es_find(&l2vpn_svc->esi);
		if (!es || bgp_evpn_local_es_is_active(es)) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("VPWS: multihoming interface %s is not active",
					   ifp->name);
		}
		/* TODO  MH*/
	}

	encode_l2attr_extcomm(&eval, l2vpn_svc->l2vpn->mtu, flag);
	bgp_evpn_local_es_evi_add(bgp, &l2vpn_svc->esi, vpn->vni, l2vpn_svc->evi, &eval);
	SET_FLAG(l2vpn_svc->flags, F_EVPN_SEND_REMOTE);

	/* Try to match remote evi */
	evi_match = bgp_evpn_es_evi_find(es, vpn, l2vpn_svc->evi);
	if (!evi_match || !CHECK_FLAG(evi_match->flags, BGP_EVPNES_EVI_LOCAL)) {
		UNSET_FLAG(l2vpn_svc->flags, F_EVPN_SEND_REMOTE);
		return;
	}

	if (!CHECK_FLAG(evi_match->flags, BGP_EVPNES_EVI_REMOTE)) {
		l2vpn_svc->reason = F_L2VPN_NO_REMOTE_AD;
		return;
	}

	if (!mh) {
		if (listcount(evi_match->es_evi_vtep_list) > 1) {
			l2vpn_svc->reason = F_L2VPN_AD_MISMATCH;
			return;
		}
		es_evi_vtep = listgetdata(listhead(evi_match->es_evi_vtep_list));
	} else {
		for (ALL_LIST_ELEMENTS_RO(evi_match->es_evi_vtep_list, node, es_evi_vtep)) {
			/* TODO  MH */
		}
	}

	IPV4_ADDR_COPY(&l2vpn_svc->addr.ipv4, &es_evi_vtep->vtep_ip);
	IPV4_ADDR_COPY(&l2vpn_svc->lsr_id, &es_evi_vtep->vtep_ip);

	bgp_l2vpn_vpws_zebra_set(bgp, l2vpn_svc, true);
}

void bgp_l2vpn_vpws_local_withdraw(struct bgp *bgp, struct l2vpn_svc *l2vpn_svc,
				   struct bgpevpn *vpn)
{
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;

	UNSET_FLAG(l2vpn_svc->flags, F_EVPN_SEND_REMOTE);
	es = bgp_evpn_es_find(&l2vpn_svc->esi);
	if (!es)
		return;
	es_evi = bgp_evpn_es_evi_find(es, vpn, l2vpn_svc->evi);
	if (!es_evi || !CHECK_FLAG(es_evi->flags, BGP_EVPNES_EVI_LOCAL))
		return;

	bgp_evpn_local_es_evi_do_del(es_evi);
}

struct l2vpn_svc *bgp_l2vpn_vpws_evi_match(uint32_t ethtag)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *l2vpn_svc;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
			if (l2vpn_svc->evi == ethtag)
				return l2vpn_svc;
		}
	}

	return NULL;
}

bool bgp_l2vpn_vpws_es_add(esi_t esi)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *l2vpn_svc;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
			if (!memcmp(&l2vpn_svc->esi, &esi, sizeof(esi_t))) {
				bgp_l2vpn_vpws_run(l2vpn_svc);
				return true;
			}
		}
	}

	return false;
}

bool bgp_evpn_vpws_vni_changed(struct bgp *bgp, struct bgpevpn *vpn)
{
	char errmsg[BUFSIZ];
	struct l2vpn *l2vpn;
	struct l2vpn_svc *l2vpn_svc, *l2vpn_svc_nxt;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH_SAFE (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_inactive_tree,
				 l2vpn_svc_nxt) {
			if (vpn->vni != l2vpn_svc->vni)
				continue;
			SET_FLAG(vpn->flags, VNI_FLAG_VPWS);

			if (!l2vpn_svc->enabled)
				continue;
			if (!is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_svc, errmsg, sizeof(errmsg))) {
				if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
					zlog_debug("%s: VPWS local-ac %u, remote-ac %u no ready, reason: %s",
						   __func__, l2vpn_svc->local_ac_id,
						   l2vpn_svc->remote_ac_id, errmsg);
				continue;
			}

			RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_inactive_tree, l2vpn_svc);
			RB_INSERT(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc);
			l2vpn_svc->local_status = EVPN_LOCAL_TX_FAULT;
			l2vpn_svc->remote_status = EVPN_NOT_FORWARDING;
			bgp_l2vpn_vpws_zebra_add(l2vpn_svc, true);

			return true;
		}
	}

	return false;
}

uint32_t bgp_evpn_vpws_vni_del(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *l2vpn_svc, *l2vpn_svc_nxt;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH_SAFE (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc_nxt) {
			if (vpn->vni != l2vpn_svc->vni)
				continue;
			UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);

			if (!l2vpn_svc->enabled)
				continue;

			bgp_l2vpn_vpws_zebra_add(l2vpn_svc, false);
			bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_svc, vpn);
			RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_tree, l2vpn_svc);
			RB_INSERT(l2vpn_svc_head, &l2vpn->svc_inactive_tree, l2vpn_svc);

			return l2vpn_svc->evi;
		}
	}

	return 0;
}

/* Read new evpn vpws status and data from zebra.
 * Update is need:
 *  - evpn vpws local status switching from EVPN_LOCAL_TX_FAULT to EVPN_NOT_FORWARDING.
 *  - evpn vpws local status is fell back to EVPN_LOCAL_TX_FAULT.
 */
void bgp_l2vpn_svc_update_status(struct zapi_l2vpn_status *zapi)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *l2vpn_svc, s;
	struct bgpevpn *vpn;
	struct interface *ifp;
	bool update_needed = false;
	struct bgp_interface *binfo;
	struct bgp *bgp = bgp_get_evpn();

	strlcpy(s.ifname, zapi->ifname, IFNAMSIZ);
	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		l2vpn_svc = RB_FIND(l2vpn_svc_head, &l2vpn->svc_tree, &s);
		if (!l2vpn_svc)
			continue;

		if (l2vpn_svc->local_status != zapi->status) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("VPWS local-ac %u remote-ac %u, switch status from %s to %s",
					   l2vpn_svc->local_ac_id, l2vpn_svc->remote_ac_id,
					   evpn_status_to_str(l2vpn_svc->local_status),
					   evpn_status_to_str(zapi->status));
		}

		/* handle AC interface switching */
		if (memcmp(l2vpn_svc->local_ac, zapi->local_ac, IFNAMSIZ)) {
			if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
				zlog_debug("VPWS local-ac %u remote-ac %u, new interface AC %s",
					   l2vpn_svc->local_ac_id, l2vpn_svc->remote_ac_id,
					   zapi->local_ac);
			/* AC ready to AC no ready */
			if (l2vpn_svc->local_status != EVPN_LOCAL_TX_FAULT &&
			    zapi->status == EVPN_LOCAL_TX_FAULT) {
				if (!memcmp(&l2vpn_svc->esi, zero_esi, sizeof(esi_t))) {
					ifp = if_lookup_by_name(l2vpn_svc->local_ac, bgp->vrf_id);
					if (ifp) {
						binfo = ifp->info;
						UNSET_FLAG(binfo->flags,
							   BGP_INTERFACE_EVPN_SINGLE_HOMED);
					}
				}
				if (BGP_DEBUG(evpn_vpws, EVPN_VPWS))
					zlog_debug("VPWS local-ac %u remote-ac %u, fell back to %s",
						   l2vpn_svc->remote_ac_id, l2vpn_svc->remote_ac_id,
						   evpn_status_to_str(l2vpn_svc->local_status));
				update_needed = true;
			}
			strlcpy(l2vpn_svc->local_ac, zapi->local_ac, IFNAMSIZ);
		}

		/* run VPWS EVPN_LOCAL_TX_FAULT -> EVPN_NOT_FORWARDING */
		if (l2vpn_svc->local_status == EVPN_LOCAL_TX_FAULT &&
		    zapi->status == EVPN_NOT_FORWARDING)
			update_needed = true;

		l2vpn_svc->local_status = zapi->status;
		if (update_needed) {
			/* send eventual withdraw RT1 */
			if (CHECK_FLAG(l2vpn_svc->flags, F_EVPN_SEND_REMOTE)) {
				vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
				bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_svc, vpn);
			}

			/* send update RT1 */
			bgp_l2vpn_vpws_run(l2vpn_svc);
		}

		break;
	}
}

void bgp_l2vpn_ifp_up(struct interface *ifp, bool up)
{
	struct l2vpn *l2vpn;
	struct bgpevpn *vpn;
	struct l2vpn_svc *l2vpn_svc;
	struct bgp *bgp = bgp_get_evpn();

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
			vpn = bgp_evpn_lookup_vni(bgp, l2vpn_svc->vni);
			if (!vpn)
				continue;
			if (!strcmp(l2vpn_svc->local_ac, ifp->name)) {
				if (up) {
					if (l2vpn_svc->local_status != EVPN_FORWARDING)
						bgp_l2vpn_vpws_run(l2vpn_svc);
				} else {
					bgp_l2vpn_vpws_zebra_set(bgp, l2vpn_svc, up);
					bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_svc, vpn);
				}

				return;
			}
		}
	}
}
