// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra L2VPN Service (VPLS, VPWS) code
 * Copyright (C) 2016 Volta Networks, Inc.
 * Copyright 2026 6WIND S.A.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "frrevent.h"
#include "command.h"
#include "vrf.h"
#include "lib/json.h"
#include "printfrr.h"

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_l2vpn_svc.h"
#include "zebra/zebra_evpn_mh.h"

DEFINE_MTYPE_STATIC(LIB, L2VPN_SVC, "L2VPN Service");

DEFINE_QOBJ_TYPE(zebra_l2vpn_svc);

DEFINE_HOOK(l2vpn_svc_install, (struct zebra_l2vpn_svc *svc), (svc));
DEFINE_HOOK(l2vpn_svc_uninstall, (struct zebra_l2vpn_svc *svc), (svc));

#define MPLS_NO_LABEL MPLS_INVALID_LABEL

static int zebra_l2vpn_svc_enabled(struct zebra_l2vpn_svc *);
static void zebra_l2vpn_svc_install(struct zebra_l2vpn_svc *);
static void zebra_l2vpn_svc_uninstall(struct zebra_l2vpn_svc *);
static void zebra_l2vpn_svc_install_retry(struct event *thread);
static int zebra_l2vpn_svc_check_reachability(const struct zebra_l2vpn_svc *);
static void zebra_l2vpn_svc_update_status(struct zebra_l2vpn_svc *, int);
static void zebra_evpn_bgp_vni_check(struct zebra_l2vpn_svc *svc);

static inline int l2vpn_svc_compare(const struct zebra_l2vpn_svc *a,
				    const struct zebra_l2vpn_svc *b)
{
	return (strcmp(a->ifname, b->ifname));
}

RB_GENERATE(zebra_l2vpn_svc_head, zebra_l2vpn_svc, svc_entry, l2vpn_svc_compare)
RB_GENERATE(zstatic_l2vpn_svc_head, zebra_l2vpn_svc, static_svc_entry, l2vpn_svc_compare)

struct zebra_l2vpn_svc *zebra_l2vpn_svc_add(struct zebra_vrf *zvrf, const char *ifname,
					    uint8_t protocol, union l2vpn_protocol_fields data,
					    struct zserv *client)
{
	struct zebra_l2vpn_svc *svc;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: adding L2VPN %s protocol %s", zvrf_id(zvrf), ifname,
			   zebra_route_string(protocol));

	svc = XCALLOC(MTYPE_L2VPN_SVC, sizeof(*svc));
	strlcpy(svc->ifname, ifname, sizeof(svc->ifname));
	svc->protocol = protocol;
	svc->vrf_id = zvrf_id(zvrf);
	svc->client = client;
	svc->status = PW_NOT_FORWARDING;
	svc->local_label = MPLS_NO_LABEL;
	svc->remote_label = MPLS_NO_LABEL;
	svc->flags = F_PSEUDOWIRE_CWORD;

	RB_INSERT(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree, svc);
	if (svc->protocol == ZEBRA_ROUTE_STATIC) {
		RB_INSERT(zstatic_l2vpn_svc_head, &zvrf->static_l2vpn_svc_tree, svc);
		QOBJ_REG(svc, zebra_l2vpn_svc);
	}

	if (svc->protocol == ZEBRA_ROUTE_BGP) {
		svc->status = EVPN_NOT_FORWARDING;
		if (!data.bgp.vni)
			return svc;

		svc->data.bgp.vni = data.bgp.vni;
		zebra_evpn_bgp_vni_check(svc);
	}

	return svc;
}

void zebra_l2vpn_svc_del(struct zebra_vrf *zvrf, struct zebra_l2vpn_svc *svc)
{
	struct zebra_if *zif;
	struct zebra_evpn *zevpn;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: deleting L2VPN %s protocol %s", svc->vrf_id, svc->ifname,
			   zebra_route_string(svc->protocol));

	/* remove nexthop tracking */
	zebra_deregister_rnh_l2vpn_svc(svc->vrf_id, svc);

	/* uninstall */
	if (svc->status == PW_FORWARDING) {
		hook_call(l2vpn_svc_uninstall, svc);
		dplane_l2vpn_svc_uninstall(svc);
	}

	EVENT_OFF(svc->install_retry_timer);

	/* unlink and release memory */
	RB_REMOVE(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree, svc);
	if (svc->protocol == ZEBRA_ROUTE_STATIC)
		RB_REMOVE(zstatic_l2vpn_svc_head, &zvrf->static_l2vpn_svc_tree, svc);

	if (svc->protocol == ZEBRA_ROUTE_BGP && svc->data.bgp.vni) {
		zevpn = zebra_evpn_lookup(svc->data.bgp.vni);
		if (!zevpn)
			return;

		zif = zevpn->vxlan_if->info;
		if (if_is_operative(zevpn->vxlan_if) && zif && zif->brslave_info.br_if) {
			zebra_evpn_send_add_to_client(zevpn);
			zebra_evpn_read_mac_neigh(zevpn, zevpn->vxlan_if);
		}
	}

	XFREE(MTYPE_L2VPN_SVC, svc);
}

void zebra_l2vpn_svc_change(struct zebra_l2vpn_svc *svc, ifindex_t ifindex, int type, int af,
			    union g_addr *nexthop, uint32_t local_label, uint32_t remote_label,
			    uint8_t flags, union l2vpn_protocol_fields *data)
{
	bool nht_exists;

	svc->ifindex = ifindex;
	svc->type = type;
	svc->af = af;
	svc->nexthop = *nexthop;
	svc->local_label = local_label;
	svc->remote_label = remote_label;
	svc->flags = flags;
	svc->data = *data;

	if (zebra_l2vpn_svc_enabled(svc)) {
		zebra_register_rnh_l2vpn_svc(svc->vrf_id, svc, &nht_exists);
		if (nht_exists)
			zebra_l2vpn_svc_update(svc);
	} else {
		if (svc->protocol == ZEBRA_ROUTE_STATIC)
			zebra_deregister_rnh_l2vpn_svc(svc->vrf_id, svc);
		zebra_l2vpn_svc_uninstall(svc);
	}
}

struct zebra_l2vpn_svc *zebra_l2vpn_svc_find(struct zebra_vrf *zvrf, const char *ifname)
{
	struct zebra_l2vpn_svc svc;
	strlcpy(svc.ifname, ifname, sizeof(svc.ifname));
	return RB_FIND(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree, &svc);
}

static int zebra_l2vpn_svc_enabled(struct zebra_l2vpn_svc *svc)
{
	if (svc->protocol == ZEBRA_ROUTE_STATIC) {
		if (svc->local_label == MPLS_NO_LABEL || svc->remote_label == MPLS_NO_LABEL ||
		    svc->af == AF_UNSPEC)
			return 0;
		return 1;
	} else
		return svc->enabled;
}

void zebra_l2vpn_svc_update(struct zebra_l2vpn_svc *svc)
{
	if (zebra_l2vpn_svc_check_reachability(svc) < 0) {
		zebra_l2vpn_svc_uninstall(svc);
		/* wait for NHT and try again later */
	} else {
		/*
		 * Install or reinstall the pseudowire (e.g. to update
		 * parameters like the nexthop or the use of the control word).
		 */
		event_cancel(&svc->install_retry_timer);
		zebra_l2vpn_svc_install(svc);
	}
}

static void zebra_l2vpn_svc_install(struct zebra_l2vpn_svc *svc)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: installing pseudowire %s protocol %s", svc->vrf_id, svc->ifname,
			   zebra_route_string(svc->protocol));

	hook_call(l2vpn_svc_install, svc);
	if (dplane_l2vpn_svc_install(svc) == ZEBRA_DPLANE_REQUEST_FAILURE) {
		/*
		 * Realistically this is never going to fail passing
		 * the l2vpn service data down to the dplane.  The failure modes
		 * look like impossible events but we still return
		 * on them.... but I don't see a real clean way to remove this
		 * at all.  So let's just leave the retry mechanism for
		 * the moment.
		 */
		if (svc->protocol == ZEBRA_ROUTE_BGP)
			zebra_l2vpn_svc_install_failure(svc, EVPN_NOT_FORWARDING);
		else
			zebra_l2vpn_svc_install_failure(svc, PW_NOT_FORWARDING);
		return;
	}
}

static void zebra_l2vpn_svc_uninstall(struct zebra_l2vpn_svc *svc)
{
	if (svc->status != PW_FORWARDING || svc->status != EVPN_FORWARDING)
		return;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: uninstalling L2vpn %s protocol %s", svc->vrf_id, svc->ifname,
			   zebra_route_string(svc->protocol));

	/* ignore any possible error */
	hook_call(l2vpn_svc_uninstall, svc);
	dplane_l2vpn_svc_uninstall(svc);
}

void zebra_l2vpn_svc_handle_dplane_results(struct zebra_dplane_ctx *ctx)
{
	struct zebra_l2vpn_svc *svc;
	struct zebra_vrf *vrf;
	enum dplane_op_e op;

	op = dplane_ctx_get_op(ctx);

	vrf = zebra_vrf_lookup_by_id(dplane_ctx_get_vrf(ctx));
	svc = zebra_l2vpn_svc_find(vrf, dplane_ctx_get_ifname(ctx));

	if (!svc)
		return;

	if (dplane_ctx_get_status(ctx) != ZEBRA_DPLANE_REQUEST_SUCCESS) {
		zebra_l2vpn_svc_install_failure(svc, dplane_ctx_get_l2vpn_svc_status(ctx));
	} else {
		if (op == DPLANE_OP_PW_INSTALL && svc->status != PW_FORWARDING)
			zebra_l2vpn_svc_update_status(svc, PW_FORWARDING);
		else if (op == DPLANE_OP_EVPN_VXLAN_INSTALL && svc->status != EVPN_FORWARDING)
			zebra_l2vpn_svc_update_status(svc, EVPN_FORWARDING);
		else if (op == DPLANE_OP_PW_UNINSTALL && zebra_l2vpn_svc_enabled(svc))
			zebra_l2vpn_svc_update_status(svc, PW_NOT_FORWARDING);
		else if (op == DPLANE_OP_EVPN_VXLAN_UNINSTALL)
			zebra_l2vpn_svc_update_status(svc, svc->data.bgp.local_ac[0]
						      ? EVPN_NOT_FORWARDING : EVPN_LOCAL_TX_FAULT);
	}
}

/*
 * Installation of the pseudowire in the kernel or hardware has failed. This
 * function will notify the pseudowire client about the failure and schedule
 * to retry the installation later. This function can be called by an external
 * agent that performs the pseudowire installation in an asynchronous way.
 */
void zebra_l2vpn_svc_install_failure(struct zebra_l2vpn_svc *svc, int svcstatus)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: failed installing L2VPN %s, scheduling retry in %u seconds",
			   svc->vrf_id, svc->ifname, L2VPN_INSTALL_RETRY_INTERVAL);

	/* schedule to retry later */
	EVENT_OFF(svc->install_retry_timer);
	event_add_timer(zrouter.master, zebra_l2vpn_svc_install_retry, svc,
			L2VPN_INSTALL_RETRY_INTERVAL, &svc->install_retry_timer);

	zebra_l2vpn_svc_update_status(svc, svcstatus);
}

static void zebra_l2vpn_svc_install_retry(struct event *thread)
{
	struct zebra_l2vpn_svc *svc = EVENT_ARG(thread);

	zebra_l2vpn_svc_install(svc);
}

static void zebra_l2vpn_svc_update_status(struct zebra_l2vpn_svc *svc, int status)
{
	svc->status = status;
	if (svc->client)
		zsend_l2vpn_svc_update(svc->client, svc);
}

/* Called to inform an AC or a vxlan interface may have changed
 * - mtu of vxlan or AC changed
 * - AC attached or detached
 */
void zebra_l2vpn_ac_updated(struct interface *ifp, ifindex_t old_bridge_ifindex)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;
	struct zebra_evpn *zevpn;
	struct interface *br_if;
	struct zebra_if *zif;
	enum zebra_slave_iftype zif_slave_type;
	unsigned int mtu;
	struct interface *ifp2;

	zif = (struct zebra_if *)ifp->info;
	if (!zif)
		return;
	zif_slave_type = zif->zif_slave_type;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		RB_FOREACH (svc, zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree) {
			if (!svc->data.bgp.vni)
				continue;
			zevpn = zebra_evpn_lookup(svc->data.bgp.vni);
			if (!zevpn)
				continue;
			if (!zevpn->vxlan_if)
				continue;
			br_if = zevpn->bridge_if;
			if (!br_if)
				continue;
			if (zif_slave_type == ZEBRA_IF_SLAVE_BRIDGE &&
			    zif->brslave_info.bridge_ifindex == br_if->ifindex) {
				if (!IS_ZEBRA_IF_VXLAN(ifp) &&
				    strcmp(svc->data.bgp.local_ac, ifp->name)) {
					/* - new interface attached */
					if (IS_ZEBRA_DEBUG_PW)
						zlog_debug("VPWS VXLAN: AC %s attached to VNI %u",
							   ifp->name, svc->data.bgp.vni);
					zebra_evpn_bgp_vni_check(svc);
					return;
				}
				if (IS_ZEBRA_IF_VXLAN(ifp) &&
				    zevpn->vxlan_if->ifindex != ifp->ifindex)
					/* case where a vxlan interface is an AC is not handled */
					continue;
				if (IS_ZEBRA_IF_VXLAN(ifp)) {
					ifp2 = if_lookup_by_name_all_vrf(svc->data.bgp.local_ac);
					if (!ifp2)
						continue;
					mtu = zevpn->vxlan_if->mtu > ifp2->mtu
						      ? ifp2->mtu
						      : zevpn->vxlan_if->mtu;
				} else
					mtu = zevpn->vxlan_if->mtu > ifp->mtu
						      ? ifp->mtu
						      : zevpn->vxlan_if->mtu;
				if (svc->data.bgp.mtu != mtu) {
					if (IS_ZEBRA_DEBUG_PW)
						zlog_debug("VPWS VXLAN: VNI %u, if %s new MTU %u",
							   svc->data.bgp.vni, ifp->name,
							   mtu);
					svc->data.bgp.mtu = mtu;
				}
				zebra_l2vpn_svc_update_status(svc, svc->status);
			} else if (zif_slave_type == ZEBRA_IF_SLAVE_NONE) {
				/* local AC interface detached */
				if (!strcmp(svc->data.bgp.local_ac, ifp->name)) {
					if (IS_ZEBRA_DEBUG_PW)
						zlog_debug("VPWS VXLAN: AC %s detached from VNI %u",
							   ifp->name, svc->data.bgp.vni);

					memset(&svc->data.bgp.local_ac, 0, IFNAMSIZ);
					if (svc->status == EVPN_FORWARDING)
						zebra_l2vpn_svc_uninstall(svc);
					else
						zebra_evpn_bgp_vni_check(svc);
				} else if (old_bridge_ifindex == br_if->ifindex)
					zebra_evpn_bgp_vni_check(svc);
			}
		}
	}
}

static void zebra_evpn_bgp_vni_check(struct zebra_l2vpn_svc *svc)
{
	int status;
	struct vrf *vrf;
	struct zebra_if *zif;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf;
	struct zebra_evpn *zevpn;
	vni_t vni = svc->data.bgp.vni;
	struct zebra_l2info_brslave *br_slave;
	struct interface *br_if, *ifp, *ifp_match = NULL;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("VPWS VXLAN: validating reachability for VNI %u", vni);

	status = EVPN_LOCAL_TX_FAULT;
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: missing zebra evpn for VNI %u", vni);

		goto out;
	}

	if (strcmp(svc->ifname, zevpn->vxlan_if->name)) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: pseudowire interface %s does not match the vni %u",
				   svc->ifname, vni);

		goto out;
	}

	svc->ifindex = zevpn->vxlan_if->ifindex;
	br_if = zevpn->bridge_if;
	if (!br_if) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: missing bridge for VNI %u", vni);

		goto out;
	}

	zvrf = br_if->vrf->info;
	zns = zvrf->zns;
	memset(&svc->data.bgp.local_ac, 0, IFNAMSIZ);
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->ifindex == IFINDEX_INTERNAL || !ifp->info)
				continue;
			if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp) ||
			    ifp->ifindex == zevpn->vxlan_if->ifindex)
				continue;

			zif = (struct zebra_if *)ifp->info;
			br_slave = &zif->brslave_info;
			if (br_slave->ns_id != zns->ns_id)
				continue;
			if (br_slave->bridge_ifindex != br_if->ifindex)
				continue;

			if (!ifp_match)
				ifp_match = ifp;
			else {
				if (IS_ZEBRA_DEBUG_PW)
					zlog_debug("VPWS VXLAN: multiple ACs for VNI %u", vni);

				goto out;
			}
		}
	}

	if (!ifp_match) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: missing AC for VNI %u", vni);

		goto out;
	}
	svc->data.bgp.mtu = zevpn->vxlan_if->mtu > ifp_match->mtu ? ifp_match->mtu
								  : zevpn->vxlan_if->mtu;

	/* Check AC status */
	strlcpy(svc->data.bgp.local_ac, ifp_match->name, IFNAMSIZ);
	zif = (struct zebra_if *)ifp_match->info;
	if (!zif->es_info.es) {
		/* Single-homed */
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: AC %s is active for VNI %u", ifp_match->name, vni);

		status = EVPN_NOT_FORWARDING;
		memset(&svc->data.bgp.esi, 0, sizeof(esi_t));
	} else {
		memcpy(&svc->data.bgp.esi, &zif->es_info.es->esi, sizeof(esi_t));
		if (CHECK_FLAG(zif->es_info.es->flags, ZEBRA_EVPNES_READY_FOR_BGP))
			status = EVPN_NOT_FORWARDING;

		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("VPWS VXLAN: multihoming AC %s is %s for VNI %u",
				   ifp_match->name, status == EVPN_LOCAL_TX_FAULT ? "inactive"
				   : "active", vni);
	}

out:
	svc->status = status;
	zebra_l2vpn_svc_update_status(svc, status);
}

static int zebra_pw_check_reachability_strict(const struct zebra_l2vpn_svc *svc,
					      struct route_entry *re)
{
	const struct nexthop *nexthop;
	const struct nexthop_group *nhg;
	bool found_p = false;
	bool fail_p = false;

	/* TODO: consider GRE/L2TPv3 tunnels in addition to MPLS LSPs */

	/* All active nexthops must be labelled; look at
	 * primary and backup fib lists, in case there's been
	 * a backup nexthop activation.
	 */
	nhg = rib_get_fib_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				if (nexthop->nh_label != NULL)
					found_p = true;
				else {
					fail_p = true;
					break;
				}
			}
		}
	}

	if (fail_p)
		goto done;

	nhg = rib_get_fib_backup_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				if (nexthop->nh_label != NULL)
					found_p = true;
				else {
					fail_p = true;
					break;
				}
			}
		}
	}

done:

	if (fail_p || !found_p) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: unlabeled route for %s", __func__, svc->ifname);
		return -1;
	}

	return 0;
}

static int zebra_l2vpn_svc_check_reachability(const struct zebra_l2vpn_svc *svc)
{
	struct route_entry *re;
	const struct nexthop *nexthop;
	const struct nexthop_group *nhg;
	bool found_p = false;

	/* TODO: consider VXLAN/GRE/L2TPv3 tunnels in addition to MPLS LSPs */

	/* Find route to the remote end of the pseudowire */
	re = rib_match(family2afi(svc->af), SAFI_UNICAST, svc->vrf_id, &svc->nexthop, NULL);
	if (!re) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: no route found for %s", __func__, svc->ifname);
		return -1;
	}

	/* Stricter checking for some OSes (OBSD, e.g.) */
	if (mpls_pw_reach_strict)
		return zebra_pw_check_reachability_strict(svc, re);

	/* There must be at least one installed labelled nexthop;
	 * look at primary and backup fib lists, in case there's been
	 * a backup nexthop activation.
	 */
	nhg = rib_get_fib_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				continue;

			if (svc->protocol == ZEBRA_ROUTE_BGP && svc->data.bgp.vni) {
				found_p = true;
				break;
			}

			if (nexthop->nh_label != NULL) {
				found_p = true;
				break;
			}
		}
	}

	if (found_p)
		return 0;

	nhg = rib_get_fib_backup_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) &&
			    nexthop->nh_label != NULL) {
				found_p = true;
				break;
			}
		}
	}

	if (!found_p) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: unlabeled route for %s",
				   __func__, svc->ifname);
		return -1;
	}

	return 0;
}

static int zebra_l2vpn_svc_client_close(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc, *tmp;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		RB_FOREACH_SAFE (svc, zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree, tmp) {
			if (svc->client != client)
				continue;
			zebra_l2vpn_svc_del(zvrf, svc);
		}
	}

	return 0;
}

static void zebra_l2vpn_svc_init(void)
{
	hook_register(zserv_client_close, zebra_l2vpn_svc_client_close);
}

void zebra_l2vpn_svc_init_vrf(struct zebra_vrf *zvrf)
{
	RB_INIT(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree);
	RB_INIT(zstatic_l2vpn_svc_head, &zvrf->static_l2vpn_svc_tree);
}

void zebra_l2vpn_svc_exit_vrf(struct zebra_vrf *zvrf)
{
	struct zebra_l2vpn_svc *svc;

	while (!RB_EMPTY(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree)) {
		svc = RB_ROOT(zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree);

		zebra_l2vpn_svc_del(zvrf, svc);
	}
}

void zebra_l2vpn_svc_terminate(void)
{
	hook_unregister(zserv_client_close, zebra_l2vpn_svc_client_close);
}

DEFUN_NOSH (pseudowire_if,
	    pseudowire_if_cmd,
	    "pseudowire IFNAME",
	    "Static pseudowire configuration\n"
	    "Pseudowire name\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;
	const char *ifname;
	int idx = 0;
	union l2vpn_protocol_fields data = {};

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	svc = zebra_l2vpn_svc_find(zvrf, ifname);
	if (svc && svc->protocol != ZEBRA_ROUTE_STATIC) {
		vty_out(vty, "%% Pseudowire is not static\n");
		return CMD_WARNING;
	}

	if (!svc)
		svc = zebra_l2vpn_svc_add(zvrf, ifname, ZEBRA_ROUTE_STATIC, data, NULL);
	VTY_PUSH_CONTEXT(PW_NODE, svc);

	return CMD_SUCCESS;
}

DEFUN (no_pseudowire_if,
       no_pseudowire_if_cmd,
       "no pseudowire IFNAME",
       NO_STR
       "Static pseudowire configuration\n"
       "Pseudowire name\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;
	const char *ifname;
	int idx = 0;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	svc = zebra_l2vpn_svc_find(zvrf, ifname);
	if (svc) {
		if (svc->protocol != ZEBRA_ROUTE_STATIC) {
			vty_out(vty, "%% Pseudowire is not static\n");
			return CMD_WARNING;
		}
		zebra_l2vpn_svc_del(zvrf, svc);
	}

	return CMD_SUCCESS;
}

DEFUN (pseudowire_labels,
       pseudowire_labels_cmd,
       "[no] mpls label local (16-1048575) remote (16-1048575)",
       NO_STR
       "MPLS L2VPN PW command\n"
       "MPLS L2VPN static labels\n"
       "Local pseudowire label\n"
       "Local pseudowire label\n"
       "Remote pseudowire label\n"
       "Remote pseudowire label\n")
{
	VTY_DECLVAR_CONTEXT(zebra_l2vpn_svc, svc);
	int idx = 0;
	mpls_label_t local_label, remote_label;

	if (argv_find(argv, argc, "no", &idx)) {
		local_label = MPLS_NO_LABEL;
		remote_label = MPLS_NO_LABEL;
	} else {
		argv_find(argv, argc, "local", &idx);
		local_label = atoi(argv[idx + 1]->arg);
		argv_find(argv, argc, "remote", &idx);
		remote_label = atoi(argv[idx + 1]->arg);
	}

	zebra_l2vpn_svc_change(svc, svc->ifindex, svc->type, svc->af, &svc->nexthop, local_label,
			       remote_label, svc->flags, &svc->data);

	return CMD_SUCCESS;
}

DEFUN (pseudowire_neighbor,
       pseudowire_neighbor_cmd,
       "[no] neighbor <A.B.C.D|X:X::X:X>",
       NO_STR
       "Specify the IPv4 or IPv6 address of the remote endpoint\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	VTY_DECLVAR_CONTEXT(zebra_l2vpn_svc, svc);
	int idx = 0;
	const char *address;
	int af;
	union g_addr nexthop;

	af = AF_UNSPEC;
	memset(&nexthop, 0, sizeof(nexthop));

	if (!argv_find(argv, argc, "no", &idx)) {
		argv_find(argv, argc, "neighbor", &idx);
		address = argv[idx + 1]->arg;

		if (inet_pton(AF_INET, address, &nexthop.ipv4) == 1)
			af = AF_INET;
		else if (inet_pton(AF_INET6, address, &nexthop.ipv6) == 1)
			af = AF_INET6;
		else {
			vty_out(vty, "%% Malformed address\n");
			return CMD_WARNING;
		}
	}

	zebra_l2vpn_svc_change(svc, svc->ifindex, svc->type, af, &nexthop, svc->local_label,
			       svc->remote_label, svc->flags, &svc->data);

	return CMD_SUCCESS;
}

DEFUN (pseudowire_control_word,
       pseudowire_control_word_cmd,
       "[no] control-word <exclude|include>",
       NO_STR
       "Control-word options\n"
       "Exclude control-word in pseudowire packets\n"
       "Include control-word in pseudowire packets\n")
{
	VTY_DECLVAR_CONTEXT(zebra_l2vpn_svc, svc);
	int idx = 0;
	uint8_t flags = 0;

	if (argv_find(argv, argc, "no", &idx))
		flags = F_PSEUDOWIRE_CWORD;
	else {
		argv_find(argv, argc, "control-word", &idx);
		if (argv[idx + 1]->text[0] == 'i')
			flags = F_PSEUDOWIRE_CWORD;
	}

	zebra_l2vpn_svc_change(svc, svc->ifindex, svc->type, svc->af, &svc->nexthop,
			       svc->local_label, svc->remote_label, flags, &svc->data);

	return CMD_SUCCESS;
}

DEFUN (show_pseudowires,
       show_pseudowires_cmd,
       "show mpls pseudowires",
       SHOW_STR
       MPLS_STR
       "Pseudowires\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	vty_out(vty, "%-16s %-24s %-12s %-8s %-10s\n", "Interface", "Neighbor",
		"Labels", "Protocol", "Status");

	RB_FOREACH (svc, zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree) {
		char buf_nbr[INET6_ADDRSTRLEN];
		char buf_labels[64];

		if (svc->protocol == ZEBRA_ROUTE_BGP && svc->data.bgp.vni)
			continue;

		inet_ntop(svc->af, &svc->nexthop, buf_nbr, sizeof(buf_nbr));

		if (svc->local_label != MPLS_NO_LABEL && svc->remote_label != MPLS_NO_LABEL)
			snprintf(buf_labels, sizeof(buf_labels), "%u/%u", svc->local_label,
				 svc->remote_label);
		else
			snprintf(buf_labels, sizeof(buf_labels), "-");

		vty_out(vty, "%-16s %-24s %-12s %-8s %-10s\n", svc->ifname,
			(svc->af != AF_UNSPEC) ? buf_nbr : "-", buf_labels,
			zebra_route_string(svc->protocol),
			(zebra_l2vpn_svc_enabled(svc) && svc->status == PW_FORWARDING) ? "UP"
										       : "DOWN");
	}

	return CMD_SUCCESS;
}

static void vty_show_mpls_pseudowire_detail(struct vty *vty)
{
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	RB_FOREACH (svc, zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree) {
		char buf_nbr[INET6_ADDRSTRLEN];
		char buf_nh[100];

		vty_out(vty, "Interface: %s\n", svc->ifname);
		inet_ntop(svc->af, &svc->nexthop, buf_nbr, sizeof(buf_nbr));
		vty_out(vty, "  Neighbor: %s\n", (svc->af != AF_UNSPEC) ? buf_nbr : "-");
		if (svc->local_label != MPLS_NO_LABEL)
			vty_out(vty, "  Local Label: %u\n", svc->local_label);
		else
			vty_out(vty, "  Local Label: %s\n", "-");
		if (svc->remote_label != MPLS_NO_LABEL)
			vty_out(vty, "  Remote Label: %u\n", svc->remote_label);
		else
			vty_out(vty, "  Remote Label: %s\n", "-");
		vty_out(vty, "  Protocol: %s\n", zebra_route_string(svc->protocol));
		if (svc->protocol == ZEBRA_ROUTE_LDP)
			vty_out(vty, "  VC-ID: %u\n", svc->data.ldp.pwid);
		vty_out(vty, "  Status: %s \n",
			(zebra_l2vpn_svc_enabled(svc) && svc->status == PW_FORWARDING) ? "Up"
										       : "Down");
		re = rib_match(family2afi(svc->af), SAFI_UNICAST, svc->vrf_id, &svc->nexthop, NULL);
		if (re == NULL)
			continue;

		nhg = rib_get_fib_nhg(re);
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv",
				   nexthop);
			vty_out(vty, "  Next Hop: %s\n", buf_nh);
			if (nexthop->nh_label)
				vty_out(vty, "  Next Hop label: %u\n",
					nexthop->nh_label->label[0]);
			else
				vty_out(vty, "  Next Hop label: %s\n",
					"-");
		}

		/* Include any installed backups */
		nhg = rib_get_fib_backup_nhg(re);
		if (nhg == NULL)
			continue;

		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv",
				   nexthop);
			vty_out(vty, "  Next Hop: %s\n", buf_nh);
			if (nexthop->nh_label)
				vty_out(vty, "  Next Hop label: %u\n",
					nexthop->nh_label->label[0]);
			else
				vty_out(vty, "  Next Hop label: %s\n",
					"-");
		}
	}
}

static void vty_show_mpls_pseudowire(struct zebra_l2vpn_svc *svc, json_object *json_svcs)
{
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;
	char buf_nbr[INET6_ADDRSTRLEN];
	char buf_nh[100];
	json_object *json_svc = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_nexthops = NULL;

	json_nexthops = json_object_new_array();
	json_svc = json_object_new_object();

	json_object_string_add(json_svc, "interface", svc->ifname);
	if (svc->af == AF_UNSPEC)
		json_object_string_add(json_svc, "neighbor", "-");
	else {
		inet_ntop(svc->af, &svc->nexthop, buf_nbr, sizeof(buf_nbr));
		json_object_string_add(json_svc, "neighbor", buf_nbr);
	}
	if (svc->local_label != MPLS_NO_LABEL)
		json_object_int_add(json_svc, "localLabel", svc->local_label);
	else
		json_object_string_add(json_svc, "localLabel", "-");
	if (svc->remote_label != MPLS_NO_LABEL)
		json_object_int_add(json_svc, "remoteLabel", svc->remote_label);
	else
		json_object_string_add(json_svc, "remoteLabel", "-");
	json_object_string_add(json_svc, "protocol", zebra_route_string(svc->protocol));
	if (svc->protocol == ZEBRA_ROUTE_LDP)
		json_object_int_add(json_svc, "vcId", svc->data.ldp.pwid);
	json_object_string_add(json_svc, "Status",
			       (zebra_l2vpn_svc_enabled(svc) && svc->status == PW_FORWARDING)
				       ? "Up"
				       : "Down");
	re = rib_match(family2afi(svc->af), SAFI_UNICAST, svc->vrf_id, &svc->nexthop, NULL);
	if (re == NULL)
		goto done;

	nhg = rib_get_fib_nhg(re);
	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		json_nexthop = json_object_new_object();
		snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv", nexthop);
		json_object_string_add(json_nexthop, "nexthop", buf_nh);
		if (nexthop->nh_label)
			json_object_int_add(
				json_nexthop, "nhLabel",
				nexthop->nh_label->label[0]);
		else
			json_object_string_add(json_nexthop, "nhLabel",
					       "-");

		json_object_array_add(json_nexthops, json_nexthop);
	}

	/* Include installed backup nexthops also */
	nhg = rib_get_fib_backup_nhg(re);
	if (nhg == NULL)
		goto done;

	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		json_nexthop = json_object_new_object();
		snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv", nexthop);
		json_object_string_add(json_nexthop, "nexthop", buf_nh);
		if (nexthop->nh_label)
			json_object_int_add(
				json_nexthop, "nhLabel",
				nexthop->nh_label->label[0]);
		else
			json_object_string_add(json_nexthop, "nhLabel",
					       "-");

		json_object_array_add(json_nexthops, json_nexthop);
	}

done:

	json_object_object_add(json_svc, "nexthops", json_nexthops);
	json_object_array_add(json_svcs, json_svc);
}

static void vty_show_mpls_pseudowire_detail_json(struct vty *vty)
{
	json_object *json = NULL;
	json_object *json_svcs = NULL;
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	json = json_object_new_object();
	json_svcs = json_object_new_array();
	RB_FOREACH (svc, zebra_l2vpn_svc_head, &zvrf->l2vpn_svc_tree) {
		vty_show_mpls_pseudowire(svc, json_svcs);
	}
	json_object_object_add(json, "svc", json_svcs);
	vty_json(vty, json);
}

DEFUN(show_pseudowires_detail, show_pseudowires_detail_cmd,
      "show mpls pseudowires detail [json]$json",
      SHOW_STR MPLS_STR
      "Pseudowires\n"
      "Detailed output\n" JSON_STR)
{
	bool uj = use_json(argc, argv);

	if (uj)
		vty_show_mpls_pseudowire_detail_json(vty);
	else
		vty_show_mpls_pseudowire_detail(vty);

	return CMD_SUCCESS;
}

/* Pseudowire configuration write function. */
static int zebra_l2vpn_svc_config(struct vty *vty)
{
	int write = 0;
	struct zebra_vrf *zvrf;
	struct zebra_l2vpn_svc *svc;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	RB_FOREACH (svc, zstatic_l2vpn_svc_head, &zvrf->static_l2vpn_svc_tree) {
		vty_out(vty, "pseudowire %s\n", svc->ifname);
		if (svc->local_label != MPLS_NO_LABEL && svc->remote_label != MPLS_NO_LABEL)
			vty_out(vty, " mpls label local %u remote %u\n", svc->local_label,
				svc->remote_label);
		else
			vty_out(vty,
				" ! Incomplete config, specify the static MPLS labels\n");

		if (svc->af != AF_UNSPEC) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(svc->af, &svc->nexthop, buf, sizeof(buf));
			vty_out(vty, " neighbor %s\n", buf);
		} else
			vty_out(vty,
				" ! Incomplete config, specify a neighbor address\n");

		if (!(svc->flags & F_PSEUDOWIRE_CWORD))
			vty_out(vty, " control-word exclude\n");

		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
		write = 1;
	}

	return write;
}

static int zebra_l2vpn_svc_config(struct vty *vty);
static struct cmd_node pw_node = {
	.name = "pw",
	.node = PW_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pw)# ",
	.config_write = zebra_l2vpn_svc_config,
};

void zebra_pw_vty_init(void)
{
	install_node(&pw_node);
	install_default(PW_NODE);

	install_element(CONFIG_NODE, &pseudowire_if_cmd);
	install_element(CONFIG_NODE, &no_pseudowire_if_cmd);
	install_element(PW_NODE, &pseudowire_labels_cmd);
	install_element(PW_NODE, &pseudowire_neighbor_cmd);
	install_element(PW_NODE, &pseudowire_control_word_cmd);

	install_element(VIEW_NODE, &show_pseudowires_cmd);
	install_element(VIEW_NODE, &show_pseudowires_detail_cmd);

	zebra_l2vpn_svc_init();
}
