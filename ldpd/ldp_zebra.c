// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 by Open Source Routing.
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "command.h"
#include "network.h"
#include "linklist.h"
#include "mpls.h"

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "ldp_sync.h"
#include "log.h"
#include "ldp_debug.h"

static void	 ifp2kif(struct interface *, struct kif *);
static void	 ifc2kaddr(struct interface *, struct connected *, struct kaddr *);
static int	 ldp_zebra_send_mpls_labels(int, struct kroute *);
static int	 ldp_router_id_update(ZAPI_CALLBACK_ARGS);
static int	 ldp_interface_address_add(ZAPI_CALLBACK_ARGS);
static int	 ldp_interface_address_delete(ZAPI_CALLBACK_ARGS);
static int	 ldp_zebra_read_route(ZAPI_CALLBACK_ARGS);
static int	 ldp_zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS);
static void	 ldp_zebra_connected(struct zclient *);
static void	 ldp_zebra_filter_update(struct access_list *access);

static void 	ldp_zebra_opaque_register(void);
static void 	ldp_zebra_opaque_unregister(void);
static int 	ldp_sync_zebra_send_announce(void);
static int 	ldp_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS);
static void 	ldp_sync_zebra_init(void);

static struct zclient	*zclient;
extern struct zclient *zclient_sync;
static bool zebra_registered = false;

static void
ifp2kif(struct interface *ifp, struct kif *kif)
{
	memset(kif, 0, sizeof(*kif));
	strlcpy(kif->ifname, ifp->name, sizeof(kif->ifname));
	kif->ifindex = ifp->ifindex;
	kif->operative = if_is_operative(ifp);
	if (ifp->ll_type == ZEBRA_LLT_ETHER)
		memcpy(kif->mac, ifp->hw_addr, ETH_ALEN);
}

static void
ifc2kaddr(struct interface *ifp, struct connected *ifc, struct kaddr *ka)
{
	memset(ka, 0, sizeof(*ka));
	strlcpy(ka->ifname, ifp->name, sizeof(ka->ifname));
	ka->ifindex = ifp->ifindex;
	ka->af = ifc->address->family;
	ka->prefixlen = ifc->address->prefixlen;

	switch (ka->af) {
	case AF_INET:
		ka->addr.v4 = ifc->address->u.prefix4;
		if (ifc->destination)
			ka->dstbrd.v4 = ifc->destination->u.prefix4;
		break;
	case AF_INET6:
		ka->addr.v6 = ifc->address->u.prefix6;
		if (ifc->destination)
			ka->dstbrd.v6 = ifc->destination->u.prefix6;
		break;
	default:
		break;
	}
}

void
pw2zpw(struct l2vpn_pw *pw, struct zapi_pw *zpw)
{
	memset(zpw, 0, sizeof(*zpw));
	strlcpy(zpw->ifname, pw->ifname, sizeof(zpw->ifname));
	zpw->ifindex = pw->ifindex;
	zpw->type = pw->l2vpn->pw_type;
	zpw->af = pw->af;
	zpw->nexthop.ipv6 = pw->addr.v6;
	zpw->local_label = NO_LABEL;
	zpw->remote_label = NO_LABEL;
	if (CHECK_FLAG(pw->flags, F_PW_CWORD))
		zpw->flags = F_PSEUDOWIRE_CWORD;
	zpw->data.ldp.lsr_id = pw->lsr_id;
	zpw->data.ldp.pwid = pw->pwid;
	strlcpy(zpw->data.ldp.vpn_name, pw->l2vpn->name,
	    sizeof(zpw->data.ldp.vpn_name));
}

static void
ldp_zebra_opaque_register(void)
{
	zclient_register_opaque(zclient, LDP_IGP_SYNC_IF_STATE_REQUEST);
	zclient_register_opaque(zclient, LDP_RLFA_REGISTER);
	zclient_register_opaque(zclient, LDP_RLFA_UNREGISTER_ALL);
}

static void
ldp_zebra_opaque_unregister(void)
{
	zclient_unregister_opaque(zclient, LDP_IGP_SYNC_IF_STATE_REQUEST);
	zclient_unregister_opaque(zclient, LDP_RLFA_REGISTER);
	zclient_unregister_opaque(zclient, LDP_RLFA_UNREGISTER_ALL);
}

int
ldp_sync_zebra_send_state_update(struct ldp_igp_sync_if_state *state)
{
	if (zclient_send_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE,
				(const uint8_t *)state, sizeof(*state))
	    == ZCLIENT_SEND_FAILURE)
		return -1;
	else
		return 0;
}

static int
ldp_sync_zebra_send_announce(void)
{
	struct ldp_igp_sync_announce announce;
	announce.proto = ZEBRA_ROUTE_LDP;

	if (zclient_send_opaque(zclient, LDP_IGP_SYNC_ANNOUNCE_UPDATE,
				(const uint8_t *)&announce, sizeof(announce))
	    == ZCLIENT_SEND_FAILURE)
		return -1;
	else
		return 0;
}

int ldp_zebra_send_rlfa_labels(struct zapi_rlfa_response *rlfa_labels)
{
	int ret;

	ret = zclient_send_opaque(zclient, LDP_RLFA_LABELS,
				  (const uint8_t *)rlfa_labels,
				  sizeof(*rlfa_labels));
	if (ret == ZCLIENT_SEND_FAILURE) {
		log_warn("failed to send RLFA labels to IGP");
		return -1;
	}

	return 0;
}

static int
ldp_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_msg info;
	struct ldp_igp_sync_if_state_req state_req;
	struct zapi_rlfa_igp igp;
	struct zapi_rlfa_request rlfa;

	s = zclient->ibuf;

	if(zclient_opaque_decode(s, &info) != 0)
		return -1;

	switch (info.type) {
	case LDP_IGP_SYNC_IF_STATE_REQUEST:
		STREAM_GET(&state_req, s, sizeof(state_req));
		main_imsg_compose_ldpe(IMSG_LDP_SYNC_IF_STATE_REQUEST, 0, &state_req,
			    sizeof(state_req));
		break;
	case LDP_RLFA_REGISTER:
		STREAM_GET(&rlfa, s, sizeof(rlfa));
		main_imsg_compose_both(IMSG_RLFA_REG, &rlfa, sizeof(rlfa));
		break;
	case LDP_RLFA_UNREGISTER_ALL:
		STREAM_GET(&igp, s, sizeof(igp));
		main_imsg_compose_both(IMSG_RLFA_UNREG_ALL, &igp, sizeof(igp));
		break;
	default:
		break;
	}

stream_failure:
        return 0;
}

static void
ldp_sync_zebra_init(void)
{
	ldp_sync_zebra_send_announce();
}

static int
ldp_zebra_send_mpls_labels(int cmd, struct kroute *kr)
{
	struct zapi_labels zl = {};
	struct zapi_nexthop *znh;

	if (kr->local_label < MPLS_LABEL_RESERVED_MAX)
		return (0);

	debug_zebra_out("prefix %s/%u nexthop %s ifindex %u labels %s/%s (%s)",
	    log_addr(kr->af, &kr->prefix), kr->prefixlen,
	    log_addr(kr->af, &kr->nexthop), kr->ifindex,
	    log_label(kr->local_label), log_label(kr->remote_label),
	    (cmd == ZEBRA_MPLS_LABELS_ADD) ? "add" : "delete");

	zl.type = ZEBRA_LSP_LDP;
	zl.local_label = kr->local_label;

	/* Set prefix. */
	if (kr->remote_label != NO_LABEL) {
		SET_FLAG(zl.message, ZAPI_LABELS_FTN);
		zl.route.prefix.family = kr->af;
		switch (kr->af) {
		case AF_INET:
			zl.route.prefix.u.prefix4 = kr->prefix.v4;
			break;
		case AF_INET6:
			zl.route.prefix.u.prefix6 = kr->prefix.v6;
			break;
		default:
			fatalx("ldp_zebra_send_mpls_labels: unknown af");
		}
		zl.route.prefix.prefixlen = kr->prefixlen;
		zl.route.type = kr->route_type;
		zl.route.instance = kr->route_instance;
	}

	/* If allow-broken-lsps is enabled then if an lsp is received with
	 * no remote label, instruct the forwarding plane to pop the top-level
	 * label and forward packets normally. This is a best-effort attempt
	 * to deliver labeled IP packets to their final destination (instead of
	 * dropping them).
	 */
	if (kr->remote_label == NO_LABEL
	    && !CHECK_FLAG(ldpd_conf->flags, F_LDPD_ALLOW_BROKEN_LSP)
	    && cmd == ZEBRA_MPLS_LABELS_ADD)
		return 0;

	if (kr->remote_label == NO_LABEL)
		kr->remote_label = MPLS_LABEL_IMPLICIT_NULL;

	/* Set nexthop. */
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	switch (kr->af) {
	case AF_INET:
		znh->gate.ipv4 = kr->nexthop.v4;
		if (kr->ifindex)
			znh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		else
			znh->type = NEXTHOP_TYPE_IPV4;
		break;
	case AF_INET6:
		znh->gate.ipv6 = kr->nexthop.v6;
		if (kr->ifindex)
			znh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		else
			znh->type = NEXTHOP_TYPE_IPV6;
		break;
	default:
		break;
	}
	znh->ifindex = kr->ifindex;
	znh->label_num = 1;
	znh->labels[0] = kr->remote_label;

	if (zebra_send_mpls_labels(zclient, cmd, &zl) == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

int
kr_change(struct kroute *kr)
{
	return (ldp_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, kr));
}

int
kr_delete(struct kroute *kr)
{
	return (ldp_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, kr));
}

int
kmpw_add(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (add)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return zebra_send_pw(zclient, ZEBRA_PW_ADD, zpw) == ZCLIENT_SEND_FAILURE;
}

int
kmpw_del(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (del)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return zebra_send_pw(zclient, ZEBRA_PW_DELETE, zpw) == ZCLIENT_SEND_FAILURE;
}

int
kmpw_set(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s labels %u/%u (set)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop),
	    zpw->local_label, zpw->remote_label);

	return zebra_send_pw(zclient, ZEBRA_PW_SET, zpw) == ZCLIENT_SEND_FAILURE;
}

int
kmpw_unset(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (unset)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return zebra_send_pw(zclient, ZEBRA_PW_UNSET, zpw) == ZCLIENT_SEND_FAILURE;
}

void
kif_redistribute(const char *ifname)
{
	struct vrf		*vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface	*ifp;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (ifname && strcmp(ifname, ifp->name) != 0)
			continue;

		ifp2kif(ifp, &kif);
		main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

		frr_each (if_connected, ifp->connected, ifc) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka, sizeof(ka));
		}
	}
}

static int
ldp_router_id_update(ZAPI_CALLBACK_ARGS)
{
	struct prefix	 router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (bad_addr_v4(router_id.u.prefix4))
		return (0);

	debug_zebra_in("router-id update %pI4", &router_id.u.prefix4);

	global.rtr_id.s_addr = router_id.u.prefix4.s_addr;
	main_imsg_compose_ldpe(IMSG_RTRID_UPDATE, 0, &global.rtr_id,
	    sizeof(global.rtr_id));

	return (0);
}

static int
ldp_ifp_create(struct interface *ifp)
{
	struct kif		 kif;

	debug_zebra_in("interface add %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return 0;
}

static int
ldp_ifp_destroy(struct interface *ifp)
{
	struct kif		 kif;

	debug_zebra_in("interface delete %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return (0);
}

static int
ldp_interface_status_change(struct interface *ifp)
{
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	debug_zebra_in("interface %s state update", ifp->name);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	if (if_is_operative(ifp)) {
		frr_each (if_connected, ifp->connected, ifc) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka, sizeof(ka));
		}
	} else {
		frr_each (if_connected, ifp->connected, ifc) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka, sizeof(ka));
		}
	}

	return (0);
}

static int ldp_ifp_up(struct interface *ifp)
{
	return ldp_interface_status_change(ifp);
}

static int ldp_ifp_down(struct interface *ifp)
{
	return ldp_interface_status_change(ifp);
}

static int
ldp_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address add %s/%u interface %s",
	    log_addr(ka.af, &ka.addr), ka.prefixlen, ifp->name);

	/* notify ldpe about new address */
	main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);
	connected_free(&ifc);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address delete %s/%u interface %s",
	    log_addr(ka.af, &ka.addr), ka.prefixlen, ifp->name);

	/* notify ldpe about removed address */
	main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route	 api;
	struct zapi_nexthop	*api_nh;
	struct kroute		 kr;
	int			 i, add = 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return (0);

	memset(&kr, 0, sizeof(kr));
	kr.af = api.prefix.family;
	switch (kr.af) {
	case AF_INET:
		kr.prefix.v4 = api.prefix.u.prefix4;
		break;
	case AF_INET6:
		kr.prefix.v6 = api.prefix.u.prefix6;
		break;
	default:
		break;
	}
	kr.prefixlen = api.prefix.prefixlen;
	kr.route_type = api.type;
	kr.route_instance = api.instance;

	switch (api.type) {
	case ZEBRA_ROUTE_CONNECT:
		SET_FLAG(kr.flags, F_CONNECTED);
		break;
	case ZEBRA_ROUTE_BGP:
		/* LDP should follow the IGP and ignore BGP routes */
		return (0);
	default:
		break;
	}

	if (bad_addr(kr.af, &kr.prefix) ||
	    (kr.af == AF_INET6 && IN6_IS_SCOPE_EMBED(&kr.prefix.v6)))
		return (0);

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		add = 1;

	if (api.nexthop_num == 0)
		debug_zebra_in("route %s %s/%d (%s)", (add) ? "add" : "delete",
		    log_addr(kr.af, &kr.prefix), kr.prefixlen,
		    zebra_route_string(api.type));

	/* loop through all the nexthops */
	for (i = 0; i < api.nexthop_num; i++) {
		api_nh = &api.nexthops[i];
		switch (api_nh->type) {
		case NEXTHOP_TYPE_IPV4:
			if (kr.af != AF_INET)
				continue;
			kr.nexthop.v4 = api_nh->gate.ipv4;
			kr.ifindex = 0;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			if (kr.af != AF_INET)
				continue;
			kr.nexthop.v4 = api_nh->gate.ipv4;
			kr.ifindex = api_nh->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			if (kr.af != AF_INET6)
				continue;
			kr.nexthop.v6 = api_nh->gate.ipv6;
			kr.ifindex = 0;
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (kr.af != AF_INET6)
				continue;
			kr.nexthop.v6 = api_nh->gate.ipv6;
			kr.ifindex = api_nh->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			if (!CHECK_FLAG(kr.flags, F_CONNECTED))
				continue;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			continue;
		}

		debug_zebra_in("route %s %s/%d nexthop %s ifindex %u (%s)",
		    (add) ? "add" : "delete", log_addr(kr.af, &kr.prefix),
		    kr.prefixlen, log_addr(kr.af, &kr.nexthop), kr.ifindex,
		    zebra_route_string(api.type));

		if (add)
			main_imsg_compose_lde(IMSG_NETWORK_ADD, 0, &kr, sizeof(kr));
	}

	main_imsg_compose_lde(IMSG_NETWORK_UPDATE, 0, &kr, sizeof(kr));

	return (0);
}

/*
 * Receive PW status update from Zebra and send it to LDE process.
 */
static int
ldp_zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS)
{
	struct zapi_pw_status	 zpw;

	zebra_read_pw_status_update(cmd, zclient, length, vrf_id, &zpw);

	debug_zebra_in("pseudowire %s status %s 0x%x", zpw.ifname,
	    (zpw.status == PW_FORWARDING) ? "up" : "down",
	    zpw.status);

	main_imsg_compose_lde(IMSG_PW_UPDATE, 0, &zpw, sizeof(zpw));

	return (0);
}

void ldp_zebra_regdereg_zebra_info(bool want_register)
{
	if (zebra_registered == want_register)
		return;

	log_debug("%s to receive default VRF information",
		  want_register ? "Register" : "De-register");

	if (want_register) {
		zclient_send_reg_requests(zclient, VRF_DEFAULT);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
					ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient,
					AFI_IP6, ZEBRA_ROUTE_ALL, 0,
					VRF_DEFAULT);
	} else {
		zclient_send_dereg_requests(zclient, VRF_DEFAULT);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, ZEBRA_ROUTE_ALL, 0,
					VRF_DEFAULT);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, ZEBRA_ROUTE_ALL, 0,
					VRF_DEFAULT);
	}
	zebra_registered = want_register;
}

static void
ldp_zebra_connected(struct zclient *zclient)
{
	zebra_registered = false;

	/* if MPLS was already enabled and we are re-connecting, register again
	 */
	if (CHECK_FLAG(vty_conf->flags, F_LDPD_ENABLED))
		ldp_zebra_regdereg_zebra_info(true);

	ldp_zebra_opaque_register();

	ldp_sync_zebra_init();
}

static void
ldp_zebra_filter_update(struct access_list *access)
{
	struct ldp_access laccess;

	if (access && access->name[0] != '\0') {
		strlcpy(laccess.name, access->name, sizeof(laccess.name));
		debug_evt("%s ACL update filter name %s", __func__, access->name);

		main_imsg_compose_both(IMSG_FILTER_UPDATE, &laccess, sizeof(laccess));
	}
}

extern struct zebra_privs_t ldpd_privs;

static zclient_handler *const ldp_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = ldp_router_id_update,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = ldp_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = ldp_interface_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = ldp_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = ldp_zebra_read_route,
	[ZEBRA_PW_STATUS_UPDATE] = ldp_zebra_read_pw_status_update,
	[ZEBRA_OPAQUE_MESSAGE] = ldp_zebra_opaque_msg_handler,
};

void ldp_zebra_init(struct event_loop *master)
{
	hook_register_prio(if_real, 0, ldp_ifp_create);
	hook_register_prio(if_up, 0, ldp_ifp_up);
	hook_register_prio(if_down, 0, ldp_ifp_down);
	hook_register_prio(if_unreal, 0, ldp_ifp_destroy);

	/* Set default values. */
	zclient = zclient_new(master, &zclient_options_default, ldp_handlers,
			      array_size(ldp_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_LDP, 0, &ldpd_privs);

	/* set callbacks */
	zclient->zebra_connected = ldp_zebra_connected;

	/* Access list initialize. */
	access_list_add_hook(ldp_zebra_filter_update);
	access_list_delete_hook(ldp_zebra_filter_update);
}

void
ldp_zebra_destroy(void)
{
	ldp_zebra_opaque_unregister();
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;

	if (zclient_sync == NULL)
		return;
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
	zclient_sync = NULL;
}
