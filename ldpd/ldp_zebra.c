/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
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
#include "log.h"
#include "ldp_debug.h"

static void	 ifp2kif(struct interface *, struct kif *);
static void	 ifc2kaddr(struct interface *, struct connected *,
		    struct kaddr *);
static int	 zebra_send_mpls_labels(int, struct kroute *);
static int	 ldp_router_id_update(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_add(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_delete(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_status_change(int command, struct zclient *,
		    zebra_size_t, vrf_id_t);
static int	 ldp_interface_address_add(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_address_delete(int, struct zclient *,
		    zebra_size_t, vrf_id_t);
static int	 ldp_zebra_read_route(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_zebra_read_pw_status_update(int, struct zclient *,
		    zebra_size_t, vrf_id_t);
static void	 ldp_zebra_connected(struct zclient *);

static struct zclient	*zclient;

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
	if (pw->flags & F_PW_CWORD)
		zpw->flags = F_PSEUDOWIRE_CWORD;
	zpw->data.ldp.lsr_id = pw->lsr_id;
	zpw->data.ldp.pwid = pw->pwid;
	strlcpy(zpw->data.ldp.vpn_name, pw->l2vpn->name,
	    sizeof(zpw->data.ldp.vpn_name));
}

static int
zebra_send_mpls_labels(int cmd, struct kroute *kr)
{
	struct stream		*s;

	if (kr->local_label < MPLS_LABEL_RESERVED_MAX ||
	    kr->remote_label == NO_LABEL)
		return (0);

	debug_zebra_out("prefix %s/%u nexthop %s ifindex %u labels %s/%s (%s)",
	    log_addr(kr->af, &kr->prefix), kr->prefixlen,
	    log_addr(kr->af, &kr->nexthop), kr->ifindex,
	    log_label(kr->local_label), log_label(kr->remote_label),
	    (cmd == ZEBRA_MPLS_LABELS_ADD) ? "add" : "delete");

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putc(s, ZEBRA_LSP_LDP);
	stream_putl(s, kr->af);
	switch (kr->af) {
	case AF_INET:
		stream_put_in_addr(s, &kr->prefix.v4);
		stream_putc(s, kr->prefixlen);
		stream_put_in_addr(s, &kr->nexthop.v4);
		break;
	case AF_INET6:
		stream_write(s, (u_char *)&kr->prefix.v6, 16);
		stream_putc(s, kr->prefixlen);
		stream_write(s, (u_char *)&kr->nexthop.v6, 16);
		break;
	default:
		fatalx("kr_change: unknown af");
	}
	stream_putl(s, kr->ifindex);
	stream_putc(s, kr->priority);
	stream_putl(s, kr->local_label);
	stream_putl(s, kr->remote_label);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return (zclient_send_message(zclient));
}

int
kr_change(struct kroute *kr)
{
	return (zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, kr));
}

int
kr_delete(struct kroute *kr)
{
	return (zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, kr));
}

int
kmpw_add(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (add)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_ADD, zpw));
}

int
kmpw_del(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (del)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_DELETE, zpw));
}

int
kmpw_set(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s labels %u/%u (set)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop),
	    zpw->local_label, zpw->remote_label);

	return (zebra_send_pw(zclient, ZEBRA_PW_SET, zpw));
}

int
kmpw_unset(struct zapi_pw *zpw)
{
	debug_zebra_out("pseudowire %s nexthop %s (unset)",
	    zpw->ifname, log_addr(zpw->af, (union ldpd_addr *)&zpw->nexthop));

	return (zebra_send_pw(zclient, ZEBRA_PW_UNSET, zpw));
}

void
kif_redistribute(const char *ifname)
{
	struct vrf		*vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct listnode		*cnode;
	struct interface	*ifp;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		if (ifname && strcmp(ifname, ifp->name) != 0)
			continue;

		ifp2kif(ifp, &kif);
		main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	}
}

static int
ldp_router_id_update(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct prefix	 router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (bad_addr_v4(router_id.u.prefix4))
		return (0);

	debug_zebra_in("router-id update %s", inet_ntoa(router_id.u.prefix4));

	global.rtr_id.s_addr = router_id.u.prefix4.s_addr;
	main_imsg_compose_ldpe(IMSG_RTRID_UPDATE, 0, &global.rtr_id,
	    sizeof(global.rtr_id));

	return (0);
}

static int
ldp_interface_add(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct interface	*ifp;
	struct kif		 kif;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	debug_zebra_in("interface add %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return (0);
}

static int
ldp_interface_delete(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct interface	*ifp;
	struct kif		 kif;

	/* zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return (0);

	debug_zebra_in("interface delete %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	/* To support pseudo interface do not free interface structure.  */
	/* if_delete(ifp); */
	if_set_index(ifp, IFINDEX_INTERNAL);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	return (0);
}

static int
ldp_interface_status_change(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface	*ifp;
	struct listnode		*node;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	/*
	 * zebra_interface_state_read() updates interface structure in
	 * iflist.
	 */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return (0);

	debug_zebra_in("interface %s state update", ifp->name);

	ifp2kif(ifp, &kif);
	main_imsg_compose_both(IMSG_IFSTATUS, &kif, sizeof(kif));

	if (if_is_operative(ifp)) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	} else {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka,
			    sizeof(ka));
		}
	}

	return (0);
}

static int
ldp_interface_address_add(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
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
ldp_interface_address_delete(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);
	connected_free(ifc);

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
ldp_zebra_read_route(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
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
	kr.priority = api.distance;

	switch (api.type) {
	case ZEBRA_ROUTE_CONNECT:
		kr.flags |= F_CONNECTED;
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

	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		add = 1;

	if (api.nexthop_num == 0)
		debug_zebra_in("route %s %s/%d (%s)", (add) ? "add" : "delete",
		    log_addr(kr.af, &kr.prefix), kr.prefixlen,
		    zebra_route_string(api.type));

	/* loop through all the nexthops */
	for (i = 0; i < api.nexthop_num; i++) {
		api_nh = &api.nexthops[i];

		switch (kr.af) {
		case AF_INET:
			kr.nexthop.v4 = api_nh->gate.ipv4;
			break;
		case AF_INET6:
			kr.nexthop.v6 = api_nh->gate.ipv6;
			break;
		default:
			break;
		}
		kr.ifindex = api_nh->ifindex;;

		debug_zebra_in("route %s %s/%d nexthop %s ifindex %u (%s)",
		    (add) ? "add" : "delete", log_addr(kr.af, &kr.prefix),
		    kr.prefixlen, log_addr(kr.af, &kr.nexthop), kr.ifindex,
		    zebra_route_string(api.type));

		if (add)
			main_imsg_compose_lde(IMSG_NETWORK_ADD, 0, &kr,
			    sizeof(kr));
	}

	main_imsg_compose_lde(IMSG_NETWORK_UPDATE, 0, &kr, sizeof(kr));

	return (0);
}

/*
 * Receive PW status update from Zebra and send it to LDE process.
 */
static int
ldp_zebra_read_pw_status_update(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_pw_status	 zpw;

	zebra_read_pw_status_update(command, zclient, length, vrf_id, &zpw);

	debug_zebra_in("pseudowire %s status %s", zpw.ifname,
	    (zpw.status == PW_STATUS_UP) ? "up" : "down");

	main_imsg_compose_lde(IMSG_PW_UPDATE, 0, &zpw, sizeof(zpw));

	return (0);
}

static void
ldp_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
}

void
ldp_zebra_init(struct thread_master *master)
{
	/* Set default values. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_LDP, 0);

	/* set callbacks */
	zclient->zebra_connected = ldp_zebra_connected;
	zclient->router_id_update = ldp_router_id_update;
	zclient->interface_add = ldp_interface_add;
	zclient->interface_delete = ldp_interface_delete;
	zclient->interface_up = ldp_interface_status_change;
	zclient->interface_down = ldp_interface_status_change;
	zclient->interface_address_add = ldp_interface_address_add;
	zclient->interface_address_delete = ldp_interface_address_delete;
	zclient->redistribute_route_add = ldp_zebra_read_route;
	zclient->redistribute_route_del = ldp_zebra_read_route;
	zclient->pw_status_update = ldp_zebra_read_pw_status_update;
}

void
ldp_zebra_destroy(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}
