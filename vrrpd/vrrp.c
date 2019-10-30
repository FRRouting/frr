/*
 * VRRP global definitions and state machine.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/hash.h"
#include "lib/hook.h"
#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/sockopt.h"
#include "lib/sockunion.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "vrrp.h"
#include "vrrp_arp.h"
#include "vrrp_debug.h"
#include "vrrp_ndisc.h"
#include "vrrp_packet.h"
#include "vrrp_zebra.h"

#define VRRP_LOGPFX "[CORE] "

DEFINE_MTYPE_STATIC(VRRPD, VRRP_IP, "VRRP IP address")
DEFINE_MTYPE_STATIC(VRRPD, VRRP_RTR, "VRRP Router")

/* statics */
struct hash *vrrp_vrouters_hash;
bool vrrp_autoconfig_is_on;
int vrrp_autoconfig_version;

struct vrrp_defaults vd;

const char *vrrp_state_names[3] = {
	[VRRP_STATE_INITIALIZE] = "Initialize",
	[VRRP_STATE_MASTER] = "Master",
	[VRRP_STATE_BACKUP] = "Backup",
};

const char *vrrp_event_names[2] = {
	[VRRP_EVENT_STARTUP] = "Startup",
	[VRRP_EVENT_SHUTDOWN] = "Shutdown",
};


/* Utility functions ------------------------------------------------------- */

/*
 * Sets an ethaddr to RFC-defined Virtual Router MAC address.
 *
 * mac
 *    ethaddr to set
 *
 * v6
 *    Whether this is a V6 or V4 Virtual Router MAC
 *
 * vrid
 *    Virtual Router Identifier
 */
static void vrrp_mac_set(struct ethaddr *mac, bool v6, uint8_t vrid)
{
	/*
	 * V4: 00-00-5E-00-01-{VRID}
	 * V6: 00-00-5E-00-02-{VRID}
	 */
	mac->octet[0] = 0x00;
	mac->octet[1] = 0x00;
	mac->octet[2] = 0x5E;
	mac->octet[3] = 0x00;
	mac->octet[4] = v6 ? 0x02 : 0x01;
	mac->octet[5] = vrid;
}

/*
 * Recalculates and sets skew_time and master_down_interval based
 * values.
 *
 * r
 *   VRRP Router to operate on
 */
static void vrrp_recalculate_timers(struct vrrp_router *r)
{
	uint16_t mdiadv = r->vr->version == 3 ? r->master_adver_interval
					      : r->vr->advertisement_interval;
	uint16_t skm = (r->vr->version == 3) ? r->master_adver_interval : 100;

	r->skew_time = ((256 - r->vr->priority) * skm) / 256;
	r->master_down_interval = 3 * mdiadv;
	r->master_down_interval += r->skew_time;
}

/*
 * Determines if a VRRP router is the owner of the specified address.
 *
 * The determining factor for whether an interface is the address owner is
 * simply whether the address is assigned to the VRRP base interface by someone
 * other than vrrpd.
 *
 * This function should always return the correct answer regardless of
 * master/backup status.
 *
 * ifp
 *    The interface to check owernship of. This should be the base interface of
 *    a VRRP router.
 *
 * vr
 *    Virtual Router
 *
 * Returns:
 *    whether or not vr owns the specified address
 */
static bool vrrp_is_owner(struct interface *ifp, struct ipaddr *addr)
{
	/*
	 * This code sanity checks implicit ownership configuration. Ideally,
	 * the way we determine address ownership status for this VRRP router
	 * is by looking at whether our VIPs are also assigned to the base
	 * interface, and therefore count as "real" addresses. This frees the
	 * user from having to manually configure priority 255 to indicate
	 * address ownership. However, this means one of the VIPs will be used
	 * as the source address for VRRP advertisements, which in turn means
	 * that other VRRP routers will be receiving packets with a source
	 * address they themselves have. This causes lots of different issues
	 * so for now we're disabling this and forcing the user to configure
	 * priority 255 to indicate ownership.
	 */

	return false;

#if 0
	struct prefix p;

	p.family = IS_IPADDR_V4(addr) ? AF_INET : AF_INET6;
	p.prefixlen = IS_IPADDR_V4(addr) ? IPV4_MAX_BITLEN : IPV6_MAX_BITLEN;
	memcpy(&p.u, &addr->ip, sizeof(addr->ip));

	return !!connected_lookup_prefix_exact(ifp, &p);
#endif
}

/*
 * Whether an interface has a MAC address that matches the VRRP RFC.
 *
 * ifp
 *    Interface to check
 *
 * Returns:
 *    Whether the interface has a VRRP mac or not
 */
static bool vrrp_ifp_has_vrrp_mac(struct interface *ifp)
{
	struct ethaddr vmac4;
	struct ethaddr vmac6;

	vrrp_mac_set(&vmac4, 0, 0x00);
	vrrp_mac_set(&vmac6, 1, 0x00);

	return !memcmp(ifp->hw_addr, vmac4.octet, sizeof(vmac4.octet) - 1)
	       || !memcmp(ifp->hw_addr, vmac6.octet, sizeof(vmac6.octet) - 1);
}

/*
 * Lookup a Virtual Router instance given a macvlan subinterface.
 *
 * The VRID is extracted from the interface MAC and the 2-tuple (iface, vrid)
 * is used to look up any existing instances that match the interface. It does
 * not matter whether the instance is already bound to the interface or not.
 *
 * mvl_ifp
 *    Interface pointer to use to lookup. Should be a macvlan device.
 *
 * Returns:
 *    Virtual Router, if found
 *    NULL otherwise
 */
static struct vrrp_vrouter *vrrp_lookup_by_if_mvl(struct interface *mvl_ifp)
{
	struct interface *p;

	if (!mvl_ifp || mvl_ifp->link_ifindex == 0
	    || !vrrp_ifp_has_vrrp_mac(mvl_ifp)) {
		if (mvl_ifp && mvl_ifp->link_ifindex == 0)
			DEBUGD(&vrrp_dbg_zebra,
			       VRRP_LOGPFX
			       "Interface %s has no parent ifindex; disregarding",
			       mvl_ifp->name);
		if (mvl_ifp && !vrrp_ifp_has_vrrp_mac(mvl_ifp))
			DEBUGD(&vrrp_dbg_zebra,
			       VRRP_LOGPFX
			       "Interface %s has a non-VRRP MAC; disregarding",
			       mvl_ifp->name);
		return NULL;
	}

	p = if_lookup_by_index(mvl_ifp->link_ifindex, VRF_DEFAULT);
	uint8_t vrid = mvl_ifp->hw_addr[5];

	return vrrp_lookup(p, vrid);
}

/*
 * Lookup the Virtual Router instances configured on a particular interface.
 *
 * ifp
 *    Interface pointer to use to lookup. Should not be a macvlan device.
 *
 * Returns:
 *    List of virtual routers found
 */
static struct list *vrrp_lookup_by_if(struct interface *ifp)
{
	struct list *l = hash_to_list(vrrp_vrouters_hash);
	struct listnode *ln, *nn;
	struct vrrp_vrouter *vr;

	for (ALL_LIST_ELEMENTS(l, ln, nn, vr))
		if (vr->ifp != ifp)
			list_delete_node(l, ln);

	return l;
}

/*
 * Lookup any Virtual Router instances associated with a particular interface.
 * This is a combination of the results from vrrp_lookup_by_if_mvl and
 * vrrp_lookup_by_if.
 *
 * Suppose the system interface list looks like the following:
 *
 * eth0
 * \- eth0-v0 00:00:5e:00:01:01
 * \- eth0-v1 00:00:5e:00:02:01
 * \- eth0-v2 00:00:5e:00:01:0a
 *
 * Passing eth0-v2 to this function will give you the VRRP instance configured
 * on eth0 with VRID 10. Passing eth0-v0 or eth0-v1 will give you the VRRP
 * instance configured on eth0 with VRID 1. Passing eth0 will give you both.
 *
 * ifp
 *    Interface pointer to use to lookup. Can be any interface.
 *
 * Returns:
 *    List of virtual routers found
 */
static struct list *vrrp_lookup_by_if_any(struct interface *ifp)
{
	struct vrrp_vrouter *vr;
	struct list *vrs;

	vr = vrrp_lookup_by_if_mvl(ifp);
	vrs = vr ? list_new() : vrrp_lookup_by_if(ifp);

	if (vr)
		listnode_add(vrs, vr);

	return vrs;
}

/* Configuration controllers ----------------------------------------------- */

void vrrp_check_start(struct vrrp_vrouter *vr)
{
	struct vrrp_router *r;
	bool start;
	const char *whynot = NULL;

	if (vr->shutdown || vr->ifp == NULL)
		return;

	r = vr->v4;
	/* Must not already be started */
	start = r->fsm.state == VRRP_STATE_INITIALIZE;
	whynot = (!start && !whynot) ? "Already running" : whynot;
	/* Must have a parent interface */
	start = start && (vr->ifp != NULL);
	whynot = (!start && !whynot) ? "No base interface" : whynot;
#if 0
	/* Parent interface must be up */
	start = start && if_is_operative(vr->ifp);
	start = (!start && !whynot) ? "Base interface inoperative" : whynot;
#endif
	/* Parent interface must have at least one v4 */
	start = start && connected_count_by_family(vr->ifp, AF_INET) > 0;
	whynot = (!start && !whynot) ? "No primary IPv4 address" : whynot;
	/* Must have a macvlan interface */
	start = start && (r->mvl_ifp != NULL);
	whynot = (!start && !whynot) ? "No VRRP interface" : whynot;
#if 0
	/* Macvlan interface must be admin up */
	start = start && CHECK_FLAG(r->mvl_ifp->flags, IFF_UP);
	start = (!start && !whynot) ? "Macvlan device admin down" : whynot;
#endif
	/* Must have at least one VIP configured */
	start = start && r->addrs->count > 0;
	whynot = (!start && !whynot) ? "No Virtual IP address configured"
				     : whynot;
	if (start)
		vrrp_event(r, VRRP_EVENT_STARTUP);
	else if (whynot)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Refusing to start Virtual Router: %s",
			  vr->vrid, family2str(r->family), whynot);

	whynot = NULL;

	r = vr->v6;
	/* Must not already be started */
	start = r->fsm.state == VRRP_STATE_INITIALIZE;
	whynot = (!start && !whynot) ? "Already running" : whynot;
	/* Must not be v2 */
	start = start && vr->version != 2;
	whynot = (!start && !whynot) ? "VRRPv2 does not support v6" : whynot;
	/* Must have a parent interface */
	start = start && (vr->ifp != NULL);
	whynot = (!start && !whynot) ? "No base interface" : whynot;
#if 0
	/* Parent interface must be up */
	start = start && if_is_operative(vr->ifp);
	start = (!start && !whynot) ? "Base interface inoperative" : whynot;
#endif
	/* Must have a macvlan interface */
	start = start && (r->mvl_ifp != NULL);
	whynot = (!start && !whynot) ? "No VRRP interface" : whynot;
#if 0
	/* Macvlan interface must be admin up */
	start = start && CHECK_FLAG(r->mvl_ifp->flags, IFF_UP);
	start = (!start && !whynot) ? "Macvlan device admin down" : whynot;
	/* Macvlan interface must have a link local */
	start = start && connected_get_linklocal(r->mvl_ifp);
	whynot =
		(!start && !whynot) ? "No link local address configured" : whynot;
	/* Macvlan interface must have a v6 IP besides the link local */
	start = start && (connected_count_by_family(r->mvl_ifp, AF_INET6) > 1);
	whynot = (!start && !whynot)
			 ? "No Virtual IPv6 address configured on macvlan device"
			 : whynot;
#endif
	/* Must have at least one VIP configured */
	start = start && r->addrs->count > 0;
	whynot =
		(!start && !whynot) ? "No Virtual IP address configured" : whynot;
	if (start)
		vrrp_event(r, VRRP_EVENT_STARTUP);
	else if (whynot)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Refusing to start Virtual Router: %s",
			  vr->vrid, family2str(r->family), whynot);
}

void vrrp_set_priority(struct vrrp_vrouter *vr, uint8_t priority)
{
	vr->priority = priority;
	vr->v4->priority = priority;
	vr->v6->priority = priority;
}

void vrrp_set_advertisement_interval(struct vrrp_vrouter *vr,
				     uint16_t advertisement_interval)
{
	if (vr->advertisement_interval == advertisement_interval)
		return;

	vr->advertisement_interval = advertisement_interval;
	vrrp_recalculate_timers(vr->v4);
	vrrp_recalculate_timers(vr->v6);
}

static bool vrrp_has_ip(struct vrrp_vrouter *vr, struct ipaddr *ip)
{
	struct vrrp_router *r = ip->ipa_type == IPADDR_V4 ? vr->v4 : vr->v6;
	struct listnode *ln;
	struct ipaddr *iter;

	for (ALL_LIST_ELEMENTS_RO(r->addrs, ln, iter))
		if (!memcmp(&iter->ip, &ip->ip, IPADDRSZ(ip)))
			return true;

	return false;
}

int vrrp_add_ip(struct vrrp_router *r, struct ipaddr *ip)
{
	int af = (ip->ipa_type == IPADDR_V6) ? AF_INET6 : AF_INET;

	assert(r->family == af);
	assert(!(r->vr->version == 2 && ip->ipa_type == IPADDR_V6));

	if (vrrp_has_ip(r->vr, ip))
		return 0;

	if (!vrrp_is_owner(r->vr->ifp, ip) && r->is_owner) {
		char ipbuf[INET6_ADDRSTRLEN];

		inet_ntop(r->family, &ip->ip, ipbuf, sizeof(ipbuf));
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"This VRRP router is not the address owner of %s, but is the address owner of other addresses; this config is unsupported.",
			r->vr->vrid, family2str(r->family), ipbuf);
		return -1;
	}

	struct ipaddr *new = XCALLOC(MTYPE_VRRP_IP, sizeof(struct ipaddr));

	*new = *ip;
	listnode_add(r->addrs, new);

	if (r->fsm.state == VRRP_STATE_MASTER) {
		switch (r->family) {
		case AF_INET:
			vrrp_garp_send(r, &new->ipaddr_v4);
			break;
		case AF_INET6:
			vrrp_ndisc_una_send(r, new);
			break;
		}
	}

	return 0;
}

int vrrp_add_ipv4(struct vrrp_vrouter *vr, struct in_addr v4)
{
	struct ipaddr ip;

	ip.ipa_type = IPADDR_V4;
	ip.ipaddr_v4 = v4;
	return vrrp_add_ip(vr->v4, &ip);
}

int vrrp_add_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6)
{
	assert(vr->version != 2);

	struct ipaddr ip;

	ip.ipa_type = IPADDR_V6;
	ip.ipaddr_v6 = v6;
	return vrrp_add_ip(vr->v6, &ip);
}

int vrrp_del_ip(struct vrrp_router *r, struct ipaddr *ip)
{
	struct listnode *ln, *nn;
	struct ipaddr *iter;
	int ret = 0;

	if (!vrrp_has_ip(r->vr, ip))
		return 0;

	for (ALL_LIST_ELEMENTS(r->addrs, ln, nn, iter))
		if (!memcmp(&iter->ip, &ip->ip, IPADDRSZ(ip)))
			list_delete_node(r->addrs, ln);

	/*
	 * NB: Deleting the last address and then issuing a shutdown will cause
	 * transmission of a priority 0 VRRP Advertisement - as per the RFC -
	 * but it will have no addresses. This is not forbidden in the RFC but
	 * might confuse other implementations.
	 */
	if (r->addrs->count == 0 && r->fsm.state != VRRP_STATE_INITIALIZE)
		ret = vrrp_event(r, VRRP_EVENT_SHUTDOWN);

	return ret;
}

int vrrp_del_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6)
{
	struct ipaddr ip;

	ip.ipa_type = IPADDR_V6;
	ip.ipaddr_v6 = v6;
	return vrrp_del_ip(vr->v6, &ip);
}

int vrrp_del_ipv4(struct vrrp_vrouter *vr, struct in_addr v4)
{
	struct ipaddr ip;

	ip.ipa_type = IPADDR_V4;
	ip.ipaddr_v4 = v4;
	return vrrp_del_ip(vr->v4, &ip);
}


/* Creation and destruction ------------------------------------------------ */

static void vrrp_router_addr_list_del_cb(void *val)
{
	struct ipaddr *ip = val;

	XFREE(MTYPE_VRRP_IP, ip);
}

/*
 * Search for a suitable macvlan subinterface we can attach to, and if found,
 * attach to it.
 *
 * r
 *    Router to attach to interface
 *
 * Returns:
 *    Whether an interface was successfully attached
 */
static bool vrrp_attach_interface(struct vrrp_router *r)
{
	/* Search for existing interface with computed MAC address */
	struct interface **ifps;

	size_t ifps_cnt = if_lookup_by_hwaddr(
		r->vmac.octet, sizeof(r->vmac.octet), &ifps, VRF_DEFAULT);

	/*
	 * Filter to only those macvlan interfaces whose parent is the base
	 * interface this VRRP router is configured on.
	 *
	 * If there are still multiple interfaces we just select the first one,
	 * as it should be functionally identical to the others.
	 */
	unsigned int candidates = 0;
	struct interface *selection = NULL;

	for (unsigned int i = 0; i < ifps_cnt; i++) {
		if (ifps[i]->link_ifindex != r->vr->ifp->ifindex)
			ifps[i] = NULL;
		else {
			selection = selection ? selection : ifps[i];
			candidates++;
		}
	}

	if (ifps_cnt)
		XFREE(MTYPE_TMP, ifps);

	char ethstr[ETHER_ADDR_STRLEN];

	prefix_mac2str(&r->vmac, ethstr, sizeof(ethstr));

	assert(!!selection == !!candidates);

	if (candidates == 0)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Interface: None (no interface found w/ MAC %s)",
			  r->vr->vrid, family2str(r->family), ethstr);
	else if (candidates > 1)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Interface: Multiple interfaces found; using %s",
			  r->vr->vrid, family2str(r->family), selection->name);
	else
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Interface: %s",
			  r->vr->vrid, family2str(r->family), selection->name);

	r->mvl_ifp = selection;

	return !!r->mvl_ifp;
}

static struct vrrp_router *vrrp_router_create(struct vrrp_vrouter *vr,
					      int family)
{
	struct vrrp_router *r =
		XCALLOC(MTYPE_VRRP_RTR, sizeof(struct vrrp_router));

	r->family = family;
	r->sock_rx = -1;
	r->sock_tx = -1;
	r->vr = vr;
	r->addrs = list_new();
	r->addrs->del = vrrp_router_addr_list_del_cb;
	r->priority = vr->priority;
	r->fsm.state = VRRP_STATE_INITIALIZE;
	vrrp_mac_set(&r->vmac, family == AF_INET6, vr->vrid);

	vrrp_attach_interface(r);

	return r;
}

static void vrrp_router_destroy(struct vrrp_router *r)
{
	if (r->is_active)
		vrrp_event(r, VRRP_EVENT_SHUTDOWN);

	if (r->sock_rx >= 0)
		close(r->sock_rx);
	if (r->sock_tx >= 0)
		close(r->sock_tx);

	/* FIXME: also delete list elements */
	list_delete(&r->addrs);
	XFREE(MTYPE_VRRP_RTR, r);
}

struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid,
					 uint8_t version)
{
	struct vrrp_vrouter *vr = vrrp_lookup(ifp, vrid);

	if (vr)
		return vr;

	if (version != 2 && version != 3)
		return NULL;

	vr = XCALLOC(MTYPE_VRRP_RTR, sizeof(struct vrrp_vrouter));

	vr->ifp = ifp;
	vr->version = version;
	vr->vrid = vrid;
	vr->priority = vd.priority;
	vr->preempt_mode = vd.preempt_mode;
	vr->accept_mode = vd.accept_mode;
	vr->shutdown = vd.shutdown;

	vr->v4 = vrrp_router_create(vr, AF_INET);
	vr->v6 = vrrp_router_create(vr, AF_INET6);

	vrrp_set_advertisement_interval(vr, vd.advertisement_interval);

	hash_get(vrrp_vrouters_hash, vr, hash_alloc_intern);

	return vr;
}

void vrrp_vrouter_destroy(struct vrrp_vrouter *vr)
{
	vrrp_router_destroy(vr->v4);
	vrrp_router_destroy(vr->v6);
	hash_release(vrrp_vrouters_hash, vr);
	XFREE(MTYPE_VRRP_RTR, vr);
}

struct vrrp_vrouter *vrrp_lookup(struct interface *ifp, uint8_t vrid)
{
	struct vrrp_vrouter vr;

	vr.vrid = vrid;
	vr.ifp = ifp;

	return hash_lookup(vrrp_vrouters_hash, &vr);
}

/* Network ----------------------------------------------------------------- */

/* Forward decls */
static void vrrp_change_state(struct vrrp_router *r, int to);
static int vrrp_adver_timer_expire(struct thread *thread);
static int vrrp_master_down_timer_expire(struct thread *thread);

/*
 * Finds the first connected address of the appropriate family on a VRRP
 * router's interface and binds the Tx socket of the VRRP router to that
 * address.
 *
 * Also sets src field of vrrp_router.
 *
 * r
 *    VRRP router to operate on
 *
 * Returns:
 *     0 on success
 *    -1 on failure
 */
static int vrrp_bind_to_primary_connected(struct vrrp_router *r)
{
	char ipstr[INET6_ADDRSTRLEN];
	struct interface *ifp;

	/*
	 * A slight quirk: the RFC specifies that advertisements under IPv6 must
	 * be transmitted using the link local address of the source interface
	 */
	ifp = r->family == AF_INET ? r->vr->ifp : r->mvl_ifp;

	struct listnode *ln;
	struct connected *c = NULL;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, ln, c))
		if (c->address->family == r->family) {
			if (r->family == AF_INET6
			    && IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6))
				break;
			else if (r->family == AF_INET)
				break;
		}

	if (c == NULL) {
		zlog_err(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			 "Failed to find address to bind on %s",
			 r->vr->vrid, family2str(r->family), ifp->name);
		return -1;
	}

	union sockunion su;

	memset(&su, 0x00, sizeof(su));

	switch (r->family) {
	case AF_INET:
		r->src.ipa_type = IPADDR_V4;
		r->src.ipaddr_v4 = c->address->u.prefix4;
		su.sin.sin_family = AF_INET;
		su.sin.sin_addr = c->address->u.prefix4;
		break;
	case AF_INET6:
		r->src.ipa_type = IPADDR_V6;
		r->src.ipaddr_v6 = c->address->u.prefix6;
		su.sin6.sin6_family = AF_INET6;
		su.sin6.sin6_scope_id = ifp->ifindex;
		su.sin6.sin6_addr = c->address->u.prefix6;
		break;
	}

	int ret = 0;

	sockopt_reuseaddr(r->sock_tx);
	if (bind(r->sock_tx, (const struct sockaddr *)&su, sizeof(su)) < 0) {
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Failed to bind Tx socket to primary IP address %s: %s",
			r->vr->vrid, family2str(r->family),
			inet_ntop(r->family,
				  (const void *)&c->address->u.prefix, ipstr,
				  sizeof(ipstr)),
			safe_strerror(errno));
		ret = -1;
	} else {
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Bound Tx socket to primary IP address %s",
		       r->vr->vrid, family2str(r->family),
		       inet_ntop(r->family, (const void *)&c->address->u.prefix,
				 ipstr, sizeof(ipstr)));
	}

	return ret;
}


/*
 * Create and multicast a VRRP ADVERTISEMENT message.
 *
 * r
 *    VRRP Router for which to send ADVERTISEMENT
 */
static void vrrp_send_advertisement(struct vrrp_router *r)
{
	struct vrrp_pkt *pkt;
	ssize_t pktsz;
	struct ipaddr *addrs[r->addrs->count];
	union sockunion dest;

	if (r->src.ipa_type == IPADDR_NONE
	    && vrrp_bind_to_primary_connected(r) < 0)
		return;

	list_to_array(r->addrs, (void **)addrs, r->addrs->count);

	pktsz = vrrp_pkt_adver_build(&pkt, &r->src, r->vr->version, r->vr->vrid,
				     r->priority, r->vr->advertisement_interval,
				     r->addrs->count, (struct ipaddr **)&addrs);

	if (DEBUG_MODE_CHECK(&vrrp_dbg_pkt, DEBUG_MODE_ALL))
		zlog_hexdump(pkt, (size_t)pktsz);

	const char *group = r->family == AF_INET ? VRRP_MCASTV4_GROUP_STR
						 : VRRP_MCASTV6_GROUP_STR;
	(void)str2sockunion(group, &dest);

	ssize_t sent = sendto(r->sock_tx, pkt, (size_t)pktsz, 0, &dest.sa,
			      sockunion_sizeof(&dest));

	vrrp_pkt_free(pkt);

	if (sent < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Failed to send VRRP Advertisement: %s",
			  r->vr->vrid, family2str(r->family),
			  safe_strerror(errno));
	} else {
		++r->stats.adver_tx_cnt;
	}
}

/*
 * Receive and parse VRRP advertisement.
 *
 * By the time we get here all fields have been validated for basic correctness
 * and the packet is a valid VRRP packet.
 *
 * However, we have not validated whether the VRID is correct for this virtual
 * router, nor whether the priority is correct (i.e. is not 255 when we are the
 * address owner), nor whether the advertisement interval equals our own
 * configured value (this check is only performed in VRRPv2).
 *
 * r
 *    VRRP Router associated with the socket this advertisement was received on
 *
 * src
 *    Source address of sender
 *
 * pkt
 *    The advertisement they sent
 *
 * pktsize
 *    Size of advertisement
 *
 * Returns:
 *    -1 if advertisement is invalid
 *     0 otherwise
 */
static int vrrp_recv_advertisement(struct vrrp_router *r, struct ipaddr *src,
				   struct vrrp_pkt *pkt, size_t pktsize)
{
	char sipstr[INET6_ADDRSTRLEN];
	char dipstr[INET6_ADDRSTRLEN];

	ipaddr2str(src, sipstr, sizeof(sipstr));
	ipaddr2str(&r->src, dipstr, sizeof(dipstr));

	char dumpbuf[BUFSIZ];

	vrrp_pkt_adver_dump(dumpbuf, sizeof(dumpbuf), pkt);
	DEBUGD(&vrrp_dbg_proto,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Received VRRP Advertisement from %s:\n%s",
	       r->vr->vrid, family2str(r->family), sipstr, dumpbuf);

	/* Check that VRID matches our configured VRID */
	if (pkt->hdr.vrid != r->vr->vrid) {
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram invalid: Advertisement contains VRID %" PRIu8
		       " which does not match our instance",
		       r->vr->vrid, family2str(r->family), pkt->hdr.vrid);
		return -1;
	}

	/* Verify that we are not the IPvX address owner */
	if (r->is_owner) {
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram invalid: Received advertisement but we are the address owner",
		       r->vr->vrid, family2str(r->family));
		return -1;
	}

	/* If v2, verify that adver time matches ours */
	bool adveq = (pkt->hdr.v2.adver_int
		      == MAX(r->vr->advertisement_interval / 100, 1));
	if (r->vr->version == 2 && !adveq) {
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram invalid: Received advertisement with advertisement interval %" PRIu8
		       " unequal to our configured value %u",
		       r->vr->vrid, family2str(r->family),
		       pkt->hdr.v2.adver_int,
		       MAX(r->vr->advertisement_interval / 100, 1));
		return -1;
	}


	/* Check that # IPs received matches our # configured IPs */
	if (pkt->hdr.naddr != r->addrs->count)
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram has %" PRIu8
		       " addresses, but this VRRP instance has %u",
		       r->vr->vrid, family2str(r->family), pkt->hdr.naddr,
		       r->addrs->count);

	++r->stats.adver_rx_cnt;

	int addrcmp;

	switch (r->fsm.state) {
	case VRRP_STATE_MASTER:
		addrcmp = memcmp(&src->ip, &r->src.ip, IPADDRSZ(src));

		if (pkt->hdr.priority == 0) {
			vrrp_send_advertisement(r);
			THREAD_OFF(r->t_adver_timer);
			thread_add_timer_msec(
				master, vrrp_adver_timer_expire, r,
				r->vr->advertisement_interval * CS2MS,
				&r->t_adver_timer);
		} else if (pkt->hdr.priority > r->priority
			   || ((pkt->hdr.priority == r->priority)
			       && addrcmp > 0)) {
			zlog_info(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Received advertisement from %s w/ priority %" PRIu8
				"; switching to Backup",
				r->vr->vrid, family2str(r->family), sipstr,
				pkt->hdr.priority);
			THREAD_OFF(r->t_adver_timer);
			if (r->vr->version == 3) {
				r->master_adver_interval =
					htons(pkt->hdr.v3.adver_int);
			}
			vrrp_recalculate_timers(r);
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(master,
					      vrrp_master_down_timer_expire, r,
					      r->master_down_interval * CS2MS,
					      &r->t_master_down_timer);
			vrrp_change_state(r, VRRP_STATE_BACKUP);
		} else {
			/* Discard advertisement */
			DEBUGD(&vrrp_dbg_proto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			       "Discarding advertisement from %s (%" PRIu8
			       " <= %" PRIu8 " & %s <= %s)",
			       r->vr->vrid, family2str(r->family), sipstr,
			       pkt->hdr.priority, r->priority, sipstr, dipstr);
		}
		break;
	case VRRP_STATE_BACKUP:
		if (pkt->hdr.priority == 0) {
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(
				master, vrrp_master_down_timer_expire, r,
				r->skew_time * CS2MS, &r->t_master_down_timer);
		} else if (r->vr->preempt_mode == false
			   || pkt->hdr.priority >= r->priority) {
			if (r->vr->version == 3) {
				r->master_adver_interval =
					ntohs(pkt->hdr.v3.adver_int);
			}
			vrrp_recalculate_timers(r);
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(master,
					      vrrp_master_down_timer_expire, r,
					      r->master_down_interval * CS2MS,
					      &r->t_master_down_timer);
		} else if (r->vr->preempt_mode == true
			   && pkt->hdr.priority < r->priority) {
			/* Discard advertisement */
			DEBUGD(&vrrp_dbg_proto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			       "Discarding advertisement from %s (%" PRIu8
			       " < %" PRIu8 " & preempt = true)",
			       r->vr->vrid, family2str(r->family), sipstr,
			       pkt->hdr.priority, r->priority);
		}
		break;
	case VRRP_STATE_INITIALIZE:
		zlog_err(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			 "Received ADVERTISEMENT in state %s; this is a bug",
			 r->vr->vrid, family2str(r->family),
			 vrrp_state_names[r->fsm.state]);
		break;
	}

	return 0;
}

/*
 * Read and process next IPvX datagram.
 */
static int vrrp_read(struct thread *thread)
{
	struct vrrp_router *r = thread->arg;

	struct vrrp_pkt *pkt;
	ssize_t pktsize;
	ssize_t nbytes;
	bool resched;
	char errbuf[BUFSIZ];
	struct sockaddr_storage sa;
	uint8_t control[64];
	struct ipaddr src = {};

	struct msghdr m = {};
	struct iovec iov;

	iov.iov_base = r->ibuf;
	iov.iov_len = sizeof(r->ibuf);
	m.msg_name = &sa;
	m.msg_namelen = sizeof(sa);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = control;
	m.msg_controllen = sizeof(control);

	nbytes = recvmsg(r->sock_rx, &m, MSG_DONTWAIT);

	if ((nbytes < 0 && ERRNO_IO_RETRY(errno))) {
		resched = true;
		goto done;
	} else if (nbytes <= 0) {
		vrrp_event(r, VRRP_EVENT_SHUTDOWN);
		resched = false;
		goto done;
	}

	if (DEBUG_MODE_CHECK(&vrrp_dbg_pkt, DEBUG_MODE_ALL)) {
		DEBUGD(&vrrp_dbg_pkt,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram rx: ",
		       r->vr->vrid, family2str(r->family));
		zlog_hexdump(r->ibuf, nbytes);
	}

	pktsize = vrrp_pkt_parse_datagram(r->family, r->vr->version, &m, nbytes,
					  &src, &pkt, errbuf, sizeof(errbuf));

	if (pktsize < 0)
		DEBUGD(&vrrp_dbg_pkt,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Datagram invalid: %s",
		       r->vr->vrid, family2str(r->family), errbuf);
	else
		vrrp_recv_advertisement(r, &src, pkt, pktsize);

	resched = true;

done:
	memset(r->ibuf, 0x00, sizeof(r->ibuf));

	if (resched)
		thread_add_read(master, vrrp_read, r, r->sock_rx, &r->t_read);

	return 0;
}

/*
 * Creates and configures VRRP router sockets.
 *
 * This function:
 * - Creates two sockets, one for Tx, one for Rx
 * - Joins the Rx socket to the appropriate VRRP multicast group
 * - Sets the Tx socket to set the TTL (v4) or Hop Limit (v6) field to 255 for
 *   all transmitted IPvX packets
 * - Requests the kernel to deliver IPv6 header values needed to validate VRRP
 *   packets
 *
 * If any of the above fail, the sockets are closed. The only exception is if
 * the TTL / Hop Limit settings fail; these are logged, but configuration
 * proceeds.
 *
 * The first connected address on the Virtual Router's interface is used as the
 * interface address.
 *
 * r
 *    VRRP Router for which to create listen socket
 *
 * Returns:
 *     0 on success
 *    -1 on failure
 */
static int vrrp_socket(struct vrrp_router *r)
{
	int ret;
	bool failed = false;

	frr_with_privs(&vrrp_privs) {
		r->sock_rx = socket(r->family, SOCK_RAW, IPPROTO_VRRP);
		r->sock_tx = socket(r->family, SOCK_RAW, IPPROTO_VRRP);
	}

	if (r->sock_rx < 0 || r->sock_tx < 0) {
		const char *rxtx = r->sock_rx < 0 ? "Rx" : "Tx";

		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Can't create VRRP %s socket",
			  r->vr->vrid, family2str(r->family), rxtx);
		failed = true;
		goto done;
	}

	/* Configure sockets */
	if (r->family == AF_INET) {
		/* Set Tx socket to always Tx with TTL set to 255 */
		int ttl = 255;

		ret = setsockopt(r->sock_tx, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
				 sizeof(ttl));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Failed to set outgoing multicast TTL count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid, family2str(r->family));
		}

		/* Set Tx socket DSCP byte */
		setsockopt_ipv4_tos(r->sock_tx, IPTOS_PREC_INTERNETCONTROL);

		/* Turn off multicast loop on Tx */
		setsockopt_ipv4_multicast_loop(r->sock_tx, 0);

		/* Bind Rx socket to exact interface */
		frr_with_privs(&vrrp_privs) {
			ret = setsockopt(r->sock_rx, SOL_SOCKET,
					 SO_BINDTODEVICE, r->vr->ifp->name,
					 strlen(r->vr->ifp->name));
		}
		if (ret) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				  "Failed to bind Rx socket to %s: %s",
				  r->vr->vrid, family2str(r->family),
				  r->vr->ifp->name, safe_strerror(errno));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Bound Rx socket to %s",
		       r->vr->vrid, family2str(r->family), r->vr->ifp->name);

		/* Bind Rx socket to v4 multicast address */
		struct sockaddr_in sa = {0};

		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(VRRP_MCASTV4_GROUP);
		if (bind(r->sock_rx, (struct sockaddr *)&sa, sizeof(sa))) {
			zlog_err(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Failed to bind Rx socket to VRRP multicast group: %s",
				r->vr->vrid, family2str(r->family),
				safe_strerror(errno));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Bound Rx socket to VRRP multicast group",
		       r->vr->vrid, family2str(r->family));

		/* Join Rx socket to VRRP IPv4 multicast group */
		assert(listhead(r->vr->ifp->connected));
		struct connected *c = listhead(r->vr->ifp->connected)->data;
		struct in_addr v4 = c->address->u.prefix4;

		ret = setsockopt_ipv4_multicast(r->sock_rx, IP_ADD_MEMBERSHIP,
						v4, htonl(VRRP_MCASTV4_GROUP),
						r->vr->ifp->ifindex);
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to join VRRP %s multicast group",
				  r->vr->vrid, family2str(r->family));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Joined VRRP multicast group",
		       r->vr->vrid, family2str(r->family));

		/* Set outgoing interface for advertisements */
		struct ip_mreqn mreqn = {};

		mreqn.imr_ifindex = r->mvl_ifp->ifindex;
		ret = setsockopt(r->sock_tx, IPPROTO_IP, IP_MULTICAST_IF,
				 (void *)&mreqn, sizeof(mreqn));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Could not set %s as outgoing multicast interface",
				r->vr->vrid, family2str(r->family),
				r->mvl_ifp->name);
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Set %s as outgoing multicast interface",
		       r->vr->vrid, family2str(r->family), r->mvl_ifp->name);

		/* Select and bind source address */
		if (vrrp_bind_to_primary_connected(r) < 0) {
			failed = true;
			goto done;
		}

	} else if (r->family == AF_INET6) {
		/* Always transmit IPv6 packets with hop limit set to 255 */
		ret = setsockopt_ipv6_multicast_hops(r->sock_tx, 255);
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Failed to set outgoing multicast hop count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid, family2str(r->family));
		}

		/* Set Tx socket DSCP byte */
		setsockopt_ipv6_tclass(r->sock_tx, IPTOS_PREC_INTERNETCONTROL);

		/* Request hop limit delivery */
		setsockopt_ipv6_hoplimit(r->sock_rx, 1);
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				  "Failed to request IPv6 Hop Limit delivery",
				  r->vr->vrid, family2str(r->family));
			failed = true;
			goto done;
		}

		/* Turn off multicast loop on Tx */
		setsockopt_ipv6_multicast_loop(r->sock_tx, 0);

		/* Bind Rx socket to exact interface */
		frr_with_privs(&vrrp_privs) {
			ret = setsockopt(r->sock_rx, SOL_SOCKET,
					 SO_BINDTODEVICE, r->vr->ifp->name,
					 strlen(r->vr->ifp->name));
		}
		if (ret) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				  "Failed to bind Rx socket to %s: %s",
				  r->vr->vrid, family2str(r->family),
				  r->vr->ifp->name, safe_strerror(errno));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Bound Rx socket to %s",
		       r->vr->vrid, family2str(r->family), r->vr->ifp->name);

		/* Bind Rx socket to v6 multicast address */
		struct sockaddr_in6 sa = {0};

		sa.sin6_family = AF_INET6;
		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR, &sa.sin6_addr);
		if (bind(r->sock_rx, (struct sockaddr *)&sa, sizeof(sa))) {
			zlog_err(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Failed to bind Rx socket to VRRP multicast group: %s",
				r->vr->vrid, family2str(r->family),
				safe_strerror(errno));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Bound Rx socket to VRRP multicast group",
		       r->vr->vrid, family2str(r->family));

		/* Join VRRP IPv6 multicast group */
		struct ipv6_mreq mreq;

		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR,
			  &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = r->vr->ifp->ifindex;
		ret = setsockopt(r->sock_rx, IPPROTO_IPV6, IPV6_JOIN_GROUP,
				 &mreq, sizeof(mreq));
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				  "Failed to join VRRP multicast group",
				  r->vr->vrid, family2str(r->family));
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Joined VRRP multicast group",
		       r->vr->vrid, family2str(r->family));

		/* Set outgoing interface for advertisements */
		ret = setsockopt(r->sock_tx, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				 &r->mvl_ifp->ifindex, sizeof(ifindex_t));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
				"Could not set %s as outgoing multicast interface",
				r->vr->vrid, family2str(r->family),
				r->mvl_ifp->name);
			failed = true;
			goto done;
		}
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Set %s as outgoing multicast interface",
		       r->vr->vrid, family2str(r->family), r->mvl_ifp->name);
	}

done:
	ret = 0;
	if (failed) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Failed to initialize VRRP router",
			  r->vr->vrid, family2str(r->family));
		if (r->sock_rx >= 0) {
			close(r->sock_rx);
			r->sock_rx = -1;
		}
		if (r->sock_tx >= 0) {
			close(r->sock_tx);
			r->sock_tx = -1;
		}
		ret = -1;
	}

	return ret;
}


/* State machine ----------------------------------------------------------- */

DEFINE_HOOK(vrrp_change_state_hook, (struct vrrp_router *r, int to), (r, to));

/*
 * Handle any necessary actions during state change to MASTER state.
 *
 * r
 *    VRRP Router to operate on
 */
static void vrrp_change_state_master(struct vrrp_router *r)
{
	/* Enable ND Router Advertisements */
	if (r->family == AF_INET6)
		vrrp_zebra_radv_set(r, true);

	/* Set protodown off */
	vrrp_zclient_send_interface_protodown(r->mvl_ifp, false);

	/*
	 * If protodown is already off, we can send our stuff, otherwise we
	 * have to delay until the interface is all the way up
	 */
	if (if_is_operative(r->mvl_ifp)) {
		vrrp_send_advertisement(r);

		if (r->family == AF_INET)
			vrrp_garp_send_all(r);
		else if (r->family == AF_INET6)
			vrrp_ndisc_una_send_all(r);
	} else {
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Delaying VRRP advertisement until interface is up",
		       r->vr->vrid, family2str(r->family));
		r->advert_pending = true;

		if (r->family == AF_INET) {
			DEBUGD(&vrrp_dbg_proto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			       "Delaying VRRP gratuitous ARPs until interface is up",
			       r->vr->vrid, family2str(r->family));
			r->garp_pending = true;
		} else if (r->family == AF_INET6) {
			DEBUGD(&vrrp_dbg_proto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			       "Delaying VRRP unsolicited neighbor advertisement until interface is up",
			       r->vr->vrid, family2str(r->family));
			r->ndisc_pending = true;
		}
	}
}

/*
 * Handle any necessary actions during state change to BACKUP state.
 *
 * r
 *    Virtual Router to operate on
 */
static void vrrp_change_state_backup(struct vrrp_router *r)
{
	/* Disable ND Router Advertisements */
	if (r->family == AF_INET6)
		vrrp_zebra_radv_set(r, false);

	/* Disable Adver_Timer */
	THREAD_OFF(r->t_adver_timer);

	r->advert_pending = false;
	r->garp_pending = false;
	r->ndisc_pending = false;
	memset(&r->src, 0x00, sizeof(r->src));

	vrrp_zclient_send_interface_protodown(r->mvl_ifp, true);
}

/*
 * Handle any necessary actions during state change to INITIALIZE state.
 *
 * This is not called for initial startup, only when transitioning from MASTER
 * or BACKUP.
 *
 * r
 *    VRRP Router to operate on
 */
static void vrrp_change_state_initialize(struct vrrp_router *r)
{
	r->master_adver_interval = 0;
	vrrp_recalculate_timers(r);

	r->advert_pending = false;
	r->garp_pending = false;
	r->ndisc_pending = false;

	/* Disable ND Router Advertisements */
	if (r->family == AF_INET6)
		vrrp_zebra_radv_set(r, false);
}

void (*vrrp_change_state_handlers[])(struct vrrp_router *vr) = {
	[VRRP_STATE_MASTER] = vrrp_change_state_master,
	[VRRP_STATE_BACKUP] = vrrp_change_state_backup,
	[VRRP_STATE_INITIALIZE] = vrrp_change_state_initialize,
};

/*
 * Change Virtual Router FSM position. Handles transitional actions and calls
 * any subscribers to the state change hook.
 *
 * r
 *    Virtual Router for which to change state
 *
 * to
 *    State to change to
 */
static void vrrp_change_state(struct vrrp_router *r, int to)
{
	if (r->fsm.state == to)
		return;

	/* Call our handlers, then any subscribers */
	vrrp_change_state_handlers[to](r);
	hook_call(vrrp_change_state_hook, r, to);
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM "%s -> %s",
		  r->vr->vrid, family2str(r->family),
		  vrrp_state_names[r->fsm.state], vrrp_state_names[to]);
	r->fsm.state = to;

	++r->stats.trans_cnt;
}

/*
 * Called when Adver_Timer expires.
 */
static int vrrp_adver_timer_expire(struct thread *thread)
{
	struct vrrp_router *r = thread->arg;

	DEBUGD(&vrrp_dbg_proto,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Adver_Timer expired",
	       r->vr->vrid, family2str(r->family));

	if (r->fsm.state == VRRP_STATE_MASTER) {
		/* Send an ADVERTISEMENT */
		vrrp_send_advertisement(r);

		/* Reset the Adver_Timer to Advertisement_Interval */
		thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
				      r->vr->advertisement_interval * CS2MS,
				      &r->t_adver_timer);
	} else {
		zlog_err(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			 "Adver_Timer expired in state '%s'; this is a bug",
			 r->vr->vrid, family2str(r->family),
			 vrrp_state_names[r->fsm.state]);
	}

	return 0;
}

/*
 * Called when Master_Down_Timer expires.
 */
static int vrrp_master_down_timer_expire(struct thread *thread)
{
	struct vrrp_router *r = thread->arg;

	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		  "Master_Down_Timer expired",
		  r->vr->vrid, family2str(r->family));

	thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
			      r->vr->advertisement_interval * CS2MS,
			      &r->t_adver_timer);
	vrrp_change_state(r, VRRP_STATE_MASTER);

	return 0;
}

/*
 * Event handler for Startup event.
 *
 * Creates sockets, sends advertisements and ARP requests, starts timers,
 * and transitions the Virtual Router to either Master or Backup states.
 *
 * This function will also initialize the program's global ARP subsystem if it
 * has not yet been initialized.
 *
 * r
 *    VRRP Router on which to apply Startup event
 *
 * Returns:
 *    < 0 if the session socket could not be created, or the state is not
 *        Initialize
 *      0 on success
 */
static int vrrp_startup(struct vrrp_router *r)
{
	/* May only be called when the state is Initialize */
	if (r->fsm.state != VRRP_STATE_INITIALIZE)
		return -1;

	/* Must have a valid macvlan interface available */
	if (r->mvl_ifp == NULL && !vrrp_attach_interface(r)) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "No appropriate interface found",
			  r->vr->vrid, family2str(r->family));
		return -1;
	}

	/* Initialize global gratuitous ARP socket if necessary */
	if (r->family == AF_INET && !vrrp_garp_is_init())
		vrrp_garp_init();
	if (r->family == AF_INET6 && !vrrp_ndisc_is_init())
		vrrp_ndisc_init();

	/* Create socket */
	if (r->sock_rx < 0 || r->sock_tx < 0) {
		int ret = vrrp_socket(r);

		if (ret < 0 || r->sock_tx < 0 || r->sock_rx < 0)
			return ret;
	}

	/* Schedule listener */
	thread_add_read(master, vrrp_read, r, r->sock_rx, &r->t_read);

	/* Configure effective priority */
	assert(listhead(r->addrs));
	struct ipaddr *primary = (struct ipaddr *)listhead(r->addrs)->data;
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(r->family, &primary->ip.addr, ipbuf, sizeof(ipbuf));

	if (r->vr->priority == VRRP_PRIO_MASTER
	    || vrrp_is_owner(r->vr->ifp, primary)) {
		r->priority = VRRP_PRIO_MASTER;
		vrrp_recalculate_timers(r);

		zlog_info(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"%s has priority set to 255 or owns primary Virtual Router IP %s; electing self as Master",
			r->vr->vrid, family2str(r->family), r->vr->ifp->name,
			ipbuf);
	}

	if (r->priority == VRRP_PRIO_MASTER) {
		thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
				      r->vr->advertisement_interval * CS2MS,
				      &r->t_adver_timer);
		vrrp_change_state(r, VRRP_STATE_MASTER);
	} else {
		r->master_adver_interval = r->vr->advertisement_interval;
		vrrp_recalculate_timers(r);
		thread_add_timer_msec(master, vrrp_master_down_timer_expire, r,
				      r->master_down_interval * CS2MS,
				      &r->t_master_down_timer);
		vrrp_change_state(r, VRRP_STATE_BACKUP);
	}

	r->is_active = true;

	return 0;
}

/*
 * Shuts down a Virtual Router and transitions it to Initialize.
 *
 * This call must be idempotent; it is safe to call multiple times on the same
 * VRRP Router.
 */
static int vrrp_shutdown(struct vrrp_router *r)
{
	uint8_t saved_prio;

	switch (r->fsm.state) {
	case VRRP_STATE_MASTER:
		/* Send an ADVERTISEMENT with Priority = 0 */
		saved_prio = r->priority;
		r->priority = 0;
		vrrp_send_advertisement(r);
		r->priority = saved_prio;
		break;
	case VRRP_STATE_BACKUP:
		break;
	case VRRP_STATE_INITIALIZE:
		DEBUGD(&vrrp_dbg_proto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Received '%s' event in '%s' state; ignoring",
		       r->vr->vrid, family2str(r->family),
		       vrrp_event_names[VRRP_EVENT_SHUTDOWN],
		       vrrp_state_names[VRRP_STATE_INITIALIZE]);
		break;
	}

	/* Cancel all timers */
	THREAD_OFF(r->t_adver_timer);
	THREAD_OFF(r->t_master_down_timer);
	THREAD_OFF(r->t_read);
	THREAD_OFF(r->t_write);

	/* Protodown macvlan */
	vrrp_zclient_send_interface_protodown(r->mvl_ifp, true);

	/* Throw away our source address */
	memset(&r->src, 0x00, sizeof(r->src));

	if (r->sock_rx > 0) {
		close(r->sock_rx);
		r->sock_rx = -1;
	}
	if (r->sock_tx > 0) {
		close(r->sock_tx);
		r->sock_tx = -1;
	}

	vrrp_change_state(r, VRRP_STATE_INITIALIZE);

	r->is_active = false;

	return 0;
}

static int (*vrrp_event_handlers[])(struct vrrp_router *r) = {
	[VRRP_EVENT_STARTUP] = vrrp_startup,
	[VRRP_EVENT_SHUTDOWN] = vrrp_shutdown,
};

/*
 * Spawn a VRRP FSM event on a VRRP Router.
 *
 * vr
 *    VRRP Router on which to spawn event
 *
 * event
 *    The event to spawn
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
int vrrp_event(struct vrrp_router *r, int event)
{
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM "'%s' event",
		  r->vr->vrid, family2str(r->family), vrrp_event_names[event]);
	return vrrp_event_handlers[event](r);
}


/* Autoconfig -------------------------------------------------------------- */

/*
 * Set the configured addresses for this VRRP instance to exactly the addresses
 * present on its macvlan subinterface(s).
 *
 * vr
 *    VRRP router to act on
 */
static void vrrp_autoconfig_autoaddrupdate(struct vrrp_router *r)
{
	struct listnode *ln;
	struct connected *c = NULL;
	bool is_v6_ll;
	char ipbuf[INET6_ADDRSTRLEN];

	if (!r->mvl_ifp)
		return;

	DEBUGD(&vrrp_dbg_auto,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Setting Virtual IP list to match IPv4 addresses on %s",
	       r->vr->vrid, family2str(r->family), r->mvl_ifp->name);
	for (ALL_LIST_ELEMENTS_RO(r->mvl_ifp->connected, ln, c)) {
		is_v6_ll = (c->address->family == AF_INET6
			    && IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6));
		if (c->address->family == r->family && !is_v6_ll) {
			inet_ntop(r->family, &c->address->u.prefix, ipbuf,
				  sizeof(ipbuf));
			DEBUGD(&vrrp_dbg_auto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			       "Adding %s",
			       r->vr->vrid, family2str(r->family), ipbuf);
			if (r->family == AF_INET)
				vrrp_add_ipv4(r->vr, c->address->u.prefix4);
			else if (r->vr->version == 3)
				vrrp_add_ipv6(r->vr, c->address->u.prefix6);
		}
	}

	vrrp_check_start(r->vr);

	if (r->addrs->count == 0 && r->fsm.state != VRRP_STATE_INITIALIZE) {
		DEBUGD(&vrrp_dbg_auto,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
		       "Virtual IP list is empty; shutting down",
		       r->vr->vrid, family2str(r->family));
		vrrp_event(r, VRRP_EVENT_SHUTDOWN);
	}
}

static struct vrrp_vrouter *
vrrp_autoconfig_autocreate(struct interface *mvl_ifp)
{
	struct interface *p;
	struct vrrp_vrouter *vr;

	p = if_lookup_by_index(mvl_ifp->link_ifindex, VRF_DEFAULT);

	if (!p)
		return NULL;

	uint8_t vrid = mvl_ifp->hw_addr[5];
	uint8_t fam = mvl_ifp->hw_addr[4];

	DEBUGD(&vrrp_dbg_auto,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Autoconfiguring VRRP on %s",
	       vrid, family2str(fam), p->name);

	vr = vrrp_vrouter_create(p, vrid, vrrp_autoconfig_version);

	if (!vr) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Failed to autoconfigure VRRP on %s",
			  vrid, family2str(fam), p->name);
		return NULL;
	}

	vr->autoconf = true;

	/*
	 * If these interfaces are protodown on, we need to un-protodown them
	 * in order to get Zebra to send us their addresses so we can
	 * autoconfigure them.
	 */
	if (vr->v4->mvl_ifp)
		vrrp_zclient_send_interface_protodown(vr->v4->mvl_ifp, false);
	if (vr->v6->mvl_ifp)
		vrrp_zclient_send_interface_protodown(vr->v6->mvl_ifp, false);

	 /* If they're not, we can go ahead and add the addresses we have */
	vrrp_autoconfig_autoaddrupdate(vr->v4);
	vrrp_autoconfig_autoaddrupdate(vr->v6);

	return vr;
}

/*
 * Callback to notify autoconfig of interface add.
 *
 * If the interface is a VRRP-compatible device, and there is no existing VRRP
 * router running on it, one is created. All addresses on the interface are
 * added to the router.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
static int vrrp_autoconfig_if_add(struct interface *ifp)
{
	bool created = false;
	struct vrrp_vrouter *vr;

	if (!vrrp_autoconfig_is_on)
		return 0;

	if (!ifp || !ifp->link_ifindex || !vrrp_ifp_has_vrrp_mac(ifp))
		return -1;

	vr = vrrp_lookup_by_if_mvl(ifp);

	if (!vr) {
		vr = vrrp_autoconfig_autocreate(ifp);
		created = true;
	}

	if (!vr || vr->autoconf == false)
		return 0;

	if (!created) {
		/*
		 * We didn't create it, but it has already been autoconfigured.
		 * Try to attach this interface to the existing instance.
		 */
		if (!vr->v4->mvl_ifp) {
			vrrp_attach_interface(vr->v4);
			/* If we just attached it, make sure it's turned on */
			if (vr->v4->mvl_ifp) {
				vrrp_zclient_send_interface_protodown(
					vr->v4->mvl_ifp, false);
				/*
				 * If it's already up, we can go ahead and add
				 * the addresses we have
				 */
				vrrp_autoconfig_autoaddrupdate(vr->v4);
			}
		}
		if (!vr->v6->mvl_ifp) {
			vrrp_attach_interface(vr->v6);
			/* If we just attached it, make sure it's turned on */
			if (vr->v6->mvl_ifp) {
				vrrp_zclient_send_interface_protodown(
					vr->v6->mvl_ifp, false);
				/*
				 * If it's already up, we can go ahead and add
				 * the addresses we have
				 */
				vrrp_autoconfig_autoaddrupdate(vr->v6);
			}
		}
	}

	return 0;
}

/*
 * Callback to notify autoconfig of interface delete.
 *
 * If the interface is a VRRP-compatible device, and a VRRP router is running
 * on it, and that VRRP router was automatically configured, it will be
 * deleted. If that was the last router for the corresponding VRID (i.e., if
 * this interface was a v4 VRRP interface and no v6 router is configured for
 * the same VRID) then the entire virtual router is deleted.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
static int vrrp_autoconfig_if_del(struct interface *ifp)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *vrs;

	vrs = vrrp_lookup_by_if_any(ifp);

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr))
		if (vr->autoconf
		    && (!vr->ifp || (!vr->v4->mvl_ifp && !vr->v6->mvl_ifp))) {
			DEBUGD(&vrrp_dbg_auto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID
			       "All VRRP interfaces for instance deleted; destroying autoconfigured VRRP router",
			       vr->vrid);
			vrrp_vrouter_destroy(vr);
		}

	list_delete(&vrs);

	return 0;
}

/*
 * Callback to notify autoconfig of interface up.
 *
 * Creates VRRP instance on interface if it does not exist. Otherwise does
 * nothing.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
static int vrrp_autoconfig_if_up(struct interface *ifp)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	struct vrrp_vrouter *vr = vrrp_lookup_by_if_mvl(ifp);

	if (vr && !vr->autoconf)
		return 0;

	if (!vr) {
		vrrp_autoconfig_if_add(ifp);
		return 0;
	}

	return 0;
}

/*
 * Callback to notify autoconfig of interface down.
 *
 * Does nothing. An interface down event is accompanied by address deletion
 * events for all the addresses on the interface; if an autoconfigured VRRP
 * router exists on this interface, then it will have all its addresses deleted
 * and end up in Initialize.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
static int vrrp_autoconfig_if_down(struct interface *ifp)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	return 0;
}

/*
 * Callback to notify autoconfig of a new interface address.
 *
 * If a VRRP router exists on this interface, its address list is updated to
 * match the new address list. If no addresses remain, a Shutdown event is
 * issued to the VRRP router.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 *
 */
static int vrrp_autoconfig_if_address_add(struct interface *ifp)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	struct vrrp_vrouter *vr = vrrp_lookup_by_if_mvl(ifp);

	if (vr && vr->autoconf) {
		if (vr->v4->mvl_ifp == ifp)
			vrrp_autoconfig_autoaddrupdate(vr->v4);
		else if (vr->v6->mvl_ifp == ifp)
			vrrp_autoconfig_autoaddrupdate(vr->v6);
	}

	return 0;
}

/*
 * Callback to notify autoconfig of a removed interface address.
 *
 * If a VRRP router exists on this interface, its address list is updated to
 * match the new address list. If no addresses remain, a Shutdown event is
 * issued to the VRRP router.
 *
 * ifp
 *    Interface to operate on
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 *
 */
static int vrrp_autoconfig_if_address_del(struct interface *ifp)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	struct vrrp_vrouter *vr = vrrp_lookup_by_if_mvl(ifp);

	if (vr && vr->autoconf) {
		if (vr->v4->mvl_ifp == ifp)
			vrrp_autoconfig_autoaddrupdate(vr->v4);
		else if (vr->v6->mvl_ifp == ifp)
			vrrp_autoconfig_autoaddrupdate(vr->v6);
	}

	return 0;
}

int vrrp_autoconfig(void)
{
	if (!vrrp_autoconfig_is_on)
		return 0;

	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		vrrp_autoconfig_if_add(ifp);

	return 0;
}

void vrrp_autoconfig_on(int version)
{
	vrrp_autoconfig_is_on = true;
	vrrp_autoconfig_version = version;

	vrrp_autoconfig();
}

void vrrp_autoconfig_off(void)
{
	vrrp_autoconfig_is_on = false;

	struct list *ll = hash_to_list(vrrp_vrouters_hash);

	struct listnode *ln;
	struct vrrp_vrouter *vr;

	for (ALL_LIST_ELEMENTS_RO(ll, ln, vr))
		if (vr->autoconf)
			vrrp_vrouter_destroy(vr);

	list_delete(&ll);
}

/* Interface tracking ------------------------------------------------------ */

/*
 * Bind any pending interfaces.
 *
 * mvl_ifp
 *    macvlan interface that some VRRP instances might want to bind to
 */
static void vrrp_bind_pending(struct interface *mvl_ifp)
{
	struct vrrp_vrouter *vr;

	DEBUGD(&vrrp_dbg_zebra,
	       VRRP_LOGPFX
	       "Searching for instances that could use interface %s",
	       mvl_ifp->name);

	vr = vrrp_lookup_by_if_mvl(mvl_ifp);

	if (vr) {
		DEBUGD(&vrrp_dbg_zebra,
		       VRRP_LOGPFX VRRP_LOGPFX_VRID
		       "<-- This instance can probably use interface %s",
		       vr->vrid, mvl_ifp->name);

		if (mvl_ifp->hw_addr[4] == 0x01 && !vr->v4->mvl_ifp)
			vrrp_attach_interface(vr->v4);
		else if (mvl_ifp->hw_addr[4] == 0x02 && !vr->v6->mvl_ifp)
			vrrp_attach_interface(vr->v6);
	}
}

void vrrp_if_up(struct interface *ifp)
{
	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *vrs;

	vrrp_bind_pending(ifp);

	vrs = vrrp_lookup_by_if_any(ifp);

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr)) {
		vrrp_check_start(vr);

		if (!if_is_operative(ifp))
			continue;

		/*
		 * Handle the situation in which we performed a state
		 * transition on this VRRP router but needed to wait for the
		 * macvlan interface to come up to perform some actions
		 */
		if (ifp == vr->v4->mvl_ifp) {
			if (vr->v4->advert_pending) {
				DEBUGD(&vrrp_dbg_proto,
				       VRRP_LOGPFX VRRP_LOGPFX_VRID
					       VRRP_LOGPFX_FAM
				       "Interface up; sending pending advertisement",
				       vr->vrid, family2str(vr->v4->family));
				vrrp_send_advertisement(vr->v4);
				vr->v4->advert_pending = false;
			}
			if (vr->v4->garp_pending) {
				DEBUGD(&vrrp_dbg_proto,
				       VRRP_LOGPFX VRRP_LOGPFX_VRID
					       VRRP_LOGPFX_FAM
				       "Interface up; sending pending gratuitous ARP",
				       vr->vrid, family2str(vr->v4->family));
				vrrp_garp_send_all(vr->v4);
				vr->v4->garp_pending = false;
			}
		}
		if (ifp == vr->v6->mvl_ifp) {
			if (vr->v6->advert_pending) {
				DEBUGD(&vrrp_dbg_proto,
				       VRRP_LOGPFX VRRP_LOGPFX_VRID
					       VRRP_LOGPFX_FAM
				       "Interface up; sending pending advertisement",
				       vr->vrid, family2str(vr->v6->family));
				vrrp_send_advertisement(vr->v6);
				vr->v6->advert_pending = false;
			}
			if (vr->v6->ndisc_pending) {
				DEBUGD(&vrrp_dbg_proto,
				       VRRP_LOGPFX VRRP_LOGPFX_VRID
					       VRRP_LOGPFX_FAM
				       "Interface up; sending pending Unsolicited Neighbor Advertisement",
				       vr->vrid, family2str(vr->v6->family));
				vrrp_ndisc_una_send_all(vr->v6);
				vr->v6->ndisc_pending = false;
			}
		}
	}

	list_delete(&vrs);

	vrrp_autoconfig_if_up(ifp);
}

void vrrp_if_down(struct interface *ifp)
{
	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *vrs;

	vrrp_bind_pending(ifp);

	vrs = vrrp_lookup_by_if_any(ifp);

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr)) {
		vrrp_check_start(vr);

		if (vr->ifp == ifp || vr->v4->mvl_ifp == ifp
		    || vr->v6->mvl_ifp == ifp) {
			DEBUGD(&vrrp_dbg_auto,
			       VRRP_LOGPFX VRRP_LOGPFX_VRID "Interface %s down",
			       vr->vrid, ifp->name);
		}
	}

	list_delete(&vrs);

	vrrp_autoconfig_if_down(ifp);
}

void vrrp_if_add(struct interface *ifp)
{
	vrrp_bind_pending(ifp);

	/* thanks, zebra */
	if (CHECK_FLAG(ifp->flags, IFF_UP))
		vrrp_if_up(ifp);

	vrrp_autoconfig_if_add(ifp);
}

void vrrp_if_del(struct interface *ifp)
{
	struct listnode *ln;
	struct vrrp_vrouter *vr;
	struct list *vrs = vrrp_lookup_by_if_any(ifp);

	vrrp_if_down(ifp);

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr)) {
		if ((vr->v4->mvl_ifp == ifp || vr->ifp == ifp)
		    && vr->v4->fsm.state != VRRP_STATE_INITIALIZE) {
			vrrp_event(vr->v4, VRRP_EVENT_SHUTDOWN);
			vr->v4->mvl_ifp = NULL;
		} else if ((vr->v6->mvl_ifp == ifp || vr->ifp == ifp)
			   && vr->v6->fsm.state != VRRP_STATE_INITIALIZE) {
			vrrp_event(vr->v6, VRRP_EVENT_SHUTDOWN);
			vr->v6->mvl_ifp = NULL;
		}
	}

	list_delete(&vrs);

	vrrp_autoconfig_if_del(ifp);
}

void vrrp_if_address_add(struct interface *ifp)
{
	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *vrs;

	/*
	 * We have to do a wide search here, because we need to know when a v6
	 * macvlan device gets a new address. This is because the macvlan link
	 * local is used as the source address for v6 advertisements, and hence
	 * "do I have a link local" constitutes an activation condition for v6
	 * virtual routers.
	 */
	vrs = vrrp_lookup_by_if_any(ifp);

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr))
		vrrp_check_start(vr);

	list_delete(&vrs);

	vrrp_autoconfig_if_address_add(ifp);
}

void vrrp_if_address_del(struct interface *ifp)
{
	/*
	 * Zebra is stupid and sends us address deletion notifications
	 * when any of the following condition sets are met:
	 *
	 * - if_is_operative && address deleted
	 * - if_is_operative -> !if_is_operative
	 *
	 * Note that the second one is nonsense, because Zebra behaves as
	 * though an interface going down means all the addresses on that
	 * interface got deleted. Which is a problem for autoconfig because all
	 * the addresses on an interface going away means the VRRP session goes
	 * to Initialize. However interfaces go down whenever we transition to
	 * Backup, so this effectively means that for autoconfigured instances
	 * we actually end up in Initialize whenever we try to go into Backup.
	 *
	 * Also, Zebra does NOT send us notifications when:
	 * - !if_is_operative && address deleted
	 *
	 * Which means if we're in backup and an address is deleted out from
	 * under us, we won't even know.
	 *
	 * The only solution here is to only resynchronize our address list
	 * when:
	 *
	 * - An interfaces comes up
	 * - An interface address is added
	 * - An interface address is deleted AND the interface is up
	 *
	 * Even though this is only a problem with autoconfig at the moment I'm
	 * papering over Zebra's braindead semantics here. Every piece of code
	 * in this function should be protected by a check that the interface
	 * is up.
	 */
	if (if_is_operative(ifp))
		vrrp_autoconfig_if_address_del(ifp);
}

/* Other ------------------------------------------------------------------- */

int vrrp_config_write_interface(struct vty *vty)
{
	struct list *vrs = hash_to_list(vrrp_vrouters_hash);
	struct listnode *ln, *ipln;
	struct vrrp_vrouter *vr;
	int writes = 0;

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr)) {
		vty_frame(vty, "interface %s\n", vr->ifp->name);
		++writes;

		vty_out(vty, " vrrp %" PRIu8 "%s\n", vr->vrid,
			vr->version == 2 ? " version 2" : "");
		++writes;

		if (vr->shutdown != vd.shutdown && ++writes)
			vty_out(vty, " %svrrp %" PRIu8 " shutdown\n",
				vr->shutdown ? "" : "no ", vr->vrid);

		if (vr->preempt_mode != vd.preempt_mode && ++writes)
			vty_out(vty, " %svrrp %" PRIu8 " preempt\n",
				vr->preempt_mode ? "" : "no ", vr->vrid);

		if (vr->accept_mode != vd.accept_mode && ++writes)
			vty_out(vty, " %svrrp %" PRIu8 " accept\n",
				vr->accept_mode ? "" : "no ", vr->vrid);

		if (vr->advertisement_interval != vd.advertisement_interval
		    && ++writes)
			vty_out(vty,
				" vrrp %" PRIu8
				" advertisement-interval %d\n",
				vr->vrid, vr->advertisement_interval * CS2MS);

		if (vr->priority != vd.priority && ++writes)
			vty_out(vty, " vrrp %" PRIu8 " priority %" PRIu8 "\n",
				vr->vrid, vr->priority);

		struct ipaddr *ip;

		for (ALL_LIST_ELEMENTS_RO(vr->v4->addrs, ipln, ip)) {
			char ipbuf[INET6_ADDRSTRLEN];

			ipaddr2str(ip, ipbuf, sizeof(ipbuf));
			vty_out(vty, " vrrp %" PRIu8 " ip %s\n", vr->vrid,
				ipbuf);
			++writes;
		}

		for (ALL_LIST_ELEMENTS_RO(vr->v6->addrs, ipln, ip)) {
			char ipbuf[INET6_ADDRSTRLEN];

			ipaddr2str(ip, ipbuf, sizeof(ipbuf));
			vty_out(vty, " vrrp %" PRIu8 " ipv6 %s\n", vr->vrid,
				ipbuf);
			++writes;
		}
		vty_endframe(vty, "!\n");
	}

	list_delete(&vrs);

	return writes;
}

int vrrp_config_write_global(struct vty *vty)
{
	unsigned int writes = 0;

	if (vrrp_autoconfig_is_on && ++writes)
		vty_out(vty, "vrrp autoconfigure%s\n",
			vrrp_autoconfig_version == 2 ? " version 2" : "");

	if (vd.priority != VRRP_DEFAULT_PRIORITY && ++writes)
		vty_out(vty, "vrrp default priority %" PRIu8 "\n", vd.priority);

	if (vd.advertisement_interval != VRRP_DEFAULT_ADVINT && ++writes)
		vty_out(vty,
			"vrrp default advertisement-interval %" PRIu16 "\n",
			vd.advertisement_interval * CS2MS);

	if (vd.preempt_mode != VRRP_DEFAULT_PREEMPT && ++writes)
		vty_out(vty, "%svrrp default preempt\n",
			!vd.preempt_mode ? "no " : "");

	if (vd.accept_mode != VRRP_DEFAULT_ACCEPT && ++writes)
		vty_out(vty, "%svrrp default accept\n",
			!vd.accept_mode ? "no " : "");

	if (vd.shutdown != VRRP_DEFAULT_SHUTDOWN && ++writes)
		vty_out(vty, "%svrrp default shutdown\n",
			!vd.shutdown ? "no " : "");

	return writes;
}

static unsigned int vrrp_hash_key(const void *arg)
{
	const struct vrrp_vrouter *vr = arg;
	char key[IFNAMSIZ + 64];

	snprintf(key, sizeof(key), "%s@%" PRIu8, vr->ifp->name, vr->vrid);

	return string_hash_make(key);
}

static bool vrrp_hash_cmp(const void *arg1, const void *arg2)
{
	const struct vrrp_vrouter *vr1 = arg1;
	const struct vrrp_vrouter *vr2 = arg2;

	if (vr1->ifp != vr2->ifp)
		return 0;
	if (vr1->vrid != vr2->vrid)
		return 0;

	return 1;
}

void vrrp_init(void)
{
	/* Set default defaults */
	vd.priority = VRRP_DEFAULT_PRIORITY;
	vd.advertisement_interval = VRRP_DEFAULT_ADVINT;
	vd.preempt_mode = VRRP_DEFAULT_PREEMPT;
	vd.accept_mode = VRRP_DEFAULT_ACCEPT;
	vd.shutdown = VRRP_DEFAULT_SHUTDOWN;

	vrrp_autoconfig_version = 3;
	vrrp_vrouters_hash = hash_create(&vrrp_hash_key, vrrp_hash_cmp,
					 "VRRP virtual router hash");
	vrf_init(NULL, NULL, NULL, NULL, NULL);
}

void vrrp_fini(void)
{
	/* Destroy all instances */
	struct list *vrs = hash_to_list(vrrp_vrouters_hash);

	struct listnode *ln;
	struct vrrp_vrouter *vr;

	for (ALL_LIST_ELEMENTS_RO(vrs, ln, vr))
		vrrp_vrouter_destroy(vr);

	list_delete(&vrs);

	hash_clean(vrrp_vrouters_hash, NULL);
	hash_free(vrrp_vrouters_hash);
}
