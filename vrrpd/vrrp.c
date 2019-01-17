/*
 * VRRPD global definitions and state machine
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
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

#include "vrrp.h"
#include "vrrp_arp.h"
#include "vrrp_packet.h"

#define VRRP_LOGPFX "[CORE] "

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
	r->skew_time =
		((256 - r->vr->priority) * r->master_adver_interval) / 256;
	r->master_down_interval = (3 * r->master_adver_interval);
	r->master_down_interval += r->skew_time;
}

/*
 * Determines if a VRRP router is the owner of the specified address.
 *
 * The determining factor for whether an interface is the address owner is
 * simply whether the address is assigned to the VRRP subinterface by someone
 * other than vrrpd.
 *
 * This function should always return the correct answer regardless of
 * master/backup status.
 *
 * vr
 *    Virtual Router
 *
 * Returns:
 *    whether or not vr owns the specified address
 */
static bool vrrp_is_owner(struct interface *ifp, struct ipaddr *addr)
{
	struct prefix p;

	p.family = IS_IPADDR_V4(addr) ? AF_INET : AF_INET6;
	p.prefixlen = IS_IPADDR_V4(addr) ? IPV4_MAX_BITLEN : IPV6_MAX_BITLEN;
	memcpy(&p.u, &addr->ip, sizeof(addr->ip));

	return !!connected_lookup_prefix_exact(ifp, &p);
}

/* Configuration controllers ----------------------------------------------- */

void vrrp_set_priority(struct vrrp_vrouter *vr, uint8_t priority)
{
	if (vr->priority == priority)
		return;

	vr->priority = priority;
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

void vrrp_add_ipv4(struct vrrp_vrouter *vr, struct in_addr v4)
{
	struct ipaddr *v4_ins = XCALLOC(MTYPE_TMP, sizeof(struct ipaddr));

	v4_ins->ipa_type = IPADDR_V4;
	v4_ins->ipaddr_v4 = v4;

	if (!vrrp_is_owner(vr->ifp, v4_ins) && vr->v4->is_owner) {
		char ipbuf[INET6_ADDRSTRLEN];
		ipaddr2str(v4_ins, ipbuf, sizeof(ipbuf));
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"This VRRP router is not the address owner of %s, but is the address owner of other addresses; this config is unsupported.",
			vr->vrid, ipbuf);
		/* FIXME: indicate failure with rc */
		return;
	}

	listnode_add(vr->v4->addrs, v4_ins);
}

void vrrp_add_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6)
{
	struct ipaddr *v6_ins = XCALLOC(MTYPE_TMP, sizeof(struct ipaddr));

	v6_ins->ipa_type = IPADDR_V6;
	memcpy(&v6_ins->ipaddr_v6, &v6, sizeof(struct in6_addr));

	if (!vrrp_is_owner(vr->ifp, v6_ins) && vr->v6->is_owner) {
		char ipbuf[INET6_ADDRSTRLEN];
		ipaddr2str(v6_ins, ipbuf, sizeof(ipbuf));
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"This VRRP router is not the address owner of %s, but is the address owner of other addresses; this config is unsupported.",
			vr->vrid, ipbuf);
		/* FIXME: indicate failure with rc */
		return;
	}

	listnode_add(vr->v6->addrs, v6_ins);
}

void vrrp_add_ip(struct vrrp_vrouter *vr, struct ipaddr ip)
{
	if (ip.ipa_type == IPADDR_V4)
		vrrp_add_ipv4(vr, ip.ipaddr_v4);
	else if (ip.ipa_type == IPADDR_V6)
		vrrp_add_ipv6(vr, ip.ipaddr_v6);
}


/* Creation and destruction ------------------------------------------------ */

static struct vrrp_router *vrrp_router_create(struct vrrp_vrouter *vr,
					      int family)
{
	struct vrrp_router *r = XCALLOC(MTYPE_TMP, sizeof(struct vrrp_router));

	r->family = family;
	r->sock_rx = -1;
	r->sock_tx = -1;
	r->vr = vr;
	r->addrs = list_new();
	r->priority = vr->priority;
	r->fsm.state = VRRP_STATE_INITIALIZE;
	vrrp_mac_set(&r->vmac, family == AF_INET6, vr->vrid);

	/* Search for existing interface with computed MAC address */
	struct interface **ifps;
	size_t ifps_cnt = if_lookup_by_hwaddr(
		r->vmac.octet, sizeof(r->vmac.octet), &ifps, VRF_DEFAULT);

	/*
	 * Filter to only those interfaces whose names begin with VRRP
	 * interface name. E.g. if this VRRP instance was configured on eth0,
	 * then we filter the list to only keep interfaces matching ^eth0.*
	 *
	 * If there are still multiple interfaces we just select the first one,
	 * as it should be functionally identical to the others.
	 */
	unsigned int candidates = 0;
	struct interface *selection = NULL;
	for (unsigned int i = 0; i < ifps_cnt; i++) {
		zlog_info("Found VRRP interface %s", ifps[i]->name);
		if (strncmp(ifps[i]->name, r->vr->ifp->name,
			    strlen(r->vr->ifp->name)))
			ifps[i] = NULL;
		else {
			selection = selection ? selection : ifps[i];
			candidates++;
		}
	}

	XFREE(MTYPE_TMP, ifps);

	char ethstr[ETHER_ADDR_STRLEN];
	prefix_mac2str(&r->vmac, ethstr, sizeof(ethstr));

	assert(!!selection == !!candidates);

	if (candidates == 0)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "No interface found w/ MAC %s; using default",
			  r->vr->vrid, ethstr);
	else if (candidates > 1)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Multiple VRRP interfaces found; using %s",
			  r->vr->vrid, selection->name);
	else
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Selected %s",
			  r->vr->vrid, selection->name);

	r->mvl_ifp = selection;

	return r;
}

static void vrrp_router_destroy(struct vrrp_router *r)
{
	if (r->sock_rx >= 0)
		close(r->sock_rx);
	if (r->sock_tx >= 0)
		close(r->sock_tx);
	/* FIXME: also delete list elements */
	list_delete(&r->addrs);
	XFREE(MTYPE_TMP, r);
}

struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid)
{
	struct vrrp_vrouter *vr =
		XCALLOC(MTYPE_TMP, sizeof(struct vrrp_vrouter));

	vr->ifp = ifp;
	vr->vrid = vrid;
	vr->priority = VRRP_DEFAULT_PRIORITY;
	vr->preempt_mode = true;
	vr->accept_mode = false;

	vr->v4 = vrrp_router_create(vr, AF_INET);
	vr->v6 = vrrp_router_create(vr, AF_INET6);

	vrrp_set_advertisement_interval(vr, VRRP_DEFAULT_ADVINT);

	hash_get(vrrp_vrouters_hash, vr, hash_alloc_intern);

	return vr;
}

void vrrp_vrouter_destroy(struct vrrp_vrouter *vr)
{
	vr->ifp = NULL;
	vrrp_router_destroy(vr->v4);
	vrrp_router_destroy(vr->v6);
	hash_release(vrrp_vrouters_hash, vr);
	XFREE(MTYPE_TMP, vr);
}

struct vrrp_vrouter *vrrp_lookup(uint8_t vrid)
{
	struct vrrp_vrouter vr;
	vr.vrid = vrid;

	return hash_lookup(vrrp_vrouters_hash, &vr);
}

/* Network ----------------------------------------------------------------- */

/* Forward decls */
static void vrrp_change_state(struct vrrp_router *r, int to);
static int vrrp_adver_timer_expire(struct thread *thread);
static int vrrp_master_down_timer_expire(struct thread *thread);

/*
 * Create and multicast a VRRP ADVERTISEMENT message.
 *
 * r
 *    VRRP Router for which to send ADVERTISEMENT
 */
static void vrrp_send_advertisement(struct vrrp_router *r)
{
	struct vrrp_pkt *pkt;
	ssize_t pktlen;
	struct ipaddr *addrs[r->addrs->count];
	union sockunion dest;

	list_to_array(r->addrs, (void **)addrs, r->addrs->count);

	pktlen = vrrp_pkt_build(&pkt, r->vr->vrid, r->priority,
				r->vr->advertisement_interval, r->addrs->count,
				(struct ipaddr **)&addrs);

	if (pktlen > 0)
		zlog_hexdump(pkt, (size_t) pktlen);
	else
		zlog_warn("Could not build VRRP packet");

	const char *group =
		r->family == AF_INET ? VRRP_MCASTV4_GROUP_STR : VRRP_MCASTV6_GROUP_STR;
	str2sockunion(group, &dest);

	ssize_t sent = sendto(r->sock_tx, pkt, (size_t)pktlen, 0, &dest.sa,
			      sockunion_sizeof(&dest));

	XFREE(MTYPE_TMP, pkt);

	if (sent < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to send VRRP Advertisement",
			  r->vr->vrid);
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
 * address owner).
 */
static int vrrp_recv_advertisement(struct vrrp_router *r, struct vrrp_pkt *pkt,
				    size_t pktsize)
{
	char dumpbuf[BUFSIZ];
	vrrp_pkt_dump(dumpbuf, sizeof(dumpbuf), pkt);
	zlog_debug("Received VRRP Advertisement:\n%s", dumpbuf);

	/* Check that VRID matches our configured VRID */
	if (pkt->hdr.vrid != r->vr->vrid) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"%s datagram invalid: Advertisement contains VRID %" PRIu8
			" which does not match our instance",
			r->vr->vrid, family2str(r->family), pkt->hdr.vrid);
		return -1;
	}

	/* Verify that we are not the IPvX address owner */
	if (r->is_owner) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"%s datagram invalid: Received advertisement but we are the address owner",
			r->vr->vrid, family2str(r->family));
		return -1;
	}

	/* Check that # IPs received matches our # configured IPs */
	if (pkt->hdr.naddr != r->addrs->count) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "%s datagram has %" PRIu8
			  " addresses, but this VRRP instance has %u",
			  r->vr->vrid, family2str(r->family), pkt->hdr.naddr,
			  r->addrs->count);
	}

	switch (r->fsm.state) {
	case VRRP_STATE_MASTER:
		if (pkt->hdr.priority == 0) {
			vrrp_send_advertisement(r);
			THREAD_OFF(r->t_adver_timer);
			thread_add_timer_msec(
				master, vrrp_adver_timer_expire, r,
				r->vr->advertisement_interval * 10,
				&r->t_adver_timer);
			/* FIXME: 6.4.3 mandates checking sender IP address */
		} else if (pkt->hdr.priority > r->priority) {
			zlog_err("NOT IMPLEMENTED");
			THREAD_OFF(r->t_adver_timer);
			r->master_adver_interval = ntohs(pkt->hdr.v3.adver_int);
			vrrp_recalculate_timers(r);
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(master,
					      vrrp_master_down_timer_expire, r,
					      r->master_down_interval * 10,
					      &r->t_master_down_timer);
			vrrp_change_state(r, VRRP_STATE_BACKUP);
		} else {
			/* Discard advertisement */
		}
		break;
	case VRRP_STATE_BACKUP:
		if (pkt->hdr.priority == 0) {
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(
				master, vrrp_master_down_timer_expire, r,
				r->skew_time * 10, &r->t_master_down_timer);
		} else if (r->vr->preempt_mode == false
			   || pkt->hdr.priority >= r->priority) {
			r->master_adver_interval = ntohs(pkt->hdr.v3.adver_int);
			vrrp_recalculate_timers(r);
			THREAD_OFF(r->t_master_down_timer);
			thread_add_timer_msec(master,
					      vrrp_master_down_timer_expire, r,
					      r->master_down_interval * 10,
					      &r->t_master_down_timer);
		} else if (r->vr->preempt_mode == true
			   && pkt->hdr.priority < r->priority) {
			/* Discard advertisement */
		}
		break;
	case VRRP_STATE_INITIALIZE:
		zlog_err(VRRP_LOGPFX VRRP_LOGPFX_VRID
			 "Received ADVERTISEMENT in state %s; this is a bug",
			 r->vr->vrid, vrrp_state_names[r->fsm.state]);
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
	uint8_t control[64];

	struct msghdr m;
	struct iovec iov;
	iov.iov_base = r->ibuf;
	iov.iov_len = sizeof(r->ibuf);
	m.msg_name = NULL;
	m.msg_namelen = 0;
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

	zlog_debug(VRRP_LOGPFX VRRP_LOGPFX_VRID "Received %s datagram: ",
		   r->vr->vrid, family2str(r->family));
	zlog_hexdump(r->ibuf, nbytes);

	pktsize = vrrp_parse_datagram(r->family, &m, nbytes, &pkt, errbuf,
				      sizeof(errbuf));

	if (pktsize < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "%s datagram invalid: %s",
			  r->vr->vrid, family2str(r->family), errbuf);
	} else {
		zlog_debug(VRRP_LOGPFX VRRP_LOGPFX_VRID "Packet looks good",
			   r->vr->vrid);
		vrrp_recv_advertisement(r, pkt, pktsize);
	}

	XFREE(MTYPE_TMP, pkt);

	resched = true;

done:
	memset(r->ibuf, 0x00, sizeof(r->ibuf));

	if (resched)
		thread_add_read(master, vrrp_read, r, r->sock_rx, &r->t_read);

	return 0;
}

/*
 * Finds the first connected address of the appropriate family on a VRRP
 * router's interface and binds the Tx socket of the VRRP router to that
 * address.
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
		if (c->address->family == r->family)
			break;

	if (c == NULL) {
		zlog_err(VRRP_LOGPFX VRRP_LOGPFX_VRID
			 "Failed to find %s address to bind on %s",
			 r->vr->vrid, family2str(r->family), ifp->name);
		return -1;
	}

	union sockunion su;
	memset(&su, 0x00, sizeof(su));

	switch (r->family) {
	case AF_INET:
		su.sin.sin_family = AF_INET;
		su.sin.sin_addr = c->address->u.prefix4;
		break;
	case AF_INET6:
		su.sin6.sin6_family = AF_INET6;
		su.sin6.sin6_scope_id = ifp->ifindex;
		su.sin6.sin6_addr = c->address->u.prefix6;
		break;
	}

	sockopt_reuseaddr(r->sock_tx);
	if (bind(r->sock_tx, (const struct sockaddr *)&su, sizeof(su)) < 0) {
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"Failed to bind Tx socket to primary IP address %s: %s",
			r->vr->vrid,
			inet_ntop(r->family,
				  (const void *)&c->address->u.prefix, ipstr,
				  sizeof(ipstr)),
			safe_strerror(errno));
		return -1;
	} else {
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Bound Tx socket to primary IP address %s",
			  r->vr->vrid,
			  inet_ntop(r->family,
				    (const void *)&c->address->u.prefix, ipstr,
				    sizeof(ipstr)));
	}

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

	frr_elevate_privs(&vrrp_privs)
	{
		r->sock_rx = socket(r->family, SOCK_RAW, IPPROTO_VRRP);
		r->sock_tx = socket(r->family, SOCK_RAW, IPPROTO_VRRP);
	}

	if (r->sock_rx < 0 || r->sock_tx < 0) {
		const char *rxtx = r->sock_rx < 0 ? "Rx" : "Tx";
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Can't create %s VRRP %s socket",
			  r->vr->vrid, family2str(r->family), rxtx);
		failed = true;
		goto done;
	}

	/* Configure sockets */
	if (!listcount(r->vr->ifp->connected)) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"No address on interface %s; cannot configure multicast",
			r->vr->vrid, r->vr->ifp->name);
		failed = true;
		goto done;
	}

	if (r->family == AF_INET) {
		/* Set Tx socket to always Tx with TTL set to 255 */
		int ttl = 255;
		ret = setsockopt(r->sock_tx, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
				 sizeof(ttl));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to set outgoing multicast TTL count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid);
		}

		/* Bind Rx socket to exact interface */
		vrrp_privs.change(ZPRIVS_RAISE);
		{
			ret = setsockopt(r->sock_rx, SOL_SOCKET,
					 SO_BINDTODEVICE, r->vr->ifp->name,
					 strlen(r->vr->ifp->name));
		}
		vrrp_privs.change(ZPRIVS_LOWER);
		if (ret) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to bind Rx socket to %s: %s",
				  r->vr->vrid, r->vr->ifp->name,
				  safe_strerror(errno));
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Bound Rx socket to %s",
			  r->vr->vrid, r->vr->ifp->name);

		/* Bind Rx socket to v4 multicast address */
		struct sockaddr_in sa = {0};
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(VRRP_MCASTV4_GROUP);
		if (bind(r->sock_rx, (struct sockaddr *)&sa, sizeof(sa))) {
			zlog_err(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to bind Rx socket to VRRP %s multicast group: %s",
				r->vr->vrid, family2str(r->family),
				safe_strerror(errno));
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Bound Rx socket to VRRP %s multicast group",
			  r->vr->vrid, family2str(r->family));

		/* Join Rx socket to VRRP IPv4 multicast group */
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
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Joined %s VRRP multicast group",
			  r->vr->vrid, family2str(r->family));

		/* Set outgoing interface for advertisements */
		struct ip_mreqn mreqn = {};
		mreqn.imr_ifindex = r->mvl_ifp->ifindex;
		ret = setsockopt(r->sock_tx, IPPROTO_IP, IP_MULTICAST_IF,
				 (void *)&mreqn, sizeof(mreqn));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Could not set %s as outgoing multicast interface",
				r->vr->vrid, r->mvl_ifp->name);
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Set %s as outgoing multicast interface",
			  r->vr->vrid, r->mvl_ifp->name);
	} else if (r->family == AF_INET6) {
		/* Always transmit IPv6 packets with hop limit set to 255 */
		ret = setsockopt_ipv6_multicast_hops(r->sock_tx, 255);
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to set outgoing multicast hop count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid);
		}
		ret = setsockopt_ipv6_hoplimit(r->sock_rx, 1);
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to request IPv6 Hop Limit delivery",
				  r->vr->vrid);
			failed = true;
			goto done;
		}

		/* Bind Rx socket to exact interface */
		vrrp_privs.change(ZPRIVS_RAISE);
		{
			ret = setsockopt(r->sock_rx, SOL_SOCKET,
					 SO_BINDTODEVICE, r->vr->ifp->name,
					 strlen(r->vr->ifp->name));
		}
		vrrp_privs.change(ZPRIVS_LOWER);
		if (ret) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to bind Rx socket to %s: %s",
				  r->vr->vrid, r->vr->ifp->name,
				  safe_strerror(errno));
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Bound Rx socket to %s",
			  r->vr->vrid, r->vr->ifp->name);

		/* Bind Rx socket to v6 multicast address */
		struct sockaddr_in6 sa = {0};
		sa.sin6_family = AF_INET6;
		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR, &sa.sin6_addr);
		if (bind(r->sock_rx, (struct sockaddr *)&sa, sizeof(sa))) {
			zlog_err(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to bind Rx socket to VRRP %s multicast group: %s",
				r->vr->vrid, family2str(r->family),
				safe_strerror(errno));
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Bound Rx socket to VRRP %s multicast group",
			  r->vr->vrid, family2str(r->family));

		/* Join VRRP IPv6 multicast group */
		struct ipv6_mreq mreq;
		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR,
			  &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = r->vr->ifp->ifindex;
		ret = setsockopt(r->sock_rx, IPPROTO_IPV6, IPV6_JOIN_GROUP,
				 &mreq, sizeof(mreq));
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to join VRRP %s multicast group",
				  r->vr->vrid, family2str(r->family));
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Joined %s VRRP multicast group",
			  r->vr->vrid, family2str(r->family));

		/* Set outgoing interface for advertisements */
		ret = setsockopt(r->sock_tx, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				 &r->mvl_ifp->ifindex, sizeof(ifindex_t));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Could not set %s as outgoing multicast interface",
				r->vr->vrid, r->mvl_ifp->name);
			failed = true;
			goto done;
		}
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Set %s as outgoing multicast interface",
			  r->vr->vrid, r->mvl_ifp->name);
	}

	/* Bind Tx socket to link-local address */
	if (vrrp_bind_to_primary_connected(r) < 0) {
		failed = true;
		goto done;
	}

done:
	ret = 0;
	if (failed) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to initialize VRRP %s router",
			  r->vr->vrid, family2str(r->family));
		if (r->sock_rx >= 0)
			close(r->sock_rx);
		if (r->sock_tx >= 0)
			close(r->sock_tx);
		ret = -1;
	}

	return ret;
}


/* State machine ----------------------------------------------------------- */

DEFINE_HOOK(vrrp_change_state_hook, (struct vrrp_router * r, int to), (r, to));

/*
 * Handle any necessary actions during state change to MASTER state.
 *
 * r
 *    VRRP Router to operate on
 */
static void vrrp_change_state_master(struct vrrp_router *r)
{
	/* NOTHING */
}

/*
 * Handle any necessary actions during state change to BACKUP state.
 *
 * r
 *    Virtual Router to operate on
 */
static void vrrp_change_state_backup(struct vrrp_router *r)
{
	/* Uninstall ARP entry for router MAC */
	/* ... */
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
	r->vr->advertisement_interval = r->vr->advertisement_interval;
	r->master_adver_interval = 0;
	vrrp_recalculate_timers(r);
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
	/* Call our handlers, then any subscribers */
	vrrp_change_state_handlers[to](r);
	hook_call(vrrp_change_state_hook, r, to);
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "%s -> %s", r->vr->vrid,
		  vrrp_state_names[r->fsm.state], vrrp_state_names[to]);
	r->fsm.state = to;
}

/*
 * Called when Adver_Timer expires.
 */
static int vrrp_adver_timer_expire(struct thread *thread)
{
	struct vrrp_router *r = thread->arg;

	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Adver_Timer expired",
		  r->vr->vrid);

	if (r->fsm.state == VRRP_STATE_MASTER) {
		/* Send an ADVERTISEMENT */
		vrrp_send_advertisement(r);

		/* Reset the Adver_Timer to Advertisement_Interval */
		thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
				      r->vr->advertisement_interval * 10,
				      &r->t_adver_timer);
	} else {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Adver_Timer expired in state '%s'; this is a bug",
			  r->vr->vrid, vrrp_state_names[r->fsm.state]);
	}

	return 0;
}

/*
 * Called when Master_Down_Timer expires.
 */
static int vrrp_master_down_timer_expire(struct thread *thread)
{
	struct vrrp_router *r = thread->arg;

	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Master_Down_Timer expired",
		  r->vr->vrid);

	vrrp_send_advertisement(r);
	if (r->family == AF_INET)
		vrrp_garp_send_all(r);
	thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
			      r->vr->advertisement_interval * 10,
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
	if (r->mvl_ifp == NULL) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "No appropriate interface for %s VRRP found",
			  r->vr->vrid, family2str(r->family));
		return -1;
	}

	/* Initialize global gratuitous ARP socket if necessary */
	if (r->family == AF_INET && !vrrp_garp_is_init())
		vrrp_garp_init();

	/* Create socket */
	if (r->sock_rx < 0 || r->sock_tx < 0) {
		int ret = vrrp_socket(r);
		if (ret < 0 || r->sock_tx < 0 || r->sock_rx < 0)
			return ret;
	}

	/* Schedule listener */
	thread_add_read(master, vrrp_read, r, r->sock_rx, &r->t_read);

	/* Configure effective priority */
	struct ipaddr *primary = (struct ipaddr *)listhead(r->addrs)->data;

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(r->family, &primary->ip.addr, ipbuf, sizeof(ipbuf));

	if (vrrp_is_owner(r->vr->ifp, primary)) {
		r->priority = VRRP_PRIO_MASTER;
		vrrp_recalculate_timers(r);

		zlog_info(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"%s owns primary Virtual Router IP %s; electing self as Master",
			r->vr->vrid, r->vr->ifp->name, ipbuf);
	}

	if (r->priority == VRRP_PRIO_MASTER) {
		vrrp_send_advertisement(r);

		if (r->family == AF_INET)
			vrrp_garp_send_all(r);

		thread_add_timer_msec(master, vrrp_adver_timer_expire, r,
				      r->vr->advertisement_interval * 10,
				      &r->t_adver_timer);
		vrrp_change_state(r, VRRP_STATE_MASTER);
	} else {
		r->master_adver_interval = r->vr->advertisement_interval;
		vrrp_recalculate_timers(r);
		thread_add_timer_msec(master, vrrp_master_down_timer_expire, r,
				      r->master_down_interval * 10,
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
	switch (r->fsm.state) {
	case VRRP_STATE_MASTER:
		/* Cancel the Adver_Timer */
		THREAD_OFF(r->t_adver_timer);
		/* Send an ADVERTISEMENT with Priority = 0 */
		uint8_t saved_prio = r->priority;
		r->priority = 0;
		vrrp_send_advertisement(r);
		r->priority = saved_prio;
		break;
	case VRRP_STATE_BACKUP:
		/* Cancel the Master_Down_Timer */
		THREAD_OFF(r->t_master_down_timer);
		break;
	case VRRP_STATE_INITIALIZE:
		zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Received '%s' event in '%s' state; ignoring",
			  r->vr->vrid, vrrp_event_names[VRRP_EVENT_SHUTDOWN],
			  vrrp_state_names[VRRP_STATE_INITIALIZE]);
		break;
	}

	/* Transition to the Initialize state */
	vrrp_change_state(r, VRRP_STATE_INITIALIZE);

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
 */
int vrrp_event(struct vrrp_router *r, int event)
{
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "'%s' event", r->vr->vrid,
		  vrrp_event_names[r->fsm.state]);
	return vrrp_event_handlers[event](r);
}


/* Other ------------------------------------------------------------------- */

static unsigned int vrrp_hash_key(void *arg)
{
	struct vrrp_vrouter *vr = arg;

	return vr->vrid;
}

static bool vrrp_hash_cmp(const void *arg1, const void *arg2)
{
	const struct vrrp_vrouter *vr1 = arg1;
	const struct vrrp_vrouter *vr2 = arg2;

	return vr1->vrid == vr2->vrid;
}

void vrrp_init(void)
{
	vrrp_vrouters_hash = hash_create(&vrrp_hash_key, vrrp_hash_cmp,
					 "VRRP virtual router hash");
	vrf_init(NULL, NULL, NULL, NULL, NULL);
}
