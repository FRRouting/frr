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
 * vr
 *    Virtual Router
 *
 * Returns:
 *    whether or not vr owns the specified address
 */
static bool vrrp_is_owner(struct vrrp_vrouter *vr, struct ipaddr *addr)
{
	struct prefix *p;
	struct prefix_ipv4 p4;
	struct prefix_ipv6 p6;

	if (IS_IPADDR_V4(addr)) {
		p4.family = AF_INET;
		p4.prefixlen = IPV4_MAX_BITLEN;
		p4.prefix = addr->ipaddr_v4;
		p = (struct prefix *)&p4;
	} else {
		p6.family = AF_INET6;
		p6.prefixlen = IPV6_MAX_BITLEN;
		memcpy(&p6.prefix, &addr->ipaddr_v6, sizeof(struct in6_addr));
		p = (struct prefix *)&p6;
	}

	return !!connected_lookup_prefix_exact(vr->ifp, p);
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
	listnode_add(vr->v4->addrs, v4_ins);
}

void vrrp_add_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6)
{
	struct ipaddr *v6_ins = XCALLOC(MTYPE_TMP, sizeof(struct ipaddr));

	v6_ins->ipa_type = IPADDR_V6;
	memcpy(&v6_ins->ipaddr_v6, &v6, sizeof(struct in6_addr));
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
	r->sock = -1;
	r->vr = vr;
	r->addrs = list_new();
	r->priority = vr->priority;
	r->fsm.state = VRRP_STATE_INITIALIZE;
	vrrp_mac_set(&r->vmac, family == AF_INET6, vr->vrid);

	return r;
}

static void vrrp_router_destroy(struct vrrp_router *r)
{
	if (r->sock >= 0)
		close(r->sock);
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

	ssize_t sent = sendto(r->sock, pkt, (size_t)pktlen, 0, &dest.sa,
			      sockunion_sizeof(&dest));

	if (sent < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to send VRRP Advertisement",
			  r->vr->vrid);
	}
}

static void vrrp_recv_advertisement(struct vrrp_router *r, struct vrrp_pkt *pkt,
				    size_t pktsize)
{
	char dumpbuf[BUFSIZ];
	vrrp_pkt_dump(dumpbuf, sizeof(dumpbuf), pkt);
	zlog_debug("Received VRRP Advertisement:\n%s", dumpbuf);
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

	nbytes = recvmsg(r->sock, &m, MSG_DONTWAIT);

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

	resched = true;

done:
	memset(r->ibuf, 0x00, sizeof(r->ibuf));

	if (resched)
		thread_add_read(master, vrrp_read, r, r->sock, &r->t_read);

	return 0;
}

/*
 * Create Virtual Router listen socket and join it to the VRRP multicast group.
 *
 * The first connected address on the Virtual Router's interface is used as the
 * interface address.
 *
 * r
 *    VRRP Router for which to create listen socket
 */
static int vrrp_socket(struct vrrp_router *r)
{
	int ret;
	bool failed = false;
	struct connected *c;

	frr_elevate_privs(&vrrp_privs) {
		r->sock = socket(r->family, SOCK_RAW, IPPROTO_VRRP);
	}

	if (r->sock < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Can't create %s VRRP socket",
			  r->vr->vrid, r->family == AF_INET ? "v4" : "v6");
		failed = true;
		goto done;
	}

	if (!listcount(r->vr->ifp->connected)) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"No address on interface %s; cannot configure multicast",
			r->vr->vrid, r->vr->ifp->name);
		failed = true;
		goto done;
	}

	if (r->family == AF_INET) {
		int ttl = 255;
		ret = setsockopt(r->sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
				 sizeof(ttl));
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to set outgoing multicast TTL count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid);
		}

		c = listhead(r->vr->ifp->connected)->data;
		struct in_addr v4 = c->address->u.prefix4;

		/* Join VRRP IPv4 multicast group */
		ret = setsockopt_ipv4_multicast(r->sock, IP_ADD_MEMBERSHIP, v4,
						htonl(VRRP_MCASTV4_GROUP),
						r->vr->ifp->ifindex);
	} else if (r->family == AF_INET6) {
		ret = setsockopt_ipv6_multicast_hops(r->sock, 255);
		if (ret < 0) {
			zlog_warn(
				VRRP_LOGPFX VRRP_LOGPFX_VRID
				"Failed to set outgoing multicast hop count to 255; RFC 5798 compliant implementations will drop our packets",
				r->vr->vrid);
		}
		ret = setsockopt_ipv6_hoplimit(r->sock, 1);
		if (ret < 0) {
			zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Failed to request IPv6 Hop Limit delivery",
				  r->vr->vrid);
			failed = true;
			goto done;
		}

		/* Join VRRP IPv6 multicast group */
		struct ipv6_mreq mreq;
		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = r->vr->ifp->ifindex;
		ret = setsockopt(r->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq,
			   sizeof(mreq));
	}

	if (ret < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to join VRRP %s multicast group",
			  r->vr->vrid, family2str(r->family));
		failed = true;
	}
done:
	ret = 0;
	if (failed) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to initialize VRRP %s router",
			  r->vr->vrid, family2str(r->family));
		if (r->sock >= 0)
			close(r->sock);
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

	/* Initialize global gratuitous ARP socket if necessary */
	if (r->family == AF_INET && !vrrp_garp_is_init())
		vrrp_garp_init();

	/* Create socket */
	if (r->sock < 0) {
		int ret = vrrp_socket(r);
		if (ret < 0 || r->sock < 0)
			return ret;
	}

	/* Schedule listener */
	thread_add_read(master, vrrp_read, r, r->sock, &r->t_read);

	/* Configure effective priority */
	struct ipaddr *primary = (struct ipaddr *)listhead(r->addrs)->data;

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(r->family, &primary->ip.addr, ipbuf, sizeof(ipbuf));

	if (vrrp_is_owner(r->vr, primary)) {
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
