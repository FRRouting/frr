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

#include "lib/memory.h"
#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/prefix.h"
#include "lib/hash.h"
#include "lib/vrf.h"
#include "lib/hook.h"

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
 * Sets advertisement_interval and master_adver_interval on a Virtual Router,
 * then recalculates and sets skew_time and master_down_interval based on these
 * values.
 *
 * vr
 *    Virtual Router to operate on
 *
 * advertisement_interval
 *    Advertisement_Interval to set
 *
 * master_adver_interval
 *    Master_Adver_Interval to set
 */
static void vrrp_update_times(struct vrrp_vrouter *vr,
			      uint16_t advertisement_interval,
			      uint16_t master_adver_interval)
{
	vr->advertisement_interval = advertisement_interval;
	vr->master_adver_interval = master_adver_interval;
	vr->skew_time = ((256 - vr->priority) * master_adver_interval) / 256;
	vr->master_down_interval = (3 * master_adver_interval);
	vr->master_down_interval += vr->skew_time;
}

/*
 */
static void vrrp_reset_times(struct vrrp_vrouter *vr)
{
	vrrp_update_times(vr, vr->advertisement_interval, 0);
}

/*
 * Determines if a VRRP router is the owner of the specified address.
 *
 * vr
 *    VRRP router
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
	if (vr->priority_conf == priority)
		return;

	vr->priority_conf = priority;
}

void vrrp_set_advertisement_interval(struct vrrp_vrouter *vr,
				     uint16_t advertisement_interval)
{
	if (vr->advertisement_interval == advertisement_interval)
		return;

	vrrp_update_times(vr, advertisement_interval, vr->master_adver_interval);
}

void vrrp_add_ip(struct vrrp_vrouter *vr, struct in_addr v4)
{
	struct in_addr *v4_ins = XCALLOC(MTYPE_TMP, sizeof(struct in_addr));

	*v4_ins = v4;
	listnode_add(vr->v4, v4_ins);
}


/* Creation and destruction ------------------------------------------------ */

struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid)
{
	struct vrrp_vrouter *vr =
		XCALLOC(MTYPE_TMP, sizeof(struct vrrp_vrouter));

	vr->sock = -1;
	vr->ifp = ifp;
	vr->vrid = vrid;
	vr->v4 = list_new();
	vr->v6 = list_new();
	vr->priority_conf = VRRP_DEFAULT_PRIORITY;
	vr->priority = VRRP_DEFAULT_PRIORITY;
	vr->preempt_mode = true;
	vr->accept_mode = false;
	vrrp_mac_set(&vr->vr_mac_v4, false, vrid);
	vrrp_mac_set(&vr->vr_mac_v6, true, vrid);
	vr->fsm.state = VRRP_STATE_INITIALIZE;
	vrrp_set_advertisement_interval(vr, VRRP_DEFAULT_ADVINT);
	vrrp_reset_times(vr);

	hash_get(vrrp_vrouters_hash, vr, hash_alloc_intern);

	return vr;
}

void vrrp_vrouter_destroy(struct vrrp_vrouter *vr)
{
	if (vr->sock >= 0)
		close(vr->sock);
	vr->ifp = NULL;
	list_delete(&vr->v4);
	list_delete(&vr->v6);
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
 * Create and broadcast VRRP ADVERTISEMENT message.
 *
 * vr
 *    Virtual Router for which to send ADVERTISEMENT
 */
static void vrrp_send_advertisement(struct vrrp_vrouter *vr)
{
	struct vrrp_pkt *pkt;
	ssize_t pktlen;
	struct in_addr *v4[vr->v4->count];
	struct in6_addr *v6[vr->v6->count];
	struct sockaddr_in dest;

	list_to_array(vr->v4, (void **)v4, vr->v4->count);
	list_to_array(vr->v6, (void **)v6, vr->v6->count);

	pktlen = vrrp_pkt_build(&pkt, vr->vrid, vr->priority,
				vr->advertisement_interval, false,
				vr->v4->count, (void **)&v4);

	if (pktlen > 0)
		zlog_hexdump(pkt, (size_t) pktlen);
	else
		zlog_warn("Could not build VRRP packet");

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = htonl(VRRP_MCAST_GROUP_HEX);

	ssize_t sent = sendto(vr->sock, pkt, (size_t)pktlen, 0, &dest,
			      sizeof(struct sockaddr_in));

	if (sent < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Failed to send VRRP Advertisement",
			  vr->vrid);
	}
}

/* FIXME:
static void vrrp_recv_advertisement(struct thread *thread)
{
}
*/

/*
 * Create Virtual Router listen socket and join it to the VRRP multicast group.
 *
 * The first connected address on the Virtual Router's interface is used as the
 * interface address.
 *
 * vr
 *    Virtual Router for which to create listen socket
 */
static int vrrp_socket(struct vrrp_vrouter *vr)
{
	struct ip_mreqn req;
	int ret;
	struct connected *c;

	frr_elevate_privs(&vrrp_privs) {
		vr->sock = socket(AF_INET, SOCK_RAW, IPPROTO_VRRP);
	}

	if (vr->sock < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Can't create VRRP socket",
			  vr->vrid);
		return errno;
	}

	/* Join the multicast group.*/

	 /* FIXME: Use first address on the interface and for imr_interface */
	if (!listcount(vr->ifp->connected))
		return -1;

	c = listhead(vr->ifp->connected)->data;
	struct in_addr v4 = c->address->u.prefix4;

	memset(&req, 0, sizeof(req));
	req.imr_multiaddr.s_addr = htonl(VRRP_MCAST_GROUP_HEX);
	req.imr_address = v4;
	req.imr_ifindex = 0; // FIXME: vr->ifp->ifindex ?
	ret = setsockopt(vr->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&req,
			 sizeof(struct ip_mreq));
	if (ret < 0) {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Can't join VRRP multicast group",
			  vr->vrid);
		return errno;
	}
	return 0;
}


/* State machine ----------------------------------------------------------- */

DEFINE_HOOK(vrrp_change_state_hook, (struct vrrp_vrouter *vr, int to), (vr, to));

/*
 * Handle any necessary actions during state change to MASTER state.
 *
 * vr
 *    Virtual Router to operate on
 */
static void vrrp_change_state_master(struct vrrp_vrouter *vr)
{
}

/*
 * Handle any necessary actions during state change to BACKUP state.
 *
 * vr
 *    Virtual Router to operate on
 */
static void vrrp_change_state_backup(struct vrrp_vrouter *vr)
{
	/* Uninstall ARP entry for vrouter MAC */
	/* ... */
}

/*
 * Handle any necessary actions during state change to INITIALIZE state.
 *
 * This is not called for initial startup, only when transitioning from MASTER
 * or BACKUP.
 *
 * vr
 *    Virtual Router to operate on
 */
static void vrrp_change_state_initialize(struct vrrp_vrouter *vr)
{
	/* Reset timers */
	vrrp_reset_times(vr);
}

void (*vrrp_change_state_handlers[])(struct vrrp_vrouter *vr) = {
	[VRRP_STATE_MASTER] = vrrp_change_state_master,
	[VRRP_STATE_BACKUP] = vrrp_change_state_backup,
	[VRRP_STATE_INITIALIZE] = vrrp_change_state_initialize,
};

/*
 * Change Virtual Router FSM position. Handles transitional actions and calls
 * any subscribers to the state change hook.
 *
 * vr
 *    Virtual Router for which to change state
 *
 * to
 *    State to change to
 */
static void vrrp_change_state(struct vrrp_vrouter *vr, int to)
{
	/* Call our handlers, then any subscribers */
	vrrp_change_state_handlers[to](vr);
	hook_call(vrrp_change_state_hook, vr, to);
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "%s -> %s", vr->vrid,
		  vrrp_state_names[vr->fsm.state], vrrp_state_names[to]);
	vr->fsm.state = to;
}

/*
 * Called when Adver_Timer expires.
 */
static int vrrp_adver_timer_expire(struct thread *thread)
{
	struct vrrp_vrouter *vr = thread->arg;

	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Adver_Timer expired", vr->vrid);

	if (vr->fsm.state == VRRP_STATE_MASTER) {
		/* Send an ADVERTISEMENT */
		vrrp_send_advertisement(vr);

		/* Reset the Adver_Timer to Advertisement_Interval */
		thread_add_timer_msec(master, vrrp_adver_timer_expire, vr,
				      vr->advertisement_interval * 10,
				      &vr->t_adver_timer);
	} else {
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID
			  "Adver_Timer expired in state '%s'; this is a bug",
			  vr->vrid, vrrp_state_names[vr->fsm.state]);
	}

	return 0;
}

/*
 * Called when Master_Down_Timer expires.
 */
static int vrrp_master_down_timer_expire(struct thread *thread)
{
	struct vrrp_vrouter *vr = thread->arg;

	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "Master_Down_Timer expired",
		  vr->vrid);

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
 * vr
 *    Virtual Router on which to apply Startup event
 *
 * Returns:
 *    < 0 if the session socket could not be created, or the state is not
 *        Initialize
 *      0 on success
 */
static int vrrp_startup(struct vrrp_vrouter *vr)
{
	/* May only be called when the state is Initialize */
	if (vr->fsm.state != VRRP_STATE_INITIALIZE)
		return -1;

	/* Initialize global gratuitous ARP socket if necessary */
	if (!vrrp_garp_is_init())
		vrrp_garp_init();

	/* Create socket */
	int ret = vrrp_socket(vr);
	if (ret < 0)
		return ret;

	/* Schedule listener */
	/* ... */

	/* configure effective priority */
	struct in_addr *primary = (struct in_addr *) listhead(vr->v4)->data;
	struct ipaddr primary_ipaddr;
	primary_ipaddr.ipa_type = IPADDR_V4;
	primary_ipaddr.ipaddr_v4 = *primary;

	char ipbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, primary, ipbuf, sizeof(ipbuf));

	if (vrrp_is_owner(vr, &primary_ipaddr)) {
		vr->priority = VRRP_PRIO_MASTER;
		/* Timers depend on priority value, need to recalculate them */
		vrrp_update_times(vr, vr->advertisement_interval,
				  vr->master_adver_interval);
		zlog_info(
			VRRP_LOGPFX VRRP_LOGPFX_VRID
			"%s owns primary Virtual Router IP %s; electing self as Master",
			vr->vrid, vr->ifp->name, ipbuf);
	}

	if (vr->priority == VRRP_PRIO_MASTER) {
		vrrp_send_advertisement(vr);
		vrrp_garp_send_all(vr);

		thread_add_timer_msec(master, vrrp_adver_timer_expire, vr,
				      vr->advertisement_interval * 10,
				      &vr->t_adver_timer);
		vrrp_change_state(vr, VRRP_STATE_MASTER);
	} else {
		vrrp_update_times(vr, vr->advertisement_interval,
				  vr->advertisement_interval);
		thread_add_timer_msec(master, vrrp_master_down_timer_expire, vr,
				      vr->master_down_interval * 10,
				      &vr->t_master_down_timer);
		vrrp_change_state(vr, VRRP_STATE_BACKUP);
	}

	return 0;
}

/*
 * Shuts down a Virtual Router and transitions it to Initialize.
 *
 * This call must be idempotent; it is safe to call multiple times on the same
 * Virtual Router.
 */
static int vrrp_shutdown(struct vrrp_vrouter *vr)
{
	switch (vr->fsm.state) {
		case VRRP_STATE_MASTER:
			/* Cancel the Adver_Timer */
			THREAD_OFF(vr->t_adver_timer);
			/* Send an ADVERTISEMENT with Priority = 0 */
			uint8_t saved_prio = vr->priority;
			vr->priority = 0;
			vrrp_send_advertisement(vr);
			vr->priority = saved_prio;
			break;
		case VRRP_STATE_BACKUP:
			/* Cancel the Master_Down_Timer */
			THREAD_OFF(vr->t_master_down_timer);
			break;
		case VRRP_STATE_INITIALIZE:
			zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID
				  "Received '%s' event in '%s' state; ignoring",
				  vr->vrid,
				  vrrp_event_names[VRRP_EVENT_SHUTDOWN],
				  vrrp_state_names[VRRP_STATE_INITIALIZE]);
			break;
	}

	/* close socket */
	if (vr->sock >= 0)
		close(vr->sock);

	/* Transition to the Initialize state */
	vrrp_change_state(vr, VRRP_STATE_INITIALIZE);

	return 0;
}

static int (*vrrp_event_handlers[])(struct vrrp_vrouter *vr) = {
	[VRRP_EVENT_STARTUP] = vrrp_startup,
	[VRRP_EVENT_SHUTDOWN] = vrrp_shutdown,
};

/*
 * Spawn a VRRP FSM event on a Virtual Router.
 *
 * vr
 *    Virtual Router on which to spawn event
 *
 * event
 *    The event to spawn
 */
int vrrp_event(struct vrrp_vrouter *vr, int event)
{
	zlog_info(VRRP_LOGPFX VRRP_LOGPFX_VRID "'%s' event", vr->vrid,
		  vrrp_event_names[vr->fsm.state]);
	return vrrp_event_handlers[event](vr);
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
