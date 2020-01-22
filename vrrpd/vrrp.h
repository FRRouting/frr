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
#ifndef __VRRP_H__
#define __VRRP_H__

#include <zebra.h>
#include <netinet/ip.h>

#include "lib/memory.h"
#include "lib/hash.h"
#include "lib/hook.h"
#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/northbound.h"
#include "lib/privs.h"
#include "lib/stream.h"
#include "lib/thread.h"
#include "lib/vty.h"

/* Global definitions */
#define VRRP_RADV_INT 16
#define VRRP_PRIO_MASTER 255
#define VRRP_MCASTV4_GROUP_STR "224.0.0.18"
#define VRRP_MCASTV6_GROUP_STR "ff02:0:0:0:0:0:0:12"
#define VRRP_MCASTV4_GROUP 0xe0000012
#define VRRP_MCASTV6_GROUP 0xff020000000000000000000000000012
#define IPPROTO_VRRP 112

#define VRRP_LOGPFX_VRID "[VRID %u] "
#define VRRP_LOGPFX_FAM "[%s] "

/* Default defaults */
#define VRRP_XPATH_FULL "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group"
#define VRRP_XPATH "./frr-vrrpd:vrrp/vrrp-group"
#define VRRP_DEFAULT_PRIORITY 100
#define VRRP_DEFAULT_ADVINT 100
#define VRRP_DEFAULT_PREEMPT true
#define VRRP_DEFAULT_ACCEPT true
#define VRRP_DEFAULT_SHUTDOWN false

/* User compatibility constant */
#define CS2MS 10

DECLARE_MGROUP(VRRPD)

/* Northbound */
extern const struct frr_yang_module_info frr_vrrpd_info;

/* Configured defaults */
struct vrrp_defaults {
	uint8_t version;
	uint8_t priority;
	uint16_t advertisement_interval;
	bool preempt_mode;
	bool accept_mode;
	bool shutdown;
};

extern struct vrrp_defaults vd;

/* threadmaster */
extern struct thread_master *master;

/* privileges */
extern struct zebra_privs_t vrrp_privs;

/* Global hash of all Virtual Routers */
extern struct hash *vrrp_vrouters_hash;

/*
 * VRRP Router.
 *
 * This struct contains all state for a particular VRRP Router operating
 * in a Virtual Router for either IPv4 or IPv6.
 */
struct vrrp_router {
	/*
	 * Whether this VRRP Router is active.
	 */
	bool is_active;

	/* Whether we are the address owner */
	bool is_owner;

	/* Rx socket: Rx from parent of mvl_ifp */
	int sock_rx;
	/* Tx socket; Tx from mvl_ifp */
	int sock_tx;

	/* macvlan interface */
	struct interface *mvl_ifp;

	/* Source address for advertisements */
	struct ipaddr src;

	/* Socket read buffer */
#ifdef FUZZING
	size_t fuzzing_input_size;
	struct sockaddr_in fuzzing_sa;
#endif
	uint8_t ibuf[IP_MAXPACKET];

	/*
	 * Address family of this Virtual Router.
	 * Either AF_INET or AF_INET6.
	 */
	int family;

	/*
	 * Virtual Router this VRRP Router is participating in.
	 */
	struct vrrp_vrouter *vr;

	/*
	 * One or more IPvX addresses associated with this Virtual
	 * Router. The first address must be the "primary" address this
	 * Virtual Router is backing up in the case of IPv4. In the case of
	 * IPv6 it must be the link-local address of vr->ifp.
	 *
	 * Type: struct ipaddr *
	 */
	struct list *addrs;

	/*
	 * This flag says whether we are waiting on an interface up
	 * notification from Zebra before we send an ADVERTISEMENT.
	 */
	bool advert_pending;

	/*
	 * If this is an IPv4 VRRP router, this flag says whether we are
	 * waiting on an interface up notification from Zebra before we send
	 * gratuitous ARP packets for all our addresses. Should never be true
	 * if family == AF_INET6.
	 */
	bool garp_pending;
	/*
	 * If this is an IPv6 VRRP router, this flag says whether we are
	 * waiting on an interface up notification from Zebra before we send
	 * Unsolicited Neighbor Advertisement packets for all our addresses.
	 * Should never be true if family == AF_INET.
	 */
	bool ndisc_pending;

	/*
	 * Effective priority
	 *    => vr->priority if we are Backup
	 *    => 255 if we are Master
	 */
	uint8_t priority;

	/*
	 * Advertisement interval contained in ADVERTISEMENTS received from the
	 * Master (centiseconds)
	 */
	uint16_t master_adver_interval;

	/*
	 * Time to skew Master_Down_Interval in centiseconds. Calculated as:
	 * (((256 - priority) * Master_Adver_Interval) / 256)
	 */
	uint16_t skew_time;

	/*
	 * Time interval for Backup to declare Master down (centiseconds).
	 * Calculated as:
	 * (3 * Master_Adver_Interval) + Skew_time
	 */
	uint16_t master_down_interval;

	/*
	 * The MAC address used for the source MAC address in VRRP
	 * advertisements, advertised in ARP requests/responses, and advertised
	 * in ND Neighbor Advertisements.
	 */
	struct ethaddr vmac;

	struct {
		int state;
	} fsm;

	struct {
		/* Total number of advertisements sent and received */
		uint32_t adver_tx_cnt;
		uint32_t adver_rx_cnt;
		/* Total number of gratuitous ARPs sent */
		uint32_t garp_tx_cnt;
		/* Total number of unsolicited Neighbor Advertisements sent */
		uint32_t una_tx_cnt;
		/* Total number of state transitions */
		uint32_t trans_cnt;
	} stats;

	struct thread *t_master_down_timer;
	struct thread *t_adver_timer;
	struct thread *t_read;
	struct thread *t_write;
};

/*
 * VRRP Virtual Router.
 *
 * This struct contains all state and configuration for a given Virtual Router
 * Identifier on a given interface, both v4 and v6.
 *
 * RFC5798 s. 1 states:
 *    "Within a VRRP router, the virtual routers in each of the IPv4 and IPv6
 *    address families are a domain unto themselves and do not overlap."
 *
 * This implementation has chosen the tuple (interface, VRID) as the key for a
 * particular VRRP Router, and the rest of the program is designed around this
 * assumption. Additionally, base protocol configuration parameters such as the
 * advertisement interval and (configured) priority are shared between v4 and
 * v6 instances. This corresponds to the choice made by other industrial
 * implementations.
 */
struct vrrp_vrouter {
	/* Whether this instance was automatically configured */
	bool autoconf;

	/* Whether this VRRP router is in administrative shutdown */
	bool shutdown;

	/* Interface */
	struct interface *ifp;

	/* Version */
	uint8_t version;

	/* Virtual Router Identifier */
	uint32_t vrid;

	/* Configured priority */
	uint8_t priority;

	/*
	 * Time interval between ADVERTISEMENTS (centiseconds). Default is 100
	 * centiseconds (1 second).
	 */
	uint16_t advertisement_interval;

	/*
	 * Controls whether a (starting or restarting) higher-priority Backup
	 * router preempts a lower-priority Master router. Values are True to
	 * allow preemption and False to prohibit preemption. Default is True.
	 */
	bool preempt_mode;

	/*
	 * Controls whether a virtual router in Master state will accept
	 * packets addressed to the address owner's IPvX address as its own if
	 * it is not the IPvX address owner. The default is False.
	 */
	bool accept_mode;

	struct vrrp_router *v4;
	struct vrrp_router *v6;
};

/*
 * Initialize VRRP global datastructures.
 */
void vrrp_init(void);

/*
 * Destroy all VRRP instances and gracefully shutdown.
 *
 * For instances in Master state, VRRP advertisements with 0 priority will be
 * sent if possible to notify Backup routers that we are going away.
 */
void vrrp_fini(void);


/* Creation and destruction ------------------------------------------------ */

/*
 * Create and register a new VRRP Virtual Router.
 *
 * ifp
 *    Base interface to configure VRRP on
 *
 * vrid
 *    Virtual Router Identifier
 */
struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid,
					 uint8_t version);

/*
 * Destroy a VRRP Virtual Router, freeing all its resources.
 *
 * If there are any running VRRP instances, these are stopped and destroyed.
 */
void vrrp_vrouter_destroy(struct vrrp_vrouter *vr);


/* Configuration controllers ----------------------------------------------- */

/*
 * Check if a Virtual Router ought to be started, and if so, start it.
 *
 * vr
 *    Virtual Router to checkstart
 */
void vrrp_check_start(struct vrrp_vrouter *vr);

/*
 * Change the configured priority of a VRRP Virtual Router.
 *
 * Note that this only changes the configured priority of the Virtual Router.
 * The currently effective priority will not be changed; to change the
 * effective priority, the Virtual Router must be restarted by issuing a
 * VRRP_EVENT_SHUTDOWN followed by a VRRP_EVENT_STARTUP.
 *
 * vr
 *    Virtual Router to change priority of
 *
 * priority
 *    New priority
 */
void vrrp_set_priority(struct vrrp_vrouter *vr, uint8_t priority);

/*
 * Set Advertisement Interval on this Virtual Router.
 *
 * vr
 *    Virtual Router to change priority of
 *
 * advertisement_interval
 *    New advertisement interval
 */
void vrrp_set_advertisement_interval(struct vrrp_vrouter *vr,
				     uint16_t advertisement_interval);

/*
 * Add an IPvX address to a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to add IPvx address to
 *
 * ip
 *    Address to add
 *
 * activate
 *    Whether to automatically start the VRRP router if this is the first IP
 *    address added.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_add_ip(struct vrrp_vrouter *vr, struct ipaddr *ip);

/*
 * Add an IPv4 address to a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to add IPv4 address to
 *
 * v4
 *    Address to add
 *
 * activate
 *    Whether to automatically start the VRRP router if this is the first IP
 *    address added.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_add_ipv4(struct vrrp_vrouter *vr, struct in_addr v4);

/*
 * Add an IPv6 address to a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to add IPv6 address to
 *
 * v6
 *    Address to add
 *
 * activate
 *    Whether to automatically start the VRRP router if this is the first IP
 *    address added.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_add_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6);

/*
 * Remove an IP address from a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to remove IP address from
 *
 * ip
 *    Address to remove
 *
 * deactivate
 *    Whether to automatically stop the VRRP router if removing v4 would leave
 *    us with an empty address list. If this is not true and ip is the only IP
 *    address backed up by this virtual router, this function will not remove
 *    the address and return failure.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_del_ip(struct vrrp_vrouter *vr, struct ipaddr *ip);

/*
 * Remove an IPv4 address from a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to remove IPv4 address from
 *
 * v4
 *    Address to remove
 *
 * deactivate
 *    Whether to automatically stop the VRRP router if removing v4 would leave
 *    us with an empty address list. If this is not true and v4 is the only
 *    IPv4 address backed up by this virtual router, this function will not
 *    remove the address and return failure.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_del_ipv4(struct vrrp_vrouter *vr, struct in_addr v4);

/*
 * Remove an IPv6 address from a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to remove IPv6 address from
 *
 * v6
 *    Address to remove
 *
 * deactivate
 *    Whether to automatically stop the VRRP router if removing v5 would leave
 *    us with an empty address list. If this is not true and v4 is the only
 *    IPv6 address backed up by this virtual router, this function will not
 *    remove the address and return failure.
 *
 * Returns:
 *    -1 on error
 *     0 otherwise
 */
int vrrp_del_ipv6(struct vrrp_vrouter *vr, struct in6_addr v6);

#ifdef FUZZING
int vrrp_read(struct thread *thread);
#endif

/* State machine ----------------------------------------------------------- */

#define VRRP_STATE_INITIALIZE 0
#define VRRP_STATE_MASTER 1
#define VRRP_STATE_BACKUP 2
#define VRRP_EVENT_STARTUP 0
#define VRRP_EVENT_SHUTDOWN 1

extern const char *const vrrp_state_names[3];

/*
 * This hook called whenever the state of a Virtual Router changes, after the
 * specific internal state handlers have run.
 *
 * Use this if you need to react to state changes to perform non-critical
 * tasks. Critical tasks should go in the internal state change handlers.
 */
DECLARE_HOOK(vrrp_change_state_hook, (struct vrrp_router *r, int to), (r, to));

/*
 * Trigger a VRRP event on a given Virtual Router..
 *
 * vr
 *    Virtual Router to operate on
 *
 * event
 *    Event to kick off. All event related processing will have completed upon
 *    return of this function.
 *
 * Returns:
 *    < 0 if the event created an error
 *      0 otherwise
 */
int vrrp_event(struct vrrp_router *r, int event);

/* Autoconfig -------------------------------------------------------------- */

/*
 * Search for and automatically configure VRRP instances on interfaces.
 *
 * ifp
 *    Interface to autoconfig. If it is a macvlan interface and has a VRRP MAC,
 *    a VRRP instance corresponding to VMAC assigned to macvlan will be created
 *    on the parent interface and all addresses on the macvlan interface except
 *    the v6 link local will be configured as VRRP addresses. If NULL, this
 *    treatment will be applied to all existing interfaces matching the above
 *    criterion.
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
int vrrp_autoconfig(void);

/*
 * Enable autoconfiguration.
 *
 * Calling this function will cause vrrpd to automatically configure VRRP
 * instances on existing compatible macvlan interfaces. These instances will
 * react to interface up/down and address add/delete events to keep themselves
 * in sync with the available interfaces.
 *
 * version
 *    VRRP version to use for autoconfigured instances. Must be 2 or 3.
 */
void vrrp_autoconfig_on(int version);

/*
 * Disable autoconfiguration.
 *
 * Calling this function will delete all existing autoconfigured VRRP instances.
 */
void vrrp_autoconfig_off(void);

/* Interface Tracking ------------------------------------------------------ */

void vrrp_if_add(struct interface *ifp);
void vrrp_if_del(struct interface *ifp);
void vrrp_if_up(struct interface *ifp);
void vrrp_if_down(struct interface *ifp);
void vrrp_if_address_add(struct interface *ifp);
void vrrp_if_address_del(struct interface *ifp);

/* Other ------------------------------------------------------------------- */

/*
 * Write global level configuration to vty.
 *
 * vty
 *    vty to write config to
 *
 * Returns:
 *    # of lines written
 */
int vrrp_config_write_global(struct vty *vty);

/*
 * Find VRRP Virtual Router by Virtual Router ID
 */
struct vrrp_vrouter *vrrp_lookup(const struct interface *ifp, uint8_t vrid);

#endif /* __VRRP_H__ */
