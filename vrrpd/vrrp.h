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
#ifndef _VRRP_H
#define _VRRP_H

#include <zebra.h>

#include "lib/hash.h"
#include "lib/hook.h"
#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/privs.h"
#include "lib/thread.h"

/* Global definitions */
#define VRRP_DEFAULT_ADVINT 100
#define VRRP_DEFAULT_PRIORITY 100
#define VRRP_PRIO_MASTER 255
#define VRRP_MCAST_GROUP "224.0.0.18"
#define VRRP_MCAST_GROUP_HEX 0xe0000012
#define IPPROTO_VRRP 112

#define VRRP_LOGPFX_VRID "[VRID: %u] "

/* threadmaster */
extern struct thread_master *master;

/* privileges */
extern struct zebra_privs_t vrrp_privs;

/* Global hash of all Virtual Routers */
struct hash *vrrp_vrouters_hash;

/*
 * VRRP Virtual Router
 */
struct vrrp_vrouter {
	/* Socket */
	int sock;

	/* Interface */
	struct interface *ifp;

	/* Virtual Router Identifier */
	uint32_t vrid;

	/* One or more IPv4 addresses associated with this Virtual Router. */
	struct list *v4;

	/*
	 * One ore more IPv6 addresses associated with this Virtual Router. The
	 * first address must be the Link-Local address associated with the
	 * virtual router.
	 */
	struct list *v6;

	/* Configured priority */
	uint8_t priority_conf;

	/*
	 * Effective priority
	 *    => priority if we are Backup
	 *    => 255 if we are Master
	 */
	uint8_t priority;

	/*
	 * Time interval between ADVERTISEMENTS (centiseconds). Default is 100
	 * centiseconds (1 second).
	 */
	uint16_t advertisement_interval;
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

	/*
	 * The MAC address used for the source MAC address in VRRP
	 * advertisements and advertised in ARP responses as the MAC address to
	 * use for IP_Addresses.
	 */
	struct ethaddr vr_mac_v4;
	struct ethaddr vr_mac_v6;

	struct thread *t_master_down_timer;
	struct thread *t_adver_timer;

	struct {
		int state;
	} fsm;
};

/*
 * Initialize VRRP global datastructures.
 */
void vrrp_init(void);


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
struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid);

/*
 * Destroy a VRRP Virtual Router.
 */
void vrrp_vrouter_destroy(struct vrrp_vrouter *vr);


/* Configuration controllers ----------------------------------------------- */

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
 * Add IPv4 address to a VRRP Virtual Router.
 *
 * vr
 *    Virtual Router to add IPv4 address to
 *
 * v4
 *    Address to add
 */
void vrrp_add_ip(struct vrrp_vrouter *vr, struct in_addr v4);


/* State machine ----------------------------------------------------------- */

#define VRRP_STATE_INITIALIZE 0
#define VRRP_STATE_MASTER 1
#define VRRP_STATE_BACKUP 2
#define VRRP_EVENT_STARTUP 0
#define VRRP_EVENT_SHUTDOWN 1

extern const char *vrrp_state_names[3];
extern const char *vrrp_event_names[2];

/*
 * This hook called whenever the state of a Virtual Router changes, after the
 * specific internal state handlers have run.
 *
 * Use this if you need to react to state changes to perform non-critical
 * tasks. Critical tasks should go in the internal state change handlers.
 */
DECLARE_HOOK(vrrp_change_state_hook, (struct vrrp_vrouter *vr, int to), (vr, to));

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
int vrrp_event(struct vrrp_vrouter *vr, int event);


/* Other ------------------------------------------------------------------- */

/*
 * Find VRRP Virtual Router by Virtual Router ID
 */
struct vrrp_vrouter *vrrp_lookup(uint8_t vrid);

#endif /* _VRRP_H */
