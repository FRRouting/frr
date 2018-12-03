/*
 * VRRPD global definitions
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
#include "linklist.h"
#include "hash.h"
#include "if.h"
#include "thread.h"
#include "hook.h"

/* Global definitions */
#define VRRP_DEFAULT_ADVINT 100
#define VRRP_DEFAULT_PRIORITY 100
#define VRRP_PRIO_MASTER 255
#define VRRP_MCAST_GROUP "224.0.0.18"
#define VRRP_MCAST_GROUP_HEX 0xe0000012
#define IPPROTO_VRRP 112

/* threadmaster */
extern struct thread_master *master;

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

	/* Time between ADVERTISEMENTS (centiseconds) */
	int advint;

	/* Whether this VRRP Router is currently the master */
	bool is_master;

	/* Priority */
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

/* State machine */
#define VRRP_STATE_INITIALIZE 1
#define VRRP_STATE_MASTER 2
#define VRRP_STATE_BACKUP 3
#define VRRP_EVENT_STARTUP 1
#define VRRP_EVENT_SHUTDOWN 2

DECLARE_HOOK(vrrp_change_state_hook, (struct vrrp_vrouter *vr, int to), (vr, to));
/* End state machine */


/*
 * Initialize VRRP global datastructures.
 */
void vrrp_init(void);

/*
 * Create and register a new VRRP Virtual Router.
 */
struct vrrp_vrouter *vrrp_vrouter_create(struct interface *ifp, uint8_t vrid);

/*
 * Find VRRP Virtual Router by Virtual Router ID
 */
struct vrrp_vrouter *vrrp_lookup(uint8_t vrid);

/*
 * Trigger VRRP event
 */
int vrrp_event(struct vrrp_vrouter *vr, int event);

#endif /* _VRRP_H */
