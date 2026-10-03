// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound (data plane) interface.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#ifndef PIM_SOUTHBOUND_H
#define PIM_SOUTHBOUND_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "lib/if.h"

#include "pim_addr.h"

struct channel_oil;
struct interface;
struct pim_instance;

/*
 * Here are declared all needed pieces to operate PIM southbound: the
 * default implementation uses the kernel, modules may replace it.
 */

/* Multicast interface traffic counters (see `interface_update_counters`). */
struct pim_interface_counters {
	unsigned long packets_in;
	unsigned long packets_out;
	unsigned long bytes_in;
	unsigned long bytes_out;
};

/* Type definitions, used below in the callbacks data structure. */
typedef void (*pim_mroute_socket_cb)(struct pim_instance *pim);
typedef int (*pim_interface_enable_cb)(struct interface *ifp, pim_addr ifaddr,
				       unsigned char vif_flags);
typedef void (*pim_interface_disable_cb)(struct interface *ifp);
typedef void (*pim_interface_update_counters_cb)(struct interface *ifp,
						 struct pim_interface_counters *counters);
typedef void (*pim_gmp_join_cb)(struct interface *ifp);
typedef void (*pim_gmp_leave_cb)(struct interface *ifp, const pim_addr *source,
				 const pim_addr *group);
typedef int (*pim_multicast_route_cb)(struct channel_oil *c_oil, const char *name);
typedef void (*pim_multicast_update_counters_cb)(struct channel_oil *c_oil);
typedef ssize_t (*pim_packet_send_cb)(const struct interface *ifp, const pim_addr *source,
				      const pim_addr *destination, uint8_t protocol, uint8_t ttl,
				      const void *data, size_t data_length);

/* PIM southbound handlers: callbacks and the data plane properties. */
struct pim_sb_cbs {
	/*
	 * (MANDATORY)
	 * Maximum number of multicast interfaces: valid indexes go from 0 to
	 * `interface_max - 1`, `interface_max` itself means "no interface".
	 *
	 * It may exceed `MAXVIFS`: the kernel MFC conversion
	 * (`channel_oil_to_mfcc`) is only used by the kernel southbound.
	 */
	ifindex_t interface_max;

	/*
	 * (OPTIONAL)
	 * The southbound installs the multicast routes through zebra (FPM):
	 * install them again when zebra reconnects or asks for an FPM sync, and
	 * when their register destination (the RP) changes.
	 */
	bool fpm_sync;

	/*
	 * (OPTIONAL)
	 * The southbound owns the sockets, don't use the OS ones:
	 *  - PIM: every interface uses `pim_fd` (the southbound reads it and
	 *    hands us the packets), the messages are sent with `send`;
	 *  - IGMP/MLD: the interfaces the data plane handles (see
	 *    `pim_sb_owns_interface`: loopbacks and VRF devices keep the OS
	 *    sockets) send with `send`, the southbound hands us their packets;
	 *  - static IGMP/MLD joins: every interface (loopbacks included)
	 *    announces them with `interface_join` and `interface_leave`.
	 *
	 * Requires `send`, `interface_join` and `interface_leave`, which are
	 * only used with it.
	 *
	 * mtrace, AutoRP and ssmpingd keep their OS sockets: their packets don't
	 * go through the data plane.
	 */
	bool own_sockets;

	/*
	 * (`own_sockets` only)
	 * The southbound PIM socket: PIM interfaces only use it to tell whether
	 * PIM is up (so -1 means down, PIM interfaces won't come up until it is
	 * set).
	 */
	int pim_fd;

	/*
	 * (OPTIONAL)
	 * The data plane forwards the RP's own sources natively: never add
	 * `pimreg` as output interface when we are the group RP.
	 */
	bool no_register_on_rp;

	/*
	 * (MANDATORY)
	 * This callback is tasked to create the routing socket and set
	 * `pim->mroute_socket` and `pim->mroute_socket_creation` entries.
	 *
	 * With `own_sockets`, a socket reading the IGMP of the interfaces the
	 * data plane doesn't handle must skip the ones it does (see
	 * `pim_sb_owns_interface`): the southbound hands their packets to
	 * `pim_mroute_msg` itself, the operating system would only deliver
	 * copies.
	 */
	pim_mroute_socket_cb mroute_enable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to destroy the routing socket and
	 * unset `pim->mroute_socket`, `pim->mroute_socket_creation` entries.
	 */
	pim_mroute_socket_cb mroute_disable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to install multicast route.
	 */
	pim_multicast_route_cb mroute_install;

	/*
	 * (MANDATORY)
	 * This callback is tasked to uninstall multicast route.
	 */
	pim_multicast_route_cb mroute_uninstall;

	/*
	 * (OPTIONAL)
	 * This callback is tasked to update route counters.
	 *
	 * Without it the southbound reports the traffic instead:
	 * `pim_upstream_data_start` when it flows and `pim_upstream_data_stop`
	 * when it stops. Sources only look active while their traffic is
	 * reported, except the SPT switched LHR ones (the data plane may
	 * forward them without reporting their traffic) which never look idle:
	 * when their traffic stops the southbound runs the keepalive timer
	 * expiry (`pim_upstream_keep_alive_timer_proc`) to release them. It
	 * must do so for every SPT switched LHR source it forwards, even the
	 * ones whose start it never reported.
	 */
	pim_multicast_update_counters_cb mroute_update_counters;

	/*
	 * (MANDATORY)
	 * This callback is tasked to enable multicast in an interface.
	 *
	 * You may manipulate
	 * `((struct pim_interface *)interface->info)->mroute_vif_index`
	 * to select a different multicast interface index or use the
	 * already selected index. A different index must be unused and below
	 * `interface_max`: it is added to the instance multicast interface
	 * list as is when this returns.
	 */
	pim_interface_enable_cb interface_enable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to disable multicast in an interface.
	 */
	pim_interface_disable_cb interface_disable;

	/*
	 * (OPTIONAL)
	 * This callback is tasked to read the multicast interface traffic
	 * counters (displayed as zero without it).
	 */
	pim_interface_update_counters_cb interface_update_counters;

	/*
	 * (MANDATORY with `own_sockets`, unused without it)
	 * This callback is tasked to (re)announce the static IGMP/MLD joins
	 * of the interface: called when a join is added, the interface gets
	 * an address, queries are sent or received, MLDv1 leaves are received,
	 * memberships expire and the multicast state is cleared (it may
	 * coalesce the calls). Only for multicast enabled interfaces with an
	 * interface index (see `pim_sb_interface_join`).
	 *
	 * Like the kernel loops its reports back, the southbound also hands the
	 * reports it sends to our own IGMP/MLD instance (`pim_igmp_packet`,
	 * `gm_rx_process`) on every interface, loopbacks included (where it
	 * only does that): this is what makes us a member of the groups. It
	 * does so deferred (e.g. from a timer: the IGMP/MLD code is not
	 * reentrant) and the data plane must not deliver them back too.
	 *
	 * Without `own_sockets` the OS joins the groups (*BSD/Linux kernels
	 * send the reports).
	 */
	pim_gmp_join_cb interface_join;

	/*
	 * (MANDATORY with `own_sockets`, unused without it)
	 * This callback is tasked to leave a static IGMP/MLD group
	 * immediately by sending the appropriate GMP mechanism (only for the
	 * joins `interface_join` announced, see `pim_sb_interface_leave`),
	 * handed to our own IGMP/MLD instance too (see `interface_join`).
	 *
	 * Without `own_sockets` the OS leaves the groups (*BSD/Linux kernels
	 * send the leaves).
	 */
	pim_gmp_leave_cb interface_leave;

	/*
	 * (MANDATORY with `own_sockets`, unused without it)
	 * This callback is tasked to send IGMP/MLD/PIM packets: `data` is the
	 * IP payload, `protocol` and `ttl` its IP protocol and TTL (IPv6: hop
	 * limit).
	 *  - Multicast packets and unicast ones to a neighbor (on the link) go
	 *    out of `ifp`.
	 *  - The other unicast packets (Register, Register-Stop, Candidate-RP
	 *    advertisement) are routed by the data plane: they come without
	 *    interface (`ifp` NULL) in the default VRF and with the VRF device
	 *    in the others.
	 * `source` may be NULL when `ifp` is set: use the interface primary
	 * (IPv6: link-local) address then.
	 *
	 * Packets may exceed the MTU (e.g. a Register encapsulating a full
	 * sized packet): the southbound fragments them, like the OS does.
	 *
	 * Like the OS sockets do, the southbound adds the IP Router Alert
	 * option to IGMP packets and the hop-by-hop Router Alert option to MLD
	 * ones (and the internetwork control precedence to IPv4 packets): tell
	 * them apart with `protocol`.
	 *
	 * MLD depends on receiving its own multicast packets, like the kernel
	 * loops them back: the querier only starts its general and group
	 * specific expiries when it receives its own queries. So the southbound
	 * hands them to `gm_rx_process`, deferred (e.g. from a timer: the MLD
	 * code is not reentrant), and the data plane must not deliver them back
	 * too.
	 *
	 * The data plane doesn't handle loopbacks: IGMP/MLD on those stay
	 * with the OS sockets (see `pim_sb_owns_interface`).
	 *
	 * Returns the bytes sent (`data_length`) or -1 (with `errno` set).
	 */
	pim_packet_send_cb send;
};

/*
 * The southbound in use: the kernel one by default, a module may replace it
 * from its `init` (`pim_router_init` checks it right after loading the
 * modules). It must not change afterwards: the PIM state depends on it (e.g.
 * the multicast routes use `interface_max` for "no interface").
 */
extern struct pim_sb_cbs pim_southbound;

/* Checks the southbound has the mandatory handlers (aborts otherwise). */
extern void pim_sb_check(void);

/**
 * Tells whether the southbound owns `ifp` IGMP/MLD sockets: loopbacks
 * (and VRF devices) are not handled by data planes, so they keep the OS ones.
 */
static inline bool pim_sb_owns_interface(const struct interface *ifp)
{
	return pim_southbound.own_sockets && !if_is_loopback(ifp);
}

/**
 * Announces the static IGMP/MLD joins of `ifp` again when the southbound owns
 * them (see `interface_join`). Joins configured before the interface has an
 * index start once it gets an address.
 */
static inline void pim_sb_interface_join(struct interface *ifp)
{
	if (!pim_southbound.own_sockets || ifp->ifindex == IFINDEX_INTERNAL || ifp->info == NULL)
		return;

	pim_southbound.interface_join(ifp);
}

/**
 * Leaves the static IGMP/MLD group `pim_sb_interface_join` announced (see
 * `interface_leave`).
 */
static inline void pim_sb_interface_leave(struct interface *ifp, const pim_addr *source,
					  const pim_addr *group)
{
	if (!pim_southbound.own_sockets || ifp->ifindex == IFINDEX_INTERNAL || ifp->info == NULL)
		return;

	pim_southbound.interface_leave(ifp, source, group);
}

#endif /* PIM_SOUTHBOUND_H */
