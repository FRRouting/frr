// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN ARP/ND packet handler
 *
 * Copyright (C) 2020 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 */

#ifndef _ZEBRA_ARP_ND_H
#define _ZEBRA_ARP_ND_H

#include <zebra.h>

#include "interface.h"

/* Maximum packets read in one invocation of the thread */
#define ZEBRA_EVPN_ARP_ND_PKT_MAX 20

/* to meaninfully process the packet we need atleast the ethheader */
#define ZEBRA_EVPN_ARP_ND_MIN_PKT_LEN 14
#define ZEBRA_EVPN_ARP_ND_MAX_PKT_LEN 1024

/* sizeof rcv buffer associated with each bridge member */
#define ZEBRA_EVPN_ARP_ND_SOC_RCVBUF (4 * 1024 * 1024)

/* standard VxLAN dest port */
#define ZEBRA_EVPN_VXLAN_UDP_PORT 4789

/* ARP/NA packet stats */
struct zebra_evpn_arp_nd_stats {
	uint32_t arp;
	uint32_t na;
	uint32_t not_ready;
	uint32_t vni_missing;
	uint32_t mac_missing;
	uint32_t es_non_local;
	uint32_t es_up;
	uint32_t nh_missing;
	uint32_t redirect;
};

/* ARP/ND global information */
struct zebra_evpn_arp_nd_info {
	uint32_t flags;
#define ZEBRA_EVPN_ARP_ND_FAILOVER (1 << 0)

	/*
	 * number of ESs that are operationally down
	 * XXX - use this to optimize packet parsing if needed
	 */
	uint32_t down_es_cnt;
	int udp_fd;
	struct zebra_evpn_arp_nd_stats stat;
};

/*****************************************************************************/
extern void zebra_evpn_arp_nd_failover_enable(void);
extern void zebra_evpn_arp_nd_failover_disable(void);
extern void zebra_evpn_arp_nd_udp_sock_create(void);
extern void zebra_evpn_arp_nd_if_update(struct zebra_if *zif, bool enable);
extern void zebra_evpn_arp_nd_print_summary(struct vty *vty, bool uj);
extern void zebra_evpn_arp_nd_if_print(struct vty *vty, struct zebra_if *zif);

#endif /* _ZEBRA_ARP_ND_H */
