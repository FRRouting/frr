/*
 * Zebra NS header
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#if !defined(__ZEBRA_NS_H__)
#define __ZEBRA_NS_H__

#include <lib/ns.h>
#include <lib/vrf.h>

#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"

#ifdef HAVE_NETLINK
/* Socket interface to kernel */
struct nlsock {
	int sock;
	int seq;
	struct sockaddr_nl snl;
	char name[64];
};
#endif

struct zebra_ns_table {
	RB_ENTRY(zebra_ns_table) zebra_ns_table_entry;

	uint32_t tableid;
	afi_t afi;
	ns_id_t ns_id;

	struct route_table *table;
};
RB_HEAD(zebra_ns_table_head, zebra_ns_table);
RB_PROTOTYPE(zebra_ns_table_head, zebra_ns_table, zebra_ns_table_entry,
	     zebra_ns_table_entry_compare)

struct zebra_ns {
	/* net-ns name.  */
	char name[VRF_NAMSIZ];

	/* Identifier. */
	ns_id_t ns_id;

#ifdef HAVE_NETLINK
	struct nlsock netlink;     /* kernel messages */
	struct nlsock netlink_cmd; /* command channel */
	struct thread *t_netlink;
#endif

	struct route_table *if_table;

	/* L3-VNI hash table (for EVPN). Only in default instance */
	struct hash *l3vni_table;

#if defined(HAVE_RTADV)
	struct rtadv rtadv;
#endif /* HAVE_RTADV */

	struct zebra_ns_table_head ns_tables;

	struct hash *rules_hash;

	struct hash *ipset_hash;

	struct hash *ipset_entry_hash;

	struct hash *iptable_hash;

	/* Back pointer */
	struct ns *ns;
};

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id);

int zebra_ns_init(void);
int zebra_ns_enable(ns_id_t ns_id, void **info);
int zebra_ns_disabled(struct ns *ns);
int zebra_ns_disable(ns_id_t ns_id, void **info);

extern struct route_table *zebra_ns_find_table(struct zebra_ns *zns,
					       uint32_t tableid, afi_t afi);
extern struct route_table *zebra_ns_get_table(struct zebra_ns *zns,
					      struct zebra_vrf *zvrf,
					      uint32_t tableid, afi_t afi);
int zebra_ns_config_write(struct vty *vty, struct ns *ns);

unsigned long zebra_ns_score_proto(uint8_t proto, unsigned short instance);
void zebra_ns_sweep_route(void);
#endif
