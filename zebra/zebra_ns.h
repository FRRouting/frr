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

#ifdef HAVE_NETLINK
/* Socket interface to kernel */
struct nlsock {
	int sock;
	int seq;
	struct sockaddr_nl snl;
	char name[64];
};
#endif

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
};

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id);

int zebra_ns_init(void);
int zebra_ns_enable(ns_id_t ns_id, void **info);
int zebra_ns_disable(ns_id_t ns_id, void **info);
#endif
