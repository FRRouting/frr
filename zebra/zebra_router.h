/* Zebra Router header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __ZEBRA_ROUTER_H__
#define __ZEBRA_ROUTER_H__

#include "lib/mlag.h"

#include "zebra/zebra_ns.h"

/*
 * This header file contains the idea of a router and as such
 * owns data that is associated with a router from zebra's
 * perspective.
 */

struct zebra_router_table {
	RB_ENTRY(zebra_router_table) zebra_router_table_entry;

	uint32_t tableid;
	afi_t afi;
	safi_t safi;
	ns_id_t ns_id;

	struct route_table *table;
};
RB_HEAD(zebra_router_table_head, zebra_router_table);
RB_PROTOTYPE(zebra_router_table_head, zebra_router_table,
	     zebra_router_table_entry, zebra_router_table_entry_compare)

struct zebra_mlag_info {
	/* Role this zebra router is playing */
	enum mlag_role role;

	/* The peerlink being used for mlag */
	char *peerlink;
	ifindex_t peerlink_ifindex;

	/* The system mac being used */
	struct ethaddr mac;
};

struct zebra_router {
	/* Thread master */
	struct thread_master *master;

	/* Lists of clients who have connected to us */
	struct list *client_list;

	struct zebra_router_table_head tables;

	/* L3-VNI hash table (for EVPN). Only in default instance */
	struct hash *l3vni_table;

	struct hash *rules_hash;

	struct hash *ipset_hash;

	struct hash *ipset_entry_hash;

	struct hash *iptable_hash;

#if defined(HAVE_RTADV)
	struct rtadv rtadv;
#endif /* HAVE_RTADV */

	/* A sequence number used for tracking routes */
	_Atomic uint32_t sequence_num;

	/* The default table used for this router */
	uint32_t rtm_table_default;

	/* rib work queue */
#define ZEBRA_RIB_PROCESS_HOLD_TIME 10
#define ZEBRA_RIB_PROCESS_RETRY_TIME 1
	struct work_queue *ribq;

	/* Meta Queue Information */
	struct meta_queue *mq;

	/* LSP work queue */
	struct work_queue *lsp_process_q;

#define ZEBRA_ZAPI_PACKETS_TO_PROCESS 1000
	_Atomic uint32_t packets_to_process;

	/* Mlag information for the router */
	struct zebra_mlag_info mlag_info;
};

extern struct zebra_router zrouter;

extern void zebra_router_init(void);
extern void zebra_router_terminate(void);

extern struct route_table *zebra_router_find_table(struct zebra_vrf *zvrf,
						   uint32_t tableid, afi_t afi,
						   safi_t safi);
extern struct route_table *zebra_router_get_table(struct zebra_vrf *zvrf,
						  uint32_t tableid, afi_t afi,
						  safi_t safi);

extern int zebra_router_config_write(struct vty *vty);

extern unsigned long zebra_router_score_proto(uint8_t proto,
					      unsigned short instance);
extern void zebra_router_sweep_route(void);

extern void zebra_router_show_table_summary(struct vty *vty);

extern uint32_t zebra_router_get_next_sequence(void);
#endif
