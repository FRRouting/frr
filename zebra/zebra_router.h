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

#ifdef __cplusplus
extern "C" {
#endif

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

/* RPF lookup behaviour */
enum multicast_mode {
	MCAST_NO_CONFIG = 0,  /* MIX_MRIB_FIRST, but no show in config write */
	MCAST_MRIB_ONLY,      /* MRIB only */
	MCAST_URIB_ONLY,      /* URIB only */
	MCAST_MIX_MRIB_FIRST, /* MRIB, if nothing at all then URIB */
	MCAST_MIX_DISTANCE,   /* MRIB & URIB, lower distance wins */
	MCAST_MIX_PFXLEN,     /* MRIB & URIB, longer prefix wins */
			      /* on equal value, MRIB wins for last 2 */
};

struct zebra_mlag_info {
	/* Role this zebra router is playing */
	enum mlag_role role;

	/* The peerlink being used for mlag */
	char *peerlink;
	ifindex_t peerlink_ifindex;

	/* The system mac being used */
	struct ethaddr mac;
	/*
	 * Zebra will open the communication channel with MLAGD only if any
	 * clients are interested and it is controlled dynamically based on
	 * client registers & un-registers.
	 */
	uint32_t clients_interested_cnt;

	/* coomunication channel with MLAGD is established */
	bool connected;

	/* connection retry timer is running */
	bool timer_running;

	/* Holds the client data(unencoded) that need to be pushed to MCLAGD*/
	struct stream_fifo *mlag_fifo;

	/*
	 * A new Kernel thread will be created to post the data to MCLAGD.
	 * where as, read will be performed from the zebra main thread, because
	 * read involves accessing client registartion data structures.
	 */
	struct frr_pthread *zebra_pth_mlag;

	/* MLAG Thread context 'master' */
	struct thread_master *th_master;

	/*
	 * Event for Initial MLAG Connection setup & Data Read
	 * Read can be performed only after successful connection establishment,
	 * so no issues.
	 *
	 */
	struct thread *t_read;
	/* Event for MLAG write */
	struct thread *t_write;
};

struct zebra_router {
	atomic_bool in_shutdown;

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

	/* used if vrf backend is not network namespace */
	int rtadv_sock;

	/* A sequence number used for tracking routes */
	_Atomic uint32_t sequence_num;

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

	/*
	 * The EVPN instance, if any
	 */
	struct zebra_vrf *evpn_vrf;

	uint32_t multipath_num;

	/* RPF Lookup behavior */
	enum multicast_mode ipv4_multicast_mode;

	/*
	 * Time for when we sweep the rib from old routes
	 */
	time_t startup_time;

	/*
	 * The hash of nexthop groups associated with this router
	 */
	struct hash *nhgs;
	struct hash *nhgs_id;
};

#define GRACEFUL_RESTART_TIME 60

extern struct zebra_router zrouter;

extern void zebra_router_init(void);
extern void zebra_router_cleanup(void);
extern void zebra_router_terminate(void);

extern struct route_table *zebra_router_find_table(struct zebra_vrf *zvrf,
						   uint32_t tableid, afi_t afi,
						   safi_t safi);
extern struct route_table *zebra_router_get_table(struct zebra_vrf *zvrf,
						  uint32_t tableid, afi_t afi,
						  safi_t safi);
extern void zebra_router_release_table(struct zebra_vrf *zvrf, uint32_t tableid,
				       afi_t afi, safi_t safi);

extern int zebra_router_config_write(struct vty *vty);

extern void zebra_router_sweep_route(void);
extern void zebra_router_sweep_nhgs(void);

extern void zebra_router_show_table_summary(struct vty *vty);

extern uint32_t zebra_router_get_next_sequence(void);

static inline vrf_id_t zebra_vrf_get_evpn_id(void)
{
	return zrouter.evpn_vrf ? zvrf_id(zrouter.evpn_vrf) : VRF_DEFAULT;
}
static inline struct zebra_vrf *zebra_vrf_get_evpn(void)
{
	return zrouter.evpn_vrf ? zrouter.evpn_vrf
			        : zebra_vrf_lookup_by_id(VRF_DEFAULT);
}

extern void multicast_mode_ipv4_set(enum multicast_mode mode);

extern enum multicast_mode multicast_mode_ipv4_get(void);

#ifdef __cplusplus
}
#endif

#endif
