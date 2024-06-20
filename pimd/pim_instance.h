// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRR - PIM Instance
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
 */
#ifndef __PIM_INSTANCE_H__
#define __PIM_INSTANCE_H__

#include <mlag.h>

#include "pim_str.h"
#include "pim_msdp.h"
#include "pim_assert.h"
#include "pim_bsm.h"
#include "pim_vxlan_instance.h"
#include "pim_oil.h"
#include "pim_upstream.h"
#include "pim_mroute.h"
#include "pim_autorp.h"

enum pim_spt_switchover {
	PIM_SPT_IMMEDIATE,
	PIM_SPT_INFINITY,
};

/* stats for updates rxed from the MLAG component during the life of a
 * session
 */
struct pim_mlag_msg_stats {
	uint32_t mroute_add_rx;
	uint32_t mroute_add_tx;
	uint32_t mroute_del_rx;
	uint32_t mroute_del_tx;
	uint32_t mlag_status_updates;
	uint32_t pim_status_updates;
	uint32_t vxlan_updates;
	uint32_t peer_zebra_status_updates;
};

struct pim_mlag_stats {
	/* message stats are reset when the connection to mlagd flaps */
	struct pim_mlag_msg_stats msg;
	uint32_t mlagd_session_downs;
	uint32_t peer_session_downs;
	uint32_t peer_zebra_downs;
};

enum pim_mlag_flags {
	PIM_MLAGF_NONE = 0,
	/* connection to the local MLAG daemon is up */
	PIM_MLAGF_LOCAL_CONN_UP = (1 << 0),
	/* connection to the MLAG daemon on the peer switch is up. note
	 * that there is no direct connection between FRR and the peer MLAG
	 * daemon. this is just a peer-session status provided by the local
	 * MLAG daemon.
	 */
	PIM_MLAGF_PEER_CONN_UP = (1 << 1),
	/* status update rxed from the local daemon */
	PIM_MLAGF_STATUS_RXED = (1 << 2),
	/* initial dump of data done post peerlink flap */
	PIM_MLAGF_PEER_REPLAY_DONE = (1 << 3),
	/* zebra is up on the peer */
	PIM_MLAGF_PEER_ZEBRA_UP = (1 << 4)
};

struct pim_router {
	struct event_loop *master;

	uint32_t debugs;

	int t_periodic;
	struct pim_assert_metric infinite_assert_metric;
	long rpf_cache_refresh_delay_msec;
	uint32_t register_suppress_time;
	int packet_process;
	uint32_t register_probe_time;
	uint16_t multipath;

	/*
	 * What is the default vrf that we work in
	 */
	vrf_id_t vrf_id;

	enum mlag_role mlag_role;
	uint32_t pim_mlag_intf_cnt;
	/* if true we have registered with MLAG */
	bool mlag_process_register;
	/* if true local MLAG process reported that it is connected
	 * with the peer MLAG process
	 */
	bool connected_to_mlag;
	/* Holds the client data(unencoded) that need to be pushed to MCLAGD*/
	struct stream_fifo *mlag_fifo;
	struct stream *mlag_stream;
	struct event *zpthread_mlag_write;
	struct in_addr anycast_vtep_ip;
	struct in_addr local_vtep_ip;
	struct pim_mlag_stats mlag_stats;
	enum pim_mlag_flags mlag_flags;
	char peerlink_rif[IFNAMSIZ];
	struct interface *peerlink_rif_p;
};

/* Per VRF PIM DB */
struct pim_instance {
	// vrf_id_t vrf_id;
	struct vrf *vrf;

	struct {
		enum pim_spt_switchover switchover;
		char *plist;
	} spt;

	/* The name of the register-accept prefix-list */
	char *register_plist;

	struct hash *rpf_hash;

	void *ssm_info; /* per-vrf SSM configuration */

	int send_v6_secondary;

	struct event *thread;
	int mroute_socket;
	int reg_sock; /* Socket to send register msg */
	int64_t mroute_socket_creation;
	int64_t mroute_add_events;
	int64_t mroute_add_last;
	int64_t mroute_del_events;
	int64_t mroute_del_last;

	struct interface *regiface;

	// List of static routes;
	struct list *static_routes;

	// Upstream vrf specific information
	struct rb_pim_upstream_head upstream_head;
	struct timer_wheel *upstream_sg_wheel;

	/*
	 * RP information
	 */
	struct list *rp_list;
	struct route_table *rp_table;

	int iface_vif_index[MAXVIFS];
	int mcast_if_count;

	struct rb_pim_oil_head channel_oil_head;

	struct pim_msdp msdp;
	struct pim_vxlan_instance vxlan;

	struct pim_autorp *autorp;

	struct list *ssmpingd_list;
	pim_addr ssmpingd_group_addr;

	unsigned int gm_socket_if_count;
	int gm_socket;
	struct event *t_gm_recv;

	unsigned int gm_group_count;
	unsigned int gm_watermark_limit;
	unsigned int keep_alive_time;
	unsigned int rp_keep_alive_time;

	bool ecmp_enable;
	bool ecmp_rebalance_enable;
	/* No. of Dual active I/fs in pim_instance */
	uint32_t inst_mlag_intf_cnt;

	/* Bsm related */
	struct bsm_scope global_scope;
	uint64_t bsm_rcvd;
	uint64_t bsm_sent;
	uint64_t bsm_dropped;

	/* If we need to rescan all our upstreams */
	struct event *rpf_cache_refresher;
	int64_t rpf_cache_refresh_requests;
	int64_t rpf_cache_refresh_events;
	int64_t rpf_cache_refresh_last;
	int64_t scan_oil_events;
	int64_t scan_oil_last;

	int64_t nexthop_lookups;
	int64_t nexthop_lookups_avoided;
	int64_t last_route_change_time;

	uint64_t gm_rx_drop_sys;
};

void pim_vrf_init(void);
void pim_vrf_terminate(void);

extern struct pim_router *router;

struct pim_instance *pim_get_pim_instance(vrf_id_t vrf_id);

#endif
