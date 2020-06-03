/* BGP message definition header.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGPD_H
#define _QUAGGA_BGPD_H

#include "qobj.h"
#include <pthread.h>

#include "hook.h"
#include "frr_pthread.h"
#include "lib/json.h"
#include "vrf.h"
#include "vty.h"
#include "iana_afi.h"

/* For union sockunion.  */
#include "queue.h"
#include "sockunion.h"
#include "routemap.h"
#include "linklist.h"
#include "defaults.h"
#include "bgp_memory.h"
#include "bitfield.h"
#include "vxlan.h"
#include "bgp_labelpool.h"
#include "bgp_addpath_types.h"

#define BGP_MAX_HOSTNAME 64	/* Linux max, is larger than most other sys */
#define BGP_PEER_MAX_HASH_SIZE 16384

/* Default interval for IPv6 RAs when triggered by BGP unnumbered neighbor. */
#define BGP_UNNUM_DEFAULT_RA_INTERVAL 10

struct update_subgroup;
struct bpacket;
struct bgp_pbr_config;

/*
 * Allow the neighbor XXXX remote-as to take internal or external
 * AS_SPECIFIED is zero to auto-inherit original non-feature/enhancement
 * behavior
 * in the system.
 */
enum { AS_UNSPECIFIED = 0,
       AS_SPECIFIED,
       AS_INTERNAL,
       AS_EXTERNAL,
};

/* Zebra Gracaful Restart states */
enum zebra_gr_mode {
	ZEBRA_GR_DISABLE = 0,
	ZEBRA_GR_ENABLE
};

/* Typedef BGP specific types.  */
typedef uint32_t as_t;
typedef uint16_t as16_t; /* we may still encounter 16 Bit asnums */
typedef uint16_t bgp_size_t;

#define max(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a > _b ? _a : _b;                                             \
	})

enum bgp_af_index {
	BGP_AF_START,
	BGP_AF_IPV4_UNICAST = BGP_AF_START,
	BGP_AF_IPV4_MULTICAST,
	BGP_AF_IPV4_VPN,
	BGP_AF_IPV6_UNICAST,
	BGP_AF_IPV6_MULTICAST,
	BGP_AF_IPV6_VPN,
	BGP_AF_IPV4_ENCAP,
	BGP_AF_IPV6_ENCAP,
	BGP_AF_L2VPN_EVPN,
	BGP_AF_IPV4_LBL_UNICAST,
	BGP_AF_IPV6_LBL_UNICAST,
	BGP_AF_IPV4_FLOWSPEC,
	BGP_AF_IPV6_FLOWSPEC,
	BGP_AF_MAX
};

#define AF_FOREACH(af) for ((af) = BGP_AF_START; (af) < BGP_AF_MAX; (af)++)

#define FOREACH_AFI_SAFI(afi, safi)                                            \
	for (afi = AFI_IP; afi < AFI_MAX; afi++)                               \
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

#define FOREACH_SAFI(safi)                                            \
	for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

extern struct frr_pthread *bgp_pth_io;
extern struct frr_pthread *bgp_pth_ka;

/* BGP master for system wide configurations and variables.  */
struct bgp_master {
	/* BGP instance list.  */
	struct list *bgp;

	/* BGP thread master.  */
	struct thread_master *master;

	/* work queues */
	struct work_queue *process_main_queue;

	/* Listening sockets */
	struct list *listen_sockets;

	/* BGP port number.  */
	uint16_t port;

	/* Listener address */
	char *address;

	/* The Mac table */
	struct hash *self_mac_hash;

	/* BGP start time.  */
	time_t start_time;

	/* Various BGP global configuration.  */
	uint8_t options;
#define BGP_OPT_NO_FIB                   (1 << 0)
#define BGP_OPT_NO_LISTEN                (1 << 1)
#define BGP_OPT_NO_ZEBRA                 (1 << 2)

	uint64_t updgrp_idspace;
	uint64_t subgrp_idspace;

	/* timer to dampen route map changes */
	struct thread *t_rmap_update; /* Handle route map updates */
	uint32_t rmap_update_timer;   /* Route map update timer */
#define RMAP_DEFAULT_UPDATE_TIMER 5 /* disabled by default */

	/* Id space for automatic RD derivation for an EVI/VRF */
	bitfield_t rd_idspace;

	/* dynamic mpls label allocation pool */
	struct labelpool labelpool;

	/* BGP-EVPN VRF ID. Defaults to default VRF (if any) */
	struct bgp* bgp_evpn;

	/* How big should we set the socket buffer size */
	uint32_t socket_buffer;

	/* EVPN multihoming */
	struct bgp_evpn_mh_info *mh_info;

	bool terminating;	/* global flag that sigint terminate seen */
	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(bgp_master)

/* BGP route-map structure.  */
struct bgp_rmap {
	char *name;
	struct route_map *map;
};

struct bgp_redist {
	unsigned short instance;

	/* BGP redistribute metric configuration. */
	uint8_t redist_metric_flag;
	uint32_t redist_metric;

	/* BGP redistribute route-map.  */
	struct bgp_rmap rmap;
};

typedef enum {
	BGP_VPN_POLICY_DIR_FROMVPN = 0,
	BGP_VPN_POLICY_DIR_TOVPN = 1,
	BGP_VPN_POLICY_DIR_MAX = 2
} vpn_policy_direction_t;

struct vpn_policy {
	struct bgp *bgp; /* parent */
	afi_t afi;
	struct ecommunity *rtlist[BGP_VPN_POLICY_DIR_MAX];
	struct ecommunity *import_redirect_rtlist;
	char *rmap_name[BGP_VPN_POLICY_DIR_MAX];
	struct route_map *rmap[BGP_VPN_POLICY_DIR_MAX];

	/* should be mpls_label_t? */
	uint32_t tovpn_label; /* may be MPLS_LABEL_NONE */
	uint32_t tovpn_zebra_vrf_label_last_sent;
	struct prefix_rd tovpn_rd;
	struct prefix tovpn_nexthop; /* unset => set to 0 */
	uint32_t flags;
#define BGP_VPN_POLICY_TOVPN_LABEL_AUTO        (1 << 0)
#define BGP_VPN_POLICY_TOVPN_RD_SET            (1 << 1)
#define BGP_VPN_POLICY_TOVPN_NEXTHOP_SET       (1 << 2)

	/*
	 * If we are importing another vrf into us keep a list of
	 * vrf names that are being imported into us.
	 */
	struct list *import_vrf;

	/*
	 * if we are being exported to another vrf keep a list of
	 * vrf names that we are being exported to.
	 */
	struct list *export_vrf;
};

/*
 * Type of 'struct bgp'.
 * - Default: The default instance
 * - VRF: A specific (non-default) VRF
 * - View: An instance used for route exchange
 * The "default" instance is treated separately to simplify the code. Note
 * that if deployed in a Multi-VRF environment, it may not exist.
 */
enum bgp_instance_type {
	BGP_INSTANCE_TYPE_DEFAULT,
	BGP_INSTANCE_TYPE_VRF,
	BGP_INSTANCE_TYPE_VIEW
};

#define BGP_SEND_EOR(bgp, afi, safi)                                           \
	(!CHECK_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR)                      \
	 && ((bgp->gr_info[afi][safi].t_select_deferral == NULL)               \
	     || (bgp->gr_info[afi][safi].eor_required                          \
		 == bgp->gr_info[afi][safi].eor_received)))

/* BGP GR Global ds */

#define BGP_GLOBAL_GR_MODE 4
#define BGP_GLOBAL_GR_EVENT_CMD 4

/* Graceful restart selection deferral timer info */
struct graceful_restart_info {
	/* Count of EOR message expected */
	uint32_t eor_required;
	/* Count of EOR received */
	uint32_t eor_received;
	/* Deferral Timer */
	struct thread *t_select_deferral;
	/* Route list */
	struct list *route_list;
	/* Best route select */
	struct thread *t_route_select;
	/* AFI, SAFI enabled */
	bool af_enabled[AFI_MAX][SAFI_MAX];
	/* Route update completed */
	bool route_sync[AFI_MAX][SAFI_MAX];
};

enum global_mode {
	GLOBAL_HELPER = 0, /* This is the default mode */
	GLOBAL_GR,
	GLOBAL_DISABLE,
	GLOBAL_INVALID
};

enum global_gr_command {
	GLOBAL_GR_CMD = 0,
	NO_GLOBAL_GR_CMD,
	GLOBAL_DISABLE_CMD,
	NO_GLOBAL_DISABLE_CMD
};

#define BGP_GR_SUCCESS 0
#define BGP_GR_FAILURE 1

/* Handling of BGP link bandwidth (LB) on receiver - whether and how to
 * do weighted ECMP. Note: This applies after multipath computation.
 */
enum bgp_link_bw_handling {
	/* Do ECMP if some paths don't have LB - default */
	BGP_LINK_BW_ECMP,
	/* Completely ignore LB, just do regular ECMP */
	BGP_LINK_BW_IGNORE_BW,
	/* Skip paths without LB, do wECMP on others */
	BGP_LINK_BW_SKIP_MISSING,
	/* Do wECMP with default weight for paths not having LB */
	BGP_LINK_BW_DEFWT_4_MISSING
};

/* BGP instance structure.  */
struct bgp {
	/* AS number of this BGP instance.  */
	as_t as;

	/* Name of this BGP instance.  */
	char *name;
	char *name_pretty;	/* printable "VRF|VIEW name|default" */

	/* Type of instance and VRF id. */
	enum bgp_instance_type inst_type;
	vrf_id_t vrf_id;

	/* Reference count to allow peer_delete to finish after bgp_delete */
	int lock;

	/* Self peer.  */
	struct peer *peer_self;

	/* BGP peer. */
	struct list *peer;
	struct hash *peerhash;

	/* BGP peer group.  */
	struct list *group;

	/* The maximum number of BGP dynamic neighbors that can be created */
	int dynamic_neighbors_limit;

	/* The current number of BGP dynamic neighbors */
	int dynamic_neighbors_count;

	struct hash *update_groups[BGP_AF_MAX];

	/*
	 * Global statistics for update groups.
	 */
	struct {
		uint32_t join_events;
		uint32_t prune_events;
		uint32_t merge_events;
		uint32_t split_events;
		uint32_t updgrp_switch_events;
		uint32_t peer_refreshes_combined;
		uint32_t adj_count;
		uint32_t merge_checks_triggered;

		uint32_t updgrps_created;
		uint32_t updgrps_deleted;
		uint32_t subgrps_created;
		uint32_t subgrps_deleted;
	} update_group_stats;

	/* BGP configuration.  */
	uint16_t config;
#define BGP_CONFIG_CLUSTER_ID             (1 << 0)
#define BGP_CONFIG_CONFEDERATION          (1 << 1)

	/* BGP router identifier.  */
	struct in_addr router_id;
	struct in_addr router_id_static;
	struct in_addr router_id_zebra;

	/* BGP route reflector cluster ID.  */
	struct in_addr cluster_id;

	/* BGP confederation information.  */
	as_t confed_id;
	as_t *confed_peers;
	int confed_peers_cnt;

	struct thread
		*t_startup; /* start-up timer on only once at the beginning */

	uint32_t v_maxmed_onstartup; /* Duration of max-med on start-up */
#define BGP_MAXMED_ONSTARTUP_UNCONFIGURED  0 /* 0 means off, its the default */
	uint32_t maxmed_onstartup_value;     /* Max-med value when active on
						 start-up */
	struct thread
		*t_maxmed_onstartup; /* non-null when max-med onstartup is on */
	uint8_t maxmed_onstartup_over; /* Flag to make it effective only once */

	uint8_t v_maxmed_admin; /* 1/0 if max-med administrative is on/off */
#define BGP_MAXMED_ADMIN_UNCONFIGURED  0 /* Off by default */
	uint32_t maxmed_admin_value; /* Max-med value when administrative in on
				      */
#define BGP_MAXMED_VALUE_DEFAULT  4294967294 /* Maximum by default */

	uint8_t maxmed_active; /* 1/0 if max-med is active or not */
	uint32_t maxmed_value; /* Max-med value when its active */

	/* BGP update delay on startup */
	struct thread *t_update_delay;
	struct thread *t_establish_wait;
	uint8_t update_delay_over;
	uint8_t main_zebra_update_hold;
	uint8_t main_peers_update_hold;
	uint16_t v_update_delay;
	uint16_t v_establish_wait;
	char update_delay_begin_time[64];
	char update_delay_end_time[64];
	char update_delay_zebra_resume_time[64];
	char update_delay_peers_resume_time[64];
	uint32_t established;
	uint32_t restarted_peers;
	uint32_t implicit_eors;
	uint32_t explicit_eors;
#define BGP_UPDATE_DELAY_DEF              0
#define BGP_UPDATE_DELAY_MIN              0
#define BGP_UPDATE_DELAY_MAX              3600

	/* Reference bandwidth for BGP link-bandwidth. Used when
	 * the LB value has to be computed based on some other
	 * factor (e.g., number of multipaths for the prefix)
	 * Value is in Mbps
	 */
	uint32_t lb_ref_bw;
#define BGP_LINK_BW_REF_BW                1

	/* BGP flags. */
	uint32_t flags;
#define BGP_FLAG_ALWAYS_COMPARE_MED       (1 << 0)
#define BGP_FLAG_DETERMINISTIC_MED        (1 << 1)
#define BGP_FLAG_MED_MISSING_AS_WORST     (1 << 2)
#define BGP_FLAG_MED_CONFED               (1 << 3)
#define BGP_FLAG_NO_DEFAULT_IPV4          (1 << 4)
#define BGP_FLAG_NO_CLIENT_TO_CLIENT      (1 << 5)
#define BGP_FLAG_COMPARE_ROUTER_ID        (1 << 7)
#define BGP_FLAG_ASPATH_IGNORE            (1 << 8)
#define BGP_FLAG_IMPORT_CHECK             (1 << 9)
#define BGP_FLAG_NO_FAST_EXT_FAILOVER     (1 << 10)
#define BGP_FLAG_LOG_NEIGHBOR_CHANGES     (1 << 11)

/* This flag is set when we have full BGP Graceful-Restart mode enable */
#define BGP_FLAG_GRACEFUL_RESTART         (1 << 12)

#define BGP_FLAG_ASPATH_CONFED            (1 << 13)
#define BGP_FLAG_ASPATH_MULTIPATH_RELAX   (1 << 14)
#define BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY (1 << 15)
#define BGP_FLAG_DISABLE_NH_CONNECTED_CHK (1 << 16)
#define BGP_FLAG_MULTIPATH_RELAX_AS_SET   (1 << 17)
#define BGP_FLAG_FORCE_STATIC_PROCESS     (1 << 18)
#define BGP_FLAG_SHOW_HOSTNAME            (1 << 19)
#define BGP_FLAG_GR_PRESERVE_FWD          (1 << 20)
#define BGP_FLAG_GRACEFUL_SHUTDOWN        (1 << 21)
#define BGP_FLAG_DELETE_IN_PROGRESS       (1 << 22)
#define BGP_FLAG_SELECT_DEFER_DISABLE     (1 << 23)
#define BGP_FLAG_GR_DISABLE_EOR           (1 << 24)
#define BGP_FLAG_EBGP_REQUIRES_POLICY (1 << 25)

	enum global_mode GLOBAL_GR_FSM[BGP_GLOBAL_GR_MODE]
				      [BGP_GLOBAL_GR_EVENT_CMD];
	enum global_mode global_gr_present_state;

	/* This variable stores the current Graceful Restart state of Zebra
	 * - ZEBRA_GR_ENABLE / ZEBRA_GR_DISABLE
	 */
	enum zebra_gr_mode present_zebra_gr_state;

	/* BGP Per AF flags */
	uint16_t af_flags[AFI_MAX][SAFI_MAX];
#define BGP_CONFIG_DAMPENING				(1 << 0)
/* l2vpn evpn flags - 1 << 0 is used for DAMPENNG */
#define BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST		(1 << 1)
#define BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST		(1 << 2)
#define BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4		(1 << 3)
#define BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6		(1 << 4)
/* import/export between address families */
#define BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT		(1 << 5)
#define BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT		(1 << 6)
/* vrf-route leaking flags */
#define BGP_CONFIG_VRF_TO_VRF_IMPORT			(1 << 7)
#define BGP_CONFIG_VRF_TO_VRF_EXPORT			(1 << 8)

	/* BGP per AF peer count */
	uint32_t af_peer_count[AFI_MAX][SAFI_MAX];

	/* Route table for next-hop lookup cache. */
	struct bgp_table *nexthop_cache_table[AFI_MAX];

	/* Route table for import-check */
	struct bgp_table *import_check_table[AFI_MAX];

	struct bgp_table *connected_table[AFI_MAX];

	struct hash *address_hash;

	/* DB for all local tunnel-ips - used mainly for martian checks
	   Currently it only has all VxLan tunnel IPs*/
	struct hash *tip_hash;

	/* Static route configuration.  */
	struct bgp_table *route[AFI_MAX][SAFI_MAX];

	/* Aggregate address configuration.  */
	struct bgp_table *aggregate[AFI_MAX][SAFI_MAX];

	/* BGP routing information base.  */
	struct bgp_table *rib[AFI_MAX][SAFI_MAX];

	/* BGP table route-map.  */
	struct bgp_rmap table_map[AFI_MAX][SAFI_MAX];

	/* BGP redistribute configuration. */
	struct list *redist[AFI_MAX][ZEBRA_ROUTE_MAX];

	/* Allocate MPLS labels */
	uint8_t allocate_mpls_labels[AFI_MAX][SAFI_MAX];

	/* Allocate hash entries to store policy routing information
	 * The hash are used to host pbr rules somewhere.
	 * Actually, pbr will only be used by flowspec
	 * those hash elements will have relationship together as
	 * illustrated in below diagram:
	 *
	 *  pbr_action a <----- pbr_match i <--- pbr_match_entry 1..n
	 *              <----- pbr_match j <--- pbr_match_entry 1..m
	 *              <----- pbr_rule k
	 *
	 * - here in BGP structure, the list of match and actions will
	 * stand for the list of ipset sets, and table_ids in the kernel
	 * - the arrow above between pbr_match and pbr_action indicate
	 * that a backpointer permits match to find the action
	 * - the arrow betwen match_entry and match is a hash list
	 * contained in match, that lists the whole set of entries
	 */
	struct hash *pbr_match_hash;
	struct hash *pbr_rule_hash;
	struct hash *pbr_action_hash;

	/* timer to re-evaluate neighbor default-originate route-maps */
	struct thread *t_rmap_def_originate_eval;
#define RMAP_DEFAULT_ORIGINATE_EVAL_TIMER 5

	/* BGP distance configuration.  */
	uint8_t distance_ebgp[AFI_MAX][SAFI_MAX];
	uint8_t distance_ibgp[AFI_MAX][SAFI_MAX];
	uint8_t distance_local[AFI_MAX][SAFI_MAX];

	/* BGP default local-preference.  */
	uint32_t default_local_pref;

	/* BGP default subgroup pkt queue max  */
	uint32_t default_subgroup_pkt_queue_max;

	/* BGP default timer.  */
	uint32_t default_holdtime;
	uint32_t default_keepalive;
	uint32_t default_connect_retry;

	/* BGP graceful restart */
	uint32_t restart_time;
	uint32_t stalepath_time;
	uint32_t select_defer_time;
	struct graceful_restart_info gr_info[AFI_MAX][SAFI_MAX];
	uint32_t rib_stale_time;

#define BGP_ROUTE_SELECT_DELAY 1
#define BGP_MAX_BEST_ROUTE_SELECT 10000
	/* Maximum-paths configuration */
	struct bgp_maxpaths_cfg {
		uint16_t maxpaths_ebgp;
		uint16_t maxpaths_ibgp;
		uint16_t ibgp_flags;
#define BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN (1 << 0)
	} maxpaths[AFI_MAX][SAFI_MAX];

	_Atomic uint32_t wpkt_quanta; // max # packets to write per i/o cycle
	_Atomic uint32_t rpkt_quanta; // max # packets to read per i/o cycle

	/* Automatic coalesce adjust on/off */
	bool heuristic_coalesce;
	/* Actual coalesce time */
	uint32_t coalesce_time;

	/* Auto-shutdown new peers */
	bool autoshutdown;

	struct bgp_addpath_bgp_data tx_addpath;

#ifdef ENABLE_BGP_VNC
	struct rfapi_cfg *rfapi_cfg;
	struct rfapi *rfapi;
#endif

	/* EVPN related information */

	/* EVI hash table */
	struct hash *vnihash;

	/* EVPN enable - advertise gateway macip routes */
	int advertise_gw_macip;

	/* EVPN enable - advertise local VNIs and their MACs etc. */
	int advertise_all_vni;

	/* draft-ietf-idr-deprecate-as-set-confed-set
	 * Reject aspaths with AS_SET and/or AS_CONFED_SET.
	 */
	bool reject_as_sets;

	struct bgp_evpn_info *evpn_info;

	/* EVPN - use RFC 8365 to auto-derive RT */
	int advertise_autort_rfc8365;

	/*
	 * Flooding mechanism for BUM packets for VxLAN-EVPN.
	 */
	enum vxlan_flood_control vxlan_flood_ctrl;

	/* Hash table of Import RTs to EVIs */
	struct hash *import_rt_hash;

	/* Hash table of VRF import RTs to VRFs */
	struct hash *vrf_import_rt_hash;

	/* L3-VNI corresponding to this vrf */
	vni_t l3vni;

	/* router-mac to be used in mac-ip routes for this vrf */
	struct ethaddr rmac;

	/* originator ip - to be used as NH for type-5 routes */
	struct in_addr originator_ip;

	/* SVI associated with the L3-VNI corresponding to this vrf */
	ifindex_t l3vni_svi_ifindex;

	/* vrf flags */
	uint32_t vrf_flags;
#define BGP_VRF_AUTO                        (1 << 0)
#define BGP_VRF_IMPORT_RT_CFGD              (1 << 1)
#define BGP_VRF_EXPORT_RT_CFGD              (1 << 2)
#define BGP_VRF_RD_CFGD                     (1 << 3)
#define BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY    (1 << 4)

	/* unique ID for auto derivation of RD for this vrf */
	uint16_t vrf_rd_id;

	/* Automatically derived RD for this VRF */
	struct prefix_rd vrf_prd_auto;

	/* RD for this VRF */
	struct prefix_rd vrf_prd;

	/* import rt list for the vrf instance */
	struct list *vrf_import_rtl;

	/* export rt list for the vrf instance */
	struct list *vrf_export_rtl;

	/* list of corresponding l2vnis (struct bgpevpn) */
	struct list *l2vnis;

	/* route map for advertise ipv4/ipv6 unicast (type-5 routes) */
	struct bgp_rmap adv_cmd_rmap[AFI_MAX][SAFI_MAX];

	struct vpn_policy vpn_policy[AFI_MAX];

	struct bgp_pbr_config *bgp_pbr_cfg;

	/* Count of peers in established state */
	uint32_t established_peers;

	/* Weighted ECMP related config. */
	enum bgp_link_bw_handling lb_handling;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(bgp)

DECLARE_HOOK(bgp_inst_delete, (struct bgp *bgp), (bgp))
DECLARE_HOOK(bgp_inst_config_write,
		(struct bgp *bgp, struct vty *vty),
		(bgp, vty))

/* Thread callback information */
struct afi_safi_info {
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;
};

#define BGP_ROUTE_ADV_HOLD(bgp) (bgp->main_peers_update_hold)

#define IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)                                        \
	(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT                           \
	 || (bgp->inst_type == BGP_INSTANCE_TYPE_VRF                           \
	     && bgp->vrf_id != VRF_UNKNOWN))

#define BGP_SELECT_DEFER_DISABLE(bgp)                                          \
	(CHECK_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE))

/* BGP peer-group support. */
struct peer_group {
	/* Name of the peer-group. */
	char *name;

	/* Pointer to BGP.  */
	struct bgp *bgp;

	/* Peer-group client list. */
	struct list *peer;

	/** Dynamic neighbor listening ranges */
	struct list *listen_range[AFI_MAX];

	/* Peer-group config */
	struct peer *conf;
};

/* BGP Notify message format. */
struct bgp_notify {
	uint8_t code;
	uint8_t subcode;
	char *data;
	bgp_size_t length;
	uint8_t *raw_data;
};

/* Next hop self address. */
struct bgp_nexthop {
	struct interface *ifp;
	struct in_addr v4;
	struct in6_addr v6_global;
	struct in6_addr v6_local;
};

/* BGP addpath values */
#define BGP_ADDPATH_RX     1
#define BGP_ADDPATH_TX     2
#define BGP_ADDPATH_ID_LEN 4

#define BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE 1

/* Route map direction */
#define RMAP_IN  0
#define RMAP_OUT 1
#define RMAP_MAX 2

#define BGP_DEFAULT_TTL         1
#define BGP_GTSM_HOPS_DISABLED  0
#define BGP_GTSM_HOPS_CONNECTED 1

#include "filter.h"

/* BGP filter structure. */
struct bgp_filter {
	/* Distribute-list.  */
	struct {
		char *name;
		struct access_list *alist;
	} dlist[FILTER_MAX];

	/* Prefix-list.  */
	struct {
		char *name;
		struct prefix_list *plist;
	} plist[FILTER_MAX];

	/* Filter-list.  */
	struct {
		char *name;
		struct as_list *aslist;
	} aslist[FILTER_MAX];

	/* Route-map.  */
	struct {
		char *name;
		struct route_map *map;
	} map[RMAP_MAX];

	/* Unsuppress-map.  */
	struct {
		char *name;
		struct route_map *map;
	} usmap;
};

/* IBGP/EBGP identifier.  We also have a CONFED peer, which is to say,
   a peer who's AS is part of our Confederation.  */
typedef enum {
	BGP_PEER_UNSPECIFIED,
	BGP_PEER_IBGP,
	BGP_PEER_EBGP,
	BGP_PEER_INTERNAL,
	BGP_PEER_CONFED,
} bgp_peer_sort_t;

/* BGP message header and packet size.  */
#define BGP_MARKER_SIZE		                16
#define BGP_HEADER_SIZE		                19
#define BGP_MAX_PACKET_SIZE                   4096
#define BGP_MAX_PACKET_SIZE_OVERFLOW          1024

/*
 * Trigger delay for bgp_announce_route().
 */
#define BGP_ANNOUNCE_ROUTE_SHORT_DELAY_MS  100
#define BGP_ANNOUNCE_ROUTE_DELAY_MS        500

struct peer_af {
	/* back pointer to the peer */
	struct peer *peer;

	/* which subgroup the peer_af belongs to */
	struct update_subgroup *subgroup;

	/* for being part of an update subgroup's peer list */
	LIST_ENTRY(peer_af) subgrp_train;

	/* for being part of a packet's peer list */
	LIST_ENTRY(peer_af) pkt_train;

	struct bpacket *next_pkt_to_send;

	/*
	 * Trigger timer for bgp_announce_route().
	 */
	struct thread *t_announce_route;

	afi_t afi;
	safi_t safi;
	int afid;
};
/* BGP GR per peer ds */

#define BGP_PEER_GR_MODE 5
#define BGP_PEER_GR_EVENT_CMD 6

enum peer_mode {
	PEER_HELPER = 0,
	PEER_GR,
	PEER_DISABLE,
	PEER_INVALID,
	PEER_GLOBAL_INHERIT /* This is the default mode */

};

enum peer_gr_command {
	PEER_GR_CMD = 0,
	NO_PEER_GR_CMD,
	PEER_DISABLE_CMD,
	NO_PEER_DISABLE_CMD,
	PEER_HELPER_CMD,
	NO_PEER_HELPER_CMD
};

typedef unsigned int  (*bgp_peer_gr_action_ptr)(struct peer *, int, int);

struct bgp_peer_gr {
	enum peer_mode next_state;
	bgp_peer_gr_action_ptr action_fun;
};

/* BGP finite state machine events.  */
enum bgp_fsm_events {
	BGP_Start = 1,
	BGP_Stop,
	TCP_connection_open,
	TCP_connection_closed,
	TCP_connection_open_failed,
	TCP_fatal_error,
	ConnectRetry_timer_expired,
	Hold_Timer_expired,
	KeepAlive_timer_expired,
	Receive_OPEN_message,
	Receive_KEEPALIVE_message,
	Receive_UPDATE_message,
	Receive_NOTIFICATION_message,
	Clearing_Completed,
	BGP_EVENTS_MAX,
};

/* BGP finite state machine status.  */
enum bgp_fsm_status {
	Idle = 1,
	Connect,
	Active,
	OpenSent,
	OpenConfirm,
	Established,
	Clearing,
	Deleted,
	BGP_STATUS_MAX,
};

/* BGP neighbor structure. */
struct peer {
	/* BGP structure.  */
	struct bgp *bgp;

	/* reference count, primarily to allow bgp_process'ing of route_node's
	 * to be done after a struct peer is deleted.
	 *
	 * named 'lock' for hysterical reasons within Quagga.
	 */
	int lock;

	/* BGP peer group.  */
	struct peer_group *group;
	uint64_t version[AFI_MAX][SAFI_MAX];

	/* BGP peer_af structures, per configured AF on this peer */
	struct peer_af *peer_af_array[BGP_AF_MAX];

	/* Peer's remote AS number. */
	int as_type;
	as_t as;

	/* Peer's local AS number. */
	as_t local_as;

	bgp_peer_sort_t sort;

	/* Peer's Change local AS number. */
	as_t change_local_as;

	/* Remote router ID. */
	struct in_addr remote_id;

	/* Local router ID. */
	struct in_addr local_id;

	/* Packet receive and send buffer. */
	pthread_mutex_t io_mtx;   // guards ibuf, obuf
	struct stream_fifo *ibuf; // packets waiting to be processed
	struct stream_fifo *obuf; // packets waiting to be written

	struct ringbuf *ibuf_work; // WiP buffer used by bgp_read() only
	struct stream *obuf_work;  // WiP buffer used to construct packets

	struct stream *curr; // the current packet being parsed

	/* We use a separate stream to encode MP_REACH_NLRI for efficient
	 * NLRI packing. peer->obuf_work stores all the other attributes. The
	 * actual packet is then constructed by concatenating the two.
	 */
	struct stream *scratch;

	/* the doppelganger peer structure, due to dual TCP conn setup */
	struct peer *doppelganger;

	/* Status of the peer. */
	enum bgp_fsm_status status;
	enum bgp_fsm_status ostatus;

	/* FSM events, stored for debug purposes.
	 * Note: uchar used for reduced memory usage.
	 */
	enum bgp_fsm_events cur_event;
	enum bgp_fsm_events last_event;
	enum bgp_fsm_events last_major_event;

	/* Peer index, used for dumping TABLE_DUMP_V2 format */
	uint16_t table_dump_index;

	/* Peer information */
	int fd;		     /* File descriptor */
	int ttl;	     /* TTL of TCP connection to the peer. */
	int rtt;	     /* Estimated round-trip-time from TCP_INFO */
	int gtsm_hops;       /* minimum hopcount to peer */
	char *desc;	  /* Description of the peer. */
	unsigned short port; /* Destination port for peer */
	char *host;	  /* Printable address of the peer. */
	union sockunion su;  /* Sockunion address of the peer. */
#define BGP_PEER_SU_UNSPEC(peer) (peer->su.sa.sa_family == AF_UNSPEC)
	time_t uptime;       /* Last Up/Down time */
	time_t readtime;     /* Last read time */
	time_t resettime;    /* Last reset time */

	char *conf_if;	 /* neighbor interface config name. */
	struct interface *ifp; /* corresponding interface */
	char *ifname;	  /* bind interface name. */
	char *update_if;
	union sockunion *update_source;

	union sockunion *su_local;  /* Sockunion of local address.  */
	union sockunion *su_remote; /* Sockunion of remote address.  */
	int shared_network;	 /* Is this peer shared same network. */
	struct bgp_nexthop nexthop; /* Nexthop */

	/* Peer address family configuration. */
	uint8_t afc[AFI_MAX][SAFI_MAX];
	uint8_t afc_nego[AFI_MAX][SAFI_MAX];
	uint8_t afc_adv[AFI_MAX][SAFI_MAX];
	uint8_t afc_recv[AFI_MAX][SAFI_MAX];

	/* Capability flags (reset in bgp_stop) */
	uint32_t cap;
#define PEER_CAP_REFRESH_ADV                (1 << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_OLD_RCV            (1 << 1) /* refresh old received */
#define PEER_CAP_REFRESH_NEW_RCV            (1 << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV                (1 << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV                (1 << 4) /* dynamic received */
#define PEER_CAP_RESTART_ADV                (1 << 5) /* restart advertised */
#define PEER_CAP_RESTART_RCV                (1 << 6) /* restart received */
#define PEER_CAP_AS4_ADV                    (1 << 7) /* as4 advertised */
#define PEER_CAP_AS4_RCV                    (1 << 8) /* as4 received */
#define PEER_CAP_RESTART_BIT_ADV            (1 << 9) /* sent restart state */
#define PEER_CAP_RESTART_BIT_RCV            (1 << 10) /* peer restart state */
#define PEER_CAP_ADDPATH_ADV                (1 << 11) /* addpath advertised */
#define PEER_CAP_ADDPATH_RCV                (1 << 12) /* addpath received */
#define PEER_CAP_ENHE_ADV                   (1 << 13) /* Extended nexthop advertised */
#define PEER_CAP_ENHE_RCV                   (1 << 14) /* Extended nexthop received */
#define PEER_CAP_HOSTNAME_ADV               (1 << 15) /* hostname advertised */
#define PEER_CAP_HOSTNAME_RCV               (1 << 16) /* hostname received */

	/* Capability flags (reset in bgp_stop) */
	uint32_t af_cap[AFI_MAX][SAFI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1 << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1 << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1 << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1 << 3) /* receive-mode received */
#define PEER_CAP_ORF_PREFIX_SM_OLD_RCV      (1 << 4) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_OLD_RCV      (1 << 5) /* receive-mode received */
#define PEER_CAP_RESTART_AF_RCV             (1 << 6) /* graceful restart afi/safi received */
#define PEER_CAP_RESTART_AF_PRESERVE_RCV    (1 << 7) /* graceful restart afi/safi F-bit received */
#define PEER_CAP_ADDPATH_AF_TX_ADV          (1 << 8) /* addpath tx advertised */
#define PEER_CAP_ADDPATH_AF_TX_RCV          (1 << 9) /* addpath tx received */
#define PEER_CAP_ADDPATH_AF_RX_ADV          (1 << 10) /* addpath rx advertised */
#define PEER_CAP_ADDPATH_AF_RX_RCV          (1 << 11) /* addpath rx received */
#define PEER_CAP_ENHE_AF_ADV                (1 << 12) /* Extended nexthopi afi/safi advertised */
#define PEER_CAP_ENHE_AF_RCV                (1 << 13) /* Extended nexthop afi/safi received */
#define PEER_CAP_ENHE_AF_NEGO               (1 << 14) /* Extended nexthop afi/safi negotiated */

	/* Global configuration flags. */
	/*
	 * Parallel array to flags that indicates whether each flag originates
	 * from a peer-group or if it is config that is specific to this
	 * individual peer. If a flag is set independent of the peer-group, the
	 * same bit should be set here. If this peer is a peer-group, this
	 * memory region should be all zeros.
	 *
	 * The assumption is that the default state for all flags is unset,
	 * so if a flag is unset, the corresponding override flag is unset too.
	 * However if a flag is set, the corresponding override flag is set.
	 */
	uint32_t flags_override;
	/*
	 * Parallel array to flags that indicates whether the default behavior
	 * of *flags_override* should be inverted. If a flag is unset and the
	 * corresponding invert flag is set, the corresponding override flag
	 * would be set. However if a flag is set and the corresponding invert
	 * flag is unset, the corresponding override flag would be unset.
	 *
	 * This can be used for attributes like *send-community*, which are
	 * implicitely enabled and have to be disabled explicitely, compared to
	 * 'normal' attributes like *next-hop-self* which are implicitely set.
	 *
	 * All operations dealing with flags should apply the following boolean
	 * logic to keep the internal flag system in a sane state:
	 *
	 * value=0 invert=0	Inherit flag if member, otherwise unset flag
	 * value=0 invert=1	Unset flag unconditionally
	 * value=1 invert=0	Set flag unconditionally
	 * value=1 invert=1	Inherit flag if member, otherwise set flag
	 *
	 * Contrary to the implementation of *flags_override*, the flag
	 * inversion state can be set either on the peer OR the peer *and* the
	 * peer-group. This was done on purpose, as the inversion state of a
	 * flag can be determined on either the peer or the peer-group.
	 *
	 * Example: Enabling the cisco configuration mode inverts all flags
	 * related to *send-community* unconditionally for both peer-groups and
	 * peers.
	 *
	 * This behavior is different for interface peers though, which enable
	 * the *extended-nexthop* flag by default, which regular peers do not.
	 * As the peer-group can contain both regular and interface peers, the
	 * flag inversion state must be set on the peer only.
	 *
	 * When a peer inherits the configuration from a peer-group and the
	 * inversion state of the flag differs between peer and peer-group, the
	 * newly set value must equal to the inverted state of the peer-group.
	 */
	uint32_t flags_invert;
	/*
	 * Effective array for storing the peer/peer-group flags. In case of a
	 * peer-group, the peer-specific overrides (see flags_override and
	 * flags_invert) must be respected.
	 */
	uint32_t flags;
#define PEER_FLAG_PASSIVE                   (1 << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1 << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1 << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1 << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1 << 4) /* strict-match */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1 << 5) /* dynamic capability */
#define PEER_FLAG_DISABLE_CONNECTED_CHECK   (1 << 6) /* disable-connected-check */
#define PEER_FLAG_LOCAL_AS_NO_PREPEND       (1 << 7) /* local-as no-prepend */
#define PEER_FLAG_LOCAL_AS_REPLACE_AS       (1 << 8) /* local-as no-prepend replace-as */
#define PEER_FLAG_DELETE                    (1 << 9) /* mark the peer for deleting */
#define PEER_FLAG_CONFIG_NODE               (1 << 10) /* the node to update configs on */
#define PEER_FLAG_LONESOUL                  (1 << 11)
#define PEER_FLAG_DYNAMIC_NEIGHBOR          (1 << 12) /* dynamic neighbor */
#define PEER_FLAG_CAPABILITY_ENHE           (1 << 13) /* Extended next-hop (rfc 5549)*/
#define PEER_FLAG_IFPEER_V6ONLY             (1 << 14) /* if-based peer is v6 only */
#define PEER_FLAG_IS_RFAPI_HD               (1 << 15) /* attached to rfapi HD */
#define PEER_FLAG_ENFORCE_FIRST_AS          (1 << 16) /* enforce-first-as */
#define PEER_FLAG_ROUTEADV                  (1 << 17) /* route advertise */
#define PEER_FLAG_TIMER                     (1 << 18) /* keepalive & holdtime */
#define PEER_FLAG_TIMER_CONNECT             (1 << 19) /* connect timer */
#define PEER_FLAG_PASSWORD                  (1 << 20) /* password */
#define PEER_FLAG_LOCAL_AS                  (1 << 21) /* local-as */
#define PEER_FLAG_UPDATE_SOURCE             (1 << 22) /* update-source */

	/* BGP-GR Peer related  flags */
#define PEER_FLAG_GRACEFUL_RESTART_HELPER   (1 << 23) /* Helper */
#define PEER_FLAG_GRACEFUL_RESTART          (1 << 24) /* Graceful Restart */
#define PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT (1 << 25) /* Global-Inherit */

	/*
	 *GR-Disabled mode means unset PEER_FLAG_GRACEFUL_RESTART
	 *& PEER_FLAG_GRACEFUL_RESTART_HELPER
	 *and PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT
	 */

	struct bgp_peer_gr PEER_GR_FSM[BGP_PEER_GR_MODE][BGP_PEER_GR_EVENT_CMD];
	enum peer_mode peer_gr_present_state;
	/* Non stop forwarding afi-safi count for BGP gr feature*/
	uint8_t nsf_af_count;

	uint8_t peer_gr_new_status_flag;
#define PEER_GRACEFUL_RESTART_NEW_STATE_HELPER   (1 << 0)
#define PEER_GRACEFUL_RESTART_NEW_STATE_RESTART  (1 << 1)
#define PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT  (1 << 2)

	/* outgoing message sent in CEASE_ADMIN_SHUTDOWN notify */
	char *tx_shutdown_message;

	/* NSF mode (graceful restart) */
	uint8_t nsf[AFI_MAX][SAFI_MAX];
	/* EOR Send time */
	time_t eor_stime[AFI_MAX][SAFI_MAX];
	/* Last update packet sent time */
	time_t pkt_stime[AFI_MAX][SAFI_MAX];

	/* Peer Per AF flags */
	/*
	 * Please consult the comments for *flags_override*, *flags_invert* and
	 * *flags* to understand what these three arrays do. The address-family
	 * specific attributes are being treated the exact same way as global
	 * peer attributes.
	 */
	uint32_t af_flags_override[AFI_MAX][SAFI_MAX];
	uint32_t af_flags_invert[AFI_MAX][SAFI_MAX];
	uint32_t af_flags[AFI_MAX][SAFI_MAX];
#define PEER_FLAG_SEND_COMMUNITY            (1 << 0) /* send-community */
#define PEER_FLAG_SEND_EXT_COMMUNITY        (1 << 1) /* send-community ext. */
#define PEER_FLAG_NEXTHOP_SELF              (1 << 2) /* next-hop-self */
#define PEER_FLAG_REFLECTOR_CLIENT          (1 << 3) /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT            (1 << 4) /* route-server-client */
#define PEER_FLAG_SOFT_RECONFIG             (1 << 5) /* soft-reconfiguration */
#define PEER_FLAG_AS_PATH_UNCHANGED         (1 << 6) /* transparent-as */
#define PEER_FLAG_NEXTHOP_UNCHANGED         (1 << 7) /* transparent-next-hop */
#define PEER_FLAG_MED_UNCHANGED             (1 << 8) /* transparent-next-hop */
#define PEER_FLAG_DEFAULT_ORIGINATE         (1 << 9) /* default-originate */
#define PEER_FLAG_REMOVE_PRIVATE_AS         (1 << 10) /* remove-private-as */
#define PEER_FLAG_ALLOWAS_IN                (1 << 11) /* set allowas-in */
#define PEER_FLAG_ORF_PREFIX_SM             (1 << 12) /* orf capability send-mode */
#define PEER_FLAG_ORF_PREFIX_RM             (1 << 13) /* orf capability receive-mode */
#define PEER_FLAG_MAX_PREFIX                (1 << 14) /* maximum prefix */
#define PEER_FLAG_MAX_PREFIX_WARNING        (1 << 15) /* maximum prefix warning-only */
#define PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED   (1 << 16) /* leave link-local nexthop unchanged */
#define PEER_FLAG_FORCE_NEXTHOP_SELF        (1 << 17) /* next-hop-self force */
#define PEER_FLAG_REMOVE_PRIVATE_AS_ALL     (1 << 18) /* remove-private-as all */
#define PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE (1 << 19) /* remove-private-as replace-as */
#define PEER_FLAG_AS_OVERRIDE               (1 << 20) /* as-override */
#define PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE (1 << 21) /* remove-private-as all replace-as */
#define PEER_FLAG_WEIGHT                    (1 << 24) /* weight */
#define PEER_FLAG_ALLOWAS_IN_ORIGIN         (1 << 25) /* allowas-in origin */
#define PEER_FLAG_SEND_LARGE_COMMUNITY      (1 << 26) /* Send large Communities */
#define PEER_FLAG_MAX_PREFIX_OUT            (1 << 27) /* outgoing maximum prefix */

	enum bgp_addpath_strat addpath_type[AFI_MAX][SAFI_MAX];

	/* MD5 password */
	char *password;

	/* default-originate route-map.  */
	struct {
		char *name;
		struct route_map *map;
	} default_rmap[AFI_MAX][SAFI_MAX];

	/* Peer status flags. */
	uint16_t sflags;
#define PEER_STATUS_ACCEPT_PEER	      (1 << 0) /* accept peer */
#define PEER_STATUS_PREFIX_OVERFLOW   (1 << 1) /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN   (1 << 2) /* capability open send */
#define PEER_STATUS_HAVE_ACCEPT       (1 << 3) /* accept peer's parent */
#define PEER_STATUS_GROUP             (1 << 4) /* peer-group conf */
#define PEER_STATUS_NSF_MODE          (1 << 5) /* NSF aware peer */
#define PEER_STATUS_NSF_WAIT          (1 << 6) /* wait comeback peer */

	/* Peer status af flags (reset in bgp_stop) */
	uint16_t af_sflags[AFI_MAX][SAFI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND   (1 << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH  (1 << 1) /* wait refresh received peer */
#define PEER_STATUS_PREFIX_THRESHOLD  (1 << 2) /* exceed prefix-threshold */
#define PEER_STATUS_PREFIX_LIMIT      (1 << 3) /* exceed prefix-limit */
#define PEER_STATUS_EOR_SEND          (1 << 4) /* end-of-rib send to peer */
#define PEER_STATUS_EOR_RECEIVED      (1 << 5) /* end-of-rib received from peer */

	/* Configured timer values. */
	_Atomic uint32_t holdtime;
	_Atomic uint32_t keepalive;
	_Atomic uint32_t connect;
	_Atomic uint32_t routeadv;

	/* Timer values. */
	_Atomic uint32_t v_start;
	_Atomic uint32_t v_connect;
	_Atomic uint32_t v_holdtime;
	_Atomic uint32_t v_keepalive;
	_Atomic uint32_t v_routeadv;
	_Atomic uint32_t v_pmax_restart;
	_Atomic uint32_t v_gr_restart;

	/* Threads. */
	struct thread *t_read;
	struct thread *t_write;
	struct thread *t_start;
	struct thread *t_connect_check_r;
	struct thread *t_connect_check_w;
	struct thread *t_connect;
	struct thread *t_holdtime;
	struct thread *t_routeadv;
	struct thread *t_pmax_restart;
	struct thread *t_gr_restart;
	struct thread *t_gr_stale;
	struct thread *t_generate_updgrp_packets;
	struct thread *t_process_packet;

	/* Thread flags. */
	_Atomic uint32_t thread_flags;
#define PEER_THREAD_WRITES_ON         (1 << 0)
#define PEER_THREAD_READS_ON          (1 << 1)
#define PEER_THREAD_KEEPALIVES_ON     (1 << 2)
	/* workqueues */
	struct work_queue *clear_node_queue;

#define PEER_TOTAL_RX(peer)                                                    \
	atomic_load_explicit(&peer->open_in, memory_order_relaxed)             \
		+ atomic_load_explicit(&peer->update_in, memory_order_relaxed) \
		+ atomic_load_explicit(&peer->notify_in, memory_order_relaxed) \
		+ atomic_load_explicit(&peer->refresh_in,                      \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->keepalive_in,                    \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->dynamic_cap_in,                  \
				       memory_order_relaxed)

#define PEER_TOTAL_TX(peer)                                                    \
	atomic_load_explicit(&peer->open_out, memory_order_relaxed)            \
		+ atomic_load_explicit(&peer->update_out,                      \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->notify_out,                      \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->refresh_out,                     \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->keepalive_out,                   \
				       memory_order_relaxed)                   \
		+ atomic_load_explicit(&peer->dynamic_cap_out,                 \
				       memory_order_relaxed)

	/* Statistics field */
	_Atomic uint32_t open_in;	 /* Open message input count */
	_Atomic uint32_t open_out;	/* Open message output count */
	_Atomic uint32_t update_in;       /* Update message input count */
	_Atomic uint32_t update_out;      /* Update message ouput count */
	_Atomic time_t update_time;       /* Update message received time. */
	_Atomic uint32_t keepalive_in;    /* Keepalive input count */
	_Atomic uint32_t keepalive_out;   /* Keepalive output count */
	_Atomic uint32_t notify_in;       /* Notify input count */
	_Atomic uint32_t notify_out;      /* Notify output count */
	_Atomic uint32_t refresh_in;      /* Route Refresh input count */
	_Atomic uint32_t refresh_out;     /* Route Refresh output count */
	_Atomic uint32_t dynamic_cap_in;  /* Dynamic Capability input count.  */
	_Atomic uint32_t dynamic_cap_out; /* Dynamic Capability output count. */

	uint32_t stat_pfx_filter;
	uint32_t stat_pfx_aspath_loop;
	uint32_t stat_pfx_originator_loop;
	uint32_t stat_pfx_cluster_loop;
	uint32_t stat_pfx_nh_invalid;
	uint32_t stat_pfx_dup_withdraw;
	uint32_t stat_upd_7606;  /* RFC7606: treat-as-withdraw */

	/* BGP state count */
	uint32_t established; /* Established */
	uint32_t dropped;     /* Dropped */

	/* Update delay related fields */
	uint8_t update_delay_over; /* When this is set, BGP is no more waiting
				     for EOR */

	/* Syncronization list and time.  */
	struct bgp_synchronize *sync[AFI_MAX][SAFI_MAX];
	time_t synctime;
	/* timestamp when the last UPDATE msg was written */
	_Atomic time_t last_write;
	/* timestamp when the last msg was written */
	_Atomic time_t last_update;

	/* Notify data. */
	struct bgp_notify notify;

	/* Filter structure. */
	struct bgp_filter filter[AFI_MAX][SAFI_MAX];

	/*
	 * Parallel array to filter that indicates whether each filter
	 * originates from a peer-group or if it is config that is specific to
	 * this individual peer. If a filter is set independent of the
	 * peer-group the appropriate bit should be set here. If this peer is a
	 * peer-group, this memory region should be all zeros. The assumption
	 * is that the default state for all flags is unset. Due to filters
	 * having a direction (e.g. in/out/...), this array has a third
	 * dimension for storing the overrides independently per direction.
	 *
	 * Notes:
	 * - if a filter for an individual peer is unset, the corresponding
	 *   override flag is unset and the peer is considered to be back in
	 *   sync with the peer-group.
	 * - This does *not* contain the filter values, rather it contains
	 *   whether the filter in filter (struct bgp_filter) is peer-specific.
	 */
	uint8_t filter_override[AFI_MAX][SAFI_MAX][FILTER_MAX];
#define PEER_FT_DISTRIBUTE_LIST       (1 << 0) /* distribute-list */
#define PEER_FT_FILTER_LIST           (1 << 1) /* filter-list */
#define PEER_FT_PREFIX_LIST           (1 << 2) /* prefix-list */
#define PEER_FT_ROUTE_MAP             (1 << 3) /* route-map */
#define PEER_FT_UNSUPPRESS_MAP        (1 << 4) /* unsuppress-map */

	/* ORF Prefix-list */
	struct prefix_list *orf_plist[AFI_MAX][SAFI_MAX];

	/* Text description of last attribute rcvd */
	char rcvd_attr_str[BUFSIZ];

	/* Track if we printed the attribute in debugs */
	int rcvd_attr_printed;

	/* Prefix count. */
	uint32_t pcount[AFI_MAX][SAFI_MAX];

	/* Max prefix count. */
	uint32_t pmax[AFI_MAX][SAFI_MAX];
	uint8_t pmax_threshold[AFI_MAX][SAFI_MAX];
	uint16_t pmax_restart[AFI_MAX][SAFI_MAX];
#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

	/* Send prefix count. */
	uint32_t pmax_out[AFI_MAX][SAFI_MAX];

	/* allowas-in. */
	char allowas_in[AFI_MAX][SAFI_MAX];

	/* weight */
	unsigned long weight[AFI_MAX][SAFI_MAX];

	/* peer reset cause */
	uint8_t last_reset;
#define PEER_DOWN_RID_CHANGE             1 /* bgp router-id command */
#define PEER_DOWN_REMOTE_AS_CHANGE       2 /* neighbor remote-as command */
#define PEER_DOWN_LOCAL_AS_CHANGE        3 /* neighbor local-as command */
#define PEER_DOWN_CLID_CHANGE            4 /* bgp cluster-id command */
#define PEER_DOWN_CONFED_ID_CHANGE       5 /* bgp confederation id command */
#define PEER_DOWN_CONFED_PEER_CHANGE     6 /* bgp confederation peer command */
#define PEER_DOWN_RR_CLIENT_CHANGE       7 /* neighbor rr-client command */
#define PEER_DOWN_RS_CLIENT_CHANGE       8 /* neighbor rs-client command */
#define PEER_DOWN_UPDATE_SOURCE_CHANGE   9 /* neighbor update-source command */
#define PEER_DOWN_AF_ACTIVATE           10 /* neighbor activate command */
#define PEER_DOWN_USER_SHUTDOWN         11 /* neighbor shutdown command */
#define PEER_DOWN_USER_RESET            12 /* clear ip bgp command */
#define PEER_DOWN_NOTIFY_RECEIVED       13 /* notification received */
#define PEER_DOWN_NOTIFY_SEND           14 /* notification send */
#define PEER_DOWN_CLOSE_SESSION         15 /* tcp session close */
#define PEER_DOWN_NEIGHBOR_DELETE       16 /* neghbor delete */
#define PEER_DOWN_RMAP_BIND             17 /* neghbor peer-group command */
#define PEER_DOWN_RMAP_UNBIND           18 /* no neighbor peer-group command */
#define PEER_DOWN_CAPABILITY_CHANGE     19 /* neighbor capability command */
#define PEER_DOWN_PASSIVE_CHANGE        20 /* neighbor passive command */
#define PEER_DOWN_MULTIHOP_CHANGE       21 /* neighbor multihop command */
#define PEER_DOWN_NSF_CLOSE_SESSION     22 /* NSF tcp session close */
#define PEER_DOWN_V6ONLY_CHANGE         23 /* if-based peering v6only toggled */
#define PEER_DOWN_BFD_DOWN              24 /* BFD down */
#define PEER_DOWN_IF_DOWN               25 /* Interface down */
#define PEER_DOWN_NBR_ADDR_DEL          26 /* Peer address lost */
#define PEER_DOWN_WAITING_NHT           27 /* Waiting for NHT to resolve */
#define PEER_DOWN_NBR_ADDR              28 /* Waiting for peer IPv6 IP Addr */
#define PEER_DOWN_VRF_UNINIT            29 /* Associated VRF is not init yet */
#define PEER_DOWN_NOAFI_ACTIVATED       30 /* No AFI/SAFI activated for peer */
#define PEER_DOWN_AS_SETS_REJECT        31 /* Reject routes with AS_SET */
#define PEER_DOWN_WAITING_OPEN          32 /* Waiting for open to succeed */
#define PEER_DOWN_PFX_COUNT             33 /* Reached received prefix count */
	/*
	 * Remember to update peer_down_str in bgp_fsm.c when you add
	 * a new value to the last_reset reason
	 */

	size_t last_reset_cause_size;
	uint8_t last_reset_cause[BGP_MAX_PACKET_SIZE];

	/* The kind of route-map Flags.*/
	uint16_t rmap_type;
#define PEER_RMAP_TYPE_IN             (1 << 0) /* neighbor route-map in */
#define PEER_RMAP_TYPE_OUT            (1 << 1) /* neighbor route-map out */
#define PEER_RMAP_TYPE_NETWORK        (1 << 2) /* network route-map */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1 << 3) /* redistribute route-map */
#define PEER_RMAP_TYPE_DEFAULT        (1 << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_NOSET          (1 << 5) /* not allow to set commands */
#define PEER_RMAP_TYPE_IMPORT         (1 << 6) /* neighbor route-map import */
#define PEER_RMAP_TYPE_EXPORT         (1 << 7) /* neighbor route-map export */
#define PEER_RMAP_TYPE_AGGREGATE      (1 << 8) /* aggregate-address route-map */

	/* peer specific BFD information */
	struct bfd_info *bfd_info;

	/* hostname and domainname advertised by host */
	char *hostname;
	char *domainname;

	/* Sender side AS path loop detection. */
	bool as_path_loop_detection;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(peer)

/* Inherit peer attribute from peer-group. */
#define PEER_ATTR_INHERIT(peer, group, attr)                                   \
	((peer)->attr = (group)->conf->attr)
#define PEER_STR_ATTR_INHERIT(peer, group, attr, mt)                           \
	do {                                                                   \
		XFREE(mt, (peer)->attr);                                       \
		if ((group)->conf->attr)                                       \
			(peer)->attr = XSTRDUP(mt, (group)->conf->attr);       \
		else                                                           \
			(peer)->attr = NULL;                                   \
	} while (0)
#define PEER_SU_ATTR_INHERIT(peer, group, attr)                                \
	do {                                                                   \
		if ((peer)->attr)                                              \
			sockunion_free((peer)->attr);                          \
		if ((group)->conf->attr)                                       \
			(peer)->attr = sockunion_dup((group)->conf->attr);     \
		else                                                           \
			(peer)->attr = NULL;                                   \
	} while (0)

/* Check if suppress start/restart of sessions to peer. */
#define BGP_PEER_START_SUPPRESSED(P)                                           \
	(CHECK_FLAG((P)->flags, PEER_FLAG_SHUTDOWN)                            \
	 || CHECK_FLAG((P)->sflags, PEER_STATUS_PREFIX_OVERFLOW))

#define PEER_PASSWORD_MINLEN	(1)
#define PEER_PASSWORD_MAXLEN	(80)

/* This structure's member directly points incoming packet data
   stream. */
struct bgp_nlri {
	/* AFI.  */
	uint16_t afi; /* iana_afi_t */

	/* SAFI.  */
	uint8_t safi; /* iana_safi_t */

	/* Pointer to NLRI byte stream.  */
	uint8_t *nlri;

	/* Length of whole NLRI.  */
	bgp_size_t length;
};

/* BGP versions.  */
#define BGP_VERSION_4		                 4

/* Default BGP port number.  */
#define BGP_PORT_DEFAULT                       179

/* BGP minimum message size.  */
#define BGP_MSG_OPEN_MIN_SIZE                   (BGP_HEADER_SIZE + 10)
#define BGP_MSG_UPDATE_MIN_SIZE                 (BGP_HEADER_SIZE + 4)
#define BGP_MSG_NOTIFY_MIN_SIZE                 (BGP_HEADER_SIZE + 2)
#define BGP_MSG_KEEPALIVE_MIN_SIZE              (BGP_HEADER_SIZE + 0)
#define BGP_MSG_ROUTE_REFRESH_MIN_SIZE          (BGP_HEADER_SIZE + 4)
#define BGP_MSG_CAPABILITY_MIN_SIZE             (BGP_HEADER_SIZE + 3)

/* BGP message types.  */
#define	BGP_MSG_OPEN		                 1
#define	BGP_MSG_UPDATE		                 2
#define	BGP_MSG_NOTIFY		                 3
#define	BGP_MSG_KEEPALIVE	                 4
#define BGP_MSG_ROUTE_REFRESH_NEW                5
#define BGP_MSG_CAPABILITY                       6
#define BGP_MSG_ROUTE_REFRESH_OLD              128

/* BGP open optional parameter.  */
#define BGP_OPEN_OPT_AUTH                        1
#define BGP_OPEN_OPT_CAP                         2

/* BGP4 attribute type codes.  */
#define BGP_ATTR_ORIGIN                          1
#define BGP_ATTR_AS_PATH                         2
#define BGP_ATTR_NEXT_HOP                        3
#define BGP_ATTR_MULTI_EXIT_DISC                 4
#define BGP_ATTR_LOCAL_PREF                      5
#define BGP_ATTR_ATOMIC_AGGREGATE                6
#define BGP_ATTR_AGGREGATOR                      7
#define BGP_ATTR_COMMUNITIES                     8
#define BGP_ATTR_ORIGINATOR_ID                   9
#define BGP_ATTR_CLUSTER_LIST                   10
#define BGP_ATTR_DPA                            11
#define BGP_ATTR_ADVERTISER                     12
#define BGP_ATTR_RCID_PATH                      13
#define BGP_ATTR_MP_REACH_NLRI                  14
#define BGP_ATTR_MP_UNREACH_NLRI                15
#define BGP_ATTR_EXT_COMMUNITIES                16
#define BGP_ATTR_AS4_PATH                       17
#define BGP_ATTR_AS4_AGGREGATOR                 18
#define BGP_ATTR_AS_PATHLIMIT                   21
#define BGP_ATTR_PMSI_TUNNEL                    22
#define BGP_ATTR_ENCAP                          23
#define BGP_ATTR_LARGE_COMMUNITIES              32
#define BGP_ATTR_PREFIX_SID                     40
#ifdef ENABLE_BGP_VNC_ATTR
#define BGP_ATTR_VNC                           255
#endif

/* BGP update origin.  */
#define BGP_ORIGIN_IGP                           0
#define BGP_ORIGIN_EGP                           1
#define BGP_ORIGIN_INCOMPLETE                    2
#define BGP_ORIGIN_UNSPECIFIED                 255

/* BGP notify message codes.  */
#define BGP_NOTIFY_HEADER_ERR                    1
#define BGP_NOTIFY_OPEN_ERR                      2
#define BGP_NOTIFY_UPDATE_ERR                    3
#define BGP_NOTIFY_HOLD_ERR                      4
#define BGP_NOTIFY_FSM_ERR                       5
#define BGP_NOTIFY_CEASE                         6
#define BGP_NOTIFY_CAPABILITY_ERR                7

/* Subcodes for BGP Finite State Machine Error */
#define BGP_NOTIFY_FSM_ERR_SUBCODE_UNSPECIFIC  0
#define BGP_NOTIFY_FSM_ERR_SUBCODE_OPENSENT    1
#define BGP_NOTIFY_FSM_ERR_SUBCODE_OPENCONFIRM 2
#define BGP_NOTIFY_FSM_ERR_SUBCODE_ESTABLISHED 3

#define BGP_NOTIFY_SUBCODE_UNSPECIFIC            0

/* BGP_NOTIFY_HEADER_ERR sub codes.  */
#define BGP_NOTIFY_HEADER_NOT_SYNC               1
#define BGP_NOTIFY_HEADER_BAD_MESLEN             2
#define BGP_NOTIFY_HEADER_BAD_MESTYPE            3

/* BGP_NOTIFY_OPEN_ERR sub codes.  */
#define BGP_NOTIFY_OPEN_MALFORMED_ATTR           0
#define BGP_NOTIFY_OPEN_UNSUP_VERSION            1
#define BGP_NOTIFY_OPEN_BAD_PEER_AS              2
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT            3
#define BGP_NOTIFY_OPEN_UNSUP_PARAM              4
#define BGP_NOTIFY_OPEN_AUTH_FAILURE             5
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME          6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL              7

/* BGP_NOTIFY_UPDATE_ERR sub codes.  */
#define BGP_NOTIFY_UPDATE_MAL_ATTR               1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR             2
#define BGP_NOTIFY_UPDATE_MISS_ATTR              3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR          4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR          5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN           6
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP          7
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP         8
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR           9
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK         10
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH           11

/* BGP_NOTIFY_CEASE sub codes (RFC 4486).  */
#define BGP_NOTIFY_CEASE_MAX_PREFIX              1
#define BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN          2
#define BGP_NOTIFY_CEASE_PEER_UNCONFIG           3
#define BGP_NOTIFY_CEASE_ADMIN_RESET             4
#define BGP_NOTIFY_CEASE_CONNECT_REJECT          5
#define BGP_NOTIFY_CEASE_CONFIG_CHANGE           6
#define BGP_NOTIFY_CEASE_COLLISION_RESOLUTION    7
#define BGP_NOTIFY_CEASE_OUT_OF_RESOURCE         8

/* BGP_NOTIFY_CAPABILITY_ERR sub codes (draft-ietf-idr-dynamic-cap-02). */
#define BGP_NOTIFY_CAPABILITY_INVALID_ACTION     1
#define BGP_NOTIFY_CAPABILITY_INVALID_LENGTH     2
#define BGP_NOTIFY_CAPABILITY_MALFORMED_CODE     3

/* BGP timers default value.  */
#define BGP_INIT_START_TIMER                     1
/* The following 3 are RFC defaults that are overridden in bgp_vty.c with
 * version-/profile-specific values.  The values here do not matter, they only
 * exist to provide a clear layering separation between core and CLI.
 */
#define BGP_DEFAULT_HOLDTIME                   180
#define BGP_DEFAULT_KEEPALIVE                   60
#define BGP_DEFAULT_CONNECT_RETRY              120

#define BGP_DEFAULT_EBGP_ROUTEADV                0
#define BGP_DEFAULT_IBGP_ROUTEADV                0

/* BGP default local preference.  */
#define BGP_DEFAULT_LOCAL_PREF                 100

/* BGP local-preference to send when 'bgp graceful-shutdown'
 * is configured */
#define BGP_GSHUT_LOCAL_PREF                     0

/* BGP default subgroup packet queue max .  */
#define BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX      40

/* BGP graceful restart  */
#define BGP_DEFAULT_RESTART_TIME               120
#define BGP_DEFAULT_STALEPATH_TIME             360
#define BGP_DEFAULT_SELECT_DEFERRAL_TIME       360
#define BGP_DEFAULT_RIB_STALE_TIME             500

/* BGP uptime string length.  */
#define BGP_UPTIME_LEN 25

/* Default configuration settings for bgpd.  */
#define BGP_VTY_PORT                          2605
#define BGP_DEFAULT_CONFIG             "bgpd.conf"

/* BGP Dynamic Neighbors feature */
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT    100
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_MIN          1
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_MAX       5000

/* Flag for peer_clear_soft().  */
enum bgp_clear_type {
	BGP_CLEAR_SOFT_NONE,
	BGP_CLEAR_SOFT_OUT,
	BGP_CLEAR_SOFT_IN,
	BGP_CLEAR_SOFT_BOTH,
	BGP_CLEAR_SOFT_IN_ORF_PREFIX
};

/* Macros. */
#define BGP_INPUT(P)         ((P)->curr)
#define BGP_INPUT_PNT(P)     (stream_pnt(BGP_INPUT(P)))
#define BGP_IS_VALID_STATE_FOR_NOTIF(S)                                        \
	(((S) == OpenSent) || ((S) == OpenConfirm) || ((S) == Established))

/* BGP error codes.  */
#define BGP_SUCCESS                               0
#define BGP_CREATED                               1
#define BGP_ERR_INVALID_VALUE                    -1
#define BGP_ERR_INVALID_FLAG                     -2
#define BGP_ERR_INVALID_AS                       -3
#define BGP_ERR_INVALID_BGP                      -4
#define BGP_ERR_PEER_GROUP_MEMBER                -5
#define BGP_ERR_PEER_GROUP_NO_REMOTE_AS          -7
#define BGP_ERR_PEER_GROUP_CANT_CHANGE           -8
#define BGP_ERR_PEER_GROUP_MISMATCH              -9
#define BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT  -10
#define BGP_ERR_AS_MISMATCH                     -12
#define BGP_ERR_PEER_FLAG_CONFLICT              -13
#define BGP_ERR_PEER_GROUP_SHUTDOWN             -14
#define BGP_ERR_PEER_FILTER_CONFLICT            -15
#define BGP_ERR_NOT_INTERNAL_PEER               -16
#define BGP_ERR_REMOVE_PRIVATE_AS               -17
#define BGP_ERR_AF_UNCONFIGURED                 -18
#define BGP_ERR_SOFT_RECONFIG_UNCONFIGURED      -19
#define BGP_ERR_INSTANCE_MISMATCH               -20
#define BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP  -21
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS    -22
#define BGP_ERR_TCPSIG_FAILED			-23
#define BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK	-24
#define BGP_ERR_NO_IBGP_WITH_TTLHACK		-25
#define BGP_ERR_NO_INTERFACE_CONFIG             -26
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS_REMOTE_AS    -27
#define BGP_ERR_AS_OVERRIDE                     -28
#define BGP_ERR_INVALID_DYNAMIC_NEIGHBORS_LIMIT -29
#define BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_EXISTS  -30
#define BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_NOT_FOUND -31
#define BGP_ERR_INVALID_FOR_DYNAMIC_PEER        -32
#define BGP_ERR_MAX                             -33
#define BGP_ERR_INVALID_FOR_DIRECT_PEER         -34
#define BGP_ERR_PEER_SAFI_CONFLICT              -35

/* BGP GR ERRORS */
#define BGP_ERR_GR_INVALID_CMD                  -36
#define BGP_ERR_GR_OPERATION_FAILED             -37
#define BGP_GR_NO_OPERATION                     -38

/*
 * Enumeration of different policy kinds a peer can be configured with.
 */
typedef enum {
	BGP_POLICY_ROUTE_MAP,
	BGP_POLICY_FILTER_LIST,
	BGP_POLICY_PREFIX_LIST,
	BGP_POLICY_DISTRIBUTE_LIST,
} bgp_policy_type_e;

/* peer_flag_change_type. */
enum peer_change_type {
	peer_change_none,
	peer_change_reset,
	peer_change_reset_in,
	peer_change_reset_out,
};

extern struct bgp_master *bm;
extern unsigned int multipath_num;

/* Prototypes. */
extern void bgp_terminate(void);
extern void bgp_reset(void);
extern time_t bgp_clock(void);
extern void bgp_zclient_reset(void);
extern struct bgp *bgp_get_default(void);
extern struct bgp *bgp_lookup(as_t, const char *);
extern struct bgp *bgp_lookup_by_name(const char *);
extern struct bgp *bgp_lookup_by_vrf_id(vrf_id_t);
extern struct bgp *bgp_get_evpn(void);
extern void bgp_set_evpn(struct bgp *bgp);
extern struct peer *peer_lookup(struct bgp *, union sockunion *);
extern struct peer *peer_lookup_by_conf_if(struct bgp *, const char *);
extern struct peer *peer_lookup_by_hostname(struct bgp *, const char *);
extern void bgp_peer_conf_if_to_su_update(struct peer *);
extern int peer_group_listen_range_del(struct peer_group *, struct prefix *);
extern struct peer_group *peer_group_lookup(struct bgp *, const char *);
extern struct peer_group *peer_group_get(struct bgp *, const char *);
extern struct peer *peer_create_bind_dynamic_neighbor(struct bgp *,
						      union sockunion *,
						      struct peer_group *);
extern struct prefix *
peer_group_lookup_dynamic_neighbor_range(struct peer_group *, struct prefix *);
extern struct peer_group *peer_group_lookup_dynamic_neighbor(struct bgp *,
							     struct prefix *,
							     struct prefix **);
extern struct peer *peer_lookup_dynamic_neighbor(struct bgp *,
						 union sockunion *);

/*
 * Peers are incredibly easy to memory leak
 * due to the various ways that they are actually used
 * Provide some functionality to debug locks and unlocks
 */
extern struct peer *peer_lock_with_caller(const char *, struct peer *);
extern struct peer *peer_unlock_with_caller(const char *, struct peer *);
#define peer_unlock(A) peer_unlock_with_caller(__FUNCTION__, (A))
#define peer_lock(B) peer_lock_with_caller(__FUNCTION__, (B))

extern bgp_peer_sort_t peer_sort(struct peer *peer);
extern bgp_peer_sort_t peer_sort_lookup(struct peer *peer);

extern bool peer_active(struct peer *);
extern bool peer_active_nego(struct peer *);
extern void bgp_recalculate_all_bestpaths(struct bgp *bgp);
extern struct peer *peer_create(union sockunion *, const char *, struct bgp *,
				as_t, as_t, int, afi_t, safi_t,
				struct peer_group *);
extern struct peer *peer_create_accept(struct bgp *);
extern void peer_xfer_config(struct peer *dst, struct peer *src);
extern char *peer_uptime(time_t uptime2, char *buf, size_t len, bool use_json,
			 json_object *json);

extern int bgp_config_write(struct vty *);

extern void bgp_master_init(struct thread_master *master,
			    const int buffer_size);

extern void bgp_init(unsigned short instance);
extern void bgp_pthreads_run(void);
extern void bgp_pthreads_finish(void);
extern void bgp_route_map_init(void);
extern void bgp_session_reset(struct peer *);

extern int bgp_option_set(int);
extern int bgp_option_unset(int);
extern int bgp_option_check(int);

extern int bgp_get(struct bgp **, as_t *, const char *, enum bgp_instance_type);
extern void bgp_instance_up(struct bgp *);
extern void bgp_instance_down(struct bgp *);
extern int bgp_delete(struct bgp *);

extern int bgp_handle_socket(struct bgp *bgp, struct vrf *vrf,
			     vrf_id_t old_vrf_id, bool create);

extern void bgp_router_id_zebra_bump(vrf_id_t, const struct prefix *);
extern void bgp_router_id_static_set(struct bgp *, struct in_addr);

extern int bgp_cluster_id_set(struct bgp *, struct in_addr *);
extern int bgp_cluster_id_unset(struct bgp *);

extern int bgp_confederation_id_set(struct bgp *, as_t);
extern int bgp_confederation_id_unset(struct bgp *);
extern bool bgp_confederation_peers_check(struct bgp *, as_t);

extern int bgp_confederation_peers_add(struct bgp *, as_t);
extern int bgp_confederation_peers_remove(struct bgp *, as_t);

extern void bgp_timers_set(struct bgp *, uint32_t keepalive, uint32_t holdtime,
			   uint32_t connect_retry);
extern void bgp_timers_unset(struct bgp *);

extern int bgp_default_local_preference_set(struct bgp *, uint32_t);
extern int bgp_default_local_preference_unset(struct bgp *);

extern int bgp_default_subgroup_pkt_queue_max_set(struct bgp *bgp, uint32_t);
extern int bgp_default_subgroup_pkt_queue_max_unset(struct bgp *bgp);

extern int bgp_listen_limit_set(struct bgp *, int);
extern int bgp_listen_limit_unset(struct bgp *);

extern bool bgp_update_delay_active(struct bgp *);
extern bool bgp_update_delay_configured(struct bgp *);
extern int bgp_afi_safi_peer_exists(struct bgp *bgp, afi_t afi, safi_t safi);
extern void peer_as_change(struct peer *, as_t, int);
extern int peer_remote_as(struct bgp *, union sockunion *, const char *, as_t *,
			  int, afi_t, safi_t);
extern int peer_group_remote_as(struct bgp *, const char *, as_t *, int);
extern int peer_delete(struct peer *peer);
extern void peer_notify_unconfig(struct peer *peer);
extern int peer_group_delete(struct peer_group *);
extern int peer_group_remote_as_delete(struct peer_group *);
extern int peer_group_listen_range_add(struct peer_group *, struct prefix *);
extern void peer_group_notify_unconfig(struct peer_group *group);

extern int peer_activate(struct peer *, afi_t, safi_t);
extern int peer_deactivate(struct peer *, afi_t, safi_t);
extern int peer_afc_set(struct peer *, afi_t, safi_t, int);

extern int peer_group_bind(struct bgp *, union sockunion *, struct peer *,
			   struct peer_group *, as_t *);

extern int peer_flag_set(struct peer *, uint32_t);
extern int peer_flag_unset(struct peer *, uint32_t);
extern void peer_flag_inherit(struct peer *peer, uint32_t flag);

extern int peer_af_flag_set(struct peer *, afi_t, safi_t, uint32_t);
extern int peer_af_flag_unset(struct peer *, afi_t, safi_t, uint32_t);
extern int peer_af_flag_check(struct peer *, afi_t, safi_t, uint32_t);
extern void peer_af_flag_inherit(struct peer *peer, afi_t afi, safi_t safi,
				 uint32_t flag);
extern void peer_change_action(struct peer *peer, afi_t afi, safi_t safi,
			       enum peer_change_type type);

extern int peer_ebgp_multihop_set(struct peer *, int);
extern int peer_ebgp_multihop_unset(struct peer *);
extern int is_ebgp_multihop_configured(struct peer *peer);

extern void peer_description_set(struct peer *, const char *);
extern void peer_description_unset(struct peer *);

extern int peer_update_source_if_set(struct peer *, const char *);
extern int peer_update_source_addr_set(struct peer *, const union sockunion *);
extern int peer_update_source_unset(struct peer *);

extern int peer_default_originate_set(struct peer *peer, afi_t afi, safi_t safi,
				      const char *rmap,
				      struct route_map *route_map);
extern int peer_default_originate_unset(struct peer *, afi_t, safi_t);

extern void peer_port_set(struct peer *, uint16_t);
extern void peer_port_unset(struct peer *);

extern int peer_weight_set(struct peer *, afi_t, safi_t, uint16_t);
extern int peer_weight_unset(struct peer *, afi_t, safi_t);

extern int peer_timers_set(struct peer *, uint32_t keepalive,
			   uint32_t holdtime);
extern int peer_timers_unset(struct peer *);

extern int peer_timers_connect_set(struct peer *, uint32_t);
extern int peer_timers_connect_unset(struct peer *);

extern int peer_advertise_interval_set(struct peer *, uint32_t);
extern int peer_advertise_interval_unset(struct peer *);

extern void peer_interface_set(struct peer *, const char *);
extern void peer_interface_unset(struct peer *);

extern int peer_distribute_set(struct peer *, afi_t, safi_t, int, const char *);
extern int peer_distribute_unset(struct peer *, afi_t, safi_t, int);

extern int peer_allowas_in_set(struct peer *, afi_t, safi_t, int, int);
extern int peer_allowas_in_unset(struct peer *, afi_t, safi_t);

extern int peer_local_as_set(struct peer *, as_t, int, int);
extern int peer_local_as_unset(struct peer *);

extern int peer_prefix_list_set(struct peer *, afi_t, safi_t, int,
				const char *);
extern int peer_prefix_list_unset(struct peer *, afi_t, safi_t, int);

extern int peer_aslist_set(struct peer *, afi_t, safi_t, int, const char *);
extern int peer_aslist_unset(struct peer *, afi_t, safi_t, int);

extern int peer_route_map_set(struct peer *peer, afi_t afi, safi_t safi, int,
			      const char *name, struct route_map *route_map);
extern int peer_route_map_unset(struct peer *, afi_t, safi_t, int);

extern int peer_unsuppress_map_set(struct peer *peer, afi_t afi, safi_t safi,
				   const char *name,
				   struct route_map *route_map);

extern int peer_password_set(struct peer *, const char *);
extern int peer_password_unset(struct peer *);

extern int peer_unsuppress_map_unset(struct peer *, afi_t, safi_t);

extern int peer_maximum_prefix_set(struct peer *, afi_t, safi_t, uint32_t,
				   uint8_t, int, uint16_t);
extern int peer_maximum_prefix_unset(struct peer *, afi_t, safi_t);

extern int peer_clear(struct peer *, struct listnode **);
extern int peer_clear_soft(struct peer *, afi_t, safi_t, enum bgp_clear_type);

extern int peer_ttl_security_hops_set(struct peer *, int);
extern int peer_ttl_security_hops_unset(struct peer *);

extern void peer_tx_shutdown_message_set(struct peer *, const char *msg);
extern void peer_tx_shutdown_message_unset(struct peer *);

extern int bgp_route_map_update_timer(struct thread *thread);
extern void bgp_route_map_terminate(void);

extern int peer_cmp(struct peer *p1, struct peer *p2);

extern int bgp_map_afi_safi_iana2int(iana_afi_t pkt_afi, iana_safi_t pkt_safi,
				     afi_t *afi, safi_t *safi);
extern int bgp_map_afi_safi_int2iana(afi_t afi, safi_t safi,
				     iana_afi_t *pkt_afi,
				     iana_safi_t *pkt_safi);

extern struct peer_af *peer_af_create(struct peer *, afi_t, safi_t);
extern struct peer_af *peer_af_find(struct peer *, afi_t, safi_t);
extern int peer_af_delete(struct peer *, afi_t, safi_t);

extern void bgp_close(void);
extern void bgp_free(struct bgp *);
void bgp_gr_apply_running_config(void);

/* BGP GR */
int bgp_global_gr_init(struct bgp *bgp);
int bgp_peer_gr_init(struct peer *peer);


#define BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(_bgp, _peer_list)    \
	do {                                                                   \
		struct peer *peer_loop;                                        \
		bool gr_router_detected = false;                               \
		struct listnode *node = {0};                                   \
		for (ALL_LIST_ELEMENTS_RO(_peer_list, node, peer_loop)) {      \
			if (CHECK_FLAG(peer_loop->flags,                       \
				       PEER_FLAG_GRACEFUL_RESTART))            \
				gr_router_detected = true;                     \
		}                                                              \
		if (gr_router_detected                                         \
		    && _bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {     \
			bgp_zebra_send_capabilities(_bgp, false);              \
		} else if (!gr_router_detected                                 \
			   && _bgp->present_zebra_gr_state                     \
				      == ZEBRA_GR_ENABLE) {                    \
			bgp_zebra_send_capabilities(_bgp, true);               \
		}                                                              \
	} while (0)

static inline struct bgp *bgp_lock(struct bgp *bgp)
{
	bgp->lock++;
	return bgp;
}

static inline void bgp_unlock(struct bgp *bgp)
{
	assert(bgp->lock > 0);
	if (--bgp->lock == 0)
		bgp_free(bgp);
}

static inline int afindex(afi_t afi, safi_t safi)
{
	switch (afi) {
	case AFI_IP:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_AF_IPV4_UNICAST;
		case SAFI_MULTICAST:
			return BGP_AF_IPV4_MULTICAST;
		case SAFI_LABELED_UNICAST:
			return BGP_AF_IPV4_LBL_UNICAST;
		case SAFI_MPLS_VPN:
			return BGP_AF_IPV4_VPN;
		case SAFI_ENCAP:
			return BGP_AF_IPV4_ENCAP;
		case SAFI_FLOWSPEC:
			return BGP_AF_IPV4_FLOWSPEC;
		default:
			return BGP_AF_MAX;
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_AF_IPV6_UNICAST;
		case SAFI_MULTICAST:
			return BGP_AF_IPV6_MULTICAST;
		case SAFI_LABELED_UNICAST:
			return BGP_AF_IPV6_LBL_UNICAST;
		case SAFI_MPLS_VPN:
			return BGP_AF_IPV6_VPN;
		case SAFI_ENCAP:
			return BGP_AF_IPV6_ENCAP;
		case SAFI_FLOWSPEC:
			return BGP_AF_IPV6_FLOWSPEC;
		default:
			return BGP_AF_MAX;
		}
		break;
	case AFI_L2VPN:
		switch (safi) {
		case SAFI_EVPN:
			return BGP_AF_L2VPN_EVPN;
		default:
			return BGP_AF_MAX;
		}
	default:
		return BGP_AF_MAX;
	}
}

/* If the peer is not a peer-group but is bound to a peer-group return 1 */
static inline int peer_group_active(struct peer *peer)
{
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP) && peer->group)
		return 1;
	return 0;
}

/* If peer is negotiated at least one address family return 1. */
static inline int peer_afi_active_nego(const struct peer *peer, afi_t afi)
{
	if (peer->afc_nego[afi][SAFI_UNICAST]
	    || peer->afc_nego[afi][SAFI_MULTICAST]
	    || peer->afc_nego[afi][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[afi][SAFI_MPLS_VPN]
	    || peer->afc_nego[afi][SAFI_ENCAP]
	    || peer->afc_nego[afi][SAFI_FLOWSPEC]
	    || peer->afc_nego[afi][SAFI_EVPN])
		return 1;
	return 0;
}

/* If at least one address family activated for group, return 1. */
static inline int peer_group_af_configured(struct peer_group *group)
{
	struct peer *peer = group->conf;

	if (peer->afc[AFI_IP][SAFI_UNICAST] || peer->afc[AFI_IP][SAFI_MULTICAST]
	    || peer->afc[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP][SAFI_FLOWSPEC]
	    || peer->afc[AFI_IP][SAFI_MPLS_VPN] || peer->afc[AFI_IP][SAFI_ENCAP]
	    || peer->afc[AFI_IP6][SAFI_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc[AFI_IP6][SAFI_ENCAP]
	    || peer->afc[AFI_IP6][SAFI_FLOWSPEC]
	    || peer->afc[AFI_L2VPN][SAFI_EVPN])
		return 1;
	return 0;
}

static inline char *timestamp_string(time_t ts)
{
	time_t tbuf;
	tbuf = time(NULL) - (bgp_clock() - ts);
	return ctime(&tbuf);
}

static inline int peer_established(struct peer *peer)
{
	if (peer->status == Established)
		return 1;
	return 0;
}

static inline int peer_dynamic_neighbor(struct peer *peer)
{
	return (CHECK_FLAG(peer->flags, PEER_FLAG_DYNAMIC_NEIGHBOR)) ? 1 : 0;
}

static inline int peer_cap_enhe(struct peer *peer, afi_t afi, safi_t safi)
{
	return (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ENHE_AF_NEGO));
}

/* Lookup VRF for BGP instance based on its type. */
static inline struct vrf *bgp_vrf_lookup_by_instance_type(struct bgp *bgp)
{
	struct vrf *vrf;

	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	else if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		vrf = vrf_lookup_by_name(bgp->name);
	else
		vrf = NULL;

	return vrf;
}

/* Link BGP instance to VRF. */
static inline void bgp_vrf_link(struct bgp *bgp, struct vrf *vrf)
{
	bgp->vrf_id = vrf->vrf_id;
	if (vrf->info != (void *)bgp)
		vrf->info = (void *)bgp_lock(bgp);
}

/* Unlink BGP instance from VRF. */
static inline void bgp_vrf_unlink(struct bgp *bgp, struct vrf *vrf)
{
	if (vrf->info == (void *)bgp) {
		vrf->info = NULL;
		bgp_unlock(bgp);
	}
	bgp->vrf_id = VRF_UNKNOWN;
}

extern void bgp_unset_redist_vrf_bitmaps(struct bgp *, vrf_id_t);

/* For benefit of rfapi */
extern struct peer *peer_new(struct bgp *bgp);

extern struct peer *peer_lookup_in_view(struct vty *vty, struct bgp *bgp,
					const char *ip_str, bool use_json);

/* Hooks */
DECLARE_HOOK(peer_status_changed, (struct peer * peer), (peer))
void peer_nsf_stop(struct peer *peer);

#endif /* _QUAGGA_BGPD_H */
