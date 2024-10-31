// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP message definition header.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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
#include "srv6.h"
#include "iana_afi.h"
#include "asn.h"

PREDECL_LIST(zebra_announce);

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
#include "bgp_nexthop.h"
#include "bgp_io.h"
#include "bgp_damp.h"

#include "lib/bfd.h"

DECLARE_HOOK(bgp_hook_config_write_vrf, (struct vty *vty, struct vrf *vrf),
	     (vty, vrf));

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
enum peer_asn_type {
	AS_UNSPECIFIED = 1,
	AS_SPECIFIED = 2,
	AS_INTERNAL = 4,
	AS_EXTERNAL = 8,
	AS_AUTO = 16,
};

/* Zebra Gracaful Restart states */
enum zebra_gr_mode {
	ZEBRA_GR_DISABLE = 0,
	ZEBRA_GR_ENABLE
};

/* Typedef BGP specific types.  */
typedef uint16_t as16_t; /* we may still encounter 16 Bit asnums */
typedef uint16_t bgp_size_t;

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

#define FOREACH_SAFI(safi)                                            \
	for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

extern struct frr_pthread *bgp_pth_io;
extern struct frr_pthread *bgp_pth_ka;

/* BGP master for system wide configurations and variables.  */
struct bgp_master {
	/* BGP instance list.  */
	struct list *bgp;

	/* BGP thread master.  */
	struct event_loop *master;

	/* Listening sockets */
	struct list *listen_sockets;

	/* BGP port number.  */
	uint16_t port;

	/* Listener addresses */
	struct list *addresses;

	/* The Mac table */
	struct hash *self_mac_hash;

	/* BGP start time.  */
	time_t start_time;

	/* Various BGP global configuration.  */
	uint8_t options;

#define BGP_OPT_NO_FIB                   (1 << 0)
#define BGP_OPT_NO_LISTEN                (1 << 1)
#define BGP_OPT_NO_ZEBRA                 (1 << 2)
#define BGP_OPT_TRAPS_RFC4273            (1 << 3)
#define BGP_OPT_TRAPS_BGP4MIBV2          (1 << 4)
#define BGP_OPT_TRAPS_RFC4382		 (1 << 5)

	uint64_t updgrp_idspace;
	uint64_t subgrp_idspace;

	/* timer to dampen route map changes */
	struct event *t_rmap_update; /* Handle route map updates */
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

	/* Should we do wait for fib install globally? */
	bool wait_for_fib;

	/* EVPN multihoming */
	struct bgp_evpn_mh_info *mh_info;

	/* global update-delay timer values */
	uint16_t v_update_delay;
	uint16_t v_establish_wait;

	uint32_t flags;
#define BM_FLAG_GRACEFUL_SHUTDOWN        (1 << 0)
#define BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA (1 << 1)
#define BM_FLAG_MAINTENANCE_MODE	 (1 << 2)
#define BM_FLAG_GR_RESTARTER		 (1 << 3)
#define BM_FLAG_GR_DISABLED		 (1 << 4)
#define BM_FLAG_GR_PRESERVE_FWD		 (1 << 5)
#define BM_FLAG_GRACEFUL_RESTART	 (1 << 6)
#define BM_FLAG_GR_COMPLETE		 (1 << 7)
#define BM_FLAG_IPV6_NO_AUTO_RA		 (1 << 8)

#define BM_FLAG_GR_CONFIGURED (BM_FLAG_GR_RESTARTER | BM_FLAG_GR_DISABLED)

	/* BGP-wide graceful restart config params */
	uint32_t restart_time;
	uint32_t stalepath_time;
	uint32_t select_defer_time;
	uint32_t rib_stale_time;

	time_t startup_time;
	time_t gr_completion_time;

	bool terminating;	/* global flag that sigint terminate seen */

	/* TOS value for outgoing packets in BGP connections */
	uint8_t ip_tos;

#define BM_DEFAULT_Q_LIMIT 10000
	uint32_t inq_limit;
	uint32_t outq_limit;

	struct event *t_bgp_sync_label_manager;
	struct event *t_bgp_start_label_manager;

	struct event *t_bgp_zebra_route;

	bool v6_with_v4_nexthops;

	/* To preserve ordering of installations into zebra across all Vrfs */
	struct zebra_announce_head zebra_announce_head;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(bgp_master);

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

enum vpn_policy_direction {
	BGP_VPN_POLICY_DIR_FROMVPN = 0,
	BGP_VPN_POLICY_DIR_TOVPN = 1,
	BGP_VPN_POLICY_DIR_MAX = 2
};

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
	char *tovpn_rd_pretty;
	struct prefix_rd tovpn_rd;
	struct prefix tovpn_nexthop; /* unset => set to 0 */
	uint32_t flags;
#define BGP_VPN_POLICY_TOVPN_LABEL_AUTO        (1 << 0)
#define BGP_VPN_POLICY_TOVPN_RD_SET            (1 << 1)
#define BGP_VPN_POLICY_TOVPN_NEXTHOP_SET       (1 << 2)
#define BGP_VPN_POLICY_TOVPN_SID_AUTO          (1 << 3)
#define BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP (1 << 4)
/* Manual label is registered with zebra label manager */
#define BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG (1 << 5)

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

	/*
	 * Segment-Routing SRv6 Mode
	 */
	uint32_t tovpn_sid_index; /* unset => set to 0 */
	struct in6_addr *tovpn_sid;
	struct srv6_locator *tovpn_sid_locator;
	uint32_t tovpn_sid_transpose_label;
	struct in6_addr *tovpn_zebra_vrf_sid_last_sent;
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
	struct event *t_select_deferral;
	/* Routes Deferred */
	uint32_t gr_deferred;
	/* Best route select */
	struct event *t_route_select;
	/* AFI, SAFI enabled */
	bool af_enabled;
	/* Route update completed */
	bool route_sync;
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

RB_HEAD(bgp_es_vrf_rb_head, bgp_evpn_es_vrf);
RB_PROTOTYPE(bgp_es_vrf_rb_head, bgp_evpn_es_vrf, rb_node, bgp_es_vrf_rb_cmp);

struct bgp_snmp_stats {
	/* SNMP variables for mplsL3Vpn*/
	time_t creation_time;
	time_t modify_time;
	bool active;
	uint32_t routes_added;
	uint32_t routes_deleted;
};

struct bgp_srv6_function {
	struct in6_addr sid;
	char locator_name[SRV6_LOCNAME_SIZE];
};

struct as_confed {
	as_t as;
	char *as_pretty;
};

struct bgp_mplsvpn_nh_label_bind_cache;
PREDECL_RBTREE_UNIQ(bgp_mplsvpn_nh_label_bind_cache);

/* BGP instance structure.  */
struct bgp {
	/* AS number of this BGP instance.  */
	as_t as;
	char *as_pretty;

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

	struct bgp_snmp_stats *snmp_stats;

	/* BGP configuration.  */
	uint16_t config;
#define BGP_CONFIG_CLUSTER_ID             (1 << 0)
#define BGP_CONFIG_CONFEDERATION          (1 << 1)
#define BGP_CONFIG_ASNOTATION             (1 << 2)

	/* BGP router identifier.  */
	struct in_addr router_id;
	struct in_addr router_id_static;
	struct in_addr router_id_zebra;

	/* BGP route reflector cluster ID.  */
	struct in_addr cluster_id;

	/* BGP confederation information.  */
	as_t confed_id;
	char *confed_id_pretty;
	struct as_confed *confed_peers;
	int confed_peers_cnt;

	/* start-up timer on only once at the beginning */
	struct event *t_startup;

	uint32_t v_maxmed_onstartup; /* Duration of max-med on start-up */
#define BGP_MAXMED_ONSTARTUP_UNCONFIGURED  0 /* 0 means off, its the default */
	uint32_t maxmed_onstartup_value;     /* Max-med value when active on
						 start-up */

	/* non-null when max-med onstartup is on */
	struct event *t_maxmed_onstartup;
	uint8_t maxmed_onstartup_over; /* Flag to make it effective only once */

	bool v_maxmed_admin; /* true/false if max-med administrative is on/off
			      */
#define BGP_MAXMED_ADMIN_UNCONFIGURED false /* Off by default */
	uint32_t maxmed_admin_value; /* Max-med value when administrative in on
				      */
#define BGP_MAXMED_VALUE_DEFAULT  4294967294 /* Maximum by default */

	uint8_t maxmed_active; /* 1/0 if max-med is active or not */
	uint32_t maxmed_value; /* Max-med value when its active */

	/* BGP update delay on startup */
	struct event *t_update_delay;
	struct event *t_establish_wait;
	struct event *t_revalidate[AFI_MAX][SAFI_MAX];

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
#define BGP_UPDATE_DELAY_DEFAULT 0

	/* Reference bandwidth for BGP link-bandwidth. Used when
	 * the LB value has to be computed based on some other
	 * factor (e.g., number of multipaths for the prefix)
	 * Value is in Mbps
	 */
	uint64_t lb_ref_bw;
#define BGP_LINK_BW_REF_BW                1

	/* BGP flags. */
	uint64_t flags;
#define BGP_FLAG_ALWAYS_COMPARE_MED (1ULL << 0)
#define BGP_FLAG_DETERMINISTIC_MED (1ULL << 1)
#define BGP_FLAG_MED_MISSING_AS_WORST (1ULL << 2)
#define BGP_FLAG_MED_CONFED (1ULL << 3)
#define BGP_FLAG_NO_CLIENT_TO_CLIENT (1ULL << 4)
#define BGP_FLAG_COMPARE_ROUTER_ID (1ULL << 5)
#define BGP_FLAG_ASPATH_IGNORE (1ULL << 6)
#define BGP_FLAG_IMPORT_CHECK (1ULL << 7)
#define BGP_FLAG_NO_FAST_EXT_FAILOVER (1ULL << 8)
#define BGP_FLAG_LOG_NEIGHBOR_CHANGES (1ULL << 9)

/* This flag is set when we have full BGP Graceful-Restart mode enable */
#define BGP_FLAG_GRACEFUL_RESTART (1ULL << 10)

#define BGP_FLAG_ASPATH_CONFED (1ULL << 11)
#define BGP_FLAG_ASPATH_MULTIPATH_RELAX (1ULL << 12)
#define BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY (1ULL << 13)
#define BGP_FLAG_DISABLE_NH_CONNECTED_CHK (1ULL << 14)
#define BGP_FLAG_MULTIPATH_RELAX_AS_SET (1ULL << 15)
#define BGP_FLAG_FORCE_STATIC_PROCESS (1ULL << 16)
#define BGP_FLAG_SHOW_HOSTNAME (1ULL << 17)
#define BGP_FLAG_GR_PRESERVE_FWD (1ULL << 18)
#define BGP_FLAG_GRACEFUL_SHUTDOWN (1ULL << 19)
#define BGP_FLAG_DELETE_IN_PROGRESS (1ULL << 20)
#define BGP_FLAG_SELECT_DEFER_DISABLE (1ULL << 21)
#define BGP_FLAG_GR_DISABLE_EOR (1ULL << 22)
#define BGP_FLAG_EBGP_REQUIRES_POLICY (1ULL << 23)
#define BGP_FLAG_SHOW_NEXTHOP_HOSTNAME (1ULL << 24)

/* This flag is set if the instance is in administrative shutdown */
#define BGP_FLAG_SHUTDOWN (1ULL << 25)
#define BGP_FLAG_SUPPRESS_FIB_PENDING (1ULL << 26)
#define BGP_FLAG_SUPPRESS_DUPLICATES (1ULL << 27)
#define BGP_FLAG_PEERTYPE_MULTIPATH_RELAX (1ULL << 29)
/* Indicate Graceful Restart support for BGP NOTIFICATION messages */
#define BGP_FLAG_GRACEFUL_NOTIFICATION (1ULL << 30)
/* Send Hard Reset CEASE Notification for 'Administrative Reset' */
#define BGP_FLAG_HARD_ADMIN_RESET (1ULL << 31)
/* Evaluate the AIGP attribute during the best path selection process */
#define BGP_FLAG_COMPARE_AIGP (1ULL << 32)
/* For BGP-LU, force IPv4 local prefixes to use ipv4-explicit-null label */
#define BGP_FLAG_LU_IPV4_EXPLICIT_NULL (1ULL << 33)
/* For BGP-LU, force IPv6 local prefixes to use ipv6-explicit-null label */
#define BGP_FLAG_LU_IPV6_EXPLICIT_NULL (1ULL << 34)
#define BGP_FLAG_SOFT_VERSION_CAPABILITY (1ULL << 35)
#define BGP_FLAG_ENFORCE_FIRST_AS (1ULL << 36)
#define BGP_FLAG_DYNAMIC_CAPABILITY (1ULL << 37)
#define BGP_FLAG_VNI_DOWN		 (1ULL << 38)
#define BGP_FLAG_INSTANCE_HIDDEN	 (1ULL << 39)
/* Prohibit BGP from enabling IPv6 RA on interfaces */
#define BGP_FLAG_IPV6_NO_AUTO_RA (1ULL << 40)

	/* BGP default address-families.
	 * New peers inherit enabled afi/safis from bgp instance.
	 */
	uint16_t default_af[AFI_MAX][SAFI_MAX];

	enum global_mode GLOBAL_GR_FSM[BGP_GLOBAL_GR_MODE]
				      [BGP_GLOBAL_GR_EVENT_CMD];
	enum global_mode global_gr_present_state;

	/* This variable stores the current Graceful Restart state of Zebra
	 * - ZEBRA_GR_ENABLE / ZEBRA_GR_DISABLE
	 */
	enum zebra_gr_mode present_zebra_gr_state;

	/* Is deferred path selection still not complete? */
	bool gr_route_sync_pending;

	/* BGP Per AF flags */
	uint16_t af_flags[AFI_MAX][SAFI_MAX];
#define BGP_CONFIG_DAMPENING				(1 << 0)
/* l2vpn evpn flags - 1 << 0 is used for DAMPENNG */
#define BGP_L2VPN_EVPN_ADV_IPV4_UNICAST (1 << 1)
#define BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP (1 << 2)
#define BGP_L2VPN_EVPN_ADV_IPV6_UNICAST (1 << 3)
#define BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP (1 << 4)
#define BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4 (1 << 5)
#define BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6 (1 << 6)
/* import/export between address families */
#define BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT (1 << 7)
#define BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT (1 << 8)
/* vrf-route leaking flags */
#define BGP_CONFIG_VRF_TO_VRF_IMPORT (1 << 9)
#define BGP_CONFIG_VRF_TO_VRF_EXPORT (1 << 10)
/* vpnvx retain flag */
#define BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL (1 << 11)

	/* BGP per AF peer count */
	uint32_t af_peer_count[AFI_MAX][SAFI_MAX];

	/* Tree for next-hop lookup cache. */
	struct bgp_nexthop_cache_head nexthop_cache_table[AFI_MAX];

	/* Tree for import-check */
	struct bgp_nexthop_cache_head import_check_table[AFI_MAX];

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

	/* Tree for next-hop lookup cache. */
	struct bgp_label_per_nexthop_cache_head
		mpls_labels_per_nexthop[AFI_MAX];

	/* Tree for mplsvpn next-hop label bind cache */
	struct bgp_mplsvpn_nh_label_bind_cache_head mplsvpn_nh_label_bind;

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
	struct event *t_rmap_def_originate_eval;
	uint16_t rmap_def_originate_eval_timer;
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
	uint32_t default_delayopen;

	/* BGP minimum holdtime.  */
	uint16_t default_min_holdtime;

	/* BGP graceful restart */
	uint32_t restart_time;
	uint32_t stalepath_time;
	uint32_t select_defer_time;
	struct graceful_restart_info gr_info[AFI_MAX][SAFI_MAX];
	uint32_t rib_stale_time;

	/* BGP Long-lived Graceful Restart */
	uint32_t llgr_stale_time;

#define BGP_ROUTE_SELECT_DELAY 1
#define BGP_MAX_BEST_ROUTE_SELECT 10000
	/* Maximum-paths configuration */
	struct bgp_maxpaths_cfg {
		uint16_t maxpaths_ebgp;
		uint16_t maxpaths_ibgp;
		bool same_clusterlen;
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

	/*
	 * VNI hash table based on SVI ifindex as its key.
	 * We use SVI ifindex as key to lookup a VNI table for gateway IP
	 * overlay index recursive lookup.
	 * For this purpose, a hashtable is added which optimizes this lookup.
	 */
	struct hash *vni_svi_hash;

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

	/* RB tree of ES-VRFs */
	struct bgp_es_vrf_rb_head es_vrf_rb_tree;

	/* Hash table of EVPN nexthops maintained per-tenant-VRF */
	struct hash *evpn_nh_table;

	/*
	 * Flag resolve_overlay_index is used for recursive resolution
	 * procedures for EVPN type-5 route's gateway IP overlay index.
	 * When this flag is set, we build remote-ip-hash for
	 * all L2VNIs and resolve overlay index nexthops using this hash.
	 * Overlay index nexthops remain unresolved if this flag is not set.
	 */
	bool resolve_overlay_index;

	/* vrf flags */
	uint32_t vrf_flags;
#define BGP_VRF_AUTO                        (1 << 0)
#define BGP_VRF_IMPORT_RT_CFGD              (1 << 1)
#define BGP_VRF_EXPORT_RT_CFGD              (1 << 2)
#define BGP_VRF_IMPORT_AUTO_RT_CFGD         (1 << 3) /* retain auto when cfgd */
#define BGP_VRF_EXPORT_AUTO_RT_CFGD         (1 << 4) /* retain auto when cfgd */
#define BGP_VRF_RD_CFGD                     (1 << 5)
#define BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY    (1 << 6)
/* per-VRF toVPN SID */
#define BGP_VRF_TOVPN_SID_AUTO              (1 << 7)

	/* unique ID for auto derivation of RD for this vrf */
	uint16_t vrf_rd_id;

	/* Automatically derived RD for this VRF */
	struct prefix_rd vrf_prd_auto;

	/* RD for this VRF */
	struct prefix_rd vrf_prd;
	char *vrf_prd_pretty;

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

	/* Process Queue for handling routes */
	struct work_queue *process_queue;

	bool fast_convergence;

	/* BGP Conditional advertisement */
	uint32_t condition_check_period;
	uint32_t condition_filter_count;
	struct event *t_condition_check;

	/* BGP VPN SRv6 backend */
	bool srv6_enabled;
	char srv6_locator_name[SRV6_LOCNAME_SIZE];
	struct srv6_locator *srv6_locator;
	struct list *srv6_locator_chunks;
	struct list *srv6_functions;
	uint32_t tovpn_sid_index; /* unset => set to 0 */
	struct in6_addr *tovpn_sid;
	struct srv6_locator *tovpn_sid_locator;
	uint32_t tovpn_sid_transpose_label;
	struct in6_addr *tovpn_zebra_vrf_sid_last_sent;

	/* TCP keepalive parameters for BGP connection */
	uint16_t tcp_keepalive_idle;
	uint16_t tcp_keepalive_intvl;
	uint16_t tcp_keepalive_probes;

	struct timeval ebgprequirespolicywarning;
#define FIFTEENMINUTE2USEC (int64_t)15 * 60 * 1000000

	bool allow_martian;

	enum asnotation_mode asnotation;

	/* BGP route flap dampening configuration */
	struct bgp_damp_config damp[AFI_MAX][SAFI_MAX];

	uint64_t bestpath_runs;
	uint64_t node_already_on_queue;
	uint64_t node_deferred_on_queue;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(bgp);

struct bgp_interface {
#define BGP_INTERFACE_MPLS_BGP_FORWARDING (1 << 0)
/* L3VPN multi domain switching */
#define BGP_INTERFACE_MPLS_L3VPN_SWITCHING (1 << 1)
	uint32_t flags;
};

DECLARE_HOOK(bgp_inst_delete, (struct bgp *bgp), (bgp));
DECLARE_HOOK(bgp_inst_config_write,
		(struct bgp *bgp, struct vty *vty),
		(bgp, vty));
DECLARE_HOOK(bgp_snmp_traps_config_write, (struct vty *vty), (vty));
DECLARE_HOOK(bgp_config_end, (struct bgp *bgp), (bgp));
DECLARE_HOOK(bgp_hook_vrf_update, (struct vrf *vrf, bool enabled),
	     (vrf, enabled));
DECLARE_HOOK(bgp_instance_state, (struct bgp *bgp), (bgp));

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

#define BGP_SUPPRESS_FIB_ENABLED(bgp)                                          \
	(CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING)                 \
	 || bm->wait_for_fib)

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
	bgp_size_t length;
	bool hard_reset;
	char *data;
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

/* Advertise map */
#define CONDITION_NON_EXIST	false
#define CONDITION_EXIST		true

enum update_type { UPDATE_TYPE_WITHDRAW, UPDATE_TYPE_ADVERTISE };

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

	/* Advertise-map */
	struct {
		char *aname;
		struct route_map *amap;

		bool condition;

		char *cname;
		struct route_map *cmap;

		enum update_type update_type;
	} advmap;
};

/* IBGP/EBGP identifier.  We also have a CONFED peer, which is to say,
   a peer who's AS is part of our Confederation.  */
enum bgp_peer_sort {
	BGP_PEER_UNSPECIFIED,
	BGP_PEER_IBGP,
	BGP_PEER_EBGP,
	BGP_PEER_INTERNAL,
	BGP_PEER_CONFED,
};

/* BGP peering sub-types
 * E.g.:
 * EBGP-OAD - https://datatracker.ietf.org/doc/html/draft-uttaro-idr-bgp-oad
 */
enum bgp_peer_sub_sort {
	BGP_PEER_EBGP_OAD = 1,
};

/* BGP message header and packet size.  */
#define BGP_MARKER_SIZE		                16
#define BGP_HEADER_SIZE		                19
#define BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE 4096
#define BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE 65535
#define BGP_MAX_PACKET_SIZE BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE
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
	struct event *t_announce_route;

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

typedef unsigned int (*bgp_peer_gr_action_ptr)(struct peer *, enum peer_mode,
					       enum peer_mode);

struct bgp_peer_gr {
	enum peer_mode next_state;
	bgp_peer_gr_action_ptr action_fun;
};

/*
 * BGP FSM event codes, per RFC 4271 ss. 8.1
 */
enum bgp_fsm_rfc_codes {
	BGP_FSM_ManualStart = 1,
	BGP_FSM_ManualStop = 2,
	BGP_FSM_AutomaticStart = 3,
	BGP_FSM_ManualStart_with_PassiveTcpEstablishment = 4,
	BGP_FSM_AutomaticStart_with_PassiveTcpEstablishment = 5,
	BGP_FSM_AutomaticStart_with_DampPeerOscillations = 6,
	BGP_FSM_AutomaticStart_with_DampPeerOscillations_and_PassiveTcpEstablishment =
		7,
	BGP_FSM_AutomaticStop = 8,
	BGP_FSM_ConnectRetryTimer_Expires = 9,
	BGP_FSM_HoldTimer_Expires = 10,
	BGP_FSM_KeepaliveTimer_Expires = 11,
	BGP_FSM_DelayOpenTimer_Expires = 12,
	BGP_FSM_IdleHoldTimer_Expires = 13,
	BGP_FSM_TcpConnection_Valid = 14,
	BGP_FSM_Tcp_CR_Invalid = 15,
	BGP_FSM_Tcp_CR_Acked = 16,
	BGP_FSM_TcpConnectionConfirmed = 17,
	BGP_FSM_TcpConnectionFails = 18,
	BGP_FSM_BGPOpen = 19,
	BGP_FSM_BGPOpen_with_DelayOpenTimer_running = 20,
	BGP_FSM_BGPHeaderErr = 21,
	BGP_FSM_BGPOpenMsgErr = 22,
	BGP_FSM_OpenCollisionDump = 23,
	BGP_FSM_NotifMsgVerErr = 24,
	BGP_FSM_NotifMsg = 25,
	BGP_FSM_KeepAliveMsg = 26,
	BGP_FSM_UpdateMsg = 27,
	BGP_FSM_UpdateMsgErr = 28
};

/*
 * BGP finite state machine events
 *
 * Note: these do not correspond to RFC-defined event codes. Those are
 * defined elsewhere.
 */
enum bgp_fsm_events {
	BGP_Start = 1,
	BGP_Stop,
	TCP_connection_open,
	TCP_connection_open_w_delay,
	TCP_connection_closed,
	TCP_connection_open_failed,
	TCP_fatal_error,
	ConnectRetry_timer_expired,
	Hold_Timer_expired,
	KeepAlive_timer_expired,
	DelayOpen_timer_expired,
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

#define PEER_HOSTNAME(peer) ((peer)->host ? (peer)->host : "(unknown peer)")

struct llgr_info {
	uint32_t stale_time;
	uint8_t flags;
};

struct addpath_paths_limit {
	uint16_t send;
	uint16_t receive;
};

struct peer_connection {
	struct peer *peer;

	/* Status of the peer connection. */
	enum bgp_fsm_status status;
	enum bgp_fsm_status ostatus;

	int fd;

	/* Thread flags */
	_Atomic uint32_t thread_flags;
#define PEER_THREAD_WRITES_ON (1U << 0)
#define PEER_THREAD_READS_ON  (1U << 1)

	/* Packet receive and send buffer. */
	pthread_mutex_t io_mtx;	  // guards ibuf, obuf
	struct stream_fifo *ibuf; // packets waiting to be processed
	struct stream_fifo *obuf; // packets waiting to be written

	struct ringbuf *ibuf_work; // WiP buffer used by bgp_read() only

	struct event *t_read;
	struct event *t_write;
	struct event *t_connect;
	struct event *t_delayopen;
	struct event *t_start;
	struct event *t_holdtime;

	struct event *t_connect_check_r;
	struct event *t_connect_check_w;

	struct event *t_gr_restart;
	struct event *t_gr_stale;

	struct event *t_generate_updgrp_packets;
	struct event *t_pmax_restart;

	struct event *t_routeadv;
	struct event *t_process_packet;
	struct event *t_process_packet_error;

	struct event *t_stop_with_notify;

	union sockunion su;
#define BGP_CONNECTION_SU_UNSPEC(connection)                                   \
	(connection->su.sa.sa_family == AF_UNSPEC)
};
extern struct peer_connection *bgp_peer_connection_new(struct peer *peer);
extern void bgp_peer_connection_free(struct peer_connection **connection);
extern void bgp_peer_connection_buffers_free(struct peer_connection *connection);

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

	/* BGP peer_af structures, per configured AF on this peer */
	struct peer_af *peer_af_array[BGP_AF_MAX];

	/* Peer's remote AS number. */
	enum peer_asn_type as_type;
	as_t as;
	/* for vty as format */
	char *as_pretty;

	/* Peer's local AS number. */
	as_t local_as;

	enum bgp_peer_sort sort;
	enum bgp_peer_sub_sort sub_sort;

	/* Peer's Change local AS number. */
	as_t change_local_as;
	/* for vty as format */
	char *change_local_as_pretty;

	/* Remote router ID. */
	struct in_addr remote_id;

	/* Local router ID. */
	struct in_addr local_id;

	struct stream *curr; // the current packet being parsed

	/* the doppelganger peer structure, due to dual TCP conn setup */
	struct peer *doppelganger;

	/* FSM events, stored for debug purposes.
	 * Note: uchar used for reduced memory usage.
	 */
	enum bgp_fsm_events cur_event;
	enum bgp_fsm_events last_event;
	enum bgp_fsm_events last_major_event;

	/* Peer index, used for dumping TABLE_DUMP_V2 format */
	uint16_t table_dump_index;

	/* Peer information */

	/*
	 * We will have 2 `struct peer_connection` data structures
	 * connection is our attempt to talk to our peer.  incoming
	 * is the peer attempting to talk to us.  When it is
	 * time to consolidate between the two, we'll solidify
	 * into the connection variable being used.
	 */
	struct peer_connection *connection;

	int ttl;	     /* TTL of TCP connection to the peer. */
	int rtt;	     /* Estimated round-trip-time from TCP_INFO */
	int rtt_expected; /* Expected round-trip-time for a peer */
	uint8_t rtt_keepalive_rcv; /* Received count for RTT shutdown */
	uint8_t rtt_keepalive_conf; /* Configured count for RTT shutdown */
	int gtsm_hops;       /* minimum hopcount to peer */
	char *desc;	  /* Description of the peer. */
	unsigned short port; /* Destination port for peer */
	char *host;	  /* Printable address of the peer. */

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

	/* Roles in bgp session */
	uint8_t local_role;
	uint8_t remote_role;
#define ROLE_PROVIDER                       0
#define ROLE_RS_SERVER                      1
#define ROLE_RS_CLIENT                      2
#define ROLE_CUSTOMER                       3
#define ROLE_PEER                           4
#define ROLE_UNDEFINED                    255

#define ROLE_NAME_MAX_LEN                  20

	/* Peer address family configuration. */
	uint8_t afc[AFI_MAX][SAFI_MAX];
	uint8_t afc_nego[AFI_MAX][SAFI_MAX];
	uint8_t afc_adv[AFI_MAX][SAFI_MAX];
	uint8_t afc_recv[AFI_MAX][SAFI_MAX];

	/* Capability flags (reset in bgp_stop) */
	uint64_t cap;
#define PEER_CAP_REFRESH_ADV (1ULL << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_RCV (1ULL << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV (1ULL << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV (1ULL << 4) /* dynamic received */
#define PEER_CAP_RESTART_ADV (1ULL << 5) /* restart advertised */
#define PEER_CAP_RESTART_RCV (1ULL << 6) /* restart received */
#define PEER_CAP_AS4_ADV     (1ULL << 7) /* as4 advertised */
#define PEER_CAP_AS4_RCV     (1ULL << 8) /* as4 received */
/* sent graceful-restart restart (R) bit */
#define PEER_CAP_GRACEFUL_RESTART_R_BIT_ADV (1ULL << 9)
/* received graceful-restart restart (R) bit */
#define PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV (1ULL << 10)
#define PEER_CAP_ADDPATH_ADV		    (1ULL << 11) /* addpath advertised */
#define PEER_CAP_ADDPATH_RCV		    (1ULL << 12) /* addpath received */
#define PEER_CAP_ENHE_ADV		    (1ULL << 13) /* Extended nexthop advertised */
#define PEER_CAP_ENHE_RCV		    (1ULL << 14) /* Extended nexthop received */
#define PEER_CAP_HOSTNAME_ADV		    (1ULL << 15) /* hostname advertised */
#define PEER_CAP_HOSTNAME_RCV		    (1ULL << 16) /* hostname received */
#define PEER_CAP_ENHANCED_RR_ADV	    (1ULL << 17) /* enhanced rr advertised */
#define PEER_CAP_ENHANCED_RR_RCV	    (1ULL << 18) /* enhanced rr received */
#define PEER_CAP_EXTENDED_MESSAGE_ADV	    (1ULL << 19)
#define PEER_CAP_EXTENDED_MESSAGE_RCV	    (1ULL << 20)
#define PEER_CAP_LLGR_ADV		    (1ULL << 21)
#define PEER_CAP_LLGR_RCV		    (1ULL << 22)
/* sent graceful-restart notification (N) bit */
#define PEER_CAP_GRACEFUL_RESTART_N_BIT_ADV (1ULL << 23)
/* received graceful-restart notification (N) bit */
#define PEER_CAP_GRACEFUL_RESTART_N_BIT_RCV (1ULL << 24)
#define PEER_CAP_ROLE_ADV		    (1ULL << 25) /* role advertised */
#define PEER_CAP_ROLE_RCV		    (1ULL << 26) /* role received */
#define PEER_CAP_SOFT_VERSION_ADV	    (1ULL << 27)
#define PEER_CAP_SOFT_VERSION_RCV	    (1ULL << 28)
#define PEER_CAP_PATHS_LIMIT_ADV (1U << 29)
#define PEER_CAP_PATHS_LIMIT_RCV (1U << 30)

	/* Capability flags (reset in bgp_stop) */
	uint32_t af_cap[AFI_MAX][SAFI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1U << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1U << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1U << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1U << 3) /* receive-mode received */
#define PEER_CAP_RESTART_AF_RCV             (1U << 6) /* graceful restart afi/safi received */
#define PEER_CAP_RESTART_AF_PRESERVE_RCV    (1U << 7) /* graceful restart afi/safi F-bit received */
#define PEER_CAP_ADDPATH_AF_TX_ADV          (1U << 8) /* addpath tx advertised */
#define PEER_CAP_ADDPATH_AF_TX_RCV          (1U << 9) /* addpath tx received */
#define PEER_CAP_ADDPATH_AF_RX_ADV          (1U << 10) /* addpath rx advertised */
#define PEER_CAP_ADDPATH_AF_RX_RCV          (1U << 11) /* addpath rx received */
#define PEER_CAP_ENHE_AF_ADV                (1U << 12) /* Extended nexthopi afi/safi advertised */
#define PEER_CAP_ENHE_AF_RCV                (1U << 13) /* Extended nexthop afi/safi received */
#define PEER_CAP_ENHE_AF_NEGO               (1U << 14) /* Extended nexthop afi/safi negotiated */
#define PEER_CAP_LLGR_AF_ADV                (1U << 15)
#define PEER_CAP_LLGR_AF_RCV                (1U << 16)
#define PEER_CAP_PATHS_LIMIT_AF_ADV         (1U << 17)
#define PEER_CAP_PATHS_LIMIT_AF_RCV         (1U << 18)

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
	uint64_t flags_override;
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
	uint64_t flags_invert;
	/*
	 * Effective array for storing the peer/peer-group flags. In case of a
	 * peer-group, the peer-specific overrides (see flags_override and
	 * flags_invert) must be respected.
	 * When changing the structure of flags/af_flags, do not forget to
	 * change flags_invert/flags_override too.
	 */
	uint64_t flags;
#define PEER_FLAG_PASSIVE                   (1ULL << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1ULL << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1ULL << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1ULL << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1ULL << 4) /* strict-match */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1ULL << 5) /* dynamic capability */
#define PEER_FLAG_DISABLE_CONNECTED_CHECK   (1ULL << 6) /* disable-connected-check */
#define PEER_FLAG_LOCAL_AS_NO_PREPEND       (1ULL << 7) /* local-as no-prepend */
#define PEER_FLAG_LOCAL_AS_REPLACE_AS       (1ULL << 8) /* local-as no-prepend replace-as */
#define PEER_FLAG_DELETE                    (1ULL << 9) /* mark the peer for deleting */
#define PEER_FLAG_CONFIG_NODE               (1ULL << 10) /* the node to update configs on */
#define PEER_FLAG_LONESOUL                  (1ULL << 11)
#define PEER_FLAG_DYNAMIC_NEIGHBOR          (1ULL << 12) /* dynamic neighbor */
#define PEER_FLAG_CAPABILITY_ENHE           (1ULL << 13) /* Extended next-hop (rfc 5549)*/
#define PEER_FLAG_IFPEER_V6ONLY             (1ULL << 14) /* if-based peer is v6 only */
#define PEER_FLAG_IS_RFAPI_HD               (1ULL << 15) /* attached to rfapi HD */
#define PEER_FLAG_ENFORCE_FIRST_AS          (1ULL << 16) /* enforce-first-as */
#define PEER_FLAG_ROUTEADV                  (1ULL << 17) /* route advertise */
#define PEER_FLAG_TIMER                     (1ULL << 18) /* keepalive & holdtime */
#define PEER_FLAG_TIMER_CONNECT             (1ULL << 19) /* connect timer */
#define PEER_FLAG_PASSWORD                  (1ULL << 20) /* password */
#define PEER_FLAG_LOCAL_AS                  (1ULL << 21) /* local-as */
#define PEER_FLAG_UPDATE_SOURCE             (1ULL << 22) /* update-source */

	/* BGP-GR Peer related  flags */
#define PEER_FLAG_GRACEFUL_RESTART_HELPER   (1ULL << 23) /* Helper */
#define PEER_FLAG_GRACEFUL_RESTART          (1ULL << 24) /* Graceful Restart */
#define PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT (1ULL << 25) /* Global-Inherit */
#define PEER_FLAG_RTT_SHUTDOWN (1ULL << 26) /* shutdown rtt */
#define PEER_FLAG_TIMER_DELAYOPEN (1ULL << 27) /* delayopen timer */
#define PEER_FLAG_TCP_MSS (1ULL << 28)	 /* tcp-mss */
/* Disable IEEE floating-point link bandwidth encoding in
 * extended communities.
 */
#define PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE (1ULL << 29)
/* force the extended format for Optional Parameters in OPEN message */
#define PEER_FLAG_EXTENDED_OPT_PARAMS (1ULL << 30)

	/* BGP Open Policy flags.
	 * Enforce using roles on both sides:
	 * `local-role ROLE strict-mode` configured.
	 */
#define PEER_FLAG_ROLE_STRICT_MODE (1ULL << 31)
	/* `local-role` configured */
#define PEER_FLAG_ROLE (1ULL << 32)
#define PEER_FLAG_PORT (1ULL << 33)
#define PEER_FLAG_AIGP (1ULL << 34)
#define PEER_FLAG_GRACEFUL_SHUTDOWN (1ULL << 35)
#define PEER_FLAG_CAPABILITY_SOFT_VERSION (1ULL << 36)
#define PEER_FLAG_CAPABILITY_FQDN (1ULL << 37)  /* fqdn capability */
#define PEER_FLAG_AS_LOOP_DETECTION (1ULL << 38) /* as path loop detection */
#define PEER_FLAG_EXTENDED_LINK_BANDWIDTH (1ULL << 39)
#define PEER_FLAG_DUAL_AS		  (1ULL << 40)

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
#define PEER_GRACEFUL_RESTART_NEW_STATE_HELPER   (1U << 0)
#define PEER_GRACEFUL_RESTART_NEW_STATE_RESTART  (1U << 1)
#define PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT  (1U << 2)

	/* outgoing message sent in CEASE_ADMIN_SHUTDOWN notify */
	char *tx_shutdown_message;

	/* NSF mode (graceful restart) */
	uint8_t nsf[AFI_MAX][SAFI_MAX];
	/* EOR Send time */
	time_t eor_stime[AFI_MAX][SAFI_MAX];
	/* Last update packet sent time */
	time_t pkt_stime[AFI_MAX][SAFI_MAX];

	/* Peer / peer group route flap dampening configuration */
	struct bgp_damp_config damp[AFI_MAX][SAFI_MAX];

	/* Peer Per AF flags */
	/*
	 * Please consult the comments for *flags_override*, *flags_invert* and
	 * *flags* to understand what these three arrays do. The address-family
	 * specific attributes are being treated the exact same way as global
	 * peer attributes.
	 */
	uint64_t af_flags_override[AFI_MAX][SAFI_MAX];
	uint64_t af_flags_invert[AFI_MAX][SAFI_MAX];
	uint64_t af_flags[AFI_MAX][SAFI_MAX];
#define PEER_FLAG_SEND_COMMUNITY (1ULL << 0)
#define PEER_FLAG_SEND_EXT_COMMUNITY (1ULL << 1)
#define PEER_FLAG_NEXTHOP_SELF (1ULL << 2)
#define PEER_FLAG_REFLECTOR_CLIENT (1ULL << 3)
#define PEER_FLAG_RSERVER_CLIENT (1ULL << 4)
#define PEER_FLAG_SOFT_RECONFIG (1ULL << 5)
#define PEER_FLAG_AS_PATH_UNCHANGED (1ULL << 6)
#define PEER_FLAG_NEXTHOP_UNCHANGED (1ULL << 7)
#define PEER_FLAG_MED_UNCHANGED (1ULL << 8)
#define PEER_FLAG_DEFAULT_ORIGINATE (1ULL << 9)
#define PEER_FLAG_REMOVE_PRIVATE_AS (1ULL << 10)
#define PEER_FLAG_ALLOWAS_IN (1ULL << 11)
#define PEER_FLAG_ORF_PREFIX_SM (1ULL << 12)
#define PEER_FLAG_ORF_PREFIX_RM (1ULL << 13)
#define PEER_FLAG_MAX_PREFIX (1ULL << 14)
#define PEER_FLAG_MAX_PREFIX_WARNING (1ULL << 15)
#define PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED (1ULL << 16)
#define PEER_FLAG_FORCE_NEXTHOP_SELF (1ULL << 17)
#define PEER_FLAG_REMOVE_PRIVATE_AS_ALL (1ULL << 18)
#define PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE (1ULL << 19)
#define PEER_FLAG_AS_OVERRIDE (1ULL << 20)
#define PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE (1ULL << 21)
#define PEER_FLAG_WEIGHT (1ULL << 22)
#define PEER_FLAG_ALLOWAS_IN_ORIGIN (1ULL << 23)
#define PEER_FLAG_SEND_LARGE_COMMUNITY (1ULL << 24)
#define PEER_FLAG_MAX_PREFIX_OUT (1ULL << 25)
#define PEER_FLAG_MAX_PREFIX_FORCE (1ULL << 26)
#define PEER_FLAG_DISABLE_ADDPATH_RX (1ULL << 27)
#define PEER_FLAG_SOO (1ULL << 28)
#define PEER_FLAG_SEND_EXT_COMMUNITY_RPKI (1ULL << 29)
#define PEER_FLAG_ADDPATH_RX_PATHS_LIMIT (1ULL << 30)
#define PEER_FLAG_CONFIG_DAMPENING (1U << 31)
#define PEER_FLAG_ACCEPT_OWN (1ULL << 63)

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
#define PEER_STATUS_ACCEPT_PEER	      (1U << 0) /* accept peer */
#define PEER_STATUS_PREFIX_OVERFLOW   (1U << 1) /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN   (1U << 2) /* capability open send */
#define PEER_STATUS_HAVE_ACCEPT       (1U << 3) /* accept peer's parent */
#define PEER_STATUS_GROUP             (1U << 4) /* peer-group conf */
#define PEER_STATUS_NSF_MODE          (1U << 5) /* NSF aware peer */
#define PEER_STATUS_NSF_WAIT          (1U << 6) /* wait comeback peer */
/* received extended format encoding for OPEN message */
#define PEER_STATUS_EXT_OPT_PARAMS_LENGTH (1U << 7)

	/* Peer status af flags (reset in bgp_stop) */
	uint16_t af_sflags[AFI_MAX][SAFI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND   (1U << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH  (1U << 1) /* wait refresh received peer */
#define PEER_STATUS_PREFIX_THRESHOLD  (1U << 2) /* exceed prefix-threshold */
#define PEER_STATUS_PREFIX_LIMIT      (1U << 3) /* exceed prefix-limit */
#define PEER_STATUS_EOR_SEND          (1U << 4) /* end-of-rib send to peer */
#define PEER_STATUS_EOR_RECEIVED      (1U << 5) /* end-of-rib received from peer */
#define PEER_STATUS_ENHANCED_REFRESH (1U << 6) /* Enhanced Route Refresh */
#define PEER_STATUS_BORR_SEND (1U << 7) /* BoRR send to peer */
#define PEER_STATUS_BORR_RECEIVED (1U << 8) /* BoRR received from peer */
#define PEER_STATUS_EORR_SEND (1U << 9) /* EoRR send to peer */
#define PEER_STATUS_EORR_RECEIVED (1U << 10) /* EoRR received from peer */
/* LLGR aware peer */
#define PEER_STATUS_LLGR_WAIT (1U << 11)
#define PEER_STATUS_REFRESH_PENDING (1U << 12) /* refresh request from peer */
#define PEER_STATUS_RTT_SHUTDOWN (1U << 13) /* In shutdown state due to RTT */

	/* Configured timer values. */
	_Atomic uint32_t holdtime;
	_Atomic uint32_t keepalive;
	_Atomic uint32_t connect;
	_Atomic uint32_t routeadv;
	_Atomic uint32_t delayopen;

	/* Timer values. */
	_Atomic uint32_t v_start;
	_Atomic uint32_t v_connect;
	_Atomic uint32_t v_holdtime;
	_Atomic uint32_t v_keepalive;
	_Atomic uint32_t v_routeadv;
	_Atomic uint32_t v_delayopen;
	_Atomic uint32_t v_pmax_restart;
	_Atomic uint32_t v_gr_restart;

	/* Threads. */
	struct event *t_llgr_stale[AFI_MAX][SAFI_MAX];
	struct event *t_revalidate_all[AFI_MAX][SAFI_MAX];
	struct event *t_refresh_stalepath;

	/* Thread flags. */
	_Atomic uint32_t thread_flags;
#define PEER_THREAD_KEEPALIVES_ON (1U << 0)
#define PEER_THREAD_SUBGRP_ADV_DELAY (1U << 1)

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
	uint64_t stat_pfx_loc_rib; /* RFC7854 : Number of routes in Loc-RIB */
	uint64_t stat_pfx_adj_rib_in; /* RFC7854 : Number of routes in Adj-RIBs-In */

	/* BGP state count */
	uint32_t established; /* Established */
	uint32_t dropped;     /* Dropped */

	/* Update delay related fields */
	uint8_t update_delay_over; /* When this is set, BGP is no more waiting
				     for EOR */

	time_t synctime;
	/* timestamp when the last UPDATE msg was written */
	_Atomic time_t last_write;
	/* timestamp when the last msg was written */
	_Atomic time_t last_update;

	/* only updated under io_mtx.
	 * last_sendq_warn is only for ratelimiting log warning messages.
	 */
	time_t last_sendq_ok, last_sendq_warn;

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
#define PEER_FT_DISTRIBUTE_LIST       (1U << 0) /* distribute-list */
#define PEER_FT_FILTER_LIST           (1U << 1) /* filter-list */
#define PEER_FT_PREFIX_LIST           (1U << 2) /* prefix-list */
#define PEER_FT_ROUTE_MAP             (1U << 3) /* route-map */
#define PEER_FT_UNSUPPRESS_MAP        (1U << 4) /* unsuppress-map */
#define PEER_FT_ADVERTISE_MAP         (1U << 5) /* advertise-map */

	/* ORF Prefix-list */
	struct prefix_list *orf_plist[AFI_MAX][SAFI_MAX];

	/* Text description of last attribute rcvd */
	char rcvd_attr_str[BUFSIZ];

	/*
	 * Track if we printed the attribute in debugs
	 *
	 * These two rcvd_attr_str and rcvd_attr_printed are going to
	 * be fun in the long term when we want to break up parsing
	 * of data from the nlri in multiple pthreads or really
	 * if we ever change order of things this will just break
	 */
	bool rcvd_attr_printed;

	/* Accepted prefix count */
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

	/* soo */
	struct ecommunity *soo[AFI_MAX][SAFI_MAX];

	/* weight */
	unsigned long weight[AFI_MAX][SAFI_MAX];

	/* peer reset cause */
	uint8_t last_reset;
#define PEER_DOWN_RID_CHANGE             1U /* bgp router-id command */
#define PEER_DOWN_REMOTE_AS_CHANGE       2U /* neighbor remote-as command */
#define PEER_DOWN_LOCAL_AS_CHANGE        3U /* neighbor local-as command */
#define PEER_DOWN_CLID_CHANGE            4U /* bgp cluster-id command */
#define PEER_DOWN_CONFED_ID_CHANGE       5U /* bgp confederation id command */
#define PEER_DOWN_CONFED_PEER_CHANGE     6U /* bgp confederation peer command */
#define PEER_DOWN_RR_CLIENT_CHANGE       7U /* neighbor rr-client command */
#define PEER_DOWN_RS_CLIENT_CHANGE       8U /* neighbor rs-client command */
#define PEER_DOWN_UPDATE_SOURCE_CHANGE   9U /* neighbor update-source command */
#define PEER_DOWN_AF_ACTIVATE           10U /* neighbor activate command */
#define PEER_DOWN_USER_SHUTDOWN         11U /* neighbor shutdown command */
#define PEER_DOWN_USER_RESET            12U /* clear ip bgp command */
#define PEER_DOWN_NOTIFY_RECEIVED       13U /* notification received */
#define PEER_DOWN_NOTIFY_SEND           14U /* notification send */
#define PEER_DOWN_CLOSE_SESSION         15U /* tcp session close */
#define PEER_DOWN_NEIGHBOR_DELETE       16U /* neghbor delete */
#define PEER_DOWN_RMAP_BIND             17U /* neghbor peer-group command */
#define PEER_DOWN_RMAP_UNBIND           18U /* no neighbor peer-group command */
#define PEER_DOWN_CAPABILITY_CHANGE     19U /* neighbor capability command */
#define PEER_DOWN_PASSIVE_CHANGE        20U /* neighbor passive command */
#define PEER_DOWN_MULTIHOP_CHANGE       21U /* neighbor multihop command */
#define PEER_DOWN_NSF_CLOSE_SESSION     22U /* NSF tcp session close */
#define PEER_DOWN_V6ONLY_CHANGE         23U /* if-based peering v6only toggled */
#define PEER_DOWN_BFD_DOWN              24U /* BFD down */
#define PEER_DOWN_IF_DOWN               25U /* Interface down */
#define PEER_DOWN_NBR_ADDR_DEL          26U /* Peer address lost */
#define PEER_DOWN_WAITING_NHT           27U /* Waiting for NHT to resolve */
#define PEER_DOWN_NBR_ADDR              28U /* Waiting for peer IPv6 IP Addr */
#define PEER_DOWN_VRF_UNINIT            29U /* Associated VRF is not init yet */
#define PEER_DOWN_NOAFI_ACTIVATED       30U /* No AFI/SAFI activated for peer */
#define PEER_DOWN_AS_SETS_REJECT        31U /* Reject routes with AS_SET */
#define PEER_DOWN_WAITING_OPEN          32U /* Waiting for open to succeed */
#define PEER_DOWN_PFX_COUNT             33U /* Reached received prefix count */
#define PEER_DOWN_SOCKET_ERROR          34U /* Some socket error happened */
#define PEER_DOWN_RTT_SHUTDOWN          35U /* Automatically shutdown due to RTT */
#define PEER_DOWN_SUPPRESS_FIB_PENDING	 36U /* Suppress fib pending changed */
#define PEER_DOWN_PASSWORD_CHANGE	 37U /* neighbor password command */
	/*
	 * Remember to update peer_down_str in bgp_fsm.c when you add
	 * a new value to the last_reset reason
	 */

	struct stream *last_reset_cause;

	/* The kind of route-map Flags.*/
	uint8_t rmap_type;
#define PEER_RMAP_TYPE_IN             (1U << 0) /* neighbor route-map in */
#define PEER_RMAP_TYPE_OUT            (1U << 1) /* neighbor route-map out */
#define PEER_RMAP_TYPE_NETWORK        (1U << 2) /* network route-map */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1U << 3) /* redistribute route-map */
#define PEER_RMAP_TYPE_DEFAULT        (1U << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_AGGREGATE      (1U << 5) /* aggregate-address route-map */

	/** Peer overwrite configuration. */
	struct bfd_session_config {
		/**
		 * Manual configuration bit.
		 *
		 * This flag only makes sense for real peers (and not groups),
		 * it keeps track if the user explicitly configured BFD for a
		 * peer.
		 */
		bool manual;
		/** Control Plane Independent. */
		bool cbit;
		/** Detection multiplier. */
		uint8_t detection_multiplier;
		/** Minimum required RX interval. */
		uint32_t min_rx;
		/** Minimum required TX interval. */
		uint32_t min_tx;
		/** Profile name. */
		char profile[BFD_PROFILE_NAME_LEN];
		/** Peer BFD session */
		struct bfd_session_params *session;
	} * bfd_config;

	/* hostname and domainname advertised by host */
	char *hostname;
	char *domainname;

	/* Extended Message Support */
	uint16_t max_packet_size;

	/* Conditional advertisement */
	bool advmap_config_change[AFI_MAX][SAFI_MAX];
	bool advmap_table_change;

	/* set TCP max segment size */
	uint32_t tcp_mss;

	/* Long-lived Graceful Restart */
	struct llgr_info llgr[AFI_MAX][SAFI_MAX];

	bool shut_during_cfg;

#define BGP_ATTR_MAX 255
	/* Path attributes discard */
	bool discard_attrs[BGP_ATTR_MAX + 1];

	/* Path attributes treat-as-withdraw */
	bool withdraw_attrs[BGP_ATTR_MAX + 1];

	/* BGP Software Version Capability */
#define BGP_MAX_SOFT_VERSION 64
	char *soft_version;

	/* Add-Path Best selected paths number to advertise */
	uint8_t addpath_best_selected[AFI_MAX][SAFI_MAX];

	/* Add-Path Paths-Limit */
	struct addpath_paths_limit addpath_paths_limit[AFI_MAX][SAFI_MAX];

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(peer);

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
	(CHECK_FLAG((P)->flags, PEER_FLAG_SHUTDOWN) ||                         \
	 CHECK_FLAG((P)->sflags, PEER_STATUS_PREFIX_OVERFLOW) ||               \
	 CHECK_FLAG((P)->bgp->flags, BGP_FLAG_SHUTDOWN) ||                     \
	 (P)->shut_during_cfg)

#define PEER_ROUTE_ADV_DELAY(peer)					       \
	(CHECK_FLAG(peer->thread_flags, PEER_THREAD_SUBGRP_ADV_DELAY))

#define PEER_PASSWORD_MINLEN	(1)
#define PEER_PASSWORD_MAXLEN	(80)

/* This structure's member directly points incoming packet data
   stream. */
struct bgp_nlri {
	/* AFI.  */
	uint16_t afi; /* iana_afi_t */

	/* SAFI.  */
	uint8_t safi; /* iana_safi_t */

	/* Length of whole NLRI.  */
	bgp_size_t length;

	/* Pointer to NLRI byte stream.  */
	uint8_t *nlri;
};

/* BGP versions.  */
#define BGP_VERSION_4		                 4

/* Default BGP port number.  */
#define BGP_PORT_DEFAULT                       179

/* Extended BGP Administrative Shutdown Communication */
#define BGP_ADMIN_SHUTDOWN_MSG_LEN 255

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
#define BGP_ATTR_MP_REACH_NLRI                  14
#define BGP_ATTR_MP_UNREACH_NLRI                15
#define BGP_ATTR_EXT_COMMUNITIES                16
#define BGP_ATTR_AS4_PATH                       17
#define BGP_ATTR_AS4_AGGREGATOR                 18
#define BGP_ATTR_PMSI_TUNNEL                    22
#define BGP_ATTR_ENCAP                          23
#define BGP_ATTR_IPV6_EXT_COMMUNITIES           25
#define BGP_ATTR_AIGP                           26
#define BGP_ATTR_LARGE_COMMUNITIES              32
#define BGP_ATTR_OTC                            35
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
#define BGP_NOTIFY_ROUTE_REFRESH_ERR             7
#define BGP_NOTIFY_SEND_HOLD_ERR                 8

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
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME          6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL              7
#define BGP_NOTIFY_OPEN_ROLE_MISMATCH           11

/* BGP_NOTIFY_UPDATE_ERR sub codes.  */
#define BGP_NOTIFY_UPDATE_MAL_ATTR               1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR             2
#define BGP_NOTIFY_UPDATE_MISS_ATTR              3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR          4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR          5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN           6
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
#define BGP_NOTIFY_CEASE_HARD_RESET 9
#define BGP_NOTIFY_CEASE_BFD_DOWN 10

/* BGP_NOTIFY_ROUTE_REFRESH_ERR sub codes (RFC 7313). */
#define BGP_NOTIFY_ROUTE_REFRESH_INVALID_MSG_LEN 1

/* BGP route refresh optional subtypes. */
#define BGP_ROUTE_REFRESH_NORMAL 0
#define BGP_ROUTE_REFRESH_BORR 1
#define BGP_ROUTE_REFRESH_EORR 2

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

/* BGP RFC 4271 DelayOpenTime default value */
#define BGP_DEFAULT_DELAYOPEN 120

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
#define BGP_DEFAULT_UPDATE_ADVERTISEMENT_TIME  1

/* BGP Long-lived Graceful Restart */
#define BGP_DEFAULT_LLGR_STALE_TIME 0

/* BGP uptime string length.  */
#define BGP_UPTIME_LEN 25

/* Default configuration settings for bgpd.  */
#define BGP_DEFAULT_CONFIG             "bgpd.conf"

/* BGP Dynamic Neighbors feature */
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT    100
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_MIN          1
#define BGP_DYNAMIC_NEIGHBORS_LIMIT_MAX      65535

/* BGP AIGP */
#define BGP_AIGP_TLV_RESERVED 0 /* AIGP Reserved */
#define BGP_AIGP_TLV_METRIC 1   /* AIGP Metric */
#define BGP_AIGP_TLV_METRIC_LEN 11
#define BGP_AIGP_TLV_METRIC_MAX 0xffffffffffffffffULL
#define BGP_AIGP_TLV_METRIC_DESC "Accumulated IGP Metric"

/* Flag for peer_clear_soft().  */
enum bgp_clear_type {
	BGP_CLEAR_SOFT_NONE,
	BGP_CLEAR_SOFT_OUT,
	BGP_CLEAR_SOFT_IN,
	BGP_CLEAR_SOFT_BOTH,
	BGP_CLEAR_SOFT_IN_ORF_PREFIX,
	BGP_CLEAR_MESSAGE_STATS,
	BGP_CLEAR_CAPABILITIES,
};

/* Macros. */
#define BGP_INPUT(P)         ((P)->curr)
#define BGP_INPUT_PNT(P)     (stream_pnt(BGP_INPUT(P)))
#define BGP_IS_VALID_STATE_FOR_NOTIF(S)                                        \
	(((S) == OpenSent) || ((S) == OpenConfirm) || ((S) == Established))

/* BGP error codes.  */
enum bgp_create_error_code {
	BGP_SUCCESS = 0,
	BGP_CREATED = 1,
	BGP_INSTANCE_EXISTS = 2,
	BGP_ERR_INVALID_VALUE = -1,
	BGP_ERR_INVALID_FLAG = -2,
	BGP_ERR_INVALID_AS = -3,
	BGP_ERR_PEER_GROUP_MEMBER = -4,
	BGP_ERR_PEER_GROUP_NO_REMOTE_AS = -5,
	BGP_ERR_PEER_GROUP_CANT_CHANGE = -6,
	BGP_ERR_PEER_GROUP_MISMATCH = -7,
	BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT = -8,
	BGP_ERR_AS_MISMATCH = -9,
	BGP_ERR_PEER_FLAG_CONFLICT = -10,
	BGP_ERR_PEER_GROUP_SHUTDOWN = -11,
	BGP_ERR_PEER_FILTER_CONFLICT = -12,
	BGP_ERR_NOT_INTERNAL_PEER = -13,
	BGP_ERR_REMOVE_PRIVATE_AS = -14,
	BGP_ERR_AF_UNCONFIGURED = -15,
	BGP_ERR_SOFT_RECONFIG_UNCONFIGURED = -16,
	BGP_ERR_INSTANCE_MISMATCH = -17,
	BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS = -19,
	BGP_ERR_TCPSIG_FAILED = -20,
	BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK = -21,
	BGP_ERR_NO_IBGP_WITH_TTLHACK = -22,
	BGP_ERR_NO_INTERFACE_CONFIG = -23,
	BGP_ERR_AS_OVERRIDE = -25,
	BGP_ERR_INVALID_DYNAMIC_NEIGHBORS_LIMIT = -26,
	BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_EXISTS = -27,
	BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_NOT_FOUND = -28,
	BGP_ERR_INVALID_FOR_DYNAMIC_PEER = -29,
	BGP_ERR_INVALID_FOR_DIRECT_PEER = -30,
	BGP_ERR_PEER_SAFI_CONFLICT = -31,

	/* BGP GR ERRORS */
	BGP_ERR_GR_INVALID_CMD = -32,
	BGP_ERR_GR_OPERATION_FAILED = -33,
	BGP_GR_NO_OPERATION = -34,

	/*BGP Open Policy ERRORS */
	BGP_ERR_INVALID_ROLE_NAME = -35,
	BGP_ERR_INVALID_INTERNAL_ROLE = -36
};

/*
 * Enumeration of different policy kinds a peer can be configured with.
 */
enum bgp_policy_type {
	BGP_POLICY_ROUTE_MAP,
	BGP_POLICY_FILTER_LIST,
	BGP_POLICY_PREFIX_LIST,
	BGP_POLICY_DISTRIBUTE_LIST,
};

/* peer_flag_change_type. */
enum peer_change_type {
	peer_change_none,
	peer_change_reset,
	peer_change_reset_in,
	peer_change_reset_out,
};

/* Enumeration of martian ("self") entry types.
 * Routes carrying fields that match a self entry are considered martians
 * and should be handled accordingly, i.e. dropped or import-filtered.
 * Note:
 *     These "martians" are separate from routes optionally allowed via
 *     'bgp allow-martian-nexthop'. The optionally allowed martians are
 *     simply prefixes caught by ipv4_martian(), i.e. routes outside
 *     the non-reserved IPv4 Unicast address space.
 */
enum bgp_martian_type {
	BGP_MARTIAN_IF_IP,  /* bgp->address_hash */
	BGP_MARTIAN_TUN_IP, /* bgp->tip_hash */
	BGP_MARTIAN_IF_MAC, /* bgp->self_mac_hash */
	BGP_MARTIAN_RMAC,   /* bgp->rmac */
	BGP_MARTIAN_SOO,    /* bgp->evpn_info->macvrf_soo */
};

extern const struct message bgp_martian_type_str[];
extern const char *bgp_martian_type2str(enum bgp_martian_type mt);

extern struct bgp_master *bm;
extern unsigned int multipath_num;

/* Prototypes. */
extern void bgp_terminate(void);
extern void bgp_reset(void);
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
extern void bgp_peer_conf_if_to_su_update(struct peer_connection *connection);
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

extern enum bgp_peer_sort peer_sort(struct peer *peer);
extern enum bgp_peer_sort peer_sort_lookup(struct peer *peer);

extern bool peer_active(struct peer *);
extern bool peer_active_nego(struct peer *);
extern bool peer_afc_received(struct peer *peer);
extern bool peer_afc_advertised(struct peer *peer);
extern void bgp_recalculate_all_bestpaths(struct bgp *bgp);
extern struct peer *peer_create(union sockunion *su, const char *conf_if,
				struct bgp *bgp, as_t local_as, as_t remote_as,
				enum peer_asn_type as_type,
				struct peer_group *group, bool config_node,
				const char *as_str);
extern struct peer *peer_create_accept(struct bgp *);
extern void peer_xfer_config(struct peer *dst, struct peer *src);
extern char *peer_uptime(time_t uptime2, char *buf, size_t len, bool use_json,
			 json_object *json);

extern int bgp_config_write(struct vty *);

extern void bgp_master_init(struct event_loop *master, const int buffer_size,
			    struct list *addresses);

extern void bgp_init(unsigned short instance);
extern void bgp_pthreads_run(void);
extern void bgp_pthreads_finish(void);
extern void bgp_route_map_init(void);
extern void bgp_session_reset(struct peer *);

extern int bgp_option_set(int);
extern int bgp_option_unset(int);
extern int bgp_option_check(int);

/* set the bgp no-rib option during runtime and remove installed routes */
extern void bgp_option_norib_set_runtime(void);

/* unset the bgp no-rib option during runtime and reset all peers */
extern void bgp_option_norib_unset_runtime(void);

extern int bgp_get(struct bgp **bgp, as_t *as, const char *name,
		   enum bgp_instance_type kind, const char *as_pretty,
		   enum asnotation_mode asnotation);
extern void bgp_instance_up(struct bgp *);
extern void bgp_instance_down(struct bgp *);
extern int bgp_delete(struct bgp *);

extern int bgp_handle_socket(struct bgp *bgp, struct vrf *vrf,
			     vrf_id_t old_vrf_id, bool create);

extern void bgp_router_id_zebra_bump(vrf_id_t, const struct prefix *);
extern void bgp_router_id_static_set(struct bgp *, struct in_addr);

extern void bm_wait_for_fib_set(bool set);
extern void bgp_suppress_fib_pending_set(struct bgp *bgp, bool set);
extern void bgp_cluster_id_set(struct bgp *bgp, struct in_addr *cluster_id);
extern void bgp_cluster_id_unset(struct bgp *bgp);

extern void bgp_confederation_id_set(struct bgp *bgp, as_t as,
				     const char *as_str);
extern void bgp_confederation_id_unset(struct bgp *bgp);
extern bool bgp_confederation_peers_check(struct bgp *, as_t);

extern void bgp_confederation_peers_add(struct bgp *bgp, as_t as,
					const char *as_str);
extern void bgp_confederation_peers_remove(struct bgp *bgp, as_t as);

extern void bgp_timers_set(struct vty *vty, struct bgp *, uint32_t keepalive,
			   uint32_t holdtime, uint32_t connect_retry,
			   uint32_t delayopen);
extern void bgp_timers_unset(struct bgp *);

extern void bgp_default_local_preference_set(struct bgp *bgp,
					     uint32_t local_pref);
extern void bgp_default_local_preference_unset(struct bgp *bgp);

extern void bgp_default_subgroup_pkt_queue_max_set(struct bgp *bgp,
						   uint32_t queue_size);
extern void bgp_default_subgroup_pkt_queue_max_unset(struct bgp *bgp);

extern void bgp_listen_limit_set(struct bgp *bgp, int listen_limit);
extern void bgp_listen_limit_unset(struct bgp *bgp);

extern bool bgp_update_delay_active(struct bgp *);
extern bool bgp_update_delay_configured(struct bgp *);
extern bool bgp_afi_safi_peer_exists(struct bgp *bgp, afi_t afi, safi_t safi);
extern void peer_as_change(struct peer *peer, as_t as,
			   enum peer_asn_type as_type, const char *as_str);
extern int peer_remote_as(struct bgp *bgp, union sockunion *su,
			  const char *conf_if, as_t *as,
			  enum peer_asn_type as_type, const char *as_str);
extern int peer_group_remote_as(struct bgp *bgp, const char *peer_str, as_t *as,
				enum peer_asn_type as_type, const char *as_str);
extern int peer_delete(struct peer *peer);
extern void peer_notify_unconfig(struct peer *peer);
extern int peer_group_delete(struct peer_group *);
extern int peer_group_remote_as_delete(struct peer_group *);
extern int peer_group_listen_range_add(struct peer_group *, struct prefix *);
extern void peer_group_notify_unconfig(struct peer_group *group);

extern int peer_activate(struct peer *, afi_t, safi_t);
extern int peer_deactivate(struct peer *, afi_t, safi_t);

extern int peer_group_bind(struct bgp *, union sockunion *, struct peer *,
			   struct peer_group *, as_t *);

extern int peer_flag_set(struct peer *peer, uint64_t flag);
extern int peer_flag_unset(struct peer *peer, uint64_t flag);
extern void peer_flag_inherit(struct peer *peer, uint64_t flag);

extern int peer_af_flag_set(struct peer *peer, afi_t afi, safi_t safi,
			    uint64_t flag);
extern int peer_af_flag_unset(struct peer *peer, afi_t afi, safi_t safi,
			      uint64_t flag);
extern bool peer_af_flag_check(struct peer *peer, afi_t afi, safi_t safi,
			       uint64_t flag);
extern void peer_af_flag_inherit(struct peer *peer, afi_t afi, safi_t safi,
				 uint64_t flag);
extern void peer_change_action(struct peer *peer, afi_t afi, safi_t safi,
			       enum peer_change_type type);

extern int peer_ebgp_multihop_set(struct peer *, int);
extern int peer_ebgp_multihop_unset(struct peer *);
extern int is_ebgp_multihop_configured(struct peer *peer);

extern int peer_role_set(struct peer *peer, uint8_t role, bool strict_mode);
extern int peer_role_unset(struct peer *peer);

extern void peer_description_set(struct peer *, const char *);
extern void peer_description_unset(struct peer *);

extern int peer_update_source_if_set(struct peer *, const char *);
extern void peer_update_source_addr_set(struct peer *peer,
					const union sockunion *su);
extern void peer_update_source_unset(struct peer *peer);

extern int peer_default_originate_set(struct peer *peer, afi_t afi, safi_t safi,
				      const char *rmap,
				      struct route_map *route_map);
extern int peer_default_originate_unset(struct peer *, afi_t, safi_t);
extern void bgp_tcp_keepalive_set(struct bgp *bgp, uint16_t idle,
				  uint16_t interval, uint16_t probes);
extern void bgp_tcp_keepalive_unset(struct bgp *bgp);

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

extern int peer_timers_delayopen_set(struct peer *peer, uint32_t delayopen);
extern int peer_timers_delayopen_unset(struct peer *peer);

extern void peer_interface_set(struct peer *, const char *);
extern void peer_interface_unset(struct peer *);

extern int peer_distribute_set(struct peer *, afi_t, safi_t, int, const char *);
extern int peer_distribute_unset(struct peer *, afi_t, safi_t, int);

extern int peer_allowas_in_set(struct peer *, afi_t, safi_t, int, int);
extern int peer_allowas_in_unset(struct peer *, afi_t, safi_t);

extern int peer_local_as_set(struct peer *peer, as_t as, bool no_prepend,
			     bool replace_as, bool dual_as, const char *as_str);
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

extern int peer_advertise_map_set(struct peer *peer, afi_t afi, safi_t safi,
				  const char *advertise_name,
				  struct route_map *advertise_map,
				  const char *condition_name,
				  struct route_map *condition_map,
				  bool condition);

extern int peer_password_set(struct peer *, const char *);
extern int peer_password_unset(struct peer *);

extern int peer_unsuppress_map_unset(struct peer *, afi_t, safi_t);

extern int peer_advertise_map_unset(struct peer *peer, afi_t afi, safi_t safi,
				    const char *advertise_name,
				    struct route_map *advertise_map,
				    const char *condition_name,
				    struct route_map *condition_map,
				    bool condition);

extern int peer_maximum_prefix_set(struct peer *, afi_t, safi_t, uint32_t,
				   uint8_t, int, uint16_t, bool force);
extern int peer_maximum_prefix_unset(struct peer *, afi_t, safi_t);

extern void peer_maximum_prefix_out_refresh_routes(struct peer *peer, afi_t afi,
						   safi_t safi);
extern int peer_maximum_prefix_out_set(struct peer *peer, afi_t afi,
				       safi_t safi, uint32_t max);
extern int peer_maximum_prefix_out_unset(struct peer *peer, afi_t afi,
					 safi_t safi);

extern int peer_clear(struct peer *, struct listnode **);
extern int peer_clear_soft(struct peer *, afi_t, safi_t, enum bgp_clear_type);

extern int peer_ttl_security_hops_set(struct peer *, int);
extern int peer_ttl_security_hops_unset(struct peer *);

extern void peer_tx_shutdown_message_set(struct peer *, const char *msg);
extern void peer_tx_shutdown_message_unset(struct peer *);

extern void bgp_route_map_update_timer(struct event *thread);
extern const char *bgp_get_name_by_role(uint8_t role);
extern enum asnotation_mode bgp_get_asnotation(struct bgp *bgp);

extern void bgp_route_map_terminate(void);

extern bool bgp_route_map_has_extcommunity_rt(const struct route_map *map);

extern int peer_cmp(struct peer *p1, struct peer *p2);

extern int bgp_map_afi_safi_iana2int(iana_afi_t pkt_afi, iana_safi_t pkt_safi,
				     afi_t *afi, safi_t *safi);
extern int bgp_map_afi_safi_int2iana(afi_t afi, safi_t safi,
				     iana_afi_t *pkt_afi,
				     iana_safi_t *pkt_safi);

extern struct peer_af *peer_af_create(struct peer *, afi_t, safi_t);
extern struct peer_af *peer_af_find(struct peer *, afi_t, safi_t);
extern int peer_af_delete(struct peer *, afi_t, safi_t);

extern void bgp_shutdown_enable(struct bgp *bgp, const char *msg);
extern void bgp_shutdown_disable(struct bgp *bgp);

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
		case SAFI_EVPN:
		case SAFI_UNSPEC:
		case SAFI_MAX:
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
		case SAFI_EVPN:
		case SAFI_UNSPEC:
		case SAFI_MAX:
			return BGP_AF_MAX;
		}
		break;
	case AFI_L2VPN:
		switch (safi) {
		case SAFI_EVPN:
			return BGP_AF_L2VPN_EVPN;
		case SAFI_UNICAST:
		case SAFI_MULTICAST:
		case SAFI_LABELED_UNICAST:
		case SAFI_MPLS_VPN:
		case SAFI_ENCAP:
		case SAFI_FLOWSPEC:
		case SAFI_UNSPEC:
		case SAFI_MAX:
			return BGP_AF_MAX;
		}
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		return BGP_AF_MAX;
	}

	assert(!"Reached end of function we should never hit");
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

static inline char *timestamp_string(time_t ts, char *timebuf)
{
	time_t tbuf;

	tbuf = time(NULL) - (monotime(NULL) - ts);
	return ctime_r(&tbuf, timebuf);
}

static inline bool peer_established(struct peer_connection *connection)
{
	return connection->status == Established;
}

static inline bool peer_dynamic_neighbor(struct peer *peer)
{
	return CHECK_FLAG(peer->flags, PEER_FLAG_DYNAMIC_NEIGHBOR);
}

static inline bool peer_dynamic_neighbor_no_nsf(struct peer *peer)
{
	return (peer_dynamic_neighbor(peer) &&
		!CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT));
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

static inline uint32_t bgp_vrf_interfaces(struct bgp *bgp, bool active)
{
	struct vrf *vrf;
	struct interface *ifp;
	uint32_t count = 0;

	/* if there is one interface in the vrf which is up then it is deemed
	 *  active
	 */
	vrf = bgp_vrf_lookup_by_instance_type(bgp);
	if (vrf == NULL)
		return 0;
	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		if (strcmp(ifp->name, bgp->name) == 0)
			continue;
		if (!active || if_is_up(ifp))
			count++;
	}
	return count;
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

static inline bool bgp_in_graceful_shutdown(struct bgp *bgp)
{
	/* True if either set for this instance or globally */
	return (!!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN) ||
	        !!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN));
}

static inline bool bgp_in_graceful_restart(void)
{
	/* True if BGP has (re)started gracefully (based on flags
	 * noted at startup) and GR is not complete.
	 */
	return (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART) &&
		!CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE));
}

static inline bool bgp_is_graceful_restart_complete(void)
{
	/* True if BGP has (re)started gracefully (based on flags
	 * noted at startup) and GR is marked as complete.
	 */
	return (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART) &&
		CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE));
}

static inline void bgp_update_gr_completion(void)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	/*
	 * Check and mark GR complete. This is done when deferred
	 * path selection has been completed for all instances and
	 * route-advertisement/EOR and route-sync with zebra has
	 * been invoked.
	 */
	if (!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART) ||
	    CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE))
		return;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp->gr_route_sync_pending)
			return;
	}

	SET_FLAG(bm->flags, BM_FLAG_GR_COMPLETE);
	bm->gr_completion_time = monotime(NULL);
}

static inline bool bgp_gr_is_forwarding_preserved(struct bgp *bgp)
{
	/*
	 * Is forwarding state preserved? Based either on config
	 * or if BGP restarted gracefully.
	 * TBD: Additional AFI/SAFI based checks etc.
	 */
	return (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART) ||
		CHECK_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD));
}

/* For benefit of rfapi */
extern struct peer *peer_new(struct bgp *bgp);

extern struct peer *peer_lookup_in_view(struct vty *vty, struct bgp *bgp,
					const char *ip_str, bool use_json);
extern int bgp_lookup_by_as_name_type(struct bgp **bgp_val, as_t *as,
				      const char *as_pretty,
				      enum asnotation_mode asnotation,
				      const char *name,
				      enum bgp_instance_type inst_type);

/* Hooks */
DECLARE_HOOK(bgp_vrf_status_changed, (struct bgp *bgp, struct interface *ifp),
	     (bgp, ifp));
DECLARE_HOOK(peer_status_changed, (struct peer *peer), (peer));
DECLARE_HOOK(bgp_snmp_init_stats, (struct bgp *bgp), (bgp));
DECLARE_HOOK(bgp_snmp_update_last_changed, (struct bgp *bgp), (bgp));
DECLARE_HOOK(bgp_snmp_update_stats,
	     (struct bgp_dest *rn, struct bgp_path_info *pi, bool added),
	     (rn, pi, added));
DECLARE_HOOK(bgp_rpki_prefix_status,
	     (struct peer * peer, struct attr *attr,
	      const struct prefix *prefix),
	     (peer, attr, prefix));

void peer_nsf_stop(struct peer *peer);

void peer_tcp_mss_set(struct peer *peer, uint32_t tcp_mss);
void peer_tcp_mss_unset(struct peer *peer);

extern void bgp_recalculate_afi_safi_bestpaths(struct bgp *bgp, afi_t afi,
					       safi_t safi);
extern void peer_on_policy_change(struct peer *peer, afi_t afi, safi_t safi,
				  int outbound);
extern bool bgp_path_attribute_discard(struct peer *peer, char *buf,
				       size_t size);
extern bool bgp_path_attribute_treat_as_withdraw(struct peer *peer, char *buf,
						 size_t size);

extern void srv6_function_free(struct bgp_srv6_function *func);

extern void bgp_session_reset_safe(struct peer *peer, struct listnode **nnode);

#ifdef _FRR_ATTRIBUTE_PRINTFRR
/* clang-format off */
#pragma FRR printfrr_ext "%pBP" (struct peer *)
/* clang-format on */
#endif

/* Macro to check if default bgp instance is hidden */
#define IS_BGP_INSTANCE_HIDDEN(_bgp)                                           \
	(CHECK_FLAG(_bgp->flags, BGP_FLAG_INSTANCE_HIDDEN) &&                  \
	 (_bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT ||                      \
	  _bgp->inst_type == BGP_INSTANCE_TYPE_VRF))

/* Macro to check if bgp instance delete in-progress and !hidden */
#define BGP_INSTANCE_HIDDEN_DELETE_IN_PROGRESS(_bgp, _afi, _safi)              \
	(CHECK_FLAG(_bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) &&               \
	 !IS_BGP_INSTANCE_HIDDEN(_bgp) &&                                      \
	 !(_afi == AFI_IP && _safi == SAFI_MPLS_VPN) &&                        \
	 !(_afi == AFI_IP6 && _safi == SAFI_MPLS_VPN))

#endif /* _QUAGGA_BGPD_H */
