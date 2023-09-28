// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFd main header.
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 */

#ifndef _ZEBRA_OSPFD_H
#define _ZEBRA_OSPFD_H

#include <zebra.h>
#include "typesafe.h"
#include "qobj.h"
#include "libospf.h"
#include "ldp_sync.h"

#include "filter.h"
#include "log.h"
#include "vrf.h"

#include "ospf_memory.h"
#include "ospf_dump_api.h"

#define OSPF_VERSION            2

/* VTY port number. */
#define OSPF_VTY_PORT          2604

/* IP TTL for OSPF protocol. */
#define OSPF_IP_TTL             1
#define OSPF_VL_IP_TTL          100

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"

#define OSPF_NSSA_TRANS_STABLE_DEFAULT		40

#define OSPF_ALLSPFROUTERS              0xe0000005      /* 224.0.0.5 */
#define OSPF_ALLDROUTERS                0xe0000006      /* 224.0.0.6 */

/* OSPF Authentication Type. */
#define OSPF_AUTH_NULL                      0
#define OSPF_AUTH_SIMPLE                    1
#define OSPF_AUTH_CRYPTOGRAPHIC             2
/* For Interface authentication setting default */
#define OSPF_AUTH_NOTSET                   -1
/* For the consumption and sanity of the command handler */
/* DO NIOT REMOVE!!! Need to detect whether a value has
   been given or not in VLink command handlers */
#define OSPF_AUTH_CMD_NOTSEEN              -2

/* OSPF options. */
#define OSPF_OPTION_MT                   0x01  /* M/T */
#define OSPF_OPTION_E                    0x02
#define OSPF_OPTION_MC                   0x04
#define OSPF_OPTION_NP                   0x08
#define OSPF_OPTION_EA                   0x10
#define OSPF_OPTION_DC                   0x20
#define OSPF_OPTION_O                    0x40
#define OSPF_OPTION_DN                   0x80

/* OSPF Database Description flags. */
#define OSPF_DD_FLAG_MS                  0x01
#define OSPF_DD_FLAG_M                   0x02
#define OSPF_DD_FLAG_I                   0x04
#define OSPF_DD_FLAG_ALL                 0x07

#define OSPF_LS_REFRESH_SHIFT       (60 * 15)
#define OSPF_LS_REFRESH_JITTER      60

/* Default socket buffer size */
#define OSPF_DEFAULT_SOCK_BUFSIZE   (8 * 1024 * 1024)

/* OSPF config processing timer thread */
extern struct event *t_ospf_cfg;

struct ospf_external {
	unsigned short instance;
	struct route_table *external_info;
};

/* OSPF master for system wide configuration and variables. */
struct ospf_master {
	/* OSPF instance. */
	struct list *ospf;

	/* OSPF thread master. */
	struct event_loop *master;

	/* Various OSPF global configuration. */
	uint8_t options;
#define OSPF_MASTER_SHUTDOWN (1 << 0) /* deferred-shutdown */
};

struct ospf_redist {
	unsigned short instance;

	/* Redistribute metric info. */
	struct {
		int type;  /* External metric type (E1 or E2).  */
		int value; /* Value for static metric (24-bit).
			      -1 means metric value is not set. */
	} dmetric;

	/* For redistribute route map. */
	struct {
		char *name;
		struct route_map *map;
	} route_map; /* +1 is for default-information */
#define ROUTEMAP_NAME(R)   (R->route_map.name)
#define ROUTEMAP(R) (R->route_map.map)
};

/* OSPF area flood reduction info */
struct ospf_area_fr_info {
	bool enabled;       /* Area support for Flood Reduction */
	bool configured;    /* Flood Reduction configured per area knob */
	bool state_changed; /* flood reduction state change info */
	int router_lsas_recv_dc_bit; /* Number of unique router lsas
				      * received with DC bit set.
				      * (excluding self)
				      */
	bool area_ind_lsa_recvd;     /* Indication lsa received in this area */
	bool area_dc_clear;	  /* Area has atleast one lsa with dc bit 0(
				      * excluding indication lsa)
				      */
	struct ospf_lsa *indication_lsa_self; /* Indication LSA generated
					       * in the area.
					       */
};

/* ospf->config */
enum {
	OSPF_RFC1583_COMPATIBLE =	(1 << 0),
	OSPF_OPAQUE_CAPABLE =		(1 << 2),
	OSPF_LOG_ADJACENCY_CHANGES =	(1 << 3),
	OSPF_LOG_ADJACENCY_DETAIL =	(1 << 4),
	OSPF_SEND_EXTRA_DATA_TO_ZEBRA =	(1 << 5),
};

/* TI-LFA */
enum protection_type {
	OSPF_TI_LFA_UNDEFINED_PROTECTION,
	OSPF_TI_LFA_LINK_PROTECTION,
	OSPF_TI_LFA_NODE_PROTECTION,
};

/* OSPF nonstop forwarding aka Graceful Restart */
struct ospf_gr_info {
	bool restart_support;
	bool restart_in_progress;
	bool prepare_in_progress;
	bool finishing_restart;
	uint32_t grace_period;
	int reason;
	char *exit_reason;
	struct event *t_grace_period;
};

/* OSPF instance structure. */
struct ospf {
	/* OSPF's running state based on the '[no] router ospf [<instance>]'
	 * config. */
	uint8_t oi_running;

	/* OSPF instance ID  */
	unsigned short instance;

	/* OSPF Router ID. */
	struct in_addr router_id;	/* Configured automatically. */
	struct in_addr router_id_static; /* Configured manually. */
	struct in_addr router_id_zebra;

	vrf_id_t vrf_id; /* VRF Id */
	char *name;      /* VRF name */

	/* ABR/ASBR internal flags. */
	uint8_t flags;
#define OSPF_FLAG_ABR           0x0001
#define OSPF_FLAG_ASBR          0x0002

	/* ABR type. */
	uint8_t abr_type;
#define OSPF_ABR_UNKNOWN	0
#define OSPF_ABR_STAND          1
#define OSPF_ABR_IBM            2
#define OSPF_ABR_CISCO          3
#define OSPF_ABR_SHORTCUT       4
#define OSPF_ABR_DEFAULT	OSPF_ABR_CISCO

	/* NSSA ABR */
	uint8_t anyNSSA; /* Bump for every NSSA attached. */

	/* Configuration bitmask, refer to enum above */
	uint8_t config;

	/* Opaque-LSA administrative flags. */
	uint8_t opaque;
#define OPAQUE_OPERATION_READY_BIT	(1 << 0)

	/* RFC3137 stub router. Configured time to stay stub / max-metric */
	unsigned int stub_router_startup_time;  /* seconds */
	unsigned int stub_router_shutdown_time; /* seconds */
#define OSPF_STUB_ROUTER_UNCONFIGURED	  0
	uint8_t stub_router_admin_set;
#define OSPF_STUB_ROUTER_ADMINISTRATIVE_SET     1
#define OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET   0

#define OSPF_STUB_MAX_METRIC_SUMMARY_COST	0x00ff0000

	/* LSA timers */
	unsigned int min_ls_interval; /* minimum delay between LSAs (in msec) */
	unsigned int min_ls_arrival;  /* minimum interarrival time between LSAs
					 (in msec) */

	/* SPF parameters */
	unsigned int spf_delay;	/* SPF delay time. */
	unsigned int spf_holdtime;     /* SPF hold time. */
	unsigned int spf_max_holdtime; /* SPF maximum-holdtime */
	unsigned int
		spf_hold_multiplier; /* Adaptive multiplier for hold time */

	int default_originate;	/* Default information originate. */
#define DEFAULT_ORIGINATE_NONE		0
#define DEFAULT_ORIGINATE_ZEBRA		1
#define DEFAULT_ORIGINATE_ALWAYS	2
	uint32_t ref_bandwidth;       /* Reference Bandwidth (Kbps). */
	struct route_table *networks; /* OSPF config networks. */
	struct list *vlinks;	  /* Configured Virtual-Links. */
	struct list *areas;	   /* OSPF areas. */
	struct route_table *nbr_nbma;
	struct ospf_area *backbone; /* Pointer to the Backbone Area. */

	struct list *oiflist;		  /* ospf interfaces */
	uint8_t passive_interface_default; /* passive-interface default */

	/* LSDB of AS-external-LSAs. */
	struct ospf_lsdb *lsdb;

	/* Flags. */
	int ase_calc;	/* ASE calculation flag. */

	struct list *opaque_lsa_self; /* Type-11 Opaque-LSAs */

	/* Routing tables. */
	struct route_table *old_table; /* Old routing table. */
	struct route_table *new_table; /* Current routing table. */

	struct route_table *oall_rtrs; /* Old router RT. */
	struct route_table *all_rtrs;  /* New routers RT. */

	struct route_table *old_rtrs; /* Old ABR/ASBR RT. */
	struct route_table *new_rtrs; /* New ABR/ASBR RT. */

	struct route_table *new_external_route; /* New External Route. */
	struct route_table *old_external_route; /* Old External Route. */

	struct route_table *external_lsas; /* Database of external LSAs,
					      prefix is LSA's adv. network*/

	/* Time stamps */
	struct timeval ts_spf;		/* SPF calculation time stamp. */
	struct timeval ts_spf_duration; /* Execution time of last SPF */

	struct route_table *maxage_lsa; /* List of MaxAge LSA for deletion. */
	int redistribute;		/* Num of redistributed protocols. */

	/* Threads. */
	struct event *t_abr_task;		 /* ABR task timer. */
	struct event *t_abr_fr;			 /* ABR FR timer. */
	struct event *t_asbr_check;		 /* ASBR check timer. */
	struct event *t_asbr_redist_update; /* ASBR redistribution update
					       timer. */
	struct event *t_distribute_update; /* Distirbute list update timer. */
	struct event *t_spf_calc;	   /* SPF calculation timer. */
	struct event *t_ase_calc;	   /* ASE calculation timer. */
	struct event *t_opaque_lsa_self; /* Type-11 Opaque-LSAs origin event. */
	struct event *t_sr_update;	 /* Segment Routing update timer */

	unsigned int maxage_delay;      /* Delay on Maxage remover timer, sec */
	struct event *t_maxage;		/* MaxAge LSA remover timer. */
	struct event *t_maxage_walker;	/* MaxAge LSA checking timer. */

	struct event
		*t_deferred_shutdown; /* deferred/stub-router shutdown timer*/

	struct event *t_write;
#define OSPF_WRITE_INTERFACE_COUNT_DEFAULT    20
	struct event *t_default_routemap_timer;

	int write_oi_count; /* Num of packets sent per thread invocation */
	struct event *t_read;
	int fd;
	struct stream *ibuf;
	struct list *oi_write_q;

	/* Distribute lists out of other route sources. */
	struct {
		char *name;
		struct access_list *list;
	} dlist[ZEBRA_ROUTE_MAX];
#define DISTRIBUTE_NAME(O,T)    (O)->dlist[T].name
#define DISTRIBUTE_LIST(O,T)    (O)->dlist[T].list

	/* OSPF redistribute configuration */
	struct list *redist[ZEBRA_ROUTE_MAX + 1];

	/* Redistribute tag info. */
	route_tag_t
		dtag[ZEBRA_ROUTE_MAX + 1]; // Pending: cant configure as of now

	int default_metric; /* Default metric for redistribute. */

	/* NSSA default-information-originate */
	struct {
		/* # of NSSA areas requesting default information */
		uint16_t refcnt;

		/*
		 * Whether a default route known through non-OSPF protocol is
		 * present in the RIB.
		 */
		bool status;
	} nssa_default_import_check;

#define OSPF_LSA_REFRESHER_GRANULARITY 10
#define OSPF_LSA_REFRESHER_SLOTS                                               \
	((OSPF_LS_REFRESH_TIME + OSPF_LS_REFRESH_SHIFT)                        \
		 / OSPF_LSA_REFRESHER_GRANULARITY                              \
	 + 1)
	struct {
		uint16_t index;
		struct list *qs[OSPF_LSA_REFRESHER_SLOTS];
	} lsa_refresh_queue;

	struct event *t_lsa_refresher;
	time_t lsa_refresher_started;
#define OSPF_LSA_REFRESH_INTERVAL_DEFAULT 10
	uint16_t lsa_refresh_interval;
	uint16_t lsa_refresh_timer;

	/* Distance parameter. */
	uint8_t distance_all;
	uint8_t distance_intra;
	uint8_t distance_inter;
	uint8_t distance_external;

	/* Statistics for LSA origination. */
	uint32_t lsa_originate_count;

	/* Statistics for LSA used for new instantiation. */
	uint32_t rx_lsa_count;

	struct route_table *distance_table;

	/* Used during ospf instance going down send LSDB
	 * update to neighbors immediatly */
	uint8_t inst_shutdown;

	/* Enable or disable sending proactive ARP requests. */
	bool proactive_arp;
#define OSPF_PROACTIVE_ARP_DEFAULT true

	/* Redistributed external information. */
	struct list *external[ZEBRA_ROUTE_MAX + 1];
#define EXTERNAL_INFO(E) (E->external_info)

	/* Graceful restart Helper supported configs*/
	/* Supported grace interval*/
	uint32_t supported_grace_time;

	/* Helper support
	 * Supported : True
	 * Not Supported : False.
	 */
	bool is_helper_supported;

	/* Support for strict LSA check.
	 * if it is set,Helper aborted
	 * upon a TOPO change.
	 */
	bool strict_lsa_check;

	/* Support as HELPER only for
	 * planned restarts.
	 */
	bool only_planned_restart;

	/* This list contains the advertisement
	 * routerids which are not support for HELPERs.
	 */
	struct hash *enable_rtr_list;

	/* HELPER for number of active
	 * RESTARTERs.
	 */
	uint16_t active_restarter_cnt;

	/* last HELPER exit reason */
	uint32_t last_exit_reason;

	/* delay timer to process external routes
	 * with summary address.
	 */
	struct event *t_external_aggr;

	/* delay interval in seconds */
	uint16_t aggr_delay_interval;

	/* Table of configured Aggregate addresses */
	struct route_table *rt_aggr_tbl;

	/* used as argument for aggr delay
	 * timer thread.
	 */
	int aggr_action;

	/* Max number of multiple paths
	 * to support ECMP.
	 */
	uint16_t max_multipath;

	/* MPLS LDP-IGP Sync */
	struct ldp_sync_info_cmd ldp_sync_cmd;

	/* OSPF Graceful Restart info */
	struct ospf_gr_info gr_info;

	/* TI-LFA support for all interfaces. */
	bool ti_lfa_enabled;
	enum protection_type ti_lfa_protection_type;

	/* Flood Reduction configuration state */
	bool fr_configured;

	/* Socket buffer sizes */
	uint32_t recv_sock_bufsize;
	uint32_t send_sock_bufsize;

	/* Per-interface write socket */
	bool intf_socket_enabled;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(ospf);

enum ospf_ti_lfa_p_q_space_adjacency {
	OSPF_TI_LFA_P_Q_SPACE_ADJACENT,
	OSPF_TI_LFA_P_Q_SPACE_NON_ADJACENT,
};

enum ospf_ti_lfa_node_type {
	OSPF_TI_LFA_UNDEFINED_NODE,
	OSPF_TI_LFA_PQ_NODE,
	OSPF_TI_LFA_P_NODE,
	OSPF_TI_LFA_Q_NODE,
};

struct ospf_ti_lfa_node_info {
	struct vertex *node;
	enum ospf_ti_lfa_node_type type;
	struct in_addr nexthop;
};

struct ospf_ti_lfa_inner_backup_path_info {
	struct ospf_ti_lfa_node_info p_node_info;
	struct ospf_ti_lfa_node_info q_node_info;
	struct mpls_label_stack *label_stack;
};

struct protected_resource {
	enum protection_type type;

	/* Link Protection */
	struct router_lsa_link *link;

	/* Node Protection */
	struct in_addr router_id;
};

PREDECL_RBTREE_UNIQ(q_spaces);
struct q_space {
	struct vertex *root;
	struct list *vertex_list;
	struct mpls_label_stack *label_stack;
	struct in_addr nexthop;
	struct list *pc_path;
	struct ospf_ti_lfa_node_info *p_node_info;
	struct ospf_ti_lfa_node_info *q_node_info;
	struct q_spaces_item q_spaces_item;
};

PREDECL_RBTREE_UNIQ(p_spaces);
struct p_space {
	struct vertex *root;
	struct protected_resource *protected_resource;
	struct q_spaces_head *q_spaces;
	struct list *vertex_list;
	struct vertex *pc_spf;
	struct list *pc_vertex_list;
	struct p_spaces_item p_spaces_item;
};

/* OSPF area structure. */
struct ospf_area {
	/* OSPF instance. */
	struct ospf *ospf;

	/* Zebra interface list belonging to the area. */
	struct list *oiflist;

	/* Area ID. */
	struct in_addr area_id;

	/* Area ID format. */
	int area_id_fmt;
#define OSPF_AREA_ID_FMT_DOTTEDQUAD     1
#define OSPF_AREA_ID_FMT_DECIMAL        2

	/* Address range. */
	struct list *address_range;

	/* Configured variables. */
	int external_routing;    /* ExternalRoutingCapability. */
	int no_summary;		 /* Don't inject summaries into stub.*/
	int shortcut_configured; /* Area configured as shortcut. */
#define OSPF_SHORTCUT_DEFAULT	0
#define OSPF_SHORTCUT_ENABLE	1
#define OSPF_SHORTCUT_DISABLE	2
	int shortcut_capability; /* Other ABRs agree on S-bit */
	uint32_t default_cost;   /* StubDefaultCost. */
	int auth_type;		 /* Authentication type. */
	int suppress_fa;	 /* Suppress forwarding address in NSSA ABR */

	uint8_t NSSATranslatorRole; /* NSSA configured role */
#define OSPF_NSSA_ROLE_NEVER     0
#define OSPF_NSSA_ROLE_CANDIDATE 1
#define OSPF_NSSA_ROLE_ALWAYS    2
	uint8_t NSSATranslatorState; /* NSSA operational role */
#define OSPF_NSSA_TRANSLATE_DISABLED 0
#define OSPF_NSSA_TRANSLATE_ENABLED  1
	int NSSATranslatorStabilityInterval;

	uint8_t transit; /* TransitCapability. */
#define OSPF_TRANSIT_FALSE      0
#define OSPF_TRANSIT_TRUE       1
	struct route_table *ranges; /* Configured Area Ranges. */
	struct route_table *nssa_ranges; /* Configured NSSA Area Ranges. */

	/* RFC3137 stub router state flags for area */
	uint8_t stub_router_state;
#define OSPF_AREA_ADMIN_STUB_ROUTED	(1 << 0) /* admin stub-router set */
#define OSPF_AREA_IS_STUB_ROUTED	(1 << 1) /* stub-router active */
#define OSPF_AREA_WAS_START_STUB_ROUTED	(1 << 2) /* startup SR was done */
	/* Area related LSDBs[Type1-4]. */
	struct ospf_lsdb *lsdb;

	/* Self-originated LSAs. */
	struct ospf_lsa *router_lsa_self;
	struct list *opaque_lsa_self; /* Type-10 Opaque-LSAs */

	/* Area announce list. */
	struct {
		char *name;
		struct access_list *list;
	} _export;
#define EXPORT_NAME(A)  (A)->_export.name
#define EXPORT_LIST(A)  (A)->_export.list

	/* Area acceptance list. */
	struct {
		char *name;
		struct access_list *list;
	} import;
#define IMPORT_NAME(A)  (A)->import.name
#define IMPORT_LIST(A)  (A)->import.list

	/* Type 3 LSA Area prefix-list. */
	struct {
		char *name;
		struct prefix_list *list;
	} plist_in;
#define PREFIX_LIST_IN(A)   (A)->plist_in.list
#define PREFIX_NAME_IN(A)   (A)->plist_in.name

	struct {
		char *name;
		struct prefix_list *list;
	} plist_out;
#define PREFIX_LIST_OUT(A)  (A)->plist_out.list
#define PREFIX_NAME_OUT(A)  (A)->plist_out.name

	/* NSSA default-information-originate */
	struct {
		bool enabled;
		int metric_type;
		int metric_value;
	} nssa_default_originate;

	/* Shortest Path Tree. */
	struct vertex *spf;
	struct list *spf_vertex_list;

	bool spf_dry_run;   /* flag for checking if the SPF calculation is
			       intended for the local RIB */
	bool spf_root_node; /* flag for checking if the calculating node is the
			       root node of the SPF tree */

	/* TI-LFA protected link for SPF calculations */
	struct protected_resource *spf_protected_resource;

	/* P/Q spaces for TI-LFA */
	struct p_spaces_head *p_spaces;

	/* Threads. */
	struct event *t_stub_router;	 /* Stub-router timer */
	struct event *t_opaque_lsa_self; /* Type-10 Opaque-LSAs origin. */

	/* Statistics field. */
	uint32_t spf_calculation; /* SPF Calculation Count. */

	/* reverse SPF (used for TI-LFA Q spaces) */
	bool spf_reversed;

	/* Time stamps. */
	struct timeval ts_spf; /* SPF calculation time stamp. */

	/* Router count. */
	uint32_t abr_count;  /* ABR router in this area. */
	uint32_t asbr_count; /* ASBR router in this area. */

	/* Counters. */
	uint32_t act_ints;  /* Active interfaces. */
	uint32_t full_nbrs; /* Fully adjacent neighbors. */
	uint32_t full_vls;  /* Fully adjacent virtual neighbors. */

	struct ospf_area_fr_info fr_info; /* Flood reduction info. */
};

/* OSPF config network structure. */
struct ospf_network {
	/* Area ID. */
	struct in_addr area_id;
	int area_id_fmt;
};

/* OSPF NBMA neighbor structure. */
struct ospf_nbr_nbma {
	/* Neighbor IP address. */
	struct in_addr addr;

	/* OSPF interface. */
	struct ospf_interface *oi;

	/* OSPF neighbor structure. */
	struct ospf_neighbor *nbr;

	/* Neighbor priority. */
	uint8_t priority;

	/* Poll timer value. */
	uint32_t v_poll;

	/* Poll timer thread. */
	struct event *t_poll;

	/* State change. */
	uint32_t state_change;
};

/* Macro. */
#define OSPF_AREA_SAME(X, Y)                                                   \
	(memcmp((X->area_id), (Y->area_id), IPV4_MAX_BYTELEN) == 0)

#define IS_OSPF_ABR(O)		((O)->flags & OSPF_FLAG_ABR)
#define IS_OSPF_ASBR(O)		((O)->flags & OSPF_FLAG_ASBR)

#define OSPF_IS_AREA_ID_BACKBONE(I) ((I).s_addr == OSPF_AREA_BACKBONE)
#define OSPF_IS_AREA_BACKBONE(A) OSPF_IS_AREA_ID_BACKBONE ((A)->area_id)

#ifdef roundup
#  define ROUNDUP(val, gran)	roundup(val, gran)
#else  /* roundup */
#  define ROUNDUP(val, gran)	(((val) - 1 | (gran) - 1) + 1)
#endif /* roundup */

#define LSA_OPTIONS_GET(area)                                                  \
	(((area)->external_routing == OSPF_AREA_DEFAULT) ? OSPF_OPTION_E : 0)
#define LSA_OPTIONS_NSSA_GET(area)                                             \
	(((area)->external_routing == OSPF_AREA_NSSA) ? OSPF_OPTION_NP : 0)

#define OSPF_TIMER_ON(T, F, V) event_add_timer(master, (F), ospf, (V), &(T))
#define OSPF_AREA_TIMER_ON(T, F, V)                                            \
	event_add_timer(master, (F), area, (V), &(T))
#define OSPF_POLL_TIMER_ON(T, F, V)                                            \
	event_add_timer(master, (F), nbr_nbma, (V), &(T))

/* Extern variables. */
extern struct ospf_master *om;
extern unsigned short ospf_instance;
extern const int ospf_redistributed_proto_max;
extern struct zclient *zclient;
extern struct event_loop *master;
extern int ospf_zlog;
extern struct zebra_privs_t ospfd_privs;

/* Prototypes. */
extern const char *ospf_redist_string(unsigned int route_type);
extern struct ospf *ospf_lookup_instance(unsigned short instance);
extern struct ospf *ospf_lookup(unsigned short instance, const char *name);
extern struct ospf *ospf_get(unsigned short instance, const char *name,
			     bool *created);
extern struct ospf *ospf_new_alloc(unsigned short instance, const char *name);
extern struct ospf *ospf_lookup_by_inst_name(unsigned short instance,
					     const char *name);
extern struct ospf *ospf_lookup_by_vrf_id(vrf_id_t vrf_id);
extern uint32_t ospf_count_area_params(struct ospf *ospf);
extern void ospf_finish(struct ospf *ospf);
extern void ospf_process_refresh_data(struct ospf *ospf, bool reset);
extern void ospf_router_id_update(struct ospf *ospf);
extern void ospf_process_reset(struct ospf *ospf);
extern void ospf_neighbor_reset(struct ospf *ospf, struct in_addr nbr_id,
				const char *nbr_str);
extern int ospf_network_set(struct ospf *ospf, struct prefix_ipv4 *p,
			    struct in_addr area_id, int df);
extern int ospf_network_unset(struct ospf *ospf, struct prefix_ipv4 *p,
			      struct in_addr aread_id);
extern int ospf_area_display_format_set(struct ospf *ospf,
					struct ospf_area *area, int df);
extern int ospf_area_stub_set(struct ospf *ospf, struct in_addr area_id);
extern int ospf_area_stub_unset(struct ospf *ospf, struct in_addr area_id);
extern int ospf_area_no_summary_set(struct ospf *ospf, struct in_addr area_id);
extern int ospf_area_no_summary_unset(struct ospf *ospf,
				      struct in_addr area_id);
extern int ospf_area_nssa_set(struct ospf *ospf, struct in_addr area_id);
extern int ospf_area_nssa_unset(struct ospf *ospf, struct in_addr area_id);
extern int ospf_area_nssa_suppress_fa_set(struct ospf *ospf,
					  struct in_addr area_id);
extern int ospf_area_nssa_suppress_fa_unset(struct ospf *ospf,
					    struct in_addr area_id);
extern int ospf_area_nssa_translator_role_set(struct ospf *ospf,
					      struct in_addr area_id, int role);
extern void ospf_area_nssa_default_originate_set(struct ospf *ospf,
						 struct in_addr area_id,
						 int metric, int metric_type);
extern void ospf_area_nssa_default_originate_unset(struct ospf *ospf,
						   struct in_addr area_id);
extern int ospf_area_export_list_set(struct ospf *ospf,
				     struct ospf_area *area_id,
				     const char *list_name);
extern int ospf_area_export_list_unset(struct ospf *ospf,
				       struct ospf_area *area_id);
extern int ospf_area_import_list_set(struct ospf *ospf,
				     struct ospf_area *area_id,
				     const char *name);
extern int ospf_area_import_list_unset(struct ospf *ospf,
				       struct ospf_area *area_id);
extern int ospf_area_shortcut_set(struct ospf *ospf, struct ospf_area *area_id,
				  int mode);
extern int ospf_area_shortcut_unset(struct ospf *ospf,
				    struct ospf_area *area_id);
extern int ospf_timers_refresh_set(struct ospf *ospf, int interval);
extern int ospf_timers_refresh_unset(struct ospf *ospf);
void ospf_area_lsdb_discard_delete(struct ospf_area *area);
extern int ospf_nbr_nbma_set(struct ospf *ospf, struct in_addr nbr_addr);
extern int ospf_nbr_nbma_unset(struct ospf *ospf, struct in_addr nbr_addr);
extern int ospf_nbr_nbma_priority_set(struct ospf *ospf,
				      struct in_addr nbr_addr,
				      uint8_t priority);
extern int ospf_nbr_nbma_priority_unset(struct ospf *ospf,
					struct in_addr nbr_addr);
extern int ospf_nbr_nbma_poll_interval_set(struct ospf *ospf,
					   struct in_addr nbr_addr,
					   unsigned int interval);
extern int ospf_nbr_nbma_poll_interval_unset(struct ospf *ospf,
					     struct in_addr addr);
extern void ospf_if_update(struct ospf *ospf, struct interface *ifp);
extern void ospf_ls_upd_queue_empty(struct ospf_interface *oi);
extern void ospf_terminate(void);
extern void ospf_nbr_nbma_if_update(struct ospf *ospf,
				    struct ospf_interface *oi);
extern struct ospf_nbr_nbma *ospf_nbr_nbma_lookup(struct ospf *ospf,
						  struct in_addr nbr_addr);
extern int ospf_oi_count(struct interface *ifp);

extern struct ospf_area *ospf_area_new(struct ospf *ospf,
				       struct in_addr area_id);
extern struct ospf_area *ospf_area_get(struct ospf *ospf,
				       struct in_addr area_id);
extern void ospf_area_check_free(struct ospf *ospf, struct in_addr area_id);
extern struct ospf_area *ospf_area_lookup_by_area_id(struct ospf *ospf,
						     struct in_addr area_id);
extern void ospf_area_add_if(struct ospf_area *oa, struct ospf_interface *oi);
extern void ospf_area_del_if(struct ospf_area *oa, struct ospf_interface *oi);

extern void ospf_interface_area_set(struct ospf *ospf, struct interface *ifp);
extern void ospf_interface_area_unset(struct ospf *ospf, struct interface *ifp);

extern void ospf_route_map_init(void);

extern void ospf_master_init(struct event_loop *master);
extern void ospf_vrf_init(void);
extern void ospf_vrf_terminate(void);
extern void ospf_vrf_link(struct ospf *ospf, struct vrf *vrf);
extern void ospf_vrf_unlink(struct ospf *ospf, struct vrf *vrf);
const char *ospf_vrf_id_to_name(vrf_id_t vrf_id);
int ospf_area_nssa_no_summary_set(struct ospf *ospf, struct in_addr area_id);

const char *ospf_get_name(const struct ospf *ospf);
extern struct ospf_interface *add_ospf_interface(struct connected *co,
						 struct ospf_area *area);
/* Update socket bufsize(s), after config change */
void ospf_update_bufsize(struct ospf *ospf, uint32_t recvsize,
			 uint32_t sendsize);

extern int p_spaces_compare_func(const struct p_space *a,
				 const struct p_space *b);
extern int q_spaces_compare_func(const struct q_space *a,
				 const struct q_space *b);

#endif /* _ZEBRA_OSPFD_H */
