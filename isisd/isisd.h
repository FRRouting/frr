// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isisd.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef ISISD_H
#define ISISD_H

#include "vty.h"
#include "memory.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_redist.h"
#include "isisd/isis_pdu_counter.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_srv6.h"
#include "isis_flags.h"
#include "isis_lsp.h"
#include "isis_lfa.h"
#include "qobj.h"
#include "ldp_sync.h"
#include "iso.h"

DECLARE_MGROUP(ISISD);

#ifdef FABRICD
static const bool fabricd = true;
#define PROTO_TYPE ZEBRA_ROUTE_OPENFABRIC
#define PROTO_NAME "openfabric"
#define PROTO_HELP "OpenFabric routing protocol\n"
#define PROTO_REDIST_STR FRR_REDIST_STR_FABRICD
#define PROTO_IP_REDIST_STR FRR_IP_REDIST_STR_FABRICD
#define PROTO_IP6_REDIST_STR FRR_IP6_REDIST_STR_FABRICD
#define PROTO_REDIST_HELP FRR_REDIST_HELP_STR_FABRICD
#define PROTO_IP_REDIST_HELP FRR_IP_REDIST_HELP_STR_FABRICD
#define PROTO_IP6_REDIST_HELP FRR_IP6_REDIST_HELP_STR_FABRICD
#define ROUTER_NODE OPENFABRIC_NODE
#else
static const bool fabricd = false;
#define PROTO_TYPE ZEBRA_ROUTE_ISIS
#define PROTO_NAME "isis"
#define PROTO_HELP "IS-IS routing protocol\n"
#define PROTO_REDIST_STR FRR_REDIST_STR_ISISD
#define PROTO_IP_REDIST_STR FRR_IP_REDIST_STR_ISISD
#define PROTO_IP6_REDIST_STR FRR_IP6_REDIST_STR_ISISD
#define PROTO_REDIST_HELP FRR_REDIST_HELP_STR_ISISD
#define PROTO_IP_REDIST_HELP FRR_IP_REDIST_HELP_STR_ISISD
#define PROTO_IP6_REDIST_HELP FRR_IP6_REDIST_HELP_STR_ISISD
#define ROUTER_NODE ISIS_NODE
extern void isis_cli_init(void);
#endif

#define ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf)             \
	if (argv_find(argv, argc, "vrf", &idx_vrf)) {                          \
		vrf_name = argv[idx_vrf + 1]->arg;                             \
		all_vrf = strmatch(vrf_name, "all");                           \
	}

extern struct zebra_privs_t isisd_privs;

/* uncomment if you are a developer in bug hunt */
/* #define EXTREME_DEBUG  */

struct fabricd;

struct isis_master {
	/* ISIS instance. */
	struct list *isis;
	/* ISIS thread master. */
	struct event_loop *master;
	uint8_t options;
};
#define F_ISIS_UNIT_TEST 0x01

#define ISIS_DEFAULT_MAX_AREA_ADDRESSES 3

struct isis {
	vrf_id_t vrf_id;
	char *name;
	unsigned long process_id;
	int sysid_set;
	uint8_t sysid[ISIS_SYS_ID_LEN]; /* SystemID for this IS */
	uint32_t router_id;		/* Router ID from zebra */
	struct list *area_list;	/* list of IS-IS areas */
	uint8_t max_area_addrs;		  /* maximumAreaAdresses */
	struct iso_address *man_area_addrs; /* manualAreaAddresses */
	time_t uptime;			  /* when did we start */
	struct event *t_dync_clean; /* dynamic hostname cache cleanup thread */
	uint32_t circuit_ids_used[8];     /* 256 bits to track circuit ids 1 through 255 */
	int snmp_notifications;
	struct list *dyn_cache;

	struct route_table *ext_info[REDIST_PROTOCOL_COUNT];
};

extern struct isis_master *im;

extern struct event *t_isis_cfg;

enum spf_tree_id {
	SPFTREE_IPV4 = 0,
	SPFTREE_IPV6,
	SPFTREE_DSTSRC,
	SPFTREE_COUNT
};

struct lsp_refresh_arg {
	struct isis_area *area;
	int level;
};

/* for yang configuration */
enum isis_metric_style {
	ISIS_NARROW_METRIC = 0,
	ISIS_WIDE_METRIC,
	ISIS_TRANSITION_METRIC,
};

struct isis_area {
	struct isis *isis;			       /* back pointer */
	struct lspdb_head lspdb[ISIS_LEVELS];	       /* link-state dbs */
	struct isis_spftree *spftree[SPFTREE_COUNT][ISIS_LEVELS];
#define DEFAULT_LSP_MTU 1497
	unsigned int lsp_mtu;      /* Size of LSPs to generate */
	struct list *circuit_list; /* IS-IS circuits */
	struct list *adjacency_list; /* IS-IS adjacencies */
	struct flags flags;
	struct event *t_tick; /* LSP walker */
	struct event *t_lsp_refresh[ISIS_LEVELS];
	struct event *t_overload_on_startup_timer;
	struct timeval last_lsp_refresh_event[ISIS_LEVELS];
	struct event *t_rlfa_rib_update;
	/* t_lsp_refresh is used in two ways:
	 * a) regular refresh of LSPs
	 * b) (possibly throttled) updates to LSPs
	 *
	 * The lsp_regenerate_pending flag tracks whether the timer is active
	 * for the a) or the b) case.
	 *
	 * It is of utmost importance to clear this flag when the timer is
	 * rescheduled for normal refresh, because otherwise, updates will
	 * be delayed until the next regular refresh.
	 */
	int lsp_regenerate_pending[ISIS_LEVELS];

	bool bfd_signalled_down;
	bool bfd_force_spf_refresh;

	struct fabricd *fabricd;

	/*
	 * Configurables
	 */
	struct isis_passwd area_passwd;
	struct isis_passwd domain_passwd;
	/* do we support dynamic hostnames?  */
	char dynhostname;
	/* do we support new style metrics?  */
	char newmetric;
	char oldmetric;
	/* Allow sending the default admin-group value of 0x00000000. */
	bool admin_group_send_zero;
	/* Set the legacy flag (aka. L-FLAG) in the ASLA Sub-TLV */
	bool asla_legacy_flag;
	/* identifies the routing instance   */
	char *area_tag;
	/* area addresses for this area      */
	struct list *area_addrs;
	uint16_t max_lsp_lifetime[ISIS_LEVELS];
	char is_type; /* level-1 level-1-2 or level-2-only */
	/* are we overloaded? */
	char overload_bit;
	bool overload_configured;
	uint32_t overload_counter;
	uint32_t overload_on_startup_time;
	/* advertise prefixes of passive interfaces only? */
	bool advertise_passive_only;
	/* Are we advertising high metrics? */
	bool advertise_high_metrics;
	/* L1/L2 router identifier for inter-area traffic */
	char attached_bit_send;
	char attached_bit_rcv_ignore;
	uint16_t lsp_refresh[ISIS_LEVELS];
	/* minimum time allowed before lsp retransmission */
	uint16_t lsp_gen_interval[ISIS_LEVELS];
	/* min interval between between consequtive SPFs */
	uint16_t min_spf_interval[ISIS_LEVELS];
	/* the percentage of LSP mtu size used, before generating a new frag */
	int lsp_frag_threshold;
	uint64_t lsp_gen_count[ISIS_LEVELS];
	uint64_t lsp_purge_count[ISIS_LEVELS];
	uint32_t lsp_exceeded_max_counter;
	uint32_t lsp_seqno_skipped_counter;
	uint64_t spf_run_count[ISIS_LEVELS];
	int ip_circuits;
	/* logging adjacency changes? */
	uint8_t log_adj_changes;
	/* logging pdu drops? */
	uint8_t log_pdu_drops;
	/* multi topology settings */
	struct list *mt_settings;
	/* MPLS-TE settings */
	struct mpls_te_area *mta;
	/* Segment Routing information */
	struct isis_sr_db srdb;
	/* Segment Routing over IPv6 (SRv6) information */
	struct isis_srv6_db srv6db;
	int ipv6_circuits;
	bool purge_originator;
	/* SPF prefix priorities. */
	struct spf_prefix_priority_acl
		spf_prefix_priorities[SPF_PREFIX_PRIO_MAX];
	/* Fast Re-Route information. */
	size_t lfa_protected_links[ISIS_LEVELS];
	size_t lfa_load_sharing[ISIS_LEVELS];
	enum spf_prefix_priority lfa_priority_limit[ISIS_LEVELS];
	struct lfa_tiebreaker_tree_head lfa_tiebreakers[ISIS_LEVELS];
	char *rlfa_plist_name[ISIS_LEVELS];
	struct prefix_list *rlfa_plist[ISIS_LEVELS];
	size_t rlfa_protected_links[ISIS_LEVELS];
	size_t tilfa_protected_links[ISIS_LEVELS];
	/* MPLS LDP-IGP Sync */
	struct ldp_sync_info_cmd ldp_sync_cmd;
#ifndef FABRICD
	/* Flex-Algo */
	struct flex_algos *flex_algos;
#endif /* ifndef FABRICD */
	/* Counters */
	uint32_t circuit_state_changes;
	struct list *redist_settings[REDIST_PROTOCOL_COUNT][ZEBRA_ROUTE_MAX + 1]
				    [ISIS_LEVELS];
	struct route_table *ext_reach[REDIST_PROTOCOL_COUNT][ISIS_LEVELS];

	struct spf_backoff *spf_delay_ietf[ISIS_LEVELS]; /*Structure with IETF
							    SPF algo
							    parameters*/
	struct event *spf_timer[ISIS_LEVELS];

	struct lsp_refresh_arg lsp_refresh_arg[ISIS_LEVELS];

	pdu_counter_t pdu_tx_counters;
	pdu_counter_t pdu_rx_counters;
	pdu_counter_t pdu_drop_counters;
	uint64_t lsp_rxmt_count;

	/* Area counters */
	uint64_t rej_adjacencies[2];
	uint64_t auth_type_failures[2];
	uint64_t auth_failures[2];
	uint64_t id_len_mismatches[2];
	uint64_t lsp_error_counter[2];

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(isis_area);

DECLARE_MTYPE(ISIS_ACL_NAME);	/* isis_area->spf_prefix_prioritites */
DECLARE_MTYPE(ISIS_AREA_ADDR);	/* isis_area->area_addrs */
DECLARE_MTYPE(ISIS_PLIST_NAME);

DECLARE_HOOK(isis_area_overload_bit_update, (struct isis_area * area), (area));

void isis_terminate(void);
void isis_master_init(struct event_loop *master);
void isis_vrf_link(struct isis *isis, struct vrf *vrf);
void isis_vrf_unlink(struct isis *isis, struct vrf *vrf);
struct isis *isis_lookup_by_vrfid(vrf_id_t vrf_id);
struct isis *isis_lookup_by_vrfname(const char *vrfname);
struct isis *isis_lookup_by_sysid(const uint8_t *sysid);

void isis_init(void);
void isis_vrf_init(void);

struct isis *isis_new(const char *vrf_name);
void isis_finish(struct isis *isis);

void isis_area_add_circuit(struct isis_area *area,
			   struct isis_circuit *circuit);
void isis_area_del_circuit(struct isis_area *area,
			   struct isis_circuit *circuit);

struct isis_area *isis_area_create(const char *, const char *);
struct isis_area *isis_area_lookup(const char *, vrf_id_t vrf_id);
struct isis_area *isis_area_lookup_by_vrf(const char *area_tag,
					  const char *vrf_name);
int isis_area_get(struct vty *vty, const char *area_tag);
void isis_area_destroy(struct isis_area *area);
void isis_filter_update(struct access_list *access);
void isis_prefix_list_update(struct prefix_list *plist);
void print_debug(struct vty *, int, int);
struct isis_lsp *lsp_for_sysid(struct lspdb_head *head, const char *sysid_str,
			       struct isis *isis);

void isis_area_invalidate_routes(struct isis_area *area, int levels);
void isis_area_verify_routes(struct isis_area *area);
void isis_area_switchover_routes(struct isis_area *area, int family,
				 union g_addr *nexthop_ip, ifindex_t ifindex,
				 int level);

void isis_area_overload_bit_set(struct isis_area *area, bool overload_bit);
void isis_area_overload_on_startup_set(struct isis_area *area,
				       uint32_t startup_time);
void isis_area_advertise_high_metrics_set(struct isis_area *area,
					  bool advertise_high_metrics);
void isis_area_attached_bit_send_set(struct isis_area *area, bool attached_bit);
void isis_area_attached_bit_receive_set(struct isis_area *area,
					bool attached_bit);
void isis_area_dynhostname_set(struct isis_area *area, bool dynhostname);
void isis_area_metricstyle_set(struct isis_area *area, bool old_metric,
			       bool new_metric);
void isis_area_lsp_mtu_set(struct isis_area *area, unsigned int lsp_mtu);
void isis_area_is_type_set(struct isis_area *area, int is_type);
void isis_area_max_lsp_lifetime_set(struct isis_area *area, int level,
				    uint16_t max_lsp_lifetime);
void isis_area_lsp_refresh_set(struct isis_area *area, int level,
			       uint16_t lsp_refresh);
/* IS_LEVEL_1 sets area_passwd, IS_LEVEL_2 domain_passwd */
int isis_area_passwd_unset(struct isis_area *area, int level);
int isis_area_passwd_cleartext_set(struct isis_area *area, int level,
				   const char *passwd, uint8_t snp_auth);
int isis_area_passwd_hmac_md5_set(struct isis_area *area, int level,
				  const char *passwd, uint8_t snp_auth);
void show_isis_database_lspdb_json(struct json_object *json,
				   struct isis_area *area, int level,
				   struct lspdb_head *lspdb, const char *argv,
				   int ui_level);
void show_isis_database_lspdb_vty(struct vty *vty, struct isis_area *area,
				  int level, struct lspdb_head *lspdb,
				  const char *argv, int ui_level);
char *isis_restart_filepath(void);
void isis_restart_write_overload_time(struct isis_area *isis_area,
				      uint32_t overload_time);
uint32_t isis_restart_read_overload_time(struct isis_area *isis_area);
void config_end_lsp_generate(struct isis_area *area);

/* YANG paths */
#define ISIS_INSTANCE	"/frr-isisd:isis/instance"
#define ISIS_SR		"/frr-isisd:isis/instance/segment-routing"
#define ISIS_SRV6	"/frr-isisd:isis/instance/segment-routing-srv6"

/* Master of threads. */
extern struct event_loop *master;

extern unsigned long debug_adj_pkt;
extern unsigned long debug_snp_pkt;
extern unsigned long debug_update_pkt;
extern unsigned long debug_spf_events;
extern unsigned long debug_rte_events;
extern unsigned long debug_events;
extern unsigned long debug_pkt_dump;
extern unsigned long debug_lsp_gen;
extern unsigned long debug_lsp_sched;
extern unsigned long debug_flooding;
extern unsigned long debug_bfd;
extern unsigned long debug_tx_queue;
extern unsigned long debug_sr;
extern unsigned long debug_ldp_sync;
extern unsigned long debug_lfa;
extern unsigned long debug_te;

#define DEBUG_ADJ_PACKETS                (1<<0)
#define DEBUG_SNP_PACKETS                (1<<1)
#define DEBUG_UPDATE_PACKETS             (1<<2)
#define DEBUG_SPF_EVENTS                 (1<<3)
#define DEBUG_RTE_EVENTS                 (1<<4)
#define DEBUG_EVENTS                     (1<<5)
#define DEBUG_PACKET_DUMP                (1<<6)
#define DEBUG_LSP_GEN                    (1<<7)
#define DEBUG_LSP_SCHED                  (1<<8)
#define DEBUG_FLOODING                   (1<<9)
#define DEBUG_BFD                        (1<<10)
#define DEBUG_TX_QUEUE                   (1<<11)
#define DEBUG_SR                         (1<<12)
#define DEBUG_LDP_SYNC                   (1<<13)
#define DEBUG_LFA                        (1<<14)
#define DEBUG_TE                         (1<<15)

/* Debug related macro. */
#define IS_DEBUG_ADJ_PACKETS (debug_adj_pkt & DEBUG_ADJ_PACKETS)
#define IS_DEBUG_SNP_PACKETS (debug_snp_pkt & DEBUG_SNP_PACKETS)
#define IS_DEBUG_UPDATE_PACKETS (debug_update_pkt & DEBUG_UPDATE_PACKETS)
#define IS_DEBUG_SPF_EVENTS (debug_spf_events & DEBUG_SPF_EVENTS)
#define IS_DEBUG_RTE_EVENTS (debug_rte_events & DEBUG_RTE_EVENTS)
#define IS_DEBUG_EVENTS (debug_events & DEBUG_EVENTS)
#define IS_DEBUG_PACKET_DUMP (debug_pkt_dump & DEBUG_PACKET_DUMP)
#define IS_DEBUG_LSP_GEN (debug_lsp_gen & DEBUG_LSP_GEN)
#define IS_DEBUG_LSP_SCHED (debug_lsp_sched & DEBUG_LSP_SCHED)
#define IS_DEBUG_FLOODING (debug_flooding & DEBUG_FLOODING)
#define IS_DEBUG_BFD (debug_bfd & DEBUG_BFD)
#define IS_DEBUG_TX_QUEUE (debug_tx_queue & DEBUG_TX_QUEUE)
#define IS_DEBUG_SR (debug_sr & DEBUG_SR)
#define IS_DEBUG_LDP_SYNC (debug_ldp_sync & DEBUG_LDP_SYNC)
#define IS_DEBUG_LFA (debug_lfa & DEBUG_LFA)
#define IS_DEBUG_TE (debug_te & DEBUG_TE)

#define lsp_debug(...)                                                         \
	do {                                                                   \
		if (IS_DEBUG_LSP_GEN)                                          \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define sched_debug(...)                                                       \
	do {                                                                   \
		if (IS_DEBUG_LSP_SCHED)                                        \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define sr_debug(...)                                                          \
	do {                                                                   \
		if (IS_DEBUG_SR)                                               \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define te_debug(...)                                                          \
	do {                                                                   \
		if (IS_DEBUG_TE)                                               \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#endif /* ISISD_H */
