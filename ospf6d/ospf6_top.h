// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "qobj.h"
#include "routemap.h"
struct ospf6_master {

	/* OSPFv3 instance. */
	struct list *ospf6;
	/* OSPFv3 thread master. */
	struct event_loop *master;
};

/* ospf6->config_flags */
enum { OSPF6_LOG_ADJACENCY_CHANGES	= (1 << 0),
       OSPF6_LOG_ADJACENCY_DETAIL	= (1 << 1),
       OSPF6_SEND_EXTRA_DATA_TO_ZEBRA	= (1 << 2),
};

/* For processing route-map change update in the callback */
#define OSPF6_IS_RMAP_CHANGED 0x01
struct ospf6_redist {
	uint8_t instance;

	uint8_t flag;
	/* Redistribute metric info. */
	struct {
		int type;  /* External metric type (E1 or E2).  */
		int value; /* Value for static metric (24-bit).
			    * -1 means metric value is not set.
			    */
	} dmetric;

	/* For redistribute route map. */
	struct {
		char *name;
		struct route_map *map;
	} route_map;
#define ROUTEMAP_NAME(R) (R->route_map.name)
#define ROUTEMAP(R) (R->route_map.map)
};

struct ospf6_gr_info {
	bool restart_support;
	bool restart_in_progress;
	bool prepare_in_progress;
	bool finishing_restart;
	uint32_t grace_period;
	int reason;
	char *exit_reason;
	struct event *t_grace_period;
};

struct ospf6_gr_helper {
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
	 * routerids for which Helper support is
	 * enabled.
	 */
	struct hash *enable_rtr_list;

	/* HELPER for number of active
	 * RESTARTERs.
	 */
	int active_restarter_cnt;

	/* last HELPER exit reason */
	uint32_t last_exit_reason;
};

/* OSPFv3 top level data structure */
struct ospf6 {
	/* The relevant vrf_id */
	vrf_id_t vrf_id;

	char *name; /* VRF name */

	/* my router id */
	in_addr_t router_id;

	/* static router id */
	in_addr_t router_id_static;

	in_addr_t router_id_zebra;

	/* start time */
	struct timeval starttime;

	/* list of areas */
	struct list *area_list;
	struct ospf6_area *backbone;

	/* AS scope link state database */
	struct ospf6_lsdb *lsdb;
	struct ospf6_lsdb *lsdb_self;

	struct ospf6_route_table *route_table;
	struct ospf6_route_table *brouter_table;

	struct ospf6_route_table *external_table;
#define OSPF6_EXT_INIT_LS_ID 1
	uint32_t external_id;

	/* OSPF6 redistribute configuration */
	struct list *redist[ZEBRA_ROUTE_MAX + 1];

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

	uint8_t flag;
#define OSPF6_FLAG_ABR          0x04
#define OSPF6_FLAG_ASBR         0x08

	int redistribute; /* Num of redistributed protocols. */

	/* Configuration bitmask, refer to enum above */
	uint8_t config_flags;
	int default_originate; /* Default information originate. */
#define DEFAULT_ORIGINATE_NONE 0
#define DEFAULT_ORIGINATE_ZEBRA 1
#define DEFAULT_ORIGINATE_ALWAYS 2
	/* LSA timer parameters */
	unsigned int lsa_minarrival; /* LSA minimum arrival in milliseconds. */

	/* SPF parameters */
	unsigned int spf_delay;	/* SPF delay time. */
	unsigned int spf_holdtime;     /* SPF hold time. */
	unsigned int spf_max_holdtime; /* SPF maximum-holdtime */
	unsigned int
		spf_hold_multiplier; /* Adaptive multiplier for hold time */
	unsigned int spf_reason;     /* reason bits while scheduling SPF */

	struct timeval ts_spf;		/* SPF calculation time stamp. */
	struct timeval ts_spf_duration; /* Execution time of last SPF */
	unsigned int last_spf_reason;   /* Last SPF reason */

	int fd;
	/* Threads */
	struct event *t_spf_calc; /* SPF calculation timer. */
	struct event *t_ase_calc; /* ASE calculation timer. */
	struct event *maxage_remover;
	struct event *t_distribute_update; /* Distirbute update timer. */
	struct event *t_ospf6_receive;	   /* OSPF6 receive timer */
	struct event *t_external_aggr;	   /* OSPF6 aggregation timer */
#define OSPF6_WRITE_INTERFACE_COUNT_DEFAULT 20
	struct event *t_write;

	int write_oi_count; /* Num of packets sent per thread invocation */
	uint32_t ref_bandwidth;

	/* Distance parameters */
	uint8_t distance_all;
	uint8_t distance_intra;
	uint8_t distance_inter;
	uint8_t distance_external;

	struct route_table *distance_table;

	/* Used during ospf instance going down send LSDB
	 * update to neighbors immediatly */
	uint8_t inst_shutdown;

	/* Max number of multiple paths
	 * to support ECMP.
	 */
	uint16_t max_multipath;

	/* OSPF Graceful Restart info (restarting mode) */
	struct ospf6_gr_info gr_info;

	/*ospf6 Graceful restart helper info */
	struct ospf6_gr_helper ospf6_helper_cfg;

	/* Count of NSSA areas */
	uint8_t anyNSSA;
	struct event *t_abr_task; /* ABR task timer. */
	struct list *oi_write_q;

	uint32_t redist_count;

	/* Action for aggregation of external LSAs */
	int aggr_action;

	uint32_t seqnum_l; /* lower order Sequence Number */
	uint32_t seqnum_h; /* higher order Sequence Number */
#define OSPF6_EXTL_AGGR_DEFAULT_DELAY 5
	/* For ASBR summary delay timer */
	uint16_t aggr_delay_interval;
	/* Table of configured Aggregate addresses */
	struct route_table *rt_aggr_tbl;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(ospf6);

#define OSPF6_DISABLED    0x01
#define OSPF6_STUB_ROUTER 0x02

/* global pointer for OSPF top data structure */
extern struct ospf6 *ospf6;
extern struct ospf6_master *om6;

/* prototypes */
extern void ospf6_master_init(struct event_loop *master);
extern void ospf6_master_delete(void);

extern void install_element_ospf6_clear_process(void);
extern void ospf6_top_init(void);
extern void ospf6_delete(struct ospf6 *o);
extern bool ospf6_router_id_update(struct ospf6 *ospf6, bool init);
void ospf6_restart_spf(struct ospf6 *ospf6);

extern void ospf6_maxage_remove(struct ospf6 *o);
extern struct ospf6 *ospf6_instance_create(const char *name);
void ospf6_vrf_link(struct ospf6 *ospf6, struct vrf *vrf);
void ospf6_vrf_unlink(struct ospf6 *ospf6, struct vrf *vrf);
struct ospf6 *ospf6_lookup_by_vrf_id(vrf_id_t vrf_id);
struct ospf6 *ospf6_lookup_by_vrf_name(const char *name);
const char *ospf6_vrf_id_to_name(vrf_id_t vrf_id);
void ospf6_vrf_init(void);
bool ospf6_is_valid_summary_addr(struct vty *vty, struct prefix *p);
#endif /* OSPF6_TOP_H */
