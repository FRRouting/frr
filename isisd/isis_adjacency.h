// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.h
 *                             IS-IS adjacency handling
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 */

#ifndef _ZEBRA_ISIS_ADJACENCY_H
#define _ZEBRA_ISIS_ADJACENCY_H

#include "isisd/isis_tlvs.h"

DECLARE_MTYPE(ISIS_ADJACENCY_INFO);

enum isis_adj_usage {
	ISIS_ADJ_NONE,
	ISIS_ADJ_LEVEL1,
	ISIS_ADJ_LEVEL2,
	ISIS_ADJ_LEVEL1AND2
};

enum isis_system_type {
	ISIS_SYSTYPE_UNKNOWN,
	ISIS_SYSTYPE_ES,
	ISIS_SYSTYPE_IS,
	ISIS_SYSTYPE_L1_IS,
	ISIS_SYSTYPE_L2_IS
};

enum isis_adj_state {
	ISIS_ADJ_UNKNOWN,
	ISIS_ADJ_INITIALIZING,
	ISIS_ADJ_UP,
	ISIS_ADJ_DOWN
};

/*
 * we use the following codes to give an indication _why_
 * a specific adjacency is up or down
 */
enum isis_adj_updown_reason {
	ISIS_ADJ_REASON_SEENSELF,
	ISIS_ADJ_REASON_AREA_MISMATCH,
	ISIS_ADJ_REASON_HOLDTIMER_EXPIRED,
	ISIS_ADJ_REASON_AUTH_FAILED,
	ISIS_ADJ_REASON_CHECKSUM_FAILED
};

#define DIS_RECORDS 8	/* keep the last 8 DIS state changes on record */

struct isis_dis_record {
	int dis;		/* is our neighbor the DIS ? */
	time_t last_dis_change; /* timestamp for last dis change */
};

struct bfd_session;
struct isis_area;

struct isis_adjacency {
	uint8_t snpa[ETH_ALEN];		    /* NeighbourSNPAAddress */
	uint8_t sysid[ISIS_SYS_ID_LEN];     /* neighbourSystemIdentifier */
	uint8_t lanid[ISIS_SYS_ID_LEN + 1]; /* LAN id on bcast circuits */
	int dischanges[ISIS_LEVELS];       /* how many DIS changes ? */
	/* an array of N levels for M records */
	struct isis_dis_record dis_record[DIS_RECORDS * ISIS_LEVELS];
	enum isis_adj_state adj_state;    /* adjacencyState */
	enum isis_adj_usage adj_usage;    /* adjacencyUsage */
	struct iso_address *area_addresses; /* areaAdressesOfNeighbour */
	unsigned int area_address_count;
	struct nlpids nlpids; /* protocols spoken ... */
	struct in_addr *ipv4_addresses;
	unsigned int ipv4_address_count;
	struct in6_addr *ll_ipv6_addrs; /* Link local IPv6 neighbor address */
	unsigned int ll_ipv6_count;
	struct in6_addr *global_ipv6_addrs; /* Global IPv6 neighbor address */
	unsigned int global_ipv6_count;
	uint8_t prio[ISIS_LEVELS];      /* priorityOfNeighbour for DIS */
	int circuit_t;			/* from hello PDU hdr */
	int level;			/* level (1 or 2) */
	enum isis_system_type sys_type; /* neighbourSystemType */
	uint16_t hold_time;		/* entryRemainingTime */
	time_t last_upd;
	time_t last_flap; /* last time the adj flapped */
	enum isis_threeway_state threeway_state;
	uint32_t ext_circuit_id;
	int flaps;		      /* number of adjacency flaps  */
	struct event *t_expire;	      /* expire after hold_time  */
	struct isis_circuit *circuit; /* back pointer */
	uint16_t *mt_set;      /* Topologies this adjacency is valid for */
	unsigned int mt_count; /* Number of entries in mt_set */
	struct bfd_session_params *bfd_session;
	struct list *adj_sids; /* Segment Routing Adj-SIDs. */
	uint32_t snmp_idx;
	struct listnode *snmp_list_node;

	struct list *srv6_endx_sids; /* SRv6 End.X SIDs. */
};

struct isis_threeway_adj;

struct isis_adjacency *isis_adj_lookup(const uint8_t *sysid,
				       struct list *adjdb);
struct isis_adjacency *isis_adj_lookup_snpa(const uint8_t *ssnpa,
					    struct list *adjdb);
struct isis_adjacency *isis_adj_find(const struct isis_area *area, int level,
				     const uint8_t *sysid);
struct isis_adjacency *isis_new_adj(const uint8_t *id, const uint8_t *snpa,
				    int level, struct isis_circuit *circuit);
void isis_delete_adj(void *adj);
void isis_adj_process_threeway(struct isis_adjacency **padj,
			       struct isis_threeway_adj *tw_adj,
			       enum isis_adj_usage adj_usage);
DECLARE_HOOK(isis_adj_state_change_hook, (struct isis_adjacency *adj), (adj));
DECLARE_HOOK(isis_adj_ip_enabled_hook,
	     (struct isis_adjacency * adj, int family, bool global),
	     (adj, family, global));
DECLARE_HOOK(isis_adj_ip_disabled_hook,
	     (struct isis_adjacency * adj, int family, bool global),
	     (adj, family, global));
void isis_log_adj_change(struct isis_adjacency *adj,
			 enum isis_adj_state old_state,
			 enum isis_adj_state new_state, const char *reason);
void isis_adj_state_change(struct isis_adjacency **adj,
			   enum isis_adj_state state, const char *reason);
void isis_adj_print(struct isis_adjacency *adj);
const char *isis_adj_yang_state(enum isis_adj_state state);
void isis_adj_expire(struct event *thread);
void isis_adj_print_vty(struct isis_adjacency *adj, struct vty *vty,
			char detail);
void isis_adj_print_json(struct isis_adjacency *adj, struct json_object *json,
			 char detail);
void isis_adj_build_neigh_list(struct list *adjdb, struct list *list);
void isis_adj_build_up_list(struct list *adjdb, struct list *list);
int isis_adj_usage2levels(enum isis_adj_usage usage);
void isis_bfd_startup_timer(struct event *thread);
const char *isis_adj_name(const struct isis_adjacency *adj);
#endif /* ISIS_ADJACENCY_H */
