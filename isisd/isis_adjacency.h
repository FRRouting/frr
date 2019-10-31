/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.h
 *                             IS-IS adjacency handling
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_ISIS_ADJACENCY_H
#define _ZEBRA_ISIS_ADJACENCY_H

#include "isisd/isis_tlvs.h"

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

struct isis_adjacency {
	uint8_t snpa[ETH_ALEN];		    /* NeighbourSNPAAddress */
	uint8_t sysid[ISIS_SYS_ID_LEN];     /* neighbourSystemIdentifier */
	uint8_t lanid[ISIS_SYS_ID_LEN + 1]; /* LAN id on bcast circuits */
	int dischanges[ISIS_LEVELS];       /* how many DIS changes ? */
	/* an array of N levels for M records */
	struct isis_dis_record dis_record[DIS_RECORDS * ISIS_LEVELS];
	enum isis_adj_state adj_state;    /* adjacencyState */
	enum isis_adj_usage adj_usage;    /* adjacencyUsage */
	struct area_addr *area_addresses; /* areaAdressesOfNeighbour */
	unsigned int area_address_count;
	struct nlpids nlpids; /* protocols spoken ... */
	struct in_addr *ipv4_addresses;
	unsigned int ipv4_address_count;
	struct in_addr router_address;
	struct in6_addr *ipv6_addresses;
	unsigned int ipv6_address_count;
	struct in6_addr router_address6;
	uint8_t prio[ISIS_LEVELS];      /* priorityOfNeighbour for DIS */
	int circuit_t;			/* from hello PDU hdr */
	int level;			/* level (1 or 2) */
	enum isis_system_type sys_type; /* neighbourSystemType */
	uint16_t hold_time;		/* entryRemainingTime */
	uint32_t last_upd;
	uint32_t last_flap; /* last time the adj flapped */
	enum isis_threeway_state threeway_state;
	uint32_t ext_circuit_id;
	int flaps;		      /* number of adjacency flaps  */
	struct thread *t_expire;      /* expire after hold_time  */
	struct isis_circuit *circuit; /* back pointer */
	uint16_t *mt_set;      /* Topologies this adjacency is valid for */
	unsigned int mt_count; /* Number of entries in mt_set */
	struct bfd_session *bfd_session;
};

struct isis_threeway_adj;

struct isis_adjacency *isis_adj_lookup(const uint8_t *sysid,
				       struct list *adjdb);
struct isis_adjacency *isis_adj_lookup_snpa(const uint8_t *ssnpa,
					    struct list *adjdb);
struct isis_adjacency *isis_new_adj(const uint8_t *id, const uint8_t *snpa,
				    int level, struct isis_circuit *circuit);
void isis_delete_adj(void *adj);
void isis_adj_process_threeway(struct isis_adjacency *adj,
			       struct isis_threeway_adj *tw_adj,
			       enum isis_adj_usage adj_usage);
DECLARE_HOOK(isis_adj_state_change_hook, (struct isis_adjacency *adj), (adj))
void isis_adj_state_change(struct isis_adjacency *adj,
			   enum isis_adj_state state, const char *reason);
void isis_adj_print(struct isis_adjacency *adj);
const char *isis_adj_yang_state(enum isis_adj_state state);
int isis_adj_expire(struct thread *thread);
void isis_adj_print_vty(struct isis_adjacency *adj, struct vty *vty,
			char detail);
void isis_adj_build_neigh_list(struct list *adjdb, struct list *list);
void isis_adj_build_up_list(struct list *adjdb, struct list *list);
int isis_adj_usage2levels(enum isis_adj_usage usage);

#endif /* ISIS_ADJACENCY_H */
