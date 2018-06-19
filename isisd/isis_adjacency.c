/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.c
 *                             handling of IS-IS adjacencies
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
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

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "hash.h"
#include "vty.h"
#include "linklist.h"
#include "thread.h"
#include "if.h"
#include "stream.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_events.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_tlvs.h"

extern struct isis *isis;

static struct isis_adjacency *adj_alloc(const uint8_t *id)
{
	struct isis_adjacency *adj;

	adj = XCALLOC(MTYPE_ISIS_ADJACENCY, sizeof(struct isis_adjacency));
	memcpy(adj->sysid, id, ISIS_SYS_ID_LEN);

	return adj;
}

struct isis_adjacency *isis_new_adj(const uint8_t *id, const uint8_t *snpa,
				    int level, struct isis_circuit *circuit)
{
	struct isis_adjacency *adj;
	int i;

	adj = adj_alloc(id); /* P2P kludge */

	if (snpa) {
		memcpy(adj->snpa, snpa, ETH_ALEN);
	} else {
		memset(adj->snpa, ' ', ETH_ALEN);
	}

	adj->circuit = circuit;
	adj->level = level;
	adj->flaps = 0;
	adj->last_flap = time(NULL);
	adj->threeway_state = ISIS_THREEWAY_DOWN;
	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		listnode_add(circuit->u.bc.adjdb[level - 1], adj);
		adj->dischanges[level - 1] = 0;
		for (i = 0; i < DIS_RECORDS;
		     i++) /* clear N DIS state change records */
		{
			adj->dis_record[(i * ISIS_LEVELS) + level - 1].dis =
				ISIS_UNKNOWN_DIS;
			adj->dis_record[(i * ISIS_LEVELS) + level - 1]
				.last_dis_change = time(NULL);
		}
	}

	return adj;
}

struct isis_adjacency *isis_adj_lookup(const uint8_t *sysid, struct list *adjdb)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj))
		if (memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN) == 0)
			return adj;

	return NULL;
}

struct isis_adjacency *isis_adj_lookup_snpa(const uint8_t *ssnpa,
					    struct list *adjdb)
{
	struct listnode *node;
	struct isis_adjacency *adj;

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj))
		if (memcmp(adj->snpa, ssnpa, ETH_ALEN) == 0)
			return adj;

	return NULL;
}

void isis_delete_adj(void *arg)
{
	struct isis_adjacency *adj = arg;

	if (!adj)
		return;

	THREAD_TIMER_OFF(adj->t_expire);

	/* remove from SPF trees */
	spftree_area_adj_del(adj->circuit->area, adj);

	if (adj->area_addresses)
		XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->area_addresses);
	if (adj->ipv4_addresses)
		XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->ipv4_addresses);
	if (adj->ipv6_addresses)
		XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->ipv6_addresses);

	adj_mt_finish(adj);

	XFREE(MTYPE_ISIS_ADJACENCY, adj);
	return;
}

static const char *adj_state2string(int state)
{

	switch (state) {
	case ISIS_ADJ_INITIALIZING:
		return "Initializing";
	case ISIS_ADJ_UP:
		return "Up";
	case ISIS_ADJ_DOWN:
		return "Down";
	default:
		return "Unknown";
	}

	return NULL; /* not reached */
}

void isis_adj_process_threeway(struct isis_adjacency *adj,
			       struct isis_threeway_adj *tw_adj,
			       enum isis_adj_usage adj_usage)
{
	enum isis_threeway_state next_tw_state = ISIS_THREEWAY_DOWN;

	if (tw_adj && !adj->circuit->disable_threeway_adj) {
		if (tw_adj->state == ISIS_THREEWAY_DOWN) {
			next_tw_state = ISIS_THREEWAY_INITIALIZING;
		} else if (tw_adj->state == ISIS_THREEWAY_INITIALIZING) {
			next_tw_state = ISIS_THREEWAY_UP;
		} else if (tw_adj->state == ISIS_THREEWAY_UP) {
			if (adj->threeway_state == ISIS_THREEWAY_DOWN)
				next_tw_state = ISIS_THREEWAY_DOWN;
			else
				next_tw_state = ISIS_THREEWAY_UP;
		}
	} else {
		next_tw_state = ISIS_THREEWAY_UP;
	}

	if (next_tw_state != adj->threeway_state) {
		if (isis->debugs & DEBUG_ADJ_PACKETS) {
			zlog_info("ISIS-Adj (%s): Threeway state change %s to %s",
				  adj->circuit->area->area_tag,
				  isis_threeway_state_name(adj->threeway_state),
				  isis_threeway_state_name(next_tw_state));
		}
	}

	if (next_tw_state == ISIS_THREEWAY_DOWN) {
		isis_adj_state_change(adj, ISIS_ADJ_DOWN, "Neighbor restarted");
		return;
	}

	if (next_tw_state == ISIS_THREEWAY_UP) {
		if (adj->adj_state != ISIS_ADJ_UP) {
			isis_adj_state_change(adj, ISIS_ADJ_UP, NULL);
			adj->adj_usage = adj_usage;
		}
	}

	adj->threeway_state = next_tw_state;
}

void isis_adj_state_change(struct isis_adjacency *adj,
			   enum isis_adj_state new_state, const char *reason)
{
	int old_state;
	int level;
	struct isis_circuit *circuit;
	bool del;

	old_state = adj->adj_state;
	adj->adj_state = new_state;

	circuit = adj->circuit;

	if (isis->debugs & DEBUG_ADJ_PACKETS) {
		zlog_debug("ISIS-Adj (%s): Adjacency state change %d->%d: %s",
			   circuit->area->area_tag, old_state, new_state,
			   reason ? reason : "unspecified");
	}

	if (circuit->area->log_adj_changes) {
		const char *adj_name;
		struct isis_dynhn *dyn;

		dyn = dynhn_find_by_id(adj->sysid);
		if (dyn)
			adj_name = dyn->hostname;
		else
			adj_name = sysid_print(adj->sysid);

		zlog_info(
			"%%ADJCHANGE: Adjacency to %s (%s) changed from %s to %s, %s",
			adj_name, adj->circuit->interface->name,
			adj_state2string(old_state),
			adj_state2string(new_state),
			reason ? reason : "unspecified");
	}

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		del = false;
		for (level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
			if ((adj->level & level) == 0)
				continue;
			if (new_state == ISIS_ADJ_UP) {
				circuit->upadjcount[level - 1]++;
				isis_event_adjacency_state_change(adj,
								  new_state);
				/* update counter & timers for debugging
				 * purposes */
				adj->last_flap = time(NULL);
				adj->flaps++;
			} else if (new_state == ISIS_ADJ_DOWN) {
				listnode_delete(circuit->u.bc.adjdb[level - 1],
						adj);

				circuit->upadjcount[level - 1]--;
				if (circuit->upadjcount[level - 1] == 0)
					isis_circuit_lsp_queue_clean(circuit);

				isis_event_adjacency_state_change(adj,
								  new_state);
				del = true;
			}

			if (circuit->u.bc.lan_neighs[level - 1]) {
				list_delete_all_node(
					circuit->u.bc.lan_neighs[level - 1]);
				isis_adj_build_neigh_list(
					circuit->u.bc.adjdb[level - 1],
					circuit->u.bc.lan_neighs[level - 1]);
			}

			/* On adjacency state change send new pseudo LSP if we
			 * are the DR */
			if (circuit->u.bc.is_dr[level - 1])
				lsp_regenerate_schedule_pseudo(circuit, level);
		}

		if (del)
			isis_delete_adj(adj);

	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		del = false;
		for (level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
			if ((adj->level & level) == 0)
				continue;
			if (new_state == ISIS_ADJ_UP) {
				circuit->upadjcount[level - 1]++;
				isis_event_adjacency_state_change(adj,
								  new_state);

				if (adj->sys_type == ISIS_SYSTYPE_UNKNOWN)
					send_hello(circuit, level);

				/* update counter & timers for debugging
				 * purposes */
				adj->last_flap = time(NULL);
				adj->flaps++;

				/* 7.3.17 - going up on P2P -> send CSNP */
				/* FIXME: yup, I know its wrong... but i will do
				 * it! (for now) */
				send_csnp(circuit, level);
			} else if (new_state == ISIS_ADJ_DOWN) {
				if (adj->circuit->u.p2p.neighbor == adj)
					adj->circuit->u.p2p.neighbor = NULL;
				circuit->upadjcount[level - 1]--;
				if (circuit->upadjcount[level - 1] == 0)
					isis_circuit_lsp_queue_clean(circuit);

				isis_event_adjacency_state_change(adj,
								  new_state);
				del = true;
			}
		}

		if (del)
			isis_delete_adj(adj);
	}

	return;
}


void isis_adj_print(struct isis_adjacency *adj)
{
	struct isis_dynhn *dyn;

	if (!adj)
		return;
	dyn = dynhn_find_by_id(adj->sysid);
	if (dyn)
		zlog_debug("%s", dyn->hostname);

	zlog_debug("SystemId %20s SNPA %s, level %d\nHolding Time %d",
		   sysid_print(adj->sysid), snpa_print(adj->snpa), adj->level,
		   adj->hold_time);
	if (adj->ipv4_address_count) {
		zlog_debug("IPv4 Address(es):");
		for (unsigned int i = 0; i < adj->ipv4_address_count; i++)
			zlog_debug("%s", inet_ntoa(adj->ipv4_addresses[i]));
	}

	if (adj->ipv6_address_count) {
		zlog_debug("IPv6 Address(es):");
		for (unsigned int i = 0; i < adj->ipv6_address_count; i++) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &adj->ipv6_addresses[i], buf,
				  sizeof(buf));
			zlog_debug("%s", buf);
		}
	}
	zlog_debug("Speaks: %s", nlpid2string(&adj->nlpids));

	return;
}

int isis_adj_expire(struct thread *thread)
{
	struct isis_adjacency *adj;

	/*
	 * Get the adjacency
	 */
	adj = THREAD_ARG(thread);
	assert(adj);
	adj->t_expire = NULL;

	/* trigger the adj expire event */
	isis_adj_state_change(adj, ISIS_ADJ_DOWN, "holding time expired");

	return 0;
}

/*
 * show isis neighbor [detail]
 */
void isis_adj_print_vty(struct isis_adjacency *adj, struct vty *vty,
			char detail)
{
	time_t now;
	struct isis_dynhn *dyn;
	int level;

	dyn = dynhn_find_by_id(adj->sysid);
	if (dyn)
		vty_out(vty, "  %-20s", dyn->hostname);
	else
		vty_out(vty, "  %-20s", sysid_print(adj->sysid));

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		if (adj->circuit)
			vty_out(vty, "%-12s", adj->circuit->interface->name);
		else
			vty_out(vty, "NULL circuit!");
		vty_out(vty, "%-3u", adj->level); /* level */
		vty_out(vty, "%-13s", adj_state2string(adj->adj_state));
		now = time(NULL);
		if (adj->last_upd)
			vty_out(vty, "%-9llu",
				(unsigned long long)adj->last_upd
					+ adj->hold_time - now);
		else
			vty_out(vty, "-        ");
		vty_out(vty, "%-10s", snpa_print(adj->snpa));
		vty_out(vty, "\n");
	}

	if (detail == ISIS_UI_LEVEL_DETAIL) {
		level = adj->level;
		vty_out(vty, "\n");
		if (adj->circuit)
			vty_out(vty, "    Interface: %s",
				adj->circuit->interface->name);
		else
			vty_out(vty, "    Interface: NULL circuit");
		vty_out(vty, ", Level: %u", adj->level); /* level */
		vty_out(vty, ", State: %s", adj_state2string(adj->adj_state));
		now = time(NULL);
		if (adj->last_upd)
			vty_out(vty, ", Expires in %s",
				time2string(adj->last_upd + adj->hold_time
					    - now));
		else
			vty_out(vty, ", Expires in %s",
				time2string(adj->hold_time));
		vty_out(vty, "\n");
		vty_out(vty, "    Adjacency flaps: %u", adj->flaps);
		vty_out(vty, ", Last: %s ago",
			time2string(now - adj->last_flap));
		vty_out(vty, "\n");
		vty_out(vty, "    Circuit type: %s",
			circuit_t2string(adj->circuit_t));
		vty_out(vty, ", Speaks: %s", nlpid2string(&adj->nlpids));
		vty_out(vty, "\n");
		if (adj->mt_count != 1
		    || adj->mt_set[0] != ISIS_MT_IPV4_UNICAST) {
			vty_out(vty, "    Topologies:\n");
			for (unsigned int i = 0; i < adj->mt_count; i++)
				vty_out(vty, "      %s\n",
					isis_mtid2str(adj->mt_set[i]));
		}
		vty_out(vty, "    SNPA: %s", snpa_print(adj->snpa));
		if (adj->circuit
		    && (adj->circuit->circ_type == CIRCUIT_T_BROADCAST)) {
			dyn = dynhn_find_by_id(adj->lanid);
			if (dyn)
				vty_out(vty, ", LAN id: %s.%02x", dyn->hostname,
					adj->lanid[ISIS_SYS_ID_LEN]);
			else
				vty_out(vty, ", LAN id: %s.%02x",
					sysid_print(adj->lanid),
					adj->lanid[ISIS_SYS_ID_LEN]);

			vty_out(vty, "\n");
			vty_out(vty, "    LAN Priority: %u",
				adj->prio[adj->level - 1]);

			vty_out(vty, ", %s, DIS flaps: %u, Last: %s ago",
				isis_disflag2string(
					adj->dis_record[ISIS_LEVELS + level - 1]
						.dis),
				adj->dischanges[level - 1],
				time2string(now - (adj->dis_record[ISIS_LEVELS
								   + level - 1]
							   .last_dis_change)));
		}
		vty_out(vty, "\n");

		if (adj->area_address_count) {
			vty_out(vty, "    Area Address(es):\n");
			for (unsigned int i = 0; i < adj->area_address_count;
			     i++) {
				vty_out(vty, "      %s\n",
					isonet_print(adj->area_addresses[i]
							     .area_addr,
						     adj->area_addresses[i]
							     .addr_len));
			}
		}
		if (adj->ipv4_address_count) {
			vty_out(vty, "    IPv4 Address(es):\n");
			for (unsigned int i = 0; i < adj->ipv4_address_count;
			     i++)
				vty_out(vty, "      %s\n",
					inet_ntoa(adj->ipv4_addresses[i]));
		}
		if (adj->ipv6_address_count) {
			vty_out(vty, "    IPv6 Address(es):\n");
			for (unsigned int i = 0; i < adj->ipv6_address_count;
			     i++) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &adj->ipv6_addresses[i],
					  buf, sizeof(buf));
				vty_out(vty, "      %s\n", buf);
			}
		}
		vty_out(vty, "\n");
	}
	return;
}

void isis_adj_build_neigh_list(struct list *adjdb, struct list *list)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	if (!list) {
		zlog_warn("isis_adj_build_neigh_list(): NULL list");
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
		if (!adj) {
			zlog_warn("isis_adj_build_neigh_list(): NULL adj");
			return;
		}

		if ((adj->adj_state == ISIS_ADJ_UP
		     || adj->adj_state == ISIS_ADJ_INITIALIZING))
			listnode_add(list, adj->snpa);
	}
	return;
}

void isis_adj_build_up_list(struct list *adjdb, struct list *list)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	if (adjdb == NULL) {
		zlog_warn("isis_adj_build_up_list(): adjacency DB is empty");
		return;
	}

	if (!list) {
		zlog_warn("isis_adj_build_up_list(): NULL list");
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
		if (!adj) {
			zlog_warn("isis_adj_build_up_list(): NULL adj");
			return;
		}

		if (adj->adj_state == ISIS_ADJ_UP)
			listnode_add(list, adj);
	}

	return;
}

int isis_adj_usage2levels(enum isis_adj_usage usage)
{
	switch (usage) {
	case ISIS_ADJ_LEVEL1:
		return IS_LEVEL_1;
	case ISIS_ADJ_LEVEL2:
		return IS_LEVEL_2;
	case ISIS_ADJ_LEVEL1AND2:
		return IS_LEVEL_1 | IS_LEVEL_2;
	default:
		break;
	}
	return 0;
}
