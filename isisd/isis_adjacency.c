// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.c
 *                             handling of IS-IS adjacencies
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "hash.h"
#include "vty.h"
#include "linklist.h"
#include "frrevent.h"
#include "if.h"
#include "stream.h"
#include "bfd.h"

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
#include "isisd/isis_events.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_tlvs.h"
#include "isisd/fabricd.h"
#include "isisd/isis_nb.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_ADJACENCY, "ISIS adjacency");
DEFINE_MTYPE(ISISD, ISIS_ADJACENCY_INFO, "ISIS adjacency info");

static struct isis_adjacency *adj_alloc(struct isis_circuit *circuit,
					const uint8_t *id)
{
	struct isis_adjacency *adj;

	adj = XCALLOC(MTYPE_ISIS_ADJACENCY, sizeof(struct isis_adjacency));
	memcpy(adj->sysid, id, ISIS_SYS_ID_LEN);

	adj->snmp_idx = ++circuit->snmp_adj_idx_gen;

	if (circuit->snmp_adj_list == NULL)
		circuit->snmp_adj_list = list_new();

	adj->snmp_list_node = listnode_add(circuit->snmp_adj_list, adj);

	return adj;
}

struct isis_adjacency *isis_new_adj(const uint8_t *id, const uint8_t *snpa,
				    int level, struct isis_circuit *circuit)
{
	struct isis_adjacency *adj;
	int i;

	adj = adj_alloc(circuit, id); /* P2P kludge */

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
	adj->adj_sids = list_new();
	adj->srv6_endx_sids = list_new();
	listnode_add(circuit->area->adjacency_list, adj);

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

struct isis_adjacency *isis_adj_find(const struct isis_area *area, int level,
				     const uint8_t *sysid)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->adjacency_list, node, adj)) {
		if (!(adj->level & level))
			continue;

		if (!memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN))
			return adj;
	}

	return NULL;
}

DEFINE_HOOK(isis_adj_state_change_hook, (struct isis_adjacency *adj), (adj));

void isis_delete_adj(void *arg)
{
	struct isis_adjacency *adj = arg;

	if (!adj)
		return;
	/* Remove self from snmp list without walking the list*/
	list_delete_node(adj->circuit->snmp_adj_list, adj->snmp_list_node);

	EVENT_OFF(adj->t_expire);
	if (adj->adj_state != ISIS_ADJ_DOWN)
		adj->adj_state = ISIS_ADJ_DOWN;

	hook_call(isis_adj_state_change_hook, adj);

	XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->area_addresses);
	XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->ipv4_addresses);
	XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->ll_ipv6_addrs);
	XFREE(MTYPE_ISIS_ADJACENCY_INFO, adj->global_ipv6_addrs);
	adj_mt_finish(adj);
	list_delete(&adj->adj_sids);
	list_delete(&adj->srv6_endx_sids);

	listnode_delete(adj->circuit->area->adjacency_list, adj);
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

static const char *adj_level2string(int level)
{
	switch (level) {
	case IS_LEVEL_1:
		return "level-1";
	case IS_LEVEL_2:
		return "level-2";
	case IS_LEVEL_1_AND_2:
		return "level-1-2";
	default:
		return "unknown";
	}

	return NULL; /* not reached */
}

static void isis_adj_route_switchover(struct isis_adjacency *adj)
{
	union g_addr ip = {};
	ifindex_t ifindex;
	unsigned int i;

	if (!adj->circuit || !adj->circuit->interface)
		return;

	ifindex = adj->circuit->interface->ifindex;

	for (i = 0; i < adj->ipv4_address_count; i++) {
		ip.ipv4 = adj->ipv4_addresses[i];
		isis_circuit_switchover_routes(adj->circuit, AF_INET, &ip,
					       ifindex);
	}

	for (i = 0; i < adj->ll_ipv6_count; i++) {
		ip.ipv6 = adj->ll_ipv6_addrs[i];
		isis_circuit_switchover_routes(adj->circuit, AF_INET6, &ip,
					       ifindex);
	}

	for (i = 0; i < adj->global_ipv6_count; i++) {
		ip.ipv6 = adj->global_ipv6_addrs[i];
		isis_circuit_switchover_routes(adj->circuit, AF_INET6, &ip,
					       ifindex);
	}
}

void isis_adj_process_threeway(struct isis_adjacency **padj,
			       struct isis_threeway_adj *tw_adj,
			       enum isis_adj_usage adj_usage)
{
	enum isis_threeway_state next_tw_state = ISIS_THREEWAY_DOWN;
	struct isis_adjacency *adj = *padj;

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
		if (IS_DEBUG_ADJ_PACKETS) {
			zlog_info("ISIS-Adj (%s): Threeway state change %s to %s",
				  adj->circuit->area->area_tag,
				  isis_threeway_state_name(adj->threeway_state),
				  isis_threeway_state_name(next_tw_state));
		}
	}

	if (next_tw_state != ISIS_THREEWAY_DOWN)
		fabricd_initial_sync_hello(adj->circuit);

	if (next_tw_state == ISIS_THREEWAY_DOWN) {
		isis_adj_state_change(padj, ISIS_ADJ_DOWN, "Neighbor restarted");
		return;
	}

	if (next_tw_state == ISIS_THREEWAY_UP) {
		if (adj->adj_state != ISIS_ADJ_UP) {
			isis_adj_state_change(padj, ISIS_ADJ_UP, NULL);
			adj->adj_usage = adj_usage;
		}
	}

	if (adj->threeway_state != next_tw_state) {
		send_hello_sched(adj->circuit, 0, TRIGGERED_IIH_DELAY);
	}

	adj->threeway_state = next_tw_state;
}
const char *isis_adj_name(const struct isis_adjacency *adj)
{
	static char buf[ISO_SYSID_STRLEN];

	if (!adj)
		return "NONE";

	struct isis_dynhn *dyn;

	dyn = dynhn_find_by_id(adj->circuit->isis, adj->sysid);
	if (adj->circuit->area->dynhostname && dyn)
		return dyn->hostname;

	snprintfrr(buf, sizeof(buf), "%pSY", adj->sysid);
	return buf;
}
void isis_log_adj_change(struct isis_adjacency *adj,
			 enum isis_adj_state old_state,
			 enum isis_adj_state new_state, const char *reason)
{
	zlog_info(
		"%%ADJCHANGE: Adjacency to %s (%s) for %s changed from %s to %s, %s",
		isis_adj_name(adj), adj->circuit->interface->name,
		adj_level2string(adj->level), adj_state2string(old_state),
		adj_state2string(new_state), reason ? reason : "unspecified");
}
void isis_adj_state_change(struct isis_adjacency **padj,
			   enum isis_adj_state new_state, const char *reason)
{
	struct isis_adjacency *adj = *padj;
	enum isis_adj_state old_state = adj->adj_state;
	struct isis_circuit *circuit = adj->circuit;
	bool del = false;

	if (new_state == old_state)
		return;

	if (old_state == ISIS_ADJ_UP &&
	    !CHECK_FLAG(adj->circuit->flags, ISIS_CIRCUIT_IF_DOWN_FROM_Z)) {
		if (IS_DEBUG_EVENTS)
			zlog_debug(
				"ISIS-Adj (%s): Starting fast-reroute on state change %d->%d: %s",
				circuit->area->area_tag, old_state, new_state,
				reason ? reason : "unspecified");
		isis_adj_route_switchover(adj);
	}

	adj->adj_state = new_state;
	send_hello_sched(circuit, adj->level, TRIGGERED_IIH_DELAY);

	if (IS_DEBUG_ADJ_PACKETS) {
		zlog_debug("ISIS-Adj (%s): Adjacency state change %d->%d: %s",
			   circuit->area->area_tag, old_state, new_state,
			   reason ? reason : "unspecified");
	}

	if (circuit->area->log_adj_changes)
		isis_log_adj_change(adj, old_state, new_state, reason);

#ifndef FABRICD
	/* send northbound notification */
	isis_notif_adj_state_change(adj, new_state, reason);
#endif /* ifndef FABRICD */

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
			if ((adj->level & level) == 0)
				continue;
			if (new_state == ISIS_ADJ_UP) {
				circuit->adj_state_changes++;
				circuit->upadjcount[level - 1]++;
				/* update counter & timers for debugging
				 * purposes */
				adj->last_flap = time(NULL);
				adj->flaps++;
			} else {
				if (old_state == ISIS_ADJ_UP) {
					circuit->adj_state_changes++;

					circuit->upadjcount[level - 1]--;
					if (circuit->upadjcount[level - 1] == 0)
						isis_tx_queue_clean(
							circuit->tx_queue);
				}

				if (new_state == ISIS_ADJ_DOWN) {
					listnode_delete(
						circuit->u.bc.adjdb[level - 1],
						adj);

					del = true;
				}
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

	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
			if ((adj->level & level) == 0)
				continue;
			if (new_state == ISIS_ADJ_UP) {
				circuit->upadjcount[level - 1]++;

				/* update counter & timers for debugging
				 * purposes */
				adj->last_flap = time(NULL);
				adj->flaps++;

				if (level == IS_LEVEL_1) {
					event_add_timer(
						master, send_l1_csnp, circuit,
						0, &circuit->t_send_csnp[0]);
				} else {
					event_add_timer(
						master, send_l2_csnp, circuit,
						0, &circuit->t_send_csnp[1]);
				}
			} else {
				if (old_state == ISIS_ADJ_UP) {
					circuit->upadjcount[level - 1]--;
					if (circuit->upadjcount[level - 1] == 0)
						isis_tx_queue_clean(
							circuit->tx_queue);
				}

				if (new_state == ISIS_ADJ_DOWN) {
					if (adj->circuit->u.p2p.neighbor == adj)
						adj->circuit->u.p2p.neighbor =
							NULL;

					del = true;
				}
			}
		}
	}

	hook_call(isis_adj_state_change_hook, adj);

	if (del) {
		isis_delete_adj(adj);
		*padj = NULL;
	}
}


void isis_adj_print(struct isis_adjacency *adj)
{
	struct isis_dynhn *dyn;

	if (!adj)
		return;
	dyn = dynhn_find_by_id(adj->circuit->isis, adj->sysid);
	if (dyn)
		zlog_debug("%s", dyn->hostname);

	zlog_debug("SystemId %20pSY SNPA %pSY, level %d; Holding Time %d",
		   adj->sysid, adj->snpa, adj->level, adj->hold_time);
	if (adj->ipv4_address_count) {
		zlog_debug("IPv4 Address(es):");
		for (unsigned int i = 0; i < adj->ipv4_address_count; i++)
			zlog_debug("%pI4", &adj->ipv4_addresses[i]);
	}

	if (adj->ll_ipv6_count) {
		zlog_debug("IPv6 Address(es):");
		for (unsigned int i = 0; i < adj->ll_ipv6_count; i++) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &adj->ll_ipv6_addrs[i], buf,
				  sizeof(buf));
			zlog_debug("%s", buf);
		}
	}
	zlog_debug("Speaks: %s", nlpid2string(&adj->nlpids));

	return;
}

const char *isis_adj_yang_state(enum isis_adj_state state)
{
	switch (state) {
	case ISIS_ADJ_DOWN:
		return "down";
	case ISIS_ADJ_UP:
		return "up";
	case ISIS_ADJ_INITIALIZING:
		return "init";
	case ISIS_ADJ_UNKNOWN:
		return "failed";
	}

	assert(!"Reached end of function where we are not expecting to");
}

void isis_adj_expire(struct event *thread)
{
	struct isis_adjacency *adj;

	/*
	 * Get the adjacency
	 */
	adj = EVENT_ARG(thread);
	assert(adj);
	adj->t_expire = NULL;

	/* trigger the adj expire event */
	isis_adj_state_change(&adj, ISIS_ADJ_DOWN, "holding time expired");
}

/*
 * show isis neighbor [detail] json
 */
void isis_adj_print_json(struct isis_adjacency *adj, struct json_object *json,
			 char detail)
{
	json_object *iface_json, *ipv4_addr_json, *ipv6_link_json,
		*ipv6_non_link_json, *topo_json, *dis_flaps_json,
		*area_addr_json, *adj_sid_json;
	time_t now;
	struct isis_dynhn *dyn;
	int level;
	char buf[256];

	json_object_string_add(json, "adj", isis_adj_name(adj));

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		if (adj->circuit)
			json_object_string_add(json, "interface",
					       adj->circuit->interface->name);
		else
			json_object_string_add(json, "interface",
					       "NULL circuit!");
		json_object_int_add(json, "level", adj->level);
		json_object_string_add(json, "state",
				       adj_state2string(adj->adj_state));
		now = time(NULL);
		if (adj->last_upd) {
			if (adj->last_upd + adj->hold_time < now)
				json_object_string_add(json, "last-upd",
						       "expiring");
			else
				json_object_string_add(
					json, "expires-in",
					time2string(adj->last_upd +
						    adj->hold_time - now));
		}
		json_object_string_addf(json, "snpa", "%pSY", adj->snpa);
	}

	if (detail == ISIS_UI_LEVEL_DETAIL) {
		struct sr_adjacency *sra;
		struct listnode *anode;

		level = adj->level;
		iface_json = json_object_new_object();
		json_object_object_add(json, "interface", iface_json);
		if (adj->circuit)
			json_object_string_add(iface_json, "name",
					       adj->circuit->interface->name);
		else
			json_object_string_add(iface_json, "name",
					       "null-circuit");
		json_object_int_add(json, "level", adj->level);
		json_object_string_add(iface_json, "state",
				       adj_state2string(adj->adj_state));
		now = time(NULL);
		if (adj->last_upd) {
			if (adj->last_upd + adj->hold_time < now)
				json_object_string_add(iface_json, "last-upd",
						       "expiring");
			else
				json_object_string_add(
					json, "expires-in",
					time2string(adj->last_upd +
						    adj->hold_time - now));
		} else
			json_object_string_add(json, "expires-in",
					       time2string(adj->hold_time));
		json_object_int_add(iface_json, "adj-flaps", adj->flaps);
		json_object_string_add(iface_json, "last-ago",
				       time2string(now - adj->last_flap));
		json_object_string_add(iface_json, "circuit-type",
				       circuit_t2string(adj->circuit_t));
		json_object_string_add(iface_json, "speaks",
				       nlpid2string(&adj->nlpids));
		if (adj->mt_count != 1 ||
		    adj->mt_set[0] != ISIS_MT_IPV4_UNICAST) {
			topo_json = json_object_new_object();
			json_object_object_add(iface_json, "topologies",
					       topo_json);
			for (unsigned int i = 0; i < adj->mt_count; i++) {
				snprintfrr(buf, sizeof(buf), "topo-%d", i);
				json_object_string_add(
					topo_json, buf,
					isis_mtid2str(adj->mt_set[i]));
			}
		}
		json_object_string_addf(iface_json, "snpa", "%pSY", adj->snpa);
		if (adj->circuit &&
		    (adj->circuit->circ_type == CIRCUIT_T_BROADCAST)) {
			dyn = dynhn_find_by_id(adj->circuit->isis, adj->lanid);
			if (dyn) {
				snprintfrr(buf, sizeof(buf), "%s-%02x",
					   dyn->hostname,
					   adj->lanid[ISIS_SYS_ID_LEN]);
				json_object_string_add(iface_json, "lan-id",
						       buf);
			} else {
				json_object_string_addf(iface_json, "lan-id",
							"%pSY", adj->lanid);
			}

			json_object_int_add(iface_json, "lan-prio",
					    adj->prio[adj->level - 1]);

			dis_flaps_json = json_object_new_object();
			json_object_object_add(iface_json, "dis-flaps",
					       dis_flaps_json);
			json_object_string_add(
				dis_flaps_json, "dis-record",
				isis_disflag2string(
					adj->dis_record[ISIS_LEVELS + level - 1]
						.dis));
			json_object_int_add(dis_flaps_json, "last",
					    adj->dischanges[level - 1]);
			json_object_string_add(
				dis_flaps_json, "ago",
				time2string(now - (adj->dis_record[ISIS_LEVELS +
								   level - 1]
							   .last_dis_change)));
		}

		if (adj->area_address_count) {
			area_addr_json = json_object_new_object();
			json_object_object_add(iface_json, "area-address",
					       area_addr_json);
			for (unsigned int i = 0; i < adj->area_address_count;
			     i++) {
				json_object_string_addf(
					area_addr_json, "isonet", "%pIS",
					&adj->area_addresses[i]);
			}
		}
		if (adj->ipv4_address_count) {
			ipv4_addr_json = json_object_new_object();
			json_object_object_add(iface_json, "ipv4-address",
					       ipv4_addr_json);
			for (unsigned int i = 0; i < adj->ipv4_address_count;
			     i++){
				inet_ntop(AF_INET, &adj->ipv4_addresses[i], buf,
					  sizeof(buf));
			json_object_string_add(ipv4_addr_json, "ipv4", buf);
		}
		}
		if (adj->ll_ipv6_count) {
			ipv6_link_json = json_object_new_object();
			json_object_object_add(iface_json, "ipv6-link-local",
					       ipv6_link_json);
			for (unsigned int i = 0; i < adj->ll_ipv6_count; i++) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &adj->ll_ipv6_addrs[i], buf,
					  sizeof(buf));
				json_object_string_add(ipv6_link_json, "ipv6",
						       buf);
			}
		}
		if (adj->global_ipv6_count) {
			ipv6_non_link_json = json_object_new_object();
			json_object_object_add(iface_json, "ipv6-global",
					       ipv6_non_link_json);
			for (unsigned int i = 0; i < adj->global_ipv6_count;
			     i++) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &adj->global_ipv6_addrs[i],
					  buf, sizeof(buf));
				json_object_string_add(ipv6_non_link_json,
						       "ipv6", buf);
			}
		}

		adj_sid_json = json_object_new_object();
		json_object_object_add(iface_json, "adj-sid", adj_sid_json);
		for (ALL_LIST_ELEMENTS_RO(adj->adj_sids, anode, sra)) {
			const char *adj_type;
			const char *backup;
			uint32_t sid;

			switch (sra->adj->circuit->circ_type) {
			case CIRCUIT_T_BROADCAST:
				adj_type = "LAN Adjacency-SID";
				sid = sra->u.ladj_sid->sid;
				break;
			case CIRCUIT_T_P2P:
				adj_type = "Adjacency-SID";
				sid = sra->u.adj_sid->sid;
				break;
			default:
				continue;
			}
			backup = (sra->type == ISIS_SR_ADJ_BACKUP) ? " (backup)"
								   : "";

			json_object_string_add(adj_sid_json, "nexthop",
					       (sra->nexthop.family == AF_INET)
						       ? "IPv4"
						       : "IPv6");
			json_object_string_add(adj_sid_json, "adj-type",
					       adj_type);
			json_object_string_add(adj_sid_json, "is-backup",
					       backup);
			json_object_int_add(adj_sid_json, "sid", sid);
		}
	}
	return;
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

	vty_out(vty, " %-20s", isis_adj_name(adj));

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		if (adj->circuit)
			vty_out(vty, "%-12s", adj->circuit->interface->name);
		else
			vty_out(vty, "NULL circuit!");
		vty_out(vty, "%-3u", adj->level); /* level */
		vty_out(vty, "%-13s", adj_state2string(adj->adj_state));
		now = time(NULL);
		if (adj->last_upd) {
			if (adj->last_upd + adj->hold_time < now)
				vty_out(vty, " Expiring ");
			else
				vty_out(vty, " %-9llu",
					(unsigned long long)adj->last_upd
						+ adj->hold_time - now);
		} else
			vty_out(vty, " -        ");
		vty_out(vty, "%-10pSY", adj->snpa);
		vty_out(vty, "\n");
	}

	if (detail == ISIS_UI_LEVEL_DETAIL) {
		struct sr_adjacency *sra;
		struct listnode *anode;

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
		if (adj->last_upd) {
			if (adj->last_upd + adj->hold_time < now)
				vty_out(vty, " Expiring");
			else
				vty_out(vty, ", Expires in %s",
					time2string(adj->last_upd
						    + adj->hold_time - now));
		} else
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
		vty_out(vty, "    SNPA: %pSY", adj->snpa);
		if (adj->circuit
		    && (adj->circuit->circ_type == CIRCUIT_T_BROADCAST)) {
			dyn = dynhn_find_by_id(adj->circuit->isis, adj->lanid);
			if (dyn)
				vty_out(vty, ", LAN id: %s.%02x", dyn->hostname,
					adj->lanid[ISIS_SYS_ID_LEN]);
			else
				vty_out(vty, ", LAN id: %pPN", adj->lanid);

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
				vty_out(vty, "      %pIS\n",
					&adj->area_addresses[i]);
			}
		}
		if (adj->ipv4_address_count) {
			vty_out(vty, "    IPv4 Address(es):\n");
			for (unsigned int i = 0; i < adj->ipv4_address_count;
			     i++)
				vty_out(vty, "      %pI4\n",
					&adj->ipv4_addresses[i]);
		}
		if (adj->ll_ipv6_count) {
			vty_out(vty, "    IPv6 Address(es):\n");
			for (unsigned int i = 0; i < adj->ll_ipv6_count; i++) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &adj->ll_ipv6_addrs[i],
					  buf, sizeof(buf));
				vty_out(vty, "      %s\n", buf);
			}
		}
		if (adj->global_ipv6_count) {
			vty_out(vty, "    Global IPv6 Address(es):\n");
			for (unsigned int i = 0; i < adj->global_ipv6_count;
			     i++) {
				char buf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &adj->global_ipv6_addrs[i],
					  buf, sizeof(buf));
				vty_out(vty, "      %s\n", buf);
			}
		}
		if (adj->circuit && adj->circuit->bfd_config.enabled) {
			vty_out(vty, "    BFD is %s%s\n",
				adj->bfd_session ? "active, status "
						 : "configured",
				!adj->bfd_session
					? ""
					: bfd_get_status_str(bfd_sess_status(
						  adj->bfd_session)));
		}
		for (ALL_LIST_ELEMENTS_RO(adj->adj_sids, anode, sra)) {
			const char *adj_type;
			const char *backup;
			uint32_t sid;

			switch (sra->adj->circuit->circ_type) {
			case CIRCUIT_T_BROADCAST:
				adj_type = "LAN Adjacency-SID";
				sid = sra->u.ladj_sid->sid;
				break;
			case CIRCUIT_T_P2P:
				adj_type = "Adjacency-SID";
				sid = sra->u.adj_sid->sid;
				break;
			default:
				continue;
			}
			backup = (sra->type == ISIS_SR_ADJ_BACKUP) ? " (backup)"
								   : "";

			vty_out(vty, "    %s %s%s: %u\n",
				(sra->nexthop.family == AF_INET) ? "IPv4"
								 : "IPv6",
				adj_type, backup, sid);
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
		zlog_warn("%s: NULL list", __func__);
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
		if (!adj) {
			zlog_warn("%s: NULL adj", __func__);
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
		zlog_warn("%s: adjacency DB is empty", __func__);
		return;
	}

	if (!list) {
		zlog_warn("%s: NULL list", __func__);
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
		if (!adj) {
			zlog_warn("%s: NULL adj", __func__);
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
	case ISIS_ADJ_NONE:
		return 0;
	}

	assert(!"Reached end of function where we are not expecting to");
}
