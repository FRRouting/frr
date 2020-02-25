/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
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
#ifdef GNU_LINUX
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
#endif

#include "log.h"
#include "memory.h"
#include "vrf.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"
#include "qobj.h"
#include "lib/northbound_cli.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dr.h"
#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_nb.h"

DEFINE_QOBJ_TYPE(isis_circuit)

DEFINE_HOOK(isis_if_new_hook, (struct interface *ifp), (ifp))

/*
 * Prototypes.
 */
int isis_interface_config_write(struct vty *);
int isis_if_new_hook(struct interface *);
int isis_if_delete_hook(struct interface *);

struct isis_circuit *isis_circuit_new(void)
{
	struct isis_circuit *circuit;
	int i;

	circuit = XCALLOC(MTYPE_ISIS_CIRCUIT, sizeof(struct isis_circuit));

	/*
	 * Default values
	 */
#ifndef FABRICD
	circuit->is_type = yang_get_default_enum(
		"/frr-interface:lib/interface/frr-isisd:isis/circuit-type");
	circuit->flags = 0;

	circuit->pad_hellos = yang_get_default_bool(
		"/frr-interface:lib/interface/frr-isisd:isis/hello/padding");
	circuit->hello_interval[0] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1");
	circuit->hello_interval[1] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2");
	circuit->hello_multiplier[0] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1");
	circuit->hello_multiplier[1] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2");
	circuit->csnp_interval[0] = yang_get_default_uint16(
		"/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1");
	circuit->csnp_interval[1] = yang_get_default_uint16(
		"/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2");
	circuit->psnp_interval[0] = yang_get_default_uint16(
		"/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1");
	circuit->psnp_interval[1] = yang_get_default_uint16(
		"/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2");
	circuit->priority[0] = yang_get_default_uint8(
		"/frr-interface:lib/interface/frr-isisd:isis/priority/level-1");
	circuit->priority[1] = yang_get_default_uint8(
		"/frr-interface:lib/interface/frr-isisd:isis/priority/level-2");
	circuit->metric[0] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/metric/level-1");
	circuit->metric[1] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/metric/level-2");
	circuit->te_metric[0] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/metric/level-1");
	circuit->te_metric[1] = yang_get_default_uint32(
		"/frr-interface:lib/interface/frr-isisd:isis/metric/level-2");

	for (i = 0; i < 2; i++) {
		circuit->level_arg[i].level = i + 1;
		circuit->level_arg[i].circuit = circuit;
	}
#else
	circuit->is_type = IS_LEVEL_1_AND_2;
	circuit->flags = 0;
	circuit->pad_hellos = 1;
	for (i = 0; i < 2; i++) {
		circuit->hello_interval[i] = DEFAULT_HELLO_INTERVAL;
		circuit->hello_multiplier[i] = DEFAULT_HELLO_MULTIPLIER;
		circuit->csnp_interval[i] = DEFAULT_CSNP_INTERVAL;
		circuit->psnp_interval[i] = DEFAULT_PSNP_INTERVAL;
		circuit->priority[i] = DEFAULT_PRIORITY;
		circuit->metric[i] = DEFAULT_CIRCUIT_METRIC;
		circuit->te_metric[i] = DEFAULT_CIRCUIT_METRIC;
		circuit->level_arg[i].level = i + 1;
		circuit->level_arg[i].circuit = circuit;
	}
#endif /* ifndef FABRICD */

	circuit_mt_init(circuit);

	QOBJ_REG(circuit, isis_circuit);

	return circuit;
}

void isis_circuit_del(struct isis_circuit *circuit)
{
	if (!circuit)
		return;

	QOBJ_UNREG(circuit);

	isis_circuit_if_unbind(circuit, circuit->interface);

	circuit_mt_finish(circuit);

	/* and lastly the circuit itself */
	XFREE(MTYPE_ISIS_CIRCUIT, circuit);

	return;
}

void isis_circuit_configure(struct isis_circuit *circuit,
			    struct isis_area *area)
{
	assert(area);
	circuit->area = area;

	/*
	 * Whenever the is-type of an area is changed, the is-type of each
	 * circuit
	 * in that area is updated to a non-empty subset of the area is-type.
	 * Inversely, when configuring a new circuit, this property should be
	 * ensured as well.
	 */
	if (area->is_type != IS_LEVEL_1_AND_2)
		circuit->is_type = area->is_type;

	/*
	 * Add the circuit into area
	 */
	listnode_add(area->circuit_list, circuit);

	circuit->idx = flags_get_index(&area->flags);

	return;
}

void isis_circuit_deconfigure(struct isis_circuit *circuit,
			      struct isis_area *area)
{
	/* Free the index of SRM and SSN flags */
	flags_free_index(&area->flags, circuit->idx);
	circuit->idx = 0;
	/* Remove circuit from area */
	assert(circuit->area == area);
	listnode_delete(area->circuit_list, circuit);
	circuit->area = NULL;

	return;
}

struct isis_circuit *circuit_lookup_by_ifp(struct interface *ifp,
					   struct list *list)
{
	struct isis_circuit *circuit = NULL;
	struct listnode *node;

	if (!list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(list, node, circuit))
		if (circuit->interface == ifp) {
			assert(ifp->info == circuit);
			return circuit;
		}

	return NULL;
}

struct isis_circuit *circuit_scan_by_ifp(struct interface *ifp)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis_circuit *circuit;

	if (ifp->info)
		return (struct isis_circuit *)ifp->info;

	if (isis->area_list) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			circuit =
				circuit_lookup_by_ifp(ifp, area->circuit_list);
			if (circuit)
				return circuit;
		}
	}
	return circuit_lookup_by_ifp(ifp, isis->init_circ_list);
}

void isis_circuit_add_addr(struct isis_circuit *circuit,
			   struct connected *connected)
{
	struct listnode *node;
	struct prefix_ipv4 *ipv4;
#if defined(EXTREME_DEBUG)
	char buf[PREFIX2STR_BUFFER];
#endif
	struct prefix_ipv6 *ipv6;

	if (connected->address->family == AF_INET) {
		uint32_t addr = connected->address->u.prefix4.s_addr;
		addr = ntohl(addr);
		if (IPV4_NET0(addr) || IPV4_NET127(addr) || IN_CLASSD(addr)
		    || IPV4_LINKLOCAL(addr))
			return;

		for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node, ipv4))
			if (prefix_same((struct prefix *)ipv4,
					connected->address))
				return;

		ipv4 = prefix_ipv4_new();
		ipv4->prefixlen = connected->address->prefixlen;
		ipv4->prefix = connected->address->u.prefix4;
		listnode_add(circuit->ip_addrs, ipv4);

		/* Update Local IP address parameter if MPLS TE is enable */
		if (circuit->ext && IS_MPLS_TE(circuit->ext)) {
			circuit->ext->local_addr.s_addr = ipv4->prefix.s_addr;
			SET_SUBTLV(circuit->ext, EXT_LOCAL_ADDR);
		}

		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);

#ifdef EXTREME_DEBUG
		prefix2str(connected->address, buf, sizeof(buf));
		zlog_debug("Added IP address %s to circuit %s", buf,
			   circuit->interface->name);
#endif /* EXTREME_DEBUG */
	}
	if (connected->address->family == AF_INET6) {
		if (IN6_IS_ADDR_LOOPBACK(&connected->address->u.prefix6))
			return;

		for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node, ipv6))
			if (prefix_same((struct prefix *)ipv6,
					connected->address))
				return;
		for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node, ipv6))
			if (prefix_same((struct prefix *)ipv6,
					connected->address))
				return;

		ipv6 = prefix_ipv6_new();
		ipv6->prefixlen = connected->address->prefixlen;
		ipv6->prefix = connected->address->u.prefix6;

		if (IN6_IS_ADDR_LINKLOCAL(&ipv6->prefix))
			listnode_add(circuit->ipv6_link, ipv6);
		else
			listnode_add(circuit->ipv6_non_link, ipv6);
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);

#ifdef EXTREME_DEBUG
		prefix2str(connected->address, buf, sizeof(buf));
		zlog_debug("Added IPv6 address %s to circuit %s", buf,
			   circuit->interface->name);
#endif /* EXTREME_DEBUG */
	}
	return;
}

void isis_circuit_del_addr(struct isis_circuit *circuit,
			   struct connected *connected)
{
	struct prefix_ipv4 *ipv4, *ip = NULL;
	struct listnode *node;
	char buf[PREFIX2STR_BUFFER];
	struct prefix_ipv6 *ipv6, *ip6 = NULL;
	int found = 0;

	if (connected->address->family == AF_INET) {
		ipv4 = prefix_ipv4_new();
		ipv4->prefixlen = connected->address->prefixlen;
		ipv4->prefix = connected->address->u.prefix4;

		for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node, ip))
			if (prefix_same((struct prefix *)ip,
					(struct prefix *)ipv4))
				break;

		if (ip) {
			listnode_delete(circuit->ip_addrs, ip);
			prefix_ipv4_free(&ip);
			if (circuit->area)
				lsp_regenerate_schedule(circuit->area,
							circuit->is_type, 0);
		} else {
			prefix2str(connected->address, buf, sizeof(buf));
			zlog_warn(
				"Nonexistent ip address %s removal attempt from \
                      circuit %s",
				buf, circuit->interface->name);
			zlog_warn("Current ip addresses on %s:",
				  circuit->interface->name);
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node,
						  ip)) {
				prefix2str(ip, buf, sizeof(buf));
				zlog_warn("  %s", buf);
			}
			zlog_warn("End of addresses");
		}

		prefix_ipv4_free(&ipv4);
	}
	if (connected->address->family == AF_INET6) {
		ipv6 = prefix_ipv6_new();
		ipv6->prefixlen = connected->address->prefixlen;
		ipv6->prefix = connected->address->u.prefix6;

		if (IN6_IS_ADDR_LINKLOCAL(&ipv6->prefix)) {
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip6)) {
				if (prefix_same((struct prefix *)ip6,
						(struct prefix *)ipv6))
					break;
			}
			if (ip6) {
				listnode_delete(circuit->ipv6_link, ip6);
				prefix_ipv6_free(&ip6);
				found = 1;
			}
		} else {
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip6)) {
				if (prefix_same((struct prefix *)ip6,
						(struct prefix *)ipv6))
					break;
			}
			if (ip6) {
				listnode_delete(circuit->ipv6_non_link, ip6);
				prefix_ipv6_free(&ip6);
				found = 1;
			}
		}

		if (!found) {
			prefix2str(connected->address, buf, sizeof(buf));
			zlog_warn(
				"Nonexistent ip address %s removal attempt from \
		      circuit %s",
				buf, circuit->interface->name);
			zlog_warn("Current ip addresses on %s:",
				  circuit->interface->name);
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip6)) {
				prefix2str((struct prefix *)ip6, (char *)buf,
					   sizeof(buf));
				zlog_warn("  %s", buf);
			}
			zlog_warn(" -----");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip6)) {
				prefix2str((struct prefix *)ip6, (char *)buf,
					   sizeof(buf));
				zlog_warn("  %s", buf);
			}
			zlog_warn("End of addresses");
		} else if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);

		prefix_ipv6_free(&ipv6);
	}
	return;
}

static uint8_t isis_circuit_id_gen(struct isis *isis, struct interface *ifp)
{
	/* Circuit ids MUST be unique for any broadcast circuits. Otherwise,
	 * Pseudo-Node LSPs cannot be generated correctly.
	 *
	 * Currently, allocate one circuit ID for any circuit, limiting the total
	 * numer of circuits IS-IS can run on to 255.
	 *
	 * We should revisit this when implementing 3-way adjacencies for p2p, since
	 * we then have extended interface IDs available.
	 */
	uint8_t id = ifp->ifindex;
	unsigned int i;

	for (i = 0; i < 256; i++) {
		if (id && !_ISIS_CHECK_FLAG(isis->circuit_ids_used, id))
			break;
		id++;
	}

	if (i == 256) {
		zlog_warn("Could not allocate a circuit id for '%s'",
			  ifp->name);
		return 0;
	}

	_ISIS_SET_FLAG(isis->circuit_ids_used, id);
	return id;
}

void isis_circuit_if_add(struct isis_circuit *circuit, struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct connected *conn;

	isis_circuit_if_bind(circuit, ifp);

	if (if_is_broadcast(ifp)) {
		if (fabricd || circuit->circ_type_config == CIRCUIT_T_P2P)
			circuit->circ_type = CIRCUIT_T_P2P;
		else
			circuit->circ_type = CIRCUIT_T_BROADCAST;
	} else if (if_is_pointopoint(ifp)) {
		circuit->circ_type = CIRCUIT_T_P2P;
	} else if (if_is_loopback(ifp)) {
		circuit->circ_type = CIRCUIT_T_LOOPBACK;
		circuit->is_passive = 1;
	} else {
		/* It's normal in case of loopback etc. */
		if (isis->debugs & DEBUG_EVENTS)
			zlog_debug("isis_circuit_if_add: unsupported media");
		circuit->circ_type = CIRCUIT_T_UNKNOWN;
	}

	circuit->ip_addrs = list_new();
	circuit->ipv6_link = list_new();
	circuit->ipv6_non_link = list_new();

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, conn))
		isis_circuit_add_addr(circuit, conn);

}

void isis_circuit_if_del(struct isis_circuit *circuit, struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct connected *conn;

	assert(circuit->interface == ifp);

	/* destroy addresses */
	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, conn))
		isis_circuit_del_addr(circuit, conn);

	if (circuit->ip_addrs) {
		assert(listcount(circuit->ip_addrs) == 0);
		list_delete(&circuit->ip_addrs);
	}

	if (circuit->ipv6_link) {
		assert(listcount(circuit->ipv6_link) == 0);
		list_delete(&circuit->ipv6_link);
	}

	if (circuit->ipv6_non_link) {
		assert(listcount(circuit->ipv6_non_link) == 0);
		list_delete(&circuit->ipv6_non_link);
	}

	circuit->circ_type = CIRCUIT_T_UNKNOWN;
}

void isis_circuit_if_bind(struct isis_circuit *circuit, struct interface *ifp)
{
	assert(circuit != NULL);
	assert(ifp != NULL);
	if (circuit->interface)
		assert(circuit->interface == ifp);
	else
		circuit->interface = ifp;
	if (ifp->info)
		assert(ifp->info == circuit);
	else
		ifp->info = circuit;
}

void isis_circuit_if_unbind(struct isis_circuit *circuit, struct interface *ifp)
{
	assert(circuit != NULL);
	assert(ifp != NULL);
	assert(circuit->interface == ifp);
	assert(ifp->info == circuit);
	circuit->interface = NULL;
	ifp->info = NULL;
}

static void isis_circuit_update_all_srmflags(struct isis_circuit *circuit,
					     int is_set)
{
	struct isis_area *area;
	struct isis_lsp *lsp;
	int level;

	assert(circuit);
	area = circuit->area;
	assert(area);
	for (level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		if (!(level & circuit->is_type))
			continue;

		if (!lspdb_count(&area->lspdb[level - 1]))
			continue;

		frr_each (lspdb, &area->lspdb[level - 1], lsp) {
			if (is_set) {
				isis_tx_queue_add(circuit->tx_queue, lsp,
						  TX_LSP_NORMAL);
			} else {
				isis_tx_queue_del(circuit->tx_queue, lsp);
			}
		}
	}
}

size_t isis_circuit_pdu_size(struct isis_circuit *circuit)
{
	return ISO_MTU(circuit);
}

void isis_circuit_stream(struct isis_circuit *circuit, struct stream **stream)
{
	size_t stream_size = isis_circuit_pdu_size(circuit);

	if (!*stream) {
		*stream = stream_new(stream_size);
	} else {
		if (STREAM_SIZE(*stream) != stream_size)
			stream_resize_inplace(stream, stream_size);
		stream_reset(*stream);
	}
}

void isis_circuit_prepare(struct isis_circuit *circuit)
{
#if ISIS_METHOD != ISIS_METHOD_DLPI
	thread_add_read(master, isis_receive, circuit, circuit->fd,
			&circuit->t_read);
#else
	thread_add_timer_msec(master, isis_receive, circuit,
			      listcount(circuit->area->circuit_list) * 100,
			      &circuit->t_read);
#endif
}

int isis_circuit_up(struct isis_circuit *circuit)
{
	int retv;

	/* Set the flags for all the lsps of the circuit. */
	isis_circuit_update_all_srmflags(circuit, 1);

	if (circuit->state == C_STATE_UP)
		return ISIS_OK;

	if (circuit->is_passive)
		return ISIS_OK;

	if (circuit->area->lsp_mtu > isis_circuit_pdu_size(circuit)) {
		flog_err(
			EC_ISIS_CONFIG,
			"Interface MTU %zu on %s is too low to support area lsp mtu %u!",
			isis_circuit_pdu_size(circuit),
			circuit->interface->name, circuit->area->lsp_mtu);
		isis_circuit_update_all_srmflags(circuit, 0);
		return ISIS_ERROR;
	}

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		circuit->circuit_id = isis_circuit_id_gen(isis, circuit->interface);
		if (!circuit->circuit_id) {
			flog_err(
				EC_ISIS_CONFIG,
				"There are already 255 broadcast circuits active!");
			return ISIS_ERROR;
		}

		/*
		 * Get the Hardware Address
		 */
		if (circuit->interface->hw_addr_len != ETH_ALEN) {
			zlog_warn("unsupported link layer");
		} else {
			memcpy(circuit->u.bc.snpa, circuit->interface->hw_addr,
			       ETH_ALEN);
		}
#ifdef EXTREME_DEGUG
		zlog_debug("isis_circuit_if_add: if_id %d, isomtu %d snpa %s",
			   circuit->interface->ifindex, ISO_MTU(circuit),
			   snpa_print(circuit->u.bc.snpa));
#endif /* EXTREME_DEBUG */

		circuit->u.bc.adjdb[0] = list_new();
		circuit->u.bc.adjdb[1] = list_new();

		/*
		 * ISO 10589 - 8.4.1 Enabling of broadcast circuits
		 */

		/* initilizing the hello sending threads
		 * for a broadcast IF
		 */

		/* 8.4.1 a) commence sending of IIH PDUs */

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(circuit->is_type & level))
				continue;

			send_hello_sched(circuit, level, TRIGGERED_IIH_DELAY);
			circuit->u.bc.lan_neighs[level - 1] = list_new();

			thread_add_timer(master, isis_run_dr,
					 &circuit->level_arg[level - 1],
					 2 * circuit->hello_interval[level - 1],
					 &circuit->u.bc.t_run_dr[level - 1]);
		}

		/* 8.4.1 b) FIXME: solicit ES - 8.4.6 */
		/* 8.4.1 c) FIXME: listen for ESH PDUs */
	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		/* initializing the hello send threads
		 * for a ptp IF
		 */
		circuit->u.p2p.neighbor = NULL;
		send_hello_sched(circuit, 0, TRIGGERED_IIH_DELAY);
	}

	/* initializing PSNP timers */
	if (circuit->is_type & IS_LEVEL_1)
		thread_add_timer(
			master, send_l1_psnp, circuit,
			isis_jitter(circuit->psnp_interval[0], PSNP_JITTER),
			&circuit->t_send_psnp[0]);

	if (circuit->is_type & IS_LEVEL_2)
		thread_add_timer(
			master, send_l2_psnp, circuit,
			isis_jitter(circuit->psnp_interval[1], PSNP_JITTER),
			&circuit->t_send_psnp[1]);

	/* unified init for circuits; ignore warnings below this level */
	retv = isis_sock_init(circuit);
	if (retv != ISIS_OK) {
		isis_circuit_down(circuit);
		return retv;
	}

	/* initialize the circuit streams after opening connection */
	isis_circuit_stream(circuit, &circuit->rcv_stream);
	isis_circuit_stream(circuit, &circuit->snd_stream);

	isis_circuit_prepare(circuit);

	circuit->tx_queue = isis_tx_queue_new(circuit, send_lsp);

#ifndef FABRICD
	/* send northbound notification */
	isis_notif_if_state_change(circuit, false);
#endif /* ifndef FABRICD */

	return ISIS_OK;
}

void isis_circuit_down(struct isis_circuit *circuit)
{
#ifndef FABRICD
	/* send northbound notification */
	isis_notif_if_state_change(circuit, true);
#endif /* ifndef FABRICD */

	/* Clear the flags for all the lsps of the circuit. */
	isis_circuit_update_all_srmflags(circuit, 0);

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		/* destroy neighbour lists */
		if (circuit->u.bc.lan_neighs[0]) {
			list_delete(&circuit->u.bc.lan_neighs[0]);
			circuit->u.bc.lan_neighs[0] = NULL;
		}
		if (circuit->u.bc.lan_neighs[1]) {
			list_delete(&circuit->u.bc.lan_neighs[1]);
			circuit->u.bc.lan_neighs[1] = NULL;
		}
		/* destroy adjacency databases */
		if (circuit->u.bc.adjdb[0]) {
			circuit->u.bc.adjdb[0]->del = isis_delete_adj;
			list_delete(&circuit->u.bc.adjdb[0]);
			circuit->u.bc.adjdb[0] = NULL;
		}
		if (circuit->u.bc.adjdb[1]) {
			circuit->u.bc.adjdb[1]->del = isis_delete_adj;
			list_delete(&circuit->u.bc.adjdb[1]);
			circuit->u.bc.adjdb[1] = NULL;
		}
		if (circuit->u.bc.is_dr[0]) {
			isis_dr_resign(circuit, 1);
			circuit->u.bc.is_dr[0] = 0;
		}
		memset(circuit->u.bc.l1_desig_is, 0, ISIS_SYS_ID_LEN + 1);
		if (circuit->u.bc.is_dr[1]) {
			isis_dr_resign(circuit, 2);
			circuit->u.bc.is_dr[1] = 0;
		}
		memset(circuit->u.bc.l2_desig_is, 0, ISIS_SYS_ID_LEN + 1);
		memset(circuit->u.bc.snpa, 0, ETH_ALEN);

		THREAD_TIMER_OFF(circuit->u.bc.t_send_lan_hello[0]);
		THREAD_TIMER_OFF(circuit->u.bc.t_send_lan_hello[1]);
		THREAD_TIMER_OFF(circuit->u.bc.t_run_dr[0]);
		THREAD_TIMER_OFF(circuit->u.bc.t_run_dr[1]);
		THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[0]);
		THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[1]);
		circuit->lsp_regenerate_pending[0] = 0;
		circuit->lsp_regenerate_pending[1] = 0;

		_ISIS_CLEAR_FLAG(isis->circuit_ids_used, circuit->circuit_id);
		circuit->circuit_id = 0;
	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		isis_delete_adj(circuit->u.p2p.neighbor);
		circuit->u.p2p.neighbor = NULL;
		THREAD_TIMER_OFF(circuit->u.p2p.t_send_p2p_hello);
	}

	/* Cancel all active threads */
	THREAD_TIMER_OFF(circuit->t_send_csnp[0]);
	THREAD_TIMER_OFF(circuit->t_send_csnp[1]);
	THREAD_TIMER_OFF(circuit->t_send_psnp[0]);
	THREAD_TIMER_OFF(circuit->t_send_psnp[1]);
	THREAD_OFF(circuit->t_read);

	if (circuit->tx_queue) {
		isis_tx_queue_free(circuit->tx_queue);
		circuit->tx_queue = NULL;
	}

	/* send one gratuitous hello to spead up convergence */
	if (circuit->state == C_STATE_UP) {
		if (circuit->is_type & IS_LEVEL_1)
			send_hello(circuit, IS_LEVEL_1);
		if (circuit->is_type & IS_LEVEL_2)
			send_hello(circuit, IS_LEVEL_2);
	}

	circuit->upadjcount[0] = 0;
	circuit->upadjcount[1] = 0;

	/* close the socket */
	if (circuit->fd) {
		close(circuit->fd);
		circuit->fd = 0;
	}

	if (circuit->rcv_stream != NULL) {
		stream_free(circuit->rcv_stream);
		circuit->rcv_stream = NULL;
	}

	if (circuit->snd_stream != NULL) {
		stream_free(circuit->snd_stream);
		circuit->snd_stream = NULL;
	}

	thread_cancel_event(master, circuit);

	return;
}

void circuit_update_nlpids(struct isis_circuit *circuit)
{
	circuit->nlpids.count = 0;

	if (circuit->ip_router) {
		circuit->nlpids.nlpids[0] = NLPID_IP;
		circuit->nlpids.count++;
	}
	if (circuit->ipv6_router) {
		circuit->nlpids.nlpids[circuit->nlpids.count] = NLPID_IPV6;
		circuit->nlpids.count++;
	}
	return;
}

void isis_circuit_print_vty(struct isis_circuit *circuit, struct vty *vty,
			    char detail)
{
	if (detail == ISIS_UI_LEVEL_BRIEF) {
		vty_out(vty, "  %-12s", circuit->interface->name);
		vty_out(vty, "0x%-7x", circuit->circuit_id);
		vty_out(vty, "%-9s", circuit_state2string(circuit->state));
		vty_out(vty, "%-9s", circuit_type2string(circuit->circ_type));
		vty_out(vty, "%-9s", circuit_t2string(circuit->is_type));
		vty_out(vty, "\n");
	}

	if (detail == ISIS_UI_LEVEL_DETAIL) {
		struct listnode *node;
		struct prefix *ip_addr;
		char buf[BUFSIZ];

		vty_out(vty, "  Interface: %s", circuit->interface->name);
		vty_out(vty, ", State: %s",
			circuit_state2string(circuit->state));
		if (circuit->is_passive)
			vty_out(vty, ", Passive");
		else
			vty_out(vty, ", Active");
		vty_out(vty, ", Circuit Id: 0x%x", circuit->circuit_id);
		vty_out(vty, "\n");
		vty_out(vty, "    Type: %s",
			circuit_type2string(circuit->circ_type));
		vty_out(vty, ", Level: %s", circuit_t2string(circuit->is_type));
		if (circuit->circ_type == CIRCUIT_T_BROADCAST)
			vty_out(vty, ", SNPA: %-10s",
				snpa_print(circuit->u.bc.snpa));
		vty_out(vty, "\n");
		if (circuit->is_type & IS_LEVEL_1) {
			vty_out(vty, "    Level-1 Information:\n");
			if (circuit->area->newmetric)
				vty_out(vty, "      Metric: %d",
					circuit->te_metric[0]);
			else
				vty_out(vty, "      Metric: %d",
					circuit->metric[0]);
			if (!circuit->is_passive) {
				vty_out(vty, ", Active neighbors: %u\n",
					circuit->upadjcount[0]);
				vty_out(vty,
					"      Hello interval: %u, "
					"Holddown count: %u %s\n",
					circuit->hello_interval[0],
					circuit->hello_multiplier[0],
					(circuit->pad_hellos ? "(pad)"
							     : "(no-pad)"));
				vty_out(vty,
					"      CNSP interval: %u, "
					"PSNP interval: %u\n",
					circuit->csnp_interval[0],
					circuit->psnp_interval[0]);
				if (circuit->circ_type == CIRCUIT_T_BROADCAST)
					vty_out(vty,
						"      LAN Priority: %u, %s\n",
						circuit->priority[0],
						(circuit->u.bc.is_dr[0]
							 ? "is DIS"
							 : "is not DIS"));
			} else {
				vty_out(vty, "\n");
			}
		}
		if (circuit->is_type & IS_LEVEL_2) {
			vty_out(vty, "    Level-2 Information:\n");
			if (circuit->area->newmetric)
				vty_out(vty, "      Metric: %d",
					circuit->te_metric[1]);
			else
				vty_out(vty, "      Metric: %d",
					circuit->metric[1]);
			if (!circuit->is_passive) {
				vty_out(vty, ", Active neighbors: %u\n",
					circuit->upadjcount[1]);
				vty_out(vty,
					"      Hello interval: %u, "
					"Holddown count: %u %s\n",
					circuit->hello_interval[1],
					circuit->hello_multiplier[1],
					(circuit->pad_hellos ? "(pad)"
							     : "(no-pad)"));
				vty_out(vty,
					"      CNSP interval: %u, "
					"PSNP interval: %u\n",
					circuit->csnp_interval[1],
					circuit->psnp_interval[1]);
				if (circuit->circ_type == CIRCUIT_T_BROADCAST)
					vty_out(vty,
						"      LAN Priority: %u, %s\n",
						circuit->priority[1],
						(circuit->u.bc.is_dr[1]
							 ? "is DIS"
							 : "is not DIS"));
			} else {
				vty_out(vty, "\n");
			}
		}
		if (circuit->ip_addrs && listcount(circuit->ip_addrs) > 0) {
			vty_out(vty, "    IP Prefix(es):\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node,
						  ip_addr)) {
				prefix2str(ip_addr, buf, sizeof(buf));
				vty_out(vty, "      %s\n", buf);
			}
		}
		if (circuit->ipv6_link && listcount(circuit->ipv6_link) > 0) {
			vty_out(vty, "    IPv6 Link-Locals:\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip_addr)) {
				prefix2str(ip_addr, (char *)buf, BUFSIZ);
				vty_out(vty, "      %s\n", buf);
			}
		}
		if (circuit->ipv6_non_link
		    && listcount(circuit->ipv6_non_link) > 0) {
			vty_out(vty, "    IPv6 Prefixes:\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip_addr)) {
				prefix2str(ip_addr, (char *)buf, BUFSIZ);
				vty_out(vty, "      %s\n", buf);
			}
		}

		vty_out(vty, "\n");
	}
	return;
}

DEFINE_HOOK(isis_circuit_config_write,
	    (struct isis_circuit *circuit, struct vty *vty),
	    (circuit, vty))

#ifdef FABRICD
int isis_interface_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	int write = 0;
	struct listnode *node;
	struct interface *ifp;
	struct isis_area *area;
	struct isis_circuit *circuit;
	int i;

	FOR_ALL_INTERFACES (vrf, ifp) {
		/* IF name */
		vty_frame(vty, "interface %s\n", ifp->name);
		write++;
		/* IF desc */
		if (ifp->desc) {
			vty_out(vty, " description %s\n", ifp->desc);
			write++;
		}
		/* ISIS Circuit */
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			circuit =
				circuit_lookup_by_ifp(ifp, area->circuit_list);
			if (circuit == NULL)
				continue;
			if (circuit->ip_router) {
				vty_out(vty, " ip router " PROTO_NAME " %s\n",
					area->area_tag);
				write++;
			}
			if (circuit->is_passive) {
				vty_out(vty, " " PROTO_NAME " passive\n");
				write++;
			}
			if (circuit->circ_type_config == CIRCUIT_T_P2P) {
				vty_out(vty, " " PROTO_NAME " network point-to-point\n");
				write++;
			}
			if (circuit->ipv6_router) {
				vty_out(vty, " ipv6 router " PROTO_NAME " %s\n",
					area->area_tag);
				write++;
			}

			/* ISIS - circuit type */
			if (!fabricd) {
				if (circuit->is_type == IS_LEVEL_1) {
					vty_out(vty, " " PROTO_NAME " circuit-type level-1\n");
					write++;
				} else {
					if (circuit->is_type == IS_LEVEL_2) {
						vty_out(vty,
							" " PROTO_NAME " circuit-type level-2-only\n");
						write++;
					}
				}
			}

			/* ISIS - CSNP interval */
			if (circuit->csnp_interval[0]
			    == circuit->csnp_interval[1]) {
				if (circuit->csnp_interval[0]
				    != DEFAULT_CSNP_INTERVAL) {
					vty_out(vty, " " PROTO_NAME " csnp-interval %d\n",
						circuit->csnp_interval[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->csnp_interval[i]
					    != DEFAULT_CSNP_INTERVAL) {
						vty_out(vty,
							" " PROTO_NAME " csnp-interval %d level-%d\n",
							circuit->csnp_interval
								[i],
							i + 1);
						write++;
					}
				}
			}

			/* ISIS - PSNP interval */
			if (circuit->psnp_interval[0]
			    == circuit->psnp_interval[1]) {
				if (circuit->psnp_interval[0]
				    != DEFAULT_PSNP_INTERVAL) {
					vty_out(vty, " " PROTO_NAME " psnp-interval %d\n",
						circuit->psnp_interval[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->psnp_interval[i]
					    != DEFAULT_PSNP_INTERVAL) {
						vty_out(vty,
							" " PROTO_NAME " psnp-interval %d level-%d\n",
							circuit->psnp_interval
								[i],
							i + 1);
						write++;
					}
				}
			}

			/* ISIS - Hello padding - Defaults to true so only
			 * display if false */
			if (circuit->pad_hellos == 0) {
				vty_out(vty, " no " PROTO_NAME " hello padding\n");
				write++;
			}

			if (circuit->disable_threeway_adj) {
				vty_out(vty, " no isis three-way-handshake\n");
				write++;
			}

			/* ISIS - Hello interval */
			if (circuit->hello_interval[0]
			    == circuit->hello_interval[1]) {
				if (circuit->hello_interval[0]
				    != DEFAULT_HELLO_INTERVAL) {
					vty_out(vty,
						" " PROTO_NAME " hello-interval %d\n",
						circuit->hello_interval[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->hello_interval[i]
					    != DEFAULT_HELLO_INTERVAL) {
						vty_out(vty,
							" " PROTO_NAME " hello-interval %d level-%d\n",
							circuit->hello_interval
								[i],
							i + 1);
						write++;
					}
				}
			}

			/* ISIS - Hello Multiplier */
			if (circuit->hello_multiplier[0]
			    == circuit->hello_multiplier[1]) {
				if (circuit->hello_multiplier[0]
				    != DEFAULT_HELLO_MULTIPLIER) {
					vty_out(vty,
						" " PROTO_NAME " hello-multiplier %d\n",
						circuit->hello_multiplier[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->hello_multiplier[i]
					    != DEFAULT_HELLO_MULTIPLIER) {
						vty_out(vty,
							" " PROTO_NAME " hello-multiplier %d level-%d\n",
							circuit->hello_multiplier
								[i],
							i + 1);
						write++;
					}
				}
			}

			/* ISIS - Priority */
			if (circuit->priority[0] == circuit->priority[1]) {
				if (circuit->priority[0] != DEFAULT_PRIORITY) {
					vty_out(vty, " " PROTO_NAME " priority %d\n",
						circuit->priority[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->priority[i]
					    != DEFAULT_PRIORITY) {
						vty_out(vty,
							" " PROTO_NAME " priority %d level-%d\n",
							circuit->priority[i],
							i + 1);
						write++;
					}
				}
			}

			/* ISIS - Metric */
			if (circuit->te_metric[0] == circuit->te_metric[1]) {
				if (circuit->te_metric[0]
				    != DEFAULT_CIRCUIT_METRIC) {
					vty_out(vty, " " PROTO_NAME " metric %d\n",
						circuit->te_metric[0]);
					write++;
				}
			} else {
				for (i = 0; i < 2; i++) {
					if (circuit->te_metric[i]
					    != DEFAULT_CIRCUIT_METRIC) {
						vty_out(vty,
							" " PROTO_NAME " metric %d level-%d\n",
							circuit->te_metric[i],
							i + 1);
						write++;
					}
				}
			}
			if (circuit->passwd.type == ISIS_PASSWD_TYPE_HMAC_MD5) {
				vty_out(vty, " " PROTO_NAME " password md5 %s\n",
					circuit->passwd.passwd);
				write++;
			} else if (circuit->passwd.type
				   == ISIS_PASSWD_TYPE_CLEARTXT) {
				vty_out(vty, " " PROTO_NAME " password clear %s\n",
					circuit->passwd.passwd);
				write++;
			}
			write += hook_call(isis_circuit_config_write,
					   circuit, vty);
		}
		vty_endframe(vty, "!\n");
	}

	return write;
}
#else
int isis_interface_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	int write = 0;
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct lyd_node *dnode;

	FOR_ALL_INTERFACES (vrf, ifp) {
		dnode = yang_dnode_get(
			running_config->dnode,
			"/frr-interface:lib/interface[name='%s'][vrf='%s']",
			ifp->name, vrf->name);
		if (dnode == NULL)
			continue;

		write++;
		nb_cli_show_dnode_cmds(vty, dnode, false);
		circuit = circuit_scan_by_ifp(ifp);
		if (circuit)
			write += hook_call(isis_circuit_config_write, circuit,
					   vty);
	}
	return write;
}
#endif /* ifdef FABRICD */

struct isis_circuit *isis_circuit_create(struct isis_area *area,
					 struct interface *ifp)
{
	struct isis_circuit *circuit = circuit_scan_by_ifp(ifp);
	if (circuit && circuit->area)
		return NULL;
	circuit = isis_csm_state_change(ISIS_ENABLE, circuit, area);
	if (circuit->state != C_STATE_CONF && circuit->state != C_STATE_UP)
		return circuit;
	isis_circuit_if_bind(circuit, ifp);
	return circuit;
}

void isis_circuit_af_set(struct isis_circuit *circuit, bool ip_router,
			 bool ipv6_router)
{
	struct isis_area *area = circuit->area;
	bool change = circuit->ip_router != ip_router
		      || circuit->ipv6_router != ipv6_router;

	area->ip_circuits += ip_router - circuit->ip_router;
	area->ipv6_circuits += ipv6_router - circuit->ipv6_router;
	circuit->ip_router = ip_router;
	circuit->ipv6_router = ipv6_router;

	if (!change)
		return;

	circuit_update_nlpids(circuit);

	if (!ip_router && !ipv6_router)
		isis_csm_state_change(ISIS_DISABLE, circuit, area);
	else
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);
}

ferr_r isis_circuit_passive_set(struct isis_circuit *circuit, bool passive)
{
	if (circuit->is_passive == passive)
		return ferr_ok();

	if (if_is_loopback(circuit->interface) && !passive)
		return ferr_cfg_invalid("loopback is always passive");

	if (circuit->state != C_STATE_UP) {
		circuit->is_passive = passive;
	} else {
		struct isis_area *area = circuit->area;
		isis_csm_state_change(ISIS_DISABLE, circuit, area);
		circuit->is_passive = passive;
		isis_csm_state_change(ISIS_ENABLE, circuit, area);
	}

	return ferr_ok();
}

ferr_r isis_circuit_metric_set(struct isis_circuit *circuit, int level,
			       int metric)
{
	assert(level == IS_LEVEL_1 || level == IS_LEVEL_2);
	if (metric > MAX_WIDE_LINK_METRIC)
		return ferr_cfg_invalid("metric %d too large for wide metric",
					metric);
	if (circuit->area && circuit->area->oldmetric
	    && metric > MAX_NARROW_LINK_METRIC)
		return ferr_cfg_invalid("metric %d too large for narrow metric",
					metric);

	circuit->te_metric[level - 1] = metric;
	circuit->metric[level - 1] = metric;

	if (circuit->area)
		lsp_regenerate_schedule(circuit->area, level, 0);
	return ferr_ok();
}

ferr_r isis_circuit_passwd_unset(struct isis_circuit *circuit)
{
	memset(&circuit->passwd, 0, sizeof(circuit->passwd));
	return ferr_ok();
}

ferr_r isis_circuit_passwd_set(struct isis_circuit *circuit,
			       uint8_t passwd_type, const char *passwd)
{
	int len;

	if (!passwd)
		return ferr_code_bug("no circuit password given");

	len = strlen(passwd);
	if (len > 254)
		return ferr_code_bug(
			"circuit password too long (max 254 chars)");

	circuit->passwd.len = len;
	strlcpy((char *)circuit->passwd.passwd, passwd,
		sizeof(circuit->passwd.passwd));
	circuit->passwd.type = passwd_type;
	return ferr_ok();
}

ferr_r isis_circuit_passwd_cleartext_set(struct isis_circuit *circuit,
					 const char *passwd)
{
	return isis_circuit_passwd_set(circuit, ISIS_PASSWD_TYPE_CLEARTXT,
				       passwd);
}

ferr_r isis_circuit_passwd_hmac_md5_set(struct isis_circuit *circuit,
					const char *passwd)
{
	return isis_circuit_passwd_set(circuit, ISIS_PASSWD_TYPE_HMAC_MD5,
				       passwd);
}

struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1,
};

void isis_circuit_circ_type_set(struct isis_circuit *circuit, int circ_type)
{
	if (circuit->circ_type == circ_type)
		return;

	if (circuit->state != C_STATE_UP) {
		circuit->circ_type = circ_type;
		circuit->circ_type_config = circ_type;
	} else {
		struct isis_area *area = circuit->area;

		isis_csm_state_change(ISIS_DISABLE, circuit, area);
		circuit->circ_type = circ_type;
		circuit->circ_type_config = circ_type;
		isis_csm_state_change(ISIS_ENABLE, circuit, area);
	}
}

int isis_circuit_mt_enabled_set(struct isis_circuit *circuit, uint16_t mtid,
				bool enabled)
{
	struct isis_circuit_mt_setting *setting;

	setting = circuit_get_mt_setting(circuit, mtid);
	if (setting->enabled != enabled) {
		setting->enabled = enabled;
		lsp_regenerate_schedule(circuit->area, IS_LEVEL_1 | IS_LEVEL_2,
					0);
	}

	return CMD_SUCCESS;
}

int isis_if_new_hook(struct interface *ifp)
{
	return 0;
}

int isis_if_delete_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	/* Clean up the circuit data */
	if (ifp && ifp->info) {
		circuit = ifp->info;
		isis_csm_state_change(IF_DOWN_FROM_Z, circuit, circuit->area);
		isis_csm_state_change(ISIS_DISABLE, circuit, circuit->area);
	}

	return 0;
}

static int isis_ifp_create(struct interface *ifp)
{
	if (if_is_operative(ifp))
		isis_csm_state_change(IF_UP_FROM_Z, circuit_scan_by_ifp(ifp),
				      ifp);

	hook_call(isis_if_new_hook, ifp);

	return 0;
}

static int isis_ifp_up(struct interface *ifp)
{
	isis_csm_state_change(IF_UP_FROM_Z, circuit_scan_by_ifp(ifp), ifp);

	return 0;
}

static int isis_ifp_down(struct interface *ifp)
{
	struct isis_circuit *circuit;

	circuit = isis_csm_state_change(IF_DOWN_FROM_Z,
					circuit_scan_by_ifp(ifp), ifp);
	if (circuit)
		SET_FLAG(circuit->flags, ISIS_CIRCUIT_FLAPPED_AFTER_SPF);

	return 0;
}

static int isis_ifp_destroy(struct interface *ifp)
{
	if (if_is_operative(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	isis_csm_state_change(IF_DOWN_FROM_Z, circuit_scan_by_ifp(ifp), ifp);

	/* Cannot call if_delete because we should retain the pseudo interface
	   in case there is configuration info attached to it. */
	if_delete_retain(ifp);

	return 0;
}

void isis_circuit_init(void)
{
	/* Initialize Zebra interface data structure */
	hook_register_prio(if_add, 0, isis_if_new_hook);
	hook_register_prio(if_del, 0, isis_if_delete_hook);

	/* Install interface node */
	install_node(&interface_node, isis_interface_config_write);
	if_cmd_init();
	if_zapi_callbacks(isis_ifp_create, isis_ifp_up,
			  isis_ifp_down, isis_ifp_destroy);
}
