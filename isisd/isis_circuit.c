// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
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
#include "frrevent.h"
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
#include "isisd/isis_srv6.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_ldp_sync.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_CIRCUIT, "ISIS circuit");

DEFINE_QOBJ_TYPE(isis_circuit);

DEFINE_HOOK(isis_if_new_hook, (struct interface *ifp), (ifp));

/*
 * Prototypes.
 */
int isis_if_new_hook(struct interface *);
int isis_if_delete_hook(struct interface *);

DEFINE_HOOK(isis_circuit_new_hook, (struct isis_circuit *circuit), (circuit));
DEFINE_HOOK(isis_circuit_del_hook, (struct isis_circuit *circuit), (circuit));

static void isis_circuit_enable(struct isis_circuit *circuit)
{
	struct isis_area *area = circuit->area;
	struct interface *ifp = circuit->interface;

	if (!area) {
		area = isis_area_lookup(circuit->tag, ifp->vrf->vrf_id);
		if (area)
			isis_area_add_circuit(area, circuit);
	}

	if (if_is_operative(ifp))
		isis_csm_state_change(IF_UP_FROM_Z, circuit, ifp);
}

static void isis_circuit_disable(struct isis_circuit *circuit)
{
	struct isis_area *area = circuit->area;
	struct interface *ifp = circuit->interface;

	if (if_is_operative(ifp))
		isis_csm_state_change(IF_DOWN_FROM_Z, circuit, ifp);

	if (area)
		isis_area_del_circuit(area, circuit);
}

struct isis_circuit *isis_circuit_new(struct interface *ifp, const char *tag)
{
	struct isis_circuit *circuit;
	int i;

	circuit = XCALLOC(MTYPE_ISIS_CIRCUIT, sizeof(struct isis_circuit));

	circuit->tag = XSTRDUP(MTYPE_ISIS_CIRCUIT, tag);

	/*
	 * Default values
	 */
#ifndef FABRICD
	circuit->is_type_config = yang_get_default_enum(
		"/frr-interface:lib/interface/frr-isisd:isis/circuit-type");
	circuit->flags = 0;

	circuit->pad_hellos = yang_get_default_enum(
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
	circuit->is_type_config = IS_LEVEL_1_AND_2;
	circuit->flags = 0;
	circuit->pad_hellos = ISIS_HELLO_PADDING_ALWAYS;
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

	circuit->is_type = circuit->is_type_config;

	circuit_mt_init(circuit);
	isis_lfa_excluded_ifaces_init(circuit, ISIS_LEVEL1);
	isis_lfa_excluded_ifaces_init(circuit, ISIS_LEVEL2);

	circuit->ldp_sync_info = ldp_sync_info_create();
	circuit->ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

	QOBJ_REG(circuit, isis_circuit);

	isis_circuit_if_bind(circuit, ifp);

	circuit->ip_addrs = list_new();
	circuit->ipv6_link = list_new();
	circuit->ipv6_non_link = list_new();

	if (ifp->ifindex != IFINDEX_INTERNAL)
		isis_circuit_enable(circuit);

	return circuit;
}

void isis_circuit_del(struct isis_circuit *circuit)
{
	if (!circuit)
		return;

	if (circuit->interface->ifindex != IFINDEX_INTERNAL)
		isis_circuit_disable(circuit);

	isis_circuit_if_unbind(circuit, circuit->interface);

	QOBJ_UNREG(circuit);

	ldp_sync_info_free(&circuit->ldp_sync_info);

	circuit_mt_finish(circuit);
	isis_lfa_excluded_ifaces_delete(circuit, ISIS_LEVEL1);
	isis_lfa_excluded_ifaces_delete(circuit, ISIS_LEVEL2);

	list_delete(&circuit->ip_addrs);
	list_delete(&circuit->ipv6_link);
	list_delete(&circuit->ipv6_non_link);

	if (circuit->ext) {
		isis_del_ext_subtlvs(circuit->ext);
		circuit->ext = NULL;
	}

	XFREE(MTYPE_TMP, circuit->bfd_config.profile);
	XFREE(MTYPE_ISIS_CIRCUIT, circuit->tag);

	/* and lastly the circuit itself */
	XFREE(MTYPE_ISIS_CIRCUIT, circuit);

	return;
}

void isis_circuit_configure(struct isis_circuit *circuit,
			    struct isis_area *area)
{
	assert(area);
	circuit->isis = area->isis;
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

	hook_call(isis_circuit_new_hook, circuit);

	return;
}

void isis_circuit_deconfigure(struct isis_circuit *circuit,
			      struct isis_area *area)
{
	hook_call(isis_circuit_del_hook, circuit);

	/* Free the index of SRM and SSN flags */
	flags_free_index(&area->flags, circuit->idx);
	circuit->idx = 0;

	/* Reset IS type to configured */
	circuit->is_type = circuit->is_type_config;

	/* Remove circuit from area */
	assert(circuit->area == area);
	listnode_delete(area->circuit_list, circuit);
	circuit->area = NULL;
	circuit->isis = NULL;

	return;
}

struct isis_circuit *circuit_scan_by_ifp(struct interface *ifp)
{
	return (struct isis_circuit *)ifp->info;
}

DEFINE_HOOK(isis_circuit_add_addr_hook, (struct isis_circuit *circuit),
	    (circuit));

void isis_circuit_add_addr(struct isis_circuit *circuit,
			   struct connected *connected)
{
	struct listnode *node;
	struct prefix_ipv4 *ipv4;
	struct prefix_ipv6 *ipv6;

	if (connected->address->family == AF_INET) {
		uint32_t addr = connected->address->u.prefix4.s_addr;
		addr = ntohl(addr);
		if (IPV4_NET0(addr) || IPV4_NET127(addr) || IN_CLASSD(addr))
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
		if (circuit->ext && circuit->area
		    && IS_MPLS_TE(circuit->area->mta)) {
			circuit->ext->local_addr.s_addr = ipv4->prefix.s_addr;
			SET_SUBTLV(circuit->ext, EXT_LOCAL_ADDR);
		}

		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);

#ifdef EXTREME_DEBUG
		if (IS_DEBUG_EVENTS)
			zlog_debug("Added IP address %pFX to circuit %s",
				   connected->address,
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
		else {
			listnode_add(circuit->ipv6_non_link, ipv6);
			/* Update Local IPv6 address param. if MPLS TE is on */
			if (circuit->ext && circuit->area
			    && IS_MPLS_TE(circuit->area->mta)) {
				IPV6_ADDR_COPY(&circuit->ext->local_addr6,
					       &ipv6->prefix);
				SET_SUBTLV(circuit->ext, EXT_LOCAL_ADDR6);
			}
		}
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);

#ifdef EXTREME_DEBUG
		if (IS_DEBUG_EVENTS)
			zlog_debug("Added IPv6 address %pFX to circuit %s",
				   connected->address,
				   circuit->interface->name);
#endif /* EXTREME_DEBUG */
	}

	hook_call(isis_circuit_add_addr_hook, circuit);

	return;
}

void isis_circuit_del_addr(struct isis_circuit *circuit,
			   struct connected *connected)
{
	struct prefix_ipv4 *ipv4, *ip = NULL;
	struct listnode *node;
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
			zlog_warn(
				"Nonexistent ip address %pFX removal attempt from circuit %s",
				connected->address, circuit->interface->name);
			zlog_warn("Current ip addresses on %s:",
				  circuit->interface->name);
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node,
						  ip)) {
				zlog_warn("  %pFX", ip);
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
			zlog_warn(
				"Nonexistent ip address %pFX removal attempt from circuit %s",
				connected->address, circuit->interface->name);
			zlog_warn("Current ip addresses on %s:",
				  circuit->interface->name);
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip6))
				zlog_warn("  %pFX", (struct prefix *)ip6);
			zlog_warn(" -----");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip6))
				zlog_warn("  %pFX", (struct prefix *)ip6);
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
	struct connected *conn;

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
		if (IS_DEBUG_EVENTS)
			zlog_debug("%s: unsupported media", __func__);
		circuit->circ_type = CIRCUIT_T_UNKNOWN;
	}

	frr_each (if_connected, ifp->connected, conn)
		isis_circuit_add_addr(circuit, conn);
}

void isis_circuit_if_del(struct isis_circuit *circuit, struct interface *ifp)
{
	struct connected *conn;

	assert(circuit->interface == ifp);

	/* destroy addresses */
	frr_each_safe (if_connected, ifp->connected, conn)
		isis_circuit_del_addr(circuit, conn);

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

static bool isis_circuit_lfa_enabled(struct isis_circuit *circuit, int level)
{
	return (circuit->lfa_protection[level - 1] ||
		circuit->rlfa_protection[level - 1] ||
		circuit->tilfa_protection[level - 1]);
}

void isis_circuit_switchover_routes(struct isis_circuit *circuit, int family,
				    union g_addr *nexthop_ip, ifindex_t ifindex)
{
	char is_type;

	if (!circuit->area)
		return;

	is_type = circuit->area->is_type;
	if ((is_type == IS_LEVEL_1 || is_type == IS_LEVEL_1_AND_2) &&
	    isis_circuit_lfa_enabled(circuit, IS_LEVEL_1))
		isis_area_switchover_routes(circuit->area, family, nexthop_ip,
					    ifindex, IS_LEVEL_1);
	if ((is_type == IS_LEVEL_2 || is_type == IS_LEVEL_1_AND_2) &&
	    isis_circuit_lfa_enabled(circuit, IS_LEVEL_2))
		isis_area_switchover_routes(circuit->area, family, nexthop_ip,
					    ifindex, IS_LEVEL_2);
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
	event_add_read(master, isis_receive, circuit, circuit->fd,
		       &circuit->t_read);
#else
	event_add_timer_msec(master, isis_receive, circuit,
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

	if (circuit->is_passive) {
		circuit->last_uptime = time(NULL);
		/* make sure the union fields are initialized, else we
		 * could end with garbage values from a previous circuit
		 * type, which would then cause a segfault when building
		 * LSPs or computing the SPF tree
		 */
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			circuit->u.bc.adjdb[0] = list_new();
			circuit->u.bc.adjdb[1] = list_new();
		} else if (circuit->circ_type == CIRCUIT_T_P2P) {
			circuit->u.p2p.neighbor = NULL;
		}
		return ISIS_OK;
	}

	if (circuit->area->lsp_mtu > isis_circuit_pdu_size(circuit)) {
		flog_err(
			EC_ISIS_CONFIG,
			"Interface MTU %zu on %s is too low to support area lsp mtu %u!",
			isis_circuit_pdu_size(circuit),
			circuit->interface->name, circuit->area->lsp_mtu);

		/* Allow ISIS to continue configuration.   With this
		 * configuration failure ISIS will attempt to send lsp
		 * packets but will fail until the mtu is configured properly
		 */
	}

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		circuit->circuit_id =
			isis_circuit_id_gen(circuit->isis, circuit->interface);
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
		if (IS_DEBUG_EVENTS)
			zlog_debug("%s: if_id %d, isomtu %d snpa %pSY",
				   __func__, circuit->interface->ifindex,
				   ISO_MTU(circuit), circuit->u.bc.snpa);
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

			event_add_timer(master, isis_run_dr,
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
		event_add_timer(
			master, send_l1_psnp, circuit,
			isis_jitter(circuit->psnp_interval[0], PSNP_JITTER),
			&circuit->t_send_psnp[0]);

	if (circuit->is_type & IS_LEVEL_2)
		event_add_timer(
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

	circuit->last_uptime = time(NULL);

	if (circuit->area->mta && circuit->area->mta->status)
		isis_link_params_update(circuit, circuit->interface);

	isis_if_ldp_sync_enable(circuit);

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

	isis_if_ldp_sync_disable(circuit);

	/* log adjacency changes if configured to do so */
	if (circuit->area->log_adj_changes) {
		struct isis_adjacency *adj = NULL;
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			adj = circuit->u.p2p.neighbor;
			if (adj)
				isis_log_adj_change(
					adj, adj->adj_state, ISIS_ADJ_DOWN,
					"circuit is being brought down");
		} else if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			struct list *adj_list;
			struct listnode *node;
			if (circuit->u.bc.adjdb[0]) {
				adj_list = list_new();
				isis_adj_build_up_list(circuit->u.bc.adjdb[0],
						       adj_list);
				for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj))
					isis_log_adj_change(
						adj, adj->adj_state,
						ISIS_ADJ_DOWN,
						"circuit is being brought down");
				list_delete(&adj_list);
			}
			if (circuit->u.bc.adjdb[1]) {
				adj_list = list_new();
				isis_adj_build_up_list(circuit->u.bc.adjdb[1],
						       adj_list);
				for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj))
					isis_log_adj_change(
						adj, adj->adj_state,
						ISIS_ADJ_DOWN,
						"circuit is being brought down");
				list_delete(&adj_list);
			}
		}
	}

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

		EVENT_OFF(circuit->u.bc.t_send_lan_hello[0]);
		EVENT_OFF(circuit->u.bc.t_send_lan_hello[1]);
		EVENT_OFF(circuit->u.bc.t_run_dr[0]);
		EVENT_OFF(circuit->u.bc.t_run_dr[1]);
		EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[0]);
		EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[1]);
		circuit->lsp_regenerate_pending[0] = 0;
		circuit->lsp_regenerate_pending[1] = 0;

		_ISIS_CLEAR_FLAG(circuit->isis->circuit_ids_used,
				 circuit->circuit_id);
		circuit->circuit_id = 0;
	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		isis_delete_adj(circuit->u.p2p.neighbor);
		circuit->u.p2p.neighbor = NULL;
		EVENT_OFF(circuit->u.p2p.t_send_p2p_hello);
	}

	/*
	 * All adjacencies have to be gone, delete snmp list
	 * and reset snmpd idx generator
	 */
	if (circuit->snmp_adj_list != NULL)
		list_delete(&circuit->snmp_adj_list);

	circuit->snmp_adj_idx_gen = 0;

	/* Cancel all active threads */
	EVENT_OFF(circuit->t_send_csnp[0]);
	EVENT_OFF(circuit->t_send_csnp[1]);
	EVENT_OFF(circuit->t_send_psnp[0]);
	EVENT_OFF(circuit->t_send_psnp[1]);
	EVENT_OFF(circuit->t_read);

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

	event_cancel_event(master, circuit);

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

void isis_circuit_print_json(struct isis_circuit *circuit,
			     struct json_object *json, char detail)
{
	int level;
	json_object *iface_json, *ipv4_addr_json, *ipv6_link_json,
		*ipv6_non_link_json, *hold_json, *lan_prio_json, *levels_json,
		*level_json;
	char buf_prx[INET6_BUFSIZ];
	char buf[255];

	snprintfrr(buf, sizeof(buf), "0x%x", circuit->circuit_id);
	if (detail == ISIS_UI_LEVEL_BRIEF) {
		iface_json = json_object_new_object();
		json_object_object_add(json, "interface", iface_json);
		json_object_string_add(iface_json, "name",
				       circuit->interface->name);
		json_object_string_add(iface_json, "circuit-id", buf);
		json_object_string_add(iface_json, "state",
				       circuit_state2string(circuit->state));
		json_object_string_add(iface_json, "type",
				       circuit_type2string(circuit->circ_type));
		json_object_string_add(iface_json, "level",
				       circuit_t2string(circuit->is_type));
	}

	if (detail == ISIS_UI_LEVEL_DETAIL) {
		struct listnode *node;
		struct prefix *ip_addr;

		iface_json = json_object_new_object();
		json_object_object_add(json, "interface", iface_json);
		json_object_string_add(iface_json, "name",
				       circuit->interface->name);
		json_object_string_add(iface_json, "state",
				       circuit_state2string(circuit->state));
		if (circuit->is_passive)
			json_object_string_add(iface_json, "is-passive",
					       "passive");
		else
			json_object_string_add(iface_json, "is-passive",
					       "active");
		json_object_string_add(iface_json, "circuit-id", buf);
		json_object_string_add(iface_json, "type",
				       circuit_type2string(circuit->circ_type));
		json_object_string_add(iface_json, "level",
				       circuit_t2string(circuit->is_type));
		if (circuit->circ_type == CIRCUIT_T_BROADCAST)
			json_object_string_addf(iface_json, "snpa", "%pSY",
						circuit->u.bc.snpa);


		levels_json = json_object_new_array();
		json_object_object_add(iface_json, "levels", levels_json);
		for (level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((circuit->is_type & level) == 0)
				continue;
			level_json = json_object_new_object();
			json_object_string_add(level_json, "level",
					       circuit_t2string(level));
			if (circuit->area->newmetric)
				json_object_int_add(level_json, "metric",
						    circuit->te_metric[0]);
			else
				json_object_int_add(level_json, "metric",
						    circuit->metric[0]);
			if (!circuit->is_passive) {
				json_object_int_add(level_json,
						    "active-neighbors",
						    circuit->upadjcount[0]);
				json_object_int_add(level_json,
						    "hello-interval",
						    circuit->hello_interval[0]);
				hold_json = json_object_new_object();
				json_object_object_add(level_json, "holddown",
						       hold_json);
				json_object_int_add(
					hold_json, "count",
					circuit->hello_multiplier[0]);
				json_object_string_add(
					hold_json, "pad",
					isis_hello_padding2string(
						circuit->pad_hellos));
				json_object_int_add(level_json, "cnsp-interval",
						    circuit->csnp_interval[0]);
				json_object_int_add(level_json, "psnp-interval",
						    circuit->psnp_interval[0]);
				if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
					lan_prio_json =
						json_object_new_object();
					json_object_object_add(level_json,
							       "lan",
							       lan_prio_json);
					json_object_int_add(
						lan_prio_json, "priority",
						circuit->priority[0]);
					json_object_string_add(
						lan_prio_json, "is-dis",
						(circuit->u.bc.is_dr[0]
							 ? "yes"
							 : "no"));
				}
			}
			json_object_array_add(levels_json, level_json);
		}

		if (listcount(circuit->ip_addrs) > 0) {
			ipv4_addr_json = json_object_new_object();
			json_object_object_add(iface_json, "ip-prefix",
					       ipv4_addr_json);
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node,
						  ip_addr)) {
				snprintfrr(buf_prx, INET6_BUFSIZ, "%pFX",
					   ip_addr);
				json_object_string_add(ipv4_addr_json, "ip",
						       buf_prx);
			}
		}
		if (listcount(circuit->ipv6_link) > 0) {
			ipv6_link_json = json_object_new_object();
			json_object_object_add(iface_json, "ipv6-link-locals",
					       ipv6_link_json);
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip_addr)) {
				snprintfrr(buf_prx, INET6_BUFSIZ, "%pFX",
					   ip_addr);
				json_object_string_add(ipv6_link_json, "ipv6",
						       buf_prx);
			}
		}
		if (listcount(circuit->ipv6_non_link) > 0) {
			ipv6_non_link_json = json_object_new_object();
			json_object_object_add(iface_json, "ipv6-prefixes",
					       ipv6_non_link_json);
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip_addr)) {
				snprintfrr(buf_prx, INET6_BUFSIZ, "%pFX",
					   ip_addr);
				json_object_string_add(ipv6_non_link_json,
						       "ipv6", buf_prx);
			}
		}
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
			vty_out(vty, ", SNPA: %-10pSY", circuit->u.bc.snpa);
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
					"      Hello interval: %u, Holddown count: %u, Padding: %s\n",
					circuit->hello_interval[0],
					circuit->hello_multiplier[0],
					isis_hello_padding2string(
						circuit->pad_hellos));
				vty_out(vty,
					"      CNSP interval: %u, PSNP interval: %u\n",
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
					"      Hello interval: %u, Holddown count: %u, Padding: %s\n",
					circuit->hello_interval[1],
					circuit->hello_multiplier[1],
					isis_hello_padding2string(
						circuit->pad_hellos));
				vty_out(vty,
					"      CNSP interval: %u, PSNP interval: %u\n",
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
		if (listcount(circuit->ip_addrs) > 0) {
			vty_out(vty, "    IP Prefix(es):\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node,
						  ip_addr))
				vty_out(vty, "      %pFX\n", ip_addr);
		}
		if (listcount(circuit->ipv6_link) > 0) {
			vty_out(vty, "    IPv6 Link-Locals:\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node,
						  ip_addr))
				vty_out(vty, "      %pFX\n", ip_addr);
		}
		if (listcount(circuit->ipv6_non_link) > 0) {
			vty_out(vty, "    IPv6 Prefixes:\n");
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node,
						  ip_addr))
				vty_out(vty, "      %pFX\n", ip_addr);
		}

		vty_out(vty, "\n");
	}
	return;
}

#ifdef FABRICD
DEFINE_HOOK(isis_circuit_config_write,
	    (struct isis_circuit *circuit, struct vty *vty),
	    (circuit, vty));

static int isis_interface_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	int write = 0;
	struct interface *ifp;
	struct isis_circuit *circuit;
	int i;

	FOR_ALL_INTERFACES (vrf, ifp) {
		/* IF name */
		if_vty_config_start(vty, ifp);
		write++;
		/* IF desc */
		if (ifp->desc) {
			vty_out(vty, " description %s\n", ifp->desc);
			write++;
		}
		/* ISIS Circuit */
		do {
			circuit = circuit_scan_by_ifp(ifp);
			if (circuit == NULL)
				break;
			if (circuit->ip_router) {
				vty_out(vty, " ip router " PROTO_NAME " %s\n",
					circuit->tag);
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
					circuit->tag);
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

			/* ISIS - Hello padding - Defaults to always so only
			 * display if not always */
			switch (circuit->pad_hellos) {
			case ISIS_HELLO_PADDING_DISABLED:
				vty_out(vty, " no " PROTO_NAME " hello padding\n");
				write++;
				break;
			case ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION:
				vty_out(vty, PROTO_NAME
					" hello padding during-adjacency-formation\n");
				write++;
				break;
			case ISIS_HELLO_PADDING_ALWAYS:
				break;
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
			if (circuit->bfd_config.enabled) {
				vty_out(vty, " " PROTO_NAME " bfd\n");
				write++;
			}
			write += hook_call(isis_circuit_config_write,
					   circuit, vty);
		} while (0);
		if_vty_config_end(vty);
	}

	return write;
}
#endif /* ifdef FABRICD */

void isis_circuit_af_set(struct isis_circuit *circuit, bool ip_router,
			 bool ipv6_router)
{
	struct isis_area *area = circuit->area;
	int old_ipr = circuit->ip_router;
	int old_ipv6r = circuit->ipv6_router;

	/* is there something to do? */
	if (old_ipr == ip_router && old_ipv6r == ipv6_router)
		return;

	circuit->ip_router = ip_router;
	circuit->ipv6_router = ipv6_router;
	circuit_update_nlpids(circuit);

	if (area) {
		area->ip_circuits += ip_router - old_ipr;
		area->ipv6_circuits += ipv6_router - old_ipv6r;

		if (ip_router || ipv6_router)
			lsp_regenerate_schedule(area, circuit->is_type, 0);
	}
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

	/* Don't modify metric if advertise high metrics is configured */
	if (circuit->area && circuit->area->advertise_high_metrics)
		return ferr_ok();

	/* inform ldp-sync of metric change
         *   if ldp-sync is running need to save metric
         *   and restore new values after ldp-sync completion.
	 */
	if (isis_ldp_sync_if_metric_config(circuit, level, metric)) {
		circuit->te_metric[level - 1] = metric;
		circuit->metric[level - 1] = metric;
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, level, 0);
	}
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
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area,
						IS_LEVEL_1 | IS_LEVEL_2, 0);
	}

	return CMD_SUCCESS;
}

int isis_if_new_hook(struct interface *ifp)
{
	return 0;
}

int isis_if_delete_hook(struct interface *ifp)
{
	if (ifp->info)
		isis_circuit_del(ifp->info);

	return 0;
}

static int isis_ifp_create(struct interface *ifp)
{
	struct isis_circuit *circuit = ifp->info;

	if (circuit)
		isis_circuit_enable(circuit);

	hook_call(isis_if_new_hook, ifp);

	return 0;
}

static int isis_ifp_up(struct interface *ifp)
{
	struct isis_circuit *circuit = ifp->info;

	if (circuit) {
		UNSET_FLAG(circuit->flags, ISIS_CIRCUIT_IF_DOWN_FROM_Z);
		isis_csm_state_change(IF_UP_FROM_Z, circuit, ifp);
	}

	/* Notify SRv6 that the interface went up */
	isis_srv6_ifp_up_notify(ifp);

	return 0;
}

static int isis_ifp_down(struct interface *ifp)
{
	afi_t afi;
	struct isis_circuit *circuit = ifp->info;

	if (circuit &&
	    !CHECK_FLAG(circuit->flags, ISIS_CIRCUIT_IF_DOWN_FROM_Z)) {
		SET_FLAG(circuit->flags, ISIS_CIRCUIT_IF_DOWN_FROM_Z);
		for (afi = AFI_IP; afi <= AFI_IP6; afi++)
			isis_circuit_switchover_routes(
				circuit, afi == AFI_IP ? AF_INET : AF_INET6,
				NULL, ifp->ifindex);
		isis_csm_state_change(IF_DOWN_FROM_Z, circuit, ifp);

		SET_FLAG(circuit->flags, ISIS_CIRCUIT_FLAPPED_AFTER_SPF);
	}

	return 0;
}

static int isis_ifp_destroy(struct interface *ifp)
{
	struct isis_circuit *circuit = ifp->info;

	if (circuit)
		isis_circuit_disable(circuit);

	return 0;
}

void isis_circuit_init(void)
{
	/* Initialize Zebra interface data structure */
	hook_register_prio(if_add, 0, isis_if_new_hook);
	hook_register_prio(if_del, 0, isis_if_delete_hook);

	/* Install interface node */
#ifdef FABRICD
	if_cmd_init(isis_interface_config_write);
#else
	if_cmd_init_default();
#endif
	hook_register_prio(if_real, 0, isis_ifp_create);
	hook_register_prio(if_up, 0, isis_ifp_up);
	hook_register_prio(if_down, 0, isis_ifp_down);
	hook_register_prio(if_unreal, 0, isis_ifp_destroy);
}
