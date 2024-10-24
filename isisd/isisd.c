// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isisd.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "time.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"
#include "qobj.h"
#include "zclient.h"
#include "vrf.h"
#include "spf_backoff.h"
#include "flex_algo.h"
#include "lib/northbound_cli.h"
#include "bfd.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_events.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_flex_algo.h"
#include "isisd/fabricd.h"
#include "isisd/isis_nb.h"

/* For debug statement. */
unsigned long debug_adj_pkt;
unsigned long debug_snp_pkt;
unsigned long debug_update_pkt;
unsigned long debug_spf_events;
unsigned long debug_rte_events;
unsigned long debug_events;
unsigned long debug_pkt_dump;
unsigned long debug_lsp_gen;
unsigned long debug_lsp_sched;
unsigned long debug_flooding;
unsigned long debug_bfd;
unsigned long debug_tx_queue;
unsigned long debug_sr;
unsigned long debug_ldp_sync;
unsigned long debug_lfa;
unsigned long debug_te;

DEFINE_MGROUP(ISISD, "isisd");

DEFINE_MTYPE_STATIC(ISISD, ISIS,      "ISIS process");
DEFINE_MTYPE_STATIC(ISISD, ISIS_NAME, "ISIS process name");
DEFINE_MTYPE_STATIC(ISISD, ISIS_AREA, "ISIS area");
DEFINE_MTYPE(ISISD, ISIS_AREA_ADDR,   "ISIS area address");
DEFINE_MTYPE(ISISD, ISIS_ACL_NAME,    "ISIS access-list name");
DEFINE_MTYPE(ISISD, ISIS_PLIST_NAME, "ISIS prefix-list name");

DEFINE_QOBJ_TYPE(isis_area);

/* ISIS process wide configuration. */
static struct isis_master isis_master;

/* ISIS process wide configuration pointer to export. */
struct isis_master *im;

/* ISIS config processing thread */
struct event *t_isis_cfg;

#ifndef FABRICD
DEFINE_HOOK(isis_hook_db_overload, (const struct isis_area *area), (area));
#endif /* ifndef FABRICD */

/*
 * Prototypes.
 */
int isis_area_get(struct vty *, const char *);
int area_net_title(struct vty *, const char *);
int area_clear_net_title(struct vty *, const char *);
int show_isis_interface_common(struct vty *, struct json_object *json,
			       const char *ifname, char, const char *vrf_name,
			       bool all_vrf);
int show_isis_interface_common_vty(struct vty *, const char *ifname, char,
				   const char *vrf_name, bool all_vrf);
int show_isis_interface_common_json(struct json_object *json,
				    const char *ifname, char,
				    const char *vrf_name, bool all_vrf);
int show_isis_neighbor_common(struct vty *, struct json_object *json,
			      const char *id, char, const char *vrf_name,
			      bool all_vrf);
int clear_isis_neighbor_common(struct vty *, const char *id,
			       const char *vrf_name, bool all_vrf);

/* Link ISIS instance to VRF. */
void isis_vrf_link(struct isis *isis, struct vrf *vrf)
{
	isis->vrf_id = vrf->vrf_id;
	if (vrf->info != (void *)isis)
		vrf->info = (void *)isis;
}

/* Unlink ISIS instance to VRF. */
void isis_vrf_unlink(struct isis *isis, struct vrf *vrf)
{
	if (vrf->info == (void *)isis)
		vrf->info = NULL;
	isis->vrf_id = VRF_UNKNOWN;
}

struct isis *isis_lookup_by_vrfid(vrf_id_t vrf_id)
{
	struct isis *isis;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
		if (isis->vrf_id == vrf_id)
			return isis;

	return NULL;
}

struct isis *isis_lookup_by_vrfname(const char *vrfname)
{
	struct isis *isis;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
		if (isis->name && vrfname && strcmp(isis->name, vrfname) == 0)
			return isis;

	return NULL;
}

struct isis *isis_lookup_by_sysid(const uint8_t *sysid)
{
	struct isis *isis;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
		if (!memcmp(isis->sysid, sysid, ISIS_SYS_ID_LEN))
			return isis;

	return NULL;
}

void isis_master_init(struct event_loop *master)
{
	memset(&isis_master, 0, sizeof(isis_master));
	im = &isis_master;
	im->isis = list_new();
	im->master = master;
}

void isis_master_terminate(void)
{
	list_delete(&im->isis);
}

struct isis *isis_new(const char *vrf_name)
{
	struct vrf *vrf;
	struct isis *isis;

	isis = XCALLOC(MTYPE_ISIS, sizeof(struct isis));

	isis->name = XSTRDUP(MTYPE_ISIS_NAME, vrf_name);

	vrf = vrf_lookup_by_name(vrf_name);

	if (vrf)
		isis_vrf_link(isis, vrf);
	else
		isis->vrf_id = VRF_UNKNOWN;

	isis_zebra_vrf_register(isis);

	if (IS_DEBUG_EVENTS)
		zlog_debug(
			"%s: Create new isis instance with vrf_name %s vrf_id %u",
			__func__, isis->name, isis->vrf_id);

	/*
	 * Default values
	 */
	isis->max_area_addrs = ISIS_DEFAULT_MAX_AREA_ADDRESSES;
	isis->process_id = getpid();
	isis->router_id = 0;
	isis->area_list = list_new();
	isis->uptime = time(NULL);
	isis->snmp_notifications = 1;
	dyn_cache_init(isis);

	listnode_add(im->isis, isis);

	return isis;
}

void isis_finish(struct isis *isis)
{
	struct isis_area *area;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(isis->area_list, node, nnode, area))
		isis_area_destroy(area);

	struct vrf *vrf = NULL;

	listnode_delete(im->isis, isis);

	isis_zebra_vrf_deregister(isis);

	vrf = vrf_lookup_by_name(isis->name);
	if (vrf)
		isis_vrf_unlink(isis, vrf);
	XFREE(MTYPE_ISIS_NAME, isis->name);

	isis_redist_free(isis);
	list_delete(&isis->area_list);
	dyn_cache_finish(isis);
	XFREE(MTYPE_ISIS, isis);
}

void isis_area_add_circuit(struct isis_area *area, struct isis_circuit *circuit)
{
	isis_csm_state_change(ISIS_ENABLE, circuit, area);

	area->ip_circuits += circuit->ip_router;
	area->ipv6_circuits += circuit->ipv6_router;

	area->lfa_protected_links[0] += circuit->lfa_protection[0];
	area->rlfa_protected_links[0] += circuit->rlfa_protection[0];
	area->tilfa_protected_links[0] += circuit->tilfa_protection[0];

	area->lfa_protected_links[1] += circuit->lfa_protection[1];
	area->rlfa_protected_links[1] += circuit->rlfa_protection[1];
	area->tilfa_protected_links[1] += circuit->tilfa_protection[1];
}

void isis_area_del_circuit(struct isis_area *area, struct isis_circuit *circuit)
{
	area->ip_circuits -= circuit->ip_router;
	area->ipv6_circuits -= circuit->ipv6_router;

	area->lfa_protected_links[0] -= circuit->lfa_protection[0];
	area->rlfa_protected_links[0] -= circuit->rlfa_protection[0];
	area->tilfa_protected_links[0] -= circuit->tilfa_protection[0];

	area->lfa_protected_links[1] -= circuit->lfa_protection[1];
	area->rlfa_protected_links[1] -= circuit->rlfa_protection[1];
	area->tilfa_protected_links[1] -= circuit->tilfa_protection[1];

	isis_csm_state_change(ISIS_DISABLE, circuit, area);
}

void isis_area_address_delete(void *arg)
{
	struct iso_address *addr = (struct iso_address *)arg;

	XFREE(MTYPE_ISIS_AREA_ADDR, addr);
}

struct isis_area *isis_area_create(const char *area_tag, const char *vrf_name)
{
	struct isis_area *area;
	struct isis *isis = NULL;
	struct vrf *vrf = NULL;
	struct interface *ifp;
	struct isis_circuit *circuit;

	area = XCALLOC(MTYPE_ISIS_AREA, sizeof(struct isis_area));

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_name(vrf_name);
	isis = isis_lookup_by_vrfname(vrf_name);

	if (isis == NULL)
		isis = isis_new(vrf_name);

	listnode_add(isis->area_list, area);
	area->isis = isis;

	/*
	 * Fabricd runs only as level-2.
	 * For IS-IS, the default is level-1-2
	 */
	if (fabricd)
		area->is_type = IS_LEVEL_2;
	else
		area->is_type = yang_get_default_enum(
			"/frr-isisd:isis/instance/is-type");

	/*
	 * intialize the databases
	 */
	if (area->is_type & IS_LEVEL_1)
		lsp_db_init(&area->lspdb[0]);
	if (area->is_type & IS_LEVEL_2)
		lsp_db_init(&area->lspdb[1]);

#ifndef FABRICD
	/* Flex-Algo */
	area->flex_algos = flex_algos_alloc(isis_flex_algo_data_alloc,
					    isis_flex_algo_data_free);
#endif /* ifndef FABRICD */

	spftree_area_init(area);

	area->circuit_list = list_new();
	area->adjacency_list = list_new();
	area->area_addrs = list_new();
	area->area_addrs->del = isis_area_address_delete;

	if (!CHECK_FLAG(im->options, F_ISIS_UNIT_TEST))
		event_add_timer(master, lsp_tick, area, 1, &area->t_tick);
	flags_initialize(&area->flags);

	isis_sr_area_init(area);
	isis_srv6_area_init(area);

	/*
	 * Default values
	 */
#ifndef FABRICD
	enum isis_metric_style default_style;

	area->max_lsp_lifetime[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-1/maximum-lifetime");
	area->max_lsp_lifetime[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-2/maximum-lifetime");
	area->lsp_refresh[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-1/refresh-interval");
	area->lsp_refresh[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-2/refresh-interval");
	area->lsp_gen_interval[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-1/generation-interval");
	area->lsp_gen_interval[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/timers/level-2/generation-interval");
	area->min_spf_interval[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/spf/minimum-interval/level-1");
	area->min_spf_interval[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/spf/minimum-interval/level-1");
	area->dynhostname = yang_get_default_bool(
		"/frr-isisd:isis/instance/dynamic-hostname");
	default_style =
		yang_get_default_enum("/frr-isisd:isis/instance/metric-style");
	area->oldmetric = default_style == ISIS_WIDE_METRIC ? 0 : 1;
	area->newmetric = default_style == ISIS_NARROW_METRIC ? 0 : 1;
	area->lsp_frag_threshold = 90; /* not currently configurable */
	area->lsp_mtu =
		yang_get_default_uint16("/frr-isisd:isis/instance/lsp/mtu");
	area->lfa_load_sharing[0] = yang_get_default_bool(
		"/frr-isisd:isis/instance/fast-reroute/level-1/lfa/load-sharing");
	area->lfa_load_sharing[1] = yang_get_default_bool(
		"/frr-isisd:isis/instance/fast-reroute/level-2/lfa/load-sharing");
	area->attached_bit_send =
		yang_get_default_bool("/frr-isisd:isis/instance/attach-send");
	area->attached_bit_rcv_ignore = yang_get_default_bool(
		"/frr-isisd:isis/instance/attach-receive-ignore");

#else
	area->max_lsp_lifetime[0] = DEFAULT_LSP_LIFETIME;    /* 1200 */
	area->max_lsp_lifetime[1] = DEFAULT_LSP_LIFETIME;    /* 1200 */
	area->lsp_refresh[0] = DEFAULT_MAX_LSP_GEN_INTERVAL; /* 900 */
	area->lsp_refresh[1] = DEFAULT_MAX_LSP_GEN_INTERVAL; /* 900 */
	area->lsp_gen_interval[0] = DEFAULT_MIN_LSP_GEN_INTERVAL;
	area->lsp_gen_interval[1] = DEFAULT_MIN_LSP_GEN_INTERVAL;
	area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
	area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;
	area->dynhostname = 1;
	area->oldmetric = 0;
	area->newmetric = 1;
	area->lsp_frag_threshold = 90;
	area->lsp_mtu = DEFAULT_LSP_MTU;
	area->lfa_load_sharing[0] = true;
	area->lfa_load_sharing[1] = true;
	area->attached_bit_send = true;
	area->attached_bit_rcv_ignore = false;
#endif /* ifndef FABRICD */
	area->lfa_priority_limit[0] = SPF_PREFIX_PRIO_LOW;
	area->lfa_priority_limit[1] = SPF_PREFIX_PRIO_LOW;
	isis_lfa_tiebreakers_init(area, ISIS_LEVEL1);
	isis_lfa_tiebreakers_init(area, ISIS_LEVEL2);

	area_mt_init(area);

	area->area_tag = strdup(area_tag);

	if (fabricd)
		area->fabricd = fabricd_new(area);

	area->lsp_refresh_arg[0].area = area;
	area->lsp_refresh_arg[0].level = IS_LEVEL_1;
	area->lsp_refresh_arg[1].area = area;
	area->lsp_refresh_arg[1].level = IS_LEVEL_2;

	area->bfd_signalled_down = false;
	area->bfd_force_spf_refresh = false;

	QOBJ_REG(area, isis_area);

	if (vrf) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->ifindex == IFINDEX_INTERNAL)
				continue;

			circuit = ifp->info;
			if (circuit && strmatch(circuit->tag, area->area_tag))
				isis_area_add_circuit(area, circuit);
		}
	}

	return area;
}

struct isis_area *isis_area_lookup_by_vrf(const char *area_tag,
					  const char *vrf_name)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis *isis = NULL;

	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if (strcmp(area->area_tag, area_tag) == 0)
			return area;

	return NULL;
}

struct isis_area *isis_area_lookup(const char *area_tag, vrf_id_t vrf_id)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis *isis;

	isis = isis_lookup_by_vrfid(vrf_id);
	if (isis == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if ((area->area_tag == NULL && area_tag == NULL)
		    || (area->area_tag && area_tag
			&& strcmp(area->area_tag, area_tag) == 0))
			return area;

	return NULL;
}

struct isis_area *isis_area_lookup_by_sysid(const uint8_t *sysid)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis *isis;
	struct iso_address *addr = NULL;

	isis = isis_lookup_by_sysid(sysid);
	if (isis == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		if (listcount(area->area_addrs) > 0) {
			addr = listgetdata(listhead(area->area_addrs));
			if (!memcmp(addr->area_addr + addr->addr_len, sysid,
				    ISIS_SYS_ID_LEN))
				return area;
			}
		}

	return NULL;
}

int isis_area_get(struct vty *vty, const char *area_tag)
{
	struct isis_area *area;

	area = isis_area_lookup(area_tag, VRF_DEFAULT);

	if (area) {
		VTY_PUSH_CONTEXT(ROUTER_NODE, area);
		return CMD_SUCCESS;
	}

	area = isis_area_create(area_tag, VRF_DEFAULT_NAME);

	if (IS_DEBUG_EVENTS)
		zlog_debug("New IS-IS area instance %s", area->area_tag);

	VTY_PUSH_CONTEXT(ROUTER_NODE, area);

	return CMD_SUCCESS;
}

void isis_area_destroy(struct isis_area *area)
{
	struct listnode *node, *nnode;
	struct isis_circuit *circuit;
	struct iso_address *addr;

	QOBJ_UNREG(area);

	if (fabricd)
		fabricd_finish(area->fabricd);

	if (area->circuit_list) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit))
			isis_area_del_circuit(area, circuit);

		list_delete(&area->circuit_list);
	}
	if (area->flags.free_idcs)
		list_delete(&area->flags.free_idcs);

	list_delete(&area->adjacency_list);

	lsp_db_fini(&area->lspdb[0]);
	lsp_db_fini(&area->lspdb[1]);

	/* invalidate and verify to delete all routes from zebra */
	isis_area_invalidate_routes(area, area->is_type);
	isis_area_verify_routes(area);

#ifndef FABRICD
	flex_algos_free(area->flex_algos);
#endif /* ifndef FABRICD */

	isis_sr_area_term(area);
	isis_srv6_area_term(area);

	isis_mpls_te_term(area);

	spftree_area_del(area);

	if (area->spf_timer[0])
		isis_spf_timer_free(EVENT_ARG(area->spf_timer[0]));
	EVENT_OFF(area->spf_timer[0]);
	if (area->spf_timer[1])
		isis_spf_timer_free(EVENT_ARG(area->spf_timer[1]));
	EVENT_OFF(area->spf_timer[1]);

	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);

	if (!CHECK_FLAG(im->options, F_ISIS_UNIT_TEST))
		isis_redist_area_finish(area);

	if (listcount(area->area_addrs) > 0) {
		addr = listgetdata(listhead(area->area_addrs));
		if (!memcmp(addr->area_addr + addr->addr_len, area->isis->sysid,
			    ISIS_SYS_ID_LEN)) {
			memset(area->isis->sysid, 0, ISIS_SYS_ID_LEN);
			area->isis->sysid_set = 0;
		}
	}

	list_delete(&area->area_addrs);

	for (int i = SPF_PREFIX_PRIO_CRITICAL; i <= SPF_PREFIX_PRIO_MEDIUM;
	     i++) {
		struct spf_prefix_priority_acl *ppa;

		ppa = &area->spf_prefix_priorities[i];
		XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	}
	isis_lfa_tiebreakers_clear(area, ISIS_LEVEL1);
	isis_lfa_tiebreakers_clear(area, ISIS_LEVEL2);

	EVENT_OFF(area->t_tick);
	EVENT_OFF(area->t_lsp_refresh[0]);
	EVENT_OFF(area->t_lsp_refresh[1]);
	EVENT_OFF(area->t_rlfa_rib_update);

	event_cancel_event(master, area);

	listnode_delete(area->isis->area_list, area);

	free(area->area_tag);

	area_mt_finish(area);

	if (area->rlfa_plist_name[0])
		XFREE(MTYPE_ISIS_PLIST_NAME, area->rlfa_plist_name[0]);
	if (area->rlfa_plist_name[1])
		XFREE(MTYPE_ISIS_PLIST_NAME, area->rlfa_plist_name[1]);

	XFREE(MTYPE_ISIS_AREA, area);

}

/* This is hook function for vrf create called as part of vrf_init */
static int isis_vrf_new(struct vrf *vrf)
{
	if (IS_DEBUG_EVENTS)
		zlog_debug("%s: VRF Created: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

/* This is hook function for vrf delete call as part of vrf_init */
static int isis_vrf_delete(struct vrf *vrf)
{
	if (IS_DEBUG_EVENTS)
		zlog_debug("%s: VRF Deletion: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static void isis_set_redist_vrf_bitmaps(struct isis *isis, bool set)
{
	struct listnode *node, *lnode;
	struct isis_area *area;
	int type;
	int level;
	int protocol;
	struct isis_redist *redist;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
			for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++)
				for (level = 0; level < ISIS_LEVELS; level++) {
					if (area->redist_settings[protocol][type]
								 [level] == NULL)
						continue;
					for (ALL_LIST_ELEMENTS_RO(area->redist_settings
									  [protocol]
									  [type]
									  [level],
								  lnode,
								  redist)) {
						if (redist->redist == 0)
							continue;
						/* This field is actually
						 * controlling transmission of
						 * the IS-IS
						 * routes to Zebra and has
						 * nothing to do with
						 * redistribution,
						 * so skip it. */
						afi_t afi =
							afi_for_redist_protocol(
								protocol);

						if (type == DEFAULT_ROUTE) {
							if (set)
								vrf_bitmap_set(
									&zclient->default_information
										 [afi],
									isis->vrf_id);
							else
								vrf_bitmap_unset(
									&zclient->default_information
										 [afi],
									isis->vrf_id);
						} else {
							if (set)
								vrf_bitmap_set(
									&zclient->redist
										 [afi]
										 [type],
									isis->vrf_id);
							else
								vrf_bitmap_unset(
									&zclient->redist
										 [afi]
										 [type],
									isis->vrf_id);
						}
					}
				}
}

static int isis_vrf_enable(struct vrf *vrf)
{
	struct isis *isis;
	vrf_id_t old_vrf_id;

	if (IS_DEBUG_EVENTS)
		zlog_debug("%s: VRF %s id %u enabled", __func__, vrf->name,
			   vrf->vrf_id);

	isis = isis_lookup_by_vrfname(vrf->name);
	if (isis && isis->vrf_id != vrf->vrf_id) {
		old_vrf_id = isis->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		isis_vrf_link(isis, vrf);
		if (IS_DEBUG_EVENTS)
			zlog_debug(
				"%s: isis linked to vrf %s vrf_id %u (old id %u)",
				__func__, vrf->name, isis->vrf_id, old_vrf_id);
		/* start zebra redist to us for new vrf */
		isis_set_redist_vrf_bitmaps(isis, true);

		isis_zebra_vrf_register(isis);
	}

	return 0;
}

static int isis_vrf_disable(struct vrf *vrf)
{
	struct isis *isis;
	vrf_id_t old_vrf_id = VRF_UNKNOWN;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (IS_DEBUG_EVENTS)
		zlog_debug("%s: VRF %s id %d disabled.", __func__, vrf->name,
			   vrf->vrf_id);
	isis = isis_lookup_by_vrfname(vrf->name);
	if (isis) {
		old_vrf_id = isis->vrf_id;

		isis_zebra_vrf_deregister(isis);

		isis_set_redist_vrf_bitmaps(isis, false);

		/* We have instance configured, unlink
		 * from VRF and make it "down".
		 */
		isis_vrf_unlink(isis, vrf);
		if (IS_DEBUG_EVENTS)
			zlog_debug("%s: isis old_vrf_id %d unlinked", __func__,
				   old_vrf_id);
	}

	return 0;
}

void isis_vrf_init(void)
{
	vrf_init(isis_vrf_new, isis_vrf_enable, isis_vrf_disable,
		 isis_vrf_delete);

	vrf_cmd_init(NULL);
}

void isis_terminate(void)
{
	struct isis *isis;
	struct listnode *node, *nnode;

	bfd_protocol_integration_set_shutdown(true);

	if (listcount(im->isis) == 0)
		return;

	for (ALL_LIST_ELEMENTS(im->isis, node, nnode, isis))
		isis_finish(isis);
}

void isis_filter_update(struct access_list *access)
{
	struct isis *isis;
	struct isis_area *area;
	struct listnode *node, *anode;

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
			for (int i = SPF_PREFIX_PRIO_CRITICAL;
			     i <= SPF_PREFIX_PRIO_MEDIUM; i++) {
				struct spf_prefix_priority_acl *ppa;

				ppa = &area->spf_prefix_priorities[i];
				ppa->list_v4 =
					access_list_lookup(AFI_IP, ppa->name);
				ppa->list_v6 =
					access_list_lookup(AFI_IP6, ppa->name);
			}
			lsp_regenerate_schedule(area, area->is_type, 0);
		}
	}
}

void isis_prefix_list_update(struct prefix_list *plist)
{
	struct isis *isis;
	struct isis_area *area;
	struct listnode *node, *anode;

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++) {
				const char *plist_name =
					prefix_list_name(plist);

				if (!area->rlfa_plist_name[level - 1])
					continue;

				if (!strmatch(area->rlfa_plist_name[level - 1],
					      plist_name))
					continue;

				area->rlfa_plist[level - 1] =
					prefix_list_lookup(AFI_IP, plist_name);
				lsp_regenerate_schedule(area, area->is_type, 0);
			}
		}
	}
}

#ifdef FABRICD
static void area_set_mt_enabled(struct isis_area *area, uint16_t mtid,
				bool enabled)
{
	struct isis_area_mt_setting *setting;

	setting = area_get_mt_setting(area, mtid);
	if (setting->enabled != enabled) {
		setting->enabled = enabled;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);
	}
}

static void area_set_mt_overload(struct isis_area *area, uint16_t mtid,
				 bool overload)
{
	struct isis_area_mt_setting *setting;

	setting = area_get_mt_setting(area, mtid);
	if (setting->overload != overload) {
		setting->overload = overload;
		if (setting->enabled)
			lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2,
						0);
	}
}
#endif /* ifdef FABRICD */

int area_net_title(struct vty *vty, const char *net_title)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	struct iso_address *addr;
	struct iso_address *addrp;
	struct listnode *node;

	uint8_t buff[255];

	/* We check that we are not over the maximal number of addresses */
	if (listcount(area->area_addrs) >= area->isis->max_area_addrs) {
		vty_out(vty,
			"Maximum of area addresses (%d) already reached \n",
			area->isis->max_area_addrs);
		return CMD_ERR_NOTHING_TODO;
	}

	addr = XMALLOC(MTYPE_ISIS_AREA_ADDR, sizeof(struct iso_address));
	addr->addr_len = dotformat2buff(buff, net_title);
	memcpy(addr->area_addr, buff, addr->addr_len);
#ifdef EXTREME_DEBUG
	zlog_debug("added area address %s for area %s (address length %d)",
		   net_title, area->area_tag, addr->addr_len);
#endif /* EXTREME_DEBUG */
	if (addr->addr_len < ISO_ADDR_MIN || addr->addr_len > ISO_ADDR_SIZE) {
		vty_out(vty,
			"area address must be at least 8..20 octets long (%d)\n",
			addr->addr_len);
		XFREE(MTYPE_ISIS_AREA_ADDR, addr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (addr->area_addr[addr->addr_len - 1] != 0) {
		vty_out(vty,
			"nsel byte (last byte) in area address must be 0\n");
		XFREE(MTYPE_ISIS_AREA_ADDR, addr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (area->isis->sysid_set == 0) {
		/*
		 * First area address - get the SystemID for this router
		 */
		memcpy(area->isis->sysid, GETSYSID(addr), ISIS_SYS_ID_LEN);
		area->isis->sysid_set = 1;
		if (IS_DEBUG_EVENTS)
			zlog_debug("Router has SystemID %pSY",
				   area->isis->sysid);
	} else {
		/*
		 * Check that the SystemID portions match
		 */
		if (memcmp(area->isis->sysid, GETSYSID(addr),
			   ISIS_SYS_ID_LEN)) {
			vty_out(vty,
				"System ID must not change when defining additional area addresses\n");
			XFREE(MTYPE_ISIS_AREA_ADDR, addr);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* now we see that we don't already have this address */
		for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node, addrp)) {
			if ((addrp->addr_len + ISIS_SYS_ID_LEN + ISIS_NSEL_LEN)
			    != (addr->addr_len))
				continue;
			if (!memcmp(addrp->area_addr, addr->area_addr,
				    addr->addr_len)) {
				XFREE(MTYPE_ISIS_AREA_ADDR, addr);
				return CMD_SUCCESS; /* silent fail */
			}
		}
	}

	/*
	 * Forget the systemID part of the address
	 */
	addr->addr_len -= (ISIS_SYS_ID_LEN + ISIS_NSEL_LEN);
	listnode_add(area->area_addrs, addr);

	/* only now we can safely generate our LSPs for this area */
	if (listcount(area->area_addrs) > 0) {
		if (area->is_type & IS_LEVEL_1)
			lsp_generate(area, IS_LEVEL_1);
		if (area->is_type & IS_LEVEL_2)
			lsp_generate(area, IS_LEVEL_2);
	}

	return CMD_SUCCESS;
}

int area_clear_net_title(struct vty *vty, const char *net_title)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	struct iso_address addr, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];

	addr.addr_len = dotformat2buff(buff, net_title);
	if (addr.addr_len < ISO_ADDR_MIN || addr.addr_len > ISO_ADDR_SIZE) {
		vty_out(vty,
			"Unsupported area address length %d, should be 8...20 \n",
			addr.addr_len);
		return CMD_WARNING_CONFIG_FAILED;
	}

	memcpy(addr.area_addr, buff, (int)addr.addr_len);

	for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node, addrp))
		if ((addrp->addr_len + ISIS_SYS_ID_LEN + 1) == addr.addr_len
		    && !memcmp(addrp->area_addr, addr.area_addr, addr.addr_len))
			break;

	if (!addrp) {
		vty_out(vty, "No area address %s for area %s \n", net_title,
			area->area_tag);
		return CMD_ERR_NO_MATCH;
	}

	listnode_delete(area->area_addrs, addrp);
	XFREE(MTYPE_ISIS_AREA_ADDR, addrp);

	/*
	 * Last area address - reset the SystemID for this router
	 */
	if (listcount(area->area_addrs) == 0) {
		memset(area->isis->sysid, 0, ISIS_SYS_ID_LEN);
		area->isis->sysid_set = 0;
		if (IS_DEBUG_EVENTS)
			zlog_debug("Router has no SystemID");
	}

	return CMD_SUCCESS;
}

/*
 * 'show isis interface' command
 */
int show_isis_interface_common(struct vty *vty, struct json_object *json,
			       const char *ifname, char detail,
			       const char *vrf_name, bool all_vrf)
{
	if (json) {
		return show_isis_interface_common_json(json, ifname, detail,
						       vrf_name, all_vrf);
	} else {
		return show_isis_interface_common_vty(vty, ifname, detail,
						      vrf_name, all_vrf);
	}
}

int show_isis_interface_common_json(struct json_object *json,
				    const char *ifname, char detail,
				    const char *vrf_name, bool all_vrf)
{
	struct listnode *anode, *cnode, *inode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct isis *isis;
	struct json_object *areas_json, *area_json;
	struct json_object *circuits_json, *circuit_json;
	if (!im) {
		// IS-IS Routing Process not enabled
		json_object_string_add(json, "is-is-routing-process-enabled",
				       "no");
		return CMD_SUCCESS;
	}

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
			areas_json = json_object_new_array();
			json_object_object_add(json, "areas", areas_json);
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
				area_json = json_object_new_object();
				json_object_string_add(area_json, "area",
						       area->area_tag
							       ? area->area_tag
							       : "null");
				circuits_json = json_object_new_array();
				json_object_object_add(area_json, "circuits",
						       circuits_json);
				for (ALL_LIST_ELEMENTS_RO(area->circuit_list,
							  cnode, circuit)) {
					circuit_json = json_object_new_object();
					json_object_int_add(
						circuit_json, "circuit",
						circuit->circuit_id);
					if (!ifname)
						isis_circuit_print_json(circuit,
									circuit_json,
									detail);
					else if (strcmp(circuit->interface->name,
							ifname) == 0)
						isis_circuit_print_json(circuit,
									circuit_json,
									detail);
					json_object_array_add(circuits_json,
							      circuit_json);
				}
				json_object_array_add(areas_json, area_json);
			}
		}
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		areas_json = json_object_new_array();
		json_object_object_add(json, "areas", areas_json);
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
			area_json = json_object_new_object();
			json_object_string_add(area_json, "area",
					       area->area_tag ? area->area_tag
							      : "null");

			circuits_json = json_object_new_array();
			json_object_object_add(area_json, "circuits",
					       circuits_json);
			for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode,
						  circuit)) {
				circuit_json = json_object_new_object();
				json_object_int_add(circuit_json, "circuit",
						    circuit->circuit_id);
				if (!ifname)
					isis_circuit_print_json(circuit,
								circuit_json,
								detail);
				else if (strcmp(circuit->interface->name,
						ifname) == 0)
					isis_circuit_print_json(circuit,
								circuit_json,
								detail);
				json_object_array_add(circuits_json,
						      circuit_json);
			}
			json_object_array_add(areas_json, area_json);
		}
	}

	return CMD_SUCCESS;
}

int show_isis_interface_common_vty(struct vty *vty, const char *ifname,
				   char detail, const char *vrf_name,
				   bool all_vrf)
{
	struct listnode *anode, *cnode, *inode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct isis *isis;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
				vty_out(vty, "Area %s:\n", area->area_tag);

				if (detail == ISIS_UI_LEVEL_BRIEF)
					vty_out(vty,
						"  Interface   CircId   State    Type     Level\n");

				for (ALL_LIST_ELEMENTS_RO(area->circuit_list,
							  cnode, circuit))
					if (!ifname)
						isis_circuit_print_vty(circuit,
								       vty,
								       detail);
					else if (strcmp(circuit->interface->name,
							ifname) == 0)
						isis_circuit_print_vty(circuit,
								       vty,
								       detail);
			}
		}
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
			vty_out(vty, "Area %s:\n", area->area_tag);

			if (detail == ISIS_UI_LEVEL_BRIEF)
				vty_out(vty,
					"  Interface   CircId   State    Type     Level\n");

			for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode,
						  circuit))
				if (!ifname)
					isis_circuit_print_vty(circuit, vty,
							       detail);
				else if (strcmp(circuit->interface->name,
						ifname) == 0)
					isis_circuit_print_vty(circuit, vty,
							       detail);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_isis_interface,
      show_isis_interface_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] interface [json]",
      SHOW_STR
      PROTO_HELP 
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "json output\n"
      "IS-IS interface\n")
{
	int res = CMD_SUCCESS;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();
	res = show_isis_interface_common(vty, json, NULL, ISIS_UI_LEVEL_BRIEF,
					 vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

DEFUN(show_isis_interface_detail,
      show_isis_interface_detail_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] interface detail [json]",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "IS-IS interface\n"
      "show detailed information\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();
	res = show_isis_interface_common(vty, json, NULL, ISIS_UI_LEVEL_DETAIL,
					 vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

DEFUN(show_isis_interface_arg,
      show_isis_interface_arg_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] interface WORD [json]",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "IS-IS interface\n"
      "IS-IS interface name\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	int idx_word = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();

	char *ifname = argv_find(argv, argc, "WORD", &idx_word)
			       ? argv[idx_word]->arg
			       : NULL;
	res = show_isis_interface_common(
		vty, json, ifname, ISIS_UI_LEVEL_DETAIL, vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

static int id_to_sysid(struct isis *isis, const char *id, uint8_t *sysid)
{
	struct isis_dynhn *dynhn;

	memset(sysid, 0, ISIS_SYS_ID_LEN);
	if (id) {
		if (sysid2buff(sysid, id) == 0) {
			dynhn = dynhn_find_by_name(isis, id);
			if (dynhn == NULL)
				return -1;
			memcpy(sysid, dynhn->id, ISIS_SYS_ID_LEN);
		}
	}

	return 0;
}

static void isis_neighbor_common_json(struct json_object *json, const char *id,
				      char detail, struct isis *isis,
				      uint8_t *sysid)
{
	struct listnode *anode, *cnode, *node;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;
	struct json_object *areas_json, *area_json;
	struct json_object *circuits_json, *circuit_json;
	int i;

	areas_json = json_object_new_array();
	json_object_object_add(json, "areas", areas_json);
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		area_json = json_object_new_object();
		json_object_string_add(area_json, "area",
				       area->area_tag ? area->area_tag
						      : "null");
		circuits_json = json_object_new_array();
		json_object_object_add(area_json, "circuits", circuits_json);
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			circuit_json = json_object_new_object();
			json_object_int_add(circuit_json, "circuit",
					    circuit->circuit_id);
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS_RO(
							     adjdb, node, adj))
							if (!id ||
							    !memcmp(adj->sysid,
								    sysid,
								    ISIS_SYS_ID_LEN))
								isis_adj_print_json(
									adj,
									circuit_json,
									detail);
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P &&
				   circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id ||
				    !memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN))
					isis_adj_print_json(adj, circuit_json,
							    detail);
			}
			json_object_array_add(circuits_json, circuit_json);
		}
		json_object_array_add(areas_json, area_json);
	}
}

static void isis_neighbor_common_vty(struct vty *vty, const char *id,
				     char detail, struct isis *isis,
				     uint8_t *sysid)
{
	struct listnode *anode, *cnode, *node;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;
	int i;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		vty_out(vty, "Area %s:\n", area->area_tag);

		if (detail == ISIS_UI_LEVEL_BRIEF)
			vty_out(vty,
				" System Id           Interface   L  State         Holdtime SNPA\n");

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS_RO(
							     adjdb, node, adj))
							if (!id ||
							    !memcmp(adj->sysid,
								    sysid,
								    ISIS_SYS_ID_LEN))
								isis_adj_print_vty(
									adj,
									vty,
									detail);
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P &&
				   circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id ||
				    !memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN))
					isis_adj_print_vty(adj, vty, detail);
			}
		}
	}
}

static void isis_neighbor_common(struct vty *vty, struct json_object *json,
				 const char *id, char detail, struct isis *isis,
				 uint8_t *sysid)
{
	if (json) {
		isis_neighbor_common_json(json, id, detail,isis,sysid);
	} else {
		isis_neighbor_common_vty(vty, id, detail,isis,sysid);
	}
}

/*
 * 'show isis neighbor' command
 */

int show_isis_neighbor_common(struct vty *vty, struct json_object *json,
			      const char *id, char detail, const char *vrf_name,
			      bool all_vrf)
{
	struct listnode *node;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	struct isis *isis;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			if (id_to_sysid(isis, id, sysid)) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			isis_neighbor_common(vty, json, id, detail, isis, sysid);
		}
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		if (id_to_sysid(isis, id, sysid)) {
			vty_out(vty, "Invalid system id %s\n", id);
			return CMD_SUCCESS;
		}
		isis_neighbor_common(vty, json, id, detail, isis, sysid);
	}

	return CMD_SUCCESS;
}

static void isis_neighbor_common_clear(struct vty *vty, const char *id,
				       uint8_t *sysid, struct isis *isis)
{
	struct listnode *anode, *cnode, *node, *nnode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;
	int i;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS(
							     adjdb, node, nnode,
							     adj))
							if (!id
							    || !memcmp(
								    adj->sysid,
								    sysid,
								    ISIS_SYS_ID_LEN))
								isis_adj_state_change(
									&adj,
									ISIS_ADJ_DOWN,
									"clear user request");
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id
				    || !memcmp(adj->sysid, sysid,
					       ISIS_SYS_ID_LEN))
					isis_adj_state_change(
						&adj, ISIS_ADJ_DOWN,
						"clear user request");
			}
		}
	}
}
/*
 * 'clear isis neighbor' command
 */
int clear_isis_neighbor_common(struct vty *vty, const char *id, const char *vrf_name,
			       bool all_vrf)
{
	struct listnode *node;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	struct isis *isis;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			if (id_to_sysid(isis, id, sysid)) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			isis_neighbor_common_clear(vty, id, sysid, isis);
		}
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		if (id_to_sysid(isis, id, sysid)) {
			vty_out(vty, "Invalid system id %s\n", id);
			return CMD_SUCCESS;
		}
		isis_neighbor_common_clear(vty, id, sysid, isis);
	}

	return CMD_SUCCESS;
}

DEFUN(show_isis_neighbor,
      show_isis_neighbor_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] neighbor [json]",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All vrfs\n"
      "IS-IS neighbor adjacencies\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();
	res = show_isis_neighbor_common(vty, json, NULL, ISIS_UI_LEVEL_BRIEF,
					vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

DEFUN(show_isis_neighbor_detail,
      show_isis_neighbor_detail_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] neighbor detail [json]",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "all vrfs\n"
      "IS-IS neighbor adjacencies\n"
      "show detailed information\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();

	res = show_isis_neighbor_common(vty, json, NULL, ISIS_UI_LEVEL_DETAIL,
					vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

DEFUN(show_isis_neighbor_arg,
      show_isis_neighbor_arg_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] neighbor WORD [json]",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All vrfs\n"
      "IS-IS neighbor adjacencies\n"
      "System id\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	int idx_word = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();
	char *id = argv_find(argv, argc, "WORD", &idx_word)
			   ? argv[idx_word]->arg
			   : NULL;

	res = show_isis_neighbor_common(vty, json, id, ISIS_UI_LEVEL_DETAIL,
					vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

DEFUN(clear_isis_neighbor,
      clear_isis_neighbor_cmd,
      "clear " PROTO_NAME " [vrf <NAME|all>] neighbor",
      CLEAR_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All vrfs\n"
      "IS-IS neighbor adjacencies\n")
{
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	return clear_isis_neighbor_common(vty, NULL, vrf_name, all_vrf);
}

DEFUN(clear_isis_neighbor_arg,
      clear_isis_neighbor_arg_cmd,
      "clear " PROTO_NAME " [vrf <NAME|all>] neighbor WORD",
      CLEAR_STR
      PROTO_HELP
      VRF_CMD_HELP_STR
      "All vrfs\n"
      "IS-IS neighbor adjacencies\n"
      "System id\n")
{
	int idx_word = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;

	char *id = argv_find(argv, argc, "WORD", &idx_word)
			   ? argv[idx_word]->arg
			   : NULL;
	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	return clear_isis_neighbor_common(vty, id, vrf_name, all_vrf);
}

/*
 * 'isis debug', 'show debugging'
 */
void print_debug(struct vty *vty, int flags, int onoff)
{
	const char *onoffs = onoff ? "on" : "off";

	if (flags & DEBUG_ADJ_PACKETS)
		vty_out(vty,
			"IS-IS Adjacency related packets debugging is %s\n",
			onoffs);
	if (flags & DEBUG_TX_QUEUE)
		vty_out(vty, "IS-IS TX queue debugging is %s\n",
			onoffs);
	if (flags & DEBUG_SNP_PACKETS)
		vty_out(vty, "IS-IS CSNP/PSNP packets debugging is %s\n",
			onoffs);
	if (flags & DEBUG_SPF_EVENTS)
		vty_out(vty, "IS-IS SPF events debugging is %s\n", onoffs);
	if (flags & DEBUG_SR)
		vty_out(vty, "IS-IS Segment Routing events debugging is %s\n",
			onoffs);
	if (flags & DEBUG_TE)
		vty_out(vty,
			"IS-IS Traffic Engineering events debugging is %s\n",
			onoffs);
	if (flags & DEBUG_LFA)
		vty_out(vty, "IS-IS LFA events debugging is %s\n", onoffs);
	if (flags & DEBUG_UPDATE_PACKETS)
		vty_out(vty, "IS-IS Update related packet debugging is %s\n",
			onoffs);
	if (flags & DEBUG_RTE_EVENTS)
		vty_out(vty, "IS-IS Route related debugging is %s\n", onoffs);
	if (flags & DEBUG_EVENTS)
		vty_out(vty, "IS-IS Event debugging is %s\n", onoffs);
	if (flags & DEBUG_PACKET_DUMP)
		vty_out(vty, "IS-IS Packet dump debugging is %s\n", onoffs);
	if (flags & DEBUG_LSP_GEN)
		vty_out(vty, "IS-IS LSP generation debugging is %s\n", onoffs);
	if (flags & DEBUG_LSP_SCHED)
		vty_out(vty, "IS-IS LSP scheduling debugging is %s\n", onoffs);
	if (flags & DEBUG_FLOODING)
		vty_out(vty, "IS-IS Flooding debugging is %s\n", onoffs);
	if (flags & DEBUG_BFD)
		vty_out(vty, "IS-IS BFD debugging is %s\n", onoffs);
	if (flags & DEBUG_LDP_SYNC)
		vty_out(vty, "IS-IS ldp-sync debugging is %s\n", onoffs);
}

DEFUN_NOSH (show_debugging,
	    show_debugging_isis_cmd,
	    "show debugging [" PROTO_NAME "]",
	    SHOW_STR
	    "State of each debugging option\n"
	    PROTO_HELP)
{
	vty_out(vty, PROTO_NAME " debugging status:\n");

	if (IS_DEBUG_ADJ_PACKETS)
		print_debug(vty, DEBUG_ADJ_PACKETS, 1);
	if (IS_DEBUG_TX_QUEUE)
		print_debug(vty, DEBUG_TX_QUEUE, 1);
	if (IS_DEBUG_SNP_PACKETS)
		print_debug(vty, DEBUG_SNP_PACKETS, 1);
	if (IS_DEBUG_SPF_EVENTS)
		print_debug(vty, DEBUG_SPF_EVENTS, 1);
	if (IS_DEBUG_SR)
		print_debug(vty, DEBUG_SR, 1);
	if (IS_DEBUG_TE)
		print_debug(vty, DEBUG_TE, 1);
	if (IS_DEBUG_UPDATE_PACKETS)
		print_debug(vty, DEBUG_UPDATE_PACKETS, 1);
	if (IS_DEBUG_RTE_EVENTS)
		print_debug(vty, DEBUG_RTE_EVENTS, 1);
	if (IS_DEBUG_EVENTS)
		print_debug(vty, DEBUG_EVENTS, 1);
	if (IS_DEBUG_PACKET_DUMP)
		print_debug(vty, DEBUG_PACKET_DUMP, 1);
	if (IS_DEBUG_LSP_GEN)
		print_debug(vty, DEBUG_LSP_GEN, 1);
	if (IS_DEBUG_LSP_SCHED)
		print_debug(vty, DEBUG_LSP_SCHED, 1);
	if (IS_DEBUG_FLOODING)
		print_debug(vty, DEBUG_FLOODING, 1);
	if (IS_DEBUG_BFD)
		print_debug(vty, DEBUG_BFD, 1);
	if (IS_DEBUG_LDP_SYNC)
		print_debug(vty, DEBUG_LDP_SYNC, 1);
	if (IS_DEBUG_LFA)
		print_debug(vty, DEBUG_LFA, 1);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

static int config_write_debug(struct vty *vty);
/* Debug node. */
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};

static int config_write_debug(struct vty *vty)
{
	int write = 0;

	if (IS_DEBUG_ADJ_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " adj-packets\n");
		write++;
	}
	if (IS_DEBUG_TX_QUEUE) {
		vty_out(vty, "debug " PROTO_NAME " tx-queue\n");
		write++;
	}
	if (IS_DEBUG_SNP_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " snp-packets\n");
		write++;
	}
	if (IS_DEBUG_SPF_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " spf-events\n");
		write++;
	}
	if (IS_DEBUG_SR) {
		vty_out(vty, "debug " PROTO_NAME " sr-events\n");
		write++;
	}
	if (IS_DEBUG_TE) {
		vty_out(vty, "debug " PROTO_NAME " te-events\n");
		write++;
	}
	if (IS_DEBUG_LFA) {
		vty_out(vty, "debug " PROTO_NAME " lfa\n");
		write++;
	}
	if (IS_DEBUG_UPDATE_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " update-packets\n");
		write++;
	}
	if (IS_DEBUG_RTE_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " route-events\n");
		write++;
	}
	if (IS_DEBUG_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " events\n");
		write++;
	}
	if (IS_DEBUG_PACKET_DUMP) {
		vty_out(vty, "debug " PROTO_NAME " packet-dump\n");
		write++;
	}
	if (IS_DEBUG_LSP_GEN) {
		vty_out(vty, "debug " PROTO_NAME " lsp-gen\n");
		write++;
	}
	if (IS_DEBUG_LSP_SCHED) {
		vty_out(vty, "debug " PROTO_NAME " lsp-sched\n");
		write++;
	}
	if (IS_DEBUG_FLOODING) {
		vty_out(vty, "debug " PROTO_NAME " flooding\n");
		write++;
	}
	if (IS_DEBUG_BFD) {
		vty_out(vty, "debug " PROTO_NAME " bfd\n");
		write++;
	}
	if (IS_DEBUG_LDP_SYNC) {
		vty_out(vty, "debug " PROTO_NAME " ldp-sync\n");
		write++;
	}
	write += spf_backoff_write_config(vty);

	return write;
}

DEFUN (debug_isis_adj,
       debug_isis_adj_cmd,
       "debug " PROTO_NAME " adj-packets",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Adjacency related packets\n")
{
	debug_adj_pkt |= DEBUG_ADJ_PACKETS;
	print_debug(vty, DEBUG_ADJ_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_adj,
       no_debug_isis_adj_cmd,
       "no debug " PROTO_NAME " adj-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Adjacency related packets\n")
{
	debug_adj_pkt &= ~DEBUG_ADJ_PACKETS;
	print_debug(vty, DEBUG_ADJ_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_tx_queue,
       debug_isis_tx_queue_cmd,
       "debug " PROTO_NAME " tx-queue",
       DEBUG_STR
       PROTO_HELP
       "IS-IS TX queues\n")
{
	debug_tx_queue |= DEBUG_TX_QUEUE;
	print_debug(vty, DEBUG_TX_QUEUE, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_tx_queue,
       no_debug_isis_tx_queue_cmd,
       "no debug " PROTO_NAME " tx-queue",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS TX queues\n")
{
	debug_tx_queue &= ~DEBUG_TX_QUEUE;
	print_debug(vty, DEBUG_TX_QUEUE, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_flooding,
       debug_isis_flooding_cmd,
       "debug " PROTO_NAME " flooding",
       DEBUG_STR
       PROTO_HELP
       "Flooding algorithm\n")
{
	debug_flooding |= DEBUG_FLOODING;
	print_debug(vty, DEBUG_FLOODING, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_flooding,
       no_debug_isis_flooding_cmd,
       "no debug " PROTO_NAME " flooding",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "Flooding algorithm\n")
{
	debug_flooding &= ~DEBUG_FLOODING;
	print_debug(vty, DEBUG_FLOODING, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_snp,
       debug_isis_snp_cmd,
       "debug " PROTO_NAME " snp-packets",
       DEBUG_STR
       PROTO_HELP
       "IS-IS CSNP/PSNP packets\n")
{
	debug_snp_pkt |= DEBUG_SNP_PACKETS;
	print_debug(vty, DEBUG_SNP_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_snp,
       no_debug_isis_snp_cmd,
       "no debug " PROTO_NAME " snp-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS CSNP/PSNP packets\n")
{
	debug_snp_pkt &= ~DEBUG_SNP_PACKETS;
	print_debug(vty, DEBUG_SNP_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_upd,
       debug_isis_upd_cmd,
       "debug " PROTO_NAME " update-packets",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Update related packets\n")
{
	debug_update_pkt |= DEBUG_UPDATE_PACKETS;
	print_debug(vty, DEBUG_UPDATE_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_upd,
       no_debug_isis_upd_cmd,
       "no debug " PROTO_NAME " update-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Update related packets\n")
{
	debug_update_pkt &= ~DEBUG_UPDATE_PACKETS;
	print_debug(vty, DEBUG_UPDATE_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_spfevents,
       debug_isis_spfevents_cmd,
       "debug " PROTO_NAME " spf-events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Shortest Path First Events\n")
{
	debug_spf_events |= DEBUG_SPF_EVENTS;
	print_debug(vty, DEBUG_SPF_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_spfevents,
       no_debug_isis_spfevents_cmd,
       "no debug " PROTO_NAME " spf-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Shortest Path First Events\n")
{
	debug_spf_events &= ~DEBUG_SPF_EVENTS;
	print_debug(vty, DEBUG_SPF_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_srevents,
       debug_isis_srevents_cmd,
       "debug " PROTO_NAME " sr-events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Segment Routing Events\n")
{
	debug_sr |= DEBUG_SR;
	print_debug(vty, DEBUG_SR, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_srevents,
       no_debug_isis_srevents_cmd,
       "no debug " PROTO_NAME " sr-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Segment Routing Events\n")
{
	debug_sr &= ~DEBUG_SR;
	print_debug(vty, DEBUG_SR, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_teevents,
       debug_isis_teevents_cmd,
       "debug " PROTO_NAME " te-events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Traffic Engineering Events\n")
{
	debug_te |= DEBUG_TE;
	print_debug(vty, DEBUG_TE, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_teevents,
       no_debug_isis_teevents_cmd,
       "no debug " PROTO_NAME " te-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Traffic Engineering Events\n")
{
	debug_te &= ~DEBUG_TE;
	print_debug(vty, DEBUG_TE, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_lfa,
       debug_isis_lfa_cmd,
       "debug " PROTO_NAME " lfa",
       DEBUG_STR
       PROTO_HELP
       "IS-IS LFA Events\n")
{
	debug_lfa |= DEBUG_LFA;
	print_debug(vty, DEBUG_LFA, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lfa,
       no_debug_isis_lfa_cmd,
       "no debug " PROTO_NAME " lfa",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS LFA Events\n")
{
	debug_lfa &= ~DEBUG_LFA;
	print_debug(vty, DEBUG_LFA, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_rtevents,
       debug_isis_rtevents_cmd,
       "debug " PROTO_NAME " route-events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Route related events\n")
{
	debug_rte_events |= DEBUG_RTE_EVENTS;
	print_debug(vty, DEBUG_RTE_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_rtevents,
       no_debug_isis_rtevents_cmd,
       "no debug " PROTO_NAME " route-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Route related events\n")
{
	debug_rte_events &= ~DEBUG_RTE_EVENTS;
	print_debug(vty, DEBUG_RTE_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_events,
       debug_isis_events_cmd,
       "debug " PROTO_NAME " events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Events\n")
{
	debug_events |= DEBUG_EVENTS;
	print_debug(vty, DEBUG_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_events,
       no_debug_isis_events_cmd,
       "no debug " PROTO_NAME " events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS Events\n")
{
	debug_events &= ~DEBUG_EVENTS;
	print_debug(vty, DEBUG_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_packet_dump,
       debug_isis_packet_dump_cmd,
       "debug " PROTO_NAME " packet-dump",
       DEBUG_STR
       PROTO_HELP
       "IS-IS packet dump\n")
{
	debug_pkt_dump |= DEBUG_PACKET_DUMP;
	print_debug(vty, DEBUG_PACKET_DUMP, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_packet_dump,
       no_debug_isis_packet_dump_cmd,
       "no debug " PROTO_NAME " packet-dump",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS packet dump\n")
{
	debug_pkt_dump &= ~DEBUG_PACKET_DUMP;
	print_debug(vty, DEBUG_PACKET_DUMP, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_lsp_gen,
       debug_isis_lsp_gen_cmd,
       "debug " PROTO_NAME " lsp-gen",
       DEBUG_STR
       PROTO_HELP
       "IS-IS generation of own LSPs\n")
{
	debug_lsp_gen |= DEBUG_LSP_GEN;
	print_debug(vty, DEBUG_LSP_GEN, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lsp_gen,
       no_debug_isis_lsp_gen_cmd,
       "no debug " PROTO_NAME " lsp-gen",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS generation of own LSPs\n")
{
	debug_lsp_gen &= ~DEBUG_LSP_GEN;
	print_debug(vty, DEBUG_LSP_GEN, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_lsp_sched,
       debug_isis_lsp_sched_cmd,
       "debug " PROTO_NAME " lsp-sched",
       DEBUG_STR
       PROTO_HELP
       "IS-IS scheduling of LSP generation\n")
{
	debug_lsp_sched |= DEBUG_LSP_SCHED;
	print_debug(vty, DEBUG_LSP_SCHED, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lsp_sched,
       no_debug_isis_lsp_sched_cmd,
       "no debug " PROTO_NAME " lsp-sched",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "IS-IS scheduling of LSP generation\n")
{
	debug_lsp_sched &= ~DEBUG_LSP_SCHED;
	print_debug(vty, DEBUG_LSP_SCHED, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_bfd,
       debug_isis_bfd_cmd,
       "debug " PROTO_NAME " bfd",
       DEBUG_STR
       PROTO_HELP
       PROTO_NAME " interaction with BFD\n")
{
	debug_bfd |= DEBUG_BFD;
	bfd_protocol_integration_set_debug(true);
	print_debug(vty, DEBUG_BFD, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_isis_bfd,
       no_debug_isis_bfd_cmd,
       "no debug " PROTO_NAME " bfd",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       PROTO_NAME " interaction with BFD\n")
{
	debug_bfd &= ~DEBUG_BFD;
	bfd_protocol_integration_set_debug(false);
	print_debug(vty, DEBUG_BFD, 0);

	return CMD_SUCCESS;
}

DEFUN(debug_isis_ldp_sync, debug_isis_ldp_sync_cmd,
      "debug " PROTO_NAME " ldp-sync",
      DEBUG_STR PROTO_HELP PROTO_NAME " interaction with LDP-Sync\n")
{
	debug_ldp_sync |= DEBUG_LDP_SYNC;
	print_debug(vty, DEBUG_LDP_SYNC, 1);

	return CMD_SUCCESS;
}

DEFUN(no_debug_isis_ldp_sync, no_debug_isis_ldp_sync_cmd,
      "no debug " PROTO_NAME " ldp-sync",
      NO_STR UNDEBUG_STR PROTO_HELP PROTO_NAME " interaction with LDP-Sync\n")
{
	debug_ldp_sync &= ~DEBUG_LDP_SYNC;
	print_debug(vty, DEBUG_LDP_SYNC, 0);

	return CMD_SUCCESS;
}

DEFUN (show_hostname,
       show_hostname_cmd,
       "show " PROTO_NAME " [vrf <NAME|all>] hostname",
       SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
       "All VRFs\n"
       "IS-IS Dynamic hostname mapping\n")
{
	struct listnode *node;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;
	struct isis *isis;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
			dynhn_print_all(vty, isis);

		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL)
		dynhn_print_all(vty, isis);

	return CMD_SUCCESS;
}

static void isis_spf_ietf_common(struct vty *vty, struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {

		vty_out(vty, "vrf    : %s\n", isis->name);
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;

			vty_out(vty, "  Level-%d:\n", level);
			vty_out(vty, "    SPF delay status: ");
			if (area->spf_timer[level - 1]) {
				struct timeval remain = event_timer_remain(
					area->spf_timer[level - 1]);
				vty_out(vty, "Pending, due in %lld msec\n",
					(long long)remain.tv_sec * 1000
						+ remain.tv_usec / 1000);
			} else {
				vty_out(vty, "Not scheduled\n");
			}

			if (area->spf_delay_ietf[level - 1]) {
				vty_out(vty,
					"    Using draft-ietf-rtgwg-backoff-algo-04\n");
				spf_backoff_show(
					area->spf_delay_ietf[level - 1], vty,
					"    ");
			} else {
				vty_out(vty, "    Using legacy backoff algo\n");
			}
		}
	}
}

DEFUN(show_isis_spf_ietf, show_isis_spf_ietf_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] spf-delay-ietf",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      "SPF delay IETF information\n")
{
	struct listnode *node;
	struct isis *isis;
	int idx_vrf = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf)

	if (!im) {
		vty_out(vty, "ISIS is not running\n");
		return CMD_SUCCESS;
	}

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
			isis_spf_ietf_common(vty, isis);

		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL)
		isis_spf_ietf_common(vty, isis);

	return CMD_SUCCESS;
}


static const char *pdu_counter_index_to_name_json(enum pdu_counter_index index)
{
	switch (index) {
	case L1_LAN_HELLO_INDEX:
		return "l1-iih";
	case L2_LAN_HELLO_INDEX:
		return "l2-iih";
	case P2P_HELLO_INDEX:
		return "p2p-iih";
	case L1_LINK_STATE_INDEX:
		return "l1-lsp";
	case L2_LINK_STATE_INDEX:
		return "l2-lsp";
	case FS_LINK_STATE_INDEX:
		return "fs-lsp";
	case L1_COMPLETE_SEQ_NUM_INDEX:
		return "l1-csnp";
	case L2_COMPLETE_SEQ_NUM_INDEX:
		return "l2-csnp";
	case L1_PARTIAL_SEQ_NUM_INDEX:
		return "l1-psnp";
	case L2_PARTIAL_SEQ_NUM_INDEX:
		return "l2-psnp";
	case PDU_COUNTER_SIZE:
		return "???????";
	}

	assert(!"Reached end of function where we are not expecting to");
}

static void common_isis_summary_json(struct json_object *json,
				     struct isis *isis)
{
	int level;
	json_object *vrf_json, *areas_json, *area_json, *tx_pdu_json, *rx_pdu_json, *levels_json,
		*level_json;
	struct listnode *node, *node2;
	struct isis_area *area;
	time_t cur;
	char uptime[MONOTIME_STRLEN];
	char stier[5];

	vrf_json = json_object_new_object();
	json_object_string_add(vrf_json, "vrf", isis->name);
	json_object_int_add(vrf_json, "process-id", isis->process_id);
	if (isis->sysid_set)
		json_object_string_addf(vrf_json, "system-id", "%pSY", isis->sysid);

	cur = time(NULL);
	cur -= isis->uptime;
	frrtime_to_interval(cur, uptime, sizeof(uptime));
	json_object_string_add(vrf_json, "up-time", uptime);
	if (isis->area_list)
		json_object_int_add(vrf_json, "number-areas", isis->area_list->count);
	areas_json = json_object_new_array();
	json_object_object_add(vrf_json, "areas", areas_json);
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		area_json = json_object_new_object();
		json_object_string_add(area_json, "area",
				       area->area_tag ? area->area_tag
						      : "null");

		if (fabricd) {
			uint8_t tier = fabricd_tier(area);
			snprintfrr(stier, sizeof(stier), "%s", &tier);
			json_object_string_add(area_json, "tier",
					       tier == ISIS_TIER_UNDEFINED
						       ? "undefined"
						       : stier);
		}

		if (listcount(area->area_addrs) > 0) {
			struct iso_address *area_addr;
			for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node2,
						  area_addr))
				json_object_string_addf(area_json, "net",
							"%pISl", area_addr);
		}

		tx_pdu_json = json_object_new_object();
		json_object_object_add(area_json, "tx-pdu-type", tx_pdu_json);
		for (int i = 0; i < PDU_COUNTER_SIZE; i++) {
			if (!area->pdu_tx_counters[i])
				continue;
			json_object_int_add(tx_pdu_json,
					    pdu_counter_index_to_name_json(i),
					    area->pdu_tx_counters[i]);
		}
		json_object_int_add(tx_pdu_json, "lsp-rxmt",
				    area->lsp_rxmt_count);

		rx_pdu_json = json_object_new_object();
		json_object_object_add(area_json, "rx-pdu-type", rx_pdu_json);
		for (int i = 0; i < PDU_COUNTER_SIZE; i++) {
			if (!area->pdu_rx_counters[i])
				continue;
			json_object_int_add(rx_pdu_json,
					    pdu_counter_index_to_name_json(i),
					    area->pdu_rx_counters[i]);
		}

		levels_json = json_object_new_array();
		json_object_object_add(area_json, "levels", levels_json);
		for (level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;
			level_json = json_object_new_object();
			json_object_int_add(level_json, "id", level);
			json_object_int_add(level_json, "lsp0-regenerated",
					    area->lsp_gen_count[level - 1]);
			json_object_int_add(level_json, "lsp-purged",
					    area->lsp_purge_count[level - 1]);
			if (area->spf_timer[level - 1])
				json_object_string_add(level_json, "spf",
						       "pending");
			else
				json_object_string_add(level_json, "spf",
						       "no pending");
			json_object_int_add(level_json, "minimum-interval",
					    area->min_spf_interval[level - 1]);
			if (area->spf_delay_ietf[level - 1])
				json_object_string_add(
					level_json, "ietf-spf-delay-activated",
					"not used");
			if (area->ip_circuits) {
				isis_spf_print_json(
					area->spftree[SPFTREE_IPV4][level - 1],
					level_json);
			}
			if (area->ipv6_circuits) {
				isis_spf_print_json(
					area->spftree[SPFTREE_IPV6][level - 1],
					level_json);
			}
			json_object_array_add(levels_json, level_json);
		}
		json_object_array_add(areas_json, area_json);
	}
	json_object_array_add(json, vrf_json);
}

static void common_isis_summary_vty(struct vty *vty, struct isis *isis)
{
	struct listnode *node, *node2;
	struct isis_area *area;
	int level;

	vty_out(vty, "vrf             : %s\n", isis->name);
	vty_out(vty, "Process Id      : %ld\n", isis->process_id);
	if (isis->sysid_set)
		vty_out(vty, "System Id       : %pSY\n", isis->sysid);

	vty_out(vty, "Up time         : ");
	vty_out_timestr(vty, isis->uptime);
	vty_out(vty, "\n");

	if (isis->area_list)
		vty_out(vty, "Number of areas : %d\n", isis->area_list->count);

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		if (fabricd) {
			uint8_t tier = fabricd_tier(area);
			if (tier == ISIS_TIER_UNDEFINED)
				vty_out(vty, "  Tier: undefined\n");
			else
				vty_out(vty, "  Tier: %hhu\n", tier);
		}

		if (listcount(area->area_addrs) > 0) {
			struct iso_address *area_addr;
			for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node2,
						  area_addr))
				vty_out(vty, "  Net: %pISl\n", area_addr);
		}

		vty_out(vty, "  TX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_tx_counters);
		vty_out(vty, "   LSP RXMT: %" PRIu64 "\n",
			area->lsp_rxmt_count);
		vty_out(vty, "  RX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_rx_counters);

		vty_out(vty, "  Drop counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_drop_counters);

		vty_out(vty, "  Advertise high metrics: %s\n",
			area->advertise_high_metrics ? "Enabled" : "Disabled");

		for (level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;

			vty_out(vty, "  Level-%d:\n", level);

			vty_out(vty, "    LSP0 regenerated: %" PRIu64 "\n",
				area->lsp_gen_count[level - 1]);

			vty_out(vty, "         LSPs purged: %" PRIu64 "\n",
				area->lsp_purge_count[level - 1]);

			if (area->spf_timer[level - 1])
				vty_out(vty, "    SPF: (pending)\n");
			else
				vty_out(vty, "    SPF:\n");

			vty_out(vty, "      minimum interval  : %d",
				area->min_spf_interval[level - 1]);
			if (area->spf_delay_ietf[level - 1])
				vty_out(vty,
					" (not used, IETF SPF delay activated)");
			vty_out(vty, "\n");

			if (area->ip_circuits) {
				vty_out(vty, "    IPv4 route computation:\n");
				isis_spf_print(
					area->spftree[SPFTREE_IPV4][level - 1],
					vty);
			}

			if (area->ipv6_circuits) {
				vty_out(vty, "    IPv6 route computation:\n");
				isis_spf_print(
					area->spftree[SPFTREE_IPV6][level - 1],
					vty);
			}

			if (area->ipv6_circuits
			    && isis_area_ipv6_dstsrc_enabled(area)) {
				vty_out(vty,
					"    IPv6 dst-src route computation:\n");
				isis_spf_print(area->spftree[SPFTREE_DSTSRC]
							    [level - 1],
					       vty);
			}
		}
	}
}

static void common_isis_summary(struct vty *vty, struct json_object *json, const char *vrf_name,
				bool all_vrf)
{
	struct listnode *node;
	struct isis *isis;

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			if (json)
				common_isis_summary_json(json, isis);
			else
				common_isis_summary_vty(vty, isis);
		}
	} else {
		isis = isis_lookup_by_vrfname(vrf_name);
		if (isis != NULL) {
			if (json)
				common_isis_summary_json(json, isis);
			else
				common_isis_summary_vty(vty, isis);
		}
	}
}

DEFUN(show_isis_summary, show_isis_summary_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] summary [json]",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
       "json output\n"
      "summary\n")
{
	int idx_vrf = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *vrfs_json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf)
	if (!im) {
		vty_out(vty, PROTO_NAME " is not running\n");
		return CMD_SUCCESS;
	}
	if (uj) {
		json = json_object_new_object();
		vrfs_json = json_object_new_array();
		json_object_object_add(json, "vrfs", vrfs_json);
	}

	common_isis_summary(vty, vrfs_json, vrf_name, all_vrf);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

struct isis_lsp *lsp_for_sysid(struct lspdb_head *head, const char *sysid_str,
			       struct isis *isis)
{
	char sysid[255] = {0};
	uint8_t number[3] = {0};
	const char *pos;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2] = {0};
	struct isis_dynhn *dynhn;
	struct isis_lsp *lsp = NULL;

	if (!sysid_str)
		return NULL;

	/*
	 * extract fragment and pseudo id from the string sysid_str
	 * in the forms:
	 * (a) <systemid/hostname>.<pseudo-id>-<framenent> or
	 * (b) <systemid/hostname>.<pseudo-id> or
	 * (c) <systemid/hostname> or
	 * Where systemid is in the form:
	 * xxxx.xxxx.xxxx
	 */
	strlcpy(sysid, sysid_str, sizeof(sysid));

	if (strlen(sysid_str) > 3) {
		pos = sysid_str + strlen(sysid_str) - 3;
		if (strncmp(pos, "-", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[ISIS_SYS_ID_LEN + 1] =
				(uint8_t)strtol((char *)number, NULL, 16);
			pos -= 4;
			if (strncmp(pos, ".", 1) != 0)
				return NULL;
		}
		if (strncmp(pos, ".", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[ISIS_SYS_ID_LEN] =
				(uint8_t)strtol((char *)number, NULL, 16);
			sysid[pos - sysid_str - 1] = '\0';
		}
	}

	/*
	 * Try to find the lsp-id if the sysid_str
	 * is in the form
	 * hostname.<pseudo-id>-<fragment>
	 */
	if (sysid2buff(lspid, sysid)) {
		lsp = lsp_search(head, lspid);
	} else if ((dynhn = dynhn_find_by_name(isis, sysid))) {
		memcpy(lspid, dynhn->id, ISIS_SYS_ID_LEN);
		lsp = lsp_search(head, lspid);
	} else if (strncmp(cmd_hostname_get(), sysid, 15) == 0) {
		memcpy(lspid, isis->sysid, ISIS_SYS_ID_LEN);
		lsp = lsp_search(head, lspid);
	}

	return lsp;
}

void show_isis_database_lspdb_json(struct json_object *json,
				   struct isis_area *area, int level,
				   struct lspdb_head *lspdb,
				   const char *sysid_str, int ui_level)
{
	struct json_object *array_json, *lsp_json;
	struct isis_lsp *lsp;
	int lsp_count;
	struct json_object *lsp_arr_json;

	if (lspdb_count(lspdb) > 0) {
		lsp = lsp_for_sysid(lspdb, sysid_str, area->isis);

		if (lsp != NULL || sysid_str == NULL) {
			json_object_int_add(json, "id", level + 1);
		}

		if (lsp) {
			json_object_object_get_ex(json, "lsps", &array_json);
			if (!array_json) {
				array_json = json_object_new_array();
				json_object_object_add(json, "lsps", array_json);
			}
			lsp_json = json_object_new_object();
			json_object_array_add(array_json, lsp_json);

			if (ui_level == ISIS_UI_LEVEL_DETAIL)
				lsp_print_detail(lsp, NULL, lsp_json,
						 area->dynhostname, area->isis);
			else
				lsp_print_json(lsp, lsp_json, area->dynhostname,
					       area->isis);
		} else if (sysid_str == NULL) {
			lsp_arr_json = json_object_new_array();
			json_object_object_add(json, "lsps", lsp_arr_json);

			lsp_count = lsp_print_all(NULL, lsp_arr_json, lspdb,
						  ui_level, area->dynhostname,
						  area->isis);

			json_object_int_add(json, "count", lsp_count);
		}
	}
}
void show_isis_database_lspdb_vty(struct vty *vty, struct isis_area *area,
				  int level, struct lspdb_head *lspdb,
				  const char *sysid_str, int ui_level)
{
	struct isis_lsp *lsp;
	int lsp_count;

	if (lspdb_count(lspdb) > 0) {
		lsp = lsp_for_sysid(lspdb, sysid_str, area->isis);

		if (lsp != NULL || sysid_str == NULL) {
			vty_out(vty, "IS-IS Level-%d link-state database:\n",
				level + 1);

			/* print the title in all cases */
			vty_out(vty,
				"LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL\n");
		}

		if (lsp) {
			if (ui_level == ISIS_UI_LEVEL_DETAIL)
				lsp_print_detail(lsp, vty, NULL,
						 area->dynhostname, area->isis);
			else
				lsp_print_vty(lsp, vty, area->dynhostname,
					      area->isis);
		} else if (sysid_str == NULL) {
			lsp_count =
				lsp_print_all(vty, NULL, lspdb, ui_level,
					      area->dynhostname, area->isis);

			vty_out(vty, "    %u LSPs\n\n", lsp_count);
		}
	}
}

static void show_isis_database_json(struct json_object *json, const char *sysid_str,
				      int ui_level, struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;
	int level;
	struct json_object *tag_area_json,*area_json, *lsp_json, *area_arr_json, *arr_json;

	if (isis->area_list->count == 0)
		return;

	area_arr_json = json_object_new_array();
	json_object_object_add(json, "areas", area_arr_json);
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		area_json = json_object_new_object();
		tag_area_json = json_object_new_object();
		json_object_string_add(tag_area_json, "name",
				       area->area_tag ? area->area_tag
						      : "null");

		arr_json = json_object_new_array();
		json_object_object_add(area_json,"area",tag_area_json);
		json_object_object_add(area_json,"levels",arr_json);
		for (level = 0; level < ISIS_LEVELS; level++) {
			if (lspdb_count(&area->lspdb[level]) == 0)
				continue;
			lsp_json = json_object_new_object();
			show_isis_database_lspdb_json(lsp_json, area, level,
						      &area->lspdb[level],
						      sysid_str, ui_level);
			json_object_array_add(arr_json, lsp_json);
		}
		json_object_array_add(area_arr_json, area_json);
	}
}

static void show_isis_database_vty(struct vty *vty, const char *sysid_str,
				      int ui_level, struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;
	int level;

	if (isis->area_list->count == 0)
		return;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (level = 0; level < ISIS_LEVELS; level++)
			show_isis_database_lspdb_vty(vty, area, level,
						 &area->lspdb[level], sysid_str,
						 ui_level);
	}
}

static void show_isis_database_common(struct vty *vty, struct json_object *json, const char *sysid_str,
				      int ui_level, struct isis *isis)
{
	if (json) {
		show_isis_database_json(json, sysid_str, ui_level, isis);
	} else {
		show_isis_database_vty(vty, sysid_str, ui_level, isis);
	}
}

/*
 * This function supports following display options:
 * [ show isis database [detail] ]
 * [ show isis database <sysid> [detail] ]
 * [ show isis database <hostname> [detail] ]
 * [ show isis database <sysid>.<pseudo-id> [detail] ]
 * [ show isis database <hostname>.<pseudo-id> [detail] ]
 * [ show isis database <sysid>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show isis database <hostname>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show isis database detail <sysid> ]
 * [ show isis database detail <hostname> ]
 * [ show isis database detail <sysid>.<pseudo-id> ]
 * [ show isis database detail <hostname>.<pseudo-id> ]
 * [ show isis database detail <sysid>.<pseudo-id>-<fragment-number> ]
 * [ show isis database detail <hostname>.<pseudo-id>-<fragment-number> ]
 */
static int show_isis_database(struct vty *vty, struct json_object *json, const char *sysid_str,
			      int ui_level, const char *vrf_name, bool all_vrf)
{
	struct listnode *node;
	struct isis *isis;

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
			show_isis_database_common(vty, json, sysid_str,
						  ui_level, isis);

		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis)
		show_isis_database_common(vty, json, sysid_str, ui_level, isis);

	return CMD_SUCCESS;
}

DEFUN(show_database, show_database_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] database [detail] [WORD] [json]",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      "Link state database\n"
      "Detailed information\n"
      "LSP ID\n"
      "json output\n")
{
	int res = CMD_SUCCESS;
	int idx = 0;
	int idx_vrf = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int uilevel = argv_find(argv, argc, "detail", &idx)
			      ? ISIS_UI_LEVEL_DETAIL
			      : ISIS_UI_LEVEL_BRIEF;
	char *id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg : NULL;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (uj)
		json = json_object_new_object();

	res = show_isis_database(vty, json, id, uilevel, vrf_name, all_vrf);
	if (uj)
		vty_json(vty, json);
	return res;
}

#ifdef FABRICD
/*
 * 'router openfabric' command
 */
DEFUN_NOSH (router_openfabric,
       router_openfabric_cmd,
       "router openfabric WORD",
       ROUTER_STR
       PROTO_HELP
       "ISO Routing area tag\n")
{
	int idx_word = 2;
	return isis_area_get(vty, argv[idx_word]->arg);
}

/*
 *'no router openfabric' command
 */
DEFUN (no_router_openfabric,
       no_router_openfabric_cmd,
       "no router openfabric WORD",
       NO_STR
       ROUTER_STR
       PROTO_HELP
       "ISO Routing area tag\n")
{
	struct isis_area *area;
	const char *area_tag;
	int idx_word = 3;

	area_tag = argv[idx_word]->arg;
	area = isis_area_lookup(area_tag, VRF_DEFAULT);
	if (area == NULL) {
		zlog_warn("%s: could not find area with area-tag %s",
				__func__, area_tag);
		return CMD_ERR_NO_MATCH;
	}

	isis_area_destroy(area);
	return CMD_SUCCESS;
}
#endif /* ifdef FABRICD */
#ifdef FABRICD
/*
 * 'net' command
 */
DEFUN (net,
       net_cmd,
       "net WORD",
       "A Network Entity Title for this process (OSI only)\n"
       "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
	int idx_word = 1;
	return area_net_title(vty, argv[idx_word]->arg);
}

/*
 * 'no net' command
 */
DEFUN (no_net,
       no_net_cmd,
       "no net WORD",
       NO_STR
       "A Network Entity Title for this process (OSI only)\n"
       "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
	int idx_word = 2;
	return area_clear_net_title(vty, argv[idx_word]->arg);
}
#endif /* ifdef FABRICD */
#ifdef FABRICD
DEFUN (isis_topology,
       isis_topology_cmd,
       "topology " ISIS_MT_NAMES " [overload]",
       "Configure IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS
       "Set overload bit for topology\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	const char *arg = argv[1]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (mtid == ISIS_MT_IPV4_UNICAST) {
		vty_out(vty, "Cannot configure IPv4 unicast topology\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	area_set_mt_enabled(area, mtid, true);
	area_set_mt_overload(area, mtid, (argc == 3));
	return CMD_SUCCESS;
}

DEFUN (no_isis_topology,
       no_isis_topology_cmd,
       "no topology " ISIS_MT_NAMES " [overload]",
       NO_STR
       "Configure IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS
       "Set overload bit for topology\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	const char *arg = argv[2]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (mtid == ISIS_MT_IPV4_UNICAST) {
		vty_out(vty, "Cannot configure IPv4 unicast topology\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	area_set_mt_enabled(area, mtid, false);
	area_set_mt_overload(area, mtid, false);
	return CMD_SUCCESS;
}
#endif /* ifdef FABRICD */

void isis_area_lsp_mtu_set(struct isis_area *area, unsigned int lsp_mtu)
{
	area->lsp_mtu = lsp_mtu;
	lsp_regenerate_schedule(area, IS_LEVEL_1_AND_2, 1);
}

static int isis_area_passwd_set(struct isis_area *area, int level,
				uint8_t passwd_type, const char *passwd,
				uint8_t snp_auth)
{
	struct isis_passwd *dest;
	struct isis_passwd modified;
	int len;

	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));
	dest = (level == IS_LEVEL_1) ? &area->area_passwd
				     : &area->domain_passwd;
	memset(&modified, 0, sizeof(modified));

	if (passwd_type != ISIS_PASSWD_TYPE_UNUSED) {
		if (!passwd)
			return -1;

		len = strlen(passwd);
		if (len > 254)
			return -1;

		modified.len = len;
		strlcpy((char *)modified.passwd, passwd,
			sizeof(modified.passwd));
		modified.type = passwd_type;
		modified.snp_auth = snp_auth;
	}

	if (memcmp(&modified, dest, sizeof(modified))) {
		memcpy(dest, &modified, sizeof(modified));
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}

	return 0;
}

int isis_area_passwd_unset(struct isis_area *area, int level)
{
	return isis_area_passwd_set(area, level, ISIS_PASSWD_TYPE_UNUSED, NULL,
				    0);
}

int isis_area_passwd_cleartext_set(struct isis_area *area, int level,
				   const char *passwd, uint8_t snp_auth)
{
	return isis_area_passwd_set(area, level, ISIS_PASSWD_TYPE_CLEARTXT,
				    passwd, snp_auth);
}

int isis_area_passwd_hmac_md5_set(struct isis_area *area, int level,
				  const char *passwd, uint8_t snp_auth)
{
	return isis_area_passwd_set(area, level, ISIS_PASSWD_TYPE_HMAC_MD5,
				    passwd, snp_auth);
}

void isis_area_invalidate_routes(struct isis_area *area, int levels)
{
#ifndef FABRICD
	struct flex_algo *fa;
	struct listnode *node;
	struct isis_flex_algo_data *data;
#endif /* ifndef FABRICD */

	for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		if (!(level & levels))
			continue;
		for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
			isis_spf_invalidate_routes(
					area->spftree[tree][level - 1]);

#ifndef FABRICD
			for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos,
						  node, fa)) {
				data = fa->data;
				isis_spf_invalidate_routes(
					data->spftree[tree][level - 1]);
			}
#endif /* ifndef FABRICD */
		}
	}
}

void isis_area_verify_routes(struct isis_area *area)
{
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++)
		isis_spf_verify_routes(area, area->spftree[tree], tree);
}

void isis_area_switchover_routes(struct isis_area *area, int family,
				 union g_addr *nexthop_ip, ifindex_t ifindex,
				 int level)
{
	int tree;

	/* TODO SPFTREE_DSTSRC */
	if (family == AF_INET)
		tree = SPFTREE_IPV4;
	else if (family == AF_INET6)
		tree = SPFTREE_IPV6;
	else
		return;

	isis_spf_switchover_routes(area, area->spftree[tree], family,
				   nexthop_ip, ifindex, level);
}


static void area_resign_level(struct isis_area *area, int level)
{
#ifndef FABRICD
	struct flex_algo *fa;
	struct listnode *node;
	struct isis_flex_algo_data *data;
#endif /* ifndef FABRICD */

	isis_area_invalidate_routes(area, level);
	isis_area_verify_routes(area);

	lsp_db_fini(&area->lspdb[level - 1]);

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		if (area->spftree[tree][level - 1]) {
			isis_spftree_del(area->spftree[tree][level - 1]);
			area->spftree[tree][level - 1] = NULL;
		}
	}

#ifndef FABRICD
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, node,
					  fa)) {
			data = fa->data;
			if (data->spftree[tree][level - 1]) {
				isis_spftree_del(
					data->spftree[tree][level - 1]);
				data->spftree[tree][level - 1] = NULL;
			}
		}
	}
#endif /* ifndef FABRICD */

	if (area->spf_timer[level - 1])
		isis_spf_timer_free(EVENT_ARG(area->spf_timer[level - 1]));

	EVENT_OFF(area->spf_timer[level - 1]);

	sched_debug(
		"ISIS (%s): Resigned from L%d - canceling LSP regeneration timer.",
		area->area_tag, level);
	EVENT_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
}

void isis_area_is_type_set(struct isis_area *area, int is_type)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (IS_DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) system type change %s -> %s",
			   area->area_tag, circuit_t2string(area->is_type),
			   circuit_t2string(is_type));

	if (area->is_type == is_type)
		return; /* No change */

	switch (area->is_type) {
	case IS_LEVEL_1:
		if (is_type == IS_LEVEL_2)
			area_resign_level(area, IS_LEVEL_1);

		lsp_db_init(&area->lspdb[1]);
		break;

	case IS_LEVEL_1_AND_2:
		if (is_type == IS_LEVEL_1)
			area_resign_level(area, IS_LEVEL_2);
		else
			area_resign_level(area, IS_LEVEL_1);
		break;

	case IS_LEVEL_2:
		if (is_type == IS_LEVEL_1)
			area_resign_level(area, IS_LEVEL_2);

		lsp_db_init(&area->lspdb[0]);
		break;

	default:
		break;
	}

	area->is_type = is_type;

	/*
	 * If area's IS type is strict Level-1 or Level-2, override circuit's
	 * IS type. Otherwise use circuit's configured IS type.
	 */
	if (area->is_type != IS_LEVEL_1_AND_2) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			isis_circuit_is_type_set(circuit, is_type);
	} else {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			isis_circuit_is_type_set(circuit, circuit->is_type_config);
	}

	spftree_area_init(area);

	if (listcount(area->area_addrs) > 0) {
		if (is_type & IS_LEVEL_1)
			lsp_generate(area, IS_LEVEL_1);
		if (is_type & IS_LEVEL_2)
			lsp_generate(area, IS_LEVEL_2);
	}
	lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);

	return;
}

void isis_area_metricstyle_set(struct isis_area *area, bool old_metric,
			       bool new_metric)
{
	area->oldmetric = old_metric;
	area->newmetric = new_metric;
	lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
}

void isis_area_overload_bit_set(struct isis_area *area, bool overload_bit)
{
	char new_overload_bit = overload_bit ? LSPBIT_OL : 0;

	if (new_overload_bit != area->overload_bit) {
		area->overload_bit = new_overload_bit;
		if (new_overload_bit) {
			area->overload_counter++;
		} else {
			/* Cancel overload on startup timer if it's running */
			if (area->t_overload_on_startup_timer) {
				EVENT_OFF(area->t_overload_on_startup_timer);
				area->t_overload_on_startup_timer = NULL;
			}
		}

#ifndef FABRICD
		hook_call(isis_hook_db_overload, area);
#endif /* ifndef FABRICD */

		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
#ifndef FABRICD
	isis_notif_db_overload(area, overload_bit);
#endif /* ifndef FABRICD */
}

void isis_area_overload_on_startup_set(struct isis_area *area,
				       uint32_t startup_time)
{
	if (area->overload_on_startup_time != startup_time) {
		area->overload_on_startup_time = startup_time;
		isis_restart_write_overload_time(area, startup_time);
	}
}

void config_end_lsp_generate(struct isis_area *area)
{
	if (listcount(area->area_addrs) > 0) {
		if (CHECK_FLAG(area->is_type, IS_LEVEL_1))
			lsp_generate(area, IS_LEVEL_1);
		if (CHECK_FLAG(area->is_type, IS_LEVEL_2))
			lsp_generate(area, IS_LEVEL_2);
	}
}

void isis_area_advertise_high_metrics_set(struct isis_area *area,
					  bool advertise_high_metrics)
{
	struct listnode *node;
	struct isis_circuit *circuit;
	int max_metric;
	char xpath[XPATH_MAXLEN];
	struct lyd_node *dnode;
	int configured_metric_l1;
	int configured_metric_l2;

	if (area->advertise_high_metrics == advertise_high_metrics)
		return;

	if (advertise_high_metrics) {
		if (area->oldmetric && area->newmetric)
			max_metric = ISIS_NARROW_METRIC_INFINITY;
		else if (area->newmetric)
			max_metric = MAX_WIDE_LINK_METRIC;
		else
			max_metric = MAX_NARROW_LINK_METRIC;

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
			isis_circuit_metric_set(circuit, IS_LEVEL_1,
						max_metric);
			isis_circuit_metric_set(circuit, IS_LEVEL_2,
						max_metric);
		}

		area->advertise_high_metrics = true;
	} else {
		area->advertise_high_metrics = false;
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
			/* Get configured metric */
			snprintf(xpath, XPATH_MAXLEN,
				 "/frr-interface:lib/interface[name='%s']",
				 circuit->interface->name);
			dnode = yang_dnode_get(running_config->dnode, xpath);

			configured_metric_l1 = yang_dnode_get_uint32(
				dnode, "./frr-isisd:isis/metric/level-1");
			configured_metric_l2 = yang_dnode_get_uint32(
				dnode, "./frr-isisd:isis/metric/level-2");

			isis_circuit_metric_set(circuit, IS_LEVEL_1,
						configured_metric_l1);
			isis_circuit_metric_set(circuit, IS_LEVEL_2,
						configured_metric_l2);
		}
	}
}

/*
 * Record in non-volatile memory the overload on startup time.
 */
void isis_restart_write_overload_time(struct isis_area *isis_area,
				      uint32_t overload_time)
{
	const char *area_name;
	json_object *json;
	json_object *json_areas;
	json_object *json_area;

	json = frr_daemon_state_load();
	area_name = isis_area->area_tag;

	json_object_object_get_ex(json, "areas", &json_areas);
	if (!json_areas) {
		json_areas = json_object_new_object();
		json_object_object_add(json, "areas", json_areas);
	}

	json_object_object_get_ex(json_areas, area_name, &json_area);
	if (!json_area) {
		json_area = json_object_new_object();
		json_object_object_add(json_areas, area_name, json_area);
	}

	json_object_int_add(json_area, "overload_time",
			    isis_area->overload_on_startup_time);

	frr_daemon_state_save(&json);
}

/*
 * Fetch from non-volatile memory the overload on startup time.
 */
uint32_t isis_restart_read_overload_time(struct isis_area *isis_area)
{
	const char *area_name;
	json_object *json;
	json_object *json_areas;
	json_object *json_area;
	json_object *json_overload_time;
	uint32_t overload_time = 0;

	area_name = isis_area->area_tag;

	json = frr_daemon_state_load();

	json_object_object_get_ex(json, "areas", &json_areas);
	if (!json_areas) {
		json_areas = json_object_new_object();
		json_object_object_add(json, "areas", json_areas);
	}

	json_object_object_get_ex(json_areas, area_name, &json_area);
	if (!json_area) {
		json_area = json_object_new_object();
		json_object_object_add(json_areas, area_name, json_area);
	}

	json_object_object_get_ex(json_area, "overload_time",
				  &json_overload_time);
	if (json_overload_time) {
		overload_time = json_object_get_int(json_overload_time);
	}

	json_object_object_del(json_areas, area_name);

	frr_daemon_state_save(&json);

	return overload_time;
}

void isis_area_attached_bit_send_set(struct isis_area *area, bool attached_bit)
{

	if (attached_bit != area->attached_bit_send) {
		area->attached_bit_send = attached_bit;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
}

void isis_area_attached_bit_receive_set(struct isis_area *area,
					bool attached_bit)
{

	if (attached_bit != area->attached_bit_rcv_ignore) {
		area->attached_bit_rcv_ignore = attached_bit;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
}

void isis_area_dynhostname_set(struct isis_area *area, bool dynhostname)
{
	if (area->dynhostname != dynhostname) {
		area->dynhostname = dynhostname;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);
	}
}

void isis_area_max_lsp_lifetime_set(struct isis_area *area, int level,
				    uint16_t max_lsp_lifetime)
{
	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

	if (area->max_lsp_lifetime[level - 1] == max_lsp_lifetime)
		return;

	area->max_lsp_lifetime[level - 1] = max_lsp_lifetime;
	lsp_regenerate_schedule(area, level, 1);
}

void isis_area_lsp_refresh_set(struct isis_area *area, int level,
			       uint16_t lsp_refresh)
{
	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

	if (area->lsp_refresh[level - 1] == lsp_refresh)
		return;

	area->lsp_refresh[level - 1] = lsp_refresh;
	lsp_regenerate_schedule(area, level, 1);
}

#ifdef FABRICD
DEFUN (log_adj_changes,
       log_adj_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->log_adj_changes = 1;

	return CMD_SUCCESS;
}

DEFUN (no_log_adj_changes,
       no_log_adj_changes_cmd,
       "no log-adjacency-changes",
       NO_STR
       "Stop logging changes in adjacency state\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->log_adj_changes = 0;

	return CMD_SUCCESS;
}
#endif /* ifdef FABRICD */
#ifdef FABRICD
/* IS-IS configuration write function */
static int isis_config_write(struct vty *vty)
{
	int write = 0;
	struct isis_area *area;
	struct listnode *node, *node2, *inode;
	struct isis *isis;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			/* ISIS - Area name */
			vty_out(vty, "router " PROTO_NAME " %s\n", area->area_tag);
			write++;
			/* ISIS - Net */
			if (listcount(area->area_addrs) > 0) {
				struct iso_address *area_addr;
				for (ALL_LIST_ELEMENTS_RO(area->area_addrs,
							  node2, area_addr)) {
					vty_out(vty, " net %pISl\n", area_addr);
					write++;
				}
			}
			/* ISIS - Dynamic hostname - Defaults to true so only
			 * display if
			 * false. */
			if (!area->dynhostname) {
				vty_out(vty, " no hostname dynamic\n");
				write++;
			}
			/* ISIS - Metric-Style - when true displays wide */
			if (!fabricd) {
				if (area->newmetric) {
					if (!area->oldmetric)
						vty_out(vty, " metric-style wide\n");
					else
						vty_out(vty,
							" metric-style transition\n");
					write++;
				} else {
					vty_out(vty, " metric-style narrow\n");
					write++;
				}
			}
			/* ISIS - overload-bit */
			if (area->overload_bit) {
				vty_out(vty, " set-overload-bit\n");
				write++;
			}
			/* ISIS - Area is-type (level-1-2 is default) */
			if (!fabricd) {
				if (area->is_type == IS_LEVEL_1) {
					vty_out(vty, " is-type level-1\n");
					write++;
				} else if (area->is_type == IS_LEVEL_2) {
					vty_out(vty, " is-type level-2-only\n");
					write++;
				}
			}
			write += isis_redist_config_write(vty, area, AF_INET);
			write += isis_redist_config_write(vty, area, AF_INET6);
			/* ISIS - Lsp generation interval */
			if (area->lsp_gen_interval[0]
			    == area->lsp_gen_interval[1]) {
				if (area->lsp_gen_interval[0]
				    != DEFAULT_MIN_LSP_GEN_INTERVAL) {
					vty_out(vty, " lsp-gen-interval %d\n",
						area->lsp_gen_interval[0]);
					write++;
				}
			} else {
				if (area->lsp_gen_interval[0]
				    != DEFAULT_MIN_LSP_GEN_INTERVAL) {
					vty_out(vty,
						" lsp-gen-interval level-1 %d\n",
						area->lsp_gen_interval[0]);
					write++;
				}
				if (area->lsp_gen_interval[1]
				    != DEFAULT_MIN_LSP_GEN_INTERVAL) {
					vty_out(vty,
						" lsp-gen-interval level-2 %d\n",
						area->lsp_gen_interval[1]);
					write++;
				}
			}
			/* ISIS - LSP lifetime */
			if (area->max_lsp_lifetime[0]
			    == area->max_lsp_lifetime[1]) {
				if (area->max_lsp_lifetime[0]
				    != DEFAULT_LSP_LIFETIME) {
					vty_out(vty, " max-lsp-lifetime %u\n",
						area->max_lsp_lifetime[0]);
					write++;
				}
			} else {
				if (area->max_lsp_lifetime[0]
				    != DEFAULT_LSP_LIFETIME) {
					vty_out(vty,
						" max-lsp-lifetime level-1 %u\n",
						area->max_lsp_lifetime[0]);
					write++;
				}
				if (area->max_lsp_lifetime[1]
				    != DEFAULT_LSP_LIFETIME) {
					vty_out(vty,
						" max-lsp-lifetime level-2 %u\n",
						area->max_lsp_lifetime[1]);
					write++;
				}
			}
			/* ISIS - LSP refresh interval */
			if (area->lsp_refresh[0] == area->lsp_refresh[1]) {
				if (area->lsp_refresh[0]
				    != DEFAULT_MAX_LSP_GEN_INTERVAL) {
					vty_out(vty,
						" lsp-refresh-interval %u\n",
						area->lsp_refresh[0]);
					write++;
				}
			} else {
				if (area->lsp_refresh[0]
				    != DEFAULT_MAX_LSP_GEN_INTERVAL) {
					vty_out(vty,
						" lsp-refresh-interval level-1 %u\n",
						area->lsp_refresh[0]);
					write++;
				}
				if (area->lsp_refresh[1]
				    != DEFAULT_MAX_LSP_GEN_INTERVAL) {
					vty_out(vty,
						" lsp-refresh-interval level-2 %u\n",
						area->lsp_refresh[1]);
					write++;
				}
			}
			if (area->lsp_mtu != DEFAULT_LSP_MTU) {
				vty_out(vty, " lsp-mtu %u\n", area->lsp_mtu);
				write++;
			}
			if (area->purge_originator) {
				vty_out(vty, " purge-originator\n");
				write++;
			}

			/* Minimum SPF interval. */
			if (area->min_spf_interval[0]
			    == area->min_spf_interval[1]) {
				if (area->min_spf_interval[0]
				    != MINIMUM_SPF_INTERVAL) {
					vty_out(vty, " spf-interval %d\n",
						area->min_spf_interval[0]);
					write++;
				}
			} else {
				if (area->min_spf_interval[0]
				    != MINIMUM_SPF_INTERVAL) {
					vty_out(vty,
						" spf-interval level-1 %d\n",
						area->min_spf_interval[0]);
					write++;
				}
				if (area->min_spf_interval[1]
				    != MINIMUM_SPF_INTERVAL) {
					vty_out(vty,
						" spf-interval level-2 %d\n",
						area->min_spf_interval[1]);
					write++;
				}
			}

			/* IETF SPF interval */
			if (area->spf_delay_ietf[0]) {
				vty_out(vty,
					" spf-delay-ietf init-delay %ld short-delay %ld long-delay %ld holddown %ld time-to-learn %ld\n",
					spf_backoff_init_delay(
						area->spf_delay_ietf[0]),
					spf_backoff_short_delay(
						area->spf_delay_ietf[0]),
					spf_backoff_long_delay(
						area->spf_delay_ietf[0]),
					spf_backoff_holddown(
						area->spf_delay_ietf[0]),
					spf_backoff_timetolearn(
						area->spf_delay_ietf[0]));
				write++;
			}

			/* Authentication passwords. */
			if (area->area_passwd.type
			    == ISIS_PASSWD_TYPE_HMAC_MD5) {
				vty_out(vty, " area-password md5 %s",
					area->area_passwd.passwd);
				if (CHECK_FLAG(area->area_passwd.snp_auth,
					       SNP_AUTH_SEND)) {
					vty_out(vty, " authenticate snp ");
					if (CHECK_FLAG(
						    area->area_passwd.snp_auth,
						    SNP_AUTH_RECV))
						vty_out(vty, "validate");
					else
						vty_out(vty, "send-only");
				}
				vty_out(vty, "\n");
				write++;
			} else if (area->area_passwd.type
				   == ISIS_PASSWD_TYPE_CLEARTXT) {
				vty_out(vty, " area-password clear %s",
					area->area_passwd.passwd);
				if (CHECK_FLAG(area->area_passwd.snp_auth,
					       SNP_AUTH_SEND)) {
					vty_out(vty, " authenticate snp ");
					if (CHECK_FLAG(
						    area->area_passwd.snp_auth,
						    SNP_AUTH_RECV))
						vty_out(vty, "validate");
					else
						vty_out(vty, "send-only");
				}
				vty_out(vty, "\n");
				write++;
			}
			if (area->domain_passwd.type
			    == ISIS_PASSWD_TYPE_HMAC_MD5) {
				vty_out(vty, " domain-password md5 %s",
					area->domain_passwd.passwd);
				if (CHECK_FLAG(area->domain_passwd.snp_auth,
					       SNP_AUTH_SEND)) {
					vty_out(vty, " authenticate snp ");
					if (CHECK_FLAG(area->domain_passwd
							       .snp_auth,
						       SNP_AUTH_RECV))
						vty_out(vty, "validate");
					else
						vty_out(vty, "send-only");
				}
				vty_out(vty, "\n");
				write++;
			} else if (area->domain_passwd.type
				   == ISIS_PASSWD_TYPE_CLEARTXT) {
				vty_out(vty, " domain-password clear %s",
					area->domain_passwd.passwd);
				if (CHECK_FLAG(area->domain_passwd.snp_auth,
					       SNP_AUTH_SEND)) {
					vty_out(vty, " authenticate snp ");
					if (CHECK_FLAG(area->domain_passwd
							       .snp_auth,
						       SNP_AUTH_RECV))
						vty_out(vty, "validate");
					else
						vty_out(vty, "send-only");
				}
				vty_out(vty, "\n");
				write++;
			}

			if (area->log_adj_changes) {
				vty_out(vty, " log-adjacency-changes\n");
				write++;
			}

			write += area_write_mt_settings(area, vty);
			write += fabricd_write_settings(area, vty);

			vty_out(vty, "exit\n");
		}
	}

	return write;
}

struct cmd_node router_node = {
	.name = "openfabric",
	.node = OPENFABRIC_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = isis_config_write,
};
#endif /* ifdef FABRICD */
#ifndef FABRICD
/* IS-IS configuration write function */
static int isis_config_write(struct vty *vty)
{
	int write = 0;
	struct lyd_node *dnode;

	dnode = yang_dnode_get(running_config->dnode, "/frr-isisd:isis");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		write++;
	}

	return write;
}

struct cmd_node router_node = {
	.name = "isis",
	.node = ISIS_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = isis_config_write,
};

struct cmd_node isis_flex_algo_node = {
	.name = "isis-flex-algo",
	.node = ISIS_FLEX_ALGO_NODE,
	.parent_node = ISIS_NODE,
	.prompt = "%s(config-router-flex-algo)# ",
};
#endif /* ifdnef FABRICD */

struct cmd_node isis_srv6_node = {
	.name = "isis-srv6",
	.node = ISIS_SRV6_NODE,
	.parent_node = ISIS_NODE,
	.prompt = "%s(config-router-srv6)# ",
};

struct cmd_node isis_srv6_node_msd_node = {
	.name = "isis-srv6-node-msd",
	.node = ISIS_SRV6_NODE_MSD_NODE,
	.parent_node = ISIS_SRV6_NODE,
	.prompt = "%s(config-router-srv6-node-msd)# ",
};

void isis_init(void)
{
	/* Install IS-IS top node */
	install_node(&router_node);

	install_element(VIEW_NODE, &show_isis_summary_cmd);

	install_element(VIEW_NODE, &show_isis_spf_ietf_cmd);

	install_element(VIEW_NODE, &show_isis_interface_cmd);
	install_element(VIEW_NODE, &show_isis_interface_detail_cmd);
	install_element(VIEW_NODE, &show_isis_interface_arg_cmd);

	install_element(VIEW_NODE, &show_isis_neighbor_cmd);
	install_element(VIEW_NODE, &show_isis_neighbor_detail_cmd);
	install_element(VIEW_NODE, &show_isis_neighbor_arg_cmd);
	install_element(ENABLE_NODE, &clear_isis_neighbor_cmd);
	install_element(ENABLE_NODE, &clear_isis_neighbor_arg_cmd);

	install_element(VIEW_NODE, &show_hostname_cmd);
	install_element(VIEW_NODE, &show_database_cmd);

	install_element(ENABLE_NODE, &show_debugging_isis_cmd);

	install_node(&debug_node);

	install_element(ENABLE_NODE, &debug_isis_adj_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_adj_cmd);
	install_element(ENABLE_NODE, &debug_isis_tx_queue_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_tx_queue_cmd);
	install_element(ENABLE_NODE, &debug_isis_flooding_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_flooding_cmd);
	install_element(ENABLE_NODE, &debug_isis_snp_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_snp_cmd);
	install_element(ENABLE_NODE, &debug_isis_upd_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_upd_cmd);
	install_element(ENABLE_NODE, &debug_isis_spfevents_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_spfevents_cmd);
	install_element(ENABLE_NODE, &debug_isis_srevents_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_srevents_cmd);
	install_element(ENABLE_NODE, &debug_isis_teevents_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_teevents_cmd);
	install_element(ENABLE_NODE, &debug_isis_lfa_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_lfa_cmd);
	install_element(ENABLE_NODE, &debug_isis_rtevents_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_rtevents_cmd);
	install_element(ENABLE_NODE, &debug_isis_events_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_events_cmd);
	install_element(ENABLE_NODE, &debug_isis_packet_dump_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_packet_dump_cmd);
	install_element(ENABLE_NODE, &debug_isis_lsp_gen_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_lsp_gen_cmd);
	install_element(ENABLE_NODE, &debug_isis_lsp_sched_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_lsp_sched_cmd);
	install_element(ENABLE_NODE, &debug_isis_bfd_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_bfd_cmd);
	install_element(ENABLE_NODE, &debug_isis_ldp_sync_cmd);
	install_element(ENABLE_NODE, &no_debug_isis_ldp_sync_cmd);

	install_element(CONFIG_NODE, &debug_isis_adj_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_adj_cmd);
	install_element(CONFIG_NODE, &debug_isis_tx_queue_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_tx_queue_cmd);
	install_element(CONFIG_NODE, &debug_isis_flooding_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_flooding_cmd);
	install_element(CONFIG_NODE, &debug_isis_snp_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_snp_cmd);
	install_element(CONFIG_NODE, &debug_isis_upd_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_upd_cmd);
	install_element(CONFIG_NODE, &debug_isis_spfevents_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_spfevents_cmd);
	install_element(CONFIG_NODE, &debug_isis_srevents_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_srevents_cmd);
	install_element(CONFIG_NODE, &debug_isis_teevents_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_teevents_cmd);
	install_element(CONFIG_NODE, &debug_isis_lfa_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_lfa_cmd);
	install_element(CONFIG_NODE, &debug_isis_rtevents_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_rtevents_cmd);
	install_element(CONFIG_NODE, &debug_isis_events_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_events_cmd);
	install_element(CONFIG_NODE, &debug_isis_packet_dump_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_packet_dump_cmd);
	install_element(CONFIG_NODE, &debug_isis_lsp_gen_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_lsp_gen_cmd);
	install_element(CONFIG_NODE, &debug_isis_lsp_sched_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_lsp_sched_cmd);
	install_element(CONFIG_NODE, &debug_isis_bfd_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_bfd_cmd);
	install_element(CONFIG_NODE, &debug_isis_ldp_sync_cmd);
	install_element(CONFIG_NODE, &no_debug_isis_ldp_sync_cmd);

	install_default(ROUTER_NODE);

#ifdef FABRICD
	install_element(CONFIG_NODE, &router_openfabric_cmd);
	install_element(CONFIG_NODE, &no_router_openfabric_cmd);

	install_element(ROUTER_NODE, &net_cmd);
	install_element(ROUTER_NODE, &no_net_cmd);

	install_element(ROUTER_NODE, &isis_topology_cmd);
	install_element(ROUTER_NODE, &no_isis_topology_cmd);

	install_element(ROUTER_NODE, &log_adj_changes_cmd);
	install_element(ROUTER_NODE, &no_log_adj_changes_cmd);
#endif /* ifdef FABRICD */
#ifndef FABRICD
	install_node(&isis_flex_algo_node);
	install_default(ISIS_FLEX_ALGO_NODE);
#endif /* ifdnef FABRICD */

	install_node(&isis_srv6_node);
	install_default(ISIS_SRV6_NODE);

	install_node(&isis_srv6_node_msd_node);
	install_default(ISIS_SRV6_NODE_MSD_NODE);

	spf_backoff_cmd_init();
}
