/*
 * IS-IS Rout(e)ing protocol - isisd.c
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

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "time.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"
#include "qobj.h"
#include "spf_backoff.h"
#include "lib/northbound_cli.h"

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
#include "isisd/fabricd.h"
#include "isisd/isis_nb.h"

struct isis *isis = NULL;

DEFINE_QOBJ_TYPE(isis)
DEFINE_QOBJ_TYPE(isis_area)

/*
 * Prototypes.
 */
int isis_area_get(struct vty *, const char *);
int area_net_title(struct vty *, const char *);
int area_clear_net_title(struct vty *, const char *);
int show_isis_interface_common(struct vty *, const char *ifname, char);
int show_isis_neighbor_common(struct vty *, const char *id, char);
int clear_isis_neighbor_common(struct vty *, const char *id);
int isis_config_write(struct vty *);


void isis_new(unsigned long process_id, vrf_id_t vrf_id)
{
	isis = XCALLOC(MTYPE_ISIS, sizeof(struct isis));
	/*
	 * Default values
	 */
	isis->vrf_id = vrf_id;
	isis->max_area_addrs = 3;
	isis->process_id = process_id;
	isis->router_id = 0;
	isis->area_list = list_new();
	isis->init_circ_list = list_new();
	isis->uptime = time(NULL);
	isis->nexthops = list_new();
	dyn_cache_init();
	/*
	 * uncomment the next line for full debugs
	 */
	/* isis->debugs = 0xFFFF; */

	QOBJ_REG(isis, isis);
}

struct isis_area *isis_area_create(const char *area_tag)
{
	struct isis_area *area;

	area = XCALLOC(MTYPE_ISIS_AREA, sizeof(struct isis_area));

	/*
	 * Fabricd runs only as level-2.
	 * For IS-IS, the first instance is level-1-2 rest are level-1,
	 * unless otherwise configured
	 */
	if (fabricd) {
		area->is_type = IS_LEVEL_2;
	} else if (listcount(isis->area_list) == 0)
		area->is_type = IS_LEVEL_1_AND_2;
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

	spftree_area_init(area);

	area->circuit_list = list_new();
	area->area_addrs = list_new();
	thread_add_timer(master, lsp_tick, area, 1, &area->t_tick);
	flags_initialize(&area->flags);

	/*
	 * Default values
	 */
#ifndef FABRICD
	enum isis_metric_style default_style;

	area->max_lsp_lifetime[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/maximum-lifetime/level-1");
	area->max_lsp_lifetime[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/maximum-lifetime/level-2");
	area->lsp_refresh[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/refresh-interval/level-1");
	area->lsp_refresh[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/refresh-interval/level-2");
	area->lsp_gen_interval[0] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/generation-interval/level-1");
	area->lsp_gen_interval[1] = yang_get_default_uint16(
		"/frr-isisd:isis/instance/lsp/generation-interval/level-2");
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
#endif /* ifndef FABRICD */

	area_mt_init(area);

	area->area_tag = strdup(area_tag);
	listnode_add(isis->area_list, area);
	area->isis = isis;

	if (fabricd)
		area->fabricd = fabricd_new(area);

	area->lsp_refresh_arg[0].area = area;
	area->lsp_refresh_arg[0].level = IS_LEVEL_1;
	area->lsp_refresh_arg[1].area = area;
	area->lsp_refresh_arg[1].level = IS_LEVEL_2;


	QOBJ_REG(area, isis_area);

	return area;
}

struct isis_area *isis_area_lookup(const char *area_tag)
{
	struct isis_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if ((area->area_tag == NULL && area_tag == NULL)
		    || (area->area_tag && area_tag
			&& strcmp(area->area_tag, area_tag) == 0))
			return area;

	return NULL;
}

int isis_area_get(struct vty *vty, const char *area_tag)
{
	struct isis_area *area;

	area = isis_area_lookup(area_tag);

	if (area) {
		VTY_PUSH_CONTEXT(ROUTER_NODE, area);
		return CMD_SUCCESS;
	}

	area = isis_area_create(area_tag);

	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("New IS-IS area instance %s", area->area_tag);

	VTY_PUSH_CONTEXT(ROUTER_NODE, area);

	return CMD_SUCCESS;
}

int isis_area_destroy(const char *area_tag)
{
	struct isis_area *area;
	struct listnode *node, *nnode;
	struct isis_circuit *circuit;
	struct area_addr *addr;

	area = isis_area_lookup(area_tag);

	if (area == NULL) {
		zlog_warn("%s: could not find area with area-tag %s",
				__func__, area_tag);
		return CMD_ERR_NO_MATCH;
	}

	QOBJ_UNREG(area);

	if (fabricd)
		fabricd_finish(area->fabricd);

	/* Disable MPLS if necessary before flooding LSP */
	if (IS_MPLS_TE(area->mta))
		area->mta->status = disable;

	if (area->circuit_list) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit)) {
			circuit->ip_router = 0;
			circuit->ipv6_router = 0;
			isis_csm_state_change(ISIS_DISABLE, circuit, area);
		}
		list_delete(&area->circuit_list);
	}

	lsp_db_fini(&area->lspdb[0]);
	lsp_db_fini(&area->lspdb[1]);

	/* invalidate and verify to delete all routes from zebra */
	isis_area_invalidate_routes(area, area->is_type);
	isis_area_verify_routes(area);

	spftree_area_del(area);

	THREAD_TIMER_OFF(area->spf_timer[0]);
	THREAD_TIMER_OFF(area->spf_timer[1]);

	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);

	isis_redist_area_finish(area);

	for (ALL_LIST_ELEMENTS(area->area_addrs, node, nnode, addr)) {
		list_delete_node(area->area_addrs, node);
		XFREE(MTYPE_ISIS_AREA_ADDR, addr);
	}
	area->area_addrs = NULL;

	THREAD_TIMER_OFF(area->t_tick);
	THREAD_TIMER_OFF(area->t_lsp_refresh[0]);
	THREAD_TIMER_OFF(area->t_lsp_refresh[1]);

	thread_cancel_event(master, area);

	listnode_delete(isis->area_list, area);

	free(area->area_tag);

	area_mt_finish(area);

	XFREE(MTYPE_ISIS_AREA, area);

	if (listcount(isis->area_list) == 0) {
		memset(isis->sysid, 0, ISIS_SYS_ID_LEN);
		isis->sysid_set = 0;
	}

	return CMD_SUCCESS;
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
	struct area_addr *addr;
	struct area_addr *addrp;
	struct listnode *node;

	uint8_t buff[255];

	/* We check that we are not over the maximal number of addresses */
	if (listcount(area->area_addrs) >= isis->max_area_addrs) {
		vty_out(vty,
			"Maximum of area addresses (%d) already reached \n",
			isis->max_area_addrs);
		return CMD_ERR_NOTHING_TODO;
	}

	addr = XMALLOC(MTYPE_ISIS_AREA_ADDR, sizeof(struct area_addr));
	addr->addr_len = dotformat2buff(buff, net_title);
	memcpy(addr->area_addr, buff, addr->addr_len);
#ifdef EXTREME_DEBUG
	zlog_debug("added area address %s for area %s (address length %d)",
		   net_title, area->area_tag, addr->addr_len);
#endif /* EXTREME_DEBUG */
	if (addr->addr_len < 8 || addr->addr_len > 20) {
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

	if (isis->sysid_set == 0) {
		/*
		 * First area address - get the SystemID for this router
		 */
		memcpy(isis->sysid, GETSYSID(addr), ISIS_SYS_ID_LEN);
		isis->sysid_set = 1;
		if (isis->debugs & DEBUG_EVENTS)
			zlog_debug("Router has SystemID %s",
				   sysid_print(isis->sysid));
	} else {
		/*
		 * Check that the SystemID portions match
		 */
		if (memcmp(isis->sysid, GETSYSID(addr), ISIS_SYS_ID_LEN)) {
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
	struct area_addr addr, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];

	addr.addr_len = dotformat2buff(buff, net_title);
	if (addr.addr_len < 8 || addr.addr_len > 20) {
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
		memset(isis->sysid, 0, ISIS_SYS_ID_LEN);
		isis->sysid_set = 0;
		if (isis->debugs & DEBUG_EVENTS)
			zlog_debug("Router has no SystemID");
	}

	return CMD_SUCCESS;
}

/*
 * 'show isis interface' command
 */

int show_isis_interface_common(struct vty *vty, const char *ifname, char detail)
{
	struct listnode *anode, *cnode;
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		vty_out(vty, "Area %s:\n", area->area_tag);

		if (detail == ISIS_UI_LEVEL_BRIEF)
			vty_out(vty,
				"  Interface   CircId   State    Type     Level\n");

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			if (!ifname)
				isis_circuit_print_vty(circuit, vty, detail);
			else if (strcmp(circuit->interface->name, ifname) == 0)
				isis_circuit_print_vty(circuit, vty, detail);
	}

	return CMD_SUCCESS;
}

DEFUN (show_isis_interface,
       show_isis_interface_cmd,
       "show " PROTO_NAME " interface",
       SHOW_STR
       PROTO_HELP
       "ISIS interface\n")
{
	return show_isis_interface_common(vty, NULL, ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_isis_interface_detail,
       show_isis_interface_detail_cmd,
       "show " PROTO_NAME " interface detail",
       SHOW_STR
       PROTO_HELP
       "ISIS interface\n"
       "show detailed information\n")
{
	return show_isis_interface_common(vty, NULL, ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_isis_interface_arg,
       show_isis_interface_arg_cmd,
       "show " PROTO_NAME " interface WORD",
       SHOW_STR
       PROTO_HELP
       "ISIS interface\n"
       "ISIS interface name\n")
{
	int idx_word = 3;
	return show_isis_interface_common(vty, argv[idx_word]->arg,
					  ISIS_UI_LEVEL_DETAIL);
}

/*
 * 'show isis neighbor' command
 */

int show_isis_neighbor_common(struct vty *vty, const char *id, char detail)
{
	struct listnode *anode, *cnode, *node;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;
	struct isis_dynhn *dynhn;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	int i;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	memset(sysid, 0, ISIS_SYS_ID_LEN);
	if (id) {
		if (sysid2buff(sysid, id) == 0) {
			dynhn = dynhn_find_by_name(id);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			memcpy(sysid, dynhn->id, ISIS_SYS_ID_LEN);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		vty_out(vty, "Area %s:\n", area->area_tag);

		if (detail == ISIS_UI_LEVEL_BRIEF)
			vty_out(vty,
				"  System Id           Interface   L  State        Holdtime SNPA\n");

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS_RO(
							     adjdb, node, adj))
							if (!id
							    || !memcmp(adj->sysid,
								       sysid,
								       ISIS_SYS_ID_LEN))
								isis_adj_print_vty(
									adj,
									vty,
									detail);
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id
				    || !memcmp(adj->sysid, sysid,
					       ISIS_SYS_ID_LEN))
					isis_adj_print_vty(adj, vty, detail);
			}
		}
	}

	return CMD_SUCCESS;
}

/*
 * 'clear isis neighbor' command
 */
int clear_isis_neighbor_common(struct vty *vty, const char *id)
{
	struct listnode *anode, *cnode, *cnextnode, *node, *nnode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;
	struct isis_dynhn *dynhn;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	int i;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	memset(sysid, 0, ISIS_SYS_ID_LEN);
	if (id) {
		if (sysid2buff(sysid, id) == 0) {
			dynhn = dynhn_find_by_name(id);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			memcpy(sysid, dynhn->id, ISIS_SYS_ID_LEN);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, cnode, cnextnode,
				       circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS(
							     adjdb, node, nnode,
							     adj))
							if (!id
							    || !memcmp(adj->sysid,
								       sysid,
								       ISIS_SYS_ID_LEN))
								isis_adj_state_change(
									adj,
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
						adj, ISIS_ADJ_DOWN,
						"clear user request");
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_isis_neighbor,
       show_isis_neighbor_cmd,
       "show " PROTO_NAME " neighbor",
       SHOW_STR
       PROTO_HELP
       "ISIS neighbor adjacencies\n")
{
	return show_isis_neighbor_common(vty, NULL, ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_isis_neighbor_detail,
       show_isis_neighbor_detail_cmd,
       "show " PROTO_NAME " neighbor detail",
       SHOW_STR
       PROTO_HELP
       "ISIS neighbor adjacencies\n"
       "show detailed information\n")
{
	return show_isis_neighbor_common(vty, NULL, ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_isis_neighbor_arg,
       show_isis_neighbor_arg_cmd,
       "show " PROTO_NAME " neighbor WORD",
       SHOW_STR
       PROTO_HELP
       "ISIS neighbor adjacencies\n"
       "System id\n")
{
	int idx_word = 3;
	return show_isis_neighbor_common(vty, argv[idx_word]->arg,
					 ISIS_UI_LEVEL_DETAIL);
}

DEFUN (clear_isis_neighbor,
       clear_isis_neighbor_cmd,
       "clear " PROTO_NAME " neighbor",
       CLEAR_STR
       PROTO_HELP
       "ISIS neighbor adjacencies\n")
{
	return clear_isis_neighbor_common(vty, NULL);
}

DEFUN (clear_isis_neighbor_arg,
       clear_isis_neighbor_arg_cmd,
       "clear " PROTO_NAME " neighbor WORD",
       CLEAR_STR
       PROTO_HELP
       "ISIS neighbor adjacencies\n"
       "System id\n")
{
	int idx_word = 3;
	return clear_isis_neighbor_common(vty, argv[idx_word]->arg);
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
	if (flags & DEBUG_UPDATE_PACKETS)
		vty_out(vty, "IS-IS Update related packet debugging is %s\n",
			onoffs);
	if (flags & DEBUG_RTE_EVENTS)
		vty_out(vty, "IS-IS Route related debuggin is %s\n", onoffs);
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
}

DEFUN_NOSH (show_debugging,
	    show_debugging_isis_cmd,
	    "show debugging [" PROTO_NAME "]",
	    SHOW_STR
	    "State of each debugging option\n"
	    PROTO_HELP)
{
	vty_out(vty, PROTO_NAME " debugging status:\n");

	if (isis->debugs)
		print_debug(vty, isis->debugs, 1);

	return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

static int config_write_debug(struct vty *vty)
{
	int write = 0;
	int flags = isis->debugs;

	if (flags & DEBUG_ADJ_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " adj-packets\n");
		write++;
	}
	if (flags & DEBUG_TX_QUEUE) {
		vty_out(vty, "debug " PROTO_NAME " tx-queue\n");
		write++;
	}
	if (flags & DEBUG_SNP_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " snp-packets\n");
		write++;
	}
	if (flags & DEBUG_SPF_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " spf-events\n");
		write++;
	}
	if (flags & DEBUG_UPDATE_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " update-packets\n");
		write++;
	}
	if (flags & DEBUG_RTE_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " route-events\n");
		write++;
	}
	if (flags & DEBUG_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " events\n");
		write++;
	}
	if (flags & DEBUG_PACKET_DUMP) {
		vty_out(vty, "debug " PROTO_NAME " packet-dump\n");
		write++;
	}
	if (flags & DEBUG_LSP_GEN) {
		vty_out(vty, "debug " PROTO_NAME " lsp-gen\n");
		write++;
	}
	if (flags & DEBUG_LSP_SCHED) {
		vty_out(vty, "debug " PROTO_NAME " lsp-sched\n");
		write++;
	}
	if (flags & DEBUG_FLOODING) {
		vty_out(vty, "debug " PROTO_NAME " flooding\n");
		write++;
	}
	if (flags & DEBUG_BFD) {
		vty_out(vty, "debug " PROTO_NAME " bfd\n");
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
	isis->debugs |= DEBUG_ADJ_PACKETS;
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
	isis->debugs &= ~DEBUG_ADJ_PACKETS;
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
	isis->debugs |= DEBUG_TX_QUEUE;
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
	isis->debugs &= ~DEBUG_TX_QUEUE;
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
	isis->debugs |= DEBUG_FLOODING;
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
	isis->debugs &= ~DEBUG_FLOODING;
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
	isis->debugs |= DEBUG_SNP_PACKETS;
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
	isis->debugs &= ~DEBUG_SNP_PACKETS;
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
	isis->debugs |= DEBUG_UPDATE_PACKETS;
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
	isis->debugs &= ~DEBUG_UPDATE_PACKETS;
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
	isis->debugs |= DEBUG_SPF_EVENTS;
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
	isis->debugs &= ~DEBUG_SPF_EVENTS;
	print_debug(vty, DEBUG_SPF_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_isis_rtevents,
       debug_isis_rtevents_cmd,
       "debug " PROTO_NAME " route-events",
       DEBUG_STR
       PROTO_HELP
       "IS-IS Route related events\n")
{
	isis->debugs |= DEBUG_RTE_EVENTS;
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
	isis->debugs &= ~DEBUG_RTE_EVENTS;
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
	isis->debugs |= DEBUG_EVENTS;
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
	isis->debugs &= ~DEBUG_EVENTS;
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
	isis->debugs |= DEBUG_PACKET_DUMP;
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
	isis->debugs &= ~DEBUG_PACKET_DUMP;
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
	isis->debugs |= DEBUG_LSP_GEN;
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
	isis->debugs &= ~DEBUG_LSP_GEN;
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
	isis->debugs |= DEBUG_LSP_SCHED;
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
	isis->debugs &= ~DEBUG_LSP_SCHED;
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
	isis->debugs |= DEBUG_BFD;
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
	isis->debugs &= ~DEBUG_BFD;
	print_debug(vty, DEBUG_BFD, 0);

	return CMD_SUCCESS;
}

DEFUN (show_hostname,
       show_hostname_cmd,
       "show " PROTO_NAME " hostname",
       SHOW_STR
       PROTO_HELP
       "IS-IS Dynamic hostname mapping\n")
{
	dynhn_print_all(vty);

	return CMD_SUCCESS;
}

DEFUN (show_isis_spf_ietf,
       show_isis_spf_ietf_cmd,
       "show " PROTO_NAME " spf-delay-ietf",
       SHOW_STR
       PROTO_HELP
       "SPF delay IETF information\n")
{
	if (!isis) {
		vty_out(vty, "ISIS is not running\n");
		return CMD_SUCCESS;
	}

	struct listnode *node;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;

			vty_out(vty, "  Level-%d:\n", level);
			vty_out(vty, "    SPF delay status: ");
			if (area->spf_timer[level - 1]) {
				struct timeval remain = thread_timer_remain(
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
	return CMD_SUCCESS;
}

DEFUN (show_isis_summary,
       show_isis_summary_cmd,
       "show " PROTO_NAME " summary",
       SHOW_STR PROTO_HELP "summary\n")
{
	struct listnode *node, *node2;
	struct isis_area *area;
	int level;

	if (isis == NULL) {
		vty_out(vty, PROTO_NAME " is not running\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Process Id      : %ld\n", isis->process_id);
	if (isis->sysid_set)
		vty_out(vty, "System Id       : %s\n",
			sysid_print(isis->sysid));

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
				vty_out(vty, "  Tier: %" PRIu8 "\n", tier);
		}

		if (listcount(area->area_addrs) > 0) {
			struct area_addr *area_addr;
			for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node2,
						  area_addr)) {
				vty_out(vty, "  Net: %s\n",
					isonet_print(area_addr->area_addr,
						     area_addr->addr_len
							     + ISIS_SYS_ID_LEN
							     + 1));
			}
		}

		vty_out(vty, "  TX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_tx_counters);
		vty_out(vty, "   LSP RXMT: %" PRIu64 "\n",
			area->lsp_rxmt_count);
		vty_out(vty, "  RX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_rx_counters);

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

			vty_out(vty, "    IPv4 route computation:\n");
			isis_spf_print(area->spftree[SPFTREE_IPV4][level - 1],
				       vty);

			vty_out(vty, "    IPv6 route computation:\n");
			isis_spf_print(area->spftree[SPFTREE_IPV6][level - 1],
				       vty);

			vty_out(vty, "    IPv6 dst-src route computation:\n");
			isis_spf_print(area->spftree[SPFTREE_DSTSRC][level-1],
				       vty);
		}
	}
	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

struct isis_lsp *lsp_for_arg(struct lspdb_head *head, const char *argv)
{
	char sysid[255] = {0};
	uint8_t number[3];
	const char *pos;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2] = {0};
	struct isis_dynhn *dynhn;
	struct isis_lsp *lsp = NULL;

	if (!argv)
		return NULL;

	/*
	 * extract fragment and pseudo id from the string argv
	 * in the forms:
	 * (a) <systemid/hostname>.<pseudo-id>-<framenent> or
	 * (b) <systemid/hostname>.<pseudo-id> or
	 * (c) <systemid/hostname> or
	 * Where systemid is in the form:
	 * xxxx.xxxx.xxxx
	 */
	if (argv)
		strlcpy(sysid, argv, sizeof(sysid));
	if (argv && strlen(argv) > 3) {
		pos = argv + strlen(argv) - 3;
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
			sysid[pos - argv - 1] = '\0';
		}
	}

	/*
	 * Try to find the lsp-id if the argv
	 * string is in
	 * the form
	 * hostname.<pseudo-id>-<fragment>
	 */
	if (sysid2buff(lspid, sysid)) {
		lsp = lsp_search(head, lspid);
	} else if ((dynhn = dynhn_find_by_name(sysid))) {
		memcpy(lspid, dynhn->id, ISIS_SYS_ID_LEN);
		lsp = lsp_search(head, lspid);
	} else if (strncmp(cmd_hostname_get(), sysid, 15) == 0) {
		memcpy(lspid, isis->sysid, ISIS_SYS_ID_LEN);
		lsp = lsp_search(head, lspid);
	}

	return lsp;
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
static int show_isis_database(struct vty *vty, const char *argv, int ui_level)
{
	struct listnode *node;
	struct isis_area *area;
	struct isis_lsp *lsp;
	int level, lsp_count;

	if (isis->area_list->count == 0)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (level = 0; level < ISIS_LEVELS; level++) {
			if (lspdb_count(&area->lspdb[level]) > 0) {
				lsp = lsp_for_arg(&area->lspdb[level], argv);

				if (lsp != NULL || argv == NULL) {
					vty_out(vty,
						"IS-IS Level-%d link-state database:\n",
						level + 1);

					/* print the title in all cases */
					vty_out(vty,
						"LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL\n");
				}

				if (lsp) {
					if (ui_level == ISIS_UI_LEVEL_DETAIL)
						lsp_print_detail(
							lsp, vty,
							area->dynhostname);
					else
						lsp_print(lsp, vty,
							  area->dynhostname);
				} else if (argv == NULL) {
					lsp_count = lsp_print_all(
						vty, &area->lspdb[level],
						ui_level, area->dynhostname);

					vty_out(vty, "    %u LSPs\n\n",
						lsp_count);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_database,
       show_database_cmd,
       "show " PROTO_NAME " database [detail] [WORD]",
       SHOW_STR
       PROTO_HELP
       "Link state database\n"
       "Detailed information\n"
       "LSP ID\n")
{
	int idx = 0;
	int uilevel = argv_find(argv, argc, "detail", &idx)
			      ? ISIS_UI_LEVEL_DETAIL
			      : ISIS_UI_LEVEL_BRIEF;
	char *id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg : NULL;
	return show_isis_database(vty, id, uilevel);
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
	int idx_word = 3;
	return isis_area_destroy(argv[idx_word]->arg);
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
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		if (!(level & levels))
			continue;
		for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
			isis_spf_invalidate_routes(
					area->spftree[tree][level - 1]);
		}
	}
}

void isis_area_verify_routes(struct isis_area *area)
{
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++)
		isis_spf_verify_routes(area, area->spftree[tree]);
}

static void area_resign_level(struct isis_area *area, int level)
{
	isis_area_invalidate_routes(area, level);
	isis_area_verify_routes(area);

	lsp_db_fini(&area->lspdb[level - 1]);

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		if (area->spftree[tree][level - 1]) {
			isis_spftree_del(area->spftree[tree][level - 1]);
			area->spftree[tree][level - 1] = NULL;
		}
	}

	THREAD_TIMER_OFF(area->spf_timer[level - 1]);

	sched_debug(
		"ISIS (%s): Resigned from L%d - canceling LSP regeneration timer.",
		area->area_tag, level);
	THREAD_TIMER_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
}

void isis_area_is_type_set(struct isis_area *area, int is_type)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (isis->debugs & DEBUG_EVENTS)
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

	/* override circuit's is_type */
	if (area->is_type != IS_LEVEL_1_AND_2) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			isis_circuit_is_type_set(circuit, is_type);
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
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
#ifndef FABRICD
	isis_notif_db_overload(area, overload_bit);
#endif /* ifndef FABRICD */
}

void isis_area_attached_bit_set(struct isis_area *area, bool attached_bit)
{
	char new_attached_bit = attached_bit ? LSPBIT_ATT : 0;

	if (new_attached_bit != area->attached_bit) {
		area->attached_bit = new_attached_bit;
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
int isis_config_write(struct vty *vty)
{
	int write = 0;

	if (isis != NULL) {
		struct isis_area *area;
		struct listnode *node, *node2;

		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			/* ISIS - Area name */
			vty_out(vty, "router " PROTO_NAME " %s\n", area->area_tag);
			write++;
			/* ISIS - Net */
			if (listcount(area->area_addrs) > 0) {
				struct area_addr *area_addr;
				for (ALL_LIST_ELEMENTS_RO(area->area_addrs,
							  node2, area_addr)) {
					vty_out(vty, " net %s\n",
						isonet_print(
							area_addr->area_addr,
							area_addr->addr_len
								+ ISIS_SYS_ID_LEN
								+ 1));
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
		}
	}

	return write;
}

#else
/* IS-IS configuration write function */
int isis_config_write(struct vty *vty)
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
#endif /* ifdef FABRICD */

struct cmd_node router_node = {ROUTER_NODE, "%s(config-router)# ", 1};

void isis_init(void)
{
	/* Install IS-IS top node */
	install_node(&router_node, isis_config_write);

	install_element(VIEW_NODE, &show_isis_summary_cmd);

	install_element(VIEW_NODE, &show_isis_spf_ietf_cmd);

	install_element(VIEW_NODE, &show_isis_interface_cmd);
	install_element(VIEW_NODE, &show_isis_interface_detail_cmd);
	install_element(VIEW_NODE, &show_isis_interface_arg_cmd);

	install_element(VIEW_NODE, &show_isis_neighbor_cmd);
	install_element(VIEW_NODE, &show_isis_neighbor_detail_cmd);
	install_element(VIEW_NODE, &show_isis_neighbor_arg_cmd);
	install_element(VIEW_NODE, &clear_isis_neighbor_cmd);
	install_element(VIEW_NODE, &clear_isis_neighbor_arg_cmd);

	install_element(VIEW_NODE, &show_hostname_cmd);
	install_element(VIEW_NODE, &show_database_cmd);

	install_element(ENABLE_NODE, &show_debugging_isis_cmd);

	install_node(&debug_node, config_write_debug);

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

	spf_backoff_cmd_init();
}
