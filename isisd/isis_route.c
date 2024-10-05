// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol               - isis_route.c
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "lib_errors.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "srcdest_table.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_spf_private.h"
#include "isis_route.h"
#include "isis_zebra.h"
#include "isis_flex_algo.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_NEXTHOP,    "ISIS nexthop");
DEFINE_MTYPE_STATIC(ISISD, ISIS_ROUTE_INFO, "ISIS route info");
DEFINE_MTYPE_STATIC(ISISD, ISIS_ROUTE_TABLE_INFO, "ISIS route table info");


DEFINE_HOOK(isis_route_update_hook,
	    (struct isis_area * area, struct prefix *prefix,
	     struct isis_route_info *route_info),
	    (area, prefix, route_info));

static struct isis_nexthop *nexthoplookup(struct list *nexthops, int family,
					  union g_addr *ip, ifindex_t ifindex);
static void isis_route_update(struct isis_area *area, struct prefix *prefix,
			      struct prefix_ipv6 *src_p,
			      struct isis_route_info *route_info);

static struct mpls_label_stack *
label_stack_dup(const struct mpls_label_stack *const orig)
{
	struct mpls_label_stack *copy;
	int array_size;

	if (orig == NULL)
		return NULL;

	array_size = orig->num_labels * sizeof(mpls_label_t);
	copy = XCALLOC(MTYPE_ISIS_NEXTHOP_LABELS,
		       sizeof(struct mpls_label_stack) + array_size);
	copy->num_labels = orig->num_labels;
	memcpy(copy->label, orig->label, array_size);
	return copy;
}

static struct isis_nexthop *
isis_nexthop_create(int family, const union g_addr *const ip, ifindex_t ifindex)
{
	struct isis_nexthop *nexthop;

	nexthop = XCALLOC(MTYPE_ISIS_NEXTHOP, sizeof(struct isis_nexthop));

	nexthop->family = family;
	nexthop->ifindex = ifindex;
	nexthop->ip = *ip;

	return nexthop;
}

static struct isis_nexthop *
isis_nexthop_dup(const struct isis_nexthop *const orig)
{
	struct isis_nexthop *nexthop;

	nexthop = isis_nexthop_create(orig->family, &orig->ip, orig->ifindex);
	memcpy(nexthop->sysid, orig->sysid, ISIS_SYS_ID_LEN);
	nexthop->sr = orig->sr;
	nexthop->label_stack = label_stack_dup(orig->label_stack);

	return nexthop;
}

void isis_nexthop_delete(struct isis_nexthop *nexthop)
{
	XFREE(MTYPE_ISIS_NEXTHOP_LABELS, nexthop->label_stack);
	XFREE(MTYPE_ISIS_NEXTHOP, nexthop);
}

static struct list *isis_nexthop_list_dup(const struct list *orig)
{
	struct list *copy;
	struct listnode *node;
	struct isis_nexthop *nh;
	struct isis_nexthop *nhcopy;

	copy = list_new();
	for (ALL_LIST_ELEMENTS_RO(orig, node, nh)) {
		nhcopy = isis_nexthop_dup(nh);
		listnode_add(copy, nhcopy);
	}
	return copy;
}

static struct isis_nexthop *nexthoplookup(struct list *nexthops, int family,
					  union g_addr *ip, ifindex_t ifindex)
{
	struct listnode *node;
	struct isis_nexthop *nh;

	for (ALL_LIST_ELEMENTS_RO(nexthops, node, nh)) {
		if (nh->ifindex != ifindex)
			continue;

		/* if the IP is unspecified, return the first nexthop found on
		 * the interface
		 */
		if (!ip)
			return nh;

		if (nh->family != family)
			continue;

		switch (family) {
		case AF_INET:
			if (IPV4_ADDR_CMP(&nh->ip.ipv4, &ip->ipv4))
				continue;
			break;
		case AF_INET6:
			if (IPV6_ADDR_CMP(&nh->ip.ipv6, &ip->ipv6))
				continue;
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address family [%d]", __func__,
				 family);
			exit(1);
		}

		return nh;
	}

	return NULL;
}

void adjinfo2nexthop(int family, struct list *nexthops,
		     struct isis_adjacency *adj, struct isis_sr_psid_info *sr,
		     struct mpls_label_stack *label_stack)
{
	struct isis_nexthop *nh;
	union g_addr ip = {};

	switch (family) {
	case AF_INET:
		for (unsigned int i = 0; i < adj->ipv4_address_count; i++) {
			ip.ipv4 = adj->ipv4_addresses[i];

			if (!nexthoplookup(nexthops, AF_INET, &ip,
					   adj->circuit->interface->ifindex)) {
				nh = isis_nexthop_create(
					AF_INET, &ip,
					adj->circuit->interface->ifindex);
				memcpy(nh->sysid, adj->sysid, sizeof(nh->sysid));
				if (sr)
					nh->sr = *sr;
				nh->label_stack = label_stack;
				listnode_add(nexthops, nh);
				break;
			}
		}
		break;
	case AF_INET6:
		for (unsigned int i = 0; i < adj->ll_ipv6_count; i++) {
			ip.ipv6 = adj->ll_ipv6_addrs[i];

			if (!nexthoplookup(nexthops, AF_INET6, &ip,
					   adj->circuit->interface->ifindex)) {
				nh = isis_nexthop_create(
					AF_INET6, &ip,
					adj->circuit->interface->ifindex);
				memcpy(nh->sysid, adj->sysid, sizeof(nh->sysid));
				if (sr)
					nh->sr = *sr;
				nh->label_stack = label_stack;
				listnode_add(nexthops, nh);
				break;
			}
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown address family [%d]",
			 __func__, family);
		exit(1);
	}
}

static void isis_route_add_dummy_nexthops(struct isis_route_info *rinfo,
					  const uint8_t *sysid,
					  struct isis_sr_psid_info *sr,
					  struct mpls_label_stack *label_stack)
{
	struct isis_nexthop *nh;

	nh = XCALLOC(MTYPE_ISIS_NEXTHOP, sizeof(struct isis_nexthop));
	memcpy(nh->sysid, sysid, sizeof(nh->sysid));
	nh->sr = *sr;
	nh->label_stack = label_stack;
	listnode_add(rinfo->nexthops, nh);
}

static struct isis_route_info *
isis_route_info_new(struct prefix *prefix, struct prefix_ipv6 *src_p,
		    uint32_t cost, uint32_t depth, struct isis_sr_psid_info *sr,
		    struct list *adjacencies, bool allow_ecmp)
{
	struct isis_route_info *rinfo;
	struct isis_vertex_adj *vadj;
	struct listnode *node;

	rinfo = XCALLOC(MTYPE_ISIS_ROUTE_INFO, sizeof(struct isis_route_info));

	rinfo->nexthops = list_new();
	for (ALL_LIST_ELEMENTS_RO(adjacencies, node, vadj)) {
		struct isis_spf_adj *sadj = vadj->sadj;
		struct isis_adjacency *adj = sadj->adj;
		struct isis_sr_psid_info *sr = &vadj->sr;
		struct mpls_label_stack *label_stack = vadj->label_stack;

		/*
		 * Create dummy nexthops when running SPF on a testing
		 * environment.
		 */
		if (CHECK_FLAG(im->options, F_ISIS_UNIT_TEST)) {
			isis_route_add_dummy_nexthops(rinfo, sadj->id, sr,
						      label_stack);
			if (!allow_ecmp)
				break;
			continue;
		}

		/* check for force resync this route */
		if (CHECK_FLAG(adj->circuit->flags,
			       ISIS_CIRCUIT_FLAPPED_AFTER_SPF))
			SET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC);

		adjinfo2nexthop(prefix->family, rinfo->nexthops, adj, sr,
				label_stack);
		if (!allow_ecmp)
			break;
	}

	rinfo->cost = cost;
	rinfo->depth = depth;
	rinfo->sr_algo[sr->algorithm] = *sr;
	rinfo->sr_algo[sr->algorithm].nexthops = rinfo->nexthops;
	rinfo->sr_algo[sr->algorithm].nexthops_backup =
		rinfo->backup ? rinfo->backup->nexthops : NULL;

	return rinfo;
}

static void isis_route_info_delete(struct isis_route_info *route_info)
{
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (!route_info->sr_algo[i].present)
			continue;

		if (route_info->sr_algo[i].nexthops == route_info->nexthops)
			continue;

		route_info->sr_algo[i].nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&route_info->sr_algo[i].nexthops);
	}

	if (route_info->nexthops) {
		route_info->nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&route_info->nexthops);
	}

	XFREE(MTYPE_ISIS_ROUTE_INFO, route_info);
}

void isis_route_node_cleanup(struct route_table *table, struct route_node *node)
{
	if (node->info)
		isis_route_info_delete(node->info);
}

struct isis_route_table_info *isis_route_table_info_alloc(uint8_t algorithm)
{
	struct isis_route_table_info *info;

	info = XCALLOC(MTYPE_ISIS_ROUTE_TABLE_INFO, sizeof(*info));
	info->algorithm = algorithm;
	return info;
}

void isis_route_table_info_free(void *info)
{
	XFREE(MTYPE_ISIS_ROUTE_TABLE_INFO, info);
}

uint8_t isis_route_table_algorithm(const struct route_table *table)
{
	const struct isis_route_table_info *info = table->info;

	return info ? info->algorithm : 0;
}

static bool isis_sr_psid_info_same(struct isis_sr_psid_info *new,
				   struct isis_sr_psid_info *old)
{
	if (new->present != old->present)
		return false;

	if (new->label != old->label)
		return false;

	if (new->sid.flags != old->sid.flags
	    || new->sid.value != old->sid.value)
		return false;

	if (new->sid.algorithm != old->sid.algorithm)
		return false;

	return true;
}

static bool isis_label_stack_same(struct mpls_label_stack *new,
				  struct mpls_label_stack *old)
{
	if (!new && !old)
		return true;
	if (!new || !old)
		return false;
	if (new->num_labels != old->num_labels)
		return false;
	if (memcmp(&new->label, &old->label,
		   sizeof(mpls_label_t) * new->num_labels))
		return false;

	return true;
}

static int isis_route_info_same(struct isis_route_info *new,
				struct isis_route_info *old, char *buf,
				size_t buf_size)
{
	struct listnode *node;
	struct isis_nexthop *new_nh, *old_nh;

	if (new->cost != old->cost) {
		if (buf)
			snprintf(buf, buf_size, "cost (old: %u, new: %u)",
				 old->cost, new->cost);
		return 0;
	}

	if (new->depth != old->depth) {
		if (buf)
			snprintf(buf, buf_size, "depth (old: %u, new: %u)",
				 old->depth, new->depth);
		return 0;
	}

	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		struct isis_sr_psid_info new_sr_algo;
		struct isis_sr_psid_info old_sr_algo;

		new_sr_algo = new->sr_algo[i];
		old_sr_algo = old->sr_algo[i];

		if (!isis_sr_psid_info_same(&new_sr_algo, &old_sr_algo)) {
			if (buf)
				snprintf(
					buf, buf_size,
					"SR input label algo-%u (old: %s, new: %s)",
					i, old_sr_algo.present ? "yes" : "no",
					new_sr_algo.present ? "yes" : "no");
			return 0;
		}
	}

	if (new->nexthops->count != old->nexthops->count) {
		if (buf)
			snprintf(buf, buf_size, "nhops num (old: %u, new: %u)",
				 old->nexthops->count, new->nexthops->count);
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(new->nexthops, node, new_nh)) {
		old_nh = nexthoplookup(old->nexthops, new_nh->family,
				       &new_nh->ip, new_nh->ifindex);
		if (!old_nh) {
			if (buf)
				snprintf(buf, buf_size,
					 "new nhop"); /* TODO: print nhop */
			return 0;
		}
		if (!isis_sr_psid_info_same(&new_nh->sr, &old_nh->sr)) {
			if (buf)
				snprintf(buf, buf_size, "nhop SR label");
			return 0;
		}
		if (!isis_label_stack_same(new_nh->label_stack,
					   old_nh->label_stack)) {
			if (buf)
				snprintf(buf, buf_size, "nhop label stack");
			return 0;
		}
	}

	/* only the resync flag needs to be checked */
	if (CHECK_FLAG(new->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC)
	    != CHECK_FLAG(old->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC)) {
		if (buf)
			snprintf(buf, buf_size, "resync flag");
		return 0;
	}

	return 1;
}

struct isis_route_info *
isis_route_create(struct prefix *prefix, struct prefix_ipv6 *src_p,
		  uint32_t cost, uint32_t depth, struct isis_sr_psid_info *sr,
		  struct list *adjacencies, bool allow_ecmp,
		  struct isis_area *area, struct route_table *table)
{
	struct route_node *route_node;
	struct isis_route_info *rinfo_new, *rinfo_old, *route_info = NULL;
	char change_buf[64];

	if (!table)
		return NULL;

	rinfo_new = isis_route_info_new(prefix, src_p, cost, depth, sr,
					adjacencies, allow_ecmp);
	route_node = srcdest_rnode_get(table, prefix, src_p);

	rinfo_old = route_node->info;
	if (!rinfo_old) {
		if (IS_DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte (%s) route created: %pFX",
				   area->area_tag, prefix);
		route_info = rinfo_new;
		UNSET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
	} else {
		route_unlock_node(route_node);
#ifdef EXTREME_DEBUG
		if (IS_DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte (%s) route already exists: %pFX",
				   area->area_tag, prefix);
#endif /* EXTREME_DEBUG */
		if (isis_route_info_same(rinfo_new, rinfo_old, change_buf,
					 sizeof(change_buf))) {
#ifdef EXTREME_DEBUG
			if (IS_DEBUG_RTE_EVENTS)
				zlog_debug(
					"ISIS-Rte (%s) route unchanged: %pFX",
					area->area_tag, prefix);
#endif /* EXTREME_DEBUG */
			isis_route_info_delete(rinfo_new);
			route_info = rinfo_old;
		} else {
			if (IS_DEBUG_RTE_EVENTS)
				zlog_debug(
					"ISIS-Rte (%s): route changed: %pFX, change: %s",
					area->area_tag, prefix, change_buf);
			for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
				rinfo_new->sr_algo_previous[i] =
					rinfo_old->sr_algo[i];
			isis_route_info_delete(rinfo_old);
			route_info = rinfo_new;
			UNSET_FLAG(route_info->flag,
				   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		}
	}

	SET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE);
	route_node->info = route_info;

	return route_info;
}

void isis_route_delete(struct isis_area *area, struct route_node *rode,
		       struct route_table *table)
{
	struct isis_route_info *rinfo;
	char buff[SRCDEST2STR_BUFFER];
	struct prefix *prefix;
	struct prefix_ipv6 *src_p;

	/* for log */
	srcdest_rnode2str(rode, buff, sizeof(buff));

	srcdest_rnode_prefixes(rode, (const struct prefix **)&prefix,
			       (const struct prefix **)&src_p);

	rinfo = rode->info;
	if (rinfo == NULL) {
		if (IS_DEBUG_RTE_EVENTS)
			zlog_debug(
				"ISIS-Rte: tried to delete non-existent route %s",
				buff);
		return;
	}

	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED)) {
		UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
		if (IS_DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte: route delete  %s", buff);
		isis_route_update(area, prefix, src_p, rinfo);
	}
	isis_route_info_delete(rinfo);
	rode->info = NULL;
	route_unlock_node(rode);
}

static void isis_route_remove_previous_sid(struct isis_area *area,
					   struct prefix *prefix,
					   struct isis_route_info *route_info)
{
	/*
	 * Explicitly uninstall previous Prefix-SID label if it has
	 * changed or was removed.
	 */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (route_info->sr_algo_previous[i].present &&
		    (!route_info->sr_algo[i].present ||
		     route_info->sr_algo_previous[i].label !=
			     route_info->sr_algo[i].label))
			isis_zebra_prefix_sid_uninstall(
				area, prefix, route_info,
				&route_info->sr_algo_previous[i]);
	}
}

static void set_merge_route_info_sr_algo(struct isis_route_info *mrinfo,
					 struct isis_route_info *rinfo)
{
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (rinfo->sr_algo[i].present) {
			assert(i == rinfo->sr_algo[i].algorithm);
			assert(rinfo->nexthops);
			assert(rinfo->backup ? rinfo->backup->nexthops != NULL
					     : true);

			if (mrinfo->sr_algo[i].nexthops != NULL &&
			    mrinfo->sr_algo[i].nexthops != mrinfo->nexthops) {
				mrinfo->sr_algo[i].nexthops->del =
					(void (*)(void *))isis_nexthop_delete;
				list_delete(&mrinfo->sr_algo[i].nexthops);
			}

			mrinfo->sr_algo[i] = rinfo->sr_algo[i];
			mrinfo->sr_algo[i].nexthops = isis_nexthop_list_dup(
				rinfo->sr_algo[i].nexthops);
		}
	}

	UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
	UNSET_FLAG(mrinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
}

static void isis_route_update(struct isis_area *area, struct prefix *prefix,
			      struct prefix_ipv6 *src_p,
			      struct isis_route_info *route_info)
{
	if (area == NULL)
		return;

	if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE)) {
		if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
			return;

		isis_route_remove_previous_sid(area, prefix, route_info);

		/* Install route. */
		isis_zebra_route_add_route(area->isis, prefix, src_p,
					   route_info);

		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
			struct isis_sr_psid_info sr_algo;

			sr_algo = route_info->sr_algo[i];

			/*
			 * Install/reinstall Prefix-SID label.
			 */
			if (sr_algo.present)
				isis_zebra_prefix_sid_install(area, prefix,
							      &sr_algo);

			hook_call(isis_route_update_hook, area, prefix,
				  route_info);
		}

		hook_call(isis_route_update_hook, area, prefix, route_info);

		SET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		UNSET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
	} else {
		/* Uninstall Prefix-SID label. */
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
			if (route_info->sr_algo[i].present)
				isis_zebra_prefix_sid_uninstall(
					area, prefix, route_info,
					&route_info->sr_algo[i]);

		/* Uninstall route. */
		isis_zebra_route_del_route(area->isis, prefix, src_p,
					   route_info);
		hook_call(isis_route_update_hook, area, prefix, route_info);

		UNSET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
	}
}

static void _isis_route_verify_table(struct isis_area *area,
				     struct route_table *table,
				     struct route_table *table_backup,
				     struct route_table **tables)
{
	struct route_node *rnode, *drnode;
	struct isis_route_info *rinfo;
#ifdef EXTREME_DEBUG
	char buff[SRCDEST2STR_BUFFER];
#endif /* EXTREME_DEBUG */
	uint8_t algorithm = isis_route_table_algorithm(table);

	for (rnode = route_top(table); rnode;
	     rnode = srcdest_route_next(rnode)) {
		if (rnode->info == NULL)
			continue;
		rinfo = rnode->info;

		struct prefix *dst_p;
		struct prefix_ipv6 *src_p;

		srcdest_rnode_prefixes(rnode,
				       (const struct prefix **)&dst_p,
				       (const struct prefix **)&src_p);

		/* Link primary route to backup route. */
		if (table_backup) {
			struct route_node *rnode_bck;

			rnode_bck = srcdest_rnode_lookup(table_backup, dst_p,
							 src_p);
			if (rnode_bck) {
				rinfo->backup = rnode_bck->info;
				rinfo->sr_algo[algorithm].nexthops_backup =
					rinfo->backup->nexthops;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			} else if (rinfo->backup) {
				rinfo->backup = NULL;
				rinfo->sr_algo[algorithm].nexthops_backup =
					NULL;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			}
		}

#ifdef EXTREME_DEBUG
		if (IS_DEBUG_RTE_EVENTS) {
			srcdest2str(dst_p, src_p, buff, sizeof(buff));
			zlog_debug(
				"ISIS-Rte (%s): route validate: %s %s %s %s",
				area->area_tag,
				(CHECK_FLAG(rinfo->flag,
					    ISIS_ROUTE_FLAG_ZEBRA_SYNCED)
					 ? "synced"
					 : "not-synced"),
				(CHECK_FLAG(rinfo->flag,
					    ISIS_ROUTE_FLAG_ZEBRA_RESYNC)
					 ? "resync"
					 : "not-resync"),
				(CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE)
					 ? "active"
					 : "inactive"),
				buff);
		}
#endif /* EXTREME_DEBUG */

		isis_route_update(area, dst_p, src_p, rinfo);

		if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE))
			continue;

		/* In case the verify is not for a merge, we use a single table
		 * directly for
		 * validating => no problems with deleting routes. */
		if (!tables) {
			isis_route_delete(area, rnode, table);
			continue;
		}

		/* If we work on a merged table,
		 * therefore we must
		 * delete node from each table as well before deleting
		 * route info. */
		for (int i = 0; tables[i]; i++) {
			drnode = srcdest_rnode_lookup(tables[i], dst_p, src_p);
			if (!drnode)
				continue;

			route_unlock_node(drnode);

			if (drnode->info != rnode->info)
				continue;

			drnode->info = NULL;
			route_unlock_node(drnode);
		}

		isis_route_delete(area, rnode, table);
	}
}

static void _isis_route_verify_merge(struct isis_area *area,
				     struct route_table **tables,
				     struct route_table **tables_backup,
				     int tree);

void isis_route_verify_table(struct isis_area *area, struct route_table *table,
			     struct route_table *table_backup, int tree)
{
	struct route_table *tables[SR_ALGORITHM_COUNT] = {table};
	struct route_table *tables_backup[SR_ALGORITHM_COUNT] = {table_backup};
#ifndef FABRICD
	int tables_next = 1;
	int level = area->is_type == IS_LEVEL_1 ? ISIS_LEVEL1 : ISIS_LEVEL2;
	struct listnode *node;
	struct flex_algo *fa;
	struct isis_flex_algo_data *data;

	for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, node, fa)) {
		data = fa->data;
		tables[tables_next] =
			data->spftree[tree][level - 1]->route_table;
		tables_backup[tables_next] =
			data->spftree[tree][level - 1]->route_table_backup;
		_isis_route_verify_table(area, tables[tables_next],
					 tables_backup[tables_next], NULL);
		tables_next++;
	}
#endif /* ifndef FABRICD */

	_isis_route_verify_merge(area, tables, tables_backup, tree);
}

/* Function to validate route tables for L1L2 areas. In this case we can't use
 * level route tables directly, we have to merge them at first. L1 routes are
 * preferred over the L2 ones.
 *
 * Merge algorithm is trivial (at least for now). All L1 paths are copied into
 * merge table at first, then L2 paths are added if L1 path for same prefix
 * doesn't already exists there.
 *
 * FIXME: Is it right place to do it at all? Maybe we should push both levels
 * to the RIB with different zebra route types and let RIB handle this? */
void isis_route_verify_merge(struct isis_area *area,
			     struct route_table *level1_table,
			     struct route_table *level1_table_backup,
			     struct route_table *level2_table,
			     struct route_table *level2_table_backup, int tree)
{
	struct route_table *tables[] = {level1_table, level2_table, NULL};
	struct route_table *tables_backup[] = {level1_table_backup,
					       level2_table_backup, NULL};
	_isis_route_verify_merge(area, tables, tables_backup, tree);
}

static void _isis_route_verify_merge(struct isis_area *area,
				     struct route_table **tables,
				     struct route_table **tables_backup,
				     int tree)
{
	struct route_table *merge;
	struct route_node *rnode, *mrnode;

	merge = srcdest_table_init();

	for (int i = 0; tables[i]; i++) {
		uint8_t algorithm = isis_route_table_algorithm(tables[i]);
		for (rnode = route_top(tables[i]); rnode;
		     rnode = srcdest_route_next(rnode)) {
			struct isis_route_info *rinfo = rnode->info;
			struct route_node *rnode_bck;

			if (!rinfo)
				continue;

			struct prefix *prefix;
			struct prefix_ipv6 *src_p;

			srcdest_rnode_prefixes(rnode,
					       (const struct prefix **)&prefix,
					       (const struct prefix **)&src_p);

			/* Link primary route to backup route. */
			rnode_bck = srcdest_rnode_lookup(tables_backup[i],
							 prefix, src_p);
			if (rnode_bck) {
				rinfo->backup = rnode_bck->info;
				rinfo->sr_algo[algorithm].nexthops_backup =
					rinfo->backup->nexthops;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			} else if (rinfo->backup) {
				rinfo->backup = NULL;
				rinfo->sr_algo[algorithm].nexthops_backup =
					NULL;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			}

			mrnode = srcdest_rnode_get(merge, prefix, src_p);
			struct isis_route_info *mrinfo = mrnode->info;
			if (mrinfo) {
				route_unlock_node(mrnode);
				set_merge_route_info_sr_algo(mrinfo, rinfo);

				if (CHECK_FLAG(mrinfo->flag,
					       ISIS_ROUTE_FLAG_ACTIVE)) {
					/* Clear the ZEBRA_SYNCED flag on the
					 * L2 route when L1 wins, otherwise L2
					 * won't get reinstalled when L1
					 * disappears.
					 */
					UNSET_FLAG(
						rinfo->flag,
						ISIS_ROUTE_FLAG_ZEBRA_SYNCED
					);
					continue;
				} else if (CHECK_FLAG(rinfo->flag,
						      ISIS_ROUTE_FLAG_ACTIVE)) {
					/* Clear the ZEBRA_SYNCED flag on the L1
					 * route when L2 wins, otherwise L1
					 * won't get reinstalled when it
					 * reappears.
					 */
					UNSET_FLAG(
						mrinfo->flag,
						ISIS_ROUTE_FLAG_ZEBRA_SYNCED
					);
				} else if (
					CHECK_FLAG(
						mrinfo->flag,
						ISIS_ROUTE_FLAG_ZEBRA_SYNCED)) {
					continue;
				}
			} else {
				mrnode->info = rnode->info;
			}
		}
	}

	_isis_route_verify_table(area, merge, NULL, tables);
	route_table_finish(merge);
}

void isis_route_invalidate_table(struct isis_area *area,
				 struct route_table *table)
{
	struct route_node *rode;
	struct isis_route_info *rinfo;
	uint8_t algorithm = isis_route_table_algorithm(table);
	for (rode = route_top(table); rode; rode = srcdest_route_next(rode)) {
		if (rode->info == NULL)
			continue;
		rinfo = rode->info;

		if (rinfo->backup) {
			rinfo->backup = NULL;
			rinfo->sr_algo[algorithm].nexthops_backup = NULL;
			/*
			 * For now, always force routes that have backup
			 * nexthops to be reinstalled.
			 */
			UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		}
		UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
	}
}

void isis_route_switchover_nexthop(struct isis_area *area,
				   struct route_table *table, int family,
				   union g_addr *nexthop_addr,
				   ifindex_t ifindex)
{
	const char *ifname = NULL, *vrfname = NULL;
	struct isis_route_info *rinfo;
	struct prefix_ipv6 *src_p;
	struct route_node *rnode;
	vrf_id_t vrf_id;
	struct prefix *prefix;

	if (IS_DEBUG_EVENTS) {
		if (area && area->isis) {
			vrf_id = area->isis->vrf_id;
			vrfname = vrf_id_to_name(vrf_id);
			ifname = ifindex2ifname(ifindex, vrf_id);
		}
		zlog_debug("%s: initiating fast-reroute %s on VRF %s iface %s",
			   __func__, family2str(family), vrfname ? vrfname : "",
			   ifname ? ifname : "");
	}

	for (rnode = route_top(table); rnode;
	     rnode = srcdest_route_next(rnode)) {
		if (!rnode->info)
			continue;
		rinfo = rnode->info;

		if (!rinfo->backup)
			continue;

		if (!nexthoplookup(rinfo->nexthops, family, nexthop_addr,
				   ifindex))
			continue;

		srcdest_rnode_prefixes(rnode, (const struct prefix **)&prefix,
				       (const struct prefix **)&src_p);

		/* Switchover route. */
		isis_route_remove_previous_sid(area, prefix, rinfo);
		UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		isis_route_update(area, prefix, src_p, rinfo->backup);

		isis_route_info_delete(rinfo);

		rnode->info = NULL;
		route_unlock_node(rnode);
	}
}
