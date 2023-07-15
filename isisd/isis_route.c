/*
 * IS-IS Rout(e)ing protocol               - isis_route.c
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
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

DEFINE_MTYPE_STATIC(ISISD, ISIS_NEXTHOP,    "ISIS nexthop");
DEFINE_MTYPE_STATIC(ISISD, ISIS_ROUTE_INFO, "ISIS route info");

DEFINE_HOOK(isis_route_update_hook,
	    (struct isis_area * area, struct prefix *prefix,
	     struct isis_route_info *route_info),
	    (area, prefix, route_info));

static struct isis_nexthop *nexthoplookup(struct list *nexthops, int family,
					  union g_addr *ip, ifindex_t ifindex);
static void isis_route_update(struct isis_area *area, struct prefix *prefix,
			      struct prefix_ipv6 *src_p,
			      struct isis_route_info *route_info);

static struct isis_nexthop *isis_nexthop_create(int family, union g_addr *ip,
						ifindex_t ifindex)
{
	struct isis_nexthop *nexthop;

	nexthop = XCALLOC(MTYPE_ISIS_NEXTHOP, sizeof(struct isis_nexthop));

	nexthop->family = family;
	nexthop->ifindex = ifindex;
	nexthop->ip = *ip;

	return nexthop;
}

void isis_nexthop_delete(struct isis_nexthop *nexthop)
{
	XFREE(MTYPE_ISIS_NEXTHOP_LABELS, nexthop->label_stack);
	XFREE(MTYPE_ISIS_NEXTHOP, nexthop);
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

		/* update neighbor router address */
		switch (prefix->family) {
		case AF_INET:
			if (depth == 2 && prefix->prefixlen == IPV4_MAX_BITLEN)
				adj->router_address = prefix->u.prefix4;
			break;
		case AF_INET6:
			if (depth == 2 && prefix->prefixlen == IPV6_MAX_BITLEN
			    && (!src_p || !src_p->prefixlen)) {
				adj->router_address6 = prefix->u.prefix6;
			}
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address family [%d]", __func__,
				 prefix->family);
			exit(1);
		}
		adjinfo2nexthop(prefix->family, rinfo->nexthops, adj, sr,
				label_stack);
		if (!allow_ecmp)
			break;
	}

	rinfo->cost = cost;
	rinfo->depth = depth;
	rinfo->sr = *sr;

	return rinfo;
}

static void isis_route_info_delete(struct isis_route_info *route_info)
{
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

	if (!isis_sr_psid_info_same(&new->sr, &old->sr)) {
		if (buf)
			snprintf(buf, buf_size, "SR input label");
		return 0;
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
			rinfo_new->sr_previous = rinfo_old->sr;
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
	if (route_info->sr_previous.present &&
	    (!route_info->sr.present ||
	     route_info->sr_previous.label != route_info->sr.label))
		isis_zebra_prefix_sid_uninstall(area, prefix, route_info,
						&route_info->sr_previous);
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
		/* Install/reinstall Prefix-SID label. */
		if (route_info->sr.present)
			isis_zebra_prefix_sid_install(area, prefix, route_info,
						      &route_info->sr);
		hook_call(isis_route_update_hook, area, prefix, route_info);

		SET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		UNSET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
	} else {
		/* Uninstall Prefix-SID label. */
		if (route_info->sr.present)
			isis_zebra_prefix_sid_uninstall(
				area, prefix, route_info, &route_info->sr);
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
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			} else if (rinfo->backup) {
				rinfo->backup = NULL;
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

		/* Area is either L1 or L2 => we use level route tables
		 * directly for
		 * validating => no problems with deleting routes. */
		if (!tables) {
			isis_route_delete(area, rnode, table);
			continue;
		}

		/* If area is L1L2, we work with merge table and
		 * therefore must
		 * delete node from level tables as well before deleting
		 * route info. */
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			drnode = srcdest_rnode_lookup(tables[level - 1],
						      dst_p, src_p);
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

void isis_route_verify_table(struct isis_area *area, struct route_table *table,
			     struct route_table *table_backup)
{
	_isis_route_verify_table(area, table, table_backup, NULL);
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
			     struct route_table *level2_table_backup)
{
	struct route_table *tables[] = {level1_table, level2_table};
	struct route_table *tables_backup[] = {level1_table_backup,
					       level2_table_backup};
	struct route_table *merge;
	struct route_node *rnode, *mrnode;

	merge = srcdest_table_init();

	for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		for (rnode = route_top(tables[level - 1]); rnode;
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
			rnode_bck = srcdest_rnode_lookup(
				tables_backup[level - 1], prefix, src_p);
			if (rnode_bck) {
				rinfo->backup = rnode_bck->info;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			} else if (rinfo->backup) {
				rinfo->backup = NULL;
				UNSET_FLAG(rinfo->flag,
					   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
			}

			mrnode = srcdest_rnode_get(merge, prefix, src_p);
			struct isis_route_info *mrinfo = mrnode->info;
			if (mrinfo) {
				route_unlock_node(mrnode);
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
			}
			mrnode->info = rnode->info;
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
	for (rode = route_top(table); rode; rode = srcdest_route_next(rode)) {
		if (rode->info == NULL)
			continue;
		rinfo = rode->info;

		if (rinfo->backup) {
			rinfo->backup = NULL;
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
