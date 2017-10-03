/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/json.h"
#include "log.h"
#include "network.h"
#include "if.h"
#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vty.h"
#include "vrf.h"
#include "plist.h"
#include "nexthop.h"
#include "table.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_str.h"
#include "pim_rpf.h"
#include "pim_sock.h"
#include "pim_memory.h"
#include "pim_iface.h"
#include "pim_msdp.h"
#include "pim_nht.h"


/* Cleanup pim->rpf_hash each node data */
void pim_rp_list_hash_clean(void *data)
{
	struct pim_nexthop_cache *pnc = (struct pim_nexthop_cache *)data;

	list_delete_and_null(&pnc->rp_list);

	hash_clean(pnc->upstream_hash, NULL);
	hash_free(pnc->upstream_hash);
	pnc->upstream_hash = NULL;

	XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
}

static void pim_rp_info_free(struct rp_info *rp_info)
{
	XFREE(MTYPE_PIM_RP, rp_info);
}

int pim_rp_list_cmp(void *v1, void *v2)
{
	struct rp_info *rp1 = (struct rp_info *)v1;
	struct rp_info *rp2 = (struct rp_info *)v2;

	/*
	 * Sort by RP IP address
	 */
	if (rp1->rp.rpf_addr.u.prefix4.s_addr
	    < rp2->rp.rpf_addr.u.prefix4.s_addr)
		return -1;

	if (rp1->rp.rpf_addr.u.prefix4.s_addr
	    > rp2->rp.rpf_addr.u.prefix4.s_addr)
		return 1;

	/*
	 * Sort by group IP address
	 */
	if (rp1->group.u.prefix4.s_addr < rp2->group.u.prefix4.s_addr)
		return -1;

	if (rp1->group.u.prefix4.s_addr > rp2->group.u.prefix4.s_addr)
		return 1;

	return 0;
}

void pim_rp_init(struct pim_instance *pim)
{
	struct rp_info *rp_info;
	struct route_node *rn;

	pim->rp_list = list_new();
	if (!pim->rp_list) {
		zlog_err("Unable to alloc rp_list");
		return;
	}
	pim->rp_list->del = (void (*)(void *))pim_rp_info_free;
	pim->rp_list->cmp = pim_rp_list_cmp;

	pim->rp_table = route_table_init();
	if (!pim->rp_table) {
		zlog_err("Unable to alloc rp_table");
		list_delete_and_null(&pim->rp_list);
		return;
	}

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));

	if (!rp_info) {
		zlog_err("Unable to alloc rp_info");
		route_table_finish(pim->rp_table);
		list_delete_and_null(&pim->rp_list);
		return;
	}

	if (!str2prefix("224.0.0.0/4", &rp_info->group)) {
		zlog_err("Unable to convert 224.0.0.0/4 to prefix");
		list_delete_and_null(&pim->rp_list);
		route_table_finish(pim->rp_table);
		XFREE(MTYPE_PIM_RP, rp_info);
		return;
	}
	rp_info->group.family = AF_INET;
	rp_info->rp.rpf_addr.family = AF_INET;
	rp_info->rp.rpf_addr.prefixlen = IPV4_MAX_PREFIXLEN;
	rp_info->rp.rpf_addr.u.prefix4.s_addr = INADDR_NONE;

	listnode_add(pim->rp_list, rp_info);

	rn = route_node_get(pim->rp_table, &rp_info->group);
	if (!rn) {
		zlog_err("Failure to get route node for pim->rp_table");
		list_delete_and_null(&pim->rp_list);
		route_table_finish(pim->rp_table);
		XFREE(MTYPE_PIM_RP, rp_info);
		return;
	}

	rn->info = rp_info;
	if (PIM_DEBUG_TRACE)
		zlog_debug("Allocated: %p for rp_info: %p(224.0.0.0/4) Lock: %d",
			   rn, rp_info, rn->lock);
}

void pim_rp_free(struct pim_instance *pim)
{
	if (pim->rp_list)
		list_delete_and_null(&pim->rp_list);
}

/*
 * Given an RP's prefix-list, return the RP's rp_info for that prefix-list
 */
static struct rp_info *pim_rp_find_prefix_list(struct pim_instance *pim,
					       struct in_addr rp,
					       const char *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp.s_addr == rp_info->rp.rpf_addr.u.prefix4.s_addr
		    && rp_info->plist && strcmp(rp_info->plist, plist) == 0) {
			return rp_info;
		}
	}

	return NULL;
}

/*
 * Return true if plist is used by any rp_info
 */
static int pim_rp_prefix_list_used(struct pim_instance *pim, const char *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist && strcmp(rp_info->plist, plist) == 0) {
			return 1;
		}
	}

	return 0;
}

/*
 * Given an RP's address, return the RP's rp_info that is an exact match for
 * 'group'
 */
static struct rp_info *pim_rp_find_exact(struct pim_instance *pim,
					 struct in_addr rp,
					 struct prefix *group)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp.s_addr == rp_info->rp.rpf_addr.u.prefix4.s_addr
		    && prefix_same(&rp_info->group, group))
			return rp_info;
	}

	return NULL;
}

/*
 * Given a group, return the rp_info for that group
 */
static struct rp_info *pim_rp_find_match_group(struct pim_instance *pim,
					       struct prefix *group)
{
	struct listnode *node;
	struct rp_info *best = NULL;
	struct rp_info *rp_info;
	struct prefix_list *plist;
	struct prefix *p, *bp;
	struct route_node *rn;

	bp = NULL;
	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist) {
			plist = prefix_list_lookup(AFI_IP, rp_info->plist);

			if (prefix_list_apply_which_prefix(plist, &p, group) == PREFIX_DENY)
				continue;

			if (!best) {
				best = rp_info;
				bp = p;
				continue;
			}

			if (bp && bp->prefixlen < p->prefixlen) {
				best = rp_info;
				bp = p;
			}
		}
	}

	rn = route_node_match(pim->rp_table, group);
	if (!rn) {
		zlog_err("%s: BUG We should have found default group information\n",
			 __PRETTY_FUNCTION__);
		return best;
	}

	rp_info = rn->info;
	if (PIM_DEBUG_TRACE) {
		char buf[PREFIX_STRLEN];

		route_unlock_node(rn);
		zlog_debug("Lookedup: %p for rp_info: %p(%s) Lock: %d",
			   rn, rp_info,
			   prefix2str(&rp_info->group, buf, sizeof(buf)),
			   rn->lock);
	}

	if (!best)
		return rp_info;

	if (rp_info->group.prefixlen < best->group.prefixlen)
		best = rp_info;

	return best;
}

/*
 * When the user makes "ip pim rp" configuration changes or if they change the
 * prefix-list(s) used by these statements we must tickle the upstream state
 * for each group to make them re-lookup who their RP should be.
 *
 * This is a placeholder function for now.
 */
static void pim_rp_refresh_group_to_rp_mapping(struct pim_instance *pim)
{
	pim_msdp_i_am_rp_changed(pim);
}

void pim_rp_prefix_list_update(struct pim_instance *pim,
			       struct prefix_list *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;
	int refresh_needed = 0;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist
		    && strcmp(rp_info->plist, prefix_list_name(plist)) == 0) {
			refresh_needed = 1;
			break;
		}
	}

	if (refresh_needed)
		pim_rp_refresh_group_to_rp_mapping(pim);
}

static int pim_rp_check_interface_addrs(struct rp_info *rp_info,
					struct pim_interface *pim_ifp)
{
	struct listnode *node;
	struct pim_secondary_addr *sec_addr;

	if (pim_ifp->primary_address.s_addr
	    == rp_info->rp.rpf_addr.u.prefix4.s_addr)
		return 1;

	if (!pim_ifp->sec_addr_list) {
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->sec_addr_list, node, sec_addr)) {
		if (prefix_same(&sec_addr->addr, &rp_info->rp.rpf_addr)) {
			return 1;
		}
	}

	return 0;
}

static void pim_rp_check_interfaces(struct pim_instance *pim,
				    struct rp_info *rp_info)
{
	struct interface *ifp;

	rp_info->i_am_rp = 0;
	RB_FOREACH (ifp, if_name_head, &pim->vrf->ifaces_by_name) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			rp_info->i_am_rp = 1;
		}
	}
}

int pim_rp_new(struct pim_instance *pim, const char *rp,
	       const char *group_range, const char *plist)
{
	int result = 0;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	struct prefix group_all;
	struct listnode *node, *nnode;
	struct rp_info *tmp_rp_info;
	char buffer[BUFSIZ];
	struct prefix nht_p;
	struct pim_nexthop_cache pnc;
	struct route_node *rn;

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));
	if (!rp_info)
		return PIM_MALLOC_FAIL;

	if (group_range == NULL)
		result = str2prefix("224.0.0.0/4", &rp_info->group);
	else
		result = str2prefix(group_range, &rp_info->group);

	if (!result) {
		XFREE(MTYPE_PIM_RP, rp_info);
		return PIM_GROUP_BAD_ADDRESS;
	}

	rp_info->rp.rpf_addr.family = AF_INET;
	rp_info->rp.rpf_addr.prefixlen = IPV4_MAX_PREFIXLEN;
	result = inet_pton(rp_info->rp.rpf_addr.family, rp,
			   &rp_info->rp.rpf_addr.u.prefix4);

	if (result <= 0) {
		XFREE(MTYPE_PIM_RP, rp_info);
		return PIM_RP_BAD_ADDRESS;
	}

	if (plist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_prefix_list(pim, rp_info->rp.rpf_addr.u.prefix4,
					    plist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_SUCCESS;
		}

		/*
		 * Barf if the prefix-list is already configured for an RP
		 */
		if (pim_rp_prefix_list_used(pim, plist)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_RP_PFXLIST_IN_USE;
		}

		/*
		 * Free any existing rp_info entries for this RP
		 */
		for (ALL_LIST_ELEMENTS(pim->rp_list, node, nnode,
				       tmp_rp_info)) {
			if (rp_info->rp.rpf_addr.u.prefix4.s_addr
			    == tmp_rp_info->rp.rpf_addr.u.prefix4.s_addr) {
				if (tmp_rp_info->plist)
					pim_rp_del(pim, rp, NULL,
						   tmp_rp_info->plist);
				else
					pim_rp_del(
						pim, rp,
						prefix2str(&tmp_rp_info->group,
							   buffer, BUFSIZ),
						NULL);
			}
		}

		rp_info->plist = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist);
	} else {

		if (!str2prefix("224.0.0.0/4", &group_all)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_GROUP_BAD_ADDRESS;
		}
		rp_all = pim_rp_find_match_group(pim, &group_all);

		/*
		 * Barf if group is a non-multicast subnet
		 */
		if (!prefix_match(&rp_all->group, &rp_info->group)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_GROUP_BAD_ADDRESS;
		}

		/*
		 * Remove any prefix-list rp_info entries for this RP
		 */
		for (ALL_LIST_ELEMENTS(pim->rp_list, node, nnode,
				       tmp_rp_info)) {
			if (tmp_rp_info->plist
			    && rp_info->rp.rpf_addr.u.prefix4.s_addr
				       == tmp_rp_info->rp.rpf_addr.u.prefix4
						  .s_addr) {
				pim_rp_del(pim, rp, NULL, tmp_rp_info->plist);
			}
		}

		/*
		 * Take over the 224.0.0.0/4 group if the rp is INADDR_NONE
		 */
		if (prefix_same(&rp_all->group, &rp_info->group)
		    && pim_rpf_addr_is_inaddr_none(&rp_all->rp)) {
			rp_all->rp.rpf_addr = rp_info->rp.rpf_addr;
			XFREE(MTYPE_PIM_RP, rp_info);

			/* Register addr with Zebra NHT */
			nht_p.family = AF_INET;
			nht_p.prefixlen = IPV4_MAX_BITLEN;
			nht_p.u.prefix4 =
				rp_all->rp.rpf_addr.u.prefix4; // RP address
			if (PIM_DEBUG_PIM_NHT_RP) {
				char buf[PREFIX2STR_BUFFER];
				char buf1[PREFIX2STR_BUFFER];
				prefix2str(&nht_p, buf, sizeof(buf));
				prefix2str(&rp_all->group, buf1, sizeof(buf1));
				zlog_debug(
					"%s: NHT Register rp_all addr %s grp %s ",
					__PRETTY_FUNCTION__, buf, buf1);
			}
			memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
			if (pim_find_or_track_nexthop(pim, &nht_p, NULL, rp_all,
						      &pnc)) {
				if (!pim_ecmp_nexthop_search(
					    pim, &pnc,
					    &rp_all->rp.source_nexthop, &nht_p,
					    &rp_all->group, 1))
					return PIM_RP_NO_PATH;
			} else {
				if (pim_nexthop_lookup(
					    pim, &rp_all->rp.source_nexthop,
					    rp_all->rp.rpf_addr.u.prefix4, 1)
				    != 0)
					return PIM_RP_NO_PATH;
			}
			pim_rp_check_interfaces(pim, rp_all);
			pim_rp_refresh_group_to_rp_mapping(pim);
			return PIM_SUCCESS;
		}

		/*
		 * Return if the group is already configured for this RP
		 */
		if (pim_rp_find_exact(pim, rp_info->rp.rpf_addr.u.prefix4,
				      &rp_info->group)) {
			XFREE(MTYPE_PIM_RP, rp_info);
			return PIM_SUCCESS;
		}

		/*
		 * Barf if this group is already covered by some other RP
		 */
		tmp_rp_info = pim_rp_find_match_group(pim, &rp_info->group);

		if (tmp_rp_info) {
			if (tmp_rp_info->plist) {
				XFREE(MTYPE_PIM_RP, rp_info);
				return PIM_GROUP_PFXLIST_OVERLAP;
			} else {
				/*
				 * If the only RP that covers this group is an
				 * RP configured for
				 * 224.0.0.0/4 that is fine, ignore that one.
				 * For all others
				 * though we must return PIM_GROUP_OVERLAP
				 */
				if (prefix_same(&rp_info->group,
						&tmp_rp_info->group)) {
					XFREE(MTYPE_PIM_RP, rp_info);
					return PIM_GROUP_OVERLAP;
				}
			}
		}
	}

	listnode_add_sort(pim->rp_list, rp_info);
	rn = route_node_get(pim->rp_table, &rp_info->group);
	if (!rn) {
		char buf[PREFIX_STRLEN];
		zlog_err("Failure to get route node for pim->rp_table: %s",
			 prefix2str(&rp_info->group, buf, sizeof(buf)));
		return PIM_MALLOC_FAIL;
	}
	rn->info = rp_info;

	if (PIM_DEBUG_TRACE) {
		char buf[PREFIX_STRLEN];

		zlog_debug("Allocated: %p for rp_info: %p(%s) Lock: %d",
			   rn, rp_info,
			   prefix2str(&rp_info->group, buf, sizeof(buf)),
			   rn->lock);
	}

	/* Register addr with Zebra NHT */
	nht_p.family = AF_INET;
	nht_p.prefixlen = IPV4_MAX_BITLEN;
	nht_p.u.prefix4 = rp_info->rp.rpf_addr.u.prefix4;
	if (PIM_DEBUG_PIM_NHT_RP) {
		char buf[PREFIX2STR_BUFFER];
		char buf1[PREFIX2STR_BUFFER];
		prefix2str(&nht_p, buf, sizeof(buf));
		prefix2str(&rp_info->group, buf1, sizeof(buf1));
		zlog_debug("%s: NHT Register RP addr %s grp %s with Zebra ",
			   __PRETTY_FUNCTION__, buf, buf1);
	}

	memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
	if (pim_find_or_track_nexthop(pim, &nht_p, NULL, rp_info, &pnc)) {
		if (!pim_ecmp_nexthop_search(pim, &pnc,
					     &rp_info->rp.source_nexthop,
					     &nht_p, &rp_info->group, 1))
			return PIM_RP_NO_PATH;
	} else {
		if (pim_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
				       rp_info->rp.rpf_addr.u.prefix4, 1)
		    != 0)
			return PIM_RP_NO_PATH;
	}

	pim_rp_check_interfaces(pim, rp_info);
	pim_rp_refresh_group_to_rp_mapping(pim);
	return PIM_SUCCESS;
}

int pim_rp_del(struct pim_instance *pim, const char *rp,
	       const char *group_range, const char *plist)
{
	struct prefix group;
	struct in_addr rp_addr;
	struct prefix g_all;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	int result;
	struct prefix nht_p;
	struct route_node *rn;
	bool was_plist = false;

	if (group_range == NULL)
		result = str2prefix("224.0.0.0/4", &group);
	else
		result = str2prefix(group_range, &group);

	if (!result)
		return PIM_GROUP_BAD_ADDRESS;

	result = inet_pton(AF_INET, rp, &rp_addr);
	if (result <= 0)
		return PIM_RP_BAD_ADDRESS;

	if (plist)
		rp_info = pim_rp_find_prefix_list(pim, rp_addr, plist);
	else
		rp_info = pim_rp_find_exact(pim, rp_addr, &group);

	if (!rp_info)
		return PIM_RP_NOT_FOUND;

	if (rp_info->plist) {
		XFREE(MTYPE_PIM_FILTER_NAME, rp_info->plist);
		rp_info->plist = NULL;
		was_plist = true;
	}

	/* Deregister addr with Zebra NHT */
	nht_p.family = AF_INET;
	nht_p.prefixlen = IPV4_MAX_BITLEN;
	nht_p.u.prefix4 = rp_info->rp.rpf_addr.u.prefix4;
	if (PIM_DEBUG_PIM_NHT_RP) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&nht_p, buf, sizeof(buf));
		zlog_debug("%s: Deregister RP addr %s with Zebra ",
			   __PRETTY_FUNCTION__, buf);
	}
	pim_delete_tracked_nexthop(pim, &nht_p, NULL, rp_info);

	if (!str2prefix("224.0.0.0/4", &g_all))
		return PIM_RP_BAD_ADDRESS;

	rp_all = pim_rp_find_match_group(pim, &g_all);

	if (rp_all == rp_info) {
		rp_all->rp.rpf_addr.family = AF_INET;
		rp_all->rp.rpf_addr.u.prefix4.s_addr = INADDR_NONE;
		rp_all->i_am_rp = 0;
		return PIM_SUCCESS;
	}

	listnode_delete(pim->rp_list, rp_info);

	if (!was_plist) {
		rn = route_node_get(pim->rp_table, &rp_info->group);
		if (rn) {
			if (rn->info != rp_info)
				zlog_err("WTF matey");

			if (PIM_DEBUG_TRACE) {
				char buf[PREFIX_STRLEN];

				zlog_debug("%s:Found for Freeing: %p for rp_info: %p(%s) Lock: %d",
					   __PRETTY_FUNCTION__,
					   rn, rp_info,
					   prefix2str(&rp_info->group, buf, sizeof(buf)),
					   rn->lock);
			}
			rn->info = NULL;
			route_unlock_node(rn);
			route_unlock_node(rn);
		}
	}

	pim_rp_refresh_group_to_rp_mapping(pim);

	XFREE(MTYPE_PIM_RP, rp_info);
	return PIM_SUCCESS;
}

void pim_rp_setup(struct pim_instance *pim)
{
	struct listnode *node;
	struct rp_info *rp_info;
	struct prefix nht_p;
	struct pim_nexthop_cache pnc;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->rp.rpf_addr.u.prefix4.s_addr == INADDR_NONE)
			continue;

		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4 = rp_info->rp.rpf_addr.u.prefix4;
		memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
		if (pim_find_or_track_nexthop(pim, &nht_p, NULL, rp_info, &pnc))
			pim_ecmp_nexthop_search(pim, &pnc,
						&rp_info->rp.source_nexthop,
						&nht_p, &rp_info->group, 1);
		else {
			if (PIM_DEBUG_PIM_NHT_RP) {
				char buf[PREFIX2STR_BUFFER];
				prefix2str(&nht_p, buf, sizeof(buf));
				zlog_debug(
					"%s: NHT Local Nexthop not found for RP %s ",
					__PRETTY_FUNCTION__, buf);
			}
			if (!pim_nexthop_lookup(
				    pim, &rp_info->rp.source_nexthop,
				    rp_info->rp.rpf_addr.u.prefix4, 1))
				if (PIM_DEBUG_PIM_NHT_RP)
					zlog_debug(
						"Unable to lookup nexthop for rp specified");
		}
	}
}

/*
 * Checks to see if we should elect ourself the actual RP when new if
 * addresses are added against an interface.
 */
void pim_rp_check_on_if_add(struct pim_interface *pim_ifp)
{
	struct listnode *node;
	struct rp_info *rp_info;
	bool i_am_rp_changed = false;
	struct pim_instance *pim = pim_ifp->pim;

	if (pim->rp_list == NULL)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_none(&rp_info->rp))
			continue;

		/* if i_am_rp is already set nothing to be done (adding new
		 * addresses
		 * is not going to make a difference). */
		if (rp_info->i_am_rp) {
			continue;
		}

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			i_am_rp_changed = true;
			rp_info->i_am_rp = 1;
			if (PIM_DEBUG_PIM_NHT_RP) {
				char rp[PREFIX_STRLEN];
				pim_addr_dump("<rp?>", &rp_info->rp.rpf_addr,
					      rp, sizeof(rp));
				zlog_debug("%s: %s: i am rp", __func__, rp);
			}
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
	}
}

/* up-optimized re-evaluation of "i_am_rp". this is used when ifaddresses
 * are removed. Removing numbers is an uncommon event in an active network
 * so I have made no attempt to optimize it. */
void pim_i_am_rp_re_evaluate(struct pim_instance *pim)
{
	struct listnode *node;
	struct rp_info *rp_info;
	bool i_am_rp_changed = false;
	int old_i_am_rp;

	if (pim->rp_list == NULL)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_none(&rp_info->rp))
			continue;

		old_i_am_rp = rp_info->i_am_rp;
		pim_rp_check_interfaces(pim, rp_info);

		if (old_i_am_rp != rp_info->i_am_rp) {
			i_am_rp_changed = true;
			if (PIM_DEBUG_PIM_NHT_RP) {
				char rp[PREFIX_STRLEN];
				pim_addr_dump("<rp?>", &rp_info->rp.rpf_addr,
					      rp, sizeof(rp));
				if (rp_info->i_am_rp) {
					zlog_debug("%s: %s: i am rp", __func__,
						   rp);
				} else {
					zlog_debug("%s: %s: i am no longer rp",
						   __func__, rp);
				}
			}
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
	}
}

/*
 * I_am_RP(G) is true if the group-to-RP mapping indicates that
 * this router is the RP for the group.
 *
 * Since we only have static RP, all groups are part of this RP
 */
int pim_rp_i_am_rp(struct pim_instance *pim, struct in_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	g.family = AF_INET;
	g.prefixlen = 32;
	g.u.prefix4 = group;

	rp_info = pim_rp_find_match_group(pim, &g);

	if (rp_info)
		return rp_info->i_am_rp;

	return 0;
}

/*
 * RP(G)
 *
 * Return the RP that the Group belongs too.
 */
struct pim_rpf *pim_rp_g(struct pim_instance *pim, struct in_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	g.family = AF_INET;
	g.prefixlen = 32;
	g.u.prefix4 = group;

	rp_info = pim_rp_find_match_group(pim, &g);

	if (rp_info) {
		struct prefix nht_p;
		struct pim_nexthop_cache pnc;
		/* Register addr with Zebra NHT */
		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4 = rp_info->rp.rpf_addr.u.prefix4;
		if (PIM_DEBUG_PIM_NHT_RP) {
			char buf[PREFIX2STR_BUFFER];
			char buf1[PREFIX2STR_BUFFER];
			prefix2str(&nht_p, buf, sizeof(buf));
			prefix2str(&rp_info->group, buf1, sizeof(buf1));
			zlog_debug(
				"%s: NHT Register RP addr %s grp %s with Zebra",
				__PRETTY_FUNCTION__, buf, buf1);
		}
		memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
		if (pim_find_or_track_nexthop(pim, &nht_p, NULL, rp_info, &pnc))
			pim_ecmp_nexthop_search(pim, &pnc,
						&rp_info->rp.source_nexthop,
						&nht_p, &rp_info->group, 1);
		else {
			if (PIM_DEBUG_PIM_NHT_RP) {
				char buf[PREFIX2STR_BUFFER];
				char buf1[PREFIX2STR_BUFFER];
				prefix2str(&nht_p, buf, sizeof(buf));
				prefix2str(&g, buf1, sizeof(buf1));
				zlog_debug(
					"%s: Nexthop cache not found for RP %s grp %s register with Zebra",
					__PRETTY_FUNCTION__, buf, buf1);
			}
			pim_rpf_set_refresh_time();
			pim_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					   rp_info->rp.rpf_addr.u.prefix4, 1);
		}
		return (&rp_info->rp);
	}

	// About to Go Down
	return NULL;
}

/*
 * Set the upstream IP address we want to talk to based upon
 * the rp configured and the source address
 *
 * If we have don't have a RP configured and the source address is *
 * then return failure.
 *
 */
int pim_rp_set_upstream_addr(struct pim_instance *pim, struct in_addr *up,
			     struct in_addr source, struct in_addr group)
{
	struct rp_info *rp_info;
	struct prefix g;

	memset(&g, 0, sizeof(g));
	g.family = AF_INET;
	g.prefixlen = 32;
	g.u.prefix4 = group;

	rp_info = pim_rp_find_match_group(pim, &g);

	if ((pim_rpf_addr_is_inaddr_none(&rp_info->rp))
	    && (source.s_addr == INADDR_ANY)) {
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: Received a (*,G) with no RP configured",
				   __PRETTY_FUNCTION__);
		return 0;
	}

	*up = (source.s_addr == INADDR_ANY) ? rp_info->rp.rpf_addr.u.prefix4
					    : source;

	return 1;
}

int pim_rp_config_write(struct pim_instance *pim, struct vty *vty,
			const char *spaces)
{
	struct listnode *node;
	struct rp_info *rp_info;
	char rp_buffer[32];
	char group_buffer[32];
	int count = 0;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_none(&rp_info->rp))
			continue;

		if (rp_info->plist)
			vty_out(vty, "%sip pim rp %s prefix-list %s\n", spaces,
				inet_ntop(AF_INET,
					  &rp_info->rp.rpf_addr.u.prefix4,
					  rp_buffer, 32),
				rp_info->plist);
		else
			vty_out(vty, "%sip pim rp %s %s\n", spaces,
				inet_ntop(AF_INET,
					  &rp_info->rp.rpf_addr.u.prefix4,
					  rp_buffer, 32),
				prefix2str(&rp_info->group, group_buffer, 32));
		count++;
	}

	return count;
}

int pim_rp_check_is_my_ip_address(struct pim_instance *pim,
				  struct in_addr group,
				  struct in_addr dest_addr)
{
	struct rp_info *rp_info;
	struct prefix g;

	memset(&g, 0, sizeof(g));
	g.family = AF_INET;
	g.prefixlen = 32;
	g.u.prefix4 = group;

	rp_info = pim_rp_find_match_group(pim, &g);
	/*
	 * See if we can short-cut some?
	 * This might not make sense if we ever leave a static RP
	 * type of configuration.
	 * Note - Premature optimization might bite our patooeys' here.
	 */
	if (I_am_RP(pim, group)) {
		if (dest_addr.s_addr == rp_info->rp.rpf_addr.u.prefix4.s_addr)
			return 1;
	}

	if (if_lookup_exact_address(&dest_addr, AF_INET, pim->vrf_id))
		return 1;

	return 0;
}

void pim_rp_show_information(struct pim_instance *pim, struct vty *vty,
			     u_char uj)
{
	struct rp_info *rp_info;
	struct rp_info *prev_rp_info = NULL;
	struct listnode *node;

	json_object *json = NULL;
	json_object *json_rp_rows = NULL;
	json_object *json_row = NULL;

	if (uj)
		json = json_object_new_object();
	else
		vty_out(vty,
			"RP address       group/prefix-list   OIF         I am RP\n");

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (!pim_rpf_addr_is_inaddr_none(&rp_info->rp)) {
			char buf[48];

			if (uj) {
				/*
				 * If we have moved on to a new RP then add the
				 * entry for the previous RP
				 */
				if (prev_rp_info
				    && prev_rp_info->rp.rpf_addr.u.prefix4
						       .s_addr
					       != rp_info->rp.rpf_addr.u.prefix4
							  .s_addr) {
					json_object_object_add(
						json,
						inet_ntoa(prev_rp_info->rp
								  .rpf_addr.u
								  .prefix4),
						json_rp_rows);
					json_rp_rows = NULL;
				}

				if (!json_rp_rows)
					json_rp_rows = json_object_new_array();

				json_row = json_object_new_object();
				if (rp_info->rp.source_nexthop.interface)
					json_object_string_add(
						json_row, "outboundInterface",
						rp_info->rp.source_nexthop
							.interface->name);

				if (rp_info->i_am_rp)
					json_object_boolean_true_add(json_row,
								     "iAmRP");

				if (rp_info->plist)
					json_object_string_add(json_row,
							       "prefixList",
							       rp_info->plist);
				else
					json_object_string_add(
						json_row, "group",
						prefix2str(&rp_info->group, buf,
							   48));

				json_object_array_add(json_rp_rows, json_row);
			} else {
				vty_out(vty, "%-15s  ",
					inet_ntoa(rp_info->rp.rpf_addr.u
							  .prefix4));

				if (rp_info->plist)
					vty_out(vty, "%-18s  ", rp_info->plist);
				else
					vty_out(vty, "%-18s  ",
						prefix2str(&rp_info->group, buf,
							   48));

				if (rp_info->rp.source_nexthop.interface)
					vty_out(vty, "%-10s  ",
						rp_info->rp.source_nexthop
							.interface->name);
				else
					vty_out(vty, "%-10s  ", "(Unknown)");

				if (rp_info->i_am_rp)
					vty_out(vty, "yes\n");
				else
					vty_out(vty, "no\n");
			}

			prev_rp_info = rp_info;
		}
	}

	if (uj) {
		if (prev_rp_info && json_rp_rows)
			json_object_object_add(
				json,
				inet_ntoa(prev_rp_info->rp.rpf_addr.u.prefix4),
				json_rp_rows);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
}

void pim_resolve_rp_nh(struct pim_instance *pim)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;
	struct nexthop *nh_node = NULL;
	struct prefix nht_p;
	struct pim_nexthop_cache pnc;
	struct pim_neighbor *nbr = NULL;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->rp.rpf_addr.u.prefix4.s_addr == INADDR_NONE)
			continue;

		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4 = rp_info->rp.rpf_addr.u.prefix4;
		memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
		if (!pim_find_or_track_nexthop(pim, &nht_p, NULL, rp_info,
					       &pnc))
			continue;

		for (nh_node = pnc.nexthop; nh_node; nh_node = nh_node->next) {
			if (nh_node->gate.ipv4.s_addr != 0)
				continue;

			struct interface *ifp1 = if_lookup_by_index(
				nh_node->ifindex, pim->vrf_id);
			nbr = pim_neighbor_find_if(ifp1);
			if (!nbr)
				continue;

			nh_node->gate.ipv4 = nbr->source_addr;
			if (PIM_DEBUG_PIM_NHT_RP) {
				char str[PREFIX_STRLEN];
				char str1[INET_ADDRSTRLEN];
				pim_inet4_dump("<nht_nbr?>", nbr->source_addr,
					       str1, sizeof(str1));
				pim_addr_dump("<nht_addr?>", &nht_p, str,
					      sizeof(str));
				zlog_debug(
					"%s: addr %s new nexthop addr %s interface %s",
					__PRETTY_FUNCTION__, str, str1,
					ifp1->name);
			}
		}
	}
}
