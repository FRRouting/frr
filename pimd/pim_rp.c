// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
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
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_vty.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_rpf.h"
#include "pim_sock.h"
#include "pim_memory.h"
#include "pim_neighbor.h"
#include "pim_msdp.h"
#include "pim_nht.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_zebra.h"
#include "pim_bsm.h"
#include "pim_util.h"
#include "pim_ssm.h"
#include "termtable.h"

/* Cleanup pim->rpf_hash each node data */
void pim_rp_list_hash_clean(void *data)
{
	struct pim_nexthop_cache *pnc = (struct pim_nexthop_cache *)data;

	list_delete(&pnc->rp_list);

	hash_clean_and_free(&pnc->upstream_hash, NULL);
	if (pnc->nexthop)
		nexthops_free(pnc->nexthop);

	XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
}

static void pim_rp_info_free(struct rp_info *rp_info)
{
	XFREE(MTYPE_PIM_FILTER_NAME, rp_info->plist);

	XFREE(MTYPE_PIM_RP, rp_info);
}

int pim_rp_list_cmp(void *v1, void *v2)
{
	struct rp_info *rp1 = (struct rp_info *)v1;
	struct rp_info *rp2 = (struct rp_info *)v2;
	int ret;

	/*
	 * Sort by RP IP address
	 */
	ret = pim_addr_cmp(rp1->rp.rpf_addr, rp2->rp.rpf_addr);
	if (ret)
		return ret;

	/*
	 * Sort by group IP address
	 */
	ret = prefix_cmp(&rp1->group, &rp2->group);
	if (ret)
		return ret;

	return 0;
}

void pim_rp_init(struct pim_instance *pim)
{
	struct rp_info *rp_info;
	struct route_node *rn;

	pim->rp_list = list_new();
	pim->rp_list->del = (void (*)(void *))pim_rp_info_free;
	pim->rp_list->cmp = pim_rp_list_cmp;

	pim->rp_table = route_table_init();

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));

	if (!pim_get_all_mcast_group(&rp_info->group)) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "Unable to convert all-multicast prefix");
		list_delete(&pim->rp_list);
		route_table_finish(pim->rp_table);
		XFREE(MTYPE_PIM_RP, rp_info);
		return;
	}
	rp_info->rp.rpf_addr = PIMADDR_ANY;

	listnode_add(pim->rp_list, rp_info);

	rn = route_node_get(pim->rp_table, &rp_info->group);
	rn->info = rp_info;
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("Allocated: %p for rp_info: %p(%pFX) Lock: %d", rn,
			   rp_info, &rp_info->group,
			   route_node_get_lock_count(rn));
}

void pim_rp_free(struct pim_instance *pim)
{
	if (pim->rp_table)
		route_table_finish(pim->rp_table);
	pim->rp_table = NULL;

	if (pim->rp_list)
		list_delete(&pim->rp_list);
}

/*
 * Given an RP's prefix-list, return the RP's rp_info for that prefix-list
 */
static struct rp_info *pim_rp_find_prefix_list(struct pim_instance *pim,
					       pim_addr rp, const char *plist)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if ((!pim_addr_cmp(rp, rp_info->rp.rpf_addr)) &&
		    rp_info->plist && strcmp(rp_info->plist, plist) == 0) {
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
static struct rp_info *pim_rp_find_exact(struct pim_instance *pim, pim_addr rp,
					 const struct prefix *group)
{
	struct listnode *node;
	struct rp_info *rp_info;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if ((!pim_addr_cmp(rp, rp_info->rp.rpf_addr)) &&
		    prefix_same(&rp_info->group, group))
			return rp_info;
	}

	return NULL;
}

/*
 * XXX: long-term issue:  we don't actually have a good "ip address-list"
 * implementation.  ("access-list XYZ" is the closest but honestly it's
 * kinda garbage.)
 *
 * So it's using a prefix-list to match an address here, which causes very
 * unexpected results for the user since prefix-lists by default only match
 * when the prefix length is an exact match too.  i.e. you'd have to add the
 * "le 32" and do "ip prefix-list foo permit 10.0.0.0/24 le 32"
 *
 * To avoid this pitfall, this code uses "address_mode = true" for the prefix
 * list match (this is the only user for that.)
 *
 * In the long run, we need to add a "ip address-list", but that's a wholly
 * separate bag of worms, and existing configs using ip prefix-list would
 * drop into the UX pitfall.
 */

#include "lib/plist_int.h"

/*
 * Given a group, return the rp_info for that group
 */
struct rp_info *pim_rp_find_match_group(struct pim_instance *pim,
					       const struct prefix *group)
{
	struct listnode *node;
	struct rp_info *best = NULL;
	struct rp_info *rp_info;
	struct prefix_list *plist;
	const struct prefix *bp;
	const struct prefix_list_entry *entry;
	struct route_node *rn;

	bp = NULL;
	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (rp_info->plist) {
			plist = prefix_list_lookup(PIM_AFI, rp_info->plist);

			if (prefix_list_apply_ext(plist, &entry, group, true)
			    == PREFIX_DENY || !entry)
				continue;

			if (!best) {
				best = rp_info;
				bp = &entry->prefix;
				continue;
			}

			if (bp && bp->prefixlen < entry->prefix.prefixlen) {
				best = rp_info;
				bp = &entry->prefix;
			}
		}
	}

	rn = route_node_match(pim->rp_table, group);
	if (!rn) {
		flog_err(
			EC_LIB_DEVELOPMENT,
			"%s: BUG We should have found default group information",
			__func__);
		return best;
	}

	rp_info = rn->info;
	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		if (best)
			zlog_debug(
				"Lookedup(%pFX): prefix_list match %s, rn %p found: %pFX",
				group, best->plist, rn, &rp_info->group);
		else
			zlog_debug("Lookedup(%pFX): rn %p found:%pFX", group,
				   rn, &rp_info->group);
	}

	route_unlock_node(rn);

	/*
	 * rp's with prefix lists have the group as 224.0.0.0/4 which will
	 * match anything.  So if we have a rp_info that should match a prefix
	 * list then if we do match then best should be the answer( even
	 * if it is NULL )
	 */
	if (!rp_info || (rp_info && rp_info->plist))
		return best;

	/*
	 * So we have a non plist rp_info found in the lookup and no plists
	 * at all to be choosen, return it!
	 */
	if (!best)
		return rp_info;

	/*
	 * If we have a matching non prefix list and a matching prefix
	 * list we should return the actual rp_info that has the LPM
	 * If they are equal, use the prefix-list( but let's hope
	 * the end-operator doesn't do this )
	 */
	if (rp_info->group.prefixlen > bp->prefixlen)
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
void pim_rp_refresh_group_to_rp_mapping(struct pim_instance *pim)
{
	pim_msdp_i_am_rp_changed(pim);
	pim_upstream_reeval_use_rpt(pim);
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
	pim_addr sec_paddr;

	if (!pim_addr_cmp(pim_ifp->primary_address, rp_info->rp.rpf_addr))
		return 1;

	if (!pim_ifp->sec_addr_list) {
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->sec_addr_list, node, sec_addr)) {
		sec_paddr = pim_addr_from_prefix(&sec_addr->addr);
		/* If an RP-address is self, It should be enough to say
		 * I am RP the prefix-length should not matter here */
		if (!pim_addr_cmp(sec_paddr, rp_info->rp.rpf_addr))
			return 1;
	}

	return 0;
}

static void pim_rp_check_interfaces(struct pim_instance *pim,
				    struct rp_info *rp_info)
{
	struct interface *ifp;

	rp_info->i_am_rp = 0;
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_rp_check_interface_addrs(rp_info, pim_ifp)) {
			rp_info->i_am_rp = 1;
		}
	}
}

void pim_upstream_update(struct pim_instance *pim, struct pim_upstream *up)
{
	struct pim_rpf old_rpf;
	enum pim_rpf_result rpf_result;
	pim_addr old_upstream_addr;
	pim_addr new_upstream_addr;

	old_upstream_addr = up->upstream_addr;
	pim_rp_set_upstream_addr(pim, &new_upstream_addr, up->sg.src,
				 up->sg.grp);

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: pim upstream update for old upstream %pPA",
			   __func__, &old_upstream_addr);

	if (!pim_addr_cmp(old_upstream_addr, new_upstream_addr))
		return;

	/* Lets consider a case, where a PIM upstream has a better RP as a
	 * result of a new RP configuration with more precise group range.
	 * This upstream has to be added to the upstream hash of new RP's
	 * NHT(pnc) and has to be removed from old RP's NHT upstream hash
	 */
	if (!pim_addr_is_any(old_upstream_addr)) {
		/* Deregister addr with Zebra NHT */
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Deregister upstream %s addr %pPA with Zebra NHT",
				__func__, up->sg_str, &old_upstream_addr);
		pim_delete_tracked_nexthop(pim, old_upstream_addr, up, NULL);
	}

	/* Update the upstream address */
	up->upstream_addr = new_upstream_addr;

	old_rpf.source_nexthop.interface = up->rpf.source_nexthop.interface;

	rpf_result = pim_rpf_update(pim, up, &old_rpf, __func__);
	if (rpf_result == PIM_RPF_FAILURE)
		pim_mroute_del(up->channel_oil, __func__);

	/* update kernel multicast forwarding cache (MFC) */
	if (up->rpf.source_nexthop.interface && up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	if (rpf_result == PIM_RPF_CHANGED ||
			(rpf_result == PIM_RPF_FAILURE &&
			 old_rpf.source_nexthop.interface))
		pim_zebra_upstream_rpf_changed(pim, up, &old_rpf);

}

int pim_rp_new(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, enum rp_source rp_src_flag)
{
	int result = 0;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	struct prefix group_all;
	struct listnode *node, *nnode;
	struct rp_info *tmp_rp_info;
	char buffer[BUFSIZ];
	pim_addr nht_p;
	struct route_node *rn = NULL;
	struct pim_upstream *up;
	bool upstream_updated = false;

	if (pim_addr_is_any(rp_addr))
		return PIM_RP_BAD_ADDRESS;

	rp_info = XCALLOC(MTYPE_PIM_RP, sizeof(*rp_info));

	rp_info->rp.rpf_addr = rp_addr;
	prefix_copy(&rp_info->group, &group);
	rp_info->rp_src = rp_src_flag;

	if (plist) {
		/*
		 * Return if the prefix-list is already configured for this RP
		 */
		if (pim_rp_find_prefix_list(pim, rp_addr, plist)) {
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
			if (!pim_addr_cmp(rp_info->rp.rpf_addr,
					  tmp_rp_info->rp.rpf_addr)) {
				if (tmp_rp_info->plist)
					pim_rp_del_config(pim, rp_addr, NULL,
							  tmp_rp_info->plist);
				else
					pim_rp_del_config(
						pim, rp_addr,
						prefix2str(&tmp_rp_info->group,
							   buffer, BUFSIZ),
						NULL);
			}
		}

		rp_info->plist = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist);
	} else {

		if (!pim_get_all_mcast_group(&group_all)) {
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
			if (tmp_rp_info->plist &&
			    (!pim_addr_cmp(rp_info->rp.rpf_addr,
					   tmp_rp_info->rp.rpf_addr))) {
				pim_rp_del_config(pim, rp_addr, NULL,
						  tmp_rp_info->plist);
			}
		}

		/*
		 * Take over the 224.0.0.0/4 group if the rp is INADDR_ANY
		 */
		if (prefix_same(&rp_all->group, &rp_info->group) &&
		    pim_rpf_addr_is_inaddr_any(&rp_all->rp)) {
			rp_all->rp.rpf_addr = rp_info->rp.rpf_addr;
			rp_all->rp_src = rp_src_flag;
			XFREE(MTYPE_PIM_RP, rp_info);

			/* Register addr with Zebra NHT */
			nht_p = rp_all->rp.rpf_addr;
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: NHT Register rp_all addr %pPA grp %pFX ",
					__func__, &nht_p, &rp_all->group);

			frr_each (rb_pim_upstream, &pim->upstream_head, up) {
				/* Find (*, G) upstream whose RP is not
				 * configured yet
				 */
				if (pim_addr_is_any(up->upstream_addr) &&
				    pim_addr_is_any(up->sg.src)) {
					struct prefix grp;
					struct rp_info *trp_info;

					pim_addr_to_prefix(&grp, up->sg.grp);
					trp_info = pim_rp_find_match_group(
						pim, &grp);
					if (trp_info == rp_all) {
						pim_upstream_update(pim, up);
						upstream_updated = true;
					}
				}
			}
			if (upstream_updated)
				pim_zebra_update_all_interfaces(pim);

			pim_rp_check_interfaces(pim, rp_all);
			if (rp_all->i_am_rp && PIM_DEBUG_PIM_NHT_RP)
				zlog_debug("new RP %pPA for %pFX is ourselves",
					   &rp_all->rp.rpf_addr, &rp_all->group);
			pim_rp_refresh_group_to_rp_mapping(pim);
			pim_find_or_track_nexthop(pim, nht_p, NULL, rp_all,
						  NULL);

			if (!pim_ecmp_nexthop_lookup(pim,
						     &rp_all->rp.source_nexthop,
						     nht_p, &rp_all->group, 1))
				return PIM_RP_NO_PATH;
			return PIM_SUCCESS;
		}

		/*
		 * Return if the group is already configured for this RP
		 */
		tmp_rp_info = pim_rp_find_exact(pim, rp_addr, &rp_info->group);
		if (tmp_rp_info) {
			if ((tmp_rp_info->rp_src != rp_src_flag)
			    && (rp_src_flag == RP_SRC_STATIC))
				tmp_rp_info->rp_src = rp_src_flag;
			XFREE(MTYPE_PIM_RP, rp_info);
			return result;
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
					if ((rp_src_flag == RP_SRC_STATIC)
					    && (tmp_rp_info->rp_src
						== RP_SRC_STATIC)) {
						XFREE(MTYPE_PIM_RP, rp_info);
						return PIM_GROUP_OVERLAP;
					}

					result = pim_rp_change(
						pim, rp_addr,
						tmp_rp_info->group,
						rp_src_flag);
					XFREE(MTYPE_PIM_RP, rp_info);
					return result;
				}
			}
		}
	}

	listnode_add_sort(pim->rp_list, rp_info);

	if (!rp_info->plist) {
		rn = route_node_get(pim->rp_table, &rp_info->group);
		rn->info = rp_info;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("Allocated: %p for rp_info: %p(%pFX) Lock: %d", rn,
			   rp_info, &rp_info->group,
			   rn ? route_node_get_lock_count(rn) : 0);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->sg.src)) {
			struct prefix grp;
			struct rp_info *trp_info;

			pim_addr_to_prefix(&grp, up->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);

			if (trp_info == rp_info) {
				pim_upstream_update(pim, up);
				upstream_updated = true;
			}
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);

	pim_rp_check_interfaces(pim, rp_info);
	if (rp_info->i_am_rp && PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("new RP %pPA for %pFX is ourselves",
			   &rp_info->rp.rpf_addr, &rp_info->group);
	pim_rp_refresh_group_to_rp_mapping(pim);

	/* Register addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: NHT Register RP addr %pPA grp %pFX with Zebra ",
			   __func__, &nht_p, &rp_info->group);
	pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop, nht_p,
				     &rp_info->group, 1))
		return PIM_RP_NO_PATH;

	return PIM_SUCCESS;
}

void pim_rp_del_config(struct pim_instance *pim, pim_addr rp_addr,
		       const char *group_range, const char *plist)
{
	struct prefix group;
	int result;

	if (group_range == NULL)
		result = pim_get_all_mcast_group(&group);
	else
		result = str2prefix(group_range, &group);

	if (!result) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: String to prefix failed for %pPAs group",
				__func__, &rp_addr);
		return;
	}

	pim_rp_del(pim, rp_addr, group, plist, RP_SRC_STATIC);
}

int pim_rp_del(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, enum rp_source rp_src_flag)
{
	struct prefix g_all;
	struct rp_info *rp_info;
	struct rp_info *rp_all;
	pim_addr nht_p;
	struct route_node *rn;
	bool was_plist = false;
	struct rp_info *trp_info;
	struct pim_upstream *up;
	struct bsgrp_node *bsgrp = NULL;
	struct bsm_rpinfo *bsrp = NULL;
	bool upstream_updated = false;

	if (plist)
		rp_info = pim_rp_find_prefix_list(pim, rp_addr, plist);
	else
		rp_info = pim_rp_find_exact(pim, rp_addr, &group);

	if (!rp_info)
		return PIM_RP_NOT_FOUND;

	if (rp_info->plist) {
		XFREE(MTYPE_PIM_FILTER_NAME, rp_info->plist);
		was_plist = true;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: Delete RP %pPA for the group %pFX", __func__,
			   &rp_addr, &group);

	/* While static RP is getting deleted, we need to check if dynamic RP
	 * present for the same group in BSM RP table, then install the dynamic
	 * RP for the group node into the main rp table
	 */
	if (rp_src_flag == RP_SRC_STATIC) {
		bsgrp = pim_bsm_get_bsgrp_node(&pim->global_scope, &group);

		if (bsgrp) {
			bsrp = bsm_rpinfos_first(bsgrp->bsrp_list);
			if (bsrp) {
				if (PIM_DEBUG_PIM_TRACE)
					zlog_debug(
						"%s: BSM RP %pPA found for the group %pFX",
						__func__, &bsrp->rp_address,
						&group);
				return pim_rp_change(pim, bsrp->rp_address,
						     group, RP_SRC_BSR);
			}
		} else {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: BSM RP not found for the group %pFX",
					__func__, &group);
		}
	}

	/* Deregister addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: Deregister RP addr %pPA with Zebra ", __func__,
			   &nht_p);
	pim_delete_tracked_nexthop(pim, nht_p, NULL, rp_info);

	if (!pim_get_all_mcast_group(&g_all))
		return PIM_RP_BAD_ADDRESS;

	rp_all = pim_rp_find_match_group(pim, &g_all);

	if (rp_all == rp_info) {
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			/* Find the upstream (*, G) whose upstream address is
			 * same as the deleted RP
			 */
			pim_addr rpf_addr;

			rpf_addr = rp_info->rp.rpf_addr;
			if (!pim_addr_cmp(up->upstream_addr, rpf_addr) &&
			    pim_addr_is_any(up->sg.src)) {
				struct prefix grp;

				pim_addr_to_prefix(&grp, up->sg.grp);
				trp_info = pim_rp_find_match_group(pim, &grp);
				if (trp_info == rp_all) {
					pim_upstream_rpf_clear(pim, up);
					up->upstream_addr = PIMADDR_ANY;
				}
			}
		}
		rp_all->rp.rpf_addr = PIMADDR_ANY;
		rp_all->i_am_rp = 0;
		return PIM_SUCCESS;
	}

	listnode_delete(pim->rp_list, rp_info);

	if (!was_plist) {
		rn = route_node_get(pim->rp_table, &rp_info->group);
		if (rn) {
			if (rn->info != rp_info)
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Expected rn->info to be equal to rp_info");

			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s:Found for Freeing: %p for rp_info: %p(%pFX) Lock: %d",
					__func__, rn, rp_info, &rp_info->group,
					route_node_get_lock_count(rn));

			rn->info = NULL;
			route_unlock_node(rn);
			route_unlock_node(rn);
		}
	}

	pim_rp_refresh_group_to_rp_mapping(pim);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		/* Find the upstream (*, G) whose upstream address is same as
		 * the deleted RP
		 */
		pim_addr rpf_addr;

		rpf_addr = rp_info->rp.rpf_addr;
		if (!pim_addr_cmp(up->upstream_addr, rpf_addr) &&
		    pim_addr_is_any(up->sg.src)) {
			struct prefix grp;

			pim_addr_to_prefix(&grp, up->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);

			/* RP not found for the group grp */
			if (pim_rpf_addr_is_inaddr_any(&trp_info->rp)) {
				pim_upstream_rpf_clear(pim, up);
				pim_rp_set_upstream_addr(
					pim, &up->upstream_addr, up->sg.src,
					up->sg.grp);
			}

			/* RP found for the group grp */
			else {
				pim_upstream_update(pim, up);
				upstream_updated = true;
			}
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);

	XFREE(MTYPE_PIM_RP, rp_info);
	return PIM_SUCCESS;
}

int pim_rp_change(struct pim_instance *pim, pim_addr new_rp_addr,
		  struct prefix group, enum rp_source rp_src_flag)
{
	pim_addr nht_p;
	struct route_node *rn;
	int result = 0;
	struct rp_info *rp_info = NULL;
	struct pim_upstream *up;
	bool upstream_updated = false;
	pim_addr old_rp_addr;

	rn = route_node_lookup(pim->rp_table, &group);
	if (!rn) {
		result = pim_rp_new(pim, new_rp_addr, group, NULL, rp_src_flag);
		return result;
	}

	rp_info = rn->info;

	if (!rp_info) {
		route_unlock_node(rn);
		result = pim_rp_new(pim, new_rp_addr, group, NULL, rp_src_flag);
		return result;
	}

	old_rp_addr = rp_info->rp.rpf_addr;
	if (!pim_addr_cmp(new_rp_addr, old_rp_addr)) {
		if (rp_info->rp_src != rp_src_flag) {
			rp_info->rp_src = rp_src_flag;
			route_unlock_node(rn);
			return PIM_SUCCESS;
		}
	}

	/* Deregister old RP addr with Zebra NHT */

	if (!pim_addr_is_any(old_rp_addr)) {
		nht_p = rp_info->rp.rpf_addr;
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: Deregister RP addr %pPA with Zebra ",
				   __func__, &nht_p);
		pim_delete_tracked_nexthop(pim, nht_p, NULL, rp_info);
	}

	pim_rp_nexthop_del(rp_info);
	listnode_delete(pim->rp_list, rp_info);
	/* Update the new RP address*/

	rp_info->rp.rpf_addr = new_rp_addr;
	rp_info->rp_src = rp_src_flag;
	rp_info->i_am_rp = 0;

	listnode_add_sort(pim->rp_list, rp_info);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->sg.src)) {
			struct prefix grp;
			struct rp_info *trp_info;

			pim_addr_to_prefix(&grp, up->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);

			if (trp_info == rp_info) {
				pim_upstream_update(pim, up);
				upstream_updated = true;
			}
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);

	/* Register new RP addr with Zebra NHT */
	nht_p = rp_info->rp.rpf_addr;
	if (PIM_DEBUG_PIM_NHT_RP)
		zlog_debug("%s: NHT Register RP addr %pPA grp %pFX with Zebra ",
			   __func__, &nht_p, &rp_info->group);

	pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop, nht_p,
				     &rp_info->group, 1)) {
		route_unlock_node(rn);
		return PIM_RP_NO_PATH;
	}

	pim_rp_check_interfaces(pim, rp_info);

	route_unlock_node(rn);

	pim_rp_refresh_group_to_rp_mapping(pim);

	return result;
}

void pim_rp_setup(struct pim_instance *pim)
{
	struct listnode *node;
	struct rp_info *rp_info;
	pim_addr nht_p;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		nht_p = rp_info->rp.rpf_addr;

		pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
		if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					     nht_p, &rp_info->group, 1)) {
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"Unable to lookup nexthop for rp specified");
			pim_rp_nexthop_del(rp_info);
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
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
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
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug("%s: %pPA: i am rp", __func__,
					   &rp_info->rp.rpf_addr);
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
		pim_upstream_reeval_use_rpt(pim);
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
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		old_i_am_rp = rp_info->i_am_rp;
		pim_rp_check_interfaces(pim, rp_info);

		if (old_i_am_rp != rp_info->i_am_rp) {
			i_am_rp_changed = true;
			if (PIM_DEBUG_PIM_NHT_RP) {
				if (rp_info->i_am_rp)
					zlog_debug("%s: %pPA: i am rp",
						   __func__,
						   &rp_info->rp.rpf_addr);
				else
					zlog_debug(
						"%s: %pPA: i am no longer rp",
						__func__,
						&rp_info->rp.rpf_addr);
			}
		}
	}

	if (i_am_rp_changed) {
		pim_msdp_i_am_rp_changed(pim);
		pim_upstream_reeval_use_rpt(pim);
	}
}

/*
 * I_am_RP(G) is true if the group-to-RP mapping indicates that
 * this router is the RP for the group.
 *
 * Since we only have static RP, all groups are part of this RP
 */
int pim_rp_i_am_rp(struct pim_instance *pim, pim_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	pim_addr_to_prefix(&g, group);
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
struct pim_rpf *pim_rp_g(struct pim_instance *pim, pim_addr group)
{
	struct prefix g;
	struct rp_info *rp_info;

	memset(&g, 0, sizeof(g));
	pim_addr_to_prefix(&g, group);

	rp_info = pim_rp_find_match_group(pim, &g);

	if (rp_info) {
		pim_addr nht_p;

		if (pim_addr_is_any(rp_info->rp.rpf_addr)) {
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: Skipping NHT Register since RP is not configured for the group %pPA",
					__func__, &group);
			return &rp_info->rp;
		}

		/* Register addr with Zebra NHT */
		nht_p = rp_info->rp.rpf_addr;
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug(
				"%s: NHT Register RP addr %pPA grp %pFX with Zebra",
				__func__, &nht_p, &rp_info->group);
		pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, NULL);
		pim_rpf_set_refresh_time(pim);
		(void)pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					      nht_p, &rp_info->group, 1);
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
 * then set the upstream addr as INADDR_ANY and return failure.
 *
 */
int pim_rp_set_upstream_addr(struct pim_instance *pim, pim_addr *up,
			     pim_addr source, pim_addr group)
{
	struct rp_info *rp_info;
	struct prefix g = {};

	if (!pim_addr_is_any(source)) {
		*up = source;
		return 1;
	}

	pim_addr_to_prefix(&g, group);
	rp_info = pim_rp_find_match_group(pim, &g);

	if (!rp_info || pim_rpf_addr_is_inaddr_any(&rp_info->rp)) {
		if (PIM_DEBUG_PIM_NHT_RP)
			zlog_debug("%s: Received a (*,G) with no RP configured",
				   __func__);
		*up = PIMADDR_ANY;
		return 0;
	}

	*up = rp_info->rp.rpf_addr;
	return 1;
}

int pim_rp_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct listnode *node;
	struct rp_info *rp_info;
	int count = 0;
	pim_addr rp_addr;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		if (rp_info->rp_src != RP_SRC_NONE &&
		    rp_info->rp_src != RP_SRC_STATIC)
			continue;

		rp_addr = rp_info->rp.rpf_addr;
		if (rp_info->plist)
			vty_out(vty, " rp %pPA prefix-list %s\n", &rp_addr,
				rp_info->plist);
		else
			vty_out(vty, " rp %pPA %pFX\n", &rp_addr,
				&rp_info->group);
		count++;
	}

	return count;
}

void pim_rp_show_information(struct pim_instance *pim, struct prefix *range,
			     struct vty *vty, json_object *json)
{
	struct rp_info *rp_info;
	struct rp_info *prev_rp_info = NULL;
	struct listnode *node;
	struct ttable *tt = NULL;
	char *table = NULL;
	char source[7];
	char grp[INET6_ADDRSTRLEN];

	json_object *json_rp_rows = NULL;
	json_object *json_row = NULL;

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"RP address|group/prefix-list|OIF|I am RP|Source|Group-Type");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

#if PIM_IPV == 4
		pim_addr group = rp_info->group.u.prefix4;
#else
		pim_addr group = rp_info->group.u.prefix6;
#endif
		const char *group_type =
			pim_is_grp_ssm(pim, group) ? "SSM" : "ASM";

		if (range && !prefix_match(&rp_info->group, range))
			continue;

		if (rp_info->rp_src == RP_SRC_STATIC)
			strlcpy(source, "Static", sizeof(source));
		else if (rp_info->rp_src == RP_SRC_BSR)
			strlcpy(source, "BSR", sizeof(source));
		else if (rp_info->rp_src == RP_SRC_AUTORP)
			strlcpy(source, "AutoRP", sizeof(source));
		else
			strlcpy(source, "None", sizeof(source));
		if (json) {
			/*
			 * If we have moved on to a new RP then add the
			 * entry for the previous RP
			 */
			if (prev_rp_info &&
			    (pim_addr_cmp(prev_rp_info->rp.rpf_addr,
					  rp_info->rp.rpf_addr))) {
				json_object_object_addf(
					json, json_rp_rows, "%pPA",
					&prev_rp_info->rp.rpf_addr);
				json_rp_rows = NULL;
			}

			if (!json_rp_rows)
				json_rp_rows = json_object_new_array();

			json_row = json_object_new_object();
			json_object_string_addf(json_row, "rpAddress", "%pPA",
						&rp_info->rp.rpf_addr);
			if (rp_info->rp.source_nexthop.interface)
				json_object_string_add(
					json_row, "outboundInterface",
					rp_info->rp.source_nexthop
						.interface->name);
			else
				json_object_string_add(json_row,
						       "outboundInterface",
						       "Unknown");
			if (rp_info->i_am_rp)
				json_object_boolean_true_add(json_row, "iAmRP");
			else
				json_object_boolean_false_add(json_row,
							      "iAmRP");

			if (rp_info->plist)
				json_object_string_add(json_row, "prefixList",
						       rp_info->plist);
			else
				json_object_string_addf(json_row, "group",
							"%pFX",
							&rp_info->group);
			json_object_string_add(json_row, "source", source);
			json_object_string_add(json_row, "groupType",
					       group_type);

			json_object_array_add(json_rp_rows, json_row);
		} else {
			prefix2str(&rp_info->group, grp, sizeof(grp));
			ttable_add_row(tt, "%pPA|%s|%s|%s|%s|%s",
					  &rp_info->rp.rpf_addr,
					  rp_info->plist
					  ? rp_info->plist
					  : grp,
					  rp_info->rp.source_nexthop.interface
					  ? rp_info->rp.source_nexthop
						.interface->name
						: "Unknown",
					  rp_info->i_am_rp
					  ? "yes"
					  : "no",
					  source, group_type);
		}
		prev_rp_info = rp_info;
	}

	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
		ttable_del(tt);
	} else {
		if (prev_rp_info && json_rp_rows)
			json_object_object_addf(json, json_rp_rows, "%pPA",
						&prev_rp_info->rp.rpf_addr);
	}
}

void pim_resolve_rp_nh(struct pim_instance *pim, struct pim_neighbor *nbr)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;
	struct nexthop *nh_node = NULL;
	pim_addr nht_p;
	struct pim_nexthop_cache pnc;

	for (ALL_LIST_ELEMENTS_RO(pim->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		nht_p = rp_info->rp.rpf_addr;
		memset(&pnc, 0, sizeof(struct pim_nexthop_cache));
		if (!pim_find_or_track_nexthop(pim, nht_p, NULL, rp_info, &pnc))
			continue;

		for (nh_node = pnc.nexthop; nh_node; nh_node = nh_node->next) {
#if PIM_IPV == 4
			if (!pim_addr_is_any(nh_node->gate.ipv4))
				continue;
#else
			if (!pim_addr_is_any(nh_node->gate.ipv6))
				continue;
#endif

			struct interface *ifp1 = if_lookup_by_index(
				nh_node->ifindex, pim->vrf->vrf_id);

			if (nbr->interface != ifp1)
				continue;

#if PIM_IPV == 4
			nh_node->gate.ipv4 = nbr->source_addr;
#else
			nh_node->gate.ipv6 = nbr->source_addr;
#endif
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug(
					"%s: addr %pPA new nexthop addr %pPAs interface %s",
					__func__, &nht_p, &nbr->source_addr,
					ifp1->name);
		}
	}
}
