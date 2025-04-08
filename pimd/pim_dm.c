// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_dm.c: PIM Dense Mode
 *
 * Copyright (C) 2024 ATCorp
 * Jafar Al-Gharaibeh
 */

#include <zebra.h>

#include <lib/linklist.h>
#include <lib/prefix.h>
#include <lib/vty.h>
#include <lib/vrf.h>
#include <lib/plist.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_pim.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_dm.h"
#include "pim_igmp.h"
#include "pim_join.h"

static void pim_dm_range_reevaluate(struct pim_instance *pim)
{
#if PIM_IPV == 4
	/* 1. Setup register state for (S,G) entries if G has changed from DM
	 * to
	 *    ASM.
	 * 2. check existing (*,G) IGMP registrations to see if they are
	 * still ASM. if they are now SSM delete them.
	 * 3. Allow channel setup for IGMP (*,G) members if G is now ASM
	 * 4. I could tear down all (*,G), (S,G,rpt) states. But that is an
	 * unnecessary sladge hammer and may not be particularly useful as it is
	 * likely the SPT switchover has already happened for flows along such
	 * RPTs.
	 * As for the RPT states it seems that the best thing to do is let them
	 * age
	 * out gracefully. As long as the FHR and LHR do the right thing RPTs
	 * will
	 * disappear in time for SSM groups.
	 */
	pim_upstream_register_reevaluate(pim);
	igmp_source_forward_reevaluate_all(pim);
#endif
}

void pim_dm_change_iif_mode(struct interface *ifp, enum pim_iface_mode mode)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct channel_oil *c_oil;

	if (!pim_ifp)
		return;

	if (HAVE_DENSE_MODE(mode) && !HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
		/* Enabling Dense Mode on the interface
		* If it has no neighbors and no IGMP joins to a dense group, then nothing else to do.
		* Otherwise, go through all installed multicast routes with dense groups and add this interface to the OIL.
		* Also check if the route upstream is using a dense mode interface, or the group is joined somewhere, and it's set to prune
		* then turn off the prune and instead send a graft
		*/

		if (listcount(pim_ifp->pim_neighbor_list) > 0 || pim_dm_check_gm_group_list(ifp)) {
			frr_each (rb_pim_oil, &pim_ifp->pim->channel_oil_head, c_oil) {
				if (pim_is_grp_dm(pim_ifp->pim, *oil_mcastgrp(c_oil)) &&
				    c_oil->installed) {
					oil_if_set(c_oil, pim_ifp->mroute_vif_index, 1);
					pim_upstream_mroute_update(c_oil, __func__);
				}
			}
		}
	} else if (!HAVE_DENSE_MODE(mode) && HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
		frr_each (rb_pim_oil, &pim_ifp->pim->channel_oil_head, c_oil) {
			if (pim_is_grp_dm(pim_ifp->pim, *oil_mcastgrp(c_oil)) && c_oil->installed) {
				oil_if_set(c_oil, pim_ifp->mroute_vif_index, 0);
				pim_upstream_mroute_update(c_oil, __func__);
			}
		}
	}

	pim_ifp->pim_mode = mode;
}


bool pim_dm_check_gm_group_list(struct interface *ifp)
{
	struct listnode *node;
	struct listnode *nextnode;
	struct gm_group *ij;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	if (!pim_ifp->gm_group_list)
		return false;
	for (ALL_LIST_ELEMENTS(pim_ifp->gm_group_list, node, nextnode, ij))
		if (pim_is_grp_dm(pim_ifp->pim, ij->group_addr))
			return true;

	return false;
}

void pim_dm_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist)
{
	struct pim_dm *dm = pim->dm_info;

	if (!dm->plist_name || strcmp(dm->plist_name, prefix_list_name(plist))) {
		/* not ours */
		return;
	}

	pim_dm_range_reevaluate(pim);
}

bool pim_is_grp_dm(struct pim_instance *pim, pim_addr group_addr)
{
	struct pim_dm *dm;
	struct prefix group;
	struct prefix_list *plist;

	dm = pim->dm_info;

	plist = prefix_list_lookup(PIM_AFI, dm->plist_name);
	if (!plist)
		return false;

	pim_addr_to_prefix(&group, group_addr);

	return (prefix_list_apply_ext(plist, NULL, &group, true) == PREFIX_PERMIT);
}

int pim_dm_range_set(struct pim_instance *pim, const char *plist_name)
{
	struct pim_dm *dm = pim->dm_info;
	bool reeval = false;

	if (plist_name) {
		if (dm->plist_name) {
			if (strmatch(dm->plist_name, plist_name))
				return PIM_DM_ERR_DUP;
			XFREE(MTYPE_PIM_FILTER_NAME, dm->plist_name);
		}
		dm->plist_name = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist_name);
		reeval = true;
	} else if (dm->plist_name) {
		reeval = true;
		XFREE(MTYPE_PIM_FILTER_NAME, dm->plist_name);
	}

	if (reeval)
		pim_dm_range_reevaluate(pim);

	return PIM_DM_ERR_NONE;
}

void pim_dm_init(struct pim_instance *pim)
{
	struct pim_dm *dm;

	dm = XCALLOC(MTYPE_PIM_DM_INFO, sizeof(*dm));
	pim->dm_info = dm;
}

void pim_dm_terminate(struct pim_instance *pim)
{
	if (pim->dm_info) {
		if (pim->dm_info->plist_name)
			XFREE(MTYPE_PIM_FILTER_NAME, pim->dm_info->plist_name);
		XFREE(MTYPE_PIM_DM_INFO, pim->dm_info);
	}
}
