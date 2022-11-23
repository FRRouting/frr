/*
 * IP SSM ranges for FRR
 * Copyright (C) 2017 Cumulus Networks, Inc.
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

#include <lib/linklist.h>
#include <lib/prefix.h>
#include <lib/vty.h>
#include <lib/vrf.h>
#include <lib/plist.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_instance.h"
#include "pim_ssm.h"
#include "pim_igmp.h"

static void pim_ssm_range_reevaluate(struct pim_instance *pim)
{
#if PIM_IPV == 4
	/* 1. Setup register state for (S,G) entries if G has changed from SSM
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

void pim_ssm_prefix_list_update(struct pim_instance *pim,
				struct prefix_list *plist)
{
	struct pim_ssm *ssm = pim->ssm_info;

	if (!ssm->plist_name
	    || strcmp(ssm->plist_name, prefix_list_name(plist))) {
		/* not ours */
		return;
	}

	pim_ssm_range_reevaluate(pim);
}

static int pim_is_grp_standard_ssm(struct prefix *group)
{
	pim_addr addr = pim_addr_from_prefix(group);

	return pim_addr_ssm(addr);
}

int pim_is_grp_ssm(struct pim_instance *pim, pim_addr group_addr)
{
	struct pim_ssm *ssm;
	struct prefix group;
	struct prefix_list *plist;

	pim_addr_to_prefix(&group, group_addr);

	ssm = pim->ssm_info;
	if (!ssm->plist_name) {
		return pim_is_grp_standard_ssm(&group);
	}

	plist = prefix_list_lookup(PIM_AFI, ssm->plist_name);
	if (!plist)
		return 0;

	return (prefix_list_apply_ext(plist, NULL, &group, true) ==
		PREFIX_PERMIT);
}

int pim_ssm_range_set(struct pim_instance *pim, vrf_id_t vrf_id,
		      const char *plist_name)
{
	struct pim_ssm *ssm;
	int change = 0;

	if (vrf_id != pim->vrf->vrf_id)
		return PIM_SSM_ERR_NO_VRF;

	ssm = pim->ssm_info;
	if (plist_name) {
		if (ssm->plist_name) {
			if (!strcmp(ssm->plist_name, plist_name))
				return PIM_SSM_ERR_DUP;
			XFREE(MTYPE_PIM_FILTER_NAME, ssm->plist_name);
		}
		ssm->plist_name = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist_name);
		change = 1;
	} else {
		if (ssm->plist_name) {
			change = 1;
			XFREE(MTYPE_PIM_FILTER_NAME, ssm->plist_name);
		}
	}

	if (change)
		pim_ssm_range_reevaluate(pim);

	return PIM_SSM_ERR_NONE;
}

void *pim_ssm_init(void)
{
	struct pim_ssm *ssm;

	ssm = XCALLOC(MTYPE_PIM_SSM_INFO, sizeof(*ssm));

	return ssm;
}

void pim_ssm_terminate(struct pim_ssm *ssm)
{
	if (!ssm)
		return;

	XFREE(MTYPE_PIM_FILTER_NAME, ssm->plist_name);

	XFREE(MTYPE_PIM_SSM_INFO, ssm);
}
