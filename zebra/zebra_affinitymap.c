/*
 * zebra affinity-map.
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "lib/if.h"
#include "lib/vrf.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_affinitymap.h"

static bool zebra_affinity_map_check_use(const char *affmap_name)
{
	char xpath[XPATH_MAXLEN];
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			snprintf(xpath, sizeof(xpath),
				 "/frr-interface:lib/interface[name='%s']",
				 ifp->name);
			if (!yang_dnode_exists(running_config->dnode, xpath))
				continue;
			snprintf(
				xpath, sizeof(xpath),
				"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinities[affinity='%s']",
				ifp->name, affmap_name);
			if (yang_dnode_exists(running_config->dnode, xpath))
				return true;
		}
	}
	return false;
}

static bool zebra_affinity_map_check_update(const char *affmap_name,
					    uint16_t new_pos)
{
	char xpath[XPATH_MAXLEN];
	struct interface *ifp;
	struct vrf *vrf;

	/* check whether the affinity-map new bit position is upper than 31
	 * but is used on an interface on which affinity-mode is standard.
	 * Return false if the change is not possible.
	 */
	if (new_pos < 32)
		return true;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			snprintf(xpath, sizeof(xpath),
				 "/frr-interface:lib/interface[name='%s']",
				 ifp->name);
			if (!yang_dnode_exists(running_config->dnode, xpath))
				continue;
			snprintf(
				xpath, sizeof(xpath),
				"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinities[affinity='%s']",
				ifp->name, affmap_name);
			if (!yang_dnode_exists(running_config->dnode, xpath))
				continue;
			if (yang_dnode_get_enum(
				    running_config->dnode,
				    "/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinity-mode",
				    ifp->name) == AFFINITY_MODE_STANDARD)
				return false;
		}
	}
	return true;
}

static void zebra_affinity_map_update(const char *affmap_name, uint16_t old_pos,
				      uint16_t new_pos)
{
	struct if_link_params *iflp;
	enum affinity_mode aff_mode;
	char xpath[XPATH_MAXLEN];
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			snprintf(xpath, sizeof(xpath),
				 "/frr-interface:lib/interface[name='%s']",
				 ifp->name);
			if (!yang_dnode_exists(running_config->dnode, xpath))
				continue;
			snprintf(
				xpath, sizeof(xpath),
				"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinities[affinity='%s']",
				ifp->name, affmap_name);
			if (!yang_dnode_exists(running_config->dnode, xpath))
				continue;
			aff_mode = yang_dnode_get_enum(
				running_config->dnode,
				"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinity-mode",
				ifp->name);
			iflp = if_link_params_get(ifp);
			if (aff_mode == AFFINITY_MODE_EXTENDED ||
			    aff_mode == AFFINITY_MODE_BOTH) {
				admin_group_unset(&iflp->ext_admin_grp,
						  old_pos);
				admin_group_set(&iflp->ext_admin_grp, new_pos);
			}
			if (aff_mode == AFFINITY_MODE_STANDARD ||
			    aff_mode == AFFINITY_MODE_BOTH) {
				iflp->admin_grp &= ~(1 << old_pos);
				if (new_pos < 32)
					iflp->admin_grp |= 1 << new_pos;
				if (iflp->admin_grp == 0)
					UNSET_PARAM(iflp, LP_ADM_GRP);
			}
			if (if_is_operative(ifp))
				zebra_interface_parameters_update(ifp);
		}
	}
}

void zebra_affinity_map_init(void)
{
	affinity_map_init();

	affinity_map_set_check_use_hook(zebra_affinity_map_check_use);
	affinity_map_set_check_update_hook(zebra_affinity_map_check_update);
	affinity_map_set_update_hook(zebra_affinity_map_update);
}
