// SPDX-License-Identifier: GPL-2.0-or-later
/* IS-IS  affinity-map
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>
#include "lib/if.h"
#include "lib/vrf.h"
#include "isisd/isisd.h"
#include "isisd/isis_affinitymap.h"

#ifndef FABRICD

static void isis_affinity_map_update(const char *affmap_name, uint16_t old_pos,
				     uint16_t new_pos)
{
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	struct listnode *area_node, *fa_node;
	struct isis_area *area;
	struct flex_algo *fa;
	bool changed;

	if (!isis)
		return;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area)) {
		changed = false;
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, fa_node,
					  fa)) {
			if (admin_group_get(&fa->admin_group_exclude_any,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_exclude_any,
						  old_pos);
				admin_group_set(&fa->admin_group_exclude_any,
						new_pos);
				changed = true;
			}
			if (admin_group_get(&fa->admin_group_include_any,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_include_any,
						  old_pos);
				admin_group_set(&fa->admin_group_include_any,
						new_pos);
				changed = true;
			}
			if (admin_group_get(&fa->admin_group_include_all,
					    old_pos)) {
				admin_group_unset(&fa->admin_group_include_all,
						  old_pos);
				admin_group_set(&fa->admin_group_include_all,
						new_pos);
				changed = true;
			}
		}
		if (changed)
			lsp_regenerate_schedule(area, area->is_type, 0);
	}
}

void isis_affinity_map_init(void)
{
	affinity_map_init();

	affinity_map_set_update_hook(isis_affinity_map_update);
}

#endif /* ifndef FABRICD */
