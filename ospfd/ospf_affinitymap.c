// SPDX-License-Identifier: GPL-2.0-or-later
/* OSPFv2  affinity-map
 * Copyright 2023 VMware, Inc.
 *		Pushpasis Sarkar <pushpasis@gmail.com>
 */

#include <zebra.h>
#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/mpls.h"
#include "ospfd/ospfd.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_affinitymap.h"

static bool ospf_affinity_map_check_use(const char *affmap_name)
{
        struct listnode *curr, *next;
	struct flex_algo *fad;
	struct affinity_map *map;
	uint16_t pos;

	map = affinity_map_get(affmap_name);
	pos = map->bit_position;

	FOREACH_FLEX_ALGO_DEFN(OspfRI.fad_info.fads, curr, next, fad) {
		if (admin_group_get(&fad->admin_group_exclude_any, pos) ||
		admin_group_get(&fad->admin_group_include_any, pos) ||
		admin_group_get(&fad->admin_group_include_all, pos))
			return true;
	}
	return false;
}

static void ospf_affinity_map_update(const char *affmap_name, uint16_t old_pos,
				     uint16_t new_pos)
{
        struct listnode *curr, *next;
	struct flex_algo *fad;
	bool changed;

	changed = false;
	FOREACH_FLEX_ALGO_DEFN(OspfRI.fad_info.fads, curr, next, fad) {
		if (admin_group_get(&fad->admin_group_exclude_any, old_pos)) {
			admin_group_unset(&fad->admin_group_exclude_any,
					  old_pos);
			admin_group_set(&fad->admin_group_exclude_any,
					new_pos);
			changed = true;
		}
		if (admin_group_get(&fad->admin_group_include_any, old_pos)) {
			admin_group_unset(&fad->admin_group_include_any,
					  old_pos);
			admin_group_set(&fad->admin_group_include_any,
					new_pos);
			changed = true;
		}
		if (admin_group_get(&fad->admin_group_include_all, old_pos)) {
			admin_group_unset(&fad->admin_group_include_all,
					  old_pos);
			admin_group_set(&fad->admin_group_include_all,
					new_pos);
			changed = true;
		}
	}

	if (changed)
		ospf_router_info_schedule(REFRESH_THIS_LSA);
}

void ospf_affinity_map_init(void)
{
	affinity_map_init();
	affinity_map_set_nb_bypass(true);

	affinity_map_set_check_use_hook(ospf_affinity_map_check_use);
	affinity_map_set_update_hook(ospf_affinity_map_update);
}
