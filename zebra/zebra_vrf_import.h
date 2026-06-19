// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra VRF route import
 */
#ifndef _ZEBRA_VRF_IMPORT_H
#define _ZEBRA_VRF_IMPORT_H

#include "zebra/rib.h"

struct zebra_vrf;

#ifdef __cplusplus
extern "C" {
#endif

void zebra_vrf_import_init(struct zebra_vrf *zvrf);
int zebra_vrf_import_add(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
			 const char *src_vrf_name, const char *rmap_name);
int zebra_vrf_import_del(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
			 const char *src_vrf_name);
void zebra_vrf_import_rib_update(struct route_node *rn, struct route_entry *old_selected,
				 struct route_entry *new_selected);
void zebra_vrf_import_route_map_update(const char *rmap_name);
void zebra_vrf_import_vrf_delete(struct zebra_vrf *zvrf);
void zebra_vrf_import_vrf_enable(struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VRF_IMPORT_H */
