// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra routemap header
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef __ZEBRA_ROUTEMAP_H__
#define __ZEBRA_ROUTEMAP_H__

#include "lib/routemap.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_route_map_init(void);
extern void zebra_routemap_config_write_protocol(struct vty *vty,
						 struct zebra_vrf *vrf);
extern char *zebra_get_import_table_route_map(afi_t afi, uint32_t table);
extern void zebra_add_import_table_route_map(afi_t afi, const char *rmap_name,
					     uint32_t table);
extern void zebra_del_import_table_route_map(afi_t afi, uint32_t table);

extern route_map_result_t
zebra_import_table_route_map_check(int family, int rib_type, uint8_t instance,
				   const struct prefix *p,
				   struct nexthop *nexthop, vrf_id_t vrf_id,
				   route_tag_t tag, const char *rmap_name);
extern route_map_result_t
zebra_route_map_check(afi_t family, int rib_type, uint8_t instance,
		      const struct prefix *p, struct nexthop *nexthop,
		      struct zebra_vrf *zvrf, route_tag_t tag);
extern route_map_result_t
zebra_nht_route_map_check(afi_t afi, int client_proto, const struct prefix *p,
			  struct zebra_vrf *zvrf, struct route_entry *,
			  struct nexthop *nexthop);

extern void zebra_routemap_vrf_delete(struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

extern void zebra_routemap_finish(void);

extern const struct frr_yang_module_info frr_zebra_route_map_info;
#endif
