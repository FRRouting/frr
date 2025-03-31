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
extern char *zebra_get_import_table_route_map(afi_t afi, safi_t safi, uint32_t table);
extern void zebra_add_import_table_route_map(afi_t afi, safi_t safi, const char *rmap_name,
					     uint32_t table);
extern void zebra_del_import_table_route_map(afi_t afi, safi_t safi, uint32_t table);

extern route_map_result_t zebra_import_table_route_map_check(
	int family, struct route_entry *re, const struct prefix *p,
	struct nexthop *nexthop, const char *rmap_name);
extern route_map_result_t zebra_route_map_check(afi_t family,
						struct route_entry *re,
						const struct prefix *p,
						struct nexthop *nexthop,
						struct zebra_vrf *zvrf);
extern route_map_result_t zebra_nht_route_map_check(afi_t afi, int client_proto,
						    const struct prefix *p,
						    struct zebra_vrf *zvrf,
						    struct route_entry *re,
						    struct nexthop *nexthop);

extern void zebra_route_map_set_delay_timer(uint32_t value);
extern int ip_protocol_rm_add(struct zebra_vrf *zvrf, const char *rmap,
			      int rtype, afi_t afi, safi_t safi);
extern int ip_protocol_rm_del(struct zebra_vrf *zvrf, const char *rmap,
			      int rtype, afi_t afi, safi_t safi);
extern int ip_nht_rm_add(struct zebra_vrf *zvrf, const char *rmap, int rtype,
			 int afi);
extern int ip_nht_rm_del(struct zebra_vrf *zvrf, const char *rmap, int rtype,
			 int afi);

extern void zebra_routemap_vrf_delete(struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

extern void zebra_routemap_finish(void);

extern const struct frr_yang_module_info frr_zebra_route_map_info;
#endif
