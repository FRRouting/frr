// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra next hop tracking header
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_RNH_H
#define _ZEBRA_RNH_H

#include "prefix.h"
#include "vty.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_rnh_init(void);

extern struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi,
				 bool *exists);
extern struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid,
				    safi_t safi);
extern void zebra_free_rnh(struct rnh *rnh);
extern void zebra_add_rnh_client(struct rnh *rnh, struct zserv *client,
				 vrf_id_t vrfid);
extern int zebra_send_rnh_update(struct rnh *rnh, struct zserv *client,
				 vrf_id_t vrf_id, uint32_t srte_color);
extern void zebra_register_rnh_pseudowire(vrf_id_t, struct zebra_pw *, bool *);
extern void zebra_deregister_rnh_pseudowire(vrf_id_t, struct zebra_pw *);
extern void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client);
extern void zebra_evaluate_rnh(struct zebra_vrf *zvrf, afi_t afi, int force,
			       const struct prefix *p, safi_t safi);
extern void zebra_print_rnh_table(vrf_id_t vrfid, afi_t afi, safi_t safi,
				  struct vty *vty, const struct prefix *p,
				  json_object *json);

extern int rnh_resolve_via_default(struct zebra_vrf *zvrf, int family);

extern bool rnh_nexthop_valid(const struct route_entry *re,
			      const struct nexthop *nh);

/* UI control to avoid notifications if backup nexthop status changes */
void rnh_set_hide_backups(bool hide_p);
bool rnh_get_hide_backups(void);

void show_nexthop_json_helper(json_object *json_nexthop,
			      const struct nexthop *nexthop,
			      const struct route_node *rn,
			      const struct route_entry *re);
void show_route_nexthop_helper(struct vty *vty, const struct route_node *rn,
			       const struct route_entry *re,
			       const struct nexthop *nexthop);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_RNH_H */
