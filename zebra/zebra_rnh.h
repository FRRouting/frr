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
				 struct zserv *client, bool *exists);
extern struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi,
				    struct zserv *client);
extern void zebra_free_rnh(struct rnh *rnh);
extern void zebra_rnh_node_cleanup(struct route_node *node);
extern void zebra_add_rnh_client(struct rnh *rnh, struct zserv *client,
				 vrf_id_t vrfid);

/* Callback function for iterating through RNHs for a prefix.
 * Return non-zero to stop iteration early.
 */
typedef int (*rnh_iter_cb)(struct rnh *rnh, void *ctx);

/* Iterate through all RNHs registered for a given prefix.
 * Returns number of RNHs processed.
 */
extern int zebra_rnh_iterate_prefix(struct prefix *p, vrf_id_t vrfid, safi_t safi, rnh_iter_cb cb,
				    void *ctx);
extern int zebra_send_rnh_update(struct rnh *rnh, struct zserv *client,
				 vrf_id_t vrf_id, uint32_t srte_color);
extern void zebra_register_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw, bool *nht_exists);
extern void zebra_deregister_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw);
extern void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client);
extern void zebra_evaluate_rnh(struct zebra_vrf *zvrf, afi_t afi, int force,
			       const struct prefix *p, safi_t safi);
extern void zebra_print_rnh_table(vrf_id_t vrfid, afi_t afi, safi_t safi,
				  struct vty *vty, const struct prefix *p,
				  struct json_object *json);

extern int rnh_resolve_via_default(struct zebra_vrf *zvrf, int family);

extern bool rnh_nexthop_valid(const struct route_entry *re,
			      const struct nexthop *nh);

void show_nexthop_json_helper(struct json_object *json_nexthop,
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
