// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for PBR
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __PBR_ZEBRA_H__
#define __PBR_ZEBRA_H__

struct pbr_interface {
	char mapname[100];
};

extern struct event_loop *master;

extern void pbr_zebra_init(void);
extern void pbr_zebra_destroy(void);

extern void route_add(struct pbr_nexthop_group_cache *pnhgc,
		      struct nexthop_group nhg, afi_t install_afi);
extern void route_delete(struct pbr_nexthop_group_cache *pnhgc,
			 afi_t install_afi);

extern void pbr_send_rnh(struct nexthop *nhop, bool reg);

extern bool pbr_send_pbr_map(struct pbr_map_sequence *pbrms,
			     struct pbr_map_interface *pmi, bool install,
			     bool changed);

extern struct pbr_interface *pbr_if_new(struct interface *ifp);

extern int pbr_ifp_create(struct interface *ifp);
extern int pbr_ifp_up(struct interface *ifp);
extern int pbr_ifp_down(struct interface *ifp);
extern int pbr_ifp_destroy(struct interface *ifp);

/* Free the ifp->info pointer */
extern void pbr_if_del(struct interface *ifp);

#endif
