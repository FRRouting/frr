// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for staticd
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_ZEBRA_H__
#define __STATIC_ZEBRA_H__

#ifdef __cplusplus
extern "C" {
#endif

extern struct event_loop *master;

extern void static_zebra_nht_register(struct static_nexthop *nh, bool reg);

extern void static_zebra_route_add(struct static_path *pn, bool install);
extern void static_zebra_init(void);
/* static_zebra_stop used by tests/lib/test_grpc.cpp */
extern void static_zebra_stop(void);
extern void static_zebra_vrf_register(struct vrf *vrf);
extern void static_zebra_vrf_unregister(struct vrf *vrf);

#ifdef __cplusplus
}
#endif

#endif
