// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for staticd
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_ZEBRA_H__
#define __STATIC_ZEBRA_H__

#include "static_srv6.h"

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

extern int static_zebra_srv6_manager_get_locator(const char *name);

extern void static_zebra_request_srv6_sid(struct static_srv6_sid *sid);
extern void static_zebra_release_srv6_sid(struct static_srv6_sid *sid);

extern void static_zebra_srv6_sid_install(struct static_srv6_sid *sid);
extern void static_zebra_srv6_sid_uninstall(struct static_srv6_sid *sid);

extern void static_zebra_send_neigh_discovery_req(struct interface *ifp, struct ipaddr *addr);
extern void static_zebra_neigh_get(struct interface *ifp, afi_t afi);
extern void static_zebra_neigh_register(afi_t afi, bool reg);

#ifdef __cplusplus
}
#endif

#endif
