// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra L2 bridge interface data structures and definitions
 * These are public definitions referenced by other files.
 * Copyright (C) 2021 Cumulus Networks, Inc.
 * Sharath Ramamurthy
 */

#ifndef _ZEBRA_L2_BRIDGE_IF_H
#define _ZEBRA_L2_BRIDGE_IF_H

#include <zebra.h>
#include <zebra/zebra_router.h>

#include "linklist.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#include "lib/json.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"

#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bridge interface change flags of interest. */
#define ZEBRA_BRIDGEIF_ACCESS_BD_CHANGE (1 << 0)

extern struct zebra_l2_bridge_vlan *
zebra_l2_bridge_if_vlan_find(const struct zebra_if *zif, vlanid_t vid);
extern vni_t zebra_l2_bridge_if_vni_find(const struct zebra_if *zif,
					 vlanid_t vid);
extern void zebra_l2_bridge_if_vlan_iterate(
	struct zebra_if *zif,
	int (*func)(struct zebra_if *zif, struct zebra_l2_bridge_vlan *,
		    void *),
	void *arg);
extern void
zebra_l2_bridge_if_vlan_walk(struct zebra_if *zif,
			     int (*func)(struct zebra_if *zif,
					 struct zebra_l2_bridge_vlan *, void *),
			     void *arg);
extern int
zebra_l2_bridge_if_vlan_access_bd_deref(struct zebra_evpn_access_bd *bd);
extern int
zebra_l2_bridge_if_vlan_access_bd_ref(struct zebra_evpn_access_bd *bd);
extern int zebra_l2_bridge_if_del(struct interface *ifp);
extern int zebra_l2_bridge_if_add(struct interface *ifp);
extern int zebra_l2_bridge_if_cleanup(struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_L2_BRIDGE_IF_H */
