// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

/* Get the VRR interface for SVI if any */
static inline struct interface *
zebra_get_vrr_intf_for_svi(struct interface *ifp)
{
	struct zebra_vrf *zvrf = NULL;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif = NULL;

	zvrf = ifp->vrf->info;
	assert(zvrf);

	FOR_ALL_INTERFACES (zvrf->vrf, tmp_if) {
		zif = tmp_if->info;
		if (!zif)
			continue;

		if (!IS_ZEBRA_IF_MACVLAN(tmp_if))
			continue;

		if (zif->link == ifp)
			return tmp_if;
	}

	return NULL;
}

/* EVPN<=>vxlan_zif association */
static inline void zevpn_vxlan_if_set(struct zebra_evpn *zevpn,
				      struct interface *ifp, bool set)
{
	struct zebra_if *zif;

	if (set) {
		if (zevpn->vxlan_if == ifp)
			return;
		zevpn->vxlan_if = ifp;
	} else {
		if (!zevpn->vxlan_if)
			return;
		zevpn->vxlan_if = NULL;
	}

	if (ifp)
		zif = ifp->info;
	else
		zif = NULL;

	zebra_evpn_vxl_evpn_set(zif, zevpn, set);
}

/* EVPN<=>Bridge interface association */
static inline void zevpn_bridge_if_set(struct zebra_evpn *zevpn,
				       struct interface *ifp, bool set)
{
	if (set) {
		if (zevpn->bridge_if == ifp)
			return;
		zevpn->bridge_if = ifp;
	} else {
		if (!zevpn->bridge_if)
			return;
		zevpn->bridge_if = NULL;
	}
}

/* EVPN<=>Bridge interface association */
static inline void zl3vni_bridge_if_set(struct zebra_l3vni *zl3vni,
					struct interface *ifp, bool set)
{
	if (set) {
		if (zl3vni->bridge_if == ifp)
			return;
		zl3vni->bridge_if = ifp;
	} else {
		if (!zl3vni->bridge_if)
			return;
		zl3vni->bridge_if = NULL;
	}
}
