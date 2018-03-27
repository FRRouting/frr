/*
 * Zebra Layer-2 interface Data structures and definitions
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_L2_H
#define _ZEBRA_L2_H

#include <zebra.h>

#include "if.h"
#include "vlan.h"
#include "vxlan.h"

/* zebra L2 interface information - bridge slave (linkage to bridge) */
struct zebra_l2info_brslave {
	ifindex_t bridge_ifindex; /* Bridge Master */
	struct interface *br_if;  /* Pointer to master */
};

/* zebra L2 interface information - bridge interface */
struct zebra_l2info_bridge {
	uint8_t vlan_aware; /* VLAN-aware bridge? */
};

/* zebra L2 interface information - VLAN interface */
struct zebra_l2info_vlan {
	vlanid_t vid; /* VLAN id */
};

/* zebra L2 interface information - VXLAN interface */
struct zebra_l2info_vxlan {
	vni_t vni;		/* VNI */
	struct in_addr vtep_ip; /* Local tunnel IP */
	vlanid_t access_vlan;   /* Access VLAN - for VLAN-aware bridge. */
};

union zebra_l2if_info {
	struct zebra_l2info_bridge br;
	struct zebra_l2info_vlan vl;
	struct zebra_l2info_vxlan vxl;
};

/* NOTE: These macros are to be invoked only in the "correct" context.
 * IOW, the macro VNI_FROM_ZEBRA_IF() will assume the interface is
 * of type ZEBRA_IF_VXLAN.
 */
#define VNI_FROM_ZEBRA_IF(zif) (zif)->l2info.vxl.vni
#define VLAN_ID_FROM_ZEBRA_IF(zif) (zif)->l2info.vl.vid

#define IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif) ((zif)->l2info.br.vlan_aware == 1)

extern void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave);
extern void
zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave);
extern void zebra_l2_bridge_add_update(struct interface *ifp,
				       struct zebra_l2info_bridge *bridge_info,
				       int add);
extern void zebra_l2_bridge_del(struct interface *ifp);
extern void zebra_l2_vlanif_update(struct interface *ifp,
				   struct zebra_l2info_vlan *vlan_info);
extern void zebra_l2_vxlanif_add_update(struct interface *ifp,
					struct zebra_l2info_vxlan *vxlan_info,
					int add);
extern void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
						vlanid_t access_vlan);
extern void zebra_l2_vxlanif_del(struct interface *ifp);
extern void zebra_l2if_update_bridge_slave(struct interface *ifp,
					   ifindex_t bridge_ifindex);

#endif /* _ZEBRA_L2_H */
