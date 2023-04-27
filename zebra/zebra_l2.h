// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Layer-2 interface Data structures and definitions
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_L2_H
#define _ZEBRA_L2_H

#include <zebra.h>

#include "if.h"
#include "vlan.h"
#include "vxlan.h"
#include "zebra/zebra_vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZEBRA_BRIDGE_NO_ACTION (0)
#define ZEBRA_BRIDGE_MASTER_MAC_CHANGE (1 << 1)
#define ZEBRA_BRIDGE_MASTER_UP (1 << 2)

/* zebra L2 interface information - bridge slave (linkage to bridge) */
struct zebra_l2info_brslave {
	ifindex_t bridge_ifindex; /* Bridge Master */
	struct interface *br_if;  /* Pointer to master */
	ns_id_t ns_id; /* network namespace where bridge is */
};

struct zebra_l2info_bond {
	struct list *mbr_zifs; /* slaves using this bond as a master */
};

struct zebra_l2_bridge_vlan {
	vlanid_t vid;
	struct zebra_evpn_access_bd *access_bd;
};

struct zebra_l2_bridge_if_ctx {
	/* input */
	struct zebra_if *zif;
	int (*func)(struct zebra_if *zif, struct zebra_l2_bridge_vlan *vlan,
		    void *arg);

	/* input-output */
	void *arg;
};

struct zebra_l2_bridge_if {
	uint8_t vlan_aware;
	struct zebra_if *br_zif;
	struct hash *vlan_table;
};

/* zebra L2 interface information - bridge interface */
struct zebra_l2info_bridge {
	struct zebra_l2_bridge_if bridge;
};

/* zebra L2 interface information - VLAN interface */
struct zebra_l2info_vlan {
	vlanid_t vid; /* VLAN id */
};

/* zebra L2 interface information - GRE interface */
struct zebra_l2info_gre {
	struct in_addr vtep_ip; /* IFLA_GRE_LOCAL */
	struct in_addr vtep_ip_remote; /* IFLA_GRE_REMOTE */
	uint32_t ikey;
	uint32_t okey;
	ifindex_t ifindex_link; /* Interface index of interface
				 * linked with GRE
				 */
	ns_id_t link_nsid;
};

struct zebra_vxlan_vni {
	vni_t vni;	      /* VNI */
	vlanid_t access_vlan; /* Access VLAN - for VLAN-aware bridge. */
	struct in_addr mcast_grp;
	uint16_t flags;
};

struct zebra_vxlan_vni_array {
	uint16_t count;
	struct zebra_vxlan_vni vnis[0];
};

enum {
	ZEBRA_VXLAN_IF_VNI = 0, /* per vni vxlan if */
	ZEBRA_VXLAN_IF_SVD	/* single vxlan device */
};

struct zebra_vxlan_if_vlan_ctx {
	vlanid_t vid;
	struct zebra_vxlan_vni *vni;
};

struct zebra_vxlan_if_update_ctx {
	uint16_t chgflags;
	struct in_addr old_vtep_ip;
	struct zebra_vxlan_vni old_vni;
	struct hash *old_vni_table;
};

struct zebra_vxlan_if_ctx {
	/* input */
	struct zebra_if *zif;
	int (*func)(struct zebra_if *zif, struct zebra_vxlan_vni *vni,
		    void *arg);

	/* input-output */
	void *arg;
};

struct zebra_vxlan_vni_info {
	int iftype;
	union {
		struct zebra_vxlan_vni vni; /* per vni vxlan device vni info */
		struct hash
			*vni_table; /* table of vni's assocated with this if */
	};
};

/* zebra L2 interface information - VXLAN interface */
struct zebra_l2info_vxlan {
	struct zebra_vxlan_vni_info vni_info;
	struct in_addr vtep_ip; /* Local tunnel IP */
	ifindex_t ifindex_link; /* Interface index of interface
				 * linked with VXLAN
				 */
	ns_id_t link_nsid;
};

struct zebra_l2info_bondslave {
	ifindex_t bond_ifindex;    /* Bridge Master */
	struct interface *bond_if; /* Pointer to master */
};

union zebra_l2if_info {
	struct zebra_l2info_bridge br;
	struct zebra_l2info_vlan vl;
	struct zebra_l2info_vxlan vxl;
	struct zebra_l2info_gre gre;
};

/* NOTE: These macros are to be invoked only in the "correct" context.
 * IOW, the macro VNI_FROM_ZEBRA_IF() will assume the interface is
 * of type ZEBRA_IF_VXLAN.
 */
#define VNI_INFO_FROM_ZEBRA_IF(zif) (&((zif)->l2info.vxl.vni_info))
#define IS_ZEBRA_VXLAN_IF_SVD(zif)                                             \
	((zif)->l2info.vxl.vni_info.iftype == ZEBRA_VXLAN_IF_SVD)
#define IS_ZEBRA_VXLAN_IF_VNI(zif)                                             \
	((zif)->l2info.vxl.vni_info.iftype == ZEBRA_VXLAN_IF_VNI)
#define VLAN_ID_FROM_ZEBRA_IF(zif) (zif)->l2info.vl.vid

#define BRIDGE_FROM_ZEBRA_IF(zif) (&((zif)->l2info.br.bridge))
#define IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif)                                     \
	((zif)->l2info.br.bridge.vlan_aware == 1)

extern void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave,
					 struct zebra_ns *zns);
extern void
zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave);
extern void
zebra_l2_bridge_add_update(struct interface *ifp,
			   const struct zebra_l2info_bridge *bridge_info);
extern void zebra_l2_bridge_del(struct interface *ifp);
extern void zebra_l2_vlanif_update(struct interface *ifp,
				   const struct zebra_l2info_vlan *vlan_info);
extern void zebra_l2_greif_add_update(struct interface *ifp,
				      const struct zebra_l2info_gre *vxlan_info,
				      int add);
extern void
zebra_l2_vxlanif_add_update(struct interface *ifp,
			    const struct zebra_l2info_vxlan *vxlan_info,
			    int add);
extern void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
						vlanid_t access_vlan);
extern void zebra_l2_greif_del(struct interface *ifp);
extern void zebra_l2_vxlanif_del(struct interface *ifp);
extern void zebra_l2if_update_bridge_slave(struct interface *ifp,
					   ifindex_t bridge_ifindex,
					   ns_id_t ns_id, uint8_t chgflags);

extern void zebra_l2if_update_bond_slave(struct interface *ifp,
					 ifindex_t bond_ifindex, bool bypass);
extern void zebra_vlan_bitmap_compute(struct interface *ifp,
		uint32_t vid_start, uint16_t vid_end);
extern void zebra_vlan_mbr_re_eval(struct interface *ifp,
		bitfield_t vlan_bitmap);
extern void zebra_l2if_update_bond(struct interface *ifp, bool add);
extern void zebra_l2if_update_bridge(struct interface *ifp, uint8_t chgflags);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_L2_H */
