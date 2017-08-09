/*
 * Zebra VxLAN (EVPN) Data structures and definitions
 * These are "internal" to this function.
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

#ifndef _ZEBRA_VXLAN_PRIVATE_H
#define _ZEBRA_VXLAN_PRIVATE_H

#include <zebra.h>

#include <zebra.h>

#include "if.h"
#include "linklist.h"

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;
typedef struct zebra_mac_t_ zebra_mac_t;
typedef struct zebra_neigh_t_ zebra_neigh_t;

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_ {
	/* Remote IP. */
	/* NOTE: Can only be IPv4 right now. */
	struct in_addr vtep_ip;

	/* Links. */
	struct zebra_vtep_t_ *next;
	struct zebra_vtep_t_ *prev;
};


/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_vni_t_ {
	/* VNI - key */
	vni_t vni;

	/* Flag for advertising gw macip */
	u_int8_t advertise_gw_macip;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* List of remote VTEPs */
	zebra_vtep_t *vteps;

	/* Local IP */
	struct in_addr local_vtep_ip;

	/* List of local or remote MAC */
	struct hash *mac_table;

	/* List of local or remote neighbors (MAC+IP) */
	struct hash *neigh_table;
};

/*
 * MAC hash table.
 *
 * This table contains the MAC addresses pertaining to this VNI.
 * This includes local MACs learnt on an attached VLAN that maps
 * to this VNI as well as remote MACs learnt and installed by BGP.
 * Local MACs will be known either on a VLAN sub-interface or
 * on (port, VLAN); however, it is sufficient for zebra to maintain
 * against the VNI i.e., it does not need to retain the local "port"
 * information. The correct VNI will be obtained as zebra maintains
 * the mapping (of VLAN to VNI).
 */
struct zebra_mac_t_ {
	/* MAC address. */
	struct ethaddr macaddr;

	u_int32_t flags;
#define ZEBRA_MAC_LOCAL   0x01
#define ZEBRA_MAC_REMOTE  0x02
#define ZEBRA_MAC_AUTO    0x04  /* Auto created for neighbor. */
#define ZEBRA_MAC_STICKY  0x08  /* Static MAC */

	/* Local or remote info. */
	union {
		struct {
			ifindex_t ifindex;
			vlanid_t vid;
		} local;

		struct in_addr r_vtep_ip;
	} fwd_info;

	/* List of neigh associated with this mac */
	struct list *neigh_list;
};

/*
 * Context for MAC hash walk - used by callbacks.
 */
struct mac_walk_ctx {
	zebra_vni_t *zvni;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	u_int32_t flags;
#define DEL_LOCAL_MAC                0x1
#define DEL_REMOTE_MAC               0x2
#define DEL_ALL_MAC                  (DEL_LOCAL_MAC | DEL_REMOTE_MAC)
#define DEL_REMOTE_MAC_FROM_VTEP     0x4
#define SHOW_REMOTE_MAC_FROM_VTEP    0x8

	struct in_addr r_vtep_ip; /* To walk MACs from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	u_int32_t count;	  /* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
};

enum zebra_neigh_state { ZEBRA_NEIGH_INACTIVE = 0, ZEBRA_NEIGH_ACTIVE = 1 };

#define IS_ZEBRA_NEIGH_ACTIVE(n) n->state == ZEBRA_NEIGH_ACTIVE

#define IS_ZEBRA_NEIGH_INACTIVE(n) n->state == ZEBRA_NEIGH_INACTIVE

#define ZEBRA_NEIGH_SET_ACTIVE(n) n->state = ZEBRA_NEIGH_ACTIVE

#define ZEBRA_NEIGH_SET_INACTIVE(n) n->state = ZEBRA_NEIGH_INACTIVE

/*
 * Neighbor hash table.
 *
 * This table contains the neighbors (IP to MAC bindings) pertaining to
 * this VNI. This includes local neighbors learnt on the attached VLAN
 * device that maps to this VNI as well as remote neighbors learnt and
 * installed by BGP.
 * Local neighbors will be known against the VLAN device (SVI); however,
 * it is sufficient for zebra to maintain against the VNI. The correct
 * VNI will be obtained as zebra maintains the mapping (of VLAN to VNI).
 */
struct zebra_neigh_t_ {
	/* IP address. */
	struct ipaddr ip;

	/* MAC address. */
	struct ethaddr emac;

	/* Underlying interface. */
	ifindex_t ifindex;

	u_int32_t flags;
#define ZEBRA_NEIGH_LOCAL     0x01
#define ZEBRA_NEIGH_REMOTE    0x02

	enum zebra_neigh_state state;

	/* Remote VTEP IP - applicable only for remote neighbors. */
	struct in_addr r_vtep_ip;
};

/*
 * Context for neighbor hash walk - used by callbacks.
 */
struct neigh_walk_ctx {
	zebra_vni_t *zvni;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	u_int32_t flags;
#define DEL_LOCAL_NEIGH              0x1
#define DEL_REMOTE_NEIGH             0x2
#define DEL_ALL_NEIGH                (DEL_LOCAL_NEIGH | DEL_REMOTE_NEIGH)
#define DEL_REMOTE_NEIGH_FROM_VTEP   0x4
#define SHOW_REMOTE_NEIGH_FROM_VTEP  0x8

	struct in_addr r_vtep_ip; /* To walk neighbors from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	u_int32_t count;	  /* Used by VTY handlers */
	u_char addr_width;	/* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
};

#endif /* _ZEBRA_VXLAN_PRIVATE_H */
