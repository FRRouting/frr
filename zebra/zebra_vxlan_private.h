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

#include "if.h"
#include "linklist.h"
#include "zebra_vxlan.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_STR_SZ 256

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;
typedef struct zebra_mac_t_ zebra_mac_t;
typedef struct zebra_neigh_t_ zebra_neigh_t;
typedef struct zebra_l3vni_t_ zebra_l3vni_t;

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_ {
	/* Remote IP. */
	/* NOTE: Can only be IPv4 right now. */
	struct in_addr vtep_ip;
	/* Flood mode (one of enum vxlan_flood_control) based on the PMSI
	 * tunnel type advertised by the remote VTEP
	 */
	int flood_control;

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
	uint8_t advertise_gw_macip;

	/* Flag for advertising svi macip */
	uint8_t advertise_svi_macip;

	/* Flag for advertising gw macip */
	uint8_t advertise_subnet;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* List of remote VTEPs */
	zebra_vtep_t *vteps;

	/* Local IP */
	struct in_addr local_vtep_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* tenant VRF, if any */
	vrf_id_t vrf_id;

	/* List of local or remote MAC */
	struct hash *mac_table;

	/* List of local or remote neighbors (MAC+IP) */
	struct hash *neigh_table;
};

/* L3 VNI hash table */
struct zebra_l3vni_t_ {

	/* VNI key */
	vni_t vni;

	/* vrf_id */
	vrf_id_t vrf_id;

	uint32_t filter;
#define PREFIX_ROUTES_ONLY	(1 << 0) /* l3-vni used for prefix routes only */

	/* Local IP */
	struct in_addr local_vtep_ip;

	/* kernel interface for l3vni */
	struct interface *vxlan_if;

	/* SVI interface corresponding to the l3vni */
	struct interface *svi_if;

	struct interface *mac_vlan_if;

	/* list of L2 VNIs associated with the L3 VNI */
	struct list *l2vnis;

	/* list of remote router-macs */
	struct hash *rmac_table;

	/* list of remote vtep-ip neigh */
	struct hash *nh_table;
};

/* get the vx-intf name for l3vni */
static inline const char *zl3vni_vxlan_if_name(zebra_l3vni_t *zl3vni)
{
	return zl3vni->vxlan_if ? zl3vni->vxlan_if->name : "None";
}

/* get the svi intf name for l3vni */
static inline const char *zl3vni_svi_if_name(zebra_l3vni_t *zl3vni)
{
	return zl3vni->svi_if ? zl3vni->svi_if->name : "None";
}

/* get the vrf name for l3vni */
static inline const char *zl3vni_vrf_name(zebra_l3vni_t *zl3vni)
{
	return vrf_id_to_name(zl3vni->vrf_id);
}

/* get the rmac string */
static inline const char *zl3vni_rmac2str(zebra_l3vni_t *zl3vni, char *buf,
					  int size)
{
	char *ptr;

	if (!buf)
		ptr = (char *)XMALLOC(MTYPE_TMP,
				      ETHER_ADDR_STRLEN * sizeof(char));
	else {
		assert(size >= ETHER_ADDR_STRLEN);
		ptr = buf;
	}

	if (zl3vni->mac_vlan_if)
		snprintf(ptr, (ETHER_ADDR_STRLEN),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[0],
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[1],
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[2],
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[3],
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[4],
			 (uint8_t)zl3vni->mac_vlan_if->hw_addr[5]);
	else if (zl3vni->svi_if)
		snprintf(ptr, (ETHER_ADDR_STRLEN),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 (uint8_t)zl3vni->svi_if->hw_addr[0],
			 (uint8_t)zl3vni->svi_if->hw_addr[1],
			 (uint8_t)zl3vni->svi_if->hw_addr[2],
			 (uint8_t)zl3vni->svi_if->hw_addr[3],
			 (uint8_t)zl3vni->svi_if->hw_addr[4],
			 (uint8_t)zl3vni->svi_if->hw_addr[5]);
	else
		snprintf(ptr, ETHER_ADDR_STRLEN, "None");

	return ptr;
}

/* get the sys mac string */
static inline const char *zl3vni_sysmac2str(zebra_l3vni_t *zl3vni, char *buf,
					    int size)
{
	char *ptr;

	if (!buf)
		ptr = (char *)XMALLOC(MTYPE_TMP,
				      ETHER_ADDR_STRLEN * sizeof(char));
	else {
		assert(size >= ETHER_ADDR_STRLEN);
		ptr = buf;
	}

	if (zl3vni->svi_if)
		snprintf(ptr, (ETHER_ADDR_STRLEN),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 (uint8_t)zl3vni->svi_if->hw_addr[0],
			 (uint8_t)zl3vni->svi_if->hw_addr[1],
			 (uint8_t)zl3vni->svi_if->hw_addr[2],
			 (uint8_t)zl3vni->svi_if->hw_addr[3],
			 (uint8_t)zl3vni->svi_if->hw_addr[4],
			 (uint8_t)zl3vni->svi_if->hw_addr[5]);
	else
		snprintf(ptr, ETHER_ADDR_STRLEN, "None");

	return ptr;
}

/*
 * l3-vni is oper up when:
 * 0. if EVPN is enabled (advertise-all-vni cfged)
 * 1. it is associated to a vxlan-intf
 * 2. Associated vxlan-intf is oper up
 * 3. it is associated to an SVI
 * 4. associated SVI is oper up
 */
static inline int is_l3vni_oper_up(zebra_l3vni_t *zl3vni)
{
	return (is_evpn_enabled() && zl3vni && (zl3vni->vrf_id != VRF_UNKNOWN)
		&& zl3vni->vxlan_if && if_is_operative(zl3vni->vxlan_if)
		&& zl3vni->svi_if && if_is_operative(zl3vni->svi_if));
}

static inline const char *zl3vni_state2str(zebra_l3vni_t *zl3vni)
{
	if (!zl3vni)
		return NULL;

	if (is_l3vni_oper_up(zl3vni))
		return "Up";
	else
		return "Down";

	return NULL;
}

static inline vrf_id_t zl3vni_vrf_id(zebra_l3vni_t *zl3vni)
{
	return zl3vni->vrf_id;
}

static inline void zl3vni_get_svi_rmac(zebra_l3vni_t *zl3vni,
				       struct ethaddr *rmac)
{
	if (!zl3vni)
		return;

	if (!is_l3vni_oper_up(zl3vni))
		return;

	if (zl3vni->svi_if && if_is_operative(zl3vni->svi_if))
		memcpy(rmac->octet, zl3vni->svi_if->hw_addr, ETH_ALEN);
}

struct host_rb_entry {
	RB_ENTRY(host_rb_entry) hl_entry;

	struct prefix p;
};

RB_HEAD(host_rb_tree_entry, host_rb_entry);
RB_PROTOTYPE(host_rb_tree_entry, host_rb_entry, hl_entry,
	     host_rb_entry_compare);
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

	uint32_t flags;
#define ZEBRA_MAC_LOCAL   0x01
#define ZEBRA_MAC_REMOTE  0x02
#define ZEBRA_MAC_AUTO    0x04  /* Auto created for neighbor. */
#define ZEBRA_MAC_STICKY  0x08  /* Static MAC */
#define ZEBRA_MAC_REMOTE_RMAC  0x10  /* remote router mac */
#define ZEBRA_MAC_DEF_GW  0x20
/* remote VTEP advertised MAC as default GW */
#define ZEBRA_MAC_REMOTE_DEF_GW	0x40
#define ZEBRA_MAC_DUPLICATE 0x80

	/* back pointer to zvni */
	zebra_vni_t     *zvni;

	/* Local or remote info. */
	union {
		struct {
			ifindex_t ifindex;
			vlanid_t vid;
		} local;

		struct in_addr r_vtep_ip;
	} fwd_info;

	/* Mobility sequence numbers associated with this entry. */
	uint32_t rem_seq;
	uint32_t loc_seq;

	/* List of neigh associated with this mac */
	struct list *neigh_list;

	/* list of hosts pointing to this remote RMAC */
	struct host_rb_tree_entry host_rb;

	/* Duplicate mac detection */
	uint32_t dad_count;

	struct thread *dad_mac_auto_recovery_timer;

	struct timeval detect_start_time;

	time_t dad_dup_detect_time;
};

/*
 * Context for MAC hash walk - used by callbacks.
 */
struct mac_walk_ctx {
	zebra_vni_t *zvni;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	uint32_t flags;
#define DEL_LOCAL_MAC                0x1
#define DEL_REMOTE_MAC               0x2
#define DEL_ALL_MAC                  (DEL_LOCAL_MAC | DEL_REMOTE_MAC)
#define DEL_REMOTE_MAC_FROM_VTEP     0x4
#define SHOW_REMOTE_MAC_FROM_VTEP    0x8

	struct in_addr r_vtep_ip; /* To walk MACs from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	uint32_t count;		  /* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
	bool print_dup; /* Used to print dup addr list */
};

struct rmac_walk_ctx {
	struct vty *vty;
	struct json_object *json;
};

#define IS_ZEBRA_NEIGH_ACTIVE(n) (n->state == ZEBRA_NEIGH_ACTIVE)

#define IS_ZEBRA_NEIGH_INACTIVE(n) (n->state == ZEBRA_NEIGH_INACTIVE)

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

	zebra_vni_t *zvni;

	uint32_t flags;
#define ZEBRA_NEIGH_LOCAL     0x01
#define ZEBRA_NEIGH_REMOTE    0x02
#define ZEBRA_NEIGH_REMOTE_NH    0x04 /* neigh entry for remote vtep */
#define ZEBRA_NEIGH_DEF_GW    0x08
#define ZEBRA_NEIGH_ROUTER_FLAG 0x10
#define ZEBRA_NEIGH_DUPLICATE 0x20
#define ZEBRA_NEIGH_SVI_IP 0x40

	enum zebra_neigh_state state;

	/* Remote VTEP IP - applicable only for remote neighbors. */
	struct in_addr r_vtep_ip;

	/*
	 * Mobility sequence numbers associated with this entry. The rem_seq
	 * represents the sequence number from the client (BGP) for the most
	 * recent add or update of this entry while the loc_seq represents
	 * the sequence number informed (or to be informed) by zebra to BGP
	 * for this entry.
	 */
	uint32_t rem_seq;
	uint32_t loc_seq;

	/* list of hosts pointing to this remote NH entry */
	struct host_rb_tree_entry host_rb;

	/* Duplicate ip detection */
	uint32_t dad_count;

	struct thread *dad_ip_auto_recovery_timer;

	struct timeval detect_start_time;

	time_t dad_dup_detect_time;
};

/*
 * Context for neighbor hash walk - used by callbacks.
 */
struct neigh_walk_ctx {
	zebra_vni_t *zvni;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	uint32_t flags;
#define DEL_LOCAL_NEIGH              0x1
#define DEL_REMOTE_NEIGH             0x2
#define DEL_ALL_NEIGH                (DEL_LOCAL_NEIGH | DEL_REMOTE_NEIGH)
#define DEL_REMOTE_NEIGH_FROM_VTEP   0x4
#define SHOW_REMOTE_NEIGH_FROM_VTEP  0x8

	struct in_addr r_vtep_ip; /* To walk neighbors from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	uint32_t count;		  /* Used by VTY handlers */
	uint8_t addr_width;       /* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
};

/* context for neigh hash walk - update l3vni and rmac */
struct neigh_l3info_walk_ctx {

	zebra_vni_t *zvni;
	zebra_l3vni_t *zl3vni;
	int add;
};

struct nh_walk_ctx {

	struct vty *vty;
	struct json_object *json;
};

extern zebra_l3vni_t *zl3vni_from_vrf(vrf_id_t vrf_id);
extern struct interface *zl3vni_map_to_vxlan_if(zebra_l3vni_t *zl3vni);
extern struct interface *zl3vni_map_to_svi_if(zebra_l3vni_t *zl3vni);
extern struct interface *zl3vni_map_to_mac_vlan_if(zebra_l3vni_t *zl3vni);

DECLARE_HOOK(zebra_rmac_update, (zebra_mac_t *rmac, zebra_l3vni_t *zl3vni,
	     bool delete, const char *reason), (rmac, zl3vni, delete, reason))


#ifdef __cplusplus
}
#endif

/*
 * Multicast hash table.
 *
 * This table contains -
 * 1. The (S, G) entries used for encapsulating and forwarding BUM traffic.
 *    S is the local VTEP-IP and G is a BUM mcast group address.
 * 2. The (X, G) entries used for terminating a BUM flow.
 * Multiple L2-VNIs can share the same MDT hence the need to maintain
 * an aggregated table that pimd can consume without much
 * re-interpretation.
 */
typedef struct zebra_vxlan_sg_ {
	struct zebra_vrf *zvrf;

	struct prefix_sg sg;
	char sg_str[PREFIX_SG_STR_LEN];

	/* For SG - num of L2 VNIs using this entry for sending BUM traffic */
	/* For XG - num of SG using this as parent */
	uint32_t ref_cnt;
} zebra_vxlan_sg_t;

#endif /* _ZEBRA_VXLAN_PRIVATE_H */
