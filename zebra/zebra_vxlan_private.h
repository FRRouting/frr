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
#include "zebra_evpn.h"
#include "zebra_evpn_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_STR_SZ 256

/* L3 VNI hash table */
struct zebra_l3vni {

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
static inline const char *zl3vni_vxlan_if_name(struct zebra_l3vni *zl3vni)
{
	return zl3vni->vxlan_if ? zl3vni->vxlan_if->name : "None";
}

/* get the svi intf name for l3vni */
static inline const char *zl3vni_svi_if_name(struct zebra_l3vni *zl3vni)
{
	return zl3vni->svi_if ? zl3vni->svi_if->name : "None";
}

/* get the vrf name for l3vni */
static inline const char *zl3vni_vrf_name(struct zebra_l3vni *zl3vni)
{
	return vrf_id_to_name(zl3vni->vrf_id);
}

/* get the rmac string */
static inline const char *zl3vni_rmac2str(struct zebra_l3vni *zl3vni, char *buf,
					  int size)
{
	char *ptr;

	if (!buf)
		ptr = XMALLOC(MTYPE_TMP, ETHER_ADDR_STRLEN * sizeof(char));
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
static inline const char *zl3vni_sysmac2str(struct zebra_l3vni *zl3vni,
					    char *buf, int size)
{
	char *ptr;

	if (!buf)
		ptr = XMALLOC(MTYPE_TMP, ETHER_ADDR_STRLEN * sizeof(char));
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
static inline int is_l3vni_oper_up(struct zebra_l3vni *zl3vni)
{
	return (is_evpn_enabled() && zl3vni && (zl3vni->vrf_id != VRF_UNKNOWN)
		&& zl3vni->vxlan_if && if_is_operative(zl3vni->vxlan_if)
		&& zl3vni->svi_if && if_is_operative(zl3vni->svi_if));
}

static inline const char *zl3vni_state2str(struct zebra_l3vni *zl3vni)
{
	if (!zl3vni)
		return NULL;

	if (is_l3vni_oper_up(zl3vni))
		return "Up";
	else
		return "Down";

	return NULL;
}

static inline vrf_id_t zl3vni_vrf_id(struct zebra_l3vni *zl3vni)
{
	return zl3vni->vrf_id;
}

static inline void zl3vni_get_svi_rmac(struct zebra_l3vni *zl3vni,
				       struct ethaddr *rmac)
{
	if (!zl3vni)
		return;

	if (!is_l3vni_oper_up(zl3vni))
		return;

	if (zl3vni->svi_if && if_is_operative(zl3vni->svi_if))
		memcpy(rmac->octet, zl3vni->svi_if->hw_addr, ETH_ALEN);
}


/* context for neigh hash walk - update l3vni and rmac */
struct neigh_l3info_walk_ctx {

	struct zebra_evpn *zevpn;
	struct zebra_l3vni *zl3vni;
	int add;
};

struct nh_walk_ctx {

	struct vty *vty;
	struct json_object *json;
};

extern struct zebra_l3vni *zl3vni_from_vrf(vrf_id_t vrf_id);
extern struct interface *zl3vni_map_to_vxlan_if(struct zebra_l3vni *zl3vni);
extern struct interface *zl3vni_map_to_svi_if(struct zebra_l3vni *zl3vni);
extern struct interface *zl3vni_map_to_mac_vlan_if(struct zebra_l3vni *zl3vni);
extern struct zebra_l3vni *zl3vni_lookup(vni_t vni);
extern vni_t vni_id_from_svi(struct interface *ifp, struct interface *br_if);

DECLARE_HOOK(zebra_rmac_update,
	     (struct zebra_mac * rmac, struct zebra_l3vni *zl3vni, bool delete,
	      const char *reason),
	     (rmac, zl3vni, delete, reason));


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
struct zebra_vxlan_sg {
	struct zebra_vrf *zvrf;

	struct prefix_sg sg;
	char sg_str[PREFIX_SG_STR_LEN];

	/* For SG - num of L2 VNIs using this entry for sending BUM traffic */
	/* For XG - num of SG using this as parent */
	uint32_t ref_cnt;
};

extern struct zebra_evpn *zevpn_lookup(vni_t vni);
extern void zebra_vxlan_sync_mac_dp_install(struct zebra_mac *mac,
					    bool set_inactive,
					    bool force_clear_static,
					    const char *caller);
extern bool zebra_evpn_do_dup_addr_detect(struct zebra_vrf *zvrf);

#endif /* _ZEBRA_VXLAN_PRIVATE_H */
