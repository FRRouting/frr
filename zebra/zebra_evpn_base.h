// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * "base" EVPN definitions that are included from a lot of places
 * (and have caused #include issues/loops)
 *
 * This file should very likely only contain struct definitions.
 */
#ifndef _ZEBRA_EVPN_BASE_H
#define _ZEBRA_EVPN_BASE_H

#include <stdint.h>

#include "lib/typesafe.h"

#include "lib/zebra.h" /* vrf_id_t */
#include "lib/vlan.h"  /* vlanid_t */
#include "lib/vxlan.h" /* vni_t */
#include "lib/ipaddr.h"

PREDECL_HASH(zebra_neigh_db);

RB_HEAD(zebra_es_evi_rb_head, zebra_evpn_es_evi);
RB_PROTOTYPE(zebra_es_evi_rb_head, zebra_evpn_es_evi, rb_node, zebra_es_evi_rb_cmp);

RB_HEAD(host_rb_tree_entry, host_rb_entry);
RB_PROTOTYPE(host_rb_tree_entry, host_rb_entry, hl_entry, host_rb_entry_compare);

/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_evpn {
	/* VNI - key */
	vni_t vni;

	/* ES flags */
	uint32_t flags;
#define ZEVPN_READY_FOR_BGP (1 << 0) /* ready to be sent to BGP */

	/* Corresponding Bridge information */
	vlanid_t vid;
	struct interface *bridge_if;

	/* Flag for advertising gw macip */
	uint8_t advertise_gw_macip;

	/* Flag for advertising svi macip */
	uint8_t advertise_svi_macip;

	/* Flag for advertising gw macip */
	uint8_t advertise_subnet;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* Corresponding SVI interface. */
	struct interface *svi_if;

	/* List of remote VTEPs */
	struct zebra_vtep *vteps;

	/* Local IP */
	struct ipaddr local_vtep_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* tenant VRF, if any */
	vrf_id_t vrf_id;

	/* List of local or remote MAC */
	struct hash *mac_table;

	/* List of local or remote neighbors (MAC+IP) */
	struct zebra_neigh_db_head neigh_table[1];

	/* RB tree of ES-EVIs */
	struct zebra_es_evi_rb_head es_evi_rb_tree;

	/* List of local ESs */
	struct list *local_es_evi_list;
};

#endif /* _ZEBRA_EVPN_BASE_H */
