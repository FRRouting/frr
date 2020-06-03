/*
 * Zebra Vrf Header
 * Copyright (C) 2016 Cumulus Networks
 *                    Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#if !defined(__ZEBRA_VRF_H__)
#define __ZEBRA_VRF_H__

#include "vxlan.h"

#include <zebra/zebra_ns.h>
#include <zebra/zebra_pw.h>
#include <lib/vxlan.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MPLS (Segment Routing) global block */
struct mpls_srgb {
	uint32_t start_label;
	uint32_t end_label;
};

struct zebra_rmap {
	char *name;
	struct route_map *map;
};

PREDECL_RBTREE_UNIQ(otable);

struct other_route_table {
	struct otable_item next;

	afi_t afi;
	safi_t safi;
	uint32_t table_id;

	struct route_table *table;
};

/* Routing table instance.  */
struct zebra_vrf {
	/* Back pointer */
	struct vrf *vrf;

	/* Description.  */
	char *desc;

	/* FIB identifier.  */
	uint8_t fib_id;

	/* Flags. */
	uint16_t flags;
#define ZEBRA_VRF_RETAIN          (1 << 0)
#define ZEBRA_PIM_SEND_VXLAN_SG   (1 << 1)

	uint32_t table_id;

	/* Routing table.  */
	struct route_table *table[AFI_MAX][SAFI_MAX];

	/* Recursive Nexthop table */
	struct route_table *rnh_table[AFI_MAX];

	/* Import check table (used mostly by BGP */
	struct route_table *import_check_table[AFI_MAX];

	struct otable_head other_tables;

	/* 2nd pointer type used primarily to quell a warning on
	 * ALL_LIST_ELEMENTS_RO
	 */
	struct list _rid_all_sorted_list;
	struct list _rid_lo_sorted_list;
	struct list *rid_all_sorted_list;
	struct list *rid_lo_sorted_list;
	struct prefix rid_user_assigned;

	/*
	 * Back pointer to the owning namespace.
	 */
	struct zebra_ns *zns;

	/* MPLS Label to handle L3VPN <-> vrf popping */
	mpls_label_t label[AFI_MAX];

	/* MPLS static LSP config table */
	struct hash *slsp_table;

	/* MPLS label forwarding table */
	struct hash *lsp_table;

	/* MPLS FEC binding table */
	struct route_table *fec_table[AFI_MAX];

	/* MPLS Segment Routing Global block */
	struct mpls_srgb mpls_srgb;

	/* Pseudowires. */
	struct zebra_pw_head pseudowires;
	struct zebra_static_pw_head static_pseudowires;

	struct zebra_rmap proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1];
	struct zebra_rmap nht_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1];

	/* MPLS processing flags */
	uint16_t mpls_flags;
#define MPLS_FLAG_SCHEDULE_LSPS    (1 << 0)

	/*
	 * EVPN hash table. Only in the EVPN instance.
	 */
	struct hash *evpn_table;

	/*
	 * Whether EVPN is enabled or not. Only in the EVPN instance.
	 */
	int advertise_all_vni;

	/*
	 * Whether we are advertising g/w macip in EVPN or not.
	 * Only in the EVPN instance.
	 */
	int advertise_gw_macip;

	int advertise_svi_macip;

	/* l3-vni info */
	vni_t l3vni;

	/* pim mroutes installed for vxlan flooding */
	struct hash *vxlan_sg_table;

	bool dup_addr_detect;

	int dad_time;
	uint32_t dad_max_moves;
	bool dad_freeze;
	uint32_t dad_freeze_time;

	/*
	 * Flooding mechanism for BUM packets for VxLAN-EVPN.
	 */
	enum vxlan_flood_control vxlan_flood_ctrl;

	/* Install stats */
	uint64_t installs;
	uint64_t removals;
	uint64_t installs_queued;
	uint64_t removals_queued;
	uint64_t neigh_updates;
	uint64_t lsp_installs_queued;
	uint64_t lsp_removals_queued;
	uint64_t lsp_installs;
	uint64_t lsp_removals;

#if defined(HAVE_RTADV)
	struct rtadv rtadv;
#endif /* HAVE_RTADV */

	int zebra_rnh_ip_default_route;
	int zebra_rnh_ipv6_default_route;
};
#define PROTO_RM_NAME(zvrf, afi, rtype) zvrf->proto_rm[afi][rtype].name
#define NHT_RM_NAME(zvrf, afi, rtype) zvrf->nht_rm[afi][rtype].name
#define PROTO_RM_MAP(zvrf, afi, rtype) zvrf->proto_rm[afi][rtype].map
#define NHT_RM_MAP(zvrf, afi, rtype) zvrf->nht_rm[afi][rtype].map

/*
 * special macro to allow us to get the correct zebra_vrf
 */
#define ZEBRA_DECLVAR_CONTEXT(A, B)                                            \
	struct vrf *A = VTY_GET_CONTEXT(vrf);                                  \
	struct zebra_vrf *B = (A) ? A->info : vrf_info_lookup(VRF_DEFAULT)

static inline vrf_id_t zvrf_id(struct zebra_vrf *zvrf)
{
	if (!zvrf || !zvrf->vrf)
		return VRF_DEFAULT;
	return zvrf->vrf->vrf_id;
}

static inline const char *zvrf_ns_name(struct zebra_vrf *zvrf)
{
	if (!zvrf->vrf || !zvrf->vrf->ns_ctxt)
		return NULL;
	return ns_get_name((struct ns *)zvrf->vrf->ns_ctxt);
}

static inline const char *zvrf_name(struct zebra_vrf *zvrf)
{
	if (!zvrf || !zvrf->vrf)
		return "Unknown";
	return zvrf->vrf->name;
}

static inline bool zvrf_is_active(struct zebra_vrf *zvrf)
{
	return zvrf->vrf->status & VRF_ACTIVE;
}

static inline int
zvrf_other_table_compare_func(const struct other_route_table *a,
			      const struct other_route_table *b)
{
	if (a->afi != b->afi)
		return a->afi - b->afi;

	if (a->safi != b->safi)
		return a->safi - b->safi;

	if (a->table_id != b->table_id)
		return a->table_id - b->table_id;

	return 0;
}

DECLARE_RBTREE_UNIQ(otable, struct other_route_table, next,
		    zvrf_other_table_compare_func)

extern struct route_table *
zebra_vrf_lookup_table_with_table_id(afi_t afi, safi_t safi, vrf_id_t vrf_id,
				     uint32_t table_id);
extern struct route_table *zebra_vrf_get_table_with_table_id(afi_t afi,
							     safi_t safi,
							     vrf_id_t vrf_id,
							     uint32_t table_id);

extern void zebra_vrf_update_all(struct zserv *client);
extern struct zebra_vrf *zebra_vrf_lookup_by_id(vrf_id_t vrf_id);
extern struct zebra_vrf *zebra_vrf_lookup_by_name(const char *);
extern struct zebra_vrf *zebra_vrf_alloc(void);
extern struct route_table *zebra_vrf_table(afi_t, safi_t, vrf_id_t);

extern int zebra_vrf_has_config(struct zebra_vrf *zvrf);
extern void zebra_vrf_init(void);

extern void zebra_rtable_node_cleanup(struct route_table *table,
				      struct route_node *node);

#ifdef __cplusplus
}
#endif

#endif /* ZEBRA_VRF_H */
