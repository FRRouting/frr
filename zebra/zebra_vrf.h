/*
 * Zebra Vrf Header
 * Copyright (C) 2016 Cumulus Networks
 *                    Donald Sahrp
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
#if !defined(__ZEBRA_RIB_H__)
#define __ZEBRA_RIB_H__

#include <zebra/zebra_ns.h>

/* MPLS (Segment Routing) global block */
typedef struct mpls_srgb_t_ {
	u_int32_t start_label;
	u_int32_t end_label;
} mpls_srgb_t;

/* Routing table instance.  */
struct zebra_vrf {
	/* Back pointer */
	struct vrf *vrf;

	/* Description.  */
	char *desc;

	/* FIB identifier.  */
	u_char fib_id;

	/* Flags. */
	u_int16_t flags;
#define ZEBRA_VRF_RIB_SCHEDULED   (1 << 0)
#define ZEBRA_VRF_RETAIN          (2 << 0)

	u_int32_t table_id;

	/* Routing table.  */
	struct route_table *table[AFI_MAX][SAFI_MAX];

	/* Static route configuration.  */
	struct route_table *stable[AFI_MAX][SAFI_MAX];

	/* Recursive Nexthop table */
	struct route_table *rnh_table[AFI_MAX];

	/* Import check table (used mostly by BGP */
	struct route_table *import_check_table[AFI_MAX];

	/* Routing tables off of main table for redistribute table */
	struct route_table *other_table[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

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

	/* MPLS static LSP config table */
	struct hash *slsp_table;

	/* MPLS label forwarding table */
	struct hash *lsp_table;

	/* MPLS FEC binding table */
	struct route_table *fec_table[AFI_MAX];

	/* MPLS Segment Routing Global block */
	mpls_srgb_t mpls_srgb;

	/* MPLS processing flags */
	u_int16_t mpls_flags;
#define MPLS_FLAG_SCHEDULE_LSPS    (1 << 0)

	/*
	 * VNI hash table (for EVPN). Only in default instance.
	 */
	struct hash *vni_table;
	/*
	 * Whether EVPN is enabled or not.
	 */
	int advertise_all_vni;

	/* Route Installs */
	uint64_t installs;
	uint64_t removals;
	uint64_t neigh_updates;
	uint64_t lsp_installs;
	uint64_t lsp_removals;
};

static inline vrf_id_t zvrf_id(struct zebra_vrf *zvrf)
{
	return zvrf->vrf->vrf_id;
}

static inline const char *zvrf_name(struct zebra_vrf *zvrf)
{
	return zvrf->vrf->name;
}

struct route_table *zebra_vrf_table_with_table_id(afi_t afi, safi_t safi,
						  vrf_id_t vrf_id,
						  u_int32_t table_id);

extern void zebra_vrf_static_route_interface_fixup(struct interface *ifp);
extern void zebra_vrf_update_all(struct zserv *client);
extern struct zebra_vrf *zebra_vrf_lookup_by_id(vrf_id_t vrf_id);
extern struct zebra_vrf *zebra_vrf_lookup_by_name(const char *);
extern struct zebra_vrf *zebra_vrf_alloc(void);
extern struct route_table *zebra_vrf_table(afi_t, safi_t, vrf_id_t);
extern struct route_table *zebra_vrf_static_table(afi_t, safi_t,
						  struct zebra_vrf *zvrf);
extern struct route_table *
zebra_vrf_other_route_table(afi_t afi, u_int32_t table_id, vrf_id_t vrf_id);
extern void zebra_vrf_init(void);
#endif
