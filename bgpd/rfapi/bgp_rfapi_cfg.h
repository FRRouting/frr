/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_RFAPI_CFG_H
#define _QUAGGA_BGP_RFAPI_CFG_H

#include "lib/table.h"
#include "lib/routemap.h"

#if ENABLE_BGP_VNC
#include "rfapi.h"

struct rfapi_l2_group_cfg {
	char *name;
	uint32_t logical_net_id;
	struct list *labels; /* list of uint32_t */
	struct ecommunity *rt_import_list;
	struct ecommunity *rt_export_list;
	void *rfp_cfg; /* rfp owned group config */

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(rfapi_l2_group_cfg)

typedef enum {
	RFAPI_GROUP_CFG_NVE = 1,
	RFAPI_GROUP_CFG_VRF,
	RFAPI_GROUP_CFG_L2,
	RFAPI_GROUP_CFG_MAX
} rfapi_group_cfg_type_t;

struct rfapi_nve_group_cfg {
	struct route_node *vn_node; /* backref */
	struct route_node *un_node; /* backref */

	rfapi_group_cfg_type_t type; /* NVE|VPN */
	char *name;		     /* unique by type! */
	struct prefix vn_prefix;
	struct prefix un_prefix;

	struct prefix_rd rd;
	uint8_t l2rd; /* 0 = VN addr LSB */
	uint32_t response_lifetime;
	uint32_t flags;
#define RFAPI_RFG_RESPONSE_LIFETIME	0x01 /* bits */
#define RFAPI_RFG_L2RD			0x02
#define RFAPI_RFG_VPN_NH_SELF		0x04
	struct ecommunity *rt_import_list;
	struct ecommunity *rt_export_list;
	struct rfapi_import_table *rfapi_import_table;

	void *rfp_cfg; /* rfp owned group config */
	/*
	 * List of NVE descriptors that are assigned to this NVE group
	 *
	 * Currently (Mar 2010) this list is used only by the route
	 * export code to generate per-NVE nexthops for each route.
	 *
	 * The nve descriptors listed here have pointers back to
	 * this nve group config structure to enable them to delete
	 * their own list entries when they are closed. Consequently,
	 * if an instance of this nve group config structure is deleted,
	 * we must first set the nve descriptor references to it to NULL.
	 */
	struct list *nves;

	/*
	 * Route filtering
	 *
	 * Prefix lists are segregated by afi (part of the base plist code)
	 * Route-maps are not segregated
	 */
	char *plist_export_bgp_name[AFI_MAX];
	struct prefix_list *plist_export_bgp[AFI_MAX];

	char *plist_export_zebra_name[AFI_MAX];
	struct prefix_list *plist_export_zebra[AFI_MAX];

	char *plist_redist_name[ZEBRA_ROUTE_MAX][AFI_MAX];
	struct prefix_list *plist_redist[ZEBRA_ROUTE_MAX][AFI_MAX];

	char *routemap_export_bgp_name;
	struct route_map *routemap_export_bgp;

	char *routemap_export_zebra_name;
	struct route_map *routemap_export_zebra;

	char *routemap_redist_name[ZEBRA_ROUTE_MAX];
	struct route_map *routemap_redist[ZEBRA_ROUTE_MAX];

	/* for VRF type groups */
	uint32_t label;
	struct rfapi_descriptor *rfd;
	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(rfapi_nve_group_cfg)

struct rfapi_rfg_name {
	struct rfapi_nve_group_cfg *rfg;
	char *name;
};

typedef enum {
	VNC_REDIST_MODE_PLAIN = 0, /* 0 = default */
	VNC_REDIST_MODE_RFG,
	VNC_REDIST_MODE_RESOLVE_NVE
} vnc_redist_mode_t;

struct rfapi_cfg {
	struct prefix_rd default_rd;
	uint8_t default_l2rd;
	struct ecommunity *default_rt_import_list;
	struct ecommunity *default_rt_export_list;
	uint32_t default_response_lifetime;
#define BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT 3600
	void *default_rfp_cfg; /* rfp owned group config */

	struct list *l2_groups; /* rfapi_l2_group_cfg list */
	/* three views into the same collection of rfapi_nve_group_cfg */
	struct list *nve_groups_sequential;
	struct route_table *nve_groups_vn[AFI_MAX];
	struct route_table *nve_groups_un[AFI_MAX];

	/*
	 * For Single VRF export to ordinary routing protocols. This is
	 * the nve-group that the ordinary protocols belong to. We use it
	 * to set the RD when sending unicast Zebra routes to VNC
	 */
	uint8_t redist[AFI_MAX][ZEBRA_ROUTE_MAX];
	uint32_t redist_lifetime;
	vnc_redist_mode_t redist_mode;

	/*
	 * view name of BGP unicast instance that holds
	 * exterior routes
	 */
	char *redist_bgp_exterior_view_name;
	struct bgp *redist_bgp_exterior_view;

	/*
	 * nve group for redistribution of routes from zebra to VNC
	 * (which is probably not useful for production networks)
	 */
	char *rfg_redist_name;
	struct rfapi_nve_group_cfg *rfg_redist;

	/*
	 * List of NVE groups on whose behalf we will export VNC
	 * routes to zebra. ((NB: it's actually a list of <struct
	 * rfapi_rfg_name>)
	 * This list is used when BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS is
	 * BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP
	 */
	struct list *rfg_export_zebra_l;

	/*
	 * List of NVE groups on whose behalf we will export VNC
	 * routes directly to the bgp unicast RIB. (NB: it's actually
	 * a list of <struct rfapi_rfg_name>)
	 * This list is used when BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS is
	 * BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP
	 */
	struct list *rfg_export_direct_bgp_l;

	/*
	 * Exported Route filtering
	 *
	 * Prefix lists are segregated by afi (part of the base plist code)
	 * Route-maps are not segregated
	 */
	char *plist_export_bgp_name[AFI_MAX];
	struct prefix_list *plist_export_bgp[AFI_MAX];

	char *plist_export_zebra_name[AFI_MAX];
	struct prefix_list *plist_export_zebra[AFI_MAX];

	char *routemap_export_bgp_name;
	struct route_map *routemap_export_bgp;

	char *routemap_export_zebra_name;
	struct route_map *routemap_export_zebra;

	/*
	 * Redistributed route filtering (routes from other
	 * protocols into VNC)
	 */
	char *plist_redist_name[ZEBRA_ROUTE_MAX][AFI_MAX];
	struct prefix_list *plist_redist[ZEBRA_ROUTE_MAX][AFI_MAX];

	char *routemap_redist_name[ZEBRA_ROUTE_MAX];
	struct route_map *routemap_redist[ZEBRA_ROUTE_MAX];

	/*
	 * For importing bgp unicast routes to VNC, we encode the CE
	 * (route nexthop) in a Route Origin extended community. The
	 * local part (16-bit) is user-configurable.
	 */
	uint16_t resolve_nve_roo_local_admin;
#define BGP_VNC_CONFIG_RESOLVE_NVE_ROO_LOCAL_ADMIN_DEFAULT 5226

	uint32_t flags;
#define BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP	0x00000001
#define BGP_VNC_CONFIG_CALLBACK_DISABLE		0x00000002
#define BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE	0x00000004

#define BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS	0x000000f0
#define BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS	0x00000f00

#define BGP_VNC_CONFIG_EXPORT_BGP_MODE_NONE	0x00000000
#define BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP	0x00000010
#define BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH	0x00000020      /* registerd nve */
#define BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE	0x00000040

#define BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_NONE	0x00000000
#define BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP	0x00000100
#define BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_RH	0x00000200

#define BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP	0x00001000
#define BGP_VNC_CONFIG_L2RD			0x00002000

/* Use new NVE RIB to filter callback routes */
/* Filter querying NVE's registrations from responses */
/* Default to updated-responses off */
/* Default to removal-responses off */
#define BGP_VNC_CONFIG_FLAGS_DEFAULT                                           \
	(BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP | BGP_VNC_CONFIG_CALLBACK_DISABLE \
	 | BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE)

	struct rfapi_rfp_cfg rfp_cfg; /* rfp related configuration  */
};

#define VNC_EXPORT_ZEBRA_GRP_ENABLED(hc)                                       \
	(((hc)->flags & BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS)                 \
	 == BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP)

#define VNC_EXPORT_ZEBRA_RH_ENABLED(hc)                                        \
	(((hc)->flags & BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS)                 \
	 == BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_RH)

#define VNC_EXPORT_BGP_GRP_ENABLED(hc)                                         \
	(((hc)->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS)                   \
	 == BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP)

#define VNC_EXPORT_BGP_RH_ENABLED(hc)                                          \
	(((hc)->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS)                   \
	 == BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH)

#define VNC_EXPORT_BGP_CE_ENABLED(hc)                                          \
	(((hc)->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS)                   \
	 == BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE)


void bgp_rfapi_cfg_init(void);

struct rfapi_cfg *bgp_rfapi_cfg_new(struct rfapi_rfp_cfg *cfg);

void bgp_rfapi_cfg_destroy(struct bgp *bgp, struct rfapi_cfg *h);

int bgp_rfapi_cfg_write(struct vty *vty, struct bgp *bgp);

extern int bgp_rfapi_is_vnc_configured(struct bgp *bgp);

extern void nve_group_to_nve_list(struct rfapi_nve_group_cfg *rfg,
				  struct list **nves,
				  uint8_t family); /* AF_INET, AF_INET6 */

struct rfapi_nve_group_cfg *bgp_rfapi_cfg_match_group(struct rfapi_cfg *hc,
						      struct prefix *vn,
						      struct prefix *un);

struct rfapi_nve_group_cfg *
bgp_rfapi_cfg_match_byname(struct bgp *bgp, const char *name,
			   rfapi_group_cfg_type_t type); /* _MAX = any */

extern void vnc_prefix_list_update(struct bgp *bgp);

extern void vnc_routemap_update(struct bgp *bgp, const char *unused);

extern void bgp_rfapi_show_summary(struct bgp *bgp, struct vty *vty);

extern struct rfapi_cfg *bgp_rfapi_get_config(struct bgp *bgp);

extern struct rfapi_l2_group_cfg *
bgp_rfapi_get_group_by_lni_label(struct bgp *bgp, uint32_t logical_net_id,
				 uint32_t label);

extern struct ecommunity *
bgp_rfapi_get_ecommunity_by_lni_label(struct bgp *bgp, uint32_t is_import,
				      uint32_t logical_net_id,
				      uint32_t label); /* note, 20bit label! */

extern struct list *
bgp_rfapi_get_labellist_by_lni_label(struct bgp *bgp, uint32_t logical_net_id,
				     uint32_t label); /* note, 20bit label! */

#endif /* ENABLE_BGP_VNC */

#endif /* _QUAGGA_BGP_RFAPI_CFG_H */
