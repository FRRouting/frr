/*
 * STATICd - static routes header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __STATIC_ROUTES_H__
#define __STATIC_ROUTES_H__

#include "lib/bfd.h"
#include "lib/mpls.h"
#include "table.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(STATIC);

#include "staticd/static_vrf.h"

/* Static route label information */
struct static_nh_label {
	uint8_t num_labels;
	uint8_t reserved[3];
	mpls_label_t label[MPLS_MAX_LABELS];
};

enum static_blackhole_type {
	STATIC_BLACKHOLE_DROP = 0,
	STATIC_BLACKHOLE_NULL,
	STATIC_BLACKHOLE_REJECT
};

/*
 * The order for below macros should be in sync with
 * yang model typedef nexthop-type
 */
typedef enum {
	STATIC_IFNAME = 1,
	STATIC_IPV4_GATEWAY,
	STATIC_IPV4_GATEWAY_IFNAME,
	STATIC_IPV6_GATEWAY,
	STATIC_IPV6_GATEWAY_IFNAME,
	STATIC_BLACKHOLE,
} static_types;

/*
 * Route Creation gives us:
 *  START -> Initial State, only exit is when we send the route to
 *          zebra for installation
 * When we send the route to Zebra move to SENT_TO_ZEBRA
 *  SENT_TO_ZEBRA -> A way to notice that we've sent the route to zebra
 *                   But have not received a response on it's status yet
 * After The response from zebra we move to INSTALLED or FAILED
 *  INSTALLED -> Route was accepted
 *  FAILED -> Route was rejected
 * When we receive notification about a nexthop that a route uses
 * We move the route back to START and initiate the process again.
 */
enum static_install_states {
	STATIC_START,
	STATIC_SENT_TO_ZEBRA,
	STATIC_INSTALLED,
	STATIC_NOT_INSTALLED,
};

PREDECL_DLIST(static_path_list);
PREDECL_DLIST(static_nexthop_list);

/* Static route information */
struct static_route_info {
	/* path list */
	struct static_path_list_head path_list;
};

/* Static path information */
struct static_path {
	/* Linkage for static path lists */
	struct static_path_list_item list;
	/* Administrative distance. */
	uint8_t distance;
	/* Tag */
	route_tag_t tag;
	/* Table-id */
	uint32_t table_id;
	/* Nexthop list */
	struct static_nexthop_list_head nexthop_list;
};

DECLARE_DLIST(static_path_list, struct static_path, list);

/* Static route information. */
struct static_nexthop {
	/* For linked list. */
	struct static_nexthop_list_item list;

	/* VRF identifier. */
	vrf_id_t nh_vrf_id;
	char nh_vrfname[VRF_NAMSIZ + 1];

	/*
	 * States that we walk the route through
	 * To know where we are.
	 */
	enum static_install_states state;

	/* Flag for this static route's type. */
	static_types type;

	/*
	 * Nexthop value.
	 */
	enum static_blackhole_type bh_type;
	union g_addr addr;
	ifindex_t ifindex;
	bool nh_registered;
	bool nh_valid;

	char ifname[INTERFACE_NAMSIZ + 1];

	/* Label information */
	struct static_nh_label snh_label;

	/*
	 * Whether to pretend the nexthop is directly attached to the specified
	 * link. Only meaningful when both a gateway address and interface name
	 * are specified.
	 */
	bool onlink;

	/* SR-TE color */
	uint32_t color;

	/** BFD integration data. */
	struct bfd_session_params *bsp;
	/** Back pointer for route node. */
	struct route_node *rn;
	/** Back pointer for path list. */
	struct static_path *sp;
	/** Route SAFI type. */
	safi_t safi;
	/** Path connection status. */
	bool path_down;
};

DECLARE_DLIST(static_nexthop_list, struct static_nexthop, list);

/*
 * rib_dest_from_rnode
 */
static inline struct static_route_info *
static_route_info_from_rnode(struct route_node *rn)
{
	return (struct static_route_info *)(rn->info);
}

extern bool mpls_enabled;

extern struct zebra_privs_t static_privs;

void static_fixup_vrf_ids(struct static_vrf *svrf);

extern struct static_nexthop *
static_add_nexthop(struct route_node *rn, struct static_path *pn, safi_t safi,
		   struct static_vrf *svrf, static_types type,
		   struct ipaddr *ipaddr, const char *ifname,
		   const char *nh_vrf, uint32_t color);
extern void static_install_nexthop(struct route_node *rn,
				   struct static_path *pn,
				   struct static_nexthop *nh, safi_t safi,
				   struct static_vrf *svrf, const char *ifname,
				   static_types type, const char *nh_vrf);

extern int static_delete_nexthop(struct route_node *rn, struct static_path *pn,
				 safi_t safi, struct static_vrf *svrf,
				 struct static_nexthop *nh);

extern void static_cleanup_vrf_ids(struct static_vrf *disable_svrf);

extern void static_install_intf_nh(struct interface *ifp);

extern void static_ifindex_update(struct interface *ifp, bool up);

extern void static_install_path(struct route_node *rn, struct static_path *pn,
				safi_t safi, struct static_vrf *svrf);

extern struct route_node *static_add_route(afi_t afi, safi_t safi,
					   struct prefix *p,
					   struct prefix_ipv6 *src_p,
					   struct static_vrf *svrf);
extern void static_del_route(struct route_node *rn, safi_t safi,
			     struct static_vrf *svrf);

extern struct static_path *static_add_path(struct route_node *rn,
					   uint32_t table_id, uint8_t distance);
extern void static_del_path(struct route_node *rn, struct static_path *pn,
			    safi_t safi, struct static_vrf *svrf);

extern void static_get_nh_type(static_types stype, char *type, size_t size);
extern bool static_add_nexthop_validate(const char *nh_vrf_name,
					static_types type,
					struct ipaddr *ipaddr);
extern struct stable_info *static_get_stable_info(struct route_node *rn);
extern void static_route_info_init(struct static_route_info *si);

extern void zebra_stable_node_cleanup(struct route_table *table,
				      struct route_node *node);

/*
 * Max string return via API static_get_nh_str in size_t
 */

#define NEXTHOP_STR (INET6_ADDRSTRLEN + INTERFACE_NAMSIZ + 25)
/*
 * For the given nexthop, returns the string
 * nexthop : returns the formatted string in nexthop
 * size : max size of formatted string
 */
extern void static_get_nh_str(struct static_nexthop *nh, char *nexthop,
			      size_t size);

/*
 * Route group settings.
 */
/** Next hop member data structure. */
struct static_group_member {
	/** Next hop pointer. */
	struct static_nexthop *sgm_sn;

	/** Pointer to group. */
	struct static_route_group *sgm_srg;

	/** List entry. */
	TAILQ_ENTRY(static_group_member) sgm_entry;
};

/** Route group name maximum size. */
#define ROUTE_GROUP_NAME_MAX_SIZE 64

/** static route group data structure. */
struct static_route_group {
	/** Group name. */
	char srg_name[ROUTE_GROUP_NAME_MAX_SIZE];

	/** BFD group monitor settings. */
	struct bfd_session_params *srg_bsp;

	/** Next hop entries. */
	TAILQ_HEAD(sgmlist, static_group_member) srg_sgmlist;

	/** List entry data. */
	TAILQ_ENTRY(static_route_group) srg_entry;
};

TAILQ_HEAD(srglist, static_route_group);

extern struct static_route_group *static_route_group_new(const char *name);
extern void static_route_group_free(struct static_route_group **srg);

/**
 * TODO remove me.
 *
 * This function was temporarly created to enable us to implement
 * `write_config`, once full northbound migration happens please
 * remove this function.
 */
extern struct static_group_member *
static_group_member_glookup(struct static_nexthop *sn);

/*
 * BFD integration.
 */
extern void static_next_hop_bfd_monitor_enable(struct static_nexthop *sn,
					       const struct lyd_node *dnode);
extern void static_next_hop_bfd_monitor_disable(struct static_nexthop *sn);
extern void static_next_hop_bfd_profile(struct static_nexthop *sn,
					const char *name);
extern void static_next_hop_bfd_multi_hop(struct static_nexthop *sn, bool mhop);

extern void static_group_monitor_enable(const char *name,
					struct static_nexthop *sn);
extern void static_group_monitor_disable(const char *name,
					 struct static_nexthop *sn);

/* Route group settings. */
extern void static_route_group_bfd_vrf(struct static_route_group *srg,
				       const char *vrfname);
extern void static_route_group_bfd_addresses(struct static_route_group *srg,
					     const struct lyd_node *dnode);
extern void static_route_group_bfd_interface(struct static_route_group *srg,
					     const char *ifname);
extern void static_route_group_bfd_enable(struct static_route_group *srg,
					  const struct lyd_node *dnode);
extern void static_route_group_bfd_disable(struct static_route_group *srg);
extern void static_route_group_bfd_profile(struct static_route_group *srg,
					   const char *profile);
extern void static_route_group_bfd_multi_hop(struct static_route_group *srg,
					     bool mhop);

/** Call this function after zebra client initialization. */
extern void static_bfd_initialize(struct zclient *zc, struct thread_master *tm);

extern void static_bfd_show(struct vty *vty, bool isjson);

#ifdef __cplusplus
}
#endif

#endif
