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

#include "lib/mpls.h"
#include "table.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(STATIC);

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
enum static_nh_type {
	STATIC_IFNAME = 1,
	STATIC_IPV4_GATEWAY,
	STATIC_IPV4_GATEWAY_IFNAME,
	STATIC_IPV6_GATEWAY,
	STATIC_IPV6_GATEWAY_IFNAME,
	STATIC_BLACKHOLE,
};

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
	struct static_vrf *svrf;
	safi_t safi;
	/* path list */
	struct static_path_list_head path_list;
};

/* Static path information */
struct static_path {
	/* Route node back pointer. */
	struct route_node *rn;
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
	/* Path back pointer. */
	struct static_path *pn;
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
	enum static_nh_type type;

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

static inline void static_get_nh_type(enum static_nh_type stype, char *type,
				      size_t size)
{
	switch (stype) {
	case STATIC_IFNAME:
		strlcpy(type, "ifindex", size);
		break;
	case STATIC_IPV4_GATEWAY:
		strlcpy(type, "ip4", size);
		break;
	case STATIC_IPV4_GATEWAY_IFNAME:
		strlcpy(type, "ip4-ifindex", size);
		break;
	case STATIC_BLACKHOLE:
		strlcpy(type, "blackhole", size);
		break;
	case STATIC_IPV6_GATEWAY:
		strlcpy(type, "ip6", size);
		break;
	case STATIC_IPV6_GATEWAY_IFNAME:
		strlcpy(type, "ip6-ifindex", size);
		break;
	};
}

extern bool mpls_enabled;
extern uint32_t zebra_ecmp_count;

extern struct zebra_privs_t static_privs;

void static_fixup_vrf_ids(struct static_vrf *svrf);

extern struct static_nexthop *
static_add_nexthop(struct static_path *pn, enum static_nh_type type,
		   struct ipaddr *ipaddr, const char *ifname,
		   const char *nh_vrf, uint32_t color);
extern void static_install_nexthop(struct static_nexthop *nh);

extern void static_delete_nexthop(struct static_nexthop *nh);

extern void static_cleanup_vrf_ids(struct static_vrf *disable_svrf);

extern void static_install_intf_nh(struct interface *ifp);

extern void static_ifindex_update(struct interface *ifp, bool up);

extern void static_install_path(struct static_path *pn);

extern struct route_node *static_add_route(afi_t afi, safi_t safi,
					   struct prefix *p,
					   struct prefix_ipv6 *src_p,
					   struct static_vrf *svrf);
extern void static_del_route(struct route_node *rn);

extern struct static_path *static_add_path(struct route_node *rn,
					   uint32_t table_id, uint8_t distance);
extern void static_del_path(struct static_path *pn);

extern bool static_add_nexthop_validate(const char *nh_vrf_name,
					enum static_nh_type type,
					struct ipaddr *ipaddr);
extern struct stable_info *static_get_stable_info(struct route_node *rn);

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

#ifdef __cplusplus
}
#endif

#endif
