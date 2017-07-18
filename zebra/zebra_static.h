/*
 * Static Routing Information header
 * Copyright (C) 2016 Cumulus Networks
 *               Donald Sharp
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
#ifndef __ZEBRA_STATIC_H__
#define __ZEBRA_STATIC_H__

/* Static route label information */
struct static_nh_label {
	u_int8_t num_labels;
	u_int8_t reserved[3];
	mpls_label_t label[2];
};

typedef enum {
	STATIC_IFINDEX,
	STATIC_IPV4_GATEWAY,
	STATIC_BLACKHOLE,
	STATIC_IPV6_GATEWAY,
	STATIC_IPV6_GATEWAY_IFINDEX,
} zebra_static_types;

/* Static route information. */
struct static_route {
	/* For linked list. */
	struct static_route *prev;
	struct static_route *next;

	/* VRF identifier. */
	vrf_id_t vrf_id;

	/* Administrative distance. */
	u_char distance;

	/* Tag */
	route_tag_t tag;

	/* Flag for this static route's type. */
	zebra_static_types type;

	/*
	 * Nexthop value.
	 *
	 * Under IPv4 addr and ifindex are
	 * used independentyly.
	 * STATIC_IPV4_GATEWAY uses addr
	 * STATIC_IFINDEX uses ifindex
	 */
	union g_addr addr;
	ifindex_t ifindex;

	char ifname[INTERFACE_NAMSIZ + 1];

	/* bit flags */
	u_char flags;
	/*
	 see ZEBRA_FLAG_REJECT
	     ZEBRA_FLAG_BLACKHOLE
	 */

	/* Label information */
	struct static_nh_label snh_label;
};

extern void static_install_route(afi_t afi, safi_t safi, struct prefix *p,
				 struct prefix_ipv6 *src_p,
				 struct static_route *si);
extern void static_uninstall_route(afi_t afi, safi_t safi, struct prefix *p,
				   struct prefix_ipv6 *src_p,
				   struct static_route *si);

extern int static_add_route(afi_t, safi_t safi, u_char type, struct prefix *p,
			    struct prefix_ipv6 *src_p, union g_addr *gate,
			    ifindex_t ifindex, const char *ifname, u_char flags,
			    route_tag_t tag, u_char distance,
			    struct zebra_vrf *zvrf,
			    struct static_nh_label *snh_label);

extern int static_delete_route(afi_t, safi_t safi, u_char type,
			       struct prefix *p, struct prefix_ipv6 *src_p,
			       union g_addr *gate, ifindex_t ifindex, const char *ifname,
			       route_tag_t tag, u_char distance,
			       struct zebra_vrf *zvrf,
			       struct static_nh_label *snh_label);

int zebra_static_ipv4(struct vty *vty, safi_t safi, int add_cmd,
		      const char *dest_str, const char *mask_str,
		      const char *gate_str, const char *flag_str,
		      const char *tag_str, const char *distance_str,
		      const char *vrf_id_str, const char *label_str);

int static_ipv6_func(struct vty *vty, int add_cmd, const char *dest_str,
		     const char *src_str, const char *gate_str,
		     const char *ifname, const char *flag_str,
		     const char *tag_str, const char *distance_str,
		     const char *vrf_id_str, const char *label_str);

#endif
