/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_OSPF_ASBR_H
#define _ZEBRA_OSPF_ASBR_H

struct route_map_set_values {
	int32_t metric;
	int32_t metric_type;
};

/* Redistributed external information. */
struct external_info {
	/* Type of source protocol. */
	uint8_t type;

	unsigned short instance;

	/* Prefix. */
	struct prefix_ipv4 p;

	/* Interface index. */
	ifindex_t ifindex;

	/* Nexthop address. */
	struct in_addr nexthop;

	/* Additional Route tag. */
	route_tag_t tag;

	struct route_map_set_values route_map_set;
#define ROUTEMAP_METRIC(E)      (E)->route_map_set.metric
#define ROUTEMAP_METRIC_TYPE(E) (E)->route_map_set.metric_type
};

#define OSPF_ASBR_CHECK_DELAY 30

extern void ospf_external_route_remove(struct ospf *, struct prefix_ipv4 *);
extern struct external_info *ospf_external_info_new(uint8_t, unsigned short);
extern void ospf_reset_route_map_set_values(struct route_map_set_values *);
extern int ospf_route_map_set_compare(struct route_map_set_values *,
				      struct route_map_set_values *);
extern struct external_info *ospf_external_info_add(struct ospf *, uint8_t,
						    unsigned short,
						    struct prefix_ipv4,
						    ifindex_t, struct in_addr,
						    route_tag_t);
extern void ospf_external_info_delete(struct ospf *, uint8_t, unsigned short,
				      struct prefix_ipv4);
extern struct external_info *ospf_external_info_lookup(struct ospf *, uint8_t,
						       unsigned short,
						       struct prefix_ipv4 *);
extern struct ospf_route *ospf_external_route_lookup(struct ospf *,
						     struct prefix_ipv4 *);
extern void ospf_asbr_status_update(struct ospf *, uint8_t);

extern void ospf_redistribute_withdraw(struct ospf *, uint8_t, unsigned short);
extern void ospf_asbr_check(void);
extern void ospf_schedule_asbr_check(void);
extern void ospf_asbr_route_install_lsa(struct ospf_lsa *);
extern struct ospf_lsa *ospf_external_info_find_lsa(struct ospf *,
						    struct prefix_ipv4 *p);

#endif /* _ZEBRA_OSPF_ASBR_H */
