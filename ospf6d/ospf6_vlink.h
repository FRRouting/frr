/*
 * OSPFv3 virtual link implementation.
 *
 * Copyright (C) 2021 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef OSPF6_VLINK_H
#define OSPF6_VLINK_H

#include "typesafe.h"
#include "ospf6_top.h"

/* `struct ospf6` is declared at `ospf6_top.h`. */
struct ospf6;

PREDECL_RBTREE_UNIQ(ospf6_vlink_addrs);

struct ospf6_vlink_addr {
	struct ospf6_vlink_addrs_item item;

	struct in6_addr remote_addr;

	/* can't get a proper cost for non-OSPF routes...
	 * (though connected is OK too)
	 */
	uint8_t route_type;
	bool nht_up;
};

/**
 * OSPFv3 virtual link context data structure.
 *
 * Contains virtual link configuration and some state.
 */
struct ospf6_virtual_link {
	/* RB tree by IP address */
	struct ospf6_virtual_links_item item;
	struct ospf6_area_vlinks_item areaitem;

	struct ospf6_neighbor *nbr;
	struct ospf6 *ospf6;

	/* crossed area - the virtual link itself is always in the backbone,
	 * and this is always a non-backbone area
	 */
	struct ospf6_area *area;

	ifindex_t v_ifindex;

	/* Remote end router ID. */
	struct in_addr remote;
	struct in6_addr transport;
	uint32_t spf_cost;

	struct ospf6_vlink_addrs_head addrs[1];

	/* no interface exists that would run this timer for us... */
	struct thread *t_hello;

	/* Timers in seconds. */
	uint32_t hello_interval;
	uint32_t retransmit_interval;
	uint32_t transmit_delay;
	uint32_t dead_interval;
};

/* RFC defaults */

/** Default hello packet transmission interval. */
#define VLINK_DEFAULT_HELLO_INTERVAL 10
/** Default retransmission interval between lost link state advertisements. */
#define VLINK_DEFAULT_RETRANSMIT_INTERVAL 5
/** Default link state transmission interval. */
#define VLINK_DEFAULT_TRANSMIT_DELAY 1
/** Default dead peer detection interval. */
#define VLINK_DEFAULT_DEAD_INTERVAL 40

/* Exported functions. */
struct ospf6_virtual_link *ospf6_virtual_link_find(struct ospf6 *ospf,
						   struct in_addr remote);

/** Initialize virtual link code. */
void ospf6_virtual_link_init(void);

void ospf6_vlink_init(struct ospf6 *oa);
void ospf6_vlink_fini(struct ospf6 *oa);

void ospf6_vlink_area_calculation(struct ospf6_area *oa);
void ospf6_vlink_prefix_update(struct ospf6_area *oa, in_addr_t rtr);

void ospf6_vlink_area_init(struct ospf6_area *oa);
void ospf6_vlink_area_fini(struct ospf6_area *oa);
size_t ospf6_vlink_area_vlcount(struct ospf6_area *oa);

struct vty;
void config_write_ospf6_debug_vlink(struct vty *vty);
void ospf6_vlink_area_config(struct ospf6_area *oa, struct vty *vty);

#endif /* OSPF6_VLINK_H */
