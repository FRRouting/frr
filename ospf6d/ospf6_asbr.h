/*
 * Copyright (C) 2001 Yasuhiro Ohara
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

#ifndef OSPF6_ASBR_H
#define OSPF6_ASBR_H

/* for struct ospf6_prefix */
#include "ospf6_proto.h"
/* for struct ospf6_lsa */
#include "ospf6_lsa.h"
/* for struct ospf6_route */
#include "ospf6_route.h"

/* Debug option */
extern unsigned char conf_debug_ospf6_asbr;
#define OSPF6_DEBUG_ASBR_ON() (conf_debug_ospf6_asbr = 1)
#define OSPF6_DEBUG_ASBR_OFF() (conf_debug_ospf6_asbr = 0)
#define IS_OSPF6_DEBUG_ASBR (conf_debug_ospf6_asbr)

struct ospf6_external_info {
	/* External route type */
	int type;

	/* Originating Link State ID */
	u_int32_t id;

	struct in6_addr forwarding;

	route_tag_t tag;

	ifindex_t ifindex;
};

/* AS-External-LSA */
#define OSPF6_AS_EXTERNAL_LSA_MIN_SIZE         4U /* w/o IPv6 prefix */
struct ospf6_as_external_lsa {
	u_int32_t bits_metric;

	struct ospf6_prefix prefix;
	/* followed by none or one forwarding address */
	/* followed by none or one external route tag */
	/* followed by none or one referenced LS-ID */
};

#define OSPF6_ASBR_BIT_T  ntohl (0x01000000)
#define OSPF6_ASBR_BIT_F  ntohl (0x02000000)
#define OSPF6_ASBR_BIT_E  ntohl (0x04000000)

#define OSPF6_ASBR_METRIC(E) (ntohl ((E)->bits_metric & htonl (0x00ffffff)))
#define OSPF6_ASBR_METRIC_SET(E, C)                                            \
	{                                                                      \
		(E)->bits_metric &= htonl(0xff000000);                         \
		(E)->bits_metric |= htonl(0x00ffffff) & htonl(C);              \
	}

extern void ospf6_asbr_lsa_add(struct ospf6_lsa *lsa);
extern void ospf6_asbr_lsa_remove(struct ospf6_lsa *lsa);
extern void ospf6_asbr_lsentry_add(struct ospf6_route *asbr_entry);
extern void ospf6_asbr_lsentry_remove(struct ospf6_route *asbr_entry);

extern int ospf6_asbr_is_asbr(struct ospf6 *o);
extern void ospf6_asbr_redistribute_add(int type, ifindex_t ifindex,
					struct prefix *prefix,
					u_int nexthop_num,
					struct in6_addr *nexthop,
					route_tag_t tag);
extern void ospf6_asbr_redistribute_remove(int type, ifindex_t ifindex,
					   struct prefix *prefix);

extern int ospf6_redistribute_config_write(struct vty *vty);

extern void ospf6_asbr_init(void);
extern void ospf6_asbr_redistribute_reset(void);
extern void ospf6_asbr_terminate(void);
extern void ospf6_asbr_send_externals_to_area(struct ospf6_area *);

extern int config_write_ospf6_debug_asbr(struct vty *vty);
extern void install_element_ospf6_debug_asbr(void);
extern void ospf6_asbr_update_route_ecmp_path(struct ospf6_route *old,
					      struct ospf6_route *route);
extern void ospf6_asbr_distribute_list_update(int type);

#endif /* OSPF6_ASBR_H */
