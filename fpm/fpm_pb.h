// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fpm_pb.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 */

/*
 * Public header file for fpm protobuf definitions.
 */

#ifndef _FPM_PB_H
#define _FPM_PB_H

#include "lib/route_types.h"
#include "lib/vrf.h"
#include "qpb/qpb.h"

#include "fpm/fpm.pb-c.h"

/*
 * fpm__route_key__create
 */
#define fpm_route_key_create fpm__route_key__create
static inline Fpm__RouteKey *fpm__route_key__create(qpb_allocator_t *allocator,
						    struct prefix *prefix)
{
	Fpm__RouteKey *key;

	key = QPB_ALLOC(allocator, typeof(*key));
	if (!key) {
		return NULL;
	}
	fpm__route_key__init(key);

	key->prefix = qpb__l3_prefix__create(allocator, prefix);
	if (!key->prefix) {
		return NULL;
	}

	return key;
}

/*
 * fpm__nexthop__create
 */
#define fpm_nexthop_create fpm__nexthop__create
static inline Fpm__Nexthop *
fpm__nexthop__create(qpb_allocator_t *allocator, struct nexthop *nh)
{
	Fpm__Nexthop *nexthop;
	uint8_t family;

	nexthop = QPB_ALLOC(allocator, typeof(*nexthop));
	if (!nexthop)
		return NULL;

	fpm__nexthop__init(nexthop);

	if (nh->type == NEXTHOP_TYPE_IPV4 ||
	    nh->type == NEXTHOP_TYPE_IPV4_IFINDEX)
		family = AF_INET;
	else if (nh->type == NEXTHOP_TYPE_IPV6 ||
		 nh->type == NEXTHOP_TYPE_IPV6_IFINDEX)
		family = AF_INET6;
	else
		return NULL;

	nexthop->if_id = qpb__if_identifier__create(allocator, nh->ifindex);
	if (!nexthop->if_id)
		return NULL;

	nexthop->address = qpb__l3_address__create(allocator, &nh->gate, family);
	if (!nexthop->address)
		return NULL;


	return nexthop;
}

/*
 * fpm__nexthop__get
 *
 * Read out information from a protobuf nexthop structure.
 */
#define fpm_nexthop_get fpm__nexthop__get
static inline int fpm__nexthop__get(const Fpm__Nexthop *nh,
				    struct nexthop *nexthop)
{
	struct in_addr ipv4;
	struct in6_addr ipv6;
	uint32_t ifindex;
	char *ifname;

	if (!nh)
		return 0;

	if (!qpb_if_identifier_get(nh->if_id, &ifindex, &ifname))
		return 0;

	if (nh->address) {
		if (nh->address->v4) {
			memset(&ipv4, 0, sizeof(ipv4));
			if (!qpb__ipv4_address__get(nh->address->v4, &ipv4))
				return 0;

			nexthop->vrf_id = VRF_DEFAULT;
			nexthop->type = NEXTHOP_TYPE_IPV4;
			nexthop->gate.ipv4 = ipv4;
			if (ifindex) {
				nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				nexthop->ifindex = ifindex;
			}
			return 1;
		}

		if (nh->address->v6) {
			memset(&ipv6, 0, sizeof(ipv6));
			if (!qpb__ipv6_address__get(nh->address->v6, &ipv6))
				return 0;
			nexthop->vrf_id = VRF_DEFAULT;
			nexthop->type = NEXTHOP_TYPE_IPV6;
			nexthop->gate.ipv6 = ipv6;
			if (ifindex) {
				nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				nexthop->ifindex = ifindex;
			}
			return 1;
		}
	}

	return 0;
}

#endif
