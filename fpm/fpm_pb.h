// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fpm_pb.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 *
 * Portions:
 *   Copyright (C) 2024 Carmine Scarpitta (for SRv6)
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

/*
 * fpm__srv6_sid_format__create
 */
#define fpm_srv6_sid_format_create fpm__srv6_sid_format__create
static inline Fpm__SRv6SIDFormat *
fpm__srv6_sid_format__create(qpb_allocator_t *allocator,
			     uint8_t locator_block_length,
			     uint8_t locator_node_length,
			     uint8_t function_length, uint8_t argument_length)
{
	Fpm__SRv6SIDFormat *sid_format;

	sid_format = QPB_ALLOC(allocator, typeof(*sid_format));
	if (!sid_format)
		return NULL;
	fpm__srv6_sidformat__init(sid_format);

	sid_format->locator_block_length = locator_block_length;
	sid_format->locator_node_length = locator_node_length;
	sid_format->function_length = function_length;
	sid_format->argument_length = argument_length;

	return sid_format;
}

/*
 * fpm__srv6_local_sid_end_behavior__create
 */
#define fpm_srv6_local_sid_end_behavior_create                                 \
	fpm__srv6_local_sid_end_behavior__create
static inline Fpm__SRv6LocalSID__End *
fpm__srv6_local_sid_end_behavior__create(qpb_allocator_t *allocator)
{
	Fpm__SRv6LocalSID__End *end;

	end = QPB_ALLOC(allocator, typeof(*end));
	if (!end)
		return NULL;

	fpm__srv6_local_sid__end__init(end);

	return end;
}

/*
 * fpm__srv6_local_sid_end_x_behavior__create
 */
#define fpm_srv6_local_sid_end_x_behavior_create                               \
	fpm__srv6_local_sid_end_x_behavior__create
static inline Fpm__SRv6LocalSID__EndX *
fpm__srv6_local_sid_end_x_behavior__create(qpb_allocator_t *allocator,
					   struct nexthop *nexthop)
{
	Fpm__SRv6LocalSID__EndX *end_x;

	end_x = QPB_ALLOC(allocator, typeof(*end_x));
	if (!end_x)
		return NULL;

	fpm__srv6_local_sid__end_x__init(end_x);

	end_x->nexthop = fpm_nexthop_create(allocator, nexthop);

	return end_x;
}

/*
 * fpm__srv6_local_sid_end_t_behavior__create
 */
#define fpm_srv6_local_sid_end_t_behavior_create                               \
	fpm__srv6_local_sid_end_t_behavior__create
static inline Fpm__SRv6LocalSID__EndT *
fpm__srv6_local_sid_end_t_behavior__create(qpb_allocator_t *allocator,
					   vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__EndT *end_t;

	end_t = QPB_ALLOC(allocator, typeof(*end_t));
	if (!end_t)
		return NULL;

	fpm__srv6_local_sid__end_t__init(end_t);

	end_t->vrf_id = vrf_id;

	return end_t;
}

/*
 * fpm__srv6_local_sid_end_dx6_behavior__create
 */
#define fpm_srv6_local_sid_end_dx6_behavior_create                             \
	fpm__srv6_local_sid_end_dx6_behavior__create
static inline Fpm__SRv6LocalSID__EndDX6 *
fpm__srv6_local_sid_end_dx6_behavior__create(qpb_allocator_t *allocator,
					     struct nexthop *nexthop)
{
	Fpm__SRv6LocalSID__EndDX6 *end_dx6;

	end_dx6 = QPB_ALLOC(allocator, typeof(*end_dx6));
	if (!end_dx6)
		return NULL;

	fpm__srv6_local_sid__end_dx6__init(end_dx6);

	end_dx6->nexthop = fpm_nexthop_create(allocator, nexthop);

	return end_dx6;
}

/*
 * fpm__srv6_local_sid_end_dx4_behavior__create
 */
#define fpm_srv6_local_sid_end_dx4_behavior_create                             \
	fpm__srv6_local_sid_end_dx4_behavior__create
static inline Fpm__SRv6LocalSID__EndDX4 *
fpm__srv6_local_sid_end_dx4_behavior__create(qpb_allocator_t *allocator,
					     struct nexthop *nexthop)
{
	Fpm__SRv6LocalSID__EndDX4 *end_dx4;

	end_dx4 = QPB_ALLOC(allocator, typeof(*end_dx4));
	if (!end_dx4)
		return NULL;

	fpm__srv6_local_sid__end_dx4__init(end_dx4);

	end_dx4->nexthop = fpm_nexthop_create(allocator, nexthop);

	return end_dx4;
}

/*
 * fpm__srv6_local_sid_end_dt6_behavior__create
 */
#define fpm_srv6_local_sid_end_dt6_behavior_create                             \
	fpm__srv6_local_sid_end_dt6_behavior__create
static inline Fpm__SRv6LocalSID__EndDT6 *
fpm__srv6_local_sid_end_dt6_behavior__create(qpb_allocator_t *allocator,
					     vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__EndDT6 *end_dt6;

	end_dt6 = QPB_ALLOC(allocator, typeof(*end_dt6));
	if (!end_dt6)
		return NULL;

	fpm__srv6_local_sid__end_dt6__init(end_dt6);

	end_dt6->vrf_id = vrf_id;

	return end_dt6;
}

/*
 * fpm__srv6_local_sid_end_dt4_behavior__create
 */
#define fpm_srv6_local_sid_end_dt4_behavior_create                             \
	fpm__srv6_local_sid_end_dt4_behavior__create
static inline Fpm__SRv6LocalSID__EndDT4 *
fpm__srv6_local_sid_end_dt4_behavior__create(qpb_allocator_t *allocator,
					     vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__EndDT4 *end_dt4;

	end_dt4 = QPB_ALLOC(allocator, typeof(*end_dt4));
	if (!end_dt4)
		return NULL;

	fpm__srv6_local_sid__end_dt4__init(end_dt4);

	end_dt4->vrf_id = vrf_id;

	return end_dt4;
}

/*
 * fpm__srv6_local_sid_end_dt46_behavior__create
 */
#define fpm_srv6_local_sid_end_dt46_behavior_create                            \
	fpm__srv6_local_sid_end_dt46_behavior__create
static inline Fpm__SRv6LocalSID__EndDT46 *
fpm__srv6_local_sid_end_dt46_behavior__create(qpb_allocator_t *allocator,
					      vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__EndDT46 *end_dt46;

	end_dt46 = QPB_ALLOC(allocator, typeof(*end_dt46));
	if (!end_dt46)
		return NULL;

	fpm__srv6_local_sid__end_dt46__init(end_dt46);

	end_dt46->vrf_id = vrf_id;

	return end_dt46;
}

/*
 * fpm__srv6_local_sid_un_behavior__create
 */
#define fpm_srv6_local_sid_un_behavior_create                                  \
	fpm__srv6_local_sid_un_behavior__create
static inline Fpm__SRv6LocalSID__UN *
fpm__srv6_local_sid_un_behavior__create(qpb_allocator_t *allocator)
{
	Fpm__SRv6LocalSID__UN *un;

	un = QPB_ALLOC(allocator, typeof(*un));
	if (!un)
		return NULL;

	fpm__srv6_local_sid__un__init(un);

	return un;
}

/*
 * fpm__srv6_local_sid_ua_behavior__create
 */
#define fpm_srv6_local_sid_ua_behavior_create                                  \
	fpm__srv6_local_sid_ua_behavior__create
static inline Fpm__SRv6LocalSID__UA *
fpm__srv6_local_sid_ua_behavior__create(qpb_allocator_t *allocator,
					struct nexthop *nexthop)
{
	Fpm__SRv6LocalSID__UA *ua;

	ua = QPB_ALLOC(allocator, typeof(*ua));
	if (!ua)
		return NULL;

	fpm__srv6_local_sid__ua__init(ua);

	ua->nexthop = fpm_nexthop_create(allocator, nexthop);

	return ua;
}

/*
 * fpm__srv6_local_sid_udt6_behavior__create
 */
#define fpm_srv6_local_sid_udt6_behavior_create                                \
	fpm__srv6_local_sid_udt6_behavior__create
static inline Fpm__SRv6LocalSID__UDT6 *
fpm__srv6_local_sid_udt6_behavior__create(qpb_allocator_t *allocator,
					  vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__UDT6 *udt6;

	udt6 = QPB_ALLOC(allocator, typeof(*udt6));
	if (!udt6)
		return NULL;

	fpm__srv6_local_sid__udt6__init(udt6);

	udt6->vrf_id = vrf_id;

	return udt6;
}

/*
 * fpm__srv6_local_sid_udt4_behavior__create
 */
#define fpm_srv6_local_sid_udt4_behavior_create                                \
	fpm__srv6_local_sid_udt4_behavior__create
static inline Fpm__SRv6LocalSID__UDT4 *
fpm__srv6_local_sid_udt4_behavior__create(qpb_allocator_t *allocator,
					  vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__UDT4 *udt4;

	udt4 = QPB_ALLOC(allocator, typeof(*udt4));
	if (!udt4)
		return NULL;

	fpm__srv6_local_sid__udt4__init(udt4);

	udt4->vrf_id = vrf_id;

	return udt4;
}

/*
 * fpm__srv6_local_sid_udt46_behavior__create
 */
#define fpm_srv6_local_sid_udt46_behavior_create                               \
	fpm__srv6_local_sid_udt46_behavior__create
static inline Fpm__SRv6LocalSID__UDT46 *
fpm__srv6_local_sid_udt46_behavior__create(qpb_allocator_t *allocator,
					   vrf_id_t vrf_id)
{
	Fpm__SRv6LocalSID__UDT46 *udt46;

	udt46 = QPB_ALLOC(allocator, typeof(*udt46));
	if (!udt46)
		return NULL;

	fpm__srv6_local_sid__udt46__init(udt46);

	udt46->vrf_id = vrf_id;

	return udt46;
}

#endif
