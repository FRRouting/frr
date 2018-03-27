/*
 * qpb.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
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

/*
 * Main public header file for the quagga protobuf library.
 */

#ifndef _QPB_H
#define _QPB_H

#include "prefix.h"

#include "qpb/qpb.pb-c.h"

#include "qpb/qpb_allocator.h"

/*
 * qpb__address_family__set
 */
#define qpb_address_family_set qpb__address_family__set
static inline int qpb__address_family__set(Qpb__AddressFamily *pb_family,
					   uint8_t family)
{
	switch (family) {
	case AF_INET:
		*pb_family = QPB__ADDRESS_FAMILY__IPV4;
		return 1;

	case AF_INET6:
		*pb_family = QPB__ADDRESS_FAMILY__IPV6;
		return 1;

	default:
		*pb_family = QPB__ADDRESS_FAMILY__UNKNOWN_AF;
	}

	return 0;
}

/*
 * qpb__address_family__get
 */
#define qpb_address_family_get qpb__address_family__get
static inline int qpb__address_family__get(Qpb__AddressFamily pb_family,
					   uint8_t *family)
{

	switch (pb_family) {
	case QPB__ADDRESS_FAMILY__IPV4:
		*family = AF_INET;
		return 1;

	case QPB__ADDRESS_FAMILY__IPV6:
		*family = AF_INET6;
		return 1;

	case QPB__ADDRESS_FAMILY__UNKNOWN_AF:
		return 0;
	default: /* protobuf "magic value" _QPB__ADDRESS_FAMILY_IS_INT_SIZE */
		return 0;
	}

	return 0;
}

/*
 * qpb__l3_prefix__create
 */
#define qpb_l3_prefix_create qpb__l3_prefix__create
static inline Qpb__L3Prefix *qpb__l3_prefix__create(qpb_allocator_t *allocator,
						    struct prefix *p)
{
	Qpb__L3Prefix *prefix;

	prefix = QPB_ALLOC(allocator, typeof(*prefix));
	if (!prefix) {
		return NULL;
	}
	qpb__l3_prefix__init(prefix);
	prefix->length = p->prefixlen;
	prefix->bytes.len = (p->prefixlen + 7) / 8;
	prefix->bytes.data = qpb_alloc(allocator, prefix->bytes.len);
	if (!prefix->bytes.data) {
		return NULL;
	}

	memcpy(prefix->bytes.data, &p->u.prefix, prefix->bytes.len);

	return prefix;
}

/*
 * qpb__l3_prefix__get
 */
#define qpb_l3_prefix_get qpb__l3_prefix__get
static inline int qpb__l3_prefix__get(const Qpb__L3Prefix *pb_prefix,
				      uint8_t family, struct prefix *prefix)
{

	switch (family) {

	case AF_INET:
		memset(prefix, 0, sizeof(struct prefix_ipv4));
		break;

	case AF_INET6:
		memset(prefix, 0, sizeof(struct prefix_ipv6));
		break;

	default:
		memset(prefix, 0, sizeof(*prefix));
	}

	prefix->prefixlen = pb_prefix->length;
	prefix->family = family;
	memcpy(&prefix->u.prefix, pb_prefix->bytes.data, pb_prefix->bytes.len);
	return 1;
}

/*
 * qpb__protocol__set
 *
 * Translate a quagga route type to a protobuf protocol.
 */
#define qpb_protocol_set qpb__protocol__set
static inline int qpb__protocol__set(Qpb__Protocol *pb_proto, int route_type)
{
	switch (route_type) {
	case ZEBRA_ROUTE_KERNEL:
		*pb_proto = QPB__PROTOCOL__KERNEL;
		break;

	case ZEBRA_ROUTE_CONNECT:
		*pb_proto = QPB__PROTOCOL__CONNECTED;
		break;

	case ZEBRA_ROUTE_STATIC:
		*pb_proto = QPB__PROTOCOL__STATIC;
		break;

	case ZEBRA_ROUTE_RIP:
		*pb_proto = QPB__PROTOCOL__RIP;
		break;

	case ZEBRA_ROUTE_RIPNG:
		*pb_proto = QPB__PROTOCOL__RIPNG;
		break;

	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		*pb_proto = QPB__PROTOCOL__OSPF;
		break;

	case ZEBRA_ROUTE_ISIS:
		*pb_proto = QPB__PROTOCOL__ISIS;
		break;

	case ZEBRA_ROUTE_BGP:
		*pb_proto = QPB__PROTOCOL__BGP;
		break;

	case ZEBRA_ROUTE_HSLS:
	case ZEBRA_ROUTE_OLSR:
	case ZEBRA_ROUTE_MAX:
	case ZEBRA_ROUTE_SYSTEM:
	default:
		*pb_proto = QPB__PROTOCOL__OTHER;
	}

	return 1;
}

/*
 * qpb__ipv4_address__create
 */
static inline Qpb__Ipv4Address *
qpb__ipv4_address__create(qpb_allocator_t *allocator, struct in_addr *addr)
{
	Qpb__Ipv4Address *v4;

	v4 = QPB_ALLOC(allocator, typeof(*v4));
	if (!v4) {
		return NULL;
	}
	qpb__ipv4_address__init(v4);

	v4->value = ntohl(addr->s_addr);
	return v4;
}

/*
 * qpb__ipv4_address__get
 */
static inline int qpb__ipv4_address__get(const Qpb__Ipv4Address *v4,
					 struct in_addr *addr)
{
	addr->s_addr = htonl(v4->value);
	return 1;
}

/*
 * qpb__ipv6_address__create
 */
static inline Qpb__Ipv6Address *
qpb__ipv6_address__create(qpb_allocator_t *allocator, struct in6_addr *addr)
{
	Qpb__Ipv6Address *v6;

	v6 = QPB_ALLOC(allocator, typeof(*v6));
	if (!v6)
		return NULL;

	qpb__ipv6_address__init(v6);
	v6->bytes.len = 16;
	v6->bytes.data = qpb_alloc(allocator, 16);
	if (!v6->bytes.data)
		return NULL;

	memcpy(v6->bytes.data, addr->s6_addr, v6->bytes.len);
	return v6;
}

/*
 * qpb__ipv6_address__get
 *
 * Read out information from a protobuf ipv6 address structure.
 */
static inline int qpb__ipv6_address__get(const Qpb__Ipv6Address *v6,
					 struct in6_addr *addr)
{
	if (v6->bytes.len != 16)
		return 0;

	memcpy(addr->s6_addr, v6->bytes.data, v6->bytes.len);
	return 1;
}

/*
 * qpb__l3_address__create
 */
#define qpb_l3_address_create qpb__l3_address__create
static inline Qpb__L3Address *
qpb__l3_address__create(qpb_allocator_t *allocator, union g_addr *addr,
			uint8_t family)
{
	Qpb__L3Address *l3_addr;

	l3_addr = QPB_ALLOC(allocator, typeof(*l3_addr));
	if (!l3_addr)
		return NULL;

	qpb__l3_address__init(l3_addr);

	switch (family) {

	case AF_INET:
		l3_addr->v4 = qpb__ipv4_address__create(allocator, &addr->ipv4);
		if (!l3_addr->v4)
			return NULL;

		break;

	case AF_INET6:
		l3_addr->v6 = qpb__ipv6_address__create(allocator, &addr->ipv6);
		if (!l3_addr->v6)
			return NULL;

		break;
	}
	return l3_addr;
}

/*
 * qpb__l3_address__get
 *
 * Read out a gateway address from a protobuf l3 address.
 */
#define qpb_l3_address_get qpb__l3_address__get
static inline int qpb__l3_address__get(const Qpb__L3Address *l3_addr,
				       uint8_t *family, union g_addr *addr)
{
	if (l3_addr->v4) {
		qpb__ipv4_address__get(l3_addr->v4, &addr->ipv4);
		*family = AF_INET;
		return 1;
	}

	if (l3_addr->v6) {
		qpb__ipv6_address__get(l3_addr->v6, &addr->ipv6);
		*family = AF_INET6;
		return 1;
	}

	return 0;
}

/*
 * qpb__if_identifier__create
 */
#define qpb_if_identifier_create qpb__if_identifier__create
static inline Qpb__IfIdentifier *
qpb__if_identifier__create(qpb_allocator_t *allocator, uint if_index)
{
	Qpb__IfIdentifier *if_id;

	if_id = QPB_ALLOC(allocator, typeof(*if_id));
	if (!if_id) {
		return NULL;
	}
	qpb__if_identifier__init(if_id);
	if_id->has_index = 1;
	if_id->index = if_index;
	return if_id;
}

/*
 * qpb__if_identifier__get
 *
 * Get interface name and/or if_index from an if identifier.
 */
#define qpb_if_identifier_get qpb__if_identifier__get
static inline int qpb__if_identifier__get(Qpb__IfIdentifier *if_id,
					  uint *if_index, char **name)
{
	char *str;
	uint ix;

	if (!if_index)
		if_index = &ix;

	if (!name)
		name = &str;

	if (if_id->has_index)
		*if_index = if_id->index;
	else
		*if_index = 0;

	*name = if_id->name;
	return 1;
}

#endif
