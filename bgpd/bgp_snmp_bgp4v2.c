/* BGP4V2-MIB SNMP support
 *
 * Copyright (C) 2022 Donatas Abraitis <donatas@opensourcerouting.org>
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

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "thread.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_snmp.h"
#include "bgpd/bgp_snmp_bgp4v2.h"

SNMP_LOCAL_VARIABLES

static oid bgpv2_oid[] = {BGP4V2MIB};
static struct in_addr bgp_empty_addr = {};

static struct peer *peer_lookup_all_vrf(struct ipaddr *addr)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	struct listnode *bgpnode;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			switch (sockunion_family(&peer->su)) {
			case AF_INET:
				if (IPV4_ADDR_SAME(&peer->su.sin.sin_addr,
						   &addr->ip._v4_addr))
					return peer;
				break;
			case AF_INET6:
				if (IPV6_ADDR_SAME(&peer->su.sin6.sin6_addr,
						   &addr->ip._v6_addr))
					return peer;
				break;
			default:
				break;
			}
		}
	}

	return NULL;
}

static struct peer *peer_lookup_all_vrf_next(struct ipaddr *addr, oid *offset,
					     sa_family_t family)
{
	struct bgp *bgp;
	struct peer *peer;
	struct peer *next_peer = NULL;
	struct listnode *node;
	struct listnode *bgpnode;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			sa_family_t peer_family = sockunion_family(&peer->su);

			if (peer_family != family)
				continue;

			switch (sockunion_family(&peer->su)) {
			case AF_INET:
				oid2in_addr(offset, IN_ADDR_SIZE,
					    &addr->ip._v4_addr);
				if (IPV4_ADDR_CMP(&peer->su.sin.sin_addr,
						  &addr->ip._v4_addr) < 0 ||
				    IPV4_ADDR_SAME(&peer->su.sin.sin_addr,
						   &addr->ip._v4_addr))
					continue;

				if (!next_peer ||
				    IPV4_ADDR_CMP(&next_peer->su.sin.sin_addr,
						  &peer->su.sin.sin_addr) > 0)
					next_peer = peer;

				break;
			case AF_INET6:
				oid2in6_addr(offset, &addr->ip._v6_addr);
				if (IPV6_ADDR_CMP(&peer->su.sin6.sin6_addr,
						  &addr->ip._v6_addr) < 0 ||
				    IPV6_ADDR_SAME(&peer->su.sin6.sin6_addr,
						   &addr->ip._v6_addr))
					continue;

				if (!next_peer ||
				    IPV6_ADDR_CMP(&next_peer->su.sin6.sin6_addr,
						  &peer->su.sin6.sin6_addr) > 0)
					next_peer = peer;

				break;
			default:
				break;
			}
		}
	}

	if (next_peer)
		return next_peer;

	return NULL;
}

static struct peer *bgpv2PeerTable_lookup(struct variable *v, oid name[],
					  size_t *length, int exact,
					  struct ipaddr *addr)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : BGP4V2_PEER_ENTRY_OFFSET;
	oid *offset = name + namelen;
	sa_family_t family = name[namelen - 1] == 4 ? AF_INET : AF_INET6;

	if (exact) {
		if (family == AF_INET) {
			oid2in_addr(offset, IN_ADDR_SIZE, &addr->ip._v4_addr);
			peer = peer_lookup_all_vrf(addr);
			return peer;
		} else if (family == AF_INET6) {
			oid2in6_addr(offset, &addr->ip._v6_addr);
			return peer_lookup_all_vrf(addr);
		}
	} else {
		peer = peer_lookup_all_vrf_next(addr, offset, family);
		if (peer == NULL)
			return NULL;

		switch (sockunion_family(&peer->su)) {
		case AF_INET:
			oid_copy_in_addr(offset, &peer->su.sin.sin_addr);
			*length = IN_ADDR_SIZE + namelen;
			return peer;
		case AF_INET6:
			oid_copy_in6_addr(offset, &peer->su.sin6.sin6_addr);
			*length = IN6_ADDR_SIZE + namelen;
			return peer;
		default:
			break;
		}
	}

	return NULL;
}

static uint8_t *bgpv2PeerTable(struct variable *v, oid name[], size_t *length,
			       int exact, size_t *var_len,
			       WriteMethod **write_method)
{
	struct peer *peer;
	struct ipaddr addr = {};

	if (smux_header_table(v, name, length, exact, var_len, write_method) ==
	    MATCH_FAILED)
		return NULL;

	peer = bgpv2PeerTable_lookup(v, name, length, exact, &addr);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case BGP4V2_PEER_INSTANCE:
		return SNMP_INTEGER(peer->bgp->vrf_id);
	case BGP4V2_PEER_LOCAL_ADDR_TYPE:
		if (peer->su_local)
			return SNMP_INTEGER(peer->su_local->sa.sa_family ==
							    AF_INET
						    ? AFI_IP
						    : AFI_IP6);
		else
			return SNMP_INTEGER(0);
	case BGP4V2_PEER_LOCAL_ADDR:
		if (peer->su_local)
			if (peer->su_local->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(
					peer->su_local->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(
					peer->su_local->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);
	case BGP4V2_PEER_REMOTE_ADDR_TYPE:
		if (peer->su_remote)
			return SNMP_INTEGER(peer->su_remote->sa.sa_family ==
							    AF_INET
						    ? AFI_IP
						    : AFI_IP6);
		else
			return SNMP_INTEGER(0);
	case BGP4V2_PEER_REMOTE_ADDR:
		if (peer->su_remote)
			if (peer->su_remote->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(
					peer->su_remote->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(
					peer->su_remote->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);
	case BGP4V2_PEER_LOCAL_PORT:
		if (peer->su_local)
			if (peer->su_local->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->su_local->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->su_local->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);
	case BGP4V2_PEER_LOCAL_AS:
		return SNMP_INTEGER(peer->local_as);
	case BGP4V2_PEER_LOCAL_IDENTIFIER:
		return SNMP_IPADDRESS(peer->local_id);
	case BGP4V2_PEER_REMOTE_PORT:
		if (peer->su_remote)
			if (peer->su_remote->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->su_remote->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->su_remote->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);
	case BGP4V2_PEER_REMOTE_AS:
		return SNMP_INTEGER(peer->as);
	case BGP4V2_PEER_REMOTE_IDENTIFIER:
		return SNMP_IPADDRESS(peer->remote_id);
	case BGP4V2_PEER_ADMIN_STATUS:
#define BGP_PEER_ADMIN_STATUS_HALTED 1
#define BGP_PEER_ADMIN_STATUS_RUNNING 2
		if (BGP_PEER_START_SUPPRESSED(peer))
			return SNMP_INTEGER(BGP_PEER_ADMIN_STATUS_HALTED);
		else
			return SNMP_INTEGER(BGP_PEER_ADMIN_STATUS_RUNNING);
	case BGP4V2_PEER_STATE:
		return SNMP_INTEGER(peer->status);
	case BGP4V2_PEER_DESCRIPTION:
		if (peer->desc)
			return SNMP_STRING(peer->desc);
	default:
		break;
	}

	return NULL;
}

static struct variable bgpv2_variables[] = {
	{BGP4V2_PEER_INSTANCE,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_INSTANCE, 1, 4}},
	{BGP4V2_PEER_INSTANCE,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_INSTANCE, 2, 16}},
	{BGP4V2_PEER_LOCAL_ADDR_TYPE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_ADDR_TYPE, 1, 4}},
	{BGP4V2_PEER_LOCAL_ADDR_TYPE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_ADDR_TYPE, 2, 16}},
	{BGP4V2_PEER_LOCAL_ADDR,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_ADDR, 1, 4}},
	{BGP4V2_PEER_LOCAL_ADDR,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_ADDR, 2, 16}},
	{BGP4V2_PEER_REMOTE_ADDR_TYPE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_ADDR_TYPE, 1, 4}},
	{BGP4V2_PEER_REMOTE_ADDR_TYPE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_ADDR_TYPE, 2, 16}},
	{BGP4V2_PEER_REMOTE_ADDR,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_ADDR, 1, 4}},
	{BGP4V2_PEER_REMOTE_ADDR,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_ADDR, 2, 16}},
	{BGP4V2_PEER_LOCAL_PORT,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_PORT, 1, 4}},
	{BGP4V2_PEER_LOCAL_PORT,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_PORT, 2, 16}},
	{BGP4V2_PEER_LOCAL_AS,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_AS, 1, 4}},
	{BGP4V2_PEER_LOCAL_AS,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_AS, 2, 16}},
	{BGP4V2_PEER_LOCAL_IDENTIFIER,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_IDENTIFIER, 1, 4}},
	{BGP4V2_PEER_LOCAL_IDENTIFIER,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_LOCAL_IDENTIFIER, 2, 16}},
	{BGP4V2_PEER_REMOTE_PORT,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_PORT, 1, 4}},
	{BGP4V2_PEER_REMOTE_PORT,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_PORT, 2, 16}},
	{BGP4V2_PEER_REMOTE_AS,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_AS, 1, 4}},
	{BGP4V2_PEER_REMOTE_AS,
	 ASN_UNSIGNED,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_AS, 2, 16}},
	{BGP4V2_PEER_REMOTE_IDENTIFIER,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_IDENTIFIER, 1, 4}},
	{BGP4V2_PEER_REMOTE_IDENTIFIER,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_REMOTE_IDENTIFIER, 2, 16}},
	{BGP4V2_PEER_ADMIN_STATUS,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_ADMIN_STATUS, 1, 4}},
	{BGP4V2_PEER_ADMIN_STATUS,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_ADMIN_STATUS, 2, 16}},
	{BGP4V2_PEER_STATE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_STATE, 1, 4}},
	{BGP4V2_PEER_STATE,
	 ASN_INTEGER,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_STATE, 2, 16}},
	{BGP4V2_PEER_DESCRIPTION,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_DESCRIPTION, 1, 4}},
	{BGP4V2_PEER_DESCRIPTION,
	 ASN_OCTET_STR,
	 RONLY,
	 bgpv2PeerTable,
	 6,
	 {1, 2, 1, BGP4V2_PEER_DESCRIPTION, 2, 16}},
};

int bgp_snmp_bgp4v2_init(struct thread_master *tm)
{
	REGISTER_MIB("mibII/bgpv2", bgpv2_variables, variable, bgpv2_oid);
	return 0;
}
