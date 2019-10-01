/* RIP SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "smux.h"
#include "libfrr.h"
#include "version.h"

#include "ripd/ripd.h"

/* RIPv2-MIB. */
#define RIPV2MIB 1,3,6,1,2,1,23

/* RIPv2-MIB rip2Globals values. */
#define RIP2GLOBALROUTECHANGES  1
#define RIP2GLOBALQUERIES       2

/* RIPv2-MIB rip2IfStatEntry. */
#define RIP2IFSTATENTRY         1

/* RIPv2-MIB rip2IfStatTable. */
#define RIP2IFSTATADDRESS       1
#define RIP2IFSTATRCVBADPACKETS 2
#define RIP2IFSTATRCVBADROUTES  3
#define RIP2IFSTATSENTUPDATES   4
#define RIP2IFSTATSTATUS        5

/* RIPv2-MIB rip2IfConfTable. */
#define RIP2IFCONFADDRESS       1
#define RIP2IFCONFDOMAIN        2
#define RIP2IFCONFAUTHTYPE      3
#define RIP2IFCONFAUTHKEY       4
#define RIP2IFCONFSEND          5
#define RIP2IFCONFRECEIVE       6
#define RIP2IFCONFDEFAULTMETRIC 7
#define RIP2IFCONFSTATUS        8
#define RIP2IFCONFSRCADDRESS    9

/* RIPv2-MIB rip2PeerTable. */
#define RIP2PEERADDRESS         1
#define RIP2PEERDOMAIN          2
#define RIP2PEERLASTUPDATE      3
#define RIP2PEERVERSION         4
#define RIP2PEERRCVBADPACKETS   5
#define RIP2PEERRCVBADROUTES    6

/* SNMP value hack. */
#define COUNTER     ASN_COUNTER
#define INTEGER     ASN_INTEGER
#define TIMETICKS   ASN_TIMETICKS
#define IPADDRESS   ASN_IPADDRESS
#define STRING      ASN_OCTET_STR

/* Define SNMP local variables. */
SNMP_LOCAL_VARIABLES

/* RIP-MIB instances. */
static oid rip_oid[] = {RIPV2MIB};

/* Interface cache table sorted by interface's address. */
static struct route_table *rip_ifaddr_table;

/* Hook functions. */
static uint8_t *rip2Globals(struct variable *, oid[], size_t *, int, size_t *,
			    WriteMethod **);
static uint8_t *rip2IfStatEntry(struct variable *, oid[], size_t *, int,
				size_t *, WriteMethod **);
static uint8_t *rip2IfConfAddress(struct variable *, oid[], size_t *, int,
				  size_t *, WriteMethod **);
static uint8_t *rip2PeerTable(struct variable *, oid[], size_t *, int, size_t *,
			      WriteMethod **);

static struct variable rip_variables[] = {
	/* RIP Global Counters. */
	{RIP2GLOBALROUTECHANGES, COUNTER, RONLY, rip2Globals, 2, {1, 1}},
	{RIP2GLOBALQUERIES, COUNTER, RONLY, rip2Globals, 2, {1, 2}},
	/* RIP Interface Tables. */
	{RIP2IFSTATADDRESS, IPADDRESS, RONLY, rip2IfStatEntry, 3, {2, 1, 1}},
	{RIP2IFSTATRCVBADPACKETS,
	 COUNTER,
	 RONLY,
	 rip2IfStatEntry,
	 3,
	 {2, 1, 2}},
	{RIP2IFSTATRCVBADROUTES, COUNTER, RONLY, rip2IfStatEntry, 3, {2, 1, 3}},
	{RIP2IFSTATSENTUPDATES, COUNTER, RONLY, rip2IfStatEntry, 3, {2, 1, 4}},
	{RIP2IFSTATSTATUS, COUNTER, RWRITE, rip2IfStatEntry, 3, {2, 1, 5}},
	{RIP2IFCONFADDRESS,
	 IPADDRESS,
	 RONLY,
	 rip2IfConfAddress,
	 /* RIP Interface Configuration Table. */
	 3,
	 {3, 1, 1}},
	{RIP2IFCONFDOMAIN, STRING, RONLY, rip2IfConfAddress, 3, {3, 1, 2}},
	{RIP2IFCONFAUTHTYPE, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 3}},
	{RIP2IFCONFAUTHKEY, STRING, RONLY, rip2IfConfAddress, 3, {3, 1, 4}},
	{RIP2IFCONFSEND, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 5}},
	{RIP2IFCONFRECEIVE, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 6}},
	{RIP2IFCONFDEFAULTMETRIC,
	 COUNTER,
	 RONLY,
	 rip2IfConfAddress,
	 3,
	 {3, 1, 7}},
	{RIP2IFCONFSTATUS, COUNTER, RONLY, rip2IfConfAddress, 3, {3, 1, 8}},
	{RIP2IFCONFSRCADDRESS,
	 IPADDRESS,
	 RONLY,
	 rip2IfConfAddress,
	 3,
	 {3, 1, 9}},
	{RIP2PEERADDRESS,
	 IPADDRESS,
	 RONLY,
	 rip2PeerTable,
	 /* RIP Peer Table. */
	 3,
	 {4, 1, 1}},
	{RIP2PEERDOMAIN, STRING, RONLY, rip2PeerTable, 3, {4, 1, 2}},
	{RIP2PEERLASTUPDATE, TIMETICKS, RONLY, rip2PeerTable, 3, {4, 1, 3}},
	{RIP2PEERVERSION, INTEGER, RONLY, rip2PeerTable, 3, {4, 1, 4}},
	{RIP2PEERRCVBADPACKETS, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 5}},
	{RIP2PEERRCVBADROUTES, COUNTER, RONLY, rip2PeerTable, 3, {4, 1, 6}}};

extern struct thread_master *master;

static uint8_t *rip2Globals(struct variable *v, oid name[], size_t *length,
			    int exact, size_t *var_len,
			    WriteMethod **write_method)
{
	struct rip *rip;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	rip = rip_lookup_by_vrf_id(VRF_DEFAULT);
	if (!rip)
		return NULL;

	/* Retrun global counter. */
	switch (v->magic) {
	case RIP2GLOBALROUTECHANGES:
		return SNMP_INTEGER(rip->counters.route_changes);
		break;
	case RIP2GLOBALQUERIES:
		return SNMP_INTEGER(rip->counters.queries);
		break;
	default:
		return NULL;
		break;
	}
	return NULL;
}

static int rip_snmp_ifaddr_add(struct connected *ifc)
{
	struct interface *ifp = ifc->ifp;
	struct prefix *p;
	struct route_node *rn;

	p = ifc->address;

	if (p->family != AF_INET)
		return 0;

	rn = route_node_get(rip_ifaddr_table, p);
	rn->info = ifp;
	return 0;
}

static int rip_snmp_ifaddr_del(struct connected *ifc)
{
	struct interface *ifp = ifc->ifp;
	struct prefix *p;
	struct route_node *rn;
	struct interface *i;

	p = ifc->address;

	if (p->family != AF_INET)
		return 0;

	rn = route_node_lookup(rip_ifaddr_table, p);
	if (!rn)
		return 0;
	i = rn->info;
	if (!strncmp(i->name, ifp->name, INTERFACE_NAMSIZ)) {
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
	return 0;
}

static struct interface *rip_ifaddr_lookup_next(struct in_addr *addr)
{
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct interface *ifp;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = *addr;

	rn = route_node_get(rip_ifaddr_table, (struct prefix *)&p);

	for (rn = route_next(rn); rn; rn = route_next(rn))
		if (rn->info)
			break;

	if (rn && rn->info) {
		ifp = rn->info;
		*addr = rn->p.u.prefix4;
		route_unlock_node(rn);
		return ifp;
	}
	return NULL;
}

static struct interface *rip2IfLookup(struct variable *v, oid name[],
				      size_t *length, struct in_addr *addr,
				      int exact)
{
	int len;
	struct interface *ifp;

	if (exact) {
		/* Check the length. */
		if (*length - v->namelen != sizeof(struct in_addr))
			return NULL;

		oid2in_addr(name + v->namelen, sizeof(struct in_addr), addr);

		return if_lookup_exact_address((void *)addr, AF_INET,
					       VRF_DEFAULT);
	} else {
		len = *length - v->namelen;
		if (len > 4)
			len = 4;

		oid2in_addr(name + v->namelen, len, addr);

		ifp = rip_ifaddr_lookup_next(addr);

		if (ifp == NULL)
			return NULL;

		oid_copy_addr(name + v->namelen, addr, sizeof(struct in_addr));

		*length = v->namelen + sizeof(struct in_addr);

		return ifp;
	}
	return NULL;
}

static struct rip_peer *rip2PeerLookup(struct variable *v, oid name[],
				       size_t *length, struct in_addr *addr,
				       int exact)
{
	struct rip *rip;
	int len;
	struct rip_peer *peer;

	rip = rip_lookup_by_vrf_id(VRF_DEFAULT);
	if (!rip)
		return NULL;

	if (exact) {
		/* Check the length. */
		if (*length - v->namelen != sizeof(struct in_addr) + 1)
			return NULL;

		oid2in_addr(name + v->namelen, sizeof(struct in_addr), addr);

		peer = rip_peer_lookup(rip, addr);

		if (peer->domain
		    == (int)name[v->namelen + sizeof(struct in_addr)])
			return peer;

		return NULL;
	} else {
		len = *length - v->namelen;
		if (len > 4)
			len = 4;

		oid2in_addr(name + v->namelen, len, addr);

		len = *length - v->namelen;
		peer = rip_peer_lookup(rip, addr);
		if (peer) {
			if ((len < (int)sizeof(struct in_addr) + 1)
			    || (peer->domain
				> (int)name[v->namelen
					    + sizeof(struct in_addr)])) {
				oid_copy_addr(name + v->namelen, &peer->addr,
					      sizeof(struct in_addr));
				name[v->namelen + sizeof(struct in_addr)] =
					peer->domain;
				*length =
					sizeof(struct in_addr) + v->namelen + 1;
				return peer;
			}
		}
		peer = rip_peer_lookup_next(rip, addr);

		if (!peer)
			return NULL;

		oid_copy_addr(name + v->namelen, &peer->addr,
			      sizeof(struct in_addr));
		name[v->namelen + sizeof(struct in_addr)] = peer->domain;
		*length = sizeof(struct in_addr) + v->namelen + 1;

		return peer;
	}
	return NULL;
}

static uint8_t *rip2IfStatEntry(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct interface *ifp;
	struct rip_interface *ri;
	static struct in_addr addr;
	static long valid = SNMP_VALID;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&addr, 0, sizeof(struct in_addr));

	/* Lookup interface. */
	ifp = rip2IfLookup(v, name, length, &addr, exact);
	if (!ifp)
		return NULL;

	/* Fetch rip_interface information. */
	ri = ifp->info;

	switch (v->magic) {
	case RIP2IFSTATADDRESS:
		return SNMP_IPADDRESS(addr);
		break;
	case RIP2IFSTATRCVBADPACKETS:
		*var_len = sizeof(long);
		return (uint8_t *)&ri->recv_badpackets;

	case RIP2IFSTATRCVBADROUTES:
		*var_len = sizeof(long);
		return (uint8_t *)&ri->recv_badroutes;

	case RIP2IFSTATSENTUPDATES:
		*var_len = sizeof(long);
		return (uint8_t *)&ri->sent_updates;

	case RIP2IFSTATSTATUS:
		*var_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&valid;

	default:
		return NULL;
	}
	return NULL;
}

static long rip2IfConfSend(struct rip_interface *ri)
{
#define doNotSend       1
#define ripVersion1     2
#define rip1Compatible  3
#define ripVersion2     4
#define ripV1Demand     5
#define ripV2Demand     6

	if (!ri->running)
		return doNotSend;

	if (ri->ri_send & RIPv2)
		return ripVersion2;
	else if (ri->ri_send & RIPv1)
		return ripVersion1;
	else if (ri->rip) {
		if (ri->rip->version_send == RIPv2)
			return ripVersion2;
		else if (ri->rip->version_send == RIPv1)
			return ripVersion1;
	}
	return doNotSend;
}

static long rip2IfConfReceive(struct rip_interface *ri)
{
#define rip1            1
#define rip2            2
#define rip1OrRip2      3
#define doNotReceive    4

	int recvv;

	if (!ri->running)
		return doNotReceive;

	recvv = (ri->ri_receive == RI_RIP_UNSPEC) ? ri->rip->version_recv
						  : ri->ri_receive;
	if (recvv == RI_RIP_VERSION_1_AND_2)
		return rip1OrRip2;
	else if (recvv & RIPv2)
		return rip2;
	else if (recvv & RIPv1)
		return rip1;
	else
		return doNotReceive;
}

static uint8_t *rip2IfConfAddress(struct variable *v, oid name[],
				  size_t *length, int exact, size_t *val_len,
				  WriteMethod **write_method)
{
	static struct in_addr addr;
	static long valid = SNMP_INVALID;
	static long domain = 0;
	static long config = 0;
	static unsigned int auth = 0;
	struct interface *ifp;
	struct rip_interface *ri;

	if (smux_header_table(v, name, length, exact, val_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&addr, 0, sizeof(struct in_addr));

	/* Lookup interface. */
	ifp = rip2IfLookup(v, name, length, &addr, exact);
	if (!ifp)
		return NULL;

	/* Fetch rip_interface information. */
	ri = ifp->info;

	switch (v->magic) {
	case RIP2IFCONFADDRESS:
		*val_len = sizeof(struct in_addr);
		return (uint8_t *)&addr;

	case RIP2IFCONFDOMAIN:
		*val_len = 2;
		return (uint8_t *)&domain;

	case RIP2IFCONFAUTHTYPE:
		auth = ri->auth_type;
		*val_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&auth;

	case RIP2IFCONFAUTHKEY:
		*val_len = 0;
		return (uint8_t *)&domain;
	case RIP2IFCONFSEND:
		config = rip2IfConfSend(ri);
		*val_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&config;
	case RIP2IFCONFRECEIVE:
		config = rip2IfConfReceive(ri);
		*val_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&config;

	case RIP2IFCONFDEFAULTMETRIC:
		*val_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&ifp->metric;
	case RIP2IFCONFSTATUS:
		*val_len = sizeof(long);
		v->type = ASN_INTEGER;
		return (uint8_t *)&valid;
	case RIP2IFCONFSRCADDRESS:
		*val_len = sizeof(struct in_addr);
		return (uint8_t *)&addr;

	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *rip2PeerTable(struct variable *v, oid name[], size_t *length,
			      int exact, size_t *val_len,
			      WriteMethod **write_method)
{
	static struct in_addr addr;
	static int domain = 0;
	static int version;
	/* static time_t uptime; */

	struct rip_peer *peer;

	if (smux_header_table(v, name, length, exact, val_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&addr, 0, sizeof(struct in_addr));

	/* Lookup interface. */
	peer = rip2PeerLookup(v, name, length, &addr, exact);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case RIP2PEERADDRESS:
		*val_len = sizeof(struct in_addr);
		return (uint8_t *)&peer->addr;

	case RIP2PEERDOMAIN:
		*val_len = 2;
		return (uint8_t *)&domain;

	case RIP2PEERLASTUPDATE:
#if 0
      /* We don't know the SNMP agent startup time. We have two choices here:
       * - assume ripd startup time equals SNMP agent startup time
       * - don't support this variable, at all
       * Currently, we do the latter...
       */
      *val_len = sizeof (time_t);
      uptime = peer->uptime; /* now - snmp_agent_startup - peer->uptime */
      return (uint8_t *) &uptime;
#else
		return (uint8_t *)NULL;
#endif

	case RIP2PEERVERSION:
		*val_len = sizeof(int);
		version = peer->version;
		return (uint8_t *)&version;

	case RIP2PEERRCVBADPACKETS:
		*val_len = sizeof(int);
		return (uint8_t *)&peer->recv_badpackets;

	case RIP2PEERRCVBADROUTES:
		*val_len = sizeof(int);
		return (uint8_t *)&peer->recv_badroutes;

	default:
		return NULL;
	}
	return NULL;
}

/* Register RIPv2-MIB. */
static int rip_snmp_init(struct thread_master *master)
{
	rip_ifaddr_table = route_table_init();

	smux_init(master);
	REGISTER_MIB("mibII/rip", rip_variables, variable, rip_oid);
	return 0;
}

static int rip_snmp_module_init(void)
{
	hook_register(rip_ifaddr_add, rip_snmp_ifaddr_add);
	hook_register(rip_ifaddr_del, rip_snmp_ifaddr_del);

	hook_register(frr_late_init, rip_snmp_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "ripd_snmp", .version = FRR_VERSION,
		 .description = "ripd AgentX SNMP module",
		 .init = rip_snmp_module_init, )
