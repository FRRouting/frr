/*
 * EIGRP SNMP Support.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#ifdef HAVE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"
#include "checksum.h"
#include "md5.h"
#include "keychain.h"
#include "smux.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_snmp.h"

struct list *eigrp_snmp_iflist;

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* EIGRP-MIB - 1.3.6.1.4.1.9.9.449.1*/
#define EIGRPMIB 1,3,6,1,4,1,9,9,449,1

/* EIGRP-MIB instances. */
oid eigrp_oid[] = {EIGRPMIB};

/* EIGRP VPN entry */
#define EIGRPVPNID						1
#define EIGRPVPNNAME						2

/* EIGRP Traffic statistics entry */
#define EIGRPASNUMBER					1
#define EIGRPNBRCOUNT					2
#define EIGRPHELLOSSENT					3
#define EIGRPHELLOSRCVD					4
#define EIGRPUPDATESSENT				5
#define EIGRPUPDATESRCVD				6
#define EIGRPQUERIESSENT				7
#define EIGRPQUERIESRCVD				8
#define EIGRPREPLIESSENT				9
#define EIGRPREPLIESRCVD				10
#define EIGRPACKSSENT					11
#define EIGRPACKSRCVD					12
#define EIGRPINPUTQHIGHMARK				13
#define EIGRPINPUTQDROPS				14
#define EIGRPSIAQUERIESSENT				15
#define EIGRPSIAQUERIESRCVD				16
#define EIGRPASROUTERIDTYPE				17
#define EIGRPASROUTERID					18
#define EIGRPTOPOROUTES					19
#define EIGRPHEADSERIAL					20
#define EIGRPNEXTSERIAL					21
#define EIGRPXMITPENDREPLIES				22
#define EIGRPXMITDUMMIES				23

/* EIGRP topology entry */
#define EIGRPDESTNETTYPE				1
#define EIGRPDESTNET					2
#define EIGRPDESTNETPREFIXLEN				4
#define EIGRPACTIVE					5
#define EIGRPSTUCKINACTIVE				6
#define EIGRPDESTSUCCESSORS				7
#define EIGRPFDISTANCE					8
#define EIGRPROUTEORIGINTYPE				9
#define EIGRPROUTEORIGINADDRTYPE			10
#define EIGRPROUTEORIGINADDR				11
#define EIGRPNEXTHOPADDRESSTYPE				12
#define EIGRPNEXTHOPADDRESS				13
#define EIGRPNEXTHOPINTERFACE				14
#define EIGRPDISTANCE					15
#define EIGRPREPORTDISTANCE				16

/* EIGRP peer entry */
#define EIGRPHANDLE							1
#define EIGRPPEERADDRTYPE					2
#define EIGRPPEERADDR						3
#define EIGRPPEERIFINDEX					4
#define EIGRPHOLDTIME						5
#define EIGRPUPTIME							6
#define EIGRPSRTT							7
#define EIGRPRTO							8
#define EIGRPPKTSENQUEUED					9
#define EIGRPLASTSEQ						10
#define EIGRPVERSION						11
#define EIGRPRETRANS						12
#define EIGRPRETRIES						13

/* EIGRP interface entry */
#define EIGRPPEERCOUNT						3
#define EIGRPXMITRELIABLEQ					4
#define EIGRPXMITUNRELIABLEQ	        	5
#define EIGRPMEANSRTT						6
#define EIGRPPACINGRELIABLE					7
#define EIGRPPACINGUNRELIABLE		        8
#define EIGRPMFLOWTIMER						9
#define EIGRPPENDINGROUTES					10
#define EIGRPHELLOINTERVAL					11
#define EIGRPXMITNEXTSERIAL					12
#define EIGRPUMCASTS						13
#define EIGRPRMCASTS						14
#define EIGRPUUCASTS						15
#define EIGRPRUCASTS						16
#define EIGRPMCASTEXCEPTS					17
#define EIGRPCRPKTS							18
#define EIGRPACKSSUPPRESSED					19
#define EIGRPRETRANSSENT					20
#define EIGRPOOSRCVD						21
#define EIGRPAUTHMODE						22
#define EIGRPAUTHKEYCHAIN					23

/* SNMP value hack. */
#define COUNTER                 ASN_COUNTER
#define INTEGER                 ASN_INTEGER
#define GAUGE                   ASN_GAUGE
#define TIMETICKS               ASN_TIMETICKS
#define IPADDRESS               ASN_IPADDRESS
#define STRING                  ASN_OCTET_STR
#define IPADDRESSPREFIXLEN      ASN_INTEGER
#define IPADDRESSTYPE           ASN_INTEGER
#define INTERFACEINDEXORZERO    ASN_INTEGER
#define UINTEGER                ASN_UNSIGNED

/* Hook functions. */
static uint8_t *eigrpVpnEntry(struct variable *, oid *, size_t *, int, size_t *,
			      WriteMethod **);
static uint8_t *eigrpTraffStatsEntry(struct variable *, oid *, size_t *, int,
				     size_t *, WriteMethod **);
static uint8_t *eigrpTopologyEntry(struct variable *, oid *, size_t *, int,
				   size_t *, WriteMethod **);
static uint8_t *eigrpPeerEntry(struct variable *, oid *, size_t *, int,
			       size_t *, WriteMethod **);
static uint8_t *eigrpInterfaceEntry(struct variable *, oid *, size_t *, int,
				    size_t *, WriteMethod **);


struct variable eigrp_variables[] = {
	/* EIGRP vpn variables */
	{EIGRPVPNID, INTEGER, NOACCESS, eigrpVpnEntry, 4, {1, 1, 1, 1}},
	{EIGRPVPNNAME, STRING, RONLY, eigrpVpnEntry, 4, {1, 1, 1, 2}},

	/* EIGRP traffic stats variables */
	{EIGRPASNUMBER,
	 UINTEGER,
	 NOACCESS,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 1}},
	{EIGRPNBRCOUNT, UINTEGER, RONLY, eigrpTraffStatsEntry, 4, {2, 1, 1, 2}},
	{EIGRPHELLOSSENT,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 3}},
	{EIGRPHELLOSRCVD,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 4}},
	{EIGRPUPDATESSENT,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 5}},
	{EIGRPUPDATESRCVD,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 6}},
	{EIGRPQUERIESSENT,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 7}},
	{EIGRPQUERIESRCVD,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 8}},
	{EIGRPREPLIESSENT,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 9}},
	{EIGRPREPLIESRCVD,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 10}},
	{EIGRPACKSSENT, COUNTER, RONLY, eigrpTraffStatsEntry, 4, {2, 1, 1, 11}},
	{EIGRPACKSRCVD, COUNTER, RONLY, eigrpTraffStatsEntry, 4, {2, 1, 1, 12}},
	{EIGRPINPUTQHIGHMARK,
	 INTEGER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 13}},
	{EIGRPINPUTQDROPS,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 14}},
	{EIGRPSIAQUERIESSENT,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 15}},
	{EIGRPSIAQUERIESRCVD,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 16}},
	{EIGRPASROUTERIDTYPE,
	 IPADDRESSTYPE,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 17}},
	{EIGRPASROUTERID,
	 IPADDRESS,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 18}},
	{EIGRPTOPOROUTES,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 19}},
	{EIGRPHEADSERIAL,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 20}},
	{EIGRPNEXTSERIAL,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 21}},
	{EIGRPXMITPENDREPLIES,
	 INTEGER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 22}},
	{EIGRPXMITDUMMIES,
	 COUNTER,
	 RONLY,
	 eigrpTraffStatsEntry,
	 4,
	 {2, 1, 1, 23}},

	/* EIGRP topology variables */
	{EIGRPDESTNETTYPE,
	 IPADDRESSTYPE,
	 NOACCESS,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 1}},
	{EIGRPDESTNET,
	 IPADDRESSPREFIXLEN,
	 NOACCESS,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 2}},
	{EIGRPDESTNETPREFIXLEN,
	 IPADDRESSTYPE,
	 NOACCESS,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 4}},
	{EIGRPACTIVE, INTEGER, RONLY, eigrpTopologyEntry, 4, {3, 1, 1, 5}},
	{EIGRPSTUCKINACTIVE,
	 INTEGER,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 6}},
	{EIGRPDESTSUCCESSORS,
	 INTEGER,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 7}},
	{EIGRPFDISTANCE, INTEGER, RONLY, eigrpTopologyEntry, 4, {3, 1, 1, 8}},
	{EIGRPROUTEORIGINTYPE,
	 STRING,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 9}},
	{EIGRPROUTEORIGINADDRTYPE,
	 IPADDRESSTYPE,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 10}},
	{EIGRPROUTEORIGINADDR,
	 IPADDRESS,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 11}},
	{EIGRPNEXTHOPADDRESSTYPE,
	 IPADDRESSTYPE,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 12}},
	{EIGRPNEXTHOPADDRESS,
	 IPADDRESS,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 13}},
	{EIGRPNEXTHOPINTERFACE,
	 STRING,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 14}},
	{EIGRPDISTANCE, INTEGER, RONLY, eigrpTopologyEntry, 4, {3, 1, 1, 15}},
	{EIGRPREPORTDISTANCE,
	 INTEGER,
	 RONLY,
	 eigrpTopologyEntry,
	 4,
	 {3, 1, 1, 16}},

	/* EIGRP peer variables */
	{EIGRPHANDLE, INTEGER, NOACCESS, eigrpPeerEntry, 4, {4, 1, 1, 1}},
	{EIGRPPEERADDRTYPE,
	 IPADDRESSTYPE,
	 RONLY,
	 eigrpPeerEntry,
	 4,
	 {4, 1, 1, 2}},
	{EIGRPPEERADDR, IPADDRESS, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 3}},
	{EIGRPPEERIFINDEX,
	 INTERFACEINDEXORZERO,
	 RONLY,
	 eigrpPeerEntry,
	 4,
	 {4, 1, 1, 4}},
	{EIGRPHOLDTIME, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 5}},
	{EIGRPUPTIME, STRING, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 6}},
	{EIGRPSRTT, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 7}},
	{EIGRPRTO, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 8}},
	{EIGRPPKTSENQUEUED, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 9}},
	{EIGRPLASTSEQ, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 10}},
	{EIGRPVERSION, STRING, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 11}},
	{EIGRPRETRANS, COUNTER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 12}},
	{EIGRPRETRIES, INTEGER, RONLY, eigrpPeerEntry, 4, {4, 1, 1, 13}},

	/* EIGRP interface variables */
	{EIGRPPEERCOUNT, GAUGE, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 3}},
	{EIGRPXMITRELIABLEQ,
	 GAUGE,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 4}},
	{EIGRPXMITUNRELIABLEQ,
	 GAUGE,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 5}},
	{EIGRPMEANSRTT, INTEGER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 6}},
	{EIGRPPACINGRELIABLE,
	 INTEGER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 7}},
	{EIGRPPACINGUNRELIABLE,
	 INTEGER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 8}},
	{EIGRPMFLOWTIMER, INTEGER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 9}},
	{EIGRPPENDINGROUTES,
	 GAUGE,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 10}},
	{EIGRPHELLOINTERVAL,
	 INTEGER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 11}},
	{EIGRPXMITNEXTSERIAL,
	 COUNTER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 12}},
	{EIGRPUMCASTS, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 13}},
	{EIGRPRMCASTS, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 14}},
	{EIGRPUUCASTS, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 15}},
	{EIGRPRUCASTS, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 16}},
	{EIGRPMCASTEXCEPTS,
	 COUNTER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 17}},
	{EIGRPCRPKTS, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 18}},
	{EIGRPACKSSUPPRESSED,
	 COUNTER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 19}},
	{EIGRPRETRANSSENT,
	 COUNTER,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 20}},
	{EIGRPOOSRCVD, COUNTER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 21}},
	{EIGRPAUTHMODE, INTEGER, RONLY, eigrpInterfaceEntry, 4, {5, 1, 1, 22}},
	{EIGRPAUTHKEYCHAIN,
	 STRING,
	 RONLY,
	 eigrpInterfaceEntry,
	 4,
	 {5, 1, 1, 23}}};

static struct eigrp_neighbor *eigrp_snmp_nbr_lookup(struct eigrp *eigrp,
						    struct in_addr *nbr_addr,
						    unsigned int *ifindex)
{
	struct listnode *node, *nnode, *node2, *nnode2;
	struct eigrp_interface *ei;
	struct eigrp_neighbor *nbr;

	for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei)) {
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			if (IPV4_ADDR_SAME(&nbr->src, nbr_addr)) {
				return nbr;
			}
		}
	}
	return NULL;
}

static struct eigrp_neighbor *
eigrp_snmp_nbr_lookup_next(struct in_addr *nbr_addr, unsigned int *ifindex,
			   int first)
{
	struct listnode *node, *nnode, *node2, *nnode2;
	struct eigrp_interface *ei;
	struct eigrp_neighbor *nbr;
	struct eigrp_neighbor *min = NULL;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();

	for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei)) {
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			if (first) {
				if (!min)
					min = nbr;
				else if (ntohl(nbr->src.s_addr)
					 < ntohl(min->src.s_addr))
					min = nbr;
			} else if (ntohl(nbr->src.s_addr)
				   > ntohl(nbr_addr->s_addr)) {
				if (!min)
					min = nbr;
				else if (ntohl(nbr->src.s_addr)
					 < ntohl(min->src.s_addr))
					min = nbr;
			}
		}
	}
	if (min) {
		*nbr_addr = min->src;
		*ifindex = 0;
		return min;
	}
	return NULL;
}

static struct eigrp_neighbor *eigrpNbrLookup(struct variable *v, oid *name,
					     size_t *length,
					     struct in_addr *nbr_addr,
					     unsigned int *ifindex, int exact)
{
	unsigned int len;
	int first;
	struct eigrp_neighbor *nbr;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();

	if (!eigrp)
		return NULL;

	if (exact) {
		if (*length != v->namelen + IN_ADDR_SIZE + 1)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, nbr_addr);
		*ifindex = name[v->namelen + IN_ADDR_SIZE];

		return eigrp_snmp_nbr_lookup(eigrp, nbr_addr, ifindex);
	} else {
		first = 0;
		len = *length - v->namelen;

		if (len == 0)
			first = 1;

		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(name + v->namelen, len, nbr_addr);

		len = *length - v->namelen - IN_ADDR_SIZE;
		if (len >= 1)
			*ifindex = name[v->namelen + IN_ADDR_SIZE];

		nbr = eigrp_snmp_nbr_lookup_next(nbr_addr, ifindex, first);

		if (nbr) {
			*length = v->namelen + IN_ADDR_SIZE + 1;
			oid_copy_addr(name + v->namelen, nbr_addr,
				      IN_ADDR_SIZE);
			name[v->namelen + IN_ADDR_SIZE] = *ifindex;
			return nbr;
		}
	}
	return NULL;
}


static uint8_t *eigrpVpnEntry(struct variable *v, oid *name, size_t *length,
			      int exact, size_t *var_len,
			      WriteMethod **write_method)
{
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case EIGRPVPNID: /* 1 */
		/* The unique VPN identifier */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPVPNNAME: /* 2 */
		/* The name given to the VPN */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	default:
		return NULL;
	}
	return NULL;
}

static uint32_t eigrp_neighbor_count(struct eigrp *eigrp)
{
	uint32_t count;
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	if (eigrp == NULL) {
		return 0;
	}

	count = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			if (nbr->state == EIGRP_NEIGHBOR_UP)
				count++;
		}
	}

	return count;
}


static uint8_t *eigrpTraffStatsEntry(struct variable *v, oid *name,
				     size_t *length, int exact, size_t *var_len,
				     WriteMethod **write_method)
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node, *nnode;
	int counter;

	eigrp = eigrp_lookup();

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case EIGRPASNUMBER: /* 1 */
		/* AS-number of this EIGRP instance. */
		if (eigrp)
			return SNMP_INTEGER(eigrp->AS);
		else
			return SNMP_INTEGER(0);
		break;
	case EIGRPNBRCOUNT: /* 2 */
		/* Neighbor count of this EIGRP instance */
		if (eigrp)
			return SNMP_INTEGER(eigrp_neighbor_count(eigrp));
		else
			return SNMP_INTEGER(0);
		break;
	case EIGRPHELLOSSENT: /* 3 */
		/* Hello packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->hello_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPHELLOSRCVD: /* 4 */
		/* Hello packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->hello_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPUPDATESSENT: /* 5 */
		/* Update packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->update_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPUPDATESRCVD: /* 6 */
		/* Update packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->update_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPQUERIESSENT: /* 7 */
		/* Querry packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->query_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPQUERIESRCVD: /* 8 */
		/* Querry packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->query_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPREPLIESSENT: /* 9 */
		/* Reply packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->reply_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPREPLIESRCVD: /* 10 */
		/* Reply packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->reply_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPACKSSENT: /* 11 */
		/* Acknowledgement packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->ack_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPACKSRCVD: /* 12 */
		/* Acknowledgement packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->ack_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPINPUTQHIGHMARK: /* 13 */
		/* The highest number of EIGRP packets in the input queue */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPINPUTQDROPS: /* 14 */
		/* The number of EIGRP packets dropped from the input queue */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPSIAQUERIESSENT: /* 15 */
		/* SIA querry packets output count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->siaQuery_out;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPSIAQUERIESRCVD: /* 16 */
		/* SIA querry packets input count */
		if (eigrp) {
			counter = 0;
			for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode,
					       ei)) {
				counter += ei->siaQuery_in;
			}
			return SNMP_INTEGER(counter);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPASROUTERIDTYPE: /* 17 */
		/* Whether the router ID is set manually or automatically */
		if (eigrp)
			if (eigrp->router_id_static != 0)
				return SNMP_INTEGER(1);
			else
				return SNMP_INTEGER(1);
		else
			return SNMP_INTEGER(0);
		break;
	case EIGRPASROUTERID: /* 18 */
		/* Router ID for this EIGRP AS */
		if (eigrp)
			if (eigrp->router_id_static != 0)
				return SNMP_INTEGER(eigrp->router_id_static);
			else
				return SNMP_INTEGER(eigrp->router_id);
		else
			return SNMP_INTEGER(0);
		break;
	case EIGRPTOPOROUTES: /* 19 */
		/* The total number of EIGRP derived routes currently existing
		   in the topology table for the AS */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPHEADSERIAL: /* 20 */
		/* The serial number of the first route in the internal
		   sequence for an AS*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPNEXTSERIAL: /* 21 */
		/* The serial number that would be assigned to the next new
		 or changed route in the topology table for the AS*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPXMITPENDREPLIES: /* 22 */
		/* Total number of outstanding replies expected to queries
		   that have been sent to peers in the current AS*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPXMITDUMMIES: /* 23 */
		/* Total number of currently existing dummies associated with
		 * the AS*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *eigrpTopologyEntry(struct variable *v, oid *name,
				   size_t *length, int exact, size_t *var_len,
				   WriteMethod **write_method)
{
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case EIGRPDESTNETTYPE: /* 1 */
		/* The format of the destination IP network number for a single
		   route in the topology table*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPDESTNET: /* 2 */
		/* The destination IP network number for a single route in the
		 * topology table*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPDESTNETPREFIXLEN: /* 4 */
		/* The prefix length associated with the destination IP network
		   address
		   for a single route in the topology table in the AS*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPACTIVE: /* 5 */
		/* A value of true(1) indicates the route to the destination
		   network has failed
		   A value of false(2) indicates the route is stable
		   (passive).*/
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPSTUCKINACTIVE: /* 6 */
		/* A value of true(1) indicates that that this route which is in
		   active state
		   has not received any replies to queries for alternate paths
		   */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPDESTSUCCESSORS: /* 7 */
		/* Next routing hop for a path to the destination IP network */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPFDISTANCE: /* 8 */
		/* Minimum distance from this router to the destination IP
		 * network */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPROUTEORIGINTYPE: /* 9 */
		/* Text string describing the internal origin of the EIGRP route
		 */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPROUTEORIGINADDRTYPE: /* 10 */
		/* The format of the IP address defined as the origin of this
		   topology route entry */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPROUTEORIGINADDR: /* 11 */
		/* If the origin of the topology route entry is external to this
		   router,
		   then this object is the IP address of the router from which
		   it originated */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPNEXTHOPADDRESSTYPE: /* 12 */
		/* The format of the next hop IP address */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPNEXTHOPADDRESS: /* 13 */
		/* Next hop IP address for the route */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPNEXTHOPINTERFACE: /* 14 */
		/* The interface through which the next hop IP address is
		 * reached */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPDISTANCE: /* 15 */
		/* The computed distance to the destination network entry from
		 * this router */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPREPORTDISTANCE: /* 16 */
		/* The computed distance to the destination network in the
		   topology entry
		   reported to this router by the originator of this route */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *eigrpPeerEntry(struct variable *v, oid *name, size_t *length,
			       int exact, size_t *var_len,
			       WriteMethod **write_method)
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct eigrp_neighbor *nbr;
	struct in_addr nbr_addr;
	unsigned int ifindex;

	eigrp = eigrp_lookup();

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&nbr_addr, 0, sizeof(struct in_addr));
	ifindex = 0;

	nbr = eigrpNbrLookup(v, name, length, &nbr_addr, &ifindex, exact);
	if (!nbr)
		return NULL;
	ei = nbr->ei;
	if (!ei)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case EIGRPHANDLE: /* 1 */
		/* The unique internal identifier for the peer in the AS */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPEERADDRTYPE: /* 2 */
		/* The format of the remote source IP address used by the peer
		 */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPEERADDR: /* 3 */
		/* The source IP address used by the peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPEERIFINDEX: /* 4 */
		/* The ifIndex of the interface on this router */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPHOLDTIME: /* 5 */
		/* How much time must pass without receiving a hello packet from
		   this
		   EIGRP peer before this router declares the peer down */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPUPTIME: /* 6 */
		/* The elapsed time since the EIGRP adjacency was first
		 * established */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPSRTT: /* 7 */
		/* The computed smooth round trip time for packets to and from
		 * the peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRTO: /* 8 */
		/* The computed retransmission timeout for the peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPKTSENQUEUED: /* 9 */
		/* The number of any EIGRP packets currently enqueued */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPLASTSEQ: /* 10 */
		/* sequence number of the last EIGRP packet sent to this peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPVERSION: /* 11 */
		/* The EIGRP version information reported by the remote peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRETRANS: /* 12 */
		/* The cumulative number of retransmissions to this peer */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRETRIES: /* 13 */
		/* The number of times the current unacknowledged packet has
		 * been retried */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *eigrpInterfaceEntry(struct variable *v, oid *name,
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	struct eigrp *eigrp;
	struct listnode *node, *nnode;
	struct keychain *keychain;
	struct list *keylist;

	eigrp = eigrp_lookup();

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case EIGRPPEERCOUNT: /* 3 */
		/* The number of EIGRP adjacencies currently formed with
		   peers reached through this interface */
		if (eigrp) {
			return SNMP_INTEGER(eigrp_neighbor_count(eigrp));
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPXMITRELIABLEQ: /* 4 */
		/* The number of EIGRP packets currently waiting in the reliable
		   transport transmission queue */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPXMITUNRELIABLEQ: /* 5 */
		/* The number of EIGRP packets currently waiting in the
		   unreliable
		   transport transmission queue */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPMEANSRTT: /* 6 */
		/* The average of all the computed smooth round trip time values
		   for a packet to and from all peers established on this
		   interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPACINGRELIABLE: /* 7 */
		/* The configured time interval between EIGRP packet
		 * transmissions */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPACINGUNRELIABLE: /* 8 */
		/* The configured time interval between EIGRP packet
		   transmissions
		   on the interface when the unreliable transport method is used
		   */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPMFLOWTIMER: /* 9 */
		/* The configured multicast flow control timer value */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPPENDINGROUTES: /* 10 */
		/* The number of queued EIGRP routing updates awaiting
		 * transmission */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPHELLOINTERVAL: /* 11 */
		/* The configured time interval between Hello packet
		 * transmissions */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPXMITNEXTSERIAL: /* 12 */
		/* The serial number of the next EIGRP packet that is to be
		   queued
		   for transmission */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPUMCASTS: /* 13 */
		/* The total number of unreliable EIGRP multicast packets sent
		   on this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRMCASTS: /* 14 */
		/* The total number of reliable EIGRP multicast packets sent
		   on this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPUUCASTS: /* 15 */
		/* The total number of unreliable EIGRP unicast packets sent
		   on this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRUCASTS: /* 16 */
		/* The total number of reliable EIGRP unicast packets sent
		   on this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPMCASTEXCEPTS: /* 17 */
		/* The total number of EIGRP multicast exception transmissions
		 */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPCRPKTS: /* 18 */
		/* The total number EIGRP Conditional-Receive packets sent on
		 * this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPACKSSUPPRESSED: /* 19 */
		/* The total number of individual EIGRP acknowledgement packets
		   that have been
		   suppressed and combined in an already enqueued outbound
		   reliable packet on this interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPRETRANSSENT: /* 20 */
		/* The total number EIGRP packet retransmissions sent on the
		 * interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPOOSRCVD: /* 21 */
		/* The total number of out-of-sequence EIGRP packets received */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPAUTHMODE: /* 22 */
		/* The EIGRP authentication mode of the interface */
		if (eigrp) {
			return SNMP_INTEGER(1);
		} else
			return SNMP_INTEGER(0);
		break;
	case EIGRPAUTHKEYCHAIN: /* 23 */
		/* The name of the authentication key-chain configured
		   on this interface. */
		keylist = keychain_list_get();
		for (ALL_LIST_ELEMENTS(keylist, node, nnode, keychain)) {
			return (uint8_t *)keychain->name;
		}
		if (eigrp && keychain) {
			*var_len = str_len(keychain->name);
			return (uint8_t *)keychain->name;
		} else
			return (uint8_t *)"TEST";
		break;
	default:
		return NULL;
	}
	return NULL;
}

/* Register EIGRP-MIB. */
void eigrp_snmp_init()
{
	eigrp_snmp_iflist = list_new();
	smux_init(eigrp_om->master);
	REGISTER_MIB("ciscoEigrpMIB", eigrp_variables, variable, eigrp_oid);
}
#endif
