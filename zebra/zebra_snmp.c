// SPDX-License-Identifier: GPL-2.0-or-later
/* FIB SNMP.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

/*
 * Currently SNMP is only running properly for MIBs in the default VRF.
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "smux.h"
#include "table.h"
#include "vrf.h"
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"

#define IPFWMIB 1,3,6,1,2,1,4,24

/* ipForwardTable */
#define IPFORWARDDEST                         1
#define IPFORWARDMASK                         2
#define IPFORWARDPOLICY                       3
#define IPFORWARDNEXTHOP                      4
#define IPFORWARDIFINDEX                      5
#define IPFORWARDTYPE                         6
#define IPFORWARDPROTO                        7
#define IPFORWARDAGE                          8
#define IPFORWARDINFO                         9
#define IPFORWARDNEXTHOPAS                   10
#define IPFORWARDMETRIC1                     11
#define IPFORWARDMETRIC2                     12
#define IPFORWARDMETRIC3                     13
#define IPFORWARDMETRIC4                     14
#define IPFORWARDMETRIC5                     15

/* ipCidrRouteTable */
#define IPCIDRROUTEDEST                       1
#define IPCIDRROUTEMASK                       2
#define IPCIDRROUTETOS                        3
#define IPCIDRROUTENEXTHOP                    4
#define IPCIDRROUTEIFINDEX                    5
#define IPCIDRROUTETYPE                       6
#define IPCIDRROUTEPROTO                      7
#define IPCIDRROUTEAGE                        8
#define IPCIDRROUTEINFO                       9
#define IPCIDRROUTENEXTHOPAS                 10
#define IPCIDRROUTEMETRIC1                   11
#define IPCIDRROUTEMETRIC2                   12
#define IPCIDRROUTEMETRIC3                   13
#define IPCIDRROUTEMETRIC4                   14
#define IPCIDRROUTEMETRIC5                   15
#define IPCIDRROUTESTATUS                    16

#define INTEGER32 ASN_INTEGER
#define GAUGE32 ASN_GAUGE
#define ENUMERATION ASN_INTEGER
#define ROWSTATUS ASN_INTEGER
#define IPADDRESS ASN_IPADDRESS
#define OBJECTIDENTIFIER ASN_OBJECT_ID

static oid ipfw_oid[] = {IPFWMIB};

/* Hook functions. */
static uint8_t *ipFwNumber(struct variable *, oid[], size_t *, int, size_t *,
			   WriteMethod **);
static uint8_t *ipFwTable(struct variable *, oid[], size_t *, int, size_t *,
			  WriteMethod **);
static uint8_t *ipCidrNumber(struct variable *, oid[], size_t *, int, size_t *,
			     WriteMethod **);
static uint8_t *ipCidrTable(struct variable *, oid[], size_t *, int, size_t *,
			    WriteMethod **);

static struct variable zebra_variables[] = {
	{0, GAUGE32, RONLY, ipFwNumber, 1, {1}},
	{IPFORWARDDEST, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 1}},
	{IPFORWARDMASK, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 2}},
	{IPFORWARDPOLICY, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 3}},
	{IPFORWARDNEXTHOP, IPADDRESS, RONLY, ipFwTable, 3, {2, 1, 4}},
	{IPFORWARDIFINDEX, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 5}},
	{IPFORWARDTYPE, ENUMERATION, RONLY, ipFwTable, 3, {2, 1, 6}},
	{IPFORWARDPROTO, ENUMERATION, RONLY, ipFwTable, 3, {2, 1, 7}},
	{IPFORWARDAGE, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 8}},
	{IPFORWARDINFO, OBJECTIDENTIFIER, RONLY, ipFwTable, 3, {2, 1, 9}},
	{IPFORWARDNEXTHOPAS, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 10}},
	{IPFORWARDMETRIC1, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 11}},
	{IPFORWARDMETRIC2, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 12}},
	{IPFORWARDMETRIC3, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 13}},
	{IPFORWARDMETRIC4, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 14}},
	{IPFORWARDMETRIC5, INTEGER32, RONLY, ipFwTable, 3, {2, 1, 15}},
	{0, GAUGE32, RONLY, ipCidrNumber, 1, {3}},
	{IPCIDRROUTEDEST, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 1}},
	{IPCIDRROUTEMASK, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 2}},
	{IPCIDRROUTETOS, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 3}},
	{IPCIDRROUTENEXTHOP, IPADDRESS, RONLY, ipCidrTable, 3, {4, 1, 4}},
	{IPCIDRROUTEIFINDEX, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 5}},
	{IPCIDRROUTETYPE, ENUMERATION, RONLY, ipCidrTable, 3, {4, 1, 6}},
	{IPCIDRROUTEPROTO, ENUMERATION, RONLY, ipCidrTable, 3, {4, 1, 7}},
	{IPCIDRROUTEAGE, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 8}},
	{IPCIDRROUTEINFO, OBJECTIDENTIFIER, RONLY, ipCidrTable, 3, {4, 1, 9}},
	{IPCIDRROUTENEXTHOPAS, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 10}},
	{IPCIDRROUTEMETRIC1, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 11}},
	{IPCIDRROUTEMETRIC2, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 12}},
	{IPCIDRROUTEMETRIC3, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 13}},
	{IPCIDRROUTEMETRIC4, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 14}},
	{IPCIDRROUTEMETRIC5, INTEGER32, RONLY, ipCidrTable, 3, {4, 1, 15}},
	{IPCIDRROUTESTATUS, ROWSTATUS, RONLY, ipCidrTable, 3, {4, 1, 16}}};


static uint8_t *ipFwNumber(struct variable *v, oid objid[], size_t *objid_len,
			   int exact, size_t *val_len,
			   WriteMethod **write_method)
{
	static int result;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;

	if (smux_header_generic(v, objid, objid_len, exact, val_len,
				write_method)
	    == MATCH_FAILED)
		return NULL;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return NULL;

	/* Return number of routing entries. */
	result = 0;
	for (rn = route_top(table); rn; rn = route_next(rn))
		RNODE_FOREACH_RE (rn, re) {
			result++;
		}

	return (uint8_t *)&result;
}

static uint8_t *ipCidrNumber(struct variable *v, oid objid[], size_t *objid_len,
			     int exact, size_t *val_len,
			     WriteMethod **write_method)
{
	static int result;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;

	if (smux_header_generic(v, objid, objid_len, exact, val_len,
				write_method)
	    == MATCH_FAILED)
		return NULL;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return 0;

	/* Return number of routing entries. */
	result = 0;
	for (rn = route_top(table); rn; rn = route_next(rn))
		RNODE_FOREACH_RE (rn, re) {
			result++;
		}

	return (uint8_t *)&result;
}

static int in_addr_cmp(uint8_t *p1, uint8_t *p2)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (*p1 < *p2)
			return -1;
		if (*p1 > *p2)
			return 1;
		p1++;
		p2++;
	}
	return 0;
}

static int in_addr_add(uint8_t *p, int num)
{
	int i, ip0;

	ip0 = *p;
	p += 4;
	for (i = 3; 0 <= i; i--) {
		p--;
		if (*p + num > 255) {
			*p += num;
			num = 1;
		} else {
			*p += num;
			return 1;
		}
	}
	if (ip0 > *p) {
		/* ip + num > 0xffffffff */
		return 0;
	}

	return 1;
}

static int proto_trans(int type)
{
	switch (type) {
	case ZEBRA_ROUTE_SYSTEM:
		return 1; /* other */
	case ZEBRA_ROUTE_KERNEL:
		return 1; /* other */
	case ZEBRA_ROUTE_CONNECT:
		return 2; /* local interface */
	case ZEBRA_ROUTE_STATIC:
		return 3; /* static route */
	case ZEBRA_ROUTE_RIP:
		return 8; /* rip */
	case ZEBRA_ROUTE_RIPNG:
		return 1; /* shouldn't happen */
	case ZEBRA_ROUTE_OSPF:
		return 13; /* ospf */
	case ZEBRA_ROUTE_OSPF6:
		return 1; /* shouldn't happen */
	case ZEBRA_ROUTE_BGP:
		return 14; /* bgp */
	default:
		return 1; /* other */
	}
}

static void check_replace(struct route_node *np2, struct route_entry *re2,
			  struct route_node **np, struct route_entry **re)
{
	int proto, proto2;

	if (!*np) {
		*np = np2;
		*re = re2;
		return;
	}

	if (prefix_cmp(&(*np)->p, &np2->p) < 0)
		return;
	if (prefix_cmp(&(*np)->p, &np2->p) > 0) {
		*np = np2;
		*re = re2;
		return;
	}

	proto = proto_trans((*re)->type);
	proto2 = proto_trans(re2->type);

	if (proto2 > proto)
		return;
	if (proto2 < proto) {
		*np = np2;
		*re = re2;
		return;
	}

	if (in_addr_cmp((uint8_t *)&(*re)->nhe->nhg.nexthop->gate.ipv4,
			(uint8_t *)&re2->nhe->nhg.nexthop->gate.ipv4)
	    <= 0)
		return;

	*np = np2;
	*re = re2;
	return;
}

static void get_fwtable_route_node(struct variable *v, oid objid[],
				   size_t *objid_len, int exact,
				   struct route_node **np,
				   struct route_entry **re)
{
	struct in_addr dest;
	struct route_table *table;
	struct route_node *np2;
	struct route_entry *re2;
	int proto;
	int policy;
	struct in_addr nexthop;
	uint8_t *pnt;
	int i;

	/* Init index variables */

	pnt = (uint8_t *)&dest;
	for (i = 0; i < 4; i++)
		*pnt++ = 0;

	pnt = (uint8_t *)&nexthop;
	for (i = 0; i < 4; i++)
		*pnt++ = 0;

	proto = 0;
	policy = 0;

	/* Init return variables */

	*np = NULL;
	*re = NULL;

	/* Short circuit exact matches of wrong length */

	if (exact && (*objid_len != (unsigned)v->namelen + 10))
		return;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return;

	/* Get INDEX information out of OID.
	 * ipForwardDest, ipForwardProto, ipForwardPolicy, ipForwardNextHop
	 */

	if (*objid_len > (unsigned)v->namelen)
		oid2in_addr(objid + v->namelen,
			    MIN(4U, *objid_len - v->namelen), &dest);

	if (*objid_len > (unsigned)v->namelen + 4)
		proto = objid[v->namelen + 4];

	if (*objid_len > (unsigned)v->namelen + 5)
		policy = objid[v->namelen + 5];

	if (*objid_len > (unsigned)v->namelen + 6)
		oid2in_addr(objid + v->namelen + 6,
			    MIN(4U, *objid_len - v->namelen - 6), &nexthop);

	/* Apply GETNEXT on not exact search */

	if (!exact && (*objid_len >= (unsigned)v->namelen + 10)) {
		if (!in_addr_add((uint8_t *)&nexthop, 1))
			return;
	}

	/* For exact: search matching entry in rib table. */

	if (exact) {
		if (policy) /* Not supported (yet?) */
			return;
		for (*np = route_top(table); *np; *np = route_next(*np)) {
			if (!in_addr_cmp(&(*np)->p.u.prefix,
					 (uint8_t *)&dest)) {
				RNODE_FOREACH_RE (*np, *re) {
					if (!in_addr_cmp((uint8_t *)&(*re)->nhe
							 ->nhg.nexthop
							 ->gate.ipv4,
							 (uint8_t *)&nexthop))
						if (proto
						    == proto_trans((*re)->type))
							return;
				}
			}
		}
		return;
	}

	/* Search next best entry */

	for (np2 = route_top(table); np2; np2 = route_next(np2)) {

		/* Check destination first */
		if (in_addr_cmp(&np2->p.u.prefix, (uint8_t *)&dest) > 0)
			RNODE_FOREACH_RE (np2, re2) {
				check_replace(np2, re2, np, re);
			}

		if (in_addr_cmp(&np2->p.u.prefix, (uint8_t *)&dest)
		    == 0) { /* have to look at each re individually */
			RNODE_FOREACH_RE (np2, re2) {
				int proto2, policy2;

				proto2 = proto_trans(re2->type);
				policy2 = 0;

				if ((policy < policy2)
				    || ((policy == policy2) && (proto < proto2))
				    || ((policy == policy2) && (proto == proto2)
					&& (in_addr_cmp(
						    (uint8_t *)&re2->nhe
						    ->nhg.nexthop->gate.ipv4,
						    (uint8_t *)&nexthop)
					    >= 0)))
					check_replace(np2, re2, np, re);
			}
		}
	}

	if (!*re)
		return;

	policy = 0;
	proto = proto_trans((*re)->type);

	*objid_len = v->namelen + 10;
	pnt = (uint8_t *)&(*np)->p.u.prefix;
	for (i = 0; i < 4; i++)
		objid[v->namelen + i] = *pnt++;

	objid[v->namelen + 4] = proto;
	objid[v->namelen + 5] = policy;

	{
		struct nexthop *nexthop;

		nexthop = (*re)->nhe->nhg.nexthop;
		if (nexthop) {
			pnt = (uint8_t *)&nexthop->gate.ipv4;
			for (i = 0; i < 4; i++)
				objid[i + v->namelen + 6] = *pnt++;
		}
	}

	return;
}

static uint8_t *ipFwTable(struct variable *v, oid objid[], size_t *objid_len,
			  int exact, size_t *val_len,
			  WriteMethod **write_method)
{
	struct route_node *np;
	struct route_entry *re;
	static int result;
	static int resarr[2];
	static struct in_addr netmask;
	struct nexthop *nexthop;

	if (smux_header_table(v, objid, objid_len, exact, val_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	get_fwtable_route_node(v, objid, objid_len, exact, &np, &re);
	if (!np)
		return NULL;

	nexthop = re->nhe->nhg.nexthop;
	if (!nexthop)
		return NULL;

	switch (v->magic) {
	case IPFORWARDDEST:
		*val_len = 4;
		return &np->p.u.prefix;
	case IPFORWARDMASK:
		masklen2ip(np->p.prefixlen, &netmask);
		*val_len = 4;
		return (uint8_t *)&netmask;
	case IPFORWARDPOLICY:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDNEXTHOP:
		*val_len = 4;
		return (uint8_t *)&nexthop->gate.ipv4;
	case IPFORWARDIFINDEX:
		*val_len = sizeof(int);
		return (uint8_t *)&nexthop->ifindex;
	case IPFORWARDTYPE:
		if (nexthop->type == NEXTHOP_TYPE_IFINDEX)
			result = 3;
		else
			result = 4;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDPROTO:
		result = proto_trans(re->type);
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDAGE:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDINFO:
		resarr[0] = 0;
		resarr[1] = 0;
		*val_len = 2 * sizeof(int);
		return (uint8_t *)resarr;
	case IPFORWARDNEXTHOPAS:
		result = -1;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDMETRIC1:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDMETRIC2:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDMETRIC3:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDMETRIC4:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	case IPFORWARDMETRIC5:
		result = 0;
		*val_len = sizeof(int);
		return (uint8_t *)&result;
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *ipCidrTable(struct variable *v, oid objid[], size_t *objid_len,
			    int exact, size_t *val_len,
			    WriteMethod **write_method)
{
	if (smux_header_table(v, objid, objid_len, exact, val_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	switch (v->magic) {
	case IPCIDRROUTEDEST:
		break;
	default:
		return NULL;
	}
	return NULL;
}

static int zebra_snmp_init(struct event_loop *tm)
{
	smux_init(tm);
	REGISTER_MIB("mibII/ipforward", zebra_variables, variable, ipfw_oid);
	return 0;
}

static int zebra_snmp_module_init(void)
{
	hook_register(frr_late_init, zebra_snmp_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "zebra_snmp", .version = FRR_VERSION,
		 .description = "zebra AgentX SNMP module",
		 .init = zebra_snmp_module_init,
);
