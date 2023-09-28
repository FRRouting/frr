// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP4 SNMP support
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "frrevent.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_snmp.h"
#include "bgpd/bgp_snmp_bgp4.h"
#include "bgpd/bgp_mplsvpn_snmp.h"

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* BGP-MIB instances. */
static oid bgp_oid[] = {BGP4MIB};
static oid bgp_trap_oid[] = {BGP4MIB, 0};

/* IP address 0.0.0.0. */
static struct in_addr bgp_empty_addr = {.s_addr = 0};

static uint8_t *bgpVersion(struct variable *v, oid name[], size_t *length,
			   int exact, size_t *var_len,
			   WriteMethod **write_method)
{
	static uint8_t version;

	if (smux_header_generic(v, name, length, exact, var_len,
				write_method) == MATCH_FAILED)
		return NULL;

	/* Return BGP version.  Zebra bgpd only support version 4. */
	version = (0x80 >> (BGP_VERSION_4 - 1));

	/* Return octet string length 1. */
	*var_len = 1;
	return &version;
}

static uint8_t *bgpLocalAs(struct variable *v, oid name[], size_t *length,
			   int exact, size_t *var_len,
			   WriteMethod **write_method)
{
	struct bgp *bgp;

	if (smux_header_generic(v, name, length, exact, var_len,
				write_method) == MATCH_FAILED)
		return NULL;

	/* Get BGP structure. */
	bgp = bgp_get_default();
	if (!bgp)
		return NULL;

	return SNMP_INTEGER(bgp->as);
}

static struct peer *peer_lookup_addr_ipv4(struct in_addr *src)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	struct listnode *bgpnode;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			if (sockunion_family(&peer->connection->su) != AF_INET)
				continue;

			if (sockunion2ip(&peer->connection->su) == src->s_addr)
				return peer;
		}
	}

	return NULL;
}

static struct peer *bgp_peer_lookup_next(struct in_addr *src)
{
	struct bgp *bgp;
	struct peer *peer;
	struct peer *next_peer = NULL;
	struct listnode *node;
	struct listnode *bgpnode;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			if (sockunion_family(&peer->connection->su) != AF_INET)
				continue;
			if (ntohl(sockunion2ip(&peer->connection->su)) <=
			    ntohl(src->s_addr))
				continue;

			if (!next_peer ||
			    ntohl(sockunion2ip(&next_peer->connection->su)) >
				    ntohl(sockunion2ip(&peer->connection->su))) {
				next_peer = peer;
			}
		}
	}

	if (next_peer) {
		src->s_addr = sockunion2ip(&next_peer->connection->su);
		return next_peer;
	}

	return NULL;
}

/* 1.3.6.1.2.1.15.3.1.x  = 10 */
#define PEERTAB_NAMELEN 10

static struct peer *bgpPeerTable_lookup(struct variable *v, oid name[],
					size_t *length, struct in_addr *addr,
					int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : PEERTAB_NAMELEN;
	int len;

	if (exact) {
		/* Check the length. */
		if (*length - namelen != sizeof(struct in_addr))
			return NULL;

		oid2in_addr(name + namelen, IN_ADDR_SIZE, addr);

		peer = peer_lookup_addr_ipv4(addr);
		return peer;
	} else {
		len = *length - namelen;
		if (len > 4)
			len = 4;

		oid2in_addr(name + namelen, len, addr);

		peer = bgp_peer_lookup_next(addr);

		if (peer == NULL)
			return NULL;

		oid_copy_in_addr(name + namelen, addr);
		*length = sizeof(struct in_addr) + namelen;

		return peer;
	}
	return NULL;
}

/* BGP write methods. */
static int write_bgpPeerTable(int action, uint8_t *var_val,
			      uint8_t var_val_type, size_t var_val_len,
			      uint8_t *statP, oid *name, size_t length)
{
	struct in_addr addr;
	struct peer *peer;
	struct peer_connection *connection;
	long intval;

	if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	}
	if (var_val_len != sizeof(long)) {
		return SNMP_ERR_WRONGLENGTH;
	}

	intval = *(long *)var_val;

	memset(&addr, 0, sizeof(addr));

	peer = bgpPeerTable_lookup(NULL, name, &length, &addr, 1);
	if (!peer)
		return SNMP_ERR_NOSUCHNAME;

	connection = peer->connection;

	if (action != SNMP_MSG_INTERNAL_SET_COMMIT)
		return SNMP_ERR_NOERROR;

	zlog_info("%s: SNMP write .%ld = %ld", peer->host,
		  (long)name[PEERTAB_NAMELEN - 1], intval);

	switch (name[PEERTAB_NAMELEN - 1]) {
	case BGPPEERADMINSTATUS:
#define BGP_PeerAdmin_stop 1
#define BGP_PeerAdmin_start 2
		/* When the peer is established,   */
		if (intval == BGP_PeerAdmin_stop)
			BGP_EVENT_ADD(connection, BGP_Stop);
		else if (intval == BGP_PeerAdmin_start)
			; /* Do nothing. */
		else
			return SNMP_ERR_NOSUCHNAME;
		break;
	case BGPPEERCONNECTRETRYINTERVAL:
		peer_flag_set(peer, PEER_FLAG_TIMER_CONNECT);
		peer->connect = intval;
		peer->v_connect = intval;
		break;
	case BGPPEERHOLDTIMECONFIGURED:
		peer_flag_set(peer, PEER_FLAG_TIMER);
		peer->holdtime = intval;
		peer->v_holdtime = intval;
		break;
	case BGPPEERKEEPALIVECONFIGURED:
		peer_flag_set(peer, PEER_FLAG_TIMER);
		peer->keepalive = intval;
		peer->v_keepalive = intval;
		break;
	case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
		peer->v_routeadv = intval;
		break;
	}
	return SNMP_ERR_NOERROR;
}

static uint8_t *bgpPeerTable(struct variable *v, oid name[], size_t *length,
			     int exact, size_t *var_len,
			     WriteMethod **write_method)
{
	static struct in_addr addr;
	struct peer *peer;
	uint32_t ui, uo;

	if (smux_header_table(v, name, length, exact, var_len, write_method) ==
	    MATCH_FAILED)
		return NULL;
	memset(&addr, 0, sizeof(addr));

	peer = bgpPeerTable_lookup(v, name, length, &addr, exact);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case BGPPEERIDENTIFIER:
		return SNMP_IPADDRESS(peer->remote_id);
	case BGPPEERSTATE:
		return SNMP_INTEGER(peer->connection->status);
	case BGPPEERADMINSTATUS:
		*write_method = write_bgpPeerTable;
#define BGP_PeerAdmin_stop 1
#define BGP_PeerAdmin_start 2
		if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
			return SNMP_INTEGER(BGP_PeerAdmin_stop);
		else
			return SNMP_INTEGER(BGP_PeerAdmin_start);
	case BGPPEERNEGOTIATEDVERSION:
		return SNMP_INTEGER(BGP_VERSION_4);
	case BGPPEERLOCALADDR:
		if (peer->su_local)
			return SNMP_IPADDRESS(peer->su_local->sin.sin_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);
	case BGPPEERLOCALPORT:
		if (peer->su_local)
			return SNMP_INTEGER(
				ntohs(peer->su_local->sin.sin_port));
		else
			return SNMP_INTEGER(0);
	case BGPPEERREMOTEADDR:
		if (peer->su_remote)
			return SNMP_IPADDRESS(peer->su_remote->sin.sin_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);
	case BGPPEERREMOTEPORT:
		if (peer->su_remote)
			return SNMP_INTEGER(
				ntohs(peer->su_remote->sin.sin_port));
		else
			return SNMP_INTEGER(0);
	case BGPPEERREMOTEAS:
		return SNMP_INTEGER(peer->as);
	case BGPPEERINUPDATES:
		ui = atomic_load_explicit(&peer->update_in,
					  memory_order_relaxed);
		return SNMP_INTEGER(ui);
	case BGPPEEROUTUPDATES:
		uo = atomic_load_explicit(&peer->update_out,
					  memory_order_relaxed);
		return SNMP_INTEGER(uo);
	case BGPPEERINTOTALMESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_RX(peer));
	case BGPPEEROUTTOTALMESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_TX(peer));
	case BGPPEERLASTERROR: {
		static uint8_t lasterror[2];
		lasterror[0] = peer->notify.code;
		lasterror[1] = peer->notify.subcode;
		*var_len = 2;
		return (uint8_t *)&lasterror;
	}
	case BGPPEERFSMESTABLISHEDTRANSITIONS:
		return SNMP_INTEGER(peer->established);
	case BGPPEERFSMESTABLISHEDTIME:
		if (peer->uptime == 0)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->uptime);
	case BGPPEERCONNECTRETRYINTERVAL:
		*write_method = write_bgpPeerTable;
		return SNMP_INTEGER(peer->v_connect);
	case BGPPEERHOLDTIME:
		return SNMP_INTEGER(peer->v_holdtime);
	case BGPPEERKEEPALIVE:
		return SNMP_INTEGER(peer->v_keepalive);
	case BGPPEERHOLDTIMECONFIGURED:
		*write_method = write_bgpPeerTable;
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
			return SNMP_INTEGER(peer->holdtime);
		else
			return SNMP_INTEGER(peer->v_holdtime);
	case BGPPEERKEEPALIVECONFIGURED:
		*write_method = write_bgpPeerTable;
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
			return SNMP_INTEGER(peer->keepalive);
		else
			return SNMP_INTEGER(peer->v_keepalive);
	case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
		*write_method = write_bgpPeerTable;
		return SNMP_INTEGER(peer->v_routeadv);
	case BGPPEERINUPDATEELAPSEDTIME:
		if (peer->update_time == 0)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->update_time);
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *bgpIdentifier(struct variable *v, oid name[], size_t *length,
			      int exact, size_t *var_len,
			      WriteMethod **write_method)
{
	struct bgp *bgp;

	if (smux_header_generic(v, name, length, exact, var_len,
				write_method) == MATCH_FAILED)
		return NULL;

	bgp = bgp_get_default();
	if (!bgp)
		return NULL;

	return SNMP_IPADDRESS(bgp->router_id);
}

static uint8_t *bgpRcvdPathAttrTable(struct variable *v, oid name[],
				     size_t *length, int exact, size_t *var_len,
				     WriteMethod **write_method)
{
	/* Received Path Attribute Table.  This table contains, one entry
	   per path to a network, path attributes received from all peers
	   running BGP version 3 or less.  This table is obsolete, having
	   been replaced in functionality with the bgp4PathAttrTable.  */
	return NULL;
}

static struct bgp_path_info *bgp4PathAttrLookup(struct variable *v, oid name[],
						size_t *length, struct bgp *bgp,
						struct prefix_ipv4 *addr,
						int exact)
{
	oid *offset;
	int offsetlen;
	struct bgp_path_info *path;
	struct bgp_path_info *min;
	struct bgp_dest *dest;
	union sockunion su;
	unsigned int len;
	struct in_addr paddr;

	sockunion_init(&su);

#define BGP_PATHATTR_ENTRY_OFFSET (IN_ADDR_SIZE + 1 + IN_ADDR_SIZE)

	if (exact) {
		if (*length - v->namelen != BGP_PATHATTR_ENTRY_OFFSET)
			return NULL;

		/* Set OID offset for prefix. */
		offset = name + v->namelen;
		oid2in_addr(offset, IN_ADDR_SIZE, &addr->prefix);
		offset++;

		/* Prefix length. */
		addr->prefixlen = *offset;
		offset++;

		/* Peer address. */
		su.sin.sin_family = AF_INET;
		oid2in_addr(offset, IN_ADDR_SIZE, &su.sin.sin_addr);

		/* Lookup node. */
		dest = bgp_node_lookup(bgp->rib[AFI_IP][SAFI_UNICAST],
				       (struct prefix *)addr);
		if (dest) {
			for (path = bgp_dest_get_bgp_path_info(dest); path;
			     path = path->next)
				if (sockunion_same(&path->peer->connection->su,
						   &su))
					return path;

			bgp_dest_unlock_node(dest);
		}
	} else {
		offset = name + v->namelen;
		offsetlen = *length - v->namelen;
		len = offsetlen;

		if (offsetlen == 0)
			dest = bgp_table_top(bgp->rib[AFI_IP][SAFI_UNICAST]);
		else {
			if (len > IN_ADDR_SIZE)
				len = IN_ADDR_SIZE;

			oid2in_addr(offset, len, &addr->prefix);

			offset += IN_ADDR_SIZE;
			offsetlen -= IN_ADDR_SIZE;

			if (offsetlen > 0)
				addr->prefixlen = *offset;
			else
				addr->prefixlen = len * 8;

			dest = bgp_node_get(bgp->rib[AFI_IP][SAFI_UNICAST],
					    (struct prefix *)addr);

			offset++;
			offsetlen--;
		}

		if (offsetlen > 0) {
			len = offsetlen;
			if (len > IN_ADDR_SIZE)
				len = IN_ADDR_SIZE;

			oid2in_addr(offset, len, &paddr);
		} else
			paddr.s_addr = INADDR_ANY;

		if (!dest)
			return NULL;

		do {
			min = NULL;

			for (path = bgp_dest_get_bgp_path_info(dest); path;
			     path = path->next) {
				if (path->peer->connection->su.sin.sin_family ==
					    AF_INET &&
				    ntohl(paddr.s_addr) <
					    ntohl(path->peer->connection->su.sin
							  .sin_addr.s_addr)) {
					if (min) {
						if (ntohl(path->peer->connection
								  ->su.sin
								  .sin_addr
								  .s_addr) <
						    ntohl(min->peer->connection
								  ->su.sin
								  .sin_addr
								  .s_addr))
							min = path;
					} else
						min = path;
				}
			}

			if (min) {
				const struct prefix *rn_p =
					bgp_dest_get_prefix(dest);

				*length =
					v->namelen + BGP_PATHATTR_ENTRY_OFFSET;

				offset = name + v->namelen;
				oid_copy_in_addr(offset, &rn_p->u.prefix4);
				offset++;
				*offset = rn_p->prefixlen;
				offset++;
				oid_copy_in_addr(offset,
						 &min->peer->connection->su.sin
							  .sin_addr);
				addr->prefix = rn_p->u.prefix4;
				addr->prefixlen = rn_p->prefixlen;

				bgp_dest_unlock_node(dest);

				return min;
			}

			paddr.s_addr = INADDR_ANY;
		} while ((dest = bgp_route_next(dest)) != NULL);
	}
	return NULL;
}

static uint8_t *bgp4PathAttrTable(struct variable *v, oid name[],
				  size_t *length, int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	struct bgp *bgp;
	struct bgp_path_info *path;
	struct prefix_ipv4 addr;

	bgp = bgp_get_default();
	if (!bgp)
		return NULL;

	if (smux_header_table(v, name, length, exact, var_len, write_method) ==
	    MATCH_FAILED)
		return NULL;
	memset(&addr, 0, sizeof(addr));

	path = bgp4PathAttrLookup(v, name, length, bgp, &addr, exact);
	if (!path)
		return NULL;

	switch (v->magic) {
	case BGP4PATHATTRPEER: /* 1 */
		return SNMP_IPADDRESS(path->peer->connection->su.sin.sin_addr);
	case BGP4PATHATTRIPADDRPREFIXLEN: /* 2 */
		return SNMP_INTEGER(addr.prefixlen);
	case BGP4PATHATTRIPADDRPREFIX: /* 3 */
		return SNMP_IPADDRESS(addr.prefix);
	case BGP4PATHATTRORIGIN: /* 4 */
		return SNMP_INTEGER(path->attr->origin);
	case BGP4PATHATTRASPATHSEGMENT: /* 5 */
		return aspath_snmp_pathseg(path->attr->aspath, var_len);
	case BGP4PATHATTRNEXTHOP: /* 6 */
		return SNMP_IPADDRESS(path->attr->nexthop);
	case BGP4PATHATTRMULTIEXITDISC: /* 7 */
		return SNMP_INTEGER(path->attr->med);
	case BGP4PATHATTRLOCALPREF: /* 8 */
		return SNMP_INTEGER(path->attr->local_pref);
	case BGP4PATHATTRATOMICAGGREGATE: /* 9 */
		return SNMP_INTEGER(1);
	case BGP4PATHATTRAGGREGATORAS: /* 10 */
		return SNMP_INTEGER(path->attr->aggregator_as);
	case BGP4PATHATTRAGGREGATORADDR: /* 11 */
		return SNMP_IPADDRESS(path->attr->aggregator_addr);
	case BGP4PATHATTRCALCLOCALPREF: /* 12 */
		return SNMP_INTEGER(-1);
	case BGP4PATHATTRBEST: /* 13 */
#define BGP4_PathAttrBest_false 1
#define BGP4_PathAttrBest_true 2
		if (CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
			return SNMP_INTEGER(BGP4_PathAttrBest_true);
		else
			return SNMP_INTEGER(BGP4_PathAttrBest_false);
	case BGP4PATHATTRUNKNOWN: /* 14 */
		*var_len = 0;
		return NULL;
	}
	return NULL;
}

/* BGP Traps. */
static struct trap_object bgpTrapList[] = {{3, {3, 1, BGPPEERREMOTEADDR}},
					   {3, {3, 1, BGPPEERLASTERROR}},
					   {3, {3, 1, BGPPEERSTATE}}};

static struct variable bgp_variables[] = {
	/* BGP version. */
	{BGPVERSION, OCTET_STRING, RONLY, bgpVersion, 1, {1}},
	/* BGP local AS. */
	{BGPLOCALAS, INTEGER, RONLY, bgpLocalAs, 1, {2}},
	/* BGP peer table. */
	{BGPPEERIDENTIFIER, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 1}},
	{BGPPEERSTATE, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 2}},
	{BGPPEERADMINSTATUS, INTEGER, RWRITE, bgpPeerTable, 3, {3, 1, 3}},
	{BGPPEERNEGOTIATEDVERSION,
	 INTEGER32,
	 RONLY,
	 bgpPeerTable,
	 3,
	 {3, 1, 4}},
	{BGPPEERLOCALADDR, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 5}},
	{BGPPEERLOCALPORT, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 6}},
	{BGPPEERREMOTEADDR, IPADDRESS, RONLY, bgpPeerTable, 3, {3, 1, 7}},
	{BGPPEERREMOTEPORT, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 8}},
	{BGPPEERREMOTEAS, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 9}},
	{BGPPEERINUPDATES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 10}},
	{BGPPEEROUTUPDATES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 11}},
	{BGPPEERINTOTALMESSAGES, COUNTER32, RONLY, bgpPeerTable, 3, {3, 1, 12}},
	{BGPPEEROUTTOTALMESSAGES,
	 COUNTER32,
	 RONLY,
	 bgpPeerTable,
	 3,
	 {3, 1, 13}},
	{BGPPEERLASTERROR, OCTET_STRING, RONLY, bgpPeerTable, 3, {3, 1, 14}},
	{BGPPEERFSMESTABLISHEDTRANSITIONS,
	 COUNTER32,
	 RONLY,
	 bgpPeerTable,
	 3,
	 {3, 1, 15}},
	{BGPPEERFSMESTABLISHEDTIME,
	 GAUGE32,
	 RONLY,
	 bgpPeerTable,
	 3,
	 {3, 1, 16}},
	{BGPPEERCONNECTRETRYINTERVAL,
	 INTEGER,
	 RWRITE,
	 bgpPeerTable,
	 3,
	 {3, 1, 17}},
	{BGPPEERHOLDTIME, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 18}},
	{BGPPEERKEEPALIVE, INTEGER, RONLY, bgpPeerTable, 3, {3, 1, 19}},
	{BGPPEERHOLDTIMECONFIGURED,
	 INTEGER,
	 RWRITE,
	 bgpPeerTable,
	 3,
	 {3, 1, 20}},
	{BGPPEERKEEPALIVECONFIGURED,
	 INTEGER,
	 RWRITE,
	 bgpPeerTable,
	 3,
	 {3, 1, 21}},
	{BGPPEERMINROUTEADVERTISEMENTINTERVAL,
	 INTEGER,
	 RWRITE,
	 bgpPeerTable,
	 3,
	 {3, 1, 23}},
	{BGPPEERINUPDATEELAPSEDTIME,
	 GAUGE32,
	 RONLY,
	 bgpPeerTable,
	 3,
	 {3, 1, 24}},
	/* BGP identifier. */
	{BGPIDENTIFIER, IPADDRESS, RONLY, bgpIdentifier, 1, {4}},
	/* BGP received path attribute table. */
	{BGPPATHATTRPEER, IPADDRESS, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 1}},
	{BGPPATHATTRDESTNETWORK,
	 IPADDRESS,
	 RONLY,
	 bgpRcvdPathAttrTable,
	 3,
	 {5, 1, 2}},
	{BGPPATHATTRORIGIN, INTEGER, RONLY, bgpRcvdPathAttrTable, 3, {5, 1, 3}},
	{BGPPATHATTRASPATH,
	 OCTET_STRING,
	 RONLY,
	 bgpRcvdPathAttrTable,
	 3,
	 {5, 1, 4}},
	{BGPPATHATTRNEXTHOP,
	 IPADDRESS,
	 RONLY,
	 bgpRcvdPathAttrTable,
	 3,
	 {5, 1, 5}},
	{BGPPATHATTRINTERASMETRIC,
	 INTEGER32,
	 RONLY,
	 bgpRcvdPathAttrTable,
	 3,
	 {5, 1, 6}},
	/* BGP-4 received path attribute table. */
	{BGP4PATHATTRPEER, IPADDRESS, RONLY, bgp4PathAttrTable, 3, {6, 1, 1}},
	{BGP4PATHATTRIPADDRPREFIXLEN,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 2}},
	{BGP4PATHATTRIPADDRPREFIX,
	 IPADDRESS,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 3}},
	{BGP4PATHATTRORIGIN, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 4}},
	{BGP4PATHATTRASPATHSEGMENT,
	 OCTET_STRING,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 5}},
	{BGP4PATHATTRNEXTHOP,
	 IPADDRESS,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 6}},
	{BGP4PATHATTRMULTIEXITDISC,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 7}},
	{BGP4PATHATTRLOCALPREF,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 8}},
	{BGP4PATHATTRATOMICAGGREGATE,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 9}},
	{BGP4PATHATTRAGGREGATORAS,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 10}},
	{BGP4PATHATTRAGGREGATORADDR,
	 IPADDRESS,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 11}},
	{BGP4PATHATTRCALCLOCALPREF,
	 INTEGER,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 12}},
	{BGP4PATHATTRBEST, INTEGER, RONLY, bgp4PathAttrTable, 3, {6, 1, 13}},
	{BGP4PATHATTRUNKNOWN,
	 OCTET_STRING,
	 RONLY,
	 bgp4PathAttrTable,
	 3,
	 {6, 1, 14}},
};

int bgpTrapEstablished(struct peer *peer)
{
	int ret;
	struct in_addr addr;
	oid index[sizeof(oid) * IN_ADDR_SIZE];
	struct peer_connection *connection = peer->connection;

	/* Check if this peer just went to Established */
	if ((connection->ostatus != OpenConfirm) ||
	    !(peer_established(connection)))
		return 0;

	ret = inet_aton(peer->host, &addr);
	if (ret == 0)
		return 0;

	oid_copy_in_addr(index, &addr);

	smux_trap(bgp_variables, array_size(bgp_variables), bgp_trap_oid,
		  array_size(bgp_trap_oid), bgp_oid,
		  sizeof(bgp_oid) / sizeof(oid), index, IN_ADDR_SIZE,
		  bgpTrapList, array_size(bgpTrapList), BGPESTABLISHED);
	return 0;
}

int bgpTrapBackwardTransition(struct peer *peer)
{
	int ret;
	struct in_addr addr;
	oid index[sizeof(oid) * IN_ADDR_SIZE];

	ret = inet_aton(peer->host, &addr);
	if (ret == 0)
		return 0;

	oid_copy_in_addr(index, &addr);

	smux_trap(bgp_variables, array_size(bgp_variables), bgp_trap_oid,
		  array_size(bgp_trap_oid), bgp_oid,
		  sizeof(bgp_oid) / sizeof(oid), index, IN_ADDR_SIZE,
		  bgpTrapList, array_size(bgpTrapList), BGPBACKWARDTRANSITION);
	return 0;
}

int bgp_snmp_bgp4_init(struct event_loop *tm)
{
	REGISTER_MIB("mibII/bgp", bgp_variables, variable, bgp_oid);
	return 0;
}
