/*
 * LDP SNMP support
 * Copyright (C) 2020 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This is minimal read-only implementations providing
 * mplsLdpModuleReadOnlyCompliance as described in RFC 3815.
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "vrf.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "memory.h"
#include "smux.h"
#include "libfrr.h"
#include "lib/version.h"
#include "ldpd.h"
#include "ldpe.h"

/* SNMP value hack. */
#define COUNTER32 ASN_COUNTER
#define INTEGER ASN_INTEGER
#define UNSIGNED32 ASN_GAUGE
#define TIMESTAMP ASN_TIMETICKS
#define TIMETICKS ASN_TIMETICKS
#define STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS

#define LDP_LSRID_IDX_LEN 		6
#define LDP_ENTITY_IDX_LEN		1
#define LDP_ADJACENCY_IDX_LEN		1

/* MPLS-LDP-STD-MIB. */
#define MPLS_LDP_STD_MIB 1, 3, 6, 1, 2, 1, 10, 166, 4

#define MPLS_LDP_LSR_ID				0
#define MPLS_LDP_LSR_LOOP_DETECTION_CAPABLE	0
#define MPLS_LDP_ENTITY_LAST_CHANGE		0
#define MPLS_LDP_ENTITY_INDEX_NEXT		0

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* LDP-MIB instances. */
static oid ldp_oid[] = {MPLS_LDP_STD_MIB};
static oid ldp_trap_oid[] = {MPLS_LDP_STD_MIB, 0};

static uint8_t snmp_ldp_rtrid[6] =  {0, 0, 0, 0, 0};

#define LDP_DEFAULT_ENTITY_INDEX				1

#define MPLSLDPLSRLOOPDETECTIONCAPABLE_NONE              	1
#define MPLSLDPLSRLOOPDETECTIONCAPABLE_OTHER             	2
#define MPLSLDPLSRLOOPDETECTIONCAPABLE_HOPCOUNT          	3
#define MPLSLDPLSRLOOPDETECTIONCAPABLE_PATHVECTOR		4
#define MPLSLDPLSRLOOPDETECTIONCAPABLE_HOPCOUNTANDPATHVECTOR	5

/* MPLS LDP mplsLdpHelloAdjacencyTable. */
#define MPLSLDPHELLOADJACENCYINDEX          1
#define MPLSLDPHELLOADJACENCYHOLDTIMEREM    2
#define MPLSLDPHELLOADJACENCYHOLDTIME       3
#define MPLSLDPHELLOADJACENCYTYPE           4

/* enums for column mplsLdpHelloAdjacencyType */
#define MPLSLDPHELLOADJACENCYTYPE_LINK               1
#define MPLSLDPHELLOADJACENCYTYPE_TARGETED           2

#define MPLSLDPPEERTRANSPORTADDRTYPE_UNKNOWN          0
#define MPLSLDPPEERTRANSPORTADDRTYPE_IPV4             1
#define MPLSLDPPEERTRANSPORTADDRTYPE_IPV6             2
#define MPLSLDPPEERTRANSPORTADDRTYPE_IPV4Z            3
#define MPLSLDPPEERTRANSPORTADDRTYPE_IPV6Z            4
#define MPLSLDPPEERTRANSPORTADDRTYPE_DNS              16

#define DOWNSTREAMONDEMAND         1
#define DOWNSTREAMUNSOLICITED      2

#define CONSERVATIVERETENTION      1
#define LIBERALRETENTION           2

#define TRANSPORTADDRINTERFACE     1
#define TRANSPORTADDRLOOPBACK      2

#define LABELTYPEGENERIC           1

#define STORAGETYPENONVOLATILE     3

#define ROWSTATUSACTIVE            4

#define ADMINSTATUSENABLED         1

#define OPERSTATUSENABLED          2

/* MPLS LDP mplsLdpPeerTable */
#define MPLSLDPPEERLDPID                             1
#define MPLSLDPPEERLABELDISTMETHOD                   2
#define MPLSLDPPEERPATHVECTORLIMIT                   3
#define MPLSLDPPEERTRANSPORTADDRTYPE                 4
#define MPLSLDPPEERTRANSPORTADDR                     5

#define MPLSLDPSESSIONROLE_UNKNOWN                   1
#define MPLSLDPSESSIONROLE_ACTIVE                    2
#define MPLSLDPSESSIONROLE_PASSIVE                   3

#define MPLSLDPSESSIONSTATE_NONEXISTENT              1
#define MPLSLDPSESSIONSTATE_INITIALIZED              2
#define MPLSLDPSESSIONSTATE_OPENREC                  3
#define MPLSLDPSESSIONSTATE_OPENSENT                 4
#define MPLSLDPSESSIONSTATE_OPERATIONAL              5

/* MPLS LDP mplsLdpSessionTable */
#define MPLSLDPSESSIONSTATELASTCHANGE                1
#define MPLSLDPSESSIONSTATE                          2
#define MPLSLDPSESSIONROLE                           3
#define MPLSLDPSESSIONPROTOCOLVERSION                4
#define MPLSLDPSESSIONKEEPALIVEHOLDTIMEREM           5
#define MPLSLDPSESSIONKEEPALIVETIME                  6
#define MPLSLDPSESSIONMAXPDULENGTH                   7
#define MPLSLDPSESSIONDISCONTINUITYTIME              8

/* MPLS LDP mplsLdpEntityTable */
#define MPLSLDPENTITYLDPID                1
#define MPLSLDPENTITYINDEX                2
#define MPLSLDPENTITYPROTOCOLVERSION      3
#define MPLSLDPENTITYADMINSTATUS          4
#define MPLSLDPENTITYOPERSTATUS           5
#define MPLSLDPENTITYTCPPORT              6
#define MPLSLDPENTITYUDPDSCPORT           7
#define MPLSLDPENTITYMAXPDULENGTH         8
#define MPLSLDPENTITYKEEPALIVEHOLDTIMER   9
#define MPLSLDPENTITYHELLOHOLDTIMER       10
#define MPLSLDPENTITYINITSESSIONTHRESHOLD 11
#define MPLSLDPENTITYLABELDISTMETHOD      12
#define MPLSLDPENTITYLABELRETENTIONMODE   13
#define MPLSLDPENTITYPATHVECTORLIMIT      14
#define MPLSLDPENTITYHOPCOUNTLIMIT        15
#define MPLSLDPENTITYTRANSPORTADDRKIND    16
#define MPLSLDPENTITYTARGETPEER           17
#define MPLSLDPENTITYTARGETPEERADDRTYPE   18
#define MPLSLDPENTITYTARGETPEERADDR       19
#define MPLSLDPENTITYLABELTYPE            20
#define MPLSLDPENTITYDISCONTINUITYTIME    21
#define MPLSLDPENTITYSTORAGETYPE          22
#define MPLSLDPENTITYROWSTATUS            23

/* MPLS LDP mplsLdpEntityStatsTable */
#define MPLSLDPENTITYSTATSSESSIONATTEMPTS        1
#define MPLSLDPENTITYSTATSSESSIONREJHELLO        2
#define MPLSLDPENTITYSTATSSESSIONREJAD           3
#define MPLSLDPENTITYSTATSSESSIONREJMAXPDU       4
#define MPLSLDPENTITYSTATSSESSIONREJLR           5
#define MPLSLDPENTITYSTATSBADLDPID               6
#define MPLSLDPENTITYSTATSBADPDULENGTH           7
#define MPLSLDPENTITYSTATSBADMSGLENGTH           8
#define MPLSLDPENTITYSTATSBADTLVLENGTH           9
#define MPLSLDPENTITYSTATSMALFORMEDTLV           10
#define MPLSLDPENTITYSTATSKEEPALIVEEXP           11
#define MPLSLDPENTITYSTATSSHUTDOWNRCVNOTIFY      12
#define MPLSLDPENTITYSTATSSHUTDOWNSENTNOTIFY     13

#define MPLSLDPSESSIONSTATSUNKNOWNMESTYPEERRORS     1
#define MPLSLDPSESSIONSTATSUNKNOWNTLVERRORS         2

static uint8_t *ldpLsrId(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
        if (smux_header_generic(v, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

	*var_len = 4;
	return (uint8_t *)&leconf->rtr_id.s_addr;
}

static uint8_t *ldpLoopDetectCap(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
        if (smux_header_generic(v, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

        return SNMP_INTEGER(MPLSLDPLSRLOOPDETECTIONCAPABLE_NONE);
}

extern uint32_t ldp_start_time;
static uint8_t *ldpEntityLastChange(struct variable *v, oid name[],
				size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

	*var_len = sizeof(time_t);
	return (uint8_t *) &(leconf->config_change_time);

}

static uint8_t *ldpEntityIndexNext(struct variable *v, oid name[],
				   size_t *length,int exact, size_t *var_len,
				   WriteMethod **write_method)
{
        if (smux_header_generic(v, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

	return SNMP_INTEGER(0);
}

#define LDP_ENTITY_TOTAL_LEN 21
#define LDP_ENTITY_MAX_IDX_LEN 6

static struct ldpd_af_conf *ldpEntityTable_lookup(struct variable *v, oid *name,
						  size_t *length, int exact,
						  uint32_t *index)
{
	int len;
	struct ldpd_af_conf *af_v4, *af_v6;

	af_v4 = &leconf->ipv4;
	af_v6 = &leconf->ipv6;

	if (exact) {
		if (*length != LDP_ENTITY_TOTAL_LEN)
			return NULL;

		if (leconf->trans_pref == DUAL_STACK_LDPOV6 &&
		    af_v6->flags & F_LDPD_AF_ENABLED) {
			*index = 2;
			return af_v6;
		} else {
			*index = 1;
			return af_v4;
		}
	} else {
		/* only support one router id so can just skip */
		len = *length - v->namelen - LDP_ENTITY_MAX_IDX_LEN;
		if (len <= 0) {
			if (leconf->trans_pref == DUAL_STACK_LDPOV6 &&
			    af_v6->flags & F_LDPD_AF_ENABLED) {
				*index = 2;
				return af_v6;
			} else {
				*index = 1;
				return af_v4;
			}
		}
	}
	return NULL;
}

static uint8_t *ldpEntityTable(struct variable *v, oid name[], size_t *length,
			       int exact, size_t *var_len,
			       WriteMethod **write_method)
{
	struct ldpd_af_conf *af;
	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t index = 0;

	*write_method = NULL;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	af = ldpEntityTable_lookup(v, name, length, exact, &index);
	if (af == NULL)
	    return NULL;

	if (!exact) {
		entityLdpId.s_addr = ldp_rtr_id_get(leconf);

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		*length = LDP_ENTITY_TOTAL_LEN;
		oid_copy_in_addr(name + v->namelen, &entityLdpId);
		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = LDP_DEFAULT_ENTITY_INDEX;
	}

	/* Return the current value of the variable */
	switch (v->magic) {
	case MPLSLDPENTITYLDPID:
		*var_len =  6;
		memcpy (snmp_ldp_rtrid, &entityLdpId, IN_ADDR_SIZE);
		return (uint8_t *)snmp_ldp_rtrid;
	case MPLSLDPENTITYINDEX:
		return SNMP_INTEGER(LDP_DEFAULT_ENTITY_INDEX);
	case MPLSLDPENTITYPROTOCOLVERSION:
		return SNMP_INTEGER(LDP_VERSION);
	case MPLSLDPENTITYADMINSTATUS:
		return SNMP_INTEGER(ADMINSTATUSENABLED);
	case MPLSLDPENTITYOPERSTATUS:
		return SNMP_INTEGER(OPERSTATUSENABLED);
	case MPLSLDPENTITYTCPPORT:
		return SNMP_INTEGER(LDP_PORT);
	case MPLSLDPENTITYUDPDSCPORT:
		return SNMP_INTEGER(LDP_PORT);
	case MPLSLDPENTITYMAXPDULENGTH:
		return SNMP_INTEGER(LDP_MAX_LEN);
	case MPLSLDPENTITYKEEPALIVEHOLDTIMER:
		return SNMP_INTEGER(af->keepalive);
	case MPLSLDPENTITYHELLOHOLDTIMER:
		return SNMP_INTEGER(af->lhello_holdtime);
	case MPLSLDPENTITYINITSESSIONTHRESHOLD:
		return SNMP_INTEGER(0); /* not supported */
	case MPLSLDPENTITYLABELDISTMETHOD:
		return SNMP_INTEGER(DOWNSTREAMUNSOLICITED);
	case MPLSLDPENTITYLABELRETENTIONMODE:
		return SNMP_INTEGER(LIBERALRETENTION);
	case MPLSLDPENTITYPATHVECTORLIMIT:
		return SNMP_INTEGER(0); /* not supported */
	case MPLSLDPENTITYHOPCOUNTLIMIT:
		return SNMP_INTEGER(0);
	case MPLSLDPENTITYTRANSPORTADDRKIND:
		return SNMP_INTEGER(TRANSPORTADDRLOOPBACK);
	case MPLSLDPENTITYTARGETPEER:
		return SNMP_INTEGER(1);
	case MPLSLDPENTITYTARGETPEERADDRTYPE:
		if (index == 1)
			return SNMP_INTEGER(MPLSLDPPEERTRANSPORTADDRTYPE_IPV4);
		else
			return SNMP_INTEGER(MPLSLDPPEERTRANSPORTADDRTYPE_IPV6);
	case MPLSLDPENTITYTARGETPEERADDR:
		if (index == 1) {
			*var_len = sizeof(af->trans_addr.v4);
			return ((uint8_t *)&af->trans_addr.v4);
		}else {
			*var_len = sizeof(af->trans_addr.v6);
			return ((uint8_t *)&af->trans_addr.v6);
		}
	case MPLSLDPENTITYLABELTYPE:
		return SNMP_INTEGER(LABELTYPEGENERIC);
	case MPLSLDPENTITYDISCONTINUITYTIME:
		return SNMP_INTEGER(0);
	case MPLSLDPENTITYSTORAGETYPE:
		return SNMP_INTEGER(STORAGETYPENONVOLATILE);
	case MPLSLDPENTITYROWSTATUS:
		return SNMP_INTEGER(ROWSTATUSACTIVE);
	default:
		return NULL;
	}

	return NULL;
}

static uint8_t *ldpEntityStatsTable(struct variable *v, oid name[],
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	struct in_addr entityLdpId = {.s_addr = 0};
	int len;

	*write_method = NULL;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	if (exact) {
		if (*length != LDP_ENTITY_TOTAL_LEN)
			return NULL;
	} else {
		len = *length - v->namelen - LDP_ENTITY_MAX_IDX_LEN;
		if (len > 0)
			return NULL;

		entityLdpId.s_addr = ldp_rtr_id_get(leconf);

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		*length = LDP_ENTITY_TOTAL_LEN;
		oid_copy_in_addr(name + v->namelen, &entityLdpId);
		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = LDP_DEFAULT_ENTITY_INDEX;
	}

	/* Return the current value of the variable */
	switch (v->magic) {
	case MPLSLDPENTITYSTATSSESSIONATTEMPTS:
		return SNMP_INTEGER(leconf->stats.session_attempts);
	case MPLSLDPENTITYSTATSSESSIONREJHELLO:
		return SNMP_INTEGER(leconf->stats.session_rejects_hello);
	case MPLSLDPENTITYSTATSSESSIONREJAD:
		return SNMP_INTEGER(leconf->stats.session_rejects_ad);
	case MPLSLDPENTITYSTATSSESSIONREJMAXPDU:
		return SNMP_INTEGER(leconf->stats.session_rejects_max_pdu);
	case MPLSLDPENTITYSTATSSESSIONREJLR:
		return SNMP_INTEGER(leconf->stats.session_rejects_lr);
	case MPLSLDPENTITYSTATSBADLDPID:
		return SNMP_INTEGER(leconf->stats.bad_ldp_id);
	case MPLSLDPENTITYSTATSBADPDULENGTH:
		return SNMP_INTEGER(leconf->stats.bad_pdu_len);
	case MPLSLDPENTITYSTATSBADMSGLENGTH:
		return SNMP_INTEGER(leconf->stats.bad_msg_len);
	case MPLSLDPENTITYSTATSBADTLVLENGTH:
		return SNMP_INTEGER(leconf->stats.bad_tlv_len);
	case MPLSLDPENTITYSTATSMALFORMEDTLV:
		return SNMP_INTEGER(leconf->stats.malformed_tlv);
	case MPLSLDPENTITYSTATSKEEPALIVEEXP:
		return SNMP_INTEGER(leconf->stats.keepalive_timer_exp);
	case MPLSLDPENTITYSTATSSHUTDOWNRCVNOTIFY:
		return SNMP_INTEGER(leconf->stats.shutdown_rcv_notify);
	case MPLSLDPENTITYSTATSSHUTDOWNSENTNOTIFY:
		return SNMP_INTEGER(leconf->stats.shutdown_send_notify);
	default:
		return NULL;
	}

	return NULL;
}

#define LDP_ADJACENCY_ENTRY_MAX_IDX_LEN	14

static void ldpHelloAdjacencyTable_oid_to_index(
	struct variable *v, oid name[],
	size_t *length,
	struct in_addr *entityLdpId,
	uint32_t *entityIndex,
	struct in_addr *peerLdpId,
	uint32_t *adjacencyIndex)
{
	oid *offset = name + v->namelen;
	int offsetlen = *length - v->namelen;
	int len = offsetlen;

	if (len > LDP_ADJACENCY_ENTRY_MAX_IDX_LEN)
		len = LDP_ADJACENCY_ENTRY_MAX_IDX_LEN;

	if (len >= LDP_LSRID_IDX_LEN)
                oid2in_addr(offset, sizeof(struct in_addr), entityLdpId);

	offset += LDP_LSRID_IDX_LEN;
	offsetlen -= LDP_LSRID_IDX_LEN;
	len = offsetlen;

	if (len > LDP_ENTITY_IDX_LEN)
		len = LDP_ENTITY_IDX_LEN;

	if (len >= LDP_ENTITY_IDX_LEN)
		*entityIndex = offset[0];

	offset += LDP_ENTITY_IDX_LEN;
	offsetlen -= LDP_ENTITY_IDX_LEN;
	len = offsetlen;

	if (len > LDP_LSRID_IDX_LEN)
		len = LDP_LSRID_IDX_LEN;

	if (len >= LDP_LSRID_IDX_LEN)
                oid2in_addr(offset, sizeof(struct in_addr), peerLdpId);

	offset += LDP_LSRID_IDX_LEN;
	offsetlen -= LDP_LSRID_IDX_LEN;
	len = offsetlen;

	if (len > LDP_ADJACENCY_IDX_LEN)
		len = LDP_ADJACENCY_IDX_LEN;

	if (len >= LDP_ADJACENCY_IDX_LEN)
		*adjacencyIndex = offset[0];
}

static struct adj *
nbr_get_adj_by_index(struct nbr *nbr, uint32_t adjacencyIndex)
{
	struct adj      *adj;
	uint32_t	i = 0;

	RB_FOREACH(adj, nbr_adj_head, &nbr->adj_tree)
		if (++i == adjacencyIndex)
			return adj;

	return NULL;
}

static struct ctl_adj *
ldpHelloAdjacencyTable_lookup_helper(
	struct in_addr *entityLdpId,
	uint32_t *entityIndex,
	struct in_addr *peerLdpId,
	uint32_t *adjacencyIndex)
{
	struct ctl_adj *ctl_adj = NULL;
        struct adj *adj = NULL;
	struct nbr *cur_nbr = nbr_find_ldpid(peerLdpId->s_addr);

	if (cur_nbr)
		/* If found nbr, then look to see if the
		 * adjacency exists
		 */
		adj = nbr_get_adj_by_index(cur_nbr, *adjacencyIndex);

	if (adj)
		ctl_adj = adj_to_ctl(adj);

	return ctl_adj;
}

static struct ctl_adj *
ldpHelloAdjacencyTable_next_helper(
	int first,
	struct in_addr *entityLdpId,
	uint32_t *entityIndex,
	struct in_addr *peerLdpId,
	uint32_t *adjacencyIndex)
{
	struct ctl_adj *ctl_adj = NULL;
	struct nbr *nbr = NULL;
        struct adj *adj = NULL;

	if (first)
		nbr = nbr_get_first_ldpid();
	else {
		struct nbr *cur_nbr = nbr_find_ldpid(peerLdpId->s_addr);
		if (cur_nbr)
			/* If found nbr, then look to see if the
			 * adjacency exists
			 */
			adj = nbr_get_adj_by_index(cur_nbr, *adjacencyIndex + 1);
		if (adj)
			*adjacencyIndex += 1;
		else
			nbr = nbr_get_next_ldpid(peerLdpId->s_addr);
	}

	if (!adj && nbr) {
		adj = RB_MIN(nbr_adj_head, &nbr->adj_tree);
		*adjacencyIndex = 1;
	}

	if (adj)
		ctl_adj = adj_to_ctl(adj);

	return ctl_adj;
}

#define HELLO_ADJ_MAX_IDX_LEN           14

static struct ctl_adj *
ldpHelloAdjacencyTable_lookup(struct variable *v, oid name[],
	size_t *length, int exact,
	struct in_addr *entityLdpId,
	uint32_t *entityIndex,
	struct in_addr *peerLdpId,
	uint32_t *adjacencyIndex)
{
	struct ctl_adj *hello_adj = NULL;

	if (exact) {
		if (*length < HELLO_ADJ_MAX_IDX_LEN)
			return NULL;

		ldpHelloAdjacencyTable_oid_to_index(
			v, name, length,
			entityLdpId, entityIndex, peerLdpId, adjacencyIndex);

                hello_adj = ldpHelloAdjacencyTable_lookup_helper(
			entityLdpId, entityIndex, peerLdpId, adjacencyIndex);
	} else {
		int first = 0;
		int offsetlen = *length - v->namelen;

		if (offsetlen < HELLO_ADJ_MAX_IDX_LEN)
			first = 1;

		ldpHelloAdjacencyTable_oid_to_index(
			v, name, length,
			entityLdpId, entityIndex, peerLdpId, adjacencyIndex);

                hello_adj = ldpHelloAdjacencyTable_next_helper(first,
			entityLdpId, entityIndex, peerLdpId, adjacencyIndex);

	}
	return hello_adj;
}

static uint8_t *ldpHelloAdjacencyTable(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t entityIndex = 0;
	struct in_addr peerLdpId = {.s_addr = 0};
	uint32_t adjacencyIndex = 0;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	struct ctl_adj *ctl_adj = ldpHelloAdjacencyTable_lookup(v, name,
		length, exact,
		&entityLdpId, &entityIndex, &peerLdpId, &adjacencyIndex);

	if (!ctl_adj)
		return NULL;

	if (!exact) {

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		struct in_addr entityLdpId = {.s_addr = 0};
		entityLdpId.s_addr = ldp_rtr_id_get(leconf);

		struct in_addr peerLdpId = ctl_adj->id;

		oid_copy_in_addr(name + v->namelen, &entityLdpId);
		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = LDP_DEFAULT_ENTITY_INDEX;
		oid_copy_in_addr(name + v->namelen + 7, &peerLdpId);
		name[v->namelen + 11] = 0;
		name[v->namelen + 12] = 0;
		name[v->namelen + 13] = adjacencyIndex;

		/* Set length */
		*length = v->namelen + HELLO_ADJ_MAX_IDX_LEN;
	}

	switch (v->magic) {
	case MPLSLDPHELLOADJACENCYINDEX:
		return SNMP_INTEGER(adjacencyIndex);
	case MPLSLDPHELLOADJACENCYHOLDTIMEREM:
		return SNMP_INTEGER(ctl_adj->holdtime_remaining);
	case MPLSLDPHELLOADJACENCYHOLDTIME:
		return SNMP_INTEGER(ctl_adj->holdtime);
	case MPLSLDPHELLOADJACENCYTYPE:
		if (ctl_adj->type == HELLO_LINK)
			return SNMP_INTEGER(MPLSLDPHELLOADJACENCYTYPE_LINK);
		return SNMP_INTEGER(MPLSLDPHELLOADJACENCYTYPE_TARGETED);
	default:
		return NULL;
	}

	return NULL;
}

#define LDP_LSRID_IDX_LEN 		6
#define LDP_ENTITY_IDX_LEN		1
#define LDP_PEER_ENTRY_MAX_IDX_LEN	13

static void ldpPeerTable_oid_to_index(
	struct variable *v, oid name[],
	size_t *length,
	struct in_addr *entityLdpId,
	uint32_t *entityIndex,
	struct in_addr *peerLdpId)
{
	oid *offset = name + v->namelen;
	int offsetlen = *length - v->namelen;
	int len = offsetlen;

	if (len > LDP_PEER_ENTRY_MAX_IDX_LEN)
		len = LDP_PEER_ENTRY_MAX_IDX_LEN;

	if (len >= LDP_LSRID_IDX_LEN)
                oid2in_addr(offset, sizeof(struct in_addr), entityLdpId);

	offset += LDP_LSRID_IDX_LEN;
	offsetlen -= LDP_LSRID_IDX_LEN;
	len = offsetlen;

	if (len > LDP_ENTITY_IDX_LEN)
		len = LDP_ENTITY_IDX_LEN;

	if (len >= LDP_ENTITY_IDX_LEN)
		*entityIndex = offset[0];

	offset += LDP_ENTITY_IDX_LEN;
	offsetlen -= LDP_ENTITY_IDX_LEN;
	len = offsetlen;

	if (len > LDP_LSRID_IDX_LEN)
		len = LDP_LSRID_IDX_LEN;

	if (len >= LDP_LSRID_IDX_LEN)
                oid2in_addr(offset, sizeof(struct in_addr), peerLdpId);
}

static struct ctl_nbr *
ldpPeerTable_lookup_next(int first,
	struct in_addr peerLdpId)
{
	struct nbr *nbr = NULL;
        struct ctl_nbr *ctl_nbr = NULL;;

	if (first)
		nbr = nbr_get_first_ldpid();
	else
		nbr = nbr_get_next_ldpid(peerLdpId.s_addr);

	if (nbr)
		ctl_nbr = nbr_to_ctl(nbr);

	return ctl_nbr;
}

static struct ctl_nbr *
ldpPeerTable_lookup(struct variable *v, oid name[],
			size_t *length, int exact,
			struct in_addr *entityLdpId,
			uint32_t *entityIndex,
			struct in_addr *peerLdpId)
{
	struct ctl_nbr *ctl_nbr = NULL;
	struct nbr *nbr = NULL;
	int first = 0;

	if (exact) {
		if (*length < (long unsigned int)v->namelen
		    + LDP_PEER_ENTRY_MAX_IDX_LEN)
			return NULL;

		ldpPeerTable_oid_to_index(
			v, name, length,
			entityLdpId, entityIndex, peerLdpId);

                nbr = nbr_find_ldpid(peerLdpId->s_addr);
		if (nbr)
			ctl_nbr = nbr_to_ctl(nbr);

		return ctl_nbr;
	} else {

		int offsetlen = *length - v->namelen;
		if (offsetlen < LDP_LSRID_IDX_LEN)
			first = 1;

		ldpPeerTable_oid_to_index(
			v, name, length,
			entityLdpId, entityIndex, peerLdpId);

                ctl_nbr = ldpPeerTable_lookup_next(first, *peerLdpId);
		return ctl_nbr;
	}
	return NULL;
}

static uint8_t *ldpPeerTable(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t entityIndex = 0;
	struct in_addr peerLdpId = {.s_addr = 0};
	struct ctl_nbr *ctl_nbr;


	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	ctl_nbr = ldpPeerTable_lookup(v, name, length, exact, &entityLdpId,
				      &entityIndex, &peerLdpId);

	if (!ctl_nbr)
		return NULL;

	if (!exact) {

		entityLdpId.s_addr = ldp_rtr_id_get(leconf);
		entityIndex = LDP_DEFAULT_ENTITY_INDEX;
		peerLdpId = ctl_nbr->id;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		oid_copy_in_addr(name + v->namelen, &entityLdpId);

		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = entityIndex;
		oid_copy_in_addr(name + v->namelen + 7, &peerLdpId);
		name[v->namelen + 11] = 0;
		name[v->namelen + 12] = 0;

		/* Set length */
		*length = v->namelen + LDP_PEER_ENTRY_MAX_IDX_LEN;
	}

	switch (v->magic) {
	case MPLSLDPPEERLDPID:
		*var_len = 6;
		memcpy(snmp_ldp_rtrid, &ctl_nbr->id, IN_ADDR_SIZE);
		return snmp_ldp_rtrid;
	case MPLSLDPPEERLABELDISTMETHOD:
		return SNMP_INTEGER(DOWNSTREAMUNSOLICITED);
	case MPLSLDPPEERPATHVECTORLIMIT:
		return SNMP_INTEGER(0);
	case MPLSLDPPEERTRANSPORTADDRTYPE:
		if (ctl_nbr->af == AF_INET)
			return SNMP_INTEGER(MPLSLDPPEERTRANSPORTADDRTYPE_IPV4);
		else
			return SNMP_INTEGER(MPLSLDPPEERTRANSPORTADDRTYPE_IPV6);
	case MPLSLDPPEERTRANSPORTADDR:
		if (ctl_nbr->af == AF_INET) {
			*var_len = sizeof(ctl_nbr->raddr.v4);
			return ((uint8_t *)&ctl_nbr->raddr.v4);
		} else {
			*var_len = sizeof(ctl_nbr->raddr.v6);
			return ((uint8_t *)&ctl_nbr->raddr.v6);
		}
	default:
		return NULL;
	}

	return NULL;
}
static uint8_t *ldpSessionTable(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t entityIndex = 0;
	struct in_addr peerLdpId = {.s_addr = 0};
	struct ctl_nbr *ctl_nbr;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	ctl_nbr = ldpPeerTable_lookup(v, name, length, exact, &entityLdpId,
				      &entityIndex, &peerLdpId);

	if (!ctl_nbr)
		return NULL;

	if (!exact) {
		entityLdpId.s_addr = ldp_rtr_id_get(leconf);
		entityIndex = LDP_DEFAULT_ENTITY_INDEX;
		peerLdpId = ctl_nbr->id;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		oid_copy_in_addr(name + v->namelen, &entityLdpId);

		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = entityIndex;
		oid_copy_in_addr(name + v->namelen + 7, &peerLdpId);
		name[v->namelen + 11] = 0;
		name[v->namelen + 12] = 0;

		/* Set length */
                *length = v->namelen + LDP_PEER_ENTRY_MAX_IDX_LEN;
	}

	switch (v->magic) {
	case MPLSLDPSESSIONSTATELASTCHANGE:
		*var_len = sizeof(time_t);
		return (uint8_t *) &(ctl_nbr->uptime);
	case MPLSLDPSESSIONSTATE:
		switch (ctl_nbr->nbr_state) {
		case NBR_STA_INITIAL:
			return SNMP_INTEGER(MPLSLDPSESSIONSTATE_INITIALIZED);
		case NBR_STA_OPENREC:
			return SNMP_INTEGER(MPLSLDPSESSIONSTATE_OPENREC);
		case NBR_STA_OPENSENT:
			return SNMP_INTEGER(MPLSLDPSESSIONSTATE_OPENSENT);
		case NBR_STA_OPER:
			return SNMP_INTEGER(MPLSLDPSESSIONSTATE_OPERATIONAL);
		default:
			return SNMP_INTEGER(MPLSLDPSESSIONSTATE_NONEXISTENT);
		}
	case MPLSLDPSESSIONROLE:
		if (ldp_addrcmp(ctl_nbr->af, &ctl_nbr->laddr, &ctl_nbr->raddr)
		    > 0)
			return SNMP_INTEGER(MPLSLDPSESSIONROLE_ACTIVE);
		else
			return SNMP_INTEGER(MPLSLDPSESSIONROLE_PASSIVE);
	case MPLSLDPSESSIONPROTOCOLVERSION:
		return SNMP_INTEGER(LDP_VERSION);
	case MPLSLDPSESSIONKEEPALIVEHOLDTIMEREM:
		return SNMP_INTEGER(ctl_nbr->hold_time_remaining);
	case MPLSLDPSESSIONKEEPALIVETIME:
		return SNMP_INTEGER(ctl_nbr->holdtime);
	case MPLSLDPSESSIONMAXPDULENGTH:
		if (ctl_nbr->nbr_state == NBR_STA_OPER)
			return SNMP_INTEGER(ctl_nbr->max_pdu_len);
		else
			return SNMP_INTEGER(LDP_MAX_LEN);
	case MPLSLDPSESSIONDISCONTINUITYTIME:
		return SNMP_INTEGER(0); /* not supported */
	default:
		return NULL;
	}

	return NULL;
}

static uint8_t *ldpSessionStatsTable(struct variable *v, oid name[],
				size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t entityIndex = 0;
	struct in_addr peerLdpId = {.s_addr = 0};

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	struct ctl_nbr *ctl_nbr = ldpPeerTable_lookup(v, name, length, exact,
		&entityLdpId, &entityIndex, &peerLdpId);

	if (!ctl_nbr)
		return NULL;

	if (!exact) {
		entityLdpId.s_addr = ldp_rtr_id_get(leconf);
		entityIndex = LDP_DEFAULT_ENTITY_INDEX;
		peerLdpId = ctl_nbr->id;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		oid_copy_in_addr(name + v->namelen, &entityLdpId);
		name[v->namelen + 4] = 0;
		name[v->namelen + 5] = 0;
		name[v->namelen + 6] = entityIndex;
		oid_copy_in_addr(name + v->namelen + 7, &peerLdpId);
		name[v->namelen + 11] = 0;
		name[v->namelen + 12] = 0;

                *length = v->namelen + LDP_PEER_ENTRY_MAX_IDX_LEN;
	}

	switch (v->magic) {
	case MPLSLDPSESSIONSTATSUNKNOWNMESTYPEERRORS:
		return SNMP_INTEGER(ctl_nbr->stats.unknown_msg);
	case MPLSLDPSESSIONSTATSUNKNOWNTLVERRORS:
		return SNMP_INTEGER(ctl_nbr->stats.unknown_tlv);
	default:
		return NULL;
	}

	return NULL;
}

static struct variable ldpe_variables[] = {
	{MPLS_LDP_LSR_ID, STRING, RONLY, ldpLsrId, 3, {1, 1, 1}},
	{MPLS_LDP_LSR_LOOP_DETECTION_CAPABLE, INTEGER, RONLY,
	 ldpLoopDetectCap, 3, {1, 1, 2}},
	{MPLS_LDP_ENTITY_LAST_CHANGE, TIMESTAMP, RONLY, ldpEntityLastChange,
	 3, {1, 2, 1}},
	{MPLS_LDP_ENTITY_INDEX_NEXT, UNSIGNED32, RONLY, ldpEntityIndexNext,
	 3, {1, 2, 2}},

	/* MPLS LDP mplsLdpEntityTable. */
	{MPLSLDPENTITYLDPID, STRING, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 1}},
	{MPLSLDPENTITYINDEX, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 2}},
	{MPLSLDPENTITYPROTOCOLVERSION, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 3}},
	{MPLSLDPENTITYADMINSTATUS, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 4}},
	{MPLSLDPENTITYOPERSTATUS, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 5}},
	{MPLSLDPENTITYTCPPORT, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 6}},
	{MPLSLDPENTITYUDPDSCPORT, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 7}},
	{MPLSLDPENTITYMAXPDULENGTH, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 8}},
	{MPLSLDPENTITYKEEPALIVEHOLDTIMER, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 9}},
	{MPLSLDPENTITYHELLOHOLDTIMER, UNSIGNED32, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 10}},
	{MPLSLDPENTITYINITSESSIONTHRESHOLD, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 11}},
	{MPLSLDPENTITYLABELDISTMETHOD, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 12}},
	{MPLSLDPENTITYLABELRETENTIONMODE, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 13}},
	{MPLSLDPENTITYPATHVECTORLIMIT, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 14}},
	{MPLSLDPENTITYHOPCOUNTLIMIT, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 15}},
	{MPLSLDPENTITYTRANSPORTADDRKIND, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 16}},
	{MPLSLDPENTITYTARGETPEER, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 17}},
	{MPLSLDPENTITYTARGETPEERADDRTYPE, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 18}},
	{MPLSLDPENTITYTARGETPEERADDR, STRING, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 19}},
	{MPLSLDPENTITYLABELTYPE, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 20}},
	{MPLSLDPENTITYDISCONTINUITYTIME, TIMESTAMP, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 21}},
	{MPLSLDPENTITYSTORAGETYPE, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 22}},
	{MPLSLDPENTITYROWSTATUS, INTEGER, RONLY, ldpEntityTable,
	 5, {1, 2, 3, 1, 23}},

	/* MPLS LDP mplsLdpEntityStatsTable. */
	{ MPLSLDPENTITYSTATSSESSIONATTEMPTS, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 1}},
	{ MPLSLDPENTITYSTATSSESSIONREJHELLO, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 2}},
	{ MPLSLDPENTITYSTATSSESSIONREJAD, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 3}},
	{ MPLSLDPENTITYSTATSSESSIONREJMAXPDU, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 4}},
	{ MPLSLDPENTITYSTATSSESSIONREJLR, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 5}},
	{ MPLSLDPENTITYSTATSBADLDPID, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 6}},
	{ MPLSLDPENTITYSTATSBADPDULENGTH, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 7}},
	{ MPLSLDPENTITYSTATSBADMSGLENGTH, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 8}},
	{ MPLSLDPENTITYSTATSBADTLVLENGTH, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 9}},
	{ MPLSLDPENTITYSTATSMALFORMEDTLV, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 10}},
	{ MPLSLDPENTITYSTATSKEEPALIVEEXP, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 11}},
	{ MPLSLDPENTITYSTATSSHUTDOWNRCVNOTIFY, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 12}},
	{ MPLSLDPENTITYSTATSSHUTDOWNSENTNOTIFY, COUNTER32, RONLY,
	  ldpEntityStatsTable, 5, {1, 2, 4, 1, 13}},

	/* MPLS LDP mplsLdpPeerTable */
	{MPLSLDPPEERLDPID, STRING, RONLY, ldpPeerTable, 5, {1, 3, 2, 1, 1}},
	{MPLSLDPPEERLABELDISTMETHOD, INTEGER, RONLY, ldpPeerTable,
	 5, {1, 3, 2, 1, 2}},
	{MPLSLDPPEERPATHVECTORLIMIT, INTEGER, RONLY, ldpPeerTable,
	 5, {1, 3, 2, 1, 3}},
	{MPLSLDPPEERTRANSPORTADDRTYPE, INTEGER, RONLY, ldpPeerTable,
	 5, {1, 3, 2, 1, 4}},
	{MPLSLDPPEERTRANSPORTADDR, STRING, RONLY, ldpPeerTable,
	 5, {1, 3, 2, 1, 5}},

	/* MPLS LDP mplsLdpSessionTable */
	{MPLSLDPSESSIONSTATELASTCHANGE, TIMESTAMP, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 1}},
	{MPLSLDPSESSIONSTATE, INTEGER, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 2}},
	{MPLSLDPSESSIONROLE, INTEGER, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 3}},
	{MPLSLDPSESSIONPROTOCOLVERSION, UNSIGNED32, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 4}},
	{MPLSLDPSESSIONKEEPALIVEHOLDTIMEREM, INTEGER, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 5}},
	{MPLSLDPSESSIONKEEPALIVETIME, UNSIGNED32, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 6}},
	{MPLSLDPSESSIONMAXPDULENGTH, UNSIGNED32, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 7}},
	{MPLSLDPSESSIONDISCONTINUITYTIME, TIMESTAMP, RONLY, ldpSessionTable,
	 5, {1, 3, 3, 1, 8}},

	/* MPLS LDP mplsLdpSessionStatsTable */
	{MPLSLDPSESSIONSTATSUNKNOWNMESTYPEERRORS, COUNTER32, RONLY,
	 ldpSessionStatsTable, 5, {1, 3, 4, 1, 1}},
	{MPLSLDPSESSIONSTATSUNKNOWNTLVERRORS, COUNTER32, RONLY,
	 ldpSessionStatsTable, 5, {1, 3, 4, 1, 2}},

	/* MPLS LDP mplsLdpHelloAdjacencyTable. */
	{MPLSLDPHELLOADJACENCYINDEX, UNSIGNED32, RONLY,
	 ldpHelloAdjacencyTable, 6, {1, 3, 5, 1, 1, 1}},
	{MPLSLDPHELLOADJACENCYHOLDTIMEREM, INTEGER, RONLY,
	 ldpHelloAdjacencyTable, 6, {1, 3, 5, 1, 1, 2}},
	{MPLSLDPHELLOADJACENCYHOLDTIME, UNSIGNED32, RONLY,
	 ldpHelloAdjacencyTable, 6, {1, 3, 5, 1, 1, 3}},
	{MPLSLDPHELLOADJACENCYTYPE, INTEGER, RONLY,
	 ldpHelloAdjacencyTable, 6, {1, 3, 5, 1, 1, 4}},
};

static struct variable lde_variables[] = {
};

static struct trap_object ldpSessionTrapList[] = {
        {5, {1, 3, 3, 1, MPLSLDPSESSIONSTATE}},
        {5, {1, 3, 3, 1, MPLSLDPSESSIONDISCONTINUITYTIME}},
        {5, {1, 3, 4, 1, MPLSLDPSESSIONSTATSUNKNOWNMESTYPEERRORS}},
        {5, {1, 3, 4, 1, MPLSLDPSESSIONSTATSUNKNOWNTLVERRORS}}};

/* LDP TRAP. */
#define LDPINITSESSIONTHRESHOLDEXCEEDED	1
#define LDPPATHVECTORLIMITMISMATCH	2
#define LDPSESSIONUP			3
#define LDPSESSIONDOWN			4

static void
ldpTrapSession(struct nbr * nbr, unsigned int sptrap)
{
        oid index[sizeof(oid) * (LDP_PEER_ENTRY_MAX_IDX_LEN + 1)];

	struct in_addr entityLdpId = {.s_addr = 0};
	uint32_t entityIndex = 0;
	struct in_addr peerLdpId = {.s_addr = 0};

	struct ctl_nbr *ctl_nbr = nbr_to_ctl(nbr);

	entityLdpId.s_addr = ldp_rtr_id_get(leconf);
	entityIndex = LDP_DEFAULT_ENTITY_INDEX;
	peerLdpId = ctl_nbr->id;

	oid_copy_in_addr(index, &entityLdpId);
	index[4] = 0;
	index[5] = 0;
	index[6] = entityIndex;
	oid_copy_in_addr(&index[7], &peerLdpId);
	index[11] = 0;
	index[12] = 0;

	index[LDP_PEER_ENTRY_MAX_IDX_LEN] = 0;

        smux_trap(ldpe_variables, array_size(ldpe_variables), ldp_trap_oid,
                  array_size(ldp_trap_oid), ldp_oid,
                  sizeof(ldp_oid) / sizeof(oid), index,
		  LDP_PEER_ENTRY_MAX_IDX_LEN + 1,
                  ldpSessionTrapList, array_size(ldpSessionTrapList), sptrap);
}

static void
ldpTrapSessionUp(struct nbr * nbr)
{
	ldpTrapSession(nbr, LDPSESSIONUP);
}

static void
ldpTrapSessionDown(struct nbr * nbr)
{
	ldpTrapSession(nbr, LDPSESSIONDOWN);
}

static int ldp_snmp_agentx_enabled(void)
{
	main_imsg_compose_both(IMSG_AGENTX_ENABLED, NULL, 0);

	return 0;
}

static int ldp_snmp_nbr_state_change(struct nbr * nbr, int old_state)
{
	if (old_state == nbr->state)
		return 0;

	if (nbr->state == NBR_STA_OPER)
		ldpTrapSessionUp(nbr);
	else if (old_state == NBR_STA_OPER)
		ldpTrapSessionDown(nbr);

	return 0;
}

static int ldp_snmp_init(struct thread_master *tm)
{
	hook_register(agentx_enabled, ldp_snmp_agentx_enabled);

	smux_init(tm);

	return 0;
}

static int ldp_snmp_register_mib(struct thread_master *tm)
{
	static int registered = 0;

	if (registered)
		return 0;

	registered = 1;

	smux_init(tm);

	smux_agentx_enable();

	if (ldpd_process == PROC_LDE_ENGINE)
		REGISTER_MIB("mibII/ldp", lde_variables, variable, ldp_oid);
	else if (ldpd_process == PROC_LDP_ENGINE) {
		REGISTER_MIB("mibII/ldp", ldpe_variables, variable, ldp_oid);

		hook_register(ldp_nbr_state_change, ldp_snmp_nbr_state_change);
	}

	return 0;
}

static int ldp_snmp_module_init(void)
{
	if (ldpd_process == PROC_MAIN)
		hook_register(frr_late_init, ldp_snmp_init);
	else
		hook_register(ldp_register_mib, ldp_snmp_register_mib);

	return 0;
}

FRR_MODULE_SETUP(
	.name = "ldp_snmp",
	.version = FRR_VERSION,
	.description = "ldp AgentX SNMP module",
	.init = ldp_snmp_module_init,
);
