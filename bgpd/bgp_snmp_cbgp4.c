// SPDX-License-Identifier: GPL-2.0-or-later
/* CISCO-BGP4-MIB SNMP support
 * Copyright (C) 2025 Sudharsan Rajagopalan
 */

#include <zebra.h>

#include <string.h>

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
#include "lib/version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_snmp.h"
#include "bgpd/bgp_snmp_cbgp4.h"
#include "bgpd/bgp_open.h"

SNMP_LOCAL_VARIABLES

static oid cbgp4_oid[] = { CBGP4MIB };
static oid cbgp4_trap_oid[] = {CBGP4MIB, CBGP_NOTIFY_PREFIX};
static struct in_addr bgp_empty_addr = {};

static struct trap_object cbgpPeer2TrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_LAST_ERROR}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_STATE}},
};

static struct trap_object cbgpPeer2FsmTrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_LAST_ERROR}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_STATE}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_LAST_ERROR_TXT}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE,
	     CBGP_PEER2_ENTRY, CBGP_PEER2_PREV_STATE}},
};

static int cbgp4_build_peer2_index(struct peer *peer, oid *index)
{
	switch (sockunion_family(&peer->connection->su)) {
	case AF_INET:
		index[0] = INETADDRESSTYPEIPV4;
		oid_copy_in_addr(&index[1], &peer->connection->su.sin.sin_addr);
		return IN_ADDR_SIZE + 1;
	case AF_INET6:
		index[0] = INETADDRESSTYPEIPV6;
		oid_copy_in6_addr(&index[1], &peer->connection->su.sin6.sin6_addr);
		return IN6_ADDR_SIZE + 1;
	default:
		return 0;
	}
}

static struct peer *cbgp4_peer_next_global(struct peer *peer)
{
	if (!peer)
		return NULL;

	struct ipaddr addr = {};
	sa_family_t family = sockunion_family(&peer->connection->su);

	switch (family) {
	case AF_INET:
		addr.ipa_type = AF_INET;
		addr.ip._v4_addr = peer->connection->su.sin.sin_addr;
		break;
	case AF_INET6:
		addr.ipa_type = AF_INET6;
		addr.ip._v6_addr = peer->connection->su.sin6.sin6_addr;
		break;
	default:
		return NULL;
	}

	return bgp_snmp_get_next_peer(true, peer->bgp->vrf_id, AF_UNSPEC, &addr);
}

static size_t cbgp4_fill_peer3_index(const struct peer *peer, oid *out)
{
	if (!peer || !out)
		return 0;

	out[0] = peer->bgp->vrf_id;
	switch (sockunion_family(&peer->connection->su)) {
	case AF_INET:
		out[1] = INETADDRESSTYPEIPV4;
		oid_copy_in_addr(&out[2], &peer->connection->su.sin.sin_addr);
		return IN_ADDR_SIZE + 2;
	case AF_INET6:
		out[1] = INETADDRESSTYPEIPV6;
		oid_copy_in6_addr(&out[2], &peer->connection->su.sin6.sin6_addr);
		return IN6_ADDR_SIZE + 2;
	default:
		return 0;
	}
}

static int cbgp4_compare_index(const oid *lhs, size_t lhs_len, const oid *rhs, size_t rhs_len)
{
	size_t min = lhs_len < rhs_len ? lhs_len : rhs_len;

	for (size_t i = 0; i < min; i++) {
		if (lhs[i] < rhs[i])
			return -1;
		if (lhs[i] > rhs[i])
			return 1;
	}

	if (lhs_len == rhs_len)
		return 0;

	return (lhs_len < rhs_len) ? -1 : 1;
}

static struct peer *cbgp4PeerTable_lookup(struct variable *v, oid name[], size_t *length, int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct ipaddr addr = {};

	if (!offsetlen) {
		bgp_snmp_index_init(index, CBGP_PEER_TABLE_MAX_INDEX_LEN);
	} else if (offsetlen == IN_ADDR_SIZE) {
		addr.ipa_type = AF_INET;
		oid2in_addr(index, IN_ADDR_SIZE, &addr.ip._v4_addr);
	} else {
		/* We cannot support partial indexes */
		return NULL;
	}

	if (exact)
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);
	else if (!offsetlen)
		peer = bgp_snmp_get_first_peer(false, AF_UNSPEC);
	else
		peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT, AF_INET, &addr);

	if (!peer || !peer->connection)
		return NULL;

	if (!exact) {
		oid_copy_in_addr(index, &peer->connection->su.sin.sin_addr);
		*length = namelen + IN_ADDR_SIZE;
	}

	return peer;
}

static struct peer *cbgp4Peer2Table_lookup(struct variable *v, oid name[], size_t *length,
					   int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct ipaddr addr = {};
	bool addr_present = false;
	sa_family_t family = AF_UNSPEC;

	if (!offsetlen) {
		bgp_snmp_index_init(index, CBGP_PEER2_TABLE_MAX_INDEX_LEN);
	} else if (offsetlen == 1) {
		if (index[0] == INETADDRESSTYPEIPV4)
			family = AF_INET;
		else if (index[0] == INETADDRESSTYPEIPV6)
			family = AF_INET6;
		else
			return NULL;
	} else {
		if (offsetlen == IN_ADDR_SIZE + 1 && index[0] == INETADDRESSTYPEIPV4) {
			family = AF_INET;
			addr.ipa_type = AF_INET;
			oid2in_addr(&index[1], IN_ADDR_SIZE, &addr.ip._v4_addr);
			addr_present = true;
		} else if (offsetlen == IN6_ADDR_SIZE + 1 && index[0] == INETADDRESSTYPEIPV6) {
			family = AF_INET6;
			addr.ipa_type = AF_INET6;
			oid2in6_addr(&index[1], &addr.ip._v6_addr);
			addr_present = true;
		} else {
			/* Unsupported partial index */
			return NULL;
		}
	}

	if (exact) {
		if (!addr_present)
			return NULL;
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);
		if (peer &&
		    (!peer->connection || sockunion_family(&peer->connection->su) != family))
			peer = NULL;
	} else {
		if (!offsetlen)
			peer = bgp_snmp_get_first_peer(false, AF_UNSPEC);
		else if (!addr_present)
			peer = bgp_snmp_get_first_peer(false, family);
		else {
			sa_family_t primary_family = family;

			peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT, primary_family, &addr);
			if (!peer && primary_family != AF_UNSPEC)
				peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT, AF_UNSPEC, &addr);
		}

		if (peer == NULL || !peer->connection)
			return NULL;

		switch (sockunion_family(&peer->connection->su)) {
		case AF_INET:
			index[0] = INETADDRESSTYPEIPV4;
			oid_copy_in_addr(&index[1], &peer->connection->su.sin.sin_addr);
			*length = namelen + IN_ADDR_SIZE + 1;
			break;
		case AF_INET6:
			index[0] = INETADDRESSTYPEIPV6;
			oid_copy_in6_addr(&index[1], &peer->connection->su.sin6.sin6_addr);
			*length = namelen + IN6_ADDR_SIZE + 1;
			break;
		default:
			break;
		}
	}

	return peer;
}

static struct peer *cbgp4Peer3Table_lookup(struct variable *v, oid name[], size_t *length,
					   int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	vrf_id_t vrf_id = VRF_UNKNOWN;
	struct ipaddr addr = {};
	bool addr_present = false;
	sa_family_t family = AF_UNSPEC;

	if (!offsetlen) {
		bgp_snmp_index_init(index, CBGP_PEER3_TABLE_MAX_INDEX_LEN);
	} else {
		vrf_id = index[0];

		if (offsetlen == 1) {
			/* Only VRF provided */
			; /* nothing else to parse */
		} else if (offsetlen == 2) {
			if (index[1] == INETADDRESSTYPEIPV4)
				family = AF_INET;
			else if (index[1] == INETADDRESSTYPEIPV6)
				family = AF_INET6;
			else
				return NULL;
		} else if ((offsetlen == IN_ADDR_SIZE + 2 && index[1] == INETADDRESSTYPEIPV4) ||
			   (offsetlen == IN6_ADDR_SIZE + 2 && index[1] == INETADDRESSTYPEIPV6)) {
			if (index[1] == INETADDRESSTYPEIPV4) {
				family = AF_INET;
				addr.ipa_type = AF_INET;
				oid2in_addr(&index[2], IN_ADDR_SIZE, &addr.ip._v4_addr);
				addr_present = true;
			} else {
				family = AF_INET6;
				addr.ipa_type = AF_INET6;
				oid2in6_addr(&index[2], &addr.ip._v6_addr);
				addr_present = true;
			}
		} else {
			/* Unsupported partial index */
			return NULL;
		}
	}

	if (exact) {
		if (!addr_present)
			return NULL;
		peer = bgp_snmp_lookup_peer(vrf_id, &addr);
		if (peer &&
		    (!peer->connection ||
		     (family != AF_UNSPEC && sockunion_family(&peer->connection->su) != family)))
			peer = NULL;
	} else {
		peer = bgp_snmp_get_first_peer(true, AF_UNSPEC);
		oid candidate_index[CBGP_PEER3_TABLE_MAX_INDEX_LEN];
		size_t candidate_len = 0;

		while (peer) {
			candidate_len = cbgp4_fill_peer3_index(peer, candidate_index);
			if (!candidate_len) {
				peer = cbgp4_peer_next_global(peer);
				continue;
			}

			if (!offsetlen)
				break;

			int cmp = cbgp4_compare_index(index, offsetlen, candidate_index,
						      candidate_len);
			if (cmp < 0)
				break;
			if (cmp == 0) {
				peer = cbgp4_peer_next_global(peer);
				continue;
			}

			peer = cbgp4_peer_next_global(peer);
		}

		if (!peer)
			return NULL;

		memcpy(index, candidate_index, candidate_len * sizeof(oid));
		*length = namelen + candidate_len;
	}

	return peer;
}

static uint8_t *cbgp4PeerTable(struct variable *v, oid name[], size_t *length, int exact,
			       size_t *var_len, WriteMethod **write_method)
{
	struct peer *peer;

	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	peer = cbgp4PeerTable_lookup(v, name, length, exact);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case CBGP_PEER_LAST_ERROR_TXT:
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			struct bgp_notify notify = peer->notify;
			char msg_buf[255];
			const char *msg_str = NULL;

			if (notify.code == BGP_NOTIFY_CEASE &&
			    (notify.subcode == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN ||
			     notify.subcode == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
				msg_str = bgp_notify_admin_message(msg_buf, sizeof(msg_buf),
								   (uint8_t *)notify.data,
								   notify.length);
				return SNMP_STRING(msg_str);
			}
		}
		return SNMP_STRING("");

	case CBGP_PEER_PREV_STATE:
		return SNMP_INTEGER(peer->connection ? peer->connection->ostatus : Idle);

	// Deprecated
	case CBGP_PEER_PREFIX_ACCEPTED:
	case CBGP_PEER_PREFIX_DENIED:
	case CBGP_PEER_PREFIX_LIMIT:
	case CBGP_PEER_PREFIX_ADVERTISED:
	case CBGP_PEER_PREFIX_SUPPRESSED:
	case CBGP_PEER_PREFIX_WITHDRAWN:
	default:
		break;
	}

	return NULL;
}

static uint8_t *cbgp4Peer2Table(struct variable *v, oid name[], size_t *length, int exact,
				size_t *var_len, WriteMethod **write_method)
{
	struct peer *peer;
	uint32_t ui, uo;

	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	peer = cbgp4Peer2Table_lookup(v, name, length, exact);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case CBGP_PEER2_LOCAL_ADDR:
		if (peer->connection && peer->connection->su_local)
			if (peer->connection->su_local->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(peer->connection->su_local->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(peer->connection->su_local->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);

	case CBGP_PEER2_TYPE:
		if (peer->connection && peer->connection->su_remote)
			return SNMP_INTEGER(peer->connection->su_remote->sa.sa_family == AF_INET
						    ? AFI_IP
						    : AFI_IP6);
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER2_REMOTE_ADDR:
		if (peer->connection && peer->connection->su_remote)
			if (peer->connection->su_remote->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(peer->connection->su_remote->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(peer->connection->su_remote->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);

	case CBGP_PEER2_LOCAL_PORT:
		if (peer->connection && peer->connection->su_local)
			if (peer->connection->su_local->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->connection->su_local->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->connection->su_local->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER2_LOCAL_AS:
		return SNMP_INTEGER(peer->local_as);

	case CBGP_PEER2_LOCAL_IDENTIFIER:
		return SNMP_IPADDRESS(peer->local_id);

	case CBGP_PEER2_REMOTE_PORT:
		if (peer->connection && peer->connection->su_remote)
			if (peer->connection->su_remote->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->connection->su_remote->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->connection->su_remote->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER2_REMOTE_AS:
		return SNMP_INTEGER(peer->as);

	case CBGP_PEER2_REMOTE_IDENTIFIER:
		return SNMP_IPADDRESS(peer->remote_id);

	case CBGP_PEER2_ADMIN_STATUS:
#define CBGP_PEER2_ADMIN_STATUS_HALTED	1
#define CBGP_PEER2_ADMIN_STATUS_RUNNING 2
		if (BGP_PEER_START_SUPPRESSED(peer))
			return SNMP_INTEGER(CBGP_PEER2_ADMIN_STATUS_HALTED);
		else
			return SNMP_INTEGER(CBGP_PEER2_ADMIN_STATUS_RUNNING);

	case CBGP_PEER2_STATE:
		return SNMP_INTEGER(peer->connection ? peer->connection->status : Idle);

	case CBGP_PEER2_LAST_ERROR:
	{
		static uint8_t last_error[2];
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			last_error[0] = peer->notify.code;
			last_error[1] = peer->notify.subcode;
		} else {
			last_error[0] = 0;
			last_error[1] = 0;
		}
		*var_len = 2;
		return last_error;
	}

	case CBGP_PEER2_LAST_ERROR_TXT:
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			struct bgp_notify notify = peer->notify;
			char msg_buf[255];
			const char *msg_str = NULL;

			if (notify.code == BGP_NOTIFY_CEASE &&
			    (notify.subcode == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN ||
			     notify.subcode == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
				msg_str = bgp_notify_admin_message(msg_buf, sizeof(msg_buf),
								   (uint8_t *)notify.data,
								   notify.length);
				return SNMP_STRING(msg_str);
			}
		}
		return SNMP_STRING("");

	case CBGP_PEER2_CONNECT_RETRY_INTERVAL:
		return SNMP_INTEGER(peer->v_connect);

	case CBGP_PEER2_HOLD_TIME:
		return SNMP_INTEGER(peer->v_holdtime);

	case CBGP_PEER2_KEEP_ALIVE:
		return SNMP_INTEGER(peer->v_keepalive);

	case CBGP_PEER2_HOLD_TIME_CONFIGURED:
		return SNMP_INTEGER(CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)
					    ? peer->holdtime
					    : peer->bgp->default_holdtime);

	case CBGP_PEER2_KEEP_ALIVE_CONFIGURED:
		return SNMP_INTEGER(CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)
					    ? peer->keepalive
					    : peer->bgp->default_keepalive);

	case CBGP_PEER2_MIN_ROUTE_ADVERTISEMENT_INTERVAL:
		return SNMP_INTEGER(peer->v_routeadv);

	case CBGP_PEER2_IN_UPDATE_ELAPSED_TIME:
		if (!peer->update_time)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->update_time);

	case CBGP_PEER2_IN_UPDATES:
		ui = atomic_load_explicit(&peer->update_in, memory_order_relaxed);
		return SNMP_INTEGER(ui);

	case CBGP_PEER2_OUT_UPDATES:
		uo = atomic_load_explicit(&peer->update_out, memory_order_relaxed);
		return SNMP_INTEGER(uo);

	case CBGP_PEER2_IN_TOTAL_MESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_RX(peer));

	case CBGP_PEER2_OUT_TOTAL_MESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_TX(peer));

	case CBGP_PEER2_FSM_ESTABLISHED_TRANSITIONS:
		return SNMP_INTEGER(peer->established);

	case CBGP_PEER2_FSM_ESTABLISHED_TIME:
		if (!peer->uptime)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->uptime);

	case CBGP_PEER2_PREV_STATE:
		return SNMP_INTEGER(peer->connection ? peer->connection->ostatus : Idle);

	case CBGP_PEER2_NEGOTIATED_VERSION:
		return SNMP_INTEGER(BGP_VERSION_4);

	case CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL:
		return SNMP_INTEGER(peer->v_routeadv);
	default:
		break;
	}

	return NULL;
}

static uint8_t *cbgp4Peer3Table(struct variable *v, oid name[], size_t *length, int exact,
				size_t *var_len, WriteMethod **write_method)
{
	struct peer *peer;
	uint32_t ui, uo;

	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	peer = cbgp4Peer3Table_lookup(v, name, length, exact);
	if (!peer)
		return NULL;

	switch (v->magic) {
	case CBGP_PEER3_VRF_ID:
		return SNMP_INTEGER(peer->bgp->vrf_id);
	case CBGP_PEER3_VRF_NAME:
		return SNMP_STRING(peer->bgp->name_pretty);
	case CBGP_PEER3_LOCAL_ADDR:
		if (peer->connection && peer->connection->su_local)
			if (peer->connection->su_local->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(peer->connection->su_local->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(peer->connection->su_local->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);

	case CBGP_PEER3_TYPE:
		if (peer->connection && peer->connection->su_remote)
			return SNMP_INTEGER(peer->connection->su_remote->sa.sa_family == AF_INET
						    ? AFI_IP
						    : AFI_IP6);
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER3_REMOTE_ADDR:
		if (peer->connection && peer->connection->su_remote)
			if (peer->connection->su_remote->sa.sa_family == AF_INET)
				return SNMP_IPADDRESS(peer->connection->su_remote->sin.sin_addr);
			else
				return SNMP_IP6ADDRESS(peer->connection->su_remote->sin6.sin6_addr);
		else
			return SNMP_IPADDRESS(bgp_empty_addr);

	case CBGP_PEER3_LOCAL_PORT:
		if (peer->connection && peer->connection->su_local)
			if (peer->connection->su_local->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->connection->su_local->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->connection->su_local->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER3_LOCAL_AS:
		return SNMP_INTEGER(peer->local_as);

	case CBGP_PEER3_LOCAL_IDENTIFIER:
		return SNMP_IPADDRESS(peer->local_id);

	case CBGP_PEER3_REMOTE_PORT:
		if (peer->connection && peer->connection->su_remote)
			if (peer->connection->su_remote->sa.sa_family == AF_INET)
				return SNMP_INTEGER(
					ntohs(peer->connection->su_remote->sin.sin_port));
			else
				return SNMP_INTEGER(
					ntohs(peer->connection->su_remote->sin6.sin6_port));
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER3_REMOTE_AS:
		return SNMP_INTEGER(peer->as);

	case CBGP_PEER3_REMOTE_IDENTIFIER:
		return SNMP_IPADDRESS(peer->remote_id);

	case CBGP_PEER3_ADMIN_STATUS:
#define CBGP_PEER3_ADMIN_STATUS_HALTED	1
#define CBGP_PEER3_ADMIN_STATUS_RUNNING 2
		if (BGP_PEER_START_SUPPRESSED(peer))
			return SNMP_INTEGER(CBGP_PEER3_ADMIN_STATUS_HALTED);
		else
			return SNMP_INTEGER(CBGP_PEER3_ADMIN_STATUS_RUNNING);

	case CBGP_PEER3_STATE:
		return SNMP_INTEGER(peer->connection ? peer->connection->status : Idle);

	case CBGP_PEER3_LAST_ERROR:
	{
		static uint8_t last_error[2];
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			last_error[0] = peer->notify.code;
			last_error[1] = peer->notify.subcode;
		} else {
			last_error[0] = 0;
			last_error[1] = 0;
		}
		*var_len = 2;
		return last_error;
	}

	case CBGP_PEER3_LAST_ERROR_TXT:
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			struct bgp_notify notify = peer->notify;
			char msg_buf[255];
			const char *msg_str = NULL;

			if (notify.code == BGP_NOTIFY_CEASE &&
			    (notify.subcode == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN ||
			     notify.subcode == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
				msg_str = bgp_notify_admin_message(msg_buf, sizeof(msg_buf),
								   (uint8_t *)notify.data,
								   notify.length);
				return SNMP_STRING(msg_str);
			}
		}
		return SNMP_STRING("");

	case CBGP_PEER3_CONNECT_RETRY_INTERVAL:
		return SNMP_INTEGER(peer->v_connect);

	case CBGP_PEER3_HOLD_TIME:
		return SNMP_INTEGER(peer->v_holdtime);

	case CBGP_PEER3_KEEP_ALIVE:
		return SNMP_INTEGER(peer->v_keepalive);

	case CBGP_PEER3_HOLD_TIME_CONFIGURED:
		return SNMP_INTEGER(CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)
					    ? peer->holdtime
					    : peer->bgp->default_holdtime);

	case CBGP_PEER3_KEEP_ALIVE_CONFIGURED:
		return SNMP_INTEGER(CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)
					    ? peer->keepalive
					    : peer->bgp->default_keepalive);

	case CBGP_PEER3_MIN_ROUTE_ADVERTISEMENT_INTERVAL:
		return SNMP_INTEGER(peer->v_routeadv);

	case CBGP_PEER3_IN_UPDATE_ELAPSED_TIME:
		if (!peer->update_time)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->update_time);

	case CBGP_PEER3_IN_UPDATES:
		ui = atomic_load_explicit(&peer->update_in, memory_order_relaxed);
		return SNMP_INTEGER(ui);
	case CBGP_PEER3_OUT_UPDATES:
		uo = atomic_load_explicit(&peer->update_out, memory_order_relaxed);
		return SNMP_INTEGER(uo);

	case CBGP_PEER3_IN_TOTAL_MESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_RX(peer));

	case CBGP_PEER3_OUT_TOTAL_MESSAGES:
		return SNMP_INTEGER(PEER_TOTAL_TX(peer));

	case CBGP_PEER3_FSM_ESTABLISHED_TRANSITIONS:
		return SNMP_INTEGER(peer->established);

	case CBGP_PEER3_FSM_ESTABLISHED_TIME:
		if (!peer->uptime)
			return SNMP_INTEGER(0);
		else
			return SNMP_INTEGER(monotime(NULL) - peer->uptime);

	case CBGP_PEER3_PREV_STATE:
		return SNMP_INTEGER(peer->connection ? peer->connection->ostatus : Idle);

	case CBGP_PEER3_NEGOTIATED_VERSION:
		return SNMP_INTEGER(BGP_VERSION_4);

	case CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL:
		return SNMP_INTEGER(peer->v_routeadv);
	default:
		break;
	}

	return NULL;
}

static struct peer_af *cbgp4PeerAfTable_lookup(struct variable *v, oid name[], size_t *length,
					       int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct peer_af *paf = NULL;
	afi_t afi = 0;
	safi_t safi = 0;
	iana_afi_t iana_afi;
	iana_safi_t iana_safi;
	struct ipaddr addr = {};

	if (!offsetlen) {
		bgp_snmp_index_init(index, CBGP_PEER_TABLE_MAX_INDEX_LEN + 2);
	} else if (offsetlen == IN_ADDR_SIZE + 2) {
		addr.ipa_type = AF_INET;
		oid2in_addr(index, IN_ADDR_SIZE, &addr.ip._v4_addr);
		iana_afi = index[IN_ADDR_SIZE];
		iana_safi = index[IN_ADDR_SIZE + 1];
		/* Convert IANA AFI/SAFI to internal values */
		if (bgp_map_afi_safi_iana2int(iana_afi, iana_safi, &afi, &safi)) {
			/* Unsupported AFI/SAFI */
			return NULL;
		}
	} else {
		/* We cannot support partial indexes */
		return NULL;
	}

	if (exact) {
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

		if (!peer)
			return NULL;
		paf = peer_af_find(peer, afi, safi);
	} else {
		if (!offsetlen) {
			/*
			 * First Peer lookup
			 */
			peer = bgp_snmp_get_first_peer(false, AF_INET);
			paf = bgp_snmp_peer_af_next(peer, afi, safi);

		} else {
			/*
			 * First try to lookup the current Peer to traverse all
			 * the peer_af array.
			 */
			peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

			if (!peer) {
				// This should not happen.
				assert(0);
			}

			paf = bgp_snmp_peer_af_next(peer, afi, safi);

			if (paf == NULL) {
				/*
				 * We have traversed the entire peer_af array
				 * for this peer. Go to the next peer
				 */
				peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT, AF_INET, &addr);
				if (!peer) {
					/*
					 * We have traversed all the peers
					 */
					return NULL;
				}

				afi = 0;
				safi = 0;
				paf = bgp_snmp_peer_af_next(peer, afi, safi);
			}
		}
		if (paf && peer->connection) {
			iana_afi_t pkt_afi;
			iana_safi_t pkt_safi;

			/* Convert internal AFI/SAFI to IANA values for OID */
			bgp_map_afi_safi_int2iana(paf->afi, paf->safi, &pkt_afi, &pkt_safi);

			oid_copy_in_addr(index, &peer->connection->su.sin.sin_addr);
			index[IN_ADDR_SIZE] = pkt_afi;
			index[IN_ADDR_SIZE + 1] = pkt_safi;
			*length = namelen + IN_ADDR_SIZE + 2;
		}
	}
	return paf;
}

static struct peer_af *cbgp4Peer2AfTable_lookup(struct variable *v, oid name[], size_t *length,
						int exact)
{
	struct peer *peer = NULL;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct peer_af *paf = NULL;
	afi_t afi = 0;
	safi_t safi = 0;
	iana_afi_t iana_afi;
	iana_safi_t iana_safi;
	struct ipaddr addr = {};

	if (!offsetlen) {
		bgp_snmp_index_init(index, CBGP_PEER2_TABLE_MAX_INDEX_LEN + 2);
	} else if ((offsetlen == IN_ADDR_SIZE + 3) || (offsetlen == IN6_ADDR_SIZE + 3)) {
		addr.ipa_type = index[0] == 1 ? AF_INET : AF_INET6;
		if (addr.ipa_type == AF_INET) {
			oid2in_addr(&index[1], IN_ADDR_SIZE, &addr.ip._v4_addr);
			iana_afi = index[IN_ADDR_SIZE + 1];
			iana_safi = index[IN_ADDR_SIZE + 2];
		} else if (addr.ipa_type == AF_INET6) {
			oid2in6_addr(&index[1], &addr.ip._v6_addr);
			iana_afi = index[IN6_ADDR_SIZE + 1];
			iana_safi = index[IN6_ADDR_SIZE + 2];
		}
		/* Convert IANA AFI/SAFI to internal values */
		if (bgp_map_afi_safi_iana2int(iana_afi, iana_safi, &afi, &safi)) {
			/* Unsupported AFI/SAFI */
			return NULL;
		}
	} else {
		/* We cannot support partial indexes */
		return NULL;
	}

	if (exact) {
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

		if (!peer)
			return NULL;
		paf = peer_af_find(peer, afi, safi);
	} else {
		if (!offsetlen) {
			/*
			 * First Peer lookup
			 */
			peer = bgp_snmp_get_first_peer(false, AF_UNSPEC);
			paf = bgp_snmp_peer_af_next(peer, afi, safi);

		} else {
			/*
			 * First try to lookup the current Peer to traverse all
			 * the peer_af array.
			 */
			peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

			if (!peer) {
				// This should not happen.
				assert(0);
			}

			paf = bgp_snmp_peer_af_next(peer, afi, safi);

			if (paf == NULL) {
				/*
				 * We have traversed the entire peer_af array
				 * for this peer. Go to the next peer
				 */
				sa_family_t next_family = AF_UNSPEC;

				if (addr.ipa_type == IPADDR_V4)
					next_family = AF_INET;
				else if (addr.ipa_type == IPADDR_V6)
					next_family = AF_INET6;

				peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT, next_family,
							      &addr);
				if (!peer && next_family != AF_UNSPEC)
					peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT,
								      AF_UNSPEC, &addr);
				if (!peer) {
					/*
					 * We have traversed all the peers
					 */
					return NULL;
				}

				afi = 0;
				safi = 0;
				paf = bgp_snmp_peer_af_next(peer, afi, safi);
			}
		}
		if (paf && peer->connection) {
			iana_afi_t pkt_afi;
			iana_safi_t pkt_safi;

			/* Convert internal AFI/SAFI to IANA values for OID */
			bgp_map_afi_safi_int2iana(paf->afi, paf->safi, &pkt_afi, &pkt_safi);

			switch (sockunion_family(&peer->connection->su)) {
			case AF_INET:
				index[0] = INETADDRESSTYPEIPV4;
				oid_copy_in_addr(&index[1],
						 &peer->connection->su.sin.sin_addr);
				index[1 + IN_ADDR_SIZE] = pkt_afi;
				index[2 + IN_ADDR_SIZE] = pkt_safi;
				*length = namelen + IN_ADDR_SIZE + 3;
				break;
			case AF_INET6:
				index[0] = INETADDRESSTYPEIPV6;
				oid_copy_in6_addr(&index[1],
						  &peer->connection->su.sin6.sin6_addr);
				index[1 + IN6_ADDR_SIZE] = pkt_afi;
				index[2 + IN6_ADDR_SIZE] = pkt_safi;
				*length = IN6_ADDR_SIZE + namelen + 3;
				break;
			default:
				break;
			}
		}
	}
	return paf;
}

static uint8_t *cbgp4PeerAddrFamilyTable(struct variable *v, oid name[], size_t *length, int exact,
					 size_t *var_len, WriteMethod **write_method)
{
	struct peer_af *paf = NULL;
	iana_afi_t iana_afi;
	iana_safi_t iana_safi;

	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	paf = cbgp4PeerAfTable_lookup(v, name, length, exact);
	if (!paf)
		return NULL;

	/* Convert internal AFI/SAFI to IANA values for SNMP */
	bgp_map_afi_safi_int2iana(paf->afi, paf->safi, &iana_afi, &iana_safi);

	switch (v->magic) {
	case CBGP_PEER_ADDR_FAMILY_AFI:
		return SNMP_INTEGER(iana_afi);

	case CBGP_PEER_ADDR_FAMILY_SAFI:
		return SNMP_INTEGER(iana_safi);

	case CBGP_PEER_ADDR_FAMILY_NAME:
		return SNMP_STRING(get_afi_safi_vty_str(paf->afi, paf->safi));

	default:
		break;
	}

	return NULL;
}

static uint8_t *cbgp4PeerAddrFamilyPrefixTable(struct variable *v, oid name[], size_t *length,
					       int exact, size_t *var_len,
					       WriteMethod **write_method)
{
	struct peer *peer;
	struct peer_af *paf = NULL;

	/*
	 * Validate the SMUX header
	 */
	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	/*
	 * Extract AFI and SAFI from the OID
	 */
	paf = cbgp4PeerAfTable_lookup(v, name, length, exact);
	if (!paf)
		return NULL;

	peer = paf->peer;

	/*
	 * Handle the requested variable
	 */
	switch (v->magic) {
	case CBGP_PEER_ACCEPTED_PREFIXES:
		return SNMP_INTEGER(peer->pcount[paf->afi][paf->safi]);

	case CBGP_PEER_DENIED_PREFIXES:
		return SNMP_INTEGER(peer->pfiltered[paf->afi][paf->safi]);

	case CBGP_PEER_PREFIX_ADMIN_LIMIT:
		return SNMP_INTEGER(peer->pmax[paf->afi][paf->safi]);

	case CBGP_PEER_PREFIX_THRESHOLD:
		return SNMP_INTEGER(peer->pmax_threshold[paf->afi][paf->safi]);

	case CBGP_PEER_ADVERTISED_PREFIXES:
		if (PAF_SUBGRP(paf))
			return (SNMP_INTEGER(PAF_SUBGRP(paf)->scount));
		else
			return SNMP_INTEGER(0);

	case CBGP_PEER_PREFIX_CLEAR_THRESHOLD:
		return SNMP_INTEGER(peer->pmax_threshold[paf->afi][paf->safi]);

	case CBGP_PEER_SUPPRESSED_PREFIXES:
		return SNMP_INTEGER(peer->psuppressed_cnt[paf->afi][paf->safi]);

	case CBGP_PEER_WITHDRAWN_PREFIXES:
		return SNMP_INTEGER(peer->pwithdraw_cnt[paf->afi][paf->safi]);

	default:
		break;
	}

	return NULL;
}


static uint8_t *cbgp4Peer2AddrFamilyTable(struct variable *v, oid name[], size_t *length,
					  int exact, size_t *var_len, WriteMethod **write_method)
{
	struct peer_af *paf = NULL;
	iana_afi_t iana_afi;
	iana_safi_t iana_safi;

	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	paf = cbgp4Peer2AfTable_lookup(v, name, length, exact);
	if (!paf)
		return NULL;

	/* Convert internal AFI/SAFI to IANA values for SNMP */
	bgp_map_afi_safi_int2iana(paf->afi, paf->safi, &iana_afi, &iana_safi);

	switch (v->magic) {
	case CBGP_PEER2_ADDR_FAMILY_AFI:
		return SNMP_INTEGER(iana_afi);

	case CBGP_PEER2_ADDR_FAMILY_SAFI:
		return SNMP_INTEGER(iana_safi);

	case CBGP_PEER2_ADDR_FAMILY_NAME:
		return SNMP_STRING(get_afi_safi_vty_str(paf->afi, paf->safi));

	default:
		break;
	}

	return NULL;
}

static uint8_t *cbgp4Peer2AddrFamilyPrefixTable(struct variable *v, oid name[], size_t *length,
						int exact, size_t *var_len,
						WriteMethod **write_method)
{
	struct peer *peer;
	struct peer_af *paf = NULL;

	/*
	 * Validate the SMUX header
	 */
	if (smux_header_table(v, name, length, exact, var_len, write_method) == MATCH_FAILED)
		return NULL;

	/*
	 * Extract AFI and SAFI from the OID
	 */
	paf = cbgp4Peer2AfTable_lookup(v, name, length, exact);
	if (!paf)
		return NULL;

	peer = paf->peer;

	/*
	 * Handle the requested variable
	 */
	switch (v->magic) {
	case CBGP_PEER2_ACCEPTED_PREFIXES:
		return SNMP_INTEGER(peer->pcount[paf->afi][paf->safi]);

	case CBGP_PEER2_DENIED_PREFIXES:
		return SNMP_INTEGER(peer->pfiltered[paf->afi][paf->safi]);

	case CBGP_PEER2_PREFIX_ADMIN_LIMIT:
		return SNMP_INTEGER(peer->pmax[paf->afi][paf->safi]);

	case CBGP_PEER2_PREFIX_THRESHOLD:
		return SNMP_INTEGER(peer->pmax_threshold[paf->afi][paf->safi]);

	case CBGP_PEER2_ADVERTISED_PREFIXES:
		if (PAF_SUBGRP(paf))
			return (SNMP_INTEGER(PAF_SUBGRP(paf)->scount));
		else
			return SNMP_INTEGER(0);

	/*
	 * Not supported Yet.
	 */
	case CBGP_PEER2_PREFIX_CLEAR_THRESHOLD:
		return SNMP_INTEGER(peer->pmax_threshold[paf->afi][paf->safi]);

	case CBGP_PEER2_SUPPRESSED_PREFIXES:
		return SNMP_INTEGER(peer->psuppressed_cnt[paf->afi][paf->safi]);

	case CBGP_PEER2_WITHDRAWN_PREFIXES:
		return SNMP_INTEGER(peer->pwithdraw_cnt[paf->afi][paf->safi]);

	default:
		break;
	}

	return NULL;
}
/*
 * AFI/SAFI pairs for cbgpRouteTable iteration
 * IPv4 Unicast, IPv6 Unicast, and L2VPN EVPN are supported
 */
static const struct {
	afi_t afi;
	safi_t safi;
} afi_safi_list[] = {
	{ AFI_IP, SAFI_UNICAST },    /* IPv4 Unicast */
	{ AFI_IP6, SAFI_UNICAST },   /* IPv6 Unicast */
	{ AFI_L2VPN, SAFI_EVPN },    /* L2VPN EVPN */
};
#define AFI_SAFI_LIST_SIZE (sizeof(afi_safi_list) / sizeof(afi_safi_list[0]))

/* Maximum EVPN prefix size in bytes (route_type + eth_tag + mac + ip + esi + etc) */
#define CBGP_MAX_EVPN_PREFIX_LEN 64

/* Static buffer for cbgpRouteTable OCTET STRING columns */
static uint8_t cbgp_route_octet_buf[CBGP_MAX_EVPN_PREFIX_LEN];

/*
 * Helper function to encode EVPN prefix into bytes for SNMP
 * Returns the number of bytes encoded, or 0 on error
 */
static size_t encode_evpn_prefix(const struct prefix *p, uint8_t *buf, size_t buflen)
{
	const struct prefix_evpn *evp;
	size_t offset = 0;

	if (!p || p->family != AF_EVPN || !buf || buflen < 1)
		return 0;

	evp = (const struct prefix_evpn *)p;

	/* Encode route type first */
	buf[offset++] = evp->prefix.route_type;

	switch (evp->prefix.route_type) {
	case BGP_EVPN_AD_ROUTE: /* Type 1 - Ethernet Auto-Discovery */
		/* esi (10) + eth_tag (4) + ip_len (1) + ip (0/4/16) + frag_id (2) */
		if (offset + 17 > buflen)
			return 0;
		/* ESI (10 bytes) */
		memcpy(&buf[offset], evp->prefix.ead_addr.esi.val, ESI_BYTES);
		offset += ESI_BYTES;
		/* Ethernet tag */
		buf[offset++] = (evp->prefix.ead_addr.eth_tag >> 24) & 0xff;
		buf[offset++] = (evp->prefix.ead_addr.eth_tag >> 16) & 0xff;
		buf[offset++] = (evp->prefix.ead_addr.eth_tag >> 8) & 0xff;
		buf[offset++] = evp->prefix.ead_addr.eth_tag & 0xff;
		/* IP address (optional) */
		if (IS_IPADDR_V4(&evp->prefix.ead_addr.ip)) {
			buf[offset++] = 4;
			if (offset + 4 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.ead_addr.ip.ipaddr_v4, 4);
			offset += 4;
		} else if (IS_IPADDR_V6(&evp->prefix.ead_addr.ip)) {
			buf[offset++] = 16;
			if (offset + 16 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.ead_addr.ip.ipaddr_v6, 16);
			offset += 16;
		} else {
			buf[offset++] = 0; /* No IP */
		}
		/* Fragment ID (2 bytes) */
		buf[offset++] = (evp->prefix.ead_addr.frag_id >> 8) & 0xff;
		buf[offset++] = evp->prefix.ead_addr.frag_id & 0xff;
		break;

	case BGP_EVPN_MAC_IP_ROUTE: /* Type 2 */
		/* eth_tag (4) + mac (6) + ip_len (1) + ip (0/4/16) */
		if (offset + 11 > buflen)
			return 0;
		/* Ethernet tag */
		buf[offset++] = (evp->prefix.macip_addr.eth_tag >> 24) & 0xff;
		buf[offset++] = (evp->prefix.macip_addr.eth_tag >> 16) & 0xff;
		buf[offset++] = (evp->prefix.macip_addr.eth_tag >> 8) & 0xff;
		buf[offset++] = evp->prefix.macip_addr.eth_tag & 0xff;
		/* MAC address */
		memcpy(&buf[offset], evp->prefix.macip_addr.mac.octet, 6);
		offset += 6;
		/* IP address */
		if (IS_IPADDR_V4(&evp->prefix.macip_addr.ip)) {
			buf[offset++] = 4;
			if (offset + 4 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.macip_addr.ip.ipaddr_v4, 4);
			offset += 4;
		} else if (IS_IPADDR_V6(&evp->prefix.macip_addr.ip)) {
			buf[offset++] = 16;
			if (offset + 16 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.macip_addr.ip.ipaddr_v6, 16);
			offset += 16;
		} else {
			buf[offset++] = 0; /* No IP */
		}
		break;

	case BGP_EVPN_IMET_ROUTE: /* Type 3 */
		/* eth_tag (4) + ip_len (1) + ip (4/16) */
		if (offset + 5 > buflen)
			return 0;
		/* Ethernet tag */
		buf[offset++] = (evp->prefix.imet_addr.eth_tag >> 24) & 0xff;
		buf[offset++] = (evp->prefix.imet_addr.eth_tag >> 16) & 0xff;
		buf[offset++] = (evp->prefix.imet_addr.eth_tag >> 8) & 0xff;
		buf[offset++] = evp->prefix.imet_addr.eth_tag & 0xff;
		/* IP address */
		if (IS_IPADDR_V4(&evp->prefix.imet_addr.ip)) {
			buf[offset++] = 4;
			if (offset + 4 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.imet_addr.ip.ipaddr_v4, 4);
			offset += 4;
		} else if (IS_IPADDR_V6(&evp->prefix.imet_addr.ip)) {
			buf[offset++] = 16;
			if (offset + 16 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.imet_addr.ip.ipaddr_v6, 16);
			offset += 16;
		} else {
			buf[offset++] = 0;
		}
		break;

	case BGP_EVPN_IP_PREFIX_ROUTE: /* Type 5 */
		/* eth_tag (4) + prefix_len (1) + ip (4/16) */
		if (offset + 5 > buflen)
			return 0;
		/* Ethernet tag */
		buf[offset++] = (evp->prefix.prefix_addr.eth_tag >> 24) & 0xff;
		buf[offset++] = (evp->prefix.prefix_addr.eth_tag >> 16) & 0xff;
		buf[offset++] = (evp->prefix.prefix_addr.eth_tag >> 8) & 0xff;
		buf[offset++] = evp->prefix.prefix_addr.eth_tag & 0xff;
		/* Prefix length */
		buf[offset++] = evp->prefix.prefix_addr.ip_prefix_length;
		/* IP prefix */
		if (IS_IPADDR_V4(&evp->prefix.prefix_addr.ip)) {
			if (offset + 4 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.prefix_addr.ip.ipaddr_v4, 4);
			offset += 4;
		} else if (IS_IPADDR_V6(&evp->prefix.prefix_addr.ip)) {
			if (offset + 16 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.prefix_addr.ip.ipaddr_v6, 16);
			offset += 16;
		}
		break;

	case BGP_EVPN_ES_ROUTE: /* Type 4 - Ethernet Segment */
		/* esi (10) + ip_len (1) + ip (4/16) */
		if (offset + 11 > buflen)
			return 0;
		/* ESI (10 bytes) */
		memcpy(&buf[offset], evp->prefix.es_addr.esi.val, ESI_BYTES);
		offset += ESI_BYTES;
		/* IP address */
		if (IS_IPADDR_V4(&evp->prefix.es_addr.ip)) {
			buf[offset++] = 4;
			if (offset + 4 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.es_addr.ip.ipaddr_v4, 4);
			offset += 4;
		} else if (IS_IPADDR_V6(&evp->prefix.es_addr.ip)) {
			buf[offset++] = 16;
			if (offset + 16 > buflen)
				return 0;
			memcpy(&buf[offset], &evp->prefix.es_addr.ip.ipaddr_v6, 16);
			offset += 16;
		} else {
			buf[offset++] = 0;
		}
		break;

	default:
		/* Unknown route type - just encode route type byte */
		break;
	}

	return offset;
}


/*
 * cbgpRouteTable lookup function
 * 
 * CISCO-BGP4-MIB Index Order (strict compliance):
 * INDEX { cbgpRouteAfi, cbgpRouteSafi, cbgpRoutePeerType, cbgpRoutePeer,
 *         cbgpRouteAddrPrefix, cbgpRouteAddrPrefixLen }
 *
 * OID encoding (per SNMP rules for OCTET STRING indexes):
 * - InetAddress (cbgpRoutePeer): length + bytes  (e.g., IPv4: 4.a.b.c.d)
 * - CbGpNetworkAddress (cbgpRouteAddrPrefix): length + bytes (e.g., 4.172.16.1.0)
 *
 * Full OID structure:
 * <base>.<column>.<afi>.<safi>.<peerType>.<peerLen>.<peer[0]>...<peer[n]>.<prefixLen>.<prefix[0]>...<prefix[n]>.<prefixBitLen>
 *
 * Example for IPv4 peer 10.10.0.2, prefix 172.16.1.0/24:
 * ...7.1.1.1.4.10.10.0.2.4.172.16.1.0.24
 *      ^afi ^safi ^peerType ^peerLen(4) ^peerAddr ^prefixLen(4 bytes) ^prefix ^prefixBitLen(24 bits)
 *
 * Supports: IPv4 Unicast (AFI=1, SAFI=1) and IPv6 Unicast (AFI=2, SAFI=1)
 *
 * Algorithm for GETNEXT:
 * 1. Parse OID to extract the full index tuple
 * 2. Iterate through all AFI/SAFI pairs in order
 * 3. Find the first (afi, safi, peer, route) tuple > search key
 */
static struct bgp_path_info *
cbgp4RouteTable_lookup(struct variable *v, oid name[], size_t *length,
		       struct bgp *bgp, struct prefix *addr, int exact)
{
	oid *offset;
	int offsetlen;
	size_t offsetlen_initial;
	struct bgp_path_info *path;
	struct bgp_dest *dest;
	union sockunion su;
	size_t namelen = v ? v->namelen : CBGP_ROUTE_ENTRY_OFFSET;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	
	/* Search key components */
	int search_peer_type = 0;
	size_t search_peer_len = 0;
	uint8_t search_peer_bytes[16] = {};
	size_t search_prefix_len_bytes = 0;
	uint8_t search_prefix_bytes[CBGP_MAX_EVPN_PREFIX_LEN] = {};
	uint8_t search_prefix_bitlen = 0;

	sockunion_init(&su);

	offset = name + namelen;
	offsetlen = *length - namelen;
	offsetlen_initial = (size_t)(*length - namelen);

	/* Parse IANA AFI from OID index and convert to internal */
	iana_afi_t iana_afi = IANA_AFI_IPV4;
	iana_safi_t iana_safi = IANA_SAFI_UNICAST;

	if (offsetlen > 0) {
		iana_afi = *offset;
		offset++;
		offsetlen--;
	}

	/* Parse IANA SAFI from OID index */
	if (offsetlen > 0) {
		iana_safi = *offset;
		offset++;
		offsetlen--;
	}

	/* Convert IANA to internal AFI/SAFI */
	if (bgp_map_afi_safi_iana2int(iana_afi, iana_safi, &afi, &safi)) {
		/* Invalid AFI/SAFI - use defaults */
		afi = AFI_IP;
		safi = SAFI_UNICAST;
	}

	/* Parse PeerType (InetAddressType: 1=IPv4, 2=IPv6) */
	if (offsetlen > 0) {
		search_peer_type = *offset;
		offset++;
		offsetlen--;
	}

	/* Parse PeerAddr (InetAddress: length + bytes) */
	if (offsetlen > 0) {
		search_peer_len = *offset;
		if (search_peer_len > 16)
			search_peer_len = 16;
		offset++;
		offsetlen--;

		for (size_t i = 0; i < search_peer_len && offsetlen > 0; i++) {
			search_peer_bytes[i] = *offset;
			offset++;
			offsetlen--;
		}
	}

	/* Parse Prefix (CbGpNetworkAddress: length + bytes) */
	if (offsetlen > 0) {
		search_prefix_len_bytes = *offset;
		if (search_prefix_len_bytes > CBGP_MAX_EVPN_PREFIX_LEN)
			search_prefix_len_bytes = CBGP_MAX_EVPN_PREFIX_LEN;
		offset++;
		offsetlen--;

		for (size_t i = 0; i < search_prefix_len_bytes && offsetlen > 0; i++) {
			search_prefix_bytes[i] = *offset;
			offset++;
			offsetlen--;
		}
	}

	/* Parse PrefixBitLen (Unsigned32 - the CIDR prefix length in bits) */
	if (offsetlen > 0) {
		search_prefix_bitlen = *offset;
	}

	if (exact) {
		/*
		 * Minimum index for exact match: afi(1) + safi(1) + peerType(1) + peerLen(1) + peerBytes
		 * + prefixLenBytes(1) + prefixBytes + prefixBitLen(1)
		 */
		if (offsetlen_initial < 6 + search_peer_len + search_prefix_len_bytes)
			return NULL;

		/* Build prefix from parsed bytes based on AFI */
		if (afi == AFI_IP) {
			addr->family = AF_INET;
			memcpy(&addr->u.prefix4, search_prefix_bytes, 
			       search_prefix_len_bytes > 4 ? 4 : search_prefix_len_bytes);
		} else if (afi == AFI_IP6) {
			addr->family = AF_INET6;
			memcpy(&addr->u.prefix6, search_prefix_bytes,
			       search_prefix_len_bytes > 16 ? 16 : search_prefix_len_bytes);
		} else if (afi == AFI_L2VPN) {
			/*
			 * For EVPN exact match, we need to iterate through the table
			 * and find a matching prefix since decoding EVPN from OID bytes
			 * back to struct prefix_evpn is complex. For now, return NULL
			 * for exact match on EVPN - GETNEXT still works.
			 */
			return NULL;
		} else {
			return NULL;
		}
		addr->prefixlen = search_prefix_bitlen;

		/* Build peer sockunion from parsed bytes */
		if (search_peer_type == 1) {
			su.sa.sa_family = AF_INET;
			memcpy(&su.sin.sin_addr, search_peer_bytes,
			       search_peer_len > 4 ? 4 : search_peer_len);
		} else {
			su.sa.sa_family = AF_INET6;
			memcpy(&su.sin6.sin6_addr, search_peer_bytes,
			       search_peer_len > 16 ? 16 : search_peer_len);
		}

		/* Lookup node in RIB */
		dest = bgp_node_lookup(bgp->rib[afi][safi], addr);
		if (dest) {
			for (path = bgp_dest_get_bgp_path_info(dest); path;
			     path = path->next) {
				if (sockunion_same(&path->peer->connection->su, &su)) {
					bgp_dest_unlock_node(dest);
					return path;
				}
				/* Check for self-originated routes using router-id */
				if (path->peer == path->peer->bgp->peer_self &&
				    search_peer_type == 1 && search_peer_len == 4) {
					if (memcmp(&path->peer->bgp->router_id,
						   search_peer_bytes, 4) == 0) {
						bgp_dest_unlock_node(dest);
						return path;
					}
				}
			}
			bgp_dest_unlock_node(dest);
		}
		return NULL;
	}

	/*
	 * GETNEXT handling - CISCO index order with correct InetAddress encoding
	 * 
	 * Full tuple order for comparison:
	 * 1. AFI (1=IPv4 < 2=IPv6)
	 * 2. SAFI (1=Unicast)
	 * 3. PeerType (1=IPv4 < 2=IPv6)
	 * 4. PeerLen (length of peer address)
	 * 5. PeerBytes (byte-by-byte)
	 * 6. PrefixLenBytes (length of prefix in bytes)
	 * 7. PrefixBytes (byte-by-byte)
	 * 8. PrefixBitLen (CIDR prefix length)
	 *
	 * We iterate through ALL AFI/SAFI pairs to find the minimum tuple > search key
	 */

	struct bgp_path_info *min_path = NULL;
	struct prefix min_prefix = {};
	
	/* Minimum tuple components for comparison */
	afi_t min_afi = 0;
	safi_t min_safi = 0;
	int min_peer_type = 0;
	size_t min_peer_len = 0;
	uint8_t min_peer_bytes[16] = {};
	size_t min_prefix_len_bytes = 0;
	uint8_t min_prefix_bytes[CBGP_MAX_EVPN_PREFIX_LEN] = {};
	uint8_t min_prefix_bitlen = 0;

	/* Iterate through ALL AFI/SAFI combinations */
	for (size_t af_idx = 0; af_idx < AFI_SAFI_LIST_SIZE; af_idx++) {
		afi_t cur_afi = afi_safi_list[af_idx].afi;
		safi_t cur_safi = afi_safi_list[af_idx].safi;

		/* Skip if RIB table doesn't exist */
		if (!bgp->rib[cur_afi][cur_safi])
			continue;

		/*
		 * EVPN uses a two-level RIB structure:
		 * Level 1: RD (Route Distinguisher) entries
		 * Level 2: Actual EVPN prefixes under each RD
		 *
		 * For IPv4/IPv6 unicast, it's a single-level structure.
		 */
		if (cur_afi == AFI_L2VPN && cur_safi == SAFI_EVPN) {
			/* Two-level iteration for EVPN */
			struct bgp_dest *rd_dest;
			struct bgp_table *evpn_table;

			for (rd_dest = bgp_table_top(bgp->rib[cur_afi][cur_safi]); rd_dest;
			     rd_dest = bgp_route_next(rd_dest)) {
				/* Get the sub-table for this RD */
				evpn_table = bgp_dest_get_bgp_table_info(rd_dest);
				if (!evpn_table)
					continue;

				/* Iterate actual EVPN routes in sub-table */
				for (dest = bgp_table_top(evpn_table); dest;
				     dest = bgp_route_next(dest)) {
					const struct prefix *rn_p = bgp_dest_get_prefix(dest);

					/* Skip if prefix is NULL or not EVPN */
					if (!rn_p || rn_p->family != AF_EVPN)
						continue;

					for (path = bgp_dest_get_bgp_path_info(dest); path;
					     path = path->next) {
						/* Process EVPN path - call helper macro/goto */
						/* Skip paths without peer or attr */
						if (!path->peer || !path->attr)
							continue;

						sa_family_t peer_family = sockunion_family(&path->peer->connection->su);
						int is_self_peer = 0;

						/* Handle locally originated routes (peer_self) */
						if (peer_family != AF_INET && peer_family != AF_INET6) {
							if (path->peer == path->peer->bgp->peer_self) {
								is_self_peer = 1;
								peer_family = AF_INET;
							} else {
								continue;
							}
						}

						/* Build current tuple */
						int cur_peer_type = (peer_family == AF_INET) ? 1 : 2;
						size_t cur_peer_len = (peer_family == AF_INET) ? 4 : 16;
						uint8_t cur_peer_bytes[16] = {};
						uint8_t cur_prefix_bytes[CBGP_MAX_EVPN_PREFIX_LEN] = {};
						size_t cur_prefix_len_bytes = 0;
						uint8_t cur_prefix_bitlen = rn_p->prefixlen;

						if (is_self_peer) {
							memcpy(cur_peer_bytes, &path->peer->bgp->router_id, 4);
						} else if (peer_family == AF_INET) {
							memcpy(cur_peer_bytes, &path->peer->connection->su.sin.sin_addr, 4);
						} else {
							memcpy(cur_peer_bytes, &path->peer->connection->su.sin6.sin6_addr, 16);
						}

						/* Encode EVPN prefix */
						cur_prefix_len_bytes = encode_evpn_prefix(rn_p, cur_prefix_bytes,
											  sizeof(cur_prefix_bytes));
						if (cur_prefix_len_bytes == 0)
							continue;

						/* Convert to IANA for comparison */
						iana_afi_t cur_iana_afi;
						iana_safi_t cur_iana_safi;
						bgp_map_afi_safi_int2iana(cur_afi, cur_safi, &cur_iana_afi, &cur_iana_safi);

						/* Compare current tuple with search key */
						int cmp = 0;
						if (cmp == 0)
							cmp = (int)cur_iana_afi - (int)iana_afi;
						if (cmp == 0)
							cmp = (int)cur_iana_safi - (int)iana_safi;
						if (cmp == 0)
							cmp = cur_peer_type - search_peer_type;
						if (cmp == 0)
							cmp = (int)cur_peer_len - (int)search_peer_len;
						if (cmp == 0)
							cmp = memcmp(cur_peer_bytes, search_peer_bytes, cur_peer_len);
						if (cmp == 0)
							cmp = (int)cur_prefix_len_bytes - (int)search_prefix_len_bytes;
						if (cmp == 0)
							cmp = memcmp(cur_prefix_bytes, search_prefix_bytes, cur_prefix_len_bytes);
						if (cmp == 0)
							cmp = cur_prefix_bitlen - search_prefix_bitlen;

						if (cmp <= 0)
							continue;

						/* Current > search. Check if smaller than min */
						if (!min_path) {
							min_path = path;
							min_prefix = *rn_p;
							min_afi = cur_afi;
							min_safi = cur_safi;
							min_peer_type = cur_peer_type;
							min_peer_len = cur_peer_len;
							memcpy(min_peer_bytes, cur_peer_bytes, 16);
							min_prefix_len_bytes = cur_prefix_len_bytes;
							memcpy(min_prefix_bytes, cur_prefix_bytes, cur_prefix_len_bytes);
							min_prefix_bitlen = cur_prefix_bitlen;
						} else {
							/* Compare with min */
							int min_cmp = 0;
							iana_afi_t min_iana_afi;
							iana_safi_t min_iana_safi;
							bgp_map_afi_safi_int2iana(min_afi, min_safi, &min_iana_afi, &min_iana_safi);

							if (min_cmp == 0)
								min_cmp = (int)cur_iana_afi - (int)min_iana_afi;
							if (min_cmp == 0)
								min_cmp = (int)cur_iana_safi - (int)min_iana_safi;
							if (min_cmp == 0)
								min_cmp = cur_peer_type - min_peer_type;
							if (min_cmp == 0)
								min_cmp = (int)cur_peer_len - (int)min_peer_len;
							if (min_cmp == 0)
								min_cmp = memcmp(cur_peer_bytes, min_peer_bytes, cur_peer_len);
							if (min_cmp == 0)
								min_cmp = (int)cur_prefix_len_bytes - (int)min_prefix_len_bytes;
							if (min_cmp == 0)
								min_cmp = memcmp(cur_prefix_bytes, min_prefix_bytes, cur_prefix_len_bytes);
							if (min_cmp == 0)
								min_cmp = cur_prefix_bitlen - min_prefix_bitlen;

							if (min_cmp < 0) {
								min_path = path;
								min_prefix = *rn_p;
								min_afi = cur_afi;
								min_safi = cur_safi;
								min_peer_type = cur_peer_type;
								min_peer_len = cur_peer_len;
								memcpy(min_peer_bytes, cur_peer_bytes, 16);
								min_prefix_len_bytes = cur_prefix_len_bytes;
								memcpy(min_prefix_bytes, cur_prefix_bytes, cur_prefix_len_bytes);
								min_prefix_bitlen = cur_prefix_bitlen;
							}
						}
					}
				}
			}
			continue; /* Done with EVPN, move to next AFI/SAFI */
		}

		/* Single-level iteration for IPv4/IPv6 unicast */
		for (dest = bgp_table_top(bgp->rib[cur_afi][cur_safi]); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *rn_p = bgp_dest_get_prefix(dest);

			/* Skip if prefix is NULL */
			if (!rn_p)
				continue;

			for (path = bgp_dest_get_bgp_path_info(dest); path;
			     path = path->next) {
				/* Skip paths without peer or attr */
				if (!path->peer || !path->attr)
					continue;

				sa_family_t peer_family = sockunion_family(&path->peer->connection->su);
				int is_self_peer = 0;

				/* Handle locally originated routes (peer_self) */
				if (peer_family != AF_INET && peer_family != AF_INET6) {
					/* Check if this is a self-originated route */
					if (path->peer == path->peer->bgp->peer_self) {
						is_self_peer = 1;
						peer_family = AF_INET; /* Router-ID is IPv4 */
					} else {
						continue;
					}
				}

				/* Build current tuple */
				int cur_peer_type = (peer_family == AF_INET) ? 1 : 2;
				size_t cur_peer_len = (peer_family == AF_INET) ? 4 : 16;
				uint8_t cur_peer_bytes[16] = {};
				uint8_t cur_prefix_bytes[CBGP_MAX_EVPN_PREFIX_LEN] = {};
				size_t cur_prefix_len_bytes = 0;
				uint8_t cur_prefix_bitlen = rn_p->prefixlen;

				if (is_self_peer) {
					/* Use router-id as peer address for self-originated routes */
					memcpy(cur_peer_bytes, &path->peer->bgp->router_id, 4);
				} else if (peer_family == AF_INET) {
					memcpy(cur_peer_bytes, &path->peer->connection->su.sin.sin_addr, 4);
				} else {
					memcpy(cur_peer_bytes, &path->peer->connection->su.sin6.sin6_addr, 16);
				}

				/* Handle prefix encoding based on AFI */
				if (cur_afi == AFI_IP) {
					cur_prefix_len_bytes = 4;
					memcpy(cur_prefix_bytes, &rn_p->u.prefix4, 4);
				} else if (cur_afi == AFI_IP6) {
					cur_prefix_len_bytes = 16;
					memcpy(cur_prefix_bytes, &rn_p->u.prefix6, 16);
				} else if (cur_afi == AFI_L2VPN && rn_p->family == AF_EVPN) {
					/* EVPN prefix - encode safely */
					cur_prefix_len_bytes = encode_evpn_prefix(rn_p, cur_prefix_bytes,
										     sizeof(cur_prefix_bytes));
					if (cur_prefix_len_bytes == 0)
						continue; /* Skip invalid EVPN prefix */
				} else {
					/* Unknown AFI/family combination - skip */
					continue;
				}

				/*
				 * Compare current tuple with search key
				 * Full tuple order: (AFI, SAFI, peerType, peerLen, peerBytes, prefixLenBytes, prefixBytes, prefixBitLen)
				 * Use IANA AFI/SAFI values for proper ordering (L2VPN=25 > IPv6=2 > IPv4=1)
				 */
				int cmp = 0;

				/* Convert current AFI/SAFI to IANA for comparison */
				iana_afi_t cur_iana_afi;
				iana_safi_t cur_iana_safi;
				bgp_map_afi_safi_int2iana(cur_afi, cur_safi, &cur_iana_afi, &cur_iana_safi);

				/* 1. Compare AFI (using IANA values) */
				if (cmp == 0)
					cmp = (int)cur_iana_afi - (int)iana_afi;

				/* 2. Compare SAFI (using IANA values) */
				if (cmp == 0)
					cmp = (int)cur_iana_safi - (int)iana_safi;

				/* 3. Compare PeerType */
				if (cmp == 0)
					cmp = cur_peer_type - search_peer_type;

				/* 4. Compare PeerLen */
				if (cmp == 0)
					cmp = (int)cur_peer_len - (int)search_peer_len;

				/* 5. Compare PeerBytes */
				if (cmp == 0)
					cmp = memcmp(cur_peer_bytes, search_peer_bytes, cur_peer_len);

				/* 6. Compare PrefixLenBytes */
				if (cmp == 0)
					cmp = (int)cur_prefix_len_bytes - (int)search_prefix_len_bytes;

				/* 7. Compare PrefixBytes */
				if (cmp == 0)
					cmp = memcmp(cur_prefix_bytes, search_prefix_bytes, cur_prefix_len_bytes);

				/* 8. Compare PrefixBitLen */
				if (cmp == 0)
					cmp = cur_prefix_bitlen - search_prefix_bitlen;

				/* Skip if current <= search */
				if (cmp <= 0)
					continue;

				/* Current > search. Check if smaller than current min */
				if (!min_path) {
					/* First candidate */
					min_path = path;
					min_prefix = *rn_p;
					min_afi = cur_afi;
					min_safi = cur_safi;
					min_peer_type = cur_peer_type;
					min_peer_len = cur_peer_len;
					memcpy(min_peer_bytes, cur_peer_bytes, 16);
					min_prefix_len_bytes = cur_prefix_len_bytes;
					memcpy(min_prefix_bytes, cur_prefix_bytes, cur_prefix_len_bytes);
					min_prefix_bitlen = cur_prefix_bitlen;
				} else {
					/* Compare current with min (full tuple) using IANA AFI/SAFI */
					int min_cmp = 0;
					iana_afi_t min_iana_afi;
					iana_safi_t min_iana_safi;
					bgp_map_afi_safi_int2iana(min_afi, min_safi, &min_iana_afi, &min_iana_safi);

					if (min_cmp == 0)
						min_cmp = (int)cur_iana_afi - (int)min_iana_afi;
					if (min_cmp == 0)
						min_cmp = (int)cur_iana_safi - (int)min_iana_safi;
					if (min_cmp == 0)
						min_cmp = cur_peer_type - min_peer_type;
					if (min_cmp == 0)
						min_cmp = (int)cur_peer_len - (int)min_peer_len;
					if (min_cmp == 0)
						min_cmp = memcmp(cur_peer_bytes, min_peer_bytes, cur_peer_len);
					if (min_cmp == 0)
						min_cmp = (int)cur_prefix_len_bytes - (int)min_prefix_len_bytes;
					if (min_cmp == 0)
						min_cmp = memcmp(cur_prefix_bytes, min_prefix_bytes, cur_prefix_len_bytes);
					if (min_cmp == 0)
						min_cmp = cur_prefix_bitlen - min_prefix_bitlen;

					if (min_cmp < 0) {
						/* Current < min, update min */
						min_path = path;
						min_prefix = *rn_p;
						min_afi = cur_afi;
						min_safi = cur_safi;
						min_peer_type = cur_peer_type;
						min_peer_len = cur_peer_len;
						memcpy(min_peer_bytes, cur_peer_bytes, 16);
						min_prefix_len_bytes = cur_prefix_len_bytes;
						memcpy(min_prefix_bytes, cur_prefix_bytes, cur_prefix_len_bytes);
						min_prefix_bitlen = cur_prefix_bitlen;
					}
				}
			}
		}
	}

	if (min_path) {
		/* Encode the result OID */
		offset = name + namelen;

		/* Convert internal AFI/SAFI to IANA values for OID */
		iana_afi_t out_iana_afi;
		iana_safi_t out_iana_safi;
		bgp_map_afi_safi_int2iana(min_afi, min_safi, &out_iana_afi, &out_iana_safi);

		/* AFI (IANA value) */
		*offset++ = out_iana_afi;
		/* SAFI (IANA value) */
		*offset++ = out_iana_safi;

		/* PeerType */
		*offset++ = min_peer_type;

		/* PeerAddr: length + bytes */
		*offset++ = min_peer_len;
		for (size_t i = 0; i < min_peer_len; i++)
			*offset++ = min_peer_bytes[i];

		/* Prefix: length + bytes */
		*offset++ = min_prefix_len_bytes;
		for (size_t i = 0; i < min_prefix_len_bytes; i++)
			*offset++ = min_prefix_bytes[i];

		/* PrefixBitLen (CIDR bits) */
		*offset++ = min_prefix_bitlen;

		/* Total length: namelen + afi(1) + safi(1) + peerType(1) + peerLen(1) + peer + prefixLenBytes(1) + prefix + prefixBitLen(1) */
		*length = namelen + 1 + 1 + 1 + 1 + min_peer_len + 1 + min_prefix_len_bytes + 1;

		/* Return prefix info */
		*addr = min_prefix;

		return min_path;
	}

	return NULL;
}

/*
 * cbgpRouteTable handler
 * 
 * Handles all cbgpRouteTable columns including:
 * - INDEX columns (1-6): cbgpRouteAfi, cbgpRouteSafi, cbgpRoutePeerType,
 *                        cbgpRoutePeer, cbgpRouteAddrPrefix, cbgpRouteAddrPrefixLen
 * - Data columns (7-19): cbgpRouteOrigin, cbgpRouteAsPathSegment, etc.
 */
static uint8_t *cbgp4RouteTable(struct variable *v, oid name[], size_t *length,
                int exact, size_t *var_len,
                WriteMethod **write_method)
{
    struct bgp *bgp;
    struct bgp_path_info *path;
    struct prefix addr = {};

    bgp = bgp_get_default();
    if (!bgp)
        return NULL;

    if (smux_header_table(v, name, length, exact, var_len, write_method) ==
        MATCH_FAILED)
        return NULL;

    path = cbgp4RouteTable_lookup(v, name, length, bgp, &addr, exact);
    if (!path)
        return NULL;

    /* Safety check - ensure path has valid peer and attr */
    if (!path->peer || !path->attr)
        return NULL;

    switch (v->magic) {
    /* INDEX columns (1-6) - read-only implementation */
    case CBGP_ROUTE_AFI:
        /* Return IANA AFI from the OID index */
        /* Parse AFI directly from OID: name[namelen] = AFI */
        if (*length > v->namelen) {
            return SNMP_INTEGER(name[v->namelen]);
        }
        /* Fallback based on prefix family */
        if (addr.family == AF_INET)
            return SNMP_INTEGER(1);   /* IANA AFI IPv4 */
        else if (addr.family == AF_INET6)
            return SNMP_INTEGER(2);   /* IANA AFI IPv6 */
        else if (addr.family == AF_EVPN)
            return SNMP_INTEGER(25);  /* IANA AFI L2VPN */
        else
            return SNMP_INTEGER(1);   /* Default to IPv4 */

    case CBGP_ROUTE_SAFI:
        /* Return IANA SAFI from the OID index */
        /* Parse SAFI directly from OID: name[namelen+1] = SAFI */
        if (*length > (size_t)(v->namelen + 1)) {
            return SNMP_INTEGER(name[v->namelen + 1]);
        }
        /* Fallback based on prefix family */
        if (addr.family == AF_EVPN)
            return SNMP_INTEGER(70);  /* IANA SAFI EVPN */
        else
            return SNMP_INTEGER(1);   /* IANA SAFI unicast */

    case CBGP_ROUTE_PEER_TYPE:
        /* Return peer address type: 1=IPv4, 2=IPv6 */
        /* Self-originated routes use router-id (IPv4) */
        if (path->peer == path->peer->bgp->peer_self)
            return SNMP_INTEGER(1);  /* Router-ID is IPv4 */
        else if (sockunion_family(&path->peer->connection->su) == AF_INET)
            return SNMP_INTEGER(1);  /* IPv4 */
        else
            return SNMP_INTEGER(2);  /* IPv6 */

    case CBGP_ROUTE_PEER:
        /* Return peer IP address as OCTET STRING */
        /* Self-originated routes use router-id as peer address */
        if (path->peer == path->peer->bgp->peer_self) {
            memcpy(cbgp_route_octet_buf, &path->peer->bgp->router_id, 4);
            *var_len = 4;
        } else if (sockunion_family(&path->peer->connection->su) == AF_INET) {
            memcpy(cbgp_route_octet_buf, &path->peer->connection->su.sin.sin_addr, 4);
            *var_len = 4;
        } else {
            memcpy(cbgp_route_octet_buf, &path->peer->connection->su.sin6.sin6_addr, 16);
            *var_len = 16;
        }
        return cbgp_route_octet_buf;

    case CBGP_ROUTE_ADDR_PREFIX:
        /* Return prefix address as OCTET STRING */
        if (addr.family == AF_INET) {
            memcpy(cbgp_route_octet_buf, &addr.u.prefix4, 4);
            *var_len = 4;
        } else if (addr.family == AF_INET6) {
            memcpy(cbgp_route_octet_buf, &addr.u.prefix6, 16);
            *var_len = 16;
        } else if (addr.family == AF_EVPN) {
            /* Encode EVPN prefix into bytes */
            size_t evpn_len = encode_evpn_prefix(&addr, cbgp_route_octet_buf,
                                                  sizeof(cbgp_route_octet_buf));
            if (evpn_len == 0) {
                /* Fallback on encoding error */
                *var_len = 0;
                return cbgp_route_octet_buf;
            }
            *var_len = evpn_len;
        } else {
            /* Default to IPv4 */
            memcpy(cbgp_route_octet_buf, &addr.u.prefix4, 4);
            *var_len = 4;
        }
        return cbgp_route_octet_buf;

    case CBGP_ROUTE_ADDR_PREFIX_LEN:
        /* Return prefix length in bits */
        return SNMP_INTEGER(addr.prefixlen);

    /* Data columns (7-19) */
    case CBGP_ROUTE_ORIGIN:
        /* 1=igp, 2=egp, 3=incomplete */
        switch (path->attr->origin) {
        case BGP_ORIGIN_IGP:
            return SNMP_INTEGER(1);
        case BGP_ORIGIN_EGP:
            return SNMP_INTEGER(2);
        case BGP_ORIGIN_INCOMPLETE:
            return SNMP_INTEGER(3);
        default:
            return SNMP_INTEGER(0);
        }

    case CBGP_ROUTE_AS_PATH_SEGMENT:
        if (path->attr->aspath)
            return aspath_snmp_pathseg(path->attr->aspath, var_len);
        else {
            *var_len = 0;
            return NULL;
        }

    case CBGP_ROUTE_NEXT_HOP:
        switch (path->attr->mp_nexthop_len) {
        case BGP_ATTR_NHLEN_IPV4:
            return SNMP_IPADDRESS(path->attr->mp_nexthop_global_in);
        case BGP_ATTR_NHLEN_IPV6_GLOBAL:
            return SNMP_IP6ADDRESS(path->attr->mp_nexthop_global);
        case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
            if (CHECK_FLAG(path->attr->nh_flags,
                           BGP_ATTR_NH_MP_PREFER_GLOBAL))
                return SNMP_IP6ADDRESS(path->attr->mp_nexthop_global);
            else
                return SNMP_IP6ADDRESS(path->attr->mp_nexthop_local);
        default:
            return SNMP_IPADDRESS(path->attr->nexthop);
        }

    case CBGP_ROUTE_MED_PRESENT:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
            return SNMP_INTEGER(1); /* true */
        else
            return SNMP_INTEGER(2); /* false */

    case CBGP_ROUTE_MULTI_EXIT_DISC:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
            return SNMP_INTEGER(path->attr->med);
        else
            return SNMP_INTEGER(0);

    case CBGP_ROUTE_LOCAL_PREF_PRESENT:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
            return SNMP_INTEGER(1); /* true */
        else
            return SNMP_INTEGER(2); /* false */

    case CBGP_ROUTE_LOCAL_PREF:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
            return SNMP_INTEGER(path->attr->local_pref);
        else
            return SNMP_INTEGER(0);

    case CBGP_ROUTE_ATOMIC_AGGREGATE:
        /* 1=lessSpecificRouteNotSelected, 2=lessSpecificRouteSelected */
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
            return SNMP_INTEGER(1);
        else
            return SNMP_INTEGER(2);

    case CBGP_ROUTE_AGGREGATOR_AS:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))
            return SNMP_INTEGER(path->attr->aggregator_as);
        else
            return SNMP_INTEGER(0);

    case CBGP_ROUTE_AGGREGATOR_ADDR_TYPE:
        /* Aggregator address is always IPv4 per BGP spec */
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))
            return SNMP_INTEGER(1); /* ipv4 */
        else
            return SNMP_INTEGER(0); /* unknown */

    case CBGP_ROUTE_AGGREGATOR_ADDR:
        if (CHECK_FLAG(path->attr->flag,
                   ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))
            return SNMP_IPADDRESS(path->attr->aggregator_addr);
        else
            return SNMP_IPADDRESS(bgp_empty_addr);

    case CBGP_ROUTE_BEST:
        /* 1=true, 2=false */
        if (CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
            return SNMP_INTEGER(1);
        else
            return SNMP_INTEGER(2);

	case CBGP_ROUTE_UNKNOWN_ATTR: {
		static uint8_t transit_buf[512];
		struct transit *transit = bgp_attr_get_transit(path->attr);

		if (transit && transit->val && transit->length > 0) {
			*var_len = MIN(transit->length, sizeof(transit_buf));
			memcpy(transit_buf, transit->val, *var_len);
			return transit_buf;
		}
		*var_len = 0;
		return (uint8_t *)&bgp_empty_addr;
	}

    default:
        break;
    }

    return NULL;
}

/* cbgpNotifsEnable BITS { cbgpBackwardTransition(0),
 *   cbgpPrefixThresholdExceeded(1), cbgpPrefixThresholdClear(2) }
 * All notifications enabled by default.  BITS are encoded MSB-first:
 *   bit 0 → byte-0 bit-7, bit 1 → byte-0 bit-6, bit 2 → byte-0 bit-5
 *   → 0xE0.  Read-only in this implementation.
 */
static uint8_t cbgp_notifs_enable_bits[] = {0xE0};

static uint8_t *cbgpGlobalTable(struct variable *v, oid name[], size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct bgp *bgp;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	bgp = bgp_get_default();
	if (!bgp)
		return NULL;

	switch (v->magic) {
	case CBGP_LOCAL_AS:
		return SNMP_INTEGER(bgp->as);

	case CBGP_NOTIFS_ENABLE:
		*var_len = sizeof(cbgp_notifs_enable_bits);
		return cbgp_notifs_enable_bits;

	default:
		break;
	}
	return NULL;
}

/*
 * Capability table: reconstruct received capabilities from parsed peer state.
 * Each entry has (code, index, value, value_len). Index is 1-based per code.
 */
#define CBGP_CAP_MAX_ENTRIES 64
#define CBGP_CAP_MAX_VALUE   255

struct cbgp_cap_entry {
	uint8_t code;
	uint8_t index;
	uint8_t value[CBGP_CAP_MAX_VALUE];
	uint8_t value_len;
};

struct cbgp_cap_list {
	uint16_t count;
	struct cbgp_cap_entry entries[CBGP_CAP_MAX_ENTRIES];
};

static void cbgp4_build_cap_list(struct peer *peer, struct cbgp_cap_list *caps)
{
	uint16_t n = 0;
	afi_t afi;
	safi_t safi;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	memset(caps, 0, sizeof(*caps));

	/* MP (code 1): one entry per received AFI/SAFI */
	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->afc_recv[afi][safi] && n < CBGP_CAP_MAX_ENTRIES) {
			bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
						  &pkt_safi);
			caps->entries[n].code = CAPABILITY_CODE_MP;
			caps->entries[n].value[0] = (pkt_afi >> 8) & 0xff;
			caps->entries[n].value[1] = pkt_afi & 0xff;
			caps->entries[n].value[2] = 0;
			caps->entries[n].value[3] = pkt_safi & 0xff;
			caps->entries[n].value_len = 4;
			n++;
		}
	}

	/* Route Refresh (code 2) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = CAPABILITY_CODE_REFRESH;
		caps->entries[n].value_len = 0;
		n++;
	}

	/* Extended Nexthop (code 5) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_ENHE_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint8_t *val = caps->entries[n].value;
		uint8_t vlen = 0;

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ENHE_AF_RCV) &&
			    vlen + 6 <= CBGP_CAP_MAX_VALUE) {
				bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
							  &pkt_safi);
				val[vlen++] = (pkt_afi >> 8) & 0xff;
				val[vlen++] = pkt_afi & 0xff;
				val[vlen++] = (pkt_safi >> 8) & 0xff;
				val[vlen++] = pkt_safi & 0xff;
				val[vlen++] = 0;
				val[vlen++] = AFI_IP6;
			}
		}
		caps->entries[n].code = CAPABILITY_CODE_ENHE;
		caps->entries[n].value_len = vlen;
		n++;
	}

	/* Extended Message (code 6) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_EXTENDED_MESSAGE_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = CAPABILITY_CODE_EXT_MESSAGE;
		caps->entries[n].value_len = 0;
		n++;
	}

	/* Role (code 9) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_ROLE_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = CAPABILITY_CODE_ROLE;
		caps->entries[n].value[0] = peer->remote_role;
		caps->entries[n].value_len = 1;
		n++;
	}

	/* Graceful Restart (code 64) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint8_t *val = caps->entries[n].value;
		uint8_t vlen = 0;
		uint16_t flags_time = peer->v_gr_restart & 0x0FFF;

		if (CHECK_FLAG(peer->cap,
			       PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV))
			flags_time |= 0x8000;
		if (CHECK_FLAG(peer->cap,
			       PEER_CAP_GRACEFUL_RESTART_N_BIT_RCV))
			flags_time |= 0x4000;

		val[vlen++] = (flags_time >> 8) & 0xff;
		val[vlen++] = flags_time & 0xff;

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_RESTART_AF_RCV) &&
			    vlen + 4 <= CBGP_CAP_MAX_VALUE) {
				bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
							  &pkt_safi);
				val[vlen++] = (pkt_afi >> 8) & 0xff;
				val[vlen++] = pkt_afi & 0xff;
				val[vlen++] = pkt_safi & 0xff;
				val[vlen++] = CHECK_FLAG(
					peer->af_cap[afi][safi],
					PEER_CAP_RESTART_AF_PRESERVE_RCV)
						     ? 0x80
						     : 0;
			}
		}
		caps->entries[n].code = CAPABILITY_CODE_RESTART;
		caps->entries[n].value_len = vlen;
		n++;
	}

	/* 4-byte AS (code 65) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint32_t as4 = peer->as;

		caps->entries[n].code = CAPABILITY_CODE_AS4;
		caps->entries[n].value[0] = (as4 >> 24) & 0xff;
		caps->entries[n].value[1] = (as4 >> 16) & 0xff;
		caps->entries[n].value[2] = (as4 >> 8) & 0xff;
		caps->entries[n].value[3] = as4 & 0xff;
		caps->entries[n].value_len = 4;
		n++;
	}

	/* Dynamic (code 67) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = CAPABILITY_CODE_DYNAMIC;
		caps->entries[n].value_len = 0;
		n++;
	}

	/* Addpath (code 69) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_ADDPATH_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint8_t *val = caps->entries[n].value;
		uint8_t vlen = 0;

		FOREACH_AFI_SAFI (afi, safi) {
			uint8_t sr = 0;

			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ADDPATH_AF_TX_RCV))
				sr |= 0x01;
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ADDPATH_AF_RX_RCV))
				sr |= 0x02;
			if (sr && vlen + 4 <= CBGP_CAP_MAX_VALUE) {
				bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
							  &pkt_safi);
				val[vlen++] = (pkt_afi >> 8) & 0xff;
				val[vlen++] = pkt_afi & 0xff;
				val[vlen++] = pkt_safi & 0xff;
				val[vlen++] = sr;
			}
		}
		caps->entries[n].code = CAPABILITY_CODE_ADDPATH;
		caps->entries[n].value_len = vlen;
		n++;
	}

	/* Enhanced Route Refresh (code 70) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_ENHANCED_RR_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = CAPABILITY_CODE_ENHANCED_RR;
		caps->entries[n].value_len = 0;
		n++;
	}

	/* LLGR (code 71) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_LLGR_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint8_t *val = caps->entries[n].value;
		uint8_t vlen = 0;

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_LLGR_AF_RCV) &&
			    vlen + 7 <= CBGP_CAP_MAX_VALUE) {
				uint32_t st = peer->llgr[afi][safi].stale_time;

				bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
							  &pkt_safi);
				val[vlen++] = (pkt_afi >> 8) & 0xff;
				val[vlen++] = pkt_afi & 0xff;
				val[vlen++] = pkt_safi & 0xff;
				val[vlen++] = peer->llgr[afi][safi].flags;
				val[vlen++] = (st >> 16) & 0xff;
				val[vlen++] = (st >> 8) & 0xff;
				val[vlen++] = st & 0xff;
			}
		}
		caps->entries[n].code = CAPABILITY_CODE_LLGR;
		caps->entries[n].value_len = vlen;
		n++;
	}

	/* FQDN (code 73) */
	if (CHECK_FLAG(peer->cap, PEER_CAP_HOSTNAME_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		uint8_t *val = caps->entries[n].value;
		uint8_t vlen = 0;
		uint8_t hlen = peer->hostname
				      ? strnlen(peer->hostname, 64)
				      : 0;
		uint8_t dlen = peer->domainname
				      ? strnlen(peer->domainname, 64)
				      : 0;

		if (1 + hlen + 1 + dlen <= CBGP_CAP_MAX_VALUE) {
			val[vlen++] = hlen;
			if (hlen) {
				memcpy(&val[vlen], peer->hostname, hlen);
				vlen += hlen;
			}
			val[vlen++] = dlen;
			if (dlen) {
				memcpy(&val[vlen], peer->domainname, dlen);
				vlen += dlen;
			}
		}
		caps->entries[n].code = CAPABILITY_CODE_FQDN;
		caps->entries[n].value_len = vlen;
		n++;
	}

	/* Route Refresh Old/Cisco (code 128) - upstream unifies old/new */
	if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV) &&
	    n < CBGP_CAP_MAX_ENTRIES) {
		caps->entries[n].code = BGP_MSG_ROUTE_REFRESH_OLD;
		caps->entries[n].value_len = 0;
		n++;
	}

	/* Assign per-code indices (1-based) */
	caps->count = n;
	for (uint16_t i = 0; i < n; i++) {
		uint8_t idx = 1;

		for (uint16_t j = 0; j < i; j++) {
			if (caps->entries[j].code == caps->entries[i].code)
				idx++;
		}
		caps->entries[i].index = idx;
	}
}

static struct cbgp_cap_entry *cbgp4_cap_find(struct cbgp_cap_list *caps,
					     uint8_t code, uint8_t idx)
{
	for (uint16_t i = 0; i < caps->count; i++) {
		if (caps->entries[i].code == code &&
		    caps->entries[i].index == idx)
			return &caps->entries[i];
	}
	return NULL;
}

static struct cbgp_cap_entry *cbgp4_cap_next(struct cbgp_cap_list *caps,
					     uint8_t code, uint8_t idx)
{
	bool found = (code == 0 && idx == 0);

	for (uint16_t i = 0; i < caps->count; i++) {
		if (found)
			return &caps->entries[i];
		if (caps->entries[i].code == code &&
		    caps->entries[i].index == idx)
			found = true;
	}
	return NULL;
}

/*
 * cbgpPeerCapsTable handler (legacy IPv4 peers).
 * INDEX: bgpPeerRemoteAddr(4) + capCode(1) + capIndex(1)
 */
static uint8_t *cbgp4PeerCapsTable(struct variable *v, oid name[],
				   size_t *length, int exact, size_t *var_len,
				   WriteMethod **write_method)
{
	static uint8_t cap_val_peer[CBGP_CAP_MAX_VALUE];
	struct peer *peer;
	struct cbgp_cap_list caps;
	struct cbgp_cap_entry *ent;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct ipaddr addr = {};
	uint8_t cap_code = 0, cap_idx = 0;

	if (smux_header_table(v, name, length, exact, var_len, write_method) ==
	    MATCH_FAILED)
		return NULL;

	if (offsetlen >= IN_ADDR_SIZE + 2) {
		addr.ipa_type = AF_INET;
		oid2in_addr(index, IN_ADDR_SIZE, &addr.ip._v4_addr);
		cap_code = index[IN_ADDR_SIZE];
		cap_idx = index[IN_ADDR_SIZE + 1];
	} else if (offsetlen >= IN_ADDR_SIZE) {
		addr.ipa_type = AF_INET;
		oid2in_addr(index, IN_ADDR_SIZE, &addr.ip._v4_addr);
	} else if (!offsetlen) {
		for (size_t i = 0; i < IN_ADDR_SIZE + 2; i++)
			*(index + i) = 0;
	} else {
		return NULL;
	}

	if (exact) {
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);
		if (!peer)
			return NULL;
		cbgp4_build_cap_list(peer, &caps);
		ent = cbgp4_cap_find(&caps, cap_code, cap_idx);
		if (!ent)
			return NULL;
	} else {
		if (!offsetlen)
			peer = bgp_snmp_get_first_peer(false, AF_UNSPEC);
		else
			peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

		ent = NULL;
		while (peer) {
			if (sockunion_family(&peer->connection->su) != AF_INET) {
				peer = bgp_snmp_get_next_peer(
					false, VRF_DEFAULT, AF_INET, &addr);
				continue;
			}
			cbgp4_build_cap_list(peer, &caps);
			ent = cbgp4_cap_next(&caps, cap_code, cap_idx);
			if (ent)
				break;
			addr.ipa_type = AF_INET;
			addr.ip._v4_addr = peer->connection->su.sin.sin_addr;
			peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT,
						      AF_INET, &addr);
			cap_code = 0;
			cap_idx = 0;
		}

		if (!peer || !ent)
			return NULL;

		oid_copy_in_addr(index, &peer->connection->su.sin.sin_addr);
		index[IN_ADDR_SIZE] = ent->code;
		index[IN_ADDR_SIZE + 1] = ent->index;
		*length = namelen + IN_ADDR_SIZE + 2;
	}

	switch (v->magic) {
	case CBGP_PEER_CAP_VALUE:
		*var_len = ent->value_len;
		if (ent->value_len)
			memcpy(cap_val_peer, ent->value, ent->value_len);
		return cap_val_peer;
	default:
		break;
	}
	return NULL;
}

/*
 * cbgpPeer2CapsTable handler (IPv4/IPv6 peers).
 * INDEX: addrType(1) + addr(4|16) + capCode(1) + capIndex(1)
 */
static uint8_t *cbgp4Peer2CapsTable(struct variable *v, oid name[],
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	static uint8_t cap_val_peer2[CBGP_CAP_MAX_VALUE];
	struct peer *peer;
	struct cbgp_cap_list caps;
	struct cbgp_cap_entry *ent;
	size_t namelen = v ? v->namelen : CBGP_PEER_TABLE_INDEX_OFFSET;
	oid *index = name + namelen;
	size_t offsetlen = *length - namelen;
	struct ipaddr addr = {};
	uint8_t cap_code = 0, cap_idx = 0;
	int addr_len;

	if (smux_header_table(v, name, length, exact, var_len, write_method) ==
	    MATCH_FAILED)
		return NULL;

	if (offsetlen >= IN_ADDR_SIZE + 3 || offsetlen >= IN6_ADDR_SIZE + 3) {
		addr.ipa_type = index[0] == 1 ? AF_INET : AF_INET6;
		if (addr.ipa_type == AF_INET && offsetlen >= IN_ADDR_SIZE + 3) {
			oid2in_addr(&index[1], IN_ADDR_SIZE, &addr.ip._v4_addr);
			cap_code = index[IN_ADDR_SIZE + 1];
			cap_idx = index[IN_ADDR_SIZE + 2];
		} else if (addr.ipa_type == AF_INET6 &&
			   offsetlen >= IN6_ADDR_SIZE + 3) {
			oid2in6_addr(&index[1], &addr.ip._v6_addr);
			cap_code = index[IN6_ADDR_SIZE + 1];
			cap_idx = index[IN6_ADDR_SIZE + 2];
		}
	} else if (offsetlen >= IN_ADDR_SIZE + 1 ||
		   offsetlen >= IN6_ADDR_SIZE + 1) {
		addr.ipa_type = index[0] == 1 ? AF_INET : AF_INET6;
		if (addr.ipa_type == AF_INET)
			oid2in_addr(&index[1], IN_ADDR_SIZE, &addr.ip._v4_addr);
		else
			oid2in6_addr(&index[1], &addr.ip._v6_addr);
	} else if (!offsetlen) {
		for (size_t i = 0; i < IN6_ADDR_SIZE + 3; i++)
			*(index + i) = 0;
	} else {
		return NULL;
	}

	if (exact) {
		peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);
		if (!peer)
			return NULL;
		cbgp4_build_cap_list(peer, &caps);
		ent = cbgp4_cap_find(&caps, cap_code, cap_idx);
		if (!ent)
			return NULL;
	} else {
		if (!offsetlen)
			peer = bgp_snmp_get_first_peer(false, AF_UNSPEC);
		else
			peer = bgp_snmp_lookup_peer(VRF_DEFAULT, &addr);

		ent = NULL;
		while (peer) {
			cbgp4_build_cap_list(peer, &caps);
			ent = cbgp4_cap_next(&caps, cap_code, cap_idx);
			if (ent)
				break;
			peer = bgp_snmp_get_next_peer(false, VRF_DEFAULT,
						      AF_UNSPEC, &addr);
			if (peer) {
				switch (sockunion_family(&peer->connection->su)) {
				case AF_INET:
					addr.ipa_type = AF_INET;
					addr.ip._v4_addr =
						peer->connection->su.sin.sin_addr;
					break;
				case AF_INET6:
					addr.ipa_type = AF_INET6;
					addr.ip._v6_addr =
						peer->connection->su.sin6.sin6_addr;
					break;
				default:
					continue;
				}
			}
			cap_code = 0;
			cap_idx = 0;
		}

		if (!peer || !ent)
			return NULL;

		addr_len = cbgp4_build_peer2_index(peer, index);
		if (!addr_len)
			return NULL;
		index[addr_len] = ent->code;
		index[addr_len + 1] = ent->index;
		*length = namelen + addr_len + 2;
	}

	switch (v->magic) {
	case CBGP_PEER2_CAP_VALUE:
		*var_len = ent->value_len;
		if (ent->value_len)
			memcpy(cap_val_peer2, ent->value, ent->value_len);
		return cap_val_peer2;
	default:
		break;
	}
	return NULL;
}


static struct variable cbgp4_variables[] = {
	/* cbgpGlobal scalars */
	{ CBGP_NOTIFS_ENABLE,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgpGlobalTable,
	  3,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_GLOBAL, CBGP_NOTIFS_ENABLE } },

	{ CBGP_LOCAL_AS,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgpGlobalTable,
	  3,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_GLOBAL, CBGP_LOCAL_AS } },

	/* cbgp4PeerTable */
	{ CBGP_PEER_PREFIX_ACCEPTED,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_ACCEPTED } },

	{ CBGP_PEER_PREFIX_DENIED,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_DENIED } },

	{ CBGP_PEER_PREFIX_LIMIT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_LIMIT } },

	{ CBGP_PEER_PREFIX_ADVERTISED,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_ADVERTISED } },

	{ CBGP_PEER_PREFIX_SUPPRESSED,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_SUPPRESSED } },

	{ CBGP_PEER_PREFIX_WITHDRAWN,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_WITHDRAWN } },

	{ CBGP_PEER_LAST_ERROR_TXT,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_LAST_ERROR_TXT } },

	{ CBGP_PEER_PREV_STATE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREV_STATE } },

	/* cbgpPeerCapsTable */
	{ CBGP_PEER_CAP_VALUE,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4PeerCapsTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_CAPS_TABLE,
	    CBGP_PEER_CAPS_ENTRY, CBGP_PEER_CAP_VALUE } },

	/* cbgp4PeerAddrFamilyTable */
	{ CBGP_PEER_ADDR_FAMILY_AFI,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerAddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_TABLE,
	    CBGP_PEER_ADDR_FAMILY_ENTRY, CBGP_PEER_ADDR_FAMILY_AFI } },

	{ CBGP_PEER_ADDR_FAMILY_SAFI,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerAddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_TABLE,
	    CBGP_PEER_ADDR_FAMILY_ENTRY, CBGP_PEER_ADDR_FAMILY_SAFI } },

	{ CBGP_PEER_ADDR_FAMILY_NAME,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4PeerAddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_TABLE,
	    CBGP_PEER_ADDR_FAMILY_ENTRY, CBGP_PEER_ADDR_FAMILY_NAME } },

	/* cbgp4PeerAddrFamilyPrefixTable */
	{ CBGP_PEER_ACCEPTED_PREFIXES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_ACCEPTED_PREFIXES } },

	{ CBGP_PEER_DENIED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_DENIED_PREFIXES } },

	{ CBGP_PEER_PREFIX_ADMIN_LIMIT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_ADMIN_LIMIT } },

	{ CBGP_PEER_PREFIX_THRESHOLD,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_THRESHOLD } },

	{ CBGP_PEER_PREFIX_CLEAR_THRESHOLD,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_CLEAR_THRESHOLD } },

	{ CBGP_PEER_ADVERTISED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_ADVERTISED_PREFIXES } },

	{ CBGP_PEER_SUPPRESSED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_SUPPRESSED_PREFIXES } },

	{ CBGP_PEER_WITHDRAWN_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4PeerAddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_WITHDRAWN_PREFIXES } },

	/* cbgp4Peer2Table */
	{ CBGP_PEER2_TYPE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_TYPE } },

	{ CBGP_PEER2_REMOTE_PORT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_REMOTE_PORT } },

	{ CBGP_PEER2_REMOTE_AS,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_REMOTE_AS } },

	{ CBGP_PEER2_REMOTE_IDENTIFIER,
	  ASN_IPADDRESS,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_REMOTE_IDENTIFIER } },

	{ CBGP_PEER2_IN_UPDATES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_IN_UPDATES } },

	{ CBGP_PEER2_OUT_UPDATES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_OUT_UPDATES } },

	{ CBGP_PEER2_IN_TOTAL_MESSAGES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_IN_TOTAL_MESSAGES } },

	{ CBGP_PEER2_OUT_TOTAL_MESSAGES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_OUT_TOTAL_MESSAGES } },

	{ CBGP_PEER2_LAST_ERROR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LAST_ERROR } },

	{ CBGP_PEER2_FSM_ESTABLISHED_TRANSITIONS,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_FSM_ESTABLISHED_TRANSITIONS } },

	{ CBGP_PEER2_FSM_ESTABLISHED_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_FSM_ESTABLISHED_TIME } },

	{ CBGP_PEER2_REMOTE_ADDR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_REMOTE_ADDR } },

	{ CBGP_PEER2_CONNECT_RETRY_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_CONNECT_RETRY_INTERVAL } },

	{ CBGP_PEER2_HOLD_TIME,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_HOLD_TIME } },

	{ CBGP_PEER2_KEEP_ALIVE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_KEEP_ALIVE } },

	{ CBGP_PEER2_HOLD_TIME_CONFIGURED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_HOLD_TIME_CONFIGURED } },

	{ CBGP_PEER2_KEEP_ALIVE_CONFIGURED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_KEEP_ALIVE_CONFIGURED } },

	{ CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL } },

	{ CBGP_PEER2_MIN_ROUTE_ADVERTISEMENT_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_MIN_ROUTE_ADVERTISEMENT_INTERVAL } },

	{ CBGP_PEER2_IN_UPDATE_ELAPSED_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_IN_UPDATE_ELAPSED_TIME } },

	{ CBGP_PEER2_LAST_ERROR_TXT,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LAST_ERROR_TXT } },

	{ CBGP_PEER2_PREV_STATE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_PREV_STATE } },

	{ CBGP_PEER2_STATE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_STATE } },

	{ CBGP_PEER2_ADMIN_STATUS,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_ADMIN_STATUS } },

	{ CBGP_PEER2_NEGOTIATED_VERSION,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_NEGOTIATED_VERSION } },

	{ CBGP_PEER2_LOCAL_ADDR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LOCAL_ADDR } },

	{ CBGP_PEER2_LOCAL_PORT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LOCAL_PORT } },

	{ CBGP_PEER2_LOCAL_AS,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LOCAL_AS } },

	{ CBGP_PEER2_LOCAL_IDENTIFIER,
	  ASN_IPADDRESS,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LOCAL_IDENTIFIER } },

	/* cbgpPeer2CapsTable */
	{ CBGP_PEER2_CAP_VALUE,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2CapsTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_CAPS_TABLE,
	    CBGP_PEER2_CAPS_ENTRY, CBGP_PEER2_CAP_VALUE } },

	/* cbgp4Peer2AddrFamilyTable */
	{ CBGP_PEER2_ADDR_FAMILY_AFI,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2AddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_ENTRY, CBGP_PEER2_ADDR_FAMILY_AFI } },

	{ CBGP_PEER2_ADDR_FAMILY_SAFI,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer2AddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_ENTRY, CBGP_PEER2_ADDR_FAMILY_SAFI } },

	{ CBGP_PEER2_ADDR_FAMILY_NAME,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2AddrFamilyTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_ENTRY, CBGP_PEER2_ADDR_FAMILY_NAME } },

	/* cbgp4Peer2AddrFamilyPrefixTable */
	{ CBGP_PEER2_ACCEPTED_PREFIXES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_ACCEPTED_PREFIXES } },

	{ CBGP_PEER2_DENIED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_DENIED_PREFIXES } },

	{ CBGP_PEER2_PREFIX_ADMIN_LIMIT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_PREFIX_ADMIN_LIMIT } },

	{ CBGP_PEER2_PREFIX_THRESHOLD,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_PREFIX_THRESHOLD } },

	{ CBGP_PEER2_PREFIX_CLEAR_THRESHOLD,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_PREFIX_CLEAR_THRESHOLD } },

	{ CBGP_PEER2_ADVERTISED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_ADVERTISED_PREFIXES } },

	{ CBGP_PEER2_SUPPRESSED_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_SUPPRESSED_PREFIXES } },

	{ CBGP_PEER2_WITHDRAWN_PREFIXES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2AddrFamilyPrefixTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	    CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_WITHDRAWN_PREFIXES } },


	/* cbgp4Peer3Table */
	{ CBGP_PEER3_VRF_ID,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_VRF_ID } },

	{ CBGP_PEER3_LOCAL_AS,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LOCAL_AS } },

	{ CBGP_PEER3_LOCAL_IDENTIFIER,
	  ASN_IPADDRESS,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LOCAL_IDENTIFIER } },

	{ CBGP_PEER3_REMOTE_PORT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_REMOTE_PORT } },

	{ CBGP_PEER3_REMOTE_AS,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_REMOTE_AS } },

	{ CBGP_PEER3_REMOTE_IDENTIFIER,
	  ASN_IPADDRESS,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_REMOTE_IDENTIFIER } },

	{ CBGP_PEER3_IN_UPDATES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_IN_UPDATES } },

	{ CBGP_PEER3_OUT_UPDATES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_OUT_UPDATES } },

	{ CBGP_PEER3_IN_TOTAL_MESSAGES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_IN_TOTAL_MESSAGES } },

	{ CBGP_PEER3_OUT_TOTAL_MESSAGES,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_OUT_TOTAL_MESSAGES } },

	{ CBGP_PEER3_LAST_ERROR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LAST_ERROR } },

	{ CBGP_PEER3_TYPE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_TYPE } },

	{ CBGP_PEER3_FSM_ESTABLISHED_TRANSITIONS,
	  ASN_COUNTER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_FSM_ESTABLISHED_TRANSITIONS } },

	{ CBGP_PEER3_FSM_ESTABLISHED_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_FSM_ESTABLISHED_TIME } },

	{ CBGP_PEER3_CONNECT_RETRY_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_CONNECT_RETRY_INTERVAL } },

	{ CBGP_PEER3_HOLD_TIME,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_HOLD_TIME } },

	{ CBGP_PEER3_KEEP_ALIVE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_KEEP_ALIVE } },

	{ CBGP_PEER3_HOLD_TIME_CONFIGURED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_HOLD_TIME_CONFIGURED } },

	{ CBGP_PEER3_KEEP_ALIVE_CONFIGURED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_KEEP_ALIVE_CONFIGURED } },

	{ CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL } },

	{ CBGP_PEER3_MIN_ROUTE_ADVERTISEMENT_INTERVAL,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_MIN_ROUTE_ADVERTISEMENT_INTERVAL } },

	{ CBGP_PEER3_IN_UPDATE_ELAPSED_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_IN_UPDATE_ELAPSED_TIME } },

	{ CBGP_PEER3_REMOTE_ADDR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_REMOTE_ADDR } },

	{ CBGP_PEER3_LAST_ERROR_TXT,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LAST_ERROR_TXT } },

	{ CBGP_PEER3_PREV_STATE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_PREV_STATE } },

	{ CBGP_PEER3_VRF_NAME,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_VRF_NAME } },

	{ CBGP_PEER3_STATE,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_STATE } },


	{ CBGP_PEER3_ADMIN_STATUS,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_ADMIN_STATUS } },

	{ CBGP_PEER3_NEGOTIATED_VERSION,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_NEGOTIATED_VERSION } },

	{ CBGP_PEER3_LOCAL_ADDR,
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LOCAL_ADDR } },

	{ CBGP_PEER3_LOCAL_PORT,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_LOCAL_PORT } },
	/* cbgpRouteTable - OID .1.3.6.1.4.1.9.9.187.1.1.1.1
	 * 
	 * INDEX columns (1-6) - normally not-accessible in MIB, but implemented
	 * as read-only for compatibility with some SNMP managers
	 */
    {CBGP_ROUTE_AFI,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_AFI}},

    {CBGP_ROUTE_SAFI,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_SAFI}},

    {CBGP_ROUTE_PEER_TYPE,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_PEER_TYPE}},

    {CBGP_ROUTE_PEER,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_PEER}},

    {CBGP_ROUTE_ADDR_PREFIX,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_ADDR_PREFIX}},

    {CBGP_ROUTE_ADDR_PREFIX_LEN,
     ASN_UNSIGNED,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_ADDR_PREFIX_LEN}},

	/* Data columns (7-19) */
    {CBGP_ROUTE_ORIGIN,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_ORIGIN}},

    {CBGP_ROUTE_AS_PATH_SEGMENT,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_AS_PATH_SEGMENT}},

    {CBGP_ROUTE_NEXT_HOP,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_NEXT_HOP}},

    {CBGP_ROUTE_MED_PRESENT,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_MED_PRESENT}},

    {CBGP_ROUTE_MULTI_EXIT_DISC,
     ASN_UNSIGNED,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_MULTI_EXIT_DISC}},

    {CBGP_ROUTE_LOCAL_PREF_PRESENT,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_LOCAL_PREF_PRESENT}},

    {CBGP_ROUTE_LOCAL_PREF,
     ASN_UNSIGNED,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_LOCAL_PREF}},

    {CBGP_ROUTE_ATOMIC_AGGREGATE,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_ATOMIC_AGGREGATE}},

    {CBGP_ROUTE_AGGREGATOR_AS,
     ASN_UNSIGNED,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_AGGREGATOR_AS}},

    {CBGP_ROUTE_AGGREGATOR_ADDR_TYPE,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_AGGREGATOR_ADDR_TYPE}},

    {CBGP_ROUTE_AGGREGATOR_ADDR,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_AGGREGATOR_ADDR}},

    {CBGP_ROUTE_BEST,
     ASN_INTEGER,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_BEST}},

    {CBGP_ROUTE_UNKNOWN_ATTR,
     ASN_OCTET_STR,
     RONLY,
     cbgp4RouteTable,
     5,
     {CISCO_BGP4_MIB_OBJECTS, CBGP_ROUTE, CBGP_ROUTE_TABLE, CBGP_ROUTE_ENTRY,
      CBGP_ROUTE_UNKNOWN_ATTR}},
};

/*
 * Send legacy cbgpFsmStateChange (1) or cbgpBackwardTransition (2) traps.
 * These notifications include varbinds from both BGP4-MIB and CISCO-BGP4-MIB,
 * so we construct the varbinds manually via send_v2trap.
 *
 * OBJECTS for both notifications:
 *   bgpPeerLastError     (BGP4-MIB 1.3.6.1.2.1.15.3.1.14)
 *   bgpPeerState         (BGP4-MIB 1.3.6.1.2.1.15.3.1.2)
 *   cbgpPeerLastErrorTxt (CISCO-BGP4-MIB .1.2.1.1.7)
 *   cbgpPeerPrevState    (CISCO-BGP4-MIB .1.2.1.1.8)
 */
static void cbgp4_send_legacy_trap(struct peer *peer, uint8_t trap_type)
{
	int ret;
	struct in_addr addr;
	netsnmp_variable_list *vars = NULL;

	oid snmptrap_oid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
	size_t snmptrap_oid_len = sizeof(snmptrap_oid) / sizeof(oid);

	oid notif_oid[] = {CBGP4MIB, CBGP_NOTIFY_PREFIX, 0};
	size_t notif_oid_len = sizeof(notif_oid) / sizeof(oid);

	if (sockunion_family(&peer->connection->su) != AF_INET)
		return;

	ret = inet_aton(peer->host, &addr);
	if (ret == 0)
		return;

	notif_oid[notif_oid_len - 1] = trap_type;

	snmp_varlist_add_variable(&vars, snmptrap_oid, snmptrap_oid_len,
				  ASN_OBJECT_ID, (uint8_t *)notif_oid,
				  notif_oid_len * sizeof(oid));

	/* bgpPeerLastError.<peerAddr> from BGP4-MIB */
	{
		oid vb_oid[] = {1, 3, 6, 1, 2, 1, 15, 3, 1, 14,
				0, 0, 0, 0};
		size_t vb_oid_len = sizeof(vb_oid) / sizeof(oid);
		uint8_t last_error[2] = {0, 0};

		oid_copy_in_addr(&vb_oid[10], &addr);
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			last_error[0] = peer->notify.code;
			last_error[1] = peer->notify.subcode;
		}
		snmp_varlist_add_variable(&vars, vb_oid, vb_oid_len,
					  ASN_OCTET_STR, last_error,
					  sizeof(last_error));
	}

	/* bgpPeerState.<peerAddr> from BGP4-MIB */
	{
		oid vb_oid[] = {1, 3, 6, 1, 2, 1, 15, 3, 1, 2,
				0, 0, 0, 0};
		size_t vb_oid_len = sizeof(vb_oid) / sizeof(oid);
		long state = peer->connection->status;

		oid_copy_in_addr(&vb_oid[10], &addr);
		snmp_varlist_add_variable(&vars, vb_oid, vb_oid_len,
					  ASN_INTEGER, (uint8_t *)&state,
					  sizeof(state));
	}

	/* cbgpPeerLastErrorTxt.<peerAddr> from CISCO-BGP4-MIB */
	{
		oid vb_oid[] = {CBGP4MIB, CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
				CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
				CBGP_PEER_LAST_ERROR_TXT, 0, 0, 0, 0};
		size_t vb_oid_len = sizeof(vb_oid) / sizeof(oid);
		const char *error_txt = "";
		char msg_buf[255];

		oid_copy_in_addr(&vb_oid[vb_oid_len - IN_ADDR_SIZE], &addr);
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED &&
		    peer->notify.code == BGP_NOTIFY_CEASE &&
		    (peer->notify.subcode ==
			     BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN ||
		     peer->notify.subcode ==
			     BGP_NOTIFY_CEASE_ADMIN_RESET)) {
			error_txt = bgp_notify_admin_message(
				msg_buf, sizeof(msg_buf),
				(uint8_t *)peer->notify.data,
				peer->notify.length);
		}
		snmp_varlist_add_variable(&vars, vb_oid, vb_oid_len,
					  ASN_OCTET_STR,
					  (const uint8_t *)error_txt,
					  strlen(error_txt));
	}

	/* cbgpPeerPrevState.<peerAddr> from CISCO-BGP4-MIB */
	{
		oid vb_oid[] = {CBGP4MIB, CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
				CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
				CBGP_PEER_PREV_STATE, 0, 0, 0, 0};
		size_t vb_oid_len = sizeof(vb_oid) / sizeof(oid);
		long prev_state = peer->connection->ostatus;

		oid_copy_in_addr(&vb_oid[vb_oid_len - IN_ADDR_SIZE], &addr);
		snmp_varlist_add_variable(&vars, vb_oid, vb_oid_len,
					  ASN_INTEGER,
					  (uint8_t *)&prev_state,
					  sizeof(prev_state));
	}

	send_v2trap(vars);
	snmp_free_varbind(vars);
	smux_events_update();
}

/*
 * Hook callback for peer_status_changed.
 * Fires on every BGP FSM state change.
 *
 * Sends:
 *   cbgpFsmStateChange (1)                 - legacy IPv4, every change
 *   cbgpPeer2FsmStateChange (7)            - IPv4/IPv6, every change
 *   cbgpPeer2EstablishedNotification (5)   - IPv4/IPv6, OpenConfirm→Established
 */
int cbgpPeerStatusChanged(struct peer *peer)
{
	oid index[sizeof(oid) * (IN6_ADDR_SIZE + 1)];
	int index_len;

	if (!smux_enabled())
		return 0;

	cbgp4_send_legacy_trap(peer, CBGP_FSM_STATE_CHANGE);

	index_len = cbgp4_build_peer2_index(peer, index);
	if (!index_len)
		return 0;

	smux_trap(cbgp4_variables, array_size(cbgp4_variables),
		  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
		  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
		  index, index_len,
		  cbgpPeer2FsmTrapList, array_size(cbgpPeer2FsmTrapList),
		  CBGP_PEER2_FSM_STATE_CHANGE);

	if ((peer->connection->ostatus == OpenConfirm) && peer_established(peer->connection))
		smux_trap(cbgp4_variables, array_size(cbgp4_variables),
			  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
			  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
			  index, index_len,
			  cbgpPeer2TrapList, array_size(cbgpPeer2TrapList),
			  CBGP_PEER2_ESTABLISHED_NOTIFICATION);

	return 0;
}

/*
 * Hook callback for peer_backward_transition.
 * Fires when BGP FSM transitions from Established to a lower state.
 *
 * Sends:
 *   cbgpBackwardTransition (2)               - legacy IPv4
 *   cbgpPeer2BackwardTransNotification (6)   - IPv4/IPv6
 *   cbgpPeer2BackwardTransition (8)          - IPv4/IPv6
 */
int cbgpPeerBackwardTransition(struct peer *peer)
{
	oid index[sizeof(oid) * (IN6_ADDR_SIZE + 1)];
	int index_len;

	if (!smux_enabled())
		return 0;

	cbgp4_send_legacy_trap(peer, CBGP_BACKWARD_TRANSITION);

	index_len = cbgp4_build_peer2_index(peer, index);
	if (!index_len)
		return 0;

	smux_trap(cbgp4_variables, array_size(cbgp4_variables),
		  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
		  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
		  index, index_len,
		  cbgpPeer2TrapList, array_size(cbgpPeer2TrapList),
		  CBGP_PEER2_BACKWARD_TRANS_NOTIFICATION);

	smux_trap(cbgp4_variables, array_size(cbgp4_variables),
		  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
		  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
		  index, index_len,
		  cbgpPeer2FsmTrapList, array_size(cbgpPeer2FsmTrapList),
		  CBGP_PEER2_BACKWARD_TRANSITION);

	return 0;
}

/*
 * Trap objects for cbgpPrefixThresholdExceeded (3)
 * OBJECTS: cbgpPeerPrefixAdminLimit, cbgpPeerPrefixThreshold
 */
static struct trap_object cbgpPfxThreshExceededTrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_ADMIN_LIMIT}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_THRESHOLD}},
};

/*
 * Trap objects for cbgpPrefixThresholdClear (4)
 * OBJECTS: cbgpPeerPrefixAdminLimit, cbgpPeerPrefixClearThreshold
 */
static struct trap_object cbgpPfxThreshClearTrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER_PREFIX_ADMIN_LIMIT}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER_ADDR_FAMILY_PREFIX_ENTRY,
	     CBGP_PEER_PREFIX_CLEAR_THRESHOLD}},
};

/*
 * Trap objects for cbgpPeer2PrefixThresholdExceeded (9)
 * OBJECTS: cbgpPeer2PrefixAdminLimit, cbgpPeer2PrefixThreshold
 */
static struct trap_object cbgpPeer2PfxThreshExceededTrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY,
	     CBGP_PEER2_PREFIX_ADMIN_LIMIT}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY, CBGP_PEER2_PREFIX_THRESHOLD}},
};

/*
 * Trap objects for cbgpPeer2PrefixThresholdClear (10)
 * OBJECTS: cbgpPeer2PrefixAdminLimit, cbgpPeer2PrefixClearThreshold
 */
static struct trap_object cbgpPeer2PfxThreshClearTrapList[] = {
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY,
	     CBGP_PEER2_PREFIX_ADMIN_LIMIT}},
	{5, {CISCO_BGP4_MIB_OBJECTS, CBGP_PEER,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_TABLE,
	     CBGP_PEER2_ADDR_FAMILY_PREFIX_ENTRY,
	     CBGP_PEER2_PREFIX_CLEAR_THRESHOLD}},
};

int cbgpPrefixThresholdExceeded(struct peer *peer, afi_t afi, safi_t safi)
{
	oid index[sizeof(oid) * (IN6_ADDR_SIZE + 3)];
	int index_len;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	if (!smux_enabled())
		return 0;

	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	/* Legacy trap (3) - IPv4 peers only */
	if (sockunion_family(&peer->connection->su) == AF_INET) {
		oid legacy_index[IN_ADDR_SIZE + 2];

		oid_copy_in_addr(legacy_index, &peer->connection->su.sin.sin_addr);
		legacy_index[IN_ADDR_SIZE] = pkt_afi;
		legacy_index[IN_ADDR_SIZE + 1] = pkt_safi;

		smux_trap(cbgp4_variables, array_size(cbgp4_variables),
			  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
			  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
			  legacy_index, IN_ADDR_SIZE + 2,
			  cbgpPfxThreshExceededTrapList,
			  array_size(cbgpPfxThreshExceededTrapList),
			  CBGP_PREFIX_THRESHOLD_EXCEEDED);
	}

	/* Peer2 trap (9) - all peers */
	index_len = cbgp4_build_peer2_index(peer, index);
	if (!index_len)
		return 0;
	index[index_len] = pkt_afi;
	index[index_len + 1] = pkt_safi;
	index_len += 2;

	smux_trap(cbgp4_variables, array_size(cbgp4_variables),
		  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
		  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
		  index, index_len,
		  cbgpPeer2PfxThreshExceededTrapList,
		  array_size(cbgpPeer2PfxThreshExceededTrapList),
		  CBGP_PEER2_PREFIX_THRESHOLD_EXCEEDED);

	return 0;
}

int cbgpPrefixThresholdClear(struct peer *peer, afi_t afi, safi_t safi)
{
	oid index[sizeof(oid) * (IN6_ADDR_SIZE + 3)];
	int index_len;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	if (!smux_enabled())
		return 0;

	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	/* Legacy trap (4) - IPv4 peers only */
	if (sockunion_family(&peer->connection->su) == AF_INET) {
		oid legacy_index[IN_ADDR_SIZE + 2];

		oid_copy_in_addr(legacy_index, &peer->connection->su.sin.sin_addr);
		legacy_index[IN_ADDR_SIZE] = pkt_afi;
		legacy_index[IN_ADDR_SIZE + 1] = pkt_safi;

		smux_trap(cbgp4_variables, array_size(cbgp4_variables),
			  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
			  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
			  legacy_index, IN_ADDR_SIZE + 2,
			  cbgpPfxThreshClearTrapList,
			  array_size(cbgpPfxThreshClearTrapList),
			  CBGP_PREFIX_THRESHOLD_CLEAR);
	}

	/* Peer2 trap (10) - all peers */
	index_len = cbgp4_build_peer2_index(peer, index);
	if (!index_len)
		return 0;
	index[index_len] = pkt_afi;
	index[index_len + 1] = pkt_safi;
	index_len += 2;

	smux_trap(cbgp4_variables, array_size(cbgp4_variables),
		  cbgp4_trap_oid, array_size(cbgp4_trap_oid),
		  cbgp4_oid, sizeof(cbgp4_oid) / sizeof(oid),
		  index, index_len,
		  cbgpPeer2PfxThreshClearTrapList,
		  array_size(cbgpPeer2PfxThreshClearTrapList),
		  CBGP_PEER2_PREFIX_THRESHOLD_CLEAR);

	return 0;
}

int bgp_snmp_cbgp4_init(struct event_loop *tm)
{
	REGISTER_MIB("mibI/cbgp4", cbgp4_variables, variable, cbgp4_oid);
	return 0;
}
