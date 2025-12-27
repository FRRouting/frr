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

SNMP_LOCAL_VARIABLES

static oid cbgp4_oid[] = { CBGP4MIB };
static struct in_addr bgp_empty_addr = {};

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
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED)
			return SNMP_INTEGER(peer->notify.code);
		else
			return SNMP_INTEGER(0);

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

	/*
	 * Not supported Yet.
	 */
	case CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL:
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
		if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED)
			return SNMP_INTEGER(peer->notify.code);
		else
			return SNMP_INTEGER(0);

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

	/*
	 * Not supported Yet.
	 */
	case CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL:
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

	/*
	 * Not supported Yet.
	 */
	case CBGP_PEER_SUPPRESSED_PREFIXES:
	case CBGP_PEER_WITHDRAWN_PREFIXES:
	case CBGP_PEER_PREFIX_CLEAR_THRESHOLD:
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
	case CBGP_PEER2_SUPPRESSED_PREFIXES:
	case CBGP_PEER2_WITHDRAWN_PREFIXES:
	case CBGP_PEER2_PREFIX_CLEAR_THRESHOLD:
	default:
		break;
	}

	return NULL;
}

static struct variable cbgp4_variables[] = {

	/* cbgp4PeerTable */
	{ CBGP_PEER_PREFIX_ACCEPTED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_ACCEPTED } },

	{ CBGP_PEER_PREFIX_DENIED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_DENIED } },

	{ CBGP_PEER_PREFIX_LIMIT,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_LIMIT } },

	{ CBGP_PEER_PREFIX_ADVERTISED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_ADVERTISED } },

	{ CBGP_PEER_PREFIX_SUPPRESSED,
	  ASN_INTEGER,
	  RONLY,
	  cbgp4PeerTable,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER_TABLE, CBGP_PEER_ENTRY,
	    CBGP_PEER_PREFIX_SUPPRESSED } },

	{ CBGP_PEER_PREFIX_WITHDRAWN,
	  ASN_INTEGER,
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
	  ASN_UNSIGNED,
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
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_REMOTE_IDENTIFIER } },

	{ CBGP_PEER2_IN_UPDATES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_IN_UPDATES } },

	{ CBGP_PEER2_OUT_UPDATES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_OUT_UPDATES } },

	{ CBGP_PEER2_IN_TOTAL_MESSAGES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_IN_TOTAL_MESSAGES } },

	{ CBGP_PEER2_OUT_TOTAL_MESSAGES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_OUT_TOTAL_MESSAGES } },

	{ CBGP_PEER2_LAST_ERROR,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LAST_ERROR } },

	{ CBGP_PEER2_FSM_ESTABLISHED_TRANSITIONS,
	  ASN_UNSIGNED,
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
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_CONNECT_RETRY_INTERVAL } },

	{ CBGP_PEER2_HOLD_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_HOLD_TIME } },

	{ CBGP_PEER2_KEEP_ALIVE,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_KEEP_ALIVE } },

	{ CBGP_PEER2_HOLD_TIME_CONFIGURED,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_HOLD_TIME_CONFIGURED } },

	{ CBGP_PEER2_KEEP_ALIVE_CONFIGURED,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_KEEP_ALIVE_CONFIGURED } },

	{ CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_MIN_AS_ORIGINATION_INTERVAL } },

	{ CBGP_PEER2_MIN_ROUTE_ADVERTISEMENT_INTERVAL,
	  ASN_UNSIGNED,
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
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer2Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER2_TABLE, CBGP_PEER2_ENTRY,
	    CBGP_PEER2_LOCAL_IDENTIFIER } },


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
	  ASN_UNSIGNED,
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
	  ASN_OCTET_STR,
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
	  ASN_OCTET_STR,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_REMOTE_IDENTIFIER } },

	{ CBGP_PEER3_IN_UPDATES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_IN_UPDATES } },

	{ CBGP_PEER3_OUT_UPDATES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_OUT_UPDATES } },

	{ CBGP_PEER3_IN_TOTAL_MESSAGES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_IN_TOTAL_MESSAGES } },

	{ CBGP_PEER3_OUT_TOTAL_MESSAGES,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_OUT_TOTAL_MESSAGES } },

	{ CBGP_PEER3_LAST_ERROR,
	  ASN_UNSIGNED,
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
	  ASN_UNSIGNED,
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
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_CONNECT_RETRY_INTERVAL } },

	{ CBGP_PEER3_HOLD_TIME,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_HOLD_TIME } },

	{ CBGP_PEER3_KEEP_ALIVE,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_KEEP_ALIVE } },

	{ CBGP_PEER3_HOLD_TIME_CONFIGURED,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_HOLD_TIME_CONFIGURED } },

	{ CBGP_PEER3_KEEP_ALIVE_CONFIGURED,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_KEEP_ALIVE_CONFIGURED } },

	{ CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL,
	  ASN_UNSIGNED,
	  RONLY,
	  cbgp4Peer3Table,
	  5,
	  { CISCO_BGP4_MIB_OBJECTS, CBGP_PEER, CBGP_PEER3_TABLE, CBGP_PEER3_ENTRY,
	    CBGP_PEER3_MIN_AS_ORIGINATION_INTERVAL } },

	{ CBGP_PEER3_MIN_ROUTE_ADVERTISEMENT_INTERVAL,
	  ASN_UNSIGNED,
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
};

int bgp_snmp_cbgp4_init(struct event_loop *tm)
{
	REGISTER_MIB("mibI/cbgp4", cbgp4_variables, variable, cbgp4_oid);
	return 0;
}
