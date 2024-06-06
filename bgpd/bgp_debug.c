// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP-4, BGP-4+ packet debug routine
 * Copyright (C) 1996, 97, 99 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "lib/bfd.h"
#include "lib/printfrr.h"
#include "prefix.h"
#include "linklist.h"
#include "stream.h"
#include "command.h"
#include "log.h"
#include "sockunion.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"
#include "hook.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_packet.h"

#include "bgpd/bgp_debug_clippy.c"

DEFINE_HOOK(bgp_hook_config_write_debug, (struct vty *vty, bool running),
	    (vty, running));

unsigned long conf_bgp_debug_as4;
unsigned long conf_bgp_debug_neighbor_events;
unsigned long conf_bgp_debug_events;
unsigned long conf_bgp_debug_packet;
unsigned long conf_bgp_debug_filter;
unsigned long conf_bgp_debug_keepalive;
unsigned long conf_bgp_debug_update;
unsigned long conf_bgp_debug_bestpath;
unsigned long conf_bgp_debug_zebra;
unsigned long conf_bgp_debug_nht;
unsigned long conf_bgp_debug_update_groups;
unsigned long conf_bgp_debug_vpn;
unsigned long conf_bgp_debug_flowspec;
unsigned long conf_bgp_debug_labelpool;
unsigned long conf_bgp_debug_pbr;
unsigned long conf_bgp_debug_graceful_restart;
unsigned long conf_bgp_debug_evpn_mh;
unsigned long conf_bgp_debug_bfd;
unsigned long conf_bgp_debug_cond_adv;

unsigned long term_bgp_debug_as4;
unsigned long term_bgp_debug_neighbor_events;
unsigned long term_bgp_debug_events;
unsigned long term_bgp_debug_packet;
unsigned long term_bgp_debug_filter;
unsigned long term_bgp_debug_keepalive;
unsigned long term_bgp_debug_update;
unsigned long term_bgp_debug_bestpath;
unsigned long term_bgp_debug_zebra;
unsigned long term_bgp_debug_nht;
unsigned long term_bgp_debug_update_groups;
unsigned long term_bgp_debug_vpn;
unsigned long term_bgp_debug_flowspec;
unsigned long term_bgp_debug_labelpool;
unsigned long term_bgp_debug_pbr;
unsigned long term_bgp_debug_graceful_restart;
unsigned long term_bgp_debug_evpn_mh;
unsigned long term_bgp_debug_bfd;
unsigned long term_bgp_debug_cond_adv;

struct list *bgp_debug_neighbor_events_peers = NULL;
struct list *bgp_debug_keepalive_peers = NULL;
struct list *bgp_debug_update_out_peers = NULL;
struct list *bgp_debug_update_in_peers = NULL;
struct list *bgp_debug_update_prefixes = NULL;
struct list *bgp_debug_bestpath_prefixes = NULL;
struct list *bgp_debug_zebra_prefixes = NULL;

/* messages for BGP-4 status */
const struct message bgp_status_msg[] = {{Idle, "Idle"},
					 {Connect, "Connect"},
					 {Active, "Active"},
					 {OpenSent, "OpenSent"},
					 {OpenConfirm, "OpenConfirm"},
					 {Established, "Established"},
					 {Clearing, "Clearing"},
					 {Deleted, "Deleted"},
					 {0}};

/* BGP message type string. */
const char *const bgp_type_str[] = {NULL,	   "OPEN",      "UPDATE",
			      "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH",
			      "CAPABILITY"};

/* message for BGP-4 Notify */
static const struct message bgp_notify_msg[] = {
	{BGP_NOTIFY_HEADER_ERR, "Message Header Error"},
	{BGP_NOTIFY_OPEN_ERR, "OPEN Message Error"},
	{BGP_NOTIFY_UPDATE_ERR, "UPDATE Message Error"},
	{BGP_NOTIFY_HOLD_ERR, "Hold Timer Expired"},
	{BGP_NOTIFY_FSM_ERR, "Neighbor Events Error"},
	{BGP_NOTIFY_CEASE, "Cease"},
	{BGP_NOTIFY_ROUTE_REFRESH_ERR, "ROUTE-REFRESH Message Error"},
	{BGP_NOTIFY_SEND_HOLD_ERR, "Send Hold Timer Expired"},
	{0}};

static const struct message bgp_notify_head_msg[] = {
	{BGP_NOTIFY_HEADER_NOT_SYNC, "/Connection Not Synchronized"},
	{BGP_NOTIFY_HEADER_BAD_MESLEN, "/Bad Message Length"},
	{BGP_NOTIFY_HEADER_BAD_MESTYPE, "/Bad Message Type"},
	{0}};

static const struct message bgp_notify_open_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_OPEN_UNSUP_VERSION, "/Unsupported Version Number"},
	{BGP_NOTIFY_OPEN_BAD_PEER_AS, "/Bad Peer AS"},
	{BGP_NOTIFY_OPEN_BAD_BGP_IDENT, "/Bad BGP Identifier"},
	{BGP_NOTIFY_OPEN_UNSUP_PARAM, "/Unsupported Optional Parameter"},
	{BGP_NOTIFY_OPEN_UNACEP_HOLDTIME, "/Unacceptable Hold Time"},
	{BGP_NOTIFY_OPEN_UNSUP_CAPBL, "/Unsupported Capability"},
	{BGP_NOTIFY_OPEN_ROLE_MISMATCH, "/Role Mismatch"},
	{0}};

static const struct message bgp_notify_update_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_UPDATE_MAL_ATTR, "/Malformed Attribute List"},
	{BGP_NOTIFY_UPDATE_UNREC_ATTR, "/Unrecognized Well-known Attribute"},
	{BGP_NOTIFY_UPDATE_MISS_ATTR, "/Missing Well-known Attribute"},
	{BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR, "/Attribute Flags Error"},
	{BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, "/Attribute Length Error"},
	{BGP_NOTIFY_UPDATE_INVAL_ORIGIN, "/Invalid ORIGIN Attribute"},
	{BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP, "/Invalid NEXT_HOP Attribute"},
	{BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, "/Optional Attribute Error"},
	{BGP_NOTIFY_UPDATE_INVAL_NETWORK, "/Invalid Network Field"},
	{BGP_NOTIFY_UPDATE_MAL_AS_PATH, "/Malformed AS_PATH"},
	{0}};

static const struct message bgp_notify_cease_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_CEASE_MAX_PREFIX, "/Maximum Number of Prefixes Reached"},
	{BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN, "/Administrative Shutdown"},
	{BGP_NOTIFY_CEASE_PEER_UNCONFIG, "/Peer De-configured"},
	{BGP_NOTIFY_CEASE_ADMIN_RESET, "/Administrative Reset"},
	{BGP_NOTIFY_CEASE_CONNECT_REJECT, "/Connection Rejected"},
	{BGP_NOTIFY_CEASE_CONFIG_CHANGE, "/Other Configuration Change"},
	{BGP_NOTIFY_CEASE_COLLISION_RESOLUTION,
	 "/Connection Collision Resolution"},
	{BGP_NOTIFY_CEASE_OUT_OF_RESOURCE, "/Out of Resources"},
	{BGP_NOTIFY_CEASE_HARD_RESET, "/Hard Reset"},
	{BGP_NOTIFY_CEASE_BFD_DOWN, "/BFD Down"},
	{0}};

static const struct message bgp_notify_route_refresh_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_ROUTE_REFRESH_INVALID_MSG_LEN, "/Invalid Message Length"},
	{0}};

static const struct message bgp_notify_fsm_msg[] = {
	{BGP_NOTIFY_FSM_ERR_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_FSM_ERR_SUBCODE_OPENSENT,
	 "/Receive Unexpected Message in OpenSent State"},
	{BGP_NOTIFY_FSM_ERR_SUBCODE_OPENCONFIRM,
	 "/Receive Unexpected Message in OpenConfirm State"},
	{BGP_NOTIFY_FSM_ERR_SUBCODE_ESTABLISHED,
	 "/Receive Unexpected Message in Established State"},
	{0}};

/* Origin strings. */
const char *const bgp_origin_str[] = {"i", "e", "?"};
const char *const bgp_origin_long_str[] = {"IGP", "EGP", "incomplete"};

static void bgp_debug_print_evpn_prefix(struct vty *vty, const char *desc,
					struct prefix *p);
/* Given a string return a pointer the corresponding peer structure */
static struct peer *bgp_find_peer(struct vty *vty, const char *peer_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer;

	if (!bgp) {
		return NULL;
	}
	ret = str2sockunion(peer_str, &su);

	/* 'swpX' string */
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, peer_str);

		if (!peer)
			peer = peer_lookup_by_hostname(bgp, peer_str);

		return peer;
	} else
		return peer_lookup(bgp, &su);
}

static void bgp_debug_list_free(struct list *list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	if (list)
		for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
			listnode_delete(list, filter);
			prefix_free(&filter->p);
			XFREE(MTYPE_BGP_DEBUG_STR, filter->host);
			XFREE(MTYPE_BGP_DEBUG_STR, filter->plist_name);
			XFREE(MTYPE_BGP_DEBUG_FILTER, filter);
		}
}

/*
 * Print the desc along with a list of peers/prefixes this debug is
 * enabled for
 */
static void bgp_debug_list_print(struct vty *vty, const char *desc,
				 struct list *list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	vty_out(vty, "%s", desc);

	if (list && !list_isempty(list)) {
		vty_out(vty, " for:\n");
		for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
			if (filter->host)
				vty_out(vty, "   %s", filter->host);

			if (filter->plist_name)
				vty_out(vty, " with prefix-list %s",
					filter->plist_name);

			if (filter->p && filter->p->family == AF_EVPN)
				bgp_debug_print_evpn_prefix(vty, "", filter->p);
			else if (filter->p)
				vty_out(vty, " %pFX", filter->p);

			vty_out(vty, "\n");
		}
	}

	vty_out(vty, "\n");
}

/*
 * Print the command to enable the debug for each peer/prefix this debug is
 * enabled for
 */
static int bgp_debug_list_conf_print(struct vty *vty, const char *desc,
				     struct list *list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;
	int write = 0;

	if (list && !list_isempty(list)) {
		for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
			if (filter->host && filter->plist_name) {
				vty_out(vty, "%s %s prefix-list %s\n", desc,
					filter->host, filter->plist_name);
				write++;
			} else if (filter->host) {
				vty_out(vty, "%s %s\n", desc, filter->host);
				write++;
			}

			if (filter->p && filter->p->family == AF_EVPN) {
				bgp_debug_print_evpn_prefix(vty, desc,
							    filter->p);
				write++;
			} else if (filter->p) {
				vty_out(vty, "%s %pFX\n", desc, filter->p);
				write++;
			}
		}
	}

	if (!write) {
		vty_out(vty, "%s\n", desc);
		write++;
	}

	return write;
}

static void bgp_debug_list_add_entry(struct list *list, const char *host,
				     const struct prefix *p,
				     const char *plist_name)
{
	struct bgp_debug_filter *filter;

	filter = XCALLOC(MTYPE_BGP_DEBUG_FILTER,
			 sizeof(struct bgp_debug_filter));

	if (host) {
		filter->host = XSTRDUP(MTYPE_BGP_DEBUG_STR, host);
		filter->plist_name = NULL;
		filter->plist_v4 = NULL;
		filter->plist_v6 = NULL;
		filter->p = NULL;
	} else if (p) {
		filter->host = NULL;
		filter->plist_name = NULL;
		filter->plist_v4 = NULL;
		filter->plist_v6 = NULL;
		filter->p = prefix_new();
		prefix_copy(filter->p, p);
	}

	if (plist_name) {
		filter->plist_name = XSTRDUP(MTYPE_BGP_DEBUG_STR, plist_name);
		filter->plist_v4 = prefix_list_lookup(AFI_IP,
						      filter->plist_name);
		filter->plist_v6 = prefix_list_lookup(AFI_IP6,
						      filter->plist_name);
	}

	listnode_add(list, filter);
}

static bool bgp_debug_list_remove_entry(struct list *list, const char *host,
					const struct prefix *p)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
		if (host && strcmp(filter->host, host) == 0) {
			listnode_delete(list, filter);
			XFREE(MTYPE_BGP_DEBUG_STR, filter->host);
			XFREE(MTYPE_BGP_DEBUG_STR, filter->plist_name);
			XFREE(MTYPE_BGP_DEBUG_FILTER, filter);
			return true;
		} else if (p && filter->p->prefixlen == p->prefixlen
			   && prefix_match(filter->p, p)) {
			listnode_delete(list, filter);
			prefix_free(&filter->p);
			XFREE(MTYPE_BGP_DEBUG_FILTER, filter);
			return true;
		}
	}

	return false;
}

static bool bgp_debug_list_has_entry(struct list *list, const char *host,
				     const struct prefix *p,
				     const char *plist_name)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
		if (host && plist_name) {
			if (strmatch(filter->host, host) && filter->plist_name &&
			    strmatch(filter->plist_name, plist_name))
				return true;
		} else if (host) {
			if (strmatch(filter->host, host))
				return true;
		} else if (p) {
			if (filter->p->prefixlen == p->prefixlen
			    && prefix_match(filter->p, p)) {
				return true;
			}
		}
	}

	return false;
}

bool bgp_debug_peer_updout_enabled(char *host)
{
	return (bgp_debug_list_has_entry(bgp_debug_update_out_peers, host, NULL,
					 NULL));
}

/* Dump attribute. */
bool bgp_dump_attr(struct attr *attr, char *buf, size_t size)
{
	if (!attr)
		return false;

	buf[0] = '\0';

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)))
		snprintfrr(buf, size, "nexthop %pI4", &attr->nexthop);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", origin %s",
			 bgp_origin_str[attr->origin]);

	/* Add MP case. */
	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
		snprintfrr(buf + strlen(buf), size - strlen(buf),
			   ", mp_nexthop %pI6", &attr->mp_nexthop_global);

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
		snprintfrr(buf + strlen(buf), size - strlen(buf), "(%pI6)",
			   &attr->mp_nexthop_local);

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4)
		snprintfrr(buf, size, "nexthop %pI4", &attr->nexthop);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", localpref %u", attr->local_pref);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", aigp-metric %" PRIu64,
			 (unsigned long long)bgp_attr_get_aigp_metric(attr));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", metric %u",
			 attr->med);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", community %s",
			 community_str(bgp_attr_get_community(attr), false,
				       true));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", large-community %s",
			 lcommunity_str(bgp_attr_get_lcommunity(attr), false,
					true));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", extcommunity %s",
			 ecommunity_str(bgp_attr_get_ecommunity(attr)));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", atomic-aggregate");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))
		snprintfrr(buf + strlen(buf), size - strlen(buf),
			   ", aggregated by %u %pI4", attr->aggregator_as,
			   &attr->aggregator_addr);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
		snprintfrr(buf + strlen(buf), size - strlen(buf),
			   ", originator %pI4", &attr->originator_id);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))) {
		struct cluster_list *cluster;
		int i;

		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", clusterlist");

		cluster = bgp_attr_get_cluster(attr);
		for (i = 0; i < cluster->length / 4; i++)
			snprintfrr(buf + strlen(buf), size - strlen(buf),
				   " %pI4", &cluster->list[i]);
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", pmsi tnltype %u", bgp_attr_get_pmsi_tnl_type(attr));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", path %s",
			 aspath_print(attr->aspath));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID))) {
		if (attr->label_index != BGP_INVALID_LABEL_INDEX)
			snprintf(buf + strlen(buf), size - strlen(buf),
				 ", label-index %u", attr->label_index);
	}

	if (strlen(buf) > 1)
		return true;
	else
		return false;
}

const char *bgp_notify_code_str(char code)
{
	return lookup_msg(bgp_notify_msg, code, "Unrecognized Error Code");
}

const char *bgp_notify_subcode_str(char code, char subcode)
{

	switch (code) {
	case BGP_NOTIFY_HEADER_ERR:
		return lookup_msg(bgp_notify_head_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_OPEN_ERR:
		return lookup_msg(bgp_notify_open_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_UPDATE_ERR:
		return lookup_msg(bgp_notify_update_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_HOLD_ERR:
	case BGP_NOTIFY_SEND_HOLD_ERR:
		break;
	case BGP_NOTIFY_FSM_ERR:
		return lookup_msg(bgp_notify_fsm_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_CEASE:
		return lookup_msg(bgp_notify_cease_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_ROUTE_REFRESH_ERR:
		return lookup_msg(bgp_notify_route_refresh_msg, subcode,
				  "Unrecognized Error Subcode");
	}
	return "";
}

/* extract notify admin reason if correctly present */
const char *bgp_notify_admin_message(char *buf, size_t bufsz, uint8_t *data,
				     size_t datalen)
{
	memset(buf, 0, bufsz);
	if (!data || datalen < 1)
		return buf;

	uint8_t len = data[0];
	if (!len || len > datalen - 1)
		return buf;

	return zlog_sanitize(buf, bufsz, data + 1, len);
}

/* dump notify packet */
void bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify,
		      const char *direct, bool hard_reset)
{
	const char *subcode_str;
	const char *code_str;
	const char *msg_str = NULL;
	char msg_buf[1024];

	if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)
	    || CHECK_FLAG(peer->bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
		code_str = bgp_notify_code_str(bgp_notify->code);
		subcode_str = bgp_notify_subcode_str(bgp_notify->code,
						     bgp_notify->subcode);

		if (bgp_notify->code == BGP_NOTIFY_CEASE
		    && (bgp_notify->subcode == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN
			|| bgp_notify->subcode
				   == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
			msg_str = bgp_notify_admin_message(
				msg_buf, sizeof(msg_buf), bgp_notify->raw_data,
				bgp_notify->length);
		}

		if (msg_str) {
			zlog_info(
				"%%NOTIFICATION%s: %s neighbor %s %d/%d (%s%s) \"%s\"",
				hard_reset ? "(Hard Reset)" : "",
				strcmp(direct, "received") == 0
					? "received from"
					: "sent to",
				peer->host, bgp_notify->code,
				bgp_notify->subcode, code_str, subcode_str,
				msg_str);
		} else {
			msg_str = bgp_notify->data ? bgp_notify->data : "";
			zlog_info(
				"%%NOTIFICATION%s: %s neighbor %s %d/%d (%s%s) %d bytes %s",
				hard_reset ? "(Hard Reset)" : "",
				strcmp(direct, "received") == 0
					? "received from"
					: "sent to",
				peer->host, bgp_notify->code,
				bgp_notify->subcode, code_str, subcode_str,
				bgp_notify->length, msg_str);
		}
	}
}

static void bgp_debug_clear_updgrp_update_dbg(struct bgp *bgp)
{
	if (!bgp)
		bgp = bgp_get_default();
	update_group_walk(bgp, update_group_clear_update_dbg, NULL);
}

static void bgp_debug_print_evpn_prefix(struct vty *vty, const char *desc,
					struct prefix *p)
{
	char evpn_desc[PREFIX2STR_BUFFER + INET_ADDRSTRLEN];
	char buf[PREFIX2STR_BUFFER];
	char buf2[ETHER_ADDR_STRLEN];

	if (p->u.prefix_evpn.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (is_evpn_prefix_ipaddr_none((struct prefix_evpn *)p)) {
			snprintf(
				evpn_desc, sizeof(evpn_desc),
				"l2vpn evpn type macip mac %s",
				prefix_mac2str(&p->u.prefix_evpn.macip_addr.mac,
					       buf2, sizeof(buf2)));
		} else {
			uint8_t family = is_evpn_prefix_ipaddr_v4(
						(struct prefix_evpn *)p) ?
							AF_INET : AF_INET6;
			snprintf(
				evpn_desc, sizeof(evpn_desc),
				"l2vpn evpn type macip mac %s ip %s",
				prefix_mac2str(&p->u.prefix_evpn.macip_addr.mac,
					       buf2, sizeof(buf2)),
				inet_ntop(
					family,
					&p->u.prefix_evpn.macip_addr.ip.ip.addr,
					buf, PREFIX2STR_BUFFER));
		}
	} else if (p->u.prefix_evpn.route_type == BGP_EVPN_IMET_ROUTE) {
		snprintfrr(evpn_desc, sizeof(evpn_desc),
			   "l2vpn evpn type multicast ip %pI4",
			   &p->u.prefix_evpn.imet_addr.ip.ipaddr_v4);
	} else if (p->u.prefix_evpn.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		uint8_t family = is_evpn_prefix_ipaddr_v4(
					(struct prefix_evpn *)p) ? AF_INET
								: AF_INET6;
		snprintf(evpn_desc, sizeof(evpn_desc),
			 "l2vpn evpn type prefix ip %s/%d",
			 inet_ntop(family,
				   &p->u.prefix_evpn.prefix_addr.ip.ip.addr,
				   buf, PREFIX2STR_BUFFER),
			 p->u.prefix_evpn.prefix_addr.ip_prefix_length);
	}

	vty_out(vty, "%s %s\n", desc, evpn_desc);
}

static int bgp_debug_parse_evpn_prefix(struct vty *vty, struct cmd_token **argv,
				       int argc, struct prefix *argv_p)
{
	struct ethaddr mac = {};
	struct ipaddr ip = {};
	int evpn_type = 0;
	int mac_idx = 0;
	int ip_idx = 0;

	if (bgp_evpn_cli_parse_type(&evpn_type, argv, argc) < 0)
		return CMD_WARNING;

	if (evpn_type == BGP_EVPN_MAC_IP_ROUTE) {
		memset(&ip, 0, sizeof(ip));

		if (argv_find(argv, argc, "mac", &mac_idx))
			if (!prefix_str2mac(argv[mac_idx + 1]->arg, &mac)) {
				vty_out(vty, "%% Malformed MAC address\n");
				return CMD_WARNING;
			}

		if (argv_find(argv, argc, "ip", &ip_idx))
			if (str2ipaddr(argv[ip_idx + 1]->arg, &ip) != 0) {
				vty_out(vty, "%% Malformed IP address\n");
				return CMD_WARNING;
			}

		build_evpn_type2_prefix((struct prefix_evpn *)argv_p,
					&mac, &ip);
	} else if (evpn_type == BGP_EVPN_IMET_ROUTE) {
		memset(&ip, 0, sizeof(ip));

		if (argv_find(argv, argc, "ip", &ip_idx))
			if (str2ipaddr(argv[ip_idx + 1]->arg, &ip) != 0) {
				vty_out(vty, "%% Malformed IP address\n");
				return CMD_WARNING;
			}

		build_evpn_type3_prefix((struct prefix_evpn *)argv_p,
					ip.ipaddr_v4);
	} else if (evpn_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		struct prefix ip_prefix;

		memset(&ip_prefix, 0, sizeof(ip_prefix));
		if (argv_find(argv, argc, "ip", &ip_idx)) {
			(void)str2prefix(argv[ip_idx + 1]->arg, &ip_prefix);
			apply_mask(&ip_prefix);
		}
		build_type5_prefix_from_ip_prefix(
					(struct prefix_evpn *)argv_p,
					&ip_prefix);
	}

	return CMD_SUCCESS;
}

/* Debug option setting interface. */
unsigned long bgp_debug_option = 0;

int debug(unsigned int option)
{
	return bgp_debug_option & option;
}

DEFUN (debug_bgp_as4,
       debug_bgp_as4_cmd,
       "debug bgp as4",
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(as4, AS4);
	else {
		TERM_DEBUG_ON(as4, AS4);
		vty_out(vty, "BGP as4 debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_as4,
       no_debug_bgp_as4_cmd,
       "no debug bgp as4",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(as4, AS4);
	else {
		TERM_DEBUG_OFF(as4, AS4);
		vty_out(vty, "BGP as4 debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_as4_segment,
       debug_bgp_as4_segment_cmd,
       "debug bgp as4 segment",
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n"
       "BGP AS4 aspath segment handling\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(as4, AS4_SEGMENT);
	else {
		TERM_DEBUG_ON(as4, AS4_SEGMENT);
		vty_out(vty, "BGP as4 segment debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_as4_segment,
       no_debug_bgp_as4_segment_cmd,
       "no debug bgp as4 segment",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n"
       "BGP AS4 aspath segment handling\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(as4, AS4_SEGMENT);
	else {
		TERM_DEBUG_OFF(as4, AS4_SEGMENT);
		vty_out(vty, "BGP as4 segment debugging is off\n");
	}
	return CMD_SUCCESS;
}

/* debug bgp neighbor_events */
DEFUN (debug_bgp_neighbor_events,
       debug_bgp_neighbor_events_cmd,
       "debug bgp neighbor-events",
       DEBUG_STR
       BGP_STR
       "BGP Neighbor Events\n")
{
	bgp_debug_list_free(bgp_debug_neighbor_events_peers);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(neighbor_events, NEIGHBOR_EVENTS);
	else {
		TERM_DEBUG_ON(neighbor_events, NEIGHBOR_EVENTS);
		vty_out(vty, "BGP neighbor-events debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_neighbor_events_peer,
       debug_bgp_neighbor_events_peer_cmd,
       "debug bgp neighbor-events <A.B.C.D|X:X::X:X|WORD>",
       DEBUG_STR
       BGP_STR
       "BGP Neighbor Events\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
{
	int idx_peer = 3;
	const char *host = argv[idx_peer]->arg;

	if (!bgp_debug_neighbor_events_peers)
		bgp_debug_neighbor_events_peers = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_neighbor_events_peers, host,
				     NULL, NULL)) {
		vty_out(vty,
			"BGP neighbor-events debugging is already enabled for %s\n",
			host);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_neighbor_events_peers, host, NULL,
				 NULL);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(neighbor_events, NEIGHBOR_EVENTS);
	else {
		TERM_DEBUG_ON(neighbor_events, NEIGHBOR_EVENTS);
		vty_out(vty, "BGP neighbor-events debugging is on for %s\n",
			host);
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_neighbor_events,
       no_debug_bgp_neighbor_events_cmd,
       "no debug bgp neighbor-events",
       NO_STR
       DEBUG_STR
       BGP_STR
       "Neighbor Events\n")
{
	bgp_debug_list_free(bgp_debug_neighbor_events_peers);

	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(neighbor_events, NEIGHBOR_EVENTS);
	else {
		TERM_DEBUG_OFF(neighbor_events, NEIGHBOR_EVENTS);
		vty_out(vty, "BGP neighbor-events debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_neighbor_events_peer,
       no_debug_bgp_neighbor_events_peer_cmd,
       "no debug bgp neighbor-events <A.B.C.D|X:X::X:X|WORD>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "Neighbor Events\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
{
	int idx_peer = 4;
	int found_peer = 0;
	const char *host = argv[idx_peer]->arg;

	if (bgp_debug_neighbor_events_peers
	    && !list_isempty(bgp_debug_neighbor_events_peers)) {
		found_peer = bgp_debug_list_remove_entry(
			bgp_debug_neighbor_events_peers, host, NULL);

		if (list_isempty(bgp_debug_neighbor_events_peers)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_OFF(neighbor_events, NEIGHBOR_EVENTS);
			else
				TERM_DEBUG_OFF(neighbor_events,
					       NEIGHBOR_EVENTS);
		}
	}

	if (found_peer)
		vty_out(vty, "BGP neighbor-events debugging is off for %s\n",
			host);
	else
		vty_out(vty,
			"BGP neighbor-events debugging was not enabled for %s\n",
			host);

	return CMD_SUCCESS;
}

/* debug bgp nht */
DEFUN (debug_bgp_nht,
       debug_bgp_nht_cmd,
       "debug bgp nht",
       DEBUG_STR
       BGP_STR
       "BGP nexthop tracking events\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(nht, NHT);
	else {
		TERM_DEBUG_ON(nht, NHT);
		vty_out(vty, "BGP nexthop tracking debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_nht,
       no_debug_bgp_nht_cmd,
       "no debug bgp nht",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP nexthop tracking events\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(nht, NHT);
	else {
		TERM_DEBUG_OFF(nht, NHT);
		vty_out(vty, "BGP nexthop tracking debugging is off\n");
	}
	return CMD_SUCCESS;
}

/* debug bgp keepalives */
DEFUN (debug_bgp_keepalive,
       debug_bgp_keepalive_cmd,
       "debug bgp keepalives",
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")
{
	bgp_debug_list_free(bgp_debug_keepalive_peers);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(keepalive, KEEPALIVE);
	else {
		TERM_DEBUG_ON(keepalive, KEEPALIVE);
		vty_out(vty, "BGP keepalives debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_keepalive_peer,
       debug_bgp_keepalive_peer_cmd,
       "debug bgp keepalives <A.B.C.D|X:X::X:X|WORD>",
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n"
       "BGP IPv4 neighbor to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
{
	int idx_peer = 3;
	const char *host = argv[idx_peer]->arg;

	if (!bgp_debug_keepalive_peers)
		bgp_debug_keepalive_peers = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_keepalive_peers, host, NULL,
				     NULL)) {
		vty_out(vty,
			"BGP keepalive debugging is already enabled for %s\n",
			host);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_keepalive_peers, host, NULL, NULL);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(keepalive, KEEPALIVE);
	else {
		TERM_DEBUG_ON(keepalive, KEEPALIVE);
		vty_out(vty, "BGP keepalives debugging is on for %s\n", host);
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_keepalive,
       no_debug_bgp_keepalive_cmd,
       "no debug bgp keepalives",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")
{
	bgp_debug_list_free(bgp_debug_keepalive_peers);

	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(keepalive, KEEPALIVE);
	else {
		TERM_DEBUG_OFF(keepalive, KEEPALIVE);
		vty_out(vty, "BGP keepalives debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_keepalive_peer,
       no_debug_bgp_keepalive_peer_cmd,
       "no debug bgp keepalives <A.B.C.D|X:X::X:X|WORD>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
{
	int idx_peer = 4;
	int found_peer = 0;
	const char *host = argv[idx_peer]->arg;

	if (bgp_debug_keepalive_peers
	    && !list_isempty(bgp_debug_keepalive_peers)) {
		found_peer = bgp_debug_list_remove_entry(
			bgp_debug_keepalive_peers, host, NULL);

		if (list_isempty(bgp_debug_keepalive_peers)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_OFF(keepalive, KEEPALIVE);
			else
				TERM_DEBUG_OFF(keepalive, KEEPALIVE);
		}
	}

	if (found_peer)
		vty_out(vty, "BGP keepalives debugging is off for %s\n", host);
	else
		vty_out(vty,
			"BGP keepalives debugging was not enabled for %s\n",
			host);

	return CMD_SUCCESS;
}

/* debug bgp bestpath */
DEFPY (debug_bgp_bestpath_prefix,
       debug_bgp_bestpath_prefix_cmd,
       "debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>$prefix",
       DEBUG_STR
       BGP_STR
       "BGP bestpath\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	if (!bgp_debug_bestpath_prefixes)
		bgp_debug_bestpath_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_bestpath_prefixes, NULL, prefix,
				     NULL)) {
		vty_out(vty,
			"BGP bestpath debugging is already enabled for %s\n",
			prefix_str);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_bestpath_prefixes, NULL, prefix,
				 NULL);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(bestpath, BESTPATH);
	} else {
		TERM_DEBUG_ON(bestpath, BESTPATH);
		vty_out(vty, "BGP bestpath debugging is on for %s\n",
			prefix_str);
	}

	return CMD_SUCCESS;
}

DEFPY (no_debug_bgp_bestpath_prefix,
       no_debug_bgp_bestpath_prefix_cmd,
       "no debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>$prefix",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP bestpath\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	bool found_prefix = false;

	if (bgp_debug_bestpath_prefixes
	    && !list_isempty(bgp_debug_bestpath_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_bestpath_prefixes, NULL, prefix);

		if (list_isempty(bgp_debug_bestpath_prefixes)) {
			if (vty->node == CONFIG_NODE) {
				DEBUG_OFF(bestpath, BESTPATH);
			} else {
				TERM_DEBUG_OFF(bestpath, BESTPATH);
				vty_out(vty,
					"BGP bestpath debugging (per prefix) is off\n");
			}
		}
	}

	if (found_prefix)
		vty_out(vty, "BGP bestpath debugging is off for %s\n",
			prefix_str);
	else
		vty_out(vty, "BGP bestpath debugging was not enabled for %s\n",
			prefix_str);

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_bestpath,
       no_debug_bgp_bestpath_cmd,
       "no debug bgp bestpath",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP bestpath\n")
{
	bgp_debug_list_free(bgp_debug_bestpath_prefixes);

	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(bestpath, BESTPATH);
	else {
		TERM_DEBUG_OFF(bestpath, BESTPATH);
		vty_out(vty, "BGP bestpath debugging is off\n");
	}
	return CMD_SUCCESS;
}

/* debug bgp updates */
DEFUN (debug_bgp_update,
       debug_bgp_update_cmd,
       "debug bgp updates",
       DEBUG_STR
       BGP_STR
       "BGP updates\n")
{
	bgp_debug_list_free(bgp_debug_update_in_peers);
	bgp_debug_list_free(bgp_debug_update_out_peers);
	bgp_debug_list_free(bgp_debug_update_prefixes);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(update, UPDATE_IN);
		DEBUG_ON(update, UPDATE_OUT);
	} else {
		TERM_DEBUG_ON(update, UPDATE_IN);
		TERM_DEBUG_ON(update, UPDATE_OUT);
		vty_out(vty, "BGP updates debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFPY (debug_bgp_update_detail,
       debug_bgp_update_detail_cmd,
       "[no] debug bgp updates detail",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Show detailed information about updates\n")
{
	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(update, UPDATE_DETAIL);
		else
			DEBUG_ON(update, UPDATE_DETAIL);
	} else {
		if (no)
			TERM_DEBUG_OFF(update, UPDATE_DETAIL);
		else
			TERM_DEBUG_ON(update, UPDATE_DETAIL);
		vty_out(vty, "BGP updates detail debugging is on\n");
	}

	return CMD_SUCCESS;
}

DEFUN (debug_bgp_update_direct,
       debug_bgp_update_direct_cmd,
       "debug bgp updates <in|out>",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n")
{
	int idx_in_out = 3;

	if (strncmp("i", argv[idx_in_out]->arg, 1) == 0)
		bgp_debug_list_free(bgp_debug_update_in_peers);
	else
		bgp_debug_list_free(bgp_debug_update_out_peers);

	if (vty->node == CONFIG_NODE) {
		if (strncmp("i", argv[idx_in_out]->arg, 1) == 0)
			DEBUG_ON(update, UPDATE_IN);
		else
			DEBUG_ON(update, UPDATE_OUT);
	} else {
		if (strncmp("i", argv[idx_in_out]->arg, 1) == 0) {
			TERM_DEBUG_ON(update, UPDATE_IN);
			vty_out(vty, "BGP updates debugging is on (inbound)\n");
		} else {
			TERM_DEBUG_ON(update, UPDATE_OUT);
			vty_out(vty,
				"BGP updates debugging is on (outbound)\n");
		}
	}
	return CMD_SUCCESS;
}

DEFPY (debug_bgp_update_direct_peer,
       debug_bgp_update_direct_peer_cmd,
       "debug bgp updates <in|out> <A.B.C.D|X:X::X:X|WORD> [prefix-list PREFIXLIST_NAME$plist]",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n"
       "Use prefix-list to filter prefixes to debug\n"
       "Name of prefix-list\n")
{
	int idx_in_out = 3;
	int idx_peer = 4;
	const char *host = argv[idx_peer]->arg;
	int inbound;

	if (!bgp_debug_update_in_peers)
		bgp_debug_update_in_peers = list_new();

	if (!bgp_debug_update_out_peers)
		bgp_debug_update_out_peers = list_new();

	if (strncmp("i", argv[idx_in_out]->arg, 1) == 0)
		inbound = 1;
	else
		inbound = 0;

	if (inbound) {
		if (bgp_debug_list_has_entry(bgp_debug_update_in_peers, host,
					     NULL, plist)) {
			vty_out(vty,
				"BGP inbound update debugging is already enabled for %s\n",
				host);
			return CMD_SUCCESS;
		}
	}

	else {
		if (bgp_debug_list_has_entry(bgp_debug_update_out_peers, host,
					     NULL, plist)) {
			vty_out(vty,
				"BGP outbound update debugging is already enabled for %s\n",
				host);
			return CMD_SUCCESS;
		}
	}

	if (inbound)
		bgp_debug_list_add_entry(bgp_debug_update_in_peers, host, NULL,
					 plist);
	else {
		struct peer *peer;
		struct peer_af *paf;
		int afidx;

		bgp_debug_list_add_entry(bgp_debug_update_out_peers, host, NULL,
					 plist);
		peer = bgp_find_peer(vty, host);

		if (peer) {
			for (afidx = BGP_AF_START; afidx < BGP_AF_MAX;
			     afidx++) {
				paf = peer->peer_af_array[afidx];
				if (paf != NULL) {
					if (PAF_SUBGRP(paf)) {
						UPDGRP_PEER_DBG_EN(
							PAF_SUBGRP(paf)
								->update_group);
					}
				}
			}
		}
	}

	if (vty->node == CONFIG_NODE) {
		if (inbound)
			DEBUG_ON(update, UPDATE_IN);
		else
			DEBUG_ON(update, UPDATE_OUT);
	} else {
		if (inbound) {
			TERM_DEBUG_ON(update, UPDATE_IN);
			vty_out(vty,
				"BGP updates debugging is on (inbound) for %s\n",
				argv[idx_peer]->arg);
		} else {
			TERM_DEBUG_ON(update, UPDATE_OUT);
			vty_out(vty,
				"BGP updates debugging is on (outbound) for %s\n",
				argv[idx_peer]->arg);
		}
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update_direct,
       no_debug_bgp_update_direct_cmd,
       "no debug bgp updates <in|out>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n")
{
	int idx_in_out = 4;
	if (strncmp("i", argv[idx_in_out]->arg, 1) == 0) {
		bgp_debug_list_free(bgp_debug_update_in_peers);

		if (vty->node == CONFIG_NODE) {
			DEBUG_OFF(update, UPDATE_IN);
		} else {
			TERM_DEBUG_OFF(update, UPDATE_IN);
			vty_out(vty,
				"BGP updates debugging is off (inbound)\n");
		}
	} else {
		bgp_debug_list_free(bgp_debug_update_out_peers);

		if (vty->node == CONFIG_NODE) {
			DEBUG_OFF(update, UPDATE_OUT);
		} else {
			TERM_DEBUG_OFF(update, UPDATE_OUT);
			vty_out(vty,
				"BGP updates debugging is off (outbound)\n");
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update_direct_peer,
       no_debug_bgp_update_direct_peer_cmd,
       "no debug bgp updates <in|out> <A.B.C.D|X:X::X:X|WORD> [prefix-list PREFIXLIST_NAME]",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n"
       "Use prefix-list to filter prefixes to debug\n"
       "Name of prefix-list\n")
{
	int idx_in_out = 4;
	int idx_peer = 5;
	int inbound;
	int found_peer = 0;
	const char *host = argv[idx_peer]->arg;

	if (strncmp("i", argv[idx_in_out]->arg, 1) == 0)
		inbound = 1;
	else
		inbound = 0;

	if (inbound && bgp_debug_update_in_peers
	    && !list_isempty(bgp_debug_update_in_peers)) {
		found_peer = bgp_debug_list_remove_entry(
			bgp_debug_update_in_peers, host, NULL);

		if (list_isempty(bgp_debug_update_in_peers)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_OFF(update, UPDATE_IN);
			else {
				TERM_DEBUG_OFF(update, UPDATE_IN);
				vty_out(vty,
					"BGP updates debugging (inbound) is off\n");
			}
		}
	}

	if (!inbound && bgp_debug_update_out_peers
	    && !list_isempty(bgp_debug_update_out_peers)) {
		found_peer = bgp_debug_list_remove_entry(
			bgp_debug_update_out_peers, host, NULL);

		if (list_isempty(bgp_debug_update_out_peers)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_OFF(update, UPDATE_OUT);
			else {
				TERM_DEBUG_OFF(update, UPDATE_OUT);
				vty_out(vty,
					"BGP updates debugging (outbound) is off\n");
			}
		}

		struct peer *peer;
		struct peer_af *paf;
		int afidx;
		peer = bgp_find_peer(vty, host);

		if (peer) {
			for (afidx = BGP_AF_START; afidx < BGP_AF_MAX;
			     afidx++) {
				paf = peer->peer_af_array[afidx];
				if (paf != NULL) {
					if (PAF_SUBGRP(paf)) {
						UPDGRP_PEER_DBG_DIS(
							PAF_SUBGRP(paf)
								->update_group);
					}
				}
			}
		}
	}

	if (found_peer)
		if (inbound)
			vty_out(vty,
				"BGP updates debugging (inbound) is off for %s\n",
				host);
		else
			vty_out(vty,
				"BGP updates debugging (outbound) is off for %s\n",
				host);
	else if (inbound)
		vty_out(vty,
			"BGP updates debugging (inbound) was not enabled for %s\n",
			host);
	else
		vty_out(vty,
			"BGP updates debugging (outbound) was not enabled for %s\n",
			host);

	return CMD_SUCCESS;
}

DEFPY (debug_bgp_update_prefix_afi_safi,
       debug_bgp_update_prefix_afi_safi_cmd,
       "debug bgp updates prefix l2vpn$afi evpn$safi type <<macip|2> mac <X:X:X:X:X:X|X:X:X:X:X:X/M> [ip <A.B.C.D|X:X::X:X>]|<multicast|3> ip <A.B.C.D|X:X::X:X>|<prefix|5> ip <A.B.C.D/M|X:X::X:X/M>>",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       L2VPN_HELP_STR
       EVPN_HELP_STR
       EVPN_TYPE_HELP_STR
       EVPN_TYPE_2_HELP_STR
       EVPN_TYPE_2_HELP_STR
       MAC_STR MAC_STR MAC_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       EVPN_TYPE_3_HELP_STR
       EVPN_TYPE_3_HELP_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       EVPN_TYPE_5_HELP_STR
       EVPN_TYPE_5_HELP_STR
       IP_STR
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct prefix argv_p;
	int ret = CMD_SUCCESS;

	ret = bgp_debug_parse_evpn_prefix(vty, argv, argc, &argv_p);
	if (ret != CMD_SUCCESS)
		return ret;

	if (!bgp_debug_update_prefixes)
		bgp_debug_update_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_update_prefixes, NULL, &argv_p,
				     NULL)) {
		vty_out(vty,
			"BGP updates debugging is already enabled for %pFX\n",
			&argv_p);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_update_prefixes, NULL, &argv_p, NULL);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(update, UPDATE_PREFIX);
	} else {
		TERM_DEBUG_ON(update, UPDATE_PREFIX);
		vty_out(vty, "BGP updates debugging is on for %pFX\n", &argv_p);
	}

	return CMD_SUCCESS;
}

DEFPY (no_debug_bgp_update_prefix_afi_safi,
       no_debug_bgp_update_prefix_afi_safi_cmd,
       "no debug bgp updates prefix l2vpn$afi evpn$safi type <<macip|2> mac <X:X:X:X:X:X|X:X:X:X:X:X/M> [ip <A.B.C.D|X:X::X:X>]|<multicast|3> ip <A.B.C.D|X:X::X:X>|<prefix|5> ip <A.B.C.D/M|X:X::X:X/M>>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       L2VPN_HELP_STR
       EVPN_HELP_STR
       EVPN_TYPE_HELP_STR
       EVPN_TYPE_2_HELP_STR
       EVPN_TYPE_2_HELP_STR
       MAC_STR MAC_STR MAC_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       EVPN_TYPE_3_HELP_STR
       EVPN_TYPE_3_HELP_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       EVPN_TYPE_5_HELP_STR
       EVPN_TYPE_5_HELP_STR
       IP_STR
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct prefix argv_p;
	bool found_prefix = false;
	int ret = CMD_SUCCESS;

	ret = bgp_debug_parse_evpn_prefix(vty, argv, argc, &argv_p);
	if (ret != CMD_SUCCESS)
		return ret;

	if (bgp_debug_update_prefixes
	    && !list_isempty(bgp_debug_update_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_update_prefixes, NULL, &argv_p);

		if (list_isempty(bgp_debug_update_prefixes)) {
			if (vty->node == CONFIG_NODE) {
				DEBUG_OFF(update, UPDATE_PREFIX);
			} else {
				TERM_DEBUG_OFF(update, UPDATE_PREFIX);
				vty_out(vty,
					"BGP updates debugging (per prefix) is off\n");
			}
		}
	}

	if (found_prefix)
		vty_out(vty, "BGP updates debugging is off for %pFX\n",
			&argv_p);
	else
		vty_out(vty, "BGP updates debugging was not enabled for %pFX\n",
			&argv_p);

	return ret;
}


DEFPY (debug_bgp_update_prefix,
       debug_bgp_update_prefix_cmd,
       "debug bgp updates prefix <A.B.C.D/M|X:X::X:X/M>$prefix",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	if (!bgp_debug_update_prefixes)
		bgp_debug_update_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_update_prefixes, NULL, prefix,
				     NULL)) {
		vty_out(vty,
			"BGP updates debugging is already enabled for %s\n",
			prefix_str);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_update_prefixes, NULL, prefix, NULL);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(update, UPDATE_PREFIX);
	} else {
		TERM_DEBUG_ON(update, UPDATE_PREFIX);
		vty_out(vty, "BGP updates debugging is on for %s\n",
			prefix_str);
	}

	return CMD_SUCCESS;
}

DEFPY (no_debug_bgp_update_prefix,
       no_debug_bgp_update_prefix_cmd,
       "no debug bgp updates prefix <A.B.C.D/M|X:X::X:X/M>$prefix",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	bool found_prefix = false;

	if (bgp_debug_update_prefixes
	    && !list_isempty(bgp_debug_update_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_update_prefixes, NULL, prefix);

		if (list_isempty(bgp_debug_update_prefixes)) {
			if (vty->node == CONFIG_NODE) {
				DEBUG_OFF(update, UPDATE_PREFIX);
			} else {
				TERM_DEBUG_OFF(update, UPDATE_PREFIX);
				vty_out(vty,
					"BGP updates debugging (per prefix) is off\n");
			}
		}
	}

	if (found_prefix)
		vty_out(vty, "BGP updates debugging is off for %s\n",
			prefix_str);
	else
		vty_out(vty, "BGP updates debugging was not enabled for %s\n",
			prefix_str);

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update,
       no_debug_bgp_update_cmd,
       "no debug bgp updates",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n")
{
	struct listnode *ln;
	struct bgp *bgp;

	bgp_debug_list_free(bgp_debug_update_in_peers);
	bgp_debug_list_free(bgp_debug_update_out_peers);
	bgp_debug_list_free(bgp_debug_update_prefixes);

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, ln, bgp))
		bgp_debug_clear_updgrp_update_dbg(bgp);

	if (vty->node == CONFIG_NODE) {
		DEBUG_OFF(update, UPDATE_IN);
		DEBUG_OFF(update, UPDATE_OUT);
		DEBUG_OFF(update, UPDATE_PREFIX);
	} else {
		TERM_DEBUG_OFF(update, UPDATE_IN);
		TERM_DEBUG_OFF(update, UPDATE_OUT);
		TERM_DEBUG_OFF(update, UPDATE_PREFIX);
		vty_out(vty, "BGP updates debugging is off\n");
	}
	return CMD_SUCCESS;
}

/* debug bgp zebra */
DEFUN (debug_bgp_zebra,
       debug_bgp_zebra_cmd,
       "debug bgp zebra",
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(zebra, ZEBRA);
	else {
		TERM_DEBUG_ON(zebra, ZEBRA);
		vty_out(vty, "BGP zebra debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_graceful_restart,
       debug_bgp_graceful_restart_cmd,
       "debug bgp graceful-restart",
       DEBUG_STR
       BGP_STR
       GR_DEBUG)
{
	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(graceful_restart, GRACEFUL_RESTART);
	} else {
		TERM_DEBUG_ON(graceful_restart, GRACEFUL_RESTART);
		vty_out(vty, "BGP Graceful Restart debugging is on\n");
	}
	return CMD_SUCCESS;
}


DEFPY (debug_bgp_zebra_prefix,
       debug_bgp_zebra_prefix_cmd,
       "debug bgp zebra prefix <A.B.C.D/M|X:X::X:X/M>$prefix",
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	if (!bgp_debug_zebra_prefixes)
		bgp_debug_zebra_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_zebra_prefixes, NULL, prefix,
				     NULL)) {
		vty_out(vty, "BGP zebra debugging is already enabled for %s\n",
			prefix_str);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_zebra_prefixes, NULL, prefix, NULL);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(zebra, ZEBRA);
	else {
		TERM_DEBUG_ON(zebra, ZEBRA);
		vty_out(vty, "BGP zebra debugging is on for %s\n", prefix_str);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_zebra,
       no_debug_bgp_zebra_cmd,
       "no debug bgp zebra",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n")
{
	bgp_debug_list_free(bgp_debug_zebra_prefixes);

	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(zebra, ZEBRA);
	else {
		TERM_DEBUG_OFF(zebra, ZEBRA);
		vty_out(vty, "BGP zebra debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_graceful_restart,
	no_debug_bgp_graceful_restart_cmd,
	"no debug bgp graceful-restart",
	DEBUG_STR
	BGP_STR
	GR_DEBUG
	NO_STR)
{
	if (vty->node == CONFIG_NODE) {
		DEBUG_OFF(graceful_restart, GRACEFUL_RESTART);
	} else {
		TERM_DEBUG_OFF(graceful_restart, GRACEFUL_RESTART);
		vty_out(vty, "BGP Graceful Restart debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFPY (no_debug_bgp_zebra_prefix,
       no_debug_bgp_zebra_prefix_cmd,
       "no debug bgp zebra prefix <A.B.C.D/M|X:X::X:X/M>$prefix",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	bool found_prefix = false;

	if (bgp_debug_zebra_prefixes
	    && !list_isempty(bgp_debug_zebra_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_zebra_prefixes, NULL, prefix);

		if (list_isempty(bgp_debug_zebra_prefixes)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_OFF(zebra, ZEBRA);
			else {
				TERM_DEBUG_OFF(zebra, ZEBRA);
				vty_out(vty, "BGP zebra debugging is off\n");
			}
		}
	}

	if (found_prefix)
		vty_out(vty, "BGP zebra debugging is off for %s\n", prefix_str);
	else
		vty_out(vty, "BGP zebra debugging was not enabled for %s\n",
			prefix_str);

	return CMD_SUCCESS;
}

/* debug bgp update-groups */
DEFUN (debug_bgp_update_groups,
       debug_bgp_update_groups_cmd,
       "debug bgp update-groups",
       DEBUG_STR
       BGP_STR
       "BGP update-groups\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(update_groups, UPDATE_GROUPS);
	else {
		TERM_DEBUG_ON(update_groups, UPDATE_GROUPS);
		vty_out(vty, "BGP update-groups debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update_groups,
       no_debug_bgp_update_groups_cmd,
       "no debug bgp update-groups",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP update-groups\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(update_groups, UPDATE_GROUPS);
	else {
		TERM_DEBUG_OFF(update_groups, UPDATE_GROUPS);
		vty_out(vty, "BGP update-groups debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_vpn,
       debug_bgp_vpn_cmd,
       "debug bgp vpn <leak-from-vrf|leak-to-vrf|rmap-event|label>",
       DEBUG_STR
       BGP_STR
       "VPN routes\n"
       "leaked from vrf to vpn\n"
       "leaked to vrf from vpn\n"
       "route-map updates\n"
       "labels\n")
{
	int idx = 3;

	if (argv_find(argv, argc, "leak-from-vrf", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_ON(vpn, VPN_LEAK_FROM_VRF);
		else
			TERM_DEBUG_ON(vpn, VPN_LEAK_FROM_VRF);
	} else if (argv_find(argv, argc, "leak-to-vrf", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_ON(vpn, VPN_LEAK_TO_VRF);
		else
			TERM_DEBUG_ON(vpn, VPN_LEAK_TO_VRF);
	} else if (argv_find(argv, argc, "rmap-event", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_ON(vpn, VPN_LEAK_RMAP_EVENT);
		else
			TERM_DEBUG_ON(vpn, VPN_LEAK_RMAP_EVENT);
	} else if (argv_find(argv, argc, "label", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_ON(vpn, VPN_LEAK_LABEL);
		else
			TERM_DEBUG_ON(vpn, VPN_LEAK_LABEL);
	} else {
		vty_out(vty, "%% unknown debug bgp vpn keyword\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (vty->node != CONFIG_NODE)
		vty_out(vty, "enabled debug bgp vpn %s\n", argv[idx]->text);

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_vpn,
       no_debug_bgp_vpn_cmd,
       "no debug bgp vpn <leak-from-vrf|leak-to-vrf|rmap-event|label>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "VPN routes\n"
       "leaked from vrf to vpn\n"
       "leaked to vrf from vpn\n"
       "route-map updates\n"
       "labels\n")
{
	int idx = 4;

	if (argv_find(argv, argc, "leak-from-vrf", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_OFF(vpn, VPN_LEAK_FROM_VRF);
		else
			TERM_DEBUG_OFF(vpn, VPN_LEAK_FROM_VRF);

	} else if (argv_find(argv, argc, "leak-to-vrf", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_OFF(vpn, VPN_LEAK_TO_VRF);
		else
			TERM_DEBUG_OFF(vpn, VPN_LEAK_TO_VRF);
	} else if (argv_find(argv, argc, "rmap-event", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_OFF(vpn, VPN_LEAK_RMAP_EVENT);
		else
			TERM_DEBUG_OFF(vpn, VPN_LEAK_RMAP_EVENT);
	} else if (argv_find(argv, argc, "label", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_OFF(vpn, VPN_LEAK_LABEL);
		else
			TERM_DEBUG_OFF(vpn, VPN_LEAK_LABEL);
	} else {
		vty_out(vty, "%% unknown debug bgp vpn keyword\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (vty->node != CONFIG_NODE)
		vty_out(vty, "disabled debug bgp vpn %s\n", argv[idx]->text);
	return CMD_SUCCESS;
}

/* debug bgp pbr */
DEFUN (debug_bgp_pbr,
       debug_bgp_pbr_cmd,
       "debug bgp pbr [error]",
       DEBUG_STR
       BGP_STR
       "BGP policy based routing\n"
       "BGP PBR error\n")
{
	int idx = 3;

	if (argv_find(argv, argc, "error", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_ON(pbr, PBR_ERROR);
		else {
			TERM_DEBUG_ON(pbr, PBR_ERROR);
			vty_out(vty, "BGP policy based routing error is on\n");
		}
		return CMD_SUCCESS;
	}
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(pbr, PBR);
	else {
		TERM_DEBUG_ON(pbr, PBR);
		vty_out(vty, "BGP policy based routing is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_pbr,
       no_debug_bgp_pbr_cmd,
       "no debug bgp pbr [error]",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP policy based routing\n"
       "BGP PBR Error\n")
{
	int idx = 3;

	if (argv_find(argv, argc, "error", &idx)) {
		if (vty->node == CONFIG_NODE)
			DEBUG_OFF(pbr, PBR_ERROR);
		else {
			TERM_DEBUG_OFF(pbr, PBR_ERROR);
			vty_out(vty, "BGP policy based routing error is off\n");
		}
		return CMD_SUCCESS;
	}
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(pbr, PBR);
	else {
		TERM_DEBUG_OFF(pbr, PBR);
		vty_out(vty, "BGP policy based routing is off\n");
	}
	return CMD_SUCCESS;
}

DEFPY (debug_bgp_evpn_mh,
       debug_bgp_evpn_mh_cmd,
       "[no$no] debug bgp evpn mh <es$es|route$rt>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "EVPN\n"
       "Multihoming\n"
       "Ethernet Segment debugging\n"
       "Route debugging\n")
{
	if (es) {
		if (vty->node == CONFIG_NODE) {
			if (no)
				DEBUG_OFF(evpn_mh, EVPN_MH_ES);
			else
				DEBUG_ON(evpn_mh, EVPN_MH_ES);
		} else {
			if (no) {
				TERM_DEBUG_OFF(evpn_mh, EVPN_MH_ES);
				vty_out(vty,
					"BGP EVPN-MH ES debugging is off\n");
			} else {
				TERM_DEBUG_ON(evpn_mh, EVPN_MH_ES);
				vty_out(vty,
					"BGP EVPN-MH ES debugging is on\n");
			}
		}
	}
	if (rt) {
		if (vty->node == CONFIG_NODE) {
			if (no)
				DEBUG_OFF(evpn_mh, EVPN_MH_RT);
			else
				DEBUG_ON(evpn_mh, EVPN_MH_RT);
		} else {
			if (no) {
				TERM_DEBUG_OFF(evpn_mh, EVPN_MH_RT);
				vty_out(vty,
					"BGP EVPN-MH route debugging is off\n");
			} else {
				TERM_DEBUG_ON(evpn_mh, EVPN_MH_RT);
				vty_out(vty,
					"BGP EVPN-MH route debugging is on\n");
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (debug_bgp_labelpool,
       debug_bgp_labelpool_cmd,
       "debug bgp labelpool",
       DEBUG_STR
       BGP_STR
       "label pool\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(labelpool, LABELPOOL);
	else
		TERM_DEBUG_ON(labelpool, LABELPOOL);

	if (vty->node != CONFIG_NODE)
		vty_out(vty, "enabled debug bgp labelpool\n");

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_labelpool,
       no_debug_bgp_labelpool_cmd,
       "no debug bgp labelpool",
       NO_STR
       DEBUG_STR
       BGP_STR
       "label pool\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(labelpool, LABELPOOL);
	else
		TERM_DEBUG_OFF(labelpool, LABELPOOL);


	if (vty->node != CONFIG_NODE)
		vty_out(vty, "disabled debug bgp labelpool\n");

	return CMD_SUCCESS;
}

DEFPY(debug_bgp_bfd, debug_bgp_bfd_cmd,
      "[no] debug bgp bfd",
      NO_STR
      DEBUG_STR
      BGP_STR
      "Bidirection Forwarding Detection\n")
{
	if (vty->node == CONFIG_NODE) {
		if (no) {
			DEBUG_OFF(bfd, BFD_LIB);
			bfd_protocol_integration_set_debug(false);
		} else {
			DEBUG_ON(bfd, BFD_LIB);
			bfd_protocol_integration_set_debug(true);
		}
	} else {
		if (no) {
			TERM_DEBUG_OFF(bfd, BFD_LIB);
			bfd_protocol_integration_set_debug(false);
		} else {
			TERM_DEBUG_ON(bfd, BFD_LIB);
			bfd_protocol_integration_set_debug(true);
		}
	}

	return CMD_SUCCESS;
}

DEFPY (debug_bgp_cond_adv,
       debug_bgp_cond_adv_cmd,
       "[no$no] debug bgp conditional-advertisement",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP conditional advertisement\n")
{
	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(cond_adv, COND_ADV);
		else
			DEBUG_ON(cond_adv, COND_ADV);
	} else {
		if (no) {
			TERM_DEBUG_OFF(cond_adv, COND_ADV);
			vty_out(vty,
				"BGP conditional advertisement debugging is off\n");
		} else {
			TERM_DEBUG_ON(cond_adv, COND_ADV);
			vty_out(vty,
				"BGP conditional advertisement debugging is on\n");
		}
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp,
       no_debug_bgp_cmd,
       "no debug bgp",
       NO_STR
       DEBUG_STR
       BGP_STR)
{
	struct bgp *bgp;
	struct listnode *ln;

	bgp_debug_list_free(bgp_debug_neighbor_events_peers);
	bgp_debug_list_free(bgp_debug_keepalive_peers);
	bgp_debug_list_free(bgp_debug_update_in_peers);
	bgp_debug_list_free(bgp_debug_update_out_peers);
	bgp_debug_list_free(bgp_debug_update_prefixes);
	bgp_debug_list_free(bgp_debug_bestpath_prefixes);
	bgp_debug_list_free(bgp_debug_zebra_prefixes);

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, ln, bgp))
		bgp_debug_clear_updgrp_update_dbg(bgp);

	TERM_DEBUG_OFF(keepalive, KEEPALIVE);
	TERM_DEBUG_OFF(update, UPDATE_IN);
	TERM_DEBUG_OFF(update, UPDATE_OUT);
	TERM_DEBUG_OFF(update, UPDATE_PREFIX);
	TERM_DEBUG_OFF(bestpath, BESTPATH);
	TERM_DEBUG_OFF(as4, AS4);
	TERM_DEBUG_OFF(as4, AS4_SEGMENT);
	TERM_DEBUG_OFF(neighbor_events, NEIGHBOR_EVENTS);
	TERM_DEBUG_OFF(zebra, ZEBRA);
	TERM_DEBUG_OFF(nht, NHT);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_FROM_VRF);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_TO_VRF);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_RMAP_EVENT);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_LABEL);
	TERM_DEBUG_OFF(flowspec, FLOWSPEC);
	TERM_DEBUG_OFF(labelpool, LABELPOOL);
	TERM_DEBUG_OFF(pbr, PBR);
	TERM_DEBUG_OFF(pbr, PBR_ERROR);
	TERM_DEBUG_OFF(graceful_restart, GRACEFUL_RESTART);
	TERM_DEBUG_OFF(evpn_mh, EVPN_MH_ES);
	TERM_DEBUG_OFF(evpn_mh, EVPN_MH_RT);
	TERM_DEBUG_OFF(bfd, BFD_LIB);
	TERM_DEBUG_OFF(cond_adv, COND_ADV);

	vty_out(vty, "All possible debugging has been turned off\n");

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_bgp,
	    show_debugging_bgp_cmd,
	    "show debugging [bgp]",
	    SHOW_STR
	    DEBUG_STR
	    BGP_STR)
{
	vty_out(vty, "BGP debugging status:\n");

	if (BGP_DEBUG(as4, AS4))
		vty_out(vty, "  BGP as4 debugging is on\n");

	if (BGP_DEBUG(as4, AS4_SEGMENT))
		vty_out(vty, "  BGP as4 aspath segment debugging is on\n");

	if (BGP_DEBUG(bestpath, BESTPATH))
		bgp_debug_list_print(vty, "  BGP bestpath debugging is on",
				     bgp_debug_bestpath_prefixes);

	if (BGP_DEBUG(keepalive, KEEPALIVE))
		bgp_debug_list_print(vty, "  BGP keepalives debugging is on",
				     bgp_debug_keepalive_peers);

	if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
		bgp_debug_list_print(vty,
				     "  BGP neighbor-events debugging is on",
				     bgp_debug_neighbor_events_peers);

	if (BGP_DEBUG(nht, NHT))
		vty_out(vty, "  BGP next-hop tracking debugging is on\n");

	if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
		vty_out(vty, "  BGP update-groups debugging is on\n");

	if (BGP_DEBUG(update, UPDATE_PREFIX))
		bgp_debug_list_print(vty, "  BGP updates debugging is on",
				     bgp_debug_update_prefixes);

	if (BGP_DEBUG(update, UPDATE_IN))
		bgp_debug_list_print(vty,
				     "  BGP updates debugging is on (inbound)",
				     bgp_debug_update_in_peers);

	if (BGP_DEBUG(update, UPDATE_OUT))
		bgp_debug_list_print(vty,
				     "  BGP updates debugging is on (outbound)",
				     bgp_debug_update_out_peers);

	if (BGP_DEBUG(zebra, ZEBRA))
		bgp_debug_list_print(vty, "  BGP zebra debugging is on",
				     bgp_debug_zebra_prefixes);

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		vty_out(vty, "  BGP graceful-restart debugging is on\n");

	if (BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF))
		vty_out(vty,
			"  BGP route leak from vrf to vpn debugging is on\n");
	if (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF))
		vty_out(vty,
			"  BGP route leak to vrf from vpn debugging is on\n");
	if (BGP_DEBUG(vpn, VPN_LEAK_RMAP_EVENT))
		vty_out(vty, "  BGP vpn route-map event debugging is on\n");
	if (BGP_DEBUG(vpn, VPN_LEAK_LABEL))
		vty_out(vty, "  BGP vpn label event debugging is on\n");
	if (BGP_DEBUG(flowspec, FLOWSPEC))
		vty_out(vty, "  BGP flowspec debugging is on\n");
	if (BGP_DEBUG(labelpool, LABELPOOL))
		vty_out(vty, "  BGP labelpool debugging is on\n");

	if (BGP_DEBUG(pbr, PBR))
		vty_out(vty, "  BGP policy based routing debugging is on\n");
	if (BGP_DEBUG(pbr, PBR_ERROR))
		vty_out(vty, "  BGP policy based routing error debugging is on\n");

	if (BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		vty_out(vty, "  BGP EVPN-MH ES debugging is on\n");
	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
		vty_out(vty, "  BGP EVPN-MH route debugging is on\n");

	if (BGP_DEBUG(bfd, BFD_LIB))
		vty_out(vty, "  BGP BFD library debugging is on\n");

	if (BGP_DEBUG(cond_adv, COND_ADV))
		vty_out(vty,
			"  BGP conditional advertisement debugging is on\n");

	cmd_show_lib_debugs(vty);

	hook_call(bgp_hook_config_write_debug, vty, false);

	return CMD_SUCCESS;
}

static int bgp_config_write_debug(struct vty *vty)
{
	int write = 0;

	if (CONF_BGP_DEBUG(as4, AS4)) {
		vty_out(vty, "debug bgp as4\n");
		write++;
	}

	if (CONF_BGP_DEBUG(as4, AS4_SEGMENT)) {
		vty_out(vty, "debug bgp as4 segment\n");
		write++;
	}

	if (CONF_BGP_DEBUG(bestpath, BESTPATH)) {
		write += bgp_debug_list_conf_print(vty, "debug bgp bestpath",
						   bgp_debug_bestpath_prefixes);
	}

	if (CONF_BGP_DEBUG(keepalive, KEEPALIVE)) {
		write += bgp_debug_list_conf_print(vty, "debug bgp keepalives",
						   bgp_debug_keepalive_peers);
	}

	if (CONF_BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)) {
		write += bgp_debug_list_conf_print(
			vty, "debug bgp neighbor-events",
			bgp_debug_neighbor_events_peers);
	}

	if (CONF_BGP_DEBUG(nht, NHT)) {
		vty_out(vty, "debug bgp nht\n");
		write++;
	}

	if (CONF_BGP_DEBUG(update_groups, UPDATE_GROUPS)) {
		vty_out(vty, "debug bgp update-groups\n");
		write++;
	}

	if (CONF_BGP_DEBUG(update, UPDATE_PREFIX)) {
		write += bgp_debug_list_conf_print(vty,
						   "debug bgp updates prefix",
						   bgp_debug_update_prefixes);
	}

	if (CONF_BGP_DEBUG(update, UPDATE_IN)) {
		write += bgp_debug_list_conf_print(vty, "debug bgp updates in",
						   bgp_debug_update_in_peers);
	}

	if (CONF_BGP_DEBUG(update, UPDATE_OUT)) {
		write += bgp_debug_list_conf_print(vty, "debug bgp updates out",
						   bgp_debug_update_out_peers);
	}

	if (CONF_BGP_DEBUG(update, UPDATE_DETAIL)) {
		vty_out(vty, "debug bgp updates detail\n");
		write++;
	}

	if (CONF_BGP_DEBUG(zebra, ZEBRA)) {
		if (!bgp_debug_zebra_prefixes
		    || list_isempty(bgp_debug_zebra_prefixes)) {
			vty_out(vty, "debug bgp zebra\n");
			write++;
		} else {
			write += bgp_debug_list_conf_print(
				vty, "debug bgp zebra prefix",
				bgp_debug_zebra_prefixes);
		}
	}

	if (CONF_BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF)) {
		vty_out(vty, "debug bgp vpn leak-from-vrf\n");
		write++;
	}
	if (CONF_BGP_DEBUG(vpn, VPN_LEAK_TO_VRF)) {
		vty_out(vty, "debug bgp vpn leak-to-vrf\n");
		write++;
	}
	if (CONF_BGP_DEBUG(vpn, VPN_LEAK_RMAP_EVENT)) {
		vty_out(vty, "debug bgp vpn rmap-event\n");
		write++;
	}
	if (CONF_BGP_DEBUG(vpn, VPN_LEAK_LABEL)) {
		vty_out(vty, "debug bgp vpn label\n");
		write++;
	}
	if (CONF_BGP_DEBUG(flowspec, FLOWSPEC)) {
		vty_out(vty, "debug bgp flowspec\n");
		write++;
	}
	if (CONF_BGP_DEBUG(labelpool, LABELPOOL)) {
		vty_out(vty, "debug bgp labelpool\n");
		write++;
	}

	if (CONF_BGP_DEBUG(pbr, PBR)) {
		vty_out(vty, "debug bgp pbr\n");
		write++;
	}
	if (CONF_BGP_DEBUG(pbr, PBR_ERROR)) {
		vty_out(vty, "debug bgp pbr error\n");
		write++;
	}

	if (CONF_BGP_DEBUG(graceful_restart, GRACEFUL_RESTART)) {
		vty_out(vty, "debug bgp graceful-restart\n");
		write++;
	}

	if (CONF_BGP_DEBUG(evpn_mh, EVPN_MH_ES)) {
		vty_out(vty, "debug bgp evpn mh es\n");
		write++;
	}
	if (CONF_BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
		vty_out(vty, "debug bgp evpn mh route\n");
		write++;
	}

	if (CONF_BGP_DEBUG(bfd, BFD_LIB)) {
		vty_out(vty, "debug bgp bfd\n");
		write++;
	}

	if (CONF_BGP_DEBUG(cond_adv, COND_ADV)) {
		vty_out(vty, "debug bgp conditional-advertisement\n");
		write++;
	}

	if (hook_call(bgp_hook_config_write_debug, vty, true))
		write++;

	return write;
}

static int bgp_config_write_debug(struct vty *vty);
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = bgp_config_write_debug,
};

void bgp_debug_init(void)
{
	install_node(&debug_node);

	install_element(ENABLE_NODE, &show_debugging_bgp_cmd);

	install_element(ENABLE_NODE, &debug_bgp_as4_cmd);
	install_element(CONFIG_NODE, &debug_bgp_as4_cmd);
	install_element(ENABLE_NODE, &debug_bgp_as4_segment_cmd);
	install_element(CONFIG_NODE, &debug_bgp_as4_segment_cmd);

	install_element(ENABLE_NODE, &debug_bgp_neighbor_events_cmd);
	install_element(CONFIG_NODE, &debug_bgp_neighbor_events_cmd);
	install_element(ENABLE_NODE, &debug_bgp_nht_cmd);
	install_element(CONFIG_NODE, &debug_bgp_nht_cmd);
	install_element(ENABLE_NODE, &debug_bgp_keepalive_cmd);
	install_element(CONFIG_NODE, &debug_bgp_keepalive_cmd);
	install_element(ENABLE_NODE, &debug_bgp_update_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_cmd);
	install_element(ENABLE_NODE, &debug_bgp_update_detail_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_detail_cmd);
	install_element(ENABLE_NODE, &debug_bgp_zebra_cmd);
	install_element(CONFIG_NODE, &debug_bgp_zebra_cmd);
	install_element(ENABLE_NODE, &debug_bgp_update_groups_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_groups_cmd);
	install_element(ENABLE_NODE, &debug_bgp_bestpath_prefix_cmd);
	install_element(CONFIG_NODE, &debug_bgp_bestpath_prefix_cmd);

	install_element(ENABLE_NODE, &debug_bgp_graceful_restart_cmd);
	install_element(CONFIG_NODE, &debug_bgp_graceful_restart_cmd);

	/* debug bgp updates (in|out) */
	install_element(ENABLE_NODE, &debug_bgp_update_direct_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_direct_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_direct_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_direct_cmd);

	/* debug bgp updates (in|out) A.B.C.D */
	install_element(ENABLE_NODE, &debug_bgp_update_direct_peer_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_direct_peer_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_direct_peer_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_direct_peer_cmd);

	/* debug bgp updates prefix A.B.C.D/M */
	install_element(ENABLE_NODE, &debug_bgp_update_prefix_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_prefix_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_prefix_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_prefix_cmd);
	install_element(ENABLE_NODE, &debug_bgp_update_prefix_afi_safi_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_prefix_afi_safi_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_prefix_afi_safi_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_prefix_afi_safi_cmd);

	/* debug bgp zebra prefix A.B.C.D/M */
	install_element(ENABLE_NODE, &debug_bgp_zebra_prefix_cmd);
	install_element(CONFIG_NODE, &debug_bgp_zebra_prefix_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_zebra_prefix_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_zebra_prefix_cmd);

	install_element(ENABLE_NODE, &no_debug_bgp_as4_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_as4_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_as4_segment_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_as4_segment_cmd);

	/* debug bgp neighbor-events A.B.C.D */
	install_element(ENABLE_NODE, &debug_bgp_neighbor_events_peer_cmd);
	install_element(CONFIG_NODE, &debug_bgp_neighbor_events_peer_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_neighbor_events_peer_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_neighbor_events_peer_cmd);

	/* debug bgp keepalive A.B.C.D */
	install_element(ENABLE_NODE, &debug_bgp_keepalive_peer_cmd);
	install_element(CONFIG_NODE, &debug_bgp_keepalive_peer_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_keepalive_peer_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_keepalive_peer_cmd);

	install_element(ENABLE_NODE, &no_debug_bgp_neighbor_events_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_neighbor_events_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_nht_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_nht_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_keepalive_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_keepalive_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_groups_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_groups_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_bestpath_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_bestpath_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_bestpath_prefix_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_bestpath_prefix_cmd);

	install_element(ENABLE_NODE, &no_debug_bgp_graceful_restart_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_graceful_restart_cmd);

	install_element(ENABLE_NODE, &debug_bgp_vpn_cmd);
	install_element(CONFIG_NODE, &debug_bgp_vpn_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_vpn_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_vpn_cmd);

	install_element(ENABLE_NODE, &debug_bgp_labelpool_cmd);
	install_element(CONFIG_NODE, &debug_bgp_labelpool_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_labelpool_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_labelpool_cmd);

	/* debug bgp pbr */
	install_element(ENABLE_NODE, &debug_bgp_pbr_cmd);
	install_element(CONFIG_NODE, &debug_bgp_pbr_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_pbr_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_pbr_cmd);

	install_element(ENABLE_NODE, &debug_bgp_evpn_mh_cmd);
	install_element(CONFIG_NODE, &debug_bgp_evpn_mh_cmd);

	/* debug bgp bfd */
	install_element(ENABLE_NODE, &debug_bgp_bfd_cmd);
	install_element(CONFIG_NODE, &debug_bgp_bfd_cmd);

	/* debug bgp conditional advertisement */
	install_element(ENABLE_NODE, &debug_bgp_cond_adv_cmd);
	install_element(CONFIG_NODE, &debug_bgp_cond_adv_cmd);
}

/* Return true if this prefix is on the per_prefix_list of prefixes to debug
 * for BGP_DEBUG_TYPE
 */
static int bgp_debug_per_prefix(const struct prefix *p,
				unsigned long term_bgp_debug_type,
				unsigned int BGP_DEBUG_TYPE,
				struct list *per_prefix_list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	if (term_bgp_debug_type & BGP_DEBUG_TYPE) {
		/* We are debugging all prefixes so return true */
		if (!per_prefix_list || list_isempty(per_prefix_list))
			return 1;

		else {
			if (!p)
				return 0;

			for (ALL_LIST_ELEMENTS(per_prefix_list, node, nnode,
					       filter))
				if (filter->p->prefixlen == p->prefixlen
				    && prefix_match(filter->p, p))
					return 1;

			return 0;
		}
	}

	return 0;
}

/* Return true if this peer is on the per_peer_list of peers to debug
 * for BGP_DEBUG_TYPE
 */
static bool bgp_debug_per_peer(char *host, const struct prefix *p,
			       unsigned long term_bgp_debug_type,
			       unsigned int BGP_DEBUG_TYPE,
			       struct list *per_peer_list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	if (term_bgp_debug_type & BGP_DEBUG_TYPE) {
		/* We are debugging all peers so return true */
		if (!per_peer_list || list_isempty(per_peer_list))
			return true;

		if (!host)
			return false;

		for (ALL_LIST_ELEMENTS(per_peer_list, node, nnode, filter))
			if (strmatch(filter->host, host) &&
			    filter->plist_name && p) {
				struct prefix_list *plist;
				afi_t afi = family2afi(p->family);

				plist = (afi == AFI_IP) ? filter->plist_v4
							: filter->plist_v6;

				if (!plist)
					continue;

				return prefix_list_apply(plist, p) ==
				       PREFIX_PERMIT;
			} else if (strmatch(filter->host, host)) {
				return true;
			}

		return false;
	}

	return false;
}

bool bgp_debug_neighbor_events(const struct peer *peer)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	return bgp_debug_per_peer(host, NULL, term_bgp_debug_neighbor_events,
				  BGP_DEBUG_NEIGHBOR_EVENTS,
				  bgp_debug_neighbor_events_peers);
}

bool bgp_debug_keepalive(const struct peer *peer)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	return bgp_debug_per_peer(host, NULL, term_bgp_debug_keepalive,
				  BGP_DEBUG_KEEPALIVE,
				  bgp_debug_keepalive_peers);
}

bool bgp_debug_update(const struct peer *peer, const struct prefix *p,
		      struct update_group *updgrp, unsigned int inbound)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	if (inbound) {
		if (bgp_debug_per_peer(host, p, term_bgp_debug_update,
				       BGP_DEBUG_UPDATE_IN,
				       bgp_debug_update_in_peers))
			return true;
	}

	/* outbound */
	else {
		if (bgp_debug_per_peer(host, p, term_bgp_debug_update,
				       BGP_DEBUG_UPDATE_OUT,
				       bgp_debug_update_out_peers))
			return true;

		/* Check if update debugging implicitly enabled for the group.
		 */
		if (updgrp && UPDGRP_DBG_ON(updgrp))
			return true;
	}


	if (BGP_DEBUG(update, UPDATE_PREFIX)) {
		if (bgp_debug_per_prefix(p, term_bgp_debug_update,
					 BGP_DEBUG_UPDATE_PREFIX,
					 bgp_debug_update_prefixes))
			return true;
	}

	return false;
}

bool bgp_debug_bestpath(struct bgp_dest *dest)
{
	if (BGP_DEBUG(bestpath, BESTPATH)) {
		if (bgp_debug_per_prefix(
			    bgp_dest_get_prefix(dest), term_bgp_debug_bestpath,
			    BGP_DEBUG_BESTPATH, bgp_debug_bestpath_prefixes))
			return true;
	}

	return false;
}

bool bgp_debug_zebra(const struct prefix *p)
{
	if (BGP_DEBUG(zebra, ZEBRA)) {
		if (bgp_debug_per_prefix(p, term_bgp_debug_zebra,
					 BGP_DEBUG_ZEBRA,
					 bgp_debug_zebra_prefixes))
			return true;
	}

	return false;
}

const char *bgp_debug_rdpfxpath2str(afi_t afi, safi_t safi,
				    const struct prefix_rd *prd,
				    union prefixconstptr pu,
				    mpls_label_t *label, uint8_t num_labels,
				    int addpath_valid, uint32_t addpath_id,
				    struct bgp_route_evpn *overlay_index,
				    char *str, int size)
{
	char tag_buf[30];
	char overlay_index_buf[INET6_ADDRSTRLEN + 14];
	const struct prefix_evpn *evp;
	int len = 0;

	/* ' with addpath ID '          17
	 * max strlen of uint32       + 10
	 * +/- (just in case)         +  1
	 * null terminator            +  1
	 * ============================ 29 */
	char pathid_buf[30];

	if (size < BGP_PRD_PATH_STRLEN)
		return NULL;

	/* Note: Path-id is created by default, but only included in update
	 * sometimes. */
	pathid_buf[0] = '\0';
	if (addpath_valid)
		snprintf(pathid_buf, sizeof(pathid_buf), " with addpath ID %u",
			 addpath_id);

	overlay_index_buf[0] = '\0';
	if (overlay_index && overlay_index->type == OVERLAY_INDEX_GATEWAY_IP) {
		char obuf[INET6_ADDRSTRLEN];

		obuf[0] = '\0';
		evp = pu.evp;
		if (is_evpn_prefix_ipaddr_v4(evp))
			inet_ntop(AF_INET, &overlay_index->gw_ip, obuf,
				  sizeof(obuf));
		else if (is_evpn_prefix_ipaddr_v6(evp))
			inet_ntop(AF_INET6, &overlay_index->gw_ip, obuf,
				  sizeof(obuf));

		snprintf(overlay_index_buf, sizeof(overlay_index_buf),
			 " gateway IP %s", obuf);
	}

	tag_buf[0] = '\0';
	if (bgp_labeled_safi(safi) && num_labels) {

		if (safi == SAFI_EVPN) {
			char tag_buf2[20];

			bgp_evpn_label2str(label, num_labels, tag_buf2, 20);
			snprintf(tag_buf, sizeof(tag_buf), " label %s",
				 tag_buf2);
		} else {
			uint32_t label_value;

			label_value = decode_label(label);
			snprintf(tag_buf, sizeof(tag_buf), " label %u",
				 label_value);
		}
	}

	if (prd) {
		len += snprintfrr(str + len, size - len, "RD ");
		len += snprintfrr(str + len, size - len,
				  BGP_RD_AS_FORMAT(bgp_get_asnotation(NULL)),
				  prd);
		snprintfrr(str + len, size - len, " %pFX%s%s%s %s %s", pu.p,
			   overlay_index_buf, tag_buf, pathid_buf, afi2str(afi),
			   safi2str(safi));
	} else if (safi == SAFI_FLOWSPEC) {
		char return_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
		const struct prefix_fs *fs = pu.fs;

		bgp_fs_nlri_get_string((unsigned char *)fs->prefix.ptr,
				       fs->prefix.prefixlen,
				       return_string,
				       NLRI_STRING_FORMAT_DEBUG, NULL,
				       family2afi(fs->prefix.family));
		snprintf(str, size, "FS %s Match{%s}", afi2str(afi),
			 return_string);
	} else
		snprintfrr(str, size, "%pFX%s%s %s %s", pu.p, tag_buf,
			   pathid_buf, afi2str(afi), safi2str(safi));

	return str;
}
