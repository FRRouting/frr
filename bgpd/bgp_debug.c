/* BGP-4, BGP-4+ packet debug routine
 * Copyright (C) 1996, 97, 99 Kunihiro Ishiguro
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

#include <lib/version.h>
#include "prefix.h"
#include "linklist.h"
#include "stream.h"
#include "command.h"
#include "log.h"
#include "sockunion.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_flowspec.h"

unsigned long conf_bgp_debug_as4;
unsigned long conf_bgp_debug_neighbor_events;
unsigned long conf_bgp_debug_events;
unsigned long conf_bgp_debug_packet;
unsigned long conf_bgp_debug_filter;
unsigned long conf_bgp_debug_keepalive;
unsigned long conf_bgp_debug_update;
unsigned long conf_bgp_debug_bestpath;
unsigned long conf_bgp_debug_zebra;
unsigned long conf_bgp_debug_allow_martians;
unsigned long conf_bgp_debug_nht;
unsigned long conf_bgp_debug_update_groups;
unsigned long conf_bgp_debug_vpn;
unsigned long conf_bgp_debug_flowspec;
unsigned long conf_bgp_debug_labelpool;
unsigned long conf_bgp_debug_pbr;

unsigned long term_bgp_debug_as4;
unsigned long term_bgp_debug_neighbor_events;
unsigned long term_bgp_debug_events;
unsigned long term_bgp_debug_packet;
unsigned long term_bgp_debug_filter;
unsigned long term_bgp_debug_keepalive;
unsigned long term_bgp_debug_update;
unsigned long term_bgp_debug_bestpath;
unsigned long term_bgp_debug_zebra;
unsigned long term_bgp_debug_allow_martians;
unsigned long term_bgp_debug_nht;
unsigned long term_bgp_debug_update_groups;
unsigned long term_bgp_debug_vpn;
unsigned long term_bgp_debug_flowspec;
unsigned long term_bgp_debug_labelpool;
unsigned long term_bgp_debug_pbr;

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
const char *bgp_type_str[] = {NULL,	   "OPEN",      "UPDATE",
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
	{BGP_NOTIFY_CAPABILITY_ERR, "CAPABILITY Message Error"},
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
	{BGP_NOTIFY_OPEN_AUTH_FAILURE, "/Authentication Failure"},
	{BGP_NOTIFY_OPEN_UNACEP_HOLDTIME, "/Unacceptable Hold Time"},
	{BGP_NOTIFY_OPEN_UNSUP_CAPBL, "/Unsupported Capability"},
	{0}};

static const struct message bgp_notify_update_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_UPDATE_MAL_ATTR, "/Malformed Attribute List"},
	{BGP_NOTIFY_UPDATE_UNREC_ATTR, "/Unrecognized Well-known Attribute"},
	{BGP_NOTIFY_UPDATE_MISS_ATTR, "/Missing Well-known Attribute"},
	{BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR, "/Attribute Flags Error"},
	{BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, "/Attribute Length Error"},
	{BGP_NOTIFY_UPDATE_INVAL_ORIGIN, "/Invalid ORIGIN Attribute"},
	{BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP, "/AS Routing Loop"},
	{BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP, "/Invalid NEXT_HOP Attribute"},
	{BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, "/Optional Attribute Error"},
	{BGP_NOTIFY_UPDATE_INVAL_NETWORK, "/Invalid Network Field"},
	{BGP_NOTIFY_UPDATE_MAL_AS_PATH, "/Malformed AS_PATH"},
	{0}};

static const struct message bgp_notify_cease_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_CEASE_MAX_PREFIX, "/Maximum Number of Prefixes Reached"},
	{BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN, "/Administratively Shutdown"},
	{BGP_NOTIFY_CEASE_PEER_UNCONFIG, "/Peer Unconfigured"},
	{BGP_NOTIFY_CEASE_ADMIN_RESET, "/Administratively Reset"},
	{BGP_NOTIFY_CEASE_CONNECT_REJECT, "/Connection Rejected"},
	{BGP_NOTIFY_CEASE_CONFIG_CHANGE, "/Other Configuration Change"},
	{BGP_NOTIFY_CEASE_COLLISION_RESOLUTION,
	 "/Connection collision resolution"},
	{BGP_NOTIFY_CEASE_OUT_OF_RESOURCE, "/Out of Resource"},
	{0}};

static const struct message bgp_notify_capability_msg[] = {
	{BGP_NOTIFY_SUBCODE_UNSPECIFIC, "/Unspecific"},
	{BGP_NOTIFY_CAPABILITY_INVALID_ACTION, "/Invalid Action Value"},
	{BGP_NOTIFY_CAPABILITY_INVALID_LENGTH, "/Invalid Capability Length"},
	{BGP_NOTIFY_CAPABILITY_MALFORMED_CODE, "/Malformed Capability Value"},
	{0}};

/* Origin strings. */
const char *bgp_origin_str[] = {"i", "e", "?"};
const char *bgp_origin_long_str[] = {"IGP", "EGP", "incomplete"};

static int bgp_debug_print_evpn_prefix(struct vty *vty, const char *desc,
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

			if (filter->p)
				prefix_free(&filter->p);

			if (filter->host)
				XFREE(MTYPE_BGP_DEBUG_STR, filter->host);

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
	char buf[PREFIX2STR_BUFFER];

	vty_out(vty, "%s", desc);

	if (list && !list_isempty(list)) {
		vty_out(vty, " for");
		for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
			if (filter->host)
				vty_out(vty, " %s", filter->host);

			if (filter->p && filter->p->family == AF_EVPN)
				bgp_debug_print_evpn_prefix(vty, "", filter->p);
			else if (filter->p) {
				prefix2str(filter->p, buf, sizeof(buf));
				vty_out(vty, " %s", buf);
			}
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
	char buf[PREFIX2STR_BUFFER];
	int write = 0;

	if (list && !list_isempty(list)) {
		for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
			if (filter->host) {
				vty_out(vty, "%s %s\n", desc, filter->host);
				write++;
			}

			if (filter->p && filter->p->family == AF_EVPN) {
				bgp_debug_print_evpn_prefix(vty, desc,
							    filter->p);
				write++;
			} else if (filter->p) {
				prefix2str(filter->p, buf, sizeof(buf));
				vty_out(vty, "%s %s\n", desc, buf);
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
				     const struct prefix *p)
{
	struct bgp_debug_filter *filter;

	filter = XCALLOC(MTYPE_BGP_DEBUG_FILTER,
			 sizeof(struct bgp_debug_filter));

	if (host) {
		filter->host = XSTRDUP(MTYPE_BGP_DEBUG_STR, host);
		filter->p = NULL;
	} else if (p) {
		filter->host = NULL;
		filter->p = prefix_new();
		prefix_copy(filter->p, p);
	}

	listnode_add(list, filter);
}

static int bgp_debug_list_remove_entry(struct list *list, const char *host,
				       struct prefix *p)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
		if (host && strcmp(filter->host, host) == 0) {
			listnode_delete(list, filter);
			XFREE(MTYPE_BGP_DEBUG_STR, filter->host);
			XFREE(MTYPE_BGP_DEBUG_FILTER, filter);
			return 1;
		} else if (p && filter->p->prefixlen == p->prefixlen
			   && prefix_match(filter->p, p)) {
			listnode_delete(list, filter);
			prefix_free(&filter->p);
			XFREE(MTYPE_BGP_DEBUG_FILTER, filter);
			return 1;
		}
	}

	return 0;
}

static int bgp_debug_list_has_entry(struct list *list, const char *host,
				    const struct prefix *p)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(list, node, nnode, filter)) {
		if (host) {
			if (strcmp(filter->host, host) == 0) {
				return 1;
			}
		} else if (p) {
			if (filter->p->prefixlen == p->prefixlen
			    && prefix_match(filter->p, p)) {
				return 1;
			}
		}
	}

	return 0;
}

int bgp_debug_peer_updout_enabled(char *host)
{
	return (bgp_debug_list_has_entry(bgp_debug_update_out_peers, host,
					 NULL));
}

/* Dump attribute. */
int bgp_dump_attr(struct attr *attr, char *buf, size_t size)
{
	char addrbuf[BUFSIZ];

	if (!attr)
		return 0;

	buf[0] = '\0';

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)))
		snprintf(buf, size, "nexthop %s", inet_ntoa(attr->nexthop));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGIN)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", origin %s",
			 bgp_origin_str[attr->origin]);

	/* Add MP case. */
	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", mp_nexthop %s",
			 inet_ntop(AF_INET6, &attr->mp_nexthop_global, addrbuf,
				   BUFSIZ));

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
		snprintf(buf + strlen(buf), size - strlen(buf), "(%s)",
			 inet_ntop(AF_INET6, &attr->mp_nexthop_local, addrbuf,
				   BUFSIZ));

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4)
		snprintf(buf, size, "nexthop %s", inet_ntoa(attr->nexthop));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", localpref %u", attr->local_pref);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", metric %u",
			 attr->med);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", community %s",
			 community_str(attr->community, false));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", extcommunity %s", ecommunity_str(attr->ecommunity));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", atomic-aggregate");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", aggregated by %u %s", attr->aggregator_as,
			 inet_ntoa(attr->aggregator_addr));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", originator %s", inet_ntoa(attr->originator_id));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))) {
		int i;

		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", clusterlist");
		for (i = 0; i < attr->cluster->length / 4; i++)
			snprintf(buf + strlen(buf), size - strlen(buf), " %s",
				 inet_ntoa(attr->cluster->list[i]));
	}

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL)))
		snprintf(buf + strlen(buf), size - strlen(buf),
			 ", pmsi tnltype %u", attr->pmsi_tnl_type);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH)))
		snprintf(buf + strlen(buf), size - strlen(buf), ", path %s",
			 aspath_print(attr->aspath));

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID))) {
		if (attr->label_index != BGP_INVALID_LABEL_INDEX)
			snprintf(buf + strlen(buf), size - strlen(buf),
				 ", label-index %u", attr->label_index);
	}

	if (strlen(buf) > 1)
		return 1;
	else
		return 0;
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
		break;
	case BGP_NOTIFY_FSM_ERR:
		break;
	case BGP_NOTIFY_CEASE:
		return lookup_msg(bgp_notify_cease_msg, subcode,
				  "Unrecognized Error Subcode");
	case BGP_NOTIFY_CAPABILITY_ERR:
		return lookup_msg(bgp_notify_capability_msg, subcode,
				  "Unrecognized Error Subcode");
	}
	return "";
}

/* extract notify admin reason if correctly present */
const char *bgp_notify_admin_message(char *buf, size_t bufsz, uint8_t *data,
				     size_t datalen)
{
	if (!data || datalen < 1)
		return NULL;

	uint8_t len = data[0];
	if (len > 128 || len > datalen - 1)
		return NULL;

	return zlog_sanitize(buf, bufsz, data + 1, len);
}

/* dump notify packet */
void bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify,
		      const char *direct)
{
	const char *subcode_str;
	const char *code_str;
	const char *msg_str = NULL;
	char msg_buf[1024];

	if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)
	    || bgp_flag_check(peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
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
				"%%NOTIFICATION: %s neighbor %s %d/%d (%s%s) \"%s\"",
				strcmp(direct, "received") == 0
					? "received from"
					: "sent to",
				peer->host, bgp_notify->code,
				bgp_notify->subcode, code_str, subcode_str,
				msg_str);
		} else {
			msg_str = bgp_notify->data ? bgp_notify->data : "";
			zlog_info(
				"%%NOTIFICATION: %s neighbor %s %d/%d (%s%s) %d bytes %s",
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

static int bgp_debug_print_evpn_prefix(struct vty *vty, const char *desc,
				       struct prefix *p)
{
	char evpn_desc[PREFIX2STR_BUFFER + INET_ADDRSTRLEN];
	char buf[PREFIX2STR_BUFFER];
	char buf2[ETHER_ADDR_STRLEN];

	if (p->u.prefix_evpn.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (is_evpn_prefix_ipaddr_none((struct prefix_evpn *)p)) {
			sprintf(evpn_desc, "l2vpn evpn type macip mac %s",
				 prefix_mac2str(
					&p->u.prefix_evpn.macip_addr.mac,
					buf2, sizeof(buf2)));
		} else {
			uint8_t family = is_evpn_prefix_ipaddr_v4(
						(struct prefix_evpn *)p) ?
							AF_INET : AF_INET6;
			sprintf(evpn_desc, "l2vpn evpn type macip mac %s ip %s",
				 prefix_mac2str(
					&p->u.prefix_evpn.macip_addr.mac,
					buf2, sizeof(buf2)),
				 inet_ntop(family,
					&p->u.prefix_evpn.macip_addr.ip.ip.addr,
					buf, PREFIX2STR_BUFFER));
		}
	} else if (p->u.prefix_evpn.route_type == BGP_EVPN_IMET_ROUTE) {
		sprintf(evpn_desc, "l2vpn evpn type multicast ip %s",
			inet_ntoa(p->u.prefix_evpn.imet_addr.ip.ipaddr_v4));
	} else if (p->u.prefix_evpn.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		uint8_t family = is_evpn_prefix_ipaddr_v4(
					(struct prefix_evpn *)p) ? AF_INET
								: AF_INET6;
		sprintf(evpn_desc, "l2vpn evpn type prefix ip %s/%d",
			inet_ntop(family,
				  &p->u.prefix_evpn.prefix_addr.ip.ip.addr, buf,
				  PREFIX2STR_BUFFER),
			p->u.prefix_evpn.prefix_addr.ip_prefix_length);
	}

	vty_out(vty, "%s %s\n", desc, evpn_desc);

	return 0;
}

static int bgp_debug_parse_evpn_prefix(struct vty *vty, struct cmd_token **argv,
				       int argc, struct prefix **argv_pp)
{
	struct prefix *argv_p;
	struct ethaddr mac;
	struct ipaddr ip;
	int evpn_type;
	int type_idx = 0;
	int mac_idx = 0;
	int ip_idx = 0;

	argv_p = *argv_pp;

	if (argv_find(argv, argc, "macip", &type_idx))
		evpn_type = BGP_EVPN_MAC_IP_ROUTE;
	else if (argv_find(argv, argc, "multicast", &type_idx))
		evpn_type = BGP_EVPN_IMET_ROUTE;
	else if (argv_find(argv, argc, "prefix", &type_idx))
		evpn_type = BGP_EVPN_IP_PREFIX_ROUTE;
	else
		evpn_type = 0;

	if (evpn_type == BGP_EVPN_MAC_IP_ROUTE) {
		memset(&ip, 0, sizeof(struct ipaddr));

		argv_find(argv, argc, "mac", &mac_idx);
		(void)prefix_str2mac(argv[mac_idx + 1]->arg, &mac);

		argv_find(argv, argc, "ip", &ip_idx);
		str2ipaddr(argv[ip_idx + 1]->arg, &ip);

		build_evpn_type2_prefix((struct prefix_evpn *)argv_p,
					&mac, &ip);
	} else if (evpn_type == BGP_EVPN_IMET_ROUTE) {
		memset(&ip, 0, sizeof(struct ipaddr));

		argv_find(argv, argc, "ip", &ip_idx);
		str2ipaddr(argv[ip_idx + 1]->arg, &ip);

		build_evpn_type3_prefix((struct prefix_evpn *)argv_p,
					ip.ipaddr_v4);
	} else if (evpn_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		struct prefix ip_prefix;

		memset(&ip_prefix, 0, sizeof(struct prefix));
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
				     NULL)) {
		vty_out(vty,
			"BGP neighbor-events debugging is already enabled for %s\n",
			host);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_neighbor_events_peers, host, NULL);

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
       "BGP Neighbor Events\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
{
	int idx_peer = 3;
	const char *host = argv[idx_peer]->arg;

	if (!bgp_debug_keepalive_peers)
		bgp_debug_keepalive_peers = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_keepalive_peers, host, NULL)) {
		vty_out(vty,
			"BGP keepalive debugging is already enabled for %s\n",
			host);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_keepalive_peers, host, NULL);

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
DEFUN (debug_bgp_bestpath_prefix,
       debug_bgp_bestpath_prefix_cmd,
       "debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>",
       DEBUG_STR
       BGP_STR
       "BGP bestpath\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct prefix *argv_p;
	int idx_ipv4_ipv6_prefixlen = 3;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (!bgp_debug_bestpath_prefixes)
		bgp_debug_bestpath_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_bestpath_prefixes, NULL,
				     argv_p)) {
		vty_out(vty,
			"BGP bestpath debugging is already enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_bestpath_prefixes, NULL, argv_p);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(bestpath, BESTPATH);
	} else {
		TERM_DEBUG_ON(bestpath, BESTPATH);
		vty_out(vty, "BGP bestpath debugging is on for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_bestpath_prefix,
       no_debug_bgp_bestpath_prefix_cmd,
       "no debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP bestpath\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	int idx_ipv4_ipv6_prefixlen = 4;
	struct prefix *argv_p;
	int found_prefix = 0;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (bgp_debug_bestpath_prefixes
	    && !list_isempty(bgp_debug_bestpath_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_bestpath_prefixes, NULL, argv_p);

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
			argv[idx_ipv4_ipv6_prefixlen]->arg);
	else
		vty_out(vty, "BGP bestpath debugging was not enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);

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

DEFUN (debug_bgp_update_direct_peer,
       debug_bgp_update_direct_peer_cmd,
       "debug bgp updates <in|out> <A.B.C.D|X:X::X:X|WORD>",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
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
					     NULL)) {
			vty_out(vty,
				"BGP inbound update debugging is already enabled for %s\n",
				host);
			return CMD_SUCCESS;
		}
	}

	else {
		if (bgp_debug_list_has_entry(bgp_debug_update_out_peers, host,
					     NULL)) {
			vty_out(vty,
				"BGP outbound update debugging is already enabled for %s\n",
				host);
			return CMD_SUCCESS;
		}
	}

	if (inbound)
		bgp_debug_list_add_entry(bgp_debug_update_in_peers, host, NULL);
	else {
		struct peer *peer;
		struct peer_af *paf;
		int afidx;

		bgp_debug_list_add_entry(bgp_debug_update_out_peers, host,
					 NULL);
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
       "no debug bgp updates <in|out> <A.B.C.D|X:X::X:X|WORD>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n"
       "BGP neighbor IP address to debug\n"
       "BGP IPv6 neighbor to debug\n"
       "BGP neighbor on interface to debug\n")
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

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_debug_clippy.c"
#endif

DEFPY (debug_bgp_update_prefix_afi_safi,
       debug_bgp_update_prefix_afi_safi_cmd,
       "debug bgp updates prefix l2vpn$afi evpn$safi type <macip mac <X:X:X:X:X:X|X:X:X:X:X:X/M> [ip <A.B.C.D|X:X::X:X>]|multicast ip <A.B.C.D|X:X::X:X>|prefix ip <A.B.C.D/M|X:X::X:X/M>>",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "Specify EVPN Route type\n"
       "MAC-IP (Type-2) route\n"
       MAC_STR MAC_STR MAC_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       "Multicast (Type-3) route\n"
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       "Prefix (Type-5) route\n"
       IP_STR
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct prefix *argv_p;
	int ret = CMD_SUCCESS;
	char buf[PREFIX2STR_BUFFER];

	argv_p = prefix_new();

	ret = bgp_debug_parse_evpn_prefix(vty, argv, argc, &argv_p);
	if (ret != CMD_SUCCESS) {
		prefix_free(&argv_p);
		return ret;
	}

	if (!bgp_debug_update_prefixes)
		bgp_debug_update_prefixes = list_new();

	prefix2str(argv_p, buf, sizeof(buf));

	if (bgp_debug_list_has_entry(bgp_debug_update_prefixes, NULL, argv_p)) {
		vty_out(vty,
			"BGP updates debugging is already enabled for %s\n",
			buf);
		prefix_free(&argv_p);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_update_prefixes, NULL, argv_p);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(update, UPDATE_PREFIX);
	} else {
		TERM_DEBUG_ON(update, UPDATE_PREFIX);
		vty_out(vty, "BGP updates debugging is on for %s\n", buf);
	}

	prefix_free(&argv_p);

	return CMD_SUCCESS;
}

DEFPY (no_debug_bgp_update_prefix_afi_safi,
       no_debug_bgp_update_prefix_afi_safi_cmd,
       "no debug bgp updates prefix l2vpn$afi evpn$safi type <macip mac <X:X:X:X:X:X|X:X:X:X:X:X/M> [ip <A.B.C.D|X:X::X:X>]|multicast ip <A.B.C.D|X:X::X:X>|prefix ip <A.B.C.D/M|X:X::X:X/M>>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "Specify EVPN Route type\n"
       "MAC-IP (Type-2) route\n"
       MAC_STR MAC_STR MAC_STR
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       "Multicast (Type-3) route\n"
       IP_STR
       "IPv4 address\n"
       "IPv6 address\n"
       "Prefix (Type-5) route\n"
       IP_STR
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct prefix *argv_p;
	bool found_prefix = false;
	int ret = CMD_SUCCESS;
	char buf[PREFIX2STR_BUFFER];

	argv_p = prefix_new();

	ret = bgp_debug_parse_evpn_prefix(vty, argv, argc, &argv_p);
	if (ret != CMD_SUCCESS) {
		prefix_free(&argv_p);
		return ret;
	}

	if (bgp_debug_update_prefixes
	    && !list_isempty(bgp_debug_update_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_update_prefixes, NULL, argv_p);

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

	prefix2str(argv_p, buf, sizeof(buf));

	if (found_prefix)
		vty_out(vty, "BGP updates debugging is off for %s\n", buf);
	else
		vty_out(vty, "BGP updates debugging was not enabled for %s\n",
			buf);

	prefix_free(&argv_p);

	return ret;
}


DEFUN (debug_bgp_update_prefix,
       debug_bgp_update_prefix_cmd,
       "debug bgp updates prefix <A.B.C.D/M|X:X::X:X/M>",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	int idx_ipv4_ipv6_prefixlen = 4;
	struct prefix *argv_p;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (!bgp_debug_update_prefixes)
		bgp_debug_update_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_update_prefixes, NULL, argv_p)) {
		vty_out(vty,
			"BGP updates debugging is already enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_update_prefixes, NULL, argv_p);

	if (vty->node == CONFIG_NODE) {
		DEBUG_ON(update, UPDATE_PREFIX);
	} else {
		TERM_DEBUG_ON(update, UPDATE_PREFIX);
		vty_out(vty, "BGP updates debugging is on for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update_prefix,
       no_debug_bgp_update_prefix_cmd,
       "no debug bgp updates prefix <A.B.C.D/M|X:X::X:X/M>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	int idx_ipv4_ipv6_prefixlen = 5;
	struct prefix *argv_p;
	int found_prefix = 0;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (bgp_debug_update_prefixes
	    && !list_isempty(bgp_debug_update_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_update_prefixes, NULL, argv_p);

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
			argv[idx_ipv4_ipv6_prefixlen]->arg);
	else
		vty_out(vty, "BGP updates debugging was not enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);

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

DEFUN (debug_bgp_zebra_prefix,
       debug_bgp_zebra_prefix_cmd,
       "debug bgp zebra prefix <A.B.C.D/M|X:X::X:X/M>",
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	int idx_ipv4_ipv6_prefixlen = 4;
	struct prefix *argv_p;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (!bgp_debug_zebra_prefixes)
		bgp_debug_zebra_prefixes = list_new();

	if (bgp_debug_list_has_entry(bgp_debug_zebra_prefixes, NULL, argv_p)) {
		vty_out(vty, "BGP zebra debugging is already enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
		return CMD_SUCCESS;
	}

	bgp_debug_list_add_entry(bgp_debug_zebra_prefixes, NULL, argv_p);

	if (vty->node == CONFIG_NODE)
		DEBUG_ON(zebra, ZEBRA);
	else {
		TERM_DEBUG_ON(zebra, ZEBRA);
		vty_out(vty, "BGP zebra debugging is on for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
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

DEFUN (no_debug_bgp_zebra_prefix,
       no_debug_bgp_zebra_prefix_cmd,
       "no debug bgp zebra prefix <A.B.C.D/M|X:X::X:X/M>",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n"
       "Specify a prefix to debug\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	int idx_ipv4_ipv6_prefixlen = 5;
	struct prefix *argv_p;
	int found_prefix = 0;

	argv_p = prefix_new();
	(void)str2prefix(argv[idx_ipv4_ipv6_prefixlen]->arg, argv_p);
	apply_mask(argv_p);

	if (bgp_debug_zebra_prefixes
	    && !list_isempty(bgp_debug_zebra_prefixes)) {
		found_prefix = bgp_debug_list_remove_entry(
			bgp_debug_zebra_prefixes, NULL, argv_p);

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
		vty_out(vty, "BGP zebra debugging is off for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);
	else
		vty_out(vty, "BGP zebra debugging was not enabled for %s\n",
			argv[idx_ipv4_ipv6_prefixlen]->arg);

	return CMD_SUCCESS;
}

DEFUN (debug_bgp_allow_martians,
       debug_bgp_allow_martians_cmd,
       "debug bgp allow-martians",
       DEBUG_STR
       BGP_STR
       "BGP allow martian next hops\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(allow_martians, ALLOW_MARTIANS);
	else {
		TERM_DEBUG_ON(allow_martians, ALLOW_MARTIANS);
		vty_out(vty, "BGP allow_martian next hop debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_allow_martians,
       no_debug_bgp_allow_martians_cmd,
       "no debug bgp allow-martians",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP allow martian next hops\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(allow_martians, ALLOW_MARTIANS);
	else {
		TERM_DEBUG_OFF(allow_martians, ALLOW_MARTIANS);
		vty_out(vty, "BGP allow martian next hop debugging is off\n");
	}
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
	TERM_DEBUG_OFF(allow_martians, ALLOW_MARTIANS);
	TERM_DEBUG_OFF(nht, NHT);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_FROM_VRF);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_TO_VRF);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_RMAP_EVENT);
	TERM_DEBUG_OFF(vpn, VPN_LEAK_LABEL);
	TERM_DEBUG_OFF(flowspec, FLOWSPEC);
	TERM_DEBUG_OFF(labelpool, LABELPOOL);
	TERM_DEBUG_OFF(pbr, PBR);
	TERM_DEBUG_OFF(pbr, PBR_ERROR);
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

	if (BGP_DEBUG(allow_martians, ALLOW_MARTIANS))
		vty_out(vty, "  BGP allow martian next hop debugging is on\n");

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

	vty_out(vty, "\n");
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

	if (CONF_BGP_DEBUG(allow_martians, ALLOW_MARTIANS)) {
		vty_out(vty, "debug bgp allow-martians\n");
		write++;
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
	return write;
}

static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

void bgp_debug_init(void)
{
	install_node(&debug_node, bgp_config_write_debug);

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
	install_element(ENABLE_NODE, &debug_bgp_zebra_cmd);
	install_element(CONFIG_NODE, &debug_bgp_zebra_cmd);
	install_element(ENABLE_NODE, &debug_bgp_allow_martians_cmd);
	install_element(CONFIG_NODE, &debug_bgp_allow_martians_cmd);
	install_element(ENABLE_NODE, &debug_bgp_update_groups_cmd);
	install_element(CONFIG_NODE, &debug_bgp_update_groups_cmd);
	install_element(ENABLE_NODE, &debug_bgp_bestpath_prefix_cmd);
	install_element(CONFIG_NODE, &debug_bgp_bestpath_prefix_cmd);

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
	install_element(ENABLE_NODE, &no_debug_bgp_allow_martians_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_allow_martians_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_update_groups_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_update_groups_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_bestpath_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_bestpath_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_bestpath_prefix_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_bestpath_prefix_cmd);

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

}

/* Return true if this prefix is on the per_prefix_list of prefixes to debug
 * for BGP_DEBUG_TYPE
 */
static int bgp_debug_per_prefix(struct prefix *p,
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
static int bgp_debug_per_peer(char *host, unsigned long term_bgp_debug_type,
			      unsigned int BGP_DEBUG_TYPE,
			      struct list *per_peer_list)
{
	struct bgp_debug_filter *filter;
	struct listnode *node, *nnode;

	if (term_bgp_debug_type & BGP_DEBUG_TYPE) {
		/* We are debugging all peers so return true */
		if (!per_peer_list || list_isempty(per_peer_list))
			return 1;

		else {
			if (!host)
				return 0;

			for (ALL_LIST_ELEMENTS(per_peer_list, node, nnode,
					       filter))
				if (strcmp(filter->host, host) == 0)
					return 1;

			return 0;
		}
	}

	return 0;
}

int bgp_debug_neighbor_events(struct peer *peer)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	return bgp_debug_per_peer(host, term_bgp_debug_neighbor_events,
				  BGP_DEBUG_NEIGHBOR_EVENTS,
				  bgp_debug_neighbor_events_peers);
}

int bgp_debug_keepalive(struct peer *peer)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	return bgp_debug_per_peer(host, term_bgp_debug_keepalive,
				  BGP_DEBUG_KEEPALIVE,
				  bgp_debug_keepalive_peers);
}

int bgp_debug_update(struct peer *peer, struct prefix *p,
		     struct update_group *updgrp, unsigned int inbound)
{
	char *host = NULL;

	if (peer)
		host = peer->host;

	if (inbound) {
		if (bgp_debug_per_peer(host, term_bgp_debug_update,
				       BGP_DEBUG_UPDATE_IN,
				       bgp_debug_update_in_peers))
			return 1;
	}

	/* outbound */
	else {
		if (bgp_debug_per_peer(host, term_bgp_debug_update,
				       BGP_DEBUG_UPDATE_OUT,
				       bgp_debug_update_out_peers))
			return 1;

		/* Check if update debugging implicitly enabled for the group.
		 */
		if (updgrp && UPDGRP_DBG_ON(updgrp))
			return 1;
	}


	if (BGP_DEBUG(update, UPDATE_PREFIX)) {
		if (bgp_debug_per_prefix(p, term_bgp_debug_update,
					 BGP_DEBUG_UPDATE_PREFIX,
					 bgp_debug_update_prefixes))
			return 1;
	}

	return 0;
}

int bgp_debug_bestpath(struct prefix *p)
{
	if (BGP_DEBUG(bestpath, BESTPATH)) {
		if (bgp_debug_per_prefix(p, term_bgp_debug_bestpath,
					 BGP_DEBUG_BESTPATH,
					 bgp_debug_bestpath_prefixes))
			return 1;
	}

	return 0;
}

int bgp_debug_zebra(struct prefix *p)
{
	if (BGP_DEBUG(zebra, ZEBRA)) {
		if (bgp_debug_per_prefix(p, term_bgp_debug_zebra,
					 BGP_DEBUG_ZEBRA,
					 bgp_debug_zebra_prefixes))
			return 1;
	}

	return 0;
}

const char *bgp_debug_rdpfxpath2str(afi_t afi, safi_t safi,
				    struct prefix_rd *prd,
				    union prefixconstptr pu,
				    mpls_label_t *label, uint32_t num_labels,
				    int addpath_valid, uint32_t addpath_id,
				    char *str, int size)
{
	char rd_buf[RD_ADDRSTRLEN];
	char pfx_buf[PREFIX_STRLEN];
	char tag_buf[30];
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

	tag_buf[0] = '\0';
	if (bgp_labeled_safi(safi) && num_labels) {

		if (safi == SAFI_EVPN) {
			char tag_buf2[20];

			bgp_evpn_label2str(label, num_labels, tag_buf2, 20);
			sprintf(tag_buf, " label %s", tag_buf2);
		} else {
			uint32_t label_value;

			label_value = decode_label(label);
			sprintf(tag_buf, " label %u", label_value);
		}
	}

	if (prd)
		snprintf(str, size, "RD %s %s%s%s %s %s",
			 prefix_rd2str(prd, rd_buf, sizeof(rd_buf)),
			 prefix2str(pu, pfx_buf, sizeof(pfx_buf)), tag_buf,
			 pathid_buf, afi2str(afi), safi2str(safi));
	else if (safi == SAFI_FLOWSPEC) {
		char return_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
		const struct prefix_fs *fs = pu.fs;

		bgp_fs_nlri_get_string((unsigned char *)fs->prefix.ptr,
				       fs->prefix.prefixlen,
				       return_string,
				       NLRI_STRING_FORMAT_DEBUG, NULL);
		snprintf(str, size, "FS %s Match{%s}", afi2str(afi),
			 return_string);
	} else
		snprintf(str, size, "%s%s%s %s %s",
			 prefix2str(pu, pfx_buf, sizeof(pfx_buf)), tag_buf,
			 pathid_buf, afi2str(afi), safi2str(safi));

	return str;
}
