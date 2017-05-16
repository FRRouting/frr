/*
 * Copyright (C) 2016 by Open Source Routing.
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>
#include <sys/un.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"
#include "ldp_vty.h"
#include "lib/json.h"

#include "command.h"
#include "vty.h"
#include "mpls.h"

enum show_command {
	SHOW_DISC,
	SHOW_IFACE,
	SHOW_NBR,
	SHOW_LIB,
	SHOW_L2VPN_PW,
	SHOW_L2VPN_BINDING
};

struct show_params {
	int		family;
	union ldpd_addr	addr;
	uint8_t		prefixlen;
	int		capabilities;
	int		detail;
	int		json;
};

#define LDPBUFSIZ	65535

static int		 show_interface_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_interface_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static int		 show_discovery_msg(struct vty *, struct imsg *,
			    struct show_params *);
static void		 show_discovery_detail_adj(struct vty *, char *,
			    struct ctl_adj *);
static int		 show_discovery_detail_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_discovery_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static void		 show_discovery_detail_adj_json(json_object *,
			    struct ctl_adj *);
static int		 show_discovery_detail_msg_json(struct imsg *,
			    struct show_params *, json_object *);

static int		 show_nbr_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_nbr_msg_json(struct imsg *, struct show_params *,
			    json_object *);
static void		 show_nbr_detail_adj(struct vty *, char *,
			    struct ctl_adj *);
static int		 show_nbr_detail_msg(struct vty *, struct imsg *,
			    struct show_params *);
static void		 show_nbr_detail_adj_json(struct ctl_adj *,
			    json_object *);
static int		 show_nbr_detail_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static void		 show_nbr_capabilities(struct vty *, struct ctl_nbr *);
static int		 show_nbr_capabilities_msg(struct vty *, struct imsg *,
			    struct show_params *);
static void		 show_nbr_capabilities_json(struct ctl_nbr *,
			    json_object *);
static int		 show_nbr_capabilities_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static int		 show_lib_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_lib_detail_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_lib_msg_json(struct imsg *, struct show_params *,
			    json_object *);
static int		 show_lib_detail_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static int		 show_l2vpn_binding_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_l2vpn_binding_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static int		 show_l2vpn_pw_msg(struct vty *, struct imsg *,
			    struct show_params *);
static int		 show_l2vpn_pw_msg_json(struct imsg *,
			    struct show_params *, json_object *);
static int		 ldp_vty_connect(struct imsgbuf *);
static int		 ldp_vty_dispatch_msg(struct vty *, struct imsg *,
			    enum show_command, struct show_params *,
			    json_object *);
static int		 ldp_vty_dispatch(struct vty *, struct imsgbuf *,
			    enum show_command, struct show_params *);
static int		 ldp_vty_get_af(const char *, int *);

static int
show_interface_msg(struct vty *vty, struct imsg *imsg,
    struct show_params *params)
{
	struct ctl_iface	*iface;
	char			 timers[BUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_INTERFACE:
		iface = imsg->data;

		if (params->family != AF_UNSPEC && params->family != iface->af)
			break;

		snprintf(timers, sizeof(timers), "%u/%u",
		    iface->hello_interval, iface->hello_holdtime);

		vty_out(vty, "%-4s %-11s %-6s %-8s %-12s %3u%s",
		    af_name(iface->af), iface->name,
		    if_state_name(iface->state), iface->uptime == 0 ?
		    "00:00:00" : log_time(iface->uptime), timers,
		    iface->adj_cnt, VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_interface_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_iface	*iface;
	json_object		*json_iface;
	char 			 key_name[64];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_INTERFACE:
		iface = imsg->data;

		if (params->family != AF_UNSPEC && params->family != iface->af)
			break;

		json_iface = json_object_new_object();
		json_object_string_add(json_iface, "name", iface->name);
		json_object_string_add(json_iface, "addressFamily",
		    af_name(iface->af));
		json_object_string_add(json_iface, "state",
		    if_state_name(iface->state));
		json_object_string_add(json_iface, "upTime",
		    log_time(iface->uptime));
		json_object_int_add(json_iface, "helloInterval",
		    iface->hello_interval);
		json_object_int_add(json_iface, "helloHoldtime",
		    iface->hello_holdtime);
		json_object_int_add(json_iface, "adjacencyCount",
		    iface->adj_cnt);

		sprintf(key_name, "%s: %s", iface->name, af_name(iface->af));
		json_object_object_add(json, key_name, json_iface);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_discovery_msg(struct vty *vty, struct imsg *imsg,
    struct show_params *params)
{
	struct ctl_adj		*adj;
	const char		*addr;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_DISCOVERY:
		adj = imsg->data;

		if (params->family != AF_UNSPEC && params->family != adj->af)
			break;

		vty_out(vty, "%-4s %-15s ", af_name(adj->af),
		    inet_ntoa(adj->id));
		switch(adj->type) {
		case HELLO_LINK:
			vty_out(vty, "%-8s %-15s ", "Link", adj->ifname);
			break;
		case HELLO_TARGETED:
			addr = log_addr(adj->af, &adj->src_addr);

			vty_out(vty, "%-8s %-15s ", "Targeted", addr);
			if (strlen(addr) > 15)
				vty_out(vty, "%s%46s", VTY_NEWLINE, " ");
			break;
		}
		vty_out(vty, "%9u%s", adj->holdtime, VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static void
show_discovery_detail_adj(struct vty *vty, char *buffer, struct ctl_adj *adj)
{
	size_t	 buflen = strlen(buffer);

	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "      LSR Id: %s:0%s", inet_ntoa(adj->id), VTY_NEWLINE);
	buflen = strlen(buffer);
	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "          Source address: %s%s",
	    log_addr(adj->af, &adj->src_addr), VTY_NEWLINE);
	buflen = strlen(buffer);
	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "          Transport address: %s%s",
	    log_addr(adj->af, &adj->trans_addr), VTY_NEWLINE);
	buflen = strlen(buffer);
	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "          Hello hold time: %u secs (due in %u secs)%s",
	    adj->holdtime, adj->holdtime_remaining, VTY_NEWLINE);
	buflen = strlen(buffer);
	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "          Dual-stack capability TLV: %s%s",
	    (adj->ds_tlv) ? "yes" : "no", VTY_NEWLINE);
}

static int
show_discovery_detail_msg(struct vty *vty, struct imsg *imsg,
    struct show_params *params)
{
	struct ctl_adj		*adj;
	struct ctl_disc_if	*iface;
	struct ctl_disc_tnbr	*tnbr;
	struct in_addr		 rtr_id;
	union ldpd_addr		*trans_addr;
	size_t			 buflen;
	static char		 ifaces_buffer[LDPBUFSIZ];
	static char		 tnbrs_buffer[LDPBUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_DISCOVERY:
		ifaces_buffer[0] = '\0';
		tnbrs_buffer[0] = '\0';
		break;
	case IMSG_CTL_SHOW_DISC_IFACE:
		iface = imsg->data;

		if (params->family != AF_UNSPEC &&
		    ((params->family == AF_INET && !iface->active_v4) ||
		    (params->family == AF_INET6 && !iface->active_v6)))
			break;

		buflen = strlen(ifaces_buffer);
		snprintf(ifaces_buffer + buflen, LDPBUFSIZ - buflen,
		     "    %s: %s%s", iface->name, (iface->no_adj) ?
		    "(no adjacencies)" : "", VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_DISC_TNBR:
		tnbr = imsg->data;

		if (params->family != AF_UNSPEC && params->family != tnbr->af)
			break;

		trans_addr = &(ldp_af_conf_get(ldpd_conf,
		    tnbr->af))->trans_addr;
		buflen = strlen(tnbrs_buffer);
		snprintf(tnbrs_buffer + buflen, LDPBUFSIZ - buflen,
		    "    %s -> %s: %s%s", log_addr(tnbr->af, trans_addr),
		    log_addr(tnbr->af, &tnbr->addr), (tnbr->no_adj) ?
		    "(no adjacencies)" : "", VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_DISC_ADJ:
		adj = imsg->data;

		if (params->family != AF_UNSPEC && params->family != adj->af)
			break;

		switch(adj->type) {
		case HELLO_LINK:
			show_discovery_detail_adj(vty, ifaces_buffer, adj);
			break;
		case HELLO_TARGETED:
			show_discovery_detail_adj(vty, tnbrs_buffer, adj);
			break;
		}
		break;
	case IMSG_CTL_END:
		rtr_id.s_addr = ldp_rtr_id_get(ldpd_conf);
		vty_out(vty, "Local:%s", VTY_NEWLINE);
		vty_out(vty, "  LSR Id: %s:0%s", inet_ntoa(rtr_id),
		    VTY_NEWLINE);
		if (ldpd_conf->ipv4.flags & F_LDPD_AF_ENABLED)
			vty_out(vty, "  Transport Address (IPv4): %s%s",
			    log_addr(AF_INET, &ldpd_conf->ipv4.trans_addr),
			    VTY_NEWLINE);
		if (ldpd_conf->ipv6.flags & F_LDPD_AF_ENABLED)
			vty_out(vty, "  Transport Address (IPv6): %s%s",
			    log_addr(AF_INET6, &ldpd_conf->ipv6.trans_addr),
			    VTY_NEWLINE);
		vty_out(vty, "Discovery Sources:%s", VTY_NEWLINE);
		vty_out(vty, "  Interfaces:%s", VTY_NEWLINE);
		vty_out(vty, "%s", ifaces_buffer);
		vty_out(vty, "  Targeted Hellos:%s", VTY_NEWLINE);
		vty_out(vty, "%s", tnbrs_buffer);
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_discovery_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_adj		*adj;
	json_object		*json_array;
	json_object		*json_adj;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_DISCOVERY:
		adj = imsg->data;

		if (params->family != AF_UNSPEC && params->family != adj->af)
			break;

		json_object_object_get_ex(json, "adjacencies", &json_array);
		if (!json_array) {
			json_array = json_object_new_array();
			json_object_object_add(json, "adjacencies", json_array);
		}

		json_adj = json_object_new_object();
		json_object_string_add(json_adj, "addressFamily",
		    af_name(adj->af));
		json_object_string_add(json_adj, "neighborId",
		    inet_ntoa(adj->id));
		switch(adj->type) {
		case HELLO_LINK:
			json_object_string_add(json_adj, "type", "link");
			json_object_string_add(json_adj, "interface",
			    adj->ifname);
			break;
		case HELLO_TARGETED:
			json_object_string_add(json_adj, "type", "targeted");
			json_object_string_add(json_adj, "peer",
			    log_addr(adj->af, &adj->src_addr));
			break;
		}
		json_object_int_add(json_adj, "helloHoldtime", adj->holdtime);

		json_object_array_add(json_array, json_adj);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static void
show_discovery_detail_adj_json(json_object *json, struct ctl_adj *adj)
{
	json_object *json_adj;
	json_object *json_array;

	json_object_object_get_ex(json, "adjacencies", &json_array);
	if (!json_array) {
		json_array = json_object_new_array();
		json_object_object_add(json, "adjacencies", json_array);
	}

	json_adj = json_object_new_object();
	json_object_string_add(json_adj, "lsrId", inet_ntoa(adj->id));
	json_object_string_add(json_adj, "sourceAddress", log_addr(adj->af,
	    &adj->src_addr));
	json_object_string_add(json_adj, "transportAddress", log_addr(adj->af,
	    &adj->trans_addr));
	json_object_int_add(json_adj, "helloHoldtime", adj->holdtime);
	json_object_int_add(json_adj, "helloHoldtimeRemaining",
	    adj->holdtime_remaining);
	json_object_int_add(json_adj, "dualStackCapabilityTlv",
	    adj->ds_tlv);
	json_object_array_add(json_array, json_adj);
}

static int
show_discovery_detail_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_adj		*adj;
	struct ctl_disc_if	*iface;
	struct ctl_disc_tnbr	*tnbr;
	struct in_addr		 rtr_id;
	union ldpd_addr		*trans_addr;
	json_object		*json_interface;
	json_object		*json_target;
	static json_object	*json_interfaces;
	static json_object	*json_targets;
	static json_object	*json_container;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_DISCOVERY:
		rtr_id.s_addr = ldp_rtr_id_get(ldpd_conf);
		json_object_string_add(json, "lsrId", inet_ntoa(rtr_id));
		if (ldpd_conf->ipv4.flags & F_LDPD_AF_ENABLED)
			json_object_string_add(json, "transportAddressIPv4",
			    log_addr(AF_INET, &ldpd_conf->ipv4.trans_addr));
		if (ldpd_conf->ipv6.flags & F_LDPD_AF_ENABLED)
			json_object_string_add(json, "transportAddressIPv6",
			    log_addr(AF_INET6, &ldpd_conf->ipv6.trans_addr));
		json_interfaces = json_object_new_object();
		json_object_object_add(json, "interfaces", json_interfaces);
		json_targets = json_object_new_object();
		json_object_object_add(json, "targetedHellos", json_targets);
		json_container = NULL;
		break;
	case IMSG_CTL_SHOW_DISC_IFACE:
		iface = imsg->data;

		if (params->family != AF_UNSPEC &&
		    ((params->family == AF_INET && !iface->active_v4) ||
		    (params->family == AF_INET6 && !iface->active_v6)))
			break;

		json_interface = json_object_new_object();
		json_object_object_add(json_interfaces, iface->name,
		    json_interface);
		json_container = json_interface;
		break;
	case IMSG_CTL_SHOW_DISC_TNBR:
		tnbr = imsg->data;

		if (params->family != AF_UNSPEC && params->family != tnbr->af)
			break;

		trans_addr = &(ldp_af_conf_get(ldpd_conf, tnbr->af))->trans_addr;

		json_target = json_object_new_object();
		json_object_string_add(json_target, "sourceAddress",
		    log_addr(tnbr->af, trans_addr));
		json_object_object_add(json_targets, log_addr(tnbr->af,
		    &tnbr->addr), json_target);
		json_container = json_target;
		break;
	case IMSG_CTL_SHOW_DISC_ADJ:
		adj = imsg->data;

		if (params->family != AF_UNSPEC && params->family != adj->af)
			break;

		switch(adj->type) {
		case HELLO_LINK:
			show_discovery_detail_adj_json(json_container, adj);
			break;
		case HELLO_TARGETED:
			show_discovery_detail_adj_json(json_container, adj);
			break;
		}
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_nbr_msg(struct vty *vty, struct imsg *imsg, struct show_params *params)
{
	struct ctl_nbr		*nbr;
	const char		*addr;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		addr = log_addr(nbr->af, &nbr->raddr);

		vty_out(vty, "%-4s %-15s %-11s %-15s",
		    af_name(nbr->af), inet_ntoa(nbr->id),
		    nbr_state_name(nbr->nbr_state), addr);
		if (strlen(addr) > 15)
			vty_out(vty, "%s%48s", VTY_NEWLINE, " ");
		vty_out(vty, " %8s%s", log_time(nbr->uptime), VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static void
show_nbr_detail_adj(struct vty *vty, char *buffer, struct ctl_adj *adj)
{
	size_t	 buflen = strlen(buffer);

	switch (adj->type) {
	case HELLO_LINK:
		snprintf(buffer + buflen, LDPBUFSIZ - buflen,
		    "      Interface: %s%s", adj->ifname, VTY_NEWLINE);
		break;
	case HELLO_TARGETED:
		snprintf(buffer + buflen, LDPBUFSIZ - buflen,
		    "      Targeted Hello: %s%s", log_addr(adj->af,
		    &adj->src_addr), VTY_NEWLINE);
		break;
	}
}

static int
show_nbr_detail_msg(struct vty *vty, struct imsg *imsg,
    struct show_params *params)
{
	struct ctl_nbr		*nbr;
	struct ldp_stats	*stats;
	struct ctl_adj		*adj;
	static char		 v4adjs_buffer[LDPBUFSIZ];
	static char		 v6adjs_buffer[LDPBUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		v4adjs_buffer[0] = '\0';
		v6adjs_buffer[0] = '\0';
		vty_out(vty, "Peer LDP Identifier: %s:0%s", inet_ntoa(nbr->id),
		    VTY_NEWLINE);
		vty_out(vty, "  TCP connection: %s:%u - %s:%u%s",
		    log_addr(nbr->af, &nbr->laddr), ntohs(nbr->lport),
		    log_addr(nbr->af, &nbr->raddr), ntohs(nbr->rport),
		    VTY_NEWLINE);
		vty_out(vty, "  Authentication: %s%s",
		    (nbr->auth_method == AUTH_MD5SIG) ? "TCP MD5 Signature" :
		    "none", VTY_NEWLINE);
		vty_out(vty, "  Session Holdtime: %u secs; "
		    "KeepAlive interval: %u secs%s", nbr->holdtime,
		    nbr->holdtime / KEEPALIVE_PER_PERIOD, VTY_NEWLINE);
		vty_out(vty, "  State: %s; Downstream-Unsolicited%s",
		    nbr_state_name(nbr->nbr_state), VTY_NEWLINE);
		vty_out(vty, "  Up time: %s%s", log_time(nbr->uptime),
		    VTY_NEWLINE);

		stats = &nbr->stats;
		vty_out(vty, "  Messages sent/rcvd:%s", VTY_NEWLINE);
		vty_out(vty, "   - Keepalive Messages: %u/%u%s",
		    stats->kalive_sent, stats->kalive_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Address Messages: %u/%u%s",
		    stats->addr_sent, stats->addr_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Address Withdraw Messages: %u/%u%s",
		    stats->addrwdraw_sent, stats->addrwdraw_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Notification Messages: %u/%u%s",
		    stats->notif_sent, stats->notif_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Capability Messages: %u/%u%s",
		    stats->capability_sent, stats->capability_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Label Mapping Messages: %u/%u%s",
		    stats->labelmap_sent, stats->labelmap_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Label Request Messages: %u/%u%s",
		    stats->labelreq_sent, stats->labelreq_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Label Withdraw Messages: %u/%u%s",
		    stats->labelwdraw_sent, stats->labelwdraw_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Label Release Messages: %u/%u%s",
		    stats->labelrel_sent, stats->labelrel_rcvd, VTY_NEWLINE);
		vty_out(vty, "   - Label Abort Request Messages: %u/%u%s",
		    stats->labelabreq_sent, stats->labelabreq_rcvd, VTY_NEWLINE);

		show_nbr_capabilities(vty, nbr);
		break;
	case IMSG_CTL_SHOW_NBR_DISC:
		adj = imsg->data;

		switch (adj->af) {
		case AF_INET:
			show_nbr_detail_adj(vty, v4adjs_buffer, adj);
			break;
		case AF_INET6:
			show_nbr_detail_adj(vty, v6adjs_buffer, adj);
			break;
		default:
			fatalx("show_nbr_detail_msg: unknown af");
		}
		break;
	case IMSG_CTL_SHOW_NBR_END:
		vty_out(vty, "  LDP Discovery Sources:%s", VTY_NEWLINE);
		if (v4adjs_buffer[0] != '\0') {
			vty_out(vty, "    IPv4:%s", VTY_NEWLINE);
			vty_out(vty, "%s", v4adjs_buffer);
		}
		if (v6adjs_buffer[0] != '\0') {
			vty_out(vty, "    IPv6:%s", VTY_NEWLINE);
			vty_out(vty, "%s", v6adjs_buffer);
		}
		vty_out(vty, "%s", VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_nbr_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_nbr		*nbr;
	json_object		*json_array;
	json_object		*json_nbr;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		json_object_object_get_ex(json, "neighbors", &json_array);
		if (!json_array) {
			json_array = json_object_new_array();
			json_object_object_add(json, "neighbors", json_array);
		}

		json_nbr = json_object_new_object();
		json_object_string_add(json_nbr, "addressFamily",
		    af_name(nbr->af));
		json_object_string_add(json_nbr, "neighborId",
		    inet_ntoa(nbr->id));
		json_object_string_add(json_nbr, "state",
		    nbr_state_name(nbr->nbr_state));
		json_object_string_add(json_nbr, "transportAddress",
		    log_addr(nbr->af, &nbr->raddr));
		json_object_string_add(json_nbr, "upTime",
		    log_time(nbr->uptime));

		json_object_array_add(json_array, json_nbr);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static void
show_nbr_detail_adj_json(struct ctl_adj *adj, json_object *adj_list)
{
	char adj_string[128];

	switch (adj->type) {
	case HELLO_LINK:
		strlcpy(adj_string, "interface: ", sizeof(adj_string));
		strlcat(adj_string, adj->ifname, sizeof(adj_string));
		break;
	case HELLO_TARGETED:
		strlcpy(adj_string, "targetedHello: ", sizeof(adj_string));
		strlcat(adj_string, log_addr(adj->af, &adj->src_addr),
		    sizeof(adj_string));
		break;
	}

	json_object_array_add(adj_list, json_object_new_string(adj_string));
}

static int
show_nbr_detail_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_nbr		*nbr;
	struct ldp_stats	*stats;
	struct ctl_adj		*adj;
	json_object		*json_nbr;
	json_object		*json_array;
	json_object		*json_counter;
	static json_object	*json_nbr_sources;
	static json_object	*json_v4adjs;
	static json_object	*json_v6adjs;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		json_nbr = json_object_new_object();
		json_object_object_add(json, inet_ntoa(nbr->id), json_nbr);

		json_object_string_add(json_nbr, "peerId", inet_ntoa(nbr->id));
		json_object_string_add(json_nbr, "tcpLocalAddress",
		    log_addr(nbr->af, &nbr->laddr));
		json_object_int_add(json_nbr, "tcpLocalPort",
		    ntohs(nbr->lport));
		json_object_string_add(json_nbr, "tcpRemoteAddress",
		    log_addr(nbr->af, &nbr->raddr));
		json_object_int_add(json_nbr, "tcpRemotePort",
		    ntohs(nbr->rport));
		json_object_string_add(json_nbr, "authentication",
		    (nbr->auth_method == AUTH_MD5SIG) ? "TCP MD5 Signature" :
		    "none");
		json_object_int_add(json_nbr, "sessionHoldtime", nbr->holdtime);
		json_object_int_add(json_nbr, "keepAliveInterval",
		    nbr->holdtime / KEEPALIVE_PER_PERIOD);
		json_object_string_add(json_nbr, "state",
		    nbr_state_name(nbr->nbr_state));
		json_object_string_add(json_nbr, "upTime",
		    log_time(nbr->uptime));

		/* message_counters */
		stats = &nbr->stats;
		json_array = json_object_new_array();
		json_object_object_add(json_nbr, "sentMessages", json_array);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "keepalive",
		    stats->kalive_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "address",
		    stats->addr_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "addressWithdraw",
		    stats->addrwdraw_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "notification",
		    stats->notif_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "capability",
		    stats->capability_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelMapping",
		    stats->labelmap_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelRequest",
		    stats->labelreq_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelWithdraw",
		    stats->labelwdraw_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelRelease",
		    stats->labelrel_sent);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelAbortRequest",
		    stats->labelabreq_sent);
		json_object_array_add(json_array, json_counter);

		json_array = json_object_new_array();
		json_object_object_add(json_nbr, "receivedMessages", json_array);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "keepalive",
		    stats->kalive_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "address",
		    stats->addr_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "addressWithdraw",
		    stats->addrwdraw_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "notification",
		    stats->notif_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "capability",
		    stats->capability_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelMapping",
		    stats->labelmap_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelRequest",
		    stats->labelreq_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelWithdraw",
		    stats->labelwdraw_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelRelease",
		    stats->labelrel_rcvd);
		json_object_array_add(json_array, json_counter);
		json_counter = json_object_new_object();
		json_object_int_add(json_counter, "labelAbortRequest",
		    stats->labelabreq_rcvd);
		json_object_array_add(json_array, json_counter);

		/* capabilities */
		show_nbr_capabilities_json(nbr, json_nbr);

		/* discovery sources */
		json_nbr_sources = json_object_new_object();
		json_object_object_add(json_nbr, "discoverySources",
		    json_nbr_sources);
		json_v4adjs = NULL;
		json_v6adjs = NULL;
		break;
	case IMSG_CTL_SHOW_NBR_DISC:
		adj = imsg->data;

		switch (adj->af) {
		case AF_INET:
			if (!json_v4adjs) {
				json_v4adjs = json_object_new_array();
				json_object_object_add(json_nbr_sources, "ipv4",
				    json_v4adjs);
			}
			show_nbr_detail_adj_json(adj, json_v4adjs);
			break;
		case AF_INET6:
			if (!json_v6adjs) {
				json_v6adjs = json_object_new_array();
				json_object_object_add(json_nbr_sources, "ipv6",
				    json_v6adjs);
			}
			show_nbr_detail_adj_json(adj, json_v6adjs);
			break;
		default:
			fatalx("show_nbr_detail_msg_json: unknown af");
		}
		break;
	case IMSG_CTL_SHOW_NBR_END:
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

void
show_nbr_capabilities(struct vty *vty, struct ctl_nbr *nbr)
{
	vty_out(vty, "  Capabilities Sent:%s"
	    "   - Dynamic Announcement (0x0506)%s"
	    "   - Typed Wildcard (0x050B)%s"
	    "   - Unrecognized Notification (0x0603)%s",
	    VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	vty_out(vty, "  Capabilities Received:%s", VTY_NEWLINE);
	if (nbr->flags & F_NBR_CAP_DYNAMIC)
		vty_out(vty, "   - Dynamic Announcement (0x0506)%s",
		    VTY_NEWLINE);
	if (nbr->flags & F_NBR_CAP_TWCARD)
		vty_out(vty, "   - Typed Wildcard (0x050B)%s", VTY_NEWLINE);
	if (nbr->flags & F_NBR_CAP_UNOTIF)
		vty_out(vty, "   - Unrecognized Notification (0x0603)%s",
		    VTY_NEWLINE);
}

static int
show_nbr_capabilities_msg(struct vty *vty, struct imsg *imsg, struct show_params *params)
{
	struct ctl_nbr		*nbr;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		if (nbr->nbr_state != NBR_STA_OPER)
			break;

		vty_out(vty, "Peer LDP Identifier: %s:0%s", inet_ntoa(nbr->id),
		    VTY_NEWLINE);
		show_nbr_capabilities(vty, nbr);
		vty_out(vty, "%s", VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static void
show_nbr_capabilities_json(struct ctl_nbr *nbr, json_object *json_nbr)
{
	json_object		*json_array;
	json_object		*json_cap;

	/* sent capabilities */
	json_array = json_object_new_array();
	json_object_object_add(json_nbr, "sentCapabilities", json_array);

	/* Dynamic Announcement (0x0506) */
	json_cap = json_object_new_object();
	json_object_string_add(json_cap, "description", "Dynamic Announcement");
	json_object_string_add(json_cap, "tlvType", "0x0506");
	json_object_array_add(json_array, json_cap);

	/* Typed Wildcard (0x050B) */
	json_cap = json_object_new_object();
	json_object_string_add(json_cap, "description", "Typed Wildcard");
	json_object_string_add(json_cap, "tlvType", "0x050B");
	json_object_array_add(json_array, json_cap);

	/* Unrecognized Notification (0x0603) */
	json_cap = json_object_new_object();
	json_object_string_add(json_cap, "description",
	    "Unrecognized Notification");
	json_object_string_add(json_cap, "tlvType", "0x0603");
	json_object_array_add(json_array, json_cap);

	/* received capabilities */
	json_array = json_object_new_array();
	json_object_object_add(json_nbr, "receivedCapabilities", json_array);

	/* Dynamic Announcement (0x0506) */
	if (nbr->flags & F_NBR_CAP_DYNAMIC) {
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Dynamic Announcement");
		json_object_string_add(json_cap, "tlvType", "0x0506");
		json_object_array_add(json_array, json_cap);
	}

	/* Typed Wildcard (0x050B) */
	if (nbr->flags & F_NBR_CAP_TWCARD) {
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Typed Wildcard");
		json_object_string_add(json_cap, "tlvType", "0x050B");
		json_object_array_add(json_array, json_cap);
	}

	/* Unrecognized Notification (0x0603) */
	if (nbr->flags & F_NBR_CAP_UNOTIF) {
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Unrecognized Notification");
		json_object_string_add(json_cap, "tlvType", "0x0603");
		json_object_array_add(json_array, json_cap);
	}
}

static int
show_nbr_capabilities_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_nbr		*nbr;
	json_object		*json_nbr;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_NBR:
		nbr = imsg->data;

		if (nbr->nbr_state != NBR_STA_OPER)
			break;

		json_nbr = json_object_new_object();
		json_object_object_add(json, inet_ntoa(nbr->id), json_nbr);
		show_nbr_capabilities_json(nbr, json_nbr);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_lib_msg(struct vty *vty, struct imsg *imsg, struct show_params *params)
{
	struct ctl_rt	*rt;
	char		 dstnet[BUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
	case IMSG_CTL_SHOW_LIB_RCVD:
		rt = imsg->data;

		if (imsg->hdr.type == IMSG_CTL_SHOW_LIB_BEGIN &&
		    !rt->no_downstream)
			break;

		if (params->family != AF_UNSPEC && params->family != rt->af)
			break;

		snprintf(dstnet, sizeof(dstnet), "%s/%d",
		    log_addr(rt->af, &rt->prefix), rt->prefixlen);

		vty_out(vty, "%-4s %-20s", af_name(rt->af), dstnet);
		if (strlen(dstnet) > 20)
			vty_out(vty, "%s%25s", VTY_NEWLINE, " ");
		vty_out(vty, " %-15s %-11s %-13s %6s%s", inet_ntoa(rt->nexthop),
		    log_label(rt->local_label), log_label(rt->remote_label),
		    rt->in_use ? "yes" : "no", VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_lib_detail_msg(struct vty *vty, struct imsg *imsg, struct show_params *params)
{
	struct ctl_rt	*rt = NULL;
	char		 dstnet[BUFSIZ];
	static int	 upstream, downstream;
	size_t		 buflen;
	static char	 sent_buffer[LDPBUFSIZ];
	static char	 rcvd_buffer[LDPBUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
	case IMSG_CTL_SHOW_LIB_SENT:
	case IMSG_CTL_SHOW_LIB_RCVD:
	case IMSG_CTL_SHOW_LIB_END:
		rt = imsg->data;
		if (params->family != AF_UNSPEC && params->family != rt->af)
			return (0);
		break;
	default:
		break;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
		upstream = 0;
		downstream = 0;
		sent_buffer[0] = '\0';
		rcvd_buffer[0] = '\0';

		snprintf(dstnet, sizeof(dstnet), "%s/%d",
		    log_addr(rt->af, &rt->prefix), rt->prefixlen);

		vty_out(vty, "%s%s", dstnet, VTY_NEWLINE);
		vty_out(vty, "%-8sLocal binding: label: %s%s", "",
		    log_label(rt->local_label), VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_LIB_SENT:
		upstream = 1;
		buflen = strlen(sent_buffer);
		snprintf(sent_buffer + buflen, LDPBUFSIZ - buflen,
		    "%12s%s:0%s", "", inet_ntoa(rt->nexthop), VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_LIB_RCVD:
		downstream = 1;
		buflen = strlen(rcvd_buffer);
		snprintf(rcvd_buffer + buflen, LDPBUFSIZ - buflen,
		    "%12s%s:0, label %s%s%s", "", inet_ntoa(rt->nexthop),
		    log_label(rt->remote_label),
		    rt->in_use ? " (in use)" : "", VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_LIB_END:
		if (upstream) {
			vty_out(vty, "%-8sAdvertised to:%s", "", VTY_NEWLINE);
			vty_out(vty, "%s", sent_buffer);
		}
		if (downstream) {
			vty_out(vty, "%-8sRemote bindings:%s", "", VTY_NEWLINE);
			vty_out(vty, "%s", rcvd_buffer);
		} else
			vty_out(vty, "%-8sNo remote bindings%s", "",
			    VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_lib_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_rt	*rt;
	json_object	*json_array;
	json_object	*json_lib_entry;
	char		 dstnet[BUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
	case IMSG_CTL_SHOW_LIB_RCVD:
		rt = imsg->data;

		if (imsg->hdr.type == IMSG_CTL_SHOW_LIB_BEGIN &&
		    !rt->no_downstream)
			break;

		json_object_object_get_ex(json, "bindings", &json_array);
		if (!json_array) {
			json_array = json_object_new_array();
			json_object_object_add(json, "bindings", json_array);
		}

		json_lib_entry = json_object_new_object();
		json_object_string_add(json_lib_entry, "addressFamily",
		    af_name(rt->af));
		snprintf(dstnet, sizeof(dstnet), "%s/%d",
		    log_addr(rt->af, &rt->prefix), rt->prefixlen);
		json_object_string_add(json_lib_entry, "prefix", dstnet);
		json_object_string_add(json_lib_entry, "neighborId",
		    inet_ntoa(rt->nexthop));
		json_object_string_add(json_lib_entry, "localLabel",
		    log_label(rt->local_label));
		json_object_string_add(json_lib_entry, "remoteLabel",
		    log_label(rt->remote_label));
		json_object_int_add(json_lib_entry, "inUse", rt->in_use);

		json_object_array_add(json_array, json_lib_entry);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_lib_detail_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_rt		*rt = NULL;
	char			 dstnet[BUFSIZ];
	static json_object	*json_lib_entry;
	static json_object	*json_adv_labels;
	json_object		*json_adv_label;
	static json_object	*json_remote_labels;
	json_object		*json_remote_label;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
	case IMSG_CTL_SHOW_LIB_SENT:
	case IMSG_CTL_SHOW_LIB_RCVD:
	case IMSG_CTL_SHOW_LIB_END:
		rt = imsg->data;
		if (params->family != AF_UNSPEC && params->family != rt->af)
			return (0);
		break;
	default:
		break;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB_BEGIN:
		snprintf(dstnet, sizeof(dstnet), "%s/%d",
		    log_addr(rt->af, &rt->prefix), rt->prefixlen);

		json_lib_entry = json_object_new_object();
		json_object_string_add(json_lib_entry, "localLabel",
		    log_label(rt->local_label));

		json_adv_labels = json_object_new_array();
		json_object_object_add(json_lib_entry, "advertisedTo",
		    json_adv_labels);

		json_remote_labels = json_object_new_array();
		json_object_object_add(json_lib_entry, "remoteLabels",
		    json_remote_labels);

		json_object_object_add(json, dstnet, json_lib_entry);
		break;
	case IMSG_CTL_SHOW_LIB_SENT:
		json_adv_label = json_object_new_object();
		json_object_string_add(json_adv_label, "neighborId",
		    inet_ntoa(rt->nexthop));
		json_object_array_add(json_adv_labels, json_adv_label);
		break;
	case IMSG_CTL_SHOW_LIB_RCVD:
		json_remote_label = json_object_new_object();
		json_object_string_add(json_remote_label, "neighborId",
		    inet_ntoa(rt->nexthop));
		json_object_string_add(json_remote_label, "label",
		    log_label(rt->remote_label));
		json_object_int_add(json_remote_label, "inUse", rt->in_use);
		json_object_array_add(json_remote_labels, json_remote_label);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_l2vpn_binding_msg(struct vty *vty, struct imsg *imsg,
    struct show_params *params)
{
	struct ctl_pw	*pw;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_L2VPN_BINDING:
		pw = imsg->data;

		vty_out(vty, "  Destination Address: %s, VC ID: %u%s",
		    inet_ntoa(pw->lsr_id), pw->pwid, VTY_NEWLINE);

		/* local binding */
		if (pw->local_label != NO_LABEL) {
			vty_out(vty, "    Local Label:  %u%s", pw->local_label,
			    VTY_NEWLINE);
			vty_out(vty, "%-8sCbit: %u,    VC Type: %s,    "
			    "GroupID: %u%s", "", pw->local_cword,
			    pw_type_name(pw->type), pw->local_gid,
			    VTY_NEWLINE);
			vty_out(vty, "%-8sMTU: %u%s", "", pw->local_ifmtu,
			    VTY_NEWLINE);
		} else
			vty_out(vty, "    Local Label: unassigned%s",
			    VTY_NEWLINE);

		/* remote binding */
		if (pw->remote_label != NO_LABEL) {
			vty_out(vty, "    Remote Label: %u%s",
			    pw->remote_label,  VTY_NEWLINE);
			vty_out(vty, "%-8sCbit: %u,    VC Type: %s,    "
			    "GroupID: %u%s", "", pw->remote_cword,
			    pw_type_name(pw->type), pw->remote_gid,
			    VTY_NEWLINE);
			vty_out(vty, "%-8sMTU: %u%s", "", pw->remote_ifmtu,
			    VTY_NEWLINE);
		} else
			vty_out(vty, "    Remote Label: unassigned%s",
			    VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_l2vpn_binding_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_pw	*pw;
	json_object	*json_pw;
	char 		 key_name[64];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_L2VPN_BINDING:
		pw = imsg->data;

		json_pw = json_object_new_object();
		json_object_string_add(json_pw, "destination",
		    inet_ntoa(pw->lsr_id));
		json_object_int_add(json_pw, "vcId", pw->pwid);

		/* local binding */
		if (pw->local_label != NO_LABEL) {
			json_object_int_add(json_pw, "localLabel",
			    pw->local_label);
			json_object_int_add(json_pw, "localControlWord",
			    pw->local_cword);
			json_object_string_add(json_pw, "localVcType",
			    pw_type_name(pw->type));
			json_object_int_add(json_pw, "localGroupID",
			    pw->local_gid);
			json_object_int_add(json_pw, "localIfMtu",
			    pw->local_ifmtu);
		} else
			json_object_string_add(json_pw, "localLabel",
			    "unassigned");

		/* remote binding */
		if (pw->remote_label != NO_LABEL) {
			json_object_int_add(json_pw, "remoteLabel",
			    pw->remote_label);
			json_object_int_add(json_pw, "remoteControlWord",
			    pw->remote_cword);
			json_object_string_add(json_pw, "remoteVcType",
			    pw_type_name(pw->type));
			json_object_int_add(json_pw, "remoteGroupID",
			    pw->remote_gid);
			json_object_int_add(json_pw, "remoteIfMtu",
			    pw->remote_ifmtu);
		} else
			json_object_string_add(json_pw, "remoteLabel",
			    "unassigned");

		sprintf(key_name, "%s: %u", inet_ntoa(pw->lsr_id), pw->pwid);
		json_object_object_add(json, key_name, json_pw);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_l2vpn_pw_msg(struct vty *vty, struct imsg *imsg, struct show_params *params)
{
	struct ctl_pw	*pw;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_L2VPN_PW:
		pw = imsg->data;

		vty_out(vty, "%-9s %-15s %-10u %-16s %-10s%s", pw->ifname,
		    inet_ntoa(pw->lsr_id), pw->pwid, pw->l2vpn_name,
		    (pw->status ? "UP" : "DOWN"), VTY_NEWLINE);
		break;
	case IMSG_CTL_END:
		vty_out(vty, "%s", VTY_NEWLINE);
		return (1);
	default:
		break;
	}

	return (0);
}

static int
show_l2vpn_pw_msg_json(struct imsg *imsg, struct show_params *params,
    json_object *json)
{
	struct ctl_pw	*pw;
	json_object	*json_pw;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_L2VPN_PW:
		pw = imsg->data;

		json_pw = json_object_new_object();
		json_object_string_add(json_pw, "peerId", inet_ntoa(pw->lsr_id));
		json_object_int_add(json_pw, "vcId", pw->pwid);
		json_object_string_add(json_pw, "VpnName", pw->l2vpn_name);
		if (pw->status)
			json_object_string_add(json_pw, "status", "up");
		else
			json_object_string_add(json_pw, "status", "down");
		json_object_object_add(json, pw->ifname, json_pw);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

static int
ldp_vty_connect(struct imsgbuf *ibuf)
{
	struct sockaddr_un	 s_un;
	int			 ctl_sock;

	/* connect to ldpd control socket */
	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strlcpy(s_un.sun_path, ctl_sock_path, sizeof(s_un.sun_path));
	if (connect(ctl_sock, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		log_warn("%s: connect: %s", __func__, ctl_sock_path);
		close(ctl_sock);
		return (-1);
	}

	imsg_init(ibuf, ctl_sock);

	return (0);
}

static int
ldp_vty_dispatch_msg(struct vty *vty, struct imsg *imsg, enum show_command cmd,
    struct show_params *params, json_object *json)
{
	int	 ret;

	switch (cmd) {
	case SHOW_IFACE:
		if (params->json)
			ret = show_interface_msg_json(imsg, params, json);
		else
			ret = show_interface_msg(vty, imsg, params);
		break;
	case SHOW_DISC:
		if (params->detail) {
			if (params->json)
				ret = show_discovery_detail_msg_json(imsg,
				    params, json);
			else
				ret = show_discovery_detail_msg(vty, imsg,
				    params);
		} else {
			if (params->json)
				ret = show_discovery_msg_json(imsg, params,
				    json);
			else
				ret = show_discovery_msg(vty, imsg, params);
		}
		break;
	case SHOW_NBR:
		if (params->capabilities) {
			if (params->json)
				ret = show_nbr_capabilities_msg_json(imsg,
				    params, json);
			else
				ret = show_nbr_capabilities_msg(vty, imsg,
				    params);
		} else if (params->detail) {
			if (params->json)
				ret = show_nbr_detail_msg_json(imsg, params,
				    json);
			else
				ret = show_nbr_detail_msg(vty, imsg, params);
		} else {
			if (params->json)
				ret = show_nbr_msg_json(imsg, params, json);
			else
				ret = show_nbr_msg(vty, imsg, params);
		}
		break;
	case SHOW_LIB:
		if (params->detail) {
			if (params->json)
				ret = show_lib_detail_msg_json(imsg, params,
				    json);
			else
				ret = show_lib_detail_msg(vty, imsg, params);
		} else {
			if (params->json)
				ret = show_lib_msg_json(imsg, params, json);
			else
				ret = show_lib_msg(vty, imsg, params);
		}
		break;
	case SHOW_L2VPN_PW:
		if (params->json)
			ret = show_l2vpn_pw_msg_json(imsg, params, json);
		else
			ret = show_l2vpn_pw_msg(vty, imsg, params);
		break;
	case SHOW_L2VPN_BINDING:
		if (params->json)
			ret = show_l2vpn_binding_msg_json(imsg, params, json);
		else
			ret = show_l2vpn_binding_msg(vty, imsg, params);
		break;
	default:
		return (0);
	}

	return (ret);
}

static int
ldp_vty_dispatch(struct vty *vty, struct imsgbuf *ibuf, enum show_command cmd,
    struct show_params *params)
{
	struct imsg		 imsg;
	int			 n, done = 0, ret = CMD_SUCCESS;
	json_object		*json = NULL;

	while (ibuf->w.queued)
		if (msgbuf_write(&ibuf->w) <= 0 && errno != EAGAIN) {
			log_warn("write error");
			close(ibuf->fd);
			return (CMD_WARNING);
		}

	if (params->json)
		json = json_object_new_object();

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
			log_warnx("imsg_read error");
			ret = CMD_WARNING;
			goto done;
		}
		if (n == 0) {
			log_warnx("pipe closed");
			ret = CMD_WARNING;
			goto done;
		}

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1) {
				log_warnx("imsg_get error");
				ret = CMD_WARNING;
				goto done;
			}
			if (n == 0)
				break;
			done = ldp_vty_dispatch_msg(vty, &imsg, cmd, params,
			    json);
			imsg_free(&imsg);
		}
	}

 done:
	close(ibuf->fd);
	if (json) {
		vty_out(vty, "%s%s", json_object_to_json_string_ext(json,
		    JSON_C_TO_STRING_PRETTY), VTY_NEWLINE);
		json_object_free(json);
	}

	return (ret);
}

static int
ldp_vty_get_af(const char *str, int *af)
{
	if (str == NULL) {
		*af = AF_UNSPEC;
		return (0);
	} else if (strcmp(str, "ipv4") == 0) {
		*af = AF_INET;
		return (0);
	} else if (strcmp(str, "ipv6") == 0) {
		*af = AF_INET6;
		return (0);
	}

	return (-1);
}

int
ldp_vty_show_binding(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&params, 0, sizeof(params));
	params.family = af;
	params.detail = vty_get_arg_value(args, "detail") ? 1 : 0;
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	if (!params.detail && !params.json)
		vty_out(vty, "%-4s %-20s %-15s %-11s %-13s %6s%s", "AF",
		    "Destination", "Nexthop", "Local Label", "Remote Label",
		    "In Use", VTY_NEWLINE);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_LIB, 0, 0, -1, NULL, 0);
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_LIB, &params));
}

int
ldp_vty_show_discovery(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&params, 0, sizeof(params));
	params.family = af;
	params.detail = vty_get_arg_value(args, "detail") ? 1 : 0;
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	if (!params.detail && !params.json)
		vty_out(vty, "%-4s %-15s %-8s %-15s %9s%s",
		    "AF", "ID", "Type", "Source", "Holdtime", VTY_NEWLINE);

	if (params.detail)
		imsg_compose(&ibuf, IMSG_CTL_SHOW_DISCOVERY_DTL, 0, 0, -1,
		    NULL, 0);
	else
		imsg_compose(&ibuf, IMSG_CTL_SHOW_DISCOVERY, 0, 0, -1, NULL, 0);
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_DISC, &params));
}

int
ldp_vty_show_interface(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;
	unsigned int		 ifidx = 0;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&params, 0, sizeof(params));
	params.family = af;
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	/* header */
	if (!params.json) {
		vty_out(vty, "%-4s %-11s %-6s %-8s %-12s %3s%s", "AF",
		    "Interface", "State", "Uptime", "Hello Timers", "ac",
		    VTY_NEWLINE);
	}

	imsg_compose(&ibuf, IMSG_CTL_SHOW_INTERFACE, 0, 0, -1, &ifidx,
	    sizeof(ifidx));
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_IFACE, &params));
}

int
ldp_vty_show_capabilities(struct vty *vty, struct vty_arg *args[])
{
	if (vty_get_arg_value(args, "json")) {
		json_object	*json;
		json_object	*json_array;
		json_object	*json_cap;

		json = json_object_new_object();
		json_array = json_object_new_array();
		json_object_object_add(json, "capabilities", json_array);

		/* Dynamic Announcement (0x0506) */
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Dynamic Announcement");
		json_object_string_add(json_cap, "tlvType",
		    "0x0506");
		json_object_array_add(json_array, json_cap);

		/* Typed Wildcard (0x050B) */
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Typed Wildcard");
		json_object_string_add(json_cap, "tlvType",
		    "0x050B");
		json_object_array_add(json_array, json_cap);

		/* Unrecognized Notification (0x0603) */
		json_cap = json_object_new_object();
		json_object_string_add(json_cap, "description",
		    "Unrecognized Notification");
		json_object_string_add(json_cap, "tlvType",
		    "0x0603");
		json_object_array_add(json_array, json_cap);

		vty_out(vty, "%s%s", json_object_to_json_string_ext(json,
		    JSON_C_TO_STRING_PRETTY), VTY_NEWLINE);
		json_object_free(json);
		return (0);
	}

	vty_out(vty,
	    "Supported LDP Capabilities%s"
	    " * Dynamic Announcement (0x0506)%s"
	    " * Typed Wildcard (0x050B)%s"
	    " * Unrecognized Notification (0x0603)%s%s", VTY_NEWLINE,
	    VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	return (0);
}

int
ldp_vty_show_neighbor(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	memset(&params, 0, sizeof(params));
	params.capabilities = vty_get_arg_value(args, "capabilities") ? 1 : 0;
	params.detail = vty_get_arg_value(args, "detail") ? 1 : 0;
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	if (params.capabilities)
		params.detail = 1;

	if (!params.detail && !params.json)
		vty_out(vty, "%-4s %-15s %-11s %-15s %8s%s",
		    "AF", "ID", "State", "Remote Address", "Uptime",
		    VTY_NEWLINE);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_NBR, 0, 0, -1, NULL, 0);
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_NBR, &params));
}

int
ldp_vty_show_atom_binding(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	memset(&params, 0, sizeof(params));
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	imsg_compose(&ibuf, IMSG_CTL_SHOW_L2VPN_BINDING, 0, 0, -1, NULL, 0);
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_L2VPN_BINDING, &params));
}

int
ldp_vty_show_atom_vc(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_params	 params;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	memset(&params, 0, sizeof(params));
	params.json = vty_get_arg_value(args, "json") ? 1 : 0;

	if (!params.json) {
		/* header */
		vty_out(vty, "%-9s %-15s %-10s %-16s %-10s%s",
		    "Interface", "Peer ID", "VC ID", "Name", "Status",
		    VTY_NEWLINE);
		vty_out(vty, "%-9s %-15s %-10s %-16s %-10s%s",
		    "---------", "---------------", "----------",
		    "----------------", "----------", VTY_NEWLINE);
	}

	imsg_compose(&ibuf, IMSG_CTL_SHOW_L2VPN_PW, 0, 0, -1, NULL, 0);
	return (ldp_vty_dispatch(vty, &ibuf, SHOW_L2VPN_PW, &params));
}

int
ldp_vty_clear_nbr(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	const char		*addr_str;
	struct ctl_nbr		 nbr;

	addr_str = vty_get_arg_value(args, "addr");

	memset(&nbr, 0, sizeof(nbr));
	if (addr_str &&
	    (ldp_get_address(addr_str, &nbr.af, &nbr.raddr) == -1 ||
	    bad_addr(nbr.af, &nbr.raddr))) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_CLEAR_NBR, 0, 0, -1, &nbr, sizeof(nbr));

	while (ibuf.w.queued)
		if (msgbuf_write(&ibuf.w) <= 0 && errno != EAGAIN) {
			log_warn("write error");
			close(ibuf.fd);
			return (CMD_WARNING);
		}

	close(ibuf.fd);

	return (CMD_SUCCESS);
}
