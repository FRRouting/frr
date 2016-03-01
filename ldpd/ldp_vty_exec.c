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

struct show_filter {
	int		family;
	union ldpd_addr	addr;
	uint8_t		prefixlen;
};

#define LDPBUFSIZ	65535

static int		 show_interface_msg(struct vty *, struct imsg *,
			    struct show_filter *);
static void		 show_discovery_adj(struct vty *, char *,
			    struct ctl_adj *);
static int		 show_discovery_msg(struct vty *, struct imsg *,
			    struct show_filter *);
static void		 show_nbr_adj(struct vty *, char *, struct ctl_adj *);
static int		 show_nbr_msg(struct vty *, struct imsg *,
			    struct show_filter *);
static int		 show_lib_msg(struct vty *, struct imsg *,
			    struct show_filter *);
static int		 show_l2vpn_binding_msg(struct vty *, struct imsg *);
static int		 show_l2vpn_pw_msg(struct vty *, struct imsg *);
static int		 ldp_vty_connect(struct imsgbuf *);
static int		 ldp_vty_dispatch(struct vty *, struct imsgbuf *,
			    enum show_command, struct show_filter *);
static int		 ldp_vty_get_af(const char *, int *);

static int
show_interface_msg(struct vty *vty, struct imsg *imsg,
    struct show_filter *filter)
{
	struct ctl_iface	*iface;
	char			 timers[BUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_INTERFACE:
		iface = imsg->data;

		if (filter->family != AF_UNSPEC && filter->family != iface->af)
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

static void
show_discovery_adj(struct vty *vty, char *buffer, struct ctl_adj *adj)
{
	size_t	 buflen = strlen(buffer);

	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "      LDP Id: %s:0, Transport address: %s%s",
	    inet_ntoa(adj->id), log_addr(adj->af,
	    &adj->trans_addr), VTY_NEWLINE);
	buflen = strlen(buffer);
	snprintf(buffer + buflen, LDPBUFSIZ - buflen,
	    "          Hold time: %u sec%s", adj->holdtime, VTY_NEWLINE);
}

static int
show_discovery_msg(struct vty *vty, struct imsg *imsg,
    struct show_filter *filter)
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

		if (filter->family != AF_UNSPEC &&
		    ((filter->family == AF_INET && !iface->active_v4) ||
		    (filter->family == AF_INET6 && !iface->active_v6)))
			break;

		buflen = strlen(ifaces_buffer);
		snprintf(ifaces_buffer + buflen, LDPBUFSIZ - buflen,
		     "    %s: %s%s", iface->name, (iface->no_adj) ?
		    "xmit" : "xmit/recv", VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_DISC_TNBR:
		tnbr = imsg->data;

		if (filter->family != AF_UNSPEC && filter->family != tnbr->af)
			break;

		trans_addr = &(ldp_af_conf_get(ldpd_conf,
		    tnbr->af))->trans_addr;
		buflen = strlen(tnbrs_buffer);
		snprintf(tnbrs_buffer + buflen, LDPBUFSIZ - buflen,
		    "    %s -> %s: %s%s", log_addr(tnbr->af, trans_addr),
		    log_addr(tnbr->af, &tnbr->addr), (tnbr->no_adj) ? "xmit" :
		    "xmit/recv", VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_DISC_ADJ:
		adj = imsg->data;

		if (filter->family != AF_UNSPEC && filter->family != adj->af)
			break;

		switch(adj->type) {
		case HELLO_LINK:
			show_discovery_adj(vty, ifaces_buffer, adj);
			break;
		case HELLO_TARGETED:
			show_discovery_adj(vty, tnbrs_buffer, adj);
			break;
		}
		break;
	case IMSG_CTL_END:
		rtr_id.s_addr = ldp_rtr_id_get(ldpd_conf);
		vty_out(vty, "Local LDP Identifier: %s:0%s", inet_ntoa(rtr_id),
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

static void
show_nbr_adj(struct vty *vty, char *buffer, struct ctl_adj *adj)
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
show_nbr_msg(struct vty *vty, struct imsg *imsg, struct show_filter *filter)
{
	struct ctl_adj		*adj;
	struct ctl_nbr		*nbr;
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
		vty_out(vty, "  Session Holdtime: %u sec%s", nbr->holdtime,
		    VTY_NEWLINE);
		vty_out(vty, "  State: %s; Downstream-Unsolicited%s",
		    nbr_state_name(nbr->nbr_state), VTY_NEWLINE);
		vty_out(vty, "  Up time: %s%s", log_time(nbr->uptime),
		    VTY_NEWLINE);
		break;
	case IMSG_CTL_SHOW_NBR_DISC:
		adj = imsg->data;

		switch (adj->af) {
		case AF_INET:
			show_nbr_adj(vty, v4adjs_buffer, adj);
			break;
		case AF_INET6:
			show_nbr_adj(vty, v6adjs_buffer, adj);
			break;
		default:
			fatalx("show_nbr_msg: unknown af");
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
show_lib_msg(struct vty *vty, struct imsg *imsg, struct show_filter *filter)
{
	struct ctl_rt	*rt;
	char		 dstnet[BUFSIZ];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_LIB:
		rt = imsg->data;

		if (filter->family != AF_UNSPEC && filter->family != rt->af)
			break;

		snprintf(dstnet, sizeof(dstnet), "%s/%d",
		    log_addr(rt->af, &rt->prefix), rt->prefixlen);

		if (rt->first) {
			vty_out(vty, "%s%s", dstnet, VTY_NEWLINE);
			vty_out(vty, "%-8sLocal binding: label: %s%s", "",
			    log_label(rt->local_label), VTY_NEWLINE);

			if (rt->remote_label != NO_LABEL) {
				vty_out(vty, "%-8sRemote bindings:%s", "",
				    VTY_NEWLINE);
				vty_out(vty, "%-12sPeer                Label%s",
				    "", VTY_NEWLINE);
				vty_out(vty, "%-12s-----------------   "
				    "---------%s", "", VTY_NEWLINE);
			} else
				vty_out(vty, "%-8sNo remote bindings%s", "",
				    VTY_NEWLINE);
		}
		if (rt->remote_label != NO_LABEL)
			vty_out(vty, "%12s%-20s%s%s", "", inet_ntoa(rt->nexthop),
			    log_label(rt->remote_label), VTY_NEWLINE);
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
show_l2vpn_binding_msg(struct vty *vty, struct imsg *imsg)
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
show_l2vpn_pw_msg(struct vty *vty, struct imsg *imsg)
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
	strlcpy(s_un.sun_path, LDPD_SOCKET, sizeof(s_un.sun_path));
	if (connect(ctl_sock, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		log_warn("%s: connect: %s", __func__, LDPD_SOCKET);
		close(ctl_sock);
		return (-1);
	}

	imsg_init(ibuf, ctl_sock);

	return (0);
}

static int
ldp_vty_dispatch(struct vty *vty, struct imsgbuf *ibuf, enum show_command cmd,
    struct show_filter *filter)
{
	struct imsg		 imsg;
	int			 n, done = 0;

	while (ibuf->w.queued)
		if (msgbuf_write(&ibuf->w) <= 0 && errno != EAGAIN) {
			log_warn("write error");
			close(ibuf->fd);
			return (CMD_WARNING);
		}

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
			log_warnx("imsg_read error");
			close(ibuf->fd);
			return (CMD_WARNING);
		}
		if (n == 0) {
			log_warnx("pipe closed");
			close(ibuf->fd);
			return (CMD_WARNING);
		}

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1) {
				log_warnx("imsg_get error");
				close(ibuf->fd);
				return (CMD_WARNING);
			}
			if (n == 0)
				break;
			switch (cmd) {
			case SHOW_IFACE:
				done = show_interface_msg(vty, &imsg, filter);
				break;
			case SHOW_DISC:
				done = show_discovery_msg(vty, &imsg, filter);
				break;
			case SHOW_NBR:
				done = show_nbr_msg(vty, &imsg, filter);
				break;
			case SHOW_LIB:
				done = show_lib_msg(vty, &imsg, filter);
				break;
			case SHOW_L2VPN_PW:
				done = show_l2vpn_pw_msg(vty, &imsg);
				break;
			case SHOW_L2VPN_BINDING:
				done = show_l2vpn_binding_msg(vty, &imsg);
				break;
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}

	close(ibuf->fd);

	return (CMD_SUCCESS);
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
	struct show_filter	 filter;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_LIB, 0, 0, -1, NULL, 0);

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&filter, 0, sizeof(filter));
	filter.family = af;

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_LIB, &filter));
}

int
ldp_vty_show_discovery(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_filter	 filter;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_DISCOVERY, 0, 0, -1, NULL, 0);

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&filter, 0, sizeof(filter));
	filter.family = af;

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_DISC, &filter));
}

int
ldp_vty_show_interface(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_filter	 filter;
	unsigned int		 ifidx = 0;
	const char		*af_str;
	int			 af;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_INTERFACE, 0, 0, -1, &ifidx,
	    sizeof(ifidx));

	af_str = vty_get_arg_value(args, "address-family");
	if (ldp_vty_get_af(af_str, &af) < 0)
		return (CMD_ERR_NO_MATCH);

	memset(&filter, 0, sizeof(filter));
	filter.family = af;

	/* header */
	vty_out(vty, "%-4s %-11s %-6s %-8s %-12s %3s%s", "AF",
	    "Interface", "State", "Uptime", "Hello Timers", "ac", VTY_NEWLINE);

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_IFACE, &filter));
}

int
ldp_vty_show_neighbor(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_filter	 filter;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_NBR, 0, 0, -1, NULL, 0);

	/* not used */
	memset(&filter, 0, sizeof(filter));

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_NBR, &filter));
}

int
ldp_vty_show_atom_binding(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_filter	 filter;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_L2VPN_BINDING, 0, 0, -1, NULL, 0);

	/* not used */
	memset(&filter, 0, sizeof(filter));

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_L2VPN_BINDING, &filter));
}

int
ldp_vty_show_atom_vc(struct vty *vty, struct vty_arg *args[])
{
	struct imsgbuf		 ibuf;
	struct show_filter	 filter;

	if (ldp_vty_connect(&ibuf) < 0)
		return (CMD_WARNING);

	imsg_compose(&ibuf, IMSG_CTL_SHOW_L2VPN_PW, 0, 0, -1, NULL, 0);

	/* not used */
	memset(&filter, 0, sizeof(filter));

	/* header */
	vty_out(vty, "%-9s %-15s %-10s %-16s %-10s%s",
	    "Interface", "Peer ID", "VC ID", "Name", "Status", VTY_NEWLINE);
	vty_out(vty, "%-9s %-15s %-10s %-16s %-10s%s",
	    "---------", "---------------", "----------",
	    "----------------", "----------", VTY_NEWLINE);

	return (ldp_vty_dispatch(vty, &ibuf, SHOW_L2VPN_PW, &filter));
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
