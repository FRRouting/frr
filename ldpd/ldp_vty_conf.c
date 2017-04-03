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

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"

#include "command.h"
#include "vrf.h"
#include "if.h"
#include "vty.h"
#include "ldp_vty.h"

static void	 ldp_af_iface_config_write(struct vty *, int);
static void	 ldp_af_config_write(struct vty *, int, struct ldpd_conf *,
		    struct ldpd_af_conf *);
static void	 ldp_l2vpn_pw_config_write(struct vty *, struct l2vpn_pw *);
static int	 ldp_vty_get_af(struct vty *);
static int	 ldp_iface_is_configured(struct ldpd_conf *, const char *);
static int	 ldp_vty_nbr_session_holdtime(struct vty *, struct vty_arg *[]);
static int	 ldp_vty_af_session_holdtime(struct vty *, struct vty_arg *[]);

struct cmd_node ldp_node =
{
	LDP_NODE,
	"%s(config-ldp)# ",
	1,
};

struct cmd_node ldp_ipv4_node =
{
	LDP_IPV4_NODE,
	"%s(config-ldp-af)# ",
	1,
};

struct cmd_node ldp_ipv6_node =
{
	LDP_IPV6_NODE,
	"%s(config-ldp-af)# ",
	1,
};

struct cmd_node ldp_ipv4_iface_node =
{
	LDP_IPV4_IFACE_NODE,
	"%s(config-ldp-af-if)# ",
	1,
};

struct cmd_node ldp_ipv6_iface_node =
{
	LDP_IPV6_IFACE_NODE,
	"%s(config-ldp-af-if)# ",
	1,
};

struct cmd_node ldp_l2vpn_node =
{
	LDP_L2VPN_NODE,
	"%s(config-l2vpn)# ",
	1,
};

struct cmd_node ldp_pseudowire_node =
{
	LDP_PSEUDOWIRE_NODE,
	"%s(config-l2vpn-pw)# ",
	1,
};

int
ldp_get_address(const char *str, int *af, union ldpd_addr *addr)
{
	memset(addr, 0, sizeof(*addr));

	if (inet_pton(AF_INET, str, &addr->v4) == 1) {
		*af = AF_INET;
		return (0);
	}

	if (inet_pton(AF_INET6, str, &addr->v6) == 1) {
		*af = AF_INET6;
		return (0);
	}

	return (-1);
}

static void
ldp_af_iface_config_write(struct vty *vty, int af)
{
	struct iface		*iface;
	struct iface_af		*ia;

	RB_FOREACH(iface, iface_head, &ldpd_conf->iface_tree) {
		ia = iface_af_get(iface, af);
		if (!ia->enabled)
			continue;

		vty_out(vty, "  !%s", VTY_NEWLINE);
		vty_out(vty, "  interface %s%s", iface->name, VTY_NEWLINE);

		if (ia->hello_holdtime != LINK_DFLT_HOLDTIME &&
		    ia->hello_holdtime != 0)
			vty_out(vty, "   discovery hello holdtime %u%s",
			    ia->hello_holdtime, VTY_NEWLINE);
		if (ia->hello_interval != DEFAULT_HELLO_INTERVAL &&
		    ia->hello_interval != 0)
			vty_out(vty, "   discovery hello interval %u%s",
			    ia->hello_interval, VTY_NEWLINE);
	}
}

static void
ldp_af_config_write(struct vty *vty, int af, struct ldpd_conf *conf,
    struct ldpd_af_conf *af_conf)
{
	struct tnbr		*tnbr;

	if (!(af_conf->flags & F_LDPD_AF_ENABLED))
		return;

	vty_out(vty, " !%s", VTY_NEWLINE);
	vty_out(vty, " address-family %s%s", af_name(af), VTY_NEWLINE);

	if (af_conf->lhello_holdtime != LINK_DFLT_HOLDTIME &&
	    af_conf->lhello_holdtime != 0 )
		vty_out(vty, "  discovery hello holdtime %u%s",
		    af_conf->lhello_holdtime, VTY_NEWLINE);
	if (af_conf->lhello_interval != DEFAULT_HELLO_INTERVAL &&
	    af_conf->lhello_interval != 0)
		vty_out(vty, "  discovery hello interval %u%s",
		    af_conf->lhello_interval, VTY_NEWLINE);

	if (af_conf->flags & F_LDPD_AF_THELLO_ACCEPT) {
		vty_out(vty, "  discovery targeted-hello accept");
		if (af_conf->acl_thello_accept_from[0] != '\0')
			vty_out(vty, " from %s",
			    af_conf->acl_thello_accept_from);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (af_conf->thello_holdtime != TARGETED_DFLT_HOLDTIME &&
	    af_conf->thello_holdtime != 0)
		vty_out(vty, "  discovery targeted-hello holdtime %u%s",
		    af_conf->thello_holdtime, VTY_NEWLINE);
	if (af_conf->thello_interval != DEFAULT_HELLO_INTERVAL &&
	    af_conf->thello_interval != 0)
		vty_out(vty, "  discovery targeted-hello interval %u%s",
		    af_conf->thello_interval, VTY_NEWLINE);

	if (ldp_addrisset(af, &af_conf->trans_addr))
		vty_out(vty, "  discovery transport-address %s%s",
		    log_addr(af, &af_conf->trans_addr), VTY_NEWLINE);
	else
		vty_out(vty, "  ! Incomplete config, specify a discovery "
		    "transport-address%s", VTY_NEWLINE);

	if ((af_conf->flags & F_LDPD_AF_ALLOCHOSTONLY) ||
	    af_conf->acl_label_allocate_for[0] != '\0') {
		vty_out(vty, "  label local allocate");
		if (af_conf->flags & F_LDPD_AF_ALLOCHOSTONLY)
			vty_out(vty, " host-routes");
		else
			vty_out(vty, " for %s",
			    af_conf->acl_label_allocate_for);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (af_conf->acl_label_advertise_for[0] != '\0' ||
	    af_conf->acl_label_advertise_to[0] != '\0') {
		vty_out(vty, "  label local advertise");
		if (af_conf->acl_label_advertise_to[0] != '\0')
			vty_out(vty, " to %s",
			    af_conf->acl_label_advertise_to);
		if (af_conf->acl_label_advertise_for[0] != '\0')
			vty_out(vty, " for %s",
			    af_conf->acl_label_advertise_for);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (af_conf->flags & F_LDPD_AF_EXPNULL) {
		vty_out(vty, "  label local advertise explicit-null");
		if (af_conf->acl_label_expnull_for[0] != '\0')
			vty_out(vty, " for %s",
			    af_conf->acl_label_expnull_for);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (af_conf->acl_label_accept_for[0] != '\0' ||
	    af_conf->acl_label_accept_from[0] != '\0') {
		vty_out(vty, "  label remote accept");
		if (af_conf->acl_label_accept_from[0] != '\0')
			vty_out(vty, " from %s",
			    af_conf->acl_label_accept_from);
		if (af_conf->acl_label_accept_for[0] != '\0')
			vty_out(vty, " for %s",
			    af_conf->acl_label_accept_for);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (af_conf->flags & F_LDPD_AF_NO_GTSM)
		vty_out(vty, "  ttl-security disable%s", VTY_NEWLINE);

	if (af_conf->keepalive != DEFAULT_KEEPALIVE)
		vty_out(vty, "  session holdtime %u%s", af_conf->keepalive,
		    VTY_NEWLINE);

	RB_FOREACH(tnbr, tnbr_head, &ldpd_conf->tnbr_tree) {
		if (tnbr->af == af) {
			vty_out(vty, "  !%s", VTY_NEWLINE);
			vty_out(vty, "  neighbor %s targeted%s",
			    log_addr(tnbr->af, &tnbr->addr), VTY_NEWLINE);
		}
	}

	ldp_af_iface_config_write(vty, af);

	vty_out(vty, "  !%s", VTY_NEWLINE);
}

int
ldp_config_write(struct vty *vty)
{
	struct nbr_params	*nbrp;

	if (!(ldpd_conf->flags & F_LDPD_ENABLED))
		return (0);

	vty_out(vty, "mpls ldp%s", VTY_NEWLINE);

	if (ldpd_conf->rtr_id.s_addr != 0)
		vty_out(vty, " router-id %s%s",
		    inet_ntoa(ldpd_conf->rtr_id), VTY_NEWLINE);

	if (ldpd_conf->lhello_holdtime != LINK_DFLT_HOLDTIME &&
	    ldpd_conf->lhello_holdtime != 0)
		vty_out(vty, " discovery hello holdtime %u%s",
		    ldpd_conf->lhello_holdtime, VTY_NEWLINE);
	if (ldpd_conf->lhello_interval != DEFAULT_HELLO_INTERVAL &&
	    ldpd_conf->lhello_interval != 0)
		vty_out(vty, " discovery hello interval %u%s",
		    ldpd_conf->lhello_interval, VTY_NEWLINE);

	if (ldpd_conf->thello_holdtime != TARGETED_DFLT_HOLDTIME &&
	    ldpd_conf->thello_holdtime != 0)
		vty_out(vty, " discovery targeted-hello holdtime %u%s",
		    ldpd_conf->thello_holdtime, VTY_NEWLINE);
	if (ldpd_conf->thello_interval != DEFAULT_HELLO_INTERVAL &&
	    ldpd_conf->thello_interval != 0)
		vty_out(vty, " discovery targeted-hello interval %u%s",
		    ldpd_conf->thello_interval, VTY_NEWLINE);

	if (ldpd_conf->trans_pref == DUAL_STACK_LDPOV4)
		vty_out(vty, " dual-stack transport-connection prefer ipv4%s",
		    VTY_NEWLINE);

	if (ldpd_conf->flags & F_LDPD_DS_CISCO_INTEROP)
		vty_out(vty, " dual-stack cisco-interop%s", VTY_NEWLINE);

	RB_FOREACH(nbrp, nbrp_head, &ldpd_conf->nbrp_tree) {
		if (nbrp->flags & F_NBRP_KEEPALIVE)
			vty_out(vty, " neighbor %s session holdtime %u%s",
			    inet_ntoa(nbrp->lsr_id), nbrp->keepalive,
			    VTY_NEWLINE);

		if (nbrp->flags & F_NBRP_GTSM) {
			if (nbrp->gtsm_enabled)
				vty_out(vty, " neighbor %s ttl-security hops "
				    "%u%s",  inet_ntoa(nbrp->lsr_id),
				    nbrp->gtsm_hops, VTY_NEWLINE);
			else
				vty_out(vty, " neighbor %s ttl-security "
				    "disable%s", inet_ntoa(nbrp->lsr_id),
				    VTY_NEWLINE);
		}

		if (nbrp->auth.method == AUTH_MD5SIG)
			vty_out(vty, " neighbor %s password %s%s",
			    inet_ntoa(nbrp->lsr_id), nbrp->auth.md5key,
			    VTY_NEWLINE);
	}

	ldp_af_config_write(vty, AF_INET, ldpd_conf, &ldpd_conf->ipv4);
	ldp_af_config_write(vty, AF_INET6, ldpd_conf, &ldpd_conf->ipv6);
	vty_out(vty, " !%s", VTY_NEWLINE);
	vty_out(vty, "!%s", VTY_NEWLINE);

	return (1);
}

static void
ldp_l2vpn_pw_config_write(struct vty *vty, struct l2vpn_pw *pw)
{
	int	 missing_lsrid = 0;
	int	 missing_pwid = 0;

	vty_out(vty, " !%s", VTY_NEWLINE);
	vty_out(vty, " member pseudowire %s%s", pw->ifname, VTY_NEWLINE);

	if (pw->lsr_id.s_addr != INADDR_ANY)
		vty_out(vty, "  neighbor lsr-id %s%s", inet_ntoa(pw->lsr_id),
		    VTY_NEWLINE);
	else
		missing_lsrid = 1;

	if (pw->flags & F_PW_STATIC_NBR_ADDR)
		vty_out(vty, "  neighbor address %s%s", log_addr(pw->af,
		    &pw->addr), VTY_NEWLINE);

	if (pw->pwid != 0)
		vty_out(vty, "  pw-id %u%s", pw->pwid, VTY_NEWLINE);
	else
		missing_pwid = 1;

	if (!(pw->flags & F_PW_CWORD_CONF))
		vty_out(vty, "  control-word exclude%s", VTY_NEWLINE);

	if (!(pw->flags & F_PW_STATUSTLV_CONF))
		vty_out(vty, "  pw-status disable%s", VTY_NEWLINE);

	if (missing_lsrid)
		vty_out(vty, "  ! Incomplete config, specify a neighbor "
		    "lsr-id%s", VTY_NEWLINE);
	if (missing_pwid)
		vty_out(vty, "  ! Incomplete config, specify a pw-id%s",
		    VTY_NEWLINE);
}

int
ldp_l2vpn_config_write(struct vty *vty)
{
	struct l2vpn		*l2vpn;
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	RB_FOREACH(l2vpn, l2vpn_head, &ldpd_conf->l2vpn_tree) {
		vty_out(vty, "l2vpn %s type vpls%s", l2vpn->name, VTY_NEWLINE);

		if (l2vpn->pw_type != DEFAULT_PW_TYPE)
			vty_out(vty, " vc type ethernet-tagged%s", VTY_NEWLINE);

		if (l2vpn->mtu != DEFAULT_L2VPN_MTU)
			vty_out(vty, " mtu %u%s", l2vpn->mtu, VTY_NEWLINE);

		if (l2vpn->br_ifname[0] != '\0')
			vty_out(vty, " bridge %s%s", l2vpn->br_ifname,
			    VTY_NEWLINE);

		RB_FOREACH(lif, l2vpn_if_head, &l2vpn->if_tree)
			vty_out(vty, " member interface %s%s", lif->ifname,
			    VTY_NEWLINE);

		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
			ldp_l2vpn_pw_config_write(vty, pw);
		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree)
			ldp_l2vpn_pw_config_write(vty, pw);

		vty_out(vty, " !%s", VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return (0);
}

static int
ldp_vty_get_af(struct vty *vty)
{
	switch (vty->node) {
	case LDP_IPV4_NODE:
	case LDP_IPV4_IFACE_NODE:
		return (AF_INET);
	case LDP_IPV6_NODE:
	case LDP_IPV6_IFACE_NODE:
		return (AF_INET6);
	default:
		fatalx("ldp_vty_get_af: unexpected node");
	}
}

static int
ldp_iface_is_configured(struct ldpd_conf *xconf, const char *ifname)
{
	struct l2vpn	*l2vpn;

	if (if_lookup_name(xconf, ifname))
		return (1);

	RB_FOREACH(l2vpn, l2vpn_head, &xconf->l2vpn_tree) {
		if (l2vpn_if_find(l2vpn, ifname))
			return (1);
		if (l2vpn_pw_find(l2vpn, ifname))
			return (1);
	}

	return (0);
}

int
ldp_vty_mpls_ldp(struct vty *vty, struct vty_arg *args[])
{
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;

	if (disable)
		vty_conf->flags &= ~F_LDPD_ENABLED;
	else {
		vty->node = LDP_NODE;
		vty_conf->flags |= F_LDPD_ENABLED;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_address_family(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
 	const char		*af_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	af_str = vty_get_arg_value(args, "address-family");

	if (strcmp(af_str, "ipv4") == 0) {
		af = AF_INET;
		af_conf = &vty_conf->ipv4;
	} else if (strcmp(af_str, "ipv6") == 0) {
		af = AF_INET6;
		af_conf = &vty_conf->ipv6;
	} else
		return (CMD_WARNING);

	if (disable) {
		af_conf->flags &= ~F_LDPD_AF_ENABLED;
		ldp_reload(vty_conf);
		return (CMD_SUCCESS);
	}

	switch (af) {
	case AF_INET:
		vty->node = LDP_IPV4_NODE;
		break;
	case AF_INET6:
		vty->node = LDP_IPV6_NODE;
		break;
	default:
		fatalx("ldp_vty_address_family: unknown af");
	}
	af_conf->flags |= F_LDPD_AF_ENABLED;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_disc_holdtime(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	struct iface		*iface;
	struct iface_af		*ia;
	int			 af;
	char			*ep;
	long int		 secs;
	enum hello_type		 hello_type;
	const char		*seconds_str;
	const char		*hello_type_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	seconds_str = vty_get_arg_value(args, "seconds");
	hello_type_str = vty_get_arg_value(args, "hello_type");

	secs = strtol(seconds_str, &ep, 10);
	if (*ep != '\0' || secs < MIN_HOLDTIME || secs > MAX_HOLDTIME) {
		vty_out(vty, "%% Invalid holdtime%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (hello_type_str[0] == 'h')
		hello_type = HELLO_LINK;
	else
		hello_type = HELLO_TARGETED;

	switch (vty->node) {
	case LDP_NODE:
		if (disable) {
			switch (hello_type) {
			case HELLO_LINK:
				vty_conf->lhello_holdtime = LINK_DFLT_HOLDTIME;
				break;
			case HELLO_TARGETED:
				vty_conf->thello_holdtime =
				    TARGETED_DFLT_HOLDTIME;
				break;
			}
		} else {
			switch (hello_type) {
			case HELLO_LINK:
				vty_conf->lhello_holdtime = secs;
				break;
			case HELLO_TARGETED:
				vty_conf->thello_holdtime = secs;
				break;
			}
		}
		ldp_reload(vty_conf);
		break;
	case LDP_IPV4_NODE:
	case LDP_IPV6_NODE:
		af = ldp_vty_get_af(vty);
		af_conf = ldp_af_conf_get(vty_conf, af);

		if (disable) {
			switch (hello_type) {
			case HELLO_LINK:
				af_conf->lhello_holdtime = 0;
				break;
			case HELLO_TARGETED:
				af_conf->thello_holdtime = 0;
				break;
			}
		} else {
			switch (hello_type) {
			case HELLO_LINK:
				af_conf->lhello_holdtime = secs;
				break;
			case HELLO_TARGETED:
				af_conf->thello_holdtime = secs;
				break;
			}
		}
		ldp_reload(vty_conf);
		break;
	case LDP_IPV4_IFACE_NODE:
	case LDP_IPV6_IFACE_NODE:
		af = ldp_vty_get_af(vty);
		iface = VTY_GET_CONTEXT(iface);
		VTY_CHECK_CONTEXT(iface);

		ia = iface_af_get(iface, af);
		if (disable)
			ia->hello_holdtime = 0;
		else
			ia->hello_holdtime = secs;

		ldp_reload(vty_conf);
		break;
	default:
		fatalx("ldp_vty_disc_holdtime: unexpected node");
	}

	return (CMD_SUCCESS);
}

int
ldp_vty_disc_interval(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	struct iface		*iface;
	struct iface_af		*ia;
	int			 af;
	char			*ep;
	long int		 secs;
	enum hello_type		 hello_type;
	const char		*seconds_str;
	const char		*hello_type_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	seconds_str = vty_get_arg_value(args, "seconds");
	hello_type_str = vty_get_arg_value(args, "hello_type");

	secs = strtol(seconds_str, &ep, 10);
	if (*ep != '\0' || secs < MIN_HELLO_INTERVAL ||
	    secs > MAX_HELLO_INTERVAL) {
		vty_out(vty, "%% Invalid interval%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (hello_type_str[0] == 'h')
		hello_type = HELLO_LINK;
	else
		hello_type = HELLO_TARGETED;

	switch (vty->node) {
	case LDP_NODE:
		if (disable) {
			switch (hello_type) {
			case HELLO_LINK:
				vty_conf->lhello_interval = LINK_DFLT_HOLDTIME;
				break;
			case HELLO_TARGETED:
				vty_conf->thello_interval =
				    TARGETED_DFLT_HOLDTIME;
				break;
			}
		} else {
			switch (hello_type) {
			case HELLO_LINK:
				vty_conf->lhello_interval = secs;
				break;
			case HELLO_TARGETED:
				vty_conf->thello_interval = secs;
				break;
			}
		}
		ldp_reload(vty_conf);
		break;
	case LDP_IPV4_NODE:
	case LDP_IPV6_NODE:
		af = ldp_vty_get_af(vty);
		af_conf = ldp_af_conf_get(vty_conf, af);

		if (disable) {
			switch (hello_type) {
			case HELLO_LINK:
				af_conf->lhello_interval = 0;
				break;
			case HELLO_TARGETED:
				af_conf->thello_interval = 0;
				break;
			}
		} else {
			switch (hello_type) {
			case HELLO_LINK:
				af_conf->lhello_interval = secs;
				break;
			case HELLO_TARGETED:
				af_conf->thello_interval = secs;
				break;
			}
		}
		ldp_reload(vty_conf);
		break;
	case LDP_IPV4_IFACE_NODE:
	case LDP_IPV6_IFACE_NODE:
		af = ldp_vty_get_af(vty);
		iface = VTY_GET_CONTEXT(iface);
		VTY_CHECK_CONTEXT(iface);

		ia = iface_af_get(iface, af);
		if (disable)
			ia->hello_interval = 0;
		else
			ia->hello_interval = secs;

		ldp_reload(vty_conf);
		break;
	default:
		fatalx("ldp_vty_disc_interval: unexpected node");
	}

	return (CMD_SUCCESS);
}

int
ldp_vty_targeted_hello_accept(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*acl_from_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	acl_from_str = vty_get_arg_value(args, "from_acl");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable) {
		af_conf->flags &= ~F_LDPD_AF_THELLO_ACCEPT;
		af_conf->acl_thello_accept_from[0] = '\0';
	} else {
		af_conf->flags |= F_LDPD_AF_THELLO_ACCEPT;
		if (acl_from_str)
			strlcpy(af_conf->acl_thello_accept_from, acl_from_str,
			    sizeof(af_conf->acl_thello_accept_from));
		else
			af_conf->acl_thello_accept_from[0] = '\0';
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

static int
ldp_vty_nbr_session_holdtime(struct vty *vty, struct vty_arg *args[])
{
	char			*ep;
	long int		 secs;
	struct in_addr		 lsr_id;
	struct nbr_params	*nbrp;
	const char		*seconds_str;
	const char		*lsr_id_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	seconds_str = vty_get_arg_value(args, "seconds");
	lsr_id_str = vty_get_arg_value(args, "lsr_id");

	if (inet_pton(AF_INET, lsr_id_str, &lsr_id) != 1 ||
	    bad_addr_v4(lsr_id)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	secs = strtol(seconds_str, &ep, 10);
	if (*ep != '\0' || secs < MIN_KEEPALIVE || secs > MAX_KEEPALIVE) {
		vty_out(vty, "%% Invalid holdtime%s", VTY_NEWLINE);
		return (CMD_SUCCESS);
	}

	nbrp = nbr_params_find(vty_conf, lsr_id);

	if (disable) {
		if (nbrp == NULL)
			return (CMD_SUCCESS);

		nbrp->keepalive = 0;
		nbrp->flags &= ~F_NBRP_KEEPALIVE;
	} else {
		if (nbrp == NULL) {
			nbrp = nbr_params_new(lsr_id);
			RB_INSERT(nbrp_head, &vty_conf->nbrp_tree, nbrp);
			QOBJ_REG(nbrp, nbr_params);
		} else if (nbrp->keepalive == secs)
			return (CMD_SUCCESS);

		nbrp->keepalive = secs;
		nbrp->flags |= F_NBRP_KEEPALIVE;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

static int
ldp_vty_af_session_holdtime(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	char			*ep;
	long int		 secs;
	const char		*seconds_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	seconds_str = vty_get_arg_value(args, "seconds");

	secs = strtol(seconds_str, &ep, 10);
	if (*ep != '\0' || secs < MIN_KEEPALIVE || secs > MAX_KEEPALIVE) {
		vty_out(vty, "%% Invalid holdtime%s", VTY_NEWLINE);
		return (CMD_SUCCESS);
	}

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable)
		af_conf->keepalive = DEFAULT_KEEPALIVE;
	else
		af_conf->keepalive = secs;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_session_holdtime(struct vty *vty, struct vty_arg *args[])
{
	switch (vty->node) {
	case LDP_NODE:
		return (ldp_vty_nbr_session_holdtime(vty, args));
	case LDP_IPV4_NODE:
	case LDP_IPV6_NODE:
		return (ldp_vty_af_session_holdtime(vty, args));
	default:
		fatalx("ldp_vty_session_holdtime: unexpected node");
	}
}

int
ldp_vty_interface(struct vty *vty, struct vty_arg *args[])
{
	int			 af;
	struct iface		*iface;
	struct iface_af		*ia;
	const char		*ifname;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	ifname = vty_get_arg_value(args, "ifname");

	af = ldp_vty_get_af(vty);
	iface = if_lookup_name(vty_conf, ifname);

	if (disable) {
		if (iface == NULL)
			return (CMD_SUCCESS);

		ia = iface_af_get(iface, af);
		if (ia->enabled == 0)
			return (CMD_SUCCESS);

		ia->enabled = 0;
		ia->hello_holdtime = 0;
		ia->hello_interval = 0;

		ldp_reload(vty_conf);

		return (CMD_SUCCESS);
	}

	if (iface == NULL) {
		if (ldp_iface_is_configured(vty_conf, ifname)) {
			vty_out(vty, "%% Interface is already in use%s",
			    VTY_NEWLINE);
			return (CMD_SUCCESS);
		}

		iface = if_new(ifname);
		ia = iface_af_get(iface, af);
		ia->enabled = 1;
		RB_INSERT(iface_head, &vty_conf->iface_tree, iface);
		QOBJ_REG(iface, iface);

		ldp_reload(vty_conf);
	} else {
		ia = iface_af_get(iface, af);
		if (!ia->enabled) {
			ia->enabled = 1;
			ldp_reload(vty_conf);
		}
	}

	switch (af) {
	case AF_INET:
		VTY_PUSH_CONTEXT(LDP_IPV4_IFACE_NODE, iface);
		break;
	case AF_INET6:
		VTY_PUSH_CONTEXT(LDP_IPV6_IFACE_NODE, iface);
		break;
	default:
		break;
	}

	return (CMD_SUCCESS);
}

int
ldp_vty_trans_addr(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*addr_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	addr_str = vty_get_arg_value(args, "addr");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable)
		memset(&af_conf->trans_addr, 0, sizeof(af_conf->trans_addr));
	else {
		if (inet_pton(af, addr_str, &af_conf->trans_addr) != 1 ||
		    bad_addr(af, &af_conf->trans_addr)) {
			vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
			return (CMD_SUCCESS);
		}
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_neighbor_targeted(struct vty *vty, struct vty_arg *args[])
{
	int			 af;
	union ldpd_addr		 addr;
	struct tnbr		*tnbr;
	const char		*addr_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	addr_str = vty_get_arg_value(args, "addr");

	af = ldp_vty_get_af(vty);

	if (inet_pton(af, addr_str, &addr) != 1 ||
	    bad_addr(af, &addr)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}
	if (af == AF_INET6 && IN6_IS_SCOPE_EMBED(&addr.v6)) {
		vty_out(vty, "%% Address can not be link-local%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	tnbr = tnbr_find(vty_conf, af, &addr);

	if (disable) {
		if (tnbr == NULL)
			return (CMD_SUCCESS);

		QOBJ_UNREG(tnbr);
		RB_REMOVE(tnbr_head, &vty_conf->tnbr_tree, tnbr);
		free(tnbr);

		ldp_reload(vty_conf);

		return (CMD_SUCCESS);
	}

	if (tnbr)
		return (CMD_SUCCESS);

	tnbr = tnbr_new(af, &addr);
	tnbr->flags |= F_TNBR_CONFIGURED;
	RB_INSERT(tnbr_head, &vty_conf->tnbr_tree, tnbr);
	QOBJ_REG(tnbr, tnbr);

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_label_advertise(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*acl_to_str;
	const char		*acl_for_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	acl_to_str = vty_get_arg_value(args, "to_acl");
	acl_for_str = vty_get_arg_value(args, "for_acl");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable) {
		af_conf->acl_label_advertise_to[0] = '\0';
		af_conf->acl_label_advertise_for[0] = '\0';
	} else {
		if (acl_to_str)
			strlcpy(af_conf->acl_label_advertise_to, acl_to_str,
			    sizeof(af_conf->acl_label_advertise_to));
		else
			af_conf->acl_label_advertise_to[0] = '\0';
		if (acl_for_str)
			strlcpy(af_conf->acl_label_advertise_for, acl_for_str,
			    sizeof(af_conf->acl_label_advertise_for));
		else
			af_conf->acl_label_advertise_for[0] = '\0';
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_label_allocate(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*acl_for_str;
	const char		*host_routes_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	acl_for_str = vty_get_arg_value(args, "for_acl");
	host_routes_str = vty_get_arg_value(args, "host-routes");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	af_conf->flags &= ~F_LDPD_AF_ALLOCHOSTONLY;
	af_conf->acl_label_allocate_for[0] = '\0';
	if (!disable) {
		if (host_routes_str)
			af_conf->flags |= F_LDPD_AF_ALLOCHOSTONLY;
		else
			strlcpy(af_conf->acl_label_allocate_for, acl_for_str,
			    sizeof(af_conf->acl_label_allocate_for));
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_label_expnull(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*acl_for_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	acl_for_str = vty_get_arg_value(args, "for_acl");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable) {
		af_conf->flags &= ~F_LDPD_AF_EXPNULL;
		af_conf->acl_label_expnull_for[0] = '\0';
	} else {
		af_conf->flags |= F_LDPD_AF_EXPNULL;
		if (acl_for_str)
			strlcpy(af_conf->acl_label_expnull_for, acl_for_str,
			    sizeof(af_conf->acl_label_expnull_for));
		else
			af_conf->acl_label_expnull_for[0] = '\0';
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_label_accept(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	const char		*acl_from_str;
	const char		*acl_for_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	acl_from_str = vty_get_arg_value(args, "from_acl");
	acl_for_str = vty_get_arg_value(args, "for_acl");

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable) {
		af_conf->acl_label_accept_from[0] = '\0';
		af_conf->acl_label_accept_for[0] = '\0';
	} else {
		if (acl_from_str)
			strlcpy(af_conf->acl_label_accept_from, acl_from_str,
			    sizeof(af_conf->acl_label_accept_from));
		else
			af_conf->acl_label_accept_from[0] = '\0';
		if (acl_for_str)
			strlcpy(af_conf->acl_label_accept_for, acl_for_str,
			    sizeof(af_conf->acl_label_accept_for));
		else
			af_conf->acl_label_accept_for[0] = '\0';
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_ttl_security(struct vty *vty, struct vty_arg *args[])
{
	struct ldpd_af_conf	*af_conf;
	int			 af;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;

	af = ldp_vty_get_af(vty);
	af_conf = ldp_af_conf_get(vty_conf, af);

	if (disable)
		af_conf->flags &= ~F_LDPD_AF_NO_GTSM;
	else
		af_conf->flags |= F_LDPD_AF_NO_GTSM;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_router_id(struct vty *vty, struct vty_arg *args[])
{
	const char		*addr_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	addr_str = vty_get_arg_value(args, "addr");

	if (disable)
		vty_conf->rtr_id.s_addr = INADDR_ANY;
	else {
		if (inet_pton(AF_INET, addr_str, &vty_conf->rtr_id) != 1 ||
		    bad_addr_v4(vty_conf->rtr_id)) {
			vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
			return (CMD_SUCCESS);
		}
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_ds_cisco_interop(struct vty *vty, struct vty_arg *args[])
{
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;

	if (disable)
		vty_conf->flags &= ~F_LDPD_DS_CISCO_INTEROP;
	else
		vty_conf->flags |= F_LDPD_DS_CISCO_INTEROP;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_trans_pref_ipv4(struct vty *vty, struct vty_arg *args[])
{
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;

	if (disable)
		vty_conf->trans_pref = DUAL_STACK_LDPOV6;
	else
		vty_conf->trans_pref = DUAL_STACK_LDPOV4;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_neighbor_password(struct vty *vty, struct vty_arg *args[])
{
	struct in_addr		 lsr_id;
	size_t			 password_len;
	struct nbr_params	*nbrp;
	const char		*lsr_id_str;
	const char		*password_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	lsr_id_str = vty_get_arg_value(args, "lsr_id");
	password_str = vty_get_arg_value(args, "password");

	if (inet_pton(AF_INET, lsr_id_str, &lsr_id) != 1 ||
	    bad_addr_v4(lsr_id)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	nbrp = nbr_params_find(vty_conf, lsr_id);

	if (disable) {
		if (nbrp == NULL)
			return (CMD_SUCCESS);

		memset(&nbrp->auth, 0, sizeof(nbrp->auth));
		nbrp->auth.method = AUTH_NONE;
	} else {
		if (nbrp == NULL) {
			nbrp = nbr_params_new(lsr_id);
			RB_INSERT(nbrp_head, &vty_conf->nbrp_tree, nbrp);
			QOBJ_REG(nbrp, nbr_params);
		} else if (nbrp->auth.method == AUTH_MD5SIG &&
		    strcmp(nbrp->auth.md5key, password_str) == 0)
			return (CMD_SUCCESS);

		password_len = strlcpy(nbrp->auth.md5key, password_str,
		    sizeof(nbrp->auth.md5key));
		if (password_len >= sizeof(nbrp->auth.md5key))
			vty_out(vty, "%% password has been truncated to %zu "
			    "characters.", sizeof(nbrp->auth.md5key) - 1);
		nbrp->auth.md5key_len = password_len;
		nbrp->auth.method = AUTH_MD5SIG;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_neighbor_ttl_security(struct vty *vty, struct vty_arg *args[])
{
	struct in_addr		 lsr_id;
	struct nbr_params	*nbrp;
	long int		 hops = 0;
	char			*ep;
	const char		*lsr_id_str;
	const char		*hops_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	lsr_id_str = vty_get_arg_value(args, "lsr_id");
	hops_str = vty_get_arg_value(args, "hops");

	if (inet_pton(AF_INET, lsr_id_str, &lsr_id) != 1 ||
	    bad_addr_v4(lsr_id)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (hops_str) {
		hops = strtol(hops_str, &ep, 10);
		if (*ep != '\0' || hops < 1 || hops > 254) {
			vty_out(vty, "%% Invalid hop count%s", VTY_NEWLINE);
			return (CMD_SUCCESS);
		}
	}

	nbrp = nbr_params_find(vty_conf, lsr_id);

	if (disable) {
		if (nbrp == NULL)
			return (CMD_SUCCESS);

		nbrp->flags &= ~(F_NBRP_GTSM|F_NBRP_GTSM_HOPS);
		nbrp->gtsm_enabled = 0;
		nbrp->gtsm_hops = 0;
	} else {
		if (nbrp == NULL) {
			nbrp = nbr_params_new(lsr_id);
			RB_INSERT(nbrp_head, &vty_conf->nbrp_tree, nbrp);
			QOBJ_REG(nbrp, nbr_params);
		}

		nbrp->flags |= F_NBRP_GTSM;
		nbrp->flags &= ~F_NBRP_GTSM_HOPS;
		if (hops_str) {
			nbrp->gtsm_enabled = 1;
			nbrp->gtsm_hops = hops;
			nbrp->flags |= F_NBRP_GTSM_HOPS;
		} else
			nbrp->gtsm_enabled = 0;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn(struct vty *vty, struct vty_arg *args[])
{
	struct l2vpn		*l2vpn;
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;
	const char		*name_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	name_str = vty_get_arg_value(args, "name");

	l2vpn = l2vpn_find(vty_conf, name_str);

	if (disable) {
		if (l2vpn == NULL)
			return (CMD_SUCCESS);

		RB_FOREACH(lif, l2vpn_if_head, &l2vpn->if_tree)
			QOBJ_UNREG(lif);
		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree)
			QOBJ_UNREG(pw);
		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree)
			QOBJ_UNREG(pw);
		QOBJ_UNREG(l2vpn);
		RB_REMOVE(l2vpn_head, &vty_conf->l2vpn_tree, l2vpn);
		l2vpn_del(l2vpn);

		ldp_reload(vty_conf);

		return (CMD_SUCCESS);
	}

	if (l2vpn) {
		VTY_PUSH_CONTEXT(LDP_L2VPN_NODE, l2vpn);
		return (CMD_SUCCESS);
	}

	l2vpn = l2vpn_new(name_str);
	l2vpn->type = L2VPN_TYPE_VPLS;
	RB_INSERT(l2vpn_head, &vty_conf->l2vpn_tree, l2vpn);
	QOBJ_REG(l2vpn, l2vpn);

	VTY_PUSH_CONTEXT(LDP_L2VPN_NODE, l2vpn);

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_bridge(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT(l2vpn, l2vpn);
	const char		*ifname;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	ifname = vty_get_arg_value(args, "ifname");

	if (disable)
		memset(l2vpn->br_ifname, 0, sizeof(l2vpn->br_ifname));
	else
		strlcpy(l2vpn->br_ifname, ifname, sizeof(l2vpn->br_ifname));

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_mtu(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT(l2vpn, l2vpn);
	char			*ep;
	int			 mtu;
	const char		*mtu_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	mtu_str = vty_get_arg_value(args, "mtu");

	mtu = strtol(mtu_str, &ep, 10);
	if (*ep != '\0' || mtu < MIN_L2VPN_MTU || mtu > MAX_L2VPN_MTU) {
		vty_out(vty, "%% Invalid MTU%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (disable)
		l2vpn->mtu = DEFAULT_L2VPN_MTU;
	else
		l2vpn->mtu = mtu;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pwtype(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT(l2vpn, l2vpn);
	int			 pw_type;
	const char		*type_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	type_str = vty_get_arg_value(args, "type");

	if (strcmp(type_str, "ethernet") == 0)
		pw_type = PW_TYPE_ETHERNET;
	else
		pw_type = PW_TYPE_ETHERNET_TAGGED;

	if (disable)
		l2vpn->pw_type = DEFAULT_PW_TYPE;
	else
		l2vpn->pw_type = pw_type;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_interface(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT(l2vpn, l2vpn);
	struct l2vpn_if		*lif;
	const char		*ifname;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	ifname = vty_get_arg_value(args, "ifname");

	lif = l2vpn_if_find(l2vpn, ifname);

	if (disable) {
		if (lif == NULL)
			return (CMD_SUCCESS);

		QOBJ_UNREG(lif);
		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		free(lif);

		ldp_reload(vty_conf);

		return (CMD_SUCCESS);
	}

	if (lif)
		return (CMD_SUCCESS);

	if (ldp_iface_is_configured(vty_conf, ifname)) {
		vty_out(vty, "%% Interface is already in use%s", VTY_NEWLINE);
		return (CMD_SUCCESS);
	}

	lif = l2vpn_if_new(l2vpn, ifname);
	RB_INSERT(l2vpn_if_head, &l2vpn->if_tree, lif);
	QOBJ_REG(lif, l2vpn_if);

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pseudowire(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT(l2vpn, l2vpn);
	struct l2vpn_pw		*pw;
	const char		*ifname;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	ifname = vty_get_arg_value(args, "ifname");

	pw = l2vpn_pw_find(l2vpn, ifname);

	if (disable) {
		if (pw == NULL)
			return (CMD_SUCCESS);

		QOBJ_UNREG(pw);
		if (pw->lsr_id.s_addr == INADDR_ANY || pw->pwid == 0)
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		else
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		free(pw);

		ldp_reload(vty_conf);

		return (CMD_SUCCESS);
	}

	if (pw) {
		VTY_PUSH_CONTEXT_SUB(LDP_PSEUDOWIRE_NODE, pw);
		return (CMD_SUCCESS);
	}

	if (ldp_iface_is_configured(vty_conf, ifname)) {
		vty_out(vty, "%% Interface is already in use%s", VTY_NEWLINE);
		return (CMD_SUCCESS);
	}

	pw = l2vpn_pw_new(l2vpn, ifname);
	pw->flags = F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF;
	RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
	QOBJ_REG(pw, l2vpn_pw);

	VTY_PUSH_CONTEXT_SUB(LDP_PSEUDOWIRE_NODE, pw);

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pw_cword(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT_SUB(l2vpn_pw, pw);
	const char		*preference_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	preference_str = vty_get_arg_value(args, "preference");

	if (disable)
		pw->flags |= F_PW_CWORD_CONF;
	else {
		if (preference_str[0] == 'e')
			pw->flags &= ~F_PW_CWORD_CONF;
		else
			pw->flags |= F_PW_CWORD_CONF;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pw_nbr_addr(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT_SUB(l2vpn_pw, pw);
	int			 af;
	union ldpd_addr		 addr;
	const char		*addr_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	addr_str = vty_get_arg_value(args, "addr");

	if (ldp_get_address(addr_str, &af, &addr) == -1 ||
	    bad_addr(af, &addr)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (disable) {
		pw->af = AF_UNSPEC;
		memset(&pw->addr, 0, sizeof(pw->addr));
		pw->flags &= ~F_PW_STATIC_NBR_ADDR;
	} else {
		pw->af = af;
		pw->addr = addr;
		pw->flags |= F_PW_STATIC_NBR_ADDR;
	}

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pw_nbr_id(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT_SUB(l2vpn_pw, pw);
	struct in_addr		 lsr_id;
	const char		*lsr_id_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	lsr_id_str = vty_get_arg_value(args, "lsr-id");

	if (inet_pton(AF_INET, lsr_id_str, &lsr_id) != 1 ||
	    bad_addr_v4(lsr_id)) {
		vty_out(vty, "%% Malformed address%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (disable)
		pw->lsr_id.s_addr = INADDR_ANY;
	else
		pw->lsr_id = lsr_id;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pw_pwid(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT_SUB(l2vpn_pw, pw);
	char			*ep;
	uint32_t		 pwid;
	const char		*pwid_str;
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	pwid_str = vty_get_arg_value(args, "pwid");

	pwid = strtol(pwid_str, &ep, 10);
	if (*ep != '\0' || pwid < MIN_PWID_ID || pwid > MAX_PWID_ID) {
		vty_out(vty, "%% Invalid pw-id%s", VTY_NEWLINE);
		return (CMD_WARNING);
	}

	if (disable)
		pw->pwid = 0;
	else
		pw->pwid = pwid;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

int
ldp_vty_l2vpn_pw_pwstatus(struct vty *vty, struct vty_arg *args[])
{
	VTY_DECLVAR_CONTEXT_SUB(l2vpn_pw, pw);
	int			 disable;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;

	if (disable)
		pw->flags |= F_PW_STATUSTLV_CONF;
	else
		pw->flags &= ~F_PW_STATUSTLV_CONF;

	ldp_reload(vty_conf);

	return (CMD_SUCCESS);
}

struct iface *
iface_new_api(struct ldpd_conf *conf, const char *name)
{
	const char		*ifname = name;
	struct iface		*iface;

	if (ldp_iface_is_configured(conf, ifname))
		return NULL;

	iface = if_new(name);
	RB_INSERT(iface_head, &conf->iface_tree, iface);
	QOBJ_REG(iface, iface);
	return (iface);
}

void
iface_del_api(struct ldpd_conf *conf, struct iface *iface)
{
	QOBJ_UNREG(iface);
	RB_REMOVE(iface_head, &conf->iface_tree, iface);
	free(iface);
}

struct tnbr *
tnbr_new_api(struct ldpd_conf *conf, int af, union ldpd_addr *addr)
{
	struct tnbr		*tnbr;

	if (af == AF_INET6 && IN6_IS_SCOPE_EMBED(&addr->v6))
		return (NULL);

	if (tnbr_find(conf, af, addr))
		return (NULL);

	tnbr = tnbr_new(af, addr);
	tnbr->flags |= F_TNBR_CONFIGURED;
	RB_INSERT(tnbr_head, &conf->tnbr_tree, tnbr);
	QOBJ_REG(tnbr, tnbr);
	return (tnbr);
}

void
tnbr_del_api(struct ldpd_conf *conf, struct tnbr *tnbr)
{
	QOBJ_UNREG(tnbr);
	RB_REMOVE(tnbr_head, &conf->tnbr_tree, tnbr);
	free(tnbr);
}

struct nbr_params *
nbrp_new_api(struct ldpd_conf *conf, struct in_addr lsr_id)
{
	struct nbr_params	*nbrp;

	if (nbr_params_find(conf, lsr_id))
		return (NULL);

	nbrp = nbr_params_new(lsr_id);
	RB_INSERT(nbrp_head, &conf->nbrp_tree, nbrp);
	QOBJ_REG(nbrp, nbr_params);
	return (nbrp);
}

void
nbrp_del_api(struct ldpd_conf *conf, struct nbr_params *nbrp)
{
	QOBJ_UNREG(nbrp);
	RB_REMOVE(nbrp_head, &conf->nbrp_tree, nbrp);
	free(nbrp);
}

struct l2vpn *
l2vpn_new_api(struct ldpd_conf *conf, const char *name)
{
	struct l2vpn		*l2vpn;

	if (l2vpn_find(conf, name))
		return (NULL);

	l2vpn = l2vpn_new(name);
	l2vpn->type = L2VPN_TYPE_VPLS;
	RB_INSERT(l2vpn_head, &conf->l2vpn_tree, l2vpn);
	QOBJ_REG(l2vpn, l2vpn);
	return (l2vpn);
}

void
l2vpn_del_api(struct ldpd_conf *conf, struct l2vpn *l2vpn)
{
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	while ((lif = RB_ROOT(&l2vpn->if_tree)) != NULL) {
		QOBJ_UNREG(lif);
		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		free(lif);
	}
	while ((pw = RB_ROOT(&l2vpn->pw_tree)) != NULL) {
		QOBJ_UNREG(pw);
		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		free(pw);
	}
	while ((pw = RB_ROOT(&l2vpn->pw_inactive_tree)) != NULL) {
		QOBJ_UNREG(pw);
		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		free(pw);
	}
	QOBJ_UNREG(l2vpn);
	RB_REMOVE(l2vpn_head, &conf->l2vpn_tree, l2vpn);
	free(l2vpn);
}

struct l2vpn_if *
l2vpn_if_new_api(struct ldpd_conf *conf, struct l2vpn *l2vpn,
    const char *ifname)
{
	struct l2vpn_if		*lif;

	if (ldp_iface_is_configured(conf, ifname))
		return (NULL);

	lif = l2vpn_if_new(l2vpn, ifname);
	RB_INSERT(l2vpn_if_head, &l2vpn->if_tree, lif);
	QOBJ_REG(lif, l2vpn_if);
	return (lif);
}

void
l2vpn_if_del_api(struct l2vpn *l2vpn, struct l2vpn_if *lif)
{
	QOBJ_UNREG(lif);
	RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
	free(lif);
}

struct l2vpn_pw *
l2vpn_pw_new_api(struct ldpd_conf *conf, struct l2vpn *l2vpn,
    const char *ifname)
{
	struct l2vpn_pw		*pw;

	if (ldp_iface_is_configured(conf, ifname))
		return (NULL);

	pw = l2vpn_pw_new(l2vpn, ifname);
	pw->flags = F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF;
	RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
	QOBJ_REG(pw, l2vpn_pw);
	return (pw);
}

void
l2vpn_pw_del_api(struct l2vpn *l2vpn, struct l2vpn_pw *pw)
{
	QOBJ_UNREG(pw);
	RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
	free(pw);
}
