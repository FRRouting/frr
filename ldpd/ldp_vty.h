/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef _LDP_VTY_H_
#define _LDP_VTY_H_

#include "vty.h"

extern struct cmd_node ldp_node;
extern struct cmd_node ldp_ipv4_node;
extern struct cmd_node ldp_ipv6_node;
extern struct cmd_node ldp_ipv4_iface_node;
extern struct cmd_node ldp_ipv6_iface_node;
extern struct cmd_node ldp_l2vpn_node;
extern struct cmd_node ldp_pseudowire_node;
extern struct cmd_node ldp_debug_node;

union ldpd_addr;
int	 ldp_get_address(const char *, int *, union ldpd_addr *);
int	 ldp_config_write(struct vty *);
int	 ldp_l2vpn_config_write(struct vty *);
int	 ldp_debug_config_write(struct vty *);
int	 ldp_vty_mpls_ldp (struct vty *, const char *);
int	 ldp_vty_address_family (struct vty *, const char *, const char *);
int	 ldp_vty_disc_holdtime(struct vty *, const char *, enum hello_type, long);
int	 ldp_vty_disc_interval(struct vty *, const char *, enum hello_type, long);
int	 ldp_vty_targeted_hello_accept(struct vty *, const char *, const char *);
int	 ldp_vty_nbr_session_holdtime(struct vty *, const char *, struct in_addr, long);
int	 ldp_vty_af_session_holdtime(struct vty *, const char *, long);
int	 ldp_vty_interface(struct vty *, const char *, const char *);
int	 ldp_vty_trans_addr(struct vty *, const char *, const char *);
int	 ldp_vty_neighbor_targeted(struct vty *, const char *, const char *);
int	 ldp_vty_label_advertise(struct vty *, const char *, const char *, const char *);
int	 ldp_vty_label_allocate(struct vty *, const char *, const char *, const char *);
int	 ldp_vty_label_expnull(struct vty *, const char *, const char *);
int	 ldp_vty_label_accept(struct vty *, const char *, const char *, const char *);
int	 ldp_vty_ttl_security(struct vty *, const char *);
int	 ldp_vty_router_id(struct vty *, const char *, struct in_addr);
int	 ldp_vty_ds_cisco_interop(struct vty *, const char *);
int	 ldp_vty_trans_pref_ipv4(struct vty *, const char *);
int	 ldp_vty_neighbor_password(struct vty *, const char *, struct in_addr, const char *);
int	 ldp_vty_neighbor_ttl_security(struct vty *, const char *, struct in_addr, const char *);
int	 ldp_vty_l2vpn(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_bridge(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_mtu(struct vty *, const char *, long);
int	 ldp_vty_l2vpn_pwtype(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_interface(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_pseudowire(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_pw_cword(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_pw_nbr_addr(struct vty *, const char *, const char *);
int	 ldp_vty_l2vpn_pw_nbr_id(struct vty *, const char *, struct in_addr);
int	 ldp_vty_l2vpn_pw_pwid(struct vty *, const char *, long);
int	 ldp_vty_l2vpn_pw_pwstatus(struct vty *, const char *);
int	 ldp_vty_clear_nbr(struct vty *, const char *);
int	 ldp_vty_debug(struct vty *, const char *, const char *, const char *, const char *);
int	 ldp_vty_show_binding(struct vty *, const char *, const char *, int,
	    const char *, unsigned long, unsigned long, const char *, const char *);
int	 ldp_vty_show_discovery(struct vty *, const char *, const char *, const char *);
int	 ldp_vty_show_interface(struct vty *, const char *, const char *);
int	 ldp_vty_show_capabilities(struct vty *, const char *);
int	 ldp_vty_show_neighbor(struct vty *, const char *, int, const char *, const char *);
int	 ldp_vty_show_atom_binding(struct vty *, const char *, unsigned long,
	    unsigned long, const char *);
int	 ldp_vty_show_atom_vc(struct vty *, const char *, const char *,
	    const char *, const char *);
int	 ldp_vty_show_debugging(struct vty *);

void	 ldp_vty_init(void);

#endif	/* _LDP_VTY_H_ */
