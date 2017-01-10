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
int	 ldp_vty_mpls_ldp (struct vty *, struct vty_arg *[]);
int	 ldp_vty_address_family (struct vty *, struct vty_arg *[]);
int	 ldp_vty_disc_holdtime(struct vty *, struct vty_arg *[]);
int	 ldp_vty_disc_interval(struct vty *, struct vty_arg *[]);
int	 ldp_vty_targeted_hello_accept(struct vty *, struct vty_arg *[]);
int	 ldp_vty_session_holdtime(struct vty *, struct vty_arg *[]);
int	 ldp_vty_interface(struct vty *, struct vty_arg *[]);
int	 ldp_vty_trans_addr(struct vty *, struct vty_arg *[]);
int	 ldp_vty_neighbor_targeted(struct vty *, struct vty_arg *[]);
int	 ldp_vty_explicit_null(struct vty *, struct vty_arg *[]);
int	 ldp_vty_ttl_security(struct vty *, struct vty_arg *[]);
int	 ldp_vty_router_id(struct vty *, struct vty_arg *[]);
int	 ldp_vty_ds_cisco_interop(struct vty *, struct vty_arg *[]);
int	 ldp_vty_trans_pref_ipv4(struct vty *, struct vty_arg *[]);
int	 ldp_vty_neighbor_password(struct vty *, struct vty_arg *[]);
int	 ldp_vty_neighbor_ttl_security(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_bridge(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_mtu(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pwtype(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_interface(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pseudowire(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pw_cword(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pw_nbr_addr(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pw_nbr_id(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pw_pwid(struct vty *, struct vty_arg *[]);
int	 ldp_vty_l2vpn_pw_pwstatus(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_binding(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_discovery(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_interface(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_neighbor(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_atom_binding(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_atom_vc(struct vty *, struct vty_arg *[]);
int	 ldp_vty_clear_nbr(struct vty *, struct vty_arg *[]);
int	 ldp_vty_debug(struct vty *, struct vty_arg *[]);
int	 ldp_vty_show_debugging(struct vty *, struct vty_arg *[]);

void	 ldp_vty_init(void);
void	 ldp_vty_if_init(void);

#endif	/* _LDP_VTY_H_ */
