// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 by Open Source Routing.
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
int ldp_get_address(const char *str, int *af, union ldpd_addr *addr);
int ldp_vty_mpls_ldp(struct vty *vty, const char *negate);
int ldp_vty_allow_broken_lsp(struct vty *vty, const char *negate);
int ldp_vty_address_family(struct vty *vty, const char *negate, const char *af_str);
int ldp_vty_disc_holdtime(struct vty *vty, const char *negate, enum hello_type hello_type,
			  long secs);
int ldp_vty_disc_interval(struct vty *vty, const char *negate, enum hello_type hello_type,
			  long secs);
int ldp_vty_disable_establish_hello(struct vty *vty, const char *negate);
int ldp_vty_targeted_hello_accept(struct vty *vty, const char *negate, const char *acl_from_str);
int ldp_vty_nbr_session_holdtime(struct vty *vty, const char *negate, struct in_addr lsr_id,
				 long secs);
int ldp_vty_af_session_holdtime(struct vty *vty, const char *negate, long secs);
int ldp_vty_interface(struct vty *vty, const char *negate, const char *ifname);
int ldp_vty_trans_addr(struct vty *vty, const char *negate, const char *addr_str);
int ldp_vty_neighbor_targeted(struct vty *vty, const char *negate, const char *addr_str);
int ldp_vty_label_advertise(struct vty *vty, const char *negate, const char *acl_to_str,
			    const char *acl_for_str);
int ldp_vty_label_allocate(struct vty *vty, const char *negate, const char *host_routes,
			   const char *acl_for_str);
int ldp_vty_label_expnull(struct vty *vty, const char *negate, const char *acl_for_str);
int ldp_vty_label_accept(struct vty *vty, const char *negate, const char *acl_from_str,
			 const char *acl_for_str);
int ldp_vty_ttl_security(struct vty *vty, const char *negate);
int ldp_vty_router_id(struct vty *vty, const char *negate, struct in_addr address);
int ldp_vty_ordered_control(struct vty *vty, const char *negate);
int ldp_vty_wait_for_sync_interval(struct vty *vty, const char *negate, long wait_for_sync);
int ldp_vty_ds_cisco_interop(struct vty *vty, const char *negate);
int ldp_vty_trans_pref_ipv4(struct vty *vty, const char *negate);
int ldp_vty_neighbor_password(struct vty *vty, const char *negate, struct in_addr lsr_id,
			      const char *password);
int ldp_vty_neighbor_ttl_security(struct vty *vty, const char *negate, struct in_addr lsr_id,
				  const char *hops_str);
int ldp_vty_l2vpn(struct vty *vty, const char *negate, const char *name_str);
int ldp_vty_l2vpn_bridge(struct vty *vty, const char *negate, const char *ifname);
int ldp_vty_l2vpn_mtu(struct vty *vty, const char *negate, long mtu);
int ldp_vty_l2vpn_pwtype(struct vty *vty, const char *negate, const char *type_str);
int ldp_vty_l2vpn_interface(struct vty *vty, const char *negate, const char *ifname);
int ldp_vty_l2vpn_pseudowire(struct vty *vty, const char *negate, const char *ifname);
int ldp_vty_l2vpn_pw_cword(struct vty *vty, const char *negate, const char *preference_str);
int ldp_vty_l2vpn_pw_nbr_addr(struct vty *vty, const char *negate, const char *addr_str);
int ldp_vty_l2vpn_pw_nbr_id(struct vty *vty, const char *negate, struct in_addr lsr_id);
int ldp_vty_l2vpn_pw_pwid(struct vty *vty, const char *negate, long pwid);
int ldp_vty_l2vpn_pw_pwstatus(struct vty *vty, const char *negate);
int ldp_vty_clear_nbr(struct vty *vty, const char *addr_str);
int ldp_vty_debug(struct vty *vty, const char *negate, const char *dir_str, const char *proto_str,
		  const char *type_str);
int ldp_vty_show_binding(struct vty *vty, const char *vrf_name, const char *af_str, int detail,
			 const char *addr_str, unsigned long local_label,
			 unsigned long remote_label, const char *neighbor_str, const char *json);
int ldp_vty_show_discovery(struct vty *vty, const char *vrf_name, const char *af_str,
			   const char *json);
int ldp_vty_show_interface(struct vty *vty, const char *af_str, const char *json);
int ldp_vty_show_capabilities(struct vty *vty, const char *use_json);
int ldp_vty_show_neighbor(struct vty *vty, const char *vrf_name, int detail, const char *addr_str,
			  const char *json);
int ldp_vty_show_ldp_sync(struct vty *vty, const char *json);
int ldp_vty_show_atom_binding(struct vty *vty, const char *peer_str, unsigned long local_label,
			      unsigned long remote_label, const char *json);
int ldp_vty_show_atom_vc(struct vty *vty, const char *peer_str, const char *ifname,
			 const char *vcid_str, const char *json);
int ldp_vty_show_debugging(struct vty *vty);

void	 ldp_vty_init(void);

#endif	/* _LDP_VTY_H_ */
