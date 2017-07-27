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

#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "ldpd/ldp_vty.h"
#include "json.h"

DEFUN_NOSH(ldp_mpls_ldp,
	ldp_mpls_ldp_cmd,
	"[no] mpls ldp",
	"Negate a command or set its defaults\n"
	"Global MPLS configuration subcommands\n"
	"Label Distribution Protocol\n")
{
	int		 idx = 0;
	int		 negate = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	return (ldp_vty_mpls_ldp(vty, negate));
}

DEFUN_NOSH(ldp_l2vpn,
	ldp_l2vpn_cmd,
	"[no] l2vpn WORD type vpls",
	"Negate a command or set its defaults\n"
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*name;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "WORD", &idx);
	name = argv[idx]->arg;

	return (ldp_vty_l2vpn(vty, negate, name));
}

DEFUN_NOSH(ldp_address_family,
	ldp_address_family_cmd,
	"[no] address-family <ipv4|ipv6>",
	"Negate a command or set its defaults\n"
	"Configure Address Family and its parameters\n"
	"IPv4\n"
	"IPv6\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*af;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "address-family", &idx);
	af = argv[idx + 1]->text;

	return (ldp_vty_address_family(vty, negate, af));
}

DEFUN  (ldp_discovery_holdtime,
	ldp_discovery_holdtime_cmd,
	"[no] discovery <hello|targeted-hello> holdtime (1-65535)",
	"Negate a command or set its defaults\n"
	"Configure discovery parameters\n"
	"LDP Link Hellos\n"
	"LDP Targeted Hellos\n"
	"Hello holdtime\n"
	"Time (seconds) - 65535 implies infinite\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*hello_type;
	const char	*holdtime;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "discovery", &idx);
	hello_type = argv[idx + 1]->text;
	argv_find(argv, argc, "(1-65535)", &idx);
	holdtime = argv[idx]->arg;

	return (ldp_vty_disc_holdtime(vty, negate, hello_type, holdtime));
}

DEFUN  (ldp_discovery_interval,
	ldp_discovery_interval_cmd,
	"[no] discovery <hello|targeted-hello> interval (1-65535)",
	"Negate a command or set its defaults\n"
	"Configure discovery parameters\n"
	"LDP Link Hellos\n"
	"LDP Targeted Hellos\n"
	"Hello interval\n"
	"Time (seconds)\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*hello_type;
	const char	*interval;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "discovery", &idx);
	hello_type = argv[idx + 1]->text;
	argv_find(argv, argc, "(1-65535)", &idx);
	interval = argv[idx]->arg;

	return (ldp_vty_disc_interval(vty, negate, hello_type, interval));
}

DEFUN  (ldp_dual_stack_transport_connection_prefer_ipv4,
	ldp_dual_stack_transport_connection_prefer_ipv4_cmd,
	"[no] dual-stack transport-connection prefer ipv4",
	"Negate a command or set its defaults\n"
	"Configure dual stack parameters\n"
	"Configure TCP transport parameters\n"
	"Configure prefered address family for TCP transport connection with neighbor\n"
	"IPv4\n")
{
	int		 idx = 0;
	int		 negate = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	return (ldp_vty_trans_pref_ipv4(vty, negate));
}

DEFUN  (ldp_dual_stack_cisco_interop,
	ldp_dual_stack_cisco_interop_cmd,
	"[no] dual-stack cisco-interop",
	"Negate a command or set its defaults\n"
	"Configure dual stack parameters\n"
	"Use Cisco non-compliant format to send and interpret the Dual-Stack capability TLV\n")
{
	int		 idx = 0;
	int		 negate = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	return (ldp_vty_ds_cisco_interop(vty, negate));
}

DEFUN  (ldp_neighbor_password,
	ldp_neighbor_password_cmd,
	"[no] neighbor A.B.C.D password WORD",
	"Negate a command or set its defaults\n"
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"Configure password for MD5 authentication\n"
	"The password\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*neighbor;
	const char	*password;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	neighbor = argv[idx]->arg;
	argv_find(argv, argc, "WORD", &idx);
	password = argv[idx]->arg;

	return (ldp_vty_neighbor_password(vty, negate, neighbor, password));
}

DEFUN  (ldp_neighbor_session_holdtime,
	ldp_neighbor_session_holdtime_cmd,
	"[no] neighbor A.B.C.D session holdtime (15-65535)",
	"Negate a command or set its defaults\n"
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"Configure session parameters\n"
	"Configure session holdtime\n"
	"Time (seconds)\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*neighbor;
	const char	*holdtime;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	neighbor = argv[idx]->arg;
	argv_find(argv, argc, "(15-65535)", &idx);
	holdtime = argv[idx]->arg;

	return (ldp_vty_nbr_session_holdtime(vty, negate, neighbor, holdtime));
}

DEFUN  (ldp_neighbor_ttl_security,
	ldp_neighbor_ttl_security_cmd,
	"[no] neighbor A.B.C.D ttl-security <disable|hops (1-254)>",
	"Negate a command or set its defaults\n"
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"LDP ttl security check\n"
	"Disable ttl security\n"
	"IP hops\n"
	"maximum number of hops\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*neighbor;
	const char	*hops = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	neighbor = argv[idx]->arg;
	if (argv_find(argv, argc, "(1-254)", &idx))
		hops = argv[idx]->arg;

	return (ldp_vty_neighbor_ttl_security(vty, negate, neighbor, hops));
}

DEFUN  (ldp_router_id,
	ldp_router_id_cmd,
	"[no] router-id A.B.C.D",
	"Negate a command or set its defaults\n"
	"Configure router Id\n"
	"LSR Id (in form of an IPv4 address)\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_router_id(vty, negate, address));
}

DEFUN  (ldp_discovery_targeted_hello_accept,
	ldp_discovery_targeted_hello_accept_cmd,
	"[no] discovery targeted-hello accept [from <(1-199)|(1300-2699)|WORD>]",
	"Negate a command or set its defaults\n"
	"Configure discovery parameters\n"
	"LDP Targeted Hellos\n"
	"Accept and respond to targeted hellos\n"
	"Access list to specify acceptable targeted hello source\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*from_acl = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	if (argv_find(argv, argc, "from", &idx))
		from_acl = argv[idx + 1]->arg;

	return (ldp_vty_targeted_hello_accept(vty, negate, from_acl));
}

DEFUN  (ldp_discovery_transport_address_ipv4,
	ldp_discovery_transport_address_ipv4_cmd,
	"[no] discovery transport-address A.B.C.D",
	"Negate a command or set its defaults\n"
	"Configure discovery parameters\n"
	"Specify transport address for TCP connection\n"
	"IP address to be used as transport address\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_trans_addr(vty, negate, address));
}

DEFUN  (ldp_discovery_transport_address_ipv6,
	ldp_discovery_transport_address_ipv6_cmd,
	"[no] discovery transport-address X:X::X:X",
	"Negate a command or set its defaults\n"
	"Configure discovery parameters\n"
	"Specify transport address for TCP connection\n"
	"IPv6 address to be used as transport address\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "X:X::X:X", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_trans_addr(vty, negate, address));
}

DEFUN  (ldp_label_local_advertise,
	ldp_label_local_advertise_cmd,
	"[no] label local advertise [{to <(1-199)|(1300-2699)|WORD>|for <(1-199)|(1300-2699)|WORD>}]",
	"Negate a command or set its defaults\n"
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure outbound label advertisement control\n"
	"IP Access-list specifying controls on LDP Peers\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n"
	"IP access-list for destination prefixes\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*to_acl = NULL;
	const char	*for_acl = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	/* arguments within curly braces may be provided in any order */
	if (argv_find(argv, argc, "to", &idx))
		to_acl = argv[idx + 1]->arg;
	idx = 0;
	if (argv_find(argv, argc, "for", &idx))
		for_acl = argv[idx + 1]->arg;

	return (ldp_vty_label_advertise(vty, negate, to_acl, for_acl));
}

DEFUN  (ldp_label_local_advertise_explicit_null,
	ldp_label_local_advertise_explicit_null_cmd,
	"[no] label local advertise explicit-null [for <(1-199)|(1300-2699)|WORD>]",
	"Negate a command or set its defaults\n"
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure outbound label advertisement control\n"
	"Configure explicit-null advertisement\n"
	"IP access-list for destination prefixes\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*for_acl = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	if (argv_find(argv, argc, "for", &idx))
		for_acl = argv[idx + 1]->arg;

	return (ldp_vty_label_expnull(vty, negate, for_acl));
}

DEFUN  (ldp_label_local_allocate,
	ldp_label_local_allocate_cmd,
	"[no] label local allocate <host-routes|for <(1-199)|(1300-2699)|WORD>>",
	"Negate a command or set its defaults\n"
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure label allocation control\n"
	"allocate local label for host routes only\n"
	"IP access-list\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	int		 host_routes = 0;
	const char	*for_acl = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	/* arguments within curly braces may be provided in any order */
	if (argv_find(argv, argc, "host-routes", &idx))
		host_routes = 1;
	idx = 0;
	if (argv_find(argv, argc, "for", &idx))
		for_acl = argv[idx + 1]->arg;

	return (ldp_vty_label_allocate(vty, negate, host_routes, for_acl));
}

DEFUN  (ldp_label_remote_accept,
	ldp_label_remote_accept_cmd,
	"[no] label remote accept {from <(1-199)|(1300-2699)|WORD>|for <(1-199)|(1300-2699)|WORD>}",
	"Negate a command or set its defaults\n"
	"Configure label control and policies\n"
	"Configure remote/peer label control and policies\n"
	"Configure inbound label acceptance control\n"
	"Neighbor from whom to accept label advertisement\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n"
	"IP access-list for destination prefixes\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP access-list name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*from_acl = NULL;
	const char	*for_acl = NULL;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	/* arguments within curly braces may be provided in any order */
	if (argv_find(argv, argc, "from", &idx))
		from_acl = argv[idx + 1]->arg;
	idx = 0;
	if (argv_find(argv, argc, "for", &idx))
		for_acl = argv[idx + 1]->arg;

	return (ldp_vty_label_accept(vty, negate, from_acl, for_acl));
}

DEFUN  (ldp_ttl_security_disable,
	ldp_ttl_security_disable_cmd,
	"[no] ttl-security disable",
	"Negate a command or set its defaults\n"
	"LDP ttl security check\n"
	"Disable ttl security\n")
{
	int		 idx = 0;
	int		 negate = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	return (ldp_vty_ttl_security(vty, negate));
}

DEFUN  (ldp_session_holdtime,
	ldp_session_holdtime_cmd,
	"[no] session holdtime (15-65535)",
	"Negate a command or set its defaults\n"
	"Configure session parameters\n"
	"Configure session holdtime\n"
	"Time (seconds)\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*holdtime;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "(15-65535)", &idx);
	holdtime = argv[idx]->arg;

	return (ldp_vty_af_session_holdtime(vty, negate, holdtime));
}

DEFUN_NOSH(ldp_interface,
	ldp_interface_cmd,
	"[no] interface IFNAME",
	"Negate a command or set its defaults\n"
	"Enable LDP on an interface and enter interface submode\n"
	"Interface's name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*ifname;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	return (ldp_vty_interface(vty, negate, ifname));
}

DEFUN  (ldp_neighbor_ipv4_targeted,
	ldp_neighbor_ipv4_targeted_cmd,
	"[no] neighbor A.B.C.D targeted",
	"Negate a command or set its defaults\n"
	"Configure neighbor parameters\n"
	"IP address of neighbor\n"
	"Establish targeted session\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_neighbor_targeted(vty, negate, address));
}

DEFUN  (ldp_neighbor_ipv6_targeted,
	ldp_neighbor_ipv6_targeted_cmd,
	"[no] neighbor X:X::X:X targeted",
	"Negate a command or set its defaults\n"
	"Configure neighbor parameters\n"
	"IPv6 address of neighbor\n"
	"Establish targeted session\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "X:X::X:X", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_neighbor_targeted(vty, negate, address));
}

DEFUN  (ldp_bridge,
	ldp_bridge_cmd,
	"[no] bridge IFNAME",
	"Negate a command or set its defaults\n"
	"Bridge interface\n"
	"Interface's name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*ifname;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	return (ldp_vty_l2vpn_bridge(vty, negate, ifname));
}

DEFUN  (ldp_mtu,
	ldp_mtu_cmd,
	"[no] mtu (1500-9180)",
	"Negate a command or set its defaults\n"
	"Set Maximum Transmission Unit\n"
	"Maximum Transmission Unit value\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*mtu;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "(1500-9180)", &idx);
	mtu = argv[idx]->arg;

	return (ldp_vty_l2vpn_mtu(vty, negate, mtu));
}

DEFUN  (ldp_member_interface,
	ldp_member_interface_cmd,
	"[no] member interface IFNAME",
	"Negate a command or set its defaults\n"
	"L2VPN member configuration\n"
	"Local interface\n"
	"Interface's name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*ifname;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	return (ldp_vty_l2vpn_interface(vty, negate, ifname));
}

DEFUN_NOSH(ldp_member_pseudowire,
	ldp_member_pseudowire_cmd,
	"[no] member pseudowire IFNAME",
	"Negate a command or set its defaults\n"
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*ifname;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	return (ldp_vty_l2vpn_pseudowire(vty, negate, ifname));
}

DEFUN  (ldp_vc_type,
	ldp_vc_type_cmd,
	"[no] vc type <ethernet|ethernet-tagged>",
	"Negate a command or set its defaults\n"
	"Virtual Circuit options\n"
	"Virtual Circuit type to use\n"
	"Ethernet (type 5)\n"
	"Ethernet-tagged (type 4)\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*vc_type;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "type", &idx);
	vc_type = argv[idx + 1]->text;

	return (ldp_vty_l2vpn_pwtype(vty, negate, vc_type));
}

DEFUN  (ldp_control_word,
	ldp_control_word_cmd,
	"[no] control-word <exclude|include>",
	"Negate a command or set its defaults\n"
	"Control-word options\n"
	"Exclude control-word in pseudowire packets\n"
	"Include control-word in pseudowire packets\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*preference;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "control-word", &idx);
	preference = argv[idx + 1]->text;

	return (ldp_vty_l2vpn_pw_cword(vty, negate, preference));
}

DEFUN  (ldp_neighbor_address,
	ldp_neighbor_address_cmd,
	"[no] neighbor address <A.B.C.D|X:X::X:X>",
	"Negate a command or set its defaults\n"
	"Remote endpoint configuration\n"
	"Specify the IPv4 or IPv6 address of the remote endpoint\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "address", &idx);
	address = argv[idx + 1]->arg;

	return (ldp_vty_l2vpn_pw_nbr_addr(vty, negate, address));
}

DEFUN  (ldp_neighbor_lsr_id,
	ldp_neighbor_lsr_id_cmd,
	"[no] neighbor lsr-id A.B.C.D",
	"Negate a command or set its defaults\n"
	"Remote endpoint configuration\n"
	"Specify the LSR-ID of the remote endpoint\n"
	"IPv4 address\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*address;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "A.B.C.D", &idx);
	address = argv[idx]->arg;

	return (ldp_vty_l2vpn_pw_nbr_id(vty, negate, address));
}

DEFUN  (ldp_pw_id,
	ldp_pw_id_cmd,
	"[no] pw-id (1-4294967295)",
	"Negate a command or set its defaults\n"
	"Set the Virtual Circuit ID\n"
	"Virtual Circuit ID value\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*pwid;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "(1-4294967295)", &idx);
	pwid = argv[idx]->arg;

	return (ldp_vty_l2vpn_pw_pwid(vty, negate, pwid));
}

DEFUN  (ldp_pw_status_disable,
	ldp_pw_status_disable_cmd,
	"[no] pw-status disable",
	"Negate a command or set its defaults\n"
	"Configure PW status\n"
	"Disable PW status\n")
{
	int		 idx = 0;
	int		 negate = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;

	return (ldp_vty_l2vpn_pw_pwstatus(vty, negate));
}

DEFUN  (ldp_clear_mpls_ldp_neighbor,
	ldp_clear_mpls_ldp_neighbor_cmd,
	"clear mpls ldp neighbor [<A.B.C.D|X:X::X:X>]",
	"Reset functions\n"
	"Reset MPLS statistical information\n"
	"Clear LDP state\n"
	"Clear LDP neighbor sessions\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	int		 idx = 0;
	const char	*address = NULL;

	if (argv_find(argv, argc, "neighbor", &idx))
		address = argv[idx + 1]->arg;

	return (ldp_vty_clear_nbr(vty, address));
}

DEFUN  (ldp_debug_mpls_ldp_discovery_hello,
	ldp_debug_mpls_ldp_discovery_hello_cmd,
	"[no] debug mpls ldp discovery hello <recv|sent>",
	"Negate a command or set its defaults\n"
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Discovery messages\n"
	"Discovery hello message\n"
	"Received messages\n"
	"Sent messages\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*dir;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "hello", &idx);
	dir = argv[idx + 1]->text;

	return (ldp_vty_debug(vty, negate, "discovery", dir, 0));
}

DEFUN  (ldp_debug_mpls_ldp_type,
	ldp_debug_mpls_ldp_type_cmd,
	"[no] debug mpls ldp <errors|event|zebra>",
	"Negate a command or set its defaults\n"
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Errors\n"
	"LDP event information\n"
	"LDP zebra information\n")
{
	int		 idx = 0;
	int		 negate = 0;
	const char	*type;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	argv_find(argv, argc, "ldp", &idx);
	type = argv[idx + 1]->text;

	return (ldp_vty_debug(vty, negate, type, NULL, 0));
}

DEFUN  (ldp_debug_mpls_ldp_messages_recv,
	ldp_debug_mpls_ldp_messages_recv_cmd,
	"[no] debug mpls ldp messages recv [all]",
	"Negate a command or set its defaults\n"
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Messages\n"
	"Received messages, excluding periodic Keep Alives\n"
	"Received messages, including periodic Keep Alives\n")
{
	int		 idx = 0;
	int		 negate = 0;
	int		 all = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	if (argv_find(argv, argc, "all", &idx))
		all = 1;

	return (ldp_vty_debug(vty, negate, "messages", "recv", all));
}

DEFUN  (ldp_debug_mpls_ldp_messages_sent,
	ldp_debug_mpls_ldp_messages_sent_cmd,
	"[no] debug mpls ldp messages sent [all]",
	"Negate a command or set its defaults\n"
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Messages\n"
	"Sent messages, excluding periodic Keep Alives\n"
	"Sent messages, including periodic Keep Alives\n")
{
	int		 idx = 0;
	int		 negate = 0;
	int		 all = 0;

	if (argv_find(argv, argc, "no", &idx))
		negate = 1;
	if (argv_find(argv, argc, "all", &idx))
		all = 1;

	return (ldp_vty_debug(vty, negate, "messages", "sent", all));
}

DEFUN  (ldp_show_mpls_ldp_binding,
	ldp_show_mpls_ldp_binding_cmd,
	"show mpls ldp [<ipv4|ipv6>] binding [detail] [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Label Information Base (LIB) information\n"
	"Show detailed information\n"
	JSON_STR)
{
	int		 idx = 0;
	const char	*af = NULL;
	int		 detail = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "ipv4", &idx) ||
	    argv_find(argv, argc, "ipv6", &idx))
		af = argv[idx]->text;
	if (argv_find(argv, argc, "detail", &idx))
		detail = 1;
	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_binding(vty, af, detail, json));
}

DEFUN  (ldp_show_mpls_ldp_discovery,
	ldp_show_mpls_ldp_discovery_cmd,
	"show mpls ldp [<ipv4|ipv6>] discovery [detail] [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Discovery Hello Information\n"
	"Show detailed information\n"
	JSON_STR)
{
	int		 idx = 0;
	const char	*af = NULL;
	int		 detail = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "ipv4", &idx) ||
	    argv_find(argv, argc, "ipv6", &idx))
		af = argv[idx]->text;
	if (argv_find(argv, argc, "detail", &idx))
		detail = 1;
	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_discovery(vty, af, detail, json));
}

DEFUN  (ldp_show_mpls_ldp_interface,
	ldp_show_mpls_ldp_interface_cmd,
	"show mpls ldp [<ipv4|ipv6>] interface [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"interface information\n"
	JSON_STR)
{
	int		 idx = 0;
	const char	*af = NULL;
	int		 json = 0;

	if (argv_find(argv, argc, "ipv4", &idx) ||
	    argv_find(argv, argc, "ipv6", &idx))
		af = argv[idx]->text;
	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_interface(vty, af, json));
}

DEFUN  (ldp_show_mpls_ldp_capabilities,
	ldp_show_mpls_ldp_capabilities_cmd,
	"show mpls ldp capabilities [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Display LDP Capabilities information\n"
	JSON_STR)
{
	int		 idx = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_capabilities(vty, json));
}

DEFUN  (ldp_show_mpls_ldp_neighbor,
	ldp_show_mpls_ldp_neighbor_cmd,
	"show mpls ldp neighbor [detail] [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Neighbor information\n"
	"Show detailed information\n"
	JSON_STR)
{
	int		 idx = 0;
	int		 detail = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "detail", &idx))
		detail = 1;
	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_neighbor(vty, 0, detail, json));
}

DEFUN  (ldp_show_mpls_ldp_neighbor_capabilities,
	ldp_show_mpls_ldp_neighbor_capabilities_cmd,
	"show mpls ldp neighbor capabilities [json]",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Neighbor information\n"
	"Display neighbor capability information\n"
	JSON_STR)
{
	int		 idx = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_neighbor(vty, 1, 0, json));
}

DEFUN  (ldp_show_l2vpn_atom_binding,
	ldp_show_l2vpn_atom_binding_cmd,
	"show l2vpn atom binding [json]",
	"Show running system information\n"
	"Show information about Layer2 VPN\n"
	"Show Any Transport over MPLS information\n"
	"Show AToM label binding information\n"
	JSON_STR)
{
	int		 idx = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_atom_binding(vty, json));
}

DEFUN  (ldp_show_l2vpn_atom_vc,
	ldp_show_l2vpn_atom_vc_cmd,
	"show l2vpn atom vc [json]",
	"Show running system information\n"
	"Show information about Layer2 VPN\n"
	"Show Any Transport over MPLS information\n"
	"Show AToM virtual circuit information\n"
	JSON_STR)
{
	int		 idx = 0;
	int		 json = 0;

	if (argv_find(argv, argc, "json", &idx))
		json = 1;

	return (ldp_vty_show_atom_vc(vty, json));
}

DEFUN  (ldp_show_debugging_mpls_ldp,
	ldp_show_debugging_mpls_ldp_cmd,
	"show debugging mpls ldp",
	"Show running system information\n"
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n")
{
	return (ldp_vty_show_debugging(vty));
}

void
ldp_vty_init (void)
{
	install_node(&ldp_node, ldp_config_write);
	install_node(&ldp_ipv4_node, NULL);
	install_node(&ldp_ipv6_node, NULL);
	install_node(&ldp_ipv4_iface_node, NULL);
	install_node(&ldp_ipv6_iface_node, NULL);
	install_node(&ldp_l2vpn_node, ldp_l2vpn_config_write);
	install_node(&ldp_pseudowire_node, NULL);
	install_node(&ldp_debug_node, ldp_debug_config_write);
	install_default(LDP_NODE);
	install_default(LDP_IPV4_NODE);
	install_default(LDP_IPV6_NODE);
	install_default(LDP_IPV4_IFACE_NODE);
	install_default(LDP_IPV6_IFACE_NODE);
	install_default(LDP_L2VPN_NODE);
	install_default(LDP_PSEUDOWIRE_NODE);

	install_element(CONFIG_NODE, &ldp_mpls_ldp_cmd);
	install_element(CONFIG_NODE, &ldp_l2vpn_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_discovery_hello_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_type_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_messages_recv_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_messages_sent_cmd);

	install_element(LDP_NODE, &ldp_address_family_cmd);
	install_element(LDP_NODE, &ldp_discovery_holdtime_cmd);
	install_element(LDP_NODE, &ldp_discovery_interval_cmd);
	install_element(LDP_NODE, &ldp_dual_stack_transport_connection_prefer_ipv4_cmd);
	install_element(LDP_NODE, &ldp_dual_stack_cisco_interop_cmd);
	install_element(LDP_NODE, &ldp_neighbor_password_cmd);
	install_element(LDP_NODE, &ldp_neighbor_session_holdtime_cmd);
	install_element(LDP_NODE, &ldp_neighbor_ttl_security_cmd);
	install_element(LDP_NODE, &ldp_router_id_cmd);

	install_element(LDP_IPV4_NODE, &ldp_discovery_holdtime_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_interval_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_targeted_hello_accept_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_transport_address_ipv4_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_advertise_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_advertise_explicit_null_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_allocate_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_remote_accept_cmd);
	install_element(LDP_IPV4_NODE, &ldp_ttl_security_disable_cmd);
	install_element(LDP_IPV4_NODE, &ldp_interface_cmd);
	install_element(LDP_IPV4_NODE, &ldp_session_holdtime_cmd);
	install_element(LDP_IPV4_NODE, &ldp_neighbor_ipv4_targeted_cmd);

	install_element(LDP_IPV6_NODE, &ldp_discovery_holdtime_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_interval_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_targeted_hello_accept_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_transport_address_ipv6_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_advertise_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_advertise_explicit_null_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_allocate_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_remote_accept_cmd);
	install_element(LDP_IPV6_NODE, &ldp_ttl_security_disable_cmd);
	install_element(LDP_IPV6_NODE, &ldp_interface_cmd);
	install_element(LDP_IPV6_NODE, &ldp_session_holdtime_cmd);
	install_element(LDP_IPV6_NODE, &ldp_neighbor_ipv6_targeted_cmd);

	install_element(LDP_IPV4_IFACE_NODE, &ldp_discovery_holdtime_cmd);
	install_element(LDP_IPV4_IFACE_NODE, &ldp_discovery_interval_cmd);

	install_element(LDP_IPV6_IFACE_NODE, &ldp_discovery_holdtime_cmd);
	install_element(LDP_IPV6_IFACE_NODE, &ldp_discovery_interval_cmd);

	install_element(LDP_L2VPN_NODE, &ldp_bridge_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_mtu_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_member_interface_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_member_pseudowire_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_vc_type_cmd);

	install_element(LDP_PSEUDOWIRE_NODE, &ldp_control_word_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_neighbor_address_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_neighbor_lsr_id_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_pw_id_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_pw_status_disable_cmd);

	install_element(ENABLE_NODE, &ldp_clear_mpls_ldp_neighbor_cmd);
	install_element(ENABLE_NODE, &ldp_debug_mpls_ldp_discovery_hello_cmd);
	install_element(ENABLE_NODE, &ldp_debug_mpls_ldp_type_cmd);
	install_element(ENABLE_NODE, &ldp_debug_mpls_ldp_messages_recv_cmd);
	install_element(ENABLE_NODE, &ldp_debug_mpls_ldp_messages_sent_cmd);

	install_element(VIEW_NODE, &ldp_show_mpls_ldp_binding_cmd);
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_discovery_cmd);
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_interface_cmd);
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_capabilities_cmd);
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_neighbor_cmd);
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_neighbor_capabilities_cmd);
	install_element(VIEW_NODE, &ldp_show_l2vpn_atom_binding_cmd);
	install_element(VIEW_NODE, &ldp_show_l2vpn_atom_vc_cmd);
	install_element(VIEW_NODE, &ldp_show_debugging_mpls_ldp_cmd);
}
