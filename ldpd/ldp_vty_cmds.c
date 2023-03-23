// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 by Open Source Routing.
 */

#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "json.h"

#include "ldpd/ldpd.h"
#include "ldpd/ldp_vty.h"
#include "ldpd/ldp_vty_cmds_clippy.c"

DEFPY_NOSH(ldp_mpls_ldp,
	ldp_mpls_ldp_cmd,
	"mpls ldp",
	"Global MPLS configuration subcommands\n"
	"Label Distribution Protocol\n")
{
	return (ldp_vty_mpls_ldp(vty, NULL));
}

DEFPY  (no_ldp_mpls_ldp,
	no_ldp_mpls_ldp_cmd,
	"no mpls ldp",
	NO_STR
	"Global MPLS configuration subcommands\n"
	"Label Distribution Protocol\n")
{
	return (ldp_vty_mpls_ldp(vty, "no"));
}

DEFPY_NOSH(ldp_l2vpn,
	ldp_l2vpn_cmd,
	"l2vpn WORD$l2vpn_name type vpls",
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	return (ldp_vty_l2vpn(vty, NULL, l2vpn_name));
}

DEFPY  (no_ldp_l2vpn,
	no_ldp_l2vpn_cmd,
	"no l2vpn WORD$l2vpn_name type vpls",
	NO_STR
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	return (ldp_vty_l2vpn(vty, "no", l2vpn_name));
}

DEFPY_NOSH(ldp_address_family,
	ldp_address_family_cmd,
	"address-family <ipv4|ipv6>$af",
	"Configure Address Family and its parameters\n"
	"IPv4\n"
	"IPv6\n")
{
	return (ldp_vty_address_family(vty, NULL, af));
}

DEFPY  (no_ldp_address_family,
	no_ldp_address_family_cmd,
	"no address-family <ipv4|ipv6>$af",
	NO_STR
	"Configure Address Family and its parameters\n"
	"IPv4\n"
	"IPv6\n")
{
	return (ldp_vty_address_family(vty, "no", af));
}

DEFPY_NOSH(ldp_exit_address_family,
       ldp_exit_address_family_cmd,
       "exit-address-family",
       "Exit from Address Family configuration mode\n")
{
	if (vty->node == LDP_IPV4_NODE || vty->node == LDP_IPV6_NODE)
		vty->node = LDP_NODE;
	return CMD_SUCCESS;
}

DEFPY  (ldp_discovery_link_holdtime,
	ldp_discovery_link_holdtime_cmd,
	"[no] discovery hello holdtime (1-65535)$holdtime",
	NO_STR
	"Configure discovery parameters\n"
	"LDP Link Hellos\n"
	"Hello holdtime\n"
	"Time (seconds) - 65535 implies infinite\n")
{
	return (ldp_vty_disc_holdtime(vty, no, HELLO_LINK, holdtime));
}

DEFPY  (ldp_discovery_targeted_holdtime,
	ldp_discovery_targeted_holdtime_cmd,
	"[no] discovery targeted-hello holdtime (1-65535)$holdtime",
	NO_STR
	"Configure discovery parameters\n"
	"LDP Targeted Hellos\n"
	"Hello holdtime\n"
	"Time (seconds) - 65535 implies infinite\n")
{
	return (ldp_vty_disc_holdtime(vty, no, HELLO_TARGETED, holdtime));
}

DEFPY  (ldp_discovery_link_interval,
	ldp_discovery_link_interval_cmd,
	"[no] discovery hello interval (1-65535)$interval",
	NO_STR
	"Configure discovery parameters\n"
	"LDP Link Hellos\n"
	"Hello interval\n"
	"Time (seconds)\n")
{
	return (ldp_vty_disc_interval(vty, no, HELLO_LINK, interval));
}

DEFPY  (ldp_discovery_targeted_interval,
	ldp_discovery_targeted_interval_cmd,
	"[no] discovery targeted-hello interval (1-65535)$interval",
	NO_STR
	"Configure discovery parameters\n"
	"LDP Targeted Hellos\n"
	"Hello interval\n"
	"Time (seconds)\n")
{
	return (ldp_vty_disc_interval(vty, no, HELLO_TARGETED, interval));
}

DEFPY  (ldp_dual_stack_transport_connection_prefer_ipv4,
	ldp_dual_stack_transport_connection_prefer_ipv4_cmd,
	"[no] dual-stack transport-connection prefer ipv4",
	NO_STR
	"Configure dual stack parameters\n"
	"Configure TCP transport parameters\n"
	"Configure preferred address family for TCP transport connection with neighbor\n"
	"IPv4\n")
{
	return (ldp_vty_trans_pref_ipv4(vty, no));
}

DEFPY  (ldp_dual_stack_cisco_interop,
	ldp_dual_stack_cisco_interop_cmd,
	"[no] dual-stack cisco-interop",
	NO_STR
	"Configure dual stack parameters\n"
	"Use Cisco non-compliant format to send and interpret the Dual-Stack capability TLV\n")
{
	return (ldp_vty_ds_cisco_interop(vty, no));
}

DEFPY  (ldp_neighbor_password,
	ldp_neighbor_password_cmd,
	"[no] neighbor A.B.C.D$neighbor password WORD$password",
	NO_STR
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"Configure password for MD5 authentication\n"
	"The password\n")
{
	return (ldp_vty_neighbor_password(vty, no, neighbor, password));
}

DEFPY  (ldp_neighbor_session_holdtime,
	ldp_neighbor_session_holdtime_cmd,
	"[no] neighbor A.B.C.D$neighbor session holdtime (15-65535)$holdtime",
	NO_STR
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"Configure session parameters\n"
	"Configure session holdtime\n"
	"Time (seconds)\n")
{
	return (ldp_vty_nbr_session_holdtime(vty, no, neighbor, holdtime));
}

DEFPY  (ldp_neighbor_ttl_security,
	ldp_neighbor_ttl_security_cmd,
	"[no] neighbor A.B.C.D$neighbor ttl-security <disable|hops (1-254)$hops>",
	NO_STR
	"Configure neighbor parameters\n"
	"LDP Id of neighbor\n"
	"LDP ttl security check\n"
	"Disable ttl security\n"
	"IP hops\n"
	"maximum number of hops\n")
{
	return (ldp_vty_neighbor_ttl_security(vty, no, neighbor, hops_str));
}

DEFPY  (ldp_router_id,
	ldp_router_id_cmd,
	"[no] router-id A.B.C.D$address",
	NO_STR
	"Configure router Id\n"
	"LSR Id (in form of an IPv4 address)\n")
{
	return (ldp_vty_router_id(vty, no, address));
}

DEFPY  (ldp_ordered_control,
        ldp_ordered_control_cmd,
        "[no] ordered-control",
        NO_STR
        "Configure LDP ordered label distribution control mode\n")
{
	return (ldp_vty_ordered_control(vty, no));
}

DEFPY  (ldp_wait_for_sync,
        ldp_wait_for_sync_cmd,
        "[no] wait-for-sync (1-10000)$waitforsync",
        NO_STR
        "Time to wait for LDP-IGP Sync to complete label exchange\n"
        "Time (seconds)\n")
{
        return (ldp_vty_wait_for_sync_interval(vty, no, waitforsync));

}

DEFPY  (ldp_allow_broken_lsps,
	ldp_allow_broken_lsps_cmd,
	"[no] install allow-broken-lsps",
	NO_STR
	"install lsps\n"
	"if no remote-label install with imp-null\n")
{
	return (ldp_vty_allow_broken_lsp(vty, no));
}

DEFPY  (ldp_discovery_targeted_hello_accept,
	ldp_discovery_targeted_hello_accept_cmd,
	"[no] discovery targeted-hello accept [from ACCESSLIST_NAME$from_acl]",
	NO_STR
	"Configure discovery parameters\n"
	"LDP Targeted Hellos\n"
	"Accept and respond to targeted hellos\n"
	"Access list to specify acceptable targeted hello source\n"
	"IP access-list name\n")
{
	return (ldp_vty_targeted_hello_accept(vty, no, from_acl));
}

DEFPY  (ldp_discovery_transport_address_ipv4,
	ldp_discovery_transport_address_ipv4_cmd,
	"[no] discovery transport-address A.B.C.D$address",
	NO_STR
	"Configure discovery parameters\n"
	"Specify transport address for TCP connection\n"
	"IP address to be used as transport address\n")
{
	return (ldp_vty_trans_addr(vty, no, address_str));
}

DEFPY  (ldp_discovery_transport_address_ipv6,
	ldp_discovery_transport_address_ipv6_cmd,
	"[no] discovery transport-address X:X::X:X$address",
	NO_STR
	"Configure discovery parameters\n"
	"Specify transport address for TCP connection\n"
	"IPv6 address to be used as transport address\n")
{
	return (ldp_vty_trans_addr(vty, no, address_str));
}

DEFPY  (ldp_label_local_advertise,
	ldp_label_local_advertise_cmd,
	"[no] label local advertise [{to ACCESSLIST_NAME$to_acl|for ACCESSLIST_NAME$for_acl}]",
	NO_STR
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure outbound label advertisement control\n"
	"IP Access-list specifying controls on LDP Peers\n"
	"IP access-list name\n"
	"IP access-list for destination prefixes\n"
	"IP access-list name\n")
{
	return (ldp_vty_label_advertise(vty, no, to_acl, for_acl));
}

DEFPY  (ldp_label_local_advertise_explicit_null,
	ldp_label_local_advertise_explicit_null_cmd,
	"[no] label local advertise explicit-null [for ACCESSLIST_NAME$for_acl]",
	NO_STR
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure outbound label advertisement control\n"
	"Configure explicit-null advertisement\n"
	"IP access-list for destination prefixes\n"
	"IP access-list name\n")
{
	return (ldp_vty_label_expnull(vty, no, for_acl));
}

DEFPY  (ldp_label_local_allocate,
	ldp_label_local_allocate_cmd,
	"[no] label local allocate <host-routes$host_routes|for ACCESSLIST_NAME$for_acl>",
	NO_STR
	"Configure label control and policies\n"
	"Configure local label control and policies\n"
	"Configure label allocation control\n"
	"allocate local label for host routes only\n"
	"IP access-list\n"
	"IP access-list name\n")
{
	return (ldp_vty_label_allocate(vty, no, host_routes, for_acl));
}

DEFPY  (ldp_label_remote_accept,
	ldp_label_remote_accept_cmd,
	"[no] label remote accept {from ACCESSLIST_NAME$from_acl|for ACCESSLIST_NAME$for_acl}",
	NO_STR
	"Configure label control and policies\n"
	"Configure remote/peer label control and policies\n"
	"Configure inbound label acceptance control\n"
	"Neighbor from whom to accept label advertisement\n"
	"IP access-list name\n"
	"IP access-list for destination prefixes\n"
	"IP access-list name\n")
{
	return (ldp_vty_label_accept(vty, no, from_acl, for_acl));
}

DEFPY  (ldp_ttl_security_disable,
	ldp_ttl_security_disable_cmd,
	"[no] ttl-security disable",
	NO_STR
	"LDP ttl security check\n"
	"Disable ttl security\n")
{
	return (ldp_vty_ttl_security(vty, no));
}

DEFPY  (ldp_session_holdtime,
	ldp_session_holdtime_cmd,
	"[no] session holdtime (15-65535)$holdtime",
	NO_STR
	"Configure session parameters\n"
	"Configure session holdtime\n"
	"Time (seconds)\n")
{
	return (ldp_vty_af_session_holdtime(vty, no, holdtime));
}

DEFPY_NOSH(ldp_interface,
	ldp_interface_cmd,
	"interface IFNAME$ifname",
	"Enable LDP on an interface and enter interface submode\n"
	"Interface's name\n")
{
	return (ldp_vty_interface(vty, NULL, ifname));
}

DEFPY  (no_ldp_interface,
	no_ldp_interface_cmd,
	"no interface IFNAME$ifname",
	NO_STR
	"Enable LDP on an interface and enter interface submode\n"
	"Interface's name\n")
{
	return (ldp_vty_interface(vty, "no", ifname));
}

DEFPY  (ldp_neighbor_ipv4_targeted,
	ldp_neighbor_ipv4_targeted_cmd,
	"[no] neighbor A.B.C.D$address targeted",
	NO_STR
	"Configure neighbor parameters\n"
	"IP address of neighbor\n"
	"Establish targeted session\n")
{
	return (ldp_vty_neighbor_targeted(vty, no, address_str));
}

DEFPY  (ldp_neighbor_ipv6_targeted,
	ldp_neighbor_ipv6_targeted_cmd,
	"[no] neighbor X:X::X:X$address targeted",
	NO_STR
	"Configure neighbor parameters\n"
	"IPv6 address of neighbor\n"
	"Establish targeted session\n")
{
	return (ldp_vty_neighbor_targeted(vty, no, address_str));
}

DEFPY  (ldp_bridge,
	ldp_bridge_cmd,
	"[no] bridge IFNAME$ifname",
	NO_STR
	"Bridge interface\n"
	"Interface's name\n")
{
	return (ldp_vty_l2vpn_bridge(vty, no, ifname));
}

DEFPY  (ldp_mtu,
	ldp_mtu_cmd,
	"[no] mtu (1500-9180)$mtu",
	NO_STR
	"Set Maximum Transmission Unit\n"
	"Maximum Transmission Unit value\n")
{
	return (ldp_vty_l2vpn_mtu(vty, no, mtu));
}

DEFPY  (ldp_member_interface,
	ldp_member_interface_cmd,
	"[no] member interface IFNAME$ifname",
	NO_STR
	"L2VPN member configuration\n"
	"Local interface\n"
	"Interface's name\n")
{
	return (ldp_vty_l2vpn_interface(vty, no, ifname));
}

DEFPY_NOSH(ldp_member_pseudowire,
	ldp_member_pseudowire_cmd,
	"member pseudowire IFNAME$ifname",
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	return (ldp_vty_l2vpn_pseudowire(vty, NULL, ifname));
}

DEFPY  (no_ldp_member_pseudowire,
	no_ldp_member_pseudowire_cmd,
	"no member pseudowire IFNAME$ifname",
	NO_STR
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	return (ldp_vty_l2vpn_pseudowire(vty, "no", ifname));
}

DEFPY  (ldp_vc_type,
	ldp_vc_type_cmd,
	"[no] vc type <ethernet|ethernet-tagged>$vc_type",
	NO_STR
	"Virtual Circuit options\n"
	"Virtual Circuit type to use\n"
	"Ethernet (type 5)\n"
	"Ethernet-tagged (type 4)\n")
{
	return (ldp_vty_l2vpn_pwtype(vty, no, vc_type));
}

DEFPY  (ldp_control_word,
	ldp_control_word_cmd,
	"[no] control-word <exclude|include>$preference",
	NO_STR
	"Control-word options\n"
	"Exclude control-word in pseudowire packets\n"
	"Include control-word in pseudowire packets\n")
{
	return (ldp_vty_l2vpn_pw_cword(vty, no, preference));
}

DEFPY  (ldp_neighbor_address,
	ldp_neighbor_address_cmd,
	"[no] neighbor address <A.B.C.D|X:X::X:X>$pw_address",
	NO_STR
	"Remote endpoint configuration\n"
	"Specify the IPv4 or IPv6 address of the remote endpoint\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	return (ldp_vty_l2vpn_pw_nbr_addr(vty, no, pw_address_str));
}

DEFPY  (ldp_neighbor_lsr_id,
	ldp_neighbor_lsr_id_cmd,
	"[no] neighbor lsr-id A.B.C.D$address",
	NO_STR
	"Remote endpoint configuration\n"
	"Specify the LSR-ID of the remote endpoint\n"
	"IPv4 address\n")
{
	return (ldp_vty_l2vpn_pw_nbr_id(vty, no, address));
}

DEFPY  (ldp_pw_id,
	ldp_pw_id_cmd,
	"[no] pw-id (1-4294967295)$pwid",
	NO_STR
	"Set the Virtual Circuit ID\n"
	"Virtual Circuit ID value\n")
{
	return (ldp_vty_l2vpn_pw_pwid(vty, no, pwid));
}

DEFPY  (ldp_pw_status_disable,
	ldp_pw_status_disable_cmd,
	"[no] pw-status disable",
	NO_STR
	"Configure PW status\n"
	"Disable PW status\n")
{
	return (ldp_vty_l2vpn_pw_pwstatus(vty, no));
}

DEFPY  (ldp_clear_mpls_ldp_neighbor,
	ldp_clear_mpls_ldp_neighbor_cmd,
	"clear mpls ldp neighbor [<A.B.C.D|X:X::X:X>]$address",
	"Reset functions\n"
	"Reset MPLS statistical information\n"
	"Clear LDP state\n"
	"Clear LDP neighbor sessions\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	return (ldp_vty_clear_nbr(vty, address_str));
}

DEFPY  (ldp_debug_mpls_ldp_discovery_hello,
	ldp_debug_mpls_ldp_discovery_hello_cmd,
	"[no] debug mpls ldp discovery hello <recv|sent>$dir",
	NO_STR
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Discovery messages\n"
	"Discovery hello message\n"
	"Received messages\n"
	"Sent messages\n")
{
	return (ldp_vty_debug(vty, no, "discovery", dir, NULL));
}

DEFPY  (ldp_debug_mpls_ldp_type,
	ldp_debug_mpls_ldp_type_cmd,
	"[no] debug mpls ldp <errors|event|labels|sync|zebra>$type",
	NO_STR
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Errors\n"
	"LDP event information\n"
	"LDP label allocation information\n"
	"LDP sync information\n"
	"LDP zebra information\n")
{
	return (ldp_vty_debug(vty, no, type, NULL, NULL));
}

DEFPY  (ldp_debug_mpls_ldp_messages_recv,
	ldp_debug_mpls_ldp_messages_recv_cmd,
	"[no] debug mpls ldp messages recv [all]$all",
	NO_STR
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Messages\n"
	"Received messages, excluding periodic Keep Alives\n"
	"Received messages, including periodic Keep Alives\n")
{
	return (ldp_vty_debug(vty, no, "messages", "recv", all));
}

DEFPY  (ldp_debug_mpls_ldp_messages_sent,
	ldp_debug_mpls_ldp_messages_sent_cmd,
	"[no] debug mpls ldp messages sent [all]$all",
	NO_STR
	"Debugging functions\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Messages\n"
	"Sent messages, excluding periodic Keep Alives\n"
	"Sent messages, including periodic Keep Alives\n")
{
	return (ldp_vty_debug(vty, no, "messages", "sent", all));
}

DEFPY  (ldp_show_mpls_ldp_binding,
	ldp_show_mpls_ldp_binding_cmd,
	"show mpls ldp [<ipv4|ipv6>]$af binding\
	  [<A.B.C.D/M|X:X::X:X/M>$prefix [longer-prefixes$longer_prefixes]]\
	  [{\
	    neighbor A.B.C.D$nbr\
	    |local-label (0-1048575)$local_label\
	    |remote-label (0-1048575)$remote_label\
	  }]\
	 [detail]$detail [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Label Information Base (LIB) information\n"
	"Destination prefix (IPv4)\n"
	"Destination prefix (IPv6)\n"
	"Include longer matches\n"
	"Display labels from LDP neighbor\n"
	"Neighbor LSR-ID\n"
	"Match locally assigned label values\n"
	"Locally assigned label value\n"
	"Match remotely assigned label values\n"
	"Remotely assigned label value\n"
	"Show detailed information\n"
	JSON_STR)
{
	if (!(ldpd_conf->flags & F_LDPD_ENABLED))
		return CMD_SUCCESS;
	if (!local_label_str)
		local_label = NO_LABEL;
	if (!remote_label_str)
		remote_label = NO_LABEL;
	return (ldp_vty_show_binding(vty, af, prefix_str, !!longer_prefixes,
	    nbr_str, local_label, remote_label, detail, json));
}

DEFPY  (ldp_show_mpls_ldp_discovery,
	ldp_show_mpls_ldp_discovery_cmd,
	"show mpls ldp [<ipv4|ipv6>]$af discovery [detail]$detail [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"Discovery Hello Information\n"
	"Show detailed information\n"
	JSON_STR)
{
	return (ldp_vty_show_discovery(vty, af, detail, json));
}

DEFPY  (ldp_show_mpls_ldp_interface,
	ldp_show_mpls_ldp_interface_cmd,
	"show mpls ldp [<ipv4|ipv6>]$af interface [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"IPv4 Address Family\n"
	"IPv6 Address Family\n"
	"interface information\n"
	JSON_STR)
{
	return (ldp_vty_show_interface(vty, af, json));
}

DEFPY  (ldp_show_mpls_ldp_capabilities,
	ldp_show_mpls_ldp_capabilities_cmd,
	"show mpls ldp capabilities [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Display LDP Capabilities information\n"
	JSON_STR)
{
	return (ldp_vty_show_capabilities(vty, json));
}

DEFPY  (ldp_show_mpls_ldp_neighbor,
	ldp_show_mpls_ldp_neighbor_cmd,
	"show mpls ldp neighbor [A.B.C.D]$lsr_id [detail]$detail [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Neighbor information\n"
	"Neighbor LSR-ID\n"
	"Show detailed information\n"
	JSON_STR)
{
	return (ldp_vty_show_neighbor(vty, lsr_id_str, 0, detail, json));
}

DEFPY  (ldp_show_mpls_ldp_neighbor_capabilities,
	ldp_show_mpls_ldp_neighbor_capabilities_cmd,
	"show mpls ldp neighbor [A.B.C.D]$lsr_id capabilities [json]$json",
	"Show running system information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"Neighbor information\n"
	"Neighbor LSR-ID\n"
	"Display neighbor capability information\n"
	JSON_STR)
{
	return (ldp_vty_show_neighbor(vty, lsr_id_str, 1, NULL, json));
}

DEFPY  (ldp_show_mpls_ldp_igp_sync,
	ldp_show_mpls_ldp_igp_sync_cmd,
	"show mpls ldp igp-sync [json]$json",
	"Show mpls ldp ldp-sync information\n"
	"MPLS information\n"
	"Label Distribution Protocol\n"
	"LDP-IGP Sync information\n"
	JSON_STR)
{
	return (ldp_vty_show_ldp_sync(vty, json));
}

DEFPY  (ldp_show_l2vpn_atom_binding,
	ldp_show_l2vpn_atom_binding_cmd,
	"show l2vpn atom binding\
	  [{\
	    A.B.C.D$peer\
	    |local-label (16-1048575)$local_label\
	    |remote-label (16-1048575)$remote_label\
	  }]\
	 [json]$json",
	"Show running system information\n"
	"Show information about Layer2 VPN\n"
	"Show Any Transport over MPLS information\n"
	"Show AToM label binding information\n"
	"Destination address of the VC\n"
	"Match locally assigned label values\n"
	"Locally assigned label value\n"
	"Match remotely assigned label values\n"
	"Remotely assigned label value\n"
	JSON_STR)
{
	if (!local_label_str)
		local_label = NO_LABEL;
	if (!remote_label_str)
		remote_label = NO_LABEL;
	return (ldp_vty_show_atom_binding(vty, peer_str, local_label,
	    remote_label, json));
}

DEFPY  (ldp_show_l2vpn_atom_vc,
	ldp_show_l2vpn_atom_vc_cmd,
	"show l2vpn atom vc\
	  [{\
	    A.B.C.D$peer\
	    |interface IFNAME$ifname\
	    |vc-id (1-4294967295)$vcid\
	  }]\
	 [json]$json",
	"Show running system information\n"
	"Show information about Layer2 VPN\n"
	"Show Any Transport over MPLS information\n"
	"Show AToM virtual circuit information\n"
	"Destination address of the VC\n"
	"Local interface of the pseudowire\n"
	"Interface's name\n"
	"VC ID\n"
	"VC ID\n"
	JSON_STR)
{
	return (ldp_vty_show_atom_vc(vty, peer_str, ifname, vcid_str, json));
}

DEFPY_NOSH (ldp_show_debugging_mpls_ldp,
	    ldp_show_debugging_mpls_ldp_cmd,
	    "show debugging [mpls ldp]",
	    "Show running system information\n"
	    "Debugging functions\n"
	    "MPLS information\n"
	    "Label Distribution Protocol\n")
{
	ldp_vty_show_debugging(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

static void
l2vpn_autocomplete(vector comps, struct cmd_token *token)
{
	struct l2vpn	*l2vpn;

	RB_FOREACH(l2vpn, l2vpn_head, &vty_conf->l2vpn_tree)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, l2vpn->name));
}

static const struct cmd_variable_handler l2vpn_var_handlers[] = {
	{
		.varname = "l2vpn_name",
		.completions = l2vpn_autocomplete
	},
	{
		.completions = NULL
	}
};

void
ldp_vty_init (void)
{
	cmd_variable_handler_register(l2vpn_var_handlers);

	install_node(&ldp_node);
	install_node(&ldp_ipv4_node);
	install_node(&ldp_ipv6_node);
	install_node(&ldp_ipv4_iface_node);
	install_node(&ldp_ipv6_iface_node);
	install_node(&ldp_l2vpn_node);
	install_node(&ldp_pseudowire_node);
	install_node(&ldp_debug_node);
	install_default(LDP_NODE);
	install_default(LDP_IPV4_NODE);
	install_default(LDP_IPV6_NODE);
	install_default(LDP_IPV4_IFACE_NODE);
	install_default(LDP_IPV6_IFACE_NODE);
	install_default(LDP_L2VPN_NODE);
	install_default(LDP_PSEUDOWIRE_NODE);

	install_element(CONFIG_NODE, &ldp_mpls_ldp_cmd);
	install_element(CONFIG_NODE, &no_ldp_mpls_ldp_cmd);
	install_element(CONFIG_NODE, &ldp_l2vpn_cmd);
	install_element(CONFIG_NODE, &no_ldp_l2vpn_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_discovery_hello_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_type_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_messages_recv_cmd);
	install_element(CONFIG_NODE, &ldp_debug_mpls_ldp_messages_sent_cmd);

	install_element(LDP_NODE, &ldp_address_family_cmd);
	install_element(LDP_NODE, &no_ldp_address_family_cmd);
	install_element(LDP_NODE, &ldp_discovery_link_holdtime_cmd);
	install_element(LDP_NODE, &ldp_discovery_targeted_holdtime_cmd);
	install_element(LDP_NODE, &ldp_discovery_link_interval_cmd);
	install_element(LDP_NODE, &ldp_discovery_targeted_interval_cmd);
	install_element(LDP_NODE, &ldp_dual_stack_transport_connection_prefer_ipv4_cmd);
	install_element(LDP_NODE, &ldp_dual_stack_cisco_interop_cmd);
	install_element(LDP_NODE, &ldp_neighbor_password_cmd);
	install_element(LDP_NODE, &ldp_neighbor_session_holdtime_cmd);
	install_element(LDP_NODE, &ldp_neighbor_ttl_security_cmd);
	install_element(LDP_NODE, &ldp_router_id_cmd);
	install_element(LDP_NODE, &ldp_ordered_control_cmd);
	install_element(LDP_NODE, &ldp_wait_for_sync_cmd);
	install_element(LDP_NODE, &ldp_allow_broken_lsps_cmd);

	install_element(LDP_IPV4_NODE, &ldp_discovery_link_holdtime_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_targeted_holdtime_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_link_interval_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_targeted_interval_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_targeted_hello_accept_cmd);
	install_element(LDP_IPV4_NODE, &ldp_discovery_transport_address_ipv4_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_advertise_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_advertise_explicit_null_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_local_allocate_cmd);
	install_element(LDP_IPV4_NODE, &ldp_label_remote_accept_cmd);
	install_element(LDP_IPV4_NODE, &ldp_ttl_security_disable_cmd);
	install_element(LDP_IPV4_NODE, &ldp_interface_cmd);
	install_element(LDP_IPV4_NODE, &no_ldp_interface_cmd);
	install_element(LDP_IPV4_NODE, &ldp_session_holdtime_cmd);
	install_element(LDP_IPV4_NODE, &ldp_neighbor_ipv4_targeted_cmd);
	install_element(LDP_IPV4_NODE, &ldp_exit_address_family_cmd);

	install_element(LDP_IPV6_NODE, &ldp_discovery_link_holdtime_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_targeted_holdtime_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_link_interval_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_targeted_interval_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_targeted_hello_accept_cmd);
	install_element(LDP_IPV6_NODE, &ldp_discovery_transport_address_ipv6_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_advertise_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_advertise_explicit_null_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_local_allocate_cmd);
	install_element(LDP_IPV6_NODE, &ldp_label_remote_accept_cmd);
	install_element(LDP_IPV6_NODE, &ldp_ttl_security_disable_cmd);
	install_element(LDP_IPV6_NODE, &ldp_interface_cmd);
	install_element(LDP_IPV6_NODE, &no_ldp_interface_cmd);
	install_element(LDP_IPV6_NODE, &ldp_session_holdtime_cmd);
	install_element(LDP_IPV6_NODE, &ldp_neighbor_ipv6_targeted_cmd);
	install_element(LDP_IPV6_NODE, &ldp_exit_address_family_cmd);

	install_element(LDP_IPV4_IFACE_NODE, &ldp_discovery_link_holdtime_cmd);
	install_element(LDP_IPV4_IFACE_NODE, &ldp_discovery_link_interval_cmd);

	install_element(LDP_IPV6_IFACE_NODE, &ldp_discovery_link_holdtime_cmd);
	install_element(LDP_IPV6_IFACE_NODE, &ldp_discovery_link_interval_cmd);

	install_element(LDP_L2VPN_NODE, &ldp_bridge_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_mtu_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_member_interface_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_member_pseudowire_cmd);
	install_element(LDP_L2VPN_NODE, &no_ldp_member_pseudowire_cmd);
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
	install_element(VIEW_NODE, &ldp_show_mpls_ldp_igp_sync_cmd);
}
