/* Auto-generated from ldp_vty.xml. */
/* Do not edit! */

#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "ldp_vty.h"

DEFUN (ldp_mpls_ldp,
       ldp_mpls_ldp_cmd,
       "mpls ldp",
       "Global MPLS configuration subcommands\n"
       "Label Distribution Protocol\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_mpls_ldp (vty, args);
}

DEFUN (ldp_l2vpn_word_type_vpls,
       ldp_l2vpn_word_type_vpls_cmd,
       "l2vpn WORD type vpls",
       "Configure l2vpn commands\n"
       "L2VPN name\n"
       "L2VPN type\n"
       "Virtual Private LAN Service\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "name", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn (vty, args);
}

DEFUN (ldp_no_mpls_ldp,
       ldp_no_mpls_ldp_cmd,
       "no mpls ldp",
       "Negate a command or set its defaults\n"
       "Global MPLS configuration subcommands\n"
       "Label Distribution Protocol\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_mpls_ldp (vty, args);
}

DEFUN (ldp_no_l2vpn_word_type_vpls,
       ldp_no_l2vpn_word_type_vpls_cmd,
       "no l2vpn WORD type vpls",
       "Negate a command or set its defaults\n"
       "Configure l2vpn commands\n"
       "L2VPN name\n"
       "L2VPN type\n"
       "Virtual Private LAN Service\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "name", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn (vty, args);
}

DEFUN (ldp_address_family_ipv4,
       ldp_address_family_ipv4_cmd,
       "address-family ipv4",
       "Configure Address Family and its parameters\n"
       "IPv4\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "address-family", .value = "ipv4" },
      NULL
    };
  return ldp_vty_address_family (vty, args);
}

DEFUN (ldp_address_family_ipv6,
       ldp_address_family_ipv6_cmd,
       "address-family ipv6",
       "Configure Address Family and its parameters\n"
       "IPv6\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "address-family", .value = "ipv6" },
      NULL
    };
  return ldp_vty_address_family (vty, args);
}

DEFUN (ldp_discovery_hello_holdtime_disc_time,
       ldp_discovery_hello_holdtime_disc_time_cmd,
       "discovery hello holdtime <1-65535>",
       "Configure discovery parameters\n"
       "LDP Link Hellos\n"
       "Hello holdtime\n"
       "Time (seconds) - 65535 implies infinite\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "hello_type", .value = "hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_holdtime (vty, args);
}

DEFUN (ldp_discovery_hello_interval_disc_time,
       ldp_discovery_hello_interval_disc_time_cmd,
       "discovery hello interval <1-65535>",
       "Configure discovery parameters\n"
       "LDP Link Hellos\n"
       "Hello interval\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "hello_type", .value = "hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_interval (vty, args);
}

DEFUN (ldp_discovery_targeted_hello_holdtime_disc_time,
       ldp_discovery_targeted_hello_holdtime_disc_time_cmd,
       "discovery targeted-hello holdtime <1-65535>",
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Targeted hello holdtime\n"
       "Time (seconds) - 65535 implies infinite\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_holdtime (vty, args);
}

DEFUN (ldp_discovery_targeted_hello_interval_disc_time,
       ldp_discovery_targeted_hello_interval_disc_time_cmd,
       "discovery targeted-hello interval <1-65535>",
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Targeted hello interval\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_interval (vty, args);
}

DEFUN (ldp_dual_stack_transport_connection_prefer_ipv4,
       ldp_dual_stack_transport_connection_prefer_ipv4_cmd,
       "dual-stack transport-connection prefer ipv4",
       "Configure dual stack parameters\n"
       "Configure TCP transport parameters\n"
       "Configure prefered address family for TCP transport connection with neighbor\n"
       "IPv4\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_trans_pref_ipv4 (vty, args);
}

DEFUN (ldp_dual_stack_cisco_interop,
       ldp_dual_stack_cisco_interop_cmd,
       "dual-stack cisco-interop",
       "Configure dual stack parameters\n"
       "Use Cisco non-compliant format to send and interpret the Dual-Stack capability TLV\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_ds_cisco_interop (vty, args);
}

DEFUN (ldp_neighbor_ipv4_password_word,
       ldp_neighbor_ipv4_password_word_cmd,
       "neighbor A.B.C.D password WORD",
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "Configure password for MD5 authentication\n"
       "The password\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "password", .value = argv[1] },
      NULL
    };
  return ldp_vty_neighbor_password (vty, args);
}

DEFUN (ldp_neighbor_ipv4_session_holdtime_session_time,
       ldp_neighbor_ipv4_session_holdtime_session_time_cmd,
       "neighbor A.B.C.D session holdtime <15-65535>",
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "Configure session parameters\n"
       "Configure session holdtime\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "seconds", .value = argv[1] },
      NULL
    };
  return ldp_vty_session_holdtime (vty, args);
}

DEFUN (ldp_neighbor_ipv4_ttl_security_disable,
       ldp_neighbor_ipv4_ttl_security_disable_cmd,
       "neighbor A.B.C.D ttl-security disable",
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "LDP ttl security check\n"
       "Disable ttl security\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_ttl_security (vty, args);
}

DEFUN (ldp_neighbor_ipv4_ttl_security_hops_hops,
       ldp_neighbor_ipv4_ttl_security_hops_hops_cmd,
       "neighbor A.B.C.D ttl-security hops <1-254>",
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "LDP ttl security check\n"
       "IP hops\n"
       "maximum number of hops\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "hops", .value = argv[1] },
      NULL
    };
  return ldp_vty_neighbor_ttl_security (vty, args);
}

DEFUN (ldp_router_id_ipv4,
       ldp_router_id_ipv4_cmd,
       "router-id A.B.C.D",
       "Configure router Id\n"
       "LSR Id (in form of an IPv4 address)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_router_id (vty, args);
}

DEFUN (ldp_no_address_family_ipv4,
       ldp_no_address_family_ipv4_cmd,
       "no address-family ipv4",
       "Negate a command or set its defaults\n"
       "Configure Address Family and its parameters\n"
       "IPv4\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "address-family", .value = "ipv4" },
      NULL
    };
  return ldp_vty_address_family (vty, args);
}

DEFUN (ldp_no_address_family_ipv6,
       ldp_no_address_family_ipv6_cmd,
       "no address-family ipv6",
       "Negate a command or set its defaults\n"
       "Configure Address Family and its parameters\n"
       "IPv6\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "address-family", .value = "ipv6" },
      NULL
    };
  return ldp_vty_address_family (vty, args);
}

DEFUN (ldp_no_discovery_hello_holdtime_disc_time,
       ldp_no_discovery_hello_holdtime_disc_time_cmd,
       "no discovery hello holdtime <1-65535>",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "LDP Link Hellos\n"
       "Hello holdtime\n"
       "Time (seconds) - 65535 implies infinite\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "hello_type", .value = "hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_holdtime (vty, args);
}

DEFUN (ldp_no_discovery_hello_interval_disc_time,
       ldp_no_discovery_hello_interval_disc_time_cmd,
       "no discovery hello interval <1-65535>",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "LDP Link Hellos\n"
       "Hello interval\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "hello_type", .value = "hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_interval (vty, args);
}

DEFUN (ldp_no_discovery_targeted_hello_holdtime_disc_time,
       ldp_no_discovery_targeted_hello_holdtime_disc_time_cmd,
       "no discovery targeted-hello holdtime <1-65535>",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Targeted hello holdtime\n"
       "Time (seconds) - 65535 implies infinite\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_holdtime (vty, args);
}

DEFUN (ldp_no_discovery_targeted_hello_interval_disc_time,
       ldp_no_discovery_targeted_hello_interval_disc_time_cmd,
       "no discovery targeted-hello interval <1-65535>",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Targeted hello interval\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_disc_interval (vty, args);
}

DEFUN (ldp_no_dual_stack_transport_connection_prefer_ipv4,
       ldp_no_dual_stack_transport_connection_prefer_ipv4_cmd,
       "no dual-stack transport-connection prefer ipv4",
       "Negate a command or set its defaults\n"
       "Configure dual stack parameters\n"
       "Configure TCP transport parameters\n"
       "Configure prefered address family for TCP transport connection with neighbor\n"
       "IPv4\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_trans_pref_ipv4 (vty, args);
}

DEFUN (ldp_no_dual_stack_cisco_interop,
       ldp_no_dual_stack_cisco_interop_cmd,
       "no dual-stack cisco-interop",
       "Negate a command or set its defaults\n"
       "Configure dual stack parameters\n"
       "Use Cisco non-compliant format to send and interpret the Dual-Stack capability TLV\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_ds_cisco_interop (vty, args);
}

DEFUN (ldp_no_neighbor_ipv4_password_word,
       ldp_no_neighbor_ipv4_password_word_cmd,
       "no neighbor A.B.C.D password WORD",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "Configure password for MD5 authentication\n"
       "The password\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "password", .value = argv[1] },
      NULL
    };
  return ldp_vty_neighbor_password (vty, args);
}

DEFUN (ldp_no_neighbor_ipv4_session_holdtime_session_time,
       ldp_no_neighbor_ipv4_session_holdtime_session_time_cmd,
       "no neighbor A.B.C.D session holdtime <15-65535>",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "Configure session parameters\n"
       "Configure session holdtime\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "seconds", .value = argv[1] },
      NULL
    };
  return ldp_vty_session_holdtime (vty, args);
}

DEFUN (ldp_no_neighbor_ipv4_ttl_security_disable,
       ldp_no_neighbor_ipv4_ttl_security_disable_cmd,
       "no neighbor A.B.C.D ttl-security disable",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "LDP ttl security check\n"
       "Disable ttl security\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_ttl_security (vty, args);
}

DEFUN (ldp_no_neighbor_ipv4_ttl_security_hops_hops,
       ldp_no_neighbor_ipv4_ttl_security_hops_hops_cmd,
       "no neighbor A.B.C.D ttl-security hops <1-254>",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "LDP Id of neighbor\n"
       "LDP ttl security check\n"
       "IP hops\n"
       "maximum number of hops\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "lsr_id", .value = argv[0] },
      &(struct vty_arg) { .name = "hops", .value = argv[1] },
      NULL
    };
  return ldp_vty_neighbor_ttl_security (vty, args);
}

DEFUN (ldp_no_router_id_ipv4,
       ldp_no_router_id_ipv4_cmd,
       "no router-id A.B.C.D",
       "Negate a command or set its defaults\n"
       "Configure router Id\n"
       "LSR Id (in form of an IPv4 address)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_router_id (vty, args);
}

DEFUN (ldp_discovery_targeted_hello_accept,
       ldp_discovery_targeted_hello_accept_cmd,
       "discovery targeted-hello accept",
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Accept and respond to targeted hellos\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      NULL
    };
  return ldp_vty_targeted_hello_accept (vty, args);
}

DEFUN (ldp_label_local_advertise_explicit_null,
       ldp_label_local_advertise_explicit_null_cmd,
       "label local advertise explicit-null",
       "Configure label control and policies\n"
       "Configure local label control and policies\n"
       "Configure outbound label advertisement control\n"
       "Configure explicit-null advertisement\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_explicit_null (vty, args);
}

DEFUN (ldp_ttl_security_disable,
       ldp_ttl_security_disable_cmd,
       "ttl-security disable",
       "LDP ttl security check\n"
       "Disable ttl security\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_ttl_security (vty, args);
}

DEFUN (ldp_session_holdtime_session_time,
       ldp_session_holdtime_session_time_cmd,
       "session holdtime <15-65535>",
       "Configure session parameters\n"
       "Configure session holdtime\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_session_holdtime (vty, args);
}

DEFUN (ldp_interface_ifname,
       ldp_interface_ifname_cmd,
       "interface IFNAME",
       "Enable LDP on an interface and enter interface submode\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_interface (vty, args);
}

DEFUN (ldp_discovery_transport_address_ipv4,
       ldp_discovery_transport_address_ipv4_cmd,
       "discovery transport-address A.B.C.D",
       "Configure discovery parameters\n"
       "Specify transport address for TCP connection\n"
       "IP address to be used as transport address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_trans_addr (vty, args);
}

DEFUN (ldp_neighbor_ipv4_targeted,
       ldp_neighbor_ipv4_targeted_cmd,
       "neighbor A.B.C.D targeted",
       "Configure neighbor parameters\n"
       "IP address of neighbor\n"
       "Establish targeted session\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_targeted (vty, args);
}

DEFUN (ldp_no_discovery_targeted_hello_accept,
       ldp_no_discovery_targeted_hello_accept_cmd,
       "no discovery targeted-hello accept",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "LDP Targeted Hellos\n"
       "Accept and respond to targeted hellos\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "hello_type", .value = "targeted-hello" },
      NULL
    };
  return ldp_vty_targeted_hello_accept (vty, args);
}

DEFUN (ldp_no_label_local_advertise_explicit_null,
       ldp_no_label_local_advertise_explicit_null_cmd,
       "no label local advertise explicit-null",
       "Negate a command or set its defaults\n"
       "Configure label control and policies\n"
       "Configure local label control and policies\n"
       "Configure outbound label advertisement control\n"
       "Configure explicit-null advertisement\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_explicit_null (vty, args);
}

DEFUN (ldp_no_ttl_security_disable,
       ldp_no_ttl_security_disable_cmd,
       "no ttl-security disable",
       "Negate a command or set its defaults\n"
       "LDP ttl security check\n"
       "Disable ttl security\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_ttl_security (vty, args);
}

DEFUN (ldp_no_session_holdtime_session_time,
       ldp_no_session_holdtime_session_time_cmd,
       "no session holdtime <15-65535>",
       "Negate a command or set its defaults\n"
       "Configure session parameters\n"
       "Configure session holdtime\n"
       "Time (seconds)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "seconds", .value = argv[0] },
      NULL
    };
  return ldp_vty_session_holdtime (vty, args);
}

DEFUN (ldp_no_interface_ifname,
       ldp_no_interface_ifname_cmd,
       "no interface IFNAME",
       "Negate a command or set its defaults\n"
       "Enable LDP on an interface and enter interface submode\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_interface (vty, args);
}

DEFUN (ldp_no_discovery_transport_address_ipv4,
       ldp_no_discovery_transport_address_ipv4_cmd,
       "no discovery transport-address A.B.C.D",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "Specify transport address for TCP connection\n"
       "IP address to be used as transport address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_trans_addr (vty, args);
}

DEFUN (ldp_no_neighbor_ipv4_targeted,
       ldp_no_neighbor_ipv4_targeted_cmd,
       "no neighbor A.B.C.D targeted",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "IP address of neighbor\n"
       "Establish targeted session\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_targeted (vty, args);
}

DEFUN (ldp_discovery_transport_address_ipv6,
       ldp_discovery_transport_address_ipv6_cmd,
       "discovery transport-address X:X::X:X",
       "Configure discovery parameters\n"
       "Specify transport address for TCP connection\n"
       "IPv6 address to be used as transport address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_trans_addr (vty, args);
}

DEFUN (ldp_neighbor_ipv6_targeted,
       ldp_neighbor_ipv6_targeted_cmd,
       "neighbor X:X::X:X targeted",
       "Configure neighbor parameters\n"
       "IPv6 address of neighbor\n"
       "Establish targeted session\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_targeted (vty, args);
}

DEFUN (ldp_no_discovery_transport_address_ipv6,
       ldp_no_discovery_transport_address_ipv6_cmd,
       "no discovery transport-address X:X::X:X",
       "Negate a command or set its defaults\n"
       "Configure discovery parameters\n"
       "Specify transport address for TCP connection\n"
       "IPv6 address to be used as transport address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_trans_addr (vty, args);
}

DEFUN (ldp_no_neighbor_ipv6_targeted,
       ldp_no_neighbor_ipv6_targeted_cmd,
       "no neighbor X:X::X:X targeted",
       "Negate a command or set its defaults\n"
       "Configure neighbor parameters\n"
       "IPv6 address of neighbor\n"
       "Establish targeted session\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_neighbor_targeted (vty, args);
}

DEFUN (ldp_bridge_ifname,
       ldp_bridge_ifname_cmd,
       "bridge IFNAME",
       "Bridge interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_bridge (vty, args);
}

DEFUN (ldp_mtu_mtu,
       ldp_mtu_mtu_cmd,
       "mtu <1500-9180>",
       "set Maximum Transmission Unit\n"
       "Maximum Transmission Unit value\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "mtu", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_mtu (vty, args);
}

DEFUN (ldp_member_interface_ifname,
       ldp_member_interface_ifname_cmd,
       "member interface IFNAME",
       "L2VPN member configuration\n"
       "Local interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_interface (vty, args);
}

DEFUN (ldp_member_pseudowire_ifname,
       ldp_member_pseudowire_ifname_cmd,
       "member pseudowire IFNAME",
       "L2VPN member configuration\n"
       "Pseudowire interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pseudowire (vty, args);
}

DEFUN (ldp_vc_type_pwtype,
       ldp_vc_type_pwtype_cmd,
       "vc type (ethernet|ethernet-tagged)",
       "Virtual Circuit options\n"
       "Virtual Circuit type to use\n"
       "Ethernet (type 5)\n"
       "Ethernet-tagged (type 4)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pwtype (vty, args);
}

DEFUN (ldp_no_bridge_ifname,
       ldp_no_bridge_ifname_cmd,
       "no bridge IFNAME",
       "Negate a command or set its defaults\n"
       "Bridge interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_bridge (vty, args);
}

DEFUN (ldp_no_mtu_mtu,
       ldp_no_mtu_mtu_cmd,
       "no mtu <1500-9180>",
       "Negate a command or set its defaults\n"
       "set Maximum Transmission Unit\n"
       "Maximum Transmission Unit value\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "mtu", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_mtu (vty, args);
}

DEFUN (ldp_no_member_interface_ifname,
       ldp_no_member_interface_ifname_cmd,
       "no member interface IFNAME",
       "Negate a command or set its defaults\n"
       "L2VPN member configuration\n"
       "Local interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_interface (vty, args);
}

DEFUN (ldp_no_member_pseudowire_ifname,
       ldp_no_member_pseudowire_ifname_cmd,
       "no member pseudowire IFNAME",
       "Negate a command or set its defaults\n"
       "L2VPN member configuration\n"
       "Pseudowire interface\n"
       "Interface's name\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "ifname", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pseudowire (vty, args);
}

DEFUN (ldp_no_vc_type_pwtype,
       ldp_no_vc_type_pwtype_cmd,
       "no vc type (ethernet|ethernet-tagged)",
       "Negate a command or set its defaults\n"
       "Virtual Circuit options\n"
       "Virtual Circuit type to use\n"
       "Ethernet (type 5)\n"
       "Ethernet-tagged (type 4)\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pwtype (vty, args);
}

DEFUN (ldp_control_word_cword,
       ldp_control_word_cword_cmd,
       "control-word (exclude|include)",
       "Control-word options\n"
       "Exclude control-word in pseudowire packets\n"
       "Include control-word in pseudowire packets\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "preference", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_cword (vty, args);
}

DEFUN (ldp_neighbor_address_addr,
       ldp_neighbor_address_addr_cmd,
       "neighbor address (A.B.C.D|X:X::X:X)",
       "Remote endpoint configuration\n"
       "Specify the IPv4 or IPv6 address of the remote endpoint\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_nbr_addr (vty, args);
}

DEFUN (ldp_neighbor_lsr_id_ipv4,
       ldp_neighbor_lsr_id_ipv4_cmd,
       "neighbor lsr-id A.B.C.D",
       "Remote endpoint configuration\n"
       "Specify the LSR-ID of the remote endpoint\n"
       "IPv4 address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "lsr-id", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_nbr_id (vty, args);
}

DEFUN (ldp_pw_id_pwid,
       ldp_pw_id_pwid_cmd,
       "pw-id <1-4294967295>",
       "Set the Virtual Circuit ID\n"
       "Virtual Circuit ID value\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "pwid", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_pwid (vty, args);
}

DEFUN (ldp_pw_status_disable,
       ldp_pw_status_disable_cmd,
       "pw-status disable",
       "Configure PW status\n"
       "Disable PW status\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_l2vpn_pw_pwstatus (vty, args);
}

DEFUN (ldp_no_control_word_cword,
       ldp_no_control_word_cword_cmd,
       "no control-word (exclude|include)",
       "Negate a command or set its defaults\n"
       "Control-word options\n"
       "Exclude control-word in pseudowire packets\n"
       "Include control-word in pseudowire packets\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "preference", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_cword (vty, args);
}

DEFUN (ldp_no_neighbor_address_addr,
       ldp_no_neighbor_address_addr_cmd,
       "no neighbor address (A.B.C.D|X:X::X:X)",
       "Negate a command or set its defaults\n"
       "Remote endpoint configuration\n"
       "Specify the IPv4 or IPv6 address of the remote endpoint\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_nbr_addr (vty, args);
}

DEFUN (ldp_no_neighbor_lsr_id_ipv4,
       ldp_no_neighbor_lsr_id_ipv4_cmd,
       "no neighbor lsr-id A.B.C.D",
       "Negate a command or set its defaults\n"
       "Remote endpoint configuration\n"
       "Specify the LSR-ID of the remote endpoint\n"
       "IPv4 address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "lsr-id", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_nbr_id (vty, args);
}

DEFUN (ldp_no_pw_id_pwid,
       ldp_no_pw_id_pwid_cmd,
       "no pw-id <1-4294967295>",
       "Negate a command or set its defaults\n"
       "Set the Virtual Circuit ID\n"
       "Virtual Circuit ID value\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "pwid", .value = argv[0] },
      NULL
    };
  return ldp_vty_l2vpn_pw_pwid (vty, args);
}

DEFUN (ldp_no_pw_status_disable,
       ldp_no_pw_status_disable_cmd,
       "no pw-status disable",
       "Negate a command or set its defaults\n"
       "Configure PW status\n"
       "Disable PW status\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      NULL
    };
  return ldp_vty_l2vpn_pw_pwstatus (vty, args);
}

DEFUN (ldp_show_mpls_ldp_neighbor,
       ldp_show_mpls_ldp_neighbor_cmd,
       "show mpls ldp neighbor",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Neighbor information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_neighbor (vty, args);
}

DEFUN (ldp_show_mpls_ldp_binding,
       ldp_show_mpls_ldp_binding_cmd,
       "show mpls ldp binding",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Label Information Base (LIB) information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_binding (vty, args);
}

DEFUN (ldp_show_mpls_ldp_discovery,
       ldp_show_mpls_ldp_discovery_cmd,
       "show mpls ldp discovery",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Discovery Hello Information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_discovery (vty, args);
}

DEFUN (ldp_show_mpls_ldp_interface,
       ldp_show_mpls_ldp_interface_cmd,
       "show mpls ldp interface",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "interface information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_interface (vty, args);
}

DEFUN (ldp_show_mpls_ldp_address_family_binding,
       ldp_show_mpls_ldp_address_family_binding_cmd,
       "show mpls ldp (ipv4|ipv6) binding",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "IPv4 Address Family\n"
       "IPv6 Address Family\n"
       "Label Information Base (LIB) information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "address-family", .value = argv[0] },
      NULL
    };
  return ldp_vty_show_binding (vty, args);
}

DEFUN (ldp_show_mpls_ldp_address_family_discovery,
       ldp_show_mpls_ldp_address_family_discovery_cmd,
       "show mpls ldp (ipv4|ipv6) discovery",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "IPv4 Address Family\n"
       "IPv6 Address Family\n"
       "Discovery Hello Information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "address-family", .value = argv[0] },
      NULL
    };
  return ldp_vty_show_discovery (vty, args);
}

DEFUN (ldp_show_mpls_ldp_address_family_interface,
       ldp_show_mpls_ldp_address_family_interface_cmd,
       "show mpls ldp (ipv4|ipv6) interface",
       "Show running system information\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "IPv4 Address Family\n"
       "IPv6 Address Family\n"
       "interface information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "address-family", .value = argv[0] },
      NULL
    };
  return ldp_vty_show_interface (vty, args);
}

DEFUN (ldp_show_l2vpn_atom_binding,
       ldp_show_l2vpn_atom_binding_cmd,
       "show l2vpn atom binding",
       "Show running system information\n"
       "Show information about Layer2 VPN\n"
       "Show Any Transport over MPLS information\n"
       "Show AToM label binding information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_atom_binding (vty, args);
}

DEFUN (ldp_show_l2vpn_atom_vc,
       ldp_show_l2vpn_atom_vc_cmd,
       "show l2vpn atom vc",
       "Show running system information\n"
       "Show information about Layer2 VPN\n"
       "Show Any Transport over MPLS information\n"
       "Show AToM virtual circuit information\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_atom_vc (vty, args);
}

DEFUN (ldp_show_debugging_mpls_ldp,
       ldp_show_debugging_mpls_ldp_cmd,
       "show debugging mpls ldp",
       "Show running system information\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_show_debugging (vty, args);
}

DEFUN (ldp_clear_mpls_ldp_neighbor,
       ldp_clear_mpls_ldp_neighbor_cmd,
       "clear mpls ldp neighbor",
       "Reset functions\n"
       "Reset MPLS statistical information\n"
       "Clear LDP state\n"
       "Clear LDP neighbor sessions\n")
{
  struct vty_arg *args[] = { NULL };
  return ldp_vty_clear_nbr (vty, args);
}

DEFUN (ldp_clear_mpls_ldp_neighbor_addr,
       ldp_clear_mpls_ldp_neighbor_addr_cmd,
       "clear mpls ldp neighbor (A.B.C.D|X:X::X:X)",
       "Reset functions\n"
       "Reset MPLS statistical information\n"
       "Clear LDP state\n"
       "Clear LDP neighbor sessions\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "addr", .value = argv[0] },
      NULL
    };
  return ldp_vty_clear_nbr (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_discovery_hello_dir,
       ldp_debug_mpls_ldp_discovery_hello_dir_cmd,
       "debug mpls ldp discovery hello (recv|sent)",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Discovery messages\n"
       "Discovery hello message\n"
       "Received messages\n"
       "Sent messages\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "discovery" },
      &(struct vty_arg) { .name = "dir", .value = argv[0] },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_errors,
       ldp_debug_mpls_ldp_errors_cmd,
       "debug mpls ldp errors",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Errors\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "errors" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_event,
       ldp_debug_mpls_ldp_event_cmd,
       "debug mpls ldp event",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "LDP event information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "event" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_messages_recv,
       ldp_debug_mpls_ldp_messages_recv_cmd,
       "debug mpls ldp messages recv",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Received messages, excluding periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "recv" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_messages_recv_all,
       ldp_debug_mpls_ldp_messages_recv_all_cmd,
       "debug mpls ldp messages recv all",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Received messages, excluding periodic Keep Alives\n"
       "Received messages, including periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "recv" },
      &(struct vty_arg) { .name = "all", .value = "all" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_messages_sent,
       ldp_debug_mpls_ldp_messages_sent_cmd,
       "debug mpls ldp messages sent",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Sent messages, excluding periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "sent" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_messages_sent_all,
       ldp_debug_mpls_ldp_messages_sent_all_cmd,
       "debug mpls ldp messages sent all",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Sent messages, excluding periodic Keep Alives\n"
       "Sent messages, including periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "sent" },
      &(struct vty_arg) { .name = "all", .value = "all" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_debug_mpls_ldp_zebra,
       ldp_debug_mpls_ldp_zebra_cmd,
       "debug mpls ldp zebra",
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "LDP zebra information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "type", .value = "zebra" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_discovery_hello_dir,
       ldp_no_debug_mpls_ldp_discovery_hello_dir_cmd,
       "no debug mpls ldp discovery hello (recv|sent)",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Discovery messages\n"
       "Discovery hello message\n"
       "Received messages\n"
       "Sent messages\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "discovery" },
      &(struct vty_arg) { .name = "dir", .value = argv[0] },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_errors,
       ldp_no_debug_mpls_ldp_errors_cmd,
       "no debug mpls ldp errors",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Errors\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "errors" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_event,
       ldp_no_debug_mpls_ldp_event_cmd,
       "no debug mpls ldp event",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "LDP event information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "event" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_messages_recv,
       ldp_no_debug_mpls_ldp_messages_recv_cmd,
       "no debug mpls ldp messages recv",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Received messages, excluding periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "recv" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_messages_recv_all,
       ldp_no_debug_mpls_ldp_messages_recv_all_cmd,
       "no debug mpls ldp messages recv all",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Received messages, excluding periodic Keep Alives\n"
       "Received messages, including periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "recv" },
      &(struct vty_arg) { .name = "all", .value = "all" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_messages_sent,
       ldp_no_debug_mpls_ldp_messages_sent_cmd,
       "no debug mpls ldp messages sent",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Sent messages, excluding periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "sent" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_messages_sent_all,
       ldp_no_debug_mpls_ldp_messages_sent_all_cmd,
       "no debug mpls ldp messages sent all",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "Messages\n"
       "Sent messages, excluding periodic Keep Alives\n"
       "Sent messages, including periodic Keep Alives\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "messages" },
      &(struct vty_arg) { .name = "dir", .value = "sent" },
      &(struct vty_arg) { .name = "all", .value = "all" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

DEFUN (ldp_no_debug_mpls_ldp_zebra,
       ldp_no_debug_mpls_ldp_zebra_cmd,
       "no debug mpls ldp zebra",
       "Negate a command or set its defaults\n"
       "Debugging functions\n"
       "MPLS information\n"
       "Label Distribution Protocol\n"
       "LDP zebra information\n")
{
  struct vty_arg *args[] =
    {
      &(struct vty_arg) { .name = "no", .value = "no" },
      &(struct vty_arg) { .name = "type", .value = "zebra" },
      NULL
    };
  return ldp_vty_debug (vty, args);
}

void
ldp_vty_init (void)
{
  install_element (CONFIG_NODE, &ldp_mpls_ldp_cmd);
  install_element (CONFIG_NODE, &ldp_l2vpn_word_type_vpls_cmd);
  install_element (CONFIG_NODE, &ldp_no_mpls_ldp_cmd);
  install_element (CONFIG_NODE, &ldp_no_l2vpn_word_type_vpls_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_discovery_hello_dir_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_errors_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_event_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_messages_recv_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_messages_recv_all_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_messages_sent_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_messages_sent_all_cmd);
  install_element (CONFIG_NODE, &ldp_debug_mpls_ldp_zebra_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_discovery_hello_dir_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_errors_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_event_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_messages_recv_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_messages_recv_all_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_messages_sent_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_messages_sent_all_cmd);
  install_element (CONFIG_NODE, &ldp_no_debug_mpls_ldp_zebra_cmd);
  install_node (&ldp_node, ldp_config_write);
  install_default (LDP_NODE);
  install_element (LDP_NODE, &ldp_address_family_ipv4_cmd);
  install_element (LDP_NODE, &ldp_address_family_ipv6_cmd);
  install_element (LDP_NODE, &ldp_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_NODE, &ldp_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_NODE, &ldp_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_NODE, &ldp_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_NODE, &ldp_dual_stack_transport_connection_prefer_ipv4_cmd);
  install_element (LDP_NODE, &ldp_dual_stack_cisco_interop_cmd);
  install_element (LDP_NODE, &ldp_neighbor_ipv4_password_word_cmd);
  install_element (LDP_NODE, &ldp_neighbor_ipv4_session_holdtime_session_time_cmd);
  install_element (LDP_NODE, &ldp_neighbor_ipv4_ttl_security_disable_cmd);
  install_element (LDP_NODE, &ldp_neighbor_ipv4_ttl_security_hops_hops_cmd);
  install_element (LDP_NODE, &ldp_router_id_ipv4_cmd);
  install_element (LDP_NODE, &ldp_no_address_family_ipv4_cmd);
  install_element (LDP_NODE, &ldp_no_address_family_ipv6_cmd);
  install_element (LDP_NODE, &ldp_no_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_NODE, &ldp_no_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_NODE, &ldp_no_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_NODE, &ldp_no_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_NODE, &ldp_no_dual_stack_transport_connection_prefer_ipv4_cmd);
  install_element (LDP_NODE, &ldp_no_dual_stack_cisco_interop_cmd);
  install_element (LDP_NODE, &ldp_no_neighbor_ipv4_password_word_cmd);
  install_element (LDP_NODE, &ldp_no_neighbor_ipv4_session_holdtime_session_time_cmd);
  install_element (LDP_NODE, &ldp_no_neighbor_ipv4_ttl_security_disable_cmd);
  install_element (LDP_NODE, &ldp_no_neighbor_ipv4_ttl_security_hops_hops_cmd);
  install_element (LDP_NODE, &ldp_no_router_id_ipv4_cmd);
  install_node (&ldp_ipv4_node, NULL);
  install_default (LDP_IPV4_NODE);
  install_element (LDP_IPV4_NODE, &ldp_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_discovery_targeted_hello_accept_cmd);
  install_element (LDP_IPV4_NODE, &ldp_label_local_advertise_explicit_null_cmd);
  install_element (LDP_IPV4_NODE, &ldp_ttl_security_disable_cmd);
  install_element (LDP_IPV4_NODE, &ldp_session_holdtime_session_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_interface_ifname_cmd);
  install_element (LDP_IPV4_NODE, &ldp_discovery_transport_address_ipv4_cmd);
  install_element (LDP_IPV4_NODE, &ldp_neighbor_ipv4_targeted_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_targeted_hello_accept_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_label_local_advertise_explicit_null_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_ttl_security_disable_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_session_holdtime_session_time_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_interface_ifname_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_discovery_transport_address_ipv4_cmd);
  install_element (LDP_IPV4_NODE, &ldp_no_neighbor_ipv4_targeted_cmd);
  install_node (&ldp_ipv6_node, NULL);
  install_default (LDP_IPV6_NODE);
  install_element (LDP_IPV6_NODE, &ldp_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_discovery_targeted_hello_accept_cmd);
  install_element (LDP_IPV6_NODE, &ldp_label_local_advertise_explicit_null_cmd);
  install_element (LDP_IPV6_NODE, &ldp_ttl_security_disable_cmd);
  install_element (LDP_IPV6_NODE, &ldp_session_holdtime_session_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_interface_ifname_cmd);
  install_element (LDP_IPV6_NODE, &ldp_discovery_transport_address_ipv6_cmd);
  install_element (LDP_IPV6_NODE, &ldp_neighbor_ipv6_targeted_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_targeted_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_targeted_hello_interval_disc_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_targeted_hello_accept_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_label_local_advertise_explicit_null_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_ttl_security_disable_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_session_holdtime_session_time_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_interface_ifname_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_discovery_transport_address_ipv6_cmd);
  install_element (LDP_IPV6_NODE, &ldp_no_neighbor_ipv6_targeted_cmd);
  install_node (&ldp_ipv4_iface_node, NULL);
  install_default (LDP_IPV4_IFACE_NODE);
  install_element (LDP_IPV4_IFACE_NODE, &ldp_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_IFACE_NODE, &ldp_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV4_IFACE_NODE, &ldp_no_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV4_IFACE_NODE, &ldp_no_discovery_hello_interval_disc_time_cmd);
  install_node (&ldp_ipv6_iface_node, NULL);
  install_default (LDP_IPV6_IFACE_NODE);
  install_element (LDP_IPV6_IFACE_NODE, &ldp_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_IFACE_NODE, &ldp_discovery_hello_interval_disc_time_cmd);
  install_element (LDP_IPV6_IFACE_NODE, &ldp_no_discovery_hello_holdtime_disc_time_cmd);
  install_element (LDP_IPV6_IFACE_NODE, &ldp_no_discovery_hello_interval_disc_time_cmd);
  install_node (&ldp_l2vpn_node, ldp_l2vpn_config_write);
  install_default (LDP_L2VPN_NODE);
  install_element (LDP_L2VPN_NODE, &ldp_bridge_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_mtu_mtu_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_member_interface_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_member_pseudowire_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_vc_type_pwtype_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_no_bridge_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_no_mtu_mtu_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_no_member_interface_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_no_member_pseudowire_ifname_cmd);
  install_element (LDP_L2VPN_NODE, &ldp_no_vc_type_pwtype_cmd);
  install_node (&ldp_pseudowire_node, NULL);
  install_default (LDP_PSEUDOWIRE_NODE);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_control_word_cword_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_neighbor_address_addr_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_neighbor_lsr_id_ipv4_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_pw_id_pwid_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_pw_status_disable_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_no_control_word_cword_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_no_neighbor_address_addr_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_no_neighbor_lsr_id_ipv4_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_no_pw_id_pwid_cmd);
  install_element (LDP_PSEUDOWIRE_NODE, &ldp_no_pw_status_disable_cmd);
  install_node (&ldp_debug_node, ldp_debug_config_write);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_neighbor_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_binding_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_discovery_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_interface_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_address_family_binding_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_address_family_discovery_cmd);
  install_element (ENABLE_NODE, &ldp_show_mpls_ldp_address_family_interface_cmd);
  install_element (ENABLE_NODE, &ldp_show_l2vpn_atom_binding_cmd);
  install_element (ENABLE_NODE, &ldp_show_l2vpn_atom_vc_cmd);
  install_element (ENABLE_NODE, &ldp_show_debugging_mpls_ldp_cmd);
  install_element (ENABLE_NODE, &ldp_clear_mpls_ldp_neighbor_cmd);
  install_element (ENABLE_NODE, &ldp_clear_mpls_ldp_neighbor_addr_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_discovery_hello_dir_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_errors_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_event_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_messages_recv_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_messages_recv_all_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_messages_sent_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_messages_sent_all_cmd);
  install_element (ENABLE_NODE, &ldp_debug_mpls_ldp_zebra_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_discovery_hello_dir_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_errors_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_event_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_messages_recv_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_messages_recv_all_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_messages_sent_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_messages_sent_all_cmd);
  install_element (ENABLE_NODE, &ldp_no_debug_mpls_ldp_zebra_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_neighbor_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_binding_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_discovery_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_interface_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_address_family_binding_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_address_family_discovery_cmd);
  install_element (VIEW_NODE, &ldp_show_mpls_ldp_address_family_interface_cmd);
  install_element (VIEW_NODE, &ldp_show_l2vpn_atom_binding_cmd);
  install_element (VIEW_NODE, &ldp_show_l2vpn_atom_vc_cmd);
  install_element (VIEW_NODE, &ldp_show_debugging_mpls_ldp_cmd);
  install_element (VIEW_NODE, &ldp_clear_mpls_ldp_neighbor_cmd);
  install_element (VIEW_NODE, &ldp_clear_mpls_ldp_neighbor_addr_cmd);
}