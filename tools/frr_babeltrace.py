#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Usage: frr_babeltrace.py trace_path

FRR pushes data into lttng tracepoints in the least overhead way possible
i.e. as binary-data/crf_arrays. These traces need to be converted into pretty
strings for easy greping etc. This script is a babeltrace python plugin for
that pretty printing.

Copyright (C) 2021  NVIDIA Corporation
Anuradha Karuppiah
"""

import ipaddress
import os
import socket
import sys

import babeltrace


########################### common parsers - start ############################
def print_ip_addr(field_val):
    """
    pretty print "struct ipaddr"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[4:8]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[4:])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_mac(field_val):
    """
    pretty print "u8 mac[6]"
    """
    return ":".join("%02x" % fb for fb in field_val)


def print_net_ipv4_addr(field_val):
    """
    pretty print ctf_integer_network ipv4
    """
    return str(ipaddress.IPv4Address(field_val))


def bfd_packet_validation_error2str(field_val):
    """Convert BFD packet validation error code to string"""
    errors = {
        1: "PACKET_TOO_SMALL",
        2: "INVALID_TTL",
        3: "BAD_VERSION",
        4: "ZERO_DETECT_MULT",
        5: "INVALID_LENGTH",
        6: "MULTIPOINT_SET",
        7: "ZERO_DISCRIMINATOR",
        8: "WRONG_VRF",
    }
    return errors.get(field_val, f"UNKNOWN_ERROR_{field_val}")


def bfd_dplane_op2str(field_val):
    """Convert BFD data plane operation code to string"""
    ops = {
        1: "socket",
        2: "bind",
        3: "listen",
        4: "accept",
        5: "connect",
        6: "setsockopt_reuseaddr",
    }
    return ops.get(field_val, f"UNKNOWN_OP_{field_val}")


def bfd_state2str(field_val):
    """Convert BFD state to string"""
    states = {0: "ADM_DOWN", 1: "DOWN", 2: "INIT", 3: "UP"}
    return states.get(field_val, f"UNKNOWN_STATE_{field_val}")


def print_bfd_addr(field_val, family):
    """
    pretty print BFD address (struct in6_addr with separate family)
    """
    if family == socket.AF_INET:
        addr = [str(fv) for fv in field_val[:4]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if family == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val)
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not family:
        return ""

    return field_val


def bfd_auth_type2str(field_val):
    """Convert BFD authentication type to string"""
    auth_types = {0: "NULL", 1: "SIMPLE", 2: "CRYPTOGRAPHIC"}
    return auth_types.get(field_val, f"UNKNOWN_AUTH_{field_val}")


>>>>>>> 9721dc1506f7 (bfdd: Lttng traces for bfdd module)
def print_esi(field_val):
    """
    pretty print ethernet segment id, esi_t
    """
    return ":".join("%02x" % fb for fb in field_val)


def get_field_list(event):
    """
    only fetch fields added via the TP, skip metadata etc.
    """
    return event.field_list_with_scope(babeltrace.CTFScope.EVENT_FIELDS)


def parse_event(event, field_parsers):
    """
    Wild card event parser; doesn't make things any prettier
    """
    field_list = get_field_list(event)
    field_info = {}
    for field in field_list:
        if field in field_parsers:
            field_parser = field_parsers.get(field)
            field_info[field] = field_parser(event.get(field))
        else:
            field_info[field] = event.get(field)
    print(event.name, field_info)


def print_family_str(field_val):
    """
    pretty print kernel family to string
    """
    if field_val == socket.AF_INET:
        cmd_str = "ipv4"
    elif field_val == socket.AF_INET6:
        cmd_str = "ipv6"
    elif field_val == socket.AF_BRIDGE:
        cmd_str = "bridge"
    elif field_val == 128:  # RTNL_FAMILY_IPMR:
        cmd_str = "ipv4MR"
    elif field_val == 129:  # RTNL_FAMILY_IP6MR:
        cmd_str = "ipv6MR"
    else:
        cmd_str = "Invalid family"

    return cmd_str


############################ common parsers - end #############################


############################ BFD parsers - start ###############################
def parse_frr_bfd_state_change(event):
    """Parse BFD state change events"""
    family = event.get("family")
    field_parsers = {
        "old_state": bfd_state2str,
        "new_state": bfd_state2str,
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family),
        "peer_addr": lambda x: print_bfd_addr(x, family),
        "mhop": lambda x: "multihop" if x else "singlehop",
        "diag": lambda x: {
            0: "No Diagnostic",
            1: "Control Detection Time Expired",
            2: "Echo Function Failed",
            3: "Neighbor Signaled Session Down",
            4: "Forwarding Plane Reset",
            5: "Path Down",
            6: "Concatenated Path Down",
            7: "Administratively Down",
            8: "Reverse Concatenated Path Down",
        }.get(x, f"Unknown Diag {x}"),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_vrf_lifecycle(event):
    """Parse BFD VRF lifecycle events"""
    field_parsers = {
        "action": lambda x: {1: "CREATE", 2: "DELETE", 3: "ENABLE", 4: "DISABLE"}.get(
            x, f"UNKNOWN_ACTION_{x}"
        )
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_dplane_init_error(event):
    """Parse BFD data plane initialization error events"""
    field_parsers = {
        "op_code": bfd_dplane_op2str,
        "errno_val": lambda x: f"{x} ({os.strerror(x)})" if x > 0 else str(x),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_packet_validation_error(event):
    """Parse BFD packet validation error events"""
    family = event.get("family", 0)
    error_code = event.get("error_code", 0)

    # Format error_value/expected_value based on error type
    def format_error_detail(error_code, error_val, expected_val):
        details = {
            1: f"size={error_val} (min={expected_val})",  # PACKET_TOO_SMALL
            2: f"ttl={error_val} (expected={expected_val})",  # INVALID_TTL
            3: f"version={error_val} (expected={expected_val})",  # BAD_VERSION
            4: f"detect_mult={error_val} (expected>={expected_val})",  # ZERO_DETECT_MULT
            5: f"pkt_len={error_val}, actual_len={expected_val}",  # INVALID_LENGTH
            6: f"M_bit={error_val} (expected={expected_val})",  # MULTIPOINT_SET
            7: f"my_discr={error_val} (expected!={expected_val})",  # ZERO_DISCRIMINATOR
            8: f"pkt_vrf={error_val}, session_vrf={expected_val}",  # WRONG_VRF
        }
        return details.get(error_code, f"value={error_val}, expected={expected_val}")

    expected_val = event.get("expected_value", 0)

    field_parsers = {
        "error_code": bfd_packet_validation_error2str,
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "error_value": lambda x: format_error_detail(error_code, x, expected_val),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_auth_event(event):
    """Parse BFD authentication events"""
    family = event.get("family", 0)
    field_parsers = {
        "is_success": lambda x: "SUCCESS" if x else "FAILURE",
        "auth_type": bfd_auth_type2str,
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_session_enable_event(event):
    """Parse BFD session enable/disable events"""
    family = event.get("family")
    field_parsers = {
        "is_enable": lambda x: "ENABLE" if x else "DISABLE",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family),
        "peer_addr": lambda x: print_bfd_addr(x, family),
        "state": bfd_state2str,
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_remote_discriminator_change(event):
    """Parse BFD remote discriminator change events"""
    family = event.get("family", 0)
    field_parsers = {
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_control_notify(event):
    """Parse BFD control notification events"""
    family = event.get("family", 0)
    field_parsers = {
        "notify_state": bfd_state2str,
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "mhop": lambda x: "multihop" if x else "singlehop",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_session_lifecycle(event):
    """Parse BFD session lifecycle (create/delete) events"""
    family = event.get("family")
    field_parsers = {
        "is_create": lambda x: "CREATE" if x else "DELETE",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "mhop": lambda x: "multihop" if x else "singlehop",
        "local_addr": lambda x: print_bfd_addr(x, family),
        "peer_addr": lambda x: print_bfd_addr(x, family),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_packet_session_not_found(event):
    """Parse BFD packet session not found events"""
    family = event.get("family", 0)
    field_parsers = {
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_packet_remote_discr_zero(event):
    """Parse BFD packet remote discriminator zero events"""
    family = event.get("family", 0)
    field_parsers = {
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "session_state": bfd_state2str,
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_packet_ttl_exceeded(event):
    """Parse BFD packet TTL exceeded events (multihop)"""
    family = event.get("family", 0)
    field_parsers = {
        "mhop": lambda x: "multihop" if x else "singlehop",
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_echo_packet_error(event):
    """Parse BFD echo packet error events"""
    family = event.get("family", 0)
    field_parsers = {
        "error_type": lambda x: {1: "PACKET_TOO_SMALL", 2: "ZERO_DISCRIMINATOR"}.get(
            x, f"UNKNOWN_ERROR_{x}"
        ),
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_echo_mode_change(event):
    """Parse BFD echo mode change events"""
    field_parsers = {"echo_enabled": lambda x: "ENABLED" if x else "DISABLED"}
    parse_event(event, field_parsers)


def parse_frr_bfd_control_client_event(event):
    """Parse BFD control client connect/disconnect events"""
    field_parsers = {"is_connect": lambda x: "CONNECT" if x else "DISCONNECT"}
    parse_event(event, field_parsers)


def parse_frr_bfd_dplane_session_update(event):
    """Parse BFD data plane session update events"""
    field_parsers = {"is_add": lambda x: "ADD" if x else "DELETE"}
    parse_event(event, field_parsers)


def parse_frr_bfd_dplane_echo(event):
    """Parse BFD data plane echo request/reply events"""
    field_parsers = {"is_request": lambda x: "REQUEST" if x else "REPLY"}
    parse_event(event, field_parsers)


def parse_frr_bfd_zebra_interface_event(event):
    """Parse BFD zebra interface events"""
    field_parsers = {
        "action": lambda x: {1: "ADD", 2: "DELETE", 3: "UP", 4: "DOWN"}.get(
            x, f"UNKNOWN_ACTION_{x}"
        )
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_zebra_address_event(event):
    """Parse BFD zebra address events"""
    family = event.get("family", 0)
    field_parsers = {
        "action": lambda x: {1: "ADD", 2: "DELETE"}.get(x, f"UNKNOWN_ACTION_{x}"),
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_control_protocol_error(event):
    """Parse BFD control protocol error events"""
    field_parsers = {
        "error_type": lambda x: {
            1: "SMALL_MESSAGE",
            2: "INVALID_LENGTH",
            3: "BAD_VERSION",
            4: "UNHANDLED_MESSAGE",
        }.get(x, f"UNKNOWN_ERROR_{x}")
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_ptm_session_event(event):
    """Parse BFD PTM session events"""
    family = event.get("family", 0)
    field_parsers = {
        "action": lambda x: {1: "ADD", 2: "DELETE"}.get(x, f"UNKNOWN_ACTION_{x}"),
        "diag": lambda x: {
            0: "No Diagnostic",
            1: "Control Detection Time Expired",
            2: "Echo Function Failed",
            3: "Neighbor Signaled Session Down",
            4: "Forwarding Plane Reset",
            5: "Path Down",
            6: "Concatenated Path Down",
            7: "Administratively Down",
            8: "Reverse Concatenated Path Down",
        }.get(x, f"Unknown Diag {x}"),
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family),
        "peer_addr": lambda x: print_bfd_addr(x, family),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_ptm_client_event(event):
    """Parse BFD PTM client events"""
    field_parsers = {
        "action": lambda x: {1: "REGISTER", 2: "DEREGISTER"}.get(
            x, f"UNKNOWN_ACTION_{x}"
        )
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_ptm_error(event):
    """Parse BFD PTM error events"""
    field_parsers = {
        "error_type": lambda x: {
            1: "IFNAME_TOO_BIG",
            2: "VRF_ID_NOT_FOUND",
            3: "CLIENT_REGISTER_FAILED",
            4: "CLIENT_DEREGISTER_FAILED",
            5: "REPLAY_CMD_NOT_FOUND",
            6: "SESSION_CREATE_FAILED",
            7: "SESSION_NOT_FOUND",
            8: "CLIENT_NOT_FOUND",
            9: "INVALID_MSG_TYPE",
        }.get(x, f"UNKNOWN_ERROR_{x}")
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_ptm_config_refcount_error(event):
    """Parse BFD PTM config refcount error - CLI session has refcount=0"""
    family = event.get("family", 0)
    field_parsers = {
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family),
        "peer_addr": lambda x: print_bfd_addr(x, family),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_packet_send_error(event):
    """Parse BFD packet send error events"""
    family = event.get("family", 0)
    field_parsers = {
        "error_type": lambda x: {1: "SEND_FAILURE", 2: "PARTIAL_SEND"}.get(
            x, f"UNKNOWN_ERROR_{x}"
        ),
        "family": lambda x: "IPv4"
        if x == socket.AF_INET
        else "IPv6"
        if x == socket.AF_INET6
        else f"AF_{x}",
        "local_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "peer_addr": lambda x: print_bfd_addr(x, family) if family != 0 else "N/A",
        "mhop": lambda x: "multihop" if x else "singlehop",
        "errno_val": lambda x: f"{x} ({os.strerror(x)})" if x > 0 else str(x),
    }
    parse_event(event, field_parsers)


def parse_frr_bfd_stats_error(event):
    """Parse BFD statistics error events"""
    field_parsers = {
        "error_type": lambda x: {1: "COUNTERS_UPDATE_FAILED"}.get(
            x, f"UNKNOWN_ERROR_{x}"
        ),
        "error_code": lambda x: f"{x} ({os.strerror(x)})" if x > 0 else str(x),
    }
    parse_event(event, field_parsers)


############################ BFD parsers - end #################################


############################ evpn parsers - start #############################
def parse_frr_bgp_evpn_mac_ip_zsend(event):
    """
    bgp evpn mac-ip parser; raw format -
    ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
            sizeof(struct ethaddr))
    ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
            sizeof(struct ipaddr))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {
        "ip": print_ip_addr,
        "mac": print_mac,
        "esi": print_esi,
        "vtep": print_ip_addr,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_bum_vtep_zsend(event):
    """
    bgp evpn bum-vtep parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep,
            pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)

    """
    field_parsers = {"vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_nh_rmac_send(event):
    """
    bgp evpn nh-rmac parser; raw format -
    ctf_array(unsigned char, rmac, &nh->rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"rmac": print_mac}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_add_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    """
    field_parsers = {"esi": print_esi, "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_del_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_es_evi_vtep_add(event):
    """
    bgp evpn remote ead evi remote vtep add; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_es_evi_vtep_del(event):
    """
    bgp evpn remote ead evi remote vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd(event):
    """
    bgp evpn local ead evi vtep; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del(event):
    """
    bgp evpn local ead evi vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_vni_add_zrecv(event):
    """
    bgp evpn local-vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_integer_network_hex(unsigned int, mc_grp, mc_grp.s_addr)
    """
    field_parsers = {"vtep": print_ip_addr,
                     "mc_grp": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_l3vni_add_zrecv(event):
    """
    bgp evpn local-l3vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, svi_rmac, svi_rmac, sizeof(struct ethaddr))
    ctf_array(unsigned char, vrr_rmac, vrr_rmac, sizeof(struct ethaddr))
    """
    field_parsers = {
        "vtep": print_ip_addr,
        "svi_rmac": print_mac,
        "vrr_rmac": print_mac,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_macip_add_zrecv(event):
    """
    bgp evpn local-mac-ip parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_macip_del_zrecv(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_advertise_type5(event):
    """
    local originated type-5 route
    """
    field_parsers = {
        "ip": print_ip_addr,
        "rmac": print_mac,
        "vtep": print_ip_addr,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_withdraw_type5(event):
    """
    local originated type-5 route withdraw
    """
    field_parsers = {"ip": print_ip_addr}

    parse_event(event, field_parsers)


############################ evpn parsers - end *#############################


def main():
    """
    FRR lttng trace output parser; babel trace plugin
    """
    event_parsers = {"frr_bgp:evpn_mac_ip_zsend":
                     parse_frr_bgp_evpn_mac_ip_zsend,
                     "frr_bgp:evpn_bum_vtep_zsend":
                     parse_frr_bgp_evpn_bum_vtep_zsend,
                     "frr_bgp:evpn_mh_nh_rmac_zsend":
                     parse_frr_bgp_evpn_mh_nh_rmac_send,
                     "frr_bgp:evpn_mh_local_es_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_del_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv,
                     "frr_bgp:evpn_mh_es_evi_vtep_add":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_add,
                     "frr_bgp:evpn_mh_es_evi_vtep_del":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_del,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_upd":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_del":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del,
                     "frr_bgp:evpn_local_vni_add_zrecv":
                     parse_frr_bgp_evpn_local_vni_add_zrecv,
                     "frr_bgp:evpn_local_l3vni_add_zrecv":
                     parse_frr_bgp_evpn_local_l3vni_add_zrecv,
                     "frr_bgp:evpn_local_macip_add_zrecv":
                     parse_frr_bgp_evpn_local_macip_add_zrecv,
                     "frr_bgp:evpn_local_macip_del_zrecv":
                     parse_frr_bgp_evpn_local_macip_del_zrecv,
                     "frr_bgp:evpn_advertise_type5":
                     parse_frr_bgp_evpn_advertise_type5,
                     "frr_bgp:evpn_withdraw_type5":
                     parse_frr_bgp_evpn_withdraw_type5,
                     "frr_bfd:state_change": parse_frr_bfd_state_change,
                     "frr_bfd:vrf_lifecycle": parse_frr_bfd_vrf_lifecycle,
                     "frr_bfd:dplane_init_error": parse_frr_bfd_dplane_init_error,
                     "frr_bfd:packet_validation_error": parse_frr_bfd_packet_validation_error,
                     "frr_bfd:auth_event": parse_frr_bfd_auth_event,
                     "frr_bfd:session_enable_event": parse_frr_bfd_session_enable_event,
                     "frr_bfd:control_notify": parse_frr_bfd_control_notify,
                     "frr_bfd:remote_discriminator_change": parse_frr_bfd_remote_discriminator_change,
                     "frr_bfd:session_lifecycle": parse_frr_bfd_session_lifecycle,
                     "frr_bfd:packet_session_not_found": parse_frr_bfd_packet_session_not_found,
                     "frr_bfd:packet_remote_discr_zero": parse_frr_bfd_packet_remote_discr_zero,
                     "frr_bfd:packet_ttl_exceeded": parse_frr_bfd_packet_ttl_exceeded,
                     "frr_bfd:echo_packet_error": parse_frr_bfd_echo_packet_error,
                     "frr_bfd:echo_mode_change": parse_frr_bfd_echo_mode_change,
                     "frr_bfd:control_client_event": parse_frr_bfd_control_client_event,
                     "frr_bfd:dplane_session_update": parse_frr_bfd_dplane_session_update,
                     "frr_bfd:dplane_echo": parse_frr_bfd_dplane_echo,
                     "frr_bfd:zebra_interface_event": parse_frr_bfd_zebra_interface_event,
                     "frr_bfd:zebra_address_event": parse_frr_bfd_zebra_address_event,
                     "frr_bfd:control_protocol_error": parse_frr_bfd_control_protocol_error,
                     "frr_bfd:ptm_session_event": parse_frr_bfd_ptm_session_event,
                     "frr_bfd:ptm_client_event": parse_frr_bfd_ptm_client_event,
                     "frr_bfd:ptm_error": parse_frr_bfd_ptm_error,
                     "frr_bfd:ptm_config_refcount_error": parse_frr_bfd_ptm_config_refcount_error,
                     "frr_bfd:packet_send_error": parse_frr_bfd_packet_send_error,
                     "frr_bfd:stats_error": parse_frr_bfd_stats_error,
                     }

    # get the trace path from the first command line argument
    trace_path = sys.argv[1]

    # grab events
    trace_collection = babeltrace.TraceCollection()
    trace_collection.add_traces_recursive(trace_path, "ctf")

    for event in trace_collection.events:
        if event.name in event_parsers:
            event_parser = event_parsers.get(event.name)
            event_parser(event)
        else:
            parse_event(event, {})


if __name__ == "__main__":
    main()
