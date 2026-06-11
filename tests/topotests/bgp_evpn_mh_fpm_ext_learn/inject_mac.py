#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_mac.py
#
# Netlink MAC injection tool for testing EVPN external learn mode.
# Simulates hardware MAC learning by injecting netlink FDB messages with RTPROT_HW.
#
# Copyright (c) 2026 by Cisco Systems, Inc.

"""
Netlink MAC Injection Tool

This tool injects MAC FDB entries via netlink as if they came from hardware.
It's used to test the --kernel-mac-ext-learn feature without requiring kernel patches.

Usage:
    inject_mac.py add <mac> <device> <vlan> [<dst_ip>]
    inject_mac.py del <mac> <device> <vlan>

Example:
    inject_mac.py add 00:11:22:33:44:55 vxlan1000 1000 20.0.0.3
    inject_mac.py del 00:11:22:33:44:55 vxlan1000 1000
"""

import sys
import socket
import struct
import os

# Netlink constants
NETLINK_ROUTE = 0

# RTnetlink message types
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30

# Netlink message flags
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400

# Neighbor flags
NTF_EXT_LEARNED = 0x10
NTF_USE = 0x01
NTF_MASTER = 0x04

# Neighbor states
NUD_REACHABLE = 0x02
NUD_NOARP = 0x40
NUD_PERMANENT = 0x80

# Routing protocols
RTPROT_HW = 193  # Hardware learned (new protocol from our patch)
RTPROT_ZEBRA = 11

# Netlink attributes
NDA_UNSPEC = 0
NDA_DST = 1
NDA_LLADDR = 2
NDA_CACHEINFO = 3
NDA_PROXYARP = 4
NDA_VLAN = 5
NDA_PORT = 6
NDA_VNI = 7
NDA_IFINDEX = 8
NDA_MASTER = 9
NDA_LINK_NETNSID = 10
NDA_SRC_VNI = 11
NDA_PROTOCOL = 12  # Protocol that installed this entry
NDA_NH_ID = 13
NDA_FDB_EXT_ATTRS = 14
NDA_FLAGS_EXT = 15

# FDB extension attributes
NFEA_UNSPEC = 0
NFEA_ACTIVITY_NOTIFY = 1
NFEA_DONT_REFRESH = 2


class NetlinkSocket:
    """Wrapper for netlink socket operations"""

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.sock.bind((os.getpid(), 0))
        self.seq = 0

    def send_message(self, msg_type, flags, data):
        """Send a netlink message"""
        self.seq += 1
        
        # Build netlink header
        nlmsg_len = 16 + len(data)  # header + data
        nlmsg = struct.pack("IHHII", nlmsg_len, msg_type, flags, self.seq, os.getpid())
        nlmsg += data
        
        self.sock.send(nlmsg)
        
        # Wait for ACK if requested
        if flags & NLM_F_ACK:
            response = self.sock.recv(8192)
            # Parse ACK (simplified - just check for error)
            if len(response) >= 20:
                nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("IHHII", response[:16])
                error_code = struct.unpack("i", response[16:20])[0]
                if error_code != 0:
                    return False, error_code
        return True, 0

    def close(self):
        """Close the socket"""
        self.sock.close()


def mac_str_to_bytes(mac_str):
    """Convert MAC address string to bytes"""
    return bytes.fromhex(mac_str.replace(":", ""))


def ip_str_to_bytes(ip_str):
    """Convert IP address string to bytes"""
    return socket.inet_aton(ip_str)


def get_interface_index(ifname):
    """Get interface index by name"""
    try:
        with open(f"/sys/class/net/{ifname}/ifindex", "r") as f:
            return int(f.read().strip())
    except:
        print(f"Error: Interface {ifname} not found", file=sys.stderr)
        return None


def add_netlink_attr(attr_type, attr_data):
    """Build a netlink attribute"""
    attr_len = 4 + len(attr_data)
    # Align to 4 bytes
    padding = (4 - (attr_len % 4)) % 4
    attr = struct.pack("HH", attr_len, attr_type) + attr_data + (b'\x00' * padding)
    return attr


def inject_mac_add(mac, device, vlan, dst_ip=None):
    """
    Inject a MAC add message via netlink with RTPROT_HW.
    
    Args:
        mac: MAC address (string, e.g., "00:11:22:33:44:55")
        device: Network device name (e.g., "vxlan1000")
        vlan: VLAN ID (integer)
        dst_ip: Destination VTEP IP (optional, for remote MACs)
    """
    nl_sock = NetlinkSocket()
    
    # Get interface index
    ifindex = get_interface_index(device)
    if ifindex is None:
        return False
    
    # Build neighbor message (ndmsg)
    # struct ndmsg {
    #     __u8  ndm_family;
    #     __u8  ndm_pad1;
    #     __u16 ndm_pad2;
    #     __s32 ndm_ifindex;
    #     __u16 ndm_state;
    #     __u8  ndm_flags;
    #     __u8  ndm_type;
    # };
    
    ndm_family = socket.AF_BRIDGE
    ndm_ifindex = ifindex
    ndm_state = NUD_REACHABLE | NUD_NOARP
    ndm_flags = NTF_MASTER | NTF_EXT_LEARNED  # Mark as external learned
    ndm_type = 0
    
    ndmsg = struct.pack("BBHiHBB", 
                        ndm_family, 0, 0,  # family, pad1, pad2
                        ndm_ifindex,        # interface index
                        ndm_state,          # state
                        ndm_flags,          # flags (including NTF_EXT_LEARNED)
                        ndm_type)           # type
    
    # Build attributes
    attrs = b''
    
    # NDA_LLADDR: MAC address
    mac_bytes = mac_str_to_bytes(mac)
    attrs += add_netlink_attr(NDA_LLADDR, mac_bytes)
    
    # NDA_VLAN: VLAN ID
    attrs += add_netlink_attr(NDA_VLAN, struct.pack("H", vlan))
    
    # NDA_PROTOCOL: Set to RTPROT_HW to simulate hardware learning
    attrs += add_netlink_attr(NDA_PROTOCOL, struct.pack("B", RTPROT_HW))
    
    # NDA_MASTER: Master interface index (bridge)
    # Try to find the bridge master
    try:
        with open(f"/sys/class/net/{device}/master/ifindex", "r") as f:
            master_idx = int(f.read().strip())
            attrs += add_netlink_attr(NDA_MASTER, struct.pack("i", master_idx))
    except:
        pass  # No master, skip
    
    # NDA_DST: Destination IP for remote MACs (VXLAN)
    if dst_ip:
        ip_bytes = ip_str_to_bytes(dst_ip)
        attrs += add_netlink_attr(NDA_DST, ip_bytes)
    
    # Combine message
    data = ndmsg + attrs
    
    # Send the message
    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    success, error = nl_sock.send_message(RTM_NEWNEIGH, flags, data)
    
    nl_sock.close()
    
    if not success:
        print(f"Error injecting MAC add: error code {error}", file=sys.stderr)
        return False
    
    print(f"Successfully injected MAC add: {mac} on {device} vlan {vlan} (RTPROT_HW)")
    return True


def inject_mac_del(mac, device, vlan):
    """
    Inject a MAC delete message via netlink with RTPROT_HW.
    
    Args:
        mac: MAC address (string)
        device: Network device name
        vlan: VLAN ID
    """
    nl_sock = NetlinkSocket()
    
    # Get interface index
    ifindex = get_interface_index(device)
    if ifindex is None:
        return False
    
    # Build neighbor message
    ndm_family = socket.AF_BRIDGE
    ndm_ifindex = ifindex
    ndm_state = 0
    ndm_flags = NTF_MASTER | NTF_EXT_LEARNED
    ndm_type = 0
    
    ndmsg = struct.pack("BBHiHBB",
                        ndm_family, 0, 0,
                        ndm_ifindex,
                        ndm_state,
                        ndm_flags,
                        ndm_type)
    
    # Build attributes
    attrs = b''
    
    # NDA_LLADDR: MAC address
    mac_bytes = mac_str_to_bytes(mac)
    attrs += add_netlink_attr(NDA_LLADDR, mac_bytes)
    
    # NDA_VLAN: VLAN ID
    attrs += add_netlink_attr(NDA_VLAN, struct.pack("H", vlan))
    
    # NDA_PROTOCOL: RTPROT_HW
    attrs += add_netlink_attr(NDA_PROTOCOL, struct.pack("B", RTPROT_HW))
    
    # Combine message
    data = ndmsg + attrs
    
    # Send the message
    flags = NLM_F_REQUEST | NLM_F_ACK
    success, error = nl_sock.send_message(RTM_DELNEIGH, flags, data)
    
    nl_sock.close()
    
    if not success:
        print(f"Error injecting MAC delete: error code {error}", file=sys.stderr)
        return False
    
    print(f"Successfully injected MAC delete: {mac} on {device} vlan {vlan} (RTPROT_HW)")
    return True


def main():
    """Main entry point"""
    if len(sys.argv) < 5:
        print(__doc__)
        print("\nUsage: inject_mac.py <add|del> <mac> <device> <vlan> [<dst_ip>]", file=sys.stderr)
        sys.exit(1)
    
    action = sys.argv[1]
    mac = sys.argv[2]
    device = sys.argv[3]
    vlan = int(sys.argv[4])
    dst_ip = sys.argv[5] if len(sys.argv) > 5 else None
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script must be run as root", file=sys.stderr)
        sys.exit(1)

    success = False
    
    if action == "add":
        success = inject_mac_add(mac, device, vlan, dst_ip)
    elif action == "del":
        success = inject_mac_del(mac, device, vlan)
    else:
        print(f"Error: Unknown action '{action}'. Use 'add' or 'del'.", file=sys.stderr)
        sys.exit(1)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
