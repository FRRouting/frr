#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

#
# Copyright 2018 Jorge Borreicho
# Copyright 2026 6WIND S.A.

"""
    BGP prefix injection tool
"""

import socket
import sys
import time
from datetime import datetime
import struct
import threading
import json
import os
import re
import signal
import errno


AFI_IPV4 = 1
SAFI_UNICAST = 1

AFI_L2VPN = 25
SAFI_EVPN = 70

BGP_MARKER = b"\xff" * 16

saved_pid = False
current_socket = None
global pid_file


class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(timestamp + " - " + message)


def keepalive_thread(conn, interval, disconnected):
    # Send keepalives until the session is torn down. Event.wait() doubles as the
    # sleep and the stop check: it returns True the moment the session drops, so we
    # exit promptly instead of sleeping a full interval on a dead socket.
    while not disconnected.wait(interval):
        try:
            keepalive_bgp(conn)
        except OSError:
            disconnected.set()
            break


def receive_thread(conn, disconnected):
    # Loop until the peer closes the connection (TCP FIN/RST) or an error occurs.
    try:
        while not disconnected.is_set():
            # Receiving from client
            r = conn.recv(1500)
            if not r:
                # recv() returning b"" means the peer sent a FIN: the TCP
                # connection is half-closed. Stop so the main loop can reconnect.
                break
            while True:
                start_ptr = r.find(BGP_MARKER) + 16
                end_ptr = r[16:].find(BGP_MARKER) + 16
                if (
                    start_ptr >= end_ptr
                ):  # a single message was sent in the BGP packet OR it is the last message of the BGP packet
                    decode_bgp(r[start_ptr:])
                    break
                else:  # more messages left to decode
                    decode_bgp(r[start_ptr:end_ptr])
                    r = r[end_ptr:]
    except OSError:
        # e.g. ConnectionResetError on RST, or the socket being closed during teardown
        pass
    finally:
        disconnected.set()


def decode_bgp(msg):
    if len(msg) < 3:
        return
    msg_length, msg_type = struct.unpack("!HB", msg[0:3])
    if msg_type == 4:
        # print(timestamp + " - " + "Received KEEPALIVE") #uncomment to debug
        pass
    elif msg_type == 2:
        log("Received UPDATE")
    elif msg_type == 1:
        version, remote_as, holdtime, i1, i2, i3, i4, opt_length = struct.unpack(
            "!BHHBBBBB", msg[3:13]
        )
        log("Received OPEN")
        print()
        print(
            "--> Version:"
            + str(version)
            + ", Remote AS: "
            + str(remote_as)
            + ", Hold Time:"
            + str(holdtime)
            + ", Remote ID: "
            + str(i1)
            + "."
            + str(i2)
            + "."
            + str(i3)
            + "."
            + str(i4)
        )
        print()
    elif msg_type == 3:
        log("Received NOTIFICATION")


def multiprotocol_capability(afi, safi):
    hexstream = bytes.fromhex("02060104")
    hexstream += struct.pack("!H", afi)
    hexstream += struct.pack("!B", 0)
    hexstream += struct.pack("!B", safi)

    return hexstream


def open_bgp(conn, config):
    # Build the BGP Message
    bgp_version = b"\x04"
    bgp_as = struct.pack("!H", config["my_as"])
    bgp_hold_time = struct.pack("!H", config["hold_time"])

    octet = config["bgp_identifier"].split(".")
    bgp_identifier = struct.pack(
        "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
    )

    bgp_opt = b""
    bgp_opt += multiprotocol_capability(AFI_IPV4, SAFI_UNICAST)
    bgp_opt += multiprotocol_capability(AFI_L2VPN, SAFI_EVPN)

    bgp_opt_lenght = struct.pack("!B", len(bgp_opt))

    bgp_message = (
        bgp_version + bgp_as + bgp_hold_time + bgp_identifier + bgp_opt_lenght + bgp_opt
    )

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = BGP_MARKER
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x01"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)
    return 0


def keepalive_bgp(conn):
    # Build the BGP Header
    total_length = 16 + 2 + 1
    bgp_marker = BGP_MARKER
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x04"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header

    conn.send(bgp_packet)
    return 0


def encode_ipv4_prefix(address, netmask):
    octet = address.split(".")
    length = struct.pack("!B", int(netmask))

    if int(netmask) <= 8:
        prefix = struct.pack("!B", int(octet[0]))
    elif int(netmask) <= 16:
        prefix = struct.pack("!BB", int(octet[0]), int(octet[1]))
    elif int(netmask) <= 24:
        prefix = struct.pack("!BBB", int(octet[0]), int(octet[1]), int(octet[2]))
    else:
        prefix = struct.pack(
            "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
        )

    return length + prefix


def encode_path_attribute_mp_reach_nrli(afi, safi, data, config):
    hexstream = b""
    hexstream += b"\x90"  # flags optional, extended
    hexstream += struct.pack("!B", 14)  # type code MP_REACH_NLRI

    hexstream2 = b""
    hexstream2 += struct.pack("!H", afi)
    hexstream2 += struct.pack("!B", safi)
    if ":" in config["local_address"]:
        hexstream2 += struct.pack("!B", 16)  # nexthop length
        hexstream2 += socket.inet_pton(
            socket.AF_INET6, config["local_address"]
        )  # nexthop IPv6
    else:
        hexstream2 += struct.pack("!B", 4)  # nexthop length
        hexstream2 += socket.inet_aton(config["local_address"])  # nexthop IPv4
    hexstream2 += b"\x00"  # SNPA
    hexstream2 += data

    hexstream += struct.pack("!H", len(hexstream2))  # length
    hexstream += hexstream2

    return hexstream


def encode_path_attribute_prefix_sid(data):
    hexstream = b""
    hexstream += b"\xC0"  # flags optional, transitive, complete
    hexstream += struct.pack("!B", 40)  # type code Prefix-SID
    hexstream += struct.pack("!B", len(data))  # length
    hexstream += data

    return hexstream


def encode_path_attribute(type, value):
    path_attributes = {
        "origin": [b"\x40", 1],
        "as-path": [b"\x40", 2],
        "next-hop": [b"\x40", 3],
        "med": [b"\x80", 4],
        "local_pref": [b"\x40", 5],
        "communities": [b"\xc0", 8],
        "extended-communities": [b"\xc0", 16],
        "pmsi-tunnel": [b"\xc0", 22],
        "prefix-sid": [b"\xc0", 40],
    }

    if type not in path_attributes:
        return b""

    attribute_flag = path_attributes[type][0]
    attribute_type_code = struct.pack("!B", int(path_attributes[type][1]))

    if type == "origin":
        attribute_value = struct.pack("!B", value)
    elif type == "as-path":
        as_number_list = str(value).split(" ")
        attribute_value = struct.pack("!BB", 2, len(as_number_list))
        for as_number in as_number_list:
            attribute_value += struct.pack("!H", int(as_number))
    elif type == "next-hop":
        if "." in value:
            attribute_value = socket.inet_pton(socket.AF_INET, value)
    elif type == "med":
        attribute_value = struct.pack("!I", value)
    elif type == "local_pref":
        attribute_value = struct.pack("!I", value)
    elif type == "communities":
        communities_list = value.split(" ")
        attribute_value = b""
        for community in communities_list:
            aux = community.split(":")
            attribute_value += struct.pack("!HH", int(aux[0]), int(aux[1]))
    elif type == "extended-communities":
        # Ensure it is a list so we can iterate through multiple communities
        ext_comms_list = value if isinstance(value, list) else [value]
        attribute_value = b""

        for ext_comm in ext_comms_list:
            if ext_comm.startswith("target:"):
                # Standard Route Target (Type 0x0002 or 0x0202)
                # Format: target:ASN:Value
                parts = ext_comm.split(":")[1:]
                asn = int(parts[0])
                val = int(parts[1])
                if asn <= 65535:
                    attribute_value += struct.pack("!BBHI", 0x00, 0x02, asn, val)
                else:
                    attribute_value += struct.pack(
                        "!BBHH", 0x02, 0x02, asn >> 16, asn & 0xFFFF, val
                    )

            elif ext_comm.startswith("es-import:"):
                # EVPN ES-Import Route Target (Type 0x06, SubType 0x02)
                # Format: es-import:00:11:22:33:44:55
                mac_str = ext_comm.split("es-import:")[1]
                mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
                attribute_value += struct.pack("!BB", 0x06, 0x02) + mac_bytes

            elif ext_comm.startswith("router-mac:"):
                # EVPN Router's MAC Extended Community (Type 0x06, SubType 0x03)
                # Format: router-mac:00:11:22:33:44:55
                mac_str = ext_comm.split("router-mac:")[1]
                mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
                attribute_value += struct.pack("!BB", 0x06, 0x03) + mac_bytes

            elif ext_comm.startswith("esi-label:"):
                # EVPN ESI Label Extended Community (Type 0x06, SubType 0x01)
                # Format: esi-label:<flags_in_hex>:<label>
                parts = ext_comm.split(":")
                flags = int(parts[1], 16)
                label = int(parts[2])
                attribute_value += struct.pack("!BBBB", 0x06, 0x01, flags, 0x00)
                attribute_value += struct.pack("!I", label)[
                    1:4
                ]  # Extract the 3-byte MPLS label

            elif ext_comm.startswith("encapsulation:"):
                # BGP Tunnel Encapsulation Extended Community (Type 0x03, SubType 0x0c)
                # Format: encapsulation:vxlan OU encapsulation:<id>
                tunnel_str = ext_comm.split(":")[1].lower()

                tunnel_type = 8  # Par défaut VXLAN
                if tunnel_str == "vxlan":
                    tunnel_type = 8
                elif tunnel_str == "mpls":
                    tunnel_type = 10
                elif tunnel_str == "mpls":
                    tunnel_type = 10
                elif tunnel_str.isdigit():
                    tunnel_type = int(tunnel_str)

                # Structure RFC 5512: Type (1 octet), SubType (1 octet), Réservé (4 octets), Tunnel Type (2 octets)
                # Format struct: !BBIH
                attribute_value += struct.pack(
                    "!BBIH", 0x03, 0x0C, 0x00000000, tunnel_type
                )

            elif ext_comm.startswith("router-mac:"):
                # EVPN Router's MAC Extended Community (Type 0x06, SubType 0x03)
                # Format: router-mac:aa:b7:1d:a6:f4:65
                mac_str = ext_comm.split("router-mac:")[1]
                mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
                attribute_value += struct.pack("!BB", 0x06, 0x03) + mac_bytes
            else:
                # Fallback: Treat as a raw hex string for completely custom communities
                attribute_value += bytes.fromhex(ext_comm.replace("0x", ""))
    elif type == "pmsi-tunnel":
        if isinstance(value, dict):
            flags = int(value.get("flags", 0))
            tunnel_type = int(value.get("tunnel_type", 6))

            # Pack 20-bit MPLS label shifted into a 24-bit (3-byte) structure
            label = int(value.get("label", 0)) << 4 or int(value.get("vni", 0))
            label_bytes = struct.pack("!I", label)[1:4]

            tunnel_id = value.get("tunnel_id", "")
            if ":" in tunnel_id:
                tunnel_id_bytes = socket.inet_pton(socket.AF_INET6, tunnel_id)
            elif "." in tunnel_id:
                tunnel_id_bytes = socket.inet_pton(socket.AF_INET, tunnel_id)
            else:
                tunnel_id_bytes = b""

            attribute_value = (
                struct.pack("!BB", flags, tunnel_type) + label_bytes + tunnel_id_bytes
            )
        else:
            # Fallback for raw hex
            attribute_value = bytes.fromhex(value.replace("0x", ""))

    elif type == "prefix-sid":
        if isinstance(value, str):
            # Fallback: Directly pack raw hex strings
            attribute_value = bytes.fromhex(value.replace("0x", ""))
        elif isinstance(value, list):
            attribute_value = b""
            for val in value:
                # Dynamically encode the SRv6 Prefix-SID Attribute (RFC 9252)
                srv6_type = int(val.get("type", 6))  # 5 = L3 Service, 6 = L2 Service
                sid_str = val.get("sid", "::")
                behavior = int(val.get("behavior", 0))

                # Note: Some pre-RFC FRR implementations/drafts used a 1-byte Flags
                # field just before the behavior. We expose it here just in case.
                flags_hex = val.get("flags", "").replace("0x", "")
                flags_bytes = bytes.fromhex(flags_hex) if flags_hex else b""

                sstlv_data = val.get("sid_structure", "")
                if isinstance(sstlv_data, str):
                    sub_sub_tlvs = bytes.fromhex(sstlv_data)
                elif isinstance(sstlv_data, dict):
                    # Pack: Type(2) + Length(2) + LBL(1) + LNL(1) + FL(1) + AL(1) + TL(1) + TO(1)
                    sub_sub_tlvs = struct.pack(
                        "!HHBBBBBB",
                        1,  # SID Structure type
                        6,  # Fixed Length of 6 bytes for the payload
                        int(sstlv_data.get("lbl", 0)),
                        int(sstlv_data.get("lnl", 0)),
                        int(sstlv_data.get("fl", 0)),
                        int(sstlv_data.get("al", 0)),
                        int(sstlv_data.get("tl", 0)),
                        int(sstlv_data.get("to", 0)),
                    )
                else:
                    sub_sub_tlvs = b""

                # Parse the IPv6 string into 16 bytes
                sid_bytes = socket.inet_pton(socket.AF_INET6, sid_str)
                behavior_bytes = struct.pack("!H", behavior)

                # Construct Sub-TLV 1 Payload: Reserved(1) + SID(16) + [Flags(1)] + Behavior(2) + Sub-Sub-TLVs
                sub_tlv_payload = (
                    struct.pack("!B", 0)
                    + sid_bytes
                    + flags_bytes
                    + behavior_bytes
                    + sub_sub_tlvs
                )

                # Construct Sub-TLV: Type(1) + Length(2) + Payload
                sub_tlv = struct.pack("!BH", 1, len(sub_tlv_payload)) + sub_tlv_payload

                # Construct Main TLV Payload: Reserved(1) + Sub-TLVs
                tlv_payload = struct.pack("!B", 0) + sub_tlv

                # Construct Final Attribute: Type(1) + Length(2) + Payload
                attribute_value = attribute_value + (
                    struct.pack("!BH", srv6_type, len(tlv_payload)) + tlv_payload
                )

    attribute_length = struct.pack("!B", len(attribute_value))

    return attribute_flag + attribute_type_code + attribute_length + attribute_value


# Helper to encode Route Distinguisher (RD)
def encode_rd(rd_str):
    if ":" not in rd_str:
        return bytes.fromhex(rd_str) if rd_str else (b"\x00" * 8)
    part1, part2 = rd_str.split(":")
    if "." in part1:  # IPv4 format (Type 1)
        return (
            struct.pack("!H", 1)
            + socket.inet_aton(part1)
            + struct.pack("!H", int(part2))
        )
    else:  # ASN format (Type 0)
        return struct.pack("!HHI", 0, int(part1), int(part2))


def encode_evpn_nrli_tlv(nlri):
    route_type = int(nlri.get("type", 0))
    stream = struct.pack("!B", route_type)

    data = b""

    if route_type == 2:
        # Type 2: MAC/IP Advertisement Route
        rd = encode_rd(nlri.get("rd", "0:0"))

        esi_str = nlri.get("esi", "0").replace(":", "")
        if esi_str == "0":
            esi_str = "0" * 20
        esi = bytes.fromhex(esi_str.zfill(20))

        eth_tag = struct.pack("!I", int(nlri.get("eth_tag", 0)))

        mac_str = nlri.get("mac", "").replace(":", "")
        if mac_str:
            mac = struct.pack("!B", len(mac_str) * 4) + bytes.fromhex(mac_str)
        else:
            mac = b"\x00"

        ip_str = nlri.get("ip", "")
        if ":" in ip_str:  # IPv6
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
            ip = struct.pack("!B", 128) + ip_bytes
        elif "." in ip_str:  # IPv4
            ip_bytes = socket.inet_pton(socket.AF_INET, ip_str)
            ip = struct.pack("!B", 32) + ip_bytes
        else:
            ip = b"\x00"

        if nlri.get("vni1"):
            label1 = int(nlri.get("vni1"))
            label2 = int(nlri.get("vni2", 0))
        elif nlri.get("label1"):
            label1 = int(nlri.get("label1")) << 4
            label2 = int(nlri.get("label2", 0)) << 4
            # apply bottom of stack bit
            if label2:
                label2 = label2 | 1
            else:
                label1 = label1 | 1
        else:
            label1 = 0
            label2 = 0

        label_bytes = struct.pack("!I", label1)[1:4]
        if label2:
            label_bytes = label_bytes + struct.pack("!I", label2)[1:4]

        data = rd + esi + eth_tag + mac + ip + label_bytes

    elif route_type == 3:
        # Type 3: Inclusive Multicast Ethernet Tag Route
        rd = encode_rd(nlri.get("rd", "0:0"))
        eth_tag = struct.pack("!I", int(nlri.get("eth_tag", 0)))

        ip_str = nlri.get("ip", "")
        if ":" in ip_str:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
            ip = struct.pack("!B", 128) + ip_bytes
        elif "." in ip_str:
            ip_bytes = socket.inet_pton(socket.AF_INET, ip_str)
            ip = struct.pack("!B", 32) + ip_bytes
        else:
            ip = b"\x00"

        data = rd + eth_tag + ip

    elif route_type == 5:
        # Type 5: IP Prefix Route (RFC 9136)
        rd = encode_rd(nlri.get("rd", "0:0"))

        esi_str = nlri.get("esi", "0").replace(":", "")
        if esi_str == "0":
            esi_str = "0" * 20
        esi = bytes.fromhex(esi_str.zfill(20))

        eth_tag = struct.pack("!I", int(nlri.get("eth_tag", 0)))

        # Parse the CIDR notation (e.g., "2001:1::/64")
        ip_cidr = nlri.get("ip", "")
        if "/" in ip_cidr:
            ip_str, mask_str = ip_cidr.split("/")
            mask = int(mask_str)
        else:
            ip_str = ip_cidr
            mask = 128 if ":" in ip_str else 32

        if ":" in ip_str:  # IPv6
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
            ip_payload = struct.pack("!B", mask) + ip_bytes
            gw_ip_str = nlri.get("gw_ip", "::")
            gw_ip = socket.inet_pton(socket.AF_INET6, gw_ip_str)
        elif "." in ip_str:  # IPv4
            ip_bytes = socket.inet_pton(socket.AF_INET, ip_str)
            ip_payload = struct.pack("!B", mask) + ip_bytes
            gw_ip_str = nlri.get("gw_ip", "0.0.0.0")
            gw_ip = socket.inet_pton(socket.AF_INET, gw_ip_str)
        else:
            ip_payload = b"\x00"
            gw_ip = b""

        if nlri.get("vni1"):
            label1 = int(nlri.get("vni1"))
            label2 = int(nlri.get("vni2", 0))
        elif nlri.get("label1"):
            label1 = int(nlri.get("label1")) << 4
            label2 = int(nlri.get("label2", 0)) << 4
            # apply bottom of stack bit
            if label2:
                label2 = label2 | 1
            else:
                label1 = label1 | 1
        else:
            label1 = 0
            label2 = 0

        label_bytes = struct.pack("!I", label1)[1:4]
        if label2:
            label_bytes = label_bytes + struct.pack("!I", label2)[1:4]

        data = rd + esi + eth_tag + ip_payload + gw_ip + label_bytes

    stream += struct.pack("!B", len(data))
    stream += data
    return stream


def update_bgp(conn, evpn_prefix, config):
    bgp_withdrawn_routes = b""
    bgp_withdrawn_routes_length = struct.pack("!H", len(bgp_withdrawn_routes))
    bgp_withdrawn_routes = bgp_withdrawn_routes_length + bgp_withdrawn_routes

    # Merge global path attributes with per-prefix path attributes
    merged_attributes = dict(config.get("path_attributes", {}))
    if "path_attributes" in evpn_prefix:
        merged_attributes.update(evpn_prefix["path_attributes"])

    bgp_total_path_attributes = b""

    # encode EVPN MP_REACH NLRI
    data = encode_evpn_nrli_tlv(evpn_prefix["nlri"])
    bgp_total_path_attributes += encode_path_attribute_mp_reach_nrli(
        AFI_L2VPN, SAFI_EVPN, data, config
    )

    # encode all merged attributes natively
    for key in merged_attributes.keys():
        bgp_total_path_attributes += encode_path_attribute(key, merged_attributes[key])

    bgp_total_path_attributes_length = struct.pack("!H", len(bgp_total_path_attributes))
    bgp_total_path_attributes = (
        bgp_total_path_attributes_length + bgp_total_path_attributes
    )

    bgp_new_routes = b""
    bgp_message = bgp_withdrawn_routes + bgp_total_path_attributes + bgp_new_routes

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = BGP_MARKER
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x02"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)

    log("Sent UPDATE")

    return 0


def str2ip(ip_str):
    s_octet = ip_str.split(".")
    ip_addr = struct.pack(
        "!BBBB", int(s_octet[0]), int(s_octet[1]), int(s_octet[2]), int(s_octet[3])
    )
    return ip_addr


def check_pid(pid):
    if pid < 0:  # user input error
        return False
    if pid == 0:  # all processes
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.EPERM:  # a process we were denied access to
            return True
        if err.errno == errno.ESRCH:  # No such process
            return False
        # should never happen
        return False


def savepid():
    global saved_pid
    ownid = os.getpid()

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    mode = ((os.R_OK | os.W_OK) << 6) | (os.R_OK << 3) | os.R_OK

    try:
        fd = os.open(pid_file, flags, mode)
    except OSError:
        try:
            pid = open(pid_file, "r").readline().strip()
            if check_pid(int(pid)):
                sys.stderr.write(
                    "PIDfile already exists and program still running %s\n" % pid_file
                )
                return False
            else:
                # If pid is not running, reopen file without O_EXCL
                fd = os.open(pid_file, flags ^ os.O_EXCL, mode)
        except (OSError, IOError, ValueError):
            sys.stderr.write(
                "issue accessing PID file %s (most likely permission or ownership)\n"
                % pid_file
            )
            return False

    try:
        f = os.fdopen(fd, "w")
        line = "%d\n" % ownid
        f.write(line)
        f.close()
        saved_pid = True
    except IOError:
        sys.stderr.write("Can not create PIDfile %s\n" % pid_file)
        return False
    print("Created PIDfile %s with value %d\n" % (pid_file, ownid))
    return True


def removepid():
    if not saved_pid:
        return
    try:
        os.remove(pid_file)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            pass
        else:
            sys.stderr.write("Can not remove PIDfile %s\n" % pid_file)
            return
    sys.stderr.write("Removed PIDfile %s\n" % pid_file)


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        print("Fork #1 failed: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        print("Fork #2 failed: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, "r")
    so = open(os.devnull, "a+")
    se = open(os.devnull, "a+")

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def term(signal, frame):
    log("^C received, shutting down.\n")
    if current_socket is not None:
        try:
            current_socket.close()
        except OSError:
            pass
    removepid()
    exit()


def run_session(config):
    """
    Open one BGP session, advertise the configured prefixes and block until the
    session drops (peer FIN/RST, keepalive send failure, ...).

    Returns True if a session was established (so the caller should reconnect),
    or False if the initial connection could not be made after all retries.
    """
    global current_socket

    bgp_peer = config["peer_address"]
    bgp_local = config["local_address"]
    bgp_port = config["port"]

    bgp_socket = None
    retry = 30
    while retry:
        retry -= 1
        try:
            af = socket.AF_INET6 if ":" in bgp_peer else socket.AF_INET
            bgp_socket = socket.socket(af, socket.SOCK_STREAM)
            bgp_socket.bind((bgp_local, 0))
            bgp_socket.connect((bgp_peer, bgp_port))
            open_bgp(bgp_socket, config)
            break
        except TimeoutError:
            if bgp_socket is not None:
                bgp_socket.close()
                bgp_socket = None
            if retry == 0:
                log("Error: timeout connecting to the peer.")
                return False
            time.sleep(1)
        except OSError as e:
            if bgp_socket is not None:
                bgp_socket.close()
                bgp_socket = None
            if retry == 0:
                log("Error: cannot connect to the peer: " + str(e))
                return False
            time.sleep(1)

    current_socket = bgp_socket

    # Shared flag: either worker thread sets it when the session goes down, and
    # this function blocks on it until then.
    disconnected = threading.Event()

    receive_worker = threading.Thread(
        target=receive_thread, args=(bgp_socket, disconnected)
    )  # wait for BGP msgs from peer and process them
    receive_worker.setDaemon(True)
    receive_worker.start()

    keepalive_worker = threading.Thread(
        target=keepalive_thread,
        args=(
            bgp_socket,
            (config["hold_time"]) / 3,
            disconnected,
        ),
    )  # send keep alives every hold_time/3 seconds
    keepalive_worker.setDaemon(True)
    keepalive_worker.start()

    # send a first keepalive packet before sending the initial UPDATE packet
    keepalive_bgp(bgp_socket)

    log("BGP is up.")

    time.sleep(3)
    for evpn_prefix in config["evpn_prefixes"]:
        if disconnected.is_set():
            break
        try:
            update_bgp(
                bgp_socket,
                evpn_prefix,
                config,
            )
        except OSError as e:
            log("Error sending UPDATE: " + str(e))
            disconnected.set()
            break

    # Block here until a worker thread reports the session is down.
    disconnected.wait()
    log("Session down.")

    try:
        bgp_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    bgp_socket.close()
    current_socket = None

    # Let the worker threads exit before we spin up fresh ones on reconnect.
    receive_worker.join(timeout=2)
    keepalive_worker.join(timeout=2)

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # daemonize and log to file
        daemonize()
        pid_file = os.path.join(sys.argv[1], "bgp_injector.pid")
        savepid()
        # deal with daemon termination
        signal.signal(signal.SIGTERM, term)
        signal.signal(signal.SIGINT, term)  # CTRL + C

        log_dir = os.path.join(sys.argv[1], "bgp_injector.log")
        f = open(log_dir, "w")
        sys.stdout = Unbuffered(f)
        sys.stderr = Unbuffered(f)

    log("Starting BGP injector ")

    CONFIG_FILENAME = os.path.join(sys.path[0], "bgp_injector.cfg")

    log("Reading config file " + CONFIG_FILENAME)

    input_file = open(CONFIG_FILENAME, "r")

    input = input_file.read()
    # cleanup comments that are not supported by JSON
    json_input = re.sub(r"//.*\n", "", input, flags=re.MULTILINE)

    config = json.loads(json_input)

    # seconds to wait between reconnect attempts (configurable, default 5)
    reconnect_delay = config.get("reconnect_delay", 5)

    log("Starting BGP... (peer: " + str(config["peer_address"]) + ")")

    # Reconnect loop: run a session, and when it drops (TCP FIN/RST, keepalive
    # failure, ...) wait a bit and re-establish it.
    ever_up = False
    while True:
        if run_session(config):
            ever_up = True
            log("Reconnecting in %d seconds..." % reconnect_delay)
        elif not ever_up:
            # Never managed to connect at all: preserve the original
            # "give up and exit" behaviour on first startup.
            break
        else:
            # Transient outage after having been up: keep trying.
            log("Reconnect failed, retrying in %d seconds..." % reconnect_delay)
        time.sleep(reconnect_delay)
