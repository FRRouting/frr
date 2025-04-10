#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Subscribe to a multicast group so that the kernel sends an IGMP JOIN
for the multicast group we subscribed to.
"""

import argparse
import json
import ipaddress
import os
import socket
import struct
import subprocess
import sys
import time


#
# Functions
#
def interface_name_to_index(name):
    "Gets the interface index using its name. Returns None on failure."
    try:
        interfaces = json.loads(subprocess.check_output("ip -j link show", shell=True))
    except subprocess.CalledProcessError as err:
        print(f"Error executing command: {err}")
        return None
    except json.JSONDecodeError as err:
        print(f"Error decoding JSON: {err}")
        return None

    for interface in interfaces:
        if interface.get("ifname") == name:
            return interface.get("ifindex")

    return None


def interface_index_to_address(index, iptype="inet"):
    "Gets the interface main address using its name. Returns None on failure."
    try:
        interfaces = json.loads(subprocess.check_output("ip -j addr show", shell=True))
    except subprocess.CalledProcessError as err:
        print(f"Error executing command: {err}")
        return None
    except json.JSONDecodeError as err:
        print(f"Error decoding JSON: {err}")
        return None

    for interface in interfaces:
        if interface.get("ifindex") == index:
            break
    else:
        return None

    for address in interface.get("addr_info"):
        if address.get("family") == iptype:
            break
    else:
        return None

    local_address = ipaddress.ip_address(address.get("local"))

    return local_address.packed


def group_source_req(ifindex, group, source):
    "Packs the information into 'struct group_source_req' format."
    mreq = struct.pack("<I", ifindex)
    group_bytes = (
        struct.pack("<IHHI", 0, socket.AF_INET6, 0, 0)
        + group.packed
        + struct.pack("<I", 0)
    )
    group_bytes += struct.pack(f"<{128 - len(group_bytes)}x")

    source_bytes = (
        struct.pack("<IHHI", 0, socket.AF_INET6, 0, 0)
        + source.packed
        + struct.pack("<I", 0)
    )
    source_bytes += struct.pack(f"<{128 - len(source_bytes)}x")

    return mreq + group_bytes + source_bytes + struct.pack("<4x")


def multicast_join(sock, ifindex, group, port, source=None):
    "Joins a multicast group."
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if ip_version == 4:
        if source is None:
            mreq = group.packed + struct.pack("@II", socket.INADDR_ANY, ifindex)
            opt = socket.IP_ADD_MEMBERSHIP
        else:
            source = ipaddress.ip_address(source)
            mreq = group.packed + interface_index_to_address(ifindex) + source.packed
            opt = 39
    else:
        if source is None:
            mreq = group.packed + struct.pack("@I", ifindex)
            opt = socket.IPV6_JOIN_GROUP
        else:
            mreq = group_source_req(ifindex, group, ipaddress.ip_address(source))
            print(mreq)
            opt = 46

    sock.bind((str(group), port))
    sock.setsockopt(ip_proto, opt, mreq)


#
# Main code.
#
parser = argparse.ArgumentParser(description="Multicast RX utility")
parser.add_argument("group", help="Multicast IP")
parser.add_argument("interface", help="Interface name")
parser.add_argument("--port", type=int, default=1000, help="port to send to")
parser.add_argument("--ttl", type=int, default=16, help="TTL/hops for sending packets")
parser.add_argument("--socket", help="Point to topotest UNIX socket")
parser.add_argument("--source", help="Source address for multicast")
parser.add_argument(
    "--send", help="Transmit instead of join with interval", type=float, default=0
)
args = parser.parse_args()

# Get interface index/validate.
ifindex = interface_name_to_index(args.interface)
if ifindex is None:
    sys.stderr.write("Interface {} does not exists\n".format(args.interface))
    sys.exit(1)

# We need root privileges to set up multicast.
if os.geteuid() != 0:
    sys.stderr.write("ERROR: You must have root privileges\n")
    sys.exit(1)

# Wait for topotest to synchronize with us.
if not args.socket:
    toposock = None
else:
    toposock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    while True:
        try:
            toposock.connect(args.socket)
            break
        except ConnectionRefusedError:
            time.sleep(1)
            continue
    # Set topotest socket non blocking so we can multiplex the main loop.
    toposock.setblocking(False)

args.group = ipaddress.ip_address(args.group)
ip_version = args.group.version
ip_family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
ip_proto = socket.IPPROTO_IP if ip_version == 4 else socket.IPPROTO_IPV6

msock = socket.socket(ip_family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
if args.send > 0:
    # Prepare multicast bit in that interface.
    msock.setsockopt(
        socket.SOL_SOCKET,
        25,
        struct.pack("%ds" % len(args.interface), args.interface.encode("utf-8")),
    )

    # Set packets TTL/hops.
    ttlopt = socket.IP_MULTICAST_TTL if ip_version == 4 else socket.IPV6_MULTICAST_HOPS
    if ip_version == 4:
        msock.setsockopt(ip_proto, ttlopt, struct.pack("B", args.ttl))
    else:
        msock.setsockopt(ip_proto, ttlopt, struct.pack("I", args.ttl))

    # Block to ensure packet send.
    msock.setblocking(True)
else:
    multicast_join(msock, ifindex, args.group, args.port, args.source)


def should_exit():
    if not toposock:
        # If we are sending then we have slept
        if not args.send:
            time.sleep(100)
        return False
    else:
        try:
            data = toposock.recv(1)
            if data == b"":
                print(" -> Connection closed")
                return True
        except BlockingIOError:
            return False


counter = 0
while not should_exit():
    if args.send > 0:
        msock.sendto(b"test %d" % counter, (str(args.group), args.port))
        counter += 1
        time.sleep(args.send)

msock.close()
sys.exit(0)
