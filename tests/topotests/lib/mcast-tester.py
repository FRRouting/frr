#!/usr/bin/env python3
#
# Copyright (C) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Subscribe to a multicast group so that the kernel sends an IGMP JOIN
for the multicast group we subscribed to.
"""

import argparse
import json
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
    interfaces = json.loads(subprocess.check_output("ip -j link show", shell=True))

    for interface in interfaces:
        if interface["ifname"] == name:
            return interface["ifindex"]

    return None


def multicast_join(sock, ifindex, group, port):
    "Joins a multicast group."
    mreq = struct.pack(
        "=4sLL", socket.inet_aton(args.group), socket.INADDR_ANY, ifindex
    )

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((group, port))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


#
# Main code.
#
parser = argparse.ArgumentParser(description="Multicast RX utility")
parser.add_argument("group", help="Multicast IP")
parser.add_argument("interface", help="Interface name")
parser.add_argument("--socket", help="Point to topotest UNIX socket")
parser.add_argument(
    "--send", help="Transmit instead of join with interval", type=float, default=0
)
args = parser.parse_args()

ttl = 16
port = 1000

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

msock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if args.send > 0:
    # Prepare multicast bit in that interface.
    msock.setsockopt(
        socket.SOL_SOCKET,
        25,
        struct.pack("%ds" % len(args.interface), args.interface.encode("utf-8")),
    )
    # Set packets TTL.
    msock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", ttl))
    # Block to ensure packet send.
    msock.setblocking(True)
else:
    multicast_join(msock, ifindex, args.group, port)


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
        msock.sendto(b"test %d" % counter, (args.group, port))
        counter += 1
        time.sleep(args.send)

msock.close()
sys.exit(0)
