#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# mcast-tx.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#

import argparse
import logging
import socket
import struct
import time
import sys

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s %(levelname)5s: %(message)s"
)

# Color the errors and warnings in red
logging.addLevelName(
    logging.ERROR, "\033[91m  %s\033[0m" % logging.getLevelName(logging.ERROR)
)
logging.addLevelName(
    logging.WARNING, "\033[91m%s\033[0m" % logging.getLevelName(logging.WARNING)
)
log = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description="Multicast packet generator")
parser.add_argument("group", help="Multicast IP")
parser.add_argument("ifname", help="Interface name")
parser.add_argument("--port", type=int, help="UDP port number", default=1000)
parser.add_argument("--ttl", type=int, help="time-to-live", default=20)
parser.add_argument("--count", type=int, help="Packets to send", default=1)
parser.add_argument("--interval", type=int, help="ms between packets", default=100)
args = parser.parse_args()

# Create the datagram socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# IN.SO_BINDTODEVICE is not defined in some releases of python but it is 25
# https://github.com/sivel/bonding/issues/10
#
# Bind our socket to ifname
#
# Note ugly python version incompatibility
#
if sys.version_info[0] > 2:
    sock.setsockopt(
        socket.SOL_SOCKET,
        25,
        struct.pack("%ds" % len(args.ifname), args.ifname.encode("utf-8")),
    )
else:
    sock.setsockopt(
        socket.SOL_SOCKET, 25, struct.pack("%ds" % len(args.ifname), args.ifname)
    )

# We need to make sure our sendto() finishes before we close the socket
sock.setblocking(1)

# Set the time-to-live
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", args.ttl))

ms = args.interval / 1000.0

# Send data to the multicast group
for x in range(args.count):
    log.info(
        "TX multicast UDP packet to %s:%d on %s" % (args.group, args.port, args.ifname)
    )

    #
    # Note ugly python version incompatibility
    #
    if sys.version_info[0] > 2:
        sent = sock.sendto(b"foobar %d" % x, (args.group, args.port))
    else:
        sent = sock.sendto("foobar %d" % x, (args.group, args.port))

    if args.count > 1 and ms:
        time.sleep(ms)

sock.close()
