#!/usr/bin/env python3
#
# mcast-rx.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND Cumulus Networks DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#
"""
Subscribe to a multicast group so that the kernel sends an IGMP JOIN
for the multicast group we subscribed to.
"""

import argparse
import logging
import re
import os
import socket
import subprocess
import struct
import sys
import time


def ifname_to_ifindex(ifname):
    output = subprocess.check_output(
        "ip link show %s" % ifname, shell=True, universal_newlines=True
    )
    first_line = output.split("\n")[0]
    re_index = re.search("^(\d+):", first_line)

    if re_index:
        return int(re_index.group(1))

    log.error("Could not parse the ifindex for %s out of\n%s" % (ifname, first_line))
    return None


# Thou shalt be root
if os.geteuid() != 0:
    sys.stderr.write("ERROR: You must have root privileges\n")
    sys.exit(1)


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

parser = argparse.ArgumentParser(description="Multicast RX utility")

parser.add_argument("group", help="Multicast IP")
parser.add_argument("ifname", help="Interface name")
parser.add_argument("--port", help="UDP port", default=1000)
parser.add_argument("--sleep", help="Time to sleep before we stop waiting", default=5)
args = parser.parse_args()

# Create the datagram socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((args.group, args.port))

newpid = os.fork()

if newpid == 0:
    ifindex = ifname_to_ifindex(args.ifname)
    mreq = struct.pack(
        "=4sLL", socket.inet_aton(args.group), socket.INADDR_ANY, ifindex
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    time.sleep(float(args.sleep))
    sock.close()
