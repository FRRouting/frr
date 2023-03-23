# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#

import sys
import argparse
from scapy.all import Raw, sendp
import binascii


def send_packet(packet, iface, interval, count):
    """
    Read BSR packet in Raw format and send it to specified interface

    Parameter:
    ---------
    * `packet` : BSR packet in raw format
    * `interface` : Interface from which packet would be send
    * `interval` : Interval between the packets
    * `count` : Number of packets to be sent
    """

    data = binascii.a2b_hex(packet)
    p = Raw(load=data)
    p.show()
    sendp(p, inter=int(interval), iface=iface, count=int(count))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send BSR Raw packet")
    parser.add_argument("packet", help="Packet in raw format")
    parser.add_argument("iface", help="Packet send to this ineterface")
    parser.add_argument("--interval", help="Interval between packets", default=0)
    parser.add_argument(
        "--count", help="Number of times packet is sent repetitively", default=0
    )
    args = parser.parse_args()

    if not args.packet or not args.iface:
        sys.exit(1)

    send_packet(args.packet, args.iface, args.interval, args.count)
