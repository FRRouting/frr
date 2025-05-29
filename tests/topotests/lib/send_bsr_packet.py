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

    try:
        data = binascii.a2b_hex(packet)
    except binascii.Error:
        print("Invalid packet format. Please provide a hexadecimal-encoded string.")
        sys.exit(1)

    p = Raw(load=data)
    p.show()
    try:
        sendp(p, inter=int(interval), iface=iface, count=int(count))
    except ValueError:
        print("Invalid interval or count value. Please provide integers.")
        sys.exit(1)
    except Exception as error:
        print(f"Error sending packet: {error}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send BSR Raw packet")
    parser.add_argument("packet", help="Packet in raw format")
    parser.add_argument("iface", help="Packet send to this interface")
    parser.add_argument("--interval", help="Interval between packets", default=0)
    parser.add_argument(
        "--count", help="Number of times packet is sent repetitively", default=0
    )
    args = parser.parse_args()

    if not args.packet or not args.iface:
        print("Please provide both a packet and an interface.")
        sys.exit(1)

    send_packet(args.packet, args.iface, args.interval, args.count)
