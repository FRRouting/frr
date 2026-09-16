#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# flood_dd.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#
"""Replay the last captured OSPF Database Description packet in a burst.

Used by test_ospf_dd_dup_hang.py to simulate a master that retransmits the
same DD many times.
"""

import argparse
import sys

from scapy.all import conf, sendp
from scapy.contrib.ospf import OSPF_Hdr
from scapy.utils import rdpcap

conf.verb = 0

OSPF_MSG_DB_DESC = 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-rid", default="2.2.2.2")
    parser.add_argument("--count", type=int, default=2000)
    args = parser.parse_args()

    dds = []
    for pkt in rdpcap(args.pcap):
        if not pkt.haslayer(OSPF_Hdr):
            continue
        hdr = pkt[OSPF_Hdr]
        if hdr.type == OSPF_MSG_DB_DESC and str(hdr.src) == args.src_rid:
            dds.append(pkt)

    if not dds:
        sys.stderr.write("no DD packets from router-id %s in %s\n" % (args.src_rid, args.pcap))
        sys.exit(1)

    sendp([dds[-1]] * args.count, iface=args.iface, verbose=False)


if __name__ == "__main__":
    main()
