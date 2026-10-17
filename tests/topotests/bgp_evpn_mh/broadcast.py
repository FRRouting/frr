#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# broadcast.py
#
# Copyright (c) 2026 VyOS Inc
# Kyrylo Yatsenko
#
"""Send broadcast traffic
"""

import argparse
import sys

from scapy.all import Ether, sendp
import scapy.layers.l2

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--proto", required=True)
    args = parser.parse_args()

    pkt = Ether(src="00:00:00:00:00:21", dst="ff:ff:ff:ff:ff:ff", type=int(args.proto, 0))
    for _ in range(5):
        sendp(pkt, iface=args.iface, verbose=False)


if __name__ == "__main__":
    main()
