#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: MIT
#
# July 29 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C. ("LabN")
#
import argparse
import logging
import re
import sys

from scapy.all import conf, srp

conf.verb = 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface to send packet on.")
    parser.add_argument("-I", "--imports", help="scapy symbols to import")
    parser.add_argument(
        "-t", "--timeout", type=float, default=2.0, help="timeout for reply receipts"
    )
    parser.add_argument("pktdef", help="scapy packet definition to send")
    args = parser.parse_args()

    if args.imports:
        i = args.imports.replace("\n", "").strip()
        if not re.match("[a-zA-Z0-9_ \t,]", i):
            logging.critical('Invalid imports specified: "%s"', i)
            sys.exit(1)
        exec("from scapy.all import " + i, globals(), locals())

    ans, unans = srp(eval(args.pktdef), iface=args.interface, timeout=args.timeout)
    if not ans:
        sys.exit(2)
    for pkt in ans:
        print(pkt.answer.show(dump=True))


if __name__ == "__main__":
    main()
