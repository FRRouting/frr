#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 29 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C. ("LabN")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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
