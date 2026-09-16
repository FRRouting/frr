#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# capture_ospf.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#
"""Sniff packets to a pcap until SIGINT/SIGTERM.

Used by test_ospf_dd_dup_hang.py so the test does not depend on tcpdump,
which is missing in some images and exits when the interface goes down.
"""

import argparse
import os
import signal
import sys
import time

from scapy.all import AsyncSniffer, conf, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--filter", default="ip proto 89")
    parser.add_argument("--ready-file", default="")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    sniffer = AsyncSniffer(iface=args.iface, filter=args.filter, store=True)
    try:
        sniffer.start()
    except Exception as exc:
        sys.stderr.write("scapy sniff failed on %s: %s\n" % (args.iface, exc))
        sys.exit(1)

    if args.ready_file:
        with open(args.ready_file, "w") as f:
            f.write("ready\n")

    while not _stop:
        time.sleep(0.1)

    try:
        sniffer.stop()
    except Exception:
        pass

    pkts = list(sniffer.results or [])
    wrpcap(args.pcap, pkts)
    # Make the file visible on shared rundir mounts before we exit.
    try:
        os.fsync(os.open(args.pcap, os.O_RDONLY))
    except OSError:
        pass


if __name__ == "__main__":
    main()
