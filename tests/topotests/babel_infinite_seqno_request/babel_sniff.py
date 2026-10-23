#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# babel_sniff.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Sniff Babel (UDP 6696) packets for test_babel_infinite_seqno_request.py.

Modes:
  canary  sniff for --timeout seconds and print the seqno/metric of the
          first Update for the given IPv4 prefix from the given source,
          as a python dict (empty dict when nothing matched)
  record  sniff until SIGTERM, then write all packets to a pcap file
          (with a ready-file handshake so the caller knows sniffing is
          active)
"""

import argparse
import os
import signal
import sys
import time

from scapy.all import AsyncSniffer, IPv6, UDP, conf, sniff, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def parse_babel_update(pkt, prefix):
    "Return (seqno, metric) of the Update for prefix, or None."
    if not pkt.haslayer(IPv6) or not pkt.haslayer(UDP):
        return None
    load = bytes(pkt[UDP].payload)
    if len(load) < 4 or load[0] != 42 or load[1] != 2:
        return None
    want = bytes(int(x) for x in prefix.split("."))
    body, i = load[4:], 0
    while i + 2 <= len(body):
        t, ln = body[i], body[i + 1]
        if t == 0:
            i += 1
            continue
        tlv = body[i + 2:i + 2 + ln]
        if t == 8 and len(tlv) >= 14 and tlv[0] == 1 and tlv[2] == 32 and tlv[3] == 0:
            if tlv[10:14] == want:
                return int.from_bytes(tlv[6:8], "big"), int.from_bytes(tlv[8:10], "big")
        i += 2 + ln
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["canary", "record"], required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--src", default="")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--pcap", default="")
    parser.add_argument("--ready-file", default="")
    args = parser.parse_args()

    if args.mode == "canary":
        pkts = sniff(iface=args.iface, filter="udp port 6696", timeout=args.timeout)
        found = {}
        for pkt in pkts:
            if pkt[IPv6].src != args.src or pkt[IPv6].dst != "ff02::1:6":
                continue
            res = parse_babel_update(pkt, args.prefix)
            if res:
                found = {"seqno": res[0], "metric": res[1]}
                break
        print(found)
        return

    # record mode
    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    sniffer = AsyncSniffer(iface=args.iface, filter="udp port 6696", store=True)
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
    try:
        os.fsync(os.open(args.pcap, os.O_RDONLY))
    except OSError:
        pass


if __name__ == "__main__":
    main()
