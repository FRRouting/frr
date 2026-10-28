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
import ipaddress
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


def decode_babel(payload):
    if len(payload) < 4 or payload[:2] != b"\x2a\x02":
        return
    length = int.from_bytes(payload[2:4], "big")
    if len(payload) < 4 + length:
        raise ValueError("truncated Babel packet")
    body = payload[4 : 4 + length]
    router_id = None
    previous = {1: None, 2: None}
    offset = 0
    while offset < len(body):
        kind = body[offset]
        if kind == 0:
            offset += 1
            continue
        if offset + 2 > len(body):
            raise ValueError("truncated TLV header")
        size = body[offset + 1]
        tlv = body[offset + 2 : offset + 2 + size]
        if len(tlv) != size:
            raise ValueError("truncated TLV body")
        offset += size + 2
        if kind == 6 and size >= 10:
            router_id = tlv[2:10].hex()
        elif kind == 8 and size >= 10:
            ae, flags, plen, omitted = tlv[:4]
            width = {1: 4, 2: 16}.get(ae)
            if width is None:
                yield {"kind": "update", "ae": ae, "raw": tlv.hex()}
                continue
            nbytes = (plen + 7) // 8
            if nbytes > width or omitted > nbytes or len(tlv) < 10 + nbytes - omitted:
                raise ValueError("invalid compressed prefix")
            if omitted and previous[ae] is None:
                raise ValueError("missing prefix context")
            raw = (previous[ae][:omitted] if omitted else b"") + tlv[
                10 : 10 + nbytes - omitted
            ]
            raw += b"\0" * (width - len(raw))
            if flags & 0x80:
                previous[ae] = raw
            if flags & 0x40:
                router_id = ((b"\0" * 4 + raw) if ae == 1 else raw[8:]).hex()
            prefix = str(
                ipaddress.ip_network((ipaddress.ip_address(raw), plen), strict=False)
            )
            yield {
                "kind": "update",
                "prefix": prefix,
                "ae": ae,
                "plen": plen,
                "omitted": omitted,
                "flags": flags,
                "router_id": router_id,
                "interval": int.from_bytes(tlv[4:6], "big"),
                "seqno": int.from_bytes(tlv[6:8], "big"),
                "metric": int.from_bytes(tlv[8:10], "big"),
            }
        elif kind == 10 and size >= 14:
            ae, plen = tlv[:2]
            width = {1: 4, 2: 16}.get(ae)
            if width is None:
                continue
            nbytes = (plen + 7) // 8
            if nbytes > width or len(tlv) < 14 + nbytes:
                raise ValueError("invalid request prefix")
            raw = tlv[14 : 14 + nbytes] + b"\0" * (width - nbytes)
            prefix = str(
                ipaddress.ip_network((ipaddress.ip_address(raw), plen), strict=False)
            )
            yield {
                "kind": "mhreq",
                "prefix": prefix,
                "ae": ae,
                "plen": plen,
                "router_id": tlv[6:14].hex(),
                "seqno": int.from_bytes(tlv[2:4], "big"),
                "hop": tlv[4],
            }


def parse_babel_update(pkt, prefix):
    "Return (seqno, metric) of the Update for prefix, or None."
    if not pkt.haslayer(IPv6) or not pkt.haslayer(UDP):
        return None
    for record in decode_babel(bytes(pkt[UDP].payload)):
        if record["kind"] == "update" and record.get("prefix") == prefix + "/32":
            return record["seqno"], record["metric"]
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
