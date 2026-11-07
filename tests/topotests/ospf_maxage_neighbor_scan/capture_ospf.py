#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# capture_ospf.py
#
# Copyright (c) 2026 ATCorp
#
"""Sniff packets to a pcap until SIGINT/SIGTERM.

Used by test_ospf_maxage_neighbor_scan.py so the test does not depend on
tcpdump, which is missing in some images and exits when the interface
goes down.  Alongside the pcap, writes a JSON sidecar with the parsed
OSPF events so the test process does not need to re-read the pcap.
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import time

from scapy.all import AsyncSniffer, conf, wrpcap

conf.verb = 0

_stop = False


def _request_stop(signum, frame):
    global _stop
    _stop = True


def packet_summary(packet):
    if not packet.haslayer("IP"):
        return None
    raw = bytes(packet["IP"].payload)
    if len(raw) < 24 or raw[0] != 2:
        return None
    declared = struct.unpack("!H", raw[2:4])[0]
    if declared < 24 or declared > len(raw):
        return None
    raw = raw[:declared]
    event = {
        "src": packet["IP"].src,
        "dst": packet["IP"].dst,
        "type": raw[1],
    }
    if raw[1] == 4 and declared >= 28:
        count = struct.unpack("!I", raw[24:28])[0]
        offset = 28
        lsas = []
        for _ in range(count):
            if offset + 20 > declared:
                break
            length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
            if length < 20 or offset + length > declared:
                break
            lsas.append(
                {
                    "type": raw[offset + 3],
                    "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                    "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    "age": struct.unpack("!H", raw[offset : offset + 2])[0],
                }
            )
            offset += length
        event["lsas"] = lsas
    elif raw[1] == 5:
        headers = []
        for offset in range(24, declared - 19, 20):
            headers.append(
                {
                    "type": raw[offset + 3],
                    "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                    "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    "age": struct.unpack("!H", raw[offset : offset + 2])[0],
                }
            )
        event["ack_headers"] = headers
    return event


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
    events = []
    for packet in pkts:
        event = packet_summary(packet)
        if event is not None:
            events.append(event)
    with open(args.pcap + ".json.tmp", "w") as fp:
        json.dump(events, fp, indent=1, sort_keys=True)
    os.replace(args.pcap + ".json.tmp", args.pcap + ".json")
    # Make the files visible on shared rundir mounts before we exit.
    for path in (args.pcap, args.pcap + ".json"):
        try:
            os.fsync(os.open(path, os.O_RDONLY))
        except OSError:
            pass


if __name__ == "__main__":
    main()
