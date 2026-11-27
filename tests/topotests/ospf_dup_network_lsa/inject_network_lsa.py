#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_network_lsa.py
#
"""Send crafted OSPF LS Updates on a shared segment while sniffing OSPF.

Used by test_ospf_dup_network_lsa.py to inject duplicate network-LSA
copies (same Link State ID as the real DR's network-LSA, different
Advertising Router) and to record the segment's OSPF traffic on a pcap.
Runs inside the r2 namespace; the pcap and the JSON result land on the
shared topotest rundir.
"""

import json
import os
import socket
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, IP, Raw, conf, sendp, wrpcap

conf.verb = 0


def parse_lsas(packets, injected, epoch):
    events = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        raw = bytes(packet[IP].payload)
        if len(raw) < 28 or raw[0] != 2 or raw[1] != 4:
            continue
        count = struct.unpack("!I", raw[24:28])[0]
        offset = 28
        for _ in range(count):
            if offset + 20 > len(raw):
                break
            length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
            if length < 20 or offset + length > len(raw):
                break
            events.append(
                {
                    "time": round(float(packet.time) - epoch, 6),
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "outer_router_id": socket.inet_ntoa(raw[4:8]),
                    "age": struct.unpack("!H", raw[offset : offset + 2])[0],
                    "type": raw[offset + 3],
                    "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                    "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    "seq": struct.unpack("!I", raw[offset + 12 : offset + 16])[0],
                    "length": length,
                    "injected": raw.hex() in injected,
                }
            )
            offset += length
    return events


def run(cfg):
    injected = {item["ospf_hex"] for item in cfg["packets"]}
    sniffer = AsyncSniffer(iface=cfg["iface"], filter="ip proto 89", store=True)
    sniffer.start()
    time.sleep(0.35)
    epoch = time.time()
    sent = []
    try:
        for index, item in enumerate(cfg["packets"]):
            if index:
                time.sleep(cfg["spacing"])
            frame = (
                Ether(src=cfg["src_mac"], dst=item["dst_mac"])
                / IP(src=item["src_ip"], dst=item["dst_ip"], proto=89, ttl=1)
                / Raw(bytes.fromhex(item["ospf_hex"]))
            )
            sendp(frame, iface=cfg["iface"], verbose=0)
            sent.append({"time": round(time.time() - epoch, 6), "index": index})
        time.sleep(cfg["tail"])
    finally:
        packets = list(sniffer.stop())
    wrpcap(cfg["pcap_path"], packets)
    events = parse_lsas(packets, injected, epoch)
    result = {
        "iface": cfg["iface"],
        "sent": sent,
        "injected_events": [event for event in events if event["injected"]],
        "lsa_events": events,
        "captured_ospf_packets": len(packets),
        "pcap_path": cfg["pcap_path"],
    }
    with open(cfg["result_path"] + ".tmp", "w") as fp:
        json.dump(result, fp, indent=2, sort_keys=True)
    os.replace(cfg["result_path"] + ".tmp", cfg["result_path"])
    print(
        "INJECT_SENT=%d INJECTED_SEEN=%d PCAP=%s"
        % (len(sent), len(result["injected_events"]), cfg["pcap_path"])
    )


run(json.load(open(sys.argv[1])))
