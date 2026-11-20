#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_ospf.py
#
"""Sniff OSPF on an interface while injecting crafted OSPF packets.

Used by test_ospf_adj_reset_damping.py to send non-duplicate DD packets and
LS Requests at r1 and to record the resulting exchange on a pcap.  Runs
inside the r2 namespace; the pcap and the JSON result land on the shared
topotest rundir.
"""

import json
import os
import sys
import time

from scapy.all import AsyncSniffer, Ether, IP, Raw, conf, sendp, wrpcap

conf.verb = 0


def run(cfg):
    sniffer = AsyncSniffer(iface=cfg["iface"], filter="ip proto 89", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    try:
        if not cfg["packets"]:
            time.sleep(cfg["duration"])
        else:
            for index, item in enumerate(cfg["packets"]):
                if index:
                    time.sleep(cfg["spacing"])
                payload = bytes.fromhex(item["ospf_hex"])
                frame = (
                    Ether(src=cfg["src_mac"], dst=cfg["dst_mac"])
                    / IP(src=cfg["src_ip"], dst=cfg["dst_ip"], ttl=1, proto=89)
                    / Raw(payload)
                )
                send_time = time.time()
                sendp(frame, iface=cfg["iface"], count=1, verbose=0)
                sent.append(
                    {
                        **item["fields"],
                        "time": round(send_time - epoch, 6),
                        "ospf_hex": item["ospf_hex"],
                    }
                )
            time.sleep(cfg["tail"])
    finally:
        packets = list(sniffer.stop())
    end_time = time.time() - epoch
    wrpcap(cfg["pcap_path"], packets)
    result = {
        "iface": cfg["iface"],
        "pcap_path": cfg["pcap_path"],
        "epoch": epoch,
        "capture_duration_seconds": round(end_time, 6),
        "sent": sent,
    }
    with open(cfg["result_path"] + ".tmp", "w") as fp:
        json.dump(result, fp, indent=2, sort_keys=True)
    os.replace(cfg["result_path"] + ".tmp", cfg["result_path"])
    print("INJECT_SENT=%d PCAP=%s" % (len(sent), cfg["pcap_path"]))


run(json.loads(sys.argv[1]))
