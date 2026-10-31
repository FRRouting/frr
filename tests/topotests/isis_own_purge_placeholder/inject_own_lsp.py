#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_own_lsp.py
# Part of NetDEF Topology Tests
#
"""Craft and inject IS-IS LSPs for test_isis_own_purge_placeholder.py.

Runs inside a router namespace.  PDUs are built and parsed byte-wise so
that acceptance does not depend on scapy contrib dissection.  The ISO
8473 Fletcher checksum replicates lib/checksum.c:fletcher_checksum()
(MODX 4102, C-style signed modulo).

Roles:
  template   sniff the victim's fragment-0 LSP and save it as a hex
             template for later forgery
  inject     build forged LSPs from the template and send them
  observer   sniff IS-IS PDUs (used to verify the purge flood reaches
             the observer link)
"""

import argparse
import json
import os
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, Raw, conf, get_if_hwaddr, sendp, wrpcap

conf.verb = 0


def c_mod(a, b):
    return a % b if a >= 0 else -((-a) % b)


def fletcher(data, offset):
    buf = bytearray(data)
    buf[offset] = 0
    buf[offset + 1] = 0
    c0 = c1 = 0
    left = len(buf)
    pos = 0
    while left:
        n = min(left, 4102)
        for j in range(pos, pos + n):
            c0 += buf[j]
            c1 += c0
        c0 %= 255
        c1 %= 255
        pos += n
        left -= n
    x = c_mod((len(buf) - offset - 1) * c0 - c1, 255)
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return (x << 8) | (y & 0xFF)


def build_from_template(template, sysid, seqno, lifetime, corrupt, pseudo=0, frag=0,
                        level=2):
    pdu = bytearray(template)
    # L1_LINK_STATE (18) vs L2_LINK_STATE (20); the level of a received
    # LSP is taken from the PDU type, and the IS-Type byte (low bits of
    # the P/ATT/OL/IS-Type field) is kept consistent for good measure.
    pdu[4] = 18 if level == 1 else 20
    pdu[26] = (pdu[26] & ~0x03) | level
    pdu[10:12] = struct.pack("!H", lifetime)
    pdu[12:18] = sysid
    pdu[18] = pseudo
    pdu[19] = frag
    pdu[20:24] = struct.pack("!I", seqno)
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    if corrupt:
        pdu[27] ^= 0x5A
    return bytes(pdu)


def parse_isis(raw):
    if len(raw) < 20:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if len(pdu) < 8 or pdu[0] != 0x83:
        return None
    info = {"pdutype": pdu[4], "src_mac": ":".join("%02x" % b for b in raw[6:12])}
    if pdu[4] in (18, 20) and len(pdu) >= 27:
        info["lifetime"] = struct.unpack("!H", pdu[10:12])[0]
        info["lspid"] = pdu[12:20].hex()
        info["seqno"] = struct.unpack("!I", pdu[20:24])[0]
    return info


def events_of(packets, epoch):
    events = []
    for pkt in packets:
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            continue
        if info is None:
            continue
        info["time"] = round(float(pkt.time) - epoch, 6)
        info["abs_time"] = float(pkt.time)
        events.append(info)
    return events


def send_frame(iface, pdu):
    src = get_if_hwaddr(iface)
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst="01:80:c2:00:00:15", src=src, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def run_template(args):
    def process(pkt):
        try:
            info = parse_isis(bytes(pkt))
        except Exception:
            return
        if info is None or info.get("pdutype") != 20:
            return
        if info.get("lspid") != args.lsp_id:
            return
        raw = bytes(pkt)[17:]
        tmp = args.out_file + ".tmp"
        with open(tmp, "w") as fp:
            fp.write(raw.hex())
        os.replace(tmp, args.out_file)
        print("TEMPLATE_UPDATE seq=%d" % info["seqno"], flush=True)

    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True, prn=process)
    sniffer.start()
    print("TEMPLATE_LISTENING", flush=True)
    while not os.path.exists(args.stop_file):
        time.sleep(0.3)
    packets = list(sniffer.stop() or [])
    wrpcap(args.pcap, packets)
    print("TEMPLATE_DONE", flush=True)


def run_inject(args):
    template = bytes.fromhex(open(args.template).read().strip())
    frames_spec = json.loads(args.frames)
    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    frames = []
    for spec in frames_spec:
        sysid = bytes.fromhex(spec["sysid"])
        frame = build_from_template(
            template, sysid, spec["seqno"], spec["lifetime"],
            spec.get("corrupt", False), spec.get("pseudo", 0), spec.get("frag", 0),
            spec.get("level", 2),
        )
        frames.append(frame)
        sent.append({
            "time": round(time.time() - epoch, 6),
            "sysid": spec["sysid"], "pseudo": spec.get("pseudo", 0),
            "frag": spec.get("frag", 0), "seqno": spec["seqno"],
            "lifetime": spec["lifetime"], "corrupt": spec.get("corrupt", False),
            "level": spec.get("level", 2),
        })
    for index, frame in enumerate(frames):
        if index:
            time.sleep(args.spacing)
        send_frame(args.iface, frame)
    time.sleep(args.tail)
    packets = list(sniffer.stop() or [])
    events = events_of(packets, epoch)
    wrpcap(args.pcap, packets)
    print("ISIS_CAPTURE_JSON=" + json.dumps(
        {"sent": sent, "events": events, "pcap_path": args.pcap}, sort_keys=True))


def run_observer(args):
    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True)
    sniffer.start()
    epoch = time.time()
    print("OBS_EPOCH=%f" % epoch, flush=True)
    while not os.path.exists(args.stop_file):
        time.sleep(0.3)
    packets = list(sniffer.stop() or [])
    events = events_of(packets, epoch)
    wrpcap(args.pcap, packets)
    with open(args.out_json, "w") as fp:
        json.dump({"events": events, "pcap_path": args.pcap}, fp, sort_keys=True)
    print("OBS_DONE", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True,
                        choices=["template", "inject", "observer"])
    parser.add_argument("--iface", required=True)
    parser.add_argument("--lsp-id", default=None)
    parser.add_argument("--out-file", default=None)
    parser.add_argument("--stop-file", default=None)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--template", default=None)
    parser.add_argument("--frames", default=None)
    parser.add_argument("--spacing", type=float, default=0.2)
    parser.add_argument("--tail", type=float, default=1.5)
    parser.add_argument("--out-json", default=None)
    args = parser.parse_args()

    if args.role == "template":
        run_template(args)
    elif args.role == "inject":
        run_inject(args)
    else:
        run_observer(args)


if __name__ == "__main__":
    main()
