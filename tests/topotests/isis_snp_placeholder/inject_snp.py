#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_snp.py
# Part of NetDEF Topology Tests
#
"""Craft and inject IS-IS SNPs/LSPs for test_isis_snp_placeholder.py.

Runs inside a router namespace.  PDUs are built and parsed byte-wise so
that acceptance does not depend on scapy contrib dissection.  The ISO
8473 Fletcher checksum replicates lib/checksum.c:fletcher_checksum()
(MODX 4102, C-style signed modulo).

Wire layouts used here:
  L2 LSP  (pdutype 20): fixed(8) pdu_len(2) lifetime(2) lsp_id(8)
           seqno(4) cksum(2) bits(1) [TLVs]
  L2 CSNP (pdutype 25): fixed(8) pdu_len(2) source(6) cir(1)
           start(8) stop(8) [TLVs]           (header length 33)
  L2 PSNP (pdutype 27): fixed(8) pdu_len(2) source(6) cir(1) [TLVs]
  LSP Entries TLV (type 9): lifetime(2) lsp_id(8) seqno(4) cksum(2)

Roles:
  csnp_template  sniff the injector's periodic L2 CSNP and save it as a
                 hex template for later forgery
  lsp_template   sniff the victim's fragment-0 LSP and save it as a hex
                 template for later forgery
  inject         build forged CSNPs/LSPs from the templates and send them
  observer       sniff IS-IS PDUs on the observer link
"""

import argparse
import json
import os
import struct
import sys
import time

from scapy.all import AsyncSniffer, Ether, Raw, conf, get_if_hwaddr, sendp, wrpcap

conf.verb = 0

CSNP_HDR_LEN = 33
PSNP_HDR_LEN = 17


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


def build_csnp(template, source, entries):
    "Rebuild a CSNP from a captured template: keep the 33-byte header."
    pdu = bytearray(template[:CSNP_HDR_LEN])
    pdu[10:16] = source
    pdu[16] = 0
    ids = [bytes.fromhex(e["id"]) for e in entries]
    pdu[17:25] = min(ids) if ids else b"\x00" * 8
    pdu[25:33] = max(ids) if ids else b"\xff" * 8
    body = b""
    if entries:
        # The LSP Entries TLV has a 1-byte length: at most 15 entries
        # (240 bytes) per TLV; larger batches use multiple TLVs.
        for base in range(0, len(entries), 15):
            payload = b""
            for e in entries[base:base + 15]:
                payload += struct.pack("!H", e["lifetime"])
                payload += bytes.fromhex(e["id"])
                payload += struct.pack("!I", e["seqno"])
                payload += struct.pack("!H", e["cksum"])
            body += b"\x09" + bytes([len(payload)]) + payload
    pdu = bytes(pdu) + body
    pdu = pdu[:8] + struct.pack("!H", len(pdu)) + pdu[10:]
    return pdu


def build_lsp(template, sysid, seqno, lifetime, minimal):
    "Forge an LSP from the captured template; minimal=True keeps header only."
    pdu = bytearray(template[:27] if minimal else template)
    pdu[8:10] = struct.pack("!H", len(pdu))
    pdu[10:12] = struct.pack("!H", lifetime)
    pdu[12:18] = sysid
    pdu[18] = 0
    pdu[19] = 0
    pdu[20:24] = struct.pack("!I", seqno)
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
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
        info["source"] = pdu[12:18].hex()
    elif pdu[4] in (24, 25) and len(pdu) >= CSNP_HDR_LEN:
        info["source"] = pdu[10:16].hex()
        info["start"] = pdu[17:25].hex()
        info["stop"] = pdu[25:33].hex()
        info["entries"] = parse_entries(pdu, CSNP_HDR_LEN)
    elif pdu[4] in (26, 27) and len(pdu) >= PSNP_HDR_LEN:
        info["source"] = pdu[10:16].hex()
        info["entries"] = parse_entries(pdu, PSNP_HDR_LEN)
    return info


def parse_entries(pdu, off):
    entries = []
    while off + 2 <= len(pdu):
        t, l = pdu[off], pdu[off + 1]
        if off + 2 + l > len(pdu):
            break
        if t == 9:
            for i in range(0, l - 15, 16):
                e = pdu[off + 2 + i:off + 2 + i + 16]
                entries.append({
                    "lifetime": struct.unpack("!H", e[0:2])[0],
                    "lspid": e[2:10].hex(),
                    "seqno": struct.unpack("!I", e[10:14])[0],
                })
        off += 2 + l
    return entries


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
        if info is None or info.get("pdutype") != args.pdutype:
            return
        if info.get("source") != args.source:
            return
        if args.lsp_id and info.get("lspid") != args.lsp_id:
            return
        raw = bytes(pkt)[17:]
        tmp = args.out_file + ".tmp"
        with open(tmp, "w") as fp:
            fp.write(raw.hex())
        os.replace(tmp, args.out_file)
        print("TEMPLATE_UPDATE", flush=True)

    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True, prn=process)
    sniffer.start()
    print("TEMPLATE_LISTENING", flush=True)
    while not os.path.exists(args.stop_file):
        time.sleep(0.3)
    packets = list(sniffer.stop() or [])
    wrpcap(args.pcap, packets)
    print("TEMPLATE_DONE", flush=True)


def run_inject(args):
    csnp_template = bytes.fromhex(open(args.csnp_template).read().strip())
    lsp_template = bytes.fromhex(open(args.lsp_template).read().strip())
    frames_spec = json.loads(args.frames)
    sniffer = AsyncSniffer(iface=args.iface, filter="isis", store=True)
    sniffer.start()
    time.sleep(0.4)
    epoch = time.time()
    sent = []
    frames = []
    for spec in frames_spec:
        if spec["kind"] == "csnp":
            pdu = build_csnp(csnp_template, bytes.fromhex(spec["source"]),
                             spec["entries"])
        else:
            pdu = build_lsp(lsp_template, bytes.fromhex(spec["sysid"]),
                            spec["seqno"], spec["lifetime"],
                            spec.get("minimal", False))
        frames.append(pdu)
        sent.append({"time": round(time.time() - epoch, 6), "spec": spec})
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
                        choices=["csnp_template", "lsp_template", "inject",
                                 "observer"])
    parser.add_argument("--iface", required=True)
    parser.add_argument("--pdutype", type=int, default=None)
    parser.add_argument("--source", default=None)
    parser.add_argument("--lsp-id", default=None)
    parser.add_argument("--out-file", default=None)
    parser.add_argument("--stop-file", default=None)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--csnp-template", default=None)
    parser.add_argument("--lsp-template", default=None)
    parser.add_argument("--frames", default=None)
    parser.add_argument("--spacing", type=float, default=0.2)
    parser.add_argument("--tail", type=float, default=1.5)
    parser.add_argument("--out-json", default=None)
    args = parser.parse_args()

    if args.role in ("csnp_template", "lsp_template"):
        run_template(args)
    elif args.role == "inject":
        run_inject(args)
    else:
        run_observer(args)


if __name__ == "__main__":
    main()
