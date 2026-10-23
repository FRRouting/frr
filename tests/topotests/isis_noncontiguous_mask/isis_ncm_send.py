#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# isis_ncm_send.py
#
# Build and send hand-crafted IS-IS LSPs carrying old-style IPv4
# Reachability TLVs (128/130) with a non-contiguous netmask.  Used by
# test_isis_noncontiguous_mask.py; runs on the originator namespace.

import argparse
import json
import struct
import sys
import time

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

INJECTOR_MAC = "02:00:00:00:00:02"


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


def reseal(pdu):
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)


def parse_tlvs(pdu):
    tlvs = []
    off = 27
    while off + 2 <= len(pdu):
        t, l = pdu[off], pdu[off + 1]
        if off + 2 + l > len(pdu):
            break
        tlvs.append((t, bytes(pdu[off + 2:off + 2 + l])))
        off += 2 + l
    return tlvs


def tlv128_entry(metric, prefix, mask):
    return (bytes([metric & 0x7F, 0x80, 0x80, 0x80])
            + bytes(int(x) for x in prefix.split("."))
            + bytes(int(x) for x in mask.split(".")))


def tlv128(entries):
    body = b"".join(tlv128_entry(*e) for e in entries)
    return bytes([128, len(body)]) + body


def tlv130(entries):
    body = b"".join(tlv128_entry(*e) for e in entries)
    return bytes([130, len(body)]) + body


def tlv135(metric, prefixlen, prefix):
    raw = bytes(int(x) for x in prefix.split("."))[: (prefixlen + 7) // 8]
    body = struct.pack("!I", metric) + bytes([prefixlen & 0x3F]) + raw
    return bytes([135, len(body)]) + body


def crafted_tlvs(mode):
    if mode in ("nc_mask", "invalid_cksum", "older"):
        return [
            tlv128([(10, "10.0.2.0", "255.0.255.0"),
                    (10, "10.0.3.0", "255.255.255.0"),
                    (10, "0.0.0.0", "0.0.0.0")]),
            tlv130([(10, "172.16.9.0", "255.255.0.255")]),
        ]
    if mode == "transition":
        return [
            tlv135(10, 24, "10.0.4.0"),
            tlv128([(10, "10.0.5.0", "255.0.255.0"),
                    (10, "10.0.3.0", "255.255.255.0"),
                    (10, "0.0.0.0", "0.0.0.0")]),
        ]
    raise ValueError(mode)


def synthetic_template(lsp_id, neighbor_sysid, if_addr):
    # Minimal realistic L2 LSP: TLV 2 (old IS reachability) back to the
    # neighbor, TLV 129 (protocols supported, IPv4), TLV 132 (IP interface
    # address).  TLV 128/130 of the real LSP are replaced wholesale by
    # crafted_tlvs().  In the LSP context TLV 2 starts with one reserved
    # byte before the 11-byte entries.  Without TLV 129 the receiver's
    # speaks() check skips the whole LSP in SPF.
    tlv2 = bytes([2, 12, 0]) + bytes([10, 0x80, 0x80, 0x80]) + neighbor_sysid + b"\x00"
    tlv129 = bytes([129, 1, 0xCC])
    tlv132 = bytes([132, 4]) + if_addr
    hdr = bytearray(27)
    hdr[0] = 0x83
    hdr[1] = 27
    hdr[2] = 1
    hdr[3] = 0
    hdr[4] = 20
    hdr[5] = 1
    hdr[6] = 0
    hdr[7] = 3
    hdr[12:20] = lsp_id
    hdr[26] = 0x03
    pdu = bytearray(bytes(hdr) + tlv2 + tlv129 + tlv132)
    pdu[8:10] = struct.pack("!H", len(pdu))
    pdu[10:12] = struct.pack("!H", 1200)
    pdu[20:24] = struct.pack("!I", 1)
    reseal(pdu)
    return bytes(pdu)


def build_forged(template, mode, seqno):
    pdu = bytearray(template)
    keep = [(t, v) for t, v in parse_tlvs(pdu) if t not in (128, 130)]
    body = b"".join(bytes([t, len(v)]) + v for t, v in keep)
    body += b"".join(crafted_tlvs(mode))
    pdu = bytearray(bytes(pdu[:27]) + body)
    pdu[8:10] = struct.pack("!H", len(pdu))
    pdu[10:12] = struct.pack("!H", 1200)
    pdu[20:24] = struct.pack("!I", seqno)
    reseal(pdu)
    if mode == "invalid_cksum":
        pdu[27] ^= 0x5A
    return bytes(pdu)


def describe_tlvs(pdu):
    out = []
    for t, v in parse_tlvs(pdu):
        if t in (128, 130):
            entries = []
            for i in range(0, len(v) - 11, 12):
                e = v[i:i + 12]
                entries.append({
                    "metric": e[0] & 0x7F,
                    "prefix": ".".join(str(b) for b in e[4:8]),
                    "mask": ".".join(str(b) for b in e[8:12]),
                })
            out.append({"tlv": t, "entries": entries})
        elif t == 135:
            entries = []
            off = 0
            while off + 5 <= len(v):
                metric = struct.unpack("!I", v[off:off + 4])[0]
                plen = v[off + 4] & 0x3F
                nbytes = (plen + 7) // 8
                if off + 5 + nbytes > len(v):
                    break
                prefix = ".".join(str(b) for b in v[off + 5:off + 5 + nbytes])
                entries.append({"metric": metric, "prefixlen": plen,
                                "prefix": prefix})
                off += 5 + nbytes
            out.append({"tlv": t, "entries": entries})
    return out


def send_frame(iface, pdu, src_mac):
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst="01:80:c2:00:00:15", src=src_mac, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def run_inject(args):
    template = synthetic_template(
        bytes.fromhex(args.lsp_id.replace(".", "").replace("-", "")),
        bytes.fromhex(args.neighbor_sysid.replace(".", "")),
        bytes(int(x) for x in args.if_addr.split(".")),
    )
    pdu = build_forged(template, args.mode, args.seqno)
    for index in range(args.count):
        if index:
            time.sleep(args.spacing)
        send_frame(args.iface, pdu, INJECTOR_MAC)
    print("SENT_JSON=" + json.dumps(
        {"mode": args.mode, "seq": args.seqno, "count": args.count,
         "tlvs": describe_tlvs(pdu)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    inj = parser.add_subparsers(dest="role", required=True).add_parser("inject")
    inj.add_argument("--iface", required=True)
    inj.add_argument("--lsp-id", required=True)
    inj.add_argument("--neighbor-sysid", required=True)
    inj.add_argument("--if-addr", required=True)
    inj.add_argument("--mode", required=True,
                     choices=("nc_mask", "invalid_cksum", "older", "transition"))
    inj.add_argument("--seqno", type=int, required=True)
    inj.add_argument("--count", type=int, default=1)
    inj.add_argument("--spacing", type=float, default=1.0)
    args = parser.parse_args()
    run_inject(args)


if __name__ == "__main__":
    main()
