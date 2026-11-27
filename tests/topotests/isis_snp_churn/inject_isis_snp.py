#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_isis_snp.py
#
# Copyright (c) 2026 Bing Shui
#
"""Craft and send IS-IS L2 PSNP PDUs on an interface.

Used by test_isis_snp_churn.py to request an LSP from the peer with a
deliberately stale LSP entry (lower sequence number), optionally many
times in a row to simulate a requester that repeats the same request.

The PSNP source system ID is configurable; on point-to-point circuits
FRR does not validate it against the adjacency, so an arbitrary value
is accepted as long as the p2p adjacency is up.
"""

import argparse
import json
import struct
import sys
import time

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

ALL_L2_IS = "01:80:c2:00:00:15"


def build_psnp(sysid, lsp_id, seqno, checksum, lifetime):
    entry = struct.pack("!H", lifetime) + lsp_id + struct.pack("!I", seqno)
    entry += struct.pack("!H", checksum)
    tlvs = bytes([9, len(entry)]) + entry
    pdu_len = 17 + len(tlvs)
    return (bytes([0x83, 17, 1, 6, 27, 1, 0, 3])
            + struct.pack("!H", pdu_len) + sysid + b"\x00" + tlvs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--sysid", required=True, help="12 hex digits")
    parser.add_argument("--lsp-id", required=True, help="16 hex digits")
    parser.add_argument("--seqno", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--checksum", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--lifetime", type=int, default=100)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing", type=float, default=0.0)
    parser.add_argument("--sent-log", default="")
    args = parser.parse_args()

    sysid = bytes.fromhex(args.sysid)
    lsp_id = bytes.fromhex(args.lsp_id)
    if len(sysid) != 6 or len(lsp_id) != 8:
        sys.stderr.write("sysid/lsp-id must be 12/16 hex digits\n")
        sys.exit(1)

    payload = build_psnp(sysid, lsp_id, args.seqno, args.checksum, args.lifetime)
    frame = (Ether(dst=ALL_L2_IS, src=args.src_mac, type=len(payload) + 3)
             / Raw(b"\xfe\xfe\x03" + payload))

    epoch = time.time()
    sent = []
    for _ in range(args.count):
        sent.append(round(time.time() - epoch, 6))
        sendp(frame, iface=args.iface, verbose=False)
        if args.count > 1:
            time.sleep(args.spacing)

    if args.sent_log:
        with open(args.sent_log, "w") as fp:
            json.dump({"epoch": epoch, "sent": sent}, fp)
    print("INJECT_OK count=%d" % args.count)


if __name__ == "__main__":
    main()
