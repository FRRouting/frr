#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# replay_lsp.py
#
# Copyright (c) 2026
#
"""Replay an IS-IS LSP PDU captured from the wire.

Used by test_isis_equal_lsp_churn.py to drive the receive path of the
router under test with byte-identical copies of a real LSP:

* mode "equal":   send the captured PDU unchanged, so the receiver
                  compares it LSP_EQUAL against its database copy.
* mode "newer":   bump the sequence number by one and recompute the
                  checksum, a genuinely newer but valid LSP.
* mode "invalid": recompute the checksum, then flip a body byte, so the
                  receiver drops the PDU on checksum verification.

Frames are sent from a locally administered source MAC, distinct from
the originator's real MAC, so capture-side template tracking never
mistakes an injected frame for a genuine flood.  The receiver does not
check the source MAC on point-to-point LSP receipt, so the replay still
exercises the normal receive path.

The ISO 8473 Fletcher checksum replicates lib/checksum.c
(fletcher_checksum(), MODX 4102, C-style signed modulo).
"""

import argparse
import struct
import sys
import time

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

INJECTOR_MAC = "02:00:00:00:00:02"
ISIS_ALL_MAC = "01:80:c2:00:00:15"


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


def build_from_template(template, seqno, lifetime, corrupt):
    pdu = bytearray(template)
    pdu[10:12] = struct.pack("!H", lifetime)
    pdu[20:24] = struct.pack("!I", seqno)
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    if corrupt:
        pdu[27] ^= 0x5A
    return bytes(pdu)


def send_frame(iface, pdu, src_mac):
    llc = b"\xfe\xfe\x03" + pdu
    frame = Ether(dst=ISIS_ALL_MAC, src=src_mac, type=len(llc)) / Raw(load=llc)
    sendp(frame, iface=iface, verbose=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--mode", required=True, choices=["equal", "newer", "invalid"])
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing", type=float, default=0.2)
    parser.add_argument("--src-mac", default=INJECTOR_MAC)
    args = parser.parse_args()

    template = bytes.fromhex(open(args.template).read().strip())
    template_seq = struct.unpack("!I", template[20:24])[0]
    template_lifetime = struct.unpack("!H", template[10:12])[0]

    if args.mode == "equal":
        frames = [bytes(template)] * args.count
    elif args.mode == "newer":
        frames = [
            build_from_template(template, template_seq + 1, template_lifetime, False)
        ]
    else:
        frames = [
            build_from_template(template, template_seq, template_lifetime, True)
        ]

    for index, frame in enumerate(frames):
        if index:
            time.sleep(args.spacing)
        send_frame(args.iface, frame, args.src_mac)

    print(
        "REPLAY_DONE mode=%s count=%d template_seq=%d template_lifetime=%d"
        % (args.mode, len(frames), template_seq, template_lifetime)
    )


if __name__ == "__main__":
    main()
