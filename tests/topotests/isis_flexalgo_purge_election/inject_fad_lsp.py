#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# inject_fad_lsp.py
#
# Copyright (c) 2026
#
"""Send crafted IS-IS L1 LSPs carrying a Flex-Algo Definition.

Used by test_isis_flexalgo_purge_election.py to drive the receive path
of the router under test with LSPs whose Router Capability TLV (242)
contains a FAD sub-TLV (26):

* seqno 0 with a valid lifetime: a sequence-number-less LSP must not
  feed any state consumer; the main SPF already skips it, but the FAD
  election used to count it.
* zero remaining lifetime with a valid seqno: a purge.  The receiver
  keeps the database copy with its TLVs for the zero-age window, and
  the FAD election used to keep counting it.
* fully valid high-priority FAD: a legal election change that must
  still win after the fix (control).
* FAD with an unknown sub-sub-TLV: elected but unsupported, which
  drives the algorithm into the disabled state when it is (wrongly)
  elected.

The 27-byte LSP header is taken from a template PDU captured on the
wire so common header fields stay genuine; the LSP id, seqno,
lifetime and TLVs are replaced.  Frames are sent from a locally
administered source MAC, distinct from the originator's real MAC, so
capture-side template tracking never mistakes an injected frame for a
genuine flood.  The receiver does not check the source MAC on
point-to-point LSP receipt, so the injection exercises the normal
receive path.

The ISO 8473 Fletcher checksum replicates lib/checksum.c
(fletcher_checksum(), MODX 4102, C-style signed modulo).
"""

import argparse
import json
import struct
import sys
import time

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

INJECTOR_MAC = "02:00:00:00:00:02"
ISIS_ALL_L1_MAC = "01:80:c2:00:00:14"


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


def build_lsp(template, sysid_hex, seqno, lifetime, algo, prio, unsupported):
    hdr = bytearray(template[:27])
    tlvs = bytearray()
    # TLV 1: area addresses, 49.0001
    tlvs += bytes([0x01, 0x04, 0x03, 0x49, 0x00, 0x01])
    # TLV 242: router capability, router id 10.99.99.99, flags 0
    fad = bytes([algo, 0, 0, prio])
    if unsupported:
        # unknown FAD sub-sub-TLV 99 -> unsupported_subtlv on the
        # receiver, so the definition is elected but unsupported
        fad += bytes([99, 2, 0xDE, 0xAD])
    rcap_body = bytes([10, 99, 99, 99, 0]) + bytes([26, len(fad)]) + fad
    tlvs += bytes([242, len(rcap_body)]) + rcap_body
    hdr[12:20] = bytes.fromhex(sysid_hex.replace(".", "")) + b"\x00\x00"
    hdr[20:24] = struct.pack("!I", seqno)
    hdr[10:12] = struct.pack("!H", lifetime)
    pdu = hdr + tlvs
    pdu[8:10] = struct.pack("!H", len(pdu))
    cksum = fletcher(bytes(pdu[12:]), 12)
    pdu[24:26] = struct.pack("!H", cksum)
    return bytes(pdu)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument(
        "--frames",
        required=True,
        help='JSON list, e.g. \'[{"sysid": "0000.0000.00aa", "seqno": 0, '
        '"lifetime": 1200, "algo": 201, "prio": 200, "unsupported": false}]\'',
    )
    parser.add_argument("--spacing", type=float, default=0.4)
    args = parser.parse_args()

    with open(args.template) as fp:
        template = bytes.fromhex(fp.read().strip())
    specs = json.loads(args.frames)
    for index, spec in enumerate(specs):
        if index:
            time.sleep(args.spacing)
        pdu = build_lsp(
            template,
            spec["sysid"],
            spec["seqno"],
            spec["lifetime"],
            spec["algo"],
            spec["prio"],
            spec["unsupported"],
        )
        llc = b"\xfe\xfe\x03" + pdu
        frame = Ether(dst=ISIS_ALL_L1_MAC, src=INJECTOR_MAC, type=len(llc)) / Raw(load=llc)
        sendp(frame, iface=args.iface, verbose=0)
        print(
            "SENT sysid=%s seqno=0x%08x lifetime=%d prio=%d unsupported=%s"
            % (spec["sysid"], spec["seqno"], spec["lifetime"], spec["prio"],
               spec["unsupported"])
        )


if __name__ == "__main__":
    sys.exit(main())
